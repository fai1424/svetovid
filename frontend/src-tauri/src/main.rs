// Svetovid desktop shell (Tauri 2).
//
// Responsibilities:
//   1. Ensure the Python backend (FastAPI on :7421) is running.
//      - In dev: assume the user ran `uvicorn svetovid.main:app --port 7421`.
//      - In release: launch the bundled PyInstaller sidecar binary, wait for
//        /health, then open the window.
//   2. Register Tauri plugins (dialog for folder picking, fs, shell).
//   3. Open the React frontend (dev URL or built dist).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tauri::Manager;

const BACKEND_PORT: u16 = 7421;
const BACKEND_URL: &str = "http://127.0.0.1:7421";
const HEALTH_PATH: &str = "/health";
const HEALTH_TIMEOUT: Duration = Duration::from_secs(20);
const HEALTH_POLL: Duration = Duration::from_millis(250);

/// Track the spawned backend so we can terminate it on app close.
struct BackendProcess(Mutex<Option<Child>>);

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // Generate a per-launch auth token. Passed to the sidecar via env var;
    // the frontend fetches it from /api/auth-token (localhost-only).
    let auth_token = format!("svt_{}", rand_hex(16));
    std::env::set_var("SVETOVID_AUTH_TOKEN", &auth_token);

    // Try to detect an already-running backend first (common in dev).
    let already_up = wait_for_health_blocking(Duration::from_secs(1));
    let backend_proc = if already_up {
        log::info!("backend already reachable on :{BACKEND_PORT}, not launching a sidecar");
        None
    } else {
        launch_sidecar()
    };

    let backend_state = std::sync::Arc::new(BackendProcess(Mutex::new(backend_proc)));

    // Crash-recovery supervisor: monitor the sidecar and restart on unexpected exit.
    let supervisor_state = backend_state.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            // Check + relaunch in a synchronous block — never hold the
            // MutexGuard across an .await (it's not Send).
            let need_health_check = {
                let mut guard = supervisor_state.0.lock().unwrap();
                if let Some(ref mut child) = *guard {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            log::warn!("backend exited (status={status}), restarting…");
                            *guard = launch_sidecar();
                            true
                        }
                        Ok(None) => false, // still running
                        Err(e) => {
                            log::error!("failed to poll backend: {e}");
                            *guard = launch_sidecar();
                            true
                        }
                    }
                } else {
                    false // dev mode, no sidecar
                }
            }; // guard dropped here
            if need_health_check {
                if wait_for_health(Duration::from_secs(15)).await {
                    log::info!("backend restarted successfully");
                } else {
                    log::error!("backend did not come back after restart");
                }
            }
        }
    });

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        // Auto-updater (Phase 3 deployment hardening).
        //
        // The updater checks the `endpoints` listed in tauri.conf.json →
        // plugins.updater and verifies each release against the signing
        // public key (`pubkey`). The pubkey is left empty here on purpose:
        // it is generated during the first signed release and pasted in.
        // See updater.md for the keypair generation + CI signing flow.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(backend_state)
        .setup(|app| {
            tauri::async_runtime::spawn(async move {
                if wait_for_health(HEALTH_TIMEOUT).await {
                    log::info!("backend healthy at {BACKEND_URL}");
                } else {
                    log::warn!(
                        "backend not reachable at {BACKEND_URL} after {:?}. \
                         Start it manually: cd backend && uvicorn svetovid.main:app --port 7421",
                        HEALTH_TIMEOUT
                    );
                }
            });
            let _ = app;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                if let Some(state) = window.app_handle().try_state::<BackendProcess>() {
                    let mut guard = state.0.lock().unwrap();
                    if let Some(child) = guard.take() {
                        log::info!("terminating backend sidecar (pid {})", child.id());
                        let _ = kill_process(child);
                    }
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// ---------------------------------------------------------------------------
// Backend lifecycle
// ---------------------------------------------------------------------------

fn launch_sidecar() -> Option<Child> {
    let exe = if cfg!(windows) { "svetovid-backend.exe" } else { "svetovid-backend" };

    // Try the target-triple-suffixed name (Tauri convention) and the bare name.
    let triple = get_target_triple();
    let candidates: Vec<String> = vec![
        format!("binaries/svetovid-backend-{triple}"),
        exe.to_string(),
        format!("binaries/{exe}"),
    ];

    for cmd in &candidates {
        let result = Command::new(cmd)
            .env("SVETOVID_PORT", BACKEND_PORT.to_string())
            .env("SVETOVID_AUTH_TOKEN", std::env::var("SVETOVID_AUTH_TOKEN").unwrap_or_default())
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        match result {
            Ok(child) => {
                log::info!("launched backend sidecar {cmd} (pid {})", child.id());
                return Some(child);
            }
            Err(e) => log::debug!("spawn {cmd} failed: {e}"),
        }
    }

    log::warn!(
        "could not launch backend sidecar. Start it manually: \
         `uvicorn svetovid.main:app --port {BACKEND_PORT}`"
    );
    None
}

/// Get the Rust target triple (e.g. "aarch64-apple-darwin").
fn get_target_triple() -> String {
    // Read from the compile-time env set by rustc.
    option_env!("TARGET").unwrap_or("unknown").to_string()
}

/// Generate a random hex string of `n` bytes (2n hex chars).
fn rand_hex(n: usize) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut s = String::with_capacity(n * 2);
    let mut x = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    for _ in 0..n {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        x >>= 3;
        s.push_str(&format!("{:02x}", (x & 0xff) as u8));
    }
    s
}

async fn wait_for_health(timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(resp) = client
            .get(format!("{BACKEND_URL}{HEALTH_PATH}"))
            .send()
            .await
        {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(HEALTH_POLL).await;
    }
    false
}

/// Synchronous version for the boot-time preflight check.
///
/// We do a plain TCP connect to the backend port rather than spawning a tokio
/// runtime at startup — simpler and avoids nested-runtime pitfalls.
fn wait_for_health_blocking(timeout: Duration) -> bool {
    use std::net::TcpStream;
    let deadline = Instant::now() + timeout;
    let addr = format!("127.0.0.1:{BACKEND_PORT}");
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(
            &addr.parse().unwrap_or_else(|_| "127.0.0.1:7421".parse().unwrap()),
            Duration::from_millis(250),
        ).is_ok() {
            return true;
        }
        std::thread::sleep(HEALTH_POLL);
    }
    false
}

#[cfg(unix)]
fn kill_process(mut child: Child) -> std::io::Result<()> {
    let pid = child.id() as i32;
    // Best effort: SIGTERM the whole process group. The Child handle itself
    // goes out of scope and is dropped (Unix doesn't auto-kill on drop).
    unsafe {
        libc_kill(-pid, libc_term());
    }
    // Fallback: try direct kill on the handle.
    let _ = child.kill();
    Ok(())
}

#[cfg(windows)]
fn kill_process(child: Child) -> std::io::Result<()> {
    // On Windows, dropping Child with kill_on_drop would also work, but we
    // call kill explicitly to be sure.
    child.kill()?;
    Ok(())
}

// Minimal libc shims so we don't pull a `libc` crate just for the kill call.
#[cfg(unix)]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
#[cfg(unix)]
unsafe fn libc_kill(pid: i32, sig: i32) -> i32 {
    kill(pid, sig)
}
#[cfg(unix)]
fn libc_term() -> i32 {
    // SIGTERM = 15 on all Unix targets we care about (macOS + Linux).
    15
}
