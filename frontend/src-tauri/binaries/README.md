# `src-tauri/binaries/`

Place the PyInstaller-bundled Python backend here before running
`cargo tauri build`. Naming convention (per Tauri's sidecar docs):

    svetovid-backend-<target-triple>[.exe]

e.g. on Apple Silicon:

    svetovid-backend-aarch64-apple-darwin

on Intel macOS:

    svetovid-backend-x86_64-apple-darwin

on Windows:

    svetovid-backend-x86_64-pc-windows-msvc.exe

Build the backend with:

    cd ../../backend
    pyinstaller --onefile \
        --name svetovid-backend-$(rustc -vV | grep host | awk '{print $2}') \
        --hidden-import=uvicorn.logging --hidden-import=uvicorn.protocols \
        --hidden-import=uvicorn.protocols.http --hidden-import=uvicorn.protocols.websockets \
        --hidden-import=uvicorn.lifespan.on \
        svetovid/run_sidecar.py

`run_sidecar.py` is a tiny shim that calls `svetovid.main:run()`. The
`--hidden-import`s are needed because PyInstaller can't see uvicorn's lazy
protocol imports.

In **dev** (`cargo tauri dev`) this directory can be empty — the Rust shell
detects that the sidecar isn't there and falls back to instructing the user to
run `uvicorn` manually (see `src/main.rs::launch_sidecar`).
