# Svetovid auto-updater (Tauri 2)

This document describes how the Svetovid desktop app signs, publishes, and
verifies updates via the Tauri 2 updater plugin.

The plugin is registered in `src/main.rs`:

```rust
.plugin(tauri_plugin_updater::Builder::new().build())
```

and configured under `plugins.updater` in `tauri.conf.json`:

```json
"updater": {
    "active": true,
    "endpoints": ["https://your-server/svetovid/latest.json"],
    "dialog": true,
    "pubkey": ""
}
```

The `pubkey` field is intentionally empty in the repo. It is populated with the
**public** half of the signing keypair during the first signed release (see
§1). The updater refuses to install any update whose signature does not verify
against this key, so a leaked `latest.json` cannot ship malicious binaries.

---

## 1. Generating the signing keypair

Each release artifact is signed with a private key. Generate the keypair once,
locally, with the Tauri CLI:

```bash
cargo tauri signer generate -w ~/.tauri/svetovid.key
```

This writes a password-protected key to `~/.tauri/svetovid.key` and prints the
matching **public key** to stdout, e.g.:

```
Public Key:
dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEI...
```

Copy that public-key string into `tauri.conf.json` → `plugins.updater.pubkey`
and commit it. The public key is safe to commit; only the `.key` file is
secret.

The private key + its password are then provided to the release build as
environment variables (see §3). **Never commit the `.key` file** — keep it in a
password manager or a secrets store, and back it up. If it is lost you must
generate a new keypair and every existing install will have to be re-installed
manually (there is no key rotation path that the old binary trusts).

## 2. Setting the environment variables

The `tauri build` / `cargo tauri build` step signs the installers when it sees
both:

```bash
export TAURI_PRIVATE_KEY="$(cat ~/.tauri/svetovid.key)"
export TAURI_KEY_PASSWORD="<the password you chose at key generation time>"
```

- `TAURI_PRIVATE_KEY` — contents (or path) of the private key file.
- `TAURI_KEY_PASSWORD` — passphrase used when the key was created. If the key
  has no passphrase, leave `TAURI_KEY_PASSWORD` empty.

With both set, `tauri build` emits the installers **plus** a `.sig` signature
file next to each one (e.g. `Svetovid_0.2.0_aarch64.app.tar.gz.sig`). The `.sig`
files are what the updater verifies against `pubkey` at install time.

## 3. The `latest.json` manifest

The updater fetches one of the URLs in `endpoints` and expects a JSON document
of this shape:

```json
{
  "version": "0.2.0",
  "notes": "Phase 3 release — auto-updater + network sandbox image.",
  "pub_date": "2026-07-27T12:00:00Z",
  "platforms": {
    "darwin-aarch64": {
      "signature": "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIH...",
      "url": "https://your-server/svetovid/Svetovid_0.2.0_aarch64.app.tar.gz"
    },
    "darwin-x86_64": {
      "signature": "...",
      "url": "https://your-server/svetovid/Svetovid_0.2.0_x64.app.tar.gz"
    },
    "linux-x86_64": {
      "signature": "...",
      "url": "https://your-server/svetovid/svetovid_0.2.0_amd64.AppImage.tar.gz"
    },
    "windows-x86_64": {
      "signature": "...",
      "url": "https://your-server/svetovid/Svetovid_0.2.0_x64-setup.nsis.zip"
    }
  }
}
```

Fields:

- `version` — the new version string. The updater only offers the update when
  this is **greater than** the running app's `tauri.conf.json` `version`.
- `notes` — human-readable release notes (shown in the update dialog).
- `pub_date` — RFC 3339 / ISO 8601 timestamp.
- `platforms` — a per-target map. The keys are `<os>-<arch>` where `os` is one
  of `darwin`, `linux`, `windows` and `arch` is `aarch64` or `x86_64`.
- Each platform entry carries:
  - `signature` — the **contents** of the `.sig` file produced by `tauri build`
    (a base64 minisign signature). The updater verifies the downloaded archive
    against `pubkey` using this.
  - `url` — where to download the update archive (`.app.tar.gz` on macOS,
    `.AppImage.tar.gz` on Linux, `-setup.nsis.zip` on Windows).

## 4. CI / release flow

A typical release runs in CI (GitHub Actions, GitLab CI, …):

1. **Bump version** in `tauri.conf.json` (`"version": "0.2.0"`) and commit.
2. **Provide secrets to the runner** — store the following as CI secrets and
   expose them to the build step:
   - `TAURI_PRIVATE_KEY` (contents of `~/.tauri/svetovid.key`)
   - `TAURI_KEY_PASSWORD` (the passphrase)
3. **Build + sign** on each target:
   ```bash
   cargo tauri build
   ```
   This produces, per platform, the installer **and** its `.sig` file, e.g.:
   ```
   target/release/bundle/macos/Svetovid_0.2.0_aarch64.app.tar.gz
   target/release/bundle/macos/Svetovid_0.2.0_aarch64.app.tar.gz.sig
   ```
4. **Upload the archives** (`.app.tar.gz`, `.AppImage.tar.gz`, `.nmsi.zip`) and
   their `.sig` siblings to your static host / CDN.
5. **Publish `latest.json`** — read each `.sig` file's contents into the
   `signature` field, the upload URL into `url`, set `version`/`notes`/`pub_date`,
   and PUT the JSON to `https://your-server/svetovid/latest.json`. Regenerate it
   on every release; never hand-edit the published file in place.

A minimal CI snippet:

```yaml
- name: Build & sign
  env:
    TAURI_PRIVATE_KEY: ${{ secrets.TAURI_PRIVATE_KEY }}
    TAURI_KEY_PASSWORD: ${{ secrets.TAURI_KEY_PASSWORD }}
  run: cargo tauri build

- name: Publish latest.json
  run: |
    SIG_MACOS=$(cat target/release/bundle/macos/*.app.tar.gz.sig)
    # ...assemble latest.json with version, notes, pub_date, platforms...
    aws s3 cp latest.json s3://svetovid-releases/svetovid/latest.json
```

When the app next starts (or the user clicks "Check for updates"), the updater
fetches `latest.json`, compares `version` against the running build, downloads
the matching platform archive, verifies its `.sig` against `pubkey`, and — on
success — applies the update and restarts. The whole flow is gated by the
`dialog: true` setting, which shows the user the version, notes, and an
install prompt before anything is applied.

## Notes / gotchas

- The first signed release is special: until `pubkey` is populated in
  `tauri.conf.json`, the updater cannot verify anything, so updates are
  disabled. After generating the keypair (§1) and committing the public key,
  cut a release to bootstrap the trust chain.
- `version` comparison is semver-style. Do not skip `v` prefixes or build
  metadata — `0.2.0` is correct, `v0.2.0` is not.
- If a platform is omitted from `platforms`, installs on that OS simply see no
  update (they are not broken).
- The `.sig` value is the *contents* of the signature file, base64 — not a
  file path and not a hex digest.
