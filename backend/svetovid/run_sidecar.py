"""PyInstaller entry shim for the bundled sidecar.

Tauri launches this binary directly; it just forwards to ``main:run``.
Kept separate so PyInstaller has a stable top-level script target.
"""
from svetovid.main import run

if __name__ == "__main__":
    run()
