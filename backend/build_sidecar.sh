#!/usr/bin/env bash
# Build the PyInstaller sidecar binary for the Svetovid backend.
#
# Produces: frontend/src-tauri/binaries/svetovid-backend-<target-triple>[.exe]
#
# Run from the repo root:
#   ./backend/build_sidecar.sh
#
# Requirements:
#   - pip install pyinstaller
#   - The backend must be installed: cd backend && pip install -e .

set -euo pipefail

cd "$(dirname "$0")"  # → backend/

# Get the Rust target triple (must match what Tauri expects).
if command -v rustc &>/dev/null; then
    TRIPLE=$(rustc -vV | grep host | awk '{print $2}')
else
    # Fallback: guess from uname
    ARCH=$(uname -m)
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        darwin) TRIPLE="${ARCH}-apple-darwin" ;;
        linux)  TRIPLE="${ARCH}-unknown-linux-gnu" ;;
        mingw*|msys*|cygwin*) TRIPLE="x86_64-pc-windows-msvc" ;;
        *) echo "unknown OS: $OS"; exit 1 ;;
    esac
fi

EXE=""
if [[ "$TRIPLE" == *"windows"* ]]; then
    EXE=".exe"
fi

echo "▶ Building sidecar for target: $TRIPLE"

# Clean previous builds
rm -rf build/ dist/ *.spec

# Run PyInstaller with all hidden imports FastAPI/uvicorn/LangGraph need.
pip install pyinstaller --quiet 2>/dev/null || true

pyinstaller --onefile \
    --name "svetovid-backend-${TRIPLE}" \
    --hidden-import uvicorn.logging \
    --hidden-import uvicorn.loops.auto \
    --hidden-import uvicorn.protocols.http.auto \
    --hidden-import uvicorn.protocols.websockets.auto \
    --hidden-import uvicorn.lifespan.on \
    --hidden-import uvicorn.lifespan.off \
    --hidden-import svetovid \
    --hidden-import svetovid.main \
    --hidden-import svetovid.goals.registry \
    --hidden-import svetovid.agent.react \
    --collect-submodules svetovid \
    --collect-submodules langgraph \
    --collect-submodules langchain_core \
    --collect-submodules langchain_openai \
    svetovid/run_sidecar.py 2>&1 | tail -10

BINARY="dist/svetovid-backend-${TRIPLE}${EXE}"

if [[ ! -f "$BINARY" ]]; then
    echo "✗ Build failed: $BINARY not found"
    exit 1
fi

# Copy to the Tauri binaries directory.
DEST="../frontend/src-tauri/binaries/"
mkdir -p "$DEST"
cp "$BINARY" "$DEST"
echo "✓ Sidecar copied to: ${DEST}svetovid-backend-${TRIPLE}${EXE}"
echo "  Size: $(du -h "$DEST/svetovid-backend-${TRIPLE}${EXE}" | cut -f1)"
