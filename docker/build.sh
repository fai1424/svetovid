#!/usr/bin/env bash
# Build the Svetovid Docker images in dependency order.
#
# Usage:
#   ./docker/build.sh                 # build ALL images (default)
#   ./docker/build.sh all             #   .. same as above
#   ./docker/build.sh base            # build base only
#   ./docker/build.sh eztools         # build eztools (assumes base exists)
#   ./docker/build.sh volatility      # build volatility (assumes base exists)
#   ./docker/build.sh malware         # build malware (assumes base exists)
#   ./docker/build.sh network         # build network (assumes base exists)
#
# Image → Dockerfile map:
#   svetovid/base        docker/Dockerfile.base
#   svetovid/eztools     backend/svetovid/sandbox/images/Dockerfile.eztools
#   svetovid/volatility  backend/svetovid/sandbox/images/Dockerfile.volatility
#   svetovid/malware     backend/svetovid/sandbox/images/Dockerfile.malware
#   svetovid/network     backend/svetovid/sandbox/images/Dockerfile.network
#
# Re-run safe: docker skips layers whose inputs haven't changed.

set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

WHAT="${1:-all}"

# The tool images all layer on svetovid/base, so when building everything we
# always build base first, then the four tool images in dependency order.
TOOL_ORDER=(eztools volatility malware network)

build_base() {
    echo "▶ building svetovid/base:latest"
    docker build \
        --platform linux/amd64 --platform linux/arm64 \
        -f docker/Dockerfile.base \
        -t svetovid/base:latest \
        --build-arg ATTACK_VERSION=15.1 \
        .
}

build_eztools() {
    echo "▶ building svetovid/eztools:latest (multi-arch)"
    docker build \
        --platform linux/amd64 --platform linux/arm64 \
        -f backend/svetovid/sandbox/images/Dockerfile.eztools \
        -t svetovid/eztools:latest \
        --build-arg BASE_TAG=latest \
        .
}

build_volatility() {
    echo "▶ building svetovid/volatility:latest (multi-arch)"
    docker build \
        --platform linux/amd64 --platform linux/arm64 \
        -f backend/svetovid/sandbox/images/Dockerfile.volatility \
        -t svetovid/volatility:latest \
        --build-arg BASE_TAG=latest \
        .
}

build_malware() {
    echo "▶ building svetovid/malware:latest (multi-arch)"
    docker build \
        --platform linux/amd64 --platform linux/arm64 \
        -f backend/svetovid/sandbox/images/Dockerfile.malware \
        -t svetovid/malware:latest \
        --build-arg BASE_TAG=latest \
        .
}

build_network() {
    echo "▶ building svetovid/network:latest (multi-arch)"
    docker build \
        --platform linux/amd64 --platform linux/arm64 \
        -f backend/svetovid/sandbox/images/Dockerfile.network \
        -t svetovid/network:latest \
        --build-arg BASE_TAG=latest \
        .
}

case "$WHAT" in
    base)       build_base ;;
    eztools)    build_eztools ;;
    volatility) build_volatility ;;
    malware)    build_malware ;;
    network)    build_network ;;
    all)
        # Base first (everything else depends on it), then the tool images.
        build_base
        for img in "${TOOL_ORDER[@]}"; do
            "build_${img}"
        done
        ;;
    *) echo "unknown target: $WHAT (use base|eztools|volatility|malware|network|all)"; exit 1 ;;
esac

echo "✓ done. Images:"
docker images svetovid/* --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"
