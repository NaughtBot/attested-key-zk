#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
IMAGE="${ATTESTED_KEY_ZK_GO_CONTAINER_IMAGE:-golang:1.26-alpine}"
PLATFORM="${ATTESTED_KEY_ZK_GO_CONTAINER_PLATFORM:-linux/arm64}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for the Linux/arm64 Go binding compile check" >&2
    exit 1
fi

docker run --rm \
    --platform="$PLATFORM" \
    -v "$REPO_ROOT/bindings/go:/src:ro" \
    -w /src \
    "$IMAGE" \
    sh -euxc '
        apk add --no-cache clang g++ libstdc++-dev libc-dev openssl-dev make git

        CC=gcc CXX=g++ CGO_ENABLED=1 GOOS=linux go test -run "^$" ./...

        go clean -cache
        CC=clang CXX=clang++ CGO_ENABLED=1 GOOS=linux go test -run "^$" ./...
    '
