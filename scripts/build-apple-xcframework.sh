#!/usr/bin/env bash
#
# Builds the Apple SwiftPM XCFramework wrapper around the static libraries
# already packaged in AttestedKeyZKApple.artifactbundle.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

APPLE_ARTIFACTBUNDLE="${1:-$REPO_ROOT/AttestedKeyZKApple.artifactbundle}"
APPLE_XCFRAMEWORK="${2:-$REPO_ROOT/AttestedKeyZKApple.xcframework}"

require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "ERROR: expected file at $path" >&2
        exit 1
    fi
}

require_dir() {
    local path="$1"
    if [[ ! -d "$path" ]]; then
        echo "ERROR: expected directory at $path" >&2
        exit 1
    fi
}

require_file "$APPLE_ARTIFACTBUNDLE/ios-arm64/libattested_key_zk.a"
require_file "$APPLE_ARTIFACTBUNDLE/ios-arm64-simulator/libattested_key_zk.a"
require_file "$APPLE_ARTIFACTBUNDLE/macos-arm64/libattested_key_zk.a"
require_dir "$APPLE_ARTIFACTBUNDLE/ios-arm64/headers"
require_dir "$APPLE_ARTIFACTBUNDLE/ios-arm64-simulator/headers"
require_dir "$APPLE_ARTIFACTBUNDLE/macos-arm64/headers"

rm -rf "$APPLE_XCFRAMEWORK"
xcodebuild -create-xcframework \
    -library "$APPLE_ARTIFACTBUNDLE/ios-arm64/libattested_key_zk.a" \
    -headers "$APPLE_ARTIFACTBUNDLE/ios-arm64/headers" \
    -library "$APPLE_ARTIFACTBUNDLE/ios-arm64-simulator/libattested_key_zk.a" \
    -headers "$APPLE_ARTIFACTBUNDLE/ios-arm64-simulator/headers" \
    -library "$APPLE_ARTIFACTBUNDLE/macos-arm64/libattested_key_zk.a" \
    -headers "$APPLE_ARTIFACTBUNDLE/macos-arm64/headers" \
    -output "$APPLE_XCFRAMEWORK"

echo "Apple XCFramework written to $APPLE_XCFRAMEWORK"
