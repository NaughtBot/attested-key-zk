#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

BUILD_ROOT="$TMP_DIR/build/artifactbundle"
APPLE_BUNDLE="$TMP_DIR/AttestedKeyZKApple.artifactbundle"
ANDROID_BUNDLE="$TMP_DIR/AttestedKeyZKAndroid.artifactbundle"

placeholder_libs=(
    "$BUILD_ROOT/targets/ios-arm64/libattested_key_zk.a"
    "$BUILD_ROOT/targets/ios-arm64-simulator/libattested_key_zk.a"
    "$BUILD_ROOT/targets/macos-arm64/libattested_key_zk.a"
    "$BUILD_ROOT/targets/android-aarch64/libattested_key_zk.a"
    "$BUILD_ROOT/targets/android-x86_64/libattested_key_zk.a"
)

for lib in "${placeholder_libs[@]}"; do
    mkdir -p "$(dirname "$lib")"
    : >"$lib"
done

make -C "$REPO_ROOT" \
    ARTIFACTBUNDLE_BUILD_ROOT="$BUILD_ROOT" \
    APPLE_ARTIFACTBUNDLE="$APPLE_BUNDLE" \
    ANDROID_ARTIFACTBUNDLE="$ANDROID_BUNDLE" \
    ensure-apple-artifactbundle

if [[ ! -f "$APPLE_BUNDLE/info.json" ]]; then
    echo "expected ensure-apple-artifactbundle to create the Apple bundle" >&2
    exit 1
fi

if [[ ! -f "$ANDROID_BUNDLE/.swiftpm-placeholder" ]]; then
    echo "ensure-apple-artifactbundle should create a marked Android placeholder bundle for SwiftPM" >&2
    exit 1
fi

rm -f "$ANDROID_BUNDLE/info.json"
make -C "$REPO_ROOT" \
    ARTIFACTBUNDLE_BUILD_ROOT="$BUILD_ROOT" \
    APPLE_ARTIFACTBUNDLE="$APPLE_BUNDLE" \
    ANDROID_ARTIFACTBUNDLE="$ANDROID_BUNDLE" \
    ensure-placeholder-android-artifactbundle

if [[ ! -f "$ANDROID_BUNDLE/info.json" || ! -f "$ANDROID_BUNDLE/.swiftpm-placeholder" ]]; then
    echo "ensure-placeholder-android-artifactbundle should rebuild incomplete placeholders" >&2
    exit 1
fi

python3 "$REPO_ROOT/check-apple-artifactbundle.py" "$APPLE_BUNDLE"
if python3 "$REPO_ROOT/check-android-artifactbundle.py" "$APPLE_BUNDLE"; then
    echo "Apple bundle should not satisfy Android artifact bundle checks" >&2
    exit 1
fi

make -C "$REPO_ROOT" \
    ARTIFACTBUNDLE_BUILD_ROOT="$BUILD_ROOT" \
    APPLE_ARTIFACTBUNDLE="$APPLE_BUNDLE" \
    ANDROID_ARTIFACTBUNDLE="$ANDROID_BUNDLE" \
    ensure-android-artifactbundle

if [[ ! -f "$ANDROID_BUNDLE/info.json" ]]; then
    echo "expected ensure-android-artifactbundle to create the Android bundle" >&2
    exit 1
fi
if [[ -f "$ANDROID_BUNDLE/.swiftpm-placeholder" ]]; then
    echo "ensure-android-artifactbundle should replace the Android placeholder with a real bundle" >&2
    exit 1
fi

python3 "$REPO_ROOT/check-android-artifactbundle.py" "$ANDROID_BUNDLE"
if python3 "$REPO_ROOT/check-apple-artifactbundle.py" "$ANDROID_BUNDLE"; then
    echo "Android bundle should not satisfy Apple artifact bundle checks" >&2
    exit 1
fi
python3 "$REPO_ROOT/check-apple-artifactbundle.py" "$APPLE_BUNDLE"

rm -rf "$APPLE_BUNDLE"
mkdir -p "$APPLE_BUNDLE"
: >"$APPLE_BUNDLE/incomplete"
make -C "$REPO_ROOT" \
    ARTIFACTBUNDLE_BUILD_ROOT="$BUILD_ROOT" \
    APPLE_ARTIFACTBUNDLE="$APPLE_BUNDLE" \
    ANDROID_ARTIFACTBUNDLE="$ANDROID_BUNDLE" \
    ensure-placeholder-apple-artifactbundle

if [[ ! -f "$APPLE_BUNDLE/info.json" || ! -f "$APPLE_BUNDLE/.swiftpm-placeholder" ]]; then
    echo "ensure-placeholder-apple-artifactbundle should rebuild incomplete placeholders" >&2
    exit 1
fi

if python3 "$REPO_ROOT/check-apple-artifactbundle.py" "$APPLE_BUNDLE"; then
    echo "Apple placeholder bundle should not satisfy Apple artifact bundle checks" >&2
    exit 1
fi

if ATTESTED_KEY_ZK_BUILD_ROOT="$BUILD_ROOT" \
    ATTESTED_KEY_ZK_BUNDLE_OUTPUT= \
    ATTESTED_KEY_ZK_BINARY_TARGET_NAME= \
    "$REPO_ROOT/build-artifactbundle.sh" --skip-build >/dev/null 2>&1; then
    echo "build-artifactbundle.sh should require an explicit output for combined builds" >&2
    exit 1
fi

echo "split artifact bundle regression test passed"
