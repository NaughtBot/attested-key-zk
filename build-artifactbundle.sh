#!/usr/bin/env bash
#
# build-artifactbundle.sh
#
# Builds attested-key-zk for Apple and Android targets and packages the static
# libraries into a Swift artifact bundle that repo-local SwiftPM consumers can
# depend on without local-only linker flags.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${ATTESTED_KEY_ZK_BUILD_ROOT:-$SCRIPT_DIR/build/artifactbundle}"
TARGETS_ROOT="$BUILD_ROOT/targets"
BUNDLE_OUTPUT="${ATTESTED_KEY_ZK_BUNDLE_OUTPUT:-}"
BINARY_TARGET_NAME="${ATTESTED_KEY_ZK_BINARY_TARGET_NAME:-}"
OPENSSL_SRC_DIR="${ATTESTED_KEY_ZK_OPENSSL_SRC_DIR:-$BUILD_ROOT/openssl-src}"
# OpenSSL 3.6.2 release. Pinned by commit SHA (not tag) so a compromised
# upstream mirror cannot repoint the tag to a different tree.
OPENSSL_COMMIT="${ATTESTED_KEY_ZK_OPENSSL_COMMIT:-fe686e15d84334b284f883118ed92f64b409b3aa}"
OPENSSL_REPO_URL="${ATTESTED_KEY_ZK_OPENSSL_REPO_URL:-https://github.com/openssl/openssl.git}"
IOS_DEPLOYMENT_TARGET="${ATTESTED_KEY_ZK_IOS_DEPLOYMENT_TARGET:-18.0}"
MACOS_DEPLOYMENT_TARGET="${ATTESTED_KEY_ZK_MACOS_DEPLOYMENT_TARGET:-26.0}"
ANDROID_API="${ATTESTED_KEY_ZK_ANDROID_API:-35}"
ANDROID_MAX_API="${ATTESTED_KEY_ZK_ANDROID_MAX_API:-36}"
BUILD_JOBS="${ATTESTED_KEY_ZK_BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 8)}"

BUILD_TYPE="Release"
BUILD_APPLE=1
BUILD_ANDROID=1
SKIP_BUILD=0
cmake_generator_args=()

for arg in "$@"; do
    case "$arg" in
        --debug)
            BUILD_TYPE="Debug"
            ;;
        --apple-only)
            BUILD_ANDROID=0
            ;;
        --android-only)
            BUILD_APPLE=0
            ;;
        --skip-build)
            SKIP_BUILD=1
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$BUNDLE_OUTPUT" ]]; then
    if [[ "$BUILD_APPLE" -eq 1 && "$BUILD_ANDROID" -eq 0 ]]; then
        BUNDLE_OUTPUT="$SCRIPT_DIR/AttestedKeyZKApple.artifactbundle"
    elif [[ "$BUILD_APPLE" -eq 0 && "$BUILD_ANDROID" -eq 1 ]]; then
        BUNDLE_OUTPUT="$SCRIPT_DIR/AttestedKeyZKAndroid.artifactbundle"
    else
        echo "ERROR: building both Apple and Android artifact bundles requires ATTESTED_KEY_ZK_BUNDLE_OUTPUT to be set explicitly, or use --apple-only/--android-only." >&2
        exit 1
    fi
fi

if [[ -z "$BINARY_TARGET_NAME" ]]; then
    if [[ "$BUILD_APPLE" -eq 1 && "$BUILD_ANDROID" -eq 0 ]]; then
        BINARY_TARGET_NAME="CAttestedKeyZKAppleBinary"
    elif [[ "$BUILD_APPLE" -eq 0 && "$BUILD_ANDROID" -eq 1 ]]; then
        BINARY_TARGET_NAME="CAttestedKeyZKAndroidBinary"
    else
        echo "ERROR: building both Apple and Android artifact bundles requires ATTESTED_KEY_ZK_BINARY_TARGET_NAME to be set explicitly, or use --apple-only/--android-only." >&2
        exit 1
    fi
fi

if command -v ninja >/dev/null 2>&1; then
    cmake_generator_args=(-G Ninja)
fi

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "ERROR: missing required command: $1" >&2
        exit 1
    }
}

assert_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "ERROR: expected file at $path" >&2
        exit 1
    fi
}

discover_brew_openssl_root() {
    if [[ -n "${ATTESTED_KEY_ZK_MACOS_OPENSSL_ROOT:-}" ]]; then
        printf '%s\n' "$ATTESTED_KEY_ZK_MACOS_OPENSSL_ROOT"
        return 0
    fi
    if command -v brew >/dev/null 2>&1; then
        local brew_root
        brew_root="$(brew --prefix openssl@3 2>/dev/null || true)"
        if [[ -n "$brew_root" && -f "$brew_root/lib/libcrypto.a" ]]; then
            printf '%s\n' "$brew_root"
            return 0
        fi
    fi
    if [[ -f "/opt/homebrew/opt/openssl@3/lib/libcrypto.a" ]]; then
        printf '%s\n' "/opt/homebrew/opt/openssl@3"
        return 0
    fi
    return 1
}

ensure_openssl_source() {
    if [[ -d "$OPENSSL_SRC_DIR/.git" ]]; then
        local current_sha
        current_sha="$(git -C "$OPENSSL_SRC_DIR" rev-parse HEAD 2>/dev/null || echo '')"
        if [[ "$current_sha" == "$OPENSSL_COMMIT" ]]; then
            return 0
        fi
        echo "OpenSSL source at $OPENSSL_SRC_DIR is checked out at $current_sha, expected $OPENSSL_COMMIT — refetching."
    fi
    require_cmd git
    mkdir -p "$(dirname "$OPENSSL_SRC_DIR")"
    rm -rf "$OPENSSL_SRC_DIR"
    # Pin by commit SHA. GitHub permits fetching arbitrary reachable SHAs
    # via uploadpack.allowReachableSHA1InWant; init+fetch keeps the clone shallow.
    git init -q "$OPENSSL_SRC_DIR"
    git -C "$OPENSSL_SRC_DIR" remote add origin "$OPENSSL_REPO_URL"
    git -C "$OPENSSL_SRC_DIR" fetch --depth 1 origin "$OPENSSL_COMMIT"
    git -C "$OPENSSL_SRC_DIR" checkout --detach FETCH_HEAD
    local fetched_sha
    fetched_sha="$(git -C "$OPENSSL_SRC_DIR" rev-parse HEAD)"
    if [[ "$fetched_sha" != "$OPENSSL_COMMIT" ]]; then
        echo "ERROR: fetched OpenSSL commit $fetched_sha does not match expected $OPENSSL_COMMIT" >&2
        exit 1
    fi
}

copy_openssl_source() {
    local dest="$1"
    require_cmd rsync
    mkdir -p "$dest"
    rsync -a --delete --exclude '.git' "$OPENSSL_SRC_DIR/" "$dest/"
}

openssl_common_flags=(
    no-shared
    no-tests
    no-apps
    no-docs
    no-dso
    no-module
    no-ssl
    no-ui-console
    no-autoload-config
)

build_openssl_tree() {
    local worktree="$1"
    local prefix="$2"
    shift 2
    local -a env_vars=()
    while [[ "$#" -gt 0 && "$1" != "--" ]]; do
        env_vars+=("$1")
        shift
    done
    if [[ "$#" -eq 0 ]]; then
        echo "ERROR: build_openssl_tree missing configure arguments" >&2
        exit 1
    fi
    shift
    local -a configure_args=("$@")
    copy_openssl_source "$worktree"
    mkdir -p "$prefix"
    (
        cd "$worktree"
        env "${env_vars[@]}" ./Configure "${configure_args[@]}" \
            --prefix="$prefix" \
            "${openssl_common_flags[@]}"
        env "${env_vars[@]}" make -j "$BUILD_JOBS"
        env "${env_vars[@]}" make install_sw
    )
    assert_file "$prefix/lib/libcrypto.a"
}

combine_archives() {
    local archive_tool="$1"
    local output="$2"
    shift 2
    rm -f "$output"
    if [[ -n "$archive_tool" && "$(basename "$archive_tool")" == "libtool" ]]; then
        "$archive_tool" -static -o "$output" "$@"
        assert_file "$output"
        return 0
    fi
    if [[ -z "$archive_tool" ]]; then
        echo "No archive merge tool available" >&2
        exit 1
    fi
    local mri
    mri="$(mktemp)"
    {
        printf 'create %s\n' "$output"
        for archive in "$@"; do
            printf 'addlib %s\n' "$archive"
        done
            printf 'save\nend\n'
    } >"$mri"
    "$archive_tool" -M <"$mri"
    rm -f "$mri"
    assert_file "$output"
}

find_apple_archive_tool() {
    local archive_tool
    if archive_tool="$(xcrun --find llvm-ar 2>/dev/null)"; then
        printf '%s\n' "$archive_tool"
        return 0
    fi
    if archive_tool="$(xcrun --sdk macosx --find libtool 2>/dev/null)"; then
        printf '%s\n' "$archive_tool"
        return 0
    fi
    return 1
}

cmake_build() {
    local build_dir="$1"
    shift
    if [[ "${#cmake_generator_args[@]}" -gt 0 ]]; then
        cmake -S "$SCRIPT_DIR" -B "$build_dir" "${cmake_generator_args[@]}" "$@"
    else
        cmake -S "$SCRIPT_DIR" -B "$build_dir" "$@"
    fi
    cmake --build "$build_dir" --target attested_key_zk -j "$BUILD_JOBS"
}

build_macos_variant() {
    local variant_dir="$TARGETS_ROOT/macos-arm64"
    local output_lib="$variant_dir/libattested_key_zk.a"
    if [[ "$SKIP_BUILD" -eq 1 ]]; then
        assert_file "$output_lib"
        return 0
    fi

    local openssl_root
    if openssl_root="$(discover_brew_openssl_root)"; then
        :
    else
        ensure_openssl_source
        openssl_root="$variant_dir/openssl"
        if [[ ! -f "$openssl_root/lib/libcrypto.a" ]]; then
            local worktree="$variant_dir/openssl-src"
            local sdk_path
            sdk_path="$(xcrun --sdk macosx --show-sdk-path)"
            build_openssl_tree "$worktree" "$openssl_root" \
                CC="$(xcrun --sdk macosx --find clang)" \
                CXX="$(xcrun --sdk macosx --find clang++)" \
                CFLAGS="-arch arm64 -isysroot $sdk_path -mmacosx-version-min=$MACOS_DEPLOYMENT_TARGET" \
                CXXFLAGS="-arch arm64 -isysroot $sdk_path -mmacosx-version-min=$MACOS_DEPLOYMENT_TARGET" \
                AR="$(xcrun --sdk macosx --find ar)" \
                RANLIB="$(xcrun --sdk macosx --find ranlib)" \
                -- darwin64-arm64-cc
        fi
    fi

    if [[ ! -f "$variant_dir/cmake/libattested_key_zk.a" ]]; then
        cmake_build "$variant_dir/cmake" \
            "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" \
            -DCMAKE_OSX_ARCHITECTURES=arm64 \
            "-DCMAKE_OSX_DEPLOYMENT_TARGET=$MACOS_DEPLOYMENT_TARGET" \
            "-DATTESTED_KEY_ZK_OPENSSL_ROOT=$openssl_root"
    fi

    combine_archives "$(find_apple_archive_tool)" "$output_lib" \
        "$variant_dir/cmake/libattested_key_zk.a" \
        "$openssl_root/lib/libcrypto.a"
}

build_ios_variant() {
    local sdk="$1"
    local variant_name="$2"
    local configure_target="$3"
    local min_flag="$4"
    local variant_dir="$TARGETS_ROOT/$variant_name"
    local output_lib="$variant_dir/libattested_key_zk.a"
    if [[ "$SKIP_BUILD" -eq 1 ]]; then
        assert_file "$output_lib"
        return 0
    fi

    ensure_openssl_source
    local worktree="$variant_dir/openssl-src"
    local openssl_root="${variant_dir}/openssl"
    if [[ ! -f "$openssl_root/lib/libcrypto.a" ]]; then
        local sdk_path
        sdk_path="$(xcrun --sdk "$sdk" --show-sdk-path)"
        build_openssl_tree "$worktree" "$openssl_root" \
            CC="$(xcrun --sdk "$sdk" --find clang)" \
            CXX="$(xcrun --sdk "$sdk" --find clang++)" \
            CFLAGS="-arch arm64 -isysroot $sdk_path $min_flag" \
            CXXFLAGS="-arch arm64 -isysroot $sdk_path $min_flag" \
            AR="$(xcrun --sdk "$sdk" --find ar)" \
            RANLIB="$(xcrun --sdk "$sdk" --find ranlib)" \
            -- "$configure_target"
    fi
    if [[ ! -f "$variant_dir/cmake/libattested_key_zk.a" ]]; then
        cmake_build "$variant_dir/cmake" \
            "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" \
            -DCMAKE_SYSTEM_NAME=iOS \
            "-DCMAKE_OSX_SYSROOT=$sdk" \
            -DCMAKE_OSX_ARCHITECTURES=arm64 \
            "-DCMAKE_OSX_DEPLOYMENT_TARGET=$IOS_DEPLOYMENT_TARGET" \
            -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
            -DATTESTED_KEY_ZK_BUILD_TESTS=OFF \
            "-DATTESTED_KEY_ZK_OPENSSL_ROOT=$openssl_root"
    fi

    combine_archives "$(find_apple_archive_tool)" "$output_lib" \
        "$variant_dir/cmake/libattested_key_zk.a" \
        "$openssl_root/lib/libcrypto.a"
}

discover_android_ndk_root() {
    if [[ -n "${ATTESTED_KEY_ZK_ANDROID_NDK_ROOT:-}" ]]; then
        printf '%s\n' "$ATTESTED_KEY_ZK_ANDROID_NDK_ROOT"
        return 0
    fi
    if [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
        printf '%s\n' "$ANDROID_NDK_ROOT"
        return 0
    fi
    if [[ -d "${ANDROID_HOME:-}/ndk" ]]; then
        find "${ANDROID_HOME}/ndk" -maxdepth 1 -mindepth 1 -type d | sort | tail -1
        return 0
    fi
    if [[ -d "${ANDROID_SDK_ROOT:-}/ndk" ]]; then
        find "${ANDROID_SDK_ROOT}/ndk" -maxdepth 1 -mindepth 1 -type d | sort | tail -1
        return 0
    fi
    return 1
}

discover_android_toolchain_root() {
    local ndk_root="$1"
    find "$ndk_root/toolchains/llvm/prebuilt" -maxdepth 1 -mindepth 1 -type d | sort | head -1
}

build_android_variant() {
    local abi="$1"
    local triple_prefix="$2"
    local configure_target="$3"
    local variant_name="$4"
    local variant_dir="$TARGETS_ROOT/$variant_name"
    local output_lib="$variant_dir/libattested_key_zk.a"
    if [[ "$SKIP_BUILD" -eq 1 ]]; then
        assert_file "$output_lib"
        return 0
    fi

    local ndk_root
    ndk_root="$(discover_android_ndk_root)" || {
        echo "ERROR: Android NDK not found. Set ANDROID_NDK_ROOT or ANDROID_HOME." >&2
        exit 1
    }
    local toolchain_root
    toolchain_root="$(discover_android_toolchain_root "$ndk_root")"

    ensure_openssl_source
    local worktree="$variant_dir/openssl-src"
    local openssl_root="$variant_dir/openssl"
    local cc="$toolchain_root/bin/${triple_prefix}${ANDROID_API}-clang"
    local cxx="$toolchain_root/bin/${triple_prefix}${ANDROID_API}-clang++"
    if [[ ! -f "$openssl_root/lib/libcrypto.a" ]]; then
        build_openssl_tree "$worktree" "$openssl_root" \
            PATH="$toolchain_root/bin:$PATH" \
            ANDROID_NDK_ROOT="$ndk_root" \
            CC="$cc" \
            CXX="$cxx" \
            AR="$toolchain_root/bin/llvm-ar" \
            RANLIB="$toolchain_root/bin/llvm-ranlib" \
            -- "$configure_target" "-D__ANDROID_API__=$ANDROID_API"
    fi

    if [[ ! -f "$variant_dir/cmake/libattested_key_zk.a" ]]; then
        cmake_build "$variant_dir/cmake" \
            "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" \
            "-DCMAKE_TOOLCHAIN_FILE=$ndk_root/build/cmake/android.toolchain.cmake" \
            "-DANDROID_ABI=$abi" \
            "-DANDROID_PLATFORM=android-$ANDROID_API" \
            -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
            -DATTESTED_KEY_ZK_BUILD_TESTS=OFF \
            "-DATTESTED_KEY_ZK_OPENSSL_ROOT=$openssl_root"
    fi

    combine_archives "$toolchain_root/bin/llvm-ar" "$output_lib" \
        "$variant_dir/cmake/libattested_key_zk.a" \
        "$openssl_root/lib/libcrypto.a"
}

write_bundle_headers() {
    local headers_dir="$1"
    local module_name="$2"
    mkdir -p "$headers_dir/attested_key_zk"
    cp "$SCRIPT_DIR/include/attested_key_zk/approval_proof_v1_zk.h" \
        "$headers_dir/attested_key_zk/approval_proof_v1_zk.h"
    cat >"$headers_dir/module.modulemap" <<EOF
module ${module_name} {
  header "attested_key_zk/approval_proof_v1_zk.h"
  export *
}
EOF
}

emit_variant_json() {
    local path="$1"
    local triples="$2"
    local header_path="$3"
    cat <<EOF
                {
                    "path": "${path}",
                    "supportedTriples": [${triples}],
                    "headerPath": "${header_path}"
                }
EOF
}

echo "=== Building attested-key-zk artifact bundle (build type: $BUILD_TYPE) ==="
mkdir -p "$TARGETS_ROOT"

if [[ "$BUILD_APPLE" -eq 1 ]]; then
    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        require_cmd cmake
        require_cmd xcrun
        require_cmd python3
        require_cmd perl
    fi
    echo "--- Building Apple variants ---"
    build_ios_variant iphoneos ios-arm64 ios64-xcrun "-miphoneos-version-min=$IOS_DEPLOYMENT_TARGET"
    build_ios_variant iphonesimulator ios-arm64-simulator iossimulator-arm64-xcrun "-mios-simulator-version-min=$IOS_DEPLOYMENT_TARGET"
    build_macos_variant
fi

if [[ "$BUILD_ANDROID" -eq 1 ]]; then
    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        require_cmd cmake
        require_cmd python3
        require_cmd perl
    fi
    echo "--- Building Android variants ---"
    build_android_variant arm64-v8a aarch64-linux-android android-arm64 android-aarch64
    build_android_variant x86_64 x86_64-linux-android android-x86_64 android-x86_64
fi

echo "--- Assembling artifact bundle ---"
rm -rf "$BUNDLE_OUTPUT"
mkdir -p "$BUNDLE_OUTPUT"

cat >"$BUNDLE_OUTPUT/info.json" <<'INFOJSON'
{
    "schemaVersion": "1.0",
    "artifacts": {
INFOJSON

cat >>"$BUNDLE_OUTPUT/info.json" <<INFOJSON
        "${BINARY_TARGET_NAME}": {
            "version": "1.0.0",
            "type": "staticLibrary",
            "variants": [
INFOJSON

variants=()

if [[ "$BUILD_APPLE" -eq 1 ]]; then
    mkdir -p "$BUNDLE_OUTPUT/ios-arm64" "$BUNDLE_OUTPUT/ios-arm64-simulator" "$BUNDLE_OUTPUT/macos-arm64"
    cp "$TARGETS_ROOT/ios-arm64/libattested_key_zk.a" "$BUNDLE_OUTPUT/ios-arm64/"
    cp "$TARGETS_ROOT/ios-arm64-simulator/libattested_key_zk.a" "$BUNDLE_OUTPUT/ios-arm64-simulator/"
    cp "$TARGETS_ROOT/macos-arm64/libattested_key_zk.a" "$BUNDLE_OUTPUT/macos-arm64/"
    write_bundle_headers "$BUNDLE_OUTPUT/ios-arm64/headers" "$BINARY_TARGET_NAME"
    write_bundle_headers "$BUNDLE_OUTPUT/ios-arm64-simulator/headers" "$BINARY_TARGET_NAME"
    write_bundle_headers "$BUNDLE_OUTPUT/macos-arm64/headers" "$BINARY_TARGET_NAME"
    variants+=("$(emit_variant_json "ios-arm64/libattested_key_zk.a" '"aarch64-apple-ios"' "ios-arm64/headers")")
    variants+=("$(emit_variant_json "ios-arm64-simulator/libattested_key_zk.a" '"aarch64-apple-ios-simulator"' "ios-arm64-simulator/headers")")
    variants+=("$(emit_variant_json "macos-arm64/libattested_key_zk.a" '"arm64-apple-macosx"' "macos-arm64/headers")")
fi

if [[ "$BUILD_ANDROID" -eq 1 ]]; then
    android_triples_aarch64=""
    android_triples_x86_64=""
    for api in $(seq "$ANDROID_API" "$ANDROID_MAX_API"); do
        [[ -n "$android_triples_aarch64" ]] && android_triples_aarch64+=", "
        [[ -n "$android_triples_x86_64" ]] && android_triples_x86_64+=", "
        android_triples_aarch64+="\"aarch64-unknown-linux-android${api}\""
        android_triples_x86_64+="\"x86_64-unknown-linux-android${api}\""
    done
    mkdir -p "$BUNDLE_OUTPUT/android-aarch64" "$BUNDLE_OUTPUT/android-x86_64"
    cp "$TARGETS_ROOT/android-aarch64/libattested_key_zk.a" "$BUNDLE_OUTPUT/android-aarch64/"
    cp "$TARGETS_ROOT/android-x86_64/libattested_key_zk.a" "$BUNDLE_OUTPUT/android-x86_64/"
    write_bundle_headers "$BUNDLE_OUTPUT/android-aarch64/headers" "$BINARY_TARGET_NAME"
    write_bundle_headers "$BUNDLE_OUTPUT/android-x86_64/headers" "$BINARY_TARGET_NAME"
    variants+=("$(emit_variant_json "android-aarch64/libattested_key_zk.a" "$android_triples_aarch64" "android-aarch64/headers")")
    variants+=("$(emit_variant_json "android-x86_64/libattested_key_zk.a" "$android_triples_x86_64" "android-x86_64/headers")")
fi

first=1
for variant in "${variants[@]}"; do
    if [[ "$first" -eq 1 ]]; then
        first=0
    else
        echo "," >>"$BUNDLE_OUTPUT/info.json"
    fi
    printf '%s' "$variant" >>"$BUNDLE_OUTPUT/info.json"
done

cat >>"$BUNDLE_OUTPUT/info.json" <<'INFOJSON'
            ]
        }
    }
}
INFOJSON

echo "Artifact bundle written to $BUNDLE_OUTPUT"
