#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import pathlib
import sys


REQUIRED_TRIPLE_PREFIXES = {
    "aarch64-unknown-linux-android",
    "x86_64-unknown-linux-android",
}
REQUIRED_MODULE_DECLARATION = "module CAttestedKeyZKAndroidBinary {"
REQUIRED_HEADER_DECLARATION = 'header "attested_key_zk/approval_proof_v1_zk.h"'
REQUIRED_ARTIFACT_KEY = "CAttestedKeyZKAndroidBinary"
DEFAULT_BUNDLE_NAME = "AttestedKeyZKAndroid.artifactbundle"
PLACEHOLDER_MARKER = os.environ.get(
    "ATTESTED_KEY_ZK_SWIFTPM_PLACEHOLDER_MARKER",
    ".swiftpm-placeholder",
)


def main() -> int:
    script_dir = pathlib.Path(__file__).resolve().parent
    bundle_dir = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else script_dir / DEFAULT_BUNDLE_NAME
    )
    marker = bundle_dir / PLACEHOLDER_MARKER
    if marker.exists():
        print(
            f"ERROR: Android artifact bundle at {bundle_dir} contains "
            f"placeholder marker {PLACEHOLDER_MARKER}; this bundle is a "
            "stub and must not be released.",
            file=sys.stderr,
        )
        return 1
    info_path = bundle_dir / "info.json"

    if not info_path.is_file():
        print(
            f"ERROR: Android artifact bundle at {bundle_dir} is missing "
            "info.json.",
            file=sys.stderr,
        )
        return 1

    try:
        bundle = json.loads(info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"ERROR: Android artifact bundle info.json at {info_path} is "
            f"not readable JSON: {exc}",
            file=sys.stderr,
        )
        return 1

    variants = (
        bundle.get("artifacts", {})
        .get(REQUIRED_ARTIFACT_KEY, {})
        .get("variants", [])
    )

    seen_prefixes: set[str] = set()
    for variant in variants:
        library_path = variant.get("path")
        static_library_metadata = variant.get("staticLibraryMetadata")
        if not isinstance(library_path, str) or not isinstance(static_library_metadata, dict):
            continue
        header_paths = static_library_metadata.get("headerPaths")
        module_map_path = static_library_metadata.get("moduleMapPath")
        if (
            not isinstance(header_paths, list)
            or not header_paths
            or not all(isinstance(path, str) for path in header_paths)
            or not isinstance(module_map_path, str)
        ):
            continue

        library_file = bundle_dir / library_path
        if not library_file.is_file() or library_file.stat().st_size == 0:
            continue
        headers_dirs = [bundle_dir / header_path for header_path in header_paths]
        if not any(
            (headers_dir / "attested_key_zk" / "approval_proof_v1_zk.h").is_file()
            for headers_dir in headers_dirs
        ):
            continue
        modulemap_path = bundle_dir / module_map_path
        if not modulemap_path.is_file():
            continue
        try:
            modulemap_contents = modulemap_path.read_text(encoding="utf-8")
        except OSError:
            continue
        if REQUIRED_MODULE_DECLARATION not in modulemap_contents:
            continue
        if REQUIRED_HEADER_DECLARATION not in modulemap_contents:
            continue

        for triple in variant.get("supportedTriples", []):
            if not isinstance(triple, str):
                continue
            for prefix in REQUIRED_TRIPLE_PREFIXES:
                if triple.startswith(prefix):
                    seen_prefixes.add(prefix)

    missing = REQUIRED_TRIPLE_PREFIXES - seen_prefixes
    if missing:
        print(
            f"ERROR: Android artifact bundle at {bundle_dir} is missing "
            f"required triple prefixes: {sorted(missing)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
