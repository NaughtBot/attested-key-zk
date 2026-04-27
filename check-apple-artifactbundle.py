#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import pathlib
import sys


REQUIRED_TRIPLES = {
    "aarch64-apple-ios",
    "aarch64-apple-ios-simulator",
    "arm64-apple-macosx",
}
REQUIRED_MODULE_DECLARATION = "module CAttestedKeyZKAppleBinary {"
REQUIRED_HEADER_DECLARATION = 'header "attested_key_zk/approval_proof_v1_zk.h"'
REQUIRED_ARTIFACT_KEY = "CAttestedKeyZKAppleBinary"
DEFAULT_BUNDLE_NAME = "AttestedKeyZKApple.artifactbundle"
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
            f"ERROR: Apple artifact bundle at {bundle_dir} contains "
            f"placeholder marker {PLACEHOLDER_MARKER}; this bundle is a "
            "stub and must not be released.",
            file=sys.stderr,
        )
        return 1
    info_path = bundle_dir / "info.json"

    if not info_path.is_file():
        print(
            f"ERROR: Apple artifact bundle at {bundle_dir} is missing info.json.",
            file=sys.stderr,
        )
        return 1

    try:
        bundle = json.loads(info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"ERROR: Apple artifact bundle info.json at {info_path} is not "
            f"readable JSON: {exc}",
            file=sys.stderr,
        )
        return 1

    variants = (
        bundle.get("artifacts", {})
        .get(REQUIRED_ARTIFACT_KEY, {})
        .get("variants", [])
    )

    seen_triples: set[str] = set()
    for variant in variants:
        library_path = variant.get("path")
        header_path = variant.get("headerPath")
        if not isinstance(library_path, str) or not isinstance(header_path, str):
            continue

        library_file = bundle_dir / library_path
        headers_dir = bundle_dir / header_path
        if not library_file.is_file():
            continue
        if not (headers_dir / "attested_key_zk" / "approval_proof_v1_zk.h").is_file():
            continue
        modulemap_path = headers_dir / "module.modulemap"
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
            if triple in REQUIRED_TRIPLES:
                seen_triples.add(triple)

    missing = REQUIRED_TRIPLES - seen_triples
    if missing:
        print(
            f"ERROR: Apple artifact bundle at {bundle_dir} is missing "
            f"required triples: {sorted(missing)}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
