#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import plistlib
import subprocess
import sys


DEFAULT_XCFRAMEWORK_NAME = "AttestedKeyZKApple.xcframework"
REQUIRED_MODULE_DECLARATION = "module CAttestedKeyZKAppleBinary {"
REQUIRED_HEADER_DECLARATION = 'header "attested_key_zk/approval_proof_v1_zk.h"'
REQUIRED_SYMBOLS = {
    "_approval_proof_v1_circuit_generation_error_string",
    "_approval_proof_v1_circuit_id",
    "_approval_proof_v1_circuit_id_error_string",
    "_approval_proof_v1_free",
    "_approval_proof_v1_prover_error_string",
    "_approval_proof_v1_verifier_error_string",
    "_generate_approval_proof_v1_circuit",
    "_run_approval_proof_v1_prover_from_bytes",
    "_run_approval_proof_v1_verifier_from_bytes",
}
REQUIRED_LIBRARIES = {
    "ios-arm64": {
        "platform": "ios",
        "variant": None,
        "architectures": {"arm64"},
    },
    "ios-arm64-simulator": {
        "platform": "ios",
        "variant": "simulator",
        "architectures": {"arm64"},
    },
    "macos-arm64": {
        "platform": "macos",
        "variant": None,
        "architectures": {"arm64"},
    },
}


def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def library_symbols(library_path: pathlib.Path) -> set[str]:
    try:
        result = subprocess.run(
            ["nm", "-gU", str(library_path)],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return set()

    symbols: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts:
            symbols.add(parts[-1])
    return symbols


def main() -> int:
    script_dir = pathlib.Path(__file__).resolve().parent
    xcframework_dir = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) > 1
        else script_dir / DEFAULT_XCFRAMEWORK_NAME
    )
    info_path = xcframework_dir / "Info.plist"
    if not info_path.is_file():
        return fail(f"Apple XCFramework at {xcframework_dir} is missing Info.plist.")

    try:
        info = plistlib.loads(info_path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        return fail(f"Apple XCFramework Info.plist is not readable: {exc}")

    available = info.get("AvailableLibraries")
    if not isinstance(available, list):
        return fail("Apple XCFramework Info.plist is missing AvailableLibraries.")

    by_identifier = {
        library.get("LibraryIdentifier"): library
        for library in available
        if isinstance(library, dict)
    }
    missing_identifiers = set(REQUIRED_LIBRARIES) - set(by_identifier)
    if missing_identifiers:
        return fail(f"Apple XCFramework is missing libraries: {sorted(missing_identifiers)}")

    for identifier, expected in REQUIRED_LIBRARIES.items():
        library = by_identifier[identifier]
        if library.get("SupportedPlatform") != expected["platform"]:
            return fail(f"{identifier} has unexpected platform {library.get('SupportedPlatform')!r}")
        if library.get("SupportedPlatformVariant") != expected["variant"]:
            return fail(
                f"{identifier} has unexpected platform variant "
                f"{library.get('SupportedPlatformVariant')!r}"
            )
        architectures = set(library.get("SupportedArchitectures", []))
        if not expected["architectures"].issubset(architectures):
            return fail(f"{identifier} is missing architectures: {sorted(expected['architectures'] - architectures)}")

        library_path = xcframework_dir / identifier / "libattested_key_zk.a"
        if not library_path.is_file() or library_path.stat().st_size == 0:
            return fail(f"{identifier} is missing libattested_key_zk.a")

        header_path = xcframework_dir / identifier / "Headers" / "attested_key_zk" / "approval_proof_v1_zk.h"
        if not header_path.is_file():
            return fail(f"{identifier} is missing approval_proof_v1_zk.h")
        modulemap_path = xcframework_dir / identifier / "Headers" / "module.modulemap"
        if not modulemap_path.is_file():
            return fail(f"{identifier} is missing module.modulemap")
        modulemap_contents = modulemap_path.read_text(encoding="utf-8")
        if REQUIRED_MODULE_DECLARATION not in modulemap_contents:
            return fail(f"{identifier} module.modulemap has the wrong module name")
        if REQUIRED_HEADER_DECLARATION not in modulemap_contents:
            return fail(f"{identifier} module.modulemap does not export the public header")

        missing_symbols = REQUIRED_SYMBOLS - library_symbols(library_path)
        if missing_symbols:
            return fail(f"{identifier} is missing required symbols: {sorted(missing_symbols)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
