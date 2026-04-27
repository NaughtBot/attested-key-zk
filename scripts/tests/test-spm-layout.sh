#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

python3 - <<'PY' "$REPO_ROOT"
import json
import subprocess
import sys

package_dir = sys.argv[1]
result = subprocess.run(
    ["swift", "package", "dump-package", "--package-path", package_dir],
    check=True,
    capture_output=True,
    text=True,
)
data = json.loads(result.stdout)
targets = {target["name"]: target for target in data["targets"]}

apple_binary = targets.get("CAttestedKeyZKAppleBinary")
if apple_binary is None or apple_binary.get("type") != "binary":
    raise SystemExit("expected CAttestedKeyZKAppleBinary binary target")
if apple_binary.get("path") != "AttestedKeyZKApple.artifactbundle":
    raise SystemExit("expected Apple artifact bundle binary target path")

android_binary = targets.get("CAttestedKeyZKAndroidBinary")
if android_binary is None or android_binary.get("type") != "binary":
    raise SystemExit("expected CAttestedKeyZKAndroidBinary binary target")
if android_binary.get("path") != "AttestedKeyZKAndroid.artifactbundle":
    raise SystemExit("expected Android artifact bundle binary target path")

with open(f"{package_dir}/AttestedKeyZKApple.artifactbundle/info.json", "r", encoding="utf-8") as f:
    artifact_bundle = json.load(f)

artifacts = artifact_bundle.get("artifacts", {})
if set(artifacts.keys()) != {"CAttestedKeyZKAppleBinary"}:
    raise SystemExit(f"unexpected artifact bundle keys: {sorted(artifacts.keys())}")

c_target = targets.get("CAttestedKeyZK")
if c_target is None or c_target.get("type") != "regular":
    raise SystemExit("expected CAttestedKeyZK regular target")
if c_target.get("path") != "Sources/CAttestedKeyZK":
    raise SystemExit("expected CAttestedKeyZK to use Sources/CAttestedKeyZK")
if c_target.get("publicHeadersPath") != "include":
    raise SystemExit("expected CAttestedKeyZK publicHeadersPath to be include")

swift_target = targets.get("AttestedKeyZK")
if swift_target is None or swift_target.get("type") != "regular":
    raise SystemExit("expected AttestedKeyZK regular target")

deps = {}
for dep in swift_target.get("dependencies", []):
    if "byName" in dep:
        name, condition = dep["byName"]
        deps[name] = condition
    elif "target" in dep:
        name, condition = dep["target"]
        deps[name] = condition

if set(deps) != {"CAttestedKeyZK", "CAttestedKeyZKAppleBinary", "CAttestedKeyZKAndroidBinary"}:
    raise SystemExit(f"unexpected AttestedKeyZK dependencies: {sorted(deps)}")
if deps["CAttestedKeyZK"] is not None:
    raise SystemExit("expected CAttestedKeyZK dependency to be unconditional")

apple_condition = deps["CAttestedKeyZKAppleBinary"]
if apple_condition is None or sorted(apple_condition.get("platformNames", [])) != ["ios", "macos"]:
    raise SystemExit(f"unexpected Apple binary target condition: {apple_condition}")

android_condition = deps["CAttestedKeyZKAndroidBinary"]
if android_condition is None or android_condition.get("platformNames") != ["android"]:
    raise SystemExit(f"unexpected Android binary target condition: {android_condition}")
PY

if [[ ! -f "$REPO_ROOT/Sources/CAttestedKeyZK/shim.c" ]]; then
    echo "expected Sources/CAttestedKeyZK/shim.c placeholder translation unit" >&2
    exit 1
fi

if command -v rg >/dev/null 2>&1; then
    if rg -n 'unsafeFlags|"-L"' "$REPO_ROOT/Package.swift" >/dev/null; then
        echo "root Package.swift should not contain unsafe linker flags" >&2
        exit 1
    fi
    if rg -n 'link "attested_key_zk"' "$REPO_ROOT/Sources/CAttestedKeyZK/include/module.modulemap" >/dev/null; then
        echo "module.modulemap should not link attested_key_zk directly" >&2
        exit 1
    fi
elif grep -n 'unsafeFlags\|"-L"' "$REPO_ROOT/Package.swift" >/dev/null; then
    echo "root Package.swift should not contain unsafe linker flags" >&2
    exit 1
fi
