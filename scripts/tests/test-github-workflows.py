#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import sys


WORKFLOWS = (
    pathlib.Path(".github/workflows/ci.yml"),
    pathlib.Path(".github/workflows/release.yml"),
)
NATIVE_CACHE_ACTIONS = (
    pathlib.Path(".github/actions/setup-attested-key-zk/action.yml"),
)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def require_order(
    errors: list[str],
    workflow: pathlib.Path,
    text: str,
    earlier: str,
    later: str,
) -> None:
    earlier_index = text.find(earlier)
    later_index = text.find(later)
    if earlier_index == -1:
        errors.append(f"{workflow}: missing {earlier!r}")
        return
    if later_index == -1:
        errors.append(f"{workflow}: missing {later!r}")
        return
    if earlier_index > later_index:
        errors.append(f"{workflow}: expected {earlier!r} before {later!r}")


def main() -> int:
    errors: list[str] = []

    for workflow in WORKFLOWS:
        text = (REPO_ROOT / workflow).read_text(encoding="utf-8")

        if "runs-on: macos-latest" in text:
            errors.append(
                f"{workflow}: Apple artifact bundle jobs must use macos-26"
            )
        if "runs-on: macos-26" not in text:
            errors.append(
                f"{workflow}: expected an Apple artifact bundle job on macos-26"
            )
        if "cache: pnpm" in text:
            errors.append(
                f"{workflow}: setup-node pnpm cache requires pnpm before setup-node runs"
            )

        require_order(errors, workflow, text, "corepack enable", "make test-wasm")

    for action in NATIVE_CACHE_ACTIONS:
        text = (REPO_ROOT / action).read_text(encoding="utf-8")
        if "restore-keys:" in text:
            errors.append(
                f"{action}: native build-output cache must not use restore-keys; "
                "partial cache matches can restore stale artifact bundles"
            )

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
