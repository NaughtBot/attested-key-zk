#!/usr/bin/env bash
set -euo pipefail

# Usage: scripts/release.sh <patch|minor|major|X.Y.Z>
# Env:
#   PUSH=1        push tags to REMOTE after creating them
#   REMOTE=origin git remote to fetch/push from
#   MAIN_BRANCH=main branch that releases must be cut from

VERSION_ARG="${1:-}"
PUSH="${PUSH:-0}"
REMOTE="${REMOTE:-origin}"
MAIN_BRANCH="${MAIN_BRANCH:-main}"

usage() {
  cat >&2 <<EOF
Usage: make release VERSION=<patch|minor|major|X.Y.Z> [PUSH=1]

Creates annotated tags vX.Y.Z and bindings/go/vX.Y.Z on HEAD.

VERSION:
  patch      bump latest v* tag's patch component (e.g., v0.1.2 -> v0.1.3)
  minor      bump minor, reset patch       (e.g., v0.1.2 -> v0.2.0)
  major      bump major, reset minor+patch (e.g., v0.1.2 -> v1.0.0)
  X.Y.Z      use this literal version

Optional:
  PUSH=1     push the tags to '$REMOTE' after creating (triggers CI release)
EOF
}

if [[ -z "$VERSION_ARG" ]]; then
  usage
  exit 1
fi

if [[ "$VERSION_ARG" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  NEW="$VERSION_ARG"
elif [[ "$VERSION_ARG" =~ ^(patch|minor|major)$ ]]; then
  LATEST=$(git tag -l 'v*' --sort=-v:refname \
    | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
    | head -n 1 || true)
  if [[ -z "$LATEST" ]]; then
    echo "Error: no v* tag found to bump from. Specify VERSION=X.Y.Z explicitly." >&2
    exit 1
  fi
  CURRENT="${LATEST#v}"
  IFS='.' read -r MAJ MIN PAT <<<"$CURRENT"
  case "$VERSION_ARG" in
    major) MAJ=$((MAJ + 1)); MIN=0; PAT=0 ;;
    minor) MIN=$((MIN + 1)); PAT=0 ;;
    patch) PAT=$((PAT + 1)) ;;
  esac
  NEW="$MAJ.$MIN.$PAT"
else
  echo "Error: VERSION must be 'patch', 'minor', 'major', or X.Y.Z (got: '$VERSION_ARG')" >&2
  echo >&2
  usage
  exit 1
fi

ROOT_TAG="v$NEW"
GO_TAG="bindings/go/v$NEW"

echo "==> Running pre-flight checks for release $NEW..."

if ! git diff-index --quiet HEAD -- || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "Error: working tree has uncommitted changes or untracked files." >&2
  echo "Commit, stash, or clean them before releasing." >&2
  exit 1
fi

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "$CURRENT_BRANCH" != "$MAIN_BRANCH" ]]; then
  echo "Error: must be on '$MAIN_BRANCH' to release (currently on '$CURRENT_BRANCH')." >&2
  exit 1
fi

echo "==> Fetching $REMOTE..."
git fetch "$REMOTE" "$MAIN_BRANCH" --tags --quiet

LOCAL_HEAD=$(git rev-parse HEAD)
REMOTE_HEAD=$(git rev-parse "$REMOTE/$MAIN_BRANCH")
if [[ "$LOCAL_HEAD" != "$REMOTE_HEAD" ]]; then
  echo "Error: local '$MAIN_BRANCH' is not in sync with '$REMOTE/$MAIN_BRANCH'." >&2
  echo "  local:  $LOCAL_HEAD" >&2
  echo "  remote: $REMOTE_HEAD" >&2
  echo "Pull or push as appropriate, then re-run." >&2
  exit 1
fi

for TAG in "$ROOT_TAG" "$GO_TAG"; do
  if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Error: tag '$TAG' already exists locally." >&2
    exit 1
  fi
  if git ls-remote --tags --exit-code "$REMOTE" "refs/tags/$TAG" >/dev/null 2>&1; then
    echo "Error: tag '$TAG' already exists on '$REMOTE'." >&2
    exit 1
  fi
done

COMMIT_SHORT=$(git rev-parse --short HEAD)
COMMIT_SUBJECT=$(git log -1 --format=%s)

echo
echo "Releasing $NEW"
echo "  Commit:   $COMMIT_SHORT  $COMMIT_SUBJECT"
echo "  Tags:     $ROOT_TAG, $GO_TAG"
echo

git tag -a "$ROOT_TAG" -m "Release $ROOT_TAG"
git tag -a "$GO_TAG" -m "Release $GO_TAG"
echo "==> Created tags locally."

if [[ "$PUSH" == "1" ]]; then
  echo "==> Pushing tags to $REMOTE..."
  git push "$REMOTE" "$ROOT_TAG" "$GO_TAG"
  echo "==> Pushed. CI release workflow should now be running."
else
  cat <<EOF

To trigger the release on CI, push the tags:
  git push $REMOTE $ROOT_TAG $GO_TAG

(Or run again with PUSH=1, e.g., \`make release VERSION=$VERSION_ARG PUSH=1\`)
To undo locally: git tag -d $ROOT_TAG $GO_TAG
EOF
fi
