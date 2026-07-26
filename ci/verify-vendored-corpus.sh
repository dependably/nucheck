#!/bin/sh
# Verify a vendored conformance corpus still matches the commit it claims to be pinned at.
#
# Six Dependably tools each vendor a copy of conformance/dependably/ from the spec repo
# (https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec) and record the commit they
# copied it from in a VENDOR.md beside it. VENDOR.md records that provenance but proves
# nothing by itself — nothing stops the vendored files from drifting (edited by hand, a
# case lost in a bad merge, a partial re-vendor) while VENDOR.md still claims the old pin.
# That happened once already, silently, for months. This script is the check that closes
# the gap: it clones the spec repo, checks out the exact commit VENDOR.md names, and diffs
# it against the local copy.
#
# What this deliberately does NOT do: fail because the spec repo's main has moved past the
# pinned commit. Sitting on an older commit is a legitimate, ordinary choice — that is what
# pinning means. This only fails when the local copy no longer matches its OWN declared pin.
#
# Usage:
#   verify-vendored-corpus.sh <vendored-dir>
#
# <vendored-dir> is the directory containing VENDOR.md and a dependably/ subdirectory, e.g.
# tests/conformance or tests/CsLint.Tests/conformance. Requires git and diff on PATH.

set -eu

SPEC_REPO="${DEPENDABLY_SPEC_REPO:-https://gitlab.northwardlabs.ca/moonlitlabs/dependably-spec.git}"
DEST="${1:-}"

if [ -z "$DEST" ]; then
  echo "usage: verify-vendored-corpus.sh <vendored-dir>" >&2
  exit 2
fi

VENDOR_FILE="$DEST/VENDOR.md"
if [ ! -f "$VENDOR_FILE" ]; then
  echo "ERROR: $VENDOR_FILE is missing." >&2
  echo "There is no pin to verify against — a vendored corpus without VENDOR.md has no" >&2
  echo "recorded provenance at all. Re-vendor with the spec repo's tools/vendor.sh." >&2
  exit 1
fi

# The commit line looks like: | Commit | \`aa8782989ffd87ea66b65e677c2e7dbd739e0ccf\` |
SHA="$(grep -i 'commit' "$VENDOR_FILE" | grep -oE '[0-9a-f]{40}' | head -n 1 || true)"
if [ -z "$SHA" ]; then
  echo "ERROR: could not find a parseable 40-character commit SHA in $VENDOR_FILE." >&2
  echo "Expected a line such as: | Commit | \`<sha>\` |" >&2
  exit 1
fi

if [ ! -d "$DEST/dependably" ]; then
  echo "ERROR: $DEST/dependably does not exist — nothing to verify against pin $SHA." >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "Pinned commit (from $VENDOR_FILE): $SHA"
echo "Fetching $SPEC_REPO ..."
# A full clone, not shallow: the pin can be any historical commit, and a shallow clone
# would only ever have HEAD available to check out. The spec repo is small (a handful of
# commits, well under a megabyte), so this costs nothing worth trimming.
if ! git clone --quiet "$SPEC_REPO" "$WORK/spec"; then
  echo "ERROR: failed to clone $SPEC_REPO." >&2
  exit 1
fi

if ! git -C "$WORK/spec" checkout --quiet "$SHA" 2>/dev/null; then
  echo "ERROR: commit $SHA (pinned in $VENDOR_FILE) does not exist in $SPEC_REPO." >&2
  echo "VENDOR.md is pointing at a commit the spec repo doesn't have — fix the pin." >&2
  exit 1
fi

UPSTREAM_DIR="$WORK/spec/conformance/dependably"
if [ ! -d "$UPSTREAM_DIR" ]; then
  echo "ERROR: $SPEC_REPO@$SHA has no conformance/dependably/ directory — cannot verify." >&2
  exit 1
fi

if ! diff -rq "$UPSTREAM_DIR" "$DEST/dependably" >"$WORK/diff.summary" 2>&1; then
  echo "ERROR: $DEST/dependably has drifted from its pinned commit." >&2
  echo "$VENDOR_FILE claims $SHA, but the vendored files no longer match what that" >&2
  echo "commit actually contains. Either this copy was edited or partially lost locally," >&2
  echo "or the pin is stale. Re-sync with the spec repo's tools/vendor.sh, or correct" >&2
  echo "VENDOR.md to record the commit that was actually vendored." >&2
  echo >&2
  echo "--- summary (upstream@$SHA vs. $DEST/dependably) ---" >&2
  cat "$WORK/diff.summary" >&2
  echo >&2
  echo "--- full diff ---" >&2
  diff -ru "$UPSTREAM_DIR" "$DEST/dependably" >&2 || true
  exit 1
fi

echo "OK: $DEST/dependably matches $SPEC_REPO@$SHA."
