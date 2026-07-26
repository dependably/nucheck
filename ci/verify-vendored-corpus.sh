#!/bin/sh
# Verify a vendored conformance corpus against the checksums recorded when it was copied.
#
# Vendor this script into each consuming repository alongside the corpus and run it in CI.
#
# It deliberately does not contact the spec repository. An earlier version cloned the pinned
# commit and diffed against it, which failed for two reasons worth remembering: the spec
# repository is private, so CI has no credentials for it, and half the consuming repositories
# run CI on a forge that cannot reach it at all. Checking against a manifest written at copy
# time needs no network and no credentials, so it runs everywhere and on every pipeline.
#
# What this catches: a vendored file edited, added or deleted in place after copying — the
# drift that went unnoticed for months and motivated the whole arrangement.
#
# What it does not catch: someone re-running the vendor script and committing the result. That
# is a deliberate update rather than drift, and VENDOR.md records which commit it came from.
#
# Usage:  verify-vendored-corpus.sh <conformance-dir>
#   e.g.  verify-vendored-corpus.sh tests/MyTool.Tests/conformance

set -eu

DIR="${1:-}"

if [ -z "$DIR" ]; then
    echo "usage: verify-vendored-corpus.sh <conformance-dir>" >&2
    exit 2
fi

MANIFEST="$DIR/corpus.sha256"
CORPUS="$DIR/dependably"

if [ ! -d "$CORPUS" ]; then
    echo "ERROR: $CORPUS is missing. The conformance corpus is not vendored here." >&2
    exit 1
fi

if [ ! -f "$DIR/VENDOR.md" ]; then
    echo "ERROR: $DIR/VENDOR.md is missing, so there is no record of what this copy came from." >&2
    exit 1
fi

if [ ! -f "$MANIFEST" ]; then
    echo "ERROR: $MANIFEST is missing." >&2
    echo "Re-run the vendor script to regenerate it; without a manifest this copy cannot be verified." >&2
    exit 1
fi

# shasum on macOS, sha256sum on most CI images. Resolve once rather than per file.
if command -v sha256sum >/dev/null 2>&1; then
    hash_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    hash_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    echo "ERROR: neither sha256sum nor shasum is available." >&2
    exit 2
fi

PINNED="$(sed -n 's/^| Commit | `\(.*\)` |$/\1/p' "$DIR/VENDOR.md" | head -1)"
echo "Verifying $CORPUS against $MANIFEST (pinned ${PINNED:-unknown})"

FAILED=0

# Every file the manifest names must exist and still hash the same.
while IFS= read -r line; do
    [ -n "$line" ] || continue
    expected=${line%% *}
    path=${line#* }
    path=${path# }

    if [ ! -f "$CORPUS/$path" ]; then
        echo "  MISSING   $path" >&2
        FAILED=1
        continue
    fi

    actual="$(hash_of "$CORPUS/$path")"
    if [ "$actual" != "$expected" ]; then
        echo "  MODIFIED  $path" >&2
        echo "            expected $expected" >&2
        echo "            actual   $actual" >&2
        FAILED=1
    fi
done < "$MANIFEST"

# And nothing may be present that the manifest does not name, or a file could be added here
# and silently diverge from every other copy.
( cd "$CORPUS" && find . -type f | sed 's|^\./||' | LC_ALL=C sort ) > /tmp/.corpus-actual.$$
cut -d' ' -f3- "$MANIFEST" | sed 's/^ *//' | LC_ALL=C sort > /tmp/.corpus-expected.$$

while IFS= read -r path; do
    if ! grep -Fxq "$path" /tmp/.corpus-expected.$$; then
        echo "  UNTRACKED $path" >&2
        FAILED=1
    fi
done < /tmp/.corpus-actual.$$

rm -f /tmp/.corpus-actual.$$ /tmp/.corpus-expected.$$

if [ "$FAILED" -ne 0 ]; then
    echo >&2
    echo "ERROR: the vendored corpus does not match the checksums recorded when it was copied." >&2
    echo "Either restore the files, or re-run the vendor script if you meant to update the pin." >&2
    exit 1
fi

echo "OK: $(wc -l < "$MANIFEST" | tr -d ' ') files match."
