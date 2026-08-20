#!/usr/bin/env bash
# Build and run the age-check dogfood container. See README.md.
#
# Usage: scripts/dogfood-age-check/run.sh <pkgs.tsv>
#
# <pkgs.tsv> is "<name>\t<formula|cask>\t<target version>" per line, normally
# produced from `brew outdated --json=v2` on the host.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PKGS="${1:-}"

if [ -z "$PKGS" ] || [ ! -s "$PKGS" ]; then
    echo "usage: $0 <pkgs.tsv>   (see $HERE/README.md)" >&2
    exit 2
fi

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT

# Extract the age-resolution functions from the real script rather than keeping
# a copy: a stale duplicate would measure code that is no longer shipped.
start=$(grep -n '^resolve_gh_token() {' "$REPO/brew-safe-upgrade" | cut -d: -f1)
fstart=$(grep -n '^fetch_pkg_age() {' "$REPO/brew-safe-upgrade" | cut -d: -f1)
fend=$(awk -v s="$fstart" 'NR>=s && /^}$/{print NR; exit}' "$REPO/brew-safe-upgrade")
if [ -z "$start" ] || [ -z "$fend" ]; then
    echo "could not locate the age functions" >&2
    exit 1
fi
sed -n "${start},${fend}p" "$REPO/brew-safe-upgrade" >"$BUILD/age_funcs.sh"
bash -n "$BUILD/age_funcs.sh" || {
    echo "extracted functions do not parse" >&2
    exit 1
}

cp "$HERE/Dockerfile" "$HERE/driver.sh" "$BUILD/"
cp "$PKGS" "$BUILD/pkgs.tsv"

docker build -q -t age-dogfood "$BUILD" >/dev/null
exec docker run --rm age-dogfood
