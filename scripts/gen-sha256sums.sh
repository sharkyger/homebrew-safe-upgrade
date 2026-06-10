#!/bin/bash
# Regenerate (or --check) the SHA256SUMS manifest for the script-install route.
#
# SHA256SUMS is the authoritative list of files install.sh downloads and
# verifies. Run this after changing any shipped file (and always after a
# version bump, which rewrites VERSION):
#
#   scripts/gen-sha256sums.sh           # rewrite SHA256SUMS in place
#   scripts/gen-sha256sums.sh --check   # exit non-zero if it is out of date (CI)
#
# The pytest suite (tests/test_install_manifest.py) enforces the same invariant,
# so a stale manifest fails CI either way.

set -euo pipefail

cd "$(dirname "$0")/.."

# Canonical script-install set — the files install.sh deploys into Homebrew bin.
# Keep sorted; install.sh derives its download list from the generated manifest.
FILES=(
    VERSION
    bottle_resolver.py
    brew-safe-install
    brew-safe-update
    brew-safe-upgrade
    cask_nvd_map.py
    dependency_security_check.py
)

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}

generate() {
    for f in "${FILES[@]}"; do
        sha256_of "$f"
    done
}

if [ "${1:-}" = "--check" ]; then
    if ! generate | diff -u SHA256SUMS - >/dev/null 2>&1; then
        echo "SHA256SUMS is out of date — run scripts/gen-sha256sums.sh" >&2
        exit 1
    fi
    echo "SHA256SUMS is up to date."
else
    generate >SHA256SUMS
    echo "Wrote SHA256SUMS (${#FILES[@]} files)."
fi
