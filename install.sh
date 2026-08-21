#!/bin/bash
# Install brew-safe-upgrade (script route)
# Usage: curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | bash
#
# This installer is supply-chain hardened:
#   * Files are pulled from a PINNED, immutable release tag — never a moving
#     branch — so a curl|bash run always gets exactly one published release,
#     not whatever happens to be on `main` at that instant.
#   * A signed-off `SHA256SUMS` manifest (published at the same tag) is the
#     source of truth for which files make up a release. Every file is
#     downloaded to a staging area and checksum-verified before anything is
#     written into your Homebrew bin. A truncated download, a CDN/MITM tamper,
#     or a missing file aborts the whole install — there is no partial state.
#
# Trust model (honest): the manifest and the files are fetched over the same
# TLS channel, so the checksums are defense-in-depth (integrity of the
# transfer + immutability of the tag), not a substitute for TLS. The brew
# formula route (`brew install sharkyger/tap/safe-upgrade`) remains the
# strongest path and cannot strand or partially install.
#
# Override the release for testing:  SAFE_UPGRADE_REF=my-branch bash install.sh

set -euo pipefail

# --- pinned release ----------------------------------------------------------
# Bumped on every release (kept in lockstep with the VERSION file). The tag
# v<PINNED_REF without leading v> must exist before curl|bash users are pointed
# at the matching install.sh.
PINNED_REF="v0.3.2"
REF="${SAFE_UPGRADE_REF:-$PINNED_REF}"

# Download base. Defaults to GitHub raw; SAFE_UPGRADE_BASE_URL lets a hermetic
# smoke test point the installer at a local server (and, only then, relaxes the
# https-only transport guard below). Production runs never set it.
BASE_URL="${SAFE_UPGRADE_BASE_URL:-https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade}"
REPO_RAW="${BASE_URL}/${REF}"
# Install prefix. Defaults to the Homebrew prefix; SAFE_UPGRADE_PREFIX lets the
# hermetic smoke install into a throwaway dir without touching brew.
PREFIX="${SAFE_UPGRADE_PREFIX:-$(brew --prefix 2>/dev/null || echo "/opt/homebrew")}"
INSTALL_DIR="${PREFIX}/bin"

# Curl options. Kept non-empty (bash 3.2 errors on `"${empty[@]}"` under set -u).
# Strict HTTPS-only transport for real installs; relaxed only when a test base
# URL is set, so a hermetic smoke can serve over http/file.
CURL_OPTS=(-fsSL --retry 3)
if [ -z "${SAFE_UPGRADE_BASE_URL:-}" ]; then
    CURL_OPTS+=(--proto '=https' --tlsv1.2)
fi

# Files that need the execute bit (the user-facing commands). Helper modules
# (*.py) and VERSION are imported/read, never exec'd directly.
EXECUTABLES=(brew-safe-upgrade brew-safe-install brew-safe-update)

echo "Installing brew-safe-upgrade (release ${REF})..."

# --- preflight ---------------------------------------------------------------
if [ ! -w "$INSTALL_DIR" ]; then
    echo "Error: No write permission to $INSTALL_DIR"
    echo "Try: sudo bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh)\""
    echo "Or:  git clone https://github.com/sharkyger/homebrew-safe-upgrade.git && cd homebrew-safe-upgrade && sudo cp brew-safe-upgrade brew-safe-install brew-safe-update dependency_security_check.py bottle_resolver.py cask_nvd_map.py VERSION $INSTALL_DIR/"
    exit 1
fi

fetch() {
    # Fail-closed download: fail on HTTP errors, bounded retries, HTTPS-only in
    # production (see CURL_OPTS).
    curl "${CURL_OPTS[@]}" "$1" -o "$2"
}

verify_checksums() {
    # Verifies every file listed in SHA256SUMS against the staged copies in cwd.
    # Returns non-zero if any file is missing or its hash does not match.
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c SHA256SUMS
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c SHA256SUMS
    else
        echo "Error: no sha256sum/shasum available to verify the download" >&2
        return 1
    fi
}

# --- staged, verified download ----------------------------------------------
# Stage ON THE SAME FILESYSTEM as the install dir, so the final swap is an atomic
# rename per file (no cross-device copy that could half-write on ENOSPC). The
# install dir was just confirmed writable.
STAGING="$(mktemp -d "${INSTALL_DIR}/.safe-upgrade-install.XXXXXX")"
cleanup() { rm -rf "$STAGING"; }
trap cleanup EXIT

# 1. Pull the manifest first — it is the authoritative list of release files.
fetch "$REPO_RAW/SHA256SUMS" "$STAGING/SHA256SUMS"

# 2. Completeness floor: a truncated/incomplete manifest must NEVER yield a
#    partial install reported as success (the lesson from the helper-strand
#    incident). The installer's whole purpose is the brew-safe-* commands, so
#    require every one of them to be present in the manifest before trusting it.
for exe in "${EXECUTABLES[@]}"; do
    if ! grep -q -- " ${exe}\$" "$STAGING/SHA256SUMS"; then
        echo "Error: release manifest is missing '${exe}' — incomplete/corrupt, aborting." >&2
        exit 1
    fi
done

# 3. Download exactly the files the manifest names, into staging.
while read -r _ filename; do
    [ -n "$filename" ] || continue
    # Guard against a tampered manifest smuggling a path or an option-like name —
    # basenames only, no leading dash.
    case "$filename" in
        -* | */* | .* | "")
            echo "Error: refusing suspicious filename in manifest: '$filename'" >&2
            exit 1
            ;;
    esac
    fetch "$REPO_RAW/$filename" "$STAGING/$filename"
done <"$STAGING/SHA256SUMS"

# 4. Verify everything BEFORE touching the install dir. Fail-closed.
if ! (cd "$STAGING" && verify_checksums); then
    echo "Error: checksum verification failed — aborting, nothing was installed." >&2
    exit 1
fi

# 5. All files verified — swap them into place (same-filesystem atomic rename).
while read -r _ filename; do
    [ -n "$filename" ] || continue
    mv "$STAGING/$filename" "$INSTALL_DIR/$filename"
done <"$STAGING/SHA256SUMS"

for exe in "${EXECUTABLES[@]}"; do
    chmod +x "$INSTALL_DIR/$exe"
done

echo "Installed release ${REF} to $INSTALL_DIR/ (all files checksum-verified)"
echo "Commands: brew safe-upgrade, brew safe-install, brew safe-update"
