#!/usr/bin/env bash
# Hermetic end-to-end smoke for the script installer (install.sh).
#
# Why this exists: the formula self-test historically MASKED a helper-strand bug
# because the *script* install route was never actually exercised. This harness
# runs install.sh for real — over a local HTTP server, into a throwaway prefix,
# no brew, no network egress — and asserts both the happy path and the
# fail-closed path. Run locally and in CI (ubuntu + macOS, so the bash-3.2 path
# on macOS is covered too).
#
#   tests/smoke_install.sh

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

REF="smoke"
SRV="$WORK/srv"
mkdir -p "$SRV/$REF"

# Publish the release tree the way GitHub raw would: <ref>/<file>.
cp "$REPO/SHA256SUMS" "$SRV/$REF/SHA256SUMS"
while read -r _ f; do
    [ -n "$f" ] || continue
    cp "$REPO/$f" "$SRV/$REF/$f"
done <"$REPO/SHA256SUMS"

# Serve it on a free port.
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
(cd "$SRV" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) >/dev/null 2>&1 &
SRV_PID=$!

# Wait for it to accept connections.
for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$PORT/$REF/SHA256SUMS" -o /dev/null 2>/dev/null; then
        break
    fi
    sleep 0.1
done

run_install() {
    # $1 = install prefix
    SAFE_UPGRADE_BASE_URL="http://127.0.0.1:$PORT" \
        SAFE_UPGRADE_REF="$REF" \
        SAFE_UPGRADE_PREFIX="$1" \
        bash "$REPO/install.sh"
}

# ---------------------------- happy path ----------------------------
echo "== happy path: all files verify, atomic install =="
GOOD="$WORK/good"
mkdir -p "$GOOD/bin"
run_install "$GOOD"

while read -r _ f; do
    [ -n "$f" ] || continue
    test -f "$GOOD/bin/$f" || {
        echo "FAIL: $f not installed"
        exit 1
    }
done <"$REPO/SHA256SUMS"
for exe in brew-safe-upgrade brew-safe-install brew-safe-update; do
    test -x "$GOOD/bin/$exe" || {
        echo "FAIL: $exe not executable"
        exit 1
    }
done
echo "  ok: all files present and verified"

# ---------------------------- failure path --------------------------
echo "== fail-closed path: tampered file -> abort, no partial install =="
# Tamper a served file but leave SHA256SUMS untouched -> hash mismatch.
echo "# tampered" >>"$SRV/$REF/brew-safe-upgrade"

BAD="$WORK/bad"
mkdir -p "$BAD/bin"
echo "SENTINEL" >"$BAD/bin/brew-safe-upgrade" # pre-existing install must survive

if run_install "$BAD" >/dev/null 2>&1; then
    echo "FAIL: install.sh succeeded on a tampered file (should fail closed)"
    exit 1
fi
# Atomic + fail-closed: nothing swapped in.
test "$(cat "$BAD/bin/brew-safe-upgrade")" = "SENTINEL" || {
    echo "FAIL: pre-existing install was mutated despite verification failure"
    exit 1
}
test ! -f "$BAD/bin/VERSION" || {
    echo "FAIL: partial install left VERSION behind"
    exit 1
}
echo "  ok: aborted with no partial install"

# ---------------------- incomplete-manifest path --------------------
echo "== completeness floor: truncated manifest -> abort, no partial install =="
# Drop a required command from the served manifest (simulates a truncated /
# corrupted SHA256SUMS). The installer must refuse rather than install a subset.
grep -v ' brew-safe-upgrade$' "$REPO/SHA256SUMS" >"$SRV/$REF/SHA256SUMS"

TRUNC="$WORK/trunc"
mkdir -p "$TRUNC/bin"
if run_install "$TRUNC" >/dev/null 2>&1; then
    echo "FAIL: install.sh succeeded on an incomplete manifest (should fail closed)"
    exit 1
fi
test -z "$(ls -A "$TRUNC/bin")" || {
    echo "FAIL: incomplete manifest left files behind"
    exit 1
}
echo "  ok: aborted with empty install dir"

echo "smoke_install: PASS"
