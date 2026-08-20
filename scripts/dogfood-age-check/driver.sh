#!/bin/bash
# Container entrypoint for the age-check dogfood harness. See README.md.
#
# Drives the real fetch_pkg_age over a real outdated-package list and reports
# which source answered each package. The pre-change baseline is one GitHub REST
# call per package by construction, so what this measures is how many still fall
# through to GitHub.
set -uo pipefail

# Must precede the source: the cache-directory resolution in age_funcs.sh is
# top-level code that runs at source time.
export BREW_SAFE_AGE_CACHE_DIR=/tmp/agecache
export HOME=/tmp/nohome
mkdir -p "$HOME"
rm -rf "$BREW_SAFE_AGE_CACHE_DIR"

# shellcheck source=/dev/null
source /harness/age_funcs.sh

PKGS=/harness/pkgs.tsv
[ -s "$PKGS" ] || {
    echo "no package list mounted at $PKGS" >&2
    exit 2
}

# MOCK_COMMITS_API_LOG appends a line whenever the GitHub branch is reached, so
# its length is exactly the number of REST calls the pass needed.
export MOCK_COMMITS_API_LOG=/tmp/gh_urls.log

classify() {
    case "$2" in
        cask) printf 'cask' ;;
        *) case "$1" in */*) printf 'tap' ;; *) printf 'core' ;; esac ;;
    esac
}

: >"$MOCK_COMMITS_API_LOG"
gh_calls=0
free=0
unknown=0

printf '=== PASS 1 — cold cache ===\n'
while IFS=$'\t' read -r name type version; do
    [ -n "$name" ] || continue
    ptype=$(classify "$name" "$type")

    before=$(wc -l <"$MOCK_COMMITS_API_LOG")
    out=$(fetch_pkg_age "$name" "$ptype" "$version")
    after=$(wc -l <"$MOCK_COMMITS_API_LOG")

    if [ "$after" -gt "$before" ]; then
        src="github"
        gh_calls=$((gh_calls + 1))
    else
        src="registry"
        free=$((free + 1))
    fi
    case "$(printf '%s' "$out" | awk '{print $1}')" in
        -1 | -2)
            unknown=$((unknown + 1))
            src="$src/UNRESOLVED"
            ;;
    esac
    printf '  %-32s %-6s %-18s %s\n' "$name" "$ptype" "$out" "$src"
done <"$PKGS"

printf '\n  total packages : %s\n' "$(grep -c . "$PKGS")"
printf '  github calls   : %s\n' "$gh_calls"
printf '  resolved free  : %s\n' "$free"
printf '  unresolved     : %s\n' "$unknown"

: >"$MOCK_COMMITS_API_LOG"
while IFS=$'\t' read -r name type version; do
    [ -n "$name" ] || continue
    fetch_pkg_age "$name" "$(classify "$name" "$type")" "$version" >/dev/null
done <"$PKGS"

printf '\n=== PASS 2 — warm cache (same list, immediately after) ===\n'
printf '  github calls   : %s\n' "$(wc -l <"$MOCK_COMMITS_API_LOG" | tr -d ' ')"
printf '  cache entries  : %s\n' "$(find "$BREW_SAFE_AGE_CACHE_DIR" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
