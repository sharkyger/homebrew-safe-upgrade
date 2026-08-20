# Age-check dogfood harness

Measures how many GitHub REST calls the freshness check actually spends over a
real outdated-package list, in a container rather than on the host.

Why a container: the host has a warm cache, an authenticated `gh`, and a shell
profile full of tokens — all of which hide the failure this is meant to catch.
The interesting case is the cold, anonymous one: a machine that has not been
upgraded in weeks, run by someone who never set a token. That is the case where
anonymous GitHub's 60-requests/hour ceiling bites, and it is what this image
reproduces. The image deliberately contains no `gh` CLI, no `GH_TOKEN`, and no
cache.

## Run it

```bash
# 1. capture the host's real outdated list (name, type, target version)
brew update >/dev/null
brew outdated --json=v2 | python3 -c '
import json, sys
d = json.load(sys.stdin)
for f in d["formulae"]:
    print(f"{f[\"name\"]}\tformula\t{f[\"current_version\"]}")
for c in d["casks"]:
    print(f"{c[\"name\"]}\tcask\t{c[\"current_version\"]}")
' > pkgs.tsv

# 2. build and run
scripts/dogfood-age-check/run.sh pkgs.tsv
```

## Reading the output

Each package prints the source that answered it:

```
  pandoc                           core   6 2026-08-13       registry
  sharkyger/tap/pip-cve-gate       tap    50 2026-06-29      github
  shopify/shopify/shopify-cli      tap    -1 unknown         github/UNRESOLVED
```

and the run ends with two passes:

```
  total packages : 49
  github calls   : 5      <- cold cache
  resolved free  : 44
  unresolved     : 1

=== PASS 2 — warm cache (same list, immediately after) ===
  github calls   : 1      <- only the unresolvable one, which is never cached
  cache entries  : 48
```

The pre-change baseline is one GitHub call per package by construction — the old
`fetch_pkg_age` had neither a cache nor a registry path — so on a 49-package list
the comparison is 49 calls against 5.

`github calls` in pass 2 counting anything other than the unresolved packages
would mean the cache is not being written or not being read. `unresolved` is
expected to be non-zero for taps with a non-standard repository layout; those
fail closed and are deliberately never cached, so they are re-attempted every run.
