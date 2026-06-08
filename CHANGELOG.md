# Changelog

All notable changes to `homebrew-safe-upgrade` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The project is pre-1.0; expect minor breaking changes between 0.x releases until the API is considered stable.

## [Unreleased]

## [0.2.3] — 2026-06-08

### Fixed
- **Freshness hold (`--min-age`) now covers casks, tap formulae, and `lib*` formulae, and fails closed** ([#62](https://github.com/sharkyger/homebrew-safe-upgrade/issues/62)). The age check previously looked every package up at `Homebrew/homebrew-core` `Formula/<first-letter>/<name>.rb`. Three classes of package had no release date to compare against and were reported as "age unknown, skipping age check": **casks** (which live in `homebrew-cask`), **tap formulae** (which live in their own tap repo), and **`lib*` formulae** (which homebrew-core shards under `Formula/lib/`, not `Formula/l/` — e.g. `libgit2`, `libheif`, `libusb`). The lookup is now **routed to the correct repo and path** per package: `homebrew-core` (with the `lib/` shard handled) for core formulae, `homebrew-cask` `Casks/<l>/<token>.rb` for casks, and `<user>/homebrew-<tap>` for tap formulae. When a release age **cannot be verified** (home repo unreachable, rate-limited, or a non-standard tap layout), the package is now **held** rather than allowed — the freshness hold is fail-closed, consistent with the rest of the tool. The same routing + fail-closed policy applies to the transitive-dependency age check in both `brew-safe-upgrade` and `brew-safe-install`. The known-too-fresh CVE-aware bypass (skip the hold when the *installed* version has CVEs) is unchanged. Covered by `tests/test_age_check.py` and additions to `tests/test_brew_safe_deps.py`, with a new deterministic `MOCK_COMMITS_API_DIR` test seam.

### Added
- **`--allow-unknown-age`** on `brew safe-upgrade` and `brew safe-install` — permit packages whose release age cannot be verified (default: such packages are held).

## [0.2.2] — 2026-06-06

### Fixed
- **Self-updater no longer strands helper files (single-run, atomic, fail-closed).** A `brew safe-update` run from an older updater could fetch only some files and still print "All tools updated", leaving `bottle_resolver.py` / `cask_nvd_map.py` missing — so the next `brew safe-upgrade` failed closed with `bottle SHA resolver not found`. The updater now (1) re-execs the freshly-fetched updater **before** the download loop, so the file list that runs is always current, and (2) fetches every declared file into a staging area and **swaps them in only if all arrive intact** — a partial or truncated download leaves the existing install untouched and never reports success. Regression-tested in `tests/test_install_hardening.py` and `tests/test_brew_safe_update.py`.
- **Scripts resolve their own directory through symlinks.** `brew-safe-upgrade` / `-install` / `-update` previously located their Python helpers with a bare `dirname "${BASH_SOURCE[0]}"`, which broke for a symlinked or relocated install. They now walk the symlink chain with a portable resolver (no macOS-hostile `readlink -f`), so the helpers resolve for script, Homebrew-formula, and symlinked layouts on both architectures.
- **Actionable fail-closed message.** A missing helper now prints how to fix it (`run 'brew safe-update'`) instead of the bare "make sure it's in the same directory".

### Added
- **`--version` with self-diagnosis** on all three commands (and listed in `--help`). Prints a single-source version (from the new `VERSION` file, bumped per release), the detected install route (Homebrew formula vs script), whether every helper file is present, and a warning if both install routes are on `PATH`. Turns a stranded install into a self-evident report.

## [0.2.1] — 2026-06-05

### Fixed
- **PEP 440-correct pre-release version comparison.** The CVE range matcher now uses a small, dependency-free pre-release-aware comparator (`dev < alpha < beta < rc < final`, with trailing-zero equivalence) in place of the previous tuple parser, so pre-release versions such as `1.0-beta` sort correctly relative to their final release when evaluated against advisory ranges. Constraint parsing is tightened, and every comparison site is None-safe — unparseable versions or constraints **fail closed** (treated as affected). The tool stays dependency-free: no `packaging` runtime dependency (Homebrew's Python is externally-managed and lacks it, which would fail-close the whole tool). Covered by `tests/test_version_validation.py`.
- The `test_installed_old_version_is_treated_as_incoming` test no longer reads the live Homebrew openssl@3 release date (it now runs with `--min-age 0`), so it stops failing for ~3 days after every openssl@3 bump.

### Added
- **Homebrew tap install** — `brew install sharkyger/tap/safe-upgrade` now works (formula lives in [`sharkyger/homebrew-tap`](https://github.com/sharkyger/homebrew-tap)). It installs all three commands plus the runtime modules (`bottle_resolver.py`, `cask_nvd_map.py`) and pulls in `python@3.12`. Tap installs update through brew — `brew update && brew upgrade safe-upgrade` — **not** the bundled `brew safe-update`, which only refreshes a script install in your Homebrew `bin`. README install docs updated to lead with the tap path and document this distinction.
- Product requirements doc (`docs/PRD.md`).

## [0.2.0] — 2026-06-03

### Fixed
- **`brew safe-update` is now self-healing — single-run convergence (fixes the second Intel-Mac error).** While verifying the bottle-SHA fix on a real Intel (x86_64) Mac, two distinct errors surfaced in sequence:
  1. `[BLOCKED] SHA mismatch` on **every** bottle — the architecture bug (see the arch-aware entry below). This is the one the bottle-SHA fix addresses.
  2. After updating, `Error: bottle SHA resolver not found at /usr/local/bin/bottle_resolver.py` — the fail-closed guard firing because the new `bottle_resolver.py` was missing from `/usr/local/bin`.

  Error (2) had a subtle root cause: `brew-safe-update` keeps a hardcoded list of files to fetch, and the **already-installed** updater on that Mac predated `bottle_resolver.py`, so it had no idea to download it. Running `brew safe-update` once only upgraded the *updater script itself*; the new file wasn't pulled until a **second** run — a confusing "run it twice" bootstrap trap (the immediate workaround was a one-line `curl` of the single missing file).

  Fix: `brew-safe-update` now **updates itself first and re-runs the fresh copy** before fetching the rest. Because the re-executed copy carries the current file list, any newly-added file (like `bottle_resolver.py`) is fetched in the **same** run — so a single `brew safe-update` always converges, and this trap can't recur for future file additions. Implemented by exec'ing the freshly-downloaded updater from a temp path (never overwriting a running script) and passing the real install dir through, with a re-exec guard to prevent loops. Covered by `tests/test_brew_safe_update.py` (single-run convergence + no-infinite-loop + a source-level guard that the self-heal stage stays present).
- **`brew safe-update` now ships every runtime module (follow-up to the bottle-SHA fix).** The self-updater carried its own hardcoded download list that was never synced with `install.sh`, so after the arch-aware fix landed, `brew safe-update` fetched the scripts but **not** `bottle_resolver.py` — and the new fail-closed guard then correctly aborted `brew safe-upgrade` with `bottle SHA resolver not found`. `brew-safe-update` now distributes the same set as `install.sh`, including `bottle_resolver.py` and the long-missing `cask_nvd_map.py` (a runtime import of `dependency_security_check.py`, previously absent from both lists — its cask keyword map silently fell back to empty on installed systems). A new `tests/test_distribution_manifest.py` asserts the two lists stay identical and cover every runtime file, so this class of drift can't recur.
- **Arch-aware bottle-SHA selection — fixes a uniform Intel (x86_64) false positive.** The local and canonical SHA extractors each picked the *first* bottle tag in JSON key order. `brew info --json=v2` and `formulae.brew.sh` enumerate `bottle.stable.files` in different orders, so on an Intel host the local side resolved the genuine Intel bottle while the canonical side resolved the **arm64** bottle — comparing two real-but-different-arch SHAs and flagging **every** bottle as `[BLOCKED] SHA mismatch`. (Apple Silicon was unaffected, which is why it went unnoticed.) It failed safe — no bad upgrade — but 15-of-15 bogus "tamper" warnings per run are alert fatigue: they train the user to ignore the signal so a *real* tamper later gets dismissed. The new `bottle_resolver.py` resolves the bottle SHA by the host's actual tag — `arm64_<codename>` on Apple Silicon, bare `<codename>` on Intel, `{arch}_linux` on Linux — with a same-arch, progressively-older codename fallback (Homebrew often serves an Intel host's newest OS under an older tag, e.g. `tahoe` → `sonoma`) that **never crosses architecture**. The same resolution is applied to both payloads, so a genuine same-bottle comparison matches. Forced-host-tag regression tests (`BREW_SAFE_HOST_ARCH` / `BREW_SAFE_HOST_OS`) reproduce the bug and verify the fix on any machine — no Intel hardware required. Note for packagers: `bottle_resolver.py` is a new file that must ship alongside the scripts (added to `install.sh`; tap formula updated at release).

### Added
- **Curated cask → NVD search-keyword map** (`cask_nvd_map.py`). Cask slugs like `brave-browser` rarely match NVD descriptions verbatim, so the scanner previously returned no hits for vendor-shipped GUI apps. The map translates ~55 common casks (browsers, IDEs, communication tools, runtimes) into brew's canonical product name (`name[0]` from `formulae.brew.sh/api/cask/<token>.json`), with a small set of documented overrides where brew's name is bad for NVD search. `query_nvd` looks up the mapped keyword when `ecosystem == "brew"` and the cask slug is in the map; the description-matching filter accepts the mapped keyword in addition to the raw slug. Unmapped casks fall through to the previous naive behavior — open a PR to expand the map. The README states the cask-coverage limits honestly (integrity ≠ vulnerability; SHA enforcement covers tampering, not vendor-shipped CVEs).

### Changed
- **SHA verification is now default-on** for both `brew-safe-install` and `brew-safe-upgrade`. The bottle SHA from `brew info --json=v2` is compared against the canonical SHA published at `formulae.brew.sh`. Five outcomes:
  - **Match** — `[sha] verified <local>=<canonical>`, install/upgrade proceeds.
  - **Mismatch** — `[BLOCKED] SHA mismatch` with both full fingerprints printed; the package is excluded from the install/upgrade set and the script exits non-zero. **Tampering is never overridable by `--yes`** — it's a deliberate security signal that must surface in CI/pipelines.
  - **No bottle** — `[sha] no bottle — built from source`, proceeds (canonical formula exists but isn't bottled).
  - **Tap-only / 404** — `[sha] tap-only formula — no canonical SHA available`, proceeds without a prompt (third-party taps don't publish to formulae.brew.sh).
  - **Canonical API 5xx / timeout** — batched into a single end-of-loop prompt. Interactive: `[WARN] formulae.brew.sh unreachable... Install anyway? [y/N]`. Non-interactive or `--yes`: warn loudly and continue (so the script doesn't hang in CI).

  Opt out with `--no-verify-sha`. The previous `--verify-sha` flag is accepted as a silent no-op for backward compatibility.

  Motivation: defense in depth alongside the existing CVE check + freshness hold. If a tap or mirror is compromised and ships a tampered bottle with the same version number, the SHA divergence from formulae.brew.sh's canonical record is the first signal — long before CVE databases register the incident.

- **Default `--min-age` is now 3 days** (was 0 = disabled) for both `brew-safe-install` and `brew-safe-upgrade`. The freshness hold applies to formulae only; casks remain unaffected (brew enforces the SHA256 recorded in the cask file on every install, so the supply-chain shape is different). Use `--min-age 0` to restore the previous behaviour. Motivation: recurring npm worm campaigns (Shai-Hulud, Mini Shai-Hulud) compromise packages for live windows of 1–6 hours before takedown — too short for CVE databases to react. A multi-day freshness hold trades a small upgrade lag against the entire attack window. The CVE-aware bypass that skips the age check when the *installed* version has known CVEs is unchanged, so security patches still reach you immediately.

## [0.1.1] — 2026-04-26

Hardening pass following the v0.1.0 review. All changes are internal correctness and defense-in-depth improvements; the public flag/env-var surface is unchanged.

### Fixed
- `brew list --versions` parsing now uses `awk '$NF'` instead of `awk '$2'`, so when multiple kegs of one formula are installed the **latest** version is used for the incoming-vs-installed comparison rather than the oldest.
- `INCOMING_DEPS` is now a proper bash array. Iteration uses quoted `${INCOMING_DEPS_ARR[@]}` expansion, preserving whitespace in pathological tap dep names that the previous flat-string approach would have split.
- `--min-age` for tap-namespaced deps (`foo/bar/baz`) is now an explicit `[skip-dep-age]` log line. Previously the GitHub `homebrew-core` lookup would 404 silently and the age gate fell through unenforced.

### Security (defense in depth)
- Dep names from `brew deps` output are validated against a `^[a-zA-Z0-9@._/-]+$` regex before being interpolated into any curl URL or passed to the CVE checker. A malformed name from a compromised tap is rejected with `[skip-dep] -- invalid name, refusing to query`.
- The same regex guard is now applied to the **main-package** age check in both `brew-safe-install` and `brew-safe-upgrade`. (Previously only the dep-check code was protected; the main-package path inherited a pre-existing gap from before the SSRF input validation in PR #11.)

### Changed
- The pre-install / pre-upgrade warning block no longer combines vulnerable and too-fresh deps under one `"known issues"` header. Vulnerable deps now appear under `"WARNING: incoming dependencies have known CVEs:"`; fresh deps under `"Incoming dependencies are below --min-age:"`. They are distinct risk signals and the previous wording conflated them.
- `brew-safe-upgrade --yes` stderr bypass message reworded from `"despite dep CVE warnings"` to `"despite dep warnings"` (now covers both CVE and freshness holds).

### Documented
- Added an in-code design note explaining why transitive deps deliberately do **not** receive the CVE-aware `--min-age` bypass that applies to the user-named package.



### Added
- Transitive dependency check for `brew safe-install` and `brew safe-upgrade`. The same vulnerability gate that protects the package you're installing is now applied to the dependencies that come in with it — both brand-new deps and existing deps whose version is being bumped. Already-installed deps that aren't changing are deliberately left to [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns).
- For `safe-upgrade`, incoming deps are deduplicated across the whole upgrade batch (so `openssl@3` appearing in five outdated packages is checked once).
- New `--no-deps` flag and `BREW_SAFE_NO_DEPS=1` environment variable to opt out of the dep check per invocation. Defaults remain safe; the flag is per-invocation only.
- Mock-`brew` based test harness in `tests/fixtures/mock_brew/` and `tests/test_brew_safe_deps.py` covering flag parsing, env-var override, and dep classification (not-installed / same-version / older-version).

### Reliability
- Strip Homebrew revision suffix (`_1`, `_2`, …) from the installed-version string before comparing to the latest stable version, so a revision bump of an already-current dep isn't misclassified as incoming.
- Use `|` (not `@`) as the internal `name|version` separator inside the dep list so that versioned formulae (e.g. `openssl@3`) and the rare version that contains `@` round-trip correctly.
- Read `brew deps` output line-by-line into an array so dep names containing whitespace (third-party taps) aren't word-split and silently dropped.
- Failed dep checks (network error, transient DB outage) are now collected into a `[skip-dep]` summary instead of being silently ignored — users can re-run later with the same gate.
- `BREW_SAFE_NO_DEPS` accepts `1`, `true`, `yes` (case-insensitive) instead of only `1`.
- Compatible with macOS system bash 3.2 (no `mapfile`/`readarray`).

### Documentation
- New "Transitive dependency check" section in README, including a note on NVD's 5 req/30s anonymous rate limit for large upgrade batches.
- `brew-vulns` comparison table now includes a "Scope" row that makes the division of labour explicit.
- Stated minimum Python version corrected to 3.11 in README and `pyproject.toml`. CI has tested on 3.11 and 3.13 since #16 dropped 3.9; the README and `requires-python` were left at the original 3.8 by oversight. `ruff target-version` bumped to `py311` for consistency.

## Earlier history (pre-0.1.0, untagged)

The repo had no version tags before `v0.1.0`. The summary below groups the
pre-tag history by theme rather than by release. Full detail is in `git log`.

### Wrappers and core features

- Initial release of `brew safe-upgrade` — pre-upgrade vulnerability gate against three databases (OSV.dev, GitHub Advisory, NIST NVD).
- `brew safe-install` — same gate applied before installing new packages.
- `brew safe-update` — self-updater that pulls the latest scripts from GitHub.
- Cask support added to both wrappers (with separate clean-list handling for formulae vs. casks during upgrade).
- Detailed CVE output: severity, CVSS score, advisory source.
- `--min-age N` flag — hold packages published less than N days ago. Includes a CVE-aware bypass: if the *installed* version has known CVEs, a fresh upgrade is allowed through (otherwise `--min-age` could keep users on a known-vulnerable version).
- `--verify-sha` flag — verify bottle SHA256 against `formulae.brew.sh` API as an independent pre-upgrade check.
- `--yes` / `-y` for non-interactive upgrades (CI use).

### Reliability and correctness fixes

- Stopped `brew upgrade` from consuming stdin and killing the per-package loop.
- Pin/unpin protection so excluded (vulnerable / held) packages can't slip in as transitive upgrades.
- Batched the final clean-package upgrade into a single `brew` call.
- Dropped `set -e` in favour of explicit per-step error handling so a single failed lookup doesn't abort the whole run.
- CVE description parsing for advisories that lack CPE data.
- Apple Silicon vs. Intel Homebrew prefix detection in `install.sh`; clearer permission-error messaging.
- Cache-busting on `safe-update` downloads to work around GitHub raw-CDN propagation delay.

### Security and CI

- Hardening round 1: shellcheck pass, CI workflow, `SECURITY.md`, contribution scaffolding.
- SSRF input validation on package name and version arguments so untrusted strings can't be folded into outbound URLs.
- pytest bumps for `CVE-2025-71176` (tmpdir) and follow-up to 9.0.3 across two PRs.
- CodeQL, gitleaks, and dependabot wired up.
- Community health files: issue templates (bug, false-positive, feature), discussion link from README on the open `--min-age` default question.

[Unreleased]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.1.0...v0.1.1
