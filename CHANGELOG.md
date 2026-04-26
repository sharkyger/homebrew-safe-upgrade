# Changelog

All notable changes to `homebrew-safe-upgrade` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The project is pre-1.0; expect minor breaking changes between 0.x releases until the API is considered stable.

## [Unreleased]

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

[Unreleased]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.1.0...HEAD
