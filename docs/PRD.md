# Product Requirements Document — homebrew-safe-upgrade

> Last updated: 2026-06-04 — living document.

## Mission

Security-first wrappers for `brew install` and `brew upgrade`. Every outdated package (and every incoming transitive dependency) is checked against 3 vulnerability databases against the **target version** before the install/upgrade proceeds. Clean packages move; vulnerable packages are blocked and listed separately. Operates as standalone CLI commands (`brew safe-install`, `brew safe-upgrade`, `brew safe-update`) — not as a Claude/Mistral hook.

## Why it exists / problem

`brew install` and `brew upgrade` perform no vulnerability check against the target version. [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns) audits the already-installed tree but doesn't gate incoming installs/upgrades. The result: a routine `brew upgrade` can move a user to a fresh-but-vulnerable formula version. This tool closes the install/upgrade gate by querying NIST NVD + OSV.dev + GitHub Advisory at the moment of action and blocking the bad ones while letting the clean ones through.

## Scope (in)

- `brew safe-install`, `brew safe-upgrade`, `brew safe-update` CLI commands.
- **Multi-source vulnerability query:** NIST NVD + OSV.dev + GitHub Advisory (deduplicated, version-aware).
- **Transitive dependency check (default on):**
  - Deps that aren't installed at all → checked.
  - Deps installed at an older version, being bumped → checked.
  - Deps already at the target version → skipped (that's `brew-vulns`' job).
  - Deduplicated across the upgrade batch (`openssl@3` in five outdated packages is checked once).
- **Cask CPE map (curated)** for NVD keyword mapping where the formula slug ≠ CPE name.
- **Auto-approve mode (`--yes`)** for CI / scripted use.
- **SHA verification default-on** (per #33).
- **Default `--min-age 3` for formulae** (per #32) — freshness hold; **CVE-aware bypass** when the installed version has a known CVE.
- **macOS + Linux** (Homebrew on Linux supported; CI runs the test suite on Python 3.11 and 3.13).

## Non-goals (out)

- **Not a replacement for `brew-vulns`.** That tool audits the already-installed tree; this one gates incoming installs/upgrades. Complementary, not redundant.
- **No post-install IoC scanning.** Out of scope here (lives in `composer-cve-gate`'s `safe-scan`; potential future cross-ecosystem tool).
- **No Claude/Mistral hook surface.** Those live in `claude-code-cve-gate` / `mistral-code-cve-gate`. This repo is the standalone CLI.
- **No SARIF / SBOM output.** Exit code is the contract.
- **No telemetry / phone-home.**
- **No API keys required.** Three databases are free + public; the tool stays free + zero-config.

## Quality bar

- **3-layer code review** on every PR (CodeRabbit + Mistral Vibe + source-verification).
- **Signed releases** via maintainer YubiKey.
- **No public security issues** — vulnerabilities are triaged privately and shipped as fixes.
- **Python static-analysis floor:** Bandit + Mypy moderate strict (planned, separate PR).
- **Test fixtures avoid live network/dates** wherever possible. (The `test_installed_old_version_is_treated_as_incoming` test previously read the live Homebrew openssl@3 release date and was flaky near openssl bumps; it now runs with `--min-age 0` so it makes no live date call.)
- **Scanner lineage:** `dependency_security_check.py` shares lineage with the sibling cve-gate CLIs; correctness fixes are mirrored per repo by each repo's own runtime constraints.

## Retirement / self-archive criteria

Retired when Homebrew ships **either**:

1. Native pre-install vulnerability gating that covers the same multi-source query + transitive dep scan + freshness hold, OR
2. A formal plugin API that lets a community tool register as a true pre-install gate (rather than relying on the wrapper-CLI pattern).

If neither happens but the broader ecosystem moves to a different package manager for AI-tooling use cases, evaluate then.

## Architecture

Bash entry points (`brew-safe-install`, `brew-safe-update`, `brew-safe-upgrade`) shell out to `dependency_security_check.py` (Python, stdlib-only) for the vulnerability check, plus a curated `cask_nvd_map.py` for NVD keyword/CPE resolution where the Homebrew token ≠ the CPE name.

## References

- **CLI counterparts:** [`composer-cve-gate`](https://github.com/sharkyger/composer-cve-gate), [`pip-cve-gate`](https://github.com/sharkyger/pip-cve-gate).
- **Hook counterparts:** [`claude-code-cve-gate`](https://github.com/sharkyger/claude-code-cve-gate), [`mistral-code-cve-gate`](https://github.com/sharkyger/mistral-code-cve-gate).
- **Adjacent:** [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns) — already-installed audit (complementary).

## Status

Current version: **v0.2.0** — **pre-stable** (per the pre-1.0 versioning rule). Recent shipped: SHA verification default-on, default `--min-age 3`, cask CPE map, arch-aware bottle-SHA fix, self-healing updater, and a pre-release-aware scanner comparator. Promotion to v1.0.0 gated on the quality floor (static-analysis + test stability).

## Change log for this document

| Date | Author | Change |
|---|---|---|
| 2026-05-29 | skeleton | Initial draft from the README and project notes. |
