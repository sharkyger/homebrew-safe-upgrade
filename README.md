# homebrew-safe-upgrade

A security-first wrapper for `brew upgrade`. Checks every outdated Homebrew package against 3 vulnerability databases before upgrading, so you never blindly pull in a known CVE.

## Why

`brew upgrade` upgrades everything without checking whether the new version has known security issues. Most of the time that's fine. Sometimes it isn't.

`brew safe-upgrade` adds a security gate: it queries three public vulnerability databases for each outdated package, checks whether the *target version* is actually affected, and only upgrades packages that come back clean. Packages with known vulnerabilities are blocked and listed separately.

## What it checks

Every outdated package is checked against:

| Source | Coverage | Method |
|--------|----------|--------|
| **OSV.dev** (Google) | Broad, multi-ecosystem | Native version filtering via API |
| **GitHub Advisory Database** | GitHub-tracked advisories | Version range + patch version matching |
| **NIST NVD** | US government CVE database | Keyword search + CPE version filtering |

Results are deduplicated across sources. Version-aware filtering eliminates false positives from old CVEs that don't affect the target version.

No API keys required. All three databases are free and public.

## How it works

```
brew safe-upgrade
```

1. Runs `brew update` to refresh formulae
2. Lists all outdated packages with installed and available versions
3. Checks each package's *target version* against all 3 databases
4. Reports results: clean, vulnerable, or check-failed
5. Offers to upgrade clean packages while blocking vulnerable ones

```
$ brew safe-upgrade

Updating Homebrew...
Checking for outdated packages...

Found 7 outdated package(s):

  Package                        Installed       Available
  -------                        ---------       ---------
  ddev/ddev/ddev                 1.25.1          -> 1.25.2
  gh                             2.90.0          -> 2.91.0
  imagemagick                    7.1.2-19        -> 7.1.2-21
  pydantic                       2.13.2          -> 2.13.3

Running security checks...

  [ok] ddev/ddev/ddev 1.25.2
  [ok] gh 2.91.0
  [ok] imagemagick 7.1.2-21
  [ok] pydantic 2.13.3

Results: 4 clean, 0 skipped
All clean. Run brew upgrade? [Y/n]
```

If a package has vulnerabilities:

```
  [VULN] some-package 3.2.0 -- vulnerabilities found!
  [CRITICAL] CVE-2026-12345 (CVSS 9.8)
    Source: NIST NVD + GitHub Advisory
    ...

Results: 3 clean, 0 skipped
Blocked: some-package

Upgrade clean packages only? The blocked ones will be skipped.
Proceed? [y/N]
```

### Auto-approve mode

For CI or scripted use:

```
brew safe-upgrade --yes
```

Automatically upgrades clean packages and skips vulnerable ones without prompting.

## Standalone security checker

The vulnerability checker works independently for any ecosystem:

```
python3 dependency_security_check.py <ecosystem> <package> [version]
```

Supported ecosystems: `pip`, `npm`, `composer`, `cargo`, `go`, `maven`, `gem`, `brew`

```
# Check a specific version
python3 dependency_security_check.py pip requests 2.31.0

# Check latest version (auto-resolved for pip/npm)
python3 dependency_security_check.py npm lodash
```

Exit codes:
- `0` — no known vulnerabilities
- `1` — vulnerabilities found (details on stderr, JSON on stdout)
- `2` — error (invalid input, network failure)

JSON output on stdout for programmatic use:

```json
{
  "status": "clean",
  "package": "requests",
  "ecosystem": "pip",
  "version": "2.31.0",
  "vulnerabilities": []
}
```

## Install

### Quick install (Homebrew prefix)

```bash
curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | bash

# If you get a permission error:
curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | sudo bash
```

This places both files in your Homebrew bin directory (`/opt/homebrew/bin/` on Apple Silicon, `/usr/local/bin/` on Intel). Homebrew automatically adds external commands prefixed with `brew-` as subcommands.

### Manual install

```bash
git clone https://github.com/sharkyger/homebrew-safe-upgrade.git
cd homebrew-safe-upgrade
cp brew-safe-upgrade dependency_security_check.py /opt/homebrew/bin/
chmod +x /opt/homebrew/bin/brew-safe-upgrade
```

### Verify

```bash
brew safe-upgrade
```

## Requirements

- macOS or Linux with Homebrew
- Python 3.8+
- No additional Python packages required (uses stdlib only; `certifi` optional for macOS SSL)

## How Homebrew discovers it

Homebrew automatically picks up any executable named `brew-<command>` in your PATH as a subcommand. Since the script is named `brew-safe-upgrade` and lives in `/opt/homebrew/bin/`, running `brew safe-upgrade` just works.

## How is this different from brew-vulns?

The Homebrew team released [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns) in January 2026 — a great tool that scans your installed packages for known vulnerabilities. If you're not using it yet, you should.

The two tools solve different problems:

| | `brew-vulns` | `brew safe-upgrade` |
|---|---|---|
| **When** | After install (audit) | Before upgrade (gate) |
| **Action** | Reports vulnerabilities | Blocks vulnerable upgrades |
| **Databases** | OSV.dev | OSV.dev + GitHub Advisory + NIST NVD |
| **Version filtering** | OSV native | OSV native + CPE range/exact match + GitHub patch version |
| **Workflow** | Separate step | Drop-in replacement for `brew upgrade` |

`brew-vulns` tells you what's already on your machine. `brew safe-upgrade` prevents bad versions from landing in the first place. They complement each other.

## Acknowledgments

This tool relies entirely on free, public vulnerability databases maintained by teams who believe security data should be accessible to everyone:

- **[NIST National Vulnerability Database](https://nvd.nist.gov/)** — the US government's comprehensive CVE repository, maintained by the National Institute of Standards and Technology. The backbone of vulnerability tracking worldwide.
- **[OSV.dev](https://osv.dev/)** — Google's open-source vulnerability database with native ecosystem support and version filtering. A fantastic resource for the open-source community.
- **[GitHub Advisory Database](https://github.com/advisories)** — GitHub's curated security advisories with detailed version range data and patch information.

And of course:

- **[Homebrew](https://brew.sh/)** — the package manager that makes macOS development possible. And the [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns) team for pushing security scanning into the Homebrew ecosystem.

These organizations and communities make it possible for anyone to build security tooling without paywalls or API key barriers. Thank you.

## License

MIT
