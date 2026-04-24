# homebrew-safe-upgrade

Security-first wrappers for `brew upgrade` and `brew install`. Checks every Homebrew package against 3 vulnerability databases before it touches your system, so you never blindly pull in a known CVE.

## Why

`brew upgrade` and `brew install` don't check whether a package has known security issues. Most of the time that's fine. Sometimes it isn't.

`brew safe-upgrade` and `brew safe-install` add a security gate: they query three public vulnerability databases, check whether the *target version* is actually affected, and only proceed with packages that come back clean. Packages with known vulnerabilities are blocked and listed separately.

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

Found 5 outdated package(s) (4 formulae, 1 casks):

  Package                        Type            Installed       Available
  -------                        ----            ---------       ---------
  ddev/ddev/ddev                 formula         1.25.1          -> 1.25.2
  gh                             formula         2.90.0          -> 2.91.0
  imagemagick                    formula         7.1.2-19        -> 7.1.2-21
  pydantic                       formula         2.13.2          -> 2.13.3
  claude-code                    cask            2.1.100         -> 2.1.108

Running security checks...

  [ok] ddev/ddev/ddev 1.25.2
  [ok] gh 2.91.0
  [ok] imagemagick 7.1.2-21
  [ok] pydantic 2.13.3
  [ok] claude-code 2.1.108

Results: 5 clean
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


### Minimum-age check (opt-in)

Hold back packages published less than N days ago. Protects against supply chain attacks where a compromised version is published minutes after credential theft — before any CVE database knows about it.

```
brew safe-upgrade --min-age 3
```

```
Checking package age (min-age: 3 days)...

  [ok] gh 2.91.0 — released 12 day(s) ago (2026-04-12)
  [ok] imagemagick 7.1.2-21 — released 8 day(s) ago (2026-04-16)
  [HOLD] some-pkg 2.0.0 — released 1 day(s) ago (2026-04-23), min-age: 3 days
```

**CVE-aware bypass:** If your *installed* version has known CVEs, the age check is skipped — the fresh version is likely the fix, and holding it back would leave you exposed. This means `--min-age` never prevents security patches from reaching you.

Use `--min-age 0` to disable (default behavior).

> **What should the default be?** We ship with off by default (opt-in). The community is discussing whether it should be on by default: [Discussion #14](https://github.com/sharkyger/homebrew-safe-upgrade/discussions/14)

### SHA verification (opt-in)

Verify bottle checksums against the Homebrew formulae API before upgrading. Detects local tap tampering.

```
brew safe-upgrade --verify-sha
```

```
  [ok] gh 2.91.0
    [sha] ea543daa28d39acc... verified via formulae.brew.sh
```

Note: Homebrew already verifies bottle SHAs during install. This adds a pre-upgrade check against the remote API as an independent verification. Advisory only — never blocks.

## brew safe-install

Same security gate, but for installing new packages.

```
brew safe-install [flags] package1 [package2 ...]
```

1. Resolves the version that would be installed (without installing yet)
2. Checks each package against all 3 databases
3. Reports results: clean, vulnerable, or check-failed
4. Installs only verified clean packages

```
$ brew safe-install wget imagemagick

Resolving package versions...

  Checking wget (formula, version 1.25)...
  [ok] wget 1.25
  Checking imagemagick (formula, version 7.1.2-21)...
  [ok] imagemagick 7.1.2-21

Results: 2 clean out of 2 package(s)

Install wget imagemagick? [Y/n]
```


Supports the same `--min-age` and `--verify-sha` flags:

```
brew safe-install --min-age 3 wget curl
brew safe-install --verify-sha --cask firefox
```

Works with formulae, casks, and tap packages:

```
# Install a cask
brew safe-install --cask firefox

# Install from a tap
brew safe-install ddev/ddev/ddev

# Multiple packages with flags
brew safe-install --cask slack zoom discord
```

Packages that are already installed are detected and skipped.

## brew safe-update

Updates all tools to the latest version from GitHub.

```
brew safe-update
```

No need to re-run the install script. If you get a permission error:

```
sudo brew safe-update
```

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
```

If you get a permission error:

```bash
curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | sudo bash
```

This places all files in your Homebrew bin directory (`/opt/homebrew/bin/` on Apple Silicon, `/usr/local/bin/` on Intel). Homebrew automatically adds external commands prefixed with `brew-` as subcommands.

### Manual install

```bash
git clone https://github.com/sharkyger/homebrew-safe-upgrade.git
cd homebrew-safe-upgrade
cp brew-safe-upgrade brew-safe-install brew-safe-update dependency_security_check.py /opt/homebrew/bin/
chmod +x /opt/homebrew/bin/brew-safe-upgrade /opt/homebrew/bin/brew-safe-install /opt/homebrew/bin/brew-safe-update
```

### Verify

```bash
brew safe-upgrade
```

```bash
brew safe-install wget
```

## Requirements

- macOS or Linux with Homebrew
- Python 3.8+
- No additional Python packages required (uses stdlib only; `certifi` optional for macOS SSL)

## How Homebrew discovers it

Homebrew automatically picks up any executable named `brew-<command>` in your PATH as a subcommand. Since the scripts are named `brew-safe-upgrade` and `brew-safe-install` and live in `/opt/homebrew/bin/`, running `brew safe-upgrade` or `brew safe-install` just works.

## How is this different from brew-vulns?

The Homebrew team released [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns) in January 2026 — a great tool that scans your installed packages for known vulnerabilities. If you're not using it yet, you should.

The two tools solve different problems:

| | `brew-vulns` | `brew safe-upgrade` | `brew safe-install` |
|---|---|---|---|
| **When** | After install (audit) | Before upgrade (gate) | Before install (gate) |
| **Action** | Reports vulnerabilities | Blocks vulnerable upgrades | Blocks vulnerable installs |
| **Databases** | OSV.dev | OSV.dev + GitHub Advisory + NIST NVD | OSV.dev + GitHub Advisory + NIST NVD |
| **Version filtering** | OSV native | OSV native + CPE range/exact match + GitHub patch version | Same as safe-upgrade |
| **Workflow** | Separate step | Drop-in replacement for `brew upgrade` | Drop-in replacement for `brew install` |

`brew-vulns` tells you what's already on your machine. `brew safe-upgrade` and `brew safe-install` prevent bad versions from landing in the first place. They complement each other.

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
