# homebrew-safe-upgrade

Security-first wrappers for `brew upgrade` and `brew install`. Checks every Homebrew package against 3 vulnerability databases before it touches your system, so you never blindly pull in a known CVE.

## Why

`brew upgrade` and `brew install` don't check whether a package has known security issues. Most of the time that's fine. Sometimes it isn't.

`brew safe-upgrade` and `brew safe-install` add a security gate: they query three public vulnerability databases, check whether the *target version* is actually affected, and only proceed with packages that come back clean. Packages with known vulnerabilities are blocked and listed separately.

The same gate is then applied to **transitive dependencies coming in with the install or upgrade** — both brand-new deps and existing deps whose version is being bumped. Already-installed deps that aren't changing are left to [`brew-vulns`](https://github.com/Homebrew/homebrew-brew-vulns).

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

### Getting help

Every command answers `--help` (or `-h`) with a synopsis, a flag listing, and
examples, and `--version` with the version plus install-route / helper-file
self-diagnosis:

```bash
brew safe-upgrade --help
brew safe-install --help
brew safe-update  --help
brew safe-upgrade --version
```

### Upgrading specific packages

Pass one or more package names to restrict the run to just those, instead of every outdated package:

```bash
brew safe-upgrade gh                 # only gh
brew safe-upgrade gh imagemagick     # only these two
```

Names match the full name or its basename, so `brew safe-upgrade safe-fetch` matches a tapped `sharkyger/tap/safe-fetch`. A named package that isn't outdated is reported, not silently ignored.

### Auto-approve mode

For CI or scripted use:

```
brew safe-upgrade --yes
```

Automatically upgrades clean packages and skips vulnerable ones without prompting.

### Transitive dependency check (default on)

Every `safe-install` or `safe-upgrade` also checks the dependencies that would land on your system as part of the operation:

- Deps that aren't installed at all → checked.
- Deps that are installed, but a newer version is coming in → checked.
- Deps that are installed at the same version that would be installed → skipped (already on your system; that's `brew-vulns`' job).

For `safe-upgrade`, deps are deduplicated across the entire upgrade batch — `openssl@3` showing up in five outdated packages is checked once.

```
$ brew safe-install gh

Resolving package versions...
  Checking gh (formula, version 2.91.0)...
  [ok] gh 2.91.0

Results: 1 clean out of 1 package(s)

Checking transitive dependencies...
  Found 2 incoming dependency version(s) to check

    [ok-dep] openssl@3 3.5.0
    [ok-dep] ca-certificates 2026-04-01

Install gh? [Y/n]
```

If a dep has a known CVE, the check warns and asks whether to proceed:

```
WARNING: incoming dependencies have known issues:
    libfoo 1.2.3: [HIGH] CVE-2026-99999 (CVSS 7.5) — NIST NVD
Proceeding will let brew install them anyway.
Continue install of gh? [y/N]
```

**Skipping the dep check.** If you know what you're doing — fast iteration, CI runs where you've already vetted upstream — opt out per invocation:

```
brew safe-install --no-deps gh
brew safe-upgrade --no-deps
```

…or set the env var once for the current shell:

```
export BREW_SAFE_NO_DEPS=1
```

The flag is per-invocation by design — the safe default always returns the next time you run the command without it. The env var is the only way to make it sticky, and you have to put it in your shell rc yourself; the tool never writes any persistent config.

> **Note on big upgrade batches.** `brew safe-upgrade` deduplicates incoming deps across the batch, but a large run with many unique deps can still hit NIST NVD's anonymous rate limit (5 requests / 30 seconds). When that happens you'll see `[skip-dep]` lines in the output — those deps were not vetted. Re-run the upgrade later, or pass `--no-deps` if you've vetted upstream another way. **Setting `NVD_API_KEY` largely removes this** — see below.

### `NVD_API_KEY` — strongly recommended

NIST NVD allows **5 requests per rolling 30 seconds** anonymously, and **50 with an API key**. A package that no source could answer for is *held*, not reported clean, so being throttled means packages don't upgrade. Measured on a batch of ten formulae in a container:

| | packages left unchecked |
|---|---|
| with `NVD_API_KEY` | **0 of 10** |
| without | 3 of 10 |

Requests are retried with backoff when NVD throttles, but under sustained load backoff alone cannot recover a 5-request budget — the key is what actually fixes it.

Get one free at <https://nvd.nist.gov/developers/request-an-api-key> (no approval wait; you'll get a single-use activation link by email, valid 7 days). Then:

```bash
export NVD_API_KEY="your-key-here"
```

Put it in `~/.zshenv` rather than `~/.zshrc` if you want non-interactive tools and scripts to see it — zsh only reads `.zshrc` for interactive shells. The key is sent as a request header, never in the URL, so it won't appear in logs or error output.

#### When a dependency is flagged: upgrade the rest anyway

If an incoming dependency has a CVE or is below `--min-age`, you get three choices rather than an all-or-nothing decision:

```
Incoming dependencies are below --min-age:
    taglib 2.3.1: too fresh (1 days old, min-age 3)
Depends on a flagged dependency: player
Unaffected and safe to upgrade now: unrelated ripgrep jq
Continue upgrade?
  [y] yes — upgrade everything, including the flagged dependencies
  [s] skip — upgrade only the unaffected packages above
  [N] no  — cancel the whole upgrade (default)
```

`[s]` upgrades the packages that don't touch the flagged dependency and holds back the ones that do. Use `--skip-unsafe` to take that branch non-interactively:

```
brew safe-upgrade --skip-unsafe
```

Held packages **and the flagged dependency itself** are `brew pin`-ed for the duration of the upgrade and unpinned afterwards. Keeping a dependent off brew's command line is not sufficient on its own — brew resolves dependencies itself, so the pin is what actually stops the flagged version being pulled in under some other package.

### Minimum-age / freshness check (on by default, 3 days)

Hold back **formulae, casks, and tap formulae** published less than N days ago. Protects against supply chain attacks where a compromised version is published minutes after credential theft — before any CVE database knows about it. Worm-class npm compromises (Shai-Hulud, Mini Shai-Hulud) have repeatedly shown live windows of 1–6 hours between malicious publish and registry takedown; a multi-day freshness hold trades a small lag against the entire attack window.

"Age" here is the **Homebrew metadata age** — the date of the last commit that touched the package's formula/cask file, read via the GitHub API from `homebrew-core` for core formulae, `homebrew-cask` for casks, and the tap's own repo for tap formulae. That's when the new version reached Homebrew users, which is the window a freshness hold needs to cover; it is not the upstream project's own release timestamp (a formula bump can lag or be backported).

```bash
brew safe-upgrade             # uses default --min-age 3
brew safe-upgrade --min-age 7 # stricter
```

```text
Checking package age (min-age: 3 days)...

  [ok]   gh 2.91.0 — released 12 day(s) ago (2026-04-12)
  [HOLD] some-pkg 2.0.0 — released 1 day(s) ago (2026-04-23), min-age: 3 days
  [HOLD] some-cask 5.0 — age could not be verified (min-age: 3 days); re-run with --allow-unknown-age to override
```

**Fail closed.** If the release age cannot be verified — the home repo is unreachable, or a tap uses a non-standard layout — the package is **held**, never waved through. This is deliberate: a freshness hold that silently no-ops the moment it can't reach the registry would be worthless exactly when an attacker can induce that condition. Pass `--allow-unknown-age` to permit unverifiable-age packages when you accept that risk.

**CVE-aware bypass:** If your *installed* version has known CVEs, the freshness hold on a too-fresh upgrade is skipped — the fresh version is likely the fix, and holding it back would leave you exposed. So `--min-age` never prevents security patches from reaching you.

Use `--min-age 0` to disable the freshness hold entirely.

#### GitHub API authentication (rate limits)

The age check queries the GitHub API. Unauthenticated requests are limited to **60 per hour per IP**, so on a machine with many outdated packages — or across repeated runs — the quota runs out and the age check can no longer verify packages. Authenticate to raise the limit to **5,000 per hour**:

```bash
export GH_TOKEN=ghp_...      # a Personal Access Token (no scopes needed), or
gh auth login                # the gh CLI token is picked up automatically
```

The token is read from `GH_TOKEN`, then `GITHUB_TOKEN`, then an authenticated [`gh`](https://cli.github.com/) CLI — whichever is found first. In GitHub Actions, pass the built-in token:

```yaml
- run: brew safe-upgrade
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

If the rate limit is reached, the run **stops and reports when the limit resets**, rather than mislabeling the packages as unverifiable. Pass `--allow-unknown-age` to proceed anyway (fail-open — the age check is skipped for the affected packages).

### Cask CVE coverage (honest limits)

Casks **are** checked against NVD for known CVEs, but the coverage is uneven and worth being explicit about:

- The scanner ships with a curated map (`cask_nvd_map.py`) of ~55 common cask slugs → canonical product names. Keywords are sourced from Homebrew's own cask metadata (`formulae.brew.sh/api/cask/<token>.json` → `name[0]`), with a small set of documented overrides where brew's name is bad for NVD search (verbose vendor prefixes, edition suffixes, or names shorter than the scanner's 4-character minimum).
- **Mapped casks** get accurate hits — covering the browser/IDE/communication tools most people install.
- **Unmapped casks** fall back to a naive lookup using the cask slug, which rarely matches NVD descriptions. They will usually show as clean even when CVEs exist.
- **No SHA-tampering check** for casks (brew enforces the cask-file SHA256 itself — see the integrity side above). Casks **are** freshness-gated by `--min-age` as of v0.2.3.

To extend the map for a cask you rely on: pick the cask token, look up its `name[0]` via the brew API, and add one line to `cask_nvd_map.py`. The validator enforces a 4-character minimum so the scanner doesn't silently skip the NVD query.

**Integrity ≠ vulnerability.** The cask-file SHA check prevents *download-channel tampering* (someone serving a different binary than the cask references). It does not prevent the *vendor* from shipping a binary with a known CVE — Chrome, Brave, Zoom and friends have all done so. The cask CVE check addresses that second problem; the map is the lever for how well it works.

### SHA verification (default ON)

Both `brew-safe-install` and `brew-safe-upgrade` compare the local-tap bottle SHA (from `brew info --json=v2`) against the canonical SHA published at `formulae.brew.sh`. Tampered taps that ship a bottle with the same version number but a different SHA are blocked before brew sees them.

```
  [ok] gh 2.91.0
    [sha] ea543daa28d39acc=ea543daa28d39acc
```

Five outcomes, all logged distinctly:

| Outcome | Output | Exit behaviour |
|---|---|---|
| **Match** | `[sha] verified <local>=<canonical>` | install/upgrade proceeds |
| **Mismatch** | `[BLOCKED] SHA mismatch` + both full fingerprints | package excluded, script exits non-zero; **`--yes` never overrides this** |
| **No bottle** | `[sha] no bottle — built from source` | proceeds (canonical formula exists, isn't bottled) |
| **Tap-only / 404** | `[sha] tap-only formula — no canonical SHA available` | proceeds without prompt (third-party taps) |
| **API 5xx / timeout** | end-of-loop `[WARN] formulae.brew.sh unreachable... Install anyway? [y/N]` | interactive: prompt once for all; `--yes` / non-TTY: warn and continue |

Opt out with `--no-verify-sha` if you trust your tap and want the older behaviour back:

```
brew safe-install --no-verify-sha wget
brew safe-upgrade --no-verify-sha
```

Casks are out of scope — brew already enforces the cask-file SHA on every install, so duplicating that check here adds no signal.

## Updating

Keep **safe-upgrade itself** current through the gated path — pick the line for your install route (`brew safe-upgrade --version` tells you which you're on):

| Install route | Update with |
| ------------- | ----------- |
| **Homebrew formula** (`brew install sharkyger/tap/safe-upgrade`) | `brew safe-upgrade --self` — gates safe-upgrade's own dependencies first (fail-closed), then upgrades the formula. `brew safe-update` runs this for you. |
| **Script / curl** (`install.sh`) | `brew safe-update` — re-fetches the tools from the latest release, verifies every file against the `SHA256SUMS` checksum manifest, and swaps them in atomically (fail-closed). |

Why `--self`: a plain `brew upgrade safe-upgrade` pulls safe-upgrade's own dependencies (its managed Python and that Python's dependencies — `openssl@3`, `sqlite`, …) through Homebrew **ungated** — the gap ([#87](https://github.com/sharkyger/homebrew-safe-upgrade/issues/87)) that `--self` closes.

> This updates **the tool itself**. To CVE-gate an upgrade of *all* your outdated packages, that's the everyday `brew safe-upgrade` (no `--self`).

**Full update routine** — bring both the tool and everything else current, in order:

```bash
brew update        # refresh Homebrew's metadata
brew safe-update   # update safe-upgrade itself (gated — runs --self on a formula install)
brew safe-upgrade  # then CVE-gate an upgrade of everything else outdated
```

Update the updater first, then everything else — the same *refresh, then upgrade* rhythm you already know from `apt update && apt upgrade` (or `dnf upgrade`, `pacman -Syu`, …). The leading `brew update` is optional — `safe-update` and `safe-upgrade` each run it internally.

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

Supports the same `--min-age`, `--allow-unknown-age`, `--no-verify-sha`, and `--no-deps` flags:

```bash
brew safe-install wget curl               # default --min-age 3, SHA verify on
brew safe-install --min-age 7 wget curl   # stricter
brew safe-install --allow-unknown-age foo # permit a pkg whose release age can't be verified
brew safe-install --no-verify-sha wget    # skip SHA check (e.g. on slow networks)
brew safe-install --no-deps wget          # skip transitive dep check
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

Updates all tools to the latest version from GitHub. This is for the **script / manual** install — it refreshes the copies in your Homebrew `bin`.

```
brew safe-update
```

No need to re-run the install script. If you get a permission error:

```
sudo brew safe-update
```

> **Installed via the tap?** On a tap / formula install, `brew safe-update` now delegates to `brew safe-upgrade --self` — it upgrades safe-upgrade *through its own security gate* (its dependencies are checked first, fail-closed) instead of a raw `brew upgrade`. You can also run `brew safe-upgrade --self` directly. See [Updating a tap install](#homebrew-tap-recommended) below.

## Standalone security checker

The vulnerability checker works independently for any ecosystem. Where it
lives depends on how you installed the tool:

```bash
# Homebrew tap install — the script sits in the formula's libexec:
python3 "$(brew --prefix safe-upgrade)/libexec/dependency_security_check.py" <ecosystem> <package> [version]

# Script install (install.sh) — it sits in Homebrew's bin:
python3 "$(brew --prefix)/bin/dependency_security_check.py" <ecosystem> <package> [version]
```

Supported ecosystems: `pip`, `npm`, `composer`, `cargo`, `go`, `maven`, `gem`, `brew`

```bash
# Check a specific Homebrew formula version (tap install shown)
python3 "$(brew --prefix safe-upgrade)/libexec/dependency_security_check.py" brew cmake 4.3.3

# Check a specific version in another ecosystem
python3 "$(brew --prefix safe-upgrade)/libexec/dependency_security_check.py" pip requests 2.31.0

# Check latest version (auto-resolved for pip/npm)
python3 "$(brew --prefix safe-upgrade)/libexec/dependency_security_check.py" npm lodash
```

Exit codes:

- `0` — no known vulnerabilities
- `1` — vulnerabilities found (details on stderr, JSON on stdout)
- `2` — error (invalid input, network failure, or **no source could answer**)

JSON output on stdout for programmatic use:

```json
{
  "status": "clean",
  "package": "requests",
  "ecosystem": "pip",
  "version": "2.31.0",
  "sources_ok": 3,
  "sources_total": 3,
  "sources_failed": [],
  "vulnerabilities": []
}
```

`sources_total` counts only the databases that *can* answer for the ecosystem.
OSV and the GitHub Advisory Database have no Homebrew ecosystem, so for `brew`
the total is `1` (NVD) — a `brew` result reading "3 sources checked" would be
claiming coverage that never existed.

If **no** source answers, the status is `unknown` and the exit code is `2`, not
`clean`/`0`:

```json
{
  "status": "unknown",
  "package": "openssl@3",
  "ecosystem": "brew",
  "version": "3.0.0",
  "sources_ok": 0,
  "sources_total": 1,
  "sources_failed": ["NIST NVD"],
  "vulnerabilities": []
}
```

"Nothing was found" and "nothing was checked" are different answers, and only
the first one means the package is safe to upgrade. `brew safe-upgrade` treats
exit `2` as `[skip] … check failed, will not upgrade`.

## Install

There are two install routes, and **both keep updating** — pick one and stick to it:

- **Homebrew tap (recommended, primary).** Brew-managed: every command and helper
  is installed together and updated atomically with `brew upgrade`. It structurally
  **cannot** leave a half-updated install, so it's the safest route.
- **Script / curl (secondary).** Drops the files into your Homebrew `bin` and
  updates via the hardened self-updater `brew safe-update` (atomic + fail-closed)
  or by re-running `install.sh`.

Don't run both routes at once — a script copy in `bin` and a formula install can
shadow each other on `PATH`. `brew safe-upgrade --version` reports which route you're
on, whether all helper files are present, and warns if both are detected.

### Homebrew tap (recommended)

```bash
brew install sharkyger/tap/safe-upgrade
```

This taps `sharkyger/tap` automatically and installs `brew safe-upgrade`, `brew safe-install`, and `brew safe-update`. The tools need Python 3.11+ (stdlib only); Homebrew pulls in a managed Python as a dependency (currently `python@3.12`).

Equivalently, tap once and then refer to the formula by its short name — handy if you install more than one tool from the tap:

```bash
brew tap sharkyger/tap
brew install safe-upgrade
```

**Updating a tap install:** upgrade safe-upgrade *through its own gate* —

```bash
brew safe-upgrade --self
```

This checks safe-upgrade's own outdated dependencies — its managed Python and that Python's dependencies (`openssl@3`, `sqlite`, …) — against the vulnerability databases and the freshness hold *before* upgrading (fail-closed: a flagged or too-fresh dependency aborts the update), then upgrades the formula once nothing outdated is left for brew to pull. On a formula install, `brew safe-update` runs `brew safe-upgrade --self` for you.

A plain `brew update && brew upgrade safe-upgrade` still works, but Homebrew would then pull those dependencies in unchecked — the gap [#87](https://github.com/sharkyger/homebrew-safe-upgrade/issues/87) that `--self` closes — so `--self` is the recommended path.

### Script install (no tap)

```bash
curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | bash
```

If you get a permission error:

```bash
curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | sudo bash
```

This places all files in your Homebrew bin directory (`/opt/homebrew/bin/` on Apple Silicon, `/usr/local/bin/` on Intel). Homebrew automatically adds external commands prefixed with `brew-` as subcommands.

The installer is supply-chain hardened: it pulls the files from a **pinned, immutable
release tag** (never a moving branch), downloads them to a staging area, and
**verifies every file against a published `SHA256SUMS` manifest before installing
anything**. A truncated download, a tampered file, or a missing file aborts the
whole install — there is no partial state. (The manifest and files travel the same
TLS channel, so the checksums are defense-in-depth on top of HTTPS, not a
replacement for it; the tap route above remains the strongest path.)

### Manual install

```bash
git clone https://github.com/sharkyger/homebrew-safe-upgrade.git
cd homebrew-safe-upgrade
BIN="$(brew --prefix)/bin"   # /opt/homebrew/bin on Apple Silicon, /usr/local/bin on Intel
cp brew-safe-upgrade brew-safe-install brew-safe-update dependency_security_check.py bottle_resolver.py cask_nvd_map.py VERSION "$BIN/"
chmod +x "$BIN"/brew-safe-upgrade "$BIN"/brew-safe-install "$BIN"/brew-safe-update
```

### Verify

```bash
brew safe-upgrade --version
```

This reports the version, your install route, and whether every helper file is
present (a quick way to confirm a healthy install). Then try a real run:

```bash
brew safe-upgrade
```

```bash
brew safe-install wget
```

## Requirements

- macOS or Linux with Homebrew
- Python 3.11+
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
| **Scope** | Everything currently installed | Outdated package + incoming deps | Target package + incoming deps |
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

## Sponsors

This tool stays free and default-on thanks to the people and companies funding the maintenance time.

<!-- sponsors -->No sponsors yet — [become the first](https://github.com/sponsors/sharkyger).<!-- sponsors -->

[**Become a sponsor →**](https://github.com/sponsors/sharkyger)

## License

MIT
