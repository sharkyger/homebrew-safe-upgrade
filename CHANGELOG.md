# Changelog

All notable changes to `homebrew-safe-upgrade` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The project is pre-1.0; expect minor breaking changes between 0.x releases until the API is considered stable.

## [Unreleased]

### Fixed

- **An upgrade that FIXES vulnerabilities is no longer blocked for still having some — `[IMPROVES]`.** The verdict compared the candidate's findings to the installed version's with `=`, so "exposure unchanged" passed (`[SAME]`, v0.3.4) while "exposure strictly reduced" was blocked. That failed in the unsafe direction: `python@3.12` 3.12.14 fixes two of 3.12.13's eleven findings — CVE-2026-15308 (HIGH) and CVE-2026-0864 — and introduces none, and was blocked for it, holding the machine on the *more* vulnerable version while the run exited 0. The test is now subset, not equality: block on what the candidate **adds**, never on what it removes. Equal findings stay `[SAME]`; a strict subset is `[IMPROVES]`, reported with the count it fixes, summarised on its own line, and upgraded with the clean set. A finding only the candidate carries — even alongside several it fixes — still blocks; so does a clean or unreadable installed-side scan.

- **The dependency path compares against the installed version too — `[SAME-DEP]` / `[IMPROVES-DEP]`.** The top-level scan has had a relative test since `gh` 2.98.0; the dependency path never grew one, and blocked on any finding at all in the incoming version. Because a widely-depended-on formula's newest release essentially always carries some open CVE, that tainted every dependent *permanently*, not transiently: `pip-cve-gate` 0.3.3 and `shopify-cli` 4.7.0 were both `[ok]` on their own checks and both held, leaving a batch that reported "Nothing left to upgrade" and exited 0. Dependencies now use the same subset rule as the top level. The extra installed-side scan runs only once a dep has already been flagged, so it costs one query per *flagged* dep rather than one per dep. A dep that is not installed, or whose installed-side scan fails, has no baseline and still taints — fail closed. Applies to `brew safe-install` as well as `brew safe-upgrade`.

- **`[s]` is no longer offered when it provably does nothing.** When no package in the batch is free of the flagged dependencies — which the line directly above the prompt already states — skipping is a guaranteed no-op, and offering it reads as a safe way out that silently upgrades nothing. The option now appears only when there is an unaffected package for it to upgrade.

## [0.3.4] — 2026-08-22

### Fixed

- **An interrupted `[s]` run no longer leaves your formulae pinned.** Under `[s]` / `--skip-unsafe` the excluded formulae are `brew pin`-ed around the upgrade so brew cannot drag a flagged dependency in underneath something else. That bracket was pin → upgrade → unpin with nothing in between: a Ctrl-C or crash left every excluded formula pinned, silently — and plain `brew upgrade` skips pinned formulae without a word, so a user sat on pinned *vulnerable* packages indefinitely believing they upgrade normally. The wrapper now records the pins it sets (pre-existing pins are yours and are left alone), releases them in a trap on normal exit and on a handled interrupt or termination signal (Ctrl-C, `kill`), and prints what it released. A SIGKILL or a host crash cannot run a trap — after one of those, `brew list --pinned` shows what is left. Verified with the signal delivered inside the unpin loop itself — the Held set is unpinned last, so that is the set a late Ctrl-C used to strand.

- **Identical findings on the installed and the candidate version are "unchanged exposure", not a block — `[SAME]`.** `gh 2.98.0` could never pass: CVE-2024-53858 (Deferred, never given a CPE, fixed in 2.63.0) matched the installed and the candidate version identically on the keyword path, so the freshness hold was waived because the installed version "has CVEs" and the upgrade refused because the candidate "has CVEs". Per-package CPE fixes cannot close the class; the next unscoped record recreates it. When the candidate carries exactly the finding set the installed version carries, the upgrade does not change exposure: it is reported as `[SAME]` with the findings still named, summarised on its own line, and upgraded with the clean set. A finding only the candidate carries, a clean installed version, or an installed-side scan that fails all keep the block.

- **Only the sentence-leading "in <product>" counts on the keyword path.** CVE-2026-14586 is an Unbound bug — "In NLnet Labs Unbound 1.22.0 …, in DNS-over-QUIC environments, …, an assertion in libngtcp2 …" — and the relevance rule matched its third "in", blocking `libngtcp2` on a record about another product. The first "in" of the sentence is now the only one that qualifies, and only in the boilerplate head ("In <product> …", "A vulnerability in <product>", "An issue was discovered in <product>"). Every previously pinned case keeps its side.

- **A versionless CPE is not version scope.** CVE-2026-5201 (gdk-pixbuf JPEG loader) was fixed upstream in 2.44.6; NVD's only upstream applicability is `cpe:2.3:a:gnome:gdk-pixbuf:-` — no version, no bounds — and the scanner reported it against 2.44.8 as `scoped: true`, i.e. "version-confirmed", when nothing in the record speaks to a version. The verdict is unchanged (fail closed: the record does not say 2.44.8 is fixed); the label is corrected — `scoped` is true only when a CPE carries a version bound or a concrete version — which also makes the finding visibly the same evidence-free record on both sides, so `[SAME]` lets the upgrade through instead of deadlocking it.

- **Scanner coverage notes reach the user.** The wrapper runs the scanner with its stderr discarded, so the "N unanalysed NVD records … relying on CPE-analysed records only" note only ever existed on a stderr nobody saw. The scanner now carries its notes in the verdict JSON (`notes`), and `brew safe-upgrade` prints them as `note: …` under `[ok]`, `[SAME]` and `[VULN]` — the same route the rate-limit hint already travels.

### Changed

- **The dependency graph walk is batched; its timing is reported separately from the checks.** A 34-package batch spent 378 s in the dependency phase to find two incoming dependencies: `brew deps` per package, then `brew info` and `brew list` per (package, dependency) *pair*, over closures that overlap almost entirely — several hundred Ruby start-ups. Now one `brew deps --for-each` for the batch, one `brew info` and one `brew list` for the unique dependency set, and the decision runs once per unique dependency (a shared flagged dependency still holds every dependent; each batched call falls back to the per-item call if brew rejects the batch). The phase prints `(dependency graph took Ns)` and `(dependency checks took Ns)` separately, the graph line even when nothing is incoming.

## [0.3.3] — 2026-08-21

### Fixed

- **Three fail-open holes in the new formula CPE map, caught by the CodeRabbit CLI before tagging.** (1) The authoritative CPE query sent Homebrew's version verbatim — `ruby-lang:ruby:4.0.6_1` is a version NVD has never heard of, so it answered 0 and that read as "clean"; the revision (`_N`) and build metadata are now stripped for the query (reporting keeps the raw version). (2) A tap formula sharing a mapped name (`someone/tap/php`) was looked up as `php:php`; the map now applies to core formulae only. (3) A 120-day sweep that overflowed NVD's window dropped its tail silently; it is now stated as "too generic to attribute", the same verdict as the cap.

- **Warp's version scheme parses, so its one genuine CVE clears by version.** `0.2026.08.19.08.15.stable_01` carries a `.stable` release-channel marker the parser treated as an unrecognised suffix → unparseable → every comparison false → CVE-2024-41997 (fixed 2024.07.18) stuck to every later build, recreating the deadlock the cask mapping had just removed. `stable` now parses as a final release, and the description parser reads a bound restated in the product's own scheme — "prior to 2024.07.18 **(v0.2024.07.16.08.02)**", the last affected build — which is the only form comparable to a `0.`-prefixed cask version. Caught by the pre-tag dogfood.

- **Keyword-path relevance now reads the sentence, not just its first words.** The heuristic required the package to be the first words of the description's first sentence, which silently dropped MITRE boilerplate ("An issue was discovered in version of Warp Terminal …", CVE-2024-41997) *and* vendor-prefixed subjects ("GNU Wget does not validate …", CVE-2026-15146). On the keyword path — the only path for casks, tap formulae and any product whose CPE query answers nothing — there is no CPE query underneath, so each rejection was a terminal false negative: a real CVE reported as clean. The product now counts when it is the subject (optionally behind one vendor word) or follows "in"; mentions as an object of use ("Applications that use Wget …", "DEEBOT … use wget command") and in later sentences stay rejected.

- **Verified CPE map for generic-name formulae (`formula_cpe_map.py`).** `php`, `ruby`, `node`, `python`, `certifi`, `git`, `curl`, `openssl`, `sqlite`, `glib`, `imagemagick`, `openldap`, `libssh2`, `hugo`, `pandoc` now query NVD with their verified `vendor:product` (each checked against NVD's CPE dictionary), and that answer is authoritative: zero results means NVD lists no CVE for the version, and the keyword fallback — built for products NVD has no CPE for — is not run. That fallback is what produced the 1,000-record overflow ("coverage incomplete", a permanent hold) on `certifi` and `node`, the 2003-era blocks on `php`, and the VS Code Python-extension CVEs on `python`. Live after the change: php 8.5.9, ruby 4.0.6_1, certifi 2026.7.22, node 26.7.0, imagemagick 7.1.2-29, openldap 2.7.0, glib 2.88.3 → clean; python@3.12 3.12.14 → genuine CPython CVEs only. To keep brand-new CVEs visible while NVD has not assigned a CPE yet, a bounded sweep of the last 120 days keeps keyword records that carry no CPE data — unless more than 10 such records mention the name, in which case the name is too generic for text attribution and the scanner says so (`php`: 603 in one window). Versioned formulae resolve through the base entry. The new module ships with the other helpers.

- **On the keyword path, a record's own CPE data decides what it is about.** php 8.5.9 was blocked on five 2003/2004 "PHP remote file inclusion in <some PHP app>" records whose CPEs name pMachine and ezContents; ruby 4.0.6 on ruby-saml records whose CPEs name omniauth_saml. NVD's CPE list is the authoritative applicability statement: when it exists and nothing in it names our product (exactly, or as a token of a compound like `node.js`), the CVE is about something else regardless of how the prose opens. Records with no CPE data at all are untouched.

- **Findings carry a `scoped` flag.** False when NVD has no applicability data for the record yet and the text names no version bound — the CVE is reported against every version because nothing says it is fixed, not because this version is known affected.

- **A dependency whose check could not be completed no longer rides in under a clean parent.** The dependency pass printed "These will upgrade unchecked" for a dep the scanner could not answer for, and left its dependents in "Unaffected and safe to upgrade now" — while the main pass fails closed for the very same package. An unverifiable dependency is now a flagged dependency: it taints its dependents, gets its own line in the confirmation, and under `[s]` / `--skip-unsafe` it is `brew pin`-ed like a vulnerable or too-fresh one. Same contract in `brew safe-install`. Seen on a live 50-package run, where `node` failed its check and `[skip]`-ed in the main pass but was waved through as an incoming dependency.

- **`[skip]` lines now say why.** "check failed" covered a 404, a truncated read, a rate limit and a 1,000-record overflow identically — which is how three distinct bugs looked like one. The scanner's unknown verdict now carries `failure_reasons`, and `[skip]` / `[skip-dep]` print the first one.

### Changed

- **CVE detail lines are sorted by CVSS score, and a list longer than five ends with "… and N more (M total)".** They used to be the first five in the scanner's order, which follows NVD's — and NVD's order is not stable run to run, so a package with more than five CVEs showed a different five each time and a vanished id read as "fixed".
- **Each phase reports its elapsed time** (age check, security checks, dependency checks), so a long run shows where the time went.

- **Tap formulae outside the `Formula/` layout get a real release date.** The age check asked GitHub for `Formula/<name>.rb` in the tap repo; Homebrew also permits `HomebrewFormula/` and the repo root (`shopify/homebrew-shopify` keeps `shopify-cli.rb` at the root), and for those the query returned nothing → "age could not be verified" on every run. brew already knows the real path because the tap is cloned locally: `brew formula user/tap/name` prints it, and everything after `Taps/<user>/homebrew-<tap>/` is the repo-relative path. No extra GitHub call, no guessing among layouts; the canonical path remains the fallback when brew cannot answer. Live: `shopify/shopify/shopify-cli 4.7.0` → released 2026-08-19.

- **The `warp` cask no longer inherits Cloudflare WARP's CVEs.** Brew's name for the Warp terminal cask is "Warp", which NVD resolves to `cloudflare:warp` — the WARP VPN client — so the terminal carried five Windows-only CVEs (CVE-2022-2225, CVE-2022-4428, CVE-2023-0652, CVE-2023-1412, CVE-2023-1862) on both the installed and the candidate version: the freshness hold was waived *because* the installed build was "vulnerable", then the upgrade was blocked because the candidate carried the same list, and no future release could ever pass. The cask map now sends "Warp Terminal", NVD's own wording for the product (CVE-2024-41997).

## [0.3.2] — 2026-08-21

### Fixed

- **Tap-qualified and `@`-versioned formulae were never actually checked against NVD.** `sharkyger/tap/pip-cve-gate` and `python@3.12` went into the CPE query verbatim; `/` and `@` are not CPE characters, NVD answers HTTP 404, and that error escaped the candidate loop before the base product was tried — so every third-party tap formula and every versioned formula came back `unknown` (a fail-closed hold that no re-run could clear). The tap prefix is now stripped and only CPE-safe candidates are queried, a 404 on one candidate moves on to the next, and the keyword fallback receives the formula's own name. Found on a real 50-package run of 0.3.1.

- **A response that truncated mid-body crashed the scanner.** `http.client.IncompleteRead` (seen on a ~600 KB NVD page), connection resets and socket timeouts are not `URLError`s and surfaced as a raw traceback. They are retried and, if persistent, reported as a normal source failure so the package fails closed like any other unreachable source.

- **VS Code extension CVEs no longer count against the formula.** A vendor-wildcard CPE query for product `python` returns CPython's CVEs *and* five for the VS Code Python extension (`cpe:2.3:a:microsoft:python:*:…:visual_studio_code`). CPEs whose `target_sw` is an editor-extension platform are now foreign for every ecosystem. This is why the fix above does not simply search the bare name as a keyword — that trades a 404 for false positives.

### Known

- A keyword fallback on a very generic name (`certifi`) can exceed NVD's 1,000-record window; the scanner reports "coverage incomplete" and fails closed. Honest, but a blind spot — tracked for a follow-up.

## [0.3.1] — 2026-08-20

### Fixed

- **The age check no longer exhausts GitHub's anonymous rate limit on a machine with a large upgrade backlog.** `fetch_pkg_age` spent one GitHub REST call per outdated package, and anonymous GitHub allows 60 per hour per IP. A machine left un-upgraded for a few weeks routinely has 50–70 outdated packages, so the *first* run could exhaust the quota and a second run within the hour always did — at which point the run aborts and nothing upgrades, which is the worst outcome for exactly the machines that are furthest behind. [#84](https://github.com/sharkyger/homebrew-safe-upgrade/issues/84) raised the ceiling by authenticating; this removes most of the traffic instead. Two changes:
  - Resolved publication dates are **cached on disk**, keyed by package type, name and version. A released version's date is immutable, so repeat runs re-resolve nothing. Location follows `BREW_SAFE_AGE_CACHE_DIR`, then `$HOMEBREW_CACHE/safe-upgrade-age`, then the platform default. Unresolvable ages are never cached, so a fail-closed hold is always re-attempted.
  - **homebrew-core formulae now resolve from the bottle manifest** (`org.opencontainers.image.created` on the OCI image index) rather than the GitHub commits API. Anonymous registry reads are not metered against the REST budget. Measured in a container on a real 49-package backlog (`scripts/dogfood-age-check`): **5 GitHub calls cold and 1 warm, against 49 before.**

- **The bottle timestamp is also the more accurate date.** The commits API returns the last commit that *touched* the formula file, which is not the release. homebrew-core lands a version bump and its bottle hashes as two separate commits — `python@3.14 3.14.7` on 2026-08-09, then `python@3.14: update 3.14.7 bottle.` on 2026-08-13 — and unrelated maintenance commits move the file too, so `per_page=1` could report days after the release it was meant to date. Casks and tap formulae deliberately stay on the commit date: a commit date is attested by GitHub, whereas a tap owner controls their own manifest annotations and could backdate one to slip past `--min-age`.

- **Age-cache hardening from review.** The cache key is the SHA-256 of package type, name and version — the earlier separator folding was not injective (`core:zlib@1.3_1` and `core:zlib_1.3@1` shared a file), so a stale cached date could have waved a brand-new package past `--min-age`. Every timestamp — bottle-manifest annotation, commit date, and cache entry — must now parse as a complete ISO-8601 datetime before it is used or stored; a malformed value is treated as absent and the resolver falls through to the next source, instead of caching a permanent "unknown" hold. Caches written by the pre-release branch are simply not found under the new keys and re-resolve once.

- **`NVD_API_KEY` and `GH_TOKEN` never reached the tool when invoked as `brew safe-upgrade`.** Homebrew does not pass the user's environment to external commands — `bin/brew` rebuilds it with `env -i` from an allowlist (`HOME SHELL PATH TERM …` plus every `HOMEBREW_*` variable) and drops the rest. So the documented advice to `export NVD_API_KEY=...` was silently ineffective on the `brew` route: the run fell back to the anonymous 5-requests/30s budget while the user believed the key was active, and the same applied to `GH_TOKEN`/`GITHUB_TOKEN` for the age check. `HOMEBREW_NVD_API_KEY` and Homebrew's own `HOMEBREW_GITHUB_API_TOKEN` are now accepted as equivalent spellings, both of which survive the scrub by construction. The unprefixed names keep working for direct invocation and CI, and `gh auth login` was always unaffected because that token comes off disk. README updated to stop recommending an export that cannot work.

### Added

- **Runtime hints now recommend a variable that survives `brew`.** `rate_limit_abort` told the user to `export GH_TOKEN=<token>` and the NVD throttle note told them to set `NVD_API_KEY` — neither reaches the script on the `brew safe-upgrade` route. Both now name `gh auth login` / `HOMEBREW_GITHUB_API_TOKEN` and `HOMEBREW_NVD_API_KEY`, with the unprefixed spellings marked as direct-invocation only. The wrapper's "is a key configured?" check reads both spellings too, so a user whose key is working via `HOMEBREW_NVD_API_KEY` no longer gets told to configure one.

- **`docs/age-check-rate-limit-degrade.md`** — written-up proposal for turning the all-or-nothing rate-limit abort into a per-package hold, with the call sites, the six tests that pin the current contract, and the open questions. Deliberately not implemented here: it changes fail-closed semantics and deserves its own review.

- **`scripts/dogfood-age-check`** — a container harness that runs the real age-resolution path over a real outdated-package list and reports how many GitHub calls it actually spends, cold and warm. Runs without a `gh` CLI, without tokens and without a cache, because a host with any of those hides the failure being measured.

## [0.3.0] — 2026-08-18

### Changed

- **NVD is now queried CPE-first, and the result set is paginated.** The NVD lookup used a keyword search capped at `resultsPerPage=10` with no pagination. NVD returns results oldest-first, so for any established package only its *ten oldest* CVEs were ever retrieved — openssh has 177, libreoffice 109. Every report of "current version flagged with a decades-old CVE" traces back to this: those ancient CVEs were the only candidates the matcher ever saw. Queries now go through `virtualMatchString`, which asks NVD for the CVEs applying to a specific product **and** version, so the result set is small, complete and already scoped; keyword search remains as a paginated fallback for products NVD has no CPE for. A result set too large to page through fully is reported as a source failure rather than summarised as "clean". Fixes [#94](https://github.com/sharkyger/homebrew-safe-upgrade/issues/94), [#95](https://github.com/sharkyger/homebrew-safe-upgrade/issues/95) and [#109](https://github.com/sharkyger/homebrew-safe-upgrade/issues/109).

### Added

- **A throttled run now says so, and says what to do about it.** Being rate-limited by NVD and being unable to check are the same outcome — the package is held, fail-closed — but they are not the same message. Previously the run just showed packages held with no stated reason, which reads as the tool being broken and invites reaching for `--no-deps`. NVD's 403/429 responses are now distinguished from ordinary failures, reported as `rate_limited` in the JSON, and summarised once per run by `brew safe-upgrade` / `brew safe-install` with a pointer to `NVD_API_KEY`. The signal travels in the JSON because both wrappers invoke the scanner with stderr suppressed, so its printed hint never reached the user. The note is suppressed when a key is already set, and never shown for a failure that is not a throttle.
- **`NVD_API_KEY` support, with backoff when NVD throttles.** NIST NVD allows 5 requests per rolling 30 seconds anonymously and 50 with a key. That limit became load-bearing once a package with no answering source started being held rather than reported clean: being throttled now means packages don't upgrade. Set `NVD_API_KEY` (free, from <https://nvd.nist.gov/developers/request-an-api-key>) and it is sent as a request header — never in the URL, so it cannot leak into a logged error. Measured on a ten-formula batch in a container: 0 packages left unchecked with a key, 3 without. Throttled requests are also retried with backoff and honour `Retry-After` (capped, so a bad value cannot stall a run), though under sustained load backoff alone cannot recover a 5-request budget.
- **`--skip-unsafe` and an `[s]` answer at the dependency prompt** ([#98](https://github.com/sharkyger/homebrew-safe-upgrade/issues/98)). When an incoming dependency was flagged (a CVE, or below `--min-age`), the only choices were "upgrade it anyway" or "cancel everything" — one too-fresh transitive dependency held back every unrelated package in the batch. safe-upgrade now works out which packages actually depend on the flagged one, holds just those, and upgrades the rest. The held packages *and* the flagged dependency itself are `brew pin`-ed for the duration, so brew cannot resolve the dependency back in underneath another package. `[N]` still cancels the whole run and remains the default, so existing behaviour and scripts are unchanged.

### Fixed

- **Version comparison understands two more upstream dialects.** Bare build-number versions (`b3427` — llama.cpp ships these and NVD records its bounds in that form, while Homebrew strips the prefix) and OpenSSH portmarks (`10.3p1`, a *portable build of* 10.3, ordered above 10.3 and below 10.3p2) previously failed to parse. Unparseable operands make every comparison false, which fails closed — so the freshness and range checks flagged those packages against CVEs they were long past. This also restores the freshness hold for the affected packages: a package whose installed version reads as vulnerable takes the documented CVE-aware bypass around `--min-age`, so a *permanent* false positive meant `--min-age` never applied to that package at all. Thanks to [@jpweytjens](https://github.com/jpweytjens) for identifying both the parse failure and that consequence in [#109](https://github.com/sharkyger/homebrew-safe-upgrade/issues/109).
- **A CPE naming a different product no longer decides applicability.** Version bounds were read from every vulnerable CPE on a CVE, including ones for other software. CVE-2012-4233's LibreOffice CPEs all stop at 3.6, but a single version-less `sun:openoffice.org` entry kept it applying to LibreOffice 26.2.4. When at least one CPE names the package being checked, only those are considered; when none does, the full set is kept, because Homebrew formula names and CPE product names disagree often enough (`node` vs `node.js`) that narrowing unconditionally would drop real findings.
- **Versioned formulae are resolved to their base product.** `openssl@3`, `python@3.11`, `node@20` and the like were sent verbatim to an exact-match keyword search. No CPE and no CVE description contains those strings, so the lookup returned nothing for precisely the long-lived, security-critical formulae.
- **Short formula names are queried instead of skipped.** A `len < 4` guard returned before issuing the NVD request, intended to avoid keyword noise. Because OSV and the GitHub Advisory Database have no Homebrew ecosystem and return empty without querying, NVD is the only source that answers for `brew` — so that guard left `xz`, `git`, `vim`, `php` and `zsh` unexamined.
- **The "all clean" upgrade prompt is reachable again.** `EXCLUDE_PKGS` joins four possibly-empty lists, so "nothing excluded" is a string of three spaces, and the guard compared it against two. A run with nothing blocked, held or skipped still got the cautious "Upgrade clean packages? Excluded ones will be skipped. [y/N]" instead of "All clean. Run brew upgrade? [Y/n]" — wrong text, and the default flipped from yes to no. It is now trimmed rather than matched against a fixed run of spaces.
- **Confirmation prompts are visible when stdin is not a terminal.** `read -rp` renders its prompt only for a terminal, so under a pipe — CI, `yes |` — the question was never printed and the run simply looked stalled. The upgrade prompts now echo the question first, matching what the bottle-SHA prompt already did.
- **Source coverage is accounted for honestly, and reported unknown rather than clean.** A source that could not answer was counted as if it had. The count also included sources that never ran at all, so a brew package could be described as "2/3 sources checked" when zero had examined it. If no source answers, the result is now `status: "unknown"` with exit code `2` — the documented network-failure code, which the wrappers already treat as "check failed, will not upgrade" — instead of `status: "clean"` with exit `0`. The JSON output gained `sources_ok`, `sources_total` and `sources_failed` so degraded coverage is visible to a machine reader and not only on stderr.

## [0.2.9] — 2026-07-01

### Added

- **`brew safe-upgrade --self` — guarded self-upgrade** ([#87](https://github.com/sharkyger/homebrew-safe-upgrade/issues/87)). `brew upgrade safe-upgrade` pulled safe-upgrade's own dependency chain (its managed Python and that Python's dependencies — `openssl@3`, `sqlite`, …) through Homebrew with none of the CVE / bottle-SHA / freshness checks the tool applies to everything else, and the `[y/n]` prompt carried none of that information (and is auto-answered in CI). `--self` closes that gap: it runs safe-upgrade's outdated dependencies through the normal gate first (fail-closed — a flagged or too-fresh dependency aborts the update), re-verifies none is left outdated, and only then upgrades the formula, so brew has nothing ungated left to pull. No new security logic — it reuses the existing check pipeline. Homebrew formula install only; on that route `brew safe-update` now delegates to `brew safe-upgrade --self` instead of pointing at a raw `brew upgrade safe-upgrade`. The script install continues to update via `brew safe-update`'s atomic self-updater.

## [0.2.8] — 2026-06-26

### Added

- **Authenticated GitHub API requests for the age check** ([#84](https://github.com/sharkyger/homebrew-safe-upgrade/issues/84)). The minimum-age/freshness check reads each package's Homebrew metadata age (the last-commit date of its formula/cask file) from the GitHub API, which allows only 60 requests/hour for unauthenticated callers — so a machine with many outdated packages (or repeated runs) could exhaust the quota and lose the ability to verify package age. `brew safe-upgrade` and `brew safe-install` now send authenticated requests (5,000 requests/hour) when a token is available, resolved in order from `GH_TOKEN`, `GITHUB_TOKEN`, then an authenticated `gh` CLI. With no token the tool still works, just at the lower anonymous limit.

### Fixed

- **A GitHub API rate limit is now reported distinctly instead of being mistaken for unverifiable age** ([#84](https://github.com/sharkyger/homebrew-safe-upgrade/issues/84)). When the API rate limit was exhausted, the age check previously returned the same "age could not be verified" result as an unreachable repo, so — under the fail-closed default — every remaining package was silently held. The tool now detects the rate-limit response, stops, and reports when the limit resets, with guidance to authenticate (`GH_TOKEN` / `gh auth login`) or re-run with `--allow-unknown-age`. `--allow-unknown-age` now also permits packages whose age check was blocked by a rate limit.

## [0.2.7] — 2026-06-12

### Fixed

- **More precise NVD CPE applicability matching — same-named packages from other ecosystems no longer block a Homebrew formula** ([#74](https://github.com/sharkyger/homebrew-safe-upgrade/issues/74)). NVD keyword search matches on text, so a formula could collide with an identically-named package from a language ecosystem (the canonical `cmake` formula was permanently blocked by an advisory for the long-dead npm `cmake` package). The scanner now reads the CPE 2.3 `target_sw` field and skips advisories whose every applicability statement is pinned to a *different* language ecosystem (node.js, python, ruby, php, rust, go, java, …). Fail-closed bounds kept: an advisory with even one generic or matching applicability statement still flags, and CPE relevance is now evaluated even when no version is supplied (previously CPE inspection was skipped entirely in that path — distro- and OS-scoped advisories are now filtered there too).
- **`oracle` removed from the distro-vendor CPE filter.** Oracle is also the upstream vendor of widely brewed software (MySQL, OpenJDK, VirtualBox), so its application CPEs (`cpe:2.3:a:oracle:…`) are now evaluated like any other upstream vendor instead of being skipped as distro packaging. Oracle Linux distro CPEs are OS-type and remain filtered by the existing part check. (Surfaced by CodeRabbit on the PR for this release.)
- **Per-package output lines no longer print above the package they belong to** ([#73](https://github.com/sharkyger/homebrew-safe-upgrade/issues/73)). In the "Running security checks" step, detail lines such as `[sha] verified …` printed *before* their `[ok] <package>` line, visually attaching each package's details to the previous package. Details now print indented beneath the package's own verdict line, in `brew safe-upgrade` and `brew safe-install` alike.

### Added

- **The age-check CVE bypass now names the CVEs it acted on** ([#72](https://github.com/sharkyger/homebrew-safe-upgrade/issues/72)). When a too-fresh upgrade is allowed through because the *installed* version has known CVEs, the affected CVE IDs (severity, CVSS score, source — up to 5) print under the bypass line, so the decision to upgrade rests on data instead of a bare "has CVEs" note.

### Documentation

- **README documents where the standalone scanner lives for each install route** ([#75](https://github.com/sharkyger/homebrew-safe-upgrade/issues/75)): `$(brew --prefix safe-upgrade)/libexec/dependency_security_check.py` for tap installs, `$(brew --prefix)/bin/dependency_security_check.py` for script installs.

## [0.2.6] — 2026-06-12

### Fixed

- **`brew safe-upgrade --help` (and `safe-install` / `safe-update`) now render the tool's own usage instead of Homebrew's generic `Example usage:` banner** (follow-up to [#66](https://github.com/sharkyger/homebrew-safe-upgrade/issues/66)). Homebrew's dispatcher intercepts `--help` *before* exec'ing an external command and renders help only from lines beginning with `#:` (see [External Commands](https://docs.brew.sh/External-Commands)); the scripts carried plain `#` comments, so brew fell back to its built-in banner and `print_help()` never ran on that path. Each `brew-safe-*` script now carries a `#:` help block mirroring its `print_help()`, and a regression test drives `brew <cmd> --help` through the real dispatcher to assert the generic banner is gone. The direct-invocation `--help` added in 0.2.5 was unaffected and continues to work.

## [0.2.5] — 2026-06-10

### Added

- **`--help` / `-h` on `brew safe-upgrade`, `brew safe-install`, and `brew safe-update`** ([#66](https://github.com/sharkyger/homebrew-safe-upgrade/issues/66)). Each command now prints a usage block — a one-line description, a synopsis, a flag listing, and examples — and exits cleanly. Help is handled before the helper-file guards, so it answers even on a partially-installed tree. (`--version` self-diagnosis was added in 0.2.2; the two now sit side by side.)

### Changed

- **The self-updater (`brew-safe-update`) now uses the same supply-chain-hardened fetch path as `install.sh`.** It updates to the latest published **release tag** (never a moving branch) and **verifies every file against that release's `SHA256SUMS` manifest** before the atomic, fail-closed swap — including the freshly-fetched updater it re-execs, which is verified before it is handed control. A tampered, truncated, or missing file leaves the existing install untouched. Both curl-fetch routes now share one pin-and-verify discipline. Covered by additions to `tests/test_brew_safe_update.py`.
- **Quieter `brew update` step.** `brew safe-upgrade` now filters Homebrew's own harmless description-cache backtrace (`DescriptionCacheStore`, which self-heals on `brew update-reset`) from its output, while passing any genuine warnings or errors straight through.

### Tooling

- Added a static-analysis + formatting floor: **mypy** (typed scanner + helpers), **shfmt** (shell formatting), **markdownlint**, an **assertive `.coderabbit.yaml`** profile, and a **`.pre-commit-config.yaml`** wrapping them alongside ruff and shellcheck. All wired into CI.

### Documentation

- README install section now leads with the Homebrew **tap** one-liner (`brew install sharkyger/tap/safe-upgrade`) as the recommended route, with the `curl | bash` script installer documented as the secondary route. USAGE still precedes INSTALL.

## [0.2.4] — 2026-06-09

### Changed

- **Hardened the script installer (`install.sh`) against supply-chain tampering.** The installer now pulls its files from a **pinned, immutable release tag** instead of the moving `main` branch, so a `curl … | bash` run always gets exactly one published release. It downloads every file into a staging area and **verifies each one against a published `SHA256SUMS` manifest before installing anything** — a truncated download, a tampered/MITM'd file, or a missing file aborts the whole install with no partial state. The file list is now driven by the manifest itself (one source of truth, shared with the `scripts/gen-sha256sums.sh` generator). The Homebrew tap route was already immutable and is unaffected. Covered by a new hermetic end-to-end smoke (`tests/smoke_install.sh`) that runs the real installer over a local server in CI on both Linux (bash 5) and macOS (bash 3.2) — the script-install route is now exercised in CI for the first time.

### Fixed

- **Single-source version.** `pyproject.toml`'s version had drifted behind the `VERSION` file (the release bump only touched `VERSION`). The two are now realigned and a CI-enforced test keeps them in lockstep, alongside a check that the installer's pinned tag tracks `VERSION`.

## [0.2.3] — 2026-06-08

### Fixed

- **Freshness hold (`--min-age`) now covers casks, tap formulae, and `lib*` formulae, and fails closed** ([#62](https://github.com/sharkyger/homebrew-safe-upgrade/issues/62)). The age check previously looked every package up at `Homebrew/homebrew-core` `Formula/<first-letter>/<name>.rb`. Three classes of package had no release date to compare against and were reported as "age unknown, skipping age check": **casks** (which live in `homebrew-cask`), **tap formulae** (which live in their own tap repo), and **`lib*` formulae** (which homebrew-core shards under `Formula/lib/`, not `Formula/l/` — e.g. `libgit2`, `libheif`, `libusb`). The lookup is now **routed to the correct repo and path** per package: `homebrew-core` (with the `lib/` shard handled) for core formulae, `homebrew-cask` `Casks/<l>/<token>.rb` for casks, and `<user>/homebrew-<tap>` for tap formulae. When a release age **cannot be verified** (home repo unreachable, rate-limited, or a non-standard tap layout), the package is now **held** rather than allowed — the freshness hold is fail-closed, consistent with the rest of the tool. The same routing + fail-closed policy applies to the transitive-dependency age check in both `brew-safe-upgrade` and `brew-safe-install`. The known-too-fresh CVE-aware bypass (skip the hold when the *installed* version has CVEs) is unchanged. Covered by `tests/test_age_check.py` and additions to `tests/test_brew_safe_deps.py`, with a new deterministic `MOCK_COMMITS_API_DIR` test seam.

### Added

- **`--allow-unknown-age`** on `brew safe-upgrade` and `brew safe-install` — permit packages whose release age cannot be verified (default: such packages are held).
- **Single-package `brew safe-upgrade <name> [<name> …]`** ([#61](https://github.com/sharkyger/homebrew-safe-upgrade/issues/61)). Positional package names restrict the run to just those outdated packages instead of everything `brew outdated` reports (matches the full name or its basename, so `safe-upgrade safe-fetch` matches `sharkyger/tap/safe-fetch`). A named package that isn't outdated is reported, not silently ignored.
- **Per-dependency progress in the transitive-dependency scan** ([#60](https://github.com/sharkyger/homebrew-safe-upgrade/issues/60)). Each incoming dependency is now announced with an `[i/N] checking <dep> <version>…` line before its (network-bound) age and CVE checks, so a large scan shows live progress instead of a multi-minute silent wait. Applies to both `brew safe-upgrade` and `brew safe-install`.

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

[Unreleased]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.3.4...HEAD
[0.3.4]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.9...v0.3.0
[0.2.9]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/sharkyger/homebrew-safe-upgrade/compare/v0.1.0...v0.1.1
