# LESSONS — homebrew-safe-upgrade

Durable, repo-local record of incidents that reached users, and the rule each
one bought. Read before touching distribution, install/update, or path logic.

**Golden rule: incident → regression test.** Every bug that reaches a user lands
as a CI-enforced test in the same change that fixes it — never as a note. A note
let the helper-strand recur across two releases; a test would not have.

---

## 1. Helper-file strand (recurred twice) — v0.2.0 (Intel), v0.2.1 (Apple Silicon)

**Symptom:** `brew safe-upgrade` aborts with
`Error: bottle SHA resolver not found at <prefix>/bin/bottle_resolver.py`.

**Cause:** the script-install self-updater (`brew-safe-update`) carries a
hardcoded file list. An *older* installed updater ran its own short list,
fetched only some files, **still printed "All tools updated"**, and stranded the
helpers added in a later version (`bottle_resolver.py`, `cask_nvd_map.py`). With
SHA-verify default-on, `bottle_resolver.py` is load-bearing, so the tool failed
closed. It was **not** an architecture-prefix bug — `/usr/local` and
`/opt/homebrew` both resolve fine; the only difference between the two Macs was
the *age of the installed updater*.

**Fix (v0.2.2):** updater re-execs the freshly-fetched copy **before** the
download loop (the list that runs is always current) **and** is **atomic +
fail-closed** — stage every file, swap in only if all arrive, never report
success on a partial set. See `tests/test_install_hardening.py`,
`tests/test_brew_safe_update.py`, `tests/test_distribution_manifest.py`.

**Rule:** a distribution step must be all-or-nothing and must never claim success
on a partial result. Any file added to the runtime set is guarded by
`test_distribution_manifest.py`.

## 2. Path assumptions are architecture- and layout-specific

Homebrew lives at `/usr/local` (Intel) and `/opt/homebrew` (Apple Silicon), and
an install may be a script copy in `bin`, a Homebrew-formula layout in `libexec`,
or a symlink. Self-location via bare `dirname "${BASH_SOURCE[0]}"` broke for
symlinked/relocated installs, and `readlink -f` does not exist on stock macOS.

**Fix (v0.2.2):** a portable symlink-resolving `resolve_script_dir` in all three
scripts. **Rule:** never assume a fixed prefix or a non-symlinked path; resolve
the real directory portably and test it (`test_symlinked_install_*`).

## 3. A self-test that can't see the bug is worse than no test

The Homebrew formula's `test do` ran `brew-safe-upgrade` with
`BREW_SAFE_BOTTLE_RESOLVER=/nonexistent` — it *overrode* the very path under test,
so it passed regardless of whether the real resolver was found. CI was green
while the script-install route was broken.

**Rule:** the test must exercise the real code path. v0.2.2 adds a **real
install-and-run smoke for the script route on both macOS arches** (macos-14
arm64 + macos-13 x86_64) that runs the command without the override.

## 4. You can't fix what you can't see — version visibility

There was no `--version`, so a stranded/old install was invisible to the user and
to us. **Rule:** ship `--version` with self-diagnosis (route + helper presence)
from a single-source `VERSION` file; a broken install should explain itself.

## 5. Dogfood the route users actually use

v0.2.1 was "dogfooded" only on x86_64 Linux (the real linuxbrew install failed
under qemu emulation and was substituted with a Python-level test), so the macOS
install-and-run was never verified — exactly where the bug lived.

**Rule:** before publish, run the actual install-and-run on the actual target
platforms/routes. Container/Linux checks do not substitute for the macOS routes
users run.

## 6. The installer was the weakest link — pin + verify the supply chain — v0.2.4

For a tool whose entire job is gating supply-chain risk, the script installer
itself was the soft spot: `install.sh` fetched every file from the **moving
`main` branch** with **no integrity check**, so a `curl … | bash` user got
whatever was on `main` at that instant, and a corrupted/MITM'd/CDN-tampered file
was installed silently.

**Fix (v0.2.4):** pin downloads to an **immutable release tag**, drive the file
list from a published **`SHA256SUMS` manifest**, stage every file and **verify all
before installing any** (atomic + fail-closed, like the updater in lesson 1). And
— closing the same gap as lessons 3 and 5, now for `install.sh` — a **hermetic
end-to-end smoke** (`tests/smoke_install.sh`) runs the real installer over a local
server in CI on Linux *and* macOS (bash 3.2), so the script route is finally
exercised, not assumed. Guards: `tests/test_install_manifest.py`,
`tests/test_distribution_manifest.py`.

**Honest trust model:** manifest and files travel the same TLS channel, so the
checksums are defense-in-depth (transfer integrity + tag immutability) on top of
HTTPS, not a substitute for it. The brew-formula route remains the strongest path.

**Open follow-up (tracked in `.codereview/`):** the self-updater
`brew-safe-update` still fetches from `main` with no checksum verification. It
should adopt the same pin-to-tag + `SHA256SUMS` verification so both curl-fetch
routes share one hardened path. Deferred from v0.2.4 to keep the load-bearing
updater untouched right before release.

## 7. Two version sources drift unless something ties them — v0.2.4

`pyproject.toml`'s `version` silently lagged at `0.2.2` while the `VERSION` file
(the tool's single runtime source) was already `0.2.3`, because the release bump
only ever touched `VERSION`. Nothing compared them, so the drift was invisible.

**Rule:** if a version must live in two places, a CI test ties them together. The
release bump now updates both, and `test_install_manifest.py` fails the build if
`pyproject` ≠ `VERSION`, or if the installer's pinned tag ≠ `VERSION`. A second
source with no cross-check is a drift waiting to happen.
