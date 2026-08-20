# Proposal: degrade instead of aborting on a GitHub rate limit

Status: **not implemented.** Written alongside the age-check scaling fix
(`fix(age): cut GitHub API calls 49→5`), which deliberately left this alone.

## The current behaviour

When `fetch_pkg_age` sees HTTP 403/429 with `x-ratelimit-remaining: 0` it
returns `-2 ratelimited <reset-epoch>`, and both callers hand that to
`rate_limit_abort`, which prints the reset time and calls `exit 1`.

Four call sites:

| File | Line | Context |
|---|---|---|
| `brew-safe-upgrade` | ~912 | top-level package loop |
| `brew-safe-upgrade` | ~1326 | dependency loop |
| `brew-safe-install` | ~516 | top-level |
| `brew-safe-install` | ~835 | dependency loop |

`--allow-unknown-age` is the existing escape hatch: it converts the abort into
`[ok] <pkg> — GitHub API rate-limited, allowed by --allow-unknown-age`, which is
fail-open for *every* package in the run.

## The problem

The abort is all-or-nothing, and it triggers on the *first* unresolvable
package. Everything already verified is discarded. So the user's two options are
"upgrade nothing" or "`--allow-unknown-age`, skip the freshness gate entirely" —
and the second is the one people will reach for, because the first looks like
the tool is broken.

That was a defensible design when a rate limit meant nothing could be resolved:
one call per package, quota exhausted, every remaining lookup doomed. The
scaling fix changed that premise. Core formulae now resolve from the bottle
registry and cached dates cost nothing, so a run that hits the GitHub limit has
usually **already resolved most of its packages**. On the 49-package backlog
this was measured against, only 5 packages touch GitHub at all. Aborting the
whole run because one tap lookup was throttled now throws away 44 good answers.

## Proposed behaviour

Treat a rate-limited lookup as *unverifiable for that package* — which the code
already has a well-tested policy for — rather than as fatal for the run:

- rate-limited package → `[HOLD] <pkg> — age could not be verified (GitHub API
  rate-limited, resets HH:MM)`, counted in `HELD_PKGS`
- every other package proceeds normally
- one summary note at the end, in the style of `note_rate_limit`, explaining
  that the holds are "nothing could vet this", not "known bad"
- `--allow-unknown-age` keeps its current meaning and still releases them

This is **still fail-closed per package**. It is strictly less fail-open than
the `--allow-unknown-age` workaround the current design pushes people toward.

## Why it was not done in the scaling commit

1. **It changes fail-closed semantics**, which is the security property of the
   tool. It deserves its own commit and its own review, not a footnote in a
   performance fix.
2. **It rewrites a deliberate, tested contract.** Six tests pin the current
   behaviour — four assert the abort itself, two assert the `--allow-unknown-age`
   escape hatch continues the run instead:
   - `test_age_check.py::test_upgrade_rate_limit_aborts_unless_allow_unknown_age`
   - `test_age_check.py::test_install_rate_limit_aborts_unless_allow_unknown_age`
   - `test_age_check.py::test_rate_limit_abort_reports_reset_time`
   - `test_brew_safe_deps.py::test_dep_rate_limit_aborts_run`
   - plus the two `--allow-unknown-age` companions
   These are not incidental assertions; the abort was added on purpose in #84.
3. **It is now rarely reached.** With call volume down ~90% the trigger is much
   less likely, which lowers the urgency and argues for doing it carefully.

## Open questions for whoever picks this up

- **Exit code.** Today a throttled run exits 1. If the run otherwise succeeds
  and only some packages are held, should it exit 0 (holds are a normal outcome)
  or keep a non-zero code so CI notices? Holds from `--min-age` currently do not
  fail the run, which argues for 0 — but that is a silent behaviour change for
  anyone scripting against exit 1.
- **Retry before holding.** The reset time is known. A single wait-and-retry
  when the reset is seconds away might resolve the package outright, but it puts
  an unbounded-looking pause in the middle of a run.
- **Distinguishing the hold reason in the summary.** `Held (too fresh)` and a
  new `Held (unverifiable — rate-limited)` are different user actions: wait
  three days versus authenticate. They should probably not share a bucket.
- **Dependency loop symmetry.** The dep path has its own `HOLD-DEP` handling and
  `--skip-unsafe` interaction; degrading there needs to compose with both rather
  than being copy-pasted from the top-level loop.

## Related finding, already fixed

While tracing these call sites: `rate_limit_abort` told the user to
`export GH_TOKEN=<token>`, which **cannot work** on the `brew safe-upgrade`
route. `brew` re-execs external commands through `env -i` with an allowlist
(`HOME SHELL PATH TERM …` plus `HOMEBREW_*`) and drops everything else, so
`GH_TOKEN` and `GITHUB_TOKEN` never reach the script. The message now
recommends `gh auth login` (token read from disk) and
`HOMEBREW_GITHUB_API_TOKEN` (survives by construction). Whoever rewrites this
path should keep that wording correct.
