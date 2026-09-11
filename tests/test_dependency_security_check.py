"""
Integration tests for dependency_security_check.py.

These tests hit live vulnerability databases. They are slow and network-dependent
by design — the whole point is to verify the tool correctly classifies real CVEs.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "known_cases.json"
SCRIPT = Path(__file__).parent.parent / "dependency_security_check.py"


def load_cases():
    with FIXTURES.open() as f:
        return json.load(f)


# How long we are willing to wait for a verdict before giving up on one.
#
# This is a budget, NOT the scanner's worst case — that cannot be bounded
# usefully here. One live check is not one request: _nvd_fetch pages up to
# NVD_MAX_PAGES (5) times per query, query_nvd runs that for each CPE candidate
# and may add a keyword fallback and a recent sweep, and OSV.dev and GitHub
# Advisory follow. Each individual request may be retried NVD_MAX_RETRIES (3)
# times, each socket wait bounded by _urlopen's 15s default, with backoff sleeps
# of min(NVD_RETRY_BASE_SECONDS * n, 30) that a Retry-After header can stretch to
# the full 30s. A worst case built from those numbers runs to many minutes, and
# waiting it out would be worse than not testing.
#
# So this number buys a definite answer most of the time and accepts that a
# legitimately slow-but-working scanner can still hit it. The old 60s cap is
# what made that unacceptable: it was below even a SINGLE request's worst case,
# so ordinary throttling reliably blew it, and it raised TimeoutExpired — a hard
# ERROR that never reached the exit-2 skip path below. What follows is therefore
# careful to report "no verdict within N seconds", never "the databases are
# down": we genuinely cannot tell those apart from out here, which is what the
# zero-coverage guard in conftest.py exists to catch.
CHECKER_TIMEOUT_SECONDS = 600

# Once one live check has run out of clock, the databases are effectively
# unavailable to this run. Re-spending the budget on every remaining case would
# turn one rate limit into a multi-hour job, so the first timeout short-circuits
# the rest; they would have skipped anyway.
#
# This is the dangerous half of the design: it cannot tell a rate limit from a
# scanner that hangs, so a real regression could retire the whole live suite and
# leave the build green. `live_verdicts` is what makes that visible —
# pytest_sessionfinish fails the run if a key was present and no live case ever
# reached an assertion. See tests/test_live_api_harness.py.
_LIVE_CHECKS_TIMED_OUT = False

# Session counters read by conftest.pytest_sessionfinish. Module state rather
# than a fixture because run_checker is a plain function, not a fixture user.
live_verdicts = 0
live_skips = 0


def _count_live_skip():
    global live_skips
    live_skips += 1


def _count_live_verdict():
    global live_verdicts
    live_verdicts += 1


def run_checker(ecosystem, package, version=None, live=True):
    """Run the checker and return (exit_code, parsed_json_from_stdout).

    `live` marks a call that reaches the vulnerability databases. Those may skip
    when the databases cannot answer in time. Offline calls (invalid input, a
    broken script path) pass live=False: there is no rate limit to forgive
    there, so a hang is a real bug and must stay a failure.
    """
    global _LIVE_CHECKS_TIMED_OUT

    if live and _LIVE_CHECKS_TIMED_OUT:
        _count_live_skip()
        pytest.skip(
            "an earlier live check exceeded "
            f"{CHECKER_TIMEOUT_SECONDS}s; treating the vulnerability databases "
            "as unavailable for this run"
        )

    cmd = [sys.executable, str(SCRIPT), ecosystem, package]
    if version:
        cmd.append(version)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=CHECKER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if not live:
            raise
        _LIVE_CHECKS_TIMED_OUT = True
        _count_live_skip()
        pytest.skip(
            f"{ecosystem}:{package} returned no verdict within "
            f"{CHECKER_TIMEOUT_SECONDS}s — the databases did not answer. The "
            "usual cause is NVD throttling (5 requests / 30s) with no "
            "NVD_API_KEY set; forked PRs never receive repository secrets."
        )
    try:
        parsed = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        parsed = {}
    if live:
        # Exit 2 is the documented "no source answered" shape, which
        # skip_if_unchecked turns into a skip — that is not a verdict, and
        # counting it as one would let a fully throttled run satisfy the
        # zero-coverage guard.
        if result.returncode == 2:
            _count_live_skip()
        else:
            _count_live_verdict()
    return result.returncode, parsed


def skip_if_unchecked(exit_code, output, case):
    """Exit 2 means no source answered — there is no verdict to assert against.

    These cases run against the live databases, and NVD's anonymous limit is
    5 requests / 30 seconds; a full parametrized sweep can trip it. Since the
    scanner now fails CLOSED on zero coverage (status "unknown", exit 2) rather
    than reporting "clean", that outcome is correct behaviour but carries no
    information about the package. Skipping keeps the assertion meaningful when
    the databases do answer, instead of turning a rate limit into a red build.
    """
    if exit_code == 2:
        # Exit 2 is also returned for invalid input and a broken script path.
        # Only the documented no-source-answered shape may skip; anything else
        # exiting 2 is a real failure and must not be swallowed.
        assert output.get("status") == "unknown", (
            f"exit 2 without the documented unknown-result shape: {output!r}"
        )
        assert output.get("sources_ok") == 0, f"exit 2 but sources_ok != 0: {output!r}"
        assert isinstance(output.get("sources_total"), int) and output["sources_total"] > 0, (
            f"unknown result must name how many sources were applicable: {output!r}"
        )
        assert output.get("sources_failed"), (
            f"unknown result must name the sources that failed: {output!r}"
        )
        failed = output.get("sources_failed") or ["unknown"]
        pytest.skip(
            f"no vulnerability source answered for {case['package']}@{case['version']} "
            f"(failed: {', '.join(failed)}) — no verdict to assert"
        )


@pytest.mark.parametrize(
    "case",
    load_cases()["vulnerable"],
    ids=lambda c: f"{c['ecosystem']}:{c['package']}@{c['version']}",
)
def test_known_vulnerable_is_flagged(case):
    """Known-vulnerable triples must be flagged."""
    exit_code, output = run_checker(case["ecosystem"], case["package"], case["version"])
    skip_if_unchecked(exit_code, output, case)
    assert exit_code == 1, (
        f"Expected exit code 1 (vulnerable) for {case['package']}@{case['version']}, "
        f"got {exit_code}. Reason: {case['reason']}"
    )
    assert output.get("status") == "vulnerable"
    assert len(output.get("vulnerabilities", [])) > 0


@pytest.mark.parametrize(
    "case",
    load_cases()["clean"],
    ids=lambda c: f"{c['ecosystem']}:{c['package']}@{c['version']}",
)
def test_known_clean_is_not_flagged(case):
    """Known-clean triples must not be flagged by any version-SCOPED record.

    A record NVD has not analysed yet (no CPE data, no version in the text)
    applies to every version under fail-safe semantics — that is the one
    kind of finding a "clean" fixture may tolerate, and the version filter
    has nothing to decide on it. Everything else must be excluded.
    """
    exit_code, output = run_checker(case["ecosystem"], case["package"], case["version"])
    skip_if_unchecked(exit_code, output, case)
    scoped = [v for v in output.get("vulnerabilities", []) if v.get("scoped", True)]
    assert not scoped, (
        f"{case['package']}@{case['version']} flagged by version-scoped records "
        f"{[v['id'] for v in scoped]}. If this version now has CVEs, update the fixture."
    )
    if exit_code == 0:
        assert output.get("status") == "clean"


def test_invalid_ecosystem_errors_cleanly():
    """Invalid input should exit 2, not 1."""
    exit_code, _ = run_checker("not-a-real-ecosystem", "foo", "1.0", live=False)
    assert exit_code == 2


def test_missing_version_handled():
    """For pip, no version should auto-resolve and still work."""
    exit_code, output = run_checker("pip", "requests")
    # This reaches the live databases exactly like its parametrized siblings, so
    # it needs the same forgiveness: without this it asserted straight against
    # exit_code and turned a rate limit into a red build (Dependabot #132).
    skip_if_unchecked(exit_code, output, {"package": "requests", "version": "(auto-resolved)"})
    assert exit_code in (0, 1)
