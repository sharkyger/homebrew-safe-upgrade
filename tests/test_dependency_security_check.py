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


def run_checker(ecosystem, package, version=None):
    """Run the checker and return (exit_code, parsed_json_from_stdout)."""
    cmd = [sys.executable, str(SCRIPT), ecosystem, package]
    if version:
        cmd.append(version)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    try:
        parsed = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        parsed = {}
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
    """Known-clean triples must not be flagged."""
    exit_code, output = run_checker(case["ecosystem"], case["package"], case["version"])
    skip_if_unchecked(exit_code, output, case)
    assert exit_code == 0, (
        f"Expected exit code 0 (clean) for {case['package']}@{case['version']}, "
        f"got {exit_code}. If this version now has CVEs, update the fixture."
    )
    assert output.get("status") == "clean"


def test_invalid_ecosystem_errors_cleanly():
    """Invalid input should exit 2, not 1."""
    exit_code, _ = run_checker("not-a-real-ecosystem", "foo", "1.0")
    assert exit_code == 2


def test_missing_version_handled():
    """For pip, no version should auto-resolve and still work."""
    exit_code, _ = run_checker("pip", "requests")
    assert exit_code in (0, 1)
