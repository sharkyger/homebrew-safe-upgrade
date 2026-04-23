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


@pytest.mark.parametrize(
    "case",
    load_cases()["vulnerable"],
    ids=lambda c: f"{c['ecosystem']}:{c['package']}@{c['version']}",
)
def test_known_vulnerable_is_flagged(case):
    """Known-vulnerable triples must be flagged."""
    exit_code, output = run_checker(case["ecosystem"], case["package"], case["version"])
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
