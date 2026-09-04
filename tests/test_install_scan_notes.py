"""Scanner notes reach the user of `brew safe-install`, not only safe-upgrade.

`brew-safe-upgrade` has printed the verdict JSON's `notes` since v0.3.4;
`brew-safe-install` never grew the same call. That went unnoticed until a
finding the scanner declines to BLOCK on — an unresolvable CVE on the newest
available release — started arriving on the clean path: the install side printed
a bare `[ok]` and the CVE was invisible, which is strictly worse than the false
block it replaced.

These tests drive the shell function the wrapper actually uses, so a future
refactor that drops the call or breaks the JSON shape fails here.
"""

import json
import re
import subprocess
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parent.parent / "brew-safe-install"


def _print_scan_notes(verdict: str) -> str:
    """Run the wrapper's own print_scan_notes() against a verdict payload."""
    src = WRAPPER.read_text()
    m = re.search(r"^print_scan_notes\(\) \{.*?^\}", src, re.S | re.M)
    assert m, "print_scan_notes() not found in brew-safe-install"
    script = f'{m.group(0)}\nprint_scan_notes "$1"\n'
    return subprocess.run(
        ["bash", "-c", script, "bash", verdict],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout


def test_the_install_wrapper_still_calls_print_scan_notes():
    """The regression was a missing CALL, not a missing function."""
    src = WRAPPER.read_text()
    assert "print_scan_notes()" in src, "helper missing"
    assert re.search(r'print_scan_notes "\$RESULT"', src), "helper defined but never called"


def test_an_unactionable_finding_is_printed_under_the_ok_line():
    note = (
        "CVE-2026-63728 (MEDIUM) reported by NIST NVD with no version scope, and "
        "8.30.1 is the newest release — no version exists without it."
    )
    verdict = json.dumps({"status": "clean", "notes": [note], "vulnerabilities": []})
    out = _print_scan_notes(verdict)
    assert "note:" in out
    assert "CVE-2026-63728" in out


def test_no_notes_prints_nothing():
    assert _print_scan_notes('{"status":"clean","notes":[],"vulnerabilities":[]}').strip() == ""
    assert _print_scan_notes('{"status":"clean","vulnerabilities":[]}').strip() == ""


@pytest.mark.parametrize("payload", ["not json at all", "", "null", "[]"])
def test_malformed_verdicts_do_not_crash_the_wrapper(payload):
    """The wrapper must never abort a run because a note could not be rendered."""
    assert _print_scan_notes(payload).strip() == ""


def test_the_scan_captures_do_not_fold_stderr_into_the_json():
    """`2>&1` made every json.load fail, so finding_ids was always empty and the
    dependency-relative verdicts were unreachable in production."""
    src = WRAPPER.read_text()
    for call in re.findall(r'\$\(python3 "\$SCRIPT".*?\)', src, re.S):
        assert "2>&1" not in call, f"stderr folded into a JSON capture: {call.strip()[:80]}"
