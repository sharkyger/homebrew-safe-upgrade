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


def test_vulnerability_lines_are_rendered_from_json_not_grepped():
    """The verdict is captured with 2>/dev/null, so the scanner's human-readable
    stderr lines are not in it. A grep over the JSON matched the single dump
    line and printed the ENTIRE document under [VULN]."""
    src = WRAPPER.read_text()
    assert "print_vuln_lines" in src, "install wrapper must render findings from JSON"
    assert "grep -E 'CRITICAL|HIGH|MEDIUM'" not in src, "grep over JSON dumps the whole blob"


def test_notes_render_on_every_verdict_branch():
    """A package can be blocked by one finding and carry an unactionable one, and
    a coverage note can appear on the failed path. Notes only on [ok] hid both."""
    src = WRAPPER.read_text()
    assert src.count('print_scan_notes "$RESULT"') >= 3, "notes missing from a verdict branch"
    assert 'print_scan_notes "$DEP_RESULT"' in src, "dependency path renders no notes"


def test_finding_ids_counts_unactionable_findings():
    """Unactionable is not fixed. Reading only 'vulnerabilities' let [IMPROVES]
    claim a candidate had fixed a finding that applies to both versions."""
    src = WRAPPER.read_text()
    assert "d.get('unactionable')" in src, "finding_ids ignores the unactionable array"


def test_a_null_cvss_score_does_not_erase_the_finding_list():
    """`score > 0` on a null raised TypeError inside the renderer, and the bare
    `except` swallowed it — printing [VULN] with no CVE lines at all."""
    verdict = json.dumps(
        {
            "vulnerabilities": [
                {"id": "CVE-1", "severity": "HIGH", "score": None, "source": "NVD"},
                {"id": "CVE-2", "severity": "LOW", "score": 3.1, "source": "OSV"},
            ]
        }
    )
    src = WRAPPER.read_text()
    m = re.search(r"^print_vuln_lines\(\) \{.*?^\}", src, re.S | re.M)
    out = subprocess.run(
        ["bash", "-c", f'{m.group(0)}\nprint_vuln_lines "$1"\n', "bash", verdict],
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    assert "CVE-1" in out and "CVE-2" in out


def test_cask_build_suffix_is_stripped_before_the_scanner_sees_it():
    """`brew info` reports docker-desktop as "4.89.0,238018"; the scanner's input
    validation rejects the comma, so an unstripped version made every
    comma-versioned cask fail with [skip] and never install."""
    src = WRAPPER.read_text()
    assert "c.get('version', '?')).split(',')[0]" in src or ".split(',')[0]" in src, (
        "install wrapper passes the cask build suffix through verbatim"
    )
