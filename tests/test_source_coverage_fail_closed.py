"""Source-coverage accounting must fail CLOSED when nothing vetted the package.

The scanner queries three databases, but two of them cannot answer for
Homebrew at all: `ECOSYSTEM_MAP["osv"]["brew"]` and
`ECOSYSTEM_MAP["github"]["brew"]` are both None, so query_osv/query_github
return empty WITHOUT issuing a request. NVD is the only source that ever runs
for the tool's primary ecosystem.

Before this fix, a failed NVD query on a brew package produced:

    No known vulnerabilities found (2/3 sources checked)
    {"status": "clean", ...}                      # exit 0

Two independent defects in one line: the count claimed coverage from two
sources that never ran, and "we could not look" was reported as "clean". Any
network fault — offline, proxy, captive portal, DNS block, TLS interception,
rate limit — silently disabled the CVE gate and let the upgrade proceed.

Contract pinned here:

  - Zero answering sources => status "unknown", exit 2 (the documented
    network-failure code, which the brew-safe-* wrappers already treat as
    "check failed, will not upgrade").
  - The denominator counts only sources that CAN answer for the ecosystem.
  - Partial coverage still reports clean, but names the sources that failed
    so the degradation is visible to a machine reader, not just on stderr.
  - A real finding still wins over a source failure (exit 1, not 2).
"""

import io
import json
import sys
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402


def run_main(argv, findings_by_source):
    """Run main() with each query_* stubbed to a canned findings list.

    Returns (exit_code, parsed_stdout_json).
    """
    out, err = io.StringIO(), io.StringIO()
    with (
        patch.object(sys, "argv", argv),
        patch.object(dsc, "query_osv", lambda *a, **k: list(findings_by_source["osv"])),
        patch.object(dsc, "query_github", lambda *a, **k: list(findings_by_source["github"])),
        patch.object(dsc, "query_nvd", lambda *a, **k: list(findings_by_source["nvd"])),
        redirect_stdout(out),
        redirect_stderr(err),
        pytest.raises(SystemExit) as exc,
    ):
        dsc.main()
    try:
        parsed = json.loads(out.getvalue()) if out.getvalue().strip() else {}
    except json.JSONDecodeError:
        parsed = {}
    return exc.value.code, parsed


def error_finding(source):
    return {
        "source": source,
        "id": "ERROR",
        "severity": "UNKNOWN",
        "score": 0,
        "summary": f"Query failed: {urllib.error.URLError('unreachable')}",
    }


def vuln_finding(source="NIST NVD", cve="CVE-2024-0001"):
    return {
        "source": source,
        "id": cve,
        "severity": "HIGH",
        "score": 7.5,
        "summary": "A real finding",
    }


def test_brew_nvd_failure_is_unknown_not_clean():
    """NVD is the ONLY source for brew — if it fails, nothing checked the package."""
    code, out = run_main(
        ["dependency_security_check.py", "brew", "openssl@3", "3.0.0"],
        {"osv": [], "github": [], "nvd": [error_finding("NIST NVD")]},
    )
    assert code == 2, f"expected fail-closed exit 2, got {code}"
    assert out["status"] == "unknown"
    assert out["sources_ok"] == 0
    assert out["sources_total"] == 1, "OSV and GitHub cannot answer for brew"
    assert out["sources_failed"] == ["NIST NVD"]


def test_brew_denominator_excludes_sources_that_never_run():
    """The old code said '2/3 sources checked' when zero sources ran."""
    code, out = run_main(
        ["dependency_security_check.py", "brew", "wget", "1.21.4"],
        {"osv": [], "github": [], "nvd": []},
    )
    assert code == 0
    assert out["sources_total"] == 1
    assert out["sources_ok"] == 1


def test_all_three_sources_failing_is_unknown():
    """A multi-source ecosystem with every source down must not report clean."""
    code, out = run_main(
        ["dependency_security_check.py", "pip", "django", "2.2.0"],
        {
            "osv": [error_finding("OSV.dev")],
            "github": [error_finding("GitHub Advisory")],
            "nvd": [error_finding("NIST NVD")],
        },
    )
    assert code == 2
    assert out["status"] == "unknown"
    assert out["sources_ok"] == 0
    assert out["sources_total"] == 3
    assert out["sources_failed"] == ["GitHub Advisory", "NIST NVD", "OSV.dev"]


def test_partial_coverage_reports_clean_but_names_the_failure():
    """One source down out of three is degraded, not unknown — but must be visible."""
    code, out = run_main(
        ["dependency_security_check.py", "pip", "django", "9.9.9"],
        {"osv": [], "github": [], "nvd": [error_finding("NIST NVD")]},
    )
    assert code == 0
    assert out["status"] == "clean"
    assert out["sources_ok"] == 2
    assert out["sources_total"] == 3
    assert out["sources_failed"] == ["NIST NVD"]


def test_real_finding_beats_a_source_failure():
    """A confirmed vulnerability stays exit 1 even when another source is down."""
    code, out = run_main(
        ["dependency_security_check.py", "pip", "django", "2.2.0"],
        {
            "osv": [vuln_finding("OSV.dev", "CVE-2019-14234")],
            "github": [error_finding("GitHub Advisory")],
            "nvd": [error_finding("NIST NVD")],
        },
    )
    assert code == 1
    assert out["status"] == "vulnerable"


def test_full_coverage_clean_is_unchanged():
    """The happy path keeps exit 0 and status clean."""
    code, out = run_main(
        ["dependency_security_check.py", "pip", "django", "9.9.9"],
        {"osv": [], "github": [], "nvd": []},
    )
    assert code == 0
    assert out["status"] == "clean"
    assert out["sources_ok"] == 3
    assert out["sources_failed"] == []
