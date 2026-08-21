"""
Output legibility — three things a live 50-package run showed the operator
could not read off the output (2026-08-21):

  1. `[skip] certifi -- check failed` says the same for a 404, a truncated
     read, a rate limit and a 1,000-record overflow. Three distinct bugs
     looked like one for a day because of that. The scanner already knows the
     reason; it now ships it as `failure_reasons` and the wrapper prints it.
  2. CVE detail lines were the first five of the scanner's list, unsorted and
     without a count. NVD's ordering is not stable, so a package with more
     than five CVEs showed a different five on each run — a vanished id reads
     as "fixed". Sorted by score, with "… and N more".
  3. No per-phase timing. A 10-minute run gave no way to tell where the time
     went. Each phase reports its elapsed seconds.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402
from tests.test_age_cache import outdated_formula  # noqa: E402
from tests.test_age_check import run_upgrade, write_outdated  # noqa: E402

# --------------------------------------------------------------------------
# 1. failure reasons
# --------------------------------------------------------------------------


def test_scanner_reports_failure_reasons_in_unknown_verdict(capsys):
    def failing(req, timeout=15):
        raise dsc.urllib.error.HTTPError("https://nvd", 404, "Not Found", {}, None)

    with (
        patch.object(dsc, "_urlopen", side_effect=failing),
        patch.object(sys, "argv", ["x", "brew", "someformula", "1.0"]),
    ):
        try:
            dsc.main()
        except SystemExit as e:
            assert e.code == 2
    out = capsys.readouterr().out
    verdict = json.loads(out[out.rindex("{") :])
    assert verdict["status"] == "unknown"
    assert verdict["failure_reasons"], verdict
    assert any("404" in r for r in verdict["failure_reasons"]), verdict


def _stub(age_env, monkeypatch, body: str, exit_code: int):
    stub = age_env["tmp"] / "cve_stub.py"
    stub.write_text(f"#!/usr/bin/env python3\nimport sys\nprint({body!r})\nsys.exit({exit_code})\n")
    stub.chmod(0o755)
    monkeypatch.setenv("DEPENDENCY_SECURITY_CHECK", str(stub))


def test_skip_line_names_the_reason(age_env, monkeypatch):
    write_outdated(
        age_env["brew"], formulae=[outdated_formula("certifi", "2026.6.17", "2026.7.22")]
    )
    _stub(
        age_env,
        monkeypatch,
        json.dumps(
            {
                "status": "unknown",
                "sources_failed": ["NIST NVD"],
                "failure_reasons": [
                    "NIST NVD: Result set exceeded 1000 records; coverage incomplete"
                ],
                "rate_limited": False,
                "vulnerabilities": [],
            }
        ),
        2,
    )
    result = run_upgrade(["--no-deps", "--min-age", "3"])
    assert "[skip] certifi 2026.7.22 -- check failed" in result.stdout
    assert "Result set exceeded 1000 records" in result.stdout, result.stdout


def test_skip_line_without_reason_field_still_prints(age_env, monkeypatch):
    """Older scanner output (no failure_reasons) must not break the line."""
    write_outdated(
        age_env["brew"], formulae=[outdated_formula("certifi", "2026.6.17", "2026.7.22")]
    )
    _stub(age_env, monkeypatch, '{"status": "unknown", "vulnerabilities": []}', 2)
    result = run_upgrade(["--no-deps", "--min-age", "3"])
    assert "[skip] certifi 2026.7.22 -- check failed, will not upgrade" in result.stdout


# --------------------------------------------------------------------------
# 2. CVE list: sorted, capped with a count
# --------------------------------------------------------------------------


def test_vuln_lines_are_sorted_by_score_and_report_the_remainder(age_env, monkeypatch):
    write_outdated(age_env["brew"], formulae=[outdated_formula("vscodium", "1.121", "1.126")])
    vulns = [
        {"id": f"CVE-2026-{i:05d}", "severity": "HIGH", "score": s, "source": "NIST NVD"}
        for i, s in enumerate([7.1, 8.8, 7.8, 8.4, 9.1, 7.5, 6.5])
    ]
    _stub(age_env, monkeypatch, json.dumps({"status": "vulnerable", "vulnerabilities": vulns}), 1)
    result = run_upgrade(["--no-deps", "--min-age", "3"])
    out = result.stdout
    lines = [line for line in out.splitlines() if "CVE-2026-" in line]
    assert len(lines) == 5, out
    scores = [float(line.split("CVSS ")[1].split(")")[0]) for line in lines]
    assert scores == sorted(scores, reverse=True), scores
    assert "CVE-2026-00004" in lines[0]  # 9.1 first
    assert "and 2 more (7 total)" in out, out


def test_vuln_lines_with_five_or_fewer_have_no_remainder(age_env, monkeypatch):
    write_outdated(age_env["brew"], formulae=[outdated_formula("glib", "2.88.2", "2.88.3")])
    vulns = [{"id": "CVE-2026-1", "severity": "LOW", "score": 3.7, "source": "NIST NVD"}]
    _stub(age_env, monkeypatch, json.dumps({"status": "vulnerable", "vulnerabilities": vulns}), 1)
    result = run_upgrade(["--no-deps", "--min-age", "3"])
    assert "more (" not in result.stdout


# --------------------------------------------------------------------------
# 3. per-phase timing
# --------------------------------------------------------------------------


def test_each_phase_reports_elapsed_seconds(age_env, monkeypatch):
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    _stub(age_env, monkeypatch, '{"status": "clean", "vulnerabilities": []}', 0)
    result = run_upgrade(["--no-deps", "--min-age", "3"])
    out = result.stdout
    assert "age check took " in out and "s)" in out, out
    assert "security checks took " in out, out
