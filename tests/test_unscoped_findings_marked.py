"""A finding with no version scope must say so wherever it is listed.

The freshness hold prints the INSTALLED version's findings, and it prints them
through the same renderer the security-check loop uses. That renderer showed
every finding identically:

    [HOLD] hugo 0.166.0 — ... installed 0.165.0 has findings but 0.166.0 does
           not demonstrably fix them
      [CRITICAL] CVE-2026-51785 (CVSS 9.8) — NIST NVD

A reader concludes 0.165.0 has an actionable CVSS 9.8. The truth is that NVD
never tied that record to any version — which is *precisely why* 0.166.0 does
not fix it and why the hold stands. The explanation and the evidence contradicted
each other.

Why the findings are in `vulnerabilities` rather than `unactionable` at all:
partition_unactionable() only demotes an unscoped finding when the scanned
version IS the latest. The age check scans the INSTALLED version, which by
definition is not, so they stay blocking — correctly, and with `scoped: False`
still on them. The bug was never the data; it was the rendering.

This is presentation only. `finding_ids()` must keep folding both groups into
the comparison — an unscoped finding is not fixed by an upgrade and applies to
both sides equally — so no hold/bypass decision changes here.
"""

import os
import subprocess
from pathlib import Path

from tests.test_freshness_bypass_requires_reduction import (
    too_fresh,
    write_deps,
    write_formula_info,
    write_outdated,
)

REPO = Path(__file__).parent.parent
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


def scoped_stub(tmp_path, findings):
    """Scanner stub emitting findings with explicit `scoped` flags.

    `findings` is a list of (id, scoped) where scoped is True, False, or None.
    None omits the key entirely — the shape an older scanner, or a source with
    no concept of CPE scoping, produces. Every version gets the same set, so the
    candidate never reduces exposure and the hold always stands.
    """
    items = []
    for fid, scoped in findings:
        entry = {"id": fid, "severity": "HIGH", "score": 7.5, "summary": "s", "source": "stub"}
        if scoped is not None:
            entry["scoped"] = scoped
        items.append(entry)
    stub = tmp_path / "cve_stub_scoped.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"ITEMS = {items!r}\n"
        "pkg = sys.argv[2] if len(sys.argv) > 2 else ''\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "json.dump({'status': 'vulnerable' if ITEMS else 'clean', 'package': pkg,\n"
        "           'version': ver, 'vulnerabilities': ITEMS,\n"
        "           'unactionable': []}, sys.stdout)\n"
        "sys.exit(1 if ITEMS else 0)\n"
    )
    stub.chmod(0o755)
    return stub


def held_run(brew_env, tmp_path, monkeypatch, findings):
    """Stage a too-fresh package whose findings do not shrink, and return stdout."""
    write_outdated(
        brew_env, [{"name": "widget", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    too_fresh("widget")
    monkeypatch.setenv("DEPENDENCY_SECURITY_CHECK", str(scoped_stub(tmp_path, findings)))
    result = subprocess.run(
        ["bash", str(SAFE_UPGRADE), "--no-deps"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=os.environ.copy(),
        input="n\n",
    )
    assert "[HOLD] widget" in result.stdout, result.stdout
    return result.stdout


def test_unscoped_finding_is_marked_on_its_line(brew_env, tmp_path, monkeypatch):
    out = held_run(brew_env, tmp_path, monkeypatch, [("CVE-2099-1", False)])
    line = next(ln for ln in out.splitlines() if "CVE-2099-1" in ln)
    assert "no version scope" in line, line
    # The id and severity must survive — the #72 contract is that a hold names
    # the CVEs the user is being asked to act on.
    assert "[HIGH]" in line and "CVE-2099-1" in line


def test_scoped_finding_is_not_marked(brew_env, tmp_path, monkeypatch):
    """The common case must stay quiet — a marker on everything marks nothing."""
    out = held_run(brew_env, tmp_path, monkeypatch, [("CVE-2099-1", True)])
    line = next(ln for ln in out.splitlines() if "CVE-2099-1" in ln)
    assert "no version scope" not in line, line


def test_missing_scoped_key_is_treated_as_scoped(brew_env, tmp_path, monkeypatch):
    """Absent flag must not be read as False — that would mark every OSV finding."""
    out = held_run(brew_env, tmp_path, monkeypatch, [("CVE-2099-1", None)])
    line = next(ln for ln in out.splitlines() if "CVE-2099-1" in ln)
    assert "no version scope" not in line, line


def test_mixed_findings_mark_only_the_unscoped_ones(brew_env, tmp_path, monkeypatch):
    out = held_run(brew_env, tmp_path, monkeypatch, [("CVE-2099-1", False), ("CVE-2099-2", True)])
    unscoped = next(ln for ln in out.splitlines() if "CVE-2099-1" in ln)
    scoped = next(ln for ln in out.splitlines() if "CVE-2099-2" in ln)
    assert "no version scope" in unscoped, unscoped
    assert "no version scope" not in scoped, scoped


def test_summary_line_explains_why_the_upgrade_cannot_fix_them(brew_env, tmp_path, monkeypatch):
    """The hold says "does not demonstrably fix them" — this is the reason."""
    out = held_run(brew_env, tmp_path, monkeypatch, [("CVE-2099-1", False), ("CVE-2099-2", True)])
    assert "1 of 2 finding(s) carry no version scope" in out, out


def test_no_summary_when_every_finding_is_scoped(brew_env, tmp_path, monkeypatch):
    out = held_run(brew_env, tmp_path, monkeypatch, [("CVE-2099-1", True)])
    assert "carry no version scope" not in out, out


def test_summary_counts_findings_beyond_the_five_displayed(brew_env, tmp_path, monkeypatch):
    """The list truncates at 5; the count must describe all of them, not the page."""
    findings = [(f"CVE-2099-{i}", False) for i in range(1, 8)]
    out = held_run(brew_env, tmp_path, monkeypatch, findings)
    assert "… and 2 more (7 total)" in out, out
    assert "7 of 7 finding(s) carry no version scope" in out, out


def test_both_wrappers_render_findings_identically():
    """`brew-safe-install` carries its own copy of this renderer.

    The copies have drifted before — `brew-safe-install:241` still carries the
    note that print_scan_notes landed on the upgrade side in v0.3.4 and "this
    side never grew one". A fix applied to one and not the other means
    `brew safe-install` keeps rendering unscoped findings bare, which is the
    same defect with the same consequence for the reader. Pinning byte equality
    is cruder than extracting a shared helper, but these are two standalone
    bash entrypoints with no shared library, and a crude guard that fires is
    worth more than a clean one that does not exist.
    """
    import re

    def renderer(path):
        m = re.search(r"^print_vuln_lines\(\) \{.*?^\}", (REPO / path).read_text(), re.S | re.M)
        assert m, f"print_vuln_lines not found in {path}"
        return m.group(0)

    up, inst = renderer("brew-safe-upgrade"), renderer("brew-safe-install")
    assert up == inst, "print_vuln_lines has diverged between the two wrappers"
    assert "no version scope" in inst, "the install side lost the scope marker"
