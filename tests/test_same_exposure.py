"""[SAME]: identical findings on installed and candidate is not a block.

gh 2.98.0 was blocked by CVE-2024-53858 — Deferred, never given a CPE, fixed
in 2.63.0. The keyword path matched it against the installed AND the
candidate version identically, so the age hold was waived ("installed has
CVEs") and the upgrade refused ("candidate has CVEs"): a package that could
never pass. Per-package CPE fixes do not close the class; the next unscoped
record recreates it.

The rule under test: the same finding set on both sides means the upgrade
does not change exposure — its own state, reported as such and upgraded with
the clean set. Anything else stays blocked.
"""

import json

from tests.test_partial_upgrade import (
    run_upgrade,
    write_deps,
    write_formula_info,
    write_outdated,
)


def _stub(tmp_path, table: dict):
    """table: (package, version) → list of finding ids, or 'FAIL' for exit 2."""
    stub = tmp_path / "cve_stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"TABLE = {table!r}\n"
        "pkg = sys.argv[2] if len(sys.argv) > 2 else ''\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "ids = TABLE.get((pkg, ver), [])\n"
        "if ids == 'FAIL':\n"
        "    json.dump({'status': 'error', 'failure_reasons': ['network']}, sys.stdout)\n"
        "    sys.exit(2)\n"
        "if ids:\n"
        "    json.dump({'status': 'vulnerable', 'package': pkg, 'vulnerabilities': "
        "[{'id': i, 'severity': 'MEDIUM', 'score': 6.5, 'source': 'NIST NVD'} for i in ids]}, "
        "sys.stdout)\n"
        "    sys.exit(1)\n"
        "json.dump({'status': 'clean', 'package': pkg, 'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    return stub


def _scenario(brew_env):
    write_outdated(
        brew_env, [{"name": "gh", "installed_versions": ["2.98.0"], "current_version": "2.99.0"}]
    )
    write_formula_info(brew_env, "gh", "2.99.0")
    write_deps(brew_env, "gh", [])


def _run(brew_env, stub, input_text="n\n"):
    return run_upgrade(
        ["--no-deps"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text=input_text
    )


def test_same_finding_set_is_its_own_state_and_upgrades(brew_env, tmp_path):
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {("gh", "2.98.0"): ["CVE-2024-53858"], ("gh", "2.99.0"): ["CVE-2024-53858"]},
    )
    result = _run(brew_env, stub, input_text="y\n")
    out = result.stdout
    assert "[SAME] gh 2.99.0 -- same 1 finding(s) as installed 2.98.0" in out, out
    assert "[VULN]" not in out
    assert "CVE-2024-53858" in out, "the finding is still named, the user decides on data"
    assert "Unchanged exposure (same findings as installed, upgrading): gh" in out
    assert "Blocked (vulnerable)" not in out
    assert "Clean formulae to upgrade: gh" in out, out
    # brew upgrade ran: the mock drops upgraded packages from outdated.json
    assert json.loads((brew_env / "outdated.json").read_text())["formulae"] == []


def test_order_of_findings_does_not_matter(brew_env, tmp_path):
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {
            ("gh", "2.98.0"): ["CVE-2024-1", "CVE-2024-2"],
            ("gh", "2.99.0"): ["CVE-2024-2", "CVE-2024-1", "CVE-2024-2"],
        },
    )
    out = _run(brew_env, stub).stdout
    assert "[SAME] gh 2.99.0 -- same 2 finding(s)" in out, out


def test_candidate_only_finding_stays_blocked(brew_env, tmp_path):
    """A finding the candidate carries and the installed version does not is a
    real regression — that is exactly what the gate is for."""
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {("gh", "2.98.0"): ["CVE-2024-53858"], ("gh", "2.99.0"): ["CVE-2024-53858", "CVE-2026-9"]},
    )
    out = _run(brew_env, stub).stdout
    assert "[VULN] gh 2.99.0" in out, out
    assert "[SAME]" not in out
    assert "Blocked (vulnerable): gh" in out


def test_installed_clean_stays_blocked(brew_env, tmp_path):
    _scenario(brew_env)
    stub = _stub(tmp_path, {("gh", "2.99.0"): ["CVE-2026-9"]})
    out = _run(brew_env, stub).stdout
    assert "[VULN] gh 2.99.0" in out, out
    assert "[SAME]" not in out


def test_installed_scan_failure_stays_blocked(brew_env, tmp_path):
    """Fail closed: if the installed side cannot be read, nothing is 'the same'."""
    _scenario(brew_env)
    stub = _stub(tmp_path, {("gh", "2.98.0"): "FAIL", ("gh", "2.99.0"): ["CVE-2024-53858"]})
    out = _run(brew_env, stub).stdout
    assert "[VULN] gh 2.99.0" in out, out
    assert "[SAME]" not in out
