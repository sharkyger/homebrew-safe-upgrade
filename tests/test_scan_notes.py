"""Scanner coverage notes reach the user of brew-safe-upgrade.

The wrapper runs the scanner with 2>/dev/null, so a note the scanner only
printed to stderr — "N unanalysed NVD records … relying on CPE-analysed
records only" — was invisible in a real run (2026-08-22 acceptance log). The
scanner now carries notes in the verdict JSON and the wrapper prints them
under the package line, on the clean and on the blocked path alike.
"""

from tests.test_partial_upgrade import (
    run_upgrade,
    write_deps,
    write_formula_info,
    write_outdated,
)

NOTE = "3 unanalysed NVD records from the last 120 days mention 'php' — relying on CPE only."


def _stub(tmp_path, vulnerable: bool):
    stub = tmp_path / "cve_stub.py"
    vulns = (
        "[{'id': 'CVE-2099-1', 'severity': 'HIGH', 'score': 7.5, 'source': 'NIST NVD'}]"
        if vulnerable
        else "[]"
    )
    # Only the CANDIDATE (8.5.9) is vulnerable; the installed 8.5.8 is clean, so
    # the blocked case is a real [VULN] and not the [SAME] state.
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        f"vuln = {vulnerable!r} and ver == '8.5.9'\n"
        "json.dump({'status': 'vulnerable' if vuln else 'clean', "
        f"'vulnerabilities': {vulns} if vuln else [], "
        f"'notes': [{NOTE!r}]}}, sys.stdout)\n"
        "sys.exit(1 if vuln else 0)\n"
    )
    stub.chmod(0o755)
    return stub


def _scenario(brew_env):
    write_outdated(
        brew_env, [{"name": "php", "installed_versions": ["8.5.8"], "current_version": "8.5.9"}]
    )
    write_formula_info(brew_env, "php", "8.5.9")
    write_deps(brew_env, "php", [])


def test_note_is_printed_under_a_clean_verdict(brew_env, tmp_path):
    _scenario(brew_env)
    out = run_upgrade(
        ["--no-deps"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(_stub(tmp_path, False))}
    ).stdout
    assert "[ok] php 8.5.9" in out, out
    assert f"    note: {NOTE}" in out, out
    assert out.index("[ok] php") < out.index("note: ")


def test_note_is_printed_under_a_blocked_verdict(brew_env, tmp_path):
    _scenario(brew_env)
    out = run_upgrade(
        ["--no-deps"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(_stub(tmp_path, True))}
    ).stdout
    assert "[VULN] php 8.5.9" in out, out
    assert f"    note: {NOTE}" in out, out
