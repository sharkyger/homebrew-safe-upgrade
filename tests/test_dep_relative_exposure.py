"""The dependency path compares the candidate against the INSTALLED version.

The top-level scan has had a relative test since the gh 2.98.0 deadlock (see
test_same_exposure). The dependency path never grew one: it ran the scanner on
the incoming dep version and blocked on any finding at all.

That is what trapped pip-cve-gate on 2026-08-24. pip-cve-gate 0.3.3 was [ok] on
age (55 days) and [ok] on CVEs, but it depends on python@3.12. The incoming
python@3.12 3.12.14 carried 9 findings, so it was [VULN-DEP], which tainted
every dependent — pip-cve-gate and shopify-cli both — and the run ended with
"Nothing left to upgrade" and exit 0.

The installed python@3.12 3.12.13 carried 11 findings: the same 9 plus
CVE-2026-15308 (HIGH) and CVE-2026-0864. The upgrade was a strict improvement.
Worse, this does not clear on its own — Python's newest release essentially
always carries open CVEs, so every python-dependent formula was permanently
unupgradeable, not transiently held.

Only the block path pays for the extra scan: one query per FLAGGED dep, not one
per dep, which is the traffic objection the design note in brew-safe-upgrade
raises against doing this for every dependency.
"""

import json

from tests.test_partial_upgrade import (
    run_upgrade,
    write_deps,
    write_formula_info,
    write_installed_version,
    write_outdated,
)
from tests.test_same_exposure import _stub


def _scenario(brew_env, installed_dep="3.12.13", latest_dep="3.12.14"):
    """`app` is clean on its own and depends on `libpy`, which is upgrading."""
    write_outdated(
        brew_env, [{"name": "app", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "app", "2.0")
    write_formula_info(brew_env, "libpy", latest_dep)
    write_deps(brew_env, "app", ["libpy"])
    write_deps(brew_env, "libpy", [])
    write_installed_version(brew_env, "libpy", installed_dep)


def _run(brew_env, stub, input_text="n\n"):
    return run_upgrade(
        [], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text=input_text
    )


def test_dep_strict_subset_does_not_taint_its_dependents(brew_env, tmp_path):
    """The reported bug, reduced to its bones."""
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {
            ("app", "2.0"): [],
            ("libpy", "3.12.13"): ["CVE-A", "CVE-B", "CVE-C"],
            ("libpy", "3.12.14"): ["CVE-A", "CVE-B"],
        },
    )
    out = _run(brew_env, stub, input_text="y\n").stdout
    assert (
        "[IMPROVES-DEP] libpy 3.12.14 -- fixes 1 of 3 finding(s) from installed 3.12.13" in out
    ), out
    assert "[VULN-DEP]" not in out, out
    assert "Depends on a flagged dependency" not in out, out
    assert "Nothing left to upgrade" not in out, out
    # The dependent actually upgraded — the whole point.
    assert json.loads((brew_env / "outdated.json").read_text())["formulae"] == []


def test_dep_with_unchanged_findings_does_not_taint(brew_env, tmp_path):
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {
            ("app", "2.0"): [],
            ("libpy", "3.12.13"): ["CVE-A"],
            ("libpy", "3.12.14"): ["CVE-A"],
        },
    )
    out = _run(brew_env, stub, input_text="y\n").stdout
    assert "[SAME-DEP] libpy 3.12.14 -- same 1 finding(s) as installed 3.12.13" in out, out
    assert "[VULN-DEP]" not in out
    assert json.loads((brew_env / "outdated.json").read_text())["formulae"] == []


def test_dep_that_introduces_a_finding_still_taints(brew_env, tmp_path):
    """The gate's actual job — unchanged."""
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {
            ("app", "2.0"): [],
            ("libpy", "3.12.13"): ["CVE-A"],
            ("libpy", "3.12.14"): ["CVE-A", "CVE-REGRESSION"],
        },
    )
    out = _run(brew_env, stub).stdout
    assert "[VULN-DEP] libpy 3.12.14" in out, out
    assert "[IMPROVES-DEP]" not in out
    assert "Depends on a flagged dependency: app" in out, out


def test_dep_not_installed_has_no_baseline_and_taints(brew_env, tmp_path):
    """A brand-new dep has nothing to compare against. Fail closed."""
    _scenario(brew_env)
    # No list_libpy.txt → brew reports no installed version.
    (brew_env / "list_libpy.txt").unlink()
    stub = _stub(tmp_path, {("app", "2.0"): [], ("libpy", "3.12.14"): ["CVE-A"]})
    out = _run(brew_env, stub).stdout
    assert "[VULN-DEP] libpy 3.12.14" in out, out
    assert "[IMPROVES-DEP]" not in out
    assert "[SAME-DEP]" not in out


def test_dep_installed_scan_failure_taints(brew_env, tmp_path):
    """Unreadable baseline is not a clean baseline. Fail closed."""
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {
            ("app", "2.0"): [],
            ("libpy", "3.12.13"): "FAIL",
            ("libpy", "3.12.14"): ["CVE-A"],
        },
    )
    out = _run(brew_env, stub).stdout
    assert "[VULN-DEP] libpy 3.12.14" in out, out
    assert "[IMPROVES-DEP]" not in out


def test_no_op_skip_option_is_not_offered(brew_env, tmp_path):
    """When no package in the batch is free of the flagged dep, [s] provably
    does nothing — the script says so on the line before. Offering it anyway
    sent the reporter down a dead end twice in one session."""
    _scenario(brew_env)
    stub = _stub(
        tmp_path,
        {
            ("app", "2.0"): [],
            ("libpy", "3.12.13"): ["CVE-A"],
            ("libpy", "3.12.14"): ["CVE-A", "CVE-REGRESSION"],
        },
    )
    out = _run(brew_env, stub).stdout
    assert "No package in this batch is free of the flagged dependencies." in out, out
    assert "[s] skip" not in out, out
    assert "[y] yes" in out, "the real choices stay"
    assert "[N] no" in out


def test_skip_option_is_offered_when_it_would_do_something(brew_env, tmp_path):
    """Regression guard on the line above: an unaffected package keeps [s]."""
    _scenario(brew_env)
    write_outdated(
        brew_env,
        [
            {"name": "app", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "solo", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    write_formula_info(brew_env, "solo", "2.0")
    write_deps(brew_env, "solo", [])
    stub = _stub(
        tmp_path,
        {
            ("app", "2.0"): [],
            ("solo", "2.0"): [],
            ("libpy", "3.12.13"): ["CVE-A"],
            ("libpy", "3.12.14"): ["CVE-A", "CVE-REGRESSION"],
        },
    )
    out = _run(brew_env, stub).stdout
    assert "Unaffected and safe to upgrade now: solo" in out, out
    assert "[s] skip" in out, out
