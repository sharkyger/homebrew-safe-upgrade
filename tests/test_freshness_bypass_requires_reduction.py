"""The freshness hold is waived only for a candidate that reduces exposure.

The `--min-age` hold is the control against a freshly-compromised release. It
had a CVE-aware bypass, and the bypass triggered on *exposure*: "the INSTALLED
version has known CVEs, so this fresh release is likely the fix". Likely is not
evidence, and on a real run (2026-09-10) three of four bypasses bought nothing:

    [ok] hugo 0.166.0 — released 1 day(s) ago, but installed 0.165.0 has CVEs
         — bypassing age check
      [CRITICAL] CVE-2026-51785 (CVSS 9.8) — NIST NVD
      ...
    [ok] hugo 0.166.0
      note: CVE-2026-51785 (CRITICAL) reported with no version scope, and
            0.166.0 is the newest release — reported rather than blocked.

The four findings that justified skipping the hold are carried by the candidate
too. `nss` and `snyk` were the same shape. Only `vscodium` earned it, fixing 13
of 14. So a one-day-old release skipped the supply-chain hold on no evidence of
a fix — the riskier half of the trade, taken for nothing.

The rule is now the strict-subset test the `[IMPROVES]` verdict already uses,
and it works because `finding_ids()` folds `unactionable` into the comparison:
a finding NVD could not tie to a version is not *fixed* by the upgrade, it is
merely not grounds to block, and it applies to both sides equally. That reasoning
was already written down in `finding_ids()`; the bypass never applied it.

Fail-closed cases, all covered below: no findings on the installed side, an
unreadable candidate scan, an unknown installed version, and equal findings.
"""

import datetime
import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


def write_outdated(fixture_dir, formulae=(), casks=()):
    (fixture_dir / "outdated.json").write_text(
        json.dumps({"formulae": list(formulae), "casks": list(casks)})
    )


def write_formula_info(fixture_dir, name, version):
    target = fixture_dir / f"info_{name}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "formulae": [{"name": name, "full_name": name, "versions": {"stable": version}}],
                "casks": [],
            }
        )
    )


def write_deps(fixture_dir, name, deps=()):
    (fixture_dir / f"deps_{name}.txt").write_text("\n".join(deps) + ("\n" if deps else ""))


def too_fresh(name, days=0):
    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    (Path(os.environ["MOCK_COMMITS_API_DIR"]) / f"{name}.json").write_text(
        json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])
    )


def findings_stub(tmp_path, per_version, exit_code=1):
    """Scanner stub returning a named finding set per version.

    `per_version` maps a version string to a list of (id, kind) pairs, where kind
    is "vuln" or "unactionable" — the distinction matters, because the whole
    point is that an unactionable finding still counts as present on both sides.
    """
    stub = tmp_path / "cve_stub_sets.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"SETS = {per_version!r}\n"
        "pkg = sys.argv[2] if len(sys.argv) > 2 else ''\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "items = SETS.get(ver, [])\n"
        "vulns = [{'id': i, 'severity': 'HIGH', 'score': 7.5, 'summary': 's',\n"
        "          'source': 'stub'} for i, k in items if k == 'vuln']\n"
        "unact = [{'id': i, 'severity': 'HIGH', 'score': 7.5, 'summary': 's',\n"
        "          'source': 'stub'} for i, k in items if k == 'unactionable']\n"
        "json.dump({'status': 'vulnerable' if vulns else 'clean', 'package': pkg,\n"
        "           'version': ver, 'vulnerabilities': vulns,\n"
        "           'unactionable': unact}, sys.stdout)\n"
        "sys.exit(1 if items else 0)\n"
    )
    stub.chmod(0o755)
    return stub


def run_upgrade(env_extra=None, args=(), input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE), "--no-deps", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        input=input_text,
    )


def scenario(brew_env, name="widget", installed="1.0", current="2.0"):
    write_outdated(
        brew_env,
        [{"name": name, "installed_versions": [installed], "current_version": current}],
    )
    write_formula_info(brew_env, name, current)
    write_deps(brew_env, name)
    too_fresh(name, days=0)


# --------------------------------------------------------------------------


def test_same_findings_on_both_sides_holds(brew_env, tmp_path):
    """The hugo case. Identical findings means no evidence of a fix, so a
    one-day-old release does not get to skip the supply-chain hold."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {"1.0": [("CVE-2099-1", "vuln")], "2.0": [("CVE-2099-1", "vuln")]},
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout
    assert "does not demonstrably fix them" in result.stdout, result.stdout


def test_unactionable_on_the_candidate_is_not_a_fix(brew_env, tmp_path):
    """Precisely hugo: the finding is a blocking vuln against the old version and
    merely *unactionable* against the new one. It is not fixed — NVD just could
    not scope it — so it must not count as a reduction."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {"1.0": [("CVE-2099-1", "vuln")], "2.0": [("CVE-2099-1", "unactionable")]},
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


def test_strict_reduction_bypasses(brew_env, tmp_path):
    """The vscodium case: drops findings, adds none. This is what the bypass is
    for, and it must keep working — the fix must not become a blanket hold."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {
            "1.0": [("CVE-2099-1", "vuln"), ("CVE-2099-2", "vuln"), ("CVE-2099-3", "vuln")],
            "2.0": [("CVE-2099-1", "vuln")],
        },
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" in result.stdout, result.stdout
    assert "fixes 2 of 3 finding(s) from installed 1.0 and adds none" in result.stdout, (
        result.stdout
    )
    assert "[HOLD] widget" not in result.stdout, result.stdout


def test_candidate_that_adds_a_finding_holds(brew_env, tmp_path):
    """Fixes two but introduces one. Not a strict subset — and a brand-new
    release that adds an unknown is exactly what the hold is for."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {
            "1.0": [("CVE-2099-1", "vuln"), ("CVE-2099-2", "vuln"), ("CVE-2099-3", "vuln")],
            "2.0": [("CVE-2099-1", "vuln"), ("CVE-2099-9", "vuln")],
        },
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


def test_clean_installed_still_holds(brew_env, tmp_path):
    """Unchanged: nothing on the installed side means nothing to improve on."""
    scenario(brew_env)
    stub = findings_stub(tmp_path, {"1.0": [], "2.0": []})
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout
    # The plain hold, not the "has findings but does not fix them" variant.
    assert "does not demonstrably fix" not in result.stdout, result.stdout


def test_unreadable_candidate_scan_holds(brew_env, tmp_path):
    """Exit 2 is 'no source could answer'. No evidence of reduction, so the hold
    stands — fail closed, the same rule the rest of the file follows."""
    scenario(brew_env)
    stub = tmp_path / "cve_stub_err.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "if ver == '1.0':\n"
        "    json.dump({'status': 'vulnerable', 'vulnerabilities': [{'id': 'CVE-2099-1',\n"
        "               'severity': 'HIGH', 'score': 7.5, 'source': 'stub'}],\n"
        "               'unactionable': []}, sys.stdout)\n"
        "    sys.exit(1)\n"
        "json.dump({'status': 'unknown', 'sources_ok': 0, 'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(2)\n"
    )
    stub.chmod(0o755)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


def test_min_age_zero_still_overrides(brew_env, tmp_path):
    """The documented escape hatch has to keep working, or the stricter rule
    leaves a user with a genuinely exploitable installed version and no way out
    short of bypassing the tool entirely."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {"1.0": [("CVE-2099-1", "vuln")], "2.0": [("CVE-2099-1", "vuln")]},
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)}, args=("--min-age", "0"))
    assert "[HOLD] widget" not in result.stdout, result.stdout


def test_hold_line_says_why_it_was_not_bypassed(brew_env, tmp_path):
    """A user who saw the old bypass will want to know why it stopped happening;
    a bare '[HOLD] … min-age: 3 days' reads like the CVE was never noticed."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {"1.0": [("CVE-2099-1", "vuln")], "2.0": [("CVE-2099-1", "vuln")]},
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    hold = [ln for ln in result.stdout.splitlines() if "[HOLD] widget" in ln][0]
    assert "has findings" in hold, hold
    assert "--min-age 0" in hold, hold


# ---- review findings: a scan that did not answer is not a reduction --------


def crashing_candidate_stub(tmp_path):
    """Installed reports a finding; the candidate scan exits 1 with EMPTY stdout.

    That is not hypothetical: the scanner exits 1 as soon as it has findings, and
    a crash while RENDERING them (a null NVD baseScore was one, shipped once
    already — see the `or 0` note in dependency_security_check.py) leaves exit 1
    with nothing on stdout. Read naively that is "candidate has zero findings",
    i.e. a perfect reduction, and the hold is waived on a scan that never
    produced an answer.
    """
    stub = tmp_path / "cve_stub_crash.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "if ver == '1.0':\n"
        "    json.dump({'status': 'vulnerable', 'sources_ok': 1,\n"
        "               'vulnerabilities': [{'id': 'CVE-2099-1', 'severity': 'HIGH',\n"
        "               'score': 7.5, 'source': 'stub'}], 'unactionable': []}, sys.stdout)\n"
        "    sys.exit(1)\n"
        "# Candidate: dies before writing anything, exactly like the real crash.\n"
        "sys.exit(1)\n"
    )
    stub.chmod(0o755)
    return stub


def test_candidate_scan_that_crashed_does_not_count_as_a_fix(brew_env, tmp_path):
    """The fail-open the review caught: empty stdout on exit 1 must read as
    "crashed", never as "clean"."""
    scenario(brew_env)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(crashing_candidate_stub(tmp_path))})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


def test_crashed_candidate_hold_says_it_could_not_compare(brew_env, tmp_path):
    """And it must not claim a comparison it never made — the remedy for "could
    not check" (retry, set an NVD key) differs from "this buys you nothing"."""
    scenario(brew_env)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(crashing_candidate_stub(tmp_path))})
    hold = [ln for ln in result.stdout.splitlines() if "[HOLD] widget" in ln][0]
    assert "could not be checked to compare" in hold, hold
    assert "does not demonstrably fix" not in hold, hold


def test_fewer_answering_sources_is_not_a_reduction(brew_env, tmp_path):
    """A candidate scanned by fewer databases will naturally show fewer
    findings, which is indistinguishable from a fix. Not reachable for `brew`
    today — NVD is its only applicable source, so a failure means sources_ok 0
    and exit 2 — but the guard is what stops that changing silently if an
    OSV/GHSA Homebrew mapping is ever added."""
    scenario(brew_env)
    stub = tmp_path / "cve_stub_srcs.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "if ver == '1.0':\n"
        "    json.dump({'status': 'vulnerable', 'sources_ok': 2,\n"
        "               'vulnerabilities': [{'id': 'CVE-2099-1', 'severity': 'HIGH',\n"
        "               'score': 7.5, 'source': 'stub'}], 'unactionable': []}, sys.stdout)\n"
        "    sys.exit(1)\n"
        "json.dump({'status': 'clean', 'sources_ok': 1, 'vulnerabilities': [],\n"
        "           'unactionable': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "could not be checked to compare" in result.stdout, result.stdout


def test_hold_names_the_cves_the_user_must_weigh(brew_env, tmp_path):
    """#72 contract. The user is being asked to consider --min-age 0, so the
    findings they are exposed to have to be on screen — hugo's installed version
    carries a CRITICAL, and the first cut of this change printed none of it."""
    scenario(brew_env)
    stub = findings_stub(
        tmp_path,
        {"1.0": [("CVE-2099-1", "vuln")], "2.0": [("CVE-2099-1", "vuln")]},
    )
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    hold_idx = result.stdout.index("[HOLD] widget")
    assert "CVE-2099-1" in result.stdout, result.stdout
    assert result.stdout.index("CVE-2099-1") > hold_idx, result.stdout
