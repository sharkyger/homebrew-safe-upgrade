"""Edge cases in the post-upgrade verification and the unknown-baseline guard.

All four came out of the code review of the first commit on this branch. Each
is a way the two fixes could themselves fail open or cry wolf:

  1. An unknown installed version ("?") must not be scanned as if it were a
     version. `version_in_range()` answers "affected" for anything it cannot
     parse — correct when scanning a CANDIDATE, catastrophic as a BASELINE:
     the baseline comes back carrying every CVE in the database, which both
     fires the freshness bypass and makes any real regression look like [SAME].
  2. A formula the USER pinned is listed by `brew outdated` and refused by
     `brew upgrade` by definition. Reporting that as a failed upgrade would fire
     on every run forever and drag exit 1 along with it.
  3. If the verification's own `brew outdated` fails, "nothing came back" must
     not read as "everything landed".
  4. Formulae and casks are separate namespaces. A token can be both (docker,
     wireshark), so a still-outdated cask must not condemn a formula that
     upgraded fine — that misreport carries exit 1.
"""

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
    flat = name.replace("/", "_")
    (fixture_dir / f"deps_{flat}.txt").write_text("\n".join(deps) + ("\n" if deps else ""))


def stage_user_pin(fixture_dir, name):
    """Pre-existing pin, i.e. one the USER set before this run."""
    pinned = fixture_dir / "pinned"
    pinned.mkdir(parents=True, exist_ok=True)
    (pinned / name).write_text("")


def always_vulnerable_stub(tmp_path):
    """Reports findings for EVERY version asked about.

    This is what the real scanner does when handed an unparseable version such
    as "?": parse_version() returns None and version_in_range() answers True for
    every advisory. Reproducing that is the only way to show the guard matters.
    """
    stub = tmp_path / "cve_stub_all.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "pkg = sys.argv[2] if len(sys.argv) > 2 else ''\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "json.dump({'status': 'vulnerable', 'package': pkg, 'version': ver,\n"
        "           'vulnerabilities': [{'id': 'CVE-2099-0001', 'severity': 'HIGH',\n"
        "           'score': 7.5, 'summary': 'stub', 'source': 'stub'}]}, sys.stdout)\n"
        "sys.exit(1)\n"
    )
    stub.chmod(0o755)
    return stub


def clean_stub(tmp_path):
    stub = tmp_path / "cve_stub_clean.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "json.dump({'status': 'clean', 'package': sys.argv[2] if len(sys.argv) > 2 else '',\n"
        "           'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    return stub


def fresh_commit(name, days=0):
    import datetime

    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    (Path(os.environ["MOCK_COMMITS_API_DIR"]) / f"{name}.json").write_text(
        json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])
    )


def run_upgrade(env_extra=None, input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        input=input_text,
    )


# ---- 1. unknown installed version is no baseline --------------------------


def test_unknown_installed_version_does_not_bypass_the_freshness_hold(brew_env, tmp_path):
    """`installed_versions: []` yields "?", which the scanner reads as affected
    by everything. That must not be evidence for skipping the hold."""
    write_outdated(
        brew_env, [{"name": "widget", "installed_versions": [], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    fresh_commit("widget", days=0)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(always_vulnerable_stub(tmp_path))})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


def test_null_installed_version_does_not_bypass_the_freshness_hold(brew_env, tmp_path):
    """`[null]` survives the `or` (a one-element list is truthy) and stringifies
    to "None" — a different spelling of the same unknown."""
    write_outdated(
        brew_env, [{"name": "widget", "installed_versions": [None], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    fresh_commit("widget", days=0)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(always_vulnerable_stub(tmp_path))})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


def test_unknown_installed_version_does_not_clear_a_package_as_same(brew_env, tmp_path):
    """The other consumer: with a baseline that carries every CVE, the
    candidate's findings are always a subset, so a genuine regression would be
    waved through as [SAME]. No baseline must mean the block stands."""
    write_outdated(
        brew_env, [{"name": "widget", "installed_versions": [], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(always_vulnerable_stub(tmp_path))})
    assert "[SAME]" not in result.stdout, result.stdout
    assert "[IMPROVES]" not in result.stdout, result.stdout
    assert "[VULN]" in result.stdout or "BLOCKED" in result.stdout.upper(), result.stdout


# ---- 2. a user's own pin is not a failed upgrade ---------------------------


def test_user_pinned_formula_is_not_reported_as_a_failed_upgrade(brew_env, tmp_path):
    """`brew pin node` is a standing choice. brew lists it as outdated and
    refuses to upgrade it — every run, forever. Reporting that would make the
    warning permanent noise and the exit code permanently 1."""
    write_outdated(
        brew_env,
        [
            {"name": "node", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "other", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n in ("node", "other"):
        write_formula_info(brew_env, n, "2.0")
        write_deps(brew_env, n)
    stage_user_pin(brew_env, "node")
    # The pin store is what `brew list --pinned` reads (so the wrapper sees a
    # PRE-EXISTING pin); REFUSE is brew declining to upgrade it, which is what a
    # pin means at upgrade time. The mock keeps the two independent on purpose.
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_UPGRADE_REFUSE": "node",
        },
        input_text="y\n",
    )
    assert "did NOT upgrade" not in result.stdout, result.stdout
    assert result.returncode == 0, f"{result.returncode}\n{result.stdout}"


def test_a_real_failure_alongside_a_user_pin_is_still_reported(brew_env, tmp_path):
    """Don't over-filter: the pin exemption must not swallow a genuine one."""
    write_outdated(
        brew_env,
        [
            {"name": "node", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "refused", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n in ("node", "refused"):
        write_formula_info(brew_env, n, "2.0")
        write_deps(brew_env, n)
    stage_user_pin(brew_env, "node")
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_UPGRADE_REFUSE": "node refused",
        },
        input_text="y\n",
    )
    warning = result.stdout.split("did NOT upgrade", 1)
    assert len(warning) == 2, result.stdout
    assert "refused" in warning[1], result.stdout
    assert "node" not in warning[1].split("\n\n", 1)[0], result.stdout
    assert result.returncode != 0


# ---- 3. the verification must not fail open --------------------------------


def test_failed_verification_is_reported_not_treated_as_success(brew_env, tmp_path):
    """If the re-check's own `brew outdated` fails, both lists come back empty,
    nothing matches, and the run would otherwise claim every upgrade landed —
    the exact unverified claim this whole mechanism exists to remove."""
    write_outdated(
        brew_env, [{"name": "keeper", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "keeper", "2.0")
    write_deps(brew_env, "keeper")
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_OUTDATED_RECHECK_FAIL": "1",
        },
        input_text="y\n",
    )
    assert "could not verify" in result.stdout, result.stdout
    assert result.returncode != 0, f"expected non-zero exit:\n{result.stdout}"


def test_failed_verification_does_not_accuse_any_package(brew_env, tmp_path):
    """ "Could not check" is not "these failed" — naming packages there would be
    a fabricated finding."""
    write_outdated(
        brew_env, [{"name": "keeper", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "keeper", "2.0")
    write_deps(brew_env, "keeper")
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_OUTDATED_RECHECK_FAIL": "1",
        },
        input_text="y\n",
    )
    assert "did NOT upgrade" not in result.stdout, result.stdout


# ---- 4. formulae and casks are separate namespaces -------------------------


def test_outdated_cask_does_not_condemn_a_same_named_formula(brew_env, tmp_path):
    """`docker` exists as both a formula and a cask. Both are clean and both are
    offered; brew upgrades the formula and declines the cask. Only the cask
    failed, so only the cask may be named.

    Pooling the two outdated lists and matching every CLEAN_PKGS entry against
    the pool names `docker` TWICE — once for the formula that upgraded perfectly
    well. The bug is only observable as that duplicate, because the wrapper
    already conflates the two names further upstream: a same-named cask that is
    blocked also drops the formula from CLEAN_PKGS, so the formula never gets
    announced in the first place. That upstream conflation is pre-existing and
    out of scope here; this test pins the half the verification owns.
    """
    write_outdated(
        brew_env,
        formulae=[{"name": "docker", "installed_versions": ["1.0"], "current_version": "2.0"}],
        casks=[{"name": "docker", "installed_versions": ["1.0"], "current_version": "2.0"}],
    )
    write_formula_info(brew_env, "docker", "2.0")
    write_deps(brew_env, "docker")
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_UPGRADE_REFUSE_CASKS": "docker",
        },
        input_text="y\n",
    )
    # Guard: both really were offered, so this is about namespace separation and
    # not about an empty run.
    assert "Clean formulae to upgrade: docker" in result.stdout, result.stdout
    assert "Clean casks to upgrade: docker" in result.stdout, result.stdout
    assert "did NOT upgrade" in result.stdout, result.stdout
    named = result.stdout.split("did NOT upgrade:", 1)[1].split("\n", 1)[0]
    assert named.split() == ["docker"], f"the formula was accused too: {named!r}"


# ---- 5. a HEAD keg is not a usable baseline --------------------------------


def test_head_keg_is_not_used_as_the_baseline(brew_env, tmp_path):
    """brew appends a HEAD keg to all_kegs BEFORE its own `next if version.head?`
    (formula.rb), and Version#<=> ranks HEAD above every numbered version, so
    HEAD sorts LAST. Taking [-1] therefore picked `HEAD-9f3a1` where the old [0]
    picked the real version — and parse_version() cannot read it, so
    version_in_range() calls the baseline affected by everything. Same fail-open
    as the '?' sentinel, reached by a third spelling."""
    write_outdated(
        brew_env,
        [
            {
                "name": "widget",
                "installed_versions": ["1.2.3", "HEAD-9f3a1"],
                "current_version": "2.0",
            }
        ],
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    fresh_commit("widget", days=0)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(always_vulnerable_stub(tmp_path))})
    # The real keg is 1.2.3 and the stub calls everything vulnerable, so the
    # bypass is legitimate here — but it must name the version, not HEAD.
    assert "HEAD" not in result.stdout, result.stdout
    row = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("widget")]
    assert row and "1.2.3" in row[0], result.stdout


def test_head_only_rack_has_no_baseline_and_holds(brew_env, tmp_path):
    """Nothing but HEAD kegs means no usable baseline at all, so the freshness
    hold must stand rather than being bypassed on an unreadable version."""
    write_outdated(
        brew_env,
        [{"name": "widget", "installed_versions": ["HEAD-9f3a1"], "current_version": "2.0"}],
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    fresh_commit("widget", days=0)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(always_vulnerable_stub(tmp_path))})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] widget" in result.stdout, result.stdout


# ---- 6. blank installed version does not collapse the columns ---------------


def test_blank_installed_version_does_not_shift_the_columns(brew_env, tmp_path):
    """A cask's installed_version is `outdated_version(...).to_s`, which is ""
    when that resolves to nil. An empty middle field collapses the three
    space-separated columns to two, and `read name installed current` then
    slides current into installed and leaves current empty — so the age check
    gets a blank version and the scanner gets the wrong baseline."""
    write_outdated(
        brew_env,
        casks=[{"name": "widget", "installed_versions": [""], "current_version": "2.0"}],
    )
    write_formula_info(brew_env, "widget", "2.0")
    write_deps(brew_env, "widget")
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path))})
    row = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("widget")]
    assert row, result.stdout
    # Assert the CURRENT column specifically. Pre-fix the row read
    #   widget  cask  2.0  ->
    # with the *current* version slid left into the installed column and current
    # left empty — so "2.0 is somewhere in the row" passes either way and proves
    # nothing. The available version must sit on the right of the arrow.
    assert row[0].rstrip().endswith("-> 2.0"), f"columns shifted: {row[0]!r}"
    # And the scanner must be handed a version at all: pre-fix this line was
    # "[ok] widget " with the version missing entirely.
    assert "[ok] widget 2.0" in result.stdout, result.stdout


# ---- 7. re-check scoping ----------------------------------------------------


def test_cask_recheck_failure_does_not_fail_a_formula_only_run(brew_env, tmp_path):
    """The cask namespace is not even queried when no cask was announced, so a
    broken cask tap (or a brew where --cask errors at all — linuxbrew is one of
    this repo's dogfood beds) cannot end a clean formula-only upgrade with
    "could not verify" and exit 1.

    Forward guard, not a reproduction: the seam this drives did not exist in the
    shape the bug had, so it cannot fail against the commit that carried it. Its
    job is to stop the cask query being made unconditionally again.
    """
    write_outdated(
        brew_env, [{"name": "keeper", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "keeper", "2.0")
    write_deps(brew_env, "keeper")
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_OUTDATED_RECHECK_FAIL": "casks",
        },
        input_text="y\n",
    )
    assert "could not verify" not in result.stdout, result.stdout
    assert result.returncode == 0, f"{result.returncode}\n{result.stdout}"


def test_formula_recheck_failure_is_still_reported(brew_env, tmp_path):
    """Don't overcorrect: a failure in the namespace that WAS in scope must
    still mark the run unverified."""
    write_outdated(
        brew_env, [{"name": "keeper", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "keeper", "2.0")
    write_deps(brew_env, "keeper")
    result = run_upgrade(
        {
            "DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)),
            "MOCK_BREW_OUTDATED_RECHECK_FAIL": "formulae",
        },
        input_text="y\n",
    )
    assert "could not verify" in result.stdout, result.stdout
    assert result.returncode != 0


def test_recheck_reads_json_not_quiet(brew_env, tmp_path):
    """Structural guard for the alias mismatch.

    `brew outdated --json=v2` reports `f.full_name`; `--quiet` prints
    `f.full_installed_specified_name`, which is the ALIAS from the install
    receipt when one was used. A formula installed as `brew install postgresql`
    is `postgresql@18` in CLEAN_PKGS (built from the JSON) but `postgresql`
    under --quiet, so neither the full name nor the basename matched and a
    genuinely refused upgrade read as landed — silent, exit 0.

    Reading the JSON on both sides makes the two the same field by
    construction. Since that is a property of WHICH command is run rather than
    of its output, assert on the calls themselves; switching back to --quiet
    would reintroduce a fail-open that no output-level test would catch.
    """
    write_outdated(
        brew_env, [{"name": "keeper", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "keeper", "2.0")
    write_deps(brew_env, "keeper")
    log = tmp_path / "brew_calls.log"
    run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(clean_stub(tmp_path)), "MOCK_BREW_CALL_LOG": str(log)},
        input_text="y\n",
    )
    calls = [ln for ln in log.read_text().splitlines() if ln.startswith("outdated")]
    assert calls, "brew outdated was never called"
    assert not any("--quiet" in c for c in calls), f"re-check fell back to --quiet: {calls}"
    assert any("--json=v2" in c and "--formula" in c for c in calls), calls
