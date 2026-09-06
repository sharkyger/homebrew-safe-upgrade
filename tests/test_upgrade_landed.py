"""A package that clears the gate must actually upgrade — or be named.

Reported from a live run (2026-09-06). NVD rate-limited that batch, so ten
packages were `[skip]`-ped and pinned for the duration of the upgrade. Two
OTHER packages — ffmpeg and gnupg — had passed every check and were announced
under "Clean formulae to upgrade". brew then refused both, because each needed
the latest of a dependency the run had just pinned:

    Error: You must `brew unpin libvpx sdl3 sdl2-compat` as installing ffmpeg
    requires the latest version of pinned dependencies.

Their bottles were downloaded; neither was poured. brew upgraded the other
twenty and the wrapper's `|| true` swallowed the rest, so the run printed
"Done." and exited 0. Nothing in the output said ffmpeg and gnupg were still
outdated — the gate had, in effect, reported an upgrade that never happened.

The pin itself is not the bug and must stay: it is the guarantee that brew
cannot resolve an unvetted dependency in underneath something else. What was
missing is the report. These tests pin the reporting contract:

  - every package the gate cleared is verified to have actually left the
    outdated list, whatever the reason it might not have;
  - a package that did not is named in the output;
  - the run exits non-zero, because "Done." + 0 is a claim the verdict was
    carried out;
  - and a fully successful run stays silent and exits 0, so the check cannot
    become a permanent false alarm.

The verification re-asks brew what is still outdated rather than parsing its
error text — the wording differs per reason (pinned dependency, no bottle,
build failure, network) and is brew's to change.
"""

import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


def write_outdated(fixture_dir, formulae, casks=()):
    (fixture_dir / "outdated.json").write_text(
        json.dumps({"formulae": list(formulae), "casks": list(casks)})
    )


def write_formula_info(fixture_dir, name, version):
    # A tap-qualified name puts slashes in the filename; the mock reads
    # `$DIR/info_<name>.json` verbatim, so let them become real directories
    # (same trick as test_brew_safe_deps.write_formula_info).
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
    # `brew deps` normalises slashes to underscores in the mock, so this one is
    # flat where info_ is nested.
    flat = name.replace("/", "_")
    (fixture_dir / f"deps_{flat}.txt").write_text("\n".join(deps) + ("\n" if deps else ""))


def clean_cve_stub(tmp_path):
    """Everything scans clean, so the only reason a package can fail to upgrade
    in these tests is brew declining it."""
    stub = tmp_path / "cve_stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "json.dump({'status': 'clean', 'package': sys.argv[2] if len(sys.argv) > 2 else '',\n"
        "           'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    return stub


def run_upgrade(env_extra=None, input_text="y\n"):
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


def two_clean_formulae(brew_env, tmp_path):
    """`keeper` and `refused` both pass every check and both are offered."""
    write_outdated(
        brew_env,
        [
            {"name": "keeper", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "refused", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n in ("keeper", "refused"):
        write_formula_info(brew_env, n, "2.0")
        write_deps(brew_env, n)
    return clean_cve_stub(tmp_path)


# --------------------------------------------------------------------------


def test_both_packages_are_offered_as_clean(brew_env, tmp_path):
    """Guard for the tests below: if the gate stopped clearing `refused`, they
    would pass for the wrong reason (nothing to fail to upgrade)."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "refused"}
    )
    assert "Clean formulae to upgrade:" in result.stdout
    line = [ln for ln in result.stdout.splitlines() if "Clean formulae to upgrade:" in ln][0]
    assert "keeper" in line and "refused" in line, line


def test_package_brew_declined_is_named(brew_env, tmp_path):
    """The whole point: it used to vanish without a word."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "refused"}
    )
    assert "did NOT upgrade" in result.stdout, result.stdout
    warning = result.stdout.split("did NOT upgrade", 1)[1]
    assert "refused" in warning, result.stdout


def test_package_that_did_upgrade_is_not_named(brew_env, tmp_path):
    """A warning that names the innocent is as useless as no warning."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "refused"}
    )
    warning = result.stdout.split("did NOT upgrade", 1)[1].split("\n\n", 1)[0]
    assert "keeper" not in warning, warning


def test_declined_package_exits_nonzero(brew_env, tmp_path):
    """ "Done." plus exit 0 told scripts the upgrade landed. It had not."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "refused"}
    )
    assert result.returncode != 0, f"expected non-zero exit:\n{result.stdout}"


def test_successful_run_says_nothing_and_exits_zero(brew_env, tmp_path):
    """No false alarm when every cleared package really did upgrade — otherwise
    the warning becomes noise and stops being read."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "did NOT upgrade" not in result.stdout, result.stdout
    assert result.returncode == 0, f"{result.returncode}\n{result.stdout}\n{result.stderr}"


def test_declining_everything_is_reported_not_silently_successful(brew_env, tmp_path):
    """The degenerate case: brew refuses the entire batch."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "keeper refused"}
    )
    warning = result.stdout.split("did NOT upgrade", 1)[1]
    assert "keeper" in warning and "refused" in warning, result.stdout
    assert result.returncode != 0


def test_declining_a_tap_qualified_package_is_reported(brew_env, tmp_path):
    """CLEAN_PKGS carries the name brew's JSON used (`vendor/tap/tool`) while
    `brew outdated --quiet` may print either spelling, so the match has to
    consider the basename too — this is the case that would silently pass."""
    write_outdated(
        brew_env,
        [{"name": "vendor/tap/tool", "installed_versions": ["1.0"], "current_version": "2.0"}],
    )
    write_formula_info(brew_env, "vendor/tap/tool", "2.0")
    write_deps(brew_env, "vendor/tap/tool")
    stub = clean_cve_stub(tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "vendor/tap/tool"}
    )
    assert "did NOT upgrade" in result.stdout, result.stdout
    assert "tool" in result.stdout.split("did NOT upgrade", 1)[1]
    assert result.returncode != 0


def test_warning_is_not_worded_as_a_security_event(brew_env, tmp_path):
    """A pinned-dependency collision is a failed operation, not tampering. The
    two share exit 1, so the text has to keep them apart."""
    stub = two_clean_formulae(brew_env, tmp_path)
    result = run_upgrade(
        {"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_UPGRADE_REFUSE": "refused"}
    )
    warning = result.stdout.split("did NOT upgrade", 1)[1]
    assert "Nothing unsafe was installed" in warning, warning
    assert "tamper" not in warning.lower(), warning
