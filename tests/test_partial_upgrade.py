"""Partial upgrade when an incoming dependency is flagged (issue #98).

Reported behaviour: `brew safe-upgrade --greedy` found two too-fresh incoming
deps (srt, taglib) and prompted "Continue upgrade? [y/N]". Answering `n`
cancelled the ENTIRE run, so every unrelated package in the batch stayed
outdated too. The only alternatives were "upgrade the too-fresh deps anyway" or
"upgrade nothing" — the reporter wanted neither.

Top-level packages already had this: a too-fresh package is [HOLD]-ed, added to
EXCLUDE_PKGS and the rest of the batch proceeds. The dependency path was the
one that escalated to an all-or-nothing prompt. These tests pin the fix that
makes it behave like the top-level path.

The safety property under test is the interesting half. brew resolves
dependencies itself, so removing a dependent from brew's command line does not
by itself stop brew from upgrading the flagged dep underneath something else.
The fix therefore also `brew pin`s the flagged dep — see
test_flagged_dep_itself_is_pinned.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MOCK_BREW_BIN = Path(__file__).parent / "fixtures" / "mock_brew"
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


@pytest.fixture
def mock_env(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "brew_responses"
    fixture_dir.mkdir()
    monkeypatch.setenv("MOCK_BREW_DIR", str(fixture_dir))
    monkeypatch.setenv("PATH", f"{MOCK_BREW_BIN}:{os.environ['PATH']}")
    monkeypatch.delenv("BREW_SAFE_NO_DEPS", raising=False)
    monkeypatch.setenv("GH_TOKEN", "test-token")
    api_dir = tmp_path / "formulae_api_empty"
    api_dir.mkdir()
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api_dir))
    commits_dir = tmp_path / "commits_api"
    commits_dir.mkdir()
    # Default: everything is comfortably old, so only what a test overrides is fresh.
    (commits_dir / "_default.json").write_text(
        json.dumps([{"commit": {"committer": {"date": "2020-01-01T00:00:00Z"}}}])
    )
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits_dir))
    monkeypatch.setenv("MOCK_INTERACTIVE_MODE", "1")
    return fixture_dir


def make_cve_stub(tmp_path, vulnerable=()):
    """A stand-in scanner: exit 1 for named packages, exit 0 otherwise."""
    stub = tmp_path / "cve_stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"VULN = {list(vulnerable)!r}\n"
        "pkg = sys.argv[2] if len(sys.argv) > 2 else ''\n"
        "if pkg in VULN:\n"
        "    json.dump({'status': 'vulnerable', 'package': pkg, 'vulnerabilities': "
        "[{'id': 'CVE-2099-0001', 'severity': 'HIGH', 'score': 7.5, "
        "'summary': 'stub', 'source': 'stub'}]}, sys.stdout)\n"
        "    sys.exit(1)\n"
        "json.dump({'status': 'clean', 'package': pkg, 'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    return stub


def write_outdated(fixture_dir, formulae):
    (fixture_dir / "outdated.json").write_text(json.dumps({"formulae": formulae, "casks": []}))


def write_formula_info(fixture_dir, name, version):
    (fixture_dir / f"info_{name}.json").write_text(
        json.dumps({"formulae": [{"name": name, "versions": {"stable": version}}], "casks": []})
    )


def write_deps(fixture_dir, name, deps):
    (fixture_dir / f"deps_{name}.txt").write_text("\n".join(deps) + ("\n" if deps else ""))


def write_installed_version(fixture_dir, name, version):
    (fixture_dir / f"installed_{name}.txt").write_text(f"{name} {version}\n")


def fresh_commit(fixture_dir, name, days=0):
    import datetime

    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    commits_dir = Path(os.environ["MOCK_COMMITS_API_DIR"])
    (commits_dir / f"{name}.json").write_text(
        json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])
    )


def run_upgrade(args, env_extra=None, input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        input=input_text,
    )


def scenario(mock_env, tmp_path):
    """Two outdated packages; only `player` depends on the too-fresh `taglib`."""
    write_outdated(
        mock_env,
        [
            {"name": "player", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "unrelated", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n, v in (("player", "2.0"), ("unrelated", "2.0"), ("taglib", "2.3.1")):
        write_formula_info(mock_env, n, v)
    write_deps(mock_env, "player", ["taglib"])
    write_deps(mock_env, "unrelated", [])
    write_installed_version(mock_env, "taglib", "2.2.0")  # older → incoming
    fresh_commit(mock_env, "taglib", days=0)  # too fresh
    return make_cve_stub(tmp_path)


# --------------------------------------------------------------------------


def test_help_advertises_skip_unsafe():
    """Both help surfaces must document the flag."""
    text = SAFE_UPGRADE.read_text()
    assert "--skip-unsafe" in text
    result = subprocess.run(
        ["bash", str(SAFE_UPGRADE), "--help"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert "--skip-unsafe" in result.stdout


def test_prompt_offers_a_skip_option(mock_env, tmp_path):
    """The old prompt was [y/N] only — no way to keep the safe packages."""
    stub = scenario(mock_env, tmp_path)
    result = run_upgrade([], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="n\n")
    assert "[HOLD-DEP] taglib" in result.stdout
    assert "[s] skip" in result.stdout, f"expected a skip option in the prompt:\n{result.stdout}"


def test_answering_no_still_cancels_everything(mock_env, tmp_path):
    """Backward compatibility: N remains the default and still cancels."""
    stub = scenario(mock_env, tmp_path)
    result = run_upgrade([], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="n\n")
    assert "Cancelled." in result.stdout
    assert "Clean formulae to upgrade" not in result.stdout


def test_skip_answer_upgrades_only_the_unaffected_package(mock_env, tmp_path):
    """The #98 ask: keep `unrelated`, hold `player` (it pulls in taglib)."""
    stub = scenario(mock_env, tmp_path)
    result = run_upgrade(
        [], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="s\ny\n"
    )
    assert "Cancelled." not in result.stdout
    assert "Held (flagged dependency): player" in result.stdout
    assert "Clean formulae to upgrade: unrelated" in result.stdout
    assert "player" not in result.stdout.split("Clean formulae to upgrade:")[1].split("\n")[0]


def test_skip_unsafe_flag_is_non_interactive(mock_env, tmp_path):
    """--skip-unsafe gives the same partition without a prompt (for CI)."""
    stub = scenario(mock_env, tmp_path)
    result = run_upgrade(
        ["--skip-unsafe"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="y\n"
    )
    assert "[--skip-unsafe] holding: player" in result.stdout
    assert "Clean formulae to upgrade: unrelated" in result.stdout


def test_flagged_dep_itself_is_pinned(mock_env, tmp_path):
    """THE safety property.

    Dropping `player` from brew's cmdline is not sufficient — brew resolves
    dependencies itself, so taglib could still be dragged in under another
    package. The flagged dep must be pinned for the duration of the upgrade.
    """
    stub = scenario(mock_env, tmp_path)
    pin_log = tmp_path / "pin.log"
    result = run_upgrade(
        ["--skip-unsafe"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_PIN_LOG": str(pin_log)},
        input_text="y\n",
    )
    assert result.returncode == 0
    assert pin_log.exists(), "expected brew pin to be invoked"
    pinned = pin_log.read_text()
    assert "pin taglib" in pinned, f"the flagged dep must be pinned, got:\n{pinned}"
    assert "pin player" in pinned, f"the held dependent must be pinned, got:\n{pinned}"
    assert "unpin taglib" in pinned, "the pin must be released after the upgrade"


def test_all_clean_run_gets_the_affirmative_prompt(mock_env, tmp_path):
    """With nothing excluded, the prompt should default to YES.

    EXCLUDE_PKGS joins four possibly-empty lists, so "nothing excluded" is a
    string of three spaces — and it was compared against exactly two, so the
    all-clean branch was unreachable and even a completely clean run got the
    cautious "Upgrade clean packages? Excluded ones will be skipped. [y/N]".
    """
    write_outdated(
        mock_env, [{"name": "unrelated", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(mock_env, "unrelated", "2.0")
    write_deps(mock_env, "unrelated", [])
    stub = make_cve_stub(tmp_path)

    result = run_upgrade([], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="n\n")
    assert "All clean. Run brew upgrade?" in result.stdout, (
        f"expected the affirmative prompt when nothing is excluded:\n{result.stdout}"
    )
    assert "Excluded ones will be skipped" not in result.stdout


def test_everything_affected_means_nothing_to_upgrade(mock_env, tmp_path):
    """If no package is free of the flagged dep, say so instead of upgrading."""
    write_outdated(
        mock_env, [{"name": "player", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(mock_env, "player", "2.0")
    write_formula_info(mock_env, "taglib", "2.3.1")
    write_deps(mock_env, "player", ["taglib"])
    write_installed_version(mock_env, "taglib", "2.2.0")
    fresh_commit(mock_env, "taglib", days=0)
    stub = make_cve_stub(tmp_path)

    result = run_upgrade(
        ["--skip-unsafe"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="y\n"
    )
    assert "Nothing left to upgrade" in result.stdout
    assert "brew upgrade --formula" not in result.stdout
