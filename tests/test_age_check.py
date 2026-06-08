"""
Tests for the freshness/age check across package types (formula, cask, tap).

Regression coverage for the fail-open bug: the age check used to query
Homebrew/homebrew-core for EVERY package, so casks (which live in homebrew-cask)
and tap formulae (which live in their own tap repo) always came back empty and
were waved through as "age unknown, skipping age check" — a 0-day cask/tap could
sail straight past a `--min-age` hold. The fix is two-fold:

  1. Route the age lookup to the correct repo by type (core / cask / tap).
  2. Fail CLOSED when the age cannot be verified — HOLD unless --allow-unknown-age.

Test seams the production scripts honor (see fetch_pkg_age in the wrappers):
  - MOCK_COMMITS_API_DIR: per-name canned `GET /commits` JSON ('/'→'_' in the
    filename); missing name falls back to _default.json, else an empty array.
  - MOCK_COMMITS_API_LOG: appends "<type>\t<url>" per lookup so a test can assert
    the lookup was routed to the right GitHub repo.
"""

import datetime
import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MOCK_BREW_BIN = Path(__file__).parent / "fixtures" / "mock_brew"
SAFE_INSTALL = REPO / "brew-safe-install"
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


def commit_json_days_ago(days: int) -> str:
    """A `GET /commits` response (array) whose last commit is `days` days old."""
    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    return json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])


@pytest.fixture
def age_env(tmp_path, monkeypatch):
    """Mock brew, the canonical SHA API (empty), the CVE checker (clean), and the
    commits API. Returns the dirs tests need to stage per-package responses."""
    brew_dir = tmp_path / "brew_responses"
    brew_dir.mkdir()
    api_dir = tmp_path / "formulae_api_empty"
    api_dir.mkdir()
    commits_dir = tmp_path / "commits_api"
    commits_dir.mkdir()
    # Baseline: everything resolves comfortably old unless a test overrides it.
    (commits_dir / "_default.json").write_text(commit_json_days_ago(3650))

    monkeypatch.setenv("MOCK_BREW_DIR", str(brew_dir))
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api_dir))
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits_dir))
    monkeypatch.setenv("PATH", f"{MOCK_BREW_BIN}:{os.environ['PATH']}")
    monkeypatch.delenv("BREW_SAFE_NO_DEPS", raising=False)

    stub = tmp_path / "cve_stub.py"
    stub.write_text("#!/usr/bin/env python3\nimport sys\nprint('{}')\nsys.exit(0)\n")
    stub.chmod(0o755)
    monkeypatch.setenv("DEPENDENCY_SECURITY_CHECK", str(stub))

    return {"brew": brew_dir, "commits": commits_dir, "tmp": tmp_path}


# ----------------------- staging helpers -----------------------


def write_cask_info(brew_dir: Path, token: str, version: str, installed=False):
    cask = {"token": token, "full_token": token, "name": [token], "version": version}
    if installed:
        cask["installed"] = version
    (brew_dir / f"info_{token}.json").write_text(json.dumps({"formulae": [], "casks": [cask]}))


def write_formula_info(brew_dir: Path, name: str, stable: str, installed=False):
    payload = {
        "formulae": [
            {
                "name": name.split("/")[-1],
                "full_name": name,
                "versions": {"stable": stable},
                "installed": [{"version": stable}] if installed else [],
            }
        ],
        "casks": [],
    }
    (brew_dir / f"info_{name.split('/')[-1]}.json").write_text(json.dumps(payload))


def write_outdated(brew_dir: Path, formulae=None, casks=None):
    payload = {"formulae": formulae or [], "casks": casks or []}
    (brew_dir / "outdated.json").write_text(json.dumps(payload))


def set_commits(commits_dir: Path, name: str, content: str):
    """Stage a per-name commits response. '/'→'_' to match the lookup key.
    Pass '[]' to force an 'unknown age' verdict (overrides _default)."""
    (commits_dir / f"{name.replace('/', '_')}.json").write_text(content)


def run_upgrade(args, env_extra=None, input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
        input=input_text,
    )


def run_install(args, env_extra=None, input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_INSTALL), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
        input=input_text,
    )


# ----------------------- safe-upgrade: casks -----------------------


def test_upgrade_cask_unknown_age_is_held_not_skipped(age_env):
    """THE reported bug: a cask whose age can't be verified must be HELD, not
    waved through with '[ok] … age unknown, skipping age check'."""
    write_outdated(
        age_env["brew"],
        casks=[{"name": "coderabbit", "installed_versions": ["0.5.3"], "current_version": "0.5.4"}],
    )
    set_commits(age_env["commits"], "coderabbit", "[]")  # force unknown

    result = run_upgrade(["--no-deps"])

    assert "[HOLD] coderabbit 0.5.4 — age could not be verified" in result.stdout
    # The fail-open line must never appear.
    assert "age unknown, skipping age check" not in result.stdout
    assert "[ok] coderabbit" not in result.stdout
    assert "All packages held due to min-age policy." in result.stdout


def test_upgrade_cask_is_routed_to_homebrew_cask_repo(age_env):
    """A cask's age lookup must hit homebrew-cask (Casks/<l>/<token>.rb), never
    homebrew-core — the routing bug that caused the fail-open."""
    write_outdated(
        age_env["brew"],
        casks=[{"name": "coderabbit", "installed_versions": ["0.5.3"], "current_version": "0.5.4"}],
    )
    url_log = age_env["tmp"] / "urls.log"

    run_upgrade(["--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "Homebrew/homebrew-cask/commits?path=Casks/c/coderabbit.rb" in log_text
    assert "homebrew-core/commits?path=Formula/c/coderabbit.rb" not in log_text


def test_upgrade_allow_unknown_age_lets_cask_through(age_env):
    """--allow-unknown-age is the explicit override for the unverifiable case."""
    write_outdated(
        age_env["brew"],
        casks=[{"name": "coderabbit", "installed_versions": ["0.5.3"], "current_version": "0.5.4"}],
    )
    set_commits(age_env["commits"], "coderabbit", "[]")

    result = run_upgrade(["--no-deps", "--allow-unknown-age"])

    expected = "[ok] coderabbit 0.5.4 — age could not be verified, allowed by --allow-unknown-age"
    assert expected in result.stdout
    assert "[HOLD] coderabbit" not in result.stdout


def test_upgrade_cask_too_fresh_is_held(age_env):
    """A cask with a verifiable but too-recent release is held by the freshness gate."""
    write_outdated(
        age_env["brew"],
        casks=[{"name": "vscodium", "installed_versions": ["1.0"], "current_version": "2.0"}],
    )
    set_commits(age_env["commits"], "vscodium", commit_json_days_ago(0))  # released today

    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] vscodium 2.0 — released 0 day(s) ago" in result.stdout


def test_upgrade_cask_old_enough_passes(age_env):
    """A cask older than --min-age clears the freshness gate."""
    write_outdated(
        age_env["brew"],
        casks=[{"name": "vscodium", "installed_versions": ["1.0"], "current_version": "2.0"}],
    )
    set_commits(age_env["commits"], "vscodium", commit_json_days_ago(30))

    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[ok] vscodium 2.0 — released 30 day(s) ago" in result.stdout
    assert "[HOLD] vscodium" not in result.stdout


# ----------------------- safe-upgrade: tap formula -----------------------


def test_upgrade_tap_formula_is_routed_to_its_tap_repo(age_env):
    """A tap formula's age lookup must hit its own tap repo, not homebrew-core."""
    write_outdated(
        age_env["brew"],
        formulae=[
            {
                "name": "sharkyger/tap/safe-fetch",
                "installed_versions": ["0.2.1"],
                "current_version": "0.3.0",
            }
        ],
    )
    set_commits(age_env["commits"], "sharkyger/tap/safe-fetch", "[]")  # force unknown
    url_log = age_env["tmp"] / "urls.log"

    result = run_upgrade(["--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "sharkyger/homebrew-tap/commits?path=Formula/safe-fetch.rb" in log_text
    # Unverifiable tap age fails closed too.
    assert "[HOLD] sharkyger/tap/safe-fetch 0.3.0 — age could not be verified" in result.stdout


# ----------------------- safe-install: casks (were wholly exempt) -----------------------


def test_install_cask_unknown_age_is_held(age_env):
    """brew-safe-install used to gate the age check on `PKG_TYPE = formula`, so
    casks skipped it entirely. A cask with unverifiable age must now be HELD."""
    write_cask_info(age_env["brew"], "coderabbit", "0.5.4")
    set_commits(age_env["commits"], "coderabbit", "[]")

    result = run_install(["coderabbit", "--no-deps"])

    assert "[HOLD] coderabbit 0.5.4 — age could not be verified" in result.stdout


def test_install_cask_is_routed_to_homebrew_cask_repo(age_env):
    """Install-side cask age lookups must also hit homebrew-cask, not homebrew-core."""
    write_cask_info(age_env["brew"], "coderabbit", "0.5.4")
    url_log = age_env["tmp"] / "urls.log"

    run_install(["coderabbit", "--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "Homebrew/homebrew-cask/commits?path=Casks/c/coderabbit.rb" in log_text
    assert "homebrew-core/commits?path=Formula/c/coderabbit.rb" not in log_text


def test_install_lib_formula_routed_to_lib_shard(age_env):
    """Install-side parity for the homebrew-core lib/ shard (issue #62): a lib*
    formula installed via brew-safe-install must also resolve at Formula/lib/."""
    write_formula_info(age_env["brew"], "libgit2", "1.9.4")
    url_log = age_env["tmp"] / "urls.log"

    run_install(["libgit2", "--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "homebrew-core/commits?path=Formula/lib/libgit2.rb" in log_text
    assert "Formula/l/libgit2.rb" not in log_text


def test_install_cask_old_enough_is_checked_not_skipped(age_env):
    """A sufficiently-old cask proceeds to the security check (no silent skip)."""
    write_cask_info(age_env["brew"], "coderabbit", "0.5.4")
    set_commits(age_env["commits"], "coderabbit", commit_json_days_ago(30))

    result = run_install(["coderabbit", "--no-deps"])

    assert "released 30 day(s) ago" in result.stdout
    assert "[HOLD] coderabbit" not in result.stdout


# ----------------------- routing + CVE-aware bypass -----------------------


def test_upgrade_core_formula_is_routed_to_homebrew_core(age_env):
    """A core formula must still be looked up in homebrew-core (routing regression
    guard — the cask/tap routing must not have broken the common case)."""
    write_outdated(
        age_env["brew"],
        formulae=[{"name": "wget", "installed_versions": ["1.24.0"], "current_version": "1.25.0"}],
    )
    url_log = age_env["tmp"] / "urls.log"

    run_upgrade(["--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "Homebrew/homebrew-core/commits?path=Formula/w/wget.rb" in log_text
    assert "homebrew-cask" not in log_text


def test_upgrade_lib_formula_routed_to_lib_shard(age_env):
    """homebrew-core shards lib* formulae under Formula/lib/, not Formula/l/.
    Regression for issue #62 — libgit2/libheif/libusb/… were looked up at the
    wrong path, came back empty, and were waved through as 'age unknown'."""
    write_outdated(
        age_env["brew"],
        formulae=[{"name": "libgit2", "installed_versions": ["1.9.3"], "current_version": "1.9.4"}],
    )
    url_log = age_env["tmp"] / "urls.log"

    run_upgrade(["--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "homebrew-core/commits?path=Formula/lib/libgit2.rb" in log_text
    assert "Formula/l/libgit2.rb" not in log_text


def test_upgrade_non_lib_l_formula_still_uses_first_letter(age_env):
    """Guard the lib shard against over-matching: a non-lib 'l' formula (lua) must
    still route to Formula/l/, never Formula/lib/."""
    write_outdated(
        age_env["brew"],
        formulae=[{"name": "lua", "installed_versions": ["5.4.6"], "current_version": "5.4.7"}],
    )
    url_log = age_env["tmp"] / "urls.log"

    run_upgrade(["--no-deps"], env_extra={"MOCK_COMMITS_API_LOG": str(url_log)})

    log_text = url_log.read_text()
    assert "homebrew-core/commits?path=Formula/l/lua.rb" in log_text
    assert "Formula/lib/" not in log_text


def test_upgrade_too_fresh_but_installed_has_cve_bypasses_hold(age_env, monkeypatch):
    """CVE-aware bypass (unchanged behavior): a too-fresh upgrade is allowed when
    the INSTALLED version has known CVEs — the fresh release is likely the fix.
    Must remain on the *known* path only, never the unknown-age path."""
    write_outdated(
        age_env["brew"],
        formulae=[{"name": "wget", "installed_versions": ["1.24.0"], "current_version": "1.25.0"}],
    )
    set_commits(age_env["commits"], "wget", commit_json_days_ago(0))  # released today

    # CVE stub: the INSTALLED version (1.24.0) is vulnerable (exit 1); anything
    # else is clean (exit 0). The age-check probes `brew wget 1.24.0`.
    stub = age_env["tmp"] / "cve_installed_vuln.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "sys.exit(1 if ver == '1.24.0' else 0)\n"
    )
    stub.chmod(0o755)
    monkeypatch.setenv("DEPENDENCY_SECURITY_CHECK", str(stub))

    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "but installed 1.24.0 has CVEs — bypassing age check" in result.stdout
    assert "[HOLD] wget" not in result.stdout
