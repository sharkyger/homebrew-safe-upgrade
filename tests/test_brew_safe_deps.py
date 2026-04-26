"""
Tests for the transitive dependency check in brew-safe-install and brew-safe-upgrade.

Uses a mock `brew` shim on PATH so we don't need a real Homebrew install,
network access, or vulnerable test packages.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MOCK_BREW_BIN = Path(__file__).parent / "fixtures" / "mock_brew"
SAFE_INSTALL = REPO / "brew-safe-install"
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


@pytest.fixture
def mock_env(tmp_path, monkeypatch):
    """
    Set up a tempdir for mock brew responses, prepend mock-brew to PATH,
    and return the dir so individual tests can drop fixture files into it.
    """
    fixture_dir = tmp_path / "brew_responses"
    fixture_dir.mkdir()

    monkeypatch.setenv("MOCK_BREW_DIR", str(fixture_dir))
    monkeypatch.setenv("PATH", f"{MOCK_BREW_BIN}:{os.environ['PATH']}")
    # Ensure no leak from caller's env
    monkeypatch.delenv("BREW_SAFE_NO_DEPS", raising=False)

    return fixture_dir


def write_formula_info(fixture_dir: Path, name: str, stable: str, installed=False):
    """Drop an info_<name>.json that mimics `brew info --json=v2`."""
    payload = {
        "formulae": [
            {
                "name": name,
                "full_name": name,
                "versions": {"stable": stable},
                "installed": [{"version": stable}] if installed else [],
            }
        ],
        "casks": [],
    }
    (fixture_dir / f"info_{name}.json").write_text(json.dumps(payload))


def write_deps(fixture_dir: Path, name: str, deps: list[str]):
    (fixture_dir / f"deps_{name}.txt").write_text("\n".join(deps) + "\n" if deps else "")


def write_installed_version(fixture_dir: Path, name: str, version: str):
    """Mimic `brew list --versions --formula <name>` → '<name> <version>'."""
    (fixture_dir / f"list_{name}.txt").write_text(f"{name} {version}\n")


def run_safe_install(
    args: list[str], env_extra: dict | None = None, input_text: str = "n\n"
) -> subprocess.CompletedProcess:
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


def run_safe_upgrade(
    args: list[str], env_extra: dict | None = None, input_text: str = "n\n"
) -> subprocess.CompletedProcess:
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


def write_outdated(fixture_dir: Path, formulae: list[dict]):
    """Mimic `brew outdated --json=v2` output."""
    payload = {"formulae": formulae, "casks": []}
    (fixture_dir / "outdated.json").write_text(json.dumps(payload))


# ----------------------- usage / flag parsing -----------------------


def test_usage_text_mentions_no_deps_flag():
    """--no-deps must be advertised in usage output."""
    result = subprocess.run(
        ["bash", str(SAFE_INSTALL)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert "--no-deps" in result.stdout
    assert "BREW_SAFE_NO_DEPS" in result.stdout


def test_safe_upgrade_help_header_mentions_no_deps():
    """The header comment of brew-safe-upgrade documents --no-deps."""
    text = SAFE_UPGRADE.read_text()
    assert "--no-deps" in text
    assert "BREW_SAFE_NO_DEPS" in text


# ----------------------- dep check disabled paths -----------------------


def test_no_deps_flag_skips_dep_check(mock_env):
    """`--no-deps` must short-circuit dep checking with a clear notice."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    # No deps_check_skipped sentinel file needed; we look for the printed notice.

    result = run_safe_install(["--no-deps", "wget"], input_text="n\n")
    assert "Dependency check skipped" in result.stdout
    # Must NOT print the dep-check header
    assert "Checking transitive dependencies" not in result.stdout


def test_env_var_skips_dep_check(mock_env):
    """`BREW_SAFE_NO_DEPS=1` must short-circuit dep checking the same way."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_deps(mock_env, "wget", ["openssl@3"])

    result = run_safe_install(["wget"], env_extra={"BREW_SAFE_NO_DEPS": "1"}, input_text="n\n")
    assert "Dependency check skipped" in result.stdout
    assert "Checking transitive dependencies" not in result.stdout


# ----------------------- dep check enabled paths -----------------------


def test_dep_check_runs_when_enabled(mock_env):
    """Default behavior: dep check header must appear."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_deps(mock_env, "wget", [])  # no deps → "no new dependency versions"

    result = run_safe_install(["wget"], input_text="n\n")
    assert "Checking transitive dependencies" in result.stdout
    assert "No new dependency versions coming in." in result.stdout


def test_already_installed_same_version_dep_is_skipped(mock_env):
    """A dep already installed at the latest version must not be re-checked."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.5.0")  # same version → skip

    result = run_safe_install(["wget"], input_text="n\n")
    assert "Checking transitive dependencies" in result.stdout
    # No incoming deps because the only dep is already at latest
    assert "No new dependency versions coming in." in result.stdout
    # Should never have queried CVE for openssl@3
    assert "[ok-dep] openssl@3" not in result.stdout
    assert "[VULN-DEP] openssl@3" not in result.stdout


def test_installed_old_version_is_treated_as_incoming(mock_env, tmp_path):
    """A dep installed at an older version than the latest must be checked."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.0.0")  # older → incoming

    # Stub the CVE checker so this test stays offline.
    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Found 1 incoming dependency version(s) to check" in result.stdout
    assert "[ok-dep] openssl@3 3.5.0" in result.stdout


def test_revision_suffix_does_not_falsely_classify_as_incoming(mock_env, tmp_path):
    """`brew list` returns `1.2.0_1`; latest is `1.2.0` — must NOT be incoming."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.5.0_1")  # revision bump only

    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "No new dependency versions coming in." in result.stdout


def test_vulnerable_dep_triggers_warning_and_cancellation(mock_env, tmp_path):
    """A dep with CVE → WARNING block + prompt; user 'n' cancels with exit 0."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])

    # libfoo (the dep) returns exit 1 = vulnerable; everything else returns clean.
    stub = make_cve_stub(
        tmp_path,
        per_package={
            "libfoo": (1, '{"status":"vulnerable"}', "[HIGH] CVE-2026-99999"),
        },
    )

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "[VULN-DEP] libfoo 1.2.3" in result.stdout
    assert "WARNING: incoming dependencies have known issues" in result.stdout
    assert "Cancelled." in result.stdout
    assert result.returncode == 0  # current contract; cancel = clean exit


def test_dep_check_failure_is_surfaced_in_summary(mock_env, tmp_path):
    """CVE checker error (exit 2) on a dep → listed as skipped, not silently dropped."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])

    # libfoo errors out; wget itself is clean.
    stub = make_cve_stub(
        tmp_path,
        per_package={"libfoo": (2, "", "network error")},
    )

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "[skip-dep] libfoo 1.2.3" in result.stdout
    assert "dep checks failed for:" in result.stdout
    assert "libfoo" in result.stdout


# ----------------------- safe-upgrade --yes bypass -----------------------


def test_yes_flag_continues_past_vuln_dep_with_stderr_warning(mock_env, tmp_path):
    """
    `brew safe-upgrade --yes` with a vulnerable incoming dep must NOT block —
    but the warning must land on stderr so CI logs catch it.
    """
    write_outdated(
        mock_env,
        [
            {
                "name": "wget",
                "installed_versions": ["1.24.0"],
                "current_version": "1.25.0",
            }
        ],
    )
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])

    # Parent wget is clean; dep libfoo is vulnerable.
    stub = make_cve_stub(
        tmp_path,
        per_package={"libfoo": (1, '{"status":"vulnerable"}', "[HIGH] CVE-2026-99999")},
    )

    result = run_safe_upgrade(
        ["--yes"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        # No interactive input expected — the test fails its 30s timeout if --yes
        # falls through to a `read` somewhere.
        input_text="",
    )

    # Dep was correctly flagged
    assert "[VULN-DEP] libfoo 1.2.3" in result.stdout
    assert "WARNING: incoming dependencies have known issues" in result.stdout

    # The bypass notice must be on STDERR (not stdout) so it survives `>/dev/null`
    # and is conspicuous in CI log streams.
    assert "[--yes] continuing despite dep CVE warnings" in result.stderr
    assert "[--yes] continuing despite dep CVE warnings" not in result.stdout

    # The script reached the final "Done." line — i.e. upgrade was attempted.
    assert "Done." in result.stdout


# ----------------------- helpers -----------------------


def make_cve_stub(tmp_path: Path, per_package: dict | None = None) -> Path:
    """
    Write a stub for dependency_security_check.py.

    Called as: stub.py <ecosystem> <package> [version]

    `per_package` maps package_name → (exit_code, stdout, stderr). Packages not
    in the map default to clean (exit 0, '{}'). This lets a single stub serve
    different verdicts for the parent package vs. its deps.
    """
    table = per_package or {}
    stub = tmp_path / "stub_dep_check.py"
    stub.write_text(
        f"""#!/usr/bin/env python3
import sys
table = {table!r}
pkg = sys.argv[2] if len(sys.argv) > 2 else ""
exit_code, stdout_text, stderr_text = table.get(pkg, (0, "{{}}", ""))
sys.stdout.write(stdout_text)
sys.stderr.write(stderr_text)
sys.exit(exit_code)
"""
    )
    stub.chmod(0o755)
    return stub
