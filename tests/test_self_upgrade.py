"""Tests for `brew safe-upgrade --self` — the guarded self-upgrade (issue #87).

`brew upgrade safe-upgrade` pulls safe-upgrade's OWN outdated dependencies
(python@3.12 -> openssl@3, sqlite, ...) with none of the CVE / SHA / freshness
gates the tool exists to apply. `--self` closes that gap: it runs safe-upgrade's
outdated deps through the normal gate FIRST (fail-closed), verifies none is left
outdated, and only then upgrades the formula.

Harness notes:
  * The route (formula vs script install) is decided by resolve_script_dir() at
    startup and cannot be env-overridden, so the formula-route tests COPY the
    script into a `.../libexec/` dir and run it there — resolve_script_dir() then
    reports the Homebrew-formula route naturally (no test-only production seam).
  * `brew` is the stateful mock at tests/fixtures/mock_brew/brew: its `upgrade`
    drops the upgraded names from outdated.json, so the belt-and-suspenders
    re-check sees gated-and-upgraded deps as no-longer-outdated.
  * SHA verification is disabled with --no-verify-sha so the deps need no bottle
    resolver / formulae-API fixtures; the CVE verdict comes from a stub.
"""

import datetime
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MOCK_BREW_BIN = Path(__file__).parent / "fixtures" / "mock_brew"
SELF_FORMULA = "sharkyger/tap/safe-upgrade"


def commit_json_days_ago(days: int) -> str:
    """A `GET /commits` array whose last commit is `days` days old."""
    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    return json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])


def make_cve_stub(tmp_path: Path, per_package: dict | None = None) -> Path:
    """A stub for dependency_security_check.py.

    Called as `stub.py <ecosystem> <package> [version]`; `per_package` maps a
    package name to (exit_code, stdout, stderr). Unlisted packages read clean.
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


def write_outdated(fixture_dir: Path, formulae: list[dict]) -> None:
    """Write outdated.json in the `brew outdated --json=v2` shape."""
    (fixture_dir / "outdated.json").write_text(json.dumps({"formulae": formulae, "casks": []}))


def outdated_formula(name: str, installed: str, current: str) -> dict:
    return {"name": name, "installed_versions": [installed], "current_version": current}


def write_deps(fixture_dir: Path, name: str, deps: list[str]) -> None:
    """Write `brew deps <name>` output; slashes in a tap name are flattened to
    match the mock's `deps_<normalized>.txt` lookup."""
    safe = name.replace("/", "_")
    (fixture_dir / f"deps_{safe}.txt").write_text(("\n".join(deps) + "\n") if deps else "")


@pytest.fixture
def formula_env(tmp_path, monkeypatch):
    """Formula-route harness: a libexec copy of the script + a mock-brew env.

    Returns dict with `script` (the libexec copy to invoke) and `brew` (the
    fixture dir where tests drop canned brew responses / age files)."""
    brew_dir = tmp_path / "brew_responses"
    brew_dir.mkdir()

    libexec = tmp_path / "libexec"
    libexec.mkdir()
    script = libexec / "brew-safe-upgrade"
    shutil.copy(REPO / "brew-safe-upgrade", script)
    shutil.copy(REPO / "VERSION", libexec / "VERSION")
    script.chmod(0o755)

    monkeypatch.setenv("MOCK_BREW_DIR", str(brew_dir))
    monkeypatch.setenv("PATH", f"{MOCK_BREW_BIN}:{os.environ['PATH']}")
    monkeypatch.setenv("GH_TOKEN", "test-token")  # never shell out to gh
    monkeypatch.setenv("BREW_SAFE_SELF_FORMULA", SELF_FORMULA)
    # The startup guard requires the bottle resolver file to EXIST (it is not
    # invoked under --no-verify-sha); point at the real one so the check passes.
    monkeypatch.setenv("BREW_SAFE_BOTTLE_RESOLVER", str(REPO / "bottle_resolver.py"))
    # Empty formulae API dir → SHA reads as "tap-only" silent pass (belt for any
    # path that does reach SHA); we also pass --no-verify-sha in the gated run.
    api = tmp_path / "formulae_api_empty"
    api.mkdir()
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api))
    # Age check: everything reads comfortably old by default; per-name files
    # (recent date, or [] for "unknown") override for the held/unknown tests.
    commits = tmp_path / "commits_api"
    commits.mkdir()
    (commits / "_default.json").write_text(commit_json_days_ago(3650))
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits))

    return {"script": script, "brew": brew_dir, "commits": commits, "tmp": tmp_path}


def run_self(
    script: Path, args: list[str], env_extra: dict | None = None
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


# --- Script-install route --------------------------------------------------


def test_self_on_script_route_redirects_to_safe_update():
    """On the script-install route (running from the repo dir, not a libexec/
    dir), `--self` must NOT run a brew upgrade — it redirects to `brew
    safe-update` and exits non-zero."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GH_TOKEN": "test-token"}
    result = subprocess.run(
        ["bash", str(REPO / "brew-safe-upgrade"), "--self"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "brew safe-update" in result.stdout
    assert "updated through its own gate" not in result.stdout


# --- Formula route: happy paths --------------------------------------------


def test_self_no_outdated_deps_upgrades_formula_clean(formula_env, tmp_path):
    """No outdated dependency → skip the gate step, upgrade the formula clean."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12", "openssl@3"])
    write_outdated(formula_env["brew"], [])  # nothing outdated
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No outdated dependencies" in result.stdout
    assert "updated through its own gate" in result.stdout


def test_self_clean_deps_gated_then_formula_upgraded(formula_env, tmp_path):
    """Outdated deps that pass the gate are upgraded FIRST, then the formula."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12", "openssl@3"])
    write_outdated(
        formula_env["brew"],
        [
            outdated_formula("python@3.12", "3.12.0", "3.12.1"),
            outdated_formula("openssl@3", "3.5.0", "3.5.1"),
        ],
    )
    stub = make_cve_stub(tmp_path)  # all clean

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Gating outdated dependencies" in result.stdout
    assert "python@3.12" in result.stdout
    assert "updated through its own gate" in result.stdout


# --- Formula route: fail-closed --------------------------------------------


def test_self_vulnerable_dep_aborts_formula_not_upgraded(formula_env, tmp_path):
    """A CVE-flagged dep is excluded by the gated run (which may still exit 0);
    the belt-and-suspenders re-check finds it still outdated and ABORTS — the
    formula is never upgraded."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [outdated_formula("python@3.12", "3.12.0", "3.12.1")])
    stub = make_cve_stub(
        tmp_path,
        per_package={"python@3.12": (1, '{"status":"vulnerable"}', "[HIGH] CVE-2026-0001")},
    )

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "still outdated after the gate" in result.stdout
    assert "fail-closed" in result.stdout
    assert "updated through its own gate" not in result.stdout
    # Proof the gate did its job: the vulnerable dep was EXCLUDED by the gated
    # run (never upgraded), so it is still listed outdated — which is exactly
    # what the belt-and-suspenders re-check caught.
    remaining = json.loads((formula_env["brew"] / "outdated.json").read_text())
    assert any(f["name"] == "python@3.12" for f in remaining["formulae"])


def test_self_held_fresh_dep_aborts(formula_env, tmp_path):
    """A too-fresh dep is HELD by the freshness gate (default min-age 3d), left
    outdated, and the re-check aborts fail-closed."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [outdated_formula("python@3.12", "3.12.0", "3.12.1")])
    # 1-day-old release -> held; installed version is clean so no CVE bypass.
    (formula_env["commits"] / "python@3.12.json").write_text(commit_json_days_ago(1))
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "still outdated after the gate" in result.stdout
    assert "updated through its own gate" not in result.stdout


# --- Fail-closed on infrastructure errors -----------------------------------


def test_self_enumeration_error_aborts_fail_closed(formula_env, tmp_path):
    """If `brew outdated` (or `brew deps`) errors, enumeration must fail closed —
    an error must never be read as 'no outdated deps' and wave the formula
    upgrade through ungated."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [outdated_formula("python@3.12", "3.12.0", "3.12.1")])
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_FAIL": "outdated"},
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "fail-closed" in (result.stdout + result.stderr)
    assert "updated through its own gate" not in result.stdout


def test_self_brew_update_failure_aborts_fail_closed(formula_env, tmp_path):
    """A failing `brew update` must abort --self (don't gate on stale metadata)."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [outdated_formula("python@3.12", "3.12.0", "3.12.1")])
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_FAIL": "update"},
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "fail-closed" in (result.stdout + result.stderr)
    assert "updated through its own gate" not in result.stdout


# --- Flag threading ---------------------------------------------------------


def test_self_unknown_age_dep_held_without_flag(formula_env, tmp_path):
    """A dep whose age can't be verified is held (fail-closed) → --self aborts."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [outdated_formula("python@3.12", "3.12.0", "3.12.1")])
    (formula_env["commits"] / "python@3.12.json").write_text("[]")  # unknown age
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert "updated through its own gate" not in result.stdout


def test_self_allow_unknown_age_flag_threads_into_gate(formula_env, tmp_path):
    """--allow-unknown-age must thread into the gated dep run: the same
    unknown-age dep now passes, is upgraded, and the formula follows."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [outdated_formula("python@3.12", "3.12.0", "3.12.1")])
    (formula_env["commits"] / "python@3.12.json").write_text("[]")  # unknown age
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "--yes", "--no-verify-sha", "--allow-unknown-age"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "updated through its own gate" in result.stdout


# --- brew-safe-update wiring ------------------------------------------------


def test_safe_update_on_formula_route_execs_self(formula_env, tmp_path):
    """On a Homebrew formula install, `brew safe-update` must delegate to
    `brew safe-upgrade --self` rather than its script-route atomic swap."""
    libexec = formula_env["script"].parent
    shutil.copy(REPO / "brew-safe-update", libexec / "brew-safe-update")
    (libexec / "brew-safe-update").chmod(0o755)
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [])  # nothing outdated
    stub = make_cve_stub(tmp_path)

    result = run_self(
        libexec / "brew-safe-update",
        [],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "brew safe-upgrade --self" in result.stdout
    assert "updated through its own gate" in result.stdout


# --- Argument handling ------------------------------------------------------


def test_self_ignores_positional_packages(formula_env, tmp_path):
    """--self targets only the safe-upgrade formula; a stray positional package
    is ignored (does not change the self-upgrade behaviour)."""
    write_deps(formula_env["brew"], SELF_FORMULA, ["python@3.12"])
    write_outdated(formula_env["brew"], [])  # nothing outdated
    stub = make_cve_stub(tmp_path)

    result = run_self(
        formula_env["script"],
        ["--self", "wget", "--yes", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "No outdated dependencies" in result.stdout
    assert "updated through its own gate" in result.stdout
