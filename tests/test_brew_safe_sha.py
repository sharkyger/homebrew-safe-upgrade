"""
Tests for SHA verification in brew-safe-install and brew-safe-upgrade.

Contract (drafted 2026-05-14, TDD red phase):

1. Untampered formula: local tap SHA == canonical formulae.brew.sh SHA -> [sha] verified, exit 0.
2. Tampered formula: local SHA != canonical -> [BLOCKED] SHA mismatch, non-zero exit.
   No prompt, no --yes override.
3. No-bottle formula (built from source): canonical has no bottle -> log + exit 0.
4a. Canonical API returns 404 (tap-only formula): log "tap-only", no prompt, exit 0.
4b. Canonical API 5xx/timeout, interactive: prompt [WARN] ... Install anyway? [y/N].
    Default N. User declines -> non-zero exit. User confirms -> exit 0.
4c. Canonical API 5xx/timeout, batch (--yes OR non-interactive): warn loudly, continue.
5. Cask + SHA verify: pass-through, log "casks not in scope", exit 0.
   Brew enforces cask-file SHA on its end.
6. Symmetry: same contract for brew-safe-install and brew-safe-upgrade.
7. --no-verify-sha opt-out skips the check entirely. Default is ON.

Test escape hatches the production code must honor:
- MOCK_FORMULAE_API_DIR: directory of pre-canned canonical responses, used instead
  of curl https://formulae.brew.sh. File present -> 200 OK with that JSON.
  File absent -> simulate 404. File contains "__SIMULATE_API_ERROR__" -> 5xx/timeout.
- MOCK_INTERACTIVE_MODE=1: forces the prompt branch even under subprocess
  (which has no TTY). Production code never sets this; tests do.
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

CLEAN_SHA = "a" * 64
TAMPERED_SHA = "b" * 64


# ----------------------- fixtures + helpers -----------------------


@pytest.fixture
def sha_env(tmp_path, monkeypatch):
    """Mock both `brew info` and the formulae.brew.sh canonical API."""
    brew_dir = tmp_path / "brew_responses"
    brew_dir.mkdir()
    api_dir = tmp_path / "formulae_api"
    api_dir.mkdir()

    monkeypatch.setenv("MOCK_BREW_DIR", str(brew_dir))
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api_dir))
    monkeypatch.setenv("PATH", f"{MOCK_BREW_BIN}:{os.environ['PATH']}")
    monkeypatch.delenv("BREW_SAFE_NO_DEPS", raising=False)

    # Stub the CVE checker so SHA-verify tests don't hit real APIs.
    stub = tmp_path / "cve_stub.py"
    stub.write_text("#!/usr/bin/env python3\nimport sys\nprint('{}')\nsys.exit(0)\n")
    stub.chmod(0o755)
    monkeypatch.setenv("DEPENDENCY_SECURITY_CHECK", str(stub))

    return {"brew": brew_dir, "api": api_dir}


def write_formula_info(brew_dir: Path, name: str, version: str, sha256: str | None = None):
    """Mimic `brew info --json=v2 <formula>` with an optional bottle SHA."""
    formula = {
        "name": name,
        "full_name": name,
        "versions": {"stable": version},
        "installed": [],
    }
    if sha256:
        formula["bottle"] = {"stable": {"files": {"arm64_sequoia": {"sha256": sha256}}}}
    payload = {"formulae": [formula], "casks": []}
    (brew_dir / f"info_{name}.json").write_text(json.dumps(payload))


def write_cask_info(brew_dir: Path, name: str, version: str):
    payload = {
        "formulae": [],
        "casks": [{"token": name, "name": [name], "version": version}],
    }
    (brew_dir / f"info_{name}.json").write_text(json.dumps(payload))


def write_deps(brew_dir: Path, name: str, deps: list[str]):
    """Mimic `brew deps <name>`."""
    (brew_dir / f"deps_{name}.txt").write_text("\n".join(deps) + "\n" if deps else "")


def write_outdated(brew_dir: Path, formulae: list[dict]):
    """Mimic `brew outdated --json=v2` — needed for safe-upgrade tests."""
    (brew_dir / "outdated.json").write_text(json.dumps({"formulae": formulae, "casks": []}))


def write_canonical_sha(api_dir: Path, name: str, sha256: str):
    """Canonical 200 OK response from formulae.brew.sh."""
    payload = {
        "name": name,
        "bottle": {"stable": {"files": {"arm64_sequoia": {"sha256": sha256}}}},
    }
    (api_dir / f"{name}.json").write_text(json.dumps(payload))


def write_canonical_no_bottle(api_dir: Path, name: str):
    """Formula exists in canonical API but has no bottle (built from source)."""
    payload = {"name": name, "bottle": {"stable": {"files": {}}}}
    (api_dir / f"{name}.json").write_text(json.dumps(payload))


def write_canonical_api_error(api_dir: Path, name: str):
    """Simulate transient 5xx / timeout from the canonical API."""
    (api_dir / f"{name}.json").write_text("__SIMULATE_API_ERROR__")


def outdated_entry(name: str, installed: str, current: str) -> dict:
    return {
        "name": name,
        "installed_versions": [installed],
        "current_version": current,
    }


def run_safe(
    script: Path,
    args: list[str],
    env_extra: dict | None = None,
    input_text: str = "n\n",
) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
        input=input_text,
    )


# ----------------------- Case 1: untampered passes -----------------------


def test_install_untampered_formula_verifies_and_passes(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", CLEAN_SHA)
    write_canonical_sha(sha_env["api"], "wget", CLEAN_SHA)
    write_deps(sha_env["brew"], "wget", [])

    result = run_safe(SAFE_INSTALL, ["wget"], input_text="n\n")
    assert "[sha] verified" in result.stdout, result.stdout
    assert "[BLOCKED]" not in result.stdout
    assert "SHA mismatch" not in result.stdout


def test_upgrade_untampered_formula_verifies_and_passes(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", CLEAN_SHA)
    write_canonical_sha(sha_env["api"], "wget", CLEAN_SHA)
    write_deps(sha_env["brew"], "wget", [])
    write_outdated(sha_env["brew"], [outdated_entry("wget", "1.24.0", "1.25.0")])

    result = run_safe(SAFE_UPGRADE, ["--yes"], input_text="")
    assert "[sha] verified" in result.stdout, result.stdout
    assert "[BLOCKED]" not in result.stdout


# ----------------------- Case 2: tampered blocks (no prompt) -----------------------


def test_install_tampered_formula_blocks(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", TAMPERED_SHA)
    write_canonical_sha(sha_env["api"], "wget", CLEAN_SHA)
    write_deps(sha_env["brew"], "wget", [])

    result = run_safe(SAFE_INSTALL, ["wget"], input_text="n\n")
    assert "[BLOCKED]" in result.stdout, result.stdout
    assert "SHA mismatch" in result.stdout
    # No prompt — tampering is not a user choice.
    assert "Install anyway?" not in result.stdout
    assert result.returncode != 0


def test_upgrade_tampered_formula_blocks_even_with_yes(sha_env):
    """--yes never overrides a tampering block."""
    write_formula_info(sha_env["brew"], "wget", "1.25.0", TAMPERED_SHA)
    write_canonical_sha(sha_env["api"], "wget", CLEAN_SHA)
    write_deps(sha_env["brew"], "wget", [])
    write_outdated(sha_env["brew"], [outdated_entry("wget", "1.24.0", "1.25.0")])

    result = run_safe(SAFE_UPGRADE, ["--yes"], input_text="")
    assert "[BLOCKED]" in result.stdout, result.stdout
    assert "SHA mismatch" in result.stdout
    assert result.returncode != 0


# ----------------------- Case 3: no-bottle formula passes -----------------------


def test_install_no_bottle_formula_passes(sha_env):
    write_formula_info(sha_env["brew"], "buildit", "1.0.0", CLEAN_SHA)
    write_canonical_no_bottle(sha_env["api"], "buildit")
    write_deps(sha_env["brew"], "buildit", [])

    result = run_safe(SAFE_INSTALL, ["buildit"], input_text="n\n")
    assert "no bottle" in result.stdout, result.stdout
    assert "[BLOCKED]" not in result.stdout


# ----------------------- Case 4a: 404 tap-only formula -----------------------


def test_install_tap_only_formula_passes_with_log(sha_env):
    write_formula_info(sha_env["brew"], "thirdparty", "0.1.0", CLEAN_SHA)
    # No canonical fixture written -> simulates 404 from formulae.brew.sh
    write_deps(sha_env["brew"], "thirdparty", [])

    result = run_safe(SAFE_INSTALL, ["thirdparty"], input_text="n\n")
    assert "tap-only" in result.stdout, result.stdout
    assert "[BLOCKED]" not in result.stdout
    assert "Install anyway?" not in result.stdout


# ----------------------- Case 4b: API error + interactive -> prompt -----------------------


def test_install_api_error_prompts_in_interactive_user_declines(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", CLEAN_SHA)
    write_canonical_api_error(sha_env["api"], "wget")
    write_deps(sha_env["brew"], "wget", [])

    result = run_safe(
        SAFE_INSTALL,
        ["wget"],
        env_extra={"MOCK_INTERACTIVE_MODE": "1"},
        input_text="n\n",
    )
    assert "[WARN]" in result.stdout, result.stdout
    assert "Install anyway?" in result.stdout
    assert result.returncode != 0


def test_install_api_error_prompts_in_interactive_user_confirms(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", CLEAN_SHA)
    write_canonical_api_error(sha_env["api"], "wget")
    write_deps(sha_env["brew"], "wget", [])

    result = run_safe(
        SAFE_INSTALL,
        ["wget"],
        env_extra={"MOCK_INTERACTIVE_MODE": "1"},
        input_text="y\n",
    )
    assert "[WARN]" in result.stdout
    assert "Install anyway?" in result.stdout
    assert result.returncode == 0


def test_install_api_error_single_prompt_for_batch(sha_env):
    """Multiple packages with unreachable SHAs collect into ONE prompt, not N."""
    for name in ("foo", "bar", "baz"):
        write_formula_info(sha_env["brew"], name, "1.0.0", CLEAN_SHA)
        write_canonical_api_error(sha_env["api"], name)
        write_deps(sha_env["brew"], name, [])

    result = run_safe(
        SAFE_INSTALL,
        ["foo", "bar", "baz"],
        env_extra={"MOCK_INTERACTIVE_MODE": "1"},
        input_text="n\n",
    )
    # The prompt should appear exactly once.
    assert result.stdout.count("Install anyway?") == 1, result.stdout


# ----------------------- Case 4c: API error + batch -> warn + continue -----------------------


def test_upgrade_api_error_with_yes_warns_and_continues(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", CLEAN_SHA)
    write_canonical_api_error(sha_env["api"], "wget")
    write_deps(sha_env["brew"], "wget", [])
    write_outdated(sha_env["brew"], [outdated_entry("wget", "1.24.0", "1.25.0")])

    result = run_safe(SAFE_UPGRADE, ["--yes"], input_text="")
    assert "[WARN]" in result.stdout
    assert "Install anyway?" not in result.stdout  # No prompt under --yes
    assert result.returncode == 0


def test_install_api_error_non_interactive_warns_and_continues(sha_env):
    """Subprocess context (no TTY, no MOCK_INTERACTIVE_MODE): warn + continue.
    Must not hang waiting for a prompt that nobody can answer."""
    write_formula_info(sha_env["brew"], "wget", "1.25.0", CLEAN_SHA)
    write_canonical_api_error(sha_env["api"], "wget")
    write_deps(sha_env["brew"], "wget", [])

    result = run_safe(SAFE_INSTALL, ["wget"], input_text="")
    assert "[WARN]" in result.stdout, result.stdout
    assert "Install anyway?" not in result.stdout
    assert result.returncode == 0


# ----------------------- Case 5: cask pass-through -----------------------


def test_install_cask_skips_sha_check(sha_env):
    write_cask_info(sha_env["brew"], "firefox", "200.0")
    write_deps(sha_env["brew"], "firefox", [])

    result = run_safe(SAFE_INSTALL, ["firefox"], input_text="n\n")
    assert "casks not in scope" in result.stdout, result.stdout
    assert "[BLOCKED]" not in result.stdout
    assert "[sha] verified" not in result.stdout


# ----------------------- Case 7: --no-verify-sha opt-out -----------------------


def test_install_no_verify_sha_skips_check_entirely(sha_env):
    """When opted out, even a tampered SHA does not block (user took the risk)."""
    write_formula_info(sha_env["brew"], "wget", "1.25.0", TAMPERED_SHA)
    write_canonical_sha(sha_env["api"], "wget", CLEAN_SHA)
    write_deps(sha_env["brew"], "wget", [])

    result = run_safe(SAFE_INSTALL, ["--no-verify-sha", "wget"], input_text="n\n")
    assert "[sha]" not in result.stdout
    assert "[BLOCKED]" not in result.stdout
    assert "SHA mismatch" not in result.stdout


def test_upgrade_no_verify_sha_skips_check_entirely(sha_env):
    write_formula_info(sha_env["brew"], "wget", "1.25.0", TAMPERED_SHA)
    write_canonical_sha(sha_env["api"], "wget", CLEAN_SHA)
    write_deps(sha_env["brew"], "wget", [])
    write_outdated(sha_env["brew"], [outdated_entry("wget", "1.24.0", "1.25.0")])

    result = run_safe(SAFE_UPGRADE, ["--no-verify-sha", "--yes"], input_text="")
    assert "[sha]" not in result.stdout
    assert "[BLOCKED]" not in result.stdout


# ----------------------- Default-on and help-text assertions -----------------------


def test_install_verify_sha_default_is_true():
    """Source-level assertion: the initialization line must be VERIFY_SHA=true.
    Not the flag handler — that's a separate line that begins with `--verify-sha)`."""
    text = SAFE_INSTALL.read_text()
    assert re.search(r"^VERIFY_SHA=true\b", text, re.MULTILINE), (
        "Default must be ON after this PR (init line must read `VERIFY_SHA=true`)"
    )


def test_upgrade_verify_sha_default_is_true():
    text = SAFE_UPGRADE.read_text()
    assert re.search(r"^VERIFY_SHA=true\b", text, re.MULTILINE)


def test_install_help_documents_no_verify_sha_flag():
    """Help output must advertise the opt-out, not opt-in."""
    text = SAFE_INSTALL.read_text()
    assert "--no-verify-sha" in text


def test_upgrade_help_documents_no_verify_sha_flag():
    text = SAFE_UPGRADE.read_text()
    assert "--no-verify-sha" in text
