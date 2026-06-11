"""Tests for the --help / -h flags on all three commands (issue #66).

Each command must print a usage block — synopsis, a flag listing, and a one-line
description — and exit 0, WITHOUT doing any real work (no brew calls, no network,
no update). Help is handled before the helper-file guards, so it answers even on
a partially-installed tree.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
COMMANDS = ["brew-safe-upgrade", "brew-safe-install", "brew-safe-update"]

# When help text is blank Homebrew falls back to this generic banner. Its
# presence in `brew <cmd> --help` output means our help was NOT picked up.
GENERIC_BREW_HELP_MARKER = "Example usage:"


def _run(args):
    """Run a shipped command with a minimal env (no mock hooks, no network)."""
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    return subprocess.run(
        ["bash", str(REPO / args[0]), *args[1:]],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        env=env,
    )


@pytest.mark.parametrize("cmd", COMMANDS)
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_flag_prints_usage_and_exits_zero(cmd, flag):
    result = _run([cmd, flag])
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    # Synopsis line names the user-facing `brew <name>` command.
    brew_name = cmd.replace("brew-safe-", "safe-")
    assert f"brew {brew_name}" in out, out
    # A flag listing + the self-documenting flags are present.
    assert "Usage:" in out, out
    assert "-h, --help" in out, out
    assert "--version" in out, out


@pytest.mark.parametrize("cmd", COMMANDS)
def test_help_does_no_work(cmd):
    """--help must short-circuit: no 'All tools updated', no upgrade/resolve output."""
    result = _run([cmd, "--help"])
    assert "All tools updated" not in result.stdout
    assert "Resolving package versions" not in result.stdout


@pytest.mark.parametrize("cmd", COMMANDS)
def test_version_still_works(cmd):
    """Regression: --version (shipped in v0.2.2) keeps working alongside --help."""
    result = _run([cmd, "--version"])
    assert result.returncode == 0, result.stdout + result.stderr
    assert cmd in result.stdout  # e.g. "brew-safe-upgrade 0.2.x"
    assert "install route:" in result.stdout


def test_safe_install_no_package_prints_help_to_stderr():
    """No package given is a usage error: help goes to stderr, exit code 2."""
    result = _run(["brew-safe-install"])
    assert result.returncode == 2, result.stdout + result.stderr
    assert "Usage:" in result.stderr
    assert "no package" in result.stderr.lower()


@pytest.mark.parametrize("cmd", ["brew-safe-upgrade", "brew-safe-install"])
def test_min_age_without_value_errors_not_loops(cmd):
    """Regression: a bare `--min-age` (no value) must error out with exit 2, NOT
    `shift 2` past the end and loop forever. The short timeout would expire on a
    regression."""
    result = _run([cmd, "--min-age"])
    assert result.returncode == 2, result.stdout + result.stderr
    assert "requires a numeric argument" in result.stderr


# --- Homebrew dispatcher integration (issue #66 follow-up) -------------------
# `brew <cmd> --help` is intercepted by Homebrew BEFORE the script runs, so the
# print_help() tests above (which exec the script directly) cannot catch the
# real-world break. Homebrew renders external-command help only from lines that
# begin with `#:`. Without them it shows the generic brew banner instead.
@pytest.mark.parametrize("cmd", COMMANDS)
def test_brew_help_convention_present(cmd):
    """Each command must carry `#:` doc lines, or `brew <cmd> --help` will show
    the generic Homebrew banner instead of our usage."""
    lines = (REPO / cmd).read_text().splitlines()
    doc_lines = [ln for ln in lines if ln.startswith("#:")]
    brew_name = cmd.replace("brew-safe-", "safe-")
    assert doc_lines, (
        f"{cmd}: no `#:` help lines — `brew {brew_name} --help` will fall back "
        f"to the generic Homebrew help. See docs.brew.sh/External-Commands."
    )
    # The synopsis must name the user-facing `brew safe-*` command.
    assert any(f"brew {brew_name}" in ln for ln in doc_lines), doc_lines


@pytest.mark.parametrize("cmd", COMMANDS)
def test_brew_dispatcher_help_not_generic(cmd):
    """Integration: drive help through the real `brew` dispatcher and assert it
    does NOT degrade to the generic banner. Skipped where brew is unavailable
    (e.g. Linux CI without Homebrew)."""
    brew = shutil.which("brew")
    if not brew:
        pytest.skip("brew not on PATH")
    brew_name = cmd.replace("brew-safe-", "safe-")
    # Prepend the repo to PATH so brew finds our (un-installed) brew-safe-* file.
    env = dict(os.environ, PATH=f"{REPO}{os.pathsep}{os.environ.get('PATH', '')}")
    env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
    env.setdefault("HOMEBREW_NO_INSTALL_FROM_API", "1")
    result = subprocess.run(
        [brew, brew_name, "--help"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )
    out = result.stdout + result.stderr
    assert GENERIC_BREW_HELP_MARKER not in out, (
        f"`brew {brew_name} --help` returned the generic Homebrew banner — "
        f"the `#:` help block was not picked up.\n{out}"
    )
    assert f"brew {brew_name}" in out, out
