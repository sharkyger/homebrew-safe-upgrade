"""Tests for filtering Homebrew's harmless description-cache backtrace.

`brew update` occasionally prints a Ruby backtrace from its own
DescriptionCacheStore on stderr. It self-heals and does not affect the update,
but dumping brew internals mid-run is alarming. brew-safe-upgrade filters those
specific lines while passing all other stderr through unchanged.

The mock `brew` emits the trace when MOCK_BREW_UPDATE_NOISE=1 and an unrelated
real warning when MOCK_BREW_UPDATE_REALERR=1 (see tests/fixtures/mock_brew/brew).
"""

import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
MOCK_BREW_BIN = Path(__file__).parent / "fixtures" / "mock_brew"
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


@pytest.fixture
def upgrade_env(tmp_path):
    """Env for a no-op brew-safe-upgrade run: mock brew on PATH, no outdated
    packages, a clean CVE stub. Returns the env dict for subprocess."""
    brew_dir = tmp_path / "brew_responses"
    brew_dir.mkdir()
    stub = tmp_path / "cve_stub.py"
    stub.write_text("#!/usr/bin/env python3\nimport sys\nprint('{}')\nsys.exit(0)\n")
    stub.chmod(0o755)

    env = os.environ.copy()
    env["MOCK_BREW_DIR"] = str(brew_dir)  # no outdated.json -> nothing outdated
    env["PATH"] = f"{MOCK_BREW_BIN}:{os.environ['PATH']}"
    env["DEPENDENCY_SECURITY_CHECK"] = str(stub)
    env["BREW_SAFE_NO_DEPS"] = "1"
    return env


def _run(env):
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE), "--min-age", "0", "--yes"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=env,
    )


def test_description_cache_trace_is_suppressed(upgrade_env):
    upgrade_env["MOCK_BREW_UPDATE_NOISE"] = "1"
    result = _run(upgrade_env)
    assert result.returncode == 0, result.stdout + result.stderr
    # None of the harmless backtrace leaks to the user.
    assert "DescriptionCacheStore" not in result.stderr
    assert "description_cache_store.rb" not in result.stderr
    assert "Cannot load descriptions cache" not in result.stderr
    assert ".rb:50:in" not in result.stderr


def test_real_stderr_passes_through(upgrade_env):
    """Filtering must not swallow genuine warnings/errors."""
    upgrade_env["MOCK_BREW_UPDATE_NOISE"] = "1"
    upgrade_env["MOCK_BREW_UPDATE_REALERR"] = "1"
    result = _run(upgrade_env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "a genuine update warning you should still see" in result.stderr
    # ...while the harmless trace is still gone.
    assert "DescriptionCacheStore" not in result.stderr
