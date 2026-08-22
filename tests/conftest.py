"""Fixtures shared across test modules.

`age_env` lives here rather than in a test module because pytest discovers
conftest fixtures automatically: importing a fixture by name into a second
module works at runtime but reads as a redefinition to linters, and every test
that took it as a parameter tripped F811.
"""

import datetime
import json
import os
from pathlib import Path

import pytest

MOCK_BREW_BIN = Path(__file__).parent / "fixtures" / "mock_brew"


def _commit_json_days_ago(days: int) -> str:
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
    (commits_dir / "_default.json").write_text(_commit_json_days_ago(3650))

    monkeypatch.setenv("MOCK_BREW_DIR", str(brew_dir))
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api_dir))
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits_dir))
    monkeypatch.setenv("PATH", f"{MOCK_BREW_BIN}:{os.environ['PATH']}")
    monkeypatch.delenv("BREW_SAFE_NO_DEPS", raising=False)
    # Hermetic: pin a token so resolve_gh_token() short-circuits and never shells
    # out to a host `gh auth token`. In mock mode the token is unused (the commits
    # API is read from disk, not curled), so this changes nothing but the speed.
    monkeypatch.setenv("GH_TOKEN", "test-token")
    # Age lookups must not reach the real bottle registry either. The script
    # already treats "mock commits, no MOCK_GHCR_DIR" as "no bottle", so nothing
    # extra is needed here — this comment is the reminder that it is deliberate.

    stub = tmp_path / "cve_stub.py"
    stub.write_text("#!/usr/bin/env python3\nimport sys\nprint('{}')\nsys.exit(0)\n")
    stub.chmod(0o755)
    monkeypatch.setenv("DEPENDENCY_SECURITY_CHECK", str(stub))

    return {"brew": brew_dir, "commits": commits_dir, "tmp": tmp_path}


@pytest.fixture
def brew_env(tmp_path, monkeypatch):
    """Mock brew in interactive mode with a clean age baseline — the shape the
    wrapper-level tests (pin bracket, [SAME], batched dep graph) need. Same
    staging as test_partial_upgrade.mock_env, hosted here so those modules
    can take it as a parameter without re-importing a fixture by name."""
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
    (commits_dir / "_default.json").write_text(_commit_json_days_ago(3650))
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits_dir))
    monkeypatch.setenv("MOCK_INTERACTIVE_MODE", "1")
    return fixture_dir
