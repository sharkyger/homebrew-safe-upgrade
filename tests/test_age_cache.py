"""
Tests for the age-resolution cache and the bottle-registry date source.

Background: fetch_pkg_age spent one GitHub API request per outdated package.
Anonymous GitHub REST allows 60/hour/IP, and a machine that has not been
upgraded for a few weeks routinely has 50-70 outdated packages — so the first
run can exhaust the quota and a second run within the hour always does. Issue
#84 raised the ceiling by authenticating; this covers the two changes that cut
the call volume instead:

  1. (type, name, version) -> publication timestamp is cached on disk. A
     released version's date is immutable, so re-runs cost zero requests.
  2. homebrew-core formulae resolve from the ghcr.io bottle manifest
     (org.opencontainers.image.created), which is not metered against the REST
     budget. Taps and casks stay on the GitHub commit date.

Test seams the production script honors:
  - BREW_SAFE_AGE_CACHE_DIR: cache location. Setting it also *enables* the cache
    under MOCK_COMMITS_API_DIR, where it is otherwise off so that a date
    resolved by one test cannot leak into another (or into the real user cache).
  - MOCK_GHCR_DIR: per-"<name>@<version>" canned manifest JSON ('/' and '@'
    folded to '_'). A missing file means "no bottle for this version".
"""

import datetime
import json

import pytest

from tests.test_age_check import (
    commit_json_days_ago,
    run_upgrade,
    set_commits,
    write_outdated,
)


def manifest_days_ago(days: int) -> str:
    """An OCI image index whose created annotation is `days` days old."""
    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    return json.dumps(
        {"annotations": {"org.opencontainers.image.created": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}
    )


@pytest.fixture
def ghcr_dir(tmp_path, monkeypatch):
    d = tmp_path / "ghcr"
    d.mkdir()
    monkeypatch.setenv("MOCK_GHCR_DIR", str(d))
    return d


@pytest.fixture
def cache_dir(tmp_path, monkeypatch):
    d = tmp_path / "age_cache"
    monkeypatch.setenv("BREW_SAFE_AGE_CACHE_DIR", str(d))
    return d


def set_manifest(ghcr_dir, name: str, version: str, content: str):
    key = f"{name}@{version}".replace("/", "_").replace("@", "_")
    (ghcr_dir / f"{key}.json").write_text(content)


def outdated_formula(name: str, installed: str, current: str):
    return {
        "name": name,
        "installed_versions": [installed],
        "current_version": current,
    }


# ----------------------- registry as the date source -----------------------


def test_core_formula_prefers_bottle_manifest_over_commit_date(age_env, ghcr_dir):
    """For homebrew-core the bottle publication time wins. The commit date is the
    last touch on the .rb file — homebrew-core lands a version bump and its bottle
    hashes as two separate commits, so per_page=1 can report days after release."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(30))
    set_manifest(ghcr_dir, "pandoc", "3.10.2", manifest_days_ago(0))

    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] pandoc 3.10.2 — released 0 day(s) ago" in result.stdout


def test_core_formula_falls_back_to_commit_date_when_no_bottle(age_env, ghcr_dir):
    """Source-only formulae and not-yet-built versions have no manifest; those
    must still resolve via GitHub rather than becoming 'unverifiable'."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(0))
    # deliberately no manifest staged

    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] pandoc 3.10.2 — released 0 day(s) ago" in result.stdout


def test_tap_formula_ignores_the_bottle_manifest(age_env, ghcr_dir):
    """Trust boundary. Only Homebrew CI can push homebrew-core manifests, but a
    third-party tap owner controls their own annotations and could backdate one
    to slip past --min-age. Taps must stay on the GitHub-attested commit date
    even when a manifest is available."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("acme/tap/widget", "1.0", "2.0")])
    set_commits(age_env["commits"], "acme/tap/widget", commit_json_days_ago(0))
    # A backdated manifest that would wave the package through if it were trusted.
    set_manifest(ghcr_dir, "acme/tap/widget", "2.0", manifest_days_ago(900))

    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] acme/tap/widget 2.0 — released 0 day(s) ago" in result.stdout
    assert "released 900 day(s) ago" not in result.stdout


# ----------------------- the cache -----------------------


def test_resolved_date_is_cached_and_reused(age_env, cache_dir):
    """Second run must not need the commits API at all — this is what keeps a
    large backlog under the 60/hour ceiling across repeated runs."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(400))

    first = run_upgrade(["--no-deps", "--min-age", "3"])
    assert "[ok] pandoc 3.10.2 — released 400 day(s) ago" in first.stdout
    assert cache_dir.is_dir() and list(cache_dir.iterdir()), "nothing was cached"

    # Make a live lookup impossible: an empty response would read as "unknown"
    # and fail closed. Resolving anyway proves the cache served it.
    set_commits(age_env["commits"], "pandoc", "[]")
    second = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[ok] pandoc 3.10.2 — released 400 day(s) ago" in second.stdout
    assert "age could not be verified" not in second.stdout


def test_cache_is_keyed_by_version_not_just_name(age_env, cache_dir):
    """A new version of an already-cached package must trigger a fresh lookup,
    otherwise a 0-day release would inherit the old version's age."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(400))
    run_upgrade(["--no-deps", "--min-age", "3"])

    # Same package, newer version, released today.
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10.2", "3.11.0")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(0))
    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] pandoc 3.11.0 — released 0 day(s) ago" in result.stdout


def test_corrupt_cache_entry_falls_back_to_a_live_lookup(age_env, cache_dir):
    """A truncated or hand-edited cache file must never feed a bogus date into a
    security decision — it degrades to the network path."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(400))
    run_upgrade(["--no-deps", "--min-age", "3"])

    for entry in cache_dir.iterdir():
        entry.write_text("not-a-timestamp\n")

    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(0))
    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] pandoc 3.10.2 — released 0 day(s) ago" in result.stdout


def test_cache_filenames_stay_inside_the_cache_dir(age_env, cache_dir):
    """Tap names contain '/' and versioned formulae contain '@'. Both are folded
    so a key can never traverse out of the cache directory."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("acme/tap/widget", "1.0", "2.0")])
    set_commits(age_env["commits"], "acme/tap/widget", commit_json_days_ago(400))

    run_upgrade(["--no-deps", "--min-age", "3"])

    entries = list(cache_dir.iterdir())
    assert entries, "nothing was cached"
    for entry in entries:
        assert entry.parent == cache_dir
        assert "/" not in entry.name and "@" not in entry.name


def test_cache_is_off_by_default_under_mock_mode(age_env):
    """Without an explicit BREW_SAFE_AGE_CACHE_DIR the suite must not write to
    the developer's real cache, and one test's date must not leak into another."""
    write_outdated(age_env["brew"], formulae=[outdated_formula("pandoc", "3.10", "3.10.2")])
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(400))
    assert (
        "[ok] pandoc 3.10.2 — released 400 day(s) ago"
        in run_upgrade(["--no-deps", "--min-age", "3"]).stdout
    )

    # No cache in play, so the changed response must be observed immediately.
    set_commits(age_env["commits"], "pandoc", commit_json_days_ago(0))
    result = run_upgrade(["--no-deps", "--min-age", "3"])

    assert "[HOLD] pandoc 3.10.2 — released 0 day(s) ago" in result.stdout
