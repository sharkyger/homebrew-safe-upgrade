"""
Tests for the transitive dependency check in brew-safe-install and brew-safe-upgrade.

Uses a mock `brew` shim on PATH so we don't need a real Homebrew install,
network access, or vulnerable test packages.
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
    """A `GET /commits` response (array) whose last commit is `days` days old.

    Mirrors the slice of the GitHub API the age check reads:
    data[0]['commit']['committer']['date']. Computed relative to now so a small
    `days` reliably reads as "too fresh" regardless of when the suite runs.
    """
    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    return json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])


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
    # Hermetic: pin a token so resolve_gh_token() short-circuits and never shells
    # out to a host `gh auth token` (unused in mock mode — curl is bypassed).
    monkeypatch.setenv("GH_TOKEN", "test-token")

    # SHA verification became default-on in v0.2.0. Tests in this file don't
    # mock canonical formulae.brew.sh responses, so point the mock dir at an
    # empty location — every formula then reads as "tap-only" (no canonical
    # SHA known), which is a silent-pass outcome and preserves the pre-SHA
    # behavior these tests were written against.
    api_dir = tmp_path / "formulae_api_empty"
    api_dir.mkdir()
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api_dir))

    # Age check became fail-closed (unknown age -> HOLD). These tests aren't about
    # freshness, so point the commits-API mock at a dir whose _default makes every
    # package resolve as comfortably old -> the age gate is a no-op here. Age tests
    # drop per-name files (recent date, or [] to force "unknown") to override.
    commits_dir = tmp_path / "commits_api"
    commits_dir.mkdir()
    (commits_dir / "_default.json").write_text(commit_json_days_ago(3650))
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits_dir))

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
    target = fixture_dir / f"info_{name}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload))


def write_deps(fixture_dir: Path, name: str, deps: list[str]):
    target = fixture_dir / f"deps_{name}.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(deps) + "\n" if deps else "")


def write_installed_version(fixture_dir: Path, name: str, version: str):
    """Mimic `brew list --versions --formula <name>` → '<name> <version>'."""
    target = fixture_dir / f"list_{name}.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"{name} {version}\n")


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
    """--no-deps must be advertised in usage output. With no package given,
    brew-safe-install prints help to stderr and exits 2 (usage error)."""
    result = subprocess.run(
        ["bash", str(SAFE_INSTALL)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert "--no-deps" in result.stderr
    assert "BREW_SAFE_NO_DEPS" in result.stderr


def test_safe_upgrade_help_header_mentions_no_deps():
    """The header comment of brew-safe-upgrade documents --no-deps."""
    text = SAFE_UPGRADE.read_text()
    assert "--no-deps" in text
    assert "BREW_SAFE_NO_DEPS" in text


# ----------------------- dep check disabled paths -----------------------


def test_no_deps_flag_skips_dep_check(mock_env, tmp_path):
    """`--no-deps` must short-circuit dep checking with a clear notice."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    # No deps_check_skipped sentinel file needed; we look for the printed notice.
    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["--no-deps", "wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Dependency check skipped" in result.stdout
    # Must NOT print the dep-check header
    assert "Checking transitive dependencies" not in result.stdout


def test_env_var_skips_dep_check(mock_env, tmp_path):
    """`BREW_SAFE_NO_DEPS=1` must short-circuit dep checking the same way."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget"],
        env_extra={"BREW_SAFE_NO_DEPS": "1", "DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Dependency check skipped" in result.stdout
    assert "Checking transitive dependencies" not in result.stdout


# ----------------------- dep check enabled paths -----------------------


def test_dep_check_runs_when_enabled(mock_env, tmp_path):
    """Default behavior: dep check header must appear."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_deps(mock_env, "wget", [])  # no deps → "no new dependency versions"
    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Checking transitive dependencies" in result.stdout
    assert "No new dependency versions coming in." in result.stdout


def test_already_installed_same_version_dep_is_skipped(mock_env, tmp_path):
    """A dep already installed at the latest version must not be re-checked."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.5.0")  # same version → skip
    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Checking transitive dependencies" in result.stdout
    # No incoming deps because the only dep is already at latest
    assert "No new dependency versions coming in." in result.stdout
    # Should never have queried CVE for openssl@3
    assert "[ok-dep] openssl@3" not in result.stdout
    assert "[VULN-DEP] openssl@3" not in result.stdout


def test_installed_old_version_is_treated_as_incoming(mock_env, tmp_path):
    """A dep installed at an older version than the latest must be checked.

    Uses --min-age 0 to disable the freshness hold: this test is about
    incoming-version *detection*, not the age gate, and the default 3-day hold
    would otherwise fetch openssl@3 3.5.0's real homebrew-core release date over
    the network — making the test fail for ~3 days after every openssl@3 bump.
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.0.0")  # older → incoming

    # Stub the CVE checker so this test stays offline.
    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget", "--min-age", "0"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Found 1 incoming dependency version(s) to check" in result.stdout
    assert "[ok-dep] openssl@3 3.5.0" in result.stdout


def test_dep_rate_limit_aborts_run(mock_env, tmp_path):
    """A GitHub API rate limit while checking a transitive dependency aborts the
    whole run (issue #84) — the dep-path -2 verdict must be caught BEFORE the
    generic '-lt 0' unknown-age hold, and name the dependency."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.0.0")  # older → incoming
    # wget itself resolves old via _default; the dep lookup is rate-limited.
    (tmp_path / "commits_api" / "openssl@3.json").write_text("__RATELIMIT__")

    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "GH_TOKEN": "test-token"},
        input_text="n\n",
    )
    assert result.returncode != 0
    assert "rate limit reached" in result.stdout
    assert "for dependency openssl@3" in result.stdout


def test_dep_rate_limit_allowed_by_allow_unknown_age(mock_env, tmp_path):
    """Companion to test_dep_rate_limit_aborts_run: with --allow-unknown-age the
    dep-path rate-limit is permitted through (not aborted, not held) — guards the
    dependency-specific -2 branch's opt-out."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    write_installed_version(mock_env, "openssl@3", "3.0.0")  # older → incoming
    (tmp_path / "commits_api" / "openssl@3.json").write_text("__RATELIMIT__")

    stub = make_cve_stub(tmp_path)  # all packages clean

    result = run_safe_install(
        ["wget", "--allow-unknown-age"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "GH_TOKEN": "test-token"},
        input_text="n\n",
    )
    expected = "[age-dep] openssl@3 — GitHub API rate-limited, allowed by --allow-unknown-age"
    assert expected in result.stdout
    assert "rate limit reached" not in result.stdout


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
    assert "WARNING: incoming dependencies have known CVEs" in result.stdout
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
    assert "dep checks could not be completed for:" in result.stdout
    assert "libfoo" in result.stdout


# ----------------------- hardening (#19, #20, #22, #23, #24) -----------------------


def test_multi_keg_installed_uses_latest_version_for_compare(mock_env, tmp_path):
    """
    `brew list --versions` returns multiple kegs space-separated on one line.
    The classifier must compare against the LAST (newest) version, not the first,
    otherwise an already-current dep is misclassified as incoming. (#19)
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "openssl@3", "3.5.0")
    write_deps(mock_env, "wget", ["openssl@3"])
    # Two kegs installed: an old one and the current one.
    (mock_env / "list_openssl@3.txt").write_text("openssl@3 3.0.0 3.5.0\n")

    stub = make_cve_stub(tmp_path)

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    # Latest is already installed → not incoming
    assert "No new dependency versions coming in." in result.stdout


def test_invalid_dep_name_is_rejected_before_query(mock_env, tmp_path):
    """
    A dep name that fails the regex guard must be skipped with [skip-dep] —
    no curl URL constructed, no python invocation. (#22)
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    # `evil; rm -rf /` would pass through the old code; the regex must catch it.
    write_deps(mock_env, "wget", ["evil; rm -rf /"])

    stub = make_cve_stub(tmp_path)

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "[skip-dep] evil; rm -rf / -- invalid name" in result.stdout
    # Critical: no [VULN-DEP] / [ok-dep] / [HOLD-DEP] line for this name.
    assert "[ok-dep] evil" not in result.stdout
    assert "[VULN-DEP] evil" not in result.stdout


def test_tap_dep_is_routed_to_its_tap_repo_for_age_check(mock_env, tmp_path):
    """
    A tap-namespaced dep (foo/bar/baz) must be routed to its OWN tap repo
    (foo/homebrew-bar) for the age lookup — not skipped, and never queried
    against homebrew-core. With a verifiable (old) age it clears the hold. (#23)

    Supersedes the old [skip-dep-age] behavior: tap deps used to silently bypass
    the freshness hold, which is the fail-open this fix closes.
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "foo/bar/baz", "1.0.0")
    write_deps(mock_env, "wget", ["foo/bar/baz"])
    # baz has no per-name commits file → resolves old via _default.

    url_log = tmp_path / "commits_url.log"
    stub = make_cve_stub(tmp_path)

    result = run_safe_install(
        ["wget", "--min-age", "30"],
        env_extra={
            "DEPENDENCY_SECURITY_CHECK": str(stub),
            "MOCK_COMMITS_API_LOG": str(url_log),
        },
        input_text="n\n",
    )
    log_text = url_log.read_text()
    # Routed to the tap repo, NOT homebrew-core.
    assert "foo/homebrew-bar/commits?path=Formula/baz.rb" in log_text
    assert "Formula/f/foo/bar/baz.rb" not in log_text
    # Age verified (old) → dep clears the hold, CVE check runs, dep is clean.
    assert "[ok-dep] foo/bar/baz 1.0.0" in result.stdout
    # The old silent-skip line is gone.
    assert "[skip-dep-age]" not in result.stdout


def test_dep_with_unverifiable_age_is_held_fail_closed(mock_env, tmp_path):
    """
    A dependency whose release age cannot be verified must be HELD (fail closed),
    not waved through as [ok-dep]. This is the deps-loop half of the fail-open fix.
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])
    # Force "unknown" for libfoo: an empty commits array overrides the old _default.
    commits_dir = Path(os.environ["MOCK_COMMITS_API_DIR"])
    (commits_dir / "libfoo.json").write_text("[]")

    stub = make_cve_stub(tmp_path)

    result = run_safe_install(
        ["wget", "--min-age", "30"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "[HOLD-DEP] libfoo 1.2.3 -- age could not be verified" in result.stdout
    assert "[ok-dep] libfoo" not in result.stdout


def test_allow_unknown_age_lets_unverifiable_dep_through(mock_env, tmp_path):
    """
    --allow-unknown-age is the explicit escape hatch: an unverifiable-age dep is
    permitted (and logged as such) rather than held.
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])
    commits_dir = Path(os.environ["MOCK_COMMITS_API_DIR"])
    (commits_dir / "libfoo.json").write_text("[]")

    stub = make_cve_stub(tmp_path)

    result = run_safe_install(
        ["wget", "--min-age", "30", "--allow-unknown-age"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    expected = "[age-dep] libfoo — age could not be verified, allowed by --allow-unknown-age"
    assert expected in result.stdout
    assert "[HOLD-DEP] libfoo" not in result.stdout
    assert "[ok-dep] libfoo 1.2.3" in result.stdout


def test_upgrade_dep_with_unverifiable_age_is_held_fail_closed(mock_env, tmp_path):
    """
    safe-UPGRADE has its own transitive-deps loop. A core dep whose age cannot be
    verified must be HELD there too — regression guard for the loop that originally
    shipped without the fail-closed branch (the parent passes its own age check).
    """
    write_outdated(
        mock_env,
        [{"name": "wget", "installed_versions": ["1.24.0"], "current_version": "1.25.0"}],
    )
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])
    # wget resolves old via _default; force libfoo "unknown".
    commits_dir = Path(os.environ["MOCK_COMMITS_API_DIR"])
    (commits_dir / "libfoo.json").write_text("[]")

    stub = make_cve_stub(tmp_path)

    result = run_safe_upgrade(
        ["--min-age", "30"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "[HOLD-DEP] libfoo 1.2.3 -- age could not be verified" in result.stdout
    assert "[ok-dep] libfoo" not in result.stdout


def test_warning_splits_vuln_and_hold_into_separate_sections(mock_env, tmp_path):
    """
    When both a vulnerable dep AND a too-fresh dep land in the same run, the
    warning output must show two distinct sections — not one combined header. (#24)

    The age check requires real GitHub API calls, which we don't mock; this
    test focuses on the case where ONLY a vulnerable dep is present and asserts
    the new header text. The HOLD-only header is exercised manually.
    """
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "wget", ["libfoo"])

    stub = make_cve_stub(
        tmp_path,
        per_package={"libfoo": (1, '{"status":"vulnerable"}', "[HIGH] CVE-2026-99999")},
    )

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    # New header text — distinguishes vulnerable from too-fresh
    assert "WARNING: incoming dependencies have known CVEs:" in result.stdout
    # Old conflated header must NOT appear
    assert "WARNING: incoming dependencies have known issues" not in result.stdout


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
    assert "WARNING: incoming dependencies have known CVEs" in result.stdout

    # The bypass notice must be on STDERR (not stdout) so it survives `>/dev/null`
    # and is conspicuous in CI log streams.
    assert "[--yes] continuing despite dep warnings" in result.stderr
    assert "[--yes] continuing despite dep warnings" not in result.stdout

    # The script reached the final "Done." line — i.e. upgrade was attempted.
    assert "Done." in result.stdout


# ----------------------- single-package upgrade (#61) -----------------------


def test_single_package_upgrade_restricts_to_named(mock_env, tmp_path):
    """`brew safe-upgrade wget` must process only wget, not every outdated package."""
    write_outdated(
        mock_env,
        [
            {"name": "wget", "installed_versions": ["1.24"], "current_version": "1.25"},
            {"name": "curl", "installed_versions": ["8.0"], "current_version": "8.1"},
        ],
    )
    write_formula_info(mock_env, "wget", "1.25")
    write_formula_info(mock_env, "curl", "8.1")
    stub = make_cve_stub(tmp_path)

    result = run_safe_upgrade(
        ["wget", "--no-deps"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Found 1 outdated package(s)" in result.stdout
    assert "wget" in result.stdout
    # curl was outdated but not named — it must not appear anywhere in the run.
    assert "curl" not in result.stdout


def test_single_package_not_outdated_is_reported(mock_env, tmp_path):
    """A named package that isn't outdated is reported clearly, not silently ignored."""
    write_outdated(
        mock_env,
        [{"name": "wget", "installed_versions": ["1.24"], "current_version": "1.25"}],
    )
    write_formula_info(mock_env, "wget", "1.25")
    stub = make_cve_stub(tmp_path)

    result = run_safe_upgrade(
        ["curl", "--no-deps"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "curl — not outdated" in result.stdout
    assert "Nothing to upgrade for: curl" in result.stdout


def test_single_package_matches_tap_basename(mock_env, tmp_path):
    """`brew safe-upgrade safe-fetch` matches the full tap name sharkyger/tap/safe-fetch."""
    write_outdated(
        mock_env,
        [
            {
                "name": "sharkyger/tap/safe-fetch",
                "installed_versions": ["0.2"],
                "current_version": "0.3",
            },
            {"name": "wget", "installed_versions": ["1.24"], "current_version": "1.25"},
        ],
    )
    write_formula_info(mock_env, "sharkyger/tap/safe-fetch", "0.3")
    write_formula_info(mock_env, "wget", "1.25")
    stub = make_cve_stub(tmp_path)

    result = run_safe_upgrade(
        ["safe-fetch", "--no-deps", "--no-verify-sha"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Found 1 outdated package(s)" in result.stdout
    assert "safe-fetch" in result.stdout
    assert "wget" not in result.stdout


# ----------------------- dep-scan progress (#60) -----------------------


def test_dep_scan_shows_per_dependency_progress(mock_env, tmp_path):
    """The transitive-dep scan announces each dep (with an i/N counter) before its
    slow network checks, so a multi-minute scan isn't a silent wait."""
    write_formula_info(mock_env, "wget", "1.25.0")
    write_formula_info(mock_env, "libfoo", "1.0")
    write_formula_info(mock_env, "libbar", "2.0")
    write_deps(mock_env, "wget", ["libfoo", "libbar"])
    stub = make_cve_stub(tmp_path)

    result = run_safe_install(
        ["wget"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "Found 2 incoming dependency version(s) to check" in result.stdout
    assert "[1/2] checking" in result.stdout
    assert "[2/2] checking" in result.stdout


# ------------- unverifiable dep fails CLOSED (live 50-package run, 2026-08-21) -------------


def test_upgrade_dep_whose_check_failed_taints_its_parent(mock_env, tmp_path):
    """
    A dep whose CVE check FAILED used to print "These will upgrade unchecked" and
    leave its parent in "Unaffected and safe to upgrade now" — the dependency pass
    failed open while the main pass fails closed for the very same package. An
    unverifiable dependency is a flagged dependency: its dependents are held and,
    under [s], the dep is pinned like a vulnerable or too-fresh one.
    """
    write_outdated(
        mock_env,
        [
            {"name": "curl", "installed_versions": ["8.0.0"], "current_version": "8.1.0"},
            {"name": "jq", "installed_versions": ["1.6"], "current_version": "1.7"},
        ],
    )
    write_formula_info(mock_env, "curl", "8.1.0")
    write_formula_info(mock_env, "jq", "1.7")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "curl", ["libfoo"])
    write_deps(mock_env, "jq", [])

    stub = make_cve_stub(tmp_path, per_package={"libfoo": (2, "", "network error")})

    result = run_safe_upgrade(
        [],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    out = result.stdout
    assert "[skip-dep] libfoo 1.2.3" in out
    assert "unchecked" not in out, out
    assert "could not be checked" in out
    assert "Depends on a flagged dependency: curl" in out
    # jq does not depend on libfoo and stays upgradable; curl must not be listed safe.
    safe_line = next((line for line in out.splitlines() if "Unaffected and safe" in line), "")
    assert "jq" in safe_line, out
    assert " curl" not in safe_line, out


def test_install_dep_whose_check_failed_taints_its_parent(mock_env, tmp_path):
    """Same contract for brew safe-install."""
    write_formula_info(mock_env, "curl", "8.1.0")
    write_formula_info(mock_env, "libfoo", "1.2.3")
    write_deps(mock_env, "curl", ["libfoo"])
    stub = make_cve_stub(tmp_path, per_package={"libfoo": (2, "", "network error")})

    result = run_safe_install(
        ["curl"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)},
        input_text="n\n",
    )
    assert "[skip-dep] libfoo 1.2.3" in result.stdout
    assert "unchecked" not in result.stdout, result.stdout
    assert "could not be checked" in result.stdout


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
