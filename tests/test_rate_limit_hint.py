"""A throttled run must say so, and say what to do about it.

Being rate-limited and being unable to check are the same outcome (the package
is held, fail-closed) but not the same message. Without naming the cause the
user sees packages held for no stated reason, concludes the tool is broken, and
reaches for --no-deps — which is a worse security outcome than the fail-open
this all replaced.

The signal has to travel in the JSON on stdout, because both wrappers invoke the
scanner with stderr suppressed and so can never see its printed hint.
"""

import io
import json
import os
import subprocess
import sys
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402

SAFE_UPGRADE = REPO_ROOT / "brew-safe-upgrade"
SAFE_INSTALL = REPO_ROOT / "brew-safe-install"


def run_main(exc, api_key=None):
    """Run main() with every NVD request raising `exc`. Returns (code, json, stderr)."""
    saved = os.environ.pop("NVD_API_KEY", None)
    if api_key:
        os.environ["NVD_API_KEY"] = api_key
    out, err = io.StringIO(), io.StringIO()
    try:
        with (
            patch.object(sys, "argv", ["dependency_security_check.py", "brew", "wget", "1.0.0"]),
            patch.object(
                dsc, "_urlopen", side_effect=lambda r, timeout=15: (_ for _ in ()).throw(exc)
            ),
            patch.object(dsc.time, "sleep"),
            redirect_stdout(out),
            redirect_stderr(err),
            pytest.raises(SystemExit) as exc_info,
        ):
            dsc.main()
    finally:
        os.environ.pop("NVD_API_KEY", None)
        if saved is not None:
            os.environ["NVD_API_KEY"] = saved
    return exc_info.value.code, json.loads(out.getvalue()), err.getvalue()


def throttle(code=429):
    return urllib.error.HTTPError("https://nvd", code, "Too Many Requests", {}, None)


@pytest.mark.parametrize("code", [403, 429])
def test_throttle_is_flagged_and_explained(code):
    """NVD answers 403 or 429 when the limit is exceeded; both must be named."""
    rc, out, err = run_main(throttle(code))
    assert rc == 2, "still fails closed"
    assert out["status"] == "unknown"
    assert out["rate_limited"] is True
    assert "NVD_API_KEY" in err, f"the hint must name the fix:\n{err}"
    assert "nvd.nist.gov/developers/request-an-api-key" in err


def test_no_hint_when_a_key_is_already_set():
    """Telling someone who has a key to get a key is noise."""
    rc, out, err = run_main(throttle(), api_key="11111111-2222-3333-4444-555555555555")
    assert out["rate_limited"] is True, "still a throttle, still worth recording"
    assert "NVD_API_KEY" not in err, f"hint should be suppressed:\n{err}"


def test_ordinary_failure_is_not_labelled_a_rate_limit():
    """An offline machine is not a throttle — the advice would be wrong."""
    rc, out, err = run_main(urllib.error.URLError("connection refused"))
    assert rc == 2
    assert out["rate_limited"] is False
    assert "NVD_API_KEY" not in err


@pytest.mark.parametrize(
    ("nvd_findings", "expected"),
    [
        ([], "clean"),
        (
            [
                {
                    "source": "NIST NVD",
                    "id": "CVE-2099-1",
                    "severity": "HIGH",
                    "score": 7.5,
                    "summary": "x",
                }
            ],
            "vulnerable",
        ),
    ],
    ids=["clean", "vulnerable"],
)
def test_flag_is_present_on_every_status(nvd_findings, expected):
    """The wrappers read one field; it must exist regardless of verdict."""
    out_io = io.StringIO()
    with (
        patch.object(sys, "argv", ["x", "pip", "django", "9.9.9"]),
        patch.object(dsc, "query_osv", lambda *a, **k: []),
        patch.object(dsc, "query_github", lambda *a, **k: []),
        patch.object(dsc, "query_nvd", lambda *a, **k: list(nvd_findings)),
        redirect_stdout(out_io),
        redirect_stderr(io.StringIO()),
        pytest.raises(SystemExit),
    ):
        dsc.main()
    payload = json.loads(out_io.getvalue())
    assert payload["status"] == expected
    assert "rate_limited" in payload, f"{expected} payload is missing the field"


# --------------------------------------------------------------------------
# Wrapper end: the signal has to survive `2>/dev/null`
# --------------------------------------------------------------------------


def make_stub(tmp_path, rate_limited):
    """A scanner stand-in that exits 2 with the unknown-result payload."""
    stub = tmp_path / "stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "print('this stderr is discarded by the wrapper', file=sys.stderr)\n"
        "json.dump({'status': 'unknown', 'package': sys.argv[2], 'sources_ok': 0,\n"
        "           'sources_total': 1, 'sources_failed': ['NIST NVD'],\n"
        f"           'rate_limited': {rate_limited}, 'vulnerabilities': []}}, sys.stdout)\n"
        "sys.exit(2)\n"
    )
    stub.chmod(0o755)
    return stub


@pytest.fixture
def brew_env(tmp_path, monkeypatch):
    fixture_dir = tmp_path / "brew_responses"
    fixture_dir.mkdir()
    monkeypatch.setenv("MOCK_BREW_DIR", str(fixture_dir))
    monkeypatch.setenv(
        "PATH", f"{Path(__file__).parent / 'fixtures' / 'mock_brew'}:{os.environ['PATH']}"
    )
    monkeypatch.setenv("GH_TOKEN", "test-token")
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    api = tmp_path / "api"
    api.mkdir()
    monkeypatch.setenv("MOCK_FORMULAE_API_DIR", str(api))
    commits = tmp_path / "commits"
    commits.mkdir()
    (commits / "_default.json").write_text(
        json.dumps([{"commit": {"committer": {"date": "2020-01-01T00:00:00Z"}}}])
    )
    monkeypatch.setenv("MOCK_COMMITS_API_DIR", str(commits))
    (fixture_dir / "outdated.json").write_text(
        json.dumps(
            {
                "formulae": [
                    {"name": "wget", "installed_versions": ["1.0"], "current_version": "2.0"}
                ],
                "casks": [],
            }
        )
    )
    (fixture_dir / "info_wget.json").write_text(
        json.dumps({"formulae": [{"name": "wget", "versions": {"stable": "2.0"}}], "casks": []})
    )
    (fixture_dir / "deps_wget.txt").write_text("")
    return fixture_dir


def run_wrapper(script, args, stub, env_extra=None):
    env = os.environ.copy()
    env["DEPENDENCY_SECURITY_CHECK"] = str(stub)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        input="n\n",
    )


def test_upgrade_surfaces_the_note_through_suppressed_stderr(brew_env, tmp_path):
    """The wrapper drops the scanner's stderr, so it must read the JSON flag."""
    result = run_wrapper(SAFE_UPGRADE, [], make_stub(tmp_path, "True"))
    assert "[skip] wget" in result.stdout
    assert "rate-limited this run" in result.stdout, f"no note:\n{result.stdout}"
    assert "NVD_API_KEY" in result.stdout
    assert "this stderr is discarded" not in result.stdout, "stderr genuinely is suppressed"


def test_upgrade_stays_quiet_for_an_ordinary_failure(brew_env, tmp_path):
    result = run_wrapper(SAFE_UPGRADE, [], make_stub(tmp_path, "False"))
    assert "[skip] wget" in result.stdout
    assert "rate-limited this run" not in result.stdout


def test_upgrade_stays_quiet_when_a_key_is_set(brew_env, tmp_path):
    result = run_wrapper(
        SAFE_UPGRADE, [], make_stub(tmp_path, "True"), env_extra={"NVD_API_KEY": "abc"}
    )
    assert "rate-limited this run" not in result.stdout


def test_install_surfaces_the_note_too(brew_env, tmp_path):
    """Both entry points hit the same limit; both must explain it."""
    result = run_wrapper(SAFE_INSTALL, ["wget"], make_stub(tmp_path, "True"))
    assert "rate-limited this run" in result.stdout, f"no note:\n{result.stdout}"
    assert "NVD_API_KEY" in result.stdout


def make_dep_scenario(fixture_dir):
    """wget with one incoming dep, so BOTH check paths run in a single invocation."""
    (fixture_dir / "deps_wget.txt").write_text("libfoo\n")
    (fixture_dir / "info_libfoo.json").write_text(
        json.dumps({"formulae": [{"name": "libfoo", "versions": {"stable": "2.0"}}], "casks": []})
    )
    (fixture_dir / "list_libfoo.txt").write_text("libfoo 1.0\n")


def test_note_appears_once_even_when_both_paths_are_throttled(brew_env, tmp_path):
    """Two call sites, one message.

    Reaching both takes care: a throttled top-level package is EXCLUDED from
    CLEAN_PKGS, and the dependency check only runs when that list is non-empty.
    So the scenario needs one package throttled (firing the skip-summary note)
    AND a second, clean package whose dependency is throttled (firing the
    dep-summary note). Without an idempotence guard the user reads the same
    four-line paragraph twice.
    """
    (brew_env / "outdated.json").write_text(
        json.dumps(
            {
                "formulae": [
                    {"name": "pkga", "installed_versions": ["1.0"], "current_version": "2.0"},
                    {"name": "pkgb", "installed_versions": ["1.0"], "current_version": "2.0"},
                ],
                "casks": [],
            }
        )
    )
    for name in ("pkga", "pkgb", "libfoo"):
        (brew_env / f"info_{name}.json").write_text(
            json.dumps({"formulae": [{"name": name, "versions": {"stable": "2.0"}}], "casks": []})
        )
    (brew_env / "deps_pkga.txt").write_text("")
    (brew_env / "deps_pkgb.txt").write_text("libfoo\n")
    (brew_env / "list_libfoo.txt").write_text("libfoo 1.0\n")

    # Throttle pkga (top-level) and libfoo (dependency); pkgb resolves clean so
    # the dependency stage is reached at all.
    stub = tmp_path / "two_paths.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "pkg = sys.argv[2]\n"
        "if pkg in ('pkga', 'libfoo'):\n"
        "    json.dump({'status': 'unknown', 'package': pkg, 'sources_ok': 0,\n"
        "               'sources_total': 1, 'sources_failed': ['NIST NVD'],\n"
        "               'rate_limited': True, 'vulnerabilities': []}, sys.stdout)\n"
        "    sys.exit(2)\n"
        "json.dump({'status': 'clean', 'package': pkg, 'sources_ok': 1,\n"
        "           'sources_total': 1, 'sources_failed': [], 'rate_limited': False,\n"
        "           'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)

    result = run_wrapper(SAFE_UPGRADE, [], stub)
    assert "[skip] pkga" in result.stdout, result.stdout
    assert "[skip-dep] libfoo" in result.stdout, "both paths must actually run"
    occurrences = result.stdout.count("rate-limited this run")
    assert occurrences == 1, f"expected exactly one note, got {occurrences}:\n{result.stdout}"


def test_install_notes_a_dependency_only_throttle(brew_env, tmp_path):
    """The note must not depend on a top-level package also being skipped.

    brew-safe-install only called note_rate_limit inside the SKIPPED_PKGS block,
    so a run where the named package resolved fine but a dependency was
    throttled printed nothing at all.
    """
    make_dep_scenario(brew_env)
    stub = tmp_path / "dep_only.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "pkg = sys.argv[2]\n"
        "if pkg == 'libfoo':\n"
        "    json.dump({'status': 'unknown', 'package': pkg, 'sources_ok': 0,\n"
        "               'sources_total': 1, 'sources_failed': ['NIST NVD'],\n"
        "               'rate_limited': True, 'vulnerabilities': []}, sys.stdout)\n"
        "    sys.exit(2)\n"
        "json.dump({'status': 'clean', 'package': pkg, 'sources_ok': 1,\n"
        "           'sources_total': 1, 'sources_failed': [], 'rate_limited': False,\n"
        "           'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    result = run_wrapper(SAFE_INSTALL, ["wget"], stub)
    assert "[skip-dep] libfoo" in result.stdout, result.stdout
    assert result.stdout.count("rate-limited this run") == 1, (
        f"a dependency-only throttle must still be explained:\n{result.stdout}"
    )
