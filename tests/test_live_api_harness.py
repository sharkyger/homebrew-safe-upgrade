"""Guards on the live-API test harness in test_dependency_security_check.

That harness turns a timeout into a SKIP, which is the right call for a rate
limit but is also exactly the shape that can hide a real regression. These
tests pin the properties that keep it honest:

  * an offline call still FAILS on a hang — there is no rate limit to forgive
  * an offline hang does not disable live checks for the rest of the run
  * the first live timeout short-circuits the rest instead of re-waiting
  * a successful live call leaves the short-circuit clear
  * a skip is accounted as a non-verdict, so the zero-coverage guard in
    conftest.pytest_sessionfinish can see a fully skipped sweep

Isolation between test modules comes from the autouse fixture below rather than
from a property of the flag itself — it is ordinary module state.
"""

import subprocess
import textwrap
import time

import pytest

import tests.conftest as conftest
import tests.test_dependency_security_check as dsc


@pytest.fixture(autouse=True)
def _reset_short_circuit():
    """The flag is module state; leaving it set would skip unrelated tests."""
    dsc._LIVE_CHECKS_TIMED_OUT = False
    dsc.live_verdicts = 0
    dsc.live_skips = 0
    yield
    dsc._LIVE_CHECKS_TIMED_OUT = False
    dsc.live_verdicts = 0
    dsc.live_skips = 0


@pytest.fixture
def hanging_script(tmp_path, monkeypatch):
    """Point the harness at a checker that never answers."""
    script = tmp_path / "hangs.py"
    script.write_text(
        textwrap.dedent("""
        import time
        time.sleep(30)
    """)
    )
    monkeypatch.setattr(dsc, "SCRIPT", script)
    monkeypatch.setattr(dsc, "CHECKER_TIMEOUT_SECONDS", 1)
    return script


def test_live_timeout_skips_rather_than_erroring(hanging_script):
    with pytest.raises(pytest.skip.Exception) as excinfo:
        dsc.run_checker("pip", "requests")
    msg = str(excinfo.value)
    assert "no verdict" in msg
    # The skip must name the cause, or a throttled CI run is unreadable.
    assert "NVD_API_KEY" in msg


def test_offline_timeout_still_fails(hanging_script):
    """A hang with no databases involved is a bug, not a rate limit."""
    with pytest.raises(subprocess.TimeoutExpired):
        dsc.run_checker("not-a-real-ecosystem", "foo", "1.0", live=False)
    assert dsc._LIVE_CHECKS_TIMED_OUT is False, (
        "an offline hang must not disable live checks for the rest of the run"
    )


def test_first_live_timeout_short_circuits_the_rest(hanging_script):
    with pytest.raises(pytest.skip.Exception):
        dsc.run_checker("pip", "requests")
    assert dsc._LIVE_CHECKS_TIMED_OUT is True

    # The second call must skip WITHOUT spending the budget again. Timing it is
    # the only way to tell a short-circuit from a re-run that also timed out.
    start = time.monotonic()
    with pytest.raises(pytest.skip.Exception) as excinfo:
        dsc.run_checker("pip", "urllib3")
    assert time.monotonic() - start < 0.5
    assert "earlier live check" in str(excinfo.value)


def test_successful_live_call_leaves_the_flag_clear(tmp_path, monkeypatch):
    script = tmp_path / "answers.py"
    script.write_text(
        textwrap.dedent("""
        import json, sys
        json.dump({"status": "clean", "sources_ok": 1, "vulnerabilities": []}, sys.stdout)
        sys.exit(0)
    """)
    )
    monkeypatch.setattr(dsc, "SCRIPT", script)
    exit_code, output = dsc.run_checker("pip", "requests")
    assert exit_code == 0
    assert output["status"] == "clean"
    assert dsc._LIVE_CHECKS_TIMED_OUT is False


def test_skips_are_accounted_as_non_verdicts(hanging_script):
    """The zero-coverage guard can only fire if skips and verdicts are counted."""
    with pytest.raises(pytest.skip.Exception):
        dsc.run_checker("pip", "requests")
    with pytest.raises(pytest.skip.Exception):
        dsc.run_checker("pip", "urllib3")
    assert dsc.live_skips == 2
    assert dsc.live_verdicts == 0


def test_unchecked_exit_two_counts_as_a_skip_not_a_verdict(tmp_path, monkeypatch):
    """Exit 2 is "no source answered" — forgiven, but it is not coverage."""
    script = tmp_path / "unknown.py"
    script.write_text(
        textwrap.dedent("""
        import json, sys
        json.dump({"status": "unknown", "sources_ok": 0}, sys.stdout)
        sys.exit(2)
    """)
    )
    monkeypatch.setattr(dsc, "SCRIPT", script)
    exit_code, _ = dsc.run_checker("pip", "requests")
    assert exit_code == 2
    assert dsc.live_verdicts == 0, "a throttled sweep must not look like coverage"
    assert dsc.live_skips == 1


class _FakeReporter:
    def __init__(self):
        self.lines = []

    def write_sep(self, *a, **k):
        pass

    def write_line(self, line):
        self.lines.append(line)


class _FakeSession:
    def __init__(self):
        self.exitstatus = 0
        reporter = _FakeReporter()

        class _PM:
            def get_plugin(self, name):
                return reporter

        class _Config:
            pluginmanager = _PM()

        self.config = _Config()
        self.reporter = reporter


@pytest.fixture
def guard(monkeypatch):
    """conftest's zero-coverage guard, with the env under our control."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delenv("HOMEBREW_NVD_API_KEY", raising=False)
    return conftest.pytest_sessionfinish


def _run(guard, *, key, verdicts, skips, exitstatus=0, monkeypatch=None):
    if key and monkeypatch is not None:
        monkeypatch.setenv("NVD_API_KEY", "test-key")
    dsc.live_verdicts = verdicts
    dsc.live_skips = skips
    session = _FakeSession()
    session.exitstatus = exitstatus
    guard(session, exitstatus)
    return session


def test_guard_fails_a_keyed_run_with_no_live_coverage(guard, monkeypatch):
    session = _run(guard, key=True, verdicts=0, skips=6, monkeypatch=monkeypatch)
    assert session.exitstatus == 1
    assert "NVD_API_KEY was set" in "\n".join(session.reporter.lines)


def test_guard_forgives_an_unkeyed_run(guard, monkeypatch):
    """No key: skipping is the documented outcome, and forks never get one."""
    session = _run(guard, key=False, verdicts=0, skips=6, monkeypatch=monkeypatch)
    assert session.exitstatus == 0


def test_guard_passes_when_any_verdict_was_reached(guard, monkeypatch):
    session = _run(guard, key=True, verdicts=1, skips=5, monkeypatch=monkeypatch)
    assert session.exitstatus == 0


def test_guard_is_silent_when_nothing_skipped(guard, monkeypatch):
    session = _run(guard, key=True, verdicts=6, skips=0, monkeypatch=monkeypatch)
    assert session.exitstatus == 0


def test_guard_does_not_relabel_an_existing_failure(guard, monkeypatch):
    """A real test failure must keep its own exit status and message."""
    session = _run(guard, key=True, verdicts=0, skips=6, exitstatus=2, monkeypatch=monkeypatch)
    assert session.exitstatus == 2
    assert session.reporter.lines == []
