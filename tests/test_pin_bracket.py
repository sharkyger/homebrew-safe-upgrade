"""The [s] pin/unpin bracket must never leave OUR pins behind.

brew-safe-upgrade `brew pin`s every excluded formula around the upgrade so brew
cannot drag a flagged dependency in under something else. That used to be a
straight-line pin → upgrade → unpin with no trap: a Ctrl-C or crash anywhere in
between left every excluded formula pinned, silently. Plain `brew upgrade` then
skips pinned formulae without saying so, so the user sat on pinned VULNERABLE
packages indefinitely while believing they upgrade normally — fail-open.

Observed ordering on the 2026-08-22 acceptance run: the Blocked set is released
first, the Held set last, so an interrupt late in the UNPIN LOOP strands exactly
the packages that were only waiting out a timer. That is the case these tests
deliver the signal in — not merely "during the upgrade".

The assertion in every case is the one a user would make afterwards:
`brew list --pinned` is empty (or holds only what the user pinned themselves).
"""

import os
import signal
import subprocess
import time
from pathlib import Path

from tests.test_partial_upgrade import (
    SAFE_UPGRADE,
    run_upgrade,
    scenario,
)


def pinned(fixture_dir: Path) -> set[str]:
    d = fixture_dir / "pinned"
    return set(os.listdir(d)) if d.is_dir() else set()


def _start(env_extra: dict) -> subprocess.Popen:
    env = os.environ.copy()
    env.update(env_extra)
    # Own process group, so the SIGINT reaches bash AND the brew child it is
    # waiting on — exactly what a terminal Ctrl-C does.
    return subprocess.Popen(
        ["bash", str(SAFE_UPGRADE), "--skip-unsafe"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )


def _wait_for_log(log: Path, needle: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log.exists() and needle in log.read_text():
            return
        time.sleep(0.05)
    raise AssertionError(f"{needle!r} never appeared in {log}")


def _interrupt_and_collect(proc: subprocess.Popen) -> tuple[str, str]:
    os.killpg(proc.pid, signal.SIGINT)
    out, err = proc.communicate(input="y\n", timeout=30)
    return out, err


def test_clean_run_leaves_nothing_pinned(brew_env, tmp_path):
    """Baseline: the happy path pins during and unpins after."""
    stub = scenario(brew_env, tmp_path)
    pin_log = tmp_path / "pin.log"
    result = run_upgrade(
        ["--skip-unsafe"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_PIN_LOG": str(pin_log)},
        input_text="y\n",
    )
    assert result.returncode == 0, result.stderr
    assert "pin taglib" in pin_log.read_text()
    assert pinned(brew_env) == set(), "a clean run must end with brew list --pinned empty"
    assert "Interrupted" not in result.stderr


def test_preexisting_user_pin_is_left_alone(brew_env, tmp_path):
    """Pins the user set themselves are not ours to release."""
    stub = scenario(brew_env, tmp_path)
    (brew_env / "pinned").mkdir()
    (brew_env / "pinned" / "taglib").touch()  # user pinned the flagged dep already
    (brew_env / "pinned" / "mine").touch()  # and something unrelated
    pin_log = tmp_path / "pin.log"
    result = run_upgrade(
        ["--skip-unsafe"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_PIN_LOG": str(pin_log)},
        input_text="y\n",
    )
    assert result.returncode == 0, result.stderr
    log = pin_log.read_text()
    assert "pin player" in log and "unpin player" in log
    assert "pin taglib" not in log, "an already-pinned formula must not be re-pinned"
    assert "unpin taglib" not in log, "a user's pin must survive the run"
    assert pinned(brew_env) == {"taglib", "mine"}


def test_sigint_during_the_unpin_loop_releases_the_remainder(brew_env, tmp_path):
    """THE case from the acceptance run: interrupt while unpinning.

    Each mock unpin sleeps, so the signal lands after the first unpin has
    started and before the rest ran. Without the trap the remainder stayed
    pinned forever.
    """
    stub = scenario(brew_env, tmp_path)
    pin_log = tmp_path / "pin.log"
    proc = _start(
        {
            "DEPENDENCY_SECURITY_CHECK": str(stub),
            "MOCK_PIN_LOG": str(pin_log),
            "MOCK_BREW_UNPIN_SLEEP": "3",
        }
    )
    try:
        proc.stdin.write("y\n")
        proc.stdin.flush()
        _wait_for_log(pin_log, "unpin ")
        time.sleep(0.3)  # inside the first unpin's sleep
        assert pinned(brew_env), "precondition: something must still be pinned mid-loop"
        out, err = _interrupt_and_collect(proc)
    finally:
        if proc.poll() is None:
            # The whole group: proc.kill() reaches only bash, and a sleeping
            # mock brew child would keep editing the shared pin store.
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=5)
    assert proc.returncode == 130, f"rc={proc.returncode}\n{out}\n{err}"
    assert "releasing the pins brew-safe-upgrade set" in err, err
    assert pinned(brew_env) == set(), f"pins stranded after SIGINT: {pinned(brew_env)}\n{err}"


def test_sigint_during_the_upgrade_releases_every_pin(brew_env, tmp_path):
    """Interrupt while brew upgrade is running: nothing was unpinned yet."""
    stub = scenario(brew_env, tmp_path)
    pin_log = tmp_path / "pin.log"
    proc = _start(
        {
            "DEPENDENCY_SECURITY_CHECK": str(stub),
            "MOCK_PIN_LOG": str(pin_log),
            "MOCK_BREW_UPGRADE_SLEEP": "5",
        }
    )
    try:
        proc.stdin.write("y\n")
        proc.stdin.flush()
        _wait_for_log(pin_log, "pin player")
        time.sleep(0.5)  # brew upgrade is now sleeping
        assert {"player", "taglib"} <= pinned(brew_env)
        out, err = _interrupt_and_collect(proc)
    finally:
        if proc.poll() is None:
            # The whole group: proc.kill() reaches only bash, and a sleeping
            # mock brew child would keep editing the shared pin store.
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate(timeout=5)
    assert proc.returncode == 130, f"rc={proc.returncode}\n{out}\n{err}"
    assert "releasing the pins brew-safe-upgrade set: player taglib" in err.replace(
        "  ", " "
    ) or "releasing the pins brew-safe-upgrade set: taglib player" in err.replace("  ", " ")
    assert pinned(brew_env) == set(), f"pins stranded after SIGINT: {pinned(brew_env)}\n{err}"
