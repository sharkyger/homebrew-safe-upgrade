"""Tests for the self-healing brew-safe-update.

The self-updater carries a hardcoded file list. When the repo adds a new
required file, an already-installed (older) updater would miss it for one run —
which once stranded `bottle_resolver.py` and made `brew safe-upgrade` fail
closed with "bottle SHA resolver not found". The fix: update the updater itself
first and re-exec the fresh copy, so a single `brew safe-update` converges.

The production code fetches via curl; these tests inject files through the
`MOCK_UPDATE_SOURCE_DIR` hook (no network), and use `BREW_SAFE_INSTALL_DIR`
exactly as the re-exec path does.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
SAFE_UPDATE = REPO / "brew-safe-update"

ALL_FILES = [
    "brew-safe-upgrade",
    "brew-safe-install",
    "brew-safe-update",
    "dependency_security_check.py",
    "bottle_resolver.py",
    "cask_nvd_map.py",
    "VERSION",
]


def _make_source(source_dir: Path):
    """Populate the mock 'latest' source: real updater + stub payload files."""
    shutil.copy(SAFE_UPDATE, source_dir / "brew-safe-update")
    for name in ALL_FILES:
        if name != "brew-safe-update":
            (source_dir / name).write_text(f"# latest {name}\n")


def _run(install_dir: Path, source_dir: Path, timeout: int = 30):
    env = os.environ.copy()
    env["MOCK_UPDATE_SOURCE_DIR"] = str(source_dir)
    return subprocess.run(
        ["bash", str(install_dir / "brew-safe-update")],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )


def test_single_run_converges_when_new_file_added(tmp_path):
    """An installed updater whose list lacks bottle_resolver.py must still fetch
    it in ONE run, because it self-updates to the latest updater first."""
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _make_source(source_dir)

    # Install an "old" updater: the latest script minus bottle_resolver.py in its
    # file list (simulating a version from before that file existed).
    old = SAFE_UPDATE.read_text().replace(" bottle_resolver.py", "")
    assert "bottle_resolver.py" not in re.search(r"for file in (.+?); do", old).group(1)
    (install_dir / "brew-safe-update").write_text(old)
    assert not (install_dir / "bottle_resolver.py").exists()

    result = _run(install_dir, source_dir)

    assert result.returncode == 0, result.stdout + result.stderr
    # Converged in a single invocation: the new file is now present...
    assert (install_dir / "bottle_resolver.py").exists(), result.stdout
    assert (install_dir / "bottle_resolver.py").read_text() == "# latest bottle_resolver.py\n"
    # ...and the updater itself was upgraded to the full-list version.
    assert "bottle_resolver.py" in (install_dir / "brew-safe-update").read_text()


def test_no_change_run_updates_without_reexec_loop(tmp_path):
    """When the installed updater already matches latest, it must still update
    every file and finish — no infinite re-exec."""
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _make_source(source_dir)
    shutil.copy(SAFE_UPDATE, install_dir / "brew-safe-update")  # identical to latest

    result = _run(install_dir, source_dir, timeout=15)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "All tools updated." in result.stdout
    for name in ALL_FILES:
        assert (install_dir / name).exists()


def test_updater_keeps_self_heal_stage():
    """Source-level guard: the shipped updater must keep the self-update/re-exec
    stage, or the single-run convergence guarantee silently regresses."""
    text = SAFE_UPDATE.read_text()
    assert "BREW_SAFE_UPDATE_REEXECED" in text
    assert "exec bash" in text
