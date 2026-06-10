"""Tests for the self-healing, checksum-verified brew-safe-update.

Two guarantees are exercised here:

  1. Self-heal + single-run convergence (v0.2.2): the updater carries a file
     list/logic; it updates ITSELF first and re-execs the fresh copy, so a single
     `brew safe-update` converges even when the installed updater is older. This
     once stranded `bottle_resolver.py` and made `brew safe-upgrade` fail closed.

  2. Pinned + checksum-verified (v0.2.5): the updater fetches the release
     SHA256SUMS manifest and verifies every staged file against it before the
     atomic swap. A tampered/missing file aborts with the install UNTOUCHED.

The production code fetches via curl from a pinned release tag; these tests
inject files through the `MOCK_UPDATE_SOURCE_DIR` hook (no network) and use
`BREW_SAFE_INSTALL_DIR` exactly as the re-exec path does. The mock source dir
includes a SHA256SUMS generated from its own files, mirroring a real release.
"""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
SAFE_UPDATE = REPO / "brew-safe-update"

# The files a release manifest lists (the script-install set).
ALL_FILES = [
    "brew-safe-upgrade",
    "brew-safe-install",
    "brew-safe-update",
    "dependency_security_check.py",
    "bottle_resolver.py",
    "cask_nvd_map.py",
    "VERSION",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest(source_dir: Path):
    """Generate SHA256SUMS over the staged source files (sha256sum format)."""
    lines = [f"{_sha256(source_dir / name)}  {name}\n" for name in ALL_FILES]
    (source_dir / "SHA256SUMS").write_text("".join(lines))


def _make_source(source_dir: Path):
    """Populate the mock 'latest release': real updater + stub payloads + manifest."""
    shutil.copy(SAFE_UPDATE, source_dir / "brew-safe-update")
    for name in ALL_FILES:
        if name != "brew-safe-update":
            (source_dir / name).write_text(f"# latest {name}\n")
    _write_manifest(source_dir)


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


def test_single_run_converges_via_self_heal(tmp_path):
    """An OLDER installed updater (content differs from the release) must still
    converge in ONE run: it self-updates to the verified fresh updater, re-execs,
    and the manifest-driven download installs every release file."""
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _make_source(source_dir)

    # Install an "old" updater whose content differs from the release copy, so the
    # self-heal stage detects the change and re-execs the fresh, verified copy.
    old = SAFE_UPDATE.read_text() + "\n# stale marker — older installed updater\n"
    (install_dir / "brew-safe-update").write_text(old)
    assert not (install_dir / "bottle_resolver.py").exists()

    result = _run(install_dir, source_dir)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "All tools updated." in result.stdout, result.stdout
    # Converged in a single invocation: every release file is now present...
    for name in ALL_FILES:
        assert (install_dir / name).exists(), f"{name} missing\n{result.stdout}"
    assert (install_dir / "bottle_resolver.py").read_text() == "# latest bottle_resolver.py\n"
    # ...and the updater itself was upgraded to the release copy (stale marker gone).
    assert "stale marker" not in (install_dir / "brew-safe-update").read_text()


def test_no_change_run_updates_without_reexec_loop(tmp_path):
    """When the installed updater already matches the release, it must still
    verify + update every file and finish — no infinite re-exec."""
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _make_source(source_dir)
    shutil.copy(SAFE_UPDATE, install_dir / "brew-safe-update")  # identical to release

    result = _run(install_dir, source_dir, timeout=15)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "All tools updated." in result.stdout
    for name in ALL_FILES:
        assert (install_dir / name).exists()


def test_tampered_file_aborts_with_install_untouched(tmp_path):
    """A file whose content does not match the manifest must abort the update,
    fail-closed, leaving the existing install UNTOUCHED (no partial swap)."""
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _make_source(source_dir)
    shutil.copy(SAFE_UPDATE, install_dir / "brew-safe-update")  # identical -> no re-exec

    # Pre-seed a sentinel file in the install dir to prove it is not overwritten.
    sentinel = install_dir / "dependency_security_check.py"
    sentinel.write_text("# PRE-EXISTING — must survive a failed update\n")

    # Tamper: change a payload AFTER the manifest was generated, so its hash no
    # longer matches the manifest entry.
    (source_dir / "dependency_security_check.py").write_text("# TAMPERED CONTENT\n")

    result = _run(install_dir, source_dir)

    assert result.returncode != 0, result.stdout + result.stderr
    assert "checksum verification failed" in result.stdout
    assert "UNCHANGED" in result.stdout
    # Fail-closed: the pre-existing file is intact, the tampered content is NOT in.
    assert sentinel.read_text() == "# PRE-EXISTING — must survive a failed update\n"
    # No staging crumbs left behind in the install dir.
    assert not list(install_dir.glob(".safe-update.*"))


def test_missing_manifest_entry_aborts(tmp_path):
    """If the manifest omits a user-facing command, the completeness floor must
    abort (a truncated/corrupt manifest can't yield a 'successful' partial)."""
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _make_source(source_dir)
    shutil.copy(SAFE_UPDATE, install_dir / "brew-safe-update")

    # Drop brew-safe-install from the manifest.
    sums = source_dir / "SHA256SUMS"
    kept = [ln for ln in sums.read_text().splitlines() if not ln.endswith("  brew-safe-install")]
    sums.write_text("\n".join(kept) + "\n")

    result = _run(install_dir, source_dir)

    assert result.returncode != 0, result.stdout + result.stderr
    assert "missing 'brew-safe-install'" in result.stdout


def test_updater_keeps_self_heal_stage():
    """Source-level guard: the shipped updater must keep the self-update/re-exec
    stage AND the checksum-verification gate, or those guarantees silently
    regress without a failing functional test."""
    text = SAFE_UPDATE.read_text()
    assert "BREW_SAFE_UPDATE_REEXECED" in text
    assert "exec bash" in text
    assert "verify_checksums" in text
    assert "verify_one" in text
