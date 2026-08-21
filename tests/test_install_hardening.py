"""Regression tests for the v0.2.2 install-hardening fixes.

Incident -> regression test (non-negotiable). Each test pins a failure that
actually reached a user across releases:

  - STRAND: an update that can't fetch every declared file must fail closed and
    NEVER print "All tools updated" or half-overwrite the install. bottle_resolver.py
    was stranded twice (Intel @0.2.0, Apple Silicon @0.2.1) by a partial update.
  - FAIL-CLOSED: brew-safe-upgrade must refuse to run with actionable guidance
    when a load-bearing helper is missing (the user-visible symptom).
  - SYMLINK/RELOCATION: a symlinked or relocated install must still resolve its
    helpers — bare `dirname "${BASH_SOURCE[0]}"` did not.
  - --version self-diagnosis must report version, install route, and helper
    presence even mid-strand, so a broken install explains itself.
"""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
SAFE_UPGRADE = REPO / "brew-safe-upgrade"
SAFE_UPDATE = REPO / "brew-safe-update"
HELPERS = [
    "dependency_security_check.py",
    "bottle_resolver.py",
    "cask_nvd_map.py",
    "formula_cpe_map.py",
]


def _install_script(dst_dir: Path, *, with_helpers: bool = True, version: str = "9.9.9") -> Path:
    """Lay out a script-style install of brew-safe-upgrade in dst_dir."""
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(SAFE_UPGRADE, dst_dir / "brew-safe-upgrade")
    (dst_dir / "VERSION").write_text(f"{version}\n")
    if with_helpers:
        for h in HELPERS:
            shutil.copy(REPO / h, dst_dir / h)
    return dst_dir / "brew-safe-upgrade"


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False, **kw)


# --------------------------- --version self-diagnosis ---------------------------


def test_version_reports_version_route_and_all_helpers(tmp_path):
    script = _install_script(tmp_path / "bin", version="0.2.2-test")
    r = _run(["bash", str(script), "--version"])
    assert r.returncode == 0, r.stderr
    assert "0.2.2-test" in r.stdout  # read from the single-source VERSION file
    assert "install route: script" in r.stdout
    assert "helpers: all present" in r.stdout


def test_version_reports_missing_helper(tmp_path):
    bind = tmp_path / "bin"
    _install_script(bind, with_helpers=False)
    # Provide only the scanner, so the report must name the missing resolver.
    shutil.copy(REPO / "dependency_security_check.py", bind / "dependency_security_check.py")
    r = _run(["bash", str(bind / "brew-safe-upgrade"), "--version"])
    assert r.returncode == 0, r.stderr
    assert "MISSING" in r.stdout
    assert "bottle_resolver.py" in r.stdout
    assert "brew safe-update" in r.stdout


# --------------------------- fail-closed on missing helper ----------------------


def test_upgrade_fails_closed_on_missing_resolver(tmp_path):
    script = _install_script(tmp_path / "bin", with_helpers=False)
    r = _run(["bash", str(script)], input="n\n")
    assert r.returncode == 2, r.stdout + r.stderr
    assert "bottle SHA resolver not found" in r.stdout
    assert "brew safe-update" in r.stdout  # actionable, not just "same directory"


# --------------------------- symlink / relocation resolution --------------------


def test_symlinked_install_resolves_helpers_in_libexec(tmp_path):
    libexec = _install_script(tmp_path / "libexec").parent
    bind = tmp_path / "bin"
    bind.mkdir()
    link = bind / "brew-safe-upgrade"
    link.symlink_to(os.path.relpath(libexec / "brew-safe-upgrade", bind))
    r = _run(["bash", str(link), "--version"])
    assert r.returncode == 0, r.stderr
    # Symlink resolved -> SCRIPT_DIR is libexec -> helpers found. Bare dirname
    # would have pointed at bin/ and reported them MISSING.
    assert "helpers: all present" in r.stdout, r.stdout


# --------------------------- atomic / fail-closed updater -----------------------


def _make_full_source(src: Path):
    shutil.copy(SAFE_UPDATE, src / "brew-safe-update")
    for name in (
        "brew-safe-upgrade",
        "brew-safe-install",
        "dependency_security_check.py",
        "bottle_resolver.py",
        "cask_nvd_map.py",
        "formula_cpe_map.py",
    ):
        (src / name).write_text(f"# latest {name}\n")
    (src / "VERSION").write_text("9.9.9\n")
    # Release manifest over all shipped files (the updater downloads exactly these
    # and verifies them). Generated last, so a file removed afterwards is still
    # listed — exactly the "manifest names it but the fetch comes up short" case.
    names = [
        "VERSION",
        "bottle_resolver.py",
        "brew-safe-install",
        "brew-safe-update",
        "brew-safe-upgrade",
        "cask_nvd_map.py",
        "formula_cpe_map.py",
        "dependency_security_check.py",
    ]
    lines = [f"{hashlib.sha256((src / n).read_bytes()).hexdigest()}  {n}\n" for n in names]
    (src / "SHA256SUMS").write_text("".join(lines))


def test_update_fails_closed_on_partial_source_and_leaves_install_untouched(tmp_path):
    install_dir = tmp_path / "bin"
    install_dir.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    _make_full_source(src)
    # Simulate a partial/short fetch: one manifest-listed file is unavailable
    # upstream (removed AFTER the manifest was written, so it is still named).
    (src / "cask_nvd_map.py").unlink()

    # Install the CURRENT updater so the run goes straight to the atomic stage
    # (no re-exec — the fetched updater matches the installed one).
    shutil.copy(SAFE_UPDATE, install_dir / "brew-safe-update")
    sentinel = install_dir / "bottle_resolver.py"
    sentinel.write_text("SENTINEL-PRE-EXISTING\n")

    env = os.environ.copy()
    env["MOCK_UPDATE_SOURCE_DIR"] = str(src)
    r = _run(["bash", str(install_dir / "brew-safe-update")], env=env)

    assert r.returncode != 0, r.stdout
    assert "All tools updated." not in r.stdout
    assert "UNCHANGED" in r.stdout  # fail-closed message, deterministic
    # Atomic: the pre-existing install must NOT be half-overwritten.
    assert sentinel.read_text() == "SENTINEL-PRE-EXISTING\n", "install mutated despite failure"
