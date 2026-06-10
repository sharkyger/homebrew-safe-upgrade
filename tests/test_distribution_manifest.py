"""Guard the distribution file list.

Both curl-based routes now derive their file set from ONE source — the
`SHA256SUMS` manifest:

  * `install.sh` (fresh install) downloads exactly the files named in
    `SHA256SUMS` and verifies each one.
  * `brew-safe-update` (self-updater) does the same: it fetches `SHA256SUMS` and
    downloads + verifies exactly the files it names.

Because the manifest is the single source for both routes, the two can no longer
drift apart (the failure that once stranded `bottle_resolver.py`: it was added to
one route's list but not the other's). These tests pin that invariant: the
manifest must include every runtime file, those files must exist, and the
updater must stay manifest-driven (no reintroduced hardcoded file list).
"""

from pathlib import Path

REPO = Path(__file__).parent.parent
MANIFEST = REPO / "SHA256SUMS"
SAFE_UPDATE = REPO / "brew-safe-update"

# Files the installed scripts load at runtime and therefore must be distributed.
REQUIRED_RUNTIME_FILES = {
    "brew-safe-upgrade",
    "brew-safe-install",
    "brew-safe-update",
    "dependency_security_check.py",
    "bottle_resolver.py",  # hard dependency — brew-safe-* fail closed without it
    "cask_nvd_map.py",  # imported by dependency_security_check.py
    "VERSION",  # read at runtime by --version self-diagnosis (single-source version)
}


def _manifest_files() -> set[str]:
    """The release file set = the filenames listed in SHA256SUMS."""
    files = set()
    for line in MANIFEST.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        # `<hash>  <filename>` (GNU/`shasum -a 256` format).
        files.add(line.split()[-1])
    return files


def test_manifest_includes_all_runtime_files():
    """The manifest — the single download list for BOTH routes — must name every
    file the installed scripts need at runtime."""
    assert _manifest_files() >= REQUIRED_RUNTIME_FILES


def test_required_runtime_files_exist_in_repo():
    """Every file we promise to distribute must actually be in the repo."""
    for name in REQUIRED_RUNTIME_FILES:
        assert (REPO / name).is_file(), f"{name} listed for distribution but absent from repo"


def test_updater_is_manifest_driven():
    """Source-level guard: the self-updater must fetch SHA256SUMS and drive its
    download from it — never a reintroduced hardcoded `for file in …` list, which
    is exactly what drifted from install.sh and stranded a helper. If someone
    brings back a hardcoded runtime list, fail here."""
    text = SAFE_UPDATE.read_text()
    assert 'fetch_file "SHA256SUMS"' in text, "updater must fetch the release manifest"
    assert "read -r _ filename" in text, "updater must iterate the manifest, not a fixed list"
    # The old, drift-prone hardcoded loop must not return.
    assert "for file in brew-safe-upgrade brew-safe-install" not in text
