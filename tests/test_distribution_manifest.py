"""Guard the distribution file lists.

The two curl-based routes each have a list of files that constitute a release:

  * `install.sh` (fresh install) downloads exactly the files named in the
    `SHA256SUMS` manifest and verifies each one — the manifest IS its file list.
  * `brew-safe-update` (self-updater) carries a hardcoded `for file in …; do`
    loop.

They MUST agree with each other and include every file the scripts need at
runtime — a missing runtime module ships a broken install. This bit us once:
`bottle_resolver.py` was added to `install.sh` but not to `brew-safe-update`, so
`brew safe-update` produced an install that failed closed at `brew safe-upgrade`
startup ("bottle SHA resolver not found").
"""

import re
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
    """The install.sh download set = the filenames listed in SHA256SUMS."""
    files = set()
    for line in MANIFEST.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        # `<hash>  <filename>` (GNU/`shasum -a 256` format).
        files.add(line.split()[-1])
    return files


def _for_loop_files(script: Path) -> set[str]:
    """Extract the file list from a `for file in <...>; do` line."""
    text = script.read_text()
    match = re.search(r"for file in (.+?); do", text)
    assert match, f"no `for file in ...; do` loop found in {script.name}"
    return set(match.group(1).split())


def test_install_and_update_lists_match():
    """The fresh-install (manifest) and self-update file lists must be identical,
    so a file added to one is never forgotten in the other."""
    assert _manifest_files() == _for_loop_files(SAFE_UPDATE)


def test_install_list_includes_all_runtime_files():
    assert _manifest_files() >= REQUIRED_RUNTIME_FILES


def test_update_list_includes_all_runtime_files():
    assert _for_loop_files(SAFE_UPDATE) >= REQUIRED_RUNTIME_FILES


def test_required_runtime_files_exist_in_repo():
    """Every file we promise to distribute must actually be in the repo."""
    for name in REQUIRED_RUNTIME_FILES:
        assert (REPO / name).is_file(), f"{name} listed for distribution but absent from repo"
