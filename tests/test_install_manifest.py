"""Supply-chain integrity guards for the v0.2.4 script-installer hardening.

Incident class -> regression test. These pin the invariants the hardened
`install.sh` relies on, so a future change can't silently break the integrity
chain or reintroduce the version-drift that let a stale/wrong install go
unnoticed:

  * CHECKSUMS CURRENT: every hash in SHA256SUMS matches the file it names, and
    the manifest is exactly the runtime install-set. A stale manifest would make
    install.sh abort (fail-closed) for every user — caught here instead of in
    the field.
  * PINNED, NOT MOVING: install.sh must download from an immutable release tag,
    never `main`. A curl|bash user must get one published release, not whatever
    is on main at that instant.
  * REF == VERSION: install.sh's pinned tag tracks the VERSION file, so the
    release bump can't point the installer at the wrong (or a non-existent) tag.
  * VERSION SINGLE-SOURCE: pyproject's version must equal the VERSION file.
    They drifted (pyproject lagged at 0.2.2 while VERSION was 0.2.3) because the
    release bump only touched VERSION — this test kills that drift class.
"""

import hashlib
import re
import tomllib
from pathlib import Path

REPO = Path(__file__).parent.parent
MANIFEST = REPO / "SHA256SUMS"
INSTALL_SH = REPO / "install.sh"
VERSION_FILE = REPO / "VERSION"
PYPROJECT = REPO / "pyproject.toml"

EXPECTED_INSTALL_SET = {
    "VERSION",
    "bottle_resolver.py",
    "brew-safe-install",
    "brew-safe-update",
    "brew-safe-upgrade",
    "cask_nvd_map.py",
    "dependency_security_check.py",
}


def _manifest_entries() -> list[tuple[str, str]]:
    """Parse SHA256SUMS into (expected_hash, filename) pairs."""
    entries = []
    for line in MANIFEST.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        digest, filename = line.split()
        entries.append((digest, filename))
    return entries


# ----------------------------- manifest integrity -----------------------------


def test_manifest_hashes_match_files():
    """Every hash in SHA256SUMS must match the current file content. If this
    fails, run scripts/gen-sha256sums.sh — the manifest is stale and install.sh
    would fail closed for everyone."""
    for expected, filename in _manifest_entries():
        path = REPO / filename
        assert path.is_file(), f"{filename} in SHA256SUMS but missing from repo"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected, f"SHA256SUMS stale for {filename} — regenerate it"


def test_manifest_is_exactly_the_install_set():
    """No extra and no missing files — the manifest is the install contract."""
    assert {f for _, f in _manifest_entries()} == EXPECTED_INSTALL_SET


def test_manifest_has_no_path_components():
    """install.sh refuses path-bearing names; the committed manifest must comply."""
    for _, filename in _manifest_entries():
        assert "/" not in filename and not filename.startswith("."), filename


# --------------------------- pinned, not a moving branch ----------------------


def test_install_sh_pins_a_tag_not_main():
    """install.sh must resolve its download ref from a pinned tag, never `main`.
    Guards against regressing to `.../homebrew-safe-upgrade/main` for the files."""
    text = INSTALL_SH.read_text()
    # The raw base must be parameterised by $REF, not hardcoded to a branch.
    assert "/${REF}" in text, "install.sh REPO_RAW is not pinned to $REF"
    assert re.search(r'PINNED_REF="v\d+\.\d+\.\d+"', text), "no pinned semver tag in install.sh"
    # The only `…/main` allowed is in the curl|bash bootstrap hint comments, not
    # the file-fetch base. Assert no fetch base ends in `/main`.
    assert 'homebrew-safe-upgrade/main"' not in text, "install.sh still fetches files from main"


def test_install_sh_pinned_ref_matches_version():
    """The pinned tag must track the VERSION file (release bump touches both)."""
    version = VERSION_FILE.read_text().strip()
    text = INSTALL_SH.read_text()
    match = re.search(r'PINNED_REF="(v[^"]+)"', text)
    assert match, "PINNED_REF not found in install.sh"
    assert match.group(1) == f"v{version}", (
        f"install.sh PINNED_REF={match.group(1)} but VERSION={version}"
    )


# --------------------------- version single-source ----------------------------


def test_pyproject_version_matches_version_file():
    version = VERSION_FILE.read_text().strip()
    with PYPROJECT.open("rb") as fh:
        pyproject = tomllib.load(fh)
    assert pyproject["project"]["version"] == version, (
        "pyproject version drifted from the VERSION file — keep them in lockstep"
    )
