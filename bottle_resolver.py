#!/usr/bin/env python3
"""Resolve the host-appropriate bottle SHA256 from a Homebrew formula JSON.

Why this exists
---------------
The SHA-verify step compares the locally-installed bottle SHA (from
``brew info --json=v2``) against the canonical one (from
``formulae.brew.sh/api/formula/<f>.json``). The previous extractors each took
the *first* bottle tag in dict-iteration order. ``brew info`` and
formulae.brew.sh enumerate the ``bottle.stable.files`` tags in different
orders, so on an Intel (x86_64) host the local side often resolved the genuine
Intel bottle while the canonical side resolved the arm64 bottle — comparing two
real-but-different-arch SHAs and flagging EVERY bottle as ``[BLOCKED] SHA
mismatch``. Fails safe, but the alert fatigue trains users to ignore the
warning, so a real tamper later gets dismissed.

The fix: select the bottle tag matching the HOST's actual architecture and
macOS codename, applied identically to both payloads, so a genuine same-bottle
comparison resolves to the same tag and matches.

Homebrew bottle tag scheme (important — it is NOT a uniform ``{arch}_{os}``):
  * Apple Silicon macOS : ``arm64_<codename>``  (e.g. ``arm64_tahoe``)
  * Intel macOS         : ``<codename>``         (bare, e.g. ``sonoma``)
  * Linux               : ``x86_64_linux`` / ``arm64_linux``

Homebrew does not always build a bottle for the host's exact (often newest) OS;
it then serves the bottle under an older same-arch codename tag (e.g. an Intel
host on ``tahoe`` is served the ``sonoma`` bottle). So when the exact tag is
absent we fall back to the newest *available same-arch* macOS codename — never
across architectures.

The host can be forced for tests via ``BREW_SAFE_HOST_ARCH`` (``arm64`` /
``x86_64``) and ``BREW_SAFE_HOST_OS`` (a codename like ``sonoma`` or a macOS
major version like ``14``). This makes the Intel false-positive reproducible
and the fix verifiable on any machine (including arm64 dev hosts and CI Linux).
"""

import json
import os
import platform
import sys

# macOS codenames, newest -> oldest, keyed by product major version.
_CODENAMES = [
    (26, "tahoe"),
    (15, "sequoia"),
    (14, "sonoma"),
    (13, "ventura"),
    (12, "monterey"),
    (11, "big_sur"),
    (10, "catalina"),
]
_NAME_TO_VER = {name: ver for ver, name in _CODENAMES}


def _ver_to_codename(major):
    """Map a macOS major version to its codename.

    Exact match preferred; otherwise the newest codename at or below the given
    version (so a host OS newer than this table still resolves sanely)."""
    for ver, name in _CODENAMES:
        if ver == major:
            return name
    for ver, name in _CODENAMES:  # _CODENAMES is newest-first
        if ver < major:
            return name
    return None


def detect_arch():
    """Host CPU architecture, normalized to 'arm64' or 'x86_64'."""
    forced = os.environ.get("BREW_SAFE_HOST_ARCH")
    if forced:
        forced = forced.strip()
        if forced in ("aarch64", "arm64"):
            return "arm64"
        if forced in ("x86_64", "amd64", "x64"):
            return "x86_64"
        return forced
    machine = platform.machine()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine in ("x86_64", "amd64", "x64"):
        return "x86_64"
    return machine


def detect_codename():
    """Host macOS codename, or None on non-macOS hosts."""
    forced = os.environ.get("BREW_SAFE_HOST_OS")
    if forced:
        forced = forced.strip()
        if forced.isdigit():
            return _ver_to_codename(int(forced))
        return forced
    product = platform.mac_ver()[0]  # "" on non-macOS
    if not product:
        return None
    try:
        major = int(product.split(".")[0])
    except (ValueError, IndexError):
        return None
    return _ver_to_codename(major)


def tag_preferences(arch, codename):
    """Ordered list of bottle tags to try for this host, most preferred first.

    arm64 macOS : arm64_<codename>, arm64_<older>, ..., arm64_linux
    x86_64 macOS: <codename>, <older>, ..., x86_64_linux  (Intel = bare codename)
    Linux / unknown OS: only the arch's Linux tag.

    Older same-arch macOS codenames cover the case where Homebrew did not build
    a bottle for the host's exact OS. The ladder never crosses architecture, and
    the macOS codename ladder is only used when we actually know we're on macOS
    (a known codename) — otherwise a Linux host could wrongly prefer a macOS
    bottle SHA over its own ``{arch}_linux`` bottle (the same cross-platform
    false-positive this resolver exists to prevent).
    """
    linux_tag = "arm64_linux" if arch == "arm64" else "x86_64_linux"
    host_ver = _NAME_TO_VER.get(codename) if codename else None
    if host_ver is None:
        # Not macOS (or an unrecognized forced codename): stay on the same arch.
        return [linux_tag]
    ladder = [name for ver, name in _CODENAMES if ver <= host_ver]
    # arm64 macOS uses arm64_<codename>; x86_64 macOS uses the bare codename.
    prefs = [f"arm64_{name}" for name in ladder] if arch == "arm64" else list(ladder)
    prefs.append(linux_tag)
    return prefs


def resolve_sha(files, arch, codename):
    """Return the SHA256 for the host-appropriate bottle tag, or None.

    Tries the host preference ladder first (same-arch only). If no same-arch
    tag is present — a degenerate or synthetic formula, never a real Intel/arm64
    comparison — falls back to the lexicographically-first available tag so the
    local and canonical payloads still resolve deterministically (independent of
    JSON key order) and identically to each other.
    """
    if not files:
        return None
    for tag in tag_preferences(arch, codename):
        info = files.get(tag)
        if info and info.get("sha256"):
            return info["sha256"]
    for tag in sorted(files):
        info = files.get(tag)
        if info and info.get("sha256"):
            return info["sha256"]
    return None


def _bottle_files(payload, source):
    """Extract bottle.stable.files from a local (brew info) or canonical payload."""
    if source == "local":
        formulae = payload.get("formulae") or []
        if not formulae:
            return {}
        node = formulae[0]
    else:  # canonical
        node = payload
    return node.get("bottle", {}).get("stable", {}).get("files", {}) or {}


def main(argv):
    # Default to the canonical contract; --source local switches JSON shape and
    # the "silent" output contract the bash callers depend on.
    source = "canonical"
    if "--source" in argv:
        idx = argv.index("--source")
        if idx + 1 < len(argv):
            source = argv[idx + 1]

    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except Exception:
        # local: stay silent (empty -> caller treats as "no local bottle").
        # canonical: emit the PARSE_ERROR sentinel the caller classifies.
        if source == "canonical":
            print("PARSE_ERROR")
        return 0

    files = _bottle_files(payload, source)
    sha = resolve_sha(files, detect_arch(), detect_codename()) if files else None
    if sha:
        print(sha)
    elif source == "canonical":
        print("NO_BOTTLE")
    # local with no bottle: print nothing (preserves the original contract).
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
