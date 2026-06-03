"""Unit tests for bottle_resolver.py — host-aware bottle-SHA tag selection.

Regression coverage for the Intel x86_64 false-positive: the canonical-SHA
lookup used to pick the arm64 bottle tag regardless of host arch, so on Intel
Macs every bottle compared an Intel SHA (local) against an arm64 SHA
(canonical) and was wrongly flagged "[BLOCKED] SHA mismatch".

These tests FORCE the host tag (arch + macOS codename) so the bug is
reproducible and the fix verifiable on any machine — an arm64 dev host or CI
Linux included. No live Homebrew API or Intel hardware needed.
"""

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO))

import bottle_resolver as br  # noqa: E402

RESOLVER = REPO / "bottle_resolver.py"

# Distinct 64-char hex SHAs so a wrong-tag pick is unambiguous.
ARM_TAHOE_SHA = "1" * 64
ARM_SONOMA_SHA = "2" * 64
INTEL_SONOMA_SHA = "3" * 64
INTEL_VENTURA_SHA = "4" * 64


def multiarch_files(order):
    """Build a bottle.stable.files dict in a controlled key order.

    `order` is a list of (tag, sha) pairs — order matters because the OLD
    first-tag-wins bug was sensitive to JSON key order.
    """
    return {tag: {"sha256": sha} for tag, sha in order}


# Mirrors the briefing's real-world evidence (composer/ruby): the canonical
# formulae.brew.sh payload lists arm64 tags first; `brew info` on an Intel host
# lists the bare-codename Intel tag first. Same formula, different key order ->
# the old "first tag" logic compared Intel-vs-arm64 and falsely mismatched.
CANON_ORDER = [
    ("arm64_tahoe", ARM_TAHOE_SHA),
    ("arm64_sonoma", ARM_SONOMA_SHA),
    ("sonoma", INTEL_SONOMA_SHA),
    ("ventura", INTEL_VENTURA_SHA),
]
LOCAL_INTEL_ORDER = [
    ("sonoma", INTEL_SONOMA_SHA),
    ("ventura", INTEL_VENTURA_SHA),
    ("arm64_tahoe", ARM_TAHOE_SHA),
    ("arm64_sonoma", ARM_SONOMA_SHA),
]


# ----------------------- resolve_sha: arch correctness -----------------------


def test_intel_sonoma_resolves_intel_sha():
    """Forced x86_64 + sonoma must select the bare 'sonoma' (Intel) bottle."""
    files = multiarch_files(CANON_ORDER)
    assert br.resolve_sha(files, "x86_64", "sonoma") == INTEL_SONOMA_SHA


def test_arm64_tahoe_resolves_arm64_sha():
    """Forced arm64 + tahoe must select 'arm64_tahoe' (the happy path)."""
    files = multiarch_files(CANON_ORDER)
    assert br.resolve_sha(files, "arm64", "tahoe") == ARM_TAHOE_SHA


def test_intel_no_exact_tag_falls_back_to_newest_same_arch_not_arm64():
    """Intel host on an OS with no exact bottle tag falls back to the newest
    available *same-arch* macOS tag — never to an arm64 tag."""
    # Host is x86_64 + tahoe, but there is no Intel 'tahoe' nor 'sequoia' tag;
    # Homebrew serves the Intel bottle under the older 'sonoma' tag.
    files = multiarch_files(
        [
            ("arm64_tahoe", ARM_TAHOE_SHA),
            ("sonoma", INTEL_SONOMA_SHA),
            ("ventura", INTEL_VENTURA_SHA),
        ]
    )
    resolved = br.resolve_sha(files, "x86_64", "tahoe")
    assert resolved == INTEL_SONOMA_SHA
    assert resolved != ARM_TAHOE_SHA


def test_local_and_canonical_resolve_identically_under_intel_host():
    """The core fix: regardless of JSON key order, both payloads resolve to the
    same Intel tag for an Intel host -> a genuine same-bottle comparison MATCHES.
    Under the old first-tag logic these two orders resolved to different SHAs."""
    canonical = multiarch_files(CANON_ORDER)
    local = multiarch_files(LOCAL_INTEL_ORDER)
    arch, os_name = "x86_64", "sonoma"
    assert br.resolve_sha(local, arch, os_name) == br.resolve_sha(canonical, arch, os_name)
    assert br.resolve_sha(canonical, arch, os_name) == INTEL_SONOMA_SHA


def test_old_first_tag_logic_would_have_mismatched():
    """Documents the bug: first-key-in-dict differs across the two payloads."""
    canonical = multiarch_files(CANON_ORDER)
    local = multiarch_files(LOCAL_INTEL_ORDER)
    first_canon = next(iter(canonical))
    first_local = next(iter(local))
    assert first_canon != first_local  # arm64_tahoe vs sonoma -> false mismatch


# ----------------------- tag_preferences: never cross arch -----------------------


def test_x86_64_preferences_never_include_arm64_tags():
    prefs = br.tag_preferences("x86_64", "tahoe")
    assert not any(t.startswith("arm64_") for t in prefs)
    assert "x86_64_linux" in prefs
    # Bare codename ladder, newest-first, host OS downward.
    assert prefs[0] == "tahoe"
    assert "sonoma" in prefs and "ventura" in prefs


def test_arm64_preferences_only_arm64_tags():
    prefs = br.tag_preferences("arm64", "tahoe")
    assert all(t.startswith("arm64_") for t in prefs)
    assert prefs[0] == "arm64_tahoe"
    assert "arm64_linux" in prefs


def test_preferences_ladder_stops_at_host_os():
    """An older host OS must not prefer tags for newer macOS releases."""
    prefs = br.tag_preferences("x86_64", "ventura")
    assert "tahoe" not in prefs and "sequoia" not in prefs and "sonoma" not in prefs
    assert prefs[0] == "ventura"


def test_linux_host_prefers_only_linux_tag_not_macos():
    """A Linux host (codename None) must NOT prefer macOS bare-codename tags over
    its own {arch}_linux bottle — that would reintroduce the cross-platform
    false-positive for Linuxbrew."""
    assert br.tag_preferences("x86_64", None) == ["x86_64_linux"]
    assert br.tag_preferences("arm64", None) == ["arm64_linux"]


def test_linux_host_resolves_linux_bottle_consistently():
    """On Linux, both payloads must resolve x86_64_linux even when macOS tags are
    also present in the canonical JSON."""
    files = multiarch_files(
        [
            ("arm64_tahoe", ARM_TAHOE_SHA),
            ("sonoma", INTEL_SONOMA_SHA),
            ("x86_64_linux", "5" * 64),
        ]
    )
    assert br.resolve_sha(files, "x86_64", None) == "5" * 64


# ----------------------- detection + overrides -----------------------


def test_detect_arch_env_override_normalizes(monkeypatch):
    monkeypatch.setenv("BREW_SAFE_HOST_ARCH", "aarch64")
    assert br.detect_arch() == "arm64"
    monkeypatch.setenv("BREW_SAFE_HOST_ARCH", "amd64")
    assert br.detect_arch() == "x86_64"


def test_detect_codename_accepts_version_number(monkeypatch):
    monkeypatch.setenv("BREW_SAFE_HOST_OS", "14")
    assert br.detect_codename() == "sonoma"
    monkeypatch.setenv("BREW_SAFE_HOST_OS", "26")
    assert br.detect_codename() == "tahoe"


def test_detect_codename_future_os_maps_to_newest_known(monkeypatch):
    monkeypatch.setenv("BREW_SAFE_HOST_OS", "99")
    assert br.detect_codename() == "tahoe"


# ----------------------- degenerate inputs -----------------------


def test_empty_files_returns_none():
    assert br.resolve_sha({}, "x86_64", "sonoma") is None


def test_final_fallback_is_deterministic_sorted():
    """When no same-arch tag exists (synthetic/degenerate), pick the sorted-first
    tag so local and canonical resolve identically regardless of key order."""
    a = multiarch_files([("arm64_sonoma", ARM_SONOMA_SHA), ("arm64_tahoe", ARM_TAHOE_SHA)])
    b = multiarch_files([("arm64_tahoe", ARM_TAHOE_SHA), ("arm64_sonoma", ARM_SONOMA_SHA)])
    # Host is x86_64 -> no bare-codename tag present -> sorted-first fallback.
    assert br.resolve_sha(a, "x86_64", "sonoma") == br.resolve_sha(b, "x86_64", "sonoma")
    assert br.resolve_sha(a, "x86_64", "sonoma") == ARM_SONOMA_SHA  # sorts before arm64_tahoe


# ----------------------- CLI contract (source-dependent sentinels) -----------------------


def _run_cli(source, payload):
    return subprocess.run(
        [sys.executable, str(RESOLVER), "--source", source],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        check=False,
        env={"BREW_SAFE_HOST_ARCH": "x86_64", "BREW_SAFE_HOST_OS": "sonoma", "PATH": ""},
    )


def test_cli_canonical_emits_sha():
    payload = {"bottle": {"stable": {"files": dict(multiarch_files(CANON_ORDER))}}}
    out = _run_cli("canonical", payload).stdout.strip()
    assert out == INTEL_SONOMA_SHA


def test_cli_canonical_no_bottle_sentinel():
    payload = {"bottle": {"stable": {"files": {}}}}
    assert _run_cli("canonical", payload).stdout.strip() == "NO_BOTTLE"


def test_cli_local_silent_on_no_bottle():
    """Local source must stay silent (empty) so the caller reads 'no local bottle'."""
    payload = {"formulae": [{"name": "x", "versions": {"stable": "1"}}]}
    assert _run_cli("local", payload).stdout.strip() == ""


def test_cli_local_emits_sha_from_formulae_node():
    payload = {"formulae": [{"bottle": {"stable": {"files": dict(multiarch_files(CANON_ORDER))}}}]}
    assert _run_cli("local", payload).stdout.strip() == INTEL_SONOMA_SHA


def test_cli_canonical_parse_error_sentinel():
    out = subprocess.run(
        [sys.executable, str(RESOLVER), "--source", "canonical"],
        input="not json{",
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.stdout.strip() == "PARSE_ERROR"
