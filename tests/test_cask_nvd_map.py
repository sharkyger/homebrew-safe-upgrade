"""Tests for the cask → NVD keyword map.

The mapping translates cask slugs (e.g. `brave-browser`) into the canonical
NVD search keyword brew already publishes for each cask, so that `query_nvd`
actually returns hits for vendor-shipped GUI apps. Tests cover:

  - Map schema (string-valued, no empties, length ≥ 4)
  - User-installed casks resolve correctly
  - Documented overrides remain in place
  - query_nvd uses the mapped keyword in its NVD URL
  - query_nvd's description filter accepts mapped keyword AND raw slug
  - Unmapped brew packages (formulae) are unaffected by the map
  - Empty/short keywords are rejected by the validator
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cask_nvd_map  # noqa: E402
import dependency_security_check as dsc  # noqa: E402

# ─── Map schema ──────────────────────────────────────────────────────────────


def test_validator_passes_on_current_map():
    """Built-in validator runs without raising on the shipped map."""
    cask_nvd_map._validate()


def test_map_has_expected_size():
    """Floor of 40 entries — under that means something was accidentally truncated."""
    assert len(cask_nvd_map.CASK_NVD_KEYWORDS) >= 40


def test_every_entry_is_a_string():
    """Schema is {token: str}, not {token: dict}."""
    for token, keyword in cask_nvd_map.CASK_NVD_KEYWORDS.items():
        assert isinstance(keyword, str), f"{token}: keyword must be str, got {type(keyword)}"
        assert keyword, f"{token}: empty keyword"


def test_every_keyword_meets_min_length():
    """Keywords shorter than 4 chars would silently skip the NVD query."""
    for token, keyword in cask_nvd_map.CASK_NVD_KEYWORDS.items():
        assert len(keyword) >= cask_nvd_map.MIN_KEYWORD_LEN, (
            f"{token}: {keyword!r} is shorter than {cask_nvd_map.MIN_KEYWORD_LEN}"
        )


def test_validator_rejects_short_keyword():
    """Negative test — the validator must raise on a too-short keyword."""
    original = cask_nvd_map.CASK_NVD_KEYWORDS.copy()
    try:
        cask_nvd_map.CASK_NVD_KEYWORDS["bad"] = "xy"  # 2 chars
        with pytest.raises(ValueError, match="shorter than"):
            cask_nvd_map._validate()
    finally:
        cask_nvd_map.CASK_NVD_KEYWORDS.clear()
        cask_nvd_map.CASK_NVD_KEYWORDS.update(original)


def test_validator_rejects_empty_keyword():
    """Negative test — empty keyword must raise."""
    original = cask_nvd_map.CASK_NVD_KEYWORDS.copy()
    try:
        cask_nvd_map.CASK_NVD_KEYWORDS["empty"] = ""
        with pytest.raises(ValueError, match="empty"):
            cask_nvd_map._validate()
    finally:
        cask_nvd_map.CASK_NVD_KEYWORDS.clear()
        cask_nvd_map.CASK_NVD_KEYWORDS.update(original)


@pytest.mark.parametrize(
    "cask,expected_keyword",
    [
        # User-installed casks
        ("chromium", "Chromium"),
        ("vscodium", "Visual Studio Code"),  # documented override (shared source)
        ("claude-code", "Claude Code"),
        ("temurin", "Eclipse Temurin"),  # documented override (brew has verbose name)
        # Brew-canonical names (not overridden)
        ("google-chrome", "Google Chrome"),
        ("brave-browser", "Brave"),  # brew's canonical, not "Brave Browser"
        ("slack", "Slack"),
        ("zoom", "Zoom"),
        # Documented overrides
        ("obs", "OBS Studio"),  # brew "OBS" too short
        ("visual-studio-code", "Visual Studio Code"),  # strip "Microsoft" prefix
        ("intellij-idea", "IntelliJ IDEA"),  # strip "Ultimate" suffix
        ("intellij-idea-ce", "IntelliJ IDEA"),  # strip prefix + edition
    ],
)
def test_known_cask_mapping(cask, expected_keyword):
    assert cask in cask_nvd_map.CASK_NVD_KEYWORDS, f"{cask} not in CASK_NVD_KEYWORDS"
    assert cask_nvd_map.CASK_NVD_KEYWORDS[cask] == expected_keyword


def test_dropped_token_docker_is_absent():
    """`docker` was folded into `docker-desktop` by brew. The old token must
    not be in the map, or installs of the new token won't be mapped."""
    assert "docker" not in cask_nvd_map.CASK_NVD_KEYWORDS
    assert "docker-desktop" in cask_nvd_map.CASK_NVD_KEYWORDS


def test_renamed_token_handbrake_uses_new_form():
    """brew renamed `handbrake` → `handbrake-app`."""
    assert "handbrake" not in cask_nvd_map.CASK_NVD_KEYWORDS
    assert "handbrake-app" in cask_nvd_map.CASK_NVD_KEYWORDS


# ─── query_nvd integration ──────────────────────────────────────────────────


def _fake_nvd_response(cve_id, description):
    return json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": description}],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.0}}
                            ]
                        },
                        "configurations": [],
                    }
                }
            ]
        }
    ).encode()


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def test_mapped_cask_uses_mapped_keyword_in_nvd_url():
    """For a known cask, the NVD URL must contain the mapped keyword,
    URL-encoded, NOT the raw cask slug."""
    captured = []

    def fake_urlopen(req, timeout=15):
        captured.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0001", "Unrelated text."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("brave-browser", "brew", version=None)

    # CPE-first means up to two requests (a CPE product query, then the keyword
    # fallback when NVD has no CPE for it). The contract is about WHICH name is
    # searched, not how many requests it takes, so assert over all of them.
    assert captured, "expected at least one NVD request"
    # Check the KEYWORD request specifically. Accepting a match from the CPE
    # candidate URL would let a regression that drops the mapping on the keyword
    # path still pass, since the CPE product happens to contain "brave" too.
    keyword_urls = [u for u in captured if "keywordSearch=" in u]
    assert keyword_urls, f"expected a keyword-search request: {captured}"
    # "Brave" — short, URL-safe, no encoding needed beyond the keyword
    assert any("keywordSearch=Brave" in u for u in keyword_urls), (
        f"expected the mapped keyword on the keyword path: {keyword_urls}"
    )
    for url in captured:
        assert "brave-browser" not in url, f"raw slug must not appear: {url}"


def test_unmapped_brew_package_uses_raw_name():
    """Formulae (not in the cask map) use the raw package_name."""
    captured = []

    def fake_urlopen(req, timeout=15):
        captured.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0002", "openssl is vulnerable."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("openssl", "brew", version=None)

    assert "openssl" in captured[0]


def test_mapped_cask_description_match_accepts_mapped_keyword():
    """A CVE description that mentions the mapped keyword (not the raw slug)
    must still pass the filter."""

    def fake_urlopen(req, timeout=15):
        return _FakeResponse(
            _fake_nvd_response(
                "CVE-2099-0003",
                "Brave before version 1.50.0 allows remote code execution.",
            )
        )

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        findings = dsc.query_nvd("brave-browser", "brew", version=None)

    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2099-0003"


def test_mapped_cask_description_match_accepts_raw_slug_fallback():
    """If a CVE description happens to use the raw slug form, that's also
    accepted (match_terms includes both forms)."""

    def fake_urlopen(req, timeout=15):
        return _FakeResponse(
            _fake_nvd_response(
                "CVE-2099-0004",
                "brave-browser is vulnerable to remote code execution.",
            )
        )

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        findings = dsc.query_nvd("brave-browser", "brew", version=None)

    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2099-0004"


def test_mapped_cask_rejects_unrelated_cve():
    """Description that mentions neither form is rejected (no noise)."""

    def fake_urlopen(req, timeout=15):
        return _FakeResponse(_fake_nvd_response("CVE-2099-0005", "Some other product has issues."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        findings = dsc.query_nvd("brave-browser", "brew", version=None)

    assert findings == []


def test_non_brew_ecosystem_unaffected_by_cask_map():
    """ecosystem != 'brew' must skip the cask-map substitution."""
    captured = []

    def fake_urlopen(req, timeout=15):
        captured.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0006", "irrelevant"))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("chromium", "pip", version=None)

    # No substitution for pip ecosystem, even if the name happens to match a cask
    assert "chromium" in captured[0]


def test_short_cask_token_with_long_mapped_keyword():
    """Cask `obs` (3 chars) maps to 'OBS Studio'.

    This used to matter because a len<4 guard skipped the NVD query outright
    for short names. That guard is gone (it silently left xz, git, vim, php
    and zsh unchecked), but the mapping still has to be applied: the CPE
    product is `obs_studio` and the keyword fallback is "OBS Studio", never
    the bare slug.
    """
    captured = []

    def fake_urlopen(req, timeout=15):
        captured.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0007", "OBS Studio version X..."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("obs", "brew", version=None)

    assert captured, "expected at least one NVD request"
    assert any("obs_studio" in u for u in captured), f"expected CPE product query: {captured}"
    assert any("OBS%20Studio" in u for u in captured), f"expected mapped keyword: {captured}"


def test_short_formula_name_is_still_queried():
    """A <4-character formula must be queried, not silently skipped.

    `xz`, `git`, `vim`, `php` and `zsh` all fell under the old len<4 guard.
    For brew — where NVD is the only source that can answer — that meant the
    package was never checked and always came back clean, including xz 5.6.1
    (CVE-2024-3094, the backdoored release).
    """
    captured = []

    def fake_urlopen(req, timeout=15):
        captured.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0008", "irrelevant"))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("xz", "brew", version="5.6.1")

    assert captured, "a short formula name must still reach NVD"
    assert any("xz" in u for u in captured)
