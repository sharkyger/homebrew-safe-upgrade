"""Tests for the cask → NVD keyword/CPE mapping.

The mapping translates cask slugs (e.g. `brave-browser`) into the canonical
NVD search keyword (e.g. "Brave Browser") so that `query_nvd` actually
returns hits for vendor-shipped GUI apps. Tests cover:

  - Map well-formedness (no unintended CPE collisions)
  - User-installed casks resolve correctly
  - query_nvd uses the mapped keyword in its NVD URL
  - query_nvd's description filter accepts the mapped keyword
  - Unmapped brew packages (formulae) are unaffected
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Import from the repo root, not the tests dir
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cask_nvd_map  # noqa: E402
import dependency_security_check as dsc  # noqa: E402

# ─── Map well-formedness ─────────────────────────────────────────────────────


def test_map_passes_collision_validation():
    """The built-in self-check must run without raising."""
    cask_nvd_map._validate_no_unintended_collisions()


def test_map_has_expected_size():
    """Sanity floor — we curated ~50 entries; under 40 means something was
    accidentally truncated."""
    assert len(cask_nvd_map.CASK_NVD_MAP) >= 40


def test_every_entry_has_required_keys():
    """Each map entry must have keyword + vendor + product."""
    for cask, meta in cask_nvd_map.CASK_NVD_MAP.items():
        assert "keyword" in meta, f"{cask} missing 'keyword'"
        assert "vendor" in meta, f"{cask} missing 'vendor'"
        assert "product" in meta, f"{cask} missing 'product'"
        assert meta["keyword"], f"{cask} has empty keyword"


@pytest.mark.parametrize(
    "cask,expected_keyword,expected_vendor",
    [
        # User's actually-installed casks — must be mapped correctly
        ("chromium", "Chromium", "chromium"),
        ("vscodium", "Visual Studio Code", "microsoft"),
        ("claude-code", "Claude Code", "anthropic"),
        ("temurin", "Eclipse Temurin", "eclipse"),
        # Spot-check a few of the curated top-50
        ("google-chrome", "Google Chrome", "google"),
        ("brave-browser", "Brave Browser", "brave"),
        ("visual-studio-code", "Visual Studio Code", "microsoft"),
        ("docker", "Docker Desktop", "docker"),
        ("1password", "1Password", "1password"),
    ],
)
def test_known_cask_mapping(cask, expected_keyword, expected_vendor):
    assert cask in cask_nvd_map.CASK_NVD_MAP, f"{cask} not in CASK_NVD_MAP"
    meta = cask_nvd_map.CASK_NVD_MAP[cask]
    assert meta["keyword"] == expected_keyword
    assert meta["vendor"] == expected_vendor


# ─── query_nvd integration ──────────────────────────────────────────────────


def _fake_nvd_response(cve_id, description):
    """Build a minimal NVD API response body."""
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
                                {
                                    "cvssData": {
                                        "baseSeverity": "HIGH",
                                        "baseScore": 8.0,
                                    }
                                }
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
    captured_urls = []

    def fake_urlopen(req, timeout=15):
        captured_urls.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0001", "Some unrelated text."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("brave-browser", "brew", version=None)

    assert len(captured_urls) == 1
    url = captured_urls[0]
    # Mapped keyword "Brave Browser" → URL-encoded as "Brave%20Browser"
    assert "Brave%20Browser" in url, f"expected mapped keyword in URL, got: {url}"
    assert "brave-browser" not in url, f"raw cask slug must NOT appear in URL: {url}"


def test_unmapped_brew_package_uses_raw_name():
    """Formulae (not in the cask map) must use the raw package_name —
    behavior unchanged for non-cask packages."""
    captured_urls = []

    def fake_urlopen(req, timeout=15):
        captured_urls.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0002", "openssl is vulnerable."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("openssl", "brew", version=None)

    assert "openssl" in captured_urls[0]


def test_mapped_cask_description_match_accepts_mapped_keyword():
    """A CVE whose description starts with the mapped keyword must pass
    the description filter — even though the raw cask slug isn't there."""

    def fake_urlopen(req, timeout=15):
        return _FakeResponse(
            _fake_nvd_response(
                "CVE-2099-0003",
                # Description uses "Brave Browser", not "brave-browser"
                "Brave Browser before version 1.50.0 allows remote code execution.",
            )
        )

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        findings = dsc.query_nvd("brave-browser", "brew", version=None)

    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2099-0003"


def test_mapped_cask_rejects_unrelated_cve():
    """If a CVE description doesn't mention the mapped keyword at all,
    it must be rejected (no noise from NVD keyword search false positives)."""

    def fake_urlopen(req, timeout=15):
        return _FakeResponse(
            _fake_nvd_response(
                "CVE-2099-0004",
                "Some other product allows arbitrary file read.",
            )
        )

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        findings = dsc.query_nvd("brave-browser", "brew", version=None)

    assert findings == []


def test_non_brew_ecosystem_unaffected_by_cask_map():
    """A pip package named exactly like a cask in the map (extremely
    unlikely) must NOT trigger the substitution — only ecosystem=brew does."""
    captured_urls = []

    def fake_urlopen(req, timeout=15):
        captured_urls.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0005", "irrelevant"))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("chromium", "pip", version=None)

    # Should use raw "chromium", not the mapped "Chromium" keyword
    # (Same string here, but the substitution code path is gated on ecosystem)
    assert "chromium" in captured_urls[0]


def test_short_unmapped_cask_skips_query():
    """Names under 4 chars short-circuit (NVD too noisy). Must still apply
    after potential mapping — e.g. cask `obs` (3 chars) maps to 'OBS Studio'
    (>4 chars) and should now be queryable."""
    captured_urls = []

    def fake_urlopen(req, timeout=15):
        captured_urls.append(req.full_url)
        return _FakeResponse(_fake_nvd_response("CVE-2099-0006", "OBS Studio version X..."))

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        dsc.query_nvd("obs", "brew", version=None)

    # 'obs' alone would be skipped (len < 4), but the mapped keyword
    # "OBS Studio" is long enough → query should fire.
    assert len(captured_urls) == 1
    assert "OBS%20Studio" in captured_urls[0]
