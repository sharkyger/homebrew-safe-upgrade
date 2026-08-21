"""
NVD query normalisation — found running v0.3.1 on a real 50-package backlog.

Three identities never reached NVD in a form it accepts:

  1. Tap-qualified formulae (`sharkyger/tap/pip-cve-gate`): the slashes went
     into the CPE string and the keyword search verbatim. NVD answers 404 for a
     malformed virtualMatchString, the HTTPError escaped the candidate loop, and
     the package came back "unknown" — a permanent blind spot on exactly the
     least-reviewed software on the machine.
  2. Versioned formulae (`python@3.12`): `_nvd_cpe_products` already lists the
     base product second, but the literal `python@3.12` was tried FIRST, NVD
     404'd on the '@', and the loop never got to `python`. The existing test
     stubbed urlopen to always succeed, so this was invisible.
  3. A response that truncates mid-body raises http.client.IncompleteRead,
     which is not a URLError and was not caught — a raw traceback instead of a
     handled source failure.

The fix does NOT widen the keyword path: bare `python` as a keyword drags in
the VS Code Python-extension CVEs. Only the CPE product is normalised; the
keyword fallback keeps the exact formula name.
"""

import http.client
import json
import sys
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402
from tests.test_nvd_cpe_filtering import _FakeResponse, _nvd_response  # noqa: E402

EMPTY = json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()


def _http_error(code):
    return urllib.error.HTTPError("https://nvd", code, "err", {}, None)


def _nvd_server(answers):
    """A fake NVD: `answers` maps a substring of the decoded URL to a body or an
    exception. Records every URL asked so tests can assert what was sent."""
    seen = []

    def fake_urlopen(req, timeout=15):
        url = urllib.parse.unquote(req.full_url)
        seen.append(url)
        for needle, answer in answers.items():
            if needle in url:
                if isinstance(answer, Exception):
                    raise answer
                return _FakeResponse(answer)
        return _FakeResponse(EMPTY)

    return seen, fake_urlopen


# --------------------------------------------------------------------------
# 1 + 2: identity normalisation
# --------------------------------------------------------------------------


def test_tap_prefix_is_stripped_for_cpe_and_keyword():
    assert dsc._nvd_cpe_products("sharkyger/tap/pip-cve-gate", "brew") == ["pip-cve-gate"]
    assert dsc._nvd_cpe_products("shopify/shopify/shopify-cli", "brew") == ["shopify-cli"]


def test_versioned_formula_never_sends_the_at_sign_to_nvd():
    """'@' is not a CPE character. The literal name must not be a candidate."""
    assert dsc._nvd_cpe_products("python@3.12", "brew") == ["python"]
    assert dsc._nvd_cpe_products("openssl@3", "brew") == ["openssl"]


def test_plain_names_are_unchanged():
    assert dsc._nvd_cpe_products("wget", "brew") == ["wget"]


def test_tap_formula_reaches_nvd_with_the_bare_name():
    seen, server = _nvd_server({})
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("sharkyger/tap/pip-cve-gate", "brew", version="0.3.3")

    assert findings == [], findings
    assert seen, "expected at least one NVD request"
    for url in seen:
        assert "sharkyger/tap" not in url, url
    assert any("cpe:2.3:a:*:pip-cve-gate:0.3.3" in u for u in seen), seen
    # keyword fallback ran (no CPE hit) and used the formula name, not the path
    assert any("keywordSearch=pip-cve-gate" in u for u in seen), seen


def test_versioned_formula_resolves_via_base_cpe_when_literal_would_404():
    """Live NVD 404s on `python@3.12`; the base product must be reached."""
    body = json.loads(
        _nvd_response(
            "CVE-2025-0001",
            "Python 3.12.14 has an issue in tarfile.",
            ["cpe:2.3:a:python_software_foundation:python:3.12.14:*:*:*:*:*:*:*"],
        )
    )
    body["totalResults"] = 1
    seen, server = _nvd_server(
        {
            "virtualMatchString=cpe:2.3:a:*:python@3.12": _http_error(404),
            "cpe:2.3:a:*:python:3.12.14": json.dumps(body).encode(),
        }
    )
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("python@3.12", "brew", version="3.12.14")

    ids = {f["id"] for f in findings}
    assert ids == {"CVE-2025-0001"}, findings
    assert not any("python@3.12" in u for u in seen), seen


def test_keyword_fallback_is_not_widened_to_the_base_name():
    """Bare `python` as a keyword matches the VS Code Python extension. When the
    CPE path finds nothing, the keyword must stay the exact (bare-of-tap)
    formula name, never the '@'-stripped base."""
    seen, server = _nvd_server({})
    with patch.object(dsc, "_urlopen", side_effect=server):
        dsc.query_nvd("python@3.12", "brew", version="3.12.14")

    kw = [u for u in seen if "keywordSearch=" in u]
    assert kw, seen
    assert all("keywordSearch=python@3.12&" in u for u in kw), kw


def test_a_404_on_one_cpe_candidate_does_not_abort_the_query():
    """Defensive: NVD's answer to a CPE it cannot parse is 404. That is 'no
    match for this candidate', not 'the source is down'."""
    seen, server = _nvd_server({"virtualMatchString": _http_error(404)})
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("wget", "brew", version="1.25.0")

    assert findings == [], findings
    assert any("keywordSearch=wget" in u for u in seen), seen


# --------------------------------------------------------------------------
# 3: truncated body
# --------------------------------------------------------------------------


def test_incomplete_read_is_a_handled_source_failure(monkeypatch):
    monkeypatch.setattr(dsc, "NVD_MAX_RETRIES", 2)
    monkeypatch.setattr(dsc.time, "sleep", lambda *_: None)
    seen, server = _nvd_server({"virtualMatchString": http.client.IncompleteRead(b"x" * 10, 21430)})
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("certifi", "brew", version="2026.7.22")

    assert len(findings) == 1
    assert findings[0]["id"] == "ERROR"
    assert "IncompleteRead" in findings[0]["summary"]
    assert findings[0]["rate_limited"] is False


def test_incomplete_read_is_retried_once_then_succeeds(monkeypatch):
    monkeypatch.setattr(dsc, "NVD_MAX_RETRIES", 3)
    monkeypatch.setattr(dsc.time, "sleep", lambda *_: None)
    calls = {"n": 0}

    def flaky(req, timeout=15):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http.client.IncompleteRead(b"", 100)
        return _FakeResponse(EMPTY)

    with patch.object(dsc, "_urlopen", side_effect=flaky):
        data = dsc._nvd_get("https://nvd.example/?q")

    assert data == {"totalResults": 0, "vulnerabilities": []}
    assert calls["n"] == 2


@pytest.mark.parametrize("exc", [ConnectionResetError("reset"), TimeoutError("slow")])
def test_socket_level_errors_degrade_like_any_source_failure(monkeypatch, exc):
    monkeypatch.setattr(dsc, "NVD_MAX_RETRIES", 1)
    seen, server = _nvd_server({"virtualMatchString": exc})
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("wget", "brew", version="1.25.0")

    assert [f["id"] for f in findings] == ["ERROR"]


# --------------------------------------------------------------------------
# the trap: product `python` is shared with the VS Code Python extension
# --------------------------------------------------------------------------


def test_vscode_extension_cpe_is_not_cpython():
    """Live NVD, vendor-wildcard CPE `*:python:3.12.14`: 68 `python:python`
    CPEs and 5 `microsoft:python:*:…:visual_studio_code` ones (CVE-2020-1171,
    CVE-2020-1192, CVE-2020-17163, CVE-2024-49050, CVE-2025-49714). The
    extension CVEs must not survive against the formula."""
    body = json.loads(
        _nvd_response(
            "CVE-2020-1171",
            "A remote code execution vulnerability exists in Visual Studio Code "
            "when the Python extension loads workspace settings from a notebook file.",
            ["cpe:2.3:a:microsoft:python:*:*:*:*:*:visual_studio_code:*:*"],
        )
    )
    body["totalResults"] = 1
    seen, server = _nvd_server({"cpe:2.3:a:*:python:3.12.14": json.dumps(body).encode()})
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("python@3.12", "brew", version="3.12.14")

    assert findings == [], findings


def test_genuine_cpython_cpe_still_flags():
    body = json.loads(
        _nvd_response(
            "CVE-2025-0001",
            "An issue in the tarfile module of CPython 3.12.14.",
            ["cpe:2.3:a:python:python:3.12.14:*:*:*:*:*:*:*"],
        )
    )
    body["totalResults"] = 1
    seen, server = _nvd_server({"cpe:2.3:a:*:python:3.12.14": json.dumps(body).encode()})
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("python@3.12", "brew", version="3.12.14")

    assert {f["id"] for f in findings} == {"CVE-2025-0001"}


def test_keyword_result_naming_only_the_bare_product_is_rejected():
    """Keyword fallback for `python@3.12`: a record whose description names
    only "Python" (the extension-shaped noise) must not be accepted via the
    '@'-stripped base name in the description filter (CodeRabbit, PR #122)."""
    body = json.loads(
        _nvd_response(
            "CVE-2020-1192",
            "Python extension for Visual Studio Code allows remote code execution "
            "when it loads a Jupyter notebook file.",
            [],
        )
    )
    body["totalResults"] = 1
    seen, server = _nvd_server({"keywordSearch=python@3.12": json.dumps(body).encode()})
    # No version: without CPE data a versioned lookup is dropped before the
    # description filter runs, which would mask what this test is about.
    with patch.object(dsc, "_urlopen", side_effect=server):
        findings = dsc.query_nvd("python@3.12", "brew", version=None)

    # The keyword fallback must have been exercised — otherwise an empty result
    # would prove nothing about the description filter.
    assert any("keywordSearch=python@3.12&" in u for u in seen), seen
    assert findings == [], findings
