"""NVD API key handling and rate-limit backoff.

NVD throttles anonymous callers to 5 requests per rolling 30 seconds; an API key
raises that to 50. This became load-bearing when a package with no answering
source started being HELD instead of reported clean: a throttle now stops
packages upgrading rather than silently waving them through. Measured in a
container before this was added, ten packages checked back-to-back produced
three "UNABLE TO CHECK" results.

Pinned here:

  - the key travels in a HEADER, never the query string, so it cannot leak into
    a logged or reported URL;
  - no key configured => no apiKey header at all (not an empty one);
  - a throttling response is retried with backoff rather than abandoned;
  - Retry-After is honoured but capped, so a bad value cannot stall a run;
  - after the retries are spent it still fails CLOSED.
"""

import io
import json
import sys
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402

# A deliberately fake, non-functional UUID — the tests assert this value never
# escapes into a URL or program output.
SECRET = "11111111-2222-3333-4444-555555555555"  # noqa: S105


class _Resp:
    def __init__(self, body=b'{"totalResults": 0, "vulnerabilities": []}'):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _http_error(code, retry_after=None):
    headers = {"Retry-After": retry_after} if retry_after is not None else {}
    return urllib.error.HTTPError("https://nvd", code, "throttled", headers, None)


def test_api_key_is_sent_as_a_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", SECRET)
    seen = []

    def fake(req, timeout=15):
        seen.append(req)
        return _Resp()

    with patch.object(dsc, "_urlopen", side_effect=fake):
        dsc.query_nvd("wget", "brew", "1.25.0")

    assert seen, "expected a request"
    for req in seen:
        # Header names are case-insensitive in urllib's internal store.
        header_values = {k.lower(): v for k, v in req.header_items()}
        assert header_values.get("apikey") == SECRET, (
            f"key must be sent as a header: {header_values}"
        )


def test_api_key_never_appears_in_the_url(monkeypatch):
    """A URL can end up in an error string or a log; the key must not be in it."""
    monkeypatch.setenv("NVD_API_KEY", SECRET)
    seen = []

    def fake(req, timeout=15):
        seen.append(req.full_url)
        return _Resp()

    with patch.object(dsc, "_urlopen", side_effect=fake):
        dsc.query_nvd("wget", "brew", "1.25.0")

    for url in seen:
        assert SECRET not in url, f"API key leaked into the URL: {url}"
        assert "apiKey" not in url, f"API key parameter leaked into the URL: {url}"


def test_no_api_key_means_no_header(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    seen = []

    def fake(req, timeout=15):
        seen.append(req)
        return _Resp()

    with patch.object(dsc, "_urlopen", side_effect=fake):
        dsc.query_nvd("wget", "brew", "1.25.0")

    for req in seen:
        header_values = {k.lower() for k in dict(req.header_items())}
        assert "apikey" not in header_values, "must not send an empty apiKey header"


def test_blank_api_key_is_ignored(monkeypatch):
    """An exported-but-empty variable must not become an empty header."""
    monkeypatch.setenv("NVD_API_KEY", "   ")
    seen = []

    with patch.object(
        dsc, "_urlopen", side_effect=lambda req, timeout=15: seen.append(req) or _Resp()
    ):
        dsc.query_nvd("wget", "brew", "1.25.0")

    for req in seen:
        header_values = {k.lower() for k in dict(req.header_items())}
        assert "apikey" not in header_values


def test_throttled_request_is_retried_then_succeeds(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    calls = {"n": 0}
    # A non-empty CPE result, so the retry is the ONLY extra request — an empty
    # one would trigger the keyword fallback and muddy the call count.
    hit = json.dumps(
        {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0001",
                        "vulnStatus": "Analyzed",
                        "descriptions": [{"lang": "en", "value": "wget flaw"}],
                        "metrics": {},
                        "configurations": [],
                    }
                }
            ],
        }
    ).encode()

    def fake(req, timeout=15):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(403)
        return _Resp(hit)

    with patch.object(dsc, "_urlopen", side_effect=fake), patch.object(dsc.time, "sleep") as slept:
        findings = dsc.query_nvd("wget", "brew", "1.25.0")

    assert calls["n"] == 2, "a 403 should be retried once, not abandoned"
    assert slept.called, "the retry must back off rather than hammer the API"
    assert not [f for f in findings if f["id"] == "ERROR"]
    assert [f for f in findings if f["id"] == "CVE-2099-0001"], "the retried result must be used"


def test_retry_after_is_honoured_but_capped(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    calls = {"n": 0}

    def fake(req, timeout=15):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(429, retry_after="99999")
        return _Resp()

    with patch.object(dsc, "_urlopen", side_effect=fake), patch.object(dsc.time, "sleep") as slept:
        dsc.query_nvd("wget", "brew", "1.25.0")

    assert slept.call_args[0][0] <= 30, (
        f"a hostile Retry-After must not stall the run: slept {slept.call_args[0][0]}s"
    )


def test_persistent_throttling_still_fails_closed(monkeypatch):
    """Backoff must not turn a real failure into a pass."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    with (
        patch.object(
            dsc,
            "_urlopen",
            side_effect=lambda req, timeout=15: (_ for _ in ()).throw(_http_error(403)),
        ),
        patch.object(dsc.time, "sleep"),
    ):
        findings = dsc.query_nvd("wget", "brew", "1.25.0")

    assert [f for f in findings if f["id"] == "ERROR"], (
        "exhausted retries must report a source failure"
    )


def test_non_rate_limit_http_error_is_not_retried(monkeypatch):
    """A 404 is not a throttle — retrying it just wastes the rate budget."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    calls = {"n": 0}

    def fake(req, timeout=15):
        calls["n"] += 1
        raise _http_error(404)

    with patch.object(dsc, "_urlopen", side_effect=fake), patch.object(dsc.time, "sleep"):
        findings = dsc.query_nvd("wget", "brew", "1.25.0")

    assert calls["n"] == 1, f"a 404 must not be retried, was called {calls['n']}x"
    assert [f for f in findings if f["id"] == "ERROR"]


def test_scanner_output_never_contains_the_key(monkeypatch):
    """End-to-end: the key must not reach stdout or stderr on a failure path."""
    monkeypatch.setenv("NVD_API_KEY", SECRET)
    out, err = io.StringIO(), io.StringIO()

    with (
        patch.object(sys, "argv", ["dependency_security_check.py", "brew", "wget", "1.25.0"]),
        patch.object(
            dsc,
            "_urlopen",
            side_effect=lambda req, timeout=15: (_ for _ in ()).throw(_http_error(403)),
        ),
        patch.object(dsc.time, "sleep"),
        redirect_stdout(out),
        redirect_stderr(err),
        pytest.raises(SystemExit),
    ):
        dsc.main()

    combined = out.getvalue() + err.getvalue()
    assert SECRET not in combined, "the API key leaked into program output"
    assert json.loads(out.getvalue())["status"] == "unknown"
