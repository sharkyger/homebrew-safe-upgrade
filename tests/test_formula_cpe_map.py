"""
Formula → verified NVD CPE (vendor:product) map.

For a formula with a known, verified CPE the CPE query is AUTHORITATIVE: zero
results means NVD lists no CVE for that version, and the keyword fallback is
not run. The keyword fallback exists for products NVD has no CPE for; running
it for `php` or `certifi` anyway is what produced the 1,000-record overflow
("coverage incomplete", a permanent hold) and the 2003-era "PHP remote file
inclusion in <some PHP app>" blocks on a live 50-package run.

Every entry was checked against NVD's CPE dictionary
(/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:<vendor>:<product>:*) on
2026-08-21; the test below pins the shape, not the network.
"""

import json
import re
import sys
import urllib.parse
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402
import formula_cpe_map  # noqa: E402
from tests.test_nvd_cpe_filtering import _FakeResponse, _nvd_response  # noqa: E402

EMPTY = json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
CPE_COMPONENT = re.compile(r"^[a-z0-9][a-z0-9._\-]*$")


def test_map_entries_are_well_formed():
    assert len(formula_cpe_map.FORMULA_NVD_CPE) >= 10
    assert (
        "wget" not in formula_cpe_map.FORMULA_NVD_CPE
    )  # the suite's generic example stays unmapped
    for formula, (vendor, product) in formula_cpe_map.FORMULA_NVD_CPE.items():
        assert CPE_COMPONENT.match(formula), formula
        assert CPE_COMPONENT.match(vendor), (formula, vendor)
        assert CPE_COMPONENT.match(product), (formula, product)


def test_known_entries():
    m = formula_cpe_map.FORMULA_NVD_CPE
    assert m["php"] == ("php", "php")
    assert m["node"] == ("nodejs", "node.js")
    assert m["python"] == ("python", "python")
    assert m["ruby"] == ("ruby-lang", "ruby")


def _run(package, version, responses):
    seen = []

    def fake(req, timeout=15):
        url = urllib.parse.unquote(req.full_url)
        seen.append(url)
        for needle, body in responses.items():
            if needle in url:
                return _FakeResponse(body)
        return _FakeResponse(EMPTY)

    with patch.object(dsc, "_urlopen", side_effect=fake):
        findings = dsc.query_nvd(package, "brew", version=version)
    return seen, findings


def test_mapped_formula_queries_the_verified_vendor_and_product():
    seen, _ = _run("php", "8.5.9", {})
    assert any("cpe:2.3:a:php:php:8.5.9" in u for u in seen), seen


def test_mapped_formula_with_zero_cpe_results_is_clean_without_keyword_search():
    """The whole point: no UNBOUNDED keyword fallback, so no 1,000-record
    overflow and no 2003-era PHP-app noise. (The bounded recent-window sweep
    is a different, date-limited query — see the sweep test.)"""
    seen, findings = _run("php", "8.5.9", {})
    assert findings == [], findings
    unbounded = [u for u in seen if "keywordSearch=" in u and "pubStartDate=" not in u]
    assert not unbounded, seen


def test_mapped_versioned_formula_resolves_through_the_base_entry():
    seen, _ = _run("python@3.12", "3.12.14", {})
    assert any("cpe:2.3:a:python:python:3.12.14" in u for u in seen), seen
    unbounded = [u for u in seen if "keywordSearch=" in u and "pubStartDate=" not in u]
    assert not unbounded, seen


def test_mapped_formula_cpe_hit_is_reported():
    body = json.loads(
        _nvd_response(
            "CVE-2026-3644",
            "Python 3.12.14 has an issue in http.cookies.",
            ["cpe:2.3:a:python:python:3.12.14:*:*:*:*:*:*:*"],
        )
    )
    body["totalResults"] = 1
    _, findings = _run(
        "python@3.12", "3.12.14", {"cpe:2.3:a:python:python": json.dumps(body).encode()}
    )
    assert {f["id"] for f in findings} == {"CVE-2026-3644"}


def test_unmapped_formula_keeps_the_keyword_fallback():
    seen, _ = _run("someobscureformula", "1.0", {})
    assert any("cpe:2.3:a:*:someobscureformula:1.0" in u for u in seen), seen
    assert any("keywordSearch=someobscureformula" in u for u in seen), seen


def test_mapped_formula_sweeps_recent_unanalysed_records():
    """NVD assigns CPEs days to weeks after publication. Until then a record is
    invisible to the CPE query; the bounded recent-window keyword sweep keeps
    it visible — but only records WITHOUT CPE data are taken from it."""
    fresh = json.loads(
        _nvd_response(
            "CVE-2026-75926",
            "Hugo 0.161.0 placed the Node asset pipelines behind the permission model.",
            [],
        )
    )
    analysed = json.loads(
        _nvd_response(
            "CVE-2020-0001",
            "Hugo before 0.50 allowed traversal.",
            ["cpe:2.3:a:gohugo:hugo:*:*:*:*:*:*:*:*"],
        )
    )
    body = {
        "totalResults": 2,
        "vulnerabilities": fresh["vulnerabilities"] + analysed["vulnerabilities"],
    }
    seen, findings = _run("hugo", "0.165.0", {"pubStartDate=": json.dumps(body).encode()})
    sweep = [u for u in seen if "pubStartDate=" in u]
    assert sweep and all("keywordSearch=hugo&" in u for u in sweep), seen
    assert {f["id"] for f in findings} == {"CVE-2026-75926"}, findings
    assert findings[0]["scoped"] is False


def test_unmapped_formula_does_not_run_the_recent_sweep():
    seen, _ = _run("someobscureformula", "1.0", {})
    assert not any("pubStartDate=" in u for u in seen), seen


def test_recent_sweep_is_skipped_above_the_cap(capsys):
    """`php` as a keyword matches ~140 unanalysed records about other PHP
    software in one 120-day window. Prose cannot attribute those; above the
    cap the sweep contributes nothing and says so."""
    records = []
    for i in range(dsc.NVD_RECENT_SWEEP_CAP + 1):
        r = json.loads(
            _nvd_response(f"CVE-2026-{i:05d}", f"PHP remote file inclusion in SomeApp{i}.", [])
        )
        records.extend(r["vulnerabilities"])
    body = {"totalResults": len(records), "vulnerabilities": records}
    _, findings = _run("php", "8.5.9", {"pubStartDate=": json.dumps(body).encode()})
    assert findings == [], findings
    assert "too generic to attribute" in capsys.readouterr().err


# ----- CodeRabbit CLI on the batch (2026-08-21): three fail-open holes in the map -----


def test_mapped_formula_strips_homebrew_revision_from_the_cpe_version():
    """ruby 4.0.6_1 answered "clean" because ruby-lang:ruby:4.0.6_1 is a
    version NVD has never heard of — the authoritative query must carry the
    upstream version."""
    seen, _ = _run("ruby", "4.0.6_1", {})
    assert any("cpe:2.3:a:ruby-lang:ruby:4.0.6:" in u for u in seen), seen
    assert not any("4.0.6_1" in u for u in seen), seen


def test_tap_formula_sharing_a_mapped_name_is_not_mapped():
    """someone/tap/php is not php:php. It keeps the default (wildcard CPE +
    keyword) path instead of an authoritative answer for another product."""
    seen, _ = _run("someone/tap/php", "1.0", {})
    assert any("cpe:2.3:a:*:php:1.0" in u for u in seen), seen
    assert not any("cpe:2.3:a:php:php" in u for u in seen), seen
    assert any("keywordSearch=php&" in u for u in seen), seen


def test_recent_sweep_that_overflows_is_treated_as_too_generic(monkeypatch, capsys):
    monkeypatch.setattr(dsc, "NVD_MAX_PAGES", 1)
    monkeypatch.setattr(dsc, "NVD_PAGE_SIZE", 2)
    records = []
    for i in range(2):
        r = json.loads(_nvd_response(f"CVE-2026-{i:05d}", f"PHP issue in SomeApp{i}.", []))
        records.extend(r["vulnerabilities"])
    body = {"totalResults": 500, "vulnerabilities": records}
    monkeypatch.setattr(dsc, "_NOTES", [])
    _, findings = _run("php", "8.5.9", {"pubStartDate=": json.dumps(body).encode()})
    assert findings == [], findings
    assert "fetched 2 of 500 records" in capsys.readouterr().err
    # The same note rides in the verdict JSON: the wrappers run the scanner
    # with 2>/dev/null, so stderr alone never reached a brew-safe-upgrade user.
    assert any("fetched 2 of 500 records" in n for n in dsc._NOTES), dsc._NOTES


def test_versionless_cpe_is_reported_but_not_as_version_scoped():
    """CVE-2026-5201: the only upstream applicability is `gnome:gdk-pixbuf:-`
    — no version, no bounds. The fix shipped in 2.44.6, yet 2.44.8 was blocked
    with `scoped: True`, which reads as "version-confirmed". The finding stays
    (fail closed: nothing in the record says 2.44.8 is fixed) but is labelled
    unscoped, so the wrapper's [SAME] rule can see that installed and candidate
    carry the same evidence-free record."""
    body = json.loads(
        _nvd_response(
            "CVE-2026-5201",
            "A flaw was found in the gdk-pixbuf library. This heap-based buffer overflow "
            "vulnerability occurs in the JPEG image loader.",
            [
                "cpe:2.3:a:gnome:gdk-pixbuf:-:*:*:*:*:*:*:*",
                "cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*",
            ],
        )
    )
    body["totalResults"] = 1
    _, findings = _run("gdk-pixbuf", "2.44.8", {"gdk-pixbuf": json.dumps(body).encode()})
    assert {f["id"] for f in findings} == {"CVE-2026-5201"}
    assert findings[0]["scoped"] is False


def test_bounded_cpe_is_version_scoped():
    body = json.loads(
        _nvd_response(
            "CVE-2026-5201",
            "A flaw was found in the gdk-pixbuf library.",
            ["cpe:2.3:a:gnome:gdk-pixbuf:*:*:*:*:*:*:*:*"],
        )
    )
    body["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0][
        "versionEndExcluding"
    ] = "2.44.6"
    body["totalResults"] = 1
    _, findings = _run("gdk-pixbuf", "2.44.5", {"gdk-pixbuf": json.dumps(body).encode()})
    assert findings and findings[0]["scoped"] is True
    _, findings = _run("gdk-pixbuf", "2.44.8", {"gdk-pixbuf": json.dumps(body).encode()})
    assert findings == [], "2.44.8 is outside the bound and must be clean"
