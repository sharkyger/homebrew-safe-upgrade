"""
Keyword path: a record's own CPE data decides what it is about.

Live 50-package run, 2026-08-21 — php 8.5.9 blocked on CVE-2003-1086/-1256/
-1257, CVE-2004-0070/-1971; ruby 4.0.6 on CVE-2025-25291/-25292/-27407.
Every one of them reached us through the keyword path ("PHP remote file
inclusion vulnerability in pMachine ...", "ruby-saml provides ... for Ruby")
and every one carries CPE data naming a DIFFERENT product (pmachine,
ezcontents, omniauth_saml) with no statement about ours. NVD's CPE list is
the authoritative applicability statement; when it exists and nothing in it
names our product, the CVE is not about us — regardless of how the prose
reads.

CPE-matched results never come here (the query already pinned the product).
Records with NO CPE data (Deferred/Received) are untouched: there is nothing
to reason from, so they stay — fail-safe.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402
from tests.test_nvd_cpe_filtering import _FakeResponse, _nvd_response  # noqa: E402

EMPTY = json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()


def _keyword_only(package, version, cve_id, desc, cpes):
    """CPE probe finds nothing; the keyword query returns one record."""
    body = json.loads(_nvd_response(cve_id, desc, cpes))
    body["totalResults"] = 1
    payload = json.dumps(body).encode()

    def fake(req, timeout=15):
        return _FakeResponse(payload if "keywordSearch=" in req.full_url else EMPTY)

    with patch.object(dsc, "_urlopen", side_effect=fake):
        return {f["id"] for f in dsc.query_nvd(package, "brew", version=version)}


def test_php_cve_whose_cpes_name_pmachine_is_rejected():
    assert (
        _keyword_only(
            "php",
            "8.5.9",
            "CVE-2003-1086",
            "PHP remote file inclusion vulnerability in pm/lib.inc.php in pMachine Free "
            "and pMachine Pro 2.2 and 2.2.1 allows remote attackers to execute code.",
            [
                "cpe:2.3:a:pmachine:pmachine_free:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:pmachine:pmachine_pro:2.2:*:*:*:*:*:*:*",
            ],
        )
        == set()
    )


def test_ruby_cve_whose_cpes_name_omniauth_saml_is_rejected():
    assert (
        _keyword_only(
            "ruby",
            "4.0.6_1",
            "CVE-2025-25291",
            "ruby-saml provides security assertion markup language (SAML) single sign-on "
            "(SSO) for Ruby. An authentication bypass exists before 1.12.4.",
            ["cpe:2.3:a:omniauth:omniauth_saml:*:*:*:*:*:*:*:*"],
        )
        == set()
    )


def test_compound_product_naming_ours_is_kept():
    """`node` vs `node.js`, `openldap` vs `openldap-servers`: the product names
    ours as a token, so the record stays (over-block direction)."""
    assert _keyword_only(
        "node",
        None,
        "CVE-2099-0001",
        "Node.js allows an attacker to bypass permissions.",
        ["cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"],
    ) == {"CVE-2099-0001"}


def test_record_without_any_cpe_data_is_untouched():
    """Deferred/Received records carry no CPE data — nothing to reason from."""
    assert _keyword_only(
        "hugo",
        None,
        "CVE-2026-75926",
        "Hugo 0.161.0 placed the Node asset pipelines behind the permission model.",
        [],
    ) == {"CVE-2026-75926"}


def test_record_with_own_product_cpe_is_kept():
    assert _keyword_only(
        "wget",
        None,
        "CVE-2099-0002",
        "wget before 1.25.0 allows attackers to overwrite files.",
        ["cpe:2.3:a:gnu:wget:*:*:*:*:*:*:*:*"],
    ) == {"CVE-2099-0002"}
