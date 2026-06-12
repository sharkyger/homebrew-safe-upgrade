"""NVD CPE applicability filtering in query_nvd (issue #74).

NVD keyword search matches on text, so a Homebrew formula can collide with a
same-named package from a language ecosystem (the npm "cmake" package vs the
canonical cmake formula, CVE-2016-10642). The CPE 2.3 `target_sw` field says
which ecosystem an applicability statement is scoped to:

    cpe:2.3:a:cmake_project:cmake:-:*:*:*:*:node.js:*:*
                                              ^^^^^^^ target_sw

Contract pinned here:

  - A CVE whose vulnerable CPEs ALL point at a foreign language ecosystem
    (target_sw) is skipped — with and without a version (the no-version path
    previously bypassed CPE inspection entirely).
  - A CVE with at least one generic/relevant CPE still flags (fail-closed:
    ambiguity counts as affected).
  - target_sw matching the QUERIED ecosystem is not foreign — an npm query
    keeps node.js-scoped CVEs.
  - All-distro-vendor and OS-part (`cpe:2.3:o:...`) applicability is skipped
    in the no-version path too (previously only filtered when a version was
    supplied).
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def _nvd_response(cve_id, description, cpe_criteria_list):
    """Build a minimal NVD 2.0 response with one CVE and the given CPEs."""
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
                                {"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}
                            ]
                        },
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {"vulnerable": True, "criteria": c}
                                            for c in cpe_criteria_list
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        }
    ).encode()


def _query(package, ecosystem, version, response_body):
    def fake_urlopen(req, timeout=15):
        return _FakeResponse(response_body)

    with patch.object(dsc, "_urlopen", side_effect=fake_urlopen):
        return dsc.query_nvd(package, ecosystem, version=version)


# The real-world repro: the dead npm "cmake" package's advisory. Description
# passes the keyword filter (first word is "cmake"), so only the CPE's
# target_sw=node.js can tell it apart from the canonical formula.
_CMAKE_DESC = (
    "cmake installs the cmake x86 linux binaries. cmake downloads binary "
    "resources over HTTP, which leaves it vulnerable to MITM attacks."
)
_CMAKE_NPM_CPE = "cpe:2.3:a:cmake_project:cmake:-:*:*:*:*:node.js:*:*"


def test_foreign_target_sw_cpe_skipped_with_version():
    """brew cmake 4.3.3 must not be flagged by the npm-scoped advisory."""
    body = _nvd_response("CVE-2016-10642", _CMAKE_DESC, [_CMAKE_NPM_CPE])
    findings = _query("cmake", "brew", "4.3.3", body)
    assert findings == []


def test_foreign_target_sw_cpe_skipped_without_version():
    """Same advisory, no version supplied (the issue #74 repro): still skipped."""
    body = _nvd_response("CVE-2016-10642", _CMAKE_DESC, [_CMAKE_NPM_CPE])
    findings = _query("cmake", "brew", None, body)
    assert findings == []


def test_mixed_foreign_and_generic_cpe_still_flags():
    """One foreign CPE + one generic CPE: ambiguous — must stay flagged."""
    generic = "cpe:2.3:a:cmake_project:cmake:*:*:*:*:*:*:*:*"
    body = _nvd_response("CVE-2016-10642", _CMAKE_DESC, [_CMAKE_NPM_CPE, generic])
    for version in ("4.3.3", None):
        findings = _query("cmake", "brew", version, body)
        assert len(findings) == 1, f"version={version!r}: expected 1 finding"
        assert findings[0]["id"] == "CVE-2016-10642"


def test_own_ecosystem_target_sw_is_not_foreign():
    """An npm query must keep node.js-scoped CVEs."""
    body = _nvd_response("CVE-2016-10642", _CMAKE_DESC, [_CMAKE_NPM_CPE])
    findings = _query("cmake", "npm", None, body)
    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2016-10642"


def test_all_distro_vendor_cpes_skipped_without_version():
    """Distro-packaged applicability only: skipped even with no version."""
    body = _nvd_response(
        "CVE-2099-0010",
        "wget is vulnerable to a buffer overflow.",
        [
            "cpe:2.3:a:redhat:wget:1.0:*:*:*:*:*:*:*",
            "cpe:2.3:a:debian:wget:1.0:*:*:*:*:*:*:*",
        ],
    )
    findings = _query("wget", "brew", None, body)
    assert findings == []


def test_os_part_cpes_skipped_without_version():
    """OS-part (`cpe:2.3:o:...`) applicability only: skipped with no version."""
    body = _nvd_response(
        "CVE-2099-0011",
        "wget is vulnerable to a buffer overflow.",
        ["cpe:2.3:o:linux:wget:1.0:*:*:*:*:*:*:*"],
    )
    findings = _query("wget", "brew", None, body)
    assert findings == []


def test_no_cpe_data_still_flags_without_version():
    """No applicability data at all: keep the finding (fail closed)."""
    body = _nvd_response(
        "CVE-2099-0012",
        "wget is vulnerable to a buffer overflow.",
        [],
    )
    findings = _query("wget", "brew", None, body)
    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2099-0012"


def test_relevant_cpe_version_range_still_applies():
    """Version-range matching still runs over the relevant CPEs."""
    ranged = {
        "vulnerable": True,
        "criteria": "cpe:2.3:a:gnu:wget:*:*:*:*:*:*:*:*",
        "versionEndExcluding": "2.0.0",
    }
    body = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2099-0013",
                        "vulnStatus": "Analyzed",
                        "descriptions": [
                            {"lang": "en", "value": "wget before 2.0.0 is vulnerable."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}
                            ]
                        },
                        "configurations": [{"nodes": [{"cpeMatch": [ranged]}]}],
                    }
                }
            ]
        }
    ).encode()
    assert len(_query("wget", "brew", "1.9.0", body)) == 1  # in range — affected
    assert _query("wget", "brew", "2.1.0", body) == []  # past the fix — clean


def test_oracle_application_cpe_is_not_treated_as_distro_only():
    """Oracle is an upstream vendor (mysql, openjdk, virtualbox), not only a
    distro — its application CPEs must stay relevant, never blanket-skipped."""
    body = _nvd_response(
        "CVE-2099-0014",
        "mysql is vulnerable to privilege escalation.",
        ["cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"],
    )
    findings = _query("mysql", "brew", None, body)
    assert len(findings) == 1
    assert findings[0]["id"] == "CVE-2099-0014"
