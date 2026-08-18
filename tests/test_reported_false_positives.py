"""Regression tests for the false positives reported as issues #94, #95, #109.

All three arrived as "current version flagged with a decades-old CVE". They had
a shared cause that was NOT the one the reports guessed at: NVD keyword search
was issued with resultsPerPage=10 and no pagination, and NVD returns oldest
first. openssh has 177 CVEs, libreoffice 109 — so the ONLY CVEs the scanner
ever saw for an established package were its ten most ancient ones. The broken
version comparison then failed to filter them out, and the pair surfaced as
"OpenSSH 10.3p1 is vulnerable to CVE-2001-0529".

The same truncation caused false negatives nobody could report, because they
were invisible: openssh 10.3p1 is named by eight current CVEs sitting far past
result #10, which the tool never fetched.

Fixed by querying CPE-first (virtualMatchString — product+version scoped, so
the result set is small and complete) and by teaching the comparator the two
version dialects involved. These tests are hermetic: they pin the comparator
and the filtering against canned NVD payloads, so they cannot decay when the
real databases change.
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


def _nvd_response(cves, total=None):
    """Build an NVD 2.0 response. `cves` is a list of (id, desc, cpeMatch list)."""
    body = {
        "totalResults": len(cves) if total is None else total,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": desc}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}]
                    },
                    "configurations": [{"nodes": [{"cpeMatch": cpes}]}],
                }
            }
            for cve_id, desc, cpes in cves
        ],
    }
    return json.dumps(body).encode()


def run_query(package, version, payload, ecosystem="brew"):
    with patch.object(dsc, "_urlopen", side_effect=lambda req, timeout=15: _FakeResponse(payload)):
        return dsc.query_nvd(package, ecosystem, version)


def ids(findings):
    return {f["id"] for f in findings if f["id"] != "ERROR"}


# --------------------------------------------------------------------------
# #109 — llama.cpp: NVD records b-prefixed CPE bounds, Homebrew strips the b
# --------------------------------------------------------------------------


def test_llama_cpp_b_prefixed_bounds_are_comparable():
    """`b3427` must parse, or every bound is unparseable and everything flags."""
    assert dsc.parse_version("b3427") is not None
    assert dsc._ver_ge("10250", "b3427") is True
    assert dsc._ver_ge("10250", "b3561") is True
    # Homebrew's 10250 IS upstream b10250 — the two must compare equal.
    assert dsc.parse_version("10250") == dsc.parse_version("b10250")


def test_llama_cpp_fixed_build_is_not_flagged():
    """Build 10250 is past every one of the four reported fixes."""
    payload = _nvd_response(
        [
            (
                "CVE-2024-41130",
                "llama.cpp is vulnerable to a heap overflow.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:ggerganov:llama.cpp:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "b3427",
                    }
                ],
            ),
            (
                "CVE-2024-32878",
                "llama.cpp has a race condition.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:ggerganov:llama.cpp:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "b2715",
                        "versionEndExcluding": "b2740",
                    }
                ],
            ),
        ]
    )
    assert ids(run_query("llama.cpp", "10250", payload)) == set()


def test_llama_cpp_vulnerable_build_still_flags():
    """The fix must not silence a build that IS inside the range."""
    payload = _nvd_response(
        [
            (
                "CVE-2024-32878",
                "llama.cpp has a race condition.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:ggerganov:llama.cpp:*:*:*:*:*:*:*:*",
                        "versionStartIncluding": "b2715",
                        "versionEndExcluding": "b2740",
                    }
                ],
            )
        ]
    )
    assert ids(run_query("llama.cpp", "2720", payload)) == {"CVE-2024-32878"}


# --------------------------------------------------------------------------
# #94 — openssh 10.3p1: the portmark suffix made the version unparseable
# --------------------------------------------------------------------------


def test_openssh_portmark_parses_and_orders():
    """`p1` is a PORTABLE build of 10.3, not a pre-release of it."""
    assert dsc.parse_version("10.3p1") is not None
    # A portable build contains everything its base release does...
    assert dsc._ver_lt("10.3", "10.3p1") is True
    # ...and is still ordered against later portable builds.
    assert dsc._ver_lt("10.3p1", "10.3p2") is True
    # ...and against the next upstream release.
    assert dsc._ver_lt("10.3p1", "10.4") is True


def test_openssh_modern_version_not_flagged_by_2001_cve():
    """CVE-2001-0529 affects 'OpenSSH 2.9 and earlier'."""
    payload = _nvd_response(
        [
            (
                "CVE-2001-0529",
                "OpenSSH version 2.9 and earlier, with X forwarding enabled, allows a local "
                "attacker to delete any file named 'cookies' via a symlink attack.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionEndIncluding": "2.9",
                    }
                ],
            )
        ]
    )
    assert ids(run_query("openssh", "10.3p1", payload)) == set()


def test_openssh_portmark_version_inside_range_still_flags():
    """A CVE that really does cover 10.3p1 must survive the fix."""
    payload = _nvd_response(
        [
            (
                "CVE-2026-60002",
                "OpenSSH has a flaw.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionEndIncluding": "10.4",
                    }
                ],
            )
        ]
    )
    assert ids(run_query("openssh", "10.3p1", payload)) == {"CVE-2026-60002"}


# --------------------------------------------------------------------------
# #95 — libreoffice: a version-less CPE for a DIFFERENT product kept the CVE
# --------------------------------------------------------------------------


def test_libreoffice_foreign_product_cpe_does_not_flag():
    """CVE-2012-4233's libreoffice CPEs stop at 3.6; only a `sun:openoffice.org`
    CPE has no version, and that one is not our product."""
    payload = _nvd_response(
        [
            (
                "CVE-2012-4233",
                "LibreOffice 3.5.x before 3.5.7.2 and 3.6.x before 3.6.1, and OpenOffice.org "
                "(OOo), allows remote attackers to cause a denial of service.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:libreoffice:libreoffice:*:*:*:*:*:*:*:*",
                        "versionEndIncluding": "3.6",
                    },
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:sun:openoffice.org:-:*:*:*:*:*:*:*",
                    },
                ],
            )
        ]
    )
    assert ids(run_query("libreoffice", "26.2.4", payload)) == set()


def test_unmatched_product_cpes_are_kept_so_coverage_is_not_lost():
    """Narrowing to our product must be CONDITIONAL.

    Brew formula names and CPE product names disagree often (`node` vs
    `node.js`). If no CPE names our product, the full set has to stay — a CVE
    with no surviving CPE is dropped entirely, so unconditional narrowing would
    convert a precision fix into a fail-open.
    """
    payload = _nvd_response(
        [
            (
                "CVE-2026-0001",
                "Node.js has a flaw.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "24.0.0",
                    }
                ],
            )
        ]
    )
    assert ids(run_query("node", "20.1.0", payload)) == {"CVE-2026-0001"}


# --------------------------------------------------------------------------
# Coverage holes found while fixing the above
# --------------------------------------------------------------------------


def test_short_package_name_is_queried():
    """The old len<4 guard returned before querying, so xz/git/vim/php/zsh were
    NEVER checked and always came back clean — xz 5.6.1 included."""
    payload = _nvd_response(
        [
            (
                "CVE-2024-3094",
                "Malicious code was discovered in the upstream tarballs of xz, starting with "
                "version 5.6.0.",
                [{"vulnerable": True, "criteria": "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"}],
            )
        ]
    )
    assert ids(run_query("xz", "5.6.1", payload)) == {"CVE-2024-3094"}


def test_cpe_path_does_not_apply_the_description_subject_heuristic():
    """CVE-2024-3094's description opens 'Malicious code was discovered...'.

    The keyword path rejects a CVE whose first sentence names a different
    subject than the package — necessary against keyword noise, but fatal here.
    A CPE match already pins the product, so the heuristic must not run on it.
    """
    payload = _nvd_response(
        [
            (
                "CVE-2024-3094",
                "Malicious code was discovered in the upstream tarballs of xz.",
                [{"vulnerable": True, "criteria": "cpe:2.3:a:tukaani:xz:5.6.1:*:*:*:*:*:*:*"}],
            )
        ]
    )
    assert ids(run_query("xz", "5.6.1", payload)) == {"CVE-2024-3094"}


def test_versioned_formula_resolves_to_base_product():
    """`openssl@3`, `python@3.11`, `node@20` appear in no CPE and no CVE text.

    Passed verbatim to an exact-match keyword search they matched nothing, so
    every versioned formula — precisely the long-lived, security-critical ones
    — reported clean.
    """
    assert "openssl" in dsc._nvd_cpe_products("openssl@3", "brew")
    assert "python" in dsc._nvd_cpe_products("python@3.11", "brew")
    assert "postgresql" in dsc._nvd_cpe_products("postgresql@16", "brew")

    payload = _nvd_response(
        [
            (
                "CVE-2026-1234",
                "OpenSSL has a flaw.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "3.5.0",
                    }
                ],
            )
        ]
    )
    assert ids(run_query("openssl@3", "3.0.0", payload)) == {"CVE-2026-1234"}


def test_truncated_result_set_is_reported_as_a_source_failure():
    """A verdict built on a partial page is a guess, not a clean bill of health."""
    huge = _nvd_response([("CVE-2026-9999", "irrelevant", [])], total=10_000)
    findings = run_query("somepackage", "1.0", huge)
    assert any(f["id"] == "ERROR" for f in findings), (
        "an incomplete result set must surface as a source failure so the caller fails closed"
    )


def test_cpe_update_field_carries_the_openssh_portmark():
    """NVD splits the portmark into the CPE UPDATE component.

    CVE-2016-6210 is recorded as `cpe:2.3:a:openbsd:openssh:*:p2:*`. Homebrew
    spells the same thing as one string ("10.3p1"), so comparing only the
    version component against it can never match — an exact-version CPE pinned
    to a portmark would be judged not-affected and the finding lost.
    """
    payload = _nvd_response(
        [
            (
                "CVE-2016-6210",
                "OpenSSH has a user enumeration flaw.",
                [{"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:7.2:p2:*:*:*:*:*:*"}],
            )
        ]
    )
    assert ids(run_query("openssh", "7.2p2", payload)) == {"CVE-2016-6210"}, (
        "an exact-version CPE with the portmark in the update field must still match"
    )
    # ...and a different portable build of the same release must NOT match.
    assert ids(run_query("openssh", "7.2p1", payload)) == set()


def test_wildcard_version_with_portmark_does_not_flag_every_build():
    """`openssh:*:p2` pins a portable build, not "any version".

    CVE-2016-6210 is recorded exactly this way. Treating the wildcard version as
    "affects everything" and ignoring the update component flags every OpenSSH
    release — the same false positive shape as #94, just via a different field.
    """
    payload = _nvd_response(
        [
            (
                "CVE-2016-6210",
                "OpenSSH user enumeration.",
                [{"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:p2:*:*:*:*:*:*"}],
            )
        ]
    )
    assert ids(run_query("openssh", "10.3p1", payload)) == set(), "p1 is not the pinned p2 build"
    assert ids(run_query("openssh", "7.2p2", payload)) == {"CVE-2016-6210"}, "p2 must still flag"
    # No portmark at all => we cannot disprove it => fail closed.
    assert ids(run_query("openssh", "7.2", payload)) == {"CVE-2016-6210"}


def test_plain_wildcard_cpe_still_flags():
    """The portmark handling must not weaken an ordinary version wildcard."""
    payload = _nvd_response(
        [
            (
                "CVE-2099-0001",
                "OpenSSH flaw.",
                [{"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"}],
            )
        ]
    )
    assert ids(run_query("openssh", "10.3p1", payload)) == {"CVE-2099-0001"}


def test_persistent_false_positive_would_disable_the_freshness_hold():
    """Why these false positives were worse than cosmetic.

    brew-safe-upgrade has a deliberate CVE-aware bypass: when a package is
    below --min-age it queries the INSTALLED version, and if that version has
    CVEs it waives the freshness hold on the reasoning that the fresh release
    is the fix ("bypassing age check").

    A PERMANENT false positive therefore permanently unlocks that bypass. For
    llama.cpp every build was flagged, so the installed version was always
    "vulnerable", so the freshness hold — the tool's primary defence against a
    just-compromised release — never applied to it. The reporter of #109 called
    this out in the issue title and was correct.

    This is the coupling that makes a fail-closed comparator produce a
    fail-OPEN outcome one layer up, so it gets its own guard: if a version
    dialect stops parsing, this fails with the reason rather than looking like
    a cosmetic regression.
    """
    payload = _nvd_response(
        [
            (
                "CVE-2024-41130",
                "llama.cpp is vulnerable to a heap overflow.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:ggerganov:llama.cpp:*:*:*:*:*:*:*:*",
                        "versionEndExcluding": "b3427",
                    }
                ],
            )
        ]
    )
    # The INSTALLED version is what the bypass consults.
    installed = ids(run_query("llama.cpp", "10250", payload))
    assert installed == set(), (
        "a fixed build must read as clean — otherwise brew-safe-upgrade's "
        "CVE-aware bypass waives --min-age for this package on every run"
    )

    openssh_payload = _nvd_response(
        [
            (
                "CVE-2001-0529",
                "OpenSSH version 2.9 and earlier, with X forwarding enabled, allows a local "
                "attacker to delete any file named 'cookies' via a symlink attack.",
                [
                    {
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                        "versionEndIncluding": "2.9",
                    }
                ],
            )
        ]
    )
    assert ids(run_query("openssh", "10.3p1", openssh_payload)) == set(), (
        "same coupling for the openssh portmark dialect"
    )
