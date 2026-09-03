"""The no-version-scope verdict contract (docs/PRD.md § Verdict semantics).

A finding NVD cannot tie to a version — `scoped: False` — can neither be pinned
to this version nor ruled out for it. Blocking on one is only useful if some
other version does not carry it; on the newest release there is none, so the
block denies the software without reducing exposure and the user's next move is
to switch the gate off. That is the `brew install gitleaks` failure this whole
contract exists to prevent.

These tests replace a description-bound parser that was rewritten five times.
Every review round found real CVEs a previous round's parser silently dropped,
so prose is no longer evidence at all — which makes that class unreachable
rather than merely fixed.
"""

from unittest.mock import patch

import dependency_security_check as dsc

UNSCOPED = {
    "source": "NIST NVD",
    "id": "CVE-A",
    "severity": "MEDIUM",
    "score": 6.3,
    "summary": "x",
    "scoped": False,
}
SCOPED = {
    "source": "NIST NVD",
    "id": "CVE-B",
    "severity": "HIGH",
    "score": 8.1,
    "summary": "y",
    "scoped": True,
}


def _split(version, latest, findings):
    with patch.object(dsc, "resolve_latest_version", return_value=latest):
        actionable, unactionable = dsc.partition_unactionable(
            [dict(f) for f in findings], "gitleaks", "brew", version
        )
    return [f["id"] for f in actionable], [f["id"] for f in unactionable]


def test_unscoped_finding_on_the_newest_release_does_not_block():
    """The reported case: CVE-2026-63728 has no CPE data and 8.30.1 IS the fix."""
    assert _split("8.30.1", "8.30.1", [UNSCOPED]) == ([], ["CVE-A"])


def test_unscoped_finding_on_an_older_release_still_blocks():
    """A newer version exists, so the block is actionable — move to it."""
    assert _split("8.29.0", "8.30.1", [UNSCOPED]) == (["CVE-A"], [])


def test_a_scoped_finding_always_blocks():
    """Structured evidence is definite, newest release or not."""
    assert _split("8.30.1", "8.30.1", [SCOPED]) == (["CVE-B"], [])


def test_scoped_and_unscoped_are_separated_not_conflated():
    assert _split("8.30.1", "8.30.1", [UNSCOPED, SCOPED]) == (["CVE-B"], ["CVE-A"])


def test_fails_closed_when_the_latest_version_is_unknown():
    """No answer about what is newest is not an answer that nothing is."""
    assert _split("8.30.1", None, [UNSCOPED]) == (["CVE-A"], [])


def test_fails_closed_when_no_version_was_supplied():
    assert _split(None, "8.30.1", [UNSCOPED]) == (["CVE-A"], [])
