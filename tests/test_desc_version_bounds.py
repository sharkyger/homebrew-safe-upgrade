"""Description-derived version bounds: the version must clear EVERY bound.

`_desc_says_not_affected()` is the fallback used when a CVE carries no CPE
data, so its verdict alone decides whether a finding is reported. Returning
True means "not affected" and DROPS the CVE — a false negative there ships a
vulnerability, which is strictly worse than the false positive of keeping one.

Three shapes were mishandled, all found in code review and all reproduced
before being fixed:

  * a multi-branch advisory was cleared by its FIRST bound only
  * an exclusive bound mentioned in passing returned before the real
    inclusive bound was ever read
  * a prose year ("since 2019") parsed as version 2019 and ruled out every
    release below it

No network and no Homebrew needed.
"""

import json
import subprocess
from unittest.mock import patch

import dependency_security_check as dsc


def _completed(stdout, returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


# ─────────────────────────────────────────────────────────────────────────────
# Regressions: each case previously returned True and dropped a live CVE.
# ─────────────────────────────────────────────────────────────────────────────


def test_bare_year_is_not_a_version_bound():
    """ "since 2019" is prose; as a bound it ruled out every 8.x release."""
    assert dsc._desc_says_not_affected("8.30.1", "This flaw has existed since 2019.") is False
    assert dsc._desc_says_not_affected("1.2", "The vulnerability was introduced in 2021.") is False
    # A bare four-digit number is prose whatever the version scheme — it has no
    # dotted component, so it never reads as a version. Fail closed.
    assert dsc._desc_says_not_affected("2018.1", "Affected since 2019.") is False
    # An explicit "version" marker qualifies it, and the year guard then decides:
    # honoured for a date-schemed version, rejected for an 8.x one.
    assert dsc._desc_says_not_affected("2018.1", "Affected since version 2019.") is True
    assert dsc._desc_says_not_affected("8.30.1", "Affected since version 2019.") is False


# ─────────────────────────────────────────────────────────────────────────────
# Boundary semantics that must not regress.
# ─────────────────────────────────────────────────────────────────────────────

GITLEAKS = "Gitleaks prior to 8.30.1 contains a template injection vulnerability."


def test_exclusive_bounds_exclude_the_named_version():
    assert dsc._desc_says_not_affected("8.30.1", GITLEAKS) is True  # the fix itself
    assert dsc._desc_says_not_affected("8.29.0", GITLEAKS) is False
    assert dsc._desc_says_not_affected("2.0", "Bug, fixed in 2.0.") is True
    assert dsc._desc_says_not_affected("1.9", "Bug, patched in version 2.0.") is False


def test_inclusive_bounds_include_the_named_version():
    desc = "Foo through 8.30.1 allows attackers."
    assert dsc._desc_says_not_affected("8.30.1", desc) is False  # still affected
    assert dsc._desc_says_not_affected("8.30.2", desc) is True


def test_up_to_is_inclusive_but_up_to_but_not_including_is_not():
    assert dsc._desc_says_not_affected("3.0", "Affected versions up to 3.0.") is False
    assert dsc._desc_says_not_affected("4.0", "Affected versions up to 3.0.") is True
    assert dsc._desc_says_not_affected("3.0", "Affected up to but not including 3.0.") is True
    assert dsc._desc_says_not_affected("2.9", "Affected up to but not including 3.0.") is False


def test_bound_restated_in_the_products_own_scheme():
    """Warp: "prior to 2024.07.18 (v0.2024.07.16.08.02)" — see test_cask_nvd_map."""
    desc = "Affected prior to 2024.07.18 (v0.2024.07.16.08.02)."
    assert dsc._desc_says_not_affected("0.2026.08.19", desc) is True
    # A date-schemed version still compares against the PRIMARY bound.
    assert dsc._desc_says_not_affected("2024.07.17", desc) is False


def test_ambiguity_fails_closed():
    assert dsc._desc_says_not_affected("1.0", "Something bad happens somewhere.") is False
    # A boundary word with no version behind it is not a bound (CVE-2024-34062).
    assert dsc._desc_says_not_affected("4.66.3", "Arguments are passed through eval.") is False
    # An unparseable version can never clear a CVE.
    assert dsc._desc_says_not_affected("latest", "Starting in version 2.0, a flaw exists.") is False


# ─────────────────────────────────────────────────────────────────────────────
# Second-round review regressions. The first fix for multi-branch advisories
# traded a false negative for a false positive, and the new `up to` pattern
# started reading prose quantities as version bounds. Both confirmed against
# the previous revision before being fixed.
# ─────────────────────────────────────────────────────────────────────────────


def test_up_to_and_including_is_inclusive():
    desc = "Foo up to and including 3.0 is vulnerable."
    assert dsc._desc_says_not_affected("3.0", desc) is False
    assert dsc._desc_says_not_affected("3.1", desc) is True


def test_lower_bound_does_not_override_an_inclusive_bound():
    """A description naming both must fail closed."""
    desc = "Introduced in 2.0 of the rewrite. Legacy releases through 1.9 are also affected."
    assert dsc._desc_says_not_affected("1.5", desc) is False


def test_several_upper_bounds_fail_closed():
    """An advisory naming more than one upper bound is AMBIGUOUS — keep the CVE.

    "Django 4.2 before 4.2.11, 5.0 before 5.0.4" describes two release lines,
    and nothing in the text says which one a given version belongs to. Earlier
    revisions tried both readings and each was wrong somewhere: taking the first
    bound cleared 10.0 against 9.2 (dropped a live CVE), requiring every bound
    blocked the patched Django 4.2.15 (false positive), and scoping bounds by
    leading component could not tell 1.2.x from 1.3.x. Declining to guess is the
    only reading that never drops a finding.
    """
    django = "Django 4.2 before 4.2.11, 5.0 before 5.0.4 are affected."
    assert dsc._desc_says_not_affected("4.2.15", django) is False
    assert dsc._desc_says_not_affected("4.2.10", django) is False
    assert dsc._desc_says_not_affected("9.9", django) is False  # even far above both
    same_major = "Foo 1.2.x before 1.2.5 and 1.3.x before 1.3.2 are affected."
    assert dsc._desc_says_not_affected("1.2.9", same_major) is False
    two_lines = "Foo 9.x before 9.2 and 10.x before 10.1 are affected."
    assert dsc._desc_says_not_affected("10.0", two_lines) is False


def test_a_second_bound_anywhere_makes_the_description_ambiguous():
    """Two bounds is two bounds, even when one is mentioned in passing."""
    desc = "A prior issue was fixed in 1.0. This new flaw affects versions through 3.0."
    assert dsc._desc_says_not_affected("2.0", desc) is False
    assert dsc._desc_says_not_affected("3.1", desc) is False  # ambiguous, not cleared
    mixed = "Foo 2.x before 2.1 is affected. A second flaw affects everything before 9.0."
    assert dsc._desc_says_not_affected("2.5", mixed) is False


def test_a_lower_bound_counts_only_when_it_is_the_only_bound():
    """Mixed with an upper bound, "since X" is unreliable.

    "Since 1.0 the library bundles libbar. Foo before 3.0 is affected." states an
    introduction that has nothing to do with the vulnerability; honouring it
    cleared 0.9, which the same sentence calls affected.
    """
    assert dsc._desc_says_not_affected("1.9", "Starting in version 2.0 a flaw exists.") is True
    assert dsc._desc_says_not_affected("2.1", "Starting in version 2.0 a flaw exists.") is False
    mixed = "Since 1.0 the library bundles libbar. Foo before 3.0 is affected."
    assert dsc._desc_says_not_affected("0.9", mixed) is False


def test_prose_quantities_are_not_version_bounds():
    """CVE text is full of quantities; reading one as a bound DROPS the CVE.

    Guarded by an allowlist of what may FOLLOW a bound rather than a blacklist
    of units — no list of nouns is ever complete, and an unrecognised word must
    fail closed.
    """
    assert (
        dsc._desc_says_not_affected("8.30.1", "A flaw writes up to 4.0 kilobytes past the end.")
        is False
    )
    assert dsc._desc_says_not_affected("8.30.1", "Allows up to 1.5 million connections.") is False
    assert dsc._desc_says_not_affected("2024.07.18", "A flaw copies up to 256 bytes.") is False
    assert dsc._desc_says_not_affected("1000.1", "The handler loops through 8 entries.") is False


def test_version_marker_qualifies_a_single_component_bound():
    """ "prior to v8" is a version; "up to 8 entries" is not."""
    assert dsc._desc_says_not_affected("9.0", "Foo prior to v8 is vulnerable.") is True
    assert dsc._desc_says_not_affected("7.0", "Foo prior to v8 is vulnerable.") is False
    assert dsc._desc_says_not_affected("4.0", "Foo up to version 3 is vulnerable.") is True


def test_bound_is_never_truncated_at_an_internal_dot():
    """Regression: the "what may follow" lookahead let the engine backtrack and
    match "2024.07" out of "2024.07.18", comparing against a different number."""
    desc = "Affected prior to 2024.07.18 (v0.2024.07.16.08.02)."
    exclusive, _inclusive, _lower, _listed = dsc._desc_bounds("0.2026.08.19", desc)
    assert exclusive == [("2024.07.18", "0.2024.07.16.08.02")]


# ─────────────────────────────────────────────────────────────────────────────
# Fourth-review regressions. All three drop a CVE, and the first two were
# introduced by this change set rather than inherited.
# ─────────────────────────────────────────────────────────────────────────────


def test_a_cask_version_latest_resolves_to_nothing():
    """`version :latest` is not a version, and returning it is worse than None.

    The tolerant parser maps "latest" to 0, so the CPE range check reads
    `0 < versionStartIncluding` as "outside the affected range" and drops every
    CPE-ranged CVE for that package. brew has no OSV or GHSA second opinion to
    recover them, and before brew resolved at all the CPE block was skipped
    entirely, so those findings used to be kept.
    """
    payload = json.dumps({"formulae": [], "casks": [{"version": "latest"}]})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("some-cask") is None
    # A real cask version still resolves, build suffix stripped.
    payload = json.dumps({"formulae": [], "casks": [{"version": "6.0.2,1234"}]})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("some-cask") == "6.0.2"
    # Same rule on the formula path.
    payload = json.dumps({"formulae": [{"versions": {"stable": "HEAD"}}], "casks": []})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("weird") is None


def test_a_bound_is_not_truncated_at_a_non_numeric_segment():
    """ "through 1.3.x" must not become the bound 1.3, clearing the 1.3 branch."""
    assert dsc._desc_says_not_affected("1.3.5", "Foo through 1.3.x is affected.") is False
    assert dsc._desc_says_not_affected("2.4.9", "Foo up to 2.4.x is affected.") is False
    assert dsc._desc_says_not_affected("1.2.9", "Foo before 1.2.x is affected.") is False
    # A sentence-ending period still terminates a bound normally.
    assert dsc._desc_says_not_affected("8.30.2", "Foo through 8.30.1.") is True


def test_a_comma_list_of_fix_versions_is_ambiguous():
    """ "fixed in 9.4.55, 10.0.24, and 11.0.24" states one fix per release line.

    Only the first is captured, so 10.0.20 cleared against 9.4.55 — a CVE that
    applies to it. A trailing list is as ambiguous as a repeated boundary word.
    """
    jetty = "Jetty is vulnerable to a DoS. This is fixed in 9.4.55, 10.0.24, and 11.0.24."
    assert dsc._desc_says_not_affected("10.0.20", jetty) is False
    assert dsc._desc_says_not_affected("11.0.30", jetty) is False  # ambiguous, not cleared
    assert (
        dsc._desc_says_not_affected("3.4.0", "Foo before 2.1.5, 3.4.1 and 4.0.2 is affected.")
        is False
    )
    # A single bound followed by ordinary prose is still usable.
    assert (
        dsc._desc_says_not_affected("8.30.1", "Gitleaks prior to 8.30.1 contains a flaw.") is True
    )


def test_a_bound_followed_by_an_ordinary_verb_is_still_a_bound():
    """NVD's most common shape is "Foo before X <verb> ...".

    An earlier revision applied a follow-word allowlist to exclusive bounds too.
    No allowlist of English verbs is complete, so the bound was discarded and
    the release carrying the fix stayed flagged — the very bug this work
    removes, reintroduced for a large class of CPE-less advisories. Only
    inclusive words ("up to", "through") collide with quantities; nobody writes
    "before 4.0 kilobytes".
    """
    for verb in (
        "does not properly validate input",
        "mishandles certificates",
        "fails to sanitise the path",
        "might allow remote attackers to run code",
        "lacks a bounds check",
        "uses a predictable seed",
    ):
        desc = f"Foo before 1.5 {verb}."
        assert dsc._desc_says_not_affected("2.0", desc) is True, desc
        assert dsc._desc_says_not_affected("1.4", desc) is False, desc


def test_identical_bounds_are_agreement_not_ambiguity():
    """The standard GHSA Impact/Patches import states the same version twice."""
    desc = "Versions prior to 2.0.1 are affected. This issue has been patched in version 2.0.1."
    assert dsc._desc_says_not_affected("2.0.1", desc) is True
    assert dsc._desc_says_not_affected("2.0.0", desc) is False


def test_a_bound_may_be_annotated_with_a_parenthetical():
    """Advisories routinely annotate the fix: "(see the advisory)", "(commit abc)"."""
    assert dsc._desc_says_not_affected("2.0", "Fixed in 1.5 (see the advisory).") is True
    assert dsc._desc_says_not_affected("1.4", "Fixed in 1.5 (see the advisory).") is False


def test_and_does_not_qualify_a_quantity_as_a_bound():
    """ "queue up to 2.0 and the daemon crashes" is a quantity, not a bound.

    "and"/"or" follow a bare quantity as naturally as they follow a version, so
    they are deliberately absent from the inclusive follow-allowlist.
    """
    assert (
        dsc._desc_says_not_affected("4.0", "Users can queue up to 2.0 and the daemon crashes.")
        is False
    )
