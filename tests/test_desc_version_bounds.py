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

import dependency_security_check as dsc

# ─────────────────────────────────────────────────────────────────────────────
# Regressions: each case previously returned True and dropped a live CVE.
# ─────────────────────────────────────────────────────────────────────────────


def test_multi_branch_advisory_must_clear_every_bound():
    """NVD routinely lists several affected branches in one description."""
    desc = "Foo 9.x before 9.2 and 10.x before 10.1 are affected."
    assert dsc._desc_says_not_affected("10.0", desc) is False  # clears 9.2, not 10.1
    assert dsc._desc_says_not_affected("10.1", desc) is True  # clears both
    assert dsc._desc_says_not_affected("9.1", desc) is False
    desc2 = "Foo before 1.2.3 and 2.x before 2.0.1 allow RCE."
    assert dsc._desc_says_not_affected("2.0.0", desc2) is False


def test_prose_mention_of_an_earlier_fix_does_not_short_circuit():
    """An exclusive bound matched first must not skip the inclusive bound."""
    desc = "A prior issue was fixed in 1.0. This new flaw affects versions through 3.0."
    assert dsc._desc_says_not_affected("2.0", desc) is False
    assert dsc._desc_says_not_affected("3.1", desc) is True


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


def test_lower_bound_excludes_versions_predating_introduction():
    desc = "Starting in version 2.0 and prior to version 2.5, a flaw exists."
    assert dsc._desc_says_not_affected("1.9", desc) is True
    assert dsc._desc_says_not_affected("2.5", desc) is True
    assert dsc._desc_says_not_affected("2.1", desc) is False


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


def test_prose_quantities_are_not_version_bounds():
    """ "up to 256 bytes" is a quantity. Read as a bound it DROPS the CVE.

    Date-schemed casks have a large leading component, so they cleared these
    phantom bounds routinely — exactly the packages brew resolution added.
    """
    assert dsc._desc_says_not_affected("2024.07.18", "A flaw copies up to 256 bytes.") is False
    assert dsc._desc_says_not_affected("1000.1", "The handler loops through 8 entries.") is False
    assert dsc._desc_says_not_affected("5.0", "Allows up to 2 GB of memory.") is False
    # An explicit version marker still qualifies a single-component bound.
    assert dsc._desc_says_not_affected("4.0", "Foo up to version 3 is vulnerable.") is True


def test_bounds_apply_to_their_own_release_line():
    """ "Django 4.2 before 4.2.11, 5.0 before 5.0.4" — 4.2.15 IS patched.

    Requiring it to clear 5.0.4 as well blocked a patched LTS release.
    """
    django = "Django 4.2 before 4.2.11, 5.0 before 5.0.4 are affected."
    assert dsc._desc_says_not_affected("4.2.15", django) is True
    assert dsc._desc_says_not_affected("4.2.10", django) is False  # below its own bound
    assert dsc._desc_says_not_affected("5.0.1", django) is False
    curl = "curl 8.x before 8.7.1 and 7.x before 7.88.0 are affected."
    assert dsc._desc_says_not_affected("7.90.0", curl) is True
    assert dsc._desc_says_not_affected("8.5.0", curl) is False


def test_no_matching_release_line_falls_back_to_every_bound():
    """The multi-branch fix must not resurrect the first-bound-wins bug."""
    desc = "Foo 9.x before 9.2 and 10.x before 10.1 are affected."
    assert dsc._desc_says_not_affected("10.0", desc) is False  # its own line, not cleared
    assert dsc._desc_says_not_affected("10.1", desc) is True
    assert dsc._desc_says_not_affected("11.0", desc) is True  # above every line
    # A single bound on another line still applies when none names this version.
    assert dsc._desc_says_not_affected("3.5", "Foo before 2.0 is affected.") is True


def test_up_to_and_including_is_inclusive():
    desc = "Foo up to and including 3.0 is vulnerable."
    assert dsc._desc_says_not_affected("3.0", desc) is False
    assert dsc._desc_says_not_affected("3.1", desc) is True


def test_lower_bound_does_not_override_an_inclusive_bound():
    """A description naming both must fail closed."""
    desc = "Introduced in 2.0 of the rewrite. Legacy releases through 1.9 are also affected."
    assert dsc._desc_says_not_affected("1.5", desc) is False
