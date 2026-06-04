"""Version-comparison regression tests (HIGH-severity scanner bypass).

Guards two bugs in dependency_security_check.py:

1. PEP 440 pre-release drop. The old tuple-based parse_version silently lost
   pre-release suffixes — parse_version('1.0-beta') == parse_version('1.0') —
   so a vulnerable pre-release sorted equal to its release and was judged
   "not affected" against a "fixed in X" range → install/upgrade allowed.
   (Same class caught in composer-cve-gate as Mistral Vibe HIGH #1.)

2. The '=' operator precedence bug. In version_in_range, `or op == "="` was
   unparenthesized, so Python's `and`-binds-tighter-than-`or` made a bare `=N`
   constraint ALWAYS return "not affected" — a vulnerable package pinned with
   `= X` slipped through.

Both are fixed by parsing with a small stdlib pre-release-aware comparator and
parenthesizing the operator block as ((op == "=" or op == "==") and v != ref).
"""

import sys
from pathlib import Path

REPO = Path(__file__).parent.parent
sys.path.insert(0, str(REPO))

import dependency_security_check as dsc  # noqa: E402

# ----------------------- parse_version: PEP 440 -----------------------


def test_prerelease_sorts_below_its_release():
    assert dsc.parse_version("1.0-beta") < dsc.parse_version("1.0")
    assert dsc.parse_version("1.0.0-beta") < dsc.parse_version("1.0.0")
    assert dsc.parse_version("1.0-rc.1") < dsc.parse_version("1.0")
    assert dsc.parse_version("2.0.0a1") < dsc.parse_version("2.0.0")


def test_parse_version_strips_v_and_equals_prefixes():
    assert dsc.parse_version("v1.2.3") == dsc.parse_version("1.2.3")
    assert dsc.parse_version("=1.2.3") == dsc.parse_version("1.2.3")


def test_parse_version_invalid_returns_none():
    assert dsc.parse_version("") is None
    assert dsc.parse_version(None) is None
    assert dsc.parse_version("not-a-version") is None


# ----------------------- the pre-release bypass (HIGH #1) -----------------------


def test_vulnerable_prerelease_below_fix_is_still_affected():
    # "fixed in 1.0": a 1.0-beta pre-release is BELOW 1.0, so still vulnerable.
    assert dsc.version_in_range("1.0-beta", "< 1.0") is True
    assert dsc.version_in_range("1.0.0-rc.1", "< 1.0.0") is True


def test_release_at_or_above_fix_is_not_affected():
    assert dsc.version_in_range("1.0", "< 1.0") is False
    assert dsc.version_in_range("1.1", "< 1.0") is False


# ----------------------- the '=' operator bug (HIGH #2) -----------------------


def test_equals_operator_affects_only_the_exact_version():
    assert dsc.version_in_range("1.2.3", "= 1.2.3") is True
    assert dsc.version_in_range("1.2.4", "= 1.2.3") is False
    assert dsc.version_in_range("1.2.2", "= 1.2.3") is False


def test_double_equals_operator():
    assert dsc.version_in_range("1.2.3", "== 1.2.3") is True
    assert dsc.version_in_range("1.2.4", "== 1.2.3") is False


def test_not_equals_operator():
    assert dsc.version_in_range("1.2.3", "!= 1.2.3") is False
    assert dsc.version_in_range("1.2.4", "!= 1.2.3") is True


# ----------------------- ranges + fail-closed -----------------------


def test_compound_range_boundaries():
    assert dsc.version_in_range("1.5", ">= 1.0, < 2.0") is True
    assert dsc.version_in_range("2.5", ">= 1.0, < 2.0") is False
    assert dsc.version_in_range("0.5", ">= 1.0, < 2.0") is False


def test_empty_inputs_fail_closed_affected():
    assert dsc.version_in_range("", "< 1.0") is True
    assert dsc.version_in_range("1.0", "") is True


def test_unparseable_constraint_fails_closed_affected():
    # A constraint the scanner can't disprove must not mark the package clean.
    assert dsc.version_in_range("1.2.3", "< not-a-version") is True


# ----------------------- explicit pre-release ordering -----------------------


def test_prerelease_marker_ordering_dev_alpha_beta_rc_final():
    order = ["1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0"]
    parsed = [dsc.parse_version(s) for s in order]
    for lo, hi in zip(parsed, parsed[1:], strict=False):
        assert lo < hi, f"{order}: {lo} should sort below {hi}"


def test_prerelease_number_ordering():
    assert dsc.parse_version("1.0rc1") < dsc.parse_version("1.0rc2")
    assert dsc.parse_version("1.0a2") < dsc.parse_version("1.0b1")


def test_prerelease_spelling_equivalence():
    assert dsc.parse_version("1.0alpha1") == dsc.parse_version("1.0a1")
    assert dsc.parse_version("1.0beta2") == dsc.parse_version("1.0b2")
    assert dsc.parse_version("1.0c1") == dsc.parse_version("1.0rc1")


def test_trailing_zero_equivalence():
    assert dsc.parse_version("1.0") == dsc.parse_version("1.0.0")
    assert dsc.parse_version("1") == dsc.parse_version("1.0.0")
    assert dsc.parse_version("1.2") < dsc.parse_version("1.2.1")


def test_homebrew_revision_and_build_metadata_ignored_for_order():
    assert dsc.parse_version("3.5.0_1") == dsc.parse_version("3.5.0")
    assert dsc.parse_version("1.2.3+build9") == dsc.parse_version("1.2.3")


# ----------------------- more '=' / range edge cases -----------------------


def test_equals_with_prerelease_target():
    assert dsc.version_in_range("1.0rc1", "= 1.0rc1") is True
    assert dsc.version_in_range("1.0", "= 1.0rc1") is False


def test_hyphenated_prerelease_constraint_is_captured():
    # The constraint regex must not truncate a hyphenated pre-release ref to its
    # numeric part — "= 1.0-beta" must match exactly 1.0-beta, not 1.0.
    assert dsc.version_in_range("1.0-beta", "= 1.0-beta") is True
    assert dsc.version_in_range("1.0", "= 1.0-beta") is False
    assert dsc.version_in_range("1.0-alpha", "= 1.0-beta") is False
    # "< 1.0-beta": a 1.0-alpha pre-release is below the beta → affected.
    assert dsc.version_in_range("1.0-alpha", "< 1.0-beta") is True


def test_prerelease_below_fix_in_compound_range_is_affected():
    # A 1.2.5 pre-release is below the "fixed in 1.2.5" boundary → still affected.
    assert dsc.version_in_range("1.2.5rc1", ">= 1.0, < 1.2.5") is True
    # The final 1.2.5 is the fix → not affected.
    assert dsc.version_in_range("1.2.5", ">= 1.0, < 1.2.5") is False


# ----------------------- unrecognized suffix: fail closed, don't coerce to final ----------


def test_unrecognized_alpha_suffix_fails_closed_not_coerced_to_final():
    # An unmodelled pre-release spelling must NOT sort as the final release (that
    # would let "1.0-SNAPSHOT" bypass a "< 1.0" range). It fails closed instead.
    assert dsc.parse_version("1.0-SNAPSHOT") is None
    assert dsc.parse_version("1.0foo") is None
    assert dsc.parse_version("1.0.post1") is None
    assert dsc.parse_version("1.0.") is None
    # The bypass is closed: 1.0-SNAPSHOT is treated as affected by "< 1.0".
    assert dsc.version_in_range("1.0-SNAPSHOT", "< 1.0") is True


def test_homebrew_numeric_patch_suffix_keeps_base_release():
    # Real Homebrew/upstream versions like imagemagick "7.1.2-19" are a build of
    # the release, not a pre-release — keep the base ranking (must NOT fail closed).
    assert dsc.parse_version("7.1.2-19") == dsc.parse_version("7.1.2")
    assert dsc.version_in_range("7.1.2-19", "< 7.1.3") is True  # below the fix
    assert dsc.version_in_range("7.1.2-19", "< 7.1.2") is False  # at/above the base
