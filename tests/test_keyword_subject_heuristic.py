"""
Keyword-path relevance heuristic: product named in the FIRST SENTENCE.

The original rule required the package to be the first words of the first
sentence. MITRE boilerplate — "An issue was discovered in <product> ...",
"A vulnerability in <product> ..." — fails that, and on the keyword path
(the only path for packages NVD has no CPE for: casks, tap formulae) there is
no CPE query underneath, so the rejection is a terminal false negative: a
real CVE reported as clean. Found via CVE-2024-41997 (Warp terminal) while
fixing the Cloudflare WARP collision.

Trade-off, made deliberately: a first sentence that names the package as a
bundled component ("Foo Browser bundles an outdated copy of curl") now flags
for curl — an over-block, in the fail-safe direction, still subject to the
version-range filter. Mentions only in later sentences stay rejected.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import dependency_security_check as dsc  # noqa: E402

names = dsc._desc_names_this_package


@pytest.mark.parametrize(
    "desc",
    [
        # CVE-2024-41997, verbatim opening
        "An issue was discovered in version of Warp Terminal prior to 2024.07.18 "
        "(v0.2024.07.16.08.02). A command injection vulnerability exists in the "
        "Docker integration functionality.",
        "A vulnerability in Warp Terminal allows command injection via a crafted link.",
        "Multiple issues were found in Warp Terminal 0.2024.x.",
    ],
)
def test_mitre_boilerplate_naming_the_product_is_accepted(desc):
    assert names(desc, ["warp terminal"])


def test_product_as_first_words_still_accepted():
    assert names("wget before 1.25.0 allows attackers to overwrite files.", ["wget"])
    assert names("cmake installs the cmake x86 linux binaries.", ["cmake"])


def test_mention_only_in_a_later_sentence_is_still_rejected():
    assert not names("Something unrelated happened in Foo. wget is mentioned only here.", ["wget"])


def test_bundled_component_in_first_sentence_now_flags_fail_safe():
    """Documented trade-off: over-block rather than silent clean."""
    assert names("Foo Browser bundles an outdated copy of curl.", ["curl"])


def test_boundary_matching_is_preserved():
    """claude-code must not match claude-code-router."""
    assert not names("claude-code-router before 2.0 leaks tokens.", ["claude-code"])
