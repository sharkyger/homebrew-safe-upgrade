"""
Keyword-path relevance heuristic: WHERE the first sentence names the product.

The original rule required the package to be the first words of the first
sentence. That dropped MITRE boilerplate — "An issue was discovered in
<product> ...", "A vulnerability in <product> ..." — and vendor-prefixed
subjects ("GNU Wget does not validate ..."). On the keyword path (the only
path for packages NVD has no CPE for: casks, tap formulae, and any product
whose CPE query answers nothing) there is no CPE query underneath, so the
rejection was a terminal false negative: a real CVE reported as clean.
Found via CVE-2024-41997 (Warp terminal) and CVE-2026-15146 (wget).

Accepting the product anywhere in the first sentence over-corrected: the
live fixture wget@99.99.0 picked up records that name wget as an object of
use ("Applications that use Wget ...", "DEEBOT ... use wget command",
"AVTECH ... due to the use of wget"). The rule is therefore: the product is
the subject (optionally behind one vendor word), or it follows "in" ("in
[the] [version(s) of] <product>"). Object-of-use mentions and mentions only
in later sentences are rejected.
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
        (
            "An issue was discovered in version of Warp Terminal prior to 2024.07.18 "
            "(v0.2024.07.16.08.02). A command injection vulnerability exists in the "
            "Docker integration functionality."
        ),
        "A vulnerability in Warp Terminal allows command injection via a crafted link.",
        "Multiple issues were found in the Warp Terminal 0.2024.x.",
    ],
)
def test_mitre_boilerplate_naming_the_product_after_in_is_accepted(desc):
    assert names(desc, ["warp terminal"])


def test_product_as_subject_is_accepted():
    assert names("wget before 1.25.0 allows attackers to overwrite files.", ["wget"])
    assert names("cmake installs the cmake x86 linux binaries.", ["cmake"])


def test_one_vendor_word_before_the_subject_is_accepted():
    """CVE-2026-15146, verbatim opening — rejected by the original rule."""
    assert names(
        "GNU Wget does not validate the IP address provided by an FTP PASV response "
        "while operating in FTP passive mode.",
        ["wget"],
    )


@pytest.mark.parametrize(
    "desc",
    [
        # records that flagged the live fixture wget@99.99.0 under "anywhere in sentence"
        (
            "Applications that use Wget to access a remote resource using shorthand URLs "
            "and pass arbitrary user credentials in the URL are vulnerable."
        ),
        (
            "DEEBOT PRO M1 and DEEBOT PRO K1VAC use wget command with server certificate "
            "validation disabled."
        ),
        (
            "An improper certificate validation vulnerability exists in AVTECH IP cameras, "
            "DVRs, and NVRs due to the use of wget with --no-check-certificate."
        ),
    ],
)
def test_product_as_object_of_use_is_rejected(desc):
    assert not names(desc, ["wget"])


def test_mention_only_in_a_later_sentence_is_rejected():
    assert not names("Something unrelated happened in Foo. wget is mentioned only here.", ["wget"])


def test_bundled_component_is_rejected():
    assert not names("Foo Browser bundles an outdated copy of curl.", ["curl"])


def test_two_leading_words_do_not_count_as_subject():
    """`Cloudflare WARP client` must not read as the Warp terminal's subject."""
    assert not names(
        "Cloudflare WARP client for Windows allowed a malicious actor.", ["warp terminal"]
    )


def test_boundary_matching_is_preserved():
    """claude-code must not match claude-code-router."""
    assert not names("claude-code-router before 2.0 leaks tokens.", ["claude-code"])


@pytest.mark.parametrize(
    "desc",
    [
        # CVE-2026-14586, verbatim opening — an Unbound bug; the old rule matched
        # the THIRD "in" ("an assertion in libngtcp2") and flagged libngtcp2.
        (
            "In NLnet Labs Unbound 1.22.0 up to and including 1.25.1, in DNS-over-QUIC "
            "environments, with high concurrency and under pressure, an assertion in "
            "libngtcp2 about monotonic timestamps could trigger and result in server "
            "termination and thus denial of service."
        ),
        "A flaw in Foo Proxy allows a crash in libngtcp2 when handling a QUIC frame.",
        "Foo Proxy mishandles a crafted QUIC packet received from a peer in libngtcp2.",
    ],
)
def test_only_the_sentence_leading_in_counts(desc):
    assert not names(desc, ["libngtcp2"])


def test_sentence_leading_in_naming_the_product_is_still_accepted():
    """The same shape, with the product in the leading position, stays a hit."""
    assert names(
        "In libngtcp2 before 1.15.0, in high-concurrency environments, an assertion "
        "in the timestamp check could trigger.",
        ["libngtcp2"],
    )
