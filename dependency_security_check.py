#!/usr/bin/env python3
"""
Dependency Security Check — queries 3 vulnerability databases before any install.

Sources:
  1. OSV.dev (Google) — primary, supports version filtering natively
  2. GitHub Advisory Database — supports version filtering via vulnerable_version_range
  3. NIST NVD — keyword search, filtered by CPE version match when available

Usage:
  python3 dependency_security_check.py <ecosystem> <package_name> [version]

Ecosystems: pip, npm, composer, cargo, go, maven, gem, brew
Exit codes: 0 = clean, 1 = vulnerabilities found, 2 = error

No API keys required. All three databases are free and public.
"""

import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# Build SSL context — use certifi bundle if available (needed on macOS)
try:
    import certifi

    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CONTEXT = ssl.create_default_context()

USER_AGENT = "homebrew-safe-upgrade/1.0"

# Cask token → NVD search keyword.
# Imported as a module so the curated list lives in cask_nvd_map.py and
# can be reviewed/diffed independently of scanner logic. Empty fallback
# keeps the scanner working if the map file is absent at runtime.
try:
    from cask_nvd_map import CASK_NVD_KEYWORDS
except ImportError:
    CASK_NVD_KEYWORDS = {}


def _urlopen(req, timeout=15):
    """Open URL with proper SSL context."""
    return urllib.request.urlopen(req, timeout=timeout, context=SSL_CONTEXT)


# Map ecosystem names to each source's expected format
ECOSYSTEM_MAP = {
    "osv": {
        "pip": "PyPI",
        "npm": "npm",
        "composer": "Packagist",
        "cargo": "crates.io",
        "go": "Go",
        "maven": "Maven",
        "gem": "RubyGems",
        "brew": None,
    },
    "github": {
        "pip": "pip",
        "npm": "npm",
        "composer": "composer",
        "cargo": "rust",
        "go": "go",
        "maven": "maven",
        "gem": "rubygems",
        "brew": None,
    },
}

# Distro-specific CPE vendors whose package versions don't match upstream.
# Deliberately NOT "oracle": Oracle is also the upstream vendor of widely
# brewed software (mysql, openjdk, virtualbox — cpe:2.3:a:oracle:mysql:*),
# so skipping it would hide real upstream CVEs. Oracle Linux distro CPEs
# are OS-type (cpe:2.3:o:...) and are already filtered by the part check.
DISTRO_VENDORS = {
    "opensuse",
    "suse",
    "redhat",
    "debian",
    "ubuntu",
    "canonical",
    "fedoraproject",
    "centos",
}

# CPE 2.3 `target_sw` values that scope an advisory to a language-package
# ecosystem. NVD keyword search matches on text, so a package can collide
# with a same-named package from another ecosystem (e.g. the npm "cmake"
# package, cpe:2.3:a:cmake_project:cmake:-:*:*:*:*:node.js:*:*, vs the
# canonical cmake formula). A vulnerable CPE whose target_sw belongs to a
# DIFFERENT ecosystem than the one being checked is not about this package.
ECOSYSTEM_TARGET_SW = {
    "npm": {"node.js", "nodejs", "npm"},
    "pip": {"python"},
    "gem": {"ruby", "rails", "rubygems"},
    "composer": {"php"},
    "cargo": {"rust"},
    "go": {"go", "golang"},
    "maven": {"java", "maven"},
    "brew": set(),
}
_ALL_ECOSYSTEM_TARGET_SW = set().union(*ECOSYSTEM_TARGET_SW.values())


def _foreign_target_sw(target_sw, ecosystem):
    """True if a CPE's target_sw pins it to a DIFFERENT language ecosystem.

    Generic values (*, -, empty) and values we don't recognize as a language
    ecosystem are never foreign — only a positive match against another
    ecosystem's known target_sw set disqualifies a CPE (fail closed).
    """
    if target_sw in ("*", "-", ""):
        return False
    own = ECOSYSTEM_TARGET_SW.get(ecosystem, set())
    return target_sw in _ALL_ECOSYSTEM_TARGET_SW and target_sw not in own


def resolve_latest_version(package_name, ecosystem):
    """Resolve the latest version of a package from its registry."""
    try:
        if ecosystem == "pip":
            url = f"https://pypi.org/pypi/{urllib.parse.quote(package_name)}/json"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            return data.get("info", {}).get("version")
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{urllib.parse.quote(package_name)}/latest"
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with _urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
            return data.get("version")
    except Exception:
        return None
    return None


# Pre-release-aware version comparison (a focused PEP 440 subset, stdlib only).
# This tool ships as bash + stdlib Python with no pip-installed dependencies and
# no virtualenv, so we carry just enough version logic to compare correctly for
# CVE range matching rather than take a runtime dependency on `packaging`
# (Homebrew's python is externally-managed and lacks it, which would fail-close
# the whole tool). Behaviour is pinned by tests/test_version_validation.py.
#
# Handles: dotted numeric releases with trailing-zero equivalence (1.0 == 1.0.0),
# and pre-release suffixes that sort BELOW their release and among themselves
# (dev < alpha < beta < rc < final), e.g. 1.0-beta < 1.0, 1.0a1 < 1.0b1 < 1.0rc1.
# Homebrew revisions (3.5.0_1) and build metadata (+meta) are ignored for order.
# This replaces an earlier tuple parser that DROPPED pre-release suffixes, so a
# vulnerable pre-release sorted == its release and was wrongly judged
# not-affected against a "fixed in X" range (HIGH bypass).
_PRE_RANK = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "pre": 3,
    "preview": 3,
    "rc": 3,
    "c": 3,
}
_FINAL_RANK = 99  # a final release outranks every pre-release of the same number


class _Version:
    """A comparable version key. Build only via parse_version() (which returns
    None on unparseable input — callers fail closed on None)."""

    __slots__ = ("_key",)

    def __init__(self, release, pre, post=0):
        # pre is (rank, num) for a pre-release, or None for a final release.
        # post is a POST-release ordinal (OpenSSH portmarks: 10.3 < 10.3p1 <
        # 10.3p2). It sorts after the pre-release component so a portable build
        # outranks its base release without disturbing pre-release ordering.
        self._key = (release, pre if pre is not None else (_FINAL_RANK, 0), post)

    def __eq__(self, other):
        return isinstance(other, _Version) and self._key == other._key

    def __lt__(self, other):
        return self._key < other._key

    def __le__(self, other):
        return self._key <= other._key

    def __gt__(self, other):
        return self._key > other._key

    def __ge__(self, other):
        return self._key >= other._key

    def __hash__(self):
        return hash(self._key)


def parse_version(v):
    """Parse a version string into a comparable _Version, or None if unparseable.

    Pre-release-aware (1.0-beta < 1.0); returns None on empty/garbage so callers
    can fail closed. Use the _ver_lt / _ver_le / _ver_gt / _ver_ge helpers for
    None-safe relational comparisons (a bare `_Version < None` would raise).
    """
    if not v:
        return None
    s = re.sub(r"^[v=]+", "", str(v).strip())
    # Drop Homebrew revision (_N) and build metadata (+meta) before parsing.
    s = s.split("+", 1)[0].split("_", 1)[0]
    # Bare build-number versions: llama.cpp ships `b3427` upstream and NVD
    # records its CPE bounds in that form, while Homebrew installs the same
    # build with the prefix stripped ("10250"). Only a WHOLE string of `b` +
    # digits qualifies — a real pre-release always carries a release part in
    # front of it ("1.0b1"), which the pre-release branch below still handles.
    # Without this, every b-prefixed bound was unparseable, so _ver_* returned
    # False and the range check flagged every build (issue #109).
    bm = re.match(r"^b(\d+)$", s)
    if bm:
        return _Version((int(bm.group(1)),), None)
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", s)
    if not m:
        return None
    release = tuple(int(x) for x in m.group(1).split("."))
    # Trailing-zero equivalence: 1.0 == 1.0.0 == 1.
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]
    pre = None
    post = 0
    tail = m.group(2)
    if tail:
        # OpenSSH portmark: "10.3p1" is the first PORTABLE build OF 10.3, not a
        # pre-release of it. It must sort ABOVE 10.3 (it contains everything
        # 10.3 does) but below 10.3p2, so a CVE fixed in a later portable build
        # still matches. Previously "p1" matched neither branch below and fell
        # through to the fail-closed `return None`, which made every openssh
        # comparison False and flagged the package on ancient CVEs (issue #94).
        portmark = re.match(r"^p(\d+)$", tail)
        if portmark:
            return _Version(release, None, int(portmark.group(1)))
        pm = re.match(
            r"[-_.]?(dev|alpha|beta|preview|pre|rc|a|b|c)[-_.]?(\d*)",
            tail,
            re.IGNORECASE,
        )
        if pm:
            pre = (_PRE_RANK[pm.group(1).lower()], int(pm.group(2)) if pm.group(2) else 0)
        elif not re.match(r"^[-_.]?\d", tail):
            # A non-numeric, unrecognized suffix (e.g. "-SNAPSHOT", "-milestone",
            # "1.0foo", "1.0.post1", a trailing "1.0.") may be a pre-release
            # spelling we don't model. Fail closed (return None -> treated as
            # affected) rather than coerce it to a FINAL release and risk
            # *under*-flagging a vulnerable pre-release. A trailing NUMERIC patch
            # (Homebrew upstream versions like "7.1.2-19") keeps the base-release
            # ranking, since it is a build of — not a pre-release of — the release.
            return None
    return _Version(release, pre, post)


def _ver_lt(a, b):
    """parse_version(a) < parse_version(b); False (fail-closed) if either is unparseable."""
    va, vb = parse_version(a), parse_version(b)
    return va is not None and vb is not None and va < vb


def _ver_le(a, b):
    """parse_version(a) <= parse_version(b); False if either is unparseable."""
    va, vb = parse_version(a), parse_version(b)
    return va is not None and vb is not None and va <= vb


def _ver_gt(a, b):
    """parse_version(a) > parse_version(b); False if either is unparseable."""
    va, vb = parse_version(a), parse_version(b)
    return va is not None and vb is not None and va > vb


def _ver_ge(a, b):
    """parse_version(a) >= parse_version(b); False if either is unparseable."""
    va, vb = parse_version(a), parse_version(b)
    return va is not None and vb is not None and va >= vb


def version_in_range(version, range_str):
    """Check if a version falls within a vulnerable version range.

    Supports GitHub Advisory range format: "< 1.2.3", ">= 1.0, < 2.0", etc.
    Returns True if the version IS affected (vulnerable).
    """
    if not version or not range_str:
        return True  # Can't determine — assume affected for safety

    v = parse_version(version)
    if not v:
        return True

    conditions = [c.strip() for c in range_str.split(",")]

    for cond in conditions:
        cond = cond.strip()
        if not cond:
            continue

        # Ref may carry a pre-release suffix (incl. hyphenated, e.g. "1.0-beta"):
        # capture word chars, dots, plus and hyphen so parse_version sees the
        # full pre-release — otherwise "= 1.0-beta" would truncate to "1.0".
        m = re.match(r"([<>=!]+)\s*([\d][\w.+-]*)", cond)
        if not m:
            if parse_version(cond) == v:
                return True
            continue

        op, ref_str = m.group(1), m.group(2)
        ref = parse_version(ref_str)
        # Fail-closed: an unparseable constraint reference means we can't
        # disprove vulnerability, so treat the version as affected.
        if ref is None:
            return True

        if (
            (op == "<" and not (v < ref))
            or (op == "<=" and not (v <= ref))
            or (op == ">" and not (v > ref))
            or (op == ">=" and not (v >= ref))
            or ((op == "=" or op == "==") and v != ref)
            or (op == "!=" and v == ref)
        ):
            return False

    return True


def query_osv(package_name, ecosystem, version=None):
    """Query OSV.dev — supports native version filtering."""
    findings: list[dict[str, Any]] = []
    osv_ecosystem = ECOSYSTEM_MAP["osv"].get(ecosystem)
    if not osv_ecosystem:
        return findings

    try:
        payload = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
        if version:
            payload["version"] = version
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with _urlopen(req) as resp:
            data = json.loads(resp.read())

        for vuln in data.get("vulns", []):
            severity_info = vuln.get("database_specific", {})
            severity = severity_info.get("severity", "UNKNOWN")

            for s in vuln.get("severity", []):
                if s.get("type") == "CVSS_V3" and "CRITICAL" in str(severity_info):
                    severity = "CRITICAL"

            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", "unknown"))

            findings.append(
                {
                    "source": "OSV.dev",
                    "id": cve_id,
                    "severity": severity,
                    "score": 0,
                    "summary": vuln.get("summary", "No summary")[:200],
                }
            )
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        findings.append(
            {
                "source": "OSV.dev",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
            }
        )
    return findings


def query_github(package_name, ecosystem, version=None):
    """Query GitHub Advisory Database — filter by affected version range."""
    findings: list[dict[str, Any]] = []
    gh_ecosystem = ECOSYSTEM_MAP["github"].get(ecosystem)
    if not gh_ecosystem:
        return findings

    try:
        url = (
            f"https://api.github.com/advisories"
            f"?ecosystem={urllib.parse.quote(gh_ecosystem)}"
            f"&affects={urllib.parse.quote(package_name)}"
            f"&per_page=20"
        )
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT},
        )
        with _urlopen(req) as resp:
            data = json.loads(resp.read())

        for adv in data:
            severity = adv.get("severity", "unknown").upper()

            if version:
                not_affected = False
                for vuln_pkg in adv.get("vulnerabilities", []):
                    pkg_info = vuln_pkg.get("package", {})
                    if pkg_info.get("name", "").lower() != package_name.lower():
                        continue
                    vrange = vuln_pkg.get("vulnerable_version_range", "")
                    patched = vuln_pkg.get("first_patched_version")
                    if isinstance(patched, dict):
                        patched_ver = patched.get("identifier")
                    elif isinstance(patched, str):
                        patched_ver = patched
                    else:
                        patched_ver = None

                    if patched_ver and _ver_ge(version, patched_ver):
                        not_affected = True
                        break

                    if vrange and not version_in_range(version, vrange):
                        not_affected = True
                        break

                if not_affected:
                    continue

            findings.append(
                {
                    "source": "GitHub Advisory",
                    "id": adv.get("ghsa_id") or adv.get("cve_id", "unknown"),
                    "severity": severity,
                    "score": 0,
                    "summary": adv.get("summary", "No summary")[:200],
                }
            )
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        findings.append(
            {
                "source": "GitHub Advisory",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
            }
        )
    return findings


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# One CPE-matched page holds every CVE for a specific product+version in
# practice (openssh 10.3p1 -> 8, postgresql 16.0 -> 22). The cap is a runaway
# guard, not an expected limit; _nvd_fetch reports when it truncates so the
# caller can refuse to call a truncated result "clean".
NVD_PAGE_SIZE = 200
NVD_MAX_PAGES = 5


def _nvd_cpe_products(package_name, ecosystem):
    """CPE product-name candidates for a package, most specific first.

    Homebrew versioned formulae (`openssl@3`, `python@3.11`, `node@20`) carry a
    suffix that appears in no CPE and in no CVE description, so the raw name
    matched nothing and the package came back clean. The base name is tried
    after the literal one so `openssl@3` still resolves via `openssl`.
    """
    if ecosystem == "brew" and package_name in CASK_NVD_KEYWORDS:
        # A curated cask mapping is authoritative: the slug (`brave-browser`)
        # is exactly what does NOT identify the product, so trying it as a CPE
        # product name is a wasted request against a rate-limited API.
        return [CASK_NVD_KEYWORDS[package_name].lower().replace(" ", "_")]
    candidates = [package_name.lower()]
    base = package_name.split("@", 1)[0].lower()
    candidates.append(base)
    seen = set()
    ordered = []
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            ordered.append(c)
    return ordered


def _nvd_fetch(params):
    """Fetch all pages for an NVD query.

    Returns (cve_records, total_results, truncated).
    """
    records = []
    total = 0
    truncated = False
    start = 0
    for _ in range(NVD_MAX_PAGES):
        url = f"{NVD_API}?{params}&resultsPerPage={NVD_PAGE_SIZE}&startIndex={start}"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with _urlopen(req) as resp:
            data = json.loads(resp.read())
        total = data.get("totalResults", 0)
        page = data.get("vulnerabilities", [])
        records.extend(page)
        start += len(page)
        if not page or start >= total:
            break
    else:
        truncated = start < total
    return records, total, truncated


def _nvd_applicable_cpes(cve, ecosystem, products=()):
    """Vulnerable CPE matches that are actually about this package/ecosystem.

    Returns (relevant_cpes, has_any_cpe). Distro- and OS-scoped applicability
    and CPEs pinned by target_sw to a foreign language ecosystem don't count.

    When at least one CPE positively names OUR product, only those CPEs are
    kept. CVE-2012-4233 lists 26 `libreoffice:libreoffice` CPEs (all bounded by
    versionEndIncluding 3.6, so 26.2.4 is out of range) plus one
    `sun:openoffice.org:-` with no version at all. The version-less CPE of a
    DIFFERENT product was read as "affects every version" and kept the CVE
    alive against LibreOffice 26.2.4 (issue #95).

    The narrowing is deliberately conditional. Brew formula names and CPE
    product names disagree often enough (`node` vs `node.js`) that filtering
    unconditionally would silently drop every CPE for such a package, and a CVE
    with no surviving CPE is dropped entirely — turning a precision fix into a
    fail-OPEN. So we narrow only on a positive match and otherwise keep the
    full set, exactly as before.
    """
    relevant_cpes = []
    own_product_cpes = []
    has_any_cpe = False
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if not cpe.get("vulnerable", False):
                    continue
                has_any_cpe = True
                # cpe:2.3:part:vendor:product:version:update:edition:
                #   language:sw_edition:target_sw:target_hw:other
                cpe_parts = cpe.get("criteria", "").split(":")
                if len(cpe_parts) >= 5:
                    cpe_type = cpe_parts[2].lower()  # a=app, o=os, h=hw
                    cpe_vendor = cpe_parts[3].lower()
                    # OS-type CPEs are distro packages, not upstream
                    if cpe_type == "o":
                        continue
                    if cpe_vendor in DISTRO_VENDORS:
                        continue
                if len(cpe_parts) >= 11 and _foreign_target_sw(cpe_parts[10].lower(), ecosystem):
                    continue
                relevant_cpes.append(cpe)
                if products and len(cpe_parts) >= 5 and cpe_parts[4].lower() in products:
                    own_product_cpes.append(cpe)
    if own_product_cpes:
        return own_product_cpes, has_any_cpe
    return relevant_cpes, has_any_cpe


def _cpe_version_affected(version, relevant_cpes):
    """Is `version` inside any vulnerable range of these CPE matches?"""
    affected = False
    for cpe in relevant_cpes:
        ver_end_exc = cpe.get("versionEndExcluding")
        ver_end_inc = cpe.get("versionEndIncluding")
        ver_start_inc = cpe.get("versionStartIncluding")
        ver_start_exc = cpe.get("versionStartExcluding")

        if ver_end_exc or ver_end_inc or ver_start_inc or ver_start_exc:
            # Range-based CPE — check if our version falls within
            in_range = True
            if ver_start_inc and _ver_lt(version, ver_start_inc):
                in_range = False
            if ver_start_exc and _ver_le(version, ver_start_exc):
                in_range = False
            if ver_end_exc and _ver_ge(version, ver_end_exc):
                in_range = False
            if ver_end_inc and _ver_gt(version, ver_end_inc):
                in_range = False
            if in_range:
                affected = True
        else:
            # Exact version match — extract from CPE URI
            # Format: cpe:2.3:a:vendor:product:VERSION:...
            cpe_parts = cpe.get("criteria", "").split(":")
            if len(cpe_parts) >= 6:
                cpe_ver = cpe_parts[5]
                if cpe_ver in ("*", "-", ""):
                    affected = True  # Wildcard — can't determine
                elif parse_version(version) == parse_version(cpe_ver):
                    affected = True
    return affected


def _desc_says_not_affected(version, desc):
    """Description-derived version bounds, used only when a CVE has no CPE data.

    GitHub-style advisories often read "Starting in version X and prior to
    version Y". Returns True when the description positively rules the version
    out; ambiguity returns False (fail closed — the CVE stays).
    """
    v_re = r"(?:version\s+)?v?([\d]+(?:\.[\d]+)*)"

    # Exclusive upper bound: fixed at the matched version
    end_exc = re.search(
        rf"(?:before|prior to|fixed in|patched in)\s+{v_re}",
        desc,
        re.IGNORECASE,
    )
    if end_exc and _ver_ge(version, end_exc.group(1)):
        return True  # version is at or above the fix — not affected

    # Inclusive upper bound: last affected version
    end_inc = re.search(rf"\bthrough\s+{v_re}", desc, re.IGNORECASE)
    if end_inc and _ver_gt(version, end_inc.group(1)):
        return True

    # Lower bound: affected starts at this version
    start_inc = re.search(
        rf"(?:starting in|introduced in|since)\s+{v_re}",
        desc,
        re.IGNORECASE,
    )
    return bool(start_inc and _ver_lt(version, start_inc.group(1)))


def _desc_names_this_package(desc, match_terms):
    """Keyword-path relevance heuristic: is the CVE really about this package?

    NVD keyword search matches free text, so "cmake" hits the npm package of
    that name. This is a NOISE filter for keyword results only — CPE-matched
    results are already pinned to the product and must NOT be run through it
    (CVE-2024-3094's description opens "Malicious code was discovered in the
    upstream tarballs of xz", whose first word is not the package name).
    """
    desc_lower = desc.lower()

    # Boundary matching that prevents "claude-code" from matching
    # "claude-code-router" — hyphens connect compound package names, so the
    # match must not be followed or preceded by [-\w]. For mapped casks, any
    # of the match_terms ("brave browser" + "brave-browser") qualifies.
    matched_term = None
    for term in match_terms:
        term_nodash = term.replace("-", "")
        term_re = re.compile(r"(?<![a-z0-9\-])" + re.escape(term) + r"(?![a-z0-9\-])")
        term_nodash_re = re.compile(r"(?<![a-z0-9])" + re.escape(term_nodash) + r"(?![a-z0-9])")
        if term_re.search(desc_lower) or term_nodash_re.search(desc_lower):
            matched_term = term
            break
    if matched_term is None:
        return False

    # Reject if the first sentence names a different product as the subject.
    first_sentence = (
        desc.split(". ")[0].split(" is ")[0].split(" before ")[0].split(" through ")[0].strip()
    )
    sentence_words = first_sentence.split()
    term_word_count = len(matched_term.split())
    first_chunk = " ".join(sentence_words[:term_word_count]).lower()
    matched_nodash = matched_term.replace("-", "")
    matched_re = re.compile(r"(?<![a-z0-9\-])" + re.escape(matched_term) + r"(?![a-z0-9\-])")
    matched_nodash_re = re.compile(r"(?<![a-z0-9])" + re.escape(matched_nodash) + r"(?![a-z0-9])")
    return (
        first_chunk in (matched_term, matched_nodash)
        or bool(matched_re.search(first_chunk))
        or bool(matched_nodash_re.search(first_chunk))
    )


def _nvd_cve_to_finding(vuln, ecosystem, version, match_terms, require_desc_match, products=()):
    """Turn one NVD record into a finding dict, or None if it doesn't apply."""
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "unknown")

    # Skip disputed CVEs — upstream doesn't consider them valid
    vuln_status = cve.get("vulnStatus", "")
    if "DISPUTED" in vuln_status.upper() or "REJECTED" in vuln_status.upper():
        return None

    desc_list = cve.get("descriptions", [])
    desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")

    # Skip CVEs explicitly marked as disputed in description
    if desc.strip().startswith("** DISPUTED **"):
        return None

    if require_desc_match and not _desc_names_this_package(desc, match_terms):
        return None

    severity = "UNKNOWN"
    score = 0.0
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            cvss = metrics[0].get("cvssData", {})
            severity = cvss.get("baseSeverity", severity)
            score = cvss.get("baseScore", score)
            break

    relevant_cpes, has_any_cpe = _nvd_applicable_cpes(cve, ecosystem, products)

    # Every applicability statement points at a distro, an OS, or a different
    # ecosystem — the CVE is not about the package we're checking. (A CVE with
    # even ONE generic/relevant CPE stays in: ambiguity counts as affected.)
    if has_any_cpe and not relevant_cpes:
        return None

    if version:
        if relevant_cpes and not _cpe_version_affected(version, relevant_cpes):
            return None
        if not relevant_cpes and _desc_says_not_affected(version, desc):
            return None

    return {
        "source": "NIST NVD",
        "id": cve_id,
        "severity": severity,
        "score": score,
        "summary": desc[:200],
    }


def query_nvd(package_name, ecosystem, version=None):
    """Query NIST NVD, CPE-first.

    The previous implementation used keyword search with resultsPerPage=10 and
    no pagination. NVD returns oldest-first, so for any established package the
    tool only ever saw its TEN OLDEST CVEs — openssh has 177, libreoffice 109.
    That single fact produced both halves of the bug reports:

      * false positives — the only CVEs ever considered were prehistoric ones
        (CVE-2001-0529 for openssh 10.3p1, CVE-2012-4233 for libreoffice
        26.2.4, issues #94/#95), which then survived because the version
        comparison could not parse the bounds either;
      * false negatives nobody could see — openssh 10.3p1 is named by eight
        current CVEs that sit far past result #10 and were never fetched.

    A CPE query (`virtualMatchString`) asks NVD for the CVEs that apply to a
    specific product AND version, so the result set is small, complete, and
    already scoped — 8 records for openssh instead of the wrong 10 of 177. The
    keyword path is kept as a fallback for packages NVD has no CPE for, now
    paginated, and it alone runs the description-relevance heuristic.
    """
    findings: list[dict[str, Any]] = []

    # `match_terms` is what the keyword-path description filter accepts as
    # proof the CVE is about this package. Original `package_name` stays for
    # logging.
    search_name = package_name
    match_terms = [package_name.lower()]
    if ecosystem == "brew" and package_name in CASK_NVD_KEYWORDS:
        mapped_keyword = CASK_NVD_KEYWORDS[package_name]
        search_name = mapped_keyword
        match_terms = [mapped_keyword.lower(), package_name.lower()]
    base_name = package_name.split("@", 1)[0]
    if base_name.lower() != package_name.lower():
        match_terms.append(base_name.lower())

    products = _nvd_cpe_products(package_name, ecosystem)

    try:
        records = []
        matched_via_cpe = False
        truncated = False

        for product in products:
            if version:
                vm = f"cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
            else:
                vm = f"cpe:2.3:a:*:{product}"
            params = f"virtualMatchString={urllib.parse.quote(vm)}"
            records, total, truncated = _nvd_fetch(params)
            if total:
                matched_via_cpe = True
                break

        if not matched_via_cpe:
            # No CPE for this product+version. Fall back to keyword search.
            # The <4-character guard that used to sit here skipped the query
            # outright for xz, git, vim, php and zsh — for `brew`, where NVD is
            # the only source, that meant those packages were NEVER checked and
            # always reported clean. Keyword noise is handled by the
            # description filter below, not by refusing to look.
            params = f"keywordSearch={urllib.parse.quote(search_name)}&keywordExactMatch"
            records, _total, truncated = _nvd_fetch(params)

        for vuln in records:
            finding = _nvd_cve_to_finding(
                vuln,
                ecosystem,
                version,
                match_terms,
                require_desc_match=not matched_via_cpe,
                products=products,
            )
            if finding is not None:
                findings.append(finding)

        if truncated:
            # We stopped paging before the end. A "no vulnerabilities" verdict
            # built on a partial result set would be a guess, so report the gap
            # as a source failure and let the caller fail closed.
            findings.append(
                {
                    "source": "NIST NVD",
                    "id": "ERROR",
                    "severity": "UNKNOWN",
                    "score": 0,
                    "summary": (
                        f"Result set exceeded {NVD_PAGE_SIZE * NVD_MAX_PAGES} records; "
                        "coverage incomplete"
                    ),
                }
            )
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
        findings.append(
            {
                "source": "NIST NVD",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
            }
        )
    return findings


def deduplicate(findings):
    """Remove duplicate CVEs reported by multiple sources."""
    seen = set()
    unique = []
    for f in findings:
        if f["id"] in ("ERROR", "SKIP"):
            unique.append(f)
            continue
        if f["id"] not in seen:
            seen.add(f["id"])
            unique.append(f)
        else:
            for u in unique:
                if u["id"] == f["id"]:
                    u["source"] += f" + {f['source']}"
                    break
    return unique


def main():
    if len(sys.argv) < 3:
        print(
            "Usage: dependency_security_check.py <ecosystem> <package> [version]",
            file=sys.stderr,
        )
        sys.exit(2)

    ecosystem = sys.argv[1].lower()
    package_name = sys.argv[2]
    version = sys.argv[3] if len(sys.argv) > 3 else None

    # Input validation — prevent SSRF via crafted package names
    if not re.match(r"^[a-zA-Z0-9@._/\-]+$", package_name):
        print(f"Invalid package name: {package_name}", file=sys.stderr)
        sys.exit(2)
    if version and not re.match(r"^[a-zA-Z0-9._\-+]+$", version):
        print(f"Invalid version: {version}", file=sys.stderr)
        sys.exit(2)

    valid_ecosystems = ["pip", "npm", "composer", "cargo", "go", "maven", "gem", "brew"]
    if ecosystem not in valid_ecosystems:
        print(
            f"Unknown ecosystem: {ecosystem}. Valid: {', '.join(valid_ecosystems)}",
            file=sys.stderr,
        )
        sys.exit(2)

    if not version:
        version = resolve_latest_version(package_name, ecosystem)

    print(f"\nSecurity check: {package_name} ({ecosystem})", file=sys.stderr)
    if version:
        print(f"  Version: {version}", file=sys.stderr)
    else:
        print("  Version: unknown (checking all known CVEs)", file=sys.stderr)
    print(
        "  Querying 3 vulnerability databases (NVD + OSV + GitHub)...\n",
        file=sys.stderr,
    )

    all_findings = []
    all_findings.extend(query_osv(package_name, ecosystem, version))
    all_findings.extend(query_github(package_name, ecosystem, version))
    all_findings.extend(query_nvd(package_name, ecosystem, version))

    errors = [f for f in all_findings if f["id"] in ("ERROR", "SKIP")]
    vulns = [f for f in all_findings if f["id"] not in ("ERROR", "SKIP")]
    vulns = deduplicate(vulns)

    severity_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "MODERATE": 3,
        "UNKNOWN": 4,
    }
    vulns.sort(key=lambda f: severity_order.get(f["severity"], 5))

    for e in errors:
        print(f"  Warning: {e['source']}: {e['summary']}", file=sys.stderr)

    # Coverage accounting. Only sources that can actually answer for this
    # ecosystem count: OSV and GitHub have no Homebrew ecosystem (both map
    # `brew` to None) and return empty WITHOUT querying, so for `brew` NVD is
    # the only source that ever runs. Reporting "2/3 sources checked" when NVD
    # is the one that failed would claim coverage that never existed.
    applicable = ["NIST NVD"]
    if ECOSYSTEM_MAP["osv"].get(ecosystem):
        applicable.append("OSV.dev")
    if ECOSYSTEM_MAP["github"].get(ecosystem):
        applicable.append("GitHub Advisory")
    failed_sources = sorted({e["source"] for e in errors})
    sources_ok = len([s for s in applicable if s not in failed_sources])

    if not vulns and sources_ok == 0:
        # NOTHING vetted this package. "No vulnerabilities found" here means
        # "we did not look", which is not the same answer. Fail closed: exit 2
        # is the documented network-failure code, and the callers already treat
        # it as "check failed, will not upgrade".
        print(
            f"  UNABLE TO CHECK: 0/{len(applicable)} vulnerability sources answered "
            f"({', '.join(failed_sources)}). Not reporting this package as clean.",
            file=sys.stderr,
        )
        json.dump(
            {
                "status": "unknown",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "sources_ok": 0,
                "sources_total": len(applicable),
                "sources_failed": failed_sources,
                "vulnerabilities": [],
            },
            sys.stdout,
        )
        sys.exit(2)

    if not vulns:
        print(
            f"  No known vulnerabilities found ({sources_ok}/{len(applicable)} sources checked)",
            file=sys.stderr,
        )
        if failed_sources:
            print(
                f"  Warning: degraded coverage -- {', '.join(failed_sources)} did not answer.",
                file=sys.stderr,
            )
        json.dump(
            {
                "status": "clean",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "sources_ok": sources_ok,
                "sources_total": len(applicable),
                "sources_failed": failed_sources,
                "vulnerabilities": [],
            },
            sys.stdout,
        )
        sys.exit(0)
    else:
        critical_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
        print(
            f"  {len(vulns)} vulnerabilities found ({len(critical_high)} critical/high):\n",
            file=sys.stderr,
        )

        for v in vulns:
            severity_label = v["severity"]
            score_str = f" (CVSS {v['score']})" if v["score"] > 0 else ""
            print(f"  [{severity_label}] {v['id']}{score_str}", file=sys.stderr)
            print(f"    Source: {v['source']}", file=sys.stderr)
            print(f"    {v['summary']}\n", file=sys.stderr)

        json.dump(
            {
                "status": "vulnerable",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "count": len(vulns),
                "critical_high": len(critical_high),
                "vulnerabilities": vulns,
            },
            sys.stdout,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
