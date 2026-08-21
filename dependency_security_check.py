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

All three databases are free and public and no key is required. Setting
NVD_API_KEY (free, https://nvd.nist.gov/developers/request-an-api-key) raises
NVD's rate limit from 5 to 50 requests per rolling 30 seconds, which matters on
large batches: a package no source could answer for is HELD, not passed.
"""

import datetime
import http.client
import json
import os
import re
import ssl
import sys
import time
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

# Formula → verified NVD (vendor, product). For a mapped formula the CPE query
# is authoritative and the keyword fallback is not run — see formula_cpe_map.py.
try:
    from formula_cpe_map import lookup as _formula_cpe_lookup
except ImportError:

    def _formula_cpe_lookup(formula_name: str) -> tuple[str, str] | None:
        return None


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

# target_sw values that scope an advisory to an editor/IDE extension platform.
# `cpe:2.3:a:microsoft:python:*:*:*:*:*:visual_studio_code:*:*` is the VS Code
# *Python extension* (CVE-2020-1171, CVE-2024-49050, ...), not CPython — yet a
# vendor-wildcard CPE query for product `python` returns both. An extension
# marketplace is not a package ecosystem we ever check, so these are foreign
# for EVERY ecosystem, brew included.
PLATFORM_TARGET_SW = {"visual_studio_code", "visual_studio"}


def _foreign_target_sw(target_sw, ecosystem):
    """True if a CPE's target_sw pins it to a DIFFERENT language ecosystem.

    Generic values (*, -, empty) and values we don't recognize as a language
    ecosystem are never foreign — only a positive match against another
    ecosystem's known target_sw set disqualifies a CPE (fail closed).
    """
    if target_sw in ("*", "-", ""):
        return False
    if target_sw in PLATFORM_TARGET_SW:
        return True
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

# NVD throttles anonymous callers to 5 requests per rolling 30 seconds; an API
# key raises that to 50. Set NVD_API_KEY to use one — request it (free) at
# https://nvd.nist.gov/developers/request-an-api-key.
#
# Without a key this matters more than it used to. Now that a package with no
# answering source is held rather than reported clean, being throttled means
# packages do not upgrade — a batch of ten can lose several. Hence: send the key
# when present, and back off and retry rather than giving up on the first 403.
NVD_MAX_RETRIES = 3
NVD_RETRY_BASE_SECONDS = 6  # a little under the 30s window / 5 requests


NVD_KEY_HINT = (
    "NVD rate limit reached (5 requests / 30s without a key). "
    "Set NVD_API_KEY for 50/30s — free, no approval wait: "
    "https://nvd.nist.gov/developers/request-an-api-key"
)


def _nvd_api_key() -> str:
    """The NVD key, tolerating Homebrew's environment scrub.

    `brew` re-execs external commands through `env -i` with an allowlist
    (bin/brew: HOME SHELL PATH TERM ... plus every HOMEBREW_* variable), so a
    plain `export NVD_API_KEY=...` in a shell profile is dropped before
    `brew safe-upgrade` ever starts and the run is silently throttled to the
    anonymous 5-requests/30s budget. HOMEBREW_NVD_API_KEY survives that filter
    by construction, so it is accepted as an equivalent spelling.
    """
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    return api_key or os.environ.get("HOMEBREW_NVD_API_KEY", "").strip()


def _nvd_headers():
    """Request headers for NVD, including the API key when one is configured.

    The key goes in a HEADER, never the query string — NVD's documented method,
    and it keeps the secret out of anything that logs or reports a URL. Nothing
    here is ever printed: the failure paths report the exception, not the
    headers.
    """
    headers = {"User-Agent": USER_AGENT}
    api_key = _nvd_api_key()
    if api_key:
        headers["apiKey"] = api_key
    return headers


# Characters NVD accepts in a CPE 2.3 product component. '@' and '/' are not
# among them: NVD answers HTTP 404 to a virtualMatchString containing either,
# and a 404 raised out of the candidate loop used to abort the whole query.
_CPE_PRODUCT_RE = re.compile(r"^[a-z0-9][a-z0-9._\-]*$")


def _formula_name(package_name, ecosystem):
    """The formula's own name, without a tap prefix.

    `sharkyger/tap/pip-cve-gate` is how brew addresses a third-party formula,
    but the product NVD might know is `pip-cve-gate`. Sent verbatim the slashes
    404'd the CPE query and matched nothing as a keyword, so every tap formula
    came back "unknown" — a permanent blind spot on the least-reviewed software
    on the machine. Casks and non-brew ecosystems have no tap prefix; their
    names already contain '/' legitimately (npm scopes) and are left alone.
    """
    if ecosystem == "brew" and "/" in package_name:
        return package_name.rsplit("/", 1)[1]
    return package_name


def _nvd_cpe_products(package_name, ecosystem):
    """CPE product-name candidates for a package.

    Homebrew versioned formulae (`openssl@3`, `python@3.11`, `node@20`) carry a
    suffix that appears in no CPE and in no CVE description. The literal name
    used to be tried first — but '@' is not a CPE character, NVD 404s on it,
    and the HTTPError escaped the loop before the base product was reached.
    Only CPE-safe candidates are returned now, so `python@3.12` resolves
    through `python` and `sharkyger/tap/pip-cve-gate` through `pip-cve-gate`.
    """
    if ecosystem == "brew" and package_name in CASK_NVD_KEYWORDS:
        # A curated cask mapping is authoritative: the slug (`brave-browser`)
        # is exactly what does NOT identify the product, so trying it as a CPE
        # product name is a wasted request against a rate-limited API.
        return [CASK_NVD_KEYWORDS[package_name].lower().replace(" ", "_")]
    name = _formula_name(package_name, ecosystem).lower()
    candidates = [name, name.split("@", 1)[0]]
    seen = set()
    ordered = []
    for c in candidates:
        if c and c not in seen and _CPE_PRODUCT_RE.match(c):
            seen.add(c)
            ordered.append(c)
    return ordered


def _nvd_get(url):
    """GET one NVD page, retrying a throttling response with backoff.

    NVD answers 403 (and sometimes 429) when the rate limit is exceeded. Giving
    up on the first one means the package ends up with no answering source,
    which is now a HOLD rather than a false "clean" — so a transient throttle
    would stop packages upgrading. Retry a bounded number of times, honouring
    Retry-After when NVD sends it, and let the exception through afterwards so
    the caller still fails closed.
    """
    last_error = None
    for attempt in range(NVD_MAX_RETRIES):
        req = urllib.request.Request(url, headers=_nvd_headers())
        try:
            with _urlopen(req) as resp:
                return json.loads(resp.read())
        except (http.client.HTTPException, ConnectionError, TimeoutError) as e:
            # A body that truncates mid-read (IncompleteRead on a ~600 KB page),
            # a reset connection, a socket timeout. None of these is a URLError,
            # so they used to surface as a raw traceback instead of the handled
            # "source failed" path. Retry; if it keeps happening hand the caller
            # a URLError so it fails closed like any other unreachable source.
            if attempt == NVD_MAX_RETRIES - 1:
                raise urllib.error.URLError(f"{type(e).__name__}: {e}") from e
            time.sleep(min(NVD_RETRY_BASE_SECONDS * (attempt + 1), 30))
            continue
        except urllib.error.HTTPError as e:
            if e.code not in (403, 429) or attempt == NVD_MAX_RETRIES - 1:
                raise
            last_error = e
            retry_after = e.headers.get("Retry-After") if e.headers else None
            try:
                delay = (
                    float(retry_after) if retry_after else NVD_RETRY_BASE_SECONDS * (attempt + 1)
                )
            except (TypeError, ValueError):
                delay = NVD_RETRY_BASE_SECONDS * (attempt + 1)
            # Cap so a hostile or malformed Retry-After cannot stall the run.
            time.sleep(min(delay, 30))
    raise last_error if last_error else urllib.error.URLError("NVD request failed")


NVD_RECENT_WINDOW_DAYS = 120  # NVD's maximum pubStartDate..pubEndDate span
# Above this many unanalysed recent mentions the name is too generic for prose
# to attribute a record to the product (`php` → ~140 records about other PHP
# software in one window); the sweep is skipped and NVD's CPE assignment,
# which lands within days, covers them through the authoritative path.
NVD_RECENT_SWEEP_CAP = 10


def _nvd_recent_unanalysed(search_name):
    """Keyword records published in the last NVD_RECENT_WINDOW_DAYS that carry
    no CPE data yet. Used next to an authoritative CPE answer so a brand-new
    CVE is not invisible until NVD analyses it. Returns [] (with a note on
    stderr) when more than NVD_RECENT_SWEEP_CAP such records mention the
    name — see the cap's comment."""
    end = datetime.datetime.now(datetime.UTC)
    start = end - datetime.timedelta(days=NVD_RECENT_WINDOW_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = (
        f"keywordSearch={urllib.parse.quote(search_name)}&keywordExactMatch"
        f"&pubStartDate={urllib.parse.quote(start.strftime(fmt))}"
        f"&pubEndDate={urllib.parse.quote(end.strftime(fmt))}"
    )
    records, _total, _truncated = _nvd_fetch(params)
    fresh = [r for r in records if not _has_cpe_data(r.get("cve", {}))]
    if len(fresh) > NVD_RECENT_SWEEP_CAP:
        print(
            f"  Note: {len(fresh)} unanalysed NVD records from the last "
            f"{NVD_RECENT_WINDOW_DAYS} days mention '{search_name}' — too generic to "
            "attribute by text; relying on CPE-analysed records only.",
            file=sys.stderr,
        )
        return []
    return fresh


def _has_cpe_data(cve):
    """True if the record carries at least one cpeMatch entry."""
    return any(
        node.get("cpeMatch")
        for config in cve.get("configurations", [])
        for node in config.get("nodes", [])
    )


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
        data = _nvd_get(url)
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


def _cpe_data_names_product(cve, products):
    """Does any vulnerable CPE on this record name one of `products`?

    Exact product match, or the product as a token of a compound name split
    on '.', '_' and '-' — `node` in `node.js`, `openldap` in
    `openldap-servers`. Token matching errs toward keeping a record.
    """
    wanted = {p.lower() for p in products}
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if not cpe.get("vulnerable", False):
                    continue
                parts = cpe.get("criteria", "").split(":")
                if len(parts) < 5:
                    continue
                product = parts[4].lower()
                if product in wanted:
                    return True
                if wanted & set(re.split(r"[._-]", product)):
                    return True
    return False


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
            # Format: cpe:2.3:a:vendor:product:VERSION:UPDATE:...
            cpe_parts = cpe.get("criteria", "").split(":")
            if len(cpe_parts) >= 6:
                cpe_ver = cpe_parts[5]
                # NVD carries the OpenSSH portmark in the UPDATE component, not
                # in the version: CVE-2016-6210 is
                # `cpe:2.3:a:openbsd:openssh:*:p2:*`. Homebrew spells the same
                # thing as one string ("10.3p1"), so comparing only the version
                # component against it can never match — an exact-version CPE
                # pinned to a portmark would be judged not-affected, missing a
                # real finding. Rejoin them before comparing.
                cpe_update = cpe_parts[6] if len(cpe_parts) >= 7 else "*"
                update_portmark = re.match(r"^p\d+$", cpe_update or "")
                if update_portmark and cpe_ver not in ("*", "-", ""):
                    cpe_ver = f"{cpe_ver}{cpe_update}"
                if cpe_ver in ("*", "-", ""):
                    if update_portmark:
                        # Wildcard version but a pinned portable build, e.g.
                        # `openssh:*:p2`. Treating that as a bare wildcard flags
                        # EVERY OpenSSH version — the exact shape of the false
                        # positive in issue #94, since CVE-2016-6210 is recorded
                        # this way. Match only the same portmark; if the
                        # installed version carries none, we cannot disprove it
                        # and fail closed.
                        installed_portmark = re.search(r"p(\d+)$", str(version or ""))
                        if (
                            installed_portmark is None
                            or installed_portmark.group(1) == update_portmark.group(0)[1:]
                        ):
                            affected = True
                    else:
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

    # Where in the first sentence the package is named decides relevance.
    # Real reports name the product as the SUBJECT — optionally behind one
    # vendor word ("GNU Wget does not validate ...", "Cloudflare WARP client")
    # — or right after "in", MITRE's boilerplate ("An issue was discovered in
    # version of Warp Terminal ...", "A vulnerability in wget before ..."). Noise
    # names it as an object of use: "Applications that use Wget ...", "DEEBOT
    # PRO M1 use wget command with ...", "AVTECH ... due to the use of wget".
    #
    # The original rule accepted only the first words, which dropped both
    # MITRE boilerplate (CVE-2024-41997) and vendor-prefixed subjects
    # (CVE-2026-15146 "GNU Wget ..."): terminal false negatives on the keyword
    # path, where no CPE query sits underneath. Accepting anywhere in the
    # sentence re-admitted the object-of-use noise (wget@99.99.0 picked up
    # four IoT-vendor records). This is the narrowest rule that keeps every
    # pinned case on the right side.
    first_sentence = (
        desc.split(". ")[0].split(" is ")[0].split(" before ")[0].split(" through ")[0].strip()
    ).lower()
    words = first_sentence.split()
    term_word_count = len(matched_term.split())
    # subject position: within the first (term words + 1) words, so one
    # vendor/brand word may precede the product.
    head = " ".join(words[: term_word_count + 1])
    matched_nodash = matched_term.replace("-", "")
    matched_re = re.compile(r"(?<![a-z0-9\-])" + re.escape(matched_term) + r"(?![a-z0-9\-])")
    matched_nodash_re = re.compile(r"(?<![a-z0-9])" + re.escape(matched_nodash) + r"(?![a-z0-9])")
    if matched_re.search(head) or matched_nodash_re.search(head):
        return True
    # "in [the] [version(s) of] <product>" — the product is what the issue is in.
    in_re = re.compile(
        r"\bin (?:the )?(?:versions? of )?(?:the )?"
        + "(?:"
        + re.escape(matched_term)
        + "|"
        + re.escape(matched_nodash)
        + ")"
        + r"(?![a-z0-9\-])"
    )
    return bool(in_re.search(first_sentence))


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

    # Keyword path only: the record's own CPE list is NVD's authoritative
    # statement of what is affected. When it exists and nothing in it names
    # our product — exactly or as a token of a compound (node.js,
    # openldap-servers, bibtex-ruby) — the CVE is about something else, no
    # matter how the prose opens. php 8.5.9 was blocked on five 2003/2004
    # "PHP remote file inclusion in <some PHP app>" records whose CPEs name
    # pmachine and ezcontents; ruby on ruby-saml records whose CPEs name
    # omniauth_saml. CPE-matched results never reach this branch, and records
    # with no CPE data at all are untouched (nothing to reason from).
    if (
        require_desc_match
        and has_any_cpe
        and products
        and not _cpe_data_names_product(cve, products)
    ):
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
        # False when NVD has no applicability data for the record yet (typically
        # "Awaiting Analysis") and the text names no version bound: the CVE is
        # reported against every version because nothing says it is fixed, not
        # because this version is known to be affected.
        "scoped": bool(relevant_cpes),
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
    # The keyword path gets the formula's own name (tap prefix stripped) but
    # deliberately NOT the '@'-stripped base — neither as the search term nor
    # in the description filter: bare `python` drags in the VS Code
    # Python-extension CVEs, whose descriptions name "Python" without ever
    # naming python@3.12. Base-name matching is a CPE-path concern only.
    formula = _formula_name(package_name, ecosystem)
    search_name = formula
    match_terms = [formula.lower()]
    if ecosystem == "brew" and package_name in CASK_NVD_KEYWORDS:
        # A curated mapping is authoritative for the description filter too.
        # The slug stays as a secondary term only when it is a compound
        # ("claude-code", "brave-browser") that could appear verbatim in a
        # description. A bare single-word slug is exactly the ambiguous token
        # the mapping exists to replace: "warp" would re-admit "Cloudflare WARP
        # client ..." for the Warp terminal.
        mapped_keyword = CASK_NVD_KEYWORDS[package_name]
        search_name = mapped_keyword
        match_terms = [mapped_keyword.lower()]
        if "-" in package_name:
            match_terms.append(package_name.lower())

    products = _nvd_cpe_products(package_name, ecosystem)

    # A verified (vendor, product) makes the CPE query authoritative: the
    # vendor is pinned (no `*:python` → VS Code extension surprises) and zero
    # results means "NVD lists no CVE for this version" — so the keyword
    # fallback, built for products NVD has no CPE for, is skipped. For `php`,
    # `ruby`, `node`, `certifi` that fallback is what produced the
    # 1,000-record overflow and the 2003-era blocks on other PHP software.
    verified = _formula_cpe_lookup(formula) if ecosystem == "brew" else None
    if verified:
        vendor, product = verified
        products = [product]
        cpe_candidates = [(vendor, product)]
    else:
        cpe_candidates = [("*", p) for p in products]

    try:
        records = []
        matched_via_cpe = False
        truncated = False

        for vendor, product in cpe_candidates:
            if version:
                vm = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            else:
                vm = f"cpe:2.3:a:{vendor}:{product}"
            params = f"virtualMatchString={urllib.parse.quote(vm)}"
            try:
                records, total, truncated = _nvd_fetch(params)
            except urllib.error.HTTPError as e:
                # NVD's answer to a CPE string it cannot parse is 404. That is
                # "no match for this candidate", not "the source is down" —
                # try the next candidate, then the keyword path.
                if e.code != 404:
                    raise
                continue
            if total:
                matched_via_cpe = True
                break

        unanalysed = []
        if verified:
            # The CPE answer is authoritative for every record NVD has
            # analysed. It cannot see a record NVD has NOT analysed yet
            # ("Received" / "Awaiting Analysis": no CPE for days to weeks after
            # publication) — and on the keyword path that is exactly what the
            # full search would have found, buried in thousands of records
            # about other software. Sweep only the recent publication window
            # (NVD caps it at 120 days) and keep only records that still have
            # no CPE data: a bounded result set, fresh CVEs still caught.
            unanalysed = _nvd_recent_unanalysed(search_name)
        if not matched_via_cpe and verified:
            # Authoritative answer: NVD knows this product and lists nothing
            # for this version. Nothing to fall back to.
            records = []
        elif not matched_via_cpe:
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

        seen_ids = {f["id"] for f in findings}
        for vuln in unanalysed:
            finding = _nvd_cve_to_finding(
                vuln, ecosystem, version, match_terms, require_desc_match=True, products=products
            )
            if finding is not None and finding["id"] not in seen_ids:
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
        # Distinguish "NVD threw us out for asking too fast" from any other
        # failure. Both fail closed, but only one of them has a fix the user can
        # act on, and without saying so the run just looks broken.
        findings.append(
            {
                "source": "NIST NVD",
                "id": "ERROR",
                "severity": "UNKNOWN",
                "score": 0,
                "summary": f"Query failed: {e}",
                "rate_limited": isinstance(e, urllib.error.HTTPError) and e.code in (403, 429),
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
    # Which sources can actually answer for this ecosystem? OSV and GitHub have
    # no Homebrew ecosystem (both map `brew` to None) and return empty WITHOUT
    # querying, so for `brew` NVD is the only source that ever runs. Computed
    # once, before the queries, so the opening line and the closing coverage
    # count cannot disagree — announcing "3 databases" and then reporting out of
    # 1 was the same overstated-coverage problem in a different place.
    applicable = ["NIST NVD"]
    if ECOSYSTEM_MAP["osv"].get(ecosystem):
        applicable.append("OSV.dev")
    if ECOSYSTEM_MAP["github"].get(ecosystem):
        applicable.append("GitHub Advisory")
    plural = "database" if len(applicable) == 1 else "databases"
    print(
        f"  Querying {len(applicable)} vulnerability {plural} ({' + '.join(applicable)})...\n",
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

    # Coverage accounting, against the same `applicable` list the opening line
    # was built from. Reporting "2/3 sources checked" when NVD is the one that
    # failed would claim coverage that never existed.
    failed_sources = sorted({e["source"] for e in errors})
    # Surfaced in the JSON as well as on stderr: the wrappers invoke this script
    # with 2>/dev/null, so stdout is the only channel they can actually read.
    rate_limited = any(e.get("rate_limited") for e in errors)
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
        if rate_limited and not _nvd_api_key():
            print(f"  -> {NVD_KEY_HINT}", file=sys.stderr)
        json.dump(
            {
                "status": "unknown",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "sources_ok": 0,
                "sources_total": len(applicable),
                "sources_failed": failed_sources,
                # Why each source failed, for the wrapper's [skip] line. A 404,
                # a truncated read, a throttle and a 1,000-record overflow used
                # to print identically as "check failed".
                "failure_reasons": [f"{e['source']}: {e['summary']}" for e in errors],
                "rate_limited": rate_limited,
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
                "rate_limited": rate_limited,
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
                # Same coverage fields as the clean/unknown paths. A finding is
                # still worth qualifying — "1 CVE, and 2 of 3 sources answered"
                # is a different statement from "1 CVE, all sources answered" —
                # and a consumer reading sources_ok should not have to special-
                # case this branch to avoid a KeyError.
                "sources_ok": sources_ok,
                "sources_total": len(applicable),
                "sources_failed": failed_sources,
                "rate_limited": rate_limited,
                "vulnerabilities": vulns,
            },
            sys.stdout,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
