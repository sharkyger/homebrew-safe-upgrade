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

# Build SSL context — use certifi bundle if available (needed on macOS)
try:
    import certifi

    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    SSL_CONTEXT = ssl.create_default_context()

USER_AGENT = "homebrew-safe-upgrade/1.0"


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


def parse_version(v):
    """Parse a version string into a tuple for comparison."""
    if not v:
        return ()
    # Strip leading 'v' or '=' prefixes
    v = re.sub(r"^[v=]+", "", v.strip())
    parts = []
    for p in v.split("."):
        m = re.match(r"(\d+)", p)
        if m:
            parts.append(int(m.group(1)))
        else:
            parts.append(0)
    return tuple(parts)


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

        m = re.match(r"([<>=!]+)\s*([\d][\d.]*\w*)", cond)
        if not m:
            if parse_version(cond) == v:
                return True
            continue

        op, ref_str = m.group(1), m.group(2)
        ref = parse_version(ref_str)

        if (
            op == "<"
            and not (v < ref)
            or op == "<="
            and not (v <= ref)
            or op == ">"
            and not (v > ref)
            or op == ">="
            and not (v >= ref)
            or op == "="
            or op == "=="
            and v != ref
            or op == "!="
            and v == ref
        ):
            return False

    return True


def query_osv(package_name, ecosystem, version=None):
    """Query OSV.dev — supports native version filtering."""
    findings = []
    osv_ecosystem = ECOSYSTEM_MAP["osv"].get(ecosystem)
    if not osv_ecosystem:
        return findings

    try:
        payload = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
        if version:
            payload["version"] = version
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json"}
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
    findings = []
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
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT})
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

                    if patched_ver and parse_version(version) >= parse_version(patched_ver):
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


def query_nvd(package_name, ecosystem, version=None):
    """Query NIST NVD — keyword search with version filtering via CPE match."""
    findings = []

    # NVD keyword search is too noisy for short/ambiguous names
    if len(package_name) < 4:
        return findings

    try:
        url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={urllib.parse.quote(package_name)}"
            f"&keywordExactMatch"
            f"&resultsPerPage=10"
        )
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with _urlopen(req) as resp:
            data = json.loads(resp.read())

        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "unknown")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description")

            # Filter out CVEs that mention the keyword but are about different software
            desc_lower = desc.lower()
            pkg_lower = package_name.lower()

            if pkg_lower not in desc_lower and pkg_lower.replace("-", "") not in desc_lower:
                continue

            # Reject if the first sentence names a different product as the subject
            first_sentence = desc.split(". ")[0].split(" is ")[0].split(" before ")[0].split(" through ")[0].strip()
            first_word = first_sentence.split()[0] if first_sentence.split() else ""
            if (
                first_word.lower() != pkg_lower
                and first_word.lower() != pkg_lower.replace("-", "")
                and pkg_lower not in first_word.lower()
            ):
                continue

            severity = "UNKNOWN"
            score = 0.0
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cvss = metrics[0].get("cvssData", {})
                    severity = cvss.get("baseSeverity", severity)
                    score = cvss.get("baseScore", score)
                    break

            # Version filtering via CPE matches
            if version:
                affected = False
                has_cpe = False
                configurations = cve.get("configurations", [])
                for config in configurations:
                    for node in config.get("nodes", []):
                        for cpe in node.get("cpeMatch", []):
                            if not cpe.get("vulnerable", False):
                                continue
                            has_cpe = True
                            ver_end_exc = cpe.get("versionEndExcluding")
                            ver_end_inc = cpe.get("versionEndIncluding")
                            ver_start_inc = cpe.get("versionStartIncluding")
                            ver_start_exc = cpe.get("versionStartExcluding")

                            if ver_end_exc or ver_end_inc or ver_start_inc or ver_start_exc:
                                # Range-based CPE — check if our version falls within
                                in_range = True
                                if ver_start_inc and parse_version(version) < parse_version(ver_start_inc):
                                    in_range = False
                                if ver_start_exc and parse_version(version) <= parse_version(ver_start_exc):
                                    in_range = False
                                if ver_end_exc and parse_version(version) >= parse_version(ver_end_exc):
                                    in_range = False
                                if ver_end_inc and parse_version(version) > parse_version(ver_end_inc):
                                    in_range = False
                                if in_range:
                                    affected = True
                            else:
                                # Exact version match — extract from CPE URI
                                # Format: cpe:2.3:a:vendor:product:VERSION:...
                                cpe_str = cpe.get("criteria", "")
                                cpe_parts = cpe_str.split(":")
                                if len(cpe_parts) >= 6:
                                    cpe_ver = cpe_parts[5]
                                    if cpe_ver in ("*", "-", ""):
                                        affected = True  # Wildcard — can't determine
                                    elif parse_version(version) == parse_version(cpe_ver):
                                        affected = True

                # If CPE data exists and our version isn't in any affected range, skip
                if has_cpe and not affected:
                    continue

            findings.append(
                {
                    "source": "NIST NVD",
                    "id": cve_id,
                    "severity": severity,
                    "score": score,
                    "summary": desc[:200],
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
        print("Usage: dependency_security_check.py <ecosystem> <package> [version]", file=sys.stderr)
        sys.exit(2)

    ecosystem = sys.argv[1].lower()
    package_name = sys.argv[2]
    version = sys.argv[3] if len(sys.argv) > 3 else None

    valid_ecosystems = ["pip", "npm", "composer", "cargo", "go", "maven", "gem", "brew"]
    if ecosystem not in valid_ecosystems:
        print(f"Unknown ecosystem: {ecosystem}. Valid: {', '.join(valid_ecosystems)}", file=sys.stderr)
        sys.exit(2)

    if not version:
        version = resolve_latest_version(package_name, ecosystem)

    print(f"\nSecurity check: {package_name} ({ecosystem})", file=sys.stderr)
    if version:
        print(f"  Version: {version}", file=sys.stderr)
    else:
        print("  Version: unknown (checking all known CVEs)", file=sys.stderr)
    print("  Querying 3 vulnerability databases (NVD + OSV + GitHub)...\n", file=sys.stderr)

    all_findings = []
    all_findings.extend(query_osv(package_name, ecosystem, version))
    all_findings.extend(query_github(package_name, ecosystem, version))
    all_findings.extend(query_nvd(package_name, ecosystem, version))

    errors = [f for f in all_findings if f["id"] in ("ERROR", "SKIP")]
    vulns = [f for f in all_findings if f["id"] not in ("ERROR", "SKIP")]
    vulns = deduplicate(vulns)

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "MODERATE": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda f: severity_order.get(f["severity"], 5))

    for e in errors:
        print(f"  Warning: {e['source']}: {e['summary']}", file=sys.stderr)

    if not vulns:
        sources_ok = 3 - len(errors)
        print(f"  No known vulnerabilities found ({sources_ok}/3 sources checked)", file=sys.stderr)
        json.dump(
            {
                "status": "clean",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "vulnerabilities": [],
            },
            sys.stdout,
        )
        sys.exit(0)
    else:
        critical_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
        print(f"  {len(vulns)} vulnerabilities found ({len(critical_high)} critical/high):\n", file=sys.stderr)

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
