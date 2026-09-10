"""With several kegs in the Cellar, the baseline is the NEWEST one.

`brew outdated --json=v2` reports `installed_versions` as a LIST, and it holds
more than one entry whenever more than one keg survives in the Cellar — any
skipped or failed `brew cleanup` leaves an old one behind. The wrapper read
`[0]`, the OLDEST.

That is fail-open, and it fired in a live run (2026-09-06):

    safe-upgrade:  simdjson  formula  4.6.4  -> 4.6.11
    brew upgrade:  simdjson         4.6.7    -> 4.6.11

The installed version feeds two decisions — the relative CVE verdict
([SAME]/[IMPROVES]) and the CVE-aware freshness bypass. The bypass is the
dangerous one: a stale keg carries CVEs the running version has already fixed,
so "installed has CVEs" fires and waves the candidate straight past the
min-age hold. In that run simdjson 4.6.11, published the same day, cleared a
3-day hold on the strength of CVE-2026-8295 attributed to 4.6.4 — a keg the
user was not running. A brand-new release skipping the freshness hold is
precisely the supply-chain window the hold exists to close.

brew builds the list in `Formula#outdated_kegs` as
`all_kegs.sort_by(&:scheme_and_version)` — ascending, in brew's own version
ordering, which ranks revisions (`10.47` < `10.47_1`) in a way this repo's
PEP 440 comparator deliberately does not. So `[-1]` is both the newest keg and
the one brew will upgrade from, without us re-implementing brew's ordering.
The dependency path already took the last entry (`awk '$NF'`); this is the
top-level path catching up.
"""

import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).parent.parent
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


def write_outdated(fixture_dir, formulae, casks=()):
    (fixture_dir / "outdated.json").write_text(
        json.dumps({"formulae": list(formulae), "casks": list(casks)})
    )


def write_formula_info(fixture_dir, name, version):
    (fixture_dir / f"info_{name}.json").write_text(
        json.dumps(
            {
                "formulae": [{"name": name, "full_name": name, "versions": {"stable": version}}],
                "casks": [],
            }
        )
    )


def write_deps(fixture_dir, name, deps=()):
    (fixture_dir / f"deps_{name}.txt").write_text("\n".join(deps) + ("\n" if deps else ""))


def versioned_cve_stub(tmp_path, vulnerable_versions=()):
    """Scanner stub keyed on the VERSION it is asked about, not the package.

    That is the whole point here: the wrapper probes the installed version to
    decide whether to bypass the freshness hold, and the bug was probing the
    wrong one. Keying on version makes the two kegs give different answers.
    It also records every (package, version) it was asked, so a test can assert
    which keg was actually used rather than inferring it from the verdict.
    """
    log = tmp_path / "probe.log"
    stub = tmp_path / "cve_stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        f"VULN = {list(vulnerable_versions)!r}\n"
        f"LOG = {str(log)!r}\n"
        "pkg = sys.argv[2] if len(sys.argv) > 2 else ''\n"
        "ver = sys.argv[3] if len(sys.argv) > 3 else ''\n"
        "with open(LOG, 'a') as fh:\n"
        "    fh.write(f'{pkg} {ver}\\n')\n"
        "if ver in VULN:\n"
        "    json.dump({'status': 'vulnerable', 'package': pkg, 'version': ver,\n"
        "               'vulnerabilities': [{'id': 'CVE-2099-0001', 'severity': 'HIGH',\n"
        "               'score': 7.5, 'summary': 'stub', 'source': 'stub'}]}, sys.stdout)\n"
        "    sys.exit(1)\n"
        "json.dump({'status': 'clean', 'package': pkg, 'version': ver,\n"
        "           'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    return stub, log


def fresh_commit(commits_dir, name, days):
    import datetime

    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    (Path(commits_dir) / f"{name}.json").write_text(
        json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])
    )


def run_upgrade(args=(), env_extra=None, input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE), *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        input=input_text,
    )


# --------------------------------------------------------------------------


def test_outdated_table_shows_the_newest_keg(brew_env, tmp_path):
    """The live symptom: the table said 4.6.4 while brew upgraded from 4.6.7."""
    write_outdated(
        brew_env,
        [
            {
                "name": "simdjson",
                "installed_versions": ["4.6.4", "4.6.7"],
                "current_version": "4.6.11",
            }
        ],
    )
    write_formula_info(brew_env, "simdjson", "4.6.11")
    write_deps(brew_env, "simdjson")
    stub, _ = versioned_cve_stub(tmp_path)
    result = run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    row = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("simdjson")]
    assert row, result.stdout
    assert "4.6.7" in row[0], row[0]
    assert "4.6.4" not in row[0], row[0]


def test_baseline_probe_asks_about_the_newest_keg(brew_env, tmp_path):
    """Asserts the mechanism, not just the display: the CVE probe that decides
    the freshness bypass must be handed 4.6.7, never 4.6.4."""
    write_outdated(
        brew_env,
        [
            {
                "name": "simdjson",
                "installed_versions": ["4.6.4", "4.6.7"],
                "current_version": "4.6.11",
            }
        ],
    )
    write_formula_info(brew_env, "simdjson", "4.6.11")
    write_deps(brew_env, "simdjson")
    stub, log = versioned_cve_stub(tmp_path, vulnerable_versions=["4.6.4"])
    fresh_commit(os.environ["MOCK_COMMITS_API_DIR"], "simdjson", days=0)
    run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    probes = log.read_text().splitlines() if log.exists() else []
    assert probes, "the scanner was never invoked"
    assert "simdjson 4.6.4" not in probes, f"probed the stale keg: {probes}"


def test_stale_keg_cves_do_not_bypass_the_freshness_hold(brew_env, tmp_path):
    """The security property. Old keg 4.6.4 is vulnerable, running keg 4.6.7 is
    clean, candidate 4.6.11 is same-day. It must HOLD."""
    write_outdated(
        brew_env,
        [
            {
                "name": "simdjson",
                "installed_versions": ["4.6.4", "4.6.7"],
                "current_version": "4.6.11",
            }
        ],
    )
    write_formula_info(brew_env, "simdjson", "4.6.11")
    write_deps(brew_env, "simdjson")
    stub, _ = versioned_cve_stub(tmp_path, vulnerable_versions=["4.6.4"])
    fresh_commit(os.environ["MOCK_COMMITS_API_DIR"], "simdjson", days=0)
    result = run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" not in result.stdout, result.stdout
    assert "[HOLD] simdjson" in result.stdout, result.stdout


def test_running_keg_cves_still_bypass_the_freshness_hold(brew_env, tmp_path):
    """The other half — don't overcorrect. When the keg actually in use is
    vulnerable, the fresh release IS the fix and must still come through."""
    write_outdated(
        brew_env,
        [
            {
                "name": "simdjson",
                "installed_versions": ["4.6.4", "4.6.7"],
                "current_version": "4.6.11",
            }
        ],
    )
    write_formula_info(brew_env, "simdjson", "4.6.11")
    write_deps(brew_env, "simdjson")
    stub, _ = versioned_cve_stub(tmp_path, vulnerable_versions=["4.6.7"])
    fresh_commit(os.environ["MOCK_COMMITS_API_DIR"], "simdjson", days=0)
    result = run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "bypassing age check" in result.stdout, result.stdout
    assert "installed 4.6.7 has CVEs" in result.stdout, result.stdout


def test_single_keg_is_unchanged(brew_env, tmp_path):
    """Regression guard: the ordinary one-keg case must read exactly as before."""
    write_outdated(
        brew_env,
        [{"name": "wget", "installed_versions": ["1.24"], "current_version": "1.25"}],
    )
    write_formula_info(brew_env, "wget", "1.25")
    write_deps(brew_env, "wget")
    stub, _ = versioned_cve_stub(tmp_path)
    result = run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    row = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("wget")]
    assert row and "1.24" in row[0] and "1.25" in row[0], result.stdout


def test_empty_installed_versions_does_not_discard_the_whole_batch(brew_env, tmp_path):
    """`installed_versions: []` made `[0]` raise IndexError inside the parser's
    blanket `except`, which threw away EVERY outdated package — the run then
    said "Everything up to date." and exited 0. One malformed entry silently
    disabling the entire gate is the worst failure mode in the file."""
    write_outdated(
        brew_env,
        [
            {"name": "broken", "installed_versions": [], "current_version": "2.0"},
            {"name": "wget", "installed_versions": ["1.24"], "current_version": "1.25"},
        ],
    )
    for n, v in (("broken", "2.0"), ("wget", "1.25")):
        write_formula_info(brew_env, n, v)
        write_deps(brew_env, n)
    stub, _ = versioned_cve_stub(tmp_path)
    result = run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "Everything up to date" not in result.stdout, result.stdout
    assert "wget" in result.stdout, result.stdout


def test_revision_bump_keg_ordering_follows_brew(brew_env, tmp_path):
    """`10.47` and `10.47_1` differ only by Homebrew revision. parse_version()
    strips `_N` and would call them equal, so ordering these ourselves would be
    a coin flip — relying on brew's own sort is what makes `[-1]` correct."""
    write_outdated(
        brew_env,
        [{"name": "pcre2", "installed_versions": ["10.47", "10.47_1"], "current_version": "10.48"}],
    )
    write_formula_info(brew_env, "pcre2", "10.48")
    write_deps(brew_env, "pcre2")
    stub, _ = versioned_cve_stub(tmp_path)
    result = run_upgrade(env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)})
    row = [ln for ln in result.stdout.splitlines() if ln.strip().startswith("pcre2")]
    assert row and "10.47_1" in row[0], row[0] if row else result.stdout
