"""An excluded package must suppress itself and nothing else.

The clean-list build tested membership with `echo "$EXCLUDE_PKGS" | grep -qw
"$name"`, which treats the package name as a basic regular expression and
matches on word boundaries. Homebrew names are full of characters grep counts
as boundaries — @ - + . — so an excluded package silently suppressed every
OTHER outdated package whose name was a word-component of it:

    held  python@3.12  ->  also dropped  python
    held  node@22      ->  also dropped  node
    held  openssl@3    ->  also dropped  openssl

The suppressed package had already been reported `[ok]` by both the age check
and the CVE check, and counted in "Results: N clean". It then simply vanished:
not upgraded, not listed under "Held", no line anywhere saying why, exit 0.

It fails closed — nothing unsafe is installed — but it is a silent correctness
failure, and the post-upgrade verification cannot catch it either: a suppressed
package never reaches CLEAN_PKGS, so it is never announced and never
re-checked. Versioned formulae are everywhere in Homebrew and a freshness hold
on one is routine, so this was reachable on ordinary runs.

The file already carried this correction for the DEPENDENCY path, with a
comment explaining that `case` matches literally where `grep -qw` does not
(see the DEP_TAINTED_PKGS build). The top-level build never got it.

NOT covered here: a formula and a cask sharing a token still suppress each
other, because they genuinely share a name in EXCLUDE_PKGS. Separating them
needs type-tagged entries — see
.codereview/exclude-pkgs-type-conflation.local.md.
"""

import datetime
import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).parent.parent
SAFE_UPGRADE = REPO / "brew-safe-upgrade"


def write_outdated(fixture_dir, formulae=(), casks=()):
    (fixture_dir / "outdated.json").write_text(
        json.dumps({"formulae": list(formulae), "casks": list(casks)})
    )


def write_formula_info(fixture_dir, name, version):
    target = fixture_dir / f"info_{name}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(
            {
                "formulae": [{"name": name, "full_name": name, "versions": {"stable": version}}],
                "casks": [],
            }
        )
    )


def write_deps(fixture_dir, name, deps=()):
    flat = name.replace("/", "_")
    (fixture_dir / f"deps_{flat}.txt").write_text("\n".join(deps) + ("\n" if deps else ""))


def clean_stub(tmp_path):
    stub = tmp_path / "cve_stub.py"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "json.dump({'status': 'clean', 'package': sys.argv[2] if len(sys.argv) > 2 else '',\n"
        "           'vulnerabilities': []}, sys.stdout)\n"
        "sys.exit(0)\n"
    )
    stub.chmod(0o755)
    return stub


def hold_via_freshness(name, days=0):
    dt = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=days)
    (Path(os.environ["MOCK_COMMITS_API_DIR"]) / f"{name.replace('/', '_')}.json").write_text(
        json.dumps([{"commit": {"committer": {"date": dt.strftime("%Y-%m-%dT%H:%M:%SZ")}}}])
    )


def run_upgrade(env_extra=None, input_text="n\n"):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SAFE_UPGRADE)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
        input=input_text,
    )


def scenario(brew_env, tmp_path, held, kept):
    """`held` is held back for freshness; `kept` is clean and must survive."""
    write_outdated(
        brew_env,
        [
            {"name": held, "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": kept, "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n in (held, kept):
        write_formula_info(brew_env, n, "2.0")
        write_deps(brew_env, n)
    hold_via_freshness(held, days=0)
    return clean_stub(tmp_path)


# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("held", "kept"),
    [
        ("python@3.12", "python"),  # '@' is a word boundary to grep -w
        ("node@22", "node"),
        ("openssl@3", "openssl"),
        ("foo-bar", "foo"),  # '-' likewise
        # No '+' case (gtk+3 / gtk): the wrapper's own name validation rejects a
        # '+' before the age check ever runs ("invalid name, refusing to query"),
        # so that spelling cannot reach this code path at all. Asserting on it
        # would be a test that passes for a reason unrelated to the fix.
    ],
)
def test_held_package_does_not_suppress_a_name_component(brew_env, tmp_path, held, kept):
    """The core bug, across the separator characters Homebrew actually uses."""
    stub = scenario(brew_env, tmp_path, held, kept)
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert f"[HOLD] {held}" in result.stdout, result.stdout
    assert "Clean formulae to upgrade:" in result.stdout, (
        f"{kept} was silently dropped when {held} was held:\n{result.stdout}"
    )
    line = [ln for ln in result.stdout.splitlines() if "Clean formulae to upgrade:" in ln][0]
    assert kept in line.split(":", 1)[1].split(), line


def test_the_held_package_itself_is_still_excluded(brew_env, tmp_path):
    """Don't overcorrect: exact matching must still exclude the real one."""
    stub = scenario(brew_env, tmp_path, "python@3.12", "python")
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    line = [ln for ln in result.stdout.splitlines() if "Clean formulae to upgrade:" in ln][0]
    assert "python@3.12" not in line.split(":", 1)[1].split(), line


def test_a_clean_package_reported_ok_is_actually_offered(brew_env, tmp_path):
    """The symptom that makes this a correctness bug rather than a preference:
    the tool printed [ok] for the package and counted it in "Results: N clean",
    then dropped it with no explanation and exited 0."""
    stub = scenario(brew_env, tmp_path, "python@3.12", "python")
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    assert "[ok] python 2.0" in result.stdout, result.stdout
    assert "No verified clean packages to upgrade." not in result.stdout, result.stdout


def test_regex_metacharacter_in_a_candidate_name_does_not_widen_the_match(brew_env, tmp_path):
    """'.' is a wildcard in a BRE. The name under test is the PATTERN and the
    exclusion list is the SUBJECT, so the wildcard has to be in the CANDIDATE:
    `llama.cpp` (a real formula) matched an excluded `llamaXcpp` and was dropped
    with it. The dependency path documents this same hazard."""
    stub = scenario(brew_env, tmp_path, "llamaXcpp", "llama.cpp")
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    line = [ln for ln in result.stdout.splitlines() if "Clean formulae to upgrade:" in ln][0]
    assert "llama.cpp" in line.split(":", 1)[1].split(), line


def test_unrelated_packages_are_unaffected(brew_env, tmp_path):
    """Baseline: a hold on one package leaves an unrelated one alone. Guards
    against a fix that simply stops excluding anything."""
    stub = scenario(brew_env, tmp_path, "python@3.12", "wget")
    result = run_upgrade({"DEPENDENCY_SECURITY_CHECK": str(stub)})
    line = [ln for ln in result.stdout.splitlines() if "Clean formulae to upgrade:" in ln][0]
    assert "wget" in line.split(":", 1)[1].split(), line
    assert "python@3.12" not in line.split(":", 1)[1].split(), line
