"""Brew version resolution — the gate must not block the version that FIXES a CVE.

`resolve_latest_version()` handled pip and npm only; for brew it returned None
and the caller then checked the formula against its ENTIRE CVE history, so any
formula that ever had an advisory came back vulnerable at every version. The
reported case: `brew install gitleaks` refused because of CVE-2026-63728
("Gitleaks prior to 8.30.1 ..."), at Homebrew's stable 8.30.1 — the release
carrying the fix.

Fully mocked: no network, no Homebrew binary needed.
"""

import json
import subprocess
from unittest.mock import patch

import dependency_security_check as dsc


def _completed(stdout, returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr="")


def test_brew_version_read_from_formula_stable():
    payload = json.dumps({"formulae": [{"versions": {"stable": "8.30.1"}}], "casks": []})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("gitleaks") == "8.30.1"


def test_brew_version_read_from_cask_top_level():
    # Casks carry `version` at the top level, not under versions{}.
    payload = json.dumps({"formulae": [], "casks": [{"version": "1.2.3"}]})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("some-cask") == "1.2.3"


def test_brew_version_none_when_binary_missing():
    # Linux, CI, or any machine without Homebrew.
    with patch.object(dsc.subprocess, "run", side_effect=FileNotFoundError):
        assert dsc._resolve_brew_version("gitleaks") is None


def test_brew_version_none_on_timeout():
    with patch.object(
        dsc.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="brew", timeout=20)
    ):
        assert dsc._resolve_brew_version("gitleaks") is None


def test_brew_version_none_on_nonzero_exit():
    with patch.object(dsc.subprocess, "run", return_value=_completed("", returncode=1)):
        assert dsc._resolve_brew_version("no-such-formula") is None


def test_brew_version_none_on_malformed_json():
    with patch.object(dsc.subprocess, "run", return_value=_completed("not json at all")):
        assert dsc._resolve_brew_version("gitleaks") is None


def test_brew_version_none_when_payload_has_no_version():
    payload = json.dumps({"formulae": [{"versions": {}}], "casks": []})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("gitleaks") is None


def test_brew_version_none_on_non_dict_payload():
    """`--json=v1` emits a top-level list; the helper must hold up alone."""
    with patch.object(dsc.subprocess, "run", return_value=_completed('[{"versions": {}}]')):
        assert dsc._resolve_brew_version("gitleaks") is None


def test_cask_build_suffix_is_stripped():
    """Homebrew writes cask versions as `version,build` — only the first part
    is the marketing version a CVE range talks about."""
    payload = json.dumps({"formulae": [], "casks": [{"version": "6.0.2,1234"}]})
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)):
        assert dsc._resolve_brew_version("some-cask") == "6.0.2"


def test_brew_name_passed_as_argv_never_through_a_shell():
    """A crafted formula name must not be able to become a command.

    The payload carries a command separator; the assertion is that it survives
    as ONE argv element, so a shell never sees it.
    """
    payload = json.dumps({"formulae": [{"versions": {"stable": "1.0"}}], "casks": []})
    crafted = "gitleaks; touch /tmp/pwned"
    with patch.object(dsc.subprocess, "run", return_value=_completed(payload)) as run:
        dsc._resolve_brew_version(crafted)
    args, kwargs = run.call_args
    assert isinstance(args[0], list)
    assert args[0][-1] == crafted  # inert: a single argv element
    assert kwargs.get("shell") in (None, False)


def test_resolve_latest_version_routes_brew_and_leaves_others_alone():
    with patch.object(dsc, "_resolve_brew_version", return_value="8.30.1") as brew:
        assert dsc.resolve_latest_version("gitleaks", "brew") == "8.30.1"
        brew.assert_called_once_with("gitleaks")
    # Ecosystems with no branch still return None rather than being intercepted.
    with patch.object(dsc, "_resolve_brew_version") as brew:
        assert dsc.resolve_latest_version("some/pkg", "cargo") is None
        brew.assert_not_called()
