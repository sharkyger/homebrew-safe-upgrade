"""GitHub token resolution, including Homebrew's environment scrub.

`brew` does not exec an external command with the user's environment. bin/brew
rebuilds it:

    FILTERED_ENV=()
    ENV_VAR_NAMES=(HOME SHELL PATH TERM ... http_proxy https_proxy ...)
    for VAR in "${ENV_VAR_NAMES[@]}" "${!HOMEBREW_@}"; do ... done
    exec /usr/bin/env -i "${FILTERED_ENV[@]}" ... brew.sh "$@"

Only that allowlist plus every HOMEBREW_* variable survives. So the advice to
`export GH_TOKEN=...` is silently ineffective for anyone invoking the tool as
`brew safe-upgrade` — the token is dropped before the script starts and the age
check runs anonymously at 60 requests/hour. Two spellings do get through:
HOMEBREW_GITHUB_API_TOKEN (Homebrew's own documented variable), and an
authenticated `gh` CLI, whose token comes off disk rather than the environment.

resolve_gh_token is extracted and sourced rather than driven end-to-end: it is a
self-contained function, and this keeps the precedence assertions exact.
"""

import os
import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = ["brew-safe-upgrade", "brew-safe-install"]

TOKEN_ENV_VARS = [
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "HOMEBREW_GITHUB_API_TOKEN",
]


def extract_function(script: str, name: str) -> str:
    src = (REPO / script).read_text()
    match = re.search(rf"^{name}\(\) \{{.*?^\}}", src, re.MULTILINE | re.DOTALL)
    assert match, f"{name} not found in {script}"
    return match.group(0)


def resolve(script: str, env_overrides: dict, tmp_path: Path) -> str:
    """Source resolve_gh_token in isolation and return what it resolves to."""
    fn = tmp_path / "fn.sh"
    fn.write_text(extract_function(script, "resolve_gh_token") + "\n")

    env = {k: v for k, v in os.environ.items() if k not in TOKEN_ENV_VARS}
    # An authenticated host `gh` would otherwise satisfy the no-token case. bash
    # is invoked by absolute path because this PATH cannot resolve it.
    empty_bin = tmp_path / "empty_bin"
    empty_bin.mkdir(exist_ok=True)
    env["PATH"] = str(empty_bin)
    env.update(env_overrides)

    result = subprocess.run(
        ["/bin/bash", "-c", f"set -u; . '{fn}'; resolve_gh_token"],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize("script", SCRIPTS)
def test_homebrew_github_api_token_is_honoured(script, tmp_path):
    """The only environment spelling that survives `brew`'s scrub."""
    assert resolve(script, {"HOMEBREW_GITHUB_API_TOKEN": "hb-token"}, tmp_path) == "hb-token"


@pytest.mark.parametrize("script", SCRIPTS)
def test_gh_token_takes_precedence(script, tmp_path):
    """Explicit beats inherited: a directly-exported GH_TOKEN is the strongest
    signal of intent, and it does reach the script on the direct-invocation and
    CI routes where nothing scrubs the environment."""
    resolved = resolve(
        script,
        {"GH_TOKEN": "gh-token", "GITHUB_TOKEN": "gha-token", "HOMEBREW_GITHUB_API_TOKEN": "hb"},
        tmp_path,
    )
    assert resolved == "gh-token"


@pytest.mark.parametrize("script", SCRIPTS)
def test_github_token_beats_homebrew_prefixed(script, tmp_path):
    resolved = resolve(
        script, {"GITHUB_TOKEN": "gha-token", "HOMEBREW_GITHUB_API_TOKEN": "hb"}, tmp_path
    )
    assert resolved == "gha-token"


@pytest.mark.parametrize("script", SCRIPTS)
def test_no_token_resolves_empty_not_an_error(script, tmp_path):
    """Anonymous requests still work, just at 60/hour. Resolution must never
    fail the run — under `set -u` an unguarded read here would abort it."""
    assert resolve(script, {}, tmp_path) == ""


@pytest.mark.parametrize("script", SCRIPTS)
def test_blank_token_falls_through(script, tmp_path):
    """An exported-but-empty GH_TOKEN must not shadow a usable one."""
    resolved = resolve(script, {"GH_TOKEN": "", "HOMEBREW_GITHUB_API_TOKEN": "hb-token"}, tmp_path)
    assert resolved == "hb-token"
