"""The dependency graph walk is batched and deduped.

The 2026-08-22 acceptance run spent 378 s in the dependency phase to find TWO
incoming deps: `brew deps` per package, then `brew info` + `brew list` per
(package, dep) pair, over closures that overlap almost entirely. The walk now
makes one `brew deps --for-each`, one `brew info`, one `brew list`, and decides
once per unique dep. These tests pin the observable contract: same verdicts,
each dep checked once, both owners of a shared dep held, per-item fallback
when the batch call fails, and the timing split so the next slow run says
where the time went.
"""

from tests.test_partial_upgrade import (
    fresh_commit,
    make_cve_stub,
    run_upgrade,
    write_deps,
    write_formula_info,
    write_installed_version,
    write_outdated,
)


def _two_parents_one_fresh_dep(brew_env):
    write_outdated(
        brew_env,
        [
            {"name": "player", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "editor", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "unrelated", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n, v in (
        ("player", "2.0"),
        ("editor", "2.0"),
        ("unrelated", "2.0"),
        ("taglib", "2.3.1"),
        ("zlib", "1.3"),
    ):
        write_formula_info(brew_env, n, v)
    write_deps(brew_env, "player", ["taglib", "zlib"])
    write_deps(brew_env, "editor", ["taglib", "zlib"])
    write_deps(brew_env, "unrelated", ["zlib"])
    write_installed_version(brew_env, "taglib", "2.2.0")  # incoming
    write_installed_version(brew_env, "zlib", "1.3")  # current → not incoming
    fresh_commit(brew_env, "taglib", days=0)


def test_shared_dep_is_checked_once_and_holds_both_owners(brew_env, tmp_path):
    _two_parents_one_fresh_dep(brew_env)
    stub = make_cve_stub(tmp_path)
    result = run_upgrade(
        ["--skip-unsafe"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="y\n"
    )
    out = result.stdout
    assert "Found 1 incoming dependency version(s) to check" in out, out
    assert out.count("checking taglib 2.3.1") == 1
    assert "[HOLD-DEP] taglib" in out
    held = next(line for line in out.splitlines() if "holding:" in line)
    assert "player" in held and "editor" in held, held
    assert "unrelated" not in held
    assert "Clean formulae to upgrade: unrelated" in out, out


def test_batch_info_failure_falls_back_per_dep(brew_env, tmp_path):
    """Real brew fails the whole `brew info a b c` when one name is unknown;
    the walk must then ask per dep and reach the same verdict."""
    _two_parents_one_fresh_dep(brew_env)
    stub = make_cve_stub(tmp_path)
    result = run_upgrade(
        ["--skip-unsafe"],
        env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub), "MOCK_BREW_INFO_BATCH_FAIL": "1"},
        input_text="y\n",
    )
    out = result.stdout
    assert "Found 1 incoming dependency version(s) to check" in out, out
    assert "[HOLD-DEP] taglib" in out
    assert "Clean formulae to upgrade: unrelated" in out, out


def test_timing_is_split_into_graph_and_checks(brew_env, tmp_path):
    _two_parents_one_fresh_dep(brew_env)
    stub = make_cve_stub(tmp_path)
    out = run_upgrade(
        ["--skip-unsafe"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="y\n"
    ).stdout
    assert "(dependency graph took " in out, out
    assert "(dependency checks took " in out, out
    assert out.index("dependency graph took") < out.index("dependency checks took")


def test_graph_timing_is_printed_even_with_no_incoming_deps(brew_env, tmp_path):
    write_outdated(
        brew_env, [{"name": "unrelated", "installed_versions": ["1.0"], "current_version": "2.0"}]
    )
    write_formula_info(brew_env, "unrelated", "2.0")
    write_formula_info(brew_env, "zlib", "1.3")
    write_deps(brew_env, "unrelated", ["zlib"])
    write_installed_version(brew_env, "zlib", "1.3")
    stub = make_cve_stub(tmp_path)
    out = run_upgrade(
        [], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="n\n"
    ).stdout
    assert "No new dependency versions coming in." in out, out
    assert "(dependency graph took " in out, out


def test_dep_membership_in_the_batch_is_literal_not_regex(brew_env, tmp_path):
    """`foo.bar` as a regex matches the clean package `fooXbar`; the dep would
    then be skipped as "already in the batch" and never checked."""
    write_outdated(
        brew_env,
        [
            {"name": "fooXbar", "installed_versions": ["1.0"], "current_version": "2.0"},
            {"name": "player", "installed_versions": ["1.0"], "current_version": "2.0"},
        ],
    )
    for n, v in (("fooXbar", "2.0"), ("player", "2.0"), ("foo.bar", "3.0")):
        write_formula_info(brew_env, n, v)
    write_deps(brew_env, "fooXbar", [])
    write_deps(brew_env, "player", ["foo.bar"])
    write_installed_version(brew_env, "foo.bar", "2.9")  # incoming
    fresh_commit(brew_env, "foo.bar", days=0)
    stub = make_cve_stub(tmp_path)
    out = run_upgrade(
        ["--skip-unsafe"], env_extra={"DEPENDENCY_SECURITY_CHECK": str(stub)}, input_text="y\n"
    ).stdout
    assert "checking foo.bar 3.0" in out, out
    assert "[HOLD-DEP] foo.bar" in out, out
