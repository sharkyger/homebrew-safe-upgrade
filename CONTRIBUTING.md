# Contributing

Thanks for considering a contribution to homebrew-safe-upgrade. This is a solo-maintained tool, so a few notes up front to set expectations:

- I review PRs and issues when I have time, usually within a few days.
- Small, focused changes get merged faster than sprawling ones.
- If you're planning something bigger than a bug fix, open a [Discussion](https://github.com/sharkyger/homebrew-safe-upgrade/discussions) or issue first so we can align before you write code.

## Reporting issues

Three flavors:

- **Bug** — something doesn't work the way it should
- **Feature request** — something you'd like the tool to do
- **False positive** — the tool flagged a package that shouldn't be flagged (the most common kind — pick this one if a CVE check looks wrong)

Pick the right template at <https://github.com/sharkyger/homebrew-safe-upgrade/issues/new/choose>.

**Security issues**: do not open a public issue. See [SECURITY.md](SECURITY.md) for the private disclosure flow.

## Dev setup

```bash
git clone https://github.com/sharkyger/homebrew-safe-upgrade.git
cd homebrew-safe-upgrade
pip install -r requirements-dev.txt
```

Run the tests:

```bash
pytest
```

Run the linters (CI will block your PR if these fail):

```bash
ruff check .
shellcheck brew-safe-upgrade brew-safe-install brew-safe-update install.sh
```

## Branching

- Branch from `main`
- Use prefixes: `feature/`, `fix/`, `docs/`, `chore/`
- One logical change per branch — don't mix unrelated work

## Pull requests

Good PRs:

- Solve one problem (or a tightly scoped set of related ones)
- Include or update tests when behavior changes
- Pass CI: ruff, shellcheck, pytest, CodeQL, Gitleaks
- Have a description that says **what** changed and **why** — not just what

Less good PRs:

- Mix unrelated changes
- Add new dependencies without justification (this tool intentionally uses Python stdlib only)
- Skip tests "because it's a small change"
- Reformat unrelated files

## Adding new ecosystems to the standalone checker

`dependency_security_check.py` works for any ecosystem the three databases cover. Adding a new one usually means:

1. Add the ecosystem to the `OSV_ECOSYSTEMS` map
2. Add version-resolution logic if the ecosystem has a "latest" registry
3. Add tests covering at least one known-vulnerable and one known-clean version

## Maintainer

Maintained by [@sharkyger](https://github.com/sharkyger). Thanks for contributing.
