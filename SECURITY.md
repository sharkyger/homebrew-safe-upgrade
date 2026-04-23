# Security Policy

## Supported Versions

Only the latest released version is supported.

## Reporting a Vulnerability

**Do not open a public issue for security reports.**

Use GitHub's private vulnerability reporting:
https://github.com/sharkyger/homebrew-safe-upgrade/security/advisories/new

You can expect an acknowledgement within 7 days.

## Scope

In scope:

- Bugs in `dependency_security_check.py` that cause known-vulnerable versions to be classified as clean.
- Bugs in `brew-safe-*` scripts that could lead to arbitrary command execution.
- Weaknesses in the install or update process.

Out of scope:

- Known false positives from upstream vulnerability databases.
- Vulnerabilities in Homebrew itself (report to the Homebrew team).
- Vulnerabilities in the packages being scanned (this tool reports them, it does not fix them).
