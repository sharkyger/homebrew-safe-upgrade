"""Homebrew formula → verified NVD CPE `(vendor, product)`.

WHY THIS EXISTS
---------------
The scanner queries NVD CPE-first with a vendor wildcard
(`cpe:2.3:a:*:<name>:<version>`) and, when that returns nothing, falls back to
a keyword search on the formula name. The fallback is for products NVD has no
CPE for. For a product NVD *does* know, running it anyway is harmful:

  * `php` / `ruby` / `node` / `certifi` as keywords match thousands of records
    about unrelated software ("PHP remote file inclusion in <some PHP app>",
    "ruby-saml ..."). The result set exceeds NVD's 1,000-record window, the
    scanner reports "coverage incomplete" and fails closed — a permanent hold —
    or, below the window, blocks the package on 2003-era CVEs of other
    products. Both were seen on a live 50-package run (2026-08-21).
  * A vendor wildcard can also match the wrong product outright
    (`*:python` returned the VS Code Python extension).

For a formula listed here the CPE query uses the verified vendor and is
AUTHORITATIVE: zero results means NVD lists no CVE for that version, and the
keyword fallback is NOT run. Versioned formulae (`python@3.12`, `openssl@3`)
resolve through their base name.

DATA SOURCE / HOW TO EXTEND
---------------------------
Every entry was verified against NVD's CPE dictionary on the date noted:

    https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:a:<vendor>:<product>:*

and must return at least one dictionary entry. Do NOT guess a vendor — a
wrong pair silently turns a real product into "no CVEs". CPython's vendor is
`python`, not `python_software_foundation` (0 entries). Add only formulae
whose bare name is generic enough to collide or overflow (`php`, `node`,
`ruby`, `certifi`); the default path works for the rest, and a distinctive
name such as `wget` gains nothing from being pinned.
"""

# formula -> (vendor, product)            # CPE-dictionary entries, verified 2026-08-21
FORMULA_NVD_CPE = {
    "certifi": ("certifi", "certifi"),  # 61
    "curl": ("haxx", "curl"),  # 224
    "git": ("git-scm", "git"),  # 1016
    "glib": ("gnome", "glib"),  # 563
    "hugo": ("gohugo", "hugo"),  # 1292
    "imagemagick": ("imagemagick", "imagemagick"),  # 1702
    "libssh2": ("libssh2", "libssh2"),  # 41
    "node": ("nodejs", "node.js"),  # 1693
    "openldap": ("openldap", "openldap"),  # 74
    "openssl": ("openssl", "openssl"),  # 354
    "pandoc": ("pandoc", "pandoc"),  # 205
    "php": ("php", "php"),  # 1618
    "python": ("python", "python"),  # 640
    "ruby": ("ruby-lang", "ruby"),  # 1097
    "sqlite": ("sqlite", "sqlite"),  # 372
}


def lookup(formula_name: str) -> tuple[str, str] | None:
    """`(vendor, product)` for a formula, resolving `name@version` to `name`.

    Returns None when the formula is not mapped.
    """
    base = formula_name.split("@", 1)[0].lower()
    return FORMULA_NVD_CPE.get(base)
