"""Cask-name → NVD search metadata map.

The vulnerability scanner queries NVD via `keywordSearch&keywordExactMatch`.
Cask names rarely match NVD descriptions verbatim — e.g. cask `brave-browser`
will never hit a CVE whose description says "Brave Browser version 1.x".
This map translates cask names into the canonical search keyword NVD expects,
plus the vendor:product pair for any future CPE-based version filtering.

REVIEW NOTES for sharkyger:
- Each entry curated by hand. Verify any you're uncertain about against
  https://nvd.nist.gov/vuln/search before merging.
- "keyword" is what's sent to NVD's keywordSearch (case-insensitive on their
  side, but capitalized here to match how vendors actually phrase product
  names in CVE descriptions).
- "vendor" / "product" are NVD CPE 2.3 vendor and product strings. Verify by
  searching nvd.nist.gov for a known CVE in the product and checking the
  CPE configurations.
- AMBIGUOUS / SKIPPED casks listed at the bottom — they have collisions or
  unclear NVD mapping and need more care before adding.
"""

CASK_NVD_MAP = {
    # ─── Browsers ──────────────────────────────────────────────────────────
    "google-chrome": {"keyword": "Google Chrome", "vendor": "google", "product": "chrome"},
    "chromium": {
        "keyword": "Chromium",
        "vendor": "chromium",
        "product": "chromium",
    },  # Own CPE namespace; engine CVEs also appear under google:chrome, keyword search catches both
    "firefox": {"keyword": "Mozilla Firefox", "vendor": "mozilla", "product": "firefox"},
    "brave-browser": {"keyword": "Brave Browser", "vendor": "brave", "product": "brave"},
    "microsoft-edge": {
        "keyword": "Microsoft Edge",
        "vendor": "microsoft",
        "product": "edge_chromium",
    },
    "opera": {"keyword": "Opera Browser", "vendor": "opera", "product": "opera"},
    "vivaldi": {"keyword": "Vivaldi Browser", "vendor": "vivaldi", "product": "vivaldi"},
    "tor-browser": {"keyword": "Tor Browser", "vendor": "torproject", "product": "tor"},
    "thunderbird": {
        "keyword": "Mozilla Thunderbird",
        "vendor": "mozilla",
        "product": "thunderbird",
    },
    # ─── Communication ─────────────────────────────────────────────────────
    "slack": {"keyword": "Slack Desktop", "vendor": "slack", "product": "slack"},
    "zoom": {"keyword": "Zoom Client", "vendor": "zoom", "product": "meetings"},
    "discord": {"keyword": "Discord Desktop", "vendor": "discord", "product": "discord"},
    "microsoft-teams": {"keyword": "Microsoft Teams", "vendor": "microsoft", "product": "teams"},
    "telegram": {
        "keyword": "Telegram Desktop",
        "vendor": "telegram",
        "product": "telegram_desktop",
    },
    "signal": {"keyword": "Signal Desktop", "vendor": "signal", "product": "signal_desktop"},
    "whatsapp": {"keyword": "WhatsApp Desktop", "vendor": "whatsapp", "product": "whatsapp"},
    # ─── Dev tools / IDEs ──────────────────────────────────────────────────
    "visual-studio-code": {
        "keyword": "Visual Studio Code",
        "vendor": "microsoft",
        "product": "visual_studio_code",
    },
    "vscodium": {  # VSCodium is built from MS VS Code source — same CVE exposure in core editor
        "keyword": "Visual Studio Code",
        "vendor": "microsoft",
        "product": "visual_studio_code",
    },
    "claude-code": {  # Anthropic CLI; minimal CVE history as of 2026 — entry is forward-looking
        "keyword": "Claude Code",
        "vendor": "anthropic",
        "product": "claude_code",
    },
    "iterm2": {"keyword": "iTerm2", "vendor": "iterm2", "product": "iterm2"},
    "intellij-idea": {
        "keyword": "IntelliJ IDEA",
        "vendor": "jetbrains",
        "product": "intellij_idea",
    },
    "intellij-idea-ce": {
        "keyword": "IntelliJ IDEA",
        "vendor": "jetbrains",
        "product": "intellij_idea",
    },
    "pycharm": {"keyword": "PyCharm", "vendor": "jetbrains", "product": "pycharm"},
    "pycharm-ce": {"keyword": "PyCharm", "vendor": "jetbrains", "product": "pycharm"},
    "webstorm": {"keyword": "WebStorm", "vendor": "jetbrains", "product": "webstorm"},
    "phpstorm": {"keyword": "PhpStorm", "vendor": "jetbrains", "product": "phpstorm"},
    "goland": {"keyword": "GoLand", "vendor": "jetbrains", "product": "goland"},
    "rubymine": {"keyword": "RubyMine", "vendor": "jetbrains", "product": "rubymine"},
    "clion": {"keyword": "CLion", "vendor": "jetbrains", "product": "clion"},
    "sublime-text": {"keyword": "Sublime Text", "vendor": "sublimehq", "product": "sublime_text"},
    "postman": {"keyword": "Postman", "vendor": "postman", "product": "postman"},
    "insomnia": {"keyword": "Insomnia REST", "vendor": "insomnia", "product": "insomnia"},
    "docker": {"keyword": "Docker Desktop", "vendor": "docker", "product": "desktop"},
    "docker-desktop": {"keyword": "Docker Desktop", "vendor": "docker", "product": "desktop"},
    "github": {"keyword": "GitHub Desktop", "vendor": "github", "product": "desktop"},
    "sourcetree": {"keyword": "Sourcetree", "vendor": "atlassian", "product": "sourcetree"},
    # ─── Productivity ──────────────────────────────────────────────────────
    "notion": {"keyword": "Notion Desktop", "vendor": "notion", "product": "notion"},
    "obsidian": {"keyword": "Obsidian", "vendor": "obsidian", "product": "obsidian"},
    "1password": {"keyword": "1Password", "vendor": "1password", "product": "1password"},
    "bitwarden": {
        "keyword": "Bitwarden Desktop",
        "vendor": "bitwarden",
        "product": "bitwarden_desktop",
    },
    "keepassxc": {"keyword": "KeePassXC", "vendor": "keepassxc", "product": "keepassxc"},
    "raycast": {"keyword": "Raycast", "vendor": "raycast", "product": "raycast"},
    # ─── Media ─────────────────────────────────────────────────────────────
    "spotify": {"keyword": "Spotify Desktop", "vendor": "spotify", "product": "spotify"},
    "vlc": {"keyword": "VLC media player", "vendor": "videolan", "product": "vlc_media_player"},
    "handbrake": {"keyword": "HandBrake", "vendor": "handbrake", "product": "handbrake"},
    "obs": {"keyword": "OBS Studio", "vendor": "obsproject", "product": "obs_studio"},
    # ─── Design ────────────────────────────────────────────────────────────
    "figma": {"keyword": "Figma Desktop", "vendor": "figma", "product": "desktop"},
    "sketch": {"keyword": "Sketch", "vendor": "sketch", "product": "sketch"},
    # ─── Cloud / sync ──────────────────────────────────────────────────────
    "dropbox": {"keyword": "Dropbox Desktop", "vendor": "dropbox", "product": "dropbox"},
    "google-drive": {"keyword": "Google Drive", "vendor": "google", "product": "drive"},
    "onedrive": {"keyword": "Microsoft OneDrive", "vendor": "microsoft", "product": "onedrive"},
    # ─── Virtualization ────────────────────────────────────────────────────
    "vmware-fusion": {"keyword": "VMware Fusion", "vendor": "vmware", "product": "fusion"},
    "parallels": {"keyword": "Parallels Desktop", "vendor": "parallels", "product": "desktop"},
    "virtualbox": {"keyword": "VirtualBox", "vendor": "oracle", "product": "vm_virtualbox"},
    # ─── Runtimes ──────────────────────────────────────────────────────────
    "temurin": {  # Eclipse Temurin (rebranded AdoptOpenJDK); some JDK CVEs also attributed to oracle:openjdk
        "keyword": "Eclipse Temurin",
        "vendor": "eclipse",
        "product": "temurin",
    },
}

# ─── DELIBERATELY SKIPPED — ambiguous, need careful research before adding ──
#
# arc            — "Arc" alone matches dozens of unrelated CVEs (Arc Welder,
#                  Arc Touch, Arc Compact, ARC firmware...). Needs "The Browser
#                  Company Arc" as keyword but NVD doesn't index it that way yet.
# tower          — "Tower" matches everything from Cisco Tower to Apache Tower
# spark          — Apache Spark vs Readdle Spark mail client collision
# caffeine       — too generic; macOS utility vs many code-named projects
# utm            — UTM (Unified Threat Management) firewall product collision
# alfred         — alfred-app collisions with industrial control system Alfred
# cursor         — Cursor (AI editor) vs cursor library / generic CVE descriptions
# warp           — Warp Terminal vs Cloudflare Warp vs other "warp" CVEs
# the-unarchiver — works with NVD but rarely has CVEs, low signal
# balenaetcher   — Balena ecosystem has split CVE attribution (etcher vs balena)
# transmission   — common word, very high noise floor
#
# Strategy for these: skip keyword search entirely (current behavior — no hits),
# OR build proper CPE-based queries in a future PR.


# ─── Self-check: no vendor:product duplicates that point at different casks ──
# (Allowed: two casks → same CPE, e.g. intellij-idea + intellij-idea-ce.)
# (Not allowed: same CPE for two unrelated casks.)
# Documented shared-source aliases: distinct cask names that legitimately
# share a CPE because they're built from the same upstream source. The
# validator allows these without flagging a collision.
SHARED_SOURCE_ALIASES = {
    # VSCodium is built from MS VS Code source — strips telemetry/branding,
    # but core-editor CVEs apply equally to both binaries.
    frozenset({"vscodium", "visual-studio-code"}),
}


def _validate_no_unintended_collisions():
    """Check map for unintended vendor:product collisions across distinct cask families.

    Allowed collisions:
      - Same product packaged under different cask names (e.g. intellij-idea
        + intellij-idea-ce, docker + docker-desktop) — detected via suffix stripping.
      - Documented shared-source aliases (see SHARED_SOURCE_ALIASES above).
    """
    seen = {}
    suffix_tokens = ("-ce", "-community", "-desktop")
    for cask, meta in CASK_NVD_MAP.items():
        key = (meta["vendor"], meta["product"])
        cask_family = cask
        for suffix in suffix_tokens:
            if cask_family.endswith(suffix):
                cask_family = cask_family[: -len(suffix)]
        if key in seen and seen[key] != cask_family:
            pair = frozenset({cask, seen[key]})
            if any(pair == alias for alias in SHARED_SOURCE_ALIASES):
                continue  # documented intentional alias
            raise ValueError(
                f"CPE collision: {cask} and {seen[key]} both map to "
                f"{key[0]}:{key[1]} but appear to be different products"
            )
        seen[key] = cask_family


if __name__ == "__main__":
    _validate_no_unintended_collisions()
    print(f"Cask map: {len(CASK_NVD_MAP)} entries, no unintended CPE collisions.")
