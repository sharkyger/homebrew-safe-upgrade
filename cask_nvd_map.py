"""Cask token → NVD search keyword.

The vulnerability scanner queries NVD via `keywordSearch&keywordExactMatch`.
Cask tokens (e.g. `brave-browser`) rarely match NVD descriptions verbatim —
a CVE for Brave Browser will say "Brave" or "Brave Browser", not the brew
slug. This map translates the slug into the canonical product name brew
already publishes per cask.

DATA SOURCE
-----------
Keywords are derived from Homebrew's cask API:

  https://formulae.brew.sh/api/cask/<token>.json   →  .name[0]
  https://formulae.brew.sh/api/cask.json           (full catalog, ~14 MB)

For each cask token, the value is brew's canonical `name[0]` field unless
listed in `OVERRIDES` below. Overrides exist only where brew's name is
demonstrably bad for NVD search (verbose vendor prefixes, edition suffixes,
or entries shorter than the scanner's 4-character minimum).

To extend the map: pick the cask token (visible at formulae.brew.sh/cask/),
look up its `name[0]` via the API, and add the entry. The validator at the
bottom enforces a 4-char minimum so the scanner doesn't silently skip the
NVD query.

CPE-BASED FILTERING (not implemented)
-------------------------------------
This map intentionally does NOT include CPE `vendor:product` strings.
The scanner currently relies on NVD keyword search only; CPE-based version
filtering is a future improvement that would also need its own data source
(NVD's CPE dictionary). Shipping speculative CPE strings here would just
create dead code with maintenance burden.
"""

# Overrides where brew's name[0] is demonstrably worse than a manual choice
# for NVD search. Rationale per entry:
#   temurin            — brew "Eclipse Temurin Java Development Kit" is too verbose for NVD
#   obs                — brew "OBS" is 3 chars, fails the scanner's len<4 guard
#   phpstorm           — brew "JetBrains PhpStorm" prefix not used in NVD descriptions
#   pycharm-ce         — brew "Jetbrains PyCharm Community Edition" — strip prefix + edition
#   sourcetree         — brew "Atlassian SourceTree" — strip vendor prefix
#   visual-studio-code — brew "Microsoft Visual Studio Code" — strip vendor
#   virtualbox         — brew "Oracle VirtualBox" — strip vendor; NVD uses both forms
#   intellij-idea[-ce] — brew "IntelliJ IDEA Ultimate" / "...Community Edition" — strip edition
#   vscodium           — built from MS VS Code source; CVE attribution is to MS
#   telegram           — brew "Telegram for macOS"; NVD descriptions use "Telegram Desktop"
#   onedrive           — brew "OneDrive"; NVD descriptions consistently use the full form
OVERRIDES = {
    "temurin": "Eclipse Temurin",
    "obs": "OBS Studio",
    "phpstorm": "PhpStorm",
    "pycharm-ce": "PyCharm",
    "sourcetree": "Sourcetree",
    "visual-studio-code": "Visual Studio Code",
    "virtualbox": "VirtualBox",
    "intellij-idea": "IntelliJ IDEA",
    "intellij-idea-ce": "IntelliJ IDEA",
    "vscodium": "Visual Studio Code",
    "telegram": "Telegram Desktop",
    "onedrive": "Microsoft OneDrive",
}

CASK_NVD_KEYWORDS = {
    "1password": "1Password",
    "bitwarden": "Bitwarden",
    "brave-browser": "Brave",
    "chromium": "Chromium",
    "claude-code": "Claude Code",
    "clion": "CLion",
    "discord": "Discord",
    "docker-desktop": "Docker Desktop",
    "dropbox": "Dropbox",
    "figma": "Figma",
    "firefox": "Mozilla Firefox",
    "github": "GitHub Desktop",
    "goland": "Goland",
    "google-chrome": "Google Chrome",
    "google-drive": "Google Drive",
    "handbrake-app": "HandBrake",
    "insomnia": "Insomnia",
    "intellij-idea": "IntelliJ IDEA",
    "intellij-idea-ce": "IntelliJ IDEA",
    "iterm2": "iTerm2",
    "keepassxc": "KeePassXC",
    "microsoft-edge": "Microsoft Edge",
    "microsoft-teams": "Microsoft Teams",
    "notion": "Notion",
    "obs": "OBS Studio",
    "obsidian": "Obsidian",
    "onedrive": "Microsoft OneDrive",
    "opera": "Opera",
    "parallels": "Parallels Desktop",
    "phpstorm": "PhpStorm",
    "postman": "Postman",
    "pycharm": "PyCharm",
    "pycharm-ce": "PyCharm",
    "raycast": "Raycast",
    "rubymine": "RubyMine",
    "signal": "Signal",
    "sketch": "Sketch",
    "slack": "Slack",
    "sourcetree": "Sourcetree",
    "spotify": "Spotify",
    "sublime-text": "Sublime Text",
    "telegram": "Telegram Desktop",
    "temurin": "Eclipse Temurin",
    "thunderbird": "Mozilla Thunderbird",
    "tor-browser": "Tor Browser",
    "virtualbox": "VirtualBox",
    "visual-studio-code": "Visual Studio Code",
    "vivaldi": "Vivaldi",
    "vlc": "VLC media player",
    "vmware-fusion": "VMware Fusion",
    "vscodium": "Visual Studio Code",
    "webstorm": "WebStorm",
    "whatsapp": "WhatsApp",
    "zoom": "Zoom",
}

# Minimum keyword length matches the scanner's NVD-noise guard
# (`len(search_name) < 4` short-circuits the query). Keywords shorter
# than 4 chars silently skip the query, which would mean false-clean
# results for the affected cask.
MIN_KEYWORD_LEN = 4


def _validate():
    """Enforce schema rules: keyword strings, no empties, length ≥ 4."""
    for token, keyword in CASK_NVD_KEYWORDS.items():
        if not isinstance(keyword, str):
            raise TypeError(f"{token}: keyword must be str, got {type(keyword).__name__}")
        if not keyword:
            raise ValueError(f"{token}: empty keyword")
        if len(keyword) < MIN_KEYWORD_LEN:
            raise ValueError(
                f"{token}: keyword {keyword!r} is shorter than {MIN_KEYWORD_LEN} chars — "
                f"scanner would silently skip the NVD query. Use a longer canonical name."
            )


if __name__ == "__main__":
    _validate()
    print(f"Cask map: {len(CASK_NVD_KEYWORDS)} entries, validation OK.")
