#!/bin/bash
# Install brew-safe-upgrade
# Usage: curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | bash

set -euo pipefail

INSTALL_DIR="$(brew --prefix 2>/dev/null || echo "/opt/homebrew")/bin"
REPO_URL="https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main"

echo "Installing brew-safe-upgrade and brew-safe-install..."

# Check write permissions
if [ ! -w "$INSTALL_DIR" ]; then
    echo "Error: No write permission to $INSTALL_DIR"
    echo "Try: sudo bash -c \"\$(curl -fsSL $REPO_URL/install.sh)\""
    echo "Or:  git clone https://github.com/sharkyger/homebrew-safe-upgrade.git && cd homebrew-safe-upgrade && sudo cp brew-safe-upgrade dependency_security_check.py $INSTALL_DIR/"
    exit 1
fi

# Download files
for file in brew-safe-upgrade brew-safe-install brew-safe-update dependency_security_check.py; do
    curl -fsSL "$REPO_URL/$file" -o "$INSTALL_DIR/$file"
    chmod +x "$INSTALL_DIR/$file"
done

echo "Installed to $INSTALL_DIR/"
echo "Commands: brew safe-upgrade, brew safe-install, brew safe-update"
