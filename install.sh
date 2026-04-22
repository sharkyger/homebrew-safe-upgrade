#!/bin/bash
# Install brew-safe-upgrade
# Usage: curl -fsSL https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main/install.sh | bash

set -euo pipefail

INSTALL_DIR="${HOMEBREW_PREFIX:-/opt/homebrew}/bin"
REPO_URL="https://raw.githubusercontent.com/sharkyger/homebrew-safe-upgrade/main"

echo "Installing brew-safe-upgrade..."

# Check write permissions
if [ ! -w "$INSTALL_DIR" ]; then
    echo "Error: No write permission to $INSTALL_DIR"
    echo "Try: sudo bash -c \"\$(curl -fsSL $REPO_URL/install.sh)\""
    echo "Or:  git clone https://github.com/sharkyger/homebrew-safe-upgrade.git && cd homebrew-safe-upgrade && sudo cp brew-safe-upgrade dependency_security_check.py $INSTALL_DIR/"
    exit 1
fi

# Download both files
curl -fsSL "$REPO_URL/brew-safe-upgrade" -o "$INSTALL_DIR/brew-safe-upgrade"
curl -fsSL "$REPO_URL/dependency_security_check.py" -o "$INSTALL_DIR/dependency_security_check.py"

chmod +x "$INSTALL_DIR/brew-safe-upgrade"
chmod +x "$INSTALL_DIR/dependency_security_check.py"

echo "Installed to $INSTALL_DIR/"
echo "Run: brew safe-upgrade"
