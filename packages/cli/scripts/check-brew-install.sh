#!/usr/bin/env bash
# Installs Fortis from the Homebrew tap with the README's command, and checks it's this version.
# release-cli.yml runs it on macOS and Linux once the tap has the release.
# Usage: check-brew-install.sh <version>
set -euo pipefail

VERSION=$1
# GitHub's Linux runners have Homebrew installed, but not on the PATH.
command -v brew > /dev/null || eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1

brew install divine-mercyx/tap/fortis
got=$("$(brew --prefix)/bin/fortis" --version)
if [ "$got" != "$VERSION" ]; then
  echo "FAILED: brew installed fortis $got, not $VERSION"
  exit 1
fi
brew test divine-mercyx/tap/fortis
echo "ok: brew install divine-mercyx/tap/fortis installs $VERSION"
