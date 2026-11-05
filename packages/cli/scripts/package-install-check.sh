#!/usr/bin/env bash
# Installs the latest published release through the generated manifests, with the real package
# managers: Homebrew on macOS and Linux, Scoop and winget on Windows. Run from the repository root.
set -euo pipefail

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
VERSION=$(curl -fsSI https://github.com/Divine-mercyx/fortis/releases/latest | tr -d '\r' | sed -n 's#^[Ll]ocation: .*/tag/cli-v##p')
[ -n "$VERSION" ] || { echo 'FAILED: could not find the latest release'; exit 1; }
curl -fsSL -o "$work/SHA256SUMS" "https://github.com/Divine-mercyx/fortis/releases/download/cli-v$VERSION/SHA256SUMS"
node packages/cli/scripts/package-manifests.mjs --version "$VERSION" --sums "$work/SHA256SUMS" --out "$work/out"

case "$RUNNER_OS" in
  macOS | Linux)
    if [ "$RUNNER_OS" = Linux ]; then eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"; fi
    export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_INSTALL_CLEANUP=1
    brew tap-new --no-git fortis/check > /dev/null
    cp "$work/out/homebrew/Formula/fortis.rb" "$(brew --repository)/Library/Taps/fortis/homebrew-check/Formula/fortis.rb"
    brew install fortis/check/fortis
    brew test fortis/check/fortis
    [ "$(fortis --version)" = "$VERSION" ] || { echo "FAILED: brew installed $(fortis --version)"; exit 1; }
    echo "ok: brew installs $VERSION"
    ;;
  Windows)
    manifests=$(cygpath -w "$work/out")
    pwsh -NoProfile -File packages/cli/scripts/package-install-check.ps1 -Version "$VERSION" -Manifests "$manifests"
    ;;
esac
