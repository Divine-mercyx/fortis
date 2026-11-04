#!/bin/sh
# Installs the Fortis CLI on Linux or macOS. It needs no Node.
#   curl -fsSL https://github.com/Divine-mercyx/fortis/releases/latest/download/install.sh | sh
# FORTIS_VERSION pins a version, FORTIS_INSTALL_DIR changes where it goes (default ~/.fortis/bin).
set -eu

REPO="${FORTIS_REPO:-Divine-mercyx/fortis}"
DIR="${FORTIS_INSTALL_DIR:-$HOME/.fortis/bin}"
VERSION="${FORTIS_VERSION:-}"

fail() {
  echo "fortis install: $1" >&2
  exit 1
}

case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *) fail "this script is for Linux and macOS. On Windows use install.ps1." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) ARCH=x64 ;;
  arm64 | aarch64) ARCH=arm64 ;;
  *) fail "no build for $(uname -m). Use npm (npm i -D fortis-watchdog) or the Docker image." ;;
esac
if [ "$OS" = linux ] && { [ -f /etc/alpine-release ] || ldd --version 2>&1 | grep -qi musl; }; then
  fail "the binary needs glibc, and this system uses musl. Use the Docker image, or npm (npm i -D fortis-watchdog)."
fi

if [ -n "$VERSION" ]; then
  BASE="https://github.com/$REPO/releases/download/cli-v$VERSION"
else
  BASE="https://github.com/$REPO/releases/latest/download"
fi
ASSET="fortis-$OS-$ARCH.tar.gz"

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O "$2"
  else
    fail "needs curl or wget."
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $ASSET ..."
fetch "$BASE/$ASSET" "$TMP/$ASSET" || fail "could not download $BASE/$ASSET"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || fail "could not download the checksums"

cd "$TMP"
grep "[ *]$ASSET\$" SHA256SUMS >expected || fail "$ASSET is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c expected >/dev/null 2>&1 || fail "checksum mismatch for $ASSET. Not installing it."
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 -c expected >/dev/null 2>&1 || fail "checksum mismatch for $ASSET. Not installing it."
else
  fail "needs sha256sum or shasum to verify the download."
fi

tar -xzf "$ASSET"
mkdir -p "$DIR"
mv fortis "$DIR/fortis"
chmod 755 "$DIR/fortis"

echo "Installed fortis $("$DIR/fortis" --version) to $DIR/fortis"
case ":$PATH:" in
  *":$DIR:"*) ;;
  *)
    echo
    echo "Add it to your PATH (for example in ~/.bashrc or ~/.zshrc):"
    echo "  export PATH=\"$DIR:\$PATH\""
    ;;
esac
