#!/usr/bin/env bash
# Checks a musl build on a clean Alpine: install.sh must say what's missing, then install it, and the
# binary must find a key. Usage: alpine-check.sh <folder with the .tar.gz>. Needs Docker. Run from the repository root.
set -euo pipefail

RELEASE=$(cd "$1" && pwd)
(cd "$RELEASE" && sha256sum fortis-*.tar.gz > SHA256SUMS)

docker run --rm -v "$RELEASE:/release:ro" -v "$PWD/packages/cli/install/install.sh:/install.sh:ro" alpine:3.22 sh -euc '
  apk add --no-cache -q curl
  # Serve the release folder the way GitHub does, through the same download code as a real install.
  export FORTIS_DOWNLOAD_BASE=http://127.0.0.1:8123
  apk add --no-cache -q busybox-extras
  httpd -p 8123 -h /release

  if sh /install.sh > /tmp/first.txt 2>&1; then
    cat /tmp/first.txt
    echo "FAILED: the installer went ahead without libstdc++"
    exit 1
  fi
  grep -q "apk add libstdc++" /tmp/first.txt || { cat /tmp/first.txt; echo "FAILED: the installer did not say what to install"; exit 1; }

  apk add --no-cache -q libstdc++ git
  sh /install.sh
  export PATH="$HOME/.fortis/bin:$PATH"
  export FORTIS_NO_UPDATE_CHECK=1

  mkdir /repo && cd /repo
  git init -q && git config user.email ci@example.com && git config user.name CI
  KEY="AKIA$(printf "ABCD2345%.0s" 1 2)"
  echo "const key = \"$KEY\";" > config.js
  git add -A && git commit -qm key
  if fortis scan --offline --no-upload > /tmp/scan.txt 2>&1; then
    cat /tmp/scan.txt
    echo "FAILED: the binary did not block a key"
    exit 1
  fi
  grep -q SEC-GEN-001 /tmp/scan.txt || { cat /tmp/scan.txt; echo "FAILED: unexpected output"; exit 1; }
  echo "ok: Alpine installs and scans"
'
