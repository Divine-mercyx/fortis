#!/usr/bin/env bash
# Builds the small Node that macOS and Linux binaries are made from, without the parts the CLI never
# uses. CI caches the result by this file's contents, so changing anything here rebuilds it.
# Takes from 30 minutes to over an hour, depending on the machine. Usage: build-node-runtime.sh <output file>
#
# Keep the JIT (--v8-lite-mode would make scans far slower), TLS, and process.report.
set -euo pipefail

NODE_VERSION=22.23.4
NODE_SHA256=7b9adc82d612d0a2a863d96c46de2292552e250cee51956ebbe0146c42aacae9

OUT=$1
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

curl -fsSL --retry 3 -o node.tar.xz "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION.tar.xz"
actual=$(python3 -c "import hashlib,sys;print(hashlib.sha256(open('node.tar.xz','rb').read()).hexdigest())")
[ "$actual" = "$NODE_SHA256" ] || { echo "FAILED: the Node source checksum is $actual"; exit 1; }
tar -xJf node.tar.xz
cd "node-v$NODE_VERSION"

EXTRA=()
case "$(uname -s)-$(uname -m)" in
  Linux-*)
    # Node exports every symbol for native addons with -rdynamic, which the CLI has no use for. That keeps
    # all its code alive. macOS's linker already drops unused code, which is why it was 15 MB smaller.
    export CFLAGS="-ffunction-sections -fdata-sections"
    export CXXFLAGS="-ffunction-sections -fdata-sections"
    export LDFLAGS="-Wl,--gc-sections -Wl,--exclude-libs,ALL"
    EXTRA+=(--without-node-code-cache)
    ;;
  Darwin-x86_64)
    # With chained fixups, adding the CLI to the binary breaks its thread-locals on Intel Macs:
    # dyld says "unsupported thread-local, larger than 4GB".
    export LDFLAGS="-Wl,-no_fixup_chains"
    ;;
esac

# small-icu: English only, instead of about 30 MB of data for every language.
# The odd expansion is for macOS's bash 3.2, where an empty array counts as unset under set -u.
./configure ${EXTRA[@]+"${EXTRA[@]}"} \
  --with-intl=small-icu \
  --without-npm \
  --without-corepack \
  --without-inspector \
  --without-amaro \
  --without-sqlite \
  --v8-enable-snapshot-compression

if [ "$(uname -s)" = Darwin ]; then JOBS=$(sysctl -n hw.ncpu); else JOBS=$(nproc); fi
make -j"$JOBS" > /dev/null

cp out/Release/node "$OUT"
if [ "$(uname -s)" = Darwin ]; then strip -x "$OUT"; else strip --strip-all "$OUT"; fi
"$OUT" -p '`Built Node ${process.version}`'
ls -l "$OUT"
