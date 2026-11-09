#!/usr/bin/env bash
# Signs a macOS binary with the hardened runtime, then notarizes it, so Gatekeeper doesn't warn.
# Usage: sign-macos.sh <binary>
#
# APPLE_CERT_P12_BASE64, APPLE_CERT_PASSWORD   the "Developer ID Application" certificate
# APPLE_API_KEY_P8_BASE64, APPLE_API_KEY_ID, APPLE_API_ISSUER_ID   an App Store Connect API key
#
# With FORTIS_SIGN_CHECK=1 it signs ad hoc with the same options and stops, with no certificate.
# CI uses that to prove the binary still runs under the hardened runtime.
set -euo pipefail

BIN=$1
ENTITLEMENTS="$(cd "$(dirname "$0")" && pwd)/macos-entitlements.plist"
sign() { codesign --force --options runtime --entitlements "$ENTITLEMENTS" "$@" "$BIN"; }

if [ "${FORTIS_SIGN_CHECK:-}" = 1 ]; then
  sign --sign -
  codesign --verify --strict "$BIN"
  "$BIN" --version
  "$BIN" rules > /dev/null
  echo 'ok: runs under the hardened runtime'
  exit 0
fi

WORK=$(mktemp -d)
KEYCHAIN="$WORK/signing.keychain-db"
KEYCHAIN_PASSWORD=$(openssl rand -hex 16)
trap 'security delete-keychain "$KEYCHAIN" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "$APPLE_CERT_P12_BASE64" | base64 --decode > "$WORK/cert.p12"
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security set-keychain-settings -lut 3600 "$KEYCHAIN"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
security import "$WORK/cert.p12" -k "$KEYCHAIN" -P "$APPLE_CERT_PASSWORD" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN" > /dev/null
security list-keychains -d user -s "$KEYCHAIN" $(security list-keychains -d user | tr -d '"')

IDENTITY=$(security find-identity -v -p codesigning "$KEYCHAIN" | sed -n 's/.*"\(Developer ID Application:.*\)"/\1/p' | head -1)
[ -n "$IDENTITY" ] || { echo 'FAILED: no Developer ID Application certificate in APPLE_CERT_P12_BASE64'; exit 1; }

sign --sign "$IDENTITY" --timestamp
codesign --verify --strict "$BIN"

# A bare binary can't have a ticket stapled to it, so Gatekeeper looks it up online when it first runs.
echo "$APPLE_API_KEY_P8_BASE64" | base64 --decode > "$WORK/key.p8"
ditto -c -k --keepParent "$BIN" "$WORK/notarize.zip"
xcrun notarytool submit "$WORK/notarize.zip" --key "$WORK/key.p8" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" --wait --timeout 30m
echo 'ok: signed and notarized'
