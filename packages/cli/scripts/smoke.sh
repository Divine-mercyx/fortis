#!/usr/bin/env bash
# Checks a built fortis binary end to end: runs, blocks a live key at a real git push, then lets
# the fixed code through. Usage: smoke.sh path/to/fortis
set -euo pipefail

BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$BIN" --version
"$BIN" rules | grep -q 'DEP-OSV'

git init -q --bare "$WORK/origin.git"
git init -q -b main "$WORK/repo"
cd "$WORK/repo"
git config user.email smoke@example.com
git config user.name Smoke
git remote add origin "$WORK/origin.git"
export FORTIS_API_URL=http://127.0.0.1:9 # never talk to a real API from a smoke test

# Hooks find the CLI on PATH, as they would on a machine without Node.
export PATH="$(dirname "$BIN"):$PATH"
"$BIN" init >/dev/null
grep -q 'fortis scan --pre-push' .git/hooks/pre-push

echo 'class Wallet {}' > Wallet.java
git add -A && git commit -qm 'first'
git push -q origin main
echo 'pushed clean code'

# An AWS-format key, which the free rules treat as critical. Assembled so this script isn't flagged.
KEY="AKIA$(printf 'ABCD2345%.0s' 1 2)"
echo "String key = \"$KEY\";" > Config.java
git add -A && git commit -qm 'add key'
if git push -q origin main >"$WORK/out.txt" 2>&1; then
  cat "$WORK/out.txt"
  echo 'FAILED: the push with a key was not blocked'
  exit 1
fi
grep -q 'Config.java' "$WORK/out.txt" || { cat "$WORK/out.txt"; echo 'FAILED: the report did not name the file'; exit 1; }
echo 'blocked the key'

echo 'String key = System.getenv("KEY");' > Config.java
git add -A && git commit -qm 'use env'
git push -q origin main >"$WORK/out.txt" 2>&1 || { cat "$WORK/out.txt"; echo 'FAILED: the fixed code was blocked'; exit 1; }
echo 'pushed the fix'

# A full scan outside any repository must fail loudly rather than pass on zero files.
cd "$WORK"
mkdir empty && cd empty
if "$BIN" scan --offline >/dev/null 2>&1; then
  echo 'FAILED: scanning no files passed'
  exit 1
fi
echo 'smoke test passed'
