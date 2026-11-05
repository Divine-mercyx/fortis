#!/usr/bin/env bash
# Writes .fortis-baseline.json for the same small repository and prints its fingerprints, so CI can
# check that Windows (CRLF checkout, backslash-friendly paths) and macOS/Linux agree exactly.
#   baseline-parity.sh <fortis-watchdog .tgz> <output file>
set -euo pipefail
TGZ="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OUT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) TGZ="$(cygpath -m "$TGZ")"; CRLF=true ;; *) CRLF=false ;; esac
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
export FORTIS_API_URL=http://127.0.0.1:9 NO_COLOR=1
cd "$WORK"
git init -q -b main repo && cd repo
git config user.email e2e@example.com && git config user.name E2E
echo '{ "name": "parity", "version": "1.0.0", "private": true }' > package.json
npm install -D --no-audit --no-fund "$TGZ" >/dev/null
printf 'node_modules/\n' > .gitignore
KEY="AKIA$(printf 'ABCD2345%.0s' 1 2)"
mkdir -p src/config legacy
printf '// keys\n\nexport const aws = "%s";\n' "$KEY" > src/config/keys.ts
printf 'DB_PASSWORD=%s\n' "Zq8$(printf 'vR3nT6%.0s' 1 2 3)" > .env.production
printf 'const k = "%s"; // second file\n' "$KEY" > legacy/old.js
git add -A && git commit -qm fixture
# On Windows, check the files out again with CRLF endings, as most Windows users have them.
if [ "$CRLF" = true ]; then
  git config core.autocrlf true
  git rm -q --cached -r . && git reset -q --hard
  file src/config/keys.ts 2>/dev/null | grep -q CRLF || echo 'note: files were not checked out with CRLF' >&2
fi
npx --no-install fortis baseline --offline >/dev/null
node -e "const b=require('./.fortis-baseline.json'); console.log([...b.fingerprints].sort().join('\n'))" > "$OUT"
echo "$(wc -l < "$OUT") fingerprints written to $OUT"
