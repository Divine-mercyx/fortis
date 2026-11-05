#!/usr/bin/env bash
# Install-and-push check, the way a user meets Fortis: install it, run `fortis init`, and push.
#   e2e.sh <method> <artifact>
#     npm | pnpm | yarn1 | yarn-pnp | bun | global   <artifact> = the packed fortis-watchdog .tgz
#     binary                                          <artifact> = a built standalone binary
#     installer                                       <artifact> = a folder with fortis-<os>-<arch>.tar.gz
#                                                     and SHA256SUMS, served to install.sh over HTTP
# Checks, in a throwaway repository with a local bare remote:
#   1. a key committed in the FIRST commit of a first push is blocked, even under a clean later commit;
#   2. the fixed code is pushed;
#   3. a new key is blocked again;
#   4. hooks written by earlier versions are upgraded in place, keeping the user's own lines.
set -euo pipefail

METHOD="$1"
ARTIFACT="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true' EXIT
export FORTIS_API_URL=http://127.0.0.1:9 # never talk to a real API from a test
export FORTIS_CACHE_DIR="$WORK/cache"
export NO_COLOR=1
case "$(uname -s)" in MINGW* | MSYS* | CYGWIN*) WINDOWS=1 ;; *) WINDOWS= ;; esac
# npm, pnpm, Yarn and Bun on Windows want C:/... paths, not Git Bash's /c/...
[ -n "$WINDOWS" ] && ARTIFACT="$(cygpath -m "$ARTIFACT")"

step() { printf '\n== %s\n' "$*"; }
fail() {
  echo "FAILED ($METHOD): $*"
  [ -f "$WORK/out.txt" ] && cat "$WORK/out.txt"
  exit 1
}

git init -q --bare "$WORK/origin.git"
git init -q -b main "$WORK/repo"
cd "$WORK/repo"
git config user.email e2e@example.com
git config user.name E2E
git config core.autocrlf false
git remote add origin "$WORK/origin.git"
echo '{ "name": "e2e-app", "version": "1.0.0", "private": true }' > package.json

step "install with $METHOD"
case "$METHOD" in
  npm) npm install -D --no-audit --no-fund "$ARTIFACT" >/dev/null; RUN=(npx --no-install fortis) ;;
  pnpm) pnpm add -D "$ARTIFACT" >/dev/null; RUN=(pnpm exec fortis) ;;
  yarn1)
    corepack yarn@1.22.22 --version >/dev/null
    printf '{ "name": "e2e-app", "version": "1.0.0", "private": true, "packageManager": "yarn@1.22.22" }\n' > package.json
    corepack yarn@1.22.22 add -D "file:$ARTIFACT" >/dev/null
    RUN=(./node_modules/.bin/fortis)
    ;;
  yarn-pnp)
    printf '{ "name": "e2e-app", "version": "1.0.0", "private": true, "packageManager": "yarn@4.5.3" }\n' > package.json
    printf 'nodeLinker: pnp\nenableGlobalCache: false\n' > .yarnrc.yml
    # Corepack fetches Yarn 4 from repo.yarnpkg.com unless told to use the npm registry, which more networks allow.
    export COREPACK_NPM_REGISTRY="${COREPACK_NPM_REGISTRY:-https://registry.npmjs.org}"
    corepack yarn add -D "fortis-watchdog@file:$ARTIFACT" >/dev/null
    [ -f .pnp.cjs ] || fail "Yarn did not use Plug'n'Play"
    RUN=(corepack yarn fortis)
    # The hook calls plain `yarn`; make it the project's Yarn, as corepack does on a developer's machine.
    mkdir -p "$WORK/shims"
    printf '#!/bin/sh\nexec corepack yarn "$@"\n' > "$WORK/shims/yarn" && chmod +x "$WORK/shims/yarn"
    export PATH="$WORK/shims:$PATH"
    ;;
  bun) bun add -d "$ARTIFACT" >/dev/null; RUN=(bunx --bun fortis) ;;
  global)
    npm install -g --prefix "$WORK/global" --no-audit --no-fund "$ARTIFACT" >/dev/null
    if [ -n "$WINDOWS" ]; then export PATH="$WORK/global:$PATH"; else export PATH="$WORK/global/bin:$PATH"; fi
    RUN=(fortis)
    ;;
  binary)
    mkdir -p "$WORK/bin" && cp "$ARTIFACT" "$WORK/bin/" && export PATH="$WORK/bin:$PATH"
    RUN=("$WORK/bin/$(basename "$ARTIFACT")")
    ;;
  installer)
    PORT=$((20000 + RANDOM % 20000))
    (cd "$ARTIFACT" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
    SERVER_PID=$!
    for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$PORT/SHA256SUMS" >/dev/null 2>&1 && break; sleep 0.2; done
    if [ -n "$WINDOWS" ]; then
      FORTIS_DOWNLOAD_BASE="http://127.0.0.1:$PORT" FORTIS_INSTALL_DIR="$(cygpath -w "$WORK/fortis-bin")" \
        powershell -NoProfile -ExecutionPolicy Bypass -File "$SCRIPTS/../install/install.ps1"
    else
      FORTIS_DOWNLOAD_BASE="http://127.0.0.1:$PORT" FORTIS_INSTALL_DIR="$WORK/fortis-bin" sh "$SCRIPTS/../install/install.sh"
    fi
    export PATH="$WORK/fortis-bin:$PATH"
    RUN=(fortis)
    ;;
  *) fail "unknown method $METHOD" ;;
esac
"${RUN[@]}" --version || fail 'the CLI does not run'

step 'fortis init'
"${RUN[@]}" init >"$WORK/out.txt" 2>&1 || fail "init failed"
grep -q 'fortis scan --pre-push' .git/hooks/pre-push || fail 'init did not install the pre-push hook'
printf 'node_modules/\n.yarn/\n.pnp.*\n' > .gitignore

# An AWS-format key, which the free rules treat as critical. Assembled so this script isn't flagged.
KEY="AKIA$(printf 'ABCD2345%.0s' 1 2)"

step 'a key in the first commit of a first push is blocked'
echo "export const key = '$KEY';" > config.js
git add -A && git commit -qm 'first, with a key'
echo 'export const ok = true;' > other.js
git add -A && git commit -qm 'second, clean'
if git push -q origin main >"$WORK/out.txt" 2>&1; then fail 'the first push with a key in an earlier commit was not blocked'; fi
grep -q 'config.js' "$WORK/out.txt" || fail 'the report did not name config.js'

step 'the fix is pushed'
echo 'export const key = process.env.AWS_KEY;' > config.js
git add -A && git commit -qm 'read the key from the environment'
# The key is still in the first commit; a real team rotates it and rewrites or accepts history.
git push -q --no-verify origin main
echo 'export const more = 1;' > more.js
git add -A && git commit -qm 'clean change'
git push -q origin main >"$WORK/out.txt" 2>&1 || fail 'a clean push was blocked'

step 'a new key is blocked'
echo "export const again = '$KEY';" > again.js
git add -A && git commit -qm 'new key'
if git push -q origin main >"$WORK/out.txt" 2>&1; then fail 'the push with a new key was not blocked'; fi
grep -q 'again.js' "$WORK/out.txt" || fail 'the report did not name again.js'
git reset -q --hard HEAD~1

step 'hooks from earlier versions are upgraded, keeping the user’s lines'
for old in 'npx --no-install fortis scan --pre-push' 'npx --no-install fortis scan --pre-push --stdin' 'npx --no-install fortis scan --pre-push || exit 1'; do
  printf '#!/bin/sh\necho "my own check"\n# fortis-pre-push\n%s\necho "after fortis"\n' "$old" > .git/hooks/pre-push
  chmod +x .git/hooks/pre-push
  "${RUN[@]}" init >"$WORK/out.txt" 2>&1 || fail "init failed on a hook with: $old"
  grep -q 'my own check' .git/hooks/pre-push || fail "upgrading lost the user's line before ($old)"
  grep -q 'after fortis' .git/hooks/pre-push || fail "upgrading lost the user's line after ($old)"
  grep -q -- '--stdin' .git/hooks/pre-push || fail "the hook was not upgraded ($old)"
  [ "$(grep -c 'fortis scan --pre-push' .git/hooks/pre-push)" -le 4 ] || fail "the Fortis lines were duplicated ($old)"
done
echo "export const again = '$KEY';" > again.js
git add -A && git commit -qm 'new key under an upgraded hook'
if git push -q origin main >"$WORK/out.txt" 2>&1; then fail 'the upgraded hook did not block a key'; fi
grep -q 'my own check' "$WORK/out.txt" || fail "the user's own hook line did not run"

printf '\ne2e passed: %s\n' "$METHOD"
