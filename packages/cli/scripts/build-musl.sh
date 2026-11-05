#!/usr/bin/env bash
# Builds and smoke-tests the musl binary for this machine's CPU, inside Alpine, and packages it.
# Usage: build-musl.sh <asset name, e.g. linux-x64-musl> <output folder>. Needs Docker. Run from the repository root.
set -euo pipefail

NAME=$1
OUT=$2
mkdir -p "$OUT"

# A copy, so Alpine's node_modules and build output never mix with the host's.
WORK=$(mktemp -d)
trap 'sudo rm -rf "$WORK" 2>/dev/null || rm -rf "$WORK"' EXIT
git archive --format=tar HEAD | tar -x -C "$WORK"

docker run --rm -v "$WORK:/src" -w /src node:22-alpine3.22 sh -euc '
  apk add --no-cache -q git bash
  npm install -g --silent pnpm@10.28.0
  pnpm install --frozen-lockfile --filter fortis-watchdog... --silent
  pnpm --filter fortis-watchdog build:binary
  git config --global user.email ci@example.com
  git config --global user.name CI
  git config --global init.defaultBranch main
  bash packages/cli/scripts/smoke.sh packages/cli/dist-sea/fortis
  chmod -R a+rwX packages/cli/dist-sea
'

tar -czf "$OUT/fortis-$NAME.tar.gz" -C "$WORK/packages/cli/dist-sea" fortis
ls -l "$OUT"
