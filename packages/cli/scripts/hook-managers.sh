#!/usr/bin/env bash
# Checks the documented pre-commit, lefthook and Husky setups with real pushes. A new key must be
# blocked, and clean code must go through.
# Run from the repository root, after `pnpm --filter fortis-watchdog build`. Needs git, Node and Python.
set -euo pipefail

repo_root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# `fortis` on the PATH, as the docs ask for.
mkdir -p "$work/bin"
printf '#!/bin/sh\nexec node "%s/packages/cli/dist/fortis.js" "$@"\n' "$repo_root" > "$work/bin/fortis"
chmod +x "$work/bin/fortis"
export PATH="$work/bin:$PATH"
export FORTIS_KEY=''

# Built here, so the repository never holds anything a secret scanner flags.
KEY="$(printf 'sk_%s_%s' live abcdef0123456789abcdef0123456789abcdef01)"

new_project() {
  local name=$1
  git init -q --bare "$work/$name.git"
  git clone -q "$work/$name.git" "$work/$name" 2> /dev/null
  cd "$work/$name"
  git config user.email t@example.com
  git config user.name Test
  git checkout -q -b main
  echo 'const ok = 1;' > clean.js
  git add -A
  git commit -q -m clean
}

check_pushes() {
  local name=$1
  git add -A
  git commit -q -m 'set up the hook manager'
  git push -q origin main || { echo "FAILED ($name): a clean push was blocked"; exit 1; }

  echo "const PAYSTACK = \"$KEY\";" > leak.js
  git add -A
  git commit -q -m leak
  if git push -q origin main 2> "$work/$name.log"; then
    echo "FAILED ($name): a push with a live key went through"
    exit 1
  fi
  grep -q 'FX-SEC-001' "$work/$name.log" || { echo "FAILED ($name): blocked, but not by Fortis"; cat "$work/$name.log"; exit 1; }
  if grep -q "$KEY" "$work/$name.log"; then
    echo "FAILED ($name): the key appeared in the output"
    exit 1
  fi

  git reset -q --hard HEAD~1
  echo 'const alsoOk = 2;' > more.js
  git add -A
  git commit -q -m 'more clean code'
  git push -q origin main || { echo "FAILED ($name): a later clean push was blocked"; exit 1; }
  echo "ok: $name"
}

# pre-commit, reading .pre-commit-hooks.yaml from this checkout at this commit.
python -m venv "$work/venv"
"$work/venv/bin/pip" install -q pre-commit
new_project pre-commit
cat > .pre-commit-config.yaml << YAML
repos:
  - repo: file://$repo_root
    rev: $(git -C "$repo_root" rev-parse HEAD)
    hooks:
      - id: fortis
YAML
"$work/venv/bin/pre-commit" install --hook-type pre-push > /dev/null
check_pushes pre-commit

# lefthook
new_project lefthook
cat > lefthook.yml << 'YAML'
pre-push:
  commands:
    fortis:
      run: fortis scan --pre-push --stdin
      use_stdin: true
YAML
echo '{ "private": true }' > package.json
npm install -s --no-audit --no-fund lefthook
printf 'node_modules/\n' > .gitignore
npx lefthook install > /dev/null
check_pushes lefthook

# Husky
new_project husky
echo '{ "private": true }' > package.json
npm install -s --no-audit --no-fund husky
printf 'node_modules/\n' > .gitignore
npx husky init > /dev/null
rm .husky/pre-commit
# The docs use npx for a project dependency. Here the CLI is on the PATH instead of in node_modules.
echo 'fortis scan --pre-push --stdin' > .husky/pre-push
check_pushes husky
