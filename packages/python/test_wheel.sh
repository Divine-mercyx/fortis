#!/usr/bin/env bash
# Installs a built wheel into fresh virtual environments and runs the CLI from them.
# Usage: test_wheel.sh path/to/fortis_watchdog-*.whl
set -euo pipefail

WHEEL="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

for py in 3.9 3.13; do
  uv venv -q --python "$py" "venv-$py"
  uv pip install -q --python "venv-$py" "$WHEEL"
  if [ -x "venv-$py/Scripts/fortis.exe" ]; then EXE="venv-$py/Scripts/fortis.exe"; else EXE="venv-$py/bin/fortis"; fi
  echo "python $py: fortis $("$EXE" --version)"
  "$EXE" rules | grep -q 'DEP-OSV'
done
echo 'wheel test passed'
