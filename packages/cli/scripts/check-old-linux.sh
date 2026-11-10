#!/usr/bin/env bash
# Checks a Linux (glibc) fortis binary runs on the oldest systems we promise: glibc 2.28, which is
# what the manylinux_2_28 wheels and the Debian 12 Docker image claim. beta.12's binary needed
# glibc 2.38 and failed on both, so the release now stops here instead of publishing it.
# Usage: check-old-linux.sh path/to/fortis. Needs objdump, and Docker for the run checks.
set -euo pipefail

BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"

# 1. The library versions the binary asks for. Newest allowed is what AlmaLinux 8 ships.
newest() { objdump -T "$BIN" | grep -o "$1_[0-9][0-9.]*" | sed "s/^$1_//" | sort -uV | tail -1; }
fail=0
for pair in GLIBC:2.28 GLIBCXX:3.4.25 CXXABI:1.3.11; do
  lib=${pair%%:*} max=${pair#*:}
  got=$(newest "$lib")
  [ -z "$got" ] && continue
  if [ "$(printf '%s\n%s\n' "$got" "$max" | sort -V | tail -1)" != "$max" ]; then
    echo "FAILED: the binary needs ${lib}_$got, newer than ${lib}_$max"
    objdump -T "$BIN" | grep "${lib}_$got" | head -5
    fail=1
  else
    echo "ok: needs ${lib}_$got at most (limit $max)"
  fi
done
[ "$fail" = 0 ] || exit 1

# 2. Run it on each. The Docker image uses Debian 12; 22.04 is the oldest Ubuntu still supported.
for image in debian:bookworm-slim ubuntu:22.04 almalinux:8.10; do
  docker run --rm -v "$BIN:/usr/local/bin/fortis:ro" "$image" sh -euc '
    fortis --version >/dev/null
    fortis rules | grep -q DEP-OSV
  ' || { echo "FAILED: fortis does not run on $image"; exit 1; }
  echo "ok: runs on $image"
done
