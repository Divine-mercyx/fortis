#!/usr/bin/env bash
# Commits a release's manifests to the Homebrew tap and the Scoop bucket.
# Usage: publish-manifests.sh <manifests folder>. Needs PACKAGE_REPOS_TOKEN and GITHUB_REF_NAME.
# FORTIS_PACKAGE_REMOTE replaces https://github.com/Divine-mercyx, for tests.
set -euo pipefail

OUT=$1
remote=${FORTIS_PACKAGE_REMOTE:-https://github.com/Divine-mercyx}
failed=0

publish() {
  local repo=$1 from=$2
  local dir
  dir=$(mktemp -d)
  # The token goes in a header for each command, not in the remote's URL or the repository's config.
  local auth
  auth="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$PACKAGE_REPOS_TOKEN" | base64 | tr -d '\n')"
  if ! git -c "http.extraheader=$auth" clone -q --depth 1 "$remote/$repo.git" "$dir" 2>/dev/null; then
    echo "::error::Couldn't read $repo. Create it as a public repository, and give PACKAGE_REPOS_TOKEN access to it (Contents: read and write)."
    failed=1
    return
  fi
  # A new, empty repository needs no first commit: this one becomes it, on main.
  git -C "$dir" rev-parse -q --verify HEAD > /dev/null || git -C "$dir" checkout -q -b main
  cp -R "$from"/. "$dir"/
  git -C "$dir" add -A
  if git -C "$dir" diff --cached --quiet; then
    echo "$repo is already up to date"
    return
  fi
  git -C "$dir" -c user.name='fortis-release' -c user.email='fortis-release@users.noreply.github.com' commit -q -m "fortis ${GITHUB_REF_NAME#cli-v}"
  if ! git -C "$dir" -c "http.extraheader=$auth" push -q origin HEAD 2>/dev/null; then
    echo "::error::Couldn't push to $repo. PACKAGE_REPOS_TOKEN needs Contents: read and write on it."
    failed=1
    return
  fi
  echo "updated $repo"
}

publish homebrew-tap "$OUT/homebrew"
publish scoop-bucket "$OUT/scoop"
exit $failed
