#!/usr/bin/env bash
# Commits a release's manifests to the Homebrew tap and the Scoop bucket.
# Usage: publish-manifests.sh <manifests folder>. Needs PACKAGE_REPOS_TOKEN and GITHUB_REF_NAME.
set -euo pipefail

OUT=$1
owner=Divine-mercyx

publish() {
  local repo=$1 from=$2
  local dir
  dir=$(mktemp -d)
  # The token goes in a header for this one command, not in the remote's URL or the repository's config.
  local auth
  auth="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$PACKAGE_REPOS_TOKEN" | base64 -w0)"
  git -c "http.extraheader=$auth" clone -q --depth 1 "https://github.com/$owner/$repo.git" "$dir"
  cp -R "$from"/. "$dir"/
  git -C "$dir" add -A
  if git -C "$dir" diff --cached --quiet; then
    echo "$repo is already up to date"
    return
  fi
  git -C "$dir" -c user.name='fortis-release' -c user.email='fortis-release@users.noreply.github.com' commit -q -m "fortis ${GITHUB_REF_NAME#cli-v}"
  git -C "$dir" -c "http.extraheader=$auth" push -q origin HEAD
  echo "updated $repo"
}

publish homebrew-tap "$OUT/homebrew"
publish scoop-bucket "$OUT/scoop"
