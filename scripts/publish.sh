#!/usr/bin/env bash
# Release step: publish the packed tarballs in assets/ to whichever registry the @paratco scope points at (set by
# setup-node in the workflow). Platform packages first: the main package must never point at a version that is not
# there yet. A version the registry already has is skipped, so a release that failed halfway can be re-run.
# Extra arguments go to every `npm publish`.
set -euo pipefail

version="$(node -p "require('./package.json').version")"

publish() {
  local name="$1" tarball="$2"
  shift 2

  if npm view "$name@$version" version >/dev/null 2>&1; then
    echo "skip $name@$version: already published"
    return
  fi

  npm publish "$tarball" "$@"
}

for dir in npm/*; do
  target="$(basename "$dir")"
  publish "@paratco/device-key-$target" "./assets/paratco-device-key-$target-$version.tgz" "$@"
done

publish "@paratco/device-key" "./assets/paratco-device-key-$version.tgz" "$@"
