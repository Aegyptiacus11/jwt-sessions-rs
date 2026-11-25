#!/usr/bin/env bash
# check-tag.sh <tag>: may the commit checked out be published as <tag>?
# The tag is v and the version in Cargo.toml, and the commit is on origin/main. Anything else
# is an error: a version published to crates.io can be yanked, never replaced.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "::error::usage: check-tag.sh <tag>"
  exit 2
fi
tag="$1"

if ! version="$(cargo metadata --no-deps --format-version 1 |
  jq -er 'if (.packages | length) == 1 then .packages[0].version else error("expected one package") end')"; then
  echo "::error::the version cannot be read from Cargo.toml"
  exit 1
fi
if [ "$tag" != "v$version" ]; then
  echo "::error::tag $tag does not match the version in Cargo.toml, $version"
  exit 1
fi

if ! git rev-parse --verify --quiet 'origin/main^{commit}' > /dev/null; then
  echo "::error::origin/main is not here: check out with fetch-depth 0"
  exit 1
fi
if ! git merge-base --is-ancestor HEAD origin/main; then
  echo "::error::the commit of $tag is not on main"
  exit 1
fi

echo "$tag may be published"
