#!/usr/bin/env bash
# The tests of check-tag.sh, on a small crate in a repository made for them (in a new
# temporary directory, left there).
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/check-tag.sh"
work="$(mktemp -d)"

commit() { git -c user.name=test -c user.email=test@localhost -c commit.gpgsign=false commit -q "$@"; }

failed=0
# expect <exit code> <text the output must have> <what is tested> <arguments...>
expect() {
  local code="$1" text="$2" what="$3" got=0 out
  shift 3
  out="$("$script" "$@" 2>&1)" || got=$?
  if [ "$got" -eq "$code" ] && [[ "$out" == *"$text"* ]]; then
    echo "ok: $what"
  else
    echo "FAILED: $what: exit code $got (expected $code), output: $out"
    failed=1
  fi
}

mkdir -p "$work/src"
cd "$work"
git init -q -b main
cp "$here/../../rust-toolchain.toml" .
touch src/lib.rs
printf '[package]\nname = "sample"\nversion = "1.2.3"\nedition = "2021"\n' > Cargo.toml
git add .
commit -m one

expect 1 "origin/main is not here" "a checkout without main" v1.2.3

git update-ref refs/remotes/origin/main HEAD
expect 0 "v1.2.3 may be published" "the version, on main" v1.2.3
expect 1 "does not match" "another version" v1.2.4
expect 1 "does not match" "no v before the version" 1.2.3
expect 1 "does not match" "a pre-release of the version" v1.2.3-rc1
expect 1 "does not match" "an empty tag" ""
expect 2 "usage" "no tag"

commit --allow-empty -m two
expect 1 "not on main" "a commit that is not on main" v1.2.3

git update-ref refs/remotes/origin/main HEAD
git checkout -q HEAD~1
expect 0 "v1.2.3 may be published" "an older commit of main" v1.2.3

printf '[package]\nname = "sample"\nversion = "2.0.0-rc.1"\nedition = "2021"\n' > Cargo.toml
expect 0 "v2.0.0-rc.1 may be published" "a pre-release" v2.0.0-rc.1

printf 'not toml' > Cargo.toml
expect 1 "cannot be read" "a Cargo.toml cargo cannot read" v1.2.3

exit "$failed"
