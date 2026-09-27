#!/bin/bash
# Cut a release: bump the version, commit, tag. Pushing the tag runs .github/workflows/release.yml
# (CI, portable static builds, GitHub release with sums and notes). Nothing is pushed here.
#
# Usage: bench/scripts/release.sh X.Y.Z [--no-test]
#   1. checks: clean tracked tree, on main, vX.Y.Z is new and greater than the current version
#   2. runs the unit tests (unless --no-test); the parity gates are yours to run first:
#        bench/scripts/check_all.sh, check_win_images.sh, check_nix.sh all, check_dumps.sh
#   3. sets the version in Cargo.toml, Cargo.lock and the docs' "Applies to fastvol X" lines
#   4. commits "release: vX.Y.Z" and makes the annotated tag vX.Y.Z
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

die() { echo "release.sh: $*" >&2; exit 1; }

new=${1:-}
[[ $new =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "usage: release.sh X.Y.Z [--no-test]"
test=1
[ "${2:-}" = --no-test ] && test=0

old=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$old" ] || die "no version in Cargo.toml"
[ "$new" != "$old" ] || die "Cargo.toml is already at $new"
[ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -1)" = "$new" ] || die "$new is not greater than $old"
git diff --quiet && git diff --cached --quiet || die "the working tree has uncommitted changes"
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || die "on branch $branch, not main"
git rev-parse -q --verify "refs/tags/v$new" > /dev/null && die "tag v$new exists"

if [ $test = 1 ]; then
    echo "== unit tests"
    bench/scripts/cargo.sh test --profile fast --locked 2>&1 | grep -E 'test result|FAILED|panicked|^error' || true
    bench/scripts/cargo.sh test --profile fast --locked > /dev/null 2>&1 || die "unit tests failed"
fi

echo "== $old -> $new"
# the [package] version (the first `version =` line), the lock entry of the fastvol package
sed -i "0,/^version = \"$old\"/s//version = \"$new\"/" Cargo.toml
awk -v old="$old" -v new="$new" '
    /^name = "fastvol"$/ { pkg = 1 }
    pkg && $0 == "version = \"" old "\"" { $0 = "version = \"" new "\""; pkg = 0 }
    { print }' Cargo.lock > Cargo.lock.new && mv Cargo.lock.new Cargo.lock
# "Applies to fastvol X" in the docs, and the `fvol --version` example in docs/usage.md
sed -i "s/^Applies to fastvol $old\b/Applies to fastvol $new/" docs/*.md
sed -i "s/^fastvol $old\$/fastvol $new/" docs/usage.md
cargo metadata --locked --offline --format-version 1 > /dev/null || die "Cargo.lock does not match Cargo.toml"

git add Cargo.toml Cargo.lock docs/*.md
git commit -q -m "release: v$new"
git tag -a "v$new" -m "fastvol $new"
git --no-pager log --oneline -1
git --no-pager diff --stat HEAD~1
echo
echo "Tagged v$new. Publish it with:"
echo "  git push origin main v$new"
