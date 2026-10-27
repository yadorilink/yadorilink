#!/usr/bin/env bash
# Fail unless every shipped version string equals the version derived from the
# release tag (vX.Y.Z or vX.Y.Z-pre.N).
#
# Why: the update check compares semver, and 0.1.0-beta.N < 0.1.0. A beta
# tag built from a 0.1.0 manifest would announce a version that is never newer
# than what is installed, so no update notice appears.
#
# Every version-bearing file the bump touches is checked: the workspace manifest and
# lockfile, and the Windows shell extension manifest and lockfile (it is not a workspace
# member, so it carries its own version and lockfile).
#
# Usage: .github/release/check-release-version.sh [vX.Y.Z[-pre.N]]
#        .github/release/check-release-version.sh --self-test
#   (tag defaults to $GITHUB_REF_NAME). Run from anywhere inside the repo.
set -euo pipefail

if [ "${1:-}" = "--self-test" ]; then
  me="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  t="$(mktemp -d)"
  trap 'rm -rf "$t"' EXIT
  ext=crates/yadorilink-shell-ext-windows
  mkdir -p "$t/.github/release" "$t/$ext"
  cp "$me" "$t/.github/release/check-release-version.sh"
  seed() {
    printf '[workspace.package]\nversion = "0.1.0-beta.1"\n' >"$t/Cargo.toml"
    printf '[[package]]\nname = "yadorilink-cli"\nversion = "0.1.0-beta.1"\n' >"$t/Cargo.lock"
    printf '[package]\nname = "yadorilink-shell-ext-windows"\nversion = "0.1.0-beta.1"\n' >"$t/$ext/Cargo.toml"
    printf '[[package]]\nname = "yadorilink-shell-ext-windows"\nversion = "0.1.0-beta.1"\n' >"$t/$ext/Cargo.lock"
  }
  run() { bash "$t/.github/release/check-release-version.sh" v0.1.0-beta.1 >/dev/null 2>&1; }
  seed
  run || { echo "self-test FAILED: a consistent tree was rejected" >&2; exit 1; }
  for f in Cargo.toml Cargo.lock "$ext/Cargo.toml" "$ext/Cargo.lock"; do
    seed
    sed 's/beta\.1/beta.0/' "$t/$f" >"$t/$f.new" && mv "$t/$f.new" "$t/$f"
    if run; then echo "self-test FAILED: drift in $f was not caught" >&2; exit 1; fi
  done
  echo "self-test: 4/4 drifts caught"
  exit 0
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tag="${1:-${GITHUB_REF_NAME:-}}"
if ! [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$ ]]; then
  echo "usage: $0 vX.Y.Z[-pre.N]  (got '${tag}')" >&2
  exit 2
fi
want="${tag#v}"

fails=0
check() { # label file got
  if [ "$3" = "$want" ]; then
    echo "ok   $1 = $3"
  else
    echo "FAIL $1 ($2) is '${3:-<not found>}', tag wants '$want'" >&2
    fails=$((fails + 1))
  fi
}

cargo="$(awk '/^\[/{s=$0} s=="[workspace.package]" && /^version[ ]*=/{gsub(/.*= *"|".*/,""); print; exit}' "$root/Cargo.toml")"
check "Cargo.toml workspace.package.version" Cargo.toml "$cargo"

ext=crates/yadorilink-shell-ext-windows
ext_version="$(awk '/^\[/{s=$0} s=="[package]" && /^version[ ]*=/{gsub(/.*= *"|".*/,""); print; exit}' "$root/$ext/Cargo.toml" 2>/dev/null || true)"
check "$ext/Cargo.toml package.version" "$ext/Cargo.toml" "$ext_version"

# A lockfile records the version of every yadorilink-* package; the bump must reach all of them.
lock_versions() { awk '/^name = "yadorilink/{n=1; next} /^version = /&&n{gsub(/.*= *"|".*/,""); print; n=0}' "$1" 2>/dev/null | sort -u | paste -sd, - || true; }
check "Cargo.lock yadorilink package versions" Cargo.lock "$(lock_versions "$root/Cargo.lock")"
check "$ext/Cargo.lock yadorilink package versions" "$ext/Cargo.lock" "$(lock_versions "$root/$ext/Cargo.lock")"

# The channel manifest version is passed from the tag (--version) by the
# release workflow, so it equals $want by construction.
[ "$fails" -eq 0 ] || { echo "Bump the files above to $want before tagging $tag." >&2; exit 1; }
echo "release version check passed for $tag"
