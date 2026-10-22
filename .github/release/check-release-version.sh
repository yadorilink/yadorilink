#!/usr/bin/env bash
# Fail unless every shipped version string equals the version derived from the
# release tag (vX.Y.Z or vX.Y.Z-pre.N).
#
# Why: the update check compares semver, and 0.1.0-beta.N < 0.1.0. A beta
# tag built from a 0.1.0 manifest would announce a version that is never newer
# than what is installed, so no update notice appears.
#
# Usage: .github/release/check-release-version.sh [vX.Y.Z[-pre.N]]
#   (defaults to $GITHUB_REF_NAME). Run from anywhere inside the repo.
set -euo pipefail

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

# The channel manifest version is passed from the tag (--version) by the
# release workflow, so it equals $want by construction.
[ "$fails" -eq 0 ] || { echo "Bump the files above to $want before tagging $tag." >&2; exit 1; }
echo "release version check passed for $tag"
