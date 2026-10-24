#!/usr/bin/env bash
# Print the comma-separated Docker tags for a git ref.
#
# Usage: docker-image-tags.sh IMAGE REF      e.g. ghcr.io/o/yadorilink-daemon refs/tags/v0.1.0-beta.1
#        docker-image-tags.sh --self-test
#
# refs/tags/vX.Y.Z          -> IMAGE:X.Y.Z,IMAGE:latest   (stable only)
# refs/tags/vX.Y.Z-pre.N    -> IMAGE:X.Y.Z-pre.N          (never `latest`)
# anything else             -> IMAGE:nightly
set -euo pipefail

tags_for() {
  local image="$1" ref="$2" version
  if [[ "$ref" == refs/tags/v* ]]; then
    version="${ref#refs/tags/v}"
    if [[ "$version" == *-* ]]; then
      printf '%s:%s\n' "$image" "$version"
    else
      printf '%s:%s,%s:latest\n' "$image" "$version" "$image"
    fi
  else
    printf '%s:nightly\n' "$image"
  fi
}

if [ "${1:-}" = "--self-test" ]; then
  fail=0
  expect() { # ref want
    got="$(tags_for img "$1")"
    if [ "$got" != "$2" ]; then echo "FAIL $1: got '$got', want '$2'" >&2; fail=1; fi
  }
  expect refs/tags/v0.1.0 "img:0.1.0,img:latest"
  expect refs/tags/v0.1.0-beta.3 "img:0.1.0-beta.3"
  expect refs/tags/v1.2.3-rc.2 "img:1.2.3-rc.2"
  expect refs/heads/main "img:nightly"
  [ "$fail" -eq 0 ] || exit 1
  echo "docker-image-tags self-test passed"
  exit 0
fi

[ "$#" -eq 2 ] || { echo "usage: $0 IMAGE REF | --self-test" >&2; exit 2; }
tags_for "$1" "$2"
