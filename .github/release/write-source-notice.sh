#!/usr/bin/env bash
# Writes the AGPL-3.0 licence text and a source pointer into a directory that is
# about to be packaged, so every distributed binary artifact carries both.
#
#   .github/release/write-source-notice.sh <source-ref> <dest-dir>
#
# <source-ref> is the git ref the artifact was built from: the release tag
# (e.g. v0.2.0) for tagged builds, otherwise the full commit SHA, so a
# rolling or manually dispatched build points at the exact tree it came from
# rather than at an unrelated release tag. The release workflow computes it
# once as YADORILINK_SOURCE_REF.
set -euo pipefail

if [ $# -ne 2 ] || [ -z "$1" ]; then
  echo "usage: $0 <version> <dest-dir>" >&2
  exit 2
fi
source_ref="$1"
dest="$2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
repo_url="https://github.com/yadorilink/yadorilink"

mkdir -p "$dest"
cp "$repo_root/LICENSE" "$dest/LICENSE"
printf 'Corresponding source: %s/tree/%s\n' "$repo_url" "$source_ref" > "$dest/SOURCE.txt"
