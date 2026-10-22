#!/usr/bin/env bash
#
# Generate the third-party license notice that ships with distributed
# artifacts: one plain-text file listing the third-party crates compiled into
# the given packages, grouped by licence text, with the full text of each.
#
# Usage:
#   .github/release/generate-third-party-licenses.sh OUTPUT [--target TRIPLE] [MANIFEST ...]
#
#   OUTPUT     file to write (not committed; a packaging output).
#   --target   restrict the dependency graph to this target triple, so a
#              bundle lists only the crates built for its platform.
#   MANIFEST   Cargo.toml of a shipped package (repeatable; the notice covers
#              their union). Default: the whole main workspace.
#
# The engine bundles pass the packages they ship (see the engine-build job in
# the release workflow); the result is the bundle's THIRD-PARTY-LICENSES.
# Runs in the unprivileged build job only (cargo-about reads crate sources).
#
# Requires cargo-about:  cargo install cargo-about --locked --version 0.9.2
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"

if [ $# -lt 1 ]; then
  echo "usage: $0 OUTPUT [--target TRIPLE] [MANIFEST ...]" >&2
  exit 2
fi
out="$1"
shift
target_args=()
manifests=()
while [ $# -gt 0 ]; do
  case "$1" in
    --target) target_args=(--target "${2:?--target needs a triple}"); shift 2 ;;
    *) manifests+=("$1"); shift ;;
  esac
done

if ! command -v cargo-about >/dev/null 2>&1; then
  echo "error: cargo-about not found. Install with: cargo install cargo-about --locked --version 0.9.2" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# `--fail` turns any unresolved/unaccepted license into a non-zero exit so a new
# dependency carrying an unexpected license is caught rather than silently
# omitted from the notice. `--locked`: Cargo.lock is the source of truth.
common=(generate --fail --locked --format json -c "$repo_root/.config/about/about.toml")
jsons=()
if [ ${#manifests[@]} -eq 0 ]; then
  cargo about "${common[@]}" ${target_args[@]+"${target_args[@]}"} --workspace -o "$work/0.json"
  jsons+=("$work/0.json")
else
  i=0
  for manifest in "${manifests[@]}"; do
    i=$((i + 1))
    cargo about "${common[@]}" ${target_args[@]+"${target_args[@]}"} -m "$manifest" -o "$work/$i.json"
    jsons+=("$work/$i.json")
  done
fi

python3 "$repo_root/.github/release/third-party-licenses.py" render --out "$out" "${jsons[@]}"
echo "Wrote third-party license notice: $out"
