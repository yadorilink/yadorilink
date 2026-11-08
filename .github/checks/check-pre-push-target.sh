#!/usr/bin/env bash
# The pre-push hook's default target directory drops a leading "wt-" from the worktree
# name, so a worktree wt-lane and a lane that exports cargo-target/lane share one cache.
set -euo pipefail
hook="$(git rev-parse --show-toplevel)/.githooks/pre-push"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/root" "$tmp/wt-lane" "$tmp/plain"
for name in wt-lane:lane plain:plain; do
  dir="${name%%:*}"; want="${name##*:}"
  git -C "$tmp/$dir" init -q
  got="$(cd "$tmp/$dir" && env -u CARGO_TARGET_DIR YL_CARGO_TARGET_ROOT="$tmp/root" YL_PREPUSH_PRINT_TARGET=1 bash "$hook")"
  [ "$got" = "$tmp/root/$want" ] || { echo "pre-push target for $dir: got $got, want $tmp/root/$want" >&2; exit 1; }
done
echo ok
