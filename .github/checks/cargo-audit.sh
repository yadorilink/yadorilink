#!/usr/bin/env bash
# Audit every committed lockfile and report all failures, not just the first.
# The workspace lockfile is read from the repository root, where
# .cargo/audit.toml holds the reviewed ignores; the verifier crate is its own
# workspace with its own lockfile.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

status=0
for lock in Cargo.lock crates/yadorilink-verify/Cargo.lock; do
  echo "== cargo audit --file $lock"
  cargo audit --file "$lock" || status=1
done
exit "$status"
