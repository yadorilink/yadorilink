#!/usr/bin/env bash
# Runs every fuzz target for SECS seconds (default 120) on its corpus, from this directory.
#   fuzz/run.sh [SECS] [target...]
# Needs the nightly toolchain and cargo-fuzz. New inputs the fuzzer finds are written into
# corpus/<target>; a crash is left in artifacts/<target>/.
set -uo pipefail
cd "$(dirname "$0")"
secs="${1:-120}"; shift || true
targets=("$@"); [ "${#targets[@]}" -gt 0 ] || mapfile -t targets < <(cargo +nightly fuzz list)
status=0
for t in "${targets[@]}"; do
  echo "== $t"
  cargo +nightly fuzz run "$t" -- -max_total_time="$secs" -max_len=65536 -timeout=10 -rss_limit_mb=2048 \
    -dict=dict/tags.dict -print_final_stats=1 2>&1 | tail -n 12 || status=1
  [ "${PIPESTATUS[0]}" -eq 0 ] || status=1
done
exit "$status"
