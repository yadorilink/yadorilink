#!/usr/bin/env bash
# A short run of every decoder target on the committed seed corpus: proves the targets still
# build and that the seeds do not crash them. SECS per target (default 15); the daemon-linked
# targets (policy_log, send_link_code) are left to run.sh because they take a long build.
#   fuzz/smoke.sh [SECS]
set -uo pipefail
cd "$(dirname "$0")"
secs="${1:-15}"
exec ./run.sh "$secs" protocol5_message protocol5_proof authorization_checkpoint native_delta \
  author_closure native_checkpoint native_checkpoint_seal native_row_identity service_rpc \
  block_headers hello ignore_rules
