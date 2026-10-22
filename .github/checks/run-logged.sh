#!/usr/bin/env bash
# Runs a command, mirrors its combined output into test-output.log (read by
# summarize-test-log.py and uploaded when a job fails) and keeps the command's
# exit status.
set -o pipefail
"$@" 2>&1 | tee -a test-output.log
