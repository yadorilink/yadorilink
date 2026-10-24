#!/usr/bin/env bash
# Fail unless the Verify workflow finished green for one exact commit.
#
# The release builds and publishes; it does not repeat Verify's tests. This is
# the gate that makes that safe: a tag on a commit with a red, cancelled or
# missing Verify run stops here with a message that says what to do.
#
# Usage: .github/release/require-verify.sh <repo> <sha>   (needs GH_TOKEN)
#        .github/release/require-verify.sh --self-test
# A run that is still going is waited for, up to VERIFY_WAIT_MINUTES (default 90),
# with a log line every VERIFY_POLL_SECONDS (default 60).
set -euo pipefail

GH="${GH:-gh}"
wait_minutes="${VERIFY_WAIT_MINUTES:-90}"
poll_seconds="${VERIFY_POLL_SECONDS:-60}"

# Print "<event> <status> <conclusion>" of each Verify run for the commit.
# Verify checks out the triggering ref without an override, so only a push or a
# manual dispatch checks out exactly the commit. A pull_request run checks out
# the synthetic merge commit, which is a different tree, so it proves nothing
# about the tagged commit and is never eligible.
runs() { # repo sha
  "$GH" api "repos/$1/actions/workflows/verify.yml/runs?head_sha=$2&per_page=100" \
    --jq '.workflow_runs[] | "\(.event) \(.status) \(.conclusion)"'
}

# Keep only the runs whose checkout is exactly the commit.
eligible() { # lines
  printf '%s\n' "$1" | grep -E '^(push|workflow_dispatch) ' | sed -E 's/^[^ ]+ //' || true
}

# Count the lines of $1 that start with one of the statuses of a run that has
# not finished yet. Blank or unknown lines are never "running".
count() { # lines pattern
  printf '%s\n' "$1" | grep -c -E "$2" || true
}

check() { # repo sha
  local repo="$1" sha="$2" start deadline all out passed running
  start="$(date +%s)"
  deadline=$(( start + wait_minutes * 60 ))
  while :; do
    all="$(runs "$repo" "$sha")"
    out="$(eligible "$all")"
    passed="$(count "$out" '^completed success$')"
    if [ "$passed" -gt 0 ]; then
      echo "Verify is green for $sha"
      return 0
    fi
    if [ -z "${out//[[:space:]]/}" ] && [ -n "${all//[[:space:]]/}" ]; then
      echo "Only pull-request Verify runs exist for $sha; a pull-request run does not prove the tagged tree: push the commit to main or run Verify by hand, wait for it to pass, then run this release again." >&2
      return 1
    fi
    if [ -z "${out//[[:space:]]/}" ]; then
      echo "No Verify run exists for $sha. Push the commit to main (or run Verify by hand on it) and wait for it to pass, then run this release again." >&2
      return 1
    fi
    running="$(count "$out" '^(queued|in_progress|waiting|pending|requested) ')"
    if [ "$running" -eq 0 ]; then
      echo "Verify did not pass for $sha ($(printf '%s' "$out" | tr '\n' ',')). Fix it and tag a green commit." >&2
      return 1
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
      echo "Verify did not finish for $sha within $wait_minutes minutes. Wait for it, then run this release again." >&2
      return 1
    fi
    echo "Verify is still running for $sha ($(( ($(date +%s) - start) / 60 )) of $wait_minutes minutes waited); checking again in ${poll_seconds}s"
    sleep "$poll_seconds"
  done
}

self_test() {
  local d; d="$(mktemp -d)"
  trap 'rm -rf "$d"' RETURN
  printf '#!/bin/sh\ncat "$FAKE_RUNS"\n' > "$d/gh"; chmod +x "$d/gh"
  export GH="$d/gh" FAKE_RUNS="$d/runs"
  # A long wait budget, so a gate that wrongly waits is caught by the clock.
  wait_minutes=5 poll_seconds=1
  expect() { # name want runs...  ('|' separates lines)
    local name="$1" want="$2" t0 got=0; shift 2
    printf '%s' "$*" | tr '|' '\n' > "$FAKE_RUNS"
    t0="$(date +%s)"
    check o/r deadbeef >/dev/null 2>&1 || got=1
    [ "$got" = "$want" ] || { echo "FAIL $name" >&2; exit 1; }
    [ $(( $(date +%s) - t0 )) -lt 10 ] || { echo "FAIL $name: waited" >&2; exit 1; }
    echo "ok   $name"
  }
  expect green 0 "push completed success"
  expect dispatch-green 0 "workflow_dispatch completed success"
  expect retry-green 0 "push completed failure|push completed success"
  expect red 1 "push completed failure"
  expect cancelled 1 "push completed cancelled"
  expect missing 1 ""
  expect blank-line 1 "|"
  expect odd-output 1 "garbage"
  expect pr-only-green 1 "pull_request completed success"
  expect pr-green-push-red 1 "pull_request completed success|push completed failure"
  expect other-event-green 1 "schedule completed success"
  # A run that is going must be waited for (a budget of zero ends it at once).
  printf 'push in_progress \n' > "$FAKE_RUNS"
  wait_minutes=0
  if check o/r deadbeef >"$d/out" 2>&1; then echo "FAIL running passed" >&2; exit 1; fi
  grep -q 'did not finish' "$d/out" || { echo "FAIL running not reported as unfinished" >&2; exit 1; }
  echo "ok   running"
  printf 'push queued \n' > "$FAKE_RUNS"
  wait_minutes=0
  if check o/r deadbeef >"$d/out" 2>&1; then echo "FAIL queued passed" >&2; exit 1; fi
  grep -q 'did not finish' "$d/out" || { echo "FAIL queued not reported as unfinished" >&2; exit 1; }
  echo "ok   queued"
  printf 'pull_request completed success\n' > "$FAKE_RUNS"
  if check o/r deadbeef >"$d/out" 2>&1; then echo "FAIL pr-only passed" >&2; exit 1; fi
  grep -q 'does not prove the tagged tree' "$d/out" || { echo "FAIL pr-only not explained" >&2; exit 1; }
  echo "ok   pr-only-message"
  echo "require-verify self-test passed"
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit 0; fi
[ $# -eq 2 ] || { echo "usage: $0 <repo> <sha> | --self-test" >&2; exit 2; }
check "$1" "$2"
