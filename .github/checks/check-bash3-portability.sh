#!/usr/bin/env bash
# Fail if a bash >= 4-only construct appears in .github/ci/*.sh. macOS ships
# bash 3.2 (/bin/bash, and what `env bash` resolves to on dev machines), where
# e.g. `wait -n` fails at once and turns a wait loop into a CPU-burning spin.
# Plain POSIX-ish bash 3.2 only; no GNU-only tools. Comment lines are ignored.
set -uo pipefail
# shellcheck disable=SC2016  # single quotes are deliberate literal samples

# Patterns are built from fragments so this file never matches itself.
w='wait'
pat="(^|[^[:alnum:]_])${w} +-[a-z]*n"            # wait -n
pat="$pat|mapfile|readarray"
pat="$pat|(declare|local|typeset) +-[a-zA-Z]*A"  # associative arrays
pat="$pat|\\$\\{[A-Za-z_0-9]+(,,|\\^\\^)\\}"      # case-modifying expansion
pat="$pat|&>>|\\|&|coproc"
pat="$pat|\\\$EPOCHREALTIME|\\\$EPOCHSECONDS|;;&"

# scan_stdin: print offending non-comment lines read from stdin.
scan_stdin() { grep -nE "$pat" | grep -vE '^[0-9]+:[[:space:]]*#'; }

if [ "${1:-}" = "--self-test" ]; then
  bad1="  while x; do ${w} -n || true; done"
  bad2='  declare -A m=()'
  bad3='  mapfile -t a < f'
  bad4='  v="${x,,}"'
  for b in "$bad1" "$bad2" "$bad3" "$bad4"; do
    if [ -z "$(printf '%s\n' "$b" | scan_stdin)" ]; then
      echo "self-test: construct not detected: $b" >&2
      exit 1
    fi
  done
  if [ -n "$(printf '%s\n' "# ${w} -n is bash 4 only" "  ${w}" 'x=$(jobs -rp)' | scan_stdin)" ]; then
    echo "self-test: false positive" >&2
    exit 1
  fi
  echo "self-test ok"
  exit 0
fi

cd "$(git rev-parse --show-toplevel)" || exit 1
rc=0
for f in .github/ci/*.sh; do
  hits="$(scan_stdin <"$f")"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | sed "s|^|$f:|" >&2
    rc=1
  fi
done
[ "$rc" -eq 0 ] || echo "bash >= 4-only construct in .github/ci (macOS bash is 3.2)" >&2
exit "$rc"
