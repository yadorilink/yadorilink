#!/usr/bin/env bash
# Fail when a Linux executable needs a newer glibc than the support floor.
#
# Usage: check-glibc-floor.sh BINARY...
#        check-glibc-floor.sh --self-test
#
# The release is built on Ubuntu 22.04 (glibc 2.35), so Debian 12 (2.36) and the
# NAS distributions of that age run it. A binary built on a newer system still
# starts there when the newer symbol is only a weak reference, but the loader
# prints a warning on every command; this check makes that a build failure.
# Versioned symbols are read with objdump, strong and weak alike.
set -euo pipefail

FLOOR="${GLIBC_FLOOR:-2.35}"

# Highest GLIBC_x.y version named in the dynamic symbol table of a binary.
max_version() { # binary
  objdump -T "$1" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1
}

# 0 when version $1 <= floor $2.
within() { # version floor
  [ "$(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)" = "$2" ]
}

if [ "${1:-}" = "--self-test" ]; then
  within 2.34 2.35 || { echo "FAIL: 2.34 should be within 2.35" >&2; exit 1; }
  within 2.35 2.35 || { echo "FAIL: 2.35 should be within 2.35" >&2; exit 1; }
  within 2.9 2.35 || { echo "FAIL: 2.9 should be within 2.35" >&2; exit 1; }
  if within 2.39 2.35; then echo "FAIL: 2.39 must exceed 2.35" >&2; exit 1; fi
  if within 2.36 2.35; then echo "FAIL: 2.36 must exceed 2.35" >&2; exit 1; fi
  echo "check-glibc-floor self-test passed"
  exit 0
fi

[ "$#" -ge 1 ] || { echo "usage: $0 BINARY... | --self-test" >&2; exit 2; }
status=0
for bin in "$@"; do
  v="$(max_version "$bin")"
  if [ -z "$v" ]; then
    echo "FAIL: $bin names no glibc symbol version (is it a Linux executable?)" >&2
    status=1
  elif within "$v" "$FLOOR"; then
    echo "ok: $bin needs glibc $v at most (floor $FLOOR)"
  else
    echo "FAIL: $bin needs glibc $v, above the floor $FLOOR; build on the oldest supported system" >&2
    status=1
  fi
done
exit "$status"
