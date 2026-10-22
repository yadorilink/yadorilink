#!/bin/bash
#
# packaging/linux/verify-deb.sh
#
# Standalone structural verification for a built (or downloaded)
# yadorilink.deb. Unlike a full install, this does not require
# root or a real Debian/Ubuntu system: `dpkg-deb` alone can inspect an
# archive's control metadata and payload listing on any platform that has
# it installed (see README.md's "What has and hasn't been verified" section
# for what that does and doesn't prove).
#
# Checks performed:
#  1. SHA-256 checksum against the artifact's <name>.sha256 sidecar.
#  2. `dpkg-deb --info` -- control file is well-formed, Package/Version
#  fields are present.
#  3. `dpkg-deb --contents` -- the two binaries and the systemd unit are
#  present at their expected paths, with the unit file NOT executable
#  (0644) and the binaries executable (0755).
#  4. `lintian` (if installed) as a best-effort extra lint pass -- this is
#  the same tool CI's installer-linux job is expected to run; not
#  required locally.
#
# Usage:
#  packaging/linux/verify-deb.sh path/to/yadorilink_<version>_<arch>.deb

set -uo pipefail

DEB="${1:-}"
if [ -z "$DEB" ] || [ ! -f "$DEB" ]; then
    echo "usage: $0 <path-to.deb>" >&2
    exit 2
fi

FAILURES=0
fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok() { echo "OK: $*"; }
log() { echo "== $* =="; }

if ! command -v dpkg-deb >/dev/null 2>&1; then
    echo "dpkg-deb not found (Debian/Ubuntu: apt-get install dpkg-dev; macOS dev/test only: brew install dpkg)" >&2
    exit 2
fi

# --- 1. Checksum -------------------------------------------------------
log "checksum"
SIDECAR="$DEB.sha256"
if [ -f "$SIDECAR" ]; then
    if (cd "$(dirname "$DEB")" && (sha256sum -c "$(basename "$SIDECAR")" 2>/dev/null || shasum -a 256 -c "$(basename "$SIDECAR")")) >/tmp/verify-deb-checksum.$$ 2>&1; then
        ok "checksum matches $SIDECAR"
    else
        fail "checksum mismatch against $SIDECAR"
        cat /tmp/verify-deb-checksum.$$ >&2
    fi
    rm -f /tmp/verify-deb-checksum.$$
else
    fail "no checksum sidecar found at $SIDECAR"
fi

# --- 2. Control metadata -------------------------------------------------
log "dpkg-deb --info"
INFO_OUT="$(dpkg-deb --info "$DEB" 2>&1)"
echo "$INFO_OUT"
if echo "$INFO_OUT" | grep -q "Package: yadorilink"; then
    ok "control file has Package: yadorilink"
else
    fail "control file missing/incorrect Package field"
fi
if echo "$INFO_OUT" | grep -q "Version:"; then
    ok "control file has a Version field"
else
    fail "control file missing Version field"
fi

# --- 3. Payload contents --------------------------------------------------
log "dpkg-deb --contents"
CONTENTS_OUT="$(dpkg-deb --contents "$DEB" 2>&1)"
echo "$CONTENTS_OUT"

check_entry() {
    local path="$1"
    local want_exec="$2" # 1 = must be executable, 0 = must not be
    local line
    line="$(echo "$CONTENTS_OUT" | grep -E " \\.${path}$" || true)"
    if [ -z "$line" ]; then
        fail "payload missing $path"
        return
    fi
    local mode
    mode="$(echo "$line" | awk '{print $1}')"
    case "$mode" in
        -rwxr-xr-x*) is_exec=1 ;;
        -rw-r--r--*) is_exec=0 ;;
        *) is_exec=-1;;
    esac
    if [ "$is_exec" = "$want_exec" ]; then
        ok "$path present with expected mode ($mode)"
    else
        fail "$path present but unexpected mode ($mode)"
    fi
}

check_entry "/usr/bin/yadorilink" 1
check_entry "/usr/bin/yadorilink-daemon" 1
check_entry "/usr/lib/systemd/user/yadorilink-daemon.service" 0
check_entry "/usr/lib/systemd/system/yadorilink-headless.service" 0
check_entry "/usr/share/yadorilink/headless/install-headless.sh" 1
check_entry "/usr/share/yadorilink/headless/uninstall-headless.sh" 1
check_entry "/usr/share/yadorilink/headless/yadorilink-svc" 1
check_entry "/usr/share/yadorilink/headless/headless.env" 0

# --- 4. lintian (optional, best-effort) -----------------------------------
log "lintian"
if command -v lintian >/dev/null 2>&1; then
    LINTIAN_OUT="$(lintian "$DEB" 2>&1)"
    echo "$LINTIAN_OUT"
    if echo "$LINTIAN_OUT" | grep -qE "^E: "; then
        fail "lintian reported error-level tags (see above)"
    else
        ok "lintian reported no error-level tags"
    fi
else
    echo "NOTE: lintian not installed locally; skipping (CI's installer-linux job runs this)"
fi

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "verify-deb.sh: $FAILURES check(s) failed for $DEB" >&2
    exit 1
fi
echo "verify-deb.sh: all checks passed for $DEB"
exit 0
