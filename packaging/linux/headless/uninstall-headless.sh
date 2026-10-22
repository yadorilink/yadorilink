#!/bin/bash
#
# uninstall-headless.sh -- undo install-headless.sh.
#
#   sudo ./uninstall-headless.sh               # stop and disable the service; keep all data
#   sudo ./uninstall-headless.sh --purge-data  # also delete /var/lib/yadorilink and the settings file
#   sudo ./uninstall-headless.sh --remove-account
#   sudo ./uninstall-headless.sh --dry-run | --root PREFIX
#
# Never deletes the folders directory or anything in it: those are your
# files. --purge-data deletes this device's identity and sign-in
# credentials, so first run `sudo yadorilink-svc logout --yes` to revoke
# its sign-in. The device record and its folder memberships stay on the
# account either way until you remove it from another device (`yadorilink
# device remove`). Removing the program itself is `apt remove yadorilink` (the
# service must be stopped first, which this script does).

set -euo pipefail

SVC_USER=yadorilink
STATE_DIR=/var/lib/yadorilink
ETC_DIR=/etc/yadorilink
UNIT_NAME=yadorilink-headless.service

DRY=0
ROOT=""
PURGE=0
RM_ACCOUNT=0

log() { echo "[uninstall-headless] $*"; }
die() { echo "[uninstall-headless] ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --root) [ $# -ge 2 ] || die "--root needs a value"; ROOT="${2%/}"; shift ;;
        --purge-data) PURGE=1 ;;
        --remove-account) RM_ACCOUNT=1 ;;
        -h|--help) sed -n '3,17p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
    shift
done

STAGE=0
[ -n "$ROOT" ] && STAGE=1
live() { [ "$DRY" -eq 0 ] && [ "$STAGE" -eq 0 ]; }
act() {
    if [ "$DRY" -eq 1 ]; then echo "  would run: $*"; else "$@"; fi
}
p() { echo "$ROOT$1"; }

if live; then
    [ "$(id -u)" -eq 0 ] || die "run as root (sudo), or use --dry-run / --root PREFIX"
fi
if [ "$RM_ACCOUNT" -eq 1 ] && [ "$PURGE" -ne 1 ]; then
    die "--remove-account needs --purge-data: the account owns the state directory"
fi

# 1. Stop and disable.
if live && command -v systemctl >/dev/null 2>&1; then
    log "stop and disable $UNIT_NAME"
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
elif [ "$DRY" -eq 1 ]; then
    echo "  would run: systemctl disable --now $UNIT_NAME"
fi

# 2. Files this script installed. A unit that belongs to the .deb is left for
#    dpkg to remove.
UNIT_DST="$(p /usr/lib/systemd/system/$UNIT_NAME)"
owned_by_dpkg=0
if live && command -v dpkg >/dev/null 2>&1 && dpkg -S "/usr/lib/systemd/system/$UNIT_NAME" >/dev/null 2>&1; then
    owned_by_dpkg=1
fi
if [ "$owned_by_dpkg" -eq 1 ]; then
    log "keep $UNIT_DST (owned by the yadorilink package)"
else
    act rm -f "$UNIT_DST"
fi
act rm -f "$(p /usr/bin/yadorilink-svc)"
if live; then systemctl daemon-reload >/dev/null 2>&1 || true; fi

# 3. Optional data purge.
if [ "$PURGE" -eq 1 ]; then
    if live && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$UNIT_NAME"; then
        die "$UNIT_NAME is still running; refusing to delete its state"
    fi
    case "$(p "$STATE_DIR")" in
        */var/lib/yadorilink) ;;
        *) die "unexpected state directory path" ;;
    esac
    [ ! -L "$(p "$STATE_DIR")" ] || die "$STATE_DIR is a symlink; refusing"
    log "delete $STATE_DIR and $ETC_DIR/headless.env"
    act rm -rf "$(p "$STATE_DIR")"
    act rm -f "$(p "$ETC_DIR/headless.env")"
    act rmdir --ignore-fail-on-non-empty "$(p "$ETC_DIR")"
else
    log "kept $STATE_DIR (identity, credentials, sync state) and $ETC_DIR/headless.env; use --purge-data to delete"
fi

# 4. Optional account removal.
if [ "$RM_ACCOUNT" -eq 1 ]; then
    if live; then
        if id "$SVC_USER" >/dev/null 2>&1; then
            log "remove account $SVC_USER"
            userdel "$SVC_USER" || true
        fi
        if getent group "$SVC_USER" >/dev/null 2>&1; then groupdel "$SVC_USER" || true; fi
    else
        echo "  would run: userdel $SVC_USER; groupdel $SVC_USER"
    fi
fi

log "folders directory and the files in it were not touched"
log "done"
