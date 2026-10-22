#!/bin/bash
#
# install-headless.sh -- set up YadoriLink as an always-on system service
# on a headless Linux host (x86_64 or aarch64): a dedicated `yadorilink`
# account, an owner-only state directory, a folders directory it owns, the
# systemd unit, and the `yadorilink-svc` wrapper. It does NOT sign in, link a
# folder or start the daemon; those are the runbook's next steps, and it
# touches no credentials.
#
# Run as root, after installing the .deb (or pass --bin-dir to install the
# two binaries from a directory, for a tarball install):
#
#   sudo ./install-headless.sh [--folders-dir /srv/yadorilink]
#   sudo ./install-headless.sh --dry-run          # print the plan, change nothing
#   ./install-headless.sh --root "$(mktemp -d)"   # stage every file under a
#                                                 # prefix, as non-root, for review
#
# Idempotent: re-running converges on the same state and never overwrites
# /etc/yadorilink/headless.env once it exists. Fixed names (account
# yadorilink, state /var/lib/yadorilink) match the unit file; they are not
# options on purpose.

set -euo pipefail

SVC_USER=yadorilink
STATE_DIR=/var/lib/yadorilink
ETC_DIR=/etc/yadorilink
UNIT_NAME=yadorilink-headless.service

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DRY=0
ROOT=""
BIN_DIR=""
FOLDERS_DIR=/srv/yadorilink

# Set to 1 whenever a run actually changes something; a re-run that changes
# nothing says so instead of repeating the first-install instructions.
CHANGED=0

log() { echo "[install-headless] $*"; }
die() { echo "[install-headless] ERROR: $*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
usage: install-headless.sh [--dry-run] [--root PREFIX] [--bin-dir DIR] [--folders-dir DIR]

  --dry-run         print what would be done; change nothing
  --root PREFIX     stage the files under PREFIX instead of /; creates no
                    account, changes no ownership, never calls systemctl
  --bin-dir DIR     copy yadorilink and yadorilink-daemon from DIR into
                    /usr/bin (not needed after installing the .deb)
  --folders-dir DIR parent directory for linked folders, owned by the
                    service account (default /srv/yadorilink). Must be a new
                    or empty directory, or one the service account already
                    owns; an existing non-empty directory owned by anyone
                    else is refused, never re-owned.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --root)
            [ $# -ge 2 ] || die "--root needs a value"
            ROOT="${2%"${2##*[!/]}"}"
            [ -n "$ROOT" ] || die "--root / would be a real install; omit --root instead"
            shift ;;
        --bin-dir) [ $# -ge 2 ] || die "--bin-dir needs a value"; BIN_DIR="$2"; shift ;;
        --folders-dir) [ $# -ge 2 ] || die "--folders-dir needs a value"; FOLDERS_DIR="${2%/}"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
done

STAGE=0
[ -n "$ROOT" ] && STAGE=1
live() { [ "$DRY" -eq 0 ] && [ "$STAGE" -eq 0 ]; }

# Runs a command for real, or just prints it under --dry-run.
act() {
    if [ "$DRY" -eq 1 ]; then
        echo "  would run: $*"
    else
        "$@"
    fi
}
# Maps an absolute path into the staging prefix (empty prefix: unchanged).
p() { echo "$ROOT$1"; }

# --- 1. Preconditions: refuse unsafe configurations --------------------------
case "$(uname -m)" in
    x86_64|aarch64) ;;
    *) die "unsupported architecture $(uname -m); x86_64 and aarch64 only" ;;
esac

case "$FOLDERS_DIR" in
    /*) ;;
    *) die "--folders-dir must be an absolute path" ;;
esac
case "/$FOLDERS_DIR/" in
    */../*) die "--folders-dir must not contain '..'" ;;
esac
# A symlink at the path itself is refused below; resolve everything else
# (symlinked parents, "." and "//") before judging the location. Staged runs
# only normalise, since the prefix is not the real root.
FOLDERS_RAW="$FOLDERS_DIR"
if [ "$STAGE" -eq 0 ]; then
    FOLDERS_DIR="$(realpath -m -- "$FOLDERS_DIR")"
else
    FOLDERS_DIR="$(realpath -m -s -- "$FOLDERS_DIR")"
fi
case "$FOLDERS_DIR" in
    /|/tmp|/tmp/*|/var/tmp|/var/tmp/*|/root|/root/*|/home|/home/*|/proc/*|/sys/*|/dev/*)
        die "--folders-dir $FOLDERS_DIR is not a safe place for synced folders (the service cannot see /home or /root, and /tmp is not durable)" ;;
    "$STATE_DIR"|"$STATE_DIR"/*|/etc|/etc/*|/usr|/usr/*|/boot|/boot/*)
        die "--folders-dir $FOLDERS_DIR must be outside the state directory and system directories" ;;
    /srv|/mnt|/media|/opt|/var|/var/lib)
        die "--folders-dir $FOLDERS_DIR is a shared system location whose ownership would be changed; use a subdirectory such as $FOLDERS_DIR/yadorilink" ;;
esac

if live; then
    [ "$(id -u)" -eq 0 ] || die "run as root (sudo), or use --dry-run / --root PREFIX"
    [ -d /run/systemd/system ] || die "systemd is not running as init on this host"
    command -v useradd >/dev/null 2>&1 || die "useradd not found"
    command -v setpriv >/dev/null 2>&1 || die "setpriv (util-linux) not found; yadorilink-svc needs it"
fi

# Binaries: from --bin-dir, else already in /usr/bin (the .deb).
if [ -n "$BIN_DIR" ]; then
    for b in yadorilink yadorilink-daemon; do
        [ -f "$BIN_DIR/$b" ] && [ -x "$BIN_DIR/$b" ] || die "$BIN_DIR/$b is missing or not executable"
    done
else
    for b in yadorilink yadorilink-daemon; do
        [ -x "$(p /usr/bin/$b)" ] || die "$(p /usr/bin/$b) not found: install the yadorilink package first, or pass --bin-dir"
    done
fi

# A root-run service binary location must not be writable by anyone else.
if live && [ -z "$BIN_DIR" ]; then
    for b in /usr/bin/yadorilink /usr/bin/yadorilink-daemon; do
        [ "$(stat -c %u "$b")" -eq 0 ] || die "$b is not owned by root"
        mode="$(stat -c %a "$b")"
        [ $((8#$mode & 8#022)) -eq 0 ] || die "$b is writable by group or others (mode $mode)"
    done
fi

# An existing account must be an unprivileged, non-login service account.
if live && id "$SVC_USER" >/dev/null 2>&1; then
    [ "$(id -u "$SVC_USER")" -ne 0 ] || die "account $SVC_USER has uid 0"
    shell="$(getent passwd "$SVC_USER" | cut -d: -f7)"
    case "$shell" in
        */nologin|*/false) ;;
        *) die "account $SVC_USER has login shell $shell; refusing to run a service as a login account" ;;
    esac
    for g in $(id -nG "$SVC_USER"); do
        case "$g" in
            sudo|wheel|admin|root|adm|docker|lxd|disk|shadow)
                die "account $SVC_USER is in privileged group $g; remove it before installing" ;;
        esac
    done
fi

# State and folders directories: never follow a symlink, never adopt another
# user's directory (the folders directory has its own adoption check below).
check_dir_safe() {
    local d="$1"
    [ ! -L "$d" ] || die "$d is a symlink; refusing"
    if [ -e "$d" ]; then
        [ -d "$d" ] || die "$d exists and is not a directory"
        if live && id "$SVC_USER" >/dev/null 2>&1; then
            owner="$(stat -c %U "$d")"
            case "$owner" in
                "$SVC_USER"|root) ;;
                *) die "$d is owned by $owner; refusing to take over another user's directory" ;;
            esac
        fi
    fi
}
check_dir_safe "$(p "$STATE_DIR")"
[ ! -L "$(p "$FOLDERS_RAW")" ] || die "$FOLDERS_RAW is a symlink; refusing"
check_dir_safe "$(p "$FOLDERS_DIR")"
# The installer chowns the folders directory, so it only does that to a
# directory it creates, one the service account already owns, or an empty
# root-owned one (check_dir_safe already refuses other users' directories,
# empty or not). Anything else (a data-disk mount root, another user's tree, even a
# root-owned one) would lose its owner and mode, so it is refused.
if [ "$STAGE" -eq 0 ] && [ -d "$FOLDERS_DIR" ]; then
    f_owner="$(stat -c %U "$FOLDERS_DIR")"
    if [ "$f_owner" != "$SVC_USER" ] && [ -n "$(ls -A "$FOLDERS_DIR")" ]; then
        die "$FOLDERS_DIR is not empty and is owned by $f_owner, not $SVC_USER; refusing to change its ownership. Choose a new directory (for example $FOLDERS_DIR/yadorilink) or chown it yourself first"
    fi
fi

# --- 2. Unit source ------------------------------------------------------------
UNIT_SRC=""
if [ -f "$SCRIPT_DIR/../systemd/$UNIT_NAME" ]; then
    UNIT_SRC="$SCRIPT_DIR/../systemd/$UNIT_NAME"
elif [ -f "$SCRIPT_DIR/$UNIT_NAME" ]; then
    UNIT_SRC="$SCRIPT_DIR/$UNIT_NAME"
fi
UNIT_DST="$(p /usr/lib/systemd/system/$UNIT_NAME)"
[ -n "$UNIT_SRC" ] || [ -f "$UNIT_DST" ] || die "unit file $UNIT_NAME not found next to this script or in /usr/lib/systemd/system"
for f in headless.env yadorilink-svc; do
    [ -f "$SCRIPT_DIR/$f" ] || die "$SCRIPT_DIR/$f is missing"
done

# --- 3. Do it ------------------------------------------------------------------
if [ "$DRY" -eq 1 ]; then
    log "dry run: nothing will be changed"
fi

# Install a file only if its content differs; report what happened.
put_file() { # mode src dst
    local mode="$1" src="$2" dst="$3"
    if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
        log "unchanged: $dst"
        return 0
    fi
    log "install: $dst"
    CHANGED=1
    act install -D -m "$mode" "$src" "$dst"
}

# True when directory $1 is missing, or (live runs) not $SVC_USER:$SVC_USER
# with mode $2.
dir_needs_change() {
    local d="$1" mode="$2"
    [ -d "$d" ] || return 0
    live || return 1
    [ "$(stat -c '%U:%G %a' "$d")" = "$SVC_USER:$SVC_USER $mode" ] || return 0
    return 1
}

if [ -n "$BIN_DIR" ]; then
    put_file 755 "$BIN_DIR/yadorilink" "$(p /usr/bin/yadorilink)"
    put_file 755 "$BIN_DIR/yadorilink-daemon" "$(p /usr/bin/yadorilink-daemon)"
fi

if live; then
    if ! getent group "$SVC_USER" >/dev/null 2>&1; then
        log "create group $SVC_USER"
        CHANGED=1
        groupadd --system "$SVC_USER"
    fi
    if ! id "$SVC_USER" >/dev/null 2>&1; then
        nologin=/usr/sbin/nologin
        [ -x "$nologin" ] || nologin=/sbin/nologin
        log "create account $SVC_USER (system, no login, home $STATE_DIR)"
        CHANGED=1
        useradd --system --gid "$SVC_USER" --home-dir "$STATE_DIR" --no-create-home \
            --shell "$nologin" --comment "YadoriLink sync daemon" "$SVC_USER"
    fi
elif [ "$DRY" -eq 1 ]; then
    echo "  would create system group and account $SVC_USER (no login) if absent"
fi

# State directory: owner-only.
if [ "$DRY" -eq 1 ]; then
    echo "  would create $STATE_DIR owned by $SVC_USER mode 0700"
else
    if dir_needs_change "$(p "$STATE_DIR")" 700; then CHANGED=1; log "set up: $(p "$STATE_DIR")"; else log "unchanged: $(p "$STATE_DIR")"; fi
    act install -d -m 0700 "$(p "$STATE_DIR")"
    live && chown "$SVC_USER:$SVC_USER" "$STATE_DIR" && chmod 0700 "$STATE_DIR"
fi
# Folders directory: created here or already the service account's (or empty,
# checked above); group-readable so an admin can grant read access by adding
# someone to the group.
if [ "$DRY" -eq 1 ]; then
    echo "  would create $FOLDERS_DIR owned by $SVC_USER mode 0750"
else
    if dir_needs_change "$(p "$FOLDERS_DIR")" 750; then CHANGED=1; log "set up: $(p "$FOLDERS_DIR")"; else log "unchanged: $(p "$FOLDERS_DIR")"; fi
    act install -d -m 0750 "$(p "$FOLDERS_DIR")"
    live && chown "$SVC_USER:$SVC_USER" "$FOLDERS_DIR" && chmod 0750 "$FOLDERS_DIR"
fi

# Settings file: created once, never overwritten (an admin edits it).
ENV_DST="$(p "$ETC_DIR/headless.env")"
if [ -e "$ENV_DST" ]; then
    log "keep existing: $ENV_DST"
else
    log "install: $ENV_DST"
    CHANGED=1
    act install -D -m 0644 "$SCRIPT_DIR/headless.env" "$ENV_DST"
fi

put_file 755 "$SCRIPT_DIR/yadorilink-svc" "$(p /usr/bin/yadorilink-svc)"
[ -z "$UNIT_SRC" ] || put_file 644 "$UNIT_SRC" "$UNIT_DST"

if live; then
    systemctl daemon-reload
    if [ "$(systemctl is-enabled "$UNIT_NAME" 2>/dev/null || true)" = enabled ]; then
        log "unchanged: $UNIT_NAME already enabled"
    else
        systemctl enable "$UNIT_NAME"
        CHANGED=1
        log "enabled $UNIT_NAME (starts at boot)"
    fi
elif [ "$DRY" -eq 1 ]; then
    echo "  would run: systemctl daemon-reload; systemctl enable $UNIT_NAME"
fi

if [ "$DRY" -eq 1 ]; then
    log "dry run complete; nothing was changed"
    exit 0
fi
if [ "$CHANGED" -eq 0 ]; then
    log "nothing to do: everything already in place (unchanged)"
    exit 0
fi
if live && systemctl is-active --quiet "$UNIT_NAME"; then
    echo
    echo "Updated. $UNIT_NAME is running; apply a changed unit or settings with: sudo systemctl restart $UNIT_NAME"
    exit 0
fi
cat <<EOF2

Installed. $UNIT_NAME is enabled but NOT started: sign in first.
Next steps (see packaging/linux/README.md ("Always-on headless install")):
  sudo yadorilink-svc login --device
  sudo yadorilink-svc device register --name "$(hostname 2>/dev/null || echo nas)"
  sudo systemctl start $UNIT_NAME
  # wait until 'sudo yadorilink-svc status' shows connected / policy loaded, then:
  sudo yadorilink-svc share create <group> --path $FOLDERS_DIR/<group>
  # to join a group made elsewhere, create the directory first:
  sudo install -d -o $SVC_USER -g $SVC_USER -m 0750 $FOLDERS_DIR/<group>
  sudo yadorilink-svc share join <group> --path $FOLDERS_DIR/<group>
EOF2
