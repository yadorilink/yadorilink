#!/bin/sh
# Container entrypoint: start the daemon as a non-root account.
#
# Started as root (the default), it makes the state directory belong to
# PUID:PGID (default 999:999, the image's own account) and drops to that
# account for good before the daemon starts; the daemon never runs as root.
# Started as another user (`docker run --user UID:GID`), it only checks that the
# state directory is usable. Synced folders are never chowned: they belong to
# whoever owns them, and PUID/PGID should name that owner.
#
# Arguments starting with "-" go to the daemon (`docker run IMAGE --version`); anything
# else is run as the command instead (`docker run IMAGE yadorilink status`, `... sh`).
#
# Every invocation that resolves to the daemon (no arguments, or daemon options that run it) runs under a small supervisor, which stays
# PID 1. Some commands end the daemon on purpose so that it starts again with new state:
# `yadorilink device register` (the daemon reads its device identity only at startup) and
# `yadorilink daemon stop`. Without a supervisor that ends the container and kills the
# `docker exec` that asked for it. The supervisor starts the daemon again after a clean
# exit (status 0 or 75); any other status, and any stop that the container asked for
# (SIGTERM, `docker stop`), ends the container with the daemon's status. The image sets
# YADORILINK_DAEMON_SUPERVISED so the command line waits for that restart instead of
# starting a second daemon.
set -eu

supervise() {
    child=''
    stopping=''
    trap 'stopping=1; [ -z "$child" ] || kill -TERM "$child" 2>/dev/null || true' TERM INT
    while :; do
        started="$(date +%s)"
        "$@" &
        child=$!
        status=0
        while :; do
            wait "$child" && status=0 || status=$?
            # A trapped signal interrupts `wait` while the daemon is still going down.
            kill -0 "$child" 2>/dev/null || break
        done
        [ -z "$stopping" ] || exit "$status"
        case "$status" in
            0 | 75) ;;
            *) exit "$status" ;;
        esac
        echo "yadorilink: the daemon exited (status $status); starting it again" >&2
        # A daemon that exits at once, over and over, must not spin, whatever its status. Status 75
        # is a stop the daemon was asked to make so that it comes back (`device register`, a
        # replaced executable): it is restarted without waiting once it has run for a second; any
        # other exit within five seconds of the start might be a crash and waits a second.
        # (`date +%s` counts whole seconds, so even a daemon that dies at once is restarted
        # unpaced at most about once a second.)
        lived="$(( $(date +%s) - started ))"
        if [ "$status" = 75 ]; then
            [ "$lived" -ge 1 ] || sleep 1
        else
            [ "$lived" -ge 5 ] || sleep 1
        fi
        child=''
    done
}

if [ "${1:-}" = "--supervise" ]; then
    shift
    supervise "$@"
fi

# The command resolves to the daemon when there is none or it starts with "-" (daemon options).
supervised=''
if [ "$#" -eq 0 ] || [ "${1#-}" != "$1" ]; then supervised=1; fi
# A daemon option that only answers and exits (`--version`, `--help`, `--check-data-compat`, `--healthcheck`) is not the
# daemon running: under the supervisor its clean exit would be "restarted" for ever.
for arg in "$@"; do
    case "$arg" in
        --version | -V | --help | -h | --check-data-compat | --healthcheck) answers_and_exits=1 ;;
    esac
done

state="${YADORILINK_CONFIG_DIR:-/var/lib/yadorilink}"
if [ -n "$supervised" ]; then
    set -- /usr/local/bin/yadorilink-daemon "$@"
fi
if [ -n "$supervised" ] && [ -z "${answers_and_exits:-}" ]; then
    set -- /usr/local/bin/yadorilink-entrypoint --supervise "$@"
fi

if [ "$(id -u)" = 0 ]; then
    uid="${PUID:-999}"
    gid="${PGID:-${PUID:-999}}"
    case "$uid$gid" in
        '' | *[!0-9]*)
            echo "yadorilink: PUID and PGID must be numbers (got PUID=$uid PGID=$gid)" >&2
            exit 64
            ;;
    esac
    if [ "$uid" = 0 ] || [ "$gid" = 0 ]; then
        echo "yadorilink: refusing to run the daemon as root; set PUID and PGID to your account's ids (see 'id')" >&2
        exit 64
    fi
    mkdir -p "$state"
    if [ "$(stat -c '%u:%g' "$state")" != "$uid:$gid" ]; then
        echo "yadorilink: giving $state to $uid:$gid" >&2
        chown -R "$uid:$gid" "$state"
    fi
    chmod 0700 "$state"
    HOME="$state"
    export HOME
    exec setpriv --reuid="$uid" --regid="$gid" --clear-groups -- "$@"
fi

if [ ! -w "$state" ]; then
    echo "yadorilink: $state is not writable by uid $(id -u); make it owned by that user, or run the container as root (the default) with PUID and PGID set so the entrypoint can fix it" >&2
    exit 73
fi
exec "$@"
