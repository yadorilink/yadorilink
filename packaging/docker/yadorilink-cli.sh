#!/bin/sh
# `yadorilink` inside the container. `docker exec` starts as root, but the
# daemon's credentials and control socket belong to the account that owns the
# state directory; run the real command line as that account so both sides
# agree and nothing root-owned appears in the state directory.
set -eu

real=/usr/libexec/yadorilink/yadorilink
state="${YADORILINK_CONFIG_DIR:-/var/lib/yadorilink}"

if [ "$(id -u)" = 0 ] && [ -d "$state" ]; then
    owner="$(stat -c '%u' "$state")"
    group="$(stat -c '%g' "$state")"
    if [ "$owner" != 0 ]; then
        HOME="$state"
        export HOME
        exec setpriv --reuid="$owner" --regid="$group" --clear-groups -- "$real" "$@"
    fi
fi
exec "$real" "$@"
