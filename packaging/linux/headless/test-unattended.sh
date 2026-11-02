#!/bin/sh
# Restart-recovery check for the unattended profile, runnable by an
# unprivileged user on any systemd Linux box:
#
#   packaging/linux/headless/test-unattended.sh /path/to/yadorilink-daemon
#
# Starts the daemon as a transient systemd --user service with the same
# Restart= policy as yadorilink-headless.service and a throwaway state
# directory, waits for `--healthcheck` to pass, kill -9s the daemon, and
# requires the service manager to bring it back to healthy by itself.
# It also checks that the daemon opens no TCP listener beyond loopback.
set -eu
BIN=${1:?usage: test-unattended.sh /path/to/yadorilink-daemon}
STATE=$(mktemp -d)
UNIT=yl-unattended-test-$$
cleanup() {
    systemctl --user stop "$UNIT.service" >/dev/null 2>&1 || true
    rm -rf "$STATE"
}
trap cleanup EXIT

export YADORILINK_CONFIG_DIR=$STATE
wait_healthy() {
    i=0
    while [ "$i" -lt 60 ]; do
        if "$BIN" --healthcheck >/dev/null 2>&1; then return 0; fi
        i=$((i + 1))
        sleep 1
    done
    return 1
}

if "$BIN" --healthcheck >/dev/null 2>&1; then
    echo "FAIL: healthcheck passed with no daemon running" >&2
    exit 1
fi
systemd-run --user --quiet --unit="$UNIT" -p Restart=always -p RestartSec=2 \
    -p StartLimitIntervalSec=0 \
    --setenv=YADORILINK_CONFIG_DIR="$STATE" --setenv=YADORILINK_CREDENTIAL_STORE=file \
    --setenv=YADORILINK_DISABLE_OS_KEYRING=1 --setenv=YADORILINK_HTTP_API_PORT=0 \
    --setenv=YADORILINK_DAEMON_METRICS_ADDR= "$BIN"
wait_healthy || { echo "FAIL: daemon never became healthy" >&2; exit 1; }
echo "ok: healthy after start"

# Listeners: TCP may only be on loopback.
pid=$(systemctl --user show -p MainPID --value "$UNIT.service")
if command -v ss >/dev/null 2>&1; then
    bad=$(ss -Htlpn 2>/dev/null | grep "pid=$pid," | grep -v -E '127\.0\.0\.1:|\[::1\]:' || true)
    if [ -n "$bad" ]; then
        echo "FAIL: non-loopback TCP listener: $bad" >&2
        exit 1
    fi
    echo "ok: no non-loopback TCP listener"
fi

kill -9 "$pid"
sleep 1
new=$pid
i=0
while [ "$i" -lt 30 ] && [ "$new" = "$pid" -o "$new" = 0 ]; do
    sleep 1
    new=$(systemctl --user show -p MainPID --value "$UNIT.service")
    i=$((i + 1))
done
wait_healthy || { echo "FAIL: daemon not healthy after kill -9" >&2; exit 1; }
echo "ok: recovered after kill -9 (pid $pid -> $(systemctl --user show -p MainPID --value "$UNIT.service"))"

systemctl --user stop "$UNIT.service"
sleep 1
if "$BIN" --healthcheck >/dev/null 2>&1; then
    echo "FAIL: healthcheck passed after stop" >&2
    exit 1
fi
echo "ok: unhealthy after stop"
echo PASS
