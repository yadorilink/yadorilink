#!/usr/bin/env bash
# Behavioural check of the container image, run against a local or pulled image:
#
#   packaging/docker/test-image.sh IMAGE
#
# Starts the image the way the compose file does (read-only root, dropped
# capabilities, a bind-mounted folder owned by the calling user, PUID/PGID set to
# that user) and checks: the daemon runs as that user and never as root, the
# state volume and the synced folder keep the right owner, the healthcheck turns
# healthy, the command line runs as the daemon's account, the container survives a
# restart with its state, stops cleanly on SIGTERM, and refuses the unsafe
# configurations. Names are prefixed with TEST_PREFIX (default yadorilink-imgtest)
# and everything it creates is removed on exit.
set -euo pipefail

IMAGE="${1:?usage: test-image.sh IMAGE}"
PREFIX="${TEST_PREFIX:-yadorilink-imgtest}"
UID_="$(id -u)"
GID_="$(id -g)"
WORK="$(mktemp -d)"
failures=0

cleanup() {
  docker rm -f "$PREFIX-main" "$PREFIX-user" "$PREFIX-root" >/dev/null 2>&1 || true
  docker volume rm "$PREFIX-data" "$PREFIX-data2" "$PREFIX-data3" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

ok() { echo "ok: $1"; }
fail() { echo "FAIL: $1" >&2; failures=$((failures + 1)); }
check() { # description command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}

wait_healthy() { # container seconds
  local i=0
  while [ "$i" -lt "$2" ]; do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$1" 2>/dev/null)" = healthy ] && return 0
    i=$((i + 2)); sleep 2
  done
  return 1
}

hardened=(--read-only --tmpfs /tmp --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER --cap-add SETUID --cap-add SETGID
          --security-opt no-new-privileges:true)

mkdir "$WORK/files"
chmod 775 "$WORK/files"

# 1. Default start: PUID/PGID of the caller, read-only root, dropped capabilities.
docker run -d --name "$PREFIX-main" "${hardened[@]}" -e PUID="$UID_" -e PGID="$GID_" \
  -v "$PREFIX-data:/var/lib/yadorilink" -v "$WORK/files:/srv/yadorilink" "$IMAGE" >/dev/null
if wait_healthy "$PREFIX-main" 90; then ok "becomes healthy (read-only root, caps dropped)"; else
  fail "never became healthy"; docker logs "$PREFIX-main" 2>&1 | tail -20 >&2; fi

daemon_uid="$(docker exec "$PREFIX-main" sh -c 'awk "/^Uid:/{print \$2}" /proc/1/status')"
[ "$daemon_uid" = "$UID_" ] && ok "daemon runs as uid $UID_ (not root)" || fail "daemon uid is $daemon_uid, want $UID_"
[ "$(docker exec "$PREFIX-main" stat -c %u:%g /var/lib/yadorilink)" = "$UID_:$GID_" ] \
  && ok "state volume belongs to PUID:PGID" || fail "state volume owner"
[ "$(docker exec "$PREFIX-main" stat -c %a /var/lib/yadorilink)" = 700 ] && ok "state volume is 0700" || fail "state volume mode"
[ "$(stat -c %u "$WORK/files" 2>/dev/null || stat -f %u "$WORK/files")" = "$UID_" ] && ok "synced folder keeps its owner" || fail "synced folder owner changed"

docker exec --user "$UID_:$GID_" "$PREFIX-main" sh -c 'echo hi > /srv/yadorilink/probe.txt' \
  && [ -f "$WORK/files/probe.txt" ] && ok "daemon account can write the bind-mounted folder" || fail "cannot write the folder"
check "root filesystem is read-only" bash -c "! docker exec '$PREFIX-main' sh -c 'touch /usr/probe'"

# 1b. A daemon option that only answers (`--version`) ends the container: the supervisor must not restart it.
ver_out="$(timeout 30 docker run --rm "$IMAGE" --version 2>&1)" && ver_rc=0 || ver_rc=$?
[ "$ver_rc" = 0 ] && [ "$(printf '%s\n' "$ver_out" | wc -l)" = 1 ] \
  && ok "docker run IMAGE --version prints once and exits" || fail "docker run IMAGE --version (exit $ver_rc): $(printf '%s' "$ver_out" | head -c 200)"

# 2. The command line is on PATH and runs as the daemon's account.
docker exec "$PREFIX-main" yadorilink --version >/dev/null && ok "yadorilink --version" || fail "yadorilink --version"
docker exec "$PREFIX-main" yadorilink-daemon --version >/dev/null && ok "yadorilink-daemon --version" || fail "yadorilink-daemon --version"
docker exec "$PREFIX-main" yadorilink-daemon --healthcheck && ok "--healthcheck passes in the container" || fail "--healthcheck"
web="$(docker exec "$PREFIX-main" yadorilink web status 2>&1 || true)"
case "$web" in
  *"ssh -N -L"*) fail "web status gives host SSH advice inside a container: $web" ;;
  *) ok "web status gives no host SSH advice in a container" ;;
esac
docker exec "$PREFIX-main" yadorilink status >/dev/null 2>&1 || true
leftover="$(docker exec "$PREFIX-main" find /var/lib/yadorilink ! -user "$UID_" 2>/dev/null | head -3)"
[ -z "$leftover" ] && ok "the command line created nothing root-owned" || fail "root-owned files in state: $leftover"

# 3. State survives a restart.
docker exec --user "$UID_:$GID_" "$PREFIX-main" sh -c 'echo kept > /var/lib/yadorilink/marker'
before="$(docker exec "$PREFIX-main" sh -c 'cd /var/lib/yadorilink && ls | sort | tr "\n" " "')"
docker restart -t 30 "$PREFIX-main" >/dev/null
if wait_healthy "$PREFIX-main" 90; then ok "healthy again after restart"; else fail "unhealthy after restart"; fi
[ "$(docker exec "$PREFIX-main" cat /var/lib/yadorilink/marker)" = kept ] && ok "state survived the restart" || fail "marker lost"
after="$(docker exec "$PREFIX-main" sh -c 'cd /var/lib/yadorilink && ls | sort | tr "\n" " "')"
[ "$before" = "$after" ] && ok "same state files after restart" || fail "state changed: [$before] vs [$after]"

# 3b. A command that ends the daemon on purpose (`device register` does, to adopt its new
# identity) restarts it inside the container: the exec finishes, the container keeps
# running, and the same container answers again. Without the entrypoint's supervisor the
# container stops and the exec dies with 137.
pid_before="$(docker exec "$PREFIX-main" sh -c 'for d in /proc/[0-9]*; do tr "\\0" " " < "$d/cmdline" 2>/dev/null | grep -q "^/usr/local/bin/yadorilink-daemon" && echo "${d#/proc/}" && break; done; true')"
docker exec "$PREFIX-main" yadorilink daemon stop >/dev/null 2>&1 && ok "daemon stop returns normally" || fail "daemon stop did not return (exec killed?)"
pid_after=""
for _ in $(seq 1 30); do
  pid_after="$(docker exec "$PREFIX-main" sh -c 'for d in /proc/[0-9]*; do tr "\\0" " " < "$d/cmdline" 2>/dev/null | grep -q "^/usr/local/bin/yadorilink-daemon" && echo "${d#/proc/}" && break; done; true' 2>/dev/null || true)"
  [ -n "$pid_after" ] && [ "$pid_after" != "$pid_before" ] && break
  sleep 2
done
{ [ -n "$pid_after" ] && [ "$pid_before" != "$pid_after" ]; } && ok "a new daemon process runs" || fail "daemon pid $pid_before -> $pid_after"
[ "$(docker inspect -f '{{.State.Running}}' "$PREFIX-main")" = true ] && ok "container kept running" || fail "container stopped"
if docker exec "$PREFIX-main" yadorilink-daemon --healthcheck >/dev/null 2>&1 || { sleep 5; docker exec "$PREFIX-main" yadorilink-daemon --healthcheck >/dev/null 2>&1; }; then ok "the restarted daemon answers"; else fail "restarted daemon does not answer"; fi

# 3c. A daemon started with an option is supervised too: `daemon stop` restarts it and the
# container keeps running (the image tells command lines to wait for a supervisor).
docker rm -f "$PREFIX-root" >/dev/null 2>&1 || true
docker run -d --name "$PREFIX-root" "${hardened[@]}" -e PUID="$UID_" -e PGID="$GID_" \
  -v "$PREFIX-data3:/var/lib/yadorilink" "$IMAGE" --restart-on-replace >/dev/null
if wait_healthy "$PREFIX-root" 90; then ok "a daemon started with an option becomes healthy"; else
  fail "daemon with an option never became healthy"; docker logs "$PREFIX-root" 2>&1 | tail -20 >&2; fi
docker exec "$PREFIX-root" yadorilink daemon stop >/dev/null 2>&1 && ok "daemon stop returns (daemon started with an option)" || fail "daemon stop did not return (daemon started with an option)"
sleep 8
[ "$(docker inspect -f '{{.State.Running}}' "$PREFIX-root")" = true ] && ok "container with an option kept running after daemon stop" || fail "container with an option stopped after daemon stop"
if wait_healthy "$PREFIX-root" 60; then ok "the restarted daemon (started with an option) answers"; else fail "restarted daemon with an option does not answer"; fi
docker rm -f "$PREFIX-root" >/dev/null

# 3d. The supervisor's pacing, with a stand-in for the daemon that exits three times and then ends
# the container (status 1). Whatever its status, a daemon that exits at once, over and over, must
# not spin: it waits a second each time. A stop the daemon was asked to make so that it comes back
# (status 75: `device register` after the first start, a replaced executable) is restarted without
# waiting once it has run for a second. An ordinary exit (0) within five seconds still waits.
supervisor_ms() { # exit status of the stand-in's first three runs, seconds it runs before exiting
  docker run --rm --entrypoint sh "$IMAGE" -c '
    s=$(date +%s%N)
    /usr/local/bin/yadorilink-entrypoint --supervise sh -c "n=\$(cat /tmp/n 2>/dev/null || echo 0); n=\$((n + 1)); echo \$n > /tmp/n; sleep '"$2"'; [ \$n -lt 4 ] && exit '"$1"'; exit 1" >/dev/null 2>&1
    echo $(( ($(date +%s%N) - s) / 1000000 ))' 2>/dev/null | tail -n 1
}
ms="$(supervisor_ms 75 0)"
# (`date +%s` counts whole seconds: one of the three restarts may cross a second boundary and go
# unpaced, so two waits are required.)
{ [ -n "$ms" ] && [ "$ms" -ge 1800 ]; } && ok "a daemon that exits 75 at once is paced (3 restarts in ${ms} ms)" || fail "exit 75 at once did not wait (${ms:-no answer} ms)"
ms="$(supervisor_ms 0 0)"
{ [ -n "$ms" ] && [ "$ms" -ge 2800 ]; } && ok "a daemon that exits 0 at once is paced (3 restarts in ${ms} ms)" || fail "exit 0 at once did not wait (${ms:-no answer} ms)"
ms="$(supervisor_ms 75 1.1)"
{ [ -n "$ms" ] && [ "$ms" -lt 6500 ]; } && ok "a daemon that ran a second and exits 75 is restarted at once (4 runs of 1.1 s took ${ms} ms)" || fail "exit 75 after a second waited (${ms:-no answer} ms)"
ms="$(supervisor_ms 0 1.1)"
{ [ -n "$ms" ] && [ "$ms" -ge 6500 ]; } && ok "a daemon that ran a second and exits 0 still waits (4 runs of 1.1 s took ${ms} ms)" || fail "exit 0 after a second did not wait (${ms:-no answer} ms)"

# 4. SIGTERM stops it cleanly and quickly.
start="$(date +%s)"
docker stop -t 30 "$PREFIX-main" >/dev/null
elapsed=$(( $(date +%s) - start ))
code="$(docker inspect -f '{{.State.ExitCode}}' "$PREFIX-main")"
{ [ "$code" = 0 ] && [ "$elapsed" -lt 25 ]; } && ok "graceful stop (exit $code in ${elapsed}s)" || fail "stop: exit $code after ${elapsed}s"

# 5. Unsafe configurations are refused with a message.
out="$(docker run --rm -e PUID=0 -e PGID=0 "$IMAGE" 2>&1 || true)"
case "$out" in *"refusing to run the daemon as root"*) ok "PUID=0 is refused" ;; *) fail "PUID=0 not refused: $out" ;; esac
out="$(docker run --rm -e PUID=abc "$IMAGE" 2>&1 || true)"
case "$out" in *"must be numbers"*) ok "non-numeric PUID is refused" ;; *) fail "bad PUID not refused: $out" ;; esac
out="$(docker run --rm --user "$UID_:$GID_" -v "$PREFIX-data2:/var/lib/yadorilink" "$IMAGE" 2>&1 || true)"
case "$out" in *"not writable by uid $UID_"*) ok "--user with an unwritable state volume says why" ;; *) fail "unwritable state not explained: $out" ;; esac
mkdir "$WORK/state"
docker run -d --name "$PREFIX-user" --read-only --tmpfs /tmp --user "$UID_:$GID_" \
  -v "$WORK/state:/var/lib/yadorilink" "$IMAGE" >/dev/null
if wait_healthy "$PREFIX-user" 90; then ok "--user UID:GID with a bind-mounted state dir becomes healthy"; else fail "--user start"; fi
docker rm -f "$PREFIX-user" >/dev/null
out="$(docker run --rm -e YADORILINK_CONFIG_DIR=/tmp/none "$IMAGE" yadorilink-daemon --healthcheck 2>&1 || true)"
case "$out" in *unhealthy*) ok "--healthcheck fails with no daemon" ;; *) fail "healthcheck passed with no daemon: $out" ;; esac

# 6. Metadata.
label="$(docker image inspect "$IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.licenses"}}')"
[ "$label" = "AGPL-3.0-only" ] && ok "OCI labels present" || fail "OCI label missing"
[ -n "$(docker image inspect "$IMAGE" --format '{{.Config.Healthcheck}}' | grep -- '--healthcheck')" ] && ok "image declares the HEALTHCHECK" || fail "no HEALTHCHECK in image"
echo "image size: $(docker image inspect "$IMAGE" --format '{{.Size}}') bytes"

if [ "$failures" -ne 0 ]; then echo "FAILED: $failures check(s)" >&2; exit 1; fi
echo PASS
