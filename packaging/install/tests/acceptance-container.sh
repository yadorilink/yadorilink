#!/bin/sh
# Runs acceptance.sh as an unprivileged user in a clean container image (Linux).
#
#   sh packaging/install/tests/acceptance-container.sh IMAGE BIN_DIR
#   sh packaging/install/tests/acceptance-container.sh ubuntu:22.04 /path/to/linux-bins
#
# IMAGE is a Debian or Ubuntu image. As root the script installs only what the harness needs
# (curl, unzip, python3, perl, ca-certificates: the installer's own needs are curl and unzip),
# creates a user, and drops to it. BIN_DIR must hold yadorilink and yadorilink-daemon built
# against a glibc no newer than IMAGE's (build in the oldest image you test). The container is
# removed afterwards; nothing is written outside it except the read-only mounts.
set -eu
[ $# -eq 2 ] || { echo "usage: acceptance-container.sh IMAGE BIN_DIR" >&2; exit 2; }
IMAGE=$1
BINS=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")/.." && pwd)
RUNTIME=${CONTAINER_RUNTIME:-docker}
exec "$RUNTIME" run --rm \
    -v "$HERE":/src:ro -v "$BINS":/bins:ro \
    "$IMAGE" sh -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends curl unzip python3 perl ca-certificates >/dev/null
useradd -m tester
. /etc/os-release; echo "image: $PRETTY_NAME, glibc $(ldd --version | head -1 | sed "s/.* //")"
exec su tester -c "cd /home/tester && sh /src/tests/acceptance.sh --bin-dir /bins"
'
