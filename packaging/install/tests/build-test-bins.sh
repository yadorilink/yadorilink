#!/bin/sh
# Builds the programs the acceptance scripts install, in the oldest image the matrix runs on.
#
#   sh packaging/install/tests/build-test-bins.sh OUT_DIR [GIT_REV]
#
# Uses the image recipe's builder stage (packaging/docker/Dockerfile, Debian bookworm, glibc 2.36)
# with the fixture's throw-away test key compiled in as the release trust root, so the binaries
# verify only the fixture manifests and must never be shipped. OUT_DIR gets `yadorilink` and
# `yadorilink-daemon` (release profile). The source is `git archive GIT_REV` (default HEAD), so
# uncommitted changes are not built; with YL_SRC_DIR set it is that already-unpacked source tree
# instead (for a machine that has the tree but not the repository). Needs docker, and git unless
# YL_SRC_DIR is set.
set -eu
[ $# -ge 1 ] || { echo "usage: build-test-bins.sh OUT_DIR [GIT_REV]" >&2; exit 2; }
OUT=$1
REV=${2:-HEAD}
RUNTIME=${CONTAINER_RUNTIME:-docker}
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
# The public half of the fixture's test key (build-fixture.py's fixed seed; see ../README.md).
KEY_ID=yadorilink-test-key
KEY_HEX=06b77fc89d2b9785433dd37a9b98a3c8fa37f03db2b2cc0e79be76f87b223d21

if [ -n "${YL_SRC_DIR:-}" ]; then
    SRC=$YL_SRC_DIR
    TAG=yl-testbins:$(basename "$SRC")
else
    SRC=$(mktemp -d "${TMPDIR:-/tmp}/yl-testbins.XXXXXX")
    trap 'rm -rf "$SRC"' EXIT
    trap 'exit 130' INT TERM
    git -C "$REPO" archive "$REV" | tar -x -C "$SRC"
    TAG=yl-testbins:$(git -C "$REPO" rev-parse --short=9 "$REV")
fi
$RUNTIME build -q -f "$SRC/packaging/docker/Dockerfile" --target builder \
    --build-arg YADORILINK_RELEASE_MANIFEST_KEY_ID="$KEY_ID" \
    --build-arg YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX="$KEY_HEX" \
    -t "$TAG" "$SRC" >/dev/null
mkdir -p "$OUT"
cid=$($RUNTIME create "$TAG")
trap '$RUNTIME rm -f "$cid" >/dev/null 2>&1; [ -n "${YL_SRC_DIR:-}" ] || rm -rf "$SRC"' EXIT
trap 'exit 130' INT TERM
for b in yadorilink yadorilink-daemon; do
    $RUNTIME cp "$cid:/build/target/release/$b" "$OUT/$b"
done
echo "built $TAG -> $OUT ($(ls "$OUT" | tr '\n' ' '))"
