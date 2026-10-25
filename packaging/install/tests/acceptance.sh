#!/bin/sh
# Installer acceptance with the REAL programs: install.sh against a LOCAL fixture release whose
# engine bundle holds the repo's own yadorilink and yadorilink-daemon.
#
#   sh packaging/install/tests/acceptance.sh --bin-dir DIR
#
# DIR holds `yadorilink` and `yadorilink-daemon` built for this machine with the fixture trust
# root compiled into the daemon (the daemon verifies manifests against a compile-time key):
#
#   see README.md in the parent directory: build with the fixture's test key (key id
#   yadorilink-test-key, public key from build-fixture.py's default seed) as the daemon's trust
#   root, `cargo build -p yadorilink-cli` and, separately,
#   `cargo build -p yadorilink-daemon --features enforce-release-trust-root`.
#
# run-tests.sh covers the installer's refusals with version-printing stand-ins; this script adds
# what only real programs can show: after a script install the daemon reports
# install_source=script, `self-update` judges versions against the daemon's verified manifest, and
# `uninstall` removes the program tree and keeps the user's data. Everything lives under one temp
# directory (HOME, prefix, config dir, control socket); nothing touches the network (127.0.0.1
# only) or the real trust root, and the temp directory is removed at the end.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
INSTALL=$(cd "$HERE/.." && pwd)/install.sh
BIN_DIR=""
while [ $# -gt 0 ]; do
    case $1 in
        --bin-dir) BIN_DIR=$2; shift 2 ;;
        *) echo "usage: acceptance.sh --bin-dir DIR" >&2; exit 2 ;;
    esac
done
[ -x "$BIN_DIR/yadorilink" ] && [ -x "$BIN_DIR/yadorilink-daemon" ] || { echo "acceptance: --bin-dir needs yadorilink and yadorilink-daemon" >&2; exit 2; }
BIN_DIR=$(cd "$BIN_DIR" && pwd)

case $(uname -s)-$(uname -m) in
    Linux-x86_64) TARGET=linux-x86_64; TOS=Linux; TARCH=x86_64; VNAME=yadorilink-verify-linux-x86_64 ;;
    Darwin-arm64) TARGET=macos-aarch64; TOS=Darwin; TARCH=arm64; VNAME=yadorilink-verify-macos-aarch64 ;;
    *) echo "acceptance: unsupported host $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac

# A short root keeps the control socket path under the unix-socket length limit.
T=$(mktemp -d "${TMPDIR:-/tmp}/yla.XXXXXX")
T=$(cd "$T" && pwd -P)
SRV=$T/srv
H=$T/home
mkdir -p "$SRV" "$H"
SRV_PID=""
DAEMON_STARTED=0
cleanup() {
    if [ "$DAEMON_STARTED" = 1 ]; then
        env HOME="$H" YADORILINK_CONFIG_DIR="$H/cfg" YADORILINK_CONTROL_SOCKET="$T/ctl.sock" "$H/prefix/bin/yadorilink" daemon stop >/dev/null 2>&1
    fi
    [ -z "$SRV_PID" ] || kill "$SRV_PID" 2>/dev/null
    chmod -R u+w "$T" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

python3 "$HERE/serve.py" "$SRV" "$T/port" &
SRV_PID=$!
i=0
while [ ! -s "$T/port" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
[ -s "$T/port" ] || { echo "acceptance: the fixture server did not start" >&2; exit 2; }
BASE=http://127.0.0.1:$(cat "$T/port")

mkdir -p "$SRV/verifier"
printf '#!/bin/sh\nexec perl "%s" "$@"\n' "$HERE/ed25519-verify.pl" > "$SRV/verifier/$VNAME"
chmod +x "$SRV/verifier/$VNAME"
if command -v sha256sum >/dev/null 2>&1; then VSHA=$(sha256sum "$SRV/verifier/$VNAME" | cut -d' ' -f1)
else VSHA=$(shasum -a 256 "$SRV/verifier/$VNAME" | cut -d' ' -f1); fi

pass=0
failn=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { failn=$((failn + 1)); printf 'FAIL %s\n' "$1"; [ -z "${2:-}" ] || sed 's/^/     | /' "$2"; }

# fx NAME [args]: a fixture release with the real programs.
fx() {
    name=$1; shift
    python3 "$HERE/build-fixture.py" "$SRV/$name" --base-url "$BASE/$name" --targets "$TARGET" --bin-dir "$BIN_DIR" --engine-api-version "${ENGINE_API:-1}" "$@" || exit 99
}
pub() { cat "$SRV/$1/pubkey.hex"; }
# inst NAME KEYFROM [args]: run install.sh against fixture NAME. Output $T/out, status $RC.
inst() {
    name=$1; keyfrom=$2; shift 2
    env HOME="$H" SHELL=/bin/sh YADORILINK_INSTALL_TEST=1 \
        YADORILINK_INSTALL_PUBKEY_HEX="$(pub "$keyfrom")" YADORILINK_INSTALL_KEY_ID="$(cat "$SRV/$keyfrom/key_id")" \
        YADORILINK_INSTALL_BASE_URL="$BASE/$name" YADORILINK_INSTALL_MIN_GENERATED_AT="${MINGEN:-2000-01-01T00:00:00Z}" \
        YADORILINK_INSTALL_OS="$TOS" YADORILINK_INSTALL_ARCH="$TARCH" \
        YADORILINK_INSTALL_VERIFIER_BASE="$BASE/verifier" YADORILINK_INSTALL_VERIFIER_SHA256="$VSHA" \
        sh "$INSTALL" --prefix "$H/prefix" --yes "$@" > "$T/out" 2>&1
    RC=$?
}
has() { grep -q -- "$1" "$T/out"; }
# yl ARGS: the installed CLI, against this run's config dir, control socket and fixture manifest.
yl() {
    env HOME="$H" YADORILINK_CONFIG_DIR="$H/cfg" YADORILINK_CONTROL_SOCKET="$T/ctl.sock" \
        YADORILINK_CREDENTIAL_STORE=file YADORILINK_HTTP_API_DISABLE=1 \
        YADORILINK_UPDATE_MANIFEST_URL="$BASE/${REL:-rel}/beta/manifest.json" \
        "$H/prefix/bin/yadorilink" "$@" > "$T/out" 2>&1
    RC=$?
}
# fingerprint of everything installer-owned, to prove a refusal changed nothing
snapshot() { (cd "$H" && find prefix .profile -print 2>/dev/null | sort; ls -l prefix/bin 2>/dev/null | sed 's/.* yadorilink/yadorilink/'; cat prefix/share/yadorilink/install-receipt 2>/dev/null) | cksum; }

echo "host: $(uname -s) $(uname -m)   programs: $BIN_DIR"
echo "installer: $INSTALL"

# user data that no install, update or uninstall step may touch
mkdir -p "$H/Sync" && echo "precious" > "$H/Sync/notes.txt"

# --- 1 install version 1.0.0 with the real programs
fx rel --version 1.0.0
inst rel rel
if [ $RC = 0 ] && has "Manifest signature verified" && has "Installed YadoriLink 1.0.0"; then ok "install.sh installs the real programs"; else bad "install" "$T/out"; fi
SHARE=$H/prefix/share/yadorilink
[ -x "$H/prefix/bin/yadorilink" ] && [ -x "$H/prefix/bin/yadorilink-daemon" ] && ok "yadorilink and yadorilink-daemon are linked into <prefix>/bin" || bad "links"
grep -q '^install_source=script$' "$SHARE/install-receipt" && ok "install-receipt records install_source=script" || bad "receipt"
dd=$(dirname "$(readlink "$H/prefix/bin/yadorilink-daemon")")
grep -q '"source":"script"' "$dd/install-receipt.json" && ok "install-receipt.json (the daemon-readable marker) sits beside the programs" || bad "marker"
"$H/prefix/bin/yadorilink" --version > "$T/out" 2>&1
{ [ $? = 0 ] && grep -q yadorilink "$T/out"; } && ok "yadorilink --version: $(head -1 "$T/out")" || bad "--version" "$T/out"

# --- 2 the real daemon detects the script install
yl daemon start
if [ $RC = 0 ]; then DAEMON_STARTED=1; ok "yadorilink daemon start"; else bad "daemon start" "$T/out"; fi
yl update status
{ [ $RC = 0 ] && grep -q 'install_source: script' "$T/out"; } && ok "daemon reports install_source=script" || bad "daemon install_source" "$T/out"
grep -q '"install_source": *"script"' "$H/cfg/install-owner.json" && ok "ownership record (install-owner.json) says install_source=script" || { bad "ownership record"; cat "$H/cfg/install-owner.json" 2>&1 | sed 's/^/     | /'; }

# --- 3 self-update against the verified manifest
# The daemon's manifest URL is fixed when it starts (<fixture>/rel), so each step republishes
# `rel` in place, with a later generated_at each time (replay protection).
tamper() { python3 - "$1" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["manifest_json"] = e["manifest_json"].replace('"rollout_percentage": 100', '"rollout_percentage":  99', 1); json.dump(e, open(p, "w"))
PY
}
fx rel --version 2.0.0 --extra-version 1.0.0 --generated-at 2026-10-19T00:00:00Z
yl self-update --version 2.0.0
{ [ $RC = 0 ] && has "is allowed by the verified beta channel manifest" && has "install.sh | sh -s -- --channel beta --version 2.0.0 --prefix"; } && ok "self-update --version 2.0.0 is allowed and prints the pinned installer command" || bad "self-update allowed" "$T/out"
yl self-update
{ [ $RC = 0 ] && has "version 2.0.0"; } && ok "plain self-update finds 2.0.0 (rollout 100%)" || bad "plain self-update" "$T/out"
fx rel --version 2.0.0 --extra-version 1.0.0 --withdrawn 2.0.0 --generated-at 2026-10-20T00:00:00Z
yl self-update --version 2.0.0
{ [ $RC = 4 ] && has "Nothing was downloaded or changed"; } && ok "self-update refuses a withdrawn version (exit 4)" || bad "self-update withdrawn (rc=$RC)" "$T/out"
# a manifest whose signature does not verify is never read as "nothing newer" or as permission
fx rel --version 2.0.0 --generated-at 2026-10-21T00:00:00Z
tamper "$SRV/rel/beta/manifest.json"
yl self-update --version 2.0.0
{ [ $RC = 4 ] && ! has "is allowed"; } && ok "self-update refuses a tampered manifest (exit 4)" || bad "self-update tampered (rc=$RC)" "$T/out"
yl self-update
{ [ $RC != 0 ] && ! has "already up to date"; } && ok "plain self-update does not report up to date on a manifest it cannot verify" || bad "plain self-update, tampered (rc=$RC)" "$T/out"
fx rel --version 2.0.0 --extra-version 1.0.0 --generated-at 2026-10-22T00:00:00Z
# carry out the update with the command self-update prints (local installer, fixture endpoints)
before=$(snapshot)
inst rel rel --version 2.0.0
{ [ $RC = 0 ] && has "Installed YadoriLink 2.0.0" && grep -q '^version=2.0.0$' "$SHARE/install-receipt" && [ "$(ls "$SHARE/versions" | wc -l | tr -d ' ')" = 2 ]; } && ok "pinned installer run switches to 2.0.0 and keeps 1.0.0 on disk" || bad "update to 2.0.0" "$T/out"
[ -f "$H/Sync/notes.txt" ] && ok "user folder untouched by install and update" || bad "user data after update"

# --- 4 refusals leave an existing install untouched (real programs, same checks as run-tests.sh)
before=$(snapshot)
refuse() { # NAME expected-rc message
    if [ $RC = "$2" ] && has "$3" && [ "$(snapshot)" = "$before" ]; then ok "refused without side effects: $1"; else bad "refusal: $1 (rc=$RC)" "$T/out"; fi
}
fx t1 --version 3.0.0
python3 - "$SRV/t1/files/3.0.0/yadorilink-engine-beta-$TARGET.zip" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(b)
PY
inst t1 t1; refuse "tampered archive" 4 "SHA-256 does not match the signed manifest"
fx t2 --version 3.0.0
python3 - "$SRV/t2/beta/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["manifest_json"] = e["manifest_json"].replace('"rollout_percentage": 100', '"rollout_percentage":  99', 1); json.dump(e, open(p, "w"))
PY
inst t2 t2; refuse "tampered manifest (signature does not verify)" 4 "does NOT verify"
fx t3 --version 3.0.0; fx t3other --seed 6f746865726f746865726f746865726f746865726f746865726f746865726f74
inst t3 t3other; refuse "manifest signed by another key" 4 "does NOT verify"
fx t4 --version 3.0.0 --withdrawn 3.0.0
inst t4 t4 --version 3.0.0; refuse "withdrawn version" 4 "withdrawn"
fx t5 --version 3.0.0 --kill-switch
inst t5 t5; refuse "kill switch" 4 "withdrawn"
fx t6 --version 3.0.0 --generated-at 2026-10-01T00:00:00Z
MINGEN=2026-10-19T00:00:00Z; inst t6 t6; unset MINGEN
refuse "replayed (older than the pinned floor) manifest" 4 "oldest this installer accepts"
fx t7 --version 1.5.0
inst t7 t7; refuse "downgrade without --version" 6 "not downgrading"
fx t8 --version 3.0.0 --corrupt-sums
inst t8 t8; refuse "bundle file differs from SHA256SUMS" 4 "does not match SHA256SUMS"

# --- pinned downgrade (explicit --version to an older published version)
# An explicit --version never downgrades an existing install (exit 6, nothing changed): the
# installer cannot prove an older program is compatible with the current local state.
before=$(snapshot)
inst rel rel --version 1.0.0
refuse "pinned downgrade 2.0.0 -> 1.0.0 of an existing install" 6 "not downgrading"

# --- 5 uninstall: dry run, then the real thing; the user's data stays
yl uninstall --dry-run
{ [ $RC = 0 ] && has "Would remove" && [ -x "$H/prefix/bin/yadorilink" ] && [ -d "$SHARE" ]; } && ok "uninstall --dry-run lists what would go and removes nothing" || bad "uninstall --dry-run" "$T/out"
mkdir -p "$H/cfg"; echo "device state" > "$H/cfg/keep-me.txt"
yl uninstall --yes
DAEMON_STARTED=0
{ [ $RC = 0 ] && [ ! -e "$H/prefix/bin/yadorilink" ] && [ ! -e "$H/prefix/bin/yadorilink-daemon" ] && [ ! -d "$SHARE" ]; } && ok "uninstall removes the links and the program tree" || bad "uninstall" "$T/out"
! grep -q 'yadorilink (' "$H/.profile" 2>/dev/null && ok "uninstall removes the PATH block from the profile" || bad "PATH block"
{ [ "$(cat "$H/Sync/notes.txt")" = precious ] && [ "$(cat "$H/cfg/keep-me.txt")" = "device state" ] && [ -f "$H/cfg/install-owner.json" ] && [ -f "$H/cfg/device.json" -o -f "$H/cfg/sync.sqlite3" -o -d "$H/cfg" ]; } && ok "uninstall keeps the synced folder and the data directory" || bad "data after uninstall"

# --- fresh install of an older version (nothing installed after the uninstall); kept data stays untouched
inst rel rel --version 1.0.0
{ [ $RC = 0 ] && has "Installed YadoriLink 1.0.0" && [ "$(cat "$H/cfg/keep-me.txt")" = "device state" ]; } && ok "fresh install of an older version works and the data directory is intact" || bad "reinstall 1.0.0" "$T/out"

echo
echo "passed: $pass, failed: $failn"
[ "$failn" = 0 ]
