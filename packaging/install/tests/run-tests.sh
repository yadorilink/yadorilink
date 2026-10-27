#!/bin/sh
# Installer tests: site/install.sh against a LOCAL fixture release.
#
#   sh packaging/install/tests/run-tests.sh
#
# Everything happens under a temp directory: a throw-away HOME and prefix, a
# fixture release (real zips, fake binaries, a manifest signed with a TEST key)
# served from 127.0.0.1. The installer's test hooks work only because this
# script sets YADORILINK_INSTALL_TEST=1; the real trust root and endpoints are
# never touched. Needs python3, curl, unzip; uses OpenSSL 3 as a second
# Ed25519 engine when one is on PATH or at the Homebrew location.
set -u
INSTALL_SH=${INSTALL_SH:-sh}

HERE=$(cd "$(dirname "$0")" && pwd)
INSTALL=$(cd "$HERE/.." && pwd)/install.sh
T=$(mktemp -d "${TMPDIR:-/tmp}/yl-install-tests.XXXXXX")
SRV=$T/srv
mkdir -p "$SRV"
SRV_PID=""
trap 'kill "$SRV_PID" 2>/dev/null; chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT INT TERM

python3 "$HERE/serve.py" "$SRV" "$T/port" &
SRV_PID=$!
i=0
while [ ! -s "$T/port" ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i + 1)); done
[ -s "$T/port" ] || { echo "run-tests: the fixture server did not start" >&2; exit 2; }
PORT=$(cat "$T/port")
BASE=http://127.0.0.1:$PORT

# The pinned verifier is a program the installer downloads and hash-checks. The
# fixture serves a wrapper around ed25519-verify.pl (RFC 8032 reference in perl).
mkdir -p "$SRV/verifier"
for t in linux-x86_64 macos-aarch64; do
    printf '#!/bin/sh\nexec perl "%s" "$@"\n' "$HERE/ed25519-verify.pl" > "$SRV/verifier/yadorilink-verify-$t"
    chmod +x "$SRV/verifier/yadorilink-verify-$t"
done
if command -v sha256sum >/dev/null 2>&1; then VSHA=$(sha256sum "$SRV/verifier/yadorilink-verify-linux-x86_64" | cut -d' ' -f1)
else VSHA=$(shasum -a 256 "$SRV/verifier/yadorilink-verify-linux-x86_64" | cut -d' ' -f1); fi

OPENSSL3=""
for c in "$(command -v openssl 2>/dev/null)" /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    [ -n "$c" ] && [ -x "$c" ] && "$c" version 2>/dev/null | grep -q '^OpenSSL 3' && { OPENSSL3=$c; break; }
done

pass=0
failn=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { failn=$((failn + 1)); printf 'FAIL %s\n' "$1"; [ -z "${2:-}" ] || sed 's/^/     | /' "$2"; }

# fx NAME [build-fixture args]: build fixture NAME and echo nothing.
fx() {
    name=$1; shift
    python3 "$HERE/build-fixture.py" "$SRV/$name" --base-url "$BASE/$name" "$@" || exit 99
}
pub() { cat "$SRV/$1/pubkey.hex"; }

# inst NAME PUBKEYNAME [installer args]: run the installer with fixture NAME,
# trusting PUBKEYNAME's key. HOME/prefix come from $H. Output in $T/out, exit
# status in $RC. $VBASE / $VSHA_OVERRIDE change where the verifier comes from
# and which hash is pinned.
inst() {
    name=$1; keyfrom=$2; shift 2
    env HOME="$H" SHELL=/bin/sh \
        YADORILINK_INSTALL_TEST=1 \
        YADORILINK_INSTALL_PUBKEY_HEX="$(pub "$keyfrom")" \
        YADORILINK_INSTALL_KEY_ID="$(cat "$SRV/$keyfrom/key_id")" \
        YADORILINK_INSTALL_BASE_URL="${BASEURL_OVERRIDE:-$BASE/$name}" \
        YADORILINK_INSTALL_MIN_GENERATED_AT="${MINGEN:-2000-01-01T00:00:00Z}" \
        ${NOW:+YADORILINK_INSTALL_NOW="$NOW"} \
        YADORILINK_INSTALL_OS="${TOS:-Linux}" YADORILINK_INSTALL_ARCH="${TARCH:-x86_64}" \
        ${TRUSTSET:+YADORILINK_INSTALL_TRUST_SET="$TRUSTSET"} \
        YADORILINK_INSTALL_VERIFIER_BASE="${VBASE:-$BASE/verifier}" \
        YADORILINK_INSTALL_VERIFIER_SHA256="${VSHA_OVERRIDE-$VSHA}" \
        $INSTALL_SH "$INSTALL" --prefix "$H/prefix" --yes "$@" > "$T/out" 2>&1
    RC=$?
}
newhome() { H=$T/h$1; rm -rf "$H"; mkdir -p "$H"; }
has() { grep -q -- "$1" "$T/out"; }
nothing_installed() { [ ! -e "$H/prefix/bin/yadorilink" ] && [ ! -e "$H/prefix/bin/yadorilink-daemon" ] && [ ! -d "$H/prefix/share/yadorilink/versions" ] && ! ls -d "$H"/prefix/share/yadorilink/.staging.* >/dev/null 2>&1 && [ ! -e "$H/prefix/share/yadorilink/.lock" ]; }
version_is() { "$H/prefix/bin/yadorilink" --version 2>&1 | grep -q "fake $1 "; }

echo "installer: $INSTALL"
echo "openssl3: ${OPENSSL3:-none (perl engine only)}"

# --- static checks
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck -s sh "$INSTALL" >"$T/sc" 2>&1 && ok "shellcheck clean" || bad "shellcheck" "$T/sc"
else echo "skip shellcheck (not installed)"; fi
sh -n "$INSTALL" && ok "sh -n" || bad "sh -n"
if command -v dash >/dev/null 2>&1; then dash -n "$INSTALL" && ok "dash -n" || bad "dash -n"; fi
if python3 - "$INSTALL" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
# every override variable is read only inside the TEST_MODE branch
head, _, rest = s.partition('if [ "${YADORILINK_INSTALL_TEST:-}" = "1" ]; then')
block, _, tail = rest.partition("\nfi\n")
bad = [m for m in re.findall(r"YADORILINK_INSTALL_[A-Z_]+", head + tail) if m != "YADORILINK_INSTALL_TEST"]
sys.exit(1 if bad else 0)
PY
then ok "override variables are read only in the test branch"; else bad "override variables outside the test branch"; fi

# --- 1 success (default engine order), key properties
newhome 1; fx s1
inst s1 s1
if [ $RC = 0 ] && version_is 0.2.0 && has "Manifest signature verified" && has "Installed YadoriLink 0.2.0" &&
    grep -q '^install_source=script$' "$H/prefix/share/yadorilink/install-receipt" &&
    grep -q 'yadorilink (' "$H/.profile" && has "yadorilink daemon start"; then ok "success: install, receipt, PATH, next steps"; else bad "success" "$T/out"; fi
[ -x "$H/prefix/bin/yadorilink-daemon" ] && ok "daemon linked" || bad "daemon linked"

# --- verifier handling
newhome 2
# the real installer carries the released pins, so build the "not published yet" state from it
# (empty pins) instead of relying on what the repository currently pins
NOPIN=$T/install-nopin.sh
sed -E 's/^(VERIFIER_SHA_[a-z0-9_]+)=".*"$/\1=""/' "$INSTALL" > "$NOPIN"
REAL_INSTALL=$INSTALL; INSTALL=$NOPIN; VSHA_OVERRIDE=""; inst s1 s1; unset VSHA_OVERRIDE; INSTALL=$REAL_INSTALL
{ [ $RC != 0 ] && has "no pinned Ed25519 verifier" && nothing_installed; } && ok "empty verifier pin refused" || bad "empty verifier pin" "$T/out"
newhome 3
VSHA_OVERRIDE=0000000000000000000000000000000000000000000000000000000000000000; inst s1 s1; unset VSHA_OVERRIDE
{ [ $RC != 0 ] && has "does not match the SHA-256 pinned" && nothing_installed; } && ok "verifier with wrong hash is not run" || bad "verifier hash mismatch" "$T/out"
# a verifier that says yes to everything is caught by the known-answer test
mkdir -p "$SRV/liar"; printf '#!/bin/sh\nexit 0\n' > "$SRV/liar/yadorilink-verify-linux-x86_64"; chmod +x "$SRV/liar/yadorilink-verify-linux-x86_64"
LSHA=$(shasum -a 256 "$SRV/liar/yadorilink-verify-linux-x86_64" 2>/dev/null | cut -d' ' -f1 || sha256sum "$SRV/liar/yadorilink-verify-linux-x86_64" | cut -d' ' -f1)
newhome 3; VBASE=$BASE/liar; VSHA_OVERRIDE=$LSHA; inst s1 s1; unset VBASE VSHA_OVERRIDE
{ [ $RC != 0 ] && has "failed its self-test" && nothing_installed; } && ok "always-yes verifier fails the self-test" || bad "lying verifier" "$T/out"
# verifier missing on the server
newhome 3; VBASE=$BASE/nowhere; inst s1 s1; unset VBASE
{ [ $RC != 0 ] && has "could not download the signature verifier" && nothing_installed; } && ok "missing verifier refused" || bad "missing verifier" "$T/out"

# --- redirected downloads (release assets redirect to another host)
newhome 24
VBASE=$BASE/redir/verifier; inst s1 s1; unset VBASE
{ [ $RC = 0 ] && version_is 0.2.0; } && ok "verifier download follows redirects" || bad "redirected verifier" "$T/out"
# --- prefix with shell metacharacters stays literal in the profile
newhome 25; H25=$H
sh -c 'cd "$1" && mkdir -p "dollar\$tools"' sh "$H"
env HOME="$H" SHELL=/bin/sh YADORILINK_INSTALL_TEST=1 YADORILINK_INSTALL_MIN_GENERATED_AT=2000-01-01T00:00:00Z YADORILINK_INSTALL_PUBKEY_HEX="$(pub s1)" YADORILINK_INSTALL_KEY_ID="$(cat "$SRV/s1/key_id")" \
    YADORILINK_INSTALL_BASE_URL="$BASE/s1" YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 YADORILINK_INSTALL_VERIFIER_BASE="$BASE/verifier" \
    YADORILINK_INSTALL_VERIFIER_SHA256="$VSHA" sh "$INSTALL" --prefix "$H/it's \$(touch pwned)" --yes > "$T/out" 2>&1; RC=$?
if [ $RC = 0 ] && [ ! -e pwned ] && (cd "$H" && HOME="$H" sh -c '. ./.profile; command -v yadorilink >/dev/null' && [ ! -e "$H/pwned" ]); then ok "prefix metacharacters stay literal in the profile"; else bad "prefix quoting" "$T/out"; fi

# --- 3 macOS layout
newhome 4; fx s4 --targets macos-aarch64
TOS=Darwin TARCH=arm64; inst s4 s4; unset TOS TARCH
{ [ $RC = 0 ] && version_is 0.2.0 && [ -f "$H/prefix/share/yadorilink/versions/"*/bin/yadorilink ]; } && ok "macos-aarch64 layout" || bad "macos layout" "$T/out"

# --- tamper cases: each must fail closed and leave nothing
newhome 5; fx s5
python3 - "$SRV/s5/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(b)
PY
inst s5 s5
{ [ $RC != 0 ] && has "SHA-256 does not match the signed manifest" && nothing_installed; } && ok "tampered zip rejected" || bad "tampered zip" "$T/out"

newhome 6; fx s6
python3 - "$SRV/s6/beta/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["manifest_json"] = e["manifest_json"].replace('"rollout_percentage": 100', '"rollout_percentage":  99', 1); json.dump(e, open(p, "w"))
PY
inst s6 s6
{ [ $RC != 0 ] && has "does NOT verify" && nothing_installed; } && ok "tampered manifest rejected" || bad "tampered manifest" "$T/out"

newhome 7; fx s7; fx s7other --seed 6f746865726f746865726f746865726f746865726f746865726f746865726f74
inst s7 s7other
{ [ $RC != 0 ] && has "does NOT verify" && nothing_installed; } && ok "wrong key rejected" || bad "wrong key" "$T/out"
# trust SET: the entry for the manifest's key id decides; other entries do not matter
newhome 22
TS="retired-key:$(pub s7other) yadorilink-test-key:$(pub s7)"
TRUSTSET=$TS; inst s7 s7; unset TRUSTSET
{ [ $RC = 0 ] && version_is 0.2.0; } && ok "trust set: second entry accepted" || bad "trust set second entry" "$T/out"
newhome 23
TRUSTSET="yadorilink-test-key:$(pub s7other) next-key:$(pub s7)"; inst s7 s7; unset TRUSTSET
{ [ $RC != 0 ] && has "does NOT verify" && nothing_installed; } && ok "trust set: key id bound to its own key" || bad "trust set key binding" "$T/out"
# a rotation announcement (top-level trust_chain with nested key_id fields) must not break the key_id read
newhome 24; fx s24
python3 - "$SRV/s24" <<'PY'
import json, pathlib, sys
for p in pathlib.Path(sys.argv[1]).glob("*/manifest.json"):
    if p.parent.name == "files": continue
    e = json.load(open(p))
    e["trust_chain"] = [{"key_id": e["key_id"], "record_json": '{"add":[{"key_id":"spare [x]","public_key_hex":"00"}]}', "signature_base64": "AA=="}]
    json.dump(e, open(p, "w"))
PY
inst s24 s24
{ [ $RC = 0 ] && version_is 0.2.0; } && ok "envelope with trust_chain installs" || bad "envelope with trust_chain" "$T/out"
newhome 8
env HOME="$H" YADORILINK_INSTALL_TEST=1 YADORILINK_INSTALL_MIN_GENERATED_AT=2000-01-01T00:00:00Z YADORILINK_INSTALL_PUBKEY_HEX="$(pub s7)" YADORILINK_INSTALL_KEY_ID=some-other-id \
    YADORILINK_INSTALL_BASE_URL="$BASE/s7" YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 sh "$INSTALL" --prefix "$H/prefix" --yes > "$T/out" 2>&1; RC=$?
{ [ $RC != 0 ] && has "not one of the pinned release keys" && nothing_installed; } && ok "wrong key id rejected" || bad "wrong key id" "$T/out"

# --- bundles that are signed and hashed correctly but wrong inside
badbundle() { # NAME MESSAGE builder-args...
    n=$1; msg=$2; shift 2
    newhome 9; fx "b-$n" "$@"
    inst "b-$n" "b-$n"
    { [ $RC != 0 ] && has "$msg" && nothing_installed; } && ok "bad bundle rejected: $n" || bad "bad bundle: $n" "$T/out"
}
badbundle corrupt-sums "does not match SHA256SUMS" --corrupt-sums
badbundle extra-file "differ from its SHA256SUMS" --extra-file
badbundle identity-channel "expected 'beta'" --identity-channel stable
badbundle asset-name "names asset" --asset-name other.zip
badbundle broken-bin "does not run on this system" --broken-bin

# --- wrong platform / arch
newhome 10; fx s10
for pair in "Linux:aarch64" "Linux:armv7l" "FreeBSD:x86_64" "Darwin:x86_64"; do
    TOS=${pair%%:*}; TARCH=${pair#*:}; inst s10 s10; unset TOS TARCH
    { [ $RC != 0 ] && { has "unsupported\|no YadoriLink engine bundle"; } && nothing_installed; } && ok "refused $pair" || bad "refused $pair" "$T/out"
done

# --- upgrade, idempotence, force, downgrade, rollback on failure
newhome 12; fx u1 --version 0.2.0; fx u2 --version 0.3.0; fx u3 --version 0.4.0 --broken-bin
inst u1 u1
{ [ $RC = 0 ] && version_is 0.2.0; } && ok "initial install 0.2.0" || bad "initial install" "$T/out"
inst u1 u1
{ [ $RC = 0 ] && has "already installed and up to date"; } && ok "re-run is idempotent" || bad "re-run" "$T/out"
inst u2 u1
{ [ $RC = 0 ] && version_is 0.3.0 && [ "$(ls "$H/prefix/share/yadorilink/versions" | wc -l | tr -d ' ')" = 2 ]; } && ok "upgrade to 0.3.0 keeps previous version" || bad "upgrade" "$T/out"
inst u3 u1
{ [ $RC != 0 ] && has "does not run on this system" && version_is 0.3.0 && grep -q '^version=0.3.0$' "$H/prefix/share/yadorilink/install-receipt"; } && ok "failed upgrade leaves 0.3.0 active" || bad "failed upgrade" "$T/out"
inst u1 u1
{ [ $RC != 0 ] && has "not downgrading" && version_is 0.3.0; } && ok "downgrade refused" || bad "downgrade" "$T/out"
inst u1 u1 --version 0.2.0
{ [ $RC = 6 ] && has "not downgrading" && version_is 0.3.0 && grep -q '^version=0.3.0$' "$H/prefix/share/yadorilink/install-receipt" && [ "$(ls "$H/prefix/share/yadorilink/versions" | wc -l | tr -d ' ')" = 2 ]; } && ok "explicit --version older than the installed one: exit 6, nothing changed" || bad "pinned downgrade refused" "$T/out"
inst u2 u1 --force
{ [ $RC = 0 ] && version_is 0.3.0 && has "Installed YadoriLink 0.3.0"; } && ok "--force reinstalls" || bad "force" "$T/out"
inst u2 u1 --version 9.9.9
{ [ $RC != 0 ] && has "has no published manifest"; } && ok "--version without a published manifest refused" || bad "--version unpublished" "$T/out"
inst u2 u1 --version v0.3.0
{ [ $RC = 0 ]; } && ok "--version accepts v-prefix" || bad "--version v-prefix" "$T/out"

# --- a failure while switching links restores the old state
# (make the bin directory unable to take a new link by pre-creating a directory named like the temp link is not
# portable; instead check that a foreign binary blocks the install before any change)
newhome 13; fx f1
mkdir -p "$H/prefix/bin"; printf '#!/bin/sh\necho mine\n' > "$H/prefix/bin/yadorilink"; chmod +x "$H/prefix/bin/yadorilink"
inst f1 f1
{ [ $RC != 0 ] && has "was not installed by this script" && grep -q mine "$H/prefix/bin/yadorilink"; } && ok "foreign binary is never overwritten" || bad "foreign binary" "$T/out"

# --- kill switch
newhome 14; fx k1 --kill-switch
inst k1 k1
{ [ $RC != 0 ] && has "withdrawn" && nothing_installed; } && ok "kill switch honoured" || bad "kill switch" "$T/out"

# --- interrupted download
newhome 15; fx i1; : > "$SRV/i1/.truncate"
inst i1 i1
{ [ $RC != 0 ] && has "download failed or was interrupted" && nothing_installed; } && ok "interrupted download leaves nothing" || bad "interrupted download" "$T/out"

# --- read-only prefix
newhome 16; fx r1; mkdir -p "$H/prefix"; chmod 555 "$H/prefix"
if [ "$(id -u)" != 0 ]; then
    inst r1 r1
    { [ $RC != 0 ] && has "cannot write to" && [ -z "$(ls -A "$H/prefix")" ]; } && ok "read-only prefix refused up front" || bad "read-only prefix" "$T/out"
else echo "skip read-only prefix (root)"; fi
chmod 755 "$H/prefix"

# --- no network, and no release published yet
newhome 17
env HOME="$H" YADORILINK_INSTALL_TEST=1 YADORILINK_INSTALL_MIN_GENERATED_AT=2000-01-01T00:00:00Z YADORILINK_INSTALL_PUBKEY_HEX="$(pub s1)" YADORILINK_INSTALL_BASE_URL="http://127.0.0.1:1" \
    YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 sh "$INSTALL" --prefix "$H/prefix" --yes > "$T/out" 2>&1; RC=$?
{ [ $RC != 0 ] && has "could not reach" && nothing_installed; } && ok "no network fails cleanly" || bad "no network" "$T/out"
newhome 18; mkdir -p "$SRV/empty"
inst empty s1
{ [ $RC != 0 ] && has "No release is published yet" && nothing_installed; } && ok "404 says no release is published yet" || bad "404" "$T/out"

# --- overrides are ignored without YADORILINK_INSTALL_TEST=1
newhome 19; : > "$SRV/requests.log"
env HOME="$H" HTTPS_PROXY=http://127.0.0.1:1 https_proxy=http://127.0.0.1:1 ALL_PROXY=http://127.0.0.1:1 \
    YADORILINK_INSTALL_PUBKEY_HEX="$(pub s1)" YADORILINK_INSTALL_BASE_URL="$BASE/s1" YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 \
    sh "$INSTALL" --prefix "$H/prefix" --yes > "$T/out" 2>&1; RC=$?
{ [ $RC != 0 ] && ! has "TEST MODE" && has "yadori.link/dl" && [ ! -s "$SRV/requests.log" ] && nothing_installed; } && ok "test overrides ignored without YADORILINK_INSTALL_TEST=1" || bad "overrides honoured outside test mode" "$T/out"

# --- uninstall
newhome 20
inst s1 s1
inst s1 s1 --uninstall
{ [ $RC = 0 ] && [ ! -e "$H/prefix/bin/yadorilink" ] && [ ! -d "$H/prefix/share/yadorilink" ] && ! grep -q 'yadorilink (' "$H/.profile" 2>/dev/null; } && ok "uninstall removes links, files, PATH block" || bad "uninstall" "$T/out"
inst s1 s1 --uninstall
{ [ $RC = 0 ] && has "Nothing to uninstall"; } && ok "uninstall twice is harmless" || bad "uninstall twice" "$T/out"

# --- uninstall cleans up after a failed first install (no receipt)
newhome 26; mkdir -p "$SRV/empty"
inst empty s1; inst empty s1 --uninstall
{ [ $RC = 0 ] && [ ! -d "$H/prefix/share/yadorilink" ]; } && ok "uninstall without receipt cleans leftovers" || bad "uninstall without receipt" "$T/out"
# --- uninstall refuses while another install holds the lock
newhome 27; mkdir -p "$H/prefix/share/yadorilink/.lock"; echo $$ > "$H/prefix/share/yadorilink/.lock/pid"
inst s1 s1 --uninstall
{ [ $RC != 0 ] && has "another yadorilink install is running" && [ -d "$H/prefix/share/yadorilink" ]; } && ok "uninstall respects the install lock" || bad "uninstall lock" "$T/out"
# --- bash profile choice keeps an existing .profile
newhome 28; printf 'echo hi\n' > "$H/.profile"
env HOME="$H" SHELL=/bin/bash YADORILINK_INSTALL_TEST=1 YADORILINK_INSTALL_MIN_GENERATED_AT=2000-01-01T00:00:00Z YADORILINK_INSTALL_PUBKEY_HEX="$(pub s1)" YADORILINK_INSTALL_KEY_ID="$(cat "$SRV/s1/key_id")" \
    YADORILINK_INSTALL_BASE_URL="$BASE/s1" YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 YADORILINK_INSTALL_VERIFIER_BASE="$BASE/verifier" \
    YADORILINK_INSTALL_VERIFIER_SHA256="$VSHA" sh "$INSTALL" --prefix "$H/prefix" --yes > "$T/out" 2>&1; RC=$?
{ [ $RC = 0 ] && [ ! -e "$H/.bash_profile" ] && grep -q 'yadorilink (' "$H/.profile"; } && ok "bash users keep their existing login profile" || bad "bash profile" "$T/out"

# --- profile path with sed metacharacters is recorded and removed correctly
newhome 29; mkdir -p "$H/a&b|c"
env HOME="$H/a&b|c" SHELL=/bin/sh YADORILINK_INSTALL_TEST=1 YADORILINK_INSTALL_MIN_GENERATED_AT=2000-01-01T00:00:00Z YADORILINK_INSTALL_PUBKEY_HEX="$(pub s1)" YADORILINK_INSTALL_KEY_ID="$(cat "$SRV/s1/key_id")" \
    YADORILINK_INSTALL_BASE_URL="$BASE/s1" YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 YADORILINK_INSTALL_VERIFIER_BASE="$BASE/verifier" \
    YADORILINK_INSTALL_VERIFIER_SHA256="$VSHA" sh "$INSTALL" --prefix "$H/prefix" --yes > "$T/out" 2>&1
env HOME="$H/a&b|c" sh "$INSTALL" --prefix "$H/prefix" --yes --uninstall >> "$T/out" 2>&1; RC=$?
{ [ $RC = 0 ] && ! grep -q 'yadorilink (' "$H/a&b|c/.profile"; } && ok "profile path with & and | round-trips" || bad "profile path metacharacters" "$T/out"

# --- same version on another channel is installed, not skipped
newhome 30; fx n1 --channel nightly --version 0.2.0
inst s1 s1; inst n1 n1 --channel nightly
{ [ $RC = 0 ] && has "Installed YadoriLink 0.2.0 (nightly" && grep -q '^channel=nightly$' "$H/prefix/share/yadorilink/install-receipt"; } && ok "channel switch at equal version installs" || bad "channel switch" "$T/out"

# --- two prefixes sharing one profile each keep their own PATH block
newhome 31
inst s1 s1 --prefix "$H/prefix"; 
env HOME="$H" SHELL=/bin/sh YADORILINK_INSTALL_TEST=1 YADORILINK_INSTALL_MIN_GENERATED_AT=2000-01-01T00:00:00Z YADORILINK_INSTALL_PUBKEY_HEX="$(pub s1)" YADORILINK_INSTALL_KEY_ID="$(cat "$SRV/s1/key_id")" \
    YADORILINK_INSTALL_BASE_URL="$BASE/s1" YADORILINK_INSTALL_OS=Linux YADORILINK_INSTALL_ARCH=x86_64 YADORILINK_INSTALL_VERIFIER_BASE="$BASE/verifier" \
    YADORILINK_INSTALL_VERIFIER_SHA256="$VSHA" sh "$INSTALL" --prefix "$H/second prefix" --yes > "$T/out" 2>&1
env HOME="$H" sh "$INSTALL" --prefix "$H/second prefix" --yes --uninstall >> "$T/out" 2>&1; RC=$?
{ [ $RC = 0 ] && [ "$(grep -c '>>> yadorilink' "$H/.profile")" = 1 ] && grep -q "$H/prefix" "$H/.profile"; } && ok "prefixes keep separate PATH blocks (and spaces in prefix work)" || bad "per-prefix PATH blocks" "$T/out"

# --- re-running without --no-modify-path adds PATH even when up to date
newhome 32
inst s1 s1 --no-modify-path; inst s1 s1
{ [ $RC = 0 ] && has "already installed" && grep -q '>>> yadorilink' "$H/.profile"; } && ok "re-run applies PATH when version is current" || bad "re-run PATH" "$T/out"

# --- --no-modify-path, --help
newhome 21
inst s1 s1 --no-modify-path
{ [ $RC = 0 ] && [ ! -e "$H/.profile" ] && has "is not on your PATH"; } && ok "--no-modify-path" || bad "--no-modify-path" "$T/out"
sh "$INSTALL" --help > "$T/out" 2>&1; { has "Options:" && has "--prefix"; } && ok "--help" || bad "--help" "$T/out"


# --- exit codes (2 usage, 3 network, 4 signature/hash/withdrawal, 5 platform, 6 downgrade, 7 prefix)
code_is() { [ "$RC" = "$1" ]; }
newhome 40; fx x1
sh "$INSTALL" --bogus > "$T/out" 2>&1; RC=$?
{ code_is 2 && has "unknown option"; } && ok "exit 2: unknown option" || bad "exit 2 usage" "$T/out"
inst x1 x1 --channel stable
{ code_is 2 && nothing_installed; } && ok "exit 2: unknown channel" || bad "exit 2 channel" "$T/out"
BASEURL_OVERRIDE=http://127.0.0.1:1; inst x1 x1; unset BASEURL_OVERRIDE
{ code_is 3 && nothing_installed; } && ok "exit 3: network failure" || bad "exit 3 network" "$T/out"
TOS=FreeBSD; inst x1 x1; unset TOS
{ code_is 5 && nothing_installed; } && ok "exit 5: unsupported platform" || bad "exit 5 platform" "$T/out"
inst x1 x1 --force; inst x1 x1 --prefix "$H/prefix"
fx x0 --version 0.1.0
inst x0 x0
{ code_is 6 && has "not downgrading"; } && ok "exit 6: downgrade refused" || bad "exit 6 downgrade" "$T/out"
newhome 41; fx x2; mkdir -p "$H/prefix"; chmod 555 "$H/prefix"
if [ "$(id -u)" != 0 ]; then inst x2 x2; { code_is 7; } && ok "exit 7: prefix not writable" || bad "exit 7 prefix" "$T/out"; fi
chmod 755 "$H/prefix"
newhome 42; fx x3
python3 - "$SRV/x3/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 1; open(p, "wb").write(b)
PY
inst x3 x3; { code_is 4 && nothing_installed; } && ok "exit 4: hash mismatch" || bad "exit 4 hash" "$T/out"
newhome 43; fx x4 --kill-switch; inst x4 x4
{ code_is 4 && has "withdrawn" && nothing_installed; } && ok "exit 4: kill switch" || bad "exit 4 kill" "$T/out"

# --- replay floor pinned in the installer
newhome 44; fx rf --generated-at 2026-10-18T00:00:00Z
MINGEN=2026-10-19T00:00:00Z; inst rf rf; unset MINGEN
{ code_is 4 && has "oldest this installer accepts" && nothing_installed; } && ok "manifest older than the pinned floor refused" || bad "replay floor" "$T/out"
newhome 45
MINGEN=2026-10-18T00:00:00Z; inst rf rf; unset MINGEN
{ code_is 0 && version_is 0.2.0; } && ok "manifest at the pinned floor accepted" || bad "floor equal" "$T/out"
newhome 46
MINGEN=2026-01-01T00:00:00Z; inst rf rf; unset MINGEN
{ code_is 0; } && ok "manifest newer than the pinned floor accepted" || bad "floor newer" "$T/out"

# --- manifest expiry: the live manifest is refused after its expires_at, never before
fx ex --generated-at 2026-10-01T00:00:00Z --expires-at 2026-10-02T00:00:00Z
newhome 48; inst ex ex
{ code_is 4 && has "expired at 2026-10-02T00:00:00Z" && has "clock" && nothing_installed; } && ok "expired manifest refused (real clock)" || bad "expired" "$T/out"
newhome 49; NOW=2026-10-02T00:00:01Z; inst ex ex; unset NOW
{ code_is 4 && has "expired at" && nothing_installed; } && ok "manifest one second past expiry refused" || bad "expiry +1s" "$T/out"
newhome 50; NOW=2026-10-02T00:00:00Z; inst ex ex; unset NOW
{ code_is 0 && version_is 0.2.0; } && ok "manifest at its expiry second accepted" || bad "expiry boundary" "$T/out"
newhome 51; fx exneg --generated-at 2026-10-01T00:00:00Z --expires-at 2026-10-01T00:00:00Z; inst exneg exneg
{ code_is 4 && has "is not after generated_at" && nothing_installed; } && ok "expires_at not after generated_at refused" || bad "expiry order" "$T/out"
newhome 52; fx exgone --omit-expires; inst exgone exgone
{ code_is 4 && has "invalid expires_at" && nothing_installed; } && ok "manifest without expires_at refused" || bad "no expiry" "$T/out"

# --- snapshots published before expires_at existed stay usable: pinned and offline installs
fx lg --version 0.3.0 --extra-version 0.2.0 --legacy-snapshots
newhome 53; inst lg lg --version 0.2.0
{ code_is 0 && version_is 0.2.0; } && ok "pinned install from a legacy per-version manifest without expires_at" || bad "legacy pinned" "$T/out"
LGD=$T/lgfrom; rm -rf "$LGD"; mkdir -p "$LGD"
cp "$SRV/lg/0.2.0/manifest.json" "$LGD/manifest.json"
cp "$SRV/lg/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" "$LGD/"
cp "$SRV/verifier/yadorilink-verify-linux-x86_64" "$LGD/"
newhome 54; BASEURL_OVERRIDE=http://127.0.0.1:1; inst lg lg --from "$LGD/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 0 && version_is 0.2.0 && has "offline install"; } && ok "--from a legacy per-version manifest installs offline" || bad "legacy --from" "$T/out"

# --- version-pinned installs (the live channel manifest has the last word)
fx pv --version 0.3.0 --extra-version 0.2.0
newhome 47; inst pv pv --version 0.3.0
{ code_is 0 && version_is 0.3.0; } && ok "pin to the channel's current version" || bad "pin current" "$T/out"
newhome 48; inst pv pv --version 0.2.0
{ code_is 0 && version_is 0.2.0 && has "Installed YadoriLink 0.2.0"; } && ok "pin to an older published version installs from its signed per-version manifest" || bad "pin older" "$T/out"

fx pk --version 0.3.0 --extra-version 0.2.0 --kill-switch
newhome 49; inst pk pk --version 0.3.0
{ code_is 4 && has "withdrawn" && nothing_installed; } && ok "REGRESSION: pinned killed version refused (exit 4) though its snapshot verifies" || bad "pinned killed" "$T/out"
newhome 50; inst pk pk --version 0.2.0
{ code_is 0 && version_is 0.2.0; } && ok "a pin to another version is unaffected by the channel's kill switch" || bad "pin other than killed" "$T/out"

fx pw --version 0.3.0 --extra-version 0.2.0 --withdrawn 0.2.0
newhome 51; inst pw pw --version 0.2.0
{ code_is 4 && has "has been withdrawn" && nothing_installed; } && ok "REGRESSION: pinned yanked version refused (exit 4)" || bad "pinned yanked" "$T/out"

fx pm --version 0.3.0 --extra-version 0.2.0 --min-version 0.2.5
newhome 52; inst pm pm --version 0.2.0
{ code_is 4 && has "below the minimum supported version" && nothing_installed; } && ok "REGRESSION: pinned version below the minimum refused (exit 4)" || bad "pinned below minimum" "$T/out"

# live manifest unreachable or unverifiable fails closed for an online pinned install
mkdir -p "$SRV/pn"; cp -R "$SRV/pv/0.2.0" "$SRV/pn/0.2.0"; cp -R "$SRV/pv/files" "$SRV/pn/files"; cp "$SRV/pv/pubkey.hex" "$SRV/pv/key_id" "$SRV/pn/"
newhome 53; inst pn pv --version 0.2.0
{ [ $RC != 0 ] && nothing_installed; } && ok "pinned install with no live manifest fails closed" || bad "pinned, live missing" "$T/out"
fx pt --version 0.3.0 --extra-version 0.2.0
python3 - "$SRV/pt/beta/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["manifest_json"] = e["manifest_json"].replace("0.3.0", "0.3.1", 1); json.dump(e, open(p, "w"))
PY
newhome 54; inst pt pt --version 0.2.0
{ code_is 4 && has "does NOT verify" && nothing_installed; } && ok "pinned install with a tampered live manifest refused" || bad "pinned, live tampered" "$T/out"
fx ps --version 0.3.0 --extra-version 0.2.0
python3 - "$SRV/ps/0.2.0/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["manifest_json"] = e["manifest_json"].replace('"artifact_size"', '"artifact_size_x"', 1); json.dump(e, open(p, "w"))
PY
newhome 55; inst ps ps --version 0.2.0
{ code_is 4 && has "does NOT verify" && nothing_installed; } && ok "tampered per-version manifest refused" || bad "snapshot tampered" "$T/out"
# a per-version manifest that is signed but describes another version
fx pq --version 0.3.0 --extra-version 0.2.0
cp "$SRV/pq/0.3.0/manifest.json" "$SRV/pq/0.2.0/manifest.json"
newhome 56; inst pq pq --version 0.2.0
{ code_is 4 && has "describes version 0.3.0" && nothing_installed; } && ok "per-version manifest of another version refused" || bad "snapshot for another version" "$T/out"

# --- offline installs (--from)
FROMD=$T/from; rm -rf "$FROMD"; mkdir -p "$FROMD"
cp "$SRV/pv/0.2.0/manifest.json" "$FROMD/manifest.json"
cp "$SRV/pv/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" "$FROMD/"
cp "$SRV/verifier/yadorilink-verify-linux-x86_64" "$FROMD/"
newhome 57; BASEURL_OVERRIDE=http://127.0.0.1:1; inst pv pv --from "$FROMD/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 0 && version_is 0.2.0 && has "Withdrawal not checked" && has "offline install"; } && ok "--from installs offline and says withdrawal was not checked" || bad "--from offline" "$T/out"
newhome 58; inst pv pv --from "$FROMD/manifest.json"
{ code_is 0 && version_is 0.2.0 && has "does not withdraw 0.2.0"; } && ok "--from with a reachable live manifest that does not withdraw" || bad "--from live ok" "$T/out"
newhome 59; inst pw pv --from "$FROMD/manifest.json"
{ code_is 4 && has "has been withdrawn" && nothing_installed; } && ok "--from is refused when the live manifest withdraws the version" || bad "--from live withdraws" "$T/out"
newhome 60; BASEURL_OVERRIDE=http://127.0.0.1:1; inst pv pv --from "$FROMD/manifest.json" --version 0.9.9; unset BASEURL_OVERRIDE
{ code_is 4 && has "is for version 0.2.0" && nothing_installed; } && ok "--from with a different --version refused" || bad "--from version mismatch" "$T/out"
rm -f "$FROMD/yadorilink-verify-linux-x86_64"
newhome 61; BASEURL_OVERRIDE=http://127.0.0.1:1; inst pv pv --from "$FROMD/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 2 && has "verifier program" && nothing_installed; } && ok "--from needs the pinned verifier next to the manifest" || bad "--from no verifier" "$T/out"
cp "$SRV/verifier/yadorilink-verify-linux-x86_64" "$FROMD/"; rm -f "$FROMD/yadorilink-engine-beta-linux-x86_64.zip"
newhome 62; BASEURL_OVERRIDE=http://127.0.0.1:1; inst pv pv --from "$FROMD/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 2 && has "needs the engine bundle" && nothing_installed; } && ok "--from needs the engine bundle next to the manifest" || bad "--from no zip" "$T/out"
cp "$SRV/pv/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" "$FROMD/"; printf 'x' >> "$FROMD/yadorilink-engine-beta-linux-x86_64.zip"
newhome 63; BASEURL_OVERRIDE=http://127.0.0.1:1; inst pv pv --from "$FROMD/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 4 && nothing_installed; } && ok "--from with a changed bundle refused" || bad "--from tampered zip" "$T/out"
cp "$SRV/pv/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" "$FROMD/"
python3 - "$FROMD/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; e = json.load(open(p)); e["manifest_json"] = e["manifest_json"].replace('"rollout_percentage": 100', '"rollout_percentage":  99', 1); json.dump(e, open(p, "w"))
PY
newhome 64; BASEURL_OVERRIDE=http://127.0.0.1:1; inst pv pv --from "$FROMD/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 4 && nothing_installed; } && ok "--from with a tampered manifest refused" || bad "--from tampered manifest" "$T/out"

# --- --from applies the supplied manifest's own withdrawn_versions (live endpoint unreachable)
fx fw --version 0.2.0 --withdrawn 0.2.0
FROMW=$T/fromw; rm -rf "$FROMW"; mkdir -p "$FROMW"
cp "$SRV/fw/beta/manifest.json" "$FROMW/manifest.json"
cp "$SRV/fw/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" "$FROMW/"
cp "$SRV/verifier/yadorilink-verify-linux-x86_64" "$FROMW/"
newhome 70; BASEURL_OVERRIDE=http://127.0.0.1:1; inst fw fw --from "$FROMW/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 4 && has "has been withdrawn" && nothing_installed; } && ok "--from refuses a version its own manifest withdraws" || bad "--from own withdrawn" "$T/out"
# negative control: the same bundle without the withdrawal installs
fx fn --version 0.2.0
FROMN=$T/fromn; rm -rf "$FROMN"; mkdir -p "$FROMN"
cp "$SRV/fn/beta/manifest.json" "$FROMN/manifest.json"
cp "$SRV/fn/files/0.2.0/yadorilink-engine-beta-linux-x86_64.zip" "$FROMN/"
cp "$SRV/verifier/yadorilink-verify-linux-x86_64" "$FROMN/"
newhome 71; BASEURL_OVERRIDE=http://127.0.0.1:1; inst fn fn --from "$FROMN/manifest.json"; unset BASEURL_OVERRIDE
{ code_is 0 && version_is 0.2.0; } && ok "--from without a withdrawal still installs (control)" || bad "--from control" "$T/out"

# --- the daemon-readable script marker (install_source.rs) sits beside the real binaries
newhome 72; inst s1 s1
dd=$(dirname "$(readlink "$H/prefix/bin/yadorilink-daemon")")
{ code_is 0 && python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("source")=="script" else 1)' "$dd/install-receipt.json"; } &&
    ok "install writes install-receipt.json beside the daemon" || bad "daemon-readable receipt" "$T/out"
inst s1 s1 --uninstall
{ code_is 0 && [ ! -e "$dd/install-receipt.json" ]; } && ok "uninstall removes the marker with the version tree" || bad "marker removed" "$T/out"

# --- pruning touches only what the receipt recorded; a failed receipt write rolls back
newhome 70; fx p1 --version 0.2.0; fx p2 --version 0.3.0; fx p3 --version 0.4.0; fx p4 --version 0.5.0
inst p1 p1
SH=$H/prefix/share/yadorilink
mkdir -p "$SH/versions/foreign-data" && echo keep > "$SH/versions/foreign-data/file"
inst p2 p1; inst p3 p1; inst p4 p1
{ [ $RC = 0 ] && version_is 0.5.0 && [ "$(cat "$SH/versions/foreign-data/file" 2>/dev/null)" = keep ] && [ "$(ls "$SH/versions" | wc -l | tr -d ' ')" = 3 ]; } && ok "unmanaged directory under versions/ is left alone; only the recorded old version is pruned" || bad "prune ownership" "$T/out"
newhome 71; fx r1 --version 0.2.0; fx r2 --version 0.3.0
inst r1 r1
SH=$H/prefix/share/yadorilink
cp "$SH/install-receipt" "$T/receipt.before"; ls -l "$H/prefix/bin" | sed 's/.* yadorilink/yadorilink/' > "$T/links.before"
YADORILINK_INSTALL_FAIL_RECEIPT=1 inst r2 r1
ls -l "$H/prefix/bin" | sed 's/.* yadorilink/yadorilink/' > "$T/links.after"
{ [ $RC != 0 ] && has "could not write the install receipt" && ! has "Installed YadoriLink" && version_is 0.2.0 \
    && cmp -s "$SH/install-receipt" "$T/receipt.before" && cmp -s "$T/links.before" "$T/links.after" \
    && [ "$(ls "$SH/versions" | wc -l | tr -d ' ')" = 1 ]; } && ok "receipt write failure fails closed and restores links, receipt and versions" || bad "receipt failure rollback" "$T/out"

# --- ownership: the app, another installation or an unreadable record stops the install (exit 19)
newhome 72; fx o1 --version 0.2.0
owner_record() { mkdir -p "$H/cfg"; printf '{\n  "owner": "%s",\n  "install_source": "%s",\n  "install_root": "/x",\n  "release_id": "",\n  "written_at": 1\n}\n' "$1" "$2" > "$H/cfg/install-owner.json"; }
for pair in gui:app_bundle gui:microsoft_store cli:apt cli:homebrew cli:standalone; do
    newhome 73; owner_record "${pair%%:*}" "${pair#*:}"
    YADORILINK_INSTALL_FAIL_RECEIPT=0 YADORILINK_CONFIG_DIR=$H/cfg inst o1 o1
    { [ $RC = 19 ] && has "Nothing was installed" && nothing_installed; } && ok "owner ${pair} refused with 19" || bad "owner $pair" "$T/out"
done
newhome 74; mkdir -p "$H/cfg"; echo 'not json' > "$H/cfg/install-owner.json"
YADORILINK_INSTALL_FAIL_RECEIPT=0 YADORILINK_CONFIG_DIR=$H/cfg inst o1 o1
{ [ $RC = 19 ] && has "cannot be read" && nothing_installed; } && ok "unreadable ownership record refused with 19" || bad "unreadable record" "$T/out"
newhome 75; owner_record cli script
YADORILINK_INSTALL_FAIL_RECEIPT=0 YADORILINK_CONFIG_DIR=$H/cfg inst o1 o1
{ [ $RC = 0 ] && version_is 0.2.0; } && ok "script-owned data installs" || bad "script owner" "$T/out"
newhome 76
YADORILINK_INSTALL_FAIL_RECEIPT=0 YADORILINK_CONFIG_DIR=$H/cfg inst o1 o1
{ [ $RC = 0 ] && version_is 0.2.0; } && ok "no ownership record installs" || bad "no record" "$T/out"

# --- cross-check: the fixture signer (RFC 8032 reference) agrees with OpenSSL 3
if [ -n "$OPENSSL3" ]; then
    python3 - "$SRV/s1/beta/manifest.json" "$SRV/s1/pubkey.hex" "$T" "$OPENSSL3" <<'PY' && ok "fixture signature verifies under OpenSSL 3" || bad "fixture signature under OpenSSL 3"
import base64, json, subprocess, sys
env = json.load(open(sys.argv[1])); t = sys.argv[3]
open(t + "/m", "w").write(env["manifest_json"]); open(t + "/s", "wb").write(base64.b64decode(env["signature_base64"]))
open(t + "/k.der", "wb").write(bytes.fromhex("302a300506032b6570032100" + open(sys.argv[2]).read().strip()))
sys.exit(subprocess.call([sys.argv[4], "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", t + "/k.der", "-rawin", "-in", t + "/m", "-sigfile", t + "/s"], stdout=subprocess.DEVNULL))
PY
fi

echo
echo "passed: $pass, failed: $failn"
[ "$failn" = 0 ]
