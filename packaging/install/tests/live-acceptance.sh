#!/bin/sh
# Acceptance of a PUBLISHED release on a clean machine: the one-liner as a user runs it, against
# the real manifest and the real release, in a temporary prefix and data directory.
#
#   sh packaging/install/tests/live-acceptance.sh [--installer-url URL] [--version X.Y.Z] [--older-version X.Y.Z]
#
# Defaults to https://yadori.link/install.sh. Needs only what a user has (curl, unzip, a POSIX
# shell) for the install itself; sqlite3 (else python3) is used afterwards, only to craft test databases. The
# prefix and the data directory live under one temporary directory that is removed at the end;
# nothing outside it is touched. The data checks need a release whose daemon has
# `--check-data-compat`; an older release is reported as skipped, not as a failure.
#
# Prints `ok`/`FAIL`/`skip` lines and `passed: N, failed: M, skipped: K` like the other scripts.
set -u
URL=https://yadori.link/install.sh
VERSION=""
OLDER=0.1.0-beta.8
while [ $# -gt 0 ]; do
    case $1 in
        --installer-url) URL=$2; shift 2 ;;
        --version) VERSION=$2; shift 2 ;;
        --older-version) OLDER=$2; shift 2 ;;
        *) echo "usage: live-acceptance.sh [--installer-url URL] [--version X.Y.Z] [--older-version X.Y.Z]" >&2; exit 2 ;;
    esac
done

T=$(mktemp -d "${TMPDIR:-/tmp}/yl-live.XXXXXX")
trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
trap 'exit 130' INT TERM
H=$T/home; P=$T/prefix; CFG=$T/cfg
mkdir -p "$H"
pass=0; failn=0; skipn=0
ok() { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad() { failn=$((failn + 1)); printf 'FAIL %s\n' "$1"; [ -z "${2:-}" ] || sed 's/^/     | /' "$2"; }
skip() { skipn=$((skipn + 1)); printf 'skip %s\n' "$1"; }
env_run() { env HOME="$H" YADORILINK_CONFIG_DIR="$CFG" "$@"; }

echo "host: $(uname -s) $(uname -m)   installer: $URL"
curl -fsSL "$URL" -o "$T/install.sh" || { echo "FAIL could not download $URL"; exit 1; }

# 1 the one-liner (here from a file so the output can be inspected; the body is the same bytes)
env_run sh "$T/install.sh" --prefix "$P" --yes ${VERSION:+--version "$VERSION"} --no-modify-path > "$T/out" 2>&1
RC=$?
if [ $RC = 0 ] && grep -q "Manifest signature verified" "$T/out"; then ok "install.sh installs; the manifest signature verifies"; else bad "install" "$T/out"; exit 1; fi
VER=$("$P/bin/yadorilink" --version 2>"$T/err" | head -1)
case $VER in yadorilink*) ok "yadorilink --version: $VER" ;; *) bad "version: $VER" ;; esac
# Nothing on stderr: a binary built against a newer glibc than the machine's prints a loader
# warning on every command (weak symbol not found) even though it runs.
[ ! -s "$T/err" ] && ok "yadorilink --version prints nothing on stderr" || bad "yadorilink --version wrote to stderr" "$T/err"
"$P/bin/yadorilink-daemon" --version >/dev/null 2>"$T/err" && [ ! -s "$T/err" ] && ok "yadorilink-daemon --version runs and prints nothing on stderr" || bad "daemon --version" "$T/err"
grep -q '^install_source=script$' "$P/share/yadorilink/install-receipt" 2>/dev/null && ok "receipt records install_source=script" || bad "receipt"

# The programs came through curl, which sets no quarantine flag, so Gatekeeper has nothing to assess.
if [ "$(uname -s)" = Darwin ]; then
    q=""
    for f in "$P"/bin/yadorilink "$P"/bin/yadorilink-daemon "$P"/share/yadorilink/versions/*/yadorilink; do
        [ -e "$f" ] || continue
        xattr -l "$f" 2>/dev/null | grep -q 'com.apple.quarantine' && q="$q $f"
    done
    [ -z "$q" ] && ok "no quarantine flag on the installed programs (Gatekeeper has nothing to assess)" || bad "quarantine flag on:$q"
fi
# The kept installer (what `yadorilink self-update` runs): present, and the receipt records its hash.
RCPT=$P/share/yadorilink/install-receipt
KEPT=$P/share/yadorilink/installer/install.sh
want=$(sed -n 's/^installer_sha256=//p' "$RCPT" 2>/dev/null)
if [ -z "$want" ]; then bad "receipt records installer_sha256"
elif [ ! -f "$KEPT" ]; then bad "the kept installer exists at $KEPT"
else
    if command -v shasum >/dev/null 2>&1; then have=$(shasum -a 256 "$KEPT" | cut -d' ' -f1); else have=$(sha256sum "$KEPT" | cut -d' ' -f1); fi
    [ "$have" = "$want" ] && ok "the kept installer exists and its SHA-256 equals the receipt's installer_sha256" || bad "kept installer hash $have, receipt $want"
fi

# 2 re-running is a no-op
env_run sh "$T/install.sh" --prefix "$P" --yes --no-modify-path > "$T/out" 2>&1
[ $? = 0 ] && ok "re-running the installer succeeds" || bad "re-run" "$T/out"
grep -q "already installed and up to date" "$T/out" && ok "re-running says the install is already current" || bad "re-run did not say the install is already current" "$T/out"

# 2b a pinned older version is refused (exit 6) and nothing changes
inst_tree() { (cd "$P" && find . -type f -exec cksum {} + | sort | cksum); }
installed_version=$(sed -n 's/^version=//p' "$RCPT" 2>/dev/null)
if [ -z "$installed_version" ] || [ "$installed_version" = "$OLDER" ]; then
    skip "no older version to pin ($OLDER is not older than the installed '$installed_version'); pass --older-version"
else
    before=$(inst_tree)
    env_run sh "$T/install.sh" --prefix "$P" --yes --no-modify-path --version "$OLDER" > "$T/out" 2>&1; rc=$?
    { [ $rc = 6 ] && [ "$before" = "$(inst_tree)" ]; } && ok "a pinned older version ($OLDER) is refused with exit 6 and nothing changes" || bad "pinned older version $OLDER (exit $rc)" "$T/out"
fi
# self-update has nothing to do: the install is the channel's current one. It asks the daemon, so a
# daemon runs for this one row, with a state directory of its own (the data cases below need $CFG
# empty), no dashboard port, and the file credential store.
SU=$T/su
mkdir -p "$SU"
su_env() { env HOME="$H" YADORILINK_CONFIG_DIR="$SU" YADORILINK_CONTROL_SOCKET="$SU/ctl.sock" YADORILINK_HTTP_API_DISABLE=1 YADORILINK_CREDENTIAL_STORE=file "$@"; }
su_env "$P/bin/yadorilink" daemon start > "$T/su-start.out" 2>&1 < /dev/null
n=0; until su_env "$P/bin/yadorilink" links > /dev/null 2>&1 || [ $n -ge 30 ]; do sleep 1; n=$((n + 1)); done
su_env "$P/bin/yadorilink" self-update > "$T/out" 2>&1; rc=$?
su_env "$P/bin/yadorilink" daemon stop > /dev/null 2>&1
{ [ $rc = 0 ] && grep -qi "up to date" "$T/out"; } && ok "yadorilink self-update reports up to date" || bad "self-update (exit $rc)" "$T/out"

# 2c the PATH block: added to the shell profile on a normal install, removed by the uninstall
H2=$T/home2; P2=$T/prefix2
mkdir -p "$H2"
env HOME="$H2" SHELL=/bin/sh YADORILINK_CONFIG_DIR="$T/cfg2" sh "$T/install.sh" --prefix "$P2" --yes > "$T/out" 2>&1; rc=$?
if [ $rc = 0 ] && grep -qF "# >>> yadorilink ($P2) >>>" "$H2/.profile" 2>/dev/null && grep -qF "$P2/bin" "$H2/.profile"; then ok "the installer adds a PATH block to the shell profile"
else bad "PATH block (exit $rc)" "$T/out"; fi
env HOME="$H2" YADORILINK_CONFIG_DIR="$T/cfg2" "$P2/bin/yadorilink" uninstall --yes > "$T/out" 2>&1; rc=$?
{ [ $rc = 0 ] && ! grep -qF "yadorilink ($P2)" "$H2/.profile" 2>/dev/null; } && ok "uninstall removes the PATH block" || bad "uninstall left the PATH block (exit $rc)" "$T/out"

# 3 the data check of the installed daemon (--check-data-compat), on databases made for the purpose
DAEMON=$P/bin/yadorilink-daemon
env_run "$DAEMON" --check-data-compat >/dev/null 2>&1
rc=$?
if [ $rc = 2 ]; then
    skip "this release's daemon has no --check-data-compat (it predates the data check): 4 data cases"
elif ! command -v sqlite3 >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    skip "neither sqlite3 nor python3 is installed here, so the test databases cannot be made: 4 data cases"
else
    [ $rc = 0 ] && ok "no data: --check-data-compat exits 0 and creates no database" || bad "no data (exit $rc)"
    [ ! -e "$CFG/sync-state.sqlite3" ] && ok "the check created no database file" || bad "database created"
    # sqlite3 first: it is part of macOS, while a bare python3 on a clean Mac is a stub that opens
    # the developer-tools installer dialog.
    mkdb() {
        mkdir -p "$CFG"
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$CFG/sync-state.sqlite3" "pragma journal_mode=wal; create table if not exists files(id integer primary key); pragma user_version=$1;" >/dev/null
        else
            python3 - "$CFG/sync-state.sqlite3" "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1]); c.execute("pragma journal_mode=wal"); c.execute("create table if not exists files(id integer primary key)")
c.execute("pragma user_version=%d" % int(sys.argv[2])); c.commit(); c.close()
PY
        fi
    }
    # this release's own stamp: read it from a database the daemon would have written is not
    # possible without running it, so the "same generation" case uses the version the daemon reports
    # through a pair of probes: 1 is always older than any release, 999999 always newer.
    mkdb 1
    env_run "$DAEMON" --check-data-compat > "$T/out" 2>&1; rc=$?
    { [ $rc = 0 ] && grep -qi "warning" "$T/out"; } && ok "older data: exit 0 with a warning" || { bad "older data (exit $rc)" "$T/out"; }
    mkdb 999999
    env_run "$DAEMON" --check-data-compat > "$T/out" 2>&1; rc=$?
    { [ $rc = 20 ] && grep -qi "downgrad" "$T/out"; } && ok "newer data: exit 20, the message says downgrading is not supported" || bad "newer data (exit $rc)" "$T/out"
    tree() { (cd "$P" && find . -type f -exec cksum {} + | sort | cksum); }
    before=$(tree)
    env_run sh "$T/install.sh" --prefix "$P" --yes --force --no-modify-path > "$T/out" 2>&1; rc=$?
    { [ $rc = 20 ] && [ "$before" = "$(tree)" ]; } && ok "the installer refuses over newer data (exit 20) and changes nothing" || bad "installer over newer data (exit $rc)" "$T/out"
    printf 'this is not a database, but it is long enough to look like a header....' > "$CFG/sync-state.sqlite3"
    rm -f "$CFG/sync-state.sqlite3-wal" "$CFG/sync-state.sqlite3-shm"
    env_run "$DAEMON" --check-data-compat > "$T/out" 2>&1; rc=$?
    { [ $rc = 21 ] && grep -q "start the daemon once and stop it cleanly" "$T/out"; } && ok "unreadable data: exit 21 with what to do" || bad "unreadable data (exit $rc)" "$T/out"
    rm -f "$CFG/sync-state.sqlite3"*
    if command -v sqlite3 >/dev/null 2>&1; then
        # Data as a stopped daemon leaves it: the database with its write-ahead log and shared memory
        # beside it. The check must exit 0 and leave all three files byte for byte as they were. A
        # connection is held open while the files are copied, so the copies keep their -wal and -shm.
        hold() { # hold DIR SQL: run SQL, then keep the connection open until the fifo closes
            rm -f "$T/hold.fifo"; mkfifo "$T/hold.fifo"
            sqlite3 "$1/sync-state.sqlite3" < "$T/hold.fifo" > /dev/null 2>&1 &
            HOLD_PID=$!
            exec 7> "$T/hold.fifo"
            printf '%s\n' "$2" >&7
            sleep 1
        }
        release() { exec 7>&-; wait "$HOLD_PID" 2>/dev/null; rm -f "$T/hold.fifo"; }
        HOLDDIR=$T/holddb; mkdir -p "$HOLDDIR" "$CFG"
        hold "$HOLDDIR" "pragma journal_mode=wal; pragma wal_autocheckpoint=0; create table if not exists files(id integer primary key); insert into files default values; pragma user_version=1;"
        cp -p "$HOLDDIR"/sync-state.sqlite3* "$CFG"/ 2>/dev/null
        release
        # The database and its write-ahead log. The -shm file is only an index of the log that SQLite
        # rebuilds whenever it opens the database with no other connection, so any reader rewrites it;
        # it holds no data and is left out of the byte comparison.
        files3() { (cd "$CFG" && cksum sync-state.sqlite3 sync-state.sqlite3-wal 2>/dev/null | cksum); }
        before=$(files3)
        if [ -e "$CFG/sync-state.sqlite3-wal" ] && [ -e "$CFG/sync-state.sqlite3-shm" ]; then
            env_run "$DAEMON" --check-data-compat > "$T/out" 2>&1; rc=$?
            if [ $rc = 0 ] && [ "$before" = "$(files3)" ]; then ok "data with -wal and -shm beside it: exit 0 and the database and its log are byte for byte unchanged"
            else bad "data with -wal and -shm beside it (exit $rc, files unchanged: $([ "$before" = "$(files3)" ] && echo yes || echo no))" "$T/out"; fi
        else skip "could not leave -wal and -shm beside the database on this host"; fi
        rm -f "$CFG"/sync-state.sqlite3*
        # A newer stamp that exists only in the write-ahead log, with another process holding the
        # database open: still read as newer (exit 20).
        rm -rf "$HOLDDIR"; mkdir -p "$HOLDDIR"
        hold "$HOLDDIR" "pragma journal_mode=wal; pragma wal_autocheckpoint=0; create table if not exists files(id integer primary key); pragma user_version=999999;"
        env HOME="$H" YADORILINK_CONFIG_DIR="$HOLDDIR" "$DAEMON" --check-data-compat > "$T/out2" 2>&1; rc2=$?
        release
        { [ $rc2 = 20 ] && grep -qi "downgrad" "$T/out2"; } && ok "a newer stamp only in the write-ahead log, another process holding the database: exit 20" || bad "stamp only in the log (exit $rc2)" "$T/out2"
    else
        skip "sqlite3 is not installed here: the -wal/-shm and stamp-in-the-log cases"
    fi
fi

# 4 uninstall keeps the user's data
mkdir -p "$CFG"; echo "device state" > "$CFG/keep-me.txt"
env_run "$P/bin/yadorilink" uninstall --yes > "$T/out" 2>&1
{ [ $? = 0 ] && [ ! -e "$P/bin/yadorilink" ] && [ "$(cat "$CFG/keep-me.txt")" = "device state" ]; } && ok "uninstall removes the programs and keeps the data directory" || bad "uninstall" "$T/out"

# 5 reinstalling over the kept data directory adopts it
env_run sh "$T/install.sh" --prefix "$P" --yes --no-modify-path ${VERSION:+--version "$VERSION"} > "$T/out" 2>&1
{ [ $? = 0 ] && [ -x "$P/bin/yadorilink" ] && [ "$(cat "$CFG/keep-me.txt")" = "device state" ]; } && ok "reinstalling after an uninstall works and the kept data directory is intact" || bad "reinstall after uninstall" "$T/out"

echo
echo "passed: $pass, failed: $failn, skipped: $skipn"
[ "$failn" = 0 ]
