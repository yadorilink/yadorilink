#!/bin/sh
# Tests install-yadorilink.sh with stand-ins for curl, gh and the installer: the installer runs only
# after the attestation verified, with the pinned arguments, and a failed check fails the script.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
mkdir "$t/bin"
cat > "$t/bin/curl" <<'STUB'
#!/bin/sh
# usage: curl -fsSL --retry 3 -o FILE URL
out=$5; url=$6
echo "$url" > "$FAKE_LOG.url"
printf '#!/bin/sh\necho "$@" > "$FAKE_LOG.args"\n' > "$out"
STUB
cat > "$t/bin/gh" <<'STUB'
#!/bin/sh
echo "gh $*" >> "$FAKE_LOG.gh"
[ "${FAKE_GH_FAIL:-0}" = 0 ]
STUB
chmod +x "$t/bin/curl" "$t/bin/gh"
export PATH="$t/bin:$PATH" FAKE_LOG="$t/log"

fail() { echo "FAIL: $*" >&2; exit 1; }

out=$(sh "$here/install-yadorilink.sh" 0.1.0-beta.9 /opt/yl beta 2>/dev/null) || fail "install failed"
[ "$out" = /opt/yl/bin ] || fail "bin dir: $out"
grep -q 'releases/download/v0.1.0-beta.9/install.sh$' "$t/log.url" || fail "url: $(cat "$t/log.url")"
grep -q -- '--repo yadorilink/yadorilink' "$t/log.gh" || fail "no attestation check"
[ "$(cat "$t/log.args")" = "--yes --no-modify-path --channel beta --version 0.1.0-beta.9 --prefix /opt/yl" ] \
    || fail "installer args: $(cat "$t/log.args")"

rm -f "$t/log.args"
FAKE_GH_FAIL=1 sh "$here/install-yadorilink.sh" 0.1.0-beta.9 /opt/yl >/dev/null 2>&1 && fail "bad attestation accepted"
[ ! -e "$t/log.args" ] || fail "the installer ran after a failed attestation"

sh "$here/install-yadorilink.sh" '1.0;rm' /opt/yl >/dev/null 2>&1 && fail "odd version accepted"
sh "$here/install-yadorilink.sh" 1.0.0 relative >/dev/null 2>&1 && fail "relative prefix accepted"
echo "install-yadorilink tests ok"
