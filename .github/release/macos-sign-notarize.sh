#!/usr/bin/env bash
# Sign Mach-O executables with a Developer ID Application certificate (hardened runtime, secure
# timestamp) and notarize them with notarytool, on a macOS runner.
#
#   macos-sign-notarize.sh FILE=IDENTIFIER [FILE=IDENTIFIER ...]
#
# Each FILE is signed in place under the given code-signing identifier. The files are then
# submitted to the notary service as one archive and the script fails unless the service
# answers Accepted. Bare executables cannot carry a stapled ticket; the service records the
# notarization and Gatekeeper looks it up online.
#
# Credentials come from the environment, set on the one workflow step that calls this script:
#   MACOS_DEVELOPER_ID_APP_P12_BASE64, MACOS_DEVELOPER_ID_APP_P12_PASSWORD,
#   MACOS_NOTARY_ISSUER_ID, MACOS_NOTARY_KEY_ID, MACOS_NOTARY_KEY_P8_BASE64
# The certificate goes into a temporary keychain with a random password, the API key into a
# 0600 file in a temporary directory only the runner user can read; both are removed on every exit path. No secret is
# echoed, traced or written anywhere else, and the shell never runs with tracing enabled.
set -euo pipefail
umask 077

[ "$#" -ge 1 ] || { echo "usage: $0 FILE=IDENTIFIER ..." >&2; exit 2; }
for v in MACOS_DEVELOPER_ID_APP_P12_BASE64 MACOS_DEVELOPER_ID_APP_P12_PASSWORD \
         MACOS_NOTARY_ISSUER_ID MACOS_NOTARY_KEY_ID MACOS_NOTARY_KEY_P8_BASE64; do
  [ -n "${!v:-}" ] || { echo "error: $v is not set" >&2; exit 1; }
done

files=() ids=()
for arg in "$@"; do
  f="${arg%%=*}" id="${arg#*=}"
  [ "$f" != "$arg" ] && [ -f "$f" ] && [[ "$id" =~ ^[A-Za-z0-9.-]+$ ]] \
    || { echo "error: bad argument (want FILE=IDENTIFIER with an existing FILE): $arg" >&2; exit 2; }
  files+=("$f") ids+=("$id")
done

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/macos-sign.XXXXXX")"
keychain="$work/signing.keychain-db"
original_keychains="$(security list-keychains -d user | tr -d '"' | sed 's/^ *//')"

cleanup() {
  set +e
  security delete-keychain "$keychain" >/dev/null 2>&1
  if [ -n "$original_keychains" ]; then
    restore=()
    while IFS= read -r line; do [ -n "$line" ] && restore+=("$line"); done <<<"$original_keychains"
    security list-keychains -d user -s "${restore[@]}" >/dev/null 2>&1
  fi
  rm -rf "$work"
}
trap cleanup EXIT

keychain_password="$(openssl rand -base64 32)"
echo "::add-mask::$keychain_password"

printf '%s' "$MACOS_DEVELOPER_ID_APP_P12_BASE64" | base64 --decode > "$work/cert.p12"
security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security import "$work/cert.p12" -k "$keychain" -P "$MACOS_DEVELOPER_ID_APP_P12_PASSWORD" \
  -T /usr/bin/codesign -T /usr/bin/security >/dev/null
rm -f "$work/cert.p12"
security set-key-partition-list -S apple-tool:,apple: -s -k "$keychain_password" "$keychain" >/dev/null
existing=()
while IFS= read -r line; do [ -n "$line" ] && existing+=("$line"); done <<<"$original_keychains"
security list-keychains -d user -s "$keychain" ${existing[@]+"${existing[@]}"}

# Exactly one Developer ID Application identity must be usable; it is addressed by hash.
identity="$(security find-identity -v -p codesigning "$keychain" | awk '/Developer ID Application/ {print $2}')"
[ "$(printf '%s\n' "$identity" | grep -c .)" -eq 1 ] \
  || { echo "error: the keychain must hold exactly one Developer ID Application identity" >&2; exit 1; }

for i in "${!files[@]}"; do
  codesign --force --options runtime --timestamp --keychain "$keychain" \
    --identifier "${ids[$i]}" --sign "$identity" "${files[$i]}"
  codesign --verify --strict --verbose=2 "${files[$i]}"
  details="$(codesign -d --verbose=4 "${files[$i]}" 2>&1)"
  grep -q 'flags=.*runtime' <<<"$details" || { echo "error: ${files[$i]} lacks the hardened runtime" >&2; exit 1; }
  grep -q '^Authority=Developer ID Application' <<<"$details" || { echo "error: ${files[$i]} is not Developer ID signed" >&2; exit 1; }
  grep -q '^Timestamp=' <<<"$details" || { echo "error: ${files[$i]} has no secure timestamp" >&2; exit 1; }
  grep -q "^Identifier=${ids[$i]}\$" <<<"$details" || { echo "error: ${files[$i]} has the wrong identifier" >&2; exit 1; }
done

printf '%s' "$MACOS_NOTARY_KEY_P8_BASE64" | base64 --decode > "$work/notary-key.p8"
chmod 600 "$work/notary-key.p8"

mkdir "$work/submit"
for f in "${files[@]}"; do cp "$f" "$work/submit/"; done
ditto -c -k --sequesterRsrc "$work/submit" "$work/submit.zip"

auth=(--key "$work/notary-key.p8" --key-id "$MACOS_NOTARY_KEY_ID" --issuer "$MACOS_NOTARY_ISSUER_ID")
xcrun notarytool submit "$work/submit.zip" "${auth[@]}" --wait --timeout 40m --output-format json > "$work/result.json"
submission_id="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("id",""))' "$work/result.json")"
status="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("status",""))' "$work/result.json")"
echo "notarization submission id: $submission_id"
if [ "$status" != "Accepted" ]; then
  echo "error: notarization status is '$status', not Accepted" >&2
  # Apple's issue report for this submission; it holds no credentials.
  xcrun notarytool log "$submission_id" "${auth[@]}" >&2 || true
  exit 1
fi
echo "notarization accepted"
