#!/usr/bin/env bash
#
# .github/release/build-channel-manifest.sh
#
# Assemble the per-channel artifacts spec from the flattened release assets and
# drive .github/release/generate-update-manifest.py to produce the signed manifest
# envelope. Shared by the nightly and beta release jobs so both channels use
# one manifest-production path (a single code path for manifest
# production).
#
# The manifest drives update notifications only (v1 ships manual updates; the
# daemon never downloads or installs). The artifacts it points at are the
# installers placed in --dist (today the macOS .pkg). Linux is checksum-only and is
# not listed.
#
# Requires MANIFEST_SIGNING_KEY in the environment (the caller gates on it).
#
# No workflow calls this script: manifests are signed only by sign-manifest.yml. It stays as the
# fixture the daemon's release_manifest_chain integration test drives with a throwaway key.

set -euo pipefail

CHANNEL="" VERSION="" MIN_VERSION="" NOTES_URL="" DIST="" BASE_URL="" OUT="" ROLLOUT="100"
SIGN_TOOL="${YADORILINK_SIGN_MANIFEST:-target/release/yadorilink-sign-manifest}"

while [ $# -gt 0 ]; do
  case "$1" in
    --channel) CHANNEL="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --min-version) MIN_VERSION="$2"; shift 2 ;;
    --notes-url) NOTES_URL="$2"; shift 2 ;;
    --dist) DIST="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --rollout) ROLLOUT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

for req in CHANNEL VERSION MIN_VERSION DIST BASE_URL OUT; do
  if [ -z "${!req}" ]; then echo "missing --${req,,}" >&2; exit 2; fi
done

sha_of() {
  # Read the lowercase hex digest from the repo's `<file>.sha256` sidecar
  # (format: "<hex> <name>").
  local sidecar="$1"
  awk '{print $1; exit}' "$sidecar"
}

# Build the artifacts array from whichever signed install targets are present.
artifacts_json="$(mktemp)"
{
  echo "["
  first=1
  emit() { # platform arch filename
    local platform="$1" arch="$2" file="$3"
    local path="$DIST/$file"
    [ -f "$path" ] || return 0
    [ -f "$path.sha256" ] || { echo "missing checksum sidecar for $file" >&2; exit 1; }
    local sha; sha="$(sha_of "$path.sha256")"
    # Byte count of the published file; the client requires it.
    local size; size="$(wc -c < "$path" | tr -d '[:space:]')"
    [ "$first" -eq 1 ] || echo ","
    first=0
    printf '  {"platform":"%s","arch":"%s","install_source":"standalone","artifact_url":"%s","artifact_sha256":"%s","artifact_size":%s,"artifact_publisher_identity":""}' \
      "$platform" "$arch" "${BASE_URL}/${file}" "$sha" "$size"
  }
  emit macos   aarch64 yadorilink-macos.pkg
  echo ""
  echo "]"
} > "$artifacts_json"

# Fail loudly if no install target was found — an empty manifest is useless.
if ! grep -q '"platform"' "$artifacts_json"; then
  echo "no signed install artifacts found in $DIST (expected yadorilink-macos.pkg)" >&2
  exit 1
fi

python3 .github/release/generate-update-manifest.py generate \
  --channel "$CHANNEL" \
  --version "$VERSION" \
  --min-version "$MIN_VERSION" \
  --rollout-percentage "$ROLLOUT" \
  --release-notes-url "$NOTES_URL" \
  --artifacts "$artifacts_json" \
  --sign-tool "$SIGN_TOOL" \
  --require-signature \
  --out "$OUT"

rm -f "$artifacts_json"
echo "built signed $CHANNEL manifest -> $OUT"
