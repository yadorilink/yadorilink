#!/usr/bin/env bash
#
# packaging/linux/apt/build-apt-repo.sh
#
# Assembles a flat APT repository tree (one `stable` suite, `main`
# component) from already-built `.deb` files and signs its Release
# metadata. Hand-authored rather than driven by `apt-ftparchive` (not
# installed on this project's CI runners, and this project already
# prefers a hand-authored control file over a generator tool for exactly
# this kind of small, auditable metadata — see
# packaging/linux/build-deb.sh's own header comment on that same choice).
#
# Produces, under $OUT_DIR:
#   pool/main/y/yadorilink/yadorilink_<version>_<arch>.deb   (one per input .deb)
#   dists/stable/main/binary-<arch>/Packages                 (one per arch present)
#   dists/stable/main/binary-<arch>/Packages.gz
#   dists/stable/Release
#   dists/stable/Release.gpg      (detached signature)
#   dists/stable/InRelease        (Release + inline signature, clearsigned)
#
# Usage:
#   packaging/linux/apt/build-apt-repo.sh --out-dir DIR --gpg-key-id KEYID deb1 [deb2 ...]
#
# Requires on PATH: dpkg-scanpackages (dpkg-dev), gzip, gpg. The signing
# key identified by --gpg-key-id must already be present in the calling
# GPG keyring (imported by the caller — see
# packaging/linux/apt/README.md's "Signing key custody" section for where
# that key comes from and why this script never generates one itself).

set -euo pipefail

OUT_DIR=""
GPG_KEY_ID=""
DEBS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --gpg-key-id) GPG_KEY_ID="$2"; shift 2 ;;
    --) shift; DEBS+=("$@"); break ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) DEBS+=("$1"); shift ;;
  esac
done

if [ -z "$OUT_DIR" ] || [ -z "$GPG_KEY_ID" ] || [ "${#DEBS[@]}" -eq 0 ]; then
  echo "usage: $0 --out-dir DIR --gpg-key-id KEYID deb1 [deb2 ...]" >&2
  exit 2
fi

log() { echo "[build-apt-repo] $*"; }

for d in "${DEBS[@]}"; do
  [ -f "$d" ] || { echo "not a file: $d" >&2; exit 1; }
done

POOL_DIR="$OUT_DIR/pool/main/y/yadorilink"
DIST_DIR="$OUT_DIR/dists/stable"
mkdir -p "$POOL_DIR"

# --- 1. Stage each.deb into the pool, one arch at a time ------------------
declare -A ARCHES_SEEN=()
for d in "${DEBS[@]}"; do
  base="$(basename "$d")"
  cp "$d" "$POOL_DIR/$base"
  # Debian package filenames are `<name>_<version>_<arch>.deb` by
  # convention (exactly what packaging/linux/build-deb.sh produces) --
  # this is the same shape `dpkg-deb --build` always emits, not a
  # yadorilink-specific one, so parsing it back out here is safe.
  arch="${base%.deb}"; arch="${arch##*_}"
  ARCHES_SEEN["$arch"]=1
done
log "staged ${#DEBS[@]} package(s) into $POOL_DIR: arches ${!ARCHES_SEEN[*]}"

# --- 2. Packages / Packages.gz, one per architecture -----------------------
for arch in "${!ARCHES_SEEN[@]}"; do
  bin_dir="$DIST_DIR/main/binary-$arch"
  mkdir -p "$bin_dir"
  # dpkg-scanpackages scans by filename pattern; run once per arch so
  # binary-amd64/Packages never lists an arm64 package and vice versa.
  (cd "$OUT_DIR" && dpkg-scanpackages --arch "$arch" pool /dev/null) > "$bin_dir/Packages"
  gzip -9 -n -k -f "$bin_dir/Packages"
  log "wrote $bin_dir/Packages(.gz)"
done

# --- 3. Release: hand-authored, apt's documented field set -----------------
# `Date` uses the RFC 2822 format `apt`'s own sources require (`date -R`,
# UTC) -- the same format packaging/linux/build-deb.sh's changelog uses
# for its own Debian-policy-required date field.
ARCH_LIST="$(printf '%s\n' "${!ARCHES_SEEN[@]}" | sort | tr '\n' ' ')"
ARCH_LIST="${ARCH_LIST% }"

hash_block() {
  # Emits one indented "<hash>  <size> <path>" line per Packages/Packages.gz
  # file, relative to $DIST_DIR — the shape apt requires under each of
  # MD5Sum/SHA1/SHA256 in a Release file. The section header itself
  # ("MD5Sum:"/"SHA1:"/"SHA256:") is echoed by the caller, not here.
  local cmd="$1"
  for arch in $(printf '%s\n' "${!ARCHES_SEEN[@]}" | sort); do
    for f in "main/binary-$arch/Packages" "main/binary-$arch/Packages.gz"; do
      local path="$DIST_DIR/$f"
      local size; size="$(stat -c%s "$path" 2>/dev/null || stat -f%z "$path")"
      local sum; sum="$($cmd "$path" | awk '{print $1}')"
      printf ' %s %16d %s\n' "$sum" "$size" "$f"
    done
  done
}

{
  echo "Origin: yadorilink"
  echo "Label: yadorilink"
  echo "Suite: stable"
  echo "Codename: stable"
  echo "Version: 1.0"
  echo "Architectures: $ARCH_LIST"
  echo "Components: main"
  echo "Description: APT repository for yadorilink (https://github.com/yadorilink/yadorilink)"
  echo "Date: $(date -Ru)"
  echo "MD5Sum:"
  hash_block "md5sum"
  echo "SHA1:"
  hash_block "sha1sum"
  echo "SHA256:"
  hash_block "sha256sum"
} > "$DIST_DIR/Release"
log "wrote $DIST_DIR/Release"

# --- 4. Sign: both InRelease (inline) and Release.gpg (detached) -----------
# apt accepts either; shipping both covers every client's `Signed-By`
# configuration without needing to know in advance which one a given
# client checks. `--pinentry-mode loopback --batch` so this never blocks
# on an interactive prompt in CI.
gpg --batch --pinentry-mode loopback --default-key "$GPG_KEY_ID" \
  --clearsign -o "$DIST_DIR/InRelease" "$DIST_DIR/Release"
gpg --batch --pinentry-mode loopback --default-key "$GPG_KEY_ID" \
  --armor --detach-sign -o "$DIST_DIR/Release.gpg" "$DIST_DIR/Release"
log "signed InRelease + Release.gpg with key $GPG_KEY_ID"

log "APT repo built at $OUT_DIR"
