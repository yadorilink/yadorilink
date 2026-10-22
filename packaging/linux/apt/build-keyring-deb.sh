#!/bin/bash
#
# packaging/linux/apt/build-keyring-deb.sh
#
# Builds yadorilink-archive-keyring_<version>_all.deb: installs the APT
# archive's public signing key + a deb822 `.sources` file, and nothing
# else. This is the package-install alternative to install.sh (curl |
# sudo sh) for a user who prefers `dpkg -i` / already trusts a
# downloaded .deb more than piping a script to a shell -- both paths
# converge on the same two files.
#
# Usage:
#   ARMORED_PUBLIC_KEY_PATH=/path/to/pubkey.asc ./build-keyring-deb.sh
#   PKG_VERSION=1 ./build-keyring-deb.sh    # override the keyring package's own version
#
# The signing key's PUBLIC half is not sensitive -- unlike
# YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX, which is compiled into
# release binaries, this one is shipped in a published package, but the same "public half only, never the
# private key" boundary applies. See README.md's "Signing key custody"
# section for where the private half lives and who is authorized to sign
# with it.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

STAGE_DIR="$SCRIPT_DIR/.stage"
OUT_DIR="$SCRIPT_DIR/dist"

log() { echo "[build-keyring-deb] $*"; }

ARMORED_PUBLIC_KEY_PATH="${ARMORED_PUBLIC_KEY_PATH:-}"
if [ -z "$ARMORED_PUBLIC_KEY_PATH" ] || [ ! -f "$ARMORED_PUBLIC_KEY_PATH" ]; then
    log "ERROR: set ARMORED_PUBLIC_KEY_PATH to an ASCII-armored public key file (gpg --export --armor <key-id> > pubkey.asc)"
    exit 1
fi

# This package's own version is independent of yadorilink's release
# version -- it only ever changes when the signing key itself rotates
# (following the update-signing key's rotation procedure) or this script's
# packaged files change, so it does not read $REPO_ROOT/Cargo.toml's
# `version` the way build-deb.sh does.
VERSION="${PKG_VERSION:-1}"

log "Building yadorilink-archive-keyring ${VERSION}"

command -v gpg >/dev/null 2>&1 || { log "ERROR: gpg not found"; exit 1; }
command -v dpkg-deb >/dev/null 2>&1 || { log "ERROR: dpkg-deb not found"; exit 1; }

rm -rf "$STAGE_DIR"
mkdir -p \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/usr/share/keyrings" \
    "$STAGE_DIR/etc/apt/sources.list.d" \
    "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring" \
    "$STAGE_DIR/usr/share/lintian/overrides"

# `mkdir -p` inherits the *building* user's umask rather than a fixed
# mode -- same non-standard-dir-perm trap packaging/linux/build-deb.sh
# fixes for the main package's staged tree, applied here to every
# directory level (lintian checks each one, not just the leaves).
chmod 755 \
    "$STAGE_DIR" \
    "$STAGE_DIR/DEBIAN" \
    "$STAGE_DIR/etc" \
    "$STAGE_DIR/etc/apt" \
    "$STAGE_DIR/etc/apt/sources.list.d" \
    "$STAGE_DIR/usr" \
    "$STAGE_DIR/usr/share" \
    "$STAGE_DIR/usr/share/keyrings" \
    "$STAGE_DIR/usr/share/doc" \
    "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring" \
    "$STAGE_DIR/usr/share/lintian" \
    "$STAGE_DIR/usr/share/lintian/overrides"

gpg --batch --yes --dearmor -o "$STAGE_DIR/usr/share/keyrings/yadorilink-archive-keyring.gpg" "$ARMORED_PUBLIC_KEY_PATH"
chmod 644 "$STAGE_DIR/usr/share/keyrings/yadorilink-archive-keyring.gpg"

cat > "$STAGE_DIR/etc/apt/sources.list.d/yadorilink.sources" <<'EOF'
Types: deb
URIs: https://control.yadori.link/apt
Suites: stable
Components: main
Signed-By: /usr/share/keyrings/yadorilink-archive-keyring.gpg
EOF
chmod 644 "$STAGE_DIR/etc/apt/sources.list.d/yadorilink.sources"

install -m 644 "$REPO_ROOT/LICENSE" "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring/LICENSE"

# Debian Policy 12.5: every package ships /usr/share/doc/<pkg>/copyright,
# named exactly that -- LICENSE above satisfies "the license text is
# present" but not this specific, separately-checked requirement.
cat > "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring/copyright" <<'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: yadorilink
Source: https://github.com/yadorilink/yadorilink

Files: *
Copyright: 2026 Jumpei Takiyasu
License: AGPL-3.0-only

License: AGPL-3.0-only
 See /usr/share/doc/yadorilink-archive-keyring/LICENSE (installed from
 this repository's LICENSE at build time).
EOF
chmod 644 "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring/copyright"

{
    echo "yadorilink-archive-keyring (${VERSION}) unstable; urgency=low"
    echo
    echo "  * See https://github.com/yadorilink/yadorilink for release notes."
    echo
    echo " -- yadorilink project <juntaki@users.noreply.github.com>  $(date -R)"
} | gzip -n -9 > "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring/changelog.gz"
chmod 644 "$STAGE_DIR/usr/share/doc/yadorilink-archive-keyring/changelog.gz"

install -m 644 "$SCRIPT_DIR/yadorilink-archive-keyring.lintian-overrides" \
    "$STAGE_DIR/usr/share/lintian/overrides/yadorilink-archive-keyring"

# dpkg conffile: /etc/apt/sources.list.d/yadorilink.sources is
# user-editable config, not just a data file this package happens to drop
# in /etc. Without this, a keyring-package upgrade (the exact case key
# rotation triggers) silently overwrites any local edits instead of
# prompting dpkg's normal "modified conffile" conflict resolution.
echo "/etc/apt/sources.list.d/yadorilink.sources" > "$STAGE_DIR/DEBIAN/conffiles"
chmod 644 "$STAGE_DIR/DEBIAN/conffiles"

cat > "$STAGE_DIR/DEBIAN/control" <<EOF
Package: yadorilink-archive-keyring
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: all
Maintainer: yadorilink project <juntaki@users.noreply.github.com>
Description: yadorilink APT repository signing key and sources entry
 Installs the public signing key for the yadorilink APT repository
 (https://control.yadori.link/apt) and a deb822 sources entry
 (/etc/apt/sources.list.d/yadorilink.sources) scoped to that key. Installing
 this package registers the repository; it does not install yadorilink
 itself and never runs 'apt-get update' on your behalf -- run that (and
 'apt-get install yadorilink') yourself once this is installed.
EOF

mkdir -p "$OUT_DIR"
DEB_PATH="$OUT_DIR/yadorilink-archive-keyring_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$STAGE_DIR" "$DEB_PATH"
log "Built $DEB_PATH"

sha256sum "$DEB_PATH" > "$DEB_PATH.sha256" 2>/dev/null || shasum -a 256 "$DEB_PATH" > "$DEB_PATH.sha256"
log "Wrote checksum sidecar $DEB_PATH.sha256"
