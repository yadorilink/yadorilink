#!/bin/sh
#
# packaging/linux/apt/install.sh
#
# Registers the yadorilink APT repository and its signing key. Run as:
#
#   curl -fsSL https://control.yadori.link/apt/install.sh | sudo sh
#
# This script does exactly two things and nothing else: writes the
# archive's public signing key to /usr/share/keyrings, and writes a
# `.sources` file pointing apt at the repository, scoped to that key
# (`Signed-By`). It never calls `apt-get update`/`apt-get install`, and it
# never touches any package -- once registered, fetching, installing, and
# every future update of yadorilink is entirely `apt`'s own job, the same
# as any other apt-managed package. That boundary is deliberate (see
# manager::dispatch_install's "apt" case in
# crates/yadorilink-daemon/src/update/manager.rs): this script's only
# role is registration.
#
# Requires: curl (or wget, used as a fallback), gpg (for the keyring
# armor->binary conversion; part of the `gnupg` package, already a
# dependency of `apt-key`'s replacement tooling on any apt >= 2.4 system).
#
# apt's deb822 `.sources` format requires apt >= 2.4 (Debian 12
# "bookworm" / Ubuntu 22.04 "jammy" or newer). See README.md's
# "Older apt (Ubuntu 20.04 / Debian 11)" section for the one-line
# `.list` fallback on an older system.

set -eu

KEYRING_DIR="/usr/share/keyrings"
KEYRING_PATH="$KEYRING_DIR/yadorilink-archive-keyring.gpg"
SOURCES_PATH="/etc/apt/sources.list.d/yadorilink.sources"
KEY_URL="https://control.yadori.link/apt/yadorilink-archive-keyring.asc"
REPO_URL="https://control.yadori.link/apt"

log() { echo "[yadorilink apt install] $*"; }

if [ "$(id -u)" -ne 0 ]; then
    echo "This script writes to /usr/share/keyrings and /etc/apt/sources.list.d -- run it as root (e.g. via sudo)." >&2
    exit 1
fi

fetch() {
    # $1=url $2=dest
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        echo "Neither curl nor wget is available." >&2
        exit 1
    fi
}

if ! command -v gpg >/dev/null 2>&1; then
    echo "gpg is required (part of the gnupg package: 'apt-get install gnupg') to install the archive key." >&2
    exit 1
fi

log "fetching the yadorilink archive signing key"
TMP_KEY="$(mktemp)"
trap 'rm -f "$TMP_KEY"' EXIT
fetch "$KEY_URL" "$TMP_KEY"

mkdir -p "$KEYRING_DIR"
gpg --batch --yes --dearmor -o "$KEYRING_PATH" "$TMP_KEY"
chmod 644 "$KEYRING_PATH"
log "installed signing key -> $KEYRING_PATH"

cat > "$SOURCES_PATH" <<EOF
Types: deb
URIs: $REPO_URL
Suites: stable
Components: main
Signed-By: $KEYRING_PATH
EOF
chmod 644 "$SOURCES_PATH"
log "wrote $SOURCES_PATH"

log "done. Nothing has been installed or updated yet -- run:"
log "  sudo apt update && sudo apt install yadorilink"
