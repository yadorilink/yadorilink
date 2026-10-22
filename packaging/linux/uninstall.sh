#!/bin/bash
#
# packaging/linux/uninstall.sh
#
# Companion "undo" for the .deb built by build-deb.sh (a .deb uninstall is
# normally just `apt remove`/`dpkg -r`, but see below for why that alone
# leaves something behind).
#
# RUN THIS AS YOUR NORMAL USER -- do NOT run the whole script with sudo.
# `systemctl --user...` always targets the *invoking* user's own systemd
# session; if this script itself is run under `sudo`, that command would
# instead reach root's own (essentially unused) --user session, silently
# doing nothing useful. Package removal
# (dpkg/apt), which does need root, is escalated internally via `sudo`
# for just that one step.
#
# ./uninstall.sh # stop/disable the user unit, remove the package
# ./uninstall.sh --purge-data # also remove ~/.local/share/yadorilink
#
# What this does NOT remove (deliberately -- this is uninstalling the
# *application*, not the user's data), unless --purge-data is passed:
#  - ~/.local/share/yadorilink (device.json, sync state DB, block store,
#  control socket -- see crates/yadorilink-cli/src/device_config.rs)
#  - Secret Service (gnome-keyring/kwallet) credential entries the
#  `keyring` crate's linux-native backend stored under the service
#  name "yadorilink" -- no portable headless CLI exists to purge these
#  across both gnome-keyring and kwallet; remove them by hand via
#  Seahorse/KWalletManager if desired.
#  - Any linked folders' local content.

set -uo pipefail

PURGE_DATA=0
if [ "${1:-}" = "--purge-data" ]; then
    PURGE_DATA=1
fi

log() { echo "[yadorilink uninstall] $*"; }

if [ "$(id -u)" -eq 0 ]; then
    log "ERROR: do not run this script with sudo/as root."
    log "Run it as your normal user; it escalates internally (via sudo) only for package removal."
    exit 1
fi

SERVICE_NAME="yadorilink-daemon"

# --- 1. Stop/disable the per-user systemd unit, as this user ---------------
if command -v systemctl >/dev/null 2>&1; then
    log "Stopping and disabling systemd --user unit $SERVICE_NAME (if enabled)..."
    systemctl --user disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
else
    log "WARNING: systemctl not found; skipping user-unit disable step."
fi

# --- 2. Remove the package (needs root) ------------------------------------
if command -v dpkg >/dev/null 2>&1 && dpkg -s yadorilink >/dev/null 2>&1; then
    log "Removing the yadorilink package (sudo dpkg -r)..."
    sudo dpkg -r yadorilink
elif command -v apt-get >/dev/null 2>&1; then
    log "yadorilink not found via dpkg -s; trying apt-get remove anyway..."
    sudo apt-get remove -y yadorilink || true
else
    log "WARNING: could not find dpkg/apt-get, or package not installed via dpkg."
    log "Removing known installed files directly instead..."
    sudo rm -f /usr/bin/yadorilink /usr/bin/yadorilink-daemon
    sudo rm -f /usr/lib/systemd/user/yadorilink-daemon.service
    sudo rm -rf /usr/share/doc/yadorilink
fi

if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
fi

# --- 3. Optional data purge -------------------------------------------------
if [ "$PURGE_DATA" -eq 1 ]; then
    log "Purging data (--purge-data): ~/.local/share/yadorilink..."
    rm -rf "$HOME/.local/share/yadorilink"
else
    log "User data under ~/.local/share/yadorilink was left in place."
    log "Re-run with --purge-data to remove it too."
fi

log "Uninstall complete."
