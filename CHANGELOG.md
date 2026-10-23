# Changelog

All notable changes to yadorilink are recorded here. This file accumulates one
entry per **beta** release (the versioned, immutable `beta` channel). The
rolling `nightly` channel is built from `main` on every push and is not tracked
here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/), and
versions follow [semantic versioning](https://semver.org/) with a `-beta.N`
prerelease suffix (e.g. `v0.1.0-beta.1`).

## [Unreleased]

## [v0.1.0-beta.1] - 2026-10-23

First public beta of YadoriLink: cloud-like file sync without cloud file
storage. Your files stay on your own devices and move directly between your
authorized devices over encrypted connections; the coordination service
(`https://control.yadori.link`) handles accounts, device identity, sharing and
permissions, and never stores file contents.

This release is the **engine**: the sync daemon and the `yadorilink` command
line. The macOS and Windows desktop apps are released separately and are not
part of this release.

### What is included

- Folder sync between your devices and with other people, with accounts,
  sharing, roles and revocation.
- Versions and conflict copies; `yadorilink status`, `yadorilink doctor`, and
  `yadorilink preserved list|restore|retry|discard` for items set aside during
  a reset.
- Supported platforms: macOS 14+ (Apple silicon) and Windows 11 25H2+ (x64)
  as an engine bundle (`yadorilink-engine-*.zip`), and Linux x86_64
  (experimental) as a `.deb`, an engine bundle, and a
  `ghcr.io/yadorilink/yadorilink-daemon` container image.
- Release builds talk to `https://control.yadori.link` by default; set
  `YADORILINK_COORDINATION_ADDR` to use another coordination service.
- Every download has a SHA-256 checksum, and each engine bundle carries a
  build-provenance attestation that you can verify with `gh attestation verify`.
- Two devices that independently write identical content to the same file now converge to one file instead of leaving a conflicted copy. A difference in bytes, permissions, symlink target or extended attributes is still a conflict.
- Updated dependencies for security advisories in the QUIC and TLS stacks (quinn-proto, rustls, rustls-webpki) and the bundled root certificate data.

### Known limitations

- **Power-loss testing on physical hardware is pending.** Crash safety is
  verified with a deterministic simulation of power cuts and process kills;
  verification on physical internal and external SSDs is still to come.
- **No desktop apps yet.** On-demand storage and the other desktop features arrive
  with the macOS and Windows apps; the first Windows app syncs full local
  copies only.
- **Windows cannot rebuild a device's history after a very long absence.** If
  a device was offline so long that it needs a history rebuild from a trusted
  checkpoint, the daemon refuses to start it on Windows and reports `the
  rebootstrap is blocked: DurabilityUnsupported`; the folder is left
  untouched. macOS and Linux are not affected.
- **The binaries are not signed or notarized yet.** The macOS binaries are not
  notarized and the Windows binaries are not Authenticode-signed, so macOS
  Gatekeeper and Windows SmartScreen may warn when you run them. Check each
  download against its `.sha256` file and with `gh attestation verify` before
  running it; signed and notarized builds come in a later beta.
- **No in-app update download yet.** The updater announces new versions but
  does not download or install them; update by installing the new release (or
  through your package manager).
- **Pre-1.0: upgrades can be incompatible.** There are no compatibility
  migrations between pre-1.0 releases, so update every device to the same
  release together. If a version mismatch prevents startup, remove YadoriLink's
  local application state and credentials and set up again; your synced
  folders and their files are not deleted.

<!--
When cutting a beta release, add a new section ABOVE this comment:

## [vX.Y.Z-beta.N] - YYYY-MM-DD

### Added / Changed / Fixed
- ...

The release job reads the section matching the tag being published and uses it
as the GitHub Release notes body. Never edit or delete a released section —
beta releases are immutable.
-->
