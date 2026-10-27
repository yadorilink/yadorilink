# Changelog

All notable changes to yadorilink are recorded here. This file accumulates one
entry per **beta** release (the versioned, immutable `beta` channel). The
rolling `nightly` channel is built from `main` on every push and is not tracked
here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/), and
versions follow [semantic versioning](https://semver.org/) with a `-beta.N`
prerelease suffix (e.g. `v0.1.0-beta.1`).

## [Unreleased]

## [v0.1.0-beta.8] - 2026-10-28

### Fixed
- The `install.sh` one-liner reads the manifest key id correctly when the manifest carries a trust chain.
- The one-liner stops with a clear message when the desktop app or another installation already owns the data.
- A copied data area is detected and no longer shared by two devices by mistake.
- A missing nonce file beside the keychain item is repaired instead of refusing to start.
- A folder marked for start-over is adopted back into its group.
- Windows: a credential file that is a hard link is refused.

### Changed
- Account deletion that is scheduled shows up as an item that needs attention.
- Daemon refusals name the next step to take instead of a CLI command.

## [v0.1.0-beta.7] - 2026-10-25

### Added
- The macOS engine binaries are signed and notarized.
- The daemon can exit when an update replaces it so a supervisor can restart it (opt-in: `--restart-on-replace`).
- Account deletion asks for a recent sign-in and warns about the shared groups it affects.
- Windows: On-Demand fetch progress and clear failure reasons.

### Fixed
- Downloads that keep progressing are no longer cut off by a time limit.
- Windows: freeing a large file and replacing an existing file no longer fail.

## [v0.1.0-beta.5] - 2026-10-24

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
  `yadorilink preserved list|restore|retry|discard`.
- macOS 14+ (Apple silicon), Windows 11 25H2+ (x64) and Linux x86_64
  (experimental).

### Known limitations

- **Windows cannot rebuild a device's history after a very long absence.** If
  a device was offline so long that it needs a history rebuild from a trusted
  checkpoint, the daemon refuses to start it on Windows and reports `the
  rebootstrap is blocked: DurabilityUnsupported`; the folder is left
  untouched. macOS and Linux are not affected.
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
