# Changelog

All notable changes to yadorilink are recorded here. This file accumulates one
entry per **beta** release (the versioned, immutable `beta` channel). The
rolling `nightly` channel is built from `main` on every push and is not tracked
here.

The format loosely follows [Keep a Changelog](https://keepachangelog.com/), and
versions follow [semantic versioning](https://semver.org/) with a `-beta.N`
prerelease suffix (e.g. `v0.1.0-beta.1`).

## [Unreleased]

## [v0.1.0-beta.10] - 2026-11-08

### Main changes
- **Download when needed:** On Mac and Windows, folders you create and folders you join by invitation download a file when you open it. You can choose which files stay on the device.
- **Windows from the Microsoft Store:** The Windows version is distributed through the Microsoft Store only.
- **Windows pause:** Pause for 2 hours, 8 hours, 24 hours, or until you resume. The pause continues after a restart.
- **Space for older versions:** Older versions are kept up to a tenth of the disk (at most 20 GB), and the oldest are removed first.
- **Lighter to run:** Less power and network use while idle, and receiving files is lighter too.
- **Japanese text:** The command line and the install script show Japanese.

### Main fixes
- Mac: fixed problems such as Finder freezing on right-click and read-only files looking writable.
- Windows: a send or invitation that arrives while the app is busy now waits its turn instead of being lost.
- YadoriLink no longer overwrites or deletes a file you changed while it is repairing a folder.

### Before you update
- beta.10 cannot open beta.9's data. On each device, set YadoriLink up again. Your synced files are not deleted.
- First run `yadorilink preserved list` and clear anything it shows.
- Pins are not carried over. Set them again.
- Devices on beta.9 and beta.10 sync with each other, so you can update them one at a time.

## [v0.1.0-beta.9] - 2026-11-03

### Added
- Send links: send files or folders to another account with a one-time link. The receiver can preview it before accepting.
- Recent activity: see which files were added, changed, deleted, restored or had a conflict.
- Older versions are kept: a version replaced or deleted by sync can be restored for 30 days, and while there are no more than 10 newer versions. `yadorilink versions` shows which ones this device still has.
- In Finder folders, conflict copies offer "Keep this" and "Keep both".
- Sign in without a browser: `yadorilink login --code`.
- Hand over a shared folder to another account.
- `yadorilink self-update` updates to the latest verified release; `install.sh --rollback` goes back one version.
- NAS: a ready-to-use container image with a health check.

### Changed
- `yadorilink status` is simpler: one line for the overall state, one for whether your files are available, one for whether they are safely on another device, then a numbered list of anything you need to fix. `--details` shows the full view.
- Faster sync on macOS and Linux: received files go straight into your folder, and large files you edit start sending sooner and use less disk.
- Faster sign-in and quicker reconnection after the network comes back.
- Uses less power when idle.
- Only the "executable" permission is synced. Other permissions and file attributes stay as your computer sets them.
- When the disk is full, older versions are not kept, but sync keeps going. Pinned files always keep their versions.

### Fixed
- Pinning a file that is only on this device no longer fails.
- A file no one changed no longer gets a new version.
- Edits made offline are sent when you reconnect.
- A deleted file stays deleted after a power cut.

### Known limitations
- Older versions stay only on devices that had the file. A device that never opened a file has no older versions of it.
- Versions replaced by your own edits may not be kept.
- History has no size limit yet; a long history of large files uses more disk.
- Mac: macOS 27 only.

### Before you update
- Update all your devices: different versions do not sync with each other.
- First run `yadorilink preserved list` and resolve anything it shows.
- If a device will not start after the update, remove YadoriLink's local data and set it up again. Your synced files are not deleted.

## [v0.1.0-beta.8] - 2026-10-28

### Fixed
- Keeping both files when resolving a conflict no longer leaves two devices out of sync.
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
