# YadoriLink

**Cloud-like file sync, without cloud file storage.**

[日本語 README](README.ja.md)

YadoriLink gives you accounts, devices, sharing, and permissions while
keeping file contents on your own devices.

Files sync directly between authorized peers.
YadoriLink coordinates them, but does not store your files.

> Pre-1.0 — under active development.

## What it does

- Direct encrypted sync between your devices
- Account-based sharing, permissions, and revocation
- Versions and conflict copies ([what is kept, and for how long](docs/VERSION_HISTORY.md))
- On-demand storage: files can stay online and download when you open them (macOS and Windows desktop apps; not part of the engine-only release)

Supported platforms: macOS 27 (Apple silicon), Windows 11 25H2+ (x64), and Linux x86_64 (experimental).

### What is available

| | Status |
|---|---|
| Engine (`yadorilink` command line and daemon) for macOS, Windows and Linux | Available in this repository's releases |
| Linux `.deb` package | Available |
| macOS desktop app (signed, notarized DMG with in-app updates through Sparkle) | Public beta: download at [yadori.link/download](https://yadori.link/download/) |
| Windows desktop app (Microsoft Store; files can stay online and download when you open them, always as a whole file, never part of one) | Beta; the Microsoft Store release is pending |
| One-line command-line installer (`install.sh`; macOS and Linux) | Available at yadori.link |
| Homebrew formula (engine only; macOS arm64, Linux x86_64) | Available from the project's tap, `yadorilink/homebrew-yadorilink`, which is updated by hand after each release, so it can lag |
| APT repository | Tooling and tests exist, but publishing is skipped until the APT signing key is configured, so there is no repository to add yet: install the `.deb` |
| WinGet | Planned |

## Get YadoriLink

This repository contains the **engine**: the sync daemon and the
`yadorilink` command line, plus the Linux package and the Windows Explorer
integration, and a container image for a NAS or server (see Installing). The macOS and
Windows desktop apps are released separately, not from this repository. The
macOS app is in public beta (download at [yadori.link/download](https://yadori.link/download/));
the Windows app is in beta and its Microsoft Store release is pending. Watch
[yadori.link](https://yadori.link/); the app sets up the engine for you.

The engine on its own (command line and daemon, no desktop app) is available
for every platform from
[GitHub Releases](https://github.com/yadorilink/yadorilink/releases):

| Platform | Download |
|---|---|
| Linux (Debian/Ubuntu) | `yadorilink-linux-amd64.deb` |
| macOS, Windows, Linux | `yadorilink-engine-*.zip`: the engine (`yadorilink` command line and daemon) for one platform |

Each file has a `.sha256` checksum next to it. The layout of each engine
bundle is described in
[`.github/release/engine-bundle-layout.md`](.github/release/engine-bundle-layout.md).

### Installing

- **Linux (Debian/Ubuntu):** download the `.deb` from GitHub Releases, verify its
  `.sha256`, and install it with `sudo apt install ./yadorilink-linux-amd64.deb`.
- **NAS or always-on server (Docker):** `ghcr.io/yadorilink/yadorilink:<version>`
  for `linux/amd64` and `linux/arm64`, with a ready
  [`compose.yaml`](packaging/docker/compose.yaml); see
  [`packaging/docker/README.md`](packaging/docker/README.md). Use the exact release
  version as the tag.
- **Any platform, engine only:** unpack the engine bundle for your platform and
  put `yadorilink` and `yadorilink-daemon` on your `PATH`.
- **One-line installer (macOS Apple silicon, Linux x86_64):**
  `curl -fsSL https://yadori.link/install.sh | sh`. It
  installs under your home directory without administrator rights and checks
  every download against the signed release manifest before using it.
- **Homebrew (engine only; macOS arm64, Linux x86_64):**
  `brew install yadorilink/yadorilink/yadorilink` from the project's tap. The
  tap is updated by hand after each release, so it can lag the latest version.
- **APT repository:** not published. The tooling exists, but the release
  workflow skips publishing until the APT signing key is configured; today
  install the `.deb` (above).
- **WinGet:** planned, not published.

  Whichever way you install, that tool is the one that updates it.

Install steps, first run, updates, and uninstalling for Linux are in the
[Linux README](packaging/linux/README.md).

How the command-line installers work, how `yadorilink self-update` and
`yadorilink uninstall` behave, and what an uninstall keeps are in the
[install, update and uninstall FAQ](docs/INSTALL_FAQ.md).

Release builds connect to the YadoriLink coordination service
automatically. To use a different coordination service, set
`YADORILINK_COORDINATION_ADDR` (for example
`YADORILINK_COORDINATION_ADDR=http://127.0.0.1:8787`) before running any
`yadorilink` command or the daemon.

## First run

On macOS, install and open the app (public beta), sign in with Google in your
browser, and choose the folder to sync; follow the instructions that come with
the app. The Windows app works the same way once you have it (its Microsoft Store
release is pending). On every other platform, and whenever you prefer it, use the
command line below.

Linux has no desktop app. The command line works the same way on every
platform.

## Engine only / command line

Install the engine from a `.deb` (Linux) or unpack an engine bundle for your
platform, and put `yadorilink` and `yadorilink-daemon` on your `PATH`. A
desktop app starts the daemon for you; with the engine alone you start it
yourself: on Linux with the `.deb`, run `systemctl --user enable --now
yadorilink-daemon`; elsewhere run `yadorilink daemon start`. Then:

```bash
yadorilink login
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

`yadorilink status` and `yadorilink doctor` show what the daemon sees. When a
shared folder's history is rebuilt, YadoriLink keeps ("preserves") versions
or local changes it could not carry over instead of deleting them.
`yadorilink preserved list` shows them; `preserved restore <item-id>` writes
a kept version back as a new change, `retry <item-id>` re-submits one of your
own changes, and `discard <item-id>` deletes the item.

Add another of your devices:

```bash
yadorilink share joinable
yadorilink share join my-share --path ~/some/folder
```

Share with someone else:

```bash
yadorilink share invite my-share --role editor
# the recipient runs:
yadorilink share accept <code> --path ~/some/folder
```

Keep older versions and go back in time:

```bash
yadorilink versions <file>            # every kept version of a file, newest first
yadorilink restore <file> [--version N]  # restore the previous (or a chosen) version
yadorilink rewind <folder> --at 2h           # preview rewinding a folder to two hours ago
yadorilink rewind <folder> --at 2h --execute # confirm the counts, then run exactly that plan
```

Choose what is not synchronised with the folder's ignore rules (one pattern per line,
kept by YadoriLink on this device, never synchronised): `yadorilink ignore set <folder> <file>`
replaces them, and `yadorilink ignore list|test|explain <folder>` shows which patterns apply
and why a path is ignored. A line YadoriLink cannot use is refused with its line number.

Send files to another of your devices, or to someone on another account:

```bash
yadorilink send <paths...> <device>            # one transfer to one of your devices
yadorilink send-link create <paths...>         # prints a code for the recipient
yadorilink send-link redeem <code>             # the recipient accepts; add --to <folder>
yadorilink send <paths...> link:<link-id>      # fill the link
yadorilink inbox | outbox                      # transfers waiting for you, and ones you sent
yadorilink receive <transfer-id> --to <folder> # accept an incoming transfer
```

The daemon also serves a small web dashboard, on `127.0.0.1` only (port 8484;
`YADORILINK_HTTP_API_PORT` changes it). `yadorilink web status` prints its
address, where its access token is kept, and how to reach it from another
computer over SSH: `ssh -N -L 8484:127.0.0.1:8484 <user>@<host>`, then open
`http://127.0.0.1:8484/` there. The local port must equal the dashboard's
port, or it answers 403. The token is in a file that, on Linux and macOS,
only the daemon's own account can read. It changes every time the daemon
starts and is pasted into the page; it is never part of a URL. Any local account can connect to the port, so the
token file's permissions are what keep other local users out.

## Updating and resetting (pre-1.0)

Update every device to the same release. Pre-1.0 releases do not promise
compatibility migrations between versions. If a version incompatibility
prevents startup, remove YadoriLink's local application state and
credentials and set up again; your synced folders and their files are not
deleted. The Linux README lists where that state lives on Linux; the desktop apps
document it for macOS and Windows.

## How it works

YadoriLink separates management from storage.

The coordination service handles accounts, device identity, sharing,
permissions, and connectivity. File contents stay on user devices and move
only between authorized peers.

## Build from source

For development, or if you prefer to build it yourself:

The engine (command line and daemon) builds the same way on every platform:

```bash
cargo build --release -p yadorilink-cli -p yadorilink-daemon
./target/release/yadorilink --help
```

This is what the engine bundles contain. To build everything else in the
workspace, which is what continuous integration does:

- `cargo build --workspace` (all platforms).
- Windows Explorer integration: `cargo build --release --manifest-path crates/yadorilink-shell-ext-windows/Cargo.toml`
  (a separate workspace, Windows only).

Without a build-time setting, a source build connects to
`http://127.0.0.1:8787` unless `YADORILINK_COORDINATION_ADDR` is set.
Release builds are compiled with `YADORILINK_DEFAULT_COORDINATION_ADDR`
set to the production coordination service; you can set the same variable
when you build to bake in your own default. Resolution order at run time:
`YADORILINK_COORDINATION_ADDR`, then the compiled default, then
`http://127.0.0.1:8787`. Start the daemon yourself with
`yadorilink daemon start`.

## Development

YadoriLink is written primarily in Rust.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Main components:

- `crates/yadorilink-daemon` — sync daemon
- `crates/yadorilink-cli` — command-line interface
- `crates/yadorilink-transport` — peer connectivity
- `crates/yadorilink-shell-ext-windows` — Explorer integration (Cloud Files host and shell extension)

Platform packaging details are in the READMEs under
[`packaging/`](packaging/) and [`crates/yadorilink-shell-ext-windows/`](crates/yadorilink-shell-ext-windows/).

## Security

See [SECURITY.md](.github/SECURITY.md).

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## Data safety

[SAFETY_INVARIANTS.md](docs/SAFETY_INVARIANTS.md) states which data-safety decisions
the engine makes, the code and tests behind each, what is durable and when, and
what is not guaranteed.

## Version compatibility

Devices of one account must run the same release. See
[COMPATIBILITY.md](docs/COMPATIBILITY.md) for the policy and [CUTOVER.md](docs/CUTOVER.md)
for protocol-generation notes.

## License

Licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(AGPL-3.0-only). See [LICENSING.md](LICENSING.md) for how this relates to the
official applications, third-party components, and contributions.

The hosted coordination service at `control.yadori.link` is governed by the
[Privacy Policy](https://yadori.link/privacy/) and the
[Terms of Service](https://yadori.link/terms/).
