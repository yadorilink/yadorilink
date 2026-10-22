# YadoriLink Linux installer

Builds a `.deb` that installs:

| Payload | Installed to |
|---|---|
| `yadorilink` (CLI) | `/usr/bin/yadorilink` |
| `yadorilink-daemon` | `/usr/bin/yadorilink-daemon` |
| systemd `--user` service unit | `/usr/lib/systemd/user/yadorilink-daemon.service` |
| license texts | `/usr/share/doc/yadorilink/` |

This is a **CLI/daemon-only** package: there is no file-manager integration,
so nothing in it depends on GTK or appindicator.
The coordination service is a separate server-side deployment and is **not**
part of this package.

## Installing a release (most people)

Download `yadorilink-linux-amd64.deb` (and its `.sha256`) from
[GitHub Releases](https://github.com/yadorilink/yadorilink/releases), then:

```bash
sha256sum -c yadorilink-linux-amd64.deb.sha256
sudo apt install ./yadorilink-linux-amd64.deb
systemctl --user enable --now yadorilink-daemon
```

First run:

```bash
yadorilink login
yadorilink device register --name "my-box"
yadorilink share create my-share --path ~/some/folder
yadorilink status
```

If something needs attention, `yadorilink status` and `yadorilink doctor`
show what the daemon sees, and `yadorilink preserved list` / `restore` /
`retry` / `discard` manage items set aside when a folder group was reset.
The [top-level README](../../README.md) covers the same flow and sharing
with other people.

Release builds connect to the YadoriLink coordination service by default;
set `YADORILINK_COORDINATION_ADDR` to use another one (for the daemon, add
it to the unit's environment, for example with `systemctl --user edit
yadorilink-daemon`). Builds from source default to `http://127.0.0.1:8787`
unless the build was made with `YADORILINK_DEFAULT_COORDINATION_ADDR` set.

**Updating.** Update every device to the same release: install the newer
`.deb` the same way.

**Uninstalling.** `./uninstall.sh` from a repository checkout, or
`systemctl --user disable --now yadorilink-daemon` followed by
`sudo apt remove yadorilink`. Your synced folders and
`~/.local/share/yadorilink` stay in place.

**Pre-1.0 reset.** Releases before 1.0 do not promise compatibility
migrations. If a version incompatibility prevents startup, remove
YadoriLink's local application state and credentials and set up again; your
synced folders and their files are not deleted. Run
`systemctl --user stop yadorilink-daemon`, then remove
`~/.local/share/yadorilink` (or `$XDG_DATA_HOME/yadorilink` if set), which
holds the sync state database, block store, and the sign-in credentials
file `credentials.json`, then start the daemon and run `yadorilink login`
again. If you chose the system keyring as the credential store, also
remove the `yadorilink` entries there.

The rest of this file is for building the package from source.

## Always-on headless install (system service)

For a box nobody logs in to (NAS, home server, mini PC): a system service
that starts at boot as the dedicated `yadorilink` account, with state in
`/var/lib/yadorilink` and synced folders under `/srv/yadorilink`. After
installing the `.deb`:

```bash
sudo /usr/share/yadorilink/headless/install-headless.sh        # account, directories, unit; starts nothing
sudo yadorilink-svc login --device                             # approve the printed code on another device
sudo yadorilink-svc device register --name my-nas
sudo systemctl start yadorilink-headless
sudo install -d -o yadorilink -g yadorilink -m 0750 /srv/yadorilink/<group>   # the folder must exist first
sudo yadorilink-svc share join <group> --path /srv/yadorilink/<group>   # keeps a complete copy
```

`yadorilink-svc` runs the normal CLI as the service account against the
service's state directory; use it (not plain `yadorilink`) for every CLI
call on the box, and `systemctl` (not `yadorilink daemon start`/`stop`) to
start and stop the daemon; the wrapper refuses those two, and refuses
`device register` unless the service is inactive or failed (stop it,
register, start it). Settings are in `/etc/yadorilink/headless.env`;
logs are `journalctl -u yadorilink-headless`. The local dashboard listens on
`127.0.0.1:18484` only (set in `headless.env`). No TCP port is open to the network; the daemon does listen on UDP (peer transport, mDNS 5353), which is expected. Wait until `sudo yadorilink-svc status` shows connected before the first `share create`. `sudo yadorilink-svc web status` shows the dashboard port and token path. A local or disposable coordination service needs `YADORILINK_COORDINATION_ADDR` in `headless.env`.

Folders under `/home` need a systemd drop-in (`ProtectHome=read-only` plus
`ReadWritePaths=`), and a folder on a separate disk needs
`RequiresMountsFor=`. `install-headless.sh --dry-run` prints the plan, and
`--root <dir>` stages the files under a directory without touching the
system. Uninstall: `uninstall-headless.sh` (keeps data) or with
`--purge-data`; your synced folders are never deleted. The per-user unit
above remains the choice for a machine somebody logs in to.

Management from the YadoriLink app (the Manage button on another device of
the same account) is offered only by this system service: its unit sets
`YADORILINK_NAS_ADMIN=1`, and no other install sets it. Put
`YADORILINK_NAS_ADMIN=0` in `headless.env` to turn it off. A device that
signed out of the account is refused. If the box cannot reach the
coordination service, the devices it last saw keep access for up to 24
hours, after which everyone is refused until it reconnects (use the SSH
route below meanwhile).

#### Advanced / Troubleshooting: dashboard over SSH

Normal management is the app's Manage button. To reach the dashboard by hand, tunnel with the same port on both ends: `ssh -N -L 18484:127.0.0.1:18484 <host>`, then open `http://127.0.0.1:18484/` (any other local port answers 403). The bearer token is in `/var/lib/yadorilink/http-api-token` and rotates on every daemon start; `sudo yadorilink-svc web status` prints its location.

## Packaging approach

The `.deb` is built from a hand-authored `debian/control` and
`postinst`/`postrm` pair with `dpkg-deb` (this directory's `build-deb.sh`),
not with `cargo-deb`. The package is two binaries, one static unit file and
a few documentation files, so a plain `control` file is easy to audit line by
line, and no crate manifest needs packaging metadata.

## Prerequisites

- A Debian/Ubuntu-family Linux machine (or CI runner), matching this
  package's own `Depends: libc6` and its systemd-based baseline.
- Rust/cargo, for `cargo build --release`.
- `dpkg-deb`, for building the archive itself — part of the base `dpkg`
  package, present on essentially every Debian-family system already
  (`apt-get install dpkg-dev` if somehow missing, e.g. a minimal
  container image).
- Optionally `lintian`, for an extra structural lint pass
  (`apt-get install lintian`) — not required to build or install.

## Build

```bash
./build-deb.sh
```

This runs `cargo build --release --workspace
--bin yadorilink --bin yadorilink-daemon` (explicitly selecting the two bins, so
`yadorilink-daemon`'s second, maintainer-only
`yadorilink-sign-manifest` bin target — see that crate's `Cargo.toml`),
stages the payload under `.stage/` (rebuilt from scratch every run, safe
to delete between builds), and produces:

```
dist/yadorilink_<version>_<arch>.deb
dist/yadorilink_<version>_<arch>.deb.sha256
```

Version comes from the workspace's `Cargo.toml` (`[workspace.package]`);
architecture is auto-detected from `uname -m` (`amd64`/`arm64`). Override
either, or skip the `cargo build` step and package prebuilt binaries from
elsewhere:

```bash
PKG_VERSION=0.1.0-beta.1 PKG_ARCH=arm64 ./build-deb.sh
YADORILINK_BIN_DIR=/path/to/target/release ./build-deb.sh
```

Only an `x86_64`/`amd64` build has actually been run through real Linux
CI/manual verification so far; `arm64` is untested and should be treated
as experimental until someone actually runs it there.

## Install

```bash
sudo dpkg -i dist/yadorilink_<version>_<arch>.deb
# or, to also resolve the libc6 dependency automatically if missing:
sudo apt install ./dist/yadorilink_<version>_<arch>.deb
```

The systemd `--user` unit is installed but **not** started or enabled
automatically (see `systemd/yadorilink-daemon.service`'s header comment
— a per-user unit generally shouldn't be silently enabled by a package
installed as root). After installing,
each user who wants the daemon running persistently runs, once:

```bash
systemctl --user enable --now yadorilink-daemon
```

Then: `yadorilink login`, `yadorilink device
register ...`, `yadorilink share create <name> --path <folder>`,
`yadorilink status`, etc. — see the top-level README for CLI usage.

## What the package does beyond copying files

`debian/postinst` (installed as the package's `postinst`) only runs
`systemctl daemon-reload` (so a running system manager notices the new
unit file) and prints the `systemctl --user enable --now` reminder above
— it takes no other action, deliberately (see its own header comment for
why: it runs as root with no specific user session to target).

`debian/postrm` similarly only prints a reminder on `remove`/`purge`: a
per-user systemd unit the user enabled themselves can't be reached by a
root-run `dpkg -r`/`apt remove` either, so if you enabled the unit,
disable it yourself first (or use `uninstall.sh`, which does this for
you in the right order).

## Uninstall

```bash
./uninstall.sh                # stop/disable the user unit, then remove the package
./uninstall.sh --purge-data   # also remove ~/.local/share/yadorilink
```

Run as your **normal user, without sudo** on the whole script — see
`uninstall.sh`'s header comment for why (`systemctl --user` always
targets the invoking user's own session; running the whole script under
sudo would silently disable nothing). It escalates via `sudo` internally
only for the actual package removal (`dpkg -r`).

## Manual verification

Once built (`./build-deb.sh`) on a real Debian/Ubuntu machine or VM:

```bash
./verify-deb.sh dist/yadorilink_<version>_<arch>.deb
```

This checks the checksum sidecar, the control file's `Package`/`Version`
fields, and that the payload contains `/usr/bin/yadorilink`,
`/usr/bin/yadorilink-daemon` (both executable), and
`/usr/lib/systemd/user/yadorilink-daemon.service` (not executable) —
without requiring root or actually installing anything. It also runs
`lintian` if installed.

Beyond that structural check, verify the real install end to end:

1. `sudo apt install ./dist/yadorilink_<version>_<arch>.deb`
2. Confirm both binaries run: `yadorilink --version`,
   `yadorilink-daemon --version` (or `--help`).
3. Confirm the unit file is present and well-formed:
   `systemctl --user cat yadorilink-daemon` (before enabling it, this
   just prints the unit's contents from the shipped file).
4. `systemctl --user enable --now yadorilink-daemon`, then
   `systemctl --user status yadorilink-daemon` and confirm it's
   `active (running)`.
5. Kill the daemon process directly (`pkill yadorilink-daemon`) and
   confirm systemd restarts it within a couple seconds
   (`Restart=on-failure`) — `journalctl --user -u yadorilink-daemon`
   should show the restart.
6. Run `yadorilink status` against the running daemon and confirm it
   reaches it over the Unix-domain-socket control transport (see
   `crates/yadorilink-cli/src/device_config.rs` for the default socket
   path, `~/.local/share/yadorilink/daemon.sock`).
7. `./uninstall.sh`, then confirm the unit is gone
   (`systemctl --user status yadorilink-daemon` reports not-found) and
   the binaries are removed (`which yadorilink` / `which
   yadorilink-daemon` both empty).

## What has and hasn't been verified (as of this change)

The package was verified on a real Linux (x86_64) machine:

- `cargo build --release --workspace
  --bin yadorilink --bin yadorilink-daemon` — **succeeds**, real
  `x86_64-unknown-linux-gnu` binaries.
- `./build-deb.sh` end to end, including `dpkg-deb --build
  --root-owner-group` — **produces a real, valid `.deb`** (verified with
  `verify-deb.sh`: checksum, control fields, payload paths and modes all
  correct).
- `lintian` against the built `.deb` — **clean** (run via a disposable
  Ubuntu 24.04 container, since `lintian` wasn't installed on the build
  host either: `docker run ... ubuntu:24.04 ... lintian
  yadorilink_<version>_amd64.deb`).
- A real `dpkg -i`/`apt install` — **succeeds**. Exercised as part of a
  full APT-repository acceptance test (see `packaging/linux/apt/`): a
  clean Ubuntu 24.04 container ran the archive-keyring package, `apt-get
  update` (verified the repository's GPG signature), `apt-get install
  yadorilink`, and confirmed `postinst` ran (`Setting up yadorilink
  (0.1.0) ...` plus its reminder text), both binaries execute
  (`yadorilink --version`, `yadorilink-daemon --version`), and `dpkg -s
  yadorilink` reports `Status: install ok installed`.
- `systemd-analyze verify /usr/lib/systemd/user/yadorilink-daemon.service`
  against the **installed** unit (so `ExecStart`'s path actually
  resolves) — **zero errors or warnings**.

The session-dependent checks need a machine with a real per-user systemd manager, which a plain
`docker run ubuntu bash` does not have; running Ubuntu 24.04 with systemd
as PID 1 and enabling lingering for the installing user provides one.
Against a real installation on such a machine, all of the following were
observed:

- `systemctl --user enable --now yadorilink-daemon` starts the daemon and
  it reaches `active (running)`, and `yadorilink status` then reaches it
  over the control socket.
- The daemon under the unit reads the account session stored by the CLI, so
  it authenticates to the coordination plane rather than merely running.
  Worth stating separately: the daemon's process session is not the shell's,
  and a daemon that cannot read the session would look healthy locally while
  never reaching the coordination plane at all.
- `Restart=on-failure` brings the daemon back after `kill -9`, within a
  few seconds.
- `WantedBy=default.target` starts the daemon by itself after the machine
  restarts, with no user action, and previously linked folders are still
  linked.
- `./uninstall.sh`, run as the normal user, takes its live
  `systemctl --user disable --now` path: afterwards the unit is no longer
  known to systemd, both binaries and the unit file are gone, and
  `~/.local/share/yadorilink` is left in place until `--purge-data` is
  passed.

Also confirmed on that machine: `lintian` is clean when run against the
`.deb` on the machine that installs it, and `systemd-analyze verify` on the
**installed** unit reports nothing.

Every claim in that list is about *packaging and the unit file*. None of
them is a claim about sync behaviour between devices, which is covered by the
project's test suites rather than by this packaging pass.

What is still **not** verified here:

- Anything about a **signed** package. Nothing in this directory signs the
  `.deb`, and the verification above ran against an unsigned one.
- Upgrading from a previously released version, as opposed to a fresh
  install. There is no earlier release to upgrade from yet.

## ARM64 status

`build-deb.sh` was already structurally arm64-aware before this
verification pass (`uname -m`'s `aarch64|arm64` case, `PKG_ARCH`
override) — that part of
the earlier "untested and should be treated as experimental" caveat above
was about the *build itself* having never been run for arm64, not about
missing code. That later verification pass actually ran it:

- `cargo build --release --workspace
  --bin yadorilink --bin yadorilink-daemon` under real arm64 execution
  (QEMU user-mode emulation via `docker run --platform linux/arm64
  rust:1.98-bookworm`, i.e. genuinely running as an arm64 process, not
  just cross-compiled and left unexecuted).
- `PKG_ARCH=arm64 YADORILINK_BIN_DIR=<arm64 binaries> ./build-deb.sh`
  against those binaries, then `dpkg-deb --info`/`--contents` on the
  result (structural check only — this build host cannot execute an
  arm64 ELF outside of QEMU emulation).
- `packaging/docker/Dockerfile` had a real bug caught and fixed: the
  builder stage was pinned to `--platform=$BUILDPLATFORM` for build
  speed, which silently produced an **amd64** binary inside the arm64
  runtime image (a wrong-architecture binary gives "no such file or
  directory" at container start, not "exec format error", because the
  copied glibc dynamic linker path doesn't exist in the target image —
  easy to miss without actually running the image). Fixed by dropping
  that pin; see the Dockerfile's own comment. The fix was re-verified
  against real arm64 compilation mechanics (QEMU registered, workspace
  crates compiling for `aarch64`), but the final confirming end-to-end
  `docker run --platform linux/arm64 ... --version` has not been
  completed to a clean pass — see `packaging/docker/README.md` for the
  exact status. Treat the arm64 image as unverified until that run
  completes.

Not yet run on real arm64 hardware (only QEMU emulation, which proves the
build/packaging mechanics work but not real-hardware performance or any
QEMU-masked instruction-level issue) — treat this as "arm64 packaging is
now exercised and works" rather than "arm64 has been through the same
depth of manual verification as amd64" (the live systemd-session gaps
above apply here too, and were not re-checked separately for arm64).

## Files

- `build-deb.sh` — builds the workspace binaries and produces the `.deb`
- `verify-deb.sh` — standalone structural verification of a built `.deb`
  (checksum, control metadata, payload contents/modes, optional lintian)
- `debian/control` — control file template (`@VERSION@`/`@ARCH@`
  substituted at build time)
- `debian/postinst`, `debian/postrm` — package scripts (reminders only,
  no automatic systemd enable/disable — see "What the package does" above)
- `debian/copyright` — DEP-5 copyright file, references the bundled
  `LICENSE`
- `systemd/yadorilink-daemon.service` — the daemon's systemd `--user`
  service unit, installed to `/usr/lib/systemd/user/`
- `systemd/yadorilink-headless.service` — the always-on system unit, installed to `/usr/lib/systemd/system/`
- `headless/` — `install-headless.sh`, `uninstall-headless.sh`, the `yadorilink-svc` wrapper and the `headless.env` template, installed to `/usr/share/yadorilink/headless/`
- `uninstall.sh` — companion uninstaller (run as your normal user, not
  with sudo — see its header comment)
