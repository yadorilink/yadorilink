# Install, update and uninstall: FAQ

日本語版: [INSTALL_FAQ.ja.md](INSTALL_FAQ.ja.md)

Answers for installing, updating and uninstalling the YadoriLink engine (the
`yadorilink` command line and `yadorilink-daemon`). See also the
[README](../README.md#installing) and the [Linux README](../packaging/linux/README.md).

Status: the current release is engine-only. There is no desktop app yet. The
one-line installers described below are built and tested but are not
published yet (see "Planned" in the README), so today you install from the
Linux package or an engine bundle. This page also describes how the installers
behave, so you can read it before you run one. Where a statement has not been
checked on every operating system it is written as what the software does by
design, not as a test result.

## Which way should I install?

| You use | Install with | Updated by | Removed by |
|---|---|---|---|
| Debian / Ubuntu | the `.deb` from GitHub Releases | installing a newer `.deb` | `sudo apt remove yadorilink` |
| macOS, Windows or Linux, engine only, today | the engine bundle zip you unpack | you (unpack the newer bundle) | you (delete the folder) |
| macOS (Apple silicon), Linux x86_64, Windows x64, once published | the one-line installer | `yadorilink self-update`, then the installer command it prints | `yadorilink uninstall` (Windows: `install.ps1 -Uninstall`) |
| macOS or Windows desktop app (not released yet) | the app | the app | the app's own uninstall |

A Docker image, an apt repository, Homebrew and WinGet are planned and not
published yet; nothing on this page depends on them.

Update every device to the same version. Whichever way you install, that way
is also the one that updates and removes it. YadoriLink does not update an install that something else owns: the other
tool's commands refuse and tell you what to use instead (exit code 19).

## What does the one-line installer do?

```sh
curl -fsSL https://yadori.link/install.sh | sh          # macOS, Linux
irm https://yadori.link/install.ps1 | iex               # Windows (PowerShell 5.1 or newer)
```

- It installs under your home directory (`~/.local` by default,
  `%LOCALAPPDATA%\YadoriLink` on Windows). It never uses `sudo` or asks for
  administrator rights, and it does not start the daemon.
- It downloads the signed release manifest for the channel (`beta`, or
  `nightly` with `--channel nightly`), checks its signature against release
  keys built into the script, then downloads the engine bundle and checks its
  size and SHA-256 against the manifest and every file inside against the
  bundle's own checksums. Only then does it switch `yadorilink` and
  `yadorilink-daemon` in `<prefix>/bin` to the new version. If any check
  fails it stops with a message and changes nothing.
- It adds `<prefix>/bin` to your shell profile (user PATH on Windows) unless
  you pass `--no-modify-path` (`-NoModifyPath`).
- It needs `curl`, `unzip`, `awk` and `sha256sum` or `shasum`. Other
  operating systems and CPUs (for example Alpine, or 32-bit ARM) are refused
  with exit code 5.

## Can I read the script before running it?

Yes. Download it, read it, then run the file: `curl -fsSLo install.sh
https://yadori.link/install.sh`, then `sh install.sh`. The header of the
script lists every option and the exact steps it takes. `sh install.sh
--help` prints it.

## How do I install without a network connection, or in CI?

- CI: `sh install.sh --yes --no-modify-path --prefix "$RUNNER_TEMP/yadorilink"`
  (`-Yes -NoModifyPath -Prefix` on Windows) asks no questions and edits no profile.
- Offline: `--from FILE` installs from a signed manifest file you downloaded
  earlier, with the engine bundle (and, on macOS and Linux, the signature
  verifier program) next to it. If the live manifest cannot be reached the
  installer says that it could not check whether the version was withdrawn.
  The manifest is still verified.

## Who updates YadoriLink, and how?

For the Linux package, install the newer `.deb` the same way you installed the
older one. For an engine bundle, unpack the newer bundle over your old folder
or replace it. YadoriLink does not download or install updates for either; the
daemon only tells you that one exists (`yadorilink update status`).

For a command-line (script) install, you do, with:

```sh
yadorilink self-update              # the newest version your channel allows
yadorilink self-update --version 1.2.0
```

`self-update` asks the running daemon, which holds the verified channel
manifest, whether the version is allowed. If it is, `self-update` prints the
installer command to run, pinned to that version and to your prefix. Run that
command: the installer repeats every check and switches versions in one step,
and keeps the previous version on disk until the next update. `self-update`
itself downloads and installs nothing.

- A plain `self-update` waits for the staged rollout. If a newer version is
  not yet offered to you, it says so; `--version` installs it anyway.
- A version that was withdrawn, or is below the minimum supported version, is
  refused (exit code 4) before anything is downloaded.
- If the check cannot be completed (no network, a manifest that does not
  verify), `self-update` says so and does not claim you are up to date.
- The daemon only tells you that an update exists
  (`yadorilink update status`); it never installs anything.

## How do I pin a version? Can I go back to an older one?

For the Linux package or an engine bundle, you choose the version by choosing
the file you install; releases before 1.0 do not promise that an older version
can open data a newer one wrote (see the downgrade note below). For the
one-line installer:

Run the installer with `--version X.Y.Z` (`-Version` on Windows, or the
`YADORILINK_VERSION` environment variable). It installs exactly that version
from the signed per-version manifest, and still refuses it if the live channel
manifest has withdrawn it or it is below the minimum supported version.
`--force` reinstalls the same version.

Downgrading is not supported. The installer does not replace an installed
version with an older one, even with `--version`: it stops with exit code 6 and
changes nothing, because it cannot know that an older version can open the data
the newer one wrote. Uninstalling and reinstalling is not a safe way around
this either, since the data that is kept may not open with the older version.
If you must roll back by hand, back up YadoriLink's data directory first, and
expect that you may have to set the device up again. On a machine with nothing
installed, `--version` can install an older version.

Your other devices should run the same version as this one.

## What happens to my files if I uninstall?

Your synced folders stay where they are, always. Uninstalling removes the
YadoriLink programs, not the folders you synced. YadoriLink also keeps its own
data directory (the device identity, the sync database, saved versions of your
files and downloaded content), so a later reinstall continues as the same
device. Nothing is deleted from your other devices, and nothing is changed in
your account.

The data directory is:

| OS | Data directory |
|---|---|
| macOS | `~/Library/Application Support/yadorilink` |
| Windows | `%USERPROFILE%\.yadorilink` |
| Linux | `~/.local/share/yadorilink` (or `$XDG_DATA_HOME/yadorilink`) |

`YADORILINK_CONFIG_DIR` moves it. It can be large, because it holds saved
versions and downloaded content. Your sign-in is kept separately: in the
macOS Keychain or the Windows Credential Manager, and on Linux in
`credentials.json` inside the data directory.

## How do I uninstall?

First, optionally, disconnect this computer from your account (see the next
question). Then follow the row for how you installed.

**Linux package (`.deb`).**

```sh
systemctl --user disable --now yadorilink-daemon
sudo apt remove yadorilink
```

Removing the package alone does not stop a background service you enabled for
your own user, so disable it first. In a repository checkout, `./uninstall.sh`
does both, and `./uninstall.sh --purge-data` also removes the data directory.

**Engine bundle you unpacked.** Run `yadorilink daemon stop`, delete the
folder you unpacked it into and the `PATH` entry you added. There is nothing
else to remove: the bundle installs no service, scheduled task or shell
extension. `yadorilink uninstall` refuses this install (exit code 19) because
it did not put it there.

**One-line installer.**

```sh
yadorilink uninstall --dry-run      # shows what would be removed, changes nothing
yadorilink uninstall                # asks first; --yes skips the question
```

On Windows, run the installer with `-Uninstall`; `sh install.sh --uninstall`
works anywhere the shell installer did.

- Removed: the `yadorilink` and `yadorilink-daemon` links, the installed
  program files (`<prefix>/share/yadorilink`), and the PATH lines the
  installer added. The daemon is stopped first.
- Kept: your synced folders, and the data directory.
- The command refuses, and removes nothing, if it cannot tell that your
  synced folders are safe: for example a folder that lives inside the
  program directory, or a folder registry that cannot be read. `--yes` does
  not override that check.
- Files that were never downloaded (On-Demand files, which need a desktop app
  and so do not exist in the engine-only release) cannot be opened on this
  computer once YadoriLink is gone. The command counts them and refuses
  without `--yes` when there are any, or when it cannot count.

If the installation record is missing or unreadable, `uninstall` says so and
removes nothing; `yadorilink doctor` shows the fix. Any other install that
`yadorilink uninstall` finds (a package manager, an app, a container) is also
refused with exit code 19 and the owner's own step, for example
`brew uninstall --cask yadorilink` or `winget uninstall yadorilink`; those
channels are not published yet.

## How do I also delete YadoriLink's data?

Only on purpose, and it never deletes your synced folders:

- Script install on macOS or Linux: `yadorilink uninstall --purge-data`
  deletes the data directory after asking.
- Linux package: `./uninstall.sh --purge-data` from a repository checkout, or
  delete `~/.local/share/yadorilink`. If you moved the data directory with
  `XDG_DATA_HOME` or `YADORILINK_CONFIG_DIR`, delete the directory actually in
  use.
- Anywhere else (the unpacked bundle, Windows): run `yadorilink daemon stop`,
  then delete the data directory by hand.

On macOS and Windows your sign-in lives outside the data directory.
`yadorilink uninstall --purge-data` removes it along with the data directory
(if a copy of the device key cannot be removed, it stops before deleting the
data directory and says what remains). If you delete
the data directory by hand instead, run `yadorilink credentials purge` first
(add `yadorilink logout` before it to also revoke the device); deleting the
directory alone does not clear it. On Linux
the default sign-in file is inside the data directory and goes with it. A Secret
Service entry, if you configured one, is not removed by any script: delete it in
your keyring manager.

Deleting the data directory removes the saved versions and downloaded content
that no other device may hold, so check your other devices first.

## Is my computer still connected to my account after uninstalling?

Yes. Uninstalling does not sign you out or tell the service anything, so the
computer stays listed under your account. Run
`yadorilink logout` before you uninstall to disconnect this computer, or
remove it from another device with `yadorilink device remove <device-id>`.
Files already on a removed device stay there.

## Will reinstalling restore everything?

If you kept the data directory, a reinstall continues as the same device: the
identity, folders and history are reused, and you may only need to sign in
again. If you purged it, a reinstall is a first install: YadoriLink sets the
computer up as a new device and fetches your files again from your other
devices. If the data directory is a restored backup or a copy, YadoriLink
refuses to sign changes and reports `database_restored`; `yadorilink device
start-over` is the way out and keeps your files and history.

## What do the installer's exit codes mean?

| Code | Meaning |
|---|---|
| 0 | done, or already up to date |
| 1 | other failure |
| 2 | wrong usage (unknown option, missing file for `--from`) |
| 3 | could not reach the network |
| 4 | signature, hash, replay or withdrawal check refused the release |
| 5 | unsupported operating system or CPU |
| 6 | refused to replace the installed version with an older one |
| 7 | the install directory is not writable |
| 19 | (`yadorilink self-update` / `uninstall`) this install is managed by another tool |
