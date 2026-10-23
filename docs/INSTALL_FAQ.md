# Install, update and uninstall: FAQ

Answers for the command-line (engine) install. The desktop apps and the Linux
package have their own instructions; see the [README](../README.md#installing) and the
[Linux README](../packaging/linux/README.md).

Status: the one-line installers described below are built and tested but are
not published yet (see "Planned" in the README). Until they are, install from
the Linux package or an engine bundle. Everything here describes how the
installers behave, so you can read it before you run one.

## Which way should I install?

| You use | Install with | Updated by |
|---|---|---|
| macOS or Windows desktop app | the app | the app (Check for Updates, or the Store) |
| Debian / Ubuntu | the `.deb` | `apt` |
| Any other command-line use (macOS on Apple silicon, Linux x86_64, Windows x64) | the one-line installer | `yadorilink self-update` |
| An engine bundle you unpacked yourself | you | you |

Whichever way you install, that way is also the one that updates and removes
it. YadoriLink does not update an install that something else owns: the other
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

## What does uninstalling remove, and what does it keep?

```sh
yadorilink uninstall --dry-run      # shows what would be removed, changes nothing
yadorilink uninstall                # asks first; --yes skips the question
```

On Windows, run the installer with `-Uninstall`; `sh install.sh --uninstall`
works anywhere the shell installer did.

- Removed: the `yadorilink` and `yadorilink-daemon` links, the installed
  program files (`<prefix>/share/yadorilink`), and the PATH lines the
  installer added. The daemon is stopped first.
- Kept: your synced folders, always, and YadoriLink's own data directory (the
  device identity, sync database, saved versions, downloaded content and
  sign-in), so a later reinstall continues as the same device.
- `yadorilink uninstall --purge-data` also deletes the data directory, after
  asking. That is the only way uninstalling deletes it, and it never deletes
  synced folders. Saved versions and downloaded content that no other device
  holds are lost.
- The command refuses, and removes nothing, if it cannot tell that your
  synced folders are safe: for example a folder that lives inside the
  program directory, or a folder registry that cannot be read. `--yes` does
  not override that check.
- If you use On-Demand files, files that were never downloaded cannot be
  opened here once YadoriLink is gone. The command counts them and refuses
  without `--yes` when there are any, or when it cannot count.

## Is my computer still connected to my account after uninstalling?

Yes. Uninstalling does not sign you out or tell the service anything. Run
`yadorilink logout` before you uninstall to disconnect this computer, or
remove it from another device with `yadorilink device remove <device-id>`.
Files already on a removed device stay there.

## Will reinstalling restore everything?

If you kept the data directory, yes: the same device, folders and history
come back, and you may only need to sign in. If you purged it, a reinstall is
a first install: YadoriLink sets the computer up as a new device and fetches
your files again from your other devices.

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
