# Command-line installers

`install.sh` (macOS on Apple silicon, Linux x86_64) and `install.ps1` (Windows
x64) install the engine (`yadorilink`, `yadorilink-daemon`) under the user's
home directory, after checking the signed release manifest and every hash. User
documentation is in [`INSTALL_FAQ.md`](../../docs/INSTALL_FAQ.md); the header comment of each
script is the option reference.

## Tests

| What | How | Programs |
|---|---|---|
| Installer behaviour, refusals, exit codes (macOS/Linux) | `sh tests/run-tests.sh` | stand-in scripts that print a version |
| Same for Windows | `tests/windows/Run-Tests.ps1` | stand-in console exe |
| Acceptance with the real programs (macOS/Linux) | `sh tests/acceptance.sh --bin-dir DIR` | real `yadorilink`, `yadorilink-daemon` |
| Same in a clean Debian/Ubuntu container | `sh tests/acceptance-container.sh IMAGE DIR` | real |
| Acceptance with the real programs (Windows) | `tests/windows/Run-Acceptance.ps1 -BinDir DIR` | real |

Everything runs against a local fixture release (`tests/build-fixture.py`, signed
with a throw-away test key, served from `127.0.0.1` by `tests/serve.py`) under a
temporary directory. The installers' test hooks work only with
`YADORILINK_INSTALL_TEST=1`; the real trust root and endpoints are never used,
and nothing touches the network or the real signing keys.

The acceptance scripts check what stand-ins cannot: after a script install the
real daemon reports `install_source=script` and records it in the ownership
record, `yadorilink self-update` judges versions against the daemon's verified
manifest, a tampered archive or manifest, a manifest signed by another key, a
withdrawn or kill-switched version, a replayed manifest and a downgrade (even with an explicit
`--version`; downgrading an existing install is unsupported) are all
refused with the existing install unchanged, and `yadorilink uninstall` (Windows:
`install.ps1 -Uninstall`) removes the programs and keeps the user's data.

### Building the programs for the acceptance scripts

The daemon verifies manifests against a key compiled into it, so the programs
must be built with the fixture's test key as that trust root. The key below is
the public half of the fixture's throw-away test key; the private half is the
fixed test seed in `build-fixture.py`:

```sh
export YADORILINK_RELEASE_MANIFEST_KEY_ID=yadorilink-test-key
export YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX=06b77fc89d2b9785433dd37a9b98a3c8fa37f03db2b2cc0e79be76f87b223d21
cargo build -p yadorilink-cli
cargo build -p yadorilink-daemon --features enforce-release-trust-root
```

Build them in two invocations (with several `-p` packages cargo does not apply
the daemon's feature). For a container run, build in the oldest image you test
(glibc is not forward-compatible), then copy `yadorilink` and
`yadorilink-daemon` into one directory. Binaries built this way trust only the
test key and must never be shipped.
