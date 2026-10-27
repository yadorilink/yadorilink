# Cutover notes

Devices of one account must run matching versions. Changing any protocol
generation constant is therefore a coordinated cutover: users must update every
device together. `.github/checks/check-cutover-note.py` fails the build unless
this file has a line for the current value of each constant:

    - NAME = VALUE: what changed and what users must do

Tracked constants: `PROTOCOL_VERSION` (peer lane hello), `RPC_VERSION`
(peer service RPC), `SCHEMA_VERSION` (local state database). Keep older lines;
add a new one on each change.

`CONTROL_PROTOCOL_VERSION` (local app/daemon control) is exempt before 1.0. The
app and daemon ship in one package and are updated together, so a bump is never
a cross-device cutover and asks nothing of users; it changes often during
development. It keeps one standing line instead of a line per value, and the
guard still reads the constant from source. The exemption ends at 1.0, or
earlier if the control socket ever becomes reachable across devices. The
cross-device marker is the manifest `minimum_supported_version` (see
"Generation floor"), which is derived from the (`PROTOCOL_VERSION`,
`RPC_VERSION`) pair only. See [COMPATIBILITY.md](COMPATIBILITY.md) for the policy.

## Current generation

- PROTOCOL_VERSION = 4: baseline for the pre-1.0 line; peers on any other value are refused at the lane handshake.
- RPC_VERSION = 2: baseline; a service RPC with any other version is an error.
- CONTROL_PROTOCOL_VERSION: local app<->daemon only; not a cutover before 1.0
- SCHEMA_VERSION = 132: baseline; local state is not migrated before 1.0, so a schema change means the local state must be recreated.

## Generation floor

The signed update manifest's `minimum_supported_version` is the single cutover
marker: a client below it is told that an update is required. Release tooling
(`.github/release/generate-update-manifest.py`) refuses to publish a manifest
whose minimum is below the first release of the protocol generation it carries,
and refuses to run when the current generation has no line here. The peer-facing
generation is the pair (`PROTOCOL_VERSION`, `RPC_VERSION`); when either changes,
add a line naming the release that first carries the new pair:

    - Generation PROTOCOL_VERSION = N, RPC_VERSION = M: first release X.Y.Z

- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.0.0

The `0.0.0` above is a placeholder for the release tooling, not a release: it
means this generation sets no floor above the lowest version. The first public
release carrying generation (4, 2) is v0.1.0-beta.5, and beta.6 and beta.7 carry
the same generation. The machine-read line is left as is.
- SCHEMA_VERSION = 133: adds the ledger of file windows served to the OS (lets a large file read through the OS partial-content API be freed); local state is not migrated before 1.0, so the local state must be recreated.
