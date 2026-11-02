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

- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 4: first release 0.0.0

The `0.0.0` above is a placeholder for the release tooling, not a release: it
means this generation sets no floor above the lowest version. The first public
release carrying generation (4, 2) is v0.1.0-beta.5, and beta.6 and beta.7 carry
the same generation. The service RPC moved to 3 and then 4 after that, so the line names
(4, 4); the release that first carries it is set when its release record is written.
The machine-read line keeps the placeholder until then.
- SCHEMA_VERSION = 133: adds the ledger of file windows served to the OS (lets a large file read through the OS partial-content API be freed); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 134: adds the recent-activity log (the Activity view lists added, updated, deleted, conflicted and restored files); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 135: only the execute bit of a file is synchronised and extended attributes are not (the native protocol generation is now 10, the file version tag changed); the local state of every device is not migrated before 1.0, so it must be recreated, and every device must be updated together. Before updating, save what `yadorilink preserved list` shows.
- SCHEMA_VERSION = 137: the write-intent journal records the temp file whose directory entry was flushed before a batched receive's rename, so a file the user deletes while that flush is still owed stays deleted after a power cut; local state is not migrated before 1.0, so the local state must be recreated. Before updating, save what `yadorilink preserved list` shows.
- SCHEMA_VERSION = 138: adds the table that keeps when each peer was last connected (a device that is away shows when it was last seen); local state is not migrated before 1.0, so the local state must be recreated.
- RPC_VERSION = 3: the group durability summary carries how many current rows the responder holds only in its folder, not in its block store (a peer whose copy is a file alone no longer corroborates `Protected`); a service RPC with any other version is an error, so every device updates together. The generation line above gets its release when the release record names it.
- RPC_VERSION = 4: the answers to a version-present query and to a custody acquire are three-valued (held, not held, in progress), so a responder that is still reading a large version back is waited for instead of timing out; a service RPC with any other version is an error, so every device updates together.
