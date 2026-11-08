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

- Generation PROTOCOL_VERSION = 4, RPC_VERSION = 4: first release 0.1.0-beta.9

The first public release carrying generation (4, 2) was v0.1.0-beta.5; beta.6, beta.7 and beta.8 carry
the same generation. The service RPC then moved to 3 and 4 (and the state schema to 138), so v0.1.0-beta.9
is the first release of generation (4, 4): a device on an older release cannot synchronise with it, and the
beta channel's `minimum_supported_version` is set to 0.1.0-beta.9 when it is served.
- SCHEMA_VERSION = 133: adds the ledger of file windows served to the OS (lets a large file read through the OS partial-content API be freed); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 134: adds the recent-activity log (the Activity view lists added, updated, deleted, conflicted and restored files); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 135: only the execute bit of a file is synchronised and extended attributes are not (the native protocol generation is now 10, the file version tag changed); the local state of every device is not migrated before 1.0, so it must be recreated, and every device must be updated together. Before updating, save what `yadorilink preserved list` shows.
- SCHEMA_VERSION = 137: the write-intent journal records the temp file whose directory entry was flushed before a batched receive's rename, so a file the user deletes while that flush is still owed stays deleted after a power cut; local state is not migrated before 1.0, so the local state must be recreated. Before updating, save what `yadorilink preserved list` shows.
- SCHEMA_VERSION = 138: adds the table that keeps when each peer was last connected (a device that is away shows when it was last seen); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 139: the write-intent journal gains a `phase` column that records how far a write operation got (nothing writes it yet); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 140: the write-intent journal records how far each write got (prepared, landed, flush pending) and no longer records the temp file of a batched receive; a file the user deletes in the short window between a batched receive's rename and its flush, when the machine also loses power in that window, comes back after the restart instead of staying deleted (no bytes are lost); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 141: the write-intent journal gets a `delete` kind for a tombstone delete's intent, which no longer borrows a marker in the content-hash column; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 142: the record of versions that are no longer kept accepts a new reason, for versions dropped because the older versions kept on the device outgrew the space set aside for them; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 148: the namespace trie behind the summary root is patched from the heads that changed when a summary or a seal wants it, not on every head write, and a database made by schema 144 keeps its old trie triggers; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 144: the namespace trie behind the summary root is stored with the group's heads and patched with them, instead of being rebuilt in memory for every summary; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 145: the write-intent journal records the temp file a write will publish, so an interrupted received write is finished from that file instead of fetched again; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 146: a provider folder can be marked publish-only on the device (a new column on its state row); local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 149: a new table records, per group and peer, how much of this device's own history the peer last named in a frontier request, so the number of changes no other device has yet can be reported; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 150: the `pinned_items` table becomes `retention_rules` (a rule per path, `keep` or `online_only`, with a generation) and a per-group generation counter table; pins set before the update are not carried over and are set again by hand; local state is not migrated before 1.0, so the local state must be recreated.
- SCHEMA_VERSION = 151: `retention_rules` gains the apply pass's claim time, re-arm count and per-rule counts (done, skipped, retryable); local state is not migrated before 1.0, so the local state must be recreated.
- RPC_VERSION = 3: the group durability summary carries how many current rows the responder holds only in its folder, not in its block store (a peer whose copy is a file alone no longer corroborates `Protected`); a service RPC with any other version is an error, so every device updates together. The generation line above gets its release when the release record names it.
- RPC_VERSION = 4: the answers to a version-present query and to a custody acquire are three-valued (held, not held, in progress), so a responder that is still reading a large version back is waited for instead of timing out; a service RPC with any other version is an error, so every device updates together.
