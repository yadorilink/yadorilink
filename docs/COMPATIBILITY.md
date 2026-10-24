# Version compatibility policy

This is the current policy for the pre-1.0 line. It can change before 1.0, and
any change will be announced in the release notes.

## Versions must match exactly

All of a user's devices should run the same release. YadoriLink does not
negotiate between protocol generations and does not promise that a release
works with the one before it. Update every device together.

## A protocol change is an announced product event

A release that changes a protocol generation says so in its release notes and
adds a line to [CUTOVER.md](CUTOVER.md). The signed update manifest's
`minimum_supported_version` is the single cutover marker: a client older than it
is told that an update is required.

## What you see during a version mismatch

A device on a different version is reported as reachable but incompatible, with
an "update required" message. It is never shown as offline, because it is online
and the fix is to update, not to wait. Sync with it pauses until the versions
match again. Nothing is deleted or reclaimed because of the pause.

## Safety-critical operations fail closed

Storage custody, handoff, space reclaim, and demote, unlink, remove or revoke
of a device only count a peer whose version and capabilities are known and
match. A peer whose version is unknown or different is excluded, and the
operation waits or is refused instead of proceeding. An unsupported capability
never reads as "false" or as success.

## Local state

The local state database is not migrated before 1.0. A release that changes the
schema requires recreating local state, and the release notes say so. A newer
database is never opened by an older build, and an older database is never
opened by a newer build.

## Local components

The app, the command line tool, the background service and the shell
integrations must come from the same release. A partially updated install is
rejected with a message asking to restart or finish updating.

## Rolling upgrade contract

This section states exactly what happens while some of your devices run a newer or
older release than others. It applies to the pre-1.0 line, including
v0.1.0-beta.3, and complements the policy above and [CUTOVER.md](CUTOVER.md) (the generation
ledger). The rule is simple: **there is no mixed-version operation.** Devices on different
protocol generations do not sync with each other. They refuse each other
cleanly, and nothing is lost while they wait for the update.

Every statement below names the code that enforces it and the test that pins
it.

### What a newer or older peer may do

Nothing that changes your data. Concretely:

| Rule | What happens | Code | Test |
| --- | --- | --- | --- |
| Peer lane hello must match `PROTOCOL_VERSION` exactly (older or newer) | The lane is refused before any frame is read | `crates/yadorilink-sync-protocol/src/wire.rs` | `wire/tests.rs` (older, newer) |
| A hello may not carry extra bytes, even at the same version | Refused. The hello has no extension point, so a newer build cannot add a field without a version bump | `wire.rs` | `a_hello_with_extra_bytes_at_the_current_version_is_refused` |
| Service RPC (custody, handoff, durability) must match `RPC_VERSION` exactly, for requests and answers | Decode fails; trailing bytes are refused too | `crates/yadorilink-peer-session/src/service_rpc.rs` | `a_response_of_another_generation_or_unknown_kind_never_decodes`, `trailing_bytes_are_rejected` |
| An unknown RPC kind is refused, not guessed | Decode fails | `service_rpc.rs` | `an_unknown_kind_is_refused_not_guessed` |
| A stream whose lane tag is unknown is dropped | Later streams keep working | `crates/yadorilink-sync-runtime/src/runtime.rs` | `a_stream_with_an_unknown_lane_tag_does_not_stop_later_streams_being_served` |
| Local state database must match `SCHEMA_VERSION` exactly, in both directions | Older and newer databases are refused; nothing is migrated | `crates/yadorilink-sqlite-runtime/src/schema.rs` | `schema/tests.rs` (below, above) |
| App and daemon control protocol must match exactly | The request is rejected before any state is touched | `crates/yadorilink-daemon/src/control_socket.rs` | `identify_wire_tests.rs`, `migration_safety_tests.rs` |

Consequences for additive changes: this release makes no promise that unknown
fields or new message kinds are ignored. Any wire change, additive or not,
bumps a generation constant and is a cutover (see CUTOVER.md). Messages an
old peer "ignores" do not exist in this contract; an old peer refuses.

### What fails closed

A peer that sent a lane hello or a service RPC of another version, or answered
one with another version, is recorded as version incompatible
(`crates/yadorilink-sync-runtime/src/runtime.rs`,
`crates/yadorilink-daemon/src/sync_adapter/sync_stack.rs`,
`crates/yadorilink-peer-session/src/peer_session/service.rs`). From then on:

- It is not counted as a content holder for reclaim, handoff, durability or
  custody leases (`crates/yadorilink-daemon/src/peer_registry.rs`, used at
  `background_custody.rs` and `daemon_state.rs`). Reclaim
  waits instead of deleting. Test:
  `a_version_incompatible_full_replica_is_excluded_from_every_custody_set`.
- Its answers never read as success. A yes from another generation, an answer
  of an unknown kind, or an answer of a kind that was not asked for, is "no
  answer". Test:
  `a_peer_answering_from_another_generation_or_with_an_unknown_kind_never_reads_as_success`.
- The mismatch is cleared only when that connection ends and a matching one is
  up (same custody test).

### What "update required" means

The peer is online and reachable, but on a different generation. It is
reported as update required, never offline
(`crates/yadorilink-daemon/src/control_socket/status_dimensions.rs`,
`control_socket.rs`). The fix is to update, not to wait. Tests:
`a_peer_on_another_protocol_version_is_incompatible_and_still_reachable`,
`version_mismatched_peer_is_update_required_never_offline`.

A device whose own version is below the signed manifest's
`minimum_supported_version` is also told an update is required
(`crates/yadorilink-daemon/src/update/policy.rs`; test
`a_client_below_the_minimum_supported_version_is_update_required`), and an
install of a version below the minimum is refused
(`crates/yadorilink-daemon/src/update/manifest.rs`, `BelowMinimum`).

### Downgrade

An update entry at or below the running version is never selected
(`manifest/tests.rs`: `downgrade_entry_is_never_selected`). A pinned install of
a withdrawn, kill-switched or below-minimum version is refused
(`manifest.rs`). A database written by a newer build is never opened by an
older one (table above). Going back to an older release therefore means
installing it on every device and recreating local state when the schema
differs; the release notes say when.

### Minimum supported version for v0.1.0-beta.3

v0.1.0-beta.3 is the first public release, on generation
(`PROTOCOL_VERSION` 4, `RPC_VERSION` 2, `SCHEMA_VERSION` 132). No earlier
public build exists, so no older peer is supported and none is promised. The release tooling refuses a
manifest whose minimum is below the first release of the generation it
carries (`.github/release/channel_ledger.py`). Compatibility with a
previous public package is not claimed until a second public release exists
and is tested against the first.
