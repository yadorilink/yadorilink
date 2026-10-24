# Data-safety invariants

This document states which data-safety decisions YadoriLink makes, where in
this repository each one is made, and which tests and checks exercise it. It
describes shipped behavior. A statement marked **Goal** is intended but not
enforced yet, and says what is missing.

It is not a proof. Source being open does not make an implementation correct;
it lets you read the rule, find the code that enforces it, and rerun the tests.
The tests are evidence, not a formal verification, and nothing here promises
that data cannot be lost. A mechanical check
(`.github/checks/check-safety-invariants-doc.py`) fails when a file or test
named below no longer exists.

## 1. Who decides

Every decision that can delete, overwrite, hide or release user data is made by
the engine: the daemon and the crates under `crates/`. Front ends (the command
line, the official desktop apps, the Finder and Explorer integrations) collect
the user's intent, ask the engine for an operation, and display the answer.

- A front end may not decide that a copy is disposable, that a conflict has a
  winner, that a peer is trustworthy, or that stale information is fresh
  enough to act on.
- A front end may perform an operating-system action that removes or replaces
  data only for a plan or result the engine returned for that request.
- The engine answers with a typed outcome (allowed, refused with a reason,
  waiting, stale, failed). For a destructive decision, missing, unknown or
  unreadable evidence is an answer of "no", never "yes".

Section 4 says what holds today and what is still a goal.

## 2. Decisions the engine owns

Each subsection gives the rule, the code that makes the decision, the tests and
checks that exercise it, and what the rule does not cover.

### 2.1 Releasing local content (Free Up Space, eviction)

**Rule.** A device releases the bytes of a version only after an authorized
full replica has confirmed that it durably holds exactly that version (same
version hash, block list and sizes). Just before any block is removed, the
engine rechecks the current version, the materialization state, the pin, the
custody confirmation and every other reference to the block, under the
exclusive deletion guard. A check that fails or cannot be read frees nothing.
Which actions a front end may offer is computed by the engine too, and an
unknown state offers nothing.

**Enforced by.**
`crates/yadorilink-replica-engine/src/custody.rs` (a `VerifiedCustody` can only
be obtained from `verify_reclaim_custody`),
`crates/yadorilink-daemon/src/replica_coordinator/block_reclamation.rs`,
`crates/yadorilink-filesystem-sync/src/block_liveness.rs`,
`crates/yadorilink-filesystem-sync/src/materialization_eviction.rs`,
`crates/yadorilink-daemon/src/provider_reclaim.rs` (the block-store half of a
provider item the operating system no longer holds),
`crates/yadorilink-daemon/src/file_actions.rs`.
Check: `.github/checks/check-block-deletion-boundary.py` fails if production code
deletes blocks outside the two gated owners.

**Tests.** `eviction_must_not_delete_block_used_by_hydrated_file_in_another_group`,
`concurrent_evictions_across_groups_must_preserve_shared_block`,
`custody_evict_e2e.rs`, `custody_version_present.rs`, `custody_lease.rs`
(under `crates/yadorilink-daemon/tests/`),
`crates/yadorilink-filesystem-sync/tests/dst_eviction_crash_recovery.rs`.

**Does not cover.** The operating system owns the local bytes of a provider
folder; a user's own "Remove Download" acts on those bytes without the engine,
and the engine then keeps its own blocks unless custody is verified. A full
replica never reclaims its blocks. Deleting local bytes also requires the
volume to offer a durable namespace (section 3).

### 2.2 Losing a full-replica role (demote, unlink, revoke, remove a device)

**Rule.** A device does not give up its full-replica role while it holds the
only complete copy. The operation first confirms that another device holds
every current version, and records a journal entry so an interrupted or
ambiguous operation is compensated or retried instead of half-applied. Unlink
has an explicit `--force` override for a sole replica that is gone; every use is
logged, and a forced unlink latches the group as "durability unknown", which
survives a restart until a positive whole-group confirmation clears it. Demote
has no force path. A peer recorded as running another protocol version is
not counted as a holder; a peer that has not answered confirms nothing.

**Enforced by.**
`crates/yadorilink-daemon/src/application/replica_role_service.rs`
(`ensure_unlink_keeps_a_full_replica` and the role-loss journal),
`crates/yadorilink-daemon/src/custody_handoff.rs` (leases handed off before a
responder stops being a full replica),
`crates/yadorilink-daemon/src/peer_registry.rs`
(`peer_is_version_compatible`),
`crates/yadorilink-sync-sqlite/src/role_loss_operation.rs`.
The full list of rules (DL-2, DL-5, DL-6, DL-7) with symbols and test IDs is in
`crates/yadorilink-daemon/DURABILITY.md`.

**Tests.** `last_full_replica_cannot_unlink`, `unlink_refused_when_no_other_replica_is_ready`,
`demotion_refused_when_the_target_cannot_grant_a_lease`,
`ambiguous_demote_keeps_prepared_journal`,
`forced_durability_unknown_latch_survives_daemon_restart`,
`forced_unlink_latches_group_durability_unknown`,
`full_replica_handoff_ready.rs`, `unlink_and_removal_durability.rs`,
`role_loss_saga.rs`, `removed_device_handoff_ticket.rs`
(under `crates/yadorilink-daemon/tests/`).

**Does not cover.** A forced unlink can remove the last holder by design; the
guarantee is that it is explicit and remembered, not that it cannot happen.
Membership and device removal on the coordination service are decided by that
service, which is not part of this repository.

### 2.3 Garbage collection and block custody

**Rule.** Physical block deletion has two owners (the unreferenced-block sweep
and custody-verified eviction), and both require the exclusive
`BlockPhysicalDeletionGuard`. The guard proves that no write that adds a
reference to a block is in flight. Liveness is computed from the index at sweep
time rather than from counters, a block newer than the grace window is never
swept, and a sweep that crashes midway leaves a state the next sweep finishes.
A custody lease that a responder has granted is a live root for its GC.

**Enforced by.**
`crates/yadorilink-filesystem-sync/src/block_deletion.rs`
(`sweep_globally_unreferenced_blocks`),
`crates/yadorilink-filesystem-sync/src/block_liveness.rs`,
`crates/yadorilink-daemon/src/gc.rs`,
`crates/yadorilink-sync-sqlite/src/remote_custody_lease.rs`,
`crates/yadorilink-sync-sqlite/src/remote_custody_hold.rs`.

**Tests.** `gc_must_not_delete_old_deduplicated_block_adopted_after_live_snapshot`,
`eager_adoption_waits_for_the_block_deletion_gate_before_committing_a_reference`,
`concurrent_evictions_across_groups_must_preserve_shared_block`,
`custody_lease.rs`.

### 2.4 Materialization: intent, ledger and startup repair

**Rule.** Writing content into the user's folder is bracketed by a journal so
that, after a crash, the engine can tell an interrupted write from a deletion
the user made while the daemon was stopped. A file is first assembled in a
temp file, flushed, then renamed into place; a durable intent is recorded
before the bytes are written and cleared only after the rename. Every
content-writing path uses one of three journals (the intent journal, the
placeholder-to-present flip made after the rename, or the restore journal).
On startup, repair reconstructs a file whose blocks are all present, demotes a
file with missing blocks to a placeholder that is fetched again, does not
resurrect a file whose write had finished and which was then deleted offline,
and, when an intent was open and the bytes on disk differ from anything the
record explains, moves them to a conflict-named path instead of overwriting
them. While the daemon is running, repair never
quarantines or tombstones on its own, because an observed difference may be a
user's edit in progress; it hands the path to the local-change journal.
Recovery works from these durable records, not from how the folder looks.

**Enforced by.**
`crates/yadorilink-filesystem-sync/src/materialization_repair.rs`
(`repair_interrupted_materializations`, `RepairMode`),
`crates/yadorilink-daemon/src/materialization_intent.rs`,
`crates/yadorilink-sync-sqlite/src/materialization_intent_repository.rs`,
`crates/yadorilink-sync-sqlite/src/projection_obligations.rs`,
`crates/yadorilink-sync-sqlite/src/restore_operation.rs`,
`crates/yadorilink-local-storage/src/materialize_write.rs`.
Checks: `.github/checks/check-materialization-journal.py`,
`.github/checks/check-materialization-semantic-boundary.py`,
`.github/checks/check-mutation-boundary.py` (every local change to a file row
also appends the signed change in the same transaction),
`.github/checks/check-durable-namespace.py`.

**Tests.** `repair_reconstructs_locally_after_a_simulated_crash_before_rename`,
`repair_demotes_to_placeholder_when_blocks_are_also_missing_locally`,
`crates/yadorilink-filesystem-sync/tests/dst_materialization_crash_recovery.rs`,
`offline_delete_no_peer_convergence.rs`, `unservable_block_adoption.rs`,
`rewind_crash_failpoints.rs` (under `crates/yadorilink-daemon/tests/`).

### 2.5 Conflicts and "Keep this"

**Rule.** When two devices change the same path without having seen each
other's change, neither version is dropped. The version with the larger
version key keeps the name; the other is moved by its own author to a copy
path that is a pure function of the path and the version, so every replica
computes the same name. An author's set of heads at a path is bounded, and a
bounded bucket that cannot take a new version refuses instead of dropping one.
When a delete and an edit are concurrent, the edit survives, either at the
original name or as a conflict copy.
"Keep this" writes the copy's recorded content at the original name through
the guarded restore write and authors it as a new version, so the replaced
version stays in the file's history. The conflict copy itself is never moved,
renamed or deleted by the engine; it is removed only by the user. "Keep both"
moves the copy with a no-replace move and never overwrites a name that is
taken. Both actions re-read every precondition when they run; "Keep this" refuses,
with nothing changed, while the original holds edits that have not been
recorded yet.

**Enforced by.**
`crates/yadorilink-replica-domain/src/native_project.rs` (a contested path is
`Pending`, derived from replicated state only),
`crates/yadorilink-replica-domain/src/native_fork.rs` (`copy_path`, the plan
that moves a losing head),
`crates/yadorilink-replica-domain/src/conflict.rs`,
`crates/yadorilink-daemon/src/conflict_resolution.rs`.

**Tests.** `crates/yadorilink-replica-domain/src/native_fork/tests.rs`,
`the_copy_name_is_a_pure_function_of_path_and_version`,
`a_full_bucket_of_unrelated_equal_heads_refuses_instead_of_dropping`,
`partition_paused_device_edit_vs_online_device_delete_preserves_the_unobserved_edit`,
`keep_this_replaces_the_original_and_leaves_the_copy_alone`,
`keep_this_refuses_while_the_original_has_an_unrecorded_edit`,
`keep_both_never_overwrites_an_existing_name`,
`conflict_resolution.rs`, `collision_matrix.rs`, `multiway_conflict_matrix.rs`,
`dst_sec_convergence.rs` (under `crates/yadorilink-daemon/tests/`).

**Does not cover.** The rule keeps every distinct version; it does not decide
which one the user wanted.

### 2.6 Admission and authority

**Rule.** A change from another device is admitted only if one verification
function accepts it: the delta is signed by its author, it carries a proof of
authorization under a checkpoint the group's policy chain recognizes, the
checkpoint names the same group and device, and the delta continues its
author's chain (a gap holds the delta until its predecessor arrives). A path that collides with the
product's reserved names or cannot be stored faithfully on every platform is
refused. A peer cannot make this device write or delete outside the synced
folder, including through a symlink planted locally. When a membership update
revokes a peer, the daemon re-validates the group and the revoked peer's
sessions for it end.

**Enforced by.**
`crates/yadorilink-replica-domain/src/proof_carrying_delta.rs`
(`verify_proof_carrying_delta`),
`crates/yadorilink-replica-domain/src/authorization_checkpoint.rs`
(`verify_change_admission`),
`crates/yadorilink-replica-domain/src/admission.rs`,
`crates/yadorilink-sync-sqlite/src/native_admission.rs`,
`crates/yadorilink-local-storage/src/materialize_write.rs`
(`verify_write_target_within_root`).

**Tests.** `crates/yadorilink-replica-domain/src/proof_carrying_delta/tests.rs`,
`path_escape_defense.rs`, `revocation_end_to_end.rs`,
`viewer_editor_authorization_end_to_end.rs`
(under `crates/yadorilink-daemon/tests/`).

**Does not cover.** Issuing checkpoints and deciding membership are done by the
coordination service. The engine checks what it is given; it does not check the
service's decisions.

### 2.7 Stale observations do not author changes

**Rule.** An observation of the disk or of a provider (the operating system's
file-provider framework) is acted on only if it is still current when the
action commits. A provider edit is authored against the version the user saw,
not the current row; an edit that is not provably made from the current version
never replaces it and its bytes are kept as a conflict-named file. A delete is
bound to what the user saw: a folder that gained an entry since the view is
refused as stale. A late report from a removed provider root names an old root
id and is ignored. A hydration whose captured state is overtaken mid-fetch (a local edit, or a
newer version) fails instead of committing, and the row never claims a version
is present that the attempt did not write.

**Enforced by.**
`crates/yadorilink-sync-sqlite/src/provider_write.rs`,
`crates/yadorilink-sync-sqlite/src/provider.rs`,
`crates/yadorilink-sync-sqlite/src/materialized_generation.rs`,
`crates/yadorilink-daemon/src/hydration.rs`.

**Tests.** `an_edit_on_a_stale_or_unknown_base_never_touches_the_canonical_version`,
`a_file_delete_is_bound_to_what_the_user_saw`,
`a_replay_returns_the_stored_result_and_a_late_one_is_stale`,
`hydration_mid_fetch_races.rs` (under `crates/yadorilink-daemon/tests/`).

### 2.8 Reads that fail closed

**Rule.** A read of local state that fails is reported as a failure, never
turned into "absent" or "default", because the engine would act on the wrong
answer (re-author a file as new, treat a folder as unlinked, treat a corrupt
block list as an empty file). A block read back from the store is checked
against its hash; the bytes of a fetched version are verified per block and as
the assembled whole before a file is declared present. A record whose content
no peer can supply is stored as a retriable placeholder, never as present.

**Enforced by.** Checks: `.github/checks/check-index-read-fail-closed.py`,
`.github/checks/check-stored-blocklist-fail-closed.py`,
`.github/checks/check-link-enumeration-fail-closed.py`. Code:
`crates/yadorilink-local-storage/src/traits.rs` (`BlockStore::get` verifies the
checksum), `crates/yadorilink-daemon/src/hydration.rs` (`verify_assembled`).

**Tests.** `unservable_block_adoption.rs`, `custody_version_present.rs`,
`crates/yadorilink-local-storage/tests/segment_store_corruption.rs`
(under `crates/yadorilink-daemon/tests/` unless a path is given).

### 2.9 Restored or copied databases, and starting over

**Rule.** A database that is a restore of an older state, or a copy of another
installation's, must not keep authoring under the identity it carries.
The engine compares an installation witness kept outside the data set with the
one inside the database; a mismatch (or a witness it cannot read) refuses the
open and reports `database_restored`. Separately, a database that no longer
matches its sidecar or its machine, or that a peer reports as behind its own
author, mints a fresh author incarnation; the old author's history stays valid
and is never written to again. The recovery is "start over as a new device":
it needs explicit confirmation, is refused unless the daemon reports the
database as restored, keeps the user's files, retires the old identity and
registers a new device. Sending the request that the new device replaces the
old one is signed by the new device's key. Protection is shown as healthy only
when the service says so; an unreadable replacement record counts as present.

**Enforced by.**
`crates/yadorilink-daemon/src/install_witness.rs`,
`crates/yadorilink-sync-sqlite/src/author_incarnation.rs`,
`crates/yadorilink-client-core/src/ops/start_over.rs`,
`crates/yadorilink-client-core/src/ops/device_supersede.rs`,
`crates/yadorilink-local-storage/src/replacement_unconfirmed.rs`.

**Tests.** `database_restored.rs`, `start_over_not_rejoined.rs`
(under `crates/yadorilink-daemon/tests/`),
`crates/yadorilink-client-core/src/ops/device_supersede/tests.rs`.

**Does not cover.** A backup taken and restored within a single run of the
daemon leaves no trace for the witness to compare; only the peer check
(`own_author_ahead`) can notice it. A database copied to a different path reads
as a new installation.

### 2.10 Updates and migration

**Rule.** The daemon only reports that an update exists; it does not download
or install one. The manifest it reads is signed and verified before use, an
entry that is not strictly newer than the running version is never selected,
and a failed verification discards the manifest. The local database must match
the build's schema version exactly: a newer database is never opened by an
older build and an older one is never migrated or adopted. Devices of one
account must run the same release; a peer of another protocol version is
reported as reachable but incompatible, sync with it pauses, and nothing is
deleted or reclaimed because of the pause (see `COMPATIBILITY.md`). Release
tooling checks an engine artifact against its identity file.

**Enforced by.**
`crates/yadorilink-daemon/src/update/manifest.rs`,
`crates/yadorilink-daemon/src/update/manager.rs`,
`crates/yadorilink-sqlite-runtime/src/schema.rs`
(`check_schema_version_supported`), `.github/checks/check-engine-artifact.py`.

**Tests.** `crates/yadorilink-daemon/src/update/manifest/tests.rs`,
`update_manifest_fixture.rs` (under `crates/yadorilink-daemon/tests/`).

## 3. Durability model

What is durable, and when. "Durable" means the operation has asked the
operating system to put the bytes on stable storage and has not returned
before that call did.

- **Block store.** Blocks are appended to segment files and made durable with
  one barrier per group of blocks (group commit), not one per block. The rule
  is that the index never names a block whose bytes are not already durable:
  the segment is flushed, then the index transaction that maps it commits.
  Bytes whose transaction never committed are never served, and a crash at
  every commit boundary leaves a store whose index names only readable blocks.
  See `crates/yadorilink-local-storage/src/segment_store/mod.rs` and
  `crates/yadorilink-local-storage/src/segment_store/coordinator.rs`; tested by
  `crates/yadorilink-local-storage/tests/segment_store_crash.rs`.
- **SQLite state.** Every connection runs with `synchronous = FULL` in WAL
  mode, so an acknowledged commit survives an operating-system crash. On Apple
  platforms `fullfsync` and `checkpoint_fullfsync` are added, because a plain
  `fsync` there does not flush the drive's write cache; elsewhere they are off
  by default. See `crates/yadorilink-sqlite-runtime/src/database.rs`
  (`OpenOptions`, `apply_durability_pragmas`); tested by `fullfsync_pragmas` in
  `crates/yadorilink-sqlite-runtime/src/database/tests.rs`.
- **Materializing a file.** The temp file is written, its mtime is set, and it
  is flushed (`sync_all`) before the rename publishes it. On Unix the parent
  directories are then flushed; on Windows the namespace change is a
  write-through move (`MoveFileExW` with `MOVEFILE_WRITE_THROUGH`), used only on
  a local fixed NTFS volume whose probe passed. See
  `crates/yadorilink-local-storage/src/materialize_write.rs` and
  `crates/yadorilink-fs-platform/src/durable_dir.rs`. A model of what a power
  loss leaves behind, replayed over the steps an operation took, is in
  `crates/yadorilink-fs-platform/src/durable_dir/model.rs`.
- **Order across layers.** Blocks become durable first, then the index row that
  references them commits, then (for a materialization) the intent is recorded,
  the file is written, and the intent is cleared. A crash between any two
  steps is repaired from the records, section 2.4.

What is **not** guaranteed:

- Durability depends on the storage honoring flush requests. A drive or virtual
  disk that acknowledges a flush it did not perform defeats every rule here, and
  the Windows probe checks only that the operations work on the volume, not that
  the flush is honest.
- On Windows the engine deletes local bytes only on a volume whose probe passed
  and keeps them everywhere else. The Windows file-content flush is
  `FlushFileBuffers` (what `sync_all` maps to there), and no directory flush is
  claimed.
- Outside SQLite, this document claims what the standard-library calls named
  above do (`sync_data` for segment barriers, `sync_all` for materialized files);
  it does not claim a drive-cache flush on Apple platforms for those paths.
- An edit is part of history only after the engine has captured it. Bytes that
  a user's program wrote and that were not yet captured when the machine lost
  power are not in any journal; the next scan treats the folder as the user's
  current state.
- The block-store group commit makes bytes durable, not authoritative. A block
  is protected from the sweep by the grace window until the row that references
  it commits.

## 4. What front ends may and may not do

**May.** Display state the engine computed (status, reasons, next actions,
which file actions are offered). Send a request. Perform an operating-system
operation that the engine returned as allowed for that request. Hold UI-only
state. Map a typed reason to wording or an icon.

**May not.** Delete, move, overwrite, evict or release user data, or tell the
operating system to, on its own judgment. Copy a safety rule (a replica count,
"safe if a peer is online", "safe if the provider says downloaded", a conflict
winner, a timestamp comparison, an authorization decision). Guess when the engine
is unreachable, stale or returns something unknown: the answer is that nothing
was done.

**Shipped.**

- The native-app binding crate `crates/yadorilink-client-ffi` forwards only to
  `crates/yadorilink-client-core`, and client-core reaches the daemon only
  through the control-socket contract, never by linking the daemon. This is
  checked by the dependency allowlists in `.config/architecture.toml` and
  enforced by `.github/checks/check-architecture.py`.
- Product status, reasons and next actions are derived in
  `crates/yadorilink-product-view`, which depends only on the IPC contract.
- Shell-extension requests reach the daemon through one context
  (`crates/yadorilink-daemon/src/shell_context.rs`), so a context-menu action and
  the equivalent command line request run the same service; the manifest forbids
  the shell handlers from editing the pause set or naming the hydration engine
  directly.
- The Windows provider host policy is a crate with no Win32 dependency
  (`crates/yadorilink-windows-provider-policy`), tested on every platform.
- A domain removal is recorded in the engine as a durable intent and the host
  reports it done (`crates/yadorilink-sync-sqlite/src/provider.rs`).

**Goal (not yet enforced here).**

- A native end-to-end test in each official application that shows an engine
  refusal prevents the operating-system-side action. The application sources
  are not in this repository, so this document cannot cite one.
- A recorded review that those applications contain no second copy of the rules
  above. Until it exists, section 1 is a rule they are held to, not a property
  this repository can show.
- A repository check that rejects a direct destructive operating-system call in
  application code.

## 5. Adding a safety rule

A new rule needs, in the change that adds it:

1. A reproducible failure: a test, seed, failpoint or schedule that makes the
   unsafe outcome happen on the current code.
2. The invariant it violates, stated as a sentence that names what must never
   happen and who decides it. If the decision is not in the engine, move it
   there first.
3. Why the existing tests missed it: which test should have caught it and what
   it did not exercise. If the answer is "nothing covers this class", say so; the
   fix then includes a test for the class, not only for the instance.
4. The fix at the point of decision, and a test that fails without it. Where a
   rule can be violated by a new call site, a check under `.github/checks/` or a
   rule in `.config/architecture.toml` that fails on a new violation (the
   existing ones pin the allowed call sites and their count, so a new one forces
   a review).
5. An entry in this document: the rule, the code, the tests, and what it does
   not cover. A rule whose enforcement is incomplete is added as a goal.

Do not add recovery that infers what happened from the shape of the folder;
fix the invariant where the state is written, so recovery can read it.

## 6. How the invariants are tested

- **Deterministic regressions.** One test per dangerous case, named after the
  property (the test IDs above).
- **Guards on structure.** `.github/checks/` and `.config/architecture.toml`
  fail the build when production code goes around a gated seam (block deletion,
  content writes, local mutations, namespace changes, silent defaults). Each
  guard reports itself stale when the code it watches is renamed.
- **Deterministic simulation.** `crates/yadorilink-daemon/tests/dst_support/`
  runs real daemon code on a simulated clock, network and disk from a seed. A
  failure replays from its seed. The pull-request workflow runs one seed per scenario
  (`dst_turmoil_substrate_case.rs`, `dst_watcher_debounce.rs`); the nightly
  workflow runs wider sweeps.
- **Fault injection.** Seeded disk faults (full disk, I/O error, torn write),
  SQLite busy and journal-write failures, and dropped network messages are injected
  through decorators in `dst_support/` (`fault_disk.rs`, `fault_sqlite.rs`,
  `fault_carrier.rs`). `fault_gate.rs` is the negative control: a fault that a
  test names but never injected fails the gate. The block store enumerates its
  own commit points (`CommitPoint`, `FaultPlan`) and a crash at each is tested.
  Folder rewind is crashed at every journal boundary
  (`rewind_crash_failpoints.rs`).
- **Fault matrix.** `crates/yadorilink-daemon/tests/safety_gate_fault_matrix.rs`
  injects one fault at each named failure point of the gates above (the
  installation witness, the replacement record, every namespace failpoint and
  commit point, the volume probe and identity, disk-pressure refusals, a denied
  write, a planted symlink, the schema version, the update manifest and rollout
  refusals, generation files) and asserts the same four things for each: the
  attempt is refused with a typed reason (never accepted quietly), nothing is
  lost or half written, a retry after the cause is gone succeeds, and the data
  is still intact. Gates whose injection needs a fixture of their own are
  indexed in the same table as pointers to the test that injects there, and a
  gate that cannot be driven says why.
  `.github/checks/check-safety-gate-matrix.py` fails when a section of this
  document, a variant of a failpoint or refusal enum, or a test-injection seam
  has no row.
- **Boundary tests.** `crates/yadorilink-daemon/tests/dst_support/boundary_gate.rs` keeps one row per safety
  boundary with the invariant it protects, and each row also runs a version with
  a deliberate defect that the oracle must catch.
- **Model and property tests.** The namespace durability model replays real
  operation traces against what a crash would leave. The convergence suite
  (`dst_sec_convergence.rs`) checks that every device reaches the same state from
  the same set of changes in any order, with duplicated and reordered delivery,
  partitions and crash-restart replays, and names conflict copies identically.
- **Sabotage.** Maintainers also apply a deliberate defect to a safety gate
  (a check removed, an error turned into success) and require the named test to
  fail. This and the schedule explorer for small races are run by the
  maintainers and are not part of the published tree, so a third party
  cannot rerun them yet.

None of this is a formal proof, and a passing run says the cases above behave
as described, not that no other case exists.

## 7. Open items

Goals named above, collected: native end-to-end refusal tests in the official
applications; a recorded no-duplicated-policy review of their code; a
repository check for direct destructive calls in application code; publishing
the sabotage and schedule-exploration lanes. The Windows durable namespace rests
on documented behavior of write-through moves and a per-volume probe, not on a
power-loss experiment that this repository can show.
