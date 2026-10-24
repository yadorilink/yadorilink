#!/usr/bin/env python3
"""Pin every production call to a raw materialization-semantic API.

"Materialization semantics" is the family of durable facts that decide
whether a path's local bytes are trusted: the materialization intent
journal, the per-path mutation fence, `files.materialization_state` and the
held marker, placeholder identities, published materialized generations
(proofs), projection-obligation completion, the restore journal, the
local-capture adoption that writes the same facts from the other side, and
the structural-directory origin ledger (which directories this device made
only for descendants, and whose intent moves the fence).
Today several callers compose these primitives directly, each in its own
order and transaction granularity, which is how protocols drift apart (an
intent opened by one delete lane and not by the other, a revert guard that
downgrades in one hydration lane and not in the other).

Those compositions belong behind owner-side semantic operations: inherent
methods on `ReplicaCoordinator` (`crates/yadorilink-daemon/src/
replica_coordinator/`) that run one protocol, or one half of it around a
physical write, in a fixed order. This guard freezes the shape: a raw call
to any API in `FORBIDDEN` may appear only in a production file listed in
`ALLOWLIST`, only for an API listed under that file, and only as many times
as pinned there. The grand total is pinned again in `EXPECTED_ALLOWED`, so
every added, moved or removed call site is reviewed and recorded here rather
than slipping in. A change that closes a composition behind an owner
operation lowers the counts and updates them in the same commit.

Each allowlisted file is one of three kinds (`file_kind`): the owner
(`replica_coordinator/`), the SQLite repository (`yadorilink-sync-sqlite`),
or an orchestration lane (everything else: convergence, hydration, repair,
eviction, capture). Orchestration lanes may not ADD raw calls. The lane
files that still hold some are frozen in `LANE_FILES`; a lane file missing
from it fails, and so does a stale entry. Every pin, lane or not, is exact:
the check fails on any difference, in either direction, and there is no
recorded baseline to compare against. So nothing here mechanically stops a
lane's pin, or `LANE_FILES`, from growing; what the check guarantees is that
growing one takes an edit to this script, which review sees. The policy that
review enforces: a new lane, or a new step in an existing one, calls a
`ReplicaCoordinator` semantic operation (adding one there if needed) instead
of composing the primitives itself, so lane pins and `LANE_FILES` only
shrink, and counts go up only inside `replica_coordinator/` or the
repository.

A second section, `IN_FAMILY`, pins the same way the in-family row mutators
that also write non-materialization facts (peer row application, authoring
advance, local-only erase, pin, block provenance). They are not forbidden
outright because unrelated writers share them, but every production call
site is pinned in `IN_FAMILY_ALLOWLIST`, under the same lane rule.

How a hit is found (a textual scan, not a Rust parser):
  * `name(` with no identifier character immediately before `name`, so
    `dag_bump_mutation_fence(` never counts as `bump_mutation_fence(`, and
    `clear_held_in_tx(` never counts as `clear_held(`. A turbofish
    (`name::<T>(`) still counts.
  * The definition itself (`fn name(`), including a trait declaration, is
    not a call and is not counted.
  * Trailing `//` comments and whole-line comments are dropped first.
  * Test code is excluded: any item under a `cfg` that holds only in test
    builds (`#[cfg(test)]`, `#[cfg(all(test, unix))]`,
    `#[cfg(any(test, feature = "test-support"))]`; the recognized gates are
    `test` and `feature = "test-support"`, so `any(test, madsim)` or any
    other gate stays production), a module file declared
    under such a `cfg` in its parent (followed through `#[path]` and nested
    module directories), a file that opens with `#![cfg(test)]`, and
    everything outside `crates/*/src` (integration tests, benches).

Known blind spots, recorded rather than hidden: an `OpenMaterializationIntent`
guard's `.clear()` and its uncleared drop cannot be told apart from any other
`.clear()`/drop by text, so the guard instead pins every way to OBTAIN one
(`open_materialization_intent_guard(`, `MaterializationIntentGuard::open(`,
`MaterializationIntentGuard::opened(`);
and a primitive passed as a function value without a call (`.map(name)`) is
not seen. Reviewer judgment remains the backstop.

Run with no arguments to check the tree, `--list` to print every counted
call site of `FORBIDDEN` (file:line, enclosing fn, API), `--list-in-family`
for the `IN_FAMILY` sites, and `--self-test` to exercise the scanner against
synthetic fixtures.
"""

from __future__ import annotations

import argparse
from collections import Counter
import functools
from pathlib import Path
import re
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE_GLOB = "crates/*/src/**/*.rs"

# The raw materialization-semantic APIs, by bare callable name.
FORBIDDEN = (
    "MaterializationIntentGuard::open",
    "MaterializationIntentGuard::opened",
    "adopt_local_capture_absent_state",
    "adopt_local_capture_actual_state",
    "adopt_observed_actual_generation_in_tx",
    "append_initial_import",
    "begin_materialization_intent",
    "begin_materialization_intent_in_tx",
    "bump_mutation_fence",
    "clear_held",
    "clear_held_in_tx",
    "clear_materialization_intent",
    "clear_materialization_intent_in_tx",
    "clear_placeholder_generation",
    "commit_admission",
    "commit_internal_materialized_state_if_fence_current",
    "commit_local_mutations_batch",
    "commit_recursive_operation",
    "commit_recovered_materialized_state",
    "commit_restore_operation",
    "complete_obligation_if_exact_proof_current",
    "complete_obligation_if_non_exact_proof_current",
    "dag_bump_mutation_fence",
    "dag_complete_obligation_if_exact_proof_current",
    "dag_complete_obligation_if_non_exact_proof_current",
    "dag_has_usable_materialized_generation",
    "dag_lookup_materialized_generation",
    "dag_publish_materialized_generation_if_fence_current",
    "dag_snapshot_mutation_fence",
    "dag_usable_proof_names_current_version",
    "dag_zero_work_settlement_if_already_current",
    "dehydrate_windows_placeholder",
    "discard_restore_operation",
    "finalize_projected_mutations_batch",
    "has_usable_materialized_generation",
    "invalidate_published_generations",
    "mark_deleted_at",
    "mark_deleted_emitting_change",
    "mark_restore_disk_committed",
    "open_materialization_intent_guard",
    "plan_admission",
    "publish_materialized_generation_if_fence_current",
    "read_mutation_fence",
    "record_placeholder_generation",
    "record_placeholder_generation_if_absent",
    "record_local_capture_in_tx",
    "record_restore_operation_emitting_change",
    "record_restore_placing",
    "replace_group_files_from_snapshot",
    "reprove_verified_hydrated_state",
    "reset_stale_evicting_to_placeholder",
    "reset_stale_hydrating_to_placeholder",
    "retire_unproven_actual_state_in_tx",
    "set_held",
    "set_held_with_key",
    "set_materialization_state",
    "set_materialization_state_in_tx",
    "snapshot_mutation_fence",
    "stamp_hydrated_after_local_emission_in_tx",
    "strip_carried_forward_hydrated_in_tx",
    "transition_materialization_state",
    "transition_materialization_state_if_same_authoring",
    "upsert_file_emitting_change",
    "upsert_files_batch",
    "upsert_files_batch_emitting_change",
    "abandon_structural_intent",
    "adopt_structural_directory",
    "clear_retained_directory",
    "dag_adopt_structural_directory",
    "dag_forget_structural_origin",
    "dag_rekey_structural_origin",
    "record_retained_directory",
    "complete_structural_origin",
    "dag_abandon_structural_intent",
    "dag_complete_structural_origin",
    "dag_drop_structural_intents_recording_lost_provenance",
    "dag_drop_unresolved_structural_intents",
    "dag_record_structural_intent",
    "drop_structural_intent_recording_lost_provenance",
    "drop_unresolved_structural_intents",
    "forget_structural_origin",
    "rekey_structural_origin",
    "record_structural_intent",
)

# Allowed raw calls: repo-relative production file -> {API: pinned count}.
# The comment on each file names the protocol(s) the calls belong to. A
# (file, API) pair that is not listed is a violation; a listed pair whose
# count changed fails too.
D = "crates/yadorilink-daemon/src/"
F = "crates/yadorilink-filesystem-sync/src/"
L = "crates/yadorilink-local-capture/src/"
S = "crates/yadorilink-sync-sqlite/src/"
ALLOWLIST: dict[str, dict[str, int]] = {
    # Convergence engine: exact publication.
    D + "convergence/engine.rs": {
        "dag_publish_materialized_generation_if_fence_current": 1,
    },
    # Access-triggered hydration's proof read; live version restore (its
    # authoring, which journals only a restore it writes itself, and the
    # bump after target verification).
    D + "hydration.rs": {
        "dag_usable_proof_names_current_version": 1,
        "dag_lookup_materialized_generation": 1,
        "dag_bump_mutation_fence": 1,
        "record_restore_placing": 1,
    },
    # Windows CfAPI placeholder generation mint-or-read.
    D + "link_runtime/operations/capture_local_change.rs": {
        "record_placeholder_generation_if_absent": 1,
    },
    # Eager/pinned content write (the commit; its fence bump is in the
    # owner's pre-write transaction); the reconstruct-failed placeholder
    # demotion.
    D + "local_convergence/materialize/eager.rs": {
        "set_materialization_state": 1,
    },
    # Shared write_placeholder helper (the bump after the lane's verify).
    D + "local_convergence/materialize/placeholder.rs": {
        "dag_bump_mutation_fence": 1,
    },
    # Symlink lane: the PolicySkipped demotion.
    D + "local_convergence/materialize/symlink.rs": {
        "set_materialization_state": 1,
    },
    # Metadata-only settlement clear_held.
    D + "local_convergence/materialize.rs": {
        "clear_held": 1,
    },
    # The metadata fast path of a projected content head: the fence snapshot
    # when bytes and metadata already match disk, the bump when only
    # metadata is repaired.
    D + "local_convergence/reconcile.rs": {
        "dag_snapshot_mutation_fence": 1,
        "dag_bump_mutation_fence": 1,
    },
    # materialize_symlink_at's commit; metadata-only update.
    D + "local_convergence/types.rs": {
        "dag_bump_mutation_fence": 1,
        "commit_internal_materialized_state_if_fence_current": 1,
        "dag_snapshot_mutation_fence": 1,
    },
    # Native level projection (`reconcile_native.rs`): the fence snapshot an
    # observed-absent path's exact-absent evidence is valid under, and the
    # zero-work settlement of a path whose actual state is already current.
    # Both only read the fence or settle without a disk write; neither
    # composes a materialization write.
    D + "local_convergence/reconcile_native.rs": {
        "dag_snapshot_mutation_fence": 1,
        "dag_zero_work_settlement_if_already_current": 1,
    },
    # materialize_tombstone's already-deleted snapshot, and the two
    # read-only "does a usable proof exist" questions (the reconcile settle
    # check and the zero-work pre-check that asks the same question first);
    # both only read, neither composes a protocol.
    D + "local_convergence.rs": {
        "dag_snapshot_mutation_fence": 1,
        "dag_has_usable_materialized_generation": 2,
    },
    # The intent guard primitive itself.
    D + "materialization_intent.rs": {
        "begin_materialization_intent": 1,
        "clear_materialization_intent": 1,
    },
    # Coordinator adapters: repository delegation behind ReplicaCoordinator.
    D + "replica_coordinator/local_mutation.rs": {
        "commit_local_mutations_batch": 1,
        "upsert_files_batch": 2,
        "mark_deleted_at": 2,
        # Capture follows a structural directory a user renamed.
        "dag_rekey_structural_origin": 1,
        # Capture's directory operations (`commit_captured_directory`,
        # `commit_directory_removal`, `commit_directory_rename`): an explicit
        # directory's own commit, with an emitter or as an index write; a
        # removed directory's observed entries, as one signed recursive
        # delete or, without an emitter, index tombstones; a directory
        # rename, as one signed recursive rename. The capture lane calls
        # these and composes none of the primitives itself.
    },
    # Owner-side seams of the file index's local commits: a captured
    # mutation batch, an explicit directory's own commit (one mutation
    # through the same batch), and a directory's recursive delete and
    # rename. Each takes the capture's author handle and the root commit
    # permit; the capture lane reaches them only through
    # `LocalMutationStore`.
    D + "replica_coordinator/local_commit.rs": {
        "commit_local_mutations_batch": 2,
        "commit_recursive_operation": 2,
    },
    D + "replica_coordinator/materialization_execution.rs": {
        "clear_materialization_intent": 1,
        "commit_recovered_materialized_state": 1,
        "dag_usable_proof_names_current_version": 1,
        "commit_restore_operation": 1,
        "discard_restore_operation": 1,
        "MaterializationIntentGuard::open": 1,
        "bump_mutation_fence": 1,
    },
    # Owner operations for the convergence lanes: the eager content
    # write, fresh placeholder write and symlink write open halves, and the
    # symlink lane's release of a hold under an intent; the hazard hold;
    # the single-path tombstone (re-hold, open, and the two settles);
    # conflict-copy retirement publication; the engine's obligation
    # completion (exact and non-exact). The equal-authoring File metadata
    # repair's settle adds 1, owner-side: the fence-CAS commit that
    # re-proves a `Hydrated` row under the fence its own bump returned.
    # Before it the bump left that row with no usable proof, which access
    # hydration refuses as CorruptState; the lane gained no raw call.
    # The metadata-unprovable hold adds 3, owner-side: the keyed hold
    # itself, the fence read its key is built from, and the release that
    # lifts only that hold once the path settles. Before it, a file whose
    # owner cannot read it failed or retried forever in three lanes
    # (metadata-only update, content-identical projection, equal-authoring
    # repair); each now calls these owner operations and gained no raw call.
    # The directory lane adds 1, owner-side: its settle, the same fence-CAS
    # commit the symlink write makes (its open shares the symlink write's
    # open half, so it adds no call there).
    D + "replica_coordinator/materialization_owner/lanes.rs": {
        "open_materialization_intent_guard": 4,
        "set_materialization_state": 3,
        "clear_held": 5,
        "dag_bump_mutation_fence": 2,
        # The content write's pre-write transaction: intent, row, in-flight
        # state, hold clear and fence bump in one commit, and the guard of
        # the intent it opened.
        "MaterializationIntentGuard::opened": 1,
        "dag_snapshot_mutation_fence": 1,
        "set_held": 2,
        "set_held_with_key": 1,
        "dag_complete_obligation_if_exact_proof_current": 1,
        "dag_complete_obligation_if_non_exact_proof_current": 1,
        "commit_internal_materialized_state_if_fence_current": 2,
    },
    # Coordinator adapters, plus the batched open/finalize composition (A/D)
    # and zero-work settlement.
    D + "replica_coordinator/peer_replica_state.rs": {
        "set_materialization_state": 1,
        "clear_held": 1,
        "set_held": 1,
        "bump_mutation_fence": 1,
        "snapshot_mutation_fence": 1,
        "publish_materialized_generation_if_fence_current": 1,
        "commit_internal_materialized_state_if_fence_current": 2,
        "dag_lookup_materialized_generation": 2,
        "dag_usable_proof_names_current_version": 2,
        "dag_snapshot_mutation_fence": 3,
        "dag_zero_work_settlement_if_already_current": 1,
        "MaterializationIntentGuard::open": 2,
        "clear_held_in_tx": 1,
    },
    # Owner operations for the hydration lanes: convergence
    # rehydration's guard (entry CAS, hazard hold, hold release under an
    # intent, fence bump, commit, revert on drop) and access hydration's
    # guard (entry CAS, fence bump, commit, revert on drop), and its
    # Hydrated-row proof heal; the live restore's settle.
    D + "replica_coordinator/materialization_owner/hydration.rs": {
        "reprove_verified_hydrated_state": 1,
        "mark_restore_disk_committed": 1,
        "commit_restore_operation": 1,
        "dag_bump_mutation_fence": 1,
        "commit_internal_materialized_state_if_fence_current": 1,
    },
    # Owner operations for eviction and recovery: eviction's open
    # (Evicting, fence bump) and settle (Evicting -> Placeholder CAS); the
    # startup stale transient-state reset (Hydrating/Evicting ->
    # Placeholder); the repair sweep's quarantine open (intent, fence bump)
    # and reconstruct settle (the exact commit, and the authoring-bound
    # demotion when it did not publish); its symlink rebuild open (fence
    # bump, intent) and settle (the same exact commit); restore-journal
    # recovery's preservation of divergent bytes (dirty record, discard);
    # and the repair sweep's placeholder demotion open, the authoring- and
    # version-bound move to Placeholder that replaced the lane's two blind
    # `set_materialization_state` calls (the +1 on
    # `transition_materialization_state_if_same_authoring` below; the lane
    # and the port adapter lost 3 raw calls for it). Eviction's abandon
    # half adds 2, owner-side, in one transaction: the recovery
    # commit that returns a still-intact file to Hydrated with a proof, and
    # the in-tx state set for the other outcomes (Hydrated without a proof,
    # or Placeholder). Before it, a failed eviction left the row Evicting
    # until the next daemon start; the lane gained no raw call for it.
    # The snapshot-install reconciliation's disk-write open adds 1 fence
    # bump, owner-side: announced once before the lane removes, moves aside
    # or places anything under a held path; the lane has no raw call.
    D + "replica_coordinator/materialization_owner/repair.rs": {
        "discard_restore_operation": 1,
        "set_materialization_state": 1,
        "dag_bump_mutation_fence": 4,
        "transition_materialization_state": 1,
        "open_materialization_intent_guard": 2,
        "commit_internal_materialized_state_if_fence_current": 1,
        "commit_recovered_materialized_state": 1,
        "set_materialization_state_in_tx": 1,
    },
    # Owner operations of the structural-directory ledger: the two-phase
    # origin protocol around a structural `mkdir` (intent, completion,
    # abandon), interrupted-intent recovery at startup and on the periodic
    # sweep, adoption of an explicit directory kept for live descendants,
    # a removed directory's forget and retained-record
    # clear, a retained directory's record and release, the fence bump
    # before any directory the namespace decides to remove, and the fence
    # snapshot a directory's settlement is valid under.
    D + "replica_coordinator/materialization_owner/structural.rs": {
        "dag_record_structural_intent": 1,
        "dag_complete_structural_origin": 1,
        "dag_abandon_structural_intent": 1,
        "dag_drop_structural_intents_recording_lost_provenance": 1,
        "dag_adopt_structural_directory": 1,
        "dag_forget_structural_origin": 1,
        "record_retained_directory": 1,
        "clear_retained_directory": 2,
        "dag_bump_mutation_fence": 1,
        "dag_snapshot_mutation_fence": 1,
    },
    # Owner operations: the placeholder-identity record.
    D + "replica_coordinator/materialization_owner.rs": {
        "record_placeholder_generation": 1,
        "record_placeholder_generation_if_absent": 1,
        "clear_placeholder_generation": 1,
    },
    D + "replica_coordinator.rs": {
        "record_restore_placing": 1,
    },
    # Eviction to placeholder: the Windows native dehydrate (the physical
    # write itself on that platform).
    F + "materialization_eviction.rs": {
        "dehydrate_windows_placeholder": 1,
    },
    # Repair sweep: re-prove, the reconstruct bump and its journaled intent,
    # placeholder demotion (the bump after the target verification, which
    # follows the owner's guarded Placeholder open; intent clear after mode
    # and xattrs), offline delete;
    # restore-journal recovery (adopting commit, discards after a disk
    # comparison).
    # has_usable_materialized_generation 3: the live sweep's settled-row
    # short-circuit reads the proof before hashing the file (a read of the
    # same predicate the post-compare branch already uses; no state change).
    F + "materialization_repair.rs": {
        "has_usable_materialized_generation": 3,
        "commit_recovered_materialized_state": 1,
        "open_materialization_intent_guard": 1,
        "dag_bump_mutation_fence": 3,
        "clear_materialization_intent": 2,
        "discard_restore_operation": 2,
        "commit_restore_operation": 1,
    },
    # Local capture (watcher events, flush, scan). Each commits what it
    # observed through the `LocalMutationStore` port's
    # `commit_local_mutations_batch`, under the path lock, with the
    # capture's own signing author and a fresh root-commit permit: the
    # watcher's delete, the watcher's upsert, and one scan chunk.
    L + "local_change/event_ingest.rs": {
        "commit_local_mutations_batch": 2,
        "mark_deleted_at": 1,
        "upsert_files_batch": 1,
    },
    L + "local_change/flush.rs": {
        "commit_local_mutations_batch": 1,
    },
    L + "local_change/scan.rs": {
        "commit_local_mutations_batch": 1,
        "upsert_files_batch": 1,
    },
    # Atomic commit primitives (internal, recovered, reprove).
    # A zero-work close re-anchors the proof it accepts in the same
    # transaction: close the obligation, then republish at the current fence.
    S + "exact_materialized_commit.rs": {
        "publish_materialized_generation_if_fence_current": 4,
        "set_materialization_state_in_tx": 2,
        "clear_materialization_intent_in_tx": 2,
        "snapshot_mutation_fence": 3,
        "complete_obligation_if_exact_proof_current": 2,
        "commit_internal_materialized_state_if_fence_current": 2,
    },
    # Local-capture writes composing adoption / retirement in-tx, and the
    # record that each capture route's change was read off this disk (which
    # decides that projecting it may never write the disk): one per capture
    # route, in the transaction that emits the change, and nowhere else.
    S + "file_index.rs": {
        "adopt_local_capture_actual_state": 2,
        "stamp_hydrated_after_local_emission_in_tx": 2,
        "retire_unproven_actual_state_in_tx": 4,
        "adopt_local_capture_absent_state": 1,
        "mark_deleted_at": 1,
        "adopt_observed_actual_generation_in_tx": 2,
        "complete_obligation_if_exact_proof_current": 1,
        "invalidate_published_generations": 1,
    },
    # Repository wrapper around the internal atomic commit.
    S + "materialization_state.rs": {
        "commit_internal_materialized_state_if_fence_current": 1,
    },
    # Fence/proof primitives: adoption bumps; the unconditional
    # record_materialized_generation (compiled in production, called only by
    # tests) snapshots.
    S + "materialized_generation.rs": {
        "snapshot_mutation_fence": 1,
        "bump_mutation_fence": 1,
    },
    # Restore commit (internal commit, or external adoption on recovery).
    S + "restore_operation.rs": {
        "commit_internal_materialized_state_if_fence_current": 1,
        "adopt_local_capture_actual_state": 1,
        "set_materialization_state_in_tx": 1,
        "retire_unproven_actual_state_in_tx": 1,
    },
    # A structural `mkdir` bumps the path's fence as it records its intent,
    # and the intent's completion refuses a fence that moved since; a
    # rename's rekey forgets the record at the old name.
    S + "structural_origin.rs": {
        "bump_mutation_fence": 1,
        "snapshot_mutation_fence": 1,
        "forget_structural_origin": 1,
    },
    # Obligation completion wrappers; the structural-origin ledger's
    # transaction wrappers (intent, completion, abandon, recovery, adopt,
    # rekey, forget) and the retained-directory record's (record, clear).
    S + "store.rs": {
        "complete_obligation_if_exact_proof_current": 1,
        "complete_obligation_if_non_exact_proof_current": 1,
        "record_structural_intent": 1,
        "complete_structural_origin": 1,
        "abandon_structural_intent": 1,
        "drop_unresolved_structural_intents": 1,
        "drop_structural_intent_recording_lost_provenance": 1,
        "adopt_structural_directory": 1,
        "rekey_structural_origin": 1,
        "forget_structural_origin": 1,
        "record_retained_directory": 1,
        "clear_retained_directory": 1,
        "dag_lookup_materialized_generation": 1,
    },
    # The repository half of the owner's content-write open (intent, state
    # move, held release and fence bump in one transaction); it replaced the
    # same primitives previously called from the owner's lane operations.
    S + "content_write_open.rs": {
        "begin_materialization_intent_in_tx": 1,
        "bump_mutation_fence": 1,
        "clear_held_in_tx": 1,
        "set_materialization_state_in_tx": 1,
    },
}

# Pinned total of allowed raw calls. Change it only together with ALLOWLIST,
# after reviewing the added/removed site. Per file, so the next person can
# check the same list instead of re-deriving it (O = owner, R = repository,
# L = orchestration lane; see `file_kind`):
#   L daemon/convergence/engine.rs                                  1
#   L daemon/hydration.rs                                           4
#   L daemon/link_runtime/factory.rs                                1
#   L daemon/link_runtime/operations/capture_local_change.rs        1
#   L daemon/link_runtime/operations/repair_materialization.rs      1
#   L daemon/local_convergence.rs                                   2
#   L daemon/local_convergence/materialize.rs                       1
#   L daemon/local_convergence/materialize/eager.rs                 2
#   L daemon/local_convergence/materialize/placeholder.rs           1
#   L daemon/local_convergence/materialize/symlink.rs               1
#   L daemon/local_convergence/reconcile.rs                         2
#   L daemon/local_convergence/reconcile_native.rs                  2
#   L daemon/local_convergence/types.rs                             3
#   L daemon/materialization_intent.rs                              2
#   L filesystem-sync/materialization_eviction.rs                   1
#   L filesystem-sync/materialization_repair.rs                    13
#   L local-capture/local_change/event_ingest.rs                    4
#   L local-capture/local_change/flush.rs                           1
#   L local-capture/local_change/scan.rs                            2
#   O daemon/replica_coordinator.rs                                 1
#   O daemon/replica_coordinator/local_commit.rs                    4
#   O daemon/replica_coordinator/local_mutation.rs                  6
#   O daemon/replica_coordinator/materialization_execution.rs       7
#   O daemon/replica_coordinator/materialization_owner.rs           3
#   O daemon/replica_coordinator/materialization_owner/hydration.rs 10
#   O daemon/replica_coordinator/materialization_owner/lanes.rs    26
#   O daemon/replica_coordinator/materialization_owner/repair.rs 14
#   O daemon/replica_coordinator/materialization_owner/structural.rs 11
#   O daemon/replica_coordinator/peer_replica_state.rs             20
#   R sync-sqlite/exact_materialized_commit.rs                     12
#   R sync-sqlite/file_index.rs                                    16
#   R sync-sqlite/materialization_state.rs                          1
#   R sync-sqlite/materialized_generation.rs                        2
#   R sync-sqlite/restore_operation.rs                              4
#   R sync-sqlite/store.rs                                         12
#   R sync-sqlite/structural_origin.rs                              3
#   ------------------------------------------------------------
#   total 190 = lane 43 + owner 91 + repository 56 (the per-file rows above are
#   indicative; the pins in ALLOWLIST are authoritative)
EXPECTED_ALLOWED = 190

# The in-family row mutators outside `FORBIDDEN`. Each also writes
# materialization-relevant columns (a peer row's version and authoring, the
# row itself, the provenance that lets a fetched block be trusted), but is shared with writers that are not about
# materialization, so each site is pinned rather than forbidden.
IN_FAMILY = (
    "apply_projected_row_atomic",
    "erase_local_only_file",
    "record_block_provenance",
    "record_group_block_provenance",
    "set_authoring_change_hash",
    "upsert_file_with_origin",
    "upsert_file_with_origin_and_author",
)

IN_FAMILY_ALLOWLIST: dict[str, dict[str, int]] = {
    # Fetched-block provenance (access hydration).
    D + "hydration.rs": {
        "record_block_provenance": 1,
    },
    # Convergence block acquisition: provenance flush.
    D + "local_convergence/knobs.rs": {
        "record_group_block_provenance": 1,
    },
    # The tombstone authoring advance of an already-absent path (batched
    # delete, and reconcile_group_paths' already-settled re-drive); the
    # materialize_dag_content_head metadata fast path.
    D + "local_convergence/reconcile.rs": {
        "apply_projected_row_atomic": 1,
    },
    # Coordinator adapters: repository delegation behind ReplicaCoordinator.
    D + "replica_coordinator.rs": {
        "record_group_block_provenance": 1,
    },
    D + "replica_coordinator/local_mutation.rs": {
        "record_block_provenance": 1,
    },
    D + "replica_coordinator/peer_replica_state.rs": {
        "record_block_provenance": 1,
        "upsert_file_with_origin": 1,
        "record_group_block_provenance": 1,
    },
    # Owner operations: the row persist of a fresh write, the symlink open,
    # the hazard hold, and the retired copy's erase.
    D + "replica_coordinator/materialization_owner/lanes.rs": {
        "apply_projected_row_atomic": 1,
        "erase_local_only_file": 1,
    },
    # Local capture: provenance of freshly chunked blocks.
    L + "local_change/record_builder.rs": {
        "record_group_block_provenance": 1,
    },
    L + "scan_block_staging.rs": {
        "record_group_block_provenance": 1,
    },
    # Repository layer.
    S + "file_index.rs": {
        "upsert_file_with_origin": 1,
    },
}

# Pinned total of IN_FAMILY_ALLOWLIST:
#   total 13 = lane 5 + owner 7 + repository 1
EXPECTED_IN_FAMILY_ALLOWED = 13

# The orchestration-lane files that still hold raw calls of either section.
# Pinned exactly: a lane file that appears in either allowlist but not here
# fails, and so does an entry here that neither allowlist names any more.
# Adding an entry is therefore an edit to this script, visible in review, and
# by policy this set only shrinks: a lane that needs a new materialization
# step calls (or adds) a ReplicaCoordinator semantic operation instead of
# listing itself here.
LANE_FILES = frozenset(
    {
        D + "convergence/engine.rs",
        D + "hydration.rs",
        D + "link_runtime/operations/capture_local_change.rs",
        D + "local_convergence.rs",
        D + "local_convergence/knobs.rs",
        D + "local_convergence/materialize.rs",
        D + "local_convergence/materialize/eager.rs",
        D + "local_convergence/materialize/placeholder.rs",
        D + "local_convergence/materialize/symlink.rs",
        D + "local_convergence/reconcile.rs",
        D + "local_convergence/reconcile_native.rs",
        D + "local_convergence/types.rs",
        D + "materialization_intent.rs",
        F + "materialization_eviction.rs",
        F + "materialization_repair.rs",
        L + "local_change/event_ingest.rs",
        L + "local_change/flush.rs",
        L + "local_change/record_builder.rs",
        L + "local_change/scan.rs",
        L + "scan_block_staging.rs",
    }
)
OWNER_PREFIXES = (D + "replica_coordinator/", D + "replica_coordinator.rs")
REPOSITORY_PREFIX = S


def file_kind(rel: str) -> str:
    """`owner`, `repository`, or `lane` for a repo-relative source file."""
    if rel.startswith(OWNER_PREFIXES):
        return "owner"
    if rel.startswith(REPOSITORY_PREFIX):
        return "repository"
    return "lane"


def call_pattern(names: tuple[str, ...]) -> re.Pattern[str]:
    """`name(` (or `name::<T>(`) for any of `names`, not preceded by an ident char."""
    return re.compile(
        r"(?<![A-Za-z0-9_])("
        + "|".join(re.escape(name) for name in sorted(names, key=len, reverse=True))
        + r")\s*(?:::<[^()]*>)?\("
    )


CALL = call_pattern(FORBIDDEN)
IN_FAMILY_CALL = call_pattern(IN_FAMILY)
# One `#[cfg(...)]` attribute, with up to two levels of nested parentheses.
CFG_ATTR = re.compile(r"#\[cfg\(((?:[^()\]]|\((?:[^()]|\([^()]*\))*\))*)\)\]")
FN_NAME = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")
CFG_TOKEN = re.compile(r'\s*(?:(\w+)\s*=\s*"([^"]*)"|(\w+)|([(),]))')


def _parse_cfg(condition: str):
    """A `cfg(...)` predicate as a nested tuple, or `None` if unparseable.

    `("atom", name)`, `("kv", key, value)`, or `(op, [children])` for
    `all`/`any`/`not`.
    """
    tokens: list[tuple[str, ...]] = []
    position = 0
    while position < len(condition):
        if condition[position:].strip() == "":
            break
        match = CFG_TOKEN.match(condition, position)
        if not match:
            return None
        key, value, word, punct = match.groups()
        if key is not None:
            tokens.append(("kv", key, value))
        elif word is not None:
            tokens.append(("word", word))
        else:
            tokens.append(("punct", punct))
        position = match.end()

    def predicate(index: int):
        if index >= len(tokens):
            return None, index
        token = tokens[index]
        if token[0] == "kv":
            return ("kv", token[1], token[2]), index + 1
        if token[0] != "word":
            return None, index
        name = token[1]
        if index + 1 < len(tokens) and tokens[index + 1] == ("punct", "("):
            if name not in ("all", "any", "not"):
                return None, index
            children = []
            index += 2
            while index < len(tokens) and tokens[index] != ("punct", ")"):
                child, index = predicate(index)
                if child is None:
                    return None, index
                children.append(child)
                if index < len(tokens) and tokens[index] == ("punct", ","):
                    index += 1
            if index >= len(tokens):
                return None, index
            return (name, children), index + 1
        return ("atom", name), index + 1

    tree, end = predicate(0)
    if tree is None or end != len(tokens):
        return None
    return tree


def _test_only(node) -> bool:
    kind = node[0]
    if kind == "atom":
        return node[1] == "test"
    if kind == "kv":
        return node[1] == "feature" and node[2] == "test-support"
    if kind == "all":
        return any(_test_only(child) for child in node[1])
    if kind == "any":
        return bool(node[1]) and all(_test_only(child) for child in node[1])
    return False


def cfg_requires_test(condition: str) -> bool:
    """True only when a `cfg(...)` condition can hold in test builds alone.

    The recognized test gates are `test` and `feature = "test-support"`
    (that feature exists only so other crates' tests can reach fixtures,
    and is never enabled in a release build). `all(...)` is test-only when
    any of its clauses is; `any(...)` only when every clause is, so
    `any(test, madsim)` or `any(test, not(madsim))` is production code
    that happens to also compile under test. `not(...)` never is, and
    neither is any other gate (`unix`, `madsim`, another feature) or a
    condition this parser cannot read: an unrecognized gate is scanned as
    production rather than becoming a blind spot.
    """
    tree = _parse_cfg(condition)
    return tree is not None and _test_only(tree)


def _code_only(line: str) -> str:
    """Drop a trailing line comment (approximate: ignores `//` in strings)."""
    marker = line.find("//")
    return line[:marker] if marker != -1 else line


@functools.lru_cache(maxsize=None)
def cfg_test_spans(text: str) -> list[tuple[int, int]]:
    """Line ranges (1-indexed, inclusive) of items under a test-only `cfg`.

    Brace-matched from the `{` that opens the attributed item, skipping
    string literals; an attribute reaching a `;` before any `{` (a gated
    `mod tests;` or statement) covers only that statement.
    """
    spans: list[tuple[int, int]] = []
    position = 0
    size = len(text)
    while True:
        match = CFG_ATTR.search(text, position)
        if not match:
            break
        if not cfg_requires_test(match.group(1)):
            position = match.end()
            continue
        brace = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        start_line = text.count("\n", 0, match.start()) + 1
        if brace == -1 or (semicolon != -1 and semicolon < brace):
            end = semicolon if semicolon != -1 else match.end()
            spans.append((start_line, text.count("\n", 0, end) + 1))
            position = end + 1
            continue
        depth = 0
        cursor = brace
        while cursor < size:
            char = text[cursor]
            if char == '"':
                cursor += 1
                while cursor < size and text[cursor] != '"':
                    if text[cursor] == "\\":
                        cursor += 1
                    cursor += 1
                cursor += 1
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    cursor += 1
                    break
            cursor += 1
        spans.append((start_line, text.count("\n", 0, cursor) + 1))
        position = cursor
    return spans


MOD_DECL = re.compile(
    r"((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
)
PATH_ATTR = re.compile(r'#\[path\s*=\s*"([^"]+)"\]')


def test_module_files(files: list[Path]) -> set[Path]:
    """Every module file compiled only under a test-requiring `cfg`.

    Found from the declaring side: a `mod name;` whose stacked attributes
    include such a `cfg` marks the file it resolves to (`#[path]` honoured),
    and every file below a test module is a test file too.
    """
    roots: set[Path] = set()
    for path in files:
        text = path.read_text(encoding="utf-8")
        spans = cfg_test_spans(text)
        for match in MOD_DECL.finditer(text):
            attrs, name = match.group(1), match.group(2)
            line = text.count("\n", 0, match.start(2)) + 1
            inside_test_span = any(start <= line <= end for start, end in spans)
            if not inside_test_span and not any(
                cfg_requires_test(c.group(1)) for c in CFG_ATTR.finditer(attrs)
            ):
                continue
            if inside_test_span:
                # `mod name;` written inside an inline test module
                # (`#[cfg(test)] mod tests { mod name; }`): the file sits one
                # directory level below the declaring file's module directory.
                nested_base = path.parent if path.name in ("mod.rs", "lib.rs", "main.rs") else path.parent / path.stem
                roots.update(p.resolve() for p in nested_base.glob(f"*/{name}.rs"))
            explicit = PATH_ATTR.search(attrs)
            base = path.parent
            if path.name not in ("mod.rs", "lib.rs", "main.rs") and not explicit:
                base = path.parent / path.stem
            if explicit:
                roots.add((path.parent / explicit.group(1)).resolve())
            else:
                roots.add((base / f"{name}.rs").resolve())
                roots.add((base / name / "mod.rs").resolve())
    test_files: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        if resolved in roots:
            test_files.add(resolved)
            continue
        for root in roots:
            directory = root.parent if root.name == "mod.rs" else root.with_suffix("")
            if directory in resolved.parents:
                test_files.add(resolved)
                break
    return test_files


def production_lines(path: Path, text: str) -> list[tuple[int, str]]:
    """`(line number, code)` for every production line of one file."""
    lines = text.splitlines()
    if lines and lines[0].strip() == "#![cfg(test)]":
        return []
    spans = cfg_test_spans(text)
    out: list[tuple[int, str]] = []
    for number, line in enumerate(lines, start=1):
        if line.strip().startswith("//"):
            continue
        if any(start <= number <= end for start, end in spans):
            continue
        out.append((number, _code_only(line)))
    return out


def scan(root: Path, pattern: re.Pattern[str] = CALL) -> list[tuple[str, int, str, str]]:
    """Every counted call: `(repo-relative file, line, enclosing fn, API)`."""
    files = sorted(root.glob(SOURCE_GLOB))
    test_files = test_module_files(files)
    hits: list[tuple[str, int, str, str]] = []
    for path in files:
        if path.resolve() in test_files:
            continue
        rel = str(path.relative_to(root))
        text = path.read_text(encoding="utf-8")
        enclosing = "<module>"
        for number, code in production_lines(path, text):
            name = FN_NAME.match(code)
            if name:
                enclosing = name.group(1)
            for match in pattern.finditer(code):
                if re.search(r"\bfn\s+$", code[: match.start()]):
                    continue
                hits.append((rel, number, enclosing, match.group(1)))
    return hits


def evaluate(
    hits: list[tuple[str, int, str, str]],
    allowlist: dict[str, dict[str, int]],
    expected_total: int,
) -> list[str]:
    errors: list[str] = []
    found: Counter[tuple[str, str]] = Counter()
    lines: dict[tuple[str, str], list[int]] = {}
    for rel, number, _, api in hits:
        if api not in allowlist.get(rel, {}):
            hint = ""
            if file_kind(rel) == "lane":
                hint = (
                    "; an orchestration lane may not add raw calls, call a "
                    "ReplicaCoordinator semantic operation instead"
                )
            errors.append(
                f"{rel}:{number}: raw `{api}` is a materialization-semantic "
                f"primitive not allowlisted for this file{hint}"
            )
            continue
        found[(rel, api)] += 1
        lines.setdefault((rel, api), []).append(number)
    for rel, apis in sorted(allowlist.items()):
        for api, pinned in sorted(apis.items()):
            count = found[(rel, api)]
            if count != pinned:
                where = ", ".join(str(n) for n in lines.get((rel, api), [])) or "none"
                errors.append(
                    f"{rel}: `{api}` pinned at {pinned}, found {count} "
                    f"(lines: {where})"
                )
    listed = sum(sum(apis.values()) for apis in allowlist.values())
    if listed != expected_total:
        errors.append(
            f"ALLOWLIST sums to {listed} but EXPECTED_ALLOWED is {expected_total}"
        )
    total = sum(found.values())
    if total != expected_total:
        errors.append(
            f"allowlisted raw call count changed: expected {expected_total}, "
            f"found {total}"
        )
    return errors


def lane_errors(
    allowlists: list[dict[str, dict[str, int]]], lane_files: frozenset[str]
) -> list[str]:
    """The lane rule: allowlisted lane files are exactly the frozen set."""
    errors: list[str] = []
    listed = {rel for allowlist in allowlists for rel in allowlist}
    for rel in sorted(listed):
        if file_kind(rel) == "lane" and rel not in lane_files:
            errors.append(
                f"{rel}: orchestration lanes may not add raw calls; compose "
                "the step inside a ReplicaCoordinator semantic operation "
                "instead of allowlisting this file"
            )
    for rel in sorted(lane_files - listed):
        errors.append(
            f"{rel}: no longer holds raw calls; remove it from LANE_FILES"
        )
    for rel in sorted(lane_files):
        if file_kind(rel) != "lane":
            errors.append(f"{rel}: listed in LANE_FILES but is not a lane file")
    return errors


def split(allowlist: dict[str, dict[str, int]]) -> Counter[str]:
    """Pinned calls per file kind."""
    kinds: Counter[str] = Counter()
    for rel, apis in allowlist.items():
        kinds[file_kind(rel)] += sum(apis.values())
    return kinds


def self_test() -> None:
    # Only recognized test gates make code test-only; a production gate
    # that also admits `test` stays scanned.
    for condition, expected in (
        ("test", True),
        ('feature = "test-support"', True),
        ("all(test, unix)", True),
        ("all(windows, not(madsim), test)", True),
        ('any(test, feature = "test-support")', True),
        ("not(test)", False),
        ("any(test, madsim)", False),
        ("any(test, not(madsim))", False),
        ('feature = "test"', False),
        ("unix", False),
        ("all(not(test), unix)", False),
        ("any(test", False),
    ):
        assert cfg_requires_test(condition) is expected, condition
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates" / "demo" / "src"
        (src / "helpers").mkdir(parents=True)
        (src / "lib.rs").write_text(
            "mod prod;\n"
            "#[cfg(test)]\nmod tests;\n"
            "#[cfg(any(test, feature = \"test-support\"))]\npub mod helpers;\n"
            "#[cfg(test)]\n#[path = \"odd_name.rs\"]\nmod renamed;\n",
            encoding="utf-8",
        )
        (src / "prod.rs").write_text(
            "pub fn set_held(x: u8) {}\n"                       # definition
            "trait T { fn clear_held(&self); }\n"               # declaration
            "fn a(s: &S) {\n"
            "    s.dag_bump_mutation_fence(1);\n"               # counted once
            "    // s.set_held(2);\n"                           # comment
            "    s.clear_held_in_tx(3); // set_held(9)\n"      # counted once
            "    s.not_set_held(4);\n"                          # other ident
            "    MaterializationIntentGuard::open(5);\n"        # counted
            "}\n"
            "#[cfg(not(test))]\nfn b(s: &S) { s.set_held(6); }\n"  # production
            "#[cfg(all(test, unix))]\nfn c(s: &S) { s.set_held(7); }\n"
            "#[cfg(test)]\nmod t {\n    fn d(s: &S) { s.set_held(8); }\n}\n"
            "fn e(s: &S) { s.set_held::<u8>(10); }\n",       # turbofish
            encoding="utf-8",
        )
        for name in ("tests.rs", "helpers.rs", "odd_name.rs", "helpers/deep.rs"):
            (src / name).write_text("fn f(s: &S) { s.set_held(1); }\n", encoding="utf-8")
        (src / "banner.rs").write_text(
            "#![cfg(test)]\nfn f(s: &S) { s.set_held(1); }\n", encoding="utf-8"
        )

        hits = scan(root)
        got = sorted((rel.rsplit("/", 1)[-1], line, fn, api) for rel, line, fn, api in hits)
        want = sorted(
            [
                ("prod.rs", 4, "a", "dag_bump_mutation_fence"),
                ("prod.rs", 6, "a", "clear_held_in_tx"),
                ("prod.rs", 8, "a", "MaterializationIntentGuard::open"),
                ("prod.rs", 11, "b", "set_held"),
                ("prod.rs", 18, "e", "set_held"),
            ]
        )
        assert got == want, f"scan mismatch:\n got  {got}\n want {want}"

        prod = "crates/demo/src/prod.rs"
        exact = {
            prod: {
                "dag_bump_mutation_fence": 1,
                "clear_held_in_tx": 1,
                "MaterializationIntentGuard::open": 1,
                "set_held": 2,
            }
        }
        assert evaluate(hits, exact, 5) == [], evaluate(hits, exact, 5)

        # An API not allowlisted for the file is a violation.
        missing = {prod: {k: v for k, v in exact[prod].items() if k != "set_held"}}
        errors = evaluate(hits, missing, 3)
        assert any("raw `set_held`" in e for e in errors), errors

        # One extra call of an allowlisted API trips the pinned counts.
        extra = hits + [(prod, 99, "a", "set_held")]
        errors = evaluate(extra, exact, 5)
        assert any("pinned at 2, found 3" in e for e in errors), errors
        assert any("expected 5, found 6" in e for e in errors), errors

        # A removed call trips them too, and so does a stale total.
        errors = evaluate(hits[:-1], exact, 5)
        assert any("pinned at 2, found 1" in e for e in errors), errors
        assert any("EXPECTED_ALLOWED" in e for e in evaluate(hits, exact, 6))

        # A raw call in a lane file that is not allowlisted names the rule.
        errors = evaluate(hits, {}, 0)
        assert any("orchestration lane may not add" in e for e in errors), errors

        # The lane rule: a lane file must already be frozen, a frozen file
        # must still be listed, and owner/repository files are never lanes.
        owner = D + "replica_coordinator/x.rs"
        repo = S + "x.rs"
        assert file_kind(prod) == "lane"
        assert file_kind(owner) == "owner"
        assert file_kind(D + "replica_coordinator.rs") == "owner"
        assert file_kind(repo) == "repository"
        lanes = frozenset({prod})
        assert lane_errors([exact, {owner: {"set_held": 1}}], lanes) == []
        errors = lane_errors([exact], frozenset())
        assert any("may not add raw calls" in e for e in errors), errors
        errors = lane_errors([{owner: {"set_held": 1}}], lanes)
        assert any("remove it from LANE_FILES" in e for e in errors), errors
        errors = lane_errors([exact], frozenset({prod, owner}))
        assert any("is not a lane file" in e for e in errors), errors
        assert split({prod: {"a": 2}, owner: {"b": 3}, repo: {"c": 1}}) == Counter(
            {"lane": 2, "owner": 3, "repository": 1}
        )

        # The in-family pattern: exact names only, definitions skipped.
        (src / "family.rs").write_text(
            "fn upsert_file_with_origin(x: u8) {}\n"
            "fn g(s: &S) {\n"
            "    s.upsert_file_with_origin(1);\n"
            "    s.upsert_file_with_origin_and_author(2);\n"
            "    s.set_authoring_change_hash(3);\n"
            "    s.set_authoring_change_hash_flag(4);\n"
            "}\n",
            encoding="utf-8",
        )
        family = sorted(
            (line, api)
            for rel, line, _, api in scan(root, IN_FAMILY_CALL)
            if rel.endswith("family.rs")
        )
        assert family == [
            (3, "upsert_file_with_origin"),
            (4, "upsert_file_with_origin_and_author"),
            (5, "set_authoring_change_hash"),
        ], family


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true", help="print every counted call site")
    parser.add_argument(
        "--list-in-family", action="store_true", help="print every counted IN_FAMILY call site"
    )
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("materialization semantic boundary self-test passed")
        return 0

    hits = scan(ROOT)
    family_hits = scan(ROOT, IN_FAMILY_CALL)
    if args.list or args.list_in_family:
        for rel, number, enclosing, api in hits if args.list else family_hits:
            print(f"{rel}:{number}\t{enclosing}\t{api}")
        return 0

    errors = evaluate(hits, ALLOWLIST, EXPECTED_ALLOWED)
    errors += [
        error.replace("EXPECTED_ALLOWED", "EXPECTED_IN_FAMILY_ALLOWED").replace(
            "ALLOWLIST sums", "IN_FAMILY_ALLOWLIST sums"
        )
        for error in evaluate(family_hits, IN_FAMILY_ALLOWLIST, EXPECTED_IN_FAMILY_ALLOWED)
    ]
    errors += lane_errors([ALLOWLIST, IN_FAMILY_ALLOWLIST], LANE_FILES)
    if errors:
        print(
            "raw materialization-semantic calls must stay on the reviewed, "
            "pinned sites:",
            file=sys.stderr,
        )
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        print(
            "Review the site; if it is legitimate, update ALLOWLIST and "
            "EXPECTED_ALLOWED (or IN_FAMILY_ALLOWLIST and "
            "EXPECTED_IN_FAMILY_ALLOWED) in this script together. Pins are "
            "exact; by policy a lane's pins only go down.",
            file=sys.stderr,
        )
        return 1
    kinds = split(ALLOWLIST)
    family = split(IN_FAMILY_ALLOWLIST)
    print(
        f"materialization semantic boundary: ok ({EXPECTED_ALLOWED} pinned raw calls: "
        f"lane {kinds['lane']}, owner {kinds['owner']}, repository {kinds['repository']}; "
        f"{EXPECTED_IN_FAMILY_ALLOWED} pinned in-family calls: lane {family['lane']}, "
        f"owner {family['owner']}, repository {family['repository']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
