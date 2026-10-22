# Data Durability Model

Physical storage safety is defined by these invariants. Symbol names and test
IDs are the stable source of truth; file line numbers are intentionally omitted.

## DL-1: Materialized Files Have Their Blocks

- Target state: every current `Hydrated` regular file at a stable repair boundary.
- Destructive operations: cache eviction, GC, interrupted reconstruction, and block corruption.
- Enforcement symbol: `repair_interrupted_materializations` and `ReplicaCoordinator::reclaim_cached_blocks`.
- Test IDs: `repair_demotes_to_placeholder_when_blocks_are_also_missing_locally`, `eviction_must_not_delete_block_used_by_hydrated_file_in_another_group`.
- Runtime diagnosis: link materialization state, repair warning logs, and recent `block_integrity` errors.

## DL-2: Non-Forced Role Loss Keeps A Holder

- Target state: every current version in an active group before demote, unlink, revoke, or device removal.
- Destructive operations: loss of an eager ACL edge or local eager link.
- Enforcement symbol: `ensure_unlink_keeps_a_full_replica`, `full_replica_handoff_ready`, and coordination-service lease-guarded role-loss commit services.
- Test IDs: `last_full_replica_cannot_unlink`, `unlink_refused_when_no_other_replica_is_ready`, `demotion_refused_when_the_target_cannot_grant_a_lease`.
- Runtime diagnosis: handoff readiness response, durability status, role-loss journal state, and coordination-service audit events.

## DL-3: Physical Deletion Is Global

- Target state: every retained version in every group sharing a content hash.
- Destructive operations: GC sweep and on-demand cache reclaim.
- Enforcement symbol: `BlockPhysicalDeletionGuard`, `ReplicaCoordinator::reclaim_cached_blocks`, `sweep_globally_unreferenced_blocks`, and `MaterializationStateRepository::blocks_referenced_outside_current_file`.
- Test IDs: `eviction_must_not_delete_block_used_by_hydrated_file_in_another_group`, `eviction_must_not_delete_block_retained_for_uncustodied_placeholder_in_another_group`, `concurrent_evictions_across_groups_must_preserve_shared_block`.
- Runtime diagnosis: GC report, eviction outcome, and `check-block-deletion-boundary.py` CI result.

## DL-4: Liveness Snapshot And Reference Writes Do Not Race

- Target state: the device-global block store and all index commits that add block references.
- Destructive operations: GC from live-set snapshot through final physical deletion.
- Enforcement symbol: `BlockLivenessGate`, `DaemonState::begin_write_activity`, and `BlockWriteActivityProvider`.
- Test IDs: `gc_must_not_delete_old_deduplicated_block_adopted_after_live_snapshot`, `eager_adoption_waits_for_the_block_deletion_gate_before_committing_a_reference`.
- Runtime diagnosis: GC `SyncBurstInProgress`, task liveness, and GC completion counters.

## DL-5: Crash Leaves A Recoverable State

- Target state: block/index materialization and service/local role-loss operations.
- Destructive operations: process termination between block write, index commit, filesystem rename, service commit, and local commit.
- Enforcement symbol: `repair_interrupted_materializations`, `RoleLossOperation`, and `run_role_loss_reconciliation_sweep`.
- Test IDs: `repair_reconstructs_locally_after_a_simulated_crash_before_rename`, `demote_local_failure_after_worker_commit_is_compensated_and_rolled_back`, `prepared_reconcile_restores_worker_eager_after_response_loss`.
- Runtime diagnosis: materialization repair logs and persisted role-loss journal state/attempt count.

## DL-6: Role Loss Never Silently Removes The Last Holder

- Target state: demote, unlink, revoke, and multi-group device removal commits.
- Destructive operations: lease-free role loss, stale readiness, partial multi-group commit, and ambiguous coordination-service response.
- Enforcement symbol: `commit_handoff_role_loss`, atomic coordination-service device removal, and `RoleLossCommitOutcome`.
- Test IDs: `ambiguous_demote_keeps_prepared_journal`, `ambiguous_unlink_keeps_prepared_journal`, `demotion_writes_the_worker_exactly_once_via_role_loss_commit`.
- Runtime diagnosis: CLI role-loss result, coordination-service audit event, and persisted role-loss journal.

## DL-7: Forced Durability Unknown Survives Restart

- Target state: every group whose last-holder safety gate was bypassed with force.
- Destructive operations: daemon restart or a status recomputation that would otherwise report `Healthy`.
- Enforcement symbol: `RoleLossOperationRepository::latch_group_durability_unknown`, `DaemonState::group_durability_status`, and `DaemonState::clear_group_durability_latch`.
- Test IDs: `forced_durability_unknown_latch_survives_daemon_restart`, `forced_unlink_latches_group_durability_unknown`.
- Runtime diagnosis: `yadorilink status` displays `durability unknown`; persistent table `durability_unknown_latches` records the group until positive whole-group re-confirmation.

