#![cfg(test)]

use super::*;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::rewind::{RewindUnavailable, RewindUnavailableReason};

fn plan_of(entries: Vec<RewindPathEntry>) -> RewindPlan {
    RewindPlan {
        group_id: "g".to_string(),
        target_unix_nanos: 100,
        entries,
        rename_candidates: Vec::new(),
    }
}

fn entry(path: &str, action: RewindPathAction) -> RewindPathEntry {
    RewindPathEntry {
        path: path.to_string(),
        current_version_seq: 1,
        current_version_hash: VersionHash([0u8; 32]),
        action,
    }
}

/// The default response omits `unchanged` entries but must still report
/// them -- a summary that undercounted the paths a rewind would leave
/// alone would misdescribe the plan.
#[test]
fn omitting_unchanged_entries_never_changes_the_counts() {
    let plan = plan_of(vec![
        entry("a", RewindPathAction::Unchanged),
        entry("b", RewindPathAction::Delete),
        entry("c", RewindPathAction::Unchanged),
    ]);

    let trimmed = trim_for_wire(plan.clone(), false);
    assert_eq!(trimmed.counts.unchanged, 2);
    assert_eq!(trimmed.counts.delete, 1);
    assert_eq!(trimmed.total_entry_count, 3);
    assert_eq!(trimmed.entries.len(), 1, "only the non-unchanged path is listed");
    assert_eq!(trimmed.entries[0].path, "b");
    assert!(!trimmed.listing_truncated, "a filter is not a truncation");

    let verbose = trim_for_wire(plan, true);
    assert_eq!(verbose.counts, trimmed.counts, "the tallies do not depend on the listing");
    assert_eq!(verbose.entries.len(), 3);
}

/// The filter alone is not a bound: a target older than the whole
/// folder classifies every path as something other than `unchanged`.
/// The byte budget is what actually guarantees a deliverable response,
/// and it must say when it cut something.
#[test]
fn the_listing_is_capped_even_when_nothing_is_unchanged() {
    let entries = (0..200_000)
        .map(|i| {
            entry(&format!("deep/nested/directory/path/file-{i:06}.bin"), RewindPathAction::Delete)
        })
        .collect();
    let trimmed = trim_for_wire(plan_of(entries), false);

    assert_eq!(trimmed.total_entry_count, 200_000, "the whole plan is still reported");
    assert_eq!(trimmed.counts.delete, 200_000);
    assert!(trimmed.listing_truncated, "a cut listing must be flagged as cut");
    assert!(
        trimmed.entries.len() < 200_000,
        "the listing must actually be capped, not merely flagged"
    );
}

/// The advisory rename list gets its own, much smaller budget so it
/// cannot crowd out the authoritative per-path entries.
#[test]
fn the_rename_list_has_its_own_budget() {
    let mut plan = plan_of(vec![entry("a", RewindPathAction::Delete)]);
    plan.rename_candidates = (0..100_000)
        .map(|i| RewindRenameCandidate {
            from_path: format!("from/long/enough/to/matter/{i:06}"),
            to_path: format!("to/long/enough/to/matter/{i:06}"),
            version_hash: VersionHash([0u8; 32]),
        })
        .collect();

    let trimmed = trim_for_wire(plan, false);
    assert_eq!(trimmed.total_rename_candidate_count, 100_000);
    assert!(trimmed.rename_candidates.len() < 100_000);
    assert!(trimmed.listing_truncated);
    assert_eq!(
        trimmed.entries.len(),
        1,
        "the per-path entry must survive a flood of rename candidates"
    );
}

/// What a preview shows is a trimmed listing, but the id it carries is the
/// whole plan's: filtering `unchanged` entries out, listing them, or
/// cutting the listing at the byte budget all yield the id the full plan
/// has.
#[test]
fn a_trimmed_preview_carries_the_full_plans_id() {
    let small = plan_of(vec![
        entry("a", RewindPathAction::Unchanged),
        entry("b", RewindPathAction::Delete),
        entry("c", RewindPathAction::Unchanged),
    ]);
    let full_id = small.plan_id();
    assert_eq!(trim_for_wire(small.clone(), false).plan_id, full_id);
    assert_eq!(trim_for_wire(small, true).plan_id, full_id);

    let big = plan_of(
        (0..200_000)
            .map(|i| entry(&format!("deep/nested/file-{i:06}.bin"), RewindPathAction::Delete))
            .collect(),
    );
    let full_id = big.plan_id();
    let trimmed = trim_for_wire(big, false);
    assert!(trimmed.listing_truncated, "the listing must actually have been cut");
    assert_eq!(trimmed.plan_id, full_id);
}

#[test]
fn the_approved_plan_is_accepted_when_it_is_still_the_current_one() {
    let plan = plan_of(vec![entry("a", RewindPathAction::Delete)]);
    let approved = plan.plan_id();
    assert_eq!(accept_approved_plan(plan.clone(), &approved), Ok(plan));
}

/// A different current plan is refused with its own id and tallies, and
/// never handed back to be executed in place of the approved one.
#[test]
fn a_changed_plan_is_refused_as_stale() {
    let approved = plan_of(vec![entry("a", RewindPathAction::Delete)]).plan_id();
    let current =
        plan_of(vec![entry("a", RewindPathAction::Delete), entry("b", RewindPathAction::Delete)]);
    let expected = RewindExecuteError::PlanStale {
        current_plan_id: current.plan_id(),
        current_counts: current.action_counts(),
    };
    assert_eq!(accept_approved_plan(current, &approved), Err(expected));
}

/// Unavailable paths refuse the whole rewind even when the plan is exactly
/// the approved one: there is no partial execution.
#[test]
fn an_approved_plan_with_unavailable_paths_cannot_start() {
    let plan = plan_of(vec![
        entry("a", RewindPathAction::Delete),
        entry(
            "b",
            RewindPathAction::Unavailable { reason: RewindUnavailableReason::RemovedByRetention },
        ),
        entry("c", RewindPathAction::Unavailable { reason: RewindUnavailableReason::JoinedAfter }),
        entry("d", RewindPathAction::Unavailable { reason: RewindUnavailableReason::JoinedAfter }),
    ]);
    let approved = plan.plan_id();
    let refused = accept_approved_plan(plan, &approved).unwrap_err();
    assert_eq!(
        refused,
        RewindExecuteError::UnavailablePaths(RewindUnavailable {
            by_reason: vec![
                (RewindUnavailableReason::JoinedAfter, 2),
                (RewindUnavailableReason::RemovedByRetention, 1),
            ],
        })
    );
    // One sentence, grouped by cause, saying where the history is.
    assert_eq!(
        refused.to_string(),
        "3 files unavailable; rewind cannot start: 2 because this device joined after that \
         time; run the rewind from a device that has the history (e.g. your NAS); 1 because \
         older versions were removed by retention"
    );
}

mod against_a_daemon {
    use std::sync::Arc;

    use yadorilink_local_storage::SegmentBlockStore;

    use super::super::*;
    use crate::replica_coordinator::ReplicaCoordinator;

    const GROUP: &str = "group-rewind";

    /// Writes `path`'s new `current` row (superseding the previous one),
    /// admitted at `at` -- the supersede-then-insert pair of the real write
    /// path, with a chosen admission instant.
    fn write_current(state: &DaemonState, path: &str, seq: i64, size: i64, at: i64) {
        let database = state.replica_coordinator.database();
        let conn = database.pool_for_test().get().unwrap();
        conn.execute(
            "UPDATE files SET state = 'superseded' \
             WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
            rusqlite::params![GROUP, path],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                                mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
             VALUES (?1, ?2, ?3, 'current', 0, ?4, 0, '[]', ?5)",
            rusqlite::params![GROUP, path, seq, size, at],
        )
        .unwrap();
    }

    /// A linked group whose index already holds, at T=500, one untouched
    /// path and one created after the target.
    fn linked_state() -> Arc<DaemonState> {
        linked_state_at("/rewind/root")
    }

    fn linked_state_at(root: &str) -> Arc<DaemonState> {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let state = DaemonState::build(
            "device-a".into(),
            Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
            store,
        );
        // Rows first: a group linked while already holding rows records no
        // local history floor, so T=500 is answered from these rows.
        write_current(&state, "steady.txt", 1, 10, 100);
        write_current(&state, "new.txt", 1, 20, 900);
        state.replica_coordinator.link_repository().add_link(root, GROUP).unwrap();
        state
    }

    fn request(plan_id: RewindPlanId) -> RewindExecuteRequest {
        RewindExecuteRequest { group_id: GROUP.into(), target_unix_nanos: 500, plan_id }
    }

    #[tokio::test]
    async fn the_previewed_plan_verifies_against_an_unchanged_folder() {
        let state = linked_state();
        let full =
            state.replica_coordinator.sqlite().compute_rewind_plan(GROUP, 500, &|_| false).unwrap();
        let preview = preview_rewind(state.clone(), GROUP.into(), 500, false).await.unwrap();
        assert_eq!(preview.plan_id, full.plan_id(), "the preview carries the full plan's id");

        let verified = verify_rewind_plan(state, request(preview.plan_id)).await.unwrap();
        assert_eq!(verified, full, "the verified plan is the plan that was previewed");
    }

    #[tokio::test]
    async fn an_edit_after_the_preview_rejects_the_previewed_plan() {
        let state = linked_state();
        let preview = preview_rewind(state.clone(), GROUP.into(), 500, false).await.unwrap();

        // The path the preview would delete is edited before execution.
        write_current(&state, "new.txt", 2, 21, 1_000);

        let current =
            state.replica_coordinator.sqlite().compute_rewind_plan(GROUP, 500, &|_| false).unwrap();
        assert_eq!(current.action_counts(), preview.counts, "same tallies, different plan");
        match verify_rewind_plan(state, request(preview.plan_id)).await {
            Err(RewindExecuteError::PlanStale { current_plan_id, current_counts }) => {
                assert_eq!(current_plan_id, current.plan_id());
                assert_ne!(current_plan_id, preview.plan_id);
                assert_eq!(current_counts, current.action_counts());
            }
            other => panic!("expected PlanStale, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_plan_for_another_target_is_rejected() {
        let state = linked_state();
        let preview = preview_rewind(state.clone(), GROUP.into(), 500, false).await.unwrap();
        let mut later = request(preview.plan_id);
        later.target_unix_nanos = 501;
        assert!(matches!(
            verify_rewind_plan(state, later).await,
            Err(RewindExecuteError::PlanStale { .. })
        ));
    }

    #[tokio::test]
    async fn an_unlinked_group_is_refused_before_any_plan_comparison() {
        let state = linked_state();
        let preview = preview_rewind(state.clone(), GROUP.into(), 500, false).await.unwrap();
        let mut other = request(preview.plan_id);
        other.group_id = "not-linked".into();
        assert_eq!(
            verify_rewind_plan(state, other).await,
            Err(RewindExecuteError::Plan(RewindError::UnknownGroup("not-linked".into())))
        );
    }

    /// A file that existed at the target was ignored and un-ignored since:
    /// the ignore sweep erased its rows and the re-index numbered it from 1
    /// again. The preview must not plan its deletion, and executing the
    /// previewed plan is refused as a whole.
    #[tokio::test]
    async fn a_file_ignored_and_unignored_since_the_target_blocks_the_rewind() {
        let state = linked_state();
        state
            .replica_coordinator
            .file_index_repository()
            .remove_file(
                GROUP,
                "steady.txt",
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        write_current(&state, "steady.txt", 1, 10, 1_000);

        let preview = preview_rewind(state.clone(), GROUP.into(), 500, false).await.unwrap();
        assert_eq!(preview.counts.unavailable, 1);
        assert_eq!(preview.counts.delete, 1, "only new.txt was created after the target");
        assert_eq!(
            verify_rewind_plan(state, request(preview.plan_id)).await,
            Err(RewindExecuteError::UnavailablePaths(super::RewindUnavailable {
                by_reason: vec![(super::RewindUnavailableReason::ExcludedFromSync, 1)],
            }))
        );
    }

    fn erase_like_the_ignore_sweep(state: &DaemonState, path: &str) {
        assert!(state
            .replica_coordinator
            .file_index_repository()
            .remove_file(
                GROUP,
                path,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap());
    }

    /// A file that existed at the target was erased by the ignore sweep and
    /// never indexed again (it is no longer excluded, but nothing came
    /// back). The rewind cannot say what it held, so it cannot start.
    #[tokio::test]
    async fn an_erased_file_not_indexed_again_blocks_the_rewind() {
        let state = linked_state();
        erase_like_the_ignore_sweep(&state, "steady.txt");

        let preview = preview_rewind(state.clone(), GROUP.into(), 500, false).await.unwrap();
        assert_eq!(preview.counts.unavailable, 1);
        assert!(preview.entries.iter().any(|e| e.path == "steady.txt"));
        assert_eq!(
            verify_rewind_plan(state, request(preview.plan_id)).await,
            Err(RewindExecuteError::UnavailablePaths(super::RewindUnavailable {
                by_reason: vec![(super::RewindUnavailableReason::ExcludedFromSync, 1)],
            }))
        );
    }

    /// The same erased file while the folder's ignore file still excludes
    /// it: outside the plan, like any ignored path, so the rewind can start.
    #[tokio::test]
    async fn an_erased_file_that_is_still_ignored_stays_outside_the_plan() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".yadorilinkignore"), "steady.txt\n").unwrap();
        let state = linked_state_at(root.path().to_str().unwrap());
        erase_like_the_ignore_sweep(&state, "steady.txt");

        let preview = preview_rewind(state.clone(), GROUP.into(), 500, true).await.unwrap();
        assert_eq!(preview.counts.unavailable, 0);
        assert!(!preview.entries.iter().any(|e| e.path == "steady.txt"));
        assert!(verify_rewind_plan(state, request(preview.plan_id)).await.is_ok());
    }
}
