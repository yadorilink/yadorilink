//! The snapshot must agree with what the status view reports for the same
//! folder, gate by gate: it reads the same inputs and decides nothing new.

use std::sync::Arc;

use super::*;
use crate::adapters::query::link_status::DaemonLinkStatusReader;
use crate::daemon_state::DaemonState;
use crate::link_registry::DegradedCause;
use crate::queries::link_status::LinkStatusReadPort;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "group-1";

/// A folder that exists, so the volume probe has a root to identify.
fn folder() -> &'static str {
    Box::leak(tempfile::tempdir().unwrap().keep().to_str().unwrap().to_string().into_boxed_str())
}

fn state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

/// The snapshot and the composed view of the only link.
fn both(state: &Arc<DaemonState>) -> (FolderSnapshot, crate::queries::link_status::LinkStatusView) {
    let reader = DaemonLinkStatusReader::new(Arc::clone(state));
    let facts = reader.collect_links().unwrap();
    assert_eq!(facts.len(), 1);
    let view = reader.compose_links(&facts).remove(0);
    let snapshot = FolderSnapshot::read(
        &facts[0],
        crate::adapters::query::link_status::link_degraded_view(state, &facts[0].link)
            .map(|d| d.cause),
        state.authority.is_group_policy_stale(GROUP),
    );
    // The gates the view reports directly agree with the snapshot, whatever the case sets.
    let has = |b| snapshot.blockers().contains(&b);
    assert_eq!(view.paused, has(FolderBlocker::Paused));
    assert_eq!(view.policy_stale, has(FolderBlocker::PolicyStale));
    assert_eq!(view.capture_volume_changed, has(FolderBlocker::CaptureVolumeChanged));
    assert_eq!(view.capture_volume_unconfirmed, has(FolderBlocker::CaptureVolumeUnconfirmed));
    assert_eq!(view.ambiguous_local_paths.len() > 1, has(FolderBlocker::AmbiguousLink));
    assert_eq!(!view.index_damaged_path.is_empty(), has(FolderBlocker::IndexDamaged));
    assert_eq!(view.rebuild_needed, has(FolderBlocker::RebuildNeeded));
    let degraded = snapshot.blockers().iter().find_map(|b| match b {
        FolderBlocker::Degraded(cause) => Some(*cause),
        _ => None,
    });
    assert_eq!(view.degraded.as_ref().map(|d| d.cause), degraded);
    (snapshot, view)
}

#[tokio::test]
async fn an_idle_linked_folder_may_advance() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    let (snapshot, view) = both(&state);
    assert!(snapshot.may_advance());
    assert!(view.folder_blockers.is_empty());
    assert!(!view.paused && view.degraded.is_none() && !view.policy_stale);
}

#[tokio::test]
async fn paused_matches_the_view() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    state.replica_coordinator.link_repository().set_paused(path, true).unwrap();
    let (snapshot, view) = both(&state);
    assert!(view.paused);
    assert_eq!(snapshot.blockers(), [FolderBlocker::Paused]);
    assert_eq!(view.folder_blockers, [FolderBlocker::Paused]);
}

#[tokio::test]
async fn degraded_cause_matches_the_view() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    state.wait_for_disk_space(path, "full".into());
    let (snapshot, view) = both(&state);
    assert_eq!(view.degraded.as_ref().unwrap().cause, DegradedCause::WaitingForDiskSpace);
    assert_eq!(snapshot.blockers(), [FolderBlocker::Degraded(DegradedCause::WaitingForDiskSpace)]);

    state.recover_link(path);
    let (snapshot, view) = both(&state);
    assert!(view.degraded.is_none());
    assert!(snapshot.may_advance());
}

#[tokio::test]
async fn ownership_lost_is_a_degraded_blocker() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    assert!(state.lose_ownership(path));
    let (snapshot, view) = both(&state);
    assert_eq!(view.degraded.as_ref().unwrap().cause, DegradedCause::OwnershipLost);
    assert_eq!(snapshot.blockers(), [FolderBlocker::Degraded(DegradedCause::OwnershipLost)]);
}

#[tokio::test]
async fn stale_policy_matches_the_view_and_clears() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    state.mark_group_policy_stale(GROUP);
    let (snapshot, view) = both(&state);
    assert!(view.policy_stale);
    assert_eq!(snapshot.blockers(), [FolderBlocker::PolicyStale]);

    state.authority.clear_group_policy_stale(GROUP);
    let (snapshot, view) = both(&state);
    assert!(!view.policy_stale);
    assert!(snapshot.may_advance());
}

#[tokio::test]
async fn blockers_combine_in_a_fixed_order() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    state.replica_coordinator.link_repository().set_paused(path, true).unwrap();
    state.wait_for_disk_space(path, "full".into());
    state.mark_group_policy_stale(GROUP);
    let (snapshot, view) = both(&state);
    assert_eq!(
        snapshot.blockers(),
        [
            FolderBlocker::Paused,
            FolderBlocker::Degraded(DegradedCause::WaitingForDiskSpace),
            FolderBlocker::PolicyStale,
        ]
    );
    assert_eq!(view.folder_blockers, snapshot.blockers());

    // The wire status takes its gates from the snapshot and agrees with the view's own flags.
    let wire = crate::status_report::encode_link_status(view.clone());
    assert!(wire.degraded && wire.waiting_for_disk_space && wire.policy_stale && wire.paused);
    assert_eq!(wire.degraded, view.degraded.is_some());
    assert_eq!(wire.policy_stale, view.policy_stale);
    assert!(!wire.ambiguous && !wire.rebuild_needed);
    assert!(!wire.capture_volume_changed && !wire.capture_volume_unconfirmed);
}

#[tokio::test]
async fn an_orphaned_link_is_blocked_as_not_joined() {
    let state = state();
    let path = folder();
    state.replica_coordinator.link_repository().add_link(path, GROUP).unwrap();
    state.replica_coordinator.link_repository().mark_link_orphaned(path).unwrap();
    let (snapshot, view) = both(&state);
    assert!(view.orphaned);
    assert_eq!(snapshot.blockers(), [FolderBlocker::Degraded(DegradedCause::NotJoined)]);
}

/// The link registry's degraded and ownership marks are written only by the transitions in
/// `folder_state/transitions.rs`; a call elsewhere would bypass the named transition.
#[test]
fn only_the_transitions_write_the_degraded_marks() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut stack = vec![src.clone()];
    let mut offenders = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let relative = path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
            if !name.ends_with(".rs")
                || relative == "link_registry.rs"
                || relative == "folder_state/transitions.rs"
                || relative == "folder_state/tests.rs"
                || name == "tests.rs"
                || name.ends_with("_tests.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for write in [
                "links.mark_degraded(",
                "links.mark_ownership_lost(",
                "links.mark_no_change_source(",
                "links.clear_degraded(",
                "links.clear_ownership_lost(",
                "links.mark_awaiting_volume(",
                "links.clear_awaiting_volume(",
                "links.track_watcher(",
                "links.record_watch_limit_startup_failure(",
                "links.clear_watch_limit(",
            ] {
                if text.contains(write) {
                    offenders.push(format!("{relative}: {write}"));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "registry writes outside the transitions: {offenders:?}");
}

fn mark_dirty(state: &DaemonState, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .dirty_path_repository()
        .record_dirty_path(GROUP, path, "modify", 1, &permit)
        .unwrap();
}

fn own_changes(state: &DaemonState, seq: i64) {
    state
        .replica_coordinator
        .database()
        .write(|conn| {
            conn.execute(
                "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![GROUP, state.device_id, [1u8; 16].as_slice(), seq],
            )?;
            Ok::<(), yadorilink_sync_sqlite::SyncSqliteError>(())
        })
        .unwrap();
}

#[tokio::test]
async fn a_folder_with_no_other_device_has_nothing_pending() {
    let state = state();
    state.replica_coordinator.link_repository().add_link(folder(), GROUP).unwrap();
    mark_dirty(&state, "a.txt");
    own_changes(&state, 4);
    let (snapshot, view) = both(&state);
    assert_eq!(snapshot.pending_local_changes(), 0);
    assert_eq!(view.pending_local_changes, 0);
}

#[tokio::test]
async fn pending_changes_are_captured_edits_plus_changes_no_peer_holds() {
    let state = state();
    state.replica_coordinator.link_repository().add_link(folder(), GROUP).unwrap();
    state.set_peer_group_writer("device-b", GROUP, true);
    mark_dirty(&state, "a.txt");
    mark_dirty(&state, "b.txt");
    own_changes(&state, 5);
    let (snapshot, view) = both(&state);
    assert_eq!(snapshot.pending_local_changes(), 7);
    assert_eq!(view.pending_local_changes, 7);
    // The wire status carries the same figure.
    assert_eq!(crate::status_report::encode_link_status(view).pending_local_changes, 7);

    // The peer names 3 of the 5 recorded changes.
    state
        .replica_coordinator
        .database()
        .write(|conn| {
            yadorilink_sync_sqlite::peer_progress::record_peer_progress(
                conn,
                GROUP,
                "device-b",
                3,
                yadorilink_sync_sqlite::peer_progress::request_ticket(),
            )
        })
        .unwrap();
    let (snapshot, _) = both(&state);
    assert_eq!(snapshot.pending_local_changes(), 4);
}

#[tokio::test]
async fn a_folder_waits_for_its_volume_until_it_stops_waiting() {
    let state = state();
    let folder = folder();
    assert!(!state.links.is_awaiting_volume(folder));
    await_volume(&state.links, folder);
    assert!(state.links.is_awaiting_volume(folder));
    stop_awaiting_volume(&state.links, folder);
    assert!(!state.links.is_awaiting_volume(folder));
}

#[tokio::test]
async fn a_blocked_watcher_start_is_reported_until_it_is_forgotten_or_rebound() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let state = state();
    let folder = folder();
    assert!(state.links.watch_limit_reason(folder).is_none());

    watch_limit_blocked_start(&state.links, folder);
    assert!(state.links.watch_limit_reason(folder).unwrap().contains("not syncing"));
    watch_limit_forgotten(&state.links, folder);
    assert!(state.links.watch_limit_reason(folder).is_none());

    // A bound watcher reports the limit only while its flag is set.
    let flag = Arc::new(AtomicBool::new(false));
    watcher_bound(&state.links, folder, flag.clone());
    assert!(state.links.watch_limit_reason(folder).is_none());
    flag.store(true, Ordering::Relaxed);
    assert!(state.links.watch_limit_reason(folder).unwrap().contains("late"));
}
