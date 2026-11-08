//! A flush the coordination plane refuses is tried again by itself: the invariant
//! behind a past defect, where a device that edited a file while cut off kept the edit unpublished
//! after the network returned (its plane connection never dropped, so nothing ran the
//! reconnect flush), and the peer, never told of the edit, made no conflict copy.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::{INITIAL_DELAY, MAX_DELAY};
use crate::change_policy::policy_signing::signed_writer_grant_log;
use crate::checkpoint_source::{CheckpointFuture, CheckpointPurpose, CheckpointSource};
use crate::daemon_state::DaemonState;
use crate::native_test_support::{author_delta, DEVICE, GROUP};
use crate::test_support::sync_stack_fixture::{
    authority_key, device, link_folder, FixtureCheckpointSource,
};

/// The plane as a cut-off device sees it: the first `refusals` requests get no answer, the
/// rest are answered as the fixture plane does. Counts every request.
struct UnreachableThenReachable {
    inner: FixtureCheckpointSource,
    refusals: usize,
    /// The early requests are accepted but never answered (instead of refused).
    stalls: bool,
    requests: Arc<AtomicUsize>,
}

impl CheckpointSource for UnreachableThenReachable {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        purpose: CheckpointPurpose,
    ) -> CheckpointFuture<'a> {
        if self.requests.fetch_add(1, Ordering::SeqCst) < self.refusals {
            if self.stalls {
                return Box::pin(std::future::pending());
            }
            return Box::pin(async {
                Err(crate::checkpoint_source::CheckpointRefusal::Unreachable)
            });
        }
        self.inner.request_authorization_checkpoint(
            group_id,
            device_id,
            request_id,
            merkle_root,
            leaf_count,
            purpose,
        )
    }
}

/// `(service unreachable, not authorized, rejected)` as the status reports them.
fn totals(state: &DaemonState) -> (u64, u64, u64) {
    let totals = state.telemetry.unpublished_totals();
    (totals.service_unreachable, totals.not_authorized, totals.rejected)
}

fn pending(state: &DaemonState) -> usize {
    state
        .replica_coordinator
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::native_publication::pending_native_deltas_for_device(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
                &state.device_id,
            )
        })
        .unwrap()
        .len()
}

/// Lets the virtual clock run `by`, one step at a time, so every task that became ready
/// at an intermediate instant runs before the next.
async fn run_clock(by: Duration) {
    let step = Duration::from_millis(250);
    let mut elapsed = Duration::ZERO;
    while elapsed < by {
        tokio::time::advance(step).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        elapsed += step;
    }
}

async fn offline_device(refusals: usize) -> (Arc<DaemonState>, Arc<AtomicUsize>, impl Sized) {
    cut_off_device(refusals, false).await
}

async fn cut_off_device(
    refusals: usize,
    stalls: bool,
) -> (Arc<DaemonState>, Arc<AtomicUsize>, impl Sized) {
    let (state, dir) = device(DEVICE, 9);
    let folder = tempfile::tempdir().unwrap();
    let linked = link_folder(&state, folder.path());
    let authority = authority_key();
    let service_key = authority.verifying_key().to_bytes();
    let own_key = state.device_signing_key().unwrap().verifying_key().to_bytes();
    let chain = signed_writer_grant_log(&authority, GROUP, &[(DEVICE, own_key)]);
    let head: [u8; 32] = chain.policy_head.as_slice().try_into().unwrap();
    let installed = crate::change_policy::verify_group_policy_log(&service_key, &chain).unwrap();
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        GROUP.to_string(),
        installed,
    )]));
    let requests = Arc::new(AtomicUsize::new(0));
    *state.test_seal_checkpoint_source.lock().unwrap() = Some(Arc::new(UnreachableThenReachable {
        inner: FixtureCheckpointSource::for_device(&state).at_policy_point(1, head),
        refusals,
        stalls,
        requests: requests.clone(),
    }));
    // The edit made while cut off: authored locally, its checkpoint not obtainable.
    author_delta(&state.replica_coordinator.database(), 1, "a.txt");
    (state, requests, (dir, folder, linked))
}

#[tokio::test(start_paused = true)]
async fn a_refused_flush_is_retried_with_a_growing_delay_until_the_plane_answers() {
    let (state, requests, _keep) = offline_device(3).await;

    // The one flush the edit itself caused: refused.
    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(pending(&state), 1, "the plane did not answer, so the edit is unpublished");

    // No other trigger exists from here on: no reconnect, no policy frame, no local edit.
    // Retries are due 1 s, then 2 s, then 4 s later; the third retry is the first answered.
    run_clock(INITIAL_DELAY - Duration::from_millis(250)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 1, "not before the first delay is over");
    run_clock(Duration::from_millis(500)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 2, "first retry after 1 s");
    run_clock(Duration::from_secs(2)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 3, "second retry 2 s later");
    assert_eq!(pending(&state), 1);
    run_clock(Duration::from_secs(4)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 4, "third retry 4 s later");
    assert_eq!(pending(&state), 0, "the edit is published once the plane answers");

    // Published: nothing is armed any more.
    run_clock(MAX_DELAY * 2).await;
    assert_eq!(requests.load(Ordering::SeqCst), 4, "an answered flush ends the retries");
}

#[tokio::test(start_paused = true)]
async fn the_delay_stops_growing_at_the_maximum() {
    let (state, requests, _keep) = offline_device(usize::MAX).await;
    assert_eq!(MAX_DELAY, Duration::from_secs(15));

    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    // Retries at 1, 3, 7 and 15 s (delays 1, 2, 4, 8); every later one is MAX_DELAY apart.
    run_clock(Duration::from_secs(16)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 5, "the first flush and four retries");
    run_clock(Duration::from_secs(45)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 8, "then one every MAX_DELAY (30, 45, 60 s)");
    assert_eq!(pending(&state), 1);
}

/// A plane that accepts the connection but never answers must read as a refusal: the flush
/// gives up at its deadline, which arms the retry, so the edit is published once the plane
/// answers (the flush's own await would otherwise never return and never arm anything).
#[tokio::test(start_paused = true)]
async fn a_request_the_plane_never_answers_times_out_and_is_retried() {
    let (state, requests, _keep) = cut_off_device(1, true).await;

    let flushing = {
        let state = state.clone();
        tokio::spawn(async move {
            state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await
        })
    };
    run_clock(Duration::from_secs(1)).await;
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(pending(&state), 1);

    run_clock(crate::native_checkpoint_flush::CHECKPOINT_REQUEST_TIMEOUT + INITIAL_DELAY * 2).await;
    assert!(flushing.is_finished(), "the stalled request is abandoned at its deadline");
    assert_eq!(requests.load(Ordering::SeqCst), 2, "and retried");
    assert_eq!(pending(&state), 0, "published once the plane answers");
}

/// The retry delay is spread by up to a quarter, never shortened, so devices that lost the service
/// together do not retry in step after a long outage.
#[test]
fn the_retry_delay_is_spread_by_up_to_a_quarter_and_never_shortened() {
    use super::spread;
    for base in [INITIAL_DELAY, Duration::from_secs(4), MAX_DELAY] {
        assert_eq!(spread(base, 0.0), base);
        assert_eq!(spread(base, 1.0), base.mul_f64(1.25));
        let middle = spread(base, 0.5);
        assert!(middle > base && middle < base.mul_f64(1.25), "{middle:?}");
        // Out-of-range input is clamped, not extrapolated.
        assert_eq!(spread(base, -3.0), base);
        assert_eq!(spread(base, 9.0), base.mul_f64(1.25));
    }
}

/// The status counts what is waiting, and why: a plane that does not answer is "service
/// unreachable"; a plane that answers that the device may not publish is "not authorized"; both
/// clear once the edit is published.
#[tokio::test(start_paused = true)]
async fn the_status_counts_saved_edits_by_why_they_are_not_published() {
    let (state, _requests, _keep) = offline_device(usize::MAX).await;
    assert_eq!(totals(&state), (0, 0, 0), "nothing attempted yet");

    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(totals(&state), (1, 0, 0), "the service did not answer");

    // The same edit, now refused by the service: not authorized, and no longer "unreachable".
    let (state, _requests, _keep) = {
        let (state, requests, keep) = offline_device(0).await;
        *state.test_seal_checkpoint_source.lock().unwrap() = Some(Arc::new(NotAuthorizedSource));
        (state, requests, keep)
    };
    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(totals(&state), (0, 1, 0), "the device may not publish");
    assert_eq!(pending(&state), 1);
}

#[tokio::test(start_paused = true)]
async fn the_status_clears_when_the_edit_is_published_after_recovery() {
    let (state, _requests, _keep) = offline_device(1).await;
    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(totals(&state), (1, 0, 0));

    run_clock(INITIAL_DELAY * 2).await;
    assert_eq!(pending(&state), 0, "published by the retry");
    assert_eq!(totals(&state), (0, 0, 0), "nothing is waiting any more");
}

/// A plane that answers every request with "this device may not publish".
struct NotAuthorizedSource;

impl CheckpointSource for NotAuthorizedSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        _group_id: &'a str,
        _device_id: &'a str,
        _request_id: &'a str,
        _merkle_root: [u8; 32],
        _leaf_count: u64,
        _purpose: CheckpointPurpose,
    ) -> CheckpointFuture<'a> {
        Box::pin(async { Err(crate::checkpoint_source::CheckpointRefusal::NotAuthorized) })
    }
}

/// An engine that has been running long enough for a missing policy to mean something.
const LONG_RUNNING: Duration = Duration::from_secs(120);

/// A device whose database is a file, so it can be "restarted": the state is dropped and a new one is
/// built over the same file, with the same signing identity and (when `policy`) the same verified
/// group policy a restart restores from the persisted snapshot.
fn file_backed_device(db: &std::path::Path, policy: bool) -> Arc<DaemonState> {
    let store_dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
    // The previous generation's pool may still be closing its file.
    let mut attempts = 0;
    let coordinator = loop {
        match crate::replica_coordinator::ReplicaCoordinator::open(db) {
            Ok(coordinator) => break Arc::new(coordinator),
            Err(error) if attempts < 50 => {
                attempts += 1;
                let _ = error;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("could not reopen the database: {error}"),
        }
    };
    let state = DaemonState::new(DEVICE.into(), coordinator, store);
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[9; 32]));
    // Keep the block store's directory for the life of the process, as the other fixtures do for
    // theirs through `ReleasingDir`.
    std::mem::forget(store_dir);
    if policy {
        let authority = authority_key();
        let service_key = authority.verifying_key().to_bytes();
        let own_key = state.device_signing_key().unwrap().verifying_key().to_bytes();
        let chain = signed_writer_grant_log(&authority, GROUP, &[(DEVICE, own_key)]);
        let head: [u8; 32] = chain.policy_head.as_slice().try_into().unwrap();
        let installed =
            crate::change_policy::verify_group_policy_log(&service_key, &chain).unwrap();
        state.authority.replace_group_policy_states(std::collections::HashMap::from([(
            GROUP.to_string(),
            installed,
        )]));
        *state.test_seal_checkpoint_source.lock().unwrap() =
            Some(Arc::new(FixtureCheckpointSource::for_device(&state).at_policy_point(1, head)));
    }
    state
}

/// An edit made while the service is down is saved as a pending delta in the database: a restart,
/// and another, do not lose it, and it is published once the service answers.
#[tokio::test(start_paused = true)]
async fn an_edit_made_while_the_plane_is_down_survives_restarts_and_publishes_after_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("index.sqlite3");

    // The first run: the plane does not answer; the edit stays pending and is counted as such.
    {
        let state = file_backed_device(&db, true);
        *state.test_seal_checkpoint_source.lock().unwrap() =
            Some(Arc::new(UnreachableThenReachable {
                inner: FixtureCheckpointSource::for_device(&state),
                refusals: usize::MAX,
                stalls: false,
                requests: Arc::new(AtomicUsize::new(0)),
            }));
        author_delta(&state.replica_coordinator.database(), 1, "a.txt");
        state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
        assert_eq!(pending(&state), 1);
        assert_eq!(totals(&state), (1, 0, 0));
        state.stop_background_tasks_for_tests();
        state.release_reference_cycles_for_tests();
    }
    // Two restarts, the plane still down: the edit is still there (and nothing re-authors it).
    for _ in 0..2 {
        let state = file_backed_device(&db, true);
        assert_eq!(pending(&state), 1, "the saved edit survives a restart");
        state.stop_background_tasks_for_tests();
        state.release_reference_cycles_for_tests();
    }
    // The plane is back: the next flush publishes it.
    let state = file_backed_device(&db, true);
    assert_eq!(pending(&state), 1);
    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(pending(&state), 0, "published once the plane answers");
    assert_eq!(totals(&state), (0, 0, 0));
    state.stop_background_tasks_for_tests();
    state.release_reference_cycles_for_tests();
}

/// A disk edit made while the daemon was down and restarted with no group policy is only a
/// journaled dirty path (it is captured once the policy arrives). The journal keeps it across
/// restarts, and the status counts it among the changes that are only on this device.
#[tokio::test(start_paused = true)]
async fn a_journaled_disk_edit_without_the_group_policy_is_kept_and_counted() {
    use crate::queries::runtime_status::dirty_edits_without_policy;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("index.sqlite3");
    let folder = tempfile::tempdir().unwrap();

    {
        let state = file_backed_device(&db, false);
        let _canonical = link_folder(&state, folder.path());
        state
            .replica_coordinator
            .dirty_path_repository()
            .record_dirty_path(
                GROUP,
                "a.txt",
                "created_or_modified",
                1,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert_eq!(
            dirty_edits_without_policy(&state.replica_coordinator, LONG_RUNNING),
            1,
            "counted"
        );
        state.stop_background_tasks_for_tests();
        state.release_reference_cycles_for_tests();
    }
    // Restarts without the policy: the journaled edit is still there, and still counted.
    for _ in 0..2 {
        let state = file_backed_device(&db, false);
        assert_eq!(
            state.replica_coordinator.dirty_path_repository().count_dirty_paths(GROUP, 10).unwrap(),
            1,
            "the journal keeps the edit across a restart"
        );
        assert_eq!(dirty_edits_without_policy(&state.replica_coordinator, LONG_RUNNING), 1);
        state.stop_background_tasks_for_tests();
        state.release_reference_cycles_for_tests();
    }
    // With the policy restored, the journal is the ordinary moment before a capture: not counted
    // as waiting (the row stays until the capture clears it).
    let state = file_backed_device(&db, true);
    assert_eq!(
        state.replica_coordinator.dirty_path_repository().count_dirty_paths(GROUP, 10).unwrap(),
        1
    );
    assert_eq!(dirty_edits_without_policy(&state.replica_coordinator, LONG_RUNNING), 0);
    // A healthy start is not an outage: nothing is counted in the first minute, whatever the journal holds.
    assert_eq!(dirty_edits_without_policy(&state.replica_coordinator, Duration::from_secs(5)), 0);
    state.stop_background_tasks_for_tests();
    state.release_reference_cycles_for_tests();
}

/// A restart with edits still waiting tries them by itself: nothing else is guaranteed to (the plane
/// connection that would is the thing that was down).
#[tokio::test(start_paused = true)]
async fn a_restart_with_saved_edits_publishes_them_without_waiting_for_another_trigger() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("index.sqlite3");
    let folder = tempfile::tempdir().unwrap();
    {
        let state = file_backed_device(&db, true);
        let _canonical = link_folder(&state, folder.path());
        author_delta(&state.replica_coordinator.database(), 1, "a.txt");
        assert_eq!(pending(&state), 1);
        state.stop_background_tasks_for_tests();
        state.release_reference_cycles_for_tests();
    }
    let state = file_backed_device(&db, true);
    assert_eq!(pending(&state), 1, "saved before the restart");
    tokio::spawn(super::run(state.clone()));
    run_clock(INITIAL_DELAY * 3).await;
    assert_eq!(pending(&state), 0, "published by the start-up pass, with no edit and no reconnect");
    state.stop_background_tasks_for_tests();
    state.release_reference_cycles_for_tests();
}

/// A backlog longer than one batch is published over several flushes without another trigger, and the
/// status counts what is left.
#[tokio::test(start_paused = true)]
async fn a_backlog_longer_than_one_batch_is_published_to_the_end() {
    crate::native_checkpoint_flush::TEST_BATCH_CAP.with(|cap| cap.set(Some(1)));
    let (state, _requests, _keep) = offline_device(0).await;
    author_delta(&state.replica_coordinator.database(), 2, "b.txt");
    author_delta(&state.replica_coordinator.database(), 3, "c.txt");
    assert_eq!(pending(&state), 3);

    // The one flush the edits caused publishes one batch of one and asks for another pass.
    state.flush_pending_native_checkpoint_for_group_for_test(GROUP).await;
    assert_eq!(pending(&state), 2, "one batch was published");

    // The retry (armed because a remainder is left) publishes the rest, one batch at a time.
    run_clock(INITIAL_DELAY * 4).await;
    assert_eq!(pending(&state), 0, "the whole backlog was published");
    assert_eq!(totals(&state), (0, 0, 0));
    crate::native_checkpoint_flush::TEST_BATCH_CAP.with(|cap| cap.set(None));
}
