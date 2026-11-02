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
            return Box::pin(async { None });
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
