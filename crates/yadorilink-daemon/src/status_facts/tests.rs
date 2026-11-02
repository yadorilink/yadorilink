//! The builder, with a source that can be stalled or counted: the request path answers from the
//! latest facts whatever the builder is doing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use yadorilink_ipc_proto::daemonctl::{FetchAvailability, StatusResponse};
use yadorilink_local_storage::SegmentBlockStore;

use super::*;
use crate::control_context::ControlContext;
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-a";

/// The production source, plus a count of builds and a stall: the next build announces itself on
/// `started` and waits on `release`, the way a read blocked in the kernel would.
struct Probe {
    real: ProductionSource,
    builds: AtomicUsize,
    stall: Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>,
}

impl FactsSource for Probe {
    fn collect(&self) -> Result<CollectedStatus, String> {
        self.builds.fetch_add(1, Ordering::SeqCst);
        if let Some((started, release)) = self.stall.lock().unwrap().take() {
            started.send(()).unwrap();
            release.recv().unwrap();
        }
        self.real.collect()
    }

    fn data_changes(&self) -> watch::Receiver<u64> {
        self.real.data_changes()
    }
}

struct Fixture {
    hub: Arc<StatusHub>,
    probe: Arc<Probe>,
    state: Arc<DaemonState>,
    _dirs: (tempfile::TempDir, tempfile::TempDir, tempfile::TempDir),
}

fn fixture() -> Fixture {
    let index_dir = tempfile::tempdir().unwrap();
    let store_dir = tempfile::tempdir().unwrap();
    let link_dir = tempfile::tempdir().unwrap();
    let replica = Arc::new(ReplicaCoordinator::open(index_dir.path().join("index.db")).unwrap());
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = DaemonState::new("device-a".into(), replica, store);
    state
        .replica_coordinator
        .link_repository()
        .add_link(&link_dir.path().to_string_lossy(), GROUP)
        .unwrap();
    let context = ControlContext::from_state(state.clone());
    let probe = Arc::new(Probe {
        real: ProductionSource(context.status_sources.clone()),
        builds: AtomicUsize::new(0),
        stall: Mutex::new(None),
    });
    let hub = Arc::new(StatusHub::with_source(
        context.status_sources.clone(),
        context.queries.runtime_status.telemetry(),
        probe.clone(),
    ));
    Fixture { hub, probe, state, _dirs: (index_dir, store_dir, link_dir) }
}

/// Makes the next build stall; returns what the test uses to see it start and to let it go.
fn stall_next_build(probe: &Probe) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    *probe.stall.lock().unwrap() = Some((started_tx, release_rx));
    (started_rx, release_tx)
}

fn availability(status: &StatusResponse) -> (i32, u64) {
    (status.links[0].fetch_availability, status.snapshot_age_ms)
}

/// A status requested while a build is stalled: the request waits for facts newer than itself,
/// and the test moves the clock past that wait (a blocked build keeps the paused clock from
/// advancing on its own).
async fn status_during_stall(hub: &Arc<StatusHub>) -> StatusResponse {
    let asked = tokio::spawn({
        let hub = hub.clone();
        async move { hub.status().await.unwrap() }
    });
    tokio::task::yield_now().await;
    tokio::time::advance(FRESHNESS_WAIT + Duration::from_millis(10)).await;
    asked.await.unwrap()
}

/// Waits until the build with sequence number `seq` has been published.
async fn published(hub: &StatusHub, seq: u64) {
    hub.subscribe_facts()
        .wait_for(|facts| facts.as_ref().is_some_and(|f| f.started_seq >= seq))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_stalled_build_leaves_status_answering_with_its_age_and_withholds_old_claims() {
    let fx = fixture();
    let (available, _) = availability(&fx.hub.status().await.unwrap());
    assert_eq!(available, FetchAvailability::AvailableNow as i32);
    // From here the clock is moved by hand: a build blocked on a thread keeps a paused clock from
    // advancing on its own.
    tokio::time::pause();

    // A command finishes, and the build it asks for stalls.
    let (started, release) = stall_next_build(&fx.probe);
    let stalled_seq = fx.hub.started_builds() + 1;
    fx.hub.command_completed();
    let status = status_during_stall(&fx.hub).await;
    started.recv().unwrap();
    let (available, age_ms) = availability(&status);
    assert_eq!(available, FetchAvailability::AvailableNow as i32, "recent facts keep their claim");
    assert!(age_ms >= FRESHNESS_WAIT.as_millis() as u64, "the age is the real one: {age_ms}");

    // Still stalled, the facts pass the age a positive claim may stand on.
    tokio::time::advance(POSITIVE_CLAIM_MAX_AGE).await;
    let (available, age_ms) = availability(&status_during_stall(&fx.hub).await);
    assert_eq!(available, FetchAvailability::Unknown as i32, "an old fact claims nothing");
    assert!(age_ms >= POSITIVE_CLAIM_MAX_AGE.as_millis() as u64);

    // The disk answers; the next status carries new facts.
    release.send(()).unwrap();
    published(&fx.hub, stalled_seq).await;
    let (available, age_ms) = availability(&fx.hub.status().await.unwrap());
    assert_eq!(available, FetchAvailability::AvailableNow as i32);
    assert!(age_ms < POSITIVE_CLAIM_MAX_AGE.as_millis() as u64, "fresh again: {age_ms}");
}

#[tokio::test]
async fn a_status_after_a_command_shows_it() {
    let fx = fixture();
    assert_eq!(fx.hub.status().await.unwrap().links.len(), 1);

    let other = tempfile::tempdir().unwrap();
    fx.state
        .replica_coordinator
        .link_repository()
        .add_link(&other.path().to_string_lossy(), "group-b")
        .unwrap();
    fx.hub.command_completed();

    assert_eq!(fx.hub.status().await.unwrap().links.len(), 2);
    assert_eq!(fx.hub.list_links().await.unwrap().len(), 2, "ListLinks reads the same facts");
}

#[tokio::test]
async fn a_burst_of_writes_costs_one_more_build() {
    let fx = fixture();
    fx.hub.status().await.unwrap();
    assert_eq!(fx.probe.builds.load(Ordering::SeqCst), 1);
    tokio::time::pause();

    // Hold the next build at its start, write while it waits, then let it go.
    let (started, release) = stall_next_build(&fx.probe);
    let held_seq = fx.hub.started_builds() + 1;
    fx.hub.command_completed();
    status_during_stall(&fx.hub).await; // kicks the build; answers from the old facts
    started.recv().unwrap();
    for n in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        fx.state
            .replica_coordinator
            .link_repository()
            .add_link(&dir.path().to_string_lossy(), &format!("burst-{n}"))
            .unwrap();
        std::mem::forget(dir);
    }
    release.send(()).unwrap();
    published(&fx.hub, held_seq).await;

    // The writes landed after the held build marked its position, so exactly one build covers
    // them all, however long the clock then runs.
    tokio::time::advance(Duration::from_secs(2)).await;
    published(&fx.hub, held_seq + 1).await;
    // One more build covers all five writes, so the next one a request asks for is the fourth;
    // a spurious build in between would make it the fifth.
    fx.hub.command_completed();
    fx.hub.status().await.unwrap();
    assert_eq!(fx.probe.builds.load(Ordering::SeqCst), 4);
}
