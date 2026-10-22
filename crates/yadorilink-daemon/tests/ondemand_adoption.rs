//! What an on-demand folder does when a peer publishes a file.
//!
//! On-demand is a promise about *bytes*: the folder tracks every path and
//! version its peers publish, and fetches content only when something asks
//! for it. Two ways to break that promise, neither of which any surviving
//! test states after the Change protocol's own were retired:
//!
//! ```text
//!   adoption   a new file must be adopted as a placeholder, with no blocks
//!              pulled — otherwise on-demand is eager with extra steps
//!
//!   re-offer   hearing about a version already held must not start a fetch —
//!              otherwise every reconnect hydrates the whole folder
//!
//!   newer      a newer version of a file that was opened is tracked, not
//!              downloaded — opening asks for one version, not for every
//!              later one
//! ```
//!
//! All three are asserted on the index and the block store rather than on the
//! file: an on-demand placeholder legitimately exists on disk, so the file's
//! presence says nothing about whether its content was fetched.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

const GROUP: &str = "ondemand-adoption-group";
const PATH: &str = "payload.bin";

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    store: Arc<SegmentBlockStore>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl TestDevice {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }

    /// The row this device has genuinely indexed for `path`.
    ///
    /// Adopting a peer's path first writes an empty bootstrap scaffold that the
    /// real row later replaces. A bare `get_file` returns that scaffold, so a
    /// caller waiting for "the file was adopted" could read a row naming no
    /// content at all; only a real current row counts.
    fn record(&self, path: &str) -> Option<yadorilink_replica_domain::file::FileRecord> {
        let index = self.state.replica_coordinator.file_index_repository();
        if !index.has_real_current_row(GROUP, path).ok()? {
            return None;
        }
        index.get_file(GROUP, path).ok().flatten()
    }

    fn materialization_state(&self, path: &str) -> Option<MaterializationState> {
        self.state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, path)
            .ok()
            .flatten()
    }

    /// How many of `record`'s blocks this device actually holds bytes for.
    ///
    /// The observable that separates "adopted" from "fetched": an index row
    /// costs nothing, block bytes are the transfer.
    fn blocks_held(&self, record: &yadorilink_replica_domain::file::FileRecord) -> usize {
        record
            .blocks
            .iter()
            .filter(|block| self.store.get(&hex::encode(&block.hash)).is_ok())
            .count()
    }
}

fn setup_device(name: &str) -> TestDevice {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new(name.to_string(), Arc::new(sync_state), store.clone());
    support::ensure_device_signing_key(&state);
    // The on-demand capability of this device's (plain) roots, for the legacy lane these tests exercise.
    state.set_test_on_demand_allowed(true);
    TestDevice {
        device_id: name.to_string(),
        state,
        store,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

/// Registers the link with `policy` and starts watching.
///
/// The policy is set between `add_link` and `start` on purpose: an on-demand
/// folder that spends its first moments eager would fetch exactly the content
/// these tests say it must not.
fn start_watching(device: &TestDevice, policy: MaterializationPolicy) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.set_test_on_demand_allowed(true);
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    device
        .state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(&local_path, policy)
        .unwrap();
    LinkRuntimeController::new(device.state.clone()).start(local_path, GROUP.to_string()).unwrap();
}

async fn pair(a: &TestDevice, b: &TestDevice) {
    support::connect_two_daemons(
        &a.state,
        &a.device_id,
        &b.state,
        &b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;
}

/// The adoption waits must not take the bootstrap scaffold for the adopted row.
#[tokio::test]
async fn the_bootstrap_scaffold_is_not_an_adopted_record() {
    let device = setup_device("scaffold");
    device
        .state
        .replica_coordinator
        .file_index_repository()
        .ensure_bootstrap_row_for_metadata(GROUP, PATH)
        .unwrap();

    assert!(device.record(PATH).is_none(), "a scaffold row names no content and is not adopted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ondemand_folder_adopts_a_peers_file_without_fetching_its_blocks() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x31u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &content).unwrap();

    wait_until_with_context(
        || device_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "the on-demand folder never adopted the peer's file".into(),
    )
    .await;

    let record = device_b.record(PATH).expect("just waited for it");
    assert!(!record.blocks.is_empty(), "the adopted record must name the content it stands for");
    assert_eq!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Remote),
        "an on-demand adoption must land as a placeholder"
    );
    assert_eq!(
        device_b.blocks_held(&record),
        0,
        "an on-demand adoption fetched block bytes it was not asked for"
    );
}

/// Being told again about a version already held does not start a fetch.
///
/// A peer re-offers its heads on every reconnect and after every unrelated
/// local commit. If an offer for a version the placeholder already names were
/// treated as a reason to hydrate, an on-demand folder would fill up by
/// reconnecting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn re_offering_a_version_already_held_does_not_hydrate_a_placeholder() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let content = vec![0x32u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &content).unwrap();
    wait_until_with_context(
        || device_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "the on-demand folder never adopted the peer's file".into(),
    )
    .await;
    let adopted = device_b.record(PATH).expect("just waited for it");

    // An unrelated commit on the peer, so a fresh round of reconciliation
    // runs and `PATH`'s unchanged version is offered again alongside it.
    std::fs::write(device_a.path("unrelated.txt"), b"noise").unwrap();
    wait_until_with_context(
        || device_b.record("unrelated.txt").is_some(),
        Duration::from_secs(30),
        || "the unrelated commit never reached the on-demand folder".into(),
    )
    .await;

    let after = device_b.record(PATH).expect("the placeholder must still be indexed");
    assert_eq!(
        after.blocks, adopted.blocks,
        "re-offering an unchanged version must not change what the placeholder names"
    );
    assert_eq!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Remote),
        "re-offering an unchanged version must leave the placeholder a placeholder"
    );
    assert_eq!(
        device_b.blocks_held(&after),
        0,
        "re-offering a version already held started a fetch"
    );
}

/// A file that was opened on an on-demand device stays `Present` over its old
/// bytes when its peer publishes a newer version: the newer version is
/// tracked, not downloaded, and nothing is written at the path. `Present`
/// says only that an object exists -- the proof, not the state, tells that
/// the bytes there are no longer the row's version. Opening is a request for
/// the version that existed when it was made; it does not turn the path into
/// one this device keeps up to date.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_present_file_stays_present_over_its_old_bytes_when_its_peer_publishes_a_newer_version() {
    let device_a = setup_device("device-a");
    let device_b = setup_device("device-b");

    start_watching(&device_a, MaterializationPolicy::Eager);
    start_watching(&device_b, MaterializationPolicy::OnDemand);
    pair(&device_a, &device_b).await;

    let opened_content = vec![0x35u8; 256 * 1024];
    std::fs::write(device_a.path(PATH), &opened_content).unwrap();
    wait_until_with_context(
        || device_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "the on-demand folder never adopted the peer's file".into(),
    )
    .await;

    // The open: the same entry point a platform provider's fetch reaches.
    yadorilink_daemon::hydration::hydrate(&device_b.state, GROUP, PATH).await.unwrap();
    let present = device_b.record(PATH).expect("the opened path must still be indexed");
    assert_eq!(device_b.blocks_held(&present), present.blocks.len(), "opening must fetch it");
    assert_eq!(device_b.materialization_state(PATH), Some(MaterializationState::Present));

    std::fs::write(device_a.path(PATH), vec![0x36u8; 256 * 1024]).unwrap();
    wait_until_with_context(
        || device_b.record(PATH).is_some_and(|record| record.blocks != present.blocks),
        Duration::from_secs(30),
        || "the newer version was never tracked by the on-demand device".into(),
    )
    .await;

    let newer = device_b.record(PATH).expect("just waited for it");
    assert_eq!(device_b.blocks_held(&newer), 0, "the newer version was downloaded unasked");
    assert_eq!(
        device_b.materialization_state(PATH),
        Some(MaterializationState::Present),
        "an object still stands at the path, so the row stays Present"
    );
    assert_eq!(
        std::fs::read(device_b.path(PATH)).unwrap(),
        opened_content,
        "nothing may be written over the opened bytes"
    );
    assert!(
        !device_b
            .state
            .replica_coordinator
            .sqlite()
            .dag_usable_proof_names_current_version(GROUP, PATH)
            .unwrap(),
        "Present over old bytes is not evidence that the bytes equal the current version"
    );
}

/// A path that forks while an on-demand device holds none of its content
/// settles on that device without fetching anything: the source and the
/// conflict copy its resolution derives are both tracked as Remote, with no
/// block of either held.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forked_path_settles_on_an_on_demand_device_without_fetching() {
    let writer_a = setup_device("device-a");
    let writer_b = setup_device("device-b");
    let reader = setup_device("device-r");

    let groups = [GROUP.to_string()];
    for device in [&writer_a, &writer_b, &reader] {
        support::install_bootstrap_policy(&device.state, &groups);
    }

    std::fs::write(writer_a.path(PATH), vec![0x43u8; 256 * 1024]).unwrap();
    std::fs::write(writer_b.path(PATH), vec![0x44u8; 256 * 1024]).unwrap();
    start_watching(&writer_a, MaterializationPolicy::Eager);
    start_watching(&writer_b, MaterializationPolicy::Eager);
    start_watching(&reader, MaterializationPolicy::OnDemand);
    wait_until_with_context(
        || writer_a.record(PATH).is_some() && writer_b.record(PATH).is_some(),
        Duration::from_secs(30),
        || "both writers must author their own version before meeting".into(),
    )
    .await;

    pair(&reader, &writer_a).await;
    pair(&reader, &writer_b).await;

    // An on-demand device holds no object for either side of the fork, so the
    // copy is found in the index, not on disk.
    let copy_name = || {
        reader
            .state
            .replica_coordinator
            .file_index_repository()
            .list_files(GROUP)
            .unwrap()
            .into_iter()
            .map(|row| row.path)
            .find(|name| name.contains("conflicted copy") && reader.record(name).is_some())
    };
    wait_until_with_context(
        || {
            copy_name().is_some()
                && reader.materialization_state(PATH) == Some(MaterializationState::Remote)
        },
        Duration::from_secs(60),
        || {
            format!(
                "the forked path never settled as Remote on the on-demand device: source \
                 state={:?}, entries={:?}",
                reader.materialization_state(PATH),
                copy_name()
            )
        },
    )
    .await;

    let copy = copy_name().expect("just waited for it");
    for path in [PATH, copy.as_str()] {
        let record = reader.record(path).expect("indexed");
        assert_eq!(reader.blocks_held(&record), 0, "{path}: fetched content nobody asked for");
        assert_eq!(reader.materialization_state(path), Some(MaterializationState::Remote));
    }
}
