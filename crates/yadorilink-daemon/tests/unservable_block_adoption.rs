//! Adopting a record whose content no peer can supply.
//!
//! A peer can legitimately advertise a path it cannot currently serve — mid
//! directory-rename churn, or a losing conflict copy whose blocks have not
//! been written yet. The adopting device must record a retriable
//! `Remote`, never a `Present` row with no file behind it:
//!
//! ```text
//!   Placeholder   retried later, and correct in the meantime
//!   Hydrated      the index claims content that is not there — and the
//!                 repair sweep, seeing a hydrated row with nothing on disk,
//!                 demotes it to empty content. The write is then gone, and
//!                 for a losing conflict copy that write is the only copy.
//! ```
//!
//! Also: nothing may be left behind under the sync root. A failed
//! materialization that abandons its temp file turns every retry into litter.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::wait_until_with_context;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{
    BlockStore, ContentHash, GcReport, SegmentBlockStore, StorageError,
};
use yadorilink_replica_domain::session_state::MaterializationState;

const GROUP: &str = "unservable-block-group";
const PATH: &str = "loser.bin";

/// A store that keeps everything it is given and hands none of it back.
///
/// Models a peer that advertises a record it cannot currently serve. Refusing
/// at `get` rather than never storing the block keeps the authoring side
/// working normally — the file really was written and chunked — so what the
/// adopting device sees is exactly a `not_found` answer to a real request.
struct UnservableBlockStore {
    inner: Arc<SegmentBlockStore>,
    refuse: std::sync::atomic::AtomicBool,
}

impl UnservableBlockStore {
    fn new(inner: Arc<SegmentBlockStore>) -> Self {
        Self { inner, refuse: std::sync::atomic::AtomicBool::new(false) }
    }

    fn start_refusing(&self) {
        self.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn refusing(&self) -> bool {
        self.refuse.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl BlockStore for UnservableBlockStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        if self.refusing() {
            return Err(StorageError::NotFound(hash.to_string()));
        }
        self.inner.get(hash)
    }

    fn get_unchecked(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        if self.refusing() {
            return Err(StorageError::NotFound(hash.to_string()));
        }
        self.inner.get_unchecked(hash)
    }

    fn delete(&self, hash: &str) -> Result<(), StorageError> {
        self.inner.delete(hash)
    }

    fn exists(&self, hash: &str) -> Result<bool, StorageError> {
        // Honest: the block really is on this device, it just cannot be
        // handed out. Reporting it absent would make the authoring device
        // look like it had lost its own content, which is a different
        // scenario with different correct behaviour.
        self.inner.exists(hash)
    }

    fn list_by_prefix(&self, prefix: &str) -> Result<Vec<ContentHash>, StorageError> {
        self.inner.list_by_prefix(prefix)
    }

    fn sweep(
        &self,
        live: &std::collections::HashSet<ContentHash>,
        grace_cutoff: std::time::SystemTime,
        dry_run: bool,
    ) -> Result<GcReport, StorageError> {
        self.inner.sweep(live, grace_cutoff, dry_run)
    }
}

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
}

impl TestDevice {
    fn path(&self, relative: &str) -> std::path::PathBuf {
        self.root.path().join(relative)
    }
}

fn setup_device(name: &str, store: Arc<dyn BlockStore>) -> TestDevice {
    let (sync_state, index_dir) = support::open_file_backed_replica_coordinator();
    let state = DaemonState::new(name.to_string(), Arc::new(sync_state), store);
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id: name.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        _index_dir: index_dir,
    }
}

fn start_watching(device: &TestDevice) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    LinkRuntimeController::new(device.state.clone()).start(local_path, GROUP.to_string()).unwrap();
}

fn temp_files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains(".yadorilink-tmp."))
            {
                found.push(path);
            }
        }
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_whose_blocks_no_peer_can_supply_stays_a_retriable_placeholder() {
    let author_store_dir = tempfile::tempdir().unwrap();
    let author_store = Arc::new(UnservableBlockStore::new(Arc::new(
        SegmentBlockStore::new(author_store_dir.path()).unwrap(),
    )));
    let device_a = setup_device("device-a", author_store.clone());

    let adopter_store_dir = tempfile::tempdir().unwrap();
    let device_b = setup_device(
        "device-b",
        Arc::new(SegmentBlockStore::new(adopter_store_dir.path()).unwrap()),
    );

    start_watching(&device_a);
    start_watching(&device_b);
    support::connect_two_daemons(
        &device_a.state,
        &device_a.device_id,
        &device_b.state,
        &device_b.device_id,
        std::slice::from_ref(&GROUP.to_string()),
    )
    .await;

    // The authoring device writes and chunks the file normally — reading its
    // own disk, not its block store — but cannot hand the bytes out. That is
    // the shape of a peer advertising a record whose content it cannot
    // currently serve.
    author_store.start_refusing();
    let content = b"the losing conflict copy content that must not be silently lost";
    std::fs::write(device_a.path(PATH), content).unwrap();

    wait_until_with_context(
        || {
            device_b
                .state
                .replica_coordinator
                .materialization_state_repository()
                .get_materialization_state(GROUP, PATH)
                .unwrap()
                == Some(MaterializationState::Remote)
        },
        Duration::from_secs(60),
        || {
            format!(
                "the adopting device never recorded a retriable placeholder: state={:?} indexed={:?} dag={:?}",
                device_b
                    .state
                    .replica_coordinator
                    .materialization_state_repository()
                    .get_materialization_state(GROUP, PATH)
                    .unwrap(),
                device_b
                    .state
                    .replica_coordinator
                    .file_index_repository()
                    .get_file(GROUP, PATH)
                    .unwrap()
                    .is_some(),
                device_b.state.replica_coordinator.sqlite().native_group_heads(GROUP).unwrap().len()
            )
        },
    )
    .await;

    // The content genuinely never arrived — otherwise "placeholder" would be
    // a description of a successful transfer.
    assert!(
        std::fs::read(device_b.path(PATH)).map(|bytes| bytes != content).unwrap_or(true),
        "the fixture must actually have withheld the content"
    );
    assert_eq!(
        temp_files_under(device_b.root.path()),
        Vec::<std::path::PathBuf>::new(),
        "a failed materialization must not leave its temp file under the sync root"
    );
}
