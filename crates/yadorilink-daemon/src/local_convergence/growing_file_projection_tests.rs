#![cfg(test)]
//! A file this device is still writing must never be overwritten with
//! this device's own older version of it.
//!
//! The shape these pin down came from a real device: a `git clone` into
//! the sync folder. Git creates its pack file empty and streams into it.
//! The empty file is captured, becomes this device's own head, and is
//! projected back onto disk -- over the pack git is still writing. Every
//! barrier between the two let it through:
//!
//! * the pre-materialize flush tried to capture the growing file, the
//!   capture failed on it, and the flush reported the path as settled;
//! * the last-line disk check before the write skipped a row with no
//!   blocks, and skipped a row whose capture raced its own disk
//!   observation (left `Remote`, with nothing proving what is on
//!   disk).
//!
//! The overwrite is silent and permanent: no conflict copy, and a later
//! rescan sees disk matching the (stale) indexed version.

use super::*;
use crate::link_runtime::dependencies::{LinkRuntimeDependencies, LinkRuntimeHostPort};
use crate::link_runtime::operations::capture_local_change::LinkFlushHandle;
use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use std::collections::BTreeSet;
use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::{
    PeerSyncSession, PendingLocalChangeFlush, PendingLocalFlushOutcome,
};
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};

pub(super) const GROUP: &str = "growing-file-group";
pub(super) const LOCAL_DEVICE: &str = "device-local";

struct NoopHost;

impl LinkRuntimeHostPort for NoopHost {
    fn note_capture_settled(&self, _group_id: &str) {}

    fn on_local_native_commit<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }

    fn device_signing_key(&self) -> Option<SigningKey> {
        None
    }
}

/// The production flush guard: this link's own `LinkFlushHandle`, whose
/// accumulator never has anything queued, so every guard call falls back
/// to capturing the path straight from disk -- the route a file takes
/// when its watcher events have already drained or never arrived.
///
/// `after_guard`, when set, runs once, right after the next exact-path
/// guard call returns: a write that lands after the guard looked and
/// before the projection that asked it reaches the disk.
struct LinkFlush {
    /// The handle the guard asks; `Harness::set_accumulator` swaps it.
    handle: Arc<std::sync::Mutex<Arc<LinkFlushHandle>>>,
    after_guard: AfterGuardHook,
}

pub(super) type AfterGuardHook = Arc<std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

impl PendingLocalChangeFlush for LinkFlush {
    fn flush_pending_local_change<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        Box::pin(async move {
            let handle = self.handle.lock().unwrap().clone();
            let outcome = handle.flush_pending_local_change(group_id, rel_path).await;
            let hook = self.after_guard.lock().unwrap().take();
            if let Some(hook) = hook {
                hook();
            }
            outcome
        })
    }

    fn flush_case_fold_sibling<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        let handle = self.handle.lock().unwrap().clone();
        Box::pin(async move { handle.flush_case_fold_sibling(group_id, rel_path).await })
    }

    fn capture_local_path_state<'a>(
        &'a self,
        group_id: &'a str,
        rel_path: &'a str,
    ) -> Pin<Box<dyn Future<Output = PendingLocalFlushOutcome> + Send + 'a>> {
        let handle = self.handle.lock().unwrap().clone();
        Box::pin(async move { handle.capture_local_path_state(group_id, rel_path).await })
    }
}

/// An accumulator with nothing pending for any exact path: answers every
/// targeted flush with "nothing queued for that path". A case-fold sibling
/// request is answered with whatever `pending_sibling` holds, as if a
/// watcher event for it were still queued.
fn spawn_accumulator(
    mut flush_request_rx: tokio::sync::mpsc::Receiver<
        yadorilink_filesystem_sync::debounce::FlushPathRequest,
    >,
    pending_sibling: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
) {
    tokio::spawn(async move {
        while let Some(request) = flush_request_rx.recv().await {
            let found = match request.mode {
                yadorilink_filesystem_sync::debounce::FlushMode::ExactPath => None,
                yadorilink_filesystem_sync::debounce::FlushMode::CaseFoldSibling => pending_sibling
                    .lock()
                    .unwrap()
                    .take()
                    .map(|path| (path, FsChangeKind::CreatedOrModified, 1)),
            };
            let _ = request.reply.send(found);
        }
    });
}

pub(super) struct Harness {
    pub(super) session: Arc<PeerSyncSession>,
    pub(super) convergence: Arc<super::LocalConvergenceExecutor>,
    pub(super) state: Arc<ReplicaCoordinator>,
    processor: Arc<LocalChangeProcessor>,
    #[cfg(unix)]
    pub(super) store: Arc<SegmentBlockStore>,
    root: std::path::PathBuf,
    flush: Arc<LinkFlushHandle>,
    /// What `LinkFlush` (the `through_link_flush` guard) asks.
    guard_handle: Arc<std::sync::Mutex<Arc<LinkFlushHandle>>>,
    deps: Arc<LinkRuntimeDependencies>,
    root_lease: Arc<RootLease>,
    local_path: String,
    pending_sibling: Arc<std::sync::Mutex<Option<std::path::PathBuf>>>,
    /// See `LinkFlush`: only consulted when built `through_link_flush`.
    pub(super) after_guard: AfterGuardHook,
    _deps: Arc<LinkRuntimeDependencies>,
    _store_dir: tempfile::TempDir,
    _root_dir: tempfile::TempDir,
}

impl Harness {
    /// `through_link_flush`: route the executor's pre-materialize guard
    /// through a real `LinkFlushHandle` over the same processor this
    /// harness captures with. Otherwise the guard is the permissive no-op
    /// (it captures nothing), which is what "a write the flush did not
    /// capture" looks like to the materialize under test.
    /// What the fork scheduler does once contests are ingested: the losing
    /// heads move to their copy paths. The harness has one signer, so a
    /// peer's losing head is moved by it as well, standing for the peer's
    /// own fork (the delta is an ordinary writer's delta either way).
    pub(super) fn try_fork_contests(&self) -> Result<(), crate::sync_error::SyncError> {
        let key = crate::test_support::local_seam::replica_author_key(
            &self.state,
            LOCAL_DEVICE,
            SigningKey::from_bytes(&[7u8; 32]),
        )
        .unwrap();
        self.state.author_contest_forks(&key, GROUP, &|_, _| true).map(|_| ())
    }

    /// Every path native holds a head for: what a pass seeded by the armed
    /// obligations covers once forks have named their copy paths.
    pub(super) fn head_paths(&self) -> std::collections::BTreeSet<String> {
        self.state
            .database()
            .read(|conn| {
                yadorilink_sync_sqlite::native_store::load_state(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                )
            })
            .unwrap()
            .heads
            .keys()
            .map(|path| path.as_str().to_owned())
            .collect()
    }

    pub(super) fn fork_own_contests(&self) {
        self.try_fork_contests().unwrap();
    }

    pub(super) fn new(through_link_flush: bool) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let local_path = root.to_string_lossy().to_string();
        state.link_repository().add_link(&local_path, GROUP).unwrap();
        // Symlink materialization on Windows is per-link opt-in; without it
        // every received symlink here would be a policy skip that never
        // settles, so the symlink scenarios opt in to run the real write.
        #[cfg(windows)]
        state.link_repository().set_windows_symlink_opt_in(&local_path, true).unwrap();
        state
            .link_repository()
            .set_materialization_policy(&local_path, MaterializationPolicy::Eager)
            .unwrap();
        yadorilink_root_authority::root_identity::VerifiedRoot::open(&root, GROUP, state.as_ref())
            .unwrap();
        // An established link: its volume identity is already recorded.
        state
            .link_repository()
            .set_capture_volume_identity_for_group(
                GROUP,
                &yadorilink_filesystem_sync::device_boundary::root_volume_identity(&root).unwrap(),
            )
            .unwrap();
        // A live link whose startup completed: peer apply defers otherwise.
        let generation = state.startup_readiness().begin_group_startup(GROUP);
        state.startup_readiness().mark_group_ready(GROUP, generation);

        let root_lock =
            yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(&root).unwrap();
        let root_lease = Arc::new(RootLease::new(root_lock, GROUP.to_string(), 1));
        let processor = Arc::new(
            LocalChangeProcessor::new(
                state.clone(),
                Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                    store.clone(),
                )),
                LOCAL_DEVICE.to_string(),
                root_lease.clone(),
            )
            .with_change_emitter(Arc::new(
                crate::test_support::local_seam::replica_author_key(
                    &state,
                    LOCAL_DEVICE,
                    SigningKey::from_bytes(&[7u8; 32]),
                )
                .unwrap(),
            )),
        );

        let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
        let deps = Arc::new(LinkRuntimeDependencies {
            replica_coordinator: state.clone(),
            block_store: store.clone(),
            telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
            device_id: LOCAL_DEVICE.to_string(),
            host: Arc::new(NoopHost),
        });
        // An accumulator with nothing pending for any exact path: answers
        // every targeted flush with "nothing queued for that path". A
        // case-fold sibling request is answered with whatever
        // `pending_sibling` holds, as if a watcher event for it were
        // still queued.
        let pending_sibling: Arc<std::sync::Mutex<Option<std::path::PathBuf>>> = Arc::default();
        let (flush_request_tx, flush_request_rx) =
            tokio::sync::mpsc::channel::<yadorilink_filesystem_sync::debounce::FlushPathRequest>(4);
        spawn_accumulator(flush_request_rx, pending_sibling.clone());
        let (flush_all_request_tx, _flush_all_request_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(LinkFlushHandle::new(
            &deps,
            flush_request_tx,
            flush_all_request_tx,
            processor.clone(),
            root.clone(),
            local_path.clone(),
            root_lease.clone(),
        ));
        let guard_handle = Arc::new(std::sync::Mutex::new(handle.clone()));

        let (channel, _peer_end) =
            yadorilink_peer_session::ports::InMemoryPeerChannel::connected_pair();
        let transports = yadorilink_peer_session::ports::in_memory_transports(&channel);
        let mut ports = crate::test_support::peer_session_fixture::ExecutorPorts::permissive();
        let after_guard: AfterGuardHook = Arc::default();
        if through_link_flush {
            ports.pending_local_change_flush = Arc::new(LinkFlush {
                handle: guard_handle.clone(),
                after_guard: after_guard.clone(),
            });
        }
        let sync_roots = HashMap::from([(GROUP.to_string(), root.clone())]);
        let session = PeerSyncSession::over_substrate(
            LOCAL_DEVICE.to_string(),
            "device-remote".to_string(),
            state.clone() as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
            crate::replica_coordinator::engine_ports::build_peer_replica_engine(
                &state,
                store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            ),
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            vec![GROUP.to_string()],
            transports,
            yadorilink_peer_session::peer_session::PeerSyncSessionDeps::denied(),
        );
        let convergence = super::LocalConvergenceExecutor::new(
            state.clone(),
            LOCAL_DEVICE.to_string(),
            ports.root_commit_authority_provider.clone(),
            ports.pending_local_change_flush.clone(),
            sync_roots,
            store.clone() as Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
            ports.block_write_activity_provider.clone(),
            super::HeadroomPolicy::disabled(),
        );
        Self {
            session,
            convergence,
            state,
            processor,
            #[cfg(unix)]
            store,
            root,
            flush: handle,
            guard_handle,
            deps: deps.clone(),
            root_lease,
            local_path,
            pending_sibling,
            after_guard,
            _deps: deps,
            _store_dir: store_dir,
            _root_dir: root_dir,
        }
    }

    pub(super) fn path(&self, rel: &str) -> std::path::PathBuf {
        self.root.join(rel)
    }

    /// The link teardown's first step: the lease refuses every new operation.
    pub(super) fn begin_stopping(&self) {
        self.root_lease.begin_stopping();
    }

    /// Points the `through_link_flush` guard at a fresh accumulator: a live
    /// one, or (`live == false`) one whose task has already exited, so its
    /// request channel is closed while the link itself is still live.
    pub(super) fn set_accumulator(&self, live: bool) -> Arc<LinkFlushHandle> {
        let (flush_request_tx, flush_request_rx) =
            tokio::sync::mpsc::channel::<yadorilink_filesystem_sync::debounce::FlushPathRequest>(4);
        if live {
            spawn_accumulator(flush_request_rx, self.pending_sibling.clone());
        } else {
            drop(flush_request_rx);
        }
        let (flush_all_request_tx, _flush_all_request_rx) = tokio::sync::mpsc::channel(1);
        let handle = Arc::new(LinkFlushHandle::new(
            &self.deps,
            flush_request_tx,
            flush_all_request_tx,
            self.processor.clone(),
            self.root.clone(),
            self.local_path.clone(),
            self.root_lease.clone(),
        ));
        *self.guard_handle.lock().unwrap() = handle.clone();
        handle
    }

    /// A handle whose accumulator answers flush-all requests: the first with
    /// `first_drain`, every later one with nothing (the entries are gone once
    /// drained, exactly as the real accumulator behaves).
    pub(super) fn set_accumulator_draining(
        &self,
        first_drain: Vec<(std::path::PathBuf, FsChangeKind, i64)>,
    ) -> Arc<LinkFlushHandle> {
        let (flush_request_tx, flush_request_rx) =
            tokio::sync::mpsc::channel::<yadorilink_filesystem_sync::debounce::FlushPathRequest>(4);
        spawn_accumulator(flush_request_rx, self.pending_sibling.clone());
        let (flush_all_request_tx, mut flush_all_request_rx) =
            tokio::sync::mpsc::channel::<yadorilink_filesystem_sync::debounce::FlushAllRequest>(1);
        tokio::spawn(async move {
            let mut next = Some(first_drain);
            while let Some(request) = flush_all_request_rx.recv().await {
                let _ = request.reply.send(next.take().unwrap_or_default());
            }
        });
        let handle = Arc::new(LinkFlushHandle::new(
            &self.deps,
            flush_request_tx,
            flush_all_request_tx,
            self.processor.clone(),
            self.root.clone(),
            self.local_path.clone(),
            self.root_lease.clone(),
        ));
        *self.guard_handle.lock().unwrap() = handle.clone();
        handle
    }

    /// Captures `rel` the way a watcher event would.
    pub(super) async fn capture(&self, rel: &str) -> LocalChangeOutcome {
        self.processor
            .process_event(
                GROUP,
                &self.root,
                &FsChangeEvent { path: self.path(rel), kind: FsChangeKind::CreatedOrModified },
            )
            .await
            .expect("capturing a file that is not changing must succeed")
    }

    /// Delivers the watcher's removal event for `rel`, as the debounced
    /// flush does once the path lock is free.
    pub(super) async fn observe_removal(&self, rel: &str) -> LocalChangeOutcome {
        self.processor
            .process_event(
                GROUP,
                &self.root,
                &FsChangeEvent { path: self.path(rel), kind: FsChangeKind::ObservedRemoval },
            )
            .await
            .expect("observing a removal must succeed")
    }

    /// Captures `rels` the way one debounced flush of the watcher does:
    /// eligible paths are committed together as one batch.
    pub(super) async fn capture_flush(&self, rels: &[&str]) {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let paths =
            rels.iter().map(|rel| (self.path(rel), FsChangeKind::CreatedOrModified, now)).collect();
        self.processor
            .process_flush(
                GROUP,
                &self.root,
                yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(paths),
            )
            .await
            .expect("the flush must run");
    }

    /// Re-drives the dirty journal, as the daemon's backstop does: every
    /// path a scan or a failed capture left dirty is captured again.
    pub(super) async fn redrive(&self) {
        self.processor
            .redrive_dirty_journal(GROUP, &self.root)
            .await
            .expect("the redrive must run");
    }

    /// A full capture scan of the root: the pass a restart runs, which
    /// signs a delete for every indexed path it does not find on disk.
    pub(super) fn scan(&self) -> Vec<FileRecord> {
        tokio::task::block_in_place(|| {
            self.processor.scan_existing_files(GROUP, &self.root).expect("the scan must run")
        })
    }

    /// Every native delta this replica holds, as `(hash, delta)`.
    pub(super) fn all_deltas(
        &self,
    ) -> Vec<([u8; 32], yadorilink_replica_domain::signed_delta::NativeDelta)> {
        let bodies: Vec<Vec<u8>> = self
            .state
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let mut stmt = conn
                    .prepare("SELECT encoded_delta FROM native_delta_bodies WHERE group_id = ?1")?;
                let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0))?;
                Ok(rows.collect::<Result<_, _>>()?)
            })
            .unwrap();
        bodies
            .iter()
            .map(|body| {
                let delta =
                    yadorilink_replica_domain::signed_delta::NativeDelta::from_wire_bytes(body)
                        .unwrap();
                (delta.delta_hash().0, delta)
            })
            .collect()
    }

    /// The live native heads at `rel`.
    pub(super) fn native_heads(
        &self,
        rel: &str,
    ) -> Vec<yadorilink_replica_domain::native_state::LiveHead> {
        self.state
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                    &yadorilink_replica_domain::ids::SyncPath(rel.to_owned()),
                )
            })
            .unwrap()
    }

    /// This device's own current head for `rel`, in the shape the projection
    /// tests compare: the identity is the head's delta (`change_hash`), the
    /// content its version.
    pub(super) fn own_head(&self, rel: &str) -> PathHead {
        let heads = self.native_heads(rel);
        assert_eq!(heads.len(), 1, "sanity: exactly one live head for {rel}");
        let head = &heads[0];
        assert_eq!(head.dot.author.device.0, LOCAL_DEVICE, "sanity: the head is this device's own");
        let version = self
            .state
            .file_index_repository()
            .canonical_current_row(GROUP, rel)
            .unwrap()
            .map(|row| row.snapshot.mtime_unix_nanos);
        PathHead {
            change_hash: head.payload.provenance.0,
            rank: u64::from_be_bytes(head.payload.version.0[..8].try_into().unwrap()),
            device_id: head.dot.author.device.0.clone(),
            naming_device_id: head.dot.author.device.0.clone(),
            content: Some(yadorilink_replica_engine::conflict::PathHeadContent {
                version_hash: head.payload.version.0,
                mtime_unix_nanos: version.unwrap_or(0),
            }),
        }
    }

    pub(super) async fn materialize_own_head(&self, rel: &str) -> MaterializeResult {
        self.materialize_own_head_under(rel, MaterializationPolicy::Eager).await
    }

    async fn materialize_own_head_under(
        &self,
        rel: &str,
        policy: MaterializationPolicy,
    ) -> MaterializeResult {
        let node = self
            .state
            .native_plan_level(GROUP, super::namespace_steps::parent_of(rel))
            .unwrap()
            .nodes
            .get(&yadorilink_replica_domain::ids::SyncPath(rel.to_owned()))
            .cloned()
            .unwrap_or_else(|| panic!("the plan places an entry at {rel}"));
        self.convergence
            .materialize_native_entry(GROUP, rel, &node, policy, None, None)
            .await
            .expect("materialize must not error")
    }
}

pub(super) fn append(path: &std::path::Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

/// Git's first step: an empty pack file, captured as an empty version
/// (`Present`, no blocks). Git then streams into it before any capture
/// sees the new bytes. Projecting this device's own empty head at that
/// moment must not truncate what git has written -- an empty block list
/// means the file on disk must be empty, and it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_empty_head_is_not_written_over_bytes_appended_since_it_was_captured() {
    let h = Harness::new(false);
    std::fs::write(h.path("tmp_pack"), b"").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    assert_eq!(
        h.state.get_materialization_state(GROUP, "tmp_pack").unwrap(),
        Some(MaterializationState::Present),
        "sanity: a stable capture proves what it read"
    );

    append(&h.path("tmp_pack"), b"PACK streamed by a program that is still writing");

    let _ = h.materialize_own_head("tmp_pack").await;

    assert_eq!(
        std::fs::read(h.path("tmp_pack")).unwrap(),
        b"PACK streamed by a program that is still writing",
        "this device's own empty head must not be projected over newer local bytes"
    );
}

/// The on-demand lane writes a placeholder, not content, but a
/// placeholder written over a file is just as destructive: it replaces
/// the bytes with a sparse file of the row's size. The same last-line
/// check must stand in front of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_head_is_not_written_as_a_placeholder_over_bytes_appended_since_it_was_captured() {
    let h = Harness::new(false);
    std::fs::write(h.path("tmp_pack"), b"").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));

    append(&h.path("tmp_pack"), b"PACK streamed by a program that is still writing");

    let result = h.materialize_own_head_under("tmp_pack", MaterializationPolicy::OnDemand).await;

    assert_eq!(
        std::fs::read(h.path("tmp_pack")).unwrap(),
        b"PACK streamed by a program that is still writing",
        "the on-demand lane must not write a placeholder over newer local bytes"
    );
    assert!(
        matches!(result, MaterializeResult::RetryRequired),
        "a declined placeholder write must be retried, got {result:?}"
    );
}

/// The same, for a capture whose own disk observation raced the write:
/// the row names what was read, but nothing proves what is on disk, so it
/// is left `Remote`. That is not a placeholder this device wrote --
/// the file holds real bytes, newer than the row -- and projecting the
/// row's version over it destroys them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn own_head_is_not_written_over_newer_bytes_under_an_unproven_placeholder_row() {
    let h = Harness::new(false);
    std::fs::write(h.path("tmp_pack"), b"PACK first chunk").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    // What a capture whose closing observation raced leaves behind: the
    // row keeps the version that was read, and the claim that disk holds
    // it is retired (`Present` -> `Remote`). No placeholder
    // generation is recorded: this device never wrote a placeholder here.
    h.state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "tmp_pack",
            MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    append(&h.path("tmp_pack"), b" + the rest of the pack");

    let _ = h.materialize_own_head("tmp_pack").await;

    assert_eq!(
        std::fs::read(h.path("tmp_pack")).unwrap(),
        b"PACK first chunk + the rest of the pack",
        "this device's own head must not be projected over newer local bytes under a \
         Placeholder row it never wrote a placeholder for"
    );
}

/// End to end through a projection pass, with the production flush guard
/// in front of it: the file keeps growing while the guard tries to
/// capture it. The guard cannot capture a file that changes while it is
/// read, so it must say so, and the pass must leave the path alone and
/// retry it -- not project this device's own stale head over the file.
/// Once the writer finishes, a later pass captures the whole file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_still_being_written_is_retried_by_projection_and_captured_once_it_settles() {
    let h = Harness::new(true);
    let pack = h.path("tmp_pack");
    std::fs::write(&pack, b"").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));

    append(&pack, b"PACK header ");
    // Still being written: every read of the file races another append.
    let grow = pack.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(pack.clone(), move || {
        append(&grow, b"more pack ");
        true
    });

    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let attempt = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["tmp_pack".to_string()]))
        .await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&pack);
    let attempt = attempt.unwrap().expect("sanity: the pass must actually run");

    let on_disk = std::fs::read(&pack).unwrap();
    assert!(
        on_disk.starts_with(b"PACK header more pack "),
        "the projection pass must not overwrite a file that is still being written; disk now \
         holds {} bytes: {:?}",
        on_disk.len(),
        String::from_utf8_lossy(&on_disk)
    );
    assert!(
        !attempt.is_settled("tmp_pack"),
        "a path whose local edit could not be captured must not be reported settled"
    );

    // The writer is done. The next pass captures what it wrote. That
    // capture moves the path's head in the middle of the pass, so the pass
    // itself defers; the one after it finds this device's own new head
    // already on disk and settles without writing.
    let expected = std::fs::read(&pack).unwrap();
    let mut settled = false;
    for _ in 0..3 {
        let attempt = h
            .convergence
            .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["tmp_pack".to_string()]))
            .await
            .unwrap()
            .expect("sanity: the pass must actually run");
        assert_eq!(std::fs::read(&pack).unwrap(), expected, "the finished file must be untouched");
        if attempt.is_settled("tmp_pack") {
            settled = true;
            break;
        }
    }
    let row = h.state.get_file(GROUP, "tmp_pack").unwrap().expect("the path is indexed");
    assert_eq!(row.size, expected.len() as u64, "the finished file must have been captured");
    assert!(
        !h.state.dirty_path_repository().is_path_dirty(GROUP, "tmp_pack").unwrap(),
        "once captured, the path must no longer be journaled dirty"
    );
    assert!(settled, "once captured, this device's own head matches disk and the path settles");
}

/// On a case-insensitive volume a program streaming into `foo.pack` and a
/// peer's new `Foo.pack` name the same file. The exact-path guard for
/// `Foo.pack` cannot see `foo.pack` (its leaf bytes differ), so the only
/// thing standing between the growing file and the incoming write is the
/// case-fold sibling guard. When it cannot capture the sibling -- the file
/// changes while it is read -- it must say so, not report the path
/// settled: the hazard check reads only the index, and the sibling never
/// made it in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_fold_sibling_guard_defers_when_the_sibling_cannot_be_captured() {
    let h = Harness::new(true);
    let sibling = h.path("foo.pack");
    std::fs::write(&sibling, b"PACK header ").unwrap();
    *h.pending_sibling.lock().unwrap() = Some(sibling.clone());
    let grow = sibling.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(sibling.clone(), move || {
        append(&grow, b"more pack ");
        true
    });

    let outcome = h.flush.flush_case_fold_sibling(GROUP, "Foo.pack").await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&sibling);

    assert!(
        h.state.get_file(GROUP, "foo.pack").unwrap().is_none(),
        "sanity: a file that changed while it was read is not indexed"
    );
    assert_eq!(
        outcome,
        PendingLocalFlushOutcome::RetryRequired,
        "a case-fold sibling left uncaptured must defer the write to the colliding name"
    );
}

/// The guard runs for every incoming update to a path that exists on
/// disk, including in the ordinary batch's prepare step. For a file that
/// has not changed since it was captured there is nothing to capture, and
/// the guard must not cost a database write: journaling the path dirty
/// and clearing it again are two fsyncing commits per path, which turns a
/// bulk remote update of N files into 2N extra commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_on_an_unchanged_captured_file_writes_nothing() {
    let h = Harness::new(true);
    std::fs::write(h.path("stable.txt"), b"captured and unchanged").unwrap();
    assert!(matches!(h.capture("stable.txt").await, LocalChangeOutcome::FileChanged(_)));

    let database = h.state.database();
    let before = database.write_transaction_count();
    let outcome = h.flush.flush_pending_local_change(GROUP, "stable.txt").await;
    let writes = database.write_transaction_count() - before;

    assert_eq!(outcome, PendingLocalFlushOutcome::Settled);
    assert_eq!(writes, 0, "the guard on an unchanged, captured file must not write");
}

/// The guard itself, with nothing behind it: a file that changes while
/// the guard reads it cannot be captured, and the guard must report that
/// rather than license a write to the path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_reports_a_file_that_changes_while_it_is_read_as_not_settled() {
    let h = Harness::new(true);
    let pack = h.path("tmp_pack");
    std::fs::write(&pack, b"PACK header ").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    append(&pack, b"more pack ");
    let grow = pack.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(pack.clone(), move || {
        append(&grow, b"more pack ");
        true
    });

    let outcome = h.flush.flush_pending_local_change(GROUP, "tmp_pack").await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&pack);

    assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
    assert!(
        h.state.dirty_path_repository().is_path_dirty(GROUP, "tmp_pack").unwrap(),
        "the uncaptured edit must stay journaled for a later capture"
    );
}

/// A delete is as final as a content write. A tombstone arriving for a
/// file whose bytes moved on since this device captured it must be
/// retried, not applied -- once captured, the edit meets the tombstone as
/// a concurrent edit instead of vanishing. With the permissive guard the
/// last-line disk check is the only thing in the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tombstone_is_not_applied_over_bytes_changed_since_they_were_captured() {
    let h = Harness::new(false);
    std::fs::write(h.path("notes.txt"), b"captured").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    append(&h.path("notes.txt"), b" and then edited");

    let mut tombstone = h.state.get_file(GROUP, "notes.txt").unwrap().unwrap();
    tombstone.deleted = true;
    tombstone.blocks.clear();
    tombstone.size = 0;
    let result = h
        .convergence
        .materialize_tombstone(GROUP, &tombstone, "device-remote", &RootCommitPermit::for_tests())
        .await
        .expect("materialize_tombstone must not error");

    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        b"captured and then edited",
        "a tombstone must not delete bytes this device never captured"
    );
    assert_eq!(result, MaterializeResult::RetryRequired);
}

/// A symlink swapped in over a captured file is local state capture has not
/// recorded; a tombstone must not unlink it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tombstone_is_not_applied_over_a_symlink_swapped_in_since_capture() {
    let h = Harness::new(false);
    std::fs::write(h.path("notes.txt"), b"captured").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    std::fs::remove_file(h.path("notes.txt")).unwrap();
    std::os::unix::fs::symlink("elsewhere", h.path("notes.txt")).unwrap();

    let mut tombstone = h.state.get_file(GROUP, "notes.txt").unwrap().unwrap();
    tombstone.deleted = true;
    tombstone.blocks.clear();
    tombstone.size = 0;
    let result = h
        .convergence
        .materialize_tombstone(GROUP, &tombstone, "device-remote", &RootCommitPermit::for_tests())
        .await
        .expect("materialize_tombstone must not error");

    assert!(
        std::fs::symlink_metadata(h.path("notes.txt")).unwrap().file_type().is_symlink(),
        "a tombstone must not unlink a symlink this device never captured"
    );
    assert_eq!(result, MaterializeResult::RetryRequired);
}

/// A peer's delete that descends from this device's own capture makes the
/// path resolve Absent, and projecting that deletes whatever is on disk.
/// When the guard cannot capture the file (it changes while it is read),
/// its answer is the only thing that stops the delete: here each read's
/// racing write is undone before the pass reaches the disk check, so the
/// file looks exactly like the captured version. The pass must defer the
/// path, not delete the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn absent_resolution_defers_when_the_guard_cannot_capture_the_file() {
    let h = Harness::new(true);
    let pack = h.path("tmp_pack");
    std::fs::write(&pack, b"PACK v1").unwrap();
    assert!(matches!(h.capture("tmp_pack").await, LocalChangeOutcome::FileChanged(_)));
    let own = h.own_head("tmp_pack");
    crate::test_support::remote_admission_fixture::admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![crate::test_support::remote_admission_fixture::delete(
            "tmp_pack",
            vec![yadorilink_replica_domain::ids::DeltaHash(own.change_hash)],
        )],
        &[],
    );

    // Rewritten in place with the same bytes, so the guard has to read it,
    // and every read races a write that is undone again right after.
    std::fs::write(&pack, b"PACK v1").unwrap();
    let racing = pack.clone();
    yadorilink_local_capture::test_hooks::arm_content_read_race_hook(pack.clone(), move || {
        append(&racing, b" and more");
        std::fs::OpenOptions::new().write(true).open(&racing).unwrap().set_len(7).unwrap();
        true
    });
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let attempt = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["tmp_pack".to_string()]))
        .await;
    yadorilink_local_capture::test_hooks::disarm_content_read_race_hook(&pack);
    let attempt = attempt.unwrap().expect("sanity: the pass must actually run");

    assert!(
        pack.exists(),
        "an Absent resolution must not delete a file the guard could not capture"
    );
    assert!(!attempt.is_settled("tmp_pack"), "the path must be left for a later pass");
}

/// The guard before an eager write ran before the assembly, which can take
/// as long as the file is big. A write landing after it and before the
/// rename was renamed over, and the watcher then found disk equal to the
/// index and dropped the edit as an echo. The target is looked at again
/// right before the rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_write_landing_during_assembly_is_not_renamed_over() {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    let h = Harness::new(false);
    std::fs::write(h.path("scratch.bin"), b"the peer's bytes").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let version = yadorilink_replica_domain::ids::VersionHash(
        h.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = h.state.dag_get_file_version(GROUP, &version).unwrap().expect("stored here");
    std::fs::write(h.path("notes.txt"), b"captured v1").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    // A peer's update that observed the captured version: the pass writes it.
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", version, vec![own])],
        &[stored],
    );
    // The disk is exactly the captured version when the pass starts, so the
    // check before the assembly passes; the save lands after it.
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"saved during assembly").unwrap()));
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;

    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;

    assert_eq!(
        std::fs::read(h.path("notes.txt")).unwrap(),
        b"saved during assembly",
        "a write that landed between the assembly and the rename must survive"
    );
    assert!(
        h.state.dirty_path_repository().is_path_dirty(GROUP, "notes.txt").unwrap(),
        "the surviving write must be journaled for capture"
    );
    let mut leftovers: Vec<_> = std::fs::read_dir(&h.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with(".yadorilink-root"))
        .collect();
    leftovers.sort();
    assert_eq!(
        leftovers,
        vec!["notes.txt".to_string(), "scratch.bin".to_string()],
        "the abandoned temp file is removed"
    );
}

/// A peer's newer version is being written over this device's older one.
/// The write's pre-write transaction has already moved the row to the
/// newer version (in flight, under an intent for the newer bytes), but the
/// disk still holds the older bytes until the rename. A watcher event in
/// that window waits on the path lock the write holds; a full scan does
/// not: it reads the older bytes against the newer row. Those bytes are
/// not a local edit -- they are what the path displayed before the write
/// began -- and authoring them supersedes the peer's newer version with
/// the older content everywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scan_while_a_newer_version_is_in_flight_does_not_author_the_older_bytes() {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    let h = Harness::new(false);
    let newer = b"the peer's newer version";
    std::fs::write(h.path("scratch.bin"), newer).unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer_version = yadorilink_replica_domain::ids::VersionHash(
        h.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = h.state.dag_get_file_version(GROUP, &newer_version).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), b"older v1").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let older_head = h.own_head("notes.txt");
    let own = yadorilink_replica_domain::ids::DeltaHash(older_head.change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", newer_version, vec![own])],
        &[stored],
    );

    // Between the pre-write transaction and the rename: row at the newer
    // version, disk still the older bytes.
    let scanned: Arc<std::sync::Mutex<Option<Vec<FileRecord>>>> = Arc::default();
    let (processor, state, root, seen) =
        (h.processor.clone(), h.state.clone(), h.root.clone(), scanned.clone());
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(move |out_path| {
            assert_eq!(std::fs::read(out_path).unwrap(), b"older v1", "sanity: not yet renamed");
            assert!(
                state.path_lock(GROUP, "notes.txt").try_lock().is_err(),
                "sanity: the write holds the path lock, so a watcher event waits"
            );
            let records = tokio::task::block_in_place(|| {
                processor.scan_existing_files(GROUP, &root).expect("the scan must run")
            });
            *seen.lock().unwrap() = Some(records);
        }));
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;

    let scanned = scanned.lock().unwrap().take().expect("the hook ran");
    let heads = h.native_heads("notes.txt");
    let authored_here_after_admission = heads.iter().any(|head| {
        head.dot.author.device.0 == LOCAL_DEVICE
            && head.payload.provenance.0 != older_head.change_hash
    });
    assert!(
        !authored_here_after_admission,
        "the older bytes under the in-flight newer row must not be authored as a local edit: \
         scanned {:?}, heads (device, is_newer) {:?}, disk {:?}",
        scanned.iter().map(|r| (r.path.clone(), r.size)).collect::<Vec<_>>(),
        heads
            .iter()
            .map(|head| (
                head.dot.author.device.0.clone(),
                head.payload.version.0 == newer_version.0
            ))
            .collect::<Vec<_>>(),
        String::from_utf8_lossy(&std::fs::read(h.path("notes.txt")).unwrap()),
    );
    assert!(
        !scanned.iter().any(|record| record.path == "notes.txt"),
        "the scan authors nothing for a path being written"
    );

    // The scan never even prepared the path: the bytes it read were the
    // pre-image of the write open over it, so nothing was left for a later
    // capture. (A scan that prepares a path whose lock is busy, and journals
    // it once the lock frees, is pinned in the capture crate's own tests.)
    assert!(!h.state.dirty_path_repository().is_path_dirty(GROUP, "notes.txt").unwrap());
    h.redrive().await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), newer);
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].dot.author.device.0, "device-remote");
    assert_eq!(heads[0].payload.version.0, newer_version.0);
}

/// A write of a peer's newer version that fails after its pre-write
/// transaction (here the disk-headroom preflight) leaves the row at the
/// newer version, its intent open and the disk still holding the older
/// bytes -- with no lock held, since the write has returned. Nothing about
/// those bytes is a local edit: neither a watcher event nor a scan may
/// author them over the newer version, and once the failure clears the
/// write's retry lands the newer version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_older_bytes_a_failed_write_left_under_the_newer_row_are_not_authored() {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    use yadorilink_local_capture::ports::LocalMutationStore as _;
    let h = Harness::new(false);
    let newer = b"the peer's newer version";
    std::fs::write(h.path("scratch.bin"), newer).unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer_version = yadorilink_replica_domain::ids::VersionHash(
        h.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = h.state.dag_get_file_version(GROUP, &newer_version).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), b"older v1").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", newer_version, vec![own])],
        &[stored],
    );
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let project = || {
        h.convergence.reconcile_paths_directly(
            &driver,
            GROUP,
            BTreeSet::from(["notes.txt".to_string()]),
        )
    };

    h.convergence.set_headroom_override_bytes_for_tests(Some(1 << 60));
    h.convergence.set_headroom_enforced_for_tests(true);
    let _ = project().await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"older v1");
    assert!(
        h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_some(),
        "sanity: the failed write left its intent open over the older bytes"
    );
    assert!(
        h.state.has_unsettled_projection_obligation(GROUP, "notes.txt").unwrap(),
        "the failed write leaves its obligation to be retried"
    );

    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::None));
    let scanned = h.scan();
    assert!(!scanned.iter().any(|record| record.path == "notes.txt"), "{scanned:?}");
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].dot.author.device.0, "device-remote", "no local head over the newer");

    h.convergence.set_headroom_enforced_for_tests(false);
    let _ = project().await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), newer);
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].dot.author.device.0, "device-remote");
    assert_eq!(heads[0].payload.version.0, newer_version.0);
    assert!(h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_none());
}

/// A write of a peer's newer version whose reconstruct keeps failing (here:
/// the root is not writable) is demoted: the row holds the newer version, the
/// disk still holds this device's own older bytes, and the write's fence bump
/// has already voided the older bytes' proof. Startup repair must not read
/// those bytes as an offline edit and author them over the peer's version: it
/// quarantines them and rebuilds the row's version from the local blocks.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_repair_does_not_author_the_older_bytes_a_demoted_write_left_under_the_newer_row() {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    use std::os::unix::fs::PermissionsExt;
    use yadorilink_filesystem_sync::materialization_repair::{
        repair_interrupted_materializations, RepairMode,
    };
    use yadorilink_local_capture::ports::LocalMutationStore as _;
    let h = Harness::new(false);
    let (older, newer): (&[u8], &[u8]) = (b"older v1", b"the peer's newer version");
    std::fs::write(h.path("scratch.bin"), newer).unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer_version = yadorilink_replica_domain::ids::VersionHash(
        h.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = h.state.dag_get_file_version(GROUP, &newer_version).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), older).unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", newer_version, vec![own])],
        &[stored],
    );
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;

    let root = h.path("");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o555)).unwrap();
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), older, "sanity: write never landed");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "notes.txt").unwrap(),
        Some(MaterializationState::Present),
        "sanity: the failed write was demoted with the older object under the newer row"
    );
    assert!(
        h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_some(),
        "the intent stays open while the older object sits under the newer row"
    );

    let permit = RootCommitPermit::for_tests();
    let report = repair_interrupted_materializations(
        h.state.as_ref(),
        h.store.as_ref(),
        &root,
        GROUP,
        RepairMode::Startup,
        &permit,
    )
    .unwrap();

    assert_eq!(report.quarantined_dirty.len(), 1, "{report:?}");
    assert_eq!(
        std::fs::read(h.path(&report.quarantined_dirty[0].1)).unwrap(),
        older,
        "the older bytes are preserved"
    );
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), newer, "the row's version is rebuilt");
    assert!(h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_none());
    h.redrive().await;
    let heads: Vec<_> = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1, "no local head beside the peer's version");
    assert_eq!(heads[0].dot.author.device.0, "device-remote");
    assert_eq!(heads[0].payload.version.0, newer_version.0);
}

/// A peer's newer version whose blocks are not available is recorded without
/// its content: the row holds the newer version, the disk still holds this
/// device's own older bytes, untouched. Nothing was written, so those bytes
/// are neither an edit nor an interrupted write: startup repair must leave
/// them alone (no conflict copy), and the intent must not stay open.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_repair_keeps_the_untouched_older_bytes_under_an_incomplete_content_row() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    use yadorilink_filesystem_sync::materialization_repair::{
        repair_interrupted_materializations, RepairMode,
    };
    use yadorilink_local_capture::ports::LocalMutationStore as _;
    let h = Harness::new(false);
    let peer = Harness::new(false);
    let (older, newer): (&[u8], &[u8]) = (b"older v1", b"the peer's newer version");
    std::fs::write(peer.path("scratch.bin"), newer).unwrap();
    assert!(matches!(peer.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer_version = yadorilink_replica_domain::ids::VersionHash(
        peer.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = peer.state.dag_get_file_version(GROUP, &newer_version).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), older).unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", newer_version, vec![own])],
        &[stored],
    );
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), older, "sanity: nothing written");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "notes.txt").unwrap(),
        Some(MaterializationState::Present),
        "sanity: the newer row was recorded without its content over the older object"
    );

    let root = h.path("");
    let report = repair_interrupted_materializations(
        h.state.as_ref(),
        h.store.as_ref(),
        &root,
        GROUP,
        RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert!(report.quarantined_dirty.is_empty(), "{report:?}");
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), older, "untouched bytes stay");
    assert!(!h.state.dirty_path_repository().is_path_dirty(GROUP, "notes.txt").unwrap());
    assert!(h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_none());
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1, "no local head beside the peer's version");
    assert_eq!(heads[0].dot.author.device.0, "device-remote");
}

/// The row ran ahead of the disk (the newer row was recorded, the write
/// never landed) and the user then edits the older bytes still on disk. The
/// edit saw the older version, not the row's: it must not supersede the
/// peer's newer head, which no one here has looked at. Both stay live, as a
/// contest.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_of_the_bytes_on_disk_never_supersedes_the_newer_version_the_row_ran_ahead_to() {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    let h = Harness::new(false);
    let peer = Harness::new(false);
    let (older, newer): (&[u8], &[u8]) = (b"older v1", b"the peer's newer version");
    std::fs::write(peer.path("scratch.bin"), newer).unwrap();
    assert!(matches!(peer.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer_version = yadorilink_replica_domain::ids::VersionHash(
        peer.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = peer.state.dag_get_file_version(GROUP, &newer_version).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), older).unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", newer_version, vec![own])],
        &[stored],
    );
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), older, "sanity: nothing written");

    // The user edits the bytes that are on disk.
    std::fs::write(h.path("notes.txt"), b"older v1, edited").unwrap();
    let _ = h.capture("notes.txt").await;

    let heads = h.native_heads("notes.txt");
    let authors: Vec<&str> = heads.iter().map(|head| head.dot.author.device.0.as_str()).collect();
    assert!(
        authors.contains(&"device-remote"),
        "the peer's newer version must survive the edit: {authors:?}"
    );
}

/// Same as above, but the older bytes hold no proof (the fence moved after
/// they were captured). Nothing vouches for them, so the demotion keeps its
/// intent and startup repair recovers them instead of authoring them as a
/// local Put over the peer's newer version.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_repair_does_not_author_unproven_older_bytes_under_an_incomplete_content_row() {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    use yadorilink_filesystem_sync::materialization_repair::{
        repair_interrupted_materializations, RepairMode,
    };
    use yadorilink_local_capture::ports::LocalMutationStore as _;
    let h = Harness::new(false);
    let peer = Harness::new(false);
    let (older, newer): (&[u8], &[u8]) = (b"older v1", b"the peer's newer version");
    std::fs::write(peer.path("scratch.bin"), newer).unwrap();
    assert!(matches!(peer.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let newer_version = yadorilink_replica_domain::ids::VersionHash(
        peer.own_head("scratch.bin").content.unwrap().version_hash,
    );
    let stored = peer.state.dag_get_file_version(GROUP, &newer_version).unwrap().expect("stored");
    std::fs::write(h.path("notes.txt"), older).unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let own = yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash);
    admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", newer_version, vec![own])],
        &[stored],
    );
    h.state.dag_bump_mutation_fence(GROUP, "notes.txt", "test_void_proof").unwrap();
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), older, "sanity: nothing written");
    assert_eq!(
        h.state.get_materialization_state(GROUP, "notes.txt").unwrap(),
        Some(MaterializationState::Present),
        "sanity: the newer row was recorded without its content over the older object"
    );

    assert!(
        h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_some(),
        "an unproven older object keeps the intent"
    );
    let root = h.path("");
    let report = repair_interrupted_materializations(
        h.state.as_ref(),
        h.store.as_ref(),
        &root,
        GROUP,
        RepairMode::Startup,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert_eq!(report.quarantined_dirty.len(), 1, "{report:?}");
    assert!(!h.state.dirty_path_repository().is_path_dirty(GROUP, "notes.txt").unwrap());
    h.redrive().await;
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1, "no local Put beside the peer's version");
    assert_eq!(heads[0].dot.author.device.0, "device-remote");
}

/// The newer of two quick peer versions, V1 then V2. V1's bytes reach disk
/// but its proof commit loses (the path moved on while it was written), so
/// nothing proves V1 is there; V2's write then replaces V1's intent, moves
/// the row and fails before its rename. Disk holds V1, which neither the
/// open intent (V2) nor any proof names -- but this daemon wrote it, and it
/// is not a local edit: no capture or scan may author it over V2. A real
/// edit landing in the same window is still captured.
async fn an_unproven_earlier_write_under_a_failed_newer_one(
    existing: bool,
    edit: Option<&'static [u8]>,
) {
    use crate::test_support::remote_admission_fixture::{admit_remote, put};
    use yadorilink_local_capture::ports::LocalMutationStore as _;
    let h = Harness::new(false);
    let mut stored = Vec::new();
    for (scratch, content) in [("v1.bin", &b"version one"[..]), ("v2.bin", &b"version two!"[..])] {
        std::fs::write(h.path(scratch), content).unwrap();
        assert!(matches!(h.capture(scratch).await, LocalChangeOutcome::FileChanged(_)));
        let version = yadorilink_replica_domain::ids::VersionHash(
            h.own_head(scratch).content.unwrap().version_hash,
        );
        stored.push(h.state.dag_get_file_version(GROUP, &version).unwrap().unwrap());
    }
    let (v1, v2) = (stored[0].clone(), stored[1].clone());
    let mut observing = Vec::new();
    if existing {
        std::fs::write(h.path("notes.txt"), b"version zero").unwrap();
        assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
        observing
            .push(yadorilink_replica_domain::ids::DeltaHash(h.own_head("notes.txt").change_hash));
    }
    let v1_delta = admit_remote(
        &h.state,
        GROUP,
        "device-remote",
        vec![put("notes.txt", v1.version_hash, observing)],
        std::slice::from_ref(&v1),
    );
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;
    let project = || {
        h.convergence.reconcile_paths_directly(
            &driver,
            GROUP,
            BTreeSet::from(["notes.txt".to_string()]),
        )
    };

    // V2 arrives while V1 is being written, and the path's fence moves: V1
    // is renamed into place, but its proof does not commit.
    let (state, v2_admitted) = (h.state.clone(), v2.clone());
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() = Some(Box::new(move |_| {
        admit_remote(
            &state,
            GROUP,
            "device-remote",
            vec![put("notes.txt", v2_admitted.version_hash, vec![v1_delta.delta_hash()])],
            std::slice::from_ref(&v2_admitted),
        );
        state.dag_bump_mutation_fence(GROUP, "notes.txt", "test").unwrap();
    }));
    let _ = project().await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"version one");
    let proven = h
        .state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation_diagnostic(
                conn, GROUP, "notes.txt",
            )
        })
        .unwrap()
        .and_then(|basis| basis.version);
    assert_ne!(proven, Some(v1.version_hash), "sanity: nothing proves V1 is on disk");

    // V2's write moves the row and fails before its rename.
    h.convergence.set_headroom_override_bytes_for_tests(Some(1 << 60));
    h.convergence.set_headroom_enforced_for_tests(true);
    let _ = project().await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"version one");
    assert!(h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_some());

    if let Some(edit) = edit {
        std::fs::write(h.path("notes.txt"), edit).unwrap();
        let LocalChangeOutcome::FileChanged(record) = h.capture("notes.txt").await else {
            panic!("a real edit in the window must be captured");
        };
        assert_eq!(record.size, edit.len() as u64);
        let heads = h.native_heads("notes.txt");
        assert!(heads.iter().any(|head| head.dot.author.device.0 == LOCAL_DEVICE));
        return;
    }

    // A capture, a scan, and the scan a restart runs: none authors V1.
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::None));
    for _ in 0..2 {
        let scanned = h.scan();
        assert!(!scanned.iter().any(|record| record.path == "notes.txt"), "{scanned:?}");
    }
    h.redrive().await;
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1, "no local head beside the newer version");
    assert_eq!(heads[0].dot.author.device.0, "device-remote");
    assert_eq!(heads[0].payload.version.0, v2.version_hash.0);

    // Once the failure clears, the newer version lands.
    h.convergence.set_headroom_enforced_for_tests(false);
    let _ = project().await;
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"version two!");
    let heads = h.native_heads("notes.txt");
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].payload.version.0, v2.version_hash.0);
    assert!(h.state.materialization_intent_target(GROUP, "notes.txt").unwrap().is_none());
    let recorded: i64 = h
        .state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM materialization_replaced_targets \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, "notes.txt"],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(recorded, 0, "the replaced targets clear with the intent");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unproven_earlier_peer_write_is_not_authored_over_a_failed_newer_one() {
    an_unproven_earlier_write_under_a_failed_newer_one(true, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unproven_first_write_of_a_new_path_is_not_authored_over_a_failed_newer_one() {
    an_unproven_earlier_write_under_a_failed_newer_one(false, None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_edit_under_a_failed_newer_write_is_still_captured() {
    an_unproven_earlier_write_under_a_failed_newer_one(true, Some(b"my own words")).await;
}

/// A regular file at a path this device has no row for was created here
/// after the capture that preceded the write, so nothing has recorded it.
/// The last-line check used to read "no row" as "nothing to protect".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_local_file_at_a_path_without_a_row_counts_as_uncaptured() {
    let h = Harness::new(false);
    std::fs::write(h.path("scratch.bin"), b"the peer's bytes").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let incoming = h.state.get_file(GROUP, "scratch.bin").unwrap().unwrap().blocks;
    std::fs::write(h.path("fresh.txt"), b"typed here, not captured yet").unwrap();
    assert!(h.state.get_file(GROUP, "fresh.txt").unwrap().is_none(), "sanity: no row here");

    assert!(
        h.convergence
            .disk_holds_uncaptured_local_bytes(
                GROUP,
                "fresh.txt",
                &h.path("fresh.txt"),
                Some(&incoming)
            )
            .unwrap(),
        "a new local file must not be replaced by a peer's version"
    );
    assert!(
        h.convergence
            .disk_holds_uncaptured_local_bytes(GROUP, "fresh.txt", &h.path("fresh.txt"), None)
            .unwrap(),
        "nor deleted by a peer's removal"
    );
    // Bytes equal to the incoming version are not lost by writing it.
    std::fs::write(h.path("fresh.txt"), b"the peer's bytes").unwrap();
    assert!(!h
        .convergence
        .disk_holds_uncaptured_local_bytes(
            GROUP,
            "fresh.txt",
            &h.path("fresh.txt"),
            Some(&incoming)
        )
        .unwrap());
}

/// An unindexed local file that cannot be read cannot be compared with the incoming version, so
/// the last-line check must not conclude there is nothing to protect: it errors (a write is
/// declined) or reports the bytes as uncaptured, never "safe to overwrite".
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_unindexed_local_file_is_never_reported_safe_to_overwrite() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Harness::new(false);
    std::fs::write(h.path("scratch.bin"), b"the peer's bytes").unwrap();
    assert!(matches!(h.capture("scratch.bin").await, LocalChangeOutcome::FileChanged(_)));
    let incoming = h.state.get_file(GROUP, "scratch.bin").unwrap().unwrap().blocks;
    let file = h.path("locked.txt");
    std::fs::write(&file, b"typed here, unreadable").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    let restore = || std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644));
    if std::fs::File::open(&file).is_ok() {
        restore().unwrap();
        eprintln!("skipped: the file is readable despite mode 000 (running as root)");
        return;
    }
    assert!(h.state.get_file(GROUP, "locked.txt").unwrap().is_none(), "sanity: no row here");

    let write_guard = h.convergence.disk_holds_uncaptured_local_bytes(
        GROUP,
        "locked.txt",
        &file,
        Some(&incoming),
    );
    let removal_guard =
        h.convergence.disk_holds_uncaptured_local_bytes(GROUP, "locked.txt", &file, None);
    restore().unwrap();

    assert!(!matches!(write_guard, Ok(false)), "write guard: {write_guard:?}");
    assert!(!matches!(removal_guard, Ok(false)), "removal guard: {removal_guard:?}");
    assert_eq!(std::fs::read(&file).unwrap(), b"typed here, unreadable");
}

/// The symlink lane renames the link over whatever is at the path, with
/// none of the last-line checks the content, placeholder and tombstone
/// lanes make. A peer's symlink arriving over a file whose edit landed after
/// the pre-write guard must leave the edit alone.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_symlink_is_not_renamed_over_an_uncaptured_local_edit() {
    use crate::test_support::remote_admission_fixture::{admit_remote_ops, Basis};
    let h = Harness::new(true);
    std::os::unix::fs::symlink("somewhere", h.path("scratch-link")).unwrap();
    assert!(matches!(h.capture("scratch-link").await, LocalChangeOutcome::FileChanged(_)));
    let link_version = yadorilink_replica_domain::ids::VersionHash(
        h.own_head("scratch-link").content.unwrap().version_hash,
    );
    std::fs::write(h.path("notes.txt"), b"captured by this device").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    admit_remote_ops(
        &h.state,
        GROUP,
        "device-remote",
        &[yadorilink_replica_domain::local_op::Op::Put {
            path: yadorilink_replica_domain::ids::SyncPath("notes.txt".into()),
            version: link_version,
        }],
        Basis::CurrentHeads,
    );
    // The edit lands after the pre-write guard looked.
    let edited = h.path("notes.txt");
    *h.after_guard.lock().unwrap() =
        Some(Box::new(move || std::fs::write(&edited, b"edited after the guard").unwrap()));
    let driver = h.session.clone()
        as Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>;

    let _ = h
        .convergence
        .reconcile_paths_directly(&driver, GROUP, BTreeSet::from(["notes.txt".to_string()]))
        .await;

    let meta = std::fs::symlink_metadata(h.path("notes.txt")).unwrap();
    assert!(meta.is_file(), "the peer's symlink must not replace the file");
    assert_eq!(std::fs::read(h.path("notes.txt")).unwrap(), b"edited after the guard");
}

/// A chmod or xattr change moves no bytes, yet capture records it as an edit:
/// a peer's version must not be written over it before capture has.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metadata_only_local_edit_counts_as_uncaptured() {
    use std::os::unix::fs::PermissionsExt as _;
    let h = Harness::new(false);
    let file = h.path("notes.txt");
    std::fs::write(&file, b"same bytes").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    let blocks = h.state.get_file(GROUP, "notes.txt").unwrap().unwrap().blocks;
    let check = || {
        h.convergence.disk_holds_uncaptured_local_bytes(GROUP, "notes.txt", &file, Some(&blocks))
    };
    assert!(!check().unwrap(), "sanity: nothing edited yet");

    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(check().unwrap(), "a chmod alone is an uncaptured edit");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!check().unwrap());

    #[cfg(target_os = "linux")]
    {
        yadorilink_local_storage::apply_xattrs(&file, &[("user.tag".into(), b"mine".to_vec())])
            .unwrap();
        assert!(check().unwrap(), "an xattr alone is an uncaptured edit");
    }
}

/// The accumulator task has exited (watcher gone, executor gone) while the
/// link is live: its request channel is closed. What it held for the path is
/// unknown, so the guards must defer the write rather than report the path
/// settled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guards_defer_when_the_accumulator_is_gone_but_the_link_is_live() {
    let h = Harness::new(true);
    std::fs::write(h.path("notes.txt"), b"captured").unwrap();
    assert!(matches!(h.capture("notes.txt").await, LocalChangeOutcome::FileChanged(_)));
    append(&h.path("notes.txt"), b" and then edited, not yet indexed");
    let dead = h.set_accumulator(false);

    assert_eq!(
        dead.flush_pending_local_change(GROUP, "notes.txt").await,
        PendingLocalFlushOutcome::RetryRequired
    );
    assert_eq!(
        dead.flush_case_fold_sibling(GROUP, "notes.txt").await,
        PendingLocalFlushOutcome::RetryRequired
    );
    assert!(
        dead.flush_all_pending_local_changes(GROUP).await.is_err(),
        "a flush-all that could not reach the accumulator must report it"
    );
}

/// A link being torn down is the one benign closed-accumulator state: its
/// lease refuses the peer-apply path as well, so there is nothing to defer and
/// nothing to retry against.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guards_settle_when_the_link_is_being_torn_down() {
    let h = Harness::new(true);
    let dead = h.set_accumulator(false);
    h.begin_stopping();

    assert_eq!(
        dead.flush_pending_local_change(GROUP, "notes.txt").await,
        PendingLocalFlushOutcome::Settled
    );
    assert_eq!(
        dead.flush_case_fold_sibling(GROUP, "notes.txt").await,
        PendingLocalFlushOutcome::Settled
    );
    assert!(dead.flush_all_pending_local_changes(GROUP).await.is_ok());
}

/// The resume gate: a path drained by a failed flush-all is gone from the
/// accumulator but still journaled dirty, so a retried flush-all (empty drain)
/// must keep failing until the path is captured. Otherwise the link would be
/// unpaused with an edit that is not in the index.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retried_flush_all_still_fails_while_a_drained_path_is_journaled_dirty() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::new(true);
    let file = h.path("locked.txt");
    std::fs::write(&file, b"unreadable").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&file).is_ok() {
        return; // privileged user: cannot fault-inject an unreadable file
    }
    let drained = vec![(file.clone(), FsChangeKind::CreatedOrModified, 1)];
    let handle = h.set_accumulator_draining(drained);

    assert!(handle.flush_all_pending_local_changes(GROUP).await.is_err());
    assert!(h.state.dirty_path_repository().is_path_dirty(GROUP, "locked.txt").unwrap());
    // The retry finds the accumulator empty.
    let retry = handle.flush_all_pending_local_changes(GROUP).await;
    assert!(retry.is_err(), "an empty accumulator with a dirty row is not success");

    // Once the file is readable the next attempt captures it and succeeds.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(handle.flush_all_pending_local_changes(GROUP).await.is_ok());
    assert!(!h.state.dirty_path_repository().is_path_dirty(GROUP, "locked.txt").unwrap());
}

/// A dirty row the journal re-drive can capture is captured by flush-all, and
/// the empty accumulator then reports success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_all_with_an_empty_accumulator_captures_a_capturable_dirty_row() {
    let h = Harness::new(true);
    std::fs::write(h.path("a.txt"), b"journaled but never flushed").unwrap();
    {
        let permit_guard = h.root_lease.begin_operation().unwrap();
        h.state
            .dirty_path_repository()
            .record_dirty_path(GROUP, "a.txt", "created_or_modified", 1, &permit_guard.permit())
            .unwrap();
    }
    let handle = h.set_accumulator_draining(Vec::new());

    assert!(handle.flush_all_pending_local_changes(GROUP).await.is_ok());
    assert!(!h.state.dirty_path_repository().is_path_dirty(GROUP, "a.txt").unwrap());
    assert!(h
        .state
        .file_index_repository()
        .list_files(GROUP)
        .unwrap()
        .iter()
        .any(|f| f.path == "a.txt"));
}

/// No dirty rows and nothing pending is plain success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flush_all_with_nothing_pending_and_no_dirty_rows_succeeds() {
    let h = Harness::new(true);
    let handle = h.set_accumulator_draining(Vec::new());
    assert!(handle.flush_all_pending_local_changes(GROUP).await.is_ok());
}
