//! The two-device assembly every stack-level scenario starts from.
//!
//! A device here is the real thing: a `ReplicaCoordinator`, a
//! `SegmentBlockStore`, a `DaemonState`, a device signing key, and a netmap
//! entry pinning its peer. What the fixture stands in for is the *policy
//! chain* -- the verified group policy a real daemon would have received --
//! because reproducing one is a separate subject with its own tests, and
//! every group would otherwise resolve to `Withhold` the moment a netmap
//! named a writer for it.
//!
//! # Why this is not in `sync_adapter`
//!
//! It was, as `#[cfg(test)]` helpers beside the tests that first needed
//! them. `#[cfg(test)]` is crate-local: a test *binary* under `tests/`
//! compiles against this crate as an ordinary library, with `cfg(test)` off,
//! and so could not see them. That is why the stack-level partition scenario
//! had to live inside `src/` -- not because it belonged there, but because
//! its fixtures did.
//!
//! Gated `#[cfg(any(test, feature = "test-support"))]`, so this is not
//! production API: the only callers that can reach it are this crate's own
//! unit tests and a dependant that asked for the feature. This crate is
//! already its own dev-dependency with `test-support` on, so its integration
//! binaries get it without any further arrangement.
//!
//! # The authority key
//!
//! `authority_key` and `GROUP` live here rather than being borrowed from a
//! test module, because [`FixtureCheckpointSource`] and
//! [`honest_bundle_carrying`] have to agree on both or nothing verifies.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use yadorilink_lane_ports::sim_fault::EndpointId;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::author::fixtures;
use yadorilink_replica_domain::authorization_checkpoint::{
    fingerprint_signing_key, sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, DeviceId};

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

/// The one group every fixture device is a member of.
pub const GROUP: &str = "g";

/// The device id the fixture's Changes are authored under.
///
/// Distinct from the `DaemonState` device names a scenario picks: this is who
/// the Change says wrote it, and it is fixed so a bundle built on one device
/// verifies on another.
pub const DEVICE: &str = "device-A";

/// The key the fixture's deltas are signed with: the
/// fixture key of [`DEVICE`].
pub fn author_key() -> SigningKey {
    fixtures::signing_key(&DeviceId(DEVICE.into()))
}

/// The key whose signature over a checkpoint makes a fixture bundle honest.
pub fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// The fixture group's verified policy granting each of `writers` (a
/// device id and its signing key) the writer role, in order, signed by
/// [`authority_key`]: the chain a coordination plane serves once it has
/// enrolled those devices as the group's writers.
pub fn fixture_group_policy_granting(
    writers: &[(&str, VerifyingKey)],
) -> crate::change_policy::GroupPolicyState {
    use crate::change_policy::policy_signing::grant_record_at_epoch;
    let mut records = Vec::with_capacity(writers.len());
    let mut prev = [0u8; 32];
    for (index, (device, key)) in writers.iter().enumerate() {
        let record = grant_record_at_epoch(
            &authority_key(),
            GROUP,
            index as u64 + 1,
            prev,
            0,
            device,
            fingerprint_signing_key(key),
            crate::change_policy::WriterRole::Editor,
        );
        prev = record.record_hash.as_slice().try_into().expect("a 32-byte record hash");
        records.push(record);
    }
    crate::change_policy::verify_group_policy_log(
        &authority_key().verifying_key().to_bytes(),
        &crate::change_policy::GroupPolicyLog {
            group_id: GROUP.to_string(),
            current_seq: records.len() as u64,
            current_epoch: 0,
            policy_head: prev.to_vec(),
            records,
        },
    )
    .expect("the fixture group's policy verifies")
}

/// Makes every one of `states` a writer of the fixture group on every one
/// of them, as the coordination plane's policy does once it grants them:
/// installs [`fixture_group_policy_granting`] for all of them on each, and
/// stands in a coordination plane for each device's seal authorizations
/// ([`FixtureCheckpointSource`] at the policy's current point), so a base
/// a cross-Base recovery merges is sealed under a genuine authorization.
pub fn grant_fixture_writers(states: &[&DaemonState]) {
    let writers: Vec<(String, VerifyingKey)> = states
        .iter()
        .map(|state| {
            let key = state.device_signing_key().expect("the fixture device has a signing key");
            (state.device_id.clone(), key.verifying_key())
        })
        .collect();
    let named: Vec<(&str, VerifyingKey)> =
        writers.iter().map(|(device, key)| (device.as_str(), *key)).collect();
    let policy = fixture_group_policy_granting(&named);
    let point =
        (policy.to_watermark().highest_verified_seq, policy.to_watermark().highest_verified_head);
    for state in states {
        state.authority.replace_group_policy_states(std::collections::HashMap::from([(
            GROUP.to_string(),
            policy.clone(),
        )]));
        *state.test_seal_checkpoint_source.lock().unwrap_or_else(|p| p.into_inner()) = Some(
            Arc::new(FixtureCheckpointSource::for_device(state).at_policy_point(point.0, point.1)),
        );
    }
}

/// A real device: coordinator, block store, state, signing key, policy
/// bootstrap.
///
/// The returned [`ReleasingDir`] is the block store's directory, and dropping
/// it takes the store's files with it -- so a caller has to hold it for as
/// long as the device is expected to work.
pub fn device(name: &str, key_byte: u8) -> (Arc<DaemonState>, ReleasingDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(name.into(), coordinator, store);
    state.set_device_signing_key(SigningKey::from_bytes(&[key_byte; 32]));
    // Disclosure needs a group this device may serve at all, not just a peer
    // it may serve to. A real daemon gets that from a verified policy chain;
    // here the fixture stands in for one. Without it every group resolves to
    // `Withhold` the moment a netmap names a writer for it, which is correct
    // production behaviour.
    state.authority.install_test_group_policy_bootstrap(GROUP);
    let store = ReleasingDir::new(store_dir, &state);
    (state, store)
}

/// A temporary directory a test holds for as long as it uses `state`, which
/// also frees `state` when it goes.
///
/// A state that ran a stack or held a peer session is part of a reference
/// cycle back to itself (see
/// [`DaemonState::release_reference_cycles_for_tests`]), so dropping every
/// handle a test holds would not free it: its databases and their pool
/// worker threads would outlive the test, and a test binary that builds
/// hundreds of states exhausts the process's threads. A fixture's directory
/// is what every caller already holds until it is done with the state, so
/// its drop is where the cycle is broken.
pub struct ReleasingDir {
    dir: tempfile::TempDir,
    state: Arc<DaemonState>,
}

impl ReleasingDir {
    pub fn new(dir: tempfile::TempDir, state: &Arc<DaemonState>) -> Self {
        Self { dir, state: state.clone() }
    }
}

impl std::ops::Deref for ReleasingDir {
    type Target = tempfile::TempDir;

    fn deref(&self) -> &tempfile::TempDir {
        &self.dir
    }
}

impl Drop for ReleasingDir {
    fn drop(&mut self) {
        self.state.release_reference_cycles_for_tests();
    }
}

/// The endpoint identity a device built with `key_byte` will have.
///
/// `SyncStack::spawn` hands the device signing key straight to the substrate
/// node, so a device's endpoint id *is* the public half of its signing key.
/// Written that way rather than by asking iroh to derive it, because the
/// equality is the fact worth stating: it is what lets a scenario declare a
/// partition against a device that has not started yet.
pub fn endpoint_of(key_byte: u8) -> EndpointId {
    let public = SigningKey::from_bytes(&[key_byte; 32]).verifying_key().to_bytes();
    EndpointId::from_bytes(&public).expect("an ed25519 public key is a valid endpoint id")
}

/// Pin `peer` in `local`'s netmap and authorize it for the group, exactly as
/// an authenticated netmap entry would.
pub fn pin(local: &DaemonState, peer_name: &str, peer_key: u8) {
    let key = SigningKey::from_bytes(&[peer_key; 32]).verifying_key().to_bytes();
    local.record_peer_signing_key(peer_name, key);
    local.replace_peer_netmap_metadata(
        peer_name,
        Some(key),
        &std::iter::once(GROUP.to_string()).collect(),
        &Default::default(),
    );
}

/// A real, structurally valid file version of `size` bytes in one block.
///
/// The version hash is derived from the content, as it is everywhere else --
/// these fixtures never invent an identity, because a version whose hash does
/// not describe its bytes is exactly what the receiving side is supposed to
/// reject.
pub fn file_version(size: u32, seed: u8) -> FileVersion {
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(vec![seed; 32]), size }],
        size as u64,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

// ---------------------------------------------------------------------------
// Local capture: what a device writes to disk, as a Change it signed itself.
// ---------------------------------------------------------------------------
//
// Everything above builds a Change on the caller's behalf and stages it as
// already-verified. That is enough to ask whether the stack carries a Change,
// and not enough to ask whether the product notices a file. A `Case`'s `Op`
// is filesystem-level, so running one means running the pipeline production
// runs:
//
// ```text
// filesystem event
//   -> LocalChangeProcessor + LocalAuthorKey   (a Change this device signed)
//   -> Pending
//   -> flush_pending_checkpoint               (Pending -> Published)
//   -> note_local_commit_for_group
//   -> PeerSessionDriver -> SyncStack -> RBSR
// ```
//
// The `Pending` step is not a formality: a Pending Change is not servable
// over RBSR, so a scenario that captures a local write and stops there has
// built something the peer can never receive.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use yadorilink_local_capture::LocalChangeProcessor;

use crate::checkpoint_source::CheckpointSource;

/// This device's own local-capture processor, signing with the device key
/// `DaemonState` already holds.
///
/// Derived from `state.device_signing_key()` rather than from a parallel
/// generator. A device's signing key is also its substrate endpoint identity
/// (see [`endpoint_of`]), so a fixture that minted a second key for change
/// authoring would give one device two identities and make a partition
/// declared against one of them miss the other.
pub fn local_capture(state: &Arc<DaemonState>) -> Arc<LocalChangeProcessor> {
    let signing = state.device_signing_key().expect("the fixture's device has a signing key");
    Arc::new(
        LocalChangeProcessor::new(
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            state.device_id.clone(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(Arc::new(
            crate::test_support::local_seam::replica_author_key(
                &state.replica_coordinator,
                &state.device_id,
                signing,
            )
            .unwrap(),
        )),
    )
}

/// A coordination plane that issues checkpoints signed by [`authority_key`].
///
/// A fake source rather than a fake flush: `flush_pending_checkpoint` is the
/// production primitive that turns Pending into Published, and it verifies
/// every leaf against the checkpoint before attaching anything. Reaching
/// Published by calling that with a stand-in issuer exercises the primitive;
/// attaching evidence directly would skip the thing under test.
///
/// The one key it signs with is [`authority_key`], which is what the fixture
/// group's policy resolves -- so a Change published here verifies on the peer
/// without any second arrangement.
pub struct FixtureCheckpointSource {
    device_signing_public_key: VerifyingKey,
    next_seq: Mutex<u64>,
    /// The policy point (`policy_seq`, `policy_head`) every checkpoint pins.
    policy_point: (u64, [u8; 32]),
}

impl FixtureCheckpointSource {
    /// `state` is the device whose Changes this source will authorize: a
    /// checkpoint names the signing key of the device it covers, and a real
    /// coordination plane knows it because the device enrolled with it.
    pub fn for_device(state: &DaemonState) -> Self {
        Self {
            device_signing_public_key: state
                .device_signing_key()
                .expect("the fixture's device has a signing key")
                .verifying_key(),
            next_seq: Mutex::new(0),
            policy_point: (1, [0u8; 32]),
        }
    }

    /// This source pinning the policy point `(seq, head)` in every
    /// checkpoint: the point a plane that granted the device writes checks
    /// against, which a seal authorization must name for its verifier to
    /// find the sealer's grant there.
    pub fn at_policy_point(mut self, seq: u64, head: [u8; 32]) -> Self {
        self.policy_point = (seq, head);
        self
    }
}

impl CheckpointSource for FixtureCheckpointSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        _request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
        _purpose: crate::checkpoint_source::CheckpointPurpose,
    ) -> Pin<Box<dyn Future<Output = Option<(AuthorizationCheckpoint, [u8; 64])>> + Send + 'a>>
    {
        Box::pin(async move {
            let seq = {
                let mut next = self.next_seq.lock().expect("checkpoint seq lock");
                *next += 1;
                *next
            };
            let authority = authority_key();
            let checkpoint = AuthorizationCheckpoint {
                group_id: group_id.to_string(),
                device_id: device_id.to_string(),
                signing_key_fingerprint: fingerprint_signing_key(&self.device_signing_public_key),
                merkle_root,
                leaf_count,
                checkpoint_seq: seq,
                signer_key_id: fingerprint_signing_key(&authority.verifying_key()),
                policy_epoch: 0,
                policy_seq: self.policy_point.0,
                policy_head: self.policy_point.1,
                issued_at_unix: 1,
            };
            let signature = sign_checkpoint(&checkpoint, &authority);
            Some((checkpoint, signature))
        })
    }
}

/// Links `root` as this device's folder for [`GROUP`], the way linking it
/// would.
///
/// Three things, none optional, each one a state the daemon cannot be in
/// without it:
///
/// * The link row. A session's sync roots are derived from the link table, so
///   a device holding a root with no link row is a state production cannot
///   produce, and the apply path refuses to write for it.
/// * `VerifiedRoot::open`, which adopts the root token. Without it the local
///   capture refuses the root outright -- "the link has no previously-adopted
///   root token" -- and indexes nothing, which is correct: an unadopted root
///   might be a different folder that happens to sit at the same path.
/// * A completed startup. A daemon never leaves a live link without a
///   readiness gate, and peer apply defers for a live link that has none, so
///   a link made with a bare `add_link` silently defers everything for the
///   whole test budget.
/// * A live `RootCommitAuthority`. Production gets this from the `RootLease`
///   the link runtime creates in `start_link_watch`; a device without one
///   cannot commit a projection for the group, so it holds and serves
///   Changes and writes nothing -- which looks exactly like a broken
///   projection path and is not one.
///
/// The same three steps as `peer_session_fixture::link_with_completed_startup`,
/// for this fixture's own group. Not shared, because that one hard-codes its
/// own `GROUP` and the two fixtures name different groups; what is worth
/// sharing is the reasoning above, and it is written down in both places.
/// Returns the path the link was actually made under, which is `root`
/// canonicalised.
///
/// Returned rather than discarded because the difference bites. The link row,
/// the adopted root token and the readiness gate are all keyed by the
/// canonical path, while the local capture resolves an event against whatever
/// root its caller hands it -- so a caller that keeps its own uncanonical
/// path and passes that to `process_event` is describing a folder the daemon
/// has no link for, and captures nothing. On Linux a `tempfile::tempdir()`
/// under `/tmp` is already canonical and the two coincide; on macOS it is
/// `/var/folders/...`, a symlink to `/private/var/folders/...`, and they
/// never do. Taking the return value is how a caller stops holding the wrong
/// one.
#[must_use = "the link was made under the canonical path; using the original \
              path instead is what makes the capture find no link"]
pub fn link_folder(state: &DaemonState, root: &std::path::Path) -> std::path::PathBuf {
    let canonical = root.canonicalize().expect("the linked folder exists");
    let coordinator = &state.replica_coordinator;
    coordinator.link_repository().add_link(&canonical.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &canonical,
        GROUP,
        coordinator.as_ref(),
    )
    .expect("adopt a root token for the linked folder");
    let generation = coordinator.startup_readiness().begin_group_startup(GROUP);
    coordinator.startup_readiness().mark_group_ready(GROUP, generation);
    state.install_test_root_commit_authority(GROUP);
    canonical
}

/// A linked folder with the production watcher-to-capture pipeline behind it.
///
/// The whole point is that a scenario writes a file and does nothing else.
/// Everything between the write and the peer is production code:
///
/// ```text
/// std::fs::write
///   -> FsChangeEvent            (what the OS watcher would have produced)
///   -> debounce::run_debouncer  (real quiet period, real coalescing)
///   -> LocalChangeProcessor::process_flush
///   -> Pending
///   -> flush_pending_checkpoint -> Published
/// ```
///
/// The last two steps are what `DaemonState::on_local_native_commit` does in
/// production, in that order, and they are here rather than in the scenario
/// because a scenario that forgot either would produce a Change RBSR cannot
/// serve and a failure that reads like a network problem.
///
/// The simulated watch source rather than a real OS watcher: a test that
/// waited for inotify would be measuring the kernel, and on macOS or Windows
/// it would be measuring something else again. What is under test is the
/// debounce boundary and everything after it, and `SimulatedFolderWatchSource`
/// is the seam production itself uses to stand in for the OS.
pub struct WatchedFolder {
    /// Owned for its lifetime only, and `None` when the caller supplied the
    /// directory. Every path this type hands out or reports comes from
    /// `canonical` instead -- see [`WatchedFolder::path`].
    _root: Option<tempfile::TempDir>,
    canonical: std::path::PathBuf,
    events: tokio::sync::mpsc::Sender<yadorilink_filesystem_sync::watcher::FsChangeEvent>,
    /// What the registered link runtime's flush handle reaches the daemon
    /// through, held here because the handle only holds it weakly. `None`
    /// unless the folder was made by [`watch_folder_with_pending_flush`].
    _flush_dependencies: Option<Arc<crate::link_runtime::dependencies::LinkRuntimeDependencies>>,
}

impl WatchedFolder {
    /// The folder, by the name the capture pipeline knows it under.
    ///
    /// Canonical, and that is not a detail. `process_flush` is given the
    /// canonical root, and it resolves each event's path *relative to that
    /// root*; an event naming the same file by an uncanonical path is outside
    /// the root as far as the capture is concerned, and is dropped. The device
    /// then produces no Change at all, which reads exactly like a broken
    /// capture pipeline.
    ///
    /// On Linux a `tempfile::tempdir()` under `/tmp` is already canonical and
    /// the distinction never shows. On macOS the same call returns
    /// `/var/folders/...`, which is a symlink to `/private/var/folders/...`,
    /// so the two differ on every single event: four tests that pass here fail
    /// there, deterministically, with "the local capture did not produce a
    /// Change". Reported by the macOS lane rather than found locally, which is
    /// the only way this class gets found.
    ///
    /// So the uncanonical path is not exposed at all -- the `TempDir` is kept
    /// private and only for its lifetime. A caller cannot reach the wrong path
    /// to pass it back in.
    pub fn path(&self) -> &std::path::Path {
        &self.canonical
    }

    /// Reports a path to the watcher, exactly as the OS would have.
    ///
    /// Separate from the write so a caller that already performed the
    /// filesystem change -- `dst_support::op_applier::apply_op`, which is
    /// what turns a `Case`'s `Op` into disk state -- can report it without
    /// this type having to know what a `Case` is.
    ///
    /// Always called after the change, never before: the capture re-stats
    /// the path, so an event that arrives first describes a file that is not
    /// there yet and is correctly ignored.
    pub async fn notify(
        &self,
        path: std::path::PathBuf,
        kind: yadorilink_filesystem_sync::watcher::FsChangeKind,
    ) {
        self.events
            .send(yadorilink_filesystem_sync::watcher::FsChangeEvent { path, kind })
            .await
            .expect("the watcher channel outlives the folder");
    }

    /// Writes `contents` at `relative` and tells the watcher.
    ///
    /// The file's mtime is set to [`deterministic_mtime`] of the path and
    /// contents before the watcher hears of it. A file's mtime is part of
    /// its version identity, so leaving the wall-clock time the write
    /// happened to run at would give the same scenario different version
    /// and Change hashes on every run, and anything ordered by those hashes
    /// could then differ between two runs of one seed.
    pub async fn write(&self, relative: &str, contents: &[u8]) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let path = self.path().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the file's parent directory");
        }
        std::fs::write(&path, contents).expect("write the file the device should notice");
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(deterministic_mtime(relative, contents)))
            .expect("pin the written file's mtime");
        self.notify(path, FsChangeKind::CreatedOrModified).await;
    }

    /// Deletes `relative` and tells the watcher.
    pub async fn remove(&self, relative: &str) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let path = self.path().join(relative);
        std::fs::remove_file(&path).expect("remove the file the device should notice");
        self.notify(path, FsChangeKind::ObservedRemoval).await;
    }

    /// Creates the directory `relative` (and any missing parents) and tells
    /// the watcher about the directory itself, as `mkdir -p` would be
    /// reported.
    ///
    /// Distinct from the parent a [`Self::write`] creates silently: a
    /// directory the watcher reported is one the user made, so capture can
    /// author it as an explicit entry and record the filesystem object it
    /// is. A later [`Self::rename_tree`] is paired by that identity; a
    /// directory nobody reported has none to pair by.
    pub async fn mkdir(&self, relative: &str) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let path = self.path().join(relative);
        std::fs::create_dir_all(&path).expect("create the directory the device should notice");
        self.notify(path, FsChangeKind::CreatedOrModified).await;
    }

    /// Removes the directory `relative` and everything below it, as
    /// `rm -rf` does, and reports each removed path to the watcher in the
    /// order `rm -rf` removes them: every entry before the directory that
    /// held it.
    ///
    /// One event per removed path, because that is what a recursive watcher
    /// produces for `rm -rf`, and capture groups the burst back into one
    /// recursive delete from those events and what is (no longer) on disk.
    /// A primitive that reported only the top directory would test a
    /// grouping the OS never asks for.
    pub async fn remove_tree(&self, relative: &str) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let root = self.path().join(relative);
        let mut removed = Vec::new();
        collect_post_order(&root, &mut removed);
        std::fs::remove_dir_all(&root).expect("remove the tree the device should notice");
        for path in removed {
            self.notify(path, FsChangeKind::ObservedRemoval).await;
        }
    }

    /// Renames the directory `from` to `to` in one `rename(2)` and reports
    /// both sides, as a recursive watcher reports a directory move: the old
    /// path gone, the new one present, and nothing for the entries inside,
    /// which moved with their directory without being touched.
    ///
    /// `to`'s parent must exist. Both events are sent back to back, so they
    /// reach capture in one debounced flush, which is where capture pairs a
    /// vanished directory with an appearing one.
    pub async fn rename_tree(&self, from: &str, to: &str) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let (source, destination) = (self.path().join(from), self.path().join(to));
        std::fs::rename(&source, &destination).expect("rename the tree the device should notice");
        self.notify(source, FsChangeKind::ObservedRemoval).await;
        self.notify(destination, FsChangeKind::CreatedOrModified).await;
    }
}

/// Every path under `path` and `path` itself, each entry before the
/// directory holding it. Symlinks are listed, never followed.
fn collect_post_order(path: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let metadata = std::fs::symlink_metadata(path).expect("stat a path of the tree");
    if metadata.is_dir() {
        let mut children: Vec<_> = std::fs::read_dir(path)
            .expect("list a directory of the tree")
            .map(|entry| entry.expect("a directory entry of the tree").path())
            .collect();
        // Sorted, so a seed replays the same event order on every host.
        children.sort();
        for child in children {
            collect_post_order(&child, out);
        }
    }
    out.push(path.to_path_buf());
}

/// Links a fresh folder for `state` and starts the capture pipeline over it.
///
pub fn watch_folder(
    state: &Arc<DaemonState>,
    _driver: &Arc<crate::sync_adapter::PeerSessionDriver>,
) -> WatchedFolder {
    watch_folder_over(state, own_temp_dir(), false)
}

/// [`watch_folder`], with the folder also registered as the group's link
/// runtime, so the pending-change flush production runs before projecting
/// over a path -- `PendingLocalChangeFlush` on `DaemonState` -- reaches this
/// folder's debouncer.
///
/// A change that flush forces through capture is announced the way
/// production announces it, and `on_local_native_commit` finds no coordination
/// plane here to publish it with: it stays Pending until the caller
/// publishes it (`publish_local_pending`).
pub fn watch_folder_with_pending_flush(
    state: &Arc<DaemonState>,
    _driver: &Arc<crate::sync_adapter::PeerSessionDriver>,
) -> WatchedFolder {
    watch_folder_over(state, own_temp_dir(), true)
}

/// [`watch_folder`], over a directory the caller already has.
///
/// For the cases where *which* directory it is matters -- a root reached
/// through a symlink, a folder that has to outlive the handle, or a second
/// handle onto an existing one.
pub fn watch_folder_at(
    state: &Arc<DaemonState>,
    _driver: &Arc<crate::sync_adapter::PeerSessionDriver>,
    root: &std::path::Path,
) -> WatchedFolder {
    watch_folder_over(state, (None, root.to_path_buf()), false)
}

/// A fresh directory and the path to reach it by, separately, because the
/// path has to outlive the move of the `TempDir` into the handle.
fn own_temp_dir() -> (Option<tempfile::TempDir>, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("a linked folder");
    let path = root.path().to_path_buf();
    (Some(root), path)
}

/// The mtime [`WatchedFolder::write`] gives a file: a fixed epoch plus whole
/// seconds taken from an FNV-1a hash of the path and contents.
///
/// A function of what was written rather than of when or on which device,
/// so a replay reproduces it exactly. Different contents at one path get
/// different mtimes (barring a 2^30 collision), so capture never sees an
/// edit as an unchanged size-and-mtime pair -- which a per-folder counter
/// would allow when two devices each make their first write to one path.
/// Whole seconds, so a filesystem with coarse timestamps stores it intact.
fn deterministic_mtime(relative: &str, contents: &[u8]) -> std::time::SystemTime {
    const EPOCH_SECS: u64 = 1_700_000_000;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in relative.as_bytes().iter().chain([&0u8]).chain(contents) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(EPOCH_SECS + (hash & ((1 << 30) - 1)))
}

fn watch_folder_over(
    state: &Arc<DaemonState>,
    (owned_root, root): (Option<tempfile::TempDir>, std::path::PathBuf),
    register_pending_flush: bool,
) -> WatchedFolder {
    let root = root.as_path();
    use yadorilink_filesystem_sync::debounce::{self, DebounceConfig};
    use yadorilink_filesystem_sync::watcher::{FolderWatchSource, SimulatedFolderWatchSource};

    let canonical = link_folder(state, root);

    let (watch_source, events) = SimulatedFolderWatchSource::new(32);
    let ignore_set =
        Arc::new(yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&canonical, ignore_set).expect("watch the linked folder");
    let (events_rx, overflowed, guard) = watcher.split();
    // The guard keeps the watch alive; the folder outlives it by construction
    // because `WatchedFolder` owns the TempDir the watch is over.
    Box::leak(Box::new(guard));

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(debounce::run_debouncer(
        DebounceConfig::default(),
        events_rx,
        flush_tx,
        overflowed,
        flush_request_rx,
        flush_all_request_rx,
    ));

    let processor = local_capture(state);
    let flush_dependencies = register_pending_flush.then(|| {
        let dependencies = state.link_runtime_dependencies();
        let local_path = canonical.to_string_lossy().to_string();
        let root_lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
        let flush_handle =
            crate::link_runtime::operations::capture_local_change::LinkFlushHandle::new(
                &dependencies,
                flush_request_tx.clone(),
                flush_all_request_tx.clone(),
                processor.clone(),
                canonical.clone(),
                local_path.clone(),
                root_lease.clone(),
            );
        crate::link_registry::LinkRegistry::reserve_starting(&state.links, local_path)
            .expect("nothing else runs this folder")
            .publish(Arc::new(crate::link_runtime::LinkRuntime::new(
                Vec::new(),
                Arc::new(flush_handle),
                root_lease,
            )));
        dependencies
    });
    drop((flush_request_tx, flush_all_request_tx));
    let capture_root = canonical.clone();
    tokio::spawn(async move {
        while let Some(flush) = flush_rx.recv().await {
            let Ok(outcome) = processor.process_flush(GROUP, &capture_root, flush).await else {
                continue;
            };
            if outcome.records.is_empty() {
                continue;
            }
        }
    });

    WatchedFolder { _root: owned_root, canonical, events, _flush_dependencies: flush_dependencies }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mtime `write` stamps is a function of what was written: a rerun
    /// reproduces it, and an edit of the same size does not share it.
    #[test]
    fn deterministic_mtime_depends_only_on_path_and_contents() {
        let first = deterministic_mtime("docs/a.bin", &[0x11; 8]);
        assert_eq!(first, deterministic_mtime("docs/a.bin", &[0x11; 8]));
        assert_ne!(first, deterministic_mtime("docs/a.bin", &[0x99; 8]));
        assert_ne!(first, deterministic_mtime("docs/b.bin", &[0x11; 8]));
        let secs = first.duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(secs.subsec_nanos(), 0, "whole seconds survive coarse timestamps");
    }

    /// The endpoint a scenario partitions is the endpoint the device will
    /// actually have. If these ever diverge, a partition would be declared
    /// against nothing, every network fault would silently do nothing, and
    /// the scenario would pass by never being cut.
    // `device` builds a real `DaemonState`, which supervises tasks.
    #[tokio::test]
    async fn the_predicted_endpoint_is_the_one_the_device_key_yields() {
        let key_byte = 11u8;
        let (state, _dir) = device("device-endpoint", key_byte);

        let signing = state.device_signing_key().expect("the fixture set one");
        assert_eq!(
            endpoint_of(key_byte).as_bytes(),
            &signing.verifying_key().to_bytes(),
            "the endpoint a scenario cuts is not the one this device will bind"
        );
    }
}
