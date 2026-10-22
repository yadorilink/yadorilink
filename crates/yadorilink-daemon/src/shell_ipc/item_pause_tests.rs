#![cfg(test)]

//! Per-item pause from the shell context menu, observed end to end through
//! the shell IPC handler, a running link (real watcher, real local
//! capture) and the real obligation-driven projection scheduler.
//!
//! What each test observes:
//!
//! - local emission: whether a local write to a paused item became a signed
//!   change in this device's own history. A change that was never authored
//!   is a change no peer can ever be served, so "not authored" is the
//!   strongest local statement of "did not propagate";
//! - remote projection: whether a remote change already admitted into this
//!   device's history was written to the local folder by the projection
//!   scheduler;
//! - resume: both of the above catching up, including the case where the
//!   same file changed on both sides while paused.
//!
//! The remote versions these tests admit are deliberately blockless
//! (`FileVersion::new(vec![], 0, ..)`): there is nothing to fetch, so
//! projection can complete on a device with no content source. That is
//! enough to show the pause gate acting before content, and the control
//! (an unpaused path projecting in the same run) shows the gate is what
//! held the paused one. It does NOT show that content-carrying changes
//! project end to end; these tests are not evidence for that path.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_filesystem_sync::watcher::RealFolderWatchSource;
use yadorilink_ipc_proto::shellipc::{ContextActionRequest, LocalWriteRequest};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

use super::*;

const GROUP: &str = "item-pause-group";

struct Fixture {
    state: Arc<DaemonState>,
    context: ShellContext,
    root: std::path::PathBuf,
    local_path: String,
    _root_dir: crate::test_support::sync_stack_fixture::ReleasingDir,
}

async fn fixture() -> Fixture {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let local_path = root.to_string_lossy().into_owned();
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let replica_coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    // No maintenance coordinator: the projection scheduler runs only when a
    // test drives it, so "not projected" is an observation, not a race.
    let state = DaemonState::build("device-local".into(), replica_coordinator, store);
    state.set_device_signing_key(SigningKey::from_bytes(&[7u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_group_id| Ok([0u8; 32])));
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();

    let controller = LinkRuntimeController::new(state.clone());
    controller
        .start_with_source(local_path.clone(), GROUP.to_string(), Arc::new(RealFolderWatchSource))
        .expect("the watch must start");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.replica_coordinator.wait_group_ready(GROUP),
    )
    .await
    .expect("the initial scan must finish")
    .expect("the initial scan must succeed");
    register_candidate_session(&state).await;

    let context = ShellContext::from_state(state.clone());
    let _root_dir = crate::test_support::sync_stack_fixture::ReleasingDir::new(root_dir, &state);
    Fixture { state, context, root, local_path, _root_dir }
}

async fn register_candidate_session(state: &Arc<DaemonState>) {
    let deps = crate::peer_orchestrator::peer_sync_session_deps(state);
    let (transports, _peer_transports) =
        crate::test_support::session_transports_pair("device-local", "device-peer").await;
    let peer_store = Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
        state.block_store.clone(),
    ));
    let replica_engine = crate::replica_coordinator::engine_ports::build_peer_replica_engine(
        &state.replica_coordinator,
        peer_store.clone(),
    );
    let session = PeerSyncSession::over_substrate(
        "device-local".to_string(),
        "device-peer".to_string(),
        state.replica_coordinator.clone()
            as Arc<dyn yadorilink_peer_session::ports::BlockServeAuthorizationPort>,
        replica_engine,
        peer_store,
        vec![GROUP.to_string()],
        transports,
        deps,
    );
    state.peers.register_session("device-peer".to_string(), session, state.local_convergence());
}

impl Fixture {
    async fn context_action(&self, rel_path: &str, action: ContextAction) -> ContextActionResponse {
        let response = handle_message(
            &self.context,
            ShellIpcMessage {
                payload: Some(Payload::ContextActionRequest(ContextActionRequest {
                    path: self.root.join(rel_path).to_string_lossy().into_owned(),
                    action: action as i32,
                })),
            },
        )
        .await
        .unwrap();
        let Some(Payload::ContextActionResponse(r)) = response.payload else {
            panic!("expected a ContextActionResponse");
        };
        r
    }

    /// Writes `contents` and reports the write the way the File Provider
    /// does, which captures it synchronously through the same local
    /// capture path the watcher uses.
    async fn write_locally(&self, rel_path: &str, contents: &[u8]) {
        let path = self.root.join(rel_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        let response = handle_message(
            &self.context,
            ShellIpcMessage {
                payload: Some(Payload::LocalWriteRequest(LocalWriteRequest {
                    local_path: self.local_path.clone(),
                    relative_path: rel_path.to_string(),
                    kind: LocalWriteKind::CreatedOrModified as i32,
                })),
            },
        )
        .await
        .unwrap();
        let Some(Payload::LocalWriteResponse(r)) = response.payload else {
            panic!("expected a LocalWriteResponse");
        };
        assert!(r.ok, "the local write must be accepted: {}", r.error);
    }

    /// How many versions of `rel_path` this device has authored or placed
    /// (its local index history -- a remote change joins it only once it
    /// is projected).
    fn versions(&self, rel_path: &str) -> usize {
        self.state.replica_coordinator.sqlite().dag_list_versions(GROUP, rel_path).unwrap().len()
    }

    /// `rel_path`'s live native heads.
    fn live_heads(&self, rel_path: &str) -> Vec<yadorilink_replica_domain::native_state::LiveHead> {
        self.state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::native_store::native_heads_at(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                    &yadorilink_replica_domain::ids::SyncPath(rel_path.to_owned()),
                )
            })
            .unwrap()
    }

    /// The live heads of every path in `dir` whose name starts with `stem`: a
    /// file and the copies its losers were moved to.
    fn live_heads_named(
        &self,
        dir: &str,
        stem: &str,
    ) -> Vec<yadorilink_replica_domain::native_state::LiveHead> {
        let prefix = format!("{dir}/{stem}");
        self.state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let state = yadorilink_sync_sqlite::native_store::load_state(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                )?;
                Ok(state
                    .heads
                    .iter()
                    .filter(|(path, _)| path.as_str().starts_with(&prefix))
                    .flat_map(|(_, heads)| {
                        heads.iter().map(|(dot, payload)| {
                            yadorilink_replica_domain::native_state::LiveHead {
                                dot: dot.clone(),
                                payload: payload.clone(),
                            }
                        })
                    })
                    .collect())
            })
            .unwrap()
    }

    /// The devices whose deltas put `rel_path`'s live heads, sorted.
    fn head_authors(&self, rel_path: &str) -> Vec<String> {
        let mut authors: Vec<String> = self
            .live_heads(rel_path)
            .into_iter()
            .map(|head| head.dot.author.device.0.clone())
            .collect();
        authors.sort();
        authors
    }

    /// Admits a zero-length version of `rel_path` authored by another
    /// device on top of this device's current frontier -- a peer edit of
    /// the state it last saw -- exactly as remote admission would store it.
    fn admit_remote(&self, rel_path: &str, mtime: i64) {
        let parents: Vec<yadorilink_replica_domain::ids::DeltaHash> = self
            .state
            .replica_coordinator
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let mut stmt = conn
                    .prepare("SELECT DISTINCT provenance FROM native_heads WHERE group_id = ?1")?;
                let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0))?;
                Ok(rows
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .map(|bytes| {
                        yadorilink_replica_domain::ids::DeltaHash(bytes.try_into().unwrap())
                    })
                    .collect())
            })
            .unwrap();
        self.admit_remote_on(rel_path, mtime, parents);
    }

    /// Admits a zero-length peer version of `rel_path` whose author had
    /// seen exactly `parents`, so a test can build a peer history that did
    /// not see some local change. The put supersedes the heads of
    /// `rel_path` among `parents` (the ones the peer saw) and is concurrent
    /// with the rest. Its display rank is one above its author's previous
    /// change and what it supersedes, so a peer chain of its own is what
    /// lifts it above a local edit. Returns the admitted change.
    fn admit_remote_on(
        &self,
        rel_path: &str,
        mtime: i64,
        parents: Vec<yadorilink_replica_domain::ids::DeltaHash>,
    ) -> yadorilink_replica_domain::ids::DeltaHash {
        let seen: Vec<_> = self
            .live_heads(rel_path)
            .into_iter()
            .map(|head| head.payload.provenance)
            .filter(|head| parents.contains(head))
            .collect();
        let version = FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let delta = crate::test_support::remote_admission_fixture::admit_remote(
            &self.state.replica_coordinator,
            GROUP,
            "device-peer",
            vec![crate::test_support::remote_admission_fixture::put(
                rel_path,
                version.version_hash,
                seen,
            )],
            std::slice::from_ref(&version),
        );
        yadorilink_replica_domain::ids::DeltaHash(delta.delta_hash().0)
    }

    /// Drives the projection scheduler until `done` holds, or gives up
    /// after a bounded number of ticks. A tick can legitimately defer a
    /// path (the running link's own capture holds the same path lock for a
    /// moment), so a fixed tick count would make these tests timing-bound.
    async fn drive_projection_until(&self, done: impl Fn(&Self) -> bool) -> bool {
        let engine = crate::convergence::engine::ConvergenceEngine::new(self.state.clone());
        for _ in 0..50 {
            // The scheduler's fork: this device moves its own losing heads, and
            // the peer (a simulated device) moves its own.
            self.state.fork_contested_heads(GROUP);
            crate::test_support::remote_admission_fixture::admit_remote_forks(
                &self.state.replica_coordinator,
                GROUP,
                "device-peer",
            );
            crate::convergence::engine::drive_obligations_once_for_test(&engine, 128, 256).await;
            if done(self) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    /// The contents of every file in `dir` whose name starts with `stem`
    /// (a file and its conflict copies), sorted.
    fn contents_named(&self, dir: &str, stem: &str) -> Vec<Vec<u8>> {
        let mut contents: Vec<Vec<u8>> = std::fs::read_dir(self.root.join(dir))
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(stem))
            .map(|entry| std::fs::read(entry.path()).unwrap())
            .collect();
        contents.sort();
        contents
    }

    fn read(&self, rel_path: &str) -> Option<Vec<u8>> {
        std::fs::read(self.root.join(rel_path)).ok()
    }
}

/// Pausing a folder holds a local write inside it: the write is not turned
/// into a change, so nothing exists for any peer to be served. A write
/// outside the paused folder is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_write_to_a_paused_item_is_not_authored_for_peers() {
    let f = fixture().await;
    f.write_locally("dir/shared.txt", b"base").await;
    assert_eq!(f.versions("dir/shared.txt"), 1, "sanity: the base version is authored");

    let paused = f.context_action("dir", ContextAction::PauseItem).await;
    assert!(paused.ok, "pausing a linked folder item must succeed: {}", paused.error);

    f.write_locally("dir/shared.txt", b"edited while paused").await;
    f.write_locally("outside.txt", b"not paused").await;

    assert_eq!(
        f.versions("dir/shared.txt"),
        1,
        "a local write to a paused item must not be authored as a change a peer could receive"
    );
    assert_eq!(f.versions("outside.txt"), 1, "a write outside the paused item still syncs");
}

/// Pausing a folder holds remote changes to it: admitted and stored, but
/// not written to the local folder. A remote change outside it projects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_change_to_a_paused_item_is_not_projected_to_disk() {
    let f = fixture().await;
    let paused = f.context_action("dir", ContextAction::PauseItem).await;
    assert!(paused.ok, "pausing a linked folder item must succeed: {}", paused.error);

    f.admit_remote("dir/incoming.txt", 1_700_000_000);
    f.admit_remote("outside.txt", 1_700_000_001);

    assert!(
        f.drive_projection_until(|f| f.read("outside.txt").is_some()).await,
        "a remote change outside the paused item projects"
    );
    assert_eq!(
        f.head_authors("dir/incoming.txt"),
        vec!["device-peer".to_string()],
        "admission continues while paused"
    );
    assert!(
        f.read("dir/incoming.txt").is_none(),
        "a remote change to a paused item must not be written to the local folder"
    );
}

/// The projection scheduler is not the only way into a projection pass
/// (the hazard recheck reconciles held paths directly, and a path can be
/// claimed just before a pause lands). The pass itself leaves a paused path
/// unwritten and its obligation outstanding, while the same route still
/// projects an unpaused path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_projection_pass_leaves_a_paused_item_unwritten_and_outstanding() {
    let f = fixture().await;
    let paused = f.context_action("dir", ContextAction::PauseItem).await;
    assert!(paused.ok, "pausing a linked folder item must succeed: {}", paused.error);
    f.admit_remote("dir/held.txt", 1_700_000_000);
    f.admit_remote("outside.txt", 1_700_000_001);

    f.state
        .local_convergence()
        .reconcile_paths(
            GROUP,
            ["dir/held.txt".to_string(), "outside.txt".to_string()].into_iter().collect(),
        )
        .await
        .unwrap();

    assert!(f.read("outside.txt").is_some(), "sanity: this route projects an unpaused path");
    assert!(f.read("dir/held.txt").is_none(), "a paused path must not be written");
    assert!(
        f.state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(GROUP, "dir/held.txt")
            .unwrap()
            .is_some_and(|o| o.state == "pending"),
        "the paused path's obligation must stay outstanding for resume"
    );
}

/// Resume catches up everything held on both sides: a new local file and a
/// local edit are authored, a remote file is projected, and the file that
/// changed on both sides while paused keeps both contents (one at its name,
/// one as a conflict copy) rather than one silently replacing the other --
/// whichever side's edit wins the winner order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resuming_a_paused_item_catches_up_every_held_change() {
    let f = fixture().await;
    f.write_locally("dir/shared.txt", b"base").await;
    let paused = f.context_action("dir", ContextAction::PauseItem).await;
    assert!(paused.ok, "pausing a linked folder item must succeed: {}", paused.error);
    f.write_locally("dir/shared.txt", b"local edit").await;
    f.write_locally("dir/new-local.txt", b"created while paused").await;
    // The peer edits the file independently of the paused local edit, and
    // adds a file of its own.
    f.admit_remote("dir/incoming.txt", 1_700_000_001);
    f.admit_remote("dir/shared.txt", 1_700_000_000);
    f.admit_remote("outside.txt", 1_700_000_002);
    assert!(
        f.drive_projection_until(|f| f.read("outside.txt").is_some()).await,
        "sanity: the scheduler ran and projected what is not paused"
    );

    // Held, not lost: nothing local authored, nothing remote projected.
    assert_eq!(f.versions("dir/new-local.txt"), 0, "held while paused");
    assert!(f.read("dir/incoming.txt").is_none(), "held while paused");
    assert_eq!(f.read("dir/shared.txt").as_deref(), Some(&b"local edit"[..]));

    let resumed = f.context_action("dir", ContextAction::ResumeItem).await;
    assert!(resumed.ok, "resuming a paused item must succeed: {}", resumed.error);

    assert_eq!(f.versions("dir/new-local.txt"), 1, "a file created while paused is authored");
    // The edit was authored beside the remote one (never on top of a change its
    // author did not see); the loser's author may already have moved its head to
    // its copy path, so look at the path and its copies.
    let mut authors: Vec<String> = f
        .live_heads_named("dir", "shared")
        .into_iter()
        .map(|head| head.dot.author.device.0.clone())
        .collect();
    authors.sort();
    assert_eq!(
        authors,
        vec!["device-local".to_string(), "device-peer".to_string()],
        "the local edit made while paused is authored concurrent with the remote edit, not on \
         top of a change its author never saw"
    );

    // Where the platform offers no durable namespace changes, the remote
    // winner cannot replace the local original, so only the projection of the
    // remote file is awaited there.
    let replaces = crate::test_support::windows_durability_gate_allows_tests(
        "the remote winner replacing the local original",
    );
    let both_sides = vec![Vec::new(), b"local edit".to_vec()];
    assert!(
        f.drive_projection_until(|f| {
            f.read("dir/incoming.txt").is_some()
                && (!replaces || f.contents_named("dir", "shared") == both_sides)
        })
        .await,
        "after resume the remote file must be projected and a file changed on both sides while \
         paused must keep both contents; incoming: {:?}, shared: {:?}",
        f.read("dir/incoming.txt"),
        f.contents_named("dir", "shared")
    );
}

/// A local edit and a remote edit of the same file, made concurrently from
/// the same base, both survive on this device whichever of them wins the
/// tie-break: the winner at the file's name, the loser as a conflict copy.
/// This is what a pause turns into the ordinary case (every file edited on
/// both sides while paused resolves this way on resume), but nothing here is
/// paused: `local_wins` decides only which side's version hash is the larger.
/// The modification time that gives the peer's empty file a version hash above
/// (`wins`) or below the given local version, so a test can choose which side
/// keeps the file's name.
fn peer_mtime_for(local: yadorilink_replica_domain::ids::VersionHash, wins: bool) -> i64 {
    (1_700_000_000i64..)
        .find(|mtime| {
            let version = FileVersion::new(
                vec![],
                0,
                FileMeta {
                    mtime_unix_nanos: *mtime,
                    unix_mode: None,
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: Vec::new(),
                },
            );
            (version.version_hash > local) == wins
        })
        .unwrap()
}

async fn concurrent_local_and_remote_edits_both_survive(local_wins: bool) {
    let f = fixture().await;
    f.write_locally("dir/shared.txt", b"base").await;
    let base = f.live_heads("dir/shared.txt");
    assert_eq!(base.len(), 1, "sanity: one base head");
    let base = &base[0];

    f.write_locally("dir/shared.txt", b"local edit").await;
    let local = f.live_heads("dir/shared.txt");
    assert_eq!(local.len(), 1, "sanity: the local edit supersedes the base");

    // The peer edited the same base without seeing the local edit; its version is
    // chosen so that its hash is below or above the local one.
    let mtime = peer_mtime_for(local[0].payload.version, !local_wins);
    f.admit_remote_on("dir/shared.txt", mtime, vec![base.payload.provenance]);
    let heads = f.live_heads("dir/shared.txt");
    let winner = heads.iter().max_by_key(|head| head.payload.version.0).unwrap();
    assert_eq!(
        winner.dot.author.device.0 == "device-local",
        local_wins,
        "sanity: the intended side wins the winner order"
    );
    assert_eq!(
        f.head_authors("dir/shared.txt"),
        vec!["device-local".to_string(), "device-peer".to_string()],
        "sanity: the two edits are concurrent heads"
    );

    // A remote winner replacing the local original needs durable namespace
    // changes; the sanity checks above still hold without them.
    if !local_wins
        && !crate::test_support::windows_durability_gate_allows_tests(
            "the remote winner replacing the local original",
        )
    {
        return;
    }
    let both_sides = vec![Vec::new(), b"local edit".to_vec()];
    assert!(
        f.drive_projection_until(|f| f.contents_named("dir", "shared") == both_sides).await,
        "a file edited on both sides must keep both contents on this device (local wins: {}); \
         shared: {:?}",
        local_wins,
        f.contents_named("dir", "shared")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_remote_edit_that_loses_to_a_concurrent_local_edit_is_kept_as_a_conflict_copy() {
    concurrent_local_and_remote_edits_both_survive(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_edit_that_loses_to_a_concurrent_remote_edit_is_kept_as_a_conflict_copy() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    concurrent_local_and_remote_edits_both_survive(false).await;
}

/// Pause and resume name a path the user can see; one outside every linked
/// folder is refused rather than recorded and ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pausing_a_path_outside_every_linked_folder_is_refused() {
    let f = fixture().await;
    let outside = tempfile::tempdir().unwrap();
    let response = handle_message(
        &f.context,
        ShellIpcMessage {
            payload: Some(Payload::ContextActionRequest(ContextActionRequest {
                path: outside.path().join("x.txt").to_string_lossy().into_owned(),
                action: ContextAction::PauseItem as i32,
            })),
        },
    )
    .await
    .unwrap();
    let Some(Payload::ContextActionResponse(r)) = response.payload else {
        panic!("expected a ContextActionResponse");
    };
    assert!(!r.ok, "a path outside every linked folder cannot be paused");
}
