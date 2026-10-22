#![cfg(all(test, unix))]

//! A pairwise (orthogonal-array L8) matrix over four capture-boundary factors, so a bug that only
//! shows when an unreadable file meets a resume, an unindexed source or a concurrent peer write
//! is found without running all sixteen combinations:
//!
//! * A, the local source: an indexed file edited after its base was captured (0) or a file
//!   created before it was ever indexed (1).
//! * B, the capture entry: a warm full rescan (0) or a resume after a safe-stop pause with the
//!   debounced edit pending in the dirty journal (1).
//! * C, the filesystem read: readable throughout (0) or refused (EACCES) during the first capture
//!   and healed before the final settling (1).
//! * D, the peer: no concurrent remote version (0) or another device authored different bytes at
//!   the same path before the local capture settled (1).
//!
//! Row k sets D = A xor B xor C, so every pair of factor levels meets in exactly two rows. Every
//! row asserts the same invariants: the unreadable bytes are never replaced, nothing is deleted or
//! recorded empty because a read failed, the healthy sentinel converges, the journal settles by
//! itself after healing, local and peer content are both retained, and a repeated rescan authors
//! nothing. A failure names the row and its factor tuple.
//!
//! The fault is a real mode-000 file (skipped when the user can read it anyway, as root), the
//! pause is the real root lease, the peer is a signed remote put admitted into the native state,
//! and the index is file-backed; nothing sleeps.

use super::*;
use crate::test_support::TestReplica;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::sync::Arc;
use yadorilink_daemon::test_support::remote_admission_fixture as peer;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::admission::LocalAuthorKey;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::local_op::Op;

const GROUP: &str = "pairwise-group";
const TARGET: &str = "target.txt";
const SENTINEL: &str = "healthy.txt";
const BASE: &[u8] = b"base bytes captured earlier";
const LOCAL: &[u8] = b"the local bytes the user wrote";
const SENTINEL_BYTES: &[u8] = b"healthy sentinel";
/// The peer's version: one block this device's store never holds, so it is told apart by its hash.
const PEER_SIZE: u32 = 4242;
const PEER_BLOCK: [u8; 32] = [7; 32];

/// One row of the array: the levels of A, B, C and D.
#[derive(Clone, Copy, Debug)]
struct Row {
    id: u8,
    a: bool,
    b: bool,
    c: bool,
    d: bool,
}

/// Rows 1-8 are the array; row 9 is the one out-of-array anchor: the all-adverse source, entry and
/// fault without a competing peer, isolating the failure and resume from the conflict.
const ROWS: [Row; 9] = [
    Row { id: 1, a: false, b: false, c: false, d: false },
    Row { id: 2, a: false, b: false, c: true, d: true },
    Row { id: 3, a: false, b: true, c: false, d: true },
    Row { id: 4, a: false, b: true, c: true, d: false },
    Row { id: 5, a: true, b: false, c: false, d: true },
    Row { id: 6, a: true, b: false, c: true, d: false },
    Row { id: 7, a: true, b: true, c: false, d: false },
    Row { id: 8, a: true, b: true, c: true, d: true },
    Row { id: 9, a: true, b: true, c: true, d: false },
];

struct Fixture {
    row: Row,
    proc: LocalChangeProcessor,
    state: Arc<TestReplica>,
    store: Arc<SegmentBlockStore>,
    lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
    root: PathBuf,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _root_dir: tempfile::TempDir,
}

impl Fixture {
    fn new(row: Row) -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let index_dir = tempfile::tempdir().unwrap();
        let state = Arc::new(TestReplica::open_file_backed(index_dir.path()).unwrap());
        state.set_local_change_auth_provider(Arc::new(|_group_id| Ok(())));
        let lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
        let proc = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".into(),
            lease.clone(),
        )
        .with_change_emitter(Arc::new(LocalAuthorKey::for_tests(
            "device-a",
            ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]),
        )));
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        // Adopt the root while the index is empty, as a first link does, and pin its volume.
        let _ = state.link_repository().add_link(&root.to_string_lossy(), GROUP);
        yadorilink_root_authority::root_identity::VerifiedRoot::open(
            &root,
            GROUP,
            state.coordinator(),
        )
        .unwrap();
        state
            .link_repository()
            .set_capture_volume_identity_for_group(
                GROUP,
                &yadorilink_filesystem_sync::device_boundary::root_volume_identity(&root).unwrap(),
            )
            .unwrap();
        Self {
            row,
            proc,
            state,
            store,
            lease,
            root,
            _store_dir: store_dir,
            _index_dir: index_dir,
            _root_dir: root_dir,
        }
    }

    /// Names the row and its factors in every failure, with the shortest reproduction.
    fn ctx(&self, what: &str) -> String {
        let Row { id, a, b, c, d } = self.row;
        format!(
            "row {id:02} (A={} B={} C={} D={}): {what}. Reproduce: run the \
             `pairwise_matrix_tests` test for row {id:02}: it is one sequential test with no timing",
            a as u8, b as u8, c as u8, d as u8
        )
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn set_mode(&self, rel: &str, mode: u32) {
        std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    async fn rescan(&self) -> Result<FlushOutcome, LocalCaptureError> {
        self.proc.process_flush(GROUP, &self.root, DebounceFlush::RescanRequired).await
    }

    fn pending_edit(&self) -> DebounceFlush {
        DebounceFlush::Paths(vec![
            (self.path(TARGET), FsChangeKind::CreatedOrModified, 0),
            (self.path(SENTINEL), FsChangeKind::CreatedOrModified, 0),
        ])
    }

    fn dirty(&self) -> Vec<String> {
        self.state
            .dirty_path_repository()
            .list_dirty_paths(GROUP)
            .unwrap()
            .into_iter()
            .map(|d| d.path)
            .collect()
    }

    fn indexed(&self, rel: &str) -> Option<FileRecord> {
        self.state.file_index_repository().get_file(GROUP, rel).unwrap()
    }

    /// The bytes of the stored version `hash`.
    fn version_bytes(&self, version: &yadorilink_replica_domain::ids::VersionHash) -> Vec<u8> {
        use yadorilink_local_storage::BlockStore as _;
        let version = self
            .state
            .database()
            .read(|conn| yadorilink_sync_sqlite::dag_store::get_file_version(conn, GROUP, version))
            .unwrap()
            .expect("an authored version is stored");
        if version.blocks.iter().any(|b| b.hash.0 == PEER_BLOCK) {
            return b"<peer version>".to_vec();
        }
        let mut bytes = Vec::new();
        for block in &version.blocks {
            bytes.extend(self.store.get(&hex::encode(&block.hash.0)).unwrap());
        }
        assert_eq!(bytes.len() as u64, version.size, "{}", self.ctx("a stored size"));
        bytes
    }

    /// Every put and delete the native history holds at `rel`, as (bytes, deleted).
    fn history(&self, rel: &str) -> Vec<(Vec<u8>, bool)> {
        let mut out = Vec::new();
        for delta in crate::test_support::native_deltas(&self.state, GROUP) {
            for op in delta.ops.iter().filter(|op| op.path.0 == rel) {
                match &op.put {
                    Some(put) => out.push((self.version_bytes(&put.version), false)),
                    None => out.push((Vec::new(), true)),
                }
            }
        }
        out
    }

    /// The content of every live head at `rel`.
    fn live_heads(&self, rel: &str) -> Vec<Vec<u8>> {
        let provenances =
            crate::test_support::native_path_head_provenances(&self.state, GROUP, rel);
        let deltas = crate::test_support::native_deltas(&self.state, GROUP);
        provenances
            .iter()
            .filter_map(|p| deltas.iter().find(|d| d.delta_hash().0 == *p))
            .filter_map(|d| d.ops.iter().find(|op| op.path.0 == rel))
            .filter_map(|op| op.put.as_ref())
            .map(|put| self.version_bytes(&put.version))
            .collect()
    }

    /// Admits a peer's put of different bytes at `rel`: concurrent with whatever this device
    /// holds, the way a remote write arrives before reconciliation has projected it.
    fn peer_writes(&self, rel: &str, basis: peer::Basis) {
        let version = FileVersion::new(
            vec![VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(PEER_BLOCK.to_vec()),
                size: PEER_SIZE,
            }],
            u64::from(PEER_SIZE),
            FileMeta {
                mtime_unix_nanos: 1,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        self.state
            .database()
            .write(|conn| {
                yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &version)
            })
            .unwrap();
        peer::admit_remote_ops(
            &self.state,
            GROUP,
            "device-b",
            &[Op::Put { path: SyncPath(rel.to_owned()), version: version.version_hash }],
            basis,
        );
    }

    /// The identity of everything authored so far: every delta, and the live heads.
    fn authored(&self) -> (usize, Vec<yadorilink_replica_domain::ids::DeltaHash>, Vec<[u8; 32]>) {
        (
            crate::test_support::native_deltas(&self.state, GROUP).len(),
            crate::test_support::native_group_heads(&self.state, GROUP),
            crate::test_support::native_path_head_provenances(&self.state, GROUP, TARGET),
        )
    }
}

async fn run_row(row: Row) {
    let fx = Fixture::new(row);

    // Set up the local source (A) and the healthy sentinel.
    std::fs::write(fx.path(SENTINEL), SENTINEL_BYTES).unwrap();
    if !row.a {
        std::fs::write(fx.path(TARGET), BASE).unwrap();
        fx.rescan().await.unwrap();
        assert!(fx.indexed(TARGET).is_some(), "{}", fx.ctx("the base is captured"));
        // Edit after the base was captured; the sentinel waits for the entry under test.
        std::fs::write(fx.path(TARGET), LOCAL).unwrap();
    } else {
        std::fs::write(fx.path(TARGET), LOCAL).unwrap();
    }

    // The fault (C): the read is refused until it heals.
    if row.c {
        fx.set_mode(TARGET, 0o000);
        if std::fs::File::open(fx.path(TARGET)).is_ok() {
            eprintln!("skipped: permissions do not stop this user from reading the file");
            fx.set_mode(TARGET, 0o644);
            return;
        }
    }

    // The peer (D): different bytes at the same path before the local capture settles.
    if row.d {
        let basis = if row.a { peer::Basis::Nothing } else { peer::Basis::CurrentHeads };
        fx.peer_writes(TARGET, basis);
    }

    // The entry (B).
    if row.b {
        fx.lease.begin_quiesce();
        let _ = fx.proc.process_flush(GROUP, &fx.root, fx.pending_edit()).await;
        fx.lease.end_quiesce();
        fx.proc.redrive_dirty_journal(GROUP, &fx.root).await.unwrap();
    } else {
        fx.rescan().await.unwrap();
    }

    if row.c {
        // While the fault lasts: nothing is overwritten, deleted or recorded empty, the healthy
        // file has converged, and the edit is still owed (kept for the next pass).
        let history = fx.history(TARGET);
        assert!(
            history.iter().all(|(bytes, deleted)| !deleted && !bytes.is_empty()),
            "{}",
            fx.ctx("a failed read produced a tombstone or an empty version")
        );
        assert!(
            history.iter().all(|(bytes, _)| bytes != LOCAL),
            "{}",
            fx.ctx("unreadable bytes were recorded")
        );
        assert_eq!(
            fx.indexed(SENTINEL).map(|r| r.size),
            Some(SENTINEL_BYTES.len() as u64),
            "{}",
            fx.ctx("the healthy file did not converge while another path failed")
        );
        if row.b {
            assert!(
                fx.dirty().iter().any(|p| p == TARGET),
                "{}",
                fx.ctx("the edit that could not be read was dropped from the journal")
            );
        } else {
            assert!(
                fx.proc.unreadable_ledger().needing_user(GROUP).iter().any(|f| f.path == TARGET),
                "{}",
                fx.ctx("the rescan did not report the file it could not read")
            );
        }
        fx.set_mode(TARGET, 0o644);
        assert_eq!(
            std::fs::read(fx.path(TARGET)).unwrap(),
            LOCAL,
            "{}",
            fx.ctx("the unreadable local bytes were changed")
        );
        // Heal, then settle without any further user edit.
        if row.b {
            fx.proc.redrive_dirty_journal(GROUP, &fx.root).await.unwrap();
        } else {
            fx.rescan().await.unwrap();
        }
    }

    // Settled: the same invariants for every row.
    assert!(fx.dirty().is_empty(), "{}", fx.ctx(&format!("the journal kept {:?}", fx.dirty())));
    assert!(
        fx.proc.unreadable_ledger().needing_user(GROUP).is_empty(),
        "{}",
        fx.ctx("the unreadable report stayed after healing")
    );
    assert_eq!(
        std::fs::read(fx.path(TARGET)).unwrap(),
        LOCAL,
        "{}",
        fx.ctx("the local bytes were replaced")
    );
    for rel in [TARGET, SENTINEL] {
        assert!(
            fx.history(rel).iter().all(|(bytes, deleted)| !deleted && !bytes.is_empty()),
            "{}",
            fx.ctx(&format!("{rel} has a tombstone or an empty version"))
        );
    }
    assert_eq!(
        fx.indexed(SENTINEL).map(|r| r.size),
        Some(SENTINEL_BYTES.len() as u64),
        "{}",
        fx.ctx("the healthy sentinel did not converge")
    );
    let heads = fx.live_heads(TARGET);
    assert!(
        heads.iter().any(|bytes| bytes == LOCAL),
        "{}",
        fx.ctx(&format!("the local bytes are not a live head: {} heads", heads.len()))
    );
    if row.d {
        assert!(
            heads.iter().any(|bytes| bytes == b"<peer version>"),
            "{}",
            fx.ctx("the peer's version was dropped")
        );
    }

    // Repeating the rescan authors nothing for unchanged bytes.
    let settled = fx.authored();
    fx.rescan().await.unwrap();
    assert_eq!(fx.authored(), settled, "{}", fx.ctx("a repeated rescan authored new heads"));
}

macro_rules! rows {
    ($($name:ident => $index:expr),* $(,)?) => {$(
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            run_row(ROWS[$index]).await;
        }
    )*};
}

rows! {
    row_01_indexed_rescan_readable_no_peer => 0,
    row_02_indexed_rescan_unreadable_peer => 1,
    row_03_indexed_resume_readable_peer => 2,
    row_04_indexed_resume_unreadable_no_peer => 3,
    row_05_unindexed_rescan_readable_peer => 4,
    row_06_unindexed_rescan_unreadable_no_peer => 5,
    row_07_unindexed_resume_readable_no_peer => 6,
    row_08_unindexed_resume_unreadable_peer => 7,
    row_09_anchor_unindexed_resume_unreadable_no_peer => 8,
}
