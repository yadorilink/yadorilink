//! A path held for reconciliation belongs to no row this device placed: the
//! object on disk there is an edit native cannot author (its own bucket at the
//! path is full), so nothing may author it, delete it, or overwrite it until
//! the reconciliation pass has looked at it. These tests drive that pass
//! through every window a crash or a concurrent user write can open around it,
//! and check the copy name an entry takes when a directory holds its name.

use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::held_path_reconcile::{
    set_reconcile_step_hook_for_test, ReconcileStepForTest,
};
use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_capture::{LocalChangeOutcome, LocalChangeProcessor};
use yadorilink_local_storage::{chunk_file, SegmentBlockStore};
use yadorilink_replica_domain::admission::LocalAuthorKey;
use yadorilink_replica_domain::file::BlockInfo;

use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_root_authority::root_identity::VerifiedRoot;

const GROUP: &str = "group-1";

const CURRENT: &[u8] = b"the version the index holds at the path\n";
const EDIT: &[u8] = b"an edit this device's full own bucket at the path refuses\n";

struct Fixture {
    state: Arc<ReplicaCoordinator>,
    store: Arc<SegmentBlockStore>,
    processor: LocalChangeProcessor,
    root: std::path::PathBuf,
    _root_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let root_dir = tempfile::tempdir().unwrap();
        let root = root_dir.path().canonicalize().unwrap();
        let _ = state.link_repository().add_link(&root.to_string_lossy(), GROUP);
        VerifiedRoot::open(&root, GROUP, state.as_ref()).unwrap();
        state
            .link_repository()
            .set_capture_volume_identity_for_group(
                GROUP,
                &yadorilink_filesystem_sync::device_boundary::root_volume_identity(&root).unwrap(),
            )
            .unwrap();
        // The processor signs what it captures, so every row it indexes names
        // the native head it was authored as.
        let processor = LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "device-a".to_string(),
            Arc::new(RootLease::for_tests()),
        )
        .with_change_emitter(Arc::new(LocalAuthorKey::for_tests(
            "device-a",
            ed25519_dalek::SigningKey::from_bytes(&[21u8; 32]),
        )));
        Self { state, store, processor, root, _root_dir: root_dir, _store_dir: store_dir }
    }

    /// The block list `content` chunks to, with its blocks in the store.
    fn blocks(&self, content: &[u8]) -> Vec<BlockInfo> {
        let scratch = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(scratch.path(), content).unwrap();
        chunk_file(self.store.as_ref(), scratch.path()).unwrap()
    }

    /// `path` as this device has it: `content` on disk, captured into the
    /// index, and `Present`.
    async fn hydrated(&self, path: &str, content: &[u8]) {
        std::fs::write(self.root.join(path), content).unwrap();
        self.event(path).await;
        self.state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP,
                path,
                MaterializationState::Present,
                &RootCommitPermit::for_tests(),
            )
            .unwrap();
        let row = self.state.file_index_repository().get_file(GROUP, path).unwrap().unwrap();
        assert_eq!(row.size, content.len() as u64, "the fixture's own capture must index {path}");
    }

    async fn event(&self, path: &str) -> LocalChangeOutcome {
        self.processor
            .process_event(
                GROUP,
                &self.root,
                &FsChangeEvent {
                    path: self.root.join(path),
                    kind: FsChangeKind::CreatedOrModified,
                },
            )
            .await
            .unwrap()
    }

    /// Holds `path` for a local edit this replica cannot author there.
    fn hold(&self, path: &str) {
        self.state.held_path_repository().hold_unauthorable_local_edit(GROUP, path).unwrap();
    }

    /// One startup repair pass, which reconciles every held path first.
    fn repair(&self) {
        yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
            self.state.as_ref(),
            self.store.as_ref(),
            &self.root,
            GROUP,
            yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    }

    /// Every entry directly under the root other than the root marker.
    fn disk_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }

    /// Every file directly under the root other than `path` and the root
    /// marker, with its bytes.
    fn preserved_besides(&self, path: &str) -> Vec<Vec<u8>> {
        self.disk_entries()
            .into_iter()
            .filter(|name| name != path)
            .map(|name| std::fs::read(self.root.join(&name)).unwrap())
            .collect()
    }

    /// Whether `path` is a `Remote` row's: no object stands in the user tree.
    fn is_remote_with_no_object(&self, path: &str) -> bool {
        std::fs::symlink_metadata(self.root.join(path)).is_err()
            && self
                .state
                .materialization_state_repository()
                .get_materialization_state(GROUP, path)
                .unwrap()
                == Some(yadorilink_replica_domain::session_state::MaterializationState::Remote)
    }

    fn holds(&self) -> Vec<String> {
        self.state.held_path_repository().held_paths(GROUP).unwrap()
    }

    fn indexed_blocks(&self, path: &str) -> Option<Vec<BlockInfo>> {
        self.state
            .file_index_repository()
            .get_file(GROUP, path)
            .unwrap()
            .filter(|row| !row.deleted)
            .map(|row| row.blocks)
    }
}

/// Saves `content` at `path` the way an editor does: written beside it and
/// renamed over it, so the path gets a new object rather than new bytes.
fn save_atomically(path: &std::path::Path, content: &[u8]) {
    let saved = path.with_file_name("editor-save.swp");
    std::fs::write(&saved, content).unwrap();
    std::fs::rename(&saved, path).unwrap();
}

/// A local edit this device cannot author at its path is held with no prior
/// placement. The reconciliation preserves the edit under a conflict-copy
/// name, which the scan captures as a new file, and puts the path's current
/// version back: nothing is superseded unseen and nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unauthorable_local_edit_is_preserved_and_the_path_restored() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    std::fs::write(fx.root.join("doc.txt"), EDIT).unwrap();

    fx.hold("doc.txt");
    fx.repair();

    // No object: the row is `Remote`, and the released path's projection
    // obligation brings its content as policy says.
    assert!(fx.is_remote_with_no_object("doc.txt"), "the path's current version is back");
    assert!(fx.holds().is_empty(), "the hold is released");
    let entries = fx.disk_entries();
    let preserved = fx.preserved_besides("doc.txt");
    assert_eq!(
        preserved,
        vec![EDIT.to_vec()],
        "the edit was not preserved exactly once: {entries:?}"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// While the path is held, the bytes on disk are not an edit anyone may
/// author: a watcher event for them captures nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_paths_bytes_are_not_captured() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    std::fs::write(fx.root.join("doc.txt"), EDIT).unwrap();
    fx.hold("doc.txt");

    assert_eq!(fx.event("doc.txt").await, LocalChangeOutcome::None);
    let minted = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(
        minted.iter().all(|record| record.path != "doc.txt"),
        "the scan captured a held path: {minted:?}"
    );
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// A crash after reconciliation emptied the path (moved the edit aside) but
/// before it released the hold: the next pass finds nothing there and
/// releases it, and the empty path was never read as a deletion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_path_was_emptied_is_finished_by_the_next_pass() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();

    let before_repair = fx.processor.scan_existing_files(GROUP, &fx.root).unwrap();
    assert!(before_repair.is_empty(), "an emptied held path was tombstoned: {before_repair:?}");

    fx.repair();

    assert!(fx.is_remote_with_no_object("doc.txt"));
    assert!(fx.disk_entries().is_empty(), "nothing is placed: {:?}", fx.disk_entries());
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// Once reconciled, the path is an ordinary one again: an edit made after
/// that is captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_after_reconciliation_is_captured() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    fx.repair();

    let edit: &[u8] = b"an edit made after the path was reconciled\n";
    std::fs::write(fx.root.join("doc.txt"), edit).unwrap();

    match fx.event("doc.txt").await {
        LocalChangeOutcome::FileChanged(record) => assert_eq!(record.blocks, fx.blocks(edit)),
        other => panic!("an edit of the reconciled path was not captured: {other:?}"),
    }
}

/// Reconciliation found an edit and is about to move it aside -- and the user
/// saves over the path first. Whatever is at the path by the time it acts is
/// the user's save, and it is preserved, not discarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_landing_after_the_edit_was_classified_is_preserved() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    std::fs::write(fx.root.join("doc.txt"), EDIT).unwrap();
    fx.hold("doc.txt");
    let save: &[u8] = b"a save made while reconciliation was hashing the edit\n";
    let mut saved = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step == ReconcileStepForTest::Classified && !saved {
            saved = true;
            save_atomically(path, save);
        }
    });

    fx.repair();

    assert_eq!(
        fx.preserved_besides("doc.txt"),
        vec![save.to_vec()],
        "the save was not preserved exactly once"
    );
    assert!(fx.is_remote_with_no_object("doc.txt"));
    assert_eq!(fx.indexed_blocks("doc.txt"), Some(fx.blocks(CURRENT)));
}

/// The path was found empty, so reconciliation is about to release its hold
/// -- and the user creates a file at the path first. Releasing must not leave
/// that file unexamined: the hold stays, and the next pass preserves it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_created_before_the_hold_is_released_is_preserved_not_adopted() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    let created: &[u8] = b"a file the user created at the emptied path\n";
    let mut wrote = false;
    let _hook = set_reconcile_step_hook_for_test(move |step, path| {
        if step == ReconcileStepForTest::ReleasingEntry && !wrote {
            wrote = true;
            save_atomically(path, created);
        }
    });

    fx.repair();
    fx.repair();

    assert_eq!(
        fx.preserved_besides("doc.txt"),
        vec![created.to_vec()],
        "the created file was not preserved exactly once"
    );
    assert!(fx.is_remote_with_no_object("doc.txt"));
    assert!(fx.holds().is_empty(), "the path is still held after a pass found it empty again");
}

/// A crash after reconciliation took the object at a held path aside to
/// examine it, but before it settled it: the next pass settles the taken
/// object first. A user's save taken that way is preserved, not discarded
/// with the reserved name it was left under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_object_was_taken_aside_preserves_a_save_it_took() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    let save: &[u8] = b"a save the crashed pass had taken aside\n";
    let taken = yadorilink_filesystem_sync::held_path_reconcile::taken_object_path_for_test(
        &fx.root, "doc.txt",
    );
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    std::fs::write(&taken, save).unwrap();

    fx.repair();

    assert!(!taken.exists(), "the taken object was left under its reserved name");
    assert_eq!(
        fx.preserved_besides("doc.txt"),
        vec![save.to_vec()],
        "the taken save was not preserved exactly once"
    );
    assert!(fx.is_remote_with_no_object("doc.txt"));
}

/// A symlink planted at the reserved name a held path's object is taken to
/// is moved aside like any other object: never followed (the outside file it
/// points at is untouched) and never replaced.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_symlink_planted_at_the_taken_name_is_preserved_and_never_followed() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    std::fs::write(&victim, b"outside the root").unwrap();
    let taken = yadorilink_filesystem_sync::held_path_reconcile::taken_object_path_for_test(
        &fx.root, "doc.txt",
    );
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    std::os::unix::fs::symlink(&victim, &taken).unwrap();

    fx.repair();

    assert_eq!(std::fs::read(&victim).unwrap(), b"outside the root");
    assert!(std::fs::symlink_metadata(&taken).is_err(), "the reserved name was left occupied");
    let kept = fx.disk_entries().iter().any(|name| {
        std::fs::read_link(fx.root.join(name)).map(|target| target == victim).unwrap_or(false)
    });
    assert!(kept, "the planted symlink was not preserved as a conflict copy");
}

/// A directory with content planted at the taken name is moved aside whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_planted_at_the_taken_name_is_preserved_with_its_content() {
    let fx = Fixture::new();
    fx.hydrated("doc.txt", CURRENT).await;
    fx.hold("doc.txt");
    let taken = yadorilink_filesystem_sync::held_path_reconcile::taken_object_path_for_test(
        &fx.root, "doc.txt",
    );
    std::fs::remove_file(fx.root.join("doc.txt")).unwrap();
    std::fs::create_dir(&taken).unwrap();
    std::fs::write(taken.join("inner"), b"planted inner file").unwrap();

    fx.repair();

    assert!(std::fs::symlink_metadata(&taken).is_err(), "the reserved name was left occupied");
    let kept = fx.disk_entries().iter().any(|name| {
        std::fs::read(fx.root.join(name).join("inner")).ok().as_deref()
            == Some(b"planted inner file")
    });
    assert!(kept, "the planted directory or its content was lost");
}

/// A directory the user made holds the name a held entry needs. The
/// directory is kept with everything in it, the entry waits and its path stays
/// held: nothing is moved to a copy name, and the obstacle is the user's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_entry_over_a_users_directory_waits_and_nothing_moves() {
    let fx = Fixture::new();
    fx.hydrated("a", CURRENT).await;
    fx.hold("a");
    std::fs::remove_file(fx.root.join("a")).unwrap();
    std::fs::create_dir(fx.root.join("a")).unwrap();
    std::fs::write(fx.root.join("a/mine"), b"the user's own").unwrap();

    fx.repair();
    fx.repair();

    assert_eq!(std::fs::read(fx.root.join("a/mine")).unwrap(), b"the user's own");
    assert_eq!(
        fx.indexed_blocks("a"),
        Some(fx.blocks(CURRENT)),
        "the entry's row is untouched: nothing is moved to a copy name"
    );
    assert_eq!(fx.holds(), vec!["a".to_string()], "the entry waits, held");
    assert_eq!(fx.disk_entries(), vec!["a".to_string()], "no copy name appeared on disk");
}
