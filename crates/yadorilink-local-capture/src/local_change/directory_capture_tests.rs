#![cfg(test)]

//! Capture of explicit directories: a directory a user made is a
//! replicated entry of its own, authored like a file; a directory this
//! device made only to hold replicated descendants (a structural one) is
//! never authored. Which of the two a directory is comes from the
//! structural-origin ledger, never from what is on disk.

use super::*;
use yadorilink_fs_platform::fs_identity::FileIdentity;

pub(super) const GROUP: &str = "group-1";

/// Every op this device authored at `path`, oldest first: `put-dir`,
/// `put-file`, `put-symlink` (by the kind of the version put) or `delete`.
pub(super) fn ops_at(state: &TestReplica, path: &str) -> Vec<String> {
    let mut out = Vec::new();
    for delta in crate::test_support::native_deltas(state, GROUP) {
        for op in delta.ops.iter().filter(|op| op.path.as_str() == path) {
            match &op.put {
                Some(put) => {
                    let kind = state
                        .sqlite()
                        .dag_get_file_version(GROUP, &put.version)
                        .unwrap()
                        .map(|v| v.meta.record_kind);
                    out.push(match kind {
                        Some(RecordKind::Directory) => "put-dir".to_string(),
                        Some(RecordKind::Symlink) => "put-symlink".to_string(),
                        Some(RecordKind::File) => "put-file".to_string(),
                        None => "put-unknown".to_string(),
                    });
                }
                None => out.push("delete".into()),
            }
        }
    }
    out
}

pub(super) fn live_kind(state: &TestReplica, path: &str) -> Option<RecordKind> {
    state
        .file_index_repository()
        .canonical_current_row(GROUP, path)
        .unwrap()
        .filter(|row| !row.snapshot.deleted)
        .map(|row| row.snapshot.record_kind)
}

pub(super) async fn event(
    proc: &LocalChangeProcessor,
    root: &Path,
    path: &Path,
    kind: FsChangeKind,
) {
    proc.process_event(GROUP, root, &FsChangeEvent { path: path.to_path_buf(), kind })
        .await
        .unwrap();
}

/// Records `rel` as a directory this device created only for
/// descendants, the way the materializer's mkdir helper does.
pub(super) fn record_structural(state: &TestReplica, root: &Path, rel: &str) -> FileIdentity {
    state.sqlite().dag_record_structural_intent(GROUP, rel, 1).unwrap();
    let identity = FileIdentity::observe_path(&root.join(rel)).unwrap();
    state.sqlite().dag_complete_structural_origin(GROUP, rel, &identity, 2).unwrap();
    identity
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mkdir_of_an_empty_directory_is_captured_as_an_explicit_directory_entry() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("empty")).unwrap();

    event(&proc, &root, &root.join("empty"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "empty"), ["put-dir"]);
    assert_eq!(live_kind(&state, "empty"), Some(RecordKind::Directory));

    // The same directory seen again is not a new version.
    event(&proc, &root, &root.join("empty"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "empty"), ["put-dir"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rmdir_of_an_explicit_directory_emits_delete() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("empty")).unwrap();
    event(&proc, &root, &root.join("empty"), FsChangeKind::CreatedOrModified).await;

    std::fs::remove_dir(root.join("empty")).unwrap();
    event(&proc, &root, &root.join("empty"), FsChangeKind::ObservedRemoval).await;

    assert_eq!(ops_at(&state, "empty"), ["put-dir", "delete"]);
    assert_eq!(live_kind(&state, "empty"), None);
}

#[test]
fn full_scan_captures_an_offline_created_empty_directory() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    std::fs::create_dir_all(root.join("offline/nested")).unwrap();

    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "offline"), ["put-dir"]);
    assert_eq!(ops_at(&state, "offline/nested"), ["put-dir"]);
    assert_eq!(live_kind(&state, "offline/nested"), Some(RecordKind::Directory));
}

#[test]
fn full_scan_does_not_tombstone_an_explicit_directory_still_on_disk() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    std::fs::create_dir(root.join("kept")).unwrap();
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert_eq!(ops_at(&state, "kept"), ["put-dir"]);

    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "kept"), ["put-dir"], "a rescan re-authored or deleted it");
    assert_eq!(live_kind(&state, "kept"), Some(RecordKind::Directory));
}

/// `mv d /elsewhere` reaches capture as one `Removed` for `d`. Every
/// entry this device observed below it goes, and so does `d` itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn moving_a_directory_with_an_explicit_entry_out_of_the_root_deletes_its_whole_observed_subtree(
) {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/sub")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"f").unwrap();
    for rel in ["d", "d/sub", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    assert_eq!(ops_at(&state, "d"), ["put-dir"]);

    let outside = tempfile::tempdir().unwrap();
    std::fs::rename(root.join("d"), outside.path().join("d")).unwrap();
    event(&proc, &root, &root.join("d"), FsChangeKind::ObservedRemoval).await;

    assert_eq!(ops_at(&state, "d"), ["put-dir", "delete"]);
    assert_eq!(ops_at(&state, "d/sub"), ["put-dir", "delete"]);
    assert_eq!(ops_at(&state, "d/f.txt"), ["put-file", "delete"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn materializer_created_parents_are_structural_but_a_user_mkdir_is_explicit() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("made-for-a-peer")).unwrap();
    record_structural(&state, &root, "made-for-a-peer");
    std::fs::create_dir(root.join("made-by-user")).unwrap();

    for rel in ["made-for-a-peer", "made-by-user"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "made-for-a-peer"), Vec::<String>::new());
    assert_eq!(live_kind(&state, "made-for-a-peer"), None);
    assert_eq!(ops_at(&state, "made-by-user"), ["put-dir"]);
}

/// A directory whose structural `mkdir` is still between its two phases
/// may be the one being created: nothing is authored for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_whose_structural_mkdir_is_in_flight_is_not_authored() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    state.sqlite().dag_record_structural_intent(GROUP, "pending", 1).unwrap();
    std::fs::create_dir(root.join("pending")).unwrap();

    event(&proc, &root, &root.join("pending"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "pending"), Vec::<String>::new());
}

/// D5: a `chmod` of a structural directory is the user operating on the
/// directory itself, which makes it explicit with the mode they gave it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chmod_of_a_structural_directory_promotes_it_to_an_explicit_directory_with_its_mode() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("s")).unwrap();
    std::fs::set_permissions(root.join("s"), std::fs::Permissions::from_mode(0o755)).unwrap();
    record_structural(&state, &root, "s");

    event(&proc, &root, &root.join("s"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "s"), Vec::<String>::new(), "untouched, it is still structural");

    std::fs::set_permissions(root.join("s"), std::fs::Permissions::from_mode(0o700)).unwrap();
    event(&proc, &root, &root.join("s"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "s"), ["put-dir"]);
    let row = state.file_index_repository().canonical_current_row(GROUP, "s").unwrap().unwrap();
    assert_eq!(row.snapshot.record_kind, RecordKind::Directory);
    assert_eq!(row.snapshot.unix_mode, Some(0o700));
}

/// A chmod of an explicit directory is a new version of it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chmod_of_an_explicit_directory_authors_its_new_mode() {
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("e")).unwrap();
    std::fs::set_permissions(root.join("e"), std::fs::Permissions::from_mode(0o755)).unwrap();
    event(&proc, &root, &root.join("e"), FsChangeKind::CreatedOrModified).await;

    std::fs::set_permissions(root.join("e"), std::fs::Permissions::from_mode(0o750)).unwrap();
    event(&proc, &root, &root.join("e"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "e"), ["put-dir", "put-dir"]);
    let row = state.file_index_repository().canonical_current_row(GROUP, "e").unwrap().unwrap();
    assert_eq!(row.snapshot.unix_mode, Some(0o750));
}

/// The ledger names a structural directory by identity. A different
/// directory at the recorded path is not that one: it was observed to
/// replace it, so it is a directory someone made, and explicit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_replacing_a_recorded_structural_one_is_captured_as_explicit() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("r")).unwrap();
    record_structural(&state, &root, "r");

    std::fs::remove_dir(root.join("r")).unwrap();
    // A sibling first, so the replacement cannot reuse the old inode.
    std::fs::create_dir(root.join("spacer")).unwrap();
    std::fs::create_dir(root.join("r")).unwrap();
    event(&proc, &root, &root.join("r"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "r"), ["put-dir"]);
}

/// A structural `mkdir` whose record was lost -- its intent dropped as
/// stale before it completed -- leaves a directory nobody can say the
/// origin of. It is kept and authored as nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_whose_structural_provenance_was_lost_is_kept_and_not_authored() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    state.sqlite().dag_record_structural_intent(GROUP, "lost", 1).unwrap();
    state.sqlite().dag_drop_unresolved_structural_intents().unwrap();
    std::fs::create_dir(root.join("lost")).unwrap();
    let identity = FileIdentity::observe_path(&root.join("lost")).unwrap();
    // The mkdir's own completion finds its intent gone.
    state.sqlite().dag_complete_structural_origin(GROUP, "lost", &identity, 2).unwrap();

    event(&proc, &root, &root.join("lost"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "lost"), Vec::<String>::new());
    assert!(root.join("lost").is_dir());
}

#[test]
fn a_directory_becoming_ignored_is_dropped_without_a_tombstone() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    std::fs::create_dir(root.join("build")).unwrap();
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert_eq!(ops_at(&state, "build"), ["put-dir"]);

    let ignore_set = EffectiveIgnoreSet::from_user_patterns("build/\n");
    proc.scan_existing_files_with_ignore(GROUP, &root, &ignore_set).unwrap();

    assert_eq!(ops_at(&state, "build"), ["put-dir"], "becoming ignored is not a deletion");
    assert!(state.file_index_repository().get_file(GROUP, "build").unwrap().is_none());
    assert!(root.join("build").is_dir());
}

/// A removed path cannot be stat'ed, so whether a directory-only pattern
/// (`build/`) covers it comes from the index row's kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dir_only_ignore_pattern_applies_on_rmdir_event() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("build")).unwrap();
    event(&proc, &root, &root.join("build"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "build"), ["put-dir"]);

    std::fs::remove_dir(root.join("build")).unwrap();
    let ignore_set = EffectiveIgnoreSet::from_user_patterns("build/\n");
    proc.process_event_with_ignore(
        GROUP,
        &root,
        &FsChangeEvent { path: root.join("build"), kind: FsChangeKind::ObservedRemoval },
        &ignore_set,
    )
    .await
    .unwrap();

    assert_eq!(ops_at(&state, "build"), ["put-dir"]);
}

/// Seeds a live row the way the materializer's write does before the
/// bytes are on disk: current, `Hydrating`, under an open intent.
pub(super) fn index_in_flight_remote_entry(state: &TestReplica, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.into(),
                size: 3,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xCD; 32],
                    offset: 0,
                    size: 3,
                }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP, path, MaterializationState::Hydrating, &permit)
        .unwrap();
    state
        .coordinator()
        .materialization_intent_repository()
        .begin_materialization_intent(GROUP, path, &[0xCD; 32], &permit)
        .unwrap();
}

/// `rm -rf a` deletes the entries this device had on disk under `a`. A
/// peer's entry indexed under it but not yet written here was never
/// observed by the user's delete, and survives it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rm_rf_does_not_delete_child_indexed_but_not_yet_materialized() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    // Seeded before this device authors anything: the index refuses an
    // unauthored row once the group has history.
    index_in_flight_remote_entry(&state, "a/new.txt");
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::write(root.join("a/x"), b"x").unwrap();
    for rel in ["a", "a/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::ObservedRemoval).await;

    assert_eq!(ops_at(&state, "a"), ["put-dir", "delete"]);
    assert_eq!(ops_at(&state, "a/x"), ["put-file", "delete"]);
    assert_eq!(ops_at(&state, "a/new.txt"), Vec::<String>::new());
    assert!(state
        .file_index_repository()
        .get_file(GROUP, "a/new.txt")
        .unwrap()
        .is_some_and(|r| !r.deleted));
}

/// The child's own `Removed` and its directory's arrive in one flush: each
/// entry is deleted once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_and_its_child_removed_in_one_flush_are_each_deleted_once() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::write(root.join("a/x"), b"x").unwrap();
    for rel in ["a", "a/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    proc.process_flush(
        GROUP,
        &root,
        yadorilink_filesystem_sync::debounce::DebounceFlush::Paths(vec![
            (root.join("a/x"), FsChangeKind::ObservedRemoval, 1),
            (root.join("a"), FsChangeKind::ObservedRemoval, 1),
        ]),
    )
    .await
    .unwrap();

    assert_eq!(ops_at(&state, "a"), ["put-dir", "delete"]);
    assert_eq!(ops_at(&state, "a/x"), ["put-file", "delete"]);
}

/// A folder relinked on the same device keeps its structural ledger, so a
/// directory it recorded as structural stays structural for the relinked
/// capture: it is not promoted to an explicit entry.
#[test]
fn a_recorded_structural_directory_stays_structural_for_a_relinked_scan() {
    let (_first, state, _emitter, store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    std::fs::create_dir(root.join("holder")).unwrap();
    std::fs::write(root.join("holder/f.txt"), b"f").unwrap();
    record_structural(&state, &root, "holder");

    let relinked = LocalChangeProcessor::new(
        state.clone(),
        Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap()),
        "device-a".into(),
        std::sync::Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    )
    .with_change_emitter(Arc::new(LocalAuthorKey::for_tests(
        "device-a",
        ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]),
    )));
    relinked.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "holder"), Vec::<String>::new());
    assert_eq!(ops_at(&state, "holder/f.txt"), ["put-file"]);
}

/// The backend gate: a link whose backend creates directories without
/// recording them as structural authors no directory at all -- by event
/// or by scan -- while a directory entry's deletion is still captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_without_directory_capture_authors_no_directory() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let proc = proc.without_directory_capture();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("made")).unwrap();
    std::fs::write(root.join("made/f.txt"), b"f").unwrap();

    event(&proc, &root, &root.join("made"), FsChangeKind::CreatedOrModified).await;
    event(&proc, &root, &root.join("made/f.txt"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "made"), Vec::<String>::new());
    assert_eq!(ops_at(&state, "made/f.txt"), ["put-file"]);

    std::fs::remove_dir_all(root.join("made")).unwrap();
    event(&proc, &root, &root.join("made"), FsChangeKind::ObservedRemoval).await;
    assert_eq!(ops_at(&state, "made/f.txt"), ["put-file", "delete"]);
}

/// A peer's directory version with no mode (authored where there is no
/// Unix mode model) says nothing about the mode, so the mode it gets here
/// is not a local `chmod` of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_whose_version_states_no_mode_is_not_recaptured_for_its_mode() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("from-a-peer")).unwrap();
    index_settled_directory(&state, GROUP, "from-a-peer");

    event(&proc, &root, &root.join("from-a-peer"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "from-a-peer"), Vec::<String>::new());
}

/// A retained record names the directory a delete aimed at by identity.
/// That directory is not authored back; a directory made at the path after
/// the user removed it is a different object -- someone's directory -- and
/// is explicit (D6: it inherits nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_made_where_a_retained_one_was_removed_is_captured_as_explicit() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("a")).unwrap();
    let retained = FileIdentity::observe_path(&root.join("a")).unwrap();
    state
        .sqlite()
        .record_retained_directory(
            GROUP,
            "a",
            yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT,
            Some(&retained),
            1,
        )
        .unwrap();

    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "a"), Vec::<String>::new(), "the retained directory itself");

    std::fs::remove_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::ObservedRemoval).await;
    // A sibling first, so the new directory cannot reuse the old inode.
    std::fs::create_dir(root.join("spacer")).unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "a"), ["put-dir"]);
}

/// Seeds a live row the way admission of a peer's entry leaves it before
/// `materialize()` ever runs: current, with an unsettled REMOTE-origin
/// projection obligation, and no materialization intent.
fn index_admitted_remote_entry(state: &TestReplica, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.into(),
                size: 3,
                mtime_unix_nanos: 0,
                blocks: vec![yadorilink_replica_domain::file::BlockInfo {
                    hash: vec![0xCE; 32],
                    offset: 0,
                    size: 3,
                }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state.sqlite().dag_bump_projection_obligations_for_touched_paths(GROUP, &[path], 1).unwrap();
}

/// A peer's entry admitted under `a` whose projection has not even
/// started here (no intent yet, only its obligation) was never on this
/// device's disk, so the user's `rm -rf a` did not delete it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rm_rf_does_not_delete_child_admitted_but_not_yet_projected() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    index_admitted_remote_entry(&state, "a/new.txt");
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::write(root.join("a/x"), b"x").unwrap();
    for rel in ["a", "a/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::ObservedRemoval).await;

    assert_eq!(ops_at(&state, "a"), ["put-dir", "delete"]);
    assert_eq!(ops_at(&state, "a/x"), ["put-file", "delete"]);
    assert_eq!(ops_at(&state, "a/new.txt"), Vec::<String>::new());
    assert!(state
        .file_index_repository()
        .get_file(GROUP, "a/new.txt")
        .unwrap()
        .is_some_and(|r| !r.deleted));
}

/// D5 promotes a structural directory on a change of its replicated mode
/// (the permission bits) only. A setuid, setgid or sticky bit is part of
/// the directory's tracked metadata but not of its replicated mode, so
/// setting one promotes nothing.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_special_bit_on_a_structural_directory_does_not_promote_it() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("s")).unwrap();
    std::fs::set_permissions(root.join("s"), std::fs::Permissions::from_mode(0o755)).unwrap();
    record_structural(&state, &root, "s");

    std::fs::set_permissions(root.join("s"), std::fs::Permissions::from_mode(0o1755)).unwrap();
    event(&proc, &root, &root.join("s"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert_eq!(ops_at(&state, "s"), Vec::<String>::new(), "a sticky bit is not a mode change");

    std::fs::set_permissions(root.join("s"), std::fs::Permissions::from_mode(0o1700)).unwrap();
    event(&proc, &root, &root.join("s"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "s"), ["put-dir"]);
    let row = state.file_index_repository().canonical_current_row(GROUP, "s").unwrap().unwrap();
    assert_eq!(row.snapshot.unix_mode, Some(0o700));
}

/// Takes away the permission to search `dir` and gives it back on drop, so a
/// failed assertion does not leave a directory the temp-dir cleanup cannot
/// remove. `None` when this process is not stopped by the permission (it
/// runs as root), which makes the scenario impossible to set up.
#[cfg(unix)]
struct Unsearchable(std::path::PathBuf);

#[cfg(unix)]
impl Unsearchable {
    fn new(dir: &Path) -> Option<Self> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let guard = Self(dir.to_path_buf());
        std::fs::symlink_metadata(dir.join("probe"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
            .then_some(guard)
    }
}

#[cfg(unix)]
impl Drop for Unsearchable {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// A path that cannot be looked at (its directory is not searchable) is not
/// a path that is gone. Reading the permission error as "removed" authored a
/// delete, and propagated it to every peer, for a file that still exists.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_that_cannot_be_observed_is_not_captured_as_a_deletion() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("p")).unwrap();
    std::fs::write(root.join("p/f.txt"), b"still here").unwrap();
    event(&proc, &root, &root.join("p/f.txt"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "p/f.txt"), ["put-file"], "sanity: captured");
    let Some(_unsearchable) = Unsearchable::new(&root.join("p")) else { return };

    let outcome = proc
        .process_event(
            GROUP,
            &root,
            &FsChangeEvent { path: root.join("p/f.txt"), kind: FsChangeKind::ObservedRemoval },
        )
        .await
        .unwrap();

    assert!(matches!(outcome, LocalChangeOutcome::RetryLater), "got {outcome:?}");
    assert_eq!(ops_at(&state, "p/f.txt"), ["put-file"], "no delete may be authored");
    assert!(state
        .file_index_repository()
        .get_file(GROUP, "p/f.txt")
        .unwrap()
        .is_some_and(|row| !row.deleted));
}

/// The entries observed under a vanished directory are the ones no longer
/// on disk. An entry whose lookup fails for any reason but absence is not
/// known to be gone, so it is not deleted with the directory.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_entry_that_cannot_be_observed_is_not_part_of_a_directory_removal() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/x"), b"x").unwrap();
    for rel in ["d", "d/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    let Some(_unsearchable) = Unsearchable::new(&root.join("d")) else { return };

    let locked = proc
        .lock_observed_subtree(
            GROUP,
            &root,
            "d",
            &[],
            None,
            super::semantic_delete::Removal::Observed,
        )
        .await
        .unwrap();

    assert!(
        locked.entries().is_empty(),
        "entries the disk could not answer for are not observed as removed: {:?}",
        locked.entries()
    );
}

/// At commit time a delete prepared for an absent path must still find it
/// absent, not merely unreadable.
#[cfg(unix)]
#[test]
fn an_unreadable_path_does_not_match_a_delete_prepared_for_an_absent_one() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("p")).unwrap();
    let missing = dir.path().join("p/gone");
    assert!(
        (super::disk_observation::prepare_match(&missing, &None)
            != super::disk_observation::PrepareMatch::Changed),
        "sanity: absent"
    );
    let Some(_unsearchable) = Unsearchable::new(&dir.path().join("p")) else { return };

    assert!(
        !(super::disk_observation::prepare_match(&missing, &None)
            != super::disk_observation::PrepareMatch::Changed),
        "unreadable is not absent"
    );
}

/// A platform whose disk reports no mode (Windows) cannot differ from the mode
/// a directory's version records, by event or by scan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_whose_disk_reports_no_mode_is_not_recaptured_against_a_recorded_one() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("e")).unwrap();
    event(&proc, &root, &root.join("e"), FsChangeKind::CreatedOrModified).await;
    assert_eq!(ops_at(&state, "e"), ["put-dir"]);

    proc.simulate_unobservable_modes();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.join("e"), std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    event(&proc, &root, &root.join("e"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();

    assert_eq!(ops_at(&state, "e"), ["put-dir"]);
}
