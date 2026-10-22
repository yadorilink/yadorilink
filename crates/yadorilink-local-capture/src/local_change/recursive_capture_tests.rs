#![cfg(test)]

//! A recursive delete (`rm -rf d`) and a directory rename (`d -> e`) are
//! captured as one signed recursive operation: the point ops on the
//! explicit entries this device observed, cut into parts that each carry
//! the operation's descriptor. The set is observed-remove: an entry this
//! device never had on disk is not in it. A rename moves explicit entries
//! only; a structural directory stays structural under its new name.

use std::collections::{BTreeMap, BTreeSet};

use super::directory_capture::{
    event, index_in_flight_remote_entry, live_kind, ops_at, record_structural, GROUP,
};
use super::*;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_replica_domain::recursive_operation::{
    RecursiveOperationKind, RecursiveOperationRef,
};
use yadorilink_replica_domain::signed_delta::NativeDelta as Change;
use yadorilink_sync_sqlite::native_recursive_operation::NativeOperationCompleteness;

/// The part size capture cuts a recursive operation into.
const PART_OP_LIMIT: usize = 256;

fn changes(state: &TestReplica) -> Vec<Change> {
    crate::test_support::native_deltas(state, GROUP)
}

/// Every delta carrying a recursive-operation part, in part order.
fn parts(state: &TestReplica) -> Vec<Change> {
    let mut parts: Vec<Change> =
        changes(state).into_iter().filter(|c| c.recursive_part.is_some()).collect();
    parts.sort_by_key(|c| c.recursive_part.unwrap().part_index);
    parts
}

/// The paths the parts remove (`delete`) and put (`put`).
fn effect_paths(parts: &[Change]) -> BTreeMap<&'static str, BTreeSet<String>> {
    let mut out: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    for part in parts {
        for op in &part.ops {
            let (kind, what) = match &op.put {
                Some(_) => ("put", "put"),
                None => ("delete", "deleted"),
            };
            assert!(
                out.entry(kind).or_default().insert(op.path.as_str().to_string()),
                "{:?} {what} twice",
                op.path
            );
        }
    }
    out
}

fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| p.to_string()).collect()
}

/// Asserts `parts` are all the parts of one operation, complete here, and
/// returns its reference. Native does not record whether the operation was a
/// delete or a rename; `_kind` documents what the test authored.
fn assert_one_complete_operation(
    state: &TestReplica,
    parts: &[Change],
    _kind: RecursiveOperationKind,
) -> RecursiveOperationRef {
    assert!(!parts.is_empty(), "no recursive-operation part was authored");
    let first = parts[0].recursive_part.unwrap();
    assert_eq!(first.part_count as usize, parts.len(), "every part is here");
    for (index, part) in parts.iter().enumerate() {
        let descriptor = part.recursive_part.unwrap();
        assert_eq!(descriptor.part_index as usize, index);
        assert_eq!(
            (descriptor.operation_id, descriptor.part_count),
            (first.operation_id, first.part_count),
            "parts disagree"
        );
    }
    let operation = RecursiveOperationRef {
        author: parts[0].author.device.clone(),
        operation_id: first.operation_id,
    };
    let completeness = state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::native_recursive_operation::completeness(
                conn, GROUP, &operation,
            )
        })
        .unwrap();
    assert_eq!(completeness, NativeOperationCompleteness::Complete);
    operation
}

async fn flush(proc: &LocalChangeProcessor, root: &Path, paths: &[(&str, FsChangeKind)]) {
    proc.process_flush(
        GROUP,
        root,
        DebounceFlush::Paths(paths.iter().map(|(rel, kind)| (root.join(rel), *kind, 1)).collect()),
    )
    .await
    .unwrap();
}

/// `rm -rf d` over more entries than one part carries, deleting exactly
/// every head under `d`: one operation cut into ceil(n / limit) parts, each
/// naming the operation, which together remove every observed entry once.
#[test]
fn rm_rf_emits_point_deletes_for_observed_set_in_ceil_chunks() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/sub")).unwrap();
    let mut expected = vec!["d".to_string(), "d/sub".to_string()];
    for i in 0..300 {
        let rel = format!("d/f{i:03}.txt");
        std::fs::write(root.join(&rel), rel.as_bytes()).unwrap();
        expected.push(rel);
    }
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert!(parts(&state).is_empty());

    std::fs::remove_dir_all(root.join("d")).unwrap();
    tokio::runtime::Runtime::new().unwrap().block_on(event(
        &proc,
        &root,
        &root.join("d"),
        FsChangeKind::ObservedRemoval,
    ));

    let parts = parts(&state);
    assert!(expected.len() > PART_OP_LIMIT, "the entries need more than one part");
    assert_eq!(parts.len(), expected.len().div_ceil(PART_OP_LIMIT), "ceil(n / limit) parts");
    assert_eq!(
        effect_paths(&parts).get("delete"),
        Some(&expected.iter().cloned().collect::<BTreeSet<_>>()),
        "every entry is removed exactly once"
    );
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("d".into()) },
    );
    // No removal of the tree was authored outside the operation.
    for change in changes(&state) {
        if change.recursive_part.is_none() {
            assert!(change.ops.iter().all(|op| op.put.is_some()));
        }
    }
    for rel in &expected {
        assert_eq!(live_kind(&state, rel), None, "{rel} is still live");
    }
}

/// Every entry in the tree was put by a delta of its own; the operation's
/// parts remove every one of them, so no head of the tree is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rm_rf_multi_op_change_parents_cover_every_touched_basis() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/e")).unwrap();
    for rel in ["d/a", "d/b", "d/e/c"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    std::fs::write(root.join("outside"), b"o").unwrap();
    for rel in ["d", "d/e", "d/a", "d/b", "d/e/c", "outside"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("d")).unwrap();
    event(&proc, &root, &root.join("d"), FsChangeKind::ObservedRemoval).await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("d".into()) },
    );
    for rel in ["d", "d/e", "d/a", "d/b", "d/e/c"] {
        assert!(
            crate::test_support::native_path_head_provenances(&state, GROUP, rel).is_empty(),
            "a version the delete observed is still a head at {rel}"
        );
    }
    assert_eq!(
        crate::test_support::native_path_head_provenances(&state, GROUP, "outside").len(),
        1,
        "a path outside the tree is untouched"
    );
}

/// The children's own `Removed` events and their directory's arrive in one
/// flush: the whole tree is still one operation, so a folder restore gets
/// all of it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_and_its_children_removed_in_one_flush_are_one_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("a")).unwrap();
    std::fs::write(root.join("a/x"), b"x").unwrap();
    std::fs::write(root.join("a/y"), b"y").unwrap();
    for rel in ["a", "a/x", "a/y"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    flush(
        &proc,
        &root,
        &[
            ("a/x", FsChangeKind::ObservedRemoval),
            ("a/y", FsChangeKind::ObservedRemoval),
            ("a", FsChangeKind::ObservedRemoval),
        ],
    )
    .await;

    let parts = parts(&state);
    let operation = assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
    );
    assert_eq!(effect_paths(&parts).get("delete"), Some(&set(&["a", "a/x", "a/y"])));
    assert_eq!(ops_at(&state, "a/x"), ["put-file", "delete"]);
    // The trashed versions carry the operation, which is what a folder
    // restore reads once the deleting changes are compacted away.
    let trashed: BTreeSet<String> = state
        .file_index_repository()
        .list_trashed_by_recursive_operation(GROUP, &operation)
        .unwrap()
        .into_iter()
        .map(|t| t.path)
        .collect();
    assert_eq!(trashed, set(&["a", "a/x", "a/y"]));
}

/// `mv d e` of an explicit directory: one rename operation deleting each
/// observed entry under `d` and putting it under `e`, with the same
/// content.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_of_explicit_directory_is_one_recursive_rename_operation() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/sub")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/sub", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("d", FsChangeKind::ObservedRemoval), ("e", FsChangeKind::CreatedOrModified)],
    )
    .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RenameTree { from: SyncPath("d".into()), to: SyncPath("e".into()) },
    );
    let effects = effect_paths(&parts);
    assert_eq!(effects.get("delete"), Some(&set(&["d", "d/sub", "d/f.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["e", "e/sub", "e/f.txt"])));
    assert_eq!(ops_at(&state, "e"), ["put-dir"]);
    assert_eq!(ops_at(&state, "e/sub"), ["put-dir"]);
    assert_eq!(ops_at(&state, "e/f.txt"), ["put-file"]);
    let moved = state.file_index_repository().get_file(GROUP, "e/f.txt").unwrap().unwrap();
    assert!(!moved.deleted);
    assert_eq!(moved.size, 5);
    assert_eq!(live_kind(&state, "d/f.txt"), None);
}

/// A renamed file keeps the mode and attributes of the file it moved from when
/// the platform cannot read them: the destination has no row to inherit from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renamed_file_keeps_the_mode_and_attributes_of_its_source_where_none_are_readable() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state.file_index_repository().set_unix_mode(GROUP, "d/f.txt", Some(0o640), &permit).unwrap();
    let attrs = vec![("user.origin".to_string(), b"linux".to_vec())];
    state.file_index_repository().set_xattrs(GROUP, "d/f.txt", &attrs, &permit).unwrap();

    proc.simulate_unobservable_modes();
    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("d", FsChangeKind::ObservedRemoval), ("e", FsChangeKind::CreatedOrModified)],
    )
    .await;

    assert_eq!(ops_at(&state, "e/f.txt"), ["put-file"]);
    assert_eq!(state.file_index_repository().get_unix_mode(GROUP, "e/f.txt").unwrap(), Some(0o640));
    assert_eq!(state.file_index_repository().get_xattrs(GROUP, "e/f.txt").unwrap(), attrs);
}

/// FSEvents reports both sides of a rename as a change of unknown
/// direction, and in no particular order. What is on disk pairs them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_reported_without_sides_is_still_one_rename() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("e", FsChangeKind::CreatedOrModified), ("d", FsChangeKind::CreatedOrModified)],
    )
    .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RenameTree { from: SyncPath("d".into()), to: SyncPath("e".into()) },
    );
    assert_eq!(effect_paths(&parts).get("put"), Some(&set(&["e", "e/f.txt"])));
}

/// A structural directory is renamed: it stays structural under its new
/// name. Only the explicit entries below it move; nothing is authored for
/// the directory at either name, then or on a later look.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_of_structural_directory_does_not_promote_destination() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("s")).unwrap();
    record_structural(&state, &root, "s");
    std::fs::write(root.join("s/f.txt"), b"f").unwrap();
    event(&proc, &root, &root.join("s/f.txt"), FsChangeKind::CreatedOrModified).await;

    std::fs::rename(root.join("s"), root.join("t")).unwrap();
    flush(
        &proc,
        &root,
        &[("s", FsChangeKind::ObservedRemoval), ("t", FsChangeKind::CreatedOrModified)],
    )
    .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RenameTree { from: SyncPath("s".into()), to: SyncPath("t".into()) },
    );
    let effects = effect_paths(&parts);
    assert_eq!(effects.get("delete"), Some(&set(&["s/f.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["t/f.txt"])));

    event(&proc, &root, &root.join("t"), FsChangeKind::CreatedOrModified).await;
    proc.scan_existing_files(GROUP, &root).unwrap();
    assert_eq!(ops_at(&state, "t"), Vec::<String>::new(), "the renamed container was promoted");
    assert_eq!(ops_at(&state, "s"), Vec::<String>::new());
    assert_eq!(live_kind(&state, "t"), None);
}

/// A rename moves the entries this device observed. A peer's entry
/// indexed under the old name but not yet on disk here was not moved by
/// the user, and stays in the old namespace.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_directory_vs_concurrent_child_keeps_child_in_old_namespace() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    index_in_flight_remote_entry(&state, "d/new.txt");
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    for rel in ["d", "d/f.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("d", FsChangeKind::ObservedRemoval), ("e", FsChangeKind::CreatedOrModified)],
    )
    .await;

    let effects = effect_paths(&parts(&state));
    assert_eq!(effects.get("delete"), Some(&set(&["d", "d/f.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["e", "e/f.txt"])));
    assert!(state
        .file_index_repository()
        .get_file(GROUP, "d/new.txt")
        .unwrap()
        .is_some_and(|r| !r.deleted));
    assert_eq!(ops_at(&state, "d/new.txt"), Vec::<String>::new());
    assert!(state.file_index_repository().get_file(GROUP, "e/new.txt").unwrap().is_none());
}

/// `rm a; mkdir a`: the file entry is replaced by a directory entry, not
/// left live beside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn file_replaced_by_a_directory_retires_the_file_entry() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::write(root.join("a"), b"file").unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    std::fs::remove_file(root.join("a")).unwrap();
    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "a"), ["put-file", "put-dir"]);
    assert_eq!(live_kind(&state, "a"), Some(RecordKind::Directory));
}

/// `rm -rf d; echo > d` coalesced into one event for `d`: the entries
/// observed under the directory are deleted, and `d` becomes the file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn directory_replaced_by_a_file_deletes_its_observed_descendants() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/x"), b"x").unwrap();
    for rel in ["d", "d/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("d")).unwrap();
    std::fs::write(root.join("d"), b"now a file").unwrap();
    event(&proc, &root, &root.join("d"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "d/x"), ["put-file", "delete"]);
    assert_eq!(ops_at(&state, "d"), ["put-dir", "put-file"]);
    assert_eq!(live_kind(&state, "d"), Some(RecordKind::File));
    assert_eq!(live_kind(&state, "d/x"), None);
}

/// Finder deleting a folder through File Provider, or Explorer through the
/// cloud-files API, reaches capture as a single removal of the folder
/// (the virtual filesystem's delete callback routes to this same event
/// path). A structural folder has no entry of its own: its removal is the
/// point deletes of the entries observed in it, never a delete of a path
/// that holds no entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_virtual_filesystem_delete_of_a_structural_folder_expands_to_point_deletes() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("s")).unwrap();
    record_structural(&state, &root, "s");
    std::fs::write(root.join("s/x"), b"x").unwrap();
    std::fs::write(root.join("s/y"), b"y").unwrap();
    for rel in ["s/x", "s/y"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("s")).unwrap();
    event(&proc, &root, &root.join("s"), FsChangeKind::ObservedRemoval).await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("s".into()) },
    );
    assert_eq!(effect_paths(&parts).get("delete"), Some(&set(&["s/x", "s/y"])));
    assert_eq!(ops_at(&state, "s"), Vec::<String>::new(), "a delete of a path with no entry");
}

/// A rename moves an entry to a name the user ignores: it is deleted at
/// its old name and not authored at the new one, exactly as the ordinary
/// capture of the new name would leave it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_does_not_author_an_entry_at_an_ignored_new_name() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("d")).unwrap();
    std::fs::write(root.join("d/kept.txt"), b"k").unwrap();
    std::fs::write(root.join("d/secret.txt"), b"s").unwrap();
    for rel in ["d", "d/kept.txt", "d/secret.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::write(root.join(".yadorilinkignore"), b"e/secret.txt\n").unwrap();
    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("d", FsChangeKind::ObservedRemoval), ("e", FsChangeKind::CreatedOrModified)],
    )
    .await;

    let effects = effect_paths(&parts(&state));
    assert_eq!(effects.get("delete"), Some(&set(&["d", "d/kept.txt", "d/secret.txt"])));
    assert_eq!(effects.get("put"), Some(&set(&["e", "e/kept.txt"])));
    assert!(state.file_index_repository().get_file(GROUP, "e/secret.txt").unwrap().is_none());
}

/// `rm -rf a` over more entries than one debounce flush holds: the
/// watcher flushes the children's removals before `a`'s own (it flushes
/// early on a burst, and at least every couple of seconds), and `rm`
/// removes the children first. A child removed while its directory is
/// already gone is still part of the directory's removal, so the whole
/// tree is one operation and a folder restore gets all of it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_rm_rf_split_across_flushes_is_still_one_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("a/sub")).unwrap();
    for rel in ["a/x", "a/y", "a/sub/z"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    for rel in ["a", "a/sub", "a/x", "a/y", "a/sub/z"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    flush(
        &proc,
        &root,
        &[("a/x", FsChangeKind::ObservedRemoval), ("a/sub/z", FsChangeKind::ObservedRemoval)],
    )
    .await;
    flush(
        &proc,
        &root,
        &[
            ("a/y", FsChangeKind::ObservedRemoval),
            ("a/sub", FsChangeKind::ObservedRemoval),
            ("a", FsChangeKind::ObservedRemoval),
        ],
    )
    .await;

    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("a".into()) },
    );
    assert_eq!(
        effect_paths(&parts).get("delete"),
        Some(&set(&["a", "a/sub", "a/x", "a/y", "a/sub/z"]))
    );
    for change in changes(&state) {
        if change.recursive_part.is_none() {
            assert!(
                change.ops.iter().all(|op| op.put.is_some()),
                "a delete of the tree was authored outside the operation: {change:?}"
            );
        }
    }
}

/// A folder deleted while the daemon was stopped is found by the full
/// scan. It is still one recursive operation (explicit or structural
/// folder alike), so it can be restored as the unit it was removed as; a
/// loose file deleted beside it stays an ordinary delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_folder_delete_is_one_recursive_operation() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("a/sub")).unwrap();
    std::fs::create_dir(root.join("s")).unwrap();
    record_structural(&state, &root, "s");
    for rel in ["a/x", "a/sub/y", "s/z", "loose"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    for rel in ["a", "a/sub", "a/x", "a/sub/y", "s/z", "loose"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("a")).unwrap();
    std::fs::remove_dir_all(root.join("s")).unwrap();
    std::fs::remove_file(root.join("loose")).unwrap();
    proc.scan_existing_files(GROUP, &root).unwrap();

    let parts = parts(&state);
    let mut by_operation: BTreeMap<[u8; 16], Vec<Change>> = BTreeMap::new();
    for part in parts {
        by_operation.entry(part.recursive_part.unwrap().operation_id.0).or_default().push(part);
    }
    let mut removed = BTreeSet::new();
    for operation in by_operation.values() {
        // Native does not record the operation's root; the set it removed
        // tells the two folders apart.
        assert_one_complete_operation(
            &state,
            operation,
            RecursiveOperationKind::RmTree { root: SyncPath(String::new()) },
        );
        removed.insert(effect_paths(operation).get("delete").cloned().unwrap());
    }
    assert_eq!(removed, BTreeSet::from([set(&["a", "a/sub", "a/x", "a/sub/y"]), set(&["s/z"])]));
    assert_eq!(ops_at(&state, "loose"), ["put-file", "delete"]);
    assert_eq!(live_kind(&state, "a/sub/y"), None);
    assert_eq!(live_kind(&state, "s/z"), None);
}

/// An offline folder removal acts on what its pass read: the content each row
/// displayed. A peer's head that replaced the captured heads of one of its
/// paths while the pass ran is a version the removal never saw, and its
/// admission owes the path a projection: the removal withholds that path (it
/// is not eligible for a tombstone while a projection is owed), removes the
/// rest, and leaves the peer's head live to be projected again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::await_holding_lock,
    reason = "the scan-hook slot guard serializes the tests sharing the process-wide \
              scan hook; holding it across awaits is the point"
)]
async fn an_offline_folder_delete_withholds_a_path_a_peer_head_replaced_meanwhile() {
    let _hook_slot = hold_scan_hook_slot();
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("r")).unwrap();
    for rel in ["r/x", "r/y"] {
        std::fs::write(root.join(rel), rel.as_bytes()).unwrap();
    }
    for rel in ["r", "r/x", "r/y"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    std::fs::remove_dir_all(root.join("r")).unwrap();
    let peer_version = yadorilink_replica_domain::ids::VersionHash([9; 32]);
    {
        let hook_state = Arc::clone(&state);
        scan_test_hooks::set_pre_chunk_commit_recheck_hook(Some(Arc::new(
            move |gid: &str, path: &str| {
                if gid == GROUP && path == "r/x" {
                    use yadorilink_daemon::test_support::remote_admission_fixture as peer;
                    peer::admit_remote_superseding_put(
                        &hook_state,
                        GROUP,
                        "device-b",
                        "r/x",
                        peer_version,
                    );
                }
            },
        )));
    }
    let records = proc.scan_existing_files(GROUP, &root);
    scan_test_hooks::set_pre_chunk_commit_recheck_hook(None);
    let records = records.unwrap();

    assert!(
        !records.iter().any(|r| r.path == "r/x"),
        "a path with a projection owed is not tombstoned: {records:?}"
    );
    // The row stays: the owed projection decides what the path becomes.
    assert!(live_kind(&state, "r/x").is_some());
    // The removal never saw the peer's head: it is still native's head there.
    let heads = state
        .database()
        .read(|conn| {
            yadorilink_sync_sqlite::native_store::native_heads_at(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned()),
                &yadorilink_replica_domain::ids::SyncPath("r/x".to_owned()),
            )
        })
        .unwrap();
    assert_eq!(
        heads.iter().map(|head| head.payload.version).collect::<Vec<_>>(),
        vec![peer_version]
    );
    let parts = parts(&state);
    assert_one_complete_operation(
        &state,
        &parts,
        RecursiveOperationKind::RmTree { root: SyncPath("r".into()) },
    );
    // The removal never touched `r/x`: the operation removes the rest and the
    // peer's head stays.
    assert_eq!(effect_paths(&parts).get("delete"), Some(&set(&["r", "r/y"])));
}

/// A rename writes its new paths, `to` itself included, so it takes their
/// locks: a writer holding `to`'s lock (a remote apply, a `chmod` capture)
/// finishes before the rename reads and writes `to`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_rename_waits_for_the_destination_lock() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    std::fs::rename(root.join("a"), root.join("b")).unwrap();
    let held = state.path_lock_registry().path_lock(GROUP, "b").lock_owned().await;
    let blocked = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        flush(
            &proc,
            &root,
            &[("a", FsChangeKind::ObservedRemoval), ("b", FsChangeKind::CreatedOrModified)],
        ),
    )
    .await;
    assert!(blocked.is_err(), "the rename wrote `b` without its lock");
    assert_eq!(ops_at(&state, "b"), Vec::<String>::new());

    drop(held);
    flush(
        &proc,
        &root,
        &[("a", FsChangeKind::ObservedRemoval), ("b", FsChangeKind::CreatedOrModified)],
    )
    .await;
    assert_eq!(effect_paths(&parts(&state)).get("put"), Some(&set(&["b"])));
}

/// Every path lock is taken in one canonical order. A rename `zeta ->
/// alpha` must not hold `zeta` while waiting on `alpha/x`: a batch that
/// holds `alpha/x` and then takes `zeta` (sorted, as every batch locks)
/// would wait on it forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_rename_takes_its_locks_in_canonical_order() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("zeta")).unwrap();
    std::fs::write(root.join("zeta/x"), b"x").unwrap();
    for rel in ["zeta", "zeta/x"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    std::fs::rename(root.join("zeta"), root.join("alpha")).unwrap();

    // A batch writer over `alpha/x` and `zeta`, in sorted order.
    let registry = state.path_lock_registry();
    let first = registry.path_lock(GROUP, "alpha/x").lock_owned().await;
    let second = registry.path_lock(GROUP, "zeta");
    let batch = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let _second = second.lock_owned().await;
        drop(first);
    });

    let captured = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        flush(
            &proc,
            &root,
            &[("zeta", FsChangeKind::ObservedRemoval), ("alpha", FsChangeKind::CreatedOrModified)],
        ),
    )
    .await;
    assert!(captured.is_ok(), "the rename and a sorted batch deadlocked");
    tokio::time::timeout(std::time::Duration::from_secs(10), batch).await.unwrap().unwrap();
    assert_eq!(effect_paths(&parts(&state)).get("put"), Some(&set(&["alpha", "alpha/x"])));
}

/// A directory made where a peer's file is indexed but held off disk here
/// (a name hazard) does not replace that file's entry: the file was never
/// on disk, so nobody replaced it. The same vetoes decide this as decide
/// which entries a vanished directory held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_over_a_held_file_row_does_not_replace_it() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "a".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP, "a", MaterializationState::Remote, &permit)
        .unwrap();
    state.materialization_state_repository().set_held(GROUP, "a", "case_collision", 0).unwrap();

    std::fs::create_dir(root.join("a")).unwrap();
    event(&proc, &root, &root.join("a"), FsChangeKind::CreatedOrModified).await;

    assert_eq!(ops_at(&state, "a"), Vec::<String>::new());
    assert_eq!(live_kind(&state, "a"), Some(RecordKind::File));
}

/// The lock registry keys every path by its case/normalization fold, so
/// `Photos` and `photos` are one lock. A rename that only changes case
/// listed both names and took that lock twice, waiting on itself forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_case_only_directory_rename_takes_each_lock_once() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir(root.join("Photos")).unwrap();
    std::fs::write(root.join("Photos/a.txt"), b"a").unwrap();
    for rel in ["Photos", "Photos/a.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }

    let locked = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        proc.lock_observed_subtree(
            GROUP,
            &root,
            "Photos",
            &[],
            Some("photos"),
            super::semantic_delete::Removal::Observed,
        ),
    )
    .await
    .expect("locking the observed subtree waited on a lock it already held");

    assert!(locked.is_ok());
}

/// Locks are taken in the order of their keys, the fold, so another holder
/// that orders by the same key cannot form a cycle with this one. Ordered by
/// the raw strings, `Zeta.txt` (upper case sorts first) would come before
/// `alpha.txt`, which folds first; a holder of `alpha.txt` waiting for
/// `Zeta.txt` then deadlocks against it.
#[test]
fn path_locks_are_taken_in_fold_order_and_once_per_lock() {
    assert_eq!(
        super::flush::path_lock_order(["Zeta.txt", "alpha.txt", "Alpha.TXT", "beta/B"]),
        ["alpha.txt", "beta/B", "Zeta.txt"],
        "ordered by fold, and the case variant of `alpha.txt` is the same lock"
    );
    assert_eq!(super::flush::path_lock_order(["Photos", "photos"]), ["Photos"]);
}

/// Provider items follow the semantic rename in the SAME transaction: the renamed
/// directory's item and its descendants' items keep their ids, the parent index moves
/// with them, and a sibling that merely shares the name prefix is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_rename_keeps_provider_item_ids_and_moves_the_parent_index() {
    if !yadorilink_fs_platform::fs_capabilities::temp_dir_proves_object_identity_for_test() {
        return;
    }
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d/sub")).unwrap();
    std::fs::create_dir_all(root.join("dd")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"moved").unwrap();
    std::fs::write(root.join("dd/g.txt"), b"stays").unwrap();
    for rel in ["d", "d/sub", "d/f.txt", "dd", "dd/g.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    let provider = state.provider_repository();
    let root_id = provider.declare_state_only_for_tests(GROUP, "Docs").unwrap();
    let id = |path: &str| provider.mint_item(&root_id, path).unwrap();
    let (d, sub, file, sibling) = (id("d"), id("d/sub"), id("d/f.txt"), id("dd/g.txt"));

    std::fs::rename(root.join("d"), root.join("e")).unwrap();
    flush(
        &proc,
        &root,
        &[("d", FsChangeKind::ObservedRemoval), ("e", FsChangeKind::CreatedOrModified)],
    )
    .await;

    assert_eq!(
        provider.item_for_path(&root_id, "e").unwrap(),
        Some(d),
        "the directory's id changed"
    );
    assert_eq!(provider.item_for_path(&root_id, "e/sub").unwrap(), Some(sub));
    assert_eq!(provider.item_for_path(&root_id, "e/f.txt").unwrap(), Some(file));
    assert_eq!(provider.item_for_path(&root_id, "d").unwrap(), None);
    assert_eq!(provider.item_for_path(&root_id, "dd/g.txt").unwrap(), Some(sibling));
    let below_e: Vec<String> =
        provider.list_children(&root_id, "e").unwrap().into_iter().map(|(n, _)| n).collect();
    assert_eq!(below_e, ["f.txt", "sub"], "the parent index did not follow the rename");
    assert!(provider.list_children(&root_id, "d").unwrap().is_empty());
}

/// A recursive delete retires the items below it in the same transaction as the
/// tombstones, so the parent index never lists a deleted child.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recursive_delete_retires_provider_items_with_the_tombstones() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::create_dir_all(root.join("d")).unwrap();
    std::fs::write(root.join("d/f.txt"), b"x").unwrap();
    std::fs::write(root.join("keep.txt"), b"y").unwrap();
    for rel in ["d", "d/f.txt", "keep.txt"] {
        event(&proc, &root, &root.join(rel), FsChangeKind::CreatedOrModified).await;
    }
    let provider = state.provider_repository();
    let root_id = provider.declare_state_only_for_tests(GROUP, "Docs").unwrap();
    let doomed = provider.mint_item(&root_id, "d/f.txt").unwrap();
    let kept = provider.mint_item(&root_id, "keep.txt").unwrap();

    std::fs::remove_dir_all(root.join("d")).unwrap();
    flush(&proc, &root, &[("d", FsChangeKind::ObservedRemoval)]).await;

    assert_eq!(provider.path_for_item(&root_id, &doomed).unwrap(), Some(("d/f.txt".into(), false)));
    assert!(provider.list_children(&root_id, "d").unwrap().is_empty());
    assert_eq!(provider.item_for_path(&root_id, "keep.txt").unwrap(), Some(kept));
}

/// An ordinary edit goes through the REAL version-replacement write path (the current row
/// is superseded, then the new one inserted) and must keep the item's id; a delete retires
/// it and a recreated file is a new item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_keeps_the_provider_item_id_and_a_delete_then_create_mints_a_new_one() {
    let (proc, state, _emitter, _store_dir, root_dir) = processor_with_emitter();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    std::fs::write(root.join("f.txt"), b"one").unwrap();
    event(&proc, &root, &root.join("f.txt"), FsChangeKind::CreatedOrModified).await;
    let provider = state.provider_repository();
    let root_id = provider.declare_state_only_for_tests(GROUP, "Docs").unwrap();
    let id = provider.mint_item(&root_id, "f.txt").unwrap();

    for body in [&b"two"[..], b"three, longer"] {
        std::fs::write(root.join("f.txt"), body).unwrap();
        event(&proc, &root, &root.join("f.txt"), FsChangeKind::CreatedOrModified).await;
        assert_eq!(
            provider.item_for_path(&root_id, "f.txt").unwrap(),
            Some(id),
            "an edit retired the item"
        );
    }

    std::fs::remove_file(root.join("f.txt")).unwrap();
    event(&proc, &root, &root.join("f.txt"), FsChangeKind::ObservedRemoval).await;
    assert_eq!(provider.item_for_path(&root_id, "f.txt").unwrap(), None);

    std::fs::write(root.join("f.txt"), b"again").unwrap();
    event(&proc, &root, &root.join("f.txt"), FsChangeKind::CreatedOrModified).await;
    let again = provider.mint_item(&root_id, "f.txt").unwrap();
    assert_ne!(again, id, "a recreated path reused the deleted item's id");
}
