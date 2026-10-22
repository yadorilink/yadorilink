use super::*;

#[test]
fn other_version_names_keep_the_folder_and_the_extension() {
    assert_eq!(other_version_path("plan.txt", 1), "plan (other version).txt");
    assert_eq!(other_version_path("docs/plan.txt", 2), "docs/plan (other version 2).txt");
    assert_eq!(other_version_path("Makefile", 1), "Makefile (other version)");
    assert_eq!(other_version_path(".profile", 1), ".profile (other version)");
}

#[test]
fn only_a_file_copy_of_a_concurrent_edit_is_resolvable() {
    let copy = "plan (conflicted copy, 2026-01-01-000000, device-b).txt";
    assert!(conflict_copy_resolvable(copy, RecordKind::File, ConflictCopyReason::ConcurrentEdit));
    assert!(!conflict_copy_resolvable(copy, RecordKind::File, ConflictCopyReason::FolderAtPath));
    assert!(!conflict_copy_resolvable(
        copy,
        RecordKind::Symlink,
        ConflictCopyReason::ConcurrentEdit
    ));
    assert!(!conflict_copy_resolvable(
        copy,
        RecordKind::Directory,
        ConflictCopyReason::ConcurrentEdit
    ));
}

/// The daemon's own check, behind the path resolution a request goes
/// through: a folder above a listed copy that is now a link out of the root
/// is refused before anything is moved.
/// A linked group with a listed conflict copy row at `copy`; nothing on disk.
fn fixture(group: &str, copy: &str) -> (Arc<DaemonState>, tempfile::TempDir, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-under-test".to_string(), coordinator, store);
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, group).unwrap();
    state.install_test_root_commit_authority(group);
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        root.path(),
        group,
        state.replica_coordinator.as_ref(),
    )
    .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            group,
            &yadorilink_replica_domain::file::FileRecord {
                path: copy.to_string(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            "device-b",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    (state, root, store_dir)
}

/// Nothing is moved while a rebootstrap holds the group frozen.
#[tokio::test]
async fn a_frozen_group_is_not_changed() {
    const GROUP: &str = "group-frozen";
    const COPY: &str = "plan (conflicted copy, 2026-01-01-000000, device-b).txt";
    let (state, root, _store_dir) = fixture(GROUP, COPY);
    std::fs::write(root.path().join(COPY), "theirs").unwrap();
    crate::test_support::freeze_group(&state.replica_coordinator, GROUP);

    for choice in [ConflictChoice::KeepBoth, ConflictChoice::KeepThis] {
        let result = resolve_conflict(&state, GROUP, COPY, choice).await;
        assert!(matches!(result, Err(ResolveConflictError::Failed(_))), "{result:?}");
    }
    assert_eq!(std::fs::read_to_string(root.path().join(COPY)).unwrap(), "theirs");
    assert_eq!(
        std::fs::read_dir(root.path())
            .unwrap()
            .filter(|e| !e.as_ref().unwrap().file_name().to_string_lossy().starts_with('.'))
            .count(),
        1
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_copy_below_a_folder_linked_out_of_the_root_is_refused() {
    const GROUP: &str = "group-linked-out";
    const COPY: &str = "sub/plan (conflicted copy, 2026-01-01-000000, device-b).txt";
    let (state, root, _store_dir) = fixture(GROUP, COPY);
    let outside = tempfile::tempdir().unwrap();
    let outside_copy =
        outside.path().join("plan (conflicted copy, 2026-01-01-000000, device-b).txt");
    std::fs::write(&outside_copy, "outside the folder").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("sub")).unwrap();

    for choice in [ConflictChoice::KeepBoth, ConflictChoice::KeepThis] {
        let result = resolve_conflict(&state, GROUP, COPY, choice).await;
        assert!(matches!(result, Err(ResolveConflictError::NotResolvable(_))), "{result:?}");
    }
    assert_eq!(std::fs::read_to_string(&outside_copy).unwrap(), "outside the folder");
    assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 1);
}
