#![cfg(test)]

use std::sync::Arc;

use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::*;

fn upsert(coordinator: &ReplicaCoordinator, path: &str) {
    coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: path.into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
}

/// A conflict copy whose source name is a folder now -- an explicit
/// directory, or a name with synced entries below it -- is kept because
/// of that folder, not because of a concurrent edit.
#[test]
fn a_conflict_copy_names_a_folder_at_its_source_path() {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    upsert(&coordinator, "notes.txt");
    upsert(&coordinator, "notes (conflicted copy, 2026-01-01-000000, device-b).txt");
    upsert(&coordinator, "trips/beach.jpg");
    upsert(&coordinator, "trips (conflicted copy, 2026-01-01-000000, device-b)");
    upsert(&coordinator, "album");
    coordinator
        .file_index_repository()
        .set_record_kind("group-1", "album", RecordKind::Directory, &RootCommitPermit::for_tests())
        .unwrap();
    upsert(&coordinator, "album (conflicted copy, 2026-01-01-000000, device-b)");

    let service = FileHistoryQueryService::new(
        coordinator.clone(),
        Arc::new(LinkedPathResolver::new(coordinator.clone())),
    );
    let reasons: Vec<(String, ConflictCopyReason)> =
        service.list_conflicts().unwrap().into_iter().map(|c| (c.path, c.reason)).collect();
    assert!(reasons.contains(&(
        "notes (conflicted copy, 2026-01-01-000000, device-b).txt".into(),
        ConflictCopyReason::ConcurrentEdit
    )));
    assert!(reasons.contains(&(
        "trips (conflicted copy, 2026-01-01-000000, device-b)".into(),
        ConflictCopyReason::FolderAtPath
    )));
    assert!(reasons.contains(&(
        "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        ConflictCopyReason::FolderAtPath
    )));
    assert_eq!(reasons.len(), 3, "{reasons:?}");
}
