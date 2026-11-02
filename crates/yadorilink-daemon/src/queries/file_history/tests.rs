#![cfg(test)]

use std::sync::Arc;

use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::*;

fn empty_store() -> (tempfile::TempDir, Arc<dyn BlockStore + Send + Sync>) {
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn BlockStore + Send + Sync> =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap());
    (dir, store)
}

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
        Arc::new(LinkedPathResolver::new(coordinator.clone(), std::path::PathBuf::from("unused"))),
        "device-a".into(),
        empty_store().1,
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

/// The Activity list reads the log of linked folders only, tags each event
/// with its link's root, and tells this device's own changes from a peer's.
#[test]
fn list_activity_spans_linked_folders_and_splits_by_device() {
    use yadorilink_sync_sqlite::activity::{ActivityKind, ActivityOrigin, ActivityQuery};

    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let record = |path: &str, deleted: bool| FileRecord {
        path: path.into(),
        size: 10,
        mtime_unix_nanos: 0,
        blocks: vec![yadorilink_replica_domain::file::BlockInfo {
            hash: vec![1; 32],
            offset: 0,
            size: 10,
        }],
        deleted,
    };
    let permit = RootCommitPermit::for_tests();
    let files = coordinator.file_index_repository();
    files
        .upsert_file_with_origin("group-1", &record("mine.txt", false), "device-a", &permit)
        .unwrap();
    files
        .upsert_file_with_origin("group-1", &record("theirs.txt", false), "device-b", &permit)
        .unwrap();
    files
        .upsert_file_with_origin("group-1", &record("theirs.txt", true), "device-b", &permit)
        .unwrap();
    // A group no link names (an unlinked folder) never shows.
    files
        .upsert_file_with_origin("old-group", &record("x.txt", false), "device-b", &permit)
        .unwrap();

    let service = FileHistoryQueryService::new(
        coordinator.clone(),
        Arc::new(LinkedPathResolver::new(coordinator.clone(), std::path::PathBuf::from("unused"))),
        "device-a".into(),
        empty_store().1,
    );
    let all = service.list_activity(ActivityQuery { limit: 10, ..Default::default() }).unwrap();
    let summary: Vec<_> = all
        .iter()
        .map(|v| (v.local_path.as_str(), v.event.path.as_str(), v.event.kind, v.is_this_device))
        .collect();
    assert_eq!(
        summary,
        [
            ("/home/alice/Photos", "theirs.txt", ActivityKind::Deleted, false),
            ("/home/alice/Photos", "theirs.txt", ActivityKind::Added, false),
            ("/home/alice/Photos", "mine.txt", ActivityKind::Added, true),
        ]
    );
    let others = service
        .list_activity(ActivityQuery {
            limit: 10,
            origin: ActivityOrigin::OtherDevices,
            kinds: vec![ActivityKind::Added],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(others.len(), 1);
    assert_eq!(others[0].event.path, "theirs.txt");
}

mod version_content {
    use yadorilink_replica_domain::file::BlockInfo;
    use yadorilink_replica_domain::session_state::VersionState;

    use super::*;

    fn version(seq: i64, state: VersionState, blocks: Vec<BlockInfo>) -> VersionRecord {
        VersionRecord {
            path: "notes.txt".into(),
            version_seq: seq,
            size: blocks.iter().map(|b| u64::from(b.size)).sum(),
            mtime_unix_nanos: 0,
            blocks,
            deleted: false,
            state,
            origin_device_id: None,
            record_kind: RecordKind::File,
            symlink_target: None,
            exec: false,
            version_hash: yadorilink_replica_domain::ids::VersionHash([0; 32]),
        }
    }

    fn put(store: &dyn BlockStore, bytes: &[u8]) -> BlockInfo {
        let hash = store.put(bytes).unwrap();
        BlockInfo { hash: hex::decode(hash).unwrap(), offset: 0, size: bytes.len() as u32 }
    }

    fn absent(bytes: &[u8]) -> BlockInfo {
        BlockInfo {
            hash: hex::decode(yadorilink_local_storage::hash_block_bytes(bytes)).unwrap(),
            offset: 0,
            size: bytes.len() as u32,
        }
    }

    fn contents(store: &dyn BlockStore, records: Vec<VersionRecord>) -> Vec<VersionContent> {
        content_of_versions(store, records).unwrap().into_iter().map(|v| v.content).collect()
    }

    /// A superseded version whose blocks are all in the store is kept, one with a block missing is
    /// not, and the current version, a deletion, a directory and a symlink are no statement.
    #[test]
    fn each_kind_of_version_says_what_this_device_holds() {
        let (_dir, store) = empty_store();
        let held = put(store.as_ref(), b"held by this device");
        let mut deletion = version(5, VersionState::Trashed, vec![held.clone()]);
        deletion.deleted = true;
        let mut directory = version(6, VersionState::Superseded, vec![]);
        directory.record_kind = RecordKind::Directory;
        let mut symlink = version(7, VersionState::Superseded, vec![]);
        symlink.record_kind = RecordKind::Symlink;
        let records = vec![
            version(1, VersionState::Current, vec![held.clone()]),
            version(2, VersionState::Superseded, vec![held.clone()]),
            version(3, VersionState::Superseded, vec![held.clone(), absent(b"never stored")]),
            version(4, VersionState::Trashed, vec![absent(b"gone")]),
            deletion,
            directory,
            symlink,
            version(8, VersionState::Superseded, vec![]),
        ];

        assert_eq!(
            contents(store.as_ref(), records),
            [
                VersionContent::NotApplicable,
                VersionContent::Kept,
                VersionContent::NotKept,
                VersionContent::NotKept,
                VersionContent::NotApplicable,
                VersionContent::NotApplicable,
                VersionContent::NotApplicable,
                VersionContent::Kept,
            ]
        );
    }

    /// A block shared by several versions is asked once, and the listing reads no block.
    #[test]
    fn the_listing_asks_once_and_reads_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Counting {
            inner: Arc<dyn BlockStore + Send + Sync>,
            asked: AtomicUsize,
            hashes: AtomicUsize,
        }
        impl BlockStore for Counting {
            fn put(&self, data: &[u8]) -> Result<String, yadorilink_local_storage::StorageError> {
                self.inner.put(data)
            }
            fn get(&self, _: &str) -> Result<Vec<u8>, yadorilink_local_storage::StorageError> {
                unreachable!("a listing reads no block")
            }
            fn exists(&self, hash: &str) -> Result<bool, yadorilink_local_storage::StorageError> {
                self.inner.exists(hash)
            }
            fn delete(&self, hash: &str) -> Result<(), yadorilink_local_storage::StorageError> {
                self.inner.delete(hash)
            }
            fn list_by_prefix(
                &self,
                prefix: &str,
            ) -> Result<Vec<String>, yadorilink_local_storage::StorageError> {
                self.inner.list_by_prefix(prefix)
            }
            fn sweep(
                &self,
                live: &std::collections::HashSet<String>,
                grace_cutoff: std::time::SystemTime,
                dry_run: bool,
            ) -> Result<yadorilink_local_storage::GcReport, yadorilink_local_storage::StorageError>
            {
                self.inner.sweep(live, grace_cutoff, dry_run)
            }
            fn present_blocks(
                &self,
                hashes: &[String],
            ) -> Result<Vec<bool>, yadorilink_local_storage::StorageError> {
                self.asked.fetch_add(1, Ordering::SeqCst);
                self.hashes.fetch_add(hashes.len(), Ordering::SeqCst);
                self.inner.present_blocks(hashes)
            }
        }
        let (_dir, inner) = empty_store();
        let shared = put(inner.as_ref(), b"in every version");
        let store = Counting { inner, asked: AtomicUsize::new(0), hashes: AtomicUsize::new(0) };
        let records = (2..6)
            .map(|seq| version(seq, VersionState::Superseded, vec![shared.clone()]))
            .collect();

        let got = contents(&store, records);

        assert_eq!(got, [VersionContent::Kept; 4]);
        assert_eq!(store.asked.load(Ordering::SeqCst), 1, "one batched question");
        assert_eq!(store.hashes.load(Ordering::SeqCst), 1, "the shared block is asked once");
    }

    /// A listing with nothing that has bytes does not ask the store at all.
    #[test]
    fn a_listing_without_older_file_versions_does_not_touch_the_store() {
        let (_dir, store) = empty_store();
        let got = contents(store.as_ref(), vec![version(1, VersionState::Current, vec![])]);
        assert_eq!(got, [VersionContent::NotApplicable]);
    }
}
