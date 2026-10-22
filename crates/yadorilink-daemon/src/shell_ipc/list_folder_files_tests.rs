#![cfg(test)]

//! `ListFolderFilesResponse` must never present "could not read"
//! as "this folder has zero files". A platform File Provider treats a
//! successful enumeration as authoritative, so an empty listing with
//! `snapshot_available == true` tells it the folder is empty.

use std::path::Path;
use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::RealFolderWatchSource;
use yadorilink_ipc_proto::shellipc::ListFolderFilesRequest;
use yadorilink_local_storage::SegmentBlockStore;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

use super::*;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    state
        .replica_coordinator
        .set_local_policy_head_provider(std::sync::Arc::new(|_group_id| Ok([0u8; 32])));
    state
}

async fn start_watch_and_await_scan(state: &Arc<DaemonState>, root: &Path, group: &str) {
    let controller = LinkRuntimeController::new(state.clone());
    controller
        .start_with_source(
            root.to_string_lossy().into_owned(),
            group.to_string(),
            Arc::new(RealFolderWatchSource),
        )
        .expect("the watch must start");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.replica_coordinator.wait_group_ready(group),
    )
    .await
    .expect("the initial scan must finish")
    .expect("the initial scan must succeed");
}

/// The initial scan this test corrupts the schema under has already
/// finished (`start_watch_and_await_scan` awaited it), but the watcher it
/// started keeps running and can still hold a write connection open for a
/// moment. A DDL statement needs the schema lock exclusively, so it is
/// retried a few times rather than failing on that ordinary race.
fn corrupt_schema(state: &Arc<DaemonState>, sql: &str) {
    let database = state.replica_coordinator.database();
    let pool = database.pool_for_test();
    let mut attempt = 0;
    loop {
        let result = pool.get().unwrap().execute_batch(sql);
        match result {
            Ok(()) => return,
            Err(rusqlite::Error::SqliteFailure(e, _))
                if attempt < 20
                    && matches!(
                        e.code,
                        rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                    ) =>
            {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => panic!("corrupt_schema: {e}"),
        }
    }
}

async fn list_folder_files(state: &Arc<DaemonState>, local_path: &str) -> ListFolderFilesResponse {
    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        ShellIpcMessage {
            payload: Some(Payload::ListFolderFilesRequest(ListFolderFilesRequest {
                local_path: local_path.to_string(),
            })),
        },
    )
    .await
    .expect("a ListFolderFilesRequest always gets a response");
    let Some(Payload::ListFolderFilesResponse(r)) = response.payload else {
        panic!("expected a ListFolderFilesResponse");
    };
    r
}

/// The success counterpart: a live link whose index is really empty is a
/// confirmed, authoritative empty listing.
#[tokio::test]
async fn a_live_link_with_no_files_is_a_confirmed_empty_listing() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/listing-folder", "group-1").unwrap();

    let r = list_folder_files(&state, "/tmp/listing-folder").await;

    assert!(r.entries.is_empty());
    assert!(r.snapshot_available, "a confirmed empty folder must be reported as confirmed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_link_with_files_is_a_confirmed_listing() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    std::fs::write(root.path().join("a.txt"), b"hello").unwrap();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    start_watch_and_await_scan(&state, root.path(), "group-1").await;

    let r = list_folder_files(&state, &local_path).await;

    assert!(r.snapshot_available);
    assert_eq!(r.entries.iter().map(|e| e.relative_path.as_str()).collect::<Vec<_>>(), ["a.txt"]);
}

/// A file-index read failure used to become `[]` through
/// `unwrap_or_default()`, indistinguishable from an empty folder.
#[tokio::test]
async fn a_file_index_read_failure_is_not_an_authoritative_empty_listing() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/listing-folder", "group-1").unwrap();
    corrupt_schema(&state, "DROP TABLE files");

    let r = list_folder_files(&state, "/tmp/listing-folder").await;

    assert!(r.entries.is_empty());
    assert!(
        !r.snapshot_available,
        "a file-index read failure must not be reported as a confirmed empty folder"
    );
}

/// The link-table read failing is the same class: "cannot find out which
/// link this is" is not "the folder is empty".
#[tokio::test]
async fn a_link_table_read_failure_is_not_an_authoritative_empty_listing() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/listing-folder", "group-1").unwrap();
    corrupt_schema(&state, "DROP TABLE links");

    let r = list_folder_files(&state, "/tmp/listing-folder").await;

    assert!(
        !r.snapshot_available,
        "a link-table read failure must not be reported as a confirmed empty folder"
    );
}

/// A per-entry materialization-state read failure used to degrade the
/// entry to `Unspecified` and still report the listing as good. A
/// partially-read listing is not a confirmed one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_materialization_state_read_failure_is_not_a_confirmed_listing() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    std::fs::write(root.path().join("a.txt"), b"hello").unwrap();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    start_watch_and_await_scan(&state, root.path(), "group-1").await;
    corrupt_schema(
        &state,
        "ALTER TABLE files RENAME COLUMN materialization_state TO listing_broken",
    );

    let r = list_folder_files(&state, &local_path).await;

    assert!(
        !r.snapshot_available,
        "a listing whose materialization states could not be read must not be confirmed"
    );
    assert!(r.entries.is_empty(), "an unconfirmed listing carries no entries");
}

/// A `local_path` that names no live link has no snapshot to confirm; an
/// orphaned link is excluded the same way.
#[tokio::test]
async fn an_unknown_or_orphaned_link_is_not_a_confirmed_empty_listing() {
    let state = test_state();

    let r = list_folder_files(&state, "/tmp/listing-no-such-link").await;
    assert!(!r.snapshot_available, "an unknown local_path must not be a confirmed empty folder");

    state.replica_coordinator.link_repository().add_link("/tmp/listing-orphan", "group-2").unwrap();
    corrupt_schema(
        &state,
        "UPDATE links SET orphaned = 1 WHERE local_path = '/tmp/listing-orphan'",
    );
    let r = list_folder_files(&state, "/tmp/listing-orphan").await;
    assert!(!r.snapshot_available, "an orphaned link must not be a confirmed empty folder");
}

/// An explicit (tracked) directory is its own index row. The listing must
/// say it is a directory, or a File Provider would create a file node for
/// it next to the directory node it synthesizes from its children's paths.
#[tokio::test]
async fn list_folder_files_reports_explicit_directory_as_directory() {
    use yadorilink_ipc_proto::shellipc::EntryKind;
    use yadorilink_replica_domain::file::{FileRecord, RecordKind};

    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/tmp/listing-kinds", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let index = state.replica_coordinator.file_index_repository();
    for (path, kind) in [
        ("album", RecordKind::Directory),
        ("album/a.txt", RecordKind::File),
        ("album/latest", RecordKind::Symlink),
    ] {
        let record = FileRecord {
            path: path.into(),
            size: 0,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted: false,
        };
        index.upsert_file("group-1", &record, &permit).unwrap();
        index.set_record_kind("group-1", path, kind, &permit).unwrap();
    }

    let r = list_folder_files(&state, "/tmp/listing-kinds").await;

    assert!(r.snapshot_available);
    let mut kinds: Vec<(String, EntryKind)> =
        r.entries.iter().map(|e| (e.relative_path.clone(), e.kind())).collect();
    kinds.sort();
    assert_eq!(
        kinds,
        [
            ("album".to_string(), EntryKind::Directory),
            ("album/a.txt".to_string(), EntryKind::File),
            ("album/latest".to_string(), EntryKind::Symlink),
        ]
    );
}
