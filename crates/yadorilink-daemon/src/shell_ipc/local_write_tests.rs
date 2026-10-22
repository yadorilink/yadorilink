#![cfg(test)]

use std::path::Path;
use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::RealFolderWatchSource;
use yadorilink_ipc_proto::shellipc::LocalWriteRequest;
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

fn local_write_request(
    local_path: &str,
    relative_path: &str,
    kind: LocalWriteKind,
) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::LocalWriteRequest(LocalWriteRequest {
            local_path: local_path.to_string(),
            relative_path: relative_path.to_string(),
            kind: kind as i32,
        })),
    }
}

/// The core create-path test: a File Provider `createItem`
/// notification (here, a plain file already written to disk plus this
/// request -- see `LinkFlushHandle::capture_local_write`'s own doc for
/// why the request itself carries no content) results in exactly one
/// native delta and one indexed row, through the SAME admission path a
/// filesystem watcher's own event takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_write_request_for_a_new_file_admits_exactly_one_dag_change() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    start_watch_and_await_scan(&state, root.path(), "group-1").await;
    std::fs::write(root.path().join("new.txt"), b"hello from the file provider").unwrap();

    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request(&local_path, "new.txt", LocalWriteKind::CreatedOrModified),
    )
    .await
    .unwrap();

    let Some(Payload::LocalWriteResponse(r)) = response.payload else {
        panic!("expected a LocalWriteResponse");
    };
    assert!(r.ok, "expected ok=true, got error: {}", r.error);
    let record =
        state.replica_coordinator.file_index_repository().get_file("group-1", "new.txt").unwrap();
    assert!(record.is_some_and(|r| !r.deleted), "the new file must be indexed and not deleted");
    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "new.txt").unwrap().len(),
        1,
        "exactly one native delta for the create"
    );
}

/// A duplicate `createItem` replay for the exact same unchanged content
/// (a real callback retry, or the OS re-delivering the same
/// notification) must not mint a second native delta -- `process_event`'s
/// own self-echo/no-op suppression, exercised here through the new
/// signal source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_local_write_request_for_unchanged_content_does_not_duplicate_the_change() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    start_watch_and_await_scan(&state, root.path(), "group-1").await;
    std::fs::write(root.path().join("new.txt"), b"hello from the file provider").unwrap();
    handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request(&local_path, "new.txt", LocalWriteKind::CreatedOrModified),
    )
    .await
    .unwrap();

    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request(&local_path, "new.txt", LocalWriteKind::CreatedOrModified),
    )
    .await
    .unwrap();

    let Some(Payload::LocalWriteResponse(r)) = response.payload else {
        panic!("expected a LocalWriteResponse");
    };
    assert!(r.ok, "a no-op replay must still report ok=true, got error: {}", r.error);
    assert_eq!(
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "new.txt").unwrap().len(),
        1,
        "a duplicate replay of unchanged content must not mint a second native delta"
    );
}

/// A `deleteItem` notification for an existing file tombstones it
/// through the same admission path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_write_request_for_a_delete_tombstones_the_file() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    start_watch_and_await_scan(&state, root.path(), "group-1").await;
    std::fs::write(root.path().join("gone.txt"), b"will be deleted").unwrap();
    handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request(&local_path, "gone.txt", LocalWriteKind::CreatedOrModified),
    )
    .await
    .unwrap();
    std::fs::remove_file(root.path().join("gone.txt")).unwrap();

    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request(&local_path, "gone.txt", LocalWriteKind::Deleted),
    )
    .await
    .unwrap();

    let Some(Payload::LocalWriteResponse(r)) = response.payload else {
        panic!("expected a LocalWriteResponse");
    };
    assert!(r.ok, "expected ok=true, got error: {}", r.error);
    let record =
        state.replica_coordinator.file_index_repository().get_file("group-1", "gone.txt").unwrap();
    assert!(record.is_some_and(|r| r.deleted), "the file must be tombstoned, not merely absent");
}

/// An unrecognized `local_path` (not currently a live linked folder)
/// must fail closed, never silently admit a write for a group this
/// request cannot actually be authorized against.
#[tokio::test]
async fn local_write_request_for_an_unknown_local_path_is_rejected() {
    let state = test_state();

    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request("/not/a/linked/folder", "x.txt", LocalWriteKind::CreatedOrModified),
    )
    .await
    .unwrap();

    let Some(Payload::LocalWriteResponse(r)) = response.payload else {
        panic!("expected a LocalWriteResponse");
    };
    assert!(!r.ok, "an unknown local_path must not be silently accepted");
}

/// A failure to read the link table is not evidence that the folder is
/// unlinked: the File Provider must be told the daemon could not check,
/// not that its folder is no longer synced.
#[tokio::test]
async fn local_write_request_reports_a_link_table_read_failure_as_such() {
    let state = test_state();
    let root = tempfile::tempdir().unwrap();
    let local_path = root.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch("DROP TABLE links")?;
            Ok(())
        })
        .unwrap();

    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        local_write_request(&local_path, "x.txt", LocalWriteKind::CreatedOrModified),
    )
    .await
    .unwrap();

    let Some(Payload::LocalWriteResponse(r)) = response.payload else {
        panic!("expected a LocalWriteResponse");
    };
    assert!(!r.ok, "a write the daemon could not route must not be accepted");
    assert!(
        r.error.contains("could not read the linked folders"),
        "a link-table read failure must be reported as one, not as an unlinked folder: {}",
        r.error
    );
}
