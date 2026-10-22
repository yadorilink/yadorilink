//! Tests `versions`/`restore`/`trash list`/`trash restore`/`link
//! retention` end-to-end against a real daemon over the actual control
//! socket — same fixture/`TEST_MUTEX` pattern as `materialization.rs`,
//! since these commands also need no coordination-plane/auth setup.
//!
//! `commands::link::link` itself is auth-gated (it resolves a group name
//! against the coordination plane via `require_access_token`/
//! `resolve_group_id`) and out of scope for this daemon-only fixture,
//! exactly like `materialization.rs` never calls it either — tests here
//! that need a link seed it directly over `control::send`
//! (`ReqPayload::Link`), the same wire message `commands::link::link`
//! itself ultimately sends, so `--keep-versions`/`--keep-days` persistence
//! is exercised through the identical control-socket path a real `link`
//! invocation would use.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_cli::error::CliError;
use yadorilink_client_core::daemon::control;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{ListTrashRequest, ListVersionsRequest};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[29u8; 32]));
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));
    // Local edits now route through `replica_coordinator`, not `sync_state`
    // (7D-10.7) -- mirror the override there too, or `DaemonState::new`'s
    // real provider fires instead and withholds for lack of a verified
    // group policy.
    state.replica_coordinator.set_local_policy_head_provider(Arc::new(|_| Ok([0u8; 32])));

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_context = std::sync::Arc::new(
        yadorilink_daemon::control_context::ControlContext::from_state(state.clone()),
    );
    tokio::spawn(async move {
        let _ =
            yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_context)
                .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;
    (dir, state)
}

/// Tests in this file share `YADORILINK_CONTROL_SOCKET` (a process-global
/// env var) and so must not run concurrently with each other.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Writes `data`'s block into `state`'s block store and records it as
/// obtained through `group_id` (mirroring what `LocalChangeProcessor` does
/// for a real local edit — see `record_group_block_provenance`'s doc
/// comment), returning the raw hash bytes. Without this, restoring a
/// version whose block was poked directly into the store fails as
/// "content is unavailable", since physical presence alone does not prove
/// the block was obtained through the group.
fn put_and_record(state: &DaemonState, group_id: &str, data: &[u8]) -> Vec<u8> {
    let hash_hex = state.block_store.put(data).unwrap();
    let hash_bytes = hex::decode(&hash_hex).unwrap();
    state
        .replica_coordinator
        .record_block_provenance(group_id, std::slice::from_ref(&hash_bytes))
        .unwrap();
    hash_bytes
}

/// `counter` no longer feeds a version vector; it survives only as the
/// distinct `mtime_unix_nanos` that keeps successive versions of one path
/// distinguishable in these fixtures.
fn record(path: &str, counter: u64, blocks: Vec<BlockInfo>, size: u64) -> FileRecord {
    FileRecord { path: path.into(), size, mtime_unix_nanos: counter as i64, blocks, deleted: false }
}

/// `yadorilink versions <path>` succeeds and the underlying
/// `ListVersions` response (the exact data the CLI's `version_line`
/// renders — unit-tested for exact text shape in
/// `commands::version_history::tests`) is ordered newest first, including
/// the current version.
#[tokio::test]
async fn versions_command_lists_all_retained_versions_newest_first_including_current() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();

    let v1_bytes = put_and_record(&state, "group-1", b"first");
    let v1_block = BlockInfo { hash: v1_bytes, offset: 0, size: 5 };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("notes.txt", 1, vec![v1_block], 5),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let v2_bytes = put_and_record(&state, "group-1", b"second!");
    let v2_block = BlockInfo { hash: v2_bytes, offset: 0, size: 7 };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("notes.txt", 2, vec![v2_block], 7),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::versions(path.clone()).await.unwrap();

    let resp = control::send(ReqPayload::ListVersions(ListVersionsRequest { absolute_path: path }))
        .await
        .unwrap();
    let Some(RespPayload::ListVersions(list)) = resp.payload else { panic!("wrong response") };
    assert_eq!(list.versions.len(), 2);
    assert_eq!(list.versions[0].version_seq, 2, "newest first");
    assert_eq!(list.versions[0].state, "current");
    assert_eq!(list.versions[1].version_seq, 1);
    assert_eq!(list.versions[1].state, "superseded");
}

/// `yadorilink restore <path> --version <id>` succeeds and
/// writes the chosen version's content back to disk as a brand-new
/// current version.
#[tokio::test]
async fn restore_command_restores_a_specific_version_as_a_new_current_version() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    // A restore runs as one root-authorized operation (D10): it takes this
    // group's live `RootLease` before anything else, and a direct
    // `add_link` (never a real `start_link_watch`) installs none -- so
    // install the test lease `yadorilink-daemon`'s own restore tests use.
    state.install_test_root_commit_authority("group-1");
    // Writing a restored version back to disk verifies the root's adopted
    // identity first -- a direct `add_link` (never a real
    // `start_link_watch`) leaves no adopted root token behind, so this
    // fixture must adopt one itself, mirroring `yadorilink-daemon`'s own
    // `hydration.rs::seed_link` test helper.
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &folder,
        "group-1",
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let v1_bytes = put_and_record(&state, "group-1", b"original");
    let v1_block = BlockInfo { hash: v1_bytes, offset: 0, size: 8 };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", 1, vec![v1_block], 8),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let v2_bytes = put_and_record(&state, "group-1", b"edited!!");
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", 2, vec![BlockInfo { hash: v2_bytes, offset: 0, size: 8 }], 8),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let path = folder.join("todo.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::restore(path.clone(), Some(1)).await.unwrap();

    assert_eq!(std::fs::read(folder.join("todo.txt")).unwrap(), b"original");
    let versions =
        state.replica_coordinator.sqlite().dag_list_versions("group-1", "todo.txt").unwrap();
    assert_eq!(versions.len(), 3, "restore must add a new version, not rewrite history");
}

/// `yadorilink restore <path>` without `--version` defaults
/// to the most recent superseded version.
#[tokio::test]
async fn restore_command_without_version_defaults_to_most_recent_superseded() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    // See `restore_command_restores_a_specific_version_as_a_new_current_version`'s
    // identical comments.
    state.install_test_root_commit_authority("group-1");
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &folder,
        "group-1",
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let v1_bytes = put_and_record(&state, "group-1", b"first");
    let v1_block = BlockInfo { hash: v1_bytes, offset: 0, size: 5 };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", 1, vec![v1_block], 5),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("todo.txt", 2, vec![], 0),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let path = folder.join("todo.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::restore(path, None).await.unwrap();

    assert_eq!(std::fs::read(folder.join("todo.txt")).unwrap(), b"first");
}

/// The missing-blocks restore failure exits non-zero (via
/// `CliError::Other`'s existing `exit_code`, the same path every other
/// daemon-reported failure takes) with a message specifically identifying
/// unavailable version content, not a generic failure.
#[tokio::test]
async fn restore_command_fails_clearly_and_exits_non_zero_on_missing_blocks() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    // The restore's root lease is taken before the content lookup (D10);
    // without one this fails on the missing authority, not on the missing
    // blocks this test is about. See
    // `restore_command_restores_a_specific_version_as_a_new_current_version`.
    state.install_test_root_commit_authority("group-1");

    // A version referencing a block never actually written to this
    // device's block store.
    let phantom_block = BlockInfo {
        hash: {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"never fetched").to_vec()
        },
        offset: 0,
        size: 13,
    };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("phantom.bin", 1, vec![phantom_block], 13),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let path = folder.join("phantom.bin").to_string_lossy().to_string();
    let err = yadorilink_cli::commands::version_history::restore(path, Some(1)).await.unwrap_err();
    assert_ne!(err.exit_code(), 0, "a failed restore must exit non-zero");
    let CliError::Other(msg) = &err else { panic!("expected CliError::Other, got {err:?}") };
    assert!(
        msg.contains("unavailable") && msg.to_lowercase().contains("version"),
        "expected a message identifying unavailable version content, got {msg:?}"
    );
    assert!(!folder.join("phantom.bin").exists(), "a failed restore must not create a file");
}

/// `yadorilink trash list` shows a deleted file still within
/// retention, and `yadorilink trash restore <path>` recovers it.
#[tokio::test]
async fn trash_list_then_trash_restore_recovers_a_deleted_file() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("docs");
    std::fs::create_dir_all(&folder).unwrap();
    let local_path = folder.to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();
    // See `restore_command_restores_a_specific_version_as_a_new_current_version`'s
    // identical comments -- `trash restore` is the same root-authorized
    // restore and writes back to disk the same way.
    state.install_test_root_commit_authority("group-1");
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &folder,
        "group-1",
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let hash_bytes = put_and_record(&state, "group-1", b"soon deleted");
    let block = BlockInfo { hash: hash_bytes, offset: 0, size: 12 };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            "group-1",
            &record("gone.txt", 1, vec![block], 12),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .mark_deleted(
            "group-1",
            "gone.txt",
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    yadorilink_cli::commands::version_history::trash_list().await.unwrap();

    let resp = control::send(ReqPayload::ListTrash(ListTrashRequest {})).await.unwrap();
    let Some(RespPayload::ListTrash(list)) = resp.payload else { panic!("wrong response") };
    assert_eq!(list.files.len(), 1);
    assert_eq!(list.files[0].path, "gone.txt");
    assert_eq!(list.files[0].local_path, local_path);

    let path = folder.join("gone.txt").to_string_lossy().to_string();
    yadorilink_cli::commands::version_history::trash_restore(path).await.unwrap();

    assert_eq!(std::fs::read(folder.join("gone.txt")).unwrap(), b"soon deleted");
    let current = state
        .replica_coordinator
        .file_index_repository()
        .get_file("group-1", "gone.txt")
        .unwrap()
        .unwrap();
    assert!(!current.deleted, "the file must be live again after trash restore");
}
