//! `yadorilink evict` end-to-end against a
//! real daemon over the actual control socket — unlike `link`/`status`,
//! these commands need no coordination-plane/auth setup at all, so they're
//! testable directly at the CLI-command layer (not just the daemon's
//! protocol layer, already covered by `yadorilink-daemon`'s own tests).
//!
//! Unix-only (Windows local IPC support): drives the daemon via
//! `unix_transport::serve` directly rather than testing the transport
//! itself (that's `yadorilink-daemon`'s own `control_socket.rs`/`shell_ipc.rs`
//! test files' job, which do cover the Windows named-pipe path) — was
//! already implicitly Unix-only before that change.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

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

/// Tests in this file share `YADORILINK_CONTROL_SOCKET` (a process-global env
/// var) and so must not run concurrently with each other.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A linked folder holding one indexed, hydrated file `notes.txt`.
async fn seeded_hydrated_file() -> (tempfile::TempDir, Arc<DaemonState>, std::path::PathBuf) {
    let (dir, state) = start_daemon().await;
    state.set_test_on_demand_allowed(true);
    let folder = dir.path().join("shared");
    std::fs::create_dir_all(&folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    // A direct `add_link` (never a real `start_link_watch`) leaves no live
    // root lease behind for `evict`'s `root_lease_for` lookup to find --
    // `install_test_root_commit_authority` registers the same
    // always-valid, test-only lease `yadorilink-daemon`'s own equivalent
    // fixtures use for exactly this reason.
    state.install_test_root_commit_authority("group-1");
    // `evict_file` also verifies the root's adopted identity before
    // touching it -- without this, eviction fails closed with "no
    // previously-adopted root token", the same fixture step
    // `yadorilink-daemon`'s own `hydration.rs::seed_link` test helper takes
    // for the identical reason.
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &folder,
        "group-1",
        state.replica_coordinator.as_ref(),
    )
    .unwrap();

    let content = vec![5u8; 500];
    std::fs::write(folder.join("notes.txt"), &content).unwrap();
    // The indexed hash must be the file's real content hash, not a
    // placeholder: `evict_file` verifies on-disk bytes against it before
    // reclaiming anything, and silently no-ops (`Ok`, nothing evicted) on a
    // mismatch rather than erroring -- same fixture requirement
    // `yadorilink-daemon`'s own `tests/control_socket.rs` documents for the
    // identical scenario.
    let hash = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&content).to_vec()
    };
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: 500,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash, offset: 0, size: 500 }],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // `upsert_file` no longer implies `Hydrated` (schema v25 changed the
    // column default to `Placeholder` -- see `set_materialization_state_
    // in_tx`'s doc comment): this fixture writes real matching content
    // directly to disk to simulate an already-hydrated file, so it must
    // say so explicitly now, same as every other caller of this pattern.
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            "notes.txt",
            MaterializationState::Present,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    (dir, state, folder)
}

/// on-demand-sync spec "Evicting a hydrated file frees local disk space".
#[tokio::test]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "removing an evicted file needs the Linux write lease"
)]
async fn evict_command_removes_a_present_file_and_leaves_its_row_remote() {
    let _guard = TEST_MUTEX.lock().await;
    // `evict` refuses outright unless a placeholder provider is connected
    // -- see `hydration::evict`'s own doc comment; this test exercises the
    // actual eviction mechanics, so it forces that gate open for its own
    // thread, the same way `yadorilink-daemon`'s own eviction tests do.
    let (_dir, state, folder) = seeded_hydrated_file().await;
    yadorilink_cli::commands::materialization::evict(
        folder.join("notes.txt").to_string_lossy().to_string(),
    )
    .await
    .unwrap();

    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state("group-1", "notes.txt")
            .unwrap(),
        Some(MaterializationState::Remote)
    );
    assert!(
        std::fs::symlink_metadata(folder.join("notes.txt")).is_err(),
        "an evicted file must no longer stand in the user tree"
    );
}

/// `yadorilink pin` keeps a file: Free Up Space is refused while it is kept, the file stays
/// whole, and unpinning removes nothing.
#[tokio::test]
async fn pin_command_makes_evict_refuse_and_unpin_removes_nothing() {
    let _guard = TEST_MUTEX.lock().await;
    let (_dir, state, folder) = seeded_hydrated_file().await;
    let file = folder.join("notes.txt").to_string_lossy().to_string();

    yadorilink_cli::commands::materialization::pin(file.clone()).await.unwrap();
    let refused = yadorilink_cli::commands::materialization::evict(file.clone()).await;

    let message = refused.expect_err("a kept file must not be freed").to_string();
    assert!(message.contains("kept on this device"), "{message}");
    assert!(folder.join("notes.txt").exists());
    let materialization = state.replica_coordinator.materialization_state_repository();
    assert_eq!(
        materialization.get_materialization_state("group-1", "notes.txt").unwrap(),
        Some(MaterializationState::Present)
    );

    yadorilink_cli::commands::materialization::unpin(file).await.unwrap();
    assert!(folder.join("notes.txt").exists(), "unpinning never removes content");
    assert_eq!(
        materialization.get_materialization_state("group-1", "notes.txt").unwrap(),
        Some(MaterializationState::Present)
    );
}
