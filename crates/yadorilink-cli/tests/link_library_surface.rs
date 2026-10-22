//! The `commands::link` library surface
//! the onboarding window drives (`run_link_preflight` + `link_resolved`),
//! exercised against a real daemon over the actual control socket — the same
//! harness pattern `materialization.rs`/`gc.rs` use. Like those, the link
//! path needs no coordination-plane/auth setup (the group_id is opaque to the
//! daemon), so it is testable directly at the CLI-command layer.
//!
//! The coordination-plane library fns
//! (`device::register_device`, `share::{create_and_link, join}`) are the sole
//! implementations behind their unchanged CLI subcommands — the existing CLI
//! behavior is pinned by those subcommands staying byte-identical — but they
//! hit the Cloudflare-hosted coordination plane over HTTP, for which no
//! in-repo test server exists, so they are not integration-tested here.
#![cfg(unix)]

use std::sync::Arc;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

async fn start_daemon() -> (tempfile::TempDir, Arc<DaemonState>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);
    // A registered (non-empty device_id) device with no change-signing key is
    // fail-closed (`link_manager::ensure_initial_change_history`): linking a
    // folder refuses index-only sync rather than leave emission silently
    // off. Wire one before any test here links.
    state.set_device_signing_key(yadorilink_transport::DeviceSigningKeyPair::generate().signing);
    // The link preflight's free-space reading is of the real volume under the test's TMPDIR; pin the
    // reserve so the result does not depend on how full the host disk is.
    state.set_link_preflight_headroom_override_for_tests(Some(0));

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

/// the window's preflight is the same shared computation the CLI uses —
/// an empty folder raises no non-empty-folder warning, and `link_resolved`
/// registers it with the daemon (which only gates on nested-link conflicts,
/// so a non-nested link registers regardless of free-space classification —
/// low disk being a CLI/UI-layer guardrail the user acknowledges up front).
#[tokio::test]
async fn empty_folder_previews_clean_and_links() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let folder = dir.path().join("empty-shared");
    std::fs::create_dir_all(&folder).unwrap();

    let (absolute, report) =
        yadorilink_client_core::ops::links::run_link_preflight(&folder.to_string_lossy())
            .await
            .unwrap();
    // Free-space state is environment-dependent, so we assert on the folder
    // contents specifically rather than the aggregate `is_risky`.
    assert!(report.is_empty_folder(), "temp folder should scan as empty");
    assert!(
        !report.warnings().iter().any(|w| w.contains("not empty")),
        "an empty folder must not raise a non-empty warning, got {:?}",
        report.warnings()
    );

    yadorilink_client_core::ops::links::link_resolved(absolute, "group-1".into(), false)
        .await
        .unwrap();

    let linked: Vec<String> = state
        .replica_coordinator
        .link_repository()
        .list_links()
        .unwrap()
        .into_iter()
        .map(|l| l.key().to_string())
        .collect();
    assert!(
        linked.iter().any(|p| p == &folder.canonicalize().unwrap().to_string_lossy()),
        "the linked folder should now be registered with the daemon, got {linked:?}"
    );
}

/// a non-empty folder surfaces the shared "folder is not empty" warning
/// that the window renders as an acknowledgement card — the machine gates the
/// confirm on this exact warning set.
#[tokio::test]
async fn non_empty_folder_surfaces_a_warning() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, _state) = start_daemon().await;
    let folder = dir.path().join("has-content");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("existing.txt"), b"hi").unwrap();

    let (_absolute, report) =
        yadorilink_client_core::ops::links::run_link_preflight(&folder.to_string_lossy())
            .await
            .unwrap();
    assert!(report.is_risky());
    assert!(
        report.warnings().iter().any(|w| w.contains("not empty")),
        "expected a non-empty-folder warning, got {:?}",
        report.warnings()
    );
}

/// Linking a folder that nests an existing link is an unsupported topology:
/// the daemon refuses it with and without the aggregate acknowledgement, naming
/// the conflicting link, and registers nothing.
#[tokio::test]
async fn nested_link_is_refused_with_and_without_ack() {
    let _guard = TEST_MUTEX.lock().await;
    let (dir, state) = start_daemon().await;
    let parent = dir.path().join("parent");
    let child = parent.join("child");
    std::fs::create_dir_all(&child).unwrap();

    // Register the child link first — it has no nested conflict.
    let (child_abs, child_report) =
        yadorilink_client_core::ops::links::run_link_preflight(&child.to_string_lossy())
            .await
            .unwrap();
    assert!(child_report.nested_conflicts.is_empty());
    yadorilink_client_core::ops::links::link_resolved(
        child_abs.clone(),
        "group-child".into(),
        false,
    )
    .await
    .unwrap();

    // Now the parent nests an existing link: preflight detects it as a
    // prohibition (not an acknowledgeable risk) and the daemon refuses it
    // whatever the acknowledgement says.
    let (parent_abs, parent_report) =
        yadorilink_client_core::ops::links::run_link_preflight(&parent.to_string_lossy())
            .await
            .unwrap();
    assert!(
        !parent_report.structural_prohibitions().is_empty(),
        "preflight should detect the nested child link"
    );

    for acknowledge in [false, true] {
        let refused = yadorilink_client_core::ops::links::link_resolved(
            parent_abs.clone(),
            "group-parent".into(),
            acknowledge,
        )
        .await
        .expect_err("a nested link must be refused whatever acknowledge_risks says");
        assert!(
            refused.to_string().contains(&child_abs.to_string_lossy().to_string()),
            "the refusal must name the conflicting link, got {refused}"
        );
    }

    let linked: Vec<String> = state
        .replica_coordinator
        .link_repository()
        .list_links()
        .unwrap()
        .into_iter()
        .map(|l| l.key().to_string())
        .collect();
    assert_eq!(linked, vec![child_abs.to_string_lossy().to_string()], "nothing else was linked");
}
