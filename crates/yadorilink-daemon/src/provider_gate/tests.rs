#![cfg(test)]

//! A provider-backed root that is not ready fails closed: it starts nothing, authors
//! nothing, hydrates nothing and tombstones nothing. The decision is per root.

use std::path::Path;
use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::RealFolderWatchSource;
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{LocalWriteKind, LocalWriteRequest, ShellIpcMessage};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::provider::ProviderDeclaration;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;
use crate::shell_context::ShellContext;

use super::*;

const GROUP: &str = "group-1";

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

fn declare(state: &DaemonState, local_path: &str) -> String {
    state.replica_coordinator.link_repository().add_link(local_path, GROUP).unwrap();
    state
        .replica_coordinator
        .provider_repository()
        .declare_root(GROUP, ProviderKind::MacFileProvider, "Photos")
        .unwrap()
}

fn make_ready(state: &DaemonState, root: &str) {
    let repo = state.replica_coordinator.provider_repository();
    repo.set_domain_registered(root, true).unwrap();
    repo.record_extension_handshake(root, 1).unwrap();
}

fn start(state: &Arc<DaemonState>, root: &Path) -> Result<(), crate::error::DaemonError> {
    LinkRuntimeController::new(state.clone()).start_with_source(
        root.to_string_lossy().into_owned(),
        GROUP.to_string(),
        Arc::new(RealFolderWatchSource),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_plain_root_reaches_the_filesystem_pipeline() {
    let state = test_state();
    // A group whose link declares no provider is plain: unchanged.
    state.replica_coordinator.link_repository().add_link("/plain", "plain").unwrap();
    assert!(require_filesystem_root(&state.replica_coordinator, "plain").is_ok());

    // A provider root is closed to it at every stage, ready included.
    let root = declare(&state, "/provider/photos");
    let refused = || {
        let error = require_filesystem_root(&state.replica_coordinator, GROUP).unwrap_err();
        assert!(matches!(error, SyncError::NotFilesystemRoot(_)), "{error:?}");
        assert!(error.to_string().contains("provider-backed"), "{error}");
    };
    refused();
    make_ready(&state, &root);
    refused();
    state.replica_coordinator.provider_repository().record_provider_error(&root, "bad").unwrap();
    refused();
}

/// OnDemand is a per-root decision: only a READY provider root may; a plain (`ProviderKind::None`) root
/// never enters the File Provider capability, and a not-ready provider root refuses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn on_demand_is_allowed_per_root_by_provider_readiness() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/plain", "plain").unwrap();
    assert!(!state.root_allows_on_demand("plain"), "a plain root entered the provider capability");
    let root = declare(&state, "/provider/photos");
    assert!(!state.root_allows_on_demand(GROUP), "a not-ready provider root allowed OnDemand");
    make_ready(&state, &root);
    assert!(state.root_allows_on_demand(GROUP));
    assert!(!state.root_allows_on_demand("other-group"), "the decision leaked to another root");
    state.replica_coordinator.provider_repository().record_provider_error(&root, "x").unwrap();
    assert!(!state.root_allows_on_demand(GROUP));
}

/// A provider root never enters the filesystem runtime, ready or not: no watch, no scan,
/// no tombstones. The directory is not read, so a path missing from it is no evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_root_never_scans_or_tombstones() {
    let state = test_state();
    let dir = tempfile::tempdir().unwrap();
    let root = declare(&state, &dir.path().to_string_lossy());
    // An indexed file the directory does not have: a scan would tombstone it.
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "gone.txt".into(),
                size: 1,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    std::fs::write(dir.path().join("a.txt"), b"user file").unwrap();

    for ready in [false, true] {
        if ready {
            make_ready(&state, &root);
        }
        let error = start(&state, dir.path()).expect_err("a provider root started");
        assert!(error.to_string().contains("provider-backed"), "{error}");
        let index = state.replica_coordinator.file_index_repository();
        assert!(index.get_file(GROUP, "a.txt").unwrap().is_none(), "ready={ready}: scanned");
        assert!(
            index.get_file(GROUP, "gone.txt").unwrap().is_some_and(|row| !row.deleted),
            "ready={ready}: a missing path was tombstoned"
        );
    }
}

/// A link that declares a provider while its provider state is gone (a restore that kept the
/// link) is corrupt, not plain: the runtime does not start and the text says rebootstrap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_provider_state_fails_closed_with_rebootstrap_required() {
    let state = test_state();
    let dir = tempfile::tempdir().unwrap();
    let root = declare(&state, &dir.path().to_string_lossy());
    make_ready(&state, &root);
    state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM provider_roots", [])?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        state.replica_coordinator.provider_repository().declaration_for_group(GROUP).unwrap(),
        ProviderDeclaration::Corrupt(_)
    ));
    std::fs::write(dir.path().join("a.txt"), b"x").unwrap();

    let error = start(&state, dir.path()).expect_err("a root with lost provider state started");
    assert!(error.to_string().contains("rebootstrap required"), "{error}");
    assert!(state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, "a.txt")
        .unwrap()
        .is_none());
    let hydrate = crate::hydration::hydrate(&state, GROUP, "a.txt").await.unwrap_err();
    assert!(hydrate.to_string().contains("rebootstrap required"), "{hydrate}");
}

/// A hydration request for a provider root fails closed before touching anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_root_hydrates_nothing() {
    let state = test_state();
    let root = declare(&state, "/provider/photos");
    for ready in [false, true] {
        if ready {
            make_ready(&state, &root);
        }
        let error = crate::hydration::hydrate(&state, GROUP, "a.txt").await.unwrap_err();
        assert!(matches!(error, SyncError::NotFilesystemRoot(_)), "{error:?}");
    }
}

/// Every admission refuses once a group is declared a provider root, including a flush or
/// rescan that was already queued by a runtime started while the root was plain: the
/// verification every scan, flush and event begins with is refused, so nothing is authored
/// and nothing is tombstoned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_flush_after_the_group_becomes_a_provider_root_authors_nothing() {
    use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
    let state = test_state();
    let dir = tempfile::tempdir().unwrap();
    let local_path = dir.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&local_path, GROUP).unwrap();
    start(&state, dir.path()).unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.replica_coordinator.wait_group_ready(GROUP),
    )
    .await
    .unwrap()
    .unwrap();
    std::fs::write(dir.path().join("kept.txt"), b"first").unwrap();
    let ctx = ShellContext::from_state(state.clone());
    let request = |relative_path: &str, kind: LocalWriteKind| ShellIpcMessage {
        payload: Some(Payload::LocalWriteRequest(LocalWriteRequest {
            local_path: local_path.clone(),
            relative_path: relative_path.to_string(),
            kind: kind as i32,
        })),
    };
    assert!(
        crate::shell_ipc::handle_message_for_tests(
            &ctx,
            request("kept.txt", LocalWriteKind::CreatedOrModified)
        )
        .await,
        "a plain root must accept a write"
    );

    // The group is now declared a provider root (even a READY one).
    let root = state
        .replica_coordinator
        .provider_repository()
        .declare_root(GROUP, ProviderKind::MacFileProvider, "Photos")
        .unwrap();
    make_ready(&state, &root);

    // A queued event for the already-running processor.
    let processor = yadorilink_local_capture::LocalChangeProcessor::new(
        state.replica_coordinator.clone(),
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap()),
        "device-a".into(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );
    std::fs::write(dir.path().join("new.txt"), b"second").unwrap();
    let outcome = processor
        .process_event(
            GROUP,
            dir.path(),
            &FsChangeEvent {
                path: dir.path().join("new.txt"),
                kind: FsChangeKind::CreatedOrModified,
            },
        )
        .await;
    assert!(outcome.is_err(), "a queued event was admitted for a provider root");
    assert!(state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, "new.txt")
        .unwrap()
        .is_none());
    // A rescan and a write/delete notification are refused too.
    assert!(processor.scan_existing_files(GROUP, dir.path()).is_err(), "a rescan was admitted");
    std::fs::remove_file(dir.path().join("kept.txt")).unwrap();
    assert!(
        !crate::shell_ipc::handle_message_for_tests(
            &ctx,
            request("kept.txt", LocalWriteKind::Deleted)
        )
        .await
    );
    let kept =
        state.replica_coordinator.file_index_repository().get_file(GROUP, "kept.txt").unwrap();
    assert!(kept.is_some_and(|row| !row.deleted), "a provider root tombstoned a file");
}

// ---- ONE admission for every disk-touching entry ----

fn corrupt(state: &DaemonState) {
    state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM provider_roots", [])?;
            Ok(())
        })
        .unwrap();
}

/// Every way an entry verifies a root (local mutation, peer apply, materialization and repair,
/// hydration and restore all go through `VerifiedRoot`) is refused for a provider root, ready
/// or not, and for one with lost provider state: no entry can reach the directory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_root_verification_entry_refuses_a_provider_root() {
    use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionPort;
    use yadorilink_local_capture::ports::LocalMutationStore;
    use yadorilink_root_authority::root_identity::VerifiedRoot;

    for stage in ["not ready", "ready", "lost state"] {
        let state = test_state();
        let dir = tempfile::tempdir().unwrap();
        let root = declare(&state, &dir.path().to_string_lossy());
        match stage {
            "ready" => make_ready(&state, &root),
            "lost state" => corrupt(&state),
            _ => {}
        }
        let coordinator = state.replica_coordinator.as_ref();
        let path = dir.path();
        let refused = [
            ("VerifiedRoot::verify", VerifiedRoot::verify(path, GROUP, coordinator).is_err()),
            ("VerifiedRoot::open", VerifiedRoot::open(path, GROUP, coordinator).is_err()),
            ("peer apply verify_root", coordinator.verify_root(path, GROUP).is_err()),
            (
                "local mutation verify_root",
                LocalMutationStore::verify_root(coordinator, path, GROUP).is_err(),
            ),
            (
                "local mutation open_root",
                LocalMutationStore::open_root(coordinator, path, GROUP).is_err(),
            ),
            (
                "materialization verify_root",
                MaterializationExecutionPort::verify_root(coordinator, path, GROUP).is_err(),
            ),
            (
                "materialization open_root",
                MaterializationExecutionPort::open_root(coordinator, path, GROUP).is_err(),
            ),
        ];
        for (entry, was_refused) in refused {
            assert!(was_refused, "{stage}: {entry} admitted a provider root");
        }
    }
}

/// The control: a plain root is still admitted by the same funnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_root_is_still_admitted() {
    use yadorilink_root_authority::root_identity::VerifiedRoot;
    let state = test_state();
    let dir = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&dir.path().to_string_lossy(), GROUP)
        .unwrap();
    VerifiedRoot::open(dir.path(), GROUP, state.replica_coordinator.as_ref())
        .expect("a plain root must be admitted");
}

/// A grep-style guard: the admission above only protects entries that verify a root through
/// `VerifiedRoot`, so a new production file that constructs one is a new disk-touching entry and
/// must be looked at (it must pass the coordinator, which carries the admission). The list is the
/// files that construct `VerifiedRoot` today (conflict resolution verifies with the coordinator
/// passed, so a provider root is refused there too).
#[test]
fn only_the_known_files_construct_a_verified_root() {
    const ALLOWED: &[&str] = &[
        "crates/yadorilink-daemon/src/conflict_resolution.rs",
        "crates/yadorilink-daemon/src/hydration.rs",
        "crates/yadorilink-daemon/src/replica_coordinator/local_mutation.rs",
        "crates/yadorilink-daemon/src/replica_coordinator/materialization_execution.rs",
        "crates/yadorilink-daemon/src/replica_coordinator/peer_replica_state.rs",
        "crates/yadorilink-root-authority/src/root_identity.rs",
    ];
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut found = Vec::new();
    let mut stack = vec![repo_root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if path.is_dir() {
                if !["tests", "target", "examples", "test_support"].contains(&name.as_str()) {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") && !name.contains("test") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                let constructs = text.lines().any(|line| {
                    let code = line.split("//").next().unwrap_or("");
                    code.contains("VerifiedRoot::open(") || code.contains("VerifiedRoot::verify(")
                });
                if constructs {
                    let rel =
                        path.strip_prefix(&repo_root).unwrap().to_string_lossy().replace('\\', "/");
                    found.push(rel.replace("/./", "/"));
                }
            }
        }
    }
    found.sort();
    for file in &found {
        assert!(
            ALLOWED.iter().any(|allowed| file.ends_with(allowed)),
            "{file} constructs a VerifiedRoot: a new disk-touching entry. It must pass the replica \
             coordinator (which refuses provider roots); add it to this list once it does"
        );
    }
}

/// Startup recovery decides nothing about a provider root's directory: its stranded rows keep
/// their markers, nothing is inspected or promoted (a plain root's identical row is promoted).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_recovery_skips_provider_roots_before_any_disk_inspection() {
    let state = test_state();
    let provider_dir = tempfile::tempdir().unwrap();
    declare(&state, &provider_dir.path().to_string_lossy());
    let plain_dir = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&plain_dir.path().to_string_lossy(), "plain")
        .unwrap();
    for (group, dir) in [(GROUP, provider_dir.path()), ("plain", plain_dir.path())] {
        std::fs::write(dir.join("object.txt"), b"an object stands here").unwrap();
        state
            .replica_coordinator
            .database()
            .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, materialization_state) VALUES (?1, 'object.txt', 0, 0, '[]', 0, 'hydrating')",
                    [group],
                )?;
                Ok(())
            })
            .unwrap();
    }

    let _ = state.replica_coordinator.reset_stale_transient_states();

    let state_of = |group: &str| {
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(group, "object.txt")
            .unwrap()
    };
    use yadorilink_replica_domain::session_state::MaterializationState;
    assert_eq!(
        state_of("plain"),
        Some(MaterializationState::Present),
        "the control was not recovered"
    );
    assert_eq!(
        state_of(GROUP),
        Some(MaterializationState::Hydrating),
        "startup recovery inspected or promoted a provider root's directory"
    );
}

/// Peer reconciliation of a provider group never gets a root: the orchestrator's root map
/// skips it, the convergence entry refuses it, and no relative path is created from the locator.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_group_never_reaches_peer_reconciliation_roots() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/plain", "plain").unwrap();
    let locator = "provider://token-1";
    declare(&state, locator);

    let roots = crate::peer_orchestrator::sync_roots_for_groups(
        &state,
        &["plain".to_string(), GROUP.to_string()],
    );
    assert_eq!(roots.keys().collect::<Vec<_>>(), ["plain"], "a provider group got a root");

    let gate = state.replica_coordinator.link_repository().link_gate_for_group(GROUP);
    assert!(gate.is_err(), "the link gate handed out a root for a provider group: {gate:?}");

    // Nothing on disk is named like the locator, relative to the working directory.
    assert!(!std::path::Path::new("provider:").exists());
    assert!(!std::path::Path::new(locator).exists());
}

/// Space is given back only by a ready provider folder: an ordinary folder is refused by the
/// ordinary eviction gate with a reason, and the menu flag agrees with the gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_ready_provider_root_may_give_space_back() {
    let state = test_state();
    // An ordinary folder.
    state.replica_coordinator.link_repository().add_link("/plain", GROUP).unwrap();
    let refused = crate::hydration::evict_gate(&state, GROUP, "a.bin").unwrap_err();
    assert!(refused.to_string().contains("only available for provider folders"), "{refused}");
    assert!(!state.root_allows_on_demand(GROUP));

    // A provider root that is not ready yet.
    let state = test_state();
    let root = declare(&state, "/provider");
    assert!(!state.root_allows_on_demand(GROUP));
    assert!(crate::hydration::evict_gate(&state, GROUP, "a.bin").is_err());

    // Ready: the provider eviction path serves it; the ordinary gate (plain roots) still refuses,
    // so a request can never be half-served by both.
    make_ready(&state, &root);
    assert!(state.root_allows_on_demand(GROUP));
    assert!(crate::hydration::evict_gate(&state, GROUP, "a.bin").is_err());
}
