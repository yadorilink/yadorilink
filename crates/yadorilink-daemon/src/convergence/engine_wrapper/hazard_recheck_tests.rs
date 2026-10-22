#![cfg(test)]

use super::{run_hazard_recheck_pass, DaemonState};
use ed25519_dalek::SigningKey;
use std::sync::Arc;
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_root_authority::root_identity::VerifiedRoot;

const GROUP: &str = "hazard-recheck-group";

fn empty_version(mtime: i64) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Same shape as `process_group_publication_tests::
/// build_state_with_adopted_group` (`engine.rs`), trimmed to what this
/// module needs: no candidate `PeerSyncSession` is registered, since
/// `DaemonState::local_retirement_session` builds its own synthetic
/// loopback session independently of `state.peers`.
async fn build_state_with_adopted_group() -> (Arc<DaemonState>, tempfile::TempDir) {
    let root_dir = tempfile::tempdir().unwrap();
    let root = root_dir.path().canonicalize().unwrap();
    let replica_coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let block_store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );

    replica_coordinator.link_repository().add_link(&root.to_string_lossy(), GROUP).unwrap();
    VerifiedRoot::open(&root, GROUP, replica_coordinator.as_ref()).unwrap();
    let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP);
    replica_coordinator.startup_readiness().mark_group_ready(GROUP, generation);

    let state = DaemonState::build("device-local".to_string(), replica_coordinator, block_store);
    state.test_root_commit_authorities.lock().unwrap().insert(
        GROUP.to_string(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );

    (state, root_dir)
}

fn admit_change(
    state: &DaemonState,
    device: &str,
    _key: &SigningKey,
    path: &str,
    version: &FileVersion,
) -> yadorilink_replica_domain::signed_delta::NativeDelta {
    crate::test_support::remote_admission_fixture::admit_remote(
        &state.replica_coordinator,
        GROUP,
        device,
        vec![crate::test_support::remote_admission_fixture::put(
            path,
            version.version_hash,
            vec![],
        )],
        std::slice::from_ref(version),
    )
}

/// The core regression: a path manually marked held (standing in for
/// any real hazard reason) with an already-admitted, trivially-
/// materializable native version gets written to disk and un-held by
/// `run_hazard_recheck_pass` alone -- no new incoming record for this
/// exact path is ever admitted or announced. RED-confirmed by
/// commenting out the `reconcile_paths_directly` call inside `run_
/// hazard_recheck_pass` (leaving only the empty-listing early return):
/// the held path then never gets re-examined at all, exactly the gap
/// this closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_path_is_re_examined_and_cleared_by_the_sweep_alone() {
    let (state, root_dir) = build_state_with_adopted_group().await;
    let key = SigningKey::from_bytes(&[81u8; 32]);
    let version = empty_version(1_700_000_000);
    admit_change(&state, "device-a", &key, "held.txt", &version);

    // `set_held` is an UPDATE on an existing `files` row (see its own
    // doc comment) -- production always reaches it through `hold_
    // record`, which upserts the index row first. Mirrors that here
    // directly rather than going through real hazard detection (see
    // this test module's own doc comment for why).
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            GROUP,
            &yadorilink_replica_domain::file::FileRecord {
                path: "held.txt".to_string(),
                size: 0,
                mtime_unix_nanos: 1_700_000_000,
                blocks: vec![],
                deleted: false,
            },
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_held(GROUP, "held.txt", "test_injected_hazard", 1_000)
        .unwrap();
    assert!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_held_state(GROUP, "held.txt")
            .unwrap()
            .is_some(),
        "sanity: the path must actually be held before the sweep runs"
    );

    state.replica_coordinator.hazard_recheck_wake().mark_dirty(GROUP);
    let pending = state.replica_coordinator.hazard_recheck_wake().pending();
    run_hazard_recheck_pass(&state, pending).await;

    assert!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_held_state(GROUP, "held.txt")
            .unwrap()
            .is_none(),
        "the sweep must clear a hold whose hazard is already gone, with no fresh incoming \
         record for this exact path"
    );
    assert!(
        root_dir.path().join("held.txt").exists(),
        "clearing the hold must come from a real, successful reconciliation -- the path \
         must actually materialize to disk, not just have its hold bit flipped"
    );
}

/// A group with nothing held at all must settle its generation on the
/// FIRST pass (the empty-listing early-return branch) -- otherwise a
/// busy group with no real hazards would spin `pending` forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_group_with_nothing_held_settles_immediately() {
    let (state, _root_dir) = build_state_with_adopted_group().await;

    state.replica_coordinator.hazard_recheck_wake().mark_dirty(GROUP);
    let pending = state.replica_coordinator.hazard_recheck_wake().pending();
    let generation = *pending.get(GROUP).unwrap();
    run_hazard_recheck_pass(&state, pending).await;

    assert_eq!(
        state.replica_coordinator.hazard_recheck_wake().pending().get(GROUP),
        None,
        "settled generation must not still be reported pending"
    );
    let _ = generation;
}

/// Seeds `path` as an existing, write-only (0o200) file whose index row
/// and admitted version name exactly its bytes, and whose version also
/// names a replicated `user.test` attribute the file does not carry: a
/// metadata repair this device can neither confirm nor apply. Returns the
/// file's path on disk, or `None` when running as root (nothing is
/// unreadable to root, so there is nothing to test).
#[cfg(target_os = "linux")]
fn seed_owner_unreadable_file_needing_an_xattr(
    state: &DaemonState,
    root: &std::path::Path,
    path: &str,
    content: &[u8],
) -> Option<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    use yadorilink_replica_domain::file::VersionBlock;
    use yadorilink_replica_domain::ids::BlockHash;
    let block_hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(content).into();
    let version = FileVersion::new(
        vec![VersionBlock { hash: BlockHash(block_hash.to_vec()), size: content.len() as u32 }],
        content.len() as u64,
        FileMeta {
            mtime_unix_nanos: 1_700_000_000,
            unix_mode: Some(0o200),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: vec![("user.test".to_string(), b"value".to_vec())],
        },
    );
    let key = SigningKey::from_bytes(&[82u8; 32]);
    admit_change(state, "device-a", &key, path, &version);
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file_with_origin(
            GROUP,
            &crate::local_convergence::types::file_record_from_version(path, &version),
            "device-a",
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let out_path = root.join(path);
    std::fs::write(&out_path, content).unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o200)).unwrap();
    if std::fs::File::open(&out_path).is_ok() {
        return None;
    }
    Some(out_path)
}

#[cfg(target_os = "linux")]
fn metadata_unprovable_holds(state: &DaemonState) -> usize {
    state
        .replica_coordinator
        .test_observers
        .metadata_unprovable_holds
        .load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(target_os = "linux")]
async fn run_one_recheck_pass(state: &Arc<DaemonState>) {
    state.replica_coordinator.hazard_recheck_wake().mark_dirty(GROUP);
    let pending = state.replica_coordinator.hazard_recheck_wake().pending();
    run_hazard_recheck_pass(state, pending).await;
    assert_eq!(
        state.replica_coordinator.hazard_recheck_wake().pending().get(GROUP),
        None,
        "every recheck pass must still complete its generation"
    );
}

/// A path held because its existing file is unreadable to its owner used
/// to be retried every backstop tick forever (and each retry could bump the
/// fence). The sweep must not re-attempt it while nothing it was held
/// against has changed -- same file, same mode, same fence, same version --
/// and must re-check it once the user makes it readable, which then
/// applies the attribute, restores the version's mode and lifts the hold.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_metadata_hold_is_not_rechecked_until_the_file_changes() {
    use std::os::unix::fs::PermissionsExt;
    let (state, root_dir) = build_state_with_adopted_group().await;
    let root = root_dir.path().canonicalize().unwrap();
    let content = b"an existing write-only file";
    let Some(out_path) =
        seed_owner_unreadable_file_needing_an_xattr(&state, &root, "write-only.txt", content)
    else {
        return;
    };

    state
        .local_convergence()
        .reconcile_paths(GROUP, ["write-only.txt".to_string()].into_iter().collect())
        .await
        .unwrap();
    let reason = yadorilink_peer_session::hazard::metadata_unprovable_reason();
    assert_eq!(
        state
            .replica_coordinator
            .get_held_state(GROUP, "write-only.txt")
            .unwrap()
            .map(|h| h.reason),
        Some(reason.clone()),
        "sanity: the reconcile must hold the path"
    );
    assert_eq!(metadata_unprovable_holds(&state), 1);
    let fence =
        state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, "write-only.txt").unwrap();

    run_one_recheck_pass(&state).await;
    run_one_recheck_pass(&state).await;

    assert_eq!(
        metadata_unprovable_holds(&state),
        1,
        "an unchanged metadata hold must not be re-attempted by the recheck sweep"
    );
    assert_eq!(
        state.replica_coordinator.dag_snapshot_mutation_fence(GROUP, "write-only.txt").unwrap(),
        fence,
        "the sweep must not bump the fence of an unchanged held path"
    );
    assert_eq!(
        state
            .replica_coordinator
            .get_held_state(GROUP, "write-only.txt")
            .unwrap()
            .map(|h| h.reason),
        Some(reason)
    );

    // The user makes the file readable: its mode and ctime change, so the
    // hold no longer describes the file and the next pass re-checks it.
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    run_one_recheck_pass(&state).await;

    assert_eq!(
        state.replica_coordinator.get_held_state(GROUP, "write-only.txt").unwrap(),
        None,
        "once the file is readable the re-check must settle the path and lift the hold"
    );
    assert_eq!(metadata_unprovable_holds(&state), 1, "a readable file is not held again");
    assert_eq!(std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777, 0o200);
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(std::fs::read(&out_path).unwrap(), content);
    assert_eq!(
        yadorilink_local_storage::read_replicated_xattrs(&std::fs::File::open(&out_path).unwrap()),
        vec![("user.test".to_string(), b"value".to_vec())],
        "the settled re-check must have applied the version's attribute"
    );
}

/// The hold is not silent: `yadorilink status` lists it as a held file
/// with the reason naming what cannot be done and why.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metadata_hold_is_reported_by_link_status_with_its_reason() {
    use crate::queries::link_status::LinkStatusReadPort as _;
    let (state, root_dir) = build_state_with_adopted_group().await;
    let root = root_dir.path().canonicalize().unwrap();
    if seed_owner_unreadable_file_needing_an_xattr(&state, &root, "write-only.txt", b"bytes")
        .is_none()
    {
        return;
    }

    state
        .local_convergence()
        .reconcile_paths(GROUP, ["write-only.txt".to_string()].into_iter().collect())
        .await
        .unwrap();

    let views = crate::adapters::query::link_status::DaemonLinkStatusReader::new(state.clone())
        .list_links()
        .unwrap();
    let held: Vec<_> = views
        .iter()
        .filter(|view| view.group_id == GROUP)
        .flat_map(|view| view.held_files.iter())
        .map(|held| (held.path.as_str(), held.reason.as_str()))
        .collect();
    assert_eq!(
        held,
        vec![(
            "write-only.txt",
            "metadata_unprovable: replicated xattrs cannot be confirmed or applied because the \
             existing file is owner-unreadable"
        )]
    );
}
