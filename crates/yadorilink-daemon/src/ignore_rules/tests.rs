#![cfg(test)]

use std::sync::Arc;

use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_root_authority::root_identity::VerifiedRoot;
use yadorilink_sync_sqlite::projection_obligations::NonExactProofKind;

use super::{IgnoreRulesError, IgnoreRulesService};
use crate::daemon_state::DaemonState;

const GROUP: &str = "ignore-rules-group";

/// A daemon with its own state directory and one linked folder.
fn linked_state() -> (Arc<DaemonState>, tempfile::TempDir) {
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
    let state = DaemonState::build_in(
        tempfile::tempdir().unwrap().keep(),
        "device-local".to_string(),
        replica_coordinator,
        block_store,
    );
    (state, root_dir)
}

#[tokio::test]
async fn rules_round_trip_and_a_folder_without_rules_reads_empty() {
    let (state, _root) = linked_state();
    let service = IgnoreRulesService::new(state);
    assert_eq!(service.get(GROUP).unwrap(), "");

    service.set(GROUP, "*.tmp\n!keep.tmp\n").await.unwrap();
    assert_eq!(service.get(GROUP).unwrap(), "*.tmp\n!keep.tmp\n");

    service.set(GROUP, "").await.unwrap();
    assert_eq!(service.get(GROUP).unwrap(), "");
}

#[tokio::test]
async fn invalid_text_is_refused_with_its_line_and_the_stored_rules_stay() {
    let (state, _root) = linked_state();
    let service = IgnoreRulesService::new(state);
    service.set(GROUP, "keep.me\n").await.unwrap();

    let error = service.set(GROUP, "fine\n# comment\nbad//line\n").await.unwrap_err();

    assert!(matches!(error, IgnoreRulesError::Invalid(_)), "{error:?}");
    assert!(error.to_string().starts_with("line 3:"), "{error}");
    assert_eq!(service.get(GROUP).unwrap(), "keep.me\n");
}

#[tokio::test]
async fn an_unknown_folder_is_refused_and_nothing_is_stored() {
    let (state, _root) = linked_state();
    let service = IgnoreRulesService::new(state.clone());

    assert_eq!(service.get("nope").unwrap_err(), IgnoreRulesError::UnknownGroup("nope".into()));
    assert_eq!(
        service.set("nope", "*.tmp\n").await.unwrap_err(),
        IgnoreRulesError::UnknownGroup("nope".into())
    );
    let store = yadorilink_fs_platform::ignore_patterns::IgnoreRulesStore::new(state.config_dir());
    assert_eq!(store.read("nope").unwrap(), "");
}

fn empty_version() -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: 1_700_000_000,
            exec: false,
            symlink_target: None,
            record_kind: RecordKind::File,
        },
    )
}

/// A path parked because it was ignored.
fn park_ignored(state: &DaemonState, path: &str) {
    let version = empty_version();
    crate::test_support::remote_admission_fixture::admit_remote(
        &state.replica_coordinator,
        GROUP,
        "device-a",
        vec![crate::test_support::remote_admission_fixture::put(
            path,
            version.version_hash,
            vec![],
        )],
        std::slice::from_ref(&version),
    );
    let sqlite = state.replica_coordinator.sqlite();
    let obligation = sqlite.dag_lookup_projection_obligation(GROUP, path).unwrap().unwrap();
    assert!(sqlite
        .dag_complete_obligation_if_non_exact_proof_current(
            GROUP,
            path,
            obligation.invalidation_generation,
            obligation.obligation_incarnation,
            NonExactProofKind::IgnoreExcluded,
        )
        .unwrap());
}

fn obligation_state(state: &DaemonState, path: &str) -> String {
    state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(GROUP, path)
        .unwrap()
        .unwrap()
        .state
}

/// Setting the rules runs the engine's ignore recheck: a path parked as ignored is handed back
/// when the new rules no longer ignore it, and stays parked while they still do.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn setting_the_rules_rechecks_the_paths_parked_as_ignored() {
    let (state, _root) = linked_state();
    let service = IgnoreRulesService::new(state.clone());
    park_ignored(&state, "was-ignored.txt");
    assert_eq!(obligation_state(&state, "was-ignored.txt"), "ignore_blocked");

    service.set(GROUP, "was-ignored.txt\n").await.unwrap();
    assert_eq!(obligation_state(&state, "was-ignored.txt"), "ignore_blocked", "still ignored");

    service.set(GROUP, "other.txt\n").await.unwrap();
    assert_eq!(obligation_state(&state, "was-ignored.txt"), "pending", "no longer ignored");
}
