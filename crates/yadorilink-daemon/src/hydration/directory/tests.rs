#![cfg(test)]

//! A folder asked for through the materialization port acts on the files
//! below it: its status reads them and its eviction frees them.

use std::sync::Arc;

use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::adapters::runtime::materialization::DaemonMaterializationAdapter;
use crate::application::ports::MaterializationPort;
use crate::daemon_state::DaemonState;
use crate::sync_error::SyncError;

const GROUP: &str = "group-1";

fn state_with_link() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", GROUP).unwrap();
    DaemonState::new("device-a".into(), coordinator, store)
}

fn file(state: &DaemonState, path: &str, materialization: MaterializationState) {
    let permit = RootCommitPermit::for_tests();
    let coordinator = &state.replica_coordinator;
    coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: path.into(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, path, materialization, &permit)
        .unwrap();
}

/// A folder reads as the least materialized state of the files below it,
/// the link root included.
#[tokio::test]
async fn a_folder_status_reads_the_files_below_it() {
    let state = state_with_link();
    file(&state, "trips/2026/beach.jpg", MaterializationState::Present);
    file(&state, "trips/notes.txt", MaterializationState::Remote);
    let port = DaemonMaterializationAdapter::new(state.clone());

    let status = |path: &str| port.status(GROUP, path).unwrap().expect("a folder has a status");
    let here = |path: &str| {
        let state = status(path).state;
        (state.object_present, state.current_content_present)
    };
    assert_eq!(here("trips/"), (false, false));
    assert_eq!(here("trips/2026"), (true, true));
    assert_eq!(here(""), (false, false));
}

/// A folder eviction refused before it starts -- no placeholder pipeline
/// here -- changes nothing below it.
#[tokio::test]
async fn a_refused_folder_eviction_changes_nothing() {
    let state = state_with_link();
    file(&state, "trips/beach.jpg", MaterializationState::Present);
    let port = DaemonMaterializationAdapter::new(state.clone());

    state.set_test_on_demand_allowed(false);
    assert!(matches!(port.evict(GROUP, "trips"), Err(SyncError::EvictionRejected(_))));
    assert_eq!(
        state
            .replica_coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, "trips/beach.jpg")
            .unwrap(),
        Some(MaterializationState::Present)
    );
}

/// Free Up Space on an ordinary linked folder is refused for a stated reason, the same one for a
/// file and a folder, and the shell menu is not offered it: only a File Provider folder can
/// give space back, because an ordinary folder has no placeholder to leave in the file's place.
#[tokio::test]
async fn an_ordinary_folder_says_why_free_up_space_is_not_available() {
    let state = state_with_link();
    file(&state, "trips/beach.jpg", MaterializationState::Present);
    let port = DaemonMaterializationAdapter::new(state.clone());

    assert!(!port.evict_supported(GROUP));
    for path in ["trips", "trips/beach.jpg"] {
        let Err(SyncError::EvictionRejected(why)) = port.evict(GROUP, path) else {
            panic!("{path}: an ordinary folder was freed");
        };
        assert!(why.contains("File Provider"), "{why}");
        assert!(!why.contains("in this build"), "{why}");
    }
}

/// Evicting a folder with nothing hydrated below it frees nothing and is
/// not an error.
#[tokio::test]
async fn evicting_a_folder_with_nothing_hydrated_frees_nothing() {
    let state = state_with_link();
    file(&state, "trips/beach.jpg", MaterializationState::Remote);
    let port = DaemonMaterializationAdapter::new(state.clone());
    state.set_test_on_demand_allowed(true);
    let outcome = port.evict(GROUP, "trips").unwrap();
    assert!(!outcome.dehydrated, "nothing below it was hydrated");
}

fn freed(bytes: u64) -> Result<super::FileEviction, SyncError> {
    Ok(super::FileEviction { dehydrated: true, blocks_reclaimed: 1, bytes_reclaimed: bytes })
}

fn left_as_it_was() -> Result<super::FileEviction, SyncError> {
    Ok(super::FileEviction { dehydrated: false, blocks_reclaimed: 0, bytes_reclaimed: 0 })
}

/// A folder eviction that frees some files but not others reports the
/// files that stayed instead of a plain success; one that frees all of
/// them, or leaves every file as it was without a failure, is the sum.
#[test]
fn a_partly_freed_folder_is_reported_as_such() {
    use super::fold_directory_eviction as fold;
    let attempts = |list: Vec<(&str, Result<super::FileEviction, SyncError>)>| {
        list.into_iter().map(|(p, r)| (p.to_string(), r)).collect::<Vec<_>>()
    };

    let all = fold("trips", attempts(vec![("trips/a", freed(5)), ("trips/b", freed(7))])).unwrap();
    assert_eq!((all.evicted_files, all.bytes_reclaimed), (2, 12));

    let none = fold("trips", attempts(vec![("trips/a", left_as_it_was())])).unwrap();
    assert_eq!(none.evicted_files, 0);

    let busy = SyncError::EvictionRejected("trips/b: busy".into());
    let partial = fold(
        "trips",
        attempts(vec![
            ("trips/a", freed(5)),
            ("trips/b", Err(busy)),
            ("trips/c", left_as_it_was()),
        ]),
    )
    .unwrap_err();
    let text = partial.to_string();
    assert!(matches!(partial, SyncError::EvictionRejected(_)), "{text}");
    assert!(text.contains("2 of 3 files stayed"), "{text}");
    assert!(text.contains("1 freed, 5 bytes"), "{text}");
    assert!(text.contains("trips/b"), "{text}");

    let changed =
        fold("trips", attempts(vec![("trips/a", freed(5)), ("trips/c", left_as_it_was())]))
            .unwrap_err();
    assert!(changed.to_string().contains("trips/c was busy or changed"), "{changed}");

    let only_failure = SyncError::NotFound("trips/a".into());
    let failed = fold("trips", attempts(vec![("trips/a", Err(only_failure))])).unwrap_err();
    assert!(matches!(failed, SyncError::NotFound(_)), "{failed}");
}
