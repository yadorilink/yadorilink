#![cfg(test)]

//! The internal-commit port must re-verify the root inside its own commit
//! transaction, not merely inherit a check its caller made earlier.

use super::*;
use yadorilink_peer_session::ports::ExactActualState;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootLease;
use yadorilink_root_authority::sync_root_lock::SyncRootLock;

const GROUP: &str = "group-1";
const PATH: &str = "doc.txt";

/// A live lease over a real, locked sync root, plus the root's path so a
/// test can pull the ground out from under it.
fn locked_root() -> (tempfile::TempDir, RootLease) {
    let root = tempfile::tempdir().unwrap();
    let lock = SyncRootLock::acquire(root.path()).unwrap();
    let lease = RootLease::new(lock, GROUP.to_string(), 0);
    (root, lease)
}

fn seed_row(
    coordinator: &ReplicaCoordinator,
) -> (i64, yadorilink_replica_domain::ids::VersionHash) {
    let permit = RootCommitPermit::for_tests();
    coordinator.link_repository().add_link("/somewhere", GROUP).unwrap();
    coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: PATH.into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    let version = coordinator
        .file_index_repository()
        .canonical_current_row(GROUP, PATH)
        .unwrap()
        .unwrap()
        .version_hash();
    let generation = crate::replica_coordinator::ReplicaCoordinator::dag_bump_mutation_fence(
        coordinator,
        GROUP,
        PATH,
        "test_write",
    )
    .unwrap();
    (generation, version)
}

/// A root that is unlinked and recreated under the same name while a
/// materialization is in flight is the window `RootCommitPermit::verify`
/// exists for: the write went to an object this device no longer owns, so
/// a proof published for it would describe bytes under someone else's
/// root. The caller's own pre-write root check cannot see this -- it ran
/// before the block fetch and the file publish -- which is why the commit
/// takes a permit and re-verifies inside its own transaction.
#[test]
fn a_commit_publishes_nothing_once_the_root_it_was_admitted_against_is_gone() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    let (generation, version) = seed_row(&coordinator);
    let (root, lease) = locked_root();
    let operation = lease.begin_operation().unwrap();

    assert!(
        operation.permit().verify().is_ok(),
        "fixture check: the permit must start out good, or this test proves nothing"
    );

    // Unlink and recreate at the same pathname: same path, different
    // object. Exactly what an external volume swap or a racing adopt
    // leaves behind.
    let lock_path =
        root.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    assert!(
        operation.permit().verify().is_err(),
        "fixture check: the root must really look lost, or this test proves nothing"
    );

    let state_before = coordinator
        .materialization_state_repository()
        .get_materialization_state(GROUP, PATH)
        .unwrap();

    let outcome = crate::replica_coordinator::ReplicaCoordinator::commit_internal_materialized_state_if_fence_current(
        &coordinator,
        GROUP,
        PATH,
        ExactActualState::Object { kind: RecordKind::File, version, identity: Box::new(None) },
        generation,
        None,
        &operation.permit(),
    );

    assert!(
        outcome.is_err(),
        "a commit whose root is gone must fail rather than report a published proof"
    );
    assert!(
        coordinator.sqlite().dag_lookup_materialized_generation(GROUP, PATH).unwrap().is_none(),
        "nothing may be published for a path whose root this device no longer owns"
    );
    assert_eq!(
        coordinator
            .materialization_state_repository()
            .get_materialization_state(GROUP, PATH)
            .unwrap(),
        state_before,
        "and the claim that rests on that proof must not be stamped either: the commit is \
         all-or-nothing, so a refused one leaves the row exactly as it found it"
    );
}

/// The same commit, with the root still intact, must land -- otherwise the
/// assertion above would pass for a commit that never works at all.
#[test]
fn a_commit_under_a_live_root_still_publishes() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    let (generation, version) = seed_row(&coordinator);
    let (_root, lease) = locked_root();
    let operation = lease.begin_operation().unwrap();

    let published = crate::replica_coordinator::ReplicaCoordinator::commit_internal_materialized_state_if_fence_current(
        &coordinator,
        GROUP,
        PATH,
        ExactActualState::Object { kind: RecordKind::File, version, identity: Box::new(None) },
        generation,
        None,
        &operation.permit(),
    )
    .unwrap();

    assert!(published, "a live root's commit must publish");
    assert!(
        coordinator.sqlite().dag_lookup_materialized_generation(GROUP, PATH).unwrap().is_some(),
        "the proof must be there to be found"
    );
}

/// The absence lane has the same window, and does not yet close it.
///
/// A tombstone's physical delete runs under a verified root, but the
/// proof that the path is exactly absent is published afterwards --
/// retirement publishes it after its `LinkOperation` has already been
/// dropped, and obligation completion publishes it from the engine. If
/// the root is swapped in between, that proof describes an absence under
/// a root this device no longer owns: the file may well exist under the
/// root that replaced it.
///
/// Same failure an earlier fix closed for present objects, on the lane
/// beside it.
#[test]
fn an_absence_proof_publishes_nothing_once_the_root_it_was_admitted_against_is_gone() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    seed_row(&coordinator);
    // A genuine tombstone: the row must actually be absent, or the
    // publish is refused for describing a row that is still live and the
    // test would pass without ever reaching the root question.
    coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: PATH.into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: true,
            },
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    // The pre-delete bump every tombstone lane performs.
    let generation = crate::replica_coordinator::ReplicaCoordinator::dag_bump_mutation_fence(
        &coordinator,
        GROUP,
        PATH,
        "delete",
    )
    .unwrap();
    let (root, lease) = locked_root();
    let operation = lease.begin_operation().unwrap();
    assert!(operation.permit().verify().is_ok(), "fixture check: the permit must start out good");

    let lock_path =
        root.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    assert!(
        operation.permit().verify().is_err(),
        "fixture check: the root must really look lost, or this test proves nothing"
    );

    let outcome = crate::replica_coordinator::ReplicaCoordinator::dag_publish_materialized_generation_if_fence_current(
        &coordinator,
        GROUP,
        PATH,
        ExactActualState::Absent,
        generation,
        &operation.permit(),
    );

    assert!(
        outcome.is_err(),
        "an absence proof under a lost root must fail rather than report itself published"
    );
    assert!(
        coordinator.sqlite().dag_lookup_materialized_generation(GROUP, PATH).unwrap().is_none(),
        "nothing may be published for a path whose root this device no longer owns"
    );
}

/// Access hydration's proof heal has the same window.
///
/// The lane re-verified a `Present` row's bytes, identity, mode and
/// xattrs and now re-publishes its proof under the live fence. If the root
/// is swapped after that check began and before the proof commits, the
/// heal must fail and publish nothing: a proof committed first and a
/// permit checked afterwards leaves a durable proof about a root this
/// device no longer owns, behind an `Err`.
#[test]
fn a_hydrated_proof_heal_publishes_nothing_once_the_root_it_was_admitted_against_is_gone() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    seed_row(&coordinator);
    coordinator
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Present,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let row =
        coordinator.file_index_repository().canonical_current_row(GROUP, PATH).unwrap().unwrap();
    let version = row.version_hash();
    let (root, lease) = locked_root();
    let observed = root.path().join("observed");
    std::fs::write(&observed, b"").unwrap();
    let identity =
        yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&observed).unwrap();
    let operation = lease.begin_operation().unwrap();
    assert!(operation.permit().verify().is_ok(), "fixture check: the permit must start out good");

    let lock_path =
        root.path().join(yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    assert!(
        operation.permit().verify().is_err(),
        "fixture check: the root must really look lost, or this test proves nothing"
    );

    let outcome =
        coordinator.reprove_hydrated_file(GROUP, PATH, &version, identity, &operation.permit());

    assert!(outcome.is_err(), "a proof heal under a lost root must fail");
    assert!(
        coordinator.sqlite().dag_lookup_materialized_generation(GROUP, PATH).unwrap().is_none(),
        "nothing may be published for a path whose root this device no longer owns"
    );
}

/// The same heal under a live root still publishes, so the test above
/// cannot pass for a heal that never works.
#[test]
fn a_hydrated_proof_heal_under_a_live_root_still_publishes() {
    let coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    seed_row(&coordinator);
    coordinator
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            PATH,
            MaterializationState::Present,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();
    let row =
        coordinator.file_index_repository().canonical_current_row(GROUP, PATH).unwrap().unwrap();
    let (root, lease) = locked_root();
    let observed = root.path().join("observed");
    std::fs::write(&observed, b"").unwrap();
    let identity =
        yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&observed).unwrap();
    let operation = lease.begin_operation().unwrap();

    let published = coordinator
        .reprove_hydrated_file(GROUP, PATH, &row.version_hash(), identity, &operation.permit())
        .unwrap();

    assert!(published, "a live root's heal must publish");
    assert!(
        coordinator.sqlite().dag_lookup_materialized_generation(GROUP, PATH).unwrap().is_some(),
        "the proof must be there to be found"
    );
}
