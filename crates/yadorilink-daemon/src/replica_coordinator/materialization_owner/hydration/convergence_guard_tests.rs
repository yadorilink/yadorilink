//! `HydrationAttempt`'s revert-on-drop, tested against a real
//! `ReplicaCoordinator`.
//!
//! A child module of the owner's `hydration` module, because the guard's
//! fields are private to it: the tests arm a guard directly, without
//! running the entry CAS, to simulate an attempt already in flight.

use std::sync::Arc;

use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::MaterializationState;

use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-1";

/// `HydrationAttempt`'s revert-on-drop must not clobber a
/// concurrent hydration attempt for the SAME path that already
/// completed successfully. Even with `hydration::hydrate_inner` now
/// serializing on `path_lock` (see the test above), a losing internal
/// race within one lock-holding attempt's own retry/backoff logic is
/// still worth guarding directly at this layer too: if this guard's
/// own attempt fails AFTER a different, concurrent
/// attempt already committed a genuine `Present`, an unconditional
/// revert would silently downgrade that successful result back to
/// `Remote` even though the file really is on disk -- a real
/// regression in this guard's first version, which used a blind
/// `set_materialization_state`
/// instead of a conditional transition.
#[tokio::test]
async fn hydrating_state_guard_does_not_clobber_a_concurrently_completed_hydration() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let sync_root = root_dir.path().canonicalize().unwrap();
    state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&sync_root, GROUP, state.as_ref())
        .unwrap();

    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "doc.txt",
            MaterializationState::Hydrating,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // This attempt's own guard, not yet committed -- as if this
    // attempt is still in flight (e.g. about to fail).
    let guard = super::HydrationAttempt {
        coordinator: state.as_ref(),
        group_id: GROUP,
        path: "doc.txt",
        // The version this simulated attempt is about: the one the
        // row names right now, since these fixtures seed the row and
        // then move only its materialization state.
        version: state
            .file_index_repository()
            .canonical_current_row(GROUP, "doc.txt")
            .unwrap()
            .unwrap()
            .version_hash(),
        revert_to: MaterializationState::Remote,
        committed: false,
    };

    // A DIFFERENT, concurrent attempt for the same path finishes
    // first and genuinely completes.
    state
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            "doc.txt",
            MaterializationState::Present,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // This attempt's own guard now drops (uncommitted, simulating its
    // own late failure) -- it must NOT downgrade the row the
    // concurrent attempt already finished.
    drop(guard);

    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Present),
        "a losing guard's revert-on-drop must not clobber a concurrently-completed \
         hydration's Hydrated state"
    );
}

/// A state-only CAS (the previous fix) is not enough on its own: it
/// cannot distinguish "this row is still the SAME version this
/// attempt started hydrating, just still `Hydrating`" from "a NEWER
/// version of this same path became `current` mid-hydration (a
/// peer's concurrent update superseding the row) and its own,
/// unrelated hydration attempt happens to also be `Hydrating`". Only
/// binding the CAS to the version captured before this attempt started
/// closes that gap -- the deeper counter-scenario to the state-only
/// guard above.
///
/// The supersession moves the version and nothing else: same
/// `Hydrating` state, different content, so only the version binding can
/// tell this row apart from the one the guard captured.
#[tokio::test]
async fn hydrating_state_guard_does_not_clobber_a_superseding_newer_version() {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let sync_root = root_dir.path().canonicalize().unwrap();
    state.link_repository().add_link(&sync_root.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(&sync_root, GROUP, state.as_ref())
        .unwrap();

    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "doc.txt".into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .materialization_state_repository()
        .set_materialization_state(GROUP, "doc.txt", MaterializationState::Hydrating, &permit)
        .unwrap();

    let captured_version = state
        .file_index_repository()
        .canonical_current_row(GROUP, "doc.txt")
        .unwrap()
        .unwrap()
        .version_hash();
    let guard = super::HydrationAttempt {
        coordinator: state.as_ref(),
        group_id: GROUP,
        path: "doc.txt",
        version: captured_version,
        revert_to: MaterializationState::Remote,
        committed: false,
    };

    // The supersession: a column the version is derived from moves.
    state.file_index_repository().set_unix_mode(GROUP, "doc.txt", Some(0o755), &permit).unwrap();
    let superseding_version = state
        .file_index_repository()
        .canonical_current_row(GROUP, "doc.txt")
        .unwrap()
        .unwrap()
        .version_hash();
    assert_ne!(
        superseding_version, captured_version,
        "fixture check: the supersession must really move the version, or this test proves \
         nothing"
    );

    drop(guard);

    assert_eq!(
        state
            .materialization_state_repository()
            .get_materialization_state(GROUP, "doc.txt")
            .unwrap(),
        Some(MaterializationState::Hydrating),
        "an old attempt's guard must not revert a row whose version has moved on, even \
         though the state value still matches"
    );
}
