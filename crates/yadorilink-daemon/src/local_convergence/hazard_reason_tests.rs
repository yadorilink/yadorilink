#![cfg(test)]

use super::types::{
    hazard_reason_for_policy, hazard_reason_for_siblings, hold_record, VolumeFolding,
};
use yadorilink_peer_session::hazard::NamePolicy;
use yadorilink_replica_domain::file::FileRecord;

/// A real, in-memory `ReplicaCoordinator` with `root` linked as
/// `group-1`'s sync root.
fn linked_state(root: &std::path::Path) -> crate::replica_coordinator::ReplicaCoordinator {
    let state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    state.link_repository().add_link(&root.to_string_lossy(), "group-1").unwrap();
    state
}

fn record(path: &str) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    }
}

/// An incoming record whose path case-folds identically to
/// an already-indexed sibling, but isn't byte-identical to it, is a
/// case-fold-collision hazard on a case-insensitive filesystem.
///
/// Stated against a case-insensitive volume rather than whatever the
/// host happens to provide. This assertion used to skip on any
/// case-sensitive tempdir, which is every ordinary Linux runner -- so
/// the check that protects a peer syncing *to* macOS was verified
/// almost nowhere.
#[test]
fn case_fold_collision_with_an_existing_sibling_is_a_hazard() {
    let reason = hazard_reason_for_siblings(
        "photo.jpg",
        VolumeFolding { case_insensitive: true, normalization_insensitive: false },
        &[record("Photo.jpg")],
    );

    let reason = reason.expect("a differently-cased sibling must be flagged as a hazard");
    assert!(reason.starts_with(yadorilink_peer_session::hazard::HELD_REASON_CASE_COLLISION));
    assert!(reason.contains("Photo.jpg"), "reason should name the colliding sibling: {reason}");
}

/// The `normalization_collision` counterpart to the case-fold hazard
/// test above: an incoming record whose path is a different Unicode
/// normalization form of an already-indexed sibling's path is a hazard
/// on a normalization-insensitive filesystem. Stated against such a
/// volume for the same reason, and it used to skip for the same one.
#[test]
fn normalization_collision_with_an_existing_sibling_is_a_hazard() {
    let composed = "caf\u{e9}.txt";
    let decomposed = "cafe\u{301}.txt";

    let reason = hazard_reason_for_siblings(
        decomposed,
        VolumeFolding { case_insensitive: false, normalization_insensitive: true },
        &[record(composed)],
    );

    let reason = reason.expect("a differently-normalized sibling must be flagged as a hazard");
    assert!(
        reason.starts_with(yadorilink_peer_session::hazard::HELD_REASON_NORMALIZATION_COLLISION)
    );
    assert!(reason.contains(composed), "reason should name the colliding sibling: {reason}");
}

/// The exact inverse of the above: re-adopting a path identical to
/// what's already indexed for it (an ordinary update, not a new
/// arrival) must never be flagged as colliding with itself.
#[test]
fn updating_the_same_path_is_never_a_self_collision() {
    // On the volume where a self-collision is even expressible: one that
    // folds both ways at once, so neither axis nor their combination may
    // mistake a path for itself.
    let reason = hazard_reason_for_siblings(
        "Photo.jpg",
        VolumeFolding { case_insensitive: true, normalization_insensitive: true },
        &[record("Photo.jpg")],
    );
    assert_eq!(reason, None);
}

/// An ordinary, non-colliding, non-reserved name is never a hazard
/// under either policy.
#[test]
fn an_ordinary_name_is_never_a_hazard() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    for policy in [NamePolicy::Posix, NamePolicy::Windows] {
        let reason =
            hazard_reason_for_policy(&state, root.path(), "group-1", &record("notes.txt"), policy)
                .unwrap();
        assert_eq!(reason, None, "{policy:?}");
    }
}

/// The exact scenario this test targets — the *same*
/// index state (a record named after a Windows-reserved device name)
/// is held under `NamePolicy::Windows` and materializes normally
/// (`None`, i.e. not a hazard) under `NamePolicy::Posix`, proving the
/// "gated on the local platform" requirement without needing to
/// actually compile or run this suite on real Windows.
#[test]
fn windows_reserved_name_is_held_on_windows_policy_and_clear_on_posix_policy() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let incoming = record("CON.txt");

    let windows_reason =
        hazard_reason_for_policy(&state, root.path(), "group-1", &incoming, NamePolicy::Windows)
            .unwrap();
    assert!(windows_reason
        .unwrap()
        .starts_with(yadorilink_peer_session::hazard::HELD_REASON_INVALID_NAME));

    let posix_reason =
        hazard_reason_for_policy(&state, root.path(), "group-1", &incoming, NamePolicy::Posix)
            .unwrap();
    assert_eq!(posix_reason, None, "the exact same name is completely valid on a POSIX filesystem");
}

/// `hold_record` upserts the record (so it keeps
/// participating in index exchange) and sets held state, without
/// creating anything on disk.
#[test]
fn hold_record_upserts_and_marks_held_without_touching_disk() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let incoming = record("CON.txt");

    hold_record(
        &state,
        "group-1",
        &incoming,
        "invalid_name: reserved device name 'CON'",
        "device-a",
        None,
        &plain_file_columns(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();

    let stored = state.get_file("group-1", "CON.txt").unwrap();
    assert!(stored.is_some(), ": a held record must still be indexed");
    assert!(!stored.unwrap().deleted);

    let held = state.get_held_state("group-1", "CON.txt").unwrap().unwrap();
    assert!(held.reason.starts_with("invalid_name"));
    assert!(held.since_unix_nanos > 0);

    assert!(!root.path().join("CON.txt").exists(), "a held record must never be written to disk");
}

/// Reachable on every platform (not
/// just via Windows symlink policy): a brand-new held row is left at
/// `materialization_state`'s schema default of `Present`, even though
/// nothing is ever written to disk for it (the assertion just above --
/// `!root.path().join("CON.txt").exists()` -- is unconditionally true
/// for every held record, by this function's own contract). A
/// `Present` row with nothing on disk and no materialization intent is
/// exactly what the periodic repair sweep reads as an offline deletion,
/// and the always-running dirty-journal redrive turns that into a real,
/// signed, group-wide propagating tombstone Change for a path that was
/// only ever held, never deleted.
#[test]
fn hold_record_demotes_to_placeholder_so_repair_never_reads_it_as_an_offline_deletion() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let incoming = record("CON.txt");

    hold_record(
        &state,
        "group-1",
        &incoming,
        "invalid_name: reserved device name 'CON'",
        "device-a",
        None,
        &plain_file_columns(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert_eq!(
        state.get_materialization_state("group-1", "CON.txt").unwrap(),
        Some(yadorilink_replica_domain::session_state::MaterializationState::Remote),
        "a held row must never be left at the schema-default Hydrated state"
    );
}

/// The regression test this explicitly
/// calls for — a real, pre-existing sibling is already on disk;
/// holding a case-fold-colliding incoming record for it must never
/// produce a written file under any name at all, not the hazardous
/// name and not some auto-generated alternate (`"photo (1).jpg"`,
/// `"photo_2.jpg"`,...) — this crate implements no automatic
/// rename/escape path. Asserted by enumerating the whole directory
/// afterward, not just checking the one hazardous name's own
/// non-existence, so an unexpected alternate-named file would fail
/// this test too.
#[test]
fn hold_record_never_writes_under_any_alternate_name() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    std::fs::write(root.path().join("Photo.jpg"), b"original").unwrap();
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            &record("Photo.jpg"),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let incoming = record("photo.jpg");
    // The subject here is what `hold_record` puts on disk, not which
    // volumes collide -- so the reason is derived for a case-insensitive
    // volume rather than hoping the host provides one. Asking the
    // filesystem instead is what used to skip this assertion on every
    // case-sensitive runner, leaving "a held file never appears under an
    // alternate name" unchecked exactly where it runs most.
    let reason = hazard_reason_for_siblings(
        &incoming.path,
        VolumeFolding { case_insensitive: true, normalization_insensitive: false },
        &[record("Photo.jpg")],
    )
    .expect("case-fold collision must be detected");
    hold_record(
        &state,
        "group-1",
        &incoming,
        &reason,
        "device-a",
        None,
        &plain_file_columns(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();

    let mut entries: Vec<String> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    assert_eq!(
        entries,
        vec!["Photo.jpg".to_string()],
        "no alternate/renamed variant of the held file may ever appear on disk"
    );
    assert_eq!(std::fs::read(root.path().join("Photo.jpg")).unwrap(), b"original");
}

fn plain_file_columns() -> yadorilink_replica_domain::session_state::LocalFileMetaColumns {
    yadorilink_replica_domain::session_state::LocalFileMetaColumns {
        record_kind: yadorilink_replica_domain::file::RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: None,
        xattrs: Vec::new(),
    }
}
