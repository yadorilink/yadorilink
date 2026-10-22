#![cfg(test)]

use super::*;
use crate::materialized_generation::{bump_mutation_fence, snapshot_mutation_fence};
use yadorilink_fs_platform::fs_identity::{PlatformObjectId, Timestamp, VolumeIdentity};

const GROUP: &str = "g";

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::replica_tables::init_for_tests(&conn).unwrap();
    conn
}

/// A directory identity whose reuse discriminator is a generation counter,
/// so a same-object comparison is conclusive on any clock.
fn dir_identity(inode: u64, generation: u128) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 7 },
        object_id: PlatformObjectId::Unix { inode },
        object_kind: ObjectKind::Directory,
        generation_or_usn: Some(generation),
        birth_or_creation_time: Some(Timestamp {
            seconds_since_unix_epoch: 1_700_000_000,
            subsec_nanos: 0,
        }),
        observed_size: 64,
        metadata_fingerprint: [1; 32],
        link_count: Some(2),
        symlink_target_digest: None,
    }
}

fn status(
    conn: &Connection,
    path: &str,
    observed: Option<&FileIdentity>,
) -> StructuralOriginStatus {
    structural_directory_origin(conn, GROUP, path)
        .unwrap()
        .status(observed, TimestampGranularity::Coarse)
}

#[test]
fn intent_then_identity_records_a_structural_origin() {
    let conn = open();
    let before = snapshot_mutation_fence(&conn, GROUP, "a").unwrap();
    let intent = record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    assert!(intent.mutation_generation > before, "the intent bumps the path's mutation fence");
    assert_eq!(status(&conn, "a", None), StructuralOriginStatus::IntentPending);

    let made = dir_identity(100, 1);
    assert_eq!(
        complete_structural_origin(&conn, GROUP, "a", &made, 11).unwrap(),
        StructuralOriginCompletion::Recorded
    );
    assert_eq!(status(&conn, "a", Some(&made)), StructuralOriginStatus::Structural);
    assert_eq!(
        status(&conn, "a", Some(&dir_identity(100, 2))),
        StructuralOriginStatus::OriginUnknown,
        "a recreated directory at the same path inherits nothing"
    );
    assert_eq!(status(&conn, "a", None), StructuralOriginStatus::OriginUnknown);
}

/// The crash window between the `mkdir` and recording its identity: the
/// directory exists, only the intent is durable. Recovery must not decide
/// after the fact that whatever is there now is the directory this device
/// made.
#[test]
fn structural_intent_without_identity_is_dropped_on_recovery() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "a/b", 10).unwrap();
    record_structural_intent(&conn, "other", "c", 10).unwrap();
    // The process dies here, after mkdir, before the identity is recorded.

    let dropped = drop_unresolved_structural_intents(&conn).unwrap();
    assert_eq!(
        dropped,
        vec![(GROUP.to_string(), "a/b".to_string()), ("other".to_string(), "c".to_string())]
    );
    let on_disk = dir_identity(100, 1);
    assert_eq!(
        status(&conn, "a/b", Some(&on_disk)),
        StructuralOriginStatus::OriginUnknown,
        "an unresolved intent is never completed from what happens to be on disk"
    );
    assert_eq!(
        complete_structural_origin(&conn, GROUP, "a/b", &on_disk, 12).unwrap(),
        StructuralOriginCompletion::NoPendingIntent,
        "a late completion after recovery claims nothing"
    );
    assert_eq!(status(&conn, "a/b", Some(&on_disk)), StructuralOriginStatus::OriginUnknown);
}

#[test]
fn listing_can_be_limited_to_one_group() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    record_structural_intent(&conn, "other", "b", 10).unwrap();
    let only: Vec<_> = list_unresolved_structural_intents(&conn, Some(GROUP))
        .unwrap()
        .into_iter()
        .map(|intent| intent.path)
        .collect();
    assert_eq!(only, ["a"]);
}

/// A structural intent and a write intent are different obligations that
/// may sit on one path together; neither reads as the other.
#[test]
fn a_structural_intent_is_not_a_write_intent() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "d", 10).unwrap();
    let writes: i64 = conn
        .query_row("SELECT COUNT(*) FROM materialization_intents WHERE kind = 'write'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(writes, 0);
    conn.execute(
        "INSERT INTO materialization_intents (group_id, path, target_version_hash, \
         created_at_unix_nanos) VALUES (?1, 'd', x'01', 0)",
        [GROUP],
    )
    .unwrap();
    assert_eq!(list_unresolved_structural_intents(&conn, None).unwrap().len(), 1);
    assert!(abandon_structural_intent(&conn, GROUP, "d").unwrap());
    let left: i64 =
        conn.query_row("SELECT COUNT(*) FROM materialization_intents", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 1, "abandoning the mkdir leaves the write intent");
}

#[test]
fn mkdir_finding_the_name_taken_claims_no_origin() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    assert!(abandon_structural_intent(&conn, GROUP, "a").unwrap());
    assert_eq!(
        status(&conn, "a", Some(&dir_identity(100, 1))),
        StructuralOriginStatus::OriginUnknown
    );
}

#[test]
fn an_abandoned_intent_keeps_the_origin_recorded_before_it() {
    let conn = open();
    let made = dir_identity(100, 1);
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    complete_structural_origin(&conn, GROUP, "a", &made, 11).unwrap();
    // A later mkdir of the same path finds the directory already there.
    record_structural_intent(&conn, GROUP, "a", 20).unwrap();
    abandon_structural_intent(&conn, GROUP, "a").unwrap();
    assert_eq!(status(&conn, "a", Some(&made)), StructuralOriginStatus::Structural);
}

/// Nothing structural is claimed, and the directory the `mkdir` made is
/// of lost provenance rather than unrecorded.
#[test]
fn completion_after_another_mutation_of_the_path_claims_nothing() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    bump_mutation_fence(&conn, GROUP, "a", "external-actual-state-adopted", 11).unwrap();
    assert_eq!(
        complete_structural_origin(&conn, GROUP, "a", &dir_identity(100, 1), 12).unwrap(),
        StructuralOriginCompletion::FenceMoved
    );
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::ProvenanceLost(dir_identity(100, 1))
    );
    assert_eq!(
        status(&conn, "a", Some(&dir_identity(100, 1))),
        StructuralOriginStatus::OriginUnknown
    );
}

#[test]
fn completion_over_a_non_directory_claims_nothing() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    let mut file = dir_identity(100, 1);
    file.object_kind = ObjectKind::RegularFile;
    assert_eq!(
        complete_structural_origin(&conn, GROUP, "a", &file, 11).unwrap(),
        StructuralOriginCompletion::NotADirectory
    );
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::None
    );
}

/// A structural directory is followed by identity, so a rename moves its
/// record instead of leaving the moved directory looking user-made.
#[test]
fn origin_is_rekeyed_by_identity_on_rename() {
    let conn = open();
    let made = dir_identity(100, 1);
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    complete_structural_origin(&conn, GROUP, "a", &made, 11).unwrap();
    let unrelated = dir_identity(200, 1);
    adopt_structural_directory(&conn, GROUP, "z", &unrelated, 11).unwrap();

    // `a` is renamed to `b`: same object, new name. A rename does not touch
    // the directory's own tracked metadata, but other fields of the
    // observation (its link count) may differ.
    let mut seen_at_b = made;
    seen_at_b.link_count = Some(3);
    assert_eq!(
        rekey_structural_origin(&conn, GROUP, "b", &seen_at_b, TimestampGranularity::Coarse, 12)
            .unwrap(),
        Some("a".to_string())
    );
    assert_eq!(status(&conn, "b", Some(&seen_at_b)), StructuralOriginStatus::Structural);
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::None
    );
    assert_eq!(status(&conn, "z", Some(&unrelated)), StructuralOriginStatus::Structural);

    // A different object that happens to reuse the inode is not followed.
    let reused = dir_identity(200, 9);
    assert_eq!(
        rekey_structural_origin(&conn, GROUP, "c", &reused, TimestampGranularity::Coarse, 13)
            .unwrap(),
        None
    );
    assert_eq!(status(&conn, "c", Some(&reused)), StructuralOriginStatus::OriginUnknown);
}

#[test]
fn rekey_does_not_cross_groups() {
    let conn = open();
    let made = dir_identity(100, 1);
    adopt_structural_directory(&conn, "other", "a", &made, 10).unwrap();
    assert_eq!(
        rekey_structural_origin(&conn, GROUP, "b", &made, TimestampGranularity::Coarse, 11)
            .unwrap(),
        None
    );
}

/// An explicit directory whose entry was deleted while a descendant still
/// lives stays on disk as that descendant's container; from then on it is
/// structural and recognized as such.
#[test]
fn an_adopted_directory_reads_as_structural() {
    let conn = open();
    let existing = dir_identity(300, 1);
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    adopt_structural_directory(&conn, GROUP, "a", &existing, 11).unwrap();
    assert_eq!(status(&conn, "a", Some(&existing)), StructuralOriginStatus::Structural);

    let mut file = existing;
    file.object_kind = ObjectKind::RegularFile;
    assert!(matches!(
        adopt_structural_directory(&conn, GROUP, "f", &file, 12),
        Err(SyncSqliteError::InvalidInput(_))
    ));
}

#[test]
fn an_ambiguous_identity_is_not_structural() {
    let conn = open();
    let mut made = dir_identity(100, 1);
    made.generation_or_usn = None;
    adopt_structural_directory(&conn, GROUP, "a", &made, 10).unwrap();
    // Same volume, inode and birth time, but a coarse clock cannot rule out
    // that the inode was reused within the same tick.
    assert_eq!(status(&conn, "a", Some(&made)), StructuralOriginStatus::OriginUnknown);
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a")
            .unwrap()
            .status(Some(&made), TimestampGranularity::Fine),
        StructuralOriginStatus::Structural
    );
}

/// The whole protocol against a real directory: the identity recorded
/// after `mkdir` still names the directory after a child is added to it.
#[test]
fn a_real_directory_stays_structural_after_a_child_lands_in_it() {
    let conn = open();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("a");
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    std::fs::create_dir(&dir).unwrap();
    let made = FileIdentity::observe_path(&dir).unwrap();
    assert_eq!(
        complete_structural_origin(&conn, GROUP, "a", &made, 11).unwrap(),
        StructuralOriginCompletion::Recorded
    );
    std::fs::write(dir.join("x"), b"child").unwrap();
    let now = FileIdentity::observe_path(&dir).unwrap();
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a")
            .unwrap()
            .status(Some(&now), TimestampGranularity::Fine),
        StructuralOriginStatus::Structural
    );
}

#[test]
fn forgetting_an_origin_leaves_nothing_behind() {
    let conn = open();
    adopt_structural_directory(&conn, GROUP, "a", &dir_identity(1, 1), 10).unwrap();
    assert!(forget_structural_origin(&conn, GROUP, "a").unwrap());
    assert!(!forget_structural_origin(&conn, GROUP, "a").unwrap());
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::None
    );
}

/// D5=B: a user's chmod of a structural directory is an operation on the
/// directory itself, which makes it explicit. The same object with its
/// tracked metadata changed must not read as plain `Structural`, or capture
/// following `status()` would never author it.
#[test]
fn a_chmodded_structural_directory_is_not_plain_structural() {
    let conn = open();
    let made = dir_identity(100, 1);
    adopt_structural_directory(&conn, GROUP, "a", &made, 10).unwrap();
    let mut chmodded = made;
    chmodded.metadata_fingerprint = [9; 32];
    assert_eq!(
        status(&conn, "a", Some(&chmodded)),
        StructuralOriginStatus::StructuralMetadataChanged
    );
}

/// A rename carries the recorded metadata along, so a chmod made before or
/// with the rename is still seen at the new name.
#[test]
fn a_rename_does_not_launder_a_metadata_change() {
    let conn = open();
    let made = dir_identity(100, 1);
    adopt_structural_directory(&conn, GROUP, "a", &made, 10).unwrap();
    let mut moved_and_chmodded = made;
    moved_and_chmodded.metadata_fingerprint = [9; 32];
    assert_eq!(
        rekey_structural_origin(
            &conn,
            GROUP,
            "b",
            &moved_and_chmodded,
            TimestampGranularity::Coarse,
            11
        )
        .unwrap(),
        Some("a".to_string())
    );
    assert_eq!(
        status(&conn, "b", Some(&moved_and_chmodded)),
        StructuralOriginStatus::StructuralMetadataChanged
    );
    assert_eq!(status(&conn, "b", Some(&made)), StructuralOriginStatus::Structural);
}

/// The real filesystem: `chmod` of a structural directory moves its
/// fingerprint, and nothing else about it does.
#[cfg(unix)]
#[test]
fn a_real_chmod_of_a_structural_directory_is_seen() {
    use std::os::unix::fs::PermissionsExt;
    let conn = open();
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("a");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    adopt_structural_directory(&conn, GROUP, "a", &FileIdentity::observe_path(&dir).unwrap(), 10)
        .unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a")
            .unwrap()
            .status(Some(&FileIdentity::observe_path(&dir).unwrap()), TimestampGranularity::Fine),
        StructuralOriginStatus::StructuralMetadataChanged
    );
}

/// Renaming a structural directory moves the records of the structural
/// directories nested in it too: their objects moved with it.
#[test]
fn rekeying_a_renamed_directory_carries_its_nested_origins() {
    let conn = open();
    let a = dir_identity(100, 1);
    let ab = dir_identity(101, 1);
    let abc = dir_identity(102, 1);
    let sibling = dir_identity(103, 1);
    adopt_structural_directory(&conn, GROUP, "a", &a, 10).unwrap();
    adopt_structural_directory(&conn, GROUP, "a/b", &ab, 10).unwrap();
    adopt_structural_directory(&conn, GROUP, "a/b/c", &abc, 10).unwrap();
    // Shares the prefix, is not below `a`.
    adopt_structural_directory(&conn, GROUP, "a-b", &sibling, 10).unwrap();
    // A stale record below the destination is not inherited by anything.
    adopt_structural_directory(&conn, GROUP, "z/old", &dir_identity(104, 1), 10).unwrap();

    assert_eq!(
        rekey_structural_origin(&conn, GROUP, "z", &a, TimestampGranularity::Coarse, 11).unwrap(),
        Some("a".to_string())
    );
    assert_eq!(status(&conn, "z", Some(&a)), StructuralOriginStatus::Structural);
    assert_eq!(status(&conn, "z/b", Some(&ab)), StructuralOriginStatus::Structural);
    assert_eq!(status(&conn, "z/b/c", Some(&abc)), StructuralOriginStatus::Structural);
    for gone in ["a", "a/b", "a/b/c", "z/old"] {
        assert_eq!(
            structural_directory_origin(&conn, GROUP, gone).unwrap(),
            StructuralDirectoryOrigin::None,
            "{gone}"
        );
    }
    assert_eq!(status(&conn, "a-b", Some(&sibling)), StructuralOriginStatus::Structural);
}

/// A completion whose intent was dropped as stale while its `mkdir` ran
/// made the directory, but the ledger cannot call it structural any more.
/// It is recorded as of lost provenance for exactly that object, which
/// reads as unknown origin -- never as nothing recorded, which capture
/// would take for a user's directory.
#[test]
fn a_completion_that_finds_its_intent_gone_records_lost_provenance() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "a", 10).unwrap();
    drop_unresolved_structural_intents(&conn).unwrap();
    let made = dir_identity(100, 1);

    assert_eq!(
        complete_structural_origin(&conn, GROUP, "a", &made, 11).unwrap(),
        StructuralOriginCompletion::NoPendingIntent
    );

    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::ProvenanceLost(made)
    );
    assert_eq!(status(&conn, "a", Some(&made)), StructuralOriginStatus::OriginUnknown);
}

/// A later origin for the path supersedes lost provenance, and forgetting
/// the path (its directory is gone) leaves nothing behind.
#[test]
fn an_origin_recorded_later_replaces_lost_provenance() {
    let conn = open();
    record_lost_structural_provenance(&conn, GROUP, "a", &dir_identity(100, 1), 10).unwrap();

    adopt_structural_directory(&conn, GROUP, "a", &dir_identity(200, 1), 11).unwrap();
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::Recorded(dir_identity(200, 1))
    );

    forget_structural_origin(&conn, GROUP, "a").unwrap();
    record_lost_structural_provenance(&conn, GROUP, "a", &dir_identity(300, 1), 12).unwrap();
    forget_structural_origin(&conn, GROUP, "a").unwrap();
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::None
    );
}

/// Lost provenance is never recorded over an origin, nor for something
/// other than a directory.
#[test]
fn lost_provenance_does_not_displace_an_origin_or_name_a_file() {
    let conn = open();
    adopt_structural_directory(&conn, GROUP, "a", &dir_identity(100, 1), 10).unwrap();
    assert!(
        !record_lost_structural_provenance(&conn, GROUP, "a", &dir_identity(200, 1), 11).unwrap()
    );
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "a").unwrap(),
        StructuralDirectoryOrigin::Recorded(dir_identity(100, 1))
    );

    let mut file = dir_identity(300, 1);
    file.object_kind = ObjectKind::RegularFile;
    assert!(!record_lost_structural_provenance(&conn, GROUP, "f", &file, 12).unwrap());
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "f").unwrap(),
        StructuralDirectoryOrigin::None
    );
}

/// Recovery drops an interrupted intent and records the directory found
/// at its path as of lost provenance in one step, so nothing ever sees the
/// intent gone with nothing in its place. An intent recorded again for the
/// path since it was listed is a live `mkdir` and is left alone; a path
/// with nothing there drops its intent with nothing recorded.
#[test]
fn recovery_drops_an_intent_only_together_with_the_lost_provenance_it_leaves() {
    let conn = open();
    record_structural_intent(&conn, GROUP, "made", 10).unwrap();
    record_structural_intent(&conn, GROUP, "nothing", 10).unwrap();
    record_structural_intent(&conn, GROUP, "again", 10).unwrap();
    let listed = list_unresolved_structural_intents(&conn, None).unwrap();
    assert_eq!(
        listed.iter().map(|intent| intent.path.as_str()).collect::<Vec<_>>(),
        ["again", "made", "nothing"]
    );
    // A new structural mkdir of `again` after the listing.
    record_structural_intent(&conn, GROUP, "again", 20).unwrap();
    let made = dir_identity(100, 1);

    let found = |path: &str| match path {
        "made" | "again" => Some(made),
        _ => None,
    };
    let dropped: Vec<bool> = listed
        .iter()
        .map(|intent| {
            drop_structural_intent_recording_lost_provenance(
                &conn,
                intent,
                found(&intent.path).as_ref(),
                30,
            )
            .unwrap()
        })
        .collect();

    assert_eq!(dropped, [false, true, true]);
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "made").unwrap(),
        StructuralDirectoryOrigin::ProvenanceLost(made)
    );
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "nothing").unwrap(),
        StructuralDirectoryOrigin::None
    );
    assert_eq!(
        structural_directory_origin(&conn, GROUP, "again").unwrap(),
        StructuralDirectoryOrigin::IntentPending,
        "a later intent is a live mkdir, not the interrupted one"
    );
}
