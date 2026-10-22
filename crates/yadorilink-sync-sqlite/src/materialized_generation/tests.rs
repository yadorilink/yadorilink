#![cfg(test)]

use super::*;
use yadorilink_fs_platform::fs_identity::{
    ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
};

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::replica_tables::init_for_tests(&conn).unwrap();
    init_materialized_generation_schema(&conn).unwrap();
    conn
}

fn sample_identity() -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 7 },
        object_id: PlatformObjectId::Unix { inode: 42 },
        object_kind: ObjectKind::RegularFile,
        generation_or_usn: Some(3),
        birth_or_creation_time: Some(Timestamp {
            seconds_since_unix_epoch: 1_700_000_000,
            subsec_nanos: 123,
        }),
        observed_size: 1024,
        metadata_fingerprint: [9; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

fn sample_basis(
    object_kind: MaterializedObjectKind,
    filesystem_identity: Option<FileIdentity>,
) -> DiskGenerationBasis {
    DiskGenerationBasis {
        generation_id: GenerationId("g:1".to_string()),
        basis: crate::materialization_basis::ReflectedHeads::of(&[], &[]),
        resolved_path_state_hash: [0; 32],
        object_kind,
        version: None,
        filesystem_identity,
    }
}

/// An `Absent` basis whose path is genuinely still missing on disk is
/// confirmed -- the trivial, common case.
#[test]
fn revalidate_confirms_a_still_absent_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("never-existed.txt");
    let basis = sample_basis(MaterializedObjectKind::Absent, None);
    assert_eq!(
        revalidate_identity_against_disk(
            &basis,
            &missing,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
        ),
        IdentityRevalidation::Confirmed
    );
}

/// An `Absent` basis whose path now genuinely has something on disk
/// must fail closed -- the exact case this helper
/// exists to catch as defense in depth (some mutator wrote the path
/// without this device's own admission/fence machinery noticing yet).
#[test]
fn revalidate_rejects_an_absent_basis_whose_path_now_exists() {
    let dir = tempfile::tempdir().unwrap();
    let now_present = dir.path().join("surprise.txt");
    std::fs::write(&now_present, b"unexpected content").unwrap();
    let basis = sample_basis(MaterializedObjectKind::Absent, None);
    assert_eq!(
        revalidate_identity_against_disk(
            &basis,
            &now_present,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
        ),
        IdentityRevalidation::NotAMatch
    );
}

/// A real object whose CURRENT on-disk identity still matches the
/// recorded one is confirmed.
#[test]
fn revalidate_confirms_a_matching_real_object_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("still-there.txt");
    std::fs::write(&path, b"unchanged content").unwrap();
    let observed = FileIdentity::observe_path(&path).unwrap();
    let basis = sample_basis(MaterializedObjectKind::RegularFile, Some(observed));
    assert_eq!(
        revalidate_identity_against_disk(
            &basis,
            &path,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
        ),
        IdentityRevalidation::Confirmed
    );
}

/// The recorded identity no longer matches disk (the object was
/// deleted and recreated, an unrelated file now occupies
/// this path) -- fail closed rather than trust a stale record.
#[test]
fn revalidate_rejects_when_the_observed_identity_no_longer_matches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replaced.txt");
    std::fs::write(&path, b"new content after replacement").unwrap();
    // A synthetic, definitely-mismatched identity -- not this file's own.
    let basis = sample_basis(MaterializedObjectKind::RegularFile, Some(sample_identity()));
    assert_eq!(
        revalidate_identity_against_disk(
            &basis,
            &path,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
        ),
        IdentityRevalidation::NotAMatch
    );
}

/// A non-`Absent` basis with NO recorded filesystem identity has
/// nothing to revalidate against -- fail closed, never
/// treat the mere existence of a real file as confirmation.
#[test]
fn revalidate_rejects_a_non_absent_basis_with_no_recorded_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("exists-but-unrecorded.txt");
    std::fs::write(&path, b"content").unwrap();
    let basis = sample_basis(MaterializedObjectKind::RegularFile, None);
    assert_eq!(
        revalidate_identity_against_disk(
            &basis,
            &path,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
        ),
        IdentityRevalidation::NotAMatch
    );
}

#[test]
fn a_new_generation_can_be_looked_up_back_exactly() {
    let conn = open();
    let version = VersionHash([5; 32]);
    let identity = sample_identity();
    let written = record_materialized_generation(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&version),
        Some(&identity),
        1000,
    )
    .unwrap();
    let read = lookup_materialized_generation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(read, written);
    assert_eq!(read.version, Some(version));
    assert_eq!(read.filesystem_identity, Some(identity));
}

#[test]
fn an_absent_path_is_recorded_as_its_own_object_kind_not_a_missing_row() {
    let conn = open();
    record_materialized_generation(
        &conn,
        "g",
        "gone.txt",
        MaterializedObjectKind::Absent,
        None,
        None,
        1000,
    )
    .unwrap();
    let read = lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().unwrap();
    assert_eq!(read.object_kind, MaterializedObjectKind::Absent);
    assert!(read.version.is_none());
    assert!(read.filesystem_identity.is_none());
}

#[test]
fn lookup_of_a_never_recorded_path_is_none() {
    let conn = open();
    assert!(lookup_materialized_generation(&conn, "g", "never.txt").unwrap().is_none());
}

#[test]
fn recording_a_new_generation_replaces_the_row_under_a_fresh_id_not_in_place() {
    // The immutability rule: a later generation is a NEW row under a
    // new id, never an edit of the old basis in place. Proven
    // here by writing two different bases at the same path and
    // confirming the second call's `generation_id` differs from the
    // first's, and that a lookup only ever sees the latest, complete
    // row -- never a hybrid of the two.
    let conn = open();
    let first = record_materialized_generation(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([1; 32])),
        None,
        1000,
    )
    .unwrap();
    let second = record_materialized_generation(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([2; 32])),
        None,
        2000,
    )
    .unwrap();
    assert_ne!(first.generation_id, second.generation_id);
    // Both generations rest on the same reflected-heads basis (no heads
    // recorded here); what differs is the version each one proves.
    assert_eq!(first.basis, second.basis);
    assert_ne!(first.version, second.version);
    let read = lookup_materialized_generation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(read, second, "must read back exactly the latest generation, not a merge");
}

#[test]
fn many_paths_each_get_their_own_generation_row() {
    let conn = open();
    for i in 0..1000 {
        record_materialized_generation(
            &conn,
            "g",
            &format!("path-{i}.txt"),
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
            None,
            1000,
        )
        .unwrap();
    }
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM path_materialized_generations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1000, "each path gets its own generation row");
}

#[test]
fn different_paths_with_the_same_content_share_a_resolved_path_state_hash_only_if_the_path_matches()
{
    // `resolved_path_state_hash` is keyed by path (a symlink named `a`
    // pointing at content X is not interchangeable with one named `b`
    // pointing at the same content) -- confirmed here as a property of
    // the hash itself, not the table.
    let a = compute_resolved_path_state_hash(
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([1; 32])),
    );
    let b = compute_resolved_path_state_hash(
        "g",
        "b.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([1; 32])),
    );
    assert_ne!(a, b);
}

#[test]
fn resolved_path_state_hash_distinguishes_absent_from_every_present_kind() {
    let absent = compute_resolved_path_state_hash("g", "a", MaterializedObjectKind::Absent, None);
    let file = compute_resolved_path_state_hash(
        "g",
        "a",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([1; 32])),
    );
    let dir = compute_resolved_path_state_hash("g", "a", MaterializedObjectKind::Directory, None);
    assert_ne!(absent, file);
    assert_ne!(absent, dir);
}

// The filesystem-side mutation fence.

#[test]
fn bump_mutation_fence_starts_at_one_and_increments_on_each_call() {
    let conn = open();
    assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap(), 1);
    assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "materialize", 2000).unwrap(), 2);
    assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "retire", 3000).unwrap(), 3);
}

#[test]
fn bump_mutation_fence_never_touches_an_unrelated_path() {
    let conn = open();
    bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    bump_mutation_fence(&conn, "g", "b.txt", "materialize", 1000).unwrap();
    assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "materialize", 2000).unwrap(), 2);
    // b.txt's own fence must still read back at 1, not have been bumped
    // by a.txt's second bump.
    let b = snapshot_mutation_fence(&conn, "g", "b.txt").unwrap();
    assert_eq!(b, 1);
}

#[test]
fn snapshot_mutation_fence_creates_a_row_at_generation_zero_without_bumping_it() {
    let conn = open();
    let first = snapshot_mutation_fence(&conn, "g", "never-mutated.txt").unwrap();
    assert_eq!(first, 0);
    // A second snapshot of the same never-mutated path reads the same
    // value back -- snapshotting must never itself advance the fence.
    let second = snapshot_mutation_fence(&conn, "g", "never-mutated.txt").unwrap();
    assert_eq!(second, 0);
}

#[test]
fn snapshot_mutation_fence_reads_the_live_value_after_a_real_bump() {
    let conn = open();
    bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    bump_mutation_fence(&conn, "g", "a.txt", "materialize", 2000).unwrap();
    assert_eq!(snapshot_mutation_fence(&conn, "g", "a.txt").unwrap(), 2);
}

#[test]
fn record_materialized_generation_is_immediately_usable_via_lookup() {
    // The unification property this design relies on: an existing
    // caller with no knowledge of mutation fences (record_materialized_
    // generation's own contract, unchanged) still produces a row the
    // new fail-closed lookup trusts right away.
    let conn = open();
    let version = VersionHash([5; 32]);
    record_materialized_generation(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&version),
        None,
        1000,
    )
    .unwrap();
    assert!(lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_some());
}

#[test]
fn a_row_becomes_unusable_the_moment_something_else_bumps_the_fence() {
    // The fence's whole point: a published proof must stop being
    // usable the instant a physical mutation touches the path again,
    // even one this module knows nothing about the origin of.
    let conn = open();
    record_materialized_generation(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([5; 32])),
        None,
        1000,
    )
    .unwrap();
    assert!(lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_some());

    bump_mutation_fence(&conn, "g", "a.txt", "some-other-mutator", 2000).unwrap();

    assert!(
        lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_none(),
        "a row published under a now-superseded fence generation must not be returned as usable"
    );
    assert!(
        lookup_materialized_generation_diagnostic(&conn, "g", "a.txt").unwrap().is_some(),
        "the diagnostic accessor must still be able to see the stale row"
    );
}

#[test]
fn publish_if_fence_current_succeeds_when_the_claimed_epoch_is_still_live() {
    let conn = open();
    let claimed = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([5; 32])),
        None,
        claimed,
        2000,
    )
    .unwrap();
    assert!(published.is_some());
    assert!(lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_some());
}

/// The headline regression this whole mechanism exists for: an attempt
/// whose claimed epoch has been superseded by an independent mutator
/// must have its publication rejected, regardless of the native frontier
/// (which this test never even touches) -- Context finding 8's race.
#[test]
fn publish_if_fence_current_is_rejected_once_an_independent_mutator_has_bumped_it() {
    let conn = open();
    let claimed = bump_mutation_fence(&conn, "g", "c.txt", "materialize", 1000).unwrap();

    // An independent mutator (e.g. retirement) acts on the same path
    // before the first attempt's publication runs.
    bump_mutation_fence(&conn, "g", "c.txt", "retire", 1500).unwrap();

    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "c.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([5; 32])),
        None,
        claimed,
        2000,
    )
    .unwrap();
    assert!(published.is_none(), "a stale publication must be rejected, not silently accepted");
    assert!(
        lookup_materialized_generation(&conn, "g", "c.txt").unwrap().is_none(),
        "the rejected publication must not have written anything usable"
    );
}

#[test]
fn publish_if_fence_current_is_rejected_when_no_fence_row_exists_at_all() {
    // The "no row yet" variant of the same race: an attempt claiming an
    // epoch for a path with no fence row at all (e.g. it never actually
    // called bump_mutation_fence, or the row was never created) must
    // fail the same way as a superseded epoch, not succeed vacuously.
    let conn = open();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "never-fenced.txt",
        MaterializedObjectKind::RegularFile,
        Some(&VersionHash([5; 32])),
        None,
        1,
        2000,
    )
    .unwrap();
    assert!(published.is_none());
}

#[test]
fn a_path_with_no_admission_or_mutation_ever_has_no_usable_generation() {
    let conn = open();
    assert!(lookup_materialized_generation(&conn, "g", "never.txt").unwrap().is_none());
    assert!(lookup_materialized_generation_diagnostic(&conn, "g", "never.txt").unwrap().is_none());
}

/// An invalidated `Absent` proof must be exactly as unusable as no
/// proof at all -- "unknown" must never be conflated with "absent," so
/// a caller must never be tempted to treat "was Absent, since invalidated"
/// as good enough to short-circuit real verification. A freshly
/// republished Absent record, by contrast, is usable again.
#[test]
fn an_invalidated_absent_generation_is_unusable_exactly_like_no_proof_while_a_fresh_one_is_usable()
{
    let conn = open();
    record_materialized_generation(
        &conn,
        "g",
        "gone.txt",
        MaterializedObjectKind::Absent,
        None,
        None,
        1000,
    )
    .unwrap();
    assert_eq!(
        lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().map(|b| b.object_kind),
        Some(MaterializedObjectKind::Absent),
        "a fresh Absent record must be usable"
    );

    // An independent mutator touches the path without republishing.
    bump_mutation_fence(&conn, "g", "gone.txt", "some-other-mutator", 2000).unwrap();

    assert!(
        lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().is_none(),
        "an invalidated Absent proof must not be returned as usable"
    );
    assert_eq!(
        lookup_materialized_generation(&conn, "g", "gone.txt").unwrap(),
        lookup_materialized_generation(&conn, "g", "truly-never-recorded.txt").unwrap(),
        "invalidated-Absent must be indistinguishable from no-proof-at-all to a caller"
    );
    let diag = lookup_materialized_generation_diagnostic(&conn, "g", "gone.txt").unwrap().unwrap();
    assert_eq!(
        diag.object_kind,
        MaterializedObjectKind::Absent,
        "diagnostic still sees it was Absent"
    );

    // Republishing under the now-current fence makes it usable again.
    let current_fence = snapshot_mutation_fence(&conn, "g", "gone.txt").unwrap();
    let republished = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "gone.txt",
        MaterializedObjectKind::Absent,
        None,
        None,
        current_fence,
        3000,
    )
    .unwrap();
    assert!(republished.is_some());
    assert_eq!(
        lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().map(|b| b.object_kind),
        Some(MaterializedObjectKind::Absent),
        "a genuinely fresh Absent record must be usable again"
    );
}

/// Bumping the fence invalidates a row for
/// `lookup_materialized_generation` (covered elsewhere) but must not
/// mutate the row's own content -- causal basis, kind, version, hash
/// all survive unchanged, visible via the diagnostic accessor.
#[test]
fn bumping_the_fence_leaves_the_proof_rows_own_content_untouched() {
    let conn = open();
    let version = VersionHash([7; 32]);
    let identity = sample_identity();
    record_materialized_generation(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        Some(&version),
        Some(&identity),
        1000,
    )
    .unwrap();
    let before = lookup_materialized_generation_diagnostic(&conn, "g", "a.txt").unwrap().unwrap();

    bump_mutation_fence(&conn, "g", "a.txt", "some-other-mutator", 2000).unwrap();

    let after = lookup_materialized_generation_diagnostic(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(before, after, "a fence bump must not mutate the proof row's own content");
    assert_eq!(after.object_kind, MaterializedObjectKind::RegularFile);
    assert_eq!(after.version, Some(version));
    assert_eq!(after.filesystem_identity, Some(identity));
}

/// The "no row yet" variant: a first-time materialization attempt's
/// evidence (fence bumped once, never
/// published) is rejected on the fence alone once an independent
/// mutator bumps past it -- even though NO `path_materialized_
/// generations` row has ever existed for this path, so there is
/// nothing for the rejection to compare against or invalidate except
/// the fence table itself. Distinguishes from `publish_if_fence_
/// current_is_rejected_once_an_independent_mutator_has_bumped_it`
/// (which already proves the identical mechanism) only by also
/// asserting the diagnostic accessor sees NO row at all -- not even a
/// stale one -- proving the fence exists independently of the proof
/// row's own lifecycle.
#[test]
fn stale_first_publication_is_rejected_when_no_proof_row_existed_yet() {
    let conn = open();
    let first_attempt_epoch =
        bump_mutation_fence(&conn, "g", "c.txt", "materialize", 1000).unwrap();
    bump_mutation_fence(&conn, "g", "c.txt", "independent-mutator", 1500).unwrap();

    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "c.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        first_attempt_epoch,
        2000,
    )
    .unwrap();

    assert!(published.is_none(), "a stale first publication must be rejected on the fence alone");
    assert!(lookup_materialized_generation(&conn, "g", "c.txt").unwrap().is_none());
    assert!(
        lookup_materialized_generation_diagnostic(&conn, "g", "c.txt").unwrap().is_none(),
        "no row of any kind -- not even a stale one -- may ever be created by a rejected \
         first publication"
    );
}

// Directories in the namespace projection.

/// A directory generation vouches for the directory, not for its
/// entries: a child landing inside it moves the directory's size and
/// timestamps, and must not make the directory's own proof unusable.
#[test]
fn directory_generation_revalidates_after_child_added() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("d");
    std::fs::create_dir(&dir).unwrap();
    let observed = FileIdentity::observe_path(&dir).unwrap();
    for kind in [MaterializedObjectKind::Directory, MaterializedObjectKind::StructuralDirectory] {
        let basis = sample_basis(kind, Some(observed));
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.join(format!("child-{kind:?}")), b"child").unwrap();
        assert_eq!(
            revalidate_identity_against_disk(
                &basis,
                &dir,
                yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
            ),
            IdentityRevalidation::Confirmed,
            "{kind:?}"
        );
    }
}

/// An explicitly absent path whose projection holds a structural
/// directory -- its entry was deleted, a descendant still lives -- is
/// exactly a directory on disk. That is the state the `Absent` basis
/// describes, not a contradiction of it.
#[test]
fn absent_basis_over_structural_directory_confirms() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("a");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("x"), b"live descendant").unwrap();
    let basis = sample_basis(MaterializedObjectKind::Absent, None);
    let granularity = yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine;
    assert_eq!(
        revalidate_identity_against_projected_disk(
            &basis,
            &dir,
            granularity,
            ProjectedAtPath::StructuralDirectory,
        ),
        IdentityRevalidation::Confirmed
    );
    // Without a structural directory in the projection, a directory there
    // still contradicts absence.
    assert_eq!(
        revalidate_identity_against_projected_disk(
            &basis,
            &dir,
            granularity,
            ProjectedAtPath::NoStructuralDirectory,
        ),
        IdentityRevalidation::NotAMatch
    );
    assert_eq!(
        revalidate_identity_against_disk(&basis, &dir, granularity),
        IdentityRevalidation::NotAMatch
    );
    // A file is never the structural container.
    let file = root.path().join("f");
    std::fs::write(&file, b"not a directory").unwrap();
    assert_eq!(
        revalidate_identity_against_projected_disk(
            &basis,
            &file,
            granularity,
            ProjectedAtPath::StructuralDirectory,
        ),
        IdentityRevalidation::NotAMatch
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_to_a_directory_is_not_a_structural_container() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = root.path().join("a");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(
        revalidate_identity_against_projected_disk(
            &sample_basis(MaterializedObjectKind::Absent, None),
            &link,
            yadorilink_fs_platform::fs_identity::TimestampGranularity::Fine,
            ProjectedAtPath::StructuralDirectory,
        ),
        IdentityRevalidation::NotAMatch
    );
}

/// A structural directory has no version to carry, and its generation is
/// usable without one.
#[test]
fn a_structural_directory_generation_is_usable_without_a_version() {
    let conn = open();
    let mut identity = sample_identity();
    identity.object_kind = ObjectKind::Directory;
    let written = record_materialized_generation(
        &conn,
        "g",
        "a",
        MaterializedObjectKind::StructuralDirectory,
        None,
        Some(&identity),
        1,
    )
    .unwrap();
    let read = lookup_materialized_generation(&conn, "g", "a").unwrap().expect("usable");
    assert_eq!(read, written);
    assert_eq!(read.object_kind, MaterializedObjectKind::StructuralDirectory);
    assert_eq!(read.version, None);
}

#[test]
fn a_versionless_kind_carrying_a_version_is_refused() {
    let conn = open();
    for kind in [MaterializedObjectKind::StructuralDirectory, MaterializedObjectKind::Absent] {
        let err = record_materialized_generation(
            &conn,
            "g",
            "a",
            kind,
            Some(&VersionHash([1; 32])),
            None,
            1,
        )
        .expect_err("a versionless kind with a version must be refused");
        assert!(matches!(err, SyncSqliteError::InvalidInput(_)), "{kind:?}: {err:?}");
    }
}

#[test]
fn resolved_path_state_hash_distinguishes_a_structural_directory() {
    let structural = compute_resolved_path_state_hash(
        "g",
        "a",
        MaterializedObjectKind::StructuralDirectory,
        None,
    );
    for (kind, version) in [
        (MaterializedObjectKind::Absent, None),
        (MaterializedObjectKind::Directory, None),
        (MaterializedObjectKind::Directory, Some(VersionHash([1; 32]))),
    ] {
        assert_ne!(
            structural,
            compute_resolved_path_state_hash("g", "a", kind, version.as_ref()),
            "{kind:?}"
        );
    }
}
