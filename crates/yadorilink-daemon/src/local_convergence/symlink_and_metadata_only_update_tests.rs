#![cfg(test)]

use super::types::{
    materialize_symlink_at, try_apply_metadata_only_update, SymlinkMaterialization,
    SymlinkMaterializeOutcome,
};
use crate::replica_coordinator::ReplicaCoordinator;
use std::sync::Arc;
use yadorilink_replica_domain::file::BlockInfo;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
#[cfg(unix)]
use yadorilink_replica_domain::session_state::MaterializationState;

/// The version a materialization is applying, built from the values
/// that will actually be written -- the payload's shape, not the
/// row's. Both tests below deliberately seed the index row with
/// DIFFERENT values and assert that what lands on disk came from
/// here, which is the whole provenance invariant: the row is a guard,
/// the payload decides what gets written.
fn payload_version(
    record: &FileRecord,
    record_kind: RecordKind,
    unix_mode: Option<u32>,
    symlink_target: Option<&[u8]>,
) -> FileVersion {
    FileVersion::from_index_row(
        record.blocks.clone(),
        record.size,
        record.mtime_unix_nanos,
        record_kind,
        unix_mode,
        symlink_target.map(|t| t.to_vec()),
        Vec::new(),
    )
}

/// A real, in-memory `ReplicaCoordinator` with `root` linked as
/// `group-1`'s eager sync root and its marker written, so the root
/// re-verification every lane here performs has a genuine identity to
/// check against.
fn linked_state(root: &std::path::Path) -> Arc<ReplicaCoordinator> {
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let local_path = root.to_string_lossy().to_string();
    state.link_repository().add_link(&local_path, "group-1").unwrap();
    state
        .link_repository()
        .set_materialization_policy(&local_path, MaterializationPolicy::Eager)
        .unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(root, "group-1", state.as_ref())
        .unwrap();
    state
}

fn seed_file(state: &ReplicaCoordinator, record: &FileRecord) {
    state
        .file_index_repository()
        .upsert_file(
            "group-1",
            record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
}

fn symlink_record(path: &str) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    }
}

fn file_record_with_block(path: &str, hash_byte: u8) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 5,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: vec![hash_byte; 32], offset: 0, size: 5 }],
        deleted: false,
    }
}

#[cfg(unix)]
/// Seeds `path` as a symlink row whose target is `row_target`.
fn seed_symlink_row(state: &ReplicaCoordinator, record: &FileRecord, row_target: &[u8]) {
    seed_file(state, record);
    state
        .file_index_repository()
        .set_record_kind(
            "group-1",
            &record.path,
            RecordKind::Symlink,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", &record.path, Some(row_target))
        .unwrap();
}

#[cfg(unix)]
fn materialize_link(
    state: &ReplicaCoordinator,
    root: &std::path::Path,
    record: &FileRecord,
    payload_target: &[u8],
) -> SymlinkMaterializeOutcome {
    materialize_symlink_at(
        SymlinkMaterialization {
            state,
            root,
            group_id: "group-1",
            windows_opt_in: false,
            origin_device_id: "device-a",
            authoring: None,
            permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        },
        record,
        &payload_version(record, RecordKind::Symlink, None, Some(payload_target)),
    )
    .unwrap()
}

/// Given a payload that is a symlink with a target, and a row naming
/// that same version, `materialize_symlink_at` creates a real on-disk
/// symlink, publishes its proof and stamps `Present`.
#[cfg(unix)]
#[test]
fn materialize_symlink_at_creates_a_real_symlink_and_upserts_index() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let record = symlink_record("link.txt");
    seed_symlink_row(&state, &record, b"target.txt");

    let outcome = materialize_link(&state, root.path(), &record, b"target.txt");

    assert!(
        matches!(outcome, SymlinkMaterializeOutcome::WrittenExact { .. }),
        "a genuine on-disk write must report WrittenExact -- only this outcome may ever \
         settle as ExactObject: {outcome:?}"
    );
    let out_path = root.path().join("link.txt");
    assert!(
        std::fs::symlink_metadata(&out_path).unwrap().file_type().is_symlink(),
        "must be a real symlink on disk"
    );
    assert_eq!(std::fs::read_link(&out_path).unwrap(), std::path::Path::new("target.txt"));
    assert!(!state.get_file("group-1", "link.txt").unwrap().unwrap().deleted);
    // The symlink genuinely exists on disk under its exact name now --
    // `materialize_symlink_at`'s own stamp on this `WrittenExact`
    // branch is what earns `Present` here, not the schema's own
    // `Remote` default.
    assert_eq!(
        state.get_materialization_state("group-1", "link.txt").unwrap(),
        Some(MaterializationState::Present),
    );
}

/// When the current row names a different target from the payload, what is
/// written is the payload's target, and the row it leaves behind is the
/// payload's version: its target is written with the new row, while the row
/// it replaces keeps the target it was authored with.
///
/// This function used to read `state.get_symlink_target` and would
/// place the row's target on disk, so the link assertion below is a
/// regression test for that exact break: the proof names the payload's
/// version, and `version_hash` bakes the target in. A supersession that
/// lands after the write's own row is the refused-proof case, covered by
/// the armed-supersession test further down.
#[cfg(unix)]
#[test]
fn materialize_symlink_at_writes_the_payload_target_over_a_row_naming_another() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let record = symlink_record("link.txt");
    seed_symlink_row(&state, &record, b"row-target.txt");

    let outcome = materialize_link(&state, root.path(), &record, b"target.txt");

    assert_eq!(
        std::fs::read_link(root.path().join("link.txt")).unwrap(),
        std::path::Path::new("target.txt"),
        "the link must point at the PAYLOAD's target; reading the target from the index \
         row instead would have written `row-target.txt` here"
    );
    assert!(matches!(outcome, SymlinkMaterializeOutcome::WrittenExact { .. }), "{outcome:?}");
    assert_eq!(
        state.get_symlink_target("group-1", "link.txt").unwrap().as_deref(),
        Some(&b"target.txt"[..]),
        "the new row shows the payload's target"
    );
    let superseded: Option<Vec<u8>> = state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT symlink_target FROM files WHERE group_id = 'group-1' \
                 AND path = 'link.txt' AND state = 'superseded'",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(
        superseded.as_deref(),
        Some(&b"row-target.txt"[..]),
        "the superseded row keeps the target it was authored with"
    );
}

/// A free function, not a `PeerSyncSession` method, so it cannot go
/// through `self.verify_write_target` (which additionally re-verifies
/// `VerifiedRoot` identity) -- this must re-verify directly instead of
/// relying only on `verify_write_target_within_root`'s lexical
/// containment check, which cannot detect a root whose mountpoint has
/// been replaced.
#[test]
fn materialize_symlink_at_refuses_a_root_whose_marker_no_longer_matches() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let record = symlink_record("link.txt");
    seed_file(&state, &record);
    state
        .file_index_repository()
        .set_record_kind(
            "group-1",
            "link.txt",
            RecordKind::Symlink,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "link.txt", Some(b"target.txt"))
        .unwrap();

    std::fs::remove_file(
        root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    )
    .unwrap();

    let result = materialize_symlink_at(
        SymlinkMaterialization {
            state: state.as_ref(),
            root: root.path(),
            group_id: "group-1",
            windows_opt_in: false,
            origin_device_id: "device-a",
            authoring: None,
            permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        },
        &record,
        // A payload that genuinely WOULD have written, so the
        // refusal below is the root check doing its job rather than
        // a payload that was never eligible to write anything.
        &payload_version(&record, RecordKind::Symlink, None, Some(b"target.txt")),
    );
    assert!(
        result.is_err(),
        "a symlink write under a root whose marker no longer matches must be refused"
    );
    assert!(
        !root.path().join("link.txt").exists(),
        "nothing must be written when root identity fails to verify"
    );
}

/// `verify_write_target_within_root`
/// is not a pure check -- it `create_dir_all`s the sync root and the
/// target's parent directory as a side effect. If `VerifiedRoot::
/// verify` ran AFTER that call instead of before, a root whose
/// mountpoint was unmounted and replaced by something else at the
/// same path would still get a brand-new directory created on it
/// (for a nested path whose parent doesn't exist yet) before the
/// identity mismatch was ever detected -- mutating the wrong
/// filesystem despite the write itself being correctly refused.
#[test]
fn materialize_symlink_at_creates_no_directories_under_a_root_whose_marker_no_longer_matches() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let record = symlink_record("sub/nested/link.txt");
    seed_file(&state, &record);
    state
        .file_index_repository()
        .set_record_kind(
            "group-1",
            "sub/nested/link.txt",
            RecordKind::Symlink,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    state
        .file_index_repository()
        .set_symlink_target("group-1", "sub/nested/link.txt", Some(b"target.txt"))
        .unwrap();

    std::fs::remove_file(
        root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    )
    .unwrap();

    let result = materialize_symlink_at(
        SymlinkMaterialization {
            state: state.as_ref(),
            root: root.path(),
            group_id: "group-1",
            windows_opt_in: false,
            origin_device_id: "device-a",
            authoring: None,
            permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        },
        &record,
        // As above: a payload that genuinely would have written.
        &payload_version(&record, RecordKind::Symlink, None, Some(b"target.txt")),
    );
    assert!(
        result.is_err(),
        "a symlink write under a root whose marker no longer matches must be refused"
    );
    assert!(
        !root.path().join("sub").exists(),
        "no directory must be created under a root that fails identity verification, even \
         for a nested path whose parent doesn't exist yet"
    );
}

/// A symlink record with no recorded target (shouldn't normally
/// happen, but must be handled defensively) must never create a
/// broken/empty placeholder on disk — the index row still gets
/// updated, just nothing is written to the filesystem.
#[test]
fn materialize_symlink_at_with_no_target_recorded_skips_disk_write_but_still_indexes() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let record = symlink_record("mystery-link");
    seed_file(&state, &record);
    state
        .file_index_repository()
        .set_record_kind(
            "group-1",
            "mystery-link",
            RecordKind::Symlink,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // The PAYLOAD names no target -- that is what makes this a
    // policy skip now. The row's own `symlink_target` is deliberately
    // left unset too, but it is no longer what decides.

    let outcome = materialize_symlink_at(
        SymlinkMaterialization {
            state: state.as_ref(),
            root: root.path(),
            group_id: "group-1",
            windows_opt_in: false,
            origin_device_id: "device-a",
            authoring: None,
            permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        },
        &record,
        &payload_version(&record, RecordKind::Symlink, None, None),
    )
    .unwrap();

    // Regression: this outcome
    // must never be mistaken for a genuine on-disk write -- a caller
    // that unconditionally proceeded to `ExactObject` on any `Ok`
    // would falsely claim disk holds this exact desired version.
    assert_eq!(outcome, SymlinkMaterializeOutcome::PolicySkipped);
    assert_eq!(
        state.dag_snapshot_mutation_fence("group-1", "mystery-link").unwrap(),
        0,
        "a policy skip must never bump the mutation fence -- there is no mutation to \
         account for"
    );
    assert!(
        !root.path().join("mystery-link").exists(),
        "must not create anything on disk without a recorded target"
    );
    assert_eq!(
        state.get_record_kind("group-1", "mystery-link").unwrap(),
        Some(RecordKind::Symlink)
    );
}

/// When the incoming record's block list is byte-identical
/// to what's already indexed locally, the fast path applies the full
/// indexed permission bits (via a real chmod) and index bookkeeping
/// (mtime/version), leaving the file's actual content bytes completely
/// untouched.
#[cfg(unix)]
#[test]
fn metadata_only_fast_path_applies_unix_mode_without_touching_content() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    let mut local = file_record_with_block("script.sh", 0xAB);
    local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &local);

    let out_path = root.path().join("script.sh");
    std::fs::write(&out_path, b"hello").unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    // Deliberately NOT the mode the payload names. This function used
    // to read `state.get_unix_mode`/`state.get_xattrs` after its own
    // upsert while ignoring the `desired_version` it was handed
    // (`let _ = desired_version;`), so seeding a different mode here
    // is a regression test for that exact break: a supersession
    // landing mid-call would have applied the row's mode while the
    // caller settled under the payload's `version_hash`, which bakes
    // the mode in.
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "script.sh",
            Some(0o700),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let mut incoming = local.clone();
    incoming.mtime_unix_nanos = 999;

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        &payload_version(&incoming, RecordKind::File, Some(0o755), None),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert!(applied.is_some(), "an identical block list must take the metadata-only fast path");

    let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o777,
        0o755,
        "the full mode the PAYLOAD names must be applied via chmod, not merged with \
         whatever was already on disk, and not taken from the index row (seeded 0o700 \
         above) -- the proof settles under the payload's version_hash, which bakes the \
         mode in"
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), b"hello", "content bytes must be untouched");

    let stored = state.get_file("group-1", "script.sh").unwrap().unwrap();
    assert_eq!(stored.mtime_unix_nanos, 999, "index bookkeeping must still be updated");

    // A real chmod is a genuine physical mutation, exactly like a
    // content write -- the fence must be BUMPED for it, never
    // snapshotted. This path has no fence row yet: a snapshot creates
    // it at 0, and a bump creates it at 1 and returns that, so
    // `Some(1)` here is only reachable via a real bump, never a
    // snapshot of the untouched initial value.
    assert_eq!(
        applied.map(|update| update.mutation_generation),
        Some(1),
        "a genuine mode change (0o644 on disk vs. 0o755 desired) must bump the mutation \
         fence, not snapshot it -- a chmod is a real mutating syscall"
    );
}

/// The companion of the above: when the indexed mode already matches
/// what's genuinely on disk (no drift at all), applying it performs no
/// real syscall, and the fence must be SNAPSHOTTED, not bumped --
/// otherwise every routine content-identical verification would pay
/// the same writer-gate cost a real mutation does, purely because
/// metadata happened to be checked at all. Confirmed genuinely RED by
/// temporarily making `try_apply_metadata_only_update` always bump
/// (never compare first): this test's fence assertion then failed,
/// since a bump from the untouched initial value of 0 is observably
/// different from a snapshot of it.
#[cfg(unix)]
#[test]
fn metadata_only_fast_path_snapshots_the_fence_when_metadata_already_matches_disk() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    let mut local = file_record_with_block("already-correct.sh", 0xAB);
    local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &local);

    let out_path = root.path().join("already-correct.sh");
    std::fs::write(&out_path, b"hello").unwrap();
    // Disk already has the exact mode the PAYLOAD names -- no drift
    // at all. Passing a payload with no mode at all would make
    // "already matches" trivially true and this test vacuous, so the
    // payload below names 0o755 explicitly.
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "already-correct.sh",
            Some(0o755),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let mut incoming = local.clone();
    incoming.mtime_unix_nanos = 999;
    // Disk already has the exact mtime the index will say is
    // desired too -- see this test's own name: NO genuine drift in
    // ANY metadata field, mtime included (mtime is part of this same
    // snapshot-vs-bump decision).
    yadorilink_local_storage::stamp_mtime_at_path(&out_path, incoming.mtime_unix_nanos).unwrap();

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        &payload_version(&incoming, RecordKind::File, Some(0o755), None),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert_eq!(
        applied.map(|update| update.mutation_generation),
        Some(0),
        "no genuine metadata drift means no real mutating syscall, so the fence must be \
         snapshotted at its untouched initial value, never bumped"
    );
}

/// Regression: a same-content
/// version whose ONLY change is mtime (an ordinary "touch") must
/// still bump the fence (a real mutating syscall is about to be
/// attempted) AND actually attempt to stamp the new mtime onto disk
/// -- mtime is retained-only (never blocks completion), but that
/// must never mean "never even attempted" on a target that can
/// genuinely set it. Confirmed genuinely RED against a version of
/// this fast path that decided snapshot-vs-bump from unix_mode/
/// xattrs alone: it snapshotted (never bumping, never stamping) even
/// though the desired mtime differed from what was on disk, leaving
/// disk mtime permanently stale for this file.
#[test]
fn metadata_only_fast_path_stamps_mtime_on_a_touch_only_change() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    // Multiples of 100ns: Windows' FILETIME, and therefore
    // `std::fs::FileTimes`, only has 100ns resolution, so any other value
    // would round-trip through `stamp_mtime_at_path` as a different number
    // there and fail the exact-match assertion below for a reason that has
    // nothing to do with what this test is checking.
    let mut local = file_record_with_block("touched.txt", 0xAB);
    local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    local.mtime_unix_nanos = 100;
    seed_file(&state, &local);

    let out_path = root.path().join("touched.txt");
    std::fs::write(&out_path, b"hello").unwrap();
    yadorilink_local_storage::stamp_mtime_at_path(&out_path, 100).unwrap();

    let mut incoming = local.clone();
    incoming.mtime_unix_nanos = 200;

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(incoming.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert_eq!(
        applied.map(|update| update.mutation_generation),
        Some(1),
        "an mtime-only change is a real mutating syscall attempt and must bump the fence, \
         not snapshot it"
    );
    assert!(
        yadorilink_local_storage::mtime_already_matches_disk(&out_path, 200).unwrap(),
        "the new mtime must actually be stamped onto disk, not merely recorded in the index"
    );
}

/// A free function, not a `PeerSyncSession` method -- cannot go
/// through `self.verify_write_target`'s `VerifiedRoot` re-check, so
/// this must re-verify directly right before the chmod, not rely
/// only on the earlier lexical-containment check.
#[cfg(unix)]
#[test]
fn metadata_only_fast_path_refuses_a_root_whose_marker_no_longer_matches() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    let mut local = file_record_with_block("script.sh", 0xAB);
    local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &local);

    let out_path = root.path().join("script.sh");
    std::fs::write(&out_path, b"hello").unwrap();
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "script.sh",
            Some(0o755),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    std::fs::remove_file(
        root.path().join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
    )
    .unwrap();

    let mut incoming = local.clone();
    incoming.mtime_unix_nanos = 999;
    let result = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(incoming.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    );
    assert!(
        result.is_err(),
        "a metadata-only update under a root whose marker no longer matches must be refused"
    );
}

#[test]
fn metadata_only_fast_path_rejects_index_match_when_disk_bytes_do_not_match() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let mut record = file_record_with_block("partial.bin", 0xAB);
    record.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &record);
    std::fs::write(root.path().join("partial.bin"), b"wrong").unwrap();

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &record,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(record.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert!(applied.is_none(), "an interrupted materialization must take the reconstruct path");
}

/// Regression: a stale index
/// entry still classified as a plain `File`, whose on-disk path has
/// since been replaced (by a local actor, or a race) with a symlink
/// pointing OUTSIDE the sync root, must never let this fast path
/// chmod/xattr through that symlink onto the outside target --
/// `verify_write_target_within_root` only confirms the *parent*
/// directory chain, and `disk_bytes_match_indexed_blocks`/
/// `apply_unix_mode`/`apply_xattrs` all follow a terminal symlink.
/// Confirmed genuinely RED by temporarily removing the
/// `terminal_object_is_a_regular_file` check: the outside target's
/// permissions were chmodded even though it is physically outside
/// this group's sync root.
#[cfg(unix)]
#[test]
fn metadata_only_fast_path_refuses_a_terminal_symlink_even_with_matching_content() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    let mut record = file_record_with_block("escape.txt", 0xAB);
    record.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &record);

    // The real target lives entirely outside the sync root, with
    // content that happens to match the indexed blocks exactly --
    // the scenario this test describes.
    let outside = tempfile::tempdir().unwrap();
    let outside_target = outside.path().join("secret.txt");
    std::fs::write(&outside_target, b"hello").unwrap();
    std::fs::set_permissions(&outside_target, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&outside_target, root.path().join("escape.txt")).unwrap();

    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "escape.txt",
            Some(0o755),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &record,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(record.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();

    assert!(
        applied.is_none(),
        "a terminal symlink must never be accepted by this fast path, regardless of \
         whether its target's content happens to match"
    );
    assert_eq!(
        std::fs::metadata(&outside_target).unwrap().permissions().mode() & 0o777,
        0o600,
        "the outside-root target's permissions must be completely untouched"
    );
}

#[test]
fn metadata_only_fast_path_does_not_apply_with_no_prior_local_record() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let record = file_record_with_block("new.bin", 0x11);

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &record,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(record.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert!(applied.is_none(), "brand-new adoption has nothing to compare against");
    assert!(
        state.get_file("group-1", "new.bin").unwrap().is_none(),
        "the fast path must not upsert anything when it doesn't apply"
    );
}

#[test]
fn metadata_only_fast_path_does_not_apply_when_content_actually_changed() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let local = file_record_with_block("doc.txt", 0x11);
    seed_file(&state, &local);

    let incoming = file_record_with_block("doc.txt", 0x22); // different hash = real content change

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(incoming.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert!(
        applied.is_none(),
        "a genuinely different block list must not take the metadata-only path"
    );
}

#[test]
fn metadata_only_fast_path_does_not_apply_to_a_deleted_local_record() {
    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());
    let mut local = file_record_with_block("gone.bin", 0x33);
    local.deleted = true;
    seed_file(&state, &local);

    let incoming = file_record_with_block("gone.bin", 0x33);

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        super::types::MaterializationPayload::tombstone(incoming.clone()).version(),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert!(applied.is_none(), "a tombstoned local record must fall through to ordinary handling");
}

/// A supersession landing in the MIDDLE of a materialization cannot
/// rename what that materialization writes.
///
/// This is the hazard the whole payload-provenance arc exists for,
/// and the only one a static fixture cannot express. Seeding the row
/// with different metadata before the call proves only that the
/// initial read is ignored; what has to be ruled out is a concurrent
/// writer moving the row while a materialization is between its
/// payload and its proof, because the row's version can move without
/// anything this write can see moving with it -- a supersession that
/// keeps the authoring identity is exactly that.
///
/// `TestObservers::armed_upsert_supersession` fires from the real
/// coordinator's own `upsert_file_with_origin`, which this lane calls
/// partway through its body, so the move lands inside the window.
/// The hook is compiled under `#[cfg(test)]` only; the lane itself
/// carries no seam.
///
/// Before payload provenance, this lane read `state.get_unix_mode`
/// AFTER that upsert, so the superseding version's mode reached disk
/// while the caller settled under the payload's own `version_hash` --
/// which bakes the mode in. The result was an `ExactObject` proof
/// that was false about the very field it had just applied, and the
/// exactness gate could not catch it: it was verifying against the
/// same row that had supplied the wrong value.
///
/// The row is left naming the superseding metadata on purpose. A
/// correct materialization still writes its own payload's mode; the
/// disagreement is then the fence's and the proof gate's problem, not
/// something to paper over by writing whatever the row last said.
#[cfg(unix)]
#[test]
fn a_supersession_during_the_write_cannot_rename_what_is_written() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    let mut local = file_record_with_block("contended.sh", 0xAB);
    local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &local);

    let out_path = root.path().join("contended.sh");
    std::fs::write(&out_path, b"hello").unwrap();
    // Genuine drift, so this lane really does reach its chmod rather
    // than taking the zero-mutation snapshot branch.
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "contended.sh",
            Some(0o644),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // V2: same content, same authoring identity, different mode --
    // the shape that moves a row's version without moving anything
    // an in-flight write can observe. Armed to land mid-call.
    //
    // Row only: the closure rewrites the current row's mode and nothing
    // else. It does not touch disk and does not go near the mutation
    // fence, because the race this test is about is a native state/index-side
    // supersession, not a competing physical mutator.
    let weak = Arc::downgrade(&state);
    *state.test_observers.armed_upsert_supersession.lock().unwrap() =
        Some(crate::replica_coordinator::test_observers::ArmedSupersession {
            group_id: "group-1".to_string(),
            path: "contended.sh".to_string(),
            apply: Box::new(move || {
                let state = weak.upgrade().expect("coordinator outlives the call");
                state
                    .file_index_repository()
                    .set_unix_mode(
                        "group-1",
                        "contended.sh",
                        Some(0o755),
                        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                    )
                    .unwrap();
            }),
        });

    let mut incoming = local.clone();
    incoming.mtime_unix_nanos = 999;
    // V1: the payload. 0o644 is what must reach disk.
    let desired = payload_version(&incoming, RecordKind::File, Some(0o644), None);

    let applied = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        &desired,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap();
    assert!(applied.is_some(), "an identical block list must take the metadata-only fast path");

    assert_eq!(
        state.get_unix_mode("group-1", "contended.sh").unwrap(),
        Some(0o755),
        "fixture check: the supersession must really have landed during the call, or this \
         test proves nothing"
    );
    assert_eq!(
        std::fs::metadata(&out_path).unwrap().permissions().mode() & 0o777,
        0o644,
        "disk must hold the mode the PAYLOAD names. Reading it from the row after the \
         upsert -- which is what this lane used to do -- would have written 0o755 here \
         while settling under the payload's version_hash, which bakes in 0o644: an \
         ExactObject proof false about the exact field it had just applied"
    );
}

/// A file whose mode already denies its owner read access (0o200) must not
/// make the metadata-only path fail with a raw permission error, and must
/// not be handed on as `None` either, which sends it to a path that may
/// replace it (an OnDemand group writes a placeholder over it, losing any
/// edit the scanner could not read). What it holds cannot be read, so its
/// metadata can be neither confirmed nor applied: the update is refused as
/// `MetadataUnprovable`, which the callers turn into a hold, and it is
/// refused before anything is mutated -- the fence is not bumped and the
/// row is not rewritten, so refusing it again later changes nothing either.
#[cfg(target_os = "linux")]
#[test]
fn metadata_only_update_on_an_already_owner_unreadable_file_is_refused_before_any_mutation() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let state = linked_state(root.path());

    let mut local = file_record_with_block("write-only.sh", 0xAB);
    local.blocks[0].hash = <sha2::Sha256 as sha2::Digest>::digest(b"hello").to_vec();
    seed_file(&state, &local);

    let out_path = root.path().join("write-only.sh");
    std::fs::write(&out_path, b"hello").unwrap();
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o200)).unwrap();
    if std::fs::read(&out_path).is_ok() {
        // Nothing is unreadable to root, so there is nothing to test.
        return;
    }
    state
        .file_index_repository()
        .set_unix_mode(
            "group-1",
            "write-only.sh",
            Some(0o200),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    let fence_before = state.dag_snapshot_mutation_fence("group-1", "write-only.sh").unwrap();

    let mut incoming = local.clone();
    incoming.mtime_unix_nanos = 999;
    let result = try_apply_metadata_only_update(
        state.as_ref(),
        root.path(),
        "group-1",
        &incoming,
        "device-a",
        None,
        &payload_version(&incoming, RecordKind::File, Some(0o200), None),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    );
    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    match result {
        Err(yadorilink_peer_session::error::PeerSessionError::MetadataUnprovable(path)) => {
            assert_eq!(path, "write-only.sh");
        }
        other => panic!("an unreadable file must be refused as MetadataUnprovable: {other:?}"),
    }
    assert_eq!(
        state.dag_snapshot_mutation_fence("group-1", "write-only.sh").unwrap(),
        fence_before,
        "a refused update must not bump the fence"
    );
    assert_eq!(
        state.get_file("group-1", "write-only.sh").unwrap().unwrap().mtime_unix_nanos,
        0,
        "a refused update must not rewrite the row"
    );
    assert_eq!(std::fs::read(&out_path).unwrap(), b"hello");
}
