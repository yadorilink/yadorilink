#![cfg(test)]

use super::*;
use yadorilink_replica_domain::ids::VersionHash;

/// The version the row itself derives, the one canonical way -- what
/// the finalizer's own guard recomputes, so a test that invents a
/// version hash is testing a supersession, not a publish.
fn current_version_of(coordinator: &ReplicaCoordinator, path: &str) -> VersionHash {
    let snapshot = coordinator
        .sqlite()
        .get_current_version_record(
            &yadorilink_replica_domain::ids::FolderGroupId("group-1".into()),
            path,
        )
        .unwrap()
        .expect("the row under test");
    yadorilink_replica_domain::session_state::CurrentVersionRecord::from(snapshot)
        .to_file_version()
        .version_hash
}

/// Leaves the row as an ordinary batch does before the physical
/// write: the transient state the finalizer's
/// guard expects to still find.
fn open_the_batch_row(coordinator: &ReplicaCoordinator, path: &str, permit: &RootCommitPermit) {
    coordinator
        .materialization_state_repository()
        .set_materialization_state(
            "group-1",
            path,
            yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
            permit,
        )
        .unwrap();
}

/// The happy path is the one that used to break: a successfully
/// observed eager-batch write must leave a proof the obligation can
/// actually settle on.
///
/// This finalizer used to route an internal write through
/// `adopt_local_capture_actual_state`, the EXTERNAL-adoption API, which
/// bumps the mutation fence itself. The write's own epoch `N` was
/// therefore already stale by the time the convergence engine CASed on
/// it, so every successfully observed write defeated its own
/// publication -- and because the proof was also versionless, the
/// resolved-path-state hash could never match a desired resolution
/// either, so zero-work settlement could not close the path and it was
/// re-materialized indefinitely. The failure mode got MORE reliable the
/// healthier the filesystem was.
///
/// Pins both halves: the fence stays at `N`, and the published proof
/// carries the version that was written.
#[test]
fn an_observed_eager_batch_write_publishes_a_versioned_proof_under_its_own_epoch() {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let record = FileRecord {
        path: "doc.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    coordinator.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();

    // The mutator's own bump, exactly as `try_commit_ordinary_batch`
    // performs it before publishing the file to its final path.
    let n = coordinator
        .dag_bump_mutation_fence("group-1", "doc.txt", "ordinary_batch_upsert_write")
        .unwrap();

    let observed_dir = tempfile::tempdir().unwrap();
    let observed_file = observed_dir.path().join("doc.txt");
    std::fs::write(&observed_file, b"").unwrap();
    let identity =
        yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&observed_file).unwrap();
    let version_hash = current_version_of(&coordinator, "doc.txt");
    open_the_batch_row(&coordinator, "doc.txt", &permit);

    let finished = vec![yadorilink_peer_session::ports::FinishedProjectedUpsert {
        rel_path: "doc.txt".to_string(),
        kind: RecordKind::File,
        version_hash,
        mutation_generation: n,
        observed_identity: Some(identity),
        expected_state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
    }];

    coordinator.finalize_projected_mutations_batch("group-1", &finished, &[], &permit).unwrap();

    // The proof is usable RIGHT NOW, which it can only be if it was
    // published under the still-current epoch `n`.
    let published = coordinator
        .sqlite()
        .dag_lookup_materialized_generation("group-1", "doc.txt")
        .unwrap()
        .expect("an observed write must leave a proof usable under its own epoch");
    assert_eq!(
        published.version,
        Some(version_hash),
        "the proof must name the version that was written: a versionless one matches no \
         desired resolution, so zero-work settlement could never close the path"
    );

    // And finalize did not advance the fence itself -- the next bump is
    // the one immediately after the write's own epoch.
    let fence_after =
        coordinator.dag_bump_mutation_fence("group-1", "doc.txt", "test_probe").unwrap();
    assert_eq!(
        fence_after,
        n + 1,
        "finalize must not move the fence: publishing under {n} and then bumping past it is \
         how this path used to defeat its own settlement CAS"
    );
}

/// A failed disk observation costs the proof its identity, and nothing
/// else.
///
/// `observed_identity` is `Option` because `observe_path` can fail on a
/// write that nonetheless completed; the version is not optional,
/// because usability is decided by the mutation fence and matching is
/// decided by the version. An earlier shape carried kind and identity
/// together as one `Option`, so losing the observation meant losing the
/// version too -- and a versionless proof matches no desired
/// resolution at all. The degraded case must still settle.
#[test]
fn an_unobserved_eager_batch_write_still_publishes_a_versioned_proof_under_its_own_epoch() {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let record = FileRecord {
        path: "doc.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    coordinator.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();

    let version_hash = current_version_of(&coordinator, "doc.txt");
    coordinator
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &version_hash.0, &permit)
        .unwrap();
    open_the_batch_row(&coordinator, "doc.txt", &permit);

    let n = coordinator
        .dag_bump_mutation_fence("group-1", "doc.txt", "ordinary_batch_upsert_write")
        .unwrap();

    // The write landed; only the observation after it did not.
    let finished = vec![yadorilink_peer_session::ports::FinishedProjectedUpsert {
        rel_path: "doc.txt".to_string(),
        kind: RecordKind::File,
        version_hash,
        mutation_generation: n,
        observed_identity: None,
        expected_state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
    }];

    coordinator.finalize_projected_mutations_batch("group-1", &finished, &[], &permit).unwrap();

    let published = coordinator
        .sqlite()
        .dag_lookup_materialized_generation("group-1", "doc.txt")
        .unwrap()
        .expect(
            "a write whose observation failed still happened: it must leave a proof usable \
             under its own epoch, not go unrecorded",
        );
    assert_eq!(
        published.version,
        Some(version_hash),
        "the version is not contingent on the observation succeeding -- the write \
         materialized it either way"
    );
    assert!(
        published.filesystem_identity.is_none(),
        "the proof must not claim an identity this write never managed to observe"
    );

    // The proof landed, so the intent is settled and must not be left
    // open for a retry that has nothing left to do.
    assert!(
        !coordinator
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "a published proof must clear its materialization intent"
    );

    let fence_after =
        coordinator.dag_bump_mutation_fence("group-1", "doc.txt", "test_probe").unwrap();
    assert_eq!(fence_after, n + 1, "finalize must not move the fence");
}

/// When the publish CAS loses, the batch must leave the path looking
/// like a write is still in flight -- because one is.
///
/// The fence-conditional publish is the whole guard: a proof may only
/// describe disk as of the epoch the write actually produced. If
/// another mutator advances the fence in between, this batch no longer
/// knows what is on disk and must publish nothing. What it must NOT do
/// is clear the materialization intent anyway: that leaves a row
/// claiming materialization with no exact proof and no record that a
/// write was ever in flight -- the unprovable-claim state, manufactured
/// on the recovery side. Losing the CAS is not an error, so finalize
/// still returns `Ok`; the recovery information is what has to survive.
#[test]
fn an_eager_batch_write_that_loses_its_publish_cas_keeps_its_materialization_intent() {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let record = FileRecord {
        path: "doc.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    coordinator.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();

    let version_hash = current_version_of(&coordinator, "doc.txt");
    coordinator
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &version_hash.0, &permit)
        .unwrap();
    open_the_batch_row(&coordinator, "doc.txt", &permit);

    let n = coordinator
        .dag_bump_mutation_fence("group-1", "doc.txt", "ordinary_batch_upsert_write")
        .unwrap();

    // Someone else mutates this path between the batch's write and its
    // commit, so the epoch the batch is holding is no longer current.
    let competing =
        coordinator.dag_bump_mutation_fence("group-1", "doc.txt", "competing_mutator").unwrap();
    assert_eq!(competing, n + 1, "the competing mutator must own the live epoch");

    let observed_dir = tempfile::tempdir().unwrap();
    let observed_file = observed_dir.path().join("doc.txt");
    std::fs::write(&observed_file, b"").unwrap();
    let identity =
        yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&observed_file).unwrap();

    let finished = vec![yadorilink_peer_session::ports::FinishedProjectedUpsert {
        rel_path: "doc.txt".to_string(),
        kind: RecordKind::File,
        version_hash,
        mutation_generation: n,
        observed_identity: Some(identity),
        expected_state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
    }];

    coordinator.finalize_projected_mutations_batch("group-1", &finished, &[], &permit).unwrap();

    // Nothing was published at all -- not a stale row, not a row under
    // the competing epoch. The diagnostic read ignores staleness, so it
    // would see a row written under `n` if one had been.
    let raw = coordinator
        .database
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation_diagnostic(
                conn, "group-1", "doc.txt",
            )
        })
        .unwrap();
    assert!(
        raw.is_none(),
        "a lost CAS must publish no proof: this batch no longer knows what is on disk"
    );

    // And the intent stays open, so the obligation is retried rather
    // than closed unproven.
    assert!(
        coordinator
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "clearing the intent after a lost CAS would erase the only record that a write was \
         in flight, leaving a claim nothing can prove and nothing will retry"
    );
}

/// A batch spans many paths and takes real time. The finalizer used to
/// commit whatever the write produced against whatever the row had
/// become, guarded only by the mutation fence -- which a native-side
/// supersession does not touch. So a path superseded while its batch
/// was still writing had the older version's bytes on disk stamped
/// `Present` and proven current.
///
/// The guard is the row itself, recomputed inside the commit's own
/// transaction: the version the finalizer is publishing for must still
/// be the version the row names.
#[test]
fn an_eager_batch_write_superseded_during_the_batch_publishes_nothing() {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let record = FileRecord {
        path: "doc.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    coordinator.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();
    let version_hash = current_version_of(&coordinator, "doc.txt");
    coordinator
        .materialization_intent_repository()
        .begin_materialization_intent("group-1", "doc.txt", &version_hash.0, &permit)
        .unwrap();
    open_the_batch_row(&coordinator, "doc.txt", &permit);

    let n = coordinator
        .dag_bump_mutation_fence("group-1", "doc.txt", "ordinary_batch_upsert_write")
        .unwrap();

    // A newer version lands for the same path while this batch is
    // still publishing its other paths' temp files. The fence is
    // untouched -- this is a native-side supersession, not a physical
    // mutation -- so the fence CAS alone would still succeed.
    let superseding = FileRecord {
        path: "doc.txt".into(),
        size: 4,
        mtime_unix_nanos: 99,
        blocks: vec![],
        deleted: false,
    };
    coordinator.file_index_repository().upsert_file("group-1", &superseding, &permit).unwrap();
    assert_ne!(
        current_version_of(&coordinator, "doc.txt"),
        version_hash,
        "the supersession must really have changed the version the row names"
    );

    let finished = vec![yadorilink_peer_session::ports::FinishedProjectedUpsert {
        rel_path: "doc.txt".to_string(),
        kind: RecordKind::File,
        version_hash,
        mutation_generation: n,
        observed_identity: None,
        expected_state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
    }];

    coordinator.finalize_projected_mutations_batch("group-1", &finished, &[], &permit).unwrap();

    let raw = coordinator
        .database
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation_diagnostic(
                conn, "group-1", "doc.txt",
            )
        })
        .unwrap();
    assert!(
        raw.is_none(),
        "these bytes are for a version the path has moved off; publishing a proof for them \
         would claim the newer version is exactly materialized"
    );
    // The finalizer left the row exactly as the open-batch
    // transaction did -- it neither stamped a claim for these bytes
    // nor demoted a row that has moved on to a newer version.
    let left_as = coordinator
        .materialization_state_repository()
        .get_materialization_state("group-1", "doc.txt")
        .unwrap();
    assert_eq!(
        left_as,
        Some(yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE),
        "a superseded write must change no state at all"
    );
    assert_ne!(
        left_as,
        Some(yadorilink_replica_domain::session_state::MaterializationState::Present),
        "and what the batch left there in the first place is not the exact claim: these \
         bytes were never proven, and now never will be"
    );
    assert!(
        coordinator
            .materialization_intent_repository()
            .has_materialization_intent("group-1", "doc.txt")
            .unwrap(),
        "the intent stays open so the newer version is re-driven"
    );
}

/// The proof this path publishes must be the one zero-work settlement
/// actually compares against.
///
/// `resolved_path_state_hash` encodes version presence, and settlement
/// compares those hashes before it ever inspects the version. So a
/// versionless proof is not a weaker proof -- it matches no desired
/// resolution whatsoever, and the path is re-materialized forever while
/// a perfectly good generation row sits next to it. Pins that this path
/// publishes the hash a `File` at version `V` resolves to, and that the
/// versionless encoding is genuinely a different value rather than one
/// settlement might tolerate.
#[test]
fn an_eager_batch_write_publishes_the_hash_the_desired_resolution_will_be_compared_against() {
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    coordinator.link_repository().add_link("/home/alice/Photos", "group-1").unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let record = FileRecord {
        path: "doc.txt".into(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    coordinator.file_index_repository().upsert_file("group-1", &record, &permit).unwrap();

    let n = coordinator
        .dag_bump_mutation_fence("group-1", "doc.txt", "ordinary_batch_upsert_write")
        .unwrap();

    let version_hash = current_version_of(&coordinator, "doc.txt");
    open_the_batch_row(&coordinator, "doc.txt", &permit);
    let finished = vec![yadorilink_peer_session::ports::FinishedProjectedUpsert {
        rel_path: "doc.txt".to_string(),
        kind: RecordKind::File,
        version_hash,
        mutation_generation: n,
        observed_identity: None,
        expected_state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
    }];

    coordinator.finalize_projected_mutations_batch("group-1", &finished, &[], &permit).unwrap();

    let published = coordinator
        .sqlite()
        .dag_lookup_materialized_generation("group-1", "doc.txt")
        .unwrap()
        .expect("the write must leave a usable proof");
    assert_eq!(
        published.object_kind,
        MaterializedObjectKind::RegularFile,
        "a file write must be recorded as a regular file"
    );

    let desired_encoding =
        yadorilink_sync_sqlite::materialized_generation::compute_resolved_path_state_hash(
            "group-1",
            "doc.txt",
            MaterializedObjectKind::RegularFile,
            Some(&version_hash),
        );
    assert_eq!(
        published.resolved_path_state_hash, desired_encoding,
        "the published proof must hash to what a `File` at this version resolves to, or \
         settlement compares two hashes that can never agree"
    );

    let versionless_encoding =
        yadorilink_sync_sqlite::materialized_generation::compute_resolved_path_state_hash(
            "group-1",
            "doc.txt",
            MaterializedObjectKind::RegularFile,
            None,
        );
    assert_ne!(
        published.resolved_path_state_hash, versionless_encoding,
        "version presence is part of the encoding: this is why a versionless proof matches \
         nothing and re-materializes the path indefinitely, rather than merely being vague"
    );
}

/// The granularity cache must be keyed by volume identity, not by
/// path: a real path can outlive the volume mounted at it (a removable
/// drive reformatted at the same mountpoint, a network/container mount
/// replaced entirely), and this codebase already treats that as a real
/// threat, not a hypothetical one (`PeerSyncSession` re-verifies root
/// identity immediately before every write for exactly this reason).
/// Uses two distinct synthetic `VolumeIdentity` values rather than an
/// actual remount (impractical in a unit test) to prove the caching
/// decision itself: the SAME identity must reuse an already-cached
/// probe (never re-probing), and a DIFFERENT identity must always
/// re-probe, regardless of how many times the first one was already
/// cached. Confirmed genuinely RED by temporarily keying the cache on
/// a constant instead of the given identity: the second, different-
/// identity call then wrongly reused the first identity's cached
/// value instead of re-probing.
#[test]
fn granularity_cache_reprobes_on_a_different_volume_identity_but_not_the_same_one() {
    use yadorilink_fs_platform::fs_identity::{TimestampGranularity, VolumeIdentity};

    let volume_a = VolumeIdentity::Unix { device_id: 0xAAAA };
    let volume_b = VolumeIdentity::Unix { device_id: 0xBBBB };

    let probes_for_a = std::sync::atomic::AtomicU32::new(0);
    let first = cached_granularity_for_volume(volume_a, || {
        probes_for_a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        TimestampGranularity::Fine
    });
    let second = cached_granularity_for_volume(volume_a, || {
        probes_for_a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        TimestampGranularity::Coarse
    });
    assert_eq!(first, TimestampGranularity::Fine);
    assert_eq!(
        second,
        TimestampGranularity::Fine,
        "the same volume identity must reuse the cached probe"
    );
    assert_eq!(
        probes_for_a.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "must probe only once for the same identity"
    );

    let probes_for_b = std::sync::atomic::AtomicU32::new(0);
    let third = cached_granularity_for_volume(volume_b, || {
        probes_for_b.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        TimestampGranularity::Coarse
    });
    assert_eq!(
        third,
        TimestampGranularity::Coarse,
        "a different volume identity must be probed fresh, never inherit another volume's \
         cached answer -- exactly the case of a remount at the same path"
    );
    assert_eq!(probes_for_b.load(std::sync::atomic::Ordering::SeqCst), 1);
}
