//! The line between the background health check and the handoff proof.
//!
//! The background check exists because the proof was too expensive to run
//! every ninety seconds. Making it cheap is easy; making it cheap without
//! quietly becoming the thing a destructive action consults is the whole
//! problem. These tests are the fence.
//!
//! The most important one is
//! `a_corrupt_peer_is_refused_at_action_time_despite_fresh_background_evidence`.
//! If only one test in this file survives, it is that one: it is the exact
//! shape of the regression this design could introduce, and the exact shape
//! of the failure it would cause.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use yadorilink_daemon::background_custody::{BackgroundCustodyOutcome, NotCorroboratedReason};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "bg-custody-group";

struct Daemon {
    state: Arc<DaemonState>,
    // Named, not `_`-prefixed: the corruption test reaches into it.
    store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
}

fn new_daemon(device_id: &str) -> Daemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, store_dir, _index_dir: index_dir, _root: root }
}

fn record_referencing(path: &str, hash_bytes: Vec<u8>, size: u64) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: hash_bytes, offset: 0, size: size as u32 }],
        deleted: false,
    }
}

/// Writes `data`'s block into `daemon`'s store and records that it was
/// obtained through `GROUP`, mirroring what a real local edit does. Without
/// the provenance record the handoff responder answers `false` for a block
/// poked straight into the store, since physical presence alone does not
/// establish that the block came through this group.
fn put_and_record(daemon: &Daemon, data: &[u8]) -> Vec<u8> {
    let hash_hex = daemon.state.block_store.put(data).unwrap();
    let hash_bytes = hex::decode(&hash_hex).unwrap();
    daemon
        .state
        .replica_coordinator
        .record_block_provenance(GROUP, std::slice::from_ref(&hash_bytes))
        .unwrap();
    hash_bytes
}

/// Indexes `record` and marks it materialized.
///
/// `upsert_file` leaves a row `Remote`, which is correct — the row exists as
/// soon as its change is projected, before the content behind it has been
/// fetched. A test that wants a device to look like one holding the content
/// has to say so, which is the same distinction the background summary
/// carries: an object on disk under a proof that names the row's version
/// (`Present` alone says only that some object exists).
fn index_hydrated(daemon: &Daemon, record: &FileRecord, content: &[u8]) {
    let permit = RootCommitPermit::for_tests();
    daemon
        .state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(GROUP, record, &permit)
        .unwrap();
    let on_disk = daemon._root.path().join(&record.path);
    std::fs::write(&on_disk, content).unwrap();
    yadorilink_daemon::test_support::seed_prior_cycle_proof(
        &daemon.state.replica_coordinator,
        GROUP,
        &record.path,
        &on_disk,
        &permit,
    );
}

/// Two daemons sharing one file, both holding its bytes, connected, with `b`
/// treating `a` as an authorized full-replica writer. The starting point for
/// every test below.
async fn two_daemons_holding_one_file() -> (Daemon, Daemon, FileRecord) {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");

    let content = b"the only file in this group";
    let hash = put_and_record(&a, content);
    let record = record_referencing("only.bin", hash.clone(), content.len() as u64);
    index_hydrated(&a, &record, content);
    index_hydrated(&b, &record, content);
    // `b` holds the bytes too, so it is a genuine second replica rather than
    // a device that merely lists the file.
    let b_hash_hex = b.state.block_store.put(content).unwrap();
    b.state
        .replica_coordinator
        .record_block_provenance(GROUP, &[hex::decode(&b_hash_hex).unwrap()])
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    a.state.authority.set_peer_group_full_replica("device-b", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await;
    (a, b, record)
}

/// **The regression this design exists not to cause.**
///
/// Background evidence is fresh and positive. The peer's block is then
/// corrupted on disk. An unlink must still be refused, because the proof it
/// takes reads every block back and re-checksums it, and must not consult
/// the cheap evidence sitting right next to it.
///
/// The cached evidence deliberately stays in place and stays fresh through
/// the corruption: the point is not that the cache notices — it cannot, it
/// never looked at a byte — but that nothing destructive asks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_peer_is_refused_at_action_time_despite_fresh_background_evidence() {
    let (a, b, record) = two_daemons_holding_one_file().await;

    let outcome = b.state.refresh_custody_confirmation(GROUP).await;
    assert_eq!(
        outcome,
        BackgroundCustodyOutcome::Corroborated,
        "the precondition: background evidence is positive before anything is corrupted"
    );
    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "and so is the proof, while the bytes are intact"
    );

    // Corrupt the peer's copy in place. Nothing about either device's index
    // changes, so nothing invalidates the cached evidence.
    let hash_hex = hex::encode(&record.blocks[0].hash);
    support::corrupt_stored_block(a.store_dir.path(), &hash_hex);

    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "the handoff proof reads the block back and re-checksums it, so a corrupt peer is not a \
         handoff target -- this is the assertion that keeps the cheap path from becoming the gate"
    );
}

/// The other half of the same fence: the proof must not be satisfiable by
/// the cache even when the cache is as fresh as it can be and the peer has
/// simply vanished.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_absent_peer_is_refused_at_action_time_despite_fresh_background_evidence() {
    let (_a, b, _record) = two_daemons_holding_one_file().await;

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::Corroborated
    );

    // The peer is still connected, but is no longer an authorized
    // full-replica writer -- the demote/revoke shape.
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, false);

    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "a peer that is no longer an authorized complete copy cannot be the handoff target, \
         whatever the cache last recorded"
    );
}

/// D: a peer whose current state disagrees never produces a positive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_whose_current_state_differs_does_not_corroborate() {
    let (a, b, _record) = two_daemons_holding_one_file().await;

    // Only `a` learns about a second file, so the two current sets diverge.
    let extra = b"a file only device-a knows about";
    let hash = put_and_record(&a, extra);
    index_hydrated(&a, &record_referencing("extra.bin", hash, extra.len() as u64), extra);

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::NotCorroborated(NotCorroboratedReason::CurrentStateDiffers),
        "disagreement about live content is never a positive, and is reported as what it is"
    );
}

/// A peer that has projected the changes but fetched none of the content has
/// an identical current-state digest. Without the materialization half of
/// the summary this is exactly the state a digest comparison would mistake
/// for custody — and it is not a rare state, it is what every second device
/// looks like for as long as its first sync takes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_with_the_changes_but_not_the_content_does_not_corroborate() {
    let (a, b, record) = two_daemons_holding_one_file().await;

    a.state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            GROUP,
            &record.path,
            MaterializationState::Remote,
            &RootCommitPermit::for_tests(),
        )
        .unwrap();

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::NotCorroborated(NotCorroboratedReason::PeerNotMaterialized),
        "identical digests and no content is the false positive a bare index comparison makes"
    );
}

/// F: retained history and current state are different questions, and the
/// two checks answer them differently on purpose.
///
/// The peer retains a superseded version this device has never held. Its
/// whole-root digest therefore differs and always will — a device that joins
/// a folder starts from a history floor, and retention keeps a version
/// inside its count bound forever. Background corroboration must survive
/// that, because requiring whole-root agreement would make the ordinary
/// two-device folder permanently uncorroborated.
///
/// The handoff proof is unaffected either way: it asks the peer to confirm
/// *this* device's roots, and a peer holding more than that still holds all
/// of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_retaining_extra_history_still_corroborates() {
    let (a, b, _record) = two_daemons_holding_one_file().await;

    // An intermediate version only `a` ever sees -- the shape of a device
    // that was present for an edit a later-joining peer never received, and
    // of a peer whose retention sweep has not yet caught up with this one's.
    let interim = b"an edit device-b never saw";
    let interim_hash = put_and_record(&a, interim);
    index_hydrated(
        &a,
        &record_referencing("only.bin", interim_hash, interim.len() as u64),
        interim,
    );

    // Then an edit both devices do see, so their CURRENT state agrees again
    // while `a` retains one superseded version more than `b` does.
    let revised = b"the only file in this group, revised";
    let hash = put_and_record(&a, revised);
    let revised_record = record_referencing("only.bin", hash.clone(), revised.len() as u64);
    index_hydrated(&a, &revised_record, revised);
    let b_hash_hex = b.state.block_store.put(revised).unwrap();
    b.state
        .replica_coordinator
        .record_block_provenance(GROUP, &[hex::decode(&b_hash_hex).unwrap()])
        .unwrap();
    index_hydrated(&b, &revised_record, revised);

    let a_summary = a.state.local_root_set_summary(GROUP).unwrap();
    let b_summary = b.state.local_root_set_summary(GROUP).unwrap();
    assert_eq!(
        a_summary.current_digest, b_summary.current_digest,
        "the two devices agree about the live content"
    );
    assert_ne!(
        a_summary.roots_digest, b_summary.roots_digest,
        "and disagree about retained history -- the condition this test exists for"
    );

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::Corroborated,
        "retained-history divergence between honest replicas must not withhold corroboration; \
         it has no mechanism to resolve itself and would withhold it forever"
    );
}

/// E: evidence recorded under one membership generation is not usable under
/// another. A demote or revoke moves the generation, and the cached record
/// stops counting the moment it does — no waiting out the staleness bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_membership_change_invalidates_evidence_immediately() {
    let (_a, b, _record) = two_daemons_holding_one_file().await;

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::Corroborated
    );
    assert_eq!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Protected
    );

    b.state.authority.set_peer_group_full_replica("device-a", GROUP, false);

    assert_ne!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Protected,
        "the confirming peer's authorization changed, so its confirmation is not current evidence"
    );
}

/// A local content change invalidates a corroboration by itself. Nothing
/// about the peer moved and no generation counter bumped — the digest
/// re-derivation is the only thing that catches this.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_content_change_invalidates_evidence() {
    let (_a, b, _record) = two_daemons_holding_one_file().await;

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::Corroborated
    );
    assert_eq!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Protected
    );

    let new_content = b"a file that arrived after the corroboration";
    let hash = put_and_record(&b, new_content);
    index_hydrated(
        &b,
        &record_referencing("later.bin", hash, new_content.len() as u64),
        new_content,
    );

    assert_ne!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Protected,
        "no peer has corroborated the set this device now holds"
    );
}

/// A `--force` unlink latches the group to `Unknown` until a real proof
/// clears it. A background cycle is not a real proof, however positive, and
/// must leave the latch where it found it.
///
/// Before the two were separated this happened to be safe by accident: the
/// background sweep ran the proof, so its success genuinely was the thing
/// the latch was waiting for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_background_cycle_does_not_clear_a_force_latch() {
    let (_a, b, _record) = two_daemons_holding_one_file().await;

    b.state.latch_group_durability_unknown(GROUP).unwrap();
    assert_eq!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Unknown
    );

    assert_eq!(
        b.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::Corroborated,
        "the cycle itself succeeds -- the latch is not about whether a peer agrees"
    );
    assert_eq!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Unknown,
        "an index comparison is not the proof the latch was set to wait for"
    );

    // The proof is, and clears it.
    assert!(b.state.another_full_replica_is_ready(GROUP).await);
    assert_ne!(
        b.state.group_durability_status(GROUP),
        yadorilink_daemon::durability_service::GroupDurabilityStatus::Unknown,
        "a real whole-group proof retires the latch it was waiting for"
    );
}

/// With no peer at all there is nothing to corroborate, and the cycle says
/// so rather than reaching for the expensive check it replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_candidate_peer_is_reported_not_worked_around() {
    support::ensure_isolated_config_dir();
    let solo = new_daemon("device-solo");
    let content = b"nobody else has this";
    let hash = put_and_record(&solo, content);
    index_hydrated(&solo, &record_referencing("alone.bin", hash, content.len() as u64), content);

    assert_eq!(
        solo.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::NotCorroborated(NotCorroboratedReason::NoCandidatePeer),
    );
}

/// A group with no current files has nothing to protect, and says so without
/// needing a peer — the same answer the whole-pass version gave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_group_is_vacuously_corroborated() {
    support::ensure_isolated_config_dir();
    let solo = new_daemon("device-solo");
    assert_eq!(
        solo.state.refresh_custody_confirmation(GROUP).await,
        BackgroundCustodyOutcome::VacuouslyCorroborated,
    );
}
