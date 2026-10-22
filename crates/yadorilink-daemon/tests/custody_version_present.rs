//! Full-stack check of the corrected on-demand custody gate: an on-demand
//! device confirms a full replica durably holds a version's blocks over the
//! real peer-to-peer `VersionPresentQuery` before it would reclaim its cache —
//! and refuses (fail closed) when the full replica does not hold them.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::{
    connect_two_daemons, ensure_device_signing_key, open_file_backed_replica_coordinator,
};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};

const GROUP: &str = "custody-group";

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
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
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, _root: root }
}

/// Like [`new_daemon`], but this device's block store wraps its real
/// `SegmentBlockStore` in [`support::DelayedGetBlockStore`], so a
/// `VersionPresentQuery` answered by this device fires an "entered get()"
/// signal and then stalls for `delay` inside `holds_version_durably`'s
/// checksum-verifying `get` call — used to open a deterministic in-flight
/// window around that reply. Returns the concrete slow store alongside the
/// daemon so the test can arm that signal.
fn new_daemon_with_slow_get(
    device_id: &str,
    delay: Duration,
) -> (Daemon, Arc<support::DelayedGetBlockStore>) {
    let store_dir = tempfile::tempdir().unwrap();
    let inner = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let slow = Arc::new(support::DelayedGetBlockStore::new(inner, delay));
    let store: Arc<dyn BlockStore + Send + Sync> = slow.clone();
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = DaemonState::new(device_id.to_string(), Arc::new(sync_state), store);
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    (Daemon { state, _store_dir: store_dir, _index_dir: index_dir, _root: root }, slow)
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

/// Writes `data`'s block into `daemon`'s block store and records it as
/// obtained through `GROUP` (mirroring what `LocalChangeProcessor` does for a
/// real local edit — see `record_group_block_provenance`'s doc comment),
/// returning the raw hash bytes. Without this, `holds_version_durably`'s
/// provenance check (step 5: "physical presence... does not prove this
/// device obtained the bytes through the queried group") answers `false`
/// for a block this test poked directly into the store.
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

/// The `change::VersionHash` and ordered block list for a single-block
/// version with `hash_bytes`/`size`, matching the metadata every
/// `record_referencing` row implies (`mtime_unix_nanos: 0`, no exec bit, no
/// symlink target, a regular file) — the shape the daemon/index actually
/// stores for these test fixtures, so hashing it here reproduces exactly what
/// the responder recomputes from its own index row.
fn version_and_blocks(hash_bytes: Vec<u8>, size: u64) -> (VersionHash, Vec<VersionBlock>) {
    let blocks = vec![VersionBlock { hash: BlockHash(hash_bytes), size: size as u32 }];
    let meta = FileMeta {
        mtime_unix_nanos: 0,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    let version = FileVersion::new(blocks.clone(), size, meta);
    (version.version_hash, blocks)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custody_is_confirmed_only_when_a_full_replica_holds_the_blocks() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: durably holds the block
    let b = new_daemon("device-b"); // on-demand: would reclaim

    // A is a full replica that durably holds a block; both devices index it
    // under "held.bin", so A's live record matches the query it will answer.
    let held = b"content the complete copy durably holds";
    let held_bytes = put_and_record(&a, held);
    let held_record = record_referencing("held.bin", held_bytes.clone(), held.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &held_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &held_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    // Both index a block A does NOT hold, under "missing.bin": A is a full
    // replica whose record references it but whose store lacks the block (a
    // behind / incompletely-synced replica), so it must fail closed.
    let missing_record = record_referencing("missing.bin", vec![7u8; 32], 4);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &missing_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &missing_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    // B knows A is a full replica of the group; use the real peer-to-peer
    // confirmer, which issues a VersionPresentQuery over the live session.
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    let (held_vh, held_blocks) = version_and_blocks(held_bytes.clone(), held.len() as u64);
    assert!(
        b.state.full_replica_custody_confirmed(GROUP, "held.bin", &held_vh, &held_blocks),
        "the complete copy holds this block, so custody is confirmed and B may reclaim"
    );
    let (missing_vh, missing_blocks) = version_and_blocks(vec![7u8; 32], 4);
    assert!(
        !b.state.full_replica_custody_confirmed(GROUP, "missing.bin", &missing_vh, &missing_blocks),
        "the complete copy does not hold this block, so custody is not confirmed (fail closed)"
    );
    // A version hash that does not match held.bin's current version must not
    // confirm even though A is a full replica that holds held.bin — the
    // answer is bound to the exact version, not to "some block by this name
    // exists".
    let (wrong_vh, wrong_blocks) = version_and_blocks(vec![9u8; 32], held.len() as u64);
    assert!(
        !b.state.full_replica_custody_confirmed(GROUP, "held.bin", &wrong_vh, &wrong_blocks),
        "a version whose blocks don't match the live record must not confirm"
    );
}

/// Eviction custody must NOT confirm from a peer that holds the queried
/// version only as RETAINED history (superseded/trashed), even though that
/// same peer would legitimately satisfy a whole-group durability handoff for
/// it. The danger the distinction guards against: an on-demand device asks a
/// full replica "do you durably hold my current version's blocks?" before
/// dropping its last cached copy; if the replica answers yes on the strength
/// of a merely retained version, that retained row can later expire under
/// version retention and be reclaimed, leaving the device that already
/// dropped its cache with no holder at all — data loss.
///
/// Setup: device-a has advanced this file to V2 (current), so V1 survives on
/// A only as a superseded (retained) version; device-b's current is still V1.
/// B's eviction query for V1 must fail closed (A's *current* is V2, no match),
/// while the whole-group handoff — which is allowed to match retained
/// versions — still reaches A's retained V1.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eviction_custody_does_not_confirm_from_a_retained_only_peer() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: current V2, V1 retained
    let b = new_daemon("device-b"); // on-demand: current still V1, would reclaim

    // A durably holds both versions' blocks in its store.
    let v1 = b"doc version one";
    let v1_bytes = put_and_record(&a, v1);
    let v2 = b"doc version two, a newer edit device-b has not applied yet";
    let v2_bytes = put_and_record(&a, v2);

    let v1_record = record_referencing("doc.bin", v1_bytes.clone(), v1.len() as u64);
    let v2_record = record_referencing("doc.bin", v2_bytes, v2.len() as u64);

    // A: upsert V1 then V2 -> A's current is V2, V1 becomes a retained
    // (superseded) version.
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &v1_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &v2_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // B: current is still V1 (it never received the V2 edit).
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &v1_record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    // Eviction custody (for_handoff = false): A's CURRENT version is V2, so a
    // query for V1's blocks must NOT be confirmed even though A still retains
    // V1 as superseded history. If it did confirm, B could drop its only copy
    // of V1 and lose it once A's retention expires.
    let (v1_vh, v1_blocks) = version_and_blocks(v1_bytes.clone(), v1.len() as u64);
    assert!(
        !b.state.full_replica_custody_confirmed(GROUP, "doc.bin", &v1_vh, &v1_blocks),
        "eviction must not confirm from a peer that holds the queried version only as \
         retained history"
    );

    // The whole-group durability handoff (for_handoff = true), by contrast,
    // DOES reach A's retained V1: B's own current root for doc.bin is V1, and A
    // durably retains it, so the handoff is ready. This is the exact
    // capability eviction must not borrow.
    assert!(
        b.state.another_full_replica_is_ready(GROUP).await,
        "the whole-group handoff may match A's retained V1, so it is ready — the capability \
         eviction deliberately does not use"
    );
}

/// The netmap-authorization generation must advance on every real change to a
/// peer's full-replica/writer status and stay put on a no-op — it is what a
/// version-present confirmation captures before its peer round-trip and requires
/// unchanged after the reply, so a revoke/demote arriving mid-round-trip fails
/// the confirmation closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn membership_generation_bumps_only_on_real_authorization_changes() {
    support::ensure_isolated_config_dir();
    let d = new_daemon("device-x");

    let g0 = d.state.authority.membership_generation();
    d.state.authority.set_peer_group_full_replica("peer-1", GROUP, true);
    let g1 = d.state.authority.membership_generation();
    assert!(g1 > g0, "adding a complete-copy edge must bump the generation");

    d.state.authority.set_peer_group_full_replica("peer-1", GROUP, true);
    assert_eq!(d.state.authority.membership_generation(), g1, "a no-op set must not bump");

    d.state.set_peer_group_writer("peer-1", GROUP, true);
    let g2 = d.state.authority.membership_generation();
    assert!(g2 > g1, "adding a writer edge must bump the generation");

    d.state.authority.set_peer_group_full_replica("peer-1", GROUP, false);
    let g3 = d.state.authority.membership_generation();
    assert!(g3 > g2, "revoking a complete-copy edge must bump the generation");
    d.state.authority.set_peer_group_full_replica("peer-1", GROUP, false);
    assert_eq!(
        d.state.authority.membership_generation(),
        g3,
        "removing an already-absent edge must not bump"
    );
}

/// A revoke/demote of the queried peer's full-replica authorization that
/// lands while its `VersionPresentQuery` reply is still in flight must not be
/// honored, even though the peer's own answer (evaluated against its own live
/// record) would have been an affirmative "present". `confirm_version_
/// present_via_peer` captures the netmap-authorization generation ("epoch")
/// before fanning out and, after each reply, requires it unchanged and the
/// peer still recorded as an authorized full-replica writer — a revoke
/// necessarily changes both (see `membership_generation_bumps_only_on_real_
/// authorization_changes` above).
///
/// Guards against a FALSE PASS (the `false` coming from a broken
/// session/capability/query path rather than the epoch change) with a
/// POSITIVE BASELINE: over the very same session, with no mid-flight revoke,
/// the identical call returns TRUE. Only after that proves the path works do
/// we run the revoke case and attribute its `false` to the authorization
/// churn.
///
/// Deterministic, not delay-vs-delay: device-a's block store fires an
/// "entered get()" signal the instant it begins the checksum-verifying `get`
/// that `holds_version_durably` runs before replying. Awaiting that signal
/// proves the query already reached device-a — so B has already captured its
/// pre-round-trip epoch — yet the reply has not been produced; revoking right
/// then guarantees the change lands strictly inside the round-trip. The 500ms
/// `get` delay is only a backstop keeping the window wide.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_reclaim_after_membership_epoch_change() {
    support::ensure_isolated_config_dir();
    let (a, a_slow_store) = new_daemon_with_slow_get("device-a", Duration::from_millis(500));
    let b = new_daemon("device-b");

    let content = b"content behind a complete copy whose authorization churns mid-query";
    let hash_bytes = put_and_record(&a, content);
    let record = record_referencing("epoch.bin", hash_bytes.clone(), content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    let (epoch_vh, epoch_blocks) = version_and_blocks(hash_bytes.clone(), content.len() as u64);

    // Positive baseline: same session, same call, no revoke — must confirm.
    // This proves the session established, the capability negotiated, and the
    // query round-tripped, so the revoke case's `false` cannot be blamed on a
    // broken path.
    assert!(
        b.state.confirm_version_present_via_peer(GROUP, "epoch.bin", epoch_vh, &epoch_blocks).await,
        "baseline: with authorization stable, the same session/capability/query path confirms"
    );

    // Revoke case: arm the entered-get signal AFTER the baseline (whose own
    // get calls would have consumed it), then revoke exactly when device-a
    // begins answering.
    let mut entered_get = a_slow_store.arm_entered_get_signal();
    let epoch_before = b.state.authority.membership_generation();
    let confirm =
        b.state.confirm_version_present_via_peer(GROUP, "epoch.bin", epoch_vh, &epoch_blocks);
    let revoke_mid_flight = async {
        entered_get.recv().await.expect("device-a must enter get() to answer the query");
        b.state.authority.set_peer_group_full_replica("device-a", GROUP, false);
    };
    let (confirmed, ()) = tokio::join!(confirm, revoke_mid_flight);

    assert!(
        b.state.authority.membership_generation() > epoch_before,
        "the revoke must actually have bumped the generation for this test to mean anything"
    );
    assert!(
        !confirmed,
        "device-a's authorization churned mid-round-trip, so the confirmation must fail closed \
         even though device-a's own reply (against its own live record) would have been present"
    );
}

/// Complements `missing.bin` (a block device-a's store never had) with the
/// present-but-wrong case: device-a's stored bytes for this block have been
/// corrupted on disk (bit rot, a torn write) so they no longer hash to the
/// block's content-addressed name. `holds_version_durably` verifies every
/// block via `store.get`, which re-hashes and rejects a mismatch
/// (`StorageError::ChecksumMismatch`), rather than a bare existence check
/// that a corrupted-but-present file would pass — so this must fail closed
/// identically to a genuinely absent block.
///
/// Guards against a FALSE PASS two ways. A POSITIVE BASELINE first confirms
/// custody over the same session while the block is intact, proving the
/// path works. Then, after corruption, it asserts the block file still
/// EXISTS on disk (present, but with wrong bytes) *before* querying — so the
/// subsequent `false` is provably the checksum-verification path, not a
/// missing-block path. (The existence check must precede the query: `get`'s
/// self-heal deletes a checksum-failing file, so after the query the block
/// would be gone for a different reason.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_reclaim_from_corrupt_replica_block() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");

    let content = b"content that will be corrupted on disk after being stored";
    let hash_bytes = put_and_record(&a, content);
    let record = record_referencing("corrupt.bin", hash_bytes.clone(), content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    let (corrupt_vh, corrupt_blocks) = version_and_blocks(hash_bytes.clone(), content.len() as u64);

    // Positive baseline: intact block over this same session confirms.
    assert!(
        b.state.full_replica_custody_confirmed(GROUP, "corrupt.bin", &corrupt_vh, &corrupt_blocks),
        "baseline: while the block's bytes are intact, custody confirms over this session"
    );

    // Corrupt device-a's on-disk bytes for the block in place.
    let hash_hex = hex::encode(&hash_bytes);
    support::corrupt_stored_block(a._store_dir.path(), &hash_hex);
    // Precondition: the block file is still PRESENT (just wrong bytes), so the
    // upcoming `false` is the checksum path, not a missing block. Checked
    // before the query because `get`'s self-heal removes a mismatching file.
    assert!(
        a.state.block_store.exists(&hash_hex).unwrap(),
        "the corrupted block file must still exist on disk (present-but-wrong-bytes)"
    );

    assert!(
        !b.state.full_replica_custody_confirmed(GROUP, "corrupt.bin", &corrupt_vh, &corrupt_blocks),
        "device-a's on-disk bytes for this block fail their checksum, so custody is not \
         confirmed (fail closed)"
    );
}

/// Models a full replica that restarted with its block store wiped (a disk
/// swap, an emptied cache directory) while its sync-state index still names
/// the block from before the wipe. `holds_version_durably` re-verifies via a
/// live `get` on every single query rather than trusting any carried-over
/// "I already confirmed this" state, so there is no persisted confirmation
/// for a restart to invalidate in the first place — the wipe alone is enough
/// to fail the very next query, which is what this asserts directly rather
/// than actually restarting a daemon process.
///
/// Guards against a FALSE PASS with a POSITIVE BASELINE (custody confirms
/// over the same session before the wipe) and, after the wipe, two explicit
/// preconditions: the block is gone from the store (`exists == false`) AND
/// device-a's index record still names it (`get_file(...).blocks` intact).
/// Together these pin the `false` to a wiped store backing an intact index —
/// not a missing index record and not a broken session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_confirm_after_block_store_wipe() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a");
    let b = new_daemon("device-b");

    let content = b"content device-a held before its block store was wiped";
    let hash_bytes = put_and_record(&a, content);
    let hash_hex = hex::encode(&hash_bytes);
    let record = record_referencing("wiped.bin", hash_bytes.clone(), content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    assert!(a.state.block_store.exists(&hash_hex).unwrap(), "block genuinely held before the wipe");

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    let (wiped_vh, wiped_blocks) = version_and_blocks(hash_bytes.clone(), content.len() as u64);

    // Positive baseline: while device-a still holds the block, custody
    // confirms over this same session — the path works.
    assert!(
        b.state.full_replica_custody_confirmed(GROUP, "wiped.bin", &wiped_vh, &wiped_blocks),
        "baseline: while device-a holds the block, custody confirms over this session"
    );

    // The wipe: the block is gone, but device-a's index record still
    // references it, exactly the shape a restart onto an empty/replaced
    // block-store volume leaves behind.
    a.state.block_store.delete(&hash_hex).unwrap();

    // Preconditions attributing the upcoming `false` to a wiped store, not a
    // missing index record: the block is gone from the store, yet the index
    // record still names it.
    assert!(
        !a.state.block_store.exists(&hash_hex).unwrap(),
        "the block must actually be gone from device-a's store after the wipe"
    );
    let record_after = a
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, "wiped.bin")
        .unwrap()
        .unwrap();
    assert!(
        record_after.blocks.iter().any(|blk| blk.hash == hash_bytes),
        "device-a's index record must still name the (now-absent) block"
    );

    assert!(
        !b.state.full_replica_custody_confirmed(GROUP, "wiped.bin", &wiped_vh, &wiped_blocks),
        "device-a's block store no longer has this block, so custody is not confirmed even \
         though its index still names it (fail closed)"
    );
}

/// The identity check binds the FULL `change::VersionHash` — blocks, size,
/// AND metadata (mtime, exec bit, symlink target, record kind) — not merely
/// the block hash list. A query whose `block_hashes`/`block_sizes` exactly
/// match the responder's real content, but whose `version_hash` was computed
/// assuming a different `mtime` than the responder's actual record, must be
/// rejected. If the responder matched on block hashes alone, restating the
/// real blocks under a fabricated or stale metadata claim would wrongly
/// confirm a version that isn't actually the responder's own row — exactly
/// the gap binding the full canonical `FileVersion` closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custody_rejects_a_query_whose_version_hash_differs_despite_matching_blocks() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: durably holds the real content
    let b = new_daemon("device-b");

    let content = b"content shared by two version_hash claims that differ only in metadata";
    let hash_bytes = put_and_record(&a, content);
    // `record_referencing` always uses `mtime_unix_nanos: 0`, so device-a's
    // real stored record's version_hash is over that mtime.
    let record = record_referencing("meta.bin", hash_bytes.clone(), content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    // Sanity/positive baseline: the real version_hash, matching device-a's
    // actual record, DOES confirm — proves the connection and setup are sound
    // before the negative case below.
    let (real_vh, blocks) = version_and_blocks(hash_bytes.clone(), content.len() as u64);
    assert!(
        b.state.confirm_version_present_via_peer(GROUP, "meta.bin", real_vh, &blocks).await,
        "sanity: the real version_hash, matching device-a's actual record, must confirm"
    );

    // Identical block hashes and sizes, but a version_hash computed assuming
    // a DIFFERENT mtime than device-a's real record actually has.
    let wrong_meta = FileMeta {
        mtime_unix_nanos: 999,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    let wrong_vh = FileVersion::new(blocks.clone(), content.len() as u64, wrong_meta).version_hash;
    assert_ne!(
        wrong_vh, real_vh,
        "the two FileVersions must actually hash differently for this test to mean anything"
    );

    assert!(
        !b.state.confirm_version_present_via_peer(GROUP, "meta.bin", wrong_vh, &blocks).await,
        "identical block hashes/sizes must NOT confirm when the version_hash (bound to \
         mtime/unix_mode/symlink_target/record_kind too) doesn't match device-a's real record"
    );
}

/// Proves the responder folds a per-row metadata COLUMN — the exec bit — into
/// the identity it recomputes, which is only possible if it reads that column
/// from the same atomic current-row snapshot as the blocks (not a stitched
/// multi-read). device-a's real current row has the exec bit SET; a query
/// whose `version_hash` assumes unix_mode=false (same blocks, same size, same
/// mtime) must be rejected, while the unix_mode=true hash confirms. If the
/// responder ignored the exec bit — or read it from a torn/hybrid snapshot —
/// the unix_mode=false query would wrongly confirm.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn custody_binds_the_unix_mode_from_the_atomic_current_row() {
    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // complete copy: current row has exec bit set
    let b = new_daemon("device-b");

    let content = b"an executable script's content";
    let hash_bytes = put_and_record(&a, content);
    let record = record_referencing("script.sh", hash_bytes.clone(), content.len() as u64);
    a.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    b.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &record,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    // Set the exec bit on device-a's CURRENT row, so its real version identity
    // is over unix_mode=true.
    a.state
        .replica_coordinator
        .file_index_repository()
        .set_unix_mode(
            GROUP,
            "script.sh",
            Some(0o755),
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await; // let the session establish

    let blocks =
        vec![VersionBlock { hash: BlockHash(hash_bytes.clone()), size: content.len() as u32 }];
    let meta_with_exec = FileMeta {
        mtime_unix_nanos: 0,
        unix_mode: Some(0o755),
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    let meta_no_exec = FileMeta { unix_mode: Some(0o644), ..meta_with_exec.clone() };
    let vh_exec =
        FileVersion::new(blocks.clone(), content.len() as u64, meta_with_exec).version_hash;
    let vh_no_exec =
        FileVersion::new(blocks.clone(), content.len() as u64, meta_no_exec).version_hash;
    assert_ne!(vh_exec, vh_no_exec, "the exec bit must change the version_hash");

    // The unix_mode=true hash matches device-a's real current row → confirms,
    // proving the responder read the exec bit from the atomic row.
    assert!(
        b.state.confirm_version_present_via_peer(GROUP, "script.sh", vh_exec, &blocks).await,
        "the version_hash bound to unix_mode=true matches device-a's real current row"
    );
    // The unix_mode=false hash (identical blocks/size/mtime) must fail closed.
    assert!(
        !b.state.confirm_version_present_via_peer(GROUP, "script.sh", vh_no_exec, &blocks).await,
        "a version_hash assuming unix_mode=false must NOT confirm against a current row whose \
         exec bit is set"
    );
}

/// The responder's strong proof (every block read and re-hashed) is synchronous
/// disk work. While a `VersionPresent` query waits on it, the async runtime must
/// keep running: with a single worker, a timer task keeps ticking.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_version_present_proof_does_not_stall_the_async_runtime() {
    support::ensure_isolated_config_dir();
    let (a, slow) = new_daemon_with_slow_get("device-a", Duration::from_millis(1000));
    let b = new_daemon("device-b");
    let content = b"content whose proof takes a while";
    let hash_bytes = put_and_record(&a, content);
    let record = record_referencing("slow.bin", hash_bytes.clone(), content.len() as u64);
    for d in [&a, &b] {
        d.state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }
    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (vh, blocks) = version_and_blocks(hash_bytes, content.len() as u64);

    let mut entered_get = slow.arm_entered_get_signal();
    let asker = b.state.clone();
    let query = tokio::spawn(async move {
        asker.confirm_version_present_via_peer(GROUP, "slow.bin", vh, &blocks).await
    });
    entered_get.recv().await.expect("the proof must start");
    let ticks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ticker = {
        let ticks = ticks.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(700)).await;
    let during = ticks.load(std::sync::atomic::Ordering::SeqCst);
    ticker.abort();
    assert!(query.await.unwrap());
    assert!(during >= 10, "the runtime ran {during} timer ticks in 700ms during the proof");
}

/// A full replica whose version is not known to match is not counted as a full replica for
/// reclaim custody, handoff or durability: reclaim waits (refused), never proceeds, and nothing is
/// deleted. It counts again once the versions match, so the refusal is a pause and not a verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_version_incompatible_full_replica_is_excluded_from_every_custody_set() {
    use yadorilink_daemon::peer_connectivity_runtime::reachability_source_for_tests as reach;
    use yadorilink_replica_engine::custody::verify_reclaim_custody;

    support::ensure_isolated_config_dir();
    let a = new_daemon("device-a"); // the only other copy: a full replica holding the block
    let b = new_daemon("device-b"); // on-demand: would reclaim

    let held = b"content the only other copy durably holds";
    let held_bytes = put_and_record(&a, held);
    let record = record_referencing("held.bin", held_bytes.clone(), held.len() as u64);
    for daemon in [&a, &b] {
        daemon
            .state
            .replica_coordinator
            .file_index_repository()
            .upsert_file(
                GROUP,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
    }

    connect_two_daemons(&a.state, "device-a", &b.state, "device-b", &[GROUP.to_string()]).await;
    b.state.authority.set_peer_group_full_replica("device-a", GROUP, true);
    b.state.install_p2p_custody_confirmer();
    tokio::time::sleep(Duration::from_millis(500)).await;
    reach::connected_directly(&b.state, "device-a");

    let (vh, blocks) = version_and_blocks(held_bytes, held.len() as u64);
    let reclaim_allowed =
        || verify_reclaim_custody(&*b.state, GROUP, "held.bin", &vh, &blocks).is_some();

    // Precondition: while the versions match, every set counts A.
    assert!(reclaim_allowed(), "setup: a matching full replica confirms reclaim custody");
    assert_eq!(b.state.custody_candidate_peer_count_for_tests(GROUP), 1);
    assert!(b.state.another_full_replica_is_ready(GROUP).await, "setup: handoff is ready");
    assert!(
        b.state.acquire_custody_lease_via_peer(GROUP, "held.bin", vh, &blocks).await.is_some(),
        "setup: a matching full replica grants a custody lease"
    );

    reach::version_incompatible(&b.state, "device-a");

    assert!(!reclaim_allowed(), "an incompatible full replica must not confirm reclaim custody");
    assert_eq!(
        b.state.custody_candidate_peer_count_for_tests(GROUP),
        0,
        "the durability summary must not ask an incompatible peer"
    );
    assert!(
        !b.state.another_full_replica_is_ready(GROUP).await,
        "an incompatible full replica must not count as a handoff target"
    );
    assert!(
        b.state.acquire_custody_lease_via_peer(GROUP, "held.bin", vh, &blocks).await.is_none(),
        "no custody lease is taken from an incompatible full replica"
    );

    // Pause, not verdict: once the connection to the old version is gone and a matching one is up,
    // the peer counts again.
    reach::ended(&b.state, "device-a");
    reach::connected_directly(&b.state, "device-a");
    assert!(reclaim_allowed(), "after the versions match again, custody confirms again");
}
