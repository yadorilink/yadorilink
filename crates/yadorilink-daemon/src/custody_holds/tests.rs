#![cfg(test)]

use std::sync::atomic::{AtomicUsize, Ordering};

use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{
    BlockInfo, FileMeta, FileRecord, FileVersion, RecordKind, VersionBlock,
};
use yadorilink_replica_domain::ids::BlockHash;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "g";
const PATH: &str = "a.bin";
const TOKEN: AttemptToken = [7; 16];

fn state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("requester".into(), coordinator, store)
}

fn record(block: u8, deleted: bool) -> FileRecord {
    FileRecord {
        path: PATH.into(),
        size: 4,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: vec![block; 32], offset: 0, size: 4 }],
        deleted,
    }
}

/// The version hash `record(block, _)` indexes as.
fn version_of(block: u8) -> [u8; 32] {
    let meta = FileMeta {
        mtime_unix_nanos: 0,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    FileVersion::new(vec![VersionBlock { hash: BlockHash(vec![block; 32]), size: 4 }], 4, meta)
        .version_hash
        .0
}

fn index(state: &DaemonState, record: &FileRecord, at: MaterializationState) {
    let coordinator = &state.replica_coordinator;
    coordinator
        .file_index_repository()
        .upsert_file(GROUP, record, &RootCommitPermit::for_tests())
        .unwrap();
    if !record.deleted {
        coordinator
            .materialization_state_repository()
            .set_materialization_state(GROUP, PATH, at, &RootCommitPermit::for_tests())
            .unwrap();
    }
}

fn key(version: [u8; 32]) -> HoldKey {
    HoldKey {
        group_id: GROUP.into(),
        path: PATH.into(),
        version_hash: version,
        peer_id: "p".into(),
    }
}

fn hold(state: &DaemonState, key: &HoldKey, hold_state: HoldState) {
    let holds = state.replica_coordinator.remote_custody_hold_repository();
    holds.record_requested(key, 1, TOKEN).unwrap();
    if hold_state == HoldState::Granted {
        holds.mark_granted(key).unwrap();
    }
}

fn rows(state: &DaemonState) -> usize {
    state.replica_coordinator.remote_custody_hold_repository().list().unwrap().len()
}

/// Runs a pass whose release answers `answer`, returning (calls, unfinished).
async fn pass(state: &DaemonState, answer: bool) -> (usize, bool) {
    let calls = AtomicUsize::new(0);
    let unfinished = state
        .reconcile_custody_holds(|_key| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { answer }
        })
        .await;
    (calls.load(Ordering::SeqCst), unfinished)
}

/// The row is deleted only when the responder answered that the lease is gone.
#[tokio::test]
async fn a_release_answered_false_keeps_the_row_and_true_deletes_it() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Present);
    hold(&state, &key(version_of(1)), HoldState::Granted);

    assert_eq!(pass(&state, false).await, (1, true));
    assert_eq!(rows(&state), 1, "released:false keeps the row");

    assert_eq!(pass(&state, true).await, (1, false));
    assert_eq!(rows(&state), 0);
}

/// A `requested` row is released whatever the file looks like: no stamp was
/// ever issued for it, so nothing can depend on it.
#[tokio::test]
async fn a_requested_row_is_always_released() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    hold(&state, &key(version_of(1)), HoldState::Requested);

    assert_eq!(pass(&state, true).await, (1, false));
    assert_eq!(rows(&state), 0);
}

/// A granted row for a path that is a placeholder (or in flight towards or
/// away from one) at the held version is never released.
#[tokio::test]
async fn a_granted_row_the_path_still_depends_on_is_not_released() {
    for at in [
        MaterializationState::Remote,
        MaterializationState::Evicting,
        MaterializationState::Hydrating,
    ] {
        let state = state();
        index(&state, &record(1, false), at);
        hold(&state, &key(version_of(1)), HoldState::Granted);
        assert_eq!(pass(&state, true).await, (0, false), "{at:?}");
        assert_eq!(rows(&state), 1, "{at:?}");
    }
}

/// Present again, a different version, deleted, or no longer indexed at all:
/// the granted row is obsolete.
#[tokio::test]
async fn a_granted_row_nothing_depends_on_any_more_is_released() {
    let held = version_of(1);
    for case in ["present", "newer", "deleted", "unindexed"] {
        let state = state();
        match case {
            "present" => index(&state, &record(1, false), MaterializationState::Present),
            "newer" => index(&state, &record(2, false), MaterializationState::Remote),
            "deleted" => index(&state, &record(1, true), MaterializationState::Remote),
            _ => {}
        }
        hold(&state, &key(held), HoldState::Granted);
        assert_eq!(pass(&state, true).await, (1, false), "{case}");
        assert_eq!(rows(&state), 0, "{case}");
    }
}

/// A path whose lock is held (an eviction in flight) is skipped, not waited
/// for and not released; the pass reports it as unfinished.
#[tokio::test]
async fn a_busy_path_is_skipped_and_reported_unfinished() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Present);
    hold(&state, &key(version_of(1)), HoldState::Granted);
    let lock = state.replica_coordinator.path_lock(GROUP, PATH);
    let eviction = lock.lock().await;

    assert_eq!(pass(&state, true).await, (0, true));
    assert_eq!(rows(&state), 1);

    drop(eviction);
    assert_eq!(pass(&state, true).await, (1, false));
    assert_eq!(rows(&state), 0);
}

fn full_replica_peer(state: &DaemonState) {
    state.set_peer_group_writer("p", GROUP, true);
    state.authority.set_peer_group_full_replica("p", GROUP, true);
}

fn hold_state(state: &DaemonState, key: &HoldKey) -> Option<HoldState> {
    state.replica_coordinator.remote_custody_hold_repository().get(key).unwrap().map(|h| h.state)
}

/// The exact order around the RPC: when the acquire is sent the row is
/// already committed as `requested`, and by the time the stamp is returned it
/// is `granted`.
#[tokio::test]
async fn the_hold_is_requested_when_the_acquire_is_sent_and_granted_before_the_stamp() {
    let state = state();
    full_replica_peer(&state);
    let version = version_of(1);
    let key = key(version);
    let seen_when_sent = std::sync::Mutex::new(None);
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            vec!["p".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(version),
            |_peer, _token| {
                *seen_when_sent.lock().unwrap() = Some(hold_state(&state, &key));
                async { true }
            },
        )
        .await
        .expect("a stamp");

    assert_eq!(stamp.peer_id(), "p");
    assert_eq!(*seen_when_sent.lock().unwrap(), Some(Some(HoldState::Requested)));
    assert_eq!(hold_state(&state, &key), Some(HoldState::Granted));
}

/// A denied acquire and one whose answer never arrives (the timeout) both
/// leave the `requested` row: the peer may have committed a lease.
#[tokio::test(start_paused = true)]
async fn a_denied_or_timed_out_acquire_keeps_its_requested_row() {
    let state = state();
    full_replica_peer(&state);
    let key = key(version_of(1));
    let epoch = state.authority.membership_generation();

    let denied = state
        .acquire_custody_lease_with(
            vec!["p".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(key.version_hash),
            |_peer, _token| async { false },
        )
        .await;
    assert!(denied.is_none());
    assert_eq!(hold_state(&state, &key), Some(HoldState::Requested));

    let timed_out = state
        .acquire_custody_lease_with(
            vec!["p".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(key.version_hash),
            |_peer, _token| std::future::pending::<bool>(),
        )
        .await;
    assert!(timed_out.is_none());
    assert_eq!(hold_state(&state, &key), Some(HoldState::Requested));
}

/// A stamp is not issued if authorization moved while the acquire was out.
#[tokio::test]
async fn no_stamp_when_the_peer_lost_its_role_during_the_acquire() {
    let state = state();
    full_replica_peer(&state);
    let key = key(version_of(1));
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            vec!["p".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(key.version_hash),
            |_peer, _token| {
                state.authority.set_peer_group_full_replica("p", GROUP, false);
                async { true }
            },
        )
        .await;

    assert!(stamp.is_none());
    assert_eq!(hold_state(&state, &key), Some(HoldState::Requested), "never granted");
}

/// The reconciler runs again on its own while anything is outstanding, and
/// sleeps only when there are no holds at all.
#[test]
fn the_reconciler_reschedules_itself_while_holds_remain() {
    assert_eq!(next_pass_after(true, true), Some(RETRY_INTERVAL));
    assert_eq!(next_pass_after(false, true), Some(RECHECK_INTERVAL));
    assert_eq!(next_pass_after(false, false), None);
    assert!(RETRY_INTERVAL < RECHECK_INTERVAL);
}

/// The acquire carries the token stored on the hold row, and a second attempt
/// for the same hold (the first was denied or timed out and its row kept)
/// carries the same one: the release that eventually ends the hold names the
/// attempt that may have reached the peer.
#[tokio::test]
async fn every_attempt_for_a_hold_carries_the_token_stored_on_its_row() {
    let state = state();
    full_replica_peer(&state);
    let key = key(version_of(1));
    let epoch = state.authority.membership_generation();
    let sent = std::sync::Mutex::new(Vec::new());

    for answer in [false, true] {
        let sent = &sent;
        state
            .acquire_custody_lease_with(
                vec!["p".into()],
                epoch,
                GROUP,
                PATH,
                VersionHash(key.version_hash),
                |_peer, token| {
                    sent.lock().unwrap().push(token);
                    async move { answer }
                },
            )
            .await;
    }

    let sent = sent.into_inner().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1], "a retry of the same hold is the same attempt");
    let stored = state.replica_coordinator.remote_custody_hold_repository().get(&key).unwrap();
    assert_eq!(stored.unwrap().attempt_token, sent[0]);
}

/// A released hold starts its next attempt under a new token.
#[tokio::test]
async fn a_new_attempt_after_a_release_has_a_new_token() {
    let state = state();
    full_replica_peer(&state);
    let key = key(version_of(1));
    let epoch = state.authority.membership_generation();
    let sent = std::sync::Mutex::new(Vec::new());
    for _ in 0..2 {
        let sent = &sent;
        state
            .acquire_custody_lease_with(
                vec!["p".into()],
                epoch,
                GROUP,
                PATH,
                VersionHash(key.version_hash),
                |_peer, token| {
                    sent.lock().unwrap().push(token);
                    async { false }
                },
            )
            .await;
        state.replica_coordinator.remote_custody_hold_repository().delete(&key).unwrap();
    }
    let sent = sent.into_inner().unwrap();
    assert_ne!(sent[0], sent[1]);
}

/// The release the reconciler sends names the token on the row.
#[tokio::test]
async fn the_release_names_the_attempt_token_of_the_row() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Present);
    hold(&state, &key(version_of(1)), HoldState::Granted);
    let seen = std::sync::Mutex::new(None);
    state
        .reconcile_custody_holds(|hold| {
            *seen.lock().unwrap() = Some((hold.key.clone(), hold.attempt_token));
            async { true }
        })
        .await;
    assert_eq!(seen.into_inner().unwrap(), Some((key(version_of(1)), TOKEN)));
}

// ---- moving a hold off a peer that is giving up its role ----

use std::sync::atomic::AtomicBool;

/// Drives `rehome_custody_hold_with`, recording what it asked for.
async fn rehome(
    state: &DaemonState,
    token: AttemptToken,
    acquire_answer: bool,
    release_answer: bool,
) -> (bool, bool, bool) {
    let acquired = AtomicBool::new(false);
    let released = AtomicBool::new(false);
    let moved = state
        .rehome_custody_hold_with(
            "p",
            GROUP,
            PATH,
            VersionHash(version_of(1)),
            token,
            |_blocks| {
                acquired.store(true, Ordering::SeqCst);
                async move { acquire_answer }
            },
            || {
                released.store(true, Ordering::SeqCst);
                async move { release_answer }
            },
        )
        .await;
    (moved, acquired.load(Ordering::SeqCst), released.load(Ordering::SeqCst))
}

/// A placeholder that depends on the lease: custody is taken elsewhere first,
/// then the old lease is released and its row forgotten.
#[tokio::test]
async fn a_needed_hold_is_acquired_elsewhere_before_the_old_lease_is_released() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    hold(&state, &key(version_of(1)), HoldState::Granted);

    assert_eq!(rehome(&state, TOKEN, true, true).await, (true, true, true));
    assert_eq!(rows(&state), 0);
}

/// No other full replica takes custody: the old lease stays, untouched.
#[tokio::test]
async fn a_needed_hold_with_nowhere_to_go_is_neither_released_nor_forgotten() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    hold(&state, &key(version_of(1)), HoldState::Granted);

    assert_eq!(rehome(&state, TOKEN, false, true).await, (false, true, false));
    assert_eq!(rows(&state), 1);
}

/// The old peer did not confirm the release: the row stays, the answer is no,
/// and a retry (which acquires the same lease again) can finish it.
#[tokio::test]
async fn an_unconfirmed_release_keeps_the_row_and_answers_no() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    hold(&state, &key(version_of(1)), HoldState::Granted);

    assert_eq!(rehome(&state, TOKEN, true, false).await, (false, true, true));
    assert_eq!(rows(&state), 1);
    assert_eq!(rehome(&state, TOKEN, true, true).await, (true, true, true));
    assert_eq!(rows(&state), 0);
}

/// Nothing depends on the lease (the file is present again, a newer version
/// arrived): it is released without taking custody anywhere.
#[tokio::test]
async fn an_obsolete_hold_is_released_without_acquiring_elsewhere() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Present);
    hold(&state, &key(version_of(1)), HoldState::Granted);

    assert_eq!(rehome(&state, TOKEN, false, true).await, (true, false, true));
    assert_eq!(rows(&state), 0);
}

/// A hold that was only `requested` backs no stamp: released, not re-acquired.
#[tokio::test]
async fn a_requested_hold_is_released_without_acquiring_elsewhere() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    hold(&state, &key(version_of(1)), HoldState::Requested);

    assert_eq!(rehome(&state, TOKEN, false, true).await, (true, false, true));
    assert_eq!(rows(&state), 0);
}

/// A request that names a lease this device has no hold for, or names it by a
/// different attempt, is refused and changes nothing: a lease this device does
/// not account for is not released on a peer's say-so.
#[tokio::test]
async fn a_request_for_a_lease_this_device_does_not_account_for_is_refused() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    assert_eq!(rehome(&state, TOKEN, true, true).await, (false, false, false), "no row");

    hold(&state, &key(version_of(1)), HoldState::Granted);
    assert_eq!(rehome(&state, [9; 16], true, true).await, (false, false, false), "other attempt");
    assert_eq!(rows(&state), 1);
}

/// A path another operation holds is waited for only briefly, then the request
/// is refused rather than blocking the sender.
#[tokio::test(start_paused = true)]
async fn a_busy_path_refuses_the_request_after_a_bounded_wait() {
    let state = state();
    index(&state, &record(1, false), MaterializationState::Remote);
    hold(&state, &key(version_of(1)), HoldState::Granted);
    let lock = state.replica_coordinator.path_lock(GROUP, PATH);
    let _eviction = lock.lock().await;

    assert_eq!(rehome(&state, TOKEN, true, true).await, (false, false, false));
    assert_eq!(rows(&state), 1);
}

/// A provider item the OS owns: its row is `Remote`, so the lease is released exactly when the
/// device's own block store holds every block of the held version.
mod provider_local_recovery {
    use super::*;
    use yadorilink_replica_domain::session_state::ProviderKind;

    struct Provider {
        state: Arc<DaemonState>,
        root: std::path::PathBuf,
        hash: String,
    }

    fn provider_item(declared_size: u32) -> Provider {
        let root = tempfile::tempdir().unwrap().keep();
        let store = Arc::new(SegmentBlockStore::new(root.clone()).unwrap());
        let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("requester".into(), coordinator, store);
        let data = vec![9u8; 4096];
        let hash = state.block_store.put(&data).unwrap();
        state.replica_coordinator.link_repository().add_link("/provider/photos", GROUP).unwrap();
        let repo = state.replica_coordinator.provider_repository();
        let declared = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "Photos").unwrap();
        repo.set_domain_registered(&declared, true).unwrap();
        let record = FileRecord {
            path: PATH.into(),
            size: data.len() as u64,
            mtime_unix_nanos: 0,
            blocks: vec![BlockInfo {
                hash: hex::decode(&hash).unwrap(),
                offset: 0,
                size: declared_size,
            }],
            deleted: false,
        };
        index(&state, &record, MaterializationState::Remote);
        let version = state
            .replica_coordinator
            .sqlite()
            .dag_get_current_version_record(GROUP, PATH)
            .unwrap()
            .unwrap()
            .to_file_version()
            .version_hash
            .0;
        hold(&state, &key(version), HoldState::Granted);
        Provider { state, root, hash }
    }

    /// With every block verified locally the device no longer needs the lease.
    #[tokio::test]
    async fn verified_local_blocks_release_the_lease() {
        let p = provider_item(4096);
        assert_eq!(pass(&p.state, true).await, (1, false));
        assert_eq!(rows(&p.state), 0);
    }

    /// An indexed block whose payload does not verify is not a local copy: the remote lease
    /// stays and no release is sent.
    #[tokio::test]
    async fn an_indexed_but_corrupt_block_keeps_the_lease() {
        let p = provider_item(4096);
        yadorilink_local_storage::segment_store::testing::flip_one_payload_bit(&p.root, &p.hash)
            .unwrap();
        assert!(p.state.block_store.exists(&p.hash).unwrap(), "premise: indexed");

        assert_eq!(pass(&p.state, true).await, (0, false));
        assert_eq!(rows(&p.state), 1);
    }

    /// A hash-valid payload that is not the length the version declares does not back a release.
    #[tokio::test]
    async fn a_block_of_the_wrong_declared_length_keeps_the_lease() {
        let p = provider_item(4097);
        assert_eq!(pass(&p.state, true).await, (0, false));
        assert_eq!(rows(&p.state), 1);
    }
}

// ---- a silent candidate, and a retried move ----

fn full_replica(state: &DaemonState, peer: &str) {
    state.set_peer_group_writer(peer, GROUP, true);
    state.authority.set_peer_group_full_replica(peer, GROUP, true);
}

/// A candidate that never answers uses up only its own share of the budget:
/// the next one is still asked and its stamp returned within the overall bound.
#[tokio::test(start_paused = true)]
async fn a_silent_first_candidate_does_not_spend_the_whole_budget() {
    let state = state();
    full_replica(&state, "silent");
    full_replica(&state, "healthy");
    let asked = std::sync::Mutex::new(Vec::new());
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            vec!["silent".into(), "healthy".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(version_of(1)),
            |peer, _token| {
                asked.lock().unwrap().push(peer.to_string());
                let silent = peer == "silent";
                async move {
                    if silent {
                        std::future::pending::<bool>().await
                    } else {
                        true
                    }
                }
            },
        )
        .await
        .expect("the healthy candidate grants");

    assert_eq!(stamp.peer_id(), "healthy");
    assert_eq!(*asked.lock().unwrap(), vec!["silent", "healthy"]);
}

/// Silent candidates ahead of a healthy one never starve it, however many there
/// are: each gets a share of what remains, so every candidate is asked.
#[tokio::test(start_paused = true)]
async fn many_silent_candidates_still_leave_the_last_one_an_attempt() {
    let state = state();
    let names = ["s1", "s2", "s3", "s4", "s5", "healthy"];
    for name in names {
        full_replica(&state, name);
    }
    let asked = std::sync::Mutex::new(Vec::new());
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            names.map(String::from).to_vec(),
            epoch,
            GROUP,
            PATH,
            VersionHash(version_of(1)),
            |peer, _token| {
                asked.lock().unwrap().push(peer.to_string());
                let silent = peer != "healthy";
                async move {
                    if silent {
                        std::future::pending::<bool>().await
                    } else {
                        true
                    }
                }
            },
        )
        .await
        .expect("the healthy candidate grants");

    assert_eq!(stamp.peer_id(), "healthy");
    assert_eq!(asked.lock().unwrap().len(), names.len());
}

/// Candidates are still tried one after another, and one that granted ends the
/// search: a call creates at most one lease it relies on.
#[tokio::test]
async fn the_first_candidate_that_grants_ends_the_search() {
    let state = state();
    full_replica(&state, "a");
    full_replica(&state, "b");
    let asked = AtomicUsize::new(0);
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            vec!["a".into(), "b".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(version_of(1)),
            |_peer, _token| {
                asked.fetch_add(1, Ordering::SeqCst);
                async { true }
            },
        )
        .await
        .expect("a stamp");

    assert_eq!(stamp.peer_id(), "a");
    assert_eq!(asked.load(Ordering::SeqCst), 1);
}

/// A retried move asks the peer that already holds a granted hold for this
/// version first. That peer answers with its existing lease (or refuses), so a
/// retry after a lost release acknowledgement adds no further hold; a peer that
/// is only requested, or holds another version, gets no preference.
#[tokio::test]
async fn peers_already_holding_this_version_are_asked_first() {
    let state = state();
    let version = version_of(1);
    hold(&state, &HoldKey { peer_id: "granted".into(), ..key(version) }, HoldState::Granted);
    hold(&state, &HoldKey { peer_id: "requested".into(), ..key(version) }, HoldState::Requested);
    hold(
        &state,
        &HoldKey { peer_id: "other-version".into(), ..key(version_of(2)) },
        HoldState::Granted,
    );
    let peers = ["new", "requested", "other-version", "granted"].map(String::from).to_vec();

    let ordered = state.existing_holders_first(GROUP, PATH, &version, peers);

    assert_eq!(ordered, ["granted", "new", "requested", "other-version"]);
}

/// The hold of a peer that is asked again keeps its row and token, so the
/// repeated acquire is the same attempt, and a granting first candidate ends
/// the search with no second hold.
#[tokio::test]
async fn asking_the_existing_holder_again_adds_no_hold() {
    let state = state();
    full_replica(&state, "q");
    full_replica(&state, "new");
    let version = version_of(1);
    let held = HoldKey { peer_id: "q".into(), ..key(version) };
    hold(&state, &held, HoldState::Granted);
    let peers = state.existing_holders_first(
        GROUP,
        PATH,
        &version,
        vec!["new".to_string(), "q".to_string()],
    );
    let asked = std::sync::Mutex::new(Vec::new());
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            peers,
            epoch,
            GROUP,
            PATH,
            VersionHash(version),
            |peer, token| {
                asked.lock().unwrap().push((peer.to_string(), token));
                async { true }
            },
        )
        .await
        .expect("a stamp");

    assert_eq!(stamp.peer_id(), "q");
    assert_eq!(*asked.lock().unwrap(), vec![("q".to_string(), TOKEN)], "the first attempt's token");
    assert_eq!(rows(&state), 1);
}

// ---- scale probe ----

/// `holds` granted holds the paths no longer depend on, spread over two peers,
/// one of them offline. A pass asks each hold's peer exactly once (one RPC per
/// hold, no repeats), deletes the online peer's holds, keeps the offline
/// peer's and reports itself unfinished so the reconciler retries.
async fn scale_probe(holds: usize) {
    let state = state();
    let repo = state.replica_coordinator.remote_custody_hold_repository();
    for n in 0..holds {
        let peer = if n % 2 == 0 { "online" } else { "offline" };
        let key = HoldKey {
            group_id: GROUP.into(),
            path: format!("dir/{n}.bin"),
            version_hash: version_of(1),
            peer_id: peer.into(),
        };
        repo.record_requested(&key, 1, TOKEN).unwrap();
        repo.mark_granted(&key).unwrap();
    }
    let calls = AtomicUsize::new(0);

    let unfinished = state
        .reconcile_custody_holds(|hold| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { hold.key.peer_id == "online" }
        })
        .await;

    assert!(unfinished, "the offline peer's holds are retried");
    assert_eq!(calls.load(Ordering::SeqCst), holds, "one release round trip per hold");
    let left = repo.list().unwrap();
    assert_eq!(left.len(), holds / 2);
    assert!(left.iter().all(|hold| hold.key.peer_id == "offline"));

    // The retry asks only for what is left.
    calls.store(0, Ordering::SeqCst);
    state
        .reconcile_custody_holds(|_hold| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { true }
        })
        .await;
    assert_eq!(calls.load(Ordering::SeqCst), holds / 2);
    assert_eq!(rows(&state), 0);
}

#[tokio::test]
async fn scale_probe_100_holds() {
    scale_probe(100).await;
}

#[tokio::test]
async fn scale_probe_1000_holds() {
    scale_probe(1_000).await;
}

/// The large selective-sync tier: run on request
/// (`cargo test -p yadorilink-daemon --lib scale_probe_10000 -- --ignored`).
#[tokio::test]
#[ignore = "large tier; run on request"]
async fn scale_probe_10000_holds() {
    scale_probe(10_000).await;
}

/// A lone candidate that is merely slow (longer than a share of the budget,
/// within the whole of it) still grants.
#[tokio::test(start_paused = true)]
async fn a_lone_slow_candidate_may_use_the_whole_budget() {
    let state = state();
    full_replica(&state, "slow");
    let epoch = state.authority.membership_generation();

    let stamp = state
        .acquire_custody_lease_with(
            vec!["slow".into()],
            epoch,
            GROUP,
            PATH,
            VersionHash(version_of(1)),
            |_peer, _token| async {
                tokio::time::sleep(Duration::from_secs(8)).await;
                true
            },
        )
        .await;

    assert!(stamp.is_some());
}

/// Three peers: a move off `p` acquires at `b`, `p`'s release is not
/// confirmed. The retry sees the candidates in another order (the registry has
/// none), yet asks `b` again first and never `c`: one replacement hold, and the
/// retry only finishes the old release.
#[tokio::test]
async fn a_retried_move_reuses_the_replacement_it_took_and_never_asks_a_third_peer() {
    let state = state();
    for peer in ["b", "c"] {
        full_replica(&state, peer);
    }
    index(&state, &record(1, false), MaterializationState::Remote);
    let version = version_of(1);
    hold(&state, &key(version), HoldState::Granted);
    let asked = std::sync::Mutex::new(Vec::new());
    let epoch = state.authority.membership_generation();

    for (attempt, order, release_confirmed) in [(1, ["b", "c"], false), (2, ["c", "b"], true)] {
        asked.lock().unwrap().clear();
        let moved = state
            .rehome_custody_hold_with(
                "p",
                GROUP,
                PATH,
                VersionHash(version),
                TOKEN,
                |_blocks| async {
                    let peers = state.existing_holders_first(
                        GROUP,
                        PATH,
                        &version,
                        order.map(String::from).to_vec(),
                    );
                    state
                        .acquire_custody_lease_with(
                            peers,
                            epoch,
                            GROUP,
                            PATH,
                            VersionHash(version),
                            |peer, _token| {
                                asked.lock().unwrap().push(peer.to_string());
                                async { true }
                            },
                        )
                        .await
                        .is_some()
                },
                || async move { release_confirmed },
            )
            .await;
        assert_eq!(moved, release_confirmed, "attempt {attempt}");
        assert_eq!(asked.lock().unwrap().len(), 1, "attempt {attempt}: one candidate asked");
        assert_eq!(asked.lock().unwrap()[0], "b", "attempt {attempt}");
    }

    assert_eq!(rows(&state), 1, "only the replacement remains");
    let b = HoldKey { peer_id: "b".into(), ..key(version) };
    assert_eq!(hold_state(&state, &b), Some(HoldState::Granted));
}
