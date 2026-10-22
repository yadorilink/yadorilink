#![cfg(test)]

use std::collections::{HashMap, HashSet};

use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_sync_sqlite::remote_custody_lease::CustodyLeaseRequest;

use yadorilink_replica_domain::session_state::MaterializationPolicy;

use super::*;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "g";
const OTHER_GROUP: &str = "g2";
const REQUESTER: &str = "ondemand";
const TOKEN: [u8; 16] = [3; 16];

fn state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("responder".into(), coordinator, store)
}

fn lease_for(group: &str, requester: &str, path: &str, generation: u64) -> CustodyLeaseRequest {
    CustodyLeaseRequest {
        group_id: group.into(),
        requester_device_id: requester.into(),
        path: path.into(),
        version_hash: [9; 32],
        blocks: vec!["aa".into()],
        membership_generation: generation,
        attempt_token: TOKEN,
        now_unix: 1,
    }
}

fn hold_lease(state: &DaemonState, group: &str, requester: &str) {
    state
        .replica_coordinator
        .remote_custody_lease_repository()
        .acquire(&lease_for(group, requester, "a.bin", 1))
        .unwrap();
}

fn leases(state: &DaemonState) -> Vec<(String, String)> {
    let mut all: Vec<_> = state
        .replica_coordinator
        .remote_custody_lease_repository()
        .list_active()
        .unwrap()
        .into_iter()
        .map(|l| (l.group_id, l.requester_device_id))
        .collect();
    all.sort();
    all
}

fn netmap(entries: &[(&str, &[&str])]) -> HashMap<String, HashSet<String>> {
    entries
        .iter()
        .map(|(device, groups)| {
            (device.to_string(), groups.iter().map(|g| g.to_string()).collect::<HashSet<_>>())
        })
        .collect()
}

fn link(state: &DaemonState, group: &str, policy: MaterializationPolicy) -> String {
    let path = format!("/links/{group}");
    let links = state.replica_coordinator.link_repository();
    links.add_link(&path, group).unwrap();
    links.set_materialization_policy(&path, policy).unwrap();
    path
}

// ---- a requester that left the group ----

fn edge(device: &str, group: &str) -> (String, String) {
    (device.to_string(), group.to_string())
}

/// A snapshot that no longer lists the requester for the group drops its
/// lease; a requester it still lists for that group, or another group's
/// lease, is left alone.
#[tokio::test]
async fn a_requester_the_snapshot_no_longer_lists_for_the_group_loses_its_leases() {
    let state = state();
    hold_lease(&state, GROUP, REQUESTER);
    hold_lease(&state, GROUP, "kept");
    hold_lease(&state, OTHER_GROUP, REQUESTER);

    let dropped = state.drop_custody_leases_of_departed_requesters(
        &[edge(REQUESTER, GROUP)],
        &netmap(&[(REQUESTER, &[OTHER_GROUP]), ("kept", &[GROUP])]),
        true,
    );

    assert_eq!(dropped, 1);
    assert_eq!(
        leases(&state),
        vec![(GROUP.to_string(), "kept".to_string()), (OTHER_GROUP.to_string(), REQUESTER.into())]
    );
}

/// A frame that cannot be ranked against the persisted authorization (the run's
/// first, older than the cache) deletes nothing, whether it is silent about the
/// requester or lists it without the group: a lease dropped on a replayed
/// frame is not restored by the next one.
#[tokio::test]
async fn a_frame_that_may_not_withdraw_drops_nothing_and_a_later_one_does() {
    let state = state();
    hold_lease(&state, GROUP, REQUESTER);
    hold_lease(&state, GROUP, "narrowed");
    let snapshot = netmap(&[("narrowed", &[OTHER_GROUP])]);
    let removed = [edge(REQUESTER, GROUP), edge("narrowed", GROUP)];

    assert_eq!(state.drop_custody_leases_of_departed_requesters(&removed, &snapshot, false), 0);
    assert_eq!(leases(&state).len(), 2);
    assert!(!state.replica_coordinator.custody_closing().is_barred(GROUP, REQUESTER));

    assert_eq!(state.drop_custody_leases_of_departed_requesters(&removed, &snapshot, true), 2);
    assert!(leases(&state).is_empty());
}

/// Dropping a requester also forgets the attempts it released: its standing is
/// gone, and a return to the group starts clean. Found even though it holds no
/// lease.
#[tokio::test]
async fn a_departed_requesters_release_tombstones_go_with_its_leases() {
    let state = state();
    let repo = state.replica_coordinator.remote_custody_lease_repository();
    hold_lease(&state, GROUP, REQUESTER);
    repo.release(GROUP, REQUESTER, "a.bin", &[9; 32], &TOKEN).unwrap();
    assert_eq!(repo.tombstone_count().unwrap(), 1);

    state.drop_custody_leases_of_departed_requesters(&[], &netmap(&[]), true);

    assert_eq!(repo.tombstone_count().unwrap(), 0);
}

/// A requester removed in a frame is barred from acquiring even though it held
/// nothing here: an acquire already past the session's group check commits
/// nothing. A later snapshot that lists it again lifts the bar.
#[tokio::test]
async fn a_removed_requester_cannot_acquire_until_the_plane_lists_it_again() {
    let state = state();
    let adapter = crate::replica_coordinator::engine_ports::CustodyLeaseAdapter {
        coordinator: state.replica_coordinator.clone(),
    };
    let request = || yadorilink_replica_engine::ports::CustodyLeaseRequest {
        group_id: GROUP.into(),
        requester_device_id: REQUESTER.into(),
        path: "a.bin".into(),
        version_hash: [9; 32],
        block_hashes: vec![vec![0xaa; 32]],
        membership_generation: 1,
        attempt_token: TOKEN,
    };
    use yadorilink_replica_engine::CustodyLeasePort;
    assert!(adapter.acquire(&request()).unwrap(), "sanity: an authorized requester acquires");
    adapter.release(GROUP, REQUESTER, "a.bin", &[9; 32], &TOKEN).unwrap();

    state.drop_custody_leases_of_departed_requesters(&[edge(REQUESTER, GROUP)], &netmap(&[]), true);
    assert!(!adapter.acquire(&request()).unwrap(), "refused");
    assert!(leases(&state).is_empty(), "and nothing was committed");

    state.drop_custody_leases_of_departed_requesters(&[], &netmap(&[(REQUESTER, &[GROUP])]), true);
    assert!(!state.replica_coordinator.custody_closing().is_barred(GROUP, REQUESTER));
    let again = yadorilink_replica_engine::ports::CustodyLeaseRequest {
        attempt_token: [8; 16],
        ..request()
    };
    assert!(adapter.acquire(&again).unwrap(), "listed again, it acquires");
}

// ---- this device stopped being the group's full replica ----

/// A device that stops keeping the group as a full replica does not drop the
/// leases it holds for others on its own: they are another device's only copy,
/// and end only by release, hand-off, or the requester leaving the group.
#[tokio::test]
async fn a_leftover_lease_outlives_the_full_replica_role_that_held_it() {
    let state = state();
    let path = link(&state, GROUP, MaterializationPolicy::Eager);
    hold_lease(&state, GROUP, REQUESTER);

    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(&path, MaterializationPolicy::OnDemand)
        .unwrap();
    state.drop_custody_leases_of_departed_requesters(&[], &netmap(&[(REQUESTER, &[GROUP])]), true);
    state.replica_coordinator.link_repository().mark_link_orphaned(&path).unwrap();
    state.drop_custody_leases_of_departed_requesters(&[], &netmap(&[(REQUESTER, &[GROUP])]), true);

    assert_eq!(leases(&state).len(), 1);
}

// ---- membership generation ----

/// The generation counts every netmap change; it says nothing about whether a
/// lease is still owed. A lease acquired under an old generation survives any
/// number of transitions while the requester stays listed.
#[tokio::test]
async fn a_membership_generation_transition_alone_leaves_a_lease_in_place() {
    let state = state();
    state
        .replica_coordinator
        .remote_custody_lease_repository()
        .acquire(&lease_for(GROUP, REQUESTER, "a.bin", 1))
        .unwrap();
    let before = state.authority.membership_generation();

    state.set_peer_group_writer("someone-else", GROUP, true);
    state.authority.set_peer_group_full_replica("someone-else", GROUP, true);
    state.set_peer_group_writer("someone-else", GROUP, false);
    assert!(state.authority.membership_generation() > before);

    assert_eq!(
        state.drop_custody_leases_of_departed_requesters(
            &[],
            &netmap(&[(REQUESTER, &[GROUP])]),
            true
        ),
        0
    );
    let kept = state.replica_coordinator.remote_custody_lease_repository().list_active().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept[0].membership_generation, 1,
        "the stamp of the acquire is recorded, not rewritten"
    );
}

/// What a transition does change is standing: the same lease is dropped once
/// a later snapshot (a later generation) no longer lists its requester.
#[tokio::test]
async fn a_transition_that_removes_the_requester_ends_its_lease() {
    let state = state();
    hold_lease(&state, GROUP, REQUESTER);
    state.set_peer_group_writer(REQUESTER, GROUP, true);
    state.set_peer_group_writer(REQUESTER, GROUP, false);

    state.drop_custody_leases_of_departed_requesters(&[edge(REQUESTER, GROUP)], &netmap(&[]), true);

    assert!(leases(&state).is_empty());
}

// ---- closing a group while its leases move ----

/// While a group is closed an acquire commits nothing; once the guard is
/// dropped it commits again, and a close elsewhere does not reach it.
#[tokio::test]
async fn a_closed_group_takes_no_lease_and_reopens_when_the_guard_drops() {
    let state = state();
    let closing = state.replica_coordinator.custody_closing();
    assert!(state.hand_off_custody_leases(GROUP).await.is_ok(), "nothing to move");
    // The guard returned above was dropped at the end of the statement.
    assert!(!closing.is_closed(GROUP));

    let guard = state.hand_off_custody_leases(GROUP).await.unwrap();
    assert!(closing.is_closed(GROUP));
    assert!(!closing.is_closed(OTHER_GROUP));
    drop(guard);
    assert!(!closing.is_closed(GROUP));
}

/// The commit of an acquire and the close are ordered: a close returns only
/// after every acquire it did not stop has committed.
#[test]
fn a_close_waits_for_the_acquire_that_was_admitted_before_it() {
    let closing = std::sync::Arc::new(CustodyClosing::default());
    let admitted = std::sync::Arc::new(std::sync::Barrier::new(2));
    let committed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let acquire = {
        let (closing, admitted, committed) = (closing.clone(), admitted.clone(), committed.clone());
        std::thread::spawn(move || {
            closing.while_open(GROUP, REQUESTER, || {
                admitted.wait();
                std::thread::sleep(Duration::from_millis(100));
                committed.store(true, std::sync::atomic::Ordering::SeqCst);
            })
        })
    };
    admitted.wait();
    closing.close(GROUP, None);

    assert!(
        committed.load(std::sync::atomic::Ordering::SeqCst),
        "close returned before the commit"
    );
    assert!(acquire.join().unwrap().is_some());
    assert!(closing.while_open(GROUP, REQUESTER, || ()).is_none(), "later acquires find it closed");
}

/// Two operations closing the same group each reopen only their own close.
#[test]
fn operations_closing_the_same_group_reopen_only_their_own_close() {
    let closing = CustodyClosing::default();
    let operation = closing.close(GROUP, None);
    let other = closing.close(GROUP, Some(Instant::now() + Duration::from_secs(600)));
    closing.reopen(operation);
    assert!(closing.is_closed(GROUP), "the other operation's close is still in place");
    closing.reopen(other);
    assert!(!closing.is_closed(GROUP));
}

/// A lease whose requester has no session cannot move: the hand-off names it
/// and fails, leaves the lease where it is, and reopens the group.
#[tokio::test]
async fn a_lease_whose_requester_is_unreachable_blocks_the_hand_off() {
    let state = state();
    hold_lease(&state, GROUP, REQUESTER);

    let error = state.hand_off_custody_leases(GROUP).await.err().expect("must refuse");

    assert!(error.contains(REQUESTER), "{error}");
    assert_eq!(leases(&state).len(), 1, "the lease stays");
    assert!(!state.replica_coordinator.custody_closing().is_closed(GROUP));
}

/// A removal ticket is refused while a lease cannot move, and the group does
/// not stay closed after a refusal.
#[tokio::test]
async fn a_removal_ticket_is_refused_while_a_custody_lease_cannot_move() {
    let state = state();
    hold_lease(&state, GROUP, REQUESTER);

    assert!(state.obtain_own_handoff_ticket(GROUP).await.is_none());

    assert_eq!(leases(&state).len(), 1);
    assert!(!state.replica_coordinator.custody_closing().is_closed(GROUP));
}

/// A ticket for a group with nothing to hand off carries no lease, cannot be
/// bound to a lease-guarded commit and is discarded by the responder, so it
/// closes nothing: an unusable ticket must not keep custody leases out.
#[tokio::test]
async fn a_ticket_without_a_lease_closes_nothing() {
    let state = state();

    assert!(state.obtain_own_handoff_ticket(GROUP).await.is_some());

    assert!(!state.replica_coordinator.custody_closing().is_closed(GROUP));
}

/// The close a ticket holds covers the whole of its handoff lease, however long
/// the coordination plane is configured to make that, and is measured as a
/// duration from the grant's arrival -- not as an expiry compared with this
/// device's clock, which the coordination plane's need not agree with.
#[test]
fn a_ticket_keeps_the_group_closed_for_the_whole_lifetime_of_its_lease() {
    let fifteen_minutes = Duration::from_secs(15 * 60);
    assert!(ticket_close_for(15 * 60) > fifteen_minutes);
    assert_eq!(ticket_close_for(15 * 60), fifteen_minutes + TICKET_CLOSE_MARGIN);
    assert!(
        ticket_close_for(3600) > Duration::from_secs(3600),
        "a longer configured lease closes for longer"
    );
    assert_eq!(ticket_close_for(0), TICKET_CLOSE_MARGIN);
    assert_eq!(
        ticket_close_for(-5),
        TICKET_CLOSE_MARGIN,
        "a nonsensical lifetime still gets the margin"
    );
}

/// A release as the target answers it: `acked` is whether the target
/// acknowledged ending the ticket's handoff lease.
async fn release(state: &DaemonState, group: &str, lease_id: &str, acked: bool) {
    state.end_ticket_close_when_released(group, lease_id, || async move { acked }).await;
}

/// An acknowledged release reopens that ticket's close and no other, so a
/// delayed release of an earlier ticket cannot reopen the group under a newer
/// one, and repeating it changes nothing.
#[tokio::test]
async fn an_acknowledged_release_reopens_only_that_tickets_close() {
    let state = state();
    let closing = state.replica_coordinator.custody_closing();
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(600)).await;
    grant_ticket(&state, GROUP, "lease-b", Duration::from_secs(600)).await;
    assert!(closing.is_closed(GROUP));

    release(&state, GROUP, "lease-a", true).await;
    assert!(closing.is_closed(GROUP), "the newer ticket still holds the group closed");
    release(&state, GROUP, "lease-a", true).await;
    assert!(closing.is_closed(GROUP), "a repeated release of the first changes nothing");

    release(&state, GROUP, "lease-b", true).await;
    assert!(!closing.is_closed(GROUP));
}

/// Without the target's acknowledgement the ticket may still be usable, so the
/// close stays; a later release that is acknowledged ends it.
#[tokio::test]
async fn an_unacknowledged_release_keeps_the_close_until_a_retry_is_acknowledged() {
    let state = state();
    let closing = state.replica_coordinator.custody_closing();
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(600)).await;

    release(&state, GROUP, "lease-a", false).await;
    assert!(closing.is_closed(GROUP), "target unreachable: still closed");
    assert!(!acquire_at(&state, GROUP, 1));
    release(&state, GROUP, "lease-a", false).await;
    assert!(closing.is_closed(GROUP));

    release(&state, GROUP, "lease-a", true).await;
    assert!(!closing.is_closed(GROUP));
    assert!(acquire_at(&state, GROUP, 2));
}

/// The same across a restart: a release the target never acknowledged leaves
/// the durable close, and the restarted daemon is still closed; the retry that
/// is acknowledged ends it for good.
#[tokio::test]
async fn an_unacknowledged_release_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(600)).await;
    release(&state, GROUP, "lease-a", false).await;

    let state = restart(state, dir.path());
    assert!(!acquire_at(&state, GROUP, 1), "still closed after the restart");

    release(&state, GROUP, "lease-a", true).await;
    assert!(acquire_at(&state, GROUP, 2));
    let state = restart(state, dir.path());
    assert!(acquire_at(&state, GROUP, 3), "an acknowledged release is not revived");
}

/// The acknowledgement of an old ticket's release (it arrives late) does not
/// reopen the group while a newer ticket's close is in place, before or after
/// a restart.
#[tokio::test]
async fn a_late_acknowledgement_of_an_old_ticket_does_not_reopen_a_newer_ticket() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "old", Duration::from_secs(600)).await;
    release(&state, GROUP, "old", true).await;
    assert!(!state.replica_coordinator.custody_closing().is_closed(GROUP), "the old close ended");
    grant_ticket(&state, GROUP, "new", Duration::from_secs(600)).await;

    release(&state, GROUP, "old", true).await;
    assert!(!acquire_at(&state, GROUP, 2), "the late acknowledgement leaves the new close");
    let state = restart(state, dir.path());
    release(&state, GROUP, "old", true).await;
    assert!(!acquire_at(&state, GROUP, 3));
    release(&state, GROUP, "new", true).await;
    assert!(acquire_at(&state, GROUP, 4));
}

/// A close made for an operation has no deadline of its own: however long the
/// moves take, the group stays closed until the operation lets go.
#[test]
fn an_operations_close_does_not_run_out() {
    let closing = CustodyClosing::default();
    let key = closing.close(GROUP, None);
    assert!(closing.is_closed(GROUP));
    // A later close (and its sweep of expired ones) leaves it in place.
    let other = closing.close(OTHER_GROUP, Some(Instant::now()));
    assert!(closing.is_closed(GROUP));
    assert!(!closing.is_closed(OTHER_GROUP), "a close past its deadline is no close");
    closing.reopen(other);
    closing.reopen(key);
    assert!(!closing.is_closed(GROUP));
}

/// A lifetime too long to add to the clock is a close with no deadline of its
/// own (it ends when the ticket is released), not a panic and not an early end.
#[tokio::test]
async fn a_ticket_lifetime_beyond_what_a_deadline_can_hold_still_closes_the_group() {
    let state = state();
    let closing = state.replica_coordinator.custody_closing();
    assert!(ticket_close_for(i64::MAX) > Duration::from_secs(31 * 24 * 3600));

    state
        .hand_off_custody_leases(GROUP)
        .await
        .unwrap()
        .hold_for_ticket(Duration::MAX, "lease-x")
        .unwrap();
    assert!(closing.is_closed(GROUP));
    release(&state, GROUP, "lease-x", true).await;
    assert!(!closing.is_closed(GROUP));
}

/// The record of which close a ticket holds does not outlive the close: a
/// ticket nobody releases is forgotten once its close has run out.
#[test]
fn tickets_whose_close_ran_out_are_forgotten() {
    let closing = CustodyClosing::default();
    for n in 0..50 {
        let key = closing.close(GROUP, None);
        closing.hold_for_ticket(key, Duration::ZERO, &format!("lease-{n}")).unwrap();
    }
    closing.close(OTHER_GROUP, None);
    assert!(closing.ticket_count() <= 1, "expired tickets are swept by the next close");
}

// ---- a ticket's close survives a restart ----

use crate::replica_coordinator::engine_ports::CustodyLeaseAdapter;
use yadorilink_replica_engine::ports::{CustodyLeasePort, CustodyLeaseRequest as EngineAcquire};

/// A daemon over the database file in `dir`; opening it again is a restart.
fn state_at(dir: &std::path::Path) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(dir.join("blocks")).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open(dir.join("replica.db")).unwrap());
    DaemonState::new("responder".into(), coordinator, store)
}

/// What a still-authorized On-Demand requester sends; `true` when the
/// responder committed a lease for it.
fn acquire_at(state: &DaemonState, group: &str, token: u8) -> bool {
    CustodyLeaseAdapter { coordinator: state.replica_coordinator.clone() }
        .acquire(&EngineAcquire {
            group_id: group.into(),
            requester_device_id: REQUESTER.into(),
            path: "late.bin".into(),
            version_hash: [7; 32],
            block_hashes: vec![vec![0xaa]],
            membership_generation: 1,
            attempt_token: [token; 16],
        })
        .unwrap()
}

async fn grant_ticket(state: &DaemonState, group: &str, lease_id: &str, close_for: Duration) {
    state
        .hand_off_custody_leases(group)
        .await
        .unwrap()
        .hold_for_ticket(close_for, lease_id)
        .expect("the ticket's close is recorded");
}

fn restart(state: Arc<DaemonState>, dir: &std::path::Path) -> Arc<DaemonState> {
    drop(state);
    state_at(dir)
}

/// The issue's sequence: a ticket is granted, the daemon restarts before the
/// removal commits, and a new acquire must not commit until the ticket ends.
#[tokio::test]
async fn a_late_acquire_after_a_restart_is_refused_until_the_ticket_is_released() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(600)).await;
    assert!(!acquire_at(&state, GROUP, 1), "refused while running");

    let state = restart(state, dir.path());
    assert!(!acquire_at(&state, GROUP, 2), "refused after the restart");
    assert!(leases(&state).is_empty(), "nothing committed after the proof boundary");

    release(&state, GROUP, "lease-a", true).await;
    assert!(acquire_at(&state, GROUP, 3), "open again once the ticket is released");
    let state = restart(state, dir.path());
    assert!(acquire_at(&state, GROUP, 4), "a released ticket is not revived by another restart");
}

/// Another group is unaffected, and one ticket's release does not reopen
/// another's, before or after a restart.
#[tokio::test]
async fn releases_are_scoped_to_their_group_and_ticket_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(600)).await;
    grant_ticket(&state, GROUP, "lease-b", Duration::from_secs(600)).await;
    grant_ticket(&state, OTHER_GROUP, "lease-c", Duration::from_secs(600)).await;

    let state = restart(state, dir.path());
    release(&state, GROUP, "lease-a", true).await;
    assert!(!acquire_at(&state, GROUP, 1), "lease-b still closes the group");
    assert!(!acquire_at(&state, OTHER_GROUP, 1), "lease-c closes its own group");
    // Same lease id, other group: not the same ticket.
    release(&state, OTHER_GROUP, "lease-b", true).await;
    assert!(!acquire_at(&state, OTHER_GROUP, 2));

    let state = restart(state, dir.path());
    release(&state, GROUP, "lease-b", true).await;
    release(&state, GROUP, "lease-b", true).await;
    assert!(acquire_at(&state, GROUP, 3));
    assert!(!acquire_at(&state, OTHER_GROUP, 3));
}

/// A close made for an operation that never granted a ticket is owned by that
/// operation alone: nothing outside depends on it, so a crash leaves nothing
/// to honour. A ticket's close runs out like it does in a process that never
/// restarted: the restart counts it afresh from the start, never shorter.
#[tokio::test]
async fn a_restart_keeps_a_ticket_close_for_its_full_length_and_forgets_it_after() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    let _unfinished = state.hand_off_custody_leases("unfinished").await.unwrap();
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(1)).await;
    std::mem::forget(_unfinished);

    let state = restart(state, dir.path());
    assert!(acquire_at(&state, "unfinished", 1), "no ticket was granted for it");
    assert!(!acquire_at(&state, GROUP, 1), "re-armed for its whole length");
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert!(acquire_at(&state, GROUP, 2), "and open once that has passed");

    // Observing the run-out close ends its record without any later close, so
    // it is not re-armed by every later restart.
    let leases = state.replica_coordinator.remote_custody_lease_repository();
    assert!(leases.ticket_closes().unwrap().is_empty());
    let state = restart(state, dir.path());
    assert!(acquire_at(&state, GROUP, 3));
}

fn ticket_rows(state: &DaemonState) -> Vec<(String, String, Option<u64>)> {
    state.replica_coordinator.remote_custody_lease_repository().ticket_closes().unwrap()
}

async fn run_out() {
    tokio::time::sleep(Duration::from_millis(1300)).await;
}

/// A timed ticket close that runs out in one process, with no later close and
/// no release, has its durable record removed once it is observed.
#[tokio::test]
async fn an_expired_ticket_close_loses_its_record_without_any_later_close() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(1)).await;
    assert_eq!(ticket_rows(&state).len(), 1);
    assert!(!acquire_at(&state, GROUP, 1), "closed while live");
    assert_eq!(ticket_rows(&state).len(), 1, "a live close keeps its record");

    run_out().await;
    assert!(acquire_at(&state, GROUP, 2), "open once it ran out");
    assert!(ticket_rows(&state).is_empty(), "record removed");
    assert_eq!(state.replica_coordinator.custody_closing().ticket_count(), 0);
}

/// After that cleanup a restart does not close the group again.
#[tokio::test]
async fn a_restart_after_the_expiry_cleanup_does_not_reclose_the_group() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(1)).await;
    run_out().await;
    assert!(acquire_at(&state, GROUP, 1));

    let state = restart(state, dir.path());
    assert!(acquire_at(&state, GROUP, 2), "not re-armed");
}

/// When the record cannot be deleted it stays, so a restart may re-close (the
/// safe side), and a later observation retries the deletion.
#[tokio::test]
async fn a_failed_expiry_cleanup_keeps_the_record_and_retries() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::from_secs(1)).await;
    let side = rusqlite::Connection::open(dir.path().join("replica.db")).unwrap();
    side.execute_batch(
        "CREATE TRIGGER no_delete BEFORE DELETE ON custody_ticket_close \
         BEGIN SELECT RAISE(ABORT, 'no'); END;",
    )
    .unwrap();

    run_out().await;
    assert!(acquire_at(&state, GROUP, 1), "the run-out close does not hold the live process");
    assert_eq!(ticket_rows(&state).len(), 1, "record kept");

    let state2 = restart(state, dir.path());
    assert!(!acquire_at(&state2, GROUP, 2), "the restart re-closes: safe side");
    run_out().await;

    side.execute_batch("DROP TRIGGER no_delete;").unwrap();
    assert!(acquire_at(&state2, GROUP, 3));
    assert!(ticket_rows(&state2).is_empty(), "a later observation retried the delete");
}

/// One ticket running out never ends a newer ticket's close for the group.
#[tokio::test]
async fn an_expired_ticket_does_not_end_a_newer_tickets_close() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-old", Duration::from_secs(1)).await;
    grant_ticket(&state, GROUP, "lease-new", Duration::from_secs(600)).await;

    run_out().await;
    assert!(!acquire_at(&state, GROUP, 1), "the newer ticket still closes the group");
    let rows = ticket_rows(&state);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "lease-new");

    let state = restart(state, dir.path());
    assert!(!acquire_at(&state, GROUP, 2), "and across a restart");
    release(&state, GROUP, "lease-new", true).await;
    assert!(acquire_at(&state, GROUP, 3));
}

/// A close with no deadline is never swept by the timed path.
#[tokio::test]
async fn an_indefinite_ticket_close_is_never_swept() {
    let dir = tempfile::tempdir().unwrap();
    let state = state_at(dir.path());
    grant_ticket(&state, GROUP, "lease-a", Duration::MAX).await;
    assert_eq!(ticket_rows(&state), vec![(GROUP.to_string(), "lease-a".to_string(), None)]);

    run_out().await;
    assert!(!acquire_at(&state, GROUP, 1));
    assert!(!acquire_at(&state, GROUP, 2));
    assert_eq!(ticket_rows(&state).len(), 1);
    let state = restart(state, dir.path());
    assert!(!acquire_at(&state, GROUP, 3));
    release(&state, GROUP, "lease-a", true).await;
    assert!(acquire_at(&state, GROUP, 4));
}

// ---- moving many leases ----

fn many_leases(count: usize) -> Vec<CustodyLease> {
    let state = state();
    let repo = state.replica_coordinator.remote_custody_lease_repository();
    (0..count)
        .map(|n| {
            repo.acquire(&lease_for(GROUP, &format!("r{n}"), &format!("f{n}.bin"), 1))
                .unwrap()
                .lease()
                .cloned()
                .unwrap()
        })
        .collect()
}

/// Counts how many movers run at once.
#[derive(Default)]
struct Concurrency {
    now: std::sync::atomic::AtomicUsize,
    max: std::sync::atomic::AtomicUsize,
}

impl Concurrency {
    async fn run(&self, ok: bool) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        let now = self.now.fetch_add(1, SeqCst) + 1;
        self.max.fetch_max(now, SeqCst);
        tokio::time::sleep(Duration::from_millis(20)).await;
        self.now.fetch_sub(1, SeqCst);
        ok
    }
    fn max(&self) -> usize {
        self.max.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Independent leases move at the same time, but never more than the cap, so
/// the handoff costs about one round trip per cap leases and not one per lease.
#[tokio::test]
async fn independent_leases_move_in_parallel_up_to_a_fixed_cap() {
    let leases = many_leases(40);
    let seen = Concurrency::default();

    let moved = move_all(&leases, |_| seen.run(true)).await;

    assert!(moved.iter().all(|m| *m));
    assert!(seen.max() > 1, "leases moved one at a time");
    assert!(seen.max() <= MOVE_PARALLELISM, "{} at once", seen.max());
}

/// A lease that cannot move is reported as stuck at its own position and does
/// not stop the others; none is reported moved on another's account.
#[tokio::test]
async fn a_lease_that_cannot_move_does_not_stop_or_pass_for_the_others() {
    let leases = many_leases(25);
    let seen = Concurrency::default();
    let stuck: HashSet<&str> = ["r3", "r17"].into();

    let moved =
        move_all(&leases, |lease| seen.run(!stuck.contains(lease.requester_device_id.as_str())))
            .await;

    for (lease, moved) in leases.iter().zip(&moved) {
        assert_eq!(*moved, !stuck.contains(lease.requester_device_id.as_str()), "{lease:?}");
    }
}

/// Leases of the same requester and path share that device's path lock while
/// it rehomes them, so they move one after another; others do not wait.
#[tokio::test]
async fn leases_of_one_path_of_one_requester_move_one_at_a_time() {
    let mut leases = many_leases(6);
    for lease in &mut leases {
        lease.requester_device_id = "same".into();
        lease.path = "same.bin".into();
    }
    let seen = Concurrency::default();

    move_all(&leases, |_| seen.run(true)).await;

    assert_eq!(seen.max(), 1);
}

/// `count` leases for `count / 4` requesters, one of every four requesters
/// offline: every lease is attempted once (one round trip each, at most the
/// cap at once), exactly the offline requesters' leases are stuck, and the
/// whole result is the same at any size.
async fn handoff_probe(count: usize) {
    let state = state();
    let repo = state.replica_coordinator.remote_custody_lease_repository();
    let leases: Vec<CustodyLease> = (0..count)
        .map(|n| {
            repo.acquire(&lease_for(
                GROUP,
                &format!("r{}", n % (count / 4)),
                &format!("f{n}.bin"),
                1,
            ))
            .unwrap()
            .lease()
            .cloned()
            .unwrap()
        })
        .collect();
    let seen = Concurrency::default();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let offline = |lease: &CustodyLease| {
        lease.requester_device_id.trim_start_matches('r').parse::<usize>().unwrap() % 4 == 0
    };

    let moved = move_all(&leases, |lease| {
        calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        seen.run(!offline(lease))
    })
    .await;

    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), count);
    assert!(seen.max() <= MOVE_PARALLELISM);
    for (lease, moved) in leases.iter().zip(moved) {
        assert_eq!(moved, !offline(lease));
    }
}

#[tokio::test(start_paused = true)]
async fn handoff_probe_100_leases() {
    handoff_probe(100).await;
}

#[tokio::test(start_paused = true)]
async fn handoff_probe_1000_leases() {
    handoff_probe(1_000).await;
}

#[tokio::test(start_paused = true)]
#[ignore = "large tier; run on request"]
async fn handoff_probe_10000_leases() {
    handoff_probe(10_000).await;
}

/// With some leases moved and some stuck, the refusal counts the stuck ones
/// (not every lease held) and names each requester once.
#[tokio::test]
async fn the_refusal_counts_the_stuck_leases_not_all_of_them() {
    let leases = many_leases(100);
    let stuck_requesters: HashSet<&str> = ["r3", "r17"].into();
    let moved = move_all(&leases, |lease| {
        std::future::ready(!stuck_requesters.contains(lease.requester_device_id.as_str()))
    })
    .await;
    let stuck: Vec<&str> = leases
        .iter()
        .zip(moved)
        .filter(|(_, moved)| !moved)
        .map(|(lease, _)| lease.requester_device_id.as_str())
        .collect();

    let message = stuck_refusal(stuck);

    assert!(message.starts_with("2 kept version(s)"), "{message}");
    assert!(message.contains("(r17, r3)"), "{message}");
}

/// Why the handoff is bounded-parallel rather than serial. The removal ticket
/// is requested by another device over a service RPC that gives up after 30 s,
/// and a lease moves in about two round trips plus the new holder's proof. At a
/// plausible 250 ms per lease the serial loop passes that deadline at 120
/// leases; the capped one is still inside it there and at several times that.
/// (Past roughly 900 leases the deadline is passed either way; that is a limit
/// of one synchronous ticket request, not of the loop.) Virtual time, so the
/// numbers are the model's, not this machine's.
#[tokio::test(start_paused = true)]
async fn a_serial_handoff_outlasts_the_ticket_deadline_where_the_capped_one_does_not() {
    let rpc_deadline = Duration::from_secs(30);
    let per_lease = Duration::from_millis(250);
    let sleep_ok = |_: &CustodyLease| async move {
        tokio::time::sleep(per_lease).await;
        true
    };
    for (count, serial_fits) in [(100usize, true), (120, false), (800, false)] {
        let leases = many_leases(count);

        let started = tokio::time::Instant::now();
        for lease in &leases {
            sleep_ok(lease).await;
        }
        let serial = started.elapsed();

        let started = tokio::time::Instant::now();
        move_all(&leases, sleep_ok).await;
        let capped = started.elapsed();

        eprintln!("{count} leases at {per_lease:?}: serial {serial:?}, capped {capped:?}");
        assert_eq!(serial < rpc_deadline, serial_fits, "{count}");
        assert!(capped < rpc_deadline, "{count}: {capped:?}");
    }
}
