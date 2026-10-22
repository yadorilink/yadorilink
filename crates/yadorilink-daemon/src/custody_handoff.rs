//! Responder-side custody leases when membership changes.
//!
//! A full replica that holds custody leases for other devices (see
//! [`yadorilink_sync_sqlite::remote_custody_lease`]) may not stop being a full
//! replica of the group while a requester still depends on one: the requester
//! has already dropped its own copy of that version. Role loss therefore
//! first hands every lease off, and refuses (so the operation can be retried)
//! when one cannot move.
//!
//! The handoff reuses the requester's own custody machinery rather than a
//! second protocol. The responder tells the requester to move; the requester
//! takes custody at another full replica through its ordinary
//! record-then-acquire path, releases the responder's lease, and answers. A
//! lease therefore never exists at a peer its requester has no hold row for.
//!
//! What a membership change does to a lease that is *not* being handed off:
//!
//! - the requester leaves the group (or is removed): its leases and the
//!   release tombstones kept for it are dropped when a full netmap snapshot
//!   no longer lists it for the group, and it is barred from acquiring until
//!   a snapshot lists it again. It cannot reach this device to release them,
//!   and nothing else here depends on them.
//! - this device stops being the group's full replica: nothing is dropped. A
//!   lease is another device's only copy of a version, so it ends only when
//!   its requester releases it or leaves the group; a forced operation that
//!   could not hand it off leaves it pinned (and the requester's stamp stops
//!   validating, so it reclaims nothing on the strength of it).
//! - the membership generation moving does nothing to a lease. It counts every
//!   netmap change, so it says nothing about whether a lease is still owed;
//!   the responder records the generation an attempt was made under and never
//!   compares it, and standing is judged from the group state itself.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::remote_custody_lease::CustodyLease;
use yadorilink_sync_sqlite::{RemoteCustodyLeaseRepository, SyncSqliteError};

use crate::daemon_state::{DaemonState, VERSION_PRESENT_QUERY_OVERALL_TIMEOUT};
use crate::replica_coordinator::ReplicaCoordinator;

/// How much longer than the handoff lease's own lifetime a removal ticket keeps
/// the group closed: delivery and processing of the grant, and the commit that
/// lands in the lease's last moments.
pub(crate) const TICKET_CLOSE_MARGIN: Duration = Duration::from_secs(60);

/// How long a group stays closed after a ticket whose handoff lease lives
/// `ttl_seconds` was granted, counted from the grant's arrival (the lease was
/// created before it arrived, so its end is no later than that plus the
/// lifetime). A duration, never an expiry compared with this device's clock:
/// the coordination plane's clock and this one need not agree.
pub(crate) fn ticket_close_for(ttl_seconds: i64) -> Duration {
    let ttl = Duration::from_secs(u64::try_from(ttl_seconds).unwrap_or(0));
    ttl.saturating_add(TICKET_CLOSE_MARGIN)
}

/// A removal ticket's close is durable. The ticket is usable by another device
/// at any later moment, so the close that makes it safe (no lease commits after
/// the leases were listed and moved) must outlive this process. The record is
/// written before the ticket leaves this device and ended only by the ticket's
/// release. It stores the close's *length*, never an expiry compared with a
/// clock: a restart counts the full length again from startup, which can only
/// close the group for longer than the ticket lives, never for less. A close
/// that has not become a ticket's is owned by the operation that made it and
/// nothing outside depends on it, so it is not recorded.
///
/// Identifies one close, so its owner reopens exactly that and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CloseKey(u64);

#[derive(Default)]
struct ClosingState {
    next_key: u64,
    /// Every close: the group, and when it ends (`None`: when its owner
    /// reopens it).
    closes: HashMap<u64, (String, Option<Instant>)>,
    /// The close each granted removal ticket holds, by (group, lease id).
    tickets: HashMap<(String, String), CloseKey>,
    /// (group, requester) pairs the plane has removed and not listed again.
    barred: HashSet<(String, String)>,
}

/// The groups this device is handing its leases off in and the requesters it
/// has just lost, with the barrier that makes "no lease commits after this
/// listed the leases" exact.
#[derive(Default)]
pub(crate) struct CustodyClosing {
    state: RwLock<ClosingState>,
    /// Where ticket closes are kept (`None`: nowhere, for unit tests).
    durable: Option<RemoteCustodyLeaseRepository>,
}

impl CustodyClosing {
    /// The closes the recorded tickets still hold, each for its full length
    /// counted from now. Built before any service request is admitted.
    pub(crate) fn open(durable: RemoteCustodyLeaseRepository) -> Result<Self, SyncSqliteError> {
        let now = Instant::now();
        let mut state = ClosingState::default();
        for (group, lease_id, close_secs) in durable.ticket_closes()? {
            let deadline = close_secs.and_then(|secs| now.checked_add(Duration::from_secs(secs)));
            let key = state.next_key;
            state.next_key += 1;
            state.closes.insert(key, (group.clone(), deadline));
            state.tickets.insert((group, lease_id), CloseKey(key));
        }
        Ok(Self { state: RwLock::new(state), durable: Some(durable) })
    }

    /// Runs `commit` (an acquire) only while the group is open to the
    /// requester. It holds the read side for the whole commit, so a close or a
    /// bar, which take the write side, return only after every acquire that
    /// was admitted has committed; every later one is refused.
    pub(crate) fn while_open<T>(
        &self,
        group_id: &str,
        requester_device_id: &str,
        commit: impl FnOnce() -> T,
    ) -> Option<T> {
        self.sweep_expired(group_id);
        let state = self.state.read().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let closed = state
            .closes
            .values()
            .any(|(group, until)| group == group_id && until.is_none_or(|end| now < end));
        let barred =
            state.barred.contains(&(group_id.to_string(), requester_device_id.to_string()));
        if closed || barred {
            return None;
        }
        Some(commit())
    }

    /// Ends each ticket close of `group_id` observed to have run out: its record, then the
    /// close. Only that ticket's own record goes, never another's for the same
    /// group, and a close with no deadline never runs out. A record that
    /// cannot be deleted is kept with its close (a restart may close the group
    /// again, the safe side) and is tried on the next observation of that group (other groups never pay for it).
    fn sweep_expired(&self, group_id: &str) {
        let ran_out = |closes: &HashMap<u64, (String, Option<Instant>)>, key: &CloseKey| {
            let now = Instant::now();
            closes.get(&key.0).is_some_and(|(_, until)| until.is_some_and(|end| now >= end))
        };
        {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            if !state
                .tickets
                .iter()
                .any(|((group, _), key)| group == group_id && ran_out(&state.closes, key))
            {
                return;
            }
        }
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        let ClosingState { closes, tickets, .. } = &mut *state;
        tickets.retain(|(group, lease_id), key| {
            if group != group_id || !ran_out(closes, key) {
                return true;
            }
            if let Some(durable) = &self.durable {
                if let Err(error) = durable.end_ticket_close(group, lease_id) {
                    tracing::warn!(%error, group, lease_id, "could not end a run-out ticket close's record; keeping it");
                    return true;
                }
            }
            closes.remove(&key.0);
            false
        });
    }

    /// Closes the group until the returned key is reopened or `deadline`
    /// passes (`None`: until reopened).
    fn close(&self, group_id: &str, deadline: Option<Instant>) -> CloseKey {
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        state.closes.retain(|_, (_, until)| until.is_none_or(|end| now < end));
        let ClosingState { closes, tickets, .. } = &mut *state;
        tickets.retain(|(group, lease_id), key| {
            let live = closes.contains_key(&key.0);
            if !live {
                // Run out: its record goes too. One that cannot be deleted now
                // only re-closes the group for its length after a restart.
                self.end_record(group, lease_id);
            }
            live
        });
        let key = state.next_key;
        state.next_key += 1;
        state.closes.insert(key, (group_id.to_string(), deadline));
        CloseKey(key)
    }

    fn reopen(&self, key: CloseKey) {
        self.state.write().unwrap_or_else(|p| p.into_inner()).closes.remove(&key.0);
    }

    /// Turns the close `key` into the close a granted removal ticket holds: it
    /// ends at `deadline` (`None`: never on its own), or earlier when that
    /// ticket, named by its handoff lease, is released.
    ///
    /// The close is recorded before this returns; on `Err` it is still the
    /// operation's own close and no ticket may be handed out.
    fn hold_for_ticket(
        &self,
        key: CloseKey,
        close_for: Duration,
        lease_id: &str,
    ) -> Result<(), String> {
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        let Some((group, _)) = state.closes.get(&key.0) else {
            return Err("the group's close has already ended".to_string());
        };
        let group = group.clone();
        // A lifetime too long to represent is a close with no deadline: it
        // ends when the ticket is released.
        let deadline = Instant::now().checked_add(close_for);
        if let Some(durable) = &self.durable {
            // Rounded up: the record never closes for less than the ticket.
            let close_secs =
                deadline.map(|_| close_for.as_secs() + u64::from(close_for.subsec_nanos() > 0));
            durable
                .record_ticket_close(&group, lease_id, close_secs)
                .map_err(|error| format!("could not record the ticket's close: {error}"))?;
        }
        if let Some((_, until)) = state.closes.get_mut(&key.0) {
            *until = deadline;
        }
        state.tickets.insert((group, lease_id.to_string()), key);
        Ok(())
    }

    fn end_record(&self, group_id: &str, lease_id: &str) {
        if let Some(durable) = &self.durable {
            if let Err(error) = durable.end_ticket_close(group_id, lease_id) {
                tracing::warn!(%error, group_id, lease_id, "could not end a ticket's recorded close");
            }
        }
    }

    /// The ticket with this handoff lease was released (its removal was
    /// abandoned or is done): its close ends. Another ticket's does not.
    pub(crate) fn release_ticket(&self, group_id: &str, lease_id: &str) {
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        // The record goes first. When it cannot, the close stays (it still runs
        // out on its own) rather than reopening a group a restart would close
        // again.
        if let Some(durable) = &self.durable {
            if let Err(error) = durable.end_ticket_close(group_id, lease_id) {
                tracing::warn!(%error, group_id, lease_id, "could not end a ticket's recorded close; keeping it closed");
                return;
            }
        }
        if let Some(key) = state.tickets.remove(&(group_id.to_string(), lease_id.to_string())) {
            state.closes.remove(&key.0);
        }
    }

    /// Bars each (group, requester) from acquiring. Returns after every acquire
    /// admitted before it has committed.
    fn bar(&self, departed: &HashSet<(String, String)>) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .barred
            .extend(departed.iter().cloned());
    }

    /// Lifts the bar from every pair `listed` says the plane lists again.
    fn unbar_listed(&self, listed: impl Fn(&str, &str) -> bool) {
        self.state
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .barred
            .retain(|(group, requester)| !listed(group, requester));
    }

    #[cfg(test)]
    pub(crate) fn is_closed(&self, group_id: &str) -> bool {
        self.while_open(group_id, "", || ()).is_none()
    }

    #[cfg(test)]
    pub(crate) fn ticket_count(&self) -> usize {
        self.state.read().unwrap_or_else(|p| p.into_inner()).tickets.len()
    }

    #[cfg(test)]
    pub(crate) fn is_barred(&self, group_id: &str, requester: &str) -> bool {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .barred
            .contains(&(group_id.to_string(), requester.to_string()))
    }
}

/// Keeps a group closed to new leases until dropped.
pub struct ClosedGroup {
    coordinator: Arc<ReplicaCoordinator>,
    key: CloseKey,
    reopen_on_drop: bool,
}

impl ClosedGroup {
    /// Lets the close run out `close_for` from now, as the close the granted
    /// removal ticket for `lease_id` holds, instead of reopening the group
    /// when this guard goes away.
    ///
    /// The close is recorded durably first; if that fails the group reopens
    /// and the caller must not hand out the ticket.
    pub(crate) fn hold_for_ticket(
        mut self,
        close_for: Duration,
        lease_id: &str,
    ) -> Result<(), String> {
        self.coordinator.custody_closing().hold_for_ticket(self.key, close_for, lease_id)?;
        self.reopen_on_drop = false;
        Ok(())
    }
}

impl Drop for ClosedGroup {
    fn drop(&mut self) {
        if self.reopen_on_drop {
            self.coordinator.custody_closing().reopen(self.key);
        }
    }
}

/// How many leases are handed off at once. Each is a round trip to its
/// requester, which may in turn ask another full replica; a fixed small cap
/// keeps the handoff to about one round trip per this many leases without an
/// unbounded fan-out of requests.
pub(crate) const MOVE_PARALLELISM: usize = 8;

/// Runs `mover` for every lease and returns, in the leases' order, whether each
/// moved. Every lease is attempted: one that cannot move does not stop the rest,
/// and none is counted as moved unless its own mover said so. At most
/// [`MOVE_PARALLELISM`] run at once, and the leases one requester holds for one
/// path (which that device moves under that path's lock) run one after another.
async fn move_all<'a, F, Fut>(leases: &'a [CustodyLease], mover: F) -> Vec<bool>
where
    F: Fn(&'a CustodyLease) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    use futures_util::stream::{self, StreamExt};
    let mut chains: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    for (index, lease) in leases.iter().enumerate() {
        chains.entry((&lease.requester_device_id, &lease.path)).or_default().push(index);
    }
    let mover = &mover;
    let mut moved = vec![false; leases.len()];
    let mut results = stream::iter(chains.into_values())
        .map(|chain| async move {
            let mut done = Vec::with_capacity(chain.len());
            for index in chain {
                done.push((index, mover(&leases[index]).await));
            }
            done
        })
        .buffer_unordered(MOVE_PARALLELISM);
    while let Some(done) = results.next().await {
        for (index, ok) in done {
            moved[index] = ok;
        }
    }
    moved
}

/// The refusal naming the leases that could not move: how many (one per stuck
/// lease, not per lease held) and which requesters hold them.
fn stuck_refusal(mut stuck: Vec<&str>) -> String {
    let count = stuck.len();
    stuck.sort_unstable();
    stuck.dedup();
    format!(
        "{count} kept version(s) held for other devices ({}) could not be moved to another \
         complete copy: each is the only copy of a version that device has dropped. Bring those \
         devices and another complete copy online, then retry.",
        stuck.join(", ")
    )
}

impl DaemonState {
    /// Closes `group_id` to new leases and moves every lease it holds there to
    /// another full replica. `Ok` holds the group closed until the guard is
    /// dropped; `Err` (some lease could not move, nothing is closed any more)
    /// names how many are left, and the caller refuses the operation.
    pub async fn hand_off_custody_leases(&self, group_id: &str) -> Result<ClosedGroup, String> {
        self.close_and_move_leases(group_id).await
    }

    async fn close_and_move_leases(&self, group_id: &str) -> Result<ClosedGroup, String> {
        let key = self.replica_coordinator.custody_closing().close(group_id, None);
        let closed = ClosedGroup {
            coordinator: self.replica_coordinator.clone(),
            key,
            reopen_on_drop: true,
        };
        let leases = self
            .replica_coordinator
            .remote_custody_lease_repository()
            .list_active_for_group(group_id)
            .map_err(|error| format!("could not list custody leases: {error}"))?;
        let moved = move_all(&leases, |lease| self.move_custody_lease(lease)).await;
        let stuck: Vec<&str> = leases
            .iter()
            .zip(moved)
            .filter(|(_, moved)| !moved)
            .map(|(lease, _)| lease.requester_device_id.as_str())
            .collect();
        if stuck.is_empty() {
            return Ok(closed);
        }
        Err(stuck_refusal(stuck))
    }

    /// Asks the lease's requester to take custody elsewhere and release this
    /// device's lease. `true` once the lease is gone.
    async fn move_custody_lease(&self, lease: &CustodyLease) -> bool {
        let Some(session) = self.peers.session(&lease.requester_device_id) else {
            return false;
        };
        let moved = tokio::time::timeout(
            VERSION_PRESENT_QUERY_OVERALL_TIMEOUT * 3,
            session.request_custody_rehome(
                &lease.group_id,
                &lease.path,
                VersionHash(lease.version_hash),
                lease.attempt_token,
            ),
        )
        .await
        .unwrap_or(false);
        if !moved {
            return false;
        }
        // The requester no longer depends on the lease. Its own release has
        // normally ended it already; ending it here as well is idempotent and
        // covers a release whose acknowledgement was lost.
        self.replica_coordinator
            .remote_custody_lease_repository()
            .release(
                &lease.group_id,
                &lease.requester_device_id,
                &lease.path,
                &lease.version_hash,
                &lease.attempt_token,
            )
            .map_err(|error| tracing::warn!(%error, "could not end a moved custody lease"))
            .is_ok()
    }

    /// Drops the leases (and release tombstones) of every requester a full
    /// netmap snapshot no longer lists for a group, and bars each from
    /// acquiring there until a snapshot lists it again. `removed_by_frame` is
    /// every (device, group) edge the previous snapshot had and this one lacks
    /// (so a requester that never held anything here is barred too, against
    /// an acquire already in flight); `current` is this snapshot. A requester
    /// this device keeps leases or tombstones for and `current` does not list
    /// for the group is dropped as well, so a removal that happened while this
    /// daemon was down is found.
    ///
    /// Acts only when `may_withdraw` says the snapshot may act on what it does
    /// not list (the run's first frame can be an older replay than the
    /// persisted authorization): deleting a lease is not undone by a later
    /// frame, so a frame that cannot be ranked changes nothing here, narrowing
    /// or not.
    pub(crate) fn drop_custody_leases_of_departed_requesters(
        &self,
        removed_by_frame: &[(String, String)],
        current: &HashMap<String, HashSet<String>>,
        may_withdraw: bool,
    ) -> usize {
        if !may_withdraw {
            return 0;
        }
        let leases = self.replica_coordinator.remote_custody_lease_repository();
        let known = match leases.requesters_with_state() {
            Ok(known) => known,
            Err(error) => {
                tracing::warn!(%error, "could not list the requesters custody leases are kept for");
                return 0;
            }
        };
        let lists = |group: &str, requester: &str| {
            current.get(requester).is_some_and(|groups| groups.contains(group))
        };
        let departed: HashSet<(String, String)> = removed_by_frame
            .iter()
            .map(|(device, group)| (group.clone(), device.clone()))
            .chain(known)
            .filter(|(group, requester)| !lists(group, requester))
            .collect();
        let closing = self.replica_coordinator.custody_closing();
        closing.bar(&departed);
        closing.unbar_listed(lists);
        let mut dropped = 0;
        for (group_id, requester) in &departed {
            match leases.forget_requester(group_id, requester) {
                Ok(count) => {
                    if count > 0 {
                        tracing::info!(
                            group_id,
                            requester,
                            count,
                            "requester left the group; dropped its custody leases"
                        );
                    }
                    dropped += count;
                }
                Err(error) => {
                    tracing::warn!(%error, group_id, requester, "could not drop a departed requester's custody leases");
                }
            }
        }
        dropped
    }
}

#[cfg(test)]
mod tests;
