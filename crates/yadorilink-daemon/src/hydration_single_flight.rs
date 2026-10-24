//! Per-`(group_id, path)` single-flight coalescing for FETCH_DATA-driven
//! hydration: multiple concurrent FETCH_DATA calls for the same path must
//! single-flight, not each independently re-fetch.
//!
//! `hydration.rs`'s existing per-path lock (`PathLockRegistry`, held for
//! `hydrate_inner`'s ENTIRE attempt -- see that call site's own doc
//! comment for the race it closes) already makes two concurrent
//! `hydrate` calls for the same path SERIALIZE: the second attempt cannot
//! start its own peer fetch until the first's finishes. What it does NOT
//! do is COALESCE them -- the second attempt, once it acquires the lock,
//! runs its own full `hydrate_inner` from scratch (a second, fully
//! redundant peer block fetch for content the first attempt just
//! materialized). Two apps opening the same file at once (or a retried
//! FETCH_DATA callback racing the original) doubles peer network load and
//! doubles the block-serve credit consumed, for zero benefit.
//!
//! This registry sits layered OUTSIDE `hydrate_inner`'s locking, in
//! `hydrate_with_timeout`, and does not change that function's internals
//! or its lock's scope at all: at most one caller per `(group_id, path)`
//! ever becomes the "leader" and actually calls `hydrate_inner`; every
//! other concurrent caller becomes a "follower" that simply awaits the
//! leader's eventual result instead of running its own attempt. The
//! leader's own path lock is therefore now provably uncontended in the
//! coalesced case -- this registry does not replace it, defense-in-depth
//! for any caller that arrives in a NEW round (after the previous
//! leader's round has already finished and this registry's entry for
//! that path has been removed).

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::watch;

type Key = (String, String);

/// `Ok(materialized)` if the leader's `hydrate_inner` succeeded (`materialized`: it fetched
/// content from peers, rather than finding the file already here), `Err(())`
/// otherwise -- deliberately not `Result<(), SyncError>` (`SyncError` is
/// not `Clone`, and `watch`'s value type must be). A follower that
/// observes `Err(())` reconstructs a generic `SyncError::HydrationFailed`
/// for its own caller, exactly matching what `hydrate_with_timeout`
/// already does today when ITS OWN `tokio::time::timeout` elapses --
/// losing the leader's specific failure detail is the same acceptable
/// trade-off, not a new one this registry introduces.
type Outcome = Result<bool, ()>;

/// Folds `path` the same way [`crate::sync_runtime::path_locks::
/// PathLockRegistry`] folds its own lock key -- two paths that case-fold
/// or Unicode-normalize to the same logical name must coalesce onto the
/// SAME leader, for the identical reason that registry's own doc comment
/// gives for its lock key: an unfolded key would let two racing callers
/// for what is physically one file each become their own leader.
fn fold_key(path: &str) -> String {
    yadorilink_fs_platform::canonical_fold::canonical_fold(path)
}

/// One instance lives on [`crate::daemon_state::DaemonState`] -- per
/// daemon-instance state, matching `PathLockRegistry`'s own reasoning:
/// under the deterministic simulator, many in-process daemon instances
/// must never share this map, which a `static` would force.
#[derive(Default)]
pub struct HydrateSingleFlight {
    in_flight: Mutex<HashMap<Key, watch::Sender<Option<Outcome>>>>,
}

/// What [`HydrateSingleFlight::join`] returns: exactly one of these two
/// roles for any given `(group_id, path)` at a time.
pub enum Role<'a> {
    /// This caller is the only one in flight for this path right now --
    /// it must actually run the hydration attempt and call
    /// [`Leader::complete`] with its outcome.
    Leader(Leader<'a>),
    /// Another caller is already hydrating this exact path -- await this
    /// receiver instead of starting a redundant attempt.
    Follower(watch::Receiver<Option<Outcome>>),
}

pub struct Leader<'a> {
    registry: &'a HydrateSingleFlight,
    key: Key,
    tx: watch::Sender<Option<Outcome>>,
    outcome: Option<Outcome>,
}

impl Leader<'_> {
    /// Records this round's outcome and ends it: removes this path's
    /// entry (a caller arriving after this point starts a fresh round,
    /// never reusing a stale result) and broadcasts to every follower
    /// that subscribed while this round was in flight.
    pub fn complete(mut self, outcome: Outcome) {
        self.outcome = Some(outcome);
        // Falls through to `Drop::drop`, which does the actual
        // remove+broadcast -- see its own doc comment for why the SAME
        // path is used whether `complete` was called or not (a panic
        // unwinding through `hydrate_inner` must still release every
        // follower, not strand them awaiting a leader that is never
        // coming back).
    }
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        // A panic (or any other early-return the compiler doesn't force
        // `complete` to run for) must still release every follower --
        // never letting them hang forever awaiting a leader that already
        // unwound away is the entire point of this being `Drop`, not
        // merely a method `complete` calls at its own end. Defaults to
        // `Err(())`: "unknown, treat as failed" is fail-closed for a
        // follower, matching `hydrate_with_timeout`'s own timeout-elapsed
        // default.
        let outcome = self.outcome.take().unwrap_or(Err(()));
        {
            let mut map =
                self.registry.in_flight.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            map.remove(&self.key);
        }
        let _ = self.tx.send(Some(outcome));
    }
}

impl HydrateSingleFlight {
    pub fn new() -> Self {
        Self::default()
    }

    /// Joins the in-flight round for `(group_id, path)`, becoming its
    /// leader if none exists yet. The short registry lock is held only to
    /// look up/insert the map entry, matching `PathLockRegistry::
    /// path_lock`'s own reasoning -- never held across an `.await`.
    pub fn join(&self, group_id: &str, path: &str) -> Role<'_> {
        let key = (group_id.to_string(), fold_key(path));
        let mut map = self.in_flight.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(tx) = map.get(&key) {
            // Subscribing while the entry is still in the map guarantees
            // this receiver observes the eventual `send` in `Drop::drop`
            // above -- that removal and this subscribe are serialized by
            // the same `Mutex`, so there is no window where a leader could
            // finish and be removed between this check and the subscribe.
            return Role::Follower(tx.subscribe());
        }
        let (tx, _rx) = watch::channel(None);
        map.insert(key.clone(), tx.clone());
        Role::Leader(Leader { registry: self, key, tx, outcome: None })
    }
}

#[cfg(test)]
mod tests;
