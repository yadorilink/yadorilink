//! Which files capture only hashes, and which it copies into the block store.
//!
//! A device that can serve a block from the user's own file (`file_block_source`) does not need a
//! store copy of every version it captures: for a large file, writing it into the store is most
//! of the time before its first byte can be announced. Capture then only hashes the file
//! ([`Ingest::FileOnly`]). The store copy is kept where it is needed:
//!
//! - an item the user pinned ("always keep on this device") or that a custody lease names, because
//!   their versions have to be there when the file has moved on;
//! - a small file, whose copy costs less than the flush that replaces it.
//!
//! [`must_keep_in_store`] is the one statement of the first rule.

use std::sync::Arc;

use yadorilink_local_capture::{AlwaysIngest, Ingest, IngestPolicy};

use crate::replica_coordinator::ReplicaCoordinator;

/// A file smaller than this is copied into the store even when the mode is on: its copy is a few
/// blocks that share the scan's group commits, and a flush per small file would cost more than the
/// copy it saves.
pub(crate) const FILE_ONLY_MIN_SIZE: u64 = 4 * 1024 * 1024;

/// How long a request for store-mode captures lasts if nothing ends it first. A lease request
/// that found a file changing asks for the group's next captures to go into the store and is
/// retried by its caller; this bounds how long the request outlives a caller that never comes back.
pub(crate) const STORE_MODE_REQUEST_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Groups whose captures are asked to put their blocks into the store, by the requests that hold
/// them and until a deadline. In memory only: a restart forgets it, and the next request asks again.
///
/// Counted, not a flag: two lease requests for a group overlap, and the first to finish must not
/// end the store mode the second still depends on. A request that leaves work pending does not
/// release; the deadline ends it.
///
/// An entry is a generation. One that outlives its deadline is over, holders and all, and the next
/// request starts a new generation; a hold taken against the old one releases nothing of the new
/// one when it is finally dropped.
#[derive(Default)]
pub(crate) struct StoreModeRequests {
    state: std::sync::Mutex<RequestState>,
}

#[derive(Default)]
struct RequestState {
    next_generation: u64,
    groups: std::collections::HashMap<String, Held>,
}

struct Held {
    generation: u64,
    holders: u32,
    until: std::time::Instant,
}

impl StoreModeRequests {
    /// Asks for `group_id`'s captures to go into the store until `ttl` from now (a later request
    /// extends the deadline, never shortens it) and counts the caller as a holder. The hold is
    /// released when it is dropped, so a request that returns early, fails or is cancelled while
    /// it waits does not keep the group in store mode; [`StoreModeHold::leave_to_expire`] leaves
    /// the request to its deadline instead.
    pub(crate) fn hold(&self, group_id: &str, ttl: std::time::Duration) -> StoreModeHold<'_> {
        let now = std::time::Instant::now();
        let until = now + ttl;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let live = state.groups.get(group_id).is_some_and(|held| held.until > now);
        if !live {
            state.next_generation += 1;
            let generation = state.next_generation;
            state.groups.insert(group_id.to_owned(), Held { generation, holders: 0, until });
        }
        let held = state.groups.get_mut(group_id).expect("just inserted or live");
        held.holders += 1;
        held.until = held.until.max(until);
        let generation = held.generation;
        drop(state);
        StoreModeHold { requests: self, group_id: group_id.to_owned(), generation, armed: true }
    }

    /// One holder of generation `generation` is done. The request ends when the last holder is
    /// done. A holder of a generation that has since ended or been replaced changes nothing.
    fn release(&self, group_id: &str, generation: u64) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(held) = state.groups.get_mut(group_id) else { return };
        if held.generation != generation {
            return;
        }
        held.holders = held.holders.saturating_sub(1);
        if held.holders == 0 {
            state.groups.remove(group_id);
        }
    }

    /// Whether `group_id` is asked to store now. An expired request is forgotten here.
    pub(crate) fn requested(&self, group_id: &str) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match state.groups.get(group_id) {
            Some(held) if held.until > std::time::Instant::now() => true,
            Some(_) => {
                state.groups.remove(group_id);
                false
            }
            None => false,
        }
    }
}

/// One holder of a store-mode request: released when dropped.
pub(crate) struct StoreModeHold<'a> {
    requests: &'a StoreModeRequests,
    group_id: String,
    generation: u64,
    armed: bool,
}

impl StoreModeHold<'_> {
    /// Leaves the request in force until its deadline: for a request that has work pending, which
    /// the group's captures must still do in store mode after the caller has gone.
    pub(crate) fn leave_to_expire(mut self) {
        self.armed = false;
    }
}

impl Drop for StoreModeHold<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.requests.release(&self.group_id, self.generation);
        }
    }
}

/// What has to be in the block store for one group, read once: whether the group has been asked to
/// store, which items are pinned, and which paths a custody lease names. A pass over many paths asks
/// the database once and tests each path in memory. A question that cannot be answered counts as
/// yes for every path.
pub(crate) struct KeepInStore {
    everything: bool,
    pinned: Vec<String>,
    leased: std::collections::HashSet<String>,
}

impl KeepInStore {
    pub(crate) fn for_group(coordinator: &ReplicaCoordinator, group_id: &str) -> Self {
        let everything = |_| Self {
            everything: true,
            pinned: Vec::new(),
            leased: std::collections::HashSet::new(),
        };
        if coordinator.store_mode_requests().requested(group_id) {
            return everything(());
        }
        let Ok(pinned) = coordinator.pinned_item_repository().list(group_id) else {
            return everything(());
        };
        let now_unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs() as i64)
            .unwrap_or(0);
        let Ok(leased) = coordinator
            .handoff_lease_repository()
            .leased_version_keys_for_group(group_id, now_unix_seconds)
        else {
            return everything(());
        };
        Self {
            everything: false,
            pinned,
            leased: leased.into_iter().map(|(leased_path, _)| leased_path).collect(),
        }
    }

    /// Whether the versions of `path` have to be in the block store: the item is pinned (itself, or
    /// by a folder above), a custody lease names it, or the group has been asked to store.
    pub(crate) fn keeps(&self, path: &str) -> bool {
        self.everything
            || crate::ingest_policy::path_is_pinned(&self.pinned, path)
            || self.leased.contains(path)
    }
}

fn path_is_pinned(pinned: &[String], path: &str) -> bool {
    yadorilink_sync_sqlite::pinned_items::path_is_covered(pinned, path)
}

/// Whether the versions of `path` have to be in the block store: the item is pinned, a custody
/// lease names it, or the group has been asked to store for a while. A question that cannot be
/// answered counts as yes.
pub(crate) fn must_keep_in_store(
    coordinator: &ReplicaCoordinator,
    group_id: &str,
    path: &str,
) -> bool {
    KeepInStore::for_group(coordinator, group_id).keeps(path)
}

/// Capture only hashes a file that is large enough, not pinned and not leased.
struct FileFirstIngest {
    coordinator: Arc<ReplicaCoordinator>,
}

impl IngestPolicy for FileFirstIngest {
    fn ingest_for(&self, group_id: &str, path: &str, size: u64) -> Ingest {
        if size < FILE_ONLY_MIN_SIZE || must_keep_in_store(&self.coordinator, group_id, path) {
            Ingest::Store
        } else {
            Ingest::FileOnly
        }
    }
}

/// The policy of a device: every file goes into the store unless serving from files is on.
pub(crate) fn ingest_policy_for(coordinator: &Arc<ReplicaCoordinator>) -> Arc<dyn IngestPolicy> {
    if coordinator.tuning().file_block_source {
        Arc::new(FileFirstIngest { coordinator: coordinator.clone() })
    } else {
        Arc::new(AlwaysIngest)
    }
}

#[cfg(test)]
mod tests;
