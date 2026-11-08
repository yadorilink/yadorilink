//! The netmap-refresh-time filter that keeps a group whose policy has gone
//! stale (or was never introduced) from being announced to peers at all.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::daemon_state::DaemonState;

/// Filters `raw_groups` down to the groups this device's own verified
/// policy state currently considers servable -- a group whose policy
/// has gone stale (own verification failure, or coordinator-flagged
/// invalid) or has not loaded yet this run is withheld from peer
/// announcement entirely, rather than being served against a policy
/// snapshot this device can no longer vouch for.
///
/// `validation_cache` scopes this (cheap, but still a lock + map read
/// per group) result to one netmap-update pass's worth of calls, so a
/// group shared by many peers is resolved once, not once per peer
/// sharing it.
pub(crate) fn effective_servable_groups(
    state: Arc<DaemonState>,
    peer_device_id: &str,
    raw_groups: &HashSet<String>,
    validation_cache: &Mutex<HashMap<String, bool>>,
) -> HashSet<String> {
    raw_groups
        .iter()
        .filter_map(|group_id| {
            if let Some(cached_ok) =
                validation_cache.lock().unwrap_or_else(|p| p.into_inner()).get(group_id).copied()
            {
                return cached_ok.then(|| group_id.clone());
            }
            // Judged as if the peer holding this entry had no authorization yet: its own admission
            // is not evidence about the group.
            let ok = state.group_is_servable_ignoring_peer(group_id, peer_device_id);
            // Shared across the peers of one pass, so only an answer that does not depend on the
            // peer is kept: for a group with no verified policy the answer depends on which other
            // peers name it.
            if state.group_servability_is_peer_independent(group_id) {
                validation_cache
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(group_id.clone(), ok);
            }
            ok.then(|| group_id.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests;
