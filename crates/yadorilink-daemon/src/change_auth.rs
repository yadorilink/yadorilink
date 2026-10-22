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
            let ok = state.group_is_servable(group_id);
            validation_cache.lock().unwrap_or_else(|p| p.into_inner()).insert(group_id.clone(), ok);
            ok.then(|| group_id.clone())
        })
        .collect()
}

#[cfg(test)]
mod tests;
