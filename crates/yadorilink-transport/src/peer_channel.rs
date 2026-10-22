//! Netmap diffing: how a device works out what a coordination-plane netmap
//! update revoked.

use std::collections::{HashMap, HashSet};

// The coordination plane's netmap subscription always pushes a *full*
// netmap snapshot, never a delta. So the client side
// (`yadorilink-daemon`'s `peer_orchestrator`) is the one that must
// diff each new snapshot against whatever it held before, to find what
// was revoked. This module owns that pure diff logic; `peer_orchestrator`
// owns holding the "previous" snapshot across updates and acting on the
// result.

/// One netmap snapshot, keyed by `device_id` (stable across calls per
/// device — the coordination plane's device registration only ever
/// inserts a fresh device or marks one removed, never rotates a key under an
/// existing `device_id`) mapping to the set of folder groups this device
/// and the peer currently share.
///
/// A `HashSet`, not a `Vec`, deliberately: the coordination plane does not
/// guarantee a stable order for a peer's `shared_group_ids`, so the same
/// peer's group list can
/// legitimately come back in a different order across two consecutive
/// calls with no group actually added or removed. Diffing by position
/// would misclassify a reorder as a group being both removed and added.
pub type NetmapSnapshot = HashMap<String, HashSet<String>>;

/// The result of [`diff_netmap`]: what disappeared between two netmap
/// snapshots, split by blast-radius: a whole device losing all shared
/// groups versus one shared group among several being revoked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetmapDiff {
    /// Device ids present in `previous` but entirely absent from
    /// `current` — no authorized group remains between the local device
    /// and this peer (whole-device revocation, e.g. `device remove`, or a
    /// `share revoke` that was this pair's only shared group). Since
    /// `compute_netmap` only ever lists a peer it shares at least one
    /// group with (a peer with zero shared groups is omitted entirely,
    /// never present with an empty group set), a device's disappearance
    /// from the snapshot *is* the signal — the peer is torn down entirely
    /// for each of these.
    pub removed_devices: Vec<String>,
    pub removed_group_edges: Vec<(String, String)>,
}

/// Diffs `current` against `previous`, classifying every
/// device that lost at least one shared group as either a whole-device
/// removal ([`NetmapDiff::removed_devices`]) or a narrower group-edge
/// removal ([`NetmapDiff::removed_group_edges`]). Devices present in
/// `current` but not `previous` (newly authorized) and groups unchanged
/// between the two snapshots produce no diff entries — this function
/// only ever reports *removals*. Output order is sorted for
/// deterministic logging/testing (`HashMap`/`HashSet` iteration order is
/// not stable).
pub fn diff_netmap(previous: &NetmapSnapshot, current: &NetmapSnapshot) -> NetmapDiff {
    let mut removed_devices = Vec::new();
    let mut removed_group_edges = Vec::new();

    for (device_id, previous_groups) in previous {
        match current.get(device_id) {
            None => removed_devices.push(device_id.clone()),
            Some(current_groups) => {
                for group_id in previous_groups {
                    if !current_groups.contains(group_id) {
                        removed_group_edges.push((device_id.clone(), group_id.clone()));
                    }
                }
            }
        }
    }

    removed_devices.sort();
    removed_group_edges.sort();
    NetmapDiff { removed_devices, removed_group_edges }
}

#[cfg(test)]
mod tests;
