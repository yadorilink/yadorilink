//! `DeviceSummary` and the cross-group member-list merge (`device_summaries`)
//! — sourced from the coordination plane's per-group member
//! listing (`GET /shares/groups/{id}/members`), never from the account's
//! device registry (`GET /devices` lacks `last_seen` and group scope).
//!
//! Everything here is pure, like `folder.rs`. There is no single "list every
//! device on my account" daemon or coordination-plane call, because
//! membership is inherently per-group, so a cross-folder view needs one
//! member-list fetch per distinct `group_id`. That fetch is the caller's:
//! `distinct_group_ids` names which groups to fetch, the caller fetches each
//! one through its coordination-plane client and projects every member into
//! a `DeviceSummary`, and `device_summaries`/`peer_count`/`peer_counts` derive
//! the view from the results. This crate therefore holds no credential, no
//! HTTP client and no local device identity of its own.

use std::collections::{HashMap, HashSet};

use yadorilink_ipc_proto::daemonctl::LinkStatus;

/// One device known to the coordination plane, coarse enough to be product
/// state (not diagnostics): who it is, a display name, and the coarse
/// online/last-seen signal the coordination plane itself reports — never a
/// live `PeerStatus.reachability` read.
#[derive(Clone, Debug, PartialEq)]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub online: bool,
    pub last_seen_unix: i64,
    /// Whether the device is on the same account as the caller.
    pub is_caller_account: bool,
}

/// The distinct folder groups behind `links`, in first-seen order — the
/// member lists a caller must fetch, exactly once each, to feed
/// `device_summaries`/`peer_counts`, so a caller rendering many folders'
/// worth of `FolderSummary` rows never pays for the same group's member
/// listing twice (the design doc's own "Open dependencies" note: a Home
/// window rendering many folders should cache/batch this rather than firing
/// it per-row).
///
/// Folders sharing a group (the `ambiguous` case) or simply repeated entries
/// never double up the network call, and a link with no `group_id` names no
/// group at all.
pub fn distinct_group_ids(links: &[LinkStatus]) -> Vec<String> {
    let mut seen_groups = HashSet::new();
    let mut out = Vec::new();
    for link in links {
        if link.group_id.is_empty() || !seen_groups.insert(link.group_id.clone()) {
            continue;
        }
        out.push(link.group_id.clone());
    }
    out
}

/// The devices that hold a full copy of at least one linked folder, as the daemon declares them.
pub fn full_replica_holders(links: &[LinkStatus]) -> HashSet<String> {
    links.iter().flat_map(|l| l.full_replica_device_ids.iter().cloned()).collect()
}

/// Whether the device is one the person can administer from here: another device of this account
/// (not of someone a folder is shared with) that holds a full copy of a folder. No device
/// profile is published, so a full-copy holder is the nearest thing known to a NAS. This is an
/// affordance only; the administration service authorizes every request itself.
pub fn can_manage_device(
    device_id: &str,
    is_this_device: bool,
    is_caller_account: bool,
    full_copy_holders: &HashSet<String>,
) -> bool {
    !is_this_device && is_caller_account && full_copy_holders.contains(device_id)
}

/// Every device with access to any of the fetched folder groups, merged
/// across groups and keyed by `device_id` — a device that belongs to more
/// than one shared group appears once, with `online = true` if any group's
/// entry reports it online and `last_seen_unix` the max across entries
/// (there is no single
/// account-wide device roster, only a per-group member list, so a
/// cross-folder Devices view has to build its own union). Sorted by
/// `device_id`.
pub fn device_summaries<'a>(
    memberships: impl IntoIterator<Item = &'a [DeviceSummary]>,
) -> Vec<DeviceSummary> {
    let mut merged: HashMap<String, DeviceSummary> = HashMap::new();

    for members in memberships {
        for member in members {
            merged
                .entry(member.device_id.clone())
                .and_modify(|existing| {
                    existing.online = existing.online || member.online;
                    existing.is_caller_account =
                        existing.is_caller_account || member.is_caller_account;
                    if member.last_seen_unix > existing.last_seen_unix {
                        existing.last_seen_unix = member.last_seen_unix;
                    }
                })
                .or_insert_with(|| member.clone());
        }
    }

    let mut out: Vec<DeviceSummary> = merged.into_values().collect();
    out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    out
}

/// How many OTHER devices have access to one folder group — its member
/// count, minus this device itself. `own_device_id` is this device's local
/// identity when it has one; without it nothing is excluded, so the count
/// fails open to "everyone" rather than silently reading 0 for every group
/// just because identity couldn't be resolved.
pub fn peer_count(members: &[DeviceSummary], own_device_id: Option<&str>) -> usize {
    members.iter().filter(|m| Some(m.device_id.as_str()) != own_device_id).count()
}

/// The batched form of `peer_count`, for a Home window rendering every
/// linked folder at once from one member-list fetch per distinct group
/// (`distinct_group_ids`): every group's peer count keyed by `group_id`, so
/// a caller does one cheap map lookup per `FolderSummary` row instead of one
/// network round trip per row.
pub fn peer_counts<'a>(
    memberships: impl IntoIterator<Item = (&'a str, &'a [DeviceSummary])>,
    own_device_id: Option<&str>,
) -> HashMap<String, usize> {
    memberships
        .into_iter()
        .map(|(group_id, members)| (group_id.to_owned(), peer_count(members, own_device_id)))
        .collect()
}

#[cfg(test)]
mod tests;
