//! Availability: can the exact content a folder needs be fetched right now.
//!
//! One of two independent product dimensions (the other is [`crate::protection`]). It says
//! nothing about whether the data would survive losing this device, and "unavailable" is a
//! property of this dimension only.
//!
//! Aggregation (a folder set is as available as its least available part, the first match wins):
//!
//! 1. `UpdateRequired`: a device holding the content is online but runs another protocol version,
//!    and no compatible device can serve it; only an update settles it
//! 2. `WaitingForExactContent`: devices are reachable but none is known to hold the exact version
//! 3. `WaitingForPeer`: a device holding the content is offline; it resolves when it returns
//! 4. `Unknown`: not enough evidence either way
//! 5. `Available`
//!
//! `Available` is therefore reported only when every part is provably available. An empty set of
//! folders needs nothing, so it is `Available`.
//!
//! Serialization contract: [`Availability::as_str`] names are stable snake_case and are what
//! `status --json` prints; the wire enum is `ProductAvailability`, where an unset value is
//! `Unknown`.

use std::collections::BTreeSet;

use yadorilink_ipc_proto::daemonctl::{LinkStatus, ProductAvailability};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Available,
    UpdateRequired,
    WaitingForPeer,
    WaitingForExactContent,
    Unknown,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::UpdateRequired => "update_required",
            Availability::WaitingForPeer => "waiting_for_peer",
            Availability::WaitingForExactContent => "waiting_for_exact_content",
            Availability::Unknown => "unknown",
        }
    }

    pub fn from_wire(wire: ProductAvailability) -> Self {
        match wire {
            ProductAvailability::Available => Availability::Available,
            ProductAvailability::UpdateRequired => Availability::UpdateRequired,
            ProductAvailability::WaitingForPeer => Availability::WaitingForPeer,
            ProductAvailability::WaitingForExactContent => Availability::WaitingForExactContent,
            ProductAvailability::Unknown | ProductAvailability::Unspecified => {
                Availability::Unknown
            }
        }
    }

    pub fn to_wire(self) -> ProductAvailability {
        match self {
            Availability::Available => ProductAvailability::Available,
            Availability::UpdateRequired => ProductAvailability::UpdateRequired,
            Availability::WaitingForPeer => ProductAvailability::WaitingForPeer,
            Availability::WaitingForExactContent => ProductAvailability::WaitingForExactContent,
            Availability::Unknown => ProductAvailability::Unknown,
        }
    }

    /// Higher rank wins an aggregation (see the module doc).
    fn rank(self) -> u8 {
        match self {
            Availability::UpdateRequired => 4,
            Availability::WaitingForExactContent => 3,
            Availability::WaitingForPeer => 2,
            Availability::Unknown => 1,
            Availability::Available => 0,
        }
    }
}

/// The availability state with the devices it concerns. Device ids are the other devices
/// recorded as full copies of the folder, sorted without duplicates; a shell resolves them to
/// display names and never shows the ids. A device is in exactly one of the three lists:
/// reachable (online, compatible), offline, or needing an update (online, another version).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailabilitySummary {
    pub availability: Availability,
    pub reachable_device_ids: Vec<String>,
    pub offline_device_ids: Vec<String>,
    pub update_required_device_ids: Vec<String>,
}

impl AvailabilitySummary {
    /// Read from the daemon's per-link fields; an older daemon's unset fields read `Unknown`.
    pub fn from_link(link: &LinkStatus) -> Self {
        AvailabilitySummary {
            availability: Availability::from_wire(link.availability()),
            reachable_device_ids: link.availability_reachable_device_ids.clone(),
            offline_device_ids: link.availability_offline_device_ids.clone(),
            update_required_device_ids: link.availability_update_required_device_ids.clone(),
        }
    }

    /// The least available of `parts`, with the union of their devices (see the module doc). A
    /// device offline for one folder is not counted reachable for another.
    pub fn aggregate(parts: &[AvailabilitySummary]) -> Self {
        let availability = parts
            .iter()
            .map(|p| p.availability)
            .fold(Availability::Available, |a, b| if b.rank() > a.rank() { b } else { a });
        let offline: BTreeSet<&String> = parts.iter().flat_map(|p| &p.offline_device_ids).collect();
        let update_required: BTreeSet<&String> =
            parts.iter().flat_map(|p| &p.update_required_device_ids).collect();
        let reachable: BTreeSet<&String> = parts
            .iter()
            .flat_map(|p| &p.reachable_device_ids)
            .filter(|id| !offline.contains(id) && !update_required.contains(id))
            .collect();
        AvailabilitySummary {
            availability,
            reachable_device_ids: reachable.into_iter().cloned().collect(),
            offline_device_ids: offline.into_iter().cloned().collect(),
            update_required_device_ids: update_required.into_iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests;
