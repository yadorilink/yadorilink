//! Derives the two product dimensions of a link (`LinkStatus.availability` and
//! `LinkStatus.protection`) from daemon truth already in the status message: the link's
//! durability, custody and fetch facts and the peer list. Nothing is recomputed per file and
//! nothing is remembered between calls; a fact that is not in the message is not claimed. The
//! meaning of each value, and how several links aggregate, is documented in
//! `yadorilink-product-view`.

use std::collections::BTreeSet;

use yadorilink_ipc_proto::daemonctl::{
    DurabilityEvidence, FetchAvailability, GroupDurabilityStatus, LinkStatus, PeerReachability,
    PeerStatus, StatusResponse,
};

use yadorilink_ipc_proto::daemonctl::{DataProtection, ProductAvailability};

/// One link's two dimensions, as the wire carries them.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LinkDimensions {
    pub availability: ProductAvailability,
    pub reachable_device_ids: Vec<String>,
    pub offline_device_ids: Vec<String>,
    pub update_required_device_ids: Vec<String>,
    pub protection: DataProtection,
    pub protection_device_ids: Vec<String>,
}

/// Fills every link's availability and protection fields from the link and the peer list.
pub(crate) fn fill_link_dimensions(response: &mut StatusResponse) {
    let peers = std::mem::take(&mut response.peers);
    for link in &mut response.links {
        let dimensions = link_dimensions(link, &peers);
        link.availability = dimensions.availability as i32;
        link.availability_reachable_device_ids = dimensions.reachable_device_ids;
        link.availability_offline_device_ids = dimensions.offline_device_ids;
        link.availability_update_required_device_ids = dimensions.update_required_device_ids;
        link.protection = dimensions.protection as i32;
        link.protection_device_ids = dimensions.protection_device_ids;
    }
    response.peers = peers;
}

/// The two dimensions of one link.
///
/// Availability reads the link's fetch availability and splits the other devices recorded as
/// full copies by whether the peer list says they are connected. A connected device that runs
/// another protocol version is neither reachable nor offline: it is reported apart as needing an
/// update, and when it is all there is the availability is `UpdateRequired` (the remedy is an
/// update, not waiting). A device is named as the one
/// being waited for only when the group's custody is currently confirmed, since a recorded full
/// copy alone does not show it holds the exact current version.
///
/// Protection reads the link's durability status, which the daemon computes from confirmed
/// custody and the recorded full copies. Reachability is deliberately not an input: a confirmed
/// copy on an offline device is still a copy. A distrusted policy is never protected.
pub(crate) fn link_dimensions(link: &LinkStatus, peers: &[PeerStatus]) -> LinkDimensions {
    let holders: BTreeSet<&String> = link.full_replica_device_ids.iter().collect();
    let connected = |id: &String| {
        peers.iter().any(|p| &p.device_id == id && p.reachability() == PeerReachability::Connected)
    };
    let incompatible =
        |id: &String| peers.iter().any(|p| &p.device_id == id && p.version_incompatible);
    let (online, offline): (Vec<&String>, Vec<&String>) =
        holders.iter().copied().partition(|id| connected(id));
    let (update_required, reachable): (Vec<&String>, Vec<&String>) =
        online.into_iter().partition(|id| incompatible(id));
    let custody_confirmed = matches!(
        link.durability_evidence(),
        DurabilityEvidence::CorroboratedIndex | DurabilityEvidence::VerifiedPayload
    ) && link.durability_status() == GroupDurabilityStatus::Protected;

    let availability = match link.fetch_availability() {
        FetchAvailability::AvailableNow => ProductAvailability::Available,
        FetchAvailability::UnavailableNow
            if reachable.is_empty() && !update_required.is_empty() =>
        {
            ProductAvailability::UpdateRequired
        }
        FetchAvailability::UnavailableNow
            if reachable.is_empty() && !offline.is_empty() && custody_confirmed =>
        {
            ProductAvailability::WaitingForPeer
        }
        FetchAvailability::UnavailableNow => ProductAvailability::WaitingForExactContent,
        FetchAvailability::Unknown | FetchAvailability::Unspecified => ProductAvailability::Unknown,
    };

    // Protected names the devices that actually answered the custody check (the daemon put them
    // in `protection_device_ids` when it built the link); a recorded full copy that has not
    // answered may still be catching up. While the first check is pending, Pending names
    // every recorded copy (the devices a confirmation is awaited from).
    let (protection, named_devices): (DataProtection, Vec<String>) = if link.policy_stale {
        (DataProtection::Unknown, Vec::new())
    } else {
        let awaited = || holders.iter().map(|id| (*id).clone()).collect();
        match link.durability_status() {
            GroupDurabilityStatus::Protected => {
                (DataProtection::Protected, link.protection_device_ids.clone())
            }
            GroupDurabilityStatus::AtRisk => (DataProtection::AtRisk, Vec::new()),
            GroupDurabilityStatus::Protecting => (DataProtection::Pending, Vec::new()),
            GroupDurabilityStatus::Unknown if link.durability_check_pending => {
                (DataProtection::Pending, awaited())
            }
            GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => {
                (DataProtection::Unknown, Vec::new())
            }
        }
    };

    LinkDimensions {
        availability,
        reachable_device_ids: reachable.into_iter().cloned().collect(),
        offline_device_ids: offline.into_iter().cloned().collect(),
        update_required_device_ids: update_required.into_iter().cloned().collect(),
        protection,
        protection_device_ids: named_devices,
    }
}

#[cfg(test)]
mod tests;
