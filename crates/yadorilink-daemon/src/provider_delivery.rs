//! Whether a version this device authored has reached a device that keeps a full replica.
//!
//! An On-Demand device (the iPhone) can author a file without any other device having its bytes
//! yet: peers fetch them from it while it is reachable. "Saved" must mean a full replica holds
//! that exact version, never "this device finished writing". The answer comes from the same
//! exact-version custody check the eviction gate runs (`confirm_version_present_witness_via_peer`):
//! a connected, authorized, `Eager` full-replica writer answers, over the peer channel, that it
//! durably holds the exact version identified by its hash and block list at this path, with every
//! block read back and verified, and the authorization view did not change while it answered.
//!
//! The question is asked afresh on every call and nothing is cached: a peer that lost the version,
//! went offline or was demoted answers "not delivered" again. A device never reports "delivered"
//! on its own evidence (not after fetching, not after its own commit), and a timeout or a silent
//! peer is "not delivered", not "unknown": the count the app shows for data that is only on this
//! device must never be too low.

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_sync_sqlite::provider::ItemId;

use crate::shell_context::ShellContext;

/// Items asked about at once. Each is one peer round trip, bounded by the check's own timeout.
const CONCURRENT_QUERIES: usize = 8;

/// The most items one call may ask about.
pub const MAX_DELIVERY_ITEMS: usize = 256;

/// One item whose delivery is asked about: the root and item ids the write path returned, and the
/// 40-byte content version identifier it returned for the item (32-byte content hash, then the
/// item generation, big endian). Only the hash is compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryItem {
    pub root_id: Vec<u8>,
    pub item_id: Vec<u8>,
    pub content_version: Vec<u8>,
}

/// What is known about one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryState {
    /// A full-replica device confirmed it durably holds exactly this version. `device_ids` are
    /// the devices that confirmed in this check (at least one).
    Delivered { device_ids: Vec<String> },
    /// No full-replica device confirmed: none is connected, none answered in time, or none holds
    /// the version. The version is only on this device as far as this device can tell.
    NotDelivered,
    /// The item's current version is no longer the one asked about (edited, replaced or
    /// deleted), so there is nothing to attest for it.
    Superseded,
    /// A folder or a link: it has no content to deliver.
    NotApplicable,
    /// The root or the item is not known here.
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemDelivery {
    pub item: DeliveryItem,
    pub state: DeliveryState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    /// In the order asked.
    pub items: Vec<ItemDelivery>,
    /// Items whose version is only known to this device: `NotDelivered`.
    pub undelivered_count: u32,
    /// When the check ran (Unix seconds).
    pub checked_at_unix: i64,
}

/// Why a call was refused before anything was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooManyItems;

pub(crate) async fn version_delivery(
    context: &ShellContext,
    items: Vec<DeliveryItem>,
) -> Result<DeliveryReport, TooManyItems> {
    if items.len() > MAX_DELIVERY_ITEMS {
        return Err(TooManyItems);
    }
    // In groups, so no more than `CONCURRENT_QUERIES` peer round trips are in flight at once.
    let mut states = Vec::with_capacity(items.len());
    for group in items.chunks(CONCURRENT_QUERIES) {
        states.extend(
            futures_util::future::join_all(group.iter().map(|item| state_of(context, item))).await,
        );
    }
    let items: Vec<ItemDelivery> =
        items.into_iter().zip(states).map(|(item, state)| ItemDelivery { item, state }).collect();
    let undelivered_count = count_undelivered(&items);
    let checked_at_unix = context.writer.now_ms() / 1000;
    Ok(DeliveryReport { items, undelivered_count, checked_at_unix })
}

/// Items whose state is `NotDelivered`, and only those: `Delivered`, `Superseded`,
/// `NotApplicable` and `NotFound` have nothing left that exists only on this device.
fn count_undelivered(items: &[ItemDelivery]) -> u32 {
    items
        .iter()
        .filter(|entry| entry.state == DeliveryState::NotDelivered)
        .count()
        .try_into()
        .unwrap_or(u32::MAX)
}

async fn state_of(context: &ShellContext, item: &DeliveryItem) -> DeliveryState {
    let root = hex::encode(&item.root_id);
    let repo = context.replica_coordinator.provider_repository();
    let Ok(Some(group_id)) = repo.group_of_root(&root) else {
        return DeliveryState::NotFound;
    };
    let Ok(item_id) = ItemId::try_from(item.item_id.as_slice()) else {
        return DeliveryState::NotFound;
    };
    let Ok(Some((path, live))) = repo.path_for_item(&root, &item_id) else {
        return DeliveryState::NotFound;
    };
    if !live {
        return DeliveryState::Superseded;
    }
    let Ok(record) =
        context.replica_coordinator.sqlite().dag_get_current_version_record(&group_id, &path)
    else {
        // The index could not be read: not an attestation either way.
        return DeliveryState::NotDelivered;
    };
    let Some(record) = record.filter(|record| !record.deleted) else {
        return DeliveryState::Superseded;
    };
    if record.record_kind != RecordKind::File {
        return DeliveryState::NotApplicable;
    }
    let version = record.to_file_version();
    if item.content_version.len() != 40 || item.content_version[..32] != version.version_hash.0 {
        return DeliveryState::Superseded;
    }
    match context
        .writer
        .state()
        .confirm_version_present_witness_via_peer(
            &group_id,
            &path,
            version.version_hash,
            &version.blocks,
        )
        .await
    {
        Some(stamp) => DeliveryState::Delivered { device_ids: vec![stamp.peer_id().to_owned()] },
        None => DeliveryState::NotDelivered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(state: DeliveryState) -> ItemDelivery {
        ItemDelivery {
            item: DeliveryItem { root_id: vec![1], item_id: vec![2], content_version: vec![0; 40] },
            state,
        }
    }

    #[test]
    fn the_count_is_exactly_the_not_delivered_items() {
        let items = vec![
            entry(DeliveryState::Delivered { device_ids: vec!["mac".into()] }),
            entry(DeliveryState::NotDelivered),
            entry(DeliveryState::Superseded),
            entry(DeliveryState::NotApplicable),
            entry(DeliveryState::NotFound),
            entry(DeliveryState::NotDelivered),
        ];
        assert_eq!(count_undelivered(&items), 2);
        assert_eq!(count_undelivered(&items[..1]), 0, "a Delivered item is never undelivered");
        assert_eq!(count_undelivered(&[]), 0);
    }
}
