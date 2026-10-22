//! What a rebootstrap set aside for the user: listing it, restoring a version and discarding
//! an item, and the summary `status` carries.

use super::common::BoxFuture;
use crate::preserved_items::{PreservedError, PreservedItem, PreservedSummary, RetainedItem};
use yadorilink_sync_sqlite::native_rebootstrap_retained::RetainedOutcome;

pub(crate) trait PreservedPort: Send + Sync {
    fn list(&self) -> BoxFuture<'_, Result<Vec<PreservedItem>, PreservedError>>;

    /// Restores a version item as one ordinary new write; the item stays.
    fn restore(
        &self,
        group_id: String,
        item_id: String,
    ) -> BoxFuture<'_, Result<(), PreservedError>>;

    /// Re-submits an own unit a rebootstrap held back to the replay engine.
    fn retry(&self, group_id: String, item_id: String)
        -> BoxFuture<'_, Result<(), PreservedError>>;

    /// The only operation that deletes an item.
    fn discard(
        &self,
        group_id: String,
        item_id: String,
    ) -> BoxFuture<'_, Result<(), PreservedError>>;

    /// The originals a rebootstrap kept under a claim.
    fn list_retained(&self) -> BoxFuture<'_, Result<Vec<RetainedItem>, PreservedError>>;

    /// Tries to release the retained originals of one group, one outcome per path.
    fn release_retained(
        &self,
        group_id: String,
    ) -> BoxFuture<'_, Result<Vec<(String, RetainedOutcome)>, PreservedError>>;

    fn summary(&self) -> PreservedSummary;

    /// Uploads retained for undecided operations (count, oldest age in ms).
    fn undecided_uploads(&self) -> (u64, u64);

    /// The groups a rebootstrap is replacing the state of right now.
    fn rebootstrapping_groups(&self) -> Vec<String>;
}
