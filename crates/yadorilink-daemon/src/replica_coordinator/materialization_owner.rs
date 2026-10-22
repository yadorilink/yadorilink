//! Owner-side materialization-semantic operations.
//!
//! A lane (eager, on-demand, symlink, tombstone, engine completion, ...)
//! used to compose the raw primitives -- open an intent, persist a row, set
//! a materialization state, clear or set the held marker, bump the
//! mutation fence, publish or complete -- itself, each in its own order.
//! Each method here is ONE protocol's exact raw-call sequence (or one half
//! of it: the "open" steps before a physical write, or the "settle" steps
//! after it), moved here unchanged, so the lane calls the semantic step
//! instead of the raw steps.
//!
//! Every method keeps the transaction boundaries it replaced: each raw step
//! is still its own transaction, in the same order, with the same checks
//! and early returns. The exception is `open_content_write`, which commits
//! its steps, still in that order, as one transaction (see its doc). No method takes a path lock (the caller holds it) or
//! performs a physical write (the lane keeps it, between an open and a
//! settle). `.github/checks/check-materialization-semantic-boundary.py` pins every
//! raw call that remains, here and in the lanes.

use yadorilink_local_storage::PlaceholderIdentityToRecord;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use super::ReplicaCoordinator;
use crate::sync_error::SyncError;

mod hydration;
mod lanes;
#[cfg(test)]
pub(crate) use lanes::plain_file_columns;
pub(crate) use lanes::{ContentWriteClose, ContentWriteCloseItem, OwnedContentWriteOpen};
#[cfg(test)]
mod pre_write_tests;
mod repair;
mod structural;

#[cfg(test)]
pub(crate) use hydration::HydrationAttempt;
#[cfg(test)]
pub(crate) use repair::set_test_fail_repair_reconstruct_proof_commit;

impl ReplicaCoordinator {
    /// Records the placeholder identity a placeholder write reported for
    /// `(group_id, path)`: overwrite, record only if absent (a concurrent
    /// winner's value is kept, and the returned identity is not needed),
    /// or clear. One transaction for whichever arm applies.
    pub(crate) fn record_placeholder_identity(
        &self,
        group_id: &str,
        path: &str,
        outcome: PlaceholderIdentityToRecord,
        permit: &RootCommitPermit<'_>,
    ) -> Result<(), SyncError> {
        let repository = self.materialization_state_repository();
        match outcome {
            PlaceholderIdentityToRecord::RecordOverwrite { identity, provider_kind } => repository
                .record_placeholder_generation(group_id, path, identity, provider_kind, permit)?,
            PlaceholderIdentityToRecord::RecordIfAbsent { identity, provider_kind } => {
                repository.record_placeholder_generation_if_absent(
                    group_id,
                    path,
                    identity,
                    provider_kind,
                    permit,
                )?;
            }
            PlaceholderIdentityToRecord::Clear => {
                repository.clear_placeholder_generation(group_id, path, permit)?
            }
        }
        Ok(())
    }
}
