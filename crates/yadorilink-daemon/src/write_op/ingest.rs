//! The ordered steps of one provider write that carries bytes from the OS into the store
//! (`OpKind::Ingest`).
//!
//! Prepare is the pending-ingest journal row, Publish is the segment store's own durable batch
//! (its barrier and fault points are unchanged) and Prove is the apply transaction. There is no
//! daemon-written visible name, so the op owes no batch flush: nothing is deferred and the
//! received-files flush has nothing to cover.
//!
//! The crash states are named by the last step recorded: `Journaled`, `StoreDurable`, `Applied`.
//! The tests in `shell_ipc/provider_apply/tests.rs` pin the order and what a retry does from each.

use super::{trace, StepEvent};

/// The identity of one ingest, as the trace keys it. Observational: it decides nothing.
#[derive(Debug, Clone)]
pub struct IngestOp {
    group_id: String,
    key: String,
}

impl IngestOp {
    /// `root` and `session_id` / `operation_seq` are the operation identity the apply log keys by.
    pub fn new(group_id: &str, root: &str, session_id: &[u8], operation_seq: u64) -> Self {
        Self {
            group_id: group_id.to_owned(),
            key: format!("{root}/{}/{operation_seq}", hex::encode(session_id)),
        }
    }

    pub fn journaled(&self) {
        trace::emit_at(&self.group_id, &self.key, StepEvent::IngestJournaled);
    }

    pub fn store_durable(&self) {
        trace::emit_at(&self.group_id, &self.key, StepEvent::IngestStoreDurable);
    }

    pub fn applied(&self) {
        trace::emit_at(&self.group_id, &self.key, StepEvent::IngestApplied);
    }

    /// The steps recorded for this ingest, in order.
    #[cfg(test)]
    pub fn steps(&self) -> Vec<StepEvent> {
        trace::StepTrace::of(&self.group_id, &self.key)
    }
}
