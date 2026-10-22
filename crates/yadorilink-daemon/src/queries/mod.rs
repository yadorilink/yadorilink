//! Read-only query services for the control socket, and the plain
//! (non-protobuf) view models they return -- `control_socket.rs` maps a
//! view to its IPC wire type itself; nothing under this module or its
//! adapter implementations ever names a `yadorilink_ipc_proto` type.
//!
//! Grown one vertical slice (one request-handler family) at a time: see
//! `link_status` for the first. `QueryServices` stays a plain field bundle
//! -- add a new field only when a new slice lands, never a placeholder for
//! one that hasn't.

pub(crate) mod diagnostics;
pub(crate) mod diagnostics_bundle;

pub(crate) mod file_history;
pub(crate) mod governance;
pub(crate) mod handoff_readiness;
pub(crate) mod health;
pub(crate) mod link_status;
pub(crate) mod linked_path;
pub(crate) mod recovery;
pub(crate) mod reporting;
pub(crate) mod runtime_status;
pub(crate) mod update_status;

use std::sync::Arc;

pub(crate) struct QueryServices {
    pub(crate) link_status: Arc<link_status::LinkStatusQueryService>,
    pub(crate) health: Arc<health::HealthQueryService>,
    pub(crate) diagnostics: Arc<diagnostics::DiagnosticsQueryService>,
    pub(crate) runtime_status: Arc<runtime_status::RuntimeStatusQueryService>,
    pub(crate) linked_path: Arc<linked_path::LinkedPathResolver>,
    pub(crate) file_history: Arc<file_history::FileHistoryQueryService>,
    pub(crate) governance: Arc<governance::GovernanceQueryService>,
    pub(crate) reporting: Arc<reporting::ReportingQueryService>,
    pub(crate) recovery: Arc<recovery::RecoveryQueryService>,
    pub(crate) diagnostics_bundle: Arc<diagnostics_bundle::DiagnosticsBundleQueryService>,
    pub(crate) handoff_readiness: Arc<handoff_readiness::HandoffReadinessQueryService>,
    pub(crate) update_status: Arc<update_status::UpdateStatusQueryService>,
    /// Track Send's `inbox` command -- see `crate::send_transfer`'s own
    /// module doc comment.
    pub(crate) inbox: Arc<crate::send_transfer::InboxQueries>,
    /// Folder Rewind's read-only preview -- see `crate::rewind`'s own
    /// module doc comment.
    pub(crate) rewind: Arc<crate::rewind::RewindQueries>,
}
