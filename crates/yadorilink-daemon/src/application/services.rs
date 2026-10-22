//! The single entry point the control socket calls into `application`
//! through. Built exactly once by the production composition root, and
//! handed down through `ControlContext`.
//!
//! Two kinds of field live here. A `*Service` field wraps a ports-based
//! application service that owns real saga/decision logic (validation,
//! sequencing, rollback, error translation). A `dyn *Port` field is a
//! command surface whose only application-level behaviour would be a 1:1
//! forward to that port, so callers reach the port directly instead of
//! through an extra wrapper type that adds nothing.

use std::sync::Arc;

use super::ports::{
    DaemonLifecyclePort, DurabilityCommandPort, GcPort, GovernanceCommandPort, GroupAdministration,
    HandoffCommandPort, LinkPauseResumePort, MaterializationPort, PreservedPort,
    ReportingCommandPort, UpdateCommandPort,
};
use super::{
    EnrollmentRecoveryService, EnrollmentService, LinkLifecycleService, ReplicaMembershipService,
    ReplicaRoleService, VersionRestoreService,
};

pub(crate) struct ApplicationServices {
    pub(crate) enrollment: Arc<EnrollmentService>,
    pub(crate) enrollment_recovery: Arc<EnrollmentRecoveryService>,
    pub(crate) materialization: Arc<dyn MaterializationPort>,
    pub(crate) membership: Arc<ReplicaMembershipService>,
    pub(crate) group_admin: Arc<dyn GroupAdministration>,
    pub(crate) replica_role: Arc<ReplicaRoleService>,
    pub(crate) pause_resume: Arc<dyn LinkPauseResumePort>,
    pub(crate) gc: Arc<dyn GcPort>,
    pub(crate) preserved: Arc<dyn PreservedPort>,
    pub(crate) lifecycle: Arc<dyn DaemonLifecyclePort>,
    pub(crate) durability: Arc<dyn DurabilityCommandPort>,
    pub(crate) handoff: Arc<dyn HandoffCommandPort>,
    pub(crate) version_restore: Arc<VersionRestoreService>,
    pub(crate) governance: Arc<dyn GovernanceCommandPort>,
    pub(crate) reporting: Arc<dyn ReportingCommandPort>,
    pub(crate) update: Arc<dyn UpdateCommandPort>,
    pub(crate) link_lifecycle: Arc<LinkLifecycleService>,
    /// Track Send's `send`/`receive` commands -- see `crate::send_transfer`'s
    /// own module doc comment for why this is a thin wrapper rather than a
    /// full ports/adapters service like the fields above.
    pub(crate) send_transfer: Arc<crate::send_transfer::SendTransferService>,
    /// Sessions for managing another device on this account -- see
    /// `crate::nas_admin_bridge`.
    pub(crate) nas_admin: Arc<crate::nas_admin_bridge::NasAdminSessions>,
    /// Folder Rewind's execution: a thin wrapper like `send_transfer`; the
    /// run itself is `crate::rewind`'s.
    pub(crate) rewind: Arc<crate::rewind::RewindService>,
}
