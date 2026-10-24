//! `application`'s own boundary traits. Concrete implementations live
//! under the adapters module tree, never here.

pub(crate) mod common;
pub(crate) mod enrollment;
pub(crate) mod governance;
pub(crate) mod group_admin;
pub(crate) mod handoff;
pub(crate) mod link_lifecycle;
pub(crate) mod materialization;
pub(crate) mod membership;
pub(crate) mod preserved;
pub(crate) mod replica_role;
pub(crate) mod reporting;
pub(crate) mod runtime_control;
#[cfg(feature = "process-model")]
pub(crate) mod update;
pub(crate) mod version_restore;

#[allow(unused_imports)]
pub(crate) use common::BoxFuture;
#[allow(unused_imports)]
pub(crate) use enrollment::{
    EnrollmentAttemptTracker, EnrollmentCoordination, EnrollmentLinkPort, EnrollmentLinkRequest,
    EnrollmentRepository,
};
#[allow(unused_imports)]
pub(crate) use governance::{GovernanceCommandPort, GovernanceLimits};
#[allow(unused_imports)]
pub(crate) use group_admin::GroupAdministration;
#[allow(unused_imports)]
pub(crate) use handoff::{
    DurabilityCommandPort, HandoffCommandPort, HandoffLeaseGrant, HandoffTicketGrant,
};
#[allow(unused_imports)]
pub(crate) use link_lifecycle::{
    LinkCommand, LinkOutcome, LinkRepositoryPort, LinkWatcherPort, PendingEnrollmentLinkCommand,
    ProviderLinkTarget,
};
#[allow(unused_imports)]
pub(crate) use materialization::{
    AssemblyProgress, ByteRange, EvictOutcome, LocalPresence, LocalTransition, MaterializationPort,
    MaterializationStatusSummary, PinOutcome, RetentionState, TempAssembly, TempMaterialization,
    TempOutcome,
};
#[allow(unused_imports)]
pub(crate) use membership::{
    HandoffTicketPort, MembershipCoordination, MembershipRepository, ReplicaReadinessPort,
};
#[allow(unused_imports)]
pub(crate) use preserved::PreservedPort;
#[allow(unused_imports)]
pub(crate) use replica_role::{
    CustodyLeaseHandoffPort, HandoffReadinessPort, LinkRuntimePort, OnDemandCapabilityPort,
    ReplicaRoleRepository, RoleLossCoordination, RoleLossJournal,
};
#[allow(unused_imports)]
pub(crate) use reporting::{
    ConsentCommand, LastErrorReport, RedactionCategoryCount as ReportingRedactionCategoryCount,
    ReportingCommandPort, SubmitReportOutcome,
};
#[allow(unused_imports)]
pub(crate) use runtime_control::{
    safe_stop_deadline, DaemonLifecyclePort, GcCommandError, GcCommandOutcome, GcPort,
    LinkPauseResumePort, SafeStopBusy, SafeStopOutcome,
};
#[cfg(feature = "process-model")]
#[allow(unused_imports)]
pub(crate) use update::{
    UpdateCommandPort, UpdateConfigCommand, UpdatePolicyView, UpdateVersionCheckKind,
};
#[allow(unused_imports)]
pub(crate) use version_restore::VersionRestorePort;
