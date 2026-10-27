//! Protocol-independent value types `application` returns and consumes.
//! Every type here is owned by `application` -- never re-exported from the
//! coordination-client module, the daemon-state module, or the IPC-proto
//! crate -- so a port implementation can be swapped without this module (or
//! anything that matches on its types) changing at all.

pub(crate) mod enrollment;
pub(crate) mod membership;
pub(crate) mod replica_role;

#[allow(unused_imports)]
pub(crate) use enrollment::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
    InviteRefusal, LinkRefusal, MintInviteError, MintedInvite,
};
#[allow(unused_imports)]
pub(crate) use membership::{
    HandoffCommitResult, MembershipCommitOutcome, MembershipCommitResult,
    MembershipOperationLookup, MembershipOperationRecord, MembershipRemoteCommand,
    MembershipRemoteRequest, MembershipRemoteRequestGroup, MembershipRemoteResult,
    MembershipRemoteStatus, RoleLossCommitOutcome, RoleLossCompensationOutcome,
};
