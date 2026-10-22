//! Protocol-independent results the Enrollment coordination port returns --
//! owned by `application`, not borrowed from the coordination-client
//! module, so this module never needs to know how those results were
//! transported.

/// Why linking a folder was refused, when a client can tell the person
/// something specific about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkRefusal {
    DiskFull,
    PathNotAllowed,
}

/// Why the coordination plane will not redeem an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteRefusal {
    Expired,
    AlreadyUsed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentPrepareResult {
    Prepared {
        group_id: String,
    },
    /// The remote prepare was NOT committed.
    DefinitelyRejected {
        detail: String,
    },
    /// The invite cannot be redeemed; the remote prepare was NOT committed.
    InviteRefused {
        reason: InviteRefusal,
        detail: String,
    },
    /// This operation_id already names a differently-shaped request.
    Conflict {
        detail: String,
    },
    /// Transport failure or an unparseable success response -- may or may
    /// not have committed.
    Ambiguous {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentActivationResult {
    Activated,
    AlreadyActive,
    /// Cross-account invite acceptance only: the coordination plane
    /// accepted this device's half, but the invite required the group
    /// owner's approval, so the membership is parked awaiting their
    /// decision and grants nothing yet. A success as far as this device's
    /// own protocol obligations go -- there is nothing left for it to
    /// retry, compensate, or reconcile -- but NOT a membership, and callers
    /// must not describe it as one.
    AwaitingApproval,
    /// A CONFIRMED terminal answer: the coordination plane has nothing left
    /// to activate for this operation.
    Deleted,
    TransientFailure {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EnrollmentCancellationResult {
    /// Includes an already-deleted/already-swept/already-active no-op.
    Confirmed,
    /// A request-identity mismatch, not a routine absence.
    Conflict {
        detail: String,
    },
    Ambiguous {
        detail: String,
    },
}

/// A freshly-minted, one-use cross-account invite -- the plaintext `code`
/// is returned exactly once, here, and never persisted by this device (the
/// coordination plane stores only its hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MintedInvite {
    pub(crate) code: String,
    pub(crate) invite_id: String,
    pub(crate) group_id: String,
    pub(crate) role: String,
    pub(crate) expires_at_unix: i64,
    /// Whether accepting this invite still needs the group owner's
    /// explicit approval before it grants anything. Echoed back by the
    /// coordination plane rather than assumed from what was requested, so
    /// a caller describes the invite that actually exists.
    pub(crate) requires_approval: bool,
}
