//! What the durability-latch and handoff lease/ticket control commands
//! need from the runtime -- the durability-unknown latch and the full-replica-handoff
//! lease/ticket round trips, none of which fit `MembershipCoordination`'s
//! shape (these act on THIS device's own local durability state and peer
//! sessions, not the coordination-plane HTTP API).

use crate::sync_error::SyncError;

use super::common::BoxFuture;

pub(crate) trait DurabilityCommandPort: Send + Sync {
    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError>;
}

/// Flattened result of a full-replica-handoff lease request -- only the
/// fields `RequestHandoffLease`'s IPC response actually carries, not the
/// full concrete coordination-client grant type.
#[derive(Debug, Clone)]
pub(crate) struct HandoffLeaseGrant {
    pub(crate) lease_id: String,
    pub(crate) expires_at_unix: i64,
}

/// Flattened result of a removed-device handoff-ticket request -- mirrors
/// `HandoffLeaseGrant`'s own "only the fields the caller actually uses"
/// shape for `ObtainHandoffTicket`'s response.
#[derive(Debug, Clone)]
pub(crate) struct HandoffTicketGrant {
    pub(crate) lease_id: String,
    pub(crate) expires_at_unix: i64,
    pub(crate) target_device_id: String,
}

pub(crate) trait HandoffCommandPort: Send + Sync {
    fn request_lease<'a>(&'a self, group_id: &'a str) -> BoxFuture<'a, Option<HandoffLeaseGrant>>;

    fn obtain_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Option<HandoffTicketGrant>>;

    /// Best-effort: matches `DaemonState::release_handoff_ticket_from_device`'s
    /// own "an unreachable device is logged, not surfaced as an error"
    /// contract -- the Worker's TTL sweep reclaims an unreleased ticket
    /// either way.
    fn release_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> BoxFuture<'a, ()>;
}
