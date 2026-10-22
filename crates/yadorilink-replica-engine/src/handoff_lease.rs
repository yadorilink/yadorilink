//! # Why only this narrow slice lives here The full handoff-lease
//! repository (`crates/yadorilink-sync-sqlite/src/handoff_lease.rs`) is a
//! `handoff_leases`-table-backed CRUD/query store: every method takes a
//! live `SyncDatabase` connection and stays in `yadorilink-sync-sqlite`
//! per the dependency plan. What moves here is the one piece of that store
//! with no SQL and no connection in it at all: turning a lease grant's
//! `ttl_seconds` duration into this device's own LOCAL pin deadline.

use crate::error::ReplicaEngineError;

/// Fixed cushion added on top of a handoff-lease grant's own TTL duration
/// when the handoff TARGET computes its LOCAL pin deadline — see
/// [`compute_pin_deadline`]. The target's pin must outlive the coordination
/// Worker's own view of the lease under any realistic clock skew between the
/// two: pinning a little too long only delays this device's own next
/// retention sweep by that much, while pinning even slightly too short can
/// let a retention sweep collect a version the handoff still depends on. The
/// safe direction is always longer, never shorter.
pub const HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS: i64 = 60;

/// Derives the handoff TARGET's own LOCAL pin deadline from its own clock
/// reading at lease-record time (`created_at_unix`) and the grant's TTL
/// duration (`ttl_seconds`) — never a foreign absolute expiry. The caller
/// (`yadorilink-sync-sqlite::handoff_lease::HandoffLeaseRepository::
/// record_handoff_lease_atomic`) stores the result as
/// `handoff_leases.expires_at_unix` and later compares it only against this
/// SAME device's own `now_unix`.
///
/// A non-positive TTL cannot produce a safe pin: it yields a deadline at or
/// before `created_at_unix`, so the pin would lapse immediately and reopen
/// the retention/GC race this lease exists to close. Reject it structurally
/// here — fail closed, before any row is ever written — so an invalid
/// duration (e.g. a malformed grant that slipped past the caller's own
/// boundary check) can never produce a too-short pin. The safety margin only
/// ever lengthens a positive TTL; it must not be relied on to rescue a
/// non-positive one.
pub fn compute_pin_deadline(
    created_at_unix: i64,
    ttl_seconds: i64,
) -> Result<i64, ReplicaEngineError> {
    if ttl_seconds <= 0 {
        return Err(ReplicaEngineError::InvalidInput(format!(
            "handoff lease ttl_seconds must be positive, got {ttl_seconds}"
        )));
    }
    Ok(created_at_unix
        .saturating_add(ttl_seconds)
        .saturating_add(HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS))
}

#[cfg(test)]
mod tests;
