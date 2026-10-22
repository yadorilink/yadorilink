//! The engine's own assessment of which groups a membership removal puts at
//! risk -- the only place that reads the coordination plane's advisory
//! answers about a device's groups and edge state, and the only place that
//! can mint the [`NoGroupsAtRisk`] witness a removal without a handoff
//! ticket requires.
//!
//! The coordination plane decides account membership; whether local data may
//! be lost is the engine's call. So a server answer is never the decision: it
//! is unioned with what this device's own netmap, verified policy and live
//! peer answers show, and the union can only add groups, never drop one.
//! The architecture manifest pins both halves (`membership_risk_reads_stay_in_
//! the_engine_assessment`, `the_no_ticket_removal_witness_is_minted_only_by_
//! the_engine_assessment`).

use super::{ReplicaMembershipError, ReplicaMembershipService};

/// The coordination plane's `acl.state` value for a live member. Every
/// membership read on that side admits a row by testing this value
/// POSITIVELY rather than by excluding known-inactive ones, so a state
/// this daemon has never heard of is correctly not a member here either.
const ACTIVE_EDGE_STATE: &str = "active";

/// Proof, produced only by [`ReplicaMembershipService::assess_removal_risk`],
/// that the engine found no group put at risk by the removal. The private
/// field keeps every other module from constructing one.
pub(super) struct NoGroupsAtRisk {
    _sealed: (),
}

/// The engine's verdict for one removal.
pub(super) enum RemovalRisk {
    /// Nothing is at risk; carries the witness that unlocks the removal
    /// without a handoff ticket.
    NoGroupsAtRisk(NoGroupsAtRisk),
    /// These groups need a ticket-bound handoff (or `--force`).
    AtRisk(Vec<String>),
    /// The coordination plane could not enumerate the target's groups and
    /// the engine has no scope to substitute: only `--force` may proceed.
    Unverified,
}

impl ReplicaMembershipService {
    /// Assesses which groups removing `target_device_id` (scoped to one group,
    /// or the whole account) puts at risk. Starts from the coordination
    /// plane's list and, for another device, adds every group the engine's own
    /// evidence (netmap role, a direct answer from the live peer) shows the
    /// target holding eagerly, within the removal's scope. For this device's
    /// own removal the caller adds its local links.
    pub(super) async fn assess_removal_risk(
        &self,
        scoped_group_id: &Option<String>,
        target_device_id: &str,
    ) -> Result<RemovalRisk, ReplicaMembershipError> {
        let mut groups_at_risk = match scoped_group_id {
            Some(group_id) => {
                if self.target_edge_is_provably_not_active(group_id, target_device_id).await {
                    Vec::new()
                } else {
                    vec![group_id.clone()]
                }
            }
            None => match self.coordination.fetch_eager_groups(target_device_id).await {
                Ok(groups) => groups,
                Err(error) => {
                    tracing::warn!(%error, target_device_id, "could not enumerate groups at risk");
                    return Ok(RemovalRisk::Unverified);
                }
            },
        };

        if target_device_id != self.device_id {
            let candidates = match scoped_group_id {
                Some(group_id) => vec![group_id.clone()],
                None => self
                    .repository
                    .list_links()?
                    .into_iter()
                    .filter(|link| !link.orphaned)
                    .map(|link| link.group_id)
                    .collect(),
            };
            for group_id in
                self.readiness.peer_eager_replica_groups(target_device_id, &candidates).await
            {
                if !groups_at_risk.contains(&group_id) {
                    groups_at_risk.push(group_id);
                }
            }
        }

        if groups_at_risk.is_empty() {
            Ok(RemovalRisk::NoGroupsAtRisk(NoGroupsAtRisk { _sealed: () }))
        } else {
            Ok(RemovalRisk::AtRisk(groups_at_risk))
        }
    }

    /// Whether the coordination plane POSITIVELY reports the target's edge
    /// on this group as something other than `active` -- the one case in
    /// which a targeted revoke needs no ticket-bound full-replica handoff.
    ///
    /// A targeted revoke otherwise treats its one group as at risk
    /// unconditionally, which is right for a live member: removing it may
    /// be removing the group's last full replica, so the removal must be
    /// bound to a lease handing those duties to a confirmed-ready peer. An
    /// edge that has never been `active` holds none of that. It has no
    /// grant, so it is in no netmap, so no peer session with it can exist
    /// and `obtain_ticket` can never succeed -- and demanding a ticket
    /// anyway made turning down an approval request (which is this same
    /// revoke) fail with "another full replica is not ready", pointing at a
    /// device holding zero data, with `--force` and its data-loss warning
    /// as the only way through. Nothing is at risk, so nothing is protected
    /// by refusing.
    ///
    /// This does not soften the guard, it only declines to apply it where
    /// it cannot bite. The coordination plane's answer is advisory: the
    /// requirement is relaxed only when this device's own verified group
    /// policy ALSO shows the target is not a member, so a wrong or stale
    /// server answer can never by itself skip the handoff.
    ///
    /// Fails closed in every uncertain case -- an unreadable listing, an
    /// edge the listing does not carry, a coordination plane that does
    /// not report edge state, or no verified local policy for the group --
    /// so the ticket requirement is relaxed only on two agreeing positive
    /// answers.
    async fn target_edge_is_provably_not_active(
        &self,
        group_id: &str,
        target_device_id: &str,
    ) -> bool {
        match self.coordination.fetch_edge_state(group_id, target_device_id).await {
            Ok(Some(state)) if state != ACTIVE_EDGE_STATE => {
                self.readiness.verified_policy_shows_non_member(group_id, target_device_id).await
            }
            Ok(Some(_)) | Ok(None) => false,
            Err(error) => {
                tracing::warn!(
                    %error,
                    group_id,
                    target_device_id,
                    "could not read the target's share-edge state; requiring a handoff ticket"
                );
                false
            }
        }
    }
}
