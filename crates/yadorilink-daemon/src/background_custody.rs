//! What the background health check learns, and what it is not allowed to
//! be mistaken for.
//!
//! Every ninety seconds this daemon would like to know whether each folder
//! group's data still exists somewhere other than here. Until this module
//! existed it found out by running the action-time handoff proof: one
//! round-trip per durability root, each one making the peer read that
//! version's blocks back off its own disk and re-hash them. On a two-device
//! group with eight thousand roots that was eight thousand round-trips and
//! eight thousand whole-file re-reads, per group, per sweep — to refresh an
//! indicator in a status listing.
//!
//! The cost was not the verification. The verification is right, and an
//! unlink still runs all of it. The cost was that a *monitor* was reusing a
//! *proof*, and the only thing stopping that was that nobody had noticed.
//!
//! So the two facts are now two types. [`BackgroundCustodyEvidence`] is what
//! a monitor can afford to learn continuously;
//! [`crate::handoff_proof::StrongHandoffProof`] is what a destructive action
//! must establish afresh. Neither converts to the other, the cache holds
//! only the first, and the architecture manifest refuses a build in which
//! the background path can reach for the second.

/// What one background custody cycle established about a group.
///
/// # `Corroborated` means, precisely
///
/// At the moment this value was made, one named peer:
///
/// 1. was connected, and was a netmap-authorized full-replica writer for
///    the group both before and after the round-trip, across an unchanged
///    local membership generation;
/// 2. reported itself `Eager` for the group — the same precondition the
///    handoff responder checks first, because an on-demand device may evict
///    at any moment;
/// 3. reported every one of its current rows for the group materialized,
///    which is what separates a peer that holds the content from one that
///    has merely projected the changes describing it;
/// 4. returned a **current-state** digest equal to this device's own, over
///    the same rows and by the same function — and this device's own had
///    not moved across the round-trip either.
///
/// # Why the current state and not the whole root set
///
/// Because the whole root set does not converge, and requiring it to would
/// have made the most ordinary two-device folder permanently
/// uncorroborated. A device that links a group it did not originate starts
/// from a local history floor and never reconstructs what came before it;
/// retention keeps any version inside its count bound indefinitely, whatever
/// its age. Two entirely honest eager replicas therefore retain different
/// history, forever, and there is no mechanism that would bring them
/// together.
///
/// `roots_digest_matched` records when the fuller agreement happens anyway.
/// It is an observation, never a condition. The whole root set is still
/// covered where it matters: by the handoff proof, at the moment something
/// irreversible is about to happen to it.
///
/// # What it does not mean
///
/// It says nothing about whether a single block exists on that peer's disk,
/// and nothing about whether any block it holds is intact. It does not
/// establish that the peer would actually serve those blocks — serving
/// authorization is per-group block provenance, which the handoff proof
/// checks and this does not. It is an index-level claim the peer makes
/// about itself, and it is worth exactly what that peer is worth.
///
/// That gap is deliberate and is not closed here. It is closed at the two
/// places where it matters: immediately before a destructive action, by a
/// fresh [`crate::handoff_proof::StrongHandoffProof`] that reads every byte
/// back; and, for latent corruption discovered at rest rather than at
/// decision time, by a budgeted scrub on a cadence measured in days rather
/// than in seconds. Asking a ninety-second monitor to answer the bit-rot
/// question is how the original defect came about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackgroundCustodyEvidence {
    /// One peer's durable state corroborates this device's, as above.
    /// `peer_device_id` is `None` for the vacuous case: the group has no
    /// current files at all, so there is nothing for a peer to corroborate
    /// and nothing at risk.
    Corroborated {
        peer_device_id: Option<String>,
        /// The current-state digest this corroboration was made against —
        /// re-derived and compared by every reader, so a later content
        /// change cannot ride an older corroboration.
        current_digest: [u8; 32],
        /// Whether the peer's retained history happened to match too. Never
        /// required; see this type's own doc comment.
        roots_digest_matched: bool,
    },
    /// The cycle ran and nothing corroborated.
    ///
    /// Carries why, because the publisher treats two kinds of negative
    /// differently — see [`NotCorroboratedReason::is_contradiction`].
    ///
    /// Written even when it is the least informative answer available,
    /// because "checked, found nothing" and "never checked" are different
    /// facts and classification treats them differently — the first can
    /// reach a structural at-risk conclusion, the second must stay unknown.
    NotCorroborated { reason: NotCorroboratedReason },
}

/// Why a cycle did not corroborate.
///
/// This is not only diagnostics. The publisher needs to tell two kinds of
/// negative apart, and getting that wrong is a real defect in either
/// direction.
///
/// An **absence** of evidence — nobody to ask, nobody answered in time —
/// must not erase a still-fresh positive. That tolerance is what the
/// staleness bound exists to provide: one missed round does not flip a
/// genuinely protected group.
///
/// A **contradiction** must. When a peer answers and its answer disagrees,
/// this device has learned something new and worse, and holding on to the
/// old positive for the rest of the staleness window would be reporting a
/// fact that has been refuted. The original publisher made no such
/// distinction, because before this design a negative could only ever mean
/// a round-trip that did not land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCorroboratedReason {
    /// No connected, netmap-authorized full-replica writer to ask.
    /// Absence.
    NoCandidatePeer,
    /// Nobody answered in time, or nobody who answered is still eligible.
    /// Absence.
    NoUsableReply,
    /// A peer answered and is not a full replica of the group after all.
    /// Contradiction.
    PeerNotEager,
    /// A peer answered and its current state disagrees with this device's.
    /// Contradiction.
    CurrentStateDiffers,
    /// A peer answered, its current state agrees, but it has not
    /// materialized all of it — it has the changes and not (yet) the
    /// content. Contradiction: this is precisely the state a bare digest
    /// comparison would have mistaken for custody.
    PeerNotMaterialized,
    /// The cycle's premises moved while it ran: this device's own root set,
    /// the membership generation, or the group's link state. Absence — the
    /// cycle learned nothing either way, and a moved root set already
    /// invalidates the cached digest by itself.
    PremisesMoved,
    /// This device could not read its own index. Absence.
    LocalStateUnreadable,
}

impl NotCorroboratedReason {
    /// Whether this is evidence AGAINST the group being corroborated, as
    /// opposed to the absence of evidence for it. Only a contradiction may
    /// retract a still-fresh positive.
    pub fn is_contradiction(self) -> bool {
        match self {
            Self::PeerNotEager | Self::CurrentStateDiffers | Self::PeerNotMaterialized => true,
            Self::NoCandidatePeer
            | Self::NoUsableReply
            | Self::PremisesMoved
            | Self::LocalStateUnreadable => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCandidatePeer => "no_candidate_peer",
            Self::NoUsableReply => "no_usable_reply",
            Self::PeerNotEager => "peer_not_eager",
            Self::CurrentStateDiffers => "current_state_differs",
            Self::PeerNotMaterialized => "peer_not_materialized",
            Self::PremisesMoved => "premises_moved",
            Self::LocalStateUnreadable => "local_state_unreadable",
        }
    }
}

/// How one background cycle ended — the caller-facing result, distinct from
/// the evidence it published.
///
/// A cycle that did not run is not a negative result, and a benchmark or a
/// test averaging the two together would quietly understate what a real
/// cycle costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundCustodyOutcome {
    Corroborated,
    /// The group has no current files. Published as corroborated; there is
    /// nothing to protect.
    VacuouslyCorroborated,
    NotCorroborated(NotCorroboratedReason),
    /// The refresh cadence had not elapsed, so no cycle started.
    NotDue,
    /// A cycle for this group was already in flight.
    AlreadyRunning,
}

impl BackgroundCustodyOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Corroborated => "corroborated",
            Self::VacuouslyCorroborated => "vacuously_corroborated",
            Self::NotCorroborated(reason) => reason.as_str(),
            Self::NotDue => "not_due",
            Self::AlreadyRunning => "already_running",
        }
    }
}

/// The components one background custody cycle reads and writes, and
/// nothing more: the durability state it publishes into, the netmap
/// authorization it re-checks, the live sessions it asks, and this
/// device's own file index. A plain field bundle, not a service locator --
/// the cycle cannot reach the rest of the daemon through it.
#[derive(Clone, Copy)]
pub(crate) struct CustodyCycleComponents<'a> {
    pub(crate) durability: &'a crate::durability_service::DurabilityService,
    pub(crate) authority: &'a crate::daemon_state::PeerAuthorityState,
    pub(crate) peers: &'a crate::peer_registry::PeerRegistry,
    pub(crate) peer_connectivity: &'a crate::peer_connectivity_runtime::PeerConnectivityRuntime,
    pub(crate) file_index: &'a yadorilink_sync_sqlite::file_index::FileIndexRepository,
}

/// How long one background cycle's fan-out may take in total.
///
/// Shares `VERSION_PRESENT_QUERY_OVERALL_TIMEOUT` with the per-version
/// eviction custody fan-out, which has the same shape: every candidate
/// asked at once, first usable answer wins, one timeout window for the
/// lot rather than one per peer.
const CUSTODY_SUMMARY_TIMEOUT: std::time::Duration =
    crate::daemon_state::VERSION_PRESENT_QUERY_OVERALL_TIMEOUT;

/// Every connected peer that is currently a netmap-authorized
/// full-replica writer for `group_id` and speaks this build's versions.
pub(crate) fn custody_candidate_peers(
    peers: &crate::peer_registry::PeerRegistry,
    peer_connectivity: &crate::peer_connectivity_runtime::PeerConnectivityRuntime,
    authority: &crate::daemon_state::PeerAuthorityState,
    group_id: &str,
) -> Vec<(String, std::sync::Arc<yadorilink_peer_session::peer_session::PeerSyncSession>)> {
    peers
        .all_sessions()
        .into_iter()
        .filter(|(peer_id, _)| {
            authority.peer_group_is_full_replica(peer_id, group_id)
                && authority.peer_is_writer(peer_id, group_id)
                && peers.peer_is_version_compatible(peer_connectivity, peer_id)
        })
        .collect()
}

/// Runs one background custody cycle for `group_id` and publishes what it
/// found, whatever that is.
///
/// # This is a monitor, not a gate
///
/// It asks each candidate peer one question — "what does your index say you
/// hold for this group" — and accepts the first answer that matches its own.
/// No peer reads a block to answer, this device reads no block to ask, and
/// the resulting [`BackgroundCustodyEvidence`] is not a value any
/// destructive action accepts. What an unlink needs is a
/// [`crate::handoff_proof::StrongHandoffProof`], it is taken fresh at the
/// moment of the unlink, and it still verifies every durability root against
/// one peer that reads every byte back.
///
/// Before this function existed, this work *was* that proof. Every ninety
/// seconds, per group, per root.
///
/// # Why it lives in this file
///
/// So that "the background path must not reach for a strong proof" is a
/// property of a file rather than of a habit. The architecture manifest
/// forbids this module from naming any of the strong-proof entry points,
/// including the `DaemonState` wrappers around them — a rule that can only
/// mean anything while the cycle body is somewhere a file-scoped rule can
/// point at. That rule is a text rule, not a call-graph rule: it catches the
/// function names, not an arbitrary indirection someone builds to reach
/// them. The types are the other half of the fence, and the test that a
/// negative cycle issues zero per-root requests is the third.
///
/// # Fail-closed, with no expensive escape hatch
///
/// Every negative outcome — no candidate, a refusal, a timeout, a
/// disagreeing digest, a premise that moved — publishes `NotCorroborated`.
/// None of them falls back to the per-root proof. That is the point: a
/// fallback would restore the whole cost on exactly the occasions a large or
/// busy group is most likely to hit, and "background evidence is
/// unavailable" is a cheap, honest, fail-safe answer.
///
/// # What is re-checked, and when
///
/// `membership_generation` and the cache epoch are captured before the
/// fan-out and re-checked after it, exactly as the whole-pass version did: a
/// generation change means some peer's authorization may have shifted
/// mid-check, and an epoch change means an unlink (possibly followed by a
/// relink) landed for this exact group while the round-trips were in flight,
/// so the result belongs to a link that is no longer there. This device's
/// own root-set generation is captured and re-checked too, which the
/// whole-pass version had no need for and this one does: the digest it
/// publishes would otherwise describe a set this device has since moved on
/// from.
pub(crate) async fn run_cycle(
    components: &CustodyCycleComponents<'_>,
    group_id: &str,
) -> BackgroundCustodyOutcome {
    use futures_util::stream::{FuturesUnordered, StreamExt};

    let CustodyCycleComponents { durability, authority, peers, peer_connectivity, file_index } =
        *components;

    let generation_before = authority.membership_generation();
    let epoch_before = durability.custody_confirmation_epoch(group_id);

    // Every record is stamped with `generation_before`; the generation read
    // at publish time only decides whether a still-fresh positive survives
    // a negative.
    let publish = |outcome: BackgroundCustodyEvidence| {
        durability.publish_background_custody(
            group_id,
            outcome,
            generation_before,
            epoch_before,
            authority.membership_generation(),
        )
    };
    let local_root_set_summary = || durability.local_root_set_summary(file_index, group_id);

    let publish_negative = |reason: NotCorroboratedReason| {
        publish(BackgroundCustodyEvidence::NotCorroborated { reason });
        BackgroundCustodyOutcome::NotCorroborated(reason)
    };

    let Some(local) = local_root_set_summary() else {
        return publish_negative(NotCorroboratedReason::LocalStateUnreadable);
    };

    // Nothing to protect. Published as corroborated, exactly as the
    // whole-pass version treated a vacuously-ready empty set -- and, exactly
    // as it did, WITHOUT clearing a post-`--force` durability latch:
    // "everything was deleted" and "this group never had anything" look
    // identical from here, so clearing would hide the uncertainty the latch
    // exists to preserve.
    if local.current_count == 0 {
        publish(BackgroundCustodyEvidence::Corroborated {
            peer_device_id: None,
            current_digest: local.current_digest,
            roots_digest_matched: true,
        });
        return BackgroundCustodyOutcome::VacuouslyCorroborated;
    }

    let candidates = custody_candidate_peers(peers, peer_connectivity, authority, group_id);
    if candidates.is_empty() {
        // Recorded, not skipped. The record is what makes
        // `has_ever_been_custody_swept` true, which is what lets
        // classification reach the structural at-risk conclusion instead of
        // sitting at unknown forever.
        return publish_negative(NotCorroboratedReason::NoCandidatePeer);
    }

    // Every candidate at once, under one overall timeout, rather than one
    // after another: the whole point of the summary RPC is that a cycle
    // costs one round-trip window regardless of how many peers there are,
    // and asking them in sequence would trade the per-root cost for a
    // per-peer one.
    let mut queries: FuturesUnordered<_> = candidates
        .into_iter()
        .map(|(peer_id, session)| async move {
            let summary = session.request_group_durability_summary(group_id).await;
            (peer_id, summary)
        })
        .collect();

    let mut reason = NotCorroboratedReason::NoUsableReply;
    let mut corroborating: Option<(String, bool)> = None;
    let settled = tokio::time::timeout(CUSTODY_SUMMARY_TIMEOUT, async {
        while let Some((peer_id, summary)) = queries.next().await {
            let Some(summary) = summary else { continue };
            if !summary.eager {
                reason = NotCorroboratedReason::PeerNotEager;
                continue;
            }
            if summary.current_digest != local.current_digest {
                reason = NotCorroboratedReason::CurrentStateDiffers;
                continue;
            }
            // Matching digests and unfetched content look identical from
            // the index alone; this is where they stop looking identical.
            if !summary.fully_materialized {
                reason = NotCorroboratedReason::PeerNotMaterialized;
                continue;
            }
            // Re-verify AFTER the reply, like every other custody path
            // here: the peer must still be an authorized full-replica
            // writer and the netmap-authorization view must not have moved
            // during the wait, so a revoke or demote mid-flight fails
            // closed rather than riding a now-stale answer.
            if authority.membership_generation() == generation_before
                && authority.peer_group_is_full_replica(&peer_id, group_id)
                && authority.peer_is_writer(&peer_id, group_id)
                && peers.peer_is_version_compatible(peer_connectivity, &peer_id)
            {
                let roots_matched = summary.roots_digest == local.roots_digest;
                corroborating = Some((peer_id, roots_matched));
                return true;
            }
            reason = NotCorroboratedReason::PremisesMoved;
        }
        false
    })
    .await;

    // A timed-out fan-out is treated exactly like "nobody corroborated" --
    // fail closed, matching every other unconfirmed outcome here.
    let Some((peer_id, roots_digest_matched)) = settled.ok().and(corroborating) else {
        return publish_negative(reason);
    };

    // This device's own state must not have moved either. Without this the
    // published digest could describe a set this device left behind while
    // the round-trips were in flight, and the staleness bound would keep it
    // trusted for the next several minutes.
    if local_root_set_summary().map(|now| now.generation) != Some(local.generation) {
        return publish_negative(NotCorroboratedReason::PremisesMoved);
    }

    // Deliberately does NOT clear a post-`--force` durability latch. That
    // latch records that this device's own handoff gate was overridden, and
    // only that gate re-earning its answer -- a real proof, against one peer
    // that read every byte back -- may retire it. An index comparison is not
    // that, however fresh.
    let published = publish(BackgroundCustodyEvidence::Corroborated {
        peer_device_id: Some(peer_id),
        current_digest: local.current_digest,
        roots_digest_matched,
    });
    if published {
        BackgroundCustodyOutcome::Corroborated
    } else {
        // The epoch moved between the last check and the write, so nothing
        // landed. Reporting success would send a reader to the cache for
        // evidence that is not there.
        BackgroundCustodyOutcome::NotCorroborated(NotCorroboratedReason::PremisesMoved)
    }
}
