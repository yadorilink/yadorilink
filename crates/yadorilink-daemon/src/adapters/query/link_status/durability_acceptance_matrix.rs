#![cfg(test)]

use super::tests::{real_digest, test_state, upsert_file, GROUP, PATH};
use super::*;
use crate::durability_service::GroupDurabilityStatus;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

fn reader_for(state: std::sync::Arc<DaemonState>) -> DaemonLinkStatusReader {
    DaemonLinkStatusReader::new(state)
}

/// Scenario A: verified full replica online + On-Demand client online
/// + direct route -> Protected / OnDemand / Available.
#[tokio::test]
async fn scenario_a_confirmed_direct_peer_is_protected_ondemand_available() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    // The confirming peer must genuinely hold the writer + full-replica
    // role -- a confirmation for a peer with no such role is a state
    // production can never reach.
    state.set_peer_group_writer("nas", GROUP, true);
    state.authority.set_peer_group_full_replica("nas", GROUP, true);
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "nas",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    assert_eq!(
        state.peer_connectivity.reachability("nas"),
        Some(crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct)),
        "sanity check: this is genuinely a direct route"
    );
    let digest = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("nas".into()),
            current_digest: digest,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(views[0].durability_status, GroupDurabilityStatus::Protected, "A: Protected");
    assert_eq!(views[0].local_storage_state, LocalStorageState::OnDemand, "A: OnDemand");
    assert_eq!(views[0].fetch_availability, FetchAvailability::AvailableNow, "A: Available");
    assert_eq!(
        views[0].full_replica_device_ids,
        vec!["nas".to_string()],
        "A: the confirmed peer's real complete-copy role is reflected in the read model"
    );
    assert_eq!(
        views[0].custody_confirmed_by,
        vec!["nas".to_string()],
        "A: the peer that answered the custody check is the one named as protecting"
    );
}

/// Scenario C: the confirming peer is now UNREACHABLE, but the
/// confirmation itself is still fresh (within the staleness bound,
/// current membership generation, matching root digest) -- durability
/// stays whatever the still-valid evidence justifies (Protected),
/// while fetch_availability is separately, honestly `UnavailableNow`.
/// This is the exact `Durability != Connectivity` pairing: "protected but currently unreachable" must
/// never read as data loss.
#[tokio::test]
async fn scenario_c_confirmed_but_now_unreachable_peer_stays_protected_but_unavailable() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    state.set_peer_group_writer("nas", GROUP, true);
    state.authority.set_peer_group_full_replica("nas", GROUP, true);
    let digest = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("nas".into()),
            current_digest: digest,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );
    // The peer has since gone offline -- no reachability recorded at
    // all (equally valid: an explicit Unreachable would produce the
    // same fetch_availability outcome).

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].durability_status,
        GroupDurabilityStatus::Protected,
        "C: durability reflects the still-valid confirmation, not current reachability"
    );
    assert_eq!(
        views[0].fetch_availability,
        FetchAvailability::UnavailableNow,
        "C: fetch not confirmed -- a separate, honest claim from durability"
    );
}

/// Scenario D: no verified required custody -- structurally, no other
/// full-replica peer is configured at all -- even though SOME peer is
/// reachable. AtRisk despite connectivity: reachability
/// of a peer that isn't even a full-replica writer proves nothing.
#[tokio::test]
async fn scenario_d_no_full_replica_peer_configured_is_at_risk_despite_a_reachable_peer() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    // NOT locally hydrated, so `fetch_availability` genuinely exercises
    // the peer-dependent path too, not just local content.
    upsert_file(&state, "a.bin", false);
    // "peer" is reachable but never declared writer/full-replica for
    // this group at all.
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "peer",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    state.refresh_custody_confirmation(GROUP).await; // establishes ever_confirmation_swept

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].durability_status,
        GroupDurabilityStatus::AtRisk,
        "D: AtRisk -- structurally no complete-copy peer exists, connectivity is irrelevant"
    );
    assert_eq!(
        views[0].fetch_availability,
        FetchAvailability::UnavailableNow,
        "D: connectivity to a non-role peer does not grant fetch access either"
    );
}

/// Scenario E: a full-replica peer IS configured and reachable, but
/// custody has never actually been confirmed -- Unknown despite
/// connectivity (distinct from D: here the ROLE is real, just
/// unconfirmed; in D there is no role at all).
///
/// This device's OWN policy is On-Demand (not eager) so the local
/// "still catching up" `Protecting` branch never fires here -- if this
/// device were itself an eager full replica with a placeholder still
/// pending, the correct/distinct answer would be `Protecting`
/// (scenario F), not `Unknown`; using an on-demand local policy is
/// what genuinely isolates "peer configured+reachable+unconfirmed" as
/// the ONLY fact in play.
#[tokio::test]
async fn scenario_e_configured_but_unconfirmed_peer_is_unknown_despite_connectivity() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    // NOT locally hydrated, so `fetch_availability` genuinely exercises
    // the peer-dependent path too, not just local content.
    upsert_file(&state, "a.bin", false);
    state.set_peer_group_writer("nas", GROUP, true);
    state.authority.set_peer_group_full_replica("nas", GROUP, true);
    crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
        &state,
        "nas",
        crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
    );
    // Sweep runs, but never actually confirms (no real custody
    // round-trip infrastructure in this unit test -- the point is
    // "declared, reachable, never confirmed").
    state.refresh_custody_confirmation(GROUP).await;

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].durability_status,
        GroupDurabilityStatus::Unknown,
        "E: Unknown -- a real role exists but was never actually confirmed"
    );
    assert_eq!(
        views[0].fetch_availability,
        FetchAvailability::UnavailableNow,
        "E: reachability to a never-confirmed peer does not grant fetch access either"
    );
}

/// A folder linked moments ago has had no custody check yet (the first one
/// runs on the sweep tick). Its `Unknown` is "checking", not a failure to
/// confirm; once a round has run, `Unknown`/`AtRisk` stand on their own.
#[tokio::test]
async fn a_freshly_linked_group_is_checking_until_its_first_custody_round() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", true);

    let views = reader_for(state.clone()).list_links().unwrap();
    assert_eq!(views[0].durability_status, GroupDurabilityStatus::Unknown);
    assert!(views[0].durability_check_pending, "no round has run yet");

    state.refresh_custody_confirmation(GROUP).await;
    let views = reader_for(state).list_links().unwrap();
    assert!(!views[0].durability_check_pending, "a round ran: nothing is pending any more");
}

/// Scenario F: this device itself is a full replica still catching up
/// (a "protection operation running") -> Protecting.
#[tokio::test]
async fn scenario_f_local_full_replica_still_catching_up_is_protecting() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    // Eager (the default materialization policy) + a peer full
    // replica configured (so the structural AtRisk check doesn't
    // preempt Protecting) + still-partial local hydration.
    state.set_peer_group_writer("nas", GROUP, true);
    state.authority.set_peer_group_full_replica("nas", GROUP, true);
    upsert_file(&state, "a.bin", false);
    state.refresh_custody_confirmation(GROUP).await;

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].durability_status,
        GroupDurabilityStatus::Protecting,
        "F: Protecting -- this device is still becoming a complete copy"
    );
}

/// Scenario G: this device holds a full local copy, but the group's
/// durability policy is otherwise insufficient (no OTHER full-replica
/// peer is configured/confirmed at all) -- must NOT infer stronger
/// group protection than the policy actually proves. This is the
/// exact conflation the durability model rules out: `LocalStorageState::FullCopy`
/// (a true statement about THIS device) must not leak into
/// `durability_status` (a claim about the GROUP).
#[tokio::test]
async fn scenario_g_local_full_copy_alone_does_not_imply_group_protection() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    upsert_file(&state, "a.bin", true); // fully hydrated locally
    state.refresh_custody_confirmation(GROUP).await; // no peer -> not confirmed

    let views = reader_for(state).list_links().unwrap();
    assert_eq!(
        views[0].local_storage_state,
        LocalStorageState::FullCopy,
        "G: this device genuinely does hold a full local copy"
    );
    assert_eq!(
        views[0].durability_status,
        GroupDurabilityStatus::AtRisk,
        "G: but group-wide protection is NOT inferred from local completeness alone"
    );
}

/// Scenario K: a confirmed peer's route changes (direct ->
/// unreachable) across snapshots -- fetch_availability tracks the
/// transition, but durability_status stays Protected throughout
/// (unchanged custody evidence), never flickering with connectivity.
#[tokio::test]
async fn scenario_k_route_transitions_change_availability_never_durability() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link(PATH, GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy(PATH, MaterializationPolicy::OnDemand)
        .unwrap();
    upsert_file(&state, "a.bin", false);
    state.set_peer_group_writer("nas", GROUP, true);
    state.authority.set_peer_group_full_replica("nas", GROUP, true);
    let digest = real_digest(&state);
    state.publish_background_custody(
        GROUP,
        crate::background_custody::BackgroundCustodyEvidence::Corroborated {
            peer_device_id: Some("nas".into()),
            current_digest: digest,

            roots_digest_matched: true,
        },
        state.authority.membership_generation(),
        0,
    );

    for (reachability, expected_fetch) in [
        (
            crate::peer_registry::PeerReachability::Connected(crate::route::RouteKind::Direct),
            FetchAvailability::AvailableNow,
        ),
        (
            crate::peer_registry::PeerReachability::Unreachable(
                crate::peer_registry::UnreachableCategory::NoResponse,
            ),
            FetchAvailability::UnavailableNow,
        ),
    ] {
        crate::peer_connectivity_runtime::reachability_source_for_tests::reach(
            &state,
            "nas",
            reachability,
        );
        // Prove each iteration's setup is genuinely distinct (an
        // earlier version never
        // asserted the actual route/reachability transition itself,
        // only its downstream fetch_availability effect).
        assert_eq!(
            state.peer_connectivity.reachability("nas"),
            Some(reachability),
            "K sanity check: this iteration's route/reachability is genuinely set"
        );
        let views = DaemonLinkStatusReader::new(state.clone()).list_links().unwrap();
        assert_eq!(
            views[0].durability_status,
            GroupDurabilityStatus::Protected,
            "K: durability must never change across a pure connectivity transition"
        );
        assert_eq!(views[0].fetch_availability, expected_fetch, "K: availability tracks route");
    }
}
