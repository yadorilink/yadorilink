#![cfg(test)]
//! What a peer's connection state means to a user, read back through the
//! real `Status` and `Health` control-socket requests.
//!
//! Four claims are pinned for every connection state:
//!
//! - how the peer appears in `StatusResponse.peers` (reachability, route,
//!   failure reason), which the CLI and the desktop app render verbatim;
//! - whether it counts in `HealthResponse.connected_peer_count`;
//! - whether it raises a `peer_disconnected` attention reason;
//! - whether a file whose content only that peer holds is available to
//!   fetch now. Durability is asserted alongside and must never move with
//!   connectivity: a fresh custody confirmation stays a fresh confirmation
//!   whether or not its peer can be reached this minute.
//!
//! The connection state is set only through [`observe`], which feeds the
//! iroh connectivity runtime the same reports its endpoint gives it. Changing
//! where reachability comes from means changing `observe` (and the source
//! behind it), not these tests: they state what each state must mean,
//! whoever reports it.

use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    DaemonControlRequest, FetchAvailability, GroupDurabilityStatus, HealthRequest, HealthResponse,
    PeerReachability, PeerStatus, RouteKind, StatusRequest, StatusResponse, UnreachableCategory,
};
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

use crate::daemon_state::DaemonState;
use crate::peer_connectivity_runtime::reachability_source_for_tests as source;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "group-1";
const LINK_PATH: &str = "/tmp/photos";
const PEER: &str = "nas";

/// A connection state a peer can be in, named by what is true on the
/// network rather than by which component notices it.
#[derive(Debug, Clone, Copy)]
enum PeerPath {
    /// Being dialled; neither up nor given up on.
    Dialing,
    /// Up over a direct path.
    Direct,
    /// Up, but only through a relay server.
    RelayOnly,
    /// Tried and not reachable, for the given reason.
    Unreachable(crate::peer_registry::UnreachableCategory),
    /// Was up; ended, and nothing replaced it.
    Ended,
}

/// Puts `PEER` into `path`. The only place these tests touch the source of
/// peer reachability.
fn observe(state: &Arc<DaemonState>, path: PeerPath) {
    match path {
        PeerPath::Dialing => source::dialing(state, PEER),
        PeerPath::Direct => source::connected_directly(state, PEER),
        PeerPath::RelayOnly => source::relay_only(state, PEER),
        PeerPath::Unreachable(why) => source::failed(state, PEER, why),
        PeerPath::Ended => source::ended(state, PEER),
    }
}

/// A device with one on-demand link holding one file whose content is not
/// local, where `PEER` is the group's full-replica writer and has freshly
/// confirmed it holds the group's current content. Whether that file can be
/// fetched now then depends on nothing but `PEER`'s reachability.
fn device_whose_content_only_the_peer_holds() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let replica = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), replica, store);

    let links = state.replica_coordinator.link_repository();
    links.add_link(LINK_PATH, GROUP).unwrap();
    links.set_materialization_policy(LINK_PATH, MaterializationPolicy::OnDemand).unwrap();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            GROUP,
            &FileRecord {
                path: "a.bin".into(),
                size: 4,
                mtime_unix_nanos: 0,
                blocks: vec![BlockInfo { hash: vec![1u8; 32], offset: 0, size: 4 }],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    state
        .replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(GROUP, "a.bin", MaterializationState::Remote, &permit)
        .unwrap();

    state.set_peer_group_writer(PEER, GROUP, true);
    state.authority.set_peer_group_full_replica(PEER, GROUP, true);
    let current_digest = state.local_root_set_summary(GROUP).unwrap().current_digest;
    assert!(
        state.publish_background_custody(
            GROUP,
            crate::background_custody::BackgroundCustodyEvidence::Corroborated {
                peer_device_id: Some(PEER.into()),
                current_digest,
                roots_digest_matched: true,
            },
            state.authority.membership_generation(),
            0,
        ),
        "precondition: the peer's custody confirmation is accepted as current"
    );
    state
}

async fn request(state: &Arc<DaemonState>, payload: ReqPayload) -> RespPayload {
    let response = super::handle_request(
        &crate::control_context::ControlContext::from_state(state.clone()),
        DaemonControlRequest {
            payload: Some(payload),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await;
    response.payload.expect("the daemon answers every well-formed request")
}

async fn status(state: &Arc<DaemonState>) -> StatusResponse {
    match request(state, ReqPayload::Status(StatusRequest {})).await {
        RespPayload::Status(status) => status,
        other => panic!("expected a Status response, got {other:?}"),
    }
}

async fn health(state: &Arc<DaemonState>) -> HealthResponse {
    match request(state, ReqPayload::Health(HealthRequest {})).await {
        RespPayload::Health(health) => health,
        other => panic!("expected a Health response, got {other:?}"),
    }
}

/// Everything a user can learn about `PEER` from one status and one health
/// request.
struct Seen {
    peer: Option<PeerStatus>,
    connected_peer_count: u32,
    flagged_disconnected: bool,
    fetch: FetchAvailability,
    durability: GroupDurabilityStatus,
}

async fn seen(state: &Arc<DaemonState>) -> Seen {
    let status = status(state).await;
    let link = status
        .links
        .iter()
        .find(|link| link.group_id == GROUP)
        .expect("the linked group is listed in status");
    Seen {
        peer: status.peers.iter().find(|peer| peer.device_id == PEER).cloned(),
        connected_peer_count: health(state).await.connected_peer_count,
        flagged_disconnected: status
            .attention_reasons
            .contains(&format!("peer_disconnected:{PEER}")),
        fetch: link.fetch_availability(),
        durability: link.durability_status(),
    }
}

#[tokio::test]
async fn a_directly_connected_peer_shows_connected_direct_and_is_available_now() {
    let state = device_whose_content_only_the_peer_holds();
    observe(&state, PeerPath::Direct);

    let seen = seen(&state).await;
    let peer = seen.peer.expect("a connected peer is listed in status");
    assert_eq!(peer.reachability(), PeerReachability::Connected);
    assert_eq!(peer.route_kind(), RouteKind::Direct, "the route of a direct path is shown");
    assert_eq!(peer.unreachable_category(), UnreachableCategory::Unspecified);
    assert_eq!(seen.connected_peer_count, 1, "a connected peer counts as connected");
    assert!(!seen.flagged_disconnected, "a connected peer needs no attention");
    assert_eq!(
        seen.fetch,
        FetchAvailability::AvailableNow,
        "content a reachable, confirmed complete copy holds can be fetched now"
    );
    assert_eq!(seen.durability, GroupDurabilityStatus::Protected);
}

#[tokio::test]
async fn an_unreachable_peer_shows_why_and_is_not_available_now() {
    use crate::peer_registry::UnreachableCategory as Why;
    for (why, shown) in [
        (Why::NoCandidates, UnreachableCategory::NoCandidates),
        (Why::NoResponse, UnreachableCategory::NoResponse),
        (Why::UdpBlocked, UnreachableCategory::UdpBlocked),
        (Why::HandshakeRefused, UnreachableCategory::HandshakeRefused),
        (Why::DeviceReplaced, UnreachableCategory::DeviceReplaced),
    ] {
        let state = device_whose_content_only_the_peer_holds();
        observe(&state, PeerPath::Unreachable(why));

        let seen = seen(&state).await;
        let peer = seen.peer.expect("an unreachable peer stays listed so the reason is visible");
        assert_eq!(peer.reachability(), PeerReachability::Unreachable, "{why:?}");
        assert_eq!(peer.unreachable_category(), shown, "the reason is carried through");
        assert_eq!(peer.route_kind(), RouteKind::Unspecified, "no path, so no route: {why:?}");
        assert_eq!(seen.connected_peer_count, 0, "{why:?}");
        assert_eq!(
            seen.flagged_disconnected,
            why != Why::DeviceReplaced,
            "an unreachable peer needs attention, a replaced one is gone for good: {why:?}"
        );
        assert_eq!(seen.fetch, FetchAvailability::UnavailableNow, "{why:?}");
        assert_eq!(
            seen.durability,
            GroupDurabilityStatus::Protected,
            "a fresh confirmation is not withdrawn because its peer is offline: {why:?}"
        );
    }
}

#[tokio::test]
async fn a_peer_still_being_dialled_shows_connecting_and_is_not_available_now() {
    let state = device_whose_content_only_the_peer_holds();
    observe(&state, PeerPath::Dialing);

    let seen = seen(&state).await;
    let peer = seen.peer.expect("a peer being dialled is listed in status");
    assert_eq!(peer.reachability(), PeerReachability::Connecting);
    assert_eq!(peer.route_kind(), RouteKind::Unspecified);
    assert_eq!(seen.connected_peer_count, 0);
    assert!(!seen.flagged_disconnected, "dialling is transient, not a reason for attention");
    assert_eq!(seen.fetch, FetchAvailability::UnavailableNow);
    assert_eq!(seen.durability, GroupDurabilityStatus::Protected);
}

#[tokio::test]
async fn a_peer_whose_connection_ended_leaves_status_and_is_not_available_now() {
    let state = device_whose_content_only_the_peer_holds();
    observe(&state, PeerPath::Direct);
    let before = seen(&state).await;
    assert_eq!(before.connected_peer_count, 1, "precondition: the peer was connected");
    assert_eq!(before.fetch, FetchAvailability::AvailableNow, "precondition");

    observe(&state, PeerPath::Ended);

    let seen = seen(&state).await;
    assert!(seen.peer.is_none(), "an ended connection leaves no stale entry behind");
    assert_eq!(seen.connected_peer_count, 0);
    assert!(!seen.flagged_disconnected);
    assert_eq!(seen.fetch, FetchAvailability::UnavailableNow);
    assert_eq!(seen.durability, GroupDurabilityStatus::Protected);
}

#[tokio::test]
async fn a_peer_never_observed_is_not_listed_and_is_not_available_now() {
    let state = device_whose_content_only_the_peer_holds();

    let seen = seen(&state).await;
    assert!(seen.peer.is_none(), "no connection state has been reported for the peer yet");
    assert_eq!(seen.connected_peer_count, 0);
    assert!(!seen.flagged_disconnected, "never observed is not known to be down");
    assert_eq!(seen.fetch, FetchAvailability::UnavailableNow);
    assert_eq!(seen.durability, GroupDurabilityStatus::Protected);
}

/// A peer whose only path is a relay server is connected: reconciliation
/// and block transfer both run over that path. Status must say so, name the
/// route as something other than direct, count the peer, and let content it
/// holds be fetched now.
#[tokio::test]
async fn a_peer_reachable_only_through_a_relay_shows_connected_relay_and_is_available_now() {
    let state = device_whose_content_only_the_peer_holds();
    observe(&state, PeerPath::RelayOnly);

    let seen = seen(&state).await;
    let peer = seen.peer.expect("a relayed peer is listed in status");
    assert_eq!(peer.reachability(), PeerReachability::Connected);
    assert_ne!(peer.route_kind(), RouteKind::Direct, "a relayed path is not shown as direct");
    assert_ne!(peer.route_kind(), RouteKind::Unspecified, "a relayed path names its route");
    assert_eq!(peer.unreachable_category(), UnreachableCategory::Unspecified);
    assert_eq!(seen.connected_peer_count, 1, "a relayed peer counts as connected");
    assert!(!seen.flagged_disconnected);
    assert_eq!(
        seen.fetch,
        FetchAvailability::AvailableNow,
        "content a relayed, confirmed complete copy holds can be fetched now"
    );
    assert_eq!(seen.durability, GroupDurabilityStatus::Protected);
}

/// Durability never moves with connectivity: walking one confirmed peer
/// through every connection state changes what can be fetched now and never
/// the group's protection.
#[tokio::test]
async fn moving_through_every_connection_state_never_changes_durability() {
    let state = device_whose_content_only_the_peer_holds();
    for (path, fetch) in [
        (PeerPath::Dialing, FetchAvailability::UnavailableNow),
        (PeerPath::Direct, FetchAvailability::AvailableNow),
        (
            PeerPath::Unreachable(crate::peer_registry::UnreachableCategory::NoResponse),
            FetchAvailability::UnavailableNow,
        ),
        (PeerPath::Direct, FetchAvailability::AvailableNow),
        (PeerPath::Ended, FetchAvailability::UnavailableNow),
    ] {
        observe(&state, path);
        let seen = seen(&state).await;
        assert_eq!(seen.fetch, fetch, "fetch availability follows {path:?}");
        assert_eq!(seen.durability, GroupDurabilityStatus::Protected, "after {path:?}");
    }
}
