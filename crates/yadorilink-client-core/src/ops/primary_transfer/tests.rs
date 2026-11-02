//! The primary-ownership transfer calls against a mock of the coordination wire contract
//! (primary ownership transfer and group creator).

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;
use crate::error::{DesktopError, RefusalReason};

fn access(server: &MockServer) -> CoordinationAccess {
    CoordinationAccess::new(yadorilink_fapi_client::test_support::offline_auth(), server.uri())
}

fn transfer_json(status: &str, direction: &str) -> serde_json::Value {
    serde_json::json!({
        "transferId": "tr-12345678", "groupId": "g-12345678", "groupName": "photos",
        "direction": direction, "status": status, "toDeviceId": "dev-target-1",
        "createdAt": 1_700_000_000, "expiresAt": 1_700_604_800
    })
}

fn body_of(request: &wiremock::Request) -> serde_json::Value {
    serde_json::from_slice(&request.body).unwrap()
}

async fn requests(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.unwrap()
}

#[tokio::test]
async fn offer_posts_the_wire_body_and_parses_the_transfer() {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/g-12345678/primary-transfer/offer"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "transfer": transfer_json("pending", "outgoing") }),
            ),
        )
        .mount(&server)
        .await;
    let offer =
        offer_in(&access(&server), state.path(), "g-12345678", "dev-target-1").await.unwrap();
    assert_eq!(offer.transfer_id, "tr-12345678");
    assert_eq!(offer.direction, TransferDirection::Outgoing);
    assert_eq!(offer.expires_at - offer.created_at, 7 * 24 * 3600);
    let sent = requests(&server).await;
    let body = body_of(&sent[0]);
    assert_eq!(body["targetDeviceId"], "dev-target-1");
    assert!(body["operationId"].as_str().is_some_and(|id| id.len() >= 8), "{body}");
    assert_eq!(body.as_object().unwrap().len(), 2, "the client sends no generation: {body}");
}

/// A lost reply must not mint a second operation: the retry (even after a restart, a fresh
/// store over the same directory) carries the same id; a definitive answer forgets it.
#[tokio::test]
async fn the_operation_id_survives_a_lost_reply_and_is_forgotten_after_the_answer() {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let route = "/shares/groups/g-12345678/primary-transfer/offer";
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "transfer": transfer_json("pending", "outgoing") }),
            ),
        )
        .mount(&server)
        .await;

    let first = offer_in(&access(&server), state.path(), "g-12345678", "dev-target-1").await;
    assert!(matches!(first, Err(CoreError::CoordinationPlaneUnreachable(_))), "{first:?}");
    offer_in(&access(&server), state.path(), "g-12345678", "dev-target-1").await.unwrap();
    // Answered: the next offer (say after a cancel) is a new request with its own id.
    offer_in(&access(&server), state.path(), "g-12345678", "dev-target-1").await.unwrap();
    // A different target is a different request, too.
    offer_in(&access(&server), state.path(), "g-12345678", "dev-other-22").await.unwrap();

    let ids: Vec<String> = requests(&server)
        .await
        .iter()
        .map(|r| body_of(r)["operationId"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(ids[0], ids[1], "the retry after a lost reply must replay the same operation");
    assert_ne!(ids[1], ids[2], "a finished request kept its operation id");
    assert_ne!(ids[2], ids[3]);
}

#[tokio::test]
async fn accept_cancel_and_decline_name_the_transfer_and_their_operation() {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/g-12345678/primary-transfer/accept"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transferId": "tr-12345678", "groupId": "g-12345678", "status": "accepted",
            "membershipGeneration": 9
        })))
        .mount(&server)
        .await;
    for (step, status) in [("cancel", "cancelled"), ("decline", "declined")] {
        Mock::given(method("POST"))
            .and(path(format!("/shares/groups/g-12345678/primary-transfer/{step}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "transfer": transfer_json(status, "outgoing") }),
            ))
            .mount(&server)
            .await;
    }
    let auth = access(&server);
    let accepted = accept_in(&auth, state.path(), "g-12345678", "tr-12345678").await.unwrap();
    assert_eq!(accepted.membership_generation, 9);
    assert_eq!(
        cancel_in(&auth, state.path(), "g-12345678", "tr-12345678").await.unwrap().status,
        "cancelled"
    );
    assert_eq!(
        decline_in(&auth, state.path(), "g-12345678", "tr-12345678").await.unwrap().status,
        "declined"
    );
    for request in requests(&server).await {
        let body = body_of(&request);
        assert_eq!(body["transferId"], "tr-12345678");
        assert!(body["operationId"].is_string());
    }
}

#[tokio::test]
async fn list_reads_both_directions_and_tolerates_a_newer_direction() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shares/primary-transfers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "transfers": [
                transfer_json("pending", "outgoing"),
                transfer_json("pending", "incoming"),
                transfer_json("pending", "sideways"),
            ]
        })))
        .mount(&server)
        .await;
    let listed = list_with(&access(&server)).await.unwrap();
    let directions: Vec<_> = listed.iter().map(|t| t.direction).collect();
    assert_eq!(
        directions,
        [TransferDirection::Outgoing, TransferDirection::Incoming, TransferDirection::Unrecognized]
    );
    assert_eq!(find_offer(&listed, "photos", TransferDirection::Incoming).len(), 1);
}

/// Every refusal the service documents arrives typed, never matched by text; the reason word
/// survives into the desktop taxonomy.
#[tokio::test]
async fn each_documented_refusal_is_typed_and_reaches_the_desktop_taxonomy() {
    let cases = [
        (
            403,
            "not_primary",
            PrimaryTransferRefusal::NotPrimary,
            RefusalReason::PrimaryTransferNotPrimary,
        ),
        (
            409,
            "target_not_member",
            PrimaryTransferRefusal::TargetNotMember,
            RefusalReason::PrimaryTransferTargetNotMember,
        ),
        (
            409,
            "target_same_account",
            PrimaryTransferRefusal::TargetSameAccount,
            RefusalReason::PrimaryTransferTargetSameAccount,
        ),
        (
            409,
            "offer_expired",
            PrimaryTransferRefusal::OfferExpired,
            RefusalReason::PrimaryTransferOfferExpired,
        ),
        (
            409,
            "group_not_active",
            PrimaryTransferRefusal::GroupNotActive,
            RefusalReason::PrimaryTransferGroupNotActive,
        ),
        (409, "conflict", PrimaryTransferRefusal::Conflict, RefusalReason::PrimaryTransferConflict),
    ];
    for (status, reason, refusal, desktop) in cases {
        let state = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status).set_body_json(serde_json::json!({
                "error": "primary_transfer_refused", "reason": reason,
                "message": "words the client must ignore"
            })))
            .mount(&server)
            .await;
        let error = accept_in(&access(&server), state.path(), "g-12345678", "tr-12345678")
            .await
            .unwrap_err();
        assert!(
            matches!(&error, CoreError::PrimaryTransferRefused(r) if *r == refusal),
            "{error:?}"
        );
        assert_eq!(refusal.reason(), reason);
        assert!(!error.to_string().contains("ignore"));
        match DesktopError::from(error) {
            DesktopError::Refused { reason: got, .. } => assert_eq!(got, desktop),
            other => panic!("{other:?}"),
        }
        // A refusal is definitive: the operation id is forgotten, so a retry is a new request.
        let first = PendingStore::at(state.path().join("provider-pending.json"))
            .token_for(&signature("accept", "g-12345678", "tr-12345678"))
            .unwrap();
        let again = PendingStore::at(state.path().join("provider-pending.json"))
            .token_for(&signature("accept", "g-12345678", "tr-12345678"))
            .unwrap();
        assert_eq!(first, again);
        let sent = body_of(&requests(&server).await[0])["operationId"].as_str().unwrap().to_owned();
        assert_ne!(sent, first, "a refused request kept its operation id");
    }
}

#[tokio::test]
async fn an_unknown_offer_is_not_found_a_quota_is_the_ordinary_limit_and_an_odd_reason_is_not_typed(
) {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/gone-group/primary-transfer/decline"))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"error": "not_found"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/g-12345678/primary-transfer/accept"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "error": "quota_exceeded", "resource": "folder_groups", "limit": 5, "current": 5
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/g-12345678/primary-transfer/cancel"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "error": "primary_transfer_refused", "reason": "from_the_future"
        })))
        .mount(&server)
        .await;
    let auth = access(&server);
    let not_found = decline_in(&auth, state.path(), "gone-group", "tr-1").await.unwrap_err();
    assert!(matches!(
        not_found,
        CoreError::PrimaryTransferRefused(PrimaryTransferRefusal::NotFound)
    ));
    let quota = accept_in(&auth, state.path(), "g-12345678", "tr-12345678").await.unwrap_err();
    assert!(matches!(&quota, CoreError::LimitExceeded { kind: LimitKind::Quota, .. }), "{quota:?}");
    assert!(matches!(
        DesktopError::from(quota),
        DesktopError::PermissionDenied {
            reason: crate::error::PermissionDeniedReason::QuotaExceeded,
            ..
        }
    ));
    let odd = cancel_in(&auth, state.path(), "g-12345678", "tr-12345678").await.unwrap_err();
    assert!(matches!(odd, CoreError::Other(_)), "{odd:?}");
}

#[test]
fn the_documented_reasons_round_trip() {
    for reason in [
        "not_primary",
        "target_not_member",
        "target_same_account",
        "offer_expired",
        "group_not_active",
        "conflict",
    ] {
        assert_eq!(PrimaryTransferRefusal::from_reason(reason).unwrap().reason(), reason);
    }
    assert_eq!(PrimaryTransferRefusal::from_reason("target_not_full_member"), None);
    assert_eq!(PrimaryTransferRefusal::from_reason("stale_membership"), None);
}

async fn listing(server: &MockServer, transfers: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/shares/primary-transfers"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "transfers": transfers })),
        )
        .mount(server)
        .await;
}

fn offer_json(id: &str, group: &str, direction: &str) -> serde_json::Value {
    serde_json::json!({
        "transferId": id, "groupId": format!("gid-{group}"), "groupName": group,
        "direction": direction, "status": "pending", "toDeviceId": "dev-target-1",
        "createdAt": 1_700_000_000, "expiresAt": 1_700_604_800
    })
}

#[tokio::test]
async fn a_selector_names_an_offer_by_id_folder_id_or_name_within_one_direction() {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    listing(
        &server,
        serde_json::json!([
            offer_json("t1", "photos", "outgoing"),
            offer_json("t2", "docs", "incoming")
        ]),
    )
    .await;
    let auth = access(&server);
    let pick = |step, selector: &'static str| {
        let auth = auth.clone();
        let dir = state.path().to_owned();
        async move { select_offer_in(&auth, &dir, step, selector).await }
    };
    assert_eq!(pick(SettleStep::Cancel, "photos").await.unwrap().transfer_id, "t1");
    assert_eq!(pick(SettleStep::Accept, "gid-docs").await.unwrap().transfer_id, "t2");
    assert_eq!(pick(SettleStep::Cancel, "t1").await.unwrap().transfer_id, "t1");
    // The other side's offer is not selectable by the wrong verb.
    assert!(matches!(
        pick(SettleStep::Cancel, "docs").await,
        Err(CoreError::PrimaryTransferRefused(PrimaryTransferRefusal::NotFound))
    ));
}

#[tokio::test]
async fn a_selector_matching_several_offers_is_refused_until_one_is_named() {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    listing(
        &server,
        serde_json::json!([
            offer_json("t1", "photos", "incoming"),
            offer_json("t2", "photos", "incoming")
        ]),
    )
    .await;
    let auth = access(&server);
    let several = select_offer_in(&auth, state.path(), SettleStep::Accept, "photos").await;
    assert!(matches!(several, Err(CoreError::Other(_))), "{several:?}");
    let named = select_offer_in(&auth, state.path(), SettleStep::Accept, "t2").await.unwrap();
    assert_eq!(named.transfer_id, "t2");
}

#[tokio::test]
async fn an_unlisted_offer_is_selected_from_its_unanswered_call_only_for_the_same_step() {
    let state = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    listing(&server, serde_json::json!([])).await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(503)).mount(&server).await;
    let auth = access(&server);
    let lost = accept_in(&auth, state.path(), "g-12345678", "tr-12345678").await;
    assert!(lost.is_err());

    let found =
        select_offer_in(&auth, state.path(), SettleStep::Accept, "tr-12345678").await.unwrap();
    assert_eq!(
        (found.group_id.as_str(), found.transfer_id.as_str()),
        ("g-12345678", "tr-12345678")
    );
    // A decline was never sent, so there is nothing to repeat.
    assert!(matches!(
        select_offer_in(&auth, state.path(), SettleStep::Decline, "tr-12345678").await,
        Err(CoreError::PrimaryTransferRefused(PrimaryTransferRefusal::NotFound))
    ));
}
