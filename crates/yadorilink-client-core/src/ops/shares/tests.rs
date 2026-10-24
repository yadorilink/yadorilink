#![cfg(test)]

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

fn base_edge() -> ShareEdgeInfo {
    ShareEdgeInfo {
        edge_id: "edge-1".into(),
        group_id: "group-1".into(),
        group_name: "photos".into(),
        device_id: "device-1".into(),
        state: "active".into(),
        role: Some("editor".into()),
    }
}

fn waiting_edge(device_id: &str, role: Option<&str>) -> ShareEdgeInfo {
    ShareEdgeInfo {
        state: STATE_PENDING_APPROVAL.into(),
        device_id: device_id.into(),
        role: role.map(str::to_string),
        ..base_edge()
    }
}

/// `GET /shares` sends camelCase keys. The literal here is the coordination
/// plane's real `ShareEdgeInfo` response shape, including the fields added for
/// approval requests.
#[test]
fn share_edge_info_deserializes_the_coordination_planes_camelcase_shape() {
    let parsed: ShareEdgeInfo = serde_json::from_str(
        r#"{"edgeId":"e-1","groupId":"g-1","groupName":"photos","deviceId":"d-1",
            "state":"pending_approval","role":"viewer"}"#,
    )
    .unwrap();
    assert_eq!(parsed.edge_id, "e-1");
    assert_eq!(parsed.group_id, "g-1");
    assert_eq!(parsed.group_name, "photos");
    assert_eq!(parsed.device_id, "d-1");
    assert_eq!(parsed.state, STATE_PENDING_APPROVAL);
    assert_eq!(parsed.role.as_deref(), Some("viewer"));
}

/// `role` is genuinely nullable on the wire, so an explicit JSON `null` must
/// parse rather than fail the whole listing.
#[test]
fn share_edge_info_accepts_a_null_role() {
    let parsed: ShareEdgeInfo = serde_json::from_str(
        r#"{"edgeId":"e-1","groupId":"g-1","groupName":"photos","deviceId":"d-1",
            "state":"pending","role":null}"#,
    )
    .unwrap();
    assert_eq!(parsed.role, None);
}

/// The narrowing from a `/shares` edge to a decision must not lose a field
/// the owner needs.
#[test]
fn a_pending_approval_keeps_every_field_a_decision_needs() {
    let request = PendingApproval::from_edge(waiting_edge("device-2", Some("viewer")));
    assert_eq!(request.group_id, "group-1");
    assert_eq!(request.group_name, "photos");
    assert_eq!(request.device_id, "device-2");
    assert_eq!(request.role.as_deref(), Some("viewer"));
}

fn owned(group_ids: &[&str]) -> HashSet<String> {
    group_ids.iter().map(|id| (*id).to_string()).collect()
}

/// The state half of the approval filter. An `active` member is not a
/// request, and neither is a `pending` edge whose own device has not finished
/// its side.
#[test]
fn pending_approval_filter_selects_only_edges_in_the_awaiting_state() {
    let edges = vec![
        base_edge(),
        waiting_edge("device-waiting", Some("viewer")),
        ShareEdgeInfo { state: "pending".into(), ..base_edge() },
        ShareEdgeInfo { state: "active".to_string(), ..base_edge() },
    ];
    let selected = approval_requests_awaiting_owner(edges, &owned(&["group-1"]));
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].device_id, "device-waiting");
}

/// The ownership half: an invited account's own awaiting-approval edge is in
/// its own listing too, and must never be shown to it as something to
/// approve.
#[test]
fn pending_approval_filter_excludes_a_request_on_a_group_this_account_does_not_own() {
    fn on_my_group() -> ShareEdgeInfo {
        ShareEdgeInfo { group_id: "group-mine".into(), ..waiting_edge("device-b", Some("viewer")) }
    }
    fn on_someone_elses_group() -> ShareEdgeInfo {
        ShareEdgeInfo {
            group_id: "group-theirs".into(),
            group_name: "someone-elses-photos".into(),
            ..waiting_edge("device-of-this-account", Some("editor"))
        }
    }

    let as_owner = approval_requests_awaiting_owner(
        vec![on_my_group(), on_someone_elses_group()],
        &owned(&["group-mine"]),
    );
    assert_eq!(as_owner.len(), 1);
    assert_eq!(as_owner[0].group_id, "group-mine");

    let as_invitee = approval_requests_awaiting_owner(vec![on_someone_elses_group()], &owned(&[]));
    assert!(
        as_invitee.is_empty(),
        "an account that owns no groups must never be shown an approval request"
    );
}

/// The approve route reads no body, so this must serialize to an empty JSON
/// object -- in particular it must never grow a `role` key.
#[test]
fn approve_request_body_is_empty_and_carries_no_role() {
    let body = serde_json::to_value(ApproveRequest {}).unwrap();
    assert_eq!(body, serde_json::json!({}));
}

#[test]
fn approve_response_deserializes_both_outcomes() {
    let approved: ApproveResponse = serde_json::from_str(r#"{"result":"approved"}"#).unwrap();
    assert_eq!(approved.result, "approved");
    let already: ApproveResponse = serde_json::from_str(r#"{"result":"already_active"}"#).unwrap();
    assert_eq!(already.result, "already_active");
}

#[test]
fn joinable_group_info_deserializes_the_coordination_planes_camelcase_shape() {
    let parsed: JoinableGroupInfo =
        serde_json::from_str(r#"{"groupId":"g-1","name":"photos"}"#).unwrap();
    assert_eq!(parsed.group_id, "g-1");
    assert_eq!(parsed.name, "photos");
}

/// The coordination plane's route handlers read camelCase JSON keys, so these
/// request bodies must serialize to exactly those keys.
#[test]
fn request_bodies_serialize_camelcase_for_the_coordination_plane() {
    let create =
        serde_json::to_value(CreateGroupRequest { name: "g", creating_device_id: "d" }).unwrap();
    assert_eq!(create["creatingDeviceId"], "d");
    assert!(create.get("creating_device_id").is_none());

    let device =
        serde_json::to_value(GrantRequest { device_id: "d", role: Some("editor") }).unwrap();
    assert_eq!(device["deviceId"], "d");
    assert!(device.get("device_id").is_none());
    assert_eq!(device["role"], "editor");

    let prepare_create = serde_json::to_value(PrepareCreateRequest {
        operation_id: "op",
        name: "g",
        creating_device_id: "d",
    })
    .unwrap();
    assert_eq!(prepare_create["operationId"], "op");
    assert_eq!(prepare_create["creatingDeviceId"], "d");

    let prepare_join = serde_json::to_value(PrepareJoinRequest {
        operation_id: "op",
        device_id: "d",
        storage_mode: "eager",
    })
    .unwrap();
    assert_eq!(prepare_join["operationId"], "op");
    assert_eq!(prepare_join["deviceId"], "d");
    assert_eq!(prepare_join["storageMode"], "eager");

    let join_operation =
        serde_json::to_value(JoinOperationBody { operation_id: "op", device_id: "d" }).unwrap();
    assert_eq!(join_operation["operationId"], "op");
    assert_eq!(join_operation["deviceId"], "d");

    let operation_only = serde_json::to_value(OperationIdBody { operation_id: "op" }).unwrap();
    assert_eq!(operation_only["operationId"], "op");
}

/// `reqwest`'s `.json(body)` serializes `None` as an explicit JSON `null`,
/// which the grant route treats as invalid rather than "use the default".
#[test]
fn grant_request_omits_the_role_key_entirely_when_none_but_serializes_it_when_some() {
    let omitted = serde_json::to_value(GrantRequest { device_id: "d", role: None }).unwrap();
    assert!(omitted.get("role").is_none(), "got: {omitted}");
    assert_eq!(omitted["deviceId"], "d");

    let present =
        serde_json::to_value(GrantRequest { device_id: "d", role: Some("viewer") }).unwrap();
    assert_eq!(present["role"], "viewer");

    let omitted_json = serde_json::to_string(&GrantRequest { device_id: "d", role: None }).unwrap();
    assert!(!omitted_json.contains("role"), "expected no `role` key in {omitted_json}");
}

#[test]
fn grant_response_deserializes_both_created_and_unchanged_shapes() {
    let created: GrantResponse =
        serde_json::from_str(r#"{"role":"editor","created":true}"#).unwrap();
    assert_eq!(created.role, "editor");
    assert!(created.created);

    let unchanged: GrantResponse =
        serde_json::from_str(r#"{"role":"editor","created":false}"#).unwrap();
    assert_eq!(unchanged.role, "editor");
    assert!(!unchanged.created);
}

#[test]
fn group_member_info_deserializes_the_coordination_planes_camelcase_response() {
    let json = r#"{
        "deviceId": "dev-1",
        "deviceName": "laptop",
        "role": "unknown",
        "isSameAccount": false,
        "isCallerAccount": false,
        "storageMode": "on-demand",
        "online": false,
        "lastSeenUnix": 0
    }"#;
    let member: GroupMemberInfo = serde_json::from_str(json).unwrap();
    assert_eq!(member.device_id, "dev-1");
    assert_eq!(member.device_name, "laptop");
    assert_eq!(member.role, "unknown");
    assert!(!member.is_same_account);
    assert!(!member.is_caller_account);
    assert_eq!(member.storage_mode, "on-demand");
    assert!(!member.online);
}

/// A live role change may request viewer or editor, never owner -- checked
/// locally as well as server-side, so a mistyped role fails before a network
/// round trip.
#[test]
fn a_role_change_accepts_viewer_and_editor_and_refuses_owner() {
    assert!(validate_changeable_role("viewer").is_ok());
    assert!(validate_changeable_role("editor").is_ok());

    let refused = validate_changeable_role("owner").unwrap_err();
    assert!(matches!(refused, CoreError::InvalidInput(_)), "{refused:?}");
    let refused = refused.to_string();
    assert!(refused.contains("owner"), "{refused}");
    assert!(refused.contains("viewer or editor"), "{refused}");

    assert_eq!(CHANGEABLE_ROLES, ["viewer", "editor"]);
}

#[test]
fn a_role_change_refuses_a_role_the_coordination_plane_would_refuse() {
    for role in ["", "Viewer", "EDITOR", "owner ", "admin", "read-only"] {
        assert!(validate_changeable_role(role).is_err(), "{role:?} must be refused locally");
    }
}

/// A rejected role must never reach the coordination plane at all. No route
/// is mounted on this server, so `received_requests()` is direct proof of
/// whether a call was made.
#[tokio::test]
async fn change_role_resolved_issues_no_request_at_all_for_a_refused_role() {
    let server = MockServer::start().await;
    let result = change_role_resolved("group-1", "device-1", "owner").await;

    assert!(result.is_err(), "an unchangeable role must be refused, not sent");
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[test]
fn change_role_request_serializes_the_coordination_planes_camelcase_shape() {
    let body =
        serde_json::to_value(ChangeRoleRequest { device_id: "dev-1", role: "viewer" }).unwrap();
    assert_eq!(body, serde_json::json!({"deviceId": "dev-1", "role": "viewer"}));
}

#[test]
fn a_change_role_request_always_carries_an_explicit_role() {
    let body =
        serde_json::to_value(ChangeRoleRequest { device_id: "dev-1", role: "editor" }).unwrap();
    assert_eq!(body["role"], "editor");
    assert_eq!(body.as_object().unwrap().len(), 2, "no other key belongs in this body");
}

fn revoke_error(
    code: ApplicationErrorCode,
    message: &str,
) -> Option<revoke_device_command_response::Result> {
    Some(revoke_device_command_response::Result::Error(
        yadorilink_ipc_proto::daemonctl::ApplicationCommandError {
            code: code as i32,
            message: message.to_string(),
            group_ids: vec!["group-1".to_string()],
            operation_id: String::new(),
        },
    ))
}

/// The durability refusal is the ONE revoke failure a force override can get
/// past, recognized by its error code, not by its wording.
#[test]
fn a_durability_refusal_is_reported_as_an_outcome_that_can_be_overridden() {
    let attempt = classify_revoke_result(revoke_error(
        ApplicationErrorCode::ReplicaNotReady,
        "another complete copy is not ready for: [\"group-1\"]",
    ))
    .expect("a durability refusal is an outcome, not an error");
    match attempt {
        RevokeAttempt::NotDurable { message, group_ids } => {
            assert!(message.contains("not ready"), "{message}");
            assert_eq!(group_ids, vec!["group-1".to_string()]);
        }
        RevokeAttempt::Committed(_) => panic!("a refused revoke must not read as committed"),
    }
}

/// Every other failure stays an error, typed with the daemon's own code.
#[test]
fn a_revoke_failure_that_forcing_cannot_help_is_never_offered_as_an_override() {
    for code in [
        ApplicationErrorCode::TargetNotFound,
        ApplicationErrorCode::CoordinationRejected,
        ApplicationErrorCode::CoordinationTransport,
        ApplicationErrorCode::LocalIdentityUnavailable,
        ApplicationErrorCode::Persistence,
        ApplicationErrorCode::Unspecified,
    ] {
        match classify_revoke_result(revoke_error(code, "something went wrong")) {
            Err(error) => assert!(error.is_command_error(code), "{code:?}: {error:?}"),
            Ok(_) => panic!("{code:?} must stay an error, not an overridable refusal"),
        }
    }
    assert!(classify_revoke_result(None).is_err());
}

#[test]
fn list_groups_response_envelope_deserializes_the_coordination_planes_camelcase_body() {
    let resp: ListGroupsResponse =
        serde_json::from_str(r#"{"groups":[{"groupId":"g-1","name":"docs"}]}"#).unwrap();
    assert_eq!(resp.groups.len(), 1);
    assert_eq!(resp.groups[0].group_id, "g-1");
    assert_eq!(resp.groups[0].name, "docs");
}

#[test]
fn folder_group_info_deserializes_the_coordination_planes_camelcase_shape() {
    let parsed: FolderGroupInfo =
        serde_json::from_str(r#"{"groupId":"g-1","name":"photos"}"#).unwrap();
    assert_eq!(parsed.group_id, "g-1");
    assert_eq!(parsed.name, "photos");
}

/// Mounts the two listings `resolve_group_id` consults, points the
/// coordination HTTP client at the mock, and resolves `group_name` over a real
/// HTTP round trip.
async fn resolve_against_mocked_listings(
    group_name: &str,
    owned: serde_json::Value,
    shares: serde_json::Value,
) -> (MockServer, Result<String, CoreError>) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shares/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(owned))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/shares"))
        .respond_with(ResponseTemplate::new(200).set_body_json(shares))
        .mount(&server)
        .await;

    let result = resolve_group_id(
        &crate::coordination::http_client::CoordinationAccess::new(
            yadorilink_fapi_client::test_support::offline_auth(),
            server.uri(),
        ),
        group_name,
    )
    .await;
    (server, result)
}

fn requested_paths(requests: &[wiremock::Request]) -> Vec<String> {
    requests.iter().map(|r| r.url.path().to_string()).collect()
}

fn cross_account_edge_listing() -> serde_json::Value {
    serde_json::json!({
        "edges": [{
            "edgeId": "7",
            "groupId": "group-owned-by-another-account",
            "groupName": "docs",
            "deviceId": "this-accounts-own-device",
            "state": "active",
        }]
    })
}

/// An account that reached a group only by accepting a cross-account invite
/// owns no folder groups, so the owner-scoped listing is empty for it; the
/// name resolves through the account-visible edge listing instead.
#[tokio::test]
async fn resolve_group_id_falls_back_to_the_shares_listing_for_a_member_account() {
    let (server, result) = resolve_against_mocked_listings(
        "docs",
        serde_json::json!({ "groups": [] }),
        cross_account_edge_listing(),
    )
    .await;

    assert_eq!(result.unwrap(), "group-owned-by-another-account");
    assert_eq!(
        requested_paths(&server.received_requests().await.unwrap()),
        vec!["/shares/groups".to_string(), "/shares".to_string()]
    );
}

/// `state` is required, so a row that omits it is a malformed response rather
/// than an edge whose state is merely unknown.
#[tokio::test]
async fn a_shares_listing_row_without_a_state_is_rejected_as_malformed() {
    let (_server, result) = resolve_against_mocked_listings(
        "docs",
        serde_json::json!({ "groups": [] }),
        serde_json::json!({
            "edges": [{
                "edgeId": "7",
                "groupId": "group-owned-by-another-account",
                "groupName": "docs",
                "deviceId": "this-accounts-own-device",
            }]
        }),
    )
    .await;
    assert!(result.is_err());
}

/// A name present in both listings resolves to this account's own group, and
/// the second request is never issued at all.
#[tokio::test]
async fn resolve_group_id_prefers_an_owned_group_and_skips_the_fallback_entirely() {
    let (server, result) = resolve_against_mocked_listings(
        "docs",
        serde_json::json!({ "groups": [{ "groupId": "my-own-group", "name": "docs" }] }),
        cross_account_edge_listing(),
    )
    .await;

    assert_eq!(result.unwrap(), "my-own-group");
    assert_eq!(
        requested_paths(&server.received_requests().await.unwrap()),
        vec!["/shares/groups".to_string()]
    );
}

/// A name in neither listing fails as invalid input, and the message names
/// both ways to get access.
#[tokio::test]
async fn resolve_group_id_fails_for_a_name_in_neither_listing() {
    let (_server, result) = resolve_against_mocked_listings(
        "nonexistent",
        serde_json::json!({ "groups": [] }),
        serde_json::json!({ "edges": [] }),
    )
    .await;

    let error = result.expect_err("a not-found refusal");
    assert_eq!(error.hint(), Some(Hint::CreateOrAcceptShare));
    let CoreError::Hinted { error: inner, .. } = error else { panic!("hinted: {error:?}") };
    let CoreError::InvalidInput(message) = *inner else { panic!("not found, got {inner:?}") };
    assert_eq!(message, "no folder group named \"nonexistent\" is visible to this account");
    assert!(!message.contains("yadorilink "), "client-core names no CLI command: {message}");
}

#[test]
fn storage_mode_words_map_to_the_on_demand_flag_and_back() {
    assert_eq!(storage_mode_str(false), "eager");
    assert_eq!(storage_mode_str(true), "on-demand");
    for (word, on_demand) in [
        ("eager", false),
        ("everything", false),
        ("EAGER", false),
        ("on-demand", true),
        ("ondemand", true),
        ("needed", true),
    ] {
        assert_eq!(parse_storage_mode(word).unwrap(), on_demand, "{word}");
    }
    let refused = parse_storage_mode("bogus").unwrap_err();
    assert!(matches!(refused, CoreError::InvalidInput(_)));
    assert_eq!(
        refused.to_string(),
        "invalid --storage-mode \"bogus\" (expected eager or on-demand)"
    );
}

#[test]
fn list_pending_invites_response_deserializes_the_coordination_planes_camelcase_shape() {
    let body = serde_json::json!({
        "invites": [{
            "inviteId": "invite-1",
            "groupId": "group-1",
            "groupName": "photos",
            "role": "viewer",
            "expiresAtUnix": 1_700_000_000i64,
            "status": "pending",
        }]
    });
    let resp: ListPendingInvitesResponse = serde_json::from_value(body).unwrap();
    assert_eq!(resp.invites.len(), 1);
    let invite = &resp.invites[0];
    assert_eq!(invite.invite_id, "invite-1");
    assert_eq!(invite.group_id, "group-1");
    assert_eq!(invite.group_name, "photos");
    assert_eq!(invite.role, "viewer");
    assert_eq!(invite.expires_at_unix, 1_700_000_000);
    assert_eq!(invite.status, "pending");
}

async fn members_as_presented(
    listing: serde_json::Value,
    own_device_id: Option<&str>,
) -> Vec<GroupMemberInfo> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shares/groups/g1/members"))
        .respond_with(ResponseTemplate::new(200).set_body_json(listing))
        .mount(&server)
        .await;
    let result = fetch_members(
        &crate::coordination::http_client::CoordinationAccess::new(
            yadorilink_fapi_client::test_support::offline_auth(),
            server.uri(),
        ),
        "g1",
        own_device_id,
    )
    .await;
    result.unwrap()
}

fn member_json(device_id: &str, online: bool) -> serde_json::Value {
    serde_json::json!({
        "deviceId": device_id,
        "deviceName": device_id,
        "role": "editor",
        "isSameAccount": true,
        "isCallerAccount": true,
        "storageMode": "eager",
        "online": online,
        "lastSeenUnix": 0,
    })
}

/// The machine showing the listing is running, whatever the coordination
/// plane last observed of its subscription.
#[tokio::test]
async fn this_device_is_never_listed_offline_even_when_the_service_says_so() {
    let members = members_as_presented(
        serde_json::json!({
            "members": [member_json("this-device", false), member_json("other-device", false)]
        }),
        Some("this-device"),
    )
    .await;

    let this = members.iter().find(|m| m.device_id == "this-device").unwrap();
    assert!(this.online, "this machine is running, so it is online");
    let other = members.iter().find(|m| m.device_id == "other-device").unwrap();
    assert!(!other.online, "another device's presence is the service's to report");
}

#[tokio::test]
async fn without_a_local_device_identity_every_member_keeps_the_services_presence() {
    let members = members_as_presented(
        serde_json::json!({ "members": [member_json("this-device", false)] }),
        None,
    )
    .await;

    assert!(!members[0].online);
}

fn pend(group_id: &str, device_id: &str) -> PendingApproval {
    PendingApproval {
        group_id: group_id.to_string(),
        group_name: "photos".to_string(),
        device_id: device_id.to_string(),
        role: Some("viewer".to_string()),
    }
}

fn mem(device_id: &str) -> GroupMemberInfo {
    GroupMemberInfo {
        device_id: device_id.to_string(),
        device_name: "laptop".to_string(),
        role: "editor".to_string(),
        is_same_account: true,
        is_caller_account: true,
        storage_mode: "eager".to_string(),
        online: true,
        last_seen_unix: 1_700_000_000,
    }
}

/// A request that is genuinely still waiting is denied, and the button
/// does exactly what it says.
#[test]
fn a_request_that_is_still_waiting_is_denied() {
    let pending = [pend("group-1", "device-a")];
    assert_eq!(deny_precheck(&pending, &[], "group-1", "device-a"), DenyPrecheck::StillWaiting);
}

/// The bug this guard exists for: the requests panel is not refreshed on
/// a timer, so a row can still say "waiting" long after the request was
/// approved from somewhere else. Denying IS revoking, so sending that
/// denial would remove a member whose access is live and working. A
/// device that appears in the member listing is never denied.
#[test]
fn a_request_already_approved_elsewhere_is_never_denied() {
    // Exactly what the stale panel still shows -- and what the fresh
    // read says instead: nobody is waiting, and the device is a member.
    let members = [mem("device-a")];
    assert_eq!(
        deny_precheck(&[], &members, "group-1", "device-a"),
        DenyPrecheck::NotWaiting(DenyRefusal::AlreadyAdmitted)
    );
}

/// Membership wins over a waiting request outright: the two listings are
/// two separate reads, so an approval landing between them shows up in
/// both, and the reading that stops a removal is the safe one.
#[test]
fn being_listed_as_a_member_outweighs_a_request_still_in_the_other_listing() {
    let pending = [pend("group-1", "device-a")];
    let members = [mem("device-a")];
    assert_eq!(
        deny_precheck(&pending, &members, "group-1", "device-a"),
        DenyPrecheck::NotWaiting(DenyRefusal::AlreadyAdmitted)
    );
}

/// Decided or withdrawn somewhere else: nothing to deny, and nothing to
/// remove either.
#[test]
fn a_request_that_is_gone_from_both_listings_is_not_denied() {
    assert_eq!(
        deny_precheck(&[], &[], "group-1", "device-a"),
        DenyPrecheck::NotWaiting(DenyRefusal::NoLongerListed)
    );
}

/// The waiting listing is account-wide, so it is narrowed by group id
/// here exactly as `pending_rows` narrows it -- a request for ANOTHER
/// folder must never make this window's Deny proceed.
#[test]
fn a_request_waiting_on_a_different_folder_does_not_make_this_deny_proceed() {
    let pending = [pend("group-2", "device-a")];
    assert_eq!(
        deny_precheck(&pending, &[], "group-1", "device-a"),
        DenyPrecheck::NotWaiting(DenyRefusal::NoLongerListed)
    );
}

#[test]
fn refusal_reasons_are_plain_and_distinct() {
    let admitted = DenyRefusal::AlreadyAdmitted.reason();
    let gone = DenyRefusal::NoLongerListed.reason();
    assert!(admitted.contains("already approved"));
    assert!(gone.contains("no longer waiting") && gone.contains("Nothing was changed"));
    assert_ne!(admitted, gone);
}

#[tokio::test]
async fn resolve_joinable_group_id_names_the_missing_group_and_its_next_step() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/shares/joinable"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "groups": [] })))
        .mount(&server)
        .await;
    let auth = crate::coordination::http_client::CoordinationAccess::new(
        yadorilink_fapi_client::test_support::offline_auth(),
        server.uri(),
    );
    let error = resolve_joinable_group_id_with(&auth, "docs").await.unwrap_err();
    assert_eq!(error.hint(), Some(Hint::ListJoinableShares));
    assert_eq!(error.to_string(), "no joinable folder group named \"docs\"");
}
