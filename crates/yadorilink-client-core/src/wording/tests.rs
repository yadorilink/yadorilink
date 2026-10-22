#![cfg(test)]

use std::time::Duration;

use yadorilink_ipc_proto::daemonctl::MembershipHandoffResult;

use super::*;
use crate::ops::auth::{BrowserPurpose, LoginEvent, SignOutKind};

fn member(device_id: &str, is_same_account: bool, is_caller_account: bool) -> GroupMemberInfo {
    GroupMemberInfo {
        device_id: device_id.to_string(),
        device_name: "laptop".to_string(),
        role: "editor".to_string(),
        is_same_account,
        is_caller_account,
        storage_mode: "eager".to_string(),
        online: true,
        last_seen_unix: 1_700_000_000,
    }
}

#[test]
fn local_first_notice_states_local_folders_are_not_deleted() {
    assert!(LOCAL_FIRST_NOTICE.contains("does NOT delete"));
    assert!(LOCAL_FIRST_NOTICE.to_lowercase().contains("local data"));
}

#[test]
fn invite_url_wraps_the_code_in_the_yadorilink_scheme() {
    assert_eq!(invite_url("abc123"), "yadorilink://invite/abc123");
}

/// Each recognized approve result gets its own wording, matched positively
/// -- and an unrecognized one must NOT fall through to "Approved", which
/// would claim an outcome this build cannot confirm happened.
#[test]
fn approve_result_line_never_claims_approval_for_an_unrecognized_result() {
    assert_eq!(
        approve_result_line("approved", "device-1", "photos"),
        "Approved device-1 for photos"
    );
    assert_eq!(
        approve_result_line("already_active", "device-1", "photos"),
        "device-1 already had access to photos; nothing to approve"
    );
    assert_eq!(
        approve_result_line("some_future_outcome", "device-1", "photos"),
        "The approval request for device-1 in photos was accepted, with an outcome this version \
         does not recognize (\"some_future_outcome\"); check `yadorilink share list` for the \
         current state"
    );
}

#[test]
fn the_no_pending_approvals_line_names_how_a_request_appears() {
    assert_eq!(
        NO_PENDING_APPROVALS,
        "No one is waiting for your approval. Requests appear here after someone redeems an \
         invite you minted with `yadorilink share invite <group> --require-approval`."
    );
}

#[test]
fn state_label_words_only_the_awaiting_state_and_passes_others_through() {
    assert_eq!(state_label("pending_approval"), "awaiting the owner's approval");
    assert_eq!(state_label("active"), "active");
    assert_eq!(state_label("some_future_state"), "some_future_state");
}

#[test]
fn the_relationship_label_covers_all_four_cases_from_the_callers_perspective() {
    let caller = "caller-device";
    assert_eq!(member_relationship_label(&member(caller, false, true), Some(caller)), "you");
    assert_eq!(
        member_relationship_label(&member("other", false, true), Some(caller)),
        "your other device"
    );
    assert_eq!(
        member_relationship_label(&member("owner", true, false), Some(caller)),
        "owner's device"
    );
    assert_eq!(member_relationship_label(&member("x", false, false), Some(caller)), "invited");
    assert_eq!(
        member_relationship_label(&member(caller, true, true), None),
        "your other device",
        "with no known own device id nothing is ever labeled \"you\""
    );
}

#[test]
fn the_storage_label_claims_a_full_copy_only_for_the_eager_mode() {
    let mut m = member("dev-1", true, true);
    assert_eq!(member_storage_label(&m), "full copy");
    m.storage_mode = "on-demand".to_string();
    assert_eq!(member_storage_label(&m), "on-demand");
    m.storage_mode = "some-future-mode".to_string();
    assert_eq!(member_storage_label(&m), "on-demand");
}

#[test]
fn a_short_device_id_is_the_leading_eight_characters_and_never_panics_on_a_shorter_one() {
    assert_eq!(short_device_id("0123456789abcdef"), "01234567");
    assert_eq!(short_device_id("abc"), "abc");
    assert_eq!(short_device_id(""), "");
}

fn outcome(forced: &[&str], unknown_scope: &str) -> ReplicaMembershipCommandOutcome {
    ReplicaMembershipCommandOutcome {
        handoffs: Vec::new(),
        forced_group_ids: forced.iter().map(|g| (*g).to_string()).collect(),
        unknown_scope_operation_id: unknown_scope.to_string(),
    }
}

#[test]
fn membership_warnings_are_pinned_verbatim() {
    assert!(membership_outcome_warnings("remove", &outcome(&[], "")).is_empty());
    assert_eq!(
        membership_outcome_warnings("remove", &outcome(&["group-1", "group-2"], "op-123")),
        vec![
            "warning: forced remove without confirmed durability for: group-1, group-2. This \
             may permanently lose data."
                .to_string(),
            "warning: remove was forced before the affected folder groups could be determined. \
             The possible data-loss scope is unknown.\nRecovery operation: op-123\nSync status \
             will remain degraded until reconciliation completes."
                .to_string(),
        ]
    );
}

#[test]
fn membership_notices_name_each_completed_handoff() {
    let mut o = outcome(&[], "");
    o.handoffs.push(MembershipHandoffResult {
        group_id: "group-1".to_string(),
        target_device_id: "device-c".to_string(),
        lease_id: "lease-1".to_string(),
        membership_generation: 7,
    });
    assert_eq!(
        membership_outcome_notices(&o),
        vec!["handoff completed: group=group-1 target=device-c generation=7 lease=lease-1"]
    );
}

#[test]
fn device_code_instructions_match_the_credential_clients_own_text() {
    for complete in [Some("https://as.test/device?user_code=ABCD-EFGH"), None] {
        let mut body = serde_json::json!({
            "device_code": "dc",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://as.test/device",
            "expires_in": 600,
        });
        if let Some(c) = complete {
            body["verification_uri_complete"] = c.into();
        }
        let authorization: yadorilink_fapi_client::DeviceAuthorization =
            serde_json::from_value(body).unwrap();
        assert_eq!(
            device_code_instructions(
                &authorization.verification_uri,
                authorization.verification_uri_complete.as_deref(),
                &authorization.user_code
            ),
            authorization.instructions()
        );
    }
}

/// The exact lines a terminal shows for each sign-in step, in the order the
/// flow emits them.
#[test]
fn login_event_lines_are_pinned_verbatim() {
    assert!(login_event_lines(&LoginEvent::Enrolling).is_empty());
    assert!(login_event_lines(&LoginEvent::WaitingForAuthorization).is_empty());
    assert_eq!(
        login_event_lines(&LoginEvent::OpenBrowser {
            url: "https://as.test/approve".into(),
            purpose: BrowserPurpose::ApproveDevice,
        }),
        vec![
            "To add this computer to your YadoriLink account, open:\n".to_string(),
            "    https://as.test/approve\n".to_string(),
        ]
    );
    assert_eq!(
        login_event_lines(&LoginEvent::WaitingForApproval { expires_in: Duration::from_secs(900) }),
        vec!["Waiting for approval (this link is valid for 15 minutes)...".to_string()]
    );
    assert_eq!(
        login_event_lines(&LoginEvent::OpenBrowser {
            url: "https://as.test/authorize".into(),
            purpose: BrowserPurpose::SignIn,
        }),
        vec![
            "\nNow sign in to finish:\n".to_string(),
            "    https://as.test/authorize\n".to_string()
        ]
    );
    assert_eq!(
        login_event_lines(&LoginEvent::ShowDeviceCode {
            verification_uri: "https://as.test/device".into(),
            verification_uri_complete: Some("https://as.test/device?user_code=ABCD-EFGH".into()),
            user_code: "ABCD-EFGH".into(),
        }),
        vec!["\nTo finish signing in, open this link on any device (your phone is fine) and check \
              that the code shown there matches:\n\n  https://as.test/device?user_code=ABCD-EFGH\n\n  \
              Code: ABCD-EFGH\n"
            .to_string()]
    );
    assert_eq!(
        login_event_lines(&LoginEvent::ShowDeviceCode {
            verification_uri: "https://as.test/device".into(),
            verification_uri_complete: None,
            user_code: "ABCD-EFGH".into(),
        }),
        vec!["\nTo finish signing in, open https://as.test/device on any device and enter this \
             code:\n\n    ABCD-EFGH\n"
            .to_string()]
    );
    assert_eq!(
        login_event_lines(&LoginEvent::SignedIn { client_id: "ylk-1".into() }),
        vec!["Logged in. This computer is enrolled as ylk-1.".to_string()]
    );
}

#[test]
fn sign_out_lines_are_pinned_verbatim() {
    assert_eq!(
        sign_out_line(&SignOutKind::Revoked { grants_revoked: 2 }),
        "Signed out. This computer's access was revoked (2 grant(s)) and its credentials were \
         removed."
    );
    assert_eq!(
        sign_out_line(&SignOutKind::AlreadyRevoked),
        "Signed out. This computer's access had already been revoked; its credentials were \
         removed."
    );
    assert_eq!(
        sign_out_line(&SignOutKind::ConfirmedRevokedAfterRejection),
        "Signed out. This computer's access was no longer valid, and the Authorization Server \
         independently confirmed the registration is revoked; its credentials were removed."
    );
}

#[test]
fn parse_invite_input_accepts_links_and_bare_codes() {
    assert_eq!(parse_invite_input("yadorilink://invite/K7QX-M2PA"), Ok("K7QX-M2PA"));
    assert_eq!(parse_invite_input("  YadoriLink://Invite/abc_1/ \n"), Ok("abc_1"));
    assert_eq!(parse_invite_input("abc123"), Ok("abc123"));
    assert_eq!(parse_invite_input(&invite_url("0123456789abcdef")), Ok("0123456789abcdef"));
}

#[test]
fn parse_invite_input_rejects_malformed_and_oversized_input() {
    assert_eq!(parse_invite_input("  "), Err(InviteLinkError::Empty));
    assert_eq!(parse_invite_input("yadorilink://invite/"), Err(InviteLinkError::Malformed));
    assert_eq!(parse_invite_input("yadorilink://invite/a/b"), Err(InviteLinkError::Malformed));
    assert_eq!(parse_invite_input("yadorilink://invite/a?x=1"), Err(InviteLinkError::Malformed));
    assert_eq!(parse_invite_input("https://example.com/x"), Err(InviteLinkError::Malformed));
    assert_eq!(parse_invite_input("a b"), Err(InviteLinkError::Malformed));
    assert_eq!(parse_invite_input("é"), Err(InviteLinkError::Malformed));
    let long = "a".repeat(MAX_INVITE_CODE_LEN + 1);
    assert_eq!(parse_invite_input(&long), Err(InviteLinkError::TooLong));
    assert_eq!(parse_invite_input(&invite_url(&long)), Err(InviteLinkError::TooLong));
    assert_eq!(parse_invite_input(&"x".repeat(100_000)), Err(InviteLinkError::TooLong));
    assert!(parse_invite_input(&"a".repeat(MAX_INVITE_CODE_LEN)).is_ok());
}

#[test]
fn every_nas_admin_failure_has_its_one_sentence_and_names_no_mechanism() {
    use super::{nas_admin_failure_message, NasAdminFailure};
    let all = [
        (NasAdminFailure::Offline, "NAS is offline."),
        (NasAdminFailure::Unavailable, "Management is not available on this NAS."),
        (NasAdminFailure::CouldNotOpen, "Could not open the NAS management page."),
    ];
    for (failure, sentence) in all {
        let shown = nas_admin_failure_message(failure);
        assert_eq!(shown, sentence);
        let lower = shown.to_ascii_lowercase();
        for word in ["ssh", "tunnel", "port", "localhost", "127.0.0.1", "alpn", "forward"] {
            assert!(!lower.contains(word), "{shown:?} must not mention {word}");
        }
    }
}
