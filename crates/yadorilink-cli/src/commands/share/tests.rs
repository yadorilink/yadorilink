#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::HandoffResult;

use super::*;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

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

fn waiting(device_id: &str, role: Option<&str>) -> PendingApproval {
    PendingApproval {
        group_id: "group-1".into(),
        group_name: "photos".into(),
        device_id: device_id.into(),
        role: role.map(str::to_string),
    }
}

fn sample_member(device_id: &str) -> GroupMemberInfo {
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

#[test]
fn share_edge_line_renders_edge_fields_verbatim() {
    assert_eq!(
        share_edge_line(&base_edge()),
        "edge-1  group=photos (group-1)  device=device-1  role=editor  active"
    );
}

/// An edge awaiting approval must be visibly different, and read as
/// something a person can act on rather than as the plane's enum spelling.
#[test]
fn share_edge_line_distinguishes_an_edge_awaiting_approval() {
    let edge = ShareEdgeInfo { state: "pending_approval".into(), role: None, ..base_edge() };
    assert_eq!(
        share_edge_line(&edge),
        "edge-1  group=photos (group-1)  device=device-1  role=unknown  awaiting the owner's \
         approval"
    );
}

#[test]
fn share_edge_line_renders_an_unrecognized_state_verbatim() {
    let edge = ShareEdgeInfo { state: "some_future_state".into(), ..base_edge() };
    let line = share_edge_line(&edge);
    assert!(line.ends_with("  some_future_state"), "{line}");
}

#[test]
fn pending_approval_line_renders_the_same_text_as_before_the_listing_was_split() {
    assert_eq!(
        pending_approval_line(&waiting("device-abcdef123", Some("editor"))),
        "group=photos (group-1)  device=device-abcdef123 (device-a)  requested role=editor"
    );
    assert!(pending_approval_line(&waiting("device-1", None)).ends_with("requested role=unknown"));
}

/// `share pending`'s full output: one line per request, a blank line, then
/// the two hints -- or the one empty-state line.
#[test]
fn pending_approvals_lines_are_pinned_verbatim() {
    assert_eq!(pending_approvals_lines(&[]), vec![NO_PENDING_APPROVALS.to_string()]);
    assert_eq!(
        pending_approvals_lines(&[waiting("device-abcdef123", Some("viewer"))]),
        vec![
            "group=photos (group-1)  device=device-abcdef123 (device-a)  requested role=viewer"
                .to_string(),
            String::new(),
            "Admit one with:   yadorilink share approve <group> <device-id>".to_string(),
            "Turn one down with: yadorilink share deny <group> <device-id>".to_string(),
        ]
    );
}

#[test]
fn accept_invite_reports_a_completed_join_when_no_approval_is_pending() {
    assert_eq!(
        accept_invite_lines("group-1", "/home/bob/Shared", false, false),
        vec!["Joined folder group group-1 and linked it at /home/bob/Shared".to_string()]
    );
}

/// An acceptance awaiting the owner's approval must NOT be reported as a
/// join.
#[test]
fn accept_invite_never_claims_a_join_while_awaiting_approval() {
    assert_eq!(
        accept_invite_lines("group-1", "/home/bob/Shared", true, true),
        vec![
            "Invite redeemed for folder group group-1, and the folder is linked at \
             /home/bob/Shared (on-demand) -- but it is NOT syncing yet."
                .to_string(),
            "This invite requires the group owner's approval. Nothing will sync until they \
             approve it, and there is no notification when they do."
                .to_string(),
            "Check the current answer with:   yadorilink share list".to_string(),
        ]
    );
}

#[test]
fn accept_invite_reports_the_storage_mode_in_both_outcomes() {
    assert!(accept_invite_lines("g", "/p", true, false)[0].contains("(on-demand)"));
    assert!(accept_invite_lines("g", "/p", true, true)[0].contains("(on-demand)"));
}

#[test]
fn member_line_renders_exactly_the_same_text_as_before_its_labels_were_extracted() {
    let member = sample_member("0123456789abcdef");
    assert_eq!(
        member_line(&member, Some("0123456789abcdef")),
        "device=laptop (01234567)  role=editor  you  online  full copy"
    );

    let mut stranger = sample_member("fedcba9876543210");
    stranger.device_name = "desktop".to_string();
    stranger.role = "viewer".to_string();
    stranger.is_same_account = false;
    stranger.is_caller_account = false;
    stranger.online = false;
    stranger.storage_mode = "on-demand".to_string();
    assert_eq!(
        member_line(&stranger, Some("0123456789abcdef")),
        "device=desktop (fedcba98)  role=viewer  invited  offline  on-demand"
    );
}

/// The relationship label the line prints is the shared one, for every one
/// of the four cases.
#[test]
fn the_shared_relationship_label_agrees_with_what_the_member_line_prints() {
    let caller = "caller-device";
    let mut own = sample_member(caller);
    own.is_same_account = false;
    let mut my_other = sample_member("other-device");
    my_other.is_same_account = false;
    let mut owners = sample_member("owner-device");
    owners.is_caller_account = false;
    let mut stranger = sample_member("stranger-device");
    stranger.is_same_account = false;
    stranger.is_caller_account = false;
    for member in [&own, &my_other, &owners, &stranger] {
        let line = member_line(member, Some(caller));
        let label = member_relationship_label(member, Some(caller));
        assert!(line.contains(&format!("  {label}  ")), "{line} should carry {label:?}");
    }
}

#[test]
fn members_lines_name_the_group_when_nobody_has_access() {
    assert_eq!(
        members_lines("photos", &[], None),
        vec!["No one has access to photos.".to_string()]
    );
    assert_eq!(
        members_lines("photos", &[sample_member("0123456789abcdef")], None),
        vec!["device=laptop (01234567)  role=editor  your other device  online  full copy"
            .to_string()]
    );
}

#[test]
fn grant_line_reports_a_fresh_grant_and_an_unchanged_one_differently() {
    assert_eq!(
        grant_line("photos", "dev-1", &GrantOutcome { role: "viewer".into(), created: true }),
        "Granted dev-1 access to photos (role: viewer)"
    );
    assert_eq!(
        grant_line("photos", "dev-1", &GrantOutcome { role: "editor".into(), created: false }),
        "dev-1 was already authorized for photos; role remains editor (change an existing \
         grant's role with `yadorilink share change-role photos dev-1 --role <viewer|editor>`)"
    );
}

#[test]
fn change_role_reports_the_role_the_device_now_holds() {
    assert_eq!(change_role_line("dev-1", "photos", "viewer"), "dev-1 is now viewer for photos");
}

#[test]
fn revoke_and_deny_close_with_their_own_wording() {
    assert_eq!(
        revoke_line(RevokeAnnouncement::Revoked, "dev-1", "photos"),
        "Revoked dev-1 access to photos"
    );
    assert_eq!(
        revoke_line(RevokeAnnouncement::Denied, "dev-1", "photos"),
        "Denied dev-1 access to photos"
    );
}

#[test]
fn joinable_lines_are_pinned_verbatim() {
    assert_eq!(
        joinable_lines(&[]),
        vec!["No joinable folder groups. Create one with `yadorilink share create`.".to_string()]
    );
    assert_eq!(
        joinable_lines(&[GroupSummary { group_id: "g-1".into(), name: "photos".into() }]),
        vec!["photos  (g-1)".to_string()]
    );
}

#[test]
fn joined_line_marks_an_on_demand_link() {
    assert_eq!(joined_line("photos", "/p", false, false), "Joined photos and linked it at /p");
    assert_eq!(
        joined_line("photos", "/p", true, false),
        "Joined photos and linked it at /p (on-demand)"
    );
}

/// A repeated `share join` of a folder already linked to the group succeeds
/// as a no-op, and must say so rather than claim a fresh join.
#[test]
fn joined_line_reports_an_already_linked_folder_as_a_no_op() {
    assert_eq!(
        joined_line("photos", "/p", false, true),
        "/p is already linked to photos; nothing to do"
    );
}

#[test]
fn storage_mode_lines_are_pinned_verbatim() {
    let unchanged = StorageModeOutcome { changed: false, handoff_result: None };
    assert_eq!(storage_mode_lines("photos", true, &unchanged), vec!["photos is already on-demand"]);
    let changed = StorageModeOutcome { changed: true, handoff_result: None };
    assert_eq!(
        storage_mode_lines("photos", false, &changed),
        vec!["Set photos storage mode to eager"]
    );
    let handed_off = StorageModeOutcome {
        changed: true,
        handoff_result: Some(HandoffResult {
            target_device_id: "dev-2".into(),
            membership_generation: 4,
            lease_id: "lease-9".into(),
            ..Default::default()
        }),
    };
    assert_eq!(
        storage_mode_lines("photos", true, &handed_off),
        vec![
            "Set photos storage mode to on-demand".to_string(),
            "  handoff completed: target=dev-2 membership_generation=4 lease=lease-9".to_string(),
        ]
    );
    let no_lease = StorageModeOutcome {
        changed: true,
        handoff_result: Some(HandoffResult {
            target_device_id: "dev-2".into(),
            membership_generation: 4,
            ..Default::default()
        }),
    };
    assert_eq!(
        storage_mode_lines("photos", true, &no_lease)[1],
        "  handoff completed: target=dev-2 membership_generation=4"
    );
}

#[test]
fn format_expiry_reports_already_expired_for_a_past_timestamp() {
    assert_eq!(format_expiry(0), "already expired");
}

#[test]
fn format_expiry_picks_the_coarsest_unit_that_still_reads_as_at_least_one() {
    let now = now();
    assert_eq!(format_expiry(now + 2 * 86_400 + 10), "2 day(s)");
    assert_eq!(format_expiry(now + 5 * 3600), "5 hour(s)");
    assert_eq!(format_expiry(now + 90), "1 minute(s)");
}

#[test]
fn render_invite_qr_produces_a_nonempty_multiline_block() {
    let qr = render_invite_qr("yadorilink://invite/abc123").expect("qr should encode");
    assert!(qr.lines().count() > 5, "expected a multi-row QR render, got:\n{qr}");
    assert!(qr.contains('█'), "expected at least one dark module");
}

/// A minted invite as the coordination plane reports it back. The expiry is
/// far enough out that `format_expiry`'s day bucket is stable.
fn minted_invite(requires_approval: bool) -> MintedInviteInfo {
    MintedInviteInfo {
        code: "abc123".into(),
        invite_id: "invite-1".into(),
        group_id: "group-1".into(),
        role: "viewer".into(),
        expires_at_unix: now() + 7 * 86_400 + 10,
        requires_approval,
    }
}

#[test]
fn invite_lines_render_the_code_url_and_expiry_then_the_recipients_command() {
    let invite = minted_invite(false);
    let url = invite_url(&invite.code);
    assert_eq!(
        invite_lines("photos", &invite, &url, None),
        vec![
            "Invite for photos (role: viewer):".to_string(),
            "  code: abc123".to_string(),
            "  url:  yadorilink://invite/abc123".to_string(),
            "  expires in: 7 day(s)".to_string(),
            String::new(),
            "This code is one-time use -- share it with exactly one recipient.".to_string(),
            "The recipient accepts it with: yadorilink share accept \
             yadorilink://invite/abc123 --path <dir>"
                .to_string(),
        ]
    );
}

#[test]
fn invite_lines_report_an_approval_gated_invite_in_both_places() {
    let invite = minted_invite(true);
    let url = invite_url(&invite.code);
    assert_eq!(
        invite_lines("photos", &invite, &url, None),
        vec![
            "Invite for photos (role: viewer):".to_string(),
            "  code: abc123".to_string(),
            "  url:  yadorilink://invite/abc123".to_string(),
            "  expires in: 7 day(s)".to_string(),
            "  approval: required (you must approve the recipient before they get access)"
                .to_string(),
            String::new(),
            "This code is one-time use -- share it with exactly one recipient.".to_string(),
            "The recipient accepts it with: yadorilink share accept \
             yadorilink://invite/abc123 --path <dir>"
                .to_string(),
            "They will not see anything until you admit them: run `yadorilink share pending` to \
             see the request, then `yadorilink share approve photos <device-id>`."
                .to_string(),
        ]
    );
}

/// The QR block sits between the invite's details and the closing
/// instructions, preceded by a blank line -- and a QR that could not be
/// rendered simply drops that block.
#[test]
fn invite_lines_place_the_qr_block_after_the_details_and_survive_its_absence() {
    let invite = minted_invite(false);
    let url = invite_url(&invite.code);
    let with_qr = invite_lines("photos", &invite, &url, Some("##\n##"));
    let without_qr = invite_lines("photos", &invite, &url, None);
    assert_eq!(with_qr[4], "");
    assert_eq!(with_qr[5], "##\n##");
    assert_eq!(with_qr.len(), without_qr.len() + 2);
}

fn base_pending_invite() -> PendingInviteInfo {
    PendingInviteInfo {
        invite_id: "invite-1".into(),
        group_id: "group-1".into(),
        group_name: "photos".into(),
        role: "viewer".into(),
        expires_at_unix: 0,
        status: "pending".into(),
    }
}

#[test]
fn invites_lines_are_pinned_verbatim() {
    assert_eq!(
        invites_lines(&[]),
        vec!["No pending invites. Mint one with `yadorilink share invite <group>`.".to_string()]
    );
    let pending = PendingInviteInfo { expires_at_unix: now() + 3600 + 30, ..base_pending_invite() };
    let expired = PendingInviteInfo { status: "expired".into(), ..base_pending_invite() };
    let cancelled = PendingInviteInfo { status: "cancelled".into(), ..base_pending_invite() };
    assert_eq!(
        invites_lines(&[pending, expired, cancelled]),
        vec![
            "invite-1  group=photos (group-1)  role=viewer  expires in 1 hour(s)".to_string(),
            "invite-1  group=photos (group-1)  role=viewer  expired".to_string(),
            "invite-1  group=photos (group-1)  role=viewer  cancelled".to_string(),
        ]
    );
}
