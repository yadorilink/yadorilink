//! `yadorilink share ...`: folder groups, members, invites and approvals.
//!
//! Each command calls the typed operation in
//! `yadorilink_client_core::ops::shares` and prints what it returned. The
//! line builders below are pure, so every line a command prints is pinned by
//! a unit test.

use yadorilink_client_core::ops::shares::{self as ops, GrantOutcome, RevokeEdgeOutcome};
use yadorilink_ipc_proto::daemonctl::MintedInviteInfo;

use crate::error::CliError;

use yadorilink_client_core::ops::shares::{
    GroupMemberInfo, GroupSummary, PendingApproval, PendingInviteInfo, ShareEdgeInfo,
    StorageModeOutcome,
};
use yadorilink_client_core::wording::{
    approve_result_line, invite_url, member_relationship_label, member_storage_label,
    short_device_id, state_label, NO_PENDING_APPROVALS,
};

/// Renders `url` as a terminal-friendly QR code (Unicode block characters,
/// roughly square modules via `module_dimensions(2, 1)` to compensate for
/// terminal character cells being taller than they are wide). Returns `None`
/// on a genuine encoding failure (the payload is too long for any QR
/// version) rather than erroring the whole `invite` command -- the code and
/// URL are still printed either way.
fn render_invite_qr(url: &str) -> Option<String> {
    let code = qrcode::QrCode::new(url).ok()?;
    Some(code.render::<char>().module_dimensions(2, 1).dark_color('█').light_color(' ').build())
}

/// Every line `share invite` prints for a freshly minted invite, in order.
///
/// `qr` is the whole pre-rendered multi-line QR block, or `None` when
/// rendering it failed; a failure simply omits the block (and its leading
/// blank line), since the code and URL are printed either way.
fn invite_lines(
    group_name: &str,
    invite: &MintedInviteInfo,
    url: &str,
    qr: Option<&str>,
) -> Vec<String> {
    let mut lines = vec![
        format!("Invite for {group_name} (role: {}):", invite.role),
        format!("  code: {}", invite.code),
        format!("  url:  {url}"),
        format!("  expires in: {}", format_expiry(invite.expires_at_unix)),
    ];
    // Reported from what the coordination plane actually recorded, not from
    // the flag this command was given, so the recipient-facing wording below
    // always describes the invite that exists.
    if invite.requires_approval {
        lines.push(
            "  approval: required (you must approve the recipient before they get access)"
                .to_string(),
        );
    }
    if let Some(qr) = qr {
        lines.push(String::new());
        lines.push(qr.to_string());
    }
    lines.push(String::new());
    lines.push("This code is one-time use -- share it with exactly one recipient.".to_string());
    lines
        .push(format!("The recipient accepts it with: yadorilink share accept {url} --path <dir>"));
    if invite.requires_approval {
        lines.push(format!(
            "They will not see anything until you admit them: run `yadorilink share pending` \
             to see the request, then `yadorilink share approve {group_name} <device-id>`."
        ));
    }
    lines
}

/// `yadorilink share invite <group>`: mints a one-use, expiring,
/// device-scoped cross-account invite and prints its code, a `yadorilink://`
/// URL, and a terminal QR code encoding that URL.
pub async fn invite(
    group_name: String,
    role: Option<String>,
    ttl_secs: Option<u64>,
    require_approval: bool,
) -> Result<(), CliError> {
    let invite = ops::mint_invite(&group_name, role, ttl_secs, require_approval).await?;
    let url = invite_url(&invite.code);
    let qr = render_invite_qr(&url);
    print_lines(&invite_lines(&group_name, &invite, &url, qr.as_deref()));
    Ok(())
}

/// A relative expiry ("7 days", "45 minutes") from the current time --
/// simpler and more directly actionable for a share-once code than an
/// absolute calendar timestamp.
fn format_expiry(expires_at_unix: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let remaining = expires_at_unix - now;
    if remaining <= 0 {
        return "already expired".to_string();
    }
    let remaining = remaining as u64;
    if remaining >= 86_400 {
        format!("{} day(s)", remaining / 86_400)
    } else if remaining >= 3600 {
        format!("{} hour(s)", remaining / 3600)
    } else {
        format!("{} minute(s)", remaining.max(60) / 60)
    }
}

fn pending_invite_line(invite: &PendingInviteInfo) -> String {
    let expiry = match invite.status.as_str() {
        "pending" => format!("expires in {}", format_expiry(invite.expires_at_unix)),
        other => other.to_string(),
    };
    format!(
        "{}  group={} ({})  role={}  {expiry}",
        invite.invite_id, invite.group_name, invite.group_id, invite.role
    )
}

fn invites_lines(invites: &[PendingInviteInfo]) -> Vec<String> {
    if invites.is_empty() {
        return vec!["No pending invites. Mint one with `yadorilink share invite <group>`.".into()];
    }
    invites.iter().map(pending_invite_line).collect()
}

/// `yadorilink share invites`: every invite this account has minted that
/// nobody has redeemed yet -- `pending`, `expired`, or `cancelled`.
pub async fn list_invites() -> Result<(), CliError> {
    print_lines(&invites_lines(&ops::list_invites_resolved().await?));
    Ok(())
}

/// `yadorilink share cancel-invite <invite-id>`.
pub async fn cancel_invite(invite_id: String) -> Result<(), CliError> {
    ops::cancel_invite(&invite_id).await?;
    println!("Cancelled invite: {invite_id}");
    Ok(())
}

/// `yadorilink share create <group> --path <dir>`: creates a new folder group
/// and links it locally in one step. The creating device becomes the group's
/// first full replica, and the local path is preflighted BEFORE the group is
/// created, so the common failure (a bad or risky folder) never creates a
/// group at all.
pub async fn create(group_name: String, path: String, yes: bool) -> Result<(), CliError> {
    let (absolute, acknowledged) =
        crate::commands::link::preflight_and_acknowledge(&path, yes).await?;
    let group_id = ops::create_and_link(group_name, absolute, false, acknowledged).await?;
    println!("Created folder group {group_id} and linked it at {path}");
    Ok(())
}

fn grant_line(group_name: &str, device_id: &str, outcome: &GrantOutcome) -> String {
    if outcome.created {
        format!("Granted {device_id} access to {group_name} (role: {})", outcome.role)
    } else {
        format!(
            "{device_id} was already authorized for {group_name}; role remains {} (change an \
             existing grant's role with `yadorilink share change-role {group_name} \
             {device_id} --role <viewer|editor>`)",
            outcome.role
        )
    }
}

/// `yadorilink share grant <group> <device> [--role viewer|editor]`:
/// authorizes another of your own already-registered devices for a folder
/// group. The coordination plane reports the device's actual effective role,
/// so this never claims a role change took effect when the device was
/// already authorized under a different role.
pub async fn grant(
    group_name: String,
    device_id: String,
    role: Option<String>,
) -> Result<(), CliError> {
    let outcome = ops::grant(&group_name, &device_id, role.as_deref()).await?;
    println!("{}", grant_line(&group_name, &device_id, &outcome));
    Ok(())
}

/// Formats one member's line for `share members`' output.
fn member_line(member: &GroupMemberInfo, own_device_id: Option<&str>) -> String {
    let short_id = short_device_id(&member.device_id);
    format!(
        "device={} ({short_id})  role={}  {}  {}  {}",
        member.device_name,
        member.role,
        member_relationship_label(member, own_device_id),
        if member.online { "online" } else { "offline" },
        member_storage_label(member),
    )
}

fn members_lines(
    group_name: &str,
    members: &[GroupMemberInfo],
    own_device_id: Option<&str>,
) -> Vec<String> {
    if members.is_empty() {
        return vec![format!("No one has access to {group_name}.")];
    }
    members.iter().map(|member| member_line(member, own_device_id)).collect()
}

/// `yadorilink share members <group>`: who has access to a folder group and
/// their role -- device display name and id, never another account's email.
pub async fn members(group_name: String) -> Result<(), CliError> {
    let members = ops::list_members(&group_name).await?;
    let own_device_id = ops::own_device_id();
    print_lines(&members_lines(&group_name, &members, own_device_id.as_deref()));
    Ok(())
}

/// `yadorilink share change-role <group> <device> --role viewer|editor`:
/// moves a device that ALREADY has access to a folder group to a different
/// role, without a revoke-and-re-invite round trip.
pub async fn change_role(
    group_name: String,
    device_id: String,
    role: String,
) -> Result<(), CliError> {
    ops::change_role(&group_name, &device_id, &role).await?;
    println!("{}", change_role_line(&device_id, &group_name, &role));
    Ok(())
}

/// What `share change-role` prints once the coordination plane has accepted
/// the change. The route answers `204 No Content`, so there is no
/// server-reported effective role to echo.
fn change_role_line(device_id: &str, group_name: &str, role: &str) -> String {
    format!("{device_id} is now {role} for {group_name}")
}

/// Which command's wording to close with once the revoke has committed.
/// `share deny` runs the same mutation for a different reason and must not
/// report it as having taken away access the device never had.
#[derive(Clone, Copy)]
enum RevokeAnnouncement {
    Revoked,
    Denied,
}

fn revoke_line(announcement: RevokeAnnouncement, device_id: &str, group_name: &str) -> String {
    match announcement {
        RevokeAnnouncement::Revoked => format!("Revoked {device_id} access to {group_name}"),
        RevokeAnnouncement::Denied => format!("Denied {device_id} access to {group_name}"),
    }
}

/// `yadorilink share revoke <group> <device> [--force]`. The daemon's
/// durability readiness gate runs before any coordination-plane write;
/// `--force` bypasses a refusal with a data-loss warning and an audit log
/// line.
pub async fn revoke(
    group_name: String,
    device_id: String,
    force: bool,
    yes: bool,
) -> Result<(), CliError> {
    confirm_revoke(&format!("device {device_id} to '{group_name}'"), yes)?;
    revoke_announcing(group_name, device_id, force, RevokeAnnouncement::Revoked).await
}

/// `yadorilink share deny <group> <device>`: turns down a device waiting for
/// this account's approval. This IS a revoke, which is load-bearing: the
/// revoke path marks the originating invite revoked atomically with removing
/// the edge, so the denied recipient cannot replay their accept. Never
/// forced: the readiness gate does not apply to a device that was never
/// admitted.
pub async fn deny(group_name: String, device_id: String) -> Result<(), CliError> {
    use yadorilink_client_core::error::CoreError;
    let group_id = ops::resolve_group_name(&group_name).await?;
    let outcome = match ops::deny_checked(group_id, device_id.clone()).await? {
        ops::DenyAttempt::Refused(refusal) => {
            return Err(CoreError::InvalidInput(refusal.reason().to_owned()).into());
        }
        ops::DenyAttempt::Attempted(ops::RevokeAttempt::Committed(outcome)) => outcome,
        ops::DenyAttempt::Attempted(ops::RevokeAttempt::NotDurable { message, group_ids }) => {
            return Err(CoreError::DurabilityBlocked { message, group_ids }.into());
        }
    };
    crate::commands::membership_render::render_membership_outcome("revoke", &outcome);
    println!("{}", revoke_line(RevokeAnnouncement::Denied, &device_id, &group_name));
    Ok(())
}

async fn revoke_announcing(
    group_name: String,
    device_id: String,
    force: bool,
    announcement: RevokeAnnouncement,
) -> Result<(), CliError> {
    let outcome = ops::revoke(&group_name, device_id.clone(), force).await?;
    crate::commands::membership_render::render_membership_outcome("revoke", &outcome);
    println!("{}", revoke_line(announcement, &device_id, &group_name));
    Ok(())
}

fn confirm_revoke(what: &str, yes: bool) -> Result<(), CliError> {
    super::confirm_destructive(
        &format!(
            "Revoke access for {what}? It will no longer sync this folder. Files already on \
             that device stay on its disk."
        ),
        yes,
    )
}

/// `yadorilink share revoke <edge-id> [--force]`. An edge that no longer
/// exists is treated as already revoked.
pub async fn revoke_edge(edge_id: String, force: bool, yes: bool) -> Result<(), CliError> {
    confirm_revoke(&format!("share {edge_id}"), yes)?;
    match ops::revoke_edge(&edge_id, force).await? {
        RevokeEdgeOutcome::Revoked(outcome) => {
            crate::commands::membership_render::render_membership_outcome("revoke", &outcome);
            println!("Revoked share edge: {edge_id}");
        }
        RevokeEdgeOutcome::AlreadyRevoked => println!("Share edge already revoked: {edge_id}"),
    }
    Ok(())
}

/// `yadorilink share delete <group> [--acknowledge-cross-account-members]`.
/// Terminal: the group and every ACL edge on it are gone.
pub async fn delete_group(
    group_name: String,
    acknowledge_cross_account_members: bool,
    yes: bool,
) -> Result<(), CliError> {
    super::confirm_destructive(
        &format!(
            "Delete folder group '{group_name}' for every member? Their access is removed; \
             files already on each device stay on its disk."
        ),
        yes,
    )?;
    ops::delete_group(&group_name, acknowledge_cross_account_members).await?;
    println!("Deleted folder group: {group_name}");
    Ok(())
}

fn share_edge_line(edge: &ShareEdgeInfo) -> String {
    format!(
        "{}  group={} ({})  device={}  role={}  {}",
        edge.edge_id,
        edge.group_name,
        edge.group_id,
        edge.device_id,
        edge.role.as_deref().unwrap_or("unknown"),
        state_label(&edge.state),
    )
}

/// `yadorilink share list`: every ACL edge this account can see.
pub async fn list_shares() -> Result<(), CliError> {
    for edge in ops::list_shares_resolved().await? {
        println!("{}", share_edge_line(&edge));
    }
    Ok(())
}

fn pending_approval_line(request: &PendingApproval) -> String {
    let short_id = short_device_id(&request.device_id);
    format!(
        "group={} ({})  device={} ({short_id})  requested role={}",
        request.group_name,
        request.group_id,
        request.device_id,
        request.role.as_deref().unwrap_or("unknown"),
    )
}

fn pending_approvals_lines(waiting: &[PendingApproval]) -> Vec<String> {
    if waiting.is_empty() {
        return vec![NO_PENDING_APPROVALS.to_string()];
    }
    let mut lines: Vec<String> = waiting.iter().map(pending_approval_line).collect();
    lines.push(String::new());
    lines.push("Admit one with:   yadorilink share approve <group> <device-id>".to_string());
    lines.push("Turn one down with: yadorilink share deny <group> <device-id>".to_string());
    lines
}

/// `yadorilink share pending`: the devices waiting for this account's
/// approval to join a folder group it owns.
pub async fn list_pending_approvals() -> Result<(), CliError> {
    print_lines(&pending_approvals_lines(&ops::pending_approvals().await?));
    Ok(())
}

/// `yadorilink share approve <group> <device>`: admits a device waiting for
/// this account's approval. Takes no `--role`: the granted role is the one
/// the redeemed invite named.
pub async fn approve(group_name: String, device_id: String) -> Result<(), CliError> {
    let result = ops::approve(&group_name, &device_id).await?;
    println!("{}", approve_result_line(&result, &device_id, &group_name));
    Ok(())
}

fn joinable_lines(groups: &[GroupSummary]) -> Vec<String> {
    let mut lines = Vec::new();
    if groups.is_empty() {
        lines.push("No joinable folder groups. Create one with `yadorilink share create`.".into());
    }
    lines.extend(groups.iter().map(|group| format!("{}  ({})", group.name, group.group_id)));
    lines
}

/// `yadorilink share joinable`: the folder groups this account owns and can
/// join on this device.
pub async fn list_joinable() -> Result<(), CliError> {
    print_lines(&joinable_lines(&ops::list_joinable_groups().await?));
    Ok(())
}

fn joined_line(
    group_name: &str,
    local_path: &str,
    on_demand: bool,
    already_linked: bool,
) -> String {
    if already_linked {
        return format!("{local_path} is already linked to {group_name}; nothing to do");
    }
    format!(
        "Joined {group_name} and linked it at {local_path}{}",
        if on_demand { " (on-demand)" } else { "" },
    )
}

/// `yadorilink share join <group> --path <dir> --storage-mode <mode>`:
/// same-account onboarding through the daemon's crash-safe Pending -> Active
/// enrollment. The local path is preflighted before any coordination-plane
/// state, so the common failure never prepares an enrollment.
pub async fn join(
    group_name: String,
    path: String,
    storage_mode: String,
    yes: bool,
) -> Result<(), CliError> {
    let on_demand = ops::parse_storage_mode(&storage_mode)?;
    let group_id = ops::resolve_joinable_group_id(&group_name).await?;
    let (absolute, acknowledged) =
        crate::commands::link::preflight_and_acknowledge(&path, yes).await?;
    let local_path = absolute.to_string_lossy().to_string();
    let outcome = ops::join_resolved_with_outcome(
        group_id,
        group_name.clone(),
        absolute,
        on_demand,
        acknowledged,
    )
    .await?;
    println!("{}", joined_line(&group_name, &local_path, on_demand, outcome.already_linked));
    Ok(())
}

/// `yadorilink share accept <code-or-url> --path <dir> --storage-mode <mode>`:
/// cross-account onboarding. The local path is preflighted first, so the
/// common failure never redeems the one-use invite at all. Re-running with
/// the SAME code after a failure or crash is always safe.
pub async fn accept(
    code_or_url: String,
    path: String,
    storage_mode: String,
    yes: bool,
) -> Result<(), CliError> {
    let on_demand = ops::parse_storage_mode(&storage_mode)?;
    let (absolute, acknowledged) =
        crate::commands::link::preflight_and_acknowledge(&path, yes).await?;
    let local_path = absolute.to_string_lossy().to_string();
    let outcome = ops::accept_invite(&code_or_url, absolute, on_demand, acknowledged).await?;
    print_lines(&accept_invite_lines(
        &outcome.group_id,
        &local_path,
        on_demand,
        outcome.awaiting_approval,
    ));
    Ok(())
}

/// What `share accept` prints once the daemon reports success.
///
/// The redemption succeeding does NOT mean the folder is syncing: an invite
/// minted with `--require-approval` lands the membership in the group
/// owner's queue, and until they decide, the linked folder deliberately syncs
/// nothing. So the two outcomes get genuinely different wording, and the
/// waiting one names the command that shows the current answer.
fn accept_invite_lines(
    group_id: &str,
    local_path: &str,
    on_demand: bool,
    awaiting_approval: bool,
) -> Vec<String> {
    let storage = if on_demand { " (on-demand)" } else { "" };
    if !awaiting_approval {
        return vec![format!(
            "Joined folder group {group_id} and linked it at {local_path}{storage}"
        )];
    }
    vec![
        format!(
            "Invite redeemed for folder group {group_id}, and the folder is linked at \
             {local_path}{storage} -- but it is NOT syncing yet."
        ),
        "This invite requires the group owner's approval. Nothing will sync until they \
         approve it, and there is no notification when they do."
            .to_string(),
        "Check the current answer with:   yadorilink share list".to_string(),
    ]
}

fn storage_mode_lines(
    group_name: &str,
    on_demand: bool,
    outcome: &StorageModeOutcome,
) -> Vec<String> {
    if !outcome.changed {
        return vec![format!("{group_name} is already {}", ops::storage_mode_str(on_demand))];
    }
    let mut lines =
        vec![format!("Set {group_name} storage mode to {}", ops::storage_mode_str(on_demand))];
    // Set only when this demotion actually went through the coordination-plane
    // handoff role-loss commit.
    if let Some(result) = &outcome.handoff_result {
        lines.push(format!(
            "  handoff completed: target={} membership_generation={}{}",
            result.target_device_id,
            result.membership_generation,
            if result.lease_id.is_empty() {
                String::new()
            } else {
                format!(" lease={}", result.lease_id)
            }
        ));
    }
    lines
}

/// `yadorilink share set-storage-mode <group> --mode <eager|on-demand>`:
/// changes this device's storage mode for a folder group it already links.
/// The demotion direction is gated by a durability handoff; the daemon is the
/// sole orchestrator of both the coordination-plane write and the local
/// policy flip.
pub async fn set_storage_mode(group_name: String, mode: String) -> Result<(), CliError> {
    let on_demand = ops::parse_storage_mode(&mode)?;
    let outcome = ops::set_storage_mode(&group_name, on_demand).await?;
    print_lines(&storage_mode_lines(&group_name, on_demand, &outcome));
    Ok(())
}

fn print_lines(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests;
