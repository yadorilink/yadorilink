//! Folder groups, their members, invites and approvals: the coordination
//! plane's `/shares/*` routes, and the daemon commands that change
//! membership.
//!
//! Same-account `revoke`/`join` are roleless: every authorized device is a
//! full bidirectional peer there. `grant` (also same-account) is role-aware
//! and the coordination plane defaults an omitted role to `editor`.
//! Cross-account sharing (`invite`/`accept`) is role-aware too, with a
//! DIFFERENT omitted-role default (`viewer`, least privilege for a
//! stranger-facing invite). `owner` is available through neither: there is no
//! management-authority model yet to back it.
//!
//! Every membership mutation goes through a daemon command rather than
//! straight to the coordination plane, so the daemon's durability readiness
//! gate and crash-safe enrollment protocol apply to every front end alike.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::coordination::http_client::CoordinationAccess;
use serde::{Deserialize, Serialize};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    accept_invite_command_response, create_and_link_command_response,
    delete_group_command_response, join_and_link_command_response, mint_invite_command_response,
    revoke_device_command_response, revoke_edge_command_response, AcceptInviteCommandRequest,
    ApplicationErrorCode, CheckFullReplicaHandoffReadyRequest, CreateAndLinkCommandRequest,
    DeleteGroupCommandRequest, HandoffResult, JoinAndLinkCommandRequest, ListLinksRequest,
    MintInviteCommandRequest, MintedInviteInfo, ReplicaMembershipCommandOutcome,
    RevokeDeviceCommandRequest, RevokeEdgeCommandRequest, SetStorageModeRequest,
};

use crate::coordination::http_client::{
    delete_no_content, get_json, post_json, post_json_no_content, require_auth,
};
use crate::daemon::control;
use crate::error::{CoreError, Hint};

/// Maps a storage-mode word to the daemon's `on_demand` flag: `eager`
/// (store everything) links a fully-hydrated folder; `on-demand` (store only
/// needed files) creates placeholders fetched on first access.
pub fn parse_storage_mode(mode: &str) -> Result<bool, CoreError> {
    match mode.to_ascii_lowercase().as_str() {
        "eager" | "everything" => Ok(false),
        "on-demand" | "ondemand" | "needed" => Ok(true),
        other => Err(CoreError::InvalidInput(format!(
            "invalid --storage-mode {other:?} (expected eager or on-demand)"
        ))),
    }
}

/// The coordination plane's storage-mode word for a link's `on_demand` flag:
/// an eager (store-everything) full replica, or an on-demand cache.
#[must_use]
pub fn storage_mode_str(on_demand: bool) -> &'static str {
    if on_demand {
        "on-demand"
    } else {
        "eager"
    }
}

// The coordination plane's `/shares/groups` route emits camelCase JSON keys
// (`groupId`, `name`) -- `#[serde(rename_all = "camelCase")]` is load-bearing:
// without it, `group_id` matches nothing in the response body and every
// caller of `resolve_group_id`/`list_groups` fails deserialization outright.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FolderGroupInfo {
    group_id: String,
    name: String,
}
#[derive(Deserialize)]
struct ListGroupsResponse {
    groups: Vec<FolderGroupInfo>,
}

/// A folder group: the add-folder picker offers one of these per group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupSummary {
    pub group_id: String,
    pub name: String,
}

/// The folder groups this account OWNS (`GET /shares/groups`).
pub async fn list_groups() -> Result<Vec<GroupSummary>, CoreError> {
    let auth = require_auth().await?;
    let resp: ListGroupsResponse = get_json("/shares/groups", &auth).await?;
    Ok(resp
        .groups
        .into_iter()
        .map(|g| GroupSummary { group_id: g.group_id, name: g.name })
        .collect())
}

/// Resolves a folder group's human-readable name to its `group_id`.
///
/// Resolves against TWO listings, in this order:
///
/// 1. `GET /shares/groups`, which the coordination plane scopes to the groups
///    this account OWNS.
/// 2. `GET /shares`, which returns every ACL edge visible to this account --
///    its own groups' edges AND the edges binding its own devices into groups
///    owned by SOMEONE ELSE -- each carrying that group's name and id.
///
/// The second lookup is what makes a name resolvable at all for an account
/// that only ever joined a group by accepting a cross-account invite: it owns
/// no groups, so the owner-scoped first listing is empty for it.
///
/// Owned groups are consulted first so a name that exists in both listings
/// resolves to the account's OWN group, deterministically. The fallback
/// grants nothing: authorization stays entirely server-side and per-route.
pub async fn resolve_group_id(
    auth: &CoordinationAccess,
    group_name: &str,
) -> Result<String, CoreError> {
    let owned: ListGroupsResponse = get_json("/shares/groups", auth).await?;
    if let Some(group) = owned.groups.into_iter().find(|g| g.name == group_name) {
        return Ok(group.group_id);
    }
    let shared: ListSharesResponse = get_json("/shares", auth).await?;
    shared.edges.into_iter().find(|e| e.group_name == group_name).map(|e| e.group_id).ok_or_else(
        || {
            CoreError::InvalidInput(format!(
                "no folder group named {group_name:?} is visible to this account"
            ))
            .hinted(Hint::CreateOrAcceptShare)
        },
    )
}

/// Signs in and resolves `group_name` (see [`resolve_group_id`]).
pub async fn resolve_group_name(group_name: &str) -> Result<String, CoreError> {
    let auth = require_auth().await?;
    resolve_group_id(&auth, group_name).await
}

/// Mints a one-use, expiring, device-scoped cross-account invite for an
/// ALREADY-RESOLVED group id and returns the coordination plane's own record
/// of it.
///
/// Minting goes through the daemon (`MintInviteCommand`) rather than a direct
/// HTTP call: the coordination plane requires a minting device id, and the
/// daemon is the only thing on this machine that knows this device's own id.
///
/// An omitted `role`/`ttl_secs` is forwarded as the proto's own "unset"
/// value (empty string / `0`), which the coordination plane resolves to its
/// defaults (`viewer`, 7 days) -- the client never guesses those locally.
pub async fn mint_invite_resolved(
    group_id: String,
    role: Option<String>,
    ttl_secs: Option<u64>,
    require_approval: bool,
) -> Result<MintedInviteInfo, CoreError> {
    let response = control::send(ReqPayload::MintInviteCommand(MintInviteCommandRequest {
        group_id,
        role: role.unwrap_or_default(),
        ttl_secs: ttl_secs.unwrap_or(0),
        requires_approval: require_approval,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::MintInviteCommand(response)) => match response.result {
            Some(mint_invite_command_response::Result::Outcome(invite)) => Ok(invite),
            Some(mint_invite_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty invite result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to mint-invite".into())),
    }
}

/// Same as [`mint_invite_resolved`], for a caller holding the folder group's
/// human-readable name instead of its id.
pub async fn mint_invite(
    group_name: &str,
    role: Option<String>,
    ttl_secs: Option<u64>,
    require_approval: bool,
) -> Result<MintedInviteInfo, CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    mint_invite_resolved(group_id, role, ttl_secs, require_approval).await
}

/// One not-yet-redeemed invite this account has minted, from
/// `GET /shares/invites` -- pending (still usable), expired, or cancelled.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInviteInfo {
    pub invite_id: String,
    pub group_id: String,
    pub group_name: String,
    pub role: String,
    pub expires_at_unix: i64,
    pub status: String,
}
#[derive(Deserialize)]
struct ListPendingInvitesResponse {
    invites: Vec<PendingInviteInfo>,
}

/// Every invite this account has minted that nobody has redeemed yet. An
/// invite someone HAS redeemed is an ordinary grant instead, listed by
/// [`list_shares_resolved`].
pub async fn list_invites_resolved() -> Result<Vec<PendingInviteInfo>, CoreError> {
    let auth = require_auth().await?;
    let resp: ListPendingInvitesResponse = get_json("/shares/invites", &auth).await?;
    Ok(resp.invites)
}

/// Withdraws a not-yet-redeemed invite before it is ever used or expires.
/// HTTP-only: there is no local device state involved. A no-op success if the
/// invite was already cancelled; the coordination plane refuses one that was
/// already accepted, or never existed.
pub async fn cancel_invite(invite_id: &str) -> Result<(), CoreError> {
    let auth = require_auth().await?;
    delete_no_content(&format!("/shares/invites/{invite_id}"), &auth).await
}

// The coordination plane reads camelCase JSON keys; these request bodies must
// serialize to match, or the field arrives undefined server-side. The
// enrollment bodies below have no production caller here any more (the daemon
// runs that protocol), but their camelCase contract is still pinned by the
// unit tests, so they stay test-only rather than being deleted outright.
#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupRequest<'a> {
    name: &'a str,
    creating_device_id: &'a str,
}

#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationIdBody<'a> {
    operation_id: &'a str,
}

#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareCreateRequest<'a> {
    operation_id: &'a str,
    name: &'a str,
    creating_device_id: &'a str,
}

#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrepareJoinRequest<'a> {
    operation_id: &'a str,
    device_id: &'a str,
    storage_mode: &'a str,
}

#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JoinOperationBody<'a> {
    operation_id: &'a str,
    device_id: &'a str,
}

/// Creates a group and links an already-resolved, already-preflighted local
/// path to it, through the daemon's crash-safe Pending -> Active enrollment:
/// prepare a Pending group (plus the creating device's Pending eager
/// membership), commit the local link, then activate. A failed link step, or
/// a CONFIRMED "never activated" answer, cancels the Pending group and rolls
/// the link back, so no phantom full replica is left counted. An AMBIGUOUS
/// activate leaves the link and its marker for the daemon's reconciliation
/// sweep. Returns the new group id.
/// What creating a provider-backed folder produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderFolderCreated {
    pub group_id: String,
    pub root_id: String,
    /// The request was a retry of one that had already completed.
    pub already_existed: bool,
}

/// Runs one provider-folder request under its durable retry identity: the token of the same payload is
/// reused across restarts, written before the request is sent, and forgotten only on success or a
/// definitive refusal.
async fn with_durable_token<F, Fut>(
    signature: String,
    send: F,
) -> Result<ProviderFolderCreated, CoreError>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<ProviderFolderCreated, CoreError>>,
{
    let store = super::provider_pending::PendingStore::at(
        super::provider_pending::PendingStore::default_path()?,
    );
    let token = store.token_for(&signature).map_err(|e| {
        CoreError::Other(format!("could not record the request before sending it: {e}"))
    })?;
    let result = send(token).await;
    if result.is_ok()
        || result.as_ref().is_err_and(super::provider_pending::is_definitive_rejection)
    {
        store.clear(&signature);
    }
    result
}

/// Creates a NEW group and a provider-backed folder (no directory: the File Provider domain is the
/// folder). The request's retry identity is kept on disk, so repeating the SAME request (even after
/// this process was restarted) is answered with the folder it already made.
pub async fn create_provider_folder(
    group_name: String,
    display_name: String,
    on_demand: bool,
) -> Result<ProviderFolderCreated, CoreError> {
    let signature =
        super::provider_pending::signature("create", "", &group_name, &display_name, on_demand);
    with_durable_token(signature, |token| {
        create_provider_folder_with_token(group_name, display_name, token, on_demand)
    })
    .await
}

async fn create_provider_folder_with_token(
    group_name: String,
    display_name: String,
    request_token: String,
    on_demand: bool,
) -> Result<ProviderFolderCreated, CoreError> {
    let response = control::send(ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
        group_name,
        local_path: String::new(),
        on_demand,
        acknowledge_risks: false,
        provider_display_name: display_name,
        request_token,
        create_local_path_if_missing: false,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::CreateAndLinkCommand(response)) => match response.result {
            Some(create_and_link_command_response::Result::Outcome(outcome)) => {
                Ok(ProviderFolderCreated {
                    group_id: outcome.group_id,
                    root_id: outcome.provider_root_id,
                    already_existed: outcome.already_linked,
                })
            }
            Some(create_and_link_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty create result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to create-and-link".into())),
    }
}

/// Joins an EXISTING group as a provider-backed folder (see [`create_provider_folder`]).
pub async fn join_provider_folder(
    group_id: String,
    group_name: String,
    display_name: String,
    on_demand: bool,
) -> Result<ProviderFolderCreated, CoreError> {
    let signature = super::provider_pending::signature(
        "join",
        &group_id,
        &group_name,
        &display_name,
        on_demand,
    );
    with_durable_token(signature, |token| {
        join_provider_folder_with_token(group_id, group_name, display_name, token, on_demand)
    })
    .await
}

async fn join_provider_folder_with_token(
    group_id: String,
    group_name: String,
    display_name: String,
    request_token: String,
    on_demand: bool,
) -> Result<ProviderFolderCreated, CoreError> {
    let response = control::send(ReqPayload::JoinAndLinkCommand(JoinAndLinkCommandRequest {
        group_id,
        group_name,
        local_path: String::new(),
        on_demand,
        acknowledge_risks: false,
        provider_display_name: display_name,
        request_token,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::JoinAndLinkCommand(response)) => match response.result {
            Some(join_and_link_command_response::Result::Outcome(outcome)) => {
                Ok(ProviderFolderCreated {
                    group_id: outcome.group_id,
                    root_id: outcome.provider_root_id,
                    already_existed: outcome.already_linked,
                })
            }
            Some(join_and_link_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty join result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to join-and-link".into())),
    }
}

pub async fn create_and_link(
    group_name: String,
    absolute_path: PathBuf,
    on_demand: bool,
    acknowledge_risks: bool,
) -> Result<String, CoreError> {
    create_and_link_inner(group_name, absolute_path, on_demand, acknowledge_risks, false).await
}

/// As [`create_and_link`], for a directory that may not exist yet: the daemon creates it
/// (and any missing parents) before linking. An existing directory is left as it is.
pub async fn create_and_link_creating_directory(
    group_name: String,
    absolute_path: PathBuf,
    on_demand: bool,
) -> Result<String, CoreError> {
    create_and_link_inner(group_name, absolute_path, on_demand, false, true).await
}

async fn create_and_link_inner(
    group_name: String,
    absolute_path: PathBuf,
    on_demand: bool,
    acknowledge_risks: bool,
    create_local_path_if_missing: bool,
) -> Result<String, CoreError> {
    let response = control::send(ReqPayload::CreateAndLinkCommand(CreateAndLinkCommandRequest {
        group_name,
        local_path: absolute_path.to_string_lossy().to_string(),
        on_demand,
        acknowledge_risks,
        provider_display_name: String::new(),
        request_token: String::new(),
        create_local_path_if_missing,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::CreateAndLinkCommand(response)) => match response.result {
            Some(create_and_link_command_response::Result::Outcome(outcome)) => {
                Ok(outcome.group_id)
            }
            Some(create_and_link_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty create result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to create-and-link".into())),
    }
}

/// `role` is `skip_serializing_if = "Option::is_none"` so an omitted role
/// produces a request body with NO `role` key at all (not a JSON `null`):
/// the coordination plane treats an absent key (defaults to editor for this
/// route) very differently from a present-but-null one (rejected).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantRequest<'a> {
    device_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<&'a str>,
}

/// `role` is the device's actual EFFECTIVE role after the call, and
/// `created` says whether this call was the one that granted it.
#[derive(Deserialize)]
struct GrantResponse {
    role: String,
    created: bool,
}

/// What a same-account grant did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantOutcome {
    /// The device's effective role after the call: the newly granted role
    /// when `created`, otherwise its pre-existing role, UNCHANGED even if a
    /// different role was requested (this route never updates an existing
    /// grant's role in place).
    pub role: String,
    /// Whether this call granted the access, rather than finding the device
    /// already authorized.
    pub created: bool,
}

/// Authorizes another of this account's own registered devices for a folder
/// group. Same-account only. The coordination plane resolves an omitted role
/// to `editor` and reports the device's actual effective role back.
pub async fn grant(
    group_name: &str,
    device_id: &str,
    role: Option<&str>,
) -> Result<GrantOutcome, CoreError> {
    let auth = require_auth().await?;
    let group_id = resolve_group_id(&auth, group_name).await?;
    let response: GrantResponse = post_json(
        &format!("/shares/groups/{group_id}/grant"),
        &GrantRequest { device_id, role },
        &auth,
    )
    .await?;
    Ok(GrantOutcome { role: response.role, created: response.created })
}

/// One device in a folder group's "people with access" listing. Mirrors the
/// coordination plane's `GroupMemberInfo` response shape exactly --
/// group-scoped minimal identity only (device name and id), no email address.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupMemberInfo {
    pub device_id: String,
    pub device_name: String,
    /// `"viewer"` / `"editor"` in ordinary use; `"unknown"` for a genuine
    /// data-integrity anomaly. Kept as a plain string: an unrecognized future
    /// role (or the `"unknown"` sentinel) still renders instead of failing
    /// the whole listing.
    pub role: String,
    /// Whether this device is on the SAME account that OWNS the group --
    /// relative to the group owner, not to the caller. See
    /// `wording::member_relationship_label` for a caller-relative label.
    pub is_same_account: bool,
    /// Whether this device is on the SAME account as the account making THIS
    /// request, regardless of who owns the group.
    pub is_caller_account: bool,
    pub storage_mode: String,
    pub online: bool,
    pub last_seen_unix: i64,
}
#[derive(Deserialize)]
struct ListMembersResponse {
    members: Vec<GroupMemberInfo>,
}

/// This device's own id, when this machine has a local device identity at
/// all. Best-effort by design: a device that has never registered locally
/// simply never matches "you" in a member listing.
#[must_use]
pub fn own_device_id() -> Option<String> {
    crate::coordination::device_config::load().ok().map(|c| c.device_id)
}

/// Who has access to an ALREADY-RESOLVED folder group id.
pub async fn list_members_resolved(group_id: &str) -> Result<Vec<GroupMemberInfo>, CoreError> {
    let auth = require_auth().await?;
    fetch_members(&auth, group_id, own_device_id().as_deref()).await
}

/// The member listing as this machine presents it; `own_device_id` is this
/// machine's own device.
///
/// This machine is running, so its own device is shown online whatever the
/// coordination plane last observed of its subscription (a reconnect in
/// flight, a projection not yet caught up). A presentation guarantee only:
/// every other device keeps the service's presence, and nothing that decides
/// durability reads `online`.
async fn fetch_members(
    auth: &CoordinationAccess,
    group_id: &str,
    own_device_id: Option<&str>,
) -> Result<Vec<GroupMemberInfo>, CoreError> {
    let response: ListMembersResponse =
        get_json(&format!("/shares/groups/{group_id}/members"), auth).await?;
    let mut members = response.members;
    for member in &mut members {
        if Some(member.device_id.as_str()) == own_device_id {
            member.online = true;
        }
    }
    Ok(members)
}

/// Same as [`list_members_resolved`], for a caller holding the folder group's
/// human-readable name instead of its id.
pub async fn list_members(group_name: &str) -> Result<Vec<GroupMemberInfo>, CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    list_members_resolved(&group_id).await
}

/// The request body for a live role change. `role` is always present --
/// this route REQUIRES it (an omitted role on an existing collaborator must
/// never silently default).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeRoleRequest<'a> {
    device_id: &'a str,
    role: &'a str,
}

/// The roles a role change may move an existing member to. `owner` is
/// deliberately absent: there is no management-authority model yet to back
/// an Owner grant, and the coordination plane rejects it on this route.
pub const CHANGEABLE_ROLES: [&str; 2] = ["viewer", "editor"];

/// Validates a requested role for a role change.
///
/// Exact, case-sensitive matching against [`CHANGEABLE_ROLES`], mirroring the
/// coordination plane's own exact-match role set: accepting a spelling the
/// plane would refuse would only move the failure one round trip later.
pub fn validate_changeable_role(role: &str) -> Result<(), CoreError> {
    if CHANGEABLE_ROLES.contains(&role) {
        return Ok(());
    }
    Err(CoreError::InvalidInput(format!(
        "invalid --role {role:?} (expected {}); owner is not available via this command yet",
        CHANGEABLE_ROLES.join(" or ")
    )))
}

/// Moves an already-granted device to a different role in an
/// ALREADY-RESOLVED folder group. HTTP-only: a role change never touches
/// this machine's local link state. A request naming the device's CURRENT
/// role is a no-op success, which is why this is safe to retry.
pub async fn change_role_resolved(
    group_id: &str,
    device_id: &str,
    role: &str,
) -> Result<(), CoreError> {
    validate_changeable_role(role)?;
    let auth = require_auth().await?;
    post_json_no_content(
        &format!("/shares/groups/{group_id}/role"),
        &ChangeRoleRequest { device_id, role },
        &auth,
    )
    .await
}

/// Same as [`change_role_resolved`], for a caller holding the group's name.
/// The role is validated before anything else, so a refused role never costs
/// a sign-in or a network round trip.
pub async fn change_role(group_name: &str, device_id: &str, role: &str) -> Result<(), CoreError> {
    validate_changeable_role(role)?;
    let group_id = resolve_group_name(group_name).await?;
    change_role_resolved(&group_id, device_id, role).await
}

/// How a revoke attempt ended.
///
/// The durability refusal is a distinct variant rather than just another
/// error because it is the ONLY revoke failure that `force` can get past, and
/// the only one where offering an override is honest. Every other failure
/// stays an ordinary error: presenting a data-loss confirmation for a failure
/// that has nothing to do with data loss would train people to click through
/// the one confirmation that matters.
pub enum RevokeAttempt {
    Committed(ReplicaMembershipCommandOutcome),
    /// The daemon refused before touching the coordination plane: revoking
    /// would leave the folder group without another confirmed-ready full
    /// replica. `message` is the daemon's own wording, and `group_ids` are the
    /// groups it named as not ready.
    NotDurable {
        message: String,
        group_ids: Vec<String>,
    },
}

/// Takes a device's access to an ALREADY-RESOLVED folder group away, with
/// the durability refusal reported as an outcome rather than an error -- for
/// a caller that can offer the override to a person.
///
/// Going through the daemon applies the durability readiness gate: without
/// `force`, a revoke that would leave the group without another
/// confirmed-ready full replica is refused BEFORE any coordination-plane
/// write. `force` is a data-loss override, never a retry convenience.
pub async fn try_revoke_resolved(
    group_id: String,
    device_id: String,
    force: bool,
) -> Result<RevokeAttempt, CoreError> {
    let response = control::send(ReqPayload::RevokeDeviceCommand(RevokeDeviceCommandRequest {
        group_id,
        device_id,
        force,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::RevokeDeviceCommand(response)) => classify_revoke_result(response.result),
        _ => Err(CoreError::Other("unexpected daemon response to revoke".into())),
    }
}

/// Sorts the daemon's revoke result into "committed", "refused for
/// durability" and "failed", positively matching the one error code `force`
/// can get past. Getting it wrong in either direction is a real hazard: a
/// misclassified other-failure offers a data-loss override that would not
/// have helped, and a misclassified refusal leaves a legitimate override
/// unreachable.
fn classify_revoke_result(
    result: Option<revoke_device_command_response::Result>,
) -> Result<RevokeAttempt, CoreError> {
    match result {
        Some(revoke_device_command_response::Result::Outcome(outcome)) => {
            Ok(RevokeAttempt::Committed(outcome))
        }
        Some(revoke_device_command_response::Result::Error(error)) => {
            if ApplicationErrorCode::try_from(error.code)
                .is_ok_and(|code| code == ApplicationErrorCode::ReplicaNotReady)
            {
                return Ok(RevokeAttempt::NotDurable {
                    message: error.message,
                    group_ids: error.group_ids,
                });
            }
            Err(CoreError::from_command_error(error))
        }
        None => Err(CoreError::Other("daemon returned an empty revoke result".into())),
    }
}

/// [`try_revoke_resolved`] with the durability refusal as an error
/// ([`CoreError::DurabilityBlocked`]). The returned outcome carries the
/// warnings a caller must still show (`wording::membership_outcome_warnings`).
pub async fn revoke_resolved(
    group_id: String,
    device_id: String,
    force: bool,
) -> Result<ReplicaMembershipCommandOutcome, CoreError> {
    match try_revoke_resolved(group_id, device_id, force).await? {
        RevokeAttempt::Committed(outcome) => Ok(outcome),
        RevokeAttempt::NotDurable { message, group_ids } => {
            Err(CoreError::DurabilityBlocked { message, group_ids })
        }
    }
}

/// What a FRESH read of this folder's access state says about the request a
/// Deny was just clicked for.
///
/// The requests panel is read when the window opens and after this window's
/// own actions, never on a timer, so a row can still name a request that was
/// decided somewhere else -- from another device, or another session --
/// minutes ago. For every other control in the panel that is harmless. For
/// this one it is not: denying IS revoking (see the share window's
/// deny action), so a Deny aimed at a request that has since been
/// APPROVED would not turn a request down, it would remove a member whose
/// access is live and working, and report it as a request being turned down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyPrecheck {
    /// Still waiting on a decision. Denying turns it down, which is exactly
    /// what the button says it does.
    StillWaiting,
    /// Not waiting any more, so the denial must not be sent at all.
    NotWaiting(DenyRefusal),
}

/// Why a Deny was not carried out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyRefusal {
    /// The request was approved already and this device now holds live
    /// access to the folder. Taking that away is a removal, and a removal
    /// belongs in the member list, behind the confirmation that names it as
    /// one.
    AlreadyAdmitted,
    /// Neither waiting nor a member. All this listing establishes is that
    /// the request is gone; it cannot say which of the several causes did
    /// it -- turned down or approved-then-removed elsewhere, withdrawn by
    /// the requester, or swept by the coordination plane when the invite it
    /// came from expired. Either way there is nothing left to decide, and
    /// the message this maps to names the possibilities rather than picking
    /// one it cannot actually observe.
    NoLongerListed,
}

/// Re-decides, from listings read immediately before the mutation would be
/// sent, whether a Deny is still the thing the button claims it is.
///
/// `members` is already scoped to this folder group (it is the group's own
/// member listing); `pending` is account-wide, so it is narrowed by group id
/// here for the same reason `pending_rows` narrows it.
///
/// Membership is checked FIRST and wins outright. The two listings come from
/// two separate reads, so a request approved in between them can appear in
/// both, and the safe reading of "this is a live member" is the one that
/// stops the removal rather than the one that sends it.
pub fn deny_precheck(
    pending: &[PendingApproval],
    members: &[GroupMemberInfo],
    group_id: &str,
    device_id: &str,
) -> DenyPrecheck {
    if members.iter().any(|member| member.device_id == device_id) {
        return DenyPrecheck::NotWaiting(DenyRefusal::AlreadyAdmitted);
    }
    let still_waiting = pending
        .iter()
        .any(|request| request.group_id == group_id && request.device_id == device_id);
    if still_waiting {
        DenyPrecheck::StillWaiting
    } else {
        DenyPrecheck::NotWaiting(DenyRefusal::NoLongerListed)
    }
}

impl DenyRefusal {
    /// Plain-language reason, for a front end with no wording of its own.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            DenyRefusal::AlreadyAdmitted => {
                "This device was already approved and now has access, so nothing was changed. \
                 Removing it is a separate action: remove its access from the member list."
            }
            DenyRefusal::NoLongerListed => {
                "This request is no longer waiting for approval (resolved, withdrawn, or \
                 expired elsewhere). Nothing was changed."
            }
        }
    }
}

/// How [`deny_checked`] ended.
pub enum DenyAttempt {
    /// The precheck stopped it; nothing was sent.
    Refused(DenyRefusal),
    Attempted(RevokeAttempt),
}

/// Denies a waiting request: re-reads the pending and member listings, and
/// only when the request is still waiting sends the (never forced) revoke.
/// An unreadable listing is an error and sends nothing.
pub async fn deny_checked(group_id: String, device_id: String) -> Result<DenyAttempt, CoreError> {
    let pending = pending_approvals().await?;
    let members = list_members_resolved(&group_id).await?;
    match deny_precheck(&pending, &members, &group_id, &device_id) {
        DenyPrecheck::NotWaiting(refusal) => Ok(DenyAttempt::Refused(refusal)),
        DenyPrecheck::StillWaiting => {
            Ok(DenyAttempt::Attempted(try_revoke_resolved(group_id, device_id, false).await?))
        }
    }
}

/// Same as [`revoke_resolved`], for a caller holding the group's name.
pub async fn revoke(
    group_name: &str,
    device_id: String,
    force: bool,
) -> Result<ReplicaMembershipCommandOutcome, CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    revoke_resolved(group_id, device_id, force).await
}

/// How revoking one share edge ended.
pub enum RevokeEdgeOutcome {
    Revoked(ReplicaMembershipCommandOutcome),
    /// The edge no longer exists: treated as already revoked.
    AlreadyRevoked,
}

/// Revokes one share edge by id. The daemon resolves `edge_id` to its
/// group/device on the coordination plane and runs the same durability
/// readiness gate a device revoke runs, so there is no window between a
/// listing and a delete where the gate could be skipped.
pub async fn revoke_edge(edge_id: &str, force: bool) -> Result<RevokeEdgeOutcome, CoreError> {
    let response = control::send(ReqPayload::RevokeEdgeCommand(RevokeEdgeCommandRequest {
        edge_id: edge_id.to_owned(),
        force,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::RevokeEdgeCommand(response)) => match response.result {
            Some(revoke_edge_command_response::Result::Outcome(outcome)) => {
                Ok(RevokeEdgeOutcome::Revoked(outcome))
            }
            Some(revoke_edge_command_response::Result::Error(error)) => {
                if ApplicationErrorCode::try_from(error.code)
                    .is_ok_and(|code| code == ApplicationErrorCode::TargetNotFound)
                {
                    return Ok(RevokeEdgeOutcome::AlreadyRevoked);
                }
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty revoke result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to revoke".into())),
    }
}

/// Deletes a folder group outright. Terminal: the group and every ACL edge on
/// it are gone. Goes through the daemon rather than a raw HTTP DELETE, like
/// every other membership mutation.
pub async fn delete_group(
    group_name: &str,
    acknowledge_cross_account_members: bool,
) -> Result<(), CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    let response = control::send(ReqPayload::DeleteGroupCommand(DeleteGroupCommandRequest {
        group_id,
        acknowledge_cross_account_members,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::DeleteGroupCommand(response)) => match response.result {
            Some(delete_group_command_response::Result::Ok(_)) => Ok(()),
            Some(delete_group_command_response::Result::Error(error)) => {
                Err(CoreError::Other(error))
            }
            None => Err(CoreError::Other("daemon returned an empty delete-group result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to delete".into())),
    }
}

/// The coordination plane's `state` value for an edge that has been
/// accepted by its invited device but is waiting for the group owner to admit
/// it. Matched as a plain string: an unrecognized future state must still
/// render, not fail the whole listing.
pub const STATE_PENDING_APPROVAL: &str = "pending_approval";

/// One ACL edge from `GET /shares` -- every folder-group/device/role/state
/// combination this account can see across the whole account.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareEdgeInfo {
    pub edge_id: String,
    pub group_id: String,
    pub group_name: String,
    pub device_id: String,
    /// The edge's membership state. Required: `acl.state` is NOT NULL and the
    /// listing reports it for every row.
    pub state: String,
    /// The current effective role for a live member, or the role the
    /// originating invite asked for when no grant has been emitted yet.
    /// `None` when the coordination plane has neither.
    #[serde(default)]
    pub role: Option<String>,
}
#[derive(Deserialize)]
struct ListSharesResponse {
    edges: Vec<ShareEdgeInfo>,
}

/// Every ACL edge this account can see, across every folder group.
pub async fn list_shares_resolved() -> Result<Vec<ShareEdgeInfo>, CoreError> {
    let auth = require_auth().await?;
    let resp: ListSharesResponse = get_json("/shares", &auth).await?;
    Ok(resp.edges)
}

/// Whether this edge is one SOMEONE is being asked to decide on. A positive
/// match on the exact state, never "not active".
fn is_awaiting_approval(edge: &ShareEdgeInfo) -> bool {
    edge.state == STATE_PENDING_APPROVAL
}

/// The subset of `edges` this account is genuinely being asked to decide on:
/// awaiting approval AND belonging to a folder group this account OWNS.
///
/// Both halves are load-bearing. `GET /shares` also returns an INVITED
/// account's own awaiting-approval edge, and showing an invitee their own
/// request with instructions to approve it is wrong -- only the group owner
/// can act. `owned_group_ids` comes from the owner-scoped `/shares/groups`
/// listing, since `ShareEdgeInfo` deliberately carries no owner field.
fn approval_requests_awaiting_owner(
    edges: Vec<ShareEdgeInfo>,
    owned_group_ids: &HashSet<String>,
) -> Vec<ShareEdgeInfo> {
    edges
        .into_iter()
        .filter(|edge| is_awaiting_approval(edge) && owned_group_ids.contains(&edge.group_id))
        .collect()
}

/// One device waiting for this account's approval to join a folder group it
/// owns. A distinct type from `ShareEdgeInfo`: what reaches here has already
/// been filtered to "this account genuinely has to decide on it".
#[derive(Clone, Debug, PartialEq)]
pub struct PendingApproval {
    pub group_id: String,
    pub group_name: String,
    pub device_id: String,
    /// The role the originating invite asked for. `None` when the
    /// coordination plane reported none.
    pub role: Option<String>,
}

impl PendingApproval {
    fn from_edge(edge: ShareEdgeInfo) -> Self {
        PendingApproval {
            group_id: edge.group_id,
            group_name: edge.group_name,
            device_id: edge.device_id,
            role: edge.role,
        }
    }
}

/// Every request this account is being asked to decide on, across all the
/// folder groups it owns.
///
/// Reads the same `GET /shares` listing as [`list_shares_resolved`] and
/// filters client-side, intersected with the owner-scoped `/shares/groups`
/// listing -- see `approval_requests_awaiting_owner`. This is a pull, not a
/// notification.
pub async fn pending_approvals() -> Result<Vec<PendingApproval>, CoreError> {
    let auth = require_auth().await?;
    let owned_group_ids: HashSet<String> =
        list_groups().await?.into_iter().map(|group| group.group_id).collect();
    let resp: ListSharesResponse = get_json("/shares", &auth).await?;
    Ok(approval_requests_awaiting_owner(resp.edges, &owned_group_ids)
        .into_iter()
        .map(PendingApproval::from_edge)
        .collect())
}

/// `result` is `approved` when this call is what admitted the device, or
/// `already_active` when it was already a member.
#[derive(Deserialize)]
struct ApproveResponse {
    result: String,
}

/// The approve route names its whole request in the URL and reads no body,
/// so there is no field an approving caller could use to widen the granted
/// role. This empty struct exists only because `post_json` always sends a
/// JSON body.
#[derive(Serialize)]
struct ApproveRequest {}

/// Admits a waiting device into an ALREADY-RESOLVED folder group and returns
/// the coordination plane's own `result` value (see
/// `wording::approve_result_line`). The granted role is the one the redeemed
/// invite named; there is no way to widen it here.
pub async fn approve_resolved(group_id: &str, device_id: &str) -> Result<String, CoreError> {
    let auth = require_auth().await?;
    let response: ApproveResponse = post_json(
        &format!("/shares/groups/{group_id}/members/{device_id}/approve"),
        &ApproveRequest {},
        &auth,
    )
    .await?;
    Ok(response.result)
}

/// Same as [`approve_resolved`], for a caller holding the group's name.
pub async fn approve(group_name: &str, device_id: &str) -> Result<String, CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    approve_resolved(&group_id, device_id).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinableGroupInfo {
    group_id: String,
    name: String,
}
#[derive(Deserialize)]
struct ListJoinableResponse {
    groups: Vec<JoinableGroupInfo>,
}

/// The folder groups this account owns and may join on this device. Identity
/// only: name/id, never file names or content.
pub async fn list_joinable_groups() -> Result<Vec<GroupSummary>, CoreError> {
    let auth = require_auth().await?;
    let resp: ListJoinableResponse = get_json("/shares/joinable", &auth).await?;
    Ok(resp
        .groups
        .into_iter()
        .map(|g| GroupSummary { group_id: g.group_id, name: g.name })
        .collect())
}

/// Resolves a joinable folder group by its human-readable name to its
/// `group_id`, searching the account's owned joinable set.
pub async fn resolve_joinable_group_id(group_name: &str) -> Result<String, CoreError> {
    let auth = require_auth().await?;
    resolve_joinable_group_id_with(&auth, group_name).await
}

/// [`resolve_joinable_group_id`] against a given coordination session.
async fn resolve_joinable_group_id_with(
    auth: &CoordinationAccess,
    group_name: &str,
) -> Result<String, CoreError> {
    let resp: ListJoinableResponse = get_json("/shares/joinable", auth).await?;
    resp.groups.into_iter().find(|g| g.name == group_name).map(|g| g.group_id).ok_or_else(|| {
        CoreError::InvalidInput(format!("no joinable folder group named {group_name:?}"))
            .hinted(Hint::ListJoinableShares)
    })
}

/// What a same-account join did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinOutcome {
    /// The folder was already linked to this group and running, so nothing
    /// changed locally: a repeated join is a no-op, not a fresh join.
    pub already_linked: bool,
}

/// Crash-safe join for a caller that already selected a group by id and
/// completed link preflight: the daemon prepares a Pending membership, commits
/// the local link, then activates -- the same Pending -> Active protocol
/// [`create_and_link`] runs, cancelling only the membership (never the group)
/// on a confirmed failure.
pub async fn join_resolved(
    group_id: String,
    group_name: String,
    absolute: PathBuf,
    on_demand: bool,
    acknowledged: bool,
) -> Result<(), CoreError> {
    join_resolved_with_outcome(group_id, group_name, absolute, on_demand, acknowledged)
        .await
        .map(|_| ())
}

/// [`join_resolved`], also reporting whether the folder was already linked.
pub async fn join_resolved_with_outcome(
    group_id: String,
    group_name: String,
    absolute: PathBuf,
    on_demand: bool,
    acknowledged: bool,
) -> Result<JoinOutcome, CoreError> {
    let local_path = absolute.to_string_lossy().to_string();
    let response = control::send(ReqPayload::JoinAndLinkCommand(JoinAndLinkCommandRequest {
        group_id,
        group_name,
        local_path,
        on_demand,
        acknowledge_risks: acknowledged,
        provider_display_name: String::new(),
        request_token: String::new(),
    }))
    .await?;
    match response.payload {
        Some(RespPayload::JoinAndLinkCommand(response)) => match response.result {
            Some(join_and_link_command_response::Result::Outcome(outcome)) => {
                Ok(JoinOutcome { already_linked: outcome.already_linked })
            }
            Some(join_and_link_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty join result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to join-and-link".into())),
    }
}

/// What redeeming an invite did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptInviteOutcome {
    pub group_id: String,
    /// The invite requires the group owner's approval: the folder is linked
    /// but syncs nothing until they approve, and no notification arrives
    /// when they do.
    pub awaiting_approval: bool,
}

/// Redeems a one-use invite minted by another account and links the
/// resulting membership locally at an already-preflighted `absolute` path,
/// through the daemon's invite-accept prepare/activate protocol. Re-running
/// with the SAME code after a failure or crash is always safe.
pub async fn accept_invite(
    code_or_url: &str,
    absolute: PathBuf,
    on_demand: bool,
    acknowledged: bool,
) -> Result<AcceptInviteOutcome, CoreError> {
    let code = crate::wording::parse_invite_input(code_or_url)
        .map_err(|e| CoreError::InvalidInput(e.to_string()))?;
    let response = control::send(ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
        code: code.to_string(),
        local_path: absolute.to_string_lossy().to_string(),
        on_demand,
        acknowledge_risks: acknowledged,
        ..Default::default()
    }))
    .await?;
    match response.payload {
        Some(RespPayload::AcceptInviteCommand(response)) => match response.result {
            Some(accept_invite_command_response::Result::Outcome(outcome)) => {
                Ok(AcceptInviteOutcome {
                    group_id: outcome.group_id,
                    awaiting_approval: outcome.awaiting_approval,
                })
            }
            Some(accept_invite_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty accept result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to accept-invite".into())),
    }
}

/// Redeems an invite and joins the group it names as a provider-backed folder named
/// `display_name` (no directory: the File Provider or Cloud Files root is the folder). The request's
/// retry identity is kept on disk like any provider-folder request, so repeating the SAME request,
/// also after a restart, finishes the folder it began; the invite code itself is kept only as a
/// digest. `awaiting_approval` is set when the owner must still approve the membership.
pub async fn accept_invite_as_provider_folder(
    code_or_url: &str,
    display_name: String,
    on_demand: bool,
) -> Result<ProviderInviteAccepted, CoreError> {
    use sha2::{Digest, Sha256};
    let code = crate::wording::parse_invite_input(code_or_url)
        .map_err(|e| CoreError::InvalidInput(e.to_string()))?
        .to_string();
    let code_digest: String =
        Sha256::digest(code.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect();
    let signature =
        super::provider_pending::signature("invite", &code_digest, "", &display_name, on_demand);
    let awaiting = std::sync::atomic::AtomicBool::new(false);
    let created = with_durable_token(signature, |token| {
        accept_invite_as_provider_folder_with_token(code, display_name, token, on_demand, &awaiting)
    })
    .await?;
    Ok(ProviderInviteAccepted {
        group_id: created.group_id,
        root_id: created.root_id,
        awaiting_approval: awaiting.load(std::sync::atomic::Ordering::Relaxed),
    })
}

/// What redeeming an invite as a provider-backed folder produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderInviteAccepted {
    pub group_id: String,
    pub root_id: String,
    /// The invite requires the group owner's approval: the folder exists but syncs nothing until
    /// they approve.
    pub awaiting_approval: bool,
}

async fn accept_invite_as_provider_folder_with_token(
    code: String,
    display_name: String,
    request_token: String,
    on_demand: bool,
    awaiting_approval: &std::sync::atomic::AtomicBool,
) -> Result<ProviderFolderCreated, CoreError> {
    let response = control::send(ReqPayload::AcceptInviteCommand(AcceptInviteCommandRequest {
        code,
        local_path: String::new(),
        on_demand,
        acknowledge_risks: false,
        provider_display_name: display_name,
        request_token,
    }))
    .await?;
    match response.payload {
        Some(RespPayload::AcceptInviteCommand(response)) => match response.result {
            Some(accept_invite_command_response::Result::Outcome(outcome)) => {
                awaiting_approval
                    .store(outcome.awaiting_approval, std::sync::atomic::Ordering::Relaxed);
                Ok(ProviderFolderCreated {
                    group_id: outcome.group_id,
                    root_id: outcome.provider_root_id,
                    already_existed: outcome.already_linked,
                })
            }
            Some(accept_invite_command_response::Result::Error(error)) => {
                Err(CoreError::from_command_error(error))
            }
            None => Err(CoreError::Other("daemon returned an empty accept result".into())),
        },
        _ => Err(CoreError::Other("unexpected daemon response to accept-invite".into())),
    }
}

/// Whether [`set_storage_mode_resolved`] actually changed anything, and (for
/// a demotion that went through the coordination-plane handoff role-loss
/// commit) the daemon's own handoff record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageModeOutcome {
    /// `false` when the device was already in the requested mode -- no
    /// daemon mutation was requested at all in that case.
    pub changed: bool,
    pub handoff_result: Option<HandoffResult>,
}

/// Changes this device's storage mode for a folder group it already links.
///
/// The `on-demand` (demotion) direction is gated by a durability handoff:
/// without central storage, an eager full replica is the group's only
/// durable copy, so this device may only give that status up once some other
/// full replica is confirmed to durably hold every file in the group. The
/// `eager` direction has no such hazard and is applied unconditionally.
///
/// The daemon is the SOLE orchestrator of both the coordination-plane write
/// and the local materialization-policy flip, strictly in that order, so any
/// error it reports means neither committed. The readiness pre-check here is
/// a fail-fast local read; the daemon re-verifies readiness itself,
/// fail-closed, right before it commits. A request for the mode the device is
/// already in is a no-op decided from this device's own link state.
///
/// `group_name_for_display` is used only in the two error messages (an
/// unlinked group, or a refused demotion).
pub async fn set_storage_mode_resolved(
    group_id: String,
    on_demand: bool,
    group_name_for_display: &str,
) -> Result<StorageModeOutcome, CoreError> {
    let resp = control::send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
    let Some(RespPayload::ListLinks(links)) = resp.payload else {
        return Err(CoreError::Other("daemon did not return link status".to_string()));
    };
    let Some(link) = links.links.into_iter().find(|l| l.group_id == group_id) else {
        return Err(CoreError::InvalidInput(format!(
            "{group_name_for_display} is not linked on this device; nothing to change"
        )));
    };
    let currently_on_demand = link.materialization_policy == "ondemand";
    if currently_on_demand == on_demand {
        return Ok(StorageModeOutcome { changed: false, handoff_result: None });
    }

    // Authoritative readiness gate for a demotion, evaluated before any
    // coordination-plane write. A promotion to eager has no durability hazard
    // and skips the gate entirely.
    if on_demand {
        let resp = control::send(ReqPayload::CheckFullReplicaHandoffReady(
            CheckFullReplicaHandoffReadyRequest { group_id: group_id.clone() },
        ))
        .await?;
        let ready = matches!(
            resp.payload,
            Some(RespPayload::CheckFullReplicaHandoffReady(r)) if r.ready
        );
        if !ready {
            return Err(CoreError::DurabilityBlocked {
                message: format!(
                    "refusing to drop complete-copy status for {group_name_for_display}: no \
                     other complete copy is confirmed to hold every file in this group yet"
                ),
                group_ids: vec![group_id],
            });
        }
    }

    let flip_resp = control::send(ReqPayload::SetStorageMode(SetStorageModeRequest {
        group_id: group_id.clone(),
        on_demand,
    }))
    .await?;

    let handoff_result = match flip_resp.payload {
        Some(RespPayload::SetStorageMode(r)) => r.handoff_result,
        _ => None,
    };
    Ok(StorageModeOutcome { changed: true, handoff_result })
}

/// Same as [`set_storage_mode_resolved`], for a caller holding the group's
/// name.
pub async fn set_storage_mode(
    group_name: &str,
    on_demand: bool,
) -> Result<StorageModeOutcome, CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    set_storage_mode_resolved(group_id, on_demand, group_name).await
}

#[cfg(test)]
mod tests;
