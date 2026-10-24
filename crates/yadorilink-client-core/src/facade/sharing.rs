//! Devices, members, shares and invites. These are coordination-plane
//! calls: fetch them on demand, never on the status timer.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{existing_directory, folder_memberships, offering_force, ClientCore};
use crate::dto::{
    self, AcceptInviteOutcome, ApproveOutcome, AssignableRole, DeviceSummary, FolderMode,
    GroupSummary, InviteSummary, MemberSummary, MembershipOutcome, PendingApprovalSummary,
    PendingInviteSummary, ProviderInviteOutcome, RevokeEdgeOutcome, ShareSummary,
};
use crate::error::{CoreError, DesktopError};
use crate::ops;

fn role_name(role: AssignableRole) -> &'static str {
    match role {
        AssignableRole::Viewer => "viewer",
        AssignableRole::Editor => "editor",
    }
}

fn group(group: ops::shares::GroupSummary) -> GroupSummary {
    GroupSummary { group_id: group.group_id, name: group.name }
}

/// The devices holding a full copy of a linked folder. When the daemon cannot say, none do, so no
/// device is offered for administration on a guess.
async fn full_copy_holders() -> std::collections::HashSet<String> {
    ops::links::list_links()
        .await
        .map(|links| yadorilink_product_view::full_replica_holders(&links))
        .unwrap_or_default()
}

fn last_seen(unix_secs: i64) -> Option<SystemTime> {
    u64::try_from(unix_secs).ok().filter(|s| *s > 0).map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

impl ClientCore {
    // ---- devices -----------------------------------------------------------------

    /// Every device with access to any linked folder, merged across groups.
    ///
    /// # Errors
    /// Daemon or coordination failures.
    pub async fn list_folder_devices(&self) -> Result<Vec<DeviceSummary>, DesktopError> {
        let memberships = folder_memberships().await?;
        let own = ops::shares::own_device_id();
        let holders = full_copy_holders().await;
        let merged = yadorilink_product_view::device_summaries(
            memberships.iter().map(|(_, members)| members.as_slice()),
        );
        Ok(merged
            .into_iter()
            .map(|d| {
                let is_this_device = own.as_deref() == Some(d.device_id.as_str());
                DeviceSummary {
                    can_manage: yadorilink_product_view::can_manage_device(
                        &d.device_id,
                        is_this_device,
                        d.is_caller_account,
                        &holders,
                    ),
                    is_this_device,
                    device_id: d.device_id,
                    display_name: d.display_name,
                    online: d.online,
                    last_seen: last_seen(d.last_seen_unix),
                    is_caller_account: d.is_caller_account,
                }
            })
            .collect())
    }

    /// Every device registered on this account, linked folders or not.
    ///
    /// # Errors
    /// Coordination failures.
    pub async fn list_account_devices(&self) -> Result<Vec<DeviceSummary>, DesktopError> {
        let own = ops::shares::own_device_id();
        let holders = full_copy_holders().await;
        Ok(ops::devices::list_devices()
            .await?
            .into_iter()
            .map(|d| {
                let is_this_device = own.as_deref() == Some(d.device_id.as_str());
                DeviceSummary {
                    can_manage: yadorilink_product_view::can_manage_device(
                        &d.device_id,
                        is_this_device,
                        true,
                        &holders,
                    ),
                    is_this_device,
                    device_id: d.device_id,
                    display_name: d.device_name,
                    online: d.online,
                    last_seen: None,
                    is_caller_account: true,
                }
            })
            .collect())
    }

    /// Removes a device from this account and every folder group.
    ///
    /// # Errors
    /// Without `force`, `DurabilityBlocked{can_force: true}` when a group
    /// would be left without a confirmed complete copy.
    pub async fn remove_device(
        &self,
        device_id: String,
        force: bool,
    ) -> Result<MembershipOutcome, DesktopError> {
        let outcome =
            ops::devices::remove_device(&device_id, force).await.map_err(offering_force(force))?;
        Ok(dto::membership_outcome(&outcome))
    }

    /// Opens the management page of `device_id`, a device on this account,
    /// over the device connection. The session lives as long as the returned
    /// handle; see [`ops::nas_admin`].
    ///
    /// # Errors
    /// Daemon failures only; the device's own state is
    /// [`ops::nas_admin::NasAdminOpen::Failed`].
    pub async fn open_nas_admin(
        &self,
        device_id: String,
    ) -> Result<ops::nas_admin::NasAdminOpen, DesktopError> {
        Ok(ops::nas_admin::open_nas_admin(device_id).await?)
    }

    // ---- groups and members ----------------------------------------------------------

    /// # Errors
    /// Coordination failures.
    pub async fn list_owned_groups(&self) -> Result<Vec<GroupSummary>, DesktopError> {
        Ok(ops::shares::list_groups().await?.into_iter().map(group).collect())
    }

    /// # Errors
    /// Coordination failures.
    pub async fn list_joinable_groups(&self) -> Result<Vec<GroupSummary>, DesktopError> {
        Ok(ops::shares::list_joinable_groups().await?.into_iter().map(group).collect())
    }

    /// # Errors
    /// Coordination failures.
    pub async fn list_members(&self, group_id: String) -> Result<Vec<MemberSummary>, DesktopError> {
        let own = ops::shares::own_device_id();
        let members = ops::shares::list_members_resolved(&group_id).await?;
        Ok(members.iter().map(|m| dto::member_summary(m, own.as_deref())).collect())
    }

    /// # Errors
    /// Coordination failures.
    pub async fn change_member_role(
        &self,
        group_id: String,
        device_id: String,
        role: AssignableRole,
    ) -> Result<(), DesktopError> {
        Ok(ops::shares::change_role_resolved(&group_id, &device_id, role_name(role)).await?)
    }

    /// Takes a device's access to a group away.
    ///
    /// # Errors
    /// Without `force`, `DurabilityBlocked{can_force: true}` when the group
    /// would be left without a confirmed complete copy.
    pub async fn revoke_member(
        &self,
        group_id: String,
        device_id: String,
        force: bool,
    ) -> Result<MembershipOutcome, DesktopError> {
        let outcome = ops::shares::revoke_resolved(group_id, device_id, force)
            .await
            .map_err(offering_force(force))?;
        Ok(dto::membership_outcome(&outcome))
    }

    /// Turns down a device waiting for approval. Never forced. Re-reads the
    /// pending and member listings first and refuses (`InvalidInput`, with a
    /// plain reason) when the request is no longer waiting, so an approved
    /// member is never removed by a stale Deny.
    ///
    /// # Errors
    /// `DurabilityBlocked{can_force: false}` when the daemon's durability
    /// gate refuses it.
    pub async fn deny_request(
        &self,
        group_id: String,
        device_id: String,
    ) -> Result<MembershipOutcome, DesktopError> {
        let attempt = ops::shares::deny_checked(group_id, device_id)
            .await
            .map_err(|e| DesktopError::from_core(e, false))?;
        match attempt {
            ops::shares::DenyAttempt::Refused(refusal) => {
                Err(DesktopError::invalid_input(refusal.reason(), "device_id"))
            }
            ops::shares::DenyAttempt::Attempted(ops::shares::RevokeAttempt::Committed(outcome)) => {
                Ok(dto::membership_outcome(&outcome))
            }
            ops::shares::DenyAttempt::Attempted(ops::shares::RevokeAttempt::NotDurable {
                message,
                group_ids,
            }) => Err(DesktopError::from_core(
                CoreError::DurabilityBlocked { message, group_ids },
                false,
            )),
        }
    }

    /// # Errors
    /// Coordination failures.
    pub async fn approve_request(
        &self,
        group_id: String,
        device_id: String,
    ) -> Result<ApproveOutcome, DesktopError> {
        Ok(match ops::shares::approve_resolved(&group_id, &device_id).await?.as_str() {
            "approved" => ApproveOutcome::Approved,
            "already_active" => ApproveOutcome::AlreadyActive,
            other => ApproveOutcome::Unrecognized { raw: other.to_owned() },
        })
    }

    /// # Errors
    /// Coordination failures.
    pub async fn list_pending_approvals(
        &self,
    ) -> Result<Vec<PendingApprovalSummary>, DesktopError> {
        let pending = ops::shares::pending_approvals().await?;
        Ok(pending.iter().map(dto::pending_approval_summary).collect())
    }

    /// # Errors
    /// Coordination failures.
    pub async fn list_shares(&self) -> Result<Vec<ShareSummary>, DesktopError> {
        let edges = ops::shares::list_shares_resolved().await?;
        Ok(edges.iter().map(dto::share_summary).collect())
    }

    /// Revokes one share edge; an edge that no longer exists reads as
    /// already revoked.
    ///
    /// # Errors
    /// Without `force`, `DurabilityBlocked{can_force: true}` as for
    /// [`ClientCore::revoke_member`].
    pub async fn revoke_share_edge(
        &self,
        edge_id: String,
        force: bool,
    ) -> Result<RevokeEdgeOutcome, DesktopError> {
        Ok(
            match ops::shares::revoke_edge(&edge_id, force).await.map_err(offering_force(force))? {
                ops::shares::RevokeEdgeOutcome::Revoked(outcome) => {
                    RevokeEdgeOutcome::Revoked { outcome: dto::membership_outcome(&outcome) }
                }
                ops::shares::RevokeEdgeOutcome::AlreadyRevoked => RevokeEdgeOutcome::AlreadyRevoked,
            },
        )
    }

    // ---- invites -------------------------------------------------------------------

    /// Mints a one-use invite. `None` role or lifetime takes the server's
    /// default.
    ///
    /// # Errors
    /// Daemon or coordination failures.
    pub async fn mint_invite(
        &self,
        group_id: String,
        role: Option<AssignableRole>,
        ttl: Option<Duration>,
        require_approval: bool,
    ) -> Result<InviteSummary, DesktopError> {
        let invite = ops::shares::mint_invite_resolved(
            group_id,
            role.map(|r| role_name(r).to_owned()),
            ttl.map(|t| t.as_secs().max(1)),
            require_approval,
        )
        .await?;
        Ok(dto::invite_summary(&invite))
    }

    /// # Errors
    /// Coordination failures.
    pub async fn list_invites(&self) -> Result<Vec<PendingInviteSummary>, DesktopError> {
        let invites = ops::shares::list_invites_resolved().await?;
        Ok(invites.iter().map(dto::pending_invite_summary).collect())
    }

    /// # Errors
    /// Coordination failures.
    pub async fn cancel_invite(&self, invite_id: String) -> Result<(), DesktopError> {
        Ok(ops::shares::cancel_invite(&invite_id).await?)
    }

    /// Validates a pasted or clicked invite (link or bare code) and returns
    /// the code. Performs no I/O.
    ///
    /// # Errors
    /// `InvalidInput{field: "invite"}` with a plain-language message.
    pub fn parse_invite_link(&self, input: &str) -> Result<String, DesktopError> {
        crate::wording::parse_invite_input(input)
            .map(str::to_owned)
            .map_err(|e| DesktopError::invalid_input(e.to_string(), "invite"))
    }

    /// Redeems an invite (its code or its `yadorilink://invite/` link) and
    /// links the folder at `local_path`. Safe to repeat with the same code.
    ///
    /// # Errors
    /// `InvalidInput{field: "local_path"}` for a path that does not resolve;
    /// daemon and coordination failures.
    pub async fn accept_invite(
        &self,
        code_or_url: String,
        local_path: String,
        mode: FolderMode,
        acknowledge_risks: bool,
    ) -> Result<AcceptInviteOutcome, DesktopError> {
        let absolute = existing_directory(&local_path)?;
        let local_path = absolute.to_string_lossy().into_owned();
        let outcome = ops::shares::accept_invite(
            &code_or_url,
            absolute,
            mode == FolderMode::OnDemand,
            acknowledge_risks,
        )
        .await?;
        Ok(AcceptInviteOutcome {
            group_id: outcome.group_id,
            local_path,
            awaiting_approval: outcome.awaiting_approval,
        })
    }

    /// Redeems an invite (its code or its `yadorilink://invite/` link) and joins the group it
    /// names as a provider-backed folder named `display_name`: no directory is linked, the
    /// operating system's root is the folder. Safe to repeat with the same code and request, also
    /// after a restart.
    ///
    /// # Errors
    /// `InvalidInput{field: "invite"}` for input that is not an invite; daemon and coordination
    /// failures, including a refusal when provider folders are not available or the name is taken.
    pub async fn accept_invite_as_provider_folder(
        &self,
        code_or_url: String,
        display_name: String,
        mode: FolderMode,
    ) -> Result<ProviderInviteOutcome, DesktopError> {
        let accepted = ops::shares::accept_invite_as_provider_folder(
            &code_or_url,
            display_name.clone(),
            mode == FolderMode::OnDemand,
        )
        .await?;
        Ok(ProviderInviteOutcome {
            group_id: accepted.group_id,
            root_id: accepted.root_id,
            display_name,
            mode,
            awaiting_approval: accepted.awaiting_approval,
        })
    }
}
