//! Linking local folders to folder groups, and the preflight that runs before
//! a link is registered.

use std::path::PathBuf;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    ApplicationErrorCode, HandoffResult, LinkRequest, LinkStatus, ListLinksRequest,
    MarkLinkNotRejoinedRequest, PendingEnrollmentKind, ReadoptVolumeRequest, UnlinkRequest,
};
use yadorilink_local_storage::link_preflight::{self, LinkPreflightReport};

use crate::daemon::control;
use crate::error::{CoreError, Hint};
use crate::ops::paths;
use crate::ops::shares::resolve_group_name;

/// Runs the shared link preflight for `local_path`: canonicalize the path,
/// gather already-linked paths for nested-link detection, and compute the
/// [`LinkPreflightReport`]. Returns the canonicalized path alongside the
/// report so the caller can pass it straight to [`link_resolved`] without
/// canonicalizing a second time.
pub async fn run_link_preflight(
    local_path: &str,
) -> Result<(PathBuf, LinkPreflightReport), CoreError> {
    let absolute = std::fs::canonicalize(local_path)
        .map_err(|_| CoreError::InvalidInput(format!("no such directory: {local_path}")))?;
    let existing_paths = fetch_existing_link_paths().await;
    // The desktop command line knows the user's home directory from its environment.
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    let report = link_preflight::run_preflight_at_home(
        &absolute,
        &existing_paths,
        None,
        home.as_deref().map(std::path::Path::new),
    );
    Ok((absolute, report))
}

/// Best-effort: an unreachable daemon (or any other `ListLinks` failure) is
/// treated as "no known existing links" rather than aborting the whole
/// preflight -- nested-link detection then just can't find anything. A real
/// link attempt still fails clearly right after, against the same unreachable
/// daemon.
async fn fetch_existing_link_paths() -> Vec<String> {
    match control::send(ReqPayload::ListLinks(ListLinksRequest {})).await {
        Ok(resp) => match resp.payload {
            Some(RespPayload::ListLinks(list)) => {
                list.links.into_iter().map(|l| l.local_path).collect()
            }
            _ => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

/// Registers a link for a caller-resolved `group_id`, eagerly, carrying the
/// caller's aggregate risk acknowledgement. The daemon still re-checks
/// preflight as defense-in-depth, so an unacknowledged risky link is refused
/// there too. A create or join never links through here: those run the
/// crash-safe protocol inside the daemon's `CreateAndLink`/`JoinAndLink`
/// commands.
pub async fn link_resolved(
    absolute_path: PathBuf,
    group_id: String,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    link_resolved_as(absolute_path, group_id, false, acknowledge_risks).await
}

/// [`link_resolved`] in a chosen storage mode: `on_demand` fetches files when
/// they are opened instead of keeping every file on this device.
pub async fn link_resolved_as(
    absolute_path: PathBuf,
    group_id: String,
    on_demand: bool,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    send_link(absolute_path, group_id, on_demand, acknowledge_risks).await
}

/// Links an already-preflighted folder to a group named by the user. Plain
/// links never run the crash-safe create/join protocol, so there is no
/// pending enrollment to track.
pub async fn link_to_named_group(
    absolute_path: PathBuf,
    group_name: &str,
    on_demand: bool,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    let group_id = resolve_group_name(group_name).await?;
    send_link(absolute_path, group_id, on_demand, acknowledge_risks).await
}

async fn send_link(
    absolute_path: PathBuf,
    group_id: String,
    on_demand: bool,
    acknowledge_risks: bool,
) -> Result<(), CoreError> {
    control::send(ReqPayload::Link(LinkRequest {
        local_path: absolute_path.to_string_lossy().to_string(),
        group_id,
        on_demand,
        acknowledge_risks,
        // A plain link tracks no enrollment.
        pending_enrollment_operation_id: String::new(),
        pending_enrollment_kind: PendingEnrollmentKind::Unspecified as i32,
        pending_enrollment_device_id: String::new(),
    }))
    .await?;
    Ok(())
}

/// Unlinks a folder. If this device is an eager full replica for the
/// folder's group, the daemon refuses fail-closed unless another full replica
/// is confirmed ready to durably hold every file; `force` bypasses that gate
/// for a genuinely dead sole replica, and the daemon audit-logs every forced
/// override. Returns the coordination-plane handoff-commit result when this
/// unlink actually went through one, `None` for every other unlink.
///
/// The daemon's durability refusal is [`CoreError::DurabilityBlocked`], with
/// the daemon's own text.
pub async fn send_unlink(
    local_path: &str,
    force: bool,
) -> Result<Option<HandoffResult>, CoreError> {
    // The daemon matches the recorded link path exactly, and `link` records the
    // canonical spelling, so resolve the typed one the same way first.
    let local_path = paths::resolve_link_path(local_path).to_string_lossy().into_owned();
    send_unlink_key(&local_path, force, None).await
}

/// Confirms that the disk now mounted at the linked folder `local_path` is
/// that folder's disk (see `ReadoptVolumeRequest`): the folder syncs again
/// with the disk as it is.
pub async fn readopt_volume(local_path: &str) -> Result<(), CoreError> {
    let local_path = paths::resolve_link_path(local_path).to_string_lossy().into_owned();
    control::send(ReqPayload::ReadoptVolume(ReadoptVolumeRequest { local_path })).await?;
    Ok(())
}

/// Keeps a linked folder visible as needing action after start over could not join it again (see
/// `MarkLinkNotRejoinedRequest`). The key goes verbatim: a provider folder has no path to resolve.
pub async fn mark_not_rejoined(local_path: &str) -> Result<(), CoreError> {
    control::send(ReqPayload::MarkLinkNotRejoined(MarkLinkNotRejoinedRequest {
        local_path: local_path.to_string(),
    }))
    .await?;
    Ok(())
}

/// Unlinks by the link's identity KEY, verbatim: a provider-backed folder has no path to resolve
/// (its key is a synthetic locator that must reach the daemon unchanged). With
/// `expected_group_id` the daemon removes the link only if it still belongs to that group,
/// and otherwise refuses with `GroupMismatch`, changing nothing.
pub async fn send_unlink_key(
    local_path: &str,
    force: bool,
    expected_group_id: Option<&str>,
) -> Result<Option<HandoffResult>, CoreError> {
    let resp = control::send(ReqPayload::Unlink(UnlinkRequest {
        local_path: local_path.to_string(),
        force,
        expected_group_id: expected_group_id.unwrap_or_default().to_string(),
    }))
    .await
    .map_err(classify_unlink_refusal)?;
    Ok(match resp.payload {
        Some(RespPayload::Unlink(r)) => r.handoff_result,
        _ => None,
    })
}

/// The daemon refuses an unlink that would lose the group's last confirmed
/// complete copy with `NotProtected`; that is the durability refusal.
fn classify_unlink_refusal(error: CoreError) -> CoreError {
    match error {
        CoreError::DaemonCommand {
            code: ApplicationErrorCode::NotProtected,
            message,
            group_ids,
            ..
        } => CoreError::DurabilityBlocked { message, group_ids }.hinted(Hint::ForceUnlink),
        other => other,
    }
}

/// Every folder this device links, with its sync state.
pub async fn list_links() -> Result<Vec<LinkStatus>, CoreError> {
    let resp = control::send(ReqPayload::ListLinks(ListLinksRequest {})).await?;
    let Some(RespPayload::ListLinks(list)) = resp.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    Ok(list.links)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refusal(code: ApplicationErrorCode) -> CoreError {
        CoreError::DaemonCommand {
            code,
            message: "refusing to unlink /f/Docs: no other complete copy; use --force".into(),
            group_ids: vec!["group-1".into()],
            operation_id: None,
        }
    }

    #[test]
    fn only_the_not_protected_refusal_becomes_durability_blocked() {
        match classify_unlink_refusal(refusal(ApplicationErrorCode::NotProtected)) {
            CoreError::Hinted { error, hint: Hint::ForceUnlink } => {
                let CoreError::DurabilityBlocked { group_ids, .. } = *error else {
                    panic!("expected a durability refusal inside the hint");
                };
                assert_eq!(group_ids, vec!["group-1".to_string()]);
            }
            other => panic!("expected a durability refusal, got {other:?}"),
        }
        assert!(matches!(
            classify_unlink_refusal(refusal(ApplicationErrorCode::Persistence)),
            CoreError::DaemonCommand { .. }
        ));
        assert!(matches!(
            classify_unlink_refusal(CoreError::DaemonRejected(
                "refusing to unlink /f/Docs: x --force".into()
            )),
            CoreError::DaemonRejected(_)
        ));
        assert!(matches!(
            classify_unlink_refusal(CoreError::DaemonNotRunning),
            CoreError::DaemonNotRunning
        ));
    }
}
