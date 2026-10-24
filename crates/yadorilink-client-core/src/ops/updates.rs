//! Application updates, owned by the daemon's update pipeline.

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    UpdateCheckRequest, UpdateCheckResponse, UpdateConfigRequest, UpdateConfigResponse,
    UpdateInstallRequest, UpdateInstallResponse, UpdateStatusRequest, UpdateStatusResponse,
    UpdateVerifiedEntryRequest, UpdateVerifiedEntryResponse, UpdateVersionCheckRequest,
    UpdateVersionCheckResponse,
};

use crate::daemon::control;
use crate::error::CoreError;

fn unexpected() -> CoreError {
    CoreError::Other("unexpected daemon response".into())
}

/// Current version, channel, last check, state, any available update, and
/// the automatic-check and install settings.
pub async fn update_status() -> Result<UpdateStatusResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateStatus(UpdateStatusRequest {})).await?;
    let Some(RespPayload::UpdateStatus(status)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(status)
}

/// Checks for an available update now.
pub async fn check_for_updates() -> Result<UpdateCheckResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateCheck(UpdateCheckRequest {})).await?;
    let Some(RespPayload::UpdateCheck(check)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(check)
}

/// Asks the daemon whether `version` may proceed, judged by the live verified channel manifest.
/// `kind` is `pinned_install` or `appcast_item`. `allowed == false` carries the reason; a
/// manifest the daemon cannot verify is a refusal, not an error to ignore.
pub async fn check_version(
    kind: &str,
    version: &str,
) -> Result<UpdateVersionCheckResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateVersionCheck(UpdateVersionCheckRequest {
        kind: kind.to_string(),
        version: version.to_string(),
    }))
    .await?;
    let Some(RespPayload::UpdateVersionCheck(check)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(check)
}

/// Asks the daemon whether an appcast item is covered by the `app_bundle` entry of the channel
/// manifest it last verified, and for that entry. The daemon answers from what it already
/// verified: no network request, no replay floor change. Not allowed carries a typed reason,
/// `cannot_confirm` when no fresh verified manifest exists. `phase` picks the check:
/// `enclosure` before the download, `downloaded` once the file's sha256 is known.
pub async fn verified_entry(
    item: &crate::dto::AppcastItem,
    phase: crate::dto::AppcastItemPhase,
) -> Result<UpdateVerifiedEntryResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateVerifiedEntry(UpdateVerifiedEntryRequest {
        version: item.version.clone(),
        sparkle_build: item.sparkle_build,
        channel: item.channel.clone().unwrap_or_default(),
        url: item.url.clone(),
        length: item.length,
        sha256: item.sha256.clone().unwrap_or_default(),
        phase: match phase {
            crate::dto::AppcastItemPhase::Enclosure => "enclosure",
            crate::dto::AppcastItemPhase::Downloaded => "downloaded",
        }
        .to_string(),
    }))
    .await?;
    let Some(RespPayload::UpdateVerifiedEntry(check)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(check)
}

/// Official page to download new versions from. v1 ships manual updates:
/// the daemon checks and reports, the user downloads and installs. Matches
/// the daemon's `update::install_source::DOWNLOAD_PAGE_URL`.
pub const DOWNLOAD_PAGE_URL: &str = "https://github.com/yadorilink/yadorilink/releases";

/// Whether a package manager or store, not the user, owns this install.
/// Matches the install sources the daemon reports in `install_source`.
pub fn is_package_managed(install_source: &str) -> bool {
    matches!(install_source, "homebrew" | "apt" | "winget" | "microsoft_store" | "app_store")
}

/// Checks a daemon's download reply and returns `(guidance, page_url)`.
/// The daemon never installs, so anything but `manual_download` is a
/// contract break. A page to open is accepted only from the structured
/// `download_url`, and only when it is the official release page (https, the
/// release path, plain path characters); a link inside the `guidance`
/// sentence is display text and is never used.
///
/// # Errors
/// The reason the reply is refused.
pub fn check_download_reply(
    reply: &UpdateInstallResponse,
) -> Result<(String, Option<String>), String> {
    if reply.outcome != "manual_download" {
        return Err(format!(
            "unexpected update reply {:?}; updates are installed manually",
            reply.outcome
        ));
    }
    if reply.guidance.trim().is_empty() {
        return Err("the update reply has no guidance".to_owned());
    }
    let url = reply.download_url.as_str();
    if url.is_empty() {
        return Ok((reply.guidance.clone(), None));
    }
    let rest = url
        .strip_prefix(DOWNLOAD_PAGE_URL)
        .ok_or_else(|| format!("refusing to open {url:?}: not the official release page"))?;
    let plain = |c: char| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.');
    let sound = rest.is_empty()
        || (rest.starts_with('/')
            && rest.chars().all(plain)
            && !rest.split('/').any(|part| part == ".." || part == "."));
    if !sound {
        return Err(format!("refusing to open {url:?}: not the official release page"));
    }
    Ok((reply.guidance.clone(), Some(url.to_owned())))
}

/// Asks the daemon how to get the new version (v1 ships manual updates;
/// nothing is installed automatically). The reply's `guidance` is the text
/// to show: the download page, or the package-manager command for a
/// package-managed install.
pub async fn download_guidance() -> Result<UpdateInstallResponse, CoreError> {
    let resp = control::send(ReqPayload::UpdateInstall(UpdateInstallRequest {})).await?;
    let Some(RespPayload::UpdateInstall(install)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(install)
}

/// Configures automatic update checks and/or the install mode (only
/// `manual` is supported in v1). `None` leaves that setting unchanged.
pub async fn set_update_config(
    automatic_checks_enabled: Option<bool>,
) -> Result<UpdateConfigResponse, CoreError> {
    let resp =
        control::send(ReqPayload::UpdateConfig(UpdateConfigRequest { automatic_checks_enabled }))
            .await?;
    let Some(RespPayload::UpdateConfig(config)) = resp.payload else {
        return Err(unexpected());
    };
    Ok(config)
}
