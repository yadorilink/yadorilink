//! IPC encode/decode for the update surface added to
//! `daemon_control.proto` -- protobuf request -> application command, and
//! application outcome -> protobuf response. All actual update-manager/
//! policy mutation lives behind `UpdateCommandPort`
//! (`crate::application::ports::update`); status reads go
//! through `UpdateStatusQueryService` (`context.queries.update_status`).

use yadorilink_ipc_proto::daemonctl::{
    UpdateCheckResponse, UpdateConfigRequest, UpdateConfigResponse, UpdateInstallResponse,
    UpdateStatusResponse, UpdateVersionCheckRequest, UpdateVersionCheckResponse,
};

use crate::application::ports::UpdateVersionCheckKind;
use crate::application::UpdateConfigCommand;

/// `UpdateStatusView` (`crate::queries::update_status`, `DaemonState`-
/// independent) -> the IPC wire type. Shared by `StatusResponse`'s
/// embedded update fields (`control_socket::encode_runtime_status`) and
/// `UpdateStatusResponse` itself -- both carry the exact same
/// information, see `daemon_control.proto`'s doc comment on why they're
/// two separate flat messages rather than one nested inside the other.
pub(crate) fn encode_update_status(
    view: crate::queries::update_status::UpdateStatusView,
) -> UpdateStatusResponse {
    UpdateStatusResponse {
        current_version: view.current_version,
        channel: view.channel,
        install_source: view.install_source,
        last_check_unix: view.last_check_unix,
        state: view.state,
        available_version: view.available_version,
        release_notes_url: view.release_notes_url,
        mandatory: view.mandatory,
        update_required: view.update_required,
        holdback_reason: view.holdback_reason,
        last_error_category: view.last_error_category,
        last_error_message: view.last_error_message,
        automatic_checks_enabled: view.automatic_checks_enabled,
        manifest_generated_at: view.manifest_generated_at,
    }
}

/// An unknown `kind` is refused rather than defaulted to a rule.
pub(crate) fn decode_version_check(
    req: UpdateVersionCheckRequest,
) -> Result<(UpdateVersionCheckKind, String), String> {
    let kind = match req.kind.as_str() {
        "pinned_install" => UpdateVersionCheckKind::PinnedInstall,
        "appcast_item" => UpdateVersionCheckKind::AppcastItem,
        other => return Err(format!("unknown update version check kind '{other}'")),
    };
    Ok((kind, req.version))
}

pub(crate) fn encode_version_check_response(
    outcome: Result<(), String>,
) -> UpdateVersionCheckResponse {
    match outcome {
        Ok(()) => UpdateVersionCheckResponse { allowed: true, reason: String::new() },
        Err(reason) => UpdateVersionCheckResponse { allowed: false, reason },
    }
}

pub(crate) fn encode_check_response(
    status: crate::queries::update_status::UpdateStatusView,
) -> UpdateCheckResponse {
    UpdateCheckResponse { status: Some(encode_update_status(status)) }
}

/// v1 ships manual updates: the daemon never installs, it points the user
/// at the official download page.
pub(crate) fn encode_download_response(
    guidance: String,
    download_url: Option<String>,
) -> UpdateInstallResponse {
    UpdateInstallResponse {
        outcome: "manual_download".into(),
        guidance,
        download_url: download_url.unwrap_or_default(),
    }
}

pub(crate) fn decode_config_request(req: UpdateConfigRequest) -> UpdateConfigCommand {
    UpdateConfigCommand { automatic_checks_enabled: req.automatic_checks_enabled }
}

pub(crate) fn encode_config_response(
    policy: crate::application::UpdatePolicyView,
) -> UpdateConfigResponse {
    UpdateConfigResponse { automatic_checks_enabled: policy.automatic_checks_enabled }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_version_check_kind_is_refused_not_defaulted() {
        let ok = decode_version_check(UpdateVersionCheckRequest {
            kind: "appcast_item".into(),
            version: "1.2.3".into(),
        })
        .unwrap();
        assert_eq!(ok, (UpdateVersionCheckKind::AppcastItem, "1.2.3".to_string()));
        for kind in ["", "pinned", "APPCAST_ITEM"] {
            assert!(decode_version_check(UpdateVersionCheckRequest {
                kind: kind.into(),
                version: "1.2.3".into()
            })
            .is_err());
        }
    }

    #[test]
    fn a_refusal_carries_its_reason_and_an_allowance_does_not() {
        let r = encode_version_check_response(Err("withdrawn".into()));
        assert!(!r.allowed && r.reason == "withdrawn");
        let r = encode_version_check_response(Ok(()));
        assert!(r.allowed && r.reason.is_empty());
    }
}
