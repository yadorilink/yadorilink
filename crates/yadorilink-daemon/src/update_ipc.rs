//! IPC encode/decode for the update surface added to
//! `daemon_control.proto` -- protobuf request -> application command, and
//! application outcome -> protobuf response. All actual update-manager/
//! policy mutation lives behind `UpdateCommandPort`
//! (`crate::application::ports::update`); status reads go
//! through `UpdateStatusQueryService` (`context.queries.update_status`).

use yadorilink_ipc_proto::daemonctl::{
    UpdateCheckResponse, UpdateConfigRequest, UpdateConfigResponse, UpdateInstallResponse,
    UpdateStatusResponse, UpdateVerifiedEntry, UpdateVerifiedEntryRequest,
    UpdateVerifiedEntryResponse, UpdateVersionCheckRequest, UpdateVersionCheckResponse,
};

use crate::application::ports::UpdateVersionCheckKind;
use crate::application::UpdateConfigCommand;
use crate::update::manager::{EntryRefusal, VerifiedEntryAnswer};
use crate::update::manifest::{AppcastItem, AppcastPhase};

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
        last_success_unix: view.last_success_unix,
        manifest_expires_at: view.manifest_expires_at,
        manifest_expired: view.manifest_expired,
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

/// An unknown `phase` is refused rather than defaulted: it would otherwise pick how strict the
/// check is.
pub(crate) fn decode_verified_entry(
    req: UpdateVerifiedEntryRequest,
) -> Result<(AppcastItem, AppcastPhase), String> {
    let phase = match req.phase.as_str() {
        "enclosure" => AppcastPhase::Enclosure,
        "downloaded" => AppcastPhase::Downloaded,
        other => return Err(format!("unknown appcast check phase '{other}'")),
    };
    Ok((
        AppcastItem {
            version: req.version,
            sparkle_build: req.sparkle_build,
            channel: (!req.channel.is_empty()).then_some(req.channel),
            url: req.url,
            length: req.length,
            sha256: (!req.sha256.is_empty()).then_some(req.sha256),
        },
        phase,
    ))
}

pub(crate) fn encode_verified_entry_response(
    answer: VerifiedEntryAnswer,
) -> UpdateVerifiedEntryResponse {
    let (outcome, reason_code, reason) = match &answer.verdict {
        Ok(()) => ("allowed", String::new(), String::new()),
        Err(EntryRefusal::CannotConfirm(why)) => {
            ("cannot_confirm", why.code().to_string(), why.to_string())
        }
        Err(EntryRefusal::Refused(r)) => ("refused", r.code().to_string(), r.to_string()),
    };
    UpdateVerifiedEntryResponse {
        outcome: outcome.to_string(),
        reason_code,
        reason,
        entry: answer.entry.map(|v| UpdateVerifiedEntry {
            channel: v.entry.channel,
            version: v.entry.version,
            sparkle_build: v.entry.sparkle_build.unwrap_or(0),
            minimum_supported_version: v.entry.minimum_supported_version,
            file: v.file,
            sha256: v.entry.artifact_sha256,
            size: v.entry.artifact_size,
            kill_switch: v.entry.kill_switch,
            rollout_percentage: u32::from(v.entry.rollout_percentage),
            generated_at: v.generated_at,
            expires_at: v.expires_at,
            update_required: v.update_required,
        }),
    }
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

    #[test]
    fn a_verified_entry_answer_encodes_outcome_code_and_entry() {
        use crate::update::manager::CannotConfirm;
        let cannot = encode_verified_entry_response(VerifiedEntryAnswer {
            entry: None,
            verdict: Err(EntryRefusal::CannotConfirm(CannotConfirm::Stale)),
        });
        assert_eq!(
            (cannot.outcome.as_str(), cannot.reason_code.as_str()),
            ("cannot_confirm", "stale")
        );
        assert!(cannot.entry.is_none());
        let refused = encode_verified_entry_response(VerifiedEntryAnswer {
            entry: None,
            verdict: Err(EntryRefusal::Refused(
                crate::update::manifest::VersionRefusal::Sha256Mismatch,
            )),
        });
        assert_eq!(
            (refused.outcome.as_str(), refused.reason_code.as_str()),
            ("refused", "sha256_mismatch")
        );
        let (item, phase) = decode_verified_entry(UpdateVerifiedEntryRequest {
            version: "1.0.0".into(),
            sparkle_build: 5,
            phase: "enclosure".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((item.channel, item.sha256, phase), (None, None, AppcastPhase::Enclosure));
        assert!(decode_verified_entry(UpdateVerifiedEntryRequest::default()).is_err());
    }
}
