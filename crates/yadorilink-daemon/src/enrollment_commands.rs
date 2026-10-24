//! The share commands (create, join, accept an invite) as the engine runs them, shared by the
//! control socket and the embedded host's commands: the refusals that precede the enrollment
//! (provider support, the folder's risks, an unmade folder) and the mapping of every failure to
//! its typed code live here once, so the two front ends refuse the same requests the same way.

use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

use crate::application::{
    AcceptInviteCommand, ApplicationServices, CreateAndLinkCommand, EnrollmentError,
    EnrollmentOutcome, JoinAndLinkCommand, LinkLifecycleService, ProviderCreation,
};

/// A provider folder needs the operating system's provider adapter (the macOS or iOS File
/// Provider or the Windows Cloud Files API); refused before anything is written.
pub(crate) fn provider_refusal(display_name: &str) -> Option<String> {
    if display_name.is_empty() {
        return None;
    }
    if yadorilink_replica_domain::session_state::ProviderKind::for_host_platform().is_none() {
        return Some("provider folders are not supported on this platform".to_string());
    }
    None
}

/// The provider-folder part of a create/join request, `None` for a plain folder.
pub(crate) fn provider_creation(
    display_name: &str,
    request_token: &str,
) -> Option<ProviderCreation> {
    (!display_name.is_empty()).then(|| ProviderCreation {
        display_name: display_name.to_string(),
        request_token: request_token.to_string(),
    })
}

/// [`LinkLifecycleService::require_risks_acknowledged`] for a link, create, join or invite
/// acceptance of `local_path`, off the async runtime (the preflight scans the folder).
pub(crate) async fn require_risks_acknowledged(
    links: &Arc<LinkLifecycleService>,
    local_path: &str,
    acknowledged: bool,
) -> Result<(), crate::error::DaemonError> {
    if acknowledged {
        return Ok(());
    }
    let links = links.clone();
    let path = std::path::PathBuf::from(local_path);
    match tokio::task::spawn_blocking(move || links.require_risks_acknowledged(&path, false)).await
    {
        Ok(result) => result,
        Err(e) => {
            Err(crate::error::DaemonError::Config(format!("link preflight did not complete: {e}")))
        }
    }
}

/// A failed risk check as the enrollment refusal it is.
pub(crate) fn risks_refusal(error: crate::error::DaemonError) -> EnrollmentError {
    match error.link_refusal() {
        Some(refusal) => EnrollmentError::LinkRefused { refusal, detail: error.to_string() },
        None => EnrollmentError::PreparationRejected { detail: error.to_string() },
    }
}

/// What a create-and-link request asks for.
pub(crate) struct CreateShare {
    pub(crate) group_name: String,
    pub(crate) local_path: String,
    pub(crate) create_local_path_if_missing: bool,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
    /// Empty for a plain folder.
    pub(crate) provider_display_name: String,
    pub(crate) request_token: String,
}

/// What a join-and-link request asks for.
pub(crate) struct JoinGroup {
    pub(crate) group_id: String,
    pub(crate) group_name: String,
    pub(crate) local_path: String,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
    /// Empty for a plain folder.
    pub(crate) provider_display_name: String,
    pub(crate) request_token: String,
}

/// Creates a group and links a folder (or a provider folder) to it.
pub(crate) async fn create_and_link(
    application: &ApplicationServices,
    request: CreateShare,
) -> Result<EnrollmentOutcome, EnrollmentError> {
    let refusal = match provider_refusal(&request.provider_display_name) {
        Some(detail) => Some(EnrollmentError::PreparationRejected { detail }),
        None if request.provider_display_name.is_empty() => {
            let created = if request.create_local_path_if_missing {
                yadorilink_fs_platform::durable_dir::create_dir_all_durably(std::path::Path::new(
                    &request.local_path,
                ))
                .map_err(|e| EnrollmentError::PreparationRejected {
                    detail: format!("could not create {}: {e}", request.local_path),
                })
            } else {
                Ok(())
            };
            match created {
                Err(error) => Some(error),
                Ok(()) => require_risks_acknowledged(
                    &application.link_lifecycle,
                    &request.local_path,
                    request.acknowledge_risks,
                )
                .await
                .err()
                .map(risks_refusal),
            }
        }
        None => None,
    };
    if let Some(error) = refusal {
        return Err(error);
    }
    application
        .enrollment
        .create_and_link(CreateAndLinkCommand {
            group_name: request.group_name,
            absolute_path: request.local_path.into(),
            on_demand: request.on_demand,
            provider: provider_creation(&request.provider_display_name, &request.request_token),
        })
        .await
}

/// Joins a group of this account and links a folder (or a provider folder) to it.
pub(crate) async fn join_and_link(
    application: &ApplicationServices,
    request: JoinGroup,
) -> Result<EnrollmentOutcome, EnrollmentError> {
    let refusal = match provider_refusal(&request.provider_display_name) {
        Some(detail) => Some(EnrollmentError::PreparationRejected { detail }),
        None if request.provider_display_name.is_empty() => require_risks_acknowledged(
            &application.link_lifecycle,
            &request.local_path,
            request.acknowledge_risks,
        )
        .await
        .err()
        .map(risks_refusal),
        None => None,
    };
    if let Some(error) = refusal {
        return Err(error);
    }
    application
        .enrollment
        .join_and_link(JoinAndLinkCommand {
            group_id: request.group_id,
            group_name: request.group_name,
            absolute_path: request.local_path.into(),
            on_demand: request.on_demand,
            provider: provider_creation(&request.provider_display_name, &request.request_token),
        })
        .await
}

/// What an invite acceptance asks for.
pub(crate) struct AcceptInvite {
    pub(crate) code: String,
    pub(crate) local_path: String,
    pub(crate) on_demand: bool,
    pub(crate) acknowledge_risks: bool,
    /// Empty for a plain folder.
    pub(crate) provider_display_name: String,
    pub(crate) request_token: String,
}

/// Redeems an invite and links a folder (or a provider folder) to the group it names. The
/// refusals come first: none of them redeems the one-use invite.
pub(crate) async fn accept_invite(
    application: &ApplicationServices,
    request: AcceptInvite,
) -> Result<EnrollmentOutcome, EnrollmentError> {
    let refusal = match provider_refusal(&request.provider_display_name) {
        Some(detail) => Some(EnrollmentError::PreparationRejected { detail }),
        None if request.provider_display_name.is_empty() => require_risks_acknowledged(
            &application.link_lifecycle,
            &request.local_path,
            request.acknowledge_risks,
        )
        .await
        .err()
        .map(risks_refusal),
        None => None,
    };
    if let Some(error) = refusal {
        return Err(error);
    }
    application
        .enrollment
        .accept_invite_and_link(AcceptInviteCommand {
            code: request.code,
            absolute_path: request.local_path.into(),
            on_demand: request.on_demand,
            provider: provider_creation(&request.provider_display_name, &request.request_token),
        })
        .await
}

/// The root id of the provider folder an outcome linked: its link's key is the locator the
/// outcome names. Empty for a plain folder.
pub(crate) fn provider_root_id(
    queries: &crate::queries::QueryServices,
    outcome: &EnrollmentOutcome,
) -> String {
    let key = outcome.local_path.to_string_lossy().to_string();
    queries
        .link_status
        .list_links()
        .ok()
        .and_then(|views| {
            views.into_iter().find_map(|v| match v.provider {
                Some((root_id, _)) if v.local_path == key => Some(root_id),
                _ => None,
            })
        })
        .unwrap_or_default()
}

/// The typed code of an enrollment failure, with the operation it concerns (empty when none).
pub(crate) fn enrollment_error_code(error: &EnrollmentError) -> (ApplicationErrorCode, String) {
    use EnrollmentError as Error;
    match error {
        Error::LocalIdentityUnavailable => {
            (ApplicationErrorCode::LocalIdentityUnavailable, String::new())
        }
        Error::RecoveryJournalUnavailable { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryJournalUnavailable, operation_id.clone())
        }
        Error::PreparationRejected { .. } => {
            (ApplicationErrorCode::PreparationRejected, String::new())
        }
        Error::PreparationAmbiguous { operation_id, .. } => {
            (ApplicationErrorCode::CoordinationAmbiguous, operation_id.clone())
        }
        Error::LocalLinkFailed { refusal: None, .. } => {
            (ApplicationErrorCode::LocalLinkFailed, String::new())
        }
        Error::LocalLinkFailed { refusal: Some(refusal), .. }
        | Error::LinkRefused { refusal, .. } => (link_refusal_code(*refusal), String::new()),
        Error::InviteRefused { reason, .. } => (
            match reason {
                crate::application::model::InviteRefusal::Expired => {
                    ApplicationErrorCode::InviteExpired
                }
                crate::application::model::InviteRefusal::AlreadyUsed => {
                    ApplicationErrorCode::InviteAlreadyUsed
                }
            },
            String::new(),
        ),
        Error::LocalLinkAmbiguous { operation_id, .. } => {
            (ApplicationErrorCode::RecoveryPending, operation_id.clone())
        }
        Error::ActivationRejected { .. } => {
            (ApplicationErrorCode::ActivationRejected, String::new())
        }
        Error::ActivationAmbiguous { operation_id, .. } => {
            (ApplicationErrorCode::ActivationAmbiguous, operation_id.clone())
        }
        Error::CompensationPending { operation_id, .. } => {
            (ApplicationErrorCode::CompensationPending, operation_id.clone())
        }
        Error::OperationConflict { operation_id, .. } => {
            (ApplicationErrorCode::OperationConflict, operation_id.clone())
        }
        Error::CoordinationTransport { .. } => {
            (ApplicationErrorCode::CoordinationTransport, String::new())
        }
        Error::Persistence(_) => (ApplicationErrorCode::Persistence, String::new()),
    }
}

pub(crate) fn link_refusal_code(
    refusal: crate::application::model::LinkRefusal,
) -> ApplicationErrorCode {
    use crate::application::model::LinkRefusal;
    match refusal {
        LinkRefusal::DiskFull => ApplicationErrorCode::DiskFull,
        LinkRefusal::PathNotAllowed => ApplicationErrorCode::PathNotAllowed,
        LinkRefusal::AccessDenied => ApplicationErrorCode::AccessDenied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::model::{InviteRefusal, LinkRefusal};

    fn code(error: EnrollmentError) -> (ApplicationErrorCode, String) {
        enrollment_error_code(&error)
    }

    #[test]
    fn every_enrollment_failure_has_its_own_typed_code() {
        use ApplicationErrorCode as Code;
        let op = || "op-1".to_owned();
        let detail = || "why".to_owned();
        let cases = [
            (EnrollmentError::LocalIdentityUnavailable, Code::LocalIdentityUnavailable, ""),
            (
                EnrollmentError::RecoveryJournalUnavailable {
                    operation_id: op(),
                    detail: detail(),
                },
                Code::RecoveryJournalUnavailable,
                "op-1",
            ),
            (
                EnrollmentError::PreparationRejected { detail: detail() },
                Code::PreparationRejected,
                "",
            ),
            (
                EnrollmentError::InviteRefused { reason: InviteRefusal::Expired, detail: detail() },
                Code::InviteExpired,
                "",
            ),
            (
                EnrollmentError::InviteRefused {
                    reason: InviteRefusal::AlreadyUsed,
                    detail: detail(),
                },
                Code::InviteAlreadyUsed,
                "",
            ),
            (
                EnrollmentError::LinkRefused { refusal: LinkRefusal::DiskFull, detail: detail() },
                Code::DiskFull,
                "",
            ),
            (
                EnrollmentError::LinkRefused {
                    refusal: LinkRefusal::PathNotAllowed,
                    detail: detail(),
                },
                Code::PathNotAllowed,
                "",
            ),
            (
                EnrollmentError::LocalLinkFailed {
                    detail: detail(),
                    refusal: Some(LinkRefusal::AccessDenied),
                },
                Code::AccessDenied,
                "",
            ),
            (
                EnrollmentError::LocalLinkFailed { detail: detail(), refusal: None },
                Code::LocalLinkFailed,
                "",
            ),
            (
                EnrollmentError::PreparationAmbiguous { operation_id: op(), detail: detail() },
                Code::CoordinationAmbiguous,
                "op-1",
            ),
            (
                EnrollmentError::LocalLinkAmbiguous { operation_id: op(), detail: detail() },
                Code::RecoveryPending,
                "op-1",
            ),
            (
                EnrollmentError::ActivationRejected { detail: detail() },
                Code::ActivationRejected,
                "",
            ),
            (
                EnrollmentError::ActivationAmbiguous { operation_id: op(), detail: detail() },
                Code::ActivationAmbiguous,
                "op-1",
            ),
            (
                EnrollmentError::CompensationPending { operation_id: op(), detail: detail() },
                Code::CompensationPending,
                "op-1",
            ),
            (
                EnrollmentError::OperationConflict { operation_id: op(), detail: detail() },
                Code::OperationConflict,
                "op-1",
            ),
            (
                EnrollmentError::CoordinationTransport { detail: detail() },
                Code::CoordinationTransport,
                "",
            ),
        ];
        for (error, expected, operation) in cases {
            let described = error.to_string();
            assert_eq!(code(error), (expected, operation.to_owned()), "{described}");
        }
    }

    #[test]
    fn a_provider_folder_is_refused_only_on_a_platform_without_an_adapter() {
        assert_eq!(provider_refusal(""), None, "a plain folder needs no adapter");
        let supported = cfg!(any(target_vendor = "apple", windows));
        assert_eq!(provider_refusal("Photos").is_none(), supported);
    }

    #[test]
    fn a_provider_creation_is_named_by_its_display_name() {
        assert!(provider_creation("", "token").is_none());
        let creation = provider_creation("Photos", "token").unwrap();
        assert_eq!(
            (creation.display_name.as_str(), creation.request_token.as_str()),
            ("Photos", "token")
        );
    }
}
