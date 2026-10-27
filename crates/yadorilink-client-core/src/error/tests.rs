#![cfg(test)]

use super::*;

fn command_error(code: i32, operation_id: &str) -> ApplicationCommandError {
    ApplicationCommandError {
        code,
        message: "refused".into(),
        group_ids: vec!["group-1".into()],
        operation_id: operation_id.into(),
    }
}

#[test]
fn a_command_error_keeps_its_code_groups_and_operation() {
    let error = CoreError::from_command_error(command_error(
        ApplicationErrorCode::ReplicaNotReady as i32,
        "op-1",
    ));
    assert!(error.is_command_error(ApplicationErrorCode::ReplicaNotReady));
    assert!(!error.is_command_error(ApplicationErrorCode::TargetNotFound));
    let CoreError::DaemonCommand { message, group_ids, operation_id, .. } = &error else {
        panic!("expected a daemon command error, got {error:?}");
    };
    assert_eq!(message, "refused");
    assert_eq!(group_ids, &["group-1".to_string()]);
    assert_eq!(operation_id.as_deref(), Some("op-1"));
    assert_eq!(error.to_string(), "refused");
}

#[test]
fn the_daemons_terms_refusal_is_the_terms_consent_error_not_a_command_failure() {
    let error = CoreError::from_command_error(command_error(
        ApplicationErrorCode::TermsConsentRequired as i32,
        "",
    ));
    assert!(matches!(error, CoreError::TermsConsentRequired { terms_version: None }), "{error:?}");
}

#[test]
fn an_unknown_command_error_code_reads_as_unspecified_and_an_empty_operation_as_none() {
    let error = CoreError::from_command_error(command_error(9_999, ""));
    assert!(error.is_command_error(ApplicationErrorCode::Unspecified));
    assert!(matches!(error, CoreError::DaemonCommand { operation_id: None, .. }));
}

#[test]
fn a_raw_io_error_keeps_its_own_message_only_the_connect_site_means_daemon_not_running() {
    // `From<io::Error>` never guesses "daemon not running": the daemon-connect call site
    // (daemon/control.rs) maps its own connect failures to `DaemonNotRunning`.
    for kind in [
        std::io::ErrorKind::NotFound,
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::BrokenPipe,
    ] {
        let error = CoreError::from(std::io::Error::new(kind, "gone"));
        assert!(matches!(&error, CoreError::Io(m) if m == "gone"), "{kind:?}: {error:?}");
    }
}

fn command(code: ApplicationErrorCode) -> CoreError {
    CoreError::from_command_error(ApplicationCommandError {
        code: code as i32,
        message: "daemon says no".into(),
        group_ids: vec!["group-1".into()],
        operation_id: "op-7".into(),
    })
}

fn desktop(error: CoreError) -> DesktopError {
    DesktopError::from(error)
}

#[test]
fn signed_out_and_an_unregistered_device_both_read_as_not_signed_in() {
    assert!(matches!(desktop(CoreError::NotLoggedIn), DesktopError::NotSignedIn { .. }));
    assert!(matches!(
        desktop(command(ApplicationErrorCode::LocalIdentityUnavailable)),
        DesktopError::NotSignedIn { .. }
    ));
}

#[test]
fn an_unreachable_or_mismatched_daemon_is_daemon_unavailable_with_its_reason() {
    assert_eq!(
        desktop(CoreError::DaemonNotRunning),
        DesktopError::DaemonUnavailable {
            message: CoreError::DaemonNotRunning.to_string(),
            reason: DaemonUnavailableReason::NotRunning,
        }
    );
    assert_eq!(
        desktop(CoreError::DaemonUnresponsive),
        DesktopError::DaemonUnavailable {
            message: CoreError::DaemonUnresponsive.to_string(),
            reason: DaemonUnavailableReason::Unresponsive,
        }
    );
    let mismatch = CoreError::DaemonProtocolMismatch { client: 3, daemon: 4 };
    let text = mismatch.to_string();
    assert_eq!(
        desktop(mismatch),
        DesktopError::DaemonUnavailable {
            message: text,
            reason: DaemonUnavailableReason::ProtocolMismatch {
                client_version: 3,
                daemon_version: 4
            },
        }
    );
}

#[test]
fn network_failures_carry_their_kind() {
    let cases = [
        (CoreError::CoordinationPlaneUnreachable("down".into()), NetworkErrorKind::Unreachable),
        (command(ApplicationErrorCode::CoordinationTransport), NetworkErrorKind::Unreachable),
        (command(ApplicationErrorCode::CoordinationAmbiguous), NetworkErrorKind::Unreachable),
        (command(ApplicationErrorCode::TicketUnavailable), NetworkErrorKind::Unreachable),
        (
            CoreError::LimitExceeded { message: "slow down".into(), kind: LimitKind::RateLimited },
            NetworkErrorKind::RateLimited,
        ),
        (
            command(ApplicationErrorCode::ActivationAmbiguous),
            NetworkErrorKind::ActivationPendingReconciliation,
        ),
    ];
    for (error, expected) in cases {
        let label = format!("{error:?}");
        match desktop(error) {
            DesktopError::Network { kind, .. } => assert_eq!(kind, expected, "{label}"),
            other => panic!("{label} mapped to {other:?}"),
        }
    }
}

#[test]
fn refusals_by_the_coordination_plane_are_permission_denied_with_their_reason() {
    let store = yadorilink_fapi_client::store::StoreError::UnknownBackend("bad".into());
    let cases = [
        (CoreError::AuthFailed("expired".into()), PermissionDeniedReason::SessionRejected),
        (CoreError::SignInRequired, PermissionDeniedReason::SessionRejected),
        (
            CoreError::TermsConsentRequired { terms_version: Some("v1".into()) },
            PermissionDeniedReason::TermsConsentRequired,
        ),
        (CoreError::AccountMismatch, PermissionDeniedReason::SessionRejected),
        // The daemon's typed refusal is the same sign-in error as the direct coordination calls.
        (
            command(ApplicationErrorCode::TermsConsentRequired),
            PermissionDeniedReason::TermsConsentRequired,
        ),
        (CoreError::DeviceSuperseded, PermissionDeniedReason::DeviceSuperseded),
        (CoreError::Forbidden("not yours".into()), PermissionDeniedReason::Forbidden),
        (CoreError::ReauthenticationRequired, PermissionDeniedReason::ReauthenticationRequired),
        (command(ApplicationErrorCode::CoordinationRejected), PermissionDeniedReason::Forbidden),
        (command(ApplicationErrorCode::ActivationRejected), PermissionDeniedReason::Forbidden),
        (command(ApplicationErrorCode::PreparationRejected), PermissionDeniedReason::Forbidden),
        (
            CoreError::LimitExceeded { message: "full".into(), kind: LimitKind::Quota },
            PermissionDeniedReason::QuotaExceeded,
        ),
        (CoreError::CredentialStore(store), PermissionDeniedReason::CredentialStoreUnusable),
    ];
    for (error, expected) in cases {
        let label = format!("{error:?}");
        match desktop(error) {
            DesktopError::PermissionDenied { reason, .. } => {
                assert_eq!(reason, expected, "{label}")
            }
            other => panic!("{label} mapped to {other:?}"),
        }
    }
}

#[test]
fn durability_refusals_keep_groups_and_operation_and_offer_force_only_when_asked() {
    let blocked = CoreError::DurabilityBlocked {
        message: "no other copy".into(),
        group_ids: vec!["g".into()],
    };
    assert_eq!(
        DesktopError::from_core(blocked, true),
        DesktopError::DurabilityBlocked {
            message: "no other copy".into(),
            group_ids: vec!["g".into()],
            operation_id: None,
            can_force: true,
        }
    );
    for code in [
        ApplicationErrorCode::ReplicaNotReady,
        ApplicationErrorCode::DurabilityLatchFailed,
        ApplicationErrorCode::RecoveryPending,
    ] {
        assert_eq!(
            desktop(command(code)),
            DesktopError::DurabilityBlocked {
                message: "daemon says no".into(),
                group_ids: vec!["group-1".into()],
                operation_id: Some("op-7".into()),
                can_force: false,
            },
            "{code:?}"
        );
    }
}

#[test]
fn bad_arguments_and_missing_targets_are_invalid_input() {
    assert!(matches!(
        desktop(CoreError::InvalidInput("no such group".into())),
        DesktopError::InvalidInput { field: None, .. }
    ));
    assert!(matches!(
        desktop(command(ApplicationErrorCode::TargetNotFound)),
        DesktopError::InvalidInput { .. }
    ));
}

#[test]
fn everything_else_is_internal_with_a_stable_category() {
    let cases = [
        (CoreError::DaemonRejected("x".into()), "cli_command_failed"),
        (CoreError::Other("x".into()), "cli_command_failed"),
        (CoreError::Io("x".into()), "cli_command_failed"),
        (command(ApplicationErrorCode::Persistence), "daemon_command_persistence"),
        (command(ApplicationErrorCode::LocalLinkFailed), "daemon_command_local_link_failed"),
        (command(ApplicationErrorCode::OperationConflict), "daemon_command_operation_conflict"),
        (command(ApplicationErrorCode::CompensationPending), "daemon_command_compensation_pending"),
        (
            command(ApplicationErrorCode::RecoveryJournalUnavailable),
            "daemon_command_recovery_journal_unavailable",
        ),
        (command(ApplicationErrorCode::Unspecified), "daemon_command_unspecified"),
    ];
    for (error, expected) in cases {
        let label = format!("{error:?}");
        match desktop(error) {
            DesktopError::Internal { category, .. } => assert_eq!(category, expected, "{label}"),
            other => panic!("{label} mapped to {other:?}"),
        }
    }
}

#[test]
fn the_message_is_always_the_client_errors_own_text() {
    let error = CoreError::AuthFailed("token expired".into());
    let text = error.to_string();
    assert_eq!(desktop(error).to_string(), text);
}

#[test]
fn link_and_invite_refusals_carry_their_typed_reason() {
    let cases = [
        (ApplicationErrorCode::DiskFull, RefusalReason::DiskFull),
        (ApplicationErrorCode::PathNotAllowed, RefusalReason::PathNotAllowed),
        (ApplicationErrorCode::AccessDenied, RefusalReason::AccessDenied),
        (ApplicationErrorCode::InviteExpired, RefusalReason::InviteExpired),
        (ApplicationErrorCode::InviteAlreadyUsed, RefusalReason::InviteAlreadyUsed),
        (ApplicationErrorCode::UnrecordedLocalChanges, RefusalReason::UnrecordedLocalChanges),
        (ApplicationErrorCode::ConflictNotResolvable, RefusalReason::ConflictNotResolvable),
        (ApplicationErrorCode::GroupMismatch, RefusalReason::GroupMismatch),
    ];
    for (code, reason) in cases {
        assert_eq!(
            desktop(command(code)),
            DesktopError::Refused { message: "daemon says no".into(), reason },
            "{code:?}"
        );
    }
}

#[test]
fn a_not_protected_unlink_is_a_durability_refusal() {
    assert_eq!(
        DesktopError::from_core(command(ApplicationErrorCode::NotProtected), true),
        DesktopError::DurabilityBlocked {
            message: "daemon says no".into(),
            group_ids: vec!["group-1".into()],
            operation_id: Some("op-7".into()),
            can_force: true,
        }
    );
}

#[test]
fn a_managed_elsewhere_refusal_is_typed_for_the_desktop() {
    let error =
        DesktopError::from_core(CoreError::ManagedElsewhere("the app owns it".into()), false);
    assert_eq!(
        error,
        DesktopError::Refused {
            message: "the app owns it".into(),
            reason: RefusalReason::ManagedElsewhere
        }
    );
}

fn mismatch(
    kind: EngineMismatchKind,
    direction: EngineMismatchDirection,
    app_api: u32,
    engine_api: u32,
) -> CoreError {
    CoreError::EngineMismatch {
        message: "update".into(),
        detail: EngineMismatchDetail {
            kind,
            direction,
            app_version: "1.2.0".into(),
            engine_version: "1.1.0".into(),
            app_release_id: "a:b".into(),
            engine_release_id: "c:d".into(),
            app_api_version: app_api,
            engine_api_version: engine_api,
        },
    }
}

#[test]
fn an_engine_mismatch_is_typed_not_a_protocol_mismatch() {
    for (kind, direction) in [
        (EngineMismatchKind::ApiVersion, EngineMismatchDirection::EngineOlder),
        (EngineMismatchKind::ApiVersion, EngineMismatchDirection::EngineNewer),
        (EngineMismatchKind::Build, EngineMismatchDirection::Unknown),
        (EngineMismatchKind::AppInstallation, EngineMismatchDirection::Unknown),
    ] {
        assert_eq!(
            desktop(mismatch(kind, direction, 7, 6)),
            DesktopError::DaemonUnavailable {
                message: "update".into(),
                reason: DaemonUnavailableReason::EngineMismatch {
                    kind,
                    direction,
                    app_version: "1.2.0".into(),
                    engine_version: "1.1.0".into(),
                    app_release_id: "a:b".into(),
                    engine_release_id: "c:d".into(),
                    app_api_version: 7,
                    engine_api_version: 6,
                },
            }
        );
    }
}

#[test]
fn an_expired_device_authorization_is_a_session_refusal_that_says_to_start_again() {
    let error = CoreError::from(yadorilink_fapi_client::Error::DeviceAuthorizationExpired);
    match error {
        CoreError::AuthFailed(message) => {
            assert!(message.contains("expired"), "{message}");
            assert!(message.contains("start the sign-in again"), "{message}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn no_core_error_text_names_a_cli_command() {
    let refusals = [
        StartOverRefusal::NotConfirmed,
        StartOverRefusal::NotRestored,
        StartOverRefusal::InProgress,
    ];
    let mut texts = vec![
        CoreError::NotLoggedIn.to_string(),
        CoreError::DaemonNotRunning.to_string(),
        CoreError::DaemonUnresponsive.to_string(),
    ];
    texts.extend(refusals.iter().map(ToString::to_string));
    for text in texts {
        for command in [
            "yadorilink login",
            "yadorilink logout",
            "yadorilink daemon start",
            "yadorilink daemon stop",
            "yadorilink device ",
            "yadorilink share ",
            "yadorilink credentials ",
            "yadorilink doctor",
        ] {
            assert!(!text.contains(command), "a host-neutral text names a command: {text}");
        }
        assert!(!text.contains('`'), "a host-neutral text quotes a command: {text}");
    }
}

#[test]
fn a_daemon_hint_reaches_a_gui_as_a_typed_start_reason_and_keeps_the_neutral_text() {
    for (hint, stop_first) in [(Hint::StartDaemon, false), (Hint::StopThenStartDaemon, true)] {
        let error = CoreError::Other("the daemon did not answer".into()).hinted(hint);
        assert_eq!(error.hint(), Some(hint));
        assert_eq!(
            desktop(error),
            DesktopError::DaemonUnavailable {
                message: "the daemon did not answer".into(),
                reason: DaemonUnavailableReason::StartNeeded { stop_first },
            }
        );
    }
}

#[test]
fn a_non_daemon_hint_keeps_the_category_of_the_error_it_wraps() {
    let error = CoreError::AuthFailed("already enrolled".into()).hinted(Hint::AlreadyEnrolled);
    assert_eq!(
        desktop(error),
        DesktopError::PermissionDenied {
            message: "authentication failed: already enrolled".into(),
            reason: PermissionDeniedReason::SessionRejected,
        }
    );
    let error = CoreError::InvalidInput("no group".into()).hinted(Hint::CreateOrAcceptShare);
    assert!(matches!(desktop(error), DesktopError::InvalidInput { .. }));
}

#[test]
fn a_hint_is_seen_through_and_carried_by_context() {
    let hinted = CoreError::Other("x".into()).hinted(Hint::StartDaemon);
    assert!(matches!(hinted.into_unhinted(), CoreError::Other(m) if m == "x"));
    let nested =
        CoreError::AuthFailed("y".into()).hinted(Hint::SignInAgain).hinted(Hint::StartDaemon);
    assert!(matches!(nested.into_unhinted(), CoreError::AuthFailed(m) if m == "y"));

    let carried = CoreError::Other("inner".into())
        .hinted(Hint::StopThenStartDaemon)
        .with_context(|why| format!("outer: {why}"), Some(Hint::StartDaemon));
    assert_eq!(carried.hint(), Some(Hint::StopThenStartDaemon));
    assert_eq!(carried.to_string(), "outer: inner");
    let fallback = CoreError::Other("inner".into())
        .with_context(|why| why.to_owned(), Some(Hint::StartDaemon));
    assert_eq!(fallback.hint(), Some(Hint::StartDaemon));
    let none = CoreError::Other("inner".into()).with_context(|why| why.to_owned(), None);
    assert_eq!(none.hint(), None);
}

#[test]
fn the_start_over_in_progress_text_is_exact() {
    assert_eq!(
        StartOverRefusal::InProgress.to_string(),
        "a start over as a new device is under way on this computer; finish it before registering"
    );
}

/// A refused refresh (`invalid_grant` at the token endpoint) is the sign-in-required refusal, but
/// the same answer to any other step (a wrong authorization code, say) stays an ordinary failure.
#[test]
fn only_a_refused_refresh_is_sign_in_required() {
    use yadorilink_fapi_client::Error as Fapi;
    let body = r#"{"error":"invalid_grant"}"#.to_owned();
    let refresh = Fapi::Response {
        step: "refresh",
        status: 400,
        body: body.clone(),
        parsed: serde_json::from_str(&body).ok(),
    };
    assert!(matches!(CoreError::from(refresh), CoreError::SignInRequired));
    let code = Fapi::Response {
        step: "token",
        status: 400,
        body: body.clone(),
        parsed: serde_json::from_str(&body).ok(),
    };
    assert!(matches!(CoreError::from(code), CoreError::AuthFailed(_)));
    let revoked = r#"{"error":"invalid_client"}"#.to_owned();
    let client = Fapi::Response {
        step: "refresh",
        status: 401,
        body: revoked.clone(),
        parsed: serde_json::from_str(&revoked).ok(),
    };
    assert!(matches!(CoreError::from(client), CoreError::AuthFailed(_)));
}

#[test]
fn a_daemon_next_step_becomes_a_hint_and_unset_is_none() {
    use yadorilink_ipc_proto::daemonctl::NextStep;
    assert_eq!(Hint::from_wire(NextStep::CheckLinkStatus as i32), Some(Hint::CheckLinkStatus));
    assert_eq!(Hint::from_wire(NextStep::KeepItemOnDevice as i32), Some(Hint::KeepItemOnDevice));
    assert_eq!(Hint::from_wire(NextStep::Unspecified as i32), None);
    assert_eq!(Hint::from_wire(999), None);
}

#[test]
fn an_invalid_argument_names_no_flag_and_reaches_a_gui_as_its_field() {
    let error = CoreError::InvalidArgument(InvalidArgument::Role("owner".into()));
    assert!(!error.to_string().contains("--"), "{error}");
    match desktop(error) {
        DesktopError::InvalidInput { field, .. } => assert_eq!(field.as_deref(), Some("role")),
        other => panic!("expected invalid input, got {other:?}"),
    }
}
