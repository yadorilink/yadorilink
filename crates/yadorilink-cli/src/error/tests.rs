#![cfg(test)]

use yadorilink_client_core::error::LimitKind;
use yadorilink_ipc_proto::daemonctl::ApplicationErrorCode;

use super::*;

fn command(code: ApplicationErrorCode) -> CoreError {
    CoreError::DaemonCommand {
        code,
        message: "daemon says no".into(),
        group_ids: vec!["group-1".into()],
        operation_id: Some("op-1".into()),
    }
}

/// Every client-layer error reaches the terminal with the message and exit
/// code this command line printed before the operations moved.
#[test]
fn every_core_error_maps_to_the_historical_message_and_exit_code() {
    let cases: Vec<(CoreError, &str, i32)> = vec![
        (CoreError::NotLoggedIn, "not logged in — run `yadorilink login`", 10),
        (CoreError::AuthFailed("bad".into()), "authentication failed: bad", 10),
        (CoreError::Forbidden("not_group_owner".into()), "not_group_owner", 1),
        (
            CoreError::CoordinationPlaneUnreachable("down".into()),
            "could not reach the YadoriLink server: down",
            3,
        ),
        (
            CoreError::LimitExceeded { message: "too many".into(), kind: LimitKind::Quota },
            "too many",
            7,
        ),
        (
            CoreError::LimitExceeded { message: "slow down".into(), kind: LimitKind::RateLimited },
            "slow down",
            7,
        ),
        (
            CoreError::DaemonNotRunning,
            "yadorilink daemon is not running — run `yadorilink daemon start`, or `systemctl start <service>` where a system service runs it",
            4,
        ),
        (
            CoreError::DaemonProtocolMismatch { client: 11, daemon: 10 },
            "CLI/daemon protocol version mismatch (CLI 11, daemon 10); run matching YadoriLink \
             CLI and daemon binaries",
            1,
        ),
        (CoreError::DaemonRejected("rejected".into()), "rejected", 1),
        (CoreError::ManagedElsewhere("the app owns it".into()), "the app owns it", 19),
        (command(ApplicationErrorCode::ActivationAmbiguous), "daemon says no", 8),
        (command(ApplicationErrorCode::ReplicaNotReady), "daemon says no", 1),
        (command(ApplicationErrorCode::TargetNotFound), "daemon says no", 1),
        (command(ApplicationErrorCode::PathNotAllowed), "daemon says no", 1),
        (command(ApplicationErrorCode::NotProtected), "daemon says no", 1),
        (
            command(ApplicationErrorCode::DiskFull),
            "there is not enough free disk space to do this; free some space and try again \
             (daemon says no)",
            1,
        ),
        (
            command(ApplicationErrorCode::InviteExpired),
            "this invite has expired; ask the person who sent it for a new one",
            1,
        ),
        (
            command(ApplicationErrorCode::InviteAlreadyUsed),
            "this invite was already used or was cancelled; ask the person who sent it for a new \
             one",
            1,
        ),
        (
            CoreError::DurabilityBlocked {
                message: "refusing to drop".into(),
                group_ids: vec!["group-1".into()],
            },
            "refusing to drop",
            1,
        ),
        (CoreError::InvalidInput("invalid --role".into()), "invalid --role", 1),
        (CoreError::Io("pipe".into()), "pipe", 1),
        (CoreError::Other("other".into()), "other", 1),
    ];
    for (core, message, code) in cases {
        let debug = format!("{core:?}");
        let cli = CliError::from(core);
        assert_eq!(cli.to_string(), message, "{debug}");
        assert_eq!(cli.exit_code(), code, "{debug}");
    }
}

#[test]
fn a_credential_store_error_keeps_its_own_category() {
    let store = yadorilink_fapi_client::store::StoreError::UnknownBackend("bogus".into());
    let cli = CliError::from(CoreError::CredentialStore(store));
    assert!(matches!(cli, CliError::CredentialStore(_)));
    assert_eq!(cli.exit_code(), 9);
}

#[test]
fn a_missing_file_is_not_reported_as_a_missing_daemon() {
    let missing = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
    let cli = CliError::from(missing);
    assert!(matches!(cli, CliError::Other(_)), "{cli:?}");
    let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
    assert!(matches!(CliError::from(refused), CliError::DaemonNotRunning));
}
