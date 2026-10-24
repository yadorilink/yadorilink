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
            command(ApplicationErrorCode::AccessDenied),
            "the system has not allowed YadoriLink to access this folder, so nothing was \
             linked. On macOS, allow it in System Settings > Privacy & Security > Files and \
             Folders (or Full Disk Access); on Windows, give your account access to the folder. \
             Then run the command again, or choose another folder (daemon says no)",
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

/// The client layer's texts are host-neutral; this command line spells the commands, so what
/// it prints is what it printed before the commands left client-core. The expected strings are
/// the ones the pre-change sites produced (git history). This test builds the core errors by
/// hand, so it pins only the CLI mapping; the real sites are pinned in client-core, each with its
/// exact text and hint (`ops::daemon`, `ops::shares`, `ops::auth`, `ops::auth::loopback`,
/// `ops::start_over` tests): a drift of a site's text or hint breaks the test next to the site.
#[test]
fn every_hinted_site_prints_the_text_it_always_printed() {
    use yadorilink_client_core::Hint;
    let cases: Vec<(CoreError, &str, i32)> =
        vec![
        (
            CoreError::Other("the daemon did not answer after it was started".into())
                .hinted(Hint::StartDaemon),
            "the daemon did not answer after it was started; run `yadorilink daemon start`",
            1,
        ),
        (
            CoreError::Other("the running daemon did not stop".into())
                .hinted(Hint::StopThenStartDaemon),
            "the running daemon did not stop; restart it with `yadorilink daemon stop` and \
             `yadorilink daemon start`",
            1,
        ),
        (
            CoreError::Other(
                "the old daemon stopped answering but is still exiting, so the new one cannot \
                 start yet; wait a moment"
                    .into(),
            )
            .hinted(Hint::WaitThenStartDaemon),
            "the old daemon stopped answering but is still exiting, so the new one cannot start \
             yet; wait a moment and run `yadorilink daemon start`",
            1,
        ),
        // The start-over wrapper carries the restart's own step: the old text embedded the
        // restart's CLI text ("...did not stop; restart it with ...") after its own prefix.
        (
            CoreError::Other(
                "the running daemon could not be restarted to pick up the current sign-in, so \
                 nothing was registered or changed and the start over can be run again: the \
                 running daemon did not stop"
                    .into(),
            )
            .hinted(Hint::StopThenStartDaemon),
            "the running daemon could not be restarted to pick up the current sign-in, so \
             nothing was registered or changed and the start over can be run again: the running \
             daemon did not stop; restart it with `yadorilink daemon stop` and `yadorilink \
             daemon start`",
            1,
        ),
        (
            CoreError::AuthFailed("no sign-in arrived within 5 seconds".into())
                .hinted(Hint::SignInAgain),
            "authentication failed: no sign-in arrived within 5 seconds. Run `yadorilink login` \
             again and open the link it prints.",
            10,
        ),
        (
            CoreError::InvalidInput("no folder group named \"g\" is visible to this account".into())
                .hinted(Hint::CreateOrAcceptShare),
            "no folder group named \"g\" is visible to this account (run `yadorilink share \
             create` to make one, or `yadorilink share accept` to join one you were invited to)",
            1,
        ),
        (
            CoreError::InvalidInput("no joinable folder group named \"g\"".into())
                .hinted(Hint::ListJoinableShares),
            "no joinable folder group named \"g\" (run `yadorilink share joinable` to see what \
             this account can join)",
            1,
        ),
        (
            CoreError::StartOverRefused(StartOverRefusal::InProgress),
            "a start over as a new device is under way on this computer; finish it \
             (`yadorilink device start-over`) before registering",
            1,
        ),
        (
            CoreError::AuthFailed("this installation is already enrolled".into())
                .hinted(Hint::AlreadyEnrolled),
            "authentication failed: this installation is already enrolled. `yadorilink logout` \
             first if you mean to enrol it again -- re-enrolling mints a NEW identity rather \
             than repairing the old one, and the old one stays live until it is revoked. The \
             sign-in belongs to this computer user, not to one data directory: if the data \
             directory was removed without signing out, `yadorilink credentials purge` deletes \
             the leftover sign-in from this computer (it does not revoke it on the server).",
            10,
        ),
    ];
    for (core, message, code) in cases {
        let debug = format!("{core:?}");
        let cli = CliError::from(core);
        assert_eq!(cli.to_string(), message, "{debug}");
        assert_eq!(cli.exit_code(), code, "{debug}");
    }
}

#[test]
fn the_credential_cleanup_advice_keeps_its_old_wording() {
    assert_eq!(
        crate::error::CREDENTIAL_CLEANUP_ADVICE,
        "Run `yadorilink credentials purge` to try again"
    );
}
