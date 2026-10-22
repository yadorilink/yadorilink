//! `yadorilink connections`'s failure contract, over the real
//! control-socket framing.
//!
//! The command makes one request -- the connection-attempt history -- and
//! it is load-bearing: when it fails there is nothing to report at all, so
//! the command must fail rather than print an empty section and succeed.
#![cfg(unix)]

/// These tests share `YADORILINK_CONTROL_SOCKET`, a process-global env var
/// -- same coordination discipline as `tests/diagnose.rs`'s own mutex.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Pointing the control socket at a path nothing is listening on is this
/// crate's established stand-in for "daemon not running" (see
/// `tests/diagnose.rs`). Nothing is printed before that failure, because
/// the first `?` returns ahead of every `println!` in `traces` -- not
/// separately asserted here, since an in-process test cannot read back the
/// harness's captured stdout.
#[tokio::test]
async fn a_failing_request_fails_the_command() {
    let _guard = TEST_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONTROL_SOCKET", dir.path().join("no-daemon-here.sock"));

    let err = yadorilink_cli::commands::connection_ops::traces(None)
        .await
        .expect_err("with no daemon at all there is nothing to report, so this must fail");
    assert!(
        matches!(err, yadorilink_cli::error::CliError::DaemonNotRunning),
        "the failure must be the unreachable daemon itself, got {err:?}"
    );
}
