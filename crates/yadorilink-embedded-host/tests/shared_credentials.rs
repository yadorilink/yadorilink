//! Engines in one process that use one credential entry: the entry is not inside either state
//! directory (here a credential file named outside both, standing in for the OS keyring, whose
//! entry is process-wide too), so two directories would refresh one token under two rotation
//! locks. The host refuses the second directory while the first runs; one directory, or a
//! credential entry of its own per engine (see `lifecycle.rs`), is fine.

use yadorilink_embedded_host::{
    CredentialBackend, CredentialConfig, EmbeddedHost, EngineConfig, HostError, KeyMirror,
    StartError,
};

mod support;
use support::{area, serialized};

/// One credential file named outside both state directories, standing in for the OS keyring,
/// whose entry is process-wide too. Both engines are configured with it.
fn shared_credentials(dir: &tempfile::TempDir) -> CredentialConfig {
    CredentialConfig::new(
        CredentialBackend::File(dir.path().join("shared-credentials.json")),
        KeyMirror::Disabled,
    )
}

#[test]
fn a_second_state_directory_is_refused_while_the_first_runs_and_allowed_after_it_stops() {
    let _serial = serialized();
    let shared_dir = tempfile::tempdir().unwrap();
    let (mut first, mut second) = (area(), area());
    first.config.credentials = shared_credentials(&shared_dir);
    second.config.credentials = shared_credentials(&shared_dir);
    let (a, b) =
        (EmbeddedHost::new(first.config.clone()), EmbeddedHost::new(second.config.clone()));

    a.start().unwrap();
    let refused = b.start();
    assert!(
        matches!(refused, Err(HostError::Start(StartError::SharedCredentialStore { .. }))),
        "{refused:?}"
    );
    a.stop().unwrap();
    b.start().expect("the other directory starts once the first engine stopped");
    b.stop().unwrap();
}

#[test]
fn another_engine_over_the_same_state_directory_is_allowed() {
    let _serial = serialized();
    let shared_dir = tempfile::tempdir().unwrap();
    let (mut first, mut second) = (area(), area());
    first.config.credentials = shared_credentials(&shared_dir);
    second.config.credentials = shared_credentials(&shared_dir);
    // The same directory (so one rotation lock), over another database and block store.
    let same_directory =
        EngineConfig { config_dir: first.config.config_dir.clone(), ..second.config.clone() };
    let (a, b) = (EmbeddedHost::new(first.config.clone()), EmbeddedHost::new(same_directory));

    a.start().unwrap();
    b.start().expect("one state directory shares its rotation lock");
    b.stop().unwrap();
    a.stop().unwrap();
}

#[test]
fn one_credential_file_spelled_two_ways_is_still_one_entry() {
    let _serial = serialized();
    let shared_dir = tempfile::tempdir().unwrap();
    let (mut first, mut second) = (area(), area());
    first.config.credentials = shared_credentials(&shared_dir);
    // The same file through a dot segment.
    second.config.credentials = CredentialConfig::new(
        CredentialBackend::File(shared_dir.path().join(".").join("shared-credentials.json")),
        KeyMirror::Disabled,
    );
    let (a, b) =
        (EmbeddedHost::new(first.config.clone()), EmbeddedHost::new(second.config.clone()));

    a.start().unwrap();
    let refused = b.start();
    assert!(
        matches!(refused, Err(HostError::Start(StartError::SharedCredentialStore { .. }))),
        "{refused:?}"
    );
    a.stop().unwrap();
}

#[test]
fn a_credential_file_that_cannot_be_resolved_refuses_the_start() {
    let _serial = serialized();
    let mut config = area();
    config.config.credentials = CredentialConfig::new(
        CredentialBackend::File(config._dir.path().join("no-such-dir").join("credentials.json")),
        KeyMirror::Disabled,
    );
    let host = EmbeddedHost::new(config.config.clone());
    assert!(host.start().is_err());
}
