use std::time::Duration;

use super::*;
use crate::error::DaemonUnavailableReason;

#[test]
fn sign_in_steps_pass_through_and_the_client_layers_signed_in_is_left_to_the_session() {
    use ops::auth::LoginEvent as Step;
    assert_eq!(login_event(Step::Enrolling), Some(LoginEvent::Enrolling));
    assert_eq!(
        login_event(Step::OpenBrowser {
            url: "https://a".into(),
            purpose: ops::auth::BrowserPurpose::SignIn
        }),
        Some(LoginEvent::OpenBrowser { url: "https://a".into(), purpose: BrowserPurpose::SignIn })
    );
    assert_eq!(
        login_event(Step::WaitingForApproval { expires_in: Duration::from_secs(9) }),
        Some(LoginEvent::WaitingForApproval { expires_in: Duration::from_secs(9) })
    );
    assert_eq!(
        login_event(Step::ShowDeviceCode {
            verification_uri: "u".into(),
            verification_uri_complete: Some("u?c".into()),
            user_code: "c".into(),
        }),
        Some(LoginEvent::ShowDeviceCode { verification_uri: "u?c".into(), user_code: "c".into() }),
        "the link with the code filled in is the one to open"
    );
    assert_eq!(
        login_event(Step::ShowDeviceCode {
            verification_uri: "u".into(),
            verification_uri_complete: None,
            user_code: "c".into(),
        }),
        Some(LoginEvent::ShowDeviceCode { verification_uri: "u".into(), user_code: "c".into() })
    );
    assert_eq!(
        login_event(Step::WaitingForAuthorization),
        Some(LoginEvent::WaitingForAuthorization)
    );
    assert_eq!(login_event(Step::SignedIn { client_id: "x".into() }), None);
}

#[test]
fn refusals_name_the_argument_and_offer_force_only_to_an_unforced_call() {
    assert_eq!(
        about("group_id")(CoreError::InvalidInput("not linked".into())),
        DesktopError::InvalidInput { message: "not linked".into(), field: Some("group_id".into()) }
    );
    assert!(matches!(
        about("group_id")(CoreError::DaemonNotRunning),
        DesktopError::DaemonUnavailable { reason: DaemonUnavailableReason::NotRunning, .. }
    ));
    let blocked = || CoreError::DurabilityBlocked { message: "m".into(), group_ids: vec![] };
    assert!(matches!(
        offering_force(false)(blocked()),
        DesktopError::DurabilityBlocked { can_force: true, .. }
    ));
    assert!(matches!(
        offering_force(true)(blocked()),
        DesktopError::DurabilityBlocked { can_force: false, .. }
    ));
}

#[test]
fn a_path_that_does_not_resolve_is_invalid_input_about_the_path() {
    assert!(matches!(
        existing_directory("/no/such/place/for/yadorilink"),
        Err(DesktopError::InvalidInput { field: Some(f), .. }) if f == "local_path"
    ));
}

#[test]
fn the_engine_api_version_is_the_one_the_engine_identity_pins() {
    let core = ClientCore::new(CoreConfig {
        daemon_launch: crate::dto::DaemonLaunch::SpawnBinary { path: None },
    });
    assert_eq!(core.engine_api_version(), yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION);
}

#[test]
fn start_over_restarts_the_daemon_with_the_launch_the_host_configured() {
    // `default_launch()` would find no engine beside a packaged app.
    let launch = crate::dto::DaemonLaunch::ScheduledTask { name: "HostChosenTask".into() };
    let core = ClientCore::new(CoreConfig { daemon_launch: launch.clone() });
    assert_eq!(core.machine_ports().launch, launch);
}

#[test]
fn the_default_folder_is_named_for_the_product_and_lives_in_the_home_directory() {
    let home = std::path::PathBuf::from("/Users/a");
    let folder = folders::default_folder_in(Some(home.clone().into_os_string())).unwrap();
    assert_eq!(folder.name, "YadoriLink Folder");
    assert_eq!(folder.path, home.join("YadoriLink").to_string_lossy());
}

#[test]
fn the_default_folder_without_a_home_directory_is_refused() {
    for home in [None, Some(std::ffi::OsString::new())] {
        let error = folders::default_folder_in(home).unwrap_err();
        assert!(matches!(error, DesktopError::InvalidInput { .. }), "{error:?}");
    }
}

/// An embedded host's status carries the host's own device name and never the environment's or
/// the `hostname` command's: with none given it is the generic label.
#[test]
fn an_embedded_status_names_the_device_from_the_hosts_settings() {
    use crate::coordination::credential_store::CredentialSettings;
    use yadorilink_fapi_client::store::Backend;
    use yadorilink_transport::KeyMirror;

    let dir = tempfile::tempdir().unwrap();
    let mut settings = CredentialSettings::new(
        Backend::File(dir.path().join("credentials.json")),
        KeyMirror::Disabled,
    );
    assert_eq!(account_status_in(dir.path(), &settings, None).default_device_name, "My Device");
    settings.host_name = Some("  Ada's iPhone ".to_owned());
    assert_eq!(account_status_in(dir.path(), &settings, None).default_device_name, "Ada's iPhone");
    settings.host_name = Some("   ".to_owned());
    assert_eq!(account_status_in(dir.path(), &settings, None).default_device_name, "My Device");
}
