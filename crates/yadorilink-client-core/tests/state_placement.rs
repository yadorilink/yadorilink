//! A packaged app must not create or write engine state under AppData: every client writer
//! gets the typed refusal first, and nothing is created on disk. One process-global environment,
//! so one test body.

use yadorilink_client_core::coordination::{credential_store, device_config};
use yadorilink_client_core::error::{CoreError, DesktopError, RefusalReason};
use yadorilink_client_core::ops;

fn is_refusal<T: std::fmt::Debug>(result: Result<T, CoreError>, what: &str) {
    match result {
        Err(CoreError::StatePlacement(_)) => {}
        other => panic!("{what}: expected the placement refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_packaged_process_creates_nothing_under_appdata() {
    let root = tempfile::tempdir().unwrap();
    let profile = root.path().join("ann");
    let roaming = profile.join("AppData").join("Roaming");
    let state = roaming.join("yl");
    std::env::set_var("USERPROFILE", &profile);
    std::env::set_var("APPDATA", &roaming);
    std::env::set_var("LOCALAPPDATA", profile.join("AppData").join("Local"));
    std::env::set_var("YADORILINK_CONFIG_DIR", &state);
    yadorilink_fs_platform::state_dir::set_package_identity_for_test(true);

    // Every writer that derives its path from the state directory.
    is_refusal(
        ops::devices::register_device("laptop".into(), &ops::daemon::default_launch()).await,
        "register_device",
    );
    is_refusal(device_config::config_dir().map_err(CoreError::from), "config_dir");
    is_refusal(
        device_config::save(&device_config::DeviceConfig {
            device_id: "d".into(),
            coordination_addr: "http://127.0.0.1:1".into(),
            signing_public_key: "k".into(),
            config_version: device_config::CONFIG_VERSION,
        }),
        "device.json",
    );
    is_refusal(credential_store::open(), "credential store (file fallback)");
    is_refusal(credential_store::installation(), "credential read");
    is_refusal(credential_store::clear().await, "credential clear");
    is_refusal(credential_store::purge_local().await, "credential purge");

    assert!(!state.exists(), "the refused directory was created");
    assert!(!roaming.exists(), "something was created under AppData");
    assert!(!profile.join("AppData").exists());

    // The desktop sees the typed refusal, not a string to match.
    let desktop =
        DesktopError::from_core(device_config::config_dir().map(|_| ()).unwrap_err().into(), false);
    assert!(matches!(
        desktop,
        DesktopError::Refused { reason: RefusalReason::StateDirUnusable, .. }
    ));

    // Outside AppData the same process is served, and the credential file override is checked
    // on its own.
    let allowed = profile.join(".yadorilink");
    std::env::set_var("YADORILINK_CONFIG_DIR", &allowed);
    assert_eq!(device_config::config_dir().unwrap(), allowed);
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", roaming.join("credentials.json"));
    is_refusal(credential_store::open(), "YADORILINK_CREDENTIAL_FILE under AppData");
    assert!(!roaming.exists());
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    yadorilink_fs_platform::state_dir::set_package_identity_for_test(false);
}
