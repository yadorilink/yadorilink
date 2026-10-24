#![cfg(test)]

use super::*;

/// `POST /devices/register`'s real success response is camelCase.
#[test]
fn register_device_response_deserializes_the_coordination_planes_camelcase_shape() {
    let parsed: RegisterDeviceResponse =
        serde_json::from_str(r#"{"deviceId":"device-1","serviceSigningPublicKeyBase64":"abc123"}"#)
            .unwrap();
    assert_eq!(parsed.device_id, "device-1");
}

/// The route reads `deviceName`/`signingPublicKeyBase64`; a snake_case body
/// arrives with every field undefined server-side.
#[test]
fn register_device_request_serializes_camelcase_for_the_coordination_plane() {
    let body = serde_json::to_value(RegisterDeviceRequest {
        device_name: "my-laptop",
        signing_public_key_base64: "sign-key".to_string(),
    })
    .unwrap();
    assert_eq!(body["deviceName"], "my-laptop");
    assert_eq!(body["signingPublicKeyBase64"], "sign-key");
    assert!(body.get("device_name").is_none());
}

/// `GET /devices`'s real response carries camelCase device keys.
#[test]
fn device_info_deserializes_the_coordination_planes_camelcase_shape() {
    let parsed: DeviceInfo =
        serde_json::from_str(r#"{"deviceId":"device-1","deviceName":"my-laptop","online":true}"#)
            .unwrap();
    assert_eq!(parsed.device_id, "device-1");
    assert_eq!(parsed.device_name, "my-laptop");
    assert!(parsed.online);
}

/// The machine showing the device list is running, whatever the coordination
/// plane last observed of its subscription.
#[tokio::test]
async fn this_device_is_never_listed_offline_even_when_the_service_says_so() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/devices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "devices": [
                { "deviceId": "this-device", "deviceName": "laptop", "online": false },
                { "deviceId": "other-device", "deviceName": "desktop", "online": false },
            ]
        })))
        .mount(&server)
        .await;
    let devices = fetch_devices(
        &crate::coordination::http_client::CoordinationAccess::new(
            yadorilink_fapi_client::test_support::offline_auth(),
            server.uri(),
        ),
        Some("this-device"),
    )
    .await;
    let devices = devices.unwrap();

    assert!(devices.iter().find(|d| d.device_id == "this-device").unwrap().online);
    assert!(!devices.iter().find(|d| d.device_id == "other-device").unwrap().online);
}

/// The registration stays done; the restart's own next step reaches the front end instead of
/// being spelled into the text and replaced by another.
#[test]
fn a_restart_that_failed_after_registration_carries_the_restarts_own_next_step() {
    let stuck = CoreError::Other("the running daemon did not stop".into())
        .hinted(Hint::StopThenStartDaemon);
    let error = restart_failed_after_registration("dev-1", stuck, None);
    assert_eq!(error.hint(), Some(Hint::StopThenStartDaemon));
    assert_eq!(
        error.to_string(),
        "this device is registered (dev-1), but the daemon could not be restarted to pick it up: \
         the running daemon did not stop"
    );
    // A restart failure with no step of its own falls back to starting the daemon.
    let error = restart_failed_after_registration("dev-1", CoreError::DaemonNotRunning, None);
    assert_eq!(error.hint(), Some(Hint::StartDaemon));
    // Through a desktop front end it is the typed start reason, with the stop step kept.
    let stuck = CoreError::Other("x".into()).hinted(Hint::StopThenStartDaemon);
    assert!(matches!(
        crate::error::DesktopError::from(restart_failed_after_registration("dev-1", stuck, None)),
        crate::error::DesktopError::DaemonUnavailable {
            reason: crate::error::DaemonUnavailableReason::StartNeeded { stop_first: true },
            ..
        }
    ));
}

/// Where starting cannot help, no start step is invented: a recorded startup refusal, or another
/// owner managing the daemon, stays what it was (and is not a GUI "start needed").
#[test]
fn no_start_step_is_invented_where_starting_cannot_help() {
    let refused = restart_failed_after_registration(
        "dev-1",
        crate::ops::daemon::did_not_answer(Some("reset steps".into())),
        Some("reset steps".into()),
    );
    assert_eq!(refused.hint(), None);
    assert!(matches!(
        crate::error::DesktopError::from(refused),
        crate::error::DesktopError::Internal { .. }
    ));
    let elsewhere = restart_failed_after_registration(
        "dev-1",
        CoreError::ManagedElsewhere("the app owns it".into()),
        None,
    );
    assert_eq!(elsewhere.hint(), None);
}
