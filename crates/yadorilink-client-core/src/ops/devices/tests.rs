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
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_COORDINATION_ADDR", server.uri());
    let devices =
        fetch_devices(&yadorilink_fapi_client::test_support::offline_auth(), Some("this-device"))
            .await;
    std::env::remove_var("YADORILINK_COORDINATION_ADDR");
    let devices = devices.unwrap();

    assert!(devices.iter().find(|d| d.device_id == "this-device").unwrap().online);
    assert!(!devices.iter().find(|d| d.device_id == "other-device").unwrap().online);
}
