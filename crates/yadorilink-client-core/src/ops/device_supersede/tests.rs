#![cfg(test)]

use ed25519_dalek::Verifier;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

fn key() -> (tempfile::TempDir, yadorilink_transport::DeviceSigningKeyPair) {
    let dir = tempfile::tempdir().unwrap();
    let key =
        yadorilink_transport::DeviceSigningKeyPair::generate_and_persist(dir.path().join("k"))
            .unwrap();
    (dir, key)
}

async fn call(server: &MockServer) -> Result<SupersedeResponse, SupersedeError> {
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_COORDINATION_ADDR", server.uri());
    let (_dir, key) = key();
    let result = send(
        &yadorilink_fapi_client::test_support::offline_auth(),
        &key,
        "acct-1",
        "old-1",
        "new-1",
    )
    .await;
    std::env::remove_var("YADORILINK_COORDINATION_ADDR");
    result
}

#[test]
fn the_proof_message_is_the_services_exact_byte_string() {
    assert_eq!(
        proof_message("acct-1", "old-1", "new-1"),
        b"yadorilink-device-supersede-v1\nacct-1\nold-1\nnew-1"
    );
}

#[tokio::test]
async fn the_request_is_camelcase_and_the_proof_verifies_under_the_new_key_only() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/devices/supersede"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "oldDeviceId": "old-1", "newDeviceId": "new-1", "supersededAtUnix": 1,
            "protection": "healthy", "unconfirmedGroupIds": []
        })))
        .mount(&server)
        .await;
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_COORDINATION_ADDR", server.uri());
    let (_dir, key) = key();
    let (_other_dir, other) = key_pair();
    let response = send(
        &yadorilink_fapi_client::test_support::offline_auth(),
        &key,
        "acct-1",
        "old-1",
        "new-1",
    )
    .await
    .unwrap();
    std::env::remove_var("YADORILINK_COORDINATION_ADDR");
    assert!(response.is_confirmed());

    let requests = server.received_requests().await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(body["oldDeviceId"], "old-1");
    assert_eq!(body["newDeviceId"], "new-1");
    assert_eq!(body.as_object().unwrap().len(), 3, "{body}");
    let proof = base64::engine::general_purpose::STANDARD
        .decode(body["newDeviceProofBase64"].as_str().unwrap())
        .unwrap();
    let signature = ed25519_dalek::Signature::from_slice(&proof).unwrap();
    let message = proof_message("acct-1", "old-1", "new-1");
    let verifying = |bytes: [u8; 32]| ed25519_dalek::VerifyingKey::from_bytes(&bytes).unwrap();
    verifying(key.public_bytes()).verify(&message, &signature).unwrap();
    assert!(verifying(other.public_bytes()).verify(&message, &signature).is_err());
    // Neither the request nor the account-bound message carries key material.
    let text = String::from_utf8_lossy(&requests[0].body).into_owned();
    assert!(
        !text.contains(&base64::engine::general_purpose::STANDARD.encode(key.signing.to_bytes()))
    );
}

fn key_pair() -> (tempfile::TempDir, yadorilink_transport::DeviceSigningKeyPair) {
    key()
}

#[tokio::test]
async fn the_unconfirmed_answer_names_its_groups() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "oldDeviceId": "old-1", "newDeviceId": "new-1", "supersededAtUnix": 5,
            "protection": "replacement-unconfirmed", "unconfirmedGroupIds": ["g1", "g2"]
        })))
        .mount(&server)
        .await;
    let response = call(&server).await.unwrap();
    assert!(!response.is_confirmed());
    assert_eq!(response.unconfirmed_group_ids, ["g1", "g2"]);
}

#[tokio::test]
async fn an_unknown_protection_value_is_never_read_as_healthy() {
    let response: SupersedeResponse = serde_json::from_value(json!({
        "oldDeviceId": "o", "newDeviceId": "n", "supersededAtUnix": 1, "protection": "fine"
    }))
    .unwrap();
    assert!(!response.is_confirmed());
}

#[tokio::test]
async fn a_stale_login_is_reported_as_reauthentication_required() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "re-authentication is required to replace a device",
            "code": "reauthentication_required"
        })))
        .mount(&server)
        .await;
    assert!(matches!(call(&server).await, Err(SupersedeError::ReauthenticationRequired)));
}

#[tokio::test]
async fn another_403_is_not_mistaken_for_a_stale_login() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({ "error": "proof does not verify" })),
        )
        .mount(&server)
        .await;
    assert!(matches!(call(&server).await, Err(SupersedeError::Failed(CoreError::Forbidden(_)))));
}

#[tokio::test]
async fn a_device_registered_to_a_signed_in_installation_is_reported_as_such() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "the replacement device is registered to another installation that is still signed in",
            "code": "installation_not_signed_out"
        })))
        .mount(&server)
        .await;
    assert!(matches!(call(&server).await, Err(SupersedeError::InstallationNotSignedOut)));
}

#[tokio::test]
async fn the_same_request_is_refused_as_stale_and_then_accepted_after_a_new_sign_in() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/devices/supersede"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "re-authentication is required to replace a device",
            "code": "reauthentication_required"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/devices/supersede"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "oldDeviceId": "old-1", "newDeviceId": "new-1", "supersededAtUnix": 5,
            "protection": "healthy", "unconfirmedGroupIds": []
        })))
        .mount(&server)
        .await;
    assert!(matches!(call(&server).await, Err(SupersedeError::ReauthenticationRequired)));
    // The retry carries the same proof for the same devices; only the sign-in differs.
    let response = call(&server).await.unwrap();
    assert!(response.is_confirmed());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let bodies: Vec<serde_json::Value> =
        requests.iter().map(|r| serde_json::from_slice(&r.body).unwrap()).collect();
    assert_eq!(bodies[0]["oldDeviceId"], bodies[1]["oldDeviceId"]);
    assert_eq!(bodies[0]["newDeviceId"], bodies[1]["newDeviceId"]);
}

#[tokio::test]
async fn a_device_already_replaced_by_another_is_reported_as_such() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({ "error": "conflict" })))
        .mount(&server)
        .await;
    assert!(matches!(call(&server).await, Err(SupersedeError::AlreadyReplaced)));
}

#[tokio::test]
async fn a_missing_device_and_an_outage_are_plain_failures_that_may_be_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "error": "not_found" })))
        .mount(&server)
        .await;
    assert!(matches!(call(&server).await, Err(SupersedeError::Failed(CoreError::Other(_)))));

    let server = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(503)).mount(&server).await;
    assert!(matches!(
        call(&server).await,
        Err(SupersedeError::Failed(CoreError::CoordinationPlaneUnreachable(_)))
    ));
}

#[test]
fn the_account_id_is_the_id_tokens_subject_and_a_missing_one_is_forgotten() {
    let payload =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"sub":"acct-9","iss":"x"}"#);
    let token = format!("h.{payload}.s");
    assert_eq!(subject_of_id_token(&token).as_deref(), Some("acct-9"));
    assert_eq!(subject_of_id_token("garbage"), None);

    let dir = tempfile::tempdir().unwrap();
    record_account_id(dir.path(), Some(&token));
    assert_eq!(recorded_account_id(dir.path()).as_deref(), Some("acct-9"));
    // The next sign-in did not name an account: the previous account's id must not linger.
    record_account_id(dir.path(), None);
    assert_eq!(recorded_account_id(dir.path()), None);
}
