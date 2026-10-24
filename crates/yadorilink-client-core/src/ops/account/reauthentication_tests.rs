#![cfg(test)]

use std::cell::Cell;

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

async fn post_to(server: &MockServer) -> Result<DeletionRequested, CoreError> {
    let result = post_request(
        &crate::coordination::http_client::CoordinationAccess::new(
            yadorilink_fapi_client::test_support::offline_auth(),
            server.uri(),
        ),
        false,
    )
    .await;
    result
}

#[tokio::test]
async fn a_stale_sign_in_is_reported_as_reauthentication_required() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/account/deletion/request"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "re-authentication is required to delete the account; sign in again",
            "code": "reauthentication_required",
            "reauthenticationWindowSeconds": 300
        })))
        .mount(&server)
        .await;
    assert!(matches!(post_to(&server).await, Err(CoreError::ReauthenticationRequired)));
}

#[tokio::test]
async fn another_forbidden_answer_is_not_mistaken_for_a_stale_sign_in() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({ "error": "no" })))
        .mount(&server)
        .await;
    assert!(matches!(post_to(&server).await, Err(CoreError::Forbidden(_))));
}

#[tokio::test]
async fn a_fresh_sign_in_gets_the_confirmation_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "state": "requested", "confirmationToken": "tok-1"
        })))
        .mount(&server)
        .await;
    assert_eq!(post_to(&server).await.unwrap().confirmation_token, "tok-1");
}

#[tokio::test]
async fn a_stale_sign_in_steps_up_once_and_retries() {
    let attempts = Cell::new(0);
    let steps = Cell::new(0);
    let result = retry_after_step_up(
        || async {
            attempts.set(attempts.get() + 1);
            if attempts.get() == 1 {
                Err(CoreError::ReauthenticationRequired)
            } else {
                Ok("done")
            }
        },
        || async {
            steps.set(steps.get() + 1);
            Ok(())
        },
    )
    .await;
    assert_eq!(result.unwrap(), "done");
    assert_eq!((attempts.get(), steps.get()), (2, 1));
}

#[tokio::test]
async fn a_fresh_sign_in_never_steps_up() {
    let steps = Cell::new(0);
    let result = retry_after_step_up(
        || async { Ok(1) },
        || async {
            steps.set(1);
            Ok(())
        },
    )
    .await;
    assert_eq!(result.unwrap(), 1);
    assert_eq!(steps.get(), 0);
}

#[tokio::test]
async fn a_second_refusal_is_returned_and_never_loops() {
    let attempts = Cell::new(0);
    let steps = Cell::new(0);
    let result: Result<(), _> = retry_after_step_up(
        || async {
            attempts.set(attempts.get() + 1);
            Err(CoreError::ReauthenticationRequired)
        },
        || async {
            steps.set(steps.get() + 1);
            Ok(())
        },
    )
    .await;
    assert!(matches!(result, Err(CoreError::ReauthenticationRequired)));
    assert_eq!((attempts.get(), steps.get()), (2, 1));
}

#[tokio::test]
async fn a_failed_step_up_ends_the_request_without_retrying() {
    let attempts = Cell::new(0);
    let result: Result<(), _> = retry_after_step_up(
        || async {
            attempts.set(attempts.get() + 1);
            Err(CoreError::ReauthenticationRequired)
        },
        || async { Err(CoreError::AuthFailed("cancelled".into())) },
    )
    .await;
    assert!(matches!(result, Err(CoreError::AuthFailed(_))));
    assert_eq!(attempts.get(), 1);
}
