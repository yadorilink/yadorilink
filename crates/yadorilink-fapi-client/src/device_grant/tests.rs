#![cfg(test)]

use super::*;

#[test]
fn an_absent_interval_is_the_specifications_five_seconds_rather_than_zero() {
    let authorization = DeviceAuthorization {
        device_code: "dc".into(),
        user_code: "AAAA-BBBB-CCCC".into(),
        verification_uri: "https://as.test/device".into(),
        verification_uri_complete: None,
        expires_in: 600,
        interval: None,
    };
    assert_eq!(authorization.poll_interval(), Duration::from_secs(5));
}

/// A zero from the server would otherwise become a hot loop against the
/// token endpoint, which is the one thing `slow_down` exists to stop.
#[test]
fn a_zero_interval_is_clamped_rather_than_spun_on() {
    let authorization = DeviceAuthorization {
        device_code: "dc".into(),
        user_code: "AAAA-BBBB-CCCC".into(),
        verification_uri: "https://as.test/device".into(),
        verification_uri_complete: None,
        expires_in: 600,
        interval: Some(0),
    };
    assert_eq!(authorization.poll_interval(), Duration::from_secs(1));
}

const COMPLETE: &str = "https://as.test/device?user_code=AAAA-BBBB-CCCC";

fn authorization(complete: Option<&str>) -> DeviceAuthorization {
    DeviceAuthorization {
        device_code: "dc".into(),
        user_code: "AAAA-BBBB-CCCC".into(),
        verification_uri: "https://as.test/device".into(),
        verification_uri_complete: complete.map(str::to_owned),
        expires_in: 600,
        interval: Some(5),
    }
}

/// With the completed URI the user opens ONE link and only compares the code;
/// nothing is typed.
#[test]
fn the_printed_instructions_use_the_completed_uri_and_show_the_code_to_compare() {
    let printed = authorization(Some(COMPLETE)).instructions();
    assert_eq!(
        printed,
        "To finish signing in, open this link on any device (your phone is fine) and check that \
         the code shown there matches:\n\n  https://as.test/device?user_code=AAAA-BBBB-CCCC\n\n  \
         Code: AAAA-BBBB-CCCC\n"
    );
    assert!(!printed.contains("enter this code"));
}

/// A server that sends no completed URI gets the two-part message.
#[test]
fn the_printed_instructions_fall_back_to_typing_the_code_without_a_completed_uri() {
    let printed = authorization(None).instructions();
    assert!(printed.contains("open https://as.test/device on any device and enter this code"));
    assert!(printed.contains("AAAA-BBBB-CCCC"));
    assert!(!printed.contains("user_code="));
}

fn granted() -> DevicePoll {
    let body = r#"{"access_token":"at","token_type":"DPoP","expires_in":300,"refresh_token":"rt","scope":"openid offline_access"}"#;
    DevicePoll::Granted(Box::new(FapiClient::accept_token_body(body, "test").expect("token")))
}

/// Runs the polling rules over a scripted token endpoint, returning the waits
/// between consecutive polls (virtual time) and the outcome.
async fn run_script(
    expires_in: u64,
    script: Vec<DevicePoll>,
) -> (Vec<Duration>, Result<TokenResponse>) {
    let mut authorization = authorization(None);
    authorization.expires_in = expires_in;
    authorization.interval = Some(5);
    let script = std::sync::Mutex::new(script.into_iter());
    let polled_at = std::sync::Mutex::new(vec![tokio::time::Instant::now()]);
    let outcome = poll_until_granted(&authorization, || {
        polled_at.lock().unwrap().push(tokio::time::Instant::now());
        let next = script.lock().unwrap().next().expect("polled past the script");
        async move { Ok(next) }
    })
    .await;
    let times = polled_at.into_inner().unwrap();
    (times.windows(2).map(|w| w[1] - w[0]).collect(), outcome)
}

/// RFC 8628 section 3.5: the interval grows by five seconds on every
/// `slow_down` and never shrinks back, `authorization_pending` included.
#[tokio::test(start_paused = true)]
async fn slow_down_twice_then_pending_then_success_only_ever_widens_the_interval() {
    let (waits, outcome) = run_script(
        600,
        vec![DevicePoll::SlowDown, DevicePoll::SlowDown, DevicePoll::Pending, granted()],
    )
    .await;
    outcome.expect("granted");
    let secs: Vec<u64> = waits.iter().map(Duration::as_secs).collect();
    assert_eq!(secs, [5, 10, 15, 15], "waits before each poll");
}

#[tokio::test(start_paused = true)]
async fn an_authorization_that_runs_out_ends_with_the_typed_expiry_not_more_polling() {
    let (waits, outcome) =
        run_script(12, std::iter::repeat_with(|| DevicePoll::Pending).take(10).collect()).await;
    assert!(matches!(outcome, Err(Error::DeviceAuthorizationExpired)), "{outcome:?}");
    assert!(waits.len() <= 3, "polling stopped at the deadline: {waits:?}");
}
