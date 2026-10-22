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
