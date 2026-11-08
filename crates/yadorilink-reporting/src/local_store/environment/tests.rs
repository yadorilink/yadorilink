#![cfg(test)]

use super::*;

#[test]
fn current_carries_the_reporter_id_only_when_present() {
    let env = current(&ConsentState::default());
    assert!(env.anonymous_reporter_id.is_none());
    assert_eq!(env.yadorilink_version, env!("CARGO_PKG_VERSION"));
    assert!(!env.arch.is_empty());
}

#[test]
fn the_bucket_is_the_major_version() {
    assert_eq!(bucket_from_dotted("27.0.1\n").as_deref(), Some("27.x"));
    assert_eq!(bucket_from_dotted("15.6").as_deref(), Some("15.x"));
    assert_eq!(bucket_from_dotted(""), None);
    assert_eq!(bucket_from_dotted("beta"), None);
}

// apple-cfg: macos-only sw_vers; iOS has no such command
#[cfg(target_os = "macos")]
#[test]
fn macos_reports_a_version_bucket() {
    assert_ne!(os_version_bucket(), "unknown");
}

#[test]
fn windows_build_numbers_map_to_the_marketing_major() {
    let ver =
        |v: &str| bucket_from_windows_ver(&format!("\r\nMicrosoft Windows [Version {v}]\r\n"));
    assert_eq!(ver("10.0.26100.1234").as_deref(), Some("11.x"));
    assert_eq!(ver("10.0.19045.5000").as_deref(), Some("10.x"));
    assert_eq!(bucket_from_windows_ver("garbage"), None);
}
