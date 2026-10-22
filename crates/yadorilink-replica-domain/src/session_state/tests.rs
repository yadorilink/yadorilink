#![cfg(test)]

use super::{EnrollmentKind, MaterializationPolicy, MaterializationState, ProviderKind};
use crate::file::RecordKind;

#[test]
fn persisted_enum_values_are_exact() {
    assert_eq!(EnrollmentKind::from_db_str("create"), EnrollmentKind::Create);
    assert_eq!(EnrollmentKind::from_db_str("join"), EnrollmentKind::Join);
    assert_eq!(MaterializationState::from_db_str("present"), MaterializationState::Present);
    assert_eq!(MaterializationState::from_db_str("remote"), MaterializationState::Remote);
    assert_eq!(MaterializationPolicy::from_db_str("eager"), MaterializationPolicy::Eager);
    assert_eq!(MaterializationPolicy::from_db_str("ondemand"), MaterializationPolicy::OnDemand);
    assert_eq!(RecordKind::from_db_str("file"), RecordKind::File);
}

#[test]
#[should_panic(expected = "unknown persisted materialization state")]
fn unknown_materialization_state_is_not_coerced() {
    let _ = MaterializationState::from_db_str("future-state");
}

#[test]
#[should_panic(expected = "unknown persisted materialization policy")]
fn unknown_materialization_policy_is_not_coerced() {
    let _ = MaterializationPolicy::from_db_str("future-policy");
}

#[test]
#[should_panic(expected = "unknown persisted enrollment kind")]
fn unknown_enrollment_kind_is_not_coerced() {
    let _ = EnrollmentKind::from_db_str("future-kind");
}

#[test]
fn provider_kinds_persist_under_their_exact_names() {
    for (kind, name) in [
        (ProviderKind::None, "none"),
        (ProviderKind::MacFileProvider, "mac_file_provider"),
        (ProviderKind::WindowsCfapi, "windows_cfapi"),
    ] {
        assert_eq!(kind.as_db_str(), name);
        assert_eq!(ProviderKind::from_db_str(name), kind);
    }
}

#[test]
fn the_host_platform_selects_its_own_provider_adapter() {
    let expected = if cfg!(target_os = "macos") {
        Some(ProviderKind::MacFileProvider)
    } else if cfg!(windows) {
        Some(ProviderKind::WindowsCfapi)
    } else {
        None
    };
    assert_eq!(ProviderKind::for_host_platform(), expected);
}
