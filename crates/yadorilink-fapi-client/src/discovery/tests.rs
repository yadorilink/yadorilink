#![cfg(test)]

use super::*;

fn deployed() -> Metadata {
    Metadata::deployed_profile("https://as.test")
}

#[test]
fn the_deployed_profile_has_nothing_unmet() {
    assert_eq!(deployed().unmet_profile_requirements(), Vec::<String>::new());
}

/// The behaviour this replaced: an absent list used to be read as
/// "unknown, probably fine".
#[test]
fn an_absent_capability_list_is_unmet_rather_than_unknown() {
    let mut metadata = deployed();
    metadata.dpop_signing_alg_values_supported.clear();
    let unmet = metadata.unmet_profile_requirements();
    assert_eq!(unmet.len(), 1, "got {unmet:?}");
    assert!(unmet[0].starts_with("dpop_signing_alg_values_supported:"), "got {unmet:?}");
}

#[test]
fn a_deployment_offering_neither_half_of_the_device_grant_is_coherent() {
    let metadata = deployed();
    assert!(metadata.unmet_profile_requirements().is_empty());
    assert!(!metadata.supports_device_grant());
}

#[test]
fn a_deployment_offering_both_halves_of_the_device_grant_is_coherent() {
    let mut metadata = deployed();
    metadata.device_authorization_endpoint = Some("https://as.test/device/auth".to_owned());
    metadata.grant_types_supported.push(crate::DEVICE_CODE_GRANT.to_owned());
    assert!(metadata.unmet_profile_requirements().is_empty());
    assert!(metadata.supports_device_grant());
}
