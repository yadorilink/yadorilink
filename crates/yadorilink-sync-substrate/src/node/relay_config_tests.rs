#![cfg(test)]

use super::*;

/// Relaying is delegated; discovering who to relay to is not.
///
/// `RelayMode::Default` uses Iroh's relay infrastructure. The `N0` preset
/// would also publish this node's address to n0's pkarr/DNS service and
/// resolve peers from it — which would make reachability depend on
/// third-party infrastructure and leak every node's address to it. The
/// endpoint is built on `presets::Minimal` for exactly that reason, and
/// this asserts the two are configured independently.
#[test]
fn the_production_default_relays_through_iroh_and_discovers_through_neither() {
    assert!(matches!(NetworkConfig::iroh_default_relays().relay_mode(), iroh::RelayMode::Default));
}

/// An empty relay configuration means "not configured", not "turn relaying
/// off". Reading it as the latter would silently strip a deployment's
/// fallback path, which surfaces much later as unreachable peers.
#[test]
fn an_empty_configuration_keeps_the_default_rather_than_disabling_relays() {
    let (config, rejected) = NetworkConfig::from_relay_urls(["", "  "]);
    assert!(rejected.is_empty());
    assert!(matches!(config.relay_mode(), iroh::RelayMode::Default));
}

/// Choosing relays explicitly is the same abstraction, which is what makes
/// moving off the public ones a configuration change rather than a
/// redesign.
#[test]
fn a_configured_relay_set_replaces_the_default() {
    let (config, rejected) = NetworkConfig::from_relay_urls(["https://relay.example/", "  "]);
    assert!(rejected.is_empty());
    assert!(matches!(config.relay_mode(), iroh::RelayMode::Custom(_)));
}

#[test]
fn direct_only_really_is_direct_only() {
    assert!(matches!(NetworkConfig::direct_only().relay_mode(), iroh::RelayMode::Disabled));
}

/// An unparsable relay is reported rather than dropped: silently ignoring
/// a mistyped one leaves a deployment believing it has a fallback it does
/// not have.
#[test]
fn an_unparsable_relay_is_reported() {
    let (_, rejected) = NetworkConfig::from_relay_urls(["not a url"]);
    assert_eq!(rejected, vec!["not a url".to_string()]);
}
