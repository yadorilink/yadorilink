#![cfg(test)]

use super::*;

#[test]
fn current_carries_the_reporter_id_only_when_present() {
    let env = current(&ConsentState::default());
    assert!(env.anonymous_reporter_id.is_none());
    assert_eq!(env.yadorilink_version, env!("CARGO_PKG_VERSION"));
    assert!(!env.arch.is_empty());
}
