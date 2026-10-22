#![cfg(test)]

use super::PeerId;

#[test]
fn hex_round_trips() {
    let id = PeerId::from_bytes([7u8; 32]);
    assert_eq!(PeerId::from_hex(&id.to_hex()), Some(id));
}

#[test]
fn malformed_hex_is_rejected() {
    assert_eq!(PeerId::from_hex(""), None);
    assert_eq!(PeerId::from_hex(&"z".repeat(64)), None);
    assert_eq!(PeerId::from_hex(&"a".repeat(63)), None);
    assert_eq!(PeerId::from_hex(&"a".repeat(65)), None);
}
