#![cfg(test)]

use super::*;
use yadorilink_replica_domain::ids::DeltaHash;

#[test]
fn pending_batch_request_id_is_order_independent_and_content_sensitive() {
    let a = DeltaHash([1u8; 32]);
    let b = DeltaHash([2u8; 32]);
    assert_eq!(
        pending_batch_request_id("g", "d", &[a, b]),
        pending_batch_request_id("g", "d", &[b, a]),
        "order of the pending set must not change the derived request_id"
    );
    assert_ne!(
        pending_batch_request_id("g", "d", &[a]),
        pending_batch_request_id("g", "d", &[a, b]),
        "a different pending set must derive a different request_id"
    );
    assert_ne!(
        pending_batch_request_id("g1", "d", &[a]),
        pending_batch_request_id("g2", "d", &[a]),
        "different groups must never collide"
    );
}
