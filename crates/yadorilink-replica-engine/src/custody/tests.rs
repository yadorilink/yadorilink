#![cfg(test)]

use super::*;

fn version() -> (VersionHash, Vec<VersionBlock>) {
    use yadorilink_replica_domain::ids::BlockHash;
    (VersionHash([7; 32]), vec![VersionBlock { hash: BlockHash(vec![3; 32]), size: 9 }])
}

#[test]
fn verifier_fails_closed_without_positive_exact_version_confirmation() {
    let (version_hash, blocks) = version();
    let rejecting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| false;
    assert!(verify_reclaim_custody_for_test(&rejecting, "group", "file", &version_hash, &blocks)
        .is_none());
}

#[test]
fn verifier_binds_token_to_the_confirmed_identity() {
    let (version_hash, blocks) = version();
    let exact = |group: &str,
                 path: &str,
                 candidate_hash: &VersionHash,
                 candidate_blocks: &[VersionBlock]| {
        group == "group"
            && path == "file"
            && candidate_hash == &version_hash
            && candidate_blocks == blocks
    };
    let verified =
        verify_reclaim_custody_for_test(&exact, "group", "file", &version_hash, &blocks).unwrap();

    assert_eq!(verified.group_id(), "group");
    assert_eq!(verified.path(), "file");
    assert_eq!(verified.version_hash(), &version_hash);
    assert_eq!(verified.blocks(), blocks);
    assert!(verified.confirmation_still_valid());
    assert!(verify_reclaim_custody_for_test(&exact, "group", "other-file", &version_hash, &blocks)
        .is_none());
}

/// With the flag on, the production verifier defers to the oracle (the stamped, lease-backed
/// confirmation) and fails closed when it says no.
#[test]
fn production_verifier_defers_to_the_oracle_and_fails_closed() {
    let (version_hash, blocks) = version();
    let accepting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| true;
    let rejecting = |_: &str, _: &str, _: &VersionHash, _: &[VersionBlock]| false;
    assert!(verify_reclaim_custody(&accepting, "group", "file", &version_hash, &blocks).is_some());
    assert!(verify_reclaim_custody(&rejecting, "group", "file", &version_hash, &blocks).is_none());
}
