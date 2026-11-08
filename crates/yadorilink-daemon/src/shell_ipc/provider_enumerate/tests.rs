#![cfg(test)]

use super::*;

/// A cursor is valid only for the root and the folder that issued it: another root, another folder
/// or another kind of cursor is refused, and nothing is misread.
#[test]
fn a_page_token_is_bound_to_its_root_its_scope_and_its_kind() {
    let token = encode_token(CHILDREN_TAG, 7, b"root-a", b"folder", b"last/path");
    assert_eq!(
        decode_token(CHILDREN_TAG, &token, b"root-a", b"folder"),
        Some((7, b"last/path".to_vec()))
    );
    assert!(decode_token(CHILDREN_TAG, &token, b"root-b", b"folder").is_none(), "another root");
    assert!(decode_token(CHILDREN_TAG, &token, b"root-a", b"other").is_none(), "another folder");
    assert!(decode_token(WORKING_SET_TAG, &token, b"root-a", b"folder").is_none(), "another kind");
    assert!(decode_token(CHILDREN_TAG, &token[..5], b"root-a", b"folder").is_none(), "truncated");
    assert!(decode_token(CHILDREN_TAG, b"", b"root-a", b"folder").is_none());
}

/// The provider item carries the same badge a path status would, and a change of the badge changes the
/// metadata identifier the OS is shown (so Finder redraws the item). A file held back needs the person.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_file_is_an_error_badge_and_the_badge_changes_the_metadata_version() {
    use crate::provider_reclaim::tests::{data_of, Fx};
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let item = fx.item("a.bin");
    let coordinator = fx.state.replica_coordinator.clone();
    let shown = |coordinator: &crate::replica_coordinator::ReplicaCoordinator| {
        coordinator.provider_repository().lookup_item(&fx.root, &item).unwrap().unwrap().0
    };

    let before = shown(&coordinator);
    let calm = badges_of(&coordinator, &fx.root, std::slice::from_ref(&before))[0];
    assert_ne!(calm, ShellBadge::Error);

    coordinator
        .materialization_state_repository()
        .set_held(crate::provider_reclaim::tests::GROUP, "a.bin", "case_collision", 5)
        .unwrap();
    let after = shown(&coordinator);
    let held = badges_of(&coordinator, &fx.root, std::slice::from_ref(&after))[0];
    assert_eq!(held, ShellBadge::Error, "a held file is not hidden");

    assert_ne!(
        with_badge(before.metadata_version, calm),
        with_badge(after.metadata_version, held),
        "a changed badge kept the same metadata version"
    );
    assert_eq!(
        with_badge(before.metadata_version, ShellBadge::Unspecified),
        before.metadata_version
    );
    assert_eq!(
        with_badge(before.metadata_version, calm),
        with_badge(before.metadata_version, calm)
    );
}
