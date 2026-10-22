#![cfg(test)]

use super::*;

/// A minimal schema covering only what these tests touch
/// (`block_fetch_refusals`) -- `yadorilink_sqlite_runtime::init_schema`
/// itself assumes a sibling schema-init call already created `changes`/
/// `pruned_changes` (see that function's own doc comment), which these
/// tests have no need for. Kept byte-identical to the `CREATE TABLE`
/// in `yadorilink-sqlite-runtime/src/schema.rs`.
fn open_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS block_fetch_refusals (
                    group_id              TEXT NOT NULL,
                    path                  TEXT NOT NULL,
                    version_hash          TEXT NOT NULL,
                    peer_device_id        TEXT NOT NULL,
                    reason                TEXT NOT NULL,
                    refused_at_unix_nanos INTEGER NOT NULL,
                    PRIMARY KEY (group_id, path, version_hash, peer_device_id)
                );",
            )
            .map_err(yadorilink_sqlite_runtime::DatabaseError::from)
        })
        .expect("open in-memory db"),
    )
}

/// The false-positive scenario the version binding rules out: a refusal
/// recorded against V1 must never show up as evidence when the query is
/// asked about V2, even for the same `(group_id, path, peer_device_id)`.
#[test]
fn refusal_recorded_against_one_version_is_invisible_to_a_different_version() {
    let repo = MaterializationStateRepository::new(open_test_db());
    let group_id = "group-1";
    let path = "foo.txt";
    let v1 = "version-hash-v1";
    let v2 = "version-hash-v2";
    let peer = "peer-m";

    repo.record_block_fetch_refusal(
        group_id,
        path,
        v1,
        peer,
        "no verified group provenance for this block",
        1000,
    )
    .unwrap();

    assert_eq!(
        repo.refusing_peers_for_path(group_id, path, v1).unwrap(),
        std::collections::HashSet::from([peer.to_string()]),
        "the refused version must see the refusal"
    );
    assert!(
        repo.refusing_peers_for_path(group_id, path, v2).unwrap().is_empty(),
        "a DIFFERENT version of the same path must never inherit another version's refusal \
         evidence"
    );
}

/// A peer that once refused a version but has since successfully
/// delivered it can never be read as still refusing it -- the stale-
/// evidence-invalidation half of the fix.
#[test]
fn clearing_a_refusal_removes_only_that_exact_peer_path_version_row() {
    let repo = MaterializationStateRepository::new(open_test_db());
    let group_id = "group-1";
    let path = "foo.txt";
    let version = "version-hash-v1";
    let refusing_peer = "peer-m";
    let other_refusing_peer = "peer-w";

    repo.record_block_fetch_refusal(
        group_id,
        path,
        version,
        refusing_peer,
        "no verified group provenance for this block",
        1000,
    )
    .unwrap();
    repo.record_block_fetch_refusal(
        group_id,
        path,
        version,
        other_refusing_peer,
        "no verified group provenance for this block",
        1000,
    )
    .unwrap();
    assert_eq!(
        repo.refusing_peers_for_path(group_id, path, version).unwrap().len(),
        2,
        "both refusals must be visible before either is cleared"
    );

    // `refusing_peer` later successfully delivers the block.
    repo.clear_block_fetch_refusal(group_id, path, version, refusing_peer).unwrap();

    let remaining = repo.refusing_peers_for_path(group_id, path, version).unwrap();
    assert_eq!(
        remaining,
        std::collections::HashSet::from([other_refusing_peer.to_string()]),
        "clearing one peer's refusal must not affect a different peer's still-standing \
         refusal for the same path/version"
    );
}

/// Clearing a refusal for one version must never touch a refusal
/// recorded against a DIFFERENT version of the same path/peer -- the
/// two rows are independent by construction (different primary keys),
/// but this pins that invariant explicitly since it is exactly the kind
/// of thing a future schema change could silently break.
#[test]
fn clearing_a_refusal_for_one_version_does_not_affect_a_different_version() {
    let repo = MaterializationStateRepository::new(open_test_db());
    let group_id = "group-1";
    let path = "foo.txt";
    let v1 = "version-hash-v1";
    let v2 = "version-hash-v2";
    let peer = "peer-m";

    repo.record_block_fetch_refusal(
        group_id,
        path,
        v1,
        peer,
        "no verified group provenance for this block",
        1000,
    )
    .unwrap();
    repo.record_block_fetch_refusal(
        group_id,
        path,
        v2,
        peer,
        "no verified group provenance for this block",
        1000,
    )
    .unwrap();

    repo.clear_block_fetch_refusal(group_id, path, v1, peer).unwrap();

    assert!(
        repo.refusing_peers_for_path(group_id, path, v1).unwrap().is_empty(),
        "v1's refusal must be gone"
    );
    assert_eq!(
        repo.refusing_peers_for_path(group_id, path, v2).unwrap(),
        std::collections::HashSet::from([peer.to_string()]),
        "v2's independent refusal must be untouched by clearing v1's"
    );
}
