#![cfg(test)]

use yadorilink_replica_engine::conflict::{
    resolve_path_heads, ConflictCopy, PathHead, PathHeadContent, PathResolution,
};

fn content_head(hash_byte: u8, lamport: u64, device: &str, mtime: i64) -> PathHead {
    PathHead {
        change_hash: [hash_byte; 32],
        rank: lamport,
        device_id: device.to_string(),
        naming_device_id: device.to_string(),
        content: Some(PathHeadContent { version_hash: [hash_byte; 32], mtime_unix_nanos: mtime }),
    }
}

fn tombstone_head(hash_byte: u8, lamport: u64, device: &str) -> PathHead {
    PathHead {
        change_hash: [hash_byte; 32],
        rank: lamport,
        device_id: device.to_string(),
        naming_device_id: device.to_string(),
        content: None,
    }
}

#[test]
fn single_content_head_holds_the_path() {
    let heads = [content_head(1, 3, "device-a", 100)];
    assert_eq!(
        resolve_path_heads("f.txt", &heads),
        PathResolution::Present { winner: 0, conflict_copies: vec![] }
    );
}

#[test]
fn single_tombstone_leaves_the_path_absent() {
    let heads = [tombstone_head(1, 3, "device-a")];
    assert_eq!(resolve_path_heads("f.txt", &heads), PathResolution::Absent);
}

#[test]
fn concurrent_content_keeps_higher_version_and_conflicts_the_loser() {
    // The higher version (head 1) keeps the name; head 0 stands at its copy path.
    let heads = [content_head(1, 5, "device-a", 100), content_head(2, 7, "device-b", 200)];
    match resolve_path_heads("report.docx", &heads) {
        PathResolution::Present { winner, conflict_copies } => {
            assert_eq!(winner, 1);
            assert_eq!(conflict_copies.len(), 1);
            assert_eq!(conflict_copies[0].head, 0);
            assert!(conflict_copies[0].path.starts_with("report (conflicted copy"));
            assert_eq!(
                conflict_copies[0].path,
                yadorilink_replica_domain::native_fork::copy_path(
                    "report.docx",
                    &yadorilink_replica_domain::ids::VersionHash([1; 32])
                ),
                "the copy is named by the path and the losing version alone"
            );
            assert!(conflict_copies[0].path.ends_with(".docx"));
        }
        other => panic!("expected Present, got {other:?}"),
    }
}

#[test]
fn resolution_is_independent_of_head_order() {
    let a = content_head(0xAA, 5, "device-a", 100);
    let b = content_head(0xBB, 5, "device-b", 200);
    let forward = resolve_path_heads("f.bin", &[a.clone(), b.clone()]);
    let reversed = resolve_path_heads("f.bin", &[b, a]);
    // Same winning *content* and same conflict-copy *name* regardless of
    // the order the heads were presented in — the commutativity the SEC
    // suite relies on. (Winner index flips with the reordering; the
    // materialized path/name does not.)
    let name = |r: &PathResolution| match r {
        PathResolution::Present { conflict_copies, .. } => conflict_copies[0].path.clone(),
        PathResolution::Absent => "<absent>".to_string(),
    };
    assert_eq!(name(&forward), name(&reversed));
}

#[test]
fn content_beats_a_concurrent_tombstone() {
    // A delete concurrent with an edit: the content survives, the
    // tombstone is acknowledged without producing a conflict copy.
    let heads = [content_head(1, 4, "device-a", 100), tombstone_head(2, 6, "device-b")];
    assert_eq!(
        resolve_path_heads("f.txt", &heads),
        PathResolution::Present { winner: 0, conflict_copies: vec![] }
    );
}

#[test]
fn three_way_content_conflict_yields_two_copies() {
    let heads = [
        content_head(1, 5, "device-a", 100),
        content_head(2, 5, "device-b", 200),
        content_head(3, 5, "device-c", 300),
    ];
    match resolve_path_heads("f.txt", &heads) {
        PathResolution::Present { winner, conflict_copies } => {
            // Equal lamports -> highest change hash (0x03) wins.
            assert_eq!(winner, 2);
            let mut losers: Vec<ConflictCopy> = conflict_copies;
            losers.sort_by_key(|c| c.head);
            assert_eq!(losers.iter().map(|c| c.head).collect::<Vec<_>>(), vec![0, 1]);
        }
        other => panic!("expected Present, got {other:?}"),
    }
}

fn content_head_vh(change: u8, lamport: u64, device: &str, version_hash: u8) -> PathHead {
    PathHead {
        change_hash: [change; 32],
        rank: lamport,
        device_id: device.to_string(),
        naming_device_id: device.to_string(),
        content: Some(PathHeadContent { version_hash: [version_hash; 32], mtime_unix_nanos: 0 }),
    }
}

#[test]
fn identical_content_heads_collapse_without_a_conflict_copy() {
    // Two concurrent heads with distinct change identities but the SAME
    // content (version hash) are one equivalence class — no conflict copy.
    let heads = [content_head_vh(1, 5, "device-a", 9), content_head_vh(2, 5, "device-b", 9)];
    match resolve_path_heads("f.txt", &heads) {
        PathResolution::Present { conflict_copies, .. } => {
            assert!(
                conflict_copies.is_empty(),
                "byte-identical content must not produce a conflict copy: {conflict_copies:?}"
            );
        }
        other => panic!("expected Present, got {other:?}"),
    }
}

#[test]
fn one_conflict_copy_per_distinct_content_class() {
    // Winner class (vh 9) + two heads of class vh 7 + one of class vh 5:
    // exactly two copies (one per losing class), not three.
    let heads = [
        content_head_vh(10, 9, "d", 9), // winner (highest lamport)
        content_head_vh(1, 5, "a", 7),
        content_head_vh(2, 5, "b", 7),
        content_head_vh(3, 5, "c", 5),
    ];
    match resolve_path_heads("f.txt", &heads) {
        PathResolution::Present { winner, conflict_copies } => {
            assert_eq!(winner, 0);
            assert_eq!(
                conflict_copies.len(),
                2,
                "one conflict copy per losing content class: {conflict_copies:?}"
            );
        }
        other => panic!("expected Present, got {other:?}"),
    }
}
