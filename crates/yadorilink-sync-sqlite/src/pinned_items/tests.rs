#![cfg(test)]

use std::sync::Arc;

use yadorilink_sqlite_runtime::{DatabaseError, SyncDatabase};

use super::*;

fn schema_init(conn: &rusqlite::Connection) -> Result<(), DatabaseError> {
    // The full schema: a pin also republishes provider items, which reads the provider tables.
    crate::replica_tables::init_for_tests(conn)
        .map_err(|e| DatabaseError::CorruptSchema(e.to_string()))?;
    yadorilink_sqlite_runtime::init_schema(conn)?;
    init_pinned_items_schema(conn).map_err(|e| DatabaseError::CorruptSchema(e.to_string()))
}

fn in_memory() -> Arc<SyncDatabase> {
    Arc::new(SyncDatabase::open_in_memory(schema_init).expect("open in-memory db"))
}

fn pinned(repo: &PinnedItemRepository, group: &str, path: &str) -> bool {
    repo.retention(group, path).unwrap().policy == RetentionPolicy::Pinned
}

#[test]
fn a_pin_covers_itself_and_its_subtree_but_not_a_sibling_sharing_its_prefix() {
    let pins = vec!["dir".to_string(), "notes.txt".to_string()];
    assert!(path_is_covered(&pins, "dir"));
    assert!(path_is_covered(&pins, "dir/a.txt"));
    assert!(path_is_covered(&pins, "dir/sub/b.txt"));
    assert!(path_is_covered(&pins, "notes.txt"));
    assert!(!path_is_covered(&pins, "dir2/a.txt"));
    assert!(!path_is_covered(&pins, "dir.txt"));
    assert!(!path_is_covered(&pins, "notes.txt.bak"));
    assert!(!path_is_covered(&pins, "other/dir/a.txt"));
    assert!(path_is_covered(&[String::new()], "anything/at/all.txt"), "the root covers all");
    assert!(!path_is_covered(&[], "dir/a.txt"));
}

#[test]
fn retention_is_reclaimable_until_pinned_and_reports_whether_the_pin_is_explicit() {
    let repo = PinnedItemRepository::new(in_memory());
    assert_eq!(
        repo.retention("g", "dir/a.txt").unwrap(),
        Retention { policy: RetentionPolicy::Reclaimable, explicit: false }
    );
    repo.pin("g", "dir").unwrap();
    assert_eq!(
        repo.retention("g", "dir").unwrap(),
        Retention { policy: RetentionPolicy::Pinned, explicit: true }
    );
    assert_eq!(
        repo.retention("g", "dir/a.txt").unwrap(),
        Retention { policy: RetentionPolicy::Pinned, explicit: false },
        "a descendant inherits, also one that did not exist when the folder was pinned"
    );
    assert!(!pinned(&repo, "g", "dir2/a.txt"));
    assert!(!pinned(&repo, "other-group", "dir/a.txt"), "a pin belongs to its group");
}

#[test]
fn a_pin_survives_reopening_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    {
        let database = Arc::new(SyncDatabase::open(&path, schema_init).unwrap());
        PinnedItemRepository::new(database).pin("g", "dir").unwrap();
    }
    let database = Arc::new(SyncDatabase::open(&path, schema_init).unwrap());
    let repo = PinnedItemRepository::new(database);
    assert_eq!(repo.list("g").unwrap(), vec!["dir".to_string()]);
    assert!(pinned(&repo, "g", "dir/deep/file.txt"));
    assert!(repo.unpin("g", "dir").unwrap(), "unpin reports that the item was pinned");
    assert!(!pinned(&repo, "g", "dir/deep/file.txt"));
    assert!(!repo.unpin("g", "dir").unwrap(), "unpinning an unpinned item is a no-op");
}

#[test]
fn pinning_twice_keeps_one_row() {
    let repo = PinnedItemRepository::new(in_memory());
    repo.pin("g", "a").unwrap();
    repo.pin("g", "a").unwrap();
    assert_eq!(repo.list("g").unwrap(), vec!["a".to_string()]);
}

/// There are no per-child overrides: a path covered only by an ancestor stays
/// pinned when "unpinned" by itself, and a child pin outlives its ancestor's.
#[test]
fn unpin_removes_only_the_pin_set_at_that_exact_path() {
    let repo = PinnedItemRepository::new(in_memory());
    repo.pin("g", "dir").unwrap();
    assert!(!repo.unpin("g", "dir/a.txt").unwrap(), "nothing was set at the child");
    assert!(pinned(&repo, "g", "dir/a.txt"), "the ancestor's pin still covers it");

    repo.pin("g", "dir/keep.txt").unwrap();
    assert!(repo.unpin("g", "dir").unwrap());
    assert!(!pinned(&repo, "g", "dir/a.txt"));
    assert!(pinned(&repo, "g", "dir/keep.txt"), "the child's own pin is untouched");
}

#[test]
fn pinned_beneath_lists_strict_descendants_only() {
    let repo = PinnedItemRepository::new(in_memory());
    for p in ["dir", "dir/a.txt", "dir/sub/b.txt", "dir2/c.txt", "dirx"] {
        repo.pin("g", p).unwrap();
    }
    repo.pin("other", "dir/z.txt").unwrap();
    assert_eq!(
        repo.pinned_beneath("g", "dir").unwrap(),
        vec!["dir/a.txt".to_string(), "dir/sub/b.txt".to_string()]
    );
    assert_eq!(repo.pinned_beneath("g", "").unwrap().len(), 5, "beneath the root is every item");
}
