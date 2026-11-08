#![cfg(test)]

//! `get_file_shared` answers exactly what `get_file` does, decodes a path's block list once while its
//! stored text is unchanged, and never answers from an older list.

use super::*;
use yadorilink_replica_domain::file::BlockInfo;

const GROUP: &str = "g";

fn repo() -> FileIndexRepository {
    FileIndexRepository::new(crate::replica_tables::open_for_tests())
}

fn blocks(count: u8) -> Vec<BlockInfo> {
    (0..count)
        .map(|i| BlockInfo { hash: vec![i; 32], offset: u64::from(i) * 100, size: 100 })
        .collect()
}

fn put(repo: &FileIndexRepository, path: &str, blocks: Vec<BlockInfo>, deleted: bool) {
    let record = FileRecord {
        path: path.into(),
        size: blocks.iter().map(|b| u64::from(b.size)).sum(),
        mtime_unix_nanos: 1,
        blocks,
        deleted,
    };
    repo.database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, GROUP, &record, "device-a", crate::retention::Retention::OwnEdit)
        })
        .unwrap();
}

#[test]
fn the_shared_record_is_the_plain_record() {
    let repo = repo();
    put(&repo, "a", blocks(5), false);
    let plain = repo.get_file(GROUP, "a").unwrap().unwrap();
    let shared = repo.get_file_shared(GROUP, "a").unwrap().unwrap();
    assert_eq!(*shared.blocks, plain.blocks);
    assert_eq!(shared.size, plain.size);
    assert_eq!(shared.mtime_unix_nanos, plain.mtime_unix_nanos);
    assert_eq!(shared.deleted, plain.deleted);
    assert!(repo.get_file_shared(GROUP, "missing").unwrap().is_none());
}

#[test]
fn an_unchanged_row_is_decoded_once() {
    let repo = repo();
    put(&repo, "a", blocks(5), false);
    let first = repo.get_file_shared(GROUP, "a").unwrap().unwrap();
    let second = repo.get_file_shared(GROUP, "a").unwrap().unwrap();
    assert!(Arc::ptr_eq(&first.blocks, &second.blocks), "the second lookup decoded the list again");
}

#[test]
fn a_changed_block_list_is_never_answered_from_the_older_one() {
    let repo = repo();
    put(&repo, "a", blocks(5), false);
    let old = repo.get_file_shared(GROUP, "a").unwrap().unwrap();
    put(&repo, "a", blocks(3), false);
    let new = repo.get_file_shared(GROUP, "a").unwrap().unwrap();
    assert_eq!(old.blocks.len(), 5);
    assert_eq!(new.blocks.len(), 3);
    assert!(!Arc::ptr_eq(&old.blocks, &new.blocks));
}

#[test]
fn a_deleted_row_is_reported_deleted() {
    let repo = repo();
    put(&repo, "a", blocks(2), false);
    assert!(!repo.get_file_shared(GROUP, "a").unwrap().unwrap().deleted);
    put(&repo, "a", blocks(2), true);
    assert!(repo.get_file_shared(GROUP, "a").unwrap().unwrap().deleted);
}

#[test]
fn the_cache_is_bounded_and_every_path_still_answers() {
    let repo = repo();
    for i in 0..(BLOCK_LIST_CACHE_PATHS + 20) {
        put(&repo, &format!("p{i}"), blocks(2), false);
    }
    for i in 0..(BLOCK_LIST_CACHE_PATHS + 20) {
        let record = repo.get_file_shared(GROUP, &format!("p{i}")).unwrap().unwrap();
        assert_eq!(record.blocks.len(), 2);
    }
    assert!(repo.block_lists.lock().unwrap().entries.len() <= BLOCK_LIST_CACHE_PATHS);
}

#[test]
fn a_corrupt_stored_list_still_fails_closed() {
    let repo = repo();
    put(&repo, "a", blocks(2), false);
    repo.database()
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute("UPDATE files SET blocks_json = 'not json' WHERE path = 'a'", [])?;
            Ok(())
        })
        .unwrap();
    assert!(repo.get_file_shared(GROUP, "a").is_err());
}
