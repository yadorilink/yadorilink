#![cfg(test)]

//! A sync that replaces a version whose bytes are only in the user's file: keeping the version
//! means reading the file into the block store, which needs room. With none, an unprotected
//! version is not kept (the replacement goes on and the gap is recorded); a protected version is
//! never given up (the replacement waits for space like any write). Nothing else is removed.
//!
//! The volume's free space is the executor's test seam against an enforced headroom, as in the
//! receive disk-pressure sequence. Each test reads the index and the store, not the code that
//! decides.

use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_sync_sqlite::file_index::upsert_file_in_tx;
use yadorilink_sync_sqlite::history_freed::FreedReason;
use yadorilink_sync_sqlite::retention::Retention;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::receive_cost_tests::{content_of, fixture, Fixture, GROUP};

const MIB: u64 = 1024 * 1024;

fn record(path: &str, content: &[u8], mtime: i64) -> FileRecord {
    let hash = hex::decode(yadorilink_local_storage::hash_block_bytes(content)).unwrap();
    FileRecord {
        path: path.into(),
        size: content.len() as u64,
        mtime_unix_nanos: mtime,
        blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
        deleted: false,
    }
}

fn index_own_edit(f: &Fixture, record: &FileRecord) {
    f.state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, GROUP, record, "device-local", Retention::OwnEdit)
        })
        .unwrap();
}

/// A path with an older version (kept) and a current one whose bytes are only in the user's file.
struct Scene {
    path: &'static str,
    older: FileRecord,
    current: FileRecord,
    next: FileRecord,
}

fn scene(f: &Fixture) -> Scene {
    let path = "doc.bin";
    let older = record(path, &content_of(3000, 1), 1);
    let current = record(path, &content_of(3000, 2), 2);
    let next = record(path, &content_of(3000, 3), 3);
    index_own_edit(f, &older);
    index_own_edit(f, &current);
    std::fs::write(f.root.join(path), content_of(3000, 2)).unwrap();
    Scene { path, older, current, next }
}

fn space(f: &Fixture, available: u64) {
    f.executor.set_headroom_enforced_for_tests(true);
    f.executor.set_headroom_override_bytes_for_tests(Some(1 << 30));
    *f.executor.fake_available_bytes.lock().unwrap() = Some(available);
}

fn in_store(f: &Fixture, record: &FileRecord) -> bool {
    let hex_hash = hex::encode(&record.blocks[0].hash);
    f.state.block_store.present_blocks(&[hex_hash]).unwrap()[0]
}

fn versions(f: &Fixture, path: &str) -> Vec<(i64, String)> {
    f.state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT version_seq, state FROM files WHERE group_id = ?1 AND path = ?2 \
                 ORDER BY version_seq",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![GROUP, path], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .unwrap()
}

fn freed(f: &Fixture, path: &str) -> Vec<yadorilink_sync_sqlite::history_freed::FreedSpan> {
    f.state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            Ok(yadorilink_sync_sqlite::history_freed::spans_by_path(conn, GROUP)?
                .remove(path)
                .unwrap_or_default())
        })
        .unwrap()
}

async fn replace_by_sync(f: &Fixture, scene: &Scene) -> Result<(), SyncSqliteError> {
    let proofs = f.executor.proofs_before_replacing(GROUP, &scene.next).await.expect("a proof");
    f.state.replica_coordinator.database().write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_in_tx(tx, GROUP, &scene.next, "device-peer", Retention::Proofs(&proofs))
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_room_the_replaced_version_is_read_into_the_store_and_kept() {
    let f = fixture(false).await;
    let scene = scene(&f);
    space(&f, u64::MAX / 2);
    assert!(!in_store(&f, &scene.current));

    replace_by_sync(&f, &scene).await.unwrap();

    assert!(in_store(&f, &scene.current), "the bytes were kept");
    assert_eq!(
        versions(&f, scene.path),
        vec![(1, "superseded".into()), (2, "superseded".into()), (3, "current".into())]
    );
    assert!(freed(&f, scene.path).is_empty(), "nothing was given up");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_room_an_unprotected_version_is_given_up_and_the_sync_goes_on() {
    let f = fixture(false).await;
    let scene = scene(&f);
    space(&f, MIB);

    // The replacement is not held back: it commits.
    replace_by_sync(&f, &scene).await.unwrap();

    assert!(!in_store(&f, &scene.current), "no byte was added to a full disk");
    assert!(!in_store(&f, &scene.older));
    // The older version stays (as it was); the replaced one has no row; the new one is current.
    assert_eq!(versions(&f, scene.path), vec![(1, "superseded".into()), (3, "current".into())]);
    let spans = freed(&f, scene.path);
    assert_eq!(spans.len(), 1, "one event, one row: {spans:?}");
    assert_eq!(spans[0].reason, FreedReason::LowSpace);
    assert_eq!((spans[0].from_seq, spans[0].to_seq), (2, 3));
    // Asking for the given-up version by number says why it is gone.
    let why = f
        .state
        .replica_coordinator
        .file_index_repository()
        .version_not_kept(GROUP, scene.path, 2)
        .unwrap()
        .expect("the version was given up");
    assert_eq!(why.reason, FreedReason::LowSpace);
    let kept = f
        .state
        .replica_coordinator
        .file_index_repository()
        .version_not_kept(GROUP, scene.path, 1)
        .unwrap();
    assert!(kept.is_none(), "the older version is still kept");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_room_a_pinned_version_is_never_given_up_and_waits_like_any_write() {
    let f = fixture(false).await;
    let scene = scene(&f);
    f.state.replica_coordinator.retention_rules().pin(GROUP, scene.path).unwrap();
    space(&f, MIB);

    let refused = f.executor.proofs_before_replacing(GROUP, &scene.next).await;

    assert!(
        matches!(refused, Err(yadorilink_peer_session::PeerSessionError::DiskPressure { .. })),
        "{refused:?}"
    );
    assert!(!in_store(&f, &scene.current));
    assert_eq!(versions(&f, scene.path), vec![(1, "superseded".into()), (2, "current".into())]);
    assert!(freed(&f, scene.path).is_empty());

    // The space returns: the same replacement proceeds and keeps the version.
    space(&f, u64::MAX / 2);
    replace_by_sync(&f, &scene).await.unwrap();
    assert!(in_store(&f, &scene.current));
    assert!(freed(&f, scene.path).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_room_a_version_named_by_a_lease_is_never_given_up() {
    let f = fixture(false).await;
    let scene = scene(&f);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    f.state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO handoff_leases (lease_id, group_id, root_digest, state, \
                 pinned_versions_json, created_at_unix, expires_at_unix) \
                 VALUES ('l', ?1, zeroblob(32), 'confirmed', ?2, ?3, ?4)",
                rusqlite::params![GROUP, format!("[[\"{}\",2]]", scene.path), now, now + 3600],
            )?;
            Ok(())
        })
        .unwrap();
    space(&f, MIB);

    let refused = f.executor.proofs_before_replacing(GROUP, &scene.next).await;

    assert!(
        matches!(refused, Err(yadorilink_peer_session::PeerSessionError::DiskPressure { .. })),
        "{refused:?}"
    );
    assert_eq!(versions(&f, scene.path), vec![(1, "superseded".into()), (2, "current".into())]);
    assert!(freed(&f, scene.path).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_already_in_the_store_needs_no_room() {
    let f = fixture(false).await;
    let scene = scene(&f);
    f.state.block_store.put(&content_of(3000, 2)).unwrap();
    f.state
        .replica_coordinator
        .record_block_provenance(GROUP, &[scene.current.blocks[0].hash.clone()])
        .unwrap();
    space(&f, MIB);

    replace_by_sync(&f, &scene).await.unwrap();

    assert_eq!(versions(&f, scene.path).len(), 3, "kept, as the bytes were already held");
    assert!(freed(&f, scene.path).is_empty());
}
