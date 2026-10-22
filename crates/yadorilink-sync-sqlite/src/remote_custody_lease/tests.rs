#![cfg(test)]

use super::*;
use crate::MaterializationStateRepository;

const GROUP: &str = "g";
const REQUESTER: &str = "ondemand-device";
const VERSION: [u8; 32] = [9; 32];
const TOKEN_A: AttemptToken = [0xa1; 16];
const TOKEN_B: AttemptToken = [0xb2; 16];

fn open_file_db(dir: &tempfile::TempDir) -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open(dir.path().join("index.db"), |conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open file-backed db"),
    )
}

fn request(blocks: &[&str]) -> CustodyLeaseRequest {
    CustodyLeaseRequest {
        group_id: GROUP.into(),
        requester_device_id: REQUESTER.into(),
        path: "a.bin".into(),
        version_hash: VERSION,
        blocks: blocks.iter().map(|b| b.to_string()).collect(),
        membership_generation: 3,
        attempt_token: TOKEN_A,
        now_unix: 100,
    }
}

fn request_with(token: AttemptToken, blocks: &[&str]) -> CustodyLeaseRequest {
    CustodyLeaseRequest { attempt_token: token, ..request(blocks) }
}

fn release(repo: &RemoteCustodyLeaseRepository, token: AttemptToken) -> bool {
    repo.release(GROUP, REQUESTER, "a.bin", &VERSION, &token).unwrap()
}

fn live(db: &Arc<SyncDatabase>) -> std::collections::HashSet<String> {
    MaterializationStateRepository::new(db.clone())
        .live_block_hashes_including_native_heads()
        .unwrap()
}

/// A retry of an acquire whose acknowledgement was lost finds the committed
/// lease instead of writing a second one.
#[test]
fn acquire_is_idempotent_and_returns_the_same_lease() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    let first = repo.acquire(&request(&["aa", "bb"])).unwrap();
    assert!(first.was_created());
    let retry = repo.acquire(&request(&["aa", "bb"])).unwrap();
    assert!(!retry.was_created());
    assert_eq!(first.lease(), retry.lease());
    assert_eq!(first.lease().unwrap().attempt_token, TOKEN_A);
    assert_eq!(repo.list_active().unwrap().len(), 1);
}

/// A lease names one exact block set; a different set under the same
/// version identity is refused rather than silently merged.
#[test]
fn a_different_block_set_under_the_same_version_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.acquire(&request(&["aa", "bb"])).unwrap();
    assert!(repo.acquire(&request(&["aa", "cc"])).is_err());
}

/// The lease blocks are in the GC live set the moment the acquire returns,
/// still there after the database is closed and reopened (a responder
/// restart), and stay there when the group's own rows move on.
#[test]
fn leased_blocks_stay_live_across_restart_and_version_advance() {
    let dir = tempfile::tempdir().unwrap();
    let block = hex::encode([0xaau8; 32]);
    {
        let db = open_file_db(&dir);
        let blocks_json = format!(r#"[{{"hash":{:?},"offset":0,"size":4}}]"#, vec![0xaau8; 32]);
        db.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted) \
                 VALUES (?1, 'a.bin', 4, 0, ?2, 0)",
                rusqlite::params![GROUP, blocks_json],
            )?;
            Ok(())
        })
        .unwrap();
        RemoteCustodyLeaseRepository::new(db.clone()).acquire(&request(&[&block])).unwrap();
        // The path advances: its old row, the only other root for the block, goes.
        db.write::<_, SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM files WHERE path = 'a.bin'", [])?;
            Ok(())
        })
        .unwrap();
        assert!(live(&db).contains(&block));
    }
    let reopened = open_file_db(&dir);
    assert!(live(&reopened).contains(&block));
}

/// Only an explicit release ends the lease's hold on its blocks.
#[test]
fn release_ends_the_hold_and_is_repeatable() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let repo = RemoteCustodyLeaseRepository::new(db.clone());
    repo.acquire(&request(&["aa"])).unwrap();
    assert!(live(&db).contains("aa"));
    assert!(release(&repo, TOKEN_A));
    assert!(!live(&db).contains("aa"));
    assert!(!release(&repo, TOKEN_A));
    assert!(repo.find(GROUP, REQUESTER, "a.bin", &VERSION).unwrap().is_none());
}

/// Cache reclamation deletes a block only if nothing else references it; a
/// block leased for another device is such a reference, whichever path or
/// group the evicted file is in.
#[test]
fn cache_reclamation_treats_a_leased_block_as_referenced() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    RemoteCustodyLeaseRepository::new(db.clone()).acquire(&request(&["aa", "bb"])).unwrap();
    let referenced = MaterializationStateRepository::new(db)
        .blocks_referenced_outside_current_file(
            "other-group",
            "other.bin",
            &yadorilink_replica_domain::ids::VersionHash([0; 32]),
            &[],
        )
        .unwrap();
    assert!(referenced.contains("aa") && referenced.contains("bb"));
}

/// A release that reaches the responder before the acquire it answers (the
/// acquire timed out at the requester, which then released an attempt the
/// responder had not seen) leaves a tombstone: the acquire that arrives late
/// must not commit a lease nobody will ever release.
#[test]
fn a_late_acquire_after_its_release_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let repo = RemoteCustodyLeaseRepository::new(db.clone());
    assert!(!release(&repo, TOKEN_A), "nothing to delete, still acknowledged");

    let late = repo.acquire(&request(&["aa"])).unwrap();
    assert_eq!(late, LeaseAcquire::Refused);
    assert!(repo.list_active().unwrap().is_empty());
    assert!(!live(&db).contains("aa"));
}

/// The tombstone belongs to the attempt, not to the version: a later attempt
/// for the same version (the requester's next acquire) is a different token
/// and commits normally.
#[test]
fn a_released_attempt_does_not_block_a_later_attempt_on_the_same_version() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.acquire(&request(&["aa"])).unwrap();
    assert!(release(&repo, TOKEN_A));
    assert_eq!(repo.acquire(&request(&["aa"])).unwrap(), LeaseAcquire::Refused);

    let next = repo.acquire(&request_with(TOKEN_B, &["aa"])).unwrap();
    assert!(next.was_created());
}

/// A duplicate release of an old attempt arriving after the requester has
/// moved on to a new attempt must not end the new attempt's lease.
#[test]
fn a_stale_release_does_not_end_a_newer_attempts_lease() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.acquire(&request(&["aa"])).unwrap();
    assert!(release(&repo, TOKEN_A));
    repo.acquire(&request_with(TOKEN_B, &["aa"])).unwrap();

    assert!(!release(&repo, TOKEN_A), "the stale release finds nothing of its own");
    assert_eq!(repo.list_active().unwrap().len(), 1);
    assert!(release(&repo, TOKEN_B));
    assert!(repo.list_active().unwrap().is_empty());
}

/// A requester that presents a new attempt for a lease the responder already
/// holds (it lost its record of the old one) takes the lease over: the old
/// attempt's release can no longer end it, the new one's does.
#[test]
fn a_new_attempt_for_an_existing_lease_takes_over_its_token() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.acquire(&request(&["aa"])).unwrap();
    let newer = CustodyLeaseRequest { membership_generation: 8, ..request_with(TOKEN_B, &["aa"]) };
    let taken = repo.acquire(&newer).unwrap();
    assert!(!taken.was_created());
    assert_eq!(taken.lease().unwrap().attempt_token, TOKEN_B);
    assert_eq!(
        repo.list_active().unwrap()[0].membership_generation,
        8,
        "the lease reports the generation of the attempt that now owns it"
    );
    assert_eq!(repo.list_active().unwrap().len(), 1);
    assert!(!release(&repo, TOKEN_A));
    assert!(release(&repo, TOKEN_B));
}

/// Only the newest tombstones of a requester are kept, whatever the clock
/// says; the oldest goes when the cap is reached, and another requester's are
/// untouched.
#[test]
fn only_the_newest_tombstones_of_a_requester_are_kept() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    let token = |n: usize| {
        let mut token = [0u8; 16];
        token[..8].copy_from_slice(&(n as u64).to_be_bytes());
        token
    };
    repo.release("other-group", REQUESTER, "a.bin", &VERSION, &[0xee; 16]).unwrap();
    for n in 0..TOMBSTONES_PER_REQUESTER + 1 {
        assert!(!release(&repo, token(n)));
    }
    assert_eq!(repo.tombstone_count().unwrap(), TOMBSTONES_PER_REQUESTER + 1);

    assert!(
        repo.acquire(&request_with(token(0), &["aa"])).unwrap().was_created(),
        "the oldest went"
    );
    assert_eq!(
        repo.acquire(&request_with(token(TOMBSTONES_PER_REQUESTER), &["aa"])).unwrap(),
        LeaseAcquire::Refused,
        "the newest is still remembered"
    );
}

/// A requester with only remembered attempts (no lease) is still known, so a
/// membership change can find it.
#[test]
fn requesters_with_state_include_those_with_only_tombstones() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.acquire(&request(&["aa"])).unwrap();
    repo.release(GROUP, "tombstone-only", "a.bin", &VERSION, &TOKEN_B).unwrap();
    assert_eq!(
        repo.requesters_with_state().unwrap(),
        vec![
            (GROUP.to_string(), REQUESTER.to_string()),
            (GROUP.to_string(), "tombstone-only".to_string())
        ]
    );
}

/// A requester that lost its standing in the group loses its leases and the
/// tombstones kept for it; another requester's and another group's stay.
#[test]
fn forgetting_a_requester_drops_its_leases_and_tombstones_in_that_group_only() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.acquire(&request(&["aa"])).unwrap();
    let other_requester =
        CustodyLeaseRequest { requester_device_id: "other".into(), ..request(&["bb"]) };
    repo.acquire(&other_requester).unwrap();
    let other_group = CustodyLeaseRequest { group_id: "g2".into(), ..request(&["cc"]) };
    repo.acquire(&other_group).unwrap();
    assert!(!release(&repo, TOKEN_B));

    assert_eq!(repo.forget_requester(GROUP, REQUESTER).unwrap(), 1);

    let left: Vec<_> = repo
        .list_active()
        .unwrap()
        .into_iter()
        .map(|l| (l.group_id, l.requester_device_id))
        .collect();
    assert_eq!(left.len(), 2);
    assert!(left.contains(&(GROUP.into(), "other".into())));
    assert!(left.contains(&("g2".into(), REQUESTER.into())));
    assert_eq!(repo.tombstone_count().unwrap(), 0);
}

/// Dropping a group's leases (this device stopped being its full replica)
/// leaves other groups alone.
#[test]
fn dropping_a_group_removes_only_that_groups_leases() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let repo = RemoteCustodyLeaseRepository::new(db.clone());
    repo.acquire(&request(&["aa"])).unwrap();
    repo.acquire(&CustodyLeaseRequest { group_id: "g2".into(), ..request(&["bb"]) }).unwrap();

    assert_eq!(repo.drop_group(GROUP).unwrap(), 1);
    let left = repo.list_active().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].group_id, "g2");
    assert_eq!(repo.list_active_for_group("g2").unwrap().len(), 1);
    assert!(repo.list_active_for_group(GROUP).unwrap().is_empty());
}

#[test]
fn a_ticket_close_is_recorded_idempotently_and_ended_by_its_own_key() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    repo.record_ticket_close("g", "lease-a", Some(960)).unwrap();
    repo.record_ticket_close("g", "lease-a", Some(960)).unwrap();
    repo.record_ticket_close("g", "lease-b", None).unwrap();
    repo.record_ticket_close("h", "lease-a", Some(5)).unwrap();
    assert_eq!(
        repo.ticket_closes().unwrap(),
        vec![
            ("g".to_string(), "lease-a".to_string(), Some(960)),
            ("g".to_string(), "lease-b".to_string(), None),
            ("h".to_string(), "lease-a".to_string(), Some(5)),
        ]
    );
    repo.end_ticket_close("g", "lease-a").unwrap();
    repo.end_ticket_close("g", "lease-a").unwrap();
    assert_eq!(repo.ticket_closes().unwrap().len(), 2);
}

/// Measurement, not a gate: what the custody part of the GC live set costs when
/// a responder holds many leases (each lease's block list is a JSON array that
/// is decoded on every live-set computation), next to the whole live-set read.
/// Run in release:
/// `cargo test --release -p yadorilink-sync-sqlite --lib custody_live_root_cost -- --ignored --nocapture`
#[test]
#[ignore = "measurement"]
fn custody_live_root_cost() {
    for (leases, blocks_per_lease) in [(1_000usize, 16usize), (10_000, 16), (10_000, 256)] {
        let dir = tempfile::tempdir().unwrap();
        let db = open_file_db(&dir);
        let repo = RemoteCustodyLeaseRepository::new(db.clone());
        db.write::<_, SyncSqliteError>(|conn| {
            let tx = conn.unchecked_transaction()?;
            {
                let mut insert = tx.prepare(
                    "INSERT INTO remote_custody_lease (lease_id, group_id, requester_device_id, \
                     path, version_hash, block_set_digest, blocks, membership_generation, \
                     attempt_token, created_at_unix) VALUES (?1,'g','r',?2,?3,?3,?4,1,?5,1)",
                )?;
                for n in 0..leases {
                    let blocks: Vec<String> = (0..blocks_per_lease)
                        .map(|b| format!("{:064x}", (n * blocks_per_lease + b) as u128))
                        .collect();
                    insert.execute(rusqlite::params![
                        format!("lease-{n}"),
                        format!("dir/{n}.bin"),
                        &[1u8; 32][..],
                        serde_json::to_string(&blocks).unwrap(),
                        &[2u8; 16][..],
                    ])?;
                }
            }
            tx.commit()?;
            Ok(())
        })
        .unwrap();
        let size = std::fs::metadata(dir.path().join("index.db")).unwrap().len();

        let started = std::time::Instant::now();
        let custody = db.read::<_, SyncSqliteError>(retained_block_hashes_all_groups).unwrap();
        let custody_took = started.elapsed();
        let started = std::time::Instant::now();
        let all = MaterializationStateRepository::new(db.clone())
            .live_block_hashes_including_native_heads()
            .unwrap();
        let all_took = started.elapsed();
        assert_eq!(custody.len(), leases * blocks_per_lease);
        eprintln!(
            "{leases} leases x {blocks_per_lease} blocks = {} block refs, db {} KiB: custody \
             live roots {custody_took:?}; whole live set ({} hashes) {all_took:?}",
            leases * blocks_per_lease,
            size / 1024,
            all.len()
        );
        drop(repo);
    }
}

const CAP: usize = 3;

fn version_n(n: u8) -> CustodyLeaseRequest {
    CustodyLeaseRequest {
        path: format!("f{n}.bin"),
        version_hash: [n; 32],
        attempt_token: [n; 16],
        ..request(&["aa"])
    }
}

fn fill_to_cap(repo: &RemoteCustodyLeaseRepository) {
    for n in 0..CAP as u8 {
        assert!(repo.acquire_with_cap(&version_n(n), CAP).unwrap().was_created());
    }
}

/// Once the requester holds the cap, a new lease is refused with the typed
/// cap refusal (not the released-attempt refusal), nothing is written and
/// every existing lease stays.
#[test]
fn a_new_lease_over_the_cap_is_refused_and_existing_leases_stay() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let repo = RemoteCustodyLeaseRepository::new(db.clone());
    fill_to_cap(&repo);

    let over = repo.acquire_with_cap(&version_n(9), CAP).unwrap();
    assert_eq!(over, LeaseAcquire::CapReached);
    assert!(over.lease().is_none());
    assert!(repo.find(GROUP, REQUESTER, "f9.bin", &[9; 32]).unwrap().is_none());
    assert_eq!(repo.list_active().unwrap().len(), CAP);
    assert!(live(&db).contains("aa"), "an existing lease stopped keeping its blocks");
}

/// The cap bounds distinct leases, not requests: re-acquiring a held version
/// at the cap, with the same or a newer attempt, succeeds and is not counted
/// twice.
#[test]
fn re_acquiring_an_existing_lease_at_the_cap_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    fill_to_cap(&repo);

    let same = repo.acquire_with_cap(&version_n(1), CAP).unwrap();
    assert!(matches!(same, LeaseAcquire::Existing(_)));
    let newer = CustodyLeaseRequest { attempt_token: TOKEN_B, ..version_n(1) };
    assert!(matches!(repo.acquire_with_cap(&newer, CAP).unwrap(), LeaseAcquire::Existing(_)));
    assert_eq!(repo.list_active().unwrap().len(), CAP);
    assert_eq!(repo.acquire_with_cap(&version_n(9), CAP).unwrap(), LeaseAcquire::CapReached);
}

/// A release frees exactly one slot for a new lease.
#[test]
fn a_release_frees_a_slot() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    fill_to_cap(&repo);
    assert_eq!(repo.acquire_with_cap(&version_n(9), CAP).unwrap(), LeaseAcquire::CapReached);

    assert!(repo.release(GROUP, REQUESTER, "f0.bin", &[0; 32], &[0; 16]).unwrap());

    assert!(repo.acquire_with_cap(&version_n(9), CAP).unwrap().was_created());
    assert_eq!(repo.acquire_with_cap(&version_n(8), CAP).unwrap(), LeaseAcquire::CapReached);
}

/// Revoking the requester's standing frees all of its capacity.
#[test]
fn forgetting_the_requester_frees_its_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    fill_to_cap(&repo);
    repo.forget_requester(GROUP, REQUESTER).unwrap();
    assert!(repo.acquire_with_cap(&version_n(9), CAP).unwrap().was_created());
}

/// The budget belongs to one (requester, group): another requester or group
/// still gets leases while this one is at the cap.
#[test]
fn one_requester_at_the_cap_does_not_block_others() {
    let dir = tempfile::tempdir().unwrap();
    let repo = RemoteCustodyLeaseRepository::new(open_file_db(&dir));
    fill_to_cap(&repo);
    let other_requester =
        CustodyLeaseRequest { requester_device_id: "other".into(), ..version_n(9) };
    let other_group = CustodyLeaseRequest { group_id: "g2".into(), ..version_n(9) };
    assert!(repo.acquire_with_cap(&other_requester, CAP).unwrap().was_created());
    assert!(repo.acquire_with_cap(&other_group, CAP).unwrap().was_created());
}

/// The count and the insert are one transaction: racing acquires of distinct
/// versions never leave more than the cap.
#[test]
fn concurrent_acquires_never_exceed_the_cap() {
    let dir = tempfile::tempdir().unwrap();
    let repo = Arc::new(RemoteCustodyLeaseRepository::new(open_file_db(&dir)));
    let handles: Vec<_> = (0..16u8)
        .map(|n| {
            let repo = repo.clone();
            std::thread::spawn(move || repo.acquire_with_cap(&version_n(n), CAP).unwrap())
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.was_created()).count(), CAP);
    assert_eq!(results.iter().filter(|r| **r == LeaseAcquire::CapReached).count(), 16 - CAP);
    assert_eq!(repo.list_active().unwrap().len(), CAP);
}
