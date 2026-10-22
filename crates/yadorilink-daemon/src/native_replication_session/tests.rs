#![cfg(test)]

use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::protocol5::{self, Message, RefusalReason};
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::native_replication;

use super::*;
use crate::native_checkpoint_flush::flush_pending_native_checkpoint;
use crate::native_test_support::*;

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

fn shares_g(group: &FolderGroupId) -> bool {
    group.0 == GROUP
}

fn shares_nothing(_: &FolderGroupId) -> bool {
    false
}

async fn publish_all(c: &SyncDatabase, source: &FakeSource) {
    flush_pending_native_checkpoint(c, source, GROUP, DEVICE, &device_vk(), &resolver_for(source))
        .await
        .unwrap();
}

/// Runs `f` with a `PeerAccess` that trusts `source`'s authority key and
/// shares group `g` (or nothing).
fn with_peer<T>(
    source: &FakeSource,
    shares: &(dyn Fn(&FolderGroupId) -> bool + Sync),
    f: impl FnOnce(&PeerAccess<'_>) -> T,
) -> T {
    with_peer_policy(source, shares, &|_, _| true, f)
}

/// [`with_peer`] with the group policy's verdict on a checkpoint's pinned
/// policy point supplied by the test.
fn with_peer_policy<T>(
    source: &FakeSource,
    shares: &(dyn Fn(&FolderGroupId) -> bool + Sync),
    vouches: &GroupPolicyPointFor<'_>,
    f: impl FnOnce(&PeerAccess<'_>) -> T,
) -> T {
    let resolver = resolver_for(source);
    let resolve =
        move |_: &FolderGroupId, key_id: &[u8; 32], head: &[u8; 32]| resolver(key_id, head);
    let key_for = |_: &yadorilink_replica_domain::author::AuthorId| None;
    f(&PeerAccess {
        shares_group: shares,
        key_for: &key_for,
        authority_key: &resolve,
        policy_point: vouches,
    })
}

fn answer_on(
    c: &SyncDatabase,
    source: &FakeSource,
    shares: &(dyn Fn(&FolderGroupId) -> bool + Sync),
    bytes: &[u8],
) -> Answer {
    with_peer(source, shares, |peer| {
        c.write(|conn| answer(conn, peer, bytes).map_err(to_db)).unwrap()
    })
}

fn to_db(error: ReplicationError) -> yadorilink_sync_sqlite::SyncSqliteError {
    yadorilink_sync_sqlite::SyncSqliteError::CorruptState(error.to_string())
}

/// One full pull by `puller` from `holder`: summary, diff, pushes. Returns
/// what the puller ingested.
fn pull(puller: &SyncDatabase, holder: &SyncDatabase, source: &FakeSource) -> Vec<IngestReport> {
    let (_, request) = summary_request(&group()).unwrap();
    let response = answer_on(holder, source, &shares_g, &request).reply.unwrap();
    let response = protocol5::decode_message(&response).unwrap();
    if puller.read(|conn| summary_matches(conn, &group(), &response).map_err(to_db)).unwrap() {
        return Vec::new();
    }
    let (_, diff) =
        puller.read(|conn| frontier_diff_request(conn, &group()).map_err(to_db)).unwrap();
    let answered = answer_on(holder, source, &shares_g, &diff);
    assert!(matches!(
        protocol5::decode_message(&answered.reply.unwrap()).unwrap(),
        Message::FrontierDiffResponse { .. }
    ));
    answered
        .pushes
        .iter()
        .map(|batch| {
            answer_on(puller, source, &shares_g, batch).ingested.expect("a delta batch is ingested")
        })
        .collect()
}

fn roots(c: &SyncDatabase) -> native_replication::SummaryRoots {
    c.read(|conn| native_replication::summary_roots(conn, &group())).unwrap()
}

#[tokio::test]
async fn a_pull_brings_an_empty_peer_up_to_date() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    author_delta(&holder, 1, "b.txt");
    author_delta(&holder, 2, "c.txt");
    publish_all(&holder, &source).await;

    let reports = pull(&puller, &holder, &source);

    assert_eq!(reports.iter().map(|r| r.admitted).sum::<usize>(), 3, "{reports:?}");
    assert!(reports.iter().all(|r| r.rejected.is_empty()), "{reports:?}");
    assert_eq!(roots(&puller), roots(&holder));
}

#[tokio::test]
async fn a_second_pull_after_convergence_moves_nothing() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    pull(&puller, &holder, &source);

    assert!(pull(&puller, &holder, &source).is_empty(), "equal roots end the round");
}

#[tokio::test]
async fn only_the_missing_tail_is_pushed() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    pull(&puller, &holder, &source);
    author_delta(&holder, 1, "b.txt");
    publish_all(&holder, &source).await;

    let reports = pull(&puller, &holder, &source);

    assert_eq!(reports.iter().map(|r| r.admitted).sum::<usize>(), 1);
    assert_eq!(roots(&puller), roots(&holder));
}

#[tokio::test]
async fn an_unpublished_delta_is_not_pushed_until_it_is_published() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");

    assert!(pull(&puller, &holder, &source).iter().all(|r| r.admitted == 0));
    assert_ne!(roots(&puller), roots(&holder));

    publish_all(&holder, &source).await;
    pull(&puller, &holder, &source);
    assert_eq!(roots(&puller), roots(&holder));
}

#[tokio::test]
async fn a_batch_delivered_out_of_order_is_held_then_released() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    author_delta(&holder, 1, "b.txt");
    publish_all(&holder, &source).await;
    let served = holder
        .read(|conn| native_replication::deltas_to_serve(conn, &group(), &[], 1000))
        .unwrap()
        .unwrap();
    let mut entries = served.entries;
    entries.reverse();
    let batches = delta_batches(&group(), entries).unwrap();
    // One entry per message so the second is delivered first.
    let one_by_one: Vec<Vec<u8>> = batches
        .iter()
        .flat_map(|batch| match protocol5::decode_message(batch).unwrap() {
            Message::DeltaBatch { group_id, entries } => entries
                .into_iter()
                .map(|entry| {
                    protocol5::encode_message(&Message::DeltaBatch {
                        group_id: group_id.clone(),
                        entries: vec![entry],
                    })
                    .unwrap()
                })
                .collect::<Vec<_>>(),
            _ => unreachable!(),
        })
        .collect();

    let reports: Vec<IngestReport> = one_by_one
        .iter()
        .map(|batch| answer_on(&puller, &source, &shares_g, batch).ingested.unwrap())
        .collect();

    assert_eq!(reports[0].held, 1, "seq 2 first: {reports:?}");
    assert_eq!(reports[1].admitted, 2, "seq 1 releases seq 2: {reports:?}");
    assert_eq!(roots(&puller), roots(&holder));
}

#[tokio::test]
async fn a_delta_batch_is_ingested_idempotently() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    let (_, diff) =
        puller.read(|conn| frontier_diff_request(conn, &group()).map_err(to_db)).unwrap();
    let pushes = answer_on(&holder, &source, &shares_g, &diff).pushes;

    let first = answer_on(&puller, &source, &shares_g, &pushes[0]).ingested.unwrap();
    let again = answer_on(&puller, &source, &shares_g, &pushes[0]).ingested.unwrap();

    assert_eq!((first.admitted, again.admitted, again.duplicates), (1, 0, 1));
}

#[tokio::test]
async fn a_group_the_peer_does_not_share_is_refused_and_its_batches_are_ignored() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    let (_, request) = summary_request(&group()).unwrap();

    let refused = answer_on(&holder, &source, &shares_nothing, &request).reply.unwrap();
    assert!(matches!(
        protocol5::decode_message(&refused).unwrap(),
        Message::Refused { reason: RefusalReason::Unauthorized, .. }
    ));

    let (_, diff) =
        puller.read(|conn| frontier_diff_request(conn, &group()).map_err(to_db)).unwrap();
    let pushes = answer_on(&holder, &source, &shares_g, &diff).pushes;
    let ignored = answer_on(&puller, &source, &shares_nothing, &pushes[0]);
    assert!(ignored.ingested.is_none());
    assert_ne!(roots(&puller), roots(&holder));
}

#[tokio::test]
async fn a_range_the_holder_no_longer_has_is_refused_not_found() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    holder
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM native_delta_bodies", [])?;
            Ok(())
        })
        .unwrap();
    let (_, diff) =
        puller.read(|conn| frontier_diff_request(conn, &group()).map_err(to_db)).unwrap();

    let answered = answer_on(&holder, &source, &shares_g, &diff);

    assert!(matches!(
        protocol5::decode_message(&answered.reply.unwrap()).unwrap(),
        Message::Refused { reason: RefusalReason::NotFound, .. }
    ));
    assert!(answered.pushes.is_empty());
}

/// A holder whose history begins at a floor it adopted answers a range that starts
/// below it with the floor it retains, not a bare not-found.
#[tokio::test]
async fn a_range_below_the_holders_history_floor_is_refused_naming_the_floor() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    let floor = holder
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let id =
                yadorilink_sync_sqlite::native_checkpoint_frontier::adopt_current_state_for_test(
                    conn,
                    &group(),
                )?;
            yadorilink_sync_sqlite::native_history_floor::adopt_history_floor(conn, &group(), &id)?;
            conn.execute("DELETE FROM native_delta_bodies", [])?;
            yadorilink_sync_sqlite::native_history_floor::history_floor(conn, &group())
                .map(|floor| floor.unwrap())
        })
        .unwrap();
    let (_, diff) =
        puller.read(|conn| frontier_diff_request(conn, &group()).map_err(to_db)).unwrap();

    let answered = answer_on(&holder, &source, &shares_g, &diff);

    let Message::Refused { reason, .. } =
        protocol5::decode_message(&answered.reply.unwrap()).unwrap()
    else {
        panic!("expected a refusal")
    };
    assert_eq!(
        reason,
        RefusalReason::HistoryTruncated {
            checkpoint_id: floor.checkpoint_id,
            frontier_root: floor.floor_frontier_root,
        }
    );
    assert!(answered.pushes.is_empty());
}

#[tokio::test]
async fn a_tampered_delta_is_rejected_and_admits_nothing() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    let served = holder
        .read(|conn| native_replication::deltas_to_serve(conn, &group(), &[], 1000))
        .unwrap()
        .unwrap();
    let mut entry = served.entries.into_iter().next().unwrap();
    let last = entry.encoded_delta.len() - 1;
    entry.encoded_delta[last] ^= 0xFF;
    let batch =
        protocol5::encode_message(&Message::DeltaBatch { group_id: group(), entries: vec![entry] })
            .unwrap();

    let report = answer_on(&puller, &source, &shares_g, &batch).ingested.unwrap();

    assert_eq!(report.admitted, 0);
    assert_eq!(report.rejected.len(), 1, "{report:?}");
    assert_eq!(roots(&puller), roots(&db()), "the puller is still empty");
}

/// A delta whose put names a real, stored content version, installed as the
/// next of `DEVICE`'s incarnation 1.
pub(crate) fn author_delta_with_version(
    c: &SyncDatabase,
    path: &str,
    mtime: i64,
) -> yadorilink_replica_domain::file::FileVersion {
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
    let version = FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let author = AuthorId { device: DeviceId(DEVICE.into()), incarnation: IncarnationId([1; 16]) };
    let group = group();
    c.write(|conn| {
        yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, &version)?;
        let entry =
            yadorilink_sync_sqlite::native_store::frontier_entry_get(conn, &group, &author)?;
        let (seq, prev) = match entry {
            None => (AuthorSeq::FIRST, None),
            Some(entry) => (entry.seq.checked_next().unwrap(), Some(entry.tip)),
        };
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group.clone(),
            author: author.clone(),
            seq,
            prev,
            ops: vec![DeltaOp {
                path: SyncPath(path.into()),
                removes: Vec::new(),
                put: Some(DeltaPut { version: version.version_hash }),
            }],
            signature: [0; 64],
        };
        delta.sign(&device_key());
        yadorilink_sync_sqlite::native_store::install_verified_delta(
            conn,
            &group,
            &delta,
            &device_vk(),
        )?;
        Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
    })
    .unwrap();
    version
}

#[tokio::test]
async fn the_versions_a_held_delta_carried_are_there_when_it_is_released() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    let first = author_delta_with_version(&holder, "a.txt", 1);
    let second = author_delta_with_version(&holder, "b.txt", 2);
    publish_all(&holder, &source).await;
    let served = holder
        .read(|conn| native_replication::deltas_to_serve(conn, &group(), &[], 1000))
        .unwrap()
        .unwrap();
    assert!(
        served.entries.iter().all(|entry| entry.versions.len() == 1),
        "each carries its version"
    );
    let mut entries = served.entries;
    entries.reverse(); // seq 2 first: it is held until seq 1 arrives
    let held_report = answer_on(
        &puller,
        &source,
        &shares_g,
        &protocol5::encode_message(&Message::DeltaBatch {
            group_id: group(),
            entries: vec![entries[0].clone()],
        })
        .unwrap(),
    )
    .ingested
    .unwrap();
    assert_eq!(held_report.held, 1);
    answer_on(
        &puller,
        &source,
        &shares_g,
        &protocol5::encode_message(&Message::DeltaBatch {
            group_id: group(),
            entries: vec![entries[1].clone()],
        })
        .unwrap(),
    );

    for version in [&first, &second] {
        let stored = puller
            .read(|conn| {
                yadorilink_sync_sqlite::dag_store::get_file_version(
                    conn,
                    GROUP,
                    &version.version_hash,
                )
            })
            .unwrap();
        assert!(stored.is_some(), "the puller resolves {:?}", version.version_hash);
    }
}

/// A file-backed replica database at `path`, so a test can drop it and reopen
/// what a crash would have left on disk.
fn file_db(path: &std::path::Path) -> SyncDatabase {
    SyncDatabase::open(path, |conn| {
        yadorilink_sync_sqlite::replica_tables::init_for_tests(conn)
            .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
    })
    .unwrap()
}

fn served_entries(holder: &SyncDatabase) -> Vec<DeltaBatchEntry> {
    holder
        .read(|conn| native_replication::deltas_to_serve(conn, &group(), &[], 1000))
        .unwrap()
        .unwrap()
        .entries
}

fn ingest_entries(
    c: &SyncDatabase,
    source: &FakeSource,
    entries: &[DeltaBatchEntry],
    store: &StoreVersions,
) -> IngestReport {
    with_peer(source, &shares_g, |peer| {
        c.write(|conn| Ok::<_, SyncSqliteError>(ingest_with(conn, peer, &group(), entries, store)))
            .unwrap()
    })
}

fn has_version(c: &SyncDatabase, version: &yadorilink_replica_domain::file::FileVersion) -> bool {
    c.read(|conn| {
        yadorilink_sync_sqlite::dag_store::has_file_version(conn, GROUP, &version.version_hash)
    })
    .unwrap()
}

/// A process that dies between committing an admitted delta and storing the
/// versions it carried used to leave a head naming content the replica could
/// not resolve, with roots that equal the sender's (so nothing asked again).
/// The admission and the versions are now one transaction: a failure storing
/// the versions leaves nothing admitted, on disk too.
#[tokio::test]
async fn a_failure_storing_the_versions_leaves_the_delta_unadmitted_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("puller.db");
    let holder = db();
    let source = FakeSource::new();
    let version = author_delta_with_version(&holder, "a.txt", 1);
    publish_all(&holder, &source).await;
    let entries = served_entries(&holder);
    let before = roots(&file_db(&path));

    let crashing: &StoreVersions = &|_, _, _, _| {
        Err(yadorilink_sync_sqlite::SyncSqliteError::CorruptState("injected failure".into()))
    };
    let puller = file_db(&path);
    let report = ingest_entries(&puller, &source, &entries, crashing);
    assert_eq!(report.admitted, 0, "{report:?}");
    assert_eq!(report.rejected.len(), 1, "{report:?}");
    drop(puller);

    let reopened = file_db(&path);
    assert_eq!(roots(&reopened), before, "no head was left behind");
    assert!(!has_version(&reopened, &version));

    // The delta was never admitted, so the same entry is simply admitted
    // whole the next time it arrives.
    let report =
        ingest_entries(&reopened, &source, &entries, &native_replication::store_carried_versions);
    assert_eq!(report.admitted, 1, "{report:?}");
    assert!(has_version(&reopened, &version));
    assert!(reopened
        .read(|conn| native_replication::unresolved_head_positions(conn, &group()))
        .unwrap()
        .is_empty());
}

/// A peer can send a valid delta whose `versions` list is empty. The head is
/// admitted (the delta is authentic) but names content that is not here; the
/// next round must notice that and fetch the versions, although the roots now
/// equal the sender's.
#[tokio::test]
async fn a_head_admitted_without_its_version_is_asked_for_again_and_resolved() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    let version = author_delta_with_version(&holder, "a.txt", 1);
    publish_all(&holder, &source).await;
    let mut entries = served_entries(&holder);
    entries[0].versions.clear();
    let report =
        ingest_entries(&puller, &source, &entries, &native_replication::store_carried_versions);
    assert_eq!(report.admitted, 1, "{report:?}");
    assert_eq!(roots(&puller), roots(&holder), "a roots comparison sees nothing wrong");
    assert!(!has_version(&puller, &version));
    assert_eq!(
        puller
            .read(|conn| native_replication::unresolved_head_positions(conn, &group()))
            .unwrap()
            .len(),
        1
    );

    // The request names the author one seq before the unresolved head, so the
    // peer serves that delta again and its versions land on a duplicate.
    let (_, diff) =
        puller.read(|conn| frontier_diff_request(conn, &group()).map_err(to_db)).unwrap();
    let answered = answer_on(&holder, &source, &shares_g, &diff);
    assert_eq!(answered.pushes.len(), 1);
    let report = answer_on(&puller, &source, &shares_g, &answered.pushes[0]).ingested.unwrap();

    assert_eq!(report.duplicates, 1, "{report:?}");
    assert!(has_version(&puller, &version));
}

/// A peer cannot use a batch to store content no delta of the batch names.
#[tokio::test]
async fn a_version_no_put_of_the_delta_names_is_not_stored() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta_with_version(&holder, "a.txt", 1);
    let unrelated = author_delta_with_version(&holder, "b.txt", 2);
    publish_all(&holder, &source).await;
    let mut entries = served_entries(&holder);
    // The first delta also carries the second delta's version.
    let extra = entries[1].versions[0].clone();
    entries[0].versions.push(extra);

    ingest_entries(&puller, &source, &entries[..1], &native_replication::store_carried_versions);

    assert!(!has_version(&puller, &unrelated));
}

fn bulky_entry(seed: u8, version_bytes: usize, versions: usize) -> DeltaBatchEntry {
    DeltaBatchEntry {
        encoded_delta: vec![seed; 200],
        checkpoint_hash: [seed; 32],
        checkpoint_encoded: vec![seed; 300],
        checkpoint_signature: [seed; 64],
        author_signing_public_key: [seed; 32],
        proof_encoded: vec![seed; 100],
        versions: (0..versions).map(|i| vec![seed.wrapping_add(i as u8); version_bytes]).collect(),
    }
}

fn decode_batch(bytes: &[u8]) -> Vec<DeltaBatchEntry> {
    match protocol5::decode_message(bytes).unwrap() {
        Message::DeltaBatch { entries, .. } => entries,
        other => panic!("not a delta batch: {other:?}"),
    }
}

/// Twenty deltas that each carry a 1 MiB version are about 20 MiB. Budgeted
/// without the versions they looked like a few KiB, went out as one message
/// over the protocol's 16 MiB limit, and the answer errored on every retry.
#[test]
fn carried_versions_count_toward_the_batch_budget() {
    let entries: Vec<_> = (0..20).map(|i| bulky_entry(i, 1024 * 1024, 1)).collect();

    let batches = delta_batches(&group(), entries).expect("the answer can always be encoded");

    assert!(batches.len() > 1, "{} batches", batches.len());
    let mut delivered = 0;
    for batch in &batches {
        assert!(batch.len() <= protocol5::MAX_MESSAGE_BYTES);
        let decoded = decode_batch(batch);
        let bytes: usize = decoded.iter().flat_map(|e| &e.versions).map(Vec::len).sum();
        assert!(bytes <= BATCH_BYTES, "a batch carries {bytes} version bytes");
        delivered += decoded.len();
    }
    assert_eq!(delivered, 20, "order and count are preserved");
}

/// One delta whose own versions exceed a message is sent as several entries
/// for that delta, so every version still reaches the receiver.
#[test]
fn one_delta_with_more_version_bytes_than_a_message_is_split_across_entries() {
    // Six 3 MiB versions: 18 MiB, over the 16 MiB message limit.
    let batches = delta_batches(&group(), vec![bulky_entry(1, 3 * 1024 * 1024, 6)])
        .expect("an oversized delta is split, not an encode error");

    assert!(batches.len() > 1);
    let entries: Vec<_> = batches.iter().flat_map(|b| decode_batch(b)).collect();
    assert!(entries.iter().all(|e| e.encoded_delta == vec![1u8; 200]), "all name the same delta");
    let versions: std::collections::BTreeSet<_> =
        entries.into_iter().flat_map(|e| e.versions).collect();
    assert_eq!(versions.len(), 6, "every version is delivered");
}

/// A delta that names a version too large for one item cannot be delivered
/// with its version. Sending it without would make the receiver admit the head,
/// find the version missing, rewind and ask again, forever. It is skipped; the
/// deltas around it still go out.
#[test]
fn a_delta_whose_version_exceeds_the_item_limit_is_skipped_not_sent_versionless() {
    let oversized = yadorilink_replica_domain::limits::MAX_ENCODED_VERSION_BYTES + 1;
    let entries =
        vec![bulky_entry(1, 1024, 1), bulky_entry(2, oversized, 1), bulky_entry(3, 1024, 1)];

    let batches = delta_batches(&group(), entries).expect("the answer is still encodable");

    let delivered: Vec<_> = batches.iter().flat_map(|b| decode_batch(b)).collect();
    let seeds: Vec<u8> = delivered.iter().map(|e| e.checkpoint_hash[0]).collect();
    assert_eq!(seeds, vec![1, 3], "the oversized delta is not sent, in any form");
}

/// One delta that puts a distinct empty-file version at each of two paths.
fn author_two_put_delta(c: &SyncDatabase) -> [yadorilink_replica_domain::file::FileVersion; 2] {
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
    let version = |mtime| {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    };
    let versions = [version(1), version(2)];
    let author = AuthorId { device: DeviceId(DEVICE.into()), incarnation: IncarnationId([1; 16]) };
    let ops: Vec<DeltaOp> = ["a.txt", "b.txt"]
        .iter()
        .zip(&versions)
        .map(|(path, version)| DeltaOp {
            path: SyncPath((*path).into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: version.version_hash }),
        })
        .collect();
    c.write(|conn| {
        for version in &versions {
            yadorilink_sync_sqlite::dag_store::put_file_version(conn, GROUP, version)?;
        }
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author.clone(),
            seq: AuthorSeq::FIRST,
            prev: None,
            ops: ops.clone(),
            signature: [0; 64],
        };
        delta.sign(&device_key());
        yadorilink_sync_sqlite::native_store::install_verified_delta(
            conn,
            &group(),
            &delta,
            &device_vk(),
        )?;
        Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
    })
    .unwrap();
    versions
}

/// A delta whose versions do not fit one message arrives as several entries,
/// each its own transaction. After the first, the delta is admitted while some
/// of its versions are not yet stored: a recognised transient state. The head
/// reconciles as not-in-sync, materialization of it fails closed, and the
/// remaining entry resolves it.
#[tokio::test]
async fn a_split_delta_admitted_with_only_its_first_entry_resolves_when_the_rest_arrives() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    let [first, second] = author_two_put_delta(&holder);
    publish_all(&holder, &source).await;
    let whole = served_entries(&holder).remove(0);
    assert_eq!(whole.versions.len(), 2);
    let part = |version: &yadorilink_replica_domain::file::FileVersion| DeltaBatchEntry {
        versions: vec![version.canonical_encoding()],
        ..whole.clone()
    };
    let store = &native_replication::store_carried_versions;
    let unresolved = |c: &SyncDatabase| {
        c.read(|conn| native_replication::unresolved_head_positions(conn, &group())).unwrap()
    };
    let desired = |c: &SyncDatabase, path: &str| {
        c.write(|conn| {
            yadorilink_sync_sqlite::native_desired_state::native_desired_path_state(
                conn, GROUP, path,
            )
        })
    };

    let report = ingest_entries(&puller, &source, &[part(&first)], store);

    assert_eq!(report.admitted, 1, "{report:?}");
    assert!(has_version(&puller, &first));
    assert!(!has_version(&puller, &second), "the head is admitted before its version");
    assert_eq!(roots(&puller), roots(&holder), "a roots comparison sees nothing wrong");
    assert_eq!(unresolved(&puller).len(), 1, "reconciliation treats the group as not in sync");
    assert!(desired(&puller, "a.txt").is_ok());
    assert!(
        matches!(desired(&puller, "b.txt"), Err(SyncSqliteError::NotFound(_))),
        "materialization of a head whose version is missing fails closed"
    );

    let report = ingest_entries(&puller, &source, &[part(&second)], store);

    assert_eq!(report.duplicates, 1, "{report:?}");
    assert!(has_version(&puller, &second));
    assert!(unresolved(&puller).is_empty());
    assert!(desired(&puller, "b.txt").is_ok());
}

#[tokio::test]
async fn a_checkpoint_the_group_policy_does_not_vouch_for_admits_nothing() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    author_delta(&holder, 1, "a.txt");
    publish_all(&holder, &source).await;
    let served = holder
        .read(|conn| native_replication::deltas_to_serve(conn, &group(), &[], 1000))
        .unwrap()
        .unwrap();
    let batches = delta_batches(&group(), served.entries).unwrap();

    let reports: Vec<IngestReport> = batches
        .iter()
        .map(|batch| {
            with_peer_policy(&source, &shares_g, &|_, _| false, |peer| {
                puller
                    .write(|conn| answer(conn, peer, batch).map_err(to_db))
                    .unwrap()
                    .ingested
                    .unwrap()
            })
        })
        .collect();

    assert!(reports.iter().all(|r| r.admitted == 0 && !r.rejected.is_empty()), "{reports:?}");
    assert_ne!(roots(&puller), roots(&holder));
}

/// A bulk-captured delta of the most ops one delta carries, put at paths a
/// scan produces.
fn bulk_delta(ops: usize) -> yadorilink_replica_domain::signed_delta::NativeDelta {
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
    use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: AuthorId { device: DeviceId(DEVICE.into()), incarnation: IncarnationId([1; 16]) },
        seq: AuthorSeq::FIRST,
        prev: None,
        ops: (0..ops)
            .map(|i| DeltaOp {
                path: SyncPath(format!("photos/2026/holiday/IMG_{i:06}.jpg")),
                removes: Vec::new(),
                put: Some(DeltaPut { version: VersionHash([i as u8; 32]) }),
            })
            .collect(),
        signature: [0; 64],
    };
    delta.sign(&device_key());
    delta
}

/// A delta of the bulk bound that names a content version per op replicates:
/// it round-trips, and cut into messages it stays within the item and message
/// limits with every carried version delivered.
#[test]
fn a_full_bulk_delta_replicates_within_the_message_limits() {
    let max_ops = yadorilink_sync_sqlite::native_authoring::BULK_DELTA_MAX_OPS;
    let delta = bulk_delta(max_ops);
    let encoded = delta.to_wire_bytes();
    assert_eq!(
        yadorilink_replica_domain::signed_delta::NativeDelta::from_wire_bytes(&encoded).unwrap(),
        delta
    );
    assert!(encoded.len() <= protocol5::MAX_BATCH_ITEM_BYTES, "{} bytes", encoded.len());
    let entry = DeltaBatchEntry {
        encoded_delta: encoded,
        checkpoint_hash: [1; 32],
        checkpoint_encoded: vec![1; 300],
        checkpoint_signature: [1; 64],
        author_signing_public_key: [1; 32],
        // A proof naming every op's path is far larger than the single-op one.
        proof_encoded: vec![1; 256 * 1024],
        versions: (0..max_ops).map(|i| vec![i as u8; 2048]).collect(),
    };

    let batches = delta_batches(&group(), vec![entry]).expect("a bulk delta is encodable");

    let mut versions = 0;
    for batch in &batches {
        assert!(batch.len() <= protocol5::MAX_MESSAGE_BYTES);
        let entries = decode_batch(batch);
        assert!(entries.iter().all(|e| e.versions.len() <= protocol5::MAX_VERSIONS_PER_ENTRY));
        versions += entries.iter().map(|e| e.versions.len()).sum::<usize>();
    }
    assert_eq!(versions, max_ops, "every carried version is delivered");
}

/// The largest delta authoring can sign: a bulk run is cut at the byte budget,
/// then the op that crosses it is added, each op naming a full class of
/// removals by the longest device ids. It is
/// within the per-item budget and `delta_batches` sends it, never drops it.
#[test]
fn the_largest_authorable_delta_is_sent_not_dropped() {
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
    use yadorilink_replica_domain::native_state::{DeltaHash, Dot};
    use yadorilink_replica_domain::signed_delta::{
        DeltaOp, DeltaPut, HeadRef, NativeDelta, MAX_REMOVES_PER_OP,
    };
    let named = |i: usize| Dot {
        author: AuthorId {
            device: DeviceId(format!("{i:0>256}")),
            incarnation: IncarnationId([1; 16]),
        },
        seq: AuthorSeq(1 + i as u64),
    };
    // Twenty long segments: a path near the limit.
    let directory = vec!["d".repeat(190); 20].join("/");
    let op_at = |n: usize| DeltaOp {
        path: SyncPath(format!("{directory}/{n:04}")),
        removes: (0..MAX_REMOVES_PER_OP)
            .map(|i| HeadRef { dot: named(i), provenance: DeltaHash([i as u8; 32]) })
            .collect(),
        put: Some(DeltaPut { version: VersionHash([9; 32]) }),
    };
    let budget = yadorilink_sync_sqlite::native_authoring::BULK_DELTA_MAX_BYTES;
    let mut ops = Vec::new();
    let mut bytes = 0usize;
    while bytes <= budget {
        ops.push(op_at(ops.len()));
        bytes = ops
            .iter()
            .map(|op| NativeDelta { ops: vec![op.clone()], ..bulk_delta(1) }.to_wire_bytes().len())
            .sum();
    }
    let mut delta = NativeDelta { ops, ..bulk_delta(1) };
    delta.sign(&device_key());
    let encoded = delta.to_wire_bytes();
    assert!(encoded.len() <= protocol5::MAX_BATCH_ITEM_BYTES, "{} bytes", encoded.len());
    let entry = DeltaBatchEntry {
        encoded_delta: encoded,
        checkpoint_hash: [1; 32],
        checkpoint_encoded: vec![1; 300],
        checkpoint_signature: [1; 64],
        author_signing_public_key: [1; 32],
        proof_encoded: vec![1; 256 * 1024],
        versions: Vec::new(),
    };
    let batches = delta_batches(&group(), vec![entry]).expect("encodable");
    assert_eq!(batches.len(), 1, "the delta is sent, not dropped");
    assert_eq!(decode_batch(&batches[0]).len(), 1);
}

/// The bulk delta of the bound admits on a puller through the replication
/// session and leaves it with the holder's roots.
#[tokio::test]
async fn a_full_bulk_delta_is_pulled_and_admitted() {
    let (holder, puller) = (db(), db());
    let source = FakeSource::new();
    let delta = bulk_delta(yadorilink_sync_sqlite::native_authoring::BULK_DELTA_MAX_OPS);
    holder
        .write(|conn| {
            yadorilink_sync_sqlite::native_store::install_verified_delta(
                conn,
                &group(),
                &delta,
                &device_vk(),
            )
        })
        .unwrap();
    publish_all(&holder, &source).await;

    let reports = pull(&puller, &holder, &source);

    assert_eq!(reports.iter().map(|r| r.admitted).sum::<usize>(), 1, "{reports:?}");
    assert!(reports.iter().all(|r| r.rejected.is_empty()), "{reports:?}");
    assert_eq!(roots(&puller), roots(&holder));
}
