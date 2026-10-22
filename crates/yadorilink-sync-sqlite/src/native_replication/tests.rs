#![cfg(test)]

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::IncarnationId;
use yadorilink_replica_domain::ids::{DeviceId, SyncPath, VersionHash};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut};

use super::*;

fn group() -> FolderGroupId {
    FolderGroupId("g".into())
}

fn author(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1; 16]) }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[5; 32])
}

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    c
}

/// Installs the author's next delta putting `version_byte` at `path`.
fn author_delta(c: &Connection, name: &str, path: &str, version_byte: u8) -> NativeDelta {
    let author = author(name);
    let entry = native_store::frontier_entry_get(c, &group(), &author).unwrap();
    let (seq, prev) = match entry {
        None => (AuthorSeq::FIRST, None),
        Some(entry) => (entry.seq.checked_next().unwrap(), Some(entry.tip)),
    };
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author,
        seq,
        prev,
        ops: vec![DeltaOp {
            path: SyncPath(path.into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: VersionHash([version_byte; 32]) }),
        }],
        signature: [0; 64],
    };
    delta.sign(&key());
    native_store::install_verified_delta(c, &group(), &delta, &key().verifying_key()).unwrap();
    delta
}

/// Marks `delta` published with stand-in evidence (serving never verifies).
fn publish(c: &Connection, delta: &NativeDelta) {
    native_publication::attach_authorization_evidence(
        c,
        &[0xCC; 32],
        "g",
        delta.author.device.as_str(),
        1,
        b"checkpoint",
        &[9u8; 64],
        &[7u8; 32],
        &[(delta.delta_hash(), b"proof".to_vec())],
    )
    .unwrap();
}

#[test]
fn an_empty_since_serves_every_published_delta_in_seq_order() {
    let c = conn();
    let first = author_delta(&c, "a", "x", 1);
    let second = author_delta(&c, "a", "y", 2);
    publish(&c, &first);
    publish(&c, &second);

    let served = deltas_to_serve(&c, &group(), &[], 1000).unwrap().unwrap();

    let seqs: Vec<_> = served
        .entries
        .iter()
        .map(|e| NativeDelta::from_wire_bytes(&e.encoded_delta).unwrap().seq.get())
        .collect();
    assert_eq!(seqs, vec![1, 2]);
    assert!(served.unpublished_tail.is_empty());
}

#[test]
fn serving_starts_after_what_the_requester_has_and_stops_at_the_unpublished_tail() {
    let c = conn();
    let first = author_delta(&c, "a", "x", 1);
    let second = author_delta(&c, "a", "y", 2);
    let _third = author_delta(&c, "a", "z", 3);
    publish(&c, &first);
    publish(&c, &second);

    let since = [FrontierEntry { author: author("a"), seq: AuthorSeq(1), tip: None }];
    let served = deltas_to_serve(&c, &group(), &since, 1000).unwrap().unwrap();

    let seqs: Vec<_> = served
        .entries
        .iter()
        .map(|e| NativeDelta::from_wire_bytes(&e.encoded_delta).unwrap().seq.get())
        .collect();
    assert_eq!(seqs, vec![2], "seq 3 is unpublished, so it is not served");
    assert_eq!(served.unpublished_tail, vec![author("a")]);
}

#[test]
fn a_truncated_body_refuses_the_range_instead_of_leaving_a_gap() {
    let c = conn();
    let first = author_delta(&c, "a", "x", 1);
    let second = author_delta(&c, "a", "y", 2);
    publish(&c, &first);
    publish(&c, &second);
    c.execute("DELETE FROM native_delta_bodies WHERE seq = 1", []).unwrap();

    let refusal = deltas_to_serve(&c, &group(), &[], 1000).unwrap().unwrap_err();

    assert_eq!(refusal, ServeRefusal::BodyUnavailable { author: author("a"), seq: AuthorSeq(1) });
}

/// A replica with three published deltas of `a`, a history floor at that frontier and
/// the bodies of seqs 1 and 2 gone, as a replica that joined at the floor holds them.
fn floored_replica() -> (Connection, [u8; 32]) {
    let c = conn();
    let deltas = [author_delta(&c, "a", "x", 1), author_delta(&c, "a", "y", 2)];
    for delta in &deltas {
        publish(&c, delta);
    }
    let id = crate::native_checkpoint_frontier::adopt_current_state_for_test(&c, &group()).unwrap();
    crate::native_history_floor::adopt_history_floor(&c, &group(), &id).unwrap();
    (c, id)
}

#[test]
fn a_missing_body_below_the_history_floor_is_a_truncation_naming_the_floor() {
    let (c, id) = floored_replica();
    c.execute("DELETE FROM native_delta_bodies WHERE seq = 1", []).unwrap();
    let floor = crate::native_history_floor::history_floor(&c, &group()).unwrap().unwrap();

    let refusal = deltas_to_serve(&c, &group(), &[], 1000).unwrap().unwrap_err();

    assert_eq!(
        refusal,
        ServeRefusal::HistoryTruncated {
            author: author("a"),
            seq: AuthorSeq(1),
            checkpoint_id: id,
            frontier_root: floor.floor_frontier_root,
        }
    );
}

#[test]
fn a_range_starting_at_the_floor_is_not_a_truncation() {
    let (c, _) = floored_replica();
    c.execute("DELETE FROM native_delta_bodies WHERE seq = 1", []).unwrap();
    let since = [FrontierEntry { author: author("a"), seq: AuthorSeq(2), tip: None }];
    let served = deltas_to_serve(&c, &group(), &since, 1000).unwrap().unwrap();
    assert!(served.entries.is_empty(), "the requester already has everything");
}

#[test]
fn a_body_still_held_below_the_floor_is_served_not_refused() {
    let (c, _) = floored_replica();
    let served = deltas_to_serve(&c, &group(), &[], 1000).unwrap().unwrap();
    assert_eq!(served.entries.len(), 2);
}

#[test]
fn a_missing_body_above_the_floor_stays_a_plain_unavailable_body() {
    let (c, _) = floored_replica();
    let third = author_delta(&c, "a", "z", 3);
    publish(&c, &third);
    c.execute("DELETE FROM native_delta_bodies WHERE seq = 3", []).unwrap();
    let since = [FrontierEntry { author: author("a"), seq: AuthorSeq(2), tip: None }];
    let refusal = deltas_to_serve(&c, &group(), &since, 1000).unwrap().unwrap_err();
    assert_eq!(refusal, ServeRefusal::BodyUnavailable { author: author("a"), seq: AuthorSeq(3) });
}

#[test]
fn newer_than_lists_only_authors_the_requester_is_behind_on() {
    let c = conn();
    author_delta(&c, "a", "x", 1);
    author_delta(&c, "b", "y", 2);
    author_delta(&c, "b", "z", 3);
    let since = [
        FrontierEntry { author: author("a"), seq: AuthorSeq(1), tip: None },
        FrontierEntry { author: author("b"), seq: AuthorSeq(1), tip: None },
    ];

    let newer = frontier_newer_than(&c, &group(), &since).unwrap();

    assert_eq!(newer.len(), 1);
    assert_eq!(newer[0].author, author("b"));
    assert_eq!(newer[0].seq, AuthorSeq(2));
    assert!(newer[0].tip.is_some());
}

#[test]
fn roots_agree_for_the_same_history_and_differ_after_one_more_delta() {
    let (left, right) = (conn(), conn());
    for c in [&left, &right] {
        author_delta(c, "a", "x", 1);
    }
    assert_eq!(summary_roots(&left, &group()).unwrap(), summary_roots(&right, &group()).unwrap());

    author_delta(&left, "a", "y", 2);
    assert_ne!(summary_roots(&left, &group()).unwrap(), summary_roots(&right, &group()).unwrap());
}

#[test]
fn one_answer_serves_at_most_the_limit_and_the_next_picks_up_where_it_stopped() {
    let c = conn();
    for (i, path) in ["a", "b", "c", "d", "e"].iter().enumerate() {
        let delta = author_delta(&c, "a", path, i as u8 + 1);
        publish(&c, &delta);
    }

    let first = deltas_to_serve(&c, &group(), &[], 2).unwrap().unwrap();
    assert_eq!(first.entries.len(), 2);

    let since = [FrontierEntry { author: author("a"), seq: AuthorSeq(2), tip: None }];
    let second = deltas_to_serve(&c, &group(), &since, 2).unwrap().unwrap();
    let seqs: Vec<_> = second
        .entries
        .iter()
        .map(|e| NativeDelta::from_wire_bytes(&e.encoded_delta).unwrap().seq.get())
        .collect();
    assert_eq!(seqs, vec![3, 4]);
}

#[test]
fn one_answer_stops_at_the_byte_budget_but_still_makes_progress() {
    let c = conn();
    for (i, path) in ["a", "b", "c"].iter().enumerate() {
        let delta = author_delta(&c, "a", path, i as u8 + 1);
        publish(&c, &delta);
    }

    // A budget below one entry still serves that entry: the answer advances.
    let first = deltas_to_serve_within(&c, &group(), &[], 1000, 1).unwrap().unwrap();
    assert_eq!(first.entries.len(), 1, "stops once the budget is crossed");

    let since = [FrontierEntry { author: author("a"), seq: AuthorSeq(1), tip: None }];
    let rest = deltas_to_serve_within(&c, &group(), &since, 1000, usize::MAX).unwrap().unwrap();
    assert_eq!(rest.entries.len(), 2, "the next ask picks up the rest");
}

thread_local! {
    static COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// An author key that counts every equality comparison made on it.
#[derive(Debug)]
struct CountedKey(u32);

impl std::hash::Hash for CountedKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl PartialEq for CountedKey {
    fn eq(&self, other: &Self) -> bool {
        COMPARISONS.with(|c| c.set(c.get() + 1));
        self.0 == other.0
    }
}

impl Eq for CountedKey {}

/// `since` is peer-supplied (up to 65,536 entries) and is consulted once per
/// local author while the answer is built, under the database's writer gate in
/// the original arrangement. The work of that must grow with the two list
/// lengths added, not multiplied.
#[test]
fn the_since_lookup_work_is_linear_in_the_authors_and_the_since_entries() {
    let (authors, entries) = (3_000u32, 6_000u32);
    let local: Vec<CountedKey> = (0..authors).map(CountedKey).collect();
    // Mostly names nobody here has: a hostile list of fabricated authors.
    let since: Vec<(CountedKey, u64)> =
        (0..entries).map(|i| (CountedKey(authors + i), 1)).chain([(CountedKey(5), 4)]).collect();
    COMPARISONS.with(|c| c.set(0));

    let index = SinceIndex::new(since.iter().map(|(key, seq)| (key, *seq)));
    let found: u64 = local.iter().map(|key| index.position(key)).sum();

    assert_eq!(found, 4, "only author 5 is named");
    let comparisons = COMPARISONS.with(|c| c.get());
    let quadratic = (authors as usize) * (entries as usize);
    assert!(
        comparisons < 4 * (authors + entries) as usize,
        "{comparisons} comparisons (a linear scan per author makes {quadratic})"
    );
}

#[test]
fn a_since_naming_an_author_twice_counts_the_first_entry() {
    let c = conn();
    author_delta(&c, "a", "x", 1);
    author_delta(&c, "a", "y", 2);
    author_delta(&c, "a", "z", 3);
    let since = [
        FrontierEntry { author: author("a"), seq: AuthorSeq(1), tip: None },
        FrontierEntry { author: author("a"), seq: AuthorSeq(3), tip: None },
    ];

    let newer = frontier_newer_than(&c, &group(), &since).unwrap();

    assert_eq!(newer.len(), 1, "position 1 (the first entry) is behind seq 3");
}

fn put_real_version(c: &Connection, mtime: i64) -> yadorilink_replica_domain::file::FileVersion {
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
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
    crate::dag_store::put_file_version(c, "g", &version).unwrap();
    version
}

/// Installs the author's next delta putting `version` at `path`.
fn author_delta_naming(c: &Connection, name: &str, path: &str, version: VersionHash) {
    let author = author(name);
    let entry = native_store::frontier_entry_get(c, &group(), &author).unwrap();
    let (seq, prev) = match entry {
        None => (AuthorSeq::FIRST, None),
        Some(entry) => (entry.seq.checked_next().unwrap(), Some(entry.tip)),
    };
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author,
        seq,
        prev,
        ops: vec![DeltaOp {
            path: SyncPath(path.into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version }),
        }],
        signature: [0; 64],
    };
    delta.sign(&key());
    native_store::install_verified_delta(c, &group(), &delta, &key().verifying_key()).unwrap();
}

#[test]
fn a_head_whose_version_is_not_stored_is_found_and_asked_for_again() {
    let c = conn();
    let stored = put_real_version(&c, 1);
    author_delta_naming(&c, "a", "x", stored.version_hash);
    author_delta_naming(&c, "a", "y", VersionHash([0xEE; 32]));
    author_delta_naming(&c, "a", "z", stored.version_hash);

    let unresolved = unresolved_head_positions(&c, &group()).unwrap();
    let since = frontier_since(&c, &group()).unwrap();

    assert_eq!(unresolved, vec![(author("a"), AuthorSeq(2))]);
    assert_eq!(since.len(), 1);
    assert_eq!(since[0].seq, AuthorSeq(1), "named one before the head with no version");
}

#[test]
fn an_unresolved_first_delta_leaves_its_author_out_of_since() {
    let c = conn();
    author_delta_naming(&c, "a", "x", VersionHash([0xEE; 32]));

    assert!(frontier_since(&c, &group()).unwrap().is_empty());
}

#[test]
fn when_every_head_resolves_since_is_exactly_the_frontier() {
    let c = conn();
    let stored = put_real_version(&c, 1);
    author_delta_naming(&c, "a", "x", stored.version_hash);
    author_delta_naming(&c, "b", "y", stored.version_hash);

    assert!(unresolved_head_positions(&c, &group()).unwrap().is_empty());
    assert_eq!(
        frontier_since(&c, &group()).unwrap().len(),
        frontier_entries(&c, &group(), false).unwrap().len()
    );
}

/// A version whose canonical encoding is larger than one replication item is
/// refused at the store, so authoring or admitting it can never leave a head
/// whose version cannot be delivered.
#[test]
fn a_version_too_large_to_send_is_refused_by_the_store() {
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
    use yadorilink_replica_domain::ids::BlockHash;
    use yadorilink_replica_domain::limits::{
        MAX_ENCODED_VERSION_BYTES, VERSION_BLOCK_ENCODED_BYTES,
    };
    let count = MAX_ENCODED_VERSION_BYTES / VERSION_BLOCK_ENCODED_BYTES + 1;
    let blocks = (0..count)
        .map(|i| VersionBlock { hash: BlockHash(vec![(i % 251) as u8; 32]), size: 1 })
        .collect();
    let meta = FileMeta {
        mtime_unix_nanos: 1,
        unix_mode: None,
        symlink_target: None,
        record_kind: RecordKind::File,
        xattrs: Vec::new(),
    };
    let version = FileVersion::new(blocks, count as u64, meta);
    let c = conn();

    let error = crate::dag_store::put_file_version(&c, "g", &version).unwrap_err();

    assert!(matches!(error, SyncSqliteError::InvalidInput(_)), "{error:?}");
    assert!(!crate::dag_store::has_file_version(&c, "g", &version.version_hash).unwrap());
}
