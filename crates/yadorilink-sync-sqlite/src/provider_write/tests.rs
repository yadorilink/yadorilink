#![cfg(test)]

//! The write path's transaction against a real replica database: operation identity, base
//! handling, collisions, rename, delete bounds and rollback.

use std::cell::Cell;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::link::LinkRepository;
use crate::local_author::LocalAuthor;
use crate::provider::ProviderRepository;

use super::*;

const GROUP: &str = "g1";
const MTIME: i64 = 1_700_000_000_000_000_000;

struct Fx {
    db: Arc<SyncDatabase>,
    repo: ProviderRepository,
    root: String,
    key: SigningKey,
    seq: Cell<u64>,
}

fn sha(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn content(bytes: &[u8]) -> ContentInput {
    ContentInput {
        blocks: vec![BlockInfo { hash: sha(bytes), offset: 0, size: bytes.len() as u32 }],
        size: bytes.len() as u64,
    }
}

/// The version a file with `bytes` and the fixed metadata of these tests has.
fn version_of(bytes: &[u8]) -> VersionHash {
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(sha(bytes)), size: bytes.len() as u32 }],
        bytes.len() as u64,
        FileMeta {
            mtime_unix_nanos: MTIME,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
    .version_hash
}

impl Fx {
    fn new() -> Self {
        let db = crate::replica_tables::open_for_tests();
        LinkRepository::new(db.clone()).add_link("/provider/p", GROUP).unwrap();
        let repo = ProviderRepository::new(db.clone());
        let root = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "P").unwrap();
        repo.mark_install_done(&root).unwrap();
        Self { db, repo, root, key: SigningKey::from_bytes(&[5u8; 32]), seq: Cell::new(0) }
    }

    fn input(&self, kind: ChangeKind) -> ApplyInput {
        let seq = self.seq.get() + 1;
        self.seq.set(seq);
        let mut fingerprint = [0u8; 32];
        fingerprint[..8].copy_from_slice(&seq.to_be_bytes());
        ApplyInput {
            root_id: self.root.clone(),
            session_id: b"session-000000001".to_vec(),
            operation_seq: seq,
            fingerprint,
            kind,
            item_id: None,
            new_parent: None,
            name: None,
            entry_kind: EntryKind::File,
            base: BaseVersion::Unknown,
            content: None,
            symlink_target: None,
            metadata: MetadataInput {
                unix_mode: Some(0o644),
                mtime_unix_nanos: Some(MTIME),
                xattrs: None,
            },
            recursive: false,
            max_subtree: DEFAULT_MAX_SUBTREE,
            base_generation: None,
            parent_generation: None,
            observed_revision: None,
            now_ms: 1_700_000_000_000,
        }
    }

    /// Runs the operation as an OS that saw the CURRENT view: the generations it did not name
    /// are filled from the database (a test that wants a stale or unknown view sets it, or uses
    /// `run_raw`).
    fn run(&self, input: &ApplyInput) -> Result<ApplyResult, ApplyError> {
        let mut input = input.clone();
        let generation_of = |path: &str| -> Option<u64> {
            self.db
                .read::<_, SyncSqliteError>(|conn| {
                    Ok(conn
                        .query_row(
                            "SELECT generation FROM provider_items \
                             WHERE root_id = ?1 AND path = ?2 AND live = 1",
                            rusqlite::params![self.root, path],
                            |r| r.get::<_, i64>(0),
                        )
                        .ok()
                        .map(|g| g as u64))
                })
                .unwrap()
        };
        let item_path = input.item_id.and_then(|id| {
            self.db
                .read::<_, SyncSqliteError>(|conn| {
                    Ok(conn
                        .query_row(
                            "SELECT path FROM provider_items WHERE root_id = ?1 AND item_id = ?2",
                            rusqlite::params![self.root, &id[..]],
                            |r| r.get::<_, String>(0),
                        )
                        .ok())
                })
                .unwrap()
        });
        if input.base_generation.is_none() {
            input.base_generation = item_path.as_deref().and_then(generation_of);
        }
        // An honest extension names the version it was shown: the published one (the current
        // one if never published). `run_raw` leaves it unknown.
        if input.base == BaseVersion::Unknown {
            if let Some(path) = item_path.as_deref() {
                input.base = BaseVersion::Opaque(self.shown_version_of(path));
            }
        }
        if input.parent_generation.is_none() {
            if let Some(path) = &item_path {
                let parent = path.rsplit_once('/').map_or("", |(p, _)| p);
                // The folder it LEAVES, by its place generation.
                input.parent_generation = self
                    .db
                    .read::<_, SyncSqliteError>(|conn| {
                        Ok(conn
                            .query_row(
                                "SELECT generation - child_bumps FROM provider_items \
                                 WHERE root_id = ?1 AND path = ?2 AND live = 1",
                                rusqlite::params![self.root, parent],
                                |r| r.get::<_, i64>(0),
                            )
                            .ok()
                            .map(|g| g as u64))
                    })
                    .unwrap();
            }
        }
        self.run_raw(&input)
    }

    fn shown_version_of(&self, path: &str) -> VersionHash {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                let published: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT published_version_hash FROM provider_items \
                         WHERE root_id = ?1 AND path = ?2 AND live = 1",
                        rusqlite::params![self.root, path],
                        |r| r.get(0),
                    )
                    .ok()
                    .flatten();
                Ok(match published.and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                    Some(hash) => VersionHash(hash),
                    None => crate::provider::current_version(conn, GROUP, path)?
                        .map_or(VersionHash([0; 32]), |v| v.version_hash),
                })
            })
            .unwrap()
    }

    fn run_raw(&self, input: &ApplyInput) -> Result<ApplyResult, ApplyError> {
        let author = LocalAuthor {
            author: AuthorId {
                device: DeviceId("device-a".into()),
                incarnation: IncarnationId([1u8; 16]),
            },
            signing_key: &self.key,
            capture: None,
        };
        let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
        self.repo.apply_change(input, &author, "device-a", &permit)
    }

    fn create(&self, parent: Option<ItemId>, name: &str, bytes: &[u8]) -> AppliedItem {
        let mut input = self.input(ChangeKind::Create);
        input.new_parent = Some(parent);
        input.name = Some(name.into());
        input.content = Some(content(bytes));
        self.run(&input).unwrap().item.unwrap()
    }

    fn create_dir(&self, parent: Option<ItemId>, name: &str) -> AppliedItem {
        let mut input = self.input(ChangeKind::Create);
        input.new_parent = Some(parent);
        input.name = Some(name.into());
        input.entry_kind = EntryKind::Directory;
        self.run(&input).unwrap().item.unwrap()
    }

    fn modify(
        &self,
        item: ItemId,
        bytes: &[u8],
        base: BaseVersion,
    ) -> Result<ApplyResult, ApplyError> {
        let mut input = self.input(ChangeKind::Modify);
        input.item_id = Some(item);
        input.content = Some(content(bytes));
        input.base = base;
        self.run(&input)
    }

    fn rename(
        &self,
        item: ItemId,
        parent: Option<Option<ItemId>>,
        name: &str,
    ) -> Result<ApplyResult, ApplyError> {
        let mut input = self.input(ChangeKind::Modify);
        input.item_id = Some(item);
        input.new_parent = parent;
        input.name = Some(name.into());
        input.metadata = MetadataInput::default();
        self.run(&input)
    }

    fn delete(
        &self,
        item: ItemId,
        base: BaseVersion,
        recursive: bool,
    ) -> Result<ApplyResult, ApplyError> {
        let mut input = self.input(ChangeKind::Delete);
        input.item_id = Some(item);
        input.base = base;
        input.recursive = recursive;
        self.run(&input)
    }

    fn live_paths(&self) -> Vec<String> {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT path FROM files WHERE group_id = ?1 AND state = 'current' \
                     AND deleted = 0 ORDER BY path",
                )?;
                let rows: Vec<String> =
                    stmt.query_map([GROUP], |r| r.get(0))?.collect::<Result<_, _>>()?;
                Ok(rows)
            })
            .unwrap()
    }

    fn heads_at(&self, path: &str) -> usize {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(crate::native_store::native_heads_at(
                    conn,
                    &FolderGroupId(GROUP.into()),
                    &SyncPath(path.into()),
                )?
                .len())
            })
            .unwrap()
    }

    fn row_version(&self, path: &str) -> Option<VersionHash> {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(crate::store::read_canonical_current_row(conn, GROUP, path)?
                    .filter(|r| !r.snapshot.deleted)
                    .map(|r| r.version_hash()))
            })
            .unwrap()
    }

    fn count_where(&self, table: &str, column: &str) -> i64 {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn
                    .query_row(&format!("SELECT SUM({column}) FROM {table}"), [], |r| r.get(0))?)
            })
            .unwrap()
    }

    fn count(&self, table: &str) -> i64 {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
            })
            .unwrap()
    }
}

fn is_collision<T: std::fmt::Debug>(result: Result<T, ApplyError>) -> bool {
    matches!(result, Err(ApplyError::NameCollision(_)))
}

// ---- operation identity ----

/// A replay returns the stored result and authors nothing; a different fingerprint is a
/// mismatch; once the stored result expired the processed mark answers STALE and nothing is
/// re-authored.
#[test]
fn a_replay_returns_the_stored_result_and_a_late_one_is_stale() {
    let fx = Fx::new();
    let mut input = fx.input(ChangeKind::Create);
    input.name = Some("a.txt".into());
    input.content = Some(content(b"one"));
    let first = fx.run(&input).unwrap();
    assert!(!first.replayed);
    let rows = fx.count("native_heads");

    let again = fx.run(&input).unwrap();
    assert!(again.replayed, "a replay was re-authored");
    assert_eq!(again.item, first.item);
    assert_eq!(fx.count("native_heads"), rows);
    assert_eq!(fx.live_paths(), ["a.txt"]);

    let mut other = input.clone();
    other.fingerprint = [9u8; 32];
    assert!(matches!(fx.run(&other), Err(ApplyError::OperationMismatch)));

    // The stored result expires; the operation stays processed and is never a new change.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM provider_apply_log", [])?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(fx.run(&input), Err(ApplyError::StaleOperation)));
    assert_eq!(fx.count("native_heads"), rows, "a stale replay authored something");
}

/// Two renames of one item are two operations, and the floor tracks processed sequence numbers
/// out of order.
#[test]
fn distinct_operations_of_one_item_do_not_collide_and_the_floor_follows() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"one").item_id; // seq 1
    let first = fx.rename(item, Some(None), "b.txt").unwrap(); // seq 2
    let second = fx.rename(item, Some(None), "c.txt").unwrap(); // seq 3
    assert_eq!(first.item.unwrap().name, "b.txt");
    assert_eq!(second.item.unwrap().name, "c.txt");
    assert_eq!(fx.live_paths(), ["c.txt"]);
    let floor: i64 = fx
        .db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row("SELECT floor_seq FROM provider_apply_sessions", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(floor, 3);
}

// ---- create ----

#[test]
fn a_create_commits_the_row_the_item_and_its_published_version_together() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "docs");
    let file = fx.create(Some(dir.item_id), "a.txt", b"hello");
    assert_eq!(file.name, "a.txt");
    assert_eq!(file.parent_item_id, Some(dir.item_id));
    assert!(file.current);
    assert_eq!(file.content_version, version_of(b"hello"));
    assert_eq!(fx.live_paths(), ["docs", "docs/a.txt"]);
    assert_eq!(
        fx.repo.publication(&fx.root, &file.item_id).unwrap(),
        Some(crate::provider::Publication::Published)
    );
    // The bytes came from the OS, which holds exactly them: the create is the handoff of its own
    // version (a file only; a directory has no content).
    assert_eq!(fx.count("provider_handoffs"), 1, "the authored file is not recorded as held");
    let handoff = fx.repo.handoff(&fx.root, &file.item_id).unwrap().unwrap();
    assert_eq!(handoff.version_hash, version_of(b"hello"));
    assert!(fx.repo.handoff(&fx.root, &dir.item_id).unwrap().is_none());

    let mut link = fx.input(ChangeKind::Create);
    link.name = Some("ln".into());
    link.entry_kind = EntryKind::Symlink;
    link.symlink_target = Some(b"docs/a.txt".to_vec());
    let symlink = fx.run(&link).unwrap().item.unwrap();
    assert_eq!(symlink.kind, EntryKind::Symlink);
}

/// An edit the user made on this device is the content the OS holds: each applied edit moves the
/// ledger to the new version with a newer evidence sequence, so the item is never offered as a
/// download; an edit that moves the item only (no content) keeps its entry.
#[test]
fn an_authored_edit_is_recorded_as_the_version_the_os_holds() {
    let fx = Fx::new();
    let file = fx.create(None, "a.txt", b"one").item_id;
    let first = fx.repo.handoff(&fx.root, &file).unwrap().unwrap();
    assert_eq!(first.version_hash, version_of(b"one"));

    fx.modify_content(file, b"two");
    let second = fx.repo.handoff(&fx.root, &file).unwrap().unwrap();
    assert_eq!(second.version_hash, version_of(b"two"));
    assert!(second.evidence_seq > first.evidence_seq);
    assert_eq!(fx.repo.latest_evidence_seq(&fx.root).unwrap(), Some(second.evidence_seq));
    assert_eq!(fx.count("provider_handoffs"), 1);
}

#[test]
fn names_that_cannot_be_created_are_refused_before_anything_is_written() {
    let fx = Fx::new();
    let file = fx.create(None, "Report.TXT", b"x");
    let dir = fx.create_dir(None, "dir");
    let _inside = fx.create(Some(dir.item_id), "child", b"c");
    let before = (fx.live_paths(), fx.count("native_heads"), fx.count("provider_apply_log"));

    for bad in ["", ".", "..", "a/b", "nul\0", &"x".repeat(256)] {
        let mut input = fx.input(ChangeKind::Create);
        input.name = Some(bad.into());
        assert!(matches!(fx.run(&input), Err(ApplyError::InvalidName(_))), "{bad:?}");
    }
    // Exactly the same name, a case variant and a normalisation variant all collide.
    for taken in ["Report.TXT", "report.txt", "REPORT.txt"] {
        let mut input = fx.input(ChangeKind::Create);
        input.name = Some(taken.into());
        assert!(is_collision(fx.run(&input)), "{taken}");
    }
    let mut decomposed = fx.input(ChangeKind::Create);
    decomposed.name = Some("cafe\u{301}.txt".into());
    decomposed.content = Some(content(b"z"));
    fx.run(&decomposed).unwrap();
    let mut composed = fx.input(ChangeKind::Create);
    composed.name = Some("caf\u{e9}.txt".into());
    assert!(is_collision(fx.run(&composed)), "NFC and NFD names were both created");
    // A file where a directory with children stands, and a child under a file.
    let mut over_dir = fx.input(ChangeKind::Create);
    over_dir.name = Some("dir".into());
    assert!(is_collision(fx.run(&over_dir)));
    let mut under_file = fx.input(ChangeKind::Create);
    under_file.new_parent = Some(Some(file.item_id));
    under_file.name = Some("child".into());
    assert!(matches!(fx.run(&under_file), Err(ApplyError::NotFound(_))));
    // The refusals changed nothing (the one accepted create added its own rows).
    assert_eq!(fx.live_paths().len(), before.0.len() + 1);
}

// ---- modify, bases and the resolver ----

/// Searches for contents whose version ordering makes the third version win or lose against the
/// second (the resolver picks the highest version hash).
fn contents_with_order(second: &[u8], wins: bool) -> Vec<u8> {
    (0..200u32)
        .map(|n| format!("third-{n}").into_bytes())
        .find(|candidate| (version_of(candidate) > version_of(second)) == wins)
        .expect("a candidate with that order")
}

#[test]
fn an_edit_on_the_current_version_is_an_ordinary_edit() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"one").item_id;
    let result = fx.modify(item, b"two", BaseVersion::Unknown).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Applied);
    let applied = result.item.unwrap();
    assert!(applied.current);
    assert_eq!(fx.row_version("a.txt"), Some(version_of(b"two")));
    assert_eq!(fx.heads_at("a.txt"), 1);
    assert_eq!(
        fx.repo.publication(&fx.root, &item).unwrap(),
        Some(crate::provider::Publication::Published)
    );
}

/// An edit whose base is not the current version, or whose provenance our own state cannot
/// prove, is UNTRUSTED (option B): nothing is authored, the current version stays canonical, and
/// the bytes stay with the user (KEEP_LOCAL until they are written as a file beside the item).
/// Both orderings of the competing version hashes behave the same: the version-hash ordering
/// never decides which version is canonical.
#[test]
fn an_edit_on_a_stale_or_unknown_base_never_touches_the_canonical_version() {
    for wins in [true, false] {
        for base in ["stale", "unknown"] {
            let fx = Fx::new();
            let item = fx.create(None, "a.txt", b"one").item_id;
            let v1 = version_of(b"one");
            fx.modify(item, b"two", BaseVersion::Unknown).unwrap();
            let heads_before = fx.count("native_heads");
            let log_before = fx.count("provider_apply_log");
            let third = contents_with_order(b"two", wins);
            let base = match base {
                "stale" => BaseVersion::Opaque(v1),
                _ => BaseVersion::Opaque(VersionHash([42u8; 32])),
            };

            let result = fx.modify(item, &third, base).unwrap();
            assert_eq!(result.outcome, OutcomeKind::Concurrent, "{base:?} wins={wins}");
            // V2 stays the canonical item, and the user's bytes exist beside it.
            assert_eq!(
                fx.row_version("a.txt"),
                Some(version_of(b"two")),
                "V2 did not stay canonical"
            );
            assert_eq!(fx.heads_at("a.txt"), 1, "the edit became a head of the canonical path");
            assert!(
                fx.kept_beside("a.txt", &third),
                "the user's bytes were not kept: {:?}",
                fx.live_paths()
            );
            assert_eq!(fx.count("native_heads"), heads_before + 1, "exactly one new file");
            assert_eq!(fx.count("provider_apply_log"), log_before + 1);
        }
    }
}

#[test]
fn a_retired_or_unknown_item_keeps_the_local_bytes() {
    let fx = Fx::new();
    let item = fx.create(None, "gone.txt", b"one").item_id;
    fx.delete(item, BaseVersion::Unknown, false).unwrap();
    // The bytes of an edit of a retired or unknown item are kept as a conflict-named file where
    // the user had it (or at the root): a durable copy, not a refusal.
    let result = fx.modify(item, b"edit", BaseVersion::Unknown).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("gone.txt", b"edit"), "{:?}", fx.live_paths());
    let unknown = fx.modify([7u8; 16], b"unknown edit", BaseVersion::Unknown).unwrap();
    assert_eq!(unknown.outcome, OutcomeKind::Concurrent);
    assert_eq!(fx.live_paths().len(), 2, "{:?}", fx.live_paths());
}

// ---- rename and move ----

#[test]
fn a_rename_keeps_the_item_and_a_directory_rename_keeps_its_descendants() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "photos");
    let file = fx.create(Some(dir.item_id), "a.jpg", b"jpeg");
    let renamed = fx.rename(dir.item_id, None, "pictures").unwrap().item.unwrap();
    assert_eq!(renamed.item_id, dir.item_id);
    assert_eq!(renamed.name, "pictures");
    assert_eq!(fx.live_paths(), ["pictures", "pictures/a.jpg"]);
    assert_eq!(
        fx.repo.path_for_item(&fx.root, &file.item_id).unwrap().unwrap().0,
        "pictures/a.jpg"
    );

    let moved = fx.rename(file.item_id, Some(None), "a.jpg").unwrap().item.unwrap();
    assert_eq!(moved.parent_item_id, None);
    assert_eq!(fx.live_paths(), ["a.jpg", "pictures"]);
}

#[test]
fn a_rename_never_replaces_and_rechecks_the_destination_subtree_and_the_folded_name() {
    let fx = Fx::new();
    let a = fx.create(None, "a.txt", b"a");
    let _b = fx.create(None, "b.txt", b"b");
    let dir = fx.create_dir(None, "d");
    let _child = fx.create(Some(dir.item_id), "inside", b"i");
    let other = fx.create_dir(None, "e");
    let before = fx.live_paths();

    assert!(is_collision(fx.rename(a.item_id, None, "b.txt")));
    assert!(is_collision(fx.rename(a.item_id, None, "B.TXT")), "a case variant collides");
    // Moving a directory onto a name whose subtree holds live entries.
    assert!(is_collision(fx.rename(other.item_id, None, "d")));
    // Into itself.
    assert!(matches!(
        fx.rename(dir.item_id, Some(Some(dir.item_id)), "d2"),
        Err(ApplyError::InvalidName(_)) | Err(ApplyError::NotFound(_))
    ));
    assert_eq!(fx.live_paths(), before, "a refused rename changed something");
}

// ---- delete ----

#[test]
fn a_file_delete_is_bound_to_what_the_user_saw() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"one").item_id;
    let v1 = version_of(b"one");
    // A newer version arrives after the user saw V1.
    fx.modify(item, b"two", BaseVersion::Unknown).unwrap();
    let result = fx.delete(item, BaseVersion::Opaque(v1), false).unwrap();
    assert_eq!(result.outcome, OutcomeKind::FileSurvived);
    assert_eq!(fx.live_paths(), ["a.txt"], "the newer version was deleted");
    assert!(fx.repo.path_for_item(&fx.root, &item).unwrap().is_some_and(|(_, live)| !live));
    // The same on the current version deletes it.
    let again = fx.create(None, "b.txt", b"x");
    let done = fx.delete(again.item_id, BaseVersion::Unknown, false).unwrap();
    assert_eq!(done.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), ["a.txt"]);
}

#[test]
fn a_directory_whose_children_are_all_as_seen_is_deleted_recursively() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let _a = fx.create(Some(dir.item_id), "a", b"a");
    let sub = fx.create_dir(Some(dir.item_id), "sub");
    let _b = fx.create(Some(sub.item_id), "b", b"b");
    let result = fx.delete(dir.item_id, BaseVersion::Unknown, true).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), Vec::<String>::new());
}

// ---- rollback ----

/// A full database fails the commit and records nothing: no row, no item change, no operation.
#[test]
fn a_full_database_fails_the_whole_change() {
    let fx = Fx::new();
    let _seed = fx.create(None, "seed", b"s");
    let pages: i64 = fx
        .db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row("PRAGMA page_count", [], |r| r.get(0))?)
        })
        .unwrap();
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.pragma_update(None, "max_page_count", pages)?;
            Ok(())
        })
        .unwrap();
    let before = (fx.live_paths(), fx.count("provider_apply_log"));
    let mut failed = false;
    for n in 0..200 {
        let mut input = fx.input(ChangeKind::Create);
        input.name = Some(format!("file-{n}-{}", "x".repeat(200)));
        input.content = Some(content(&[n as u8; 100]));
        if matches!(fx.run(&input), Err(ApplyError::Db(_))) {
            failed = true;
            break;
        }
    }
    assert!(failed, "the database never filled");
    // Whatever was committed before the failure is consistent: every file has its operation.
    let files = fx.live_paths().len() - before.0.len();
    assert_eq!(fx.count("provider_apply_log") as usize - before.1 as usize, files);
}

/// A processed identity is never aged out: an operation answered long ago stays STALE however
/// much time passes, and the number of sessions is bounded by an explicit refusal instead.
#[test]
fn processed_identities_are_never_aged_out_and_sessions_are_capped() {
    let fx = Fx::new();
    let mut first = fx.input(ChangeKind::Create);
    first.name = Some("a".into());
    fx.run(&first).unwrap();
    // The stored result is gone and 200 days pass: the replay is still stale, never applied.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM provider_apply_log", [])?;
            Ok(())
        })
        .unwrap();
    // Another session's later operation runs the pruning at the later time.
    let mut other = fx.input(ChangeKind::Create);
    other.session_id = b"other-000000000".to_vec();
    other.operation_seq = 1;
    other.name = Some("b".into());
    other.now_ms += 200 * 24 * 3600 * 1000;
    fx.run(&other).unwrap();
    let mut late = first.clone();
    late.now_ms = other.now_ms;
    assert!(matches!(fx.run(&late), Err(ApplyError::StaleOperation)));

    // The cap: further sessions are refused whole until the root is rotated.
    for n in 1..(MAX_SESSIONS_PER_ROOT - 1) {
        let mut input = fx.input(ChangeKind::Create);
        input.session_id = format!("other-{n:09}").into_bytes();
        input.operation_seq = 1;
        input.name = Some(format!("s{n}"));
        fx.run(&input).unwrap();
    }
    let mut over = fx.input(ChangeKind::Create);
    over.session_id = b"session-over".to_vec();
    over.operation_seq = 1;
    over.name = Some("over".into());
    let live = fx.live_paths();
    assert!(matches!(fx.run(&over), Err(ApplyError::TooManySessions)));
    assert_eq!(fx.live_paths(), live, "a refused session authored something");
}

/// A recursive delete above the subtree bound is refused before anything is read into memory or
/// authored; at the bound it goes through.
#[test]
fn a_recursive_delete_above_the_subtree_bound_is_refused_whole() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    for name in ["a", "b", "c"] {
        fx.create(Some(dir.item_id), name, name.as_bytes());
    }
    let before = (fx.live_paths(), fx.count("native_heads"));
    let mut input = fx.input(ChangeKind::Delete);
    input.item_id = Some(dir.item_id);
    input.recursive = true;
    input.max_subtree = 3; // the directory and three children are four rows
    assert!(matches!(fx.run(&input), Err(ApplyError::DirectoryNotEmpty(_))));
    assert_eq!((fx.live_paths(), fx.count("native_heads")), before);

    let mut input = fx.input(ChangeKind::Delete);
    input.item_id = Some(dir.item_id);
    input.recursive = true;
    input.max_subtree = 4;
    assert_eq!(fx.run(&input).unwrap().outcome, OutcomeKind::Deleted);
    assert!(fx.live_paths().is_empty());
}

// ---- the provider projector ----

impl Fx {
    /// What a fresh install leaves: the heads and their versions, no `files` row, and one open
    /// obligation per path.
    fn forget_rows_and_arm(&self, paths: &[&str]) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute("DELETE FROM files WHERE group_id = ?1", [GROUP])?;
                crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                    tx, GROUP, paths, 1,
                )?;
                Ok(())
            })
            .unwrap();
    }
}

#[test]
fn the_projector_writes_the_rows_of_an_install_and_completes_the_obligations() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    fx.create(Some(dir.item_id), "one", b"1");
    fx.create(None, "two", b"22");
    let expected = fx.live_paths();
    let one = fx.row_version("d/one");
    fx.forget_rows_and_arm(&["d", "d/one", "two"]);
    assert_eq!(fx.live_paths(), Vec::<String>::new());

    assert_eq!(fx.repo.project_batch(GROUP, 100).unwrap(), 3);

    assert_eq!(fx.live_paths(), expected);
    assert_eq!(fx.row_version("d/one"), one, "the row shows another version than its head");
    assert_eq!(fx.repo.open_obligations(GROUP).unwrap(), 0);
    assert_eq!(fx.repo.verify_namespace(GROUP).unwrap(), None);
    // A second pass has nothing to do.
    assert_eq!(fx.repo.project_batch(GROUP, 100).unwrap(), 0);
}

#[test]
fn a_batch_is_bounded_and_the_rest_waits_in_the_obligations() {
    let fx = Fx::new();
    for name in ["a", "b", "c", "d"] {
        fx.create(None, name, name.as_bytes());
    }
    fx.forget_rows_and_arm(&["a", "b", "c", "d"]);
    assert_eq!(fx.repo.project_batch(GROUP, 3).unwrap(), 3);
    assert_eq!(fx.repo.open_obligations(GROUP).unwrap(), 1);
    assert!(matches!(
        fx.repo.verify_namespace(GROUP).unwrap(),
        Some(crate::provider_projector::NotReady::OpenObligations(1))
    ));
    assert_eq!(fx.repo.project_batch(GROUP, 3).unwrap(), 1);
    assert_eq!(fx.repo.verify_namespace(GROUP).unwrap(), None);
}

/// The engine must never claim a provider group's obligations: only the projector consumes them.
#[test]
fn the_engine_claim_skips_a_provider_group() {
    let fx = Fx::new();
    fx.create(None, "a", b"a");
    fx.forget_rows_and_arm(&["a"]);
    let claimed = fx
        .db
        .read::<_, SyncSqliteError>(|conn| {
            crate::projection_obligations::claim_runnable_obligations(conn, i64::MAX, 100, 100)
        })
        .unwrap();
    assert!(claimed.is_empty(), "the engine claimed a provider group: {claimed:?}");
}

/// A verification that only compared totals would pass a namespace with a missing row; the
/// per-parent comparison and the gap check do not.
#[test]
fn the_verification_finds_a_missing_row_and_counts_structural_directories() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    fx.create(Some(dir.item_id), "x", b"x");
    fx.create(Some(dir.item_id), "y", b"y");
    fx.repo.project_batch(GROUP, 100).unwrap();
    assert_eq!(fx.repo.verify_namespace(GROUP).unwrap(), None);
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM files WHERE group_id = ?1 AND path = 'd/y'", [GROUP])?;
            Ok(())
        })
        .unwrap();
    assert!(fx.repo.verify_namespace(GROUP).unwrap().is_some(), "a missing row passed");
}

/// A row the plan does not hold (the listing would show a stranger) is found by the per-parent
/// count even though no planned entry is missing a row.
#[test]
fn the_verification_finds_a_row_the_plan_does_not_hold() {
    let fx = Fx::new();
    fx.create(None, "a", b"a");
    fx.repo.project_batch(GROUP, 100).unwrap();
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
                 VALUES (?1, zeroblob(58), zeroblob(32))",
                [GROUP],
            )?;
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state, native_authoring_identity) \
                 VALUES (?1, 'stranger', 1, 1, '[]', 0, 7, 'current', zeroblob(58))",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        fx.repo.verify_namespace(GROUP).unwrap(),
        Some(crate::provider_projector::NotReady::ChildCount(parent, 2, 1)) if parent.is_empty()
    ));
}

/// A peer's later delete (its head leaves the state) is projected by the same projector with no
/// link runtime: the row is tombstoned, so a listing no longer finds it.
#[test]
fn a_later_peer_delete_is_projected_into_a_tombstone() {
    let fx = Fx::new();
    fx.create(None, "keep", b"k");
    fx.create(None, "gone", b"g");
    fx.repo.project_batch(GROUP, 100).unwrap();
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM native_heads WHERE group_id = ?1 AND path = 'gone'", [GROUP])?;
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx,
                GROUP,
                &["gone"],
                1,
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(fx.repo.project_batch(GROUP, 100).unwrap(), 1);
    assert_eq!(fx.live_paths(), ["keep"]);
}

/// An empty namespace is not "queryable" before the install: readiness waits for the marker.
#[test]
fn an_empty_namespace_is_not_ready_before_its_install() {
    let fx = Fx::new();
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("UPDATE provider_roots SET install_done = 0", [])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        fx.repo.verify_namespace(GROUP).unwrap(),
        Some(crate::provider_projector::NotReady::NotInstalled)
    );
    fx.repo.mark_install_done(&fx.root).unwrap();
    assert_eq!(fx.repo.verify_namespace(GROUP).unwrap(), None);
}

// ---- parent-scoped enumeration ----

impl Fx {
    /// The namespace as an install leaves it for the OS: every row projected, no item minted,
    /// nothing published, no event.
    fn forget_exposure(&self) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute("DELETE FROM provider_items", [])?;
                tx.execute("DELETE FROM provider_change_events", [])?;
                tx.execute("DELETE FROM provider_enumerated_parents", [])?;
                tx.execute("UPDATE provider_roots SET namespace_revision = 0", [])?;
                Ok(())
            })
            .unwrap();
    }

    fn page(
        &self,
        parent: &[u8],
        after: Option<&str>,
        limit: usize,
    ) -> crate::provider_enumerate::ChildrenPage {
        self.repo.enumerate_children(&self.root, parent, after, limit, 256 * 1024).unwrap()
    }

    fn names(page: &crate::provider_enumerate::ChildrenPage) -> Vec<String> {
        page.items.iter().map(|i| i.name.clone()).collect()
    }

    fn event_count(&self) -> i64 {
        self.count("provider_change_events")
    }

    fn drop_row(&self, path: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute("DELETE FROM files WHERE group_id = ?1 AND path = ?2", [GROUP, path])?;
                Ok(())
            })
            .unwrap();
    }
}

/// A folder nobody opened lists its children (rows AND structural directories of any depth),
/// minting the items inside the page transaction and publishing each at the version shown.
#[test]
fn a_never_opened_folder_lists_its_children_after_an_install() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    let e = fx.create_dir(Some(d.item_id), "e");
    fx.create(Some(e.item_id), "x", b"xx");
    fx.create(Some(d.item_id), "y", b"y");
    fx.create(None, "top", b"t");
    // `d` and `d/e` become structural: no row of their own, only descendants.
    fx.drop_row("d");
    fx.drop_row("d/e");
    fx.forget_exposure();

    let root = fx.page(&[], None, 100);
    assert_eq!(Fx::names(&root), ["d", "top"]);
    let dir = &root.items[0];
    assert_eq!(dir.kind, RecordKind::Directory);
    assert!(dir.parent_item_id.is_empty());
    assert_eq!(fx.event_count(), 2, "one first-publication event per item shown");
    assert_eq!(root.anchor, 2, "the anchor is the revision this page leaves behind");

    let d_page = fx.page(&dir.item_id, None, 100);
    assert_eq!(Fx::names(&d_page), ["e", "y"]);
    assert_eq!(d_page.items[0].parent_item_id, dir.item_id.to_vec());
    let e_page = fx.page(&d_page.items[0].item_id, None, 100);
    assert_eq!(Fx::names(&e_page), ["x"]);
    assert_eq!(e_page.items[0].size, 2);
    // Every shown item is published at the version it was shown.
    assert_eq!(fx.count("provider_enumerated_parents"), 3);
}

/// Once a folder's children are all exposed, opening it again reads: no write transaction.
#[test]
fn a_repeat_page_of_an_exposed_folder_takes_no_write() {
    let fx = Fx::new();
    fx.create(None, "a", b"a");
    fx.create(None, "b", b"b");
    fx.forget_exposure();
    let first = fx.page(&[], None, 100);
    assert_eq!(Fx::names(&first), ["a", "b"]);
    let writes = fx.db.write_transaction_count();
    let events = fx.event_count();
    let again = fx.page(&[], None, 100);
    assert_eq!(Fx::names(&again), ["a", "b"]);
    assert_eq!(fx.db.write_transaction_count(), writes, "a repeat open took the writer");
    assert_eq!(fx.event_count(), events);
}

/// Keyset pages cover a folder exactly once, bounded by count and by bytes, with a cursor that
/// is the last path of the page.
#[test]
fn pages_cover_a_folder_once_and_are_bounded_by_count_and_bytes() {
    let fx = Fx::new();
    for n in 0..7 {
        fx.create(None, &format!("f{n}"), b"x");
    }
    fx.forget_exposure();
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = fx.page(&[], after.as_deref(), 3);
        assert!(page.items.len() <= 3);
        seen.extend(Fx::names(&page));
        pages += 1;
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, (0..7).map(|n| format!("f{n}")).collect::<Vec<_>>());
    assert_eq!(pages, 3);

    // The byte bound ends a page early but never returns an empty one.
    let tiny = fx.repo.enumerate_children(&fx.root, &[], None, 100, 1).unwrap();
    assert_eq!(tiny.items.len(), 1);
    assert_eq!(tiny.next_after.as_deref(), Some("f0"));
}

/// The engine, not the host, says whether the OS may drop its own copy of an item: a file or a
/// folder nothing keeps on this device is allowed, a pinned path, anything beneath a pinned
/// folder and a folder holding a pinned item are not, and an unpinned neighbour is unaffected.
#[test]
fn the_engine_decides_whether_the_os_may_drop_an_items_copy() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "docs");
    let kept = fx.create(Some(dir.item_id), "kept", b"k");
    let loose = fx.create(Some(dir.item_id), "loose", b"l");
    let other = fx.create(None, "other", b"o");
    let allowed =
        |id: &ItemId| fx.repo.lookup_item(&fx.root, id).unwrap().unwrap().0.eviction_allowed;
    assert!(allowed(&dir.item_id) && allowed(&kept.item_id) && allowed(&other.item_id));

    let pins = crate::PinnedItemRepository::new(fx.db.clone());
    pins.pin(GROUP, "docs/kept").unwrap();
    assert!(!allowed(&kept.item_id), "a kept file was allowed");
    assert!(!allowed(&dir.item_id), "a folder holding a kept file was allowed");
    assert!(allowed(&loose.item_id), "an unpinned sibling was refused");
    assert!(allowed(&other.item_id));

    pins.unpin(GROUP, "docs/kept").unwrap();
    pins.pin(GROUP, "docs").unwrap();
    assert!(!allowed(&dir.item_id) && !allowed(&kept.item_id) && !allowed(&loose.item_id));
    assert!(allowed(&other.item_id), "a pin on one folder reached another");
    pins.unpin(GROUP, "docs").unwrap();
    assert!(allowed(&kept.item_id), "an unpin did not take effect at the next read");

    // Pinning a prefix-sharing name does not cover its neighbour ("doc" vs "docs").
    pins.pin(GROUP, "doc").unwrap();
    assert!(allowed(&dir.item_id) && allowed(&loose.item_id));
}

/// A pin or unpin changes what the OS may do with the item, so the engine republishes it: the item
/// (and everything beneath a folder) gets a new generation and an upsert event, every folder above
/// gets one too without disturbing its children's tokens, unrelated items are untouched, and the
/// root has an unannounced change so the OS is signalled.
#[test]
fn a_retention_change_republishes_the_item_its_descendants_and_ancestors() {
    let fx = Fx::new();
    let docs = fx.create_dir(None, "docs");
    let a = fx.create(Some(docs.item_id), "a", b"a");
    let b = fx.create(Some(docs.item_id), "b", b"b");
    let other = fx.create(None, "other", b"o");
    let shown = |id: &ItemId| fx.repo.lookup_item(&fx.root, id).unwrap().unwrap().0;
    let changed_since = |seq: i64| -> Vec<Vec<u8>> {
        fx.db
            .read::<_, SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT item_id FROM provider_change_events WHERE root_id = ?1 AND seq > ?2",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![fx.root, seq], |r| r.get(0))?
                    .collect::<Result<Vec<Vec<u8>>, _>>()?;
                Ok(rows)
            })
            .unwrap()
    };
    let revision = || fx.repo.namespace_revision(&fx.root).unwrap().unwrap() as i64;
    let before =
        (shown(&docs.item_id), shown(&a.item_id), shown(&b.item_id), shown(&other.item_id));

    if let Some(changes) = fx.repo.unannounced_changes(&fx.root).unwrap() {
        fx.repo.mark_announced(&fx.root, changes).unwrap();
    }
    let seq = revision();
    fx.repo.retention_changed(GROUP, "docs/a").unwrap();
    let events = changed_since(seq);
    assert!(events.contains(&a.item_id.to_vec()), "the item was not republished");
    assert!(events.contains(&docs.item_id.to_vec()), "its folder was not republished");
    assert!(!events.contains(&b.item_id.to_vec()) && !events.contains(&other.item_id.to_vec()));
    assert_ne!(shown(&a.item_id).generation, before.1.generation, "the served token did not move");
    assert_ne!(shown(&docs.item_id).generation, before.0.generation);
    assert_eq!(
        shown(&b.item_id).metadata_version,
        before.2.metadata_version,
        "a sibling's token moved"
    );
    assert_eq!(shown(&b.item_id).parent_generation, before.2.parent_generation);
    assert_eq!(shown(&other.item_id), before.3);
    assert!(fx.repo.unannounced_changes(&fx.root).unwrap().is_some(), "no signal is owed");

    // A folder takes everything beneath it with it.
    let seq = revision();
    fx.repo.retention_changed(GROUP, "docs").unwrap();
    let events = changed_since(seq);
    for id in [&docs.item_id, &a.item_id, &b.item_id] {
        assert!(events.contains(&id.to_vec()), "an item beneath the changed folder was missed");
    }
    assert!(!events.contains(&other.item_id.to_vec()));

    // No provider root, no effect.
    let seq = revision();
    fx.repo.retention_changed("another-group", "x").unwrap();
    assert_eq!(revision(), seq);
}

/// A pin and its republication are one transaction: when the republication cannot be written
/// (here, the root row refuses updates, standing in for a crash between the two steps), the pin
/// is not durable either, in both directions, so a restart never finds a pin the OS was not told
/// about. When it can be written, both happen together.
#[test]
fn a_pin_and_its_republication_commit_together_or_not_at_all() {
    let fx = Fx::new();
    let a = fx.create(None, "a", b"a");
    let pins = crate::PinnedItemRepository::new(fx.db.clone());
    let refuse_root_updates = |on: bool| {
        fx.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                if on {
                    tx.execute_batch(
                        "CREATE TRIGGER refuse_root_updates BEFORE UPDATE ON provider_roots \
                         BEGIN SELECT RAISE(ABORT, 'interrupted'); END;",
                    )?;
                } else {
                    tx.execute_batch("DROP TRIGGER refuse_root_updates;")?;
                }
                Ok(())
            })
            .unwrap();
    };
    let generation = || fx.repo.lookup_item(&fx.root, &a.item_id).unwrap().unwrap().0.generation;
    let start = generation();

    refuse_root_updates(true);
    assert!(pins.pin(GROUP, "a").is_err());
    assert!(pins.list(GROUP).unwrap().is_empty(), "a pin survived its failed republication");
    refuse_root_updates(false);
    assert_eq!(generation(), start);

    pins.pin(GROUP, "a").unwrap();
    assert_eq!(pins.list(GROUP).unwrap(), ["a"]);
    let pinned = generation();
    assert_ne!(pinned, start, "the pin was not republished");

    refuse_root_updates(true);
    assert!(pins.unpin(GROUP, "a").is_err());
    assert_eq!(pins.list(GROUP).unwrap(), ["a"], "an unpin survived its failed republication");
    refuse_root_updates(false);
    assert!(pins.unpin(GROUP, "a").unwrap());
    assert_ne!(generation(), pinned, "the unpin was not republished");
}

/// A lookup serves the item without minting or publishing anything; a retired item is gone.
#[test]
fn a_lookup_does_not_publish_and_a_retired_item_is_not_found() {
    let fx = Fx::new();
    let a = fx.create(None, "a", b"a");
    fx.forget_exposure();
    let first = fx.page(&[], None, 10);
    let id = first.items[0].item_id;
    let events = fx.event_count();
    let (shown, _) = fx.repo.lookup_item(&fx.root, &id).unwrap().expect("live");
    assert_eq!(shown.name, "a");
    assert_eq!(fx.event_count(), events);
    assert!(fx.repo.retire_item(&fx.root, &id).unwrap());
    assert!(fx.repo.lookup_item(&fx.root, &id).unwrap().is_none());
    let _ = a;
    assert!(matches!(
        fx.repo.enumerate_children(&fx.root, &[9; 16], None, 10, 1000),
        Err(crate::provider_enumerate::EnumerateError::NotFound)
    ));
}

/// Opening a file as a folder is refused; the scaffold rows are not part of the namespace.
#[test]
fn a_file_is_not_a_folder_and_scaffold_rows_are_not_listed() {
    let fx = Fx::new();
    fx.create(None, "f", b"f");
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, 'scaffold', 0, 0, '[]', 0, 0, 'current')",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
    fx.forget_exposure();
    let page = fx.page(&[], None, 10);
    assert_eq!(Fx::names(&page), ["f"]);
    assert!(matches!(
        fx.repo.enumerate_children(&fx.root, &page.items[0].item_id, None, 10, 1000),
        Err(crate::provider_enumerate::EnumerateError::NotADirectory)
    ));
}

// ---- changes and the working set ----

use crate::provider_enumerate::{ChangeScope, ChangesError};

impl Fx {
    fn changes(
        &self,
        scope: &ChangeScope,
        since: u64,
        limit: usize,
    ) -> crate::provider_enumerate::ChangesPage {
        self.repo.enumerate_changes(&self.root, scope, since, limit, 256 * 1024).unwrap()
    }

    fn revision(&self) -> u64 {
        self.repo.namespace_revision(&self.root).unwrap().unwrap()
    }

    /// A peer-created file: a current row appears with no authoring through this device.
    fn peer_creates(&self, path: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
                     VALUES (?1, zeroblob(58), zeroblob(32))",
                    [GROUP],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                     version_seq, state, native_authoring_identity) \
                     VALUES (?1, ?2, 0, 1, '[]', 0, 9, 'current', zeroblob(58))",
                    rusqlite::params![GROUP, path],
                )?;
                Ok(())
            })
            .unwrap();
    }

    fn peer_deletes(&self, path: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET deleted = 1 WHERE group_id = ?1 AND path = ?2",
                    [GROUP, path],
                )?;
                Ok(())
            })
            .unwrap();
    }

    fn published_of(&self, id: &ItemId) -> Option<Vec<u8>> {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(
                    "SELECT published_version_hash FROM provider_items WHERE item_id = ?1",
                    [&id[..]],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    }

    fn rename_in_place(&self, from: &str, to: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                crate::provider::rename_tree_for_tests(tx, GROUP, from, to)?;
                tx.execute(
                    "UPDATE files SET path = ?3 WHERE group_id = ?1 AND path = ?2",
                    [GROUP, from, to],
                )?;
                Ok(())
            })
            .unwrap();
    }
}

fn names_of(items: &[crate::provider_enumerate::ShownItem]) -> Vec<String> {
    items.iter().map(|i| i.name.clone()).collect()
}

/// The working-set enumerator is told EVERY logged event: a peer's create under an opened folder
/// (an item the OS never held), its delete, and a move into a folder nobody opened (reported as
/// removed, which ends the item's membership). An item first reported is published at the
/// version shown; the next request from the new anchor finds nothing.
#[test]
fn the_working_set_is_told_every_event_and_publishes_what_it_reports() {
    let fx = Fx::new();
    fx.create(None, "a", b"a");
    fx.create_dir(None, "d");
    fx.forget_exposure();
    let listing = fx.page(&[], None, 100);
    let a_id = listing.items.iter().find(|i| i.name == "a").unwrap().item_id;
    let anchor = listing.anchor;

    fx.peer_creates("c");
    let page = fx.changes(&ChangeScope::WorkingSet, anchor, 100);
    assert_eq!(names_of(&page.upserts), ["c"], "a create under an opened folder was not reported");
    assert!(!page.more);
    assert_eq!(page.next_anchor, fx.revision());
    let c_id = page.upserts[0].item_id;
    assert!(fx.published_of(&c_id).is_some(), "a first-reported item was not published");
    assert!(fx.changes(&ChangeScope::WorkingSet, page.next_anchor, 100).upserts.is_empty());

    fx.peer_deletes("c");
    let page = fx.changes(&ChangeScope::WorkingSet, page.next_anchor, 100);
    assert_eq!(page.removed, [c_id]);

    // `a` moves into `d`, which the OS never opened: it can no longer reach it.
    fx.rename_in_place("a", "d/a");
    let page = fx.changes(&ChangeScope::WorkingSet, page.next_anchor, 100);
    assert_eq!(page.removed, [a_id]);
    // Membership ended; the history of what was published did not.
    assert!(fx.published_of(&a_id).is_some(), "removal erased the published version");
    let exposed: bool = fx
        .db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT exposed FROM provider_items WHERE item_id = ?1",
                [&a_id[..]],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(!exposed, "a removed item stayed in the working set");
}

/// An item moved A -> B -> C is reported to each container by its CURRENT state, whatever order
/// the pages come in: removed from A and from B, an upsert in C.
#[test]
fn a_move_through_two_folders_converges_for_every_container() {
    let fx = Fx::new();
    for name in ["A", "B", "C"] {
        fx.create_dir(None, name);
    }
    fx.create(Some(fx.item_of("A")), "x", b"x");
    fx.forget_exposure();
    let root = fx.page(&[], None, 100);
    let ids: std::collections::BTreeMap<String, ItemId> =
        root.items.iter().map(|i| (i.name.clone(), i.item_id)).collect();
    for name in ["A", "B", "C"] {
        fx.page(&ids[name], None, 100); // opens (enumerates) every folder
    }
    let start = fx.revision();
    let x = fx.repo.item_for_path(&fx.root, "A/x").unwrap().unwrap();

    fx.rename_in_place("A/x", "B/x");
    fx.rename_in_place("B/x", "C/x");

    let in_a = fx.changes(&ChangeScope::Container(ids["A"].to_vec()), start, 100);
    let in_b = fx.changes(&ChangeScope::Container(ids["B"].to_vec()), start, 100);
    let in_c = fx.changes(&ChangeScope::Container(ids["C"].to_vec()), start, 100);
    assert_eq!((in_a.removed.clone(), in_a.upserts.len()), (vec![x], 0), "A still shows x");
    assert_eq!((in_b.removed.clone(), in_b.upserts.len()), (vec![x], 0), "B still shows x");
    assert_eq!(in_c.removed.len(), 0);
    assert_eq!(names_of(&in_c.upserts), ["x"]);
    // A container nothing touched costs nothing and reports nothing.
    let quiet = fx.changes(&ChangeScope::Container(ids["C"].to_vec()), fx.revision(), 100);
    assert!(quiet.upserts.is_empty() && quiet.removed.is_empty() && !quiet.more);
}

impl Fx {
    fn item_of(&self, path: &str) -> ItemId {
        self.repo.item_for_path(&self.root, path).unwrap().unwrap()
    }
}

/// A page boundary can split the events of one transaction; the anchor is the last event
/// consumed, so resuming from it never skips one and never repeats one.
#[test]
fn change_pages_split_by_events_without_skipping() {
    let fx = Fx::new();
    fx.create(None, "seed", b"s");
    fx.forget_exposure();
    let anchor = fx.page(&[], None, 100).anchor;
    // Five peer creates in ONE transaction: five events.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            for n in 0..5 {
                tx.execute(
                    "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
                     VALUES (?1, zeroblob(58), zeroblob(32))",
                    [GROUP],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                     version_seq, state, native_authoring_identity) \
                     VALUES (?1, ?2, 0, 1, '[]', 0, 9, 'current', zeroblob(58))",
                    rusqlite::params![GROUP, format!("n{n}")],
                )?;
            }
            Ok(())
        })
        .unwrap();
    let mut seen = Vec::new();
    let mut since = anchor;
    let mut pages = 0;
    loop {
        let page = fx.changes(&ChangeScope::WorkingSet, since, 2);
        seen.extend(names_of(&page.upserts));
        since = page.next_anchor;
        pages += 1;
        if !page.more {
            break;
        }
    }
    seen.sort();
    assert_eq!(seen, ["n0", "n1", "n2", "n3", "n4"]);
    assert_eq!(pages, 3);
    assert_eq!(since, fx.revision());
}

/// Anchors: 0 is the valid initial anchor of a root with no events; one below the floor (after
/// pruning) or above the current revision is expired.
#[test]
fn anchors_outside_the_retained_range_are_expired() {
    let fx = Fx::new();
    fx.create(None, "a", b"a");
    fx.forget_exposure();
    // A root with no events: 0 is valid and answers nothing.
    let empty = fx.changes(&ChangeScope::WorkingSet, 0, 10);
    assert!(empty.upserts.is_empty() && !empty.more && empty.next_anchor == 0);

    fx.page(&[], None, 10);
    fx.peer_creates("b");
    fx.peer_creates("c");
    assert!(fx.revision() >= 3);
    let current = fx.revision();
    assert!(matches!(
        fx.repo.enumerate_changes(&fx.root, &ChangeScope::WorkingSet, current + 1, 10, 1000),
        Err(ChangesError::AnchorExpired)
    ));
    // Pruning only from the front raises the floor; an anchor below it is expired.
    assert_eq!(fx.repo.prune_change_events(&fx.root, 1, 0).unwrap() as u64, current - 1);
    assert!(matches!(
        fx.repo.enumerate_changes(&fx.root, &ChangeScope::WorkingSet, 0, 10, 1000),
        Err(ChangesError::AnchorExpired)
    ));
    assert!(fx
        .repo
        .enumerate_changes(&fx.root, &ChangeScope::WorkingSet, current - 1, 10, 1000)
        .is_ok());
}

/// A walk of the working set is closed by the change feed: an item first shown by a listing AFTER
/// the walk's first page (possibly with an id below the cursor) has a first-publication event
/// above the walk's anchor, so `changes since anchor` restores it. The walk is keyset by id and
/// bounded by count.
#[test]
fn a_working_set_walk_is_repaired_by_changes_since_its_anchor() {
    let fx = Fx::new();
    for name in ["a", "b", "c"] {
        fx.create(None, name, name.as_bytes());
    }
    fx.create_dir(None, "d");
    fx.create(Some(fx.item_of("d")), "late", b"l");
    fx.forget_exposure();
    fx.page(&[], None, 100); // a, b, c, d exposed
    let first = fx.repo.enumerate_working_set(&fx.root, None, 2, 256 * 1024).unwrap();
    assert_eq!(first.items.len(), 2);
    let walk_anchor = first.anchor;
    let after = first.next_after.expect("more follow");

    // While the walk is between pages, the user opens `d`: `late` is shown for the first time.
    let d = fx.item_of("d");
    fx.page(&d, None, 100);

    let mut walked = names_of(&first.items);
    let mut cursor = Some(after);
    while let Some(after) = cursor {
        let page = fx.repo.enumerate_working_set(&fx.root, Some(&after), 2, 256 * 1024).unwrap();
        walked.extend(names_of(&page.items));
        cursor = page.next_after;
    }
    let repaired = fx.changes(&ChangeScope::WorkingSet, walk_anchor, 100);
    let mut all: std::collections::BTreeSet<String> = walked.into_iter().collect();
    all.extend(names_of(&repaired.upserts));
    for expected in ["a", "b", "c", "d", "late"] {
        assert!(all.contains(expected), "{expected} is missing after the walk and its repair");
    }
    assert!(names_of(&repaired.upserts).contains(&"late".to_string()));
}

/// Opening an EMPTY folder is recorded the first time (so a first child created later is logged),
/// and once recorded a repeat open takes no write.
#[test]
fn an_empty_folder_is_recorded_when_first_opened() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    fx.forget_exposure();
    let root = fx.page(&[], None, 10);
    let d_id = root.items[0].item_id;
    let _ = d;
    let empty = fx.page(&d_id, None, 10);
    assert!(empty.items.is_empty());
    assert_eq!(fx.count("provider_enumerated_parents"), 2, "the empty folder was not recorded");
    let writes = fx.db.write_transaction_count();
    assert!(fx.page(&d_id, None, 10).items.is_empty());
    assert_eq!(fx.db.write_transaction_count(), writes, "a repeat open of an empty folder wrote");

    // A first child created by a peer afterwards is logged, and reported to the working set.
    fx.peer_creates("d/first");
    let page = fx.changes(&ChangeScope::WorkingSet, empty.anchor, 10);
    // The folder's own new token is told too: its child set changed.
    assert_eq!(names_of(&page.upserts), ["first", "d"]);
}

/// A rebootstrap carries the completed-install marker to the new root only when the same
/// namespace is completely built; with an open obligation the new root waits for its install.
#[test]
fn a_rebootstrap_carries_the_install_marker_only_for_a_completely_built_namespace() {
    let fx = Fx::new();
    fx.create(None, "a", b"a");
    fx.repo.project_batch(GROUP, 100).unwrap();
    assert_eq!(fx.repo.open_obligations(GROUP).unwrap(), 0);
    let marker = |root: &str| -> bool {
        fx.db
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(
                    "SELECT install_done FROM provider_roots WHERE root_id = ?1",
                    [root],
                    |r| r.get(0),
                )?)
            })
            .unwrap()
    };
    let carried = fx.repo.rebootstrap_root(GROUP).unwrap();
    assert!(marker(&carried), "a completely built namespace lost its install marker");
    assert_eq!(fx.repo.verify_namespace(GROUP).unwrap(), None);

    // A root whose install was never recorded passes nothing on, even with no open obligation.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("UPDATE provider_roots SET install_done = 0", [])?;
            Ok(())
        })
        .unwrap();
    let never_installed = fx.repo.rebootstrap_root(GROUP).unwrap();
    assert!(!marker(&never_installed), "an uninstalled root passed a marker on");
    fx.repo.mark_install_done(&never_installed).unwrap();

    // An open obligation: the namespace is not completely built, so nothing is carried.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx,
                GROUP,
                &["a"],
                1,
            )?;
            Ok(())
        })
        .unwrap();
    let not_carried = fx.repo.rebootstrap_root(GROUP).unwrap();
    assert!(!marker(&not_carried));
}

// ---- retiring a displaced placement (M3) ----

impl Fx {}

/// A flat level of many names is projected in one pass over its plan, not one pass per name.
#[test]
fn a_flat_batch_visits_each_plan_node_once() {
    let fx = Fx::new();
    for n in 0..60 {
        fx.create(None, &format!("f{n:03}"), b"x");
    }
    let names: Vec<String> = (0..60).map(|n| format!("f{n:03}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    fx.forget_rows_and_arm(&refs);
    assert_eq!(fx.repo.project_batch(GROUP, 100).unwrap(), 60);
    assert_eq!(fx.live_paths().len(), 60);
    assert_eq!(fx.repo.verify_namespace(GROUP).unwrap(), None);
}

// ---- what we MAY HAVE served, and the trust predicate ----

use crate::provider_provenance::{edit_base_trusted, ProvenanceInput, Served};

fn input_with(served: Served) -> ProvenanceInput {
    ProvenanceInput {
        base: Some(VersionHash([2; 32])),
        current: VersionHash([2; 32]),
        base_content_sig: Some("v2".into()),
        item_generation: 4,
        base_generation: Some(4),
        announce_in_flight: false,
        served,
    }
}

/// THE predicate, exactly: trusted only for `Single(base content)` with the generation, base and
/// announcement conditions. `Never` is NOT trusted (absence of a record is never positive
/// evidence) and `Mixed` is not; nothing but committed state is an input.
#[test]
fn the_trust_predicate_is_exactly_single_of_the_base_with_a_current_view() {
    let single = Served::Single("v2".into());
    assert!(edit_base_trusted(&input_with(single.clone())));
    assert!(!edit_base_trusted(&input_with(Served::Never)), "no record was trusted");
    assert!(!edit_base_trusted(&input_with(Served::Mixed)));
    assert!(!edit_base_trusted(&input_with(Served::Single("v1".into()))), "other content served");
    let mut unknown = input_with(single.clone());
    unknown.base_generation = None;
    assert!(!edit_base_trusted(&unknown), "an unknown generation was trusted by the hash alone");
    let mut stale = input_with(single.clone());
    stale.base_generation = Some(3);
    assert!(!edit_base_trusted(&stale));
    let mut not_current = input_with(single.clone());
    not_current.current = VersionHash([3; 32]);
    assert!(!edit_base_trusted(&not_current));
    let mut pending = input_with(single.clone());
    pending.announce_in_flight = true;
    assert!(!edit_base_trusted(&pending));
    let mut unknown_base = input_with(single.clone());
    unknown_base.base_content_sig = None;
    assert!(!edit_base_trusted(&unknown_base));
    let mut no_base = input_with(single);
    no_base.base = None;
    assert!(!edit_base_trusted(&no_base), "an absent base was trusted");
}

impl Fx {
    /// The oracle of every untrusted edit: the user's bytes exist as a file beside `canonical`
    /// (a conflict copy of it), as a live row with exactly those bytes.
    fn kept_beside(&self, canonical: &str, bytes: &[u8]) -> bool {
        let stem = canonical.strip_suffix(".txt").unwrap_or(canonical);
        self.live_paths().iter().any(|p| {
            p.starts_with(stem)
                && p.contains("(conflicted copy, local")
                && self.row_version(p) == Some(version_of(bytes))
        })
    }

    fn modify_content(&self, item: ItemId, bytes: &[u8]) -> ApplyResult {
        self.modify(item, bytes, BaseVersion::Unknown).unwrap()
    }

    fn served(&self, item: &ItemId) -> Served {
        self.repo.served(&self.root, item).unwrap()
    }

    fn sig_of(&self, path: &str) -> String {
        self.db
            .read::<_, SyncSqliteError>(|conn| {
                let v = crate::provider::current_version(conn, GROUP, path)?.unwrap();
                Ok(crate::provider_provenance::content_sig(&v))
            })
            .unwrap()
    }

    fn serve(&self, item: &ItemId, version: VersionHash) -> bool {
        self.repo.record_may_serve(&self.root, item, version).unwrap().is_some()
    }
}

/// (1) The same content handed any number of times stays Single; our own create is Single too.
#[test]
fn the_same_content_served_again_and_again_stays_single() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"content A").item_id;
    let v = fx.row_version("a").unwrap();
    assert_eq!(
        fx.served(&item),
        Served::Single(fx.sig_of("a")),
        "a create is Single of its content"
    );
    for _ in 0..20 {
        assert!(fx.serve(&item, v));
    }
    assert_eq!(fx.served(&item), Served::Single(fx.sig_of("a")));
}

/// (2) and (3) A then B is Mixed forever: later handoffs of anything (the first content again, many
/// distinct contents, more than any bounded history would keep) never bring it back.
#[test]
fn different_content_served_makes_the_item_mixed_forever() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"content A").item_id;
    let b = fx.peer_updates("a", 50);
    assert!(fx.serve(&item, b));
    assert_eq!(fx.served(&item), Served::Mixed);
    // More than eight further distinct handoffs.
    for seq in 60..80 {
        let v = fx.peer_updates("a", seq);
        assert!(fx.serve(&item, v));
        assert_eq!(fx.served(&item), Served::Mixed, "forgot an old different content at {seq}");
    }
}

/// (6) Concurrent handoffs of different contents can never lose an update: whatever the
/// interleaving, the result is Mixed (one UPDATE with CASE, never read-modify-write in code).
#[test]
fn concurrent_handoffs_of_different_content_always_end_mixed() {
    for round in 0..40 {
        let fx = Fx::new();
        let item = fx.create(None, &format!("f{round}"), b"seed").item_id;
        let repo = || ProviderRepository::new(fx.db.clone());
        std::thread::scope(|scope| {
            for content in ["content-a", "content-b", "content-a", "content-b"] {
                let (repo, root) = (repo(), fx.root.clone());
                scope.spawn(move || {
                    repo.record_served_sig_for_tests(&root, &item, content).unwrap()
                });
            }
        });
        // The create's own content "seed" plus two others: never Single.
        assert_eq!(fx.served(&item), Served::Mixed, "round {round}");
    }
}

/// (4) and (8) Provenance is a row: it survives the process (a file-backed database closed and
/// reopened) with no help from any host state.
#[test]
fn what_we_may_have_served_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    let open = || {
        std::sync::Arc::new(
            SyncDatabase::open(&path, |conn| {
                crate::init_replica_schema(conn).map_err(|e| {
                    yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
                })
            })
            .unwrap(),
        )
    };
    let (root, item, sig) = {
        let db = open();
        LinkRepository::new(db.clone()).add_link("/provider/p", GROUP).unwrap();
        let repo = ProviderRepository::new(db.clone());
        let root = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "P").unwrap();
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, 'p', 0, 9, '[]', 0, 7, 'current')",
                [GROUP],
            )?;
            let version = crate::provider::current_version(tx, GROUP, "p")?.unwrap();
            crate::dag_store::put_file_version(tx, GROUP, &version)?;
            Ok(())
        })
        .unwrap();
        let item = repo.mint_item(&root, "p").unwrap();
        let v = repo.current_version_hash(&root, &item).unwrap().unwrap();
        assert!(repo.record_may_serve(&root, &item, v).unwrap().is_some());
        let sig = match repo.served(&root, &item).unwrap() {
            Served::Single(sig) => sig,
            other => panic!("{other:?}"),
        };
        (root, item, sig)
    };
    // The process "restarts": a new database handle over the same file.
    let db = open();
    let repo = ProviderRepository::new(db);
    assert_eq!(repo.served(&root, &item).unwrap(), Served::Single(sig));
}

/// (9) An item nothing was ever served for has NO record, and that is not trust: the edit is kept
/// beside the file, never authored over it.
#[test]
fn an_item_with_no_record_is_untrusted() {
    let fx = Fx::new();
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, 'p', 0, 9, '[]', 0, 7, 'current')",
                [GROUP],
            )?;
            let version = crate::provider::current_version(tx, GROUP, "p")?.unwrap();
            crate::dag_store::put_file_version(tx, GROUP, &version)?;
            Ok(())
        })
        .unwrap();
    let item = fx.repo.mint_item(&fx.root, "p").unwrap();
    let v = fx.row_version("p").unwrap();
    fx.repo.publish_first(&fx.root, &item, v).unwrap();
    assert_eq!(fx.served(&item), Served::Never);
    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"typed over an item nobody served"));
    edit.base = BaseVersion::Opaque(v);
    edit.base_generation = Some(item_generation_of(&fx, &item));
    let result = fx.run_raw(&edit).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Concurrent, "an unserved item was edited in place");
    assert_eq!(fx.row_version("p"), Some(v), "the canonical version was overwritten");
    assert!(fx.kept_beside("p", b"typed over an item nobody served"));
}

/// A trusted edit replaces the summary with the content it wrote (the OS now holds exactly that);
/// a Mixed item is never reset by an authored write (its edits are kept beside it).
#[test]
fn authored_writes_set_single_and_never_reset_mixed() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"one").item_id;
    fx.modify_content(item, b"two");
    assert_eq!(fx.served(&item), Served::Single(fx.sig_of("a")));
    let v2 = fx.peer_updates("a", 50);
    assert!(fx.serve(&item, v2));
    assert_eq!(fx.served(&item), Served::Mixed);
    // A modify of the mixed item is untrusted: kept beside, the item stays mixed.
    let _ = fx.modify(item, b"three", BaseVersion::Opaque(v2)).unwrap();
    assert_eq!(fx.served(&item), Served::Mixed);
}

// ---- generations: an operation is authored only against a known, current view (Q4) ----

fn stale_view<T: std::fmt::Debug>(result: Result<T, ApplyError>) -> bool {
    matches!(result, Err(ApplyError::StaleView(_)))
}

/// The oracle of an edit on an unknown or stale view: canonical unchanged AND the user's bytes
/// exist as a conflict copy beside it (a content edit is never refused with its bytes dropped).
fn assert_bytes_kept(
    fx: &Fx,
    result: Result<ApplyResult, ApplyError>,
    path: &str,
    canonical: Option<VersionHash>,
    bytes: &[u8],
    why: &str,
) {
    let result = result.unwrap_or_else(|e| panic!("{why}: {e:?}"));
    assert_eq!(result.outcome, OutcomeKind::Concurrent, "{why}");
    assert_eq!(fx.row_version(path), canonical, "{why}: canonical changed");
    assert!(fx.kept_beside(path, bytes), "{why}: bytes lost: {:?}", fx.live_paths());
}

/// An edit that names no generation (unknown) or an old one never changes the canonical version:
/// its bytes are kept beside it. The current view is accepted as an ordinary edit.
#[test]
fn an_edit_of_an_unknown_or_stale_generation_keeps_its_bytes_beside() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"one").item_id;
    let one = fx.row_version("a");
    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"two"));
    assert_bytes_kept(&fx, fx.run_raw(&edit), "a", one, b"two", "no generation");
    // Stale: the item moved on (a second edit advanced its generation).
    let old = item_generation_of(&fx, &item);
    fx.modify_content(item, b"newer");
    let newer = fx.row_version("a");
    edit.content = Some(content(b"three"));
    edit.base_generation = Some(old);
    edit.operation_seq += 50;
    assert_bytes_kept(&fx, fx.run_raw(&edit), "a", newer, b"three", "old generation");
    // The current view is accepted.
    edit.content = Some(content(b"four"));
    edit.base = BaseVersion::Opaque(newer.unwrap());
    edit.base_generation = Some(item_generation_of(&fx, &item));
    edit.operation_seq += 50;
    assert_eq!(fx.run_raw(&edit).unwrap().outcome, OutcomeKind::Applied);
}

/// The folder's PLACE generation: its generation without child-set changes.
fn place_generation_of(fx: &Fx, item: &ItemId) -> u64 {
    fx.db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT generation - child_bumps FROM provider_items WHERE item_id = ?1",
                [&item[..]],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
        .unwrap()
}

fn item_generation_of(fx: &Fx, item: &ItemId) -> u64 {
    fx.db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT generation FROM provider_items WHERE item_id = ?1",
                [&item[..]],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
        .unwrap()
}

/// A create or move destination is a stable IDENTITY (the folder's item id): when the folder was
/// renamed or replaced meanwhile, the operation lands in the CURRENT folder of that identity, and a
/// destination that is retired or unknown refuses (and keeps the bytes). Collisions and
/// "never replace" still hold.
#[test]
fn a_create_into_a_renamed_folder_lands_in_the_current_destination() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    fx.rename(d.item_id, None, "e").unwrap();

    let mut create = fx.input(ChangeKind::Create);
    create.new_parent = Some(Some(d.item_id));
    create.name = Some("x".into());
    create.parent_generation = None;
    let created = fx.run_raw(&create).unwrap();
    assert_eq!(created.outcome, OutcomeKind::Applied);
    assert!(fx.live_paths().contains(&"e/x".to_owned()), "{:?}", fx.live_paths());

    // Never replace: the same name again is a collision, with or without bytes.
    let mut again = fx.input(ChangeKind::Create);
    again.new_parent = Some(Some(d.item_id));
    again.name = Some("x".into());
    assert!(is_collision(fx.run_raw(&again)));

    // A destination that is retired (replaced by a new identity) refuses: no bytes, NotFound.
    fx.delete(d.item_id, BaseVersion::Unknown, true).unwrap();
    let mut gone = fx.input(ChangeKind::Create);
    gone.new_parent = Some(Some(d.item_id));
    gone.name = Some("y".into());
    assert!(matches!(fx.run_raw(&gone), Err(ApplyError::NotFound(_))));
    // With bytes, they are kept as a conflict-named file at the root.
    let mut with_bytes = fx.input(ChangeKind::Create);
    with_bytes.new_parent = Some(Some(d.item_id));
    with_bytes.name = Some("z.txt".into());
    with_bytes.content = Some(content(b"bytes for a retired destination"));
    assert_eq!(fx.run_raw(&with_bytes).unwrap().outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("z.txt", b"bytes for a retired destination"), "{:?}", fx.live_paths());
}

/// A pure move is a namespace command on the item's identity: it needs neither the item's own
/// generation nor the place generation of the folder it leaves.
#[test]
fn a_pure_move_needs_no_view_of_the_item_or_of_the_folder_it_leaves() {
    let fx = Fx::new();
    let from = fx.create_dir(None, "from");
    let to = fx.create_dir(None, "to");
    let f = fx.create(Some(from.item_id), "f", b"f").item_id;
    let from_g = place_generation_of(&fx, &from.item_id);
    let mut input = fx.input(ChangeKind::Modify);
    input.item_id = Some(f);
    input.new_parent = Some(Some(to.item_id));
    input.metadata = MetadataInput::default();
    input.base = BaseVersion::Unknown;
    input.base_generation = Some(item_generation_of(&fx, &f) + 7);
    input.parent_generation = Some(from_g + 5);
    input.observed_revision = Some(0);
    let ok = fx.run_raw(&input);
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(fx.live_paths(), ["from", "to", "to/f"]);
}

/// (f) A MIXED modify (a move together with bytes) is not structural-only: it keeps the strict path
/// exactly as before. Here the item's own view is current but the folder it leaves is stale: the
/// change does not apply as an edit-and-move; nothing moves and the user's bytes are kept beside.
#[test]
fn a_move_together_with_bytes_from_a_stale_folder_view_does_not_apply() {
    let fx = Fx::new();
    let from = fx.create_dir(None, "from");
    let to = fx.create_dir(None, "to");
    let item = fx.create(Some(from.item_id), "a", b"one").item_id;
    let current = fx.row_version("from/a").unwrap();
    let mut input = fx.input(ChangeKind::Modify);
    input.item_id = Some(item);
    input.new_parent = Some(Some(to.item_id));
    input.content = Some(content(b"mine"));
    input.base = BaseVersion::Opaque(current);
    input.base_generation = Some(item_generation_of(&fx, &item));
    input.parent_generation = Some(place_generation_of(&fx, &from.item_id) + 99);
    let result = fx.run_raw(&input);
    assert!(
        !matches!(&result, Ok(r) if r.outcome == OutcomeKind::Applied),
        "a mixed modify on a stale folder view applied: {result:?}"
    );
    assert!(
        !fx.live_paths().contains(&"to/a".to_string()),
        "moved on a stale view: {:?}",
        fx.live_paths()
    );
    assert_eq!(fx.row_version("from/a"), Some(current), "the canonical version changed");
}

/// (f2) A move that also carries replicated metadata (mode, mtime) is not structural-only either: on
/// a stale item generation it is refused as before (nothing moves).
#[test]
fn a_move_together_with_metadata_on_a_stale_generation_is_a_stale_view() {
    let fx = Fx::new();
    let to = fx.create_dir(None, "to");
    let item = fx.create(None, "a", b"one").item_id;
    let mut input = fx.input(ChangeKind::Modify);
    input.item_id = Some(item);
    input.new_parent = Some(Some(to.item_id));
    // `Fx::input` carries a mode and an mtime.
    input.base_generation = Some(item_generation_of(&fx, &item) + 99);
    assert!(stale_view(fx.run_raw(&input)));
    assert_eq!(fx.live_paths(), ["a", "to"], "moved on a stale view");
}

// ---- an mtime is advisory metadata (D18b) ----

fn mtime_of(fx: &Fx, path: &str) -> Option<i64> {
    fx.db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT mtime_unix_nanos FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current' AND deleted = 0",
                    [GROUP, path],
                    |r| r.get::<_, i64>(0),
                )
                .ok())
        })
        .unwrap()
}

fn unix_mode_of(fx: &Fx, path: &str) -> Option<i64> {
    fx.db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT unix_mode FROM files WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current' AND deleted = 0",
                    [GROUP, path],
                    |r| r.get::<_, i64>(0),
                )
                .ok())
        })
        .unwrap()
}

fn mtime_only(fx: &Fx, item: ItemId, base: VersionHash, generation: u64, mtime: i64) -> ApplyInput {
    let mut input = fx.input(ChangeKind::Modify);
    input.item_id = Some(item);
    input.metadata = MetadataInput { unix_mode: None, mtime_unix_nanos: Some(mtime), xattrs: None };
    input.base = BaseVersion::Opaque(base);
    input.base_generation = Some(generation);
    input
}

/// create V1 -> rename -> the OS's queued mtime-only modify, still naming V1 and the generation of
/// the create: the content is unchanged, so the mtime applies and nothing is refused.
#[test]
fn an_mtime_over_the_same_content_applies_whatever_the_generation() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"v1").item_id;
    let v1 = fx.row_version("a").unwrap();
    let echoed = item_generation_of(&fx, &item);
    fx.rename(item, None, "b").unwrap();
    assert_ne!(item_generation_of(&fx, &item), echoed);
    let result = fx.run_raw(&mtime_only(&fx, item, v1, echoed, 7_000_000_000));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(mtime_of(&fx, "b"), Some(7_000_000_000));
    assert_eq!(fx.live_paths(), ["b"]);
}

/// A remote edit makes V2 current: a stale mtime for V1 is DROPPED with a success, and V2's mtime
/// is kept.
#[test]
fn an_mtime_over_older_content_is_dropped_and_succeeds() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"v1").item_id;
    let v1 = fx.row_version("a").unwrap();
    let generation = item_generation_of(&fx, &item);
    let v2 = fx.peer_updates("a", 50);
    assert_ne!(v1, v2);
    let v2_mtime = mtime_of(&fx, "a");
    let result = fx.run_raw(&mtime_only(&fx, item, v1, generation, 7_000_000_000));
    assert!(result.is_ok(), "a stale mtime must not be an error: {result:?}");
    assert_eq!(fx.row_version("a"), Some(v2), "the newer content was touched");
    assert_eq!(mtime_of(&fx, "a"), v2_mtime, "a stale mtime overwrote the newer one");
    // An unknown base cannot prove it is the same content: dropped too.
    let mut unknown = mtime_only(&fx, item, v1, generation, 8_000_000_000);
    unknown.base = BaseVersion::Unknown;
    assert!(fx.run_raw(&unknown).is_ok());
    assert_eq!(mtime_of(&fx, "a"), v2_mtime);
}

/// An mtime and a rename in one callback: the rename is by identity either way; the mtime applies
/// over the same content and is dropped over newer content.
#[test]
fn an_mtime_with_a_rename_renames_by_identity_and_follows_the_advisory_rule() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"v1").item_id;
    let v1 = fx.row_version("a").unwrap();
    let generation = item_generation_of(&fx, &item);
    let mut same = mtime_only(&fx, item, v1, generation + 9, 5_000_000_000);
    same.name = Some("b".into());
    assert!(fx.run_raw(&same).is_ok());
    assert_eq!(fx.live_paths(), ["b"]);
    assert_eq!(mtime_of(&fx, "b"), Some(5_000_000_000));

    let v2 = fx.peer_updates("b", 60);
    let v2_mtime = mtime_of(&fx, "b");
    let mut stale = mtime_only(&fx, item, v1, generation, 6_000_000_000);
    stale.name = Some("c".into());
    let result = fx.run_raw(&stale);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(fx.live_paths(), ["c"], "the rename must still happen");
    assert_eq!(fx.row_version("c"), Some(v2));
    assert_eq!(mtime_of(&fx, "c"), v2_mtime, "a stale mtime overwrote the newer one");
}

/// A peer's mode-only change makes the version hashes differ but not the content: a queued mtime-only
/// callback still applies (the content is the one the mtime was set on) and the peer's mode is kept.
#[test]
fn an_mtime_survives_a_peers_mode_only_change() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"v1").item_id;
    let v1 = fx.row_version("a").unwrap();
    let generation = item_generation_of(&fx, &item);
    let v1_mode = fx.peer_changes_mode("a", 70, 0o600);
    assert_ne!(v1, v1_mode, "the mode change must change the version hash");
    let result = fx.run_raw(&mtime_only(&fx, item, v1, generation, 7_000_000_000));
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(mtime_of(&fx, "a"), Some(7_000_000_000), "the user's mtime was dropped");
    assert_eq!(unix_mode_of(&fx, "a"), Some(0o600), "the peer's mode was reverted");
}

/// Mode and xattrs are semantic: stale ones are refused exactly as before.
#[test]
fn a_stale_mode_only_or_xattr_only_modify_is_still_refused() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"v1").item_id;
    let v1 = fx.row_version("a").unwrap();
    let stale = item_generation_of(&fx, &item) + 9;
    let mut mode = mtime_only(&fx, item, v1, stale, 0);
    mode.metadata = MetadataInput { unix_mode: Some(0o600), mtime_unix_nanos: None, xattrs: None };
    assert!(stale_view(fx.run_raw(&mode)));
    let mut xattr = mtime_only(&fx, item, v1, stale, 0);
    xattr.metadata = MetadataInput {
        unix_mode: None,
        mtime_unix_nanos: None,
        xattrs: Some(vec![("user.k".into(), b"v".to_vec())]),
    };
    assert!(stale_view(fx.run_raw(&xattr)));
    // An mtime that rides with a mode is not advisory either.
    let mut both = mtime_only(&fx, item, v1, stale, 1_000);
    both.metadata.unix_mode = Some(0o600);
    assert!(stale_view(fx.run_raw(&both)));
}

/// The create, rename, move sequence: a create, then a rename, then a move, each with the generation the OS
/// echoed from the previous answer's predecessor, all succeed.
#[test]
fn a_create_then_a_rename_then_a_move_succeeds_with_the_echoed_generations() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d1");
    let f = fx.create(None, "new.txt", b"hello").item_id;
    let echoed = item_generation_of(&fx, &f);
    let mut rename = fx.input(ChangeKind::Modify);
    rename.item_id = Some(f);
    rename.name = Some("renamed.txt".into());
    rename.metadata = MetadataInput::default();
    rename.base_generation = Some(echoed);
    assert!(fx.run_raw(&rename).is_ok());
    assert_ne!(item_generation_of(&fx, &f), echoed);
    let mut mv = fx.input(ChangeKind::Modify);
    mv.item_id = Some(f);
    mv.new_parent = Some(Some(d.item_id));
    mv.metadata = MetadataInput::default();
    mv.base_generation = Some(echoed);
    let moved = fx.run_raw(&mv);
    assert!(moved.is_ok(), "{moved:?}");
    assert_eq!(fx.live_paths(), ["d1", "d1/renamed.txt"]);
}

/// The domain revision the OS observed is a hint that only tightens: an operation issued before the
/// announcement of the item's current version is a stale view; an absent revision changes nothing.
#[test]
fn an_observed_revision_before_the_announcement_only_tightens_content_edits() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"a").item_id;
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE provider_items SET announce_version_hash = x'00', announce_seq = 50",
                [],
            )?;
            Ok(())
        })
        .unwrap();
    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"b"));
    edit.base_generation = Some(item_generation_of(&fx, &item));
    edit.observed_revision = Some(49);
    // A content edit is kept beside (never refused with its bytes dropped).
    assert_bytes_kept(
        &fx,
        fx.run_raw(&edit),
        "a",
        fx.row_version("a"),
        b"b",
        "before the announcement",
    );
    // A pure rename acts on the item's identity: the observed revision is irrelevant to it.
    let mut rename = fx.input(ChangeKind::Modify);
    rename.item_id = Some(item);
    rename.name = Some("z".into());
    rename.metadata = MetadataInput::default();
    rename.base = BaseVersion::Opaque(fx.row_version("a").unwrap());
    rename.base_generation = Some(item_generation_of(&fx, &item));
    rename.observed_revision = Some(49);
    assert!(!stale_view(fx.run_raw(&rename)));
}

/// Working-set membership is separate from the history of what was published and handed: an item
/// that leaves the working set keeps its published version and its ledger, and when it is shown
/// again with a newer current version it is PENDING again, not freshly consistent.
#[test]
fn leaving_the_working_set_never_erases_the_publication_history() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    let f = fx.create(None, "f", b"one").item_id;
    fx.forget_exposure();
    let listing = fx.page(&[], None, 100);
    let f_item = listing.items.iter().find(|i| i.name == "f").unwrap().item_id;
    let _ = (d, f);
    // The OS was handed V1's bytes (confirmed), then V2 became current (a peer's update).
    let v1 = fx.repo.current_version_hash(&fx.root, &f_item).unwrap().unwrap();
    assert!(fx.repo.record_may_serve(&fx.root, &f_item, v1).unwrap().is_some());
    let served_v1 = fx.served(&f_item);
    assert!(matches!(served_v1, Served::Single(_)));
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = 'f' \
                 AND state = 'current'",
                [GROUP],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
                 VALUES (?1, zeroblob(58), zeroblob(32))",
                [GROUP],
            )?;
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state, native_authoring_identity) \
                 VALUES (?1, 'f', 0, 5, '[]', 0, 50, 'current', zeroblob(58))",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
    // `f` moves into a folder nobody opened: the working-set report removes it.
    let anchor = listing.anchor;
    fx.rename_in_place("f", "d/f");
    let page = fx.changes(&ChangeScope::WorkingSet, anchor, 100);
    assert_eq!(page.removed, [f_item]);
    let published = |fx: &Fx| fx.published_of(&f_item);
    assert_eq!(published(&fx), Some(v1.0.to_vec()), "removal erased the published version");
    assert_eq!(fx.served(&f_item), served_v1, "removal erased what we served");

    // Opening `d` shows it again: still pending (V1 published, the newer version current).
    let d_id = fx.item_of("d");
    let shown = fx.page(&d_id, None, 100);
    assert_eq!(Fx::names(&shown), ["f"]);
    assert_eq!(published(&fx), Some(v1.0.to_vec()), "re-exposure made the item freshly consistent");
    assert!(shown.items[0].content_pending, "a stale item looked consistent");
}

// ---- the fence is UX only: releasing it at any point never lets a stale edit overwrite ----

#[derive(Clone, Copy, Debug)]
enum Step {
    Announce,
    TimerRelease,
    HandoffOfV2,
    MarkPublished,
}

impl Fx {
    /// A peer's update of `path`: a new current row with another content (no authoring through
    /// this device, so the ledger never saw it).
    fn peer_updates(&self, path: &str, seq: i64) -> VersionHash {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    [GROUP, path],
                )?;
                // A peer's row is vouched for by a verified identity: the group has native
                // history, so an unauthored current row is refused.
                tx.execute(
                    "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
                     VALUES (?1, zeroblob(58), zeroblob(32))",
                    [GROUP],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, native_authoring_identity) \
                     VALUES (?1, ?2, 0, 9, '[]', 0, ?3, 'current', zeroblob(58))",
                    rusqlite::params![GROUP, path, seq],
                )?;
                let version = crate::provider::current_version(tx, GROUP, path)?
                    .expect("the row just written");
                crate::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
        self.row_version(path).unwrap()
    }

    /// A peer's MODE-only change: a new current row with the same bytes and another unix mode.
    fn peer_changes_mode(&self, path: &str, seq: i64, mode: i64) -> VersionHash {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, unix_mode, native_authoring_identity) \
                     SELECT group_id, path, size, mtime_unix_nanos, blocks_json, 0, ?3, 'new', ?4, \
                            native_authoring_identity \
                     FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params![GROUP, path, seq, mode],
                )?;
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    [GROUP, path],
                )?;
                tx.execute(
                    "UPDATE files SET state = 'current' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'new'",
                    [GROUP, path],
                )?;
                let version = crate::provider::current_version(tx, GROUP, path)?
                    .expect("the row just written");
                crate::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
        self.row_version(path).unwrap()
    }

    fn do_step(&self, step: Step, item: &ItemId, v2: VersionHash) {
        match step {
            Step::Announce => {
                let _ = self.repo.announce_version(&self.root, item, v2, 1_000).unwrap();
            }
            Step::TimerRelease => {
                let _ = self.repo.release_expired(&self.root, item, i64::MAX / 2, 0).unwrap();
            }
            Step::HandoffOfV2 => {
                let _ = self.repo.record_may_serve(&self.root, item, v2).unwrap();
            }
            Step::MarkPublished => {
                let _ = self.repo.publish_for_tests(&self.root, item, v2).unwrap();
            }
        }
    }
}

fn orderings(steps: &[Step]) -> Vec<Vec<Step>> {
    // Every ordering of every subset (the fence may be released at any point, or never).
    let mut all = vec![Vec::new()];
    fn extend(prefix: Vec<Step>, left: &[Step], all: &mut Vec<Vec<Step>>) {
        for (i, step) in left.iter().enumerate() {
            let mut next = prefix.clone();
            next.push(*step);
            all.push(next.clone());
            let mut rest = left.to_vec();
            rest.remove(i);
            extend(next, &rest, all);
        }
    }
    extend(Vec::new(), steps, &mut all);
    all
}

/// THE ORACLE, run against a LYING OS: the item's bytes were handed as V1, a peer made V2 current,
/// the OS still serves V1 pages under V2 metadata and reports the CURRENT generation and base V2.
/// Whatever subset of {announce, timer release, a handoff of V2, publication} has happened, in
/// any order (the fence released early at every point), the user's edit is never authored over
/// V2: V2 stays canonical AND the edit is kept (KEEP_LOCAL: the bytes stay with the user).
#[test]
fn releasing_the_fence_at_every_point_never_lets_a_stale_edit_overwrite() {
    let steps = [Step::Announce, Step::TimerRelease, Step::HandoffOfV2, Step::MarkPublished];
    for order in orderings(&steps) {
        let fx = Fx::new();
        let item = fx.create(None, "a", b"stale bytes the OS still serves").item_id;
        let v2 = fx.peer_updates("a", 50);
        for step in &order {
            fx.do_step(*step, &item, v2);
        }
        let heads = fx.count("native_heads");
        let log = fx.count("provider_apply_log");
        let generation = item_generation_of(&fx, &item);

        let mut edit = fx.input(ChangeKind::Modify);
        edit.item_id = Some(item);
        edit.content = Some(content(b"the user's edit of the STALE bytes"));
        edit.base = BaseVersion::Opaque(v2);
        edit.base_generation = Some(generation);
        let result =
            fx.run_raw(&edit).unwrap_or_else(|e| panic!("after {order:?} the edit failed: {e:?}"));

        // V2 stays canonical AND the user's bytes survive beside it.
        assert_eq!(result.outcome, OutcomeKind::Concurrent, "after {order:?}");
        assert_eq!(fx.row_version("a"), Some(v2), "after {order:?} V2 did not stay canonical");
        assert_eq!(fx.heads_at("a"), 1, "after {order:?} the edit became a head of the path");
        assert!(
            fx.kept_beside("a", b"the user's edit of the STALE bytes"),
            "after {order:?} the user's bytes were lost: {:?}",
            fx.live_paths()
        );
        assert_eq!(fx.count("native_heads"), heads + 1, "after {order:?}");
        assert_eq!(fx.count("provider_apply_log"), log + 1, "after {order:?}");
    }
}

/// The control: where our state PROVES provenance (nothing but V2's content was ever handed, or
/// the base was authored by this device) the same edit IS authored in place, so the oracle above
/// is not satisfied by refusing everything.
#[test]
fn an_edit_with_provable_provenance_is_authored_in_place() {
    let fx = Fx::new();
    // A peer's file the OS was handed once (V2 content only).
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, 'p', 0, 9, '[]', 0, 7, 'current')",
                [GROUP],
            )?;
            let version =
                crate::provider::current_version(tx, GROUP, "p")?.expect("the row just written");
            crate::dag_store::put_file_version(tx, GROUP, &version)?;
            Ok(())
        })
        .unwrap();
    let item = fx.repo.mint_item(&fx.root, "p").unwrap();
    let v = fx.row_version("p").unwrap();
    fx.repo.publish_first(&fx.root, &item, v).unwrap();
    assert!(fx.repo.record_may_serve(&fx.root, &item, v).unwrap().is_some());
    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"typed after opening"));
    edit.base = BaseVersion::Opaque(v);
    edit.base_generation = Some(item_generation_of(&fx, &item));
    assert!(fx.run_raw(&edit).is_ok(), "an edit with provable provenance was refused");
}

// ---- the bytes of an untrusted edit are kept beside the item ----

fn untrusted(fx: &Fx, item: ItemId, bytes: &[u8]) -> Result<ApplyResult, ApplyError> {
    fx.modify(item, bytes, BaseVersion::Opaque(VersionHash([77u8; 32])))
}

/// The same bytes kept twice make one file; different bytes take their own file; a rename or a
/// metadata-only edit has no bytes to keep and authors nothing; the count is kept per root.
#[test]
fn kept_edits_are_deduplicated_counted_and_never_carry_a_rename() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"canonical").item_id;
    untrusted(&fx, item, b"first draft").unwrap();
    untrusted(&fx, item, b"first draft").unwrap();
    untrusted(&fx, item, b"second draft").unwrap();
    assert!(fx.kept_beside("a.txt", b"first draft"));
    assert!(fx.kept_beside("a.txt", b"second draft"));
    assert_eq!(fx.live_paths().len(), 3, "{:?}", fx.live_paths());
    assert_eq!(fx.row_version("a.txt"), Some(version_of(b"canonical")));
    let kept: i64 = fx
        .db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row("SELECT kept_edits FROM provider_roots", [], |r| r.get(0))?)
        })
        .unwrap();
    assert_eq!(kept, 2, "the repeated edit was counted twice");

    // The same bytes as the canonical version keep nothing.
    untrusted(&fx, item, b"canonical").unwrap();
    assert_eq!(fx.live_paths().len(), 3);

    // A rename that came with an untrusted edit is not applied; the bytes are kept beside the file.
    let mut renamed = fx.input(ChangeKind::Modify);
    renamed.item_id = Some(item);
    renamed.name = Some("b.txt".into());
    renamed.content = Some(content(b"edit and rename"));
    renamed.base = BaseVersion::Opaque(VersionHash([77u8; 32]));
    assert_eq!(fx.run(&renamed).unwrap().outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("a.txt", b"edit and rename"));
    assert_eq!(fx.live_paths().len(), 4, "{:?}", fx.live_paths());
    // A metadata-only edit has no bytes to keep and authors nothing.
    let mut chmod = fx.input(ChangeKind::Modify);
    chmod.item_id = Some(item);
    chmod.metadata.unix_mode = Some(0o600);
    chmod.base = BaseVersion::Opaque(VersionHash([77u8; 32]));
    assert!(matches!(fx.run(&chmod), Err(ApplyError::KeepLocal { .. })));
    assert_eq!(fx.live_paths().len(), 4);
}

// ---- an ambiguous delete deletes nothing ----

/// A delete after a newer version became current while only the older content was ever served:
/// the OS may still show the old bytes, so the delete is ambiguous and the file survives.
#[test]
fn a_delete_of_content_other_than_what_was_served_leaves_the_file() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"served").item_id;
    let v2 = fx.peer_updates("a", 50);
    let _ = fx.repo.announce_version(&fx.root, &item, v2, 1_000).unwrap();
    let mut gone = fx.input(ChangeKind::Delete);
    gone.item_id = Some(item);
    gone.base = BaseVersion::Opaque(v2);
    gone.base_generation = Some(item_generation_of(&fx, &item));
    let result = fx.run_raw(&gone).unwrap();
    assert_eq!(result.outcome, OutcomeKind::FileSurvived);
    assert_eq!(fx.row_version("a"), Some(v2), "the newer version was deleted");

    // An unknown generation is never destructive either.
    let fx = Fx::new();
    let item = fx.create(None, "a", b"served").item_id;
    let mut gone = fx.input(ChangeKind::Delete);
    gone.item_id = Some(item);
    gone.base = BaseVersion::Unknown;
    gone.base_generation = None;
    let result = fx.run_raw(&gone).unwrap();
    assert_eq!(result.outcome, OutcomeKind::FileSurvived);
    assert!(fx.row_version("a").is_some(), "an unknown view deleted the file");
}

// ---- an absent base is unknown, never substituted ----

/// A callback that names no base (an old OS view) is not an edit of the published version: bytes
/// are kept beside the file, a metadata-only edit changes nothing, and a delete leaves the file.
#[test]
fn an_absent_base_is_unknown_for_edits_metadata_and_deletes() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"canonical").item_id;
    let v = fx.row_version("a.txt").unwrap();
    let generation = item_generation_of(&fx, &item);

    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"typed on an unnamed base"));
    edit.base = BaseVersion::Unknown;
    edit.base_generation = Some(generation);
    let result = fx.run_raw(&edit).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Concurrent);
    assert_eq!(fx.row_version("a.txt"), Some(v), "canonical was overwritten");
    assert!(fx.kept_beside("a.txt", b"typed on an unnamed base"));

    // Metadata alone (mode) on an unnamed base: canonical metadata is not replaced.
    let mut chmod = fx.input(ChangeKind::Modify);
    chmod.item_id = Some(item);
    chmod.metadata.unix_mode = Some(0o600);
    chmod.base = BaseVersion::Unknown;
    chmod.base_generation = Some(generation);
    assert!(matches!(fx.run_raw(&chmod), Err(ApplyError::KeepLocal { .. })));
    assert_eq!(fx.row_version("a.txt"), Some(v), "metadata replaced canonical");

    let mut gone = fx.input(ChangeKind::Delete);
    gone.item_id = Some(item);
    gone.base = BaseVersion::Unknown;
    gone.base_generation = Some(generation);
    assert_eq!(fx.run_raw(&gone).unwrap().outcome, OutcomeKind::FileSurvived);
    assert_eq!(fx.row_version("a.txt"), Some(v), "an unnamed base deleted the file");
}

// ---- a trusted edit starts a new provenance epoch; mixed is absorbing ----

/// (1)/(2) A@g -> trusted edit B@(g+1): the summary is Single(B) in the same transaction as the
/// generation, the next edit based on B@(g+1) is trusted, and a LATE callback naming A@g is a stale
/// view that changes nothing.
#[test]
fn a_trusted_edit_starts_the_next_epoch_and_a_late_callback_of_the_old_one_is_stale() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"A").item_id;
    let a = fx.row_version("a").unwrap();
    let g = item_generation_of(&fx, &item);
    assert_eq!(fx.served(&item), Served::Single(fx.sig_of("a")));

    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"B"));
    edit.base = BaseVersion::Opaque(a);
    edit.base_generation = Some(g);
    let applied = fx.run_raw(&edit).unwrap();
    assert_eq!(applied.outcome, OutcomeKind::Applied);
    let b = fx.row_version("a").unwrap();
    assert_eq!(b, version_of(b"B"));
    assert_eq!(
        item_generation_of(&fx, &item),
        g + 1,
        "the generation did not advance with the edit"
    );
    assert_eq!(fx.served(&item), Served::Single(fx.sig_of("a")), "the epoch did not start");

    // The late callback of the old epoch.
    let mut late = fx.input(ChangeKind::Modify);
    late.item_id = Some(item);
    late.content = Some(content(b"typed on A late"));
    late.base = BaseVersion::Opaque(a);
    late.base_generation = Some(g);
    assert_bytes_kept(&fx, fx.run_raw(&late), "a", Some(b), b"typed on A late", "late callback");

    // The next edit names B at g+1 and is trusted.
    let mut next = fx.input(ChangeKind::Modify);
    next.item_id = Some(item);
    next.content = Some(content(b"C"));
    next.base = BaseVersion::Opaque(b);
    next.base_generation = Some(g + 1);
    assert_eq!(fx.run_raw(&next).unwrap().outcome, OutcomeKind::Applied);
    assert_eq!(fx.row_version("a"), Some(version_of(b"C")));
}

/// (3) Mixed is absorbing: no edit (trusted-looking or not) and no authored write turns it back
/// into Single.
#[test]
fn mixed_never_returns_to_single() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"one").item_id;
    let v2 = fx.peer_updates("a", 50);
    assert!(fx.serve(&item, v2));
    assert_eq!(fx.served(&item), Served::Mixed);

    // An edit that names everything correctly (current base and generation) on a mixed item is
    // untrusted: kept beside the file, the item stays mixed.
    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"after"));
    edit.base = BaseVersion::Opaque(v2);
    edit.base_generation = Some(item_generation_of(&fx, &item));
    assert_eq!(fx.run_raw(&edit).unwrap().outcome, OutcomeKind::Concurrent);
    assert_eq!(fx.served(&item), Served::Mixed);
    assert_eq!(fx.row_version("a"), Some(v2), "canonical changed");

    // Even the authoring helper itself cannot reset it, and serving anything keeps it mixed.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            crate::provider_provenance::authored_in_tx(tx, &fx.root, &item, "some|File||")?;
            Ok(())
        })
        .unwrap();
    assert_eq!(fx.served(&item), Served::Mixed);
    assert!(fx.serve(&item, v2));
    assert_eq!(fx.served(&item), Served::Mixed);
}

// ---- a delete destroys only when unambiguous ----

fn delete_raw(
    fx: &Fx,
    item: ItemId,
    base: BaseVersion,
    generation: Option<u64>,
) -> Result<ApplyResult, ApplyError> {
    let mut gone = fx.input(ChangeKind::Delete);
    gone.item_id = Some(item);
    gone.base = base;
    gone.base_generation = generation;
    fx.run_raw(&gone)
}

/// (4) A never-served remote file is deleted only with the current base AND current generation.
/// (5) A stale or unknown base, an old generation, other content served, a mixed item and an
/// announcement in flight all leave the file.
#[test]
fn a_file_delete_destroys_only_when_every_condition_holds() {
    let make = || {
        let fx = Fx::new();
        fx.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state) VALUES (?1, 'p', 0, 9, '[]', 0, 7, 'current')",
                    [GROUP],
                )?;
                let version = crate::provider::current_version(tx, GROUP, "p")?.unwrap();
                crate::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
        let _ = fx.page(&[], None, 100);
        let item = fx.item_of("p");
        let v = fx.row_version("p").unwrap();
        assert_eq!(fx.served(&item), Served::Never);
        (fx, item, v)
    };
    let survives = |fx: &Fx, item, base, generation: Option<u64>, label: &str| {
        let result = delete_raw(fx, item, base, generation);
        let outcome = result.as_ref().map(|r| r.outcome);
        assert!(
            matches!(outcome, Ok(OutcomeKind::FileSurvived) | Err(ApplyError::StaleView(_))),
            "{label}: {result:?}"
        );
        assert!(fx.row_version("p").is_some(), "{label}: the file was deleted");
    };

    let (fx, item, _v) = make();
    let g = item_generation_of(&fx, &item);
    survives(&fx, item, BaseVersion::Unknown, Some(g), "unknown base");
    let (fx, item, v2) = make();
    survives(
        &fx,
        item,
        BaseVersion::Opaque(VersionHash([9; 32])),
        Some(item_generation_of(&fx, &item)),
        "other version",
    );
    let _ = v2;
    let (fx, item, v) = make();
    survives(&fx, item, BaseVersion::Opaque(v), None, "unknown generation");
    let (fx, item, v) = make();
    let g = item_generation_of(&fx, &item);
    survives(&fx, item, BaseVersion::Opaque(v), Some(g + 3), "old generation");
    let fx = Fx::new();
    let item = fx.create(None, "p", b"served first").item_id;
    let other = fx.peer_updates("p", 60);
    assert!(fx.serve(&item, other));
    assert_eq!(fx.served(&item), Served::Mixed);
    let g = item_generation_of(&fx, &item);
    survives(&fx, item, BaseVersion::Opaque(other), Some(g), "mixed");
    let (fx, item, v) = make();
    // Everything current (a never-served file) except that an announcement is in flight.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE provider_items SET announce_version_hash = ?1, announce_seq = 1 \
                 WHERE item_id = ?2",
                rusqlite::params![&v.0[..], &item[..]],
            )?;
            Ok(())
        })
        .unwrap();
    let g = item_generation_of(&fx, &item);
    survives(&fx, item, BaseVersion::Opaque(v), Some(g), "announcement in flight");

    // Everything current: the delete goes through.
    let (fx, item, v) = make();
    let g = item_generation_of(&fx, &item);
    let result = delete_raw(&fx, item, BaseVersion::Opaque(v), Some(g)).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Deleted);
}

/// C12: a provider DELETE of an item that is already gone, sent with a stale base, changes
/// nothing: it is answered `Deleted`, no other file is touched, and a file that survived a
/// retired item's delete is not removed by a repeat of it.
#[test]
fn a_delete_of_an_already_removed_item_with_a_stale_base_changes_nothing() {
    let fx = Fx::new();
    let gone = fx.create(None, "gone", b"g").item_id;
    let gone_base = fx.row_version("gone").unwrap();
    let gone_generation = item_generation_of(&fx, &gone);
    let keep = fx.create(None, "keep", b"k").item_id;
    let keep_version = fx.row_version("keep").unwrap();
    // A peer deleted `gone`; the OS still shows it at the old base.
    fx.peer_deletes("gone");
    let result =
        delete_raw(&fx, gone, BaseVersion::Opaque(gone_base), Some(gone_generation)).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), ["keep"]);
    assert_eq!(fx.row_version("keep"), Some(keep_version));
    // A repeat (or a stale replay with a bogus base and generation) is the same answer.
    for (base, generation) in [
        (BaseVersion::Opaque(gone_base), Some(gone_generation)),
        (BaseVersion::Opaque(VersionHash([9; 32])), Some(gone_generation + 5)),
        (BaseVersion::Unknown, None),
    ] {
        let again = delete_raw(&fx, gone, base, generation).unwrap();
        assert_eq!(again.outcome, OutcomeKind::Deleted);
    }
    // An item id the daemon never minted is the same.
    let unknown = delete_raw(&fx, [0xEE; 16], BaseVersion::Unknown, None).unwrap();
    assert_eq!(unknown.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), ["keep"]);

    // A delete that left a file (stale base) retires the item; its repeat deletes nothing.
    let survived = delete_raw(&fx, keep, BaseVersion::Opaque(VersionHash([9; 32])), None).unwrap();
    assert_eq!(survived.outcome, OutcomeKind::FileSurvived);
    let repeat = delete_raw(
        &fx,
        keep,
        BaseVersion::Opaque(keep_version),
        Some(item_generation_of(&fx, &keep)),
    )
    .unwrap();
    assert_eq!(repeat.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), ["keep"], "a repeat of a retired item's delete removed the file");
    assert_eq!(fx.row_version("keep"), Some(keep_version));
}

// ---- a rename or move acts only on the version the user saw ----

/// (a) A peer commits a new version that is not announced yet: a rename that echoes the old hash,
/// no hash, or the current one moves the item, and the peer's bytes move with it, untouched.
#[test]
fn a_stale_rename_after_a_remote_edit_renames_and_keeps_the_remote_bytes() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"seen").item_id;
    let seen = fx.row_version("a").unwrap();
    let generation = item_generation_of(&fx, &item);
    let unseen = fx.peer_updates("a", 50);
    assert_ne!(seen, unseen);
    let rename = |name: &str, base: BaseVersion| {
        let mut input = fx.input(ChangeKind::Modify);
        input.item_id = Some(item);
        input.name = Some(name.into());
        input.metadata = MetadataInput::default();
        input.base = base;
        input.base_generation = Some(generation);
        fx.run_raw(&input)
    };
    assert!(rename("b", BaseVersion::Opaque(seen)).is_ok());
    assert_eq!(fx.live_paths(), ["b"]);
    assert_eq!(fx.row_version("b"), Some(unseen), "the remote bytes must move with the item");
    assert!(rename("c", BaseVersion::Unknown).is_ok());
    assert_eq!(fx.live_paths(), ["c"]);
    assert_eq!(fx.row_version("c"), Some(unseen));
}

/// (b) A remote move, then a stale rename: the item is renamed at its CURRENT location. (c) A remote
/// rename, then a stale move: the item is moved keeping its CURRENT name.
#[test]
fn a_stale_rename_follows_a_remote_move_and_a_stale_move_keeps_a_remote_rename() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    let e = fx.create_dir(None, "e");
    let f = fx.create(None, "f", b"x").item_id;
    let stale_generation = item_generation_of(&fx, &f);
    // (b) a peer moved f into d.
    fx.rename_in_place("f", "d/f");
    let mut rename = fx.input(ChangeKind::Modify);
    rename.item_id = Some(f);
    rename.name = Some("g".into());
    rename.metadata = MetadataInput::default();
    rename.base_generation = Some(stale_generation);
    rename.parent_generation = Some(0);
    let renamed = fx.run_raw(&rename);
    assert!(renamed.is_ok(), "{renamed:?}");
    assert_eq!(fx.live_paths(), ["d", "d/g", "e"], "renamed where the item is now");
    // (c) a peer renamed it to h; the OS still names the old view and moves it into e.
    fx.rename_in_place("d/g", "d/h");
    let mut mv = fx.input(ChangeKind::Modify);
    mv.item_id = Some(f);
    mv.new_parent = Some(Some(e.item_id));
    mv.metadata = MetadataInput::default();
    mv.base_generation = Some(stale_generation);
    mv.parent_generation = Some(0);
    let moved = fx.run_raw(&mv);
    assert!(moved.is_ok(), "{moved:?}");
    assert_eq!(fx.live_paths(), ["d", "e", "e/h"], "moved keeping the current name");
    let _ = d;
}

/// (d) A remote delete, then a stale rename or move: the item is gone (the bytes are kept by the
/// caller as a new item); it is never resurrected.
#[test]
fn a_stale_rename_or_move_of_a_remotely_deleted_item_is_never_resurrected() {
    let fx = Fx::new();
    let e = fx.create_dir(None, "e");
    let f = fx.create(None, "f", b"x").item_id;
    let generation = item_generation_of(&fx, &f);
    fx.peer_deletes("f");
    fx.repo.project_batch(GROUP, 100).unwrap();
    for (name, parent) in [(Some("g"), None), (None, Some(Some(e.item_id)))] {
        let mut input = fx.input(ChangeKind::Modify);
        input.item_id = Some(f);
        input.name = name.map(Into::into);
        input.new_parent = parent;
        input.metadata = MetadataInput::default();
        input.base_generation = Some(generation);
        let result = fx.run_raw(&input);
        assert!(
            matches!(result, Err(ApplyError::KeepLocal { .. }) | Err(ApplyError::NotFound(_))),
            "{result:?}"
        );
    }
    assert_eq!(fx.row_version("g"), None, "a deleted item was resurrected by a rename");
    assert_eq!(fx.row_version("e/f"), None, "a deleted item was resurrected by a move");
}

/// (e) Two renames of the same item from the same stale view: both are accepted in turn, the last
/// one names the item, and the bytes are never lost.
#[test]
fn two_stale_renames_of_one_item_both_apply_in_turn_and_lose_no_bytes() {
    let fx = Fx::new();
    let f = fx.create(None, "f", b"bytes").item_id;
    let version = fx.row_version("f");
    let stale = item_generation_of(&fx, &f);
    for name in ["g", "h"] {
        let mut input = fx.input(ChangeKind::Modify);
        input.item_id = Some(f);
        input.name = Some(name.into());
        input.metadata = MetadataInput::default();
        input.base_generation = Some(stale);
        assert!(fx.run_raw(&input).is_ok());
    }
    assert_eq!(fx.live_paths(), ["h"]);
    assert_eq!(fx.row_version("h"), version);
}

/// (h) A directory rename or move moves the CURRENT subtree from a stale view, and the destination
/// rules still hold: no move into itself, no collision.
#[test]
fn a_stale_directory_move_moves_the_current_subtree_and_keeps_the_destination_rules() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    fx.create(Some(dir.item_id), "inner", b"i");
    let other = fx.create_dir(None, "o");
    fx.create(None, "taken", b"t");
    let stale = item_generation_of(&fx, &dir.item_id);
    fx.create(Some(dir.item_id), "later", b"l");
    let attempt = |parent: Option<ItemId>, name: Option<&str>| {
        let mut input = fx.input(ChangeKind::Modify);
        input.item_id = Some(dir.item_id);
        input.new_parent = parent.map(Some);
        input.name = name.map(Into::into);
        input.metadata = MetadataInput::default();
        input.base_generation = Some(stale);
        input.parent_generation = Some(0);
        fx.run_raw(&input)
    };
    assert!(matches!(attempt(None, Some("taken")), Err(ApplyError::NameCollision(_))));
    assert!(matches!(attempt(Some(dir.item_id), None), Err(ApplyError::InvalidName(_))));
    let ok = attempt(Some(other.item_id), Some("moved"));
    assert!(ok.is_ok(), "{ok:?}");
    assert_eq!(
        fx.live_paths(),
        ["o", "o/moved", "o/moved/inner", "o/moved/later", "taken"],
        "the current subtree, including the later child, moved"
    );
}

/// Renaming an item inside a folder needs no generation of that folder (identity semantics).
#[test]
fn a_nested_rename_does_not_depend_on_the_folder_generation() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let f = fx.create(Some(dir.item_id), "f", b"x").item_id;
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE provider_items SET generation = generation + 1 WHERE item_id = ?1",
                [&dir.item_id[..]],
            )?;
            Ok(())
        })
        .unwrap();
    let mut input = fx.input(ChangeKind::Modify);
    input.item_id = Some(f);
    input.name = Some("g".into());
    input.metadata = MetadataInput::default();
    input.parent_generation = Some(0);
    assert!(fx.run_raw(&input).is_ok());
    assert_eq!(fx.live_paths(), ["d", "d/g"]);
}

// ---- a folder's generation follows its child set ----

fn folder_delete_raw(
    fx: &Fx,
    dir: ItemId,
    base: BaseVersion,
    generation: Option<u64>,
) -> Result<ApplyResult, ApplyError> {
    let mut gone = fx.input(ChangeKind::Delete);
    gone.item_id = Some(dir);
    gone.base = base;
    gone.base_generation = generation;
    gone.recursive = true;
    fx.run_raw(&gone)
}

/// (ii) A child added, removed or moved in or out advances the folder's generation in the same
/// transaction and tells the OS the folder's new token; the place generation (what a rename's
/// source-folder check uses) does not move, so a sibling does not stale a rename.
#[test]
fn a_folders_generation_follows_its_child_set_and_the_os_is_told() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let f = fx.create(Some(dir.item_id), "f", b"x").item_id;
    let _ = fx.page(&[], None, 10);
    let listing = fx.page(&dir.item_id[..], None, 10);
    let (g0, p0) = (item_generation_of(&fx, &dir.item_id), place_generation_of(&fx, &dir.item_id));

    // A local create under it.
    fx.create(Some(dir.item_id), "g", b"y");
    let g1 = item_generation_of(&fx, &dir.item_id);
    assert!(g1 > g0, "a local create did not advance the folder");
    // A remote add.
    fx.peer_updates("d/h", 70);
    let _ = fx.page(&dir.item_id[..], None, 10);
    let g2 = item_generation_of(&fx, &dir.item_id);
    assert!(g2 > g1, "a remote add did not advance the folder");
    // A remote removal.
    fx.peer_deletes("d/h");
    let _ = fx.page(&dir.item_id[..], None, 10);
    let g3 = item_generation_of(&fx, &dir.item_id);
    assert!(g3 > g2, "a remote removal did not advance the folder");
    // The place generation never moved, and a rename of `f` from its view still goes through.
    assert_eq!(place_generation_of(&fx, &dir.item_id), p0);
    let mut rename = fx.input(ChangeKind::Modify);
    rename.item_id = Some(f);
    rename.name = Some("f2".into());
    rename.metadata = MetadataInput::default();
    rename.base = BaseVersion::Opaque(fx.row_version("d/f").unwrap());
    rename.base_generation = Some(item_generation_of(&fx, &f));
    rename.parent_generation = Some(p0);
    assert!(fx.run_raw(&rename).is_ok(), "a sibling staled a rename");
    // The OS is told the folder's new token: it is in the working-set report.
    let page = fx.changes(&ChangeScope::WorkingSet, listing.anchor, 100);
    assert!(
        page.upserts
            .iter()
            .any(|i| i.item_id == dir.item_id
                && i.generation == item_generation_of(&fx, &dir.item_id))
    );
}

/// A recursive delete is of the subtree the user saw: an entry that arrived BELOW a subfolder
/// after that view (a grandchild, which moves the subfolder's token and not the top folder's) is
/// new work and must not be swept away by the old delete.
#[test]
fn a_recursive_delete_does_not_sweep_an_entry_added_below_a_subfolder_after_the_view() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let sub = fx.create_dir(Some(dir.item_id), "s");
    fx.create(Some(sub.item_id), "a", b"a");
    let _ = fx.page(&dir.item_id[..], None, 10);
    let _ = fx.page(&sub.item_id[..], None, 10);
    let hash = fx.shown_version_of("d");
    let seen = item_generation_of(&fx, &dir.item_id);
    // A grandchild arrives after the view the user deleted from.
    fx.create(Some(sub.item_id), "b", b"b");
    let before = fx.live_paths();
    let old = folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(seen));
    assert!(stale_view(old), "the delete swept a grandchild the user never saw");
    assert_eq!(fx.live_paths(), before);
}

/// An edit of a known file below a folder moves the folder's token and raises a root signal, so
/// the host re-reads the folder (an old-token delete is refused only until that refresh).
#[test]
fn an_edit_below_a_folder_advances_its_token_and_signals_the_root() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let sub = fx.create_dir(Some(dir.item_id), "s");
    let file = fx.create(Some(sub.item_id), "a", b"a");
    let _ = fx.page(&dir.item_id[..], None, 10);
    let _ = fx.page(&sub.item_id[..], None, 10);
    let seen = item_generation_of(&fx, &dir.item_id);
    let signal = |fx: &Fx| fx.count_where("provider_roots", "change_seq");
    let before = signal(&fx);
    fx.modify_content(file.item_id, b"a2");
    assert!(item_generation_of(&fx, &dir.item_id) > seen, "the edit did not reach the ancestor");
    assert!(signal(&fx) > before, "no root signal followed the ancestor's new token");
}

/// (i) A recursive delete needs the folder's OWN current token: an old generation (a child came
/// after the view) and an absent base both delete nothing; the current token deletes.
#[test]
fn a_folder_delete_needs_the_folders_own_current_token() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    fx.create(Some(dir.item_id), "a", b"a");
    let _ = fx.page(&dir.item_id[..], None, 10);
    let hash = fx.shown_version_of("d");
    let seen = item_generation_of(&fx, &dir.item_id);
    // A child arrives after the view the user deleted from.
    fx.create(Some(dir.item_id), "b", b"b");
    let before = fx.live_paths();
    let old = folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(seen));
    assert!(stale_view(old), "a delete on an older folder view was accepted");
    assert!(
        stale_view(folder_delete_raw(
            &fx,
            dir.item_id,
            BaseVersion::Unknown,
            Some(item_generation_of(&fx, &dir.item_id))
        )),
        "an unknown base was accepted"
    );
    assert!(
        stale_view(folder_delete_raw(
            &fx,
            dir.item_id,
            BaseVersion::Opaque(VersionHash([5; 32])),
            Some(item_generation_of(&fx, &dir.item_id))
        )),
        "a foreign hash was accepted"
    );
    assert!(
        stale_view(folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), None)),
        "an unknown generation was accepted"
    );
    assert_eq!(fx.live_paths(), before, "something was deleted");
    let _ = fx.page(&dir.item_id[..], None, 10);
    let current = folder_delete_raw(
        &fx,
        dir.item_id,
        BaseVersion::Opaque(hash),
        Some(item_generation_of(&fx, &dir.item_id)),
    );
    assert_eq!(current.unwrap().outcome, OutcomeKind::Deleted);
}

/// A recursive folder delete means "delete the subtree of the folder as the user saw it": a folder
/// nobody opened, whose children (and grandchildren) were never shown, is deleted whole when the
/// folder's own token is current. A non-recursive delete of a non-empty folder is refused, and the
/// subtree bound still applies.
#[test]
fn a_recursive_delete_removes_the_subtree_of_a_never_opened_folder() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let hash = fx.shown_version_of("d");
    let _ = fx.page(&[], None, 10);
    // Peer children the OS was never shown (never opened, never published, never served).
    fx.peer_updates("d/one", 70);
    fx.peer_updates("d/sub/two", 71);
    let generation = item_generation_of(&fx, &dir.item_id);
    let current_token = |fx: &Fx| {
        (BaseVersion::Opaque(fx.shown_version_of("d")), Some(item_generation_of(fx, &dir.item_id)))
    };
    let _ = (hash, generation);
    let (base, g) = current_token(&fx);
    let mut plain = fx.input(ChangeKind::Delete);
    plain.item_id = Some(dir.item_id);
    plain.base = base;
    plain.base_generation = g;
    plain.recursive = false;
    assert!(matches!(fx.run_raw(&plain), Err(ApplyError::DirectoryNotEmpty(_))));
    assert_eq!(fx.live_paths().len(), 3, "{:?}", fx.live_paths());

    let (base, g) = current_token(&fx);
    let result = folder_delete_raw(&fx, dir.item_id, base, g).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), Vec::<String>::new(), "part of the subtree survived");
}

/// A folder's token covers its whole subtree: a deep descendant added after the view (A/B/y.txt
/// while the user saw A with A/B/x.txt) advances A's generation too, so the recursive delete on the
/// old token is a stale view and removes nothing; the current token deletes the subtree.
#[test]
fn a_deep_descendant_added_after_the_view_stales_the_folders_recursive_delete() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "A");
    fx.peer_updates("A/B/x.txt", 80);
    let _ = fx.page(&[], None, 10);
    let _ = fx.page(&dir.item_id[..], None, 10);
    let hash = fx.shown_version_of("A");
    let seen = item_generation_of(&fx, &dir.item_id);

    fx.peer_updates("A/B/y.txt", 81);
    let _ = fx.page(&dir.item_id[..], None, 10);
    let now = item_generation_of(&fx, &dir.item_id);
    assert!(now > seen, "a deep add did not advance the ancestor");

    let before = fx.live_paths();
    let old = folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(seen));
    assert!(stale_view(old), "the old token swept an entry the user never saw");
    assert_eq!(fx.live_paths(), before);
    let result = folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(now)).unwrap();
    assert_eq!(result.outcome, OutcomeKind::Deleted);
    assert_eq!(fx.live_paths(), Vec::<String>::new(), "the current subtree was not deleted whole");
}

/// A folder SHOWN by its parent's listing but never opened: a peer adding a direct child still
/// advances the folder's generation (the child has no item and the folder was never enumerated),
/// so a delete on the token taken before the change is a stale view and deletes nothing.
#[test]
fn a_child_added_under_a_shown_but_unopened_folder_stales_the_folders_token() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "F");
    let _ = fx.page(&[], None, 10);
    let hash = fx.shown_version_of("F");
    let seen = item_generation_of(&fx, &dir.item_id);

    fx.peer_updates("F/new", 90);
    fx.create(None, "other", b"o"); // any later write transaction reconciles the peer's commit
    assert!(item_generation_of(&fx, &dir.item_id) > seen, "the direct-child add was not counted");

    let before = fx.live_paths();
    let old = folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(seen));
    assert!(stale_view(old), "the pre-change token deleted the folder");
    assert_eq!(fx.live_paths(), before);
    let now = item_generation_of(&fx, &dir.item_id);
    let ok = folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(now)).unwrap();
    assert_eq!(ok.outcome, OutcomeKind::Deleted);
}

// ---- a replacement at the same path is a new view of the item (T2) ----

impl Fx {
    /// The projector sees ANOTHER head at the path (a replacement with the very same content and
    /// mode): the row's recorded identity no longer matches the head, so it is written again.
    fn replace_head_with_identical_content(&self, path: &str) {
        self.db
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) \
                     VALUES (?1, zeroblob(59), zeroblob(32))",
                    [GROUP],
                )?;
                tx.execute(
                    "UPDATE files SET native_authoring_identity = zeroblob(59) \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    [GROUP, path],
                )?;
                crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                    tx,
                    GROUP,
                    &[path],
                    1,
                )?;
                Ok(())
            })
            .unwrap();
        assert!(self.repo.project_batch(GROUP, 100).unwrap() >= 1);
    }
}

/// The predecessor's token (same hash, older generation) cannot author a canonical edit on a
/// replacement file that has identical content.
#[test]
fn a_replaced_file_rejects_the_predecessors_token() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"same").item_id;
    let _ = fx.page(&[], None, 10);
    let hash = fx.row_version("a").unwrap();
    let old_generation = item_generation_of(&fx, &item);

    fx.replace_head_with_identical_content("a");
    assert_eq!(fx.row_version("a"), Some(hash), "the replacement changed the version hash");
    assert!(item_generation_of(&fx, &item) > old_generation, "the replacement kept the token");

    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(b"typed on the predecessor"));
    edit.base = BaseVersion::Opaque(hash);
    edit.base_generation = Some(old_generation);
    assert_bytes_kept(
        &fx,
        fx.run_raw(&edit),
        "a",
        Some(hash),
        b"typed on the predecessor",
        "replaced file",
    );
}

/// Same for a replacement directory: the old folder token cannot delete its subtree.
#[test]
fn a_replaced_directory_rejects_the_predecessors_token() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let _ = fx.page(&[], None, 10);
    let hash = fx.shown_version_of("d");
    let old_generation = item_generation_of(&fx, &dir.item_id);

    fx.replace_head_with_identical_content("d");
    assert!(item_generation_of(&fx, &dir.item_id) > old_generation);
    let before = fx.live_paths();
    let result =
        folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(old_generation));
    assert!(stale_view(result), "the predecessor's token deleted the replacement");
    assert_eq!(fx.live_paths(), before);
}

/// Two edits based on the same A@g, one after the other: the first wins; the second's BYTES survive
/// as a conflict copy and canonical is the first's.
#[test]
fn the_second_edit_on_the_same_base_keeps_its_bytes_as_a_conflict_copy() {
    let fx = Fx::new();
    let item = fx.create(None, "a", b"A").item_id;
    let a = fx.row_version("a").unwrap();
    let g = item_generation_of(&fx, &item);
    let edit = |bytes: &[u8]| {
        let mut input = fx.input(ChangeKind::Modify);
        input.item_id = Some(item);
        input.content = Some(content(bytes));
        input.base = BaseVersion::Opaque(a);
        input.base_generation = Some(g);
        fx.run_raw(&input)
    };
    assert_eq!(edit(b"first").unwrap().outcome, OutcomeKind::Applied);
    assert_bytes_kept(
        &fx,
        edit(b"second"),
        "a",
        Some(version_of(b"first")),
        b"second",
        "second edit",
    );
    assert_eq!(fx.heads_at("a"), 1);
}

/// A real race: two connections apply edits on the same A@g at once. Exactly one is applied; the
/// other's bytes survive as a conflict copy; canonical is the winner's; nothing is lost.
#[test]
fn two_concurrent_edits_on_the_same_base_lose_no_bytes() {
    for round in 0..15 {
        let fx = Fx::new();
        let item = fx.create(None, "a", b"A").item_id;
        let a = fx.row_version("a").unwrap();
        let g = item_generation_of(&fx, &item);
        let inputs: Vec<ApplyInput> = [&b"left"[..], &b"right"[..]]
            .iter()
            .map(|bytes| {
                let mut input = fx.input(ChangeKind::Modify);
                input.item_id = Some(item);
                input.content = Some(content(bytes));
                input.base = BaseVersion::Opaque(a);
                input.base_generation = Some(g);
                input
            })
            .collect();
        let key = &fx.key;
        let repo = &fx.repo;
        let barrier = std::sync::Barrier::new(2);
        let outcomes: Vec<Result<ApplyResult, ApplyError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = inputs
                .iter()
                .map(|input| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        let author = LocalAuthor {
                            author: AuthorId {
                                device: DeviceId("device-a".into()),
                                incarnation: IncarnationId([1u8; 16]),
                            },
                            signing_key: key,
                            capture: None,
                        };
                        let permit =
                            yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
                        barrier.wait();
                        repo.apply_change(input, &author, "device-a", &permit)
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let applied = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(r) if r.outcome == OutcomeKind::Applied))
            .count();
        let beside = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(r) if r.outcome == OutcomeKind::Concurrent))
            .count();
        assert_eq!((applied, beside), (1, 1), "round {round}: {outcomes:?}");
        let winner = fx.row_version("a").unwrap();
        let (won, lost): (&[u8], &[u8]) =
            if winner == version_of(b"left") { (b"left", b"right") } else { (b"right", b"left") };
        assert_eq!(winner, version_of(won));
        assert!(
            fx.kept_beside("a", lost),
            "round {round}: the loser's bytes were lost: {:?}",
            fx.live_paths()
        );
    }
}

// ---- the folder token's hash is the CURRENT directory version (U1) ----

/// After a remote replacement that changes the directory's version, and before the driver announces
/// it, enumeration still shows the published (old) hash with the item's NEW generation. That pair
/// is not a current token: the folder delete is a stale view; the current hash and generation pass.
#[test]
fn an_old_folder_hash_with_a_new_generation_cannot_delete_the_folder() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let _ = fx.page(&[], None, 10);
    let old_hash = fx.shown_version_of("d");
    // A remote replacement with another mode: a different version, the generation moves, and
    // nothing is announced yet.
    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE files SET unix_mode = 448 WHERE group_id = ?1 AND path = 'd' AND state = 'current'",
                [GROUP],
            )?;
            yadorilink_sqlite_runtime::note_item_replaced(tx, GROUP, "d")?;
            Ok(())
        })
        .unwrap();
    let new_hash = fx.row_version("d").unwrap();
    assert_ne!(new_hash, old_hash, "the replacement did not change the directory's version");
    let generation = item_generation_of(&fx, &dir.item_id);
    // What enumeration issues now: the published hash with the new generation.
    let shown = fx.repo.lookup_item(&fx.root, &dir.item_id).unwrap().unwrap().0;
    assert_eq!(shown.content_version, old_hash);
    assert_eq!(shown.generation, generation);

    let before = fx.live_paths();
    let mixed =
        folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(old_hash), Some(generation));
    assert!(stale_view(mixed), "an old hash with a new generation deleted the folder");
    assert_eq!(fx.live_paths(), before);
    let current =
        folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(new_hash), Some(generation));
    assert_eq!(current.unwrap().outcome, OutcomeKind::Deleted);
}

// ---- an explicit directory that becomes structural (U2) ----

/// A peer removes the explicit directory head while a descendant remains: the node becomes
/// structural. The old explicit row is retired, the folder item stays with a new generation, and
/// the old folder token can no longer delete the remaining descendant.
#[test]
fn an_explicit_directory_turned_structural_stales_its_old_token() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    fx.create(Some(dir.item_id), "x", b"x");
    let _ = fx.page(&[], None, 10);
    let hash = fx.shown_version_of("d");
    let old_generation = item_generation_of(&fx, &dir.item_id);

    fx.db
        .write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM native_heads WHERE group_id = ?1 AND path = 'd'", [GROUP])?;
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx,
                GROUP,
                &["d"],
                1,
            )?;
            Ok(())
        })
        .unwrap();
    fx.repo.project_batch(GROUP, 100).unwrap();
    assert_eq!(fx.live_paths(), ["d/x"], "the explicit row of d was not retired");
    assert!(
        item_generation_of(&fx, &dir.item_id) > old_generation,
        "the folder identity did not move"
    );

    let result =
        folder_delete_raw(&fx, dir.item_id, BaseVersion::Opaque(hash), Some(old_generation));
    assert!(stale_view(result), "the old explicit token deleted the remaining descendant");
    assert_eq!(fx.live_paths(), ["d/x"]);
}

// ---- no refusal consumes the user's bytes ----

/// Every refusal of an operation that carries ingested bytes keeps them as a conflict-named file:
/// a create into a retired destination, a create whose name is taken or invalid, a modify combined with a
/// rename or move, and the same bytes retried (at different times, many times) are kept ONCE.
#[test]
fn every_refusal_of_a_byte_bearing_operation_keeps_the_bytes() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    let a = fx.create(None, "a.txt", b"canonical").item_id;
    fx.delete(d.item_id, BaseVersion::Unknown, true).unwrap();

    // Create into a retired destination.
    let mut create = fx.input(ChangeKind::Create);
    create.new_parent = Some(Some(d.item_id));
    create.name = Some("x.txt".into());
    create.content = Some(content(b"stale parent bytes"));
    let kept = fx.run_raw(&create).unwrap();
    assert_eq!(kept.outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("x.txt", b"stale parent bytes"), "{:?}", fx.live_paths());

    // Create whose name is taken, and one whose name is invalid.
    let mut taken = fx.input(ChangeKind::Create);
    taken.name = Some("a.txt".into());
    taken.content = Some(content(b"collision bytes"));
    assert_eq!(fx.run(&taken).unwrap().outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("a.txt", b"collision bytes"));
    let mut invalid = fx.input(ChangeKind::Create);
    invalid.name = Some("a/b".into());
    invalid.content = Some(content(b"invalid name bytes"));
    assert_eq!(fx.run(&invalid).unwrap().outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("file", b"invalid name bytes"), "{:?}", fx.live_paths());

    // Modify combined with a rename on a stale view: the bytes are kept, the rename is not applied.
    let mut both = fx.input(ChangeKind::Modify);
    both.item_id = Some(a);
    both.name = Some("renamed.txt".into());
    both.content = Some(content(b"edit with rename"));
    both.base = BaseVersion::Opaque(VersionHash([9; 32]));
    both.base_generation = Some(1);
    assert_eq!(fx.run_raw(&both).unwrap().outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("a.txt", b"edit with rename"));
    assert!(fx.live_paths().contains(&"a.txt".to_owned()), "the rename was applied");
}

/// The same bytes retried at different times (different mtimes), and a storm of retries, keep ONE
/// copy: the copy's name derives from the bytes and the original path, never from the clock.
#[test]
fn retries_of_the_same_bytes_keep_one_copy() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"canonical").item_id;
    let before = fx.live_paths().len();
    for n in 0..12 {
        let mut edit = fx.input(ChangeKind::Modify);
        edit.item_id = Some(item);
        edit.content = Some(content(b"same stale bytes"));
        edit.base = BaseVersion::Opaque(VersionHash([77u8; 32]));
        edit.base_generation = Some(item_generation_of(&fx, &item));
        edit.metadata.mtime_unix_nanos = Some(MTIME + n * 1_000_000_007);
        edit.now_ms += n * 1_000;
        assert_eq!(fx.run_raw(&edit).unwrap().outcome, OutcomeKind::Concurrent);
    }
    assert_eq!(fx.live_paths().len(), before + 1, "{:?}", fx.live_paths());
}

// ---- review 6: copies without a fixed limit, structural bases and bounds, the upload journal ----

/// Conflict-copy names never run out: 60 occupied candidate names later the bytes still get a
/// copy of their own.
#[test]
fn the_conflict_copy_name_has_no_fixed_limit() {
    use sha2::{Digest, Sha256};
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"canonical").item_id;
    let bytes = b"stale bytes that need a copy";
    let c = content(bytes);
    let version = FileVersion::new(
        version_blocks(&c.blocks),
        c.size,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: super::replicated_mode(Some(0o644)),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let sig = super::kept_edit_semantic_key(&version);
    let key: [u8; 32] =
        Sha256::new().chain_update(sig.as_bytes()).chain_update(b"a.txt").finalize().into();
    for n in 0..60u32 {
        let label = if n == 0 { "local".to_owned() } else { format!("local-{}", n + 1) };
        let taken = yadorilink_replica_domain::conflict::native_copy_path("a.txt", &label, &key);
        fx.peer_updates(&taken, 100 + i64::from(n));
    }
    assert_eq!(fx.live_paths().len(), 61, "the candidate names were not the ones the copy uses");
    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(bytes));
    edit.base = BaseVersion::Opaque(VersionHash([5; 32]));
    edit.base_generation = Some(item_generation_of(&fx, &item));
    assert_eq!(fx.run_raw(&edit).unwrap().outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("a.txt", bytes), "{:?}", fx.live_paths().len());
}

/// (W4, revised by the identity rule) A pure rename or move of a structural directory acts on the
/// directory by identity: whatever structural version the OS echoes (none, a foreign one, the
/// current one), the current subtree moves.
#[test]
fn a_structural_directory_rename_acts_on_its_identity() {
    let fx = Fx::new();
    let _ = fx.page(&[], None, 10);
    fx.peer_updates("s/x", 200);
    let _ = fx.page(&[], None, 10);
    let item = fx.item_of("s");
    let rename = |name: &str, base: BaseVersion| {
        let mut input = fx.input(ChangeKind::Modify);
        input.item_id = Some(item);
        input.name = Some(name.into());
        input.metadata = MetadataInput::default();
        input.base = base;
        input.base_generation = Some(item_generation_of(&fx, &item));
        fx.run_raw(&input)
    };
    assert!(rename("t", BaseVersion::Unknown).is_ok());
    assert_eq!(fx.live_paths(), ["t/x"]);
    assert!(rename("u", BaseVersion::Opaque(VersionHash([8; 32]))).is_ok());
    assert_eq!(fx.live_paths(), ["u/x"]);
}

/// A structural directory's subtree bound is enforced before any row is loaded, for a delete
/// and for a move alike.
#[test]
fn a_large_structural_tree_is_refused_by_count_before_loading() {
    let fx = Fx::new();
    let _ = fx.page(&[], None, 10);
    for n in 0..8 {
        fx.peer_updates(&format!("big/f{n}"), 300 + n);
    }
    let _ = fx.page(&[], None, 10);
    let item = fx.item_of("big");
    let hash = fx.shown_version_of("big");
    let generation = item_generation_of(&fx, &item);
    let mut gone = fx.input(ChangeKind::Delete);
    gone.item_id = Some(item);
    gone.base = BaseVersion::Opaque(hash);
    gone.base_generation = Some(generation);
    gone.recursive = true;
    gone.max_subtree = 5;
    assert!(matches!(fx.run_raw(&gone), Err(ApplyError::DirectoryNotEmpty(_))));
    let mut moved = fx.input(ChangeKind::Modify);
    moved.item_id = Some(item);
    moved.name = Some("big2".into());
    moved.metadata = MetadataInput::default();
    moved.base = BaseVersion::Opaque(hash);
    moved.base_generation = Some(generation);
    moved.max_subtree = 5;
    assert!(matches!(fx.run_raw(&moved), Err(ApplyError::DirectoryNotEmpty(_))));
    assert_eq!(fx.live_paths().len(), 8);
}

/// The journal of an undecided upload survives a refused first attempt and is cleared by the
/// operation's decision: a refusal that keeps the bytes decides the operation, a failure that can
/// keep nothing leaves the journal for the retry.
#[test]
fn the_upload_journal_survives_an_undecided_operation_and_clears_when_decided() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    fx.delete(d.item_id, BaseVersion::Unknown, true).unwrap();
    let mut create = fx.input(ChangeKind::Create);
    create.new_parent = Some(Some(d.item_id));
    create.name = Some("x.txt".into());
    create.content = Some(content(b"bytes of a refused create"));
    fx.repo
        .journal_pending_ingest(&fx.root, &create.session_id, create.operation_seq, "copy-1", 1)
        .unwrap();
    assert_eq!(
        fx.repo.pending_ingest_name(&fx.root, &create.session_id, create.operation_seq).unwrap(),
        Some("copy-1".to_owned())
    );
    assert!(fx.repo.pending_ingest_names().unwrap().contains("copy-1"));
    // The first transaction refuses; the second keeps the bytes and decides the operation.
    assert_eq!(fx.run_raw(&create).unwrap().outcome, OutcomeKind::Concurrent);
    assert_eq!(
        fx.repo.pending_ingest_name(&fx.root, &create.session_id, create.operation_seq).unwrap(),
        None,
        "a decided operation kept its journal"
    );

    // A failure that keeps nothing (an unknown root) leaves the journal for the retry.
    let mut lost = fx.input(ChangeKind::Create);
    lost.root_id = "no-such-root".into();
    lost.name = Some("y.txt".into());
    lost.content = Some(content(b"bytes nobody could keep"));
    fx.repo
        .journal_pending_ingest("no-such-root", &lost.session_id, lost.operation_seq, "copy-2", 1)
        .unwrap();
    assert!(fx.run_raw(&lost).is_err());
    assert_eq!(
        fx.repo.pending_ingest_name("no-such-root", &lost.session_id, lost.operation_seq).unwrap(),
        Some("copy-2".to_owned())
    );
}

// ---- kept edits keep their replicated metadata (X1) ----

/// Two rejected edits with the SAME bytes but different replicated metadata (a mode, an xattr) are
/// two users' data and keep two copies; the same bytes and metadata retried at different times
/// (different mtimes) keep one.
#[test]
fn kept_edits_with_different_metadata_keep_separate_copies() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"canonical").item_id;
    let before = fx.live_paths().len();
    let keep = |xattr: &str, mode: u32, mtime: i64| {
        let mut edit = fx.input(ChangeKind::Modify);
        edit.item_id = Some(item);
        edit.content = Some(content(b"same stale bytes"));
        edit.base = BaseVersion::Opaque(VersionHash([77u8; 32]));
        edit.base_generation = Some(item_generation_of(&fx, &item));
        edit.metadata.unix_mode = Some(mode);
        edit.metadata.mtime_unix_nanos = Some(mtime);
        edit.metadata.xattrs = Some(vec![(xattr.to_owned(), b"v".to_vec())]);
        fx.run_raw(&edit).unwrap();
    };
    keep("user.a", 0o644, MTIME);
    keep("user.a", 0o644, MTIME + 5_000_000_000);
    keep("user.a", 0o644, MTIME + 9_000_000_000);
    assert_eq!(fx.live_paths().len(), before + 1, "retries at other times made more copies");
    // Only xattrs the platform replicates are semantic metadata (`user.*` on Linux).
    let replicated = usize::from(cfg!(target_os = "linux"));
    keep("user.b", 0o644, MTIME);
    assert_eq!(fx.live_paths().len(), before + 1 + replicated, "another xattr was merged");
    keep("user.a", 0o600, MTIME);
    assert_eq!(fx.live_paths().len(), before + 2 + replicated, "another mode was merged");
    keep("user.b", 0o644, MTIME + 1);
    assert_eq!(fx.live_paths().len(), before + 2 + replicated);
}

// ---- a destination is an identity (V1, X3) ----

/// The destination folder moved to another path after the operation's view: a create and a move land
/// at the CURRENT location of the destination's item id.
#[test]
fn a_create_and_a_move_land_where_the_destination_is_now() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    let outer = fx.create_dir(None, "outer");
    let f = fx.create(None, "f", b"f").item_id;
    fx.rename(d.item_id, Some(Some(outer.item_id)), "d2").unwrap();

    let mut create = fx.input(ChangeKind::Create);
    create.new_parent = Some(Some(d.item_id));
    create.name = Some("x".into());
    assert_eq!(fx.run_raw(&create).unwrap().outcome, OutcomeKind::Applied);
    assert!(fx.live_paths().contains(&"outer/d2/x".to_owned()), "{:?}", fx.live_paths());

    let mut moved = fx.input(ChangeKind::Modify);
    moved.item_id = Some(f);
    moved.new_parent = Some(Some(d.item_id));
    moved.metadata = MetadataInput::default();
    moved.base = BaseVersion::Opaque(fx.row_version("f").unwrap());
    moved.base_generation = Some(item_generation_of(&fx, &f));
    moved.parent_generation = Some(0);
    assert!(fx.run_raw(&moved).is_ok());
    assert!(fx.live_paths().contains(&"outer/d2/f".to_owned()), "{:?}", fx.live_paths());
}

/// The destination hit by a same-path replacement (its generation moved) still receives the
/// operation; a name that exists there is a collision, never a replacement.
#[test]
fn a_replaced_destination_still_receives_creates_and_never_loses_a_name() {
    let fx = Fx::new();
    let d = fx.create_dir(None, "d");
    fx.create(Some(d.item_id), "taken", b"mine");
    let _ = fx.page(&[], None, 10);
    let generation = item_generation_of(&fx, &d.item_id);
    fx.replace_head_with_identical_content("d");
    assert!(item_generation_of(&fx, &d.item_id) > generation);

    let mut create = fx.input(ChangeKind::Create);
    create.new_parent = Some(Some(d.item_id));
    create.name = Some("fresh".into());
    assert_eq!(fx.run_raw(&create).unwrap().outcome, OutcomeKind::Applied);
    assert!(fx.live_paths().contains(&"d/fresh".to_owned()));

    let mut again = fx.input(ChangeKind::Create);
    again.new_parent = Some(Some(d.item_id));
    again.name = Some("taken".into());
    assert!(is_collision(fx.run_raw(&again)));
    assert_eq!(fx.row_version("d/taken"), Some(version_of(b"mine")), "a name was replaced");
}

// ---- review 7 ----

/// The key a kept copy of `bytes` (as the default test input shows them) takes for the original path.
fn kept_key(from: &str, bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let c = content(bytes);
    let version = FileVersion::new(
        version_blocks(&c.blocks),
        c.size,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: super::replicated_mode(Some(0o644)),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    let sig = super::kept_edit_semantic_key(&version);
    Sha256::new().chain_update(sig.as_bytes()).chain_update(from.as_bytes()).finalize().into()
}

/// (Y2) A stale edit with the same bytes as the canonical version but another mode is the user's
/// data and gets its own copy; the same mode and bytes keep nothing.
#[test]
fn a_stale_edit_with_the_canonical_bytes_and_another_mode_is_kept() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"same bytes").item_id;
    let before = fx.live_paths().len();
    let stale = |mode: u32, seq: i64| {
        let mut edit = fx.input(ChangeKind::Modify);
        edit.item_id = Some(item);
        edit.content = Some(content(b"same bytes"));
        edit.base = BaseVersion::Opaque(VersionHash([66u8; 32]));
        edit.base_generation = Some(item_generation_of(&fx, &item));
        edit.metadata.unix_mode = Some(mode);
        edit.operation_seq += seq as u64;
        fx.run_raw(&edit).unwrap();
    };
    let canonical_mode = 0o644;
    stale(canonical_mode, 10);
    assert_eq!(fx.live_paths().len(), before, "identical bytes and mode kept a copy");
    stale(0o600, 20);
    assert_eq!(fx.live_paths().len(), before + 1, "another mode on the same bytes was dropped");
}

/// (Y3) When the quarantine entry or its folder is occupied by a user file, or by a directory with a
/// colliding child, the next quarantine folder takes the copy: it is never refused.
#[test]
fn the_quarantine_never_refuses_a_copy() {
    let fx = Fx::new();
    let item = fx.create(None, "a.txt", b"canonical").item_id;
    let bytes = b"bytes that overflow every name";
    let key = kept_key("a.txt", bytes);
    for n in 0..1000u32 {
        let label = if n == 0 { "local".to_owned() } else { format!("local-{}", n + 1) };
        let taken = yadorilink_replica_domain::conflict::native_copy_path("a.txt", &label, &key);
        fx.peer_updates(&taken, 1000 + i64::from(n));
    }
    // The first quarantine folder is a user FILE; the second holds a colliding child (a different
    // file at the entry itself).
    fx.peer_updates("Kept bytes", 5000);
    fx.peer_updates(&format!("Kept bytes (1)/{}", hex::encode(key)), 5001);

    let mut edit = fx.input(ChangeKind::Modify);
    edit.item_id = Some(item);
    edit.content = Some(content(bytes));
    edit.base = BaseVersion::Opaque(VersionHash([5; 32]));
    edit.base_generation = Some(item_generation_of(&fx, &item));
    assert_eq!(fx.run_raw(&edit).unwrap().outcome, OutcomeKind::Concurrent);
    let landed = format!("Kept bytes (2)/{}", hex::encode(key));
    assert_eq!(fx.row_version(&landed), Some(version_of(bytes)), "{landed} missing");
}

// ---- review 8 ----

/// (Z1) The journal of an undecided upload outlives its root: a rebootstrap between the first refused
/// transaction and the second keeps the row (an orphan, counted), so every age sweep that protects
/// the journal keeps the upload.
#[test]
fn a_rebootstrap_keeps_the_journal_of_an_undecided_upload() {
    let fx = Fx::new();
    fx.repo.journal_pending_ingest(&fx.root, b"session-000000001", 4, "upload-1", 10).unwrap();
    assert_eq!(fx.repo.orphaned_uploads(1_000).unwrap().0, 0);
    let new_root = fx.repo.rebootstrap_root(GROUP).unwrap();
    assert_ne!(new_root, fx.root);
    assert!(
        fx.repo.pending_ingest_names().unwrap().contains("upload-1"),
        "the journal died with the root"
    );
    assert_eq!(fx.repo.orphaned_uploads(1_000).unwrap(), (1, 990));
    // The status counts live and orphaned rows together.
    assert_eq!(fx.repo.undecided_uploads(1_000).unwrap(), (1, 990));
    // Only an explicit resolution removes it.
    fx.repo.clear_pending_ingest(&fx.root, b"session-000000001", 4).unwrap();
    assert!(fx.repo.pending_ingest_names().unwrap().is_empty());
}

/// (Z1) The same when the last link of the group is removed.
#[test]
fn removing_the_last_link_keeps_the_journal_of_an_undecided_upload() {
    let fx = Fx::new();
    fx.repo.journal_pending_ingest(&fx.root, b"session-000000001", 5, "upload-2", 10).unwrap();
    assert!(LinkRepository::new(fx.db.clone()).remove_link("/provider/p").unwrap());
    // The provider state stays until the host reports the domain removed...
    assert!(fx.repo.pending_ingest_names().unwrap().contains("upload-2"));
    assert_eq!(fx.repo.orphaned_uploads(500).unwrap().0, 0);
    // ...and then the journal outlives its root as an orphan record.
    assert!(fx.repo.domain_removed(&fx.root, "").unwrap());
    assert!(fx.repo.pending_ingest_names().unwrap().contains("upload-2"));
    assert_eq!(fx.repo.orphaned_uploads(500).unwrap().0, 1);
}

/// (Z2) More than a thousand later operations of the same session abandon the gap below them; the
/// retry of an operation with a journaled upload still decides it (never StaleOperation).
#[test]
fn a_journaled_undecided_operation_survives_the_session_floor() {
    let fx = Fx::new();
    let mut held = fx.input(ChangeKind::Create);
    held.name = Some("held.txt".into());
    held.content = Some(content(b"held bytes"));
    fx.repo
        .journal_pending_ingest(&fx.root, &held.session_id, held.operation_seq, "upload-3", 1)
        .unwrap();
    for n in 0..1100 {
        let mut other = fx.input(ChangeKind::Create);
        other.name = Some(format!("f{n}"));
        fx.run_raw(&other).unwrap();
    }
    // The floor was held below the undecided operation (not abandoned over it).
    let floor: i64 = fx
        .db
        .read::<_, SyncSqliteError>(|c| {
            Ok(c.query_row(
                "SELECT floor_seq FROM provider_apply_sessions WHERE root_id = ?1",
                [&fx.root],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(floor < held.operation_seq as i64, "the floor passed the undecided operation");
    let late = fx.run_raw(&held);
    assert!(late.is_ok(), "the undecided operation became stale: {late:?}");
    assert!(fx.live_paths().contains(&"held.txt".to_owned()));
    assert_eq!(
        fx.repo.pending_ingest_name(&fx.root, &held.session_id, held.operation_seq).unwrap(),
        None
    );
}

// ---- review 9 ----

/// (AA2) The processed floor is MONOTONE: two undecided low sequences, more sparse later sequences
/// than the pinned bound (the floor abandons gaps up to the first undecided), then the first upload
/// resolves and inserts its old sequence: the floor must not move backward, or an early decided
/// operation whose log entry was pruned would look new and be authored again.
#[test]
fn the_processed_floor_never_moves_backward() {
    let mut session = super::Session { floor: 0, above: BTreeSet::new() };
    for k in 0..(super::MAX_ABOVE_PINNED as u64 + 10) {
        session = session.with(10 + 2 * k, Some(1));
    }
    let abandoned_to = session.floor;
    assert!(abandoned_to > 2, "the bound was never reached");
    // The first undecided operation (sequence 1) is decided now.
    session = session.with(1, Some(2));
    assert!(session.floor >= abandoned_to, "the floor moved backward to {}", session.floor);
    // Every sequence at or below the floor is processed, including an early decided create whose
    // log entry expired.
    assert!(session.processed(1) && session.processed(5) && session.processed(abandoned_to));
}

// ---- a create that is already satisfied is adopted ----

fn create_input(
    fx: &Fx,
    parent: Option<ItemId>,
    name: &str,
    kind: EntryKind,
    bytes: Option<&[u8]>,
) -> ApplyInput {
    let mut input = fx.input(ChangeKind::Create);
    input.new_parent = Some(parent);
    input.name = Some(name.into());
    input.entry_kind = kind;
    input.content = bytes.map(content);
    input
}

/// The OS re-sends a create it never saw answered: a directory that already is there is the same
/// directory (its item id comes back, nothing is authored twice).
#[test]
fn a_create_of_an_existing_directory_adopts_it() {
    let fx = Fx::new();
    let dir = fx.create_dir(None, "d");
    let child = fx.create(Some(dir.item_id), "f", b"x").item_id;
    let before = fx.count("files");
    let again = fx.run_raw(&create_input(&fx, None, "d", EntryKind::Directory, None)).unwrap();
    assert_eq!(again.outcome, OutcomeKind::Applied);
    assert_eq!(again.item.unwrap().item_id, dir.item_id, "a second item was minted");
    assert_eq!(fx.count("files"), before, "a row was authored twice");
    assert_eq!(fx.live_paths(), ["d", "d/f"]);
    let _ = child;
}

#[test]
fn a_create_of_an_existing_file_with_the_same_bytes_adopts_it_and_other_bytes_still_collide() {
    let fx = Fx::new();
    let file = fx.create(None, "a.txt", b"same").item_id;
    let again =
        fx.run_raw(&create_input(&fx, None, "a.txt", EntryKind::File, Some(b"same"))).unwrap();
    assert_eq!(again.item.unwrap().item_id, file);
    // Other bytes: the existing behaviour, nothing invented (the bytes are kept beside the entry).
    let other =
        fx.run_raw(&create_input(&fx, None, "a.txt", EntryKind::File, Some(b"different"))).unwrap();
    assert_eq!(other.outcome, OutcomeKind::Concurrent);
    assert!(fx.kept_beside("a.txt", b"different"), "{:?}", fx.live_paths());
    // Same bytes but another mode is not "the same": same treatment.
    let mut moded = create_input(&fx, None, "a.txt", EntryKind::File, Some(b"same"));
    moded.metadata.unix_mode = Some(0o600);
    assert_eq!(fx.run_raw(&moded).unwrap().outcome, OutcomeKind::Concurrent);
}

#[test]
fn a_create_of_another_kind_onto_an_existing_name_is_not_adopted() {
    let fx = Fx::new();
    fx.create(None, "f", b"x");
    fx.create_dir(None, "d");
    // A directory with no bytes onto a file: still refused.
    let dir_on_file = fx.run_raw(&create_input(&fx, None, "f", EntryKind::Directory, None));
    assert!(matches!(dir_on_file, Err(ApplyError::NameCollision(_))), "{dir_on_file:?}");
    // A file onto a directory: its bytes are kept beside, as before, and the directory is untouched.
    let file_on_dir =
        fx.run_raw(&create_input(&fx, None, "d", EntryKind::File, Some(b"x"))).unwrap();
    assert_eq!(file_on_dir.outcome, OutcomeKind::Concurrent);
    assert!(fx.live_paths().contains(&"d".to_string()));
}
