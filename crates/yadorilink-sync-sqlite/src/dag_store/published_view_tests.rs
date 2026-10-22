//! The block-serving lookup against the scan it replaced, and the ways the set of
//! published versions of a group changes under it.

use rusqlite::{params, Connection};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId};

use super::{
    published_group_file_version_references_block as lookup,
    published_group_file_version_references_block_by_scan as scan,
};
use crate::dag_store::{put_file_version, put_file_versions_batch};

fn db() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    checkpoint(&c);
    c
}

/// The authorization checkpoint every piece of evidence refers to.
fn checkpoint(c: &Connection) {
    c.execute(
        "INSERT INTO native_authorization_checkpoints \
         (checkpoint_hash, group_id, device_id, checkpoint_seq, encoded, signature, \
          author_signing_public_key) VALUES (X'cc', 'g', 'd', 1, X'', X'', X'')",
        [],
    )
    .unwrap();
}

fn block(n: u8) -> Vec<u8> {
    vec![n; 32]
}

fn version(blocks: &[u8], tag: i64) -> FileVersion {
    FileVersion::new(
        blocks.iter().map(|b| VersionBlock { hash: BlockHash(block(*b)), size: 1 }).collect(),
        blocks.len() as u64,
        FileMeta {
            mtime_unix_nanos: tag,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn delta(n: u8) -> Vec<u8> {
    vec![n; 32]
}

fn authorize(c: &Connection, delta_hash: &[u8]) {
    c.execute(
        "INSERT OR IGNORE INTO native_delta_authorization (delta_hash, checkpoint_hash, merkle_proof) \
         VALUES (?1, X'cc', X'')",
        [delta_hash],
    )
    .unwrap();
}

/// A row-witness citing `delta_hash`'s identity for `version`.
fn witness(c: &Connection, group: &str, delta_hash: &[u8], suffix: u8, version: &FileVersion) {
    let mut identity = delta_hash.to_vec();
    identity.push(suffix);
    c.execute(
        "INSERT OR IGNORE INTO native_authoring_witness (group_id, identity, version) VALUES (?1, ?2, ?3)",
        params![group, identity, &version.version_hash.0[..]],
    )
    .unwrap();
}

fn head(c: &Connection, group: &str, path: &str, provenance: &[u8], version: &FileVersion) {
    c.execute(
        "INSERT INTO native_heads (group_id, path, author, incarnation, seq, version, provenance) \
         VALUES (?1, ?2, 'a', X'00000000000000000000000000000000', 1, ?3, ?4)",
        params![group, path, &version.version_hash.0[..], provenance],
    )
    .unwrap();
}

fn serves(c: &Connection, group: &str, b: u8) -> bool {
    lookup(c, group, &block(b)).unwrap()
}

#[test]
fn lookup_agrees_with_the_scan_over_a_generated_corpus() {
    let c = db();
    let groups = ["ga", "gb", "gc"];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move |bound: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % bound
    };
    let mut batch_pending: Vec<(&str, FileVersion)> = Vec::new();
    for (g, group) in groups.iter().enumerate() {
        for i in 0..40u8 {
            let count = 1 + next(4) as usize;
            // Blocks 0..30 are shared across versions, paths and groups; the version tag keeps
            // equal block lists distinct (renames, conflict copies, superseded versions).
            let blocks: Vec<u8> = (0..count).map(|_| next(30) as u8).collect();
            let v = version(&blocks, (g * 100 + i as usize) as i64);
            let d = delta(1 + (i % 7));
            match next(7) {
                0 => {
                    authorize(&c, &d);
                    witness(&c, group, &d, i, &v);
                }
                1 => witness(&c, group, &d, i, &v), // witnessed, evidence never attached
                2 => {
                    authorize(&c, &d);
                    head(&c, group, &format!("p{i}"), &d, &v);
                }
                3 => head(&c, group, &format!("p{i}"), &delta(200), &v), // head without evidence
                4 => {
                    // An authorised witness filed under ANOTHER group than the one holding the version.
                    authorize(&c, &d);
                    witness(&c, groups[(g + 1) % 3], &d, i, &v);
                }
                _ => {} // stored, never published
            }
            if next(2) == 0 {
                put_file_version(&c, group, &v).unwrap();
            } else {
                batch_pending.push((group, v));
            }
        }
    }
    for group in groups {
        let vs: Vec<&FileVersion> =
            batch_pending.iter().filter(|(g, _)| *g == group).map(|(_, v)| v).collect();
        put_file_versions_batch(&c, group, &vs).unwrap();
    }
    // A published version whose row was never stored (or is gone) but which has an index row:
    // the index alone must not authorize.
    let stray = version(&[35], 9_999);
    authorize(&c, &delta(1));
    witness(&c, "ga", &delta(1), 99, &stray);
    c.execute(
        "INSERT INTO file_version_blocks (group_id, block_hash, version_hash) VALUES ('ga', ?1, ?2)",
        params![block(35), &stray.version_hash.0[..]],
    )
    .unwrap();
    assert!(!serves(&c, "ga", 35), "an index row without its stored version authorized a block");
    let (mut served, mut refused) = (0, 0);
    for group in groups.iter().chain(&["no-such-group"]) {
        for b in 0..40u8 {
            let (new, old) =
                (lookup(&c, group, &block(b)).unwrap(), scan(&c, group, &block(b)).unwrap());
            assert_eq!(new, old, "group {group} block {b}");
            if new {
                served += 1;
            } else {
                refused += 1;
            }
        }
    }
    assert!(
        served > 20 && refused > 20,
        "corpus is degenerate: {served} served, {refused} refused"
    );
}

#[test]
fn a_block_stays_served_while_any_published_version_names_it() {
    let c = db();
    let (v1, v2) = (version(&[1, 2], 1), version(&[2, 3], 2));
    put_file_version(&c, "g", &v1).unwrap();
    put_file_version(&c, "g", &v2).unwrap();
    authorize(&c, &delta(1));
    witness(&c, "g", &delta(1), 1, &v1);
    head(&c, "g", "p", &delta(1), &v2);
    assert!([1, 2, 3].iter().all(|b| serves(&c, "g", *b)));

    c.execute("DELETE FROM native_authoring_witness", []).unwrap();
    assert!(!serves(&c, "g", 1), "only the removed version named block 1");
    assert!(serves(&c, "g", 2) && serves(&c, "g", 3), "the head still shows v2");

    c.execute("DELETE FROM native_heads", []).unwrap();
    assert!([1, 2, 3].iter().all(|b| !serves(&c, "g", *b)));

    // Re-publishing is idempotent and brings the blocks back; storing a version again adds nothing.
    assert!(!put_file_version(&c, "g", &v1).unwrap());
    witness(&c, "g", &delta(1), 1, &v1);
    witness(&c, "g", &delta(1), 1, &v1);
    assert!(serves(&c, "g", 1) && serves(&c, "g", 2) && !serves(&c, "g", 3));

    // Losing the evidence unpublishes without touching the version rows.
    c.execute("DELETE FROM native_delta_authorization", []).unwrap();
    assert!(!serves(&c, "g", 1));
}

#[test]
fn groups_do_not_authorize_each_others_blocks() {
    let c = db();
    let v = version(&[9], 1);
    put_file_version(&c, "ga", &v).unwrap();
    put_file_version(&c, "gb", &version(&[8], 2)).unwrap();
    authorize(&c, &delta(1));
    witness(&c, "ga", &delta(1), 1, &v);
    assert!(serves(&c, "ga", 9));
    assert!(!serves(&c, "gb", 9), "block 9 is published in ga only");
    assert!(!serves(&c, "gb", 8), "gb's own version is not published");
    // The same version stored in both groups, published in one.
    put_file_version(&c, "gb", &v).unwrap();
    assert!(!serves(&c, "gb", 9));
}

#[test]
fn clearing_a_groups_native_state_unpublishes_its_blocks_but_not_the_stored_versions() {
    let c = db();
    let (old, new) = (version(&[1, 2], 1), version(&[2, 3], 2));
    put_file_version(&c, "g", &old).unwrap();
    put_file_version(&c, "g", &new).unwrap();
    authorize(&c, &delta(1));
    witness(&c, "g", &delta(1), 1, &old);
    head(&c, "g", "p", &delta(1), &old);
    assert!(serves(&c, "g", 1));

    crate::native_checkpoint_install::clear_native_state(&c, &FolderGroupId("g".into())).unwrap();
    assert!([1, 2, 3].iter().all(|b| !serves(&c, "g", *b)), "stale evidence must not serve");
    let kept: i64 = c.query_row("SELECT COUNT(*) FROM file_versions", [], |r| r.get(0)).unwrap();
    assert_eq!(kept, 2, "the install keeps stored versions");

    // The installed state publishes a different version: exactly its blocks are served.
    checkpoint(&c);
    authorize(&c, &delta(2));
    head(&c, "g", "p", &delta(2), &new);
    assert!(!serves(&c, "g", 1) && serves(&c, "g", 2) && serves(&c, "g", 3));
}

/// Observation only (not a benchmark): lookup cost by group size, old scan against the index,
/// and what indexing adds to storing a version. Run with `--ignored --nocapture`.
#[test]
#[ignore = "timing observation"]
fn observe_lookup_and_store_cost() {
    use std::time::Instant;
    for versions in [1_000u32, 10_000, 100_000] {
        let c = db();
        let tx = c.unchecked_transaction().unwrap();
        authorize(&c, &delta(1));
        let mut chunk = Vec::new();
        for i in 0..versions {
            let b = |k: u32| (i.wrapping_mul(2654435761).wrapping_add(k) % 250) as u8;
            let v = FileVersion::new(
                (0..4)
                    .map(|k| VersionBlock {
                        hash: BlockHash([b(k), (i >> 8) as u8, i as u8, k as u8].repeat(8)),
                        size: 1,
                    })
                    .collect(),
                4,
                FileMeta {
                    mtime_unix_nanos: i as i64,
                    unix_mode: Some(0o644),
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: Vec::new(),
                },
            );
            c.execute(
                "INSERT INTO native_authoring_witness (group_id, identity, version) VALUES ('g', ?1, ?2)",
                params![[&delta(1)[..], &i.to_be_bytes()[..]].concat(), &v.version_hash.0[..]],
            )
            .unwrap();
            chunk.push(v);
            if chunk.len() == 1000 {
                put_file_versions_batch(&c, "g", &chunk.iter().collect::<Vec<_>>()).unwrap();
                chunk.clear();
            }
        }
        tx.commit().unwrap();
        // A block of the last version (present) and an absent one.
        let last = versions - 1;
        let present =
            [(last.wrapping_mul(2654435761) % 250) as u8, (last >> 8) as u8, last as u8, 0]
                .repeat(8);
        let absent = block(251);
        for (name, hash) in [("present", present), ("absent", absent)] {
            let n = if versions >= 100_000 { 3 } else { 20 };
            let t = Instant::now();
            let mut a = false;
            for _ in 0..n {
                a = scan(&c, "g", &hash).unwrap();
            }
            let old = t.elapsed() / n;
            let t = Instant::now();
            let mut b = false;
            for _ in 0..1000 {
                b = lookup(&c, "g", &hash).unwrap();
            }
            let new = t.elapsed() / 1000;
            assert_eq!(a, b);
            println!("{versions:>6} versions {name:>7}: scan {old:?}  lookup {new:?}");
        }
    }
    for blocks in [1usize, 432] {
        let c = db();
        let make = |i: i64| {
            FileVersion::new(
                (0..blocks)
                    .map(|k| VersionBlock {
                        hash: BlockHash(
                            [(k % 251) as u8, (k / 251) as u8, i as u8, (i >> 8) as u8].repeat(8),
                        ),
                        size: 1,
                    })
                    .collect(),
                blocks as u64,
                FileMeta {
                    mtime_unix_nanos: i,
                    unix_mode: Some(0o644),
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: Vec::new(),
                },
            )
        };
        let vs: Vec<FileVersion> = (0..400).map(make).collect();
        let t = Instant::now();
        for v in &vs[..200] {
            put_file_version(&c, "g", v).unwrap();
        }
        let with = t.elapsed() / 200;
        let t = Instant::now();
        for v in &vs[200..] {
            c.execute(
                "INSERT OR IGNORE INTO file_versions (version_hash, group_id, encoded) VALUES (?1, 'g', ?2)",
                params![&v.version_hash.0[..], v.canonical_encoding()],
            )
            .unwrap();
        }
        let without = t.elapsed() / 200;
        println!("{blocks:>4}-block version store: with index {with:?}, file_versions row only {without:?}");
    }
}

/// Observation only: a block shared by many versions, none published (miss) or all published
/// (hit), old scan against the lookup. Run with `--ignored --nocapture`.
#[test]
#[ignore = "timing observation"]
fn observe_widely_shared_block() {
    use std::time::Instant;
    for versions in [1_000u32, 10_000, 50_000] {
        for published in [false, true] {
            let c = db();
            authorize(&c, &delta(1));
            let tx = c.unchecked_transaction().unwrap();
            let mut chunk = Vec::new();
            for i in 0..versions {
                let v = version(&[7], i as i64);
                if published {
                    c.execute(
                        "INSERT INTO native_authoring_witness (group_id, identity, version) VALUES ('g', ?1, ?2)",
                        params![[&delta(1)[..], &i.to_be_bytes()[..]].concat(), &v.version_hash.0[..]],
                    )
                    .unwrap();
                }
                chunk.push(v);
                if chunk.len() == 1000 {
                    put_file_versions_batch(&c, "g", &chunk.iter().collect::<Vec<_>>()).unwrap();
                    chunk.clear();
                }
            }
            tx.commit().unwrap();
            let t = Instant::now();
            let mut a = false;
            for _ in 0..3 {
                a = scan(&c, "g", &block(7)).unwrap();
            }
            let old = t.elapsed() / 3;
            let t = Instant::now();
            let mut b = false;
            for _ in 0..20 {
                b = lookup(&c, "g", &block(7)).unwrap();
            }
            let new = t.elapsed() / 20;
            assert_eq!(a, b);
            println!("{versions:>6} sharing versions, published={published}: scan {old:?}  lookup {new:?}");
        }
    }
}

/// Observation only: bytes per `file_version_blocks` row on a real SQLite file.
#[test]
#[ignore = "size observation"]
fn observe_index_size() {
    for (versions, blocks) in [(100_000usize, 20usize), (1, 432)] {
        let dir = std::env::temp_dir()
            .join(format!("fvb-size-{versions}-{blocks}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c = Connection::open(dir.join("db")).unwrap();
        crate::replica_tables::init(&c).unwrap();
        let tx = c.unchecked_transaction().unwrap();
        let mut chunk = Vec::new();
        for i in 0..versions {
            let v = FileVersion::new(
                (0..blocks)
                    .map(|k| VersionBlock {
                        hash: BlockHash(
                            [
                                (k * 7 + i) as u8,
                                (k >> 8) as u8 ^ 0x5a,
                                (i >> 8) as u8,
                                (i >> 16) as u8 ^ k as u8,
                            ]
                            .repeat(8),
                        ),
                        size: 1,
                    })
                    .collect(),
                blocks as u64,
                FileMeta {
                    mtime_unix_nanos: i as i64,
                    unix_mode: Some(0o644),
                    symlink_target: None,
                    record_kind: RecordKind::File,
                    xattrs: Vec::new(),
                },
            );
            chunk.push(v);
            if chunk.len() == 1000 {
                put_file_versions_batch(&c, "g", &chunk.iter().collect::<Vec<_>>()).unwrap();
                chunk.clear();
            }
        }
        put_file_versions_batch(&c, "g", &chunk.iter().collect::<Vec<_>>()).unwrap();
        tx.commit().unwrap();
        let rows: i64 =
            c.query_row("SELECT COUNT(*) FROM file_version_blocks", [], |r| r.get(0)).unwrap();
        let bytes: i64 = c
            .query_row(
                "SELECT SUM(pgsize) FROM dbstat WHERE name = 'file_version_blocks'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        let payload: i64 = c
            .query_row(
                "SELECT SUM(payload) FROM dbstat WHERE name = 'file_version_blocks'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        println!("{versions} versions x {blocks} blocks: {rows} rows, {bytes} page bytes ({} per row), {payload} payload", bytes / rows.max(1));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
