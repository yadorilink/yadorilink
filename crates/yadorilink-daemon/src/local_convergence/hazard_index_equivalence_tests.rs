#![cfg(test)]

//! The indexed hazard lookup decides exactly what the scan it replaced did,
//! for every volume the check can run against.

use super::types::{
    hazard_reason_for_siblings, hazard_reason_for_volume, hazard_reason_for_volume_scan,
    VolumeFolding,
};
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "group-1";

fn record(path: &str, deleted: bool) -> FileRecord {
    FileRecord { path: path.to_string(), size: 0, mtime_unix_nanos: 1, blocks: vec![], deleted }
}

/// Names that collide under one fold or another, in the shapes the check
/// exists for, beside names that collide under none.
const LIVE: &[&str] = &[
    // ASCII case only.
    "docs/Report.TXT",
    "docs/readme.md",
    // Unicode case folding: sharp s, final and non-final sigma, dotted I.
    "docs/stra\u{df}e.txt",
    "docs/\u{3bf}\u{3b4}\u{3bf}\u{3c3}",
    "docs/\u{130}stanbul.txt",
    "docs/ankara\u{131}.txt",
    // Composed (NFC) and decomposed (NFD) spellings of one name.
    "docs/caf\u{e9}.txt",
    "docs/Na\u{ef}ve.txt",
    "mac/re\u{301}sume\u{301}.txt",
    // A combining mark that no composed form exists for.
    "docs/x\u{323}\u{307}.txt",
    // Case and normalization at once.
    "docs/\u{c9}COLE.txt",
    // A file and a directory spelled alike except for case.
    "a",
    "B/inner.txt",
    // Plain names that collide with nothing.
    "docs/unrelated.txt",
    "deep/er/than/that/file.bin",
];

/// A tombstone and a row in another group, both of which fold onto probes
/// below but must never be reported.
const TOMBSTONES: &[&str] = &["gone/Ghost.txt", "docs/DELETED.txt"];
const OTHER_GROUP: &[&str] = &["docs/REPORT.txt", "docs/CAFE\u{301}.txt", "other/only-there.txt"];

const PROBES: &[&str] = &[
    // The path itself: never a collision with itself.
    "docs/Report.TXT",
    "docs/readme.md",
    "docs/caf\u{e9}.txt",
    "a",
    // Case-only.
    "docs/report.txt",
    "DOCS/README.MD",
    // Unicode case folding.
    "docs/STRASSE.txt",
    "docs/STRA\u{1e9e}E.txt",
    "docs/\u{39f}\u{394}\u{39f}\u{3a3}",
    "docs/\u{3bf}\u{3b4}\u{3bf}\u{3c2}",
    "docs/istanbul.txt",
    "docs/i\u{307}stanbul.txt",
    "docs/ANKARAI.txt",
    // Normalization.
    "docs/cafe\u{301}.txt",
    "docs/Nai\u{308}ve.txt",
    "mac/r\u{e9}sum\u{e9}.txt",
    "docs/x\u{307}\u{323}.txt",
    // Case and normalization together.
    "docs/Cafe\u{301}.txt",
    "docs/e\u{301}cole.txt",
    "docs/\u{e9}COLE.txt",
    // A directory spelled like the file `a`, and a file under a directory
    // that differs from an existing one only by case.
    "A/b",
    "b/inner.txt",
    "B/INNER.TXT",
    // Tombstoned and other-group names.
    "gone/ghost.txt",
    "docs/deleted.txt",
    "docs/Report.txt",
    "other/ONLY-THERE.txt",
    // Nothing near them.
    "docs/absent.txt",
    "zzz/none.bin",
];

fn volumes() -> [VolumeFolding; 4] {
    let mut all = [VolumeFolding { case_insensitive: false, normalization_insensitive: false }; 4];
    for (i, volume) in all.iter_mut().enumerate() {
        volume.case_insensitive = i & 1 != 0;
        volume.normalization_insensitive = i & 2 != 0;
    }
    all
}

fn populated() -> crate::replica_coordinator::ReplicaCoordinator {
    let state = crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    let permit = RootCommitPermit::for_tests();
    let repo = state.file_index_repository();
    for path in LIVE {
        repo.upsert_file(GROUP, &record(path, false), &permit).unwrap();
    }
    for path in TOMBSTONES {
        repo.upsert_file(GROUP, &record(path, false), &permit).unwrap();
        repo.upsert_file(GROUP, &record(path, true), &permit).unwrap();
    }
    for path in OTHER_GROUP {
        repo.upsert_file("group-2", &record(path, false), &permit).unwrap();
    }
    // A path with a superseded version behind its current one.
    repo.upsert_file(GROUP, &record("docs/Versioned.txt", false), &permit).unwrap();
    let mut newer = record("docs/Versioned.txt", false);
    newer.mtime_unix_nanos = 2;
    repo.upsert_file(GROUP, &newer, &permit).unwrap();
    state
}

/// The kind of hazard a reason names, with the colliding sibling split off.
fn kind_and_sibling(reason: &str) -> (&str, &str) {
    let (kind, rest) = reason.split_once(": collides with existing '").expect("reason shape");
    (kind, rest.strip_suffix('\'').expect("closing quote"))
}

#[test]
fn the_indexed_lookup_decides_what_the_scan_decided_for_every_probe_and_volume() {
    let state = populated();
    let mut collisions = 0;
    for probe in PROBES {
        for volume in volumes() {
            let incoming = record(probe, false);
            let scanned = hazard_reason_for_volume_scan(&state, GROUP, &incoming, volume).unwrap();
            let indexed = hazard_reason_for_volume(&state, GROUP, &incoming, volume).unwrap();
            match (&scanned, &indexed) {
                (None, None) => {}
                (Some(old), Some(new)) => {
                    collisions += 1;
                    let (old_kind, old_sibling) = kind_and_sibling(old);
                    let (new_kind, new_sibling) = kind_and_sibling(new);
                    assert_eq!(old_kind, new_kind, "{probe:?} on {volume:?}");
                    // Several rows can collide with one probe; the scan names
                    // whichever it met first, the lookup the first by path.
                    // Either way the sibling named must collide for that kind.
                    let sibling = [record(new_sibling, false)];
                    assert_eq!(
                        hazard_reason_for_siblings(probe, volume, &sibling).as_deref(),
                        Some(format!("{new_kind}: collides with existing '{new_sibling}'"))
                            .as_deref(),
                        "{probe:?} on {volume:?} named {new_sibling:?}",
                    );
                    if old_sibling != new_sibling {
                        let live = LIVE.contains(&old_sibling) && LIVE.contains(&new_sibling);
                        assert!(live, "both named siblings are live rows");
                    }
                }
                _ => panic!("{probe:?} on {volume:?}: scan {scanned:?} but index {indexed:?}"),
            }
        }
    }
    assert!(collisions >= 30, "the corpus must exercise real collisions, saw {collisions}");
}

/// The corpus is only worth anything if the decisions it makes are the ones
/// the check exists for; pin the load-bearing ones by name.
#[test]
fn the_corpus_collides_where_it_should_and_only_there() {
    let state = populated();
    let both = VolumeFolding { case_insensitive: true, normalization_insensitive: true };
    let case_only = VolumeFolding { case_insensitive: true, normalization_insensitive: false };
    let none = VolumeFolding { case_insensitive: false, normalization_insensitive: false };
    let decide = |probe: &str, volume| {
        hazard_reason_for_volume(&state, GROUP, &record(probe, false), volume).unwrap()
    };
    // The probe's own path is never its own collision.
    assert_eq!(decide("docs/Report.TXT", both), None);
    // Sharp s and sigma fold; plain lowercase would miss both.
    assert!(decide("docs/STRASSE.txt", case_only).is_some());
    assert!(decide("docs/\u{39f}\u{394}\u{39f}\u{3a3}", case_only).is_some());
    // NFD against NFC needs the normalization axis, and the combined pair
    // needs both.
    assert_eq!(decide("docs/cafe\u{301}.txt", case_only), None);
    assert!(decide("docs/cafe\u{301}.txt", both).is_some());
    assert!(decide("docs/e\u{301}cole.txt", both).is_some());
    // Another group's and a deleted row's names never collide.
    assert_eq!(decide("gone/ghost.txt", both), None);
    assert_eq!(decide("other/ONLY-THERE.txt", both), None);
    // A volume that folds nothing never collides.
    assert_eq!(decide("docs/report.txt", none), None);
    // A directory and a file spelled alike share no whole path.
    assert_eq!(decide("A/b", both), None);
}
