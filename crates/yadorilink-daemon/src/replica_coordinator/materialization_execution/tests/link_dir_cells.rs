//! The repair sweep over symlink, explicit-directory and regular-file rows, one case per
//! combination of what an interrupted write can leave: the intent (none, prepared, landed, a
//! delete's), what is at the name (nothing, the object, an object of another kind, a symlink to
//! another target, a person's directory) and the sweep mode. Each case runs the real sweep, and
//! the set of `(kind, state, action, verdict)` cells the cases reach is pinned: the action is
//! what the sweep took, the verdict what the crash-state table says. A change to what the sweep
//! or the verdict does for any of these shows up here as exactly the rows that moved.
#![cfg(unix)]

use super::*;
use std::collections::BTreeMap;

const GROUP: &str = "group-link-dir-cells";
const PATH: &str = "obj";

#[derive(Clone, Copy, Debug)]
enum Intent {
    None,
    Prepared,
    Landed,
    Delete,
}

#[derive(Clone, Copy, Debug)]
enum Disk {
    Absent,
    Object,
    OtherKind,
    OtherTarget,
    /// A person's directory (only where the recorded object is not a directory).
    OtherDirectory,
}

fn run_case(
    kind: RecordKind,
    intent: Intent,
    disk: Disk,
    mode: RepairMode,
) -> Vec<(String, String, String, String)> {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    let root = tempfile::tempdir().unwrap();
    adopt_root(&state, GROUP, root.path());
    let permit = RootCommitPermit::for_tests();
    let record = FileRecord {
        path: PATH.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    };
    upsert_hydrated_file(&state, GROUP, &record, &permit);
    state.file_index_repository().set_record_kind(GROUP, PATH, kind, &permit).unwrap();
    if kind == RecordKind::Symlink {
        state.file_index_repository().set_symlink_target(GROUP, PATH, Some(b"target.txt")).unwrap();
    }
    let at = root.path().join(PATH);
    match (disk, kind) {
        (Disk::Absent, _) => {}
        (Disk::Object, RecordKind::Symlink) => {
            std::os::unix::fs::symlink("target.txt", &at).unwrap()
        }
        (Disk::Object, RecordKind::Directory) => std::fs::create_dir(&at).unwrap(),
        (Disk::Object, _) => std::fs::write(&at, b"").unwrap(),
        (Disk::OtherKind, RecordKind::Symlink) => std::fs::write(&at, b"a person's file").unwrap(),
        (Disk::OtherKind, _) => std::fs::write(&at, b"a person's file").unwrap(),
        (Disk::OtherTarget, _) => std::os::unix::fs::symlink("elsewhere.txt", &at).unwrap(),
        (Disk::OtherDirectory, _) => std::fs::create_dir(&at).unwrap(),
    }
    match intent {
        Intent::None => {}
        Intent::Prepared => {
            state
                .materialization_intent_repository()
                .begin_materialization_intent(GROUP, PATH, &[0; 32], &permit)
                .unwrap();
        }
        Intent::Landed => {
            state
                .materialization_intent_repository()
                .begin_materialization_intent(GROUP, PATH, &[0; 32], &permit)
                .unwrap();
            let generation = state.dag_bump_mutation_fence(GROUP, PATH, "test_write").unwrap();
            state
                .materialization_intent_repository()
                .mark_write_landed(GROUP, PATH, generation, &permit)
                .unwrap();
        }
        Intent::Delete => {
            let (guard, _) = state.open_tombstone_delete(GROUP, PATH, &permit).unwrap();
            // The crash: the delete never settles.
            drop(guard);
        }
    }
    let _ = yadorilink_filesystem_sync::repair_trace::take_thread_cells();
    repair_interrupted_materializations(&state, &store, root.path(), GROUP, mode, &permit).unwrap();
    yadorilink_filesystem_sync::repair_trace::take_thread_cells()
}

#[test]
fn rows_reach_the_pinned_cells() {
    let mut cells: BTreeMap<String, usize> = BTreeMap::new();
    for kind in [RecordKind::Symlink, RecordKind::Directory, RecordKind::File] {
        for intent in [Intent::None, Intent::Prepared, Intent::Landed, Intent::Delete] {
            for disk in [
                Disk::Absent,
                Disk::Object,
                Disk::OtherKind,
                Disk::OtherTarget,
                Disk::OtherDirectory,
            ] {
                if kind == RecordKind::Directory && matches!(disk, Disk::OtherDirectory) {
                    continue;
                }
                for mode in [RepairMode::Startup, RepairMode::Live] {
                    for (cell_kind, state, action, verdict) in run_case(kind, intent, disk, mode) {
                        *cells
                            .entry(format!("{cell_kind} {state} {action} verdict={verdict}"))
                            .or_default() += 1;
                    }
                }
            }
        }
    }
    let actual: Vec<String> = cells.iter().map(|(cell, n)| format!("{n:3}  {cell}")).collect();
    assert_eq!(
        actual,
        EXPECTED,
        "the cells these cases reach changed; if that is intended, update EXPECTED:\n{}",
        actual.join("\n")
    );
}

/// What the sweep does for each combination, by `(kind, state, action, verdict)` with the number of
/// cases that reach it.
///
/// Where the sweep does not carry out the verdict (the rows whose action is `Leave` and whose
/// verdict is not):
/// - a person's DIRECTORY at a symlink's name under a write intent. The verdict quarantines it;
///   the sweep leaves it, because moving a whole directory tree aside to make room for a link is
///   not a conflict copy of some bytes;
/// - a DANGLING symlink at the name of a landed regular file. It reads as "gone" to the fact reader
///   (the file's size is unreadable), so the verdict is a removal; the executor waits, because a
///   dangling symlink says nothing about whether the person removed the file.
const EXPECTED: [&str; 32] = [
    "  6  directory X11TransientNoIntent Leave verdict=Leave",
    "  2  directory X11TransientNoIntent Prove verdict=Prove",
    "  2  directory X3RenamedUnrecorded Prove verdict=Prove",
    "  2  directory X3RenamedUnrecorded Rebuild verdict=Rebuild",
    "  2  directory X4LandedDurable Prove verdict=Prove",
    "  2  directory X4LandedDurable RecordRemoval verdict=RecordRemoval",
    "  8  directory X7Diverged Quarantine verdict=Quarantine",
    "  4  directory X7Diverged RecordRemoval verdict=RecordRemoval",
    "  2  directory X8DeleteInFlight Leave verdict=Leave",
    "  2  directory X8bDeleteNotRemoved Prove verdict=Prove",
    "  8  file X11TransientNoIntent Leave verdict=Leave",
    "  2  file X11TransientNoIntent Prove verdict=Prove",
    "  2  file X3RenamedUnrecorded Prove verdict=Prove",
    "  4  file X3RenamedUnrecorded Rebuild verdict=Rebuild",
    "  2  file X4LandedDurable Leave verdict=RecordRemoval",
    "  2  file X4LandedDurable Prove verdict=Prove",
    "  2  file X4LandedDurable RecordRemoval verdict=RecordRemoval",
    "  8  file X7Diverged Quarantine verdict=Quarantine",
    "  4  file X7Diverged RecordRemoval verdict=RecordRemoval",
    "  4  file X8DeleteInFlight Leave verdict=Leave",
    "  2  file X8bDeleteNotRemoved Prove verdict=Prove",
    "  8  symlink X11TransientNoIntent Leave verdict=Leave",
    "  2  symlink X11TransientNoIntent Prove verdict=Prove",
    "  2  symlink X3RenamedUnrecorded Prove verdict=Prove",
    "  2  symlink X3RenamedUnrecorded Rebuild verdict=Rebuild",
    "  2  symlink X4LandedDurable Prove verdict=Prove",
    "  2  symlink X4LandedDurable RecordRemoval verdict=RecordRemoval",
    "  4  symlink X7Diverged Leave verdict=Quarantine",
    "  8  symlink X7Diverged Quarantine verdict=Quarantine",
    "  6  symlink X7Diverged RecordRemoval verdict=RecordRemoval",
    "  2  symlink X8DeleteInFlight Leave verdict=Leave",
    "  2  symlink X8bDeleteNotRemoved Prove verdict=Prove",
];
