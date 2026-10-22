//! The self-
//! healing lifecycle hook.
//!
//! A bare-`PeerSyncSession` DST scenario never runs the periodic sweeps a
//! real daemon runs (`repair_interrupted_materializations` +
//! `remove_recorded_temp_files`, driven by `link_runtime`), so a state the
//! production daemon would have repaired on its next sweep -- an interrupted
//! eager materialize's live-but-fileless index row plus an orphaned
//! `.yadorilink-tmp.*` file -- surfaced as `StructuralIndexDiskMismatch` /
//! `Corruption` violations that were pure harness artifacts (the
//! canonical inline account is in the retired two-device and
//! network-fault scenarios; reproduction: seed 3298840595).
//!
//! `run_self_healing` invokes the exact same production sweep code at each
//! quiescent point and before the terminal oracle checks. Every repair it
//! performs is returned as an *informational* `RepairedBySweep` finding:
//! a sweep that fixes a state keeps the signal about how
//! often the repair path is exercised visible rather than swallowed, while
//! a sweep that *fails* to reach a consistent state leaves a hard
//! structural/corruption violation for the terminal oracles that run after
//! it -- masking nothing, since the sweep runs production code and
//! exercising it more is coverage, not suppression.
//!
//! `#![cfg(turmoil)]`-gated like every DST scenario file.

use std::path::Path;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::materialization_repair::{
    repair_interrupted_materializations, RepairMode,
};
use yadorilink_local_storage::BlockContentStore;

use super::oracle::{Violation, ViolationKind};

/// Runs the production self-healing sweeps against one device's state,
/// block store, and synced root, returning one informational
/// `RepairedBySweep` finding per repair actually performed (a
/// reconstructed file, a demote-to-placeholder, or a removed stale temp
/// file). An empty result means the sweep found nothing to repair.
///
/// The sweep's own errors are best-effort-swallowed exactly as the
/// scenarios' inline call sites did (`let _ = repair_...`): a sweep that
/// cannot run is not itself a product violation, and any inconsistency it
/// therefore leaves behind is caught by the terminal structural/corruption
/// oracles run afterward.
pub fn run_self_healing(
    state: &ReplicaCoordinator,
    store: &dyn BlockContentStore,
    root: &Path,
    group_id: &str,
) -> Vec<Violation> {
    let mut findings = Vec::new();

    // `Live`, not `Startup`: this runs at quiescent points DURING an active
    // DST scenario (see this file's own module doc comment), the same
    // "periodic sweep while live edits can be in flight" shape the
    // production periodic task runs under -- not a one-time boot pass.
    if let Ok(report) = repair_interrupted_materializations(
        state,
        store,
        root,
        group_id,
        RepairMode::Live,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    ) {
        for path in report.reconstructed {
            findings.push(repaired(path, "reconstructed an interrupted eager materialize"));
        }
        for path in report.demoted_to_placeholder {
            findings.push(repaired(
                path,
                "demoted an unrecoverable interrupted materialize to a placeholder",
            ));
        }
    }

    for removed in state.remove_recorded_temp_files(group_id, root).unwrap_or_default() {
        findings.push(repaired(
            removed.to_string_lossy().into_owned(),
            "removed a recorded temp file a crash left",
        ));
    }

    findings
}

fn repaired(path: String, what: &str) -> Violation {
    Violation {
        kind: ViolationKind::RepairedBySweep,
        path: Some(path),
        content_ids: Vec::new(),
        devices: Vec::new(),
        detail: format!(
            "self-healing sweep {what} (informational -- the same repair a production daemon's \
             periodic sweep performs; not a failure)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::oracle::GlobalOracle;
    use super::*;
    use yadorilink_local_storage::SegmentBlockStore;
    use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
    use yadorilink_replica_domain::session_state::MaterializationState;

    const GROUP_ID: &str = "sweep-test-group";

    fn setup() -> (ReplicaCoordinator, tempfile::TempDir, SegmentBlockStore, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.link_repository().add_link(&root.path().to_string_lossy(), GROUP_ID).unwrap();
        let store = SegmentBlockStore::new(store_dir.path().to_path_buf()).unwrap();
        (state, root, store, store_dir)
    }

    /// The shape the sweep exists for (interrupted eager materialize:
    /// live Hydrated row, only a partial file on disk, blocks still present
    /// in the store, plus an orphaned temp file) -- the sweep must repair
    /// it and leave the terminal structural oracle clean, and it must
    /// report the repair rather than swallowing it.
    #[test]
    fn sweep_repairs_an_interrupted_materialization_and_records_it() {
        let (state, root, store, _store_dir) = setup();
        // Establish this root's identity marker up front, the way a real
        // daemon does at initial link setup, long before any later crash.
        // Without it, `repair_interrupted_materializations`'s internal
        // `VerifiedRoot::open` sees an unmarked root and falls back to
        // corroboration-based adoption -- which the partial on-disk file
        // written below (the interrupted-materialize scenario itself) can
        // never satisfy, since a partial write is definitionally a mismatch
        // against the index. That is not a bug in root-identity: it is this
        // fixture skipping the boot-time adoption a running install already
        // completed before any crash could interrupt a materialize.
        yadorilink_root_authority::root_identity::VerifiedRoot::readopt(
            root.path(),
            GROUP_ID,
            &state,
        )
        .unwrap();
        let content = b"pre-crash acknowledged content".repeat(8);
        let hash_hex = store.put(&content).unwrap();
        let record = FileRecord {
            path: "pre-crash.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            blocks: vec![BlockInfo {
                hash: hex::decode(&hash_hex).unwrap(),
                offset: 0,
                size: content.len() as u32,
            }],
            deleted: false,
        };
        state
            .file_index_repository()
            .upsert_file(
                GROUP_ID,
                &record,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        state
            .materialization_state_repository()
            .set_materialization_state(
                GROUP_ID,
                "pre-crash.bin",
                MaterializationState::Present,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // The intent journal entry a real materialize writes before it
        // touches the disk, and which a crash mid-write therefore leaves
        // behind. It is not decoration: on the `Live` cadence a diverged
        // file with no intent is deliberately NOT reconstructed, because it
        // may be a local edit the watcher has not captured yet
        // (`materialization_repair.rs`'s `on_disk_size.is_some() &&
        // !has_intent && mode == RepairMode::Live` branch, which hands it to
        // the dirty-journal backstop instead). Without this line the fixture
        // no longer models the scenario its own name claims -- it models an
        // uncaptured local edit, which the sweep is right to leave alone.
        state
            .materialization_intent_repository()
            .begin_materialization_intent(
                GROUP_ID,
                "pre-crash.bin",
                &hex::decode(&hash_hex).unwrap(),
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        // Only a partial file on disk + a temp file a previous (crashed)
        // process had recorded before creating it: the interrupted-materialize
        // window. The record, not the file name, is what lets the sweep remove it.
        std::fs::write(root.path().join("pre-crash.bin"), &content[..content.len() / 3]).unwrap();
        let orphan = root.path().join("pre-crash.bin.yadorilink-tmp.4242.1");
        yadorilink_local_storage::TempFileLedger::record(&state.temp_ledger(GROUP_ID), &orphan)
            .unwrap();
        std::fs::write(&orphan, b"interrupted materialize temp").unwrap();

        let findings = run_self_healing(&state, &store, root.path(), GROUP_ID);

        // The full content is now on disk, and the sweep reported both the
        // reconstruction and the temp-file cleanup.
        assert_eq!(std::fs::read(root.path().join("pre-crash.bin")).unwrap(), content);
        assert!(
            findings.iter().all(|f| f.kind == ViolationKind::RepairedBySweep),
            "all findings must be informational: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("reconstructed")),
            "expected a reconstruction finding: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("removed a recorded temp file")),
            "expected a temp-file cleanup finding: {findings:?}"
        );

        // Terminal structural oracle is clean after the sweep.
        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(GROUP_ID, &[(root.path(), &state)]);
        assert!(violations.is_empty(), "sweep should leave a consistent state: {violations:?}");
    }

    /// The sweep must not mask a genuinely inconsistent row it cannot
    /// repair: a live index row with no blocks to reconstruct from and no
    /// file on disk is unrepairable, so the sweep does nothing and the
    /// terminal structural oracle still hard-flags it (a
    /// sweep that fails to produce a consistent state still yields a hard
    /// violation).
    #[test]
    fn sweep_does_not_mask_a_genuinely_inconsistent_row() {
        let (state, root, store, _store_dir) = setup();
        state
            .file_index_repository()
            .upsert_file(
                GROUP_ID,
                &FileRecord {
                    path: "ghost.bin".to_string(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    blocks: Vec::new(), // nothing to reconstruct from
                    deleted: false,
                },
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();

        let findings = run_self_healing(&state, &store, root.path(), GROUP_ID);
        assert!(findings.is_empty(), "nothing was repairable: {findings:?}");

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(GROUP_ID, &[(root.path(), &state)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::StructuralIndexDiskMismatch);
    }
}
