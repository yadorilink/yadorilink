//! The drift check finds exactly what a missed watcher event leaves behind, changes nothing, and
//! never reads a missing volume as a mass deletion.

use super::tests::{adopt_root, canonical_root, processor};
use super::{DriftKind, DriftOptions};

fn kinds(report: &super::DriftReport) -> Vec<(&str, DriftKind)> {
    report.candidates.iter().map(|c| (c.rel_path.as_str(), c.kind)).collect()
}

/// An untouched tree reports nothing, and a pass does not write to the index.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_tree_has_no_drift_and_the_pass_writes_nothing() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    std::fs::write(root.join("sub/b.txt"), b"bb").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    let before = state.file_index_repository().list_files("group-1").unwrap().len();

    let report = proc.detect_drift("group-1", &root, DriftOptions::default()).unwrap();
    assert!(report.complete && report.candidates.is_empty(), "{report:?}");
    assert!(report.walked >= 3);
    assert_eq!(state.file_index_repository().list_files("group-1").unwrap().len(), before);
}

/// A missed modify, a missed delete and a missed re-create after a delete are all found; a new
/// file is left to the add-only backstop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missed_modify_delete_and_recreate_are_found() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    for name in ["same.txt", "edited.txt", "removed.txt", "reborn.txt"] {
        std::fs::write(root.join(name), b"original").unwrap();
    }
    proc.scan_existing_files("group-1", &root).unwrap();
    // reborn.txt: deleted through the index (a tombstone), then back on disk with no event.
    std::fs::remove_file(root.join("reborn.txt")).unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();

    std::fs::write(root.join("edited.txt"), b"a longer body than before").unwrap();
    std::fs::remove_file(root.join("removed.txt")).unwrap();
    std::fs::write(root.join("reborn.txt"), b"back").unwrap();
    std::fs::write(root.join("brand-new.txt"), b"never indexed").unwrap();

    let report = proc.detect_drift("group-1", &root, DriftOptions::default()).unwrap();
    let mut found = kinds(&report);
    found.sort();
    assert_eq!(
        found,
        vec![
            ("edited.txt", DriftKind::Changed),
            ("reborn.txt", DriftKind::Reappeared),
            ("removed.txt", DriftKind::Gone),
        ],
        "{report:?}"
    );
}

/// More than half of the folder gone is a wrong or missing folder, not deletions: no "gone"
/// verdict is returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folder_that_mostly_vanished_reports_no_deletions() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    for i in 0..150 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
    }
    proc.scan_existing_files("group-1", &root).unwrap();
    for i in 0..140 {
        std::fs::remove_file(root.join(format!("f{i}.txt"))).unwrap();
    }
    let report = proc.detect_drift("group-1", &root, DriftOptions::default()).unwrap();
    assert!(report.candidates.is_empty(), "{report:?}");
    assert!(report.gone_withheld.as_deref().unwrap_or("").contains("wrong folder"));
}

/// A root that is not the one recorded for the link (an unmounted volume's empty mount point) is an
/// error, not a tree full of deletions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_root_that_is_not_the_recorded_one_is_refused() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::write(root.join("a.txt"), b"a").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();

    let other = tempfile::tempdir().unwrap();
    let other_root = canonical_root(&other);
    assert!(proc.detect_drift("group-1", &other_root, DriftOptions::default()).is_err());
    // The recorded root stays usable.
    assert!(proc.detect_drift("group-1", &root, DriftOptions::default()).is_ok());
}

/// A pass that runs out of its budget says it is incomplete and withholds "gone" verdicts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_over_its_budget_is_incomplete_and_withholds_deletions() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    for i in 0..600 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
    }
    proc.scan_existing_files("group-1", &root).unwrap();
    std::fs::remove_file(root.join("f1.txt")).unwrap();
    let options = DriftOptions { budget: std::time::Duration::ZERO, ..DriftOptions::default() };
    let report = proc.detect_drift("group-1", &root, options).unwrap();
    assert!(!report.complete);
    assert!(report.candidates.iter().all(|c| c.kind != DriftKind::Gone), "{report:?}");
}

/// Cost of one drift pass over a large tree, for the record in `docs/perf/drift-check.md`. Run on
/// demand (needs a scratch directory on a real disk, not tmpfs):
/// `YL_BENCH_DIR=/path YL_BENCH_FILES=100000 cargo test --release -p yadorilink-local-capture --lib
/// bench_drift_pass -- --ignored --nocapture`. Prints one JSON line per measurement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement, not a test: needs YL_BENCH_DIR"]
async fn bench_drift_pass() {
    use std::time::Instant;
    let base = std::env::var("YL_BENCH_DIR").expect("YL_BENCH_DIR");
    let files: usize =
        std::env::var("YL_BENCH_FILES").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let (proc, state, _store_dir, _unused) = processor();
    let scratch = tempfile::tempdir_in(&base).unwrap();
    let root = std::fs::canonicalize(scratch.path()).unwrap();
    adopt_root(&state, "group-1", &root);
    let per_dir = 1000;
    for d in 0..files.div_ceil(per_dir) {
        let dir = root.join(format!("d{d:04}"));
        std::fs::create_dir(&dir).unwrap();
        for f in 0..per_dir.min(files - d * per_dir) {
            std::fs::write(dir.join(format!("f{f:04}.dat")), format!("{d}/{f}")).unwrap();
        }
    }
    let t = Instant::now();
    proc.scan_existing_files("group-1", &root).unwrap();
    let index_ms = t.elapsed().as_millis();

    let run = |label: &str, opts: DriftOptions| {
        let t = Instant::now();
        let report = proc.detect_drift("group-1", &root, opts).unwrap();
        println!(
            "{{\"label\":\"{label}\",\"files\":{files},\"walked\":{},\"candidates\":{},\"complete\":{},\"ms\":{},\"index_ms\":{index_ms}}}",
            report.walked,
            report.candidates.len(),
            report.complete,
            t.elapsed().as_millis()
        );
        report
    };
    let unthrottled = DriftOptions { max_entries_per_sec: 0, ..DriftOptions::default() };
    run("warm_unthrottled", unthrottled);
    if std::env::var("YL_BENCH_DROP_CACHES").is_ok() {
        let _ = std::process::Command::new("sudo")
            .args(["-n", "sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"])
            .status();
        run("cold_unthrottled", unthrottled);
    }
    run("default_rate_cap", DriftOptions::default());
    // 100 missed edits and 100 missed deletes spread over the tree.
    for i in 0..100 {
        let dir = root.join(format!("d{:04}", (i * 7) % files.div_ceil(per_dir)));
        std::fs::write(dir.join(format!("f{:04}.dat", i % 50)), "a longer body than before")
            .unwrap();
        let _ = std::fs::remove_file(dir.join(format!("f{:04}.dat", 500 + i)));
    }
    let report = run("with_drift", unthrottled);
    println!(
        "{{\"label\":\"drift_found\",\"changed\":{},\"gone\":{}}}",
        report.candidates.iter().filter(|c| c.kind == DriftKind::Changed).count(),
        report.candidates.iter().filter(|c| c.kind == DriftKind::Gone).count()
    );
}

/// A file whose time differs only by the granularity of a coarse file system is not drift (it would
/// come back in every pass); a same-size file whose time differs by more is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_time_off_by_a_coarse_granularity_is_not_drift_but_a_larger_one_is() {
    use std::time::Duration;
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    std::fs::write(root.join("coarse.txt"), b"same size").unwrap();
    std::fs::write(root.join("touched.txt"), b"same size").unwrap();
    proc.scan_existing_files("group-1", &root).unwrap();
    let shift = |name: &str, by: Duration| {
        let file = std::fs::OpenOptions::new().write(true).open(root.join(name)).unwrap();
        let modified = file.metadata().unwrap().modified().unwrap();
        file.set_modified(modified + by).unwrap();
    };
    shift("coarse.txt", Duration::from_secs(1));
    shift("touched.txt", Duration::from_secs(30));
    let report = proc.detect_drift("group-1", &root, DriftOptions::default()).unwrap();
    assert_eq!(kinds(&report), vec![("touched.txt", DriftKind::Changed)], "{report:?}");
}

/// A pass that hits the candidate cap says so (it is also incomplete, so no deletions follow).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hitting_the_candidate_cap_is_said_and_withholds_deletions() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    for i in 0..10 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
    }
    proc.scan_existing_files("group-1", &root).unwrap();
    for i in 0..10 {
        std::fs::write(root.join(format!("f{i}.txt")), b"now longer").unwrap();
    }
    let options = DriftOptions { max_candidates: 3, ..DriftOptions::default() };
    let report = proc.detect_drift("group-1", &root, options).unwrap();
    assert_eq!(report.candidates.len(), 3);
    assert!(!report.complete);
    assert!(report.gone_withheld.as_deref().unwrap_or("").contains("more than 3"), "{report:?}");
}

/// More "gone" verdicts than a pass carries are withheld whole, never sent as a partial list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_deletions_than_a_pass_carries_are_all_withheld() {
    let (proc, state, _store_dir, root_dir) = processor();
    let root = canonical_root(&root_dir);
    adopt_root(&state, "group-1", &root);
    for i in 0..10 {
        std::fs::write(root.join(format!("f{i}.txt")), b"x").unwrap();
    }
    for i in 0..4 {
        std::fs::write(root.join(format!("keep{i}.txt")), b"x").unwrap();
    }
    proc.scan_existing_files("group-1", &root).unwrap();
    for i in 0..4 {
        std::fs::remove_file(root.join(format!("f{i}.txt"))).unwrap();
    }
    let options = DriftOptions { max_candidates: 3, ..DriftOptions::default() };
    let report = proc.detect_drift("group-1", &root, options).unwrap();
    assert!(report.candidates.is_empty(), "{report:?}");
    assert!(report.gone_withheld.as_deref().unwrap_or("").contains("more than a pass carries"));
}
