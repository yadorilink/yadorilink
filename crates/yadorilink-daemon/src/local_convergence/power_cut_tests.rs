#![cfg(test)]
//! PowerCut: a thin crash-state model for the deferred-flush receive path
//! (`YADORILINK_RECEIVE_DEFERRED_FSYNC`, mode 1).
//!
//! The product is not simulated. A scenario drives the REAL receive (temp file,
//! rename, commit with the intent kept open, batch barrier, clear), arranging
//! the barrier's flushes through the existing test seams
//! (`fail_received_flushes_of`, a poisoned intent clear, the `OverlapProbe`
//! seams). The model then adds the one thing a test process cannot do: it
//! decides what the destination files look like after a power cut, from two
//! layers of state.
//!
//! * Durable: what reached stable storage through a persistence boundary that
//!   completed. The block store commit and the SQLite commit are atomic and
//!   already durable (SQLite is assumed atomic; the segment store has its own
//!   crash matrix, `segment_store_crash.rs`). A destination file's data is
//!   durable after its own `F_FULLFSYNC`; its name after the parent-directory
//!   flush.
//! * Volatile: everything else. A file whose data or name is not durable comes
//!   back as one of [`Cut`]: the old content, the new content, a partial write
//!   (with or without the recorded metadata), a zero-length file, or nothing.
//!
//! A PowerCut is: pick the outcome of every non-durable file, rewrite the
//! destination accordingly, discard the process (the in-memory state), run the
//! REAL startup repair, optionally cut again during the repair, then check the
//! invariants in [`check`]. There is no fake repair.
//!
//! What this does NOT prove: that the OS/drive honours `F_FULLFSYNC` (a drive that
//! lies is outside every model), anything about the physical order in which a real
//! filesystem persists unflushed data, and the segment store's own commit ordering
//! (covered by its crash matrix). See docs/TESTING.md.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_deferred_flush_tests::{
    closed, edit_by_atomic_replace, edit_in_place_longer, edit_in_place_same_size, intent_open,
    present, proven, repair, startup, use_deferred, FULL_FLUSH_EACH,
};
use super::receive_window_concurrency_tests::{
    arm, driver, pin_concurrency, publish, put, reconcile, source,
};
use super::{OverlapProbe, ProbeSeam};
use yadorilink_filesystem_sync::materialization_repair::RepairMode;
use yadorilink_local_storage::completed_flushes_under;

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

/// What a destination whose data or name was not durable comes back as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cut {
    /// The previous version's bytes (a name whose rename was not durable), or
    /// no file when there was no previous version.
    Old,
    /// The new bytes (the cache was written back by luck).
    New,
    /// Part of the new bytes, the rest zeros, with the metadata the proof recorded.
    Partial,
    /// Part of the new bytes, the rest zeros, and the metadata of an ordinary write.
    PartialRestamped,
    /// A file of length zero.
    Zero,
    /// No file at the name.
    Missing,
}

const EVERY_CUT: [Cut; 6] =
    [Cut::Old, Cut::New, Cut::Partial, Cut::PartialRestamped, Cut::Zero, Cut::Missing];

/// What of a file reached stable storage when the power went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Durable {
    /// Data and name: nothing to decide.
    Both,
    /// The data was flushed but not the directory entry: the name may be lost.
    DataOnly,
    /// Not flushed: any of [`EVERY_CUT`].
    Neither,
    /// Only the synced temp file exists: it survives or its name is lost.
    TempOnly,
}

impl Durable {
    fn allowed(self) -> &'static [Cut] {
        match self {
            Durable::Both => &[Cut::New],
            Durable::TempOnly => &[Cut::New, Cut::Missing],
            Durable::DataOnly => &[Cut::New, Cut::Old, Cut::Missing],
            Durable::Neither => &EVERY_CUT,
        }
    }
}

/// Where in the receive the process stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    /// Intent open, temp file staged and synced, not yet renamed.
    BeforeRename,
    /// Renamed in without a flush, nothing committed (no proof, no marker).
    BeforeCommit,
    /// Committed with the intent open and marked; the barrier then ran.
    Committed,
}

/// How the barrier of a [`Stage::Committed`] run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Barrier {
    /// The process survives the barrier: files whose flush failed keep their
    /// intent, the others are cleared; the power goes later.
    Survives,
    /// The power goes while the files are being flushed: no directory flush, no clear.
    CutInFiles,
    /// Every file flushed, the power goes before the parent-directory flush.
    CutBeforeDirFlush,
    /// Files and directories flushed, the power goes before the intent clear.
    CutBeforeClear,
}

#[derive(Debug, Clone)]
pub(super) enum UserEdit {
    None,
    SameSize(usize),
    Longer(usize),
    AtomicReplace(usize),
}

#[derive(Debug, Clone)]
pub(super) struct Scenario {
    /// Makes the file names unique: the flush-failure seam matches by name across tests.
    pub(super) uid: u64,
    pub(super) files: usize,
    /// Every name already holds a previous version, received and closed.
    pub(super) prior: bool,
    pub(super) stage: Stage,
    pub(super) barrier: Barrier,
    /// Per file: its destination flush completed.
    pub(super) flushed: Vec<bool>,
    /// Per file: what it comes back as (must be allowed by its [`Durable`] class).
    pub(super) cuts: Vec<Cut>,
    pub(super) user_edit: UserEdit,
    /// A block-store sweep runs in the unflushed window.
    pub(super) gc: bool,
    /// The power goes again during the first repair, after it rebuilt files (its
    /// own durable write) and before its database commit lands.
    pub(super) second_cut: bool,
}

impl Scenario {
    fn durable(&self, file: usize) -> Durable {
        match self.stage {
            Stage::BeforeRename => Durable::TempOnly,
            Stage::BeforeCommit => Durable::Neither,
            Stage::Committed => match (self.barrier, self.flushed[file]) {
                (Barrier::Survives, true) | (Barrier::CutBeforeClear, _) => Durable::Both,
                (Barrier::Survives, false) | (Barrier::CutInFiles, false) => Durable::Neither,
                (Barrier::CutInFiles, true) | (Barrier::CutBeforeDirFlush, _) => Durable::DataOnly,
            },
        }
    }

    /// The barrier ends in a cut: its intent clear never runs.
    fn clear_never_runs(&self) -> bool {
        self.stage == Stage::Committed && self.barrier != Barrier::Survives
    }

    fn name(&self, file: usize) -> String {
        format!("pc{}_f{file}-doc.txt", self.uid)
    }

    fn validate(&self) {
        assert_eq!(self.flushed.len(), self.files, "{self:?}");
        assert_eq!(self.cuts.len(), self.files, "{self:?}");
        for file in 0..self.files {
            let allowed = self.durable(file).allowed();
            assert!(
                allowed.contains(&self.cuts[file]),
                "file {file} cannot come back so: {self:?}"
            );
        }
        if let UserEdit::SameSize(i) | UserEdit::Longer(i) | UserEdit::AtomicReplace(i) =
            self.user_edit
        {
            assert!(i < self.files && self.stage == Stage::Committed, "{self:?}");
        }
    }
}

/// Rewrites one destination the way the model says the power cut left it.
fn apply_cut(path: &Path, new: &[u8], old: Option<&[u8]>, cut: Cut) {
    use std::io::Write;
    match cut {
        Cut::New => {}
        Cut::Old => match old {
            Some(old) => {
                let _ = std::fs::remove_file(path);
                std::fs::write(path, old).unwrap();
            }
            None => {
                let _ = std::fs::remove_file(path);
            }
        },
        Cut::Partial | Cut::PartialRestamped => {
            let Ok(meta) = std::fs::metadata(path) else { return };
            let mtime = meta.modified().unwrap();
            let mut bytes = new.to_vec();
            let half = bytes.len() / 2;
            bytes[half..].fill(0);
            let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
            file.write_all(&bytes).unwrap();
            if cut == Cut::Partial {
                file.set_modified(mtime).unwrap();
            }
        }
        Cut::Zero => {
            if path.exists() {
                std::fs::OpenOptions::new().write(true).truncate(true).open(path).unwrap();
            }
        }
        Cut::Missing => {
            let _ = std::fs::remove_file(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Driving the real receive
// ---------------------------------------------------------------------------

struct Run {
    h: Harness,
    scenario: Scenario,
    /// The version the receive was given, per file.
    new: BTreeMap<String, Vec<u8>>,
    old: BTreeMap<String, Vec<u8>>,
    /// Set when the flushes the real barrier performed are not the ones the scenario
    /// assumes durable: the model derives durability from what really happened.
    flush_mismatch: Option<String>,
    /// The bytes a user wrote over a received file, per file.
    user: BTreeMap<String, Vec<u8>>,
}

async fn publish_generation(
    h: &Harness,
    scenario: &Scenario,
    generation: &str,
) -> BTreeMap<String, Vec<u8>> {
    let mut contents = BTreeMap::new();
    let mut ops = Vec::new();
    for file in 0..scenario.files {
        let name = scenario.name(file);
        let content = format!("{generation} content of {name}, long enough to tear").into_bytes();
        let tag = format!("{generation}-{file}");
        let version = source(h, &tag, &content).await;
        // The scratch name only mints the version. Left live, it is a second holder of
        // the content, and replacing the first version at the received name then waits
        // until that holder is proven on disk. A volume with a coarse birth-time clock
        // (Linux) cannot prove it, so the receive would never run.
        let scratch = format!("zz-source-{tag}");
        std::fs::remove_file(h.path(&scratch)).unwrap();
        h.observe_removal(&scratch).await;
        ops.push(put(&name, version));
        contents.insert(name, content);
    }
    publish(h, &ops);
    contents
}

/// What the real barrier flushed (recorded where the flush primitive runs) against
/// what the scenario treats as durable: a file flushed in the model but not in
/// the product, or the other way round, is a broken persistence boundary.
fn observed_flush_mismatch(h: &Harness, scenario: &Scenario, mark: usize) -> Option<String> {
    let all = completed_flushes_under(&h.path(""));
    let seen: BTreeSet<_> = all[mark..].iter().cloned().collect();
    for file in 0..scenario.files {
        let path = h.path(&scenario.name(file));
        if seen.contains(&path) != scenario.flushed[file] {
            return Some(format!(
                "{} {} flushed by the barrier but the scenario assumes it {}",
                scenario.name(file),
                if seen.contains(&path) { "was" } else { "was not" },
                if scenario.flushed[file] { "was" } else { "was not" },
            ));
        }
    }
    let dir_flushed = all[mark..].iter().any(|p| *p == h.path(""));
    if scenario.flushed.iter().any(|f| *f) && !dir_flushed {
        return Some("the parent directory was never flushed after a file was".into());
    }
    None
}

fn poison_intent_clear(h: &Harness) {
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER poison_clear BEFORE DELETE ON materialization_intents \
                 BEGIN SELECT RAISE(ABORT, 'power cut'); END;",
            )?;
            Ok(())
        })
        .unwrap();
}

fn heal_intent_clear(h: &Harness) {
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch("DROP TRIGGER IF EXISTS poison_clear")?;
            Ok(())
        })
        .unwrap();
}

async fn hold_at_seam(h: &Harness, scenario: &Scenario, seam: ProbeSeam) {
    let probe = OverlapProbe::new(seam, scenario.files, 30_000);
    probe.hold_until_released();
    arm(h, &probe);
    let task = {
        let (convergence, files) = (
            h.convergence.clone(),
            (0..scenario.files).map(|i| scenario.name(i)).collect::<BTreeSet<_>>(),
        );
        tokio::spawn(
            async move { convergence.reconcile_paths_directly(&driver(), GROUP, files).await },
        )
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < scenario.files {
        assert!(waited.elapsed() < std::time::Duration::from_secs(30), "{:?}", probe.events());
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    // The process is gone: nothing after the seam ever runs.
    task.abort();
    let _ = task.await;
    *h.convergence.overlap_probe.lock().unwrap() = None;
}

/// Receives the scenario's files through the real path up to its stage.
async fn receive(scenario: &Scenario) -> Run {
    scenario.validate();
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_deferred(&h, FULL_FLUSH_EACH);
    let all: Vec<String> = (0..scenario.files).map(|i| scenario.name(i)).collect();
    let mut old = BTreeMap::new();
    if scenario.prior {
        old = publish_generation(&h, scenario, "previous").await;
        reconcile(&h, &all).await;
        h.convergence.drain_flush_barriers().await;
        assert!(all.iter().all(|n| closed(&h, n)), "the previous version is closed and durable");
    }
    let new = publish_generation(&h, scenario, "current").await;

    let mark = completed_flushes_under(&h.path("")).len();
    let mut flush_mismatch = None;
    match scenario.stage {
        Stage::BeforeRename => hold_at_seam(&h, scenario, ProbeSeam::BeforeRename).await,
        Stage::BeforeCommit => hold_at_seam(&h, scenario, ProbeSeam::BeforeCommit).await,
        Stage::Committed => {
            if scenario.clear_never_runs() {
                poison_intent_clear(&h);
            }
            let _fail: Vec<_> = (0..scenario.files)
                .filter(|i| !scenario.flushed[*i])
                .map(|i| {
                    yadorilink_local_storage::fail_received_flushes_of(&format!(
                        "pc{}_f{i}-",
                        scenario.uid
                    ))
                })
                .collect();
            let attempt = reconcile(&h, &all).await;
            assert!(all.iter().all(|n| attempt.is_settled(n)), "{scenario:?}");
            h.convergence.drain_flush_barriers().await;
            flush_mismatch = observed_flush_mismatch(&h, scenario, mark);
        }
    }
    let mut run =
        Run { h, scenario: scenario.clone(), new, old, flush_mismatch, user: BTreeMap::new() };
    run.user_edit();
    run
}

impl Run {
    fn user_edit(&mut self) {
        let (kind, i) = match self.scenario.user_edit {
            UserEdit::None => return,
            UserEdit::SameSize(i) => (0, i),
            UserEdit::Longer(i) => (1, i),
            UserEdit::AtomicReplace(i) => (2, i),
        };
        let name = self.scenario.name(i);
        let content = self.new[&name].clone();
        let bytes = match kind {
            0 => edit_in_place_same_size(&self.h, &name, &content),
            1 => edit_in_place_longer(&self.h, &name, &content),
            _ => edit_by_atomic_replace(&self.h, &name, &content),
        };
        self.user.insert(name, bytes);
    }

    /// The window between the receive and the cut: a block-store sweep, if asked.
    fn window(&self) {
        if !self.scenario.gc {
            return;
        }
        sweep_every_unreferenced_block(&self.h);
    }

    /// Loses as many staged temp files as the scenario has `Missing` outcomes (the
    /// receive does not say which temp name belongs to which file, so the first
    /// ones by name go).
    fn lose_temp_files(&self) {
        let lost = self.scenario.cuts.iter().filter(|c| **c == Cut::Missing).count();
        let mut temps: Vec<_> = std::fs::read_dir(self.h.path(""))
            .unwrap()
            .flatten()
            .filter(|entry| is_temp_name(&entry.file_name().to_string_lossy()))
            .map(|entry| entry.path())
            .collect();
        temps.sort();
        for path in temps.into_iter().take(lost) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// The power goes: what was not durable comes back as the model says.
    fn power_cut(&self) {
        for file in 0..self.scenario.files {
            let name = self.scenario.name(file);
            if self.user.contains_key(&name) {
                // The user's own write is theirs to have flushed: it survives.
                continue;
            }
            let path = self.h.path(&name);
            match self.scenario.stage {
                Stage::BeforeRename => {
                    // Staged under a temp name (synced); the destination is untouched.
                    if file == 0 {
                        self.lose_temp_files();
                    }
                }
                _ => apply_cut(
                    &path,
                    &self.new[&name],
                    self.old.get(&name).map(|b| &b[..]),
                    self.scenario.cuts[file],
                ),
            }
        }
    }
}

/// A staged temp file: anything but the destinations, the scratch sources and the
/// root's own markers.
fn is_temp_name(leaf: &str) -> bool {
    !leaf.starts_with("zz-source-")
        && !leaf.starts_with(".yadorilink-root")
        && !leaf.starts_with("pc")
}

fn sweep_every_unreferenced_block(h: &Harness) {
    use yadorilink_local_storage::BlockReclamationStore as _;
    let live = h
        .state
        .materialization_state_repository()
        .live_block_hashes_including_native_heads()
        .unwrap();
    let cutoff = std::time::SystemTime::now() + std::time::Duration::from_secs(3600);
    h.store.sweep(&live, cutoff, false).unwrap();
}

// ---------------------------------------------------------------------------
// The invariants
// ---------------------------------------------------------------------------

fn snapshot(h: &Harness) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(h.path(""))
        .unwrap()
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap()))
        .collect()
}

/// After the repair (and, for a receive stopped before its commit, after the
/// receive resumed): the invariants of the scenario, or the first one broken.
fn check(run: &Run, phase: &str) -> Result<(), String> {
    let (h, s) = (&run.h, &run.scenario);
    let files = snapshot(h);
    for file in 0..s.files {
        let name = s.name(file);
        let want = &run.new[&name];
        let at_name = files.get(&name);
        let side: Vec<(&String, &Vec<u8>)> = files
            .iter()
            .filter(|(n, _)| **n != name && !n.starts_with("zz-source-") && n.contains("conflict"))
            .collect();
        match run.user.get(&name) {
            Some(user) => {
                // An accepted user edit is never lost: at the name or in a preserved copy.
                let kept = at_name == Some(user) || side.iter().any(|(_, b)| *b == user);
                if !kept {
                    return Err(format!("{phase}: the user's edit of {name} is lost"));
                }
            }
            None => {
                if at_name != Some(want) {
                    return Err(format!(
                        "{phase}: {name} holds {:?}, not the received version",
                        at_name.map(|b| String::from_utf8_lossy(b).into_owned())
                    ));
                }
            }
        }
        if intent_open(h, &name) {
            return Err(format!("{phase}: the intent of {name} is left unresolved"));
        }
        if run.user.contains_key(&name) {
            continue;
        }
        if !(proven(h, &name) && present(h, &name)) {
            return Err(format!("{phase}: {name} is not proven present"));
        }
    }
    // No stray temp or empty file is left to be read as content.
    for (name, bytes) in &files {
        if name.starts_with("zz-source-") || name.starts_with('.') || name.contains("conflict") {
            continue;
        }
        let expected = (0..s.files).any(|f| s.name(f) == *name);
        if !expected {
            if run.user.keys().any(|_| name == "user-editor.swp") {
                continue;
            }
            return Err(format!("{phase}: stray file {name}"));
        }
        if bytes.is_empty() {
            return Err(format!("{phase}: {name} is an empty file"));
        }
    }
    // Nothing a cut left behind was authored as a local change (the user's edit excepted).
    let authored: BTreeSet<String> = h.scan().into_iter().map(|r| r.path).collect();
    for path in &authored {
        if !run.user.contains_key(path) && !path.contains("conflict") {
            return Err(format!("{phase}: {path} was authored as a local change"));
        }
    }
    Ok(())
}

/// Runs the scenario to its end and returns the first broken invariant.
pub(super) async fn run_scenario(scenario: &Scenario) -> Result<(), String> {
    let run = receive(scenario).await;
    if let Some(mismatch) = &run.flush_mismatch {
        return Err(mismatch.clone());
    }
    run.window();
    run.power_cut();
    heal_intent_clear(&run.h);

    // Restart: the real startup repair.
    if scenario.second_cut {
        // The repair rebuilds through the same durable write as a receive; the
        // power goes before the transaction that records it commits.
        poison_intent_clear(&run.h);
        let _ =
            yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
                run.h.state.as_ref(),
                &*run.h.convergence.store,
                &run.h.path(""),
                GROUP,
                RepairMode::Startup,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            );
        heal_intent_clear(&run.h);
    }
    let first = startup(&run.h);
    if std::env::var_os("YADORILINK_POWER_CUT_TRACE").is_some() {
        eprintln!("repair: {first:?}\nfiles: {:?}", snapshot(&run.h).keys().collect::<Vec<_>>());
    }
    if scenario.stage != Stage::Committed {
        // The receive had not committed: it is still owed and resumes.
        let all: Vec<String> = (0..scenario.files).map(|i| scenario.name(i)).collect();
        let attempt = reconcile(&run.h, &all).await;
        if !all.iter().all(|n| attempt.is_settled(n)) {
            return Err(format!("the interrupted receive does not resume: {first:?}"));
        }
        run.h.convergence.drain_flush_barriers().await;
    }
    check(&run, "after repair")?;

    // Repair is idempotent: a second start changes nothing.
    let before = snapshot(&run.h);
    let again = repair(&run.h, RepairMode::Startup);
    if !again.reconstructed.is_empty()
        || !again.quarantined_dirty.is_empty()
        || !again.offline_deleted.is_empty()
        || !again.demoted_to_placeholder.is_empty()
    {
        return Err(format!("a second repair still acts: {again:?}"));
    }
    if snapshot(&run.h) != before {
        return Err("a second repair changed the files".into());
    }
    check(&run, "after the second repair")
}

// ---------------------------------------------------------------------------
// The gate: representative cases, one per numbered crash position
// ---------------------------------------------------------------------------

static NEXT_UID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn base(files: usize, stage: Stage, barrier: Barrier) -> Scenario {
    Scenario {
        uid: NEXT_UID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        files,
        prior: false,
        stage,
        barrier,
        flushed: vec![false; files],
        cuts: vec![Cut::New; files],
        user_edit: UserEdit::None,
        gc: false,
        second_cut: false,
    }
}

async fn expect_ok(scenario: Scenario) {
    if let Err(violation) = run_scenario(&scenario).await {
        panic!("PowerCut invariant broken: {violation}\nscenario: {scenario:?}");
    }
}

/// (2) After the intent is persisted, before the rename: the receive resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_cut_before_the_rename_resumes_the_receive() {
    for cut in [Cut::New, Cut::Missing] {
        for prior in [false, true] {
            let mut s = base(2, Stage::BeforeRename, Barrier::Survives);
            s.prior = prior;
            s.cuts = vec![cut; 2];
            expect_ok(s).await;
        }
    }
}

/// (3) After the rename, before any flush: lost or corrupt destinations are rebuilt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_cut_after_the_rename_before_the_commit_recovers_every_outcome() {
    for cut in EVERY_CUT {
        let mut s = base(1, Stage::BeforeCommit, Barrier::Survives);
        s.cuts = vec![cut];
        s.prior = cut == Cut::Old;
        expect_ok(s).await;
    }
}

/// (3)(4) Committed, nothing flushed, the intent open: every outcome per file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_cut_with_nothing_flushed_recovers_every_outcome() {
    for cut in EVERY_CUT {
        let mut s = base(2, Stage::Committed, Barrier::CutInFiles);
        s.prior = cut == Cut::Old;
        s.cuts = vec![cut, Cut::New];
        s.flushed = vec![false, true];
        expect_ok(s).await;
    }
}

/// (4) A flush that fails mid-barrier clears only the files that were flushed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_flush_error_keeps_the_intent_until_the_file_is_durable() {
    for cut in [Cut::Partial, Cut::Zero, Cut::Missing] {
        let mut s = base(3, Stage::Committed, Barrier::Survives);
        s.flushed = vec![true, false, true];
        s.cuts = vec![Cut::New, cut, Cut::New];
        expect_ok(s).await;
    }
}

/// (5) Files flushed, the directory not: a lost name is recoverable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_cut_before_the_directory_flush_recovers_a_lost_name() {
    for cut in [Cut::Missing, Cut::Old] {
        let mut s = base(2, Stage::Committed, Barrier::CutBeforeDirFlush);
        s.prior = cut == Cut::Old;
        s.flushed = vec![true; 2];
        s.cuts = vec![cut, Cut::New];
        expect_ok(s).await;
    }
}

/// (6) Everything flushed, the clear not run: the restart resolves the intents.
/// (7) Right after the clear: the completed content stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_cut_around_the_intent_clear_keeps_the_content() {
    let mut s = base(2, Stage::Committed, Barrier::CutBeforeClear);
    s.flushed = vec![true; 2];
    expect_ok(s).await;
    let mut s = base(2, Stage::Committed, Barrier::Survives);
    s.flushed = vec![true; 2];
    expect_ok(s).await;
}

/// (8) A user's edit in the unflushed window is never overwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_user_edit_in_the_unflushed_window_is_kept() {
    for edit in [UserEdit::SameSize(0), UserEdit::Longer(0), UserEdit::AtomicReplace(0)] {
        let mut s = base(2, Stage::Committed, Barrier::Survives);
        s.flushed = vec![false, false];
        s.cuts = vec![Cut::New, Cut::Partial];
        s.user_edit = edit;
        expect_ok(s).await;
    }
}

/// (9) A block-store sweep in the unflushed window keeps what recovery needs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_sweep_in_the_unflushed_window_keeps_the_blocks_recovery_needs() {
    let mut s = base(2, Stage::Committed, Barrier::CutInFiles);
    s.flushed = vec![false, false];
    s.cuts = vec![Cut::Missing, Cut::Zero];
    s.gc = true;
    expect_ok(s).await;
}

/// (10) The power goes again during the repair: the next start still recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gate_a_second_cut_during_the_repair_still_recovers() {
    let mut s = base(2, Stage::Committed, Barrier::CutInFiles);
    s.flushed = vec![false, false];
    s.cuts = vec![Cut::Missing, Cut::Partial];
    s.second_cut = true;
    expect_ok(s).await;
}

// ---------------------------------------------------------------------------
// Exploration: exhaustive over small state spaces, then seeded
// ---------------------------------------------------------------------------

/// Every combination of `choices[i]` for each file `i`.
fn product(choices: &[&'static [Cut]]) -> Vec<Vec<Cut>> {
    let mut all = vec![Vec::new()];
    for options in choices {
        all = all
            .into_iter()
            .flat_map(|prefix| {
                options.iter().map(move |cut| {
                    let mut next = prefix.clone();
                    next.push(*cut);
                    next
                })
            })
            .collect();
    }
    all
}

/// Every crash position x flush ordering x outcome of `files` files. `extras`
/// also varies the sweep, the repair cut and a user edit of the first file.
fn every_scenario(files: usize, prior: bool, extras: bool) -> Vec<Scenario> {
    let mut out = Vec::new();
    let shape = |stage, barrier, flushed: Vec<bool>, cuts: Vec<Cut>| Scenario {
        uid: NEXT_UID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        files,
        prior,
        stage,
        barrier,
        flushed,
        cuts,
        user_edit: UserEdit::None,
        gc: false,
        second_cut: false,
    };
    let mut skeletons = Vec::new();
    for stage in [Stage::BeforeRename, Stage::BeforeCommit] {
        let probe = shape(stage, Barrier::Survives, vec![false; files], vec![Cut::New; files]);
        let classes: Vec<_> = (0..files).map(|f| probe.durable(f).allowed()).collect();
        for cuts in product(&classes) {
            skeletons.push(shape(stage, Barrier::Survives, vec![false; files], cuts));
        }
    }
    for barrier in [
        Barrier::Survives,
        Barrier::CutInFiles,
        Barrier::CutBeforeDirFlush,
        Barrier::CutBeforeClear,
    ] {
        for mask in 0..(1usize << files) {
            let flushed: Vec<bool> = (0..files).map(|f| mask >> f & 1 == 1).collect();
            let all_flushed = flushed.iter().all(|f| *f);
            let consistent = match barrier {
                Barrier::Survives => true,
                Barrier::CutInFiles => !all_flushed,
                Barrier::CutBeforeDirFlush | Barrier::CutBeforeClear => all_flushed,
            };
            if !consistent {
                continue;
            }
            let probe = shape(Stage::Committed, barrier, flushed.clone(), vec![Cut::New; files]);
            let classes: Vec<_> = (0..files).map(|f| probe.durable(f).allowed()).collect();
            for cuts in product(&classes) {
                skeletons.push(shape(Stage::Committed, barrier, flushed.clone(), cuts));
            }
        }
    }
    for skeleton in skeletons {
        out.push(skeleton.clone());
        if extras && skeleton.stage == Stage::Committed {
            for (gc, second_cut) in [(true, false), (false, true), (true, true)] {
                out.push(Scenario { gc, second_cut, ..skeleton.clone() });
            }
            for edit in [UserEdit::SameSize(0), UserEdit::Longer(0), UserEdit::AtomicReplace(0)] {
                out.push(Scenario { user_edit: edit, ..skeleton.clone() });
            }
        }
    }
    out
}

async fn explore(scenarios: Vec<Scenario>) {
    let total = scenarios.len();
    let mut broken = Vec::new();
    for scenario in scenarios {
        if let Err(violation) = run_scenario(&scenario).await {
            broken.push(format!("{violation}\n  {scenario:?}"));
            if broken.len() >= 5 {
                break;
            }
        }
    }
    assert!(
        broken.is_empty(),
        "PowerCut: {} of {total} scenarios shown broke:\n{}",
        broken.len(),
        broken.join("\n")
    );
}

/// 1 and 2 files, with and without a previous version, every position, ordering
/// and outcome, and the sweep / repair cut / user edit variants.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "exhaustive PowerCut exploration; run by `cargo dst-lane2`"]
async fn explore_exhaustive_one_and_two_files() {
    for files in [1, 2] {
        for prior in [false, true] {
            explore(every_scenario(files, prior, true)).await;
        }
    }
}

/// 3 files, every position, ordering and outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "exhaustive PowerCut exploration; run by `cargo dst-lane2`"]
async fn explore_exhaustive_three_files_without_prior() {
    explore(every_scenario(3, false, false)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "exhaustive PowerCut exploration; run by `cargo dst-lane2`"]
async fn explore_exhaustive_three_files_with_prior() {
    explore(every_scenario(3, true, false)).await;
}

/// splitmix64: the seed is the whole schedule, so a failing seed replays alone.
struct Seed(u64);

impl Seed {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The scenario seed `seed` stands for: 1-3 files, any position, any outcome.
fn scenario_of_seed(seed: u64) -> Scenario {
    let mut rng = Seed(seed);
    let files = 1 + rng.below(3);
    let stage = [Stage::BeforeRename, Stage::BeforeCommit, Stage::Committed, Stage::Committed]
        [rng.below(4)];
    let barrier = [
        Barrier::Survives,
        Barrier::CutInFiles,
        Barrier::CutBeforeDirFlush,
        Barrier::CutBeforeClear,
    ][rng.below(4)];
    let mut flushed: Vec<bool> = (0..files).map(|_| rng.below(2) == 1).collect();
    match barrier {
        Barrier::CutInFiles if flushed.iter().all(|f| *f) => flushed[0] = false,
        Barrier::CutBeforeDirFlush | Barrier::CutBeforeClear => flushed = vec![true; files],
        _ => {}
    }
    let mut scenario = Scenario {
        uid: NEXT_UID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        files,
        prior: rng.below(2) == 1,
        stage,
        barrier,
        flushed,
        cuts: vec![Cut::New; files],
        user_edit: UserEdit::None,
        gc: false,
        second_cut: false,
    };
    scenario.cuts = (0..files)
        .map(|f| {
            let allowed = scenario.durable(f).allowed();
            allowed[rng.below(allowed.len())]
        })
        .collect();
    if stage == Stage::Committed {
        scenario.gc = rng.below(3) == 0;
        scenario.second_cut = rng.below(3) == 0;
        scenario.user_edit = match rng.below(6) {
            0 => UserEdit::SameSize(rng.below(files)),
            1 => UserEdit::Longer(rng.below(files)),
            2 => UserEdit::AtomicReplace(rng.below(files)),
            _ => UserEdit::None,
        };
    }
    scenario
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Seeded exploration beyond the exhaustive bound's reach of variants:
/// `YADORILINK_POWER_CUT_SEEDS` seeds from `YADORILINK_POWER_CUT_BASE_SEED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "seeded PowerCut exploration; run by `cargo dst-lane2`"]
async fn explore_seeded() {
    let (base, count) =
        (env_u64("YADORILINK_POWER_CUT_BASE_SEED", 1), env_u64("YADORILINK_POWER_CUT_SEEDS", 500));
    for seed in base..base + count {
        let scenario = scenario_of_seed(seed);
        if let Err(violation) = run_scenario(&scenario).await {
            panic!(
                "PowerCut seed {seed} broke: {violation}\nreplay: YADORILINK_POWER_CUT_BASE_SEED={seed} \
                 YADORILINK_POWER_CUT_SEEDS=1 cargo test -p yadorilink-daemon --lib \
                 power_cut_tests::explore_seeded -- --ignored\nscenario: {scenario:?}"
            );
        }
    }
}

/// The same seed is the same scenario.
#[test]
fn a_seed_is_the_whole_scenario() {
    let (a, b) = (scenario_of_seed(42), scenario_of_seed(42));
    assert_eq!((a.files, a.stage, a.barrier, &a.cuts), (b.files, b.stage, b.barrier, &b.cuts));
    assert!((0..200).any(|s| scenario_of_seed(s).stage == Stage::Committed));
}
