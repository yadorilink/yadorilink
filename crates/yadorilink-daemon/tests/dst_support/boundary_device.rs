//! One real device for the fast boundary tests: the production capture
//! pipeline (`LocalChangeProcessor`, a real block store, a real index) driven
//! by `Case` ops, and compared with the independent `ExplicitModel`.
//!
//! The device does not model anything itself. Ops go to disk through
//! `op_applier::apply_op`, watcher events come from `fs_events::decompose`,
//! flushes go through the real `process_flush`, and the expectation comes from
//! `directory_model::ExplicitModel`, which never sees the index. A test that
//! wants a causally ill-formed op (a delete of a file an earlier op already
//! renamed) gets it skipped by the model and by the disk alike: the model is
//! the judge of what a causally justified change is.

#![cfg(turmoil)]
#![allow(dead_code)] // each boundary test uses a different subset

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_local_capture::LocalChangeProcessor;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};

use super::case_ir::{ContentTable, Fault, Op};
use super::clock::HarnessClock;
use super::directory_model::{ExplicitModel, ModelEntry};
use super::fs_events::{coalesce, decompose, FsOp, WatchEvent};
use super::op_applier::apply_op;

pub const GROUP: &str = "boundary-group";

/// Content the boundary tests write: id `n` is `content-n`, so ids are
/// distinguishable and `op_applier`'s default needs no table entries.
pub fn table() -> ContentTable {
    ContentTable::default()
}

pub fn bytes_of(content_id: u64) -> Vec<u8> {
    format!("content-{content_id}").into_bytes()
}

/// How a run hands its events to the processor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// One flush per op: the debouncer fired between every two operations.
    PerOp,
    /// One flush for the whole sequence, coalesced to the last event per path:
    /// the debouncer saw it all in one window.
    OneWindow,
}

/// One step of a short random sequence: a file operation, or a change in
/// when the debounce window is flushed. `Pause` holds events back (the
/// capture is paused); `Retry` flushes everything held, coalesced, and
/// resumes. A sequence always ends with an implicit `Retry`.
#[derive(Debug, Clone)]
pub enum Step {
    Op(Op),
    Pause,
    Retry,
    /// The device's clock jumps to this absolute time (forwards or back);
    /// later writes are stamped from there.
    Clock(i64),
}

/// A deliberate product defect, injected into the event stream so a test can
/// prove its comparison fails when the pipeline loses something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    None,
    /// Observed removals never reach the processor.
    DropRemovals,
    /// Creations and modifications never reach the processor.
    DropCreations,
}

pub struct Device {
    pub root: PathBuf,
    pub state: Arc<ReplicaCoordinator>,
    pub processor: LocalChangeProcessor,
    pub store: Arc<SegmentBlockStore>,
    clock: HarnessClock,
    _root_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
}

impl Device {
    /// An in-memory index.
    pub fn new() -> Self {
        let state = Arc::new(ReplicaCoordinator::open_in_memory().expect("index"));
        Self::with_state(state)
    }

    fn with_state(state: Arc<ReplicaCoordinator>) -> Self {
        let root_dir = tempfile::tempdir().expect("root");
        let root = root_dir.path().canonicalize().expect("canonical root");
        let store_dir = tempfile::tempdir().expect("store");
        super::link::link_and_start(&state, &root, GROUP).expect("link");
        // The first scan's last act: record which volume the root is, without
        // which an observed removal is refused as possibly an unmounted root.
        let identity = yadorilink_filesystem_sync::device_boundary::root_volume_identity(&root)
            .expect("volume identity");
        state
            .link_repository()
            .set_capture_volume_identity_for_group(GROUP, &identity)
            .expect("record the volume");
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).expect("block store"));
        let processor = Self::processor_over(&state, &store);
        Self {
            root,
            state,
            processor,
            store,
            clock: HarnessClock::from_seed(7),
            _root_dir: root_dir,
            _store_dir: store_dir,
        }
    }

    fn processor_over(
        state: &Arc<ReplicaCoordinator>,
        store: &Arc<SegmentBlockStore>,
    ) -> LocalChangeProcessor {
        LocalChangeProcessor::new(
            state.clone(),
            store.clone(),
            "boundary-device".to_string(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
    }

    /// Stops the processor and starts a fresh one over the same index and
    /// store: nothing held in memory survives, everything committed does.
    pub fn restart_processor(&mut self) {
        self.processor = Self::processor_over(&self.state, &self.store);
    }

    /// Reopens the index file too: a full process restart.
    pub fn restart_over_file(&mut self, db: &Path) {
        self.state = Arc::new(ReplicaCoordinator::open(db).expect("reopen index"));
        self.processor = Self::processor_over(&self.state, &self.store);
    }

    /// A device whose index lives in `db`.
    pub fn over_file(db: &Path) -> Self {
        Self::with_state(Arc::new(ReplicaCoordinator::open(db).expect("index file")))
    }

    /// The device's current clock reading, in nanoseconds.
    pub fn clock_now(&self) -> i64 {
        self.clock.now_nanos()
    }

    /// Applies a clock fault from a `Case` schedule to this device's clock:
    /// a jump lands the clock on its absolute time, a skew shifts it by its
    /// delta. Returns the clock before and after, so a test can show the
    /// fault moved something. Any other fault is not this device's to apply.
    pub fn apply_clock_fault(&self, fault: &Fault) -> Option<(i64, i64)> {
        let before = self.clock.now_nanos();
        let after = match fault {
            Fault::ClockJump { to_unix_nanos, .. } => *to_unix_nanos,
            Fault::ClockSkew { delta_nanos, .. } => before.wrapping_add(*delta_nanos),
            _ => return None,
        };
        self.clock.set_now(after);
        Some((before, after))
    }

    pub fn write_file(&self, path: &str, content_id: u64) {
        apply_op(
            &self.clock,
            &self.root,
            &Op::Write { path: path.to_string(), content_id },
            &table(),
        )
        .expect("write");
    }

    fn fs_op(op: &Op) -> FsOp {
        match op {
            Op::Write { path, .. } | Op::Edit { path, .. } => FsOp::Modify { path: path.clone() },
            Op::Delete { path } => FsOp::Delete { path: path.clone() },
            Op::Rename { from, to } | Op::Move { from, to } => {
                FsOp::Rename { from: from.clone(), to: to.clone() }
            }
            other => panic!("the boundary device drives file ops only, got {other:?}"),
        }
    }

    pub fn flush_events(
        &self,
        events: Vec<WatchEvent>,
    ) -> impl std::future::Future<Output = ()> + '_ {
        async move {
            self.try_flush_events(events).await.expect("process_flush");
        }
    }

    /// [`flush_events`](Self::flush_events), returning the pipeline's refusal
    /// instead of panicking: an exploration walk keeps going past a refused
    /// flush, as a daemon does.
    pub async fn try_flush_events(&self, events: Vec<WatchEvent>) -> Result<(), String> {
        let paths: Vec<(PathBuf, FsChangeKind, i64)> =
            events.into_iter().map(|e| (self.root.join(&e.path), e.kind, 1)).collect();
        if paths.is_empty() {
            return Ok(());
        }
        self.processor
            .process_flush(GROUP, &self.root, DebounceFlush::Paths(paths))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Applies `op` to the disk only, and returns the watcher events it would
    /// raise, for the caller to deliver, hold or lose.
    pub fn apply_to_disk(&self, op: &Op) -> Vec<WatchEvent> {
        apply_op(&self.clock, &self.root, op, &table()).expect("apply op");
        decompose(&Self::fs_op(op))
    }

    /// Runs `ops` against the disk and the pipeline, skipping every op the
    /// model finds ill-formed in its state (such an op changes nothing on a
    /// real filesystem either). Returns the model's final state.
    pub async fn run(
        &self,
        mut model: ExplicitModel,
        ops: &[Op],
        delivery: Delivery,
        defect: Defect,
    ) -> ExplicitModel {
        let mut window: Vec<WatchEvent> = Vec::new();
        for op in ops {
            if model.apply(op).is_err() {
                continue;
            }
            apply_op(&self.clock, &self.root, op, &table()).expect("apply op");
            let mut events = decompose(&Self::fs_op(op));
            events.retain(|e| {
                !matches!(
                    (defect, e.kind),
                    (Defect::DropRemovals, FsChangeKind::ObservedRemoval)
                        | (Defect::DropCreations, FsChangeKind::CreatedOrModified)
                )
            });
            match delivery {
                Delivery::PerOp => self.flush_events(events).await,
                Delivery::OneWindow => window.extend(events),
            }
        }
        if delivery == Delivery::OneWindow {
            self.flush_events(coalesce(window)).await;
        }
        model
    }

    /// Runs a sequence of steps; the same op filtering as [`run`](Self::run).
    pub async fn run_steps(
        &self,
        mut model: ExplicitModel,
        steps: &[Step],
        defect: Defect,
    ) -> ExplicitModel {
        let (mut paused, mut window): (bool, Vec<WatchEvent>) = (false, Vec::new());
        for step in steps {
            match step {
                Step::Pause => paused = true,
                Step::Retry => {
                    self.flush_events(coalesce(std::mem::take(&mut window))).await;
                    paused = false;
                }
                Step::Clock(nanos) => {
                    self.clock.set_now(*nanos);
                }
                Step::Op(op) => {
                    if model.apply(op).is_err() {
                        continue;
                    }
                    apply_op(&self.clock, &self.root, op, &table()).expect("apply op");
                    let mut events = decompose(&Self::fs_op(op));
                    events.retain(|e| {
                        !matches!(
                            (defect, e.kind),
                            (Defect::DropRemovals, FsChangeKind::ObservedRemoval)
                                | (Defect::DropCreations, FsChangeKind::CreatedOrModified)
                        )
                    });
                    if paused {
                        window.extend(events);
                    } else {
                        self.flush_events(events).await;
                    }
                }
            }
        }
        self.flush_events(coalesce(window)).await;
        model
    }

    /// The live files the index holds: path to the hex block hash.
    pub fn live_index(&self) -> BTreeMap<String, String> {
        self.state
            .file_index_repository()
            .list_files(GROUP)
            .expect("list")
            .into_iter()
            .filter(|r| !r.deleted)
            .map(|r| {
                let hash =
                    r.blocks.iter().map(|b| hex::encode(&b.hash)).collect::<Vec<_>>().join("+");
                (r.path, hash)
            })
            .collect()
    }
}

/// What the model says the index must hold: each file's path to the hash the
/// block store gives its content.
pub fn expected_index(model: &ExplicitModel) -> BTreeMap<String, String> {
    let scratch = tempfile::tempdir().expect("scratch");
    let store = SegmentBlockStore::new(scratch.path()).expect("scratch store");
    model
        .entries()
        .iter()
        .filter_map(|(path, entry)| match entry {
            ModelEntry::File { content_id } => {
                Some((path.clone(), store.put(&bytes_of(*content_id)).expect("hash")))
            }
            ModelEntry::Directory => None,
        })
        .collect()
}

/// Compares the index to the model. `Err` names every path that disappeared
/// without a causing op, every path that survived its delete, and every
/// path holding other content than the model says.
pub fn compare(device: &Device, model: &ExplicitModel) -> Result<(), String> {
    let (want, have) = (expected_index(model), device.live_index());
    let mut problems = Vec::new();
    for (path, hash) in &want {
        match have.get(path) {
            None => problems.push(format!("`{path}` disappeared (no causing op)")),
            Some(h) if h != hash => problems.push(format!("`{path}` holds other content")),
            Some(_) => {}
        }
    }
    for path in have.keys().filter(|p| !want.contains_key(*p)) {
        problems.push(format!("`{path}` is live in the index but the model removed it"));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}
