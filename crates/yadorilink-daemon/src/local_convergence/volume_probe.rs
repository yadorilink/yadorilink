//! The volume-folding probes of the receive path, shared by the files that ask
//! for them at the same time.
//!
//! What the volume under a sync root folds (case, Unicode normalization) is
//! learned by a real probe: a scratch directory and a file created, looked up
//! under another spelling and removed again (see
//! `yadorilink_peer_session::hazard::is_case_insensitive_filesystem`). The
//! answer is kept only under the scope it was taken in (see
//! `yadorilink_fs_platform::folding_scope`): the mounted filesystem instance,
//! the directory itself and its per-directory folding flag. A path alone is not
//! that scope, so a different volume mounted at the same path, a replaced root
//! or a flipped flag reads as another scope and is probed afresh; so is any
//! root whose scope cannot be named and any probe that could not run.
//!
//! A pass settles its files concurrently and every one of them asks several
//! times (the displacement guard twice, the sibling flush, the hazard check),
//! each ask a handful of metadata operations that, run inline, held the one
//! task that polls the whole run: about ten probes per file, serialised, were
//! the largest single share of a bulk receive's wall time.
//!
//! Within one scope the answer is therefore asked of the filesystem once, not
//! once per ask.
//!
//! Where there is no known scope, the requesters share a probe without sharing an answer that is older than
//! their question. A request joins a probe only while that probe has not
//! started; a request that finds the probe already running starts the next
//! one. So every answer comes from a probe that began after its requester
//! asked, exactly as a probe run by the requester itself would have, and no
//! answer outlives the probe that produced it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use yadorilink_fs_platform::folding_scope::FoldingScope;

use super::types::VolumeFolding;

/// Test seam: runs once, on the probing thread, at the next probe of `root`,
/// so a test can act inside the window the probe's await opens.
#[cfg(test)]
type ProbeHook = (PathBuf, Box<dyn FnOnce() + Send>);

#[cfg(test)]
pub(crate) static PROBE_HOOKS: std::sync::Mutex<Vec<ProbeHook>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn run_probe_hook(root: &Path) {
    let hook = {
        let mut hooks = PROBE_HOOKS.lock().unwrap_or_else(|p| p.into_inner());
        hooks.iter().position(|(r, _)| r == root).map(|i| hooks.remove(i).1)
    };
    if let Some(hook) = hook {
        hook();
    }
}

/// What the two probes of one request found. `None` is a probe that could not
/// run, which each caller reads with the default its own check needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbedFolding {
    pub(crate) case_insensitive: Option<bool>,
    pub(crate) normalization_insensitive: Option<bool>,
}

impl ProbedFolding {
    /// Runs both probes now, on the calling thread.
    pub(crate) fn probe_now(root: &Path) -> Self {
        #[cfg(test)]
        run_probe_hook(root);
        let (case_insensitive, normalization_insensitive) =
            yadorilink_peer_session::hazard::probed_folding(root);
        Self { case_insensitive, normalization_insensitive }
    }

    /// The folding when both probes ran; `None` when either could not, for a
    /// check that may act only on a known answer.
    pub(crate) fn known(self) -> Option<VolumeFolding> {
        Some(VolumeFolding {
            case_insensitive: self.case_insensitive?,
            normalization_insensitive: self.normalization_insensitive?,
        })
    }

    /// The folding with the fail-closed default for a probe that could not
    /// run: a volume that may fold is treated as one that does.
    pub(crate) fn or_conservative(self) -> VolumeFolding {
        VolumeFolding {
            case_insensitive: self.case_insensitive.unwrap_or(true),
            normalization_insensitive: self.normalization_insensitive.unwrap_or(true),
        }
    }
}

/// One probe of one root: joinable until it starts.
struct Flight {
    answer: watch::Sender<Option<ProbedFolding>>,
}

type Flights = Arc<Mutex<HashMap<PathBuf, Arc<Flight>>>>;

/// The most scopes remembered; a daemon has a handful of roots.
const MAX_SCOPES: usize = 64;

type Known = Arc<Mutex<HashMap<FoldingScope, ProbedFolding>>>;

/// The probes this executor has waiting to start, per root.
pub(crate) struct VolumeProbes {
    waiting: Flights,
    known: Known,
    probe: fn(&Path) -> ProbedFolding,
    scope: fn(&Path) -> Option<FoldingScope>,
}

impl Default for VolumeProbes {
    fn default() -> Self {
        Self::with_probe(ProbedFolding::probe_now)
    }
}

impl VolumeProbes {
    /// Probes with `probe` instead of the real thing, so a test can count them.
    pub(crate) fn with_probe(probe: fn(&Path) -> ProbedFolding) -> Self {
        Self::with_probe_and_scope(probe, FoldingScope::of)
    }

    /// As [`Self::with_probe`], naming scopes with `scope` as well.
    pub(crate) fn with_probe_and_scope(
        probe: fn(&Path) -> ProbedFolding,
        scope: fn(&Path) -> Option<FoldingScope>,
    ) -> Self {
        Self { waiting: Flights::default(), known: Known::default(), probe, scope }
    }

    /// The folding of the volume under `root`, from a probe that starts after
    /// this call.
    pub(crate) async fn folding(&self, root: &Path) -> ProbedFolding {
        let scope = (self.scope)(root);
        if let Some(found) = scope.as_ref().and_then(|scope| self.recall(scope)) {
            return found;
        }
        let found = self.folding_by_probe(root).await;
        if let Some(scope) = scope {
            // Kept only for the scope the probe began in, and only as a full
            // answer: a probe that could not run is asked again.
            if found.known().is_some() && (self.scope)(root).as_ref() == Some(&scope) {
                let mut known = self.known.lock().unwrap_or_else(|p| p.into_inner());
                if known.len() >= MAX_SCOPES {
                    known.clear();
                }
                known.insert(scope, found);
            }
        }
        found
    }

    /// Forgets every kept answer, so the next ask probes (and awaits) again.
    #[cfg(test)]
    #[allow(dead_code, reason = "only the tests of platforms that name a scope call it")]
    pub(crate) fn forget(&self) {
        self.known.lock().unwrap_or_else(|p| p.into_inner()).clear();
    }

    fn recall(&self, scope: &FoldingScope) -> Option<ProbedFolding> {
        self.known.lock().unwrap_or_else(|p| p.into_inner()).get(scope).copied()
    }

    async fn folding_by_probe(&self, root: &Path) -> ProbedFolding {
        let (flight, launch) = {
            let mut waiting = self.waiting.lock().unwrap_or_else(|p| p.into_inner());
            match waiting.get(root) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let flight = Arc::new(Flight { answer: watch::channel(None).0 });
                    waiting.insert(root.to_path_buf(), flight.clone());
                    (flight, true)
                }
            }
        };
        let mut answer = flight.answer.subscribe();
        if launch {
            let waiting = self.waiting.clone();
            let root = root.to_path_buf();
            let flight = flight.clone();
            let probe = self.probe;
            // The probe is detached from this caller: a caller that goes away
            // leaves the others their answer.
            drop(tokio::task::spawn_blocking(move || {
                {
                    // From here on a request is not this probe's: it starts the next.
                    let mut waiting = waiting.lock().unwrap_or_else(|p| p.into_inner());
                    if waiting.get(&root).is_some_and(|current| Arc::ptr_eq(current, &flight)) {
                        waiting.remove(&root);
                    }
                }
                let found = probe(&root);
                flight.answer.send_replace(Some(found));
            }));
        }
        loop {
            if let Some(found) = *answer.borrow_and_update() {
                return found;
            }
            if answer.changed().await.is_err() {
                // The probe never ran (the runtime is going away): ask for
                // oneself, which is what every caller did before sharing.
                return (self.probe)(root);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static BURST_PROBES: AtomicUsize = AtomicUsize::new(0);
    static BURST_GATE: (std::sync::Mutex<bool>, std::sync::Condvar) =
        (std::sync::Mutex::new(false), std::sync::Condvar::new());
    static SEQUENTIAL_PROBES: AtomicUsize = AtomicUsize::new(0);

    /// Counts itself, then holds until the test opens the gate.
    fn gated_burst(_: &Path) -> ProbedFolding {
        BURST_PROBES.fetch_add(1, Ordering::SeqCst);
        let mut open = BURST_GATE.0.lock().unwrap();
        while !*open {
            open = BURST_GATE.1.wait(open).unwrap();
        }
        ProbedFolding { case_insensitive: Some(true), normalization_insensitive: Some(false) }
    }

    fn counted_sequential(_: &Path) -> ProbedFolding {
        SEQUENTIAL_PROBES.fetch_add(1, Ordering::SeqCst);
        ProbedFolding { case_insensitive: Some(false), normalization_insensitive: Some(false) }
    }

    /// With one blocking thread the first probe holds it, so the second probe
    /// cannot start while the requests of the second wave arrive: they all
    /// join it, and each of the two probes began after the requests it answers.
    #[test]
    fn concurrent_requests_share_a_probe_that_has_not_started() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let probes = Arc::new(VolumeProbes::with_probe(gated_burst));
            let root = PathBuf::from("/burst-root");
            let ask = |probes: &Arc<VolumeProbes>, root: &PathBuf| {
                let (probes, root) = (probes.clone(), root.clone());
                tokio::spawn(async move { probes.folding(&root).await })
            };
            let mut tasks = vec![ask(&probes, &root)];
            while BURST_PROBES.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            // The first probe is running and cannot answer anyone who asks now.
            for _ in 0..64 {
                tasks.push(ask(&probes, &root));
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            *BURST_GATE.0.lock().unwrap() = true;
            BURST_GATE.1.notify_all();
            for task in tasks {
                let found = task.await.unwrap();
                assert_eq!(found.case_insensitive, Some(true));
                assert_eq!(found.normalization_insensitive, Some(false));
            }
        });
        assert_eq!(
            BURST_PROBES.load(Ordering::SeqCst),
            2,
            "one probe for the first request, one shared by the 64 that came after it started"
        );
    }

    #[tokio::test]
    async fn a_request_after_an_answer_is_never_served_that_answer() {
        let probes = VolumeProbes::with_probe(counted_sequential);
        let root = PathBuf::from("/sequential-root");
        for expected in 1..=3 {
            probes.folding(&root).await;
            assert_eq!(SEQUENTIAL_PROBES.load(Ordering::SeqCst), expected);
        }
    }

    #[tokio::test]
    async fn an_unreachable_root_has_no_known_folding_and_a_conservative_default() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain-file");
        std::fs::write(&file, b"x").unwrap();
        let found = VolumeProbes::default().folding(&file).await;
        assert_eq!(found.known(), None);
        assert!(found.or_conservative().case_insensitive);
        assert!(found.or_conservative().normalization_insensitive);
    }

    #[tokio::test]
    async fn the_real_probe_reports_the_volume_of_a_reachable_root() {
        let dir = tempfile::tempdir().unwrap();
        let found = VolumeProbes::default().folding(dir.path()).await;
        assert!(found.known().is_some());
        assert_eq!(found, ProbedFolding::probe_now(dir.path()));
    }

    static SCOPED_PROBES: AtomicUsize = AtomicUsize::new(0);
    static SCOPE_NAME: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);
    static FAILING_PROBES: AtomicUsize = AtomicUsize::new(0);

    fn counted_scoped(_: &Path) -> ProbedFolding {
        SCOPED_PROBES.fetch_add(1, Ordering::SeqCst);
        ProbedFolding { case_insensitive: Some(false), normalization_insensitive: Some(true) }
    }

    fn counted_failing(_: &Path) -> ProbedFolding {
        FAILING_PROBES.fetch_add(1, Ordering::SeqCst);
        ProbedFolding { case_insensitive: Some(true), normalization_insensitive: None }
    }

    fn current_scope(_: &Path) -> Option<FoldingScope> {
        SCOPE_NAME.lock().unwrap().map(FoldingScope::from_parts)
    }

    /// One test body: the scope is process-global, so the cases run in order.
    #[tokio::test]
    async fn an_answer_is_kept_for_its_scope_only() {
        let root = PathBuf::from("/scoped-root");
        let probes = VolumeProbes::with_probe_and_scope(counted_scoped, current_scope);

        // A scope that cannot be named is never served from memory.
        *SCOPE_NAME.lock().unwrap() = None;
        probes.folding(&root).await;
        probes.folding(&root).await;
        assert_eq!(SCOPED_PROBES.load(Ordering::SeqCst), 2);

        // The same scope: probed once.
        *SCOPE_NAME.lock().unwrap() = Some("mount-1");
        for _ in 0..5 {
            assert_eq!(probes.folding(&root).await.normalization_insensitive, Some(true));
        }
        assert_eq!(SCOPED_PROBES.load(Ordering::SeqCst), 3);

        // Another mount, directory or folding flag at the same path: probed again.
        *SCOPE_NAME.lock().unwrap() = Some("mount-2");
        probes.folding(&root).await;
        probes.folding(&root).await;
        assert_eq!(SCOPED_PROBES.load(Ordering::SeqCst), 4);

        // Back to the first scope: its answer is still its own.
        *SCOPE_NAME.lock().unwrap() = Some("mount-1");
        probes.folding(&root).await;
        assert_eq!(SCOPED_PROBES.load(Ordering::SeqCst), 4);

        // A probe that could not run fully is not kept, and stays fail-closed.
        *SCOPE_NAME.lock().unwrap() = Some("mount-3");
        let failing = VolumeProbes::with_probe_and_scope(counted_failing, current_scope);
        for expected in 1..=3 {
            let found = failing.folding(&root).await;
            assert_eq!(found.known(), None);
            assert!(found.or_conservative().normalization_insensitive);
            assert_eq!(FAILING_PROBES.load(Ordering::SeqCst), expected);
        }
    }

    static FLIP_PROBES: AtomicUsize = AtomicUsize::new(0);
    static FLIP_SCOPE: AtomicUsize = AtomicUsize::new(0);

    fn probe_that_changes_the_scope(_: &Path) -> ProbedFolding {
        FLIP_PROBES.fetch_add(1, Ordering::SeqCst);
        FLIP_SCOPE.fetch_xor(1, Ordering::SeqCst);
        ProbedFolding { case_insensitive: Some(false), normalization_insensitive: Some(false) }
    }

    fn flipping_scope(_: &Path) -> Option<FoldingScope> {
        Some(FoldingScope::from_parts(&FLIP_SCOPE.load(Ordering::SeqCst).to_string()))
    }

    #[tokio::test]
    async fn an_answer_from_a_probe_during_which_the_scope_changed_is_not_kept() {
        let probes =
            VolumeProbes::with_probe_and_scope(probe_that_changes_the_scope, flipping_scope);
        let root = PathBuf::from("/flipping-root");
        // The scope alternates, so a stale insertion under the scope the probe
        // began in would be served on the third ask.
        for _ in 0..3 {
            probes.folding(&root).await;
        }
        assert_eq!(FLIP_PROBES.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_real_root_is_probed_once_where_the_platform_names_its_scope() {
        let dir = tempfile::tempdir().unwrap();
        if FoldingScope::of(dir.path()).is_none() {
            return;
        }
        let probes = VolumeProbes::with_probe(counted_real_root);
        for _ in 0..4 {
            probes.folding(dir.path()).await;
        }
        assert_eq!(REAL_ROOT_PROBES.load(Ordering::SeqCst), 1);
    }

    static REAL_ROOT_PROBES: AtomicUsize = AtomicUsize::new(0);

    fn counted_real_root(_: &Path) -> ProbedFolding {
        REAL_ROOT_PROBES.fetch_add(1, Ordering::SeqCst);
        ProbedFolding { case_insensitive: Some(false), normalization_insensitive: Some(false) }
    }
}
