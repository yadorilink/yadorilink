//! The volume-folding probes of the receive path, shared by the files that ask
//! for them at the same time.
//!
//! What the volume under a sync root folds (case, Unicode normalization) is
//! learned by a real probe: a scratch directory and a file created, looked up
//! under another spelling and removed again (see
//! `yadorilink_peer_session::hazard::is_case_insensitive_filesystem`). The
//! answer is deliberately never cached: a path is not a mount instance, and a
//! different volume can be mounted at the same path.
//!
//! A pass settles its files concurrently and every one of them asks several
//! times (the displacement guard twice, the sibling flush, the hazard check),
//! each ask a handful of metadata operations that, run inline, held the one
//! task that polls the whole run: about ten probes per file, serialised, were
//! the largest single share of a bulk receive's wall time.
//!
//! The requesters share a probe without sharing an answer that is older than
//! their question. A request joins a probe only while that probe has not
//! started; a request that finds the probe already running starts the next
//! one. So every answer comes from a probe that began after its requester
//! asked, exactly as a probe run by the requester itself would have, and no
//! answer outlives the probe that produced it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

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
        Self {
            case_insensitive: yadorilink_peer_session::hazard::probed_case_insensitivity(root),
            normalization_insensitive:
                yadorilink_peer_session::hazard::probed_normalization_insensitivity(root),
        }
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

/// The probes this executor has waiting to start, per root.
pub(crate) struct VolumeProbes {
    waiting: Flights,
    probe: fn(&Path) -> ProbedFolding,
}

impl Default for VolumeProbes {
    fn default() -> Self {
        Self::with_probe(ProbedFolding::probe_now)
    }
}

impl VolumeProbes {
    /// Probes with `probe` instead of the real thing, so a test can count them.
    pub(crate) fn with_probe(probe: fn(&Path) -> ProbedFolding) -> Self {
        Self { waiting: Flights::default(), probe }
    }

    /// The folding of the volume under `root`, from a probe that starts after
    /// this call.
    pub(crate) async fn folding(&self, root: &Path) -> ProbedFolding {
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
}
