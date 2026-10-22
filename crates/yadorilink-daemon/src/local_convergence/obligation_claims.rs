//! The claims an obligation-driven attempt holds, carried down to the lane
//! that closes a path's obligation in the same transaction as its proof.
//!
//! The obligation engine claims a window of paths and hands them to one
//! reconciliation attempt. A received file's content write then commits its
//! proof, its `Present` stamp, its intent clear and the obligation's
//! completion as one transaction, which needs the claim the engine read: the
//! obligation's invalidation generation and row incarnation. Every other
//! settlement is still closed by the engine after the attempt, so the engine
//! also needs to learn which paths a lane already decided.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use yadorilink_sync_sqlite::projection_obligations::ObligationClaimToken;

/// A test-only rendezvous at the instant a claimed path's obligation is
/// about to be decided, so a deterministic-interleaving test can land an
/// independent mutation there and then release the worker.
///
/// Two places pause on it:
///
/// - the eager content write, after its bytes are durable (temp file
///   synced, renamed, parent directory synced), its metadata applied and
///   verified, and immediately before the one transaction that publishes its
///   proof and closes its obligation. A mutation landed there is exactly a
///   race between the disk publish and that commit, and aborting the worker
///   there is exactly a crash in that window;
/// - the engine's zero-work close, immediately before its completion.
///
/// Never constructed in production: every caller passes `None`. Not itself
/// `cfg`-gated, because the call sites that consult one are ordinary
/// production code.
///
/// A bare `Notify` is not enough: "parked" and "proceed" are two directions,
/// and one `Notify` cannot carry both without racing the worker's wait
/// against the test's notify.
pub struct BeforeCompletionHook {
    parked: tokio::sync::Notify,
    proceed: tokio::sync::Notify,
    /// How many workers have parked here so far. A test that drives several
    /// files at once waits on this count rather than guessing a delay.
    parked_count: std::sync::atomic::AtomicUsize,
}

impl BeforeCompletionHook {
    /// Called from inside the worker: announces that it has parked, then
    /// waits for the test to call [`Self::resume`].
    pub(crate) async fn pause(&self) {
        self.parked_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.parked.notify_one();
        self.proceed.notified().await;
    }
}

// The driving half. Only a test constructs or steps a hook, gated to match
// the engine wrapper's re-export of the type for tests outside this crate.
#[cfg(any(test, feature = "test-support"))]
impl BeforeCompletionHook {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            parked: tokio::sync::Notify::new(),
            proceed: tokio::sync::Notify::new(),
            parked_count: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    /// How many workers have parked on this hook so far.
    pub fn parked_count(&self) -> usize {
        self.parked_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Resolves once at least `n` workers have parked on this hook. Panics
    /// after `timeout`, naming how many had parked.
    pub async fn wait_parked_count(&self, n: usize, timeout: std::time::Duration) {
        let started = std::time::Instant::now();
        while self.parked_count() < n {
            assert!(
                started.elapsed() < timeout,
                "only {} of {n} workers parked within {timeout:?}",
                self.parked_count()
            );
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    /// Resolves once a worker has parked on this hook.
    pub async fn wait_parked(&self) {
        self.parked.notified().await;
    }

    /// Releases the parked worker, after the test's own interleaved
    /// mutation has committed.
    pub fn resume(&self) {
        self.proceed.notify_one();
    }
}

/// Every path one attempt was handed under a claim, with the token each
/// claim read, and the record of which of them a lane already decided.
pub struct ObligationClaims {
    tokens: BTreeMap<String, ObligationClaimToken>,
    decided_in_lane: Mutex<BTreeSet<String>>,
    hook: Option<Arc<BeforeCompletionHook>>,
}

impl ObligationClaims {
    pub(crate) fn new(
        tokens: BTreeMap<String, ObligationClaimToken>,
        hook: Option<Arc<BeforeCompletionHook>>,
    ) -> Self {
        Self { tokens, decided_in_lane: Mutex::new(BTreeSet::new()), hook }
    }

    /// The claim on `path`, when this attempt holds one.
    pub(crate) fn for_path(&self, path: &str) -> Option<PathClaim<'_>> {
        self.tokens.get(path).map(|&token| PathClaim { token, claims: self })
    }

    /// Whether a lane already ran this path's completion in its own commit.
    /// Such a path must not be completed again: its decision was made under
    /// the claim, and repeating it could only repeat the same answer.
    pub(crate) fn decided_in_lane(&self, path: &str) -> bool {
        self.decided_in_lane.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).contains(path)
    }
}

/// One claimed path, as the lane that may close it sees it.
#[derive(Clone, Copy)]
pub(crate) struct PathClaim<'a> {
    token: ObligationClaimToken,
    claims: &'a ObligationClaims,
}

impl PathClaim<'_> {
    pub(crate) fn token(&self) -> ObligationClaimToken {
        self.token
    }

    /// Pauses at the test hook, when there is one.
    pub(crate) async fn before_completion(&self) {
        if let Some(hook) = &self.claims.hook {
            hook.pause().await;
        }
    }

    /// Records that the commit for `path` ran its completion, whether or
    /// not it closed the obligation.
    pub(crate) fn record_decided(&self, path: &str) {
        self.claims
            .decided_in_lane
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(path.to_owned());
    }
}
