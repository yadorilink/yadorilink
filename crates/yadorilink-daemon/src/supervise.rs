//! daemon-reliability: every `tokio::spawn` in the
//! daemon and transport used to discard its `JoinHandle` — a panic or
//! early exit in a critical task (peer orchestrator,
//! mesh-forward/presence/TTL loops) went undetected, unlogged, and
//! unrestarted, leaving the process "up" as a zombie with broken sync.
//! This module gives every long-lived task two things: (1) a name for
//! logging, and (2) an explicit policy for what happens when it exits —
//! restart with backoff, or propagate the exit to whoever's supervising
//! essential tasks together (`main.rs`'s `JoinSet`).

use std::future::Future;
use std::time::Duration;

use tokio::task::JoinHandle;

/// The essential-task supervisor container: a zero-cost newtype over
/// `tokio::task::JoinSet<&'static str>`, of which this daemon relies on
/// two behaviors: `join_next()` (yield whichever task finishes/panics
/// first) and `shutdown()` (abort every still-running task, then await
/// them all).
pub struct EssentialTasks(tokio::task::JoinSet<&'static str>);

impl EssentialTasks {
    pub fn new() -> Self {
        Self(tokio::task::JoinSet::new())
    }

    /// Spawn an essential task directly into the set, so that
    /// [`Self::shutdown`] can later abort the running task itself.
    pub fn spawn<F>(&mut self, task: F)
    where
        F: Future<Output = &'static str> + Send + 'static,
    {
        self.0.spawn(task);
    }

    /// Wait for the next essential task to finish (or be aborted). Returns
    /// `None` only when the set is empty, matching `JoinSet::join_next`.
    pub async fn join_next(&mut self) -> Option<Result<&'static str, tokio::task::JoinError>> {
        self.0.join_next().await
    }

    /// Abort every still-running task and await their completion.
    pub async fn shutdown(&mut self) {
        self.0.shutdown().await;
    }
}

impl Default for EssentialTasks {
    fn default() -> Self {
        Self::new()
    }
}

/// Backoff schedule for [`spawn_restarting`]: starts at `initial`,
/// doubles each consecutive failure, capped at `max`, with up to ±25%
/// jitter (avoids every restarting task on a multi-tenant host
/// synchronizing their retries after a shared outage, e.g. the
/// coordination server coming back up).
#[derive(Debug, Clone, Copy)]
pub struct BackoffConfig {
    pub initial: Duration,
    pub max: Duration,
}

impl BackoffConfig {
    /// daemon-reliability's own suggested range for reconnect loops
    /// (coordination netmap stream): capped 30-60s.
    pub const RECONNECT: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(45) };

    /// Convergence Engine scheduler loop restart backoff — matches the
    /// job-level backoff schedule's own cap
    /// (`yadorilink_daemon::convergence::backoff::next_backoff`) so a
    /// panicking/erroring scheduler recovers on roughly the same timescale
    /// as an ordinary job retry.
    pub const CONVERGENCE_ENGINE: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(30) };

    /// Materialization repair job restart backoff — the same shape as
    /// `CONVERGENCE_ENGINE`'s (a panicking scheduler-class task should
    /// recover on roughly the same timescale as an ordinary job retry),
    /// kept as its own named constant rather than reused so each
    /// restarting task's backoff can be tuned independently later.
    pub const MATERIALIZATION_REPAIR: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(1), max: Duration::from_secs(30) };

    /// A Degraded (disk-pressure) link's periodic free-space re-check
    /// schedule — starts at 5s (disk pressure can resolve quickly, e.g. a
    /// user manually deleting a large file) and caps at 5 minutes (a
    /// persistently full disk shouldn't be re-checked so often it's
    /// effectively a hot loop, but still recovers within a bounded,
    /// documented window once space frees up).
    pub const DEGRADED_LINK_RECHECK: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(5), max: Duration::from_secs(300) };

    /// Steady-state periodic update-check interval. `initial == max`
    /// reuses `next`'s existing ±25% jitter around a fixed point rather
    /// than modeling true escalating backoff — there's no "failure"
    /// being backed off here, just spreading many installs' checks so
    /// they don't all hit the manifest endpoint at the same wall-clock
    /// moment.
    pub const UPDATE_CHECK_INTERVAL: BackoffConfig = BackoffConfig {
        initial: Duration::from_secs(6 * 3600),
        max: Duration::from_secs(6 * 3600),
    };

    /// Backoff after a *failed* update check (manifest fetch/parse/
    /// signature error) — retried sooner than the steady-state interval
    /// above, doubling up to a cap, so a transient network blip recovers
    /// quickly but a persistently broken endpoint doesn't hot-loop
    /// against it.
    pub const UPDATE_CHECK_RETRY: BackoffConfig =
        BackoffConfig { initial: Duration::from_secs(60), max: Duration::from_secs(3600) };

    /// Made `pub` (was private, used only by `spawn_restarting` below) so
    /// `daemon_state`'s Degraded-link re-check scheduling can reuse this
    /// exact doubling+jitter+cap schedule instead of a second, independent
    /// backoff implementation.
    pub fn next(&self, attempt: u32) -> Duration {
        let scale = 1u64 << attempt.min(20); // avoid overflow on a long-lived task
        let backed_off = self.initial.saturating_mul(scale as u32).min(self.max);
        // `Duration::mul_f64` panics on a negative factor, so compute the
        // +/-25% jitter magnitude unsigned and apply it as an explicit
        // add/subtract rather than multiplying by a signed fraction.
        let jitter_frac = fastrand_unit_interval(); // [0, 1)
        let jitter_magnitude = backed_off.mul_f64(0.25 * jitter_frac);
        let jittered = if jitter_frac < 0.5 {
            backed_off.saturating_sub(jitter_magnitude)
        } else {
            backed_off.saturating_add(jitter_magnitude)
        };
        // `max` is a true ceiling — jitter must never push the delay
        // above it, only vary it below/around the un-jittered value.
        jittered.min(self.max)
    }
}

/// A small, dependency-free `[0, 1)` PRNG (splitmix64 seeded from the
/// current time) — jitter doesn't need to be cryptographically random,
/// just different across processes/restarts, and this avoids pulling in
/// `rand` as a non-dev dependency for a single call site.
fn fastrand_unit_interval() -> f64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    let prev = STATE.fetch_add(seed | 1, Ordering::Relaxed);
    let mut z = prev.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

/// Spawns a restartable loop: `make_task` is called to produce a fresh
/// future each attempt. If that future ever resolves (loops that are
/// meant to run forever, like a reconnect-and-stream loop, only return
/// on a real error) or panics, this logs it at `warn` with `name` and
/// the attempt count, waits out `backoff`, and calls `make_task` again —
/// forever. Use for tasks that should never permanently give up (e.g.
/// reconnect loops): there is no "stop trying" state,
/// since the daemon is meant to recover from an arbitrarily long outage
/// on its own.
///
/// Returns the supervising task's own `JoinHandle` — awaiting it never
/// completes under normal operation (the loop is intentionally
/// infinite); it exists so callers can still hold/abort the handle like
/// any other spawned task (e.g. for shutdown).
pub fn spawn_restarting<F, Fut>(
    name: &'static str,
    backoff: BackoffConfig,
    make_task: F,
) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let handle = tokio::spawn(async move {
        let mut attempt: u32 = 0;
        loop {
            let mut running = tokio::spawn(make_task());
            // Aborting the supervisor must stop the task it supervises too;
            // a detached inner task would keep running with nothing left to
            // restart or stop it.
            let _stop_with_supervisor = AbortOnDrop(running.abort_handle());
            let result = (&mut running).await;
            match result {
                Ok(()) => {
                    tracing::warn!(task = name, attempt, "supervised task exited; restarting");
                }
                Err(join_err) if join_err.is_panic() => {
                    tracing::error!(task = name, attempt, "supervised task panicked; restarting");
                }
                Err(join_err) => {
                    // Cancelled (aborted) — the caller is shutting this
                    // down on purpose; stop restarting rather
                    // than fighting an intentional abort.
                    tracing::info!(task = name, error = %join_err, "supervised task was cancelled; not restarting");
                    return;
                }
            }
            let delay = backoff.next(attempt);
            tracing::info!(task = name, ?delay, "waiting before restart");
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    });
    register_spawned(&handle);
    handle
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static SPAWN_SINK: std::cell::RefCell<Option<Vec<tokio::task::AbortHandle>>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `f` and returns what it returned with an abort handle for every
/// supervised task it spawned on this thread. A harness that replaces a
/// `DaemonState` over the same database uses it to stop the old state's
/// background tasks, which otherwise run on for as long as they hold it.
#[cfg(any(test, feature = "test-support"))]
pub fn collect_spawned_tasks<R>(f: impl FnOnce() -> R) -> (R, Vec<tokio::task::AbortHandle>) {
    SPAWN_SINK.with(|sink| *sink.borrow_mut() = Some(Vec::new()));
    let result = f();
    let handles = SPAWN_SINK.with(|sink| sink.borrow_mut().take()).unwrap_or_default();
    (result, handles)
}

fn register_spawned(handle: &JoinHandle<()>) {
    #[cfg(any(test, feature = "test-support"))]
    SPAWN_SINK.with(|sink| {
        if let Some(handles) = sink.borrow_mut().as_mut() {
            handles.push(handle.abort_handle());
        }
    });
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = handle;
}

/// Aborts the task behind `0` when dropped.
pub(crate) struct AbortOnDrop(pub(crate) tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spawns a one-shot essential task: logs at `error` if it exits with an
/// `Err` or panics, but does not restart it. Pair with `main.rs`'s
/// essential-task `JoinSet`/`select!`: when *any* essential
/// task's handle resolves, the daemon should treat that as fatal (log
/// and exit non-zero) rather than silently continuing as a zombie with
/// broken sync — restarting individual essential tasks in place papers
/// over exactly the failure mode this pattern exists to surface to a process
/// supervisor instead.
pub fn spawn_logged<Fut>(name: &'static str, task: Fut) -> JoinHandle<()>
where
    Fut: Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
{
    let handle = tokio::spawn(async move {
        match task.await {
            Ok(()) => tracing::warn!(task = name, "essential task exited"),
            Err(e) => tracing::error!(task = name, error = %e, "essential task failed"),
        }
    });
    register_spawned(&handle);
    handle
}

/// Spawns a task that is MEANT to finish: a one-shot job fired by some
/// event (a reconnect, a policy update) that does its work and returns.
/// Unlike [`spawn_logged`], whose tasks are long-running loops for which
/// any exit is unexpected, a clean `Ok(())` here is the normal outcome and
/// is logged at `debug`; only an `Err` is worth a `warn`. A panic still
/// surfaces through the returned handle and tokio's own panic report.
pub fn spawn_one_shot<Fut>(name: &'static str, task: Fut) -> JoinHandle<()>
where
    Fut: Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>> + Send + 'static,
{
    tokio::spawn(async move {
        match task.await {
            Ok(()) => tracing::debug!(task = name, "one-shot task finished"),
            Err(e) => tracing::warn!(task = name, error = %e, "one-shot task failed"),
        }
    })
}

#[cfg(test)]
mod tests;
