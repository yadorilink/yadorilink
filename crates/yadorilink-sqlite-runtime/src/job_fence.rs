//! A fence for a database job that runs on another thread.
//!
//! A task that hands a commit to the blocking pool keeps awaiting it while
//! it still holds everything the commit is about: path locks, root
//! operations, claims. If that task is cancelled mid-job, those guards would
//! be released while the job may still commit on their behalf. A
//! [`JobFence`] closes that: the job holds a [`JobCompletion`] that marks the
//! fence done when it is dropped (the job finished, panicked, or was dropped
//! before it ran), and every party whose guards must outlive the job holds a
//! [`FenceWait`], whose `Drop` blocks until the fence is done.
//!
//! The wait has no timeout: releasing the guards early is unsafe, and
//! elapsed time cannot tell a stuck commit from a slow one, so nothing
//! aborts on it either. While it waits it logs a warning every
//! [`FENCE_WARN_INTERVAL`] with the job's age, phase (queued for the writer
//! gate, or running its commit) and item count, so a wedged filesystem is
//! diagnosable. A wedged commit blocks link stop exactly as an inline commit
//! always did (a blocked thread cannot be aborted); the mitigation is the
//! process supervisor. The one fail-stop is a wait dropped inside a write
//! transaction with a live job: the job may be queued on the gate that thread
//! holds, and not waiting would release guards under it; that is a bug state.

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How often a waiting [`FenceWait`] logs that its job is still running.
pub const FENCE_WARN_INTERVAL: Duration = Duration::from_secs(10);

#[cfg(any(test, feature = "test-support"))]
struct TestHooks {
    fatal: Box<dyn Fn(&str) + Send + Sync>,
    warn: Box<dyn Fn(&str) + Send + Sync>,
    interval: Duration,
}

struct State {
    done: Mutex<bool>,
    changed: Condvar,
    created: Instant,
    /// Set by the job once it holds the writer gate.
    running: AtomicBool,
    items: AtomicUsize,
    #[cfg(any(test, feature = "test-support"))]
    hooks: Mutex<Option<Arc<TestHooks>>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            done: Mutex::new(false),
            changed: Condvar::new(),
            created: Instant::now(),
            running: AtomicBool::new(false),
            items: AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            hooks: Mutex::new(None),
        }
    }
}

thread_local! {
    /// The fence of the job running on this thread, so the writer gate can
    /// mark its phase.
    static CURRENT: RefCell<Option<JobFence>> = const { RefCell::new(None) };
}

/// Marks the job running on this thread (if any) as holding the writer gate.
pub(crate) fn mark_running_current() {
    CURRENT.with(|current| {
        if let Some(fence) = current.borrow().as_ref() {
            fence.0.running.store(true, Ordering::Relaxed);
        }
    });
}

/// Shared completion state of one job (or one batch of items committed by
/// one job).
#[derive(Clone, Default)]
pub struct JobFence(Arc<State>);

/// Held by the job; marks the fence done when dropped, however the job ends.
pub struct JobCompletion(JobFence);

/// While alive, the job's phase marks land on its fence.
pub struct JobScope(());

/// Blocks in `Drop` until the job it was made for has finished.
pub struct FenceWait(JobFence);

impl JobFence {
    pub fn new() -> Self {
        Self::default()
    }

    /// The guard the job holds.
    pub fn completion(&self) -> JobCompletion {
        JobCompletion(self.clone())
    }

    /// The guard whose `Drop` waits for the job.
    pub fn waiter(&self) -> FenceWait {
        FenceWait(self.clone())
    }

    pub fn is_done(&self) -> bool {
        *self.0.done.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Waits up to `bound` for the job; whether it is done.
    pub fn wait_for(&self, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        let mut done = self.0.done.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !*done {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            done = self
                .0
                .changed
                .wait_timeout(done, left)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        true
    }

    /// Per-fence test hooks: what a fail-stop and a still-waiting warning do,
    /// and how often the warning fires. Scoped to this fence so parallel tests
    /// cannot observe each other's.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_test_hooks(
        &self,
        fatal: impl Fn(&str) + Send + Sync + 'static,
        warn: impl Fn(&str) + Send + Sync + 'static,
        interval: Duration,
    ) {
        *self.0.hooks.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Arc::new(TestHooks { fatal: Box::new(fatal), warn: Box::new(warn), interval }));
    }

    fn warn_interval(&self) -> Duration {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(hooks) = self.0.hooks.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            return hooks.interval;
        }
        FENCE_WARN_INTERVAL
    }

    fn describe(&self) -> String {
        format!(
            "age_ms={} phase={} items={}",
            self.0.created.elapsed().as_millis(),
            if self.0.running.load(Ordering::Relaxed) {
                "running the commit"
            } else {
                "queued for the writer gate"
            },
            self.0.items.load(Ordering::Relaxed),
        )
    }

    fn warn(&self, message: &str) {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(hooks) = self.0.hooks.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            (hooks.warn)(message);
            return;
        }
        tracing::warn!("{message}");
    }

    /// A fenced job cannot be waited for safely; the state a stopped process
    /// leaves (intent open, row in flight) is what startup repair finishes.
    fn fail_stop(&self, reason: &str) {
        tracing::error!(reason, "fatal: a database job fence cannot be honoured; aborting");
        #[cfg(any(test, feature = "test-support"))]
        if let Some(hooks) = self.0.hooks.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            (hooks.fatal)(reason);
            return;
        }
        std::process::abort();
    }
}

impl JobCompletion {
    /// Makes this job's phase marks land on its fence, on this thread.
    pub fn enter(&self) -> JobScope {
        CURRENT.with(|current| *current.borrow_mut() = Some(self.0.clone()));
        JobScope(())
    }

    /// How many items the job commits, for the waiting warning.
    pub fn set_items(&self, items: usize) {
        self.0 .0.items.store(items, Ordering::Relaxed);
    }
}

impl Drop for JobScope {
    fn drop(&mut self) {
        CURRENT.with(|current| *current.borrow_mut() = None);
    }
}

impl Drop for JobCompletion {
    fn drop(&mut self) {
        let mut done = (self.0).0.done.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        *done = true;
        (self.0).0.changed.notify_all();
    }
}

impl Drop for FenceWait {
    fn drop(&mut self) {
        if self.0.is_done() {
            return;
        }
        if crate::current_thread_in_write_transaction() {
            // The job may be queued on the writer gate this thread holds, so
            // waiting could deadlock, and not waiting releases guards under a
            // live job. No fenced future is dropped from a write closure by
            // construction (the window run is dropped by the runtime), so
            // this is a bug state.
            self.0.fail_stop(
                "a fenced database job is still running and its waiter was dropped inside a \
                 write transaction",
            );
            return;
        }
        let interval = self.0.warn_interval();
        while !self.0.wait_for(interval) {
            self.0.warn(&format!(
                "a fenced database job is still running; its guards stay held until it ends ({})",
                self.0.describe()
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiter_blocks_until_the_completion_drops() {
        let fence = JobFence::new();
        let completion = fence.completion();
        let waiter = fence.waiter();
        let thread = std::thread::spawn(move || drop(waiter));
        std::thread::sleep(Duration::from_millis(50));
        assert!(!thread.is_finished(), "the waiter must block while the job runs");
        drop(completion);
        thread.join().unwrap();
        assert!(fence.is_done());
    }

    #[test]
    fn completion_dropped_without_running_still_signals() {
        let fence = JobFence::new();
        drop(fence.completion());
        drop(fence.waiter());
    }
}

#[cfg(test)]
mod ladder_tests {
    use super::*;

    /// The warning ladder fires at the injected interval with the job's phase
    /// and item count, the wait still ends when the job completes, and the
    /// waiter keeps its guard (the thread dropping it) until then.
    #[test]
    fn a_waiting_fence_warns_and_waits_for_the_job() {
        let fence = JobFence::new();
        let warnings: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = warnings.clone();
        fence.set_test_hooks(
            |reason| panic!("unexpected fail-stop: {reason}"),
            move |message| sink.lock().unwrap().push(message.to_owned()),
            Duration::from_millis(40),
        );
        let completion = fence.completion();
        completion.set_items(3);
        let waiter = fence.waiter();
        let returned = Arc::new(AtomicBool::new(false));
        let flag = returned.clone();
        let thread = std::thread::spawn(move || {
            drop(waiter);
            flag.store(true, Ordering::SeqCst);
        });
        // Wait for the ladder to repeat rather than for a fixed time: a loaded
        // machine can start the waiter thread late.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while warnings.lock().unwrap().len() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!returned.load(Ordering::SeqCst), "the wait gave up before the job ended");
        {
            let seen = warnings.lock().unwrap();
            assert!(seen.len() >= 2, "the ladder did not repeat: {seen:?}");
            assert!(seen[0].contains("items=3") && seen[0].contains("queued for the writer gate"));
        }
        let _scope = completion.enter();
        mark_running_current();
        drop(_scope);
        // The next warning after the phase mark reports it; wait for that warning rather than
        // for a fixed time, which a loaded machine can overrun.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !warnings.lock().unwrap().last().unwrap().contains("running the commit")
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(warnings.lock().unwrap().last().unwrap().contains("running the commit"));
        drop(completion);
        thread.join().unwrap();
        assert!(returned.load(Ordering::SeqCst));
    }
}
