//! The two long-lived handles a desktop front end holds: a sign-in in
//! progress ([`LoginSession`]) and the status poll loop ([`StatusWatch`]).
//!
//! Both run their work as a task on the Tokio runtime that is current when
//! they start, and both hand results to one consumer through a queue the
//! consumer awaits. Awaiting is cancel-safe: abandoning a `next_event` or
//! `next` call loses nothing.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::dto::{AccountStatus, LoginEvent, LoginOptions, StatusUpdate};
use crate::error::{DesktopError, NetworkErrorKind};

/// A boxed future the sessions run.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Where a sign-in flow reports its non-terminal steps.
#[derive(Clone)]
pub struct LoginEventSink {
    shared: Arc<LoginShared>,
}

impl LoginEventSink {
    /// Reports one step. A terminal event is ignored here: the session
    /// itself emits the one terminal event from the flow's result.
    pub fn send(&self, event: LoginEvent) {
        if !event.is_terminal() {
            self.shared.push(event);
        }
    }
}

/// A sign-in flow: reports its steps to the sink, then resolves to the
/// account it signed in, or to the error that ended it.
pub type LoginFlowFn =
    Box<dyn FnOnce(LoginEventSink) -> BoxFuture<Result<AccountStatus, DesktopError>> + Send>;

/// A check `begin` runs before starting the flow, so a refusal that needs no
/// network (this installation is already enrolled) is an error of `begin`
/// rather than an event.
pub type LoginPrecheckFn = Box<dyn Fn() -> Result<(), DesktopError> + Send + Sync>;

struct LoginShared {
    queue: Mutex<LoginQueue>,
    ready: Notify,
    stop: Notify,
}

#[derive(Default)]
struct LoginQueue {
    events: VecDeque<LoginEvent>,
    terminal_queued: bool,
    terminal_delivered: bool,
    /// The flow task owns the terminal event once it runs.
    flow_running: bool,
    cancel_requested: bool,
}

impl LoginShared {
    /// Queues one event. Once a terminal event is queued nothing more is,
    /// and once a cancel is requested no further step is.
    fn push(&self, event: LoginEvent) {
        let mut queue = lock(&self.queue);
        if queue.terminal_queued || (queue.cancel_requested && !event.is_terminal()) {
            return;
        }
        queue.terminal_queued = event.is_terminal();
        queue.events.push_back(event);
        drop(queue);
        self.ready.notify_one();
    }

    /// Asks the session to end as cancelled. Steps not yet read are dropped.
    /// While the flow runs, its task decides the terminal event: `Cancelled`
    /// when it stopped the flow, `SignedIn` only if the flow had already
    /// completed (and so stored its credential), so the event never claims
    /// less than what happened.
    fn cancel(&self) {
        let mut queue = lock(&self.queue);
        if !queue.terminal_queued {
            queue.cancel_requested = true;
            queue.events.clear();
            if !queue.flow_running {
                queue.events.push_back(LoginEvent::Cancelled);
                queue.terminal_queued = true;
            }
        }
        drop(queue);
        self.ready.notify_one();
        // `notify_one` keeps a permit, so a flow task that has not reached its
        // wait yet still sees the stop.
        self.stop.notify_one();
    }
}

/// A poisoned lock only means another thread panicked while holding it; the
/// queue itself is still consistent, so keep going rather than panic again.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

enum Stage {
    NotBegun { precheck: LoginPrecheckFn, flow: LoginFlowFn },
    Begun,
}

/// A sign-in, started with [`LoginSession::begin`] and read one event at a
/// time with [`LoginSession::next_event`]. The browser is opened by the
/// front end when it reads [`LoginEvent::OpenBrowser`].
pub struct LoginSession {
    overall_timeout: Option<Duration>,
    stage: Mutex<Stage>,
    shared: Arc<LoginShared>,
}

/// The one message a timed-out sign-in fails with.
pub const SIGN_IN_TIMEOUT_MESSAGE: &str = "timed out waiting for browser sign-in";

impl LoginSession {
    /// A session over any flow. The product builds its sessions with
    /// [`crate::ClientCore::new_login_session`]; this is also how a front
    /// end's tests drive a scripted sign-in.
    #[must_use]
    pub fn with_flow(options: LoginOptions, precheck: LoginPrecheckFn, flow: LoginFlowFn) -> Self {
        LoginSession {
            overall_timeout: options.overall_timeout,
            stage: Mutex::new(Stage::NotBegun { precheck, flow }),
            shared: Arc::new(LoginShared {
                queue: Mutex::new(LoginQueue::default()),
                ready: Notify::new(),
                stop: Notify::new(),
            }),
        }
    }

    /// Starts the flow on the current Tokio runtime and returns at once. A
    /// session begins at most once, whether or not that attempt succeeded.
    ///
    /// # Errors
    /// `InvalidInput` when the session was already begun or cancelled;
    /// whatever the precheck refuses with (an installation that is already
    /// enrolled is `PermissionDenied{SessionRejected}`); `Internal` when no
    /// Tokio runtime is current.
    pub fn begin(&self) -> Result<(), DesktopError> {
        let stage = std::mem::replace(&mut *lock(&self.stage), Stage::Begun);
        let Stage::NotBegun { precheck, flow } = stage else {
            return Err(DesktopError::invalid_input(
                "this sign-in was already started or cancelled; start a new one",
                "session",
            ));
        };
        if lock(&self.shared.queue).cancel_requested {
            return Err(DesktopError::invalid_input("this sign-in was cancelled", "session"));
        }
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| DesktopError::Internal {
                message: "a sign-in needs an async runtime to run on".into(),
                category: "no_runtime".into(),
            })?;
        precheck()?;
        {
            let mut queue = lock(&self.shared.queue);
            if queue.cancel_requested {
                return Err(DesktopError::invalid_input("this sign-in was cancelled", "session"));
            }
            queue.flow_running = true;
        }
        let shared = self.shared.clone();
        let running = flow(LoginEventSink { shared: shared.clone() });
        runtime.spawn(run_login(shared, running, self.overall_timeout));
        Ok(())
    }

    /// The next event in order. `None` once a terminal event (`SignedIn`,
    /// `Failed`, `Cancelled`) has been returned. For one consumer; abandoning
    /// the call loses nothing.
    pub async fn next_event(&self) -> Option<LoginEvent> {
        loop {
            {
                let mut queue = lock(&self.shared.queue);
                if queue.terminal_delivered {
                    return None;
                }
                if let Some(event) = queue.events.pop_front() {
                    queue.terminal_delivered = event.is_terminal();
                    return Some(event);
                }
            }
            self.shared.ready.notified().await;
        }
    }

    /// Idempotent. Stops the flow (nothing is written to the credential
    /// store after this), drops the steps not yet read, and ends the stream
    /// with `Cancelled` -- unless the flow had already finished, in which
    /// case its own terminal event stands.
    pub fn cancel(&self) {
        self.shared.cancel();
    }
}

impl Drop for LoginSession {
    /// A sign-in nobody can read any more is stopped, so it does not keep a
    /// loopback port open or finish writing a credential nobody asked for.
    fn drop(&mut self) {
        self.shared.cancel();
    }
}

/// Runs the flow until it finishes, is cancelled, or times out, and queues
/// the one terminal event. The stop signal is checked before every poll of
/// the flow, and the flow's store write and its completion happen in one
/// poll, so a stopped flow is dropped before it can write, and a flow that
/// did write is reported as signed in.
async fn run_login(
    shared: Arc<LoginShared>,
    flow: BoxFuture<Result<AccountStatus, DesktopError>>,
    overall_timeout: Option<Duration>,
) {
    let deadline = async {
        match overall_timeout {
            Some(limit) => tokio::time::sleep(limit).await,
            None => std::future::pending().await,
        }
    };
    let terminal = tokio::select! {
        biased;
        () = shared.stop.notified() => LoginEvent::Cancelled,
        result = flow => match result {
            Ok(account) => LoginEvent::SignedIn { account },
            Err(error) => LoginEvent::Failed { error },
        },
        () = deadline => LoginEvent::Failed {
            error: DesktopError::Network {
                message: SIGN_IN_TIMEOUT_MESSAGE.into(),
                kind: NetworkErrorKind::Unreachable,
            },
        },
    };
    shared.push(terminal);
}

/// Polls status with this, and reports what it returns.
pub type StatusPollFn = Arc<dyn Fn() -> BoxFuture<StatusUpdate> + Send + Sync>;

/// The shortest poll interval a watch accepts; anything shorter would spin.
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct WatchShared {
    latest: Mutex<WatchSlot>,
    ready: Notify,
    refresh: Notify,
    stop: Notify,
}

#[derive(Default)]
struct WatchSlot {
    /// The most recent result, and whether the consumer has read it.
    value: Option<StatusUpdate>,
    unread: bool,
    cancelled: bool,
}

/// The status poll loop: one per process. The first [`StatusWatch::next`]
/// returns the first poll's result; later calls wait until the result
/// changes (ignoring only the capture time) or [`StatusWatch::refresh`]
/// forces a poll. A slow consumer gets the latest result, never a backlog.
///
/// Because an unchanged result is not delivered again, a snapshot's
/// `captured_at` is when its content was first seen, not the last poll.
pub struct StatusWatch {
    shared: Arc<WatchShared>,
}

impl StatusWatch {
    /// Starts polling on the current Tokio runtime every `interval`. Without
    /// a current runtime there is nothing to poll on, and the watch ends at
    /// once (`next` returns `None`).
    #[must_use]
    pub fn start(poll: StatusPollFn, interval: Duration) -> Self {
        let shared = Arc::new(WatchShared {
            latest: Mutex::new(WatchSlot::default()),
            ready: Notify::new(),
            refresh: Notify::new(),
            stop: Notify::new(),
        });
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(run_watch(shared.clone(), poll, interval.max(MIN_POLL_INTERVAL)));
            }
            Err(_) => lock(&shared.latest).cancelled = true,
        }
        StatusWatch { shared }
    }

    /// The next result; `None` after [`StatusWatch::cancel`]. Abandoning the
    /// call loses nothing.
    pub async fn next(&self) -> Option<StatusUpdate> {
        loop {
            {
                let mut slot = lock(&self.shared.latest);
                if slot.cancelled {
                    return None;
                }
                if slot.unread {
                    slot.unread = false;
                    return slot.value.clone();
                }
            }
            self.shared.ready.notified().await;
        }
    }

    /// Polls now, and delivers that result even when it has not changed.
    pub fn refresh(&self) {
        self.shared.refresh.notify_one();
    }

    /// Stops the poll loop. Idempotent; dropping the watch does the same.
    pub fn cancel(&self) {
        lock(&self.shared.latest).cancelled = true;
        self.shared.stop.notify_one();
        self.shared.ready.notify_one();
    }
}

impl Drop for StatusWatch {
    fn drop(&mut self) {
        self.cancel();
    }
}

async fn run_watch(shared: Arc<WatchShared>, poll: StatusPollFn, interval: Duration) {
    let mut forced = false;
    loop {
        let update = tokio::select! {
            biased;
            () = shared.stop.notified() => return,
            update = poll() => update,
        };
        publish(&shared, update, forced);
        forced = tokio::select! {
            biased;
            () = shared.stop.notified() => return,
            () = shared.refresh.notified() => true,
            () = tokio::time::sleep(interval) => false,
        };
    }
}

/// Stores `update` as the latest result and wakes the consumer, unless it
/// is the same as what is already there and no refresh asked for it.
fn publish(shared: &WatchShared, update: StatusUpdate, forced: bool) {
    let mut slot = lock(&shared.latest);
    if slot.cancelled {
        return;
    }
    let unchanged = slot.value.as_ref().is_some_and(|current| same_content(current, &update));
    if unchanged && !forced {
        return;
    }
    if !unchanged {
        slot.value = Some(update);
    }
    slot.unread = true;
    drop(slot);
    shared.ready.notify_one();
}

/// Equal apart from the snapshot's capture time.
fn same_content(a: &StatusUpdate, b: &StatusUpdate) -> bool {
    match (a, b) {
        (StatusUpdate::Snapshot { snapshot: a }, StatusUpdate::Snapshot { snapshot: b }) => {
            let mut b = b.clone();
            b.captured_at = a.captured_at;
            *a == b
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests;
