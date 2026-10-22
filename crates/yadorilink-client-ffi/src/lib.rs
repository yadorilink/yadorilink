//! The platform-neutral client facade of YadoriLink, exported through UniFFI.
//!
//! The macOS app consumes it as Swift and the Windows app as C#, both generated
//! from this one library (`yadorilink_client_ffi`, see `Cargo.toml`).
//!
//! Four objects are exported, with the names the app codes against:
//! [`ClientCore`], [`LoginSession`], [`StatusWatch`] and [`AdminSession`]. Each wraps its
//! counterpart in `yadorilink-client-core` and adds only the bridge:
//!
//! - One multi-thread Tokio runtime, built on first use and kept for the life
//!   of the process. The foreign side (Swift, C#) drives exported futures on its own executor, so
//!   every call is spawned onto this runtime and the foreign side awaits the
//!   task's handle.
//! - Nothing panics across the boundary. A task that panics becomes
//!   `DesktopError::Internal`, and the few synchronous methods catch unwinds.
//! - A foreign caller cannot abandon an awaited call: the generated async shim ignores
//!   Task cancellation, so a call runs until the Rust side returns. The
//!   waits that could last indefinitely stop only through their own cancel
//!   methods: `LoginSession::cancel` ends `next_event` and the sign-in flow,
//!   `StatusWatch::cancel` ends `next`. The client layer bounds the rest:
//!   coordination-plane requests have connect and request deadlines, and
//!   the daemon's quick requests and shutdown have a reply deadline. A
//!   long-running daemon operation (linking, restore, garbage collection,
//!   updates, group commands) has no deadline, since it cannot be told
//!   apart from one still making progress; its call returns only when the
//!   daemon answers or closes the connection.

// `DesktopError` is the one typed error every exported call returns by value; its
// refusal reasons carry typed lists for the shells, so it is larger than clippy's
// 128-byte `Err` threshold. Boxing it would change the generated Swift/C# error type
// for no benefit on a path that runs once per user action.
#![allow(clippy::result_large_err)]

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock};

use yadorilink_client_core as core;
use yadorilink_client_core::dto::{LoginEvent, StatusUpdate};
use yadorilink_client_core::DesktopError;

uniffi::setup_scaffolding!();

mod facade;

pub use facade::ClientCore;

// ---- the runtime bridge ---------------------------------------------------------

static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

/// The process-wide runtime every call runs on.
fn runtime() -> Result<&'static tokio::runtime::Runtime, DesktopError> {
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .thread_name("yadorilink-client")
                .enable_all()
                .build()
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| DesktopError::Internal {
            message: format!("could not start the client runtime: {e}"),
            category: "runtime_unavailable".into(),
        })
}

/// Runs `work` on the client runtime and awaits it from whatever executor
/// polls the returned future. A panic in `work` is an `Internal` error.
async fn bridge<T, F>(work: F) -> Result<T, DesktopError>
where
    T: Send + 'static,
    F: Future<Output = Result<T, DesktopError>> + Send + 'static,
{
    match runtime()?.spawn(work).await {
        Ok(result) => result,
        Err(error) => Err(task_failure(&error)),
    }
}

fn task_failure(error: &tokio::task::JoinError) -> DesktopError {
    if error.is_panic() {
        DesktopError::Internal {
            message: "the operation stopped unexpectedly".into(),
            category: "panic".into(),
        }
    } else {
        DesktopError::Internal {
            message: "the operation was stopped before it finished".into(),
            category: "task_cancelled".into(),
        }
    }
}

/// Runs a synchronous method body, turning a panic into `fallback`.
fn guarded<T>(fallback: impl FnOnce() -> T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| fallback())
}

// ---- sign-in --------------------------------------------------------------------

/// A sign-in in progress; see `yadorilink_client_core::session::LoginSession`.
#[derive(uniffi::Object)]
pub struct LoginSession {
    inner: Arc<core::session::LoginSession>,
}

impl LoginSession {
    fn wrap(inner: Arc<core::session::LoginSession>) -> Arc<Self> {
        Arc::new(LoginSession { inner })
    }
}

#[uniffi::export]
impl LoginSession {
    /// Starts the flow and returns at once.
    ///
    /// # Errors
    /// `InvalidInput` when already begun or cancelled; `PermissionDenied`
    /// when this installation is already signed in.
    pub fn begin(&self) -> Result<(), DesktopError> {
        let inner = self.inner.clone();
        guarded(
            || Err(sync_panic()),
            move || {
                let _entered = runtime()?.enter();
                inner.begin()
            },
        )
    }

    /// The next event in order; `None` after the terminal event.
    ///
    /// Awaited in place rather than spawned: it only waits on the session's
    /// queue, which needs no runtime, and so an abandoned call loses no event.
    pub async fn next_event(&self) -> Option<LoginEvent> {
        self.inner.next_event().await
    }

    /// Idempotent. Stops the flow; nothing is stored after this.
    pub fn cancel(&self) {
        let inner = self.inner.clone();
        guarded(|| (), move || inner.cancel());
    }
}

// ---- status -------------------------------------------------------------------

/// The status poll loop; see `yadorilink_client_core::session::StatusWatch`.
#[derive(uniffi::Object)]
pub struct StatusWatch {
    inner: Arc<core::session::StatusWatch>,
}

#[uniffi::export]
impl StatusWatch {
    /// The next result; `None` after `cancel`. Awaited in place, like
    /// `LoginSession::next_event`, so an abandoned call loses nothing.
    pub async fn next(&self) -> Option<StatusUpdate> {
        self.inner.next().await
    }

    /// Polls now and delivers the result even if it has not changed.
    pub fn refresh(&self) {
        let inner = self.inner.clone();
        guarded(|| (), move || inner.refresh());
    }

    /// Stops polling. Idempotent; dropping the watch does the same.
    pub fn cancel(&self) {
        let inner = self.inner.clone();
        guarded(|| (), move || inner.cancel());
    }
}

// ---- device management ------------------------------------------------------------

/// What opening a device's management page came to.
#[derive(uniffi::Enum)]
pub enum NasAdminOpening {
    /// The page is served at `session.local_url()` while `session` is open.
    Opened { session: Arc<AdminSession> },
    /// It cannot be opened; `message` is the sentence to show.
    Failed { failure: core::wording::NasAdminFailure, message: String },
}

/// An open management session; see
/// `yadorilink_client_core::ops::nas_admin::AdminSession`. Ends on `close`,
/// when released, or when the daemon ends it.
#[derive(uniffi::Object)]
pub struct AdminSession {
    inner: core::ops::nas_admin::AdminSession,
}

impl AdminSession {
    fn wrap(inner: core::ops::nas_admin::AdminSession) -> Self {
        AdminSession { inner }
    }
}

#[uniffi::export]
impl AdminSession {
    /// The page address to open in the browser.
    pub fn local_url(&self) -> String {
        self.inner.local_url().to_string()
    }

    /// Ends the session. Idempotent.
    pub fn close(&self) {
        guarded(|| (), || self.inner.close());
    }

    /// Returns once the session has ended, whichever side ended it. Awaited
    /// in place, like `StatusWatch::next`.
    pub async fn ended(&self) {
        self.inner.ended().await;
    }
}

fn sync_panic() -> DesktopError {
    DesktopError::Internal {
        message: "the operation stopped unexpectedly".into(),
        category: "panic".into(),
    }
}

#[cfg(test)]
mod tests;
