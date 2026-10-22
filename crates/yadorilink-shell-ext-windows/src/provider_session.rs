//! The host's persistent connection to the daemon over its named pipe.
//!
//! The session protocol (commands out in order, pushes in as events, reconnect after a loss)
//! lives in `yadorilink_windows_provider_policy::provider_session`; this module starts it on
//! the daemon's pipe.

use std::sync::mpsc::Sender;

use yadorilink_windows_provider_policy::provider_session as policy;

pub use policy::{Session, SessionEvent};

/// Starts the session thread. Events arrive on `events`; the returned handle sends commands.
pub fn spawn<E: From<SessionEvent> + Send + 'static>(events: Sender<E>) -> Session {
    policy::spawn(crate::provider_client::Pipe, events)
}
