//! Managing another device on this account (a NAS) from this computer's
//! browser: one operation, [`open_nas_admin`], that every front end uses.
//!
//! The daemon does the work: it reaches the device over the device
//! connection, checks that its management page answers, and serves it at a
//! page address on this computer. The session lives as long as the
//! [`AdminSession`] this returns: [`AdminSession::close`], dropping it, or
//! this process exiting ends it, and the page address stops answering.

use std::sync::Mutex;

use tokio::io::AsyncReadExt as _;
use tokio::sync::{oneshot, watch};
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::open_nas_admin_response::Outcome;
use yadorilink_ipc_proto::daemonctl::{NasAdminFailureKind, OpenNasAdminRequest};

use crate::daemon::control;
use crate::error::CoreError;
use crate::wording::NasAdminFailure;

/// What opening a session came to.
#[derive(Debug)]
pub enum NasAdminOpen {
    /// The management page is served at [`AdminSession::local_url`].
    Opened(AdminSession),
    /// The page cannot be opened; [`crate::wording::nas_admin_failure_message`]
    /// says why.
    Failed(NasAdminFailure),
}

/// An open session. Ends on [`AdminSession::close`], on drop, or when the
/// daemon ends it (the device went away, or nothing used it for a while).
#[derive(Debug)]
pub struct AdminSession {
    local_url: String,
    close: Mutex<Option<oneshot::Sender<()>>>,
    ended: watch::Receiver<bool>,
}

impl AdminSession {
    /// The page address on this computer while the session lives.
    #[must_use]
    pub fn local_url(&self) -> &str {
        &self.local_url
    }

    /// Ends the session. Idempotent.
    pub fn close(&self) {
        self.close.lock().unwrap_or_else(|p| p.into_inner()).take();
    }

    /// Resolves once the session has ended, whichever side ended it.
    pub async fn ended(&self) {
        let mut ended = self.ended.clone();
        let _ = ended.wait_for(|ended| *ended).await;
    }
}

/// Opens a session for `device_id`, a device on this account.
///
/// # Errors
/// Only for the daemon itself (not running, unresponsive, another protocol
/// generation); every way the device can fail to be managed is
/// [`NasAdminOpen::Failed`].
pub async fn open_nas_admin(device_id: String) -> Result<NasAdminOpen, CoreError> {
    let (response, mut connection) =
        control::open_held(ReqPayload::OpenNasAdmin(OpenNasAdminRequest { device_id })).await?;
    let Some(RespPayload::OpenNasAdmin(answer)) = response.payload else {
        return Err(CoreError::Other("unexpected daemon response".into()));
    };
    let local_url = match answer.outcome {
        Some(Outcome::LocalUrl(url)) => url,
        Some(Outcome::Failure(kind)) => return Ok(NasAdminOpen::Failed(failure_of(kind))),
        None => return Ok(NasAdminOpen::Failed(NasAdminFailure::CouldNotOpen)),
    };
    let (close, closed) = oneshot::channel();
    let (ended_tx, ended) = watch::channel(false);
    // Holds the connection, which is what keeps the session open, until
    // the caller lets go or the daemon closes it.
    tokio::spawn(async move {
        let mut byte = [0u8; 1];
        tokio::select! {
            _ = connection.read(&mut byte) => {}
            _ = closed => {}
        }
        drop(connection);
        let _ = ended_tx.send(true);
    });
    Ok(NasAdminOpen::Opened(AdminSession { local_url, close: Mutex::new(Some(close)), ended }))
}

fn failure_of(kind: i32) -> NasAdminFailure {
    match NasAdminFailureKind::try_from(kind) {
        Ok(NasAdminFailureKind::Offline) => NasAdminFailure::Offline,
        Ok(NasAdminFailureKind::Unavailable) => NasAdminFailure::Unavailable,
        Ok(NasAdminFailureKind::CouldNotOpen | NasAdminFailureKind::Unspecified) | Err(_) => {
            NasAdminFailure::CouldNotOpen
        }
    }
}
