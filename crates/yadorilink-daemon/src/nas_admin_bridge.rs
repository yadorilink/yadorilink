//! Managing another device on this account from this computer's browser.
//!
//! The answering side is `nas_admin`; this is the dialling side. A session
//! is opened for one device when the user asks for it, and only then:
//!
//! 1. the device is looked up on this device's own account listing (its key
//!    and where it answers), and dialled from this device's endpoint on the
//!    management ALPN;
//! 2. availability is checked by opening one stream, expecting `Ready`, and
//!    dropping it;
//! 3. a listener is bound on `127.0.0.1:0`, and its address is the page
//!    address handed back;
//! 4. every TCP connection the browser makes there gets one management
//!    stream, and bytes are copied both ways. Nothing here reads HTTP:
//!    keep-alive, WebSocket and server-sent events pass through.
//!
//! The listener belongs to the session. The session ends when whoever asked
//! for it goes away (the control connection it was opened on closes), when
//! the device connection ends, or when nothing has used it for
//! [`BridgeLimits::session_idle`]; the listener is dropped with it. Nothing
//! is kept anywhere else, so a daemon restart leaves nothing behind.
//!
//! No host or port is taken from anyone: the listener address is chosen
//! here (loopback, ephemeral), and the remote end is the device's one
//! management service, named by the ALPN alone.

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Weak};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use yadorilink_sync_substrate::{NasAdminConnection, NasAdminError, PeerId};

use crate::daemon_state::DaemonState;

/// Why a session could not be opened. Closed: every failure is one of these
/// three, and none says how the page is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenFailure {
    /// The device could not be reached.
    Offline,
    /// The device does not offer management: its management page is not
    /// running, or it does not answer the management protocol at all. The
    /// second is a desktop (only the headless profile offers management) as
    /// often as an older build, and the dialler cannot tell which, so it is
    /// not reported as "needs a newer version".
    Unavailable,
    /// Anything else: refused, busy, not a device on this account, too
    /// many sessions open here.
    CouldNotOpen,
}

impl From<NasAdminError> for OpenFailure {
    fn from(error: NasAdminError) -> Self {
        match error {
            NasAdminError::Unreachable => Self::Offline,
            NasAdminError::Unsupported | NasAdminError::Unavailable => Self::Unavailable,
            NasAdminError::Unauthorized | NasAdminError::Busy | NasAdminError::Failed => {
                Self::CouldNotOpen
            }
        }
    }
}

/// The bounds of one session.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BridgeLimits {
    /// Browser connections bridged at once. Beyond it the listener stops
    /// accepting until one ends; a browser opens a handful per page.
    pub(crate) connections: usize,
    /// A bridged connection on which no byte has moved either way for this
    /// long is closed. The managed device applies the same deadline to its
    /// own end; this one does not rely on it.
    pub(crate) connection_idle: Duration,
    /// A session with no bridged connection for this long ends.
    pub(crate) session_idle: Duration,
    /// How long the dial and the availability check may each take.
    pub(crate) step: Duration,
    /// How long opening the device stream for one browser connection may
    /// take. A device that never answers must not hold a connection slot.
    pub(crate) stream_open: Duration,
}

impl Default for BridgeLimits {
    fn default() -> Self {
        Self {
            connections: 16,
            connection_idle: Duration::from_secs(60),
            session_idle: Duration::from_secs(600),
            step: Duration::from_secs(20),
            stream_open: Duration::from_secs(10),
        }
    }
}

/// How many sessions this device holds open at once.
const MAX_SESSIONS: usize = 4;

/// How long the device lookup on the coordination plane may take.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens sessions for the control socket.
pub(crate) struct NasAdminSessions {
    /// Weak, like Track Send's services: the control socket must not keep
    /// the daemon's state alive.
    state: Weak<DaemonState>,
    open: Arc<Semaphore>,
}

impl NasAdminSessions {
    pub(crate) fn new(state: &Arc<DaemonState>) -> Self {
        Self { state: Arc::downgrade(state), open: Arc::new(Semaphore::new(MAX_SESSIONS)) }
    }

    /// Opens a session for `device_id`: looks it up on this account, dials
    /// it, checks that its management page answers, and binds the local
    /// listener.
    pub(crate) async fn open(&self, device_id: &str) -> Result<OpenSession, OpenFailure> {
        let slot = self.open.clone().try_acquire_owned().map_err(|_| OpenFailure::CouldNotOpen)?;
        let state = self.state.upgrade().ok_or(OpenFailure::CouldNotOpen)?;
        if device_id == state.device_id {
            return Err(OpenFailure::CouldNotOpen);
        }
        let config = state.coordination_client_config().ok_or(OpenFailure::CouldNotOpen)?;
        let lookup =
            crate::coordination_client::find_account_device(&config.addr, &config.auth, device_id);
        let (key, hints) = match tokio::time::timeout(LOOKUP_TIMEOUT, lookup).await {
            Ok(Ok(Some(found))) => found,
            Ok(Ok(None)) => return Err(OpenFailure::CouldNotOpen),
            Ok(Err(error)) => {
                tracing::debug!(%error, "could not look up the device to manage");
                return Err(OpenFailure::CouldNotOpen);
            }
            Err(_) => return Err(OpenFailure::CouldNotOpen),
        };
        let driver = state.peer_session_driver().ok_or(OpenFailure::Offline)?;
        drop(state);
        let limits = BridgeLimits::default();
        let dial = async move {
            driver.stack().endpoint().connect_nas_admin(PeerId::from_bytes(key), hints).await
        };
        let session = BridgeSession::open(dial, limits).await.inspect_err(|failure| {
            tracing::debug!(device_id, ?failure, "could not open a management session");
        })?;
        Ok(OpenSession { session, _slot: slot })
    }
}

/// A session and its place among [`MAX_SESSIONS`].
pub(crate) struct OpenSession {
    pub(crate) session: BridgeSession,
    _slot: OwnedSemaphorePermit,
}

/// One open session: a device connection that answered `Ready`, and the
/// loopback listener in front of it.
pub(crate) struct BridgeSession {
    connection: NasAdminConnection,
    listener: TcpListener,
    limits: BridgeLimits,
}

impl BridgeSession {
    /// Dials, checks availability, then binds. Each of the first two steps
    /// is bounded by `limits.step`; a dial that does not finish in time is
    /// an unreachable device.
    pub(crate) async fn open(
        dial: impl Future<Output = Result<NasAdminConnection, NasAdminError>>,
        limits: BridgeLimits,
    ) -> Result<Self, OpenFailure> {
        let connection = tokio::time::timeout(limits.step, dial)
            .await
            .unwrap_or(Err(NasAdminError::Unreachable))?;
        // The availability check: one stream that must answer `Ready`,
        // dropped at once.
        let checked = tokio::time::timeout(limits.step, connection.open_stream())
            .await
            .unwrap_or(Err(NasAdminError::Failed));
        if let Err(error) = checked {
            connection.close();
            return Err(error.into());
        }
        let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
            Ok(listener) => listener,
            Err(error) => {
                tracing::debug!(%error, "could not bind the local management listener");
                connection.close();
                return Err(OpenFailure::CouldNotOpen);
            }
        };
        Ok(Self { connection, listener, limits })
    }

    /// The page address while the session lives. Carries no secret.
    pub(crate) fn local_url(&self) -> String {
        let port = self.listener.local_addr().map(|addr| addr.port()).unwrap_or(0);
        format!("http://127.0.0.1:{port}/")
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().expect("bound")
    }

    /// Bridges browser connections until `until` resolves, the device
    /// connection ends, or the session has been idle for
    /// [`BridgeLimits::session_idle`]. On return the listener is closed,
    /// every bridged connection is ended and the device connection is
    /// closed.
    pub(crate) async fn serve(self, until: impl Future<Output = ()>) {
        let Self { connection, listener, limits } = self;
        serve_on(connection, listener, limits, until).await;
    }
}

/// The first pause after a failed accept, doubled on each further failure up
/// to [`ACCEPT_BACKOFF_MAX`] and reset by an accepted connection.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(10);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// What accepts browser connections: the session's loopback listener.
trait Accept {
    fn accept(&self) -> impl Future<Output = std::io::Result<TcpStream>> + Send;
}

impl Accept for TcpListener {
    async fn accept(&self) -> std::io::Result<TcpStream> {
        TcpListener::accept(self).await.map(|(tcp, _)| tcp)
    }
}

async fn serve_on(
    connection: NasAdminConnection,
    listener: impl Accept,
    limits: BridgeLimits,
    until: impl Future<Output = ()>,
) {
    let mut bridged = JoinSet::new();
    let idle = tokio::time::sleep(limits.session_idle);
    tokio::pin!(idle, until);
    let closed = connection.closed();
    tokio::pin!(closed);
    // While set, accepting is paused after a failure (descriptors
    // exhausted, say) instead of retrying in a hot loop.
    let mut paused_until: Option<tokio::time::Instant> = None;
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        tokio::select! {
            () = &mut until => break,
            () = &mut closed => break,
            () = &mut idle, if bridged.is_empty() => break,
            Some(_) = bridged.join_next(), if !bridged.is_empty() => {
                if bridged.is_empty() {
                    idle.as_mut().reset(tokio::time::Instant::now() + limits.session_idle);
                }
            }
            () = async { tokio::time::sleep_until(paused_until.expect("guarded")).await },
                if paused_until.is_some() => paused_until = None,
            accepted = listener.accept(), if paused_until.is_none() && bridged.len() < limits.connections => {
                let tcp = match accepted {
                    Ok(tcp) => {
                        backoff = ACCEPT_BACKOFF_MIN;
                        tcp
                    }
                    Err(error) => {
                        tracing::debug!(%error, "accepting a local management connection failed");
                        paused_until = Some(tokio::time::Instant::now() + backoff);
                        backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                        continue;
                    }
                };
                let connection = connection.clone();
                bridged.spawn(async move {
                    // A stream the device will not open (busy, stopped,
                    // refused) or does not answer in time ends this
                    // browser connection, nothing more.
                    let opened = tokio::time::timeout(limits.stream_open, connection.open_stream()).await;
                    if let Ok(Ok(stream)) = opened {
                        pump(tcp, stream, limits.connection_idle).await;
                    }
                });
            }
        }
    }
    drop(listener);
    bridged.shutdown().await;
    connection.close();
}

/// Holds `session` for as long as `control` (the connection it was opened
/// on) stays open: the client ends the session by closing it or by sending
/// anything at all.
pub(crate) async fn serve_for_connection<S>(session: BridgeSession, control: &mut S)
where
    S: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    session
        .serve(async {
            let _ = control.read(&mut byte).await;
        })
        .await;
}

/// Copies bytes both ways between a browser connection and a management
/// stream until either side finishes, or nothing moves for `idle`.
async fn pump<S>(tcp: TcpStream, stream: S, idle: Duration)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let (mut stream_read, mut stream_write) = tokio::io::split(stream);
    let activity = tokio::sync::watch::channel(()).0;
    let up = copy_half(&mut tcp_read, &mut stream_write, &activity);
    let down = copy_half(&mut stream_read, &mut tcp_write, &activity);
    let mut quiet = activity.subscribe();
    let watchdog = async move {
        loop {
            match tokio::time::timeout(idle, quiet.changed()).await {
                Ok(Ok(())) => {}
                // Idle, or both halves are done with the sender.
                _ => return,
            }
        }
    };
    tokio::select! {
        _ = async { tokio::join!(up, down) } => {}
        () = watchdog => {}
    }
}

/// One direction: reads until end of stream, then finishes the writer so
/// the other side sees the end too. Every chunk counts as activity.
async fn copy_half<R, W>(reader: &mut R, writer: &mut W, activity: &tokio::sync::watch::Sender<()>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if writer.write_all(&buf[..n]).await.is_err() {
                    return;
                }
                activity.send_replace(());
            }
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests;
