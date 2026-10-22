//! Connection-level admission control for the HTTP listener -- gates every
//! accepted TCP connection *before* any HTTP parsing or token-based
//! authorization happens.
//!
//! This exists independent of `lib.rs::build_router`'s request-level
//! `tower::limit::ConcurrencyLimitLayer`/`tower_http::timeout::TimeoutLayer`:
//! `axum::serve` spawns one long-lived task per *accepted* connection
//! unconditionally, before a single byte of that connection's request is
//! ever read (`handle_connection` calls the make-service, then
//! `tokio::spawn`s the connection-serving future, then hyper starts reading
//! from the socket) -- a request-level middleware, which only ever runs
//! once a complete HTTP request has been parsed off that socket, cannot
//! bound how many such tasks pile up from connections that never send a
//! complete request at all. Measured directly: a client that opens a
//! connection and sends nothing gets a task and an fd from this process
//! with no request-level layer ever having a chance to run.
//!
//! Two independent bounds, both applied before a connection is handed to
//! axum's own per-connection serving loop:
//!
//! - [`ConnLimitedListener`] caps how many connections can be actively
//!   served at once, via a semaphore acquired *before* this process even
//!   calls `accept(2)` for the next connection -- once the cap is reached,
//!   further connection attempts simply queue in the kernel's own accept
//!   backlog rather than consuming a userspace task/fd, until a permit
//!   frees up.
//! - [`LimitedIo`] closes a connection that has gone genuinely idle,
//!   releasing its permit -- otherwise a flood of connections that never
//!   let this adapter finish responding could fill every permit and hold
//!   them forever, starving legitimate traffic even though the total is
//!   bounded.
//!
//! This bounds a *passively* idle flood (nothing sent, or activity that
//! stopped and never resumed) to at most [`CONNECTION_IDLE_TIMEOUT`] per
//! connection. It does NOT bound an *actively* dribbling flood: a
//! connection that sends or receives even one byte per window renews its
//! own permit indefinitely, and enough such connections can still occupy
//! every slot and starve a legitimate request -- cheaply (on the order of
//! bytes per second across the whole flood), from any other local process
//! on the same machine, whether or not it holds this daemon's own auth
//! token. No timeout-shaped fix closes this residual -- see the "Why a
//! rolling idle timeout" section below for why an additional absolute
//! connection lifetime is the wrong answer here (it would kill genuine
//! long-lived SSE streams, this adapter's main use case, without even
//! stopping the attacker, who can just reconnect). This is a known,
//! accepted gap in the "other local users" part of this adapter's threat
//! model (see this crate's top-level doc comment): a hostile local
//! process can make this HTTP/dashboard adapter itself unreachable: it
//! cannot touch folder sync, which does not depend on this adapter at
//! all.
//!
//! # Why a rolling idle timeout, not a one-shot disarm
//!
//! An earlier version of this mechanism used a pair of one-shot deadlines
//! that were permanently *disarmed* once some attacker-observable condition
//! was met: the first successful write back to the client, or the byte
//! count read from the client crossing a fixed threshold. Both conditions
//! turned out to be unsound, for the same underlying reason -- the attacker
//! controls every byte sent on a connection they opened, so any fixed,
//! one-time condition phrased purely in terms of those bytes (or in terms
//! of a write this adapter is willing to produce in response to them) is
//! something the attacker can simply *arrange to satisfy once* and then
//! stop cooperating: send enough bytes to clear a byte-count threshold, or
//! complete enough of a legal (even ordinary, non-malicious-looking)
//! protocol exchange to provoke one write back, and the connection's
//! protective deadline is gone forever, even though the connection itself
//! goes on to do nothing at all afterward. That failure mode was
//! demonstrated concretely against two different exchanges: a well-formed,
//! completely idle HTTP/2 connection (the fixed 24-byte client preface plus
//! a single empty SETTINGS frame -- ordinary HTTP/2 handshake behavior,
//! nothing malformed about it), and an ordinary authenticated HTTP/1.1
//! request completed over keep-alive with zero protocol trickery at all.
//! Both permanently disarmed every deadline this module had, and the
//! connection could then sit open, holding its connection-slot permit,
//! indefinitely.
//!
//! [`LimitedIo`] instead tracks a single rolling deadline: the time of the
//! *last* successful read or write on the connection, refreshed by
//! [`CONNECTION_IDLE_TIMEOUT`] on every one, not disarmed by any of them.
//! This is sound against the same adversary specifically because it grants
//! no permanent exemption: no amount of legitimate-looking traffic sent
//! *once* buys a connection an escape from ever being checked again -- the
//! clock keeps getting pushed out only for as long as the connection
//! keeps doing something, read or write, and the instant it stops (for
//! whatever reason -- the attacker goes silent, or a genuine client's
//! connection dies without a clean TCP close) the existing deadline, already
//! ticking, elapses and reclaims the slot. There is no code path in this
//! module that ever stops checking a connection's activity for the rest of
//! its life the way the old first-write/byte-count disarms did.
//!
//! # Choosing the idle window
//!
//! [`CONNECTION_IDLE_TIMEOUT`] has to satisfy two things at once, in
//! tension with each other:
//!
//! - Long enough that it never fires out from under a request this adapter
//!   is legitimately still working on. `lib.rs::REQUEST_TIMEOUT` (30s) is
//!   the maximum time this adapter itself allows a request to spend being
//!   actively processed before it gives up and writes back its own `408`;
//!   while that's happening, the connection may see no read or write
//!   activity at all (a slow/hung control-socket round trip produces
//!   nothing on the client-facing TCP connection until either an answer or
//!   that 30s backstop fires). If the connection-level idle timeout were
//!   close to or shorter than that 30s figure, it could win the race and
//!   tear down the raw connection before the request-level machinery ever
//!   gets to write its own well-formed response -- exactly the mistake an
//!   earlier version of this module made with a 5s deadline that always
//!   lost that race against both `REQUEST_TIMEOUT` (30s) and
//!   `control_client.rs`'s own 5s control-socket timeout, silently making
//!   the documented "hung daemon -> `503`" contract unreachable: the
//!   client observed a raw connection reset instead of the intended
//!   response. [`CONNECTION_IDLE_TIMEOUT`] is set well clear of that 30s
//!   figure to give this comfortable headroom -- but this is an assumption
//!   this constant relies on, not an independently enforced bound: it
//!   depends on `queue_delay + active_processing` (a single connection's
//!   time spent waiting behind `MAX_CONCURRENT_REQUESTS` plus its own
//!   active-processing time, see `lib.rs::REQUEST_TIMEOUT`'s doc comment
//!   for why queue time specifically isn't covered by that timer either)
//!   staying under this constant's 60s. That holds comfortably for this
//!   adapter's real request shapes (a handful of milliseconds of queueing
//!   at most, since only a token holder's requests can ever be slow, and
//!   each holds at most one 5s control-socket round trip), but is not
//!   something this code checks or enforces on its own.
//! - Short enough to still firmly bound how long a truly idle connection
//!   (attacker-controlled or otherwise) can pin a connection-slot permit.
//!
//! [`CONNECTION_IDLE_TIMEOUT`] is a flat multiple of `REQUEST_TIMEOUT`,
//! chosen to leave comfortable headroom for scheduling jitter and any
//! incidental queuing delay on top of that 30s figure, while remaining far
//! short of anything resembling an unbounded hang. SSE streams stay well
//! inside this window on their own: `handlers::events`'s poller writes a
//! fresh frame at least every `POLL_INTERVAL` (2s) when the underlying
//! status changes, and even on a perfectly idle daemon where it never has
//! new data to send, axum's own `KeepAlive::default()` (`events.rs`)
//! writes a comment frame at least every 15s -- both comfortably inside
//! [`CONNECTION_IDLE_TIMEOUT`], so a real, ongoing SSE stream keeps
//! resetting its own deadline forever, exactly as intended.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::serve::Listener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// Total concurrent HTTP connections this adapter will actively serve at
/// once, across every bound listener (`127.0.0.1` and, when available,
/// `[::1]` share one budget -- see `AppState::sse_slots` for the analogous
/// choice on the SSE-specific cap). Deliberately higher than
/// `MAX_CONCURRENT_SSE_STREAMS` (32): this cap bounds *all* connections,
/// including short-lived plain REST calls, not just long-lived streams, so
/// it needs headroom for a legitimate browser dashboard issuing several
/// concurrent requests on top of one open SSE stream. Still firmly bounded
/// -- a few hundred is far more than a single-user localhost daemon's own
/// dashboard (and any dev-server origin) will ever need concurrently, while
/// capping the worst case of an unauthenticated local flood well short of
/// this process's own fd/task limits.
///
/// The effective cap on connections actually being *served* is 2 lower than
/// this: each of the two listeners' (`127.0.0.1` and `[::1]`) accept loops
/// permanently holds one permit while parked in `ConnLimitedListener::accept`
/// waiting for the next `accept(2)` to complete, since the permit is
/// acquired before that call, not after. Harmless (254 vs. 256 makes no
/// practical difference here) and not worth complicating the accounting to
/// avoid.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// The maximum time a request this adapter is actively processing may take
/// before `lib.rs`'s own `TimeoutLayer` gives up and writes a `408` --
/// see `lib.rs::REQUEST_TIMEOUT`, the authoritative definition. Duplicated
/// here as a plain constant (rather than importing across the crate's
/// module boundary) purely so [`CONNECTION_IDLE_TIMEOUT`]'s derivation below
/// is self-contained and a change to one is easy to compare against the
/// other; keep this in sync with `lib.rs::REQUEST_TIMEOUT` if that ever
/// changes.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a connection may go with *no* successful read and *no*
/// successful write before [`LimitedIo`] closes it and releases its
/// connection-slot permit -- see this module's doc comment for the full
/// reasoning. A flat multiple of [`REQUEST_TIMEOUT`] rather than an
/// independently chosen figure, so the relationship (and the margin it
/// leaves) stays obvious at a glance: comfortably longer than the longest a
/// legitimately in-flight request can leave its connection silent, still
/// firmly bounded for a localhost daemon and well short of anything an
/// attacker could stretch this out to by sending more (any amount of)
/// traffic.
const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(REQUEST_TIMEOUT.as_secs() * 2);

/// Wraps a `TcpListener` so every accepted connection is gated by a shared
/// semaphore *before* the accept -- see this module's doc comment.
pub struct ConnLimitedListener {
    inner: TcpListener,
    slots: Arc<Semaphore>,
}

impl ConnLimitedListener {
    pub fn new(inner: TcpListener, slots: Arc<Semaphore>) -> Self {
        Self { inner, slots }
    }
}

impl Listener for ConnLimitedListener {
    type Io = LimitedIo;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = self
                .slots
                .clone()
                .acquire_owned()
                .await
                .expect("this semaphore is never closed for the life of the listener");
            match self.inner.accept().await {
                Ok((stream, addr)) => return (LimitedIo::new(stream, permit), addr),
                Err(e) => {
                    drop(permit);
                    // Mirrors axum's own `TcpListener` `Listener` impl:
                    // log and back off rather than tearing down the whole
                    // adapter over one accept error (e.g. a transient
                    // EMFILE).
                    tracing::warn!(error = %e, "accept error on the HTTP API listener");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A `TcpStream` plus the connection-slot permit it holds and this
/// connection's rolling idle deadline -- see this module's doc comment.
pub struct LimitedIo<T = TcpStream> {
    io: T,
    /// `None` on the device path (`peer.rs`), whose streams are bounded by
    /// the daemon before they arrive; the idle deadline applies all the same.
    _permit: Option<OwnedSemaphorePermit>,
    /// Fires [`CONNECTION_IDLE_TIMEOUT`] after the most recent successful
    /// read or write on `io` (or after `accept()`, before either has
    /// happened yet). Reset -- not disarmed -- by every subsequent
    /// successful read or write; see this module's doc comment for why that
    /// distinction is the whole point.
    idle_deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<T> LimitedIo<T> {
    fn new(io: T, permit: OwnedSemaphorePermit) -> Self {
        Self::idle_only_inner(io, Some(permit))
    }

    /// The idle deadline alone, for a stream that holds no slot here.
    pub(crate) fn idle_only(io: T) -> Self {
        Self::idle_only_inner(io, None)
    }

    fn idle_only_inner(io: T, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            io,
            _permit: permit,
            idle_deadline: Box::pin(tokio::time::sleep(CONNECTION_IDLE_TIMEOUT)),
        }
    }

    /// Polls the rolling idle deadline and, if it has elapsed, returns the
    /// timeout error that tears this connection down and releases its
    /// permit. Called at the top of every `poll_read`/`poll_write` -- see
    /// this module's doc comment for why re-polling (rather than only
    /// polling once at construction) matters: it keeps this deadline's
    /// registered waker current, so a connection that goes idle after its
    /// last read/write is still woken and reaped when the deadline it was
    /// last given elapses, even if nothing else ever polls this connection
    /// again in the meantime.
    fn check_idle(&mut self, cx: &mut Context<'_>) -> Option<io::Error> {
        if self.idle_deadline.as_mut().poll(cx).is_ready() {
            return Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection idle (no read or write activity) past this adapter's idle timeout",
            ));
        }
        None
    }

    /// Pushes the idle deadline [`CONNECTION_IDLE_TIMEOUT`] out from now --
    /// called after every successful read or write. Uses `Sleep::reset`
    /// (not a fresh `sleep()`) so the same timer-wheel registration and its
    /// already-registered waker carry forward: this connection's task will
    /// still be woken correctly at the new deadline even if `check_idle` is
    /// never polled again before then (e.g. an SSE stream whose next
    /// `poll_write` is seconds away, or a plain request connection sitting
    /// on the read side waiting for the next pipelined request).
    fn reset_idle(&mut self) {
        self.idle_deadline.as_mut().reset(Instant::now() + CONNECTION_IDLE_TIMEOUT);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for LimitedIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(e) = this.check_idle(cx) {
            return Poll::Ready(Err(e));
        }
        let filled_before = buf.filled().len();
        let res = Pin::new(&mut this.io).poll_read(cx, buf);
        // `Poll::Ready(Ok(()))` with nothing newly filled is EOF (the peer
        // closed its write side), not activity -- only count it as activity
        // when at least one byte was actually read.
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > filled_before {
            this.reset_idle();
        }
        res
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for LimitedIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Checked here too, not just in `poll_read`: a connection driven
        // only via repeated writes for a while (e.g. flushing a large
        // response body with no interleaved reads) must not be able to
        // outlive its idle deadline just because nothing happened to call
        // `poll_read` again in that stretch.
        if let Some(e) = this.check_idle(cx) {
            return Poll::Ready(Err(e));
        }
        let res = Pin::new(&mut this.io).poll_write(cx, buf);
        if matches!(res, Poll::Ready(Ok(n)) if n > 0) {
            this.reset_idle();
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
