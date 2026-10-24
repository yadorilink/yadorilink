//! A thin localhost HTTP/REST + SSE adapter in front of the daemon's
//! existing control-socket IPC (`yadorilink-ipc-proto`'s `daemonctl`
//! protocol, dispatched daemon-side by `yadorilink-daemon::control_socket`).
//! This crate adds no sync/business logic of its own -- every handler in
//! `handlers/` builds a `DaemonControlRequest`, sends it over
//! [`control_client::ControlClient`] (which dials the same control socket
//! the CLI already does, using the same framing), and translates the
//! `DaemonControlResponse` into JSON. See `handlers/mod.rs`'s module doc
//! comment for the JSON shapes and `handlers/events.rs` for why `/api/events`
//! is polling-based rather than push-based.
//!
//! # Security model
//!
//! This adapter is meant to be safely exposed on a machine with other local
//! users, or reachable from a browser that also has other tabs open, so
//! every request is checked at three independent, mandatory layers before
//! it reaches a handler -- see `security.rs` for the full reasoning:
//!
//! 1. `Host` header must name one of this adapter's own bound loopback
//!    addresses (defends against DNS rebinding).
//! 2. `Origin` header, if present, must be this adapter's own origin or an
//!    explicitly configured dev-server origin -- never a wildcard (defends
//!    against a malicious page's browser-issued cross-origin request).
//! 3. Every `/api/*` request must carry `Authorization: Bearer <token>`
//!    matching the token this daemon run generated at startup (`token.rs`).
//!
//! The token is delivered to callers (including this crate's own bundled
//! Web UI) **only** via that header -- never a cookie, and never a query
//! string. A cookie would be attached by the browser automatically to
//! *any* request to this origin, including one triggered by a malicious
//! cross-origin page, which is exactly the CSRF vector layer 3 exists to
//! close; a query string ends up in browser history, proxy/server access
//! logs, and the `Referer` header of any same-origin link the page
//! navigates to next. `handlers/events.rs`'s own doc comment explains why
//! this also rules out the browser's native `EventSource` API for
//! `/api/events` (it has no way to attach a header) -- this crate's bundled
//! Web UI (`webui.rs`) instead reads that endpoint with a plain
//! `fetch()` and parses the `text/event-stream` framing itself.
//!
//! Binding is loopback-only and not configurable past that: [`bind`] always
//! binds `127.0.0.1`, and best-effort also `[::1]` (a failure to bind the
//! IPv6 side -- e.g. no IPv6 support on the host -- is logged and does not
//! prevent serving on IPv4). There is no code path in this crate that binds
//! any other interface.
//!
//! A failed `[::1]` bind is more than a missing feature, though: `localhost`
//! resolves to `[::1]` first on many systems, so if some OTHER local process
//! grabs `[::1]:<port>` before this one starts, that other process -- not
//! this adapter -- is what a browser reaches by navigating to
//! `http://localhost:<port>`, at an origin this adapter's own Origin check
//! would otherwise treat as trusted, and that a browser's `localStorage`
//! treats as the SAME storage bucket the bundled Web UI persists its bearer
//! token into regardless of which process currently answers there. [`bind`]
//! only adds `localhost`/`[::1]` to `AppState::allowed_hosts`/
//! `allowed_origins` when the `[::1]` bind actually succeeded -- i.e. only
//! when this process can actually back up trusting that identity.

pub mod config;
mod conn_limit;
pub mod control_client;
pub mod error;
pub mod handlers;
mod peer;
pub mod security;
pub mod token;
mod webui;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

use conn_limit::ConnLimitedListener;

pub use config::HttpApiConfig;
use control_client::ControlClient;
pub use peer::{PeerIo, PeerStreams};

/// File name of [`HttpApiConfig::token_path`] inside the daemon's state
/// directory.
pub const TOKEN_FILE_NAME: &str = "http-api-token";
/// File name of [`HttpApiConfig::port_path`] inside the daemon's state
/// directory. The CLI reads it under the same name.
pub const PORT_FILE_NAME: &str = "http-api-port";

/// Shared, cheaply-cloneable state every handler and middleware function
/// gets via axum's `State` extractor.
#[derive(Clone)]
pub struct AppState {
    pub control: ControlClient,
    /// This run's bearer token. `Arc<str>` (not `String`) because it's
    /// cloned into every request's state and never mutated after startup.
    pub token: Arc<str>,
    /// Exact `Host` header values this adapter accepts (`security.rs`).
    pub allowed_hosts: Arc<Vec<String>>,
    /// Exact `Origin` header values this adapter accepts (`security.rs`).
    pub allowed_origins: Arc<Vec<String>>,
    /// Bounds how many `/api/events` SSE streams can be open at once --
    /// see `handlers::events`'s own module doc comment for why this exists
    /// independent of that handler's disconnect-detection fix: even with
    /// prompt cleanup, a burst of concurrent connections should have a hard
    /// ceiling on the resulting control-socket polling load.
    pub sse_slots: Arc<Semaphore>,
    /// Which door this request came through -- see [`Access`].
    pub access: Access,
}

/// How a request reached this adapter, which decides what `security.rs`
/// asks of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// The loopback TCP listener: any local OS user can connect, so the
    /// bearer token is required and `Host` must name this listener exactly.
    LocalTcp,
    /// A stream the daemon authorized as another device on the same account
    /// (see `peer.rs`): no token, `Host` may be any loopback name and port.
    Peer,
}

/// The result of [`bind`]: listeners are already open (so the real port is
/// known even when `HttpApiConfig::port == 0` requested an ephemeral one)
/// and the token is already generated and written to disk, but nothing is
/// being served yet -- that starts with [`run`]. Split this way so a caller
/// (production `app.rs`, or a test) can log/use the bound port and token
/// before the (non-returning, until shutdown) serve loop starts.
pub struct HttpApiHandle {
    /// The TCP port bound on both `127.0.0.1` and (best-effort) `[::1]`.
    pub port: u16,
    /// This run's bearer token, also already written to
    /// `HttpApiConfig::token_path`.
    pub token: String,
    router: Router,
    listeners: Vec<TcpListener>,
    /// Bounds total concurrent connections across every listener -- see
    /// `conn_limit`'s own module doc comment for why this is a *connection*
    /// admission gate, applied before `accept(2)`, rather than a
    /// request-level middleware. Not test-only, unlike `sse_slots`: `run`
    /// needs this unconditionally to build each listener's
    /// `ConnLimitedListener`.
    conn_slots: Arc<Semaphore>,
    /// `HttpApiConfig::port_path` and the exact contents written to it,
    /// removed again when `run` ends.
    port_path: std::path::PathBuf,
    port_file: String,
    /// The same routes for streams the daemon authorized (`peer.rs`).
    peer_router: Router,
    peer_queue: peer::PeerQueue,
    peer_streams: PeerStreams,
    #[cfg(any(test, feature = "test-support"))]
    sse_slots: Arc<Semaphore>,
}

/// Removes the port file when the serving future ends, however it ends
/// (an error, or the task being dropped), so the file never names a port
/// nobody is listening on while the daemon itself keeps running. It is
/// declared before the listeners in `run`, so it drops right after they
/// close, and it removes the file only while it still holds this run's
/// exact contents (port and per-run nonce): a newer daemon that already
/// wrote its own file keeps it, even when it bound the same port.
struct PortFileGuard {
    path: std::path::PathBuf,
    contents: String,
}

impl Drop for PortFileGuard {
    fn drop(&mut self) {
        let ours = std::fs::read_to_string(&self.path).is_ok_and(|text| text == self.contents);
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bounds concurrent `/api/events` SSE streams -- see `AppState::sse_slots`'s
/// own doc comment. Generous for the intended handful of browser tabs on a
/// personal dashboard, while still bounding worst-case control-socket
/// polling load.
const MAX_CONCURRENT_SSE_STREAMS: usize = 32;

/// Binds the configured port on `127.0.0.1` (mandatory) and `[::1]`
/// (best-effort), then generates and stores a fresh bearer token. Never
/// binds any other interface.
///
/// Binding before generating/writing the token (not the other way around)
/// is deliberate: if the mandatory `127.0.0.1` bind fails, this returns an
/// error before any token file exists, rather than leaving a stale,
/// valid-looking token on disk for an adapter that never actually starts
/// serving.
pub async fn bind(config: &HttpApiConfig) -> anyhow::Result<HttpApiHandle> {
    #[cfg(unix)]
    let control = ControlClient::new(config.control_socket_path.clone());
    #[cfg(windows)]
    let control = ControlClient::new(config.control_pipe_name.clone());

    let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.port);
    let v4_listener = TcpListener::bind(v4_addr)
        .await
        .with_context(|| format!("failed to bind {v4_addr} for the HTTP API"))?;
    // `local_addr()` resolves `port: 0` to whatever the OS actually
    // assigned; every allowlist and the second (IPv6) bind below use this
    // resolved value, never the possibly-`0` configured one.
    let bound_port = v4_listener.local_addr()?.port();

    let mut listeners = vec![v4_listener];
    let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), bound_port);
    // Whether this process actually owns `[::1]:<port>` -- see this module's
    // own doc comment for why the `localhost`/`[::1]` allowlist entries
    // below are conditioned on this rather than added unconditionally.
    let v6_bound = match TcpListener::bind(v6_addr).await {
        Ok(listener) => {
            listeners.push(listener);
            true
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "failed to bind [::1] for the HTTP API; continuing on 127.0.0.1 only -- \
                 the `localhost`/[::1] hostnames will NOT be trusted by the Host/Origin \
                 checks while this holds, since this process cannot vouch that it is what \
                 `localhost` resolves to on this host (another local process may be \
                 holding [::1] on this port)"
            );
            false
        }
    };

    let mut allowed_hosts = vec![format!("127.0.0.1:{bound_port}")];
    let mut allowed_origins = vec![format!("http://127.0.0.1:{bound_port}")];
    if v6_bound {
        allowed_hosts.push(format!("localhost:{bound_port}"));
        allowed_hosts.push(format!("[::1]:{bound_port}"));
        allowed_origins.push(format!("http://localhost:{bound_port}"));
        allowed_origins.push(format!("http://[::1]:{bound_port}"));
    }
    allowed_origins.extend(config.extra_allowed_origins.iter().cloned());

    let token = token::generate();
    token::write_token_file(&config.token_path, &token).with_context(|| {
        format!("failed to write HTTP API token to {}", config.token_path.display())
    })?;

    // Line 1 is the port (all `web status` reads); line 2 is a per-run nonce
    // so this run's guard removes only its own file. Written to a temp file
    // with the same owner-only writer as the token, then renamed into place,
    // so a reader never sees a partial file.
    let port_file = format!("{bound_port}\n{}\n", token::random_hex(8));
    let tmp_path = config.port_path.with_extension("tmp");
    token::write_token_file(&tmp_path, &port_file)
        .and_then(|()| std::fs::rename(&tmp_path, &config.port_path))
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp_path);
        })
        .with_context(|| {
            format!("failed to write HTTP API port to {}", config.port_path.display())
        })?;

    let sse_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_SSE_STREAMS));
    let state = AppState {
        control,
        token: Arc::from(token.as_str()),
        allowed_hosts: Arc::new(allowed_hosts),
        allowed_origins: Arc::new(allowed_origins),
        sse_slots: sse_slots.clone(),
        access: Access::LocalTcp,
    };
    let peer_state = AppState { access: Access::Peer, ..state.clone() };
    let (peer_streams, peer_queue) = peer::channel();

    let conn_slots = Arc::new(Semaphore::new(conn_limit::MAX_CONCURRENT_CONNECTIONS));

    Ok(HttpApiHandle {
        port: bound_port,
        token,
        router: build_router(state),
        listeners,
        conn_slots,
        port_path: config.port_path.clone(),
        port_file,
        peer_router: build_router(peer_state),
        peer_queue,
        peer_streams,
        #[cfg(any(test, feature = "test-support"))]
        sse_slots,
    })
}

impl HttpApiHandle {
    /// Where the daemon offers streams it has authorized as another device
    /// on the same account. Take it before `run`; it reports not serving
    /// once `run` has ended.
    pub fn peer_streams(&self) -> PeerStreams {
        self.peer_streams.clone()
    }

    /// Every address actually bound. Exists mainly so a test can assert,
    /// against the real listener the OS handed back -- not just by reading
    /// this crate's source and trusting it -- that this adapter genuinely
    /// never binds anything but a loopback address.
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.listeners.iter().filter_map(|l| l.local_addr().ok()).collect()
    }

    /// A clone of this run's `AppState::sse_slots`. Test-only: `run`
    /// consumes `self` by value (the listeners it serves on cannot be
    /// cloned), so a test that wants to keep observing
    /// `available_permits()` after spawning `run` needs its own `Arc`
    /// clone of the same semaphore taken before that move -- this lets a
    /// regression test confirm a `/api/events` poller task actually exits
    /// (and releases its slot) after its client disconnects, rather than
    /// inferring it indirectly.
    #[cfg(any(test, feature = "test-support"))]
    pub fn sse_slots_for_test(&self) -> Arc<Semaphore> {
        self.sse_slots.clone()
    }

    /// A clone of this run's connection-admission semaphore
    /// (`conn_limit::MAX_CONCURRENT_CONNECTIONS` permits) -- lets a
    /// regression test confirm a flood of unauthenticated, silent
    /// connections is bounded at the connection level rather than
    /// inferring it from process-wide fd/CPU usage.
    #[cfg(any(test, feature = "test-support"))]
    pub fn conn_slots_for_test(&self) -> Arc<Semaphore> {
        self.conn_slots.clone()
    }
}

/// Serves forever (until every listener's accept loop errors out, or the
/// process is torn down around it). Meant to be spawned as a background
/// task by the caller -- see `yadorilink-daemon`'s `app.rs`, which spawns
/// this the same non-essential, best-effort way it already spawns e.g.
/// NAT-traversal (`crate::supervise::spawn_logged`): a failure here should
/// not take down folder sync.
pub async fn run(handle: HttpApiHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let HttpApiHandle {
        router,
        listeners,
        conn_slots,
        port_path,
        port_file,
        peer_router,
        peer_queue,
        ..
    } = handle;
    let _port_file = PortFileGuard { path: port_path, contents: port_file };
    let mut tasks = tokio::task::JoinSet::new();
    // Ends only with `run`: when `run` returns or is dropped, this task and
    // its receiver go with it, which is what tells the daemon the dashboard
    // stopped (`PeerStreams::is_serving`).
    tasks.spawn(async move {
        peer::serve(peer_queue, peer_router).await;
        Ok(())
    });
    for listener in listeners {
        let router = router.clone();
        // Every accepted connection on every listener shares one
        // process-wide connection budget -- see `conn_limit`'s own module
        // doc comment for why this admission gate has to sit at the
        // listener level rather than as request-level middleware.
        let listener = ConnLimitedListener::new(listener, conn_slots.clone());
        tasks.spawn(async move { axum::serve(listener, router).await });
    }
    while let Some(res) = tasks.join_next().await {
        res??;
    }
    Ok(())
}

/// Bounds how many requests this adapter is concurrently processing at
/// once, independent of `conn_limit::MAX_CONCURRENT_CONNECTIONS`'s
/// connection-level cap: this one runs as request-level middleware (after a
/// request has already been fully parsed off some connection), protecting
/// the daemon's own control socket from a burst of concurrent
/// already-parsed requests rather than bounding raw connection/task/fd
/// count. Lower than the connection cap since one connection issues
/// requests one at a time in the common case (this workspace's control
/// socket is one-request-per-connection itself, so each in-flight HTTP
/// request here holds at most one outstanding control-socket round trip).
const MAX_CONCURRENT_REQUESTS: usize = 128;

/// How long a request may take from being *actively processed* (i.e. once
/// `ConcurrencyLimitLayer` has already let it through) to a response being
/// produced, before this adapter gives up and returns `408 Request Timeout`
/// itself, dropping the connection. This is a backstop for a hung
/// control-socket round trip only (see `control_client.rs`'s own timeout
/// for the primary defense) -- `tower`'s `Timeout` middleware is the OUTER
/// of the two in the layer stack below (`.layer(Timeout)` is applied after
/// `.layer(ConcurrencyLimit)`, so the resulting service is
/// `Timeout<ConcurrencyLimit<Router>>`), and its clock starts only once a
/// request has actually been dispatched to the inner service, so time
/// spent queued behind `MAX_CONCURRENT_REQUESTS` is *not* covered by this
/// timer (traced through `tower_http` 0.7.1's `Timeout::poll_ready`,
/// which just delegates to `ConcurrencyLimit`'s own `poll_ready`, and
/// hyper-util's `TowerToHyperService`, which drives readiness via
/// `Oneshot` before `Timeout::call` ever starts sleeping).
/// Queue time is still practically bounded in the common case (each
/// in-flight request holds at most one control-socket round trip, and that
/// round trip has its own timeout), just not by this constant. Generous
/// enough to never fire for this adapter's normal request shapes (a single
/// control-socket round trip), tight enough to still bound worst-case
/// per-request resource pinning once a request is actually being worked on.
///
/// This queue time is also not bounded by `conn_limit`'s connection-level
/// idle timeout in the way that timeout's own doc comment might suggest --
/// see that comment's note on the assumption it actually depends on
/// (`queue_delay + active_processing < CONNECTION_IDLE_TIMEOUT`), which is
/// not independently enforced anywhere.
///
/// `conn_limit`'s connection-level idle timeout is deliberately derived from
/// this constant (a flat multiple of it) rather than chosen independently --
/// see that module's own doc comment for why a request that's genuinely
/// still within this bound must never have its raw connection torn down out
/// from under it before this layer gets a chance to write its own `408`.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/status", get(handlers::reads::status))
        .route("/links", get(handlers::reads::links))
        .route("/conflicts", get(handlers::reads::conflicts))
        .route("/connections", get(handlers::reads::connections))
        .route("/versions", get(handlers::reads::versions))
        .route("/materialization", get(handlers::reads::materialization))
        .route("/events", get(handlers::events::events))
        .route("/pause", post(handlers::writes::pause))
        .route("/resume", post(handlers::writes::resume))
        .route("/readopt", post(handlers::writes::readopt))
        .route("/evict", post(handlers::writes::evict))
        .route("/restore", post(handlers::writes::restore))
        .route("/update/check", post(handlers::writes::update_check))
        .route("/link/preflight", post(handlers::linking::preflight))
        .route("/link", post(handlers::linking::link))
        .route("/share/create", post(handlers::linking::create))
        .route("/share/join", post(handlers::linking::join))
        .route("/invite/accept", post(handlers::linking::accept_invite))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::require_bearer_token,
        ));

    // `.layer(...)` (not `.route_layer`) for Host/Origin/headers/concurrency/
    // timeout: these must run for *every* request this adapter ever
    // answers, including the static Web UI at `/` and axum's own 404
    // fallback for an unmatched path -- `route_layer` would skip both. The
    // LAST `.layer()` call is the OUTERMOST wrapper: it runs first on the
    // way in (so Host is checked before Origin) and, symmetrically, last on
    // the way out -- which is exactly why `add_security_headers` is added
    // last: it must still post-process a response an inner layer already
    // rejected (a 401/403 needs `Cache-Control: no-store` too), not just a
    // handler's own 200. `ConcurrencyLimitLayer`/`TimeoutLayer` sit between
    // the Host/Origin checks and `add_security_headers` for the same
    // reason: a request that trips the timeout still needs its response
    // security-headered. These two are a request-level backstop only --
    // see `conn_limit`'s own module doc comment for the connection-level
    // admission gate that actually bounds raw, never-completed connections
    // (this middleware only ever runs once a request has been fully
    // parsed).
    Router::new()
        .route("/", get(webui::index))
        .nest("/api", api)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::require_allowed_origin,
        ))
        .layer(axum::middleware::from_fn_with_state(state.clone(), security::require_known_host))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, REQUEST_TIMEOUT))
        .layer(axum::middleware::from_fn(security::add_security_headers))
        .with_state(state)
}
