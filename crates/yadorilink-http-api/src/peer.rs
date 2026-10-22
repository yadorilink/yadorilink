//! The dashboard for a device that manages this one over its own
//! authenticated device connection.
//!
//! The daemon hands this adapter byte streams it has already authorized as
//! coming from another device on the same account. They never touch a
//! socket: they arrive through [`PeerStreams`], an in-process queue only the
//! daemon holds, and are served by the same router as the TCP listener with
//! two differences, both in `security.rs`:
//!
//! - No bearer token. The daemon's device authentication is the authority
//!   for these requests; the token exists to tell local OS users apart on
//!   the TCP listener, and a stream that arrived here did not come from one.
//!   Nothing on the TCP listener changes: it still requires the token.
//! - The browser on the managing device talks to a loopback listener of its
//!   own, on a port this adapter cannot know, so `Host` may name any port on
//!   a loopback name. It must still be a loopback name (DNS rebinding), an
//!   `Origin`, when present, must be exactly `http://` + that `Host`, and a
//!   request that can change state must carry one (cross-site requests from
//!   other pages in that browser).
//!
//! The queue closes when the dashboard stops serving, so a stream offered
//! after that is refused rather than served by anything else.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// One authorized stream: any bidirectional byte stream.
pub trait PeerIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> PeerIo for T {}

/// How many offered streams may wait for the dashboard to pick them up. As
/// many as the daemon will carry at once, so a burst within that bound is
/// never dropped for want of room.
const PEER_QUEUE: usize = 32;

/// The daemon's handle for offering authorized streams to the dashboard.
/// Cheap to clone.
#[derive(Clone, Debug)]
pub struct PeerStreams {
    tx: mpsc::Sender<Box<dyn PeerIo>>,
}

impl PeerStreams {
    /// Whether the dashboard is serving. `false` once it has stopped, for
    /// whatever reason, and never `true` again for this handle.
    pub fn is_serving(&self) -> bool {
        !self.tx.is_closed()
    }

    /// Offers one stream. `false` (and the stream dropped) when the
    /// dashboard has stopped or is not keeping up.
    pub fn offer(&self, io: Box<dyn PeerIo>) -> bool {
        self.tx.try_send(io).is_ok()
    }
}

pub(crate) fn channel() -> (PeerStreams, PeerQueue) {
    let (tx, rx) = mpsc::channel(PEER_QUEUE);
    (PeerStreams { tx }, PeerQueue { rx })
}

/// The receiving end, served by `run`.
pub(crate) struct PeerQueue {
    rx: mpsc::Receiver<Box<dyn PeerIo>>,
}

/// Serves every offered stream with `router` until this future is dropped.
///
/// Every connection runs inside this future, so `run` ending (or being
/// dropped) ends every stream it was serving, not only the queue: a stopped
/// dashboard keeps nothing open. Each stream has the TCP listener's idle
/// deadline.
pub(crate) async fn serve(mut queue: PeerQueue, router: axum::Router) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            offered = queue.rx.recv() => {
                let Some(io) = offered else {
                    // The daemon dropped its handle; serve what is open.
                    while connections.join_next().await.is_some() {}
                    return std::future::pending().await;
                };
                let service = hyper_util::service::TowerToHyperService::new(router.clone());
                let io = hyper_util::rt::TokioIo::new(crate::conn_limit::LimitedIo::idle_only(io));
                connections.spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

/// Whether `host` (a `Host` header value) names a loopback address, with
/// any port or none. Exact names only: `127.0.0.1`, `localhost`, `[::1]`.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let (name, port) = match host.rsplit_once(':') {
        // `[::1]` with no port has colons only inside the brackets.
        Some((name, port)) if !port.contains(']') => (name, Some(port)),
        _ => (host, None),
    };
    let name_ok = name == "127.0.0.1" || name.eq_ignore_ascii_case("localhost") || name == "[::1]";
    let port_ok = port.is_none_or(|port| {
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
    });
    name_ok && port_ok
}

#[cfg(test)]
mod tests {
    use super::is_loopback_host;

    #[test]
    fn loopback_names_with_any_port_are_accepted() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:1",
            "127.0.0.1:65535",
            "localhost:49152",
            "LOCALHOST:8",
            "[::1]",
            "[::1]:5000",
        ] {
            assert!(is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn anything_that_is_not_a_loopback_name_is_refused() {
        for host in [
            "",
            "evil.example",
            "evil.example:8484",
            "127.0.0.1.evil.example:80",
            "localhost.evil.example",
            "127.0.0.2:80",
            "192.168.1.10:8484",
            "0.0.0.0:8484",
            "[::]:80",
            "127.0.0.1:",
            "127.0.0.1:65536",
            "127.0.0.1:+80",
            "127.0.0.1:80:80",
            "[::1]x",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }
}
