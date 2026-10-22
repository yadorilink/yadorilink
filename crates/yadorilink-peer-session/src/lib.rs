//! The peer-to-peer sync protocol driver: timeout/retry/backpressure,
//! compression, bounded reconcile concurrency, and block serve/request
//! orchestration with one peer over that peer's stream lanes.

pub mod adaptive_window;
pub mod block_serve;
pub mod convergence_driver;
pub mod custody_diag;
pub mod error;
pub mod hazard;
pub mod peer_session;
pub mod ports;
pub mod rate_limiter;
pub mod service_rpc;

pub use error::PeerSessionError;

/// DST-only targeted trace: set `DST_TRACE_PATH=<exact sync path>` to get
/// stderr tracing of every write-side decision touching exactly that path.
/// Zero-cost when the variable is unset (one `OnceLock` read and a pointer
/// compare per call site).
pub fn dst_trace(path: &str, msg: impl FnOnce() -> String) {
    if dst_trace_enabled(path) {
        eprintln!("[DSTTRACE {path}] {}", msg());
    }
}

/// Whether `DST_TRACE_PATH` selects `path`. See `dst_trace`'s doc comment.
pub fn dst_trace_enabled(path: &str) -> bool {
    static TRACED: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let traced = TRACED.get_or_init(|| std::env::var("DST_TRACE_PATH").ok());
    match traced.as_deref() {
        None => false,
        Some("*") => true,
        Some(spec) => spec.split(',').any(|candidate| candidate.trim() == path),
    }
}
