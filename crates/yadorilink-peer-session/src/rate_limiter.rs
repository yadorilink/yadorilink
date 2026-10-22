//! A token-bucket rate limiter gating block payload bytes at the
//! sync-session/transfer layer — deliberately *not* inside
//! `yadorilink-transport` (a transport-level limiter can't distinguish
//! block payload bytes from keepalives/handshakes/relay control frames
//! without protocol-aware
//! inspection, and throttling those risks destabilizing the tunnel for a
//! problem that's really about payload volume).
//!
//! Two independent buckets (upload, download) are constructed once by the
//! daemon (`RateLimiters::unlimited`, then reconfigured from governance
//! config) and shared, via `Arc`, across every `PeerSyncSession` for a
//! given device — so concurrent per-peer block transfers, and the daemon's
//! multi-peer hydration dispatcher (which calls `PeerSyncSession::fetch_block`
//! directly, the same single choke point this module gates), all draw down
//! one global ceiling rather than each session/peer getting its own
//! full-rate allowance.
//!
//! `0` bytes/sec means unlimited: `acquire` takes a fast path of a single
//! relaxed atomic load and returns immediately without ever touching the
//! bucket's `Mutex`, so the default (unlimited) configuration imposes no
//! measurable delay on the hot block-transfer path.
//!
//! Rates are live-reloadable: `set_rate_bytes_per_sec` updates
//! the same atomic `acquire` reads from, so a rate change is visible to the
//! very next `acquire` call — including a call already sleeping, awaiting
//! refill, when the change lands — with no daemon restart and no
//! per-session replumbing (as long as every session shares the same
//! `Arc<TokenBucket>`, which `RateLimiters` guarantees).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

/// How recent a window `TokenBucket::current_rate_bytes_per_sec`
/// averages over — short enough that `yadorilink status` reflects genuinely
/// *current* activity (not an all-time average since daemon start, which
/// would understate an ongoing burst after a long idle period), long enough
/// that a handful of back-to-back small blocks don't make the reported rate
/// swing wildly between samples.
const MEASURED_RATE_WINDOW: Duration = Duration::from_secs(5);

/// A byte-denominated token bucket. `rate_bytes_per_sec == 0` means
/// unlimited (bypassed entirely).
pub struct TokenBucket {
    rate_bytes_per_sec: AtomicU64,
    state: StdMutex<BucketState>,
    measured: StdMutex<MeasuredRate>,
}

struct BucketState {
    /// Tokens currently available, in bytes. Never exceeds one second's
    /// worth of the configured rate (the bucket's capacity), so a long idle
    /// period can't let it accumulate an unbounded burst allowance.
    available: f64,
    last_refill: Instant,
}

/// A simple trailing-window byte counter, independent of the
/// rate-limiting bucket state above — tracks real throughput for
/// `yadorilink status` regardless of whether a limit is even configured
/// (an unlimited transfer still has a real, worth-reporting current rate).
struct MeasuredRate {
    window_start: Instant,
    bytes_in_window: u64,
}

impl TokenBucket {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        Self {
            rate_bytes_per_sec: AtomicU64::new(rate_bytes_per_sec),
            state: StdMutex::new(BucketState {
                available: rate_bytes_per_sec as f64,
                last_refill: Instant::now(),
            }),
            measured: StdMutex::new(MeasuredRate {
                window_start: Instant::now(),
                bytes_in_window: 0,
            }),
        }
    }

    pub fn unlimited() -> Self {
        Self::new(0)
    }

    /// Bytes/sec transferred through this bucket in roughly
    /// the last `MEASURED_RATE_WINDOW` — independent of the configured
    /// rate limit (tracked even when unlimited). Not itself gated by
    /// `acquire`'s zero-overhead bypass: this is a separate, deliberately
    /// lightweight (single mutex, no allocation) counter. The
    /// "zero overhead" refers to the *throttling* behavior, not this O(1)
    /// bookkeeping addition.
    pub fn current_rate_bytes_per_sec(&self) -> u64 {
        let m = self.measured.lock().unwrap_or_else(|p| p.into_inner());
        let elapsed = m.window_start.elapsed().as_secs_f64().max(0.001);
        (m.bytes_in_window as f64 / elapsed) as u64
    }

    fn record_measured_bytes(&self, bytes: u64) {
        let mut m = self.measured.lock().unwrap_or_else(|p| p.into_inner());
        if m.window_start.elapsed() > MEASURED_RATE_WINDOW {
            m.window_start = Instant::now();
            m.bytes_in_window = 0;
        }
        m.bytes_in_window += bytes;
    }

    /// live-reload, applied to every `acquire` call — including
    /// transfers already awaiting a refill — from this point on, no
    /// reconstruction or per-session replumbing needed.
    pub fn set_rate_bytes_per_sec(&self, rate: u64) {
        self.rate_bytes_per_sec.store(rate, Ordering::Relaxed);
    }

    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.rate_bytes_per_sec.load(Ordering::Relaxed)
    }

    /// Consumes `bytes` worth of tokens, awaiting bucket refill if none are
    /// currently available. A no-op (immediate return, no lock taken) when
    /// the configured rate is `0` (unlimited).
    pub async fn acquire(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }
        // Recorded unconditionally, including the unlimited
        // (rate == 0) fast path below — a bucket with no configured limit
        // still has a real current transfer rate worth reporting.
        self.record_measured_bytes(bytes);
        loop {
            // Re-read the rate on every loop iteration (not just once at
            // entry) so a rate change applied mid-wait is
            // honored on the very next refill computation.
            let rate = self.rate_bytes_per_sec.load(Ordering::Relaxed);
            if rate == 0 {
                return;
            }
            let wait = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                state.last_refill = now;
                // The nominal capacity is one second's worth of the
                // configured rate (the burst allowance) — but a *single*
                // request for more than that (a real, expected case: a
                // whole block payload can be tens of MB while a configured
                // rate can be a few KB/sec for a metered connection) must
                // still eventually succeed, not deadlock forever, since
                // `available` would otherwise never be allowed to climb
                // high enough to satisfy it. Widening the cap to
                // `bytes` for *this* acquire only (not persisted beyond
                // this call) lets `available` accumulate exactly enough to
                // satisfy an oversized request, converging to the correct
                // `(bytes - starting available) / rate` wait, while still
                // capping ordinary (smaller-than-capacity) requests at the
                // normal one-second burst.
                let capacity = (rate as f64).max(bytes as f64);
                state.available = (state.available + elapsed * rate as f64).min(capacity);
                if state.available >= bytes as f64 {
                    state.available -= bytes as f64;
                    None
                } else {
                    let deficit = bytes as f64 - state.available;
                    Some(Duration::from_secs_f64(deficit / rate as f64))
                }
            };
            match wait {
                None => return,
                Some(d) => {
                    // Cap each individual sleep so a live rate change
                    // iteration's rate re-read within a bounded interval,
                    // rather than only after however long the deficit
                    // implied under the *old* rate would have taken.
                    let capped = d.clamp(Duration::from_millis(1), Duration::from_millis(100));
                    tokio::time::sleep(capped).await;
                }
            }
        }
    }
}

/// The upload/download bucket pair a `PeerSyncSession` gates block transfer
/// on. `unlimited` is the default a session starts with
/// before the daemon injects its shared, config-driven pair via
/// `PeerSyncSession::set_rate_limiters`.
pub struct RateLimiters {
    pub upload: Arc<TokenBucket>,
    pub download: Arc<TokenBucket>,
}

impl RateLimiters {
    pub fn unlimited() -> Self {
        Self {
            upload: Arc::new(TokenBucket::unlimited()),
            download: Arc::new(TokenBucket::unlimited()),
        }
    }

    pub fn new(upload_bytes_per_sec: u64, download_bytes_per_sec: u64) -> Self {
        Self {
            upload: Arc::new(TokenBucket::new(upload_bytes_per_sec)),
            download: Arc::new(TokenBucket::new(download_bytes_per_sec)),
        }
    }
}

#[cfg(test)]
mod tests;
