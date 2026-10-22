//! An AIMD-style, per-peer adaptive
//! in-flight block-fetch window.
//!
//! Before this change, the number of concurrently outstanding
//! `PeerSyncSession::fetch_block` requests to one peer was a fixed
//! constant everywhere it mattered — `MAX_IN_FLIGHT_MESSAGES_PER_PEER`
//! (peer_session.rs, inbound-message concurrency bound) and
//! `PER_PEER_IN_FLIGHT_WINDOW` (yadorilink-daemon::hydration's multi-peer
//! fetch dispatcher, fixed lane count). Fast, low-RTT links never
//! got to pipeline past that fixed count; slow/lossy ones got pushed to
//! send that many requests regardless of whether the link could sustain
//! them.
//!
//! `AdaptiveWindow` replaces the *lane-count* half of that (the daemon's
//! per-candidate fetch concurrency) with a controller driven by real
//! observed conditions on this session: smoothed RTT (EWMA) and explicit
//! timeout/loss signals. It does **not** touch `MAX_IN_FLIGHT_MESSAGES_PER_PEER` —
//! that constant remains the fixed security ceiling (DoS bound
//! on *inbound* message handling) this controller's own `max` is
//! constructed to never exceed, so the adaptive window composes with,
//! rather than replaces, the existing security hardening: max never
//! exceeds the per-peer concurrency bound set by that hardening.
//!
//! Pure and synchronous (no I/O, no async) so it's directly unit-testable
//! — see the `tests` module below for the grow/shrink/ceiling/floor
//! proofs. `PeerSyncSession` (peer_session.rs) owns one instance per
//! session and feeds it real `fetch_block` outcomes; `yadorilink-daemon`'s
//! multi-peer dispatcher reads `PeerSyncSession::fetch_window` in place
//! of the old fixed lane constant.

use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

/// AIMD "AI" (additive increase) step applied to the window on every
/// `on_success` call that does *not* show RTT inflation — one more
/// concurrent in-flight request per healthy round trip, the standard
/// conservative TCP-congestion-control-style growth rate.
const ADDITIVE_INCREASE_STEP: f64 = 1.0;

/// AIMD "MD" (multiplicative decrease) factor applied on a timeout/loss
/// signal (`on_timeout`) or an RTT-inflation signal (`on_success` when the
/// new sample is much worse than the smoothed baseline) — halves the
/// window, the standard TCP-congestion-control-style back-off.
const MULTIPLICATIVE_DECREASE_FACTOR: f64 = 0.5;

/// EWMA smoothing factor for the RTT baseline: `new = old*(1-ALPHA) +
/// sample*ALPHA`. Low-ish so one noisy sample doesn't itself look like
/// "inflation" against its own freshly-updated baseline.
const RTT_EWMA_ALPHA: f64 = 0.25;

/// A fresh RTT sample counts as "inflated" (and triggers a multiplicative
/// back-off, same as an explicit timeout) once it exceeds the smoothed
/// baseline by this factor — multiplicatively backing off on
/// timeouts/loss or RTT inflation. Chosen loosely (50% worse than
/// baseline) so ordinary jitter on a real network doesn't itself look like
/// congestion; only a genuine, sustained latency increase does.
const RTT_INFLATION_FACTOR: f64 = 1.5;

/// Fallback debounce window for collapsing repeated multiplicative-
/// decrease signals into one, used until a real RTT sample exists (see
/// `WindowState::last_backoff`'s own doc comment) -- standard TCP-
/// congestion-control practice ("at most one window reduction per RTT")
/// applied here because several concurrent in-flight requests launched
/// together share one underlying congestion event: if that event causes
/// N of them to time out, treating each as an INDEPENDENT signal
/// collapses the window N times for what is really ONE episode. Confirmed
/// directly as a real bug, not a theoretical one: an initial 8-request
/// burst (`topology_simultaneous_reconnect_and_relay_hydration_failure.
/// rs`'s relay-recovery scenario) produced 4 near-simultaneous timeouts,
/// collapsing a window of 4 to its floor of 1 within a single dispatch
/// attempt -- even though the window never saw a genuinely NEW congestion
/// signal after the first. Once a real RTT sample exists, that baseline
/// -- not this fallback -- is the debounce window (the textbook choice);
/// this fixed fallback only covers the gap before any sample exists,
/// which is exactly the first-burst case above. Chosen comfortably
/// shorter than any real, separate congestion episode would need to
/// develop, but comfortably longer than how far apart several timeouts
/// from ONE simultaneous burst actually land (observed: within the same
/// polling tick of each other).
const BACKOFF_DEBOUNCE_FALLBACK: Duration = Duration::from_millis(500);

struct WindowState {
    /// Fractional so additive growth/multiplicative backoff compose
    /// smoothly across many calls instead of getting stuck at an integer
    /// step boundary — `current` rounds and clamps this to `[min, max]`
    /// for callers.
    window: f64,
    smoothed_rtt: Option<Duration>,
    /// When the most recent multiplicative decrease was actually applied
    /// -- `None` until the first one. See `BACKOFF_DEBOUNCE_FALLBACK`'s
    /// own doc comment for why repeated timeout/congestion signals within
    /// one debounce window collapse into a single backoff instead of each
    /// halving the window independently.
    last_backoff: Option<Instant>,
}

/// Per-peer AIMD in-flight window controller. `min`/`max` are fixed for
/// the controller's lifetime (`max` is clamped at construction to never
/// exceed the caller-supplied hard ceiling).
pub struct AdaptiveWindow {
    min: usize,
    max: usize,
    state: StdMutex<WindowState>,
}

impl AdaptiveWindow {
    /// `initial`/`min` are the controller's starting point and floor;
    /// `hard_ceiling` is the pre-existing, non-adaptive per-peer
    /// concurrency bound (`PeerSyncSession` passes
    /// `MAX_IN_FLIGHT_MESSAGES_PER_PEER`) that `max` is clamped to never
    /// exceed, regardless of what's passed as `max`. `initial` is itself
    /// clamped into the resulting `[min, max]` range.
    pub fn new(initial: usize, min: usize, max: usize, hard_ceiling: usize) -> Self {
        let min = min.max(1);
        let max = max.min(hard_ceiling).max(min);
        let initial = initial.clamp(min, max);
        Self {
            min,
            max,
            state: StdMutex::new(WindowState {
                window: initial as f64,
                smoothed_rtt: None,
                last_backoff: None,
            }),
        }
    }

    /// The current recommended number of concurrent in-flight requests —
    /// always within `[min, max]`, regardless of how many
    /// `on_success`/`on_timeout` calls have run.
    pub fn current(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        (state.window.round() as i64).clamp(self.min as i64, self.max as i64) as usize
    }

    /// Records a successful, answered `fetch_block` round trip and its
    /// observed latency (a smoothed RTT — an EWMA of
    /// block-request-response latency). Grows the window additively unless this
    /// sample itself shows RTT inflation relative to the smoothed
    /// baseline, in which case it backs off multiplicatively instead —
    /// the same "or RTT inflation" back-off trigger `on_timeout` also
    /// uses, just observed via latency rather than an outright missing
    /// reply.
    ///
    /// `queue_position` is how many requests to this same peer were
    /// outstanding at the moment THIS one was sent, this one included (so
    /// `1` means it had no live sibling at send time, i.e. an ISOLATED
    /// round trip).
    ///
    /// It matters because this controller's whole reason for existing is
    /// to size a PIPELINE (see this module's own doc comment): once more
    /// than one request to a peer is in flight at once, that peer's own
    /// dispatch order need not match send order at all -- confirmed
    /// directly, a real 8-request burst answered in positions
    /// `8,6,1,7,4,5,2,3` relative to send order, not the strictly serial
    /// FIFO a naive model assumes. A pipelined reply's elapsed time is
    /// therefore not attributable to any fixed share of "this request's
    /// real round trip" -- it is contaminated by however much of every
    /// OTHER concurrently in-flight request's own service time happened
    /// to land ahead of it, in an order this controller cannot recover
    /// after the fact. Reading that contaminated latency as RTT inflation
    /// used to collapse the window to `min` on the very first real
    /// multi-block transfer regardless of how healthy the link actually
    /// was -- the opposite of this controller's purpose.
    ///
    /// So a pipelined sample (`queue_position > 1`) never touches the RTT
    /// baseline and never triggers the inflation back-off -- there is no
    /// way to tell, from latency alone, whether it reflects the link or
    /// simply its siblings' own work ahead of it. It still grows the
    /// window additively: a successful reply under real concurrent load
    /// IS positive evidence this many requests in flight is sustainable,
    /// regardless of the shape of any one reply's latency. Only an
    /// ISOLATED sample (`queue_position <= 1`, no sibling in flight when
    /// it was sent) is trustworthy evidence of the link's own RTT, so
    /// only isolated samples update the smoothed baseline and can trigger
    /// the multiplicative back-off. Real degradation under concurrent
    /// load is still caught -- just via `on_timeout`/`on_congestion`
    /// (explicit loss and explicit `Busy`), which this change does not
    /// touch, rather than via inferring it from a queued reply's latency.
    pub fn on_success(&self, rtt: Duration, queue_position: usize) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if queue_position > 1 {
            // Pipelined: real success, but its latency proves nothing
            // about the link on its own (see this function's own doc
            // comment) -- grow, but leave the RTT baseline and the
            // inflation check alone.
            state.window = (state.window + ADDITIVE_INCREASE_STEP).min(self.max as f64);
            return;
        }
        let rtt_secs = rtt.as_secs_f64();
        let inflated = match state.smoothed_rtt {
            Some(baseline) if baseline.as_secs_f64() > 0.0 => {
                rtt_secs > baseline.as_secs_f64() * RTT_INFLATION_FACTOR
            }
            // No baseline yet (first sample) — nothing to compare against,
            // never treated as inflation.
            _ => false,
        };
        state.smoothed_rtt = Some(match state.smoothed_rtt {
            None => rtt,
            Some(baseline) => Duration::from_secs_f64(
                baseline.as_secs_f64() * (1.0 - RTT_EWMA_ALPHA) + rtt_secs * RTT_EWMA_ALPHA,
            ),
        });
        if inflated {
            self.apply_debounced_backoff(&mut state);
        } else {
            state.window = (state.window + ADDITIVE_INCREASE_STEP).min(self.max as f64);
        }
    }

    /// Records an explicit loss/timeout signal — a `fetch_block` request
    /// this peer never answered within the caller's own bound (see
    /// `PeerSyncSession::record_fetch_timeout`'s doc comment for why this
    /// can't be observed from inside `fetch_block` itself). Always backs
    /// off multiplicatively, floored at `min` — this controller never lets
    /// a sustained-bad-link peer starve completely (still bounded below,
    /// not just above).
    pub fn on_timeout(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.apply_debounced_backoff(&mut state);
    }

    /// Records an explicit congestion signal that is neither a healthy
    /// round trip nor an outright timeout/loss — specifically,
    /// `FetchOutcome::Busy`: the peer DID answer, quickly, but said its own
    /// serve queue is over capacity right now. Backs off multiplicatively
    /// like `on_timeout`, but does NOT touch the smoothed RTT baseline
    /// (there is no meaningful "round trip time" for a request the peer
    /// never actually served) — `on_success` must never be called for this
    /// outcome: a fast `Busy` reply is not evidence the link/peer can
    /// sustain more concurrent requests, it's the opposite, and treating
    /// it as a successful round trip would grow the window into exactly
    /// the congestion `Busy` is reporting (fast Busy -> looks like a
    /// healthy RTT -> window grows -> more requests sent -> more Busy).
    pub fn on_congestion(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.apply_debounced_backoff(&mut state);
    }

    /// Applies one multiplicative decrease, unless a backoff already
    /// landed within the current debounce window (the smoothed RTT once
    /// known, `BACKOFF_DEBOUNCE_FALLBACK` before that) -- see
    /// `WindowState::last_backoff` and `BACKOFF_DEBOUNCE_FALLBACK`'s own
    /// doc comments for why. Debounced calls are a deliberate no-op: they
    /// still represent real signals (the peer/link genuinely is
    /// congested), just not NEW evidence beyond what the most recent
    /// backoff already accounted for.
    fn apply_debounced_backoff(&self, state: &mut WindowState) {
        let debounce_window = state.smoothed_rtt.unwrap_or(BACKOFF_DEBOUNCE_FALLBACK);
        let debounced = state.last_backoff.is_some_and(|last| last.elapsed() < debounce_window);
        if debounced {
            return;
        }
        state.window = (state.window * MULTIPLICATIVE_DECREASE_FACTOR).max(self.min as f64);
        state.last_backoff = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests;
