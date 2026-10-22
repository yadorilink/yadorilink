#![cfg(test)]

use super::*;

#[test]
fn starts_at_the_clamped_initial_value() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    assert_eq!(w.current(), 4);
}

#[test]
fn initial_above_max_is_clamped_down_at_construction() {
    let w = AdaptiveWindow::new(999, 1, 64, 64);
    assert_eq!(w.current(), 64);
}

#[test]
fn max_is_clamped_to_the_hard_ceiling_even_if_a_larger_max_is_requested() {
    // A caller-requested `max` above the pre-existing hard security
    // ceiling never actually takes effect.
    let w = AdaptiveWindow::new(4, 1, 1_000_000, /* hard_ceiling */ 64);
    assert_eq!(w.max, 64);
}

/// Additively grows the in-flight window while RTT is
/// stable, clamped to [min, max]. Real proof, not just the math in
/// isolation: repeated fast, stable-RTT successes must move the
/// window up, one step at a time, and never past `max` even under a
/// long burst of perfect conditions.
#[test]
fn grows_additively_under_repeated_low_stable_rtt_and_never_exceeds_the_ceiling() {
    let ceiling = 64;
    let w = AdaptiveWindow::new(4, 1, ceiling, ceiling);
    let before = w.current();
    for _ in 0..5 {
        w.on_success(Duration::from_millis(10), 1);
    }
    let after_five = w.current();
    assert!(after_five > before, "window should have grown: {before} -> {after_five}");

    // A long burst of perfect, identical-RTT conditions — proves the
    // ceiling holds even under sustained "ideal" input, not just a
    // handful of samples.
    for _ in 0..500 {
        w.on_success(Duration::from_millis(10), 1);
    }
    assert!(
        w.current() <= ceiling,
        "adaptive window must never exceed the pre-existing hard concurrency ceiling, got {}",
        w.current()
    );
    assert_eq!(w.current(), ceiling, "sustained perfect conditions should saturate at the ceiling");
}

/// Multiplicatively backs off on timeouts/loss. Real
/// proof: grow the window under good conditions, then inject
/// timeouts (simulating packet loss / an unresponsive peer) and show
/// the window actually shrinks, floored at `min`.
///
/// Each injected timeout is spaced past the debounce window (see
/// `apply_debounced_backoff`'s own doc comment): this test is about
/// SEPARATE, real congestion episodes over time, distinct from
/// `repeated_timeouts_from_one_burst_collapse_to_a_single_backoff`
/// below, which specifically proves several timeouts arriving
/// together do NOT each apply their own backoff.
#[test]
fn shrinks_multiplicatively_on_injected_timeouts_and_floors_at_min() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    for _ in 0..20 {
        w.on_success(Duration::from_millis(10), 1);
    }
    let grown = w.current();
    assert!(grown > 4, "should have grown from the initial 4 first, got {grown}");

    // The growth phase above established a ~10ms smoothed RTT, which
    // `on_timeout` itself never touches but which IS what the
    // debounce window reads -- so a real gap comfortably above 10ms
    // between calls is enough for each to count as a separate episode.
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(20));
        w.on_timeout();
    }
    let shrunk = w.current();
    assert!(
        shrunk < grown,
        "window should have shrunk under sustained timeouts: {grown} -> {shrunk}"
    );
    assert_eq!(shrunk, 1, "sustained loss should floor the window at min, got {shrunk}");
}

/// R3g: several concurrent requests launched together share ONE
/// underlying congestion event -- if that event causes more than one
/// of them to time out, each `on_timeout` call is a signal about the
/// SAME episode, not independent evidence of repeated NEW congestion.
/// Confirmed as a real bug, not a theoretical one: an initial 8-
/// request burst produced 4 near-simultaneous timeouts, collapsing a
/// window of 4 to its floor of 1 within a single dispatch attempt
/// (`topology_simultaneous_reconnect_and_relay_hydration_failure.rs`'s
/// relay-recovery scenario).
#[test]
fn repeated_timeouts_from_one_burst_collapse_to_a_single_backoff() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    // No RTT baseline yet (`on_timeout` never sets one), so the
    // debounce window is `BACKOFF_DEBOUNCE_FALLBACK` -- these 4 calls,
    // fired back-to-back with no delay, land well inside it.
    for _ in 0..4 {
        w.on_timeout();
    }
    assert_eq!(
        w.current(),
        2,
        "4 near-simultaneous timeouts from one burst must apply exactly one halving \
         (4 -> 2), not one independent halving per signal (which would floor to 1)"
    );
}

/// The debounce window is not a permanent latch: once it genuinely
/// elapses, the NEXT timeout is treated as a new episode and backs
/// off again.
#[test]
fn a_timeout_after_the_debounce_window_elapses_applies_a_new_backoff() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    w.on_timeout();
    assert_eq!(w.current(), 2, "first timeout must apply its own halving");
    std::thread::sleep(BACKOFF_DEBOUNCE_FALLBACK + Duration::from_millis(50));
    w.on_timeout();
    assert_eq!(w.current(), 1, "a timeout genuinely after the debounce window must back off again");
}

/// Regression: `Busy` (an explicit, fast congestion signal -- see
/// `on_congestion`'s own doc comment for why this must never reach
/// `on_success`) must shrink the window like a timeout, not grow it
/// like a healthy round trip. Confirmed via repeated `on_congestion`
/// calls specifically (not `on_timeout`) so this test would catch a
/// regression that routed `Busy` through the wrong method even if
/// `on_timeout` itself stayed correct.
///
/// Spaced past the debounce window for the same reason `shrinks_
/// multiplicatively_on_injected_timeouts_and_floors_at_min` is -- see
/// that test's own doc comment.
#[test]
fn on_congestion_shrinks_multiplicatively_and_never_grows_the_window() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    for _ in 0..20 {
        w.on_success(Duration::from_millis(10), 1);
    }
    let grown = w.current();
    assert!(grown > 4, "should have grown from the initial 4 first, got {grown}");

    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(20));
        w.on_congestion();
    }
    let shrunk = w.current();
    assert!(
        shrunk < grown,
        "window should have shrunk under sustained Busy congestion signals: {grown} -> {shrunk}"
    );
    assert_eq!(shrunk, 1, "sustained Busy should floor the window at min, got {shrunk}");
}

/// `on_congestion` must never grow the window even from a single call
/// at the floor -- distinguishes it from `on_success`, which would
/// grow from `min` on its very first call.
#[test]
fn on_congestion_never_grows_the_window_even_a_single_call() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    let before = w.current();
    w.on_congestion();
    assert!(
        w.current() <= before,
        "a single Busy congestion signal must never grow the window: {before} -> {}",
        w.current()
    );
}

/// Backs off on RTT inflation too, not just an
/// outright missing reply — a real degraded-but-still-answering link
/// (rising latency, no explicit loss/timeout) must still shrink the
/// window.
#[test]
fn shrinks_on_rtt_inflation_without_any_explicit_timeout() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    for _ in 0..10 {
        w.on_success(Duration::from_millis(10), 1);
    }
    let grown = w.current();
    assert!(grown > 4);

    // Same peer, same session — no timeouts at all, but every
    // round trip is now several times slower than the established
    // baseline (RTT inflation, not loss).
    for _ in 0..10 {
        w.on_success(Duration::from_millis(200), 1);
    }
    assert!(
        w.current() < grown,
        "RTT inflation alone (no explicit timeout) should still shrink the window: {grown} -> {}",
        w.current()
    );
}

/// Regression: a healthy link served through a deep, REAL pipeline
/// (replies arriving out of send order, not the strictly serial FIFO a
/// naive model would assume) must not read as RTT inflation just
/// because a queued reply's own elapsed time is large. This is a real
/// captured 8-request burst, `(elapsed_us, queue_position_at_send)` in
/// actual arrival order -- notice positions arrive as `8,6,1,7,4,5,2,3`
/// relative to send order, and elapsed time does not track position at
/// all (see `on_success`'s own doc comment for how this was captured).
/// Under the naive per-reply-RTT design this controller shipped with,
/// several of these would have read as inflation and collapsed the
/// window to `min`; here every entry but the one true isolated sample
/// (`queue_position == 1`) must be treated as pipelined and grow the
/// window regardless of its own elapsed time.
#[test]
fn pipelined_replies_out_of_send_order_never_read_as_inflation() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    let before = w.current();
    const REAL_BURST: [(u64, usize); 8] = [
        (11_903, 8),
        (18_616, 6),
        (29_922, 1),
        (40_668, 7),
        (51_561, 4),
        (60_998, 5),
        (64_522, 2),
        (68_075, 3),
    ];
    for (elapsed_us, queue_position) in REAL_BURST {
        w.on_success(Duration::from_micros(elapsed_us), queue_position);
    }
    assert!(
        w.current() > before,
        "a real pipelined burst, however out of order or however large any single \
         reply's own latency, must never collapse the window: {before} -> {}",
        w.current()
    );
}

/// Complementary regression: an ISOLATED reply (`queue_position == 1`,
/// no sibling in flight at send time) is the one case where a large
/// latency IS trustworthy evidence of real degradation, and must still
/// shrink the window exactly as before this change -- otherwise this
/// fix would have traded a false-negative-proof controller (always
/// grows) for the false-positive-proof one it replaced.
#[test]
fn an_isolated_slow_reply_still_shrinks_the_window() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    for _ in 0..10 {
        w.on_success(Duration::from_millis(10), 1);
    }
    let grown = w.current();
    assert!(grown > 4);
    for _ in 0..10 {
        w.on_success(Duration::from_millis(200), 1);
    }
    assert!(
        w.current() < grown,
        "an isolated (unpipelined) slow reply must still read as RTT inflation: \
         {grown} -> {}",
        w.current()
    );
}

/// Grows and shrinks within bounds — a full
/// degrade-then-recover cycle, proving the window is not a one-way
/// ratchet in either direction.
#[test]
fn recovers_and_grows_again_after_conditions_improve() {
    let w = AdaptiveWindow::new(4, 1, 64, 64);
    for _ in 0..20 {
        w.on_success(Duration::from_millis(10), 1);
    }
    let grown = w.current();

    for _ in 0..30 {
        w.on_timeout();
    }
    let shrunk = w.current();
    assert!(shrunk < grown);

    // Conditions recover: the link answers quickly and reliably
    // again. Reset the baseline expectation implicitly via repeated
    // stable samples (the EWMA re-converges) and confirm real growth
    // resumes from the shrunk point.
    for _ in 0..40 {
        w.on_success(Duration::from_millis(10), 1);
    }
    assert!(
        w.current() > shrunk,
        "window should grow back once conditions improve: {shrunk} -> {}",
        w.current()
    );
}

#[test]
fn never_drops_below_min_even_under_unbounded_sustained_timeouts() {
    let w = AdaptiveWindow::new(4, 2, 64, 64);
    for _ in 0..1000 {
        w.on_timeout();
    }
    assert_eq!(w.current(), 2);
}

#[test]
fn min_floor_is_at_least_one_even_if_zero_is_requested() {
    let w = AdaptiveWindow::new(4, 0, 64, 64);
    // No RTT baseline (`on_timeout` never sets one), so each call must
    // be spaced past `BACKOFF_DEBOUNCE_FALLBACK` to count as a
    // separate episode -- see `repeated_timeouts_from_one_burst_
    // collapse_to_a_single_backoff`'s own doc comment for why rapid
    // repeated calls no longer each apply their own halving.
    for _ in 0..4 {
        std::thread::sleep(BACKOFF_DEBOUNCE_FALLBACK + Duration::from_millis(50));
        w.on_timeout();
    }
    assert_eq!(w.current(), 1, "a peer must always get at least one in-flight slot");
}
