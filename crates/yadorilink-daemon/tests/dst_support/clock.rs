//! The one harness-level clock/mtime seam.
//!
//! Before this module every `dst_*.rs` scenario carried its own copy of a
//! seed-derived synthetic "now" plus a `stamp_deterministic_mtime` helper
//! (canonically the retired network-fault scenario's `virtual_now_nanos` loop and
//! `stamp_deterministic_mtime`), keeping the simulated clock and the
//! kernel-stamped tempdir mtimes on one timeline *by convention*. A write
//! path that forgot to stamp produced a tie-break outcome production could
//! never see -- the single largest DST harness-artifact source.
//! `HarnessClock` owns that logic once, and the `dst_support`
//! file-operation wrappers (see `mod.rs`) stamp through it on every
//! mutation, so "forgot to stamp" becomes unrepresentable rather than a
//! reviewable convention.
//!
//! Seed-derived (not a fixed epoch) is deliberate and was already litigated
//! in the canonical inline comment: a fixed epoch risks a particular seed
//! permanently landing on a tie-break outcome that happens to hide a real
//! bug. Different seeds must explore different regions of the tie-break/
//! clamp space.
//!
//! `#![cfg(turmoil)]`-gated like every DST scenario file.

use std::sync::atomic::{AtomicI64, Ordering};

use yadorilink_peer_session::peer_session::set_test_clock_override;

/// The default per-stamp advance: a full second per stamp, coarse enough
/// that distinct writes never collide (matching the canonical loop's
/// +1s-per-round granularity) while still being strictly greater than every
/// previously stamped value, so a later conflict resolution always sees
/// "now" at or after every earlier write's mtime -- a real wall clock's
/// "now is always >= any past write's mtime" invariant.
///
/// A scenario whose convergence cadence is measured in sub-second intervals
/// (e.g. `dst_intermittent_catchup_chaos`, whose `RESYNC_INTERVAL` is a few
/// seconds and whose original hand-tracked loop stepped `virtual_now_nanos`
/// by +1ms per op) would have its relative event spacing inflated ~1000x if
/// every `fs_ops` write jumped the shared clock a whole second. Such a
/// scenario overrides this via `HarnessClock::with_step_nanos` to keep its
/// synthetic timeline on the same fine granularity its pre-migration code
/// used; `tick_round` (the coarse round-loop counterpart) always steps a
/// full second regardless.
const MTIME_STEP_NANOS: i64 = 1_000_000_000;

/// A seed-derived, strictly-monotonic synthetic clock shared by a whole
/// scenario run. All mtime stamping and the session-visible `now_unix_
/// nanos` override are driven from this one value, so they can never
/// drift onto two timelines.
///
/// Interior-mutable (`AtomicI64`) so a `&HarnessClock` threaded through a
/// scenario's shared device state can stamp from any write helper without
/// a `&mut` plumbing burden -- the same single-network-test-per-binary,
/// strictly-sequential-seeds discipline that makes `set_test_clock_
/// override`'s process-wide override safe (see its doc comment) applies
/// here too.
pub struct HarnessClock {
    current: AtomicI64,
    /// The per-mtime-stamp advance used by `next_mtime`. Defaults to
    /// `MTIME_STEP_NANOS` (+1s); a fine-cadence scenario lowers it via
    /// `with_step_nanos`. Immutable after construction, so a plain `i64`
    /// shared behind `&HarnessClock` is fine (only `current` needs interior
    /// mutability).
    mtime_step: i64,
}

impl HarnessClock {
    /// Seeds the synthetic "now" from `seed` itself (not a constant, not
    /// the round number) -- extracted verbatim from
    /// the retired network-fault scenario's `virtual_now_nanos` initialization so
    /// migrating scenarios keep byte-identical timelines.
    pub fn from_seed(seed: u64) -> Self {
        Self {
            current: AtomicI64::new((seed as i64).wrapping_mul(1_000_000_000)),
            mtime_step: MTIME_STEP_NANOS,
        }
    }

    /// Overrides the per-stamp advance `next_mtime` applies (default +1s).
    /// A scenario whose relative event spacing is sub-second passes its
    /// original per-op granularity here (e.g. `1_000_000` for the +1ms
    /// cadence `dst_intermittent_catchup_chaos` hand-tracked before it
    /// routed writes through `fs_ops`), so migrating onto the shared clock
    /// does not inflate its synthetic timeline. Builder style so the common
    /// default path stays `HarnessClock::from_seed(seed)` untouched.
    pub fn with_step_nanos(mut self, step_nanos: i64) -> Self {
        self.mtime_step = step_nanos;
        self
    }

    /// The current synthetic "now" in nanos-since-epoch, without advancing.
    pub fn now_nanos(&self) -> i64 {
        self.current.load(Ordering::SeqCst)
    }

    /// Advances the clock by `delta_nanos` and returns the new "now",
    /// keeping the session-visible clock override in lockstep.
    pub fn advance(&self, delta_nanos: i64) -> i64 {
        let next = self.current.fetch_add(delta_nanos, Ordering::SeqCst) + delta_nanos;
        set_test_clock_override(next);
        next
    }

    /// Advances by one coarse round step (+1s) and returns the new "now" --
    /// the round-loop counterpart of the canonical
    /// `virtual_now_nanos = virtual_now_nanos.wrapping_add(1_000_000_000)`
    /// followed by `set_test_clock_override(virtual_now_nanos)`.
    pub fn tick_round(&self) -> i64 {
        self.advance(MTIME_STEP_NANOS)
    }

    /// Produces the next strictly-monotonic mtime value for a single write
    /// and advances the shared "now" to it, so the session clock never
    /// falls behind a just-stamped file's mtime. Every value returned is
    /// strictly greater than every value any prior `next_mtime`/`tick_round`
    /// call returned in this run.
    ///
    /// Advances by this clock's `mtime_step` (the `with_step_nanos` override,
    /// or +1s by default).
    pub fn next_mtime(&self) -> i64 {
        self.advance(self.mtime_step)
    }

    /// Pushes the current "now" onto the process-wide session clock
    /// override without advancing -- for a scenario that wants to pin the
    /// session clock at run start before its first write (the canonical
    /// initial `set_test_clock_override(virtual_now_nanos)` call).
    pub fn install_as_session_clock(&self) {
        set_test_clock_override(self.now_nanos());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_mtime_is_strictly_monotonic() {
        let clock = HarnessClock::from_seed(0xABCD);
        let mut prev = clock.now_nanos();
        for _ in 0..100 {
            let m = clock.next_mtime();
            assert!(m > prev, "next_mtime {m} not strictly greater than previous {prev}");
            prev = m;
        }
    }

    #[test]
    fn same_seed_produces_identical_timelines() {
        let a = HarnessClock::from_seed(12345);
        let b = HarnessClock::from_seed(12345);
        assert_eq!(a.now_nanos(), b.now_nanos());
        for _ in 0..50 {
            assert_eq!(a.next_mtime(), b.next_mtime());
        }
    }

    #[test]
    fn different_seeds_explore_different_regions() {
        // A fixed epoch would pin every seed to the *same* origin and thus
        // the same tie-break outcomes; the seed-derived origin must instead
        // offset the two timelines so a run's early tie-breaks differ. The
        // sequences are offset (not permanently disjoint -- the canonical
        // +1s-per-step granularity means two adjacent seeds' timelines do
        // eventually interleave, and that is fine); what matters is that
        // corresponding steps differ, i.e. neither run is exploring the
        // identical value the other did at the same point.
        let a = HarnessClock::from_seed(1);
        let b = HarnessClock::from_seed(2);
        assert_ne!(a.now_nanos(), b.now_nanos());
        for _ in 0..10 {
            assert_ne!(a.next_mtime(), b.next_mtime());
        }
    }

    #[test]
    fn tick_round_matches_canonical_one_second_step() {
        let clock = HarnessClock::from_seed(0);
        let base = clock.now_nanos();
        assert_eq!(clock.tick_round(), base + 1_000_000_000);
        assert_eq!(clock.tick_round(), base + 2_000_000_000);
    }

    #[test]
    fn with_step_nanos_scales_next_mtime_but_not_tick_round() {
        // A fine-cadence scenario advances `next_mtime` by its own step
        // (here +1ms) so migrating onto the shared clock does not inflate
        // its synthetic timeline; `tick_round` stays the canonical +1s.
        let clock = HarnessClock::from_seed(0).with_step_nanos(1_000_000);
        let base = clock.now_nanos();
        assert_eq!(clock.next_mtime(), base + 1_000_000);
        assert_eq!(clock.next_mtime(), base + 2_000_000);
        assert_eq!(clock.tick_round(), base + 2_000_000 + 1_000_000_000);
    }
}
