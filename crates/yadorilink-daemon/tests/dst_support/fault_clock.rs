//! A pure, deterministic per-device clock-error model: constant CLOCK-SKEW
//! plus scheduled CLOCK-JUMP events.
//!
//! Every other DST fault injector (`dst_support::fault`'s `FaultPlan` /
//! `FaultingChannel`, the disk/sqlite injectors) is a pure, serde-
//! serializable *plan* that a scenario replays deterministically off the
//! simulated clock, never off wall time or an apply-time RNG. This module is
//! the clock-domain counterpart. `HarnessClock` (`dst_support::clock`) owns
//! the one *shared* synthetic "now" for a run; real devices, however, do not
//! agree on now -- each has a standing offset from true time (crystal skew)
//! and occasionally steps (NTP correction, suspend/resume). `ClockFaultPlan`
//! models exactly that per-device disagreement as a pure function of the
//! shared base "now", so a scenario can ask "what does device D believe now
//! is?" and replay it identically from the serialized plan alone.
//!
//! Two independent pieces, mirroring the two things a real clock does wrong:
//!   * `skews`: a constant signed-nanos offset per device, applied at *every*
//!     base "now" (a device whose crystal runs fast/slow reads a fixed offset
//!     from true time, present from t=0).
//!   * `jumps`: discrete `(device, at_nanos, delta_nanos)` step events. At and
//!     after `at_nanos` (compared against the *base* now, not the perturbed
//!     value, so the predicate is total and never self-referential) the
//!     device's clock steps by `delta_nanos`. Positive = forward correction;
//!     negative = an intentional backward step (a late NTP correction, or a
//!     suspend/resume that resumes behind where it slept).
//!
//! `skewed_now(device, base_now)` = `base_now + skew(device) + sum of every
//! jump for that device whose `at_nanos <= base_now``. Pure, total (arithmetic
//! is wrapping, never panicking), and deterministic: no wall clock, no RNG.
//!
//! ## Monotonicity
//! For a fixed device, `skewed_now` is non-decreasing in `base_now` *except*
//! across a negative jump, which steps the device clock backward on purpose --
//! that is the fault being modelled (a clock that jumps back is precisely the
//! bug DST wants to shake out). Within any interval between jump timestamps,
//! and across any positive jump, it is strictly increasing with `base_now`.
//!
//! ## How this wires into `fault_schedule` (do NOT edit those files)
//! A `Case`'s `fault_schedule: Vec<(u64 /*virtual_ts*/, Fault)>` already carries
//! `Fault::ClockSkew { device, delta_nanos }` and
//! `Fault::ClockJump { device, to_unix_nanos }` (see `dst_support::case_ir`),
//! but nothing consumes them. `ClockFaultPlan::from_fault_schedule` is the
//! bridge: walking the schedule in ascending `virtual_ts`,
//!   * a `ClockSkew` accumulates into `skews[device]` (it is a *constant*
//!     offset, so its `virtual_ts` does not bound it -- it applies at all
//!     base nows);
//!   * a `ClockJump` is absolute (land the clock *on* `to_unix_nanos`) whereas
//!     this plan stores *deltas*, so the bridge appends a jump whose
//!     `delta_nanos = to_unix_nanos - skewed_now(device, virtual_ts)` computed
//!     against the partially-built plan. After that append,
//!     `skewed_now(device, virtual_ts) == to_unix_nanos` exactly.
//! A scenario builds one `ClockFaultPlan` from its `Case.fault_schedule` once,
//! then consults it (below) wherever a device observes "now".
//!
//! ## How this wires into a future daemon `Clock` seam (do NOT edit it yet)
//! When the daemon grows a `Clock` seam (a `now()` source injected instead of
//! calling the OS clock directly), the DST implementation of that seam for
//! device `d` returns `plan.device_now(clock.now_nanos(), d)` -- i.e. it takes
//! the shared `HarnessClock` "now" (an `i64` nanos value) and applies device
//! `d`'s skew+jumps. This module stays decoupled from `dst_support::clock` on
//! purpose: it consumes a plain base-`now` `i64`, so it composes with
//! `HarnessClock` (or the real daemon clock, or a bare literal in a unit test)
//! at the call site without importing any of them. Production wires the real
//! monotonic/wall source; DST wires this. The seam is the only place that needs
//! to change; the plan itself is already the whole policy.

#![cfg(turmoil)]
#![allow(dead_code)] // not every scenario exercises this injector yet

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::case_ir::{Fault, SimNanos};

/// A device's identity within a scenario. Matches the `device: usize` index
/// the Case IR's `Fault::ClockSkew`/`ClockJump` variants use, so a plan built
/// from a `fault_schedule` needs no id remapping.
pub type DeviceId = usize;

/// One scheduled clock step for a single device. At and after `at_nanos`
/// (measured on the shared *base* clock), the device's observed now gains
/// `delta_nanos`. Named (not the bare tuple) so `delta_nanos` cannot be
/// silently swapped with `at_nanos`, and so JSON carries field names.
///
/// Distinct from the Case IR's `Fault::ClockJump`, which is *absolute*
/// (`to_unix_nanos`); `from_fault_schedule` converts absolute targets into the
/// relative `delta_nanos` this model composes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockJumpEvent {
    pub device: DeviceId,
    /// Base-clock timestamp at/after which this step is in effect.
    pub at_nanos: i64,
    /// Signed step. Positive = forward, negative = an intentional backward
    /// jump (the non-monotonic fault this model exists to inject).
    pub delta_nanos: i64,
}

/// A pure, serde-serializable per-device clock-error plan. Empty (`default`)
/// means every device's clock equals the shared base "now" -- no injected
/// clock fault -- so a scenario that does not use this injector pays nothing
/// and a corpus entry that predates it deserializes unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClockFaultPlan {
    /// Constant signed-nanos offset per device, applied at every base "now".
    /// `BTreeMap` (not `HashMap`) so serialization order -- and thus the
    /// serialized bytes of a recorded case -- is deterministic.
    #[serde(default)]
    pub skews: BTreeMap<DeviceId, i64>,
    /// Discrete step events. Order does not affect `skewed_now` (the per-device
    /// sum is commutative), but is preserved so a round-trip is exact.
    #[serde(default)]
    pub jumps: Vec<ClockJumpEvent>,
}

impl ClockFaultPlan {
    /// The constant skew configured for `device`, or `0` if none.
    pub fn skew_of(&self, device: DeviceId) -> i64 {
        self.skews.get(&device).copied().unwrap_or(0)
    }

    /// Device `device`'s belief of "now", given the shared base "now"
    /// `base_now_nanos`: its constant skew plus every one of *its* jumps that
    /// has fired by `base_now_nanos`. Pure, total, deterministic.
    ///
    /// Arithmetic is wrapping so the function is total for every `i64` input
    /// (an adversarial skew/jump near `i64::MAX` wraps rather than panicking);
    /// realistic nanos timestamps are nowhere near that boundary.
    pub fn skewed_now(&self, device: DeviceId, base_now_nanos: i64) -> i64 {
        let jump_total = self
            .jumps
            .iter()
            .filter(|j| j.device == device && j.at_nanos <= base_now_nanos)
            .fold(0i64, |acc, j| acc.wrapping_add(j.delta_nanos));
        base_now_nanos.wrapping_add(self.skew_of(device)).wrapping_add(jump_total)
    }

    /// Convenience seam helper: given the shared base "now" (e.g. the value a
    /// `HarnessClock` or the daemon `Clock` seam yields from `now_nanos()`),
    /// return `device`'s device-local skewed now. Deliberately takes a plain
    /// `i64` rather than a clock type, so this module has no compile dependency
    /// on `dst_support::clock` and composes with any now-source at the call
    /// site -- see the module docs' "daemon `Clock` seam" note. Identical in
    /// result to `skewed_now`; the name marks the intended call site.
    pub fn device_now(&self, base_now_nanos: i64, device: DeviceId) -> i64 {
        self.skewed_now(device, base_now_nanos)
    }

    /// Build a `ClockFaultPlan` from a `Case`'s `fault_schedule`. See the
    /// module docs' "wires into `fault_schedule`" note for the full contract.
    /// Non-clock faults (`Net`/`Disk`/`Crash`/`Restart`) are ignored. The
    /// schedule is expected in ascending `virtual_ts`, matching the Case IR's
    /// documented ordering, so each absolute `ClockJump` is bridged against the
    /// plan as built up to that point.
    pub fn from_fault_schedule(schedule: &[(SimNanos, Fault)]) -> Self {
        let mut plan = ClockFaultPlan::default();
        for (virtual_ts, fault) in schedule {
            let at = virtual_ts.as_nanos() as i64;
            match fault {
                Fault::ClockSkew { device, delta_nanos } => {
                    let acc = plan.skew_of(*device).wrapping_add(*delta_nanos);
                    plan.skews.insert(*device, acc);
                }
                Fault::ClockJump { device, to_unix_nanos } => {
                    // Absolute -> relative: choose the delta that lands device
                    // `device`'s clock exactly on `to_unix_nanos` at `at`,
                    // given the plan built so far.
                    let delta = to_unix_nanos.wrapping_sub(plan.skewed_now(*device, at));
                    plan.jumps.push(ClockJumpEvent {
                        device: *device,
                        at_nanos: at,
                        delta_nanos: delta,
                    });
                }
                Fault::Net(_) | Fault::Disk(_) | Fault::Crash { .. } | Fault::Restart { .. } => {}
            }
        }
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skew_offsets_only_its_own_device_by_exactly_the_configured_amount() {
        let mut skews = BTreeMap::new();
        skews.insert(1usize, 500i64);
        skews.insert(3usize, -250i64);
        let plan = ClockFaultPlan { skews, jumps: Vec::new() };

        // The configured device reads base + its skew, exactly.
        assert_eq!(plan.skewed_now(1, 10_000), 10_500);
        assert_eq!(plan.skewed_now(3, 10_000), 9_750);
        // Unconfigured devices are unaffected (skew 0).
        assert_eq!(plan.skewed_now(0, 10_000), 10_000);
        assert_eq!(plan.skewed_now(2, 10_000), 10_000);
    }

    #[test]
    fn jump_applies_only_at_or_after_its_timestamp_and_is_cumulative() {
        let plan = ClockFaultPlan {
            skews: BTreeMap::new(),
            jumps: vec![
                ClockJumpEvent { device: 0, at_nanos: 1_000, delta_nanos: 100 },
                ClockJumpEvent { device: 0, at_nanos: 2_000, delta_nanos: 30 },
            ],
        };
        assert_eq!(plan.skewed_now(0, 999), 999); // before the first jump
        assert_eq!(plan.skewed_now(0, 1_000), 1_100); // at the first (inclusive)
        assert_eq!(plan.skewed_now(0, 1_999), 2_099); // one jump active
        assert_eq!(plan.skewed_now(0, 2_000), 2_130); // both, cumulative
                                                      // Another device is untouched by device 0's jumps.
        assert_eq!(plan.skewed_now(1, 2_000), 2_000);
    }

    #[test]
    fn monotonic_within_a_device_except_across_an_intentional_negative_jump() {
        // Positive-only perturbation: strictly increasing in base now.
        let mono = ClockFaultPlan {
            skews: BTreeMap::from([(0usize, 40i64)]),
            jumps: vec![ClockJumpEvent { device: 0, at_nanos: 50, delta_nanos: 1_000 }],
        };
        let mut prev = i64::MIN;
        for t in 0..100i64 {
            let now = mono.skewed_now(0, t);
            assert!(now > prev, "expected monotonic, got {now} after {prev} at t={t}");
            prev = now;
        }

        // A negative jump is a deliberate backward step (late NTP correction /
        // suspend-resume): monotonicity is broken exactly at the jump.
        let backward = ClockFaultPlan {
            skews: BTreeMap::new(),
            jumps: vec![ClockJumpEvent { device: 0, at_nanos: 50, delta_nanos: -1_000 }],
        };
        assert_eq!(backward.skewed_now(0, 49), 49);
        assert!(
            backward.skewed_now(0, 50) < backward.skewed_now(0, 49),
            "a negative jump must step the device clock backward"
        );
    }

    #[test]
    fn the_same_plan_replays_an_identical_skewed_sequence() {
        let plan = ClockFaultPlan {
            skews: BTreeMap::from([(0usize, -5i64), (1usize, 7)]),
            jumps: vec![
                ClockJumpEvent { device: 0, at_nanos: 100, delta_nanos: 40 },
                ClockJumpEvent { device: 1, at_nanos: 150, delta_nanos: -20 },
            ],
        };
        let times = [0i64, 50, 100, 150, 200, 250];
        let run = |p: &ClockFaultPlan| {
            times.iter().flat_map(|&t| [p.skewed_now(0, t), p.skewed_now(1, t)]).collect::<Vec<_>>()
        };
        assert_eq!(run(&plan), run(&plan.clone()), "the same plan must replay identically");
    }

    #[test]
    fn plan_round_trips_through_json() {
        let plan = ClockFaultPlan {
            skews: BTreeMap::from([(0usize, 3i64), (2usize, -9)]),
            jumps: vec![
                ClockJumpEvent { device: 0, at_nanos: 1, delta_nanos: 2 },
                ClockJumpEvent { device: 2, at_nanos: 5, delta_nanos: -3 },
            ],
        };
        let json = serde_json::to_string(&plan).unwrap();
        let restored: ClockFaultPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, restored);
    }

    #[test]
    fn empty_plan_leaves_every_device_on_the_base_clock() {
        let plan = ClockFaultPlan::default();
        assert_eq!(plan.skewed_now(0, 123_456), 123_456);
        assert_eq!(plan.skewed_now(9, -5), -5);
    }

    #[test]
    fn from_fault_schedule_bridges_constant_skew_and_absolute_jump() {
        let schedule = vec![
            (SimNanos::from_nanos(0), Fault::ClockSkew { device: 0, delta_nanos: 500 }),
            (SimNanos::from_nanos(1_000), Fault::ClockJump { device: 0, to_unix_nanos: 9_000 }),
            // A fault from another domain is ignored by the clock plan.
            (SimNanos::from_nanos(1_500), Fault::Crash { device: 1 }),
        ];
        let plan = ClockFaultPlan::from_fault_schedule(&schedule);

        // The constant skew applies everywhere, including before the jump.
        assert_eq!(plan.skewed_now(0, 0), 500);
        assert_eq!(plan.skewed_now(0, 999), 1_499);
        // At/after the scheduled jump the device lands exactly on the absolute
        // target the `Fault::ClockJump` requested.
        assert_eq!(plan.skewed_now(0, 1_000), 9_000);
        assert_eq!(plan.skewed_now(0, 5_000), 13_000); // 5000 + 500 skew + 7500 jump delta
                                                       // The crashed device carries no clock fault.
        assert_eq!(plan.skewed_now(1, 5_000), 5_000);
    }

    #[test]
    fn device_now_applies_the_devices_skew_to_a_base_now() {
        // `base` stands in for whatever a `HarnessClock`/daemon `Clock` seam
        // would yield from `now_nanos()`; the helper takes the plain `i64`.
        let base = 1_700_000_000_000_000_000i64;
        let plan = ClockFaultPlan { skews: BTreeMap::from([(2usize, 777i64)]), jumps: Vec::new() };
        assert_eq!(plan.device_now(base, 2), base + 777);
        // An unconfigured device rides the base clock unchanged.
        assert_eq!(plan.device_now(base, 0), base);
        // `device_now` is exactly `skewed_now` with the args reordered for the
        // call site -- same result.
        assert_eq!(plan.device_now(base, 2), plan.skewed_now(2, base));
    }
}
