//! Clock jumps and skew, applied to a device's clock and judged by the
//! existing safety invariants.
//!
//! The product has no clock seam, and these tests do not add one. What a
//! device's clock does to data is reach the filesystem: every write is stamped
//! from it, so a jump back makes a later write carry an older mtime than an
//! earlier one, a jump forward stamps the far future, and two devices with
//! skewed clocks stamp the same moment differently. `Device` stamps from a
//! `HarnessClock` that a `Fault::ClockJump` / `Fault::ClockSkew` now moves
//! (`Device::apply_clock_fault`), so the real capture pipeline sees exactly
//! what a stepped clock produces. Replaying the same faults from the same
//! seed gives the same stamps.
//!
//! | Invariant | Test |
//! |---|---|
//! | An edit is never lost because its mtime is older than, or equal to, the recorded one | `edits_survive_*` |
//! | Capture does not depend on the clock's range or order | `clock_faults_in_a_random_walk_lose_nothing` |
//! | A conflict copy's name stays legal, bounded and content-distinct whatever the mtimes | `conflict_copy_names_survive_any_device_clock` |
//!
//! Each test shows the fault fired (the stamped mtime on disk is read back),
//! and the walk shows its comparison can fail with a pipeline that drops
//! creations. `cargo sabotage --only capture-trusts-matching-size-and-mtime`
//! plants the bug these tests exist to catch.

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_replica_domain::conflict::conflict_copy_path;

use super::boundary_device::{compare, Defect, Delivery, Device, Step};
use super::case_ir::SimNanos;
use super::case_ir::{Fault, Op};
use super::directory_model::ExplicitModel;
use super::fault_clock::ClockFaultPlan;

fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
    super::sim::block_on(1, f);
}

const DAY: i64 = 86_400 * 1_000_000_000;
const YEAR: i64 = 365 * DAY;

fn write(path: &str, content_id: u64) -> Op {
    Op::Write { path: path.to_string(), content_id }
}

fn disk_mtime(device: &Device, path: &str) -> i64 {
    let modified = std::fs::metadata(device.root.join(path)).unwrap().modified().unwrap();
    modified.duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as i64
}

/// Writes `path`, delivers it, and returns the model.
async fn write_and_flush(
    device: &Device,
    model: ExplicitModel,
    path: &str,
    id: u64,
) -> ExplicitModel {
    device.run(model, &[write(path, id)], Delivery::PerOp, Defect::None).await
}

/// A clock that steps back (an NTP correction, a resume from suspend, a hand
/// set date) makes the next same-size edit older than the recorded one. It
/// must still be captured.
#[test]
fn edits_survive_a_backward_clock_step() {
    sim(|| async {
        let device = Device::new();
        let start = 1_700_000_000 * 1_000_000_000_i64;
        device.apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: start }).unwrap();
        let model = write_and_flush(&device, ExplicitModel::default(), "a", 1).await;
        let recorded = disk_mtime(&device, "a");

        let (before, after) = device
            .apply_clock_fault(&Fault::ClockSkew { device: 0, delta_nanos: -30 * DAY })
            .expect("a skew is a clock fault");
        assert_eq!(after, before - 30 * DAY, "the skew did not move the clock");

        let model = write_and_flush(&device, model, "a", 2).await;
        let stamped = disk_mtime(&device, "a");
        assert!(
            stamped < recorded,
            "the fault did not fire: the edit's mtime {stamped} is not older than {recorded}"
        );
        compare(&device, &model).expect("a same-size edit with an older mtime was lost");
    });
}

/// The clock stands still (or steps back to the very mtime that is recorded):
/// a same-size edit with the identical mtime must be captured by content.
#[test]
fn edits_survive_an_equal_mtime_and_size() {
    sim(|| async {
        let device = Device::new();
        let t = 1_700_000_000 * 1_000_000_000_i64;
        device.apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: t }).unwrap();
        let model = write_and_flush(&device, ExplicitModel::default(), "a", 1).await;
        let recorded = disk_mtime(&device, "a");

        device.apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: t + DAY }).unwrap();
        device.apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: t }).unwrap();
        let model = write_and_flush(&device, model, "a", 2).await;
        assert_eq!(disk_mtime(&device, "a"), recorded, "the fault did not fire");
        compare(&device, &model).expect("a same-size, same-mtime edit was lost");
    });
}

/// A jump far forward and back again: files stamped in the far future and
/// then in the present are all captured, in either order.
#[test]
fn edits_survive_a_far_forward_jump_and_the_return() {
    sim(|| async {
        let device = Device::new();
        let now = 1_700_000_000 * 1_000_000_000_i64;
        device.apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: now }).unwrap();
        let mut model = write_and_flush(&device, ExplicitModel::default(), "a", 1).await;

        device
            .apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: now + 80 * YEAR })
            .unwrap();
        model = write_and_flush(&device, model, "b", 2).await;
        assert!(disk_mtime(&device, "b") > now + 79 * YEAR, "the forward jump did not fire");
        model = write_and_flush(&device, model, "a", 3).await;

        device.apply_clock_fault(&Fault::ClockJump { device: 0, to_unix_nanos: now }).unwrap();
        model = write_and_flush(&device, model, "b", 4).await;
        model = write_and_flush(&device, model, "c", 5).await;
        compare(&device, &model).expect("a clock that jumped forward and returned lost an edit");
    });
}

/// `steps` with `count` clock faults placed at seeded positions. Targets
/// come from a seeded set that includes the epoch, the past and the far
/// future; none is chosen from the wall clock.
fn with_clock_faults(steps: Vec<Step>, seed: u64, count: usize) -> Vec<Step> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xC10C);
    let base = 1_700_000_000 * 1_000_000_000_i64;
    let targets =
        [0, base - 30 * DAY, base, base + DAY, base + 10 * YEAR, 2_000_000_000 * 1_000_000_000];
    let mut out = steps;
    for _ in 0..count {
        let at = rng.random_range(0..=out.len());
        out.insert(at, Step::Clock(targets[rng.random_range(0..targets.len())]));
    }
    out
}

async fn walk(seed: u64, defect: Defect) -> Result<(), String> {
    let steps = with_clock_faults(super::random_sequences_gate::generate(seed), seed, 3);
    let device = Device::new();
    let model = device.run_steps(ExplicitModel::default(), &steps, defect).await;
    compare(&device, &model)
}

/// Seeded sequences of writes, deletes, renames and window holds with clock
/// jumps spliced in: the index ends where the independent model says. The
/// same walk with creations dropped must fail, or the comparison is blind.
#[test]
fn clock_faults_in_a_random_walk_lose_nothing() {
    sim(|| async {
        let seeds = std::env::var("DST_SEQUENCES").ok().and_then(|v| v.parse().ok()).unwrap_or(40);
        let mut failures = Vec::new();
        for seed in 0..seeds {
            if let Err(why) = walk(seed, Defect::None).await {
                failures.push(format!("seed {seed}: {why}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        let mut caught = 0;
        for seed in 0..seeds {
            if walk(seed, Defect::DropCreations).await.is_err() {
                caught += 1;
            }
        }
        assert!(caught > 0, "a pipeline dropping creations passed every clock walk");
    });
}

/// Whatever mtimes devices' clocks produce, a conflict copy's name is
/// deterministic, legal (no path separator, within 255 bytes) and keeps two
/// different contents apart.
#[test]
fn conflict_copy_names_survive_any_device_clock() {
    let schedule = vec![
        (SimNanos::from_nanos(10), Fault::ClockSkew { device: 0, delta_nanos: 2 * YEAR }),
        (SimNanos::from_nanos(20), Fault::ClockJump { device: 1, to_unix_nanos: 0 }),
        (SimNanos::from_nanos(30), Fault::ClockJump { device: 1, to_unix_nanos: i64::MIN }),
        (SimNanos::from_nanos(40), Fault::ClockJump { device: 0, to_unix_nanos: i64::MAX }),
    ];
    let plan = ClockFaultPlan::from_fault_schedule(&schedule);
    let mut seen = std::collections::HashSet::new();
    let mut mtimes = std::collections::HashSet::new();
    for device in 0..2 {
        // Sampled on the schedule's own timeline: before, at and after each
        // jump, so the boundary values themselves are reached.
        for t in [0, 10, 15, 20, 25, 30, 35, 40, 45] {
            let mtime = plan.device_now(t, device);
            mtimes.insert(mtime);
            for (path, hash) in
                [("dir/report.txt", [1u8; 32]), ("dir/report.txt", [2u8; 32]), ("noext", [3; 32])]
            {
                let name = conflict_copy_path(path, mtime, "device-x", &hash);
                assert_eq!(
                    name,
                    conflict_copy_path(path, mtime, "device-x", &hash),
                    "not deterministic"
                );
                let leaf = name.rsplit('/').next().unwrap();
                assert!(leaf.len() <= 255, "`{leaf}` exceeds a path component");
                assert!(!leaf.contains('/') && !leaf.contains('\\') && !leaf.contains(':'));
                if path.starts_with("dir") {
                    seen.insert((hash, mtime, name));
                }
            }
        }
    }
    for boundary in [0, i64::MIN, i64::MAX] {
        assert!(mtimes.contains(&boundary), "the schedule never produced mtime {boundary}");
    }
    let names_for = |hash: [u8; 32]| -> std::collections::HashSet<String> {
        seen.iter().filter(|(h, _, _)| *h == hash).map(|(_, _, n)| n.clone()).collect()
    };
    assert!(
        names_for([1; 32]).is_disjoint(&names_for([2; 32])),
        "two different contents were given the same conflict copy name"
    );
}
