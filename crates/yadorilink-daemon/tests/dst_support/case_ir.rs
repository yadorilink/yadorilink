//! The unified, serializable Case IR every DST scenario (e.g.,
//! the retired two-device scenario, `monkey_chaos`, and the full-stack daemon)
//! is retrofitted onto, replacing bespoke per-scenario event
//! bookkeeping with one shared shape that survives generator evolution (a
//! serialized `Case` persists to the corpus verbatim -- a bare seed only
//! replays as long as the generator that produced it from that seed
//! hasn't changed).
//!
//! `#![cfg(turmoil)]`-gated like every DST scenario file.
//!
//! Note: `Fault` and most of `Op` are defined comprehensively to
//! match the full IR shape, avoiding breaking schema changes later.
//! Some scenarios populate `fault_schedule` with an empty `Vec` if they
//! do not utilize fault injectors, and might only emit basic operations
//! like `Op::Write`/`Op::Delete`. Extended operations like `Rename` are
//! defined now so the type doesn't need to change shape later when used.

#![cfg(turmoil)]
#![allow(dead_code)] // not every field/variant has a producer yet

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Simulated time in nanoseconds from a run's start. The only unit a
/// `Case::fault_schedule` offset can be written in; see that field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SimNanos(u64);

/// What one logical workload round is worth on the simulated clock.
///
/// A round is a `DeviceTimeline` `virtual_ts` step. It drives no scheduling
/// itself; this is the one conversion a producer that thinks in rounds
/// (the generator) uses to place a fault at a round boundary.
pub const ROUND_NANOS: u64 = 1_000_000_000;

impl SimNanos {
    pub const ZERO: SimNanos = SimNanos(0);

    /// An offset already measured in nanoseconds.
    pub const fn from_nanos(nanos: u64) -> Self {
        SimNanos(nanos)
    }

    /// The start of logical round `round`.
    pub const fn from_round(round: u64) -> Self {
        SimNanos(round.saturating_mul(ROUND_NANOS))
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The round whose span contains this offset.
    pub const fn round(self) -> u64 {
        self.0 / ROUND_NANOS
    }
}

/// A single seed-driven scenario, fully self-describing: replaying `Case`
/// against the same scenario code (independent of the generator that
/// produced it) must reproduce the same run. Serialized (not just `seed`)
/// so a shrunk failing case survives generator evolution in the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub seed: u64,
    pub topology: Topology,
    pub workload: Vec<DeviceTimeline>,
    /// `(offset, Fault)`, sorted by offset, fired against the simulated
    /// clock.
    ///
    /// The offset is a [`SimNanos`]: **nanoseconds from the run's start**.
    /// The unit is a type, not a comment, because each producer used to
    /// assume a different one (one scenario wrote milliseconds, and the
    /// generator wrote round indices, so its faults collapsed into the run's
    /// opening instants). The scheduler reads `SimNanos::as_nanos`; a
    /// producer that has a logical round converts it with
    /// [`SimNanos::from_round`], which is the single place that says what a
    /// round is worth ([`ROUND_NANOS`]). It serializes as the bare integer,
    /// so existing corpus entries are unchanged.
    ///
    /// Note this is *not* the same quantity as `DeviceTimeline`'s own
    /// `virtual_ts`, which is a round counter that deliberately drives no
    /// scheduling.
    pub fault_schedule: Vec<(SimNanos, Fault)>,
    /// Every content value any op in `workload` can reference by
    /// `content_id`, so an oracle can prove "this surviving byte string is
    /// something a device actually wrote" rather than merely "not empty".
    pub content_table: ContentTable,
    /// The network FaultPlan this run replays (partition windows / drop / delay
    /// / duplicate). Default (empty) = no injected faults, so pre-fault corpus
    /// entries deserialize unchanged (serde default) and replay identically.
    #[serde(default)]
    pub fault_plan: FaultPlan,
    /// History-epoch steps (seal, foreign-base merge) as `(round, step)`, in
    /// the same round counter as `DeviceTimeline::ops`. Not an `Op`: neither
    /// is a filesystem action, and every `Op` consumer (applier, models,
    /// generators) would otherwise need an arm for something it cannot
    /// perform. Empty for every scenario that does not drive history
    /// compaction, so older corpus entries deserialize unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history_steps: Vec<(u64, HistoryStep)>,
}

/// A history-compaction step a scenario drives explicitly.
///
/// Compaction is not scheduled in production yet
/// (`COMPACTION_SCHEDULING_READY` is false), so nothing seals or merges on
/// its own: a scenario that wants an epoch reset has to ask for one, at a
/// point the `Case` records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryStep {
    /// `device` seals its group's history into a new history base.
    Seal { device: usize },
    /// `into` merges the base `from` stands on into its own history, sealing
    /// either side that holds history above its base first.
    Merge { into: usize, from: usize },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Topology {
    pub device_count: usize,
    pub links: Vec<LinkTopology>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkTopology {
    pub group_id: String,
    pub initial_online: bool,
}

/// One device's ordered op timeline. `virtual_ts` is a monotonic per-run
/// round counter used only to record/replay op *order* within and across
/// devices' timelines, never to drive real scheduling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTimeline {
    pub device_index: usize,
    pub ops: Vec<(u64, Op)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    Write {
        path: String,
        content_id: u64,
    },
    Edit {
        path: String,
        content_id: u64,
    },
    Delete {
        path: String,
    },
    /// Extended operation for renaming a file (see `RenameTree` for a
    /// directory).
    Rename {
        from: String,
        to: String,
    },
    Move {
        from: String,
        to: String,
    },
    Mkdir {
        path: String,
    },
    Rmdir {
        path: String,
    },
    /// `rm -rf path`: the directory and everything under it, non-empty or
    /// not. Replicated as point deletes of the entries the device had
    /// observed under `path`, never as a prefix tombstone, so an entry a
    /// peer creates under `path` concurrently survives it.
    RmTree {
        path: String,
    },
    /// `mv from to` of a whole directory: one rename of the directory
    /// entry, which moves every descendant without touching any of them.
    /// Replicated as delete-at-old-path plus put-at-new-path for each
    /// observed entry; a concurrent child created under `from` stays under
    /// `from`.
    RenameTree {
        from: String,
        to: String,
    },
    Chmod {
        path: String,
        exec_bit: bool,
    },
    /// Multiple devices' ops at the same logical round targeting paths
    /// that are expected to race -- a generator-level grouping hint for
    /// the oracle's history-legality check, not a new primitive op
    /// in its own right.
    ConflictingConcurrent {
        paths: Vec<String>,
    },
}

/// The fault classes the design specifies, defined comprehensively now so
/// future scenarios can slot their injectors in without a breaking IR change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Fault {
    Net(NetFault),
    Disk(DiskFault),
    Crash { device: usize },
    Restart { device: usize },
    ClockSkew { device: usize, delta_nanos: i64 },
    ClockJump { device: usize, to_unix_nanos: i64 },
}

/// Shape for the intercepting-transport injector; fields are the
/// minimum fault model names (`drop`/`delay`/`reorder`/`duplicate`/
/// `partition`/`heal`) so `Fault::Net` has a stable shape when
/// an actual interceptor is wired behind it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetFault {
    Drop,
    Delay { millis: u64 },
    Reorder,
    Duplicate,
    Partition { device_a: usize, device_b: usize },
    Heal { device_a: usize, device_b: usize },
}

/// Shape for the faulting `BlockStore`/`SyncState` injectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiskFault {
    Enospc,
    Eio,
    TornWrite,
    FsyncFail,
    SlowIo { millis: u64 },
    SqliteBusy,
    SqliteLocked,
}

/// The seed-driven
/// network fault plan an intercepting `FaultingChannel` (`dst_support::
/// fault`) applies, replacing the ad-hoc `outbound_partitioned: AtomicBool`
/// (`dst_intermittent_catchup_chaos.rs`). Lives in the Case IR
/// so a recorded corpus entry fully describes its network behavior and
/// replays with identical drops/delays/duplicates/partition windows.
///
/// Deliberately schedule-based, not RNG-at-apply-time: "every Nth message
/// of a class" and explicit `(start, end)` partition windows on the sim
/// clock are exactly reproducible from the serialized plan alone, so a
/// replay drops/delays/duplicates the same messages at the same simulated
/// times without needing to re-derive an RNG stream. A generator seeds the
/// plan's `*_every`/window values; from there application is pure.
///
/// Not yet a field of `Case`: adding `fault_plan` to `Case` rides with the
/// `dst_intermittent_catchup_chaos` migration, the first
/// scenario to emit one. Defined and tested
/// now so that migration is a wiring change, not a schema change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultPlan {
    /// Windows, as `(start_nanos, end_nanos)` on the simulated clock, during
    /// which the decorated side is partitioned (every outbound message is
    /// dropped). Half-open `[start, end)`. Replaces the boolean partition
    /// flag with a reproducible, time-scheduled cut/heal.
    pub partition_windows: Vec<(i64, i64)>,
    /// Drop every Nth message that reaches the channel (0 = never drop).
    pub drop_every: u32,
    /// Duplicate every Nth message (0 = never) -- the duplicate is delivered
    /// immediately after the original.
    pub duplicate_every: u32,
    /// Delay every Nth message (0 = never) by `delay_nanos` of simulated
    /// time. Heterogeneous delays are how reorder manifests: a delayed
    /// message lands after later, undelayed ones.
    pub delay_every: u32,
    /// The simulated delay applied to a delayed message.
    pub delay_nanos: i64,
}

/// Maps a `content_id` to the exact bytes a device wrote under that id, so
/// an oracle can check "the surviving hash is one of these" rather than
/// merely hashing whatever it finds on disk with nothing to compare
/// against. `content_id`s are assigned by whatever generates the `Case`
/// (sequential is fine; only uniqueness within one `Case` matters).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentTable {
    entries: HashMap<u64, Vec<u8>>,
}

impl ContentTable {
    pub fn insert(&mut self, content_id: u64, bytes: Vec<u8>) -> u64 {
        self.entries.insert(content_id, bytes);
        content_id
    }

    pub fn get(&self, content_id: u64) -> Option<&Vec<u8>> {
        self.entries.get(&content_id)
    }

    /// True if `bytes` matches exactly one recorded content value --
    /// the no-corruption oracle's core question ("did someone actually
    /// write this, byte for byte").
    pub fn contains_bytes(&self, bytes: &[u8]) -> bool {
        self.entries.values().any(|v| v.as_slice() == bytes)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u64, &Vec<u8>)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_table_round_trips_through_json() {
        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());
        table.insert(2, b"world".to_vec());

        let json = serde_json::to_string(&table).unwrap();
        let restored: ContentTable = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.get(1), Some(&b"hello".to_vec()));
        assert_eq!(restored.get(2), Some(&b"world".to_vec()));
        assert!(restored.contains_bytes(b"hello"));
        assert!(!restored.contains_bytes(b"nope"));
    }

    #[test]
    fn case_round_trips_through_json() {
        let mut content_table = ContentTable::default();
        content_table.insert(1, b"payload".to_vec());

        let case = Case {
            seed: 42,
            topology: Topology {
                device_count: 2,
                links: vec![
                    LinkTopology { group_id: "g".to_string(), initial_online: true },
                    LinkTopology { group_id: "g".to_string(), initial_online: true },
                ],
            },
            workload: vec![DeviceTimeline {
                device_index: 0,
                ops: vec![(0, Op::Write { path: "a.txt".to_string(), content_id: 1 })],
            }],
            fault_schedule: Vec::new(),
            content_table,
            fault_plan: FaultPlan::default(),
            history_steps: Vec::new(),
        };

        let json = serde_json::to_string(&case).unwrap();
        let restored: Case = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.seed, 42);
        assert_eq!(restored.workload.len(), 1);
    }

    /// back-compat: a `Case` serialized before `fault_plan`
    /// existed (no `fault_plan` key at all) must still deserialize --
    /// `#[serde(default)]` filling in `FaultPlan::default` -- so every
    /// pre-fault corpus entry on disk keeps replaying unchanged.
    #[test]
    fn case_without_fault_plan_key_deserializes_with_the_default() {
        let json = r#"{
            "seed": 7,
            "topology": {"device_count": 1, "links": []},
            "workload": [],
            "fault_schedule": [],
            "content_table": {"entries": {}}
        }"#;
        let restored: Case = serde_json::from_str(json).unwrap();
        assert_eq!(restored.fault_plan, FaultPlan::default());
        assert!(restored.history_steps.is_empty());
    }

    /// History steps survive a round trip, and a case without any leaves the
    /// key out, so a scenario that never seals writes the corpus line it
    /// wrote before the field existed.
    #[test]
    fn history_steps_round_trip_and_stay_out_of_cases_without_them() {
        let mut case: Case = serde_json::from_str(
            r#"{"seed": 7, "topology": {"device_count": 2, "links": []}, "workload": [],
                "fault_schedule": [], "content_table": {"entries": {}}}"#,
        )
        .unwrap();
        assert!(!serde_json::to_string(&case).unwrap().contains("history_steps"));

        case.history_steps = vec![
            (3, HistoryStep::Seal { device: 1 }),
            (5, HistoryStep::Merge { into: 0, from: 1 }),
        ];
        let restored: Case = serde_json::from_str(&serde_json::to_string(&case).unwrap()).unwrap();
        assert_eq!(restored.history_steps, case.history_steps);
    }
}
