//! Low-overhead milestone timeline for one "share join -> first file" attempt.
//!
//! One monotonic timeline from the moment a device joins a share to the
//! first durably materialized file, so the dominant delay can be attributed
//! before anything is optimised. This module is measurement only: it records the first time each [`Milestone`] is reached for a group
//! and emits one `tracing` event per milestone (target
//! `yadorilink::join_timeline`, level info). It never changes control flow.
//!
//! An attempt is keyed by the local device id and the group id, and carries a
//! per-attempt correlation id on every event, so two daemons in one process
//! (a test harness) never feed each other's timeline.
//!
//! Privacy: events carry only the local device id, the group id and (where the
//! call site already logs it) the peer device id -- the same identifiers
//! existing diagnostics print. No paths, hashes, file names, contents or
//! tokens.
//!
//! Cost: a timeline exists only between [`begin`] (called on a join) and its
//! end: the [`Milestone::FirstFileCommitted`] mark, an [`abandon`] (the join
//! failed), or [`MAX_AGE`] (an empty share, an on-demand join that never
//! commits a file). Expiry is checked on the event path itself, so the
//! hot-path check returns to a single relaxed atomic load without any later
//! join. With a timeline active a mark is a short uncontended mutex plus a
//! map lookup, and each milestone logs at most once per attempt.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const MILESTONES: usize = 21;

/// The load-bearing stages between a join and the first visible file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Milestone {
    /// The daemon accepted the join (or the local link was started).
    JoinAccepted,
    /// The link runtime for the group finished starting (policy/native state
    /// ready, startup barrier open).
    LinkReady,
    /// The first coordination netmap frame was applied after the join.
    NetmapReceived,
    /// A peer was pinned and authorized for this group by a netmap.
    PeerAuthorized,
    /// The coordination plane reported a substrate address (direct or relay)
    /// for a peer that shares this group.
    PeerAddressAvailable,
    /// The first dial toward a peer that shares this group began.
    LinkDialStarted,
    /// A substrate connection to a peer that shares this group was
    /// established (dialled or accepted).
    CarrierEstablished,
    /// A `PeerSyncSession` for a peer that shares this group was registered.
    PeerSyncSessionRegistered,
    /// The native replication connection to a peer was dialled or accepted.
    NativeConnected,
    /// A native replication connection that serves this group is attached.
    PeerSessionUsable,
    /// The first anti-entropy (summary) round for the group began.
    FirstReconcileRound,
    /// The first anti-entropy summary reply for the group arrived.
    SummaryReceived,
    /// The peer accepted the first sealed-state (recovery) request.
    RecoveryRequestAccepted,
    /// A peer's sealed state for the group was applied.
    SealedStateApplied,
    /// The first frontier-diff request for the group was answered.
    FrontierDiffAnswered,
    /// The first remote delta for the group was admitted.
    MetadataAdmitted,
    /// The first projection pass with actionable seeds for the group began.
    ProjectionWorkCreated,
    /// The first block request header was written to a peer.
    BlockRequestSent,
    /// The first block response header arrived from a peer.
    BlockResponseReceived,
    /// The first eager materialization began.
    MaterializationStarted,
    /// The first file was durably committed and its obligation settled.
    FirstFileCommitted,
}

impl Milestone {
    const ALL: [Milestone; MILESTONES] = [
        Milestone::JoinAccepted,
        Milestone::LinkReady,
        Milestone::NetmapReceived,
        Milestone::PeerAuthorized,
        Milestone::PeerAddressAvailable,
        Milestone::LinkDialStarted,
        Milestone::CarrierEstablished,
        Milestone::PeerSyncSessionRegistered,
        Milestone::NativeConnected,
        Milestone::PeerSessionUsable,
        Milestone::FirstReconcileRound,
        Milestone::SummaryReceived,
        Milestone::RecoveryRequestAccepted,
        Milestone::SealedStateApplied,
        Milestone::FrontierDiffAnswered,
        Milestone::MetadataAdmitted,
        Milestone::ProjectionWorkCreated,
        Milestone::BlockRequestSent,
        Milestone::BlockResponseReceived,
        Milestone::MaterializationStarted,
        Milestone::FirstFileCommitted,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Milestone::JoinAccepted => "join_accepted",
            Milestone::LinkReady => "link_ready",
            Milestone::NetmapReceived => "netmap_received",
            Milestone::PeerAuthorized => "peer_authorized",
            Milestone::PeerAddressAvailable => "peer_address_available",
            Milestone::LinkDialStarted => "link_dial_started",
            Milestone::CarrierEstablished => "carrier_established",
            Milestone::PeerSyncSessionRegistered => "peer_sync_session_registered",
            Milestone::NativeConnected => "native_connected",
            Milestone::PeerSessionUsable => "peer_session_usable",
            Milestone::FirstReconcileRound => "first_reconcile_round",
            Milestone::SummaryReceived => "summary_received",
            Milestone::RecoveryRequestAccepted => "recovery_request_accepted",
            Milestone::SealedStateApplied => "sealed_state_applied",
            Milestone::FrontierDiffAnswered => "frontier_diff_answered",
            Milestone::MetadataAdmitted => "metadata_admitted",
            Milestone::ProjectionWorkCreated => "projection_work_created",
            Milestone::BlockRequestSent => "block_request_sent",
            Milestone::BlockResponseReceived => "block_response_received",
            Milestone::MaterializationStarted => "materialization_started",
            Milestone::FirstFileCommitted => "first_file_committed",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// A finished timeline: offsets from the join start, in milestone order
/// (`None` when a milestone was never reached before the first file), plus
/// how many anti-entropy rounds had begun by the end.
#[derive(Clone, Debug)]
pub struct Finished {
    pub attempt: u64,
    /// Two joins of the same group overlapped on this device, so the sample
    /// is not one attempt's timeline and must not be used as data.
    pub ambiguous: bool,
    pub offsets: [Option<Duration>; MILESTONES],
    pub reconcile_rounds: u32,
}

struct Timeline {
    attempt: u64,
    /// Set when a second `begin` hit this device and group while this
    /// attempt was active: milestones are routed by device and group only,
    /// so the sample can no longer be attributed to one attempt.
    ambiguous: bool,
    device: String,
    start: Instant,
    prev: Instant,
    offsets: [Option<Duration>; MILESTONES],
    rounds: u32,
}

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);
static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Bounds the table so a burst of joins that never reach a first file cannot
/// grow memory without limit.
const MAX_TRACKED: usize = 64;
/// How long an attempt may wait for its first file before it is dropped.
pub const MAX_AGE: Duration = Duration::from_secs(300);

#[derive(Default)]
struct State {
    /// By group id; usually one attempt, more only when several devices in
    /// one process join the same group.
    active: HashMap<String, Vec<Timeline>>,
    finished: Vec<(String, String, Finished)>,
}

impl State {
    fn len(&self) -> usize {
        self.active.values().map(Vec::len).sum()
    }

    fn find(&mut self, device: &str, group: &str) -> Option<&mut Timeline> {
        self.active.get_mut(group)?.iter_mut().find(|t| t.device == device)
    }

    fn remove(&mut self, device: &str, group: &str) -> Option<Timeline> {
        let list = self.active.get_mut(group)?;
        let at = list.iter().position(|t| t.device == device)?;
        let timeline = list.remove(at);
        if list.is_empty() {
            self.active.remove(group);
        }
        Some(timeline)
    }

    /// Drops attempts past [`MAX_AGE`], logging each once.
    fn sweep(&mut self, now: Instant) {
        let mut expired = Vec::new();
        for (group, list) in &self.active {
            for t in list {
                if now.saturating_duration_since(t.start) >= MAX_AGE {
                    expired.push((t.device.clone(), group.clone()));
                }
            }
        }
        for (device, group) in expired {
            if let Some(t) = self.remove(&device, &group) {
                log_end(&t, "expired", now);
            }
        }
    }

    fn publish_count(&self) {
        ACTIVE.store(self.len(), Ordering::Relaxed);
    }
}

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut guard = STATE.lock().unwrap_or_else(|p| p.into_inner());
    f(guard.get_or_insert_with(State::default))
}

fn log_end(t: &Timeline, outcome: &'static str, now: Instant) {
    tracing::info!(
        target: "yadorilink::join_timeline",
        attempt = t.attempt,
        device = %t.device,
        milestones_reached = t.offsets.iter().filter(|o| o.is_some()).count() as u64,
        since_start_ms = now.saturating_duration_since(t.start).as_millis() as u64,
        reconcile_rounds = t.rounds,
        outcome,
        "join timeline ended without a first file"
    );
}

/// Starts (or restarts) the attempt for this device and group, records
/// [`Milestone::JoinAccepted`], and returns the attempt's correlation id.
pub fn begin(device_id: &str, group_id: &str) -> u64 {
    let now = Instant::now();
    let attempt = NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    with_state(|state| {
        state.sweep(now);
        if let Some(existing) = state.find(device_id, group_id) {
            // The first overlap turns the sample ambiguous (one event); any
            // further overlap adds nothing, so state stays bounded.
            if !std::mem::replace(&mut existing.ambiguous, true) {
                tracing::info!(
                    target: "yadorilink::join_timeline",
                    attempt,
                    device = %device_id,
                    group = %group_id,
                    "ambiguous overlapping join, sample discarded"
                );
            }
            return;
        }
        if state.len() >= MAX_TRACKED {
            let oldest = state
                .active
                .iter()
                .flat_map(|(g, l)| l.iter().map(move |t| (t.start, t.device.clone(), g.clone())))
                .min();
            if let Some((_, device, group)) = oldest {
                state.remove(&device, &group);
            }
        }
        let mut timeline = Timeline {
            attempt,
            ambiguous: false,
            device: device_id.to_owned(),
            start: now,
            prev: now,
            offsets: [None; MILESTONES],
            rounds: 0,
        };
        timeline.offsets[Milestone::JoinAccepted.index()] = Some(Duration::ZERO);
        state.active.entry(group_id.to_owned()).or_default().push(timeline);
        state.publish_count();
    });
    tracing::info!(
        target: "yadorilink::join_timeline",
        attempt,
        device = %device_id,
        group = %group_id,
        milestone = Milestone::JoinAccepted.name(),
        since_start_ms = 0u64,
        since_prev_ms = 0u64,
        reconcile_rounds = 0u32,
        "join timeline milestone"
    );
    attempt
}

/// Ends the attempt without a first file (the join failed, or the share has
/// nothing to materialize), so the hot path stops paying for it. Only the
/// attempt `begin` returned is ended: a newer join of the same group on this
/// device is left alone.
pub fn abandon(device_id: &str, group_id: &str, attempt: u64) {
    let now = Instant::now();
    with_state(|state| {
        // An ambiguous sample is never ended by an abandon (it cannot tell
        // which attempt is calling): it closes at the harness or at expiry.
        let remove =
            state.find(device_id, group_id).is_some_and(|t| !t.ambiguous && t.attempt == attempt);
        if remove {
            if let Some(t) = state.remove(device_id, group_id) {
                log_end(&t, "abandoned", now);
            }
        }
        state.publish_count();
    });
}

/// Records `milestone` for the attempt the first time it is reached. A no-op
/// when no join timeline is active for this device and group.
#[inline]
pub fn mark(device_id: &str, group_id: &str, milestone: Milestone) {
    if ACTIVE.load(Ordering::Relaxed) == 0 {
        return;
    }
    mark_slow(device_id, group_id, milestone, None);
}

/// [`mark`], also naming the peer device the milestone involved.
#[inline]
pub fn mark_with_peer(device_id: &str, group_id: &str, milestone: Milestone, peer: &str) {
    if ACTIVE.load(Ordering::Relaxed) == 0 {
        return;
    }
    mark_slow(device_id, group_id, milestone, Some(peer));
}

/// [`mark`] for every active attempt of `device_id`, whatever its group.
/// For events that are not about one group (a netmap frame arriving).
#[inline]
pub fn mark_device(device_id: &str, milestone: Milestone) {
    if ACTIVE.load(Ordering::Relaxed) == 0 {
        return;
    }
    let now = Instant::now();
    let recorded: Vec<(String, (u64, Duration, Duration, u32))> = with_state(|state| {
        state.sweep(now);
        let groups: Vec<String> = state
            .active
            .iter()
            .filter(|(_, list)| list.iter().any(|t| t.device == device_id))
            .map(|(group, _)| group.clone())
            .collect();
        let recorded = groups
            .into_iter()
            .filter_map(|group| {
                let r = record(state, device_id, &group, milestone, now)?;
                Some((group, r))
            })
            .collect();
        state.publish_count();
        recorded
    });
    for (group, r) in recorded {
        log_milestone(device_id, &group, milestone, None, r);
    }
}

/// Whether any join timeline is being recorded (one relaxed load), so a call
/// site that must do work to build a `mark` argument can skip it.
#[inline]
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Relaxed) != 0
}

/// Counts one anti-entropy round, so each milestone can say whether periodic
/// rounds had to run before progress resumed.
#[inline]
pub fn note_reconcile_round(device_id: &str, group_id: &str) {
    if ACTIVE.load(Ordering::Relaxed) == 0 {
        return;
    }
    with_state(|state| {
        state.sweep(Instant::now());
        if let Some(timeline) = state.find(device_id, group_id).filter(|t| !t.ambiguous) {
            timeline.rounds = timeline.rounds.saturating_add(1);
        }
        state.publish_count();
    });
}

fn mark_slow(device_id: &str, group_id: &str, milestone: Milestone, peer: Option<&str>) {
    let now = Instant::now();
    let recorded = with_state(|state| {
        state.sweep(now);
        let recorded = record(state, device_id, group_id, milestone, now);
        state.publish_count();
        recorded
    });
    if let Some(recorded) = recorded {
        log_milestone(device_id, group_id, milestone, peer, recorded);
    }
}

/// Records `milestone` for the attempt the first time it is reached and
/// returns `(attempt, since start, since previous, reconcile rounds)`.
fn record(
    state: &mut State,
    device_id: &str,
    group_id: &str,
    milestone: Milestone,
    now: Instant,
) -> Option<(u64, Duration, Duration, u32)> {
    let recorded = (|| {
        let timeline = state.find(device_id, group_id)?;
        if timeline.ambiguous {
            return None;
        }
        if timeline.offsets[milestone.index()].is_some() {
            return None;
        }
        let since_start = now.saturating_duration_since(timeline.start);
        let since_prev = now.saturating_duration_since(timeline.prev);
        timeline.offsets[milestone.index()] = Some(since_start);
        timeline.prev = now;
        Some((timeline.attempt, since_start, since_prev, timeline.rounds))
    })();
    // An ambiguous sample never completes: it stays (recording nothing)
    // until every overlapping attempt abandons, the harness takes it, or
    // it expires, so a later join cannot inherit those attempts' events.
    if recorded.is_some() && milestone == Milestone::FirstFileCommitted {
        if let Some(done) = state.remove(device_id, group_id) {
            if state.finished.len() >= MAX_TRACKED {
                state.finished.remove(0);
            }
            state.finished.push((
                device_id.to_owned(),
                group_id.to_owned(),
                Finished {
                    attempt: done.attempt,
                    ambiguous: done.ambiguous,
                    offsets: done.offsets,
                    reconcile_rounds: done.rounds,
                },
            ));
        }
    }
    recorded
}

fn log_milestone(
    device_id: &str,
    group_id: &str,
    milestone: Milestone,
    peer: Option<&str>,
    (attempt, since_start, since_prev, rounds): (u64, Duration, Duration, u32),
) {
    tracing::info!(
        target: "yadorilink::join_timeline",
        attempt,
        device = %device_id,
        group = %group_id,
        peer = peer.unwrap_or(""),
        milestone = milestone.name(),
        since_start_ms = since_start.as_millis() as u64,
        since_prev_ms = since_prev.as_millis() as u64,
        reconcile_rounds = rounds,
        "join timeline milestone"
    );
}

/// Removes and returns the finished timeline, if any.
pub fn take_finished(device_id: &str, group_id: &str) -> Option<Finished> {
    with_state(|state| {
        let at = state.finished.iter().position(|(d, g, _)| d == device_id && g == group_id)?;
        Some(state.finished.remove(at).2)
    })
}

/// Like [`take_finished`], but when the first file was never marked returns
/// (and drops) the partial timeline instead, so a harness can see how far an
/// attempt got.
pub fn take_finished_or_partial(device_id: &str, group_id: &str) -> Option<Finished> {
    if let Some(done) = take_finished(device_id, group_id) {
        return Some(done);
    }
    with_state(|state| {
        let partial = state.remove(device_id, group_id)?;
        state.publish_count();
        Some(Finished {
            attempt: partial.attempt,
            ambiguous: partial.ambiguous,
            offsets: partial.offsets,
            reconcile_rounds: partial.rounds,
        })
    })
}

/// `Some(true)` once the first file was marked, `Some(false)` while an attempt
/// is still waiting for it, `None` when there is none.
pub fn peek_complete(device_id: &str, group_id: &str) -> Option<bool> {
    with_state(|state| {
        if state.finished.iter().any(|(d, g, _)| d == device_id && g == group_id) {
            Some(true)
        } else {
            state.find(device_id, group_id).map(|_| false)
        }
    })
}

/// Milestones in order, for printing a [`Finished`].
pub fn milestones() -> [Milestone; MILESTONES] {
    Milestone::ALL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_wide_mark_reaches_only_that_devices_attempts() {
        let (dev, group) = ("unit-dev-wide", "join-timeline-wide-group");
        begin(dev, group);
        begin("unit-dev-other", "join-timeline-wide-other-group");
        mark_device(dev, Milestone::NetmapReceived);
        mark_device(dev, Milestone::NetmapReceived); // once per attempt
        mark(dev, group, Milestone::FirstFileCommitted);
        let done = take_finished(dev, group).expect("finished");
        assert!(done.offsets[Milestone::NetmapReceived.index()].is_some());
        let other = take_finished_or_partial("unit-dev-other", "join-timeline-wide-other-group")
            .expect("partial");
        assert!(other.offsets[Milestone::NetmapReceived.index()].is_none());
    }

    #[test]
    fn records_each_milestone_once_and_finishes() {
        let (dev, group) = ("unit-dev", "join-timeline-unit-group");
        mark(dev, group, Milestone::LinkReady); // no timeline: no-op
        let attempt = begin(dev, group);
        mark(dev, group, Milestone::LinkReady);
        mark(dev, group, Milestone::LinkReady);
        // Another device in the same process does not feed this attempt.
        mark("other-dev", group, Milestone::BlockRequestSent);
        note_reconcile_round(dev, group);
        mark_with_peer(dev, group, Milestone::FirstFileCommitted, "peer");
        mark(dev, group, Milestone::BlockRequestSent); // finished: no-op
        let done = take_finished(dev, group).expect("finished");
        assert_eq!(done.attempt, attempt);
        assert!(done.offsets[Milestone::LinkReady.index()].is_some());
        assert!(done.offsets[Milestone::BlockRequestSent.index()].is_none());
        assert_eq!(done.reconcile_rounds, 1);
        assert!(take_finished(dev, group).is_none());
    }

    #[test]
    fn an_abandoned_attempt_stops_recording() {
        let (dev, group) = ("unit-dev-2", "join-timeline-abandon-group");
        let attempt = begin(dev, group);
        abandon(dev, group, attempt + 1000); // a different attempt: ignored
        assert_eq!(peek_complete(dev, group), Some(false));
        abandon(dev, group, attempt);
        assert_eq!(peek_complete(dev, group), None);
        mark(dev, group, Milestone::LinkReady);
        assert!(take_finished_or_partial(dev, group).is_none());
    }

    #[test]
    fn a_stale_attempt_is_dropped_on_the_event_path_and_the_hot_path_goes_idle() {
        let (dev, group) = ("unit-dev-3", "join-timeline-expiry-group");
        begin(dev, group);
        // Age this attempt (only) past the deadline, then let any event sweep.
        with_state(|state| {
            let t = state.find(dev, group).expect("active");
            t.start = t.start.checked_sub(MAX_AGE + Duration::from_secs(1)).unwrap_or(t.start);
        });
        mark("some-other-device", "some-other-group", Milestone::LinkReady);
        assert_eq!(peek_complete(dev, group), None);
        mark(dev, group, Milestone::LinkReady);
        assert!(take_finished_or_partial(dev, group).is_none());
    }

    #[test]
    fn overlapping_joins_make_one_bounded_ambiguous_sample_with_no_output() {
        let (dev, group) = ("unit-dev-4", "join-timeline-overlap-group");
        let first = begin(dev, group);
        mark(dev, group, Milestone::LinkReady);
        let second = begin(dev, group);
        assert_ne!(first, second);
        for _ in 0..100 {
            begin(dev, group); // adds no state
        }
        with_state(|state| {
            assert_eq!(state.active.get(group).map(Vec::len), Some(1));
            // The ambiguity is flagged once; flagging again is not a transition.
            let t = state.find(dev, group).unwrap();
            assert!(t.ambiguous);
            assert!(std::mem::replace(&mut t.ambiguous, true), "already ambiguous");
        });
        // Neither attempt's later milestones are recorded, and abandons
        // (stale or not) never end the sample early.
        mark(dev, group, Milestone::BlockRequestSent);
        note_reconcile_round(dev, group);
        abandon(dev, group, second);
        abandon(dev, group, first);
        abandon(dev, group, first + 10_000);
        assert_eq!(peek_complete(dev, group), Some(false));
        // A first file does not close it either; the harness takes it.
        mark(dev, group, Milestone::FirstFileCommitted);
        begin(dev, group);
        let done = take_finished_or_partial(dev, group).expect("taken");
        assert!(done.ambiguous);
        assert!(done.offsets[Milestone::BlockRequestSent.index()].is_none());
        assert!(done.offsets[Milestone::FirstFileCommitted.index()].is_none());
        assert_eq!(peek_complete(dev, group), None);
    }

    #[test]
    fn an_ambiguous_sample_expires_and_the_hot_path_goes_idle() {
        let (dev, group) = ("unit-dev-5", "join-timeline-overlap-expiry-group");
        begin(dev, group);
        begin(dev, group);
        with_state(|state| {
            let t = state.find(dev, group).expect("active");
            t.start = t.start.checked_sub(MAX_AGE + Duration::from_secs(1)).unwrap_or(t.start);
        });
        mark("some-other-device", "some-other-group", Milestone::LinkReady);
        assert_eq!(peek_complete(dev, group), None);
    }
}
