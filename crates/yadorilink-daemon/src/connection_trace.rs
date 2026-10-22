//! Connection Operations: a bounded, in-memory history of recent
//! connection attempts, plus a connectivity-doctor summary derived from
//! it and other already-tracked daemon state.
//!
//! Bounded diagnostic traces, not verbose raw logs: every field here is
//! a structured category or a project-internal identifier (device id) —
//! never a raw socket address, hostname, or any file
//! content/path, matching this project's content-blindness discipline
//! and mirroring `crate::reporting::error_candidates`'s bounded
//! error-candidate ring buffer:
//! oldest entries are dropped once the cap is reached, this is never
//! durably persisted, and a restart starts the history empty.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runtime_telemetry::RuntimeTelemetry;

/// Bounded, matching this module's own doc comment and every sibling
/// bounded store in this crate (e.g. `reporting::error_candidates`'s cap).
pub const MAX_TRACE_ENTRIES: usize = 500;

fn now_unix_nanos() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

/// Where a connection candidate/attempt came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSource {
    /// The coordination plane itself -- its netmap subscription. The only
    /// source left: finding a path to a PEER belongs to the iroh endpoint,
    /// which reports no per-candidate attempt this log could record.
    CoordinationPlane,
}

impl CandidateSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CandidateSource::CoordinationPlane => "coordination_plane",
        }
    }
}

/// Coarse address class — never a raw IP/hostname/port, per this
/// module's redaction requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// A generic wide-area address (e.g. the coordination plane itself).
    Wan,
    Unknown,
}

impl AddressClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressClass::Wan => "wan",
            AddressClass::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    Connected,
    Failed,
    Rejected,
}

impl AttemptOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            AttemptOutcome::Connected => "connected",
            AttemptOutcome::Failed => "failed",
            AttemptOutcome::Rejected => "rejected",
        }
    }
}

/// One structured connection-attempt record — candidate source, coarse
/// address class, outcome, latency, failure category,
/// whether this attempt became the selected path, and the authorization
/// decision. `peer_device_id` is empty for an attempt that isn't
/// peer-specific (e.g. the coordination-plane netmap subscription itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAttemptTrace {
    pub peer_device_id: String,
    pub candidate_source: &'static str,
    pub address_class: &'static str,
    pub outcome: &'static str,
    pub latency_ms: u64,
    /// A stable, short category (e.g. `TransportError::category`) —
    /// never the raw error text, which can embed address/protocol detail.
    /// Empty for a successful attempt.
    pub failure_category: String,
    /// Whether this attempt is (or became) the path currently in use.
    pub selected: bool,
    /// "authorized" | "denied" | "n/a".
    pub authorization_decision: &'static str,
    pub recorded_at_unix_nanos: i64,
}

#[derive(Default)]
pub struct ConnectionTraceLog {
    entries: Mutex<VecDeque<ConnectionAttemptTrace>>,
}

impl ConnectionTraceLog {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        peer_device_id: impl Into<String>,
        candidate_source: CandidateSource,
        address_class: AddressClass,
        outcome: AttemptOutcome,
        latency_ms: u64,
        failure_category: impl Into<String>,
        selected: bool,
        authorized: Option<bool>,
    ) {
        let entry = ConnectionAttemptTrace {
            peer_device_id: peer_device_id.into(),
            candidate_source: candidate_source.as_str(),
            address_class: address_class.as_str(),
            outcome: outcome.as_str(),
            latency_ms,
            failure_category: failure_category.into(),
            selected,
            authorization_decision: match authorized {
                Some(true) => "authorized",
                Some(false) => "denied",
                None => "n/a",
            },
            recorded_at_unix_nanos: now_unix_nanos(),
        };
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.push_back(entry);
        while entries.len() > MAX_TRACE_ENTRIES {
            entries.pop_front();
        }
    }

    /// Most recent entries first, optionally filtered to one peer.
    pub fn recent(&self, peer_device_id: Option<&str>) -> Vec<ConnectionAttemptTrace> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .rev()
            .filter(|e| peer_device_id.is_none_or(|p| e.peer_device_id == p))
            .cloned()
            .collect()
    }
}

/// Connectivity-doctor categories. Each category's status is
/// derived from state this daemon already tracks cheaply (task liveness,
/// live peer statuses, this trace log, and folder-link pause state) —
/// deliberately not a full active network probe. Where the underlying
/// signal can't distinguish "this specific subsystem is down" from a
/// related-but-coarser condition, that's documented on the category
/// itself rather than left implicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCategory {
    pub name: &'static str,
    /// "ok" | "warn" | "error".
    pub status: &'static str,
    pub detail: String,
}

fn category(
    name: &'static str,
    ok: bool,
    warn_detail: impl Into<String>,
    ok_detail: &'static str,
) -> DoctorCategory {
    if ok {
        DoctorCategory { name, status: "ok", detail: ok_detail.to_string() }
    } else {
        DoctorCategory { name, status: "warn", detail: warn_detail.into() }
    }
}

pub fn run_connectivity_doctor(
    telemetry: &RuntimeTelemetry,
    sync_state: &crate::replica_coordinator::ReplicaCoordinator,
    device_id: &str,
) -> Vec<DoctorCategory> {
    let mut out = Vec::new();

    // "daemon": trivially true — this function is running inside it.
    out.push(DoctorCategory {
        name: "daemon",
        status: "ok",
        detail: "daemon process is running".to_string(),
    });

    let control_socket_alive = telemetry.task_alive("control-socket", true);
    let peer_orchestrator_alive = telemetry.task_alive("peer-orchestrator", true);

    out.push(category(
        "listener",
        control_socket_alive,
        "local control-socket listener task is not running",
        "local control-socket listener is running",
    ));

    // A dead `peer_orchestrator` task means the coordination-plane
    // subscription is certainly down; a live one means only that it has
    // not crashed, not that it is healthy right now (the recent trace
    // evidence below narrows that further). Peer-path failures are
    // surfaced per-attempt through the connection trace log itself, not as
    // a coarse doctor category: finding a path to a peer belongs to the
    // iroh endpoint, which does not report a candidate set this device
    // could enumerate.
    let recent = telemetry.recent_connection_attempts(None);
    let recent_window = recent.iter().take(50);
    let mut coordination_seen_ok = false;
    let mut denied_count = 0u32;
    for trace in recent_window {
        let ok = trace.outcome == "connected";
        if trace.candidate_source == "coordination_plane" {
            coordination_seen_ok |= ok;
        }
        if trace.authorization_decision == "denied" {
            denied_count += 1;
        }
    }

    out.push(category(
        "coordination_plane",
        peer_orchestrator_alive && (coordination_seen_ok || recent.is_empty()),
        "no recent successful coordination-plane connection observed",
        "peer-orchestrator task is running",
    ));
    out.push(if denied_count > 0 {
        DoctorCategory {
            name: "authorization",
            status: "warn",
            detail: format!(
                "{denied_count} recent connection attempt(s) were denied authorization"
            ),
        }
    } else {
        DoctorCategory {
            name: "authorization",
            status: "ok",
            detail: "no recent authorization denials".to_string(),
        }
    });

    let clock_ok = SystemTime::now().duration_since(UNIX_EPOCH).is_ok();
    out.push(category(
        "clock_config",
        clock_ok,
        "system clock reads before the Unix epoch",
        "system clock is readable and sane",
    ));

    // Diagnostics only. An unreadable link table yields an empty list, which
    // reports "not all paused" -- the non-alarming direction -- so surface the
    // read failure rather than collapsing it silently into a clean bill of
    // health for a daemon that cannot read its own state.
    let links = sync_state.link_repository().list_links().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cannot read link table; doctor policy check is not meaningful");
        Vec::new()
    });
    let all_paused = !links.is_empty() && links.iter().all(|l| l.paused);
    out.push(if all_paused {
        DoctorCategory {
            name: "policy_disabled",
            status: "warn",
            detail: "every linked folder is currently paused".to_string(),
        }
    } else {
        DoctorCategory {
            name: "policy_disabled",
            status: "ok",
            detail: "at least one linked folder is active".to_string(),
        }
    });

    // A Change this device authored but has not yet had checkpointed
    // is not just "not synced yet" -- it is structurally
    // invisible to every peer until this device reconnects and a checkpoint
    // flush succeeds. Surfacing the count distinctly from ordinary sync lag
    // matters because the cause is different (writer-status refusal or
    // coordination-plane unreachability, not peer unavailability) and the
    // fix is different (reconnect, or regain write access) -- collapsing it
    // into a generic "N changes unsynced" reading would point a user at the
    // wrong remedy.
    let mut group_ids: Vec<&str> =
        links.iter().filter(|l| !l.paused && !l.orphaned).map(|l| l.group_id.as_str()).collect();
    group_ids.sort_unstable();
    group_ids.dedup();
    let db = sync_state.database();
    let pending_count: usize = group_ids
        .iter()
        .map(|group_id| {
            db.read(|conn| {
                yadorilink_sync_sqlite::native_publication::pending_native_deltas_for_device(
                    conn,
                    &yadorilink_replica_domain::ids::FolderGroupId((*group_id).to_owned()),
                    device_id,
                )
            })
            .map(|deltas| deltas.len())
            .unwrap_or_else(|e| {
                tracing::warn!(
                    group_id, error = %e,
                    "cannot read pending-checkpoint count; doctor checkpoint_pending check is not meaningful"
                );
                0
            })
        })
        .sum();
    out.push(if pending_count > 0 {
        DoctorCategory {
            name: "checkpoint_pending",
            status: "warn",
            detail: format!(
                "{pending_count} locally-authored change(s) are not yet checkpointed -- \
                 invisible to peers until the next successful reconnect flush"
            ),
        }
    } else {
        DoctorCategory {
            name: "checkpoint_pending",
            status: "ok",
            detail: "no locally-authored changes are waiting on a checkpoint".to_string(),
        }
    });

    // Peer reachability: the biggest gap this whole category list used to
    // have. `coordination_plane` above answers "is the mechanism that
    // FINDS peers alive"; it says nothing about whether any
    // SPECIFIC peer this device has actually been trying to reach is
    // reachable right now. That per-attempt detail was already recorded
    // (`connections`/`traces` prints it) but never fed back into this
    // summary -- so a peer stuck in a long run of `no_response` failures
    // produced an all-green `doctor` report while sync was completely
    // stalled, exactly the failure this section closes.
    //
    // Per peer (not per attempt): look at that peer's own most recent
    // attempts specifically (`recent_connection_attempts(Some(peer))`, not
    // the coarser top-50-of-everything window above), across every
    // candidate source -- a peer that connected via ANY path recently is
    // fine, regardless of whether THIS one was direct. Warn only once
    // enough attempts have piled up with zero successes among them:
    // `PEER_UNREACHABLE_MIN_ATTEMPTS` rules out flagging a single transient
    // retry, and `PEER_UNREACHABLE_LOOKBACK` bounds the check to recent
    // behavior so a peer that WAS unreachable an hour ago but has since
    // reconnected isn't held responsible for old history.
    let mut peer_ids: Vec<&str> = recent
        .iter()
        .map(|trace| trace.peer_device_id.as_str())
        .filter(|id| !id.is_empty())
        .collect();
    peer_ids.sort_unstable();
    peer_ids.dedup();
    for peer in peer_ids {
        let peer_recent = telemetry.recent_connection_attempts(Some(peer));
        let lookback: Vec<&ConnectionAttemptTrace> =
            peer_recent.iter().take(PEER_UNREACHABLE_LOOKBACK).collect();
        let attempts = lookback.len();
        let connected_recently = lookback.iter().any(|trace| trace.outcome == "connected");
        if !connected_recently && attempts >= PEER_UNREACHABLE_MIN_ATTEMPTS {
            let reason = lookback
                .first()
                .map(|trace| trace.failure_category.as_str())
                .filter(|category| !category.is_empty())
                .unwrap_or("unknown");
            out.push(DoctorCategory {
                name: "peer_reachability",
                status: "warn",
                detail: format!(
                    "peer {peer} has not connected in the last {attempts} attempt(s) \
                     (most recent failure: {reason})"
                ),
            });
        }
    }

    out
}

/// How many of a peer's own most recent connection attempts to look at when
/// deciding whether it currently reads as unreachable.
const PEER_UNREACHABLE_LOOKBACK: usize = 10;

/// How many of those attempts must exist (all failed) before this is
/// reported as sustained failure rather than one-off retry noise.
const PEER_UNREACHABLE_MIN_ATTEMPTS: usize = 3;

#[cfg(test)]
mod tests;
