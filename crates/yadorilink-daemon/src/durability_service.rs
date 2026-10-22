//! Owns this device's view of folder-group durability: which groups are
//! latched `Unknown` (a `--force` override bypassed the handoff
//! gate for that group and its status must not report `Protected` again
//! until a real whole-group handoff re-check clears it), the pure
//! precedence [`classify`] applies to derive a group's status from the
//! facts `DaemonState` gathers, and the injectable custody confirmer the
//! on-demand eviction path uses to verify a specific version's blocks are
//! durably held elsewhere before reclaiming them locally.
//!
//! `group_durability_latch`/`custody_confirmer` are private, reached only
//! through this type's own methods. `classify` itself is a free function
//! taking plain facts, not a method, so it can be table-driven-tested in
//! isolation from any real `SyncState`/atomics -- `DaemonState::
//! group_durability_status` is the one place that gathers those facts and
//! calls it.
//!
//! # Canonical durability model
//!
//! `GroupDurabilityStatus` is this daemon's one authoritative "is this
//! group's data protected" derivation — every other surface (IPC/wire
//! DTOs, CLI, desktop app) must project from it rather than reconstructing
//! an equivalent judgment from lower-level booleans. Core invariant:
//! **Durability != Connectivity.** This module never reads
//! `PeerReachability`, relay route state, or any other connectivity
//! signal, and must never be changed to. A group being `Protected` says
//! nothing about whether it can be fetched *right now*; a peer being
//! online/reachable says nothing about whether this group is `Protected`.
//! See [`crate::route`]'s own doc comment for the parallel invariant on the
//! connectivity side.
//!
//! `Protected` requires real peer-confirmed evidence
//! (`DaemonState::full_replica_handoff_ready`, an exact-version-hash,
//! generation-stability-checked round-trip -- this is ALSO how a
//! genuinely-empty group reaches `Protected`, since that function's own real
//! durability-root enumeration confirms a vacuous root set exactly like a
//! non-empty one; there is deliberately no separate "does this device's
//! local file count look like zero" shortcut, since that would miss
//! retained/trash-restorable durability roots). The evidence is cached
//! with a staleness bound (monotonic clock) AND a membership-generation
//! binding by `DurabilityConfirmationJob`'s periodic sweep -- either aging
//! out or any peer netmap change since the confirmation invalidates it.
//! This device's own local materialization completeness is never
//! sufficient on its own: a device with a fully materialized local copy
//! and zero peer confirmation must never report `Protected`, since no peer
//! may hold the group at all.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::RootSetSummary;
use yadorilink_replica_engine::custody::CustodyStamp;
use yadorilink_sync_sqlite::file_index::FileIndexRepository;

use crate::background_custody::BackgroundCustodyEvidence;

/// This device's local, UI-facing view of one group's durability — distinct
/// from the coordination-plane member/share count (which only tracks who is
/// *configured* to sync a group, not who durably holds its data right now)
/// and distinct from `DegradedLinkInfo` (that's disk
/// pressure, an orthogonal axis). Answers "how safe is my data right now,
/// from what this daemon can currently confirm" — and must never overstate
/// safety: a group this daemon has no current basis to back up with a real
/// confirmation reports `Unknown`, never `Protected`.
///
/// See [`classify`] for how the unlatched default is derived, and
/// [`DurabilityService::latch_unknown`] for the one place that pins a group
/// to `Unknown` regardless of what it would otherwise derive to.
/// Canonical durability model: `Protected` (positively verified),
/// `Protecting` (verification work in progress), `Unknown` (cannot
/// currently prove either way), `AtRisk` (positively known insufficient).
/// Originally shipped under the names Healthy/Syncing/DurabilityUnknown/
/// KnownMissing and later renamed to this vocabulary,
/// once every call site (including the wire proto mirror) could be swept
/// in one pass rather than piecemeal.
///
/// Critical invariant, load-bearing across every derivation in this file:
/// `Protected`/`AtRisk` must be earned by *peer-confirmed* evidence or
/// a positively-known structural fact — never by this device's own local
/// state alone. "Durability != Connectivity": nothing here ever reads
/// `PeerReachability`/relay route state, and this device being reachable
/// or a peer being online never upgrades a group's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupDurabilityStatus {
    /// Positively verified: the group has no current files at all (nothing
    /// to protect), or a confirmed peer full replica recently proved (via
    /// `DaemonState::full_replica_handoff_ready`, an exact-version-hash,
    /// generation-stability-checked peer round-trip) that it holds the
    /// group's entire current durability-root set. Never derived from this
    /// device's own local materialization state alone.
    Protected,
    /// This device is itself a full replica for this group and is still
    /// catching up to head (not every file materialized yet) — durability
    /// work in progress, not yet confirmed, not yet known insufficient.
    Protecting,
    /// Coverage cannot currently be confirmed — either a daemon-wide
    /// "cannot currently confirm" condition applies (latch-table load
    /// failure, unresolved unknown-scope removal, recovery-blocked
    /// membership operation, a `--force`-induced per-group latch), or no
    /// peer full replica is configured to have failed the structural
    /// `AtRisk` check but no fresh peer confirmation exists either
    /// (e.g. an On-Demand device whose only full-replica peer hasn't been
    /// reconfirmed since the last sweep). The fail-safe default whenever
    /// this daemon has no other basis to report from.
    Unknown,
    /// Positively known insufficient: no device other than this one is
    /// currently configured (netmap-derived) as an authorized-writer full
    /// replica for this group. Not "unconfirmed" — a structural fact that
    /// no amount of waiting for a peer round-trip will resolve on its own.
    AtRisk,
}

/// What kind of evidence currently backs a group's [`GroupDurabilityStatus`].
///
/// A separate axis from the status itself, deliberately. "Is this group
/// protected" and "how do you know" have different answers and different
/// audiences, and collapsing them into one enum is what let a background
/// health check be mistaken for a safety proof in the first place.
///
/// Nothing decides anything from this. It is reported, and it is what a
/// person or a support transcript reads to tell the routine answer from the
/// strong one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityEvidence {
    /// No current evidence of either kind.
    None,
    /// A peer recently reported a durable index matching this device's own
    /// current state, and reported itself a full replica holding all of it.
    /// The ordinary steady state, refreshed every ninety seconds at the cost
    /// of one round-trip per group.
    ///
    /// An index-level claim the peer makes about itself. It does not
    /// establish that the bytes are on that peer's disk, nor that any of
    /// them are intact.
    CorroboratedIndex,
    /// A peer read back and re-verified the checksum of every block of every
    /// durability root -- current and retained history alike -- recently
    /// enough to still count.
    ///
    /// What `Protected` used to mean always, before establishing it every
    /// ninety seconds proved to cost one whole-file re-read per root. It is
    /// still what every destructive action establishes for itself, at the
    /// moment it acts; this value simply says that one of them ran recently
    /// and its answer is still current.
    VerifiedPayload,
}

/// Whether every current file in a group is already fully materialized
/// locally, or some are still catching up -- `DaemonState`'s reduction of
/// `SyncState::materialization_counts`' richer result down to just what
/// [`classify`] needs, so this module doesn't depend on `SyncState`'s
/// counts type directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializationHealth {
    /// Every current file is `Present` locally.
    FullyLocal,
    /// At least one current file is still a placeholder or hydrating.
    Partial,
}

/// The complete set of inputs [`classify`] derives a group's durability
/// status from. `latched_unknown` comes from `DurabilityService`'s own
/// latch table (so `DurabilityService::classify` fills it in); every other
/// field comes from `DurabilityService`'s own fail-closed flags or `SyncState`.
#[derive(Debug, Clone)]
pub struct DurabilityFacts {
    /// The persisted durability-latch table itself failed to load at
    /// startup -- every group is unknown until that's resolved, since this
    /// daemon cannot tell which ones were actually latched.
    pub latch_load_failed: bool,
    /// A `--force` removal proceeded with an unverified blast radius —
    /// every group is potentially at risk until that scope is resolved,
    /// since there is no per-group latch to narrow this down to.
    pub scope_unknown: bool,
    /// A membership operation reached `RecoveryBlocked` — automatic
    /// recovery was refused, and this device cannot currently confirm
    /// whether the forced groups it names are durably latched.
    pub recovery_blocked: bool,
    /// `group_id` is pinned to `Unknown` in `DurabilityService`'s
    /// own latch table (a `--force` override bypassed the handoff gate for
    /// it), overriding whatever `materialization` would otherwise derive.
    pub latched_unknown: bool,
    /// This group's policy/membership snapshot is marked stale
    /// (`PeerAuthorityState::is_group_policy_stale`) -- the daemon has explicitly
    /// flagged that it cannot currently trust who is authorized to write
    /// or hold this group, so any cached peer confirmation may rest on an
    /// authorization this daemon no longer believes. Treated exactly like
    /// the other daemon-wide "cannot currently confirm" facts.
    pub group_policy_stale: bool,
    /// This group's current materialization state, or `Err` if it
    /// couldn't even be read.
    pub materialization: Result<MaterializationHealth, ()>,
    /// This device's own storage mode for this group is a full replica
    /// (eager/"store everything") — the only case where local
    /// materialization state (`materialization`) is allowed to influence
    /// the result at all, and even then only to decide `Protecting`, never
    /// `Protected`.
    pub is_local_full_replica: bool,
    /// Netmap-derived, content-blind: at least one device other than this
    /// one is currently configured as an authorized-writer full replica
    /// for this group. `false` makes `AtRisk` a positively-known
    /// conclusion, not merely "not yet confirmed" -- but only once
    /// `ever_confirmation_swept` is also true (see that field's own doc
    /// comment for why).
    pub any_other_full_replica_peer_configured: bool,
    /// A whole-group peer-confirmed custody check
    /// (`full_replica_handoff_ready`) succeeded within this daemon's
    /// staleness bound and under the current membership generation. The
    /// ONLY source of `Protected` — see this module's doc comment for why
    /// local materialization state must never substitute for it. This is
    /// ALSO how a genuinely-empty group (nothing to protect) reaches
    /// `Protected`: `full_replica_handoff_ready`'s own real durability-root
    /// enumeration confirms a vacuous case exactly like a non-empty one,
    /// so there is no separate "group is empty" fact here — deriving
    /// emptiness from this device's own locally-visible file count would
    /// miss retained/trash-restorable durability roots.
    pub peer_confirmed_custody: bool,
    /// At least one `DurabilityConfirmationJob` sweep round has ever run
    /// for this group (regardless of whether it confirmed anything).
    /// `false` means this daemon hasn't checked yet at all -- distinct
    /// from "checked and found no confirming peer" -- so `classify` must
    /// not jump straight to the structural `AtRisk` conclusion
    /// before the very first sweep has even had a chance to run (most
    /// visible right after daemon startup).
    pub ever_confirmation_swept: bool,
    /// Positively confirmed,
    /// not merely inferred from connectivity/timing, that at least one
    /// currently-required path's content has NO obtainable/durable holder
    /// among this group's CURRENT authoritative membership -- distinct
    /// from `materialization`'s bare "still Partial locally", which alone
    /// cannot tell "still trying, may yet succeed" apart from "genuinely,
    /// permanently gone". Computed by `DaemonState::group_durability_
    /// status` from real evidence for each locally-required (repair-
    /// candidate) path: (1) it is still justified by a live native head and (2) missing
    /// locally -- both implied by being a repair candidate at all; (3) its
    /// origin device is no longer a netmap-authorized writer for this
    /// group (a real membership departure, not mere offline-ness); and
    /// (4) every OTHER currently-authorized writer has EXPLICITLY,
    /// definitively refused a fetch for this exact path
    /// (`block_fetch_refusals`, written only on `FetchOutcome::Rejected`,
    /// never on a transient `NotFound`/`TimedOut`/`Busy` miss). An
    /// offline-but-still-authorized writer that has simply never been
    /// asked leaves this `false` (Unknown/Protecting territory, not
    /// AtRisk) -- see `classify`'s own doc comment for why this must
    /// never be inferred from connectivity alone.
    pub known_unobtainable_required_content: bool,
}

/// Derives a group's durability status from `facts` alone, in the exact
/// precedence `DaemonState::group_durability_status` always has.
///
/// Precedence, in order — deliberately load-bearing, the actual
/// fail-*safe* property, not an implementation detail:
/// 1. Any daemon-wide/latched "cannot currently confirm" fact
///    (including `group_policy_stale`), or an unreadable materialization
///    read, wins outright -> `Unknown`.
/// 2. `peer_confirmed_custody` -> `Protected` (the ONLY path to `Protected`;
///    never local materialization alone, never merely "the group looks
///    empty locally").
/// 3. Not yet `ever_confirmation_swept` -> `Unknown` (haven't
///    checked at all yet — could still turn out empty or protected once
///    the first sweep runs; must not be reported as known-insufficient).
/// 4. No other full-replica peer configured -> `AtRisk` (positively
///    known insufficient, checked before falling back to "still catching
///    up" so a lone full replica with no peer never reports `Protecting` as
///    if a peer confirmation were merely pending).
/// 5. `known_unobtainable_required_content` -> `AtRisk` (positively confirmed, not inferred from connectivity alone, that
///    some currently-required content has no obtainable holder among
///    current membership -- checked before falling back to `Protecting`
///    for the identical reason as step 4: this is a known-insufficient
///    conclusion, not a "still catching up" one, even though local
///    materialization is also `Partial` in this case).
/// 6. This device is itself a full replica still catching up locally ->
///    `Protecting`.
/// 7. Otherwise -> `Unknown` (a peer full replica is configured
///    but no fresh confirmation exists yet — e.g. an On-Demand device
///    waiting on the next confirmation sweep).
///
/// If real behavior and this precedence ever disagree, real behavior wins;
/// update this function (and its table-driven tests below) to match, not
/// the other way around.
pub fn classify(facts: &DurabilityFacts) -> GroupDurabilityStatus {
    if evidence_distrusted(facts) {
        return GroupDurabilityStatus::Unknown;
    }
    if facts.peer_confirmed_custody {
        return GroupDurabilityStatus::Protected;
    }
    if !facts.ever_confirmation_swept {
        return GroupDurabilityStatus::Unknown;
    }
    if !facts.any_other_full_replica_peer_configured {
        return GroupDurabilityStatus::AtRisk;
    }
    if facts.known_unobtainable_required_content {
        return GroupDurabilityStatus::AtRisk;
    }
    if facts.is_local_full_replica
        && matches!(facts.materialization, Ok(MaterializationHealth::Partial))
    {
        return GroupDurabilityStatus::Protecting;
    }
    GroupDurabilityStatus::Unknown
}

/// Any daemon-wide/latched "cannot currently confirm" fact, or an unreadable
/// materialization read: `classify`'s first, outright `Unknown`.
fn evidence_distrusted(facts: &DurabilityFacts) -> bool {
    facts.latch_load_failed
        || facts.scope_unknown
        || facts.recovery_blocked
        || facts.latched_unknown
        || facts.group_policy_stale
        || facts.materialization.is_err()
}

/// Whether `classify` answers `Unknown` only because this daemon has not run
/// its first custody check for the group yet: no fact makes the evidence
/// untrustworthy, nothing has confirmed custody, and no check round has
/// happened. Transient by construction -- the first round clears it.
pub fn first_check_pending(facts: &DurabilityFacts) -> bool {
    !evidence_distrusted(facts) && !facts.peer_confirmed_custody && !facts.ever_confirmation_swept
}

/// Confirms whether a full replica durably holds an exact file version — bound
/// by its `change::VersionHash`, with the ordered block list carried alongside
/// for the responder's explicit block/size check and `get()` verification —
/// so an on-demand device may reclaim its own cached copy. Injected onto
/// [`DurabilityService`] so production performs the peer-to-peer version-present
/// query while unit tests supply a deterministic answer without a live peer.
pub trait CustodyConfirmer: Send + Sync {
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp>;

    fn confirmation_still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool;
}

#[cfg(test)]
impl<F: Fn(&str, &str, &VersionHash, &[VersionBlock]) -> bool + Send + Sync> CustodyConfirmer
    for F
{
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        self(group_id, path, version_hash, blocks).then(|| CustodyStamp::new("test-peer".into(), 0))
    }

    fn confirmation_still_valid(
        &self,
        _group_id: &str,
        _path: &str,
        _version_hash: &VersionHash,
        _stamp: &CustodyStamp,
    ) -> bool {
        true
    }
}

/// How often `DurabilityConfirmationJob` re-runs `full_replica_handoff_
/// ready_digest_and_peer` for every linked group, refreshing
/// `DurabilityService::custody_confirmation_cache`. Same cadence as
/// `MATERIALIZATION_REPAIR_SWEEP_INTERVAL` — a whole-group custody check is
/// the same order of cost (one round-trip per group) as a materialization
/// repair pass, so there's no reason for it to run on a different clock.
const CUSTODY_CONFIRMATION_SWEEP_INTERVAL: Duration = Duration::from_secs(90);

static CUSTODY_CONFIRMATION_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS: std::sync::OnceLock<
    Mutex<Option<Duration>>,
> = std::sync::OnceLock::new();

pub fn set_default_custody_confirmation_sweep_interval_for_tests(interval: Duration) {
    *CUSTODY_CONFIRMATION_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = Some(interval);
}

fn default_custody_confirmation_sweep_interval() -> Duration {
    CUSTODY_CONFIRMATION_SWEEP_INTERVAL_OVERRIDE_FOR_TESTS
        .get()
        .and_then(|m| *m.lock().unwrap_or_else(|p| p.into_inner()))
        .unwrap_or(CUSTODY_CONFIRMATION_SWEEP_INTERVAL)
}

/// How stale a `custody_confirmation_cache` entry may be before
/// `group_durability_status` stops trusting it as `Protected` evidence — 3x
/// `CUSTODY_CONFIRMATION_SWEEP_INTERVAL`, so one missed sweep round (a
/// transient peer hiccup, a slow round-trip) doesn't immediately flip a
/// genuinely-protected group to `Unknown`. Deliberately NOT
/// unbounded: past this bound the evidence is old enough that "was
/// protected" stops standing in for "is protected now" — see this module's
/// crate-level `DURABILITY.md` for why stale evidence must never be reported as
/// current.
const CUSTODY_CONFIRMATION_STALENESS_BOUND: Duration = Duration::from_secs(270);

/// One group's most recent `DurabilityConfirmationJob` sweep result — see
/// `DurabilityService::custody_confirmation_cache`'s own doc comment.
#[derive(Debug, Clone)]
struct CustodyConfirmationRecord {
    outcome: BackgroundCustodyEvidence,
    /// Display-only (a future UI surface showing "confirmed 3 min ago").
    /// NEVER used for the staleness gate itself -- `confirmed_at` below is
    /// the monotonic clock that owns that, specifically because this is a
    /// wall-clock value an adjusted system clock could roll backward.
    #[allow(dead_code)]
    confirmed_at_unix: i64,
    /// Monotonic staleness gate -- see `confirmed_at_unix`'s doc comment
    /// for why this, not that, is what `fresh_corroboration` actually
    /// checks.
    confirmed_at: std::time::Instant,
    /// `PeerAuthorityState::membership_generation()` at the moment this record
    /// was written. `fresh_corroboration` requires this to still match the
    /// CURRENT generation -- if any peer's writer/full-replica/netmap state
    /// has changed since, the confirmation this record represents may no
    /// longer hold (e.g. the confirming peer was demoted or removed), so
    /// it's treated as stale regardless of its age.
    membership_generation: u64,
}

/// `DurabilityService::custody_confirmation_cache`'s per-group value: the most
/// recent confirmation record (if any) PLUS an epoch counter, sharing one
/// `HashMap` entry under one lock deliberately. An earlier version tracked
/// the epoch in a SEPARATE `Mutex<HashMap<...>>`, which meant
/// `clear_custody_confirmation`'s remove followed by a bump, and
/// `record_custody_confirmation_outcome`'s check-then-insert each took two
/// non-atomic lock acquisitions -- a real TOCTOU where a `clear` and an
/// in-flight `refresh`'s publish could interleave such that the stale
/// publish still landed after the clear. Keeping both fields in the same map entry,
/// mutated under the same single lock acquisition in each method, makes
/// that interleaving structurally impossible.
#[derive(Debug, Clone, Default)]
struct CustodyCacheEntry {
    record: Option<CustodyConfirmationRecord>,
    epoch: u64,
    /// When a real `StrongHandoffProof` last succeeded for this group,
    /// and the whole-root-set digest it covered.
    ///
    /// Written by the proof itself, read only to answer "what kind of
    /// evidence is this status standing on" -- never to decide anything. A
    /// gate that wants this fact takes a proof; it does not look here, and
    /// there is deliberately nothing here for it to look at but a timestamp
    /// and a digest.
    last_strong_proof: Option<(std::time::Instant, [u8; 32])>,
}

/// Wall-clock seconds, display-only (see
/// `CustodyConfirmationRecord::confirmed_at_unix`).
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct DurabilityService {
    custody_confirmer: Mutex<Option<Arc<dyn CustodyConfirmer>>>,
    group_durability_latch: Mutex<HashMap<String, GroupDurabilityStatus>>,
    /// Overridable sweep interval for `maintenance::durability_confirmation::
    /// DurabilityConfirmationJob`, same shape/reason as `DaemonState`'s
    /// `materialization_repair_sweep_interval`.
    custody_confirmation_sweep_interval: Mutex<Duration>,
    /// Groups with an event-triggered custody refresh scheduled but not yet
    /// started. Coalesces a burst of peer-session events into at most one
    /// pending refresh per group.
    pending_custody_refresh: Mutex<std::collections::HashSet<String>>,
    /// group_id -> that group's custody-confirmation cache entry (the most
    /// recent whole-group peer-confirmed custody evidence, if any, plus an
    /// epoch counter) -- populated by `DurabilityConfirmationJob`'s
    /// periodic sweep. `group_durability_status` only trusts a record here
    /// as `Protected` evidence within `CUSTODY_CONFIRMATION_STALENESS_BOUND`
    /// of its confirmation time -- this is what lets `Protected` mean "a
    /// peer positively confirmed whole-group coverage recently," not "this
    /// device's own local copy looks complete". The epoch and the record share ONE
    /// lock deliberately -- see `CustodyCacheEntry`'s own doc comment for
    /// why splitting them across two locks would be a TOCTOU.
    ///
    /// Every method below takes this lock once, touches only this map, and
    /// makes no call-out while holding it; generations are passed in by the
    /// caller rather than read here.
    custody_confirmation_cache: Mutex<HashMap<String, CustodyCacheEntry>>,
    /// Per-group memo of [`Self::local_root_set_summary`], keyed inside the
    /// value by the `file_root_set_generation` counter it was computed at.
    ///
    /// Purely a cache. It is consulted only when that counter still matches,
    /// it is never persisted, and it starts empty in every process — so a
    /// database written by a build whose triggers did not exist cannot
    /// produce a stale hit here, because there is nothing to hit.
    ///
    /// A separate lock from `custody_confirmation_cache`; no method holds
    /// both, and none holds this one across a database read.
    root_set_summary_memo: Mutex<HashMap<String, RootSetSummary>>,
    /// The persisted durability-latch table failed to load at startup, so
    /// this daemon cannot tell which groups were latched and every group's
    /// status fails closed to `Unknown`. Fixed at construction.
    latch_load_failed: bool,
    /// Set while at least one `membership_operations` journal row is in
    /// `UnknownScope` state (a `--force` device removal proceeded without a
    /// verified list of groups at risk). Since the AT-RISK GROUPS are
    /// themselves unknown, this cannot be expressed as a per-group latch —
    /// it forces every group's `group_durability_status` to
    /// `Unknown` until a reconciliation pass narrows the scope
    /// down to real per-group latches and clears this flag. Loaded from
    /// `SyncState` at startup so it survives a restart, matching
    /// `latch_load_failed`'s own persistence. Only `DaemonState`, which
    /// derives it from the membership journal, writes it.
    scope_unknown: AtomicBool,
}

impl DurabilityService {
    pub(crate) fn new(
        persisted_durability_latches: HashMap<String, GroupDurabilityStatus>,
        latch_load_failed: bool,
        scope_unknown: bool,
    ) -> Self {
        Self {
            custody_confirmer: Mutex::new(None),
            group_durability_latch: Mutex::new(persisted_durability_latches),
            custody_confirmation_sweep_interval: Mutex::new(
                default_custody_confirmation_sweep_interval(),
            ),
            pending_custody_refresh: Mutex::new(std::collections::HashSet::new()),
            custody_confirmation_cache: Mutex::new(HashMap::new()),
            root_set_summary_memo: Mutex::new(HashMap::new()),
            latch_load_failed,
            scope_unknown: AtomicBool::new(scope_unknown),
        }
    }

    /// Marks `group_id` as having a custody refresh pending. True only for
    /// the caller that must schedule it; false when one is already pending.
    pub(crate) fn mark_custody_refresh_pending(&self, group_id: &str) -> bool {
        self.pending_custody_refresh
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.to_string())
    }

    /// Clears the pending mark as the refresh starts, so an event arriving
    /// while it runs schedules a follow-up rather than being lost.
    pub(crate) fn clear_custody_refresh_pending(&self, group_id: &str) {
        self.pending_custody_refresh.lock().unwrap_or_else(|p| p.into_inner()).remove(group_id);
    }

    /// Whether the persisted latch table failed to load at startup -- see
    /// the field's doc comment.
    pub(crate) fn latch_load_failed(&self) -> bool {
        self.latch_load_failed
    }

    /// Whether an unresolved unknown-scope membership operation is open --
    /// see the field's doc comment.
    pub(crate) fn scope_unknown(&self) -> bool {
        self.scope_unknown.load(Ordering::SeqCst)
    }

    /// Records the unknown-scope marker `DaemonState` derived from the
    /// membership journal.
    pub(crate) fn set_scope_unknown(&self, scope_unknown: bool) {
        self.scope_unknown.store(scope_unknown, Ordering::SeqCst);
    }

    /// `pub(crate)`: read by `maintenance::durability_confirmation::
    /// DurabilityConfirmationJob`, which owns this scheduler's sleep-loop.
    pub(crate) fn custody_confirmation_sweep_interval(&self) -> Duration {
        *self.custody_confirmation_sweep_interval.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Records the outcome of one `DurabilityConfirmationJob` sweep round
    /// for `group_id`, stamped with `membership_generation` -- the value
    /// captured BEFORE that round's peer round-trip started (never a fresh
    /// read: reading it at write time could stamp a now-current generation
    /// onto evidence a mid-flight demotion actually invalidated).
    /// `current_membership_generation` is the generation as of this call,
    /// used only for the still-fresh-positive rule below.
    ///
    /// `epoch_before` is the cache epoch captured before that same
    /// round-trip started. The epoch check and the write happen in ONE
    /// critical section (a single lock acquisition) together with
    /// `clear_custody_confirmation`'s own epoch bump+remove -- so the two
    /// can never interleave: either `clear_custody_confirmation` runs
    /// fully before this call observes its bumped epoch and drops the
    /// stale result, or it runs fully after and this call has already
    /// published (in which case the clear correctly removes what was just
    /// published). Checking the epoch and publishing as two separate lock
    /// acquisitions would leave exactly this window open.
    ///
    /// A `NotConfirmed` outcome does NOT overwrite an existing entry that
    /// is still a fresh `Confirmed` record (by this same generation +
    /// staleness test `fresh_corroboration` applies) -- one transient
    /// round-trip miss must not immediately erase the "tolerate one missed
    /// sweep" property `CUSTODY_CONFIRMATION_STALENESS_BOUND` exists to
    /// provide (if every `NotConfirmed` round unconditionally clobbered a
    /// still-good record, the staleness bound would be meaningless). It's still written when
    /// there's no existing entry at all, so `has_ever_been_custody_swept`
    /// still becomes true on first contact.
    ///
    /// Returns whether a record was actually written. A caller that reports
    /// "corroborated" needs to know: the epoch check below can reject a
    /// result silently, and a cycle announcing a result it never published
    /// would send a reader to the cache for evidence that is not there.
    pub(crate) fn publish_background_custody(
        &self,
        group_id: &str,
        outcome: BackgroundCustodyEvidence,
        membership_generation: u64,
        epoch_before: u64,
        current_membership_generation: u64,
    ) -> bool {
        let mut cache = self.custody_confirmation_cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = cache.entry(group_id.to_string()).or_default();
        if entry.epoch != epoch_before {
            // A clear (unlink, possibly followed by a relink) landed
            // between when this sweep round started and now -- drop this
            // stale result entirely rather than publish it.
            return false;
        }
        if let BackgroundCustodyEvidence::NotCorroborated { reason } = &outcome {
            // A negative that is merely the ABSENCE of evidence does not
            // erase a still-fresh positive -- that tolerance is the whole
            // reason the staleness bound is longer than the sweep interval,
            // so one missed round does not flip a genuinely protected group.
            //
            // A negative that is a CONTRADICTION does erase it. A peer that
            // answered and disagreed has told this device something new and
            // worse, and continuing to report the old positive for the rest
            // of the window would be publishing a fact that has been
            // refuted. The distinction did not exist before the background
            // check stopped being a proof: until then the only negative
            // available was a round-trip that did not land.
            if !reason.is_contradiction() {
                if let Some(existing) = &entry.record {
                    let still_fresh =
                        matches!(existing.outcome, BackgroundCustodyEvidence::Corroborated { .. })
                            && existing.confirmed_at.elapsed()
                                <= CUSTODY_CONFIRMATION_STALENESS_BOUND
                            && existing.membership_generation == current_membership_generation;
                    if still_fresh {
                        return false;
                    }
                }
            }
        }
        entry.record = Some(CustodyConfirmationRecord {
            outcome,
            confirmed_at_unix: now_unix(),
            confirmed_at: std::time::Instant::now(),
            membership_generation,
        });
        true
    }

    /// `group_id`'s cached corroboration, if it is a `Corroborated` record
    /// that is BOTH still within `CUSTODY_CONFIRMATION_STALENESS_BOUND` of
    /// its confirmation time (monotonic clock, immune to a wall-clock
    /// adjustment) AND was recorded under
    /// `current_membership_generation` (any peer netmap change since
    /// invalidates it outright, regardless of age). Returns the corroborating peer (`None` for a vacuous
    /// corroboration) and the current-state digest the corroboration was
    /// made against.
    ///
    /// Only the cache half of freshness: the caller must still compare the
    /// returned digest against this device's CURRENT root-set summary,
    /// which is a database read and so is deliberately not done here, under
    /// this lock -- see `DaemonState::has_fresh_custody_confirmation`.
    pub(crate) fn fresh_corroboration(
        &self,
        group_id: &str,
        current_membership_generation: u64,
    ) -> Option<(Option<String>, [u8; 32])> {
        let cache = self.custody_confirmation_cache.lock().unwrap_or_else(|p| p.into_inner());
        let record = cache.get(group_id).and_then(|entry| entry.record.as_ref())?;
        let BackgroundCustodyEvidence::Corroborated { peer_device_id, current_digest, .. } =
            &record.outcome
        else {
            return None;
        };
        let fresh = record.confirmed_at.elapsed() <= CUSTODY_CONFIRMATION_STALENESS_BOUND
            && record.membership_generation == current_membership_generation;
        fresh.then(|| (peer_device_id.clone(), *current_digest))
    }

    /// Whether `group_id` has had at least one `DurabilityConfirmationJob`
    /// sweep round run for it, ever (not staleness-bounded — this only
    /// exists to distinguish "never checked yet" from "checked and found
    /// nothing," so `classify` doesn't jump straight to `AtRisk`
    /// during the narrow startup window before the first sweep tick has
    /// even run once).
    pub(crate) fn has_ever_been_custody_swept(&self, group_id: &str) -> bool {
        self.custody_confirmation_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(group_id)
            .is_some_and(|entry| entry.record.is_some())
    }

    /// Current epoch counter for `group_id`'s custody-confirmation cache
    /// entry (0 if never cleared).
    pub(crate) fn custody_confirmation_epoch(&self, group_id: &str) -> u64 {
        self.custody_confirmation_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(group_id)
            .map(|entry| entry.epoch)
            .unwrap_or(0)
    }

    /// Drops `group_id`'s cached custody confirmation, if any, and bumps
    /// its epoch, atomically (one lock acquisition) -- called whenever
    /// this device's own link for that group is removed. The epoch bump
    /// is what lets `refresh_custody_confirmation` detect and discard an
    /// in-flight round-trip that started before this call and would
    /// otherwise complete afterward and resurrect a cache entry for a
    /// link that's no longer there -- doing the remove and the bump under
    /// the SAME critical section `publish_background_custody` also uses is
    /// what closes that window (two separate locks would leave it open).
    /// The removal alone is
    /// what stops a later relink of the same `group_id` within the
    /// staleness bound from reusing evidence confirmed under a now-gone
    /// link/membership state. A
    /// no-op (beyond the epoch bump) if nothing was cached.
    pub(crate) fn clear_custody_confirmation(&self, group_id: &str) {
        let mut cache = self.custody_confirmation_cache.lock().unwrap_or_else(|p| p.into_inner());
        let entry = cache.entry(group_id.to_string()).or_default();
        entry.record = None;
        entry.epoch += 1;
    }

    /// Records that a whole-group proof just succeeded for `group_id`
    /// against `roots_digest`.
    ///
    /// Display only, and structurally unable to be anything else: what it
    /// stores is an instant and a digest, so no caller can mistake it for
    /// permission. A gate that wants this fact establishes it.
    pub(crate) fn note_strong_proof(&self, group_id: &str, roots_digest: [u8; 32]) {
        self.custody_confirmation_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(group_id.to_string())
            .or_default()
            .last_strong_proof = Some((std::time::Instant::now(), roots_digest));
    }

    /// The whole-root-set digest the last strong proof for `group_id`
    /// covered, if that proof is still within
    /// `CUSTODY_CONFIRMATION_STALENESS_BOUND`. The caller re-derives the
    /// group's current whole-root-set digest (a database read, outside this
    /// lock) and only counts the proof when the two still match.
    pub(crate) fn fresh_strong_proof_digest(&self, group_id: &str) -> Option<[u8; 32]> {
        let proof = self
            .custody_confirmation_cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(group_id)
            .and_then(|entry| entry.last_strong_proof);
        let (at, digest) = proof?;
        (at.elapsed() <= CUSTODY_CONFIRMATION_STALENESS_BOUND).then_some(digest)
    }

    /// This device's own root-set summary for `group_id` as read from
    /// `repository`, memoised against the group's root-set generation.
    ///
    /// The generation is read every call — it is one indexed row — and the
    /// memo is used only when it still matches the value the memoised
    /// summary was computed at. Recomputing is an index scan and a
    /// version-hash recomputation per root, which is cheap next to what it
    /// replaces but is not free at eighty thousand roots, and the set is
    /// usually unchanged between sweeps.
    ///
    /// `None` fails closed on any read error, including an unreadable
    /// generation: this is a cache, and being unable to read its key is a
    /// reason to answer nothing, never a reason to trust what is already in
    /// it. The memo lock is never held across either database read; two
    /// concurrent misses may both recompute, which is harmless because the
    /// entry is keyed by generation.
    pub(crate) fn local_root_set_summary(
        &self,
        repository: &FileIndexRepository,
        group_id: &str,
    ) -> Option<RootSetSummary> {
        let generation = repository.root_set_generation(group_id).ok()?;
        if let Some(memoised) =
            self.root_set_summary_memo.lock().unwrap_or_else(|p| p.into_inner()).get(group_id)
        {
            if memoised.generation == generation {
                return Some(*memoised);
            }
        }
        let summary = repository.group_root_set_summary(group_id).ok()?;
        self.root_set_summary_memo
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(group_id.to_string(), summary);
        Some(summary)
    }

    /// Pins `group_id` to [`GroupDurabilityStatus::Unknown`],
    /// overriding whatever [`classify_unlatched`] would otherwise derive.
    /// Idempotent — latching an already-latched group is a no-op.
    pub fn latch_unknown(&self, group_id: &str) {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), GroupDurabilityStatus::Unknown);
    }

    /// Clears a previously-latched `Unknown` override for
    /// `group_id`, if any -- a no-op if it wasn't latched.
    pub fn clear_unknown(&self, group_id: &str) {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(group_id);
    }

    pub fn is_latched_unknown(&self, group_id: &str) -> bool {
        self.group_durability_latch
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(group_id)
    }

    /// The full derivation for `group_id`: fills in `latched_unknown` from
    /// this service's own latch table, then applies [`classify`] to the
    /// complete facts. `facts.latched_unknown` is ignored (and should be
    /// left `false`) -- this method, not the caller, owns that fact.
    pub fn classify(&self, group_id: &str, mut facts: DurabilityFacts) -> GroupDurabilityStatus {
        facts.latched_unknown = self.is_latched_unknown(group_id);
        classify(&facts)
    }

    /// Installs the custody confirmer used by the on-demand reclamation
    /// gate -- production wires a peer-to-peer confirmer, tests inject a
    /// deterministic one so custody behavior can be exercised without a
    /// live peer.
    pub fn install_custody_confirmer(&self, confirmer: Arc<dyn CustodyConfirmer>) {
        *self.custody_confirmer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(confirmer);
    }

    /// Delegates to the installed [`CustodyConfirmer`]; with none installed
    /// (or none can confirm), returns `None`.
    pub fn confirm_version(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        let confirmer =
            self.custody_confirmer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        confirmer
            .and_then(|confirmer| confirmer.confirms_present(group_id, path, version_hash, blocks))
    }

    pub fn confirmation_still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool {
        let confirmer =
            self.custody_confirmer.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        confirmer.is_some_and(|confirmer| {
            confirmer.confirmation_still_valid(group_id, path, version_hash, stamp)
        })
    }
}

#[cfg(test)]
mod tests;
