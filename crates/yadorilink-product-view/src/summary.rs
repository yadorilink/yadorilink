//! `ProductStatusSummary` — the one canonical "is YadoriLink okay right now?"
//! answer, shared by every product shell (macOS, future WinUI, CLI, web).
//!
//! A thin aggregation over `LinkStatus` fields the daemon already reports:
//! no new sync semantics and no sync-engine dependency. The closed state set
//! and its precedence live here so no shell recomputes them:
//!
//! 1. `NeedsAttention` — some folder needs user action
//! 2. `Paused` — some folder is intentionally paused
//! 3. `Syncing` — useful work is progressing
//! 4. `Waiting` — wanted content (`wants_content`) cannot be fetched yet
//! 5. `UpToDate` — nothing pending
//!
//! The attention set mirrors the daemon's `overall_status` per-link reasons (a test in the
//! daemon pins the two together); the one deliberate difference is fetch availability, which
//! the daemon rolls up as attention and this summary names `Waiting`. (`policy_stale` is not an
//! attention reason of its own: the daemon already reports a stale policy as durability
//! `Unknown`.)
//!
//! Two further dimensions ride along and never change `state`: `availability` (can the exact
//! content needed be fetched now) and `protection` (is the data still elsewhere if this device
//! is lost). They are independent of each other and of the state above; each has its own closed
//! enum and aggregation rule in its module.
//!
//! Wording beyond the fixed `label()` is the shells'. Pause-until and
//! peer-availability details are not on `LinkStatus` today and are added when
//! a trustworthy source exists.

use crate::attention::{AttentionItem, ProductAction};
use crate::availability::AvailabilitySummary;
use crate::folder::DegradedCause;
use crate::protection::ProtectionSummary;
use yadorilink_ipc_proto::daemonctl::{FetchAvailability, GroupDurabilityStatus, LinkStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProductState {
    UpToDate,
    Syncing,
    Waiting,
    NeedsAttention,
    Paused,
}

impl ProductState {
    pub fn label(self) -> &'static str {
        match self {
            ProductState::UpToDate => "Up to date",
            ProductState::Syncing => "Syncing",
            ProductState::Waiting => "Waiting",
            ProductState::NeedsAttention => "Needs attention",
            ProductState::Paused => "Paused",
        }
    }
}

/// Why a folder needs the user, as a stable product concept (not a wire code).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttentionReason {
    Conflict,
    /// The daemon marks the folder degraded, for the typed cause (`LinkStatus.degraded_cause`).
    Degraded(DegradedCause),
    LinkedTwice,
    VolumeChanged,
    /// The folder's disk was mounted again and only the user can confirm it.
    VolumeUnconfirmed,
    StrandedDirectory,
    /// One or more files are held (the daemon lists them as `held_files`).
    HeldFile,
    /// Files the scan cannot read and that need the person (`unreadable_files`).
    UnreadableFiles,
    /// Requests to join the folder's group wait for this account's decision.
    ApprovalPending,
    /// No durable copy of the group's data exists anywhere.
    DurabilityAtRisk,
    /// The group's durability cannot currently be confirmed (a check still pending is not this).
    DurabilityUnconfirmed,
}

impl AttentionReason {
    /// The shared attention item this reason is an instance of.
    pub fn item(self) -> AttentionItem {
        match self {
            AttentionReason::Conflict => AttentionItem::ConflictNeedsReview,
            AttentionReason::Degraded(cause) => cause.item(),
            AttentionReason::LinkedTwice => AttentionItem::LinkedTwice,
            AttentionReason::VolumeChanged => AttentionItem::VolumeChanged,
            AttentionReason::VolumeUnconfirmed => AttentionItem::VolumeUnconfirmed,
            AttentionReason::StrandedDirectory => AttentionItem::StrandedDirectory,
            AttentionReason::HeldFile => AttentionItem::FileHeld,
            AttentionReason::UnreadableFiles => AttentionItem::UnreadableFiles,
            AttentionReason::ApprovalPending => AttentionItem::ApprovalPending,
            AttentionReason::DurabilityAtRisk => AttentionItem::NoSafeCopy,
            AttentionReason::DurabilityUnconfirmed => AttentionItem::SafeCopyUnconfirmed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductStatusSummary {
    pub state: ProductState,
    /// Folders needing attention / paused / syncing / waiting (a folder with
    /// several conditions counts under each; `state` picks by precedence).
    pub attention_count: u64,
    pub paused_count: u64,
    pub syncing_count: u64,
    pub waiting_count: u64,
    /// Reasons behind attention (per-folder summaries only).
    pub attention_reasons: Vec<AttentionReason>,
    /// Bytes left in the active transfers; `Some` only when every folder
    /// with an active transfer has a known total and no other queued work (an eager folder
    /// still partially materialized), so a UI never shows a made-up figure
    /// or percentage.
    pub bytes_remaining: Option<u64>,
    /// Whether the exact content needed can be fetched now, across the folders summarized.
    pub availability: AvailabilitySummary,
    /// Whether the data survives losing this device, across the folders summarized.
    pub protection: ProtectionSummary,
    /// The one thing to offer for `state`: resume when paused, the action of the most severe
    /// attention reason when a folder needs the user, otherwise none. A shell renders it through
    /// the typed operation it names and adds no rule of its own.
    pub next_action: Option<ProductAction>,
}

/// One folder's flags, before they are collapsed into a state.
struct Flags {
    reasons: Vec<AttentionReason>,
    paused: bool,
    syncing: bool,
    waiting: bool,
    /// Content still queued beyond any active transfer (partially materialized or hydrating).
    queued: bool,
    /// This folder has an active transfer (whatever state precedence gives the folder).
    active_transfer: bool,
    /// `Some(remaining)` when this folder's transfer total is known.
    bytes_remaining: Option<u64>,
}

/// Content this folder wants right now: the daemon's `requested_content_count` (fetches in
/// flight, opens queued for an assembly slot, an Eager folder's unmaterialized files; never
/// evictions). Remote placeholders alone are not wanted content.
fn wants_content(link: &LinkStatus) -> bool {
    link.requested_content_count > 0
}

fn flags(link: &LinkStatus) -> Flags {
    let durability = link.durability_status();
    let checks = [
        (link.conflict_count > 0 || link.conflicts_pending > 0, AttentionReason::Conflict),
        (durability == GroupDurabilityStatus::AtRisk, AttentionReason::DurabilityAtRisk),
        (
            matches!(
                durability,
                GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified
            ) && !link.durability_check_pending,
            AttentionReason::DurabilityUnconfirmed,
        ),
        (
            link.degraded,
            AttentionReason::Degraded(DegradedCause::of(link).unwrap_or(DegradedCause::Stopped)),
        ),
        (link.ambiguous, AttentionReason::LinkedTwice),
        (link.capture_volume_changed, AttentionReason::VolumeChanged),
        (link.capture_volume_unconfirmed, AttentionReason::VolumeUnconfirmed),
        (link.stranded_directory_count > 0, AttentionReason::StrandedDirectory),
        (link.held_file_count > 0, AttentionReason::HeldFile),
        (link.unreadable_file_count > 0, AttentionReason::UnreadableFiles),
        (link.pending_approvals > 0, AttentionReason::ApprovalPending),
    ];
    let reasons = checks.into_iter().filter(|(on, _)| *on).map(|(_, r)| r).collect();
    // Waiting is wanted content that cannot be fetched: work that needs doing and cannot
    // progress. Unconfirmed availability fails closed to "cannot progress", but only when
    // content is wanted; an idle On-Demand folder's remote placeholders are not work.
    let queued = wants_content(link);
    let waiting = queued && link.fetch_availability() != FetchAvailability::AvailableNow;
    let syncing = link.has_active_transfer || (queued && !waiting);
    // Fail closed: a file in flight may itself be counted in `hydrating_count`, so a figure is
    // withheld (None) during an ordinary download rather than risk understating other
    // requested work; the counts alone cannot tell the two apart.
    // The daemon's transfer totals cover active transfers only, so they are
    // the whole remaining work only when nothing else is queued.
    let bytes_remaining = (link.has_active_transfer && link.transfer_bytes_total > 0)
        .then(|| link.transfer_bytes_total.saturating_sub(link.transfer_bytes_done));
    Flags {
        reasons,
        paused: link.paused,
        syncing,
        waiting,
        queued,
        active_transfer: link.has_active_transfer,
        bytes_remaining,
    }
}

fn state_of(f: &Flags) -> ProductState {
    if !f.reasons.is_empty() {
        ProductState::NeedsAttention
    } else if f.paused {
        ProductState::Paused
    } else if f.syncing {
        ProductState::Syncing
    } else if f.waiting {
        ProductState::Waiting
    } else {
        ProductState::UpToDate
    }
}

impl ProductStatusSummary {
    pub fn for_folder(link: &LinkStatus) -> Self {
        Self::aggregate(std::slice::from_ref(link))
    }

    pub fn global(links: &[LinkStatus]) -> Self {
        Self::aggregate(links)
    }

    fn aggregate(links: &[LinkStatus]) -> Self {
        let all: Vec<Flags> = links.iter().map(flags).collect();
        let count = |pick: fn(&Flags) -> bool| all.iter().filter(|f| pick(f)).count() as u64;
        // Every active transfer counts, whatever state precedence gives its folder (a conflicted
        // folder's download is still bytes left); one unknown total, or other queued work,
        // makes the figure unknowable.
        let active: Vec<&Flags> = all.iter().filter(|f| f.active_transfer).collect();
        let bytes_remaining = if active.is_empty() || all.iter().any(|f| f.queued) {
            None
        } else {
            active.iter().try_fold(0u64, |sum, f| Some(sum.saturating_add(f.bytes_remaining?)))
        };
        let state = all.iter().map(state_of).fold(ProductState::UpToDate, strongest);
        let attention_reasons: Vec<AttentionReason> =
            all.iter().flat_map(|f| f.reasons.iter().copied()).collect();
        let next_action = match state {
            ProductState::NeedsAttention => attention_reasons
                .iter()
                .map(|r| r.item())
                // `max_by_key` keeps the last of equal keys; the reverse keeps the first reported.
                .rev()
                .max_by_key(|item| item.severity())
                // A summary knows no volume's reclaim, so free-up-space falls back to details.
                .map(|item| item.offered_action(false)),
            ProductState::Paused => Some(ProductAction::Resume),
            ProductState::Syncing | ProductState::Waiting | ProductState::UpToDate => None,
        };
        ProductStatusSummary {
            state,
            attention_count: count(|f| !f.reasons.is_empty()),
            paused_count: count(|f| f.paused),
            syncing_count: count(|f| f.syncing),
            waiting_count: count(|f| f.waiting),
            attention_reasons,
            bytes_remaining,
            availability: AvailabilitySummary::aggregate(
                &links.iter().map(AvailabilitySummary::from_link).collect::<Vec<_>>(),
            ),
            protection: ProtectionSummary::aggregate(
                &links.iter().map(ProtectionSummary::from_link).collect::<Vec<_>>(),
            ),
            next_action,
        }
    }
}

/// Higher rank wins: attention > paused > syncing > waiting > up to date.
fn strongest(a: ProductState, b: ProductState) -> ProductState {
    fn rank(s: ProductState) -> u8 {
        match s {
            ProductState::NeedsAttention => 4,
            ProductState::Paused => 3,
            ProductState::Syncing => 2,
            ProductState::Waiting => 1,
            ProductState::UpToDate => 0,
        }
    }
    if rank(b) > rank(a) {
        b
    } else {
        a
    }
}

#[cfg(test)]
mod tests;
