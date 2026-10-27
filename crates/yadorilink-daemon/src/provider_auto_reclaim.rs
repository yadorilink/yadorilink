//! Automatic space management for provider folders: when free disk space runs low, downloaded
//! files that are safe to give back go back to being online-only.
//!
//! The only trigger is disk pressure, read from the existing free-space classification of the
//! volume (`low` or `critical` against the write headroom; no new threshold). While it lasts, the
//! largest eligible files go first, a bounded number per pass, and the pass stops as soon as free
//! space is back to the classification's `ok`. An eligible file is downloaded, not kept on this
//! device (a pin), and the ordinary "free up space" would succeed for it. Nothing is tracked about
//! when a file was last used.
//!
//! This module never frees anything itself: it selects items and then calls the same
//! [`ProviderEvictor`] a person's request goes through, one item at a time, which looks at the
//! pin, the version, the host and the custody lease again at the moment it acts. An item that has
//! become ineligible since it was selected is a normal skip.
//!
//! Selection ([`AutoReclaim::scan`]) deletes nothing and is the dry run: every item that has a
//! downloaded copy gets one [`Verdict`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::free_space::FreeSpaceState;

use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::provider::{ItemId, ProviderRoot};

use crate::daemon_state::DaemonState;
use crate::provider_evict::ProviderEvictor;
use crate::provider_evidence::{os_copy, OsCopy, ProviderMembership};
use crate::provider_reclaim::Retained;
use crate::space_management_config::SpaceManagementStore;

/// How often a pass looks at free space.
pub(crate) const PASS_INTERVAL: Duration = Duration::from_secs(10 * 60);
/// The wait before the first pass after start-up, so the host's reports of what it holds have
/// arrived and a restart never reclaims on a blank picture.
pub(crate) const FIRST_PASS_DELAY: Duration = Duration::from_secs(10 * 60);
/// The most items one pass asks the eviction path about.
pub(crate) const BATCH: usize = 8;
/// How long an item the eviction path refused is left alone (the process remembers it only).
pub(crate) const REFUSED_COOLDOWN: Duration = Duration::from_secs(24 * 60 * 60);
/// The number of rows read per page of a scan.
const PAGE: usize = 256;
/// How long a count of what could be given back is trusted before a status read starts another.
pub(crate) const RECLAIMABLE_MAX_AGE: Duration = Duration::from_secs(60);

/// What the policy says about one downloaded item. Closed: this is also the vocabulary for why a
/// request to free space was turned down.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Verdict {
    /// Would be reclaimed now.
    Eligible,
    /// The user keeps it on this device.
    Pinned,
    /// This folder (or build, or volume) never gives space back automatically.
    UnsupportedRoot,
    /// No other device that keeps full copies can confirm it holds this version right now.
    CustodyUnavailable,
    /// Another operation, a program, or the file system holds the item at the moment.
    Busy,
    /// The content is new, being updated or not confirmed by the system yet.
    Changed,
    /// Something that makes freeing unsafe or unprovable (state unreadable, host absent, host
    /// declined).
    SafetyBlocked,
}

impl Verdict {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Eligible => "eligible",
            Self::Pinned => "pinned",
            Self::UnsupportedRoot => "unsupported_root",
            Self::CustodyUnavailable => "custody_unavailable",
            Self::Busy => "busy",
            Self::Changed => "changed",
            Self::SafetyBlocked => "safety_blocked",
        }
    }

    /// The verdict for an eviction that kept something on this device.
    pub(crate) fn from_retained(why: Retained) -> Self {
        match why {
            Retained::CustodyUnsupported | Retained::FullReplica => Self::UnsupportedRoot,
            Retained::CustodyNotAcquired | Retained::CustodyRequired => Self::CustodyUnavailable,
            Retained::Busy | Retained::HostBusy => Self::Busy,
            Retained::VersionMoved | Retained::NotConfirmed | Retained::NotDownloaded => {
                Self::Changed
            }
            Retained::HostRefused | Retained::NothingFreed => Self::SafetyBlocked,
        }
    }
}

/// Whether the user keeps an item on this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kept {
    No,
    Yes,
    /// The policy could not be read: treated as kept, never as free.
    Unreadable,
}

/// Everything the policy looks at for one item; the facts are gathered by [`AutoReclaim`], the
/// decision is [`classify`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Facts {
    /// Why this folder never gives space back, if it does not ([`Retained`] names it).
    pub standing_blocker: Option<Retained>,
    pub host_connected: bool,
    pub kept: Kept,
    pub os_copy: OsCopy,
    pub busy: bool,
    /// Whether any device that could vouch for the content is connected now.
    pub custody_reachable: bool,
}

/// The one rule. `None`: the item has no downloaded copy, so there is nothing to reclaim.
pub(crate) fn classify(facts: &Facts) -> Option<Verdict> {
    if facts.os_copy == OsCopy::Absent {
        return None;
    }
    if facts.standing_blocker.is_some() {
        return Some(Verdict::UnsupportedRoot);
    }
    Some(match facts.kept {
        Kept::Yes => Verdict::Pinned,
        Kept::Unreadable => Verdict::SafetyBlocked,
        Kept::No if !facts.host_connected => Verdict::SafetyBlocked,
        Kept::No if facts.os_copy == OsCopy::Unconfirmed => Verdict::Changed,
        Kept::No if facts.busy => Verdict::Busy,
        Kept::No if !facts.custody_reachable => Verdict::CustodyUnavailable,
        Kept::No => Verdict::Eligible,
    })
}

/// Whether the free-space state calls for giving space back: `low` or `critical`.
pub(crate) fn under_pressure(state: Option<FreeSpaceState>) -> bool {
    state.is_some_and(|state| state >= FreeSpaceState::Low)
}

/// The machine facts a pass reads.
pub(crate) trait ReclaimEnvironment: Send + Sync {
    fn host_connected(&self) -> bool;
    /// Whether any peer of the group is connected (a custody lease needs one).
    fn peers_available(&self, group_id: &str) -> bool;
    /// The free-space state of the volume holding the daemon's data; `None` when it cannot be
    /// read, which is never read as pressure.
    fn free_space(&self) -> Option<FreeSpaceState>;
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }
}

/// An item a scan leaves out: the path alone is not enough, a new item at the same path starts
/// afresh.
pub(crate) type SkipKey = (String, String, ItemId);
pub(crate) type Skip = HashSet<SkipKey>;

/// One scanned item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    pub group_id: String,
    pub path: String,
    pub item: ItemId,
    /// The version the verdict is about; the eviction acts on this one only.
    pub version: VersionHash,
    pub size: u64,
    pub verdict: Verdict,
}

/// The result of a scan.
#[derive(Debug, Default)]
pub(crate) struct Scan {
    pub entries: Vec<Entry>,
    /// A root could not be read; its items are missing from `entries`.
    pub unreadable_roots: usize,
}

impl Scan {
    pub(crate) fn count(&self, verdict: Verdict) -> usize {
        self.entries.iter().filter(|entry| entry.verdict == verdict).count()
    }
}

pub(crate) struct AutoReclaim {
    pub(crate) state: Arc<DaemonState>,
    pub(crate) evictor: Arc<ProviderEvictor>,
    pub(crate) membership: Arc<ProviderMembership>,
    pub(crate) environment: Arc<dyn ReclaimEnvironment>,
    pub(crate) settings: SpaceManagementStore,
    /// Items the eviction path refused, until when (unix ms): in memory only, so that a refused
    /// item does not keep taking the pass's turns from the others.
    pub(crate) cooldown: std::sync::Mutex<std::collections::HashMap<SkipKey, i64>>,
    /// What a status read last found could be given back (see [`Self::reclaimable_by_group`]).
    reclaimable: std::sync::Mutex<ReclaimableCache>,
}

/// Bytes the eviction path would give back, per group, as of the last look.
#[derive(Default)]
struct ReclaimableCache {
    /// When the look began (unix ms); `None` before the first.
    at_ms: Option<i64>,
    refreshing: bool,
    bytes: std::collections::HashMap<String, u64>,
}

impl AutoReclaim {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        evictor: Arc<ProviderEvictor>,
        membership: Arc<ProviderMembership>,
        environment: Arc<dyn ReclaimEnvironment>,
        settings: SpaceManagementStore,
    ) -> Self {
        Self {
            state,
            evictor,
            membership,
            environment,
            settings,
            cooldown: std::sync::Mutex::default(),
            reclaimable: std::sync::Mutex::default(),
        }
    }

    /// The bytes per group that a request to free up space would give back, for a status read to
    /// offer the action only where it can succeed. Counts exactly the items a pass would hand to
    /// the eviction path (verdict `Eligible`, not cooling down), so the number and the action
    /// cannot disagree about what is safe. Empty while free space is not low: nothing is offered
    /// then, and nothing is scanned. The answer is the last one found; a stale one starts a look
    /// in the background and is returned meanwhile, so a status read never waits for a scan and
    /// the first read under pressure offers nothing yet (fail closed).
    pub(crate) fn reclaimable_by_group(self: &Arc<Self>) -> std::collections::HashMap<String, u64> {
        let mut cache = self.reclaimable.lock().unwrap_or_else(|p| p.into_inner());
        if !under_pressure(self.environment.free_space()) {
            *cache = ReclaimableCache::default();
            return std::collections::HashMap::new();
        }
        let now = self.environment.now_ms();
        let stale = cache
            .at_ms
            .is_none_or(|at| now.saturating_sub(at) >= RECLAIMABLE_MAX_AGE.as_millis() as i64);
        if stale && !cache.refreshing {
            cache.refreshing = true;
            let this = self.clone();
            tokio::spawn(async move { this.refresh_reclaimable().await });
        }
        cache.bytes.clone()
    }

    /// One look at what could be given back, stored for [`Self::reclaimable_by_group`].
    pub(crate) async fn refresh_reclaimable(self: &Arc<Self>) {
        let started = self.environment.now_ms();
        let skip = self.cooling_down();
        let this = self.clone();
        let scan = tokio::task::spawn_blocking(move || this.scan(&skip)).await;
        let mut cache = self.reclaimable.lock().unwrap_or_else(|p| p.into_inner());
        cache.refreshing = false;
        cache.at_ms = Some(started);
        cache.bytes.clear();
        match scan {
            // A root that could not be read says nothing about its items: they are not counted.
            Ok(scan) => {
                for entry in scan.entries.iter().filter(|e| e.verdict == Verdict::Eligible) {
                    let total = cache.bytes.entry(entry.group_id.clone()).or_default();
                    *total = total.saturating_add(entry.size);
                }
            }
            Err(error) => {
                tracing::warn!(%error, "could not look at what free up space would give back");
            }
        }
    }

    /// The facts for one item, read now.
    fn facts(
        &self,
        root: &ProviderRoot,
        pinned: Option<&[String]>,
        path: &str,
        item: &ItemId,
    ) -> Facts {
        let coordinator = &self.state.replica_coordinator;
        let standing_blocker = self.evictor.standing_blocker(&root.group_id);
        let kept = match pinned {
            Some(pinned) if yadorilink_sync_sqlite::pinned_items::path_is_covered(pinned, path) => {
                Kept::Yes
            }
            Some(_) => Kept::No,
            None => Kept::Unreadable,
        };
        Facts {
            standing_blocker,
            host_connected: self.environment.host_connected(),
            kept,
            os_copy: os_copy(coordinator, &self.membership, &root.root_id, item),
            busy: coordinator.path_lock(&root.group_id, path).try_lock().is_err(),
            custody_reachable: self.environment.peers_available(&root.group_id),
        }
    }

    /// Looks at every downloaded item of every provider folder and gives it a verdict, deleting
    /// nothing. `skip` leaves out items the eviction path refused recently.
    pub(crate) fn scan(&self, skip: &Skip) -> Scan {
        let mut scan = Scan::default();
        let coordinator = &self.state.replica_coordinator;
        let repo = coordinator.provider_repository();
        let roots = match repo.list_declared_roots() {
            Ok(roots) => roots,
            Err(error) => {
                tracing::warn!(%error, "automatic space management could not list the provider folders");
                scan.unreadable_roots += 1;
                return scan;
            }
        };
        for root in roots {
            let pinned = coordinator.pinned_item_repository().list(&root.group_id).ok();
            let mut after: Option<(u64, String)> = None;
            loop {
                let page = match repo.eager_page(
                    &root.root_id,
                    false,
                    after.as_ref().map(|(size, path)| (*size, path.as_str())),
                    PAGE,
                ) {
                    Ok(page) if !page.is_empty() => page,
                    Ok(_) => break,
                    Err(error) => {
                        tracing::warn!(root_id = %root.root_id, %error, "automatic space management could not read a provider folder");
                        scan.unreadable_roots += 1;
                        break;
                    }
                };
                after = page.last().map(|c| (c.size, c.path.clone()));
                for candidate in page {
                    let Some(item) = candidate.item_id else { continue };
                    if skip.contains(&(root.group_id.clone(), candidate.path.clone(), item)) {
                        continue;
                    }
                    let facts = self.facts(&root, pinned.as_deref(), &candidate.path, &item);
                    let Some(verdict) = classify(&facts) else { continue };
                    let Ok(Some(version)) = repo.current_version_hash(&root.root_id, &item) else {
                        continue;
                    };
                    scan.entries.push(Entry {
                        group_id: root.group_id.clone(),
                        path: candidate.path,
                        item,
                        version,
                        size: candidate.size,
                        verdict,
                    });
                }
            }
        }
        scan
    }
}

/// What one item's turn in a pass came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The OS copy is gone; `blocks`/`bytes` are what the daemon freed on top, and `kept` says why
    /// its cached blocks stayed when they did.
    Reclaimed { blocks: u64, bytes: u64, kept: Option<Retained> },
    /// No longer eligible when its turn came; nothing was asked of the eviction path.
    Skipped(Verdict),
    /// The eviction path left it as it was.
    Refused(Verdict),
}

/// What one pass did, item by item.
#[derive(Debug, Default)]
pub(crate) struct PassSummary {
    pub outcomes: Vec<(String, String, Outcome)>,
}

#[cfg(test)]
impl PassSummary {
    pub(crate) fn reclaimed(&self) -> usize {
        self.outcomes.iter().filter(|(_, _, o)| matches!(o, Outcome::Reclaimed { .. })).count()
    }
}

impl AutoReclaim {
    /// One pass: nothing unless the setting is On and free space is low. Then the eligible files,
    /// largest first, are handed to the eviction path, at most [`BATCH`], until free space is
    /// back to `ok`. Nothing carries over between passes except the in-memory cooldown, so a
    /// restart or a repeated pass is harmless.
    pub(crate) async fn run_pass(self: &Arc<Self>) -> PassSummary {
        if !self.settings.load_or_off().enabled || !under_pressure(self.environment.free_space()) {
            return PassSummary::default();
        }
        let skip = self.cooling_down();
        let this = self.clone();
        let scan = match tokio::task::spawn_blocking(move || this.scan(&skip)).await {
            Ok(scan) => scan,
            Err(error) => {
                tracing::warn!(%error, "automatic space management could not scan");
                return PassSummary::default();
            }
        };
        tracing::info!(
            eligible = scan.count(Verdict::Eligible),
            pinned = scan.count(Verdict::Pinned),
            unsupported = scan.count(Verdict::UnsupportedRoot),
            custody_unavailable = scan.count(Verdict::CustodyUnavailable),
            busy = scan.count(Verdict::Busy),
            changed = scan.count(Verdict::Changed),
            safety_blocked = scan.count(Verdict::SafetyBlocked),
            unreadable_roots = scan.unreadable_roots,
            "free disk space is low: automatic space management looked at the downloaded files"
        );
        let mut eligible: Vec<Entry> =
            scan.entries.into_iter().filter(|e| e.verdict == Verdict::Eligible).collect();
        // The fewest evictions free the most space.
        eligible.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
        self.reclaim_entries(&eligible).await
    }

    /// Asks the eviction path about each entry in order, after reading the facts again: the
    /// verdict of a scan is a hint, and the eviction path decides. Stops at [`BATCH`] items or
    /// when free space is no longer low.
    pub(crate) async fn reclaim_entries(&self, entries: &[Entry]) -> PassSummary {
        let mut summary = PassSummary::default();
        for entry in entries.iter().take(BATCH) {
            if !self.settings.load_or_off().enabled {
                tracing::info!("automatic space management was turned off: stopping");
                break;
            }
            if !under_pressure(self.environment.free_space()) {
                tracing::info!(
                    "free disk space is back to normal: automatic space management stops"
                );
                break;
            }
            let outcome = self.reclaim_one(entry).await;
            match outcome {
                Outcome::Reclaimed { blocks, bytes, kept } => tracing::info!(
                    group_id = %entry.group_id,
                    path = %entry.path,
                    blocks,
                    bytes,
                    data_kept_reason = kept.map(Retained::code),
                    "automatic space management returned a downloaded file to online-only"
                ),
                Outcome::Skipped(verdict) | Outcome::Refused(verdict) => tracing::info!(
                    group_id = %entry.group_id,
                    path = %entry.path,
                    reason = verdict.code(),
                    refused_by_eviction = matches!(outcome, Outcome::Refused(_)),
                    "automatic space management left a downloaded file as it is"
                ),
            }
            summary.outcomes.push((entry.group_id.clone(), entry.path.clone(), outcome));
        }
        summary
    }

    async fn reclaim_one(&self, entry: &Entry) -> Outcome {
        let current = self.recheck(entry);
        if current != Verdict::Eligible {
            return Outcome::Skipped(current);
        }
        match self
            .evictor
            .evict_expecting(&entry.group_id, &entry.path, Some((entry.item, entry.version)))
            .await
        {
            Ok(done) if done.dehydrated => Outcome::Reclaimed {
                blocks: done.reclaimed.blocks,
                bytes: done.reclaimed.bytes,
                kept: done.retained,
            },
            // The OS held nothing any more: there was nothing to give back.
            Ok(done) => {
                let verdict = done.retained.map_or(Verdict::Changed, Verdict::from_retained);
                self.cool_down(entry);
                Outcome::Refused(verdict)
            }
            Err(_) => {
                // The reason is in the eviction path's own log line; name it by what is true now.
                let verdict = match self.recheck(entry) {
                    Verdict::Eligible => Verdict::SafetyBlocked,
                    other => other,
                };
                self.cool_down(entry);
                Outcome::Refused(verdict)
            }
        }
    }

    /// The verdict for `entry` from facts read now, including that it is still the same item at
    /// the same version.
    fn recheck(&self, entry: &Entry) -> Verdict {
        let coordinator = &self.state.replica_coordinator;
        let repo = coordinator.provider_repository();
        let Ok(yadorilink_sync_sqlite::provider::ProviderDeclaration::Provider(root)) =
            repo.declaration_for_group(&entry.group_id)
        else {
            return Verdict::UnsupportedRoot;
        };
        match repo.item_for_path(&root.root_id, &entry.path) {
            Ok(Some(item)) if item == entry.item => {}
            _ => return Verdict::Changed,
        }
        match repo.current_version_hash(&root.root_id, &entry.item) {
            Ok(Some(version)) if version == entry.version => {}
            _ => return Verdict::Changed,
        }
        let pinned = coordinator.pinned_item_repository().list(&entry.group_id).ok();
        let facts = self.facts(&root, pinned.as_deref(), &entry.path, &entry.item);
        classify(&facts).unwrap_or(Verdict::Changed)
    }

    fn cool_down(&self, entry: &Entry) {
        let until = self.environment.now_ms().saturating_add(REFUSED_COOLDOWN.as_millis() as i64);
        self.cooldown
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((entry.group_id.clone(), entry.path.clone(), entry.item), until);
    }

    /// The items still cooling down; expired entries are forgotten.
    fn cooling_down(&self) -> Skip {
        let now = self.environment.now_ms();
        let mut cooldown = self.cooldown.lock().unwrap_or_else(|p| p.into_inner());
        cooldown.retain(|_, until| *until > now);
        cooldown.keys().cloned().collect()
    }
}

/// The scheduler, installed by the shell side once it exists (the control socket is built first).
#[derive(Default)]
pub(crate) struct AutoReclaimSlot(std::sync::OnceLock<Arc<AutoReclaim>>);

impl AutoReclaimSlot {
    pub(crate) fn install(&self, auto: Arc<AutoReclaim>) {
        let _ = self.0.set(auto);
    }

    /// Bytes per group that freeing up space would give back now; empty while provider folders
    /// are not available or free space is not low.
    pub(crate) fn reclaimable_by_group(&self) -> std::collections::HashMap<String, u64> {
        self.0.get().map(AutoReclaim::reclaimable_by_group).unwrap_or_default()
    }

    /// The dry run (what would be given back if free space were low now); `None` while provider
    /// folders are not available.
    pub(crate) async fn preview(&self) -> Option<Scan> {
        let auto = self.0.get()?.clone();
        tokio::task::spawn_blocking(move || auto.scan(&Skip::new())).await.ok()
    }
}

impl Verdict {
    pub(crate) fn to_wire(self) -> yadorilink_ipc_proto::daemonctl::SpaceReclaimVerdict {
        use yadorilink_ipc_proto::daemonctl::SpaceReclaimVerdict as W;
        match self {
            Self::Eligible => W::Eligible,
            Self::Pinned => W::Pinned,
            Self::UnsupportedRoot => W::UnsupportedRoot,
            Self::CustodyUnavailable => W::CustodyUnavailable,
            Self::Busy => W::Busy,
            Self::Changed => W::Changed,
            Self::SafetyBlocked => W::SafetyBlocked,
        }
    }
}

/// The background loop: a look at free space every [`PASS_INTERVAL`], the first one
/// [`FIRST_PASS_DELAY`] after start-up.
pub(crate) async fn run(auto: Arc<AutoReclaim>) {
    tokio::time::sleep(FIRST_PASS_DELAY).await;
    let mut interval = tokio::time::interval(PASS_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        auto.run_pass().await;
    }
}

#[cfg(test)]
mod tests;
