#![cfg(test)]

//! The automatic space management policy: one verdict per downloaded item, a dry run that deletes
//! nothing, and a pass that acts only under disk pressure, through the ordinary eviction.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use yadorilink_replica_domain::session_state::MaterializationPolicy;

use super::*;
use crate::provider_evict::ProviderEvictor;
use crate::provider_evidence::ProviderMembership;
use crate::provider_reclaim::tests::{data_of, Fx, Log, GROUP};
use crate::provider_reclaim::ProviderReclaim;

const OK: u8 = 0;
const LOW: u8 = 1;
const CRITICAL: u8 = 2;
const UNREADABLE: u8 = 3;

/// Free space as a test sets it. Under pressure it stays so until `relieve_after` files have been
/// handed to the host, which is when it reads `ok`.
pub(crate) struct FakeEnv {
    host: std::sync::atomic::AtomicBool,
    peers: std::sync::atomic::AtomicBool,
    free: AtomicU8,
    relieve_after: AtomicUsize,
    log: Log,
}

impl ReclaimEnvironment for FakeEnv {
    fn host_connected(&self) -> bool {
        self.host.load(Ordering::SeqCst)
    }
    fn peers_available(&self, _group_id: &str) -> bool {
        self.peers.load(Ordering::SeqCst)
    }
    fn free_space(&self) -> Option<FreeSpaceState> {
        let evicted = self.log.lock().unwrap().iter().filter(|e| *e == "host_evict").count();
        if evicted >= self.relieve_after.load(Ordering::SeqCst) {
            return Some(FreeSpaceState::Ok);
        }
        match self.free.load(Ordering::SeqCst) {
            OK => Some(FreeSpaceState::Ok),
            LOW => Some(FreeSpaceState::Low),
            CRITICAL => Some(FreeSpaceState::Critical),
            _ => None,
        }
    }
}

pub(crate) struct Rig {
    pub(crate) fx: Fx,
    pub(crate) env: Arc<FakeEnv>,
    pub(crate) auto: Arc<AutoReclaim>,
    /// Keeps the settings directory alive.
    pub(crate) _dir: tempfile::TempDir,
    downloaded: Mutex<Vec<(ItemId, u64)>>,
    epoch: std::sync::atomic::AtomicU64,
}

impl Rig {
    pub(crate) fn new() -> Self {
        Self::with_reclaim(|fx| fx.reclaim())
    }

    /// A rig whose eviction path frees blocks through the reclaim `reclaim` builds.
    pub(crate) fn with_reclaim(reclaim: impl FnOnce(&Fx) -> Arc<ProviderReclaim>) -> Self {
        let fx = Fx::new();
        let reclaim = reclaim(&fx);
        let env = Arc::new(FakeEnv {
            host: std::sync::atomic::AtomicBool::new(true),
            peers: std::sync::atomic::AtomicBool::new(true),
            free: AtomicU8::new(CRITICAL),
            relieve_after: AtomicUsize::new(usize::MAX),
            log: fx.log.clone(),
        });
        let dir = tempfile::tempdir().unwrap();
        let evictor = Arc::new(ProviderEvictor::new(
            fx.state.clone(),
            fx.host.clone(),
            reclaim,
            fx.membership.clone(),
        ));
        let auto = Arc::new(AutoReclaim::new(
            fx.state.clone(),
            evictor,
            fx.membership.clone(),
            env.clone(),
            SpaceManagementStore::new(dir.path()),
        ));
        Self {
            fx,
            env,
            auto,
            _dir: dir,
            downloaded: Mutex::default(),
            epoch: std::sync::atomic::AtomicU64::new(1000),
        }
    }

    /// A file of `len` bytes the daemon handed to the OS. The host's report of what it holds
    /// follows with [`Self::host_reports`], once for all the files.
    pub(crate) fn downloaded(&self, path: &str, seq: i64, len: usize) -> ItemId {
        self.fx.commit(path, seq, &[&data_of(seq as u8, len)]);
        let item = self.fx.item(path);
        let repo = self.fx.state.replica_coordinator.provider_repository();
        let version = repo.current_version_hash(&self.fx.root, &item).unwrap().unwrap();
        let handoff = repo.record_handoff(&self.fx.root, &item, version).unwrap().unwrap();
        self.downloaded.lock().unwrap().push((item, handoff));
        item
    }

    /// The host lists every file handed over so far as held, in one report begun after them.
    pub(crate) fn host_reports(&self) {
        self.host_reports_to(&self.fx.membership);
    }

    /// [`Self::host_reports`] to a given record of what the host holds.
    fn host_reports_to(&self, membership: &ProviderMembership) {
        let held = self.downloaded.lock().unwrap().clone();
        let repo = self.fx.state.replica_coordinator.provider_repository();
        let observed = held.iter().map(|(_, seq)| *seq).max().unwrap_or(0);
        let report = yadorilink_ipc_proto::shellipc::ProviderMaterializedReport {
            root_id: hex::decode(&self.fx.root).unwrap(),
            reporter_epoch: self.epoch.fetch_add(1, Ordering::SeqCst),
            report_seq: 1,
            full: true,
            observed_after_seq: observed,
            upserts: held
                .iter()
                .map(|(item, _)| yadorilink_ipc_proto::shellipc::ProviderMaterializedItem {
                    item_id: item.to_vec(),
                })
                .collect(),
            removed: Vec::new(),
            more: false,
        };
        let latest = repo.latest_evidence_seq(&self.fx.root).unwrap().unwrap();
        assert!(!membership.apply(&report, latest).needs_full, "report refused");
    }

    pub(crate) fn turn_on(&self) {
        self.auto.settings.set(true).unwrap();
    }

    /// The host drops its copy of `path` and reports the smaller set.
    pub(crate) fn host_dropped(&self, path: &str) {
        let repo = self.fx.state.replica_coordinator.provider_repository();
        let item = repo.item_for_path(&self.fx.root, path).unwrap().unwrap();
        self.downloaded.lock().unwrap().retain(|(i, _)| *i != item);
        self.host_reports();
    }

    pub(crate) fn host_asked(&self) -> bool {
        self.fx.log.lock().unwrap().iter().any(|entry| entry == "host_evict")
    }

    pub(crate) fn scan(&self) -> Scan {
        self.auto.scan(&HashSet::new())
    }

    pub(crate) fn verdict(&self, path: &str) -> Option<Verdict> {
        self.scan().entries.iter().find(|e| e.path == path).map(|e| e.verdict)
    }
}

fn facts() -> Facts {
    Facts {
        standing_blocker: None,
        host_connected: true,
        kept: Kept::No,
        os_copy: OsCopy::Current,
        busy: false,
        custody_reachable: true,
    }
}

#[test]
fn the_rule_gives_each_fact_its_verdict() {
    let v = |f: Facts| classify(&f);
    assert_eq!(v(facts()), Some(Verdict::Eligible));
    assert_eq!(v(Facts { kept: Kept::Yes, ..facts() }), Some(Verdict::Pinned));
    assert_eq!(v(Facts { kept: Kept::Unreadable, ..facts() }), Some(Verdict::SafetyBlocked));
    assert_eq!(v(Facts { host_connected: false, ..facts() }), Some(Verdict::SafetyBlocked));
    assert_eq!(v(Facts { os_copy: OsCopy::Unconfirmed, ..facts() }), Some(Verdict::Changed));
    assert_eq!(v(Facts { os_copy: OsCopy::Absent, ..facts() }), None);
    assert_eq!(
        v(Facts {
            os_copy: OsCopy::Absent,
            standing_blocker: Some(Retained::FullReplica),
            ..facts()
        }),
        None,
        "a file with no download is not counted against its folder"
    );
    assert_eq!(v(Facts { busy: true, ..facts() }), Some(Verdict::Busy));
    assert_eq!(v(Facts { custody_reachable: false, ..facts() }), Some(Verdict::CustodyUnavailable));
    assert_eq!(
        v(Facts { standing_blocker: Some(Retained::FullReplica), ..facts() }),
        Some(Verdict::UnsupportedRoot)
    );
}

#[test]
fn a_pin_beats_every_other_reason_to_reclaim() {
    assert_eq!(classify(&Facts { kept: Kept::Yes, ..facts() }), Some(Verdict::Pinned));
}

#[test]
fn only_low_or_critical_free_space_is_pressure_and_an_unreadable_one_is_not() {
    assert!(!under_pressure(Some(FreeSpaceState::Ok)));
    assert!(under_pressure(Some(FreeSpaceState::Low)));
    assert!(under_pressure(Some(FreeSpaceState::Critical)));
    assert!(!under_pressure(None));
}

#[test]
fn every_refusal_of_the_eviction_path_has_a_verdict() {
    use Retained::*;
    for why in [
        CustodyUnsupported,
        FullReplica,
        CustodyNotAcquired,
        Busy,
        VersionMoved,
        NothingFreed,
        HostBusy,
        CustodyRequired,
        NotConfirmed,
        HostRefused,
    ] {
        assert_ne!(Verdict::from_retained(why), Verdict::Eligible, "{}", why.code());
    }
    assert_eq!(Verdict::from_retained(HostBusy), Verdict::Busy);
    assert_eq!(Verdict::from_retained(NotConfirmed), Verdict::Changed);
    assert_eq!(Verdict::from_retained(CustodyNotAcquired), Verdict::CustodyUnavailable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scan_gives_each_downloaded_file_its_verdict_and_deletes_nothing() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.downloaded("dir/kept.bin", 4, 4096);
    rig.fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "dir").unwrap();
    // Listed with a stale copy: a newer version arrived after the download.
    rig.downloaded("changing.bin", 5, 4096);
    rig.host_reports();
    rig.fx.commit("changing.bin", 6, &[&data_of(9, 4096)]);
    // Not downloaded at all: a published item the host does not hold.
    rig.fx.commit("remote.bin", 7, &[&data_of(7, 4096)]);
    rig.fx.item("remote.bin");

    let scan = rig.scan();
    let verdict = |path: &str| scan.entries.iter().find(|e| e.path == path).map(|e| e.verdict);

    assert_eq!(verdict("a.bin"), Some(Verdict::Eligible));
    assert_eq!(verdict("dir/kept.bin"), Some(Verdict::Pinned));
    assert_eq!(verdict("changing.bin"), Some(Verdict::Changed));
    assert_eq!(verdict("remote.bin"), None, "an item with no download is not looked at");
    assert_eq!(scan.count(Verdict::Eligible), 1);
    assert!(rig.fx.log.lock().unwrap().is_empty(), "the dry run asked the host or custody");
}

/// What a status read offers as reclaimable is exactly what a pass would hand to the eviction
/// path: eligible files only, per group, nothing while space is fine, and nothing for a file the
/// eviction path refused recently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reclaimable_bytes_are_the_eligible_files_and_only_under_pressure() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.downloaded("b.bin", 2, 1000);
    rig.downloaded("dir/kept.bin", 4, 8192);
    rig.fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "dir").unwrap();
    rig.host_reports();

    // Before the first look nothing is offered (fail closed), and a status read never waits.
    assert!(rig.auto.reclaimable_by_group().is_empty());
    // ... but it started the look, which two scans at once would spoil (a path in use reads busy).
    while rig.auto.reclaimable.lock().unwrap().refreshing {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let found = rig.auto.reclaimable_by_group();
    assert_eq!(found.get(GROUP), Some(&5096), "a pinned file is not reclaimable");
    assert_eq!(found.len(), 1);

    // A file the eviction path refused is not offered again while it cools down.
    let refused = rig.scan().entries.into_iter().find(|e| e.path == "a.bin").unwrap();
    rig.auto.cool_down(&refused);
    rig.auto.refresh_reclaimable().await;
    assert_eq!(rig.auto.reclaimable_by_group().get(GROUP), Some(&1000));

    // Without custody no file can be given back: the action is not offered.
    rig.env.peers.store(false, Ordering::SeqCst);
    rig.auto.refresh_reclaimable().await;
    assert!(rig.auto.reclaimable_by_group().is_empty());

    // Space is fine again: nothing is offered and the old answer is forgotten.
    rig.env.peers.store(true, Ordering::SeqCst);
    rig.auto.refresh_reclaimable().await;
    assert_eq!(rig.auto.reclaimable_by_group().get(GROUP), Some(&1000));
    rig.env.free.store(OK, Ordering::SeqCst);
    assert!(rig.auto.reclaimable_by_group().is_empty());
    rig.env.free.store(LOW, Ordering::SeqCst);
    assert!(rig.auto.reclaimable_by_group().is_empty(), "forgotten, not served stale");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folder_that_keeps_full_copies_is_unsupported() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.fx.set_policy(MaterializationPolicy::Eager);
    assert_eq!(rig.verdict("a.bin"), Some(Verdict::UnsupportedRoot));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_connected_peer_means_custody_unavailable() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.env.peers.store(false, Ordering::SeqCst);
    assert_eq!(rig.verdict("a.bin"), Some(Verdict::CustodyUnavailable));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_item_held_by_another_operation_is_busy() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let lock = rig.fx.state.replica_coordinator.path_lock(GROUP, "a.bin");
    let _held = lock.try_lock_owned().unwrap();
    assert_eq!(rig.verdict("a.bin"), Some(Verdict::Busy));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_host_nothing_is_eligible() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.env.host.store(false, Ordering::SeqCst);
    assert_eq!(rig.verdict("a.bin"), Some(Verdict::SafetyBlocked));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scan_skips_what_it_is_told_to() {
    let rig = Rig::new();
    for n in 1..=3 {
        rig.downloaded(&format!("f{n}.bin"), n, 4096);
    }
    rig.host_reports();
    let all = rig.scan();
    let first = &all.entries[0];
    let skip: HashSet<_> = [(GROUP.to_owned(), first.path.clone(), first.item)].into();
    let skipped = rig.auto.scan(&skip);
    assert!(skipped.entries.iter().all(|e| e.path != first.path));
    assert_eq!(skipped.count(Verdict::Eligible), 2);
}

// --- the pass: only under pressure ---------------------------------------------------------------

fn outcome_of(summary: &PassSummary, path: &str) -> Outcome {
    summary.outcomes.iter().find(|(_, p, _)| p == path).map(|(_, _, o)| *o).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn off_by_default_nothing_is_read_or_asked_even_under_pressure() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();

    let summary = rig.auto.run_pass().await;

    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_pressure_nothing_is_evicted() {
    for free in [OK, UNREADABLE] {
        let rig = Rig::new();
        rig.turn_on();
        rig.downloaded("a.bin", 1, 4096);
        rig.host_reports();
        rig.env.free.store(free, Ordering::SeqCst);

        let summary = rig.auto.run_pass().await;

        assert!(summary.outcomes.is_empty());
        assert!(rig.fx.log.lock().unwrap().is_empty(), "free state {free}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_pressure_the_largest_files_go_first_and_it_stops_when_space_is_back() {
    for state in [LOW, CRITICAL] {
        let rig = Rig::new();
        rig.turn_on();
        rig.downloaded("small.bin", 1, 1_000);
        rig.downloaded("big.bin", 2, 30_000);
        rig.downloaded("mid.bin", 3, 10_000);
        rig.host_reports();
        rig.env.free.store(state, Ordering::SeqCst);
        rig.env.relieve_after.store(2, Ordering::SeqCst);

        let summary = rig.auto.run_pass().await;

        let order: Vec<_> = summary.outcomes.iter().map(|(_, p, _)| p.as_str()).collect();
        assert_eq!(order, ["big.bin", "mid.bin"], "free state {state}");
        assert!(summary.outcomes.iter().all(|(_, _, o)| matches!(o, Outcome::Reclaimed { .. })));
        assert_eq!(*rig.fx.log.lock().unwrap(), ["acquire", "host_evict", "acquire", "host_evict"]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_asks_about_a_bounded_number_of_items_and_a_repeat_continues() {
    let rig = Rig::new();
    rig.turn_on();
    let total = BATCH + 3;
    for n in 0..total {
        rig.downloaded(&format!("f{n:02}.bin"), n as i64 + 1, 4096 + n);
    }
    rig.host_reports();

    let first = rig.auto.run_pass().await;
    assert_eq!(first.reclaimed(), BATCH);
    for (_, path, _) in &first.outcomes {
        rig.host_dropped(path);
    }

    let second = rig.auto.run_pass().await;
    assert_eq!(second.reclaimed(), 3);
    for (_, path, _) in &second.outcomes {
        rig.host_dropped(path);
    }
    let third = rig.auto.run_pass().await;
    assert!(third.outcomes.is_empty(), "a finished job was done again");
}

/// Every way the ordinary eviction can say no leaves the file as it was and is named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_refusal_of_the_eviction_path_is_reported_and_leaves_the_file() {
    use crate::provider_publication::EvictOutcome as HostAnswer;

    // A program has the file open.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.fx.host.answers.lock().unwrap().push_back(HostAnswer::Busy);
    let summary = rig.auto.run_pass().await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Refused(Verdict::Busy));

    // The system declines (unshared changes).
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.fx.host.answers.lock().unwrap().push_back(HostAnswer::Error("-2008".into()));
    let summary = rig.auto.run_pass().await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Refused(Verdict::SafetyBlocked));

    // No lease, and the local blocks cannot be proven good.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.fx.custody.grant.store(false, Ordering::SeqCst);
    for entry in std::fs::read_dir(rig.fx.store_root.join("segments")).unwrap() {
        let file = std::fs::OpenOptions::new().write(true).open(entry.unwrap().path()).unwrap();
        file.set_len(0).unwrap();
    }
    let summary = rig.auto.run_pass().await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Refused(Verdict::CustodyUnavailable));
    assert!(!rig.host_asked());

    // No other device is connected: custody is unavailable before anything is asked.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.env.peers.store(false, Ordering::SeqCst);
    let summary = rig.auto.run_pass().await;
    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty());

    // The host disconnects before the pass: nothing is eligible, nothing is asked.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.env.host.store(false, Ordering::SeqCst);
    let summary = rig.auto.run_pass().await;
    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty());
}

/// A pinned, changing or busy file is never taken, whatever its size.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pinned_changing_and_busy_files_are_left_even_when_they_are_the_largest() {
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("pinned.bin", 1, 50_000);
    rig.downloaded("busy.bin", 2, 40_000);
    rig.downloaded("changing.bin", 3, 30_000);
    rig.downloaded("ok.bin", 4, 1_000);
    rig.host_reports();
    rig.fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "pinned.bin").unwrap();
    rig.fx.commit("changing.bin", 9, &[&data_of(9, 30_000)]);
    let lock = rig.fx.state.replica_coordinator.path_lock(GROUP, "busy.bin");
    let _held = lock.try_lock_owned().unwrap();

    let summary = rig.auto.run_pass().await;

    let order: Vec<_> = summary.outcomes.iter().map(|(_, p, _)| p.as_str()).collect();
    assert_eq!(order, ["ok.bin"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_item_is_left_alone_for_a_while_and_others_get_their_turn() {
    use crate::provider_publication::EvictOutcome as HostAnswer;
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.downloaded("b.bin", 2, 2048);
    rig.host_reports();
    rig.fx.host.answers.lock().unwrap().push_back(HostAnswer::Busy);

    let first = rig.auto.run_pass().await;
    assert_eq!(outcome_of(&first, "a.bin"), Outcome::Refused(Verdict::Busy));
    assert!(matches!(outcome_of(&first, "b.bin"), Outcome::Reclaimed { .. }));
    rig.host_dropped("b.bin");

    let second = rig.auto.run_pass().await;
    assert!(second.outcomes.is_empty(), "the refused item was asked again at once");

    // After the cooldown it is looked at again.
    for until in rig.auto.cooldown.lock().unwrap().values_mut() {
        *until = 0;
    }
    let third = rig.auto.run_pass().await;
    assert_eq!(third.outcomes.len(), 1);
    assert_eq!(third.outcomes[0].1, "a.bin");
}

// --- the destructive boundary --------------------------------------------------------------------

/// What happens between selection and the eviction decides: each change leaves the file alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_after_selection_means_nothing_is_evicted() {
    // Modified: a newer version arrives.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    rig.fx.commit("a.bin", 2, &[&data_of(2, 4096)]);
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Skipped(Verdict::Changed));
    assert!(rig.fx.log.lock().unwrap().is_empty());

    // Pinned.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    rig.fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "a.bin").unwrap();
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Skipped(Verdict::Pinned));
    assert!(rig.fx.log.lock().unwrap().is_empty());

    // Taken by another operation.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    let lock = rig.fx.state.replica_coordinator.path_lock(GROUP, "a.bin");
    let _held = lock.try_lock_owned().unwrap();
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Skipped(Verdict::Busy));

    // Free space recovered meanwhile: nothing is taken.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    rig.env.free.store(OK, Ordering::SeqCst);
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty());
}

/// The race inside the eviction itself: a pin or an edit that lands while the custody lease is
/// being taken is seen by the eviction's own checks, and the host is never asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_or_an_edit_during_the_lease_is_caught_by_the_eviction_itself() {
    // Pin lands during the lease.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    let state = rig.fx.state.clone();
    *rig.fx.custody.during_acquire.lock().unwrap() = Some(Box::new(move || {
        state.replica_coordinator.pinned_item_repository().pin(GROUP, "a.bin").unwrap();
    }));
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Refused(Verdict::Pinned));
    assert!(!rig.host_asked());

    // A newer version lands during the lease.
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    let fx = Arc::new(rig.fx);
    let inner = fx.clone();
    *fx.custody.during_acquire.lock().unwrap() = Some(Box::new(move || {
        inner.commit("a.bin", 2, &[&data_of(2, 4096)]);
    }));
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert_eq!(outcome_of(&summary, "a.bin"), Outcome::Refused(Verdict::Changed));
    assert!(!fx.log.lock().unwrap().iter().any(|entry| entry == "host_evict"));
}

/// Turning the setting Off while a pass is under way stops it before the next item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn turning_it_off_stops_the_pass_before_the_next_item() {
    let rig = Rig::new();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let selected = rig.scan().entries;
    // The setting was never turned on (or was turned off since selection).
    let summary = rig.auto.reclaim_entries(&selected).await;
    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty());
}

// --- acceptance: what automatic space management may and may not do ----------------------------

/// Where the ordinary eviction could never free a block (a volume without durable namespace
/// changes, such as Windows while its gate is closed, or a build without custody leases), the
/// policy is inert: every downloaded file is unsupported and nothing is asked of anyone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn where_blocks_can_never_be_freed_safely_the_policy_is_inert() {
    let rig = Rig::with_reclaim(|fx| {
        Arc::new(
            ProviderReclaim::with_custody(fx.state.clone(), fx.custody.clone())
                .with_volume_verdict_for_test(|_| false),
        )
    });
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();

    assert_eq!(rig.verdict("a.bin"), Some(Verdict::UnsupportedRoot));
    let summary = rig.auto.run_pass().await;

    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty(), "the host or custody was asked");
}

/// A folder this device keeps full copies of never gives space back automatically.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_copy_folder_is_never_reclaimed_by_a_pass() {
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.fx.set_policy(MaterializationPolicy::Eager);

    let summary = rig.auto.run_pass().await;

    assert!(summary.outcomes.is_empty());
    assert!(rig.fx.log.lock().unwrap().is_empty());
}

/// Without a lease on exactly this version (no other device holds it yet, as for an edit made
/// here and not yet shared), the OS copy may go only because every block is verified locally,
/// and not one block is deleted: the bytes stay on this device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_lease_on_the_exact_version_no_block_is_deleted() {
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    rig.fx.custody.grant.store(false, Ordering::SeqCst);
    let blocks: Vec<String> = rig
        .fx
        .state
        .replica_coordinator
        .sqlite()
        .dag_get_current_version_record(GROUP, "a.bin")
        .unwrap()
        .unwrap()
        .to_file_version()
        .blocks
        .iter()
        .map(|b| hex::encode(&b.hash.0))
        .collect();

    let summary = rig.auto.run_pass().await;

    assert_eq!(
        outcome_of(&summary, "a.bin"),
        Outcome::Reclaimed { blocks: 0, bytes: 0, kept: Some(Retained::CustodyNotAcquired) }
    );
    assert!(blocks.iter().all(|hash| rig.fx.cached(hash)), "a block was deleted without a lease");
}

/// A lease that no longer backs the version when the blocks would go frees nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_that_stops_backing_the_version_deletes_no_block() {
    let rig = Rig::new();
    rig.turn_on();
    let hashes = {
        rig.downloaded("a.bin", 1, 4096);
        rig.fx
            .state
            .replica_coordinator
            .sqlite()
            .dag_get_current_version_record(GROUP, "a.bin")
            .unwrap()
            .unwrap()
            .to_file_version()
            .blocks
            .iter()
            .map(|b| hex::encode(&b.hash.0))
            .collect::<Vec<_>>()
    };
    rig.host_reports();
    rig.fx.custody.valid.store(false, Ordering::SeqCst);

    let summary = rig.auto.run_pass().await;

    assert!(matches!(
        outcome_of(&summary, "a.bin"),
        Outcome::Reclaimed { blocks: 0, kept: Some(Retained::NothingFreed), .. }
    ));
    assert!(hashes.iter().all(|hash| rig.fx.cached(hash)), "a block went without a valid lease");
}

/// A restart forgets nothing that matters: there is no usage signal to reset, and until the host
/// has reported what it holds every file reads as not downloaded, so nothing is taken. Once it
/// has, a pass under pressure still asks about one bounded batch only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_takes_nothing_until_the_host_reports_and_then_one_batch() {
    let rig = Rig::new();
    rig.turn_on();
    for n in 0..BATCH + 3 {
        rig.downloaded(&format!("f{n:02}.bin"), n as i64 + 1, 4096 + n);
    }
    rig.host_reports();

    // The daemon restarts: the same database and settings, a new process's memory.
    let membership = Arc::new(ProviderMembership::default());
    let evictor = Arc::new(ProviderEvictor::new(
        rig.fx.state.clone(),
        rig.fx.host.clone(),
        rig.fx.reclaim(),
        membership.clone(),
    ));
    let restarted = Arc::new(AutoReclaim::new(
        rig.fx.state.clone(),
        evictor,
        membership.clone(),
        rig.env.clone(),
        SpaceManagementStore::new(rig._dir.path()),
    ));

    let before_report = restarted.run_pass().await;
    assert!(before_report.outcomes.is_empty(), "{:?}", before_report.outcomes);
    assert!(rig.fx.log.lock().unwrap().is_empty(), "a blank picture was acted on");

    rig.host_reports_to(&membership);
    let after_report = restarted.run_pass().await;
    assert_eq!(after_report.outcomes.len(), BATCH);
    assert_eq!(after_report.reclaimed(), BATCH);
}

/// The first pass after start-up waits for the host's reports to arrive.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn the_first_pass_waits_after_start_up() {
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("a.bin", 1, 4096);
    rig.host_reports();
    let task = tokio::spawn(run(rig.auto.clone()));

    tokio::time::sleep(FIRST_PASS_DELAY - Duration::from_secs(1)).await;
    assert!(!rig.host_asked(), "a pass ran before the start-up delay");

    for _ in 0..1000 {
        if rig.host_asked() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    task.abort();
    assert!(rig.host_asked(), "no pass ran after the start-up delay");
}

/// Each verdict has its own code and wire value, so a diagnostic or a dry run tells eligible,
/// pinned, unsupported, custody, busy, changed and safety apart.
#[test]
fn every_verdict_is_named_apart() {
    use Verdict::*;
    let all = [Eligible, Pinned, UnsupportedRoot, CustodyUnavailable, Busy, Changed, SafetyBlocked];
    let codes: HashSet<_> = all.iter().map(|v| v.code()).collect();
    let wire: HashSet<_> = all.iter().map(|v| v.to_wire() as i32).collect();
    assert_eq!(codes.len(), all.len());
    assert_eq!(wire.len(), all.len());
}

/// One pass reports what happened to each file in terms a person can act on: given back, kept
/// because pinned, kept for safety (refused by the eviction path).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pass_names_each_files_outcome() {
    use crate::provider_publication::EvictOutcome as HostAnswer;
    let rig = Rig::new();
    rig.turn_on();
    rig.downloaded("declined.bin", 1, 30_000);
    rig.downloaded("pinned.bin", 2, 20_000);
    rig.downloaded("ok.bin", 3, 10_000);
    rig.host_reports();
    let selected = {
        let mut entries = rig.scan().entries;
        entries.sort_by_key(|e| std::cmp::Reverse(e.size));
        entries
    };
    rig.fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "pinned.bin").unwrap();
    rig.fx.host.answers.lock().unwrap().push_back(HostAnswer::Error("-2008".into()));

    let summary = rig.auto.reclaim_entries(&selected).await;

    assert_eq!(outcome_of(&summary, "declined.bin"), Outcome::Refused(Verdict::SafetyBlocked));
    assert_eq!(outcome_of(&summary, "pinned.bin"), Outcome::Skipped(Verdict::Pinned));
    assert!(matches!(outcome_of(&summary, "ok.bin"), Outcome::Reclaimed { .. }));
}
