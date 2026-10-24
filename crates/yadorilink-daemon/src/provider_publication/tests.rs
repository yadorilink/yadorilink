#![cfg(test)]

//! The publication state machine against a fake host: the fence, the order of the steps, EBUSY
//! isolation, collapse to the latest version, every crash point, and lost-state rebootstrap.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::ProviderKind;
use yadorilink_sync_sqlite::provider::{ItemId, Publication};
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

use super::*;

const GROUP: &str = "group-1";

type EvictFn = Arc<dyn Fn(ItemId) -> BoxFuture<'static, EvictOutcome> + Send + Sync>;
type SignalFn = Arc<dyn Fn(u64, Vec<ItemId>) -> BoxFuture<'static, bool> + Send + Sync>;

struct FakeHost {
    log: Mutex<Vec<String>>,
    evict: Mutex<EvictFn>,
    signal: Mutex<SignalFn>,
    /// How many revocations fail before one succeeds.
    revoke_failures: AtomicUsize,
    revoke_calls: AtomicUsize,
    /// The parent folders each signal named (the host waits below them).
    signalled_parents: Mutex<Vec<Vec<Vec<u8>>>>,
}

impl FakeHost {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            log: Mutex::default(),
            evict: Mutex::new(Arc::new(|_| Box::pin(async { EvictOutcome::Evicted }))),
            signal: Mutex::new(Arc::new(|_, _| Box::pin(async { true }))),
            revoke_failures: AtomicUsize::new(0),
            revoke_calls: AtomicUsize::new(0),
            signalled_parents: Mutex::new(Vec::new()),
        })
    }

    fn set_evict(&self, f: EvictFn) {
        *self.evict.lock().unwrap() = f;
    }

    fn set_signal(&self, f: SignalFn) {
        *self.signal.lock().unwrap() = f;
    }

    fn raw_log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    /// The log in the order of FIRST occurrences: the signal is repeated by our own schedule
    /// until the timer publishes, so a line can appear many times.
    fn log(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        self.raw_log().into_iter().filter(|line| seen.insert(line.clone())).collect()
    }
}

impl ProviderHost for FakeHost {
    fn revoke_unconsumed_handoffs(&self, _root_id: &str, item: &ItemId) -> bool {
        let _ = item;
        self.revoke_calls.fetch_add(1, Ordering::SeqCst);
        self.revoke_failures
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_err()
    }

    fn folders_changed(&self, new_root_id: &str) {
        self.log.lock().unwrap().push(format!("folders changed {new_root_id}"));
    }

    fn evict<'a>(
        &'a self,
        _root: &'a str,
        item: ItemId,
        _t: [u8; 32],
    ) -> BoxFuture<'a, EvictOutcome> {
        self.log.lock().unwrap().push(format!("evict {}", item[0]));
        let f = self.evict.lock().unwrap().clone();
        f(item)
    }

    fn signal<'a>(
        &'a self,
        _root: &'a str,
        revision: u64,
        items: Vec<ItemId>,
        parent_ids: Vec<Vec<u8>>,
    ) -> BoxFuture<'a, bool> {
        self.signalled_parents.lock().unwrap().push(parent_ids);
        self.log.lock().unwrap().push(match items.first() {
            Some(item) => format!("signal {} r{revision}", item[0]),
            None => format!("signal root r{revision}"),
        });
        let f = self.signal.lock().unwrap().clone();
        f(revision, items)
    }
}

struct Fx {
    state: Arc<DaemonState>,
    root: String,
}

impl Fx {
    fn new() -> Self {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.replica_coordinator.link_repository().add_link("/provider/p", GROUP).unwrap();
        let root = state
            .replica_coordinator
            .provider_repository()
            .declare_root(GROUP, ProviderKind::MacFileProvider, "P")
            .unwrap();
        Self { state, root }
    }

    fn repo(&self) -> &yadorilink_sync_sqlite::provider::ProviderRepository {
        self.state.replica_coordinator.provider_repository()
    }

    /// Commits a version of `path`: size identifies the content, mtime is metadata.
    fn commit(&self, path: &str, seq: i64, size: i64, mtime: i64) {
        let blocks = if size == 0 {
            "[]".to_string()
        } else {
            format!(r#"[{{"hash":{:?},"offset":0,"size":{size}}}]"#, vec![size as u8; 32])
        };
        self.state
            .replica_coordinator
            .database()
            .write_immediate::<_, SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![GROUP, path],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state, admitted_at_unix_nanos) \
                     VALUES (?1, ?2, ?3, ?4, ?6, 0, ?5, 'current', 0)",
                    rusqlite::params![GROUP, path, size, mtime, seq, blocks],
                )?;
                let row = yadorilink_sync_sqlite::read_canonical_current_row(tx, GROUP, path)?
                    .expect("the row just written");
                let version = yadorilink_replica_domain::session_state::CurrentVersionRecord::from(
                    row.snapshot,
                )
                .to_file_version();
                yadorilink_sync_sqlite::dag_store::put_file_version(tx, GROUP, &version)?;
                Ok(())
            })
            .unwrap();
    }

    /// An item the OS was told at its current version.
    fn published_item(&self, path: &str, size: i64) -> ItemId {
        self.commit(path, 1, size, 100);
        let id = self.repo().mint_item(&self.root, path).unwrap();
        let served = self.repo().current_version_hash(&self.root, &id).unwrap().unwrap();
        self.repo().publish_first(&self.root, &id, served).unwrap();
        // The fixture's own setup is not a change the tests want announced.
        if let Some(changes) = self.repo().unannounced_changes(&self.root).unwrap() {
            self.repo().mark_announced(&self.root, changes).unwrap();
        }
        id
    }

    fn driver(&self, host: &Arc<FakeHost>) -> Arc<PublicationDriver> {
        self.driver_with_release(host, Duration::from_millis(120))
    }

    fn driver_with_release(
        &self,
        host: &Arc<FakeHost>,
        release_after: Duration,
    ) -> Arc<PublicationDriver> {
        self.driver_with_clock(host, release_after, PublicationConfig::default().now_ms)
    }

    fn driver_with_clock(
        &self,
        host: &Arc<FakeHost>,
        release_after: Duration,
        now_ms: fn() -> i64,
    ) -> Arc<PublicationDriver> {
        Arc::new(PublicationDriver::new(
            self.state.replica_coordinator.clone(),
            host.clone(),
            PublicationConfig {
                backoff_initial: Duration::from_millis(5),
                backoff_cap: Duration::from_millis(20),
                max_in_flight: 4,
                release_after,
                now_ms,
            },
        ))
    }

    fn publication(&self, id: &ItemId) -> Option<Publication> {
        self.repo().publication(&self.root, id).unwrap()
    }

    fn served_size(&self, id: &ItemId) -> i64 {
        self.repo().served_view(&self.root, id).unwrap().unwrap().version.size as i64
    }
}

async fn settle(driver: &Arc<PublicationDriver>) {
    tokio::time::timeout(Duration::from_secs(10), driver.idle())
        .await
        .expect("the publication tasks did not finish");
}

/// Waits until `done`. The bound is only a backstop against a hang: what the wait is for is the
/// condition, and a slow host reaches it late, not never.
async fn wait_for(done: impl Fn() -> bool, what: &str) {
    let started = tokio::time::Instant::now();
    while !done() {
        assert!(started.elapsed() < Duration::from_secs(60), "{what}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// [`settle`] for a run whose cost scales with the work: it fails only when
/// `progress` (which must grow with every step the host sees) stands still for
/// ten seconds, however slowly the machine runs the whole of it.
async fn settle_while_progressing(driver: &Arc<PublicationDriver>, progress: impl Fn() -> usize) {
    let idle = driver.idle();
    tokio::pin!(idle);
    let (mut last, mut since) = (progress(), tokio::time::Instant::now());
    loop {
        tokio::select! {
            () = &mut idle => return,
            () = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        let now = progress();
        if now != last {
            (last, since) = (now, tokio::time::Instant::now());
        }
        assert!(
            since.elapsed() < Duration::from_secs(10),
            "the publication tasks stopped making progress at {now} host calls"
        );
    }
}

/// A handoff file that cannot be taken back stops the publication: nothing is evicted or
/// signalled past it, and the next try (after the failure clears) publishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_revocation_stops_the_publication_until_it_succeeds() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    host.revoke_failures.store(2, Ordering::SeqCst);
    let first_evict_after_revokes = Arc::new(AtomicUsize::new(0));
    {
        let weak = Arc::downgrade(&host);
        let seen = first_evict_after_revokes.clone();
        host.set_evict(Arc::new(move |_| {
            if let Some(host) = weak.upgrade() {
                let _ = seen.compare_exchange(
                    0,
                    host.revoke_calls.load(Ordering::SeqCst),
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
            Box::pin(async { EvictOutcome::Evicted })
        }));
    }
    fx.commit("a.txt", 2, 99, 777);
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    assert!(host.revoke_calls.load(Ordering::SeqCst) >= 3);
    // The first eviction came only after the third revocation call (the first two failed).
    assert_eq!(
        first_evict_after_revokes.load(Ordering::SeqCst),
        3,
        "an eviction ran past a failed revocation"
    );
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// A worker that panics produces no result. Its item used to stay "in flight" for ever, so the
/// runner found work pending that it believed was already running and looped on it without ever
/// awaiting: a runtime thread burning a core, the item never published, and a runtime that could
/// not shut down. The item is retried after its backoff like any failed attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_attempt_is_retried_and_does_not_stall_the_runner() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    let panicked = Arc::new(AtomicUsize::new(0));
    {
        let panicked = panicked.clone();
        host.set_evict(Arc::new(move |_| {
            assert!(panicked.fetch_add(1, Ordering::SeqCst) > 0, "the host failed its first call");
            Box::pin(async { EvictOutcome::Evicted })
        }));
    }
    fx.commit("a.txt", 2, 99, 777);
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    assert!(panicked.load(Ordering::SeqCst) >= 2, "the failed attempt was not retried");
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// commit V2, fence ON, evict, signal, fence OFF: in this order, and V2 is observable nowhere
/// (not its bytes' size, not its metadata, not through a fetch) until the signal is acked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_content_change_is_fenced_evicted_signalled_and_only_then_published() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let (state, root, seen_evict) = (fx.state.clone(), fx.root.clone(), seen.clone());
        let seen_signal = seen.clone();
        let (state_signal, root_signal) = (state.clone(), root.clone());
        let seen = seen_evict;
        let (state, root) = (state, root);
        host.set_evict(Arc::new(move |item| {
            let (state, root, seen) = (state.clone(), root.clone(), seen.clone());
            Box::pin(async move {
                seen.lock().unwrap().push((
                    "evict",
                    fetch_gate(&state.replica_coordinator, &root, &item).unwrap(),
                    state
                        .replica_coordinator
                        .provider_repository()
                        .served_view(&root, &item)
                        .unwrap()
                        .unwrap()
                        .version
                        .size,
                ));
                EvictOutcome::Evicted
            })
        }));
        let (state, root, seen) = (state_signal, root_signal, seen_signal);
        host.set_signal(Arc::new(move |_, items| {
            let (state, root, seen) = (state.clone(), root.clone(), seen.clone());
            Box::pin(async move {
                seen.lock().unwrap().push((
                    "signal",
                    fetch_gate(&state.replica_coordinator, &root, &items[0]).unwrap(),
                    state
                        .replica_coordinator
                        .provider_repository()
                        .served_view(&root, &items[0])
                        .unwrap()
                        .unwrap()
                        .version
                        .size,
                ));
                true
            })
        }));
    }
    fx.commit("a.txt", 2, 99, 777); // V2: content AND metadata changed
    assert_eq!(
        fetch_gate(&fx.state.replica_coordinator, &fx.root, &id).unwrap(),
        FetchGate::PublicationPending
    );

    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;

    assert_eq!(
        host.log(),
        ["evict 0".replace('0', &id[0].to_string()), format!("signal {} r1", id[0])]
    );
    // At the eviction the OS was still shown V1 and the fetch was refused; at the signal the
    // version is announced, so it is fetchable (repeats of the pair follow until the timer).
    assert_eq!(
        seen.lock().unwrap()[..2],
        [("evict", FetchGate::PublicationPending, 10), ("signal", FetchGate::Allowed, 10)]
    );
    assert_eq!(fx.publication(&id), Some(Publication::Published));
    assert_eq!(fx.served_size(&id), 99);
    assert_eq!(
        fetch_gate(&fx.state.replica_coordinator, &fx.root, &id).unwrap(),
        FetchGate::Allowed
    );
}

/// A metadata-only change is signalled without any eviction and never fences a fetch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metadata_only_change_is_a_signal_without_an_eviction() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 10, 5555);
    assert_eq!(fx.publication(&id), Some(Publication::MetadataOnly));
    assert_eq!(
        fetch_gate(&fx.state.replica_coordinator, &fx.root, &id).unwrap(),
        FetchGate::Allowed
    );
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    assert_eq!(host.log(), [format!("signal {} r1", id[0])], "a metadata-only change evicted");
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// Eviction is a HINT: an item the OS keeps open (EBUSY forever) is still announced, delays no
/// other item and the root, and is published by the timer, never forced by anything else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_eviction_delays_nothing_and_is_not_a_release_condition() {
    let fx = Fx::new();
    let busy = fx.published_item("busy.txt", 10);
    let free = fx.published_item("free.txt", 20);
    fx.commit("busy.txt", 2, 11, 100);
    fx.commit("free.txt", 2, 21, 100);
    let host = FakeHost::new();
    host.set_evict(Arc::new(move |item| {
        Box::pin(async move {
            if item == busy {
                EvictOutcome::Busy
            } else {
                EvictOutcome::Evicted
            }
        })
    }));
    // The signals never succeed either: only the timer can publish.
    host.set_signal(Arc::new(|_, _| Box::pin(async { false })));
    // The release timer reads a clock this test moves, so how long the host takes to run it
    // cannot release the busy item early: it is released when the clock passes its due time.
    static SKEW_MS: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
    fn skewed_now_ms() -> i64 {
        (PublicationConfig::default().now_ms)() + SKEW_MS.load(Ordering::SeqCst)
    }
    let driver = fx.driver_with_clock(&host, Duration::from_secs(3600), skewed_now_ms);
    driver.kick(&fx.root);
    // Before the timer both are announced (their new views are shown), neither is published.
    wait_for(|| fx.event_seqs().len() >= 2, "the busy item delayed an announcement").await;
    assert_eq!(fx.shown_size(&busy), 11);
    assert_eq!(fx.shown_size(&free), 21);
    assert_eq!(fx.publication(&busy), Some(Publication::ContentPending));
    // The timer publishes both, the busy one included.
    SKEW_MS.store(2 * 3600 * 1000, Ordering::SeqCst);
    settle(&driver).await;
    assert_eq!(fx.publication(&busy), Some(Publication::Published));
    assert_eq!(fx.publication(&free), Some(Publication::Published));
}

/// V2 then V3 while the eviction is in flight: V3 is what is published; V2 never is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn versions_committed_while_pending_collapse_to_the_latest() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 20, 100); // V2
    let host = FakeHost::new();
    {
        let fx_state = fx.state.clone();
        let fx = Fx { state: fx_state, root: fx.root.clone() };
        let committed = Arc::new(AtomicUsize::new(0));
        host.set_evict(Arc::new(move |_| {
            let fx = Fx { state: fx.state.clone(), root: fx.root.clone() };
            let committed = committed.clone();
            Box::pin(async move {
                if committed.fetch_add(1, Ordering::SeqCst) == 0 {
                    fx.commit("a.txt", 3, 30, 100); // V3 lands during the eviction
                }
                EvictOutcome::Evicted
            })
        }));
    }
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    // V2 was evicted but never signalled (V3 landed first); V3 was evicted and then signalled.
    let log = host.log();
    // Distinct announcements: V2's was superseded by V3's (a later revision), only V3 survives.
    assert!(log.iter().filter(|l| l.starts_with("signal ")).count() >= 1, "{log:?}");
    assert_eq!(fx.served_size(&id), 30, "V2 was published");
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// Every crash point resumes from the committed rows alone: the pass starts again with an
/// eviction (idempotent) and a signal, and no item is published without a fresh eviction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_crash_point_resumes_from_the_rows() {
    // (name, what the first run's host does before the "crash")
    for point in [
        "after_commit_before_evict",
        "evict_unanswered",
        "evicted_signal_unacked",
        "signal_acked_record_lost",
    ] {
        let fx = Fx::new();
        let id = fx.published_item("a.txt", 10);
        fx.commit("a.txt", 2, 99, 100);
        let first = FakeHost::new();
        match point {
            "after_commit_before_evict" => {} // the daemon died before running anything
            "evict_unanswered" => first.set_evict(Arc::new(|_| Box::pin(std::future::pending()))),
            "evicted_signal_unacked" => {
                first.set_signal(Arc::new(|_, _| Box::pin(std::future::pending())))
            }
            "signal_acked_record_lost" => {
                // The host acked, then the daemon died before recording it: the future never
                // returns to the daemon's task.
                first.set_signal(Arc::new(|_, _| Box::pin(std::future::pending())));
            }
            _ => unreachable!(),
        }
        if point != "after_commit_before_evict" {
            let driver = fx.driver(&first);
            driver.kick(&fx.root);
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                fx.publication(&id),
                Some(Publication::ContentPending),
                "{point}: published without an ack"
            );
            assert_eq!(fx.served_size(&id), 10, "{point}: V2 observable before the ack");
            drop(driver); // the crash: tasks die with the process
        }
        // Restart: no stored progress. The host (already dataless) answers NOT_MATERIALIZED.
        let second = FakeHost::new();
        second.set_evict(Arc::new(|_| Box::pin(async { EvictOutcome::NotMaterialized })));
        let driver = fx.driver(&second);
        driver.kick(&fx.root);
        settle(&driver).await;
        assert_eq!(fx.publication(&id), Some(Publication::Published), "{point}");
        assert_eq!(fx.served_size(&id), 99, "{point}");
        let log = second.log();
        assert!(
            log[0].starts_with("evict"),
            "{point}: published without a fresh eviction: {log:?}"
        );
        assert!(log[1].starts_with("signal"), "{point}: {log:?}");
    }
}

/// No host connected: every item waits (retrying) and nothing is published or forced; the
/// host's reconnect runs the pass and everything completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_host_nothing_is_published_until_it_reconnects() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 99, 100);
    let host = FakeHost::new();
    host.set_evict(Arc::new(|_| Box::pin(async { EvictOutcome::NotConnected })));
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    // The pass runs on its own task: wait for it to have marked the item pending (a fixed
    // pause is not enough on a loaded machine, where the item still reads Published).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while fx.publication(&id) != Some(Publication::ContentPending)
        && tokio::time::Instant::now() < deadline
    {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(fx.publication(&id), Some(Publication::ContentPending));
    assert_eq!(fx.served_size(&id), 10);
    // A second pass does not start a second task for the same item.
    driver.kick(&fx.root);
    // The host reconnects.
    host.set_evict(Arc::new(|_| Box::pin(async { EvictOutcome::Evicted })));
    settle(&driver).await;
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// Published state that cannot be resolved is lost evidence: the root is rebootstrapped with a
/// new root_id and no items, and the host is told; the daemon never assumes the OS holds the
/// current version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unresolvable_published_version_rebootstraps_the_root() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 99, 100);
    fx.state
        .replica_coordinator
        .database()
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM file_versions", [])?;
            Ok(())
        })
        .unwrap();
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;

    let new_root = match fx.repo().declaration_for_group(GROUP).unwrap() {
        yadorilink_sync_sqlite::provider::ProviderDeclaration::Provider(root) => root.root_id,
        other => panic!("{other:?}"),
    };
    assert_ne!(new_root, fx.root, "the root was not replaced");
    assert!(fx.repo().path_for_item(&fx.root, &id).unwrap().is_none());
    assert_eq!(fx.repo().item_for_path(&new_root, "a.txt").unwrap(), None, "items survived");
    // Nothing was published from lost state: the only thing the host hears is the prompt to
    // list the provider folders again.
    assert_eq!(host.log(), [format!("folders changed {new_root}")]);
}

// ---- 2.3: operations bind to the PUBLISHED view ----

/// An edit built on V1 while V2 is current is a CONCURRENT edit; one built on the current
/// version is ordinary. The base the OS reports is the only truthful version signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_on_a_stale_base_is_concurrent_never_an_overwrite() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let v1 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    assert_eq!(
        classify_edit(&fx.state.replica_coordinator, &fx.root, &id, v1).unwrap(),
        Some(EditBase::Fresh)
    );

    fx.commit("a.txt", 2, 99, 100); // V2 arrives; the OS still shows V1
    let v2 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    assert_ne!(v1, v2);
    assert_eq!(
        classify_edit(&fx.state.replica_coordinator, &fx.root, &id, v1).unwrap(),
        Some(EditBase::Concurrent),
        "an edit on the published base was treated as an ordinary edit (V2 would be overwritten)"
    );
    assert_eq!(
        classify_edit(&fx.state.replica_coordinator, &fx.root, &id, v2).unwrap(),
        Some(EditBase::Fresh)
    );
    // An item that is gone has no verdict.
    fx.repo().retire_item(&fx.root, &id).unwrap();
    assert_eq!(classify_edit(&fx.state.replica_coordinator, &fx.root, &id, v1).unwrap(), None);
}

/// The fence refuses an item's fetch exactly while its content publication is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fence_on_fetch_follows_the_derived_state() {
    let fx = Fx::new();
    let fresh = fx.repo().mint_item(&fx.root, "never.txt").ok(); // no row: never fenced
    let _ = fresh;
    let id = fx.published_item("a.txt", 10);
    let gate = |item: &ItemId| fetch_gate(&fx.state.replica_coordinator, &fx.root, item).unwrap();
    assert_eq!(gate(&id), FetchGate::Allowed);
    fx.commit("a.txt", 2, 10, 5);
    assert_eq!(gate(&id), FetchGate::Allowed, "a metadata-only change fenced a fetch");
    fx.commit("a.txt", 3, 99, 5);
    assert_eq!(gate(&id), FetchGate::PublicationPending);
    fx.repo().retire_item(&fx.root, &id).unwrap();
    assert_eq!(gate(&id), FetchGate::NotFound);
}

/// A rename of a pending item keeps V2 pending and publishes the new name through the signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_keeps_the_update_pending() {
    let fx = Fx::new();
    let id = fx.published_item("old.txt", 10);
    fx.commit("old.txt", 2, 99, 100);
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            yadorilink_sync_sqlite::provider::rename_tree_for_tests(
                tx, GROUP, "old.txt", "new.txt",
            )?;
            tx.execute(
                "UPDATE files SET path = 'new.txt' WHERE group_id = ?1 AND path = 'old.txt'",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(fx.repo().item_for_path(&fx.root, "new.txt").unwrap(), Some(id));
    assert_eq!(fx.publication(&id), Some(Publication::ContentPending));
    assert_eq!(fx.served_size(&id), 10, "the renamed item showed V2");
}

/// An acknowledgement for V2 never publishes a V3 that was committed AFTER V2's signal and
/// before the ack: V3 still has to be evicted and signalled, and V2's ack never clears its fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ack_for_an_older_version_does_not_publish_a_newer_one() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 20, 100); // V2
    let host = FakeHost::new();
    let signals = Arc::new(AtomicUsize::new(0));
    {
        let (state, root) = (fx.state.clone(), fx.root.clone());
        let signals = signals.clone();
        host.set_signal(Arc::new(move |_, items| {
            let fx = Fx { state: state.clone(), root: root.clone() };
            let signals = signals.clone();
            Box::pin(async move {
                if !items.is_empty() && signals.fetch_add(1, Ordering::SeqCst) == 0 {
                    fx.commit("a.txt", 3, 30, 100); // V3 lands after V2's signal, before its ack
                }
                true
            })
        }));
    }
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;

    let log = host.log();
    assert_eq!(
        log.iter().filter(|l| l.starts_with("signal ")).count(),
        2,
        "V3 not announced and signalled: {log:?}"
    );
    assert_eq!(fx.served_size(&id), 30);
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// A rename of an unchanged version makes no item pending, but it is a provider-visible change:
/// it is counted in its own transaction and a root-level signal announces it exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rename_is_announced_by_a_root_level_signal() {
    let fx = Fx::new();
    let id = fx.published_item("old.txt", 10);
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            yadorilink_sync_sqlite::provider::rename_tree_for_tests(
                tx, GROUP, "old.txt", "new.txt",
            )?;
            tx.execute(
                "UPDATE files SET path = 'new.txt' WHERE group_id = ?1 AND path = 'old.txt'",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
    assert!(
        fx.repo().unannounced_changes(&fx.root).unwrap().is_some(),
        "the rename was not counted"
    );
    assert_eq!(fx.publication(&id), Some(Publication::Published), "nothing is item-pending");

    let host = FakeHost::new();
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    assert!(host.log().iter().any(|l| l.starts_with("signal root")), "{:?}", host.log());
    assert_eq!(fx.repo().unannounced_changes(&fx.root).unwrap(), None);
    let sent = host.log().len();
    driver.kick(&fx.root);
    settle(&driver).await;
    assert_eq!(host.log().len(), sent, "an announced change was announced again");
}

/// A large pending set is published by a BOUNDED pool: never more than the configured number of
/// attempts at once, and every item ends up published.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_pending_set_runs_on_a_bounded_pool() {
    let fx = Fx::new();
    let mut ids = Vec::new();
    for n in 0..120 {
        ids.push(fx.published_item(&format!("f{n:03}.txt"), 10));
    }
    for n in 0..120 {
        fx.commit(&format!("f{n:03}.txt"), 2, 99, 100);
    }
    let host = FakeHost::new();
    let (current, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    {
        let (current, peak) = (current.clone(), peak.clone());
        host.set_evict(Arc::new(move |_| {
            let (current, peak) = (current.clone(), peak.clone());
            Box::pin(async move {
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(2)).await;
                current.fetch_sub(1, Ordering::SeqCst);
                EvictOutcome::Evicted
            })
        }));
    }
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    // 120 items cost a fixed amount of CPU, so a loaded machine needs
    // however long it needs: what must not happen is to stand still.
    settle_while_progressing(&driver, || host.raw_log().len()).await;
    assert!(peak.load(Ordering::SeqCst) <= 4, "peak {}", peak.load(Ordering::SeqCst));
    for id in &ids {
        assert_eq!(fx.publication(id), Some(Publication::Published));
    }
}

/// Dropping the driver cancels its runners and their retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_driver_stops_its_retries() {
    let fx = Fx::new();
    fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 99, 100);
    let host = FakeHost::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    {
        let attempts = attempts.clone();
        host.set_signal(Arc::new(move |_, _| {
            attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { false })
        }));
    }
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    // Wait for the retries themselves, not for a stretch of wall-clock time.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    while attempts.load(Ordering::SeqCst) < 2 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(driver);
    tokio::time::sleep(Duration::from_millis(30)).await;
    let seen = attempts.load(Ordering::SeqCst);
    assert!(seen >= 2, "no retries happened: {seen}");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(attempts.load(Ordering::SeqCst), seen, "retries ran after the drop");
}

/// A published reference that is gone is lost evidence EVEN when the current version has the
/// same hash: every non-null reference is resolved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_published_version_is_found_even_when_it_equals_the_current_one() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10); // published == current
    fx.state
        .replica_coordinator
        .database()
        .write::<_, SyncSqliteError>(|conn| {
            conn.execute("DELETE FROM file_versions", [])?;
            Ok(())
        })
        .unwrap();
    assert!(
        fx.repo().publication(&fx.root, &id).is_err(),
        "an equal-to-current reference skipped resolution"
    );
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    let new_root = match fx.repo().declaration_for_group(GROUP).unwrap() {
        yadorilink_sync_sqlite::provider::ProviderDeclaration::Provider(root) => root.root_id,
        other => panic!("{other:?}"),
    };
    assert_ne!(new_root, fx.root, "lost evidence did not rebootstrap the root");
}

/// An item that is being attempted is never attempted again at the same time, even after an
/// earlier retry's backoff has long passed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_item_is_never_attempted_twice_at_once() {
    let fx = Fx::new();
    let id = fx.published_item("slow.txt", 10);
    fx.commit("slow.txt", 2, 11, 100);
    let host = FakeHost::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let (running, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let release = Arc::new(Notify::new());
    {
        let (calls, running, peak, release) =
            (calls.clone(), running.clone(), peak.clone(), release.clone());
        host.set_signal(Arc::new(move |_, _| {
            let (calls, running, peak, release) =
                (calls.clone(), running.clone(), peak.clone(), release.clone());
            Box::pin(async move {
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    return false; // arms a retry whose time will have passed
                }
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                release.notified().await;
                running.fetch_sub(1, Ordering::SeqCst);
                true
            })
        }));
    }
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    // Long enough for the retry to start and for several backoff periods to pass while it runs.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(peak.load(Ordering::SeqCst), 1, "the item was attempted twice at once");
    release.notify_one();
    settle(&driver).await;
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

// ---- announce ordering ----

impl Fx {
    fn shown_size(&self, id: &ItemId) -> u64 {
        self.repo().lookup_item(&self.root, id).unwrap().unwrap().0.size
    }

    fn event_seqs(&self) -> Vec<i64> {
        self.state
            .replica_coordinator
            .database()
            .read::<_, SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT seq FROM provider_change_events WHERE root_id = ?1 ORDER BY seq",
                )?;
                let rows = stmt.query_map([&self.root], |r| r.get(0))?.collect::<Result<_, _>>()?;
                Ok(rows)
            })
            .unwrap()
    }

    fn gate(&self, id: &ItemId) -> FetchGate {
        fetch_gate(&self.state.replica_coordinator, &self.root, id).unwrap()
    }
}

/// At the moment the signal goes out the change event is already durable and the shown view is
/// the new version, while a fetch is still refused: whenever the OS asks for changes after the
/// signal it finds the event, and it can never be handed V2 bytes under V1 metadata.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_event_and_the_new_view_are_durable_before_the_signal_and_the_fence_holds() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let (state, root, seen) = (fx.state.clone(), fx.root.clone(), seen.clone());
        host.set_signal(Arc::new(move |revision, items| {
            let (state, root, seen) = (state.clone(), root.clone(), seen.clone());
            Box::pin(async move {
                let repo = state.replica_coordinator.provider_repository();
                let shown = repo.lookup_item(&root, &items[0]).unwrap().unwrap().0.size;
                let gate = fetch_gate(&state.replica_coordinator, &root, &items[0]).unwrap();
                let events: Vec<i64> = state
                    .replica_coordinator
                    .database()
                    .read::<_, SyncSqliteError>(|conn| {
                        let mut stmt = conn
                            .prepare("SELECT seq FROM provider_change_events WHERE root_id = ?1")?;
                        let rows =
                            stmt.query_map([&root], |r| r.get(0))?.collect::<Result<_, _>>()?;
                        Ok(rows)
                    })
                    .unwrap();
                seen.lock().unwrap().push((revision, shown, gate, events));
                true
            })
        }));
    }
    fx.commit("a.txt", 2, 99, 777);
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;

    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    let (revision, shown, gate, events) = &seen[0];
    assert_eq!(*shown, 99, "the new version was not shown at the signal");
    assert_eq!(
        *gate,
        FetchGate::Allowed,
        "the announced version is fetchable from the announcement"
    );
    assert!(events.contains(&(*revision as i64)), "the signal's revision has no event: {events:?}");
    drop(seen);
    assert_eq!(fx.publication(&id), Some(Publication::Published));
    assert_eq!(fx.gate(&id), FetchGate::Allowed);
    let left: i64 = fx
        .state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM provider_items WHERE announce_version_hash IS NOT NULL",
                [],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert_eq!(left, 0, "an announcement outlived its publication");
}

/// The announced version stays resolvable through a retention sweep: the shown view of an item
/// whose announcement is in flight never goes missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_announced_version_survives_retention() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 99, 777);
    let v2 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    fx.repo().announce_version(&fx.root, &id, v2, 1_000).unwrap().unwrap();
    for seq in 3..40 {
        fx.commit("a.txt", seq, 100 + seq, 800);
    }
    // V2 is long superseded; expire everything past the bounds.
    yadorilink_sync_sqlite::file_index::FileIndexRepository::new(
        fx.state.replica_coordinator.database().clone(),
    )
    .expire_superseded_and_trashed_versions(GROUP, i64::MAX / 2, &Default::default())
    .unwrap();
    // The announced V2 is not current any more, so nothing is shown from it by the changes feed,
    // but its record is still in the version store (the published/announced pin).
    let announced_resolves = fx
        .state
        .replica_coordinator
        .database()
        .read::<_, SyncSqliteError>(|conn| {
            Ok(yadorilink_sync_sqlite::dag_store::get_file_version(conn, GROUP, &v2)?.is_some())
        })
        .unwrap();
    assert!(announced_resolves);
    assert_eq!(fx.shown_size(&id), 99);
}

/// The signal means: the host called `signalEnumerator` AND waited until the system finished the
/// changes below the parent directory. Anything weaker (no host, the wait unavailable, failed or
/// timed out, the host crashing between the signal and the wait) leaves the item pending and the
/// signal is repeated for the latest announcement; the OS asking for changes proves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_wait_keeps_the_item_pending_and_is_retried_until_it_succeeds() {
    use yadorilink_sync_sqlite::provider_enumerate::ChangeScope;
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    {
        let attempts = attempts.clone();
        // The first three waits fail (unavailable, timeout, host crash): never a success.
        host.set_signal(Arc::new(move |_, _| {
            let n = attempts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { n >= 3 })
        }));
    }
    fx.commit("a.txt", 2, 99, 777);
    let driver = fx.driver_with_release(&host, Duration::from_millis(400));
    driver.kick(&fx.root);
    // While the waits fail the OS keeps asking for changes: that releases nothing.
    for _ in 0..30 {
        if attempts.load(Ordering::SeqCst) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seq = fx.event_seqs()[0] as u64;
    fx.repo().enumerate_changes(&fx.root, &ChangeScope::WorkingSet, seq, 100, 1 << 20).unwrap();
    assert_eq!(
        fx.publication(&id),
        Some(Publication::ContentPending),
        "a changes request published the version"
    );
    assert_eq!(fx.event_seqs().len(), 1, "a repeated signal logged another event");

    settle(&driver).await;
    assert!(attempts.load(Ordering::SeqCst) >= 4);
    assert_eq!(fx.publication(&id), Some(Publication::Published));
    assert_eq!(fx.gate(&id), FetchGate::Allowed);
    // Every signal named the folder the host waits below (the root container here).
    assert!(host.signalled_parents.lock().unwrap().iter().all(|p| *p == vec![Vec::<u8>::new()]));
}

/// A newer version committed while the host waits: the wait that completes is for the OLD
/// announcement, so it publishes nothing; the next attempt announces the latest version (a new
/// sequence) and waits again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_committed_while_waiting_is_announced_afresh() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    let committed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (state, committed) = (fx.state.clone(), committed.clone());
        host.set_signal(Arc::new(move |_, _| {
            let (state, committed) = (state.clone(), committed.clone());
            Box::pin(async move {
                // Once, during the first wait, V3 is committed.
                if !committed.swap(true, Ordering::SeqCst) {
                    let repo = state.replica_coordinator.provider_repository();
                    let _ = repo;
                }
                true
            })
        }));
    }
    fx.commit("a.txt", 2, 99, 777);
    // V3 lands after the V2 announcement but before its acknowledgement is processed.
    let v2 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    let first = fx.repo().announce_version(&fx.root, &id, v2, 1_000).unwrap().unwrap();
    fx.commit("a.txt", 3, 150, 888);
    assert!(
        !fx.repo().publish_for_tests(&fx.root, &id, v2).unwrap(),
        "the wait for V2 published V3"
    );
    assert_eq!(fx.gate(&id), FetchGate::PublicationPending);
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    let seqs = fx.event_seqs();
    assert!(seqs.len() >= 2 && *seqs.last().unwrap() as u64 > first.seq, "{seqs:?}");
    assert_eq!(fx.shown_size(&id), 150);
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

// ---- release by our own policy, bounded and reported ----

/// A confirmed handoff of the announced version (the OS asked for its bytes and was given them)
/// is the one release our own state can see; before it, fetches of the announced version are
/// allowed and nothing newer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_confirmed_handoff_of_the_announced_version_releases_the_fence() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 99, 777);
    let v2 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    assert_eq!(fx.gate(&id), FetchGate::PublicationPending, "V2 fetchable before it is announced");
    fx.repo().announce_version(&fx.root, &id, v2, 1_000).unwrap().unwrap();
    assert_eq!(fx.gate(&id), FetchGate::Allowed, "the announced version is fetchable");
    // A newer version is not the announced one: refused again.
    fx.commit("a.txt", 3, 150, 888);
    assert_eq!(
        fx.gate(&id),
        FetchGate::PublicationPending,
        "a version newer than the announcement"
    );
    let v3 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    fx.repo().announce_version(&fx.root, &id, v3, 2_000).unwrap().unwrap();

    assert_eq!(fx.publication(&id), Some(Publication::ContentPending), "released with no handoff");
    assert!(fx.repo().record_may_serve(&fx.root, &id, v3).unwrap().is_some());
    assert_eq!(fx.publication(&id), Some(Publication::Published));
}

/// Successive announcements of one pending episode do not restart the timer: the latest announced
/// version is released `release_after` after the FIRST pending moment, whatever was committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn newer_commits_cannot_postpone_the_release_forever() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 20, 100);
    let v2 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    fx.repo().announce_version(&fx.root, &id, v2, 1_000).unwrap().unwrap();
    fx.commit("a.txt", 3, 30, 100);
    let v3 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    fx.repo().announce_version(&fx.root, &id, v3, 9_000).unwrap().unwrap();
    assert_eq!(fx.repo().release_due_in(&fx.root, &id, 9_000, 20_000).unwrap(), Some(12_000));

    assert!(!fx.repo().release_expired(&fx.root, &id, 20_999, 20_000).unwrap());
    assert!(fx.repo().release_expired(&fx.root, &id, 21_000, 20_000).unwrap());
    assert_eq!(fx.publication(&id), Some(Publication::Published));
    // The release is not delivery: it is reported until a handoff is confirmed.
    let unresolved = fx.repo().unresolved_publications(&fx.root, 25_000).unwrap();
    assert_eq!((unresolved.count, unresolved.oldest_age_ms), (1, 4_000));
    assert!(fx.repo().record_may_serve(&fx.root, &id, v3).unwrap().is_some());
    assert_eq!(fx.repo().unresolved_publications(&fx.root, 25_000).unwrap().count, 0);
}

/// The pending episode, the announcement and the timer are rows: a driver started after a restart
/// releases an item whose timer ran out while the daemon was down, without signalling again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_resumes_the_timer_from_the_stored_pending_since() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    fx.commit("a.txt", 2, 99, 777);
    let v2 = fx.repo().current_version_hash(&fx.root, &id).unwrap().unwrap();
    // Announced long ago (the first run), then the process died.
    fx.repo().announce_version(&fx.root, &id, v2, 1).unwrap().unwrap();
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    driver.kick(&fx.root);
    settle(&driver).await;
    assert_eq!(fx.publication(&id), Some(Publication::Published));
    assert!(host.raw_log().iter().all(|l| !l.starts_with("signal")), "{:?}", host.raw_log());
}

/// With NO host acknowledgement at all (every signal and wait fails), our own timer still advances
/// the publication: the item is fenced until the timer, published after it, and reported as
/// published but not confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_host_acknowledgement_our_own_timer_advances_the_publication() {
    let fx = Fx::new();
    let id = fx.published_item("a.txt", 10);
    let host = FakeHost::new();
    host.set_signal(Arc::new(|_, _| Box::pin(async { false })));
    fx.commit("a.txt", 2, 99, 777);
    let driver = fx.driver_with_release(&host, Duration::from_millis(300));
    driver.kick(&fx.root);
    for _ in 0..40 {
        if fx.publication(&id) == Some(Publication::Published) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(fx.publication(&id), Some(Publication::Published), "the timer did not release");
    assert_eq!(fx.gate(&id), FetchGate::Allowed);
    let unresolved = fx.repo().unresolved_publications(&fx.root, i64::MAX / 4).unwrap();
    assert_eq!(unresolved.count, 1, "a release by the timer was reported as delivered");
}

/// A root signal whose pending-change read fails is not "nothing to announce": it is not
/// acknowledged, so it is retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_change_read_does_not_acknowledge_the_root_signal() {
    let fx = Fx::new();
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    let fault = crate::provider_read_fault::Fault::inject(
        &fx.state.replica_coordinator,
        "provider_roots",
        "announced_change_seq",
    );
    assert!(!driver.shared.signal_root(&fx.root).await, "an unreadable read was acknowledged");
    fault.restore();
    assert!(driver.shared.signal_root(&fx.root).await, "nothing to announce is acknowledged");
}

/// A runner whose pending-change read fails does not conclude it has nothing to do and exit: it
/// keeps retrying, and leaves only once a read can say nothing is unannounced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_change_read_keeps_the_runner_alive() {
    let fx = Fx::new();
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    let fault = crate::provider_read_fault::Fault::inject(
        &fx.state.replica_coordinator,
        "provider_roots",
        "announced_change_seq",
    );
    driver.kick(&fx.root);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        driver.shared.runners.lock().unwrap().contains_key(&fx.root),
        "the runner left on an unreadable change count"
    );
    fault.restore();
    settle(&driver).await;
}

/// A read error that is not corruption never replaces the root: the runner retries, and the root
/// is still the declared one once the read works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_pending_read_does_not_rebootstrap_the_root() {
    let fx = Fx::new();
    let host = FakeHost::new();
    let driver = fx.driver(&host);
    let fault = crate::provider_read_fault::Fault::inject(
        &fx.state.replica_coordinator,
        "provider_items",
        "published_version_hash",
    );
    driver.kick(&fx.root);
    tokio::time::sleep(Duration::from_millis(300)).await;
    fault.restore();
    settle(&driver).await;
    let roots = fx.repo().list_declared_roots().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].root_id, fx.root, "a read error replaced the root");
}
