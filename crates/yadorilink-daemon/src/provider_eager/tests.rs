#![cfg(test)]

//! The Eager driver's query: candidates, exclusions and settling, backoff bound to a version,
//! pause states, the "done" query, restart, and the assembly limiter.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use yadorilink_ipc_proto::shellipc::ProviderMaterializedReport;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::session_state::ProviderKind;

use crate::daemon_state::DaemonState;

use super::*;

const GROUP: &str = "group-1";

struct FakeEnv {
    low_disk: AtomicBool,
    peers: AtomicBool,
    now: AtomicI64,
}

impl EagerEnvironment for FakeEnv {
    fn low_disk(&self, _dir: &Path, _bytes: u64) -> bool {
        self.low_disk.load(Ordering::SeqCst)
    }
    fn peers_available(&self, _group_id: &str) -> bool {
        self.peers.load(Ordering::SeqCst)
    }
    fn now_ms(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

struct Fx {
    state: Arc<DaemonState>,
    root: String,
    membership: ProviderMembership,
    env: Arc<FakeEnv>,
    driver: EagerDriver,
    staging: tempfile::TempDir,
    epoch: std::cell::Cell<u64>,
}

impl Fx {
    fn new() -> Self {
        Self::with_config(EagerConfig::default())
    }

    fn with_config(config: EagerConfig) -> Self {
        let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.replica_coordinator.link_repository().add_link("/provider/p", GROUP).unwrap();
        let repo = state.replica_coordinator.provider_repository();
        let root = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "P").unwrap();
        repo.set_domain_registered(&root, true).unwrap();
        repo.record_extension_handshake(&root, 1).unwrap();
        let env = Arc::new(FakeEnv {
            low_disk: AtomicBool::new(false),
            peers: AtomicBool::new(true),
            now: AtomicI64::new(1_000_000),
        });
        let driver = EagerDriver::new(env.clone(), config);
        let fx = Self {
            state,
            root,
            membership: ProviderMembership::default(),
            env,
            driver,
            staging: tempfile::tempdir().unwrap(),
            epoch: std::cell::Cell::new(0),
        };
        fx.snapshot(&[]);
        fx
    }

    fn repo(&self) -> &yadorilink_sync_sqlite::provider::ProviderRepository {
        self.state.replica_coordinator.provider_repository()
    }

    fn commit(&self, path: &str, seq: i64, size: i64) {
        let blocks = format!(r#"[{{"hash":{:?},"offset":0,"size":{size}}}]"#, vec![size as u8; 32]);
        self.state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
                     AND state = 'current'",
                    rusqlite::params![GROUP, path],
                )?;
                tx.execute(
                    "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                     deleted, version_seq, state) VALUES (?1, ?2, ?3, 1, ?5, 0, ?4, 'current')",
                    rusqlite::params![GROUP, path, size, seq, blocks],
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

    fn item(&self, path: &str, size: i64) -> ItemId {
        self.commit(path, 1, size);
        self.repo().mint_item(&self.root, path).unwrap()
    }

    /// A fresh, complete snapshot listing `items` (a new epoch each time).
    fn snapshot(&self, items: &[ItemId]) {
        self.epoch.set(self.epoch.get() + 1);
        let latest = self.repo().latest_evidence_seq(&self.root).unwrap().unwrap();
        let ack = self.membership.apply(
            &ProviderMaterializedReport {
                root_id: hex::decode(&self.root).unwrap(),
                reporter_epoch: self.epoch.get(),
                report_seq: 1,
                full: true,
                observed_after_seq: latest,
                upserts: items
                    .iter()
                    .map(|i| yadorilink_ipc_proto::shellipc::ProviderMaterializedItem {
                        item_id: i.to_vec(),
                    })
                    .collect(),
                removed: Vec::new(),
                more: false,
            },
            latest,
        );
        assert!(!ack.needs_full);
    }

    /// The item's content arrived and the host reported it: a handoff, then a newer snapshot.
    fn make_present(&self, items: &[ItemId]) {
        for item in items {
            let version = self.repo().current_version_hash(&self.root, item).unwrap().unwrap();
            self.repo().record_handoff(&self.root, item, version).unwrap().unwrap();
        }
        self.snapshot(items);
    }

    fn inputs(&self) -> EagerInputs<'_> {
        EagerInputs {
            coordinator: &self.state.replica_coordinator,
            membership: &self.membership,
            staging_dir: Some(self.staging.path()),
            host_attached: true,
        }
    }

    fn query(&self, exclude: &[ItemId], max: u32) -> NextProviderDownloadsResponse {
        self.driver.next_downloads(
            &self.inputs(),
            &NextProviderDownloadsRequest {
                root_id: hex::decode(&self.root).unwrap(),
                exclude_item_ids: exclude.iter().map(|i| i.to_vec()).collect(),
                max,
                request_id: Vec::new(),
            },
        )
    }

    fn offered(response: &NextProviderDownloadsResponse) -> Vec<Vec<u8>> {
        response.downloads.iter().map(|d| d.item_id.clone()).collect()
    }

    fn fail(&self, item: &ItemId) {
        let version = self.repo().current_version_hash(&self.root, item).unwrap().unwrap();
        self.driver.record_failure(&self.state.replica_coordinator, &self.root, item, version);
    }

    fn state_of(response: &NextProviderDownloadsResponse) -> DriverState {
        DriverState::try_from(response.state).unwrap()
    }
}

/// Smallest first, then path; at most `max`; items without an item yet get one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn candidates_come_smallest_first_and_unprojected_files_get_an_item() {
    let fx = Fx::new();
    let big = fx.item("a-big.bin", 5000);
    let small = fx.item("z-small.bin", 10);
    fx.commit("m-unprojected.bin", 1, 20);

    let response = fx.query(&[], 2);
    assert_eq!(Fx::state_of(&response), DriverState::Running);
    assert_eq!(Fx::offered(&response)[0], small.to_vec());
    // The second is the unprojected 20-byte file, now with an item of its own.
    let second = fx.repo().item_for_path(&fx.root, "m-unprojected.bin").unwrap().unwrap();
    assert_eq!(Fx::offered(&response)[1], second.to_vec());
    assert_eq!(response.downloads.len(), 2);
    assert!(!Fx::offered(&response).contains(&big.to_vec()));
    // The version offered is the current one.
    assert_eq!(
        response.downloads[0].version_hash,
        fx.repo().current_version_hash(&fx.root, &small).unwrap().unwrap().0.to_vec()
    );
    // `max` is honoured and never exceeds two.
    assert_eq!(fx.query(&[], 1).downloads.len(), 1);
    assert_eq!(fx.query(&[], 10).downloads.len(), 2);
    assert!(fx.query(&[], 0).downloads.is_empty());
}

/// Exclusions are never offered again, and settle when their content is current, the item is
/// gone, or it entered backoff; unsettled ones stay outstanding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exclusions_are_skipped_and_settle_when_nothing_more_is_needed() {
    let fx = Fx::new();
    let a = fx.item("a.bin", 10);
    let b = fx.item("b.bin", 20);
    let c = fx.item("c.bin", 30);

    let response = fx.query(&[a], 2);
    assert_eq!(Fx::offered(&response), [b.to_vec(), c.to_vec()], "an exclusion was offered");
    assert!(response.settled_item_ids.is_empty(), "a still-needed exclusion settled");

    // a's content arrives and is reported: it settles and drops out of the outstanding set.
    fx.make_present(&[a]);
    let response = fx.query(&[a, b], 1);
    assert_eq!(response.settled_item_ids, [a.to_vec()]);
    assert_eq!(Fx::offered(&response), [c.to_vec()]);

    // b is deleted: it settles too.
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE files SET deleted = 1 WHERE group_id = ?1 AND path = 'b.bin'",
                [GROUP],
            )?;
            Ok(())
        })
        .unwrap();
    let response = fx.query(&[b], 1);
    assert_eq!(response.settled_item_ids, [b.to_vec()]);

    // c fails and enters backoff: its exclusion settles instead of being retried at once.
    fx.fail(&c);
    let response = fx.query(&[c], 1);
    assert_eq!(response.settled_item_ids, [c.to_vec()]);
}

/// Unobtainable content backs off instead of looping, per version; the counters survive a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unobtainable_content_backs_off_per_version_and_survives_a_restart() {
    let fx = Fx::new();
    let item = fx.item("a.bin", 10);
    let other = fx.item("b.bin", 20);

    fx.fail(&item);
    let response = fx.query(&[], 2);
    assert_eq!(
        Fx::offered(&response),
        [other.to_vec()],
        "a failed item was offered inside its backoff"
    );

    // The backoff elapses: it is offered again; a second failure doubles the wait.
    fx.env.now.fetch_add(40_000, Ordering::SeqCst);
    assert!(Fx::offered(&fx.query(&[], 2)).contains(&item.to_vec()));
    fx.fail(&item);
    let failure = fx.repo().download_failure(&fx.root, &item).unwrap().unwrap();
    assert_eq!(failure.failures, 2);
    fx.env.now.fetch_add(40_000, Ordering::SeqCst);
    assert!(
        !Fx::offered(&fx.query(&[], 2)).contains(&item.to_vec()),
        "the second backoff is longer"
    );

    // A restart: a new driver over the same rows sees the same holds.
    let restarted = EagerDriver::new(fx.env.clone(), EagerConfig::default());
    let response = restarted.next_downloads(
        &fx.inputs(),
        &NextProviderDownloadsRequest {
            root_id: hex::decode(&fx.root).unwrap(),
            exclude_item_ids: Vec::new(),
            max: 2,
            request_id: Vec::new(),
        },
    );
    assert!(!Fx::offered(&response).contains(&item.to_vec()));

    // A newer version is a different fetch: the old version's failures do not hold it back.
    fx.commit("a.bin", 2, 11);
    assert!(
        Fx::offered(&fx.query(&[], 2)).contains(&item.to_vec()),
        "a superseded failure held the item"
    );

    // Success clears the record.
    fx.driver.record_success(&fx.state.replica_coordinator, &fx.root, &item);
    assert!(fx.repo().download_failure(&fx.root, &item).unwrap().is_none());
}

/// Past `stuck_after` failures the item is reported stuck and no longer blocks "done".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_item_is_listed_and_does_not_block_done() {
    let fx = Fx::new();
    let item = fx.item("a.bin", 10);
    for _ in 0..8 {
        fx.fail(&item);
    }
    let status = fx.driver.status(&fx.inputs(), &fx.root).unwrap();
    assert_eq!(status.stuck, [("a.bin".to_string(), 8)]);
    assert_eq!(status.remote, 1);
    assert_eq!(status.state, DriverState::Done, "a stuck item blocked done");
}

/// The answer names the query it answers (request id and root), on every path, so a host that
/// asked twice can drop the late answer to the first; a host that sends no id gets an empty one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_answer_echoes_the_request_id_and_root() {
    let fx = Fx::new();
    fx.item("a.bin", 10);
    let root_id = hex::decode(&fx.root).unwrap();
    let ask = |root: Vec<u8>, request_id: &[u8]| {
        fx.driver.next_downloads(
            &fx.inputs(),
            &NextProviderDownloadsRequest {
                root_id: root,
                exclude_item_ids: Vec::new(),
                max: 2,
                request_id: request_id.to_vec(),
            },
        )
    };
    // Two queries with different ids: each answer carries its own.
    let first = ask(root_id.clone(), b"one");
    let second = ask(root_id.clone(), b"two");
    assert_eq!(
        (first.request_id.as_slice(), first.root_id.as_slice()),
        (&b"one"[..], &root_id[..])
    );
    assert_eq!(second.request_id, b"two");
    assert!(!first.downloads.is_empty());

    // An unknown root is answered (empty) with the same echo.
    let unknown = ask(vec![9; 16], b"three");
    assert!(unknown.downloads.is_empty());
    assert_eq!(
        (unknown.request_id.as_slice(), unknown.root_id.as_slice()),
        (&b"three"[..], &[9u8; 16][..])
    );

    // A host that predates the id: answered with an empty id.
    let old_host = ask(root_id.clone(), b"");
    assert!(old_host.request_id.is_empty());
    assert_eq!(old_host.root_id, root_id);
    assert!(!old_host.downloads.is_empty());
}

/// No offers while the disk is low, while no peer is reachable, or while the provider side is
/// not ready.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_states_offer_nothing() {
    let fx = Fx::new();
    fx.item("a.bin", 10);

    fx.env.low_disk.store(true, Ordering::SeqCst);
    let response = fx.query(&[], 2);
    assert!(response.downloads.is_empty());
    assert_eq!(Fx::state_of(&response), DriverState::PausedLowDisk);
    fx.env.low_disk.store(false, Ordering::SeqCst);

    fx.env.peers.store(false, Ordering::SeqCst);
    let response = fx.query(&[], 2);
    assert!(response.downloads.is_empty());
    assert_eq!(Fx::state_of(&response), DriverState::WaitingPeers);
    fx.env.peers.store(true, Ordering::SeqCst);

    // No host attached, or no staging directory configured.
    let mut inputs = fx.inputs();
    inputs.host_attached = false;
    let request = NextProviderDownloadsRequest {
        root_id: hex::decode(&fx.root).unwrap(),
        exclude_item_ids: Vec::new(),
        max: 2,
        request_id: Vec::new(),
    };
    let response = fx.driver.next_downloads(&inputs, &request);
    assert_eq!(Fx::state_of(&response), DriverState::WaitingProvider);
    let mut inputs = fx.inputs();
    inputs.staging_dir = None;
    assert_eq!(
        Fx::state_of(&fx.driver.next_downloads(&inputs, &request)),
        DriverState::WaitingProvider
    );
    // And it runs again once everything is back.
    assert_eq!(Fx::state_of(&fx.query(&[], 2)), DriverState::Running);
}

/// "Done" is a continuously evaluated query against a snapshot that is fresh: a stale snapshot is
/// "waiting for the provider", an update makes the root not done again, held and paused files and
/// directories do not count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn done_is_a_query_over_a_fresh_snapshot() {
    let fx = Fx::with_config(EagerConfig {
        snapshot_max_age: Duration::from_secs(30),
        ..EagerConfig::default()
    });
    let a = fx.item("a.bin", 10);
    let b = fx.item("b.bin", 20);
    assert_eq!(fx.driver.status(&fx.inputs(), &fx.root).unwrap().state, DriverState::Running);

    fx.make_present(&[a, b]);
    let status = fx.driver.status(&fx.inputs(), &fx.root).unwrap();
    assert_eq!((status.state, status.current, status.remote), (DriverState::Done, 2, 0));
    assert_eq!(Fx::state_of(&fx.query(&[], 2)), DriverState::Done);

    // A remote update makes it not done again (the new version's content is not on the OS).
    fx.commit("a.bin", 2, 11);
    let status = fx.driver.status(&fx.inputs(), &fx.root).unwrap();
    assert_eq!((status.state, status.remote), (DriverState::Running, 1));
    assert_eq!(Fx::offered(&fx.query(&[], 2)), [a.to_vec()]);

    // A paused path is not wanted.
    fx.state.replica_coordinator.paused_item_repository().pause(GROUP, "a.bin").unwrap();
    let status = fx.driver.status(&fx.inputs(), &fx.root).unwrap();
    assert_eq!(status.state, DriverState::Done);
    // ... but Done does not say its content is on the OS: the replacement confirm must not accept it.
    assert_eq!(status.skipped, 1);
    assert!(crate::provider_status::eager_status_complete(&status).is_err());
    fx.state.replica_coordinator.paused_item_repository().resume(GROUP, "a.bin").unwrap();

    // A snapshot older than the limit proves nothing: the root is not done, nothing is offered.
    fx.membership.age_snapshot_for_tests(&fx.root, Duration::from_secs(31));
    assert_eq!(
        fx.driver.status(&fx.inputs(), &fx.root).unwrap().state,
        DriverState::WaitingProvider
    );
    assert_eq!(Fx::state_of(&fx.query(&[], 2)), DriverState::WaitingProvider);
}

/// After a restart nothing is stored but the rows: a new driver with an empty membership waits
/// for the host's full snapshot, then offers exactly what a driver that never stopped would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_rebuilds_the_queue_from_the_rows() {
    let fx = Fx::new();
    let a = fx.item("a.bin", 10);
    let b = fx.item("b.bin", 20);
    fx.make_present(&[a]);
    let before = Fx::offered(&fx.query(&[], 2));
    assert_eq!(before, [b.to_vec()]);

    // The daemon restarts: no snapshot, no handed-out set.
    fx.membership.clear();
    assert_eq!(Fx::state_of(&fx.query(&[], 2)), DriverState::WaitingProvider);
    // The host sends its FULL snapshot again; the same candidates come back.
    fx.snapshot(&[a]);
    assert_eq!(Fx::offered(&fx.query(&[], 2)), before);
}

/// A download the OS refused before any fetch is held back for a while, without counting as a
/// failed fetch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_download_is_held_back_but_not_counted() {
    let fx = Fx::new();
    let a = fx.item("a.bin", 10);
    fx.driver.record_rejection(&fx.state.replica_coordinator, &fx.root, &a);
    assert!(fx.query(&[], 2).downloads.is_empty());
    let failure = fx.repo().download_failure(&fx.root, &a).unwrap().unwrap();
    assert_eq!(failure.failures, 0);
    fx.env.now.fetch_add(60_000, Ordering::SeqCst);
    assert_eq!(fx.query(&[], 2).downloads.len(), 1);
}

/// A root that is not Eager answers nothing (the policy differs only in whether downloads are
/// requested), and the policy every convergence decision reads is OnDemand for any provider root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_on_demand_root_is_not_driven_and_a_provider_root_never_reads_as_eager() {
    let fx = Fx::new();
    fx.item("a.bin", 10);
    assert_eq!(
        fx.state.replica_coordinator.materialization_policy_for_group(GROUP).unwrap(),
        Some(MaterializationPolicy::OnDemand),
        "an Eager provider root read as Eager"
    );
    fx.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy("/provider/p", MaterializationPolicy::OnDemand)
        .unwrap();
    let response = fx.query(&[], 2);
    assert!(response.downloads.is_empty());
    assert_eq!(Fx::state_of(&response), DriverState::Unspecified);
}

/// An On-Demand root downloads exactly what the user keeps on this device (a pin, on a file or
/// on a folder above it) and nothing else; what the OS drops later (Finder's Remove Download) is
/// offered again while the pin stands; once the pin is gone the root is not driven.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_on_demand_root_downloads_only_what_is_kept_on_this_device() {
    let fx = Fx::new();
    fx.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy("/provider/p", MaterializationPolicy::OnDemand)
        .unwrap();
    let loose = fx.item("loose.bin", 5);
    let kept_file = fx.item("kept.bin", 30);
    let in_folder = fx.item("docs/a.bin", 20);
    let in_folder2 = fx.item("docs/sub/b.bin", 10);
    let sibling = fx.item("docs2/c.bin", 1);
    let pins = fx.state.replica_coordinator.pinned_item_repository();

    // Nothing kept: nothing is driven.
    let response = fx.query(&[], 2);
    assert!(response.downloads.is_empty());
    assert_eq!(Fx::state_of(&response), DriverState::Unspecified);

    pins.pin(GROUP, "docs").unwrap();
    pins.pin(GROUP, "kept.bin").unwrap();
    let response = fx.query(&[], 2);
    assert_eq!(Fx::state_of(&response), DriverState::Running);
    // Smallest first among the kept files only; a folder pin covers descendants by prefix, not
    // a sibling that merely shares the name's start.
    assert_eq!(Fx::offered(&response), vec![in_folder2.to_vec(), in_folder.to_vec()]);
    let rest = fx.query(&[in_folder2, in_folder], 2);
    assert_eq!(Fx::offered(&rest), vec![kept_file.to_vec()]);

    fx.make_present(&[in_folder2, in_folder, kept_file]);
    let done = fx.query(&[], 2);
    assert!(done.downloads.is_empty());
    assert_eq!(Fx::state_of(&done), DriverState::Done);

    // The OS drops a kept file (Remove Download): the next query offers it again.
    fx.make_present(&[in_folder2, kept_file]);
    let again = fx.query(&[], 2);
    assert_eq!(Fx::offered(&again), vec![in_folder.to_vec()]);

    // Not kept any more: an item the host still counts as outstanding settles (it frees its slot
    // for whatever is kept next), the root is not driven, and nothing is evicted by this.
    pins.unpin(GROUP, "docs").unwrap();
    let still_kept = fx.query(&[in_folder], 2);
    assert_eq!(still_kept.settled_item_ids, vec![in_folder.to_vec()]);
    assert!(still_kept.downloads.is_empty());
    pins.unpin(GROUP, "kept.bin").unwrap();
    let nothing_kept = fx.query(&[kept_file], 2);
    assert_eq!(nothing_kept.settled_item_ids, vec![kept_file.to_vec()]);
    assert!(nothing_kept.downloads.is_empty());
    assert!(!Fx::offered(&fx.query(&[], 2)).contains(&loose.to_vec()));
    assert!(!Fx::offered(&fx.query(&[], 2)).contains(&sibling.to_vec()));
}

/// A pin on a folder whose name is not ASCII still covers exactly its descendants.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_on_a_non_ascii_folder_covers_its_descendants_only() {
    let fx = Fx::new();
    fx.state
        .replica_coordinator
        .link_repository()
        .set_materialization_policy("/provider/p", MaterializationPolicy::OnDemand)
        .unwrap();
    let inside = fx.item("資料/日本.bin", 3);
    let _sibling = fx.item("資料集/日本.bin", 1);
    let _other = fx.item("資.bin", 2);
    fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, "資料").unwrap();
    assert_eq!(Fx::offered(&fx.query(&[], 2)), vec![inside.to_vec()]);
}

/// The limiter: at most `ASSEMBLIES` at once, at most `EAGER_ASSEMBLIES` of them Eager, and an
/// Open always finds a slot while Eager work saturates its class.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_limiter_caps_assemblies_and_never_starves_an_open() {
    let limiter = Arc::new(AssemblyLimiter::new(ASSEMBLIES, EAGER_ASSEMBLIES));
    let (running, peak_eager) =
        (Arc::new(Mutex::new((0usize, 0usize))), Arc::new(Mutex::new(0usize)));
    let release = Arc::new(tokio::sync::Notify::new());
    // A large queue of Eager assemblies: far more tasks than slots.
    let mut eager_tasks = Vec::new();
    for _ in 0..200 {
        let (limiter, running, peak_eager, release) =
            (limiter.clone(), running.clone(), peak_eager.clone(), release.clone());
        eager_tasks.push(tokio::spawn(async move {
            let _permits = limiter.acquire(true).await;
            {
                let mut running = running.lock().unwrap();
                running.0 += 1;
                let mut peak = peak_eager.lock().unwrap();
                *peak = (*peak).max(running.0);
            }
            release.notified().await;
            running.lock().unwrap().0 -= 1;
        }));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(*peak_eager.lock().unwrap(), 4, "the Eager class is not bounded");
    // The user's fetch gets a slot although the Eager class is saturated.
    let open = tokio::time::timeout(Duration::from_secs(5), limiter.acquire(false)).await;
    assert!(open.is_ok(), "an Open was starved by Eager work");
    drop(open);
    // Everything drains.
    for _ in 0..200 {
        release.notify_one();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    for task in eager_tasks {
        tokio::time::timeout(Duration::from_secs(10), task).await.unwrap().unwrap();
    }
}

/// An item whose newer version is still being published refuses every fetch (the fence), so the
/// driver does not offer it; once the publication completes it is offered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_item_behind_a_pending_publication_is_not_offered_until_it_is_published() {
    let fx = Fx::new();
    let pending = fx.item("a.bin", 10);
    let other = fx.item("b.bin", 20);
    let shown = fx.repo().current_version_hash(&fx.root, &pending).unwrap().unwrap();
    fx.repo().publish_first(&fx.root, &pending, shown).unwrap();
    fx.commit("a.bin", 2, 11); // a newer content version: the publication is pending
    assert_eq!(
        crate::provider_publication::fetch_gate(&fx.state.replica_coordinator, &fx.root, &pending)
            .unwrap(),
        crate::provider_publication::FetchGate::PublicationPending
    );

    assert_eq!(Fx::offered(&fx.query(&[], 2)), [other.to_vec()], "a fenced item was offered");

    let current = fx.repo().current_version_hash(&fx.root, &pending).unwrap().unwrap();
    assert!(fx.repo().publish_for_tests(&fx.root, &pending, current).unwrap());
    assert_eq!(Fx::offered(&fx.query(&[], 2)), [pending.to_vec(), other.to_vec()]);
}

/// The Eager class of an assembly does not expire while the app still lists the item as
/// outstanding, so six delayed Eager fetches fill the Eager class only and a user's Open still
/// finds a slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delayed_eager_fetches_stay_eager_and_cannot_block_an_open() {
    let fx = Fx::with_config(EagerConfig {
        request_ttl: Duration::from_millis(40),
        ..Default::default()
    });
    let items: Vec<ItemId> = (0..6).map(|n| fx.item(&format!("f{n}.bin"), 10 + n)).collect();
    let mut outstanding: Vec<ItemId> = Vec::new();
    while outstanding.len() < 6 {
        let response = fx.query(&outstanding, 2);
        outstanding.extend(
            response.downloads.iter().map(|d| ItemId::try_from(d.item_id.as_slice()).unwrap()),
        );
    }
    assert_eq!(outstanding.len(), 6);

    // The OS delays them far beyond the old expiry; the app still lists them as outstanding.
    tokio::time::sleep(Duration::from_millis(120)).await;
    fx.query(&outstanding, 2);
    assert!(
        items.iter().all(|item| fx.driver.was_requested(&fx.root, item)),
        "a delayed item became an Open"
    );

    let mut held = Vec::new();
    for item in &outstanding[..4] {
        assert!(fx.driver.was_requested(&fx.root, item));
        held.push(fx.driver.limiter.acquire(true).await);
    }
    // The fifth and sixth Eager fetches wait for their class; a user's Open does not.
    let fifth =
        tokio::time::timeout(Duration::from_millis(100), fx.driver.limiter.acquire(true)).await;
    assert!(fifth.is_err(), "the Eager class was not bounded");
    let open = tokio::time::timeout(Duration::from_secs(2), fx.driver.limiter.acquire(false)).await;
    assert!(open.is_ok(), "an Open was blocked by delayed Eager fetches");

    // What the app no longer lists is forgotten once its classification is old.
    tokio::time::sleep(Duration::from_millis(120)).await;
    fx.query(&[], 0);
    assert!(!fx.driver.was_requested(&fx.root, &items[0]));
}

/// A query with no room (the host is at capacity) still settles finished exclusions and offers
/// nothing, and never answers "done" while it has not looked for work: it is how slots free up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settlement_only_query_frees_slots_and_never_reads_as_done() {
    let fx = Fx::new();
    let a = fx.item("a.bin", 10);
    let b = fx.item("b.bin", 20);
    fx.make_present(&[a, b]);
    // Everything is present, so a real scan would answer "done"; a settlement-only query must not.
    let response = fx.query(&[a, b], 0);
    assert_eq!(response.settled_item_ids, [a.to_vec(), b.to_vec()]);
    assert!(response.downloads.is_empty());
    assert_eq!(Fx::state_of(&response), DriverState::Running);
}

/// The prefetch scheduler offers folders breadth first, one hint at a time, only when the root is
/// idle: activity pauses it, the idle period resumes it and offers the next folder, and a finished
/// session offers nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prefetch_offers_one_folder_at_a_time_and_only_when_idle() {
    use crate::provider_prefetch::{Action, PrefetchConfig, PrefetchScheduler};
    use std::time::{Duration, Instant};
    use yadorilink_ipc_proto::shellipc::{ActivityKind, PrefetchResult};
    let fx = Fx::new();
    fx.item("a/f.bin", 1);
    fx.item("b/f.bin", 1);
    let scheduler = PrefetchScheduler::new(PrefetchConfig::default());
    let repo = fx.repo();
    let t0 = Instant::now();

    let first = scheduler.tick(&fx.root, repo, true, t0);
    let Some(Action::Hint { hint_id, .. }) = first.first() else { panic!("no hint: {first:?}") };
    assert_eq!(first.len(), 1);
    assert!(scheduler.tick(&fx.root, repo, true, t0).is_empty(), "two hints were outstanding");
    assert!(
        scheduler.tick(&fx.root, repo, false, t0).is_empty(),
        "a root that is not ready was warmed"
    );

    scheduler.on_done(&fx.root, *hint_id, PrefetchResult::Done, t0);
    assert!(scheduler.on_activity(&fx.root, b"user", ActivityKind::Fetch, t0));
    assert!(
        scheduler.tick(&fx.root, repo, true, t0 + Duration::from_secs(1)).is_empty(),
        "offered while the user is active"
    );
    let resumed = scheduler.tick(&fx.root, repo, true, t0 + Duration::from_secs(6));
    assert!(matches!(resumed.first(), Some(Action::Resume(_))), "{resumed:?}");
    assert!(matches!(resumed.get(1), Some(Action::Hint { .. })), "{resumed:?}");
}

/// A SKIPPED answer is transient: the same folder is offered again after the back-off, not
/// skipped for the session; only DONE moves the queue on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_skipped_prefetch_is_retried_and_only_done_moves_on() {
    use crate::provider_prefetch::{Action, PrefetchConfig, PrefetchScheduler};
    use std::time::{Duration, Instant};
    use yadorilink_ipc_proto::shellipc::PrefetchResult;
    let fx = Fx::new();
    fx.item("a/f.bin", 1);
    fx.item("b/f.bin", 1);
    let scheduler = PrefetchScheduler::new(PrefetchConfig::default());
    let repo = fx.repo();
    let t0 = Instant::now();
    let folder_of = |actions: &[Action]| match actions.first() {
        Some(Action::Hint { folder, hint_id, .. }) => (folder.clone(), *hint_id),
        other => panic!("no hint: {other:?}"),
    };

    let (first, id) = folder_of(&scheduler.tick(&fx.root, repo, true, t0));
    scheduler.on_done(&fx.root, id, PrefetchResult::Skipped, t0);
    assert!(
        scheduler.tick(&fx.root, repo, true, t0 + Duration::from_secs(10)).is_empty(),
        "no back-off"
    );
    let later = t0 + Duration::from_secs(120);
    let (again, id) = folder_of(&scheduler.tick(&fx.root, repo, true, later));
    assert_eq!(again, first, "a skipped folder was dropped from the session");
    scheduler.on_done(&fx.root, id, PrefetchResult::Done, later);
    let (next, id) = folder_of(&scheduler.tick(&fx.root, repo, true, later));
    assert_ne!(next, first, "a finished folder was offered again");
    // A FAILED answer is retried after the back-off just like a skip, never skipped for the session.
    scheduler.on_done(&fx.root, id, PrefetchResult::Failed, later);
    let much_later = later + Duration::from_secs(120);
    let (retried, _) = folder_of(&scheduler.tick(&fx.root, repo, true, much_later));
    assert_eq!(retried, next, "a failed folder was dropped from the session");
}

/// (review) The item budget is spent by a folder's REAL child count and only when the host says DONE: a
/// folder re-offered after a skip costs nothing, and one that is never done is given up after a bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_prefetch_budget_is_spent_by_real_children_and_only_on_done() {
    use crate::provider_prefetch::{Action, PrefetchConfig, PrefetchScheduler};
    use std::time::{Duration, Instant};
    use yadorilink_ipc_proto::shellipc::PrefetchResult;
    let fx = Fx::new();
    fx.item("a/f1.bin", 1);
    fx.item("a/f2.bin", 1);
    fx.item("a/f3.bin", 1);
    fx.item("b/g.bin", 1);
    fx.item("c/h.bin", 1);
    // Room for the three-file folder and the one-file folder (4), and nothing after them.
    let scheduler =
        PrefetchScheduler::new(PrefetchConfig { items: 4, ..PrefetchConfig::default() });
    let repo = fx.repo();
    let mut now = Instant::now();
    let hint =
        |actions: Vec<Action>| match actions.into_iter().find(|a| matches!(a, Action::Hint { .. }))
        {
            Some(Action::Hint { hint_id, .. }) => hint_id,
            _ => panic!("no hint"),
        };

    // Skipped four times: no budget burned, still on the same folder, still offered.
    let first = hint(scheduler.tick(&fx.root, repo, true, now));
    scheduler.on_done(&fx.root, first, PrefetchResult::Skipped, now);
    for _ in 0..3 {
        now += Duration::from_secs(120);
        let id = hint(scheduler.tick(&fx.root, repo, true, now));
        scheduler.on_done(&fx.root, id, PrefetchResult::Skipped, now);
    }
    now += Duration::from_secs(120);
    let id = hint(scheduler.tick(&fx.root, repo, true, now));
    scheduler.on_done(&fx.root, id, PrefetchResult::Done, now); // a: 3 children spent
    let b = hint(scheduler.tick(&fx.root, repo, true, now));
    scheduler.on_done(&fx.root, b, PrefetchResult::Done, now); // b: 1 more, 4 of 4
    assert!(
        !scheduler.tick(&fx.root, repo, true, now).iter().any(|a| matches!(a, Action::Hint { .. })),
        "the budget was not spent by real child counts"
    );
}

/// (review) A folder that never answers DONE is offered a bounded number of times, then the queue moves on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_folder_that_never_finishes_is_given_up_after_a_bound() {
    use crate::provider_prefetch::{Action, PrefetchConfig, PrefetchScheduler};
    use std::time::{Duration, Instant};
    use yadorilink_ipc_proto::shellipc::PrefetchResult;
    let fx = Fx::new();
    fx.item("a/f.bin", 1);
    fx.item("b/g.bin", 1);
    let scheduler = PrefetchScheduler::new(PrefetchConfig::default());
    let repo = fx.repo();
    let mut now = Instant::now();
    let mut offered = Vec::new();
    for _ in 0..8 {
        if let Some(Action::Hint { hint_id, folder, .. }) = scheduler
            .tick(&fx.root, repo, true, now)
            .into_iter()
            .find(|a| matches!(a, Action::Hint { .. }))
        {
            offered.push(folder);
            scheduler.on_done(&fx.root, hint_id, PrefetchResult::Failed, now);
        }
        now += Duration::from_secs(120);
    }
    let first_run = offered.iter().take_while(|f| **f == offered[0]).count();
    assert_eq!(first_run, 5, "the first folder was offered {first_run} times: {}", offered.len());
    assert!(
        offered.iter().any(|f| *f != offered[0]),
        "the queue never moved past the failing folder"
    );
}

/// A read that fails is never "nothing left to download": the status is not Done, the query does
/// not conclude Done, and an exclusion is not settled because its lookup could not be answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_candidate_list_is_not_done() {
    let fx = Fx::new();
    let a = fx.item("a.bin", 10);
    let b = fx.item("b.bin", 20);
    fx.make_present(&[a, b]);
    assert_eq!(fx.driver.status(&fx.inputs(), &fx.root).unwrap().state, DriverState::Done);

    let fault = crate::provider_read_fault::Fault::inject(
        &fx.state.replica_coordinator,
        "provider_items",
        "live",
    );
    let status = fx.driver.status(&fx.inputs(), &fx.root).unwrap();
    assert_eq!(status.state, DriverState::Running);
    assert!(status.unreadable);
    let response = fx.query(&[a], 2);
    assert_eq!(Fx::state_of(&response), DriverState::Running);
    assert!(response.settled_item_ids.is_empty(), "an unanswerable exclusion settled");
    fault.restore();

    assert_eq!(fx.driver.status(&fx.inputs(), &fx.root).unwrap().state, DriverState::Done);
    let response = fx.query(&[a], 2);
    assert_eq!(response.settled_item_ids, [a.to_vec()]);
    assert_eq!(Fx::state_of(&response), DriverState::Done);
}

/// A hold, pause or policy that cannot be read is not "nothing wanted": never Done, and the
/// status says the progress is unreadable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_holds_and_policy_are_not_done() {
    let fx = Fx::new();
    let a = fx.item("a.bin", 10);
    fx.make_present(&[a]);
    assert_eq!(fx.driver.status(&fx.inputs(), &fx.root).unwrap().state, DriverState::Done);

    for (table, column) in [("held_paths", "path"), ("links", "materialization_policy")] {
        let fault =
            crate::provider_read_fault::Fault::inject(&fx.state.replica_coordinator, table, column);
        let status = fx.driver.status(&fx.inputs(), &fx.root).unwrap();
        assert!(status.unreadable, "{table}.{column}");
        assert_ne!(status.state, DriverState::Done, "{table}.{column}");
        assert_ne!(Fx::state_of(&fx.query(&[], 2)), DriverState::Done, "{table}.{column}");
        fault.restore();
        assert_eq!(fx.driver.status(&fx.inputs(), &fx.root).unwrap().state, DriverState::Done);
    }
}
