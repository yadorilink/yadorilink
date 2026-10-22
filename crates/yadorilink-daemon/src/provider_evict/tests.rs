#![cfg(test)]

//! A provider eviction frees the OS copy and, only with a durable custody lease taken first, the
//! daemon's cached blocks.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use yadorilink_replica_domain::session_state::MaterializationPolicy;

use super::*;
use crate::provider_reclaim::tests::{data_of, Fx, GROUP};

fn evictor(fx: &Fx, reclaim: Arc<ProviderReclaim>) -> ProviderEvictor {
    ProviderEvictor::new(fx.state.clone(), fx.host.clone(), reclaim, fx.membership.clone())
}

fn log(fx: &Fx) -> Vec<String> {
    fx.log.lock().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lease_is_taken_under_the_item_lock_before_the_os_drops_its_copy() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096), &data_of(2, 4096)]);
    fx.held_item("a.bin");

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert_eq!(log(&fx), ["acquire", "host_evict"], "the OS copy was dropped before the lease");
    assert!(fx.custody.lock_held_during_acquire.load(Ordering::SeqCst));
    assert!(outcome.dehydrated);
    assert_eq!(outcome.reclaimed.blocks, 2);
    assert_eq!(outcome.retained, None);
    assert!(blocks.iter().all(|hash| !fx.cached(hash)), "a block of the evicted version stayed");
    assert_eq!(fx.host.targets.lock().unwrap()[0], fx.current_version("a.bin").0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_lease_the_os_copy_goes_and_every_block_stays() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.custody.grant.store(false, Ordering::SeqCst);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(outcome.dehydrated);
    assert_eq!(outcome.reclaimed.blocks, 0);
    assert_eq!(outcome.retained, Some(Retained::CustodyNotAcquired));
    assert!(fx.cached(&blocks[0]), "a block was freed without a lease");
}

/// The shipped flag is on: reclaim as production builds it asks for a lease and frees the blocks,
/// except where the platform does not offer durable namespace changes (Windows until its gate is
/// validated), where it asks for nothing and keeps every block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_shipped_reclaim_takes_a_lease_only_where_the_platform_is_durable() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");

    let outcome = evictor(&fx, fx.shipped_reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(outcome.dehydrated);
    if yadorilink_fs_platform::durable_dir::platform_offers_durable_namespace() {
        assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 1);
        assert_eq!(outcome.retained, None);
        assert!(!fx.cached(&blocks[0]));
    } else {
        assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
        assert_eq!(outcome.retained, Some(Retained::CustodyUnsupported));
        assert!(fx.cached(&blocks[0]));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_full_replica_keeps_its_blocks() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.set_policy(MaterializationPolicy::Eager);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
    assert!(outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::FullReplica));
    assert!(fx.cached(&blocks[0]));
}

/// The lease is for one exact version: content that arrived while it was awaited is not dropped
/// on its strength, and the OS is not asked to drop anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_version_that_moves_during_the_lease_is_left_alone() {
    let fx = Fx::new();
    let old = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    // The newer version lands while the acquire is in flight.
    let fx = Arc::new(fx);
    let inner = fx.clone();
    *fx.custody.during_acquire.lock().unwrap() = Some(Box::new(move || {
        inner.commit("a.bin", 2, &[&data_of(2, 4096)]);
    }));

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::VersionMoved));
    assert_eq!(log(&fx), ["acquire"], "the OS was asked to drop a copy after the item moved");
    assert!(fx.cached(&old[0]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_the_os_has_open_keeps_its_blocks() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.host.answers.lock().unwrap().push_back(HostAnswer::Busy);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::HostBusy));
    assert!(fx.cached(&blocks[0]));
}

/// An item the OS already holds nothing of still has its blocks freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_item_already_without_its_os_copy_still_frees_the_blocks() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.host.answers.lock().unwrap().push_back(HostAnswer::NotMaterialized);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.reclaimed.blocks, 1);
    assert!(!fx.cached(&blocks[0]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_host_means_no_lease_and_an_error() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.host.connected.store(false, Ordering::SeqCst);

    let error = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap_err();

    assert!(matches!(error, SyncError::EvictionRejected(_)), "{error:?}");
    assert_eq!(fx.custody.acquires.load(Ordering::SeqCst), 0);
}

/// A block another path's current version also needs is never freed, unless that other path's own
/// custody is leased too (see the `provider_reclaim` tests): here its lease is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_shared_with_another_file_stays() {
    let fx = Fx::new();
    fx.custody.grant_only_first.store(true, Ordering::SeqCst);
    let shared = data_of(7, 4096);
    let own = data_of(8, 4096);
    let a = fx.commit("a.bin", 1, &[&shared, &own]);
    let b = fx.commit("b.bin", 1, &[&shared]);
    fx.held_item("a.bin");

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert_eq!(outcome.reclaimed.blocks, 1);
    assert!(fx.cached(&b[0]) && fx.cached(&a[0]), "the shared block was freed");
    assert!(!fx.cached(&a[1]), "the file's own block stayed");
}

/// The coordinator re-checks the lease under the deletion guard: a stamp that stopped being valid
/// frees nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_that_stops_backing_the_version_frees_nothing() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.custody.valid.store(false, Ordering::SeqCst);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(outcome.dehydrated);
    assert_eq!(outcome.reclaimed.blocks, 0);
    assert_eq!(outcome.retained, Some(Retained::NothingFreed));
    assert!(fx.cached(&blocks[0]));
}

/// An item another operation holds is neither leased nor dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_item_is_left_alone() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    let lock = fx.state.replica_coordinator.path_lock(GROUP, "a.bin");
    let _held = lock.lock().await;

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::Busy));
    assert!(log(&fx).is_empty());
    assert!(fx.cached(&blocks[0]));
}

/// The host cannot tell which version it holds, so the daemon asks it to drop a copy only for an
/// item its own evidence shows at the current version. Without that evidence nothing is asked of
/// the host; the blocks are still freed under the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_is_asked_only_for_an_item_the_evidence_shows() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.item("a.bin");

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert_eq!(log(&fx), ["acquire"], "the host was asked about an item nothing shows it holds");
    assert!(!outcome.dehydrated);
    assert_eq!(outcome.reclaimed.blocks, 1);
    assert!(!fx.cached(&blocks[0]));
}

/// The item's lock stays held from the lease until the blocks are settled, so neither the hold
/// reconciler nor a hydration of the same item can interleave.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_item_lock_is_held_while_the_host_drops_its_copy() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");

    evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(fx.host.lock_held_during_evict.load(Ordering::SeqCst));
    // And it is free again afterwards.
    let lock = fx.state.replica_coordinator.path_lock(GROUP, "a.bin");
    assert!(lock.try_lock().is_ok());
}

/// With no lease the OS copy is the only complete local copy unless every block is cached here:
/// dropping it would leave nothing to open from.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_lease_the_os_copy_stays_unless_every_block_is_local() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096), &data_of(2, 4096)]);
    fx.held_item("a.bin");
    fx.custody.grant.store(false, Ordering::SeqCst);
    fx.state.block_store.delete(&blocks[1]).unwrap();

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::CustodyRequired));
    assert!(log(&fx).iter().all(|entry| entry != "host_evict"), "the OS copy was dropped");
}

/// A lease taken for an eviction the host then refused is not kept: the reconciler sees every
/// block still local and releases it. Once the blocks are gone, it keeps the lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hold_is_kept_only_while_a_block_of_the_version_is_missing_locally() {
    use yadorilink_sync_sqlite::remote_custody_hold::HoldKey;

    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.item("a.bin");
    let hold = HoldKey {
        group_id: GROUP.into(),
        path: "a.bin".into(),
        version_hash: fx.current_version("a.bin").0,
        peer_id: "full-peer".into(),
    };
    let holds = fx.state.replica_coordinator.remote_custody_hold_repository();
    holds.record_requested(&hold, 1, rand::random()).unwrap();
    holds.mark_granted(&hold).unwrap();

    // The block is still here: nothing depends on the lease, so it is released.
    let unfinished = fx.state.reconcile_custody_holds(|_hold| async { true }).await;
    assert!(!unfinished);
    assert!(holds.get(&hold).unwrap().is_none(), "a lease nothing depends on was kept");

    // Granted again, and now the block is gone (a reclaim happened): the lease is kept.
    holds.record_requested(&hold, 1, rand::random()).unwrap();
    holds.mark_granted(&hold).unwrap();
    fx.state.block_store.delete(&blocks[0]).unwrap();
    let unfinished = fx.state.reconcile_custody_holds(|_hold| async { true }).await;
    assert!(!unfinished);
    assert!(holds.get(&hold).unwrap().is_some(), "a lease a reclaim relies on was released");
}

/// A change of metadata alone leaves the OS holding the current content: the item can still be
/// evicted, although the handoff ledger names the older (metadata) version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_metadata_only_change_does_not_hide_the_os_copy() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.touch("a.bin", 2, 99);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert_eq!(log(&fx), ["acquire", "host_evict"]);
    assert!(outcome.dehydrated);
    // The superseded version still references the same blocks, so they stay (as for any
    // retained version).
    assert_eq!(outcome.retained, Some(Retained::NothingFreed));
    assert!(fx.cached(&blocks[0]));
}

/// The item lock is held while the lease is checked and the blocks are deleted, so the hold
/// reconciler cannot release the lease between the two.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_item_lock_is_held_when_the_lease_is_checked_for_the_deletion() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");

    evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(fx.custody.lock_held_during_validation.load(Ordering::SeqCst));
}

/// A hydration holds a block-reference write while it waits for the item lock, and the deletion
/// waits for those writes: the reclaim must give the lock up so the hydration can finish, then
/// complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn a_hydration_waiting_for_the_item_lock_does_not_stall_the_reclaim() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    let writer = fx.state.begin_write_activity();
    let evictor = evictor(&fx, fx.reclaim());
    let lock = fx.state.replica_coordinator.path_lock(GROUP, "a.bin");

    let evict = async { evictor.evict(GROUP, "a.bin").await.unwrap() };
    // The hydration: a write is open, and once the reclaim holds the item lock it waits for it.
    let hydration = async {
        crate::provider_reclaim::tests::eventually("the host was asked", || log(&fx).len() == 2)
            .await;
        let _item = lock.lock().await;
        drop(writer);
        // The item stays busy a while longer: the reclaim keeps trying, it does not give up.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    };
    let (outcome, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(evict, hydration)
    })
    .await
    .expect("the reclaim waited on a hydration that waited on its lock");

    assert_eq!(outcome.reclaimed.blocks, 1);
    assert!(!fx.cached(&blocks[0]));
}

/// The host is not asked about an item nothing shows it holds with current content: listed by
/// the host, published, but never handed over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_item_without_a_handoff_is_not_dropped_on_the_hosts_word() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let item = fx.item("a.bin");
    fx.listed_without_handoff(item);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert!(log(&fx).iter().all(|entry| entry != "host_evict"));
}

/// The host is asked only when the item's CONTENT is what was handed over: a content update since
/// the handoff (even one that is already published and still listed) is not dropped on the host's
/// word, whatever later metadata-only change follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_content_update_since_the_handoff_is_not_dropped_on_the_hosts_word() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.commit("a.bin", 2, &[&data_of(2, 4096)]);
    fx.touch("a.bin", 3, 99);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert!(log(&fx).iter().all(|entry| entry != "host_evict"));
}

/// The premise of the tests below: the block is indexed, so a bare existence check passes. (A
/// verified read of the damaged bytes would fail, and also drops the store's mapping for the
/// block, so the test does not read it before the eviction does.)
fn assert_indexed(fx: &Fx, hash: &str) {
    assert!(fx.cached(hash), "premise: the block is indexed");
}

/// Without a lease the OS copy may go only if the next open can be served from verified local
/// bytes; an indexed block whose payload is torn is not that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_indexed_but_corrupt_block_without_a_lease_keeps_the_os_copy() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096), &data_of(2, 4096), &data_of(3, 4096)]);
    fx.held_item("a.bin");
    fx.custody.grant.store(false, Ordering::SeqCst);
    yadorilink_local_storage::segment_store::testing::flip_one_payload_bit(
        &fx.store_root,
        &blocks[1],
    )
    .unwrap();
    assert_indexed(&fx, &blocks[1]);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::CustodyRequired));
    assert_eq!(log(&fx), ["acquire"], "the OS was asked to drop its only good copy");
    assert!(fx.host.targets.lock().unwrap().is_empty());
    assert!(fx.cached(&blocks[0]) && fx.cached(&blocks[2]), "a verified block was freed");
}

/// A payload that cannot be read at all (its segment is truncated) refuses like a corrupt one: a
/// storage error is never read as "fine".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_block_without_a_lease_keeps_the_os_copy() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.custody.grant.store(false, Ordering::SeqCst);
    for entry in std::fs::read_dir(fx.store_root.join("segments")).unwrap() {
        let file = std::fs::OpenOptions::new().write(true).open(entry.unwrap().path()).unwrap();
        file.set_len(0).unwrap();
    }
    assert_indexed(&fx, &blocks[0]);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::CustodyRequired));
    assert!(fx.host.targets.lock().unwrap().is_empty());
}

/// The fallback holds the item's lock from the verification to the host's answer, so the
/// verified state cannot be overtaken by another operation on the item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_verified_fallback_holds_the_item_lock_until_the_host_answers() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.custody.grant.store(false, Ordering::SeqCst);

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(outcome.dehydrated);
    assert!(fx.host.lock_held_during_evict.load(Ordering::SeqCst));
}

/// A pinned item is kept: neither the lease nor the OS copy is touched, and a folder's pin covers
/// the items beneath it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pinned_item_is_not_evicted_and_nothing_is_asked_of_the_host() {
    for pin in ["dir/a.bin", "dir", ""] {
        let fx = Fx::new();
        let blocks = fx.commit("dir/a.bin", 1, &[&data_of(1, 4096)]);
        fx.held_item("dir/a.bin");
        fx.state.replica_coordinator.pinned_item_repository().pin(GROUP, pin).unwrap();

        let result = evictor(&fx, fx.reclaim()).evict(GROUP, "dir/a.bin").await;

        assert!(
            matches!(&result, Err(SyncError::EvictionRejected(m)) if m.contains("kept on this device")),
            "pin at {pin:?}: {:?}",
            result.map(|o| o.dehydrated)
        );
        assert!(
            log(&fx).is_empty(),
            "pin at {pin:?}: the host or custody was asked: {:?}",
            log(&fx)
        );
        assert!(fx.cached(&blocks[0]), "pin at {pin:?}: a pinned item's block was freed");
    }
}

/// Unpinning makes the item evictable again; the policy was the only thing in the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unpinned_item_is_evicted_as_before() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    let pins = fx.state.replica_coordinator.pinned_item_repository();
    pins.pin(GROUP, "a.bin").unwrap();
    pins.unpin(GROUP, "a.bin").unwrap();

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(outcome.dehydrated);
}

/// The user opens a file and asks to free it before the host has reported the download: the
/// answer says the download is not confirmed yet (retry shortly), and nothing is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_newer_than_the_hosts_report_is_not_confirmed_yet() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let item = fx.item("a.bin");
    let repo = fx.state.replica_coordinator.provider_repository();
    let latest = repo.latest_evidence_seq(&fx.root).unwrap().unwrap();
    let empty = yadorilink_ipc_proto::shellipc::ProviderMaterializedReport {
        root_id: hex::decode(&fx.root).unwrap(),
        reporter_epoch: 50,
        report_seq: 1,
        full: true,
        observed_after_seq: latest,
        upserts: Vec::new(),
        removed: Vec::new(),
        more: false,
    };
    assert!(!fx.membership.apply(&empty, latest).needs_full);
    let version = repo.current_version_hash(&fx.root, &item).unwrap().unwrap();
    repo.record_handoff(&fx.root, &item, version).unwrap().unwrap();

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::NotConfirmed));
    assert!(Retained::NotConfirmed.retryable());
    assert!(!log(&fx).iter().any(|entry| entry == "host_evict"));
    assert!(fx.cached(&blocks[0]), "blocks were freed for a download nothing confirmed");
}

/// The host declining (a file with changes not shared yet) is a refusal with a code, not a raw
/// system error text, and nothing is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_declining_is_a_retryable_refusal_with_a_code() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    fx.host
        .answers
        .lock()
        .unwrap()
        .push_back(HostAnswer::Error("NSFileProviderErrorDomain -2008".into()));

    let outcome = evictor(&fx, fx.reclaim()).evict(GROUP, "a.bin").await.unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::HostRefused));
    assert!(Retained::HostRefused.retryable());
    assert!(fx.cached(&blocks[0]));
}

/// A caller that decided about one version cannot evict another: the host is not asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_eviction_for_an_older_version_leaves_the_newer_one_alone() {
    let fx = Fx::new();
    fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    let item = fx.held_item("a.bin");
    let decided_on = fx.current_version("a.bin");
    let newer = fx.commit("a.bin", 2, &[&data_of(2, 4096)]);

    let outcome = evictor(&fx, fx.reclaim())
        .evict_expecting(GROUP, "a.bin", Some((item, decided_on)))
        .await
        .unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::VersionMoved));
    assert!(log(&fx).is_empty());
    assert!(fx.cached(&newer[0]));
}

/// The request is about one item: another item that now holds the path is left alone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_eviction_for_another_item_at_the_path_leaves_it_alone() {
    let fx = Fx::new();
    let blocks = fx.commit("a.bin", 1, &[&data_of(1, 4096)]);
    fx.held_item("a.bin");
    let version = fx.current_version("a.bin");
    let other_item: ItemId = [7u8; 16];

    let outcome = evictor(&fx, fx.reclaim())
        .evict_expecting(GROUP, "a.bin", Some((other_item, version)))
        .await
        .unwrap();

    assert!(!outcome.dehydrated);
    assert_eq!(outcome.retained, Some(Retained::VersionMoved));
    assert!(log(&fx).is_empty());
    assert!(fx.cached(&blocks[0]));
}
