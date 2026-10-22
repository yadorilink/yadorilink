#![cfg(test)]

use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::signed_delta::NativeDelta;
use yadorilink_sqlite_runtime::SyncDatabase;

use super::*;

use crate::native_test_support::*;

fn published(c: &SyncDatabase, delta: &NativeDelta) -> bool {
    c.read(|conn| native_publication::is_published(conn, &delta.delta_hash())).unwrap()
}

#[tokio::test]
async fn nothing_pending_makes_no_request() {
    let c = db();
    let source = FakeSource::new();
    let outcome = flush_pending_native_checkpoint(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap()
    .outcome;
    assert_eq!(outcome, FlushOutcome::NothingPending);
}

#[tokio::test]
async fn one_flush_publishes_every_incarnation_of_the_device_and_a_second_finds_nothing() {
    let c = db();
    let first = author_delta(&c, 1, "a.txt");
    let second = author_delta(&c, 1, "b.txt");
    let third = author_delta(&c, 2, "c.txt");
    let source = FakeSource::new();

    let outcome = flush_pending_native_checkpoint(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();

    assert_eq!(outcome.outcome, FlushOutcome::Flushed { batch_size: 3, checkpoint_seq: 1 });
    assert_eq!(outcome.published.len(), 3);
    for delta in [&first, &second, &third] {
        assert!(published(&c, delta));
    }
    let again = flush_pending_native_checkpoint(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap()
    .outcome;
    assert_eq!(again, FlushOutcome::NothingPending);
}

#[tokio::test]
async fn a_refusing_source_leaves_the_batch_pending_for_the_same_retry() {
    let c = db();
    let delta = author_delta(&c, 1, "a.txt");
    let mut source = FakeSource::new();
    source.refuse = true;

    let outcome = flush_pending_native_checkpoint(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap()
    .outcome;

    assert_eq!(outcome, FlushOutcome::Refused);
    assert!(!published(&c, &delta));
}

#[tokio::test]
async fn a_checkpoint_that_does_not_verify_attaches_nothing() {
    let c = db();
    let first = author_delta(&c, 1, "a.txt");
    let second = author_delta(&c, 1, "b.txt");
    let source = FakeSource::new();
    // The daemon trusts a different authority key than the one that signed.
    let other = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
    let wrong = move |_: &[u8; 32], _: &[u8; 32]| Some(other);

    let error = flush_pending_native_checkpoint(&c, &source, GROUP, DEVICE, &device_vk(), &wrong)
        .await
        .unwrap_err();

    assert!(matches!(error, FlushError::CheckpointDidNotVerify { .. }), "{error}");
    assert!(!published(&c, &first));
    assert!(!published(&c, &second));
}

/// Hashes the Merkle tree work of publishing `count` pending deltas costs.
async fn hashes_to_publish(count: usize) -> u64 {
    let c = db();
    for index in 0..count {
        author_delta(&c, 1, &format!("f{index}.txt"));
    }
    let source = FakeSource::new();
    yadorilink_replica_domain::authorization_checkpoint::hash_count::reset();
    let flushed = flush_pending_native_checkpoint(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();
    assert_eq!(flushed.published.len(), count);
    yadorilink_replica_domain::authorization_checkpoint::hash_count::get()
}

#[tokio::test]
async fn publishing_a_batch_costs_a_number_of_hashes_that_grows_near_linearly() {
    let small = hashes_to_publish(2000).await;
    let large = hashes_to_publish(4000).await;
    // Root, proofs, and one verification path per leaf: n * (log n + a few).
    assert!(large <= 4000 * 20, "{large} hashes for 4000 deltas");
    assert!(large * 2 <= small * 5, "doubling the batch took {small} -> {large} hashes");
}

#[tokio::test]
async fn a_stop_signal_between_chunks_returns_promptly_attaches_nothing_and_the_next_flush_completes(
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let count = 3 * VERIFY_CHUNK_LEAVES + 1;
    let c = db();
    for index in 0..count {
        author_delta(&c, 1, &format!("f{index}.txt"));
    }
    let source = FakeSource::new();
    let looks = AtomicUsize::new(0);
    // Quiet for the first chunk, raised from the second look on.
    let stop = || looks.fetch_add(1, Ordering::SeqCst) >= 1;

    yadorilink_replica_domain::authorization_checkpoint::hash_count::reset();
    let interrupted = flush_pending_native_checkpoint_until(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
        &stop,
    )
    .await
    .unwrap();
    let spent = yadorilink_replica_domain::authorization_checkpoint::hash_count::get();

    assert_eq!(interrupted.outcome, FlushOutcome::Interrupted);
    assert!(interrupted.published.is_empty());
    assert_eq!(looks.load(Ordering::SeqCst), 2, "no chunk ran after the signal");
    // The root and every proof (about 2 hashes per leaf each), plus one chunk
    // of verification paths (at most 15 hashes each): far from verifying all.
    assert!(spent <= (5 * count + VERIFY_CHUNK_LEAVES * 15) as u64, "{spent} hashes");
    let all_paths = (count * 14) as u64;
    assert!(spent < 4 * count as u64 + all_paths / 2, "{spent} hashes: verification ran on");
    let pending = c
        .read(|conn| {
            native_publication::pending_native_deltas_for_device(
                conn,
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
                DEVICE,
            )
        })
        .unwrap();
    assert_eq!(pending.len(), count, "no evidence was attached");

    let flushed = flush_pending_native_checkpoint(
        &c,
        &source,
        GROUP,
        DEVICE,
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();
    assert_eq!(flushed.published.len(), count);
}
