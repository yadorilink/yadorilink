#![cfg(test)]

use std::sync::Arc;

use yadorilink_local_capture::Ingest;

use super::*;
use crate::engine_tuning::{EngineTuning, FileMode};

const GROUP: &str = "group-1";
const LARGE: u64 = FILE_ONLY_MIN_SIZE + 1;

fn coordinator(file_block_source: bool) -> Arc<ReplicaCoordinator> {
    let tuning = EngineTuning {
        file_mode: if file_block_source { FileMode::ServesFromFiles } else { FileMode::Blocks },
        ..EngineTuning::default()
    };
    Arc::new(ReplicaCoordinator::open_in_memory_with(tuning).unwrap())
}

fn lease(coordinator: &ReplicaCoordinator, id: &str, path: &str, expires_in_secs: i64) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    coordinator
        .handoff_lease_repository()
        .record_handoff_lease(
            GROUP,
            id,
            [0; 32],
            &[(path.to_owned(), 1)],
            now,
            now + expires_in_secs,
        )
        .unwrap();
}

/// A device that does not serve from files puts every file into the store, however large.
#[test]
fn without_serving_from_files_every_file_goes_into_the_store() {
    let policy = ingest_policy_for(&coordinator(false));
    assert_eq!(policy.ingest_for(GROUP, "huge.bin", u64::MAX), Ingest::Store);
    assert_eq!(policy.ingest_for(GROUP, "small.txt", 1), Ingest::Store);
}

/// With it on, a large file that nothing keeps is only hashed; a small one is still copied.
#[test]
fn a_large_unkept_file_is_only_hashed_and_a_small_one_is_copied() {
    let policy = ingest_policy_for(&coordinator(true));
    assert_eq!(policy.ingest_for(GROUP, "big.bin", LARGE), Ingest::FileOnly);
    assert_eq!(policy.ingest_for(GROUP, "big.bin", FILE_ONLY_MIN_SIZE), Ingest::FileOnly);
    assert_eq!(policy.ingest_for(GROUP, "small.bin", FILE_ONLY_MIN_SIZE - 1), Ingest::Store);
}

/// A pinned item, its descendants and a leased item keep their versions in the store; another
/// path, and a lease that has expired, do not.
#[test]
fn a_pinned_or_leased_item_is_copied_into_the_store() {
    let c = coordinator(true);
    c.retention_rules().pin(GROUP, "pinned-dir").unwrap();
    lease(&c, "live", "leased.bin", 3600);
    lease(&c, "expired", "was-leased.bin", -3600);
    let policy = ingest_policy_for(&c);

    assert_eq!(policy.ingest_for(GROUP, "pinned-dir", LARGE), Ingest::Store);
    assert_eq!(policy.ingest_for(GROUP, "pinned-dir/inside/big.bin", LARGE), Ingest::Store);
    assert_eq!(policy.ingest_for(GROUP, "leased.bin", LARGE), Ingest::Store);
    assert_eq!(policy.ingest_for(GROUP, "other.bin", LARGE), Ingest::FileOnly);
    assert_eq!(policy.ingest_for(GROUP, "was-leased.bin", LARGE), Ingest::FileOnly);
    assert_eq!(policy.ingest_for("another-group", "pinned-dir", LARGE), Ingest::FileOnly);
}

/// Only the pin term follows the rule table: an online-only rule nearer than a keep above it takes
/// the pin away, and a custody lease, a store-mode request and an unreadable state still keep the
/// version in the store.
#[test]
fn an_online_only_rule_ends_only_the_pin_term_of_keeping_in_the_store() {
    use yadorilink_sync_sqlite::Rule;
    let c = coordinator(true);
    c.retention_rules().set(GROUP, "kept", Some(Rule::Keep)).unwrap();
    c.retention_rules().set(GROUP, "kept/free", Some(Rule::OnlineOnly)).unwrap();
    lease(&c, "live", "kept/free/leased.bin", 3600);
    let policy = ingest_policy_for(&c);

    assert_eq!(policy.ingest_for(GROUP, "kept/x.bin", LARGE), Ingest::Store);
    assert_eq!(
        policy.ingest_for(GROUP, "kept/free/x.bin", LARGE),
        Ingest::FileOnly,
        "the online-only exception is not kept by the pin term"
    );
    assert_eq!(
        policy.ingest_for(GROUP, "kept/free/leased.bin", LARGE),
        Ingest::Store,
        "a leased version under an online-only rule is still kept in the store"
    );
    assert!(!must_keep_in_store(&c, GROUP, "kept/free/x.bin"));
    assert!(must_keep_in_store(&c, GROUP, "kept/free/leased.bin"));

    let hold = c.store_mode_requests().hold(GROUP, std::time::Duration::from_secs(60));
    assert_eq!(
        ingest_policy_for(&c).ingest_for(GROUP, "kept/free/x.bin", LARGE),
        Ingest::Store,
        "a store-mode request keeps everything, whatever the rules say"
    );
    drop(hold);
}

/// The predicate itself, which the receive side will share.
#[test]
fn must_keep_in_store_is_the_pin_or_lease_question_alone() {
    let c = coordinator(true);
    assert!(!must_keep_in_store(&c, GROUP, "a.bin"));
    c.retention_rules().pin(GROUP, "a.bin").unwrap();
    assert!(must_keep_in_store(&c, GROUP, "a.bin"));
    lease(&c, "l", "b.bin", 3600);
    assert!(must_keep_in_store(&c, GROUP, "b.bin"));
    assert!(!must_keep_in_store(&c, GROUP, "c.bin"));
}

/// A group asked to store captures large files into the store until the request ends or expires,
/// and no other group is affected.
#[test]
fn a_store_mode_request_makes_a_group_store_until_it_ends() {
    let c = coordinator(true);
    let policy = ingest_policy_for(&c);
    assert_eq!(policy.ingest_for(GROUP, "big.bin", LARGE), Ingest::FileOnly);

    let hold = c.store_mode_requests().hold(GROUP, std::time::Duration::from_secs(60));
    assert_eq!(policy.ingest_for(GROUP, "big.bin", LARGE), Ingest::Store);
    assert_eq!(policy.ingest_for("another-group", "big.bin", LARGE), Ingest::FileOnly);

    drop(hold);
    assert_eq!(policy.ingest_for(GROUP, "big.bin", LARGE), Ingest::FileOnly);
}

/// A request lapses by itself: a caller that never comes back cannot keep a group in store mode.
#[test]
fn a_store_mode_request_expires() {
    let requests = StoreModeRequests::default();
    requests.hold(GROUP, std::time::Duration::from_millis(30)).leave_to_expire();
    assert!(requests.requested(GROUP));

    std::thread::sleep(std::time::Duration::from_millis(80));

    assert!(!requests.requested(GROUP), "the request lapsed");
}

/// A later request extends an earlier one, and never shortens it.
#[test]
fn a_later_store_mode_request_extends_and_never_shortens() {
    let requests = StoreModeRequests::default();
    let _long = requests.hold(GROUP, std::time::Duration::from_secs(60));
    requests.hold(GROUP, std::time::Duration::from_millis(1)).leave_to_expire();
    std::thread::sleep(std::time::Duration::from_millis(20));
    assert!(requests.requested(GROUP), "the shorter request did not cut the longer one");
}

/// Two requests overlap: the one that finishes first does not end the store mode the other still
/// needs, and the last to finish ends it.
#[test]
fn overlapping_store_mode_requests_end_with_the_last_holder() {
    let requests = StoreModeRequests::default();
    let first = requests.hold(GROUP, std::time::Duration::from_secs(60));
    let second = requests.hold(GROUP, std::time::Duration::from_secs(60));

    drop(first);
    assert!(requests.requested(GROUP), "one holder is still working");

    drop(second);
    assert!(!requests.requested(GROUP), "the last holder is done");
}

/// A request that leaves work pending lasts until its deadline, whatever another request's release
/// does meanwhile.
#[test]
fn a_request_left_to_expire_lasts_until_its_deadline() {
    let requests = StoreModeRequests::default();
    requests.hold(GROUP, std::time::Duration::from_millis(60)).leave_to_expire();
    drop(requests.hold(GROUP, std::time::Duration::from_millis(60))); // another finishes

    assert!(requests.requested(GROUP), "the request left to expire still holds");
    std::thread::sleep(std::time::Duration::from_millis(120));
    assert!(!requests.requested(GROUP), "its deadline ended it");
}

/// A request whose caller was cancelled (the hold dropped while it waited) releases like any other.
#[test]
fn a_dropped_hold_releases() {
    let requests = StoreModeRequests::default();
    let hold = requests.hold(GROUP, std::time::Duration::from_secs(60));
    drop(hold);
    assert!(!requests.requested(GROUP));
}

/// The holders an expired request counted never came back; a new request must not inherit them.
#[test]
fn a_new_request_does_not_inherit_the_holders_of_an_expired_one() {
    let requests = StoreModeRequests::default();
    requests.hold(GROUP, std::time::Duration::from_millis(30)).leave_to_expire();
    std::thread::sleep(std::time::Duration::from_millis(80));

    drop(requests.hold(GROUP, std::time::Duration::from_secs(60)));

    assert!(!requests.requested(GROUP), "the stale holder did not keep the group in store mode");
}

/// A hold taken against a request that has since expired must not release the request that
/// replaced it: it is a different generation, however late the old hold is dropped.
#[test]
fn a_late_hold_of_an_expired_request_does_not_release_a_newer_one() {
    let requests = StoreModeRequests::default();
    let old = requests.hold(GROUP, std::time::Duration::from_millis(30));
    std::thread::sleep(std::time::Duration::from_millis(80)); // the old request's deadline passes
    let newer = requests.hold(GROUP, std::time::Duration::from_secs(60));

    drop(old);

    assert!(requests.requested(GROUP), "the newer request still holds");
    drop(newer);
    assert!(!requests.requested(GROUP));
}
