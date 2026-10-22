#![cfg(test)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::*;

#[tokio::test]
async fn a_second_joiner_while_the_first_is_in_flight_becomes_a_follower() {
    let registry = HydrateSingleFlight::new();
    let leader = match registry.join("group-1", "doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };
    match registry.join("group-1", "doc.txt") {
        Role::Follower(_) => {}
        Role::Leader(_) => panic!("second concurrent joiner must be a follower, not a leader"),
    }
    leader.complete(Ok(()));
}

#[tokio::test]
async fn a_follower_observes_the_leaders_successful_outcome() {
    let registry = Arc::new(HydrateSingleFlight::new());
    let leader = match registry.join("group-1", "doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };
    let mut follower_rx = match registry.join("group-1", "doc.txt") {
        Role::Follower(rx) => rx,
        Role::Leader(_) => panic!("second joiner must be a follower"),
    };

    leader.complete(Ok(()));

    follower_rx.changed().await.unwrap();
    assert_eq!(*follower_rx.borrow(), Some(Ok(())));
}

#[tokio::test]
async fn a_follower_observes_the_leaders_failure() {
    let registry = HydrateSingleFlight::new();
    let leader = match registry.join("group-1", "doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };
    let mut follower_rx = match registry.join("group-1", "doc.txt") {
        Role::Follower(rx) => rx,
        Role::Leader(_) => panic!("second joiner must be a follower"),
    };

    leader.complete(Err(()));

    follower_rx.changed().await.unwrap();
    assert_eq!(*follower_rx.borrow(), Some(Err(())));
}

/// A leader that panics (or otherwise drops without ever calling
/// `complete`) must still release every follower rather than
/// stranding them awaiting a result that is never coming.
#[tokio::test]
async fn a_leader_dropped_without_completing_still_releases_followers() {
    let registry = HydrateSingleFlight::new();
    let leader = match registry.join("group-1", "doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };
    let mut follower_rx = match registry.join("group-1", "doc.txt") {
        Role::Follower(rx) => rx,
        Role::Leader(_) => panic!("second joiner must be a follower"),
    };

    drop(leader); // no `.complete(...)` call

    follower_rx.changed().await.unwrap();
    assert_eq!(*follower_rx.borrow(), Some(Err(())), "an incomplete round must fail closed");
}

/// After a round finishes, a caller for the SAME path starts a fresh
/// round (becomes a leader again) rather than replaying the previous
/// round's stale result forever.
#[tokio::test]
async fn a_new_round_starts_after_the_previous_one_completes() {
    let registry = HydrateSingleFlight::new();
    let leader = match registry.join("group-1", "doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };
    leader.complete(Ok(()));

    let second_role = registry.join("group-1", "doc.txt");
    match second_role {
        Role::Leader(l) => l.complete(Ok(())),
        Role::Follower(_) => panic!(
            "a new round after the previous one finished must start \
                                      a fresh leader, not attach to a stale one"
        ),
    }
}

/// Two paths that fold to the same logical name must coalesce onto
/// the same leader -- the identical reasoning `PathLockRegistry`'s
/// own lock key folding exists for.
#[tokio::test]
async fn case_folded_paths_coalesce_onto_the_same_leader() {
    let registry = HydrateSingleFlight::new();
    let leader = match registry.join("group-1", "Doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };
    match registry.join("group-1", "doc.txt") {
        Role::Follower(_) => {}
        Role::Leader(_) => {
            panic!("a case-folded-equivalent path must coalesce onto the same leader")
        }
    }
    leader.complete(Ok(()));
}

/// Unrelated paths never contend with each other -- both become
/// independent leaders.
#[tokio::test]
async fn unrelated_paths_do_not_coalesce() {
    let registry = HydrateSingleFlight::new();
    let a = match registry.join("group-1", "a.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("must be a leader"),
    };
    let b = match registry.join("group-1", "b.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("an unrelated path must be its own leader"),
    };
    a.complete(Ok(()));
    b.complete(Ok(()));
}

/// Many concurrent followers all observe the same single leader's
/// result -- exercises the coalescing property under real concurrency
/// (not just two sequential `join` calls), the actual shape of "many
/// apps open the same file at once".
#[tokio::test]
async fn many_concurrent_followers_all_observe_one_leaders_result() {
    let registry = Arc::new(HydrateSingleFlight::new());
    let leader = match registry.join("group-1", "doc.txt") {
        Role::Leader(l) => l,
        Role::Follower(_) => panic!("first joiner must be the leader"),
    };

    let follower_count = 32;
    let observed = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..follower_count {
        let mut rx = match registry.join("group-1", "doc.txt") {
            Role::Follower(rx) => rx,
            Role::Leader(_) => panic!("every joiner after the first must be a follower"),
        };
        let observed = observed.clone();
        handles.push(tokio::spawn(async move {
            rx.changed().await.unwrap();
            if *rx.borrow() == Some(Ok(())) {
                observed.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    leader.complete(Ok(()));
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(observed.load(Ordering::SeqCst), follower_count);
}
