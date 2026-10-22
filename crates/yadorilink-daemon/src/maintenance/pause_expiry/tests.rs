#![cfg(test)]

use super::*;
use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const T: i64 = 1_800_000_000;

fn state_with_links(paths: &[&str]) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    for (n, path) in paths.iter().enumerate() {
        state.replica_coordinator.link_repository().add_link(path, &format!("g{n}")).unwrap();
    }
    state
}

fn is_paused(state: &DaemonState, path: &str) -> bool {
    state
        .replica_coordinator
        .link_repository()
        .list_links()
        .unwrap()
        .into_iter()
        .find(|l| l.key() == path)
        .unwrap()
        .paused
}

fn job(state: &Arc<DaemonState>) -> PauseExpiryJob {
    PauseExpiryJob::new(Arc::new(LinkRuntimeController::new(state.clone())))
}

#[tokio::test]
async fn a_pause_stays_until_its_deadline_then_ends_on_the_next_tick() {
    let state = state_with_links(&["/tmp/a"]);
    let links = state.replica_coordinator.link_repository();
    links.pause_until("/tmp/a", T + 600).unwrap();
    let job = job(&state);

    job.run_once_at(T).await;
    assert!(is_paused(&state, "/tmp/a"), "before the deadline");
    assert_eq!(links.paused_until("/tmp/a").unwrap(), Some(T + 600));

    job.run_once_at(T + 599).await;
    assert!(is_paused(&state, "/tmp/a"), "one second early");

    job.run_once_at(T + 600).await;
    assert!(!is_paused(&state, "/tmp/a"), "at the deadline");
    assert_eq!(links.paused_until("/tmp/a").unwrap(), None);
}

/// Restart is the same as a late tick: the deadline is in the store, and the
/// first pass of a new job decides from the clock alone.
#[tokio::test]
async fn restart_before_the_deadline_keeps_the_pause_and_after_it_ends_it() {
    let state = state_with_links(&["/tmp/a"]);
    state.replica_coordinator.link_repository().pause_until("/tmp/a", T + 600).unwrap();

    job(&state).run_once_at(T + 10).await; // a restarted daemon, early
    assert!(is_paused(&state, "/tmp/a"));

    job(&state).run_once_at(T + 3 * 3600).await; // a restarted daemon, hours late
    assert!(!is_paused(&state, "/tmp/a"));
}

#[tokio::test]
async fn a_forward_clock_jump_ends_the_pause_early() {
    let state = state_with_links(&["/tmp/a"]);
    state.replica_coordinator.link_repository().pause_until("/tmp/a", T + 3600).unwrap();
    job(&state).run_once_at(T + 7200).await;
    assert!(!is_paused(&state, "/tmp/a"));
}

#[tokio::test]
async fn a_small_backward_jump_delays_the_end_but_a_large_one_cannot_hold_the_pause() {
    let state = state_with_links(&["/tmp/a", "/tmp/b"]);
    let links = state.replica_coordinator.link_repository();
    links.pause_until("/tmp/a", T + 600).unwrap();
    job(&state).run_once_at(T - 300).await; // clock went back five minutes
    assert!(is_paused(&state, "/tmp/a"), "delayed, not ended");
    job(&state).run_once_at(T + 600).await;
    assert!(!is_paused(&state, "/tmp/a"));

    // The clock now reads days before the time the pause was set: the stored
    // deadline lies beyond anything a pause can last, so it is over.
    links.pause_until("/tmp/b", T + 600).unwrap();
    job(&state).run_once_at(T - 5 * 24 * 3600).await;
    assert!(!is_paused(&state, "/tmp/b"));
}

#[tokio::test]
async fn manual_resume_clears_the_deadline_and_indefinite_pauses_never_expire() {
    let state = state_with_links(&["/tmp/a", "/tmp/b"]);
    let links = state.replica_coordinator.link_repository();
    links.pause_until("/tmp/a", T + 600).unwrap();
    links.set_paused("/tmp/b", true).unwrap();

    LinkRuntimeController::new(state.clone()).resume("/tmp/a").await.unwrap();
    assert!(!is_paused(&state, "/tmp/a"));
    assert_eq!(links.paused_until("/tmp/a").unwrap(), None);

    job(&state).run_once_at(T + 100 * 24 * 3600).await;
    assert!(is_paused(&state, "/tmp/b"), "paused until resumed has no deadline");
    assert_eq!(links.paused_until("/tmp/b").unwrap(), None);
}

#[tokio::test]
async fn only_the_link_whose_pause_ended_resumes() {
    let state = state_with_links(&["/tmp/a", "/tmp/b"]);
    let links = state.replica_coordinator.link_repository();
    links.pause_until("/tmp/a", T + 100).unwrap();
    links.pause_until("/tmp/b", T + 5000).unwrap();
    job(&state).run_once_at(T + 200).await;
    assert!(!is_paused(&state, "/tmp/a"));
    assert!(is_paused(&state, "/tmp/b"));
}

#[tokio::test]
async fn pausing_again_replaces_the_deadline_and_an_invalid_deadline_is_refused() {
    use crate::adapters::runtime::runtime_control::DaemonPauseResumeAdapter;
    use crate::application::ports::LinkPauseResumePort;
    use crate::pause_deadline::PauseDuration;

    let state = state_with_links(&["/tmp/a"]);
    let links = state.replica_coordinator.link_repository();
    let adapter = DaemonPauseResumeAdapter::new(
        state.clone(),
        Arc::new(LinkRuntimeController::new(state.clone())),
    );

    adapter.pause("/tmp/a", PauseDuration::ThirtyMinutes, None).unwrap();
    let first = links.paused_until("/tmp/a").unwrap().expect("a deadline");
    // One hour, not until tomorrow: midnight can be nearer than 30 minutes.
    adapter.pause("/tmp/a", PauseDuration::OneHour, None).unwrap();
    assert!(links.paused_until("/tmp/a").unwrap().unwrap() > first);
    adapter.pause("/tmp/a", PauseDuration::UntilResumed, None).unwrap();
    assert!(is_paused(&state, "/tmp/a"));
    assert_eq!(links.paused_until("/tmp/a").unwrap(), None);

    assert!(links.pause_until("/tmp/a", 1).is_err());
    assert!(links.pause_until("/tmp/missing", T).is_err());
}
