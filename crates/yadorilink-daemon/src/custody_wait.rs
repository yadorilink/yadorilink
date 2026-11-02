//! Waiting for a peer's proof of a version.
//!
//! A peer that has to read a large version back before it can vouch for it answers
//! `InProgress`: not a refusal, only "ask again shortly". Every requester of a proof (the
//! per-version eviction check, a custody lease, the whole-group handoff check) asks through
//! [`settle_proof`], which asks again with a growing pause until the proof lands or a deadline
//! passes; only then is the answer the ordinary "not held". While it waits it shows a
//! "checking copies on <device>" transfer row, so the wait is visible and is not a refusal.

use std::future::Future;
use std::time::Duration;

use yadorilink_peer_session::service_rpc::ProofAnswer;

/// How long a requester keeps asking a peer that answers `InProgress`.
pub(crate) const IN_PROGRESS_DEADLINE: Duration = Duration::from_secs(600);

/// The bound a caller puts around a whole wait: the deadline plus the last ask, which is made at
/// the deadline and must be able to finish.
pub(crate) const WAIT_OUTER_BOUND: Duration =
    Duration::from_secs(IN_PROGRESS_DEADLINE.as_secs() + 15);

pub(crate) const FIRST_PAUSE: Duration = Duration::from_secs(1);
const LONGEST_PAUSE: Duration = Duration::from_secs(15);

/// The pause after `pause` when the answer is still in progress.
pub(crate) fn longer_pause(pause: Duration) -> Duration {
    (pause * 2).min(LONGEST_PAUSE)
}

/// Asks with `ask` (each ask bounded by `ask_timeout`; no answer in time is `NotHeld`) until the
/// answer is not `InProgress`, or `deadline` has passed (then `NotHeld`). `progress` is called
/// once, when the first `InProgress` arrives, and its value is kept until the wait ends.
pub(crate) async fn settle_proof<F, Fut, G, Guard>(
    ask: F,
    ask_timeout: Duration,
    deadline: Duration,
    progress: G,
) -> ProofAnswer
where
    F: Fn() -> Fut,
    Fut: Future<Output = ProofAnswer>,
    G: FnOnce() -> Guard,
{
    let started = tokio::time::Instant::now();
    let mut pause = FIRST_PAUSE;
    let mut progress = Some(progress);
    let mut _shown = None;
    let mut seen_in_progress = false;
    loop {
        let answer = match tokio::time::timeout(ask_timeout, ask()).await {
            Ok(answer) => answer,
            // The peer said it was still checking and then a reply was lost or late: it may well
            // still be checking, so this is not a refusal. A peer that never said so is silent.
            Err(_) if seen_in_progress => ProofAnswer::InProgress,
            Err(_) => ProofAnswer::NotHeld,
        };
        if answer != ProofAnswer::InProgress {
            return answer;
        }
        seen_in_progress = true;
        let elapsed = started.elapsed();
        if elapsed >= deadline {
            return ProofAnswer::NotHeld;
        }
        if let Some(show) = progress.take() {
            _shown = Some(show());
        }
        // The last ask is made at the deadline, not a pause short of it.
        tokio::time::sleep(pause.min(deadline - elapsed)).await;
        pause = longer_pause(pause);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test(start_paused = true)]
    async fn a_proof_in_progress_is_asked_again_until_it_lands() {
        let asks = AtomicUsize::new(0);
        let shown = AtomicUsize::new(0);
        let answer = settle_proof(
            || async {
                if asks.fetch_add(1, Ordering::SeqCst) < 4 {
                    ProofAnswer::InProgress
                } else {
                    ProofAnswer::Held
                }
            },
            Duration::from_secs(12),
            IN_PROGRESS_DEADLINE,
            || shown.fetch_add(1, Ordering::SeqCst),
        )
        .await;
        assert_eq!(answer, ProofAnswer::Held);
        assert_eq!(asks.load(Ordering::SeqCst), 5);
        assert_eq!(shown.load(Ordering::SeqCst), 1, "one progress row for the whole wait");
    }

    #[tokio::test(start_paused = true)]
    async fn a_proof_that_never_lands_ends_as_not_held_at_the_deadline() {
        let asks = AtomicUsize::new(0);
        let answer = settle_proof(
            || async {
                asks.fetch_add(1, Ordering::SeqCst);
                ProofAnswer::InProgress
            },
            Duration::from_secs(12),
            Duration::from_secs(60),
            || (),
        )
        .await;
        assert_eq!(answer, ProofAnswer::NotHeld);
        assert!(asks.load(Ordering::SeqCst) > 3, "kept asking until the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn a_lost_reply_after_in_progress_is_not_a_refusal() {
        let asks = AtomicUsize::new(0);
        let answer = settle_proof(
            || async {
                match asks.fetch_add(1, Ordering::SeqCst) {
                    0 => ProofAnswer::InProgress,
                    1 => std::future::pending::<ProofAnswer>().await,
                    _ => ProofAnswer::Held,
                }
            },
            Duration::from_secs(12),
            IN_PROGRESS_DEADLINE,
            || (),
        )
        .await;
        assert_eq!(answer, ProofAnswer::Held);
        assert_eq!(asks.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_that_never_answered_is_not_held_after_one_ask_timeout() {
        let answer = settle_proof(
            std::future::pending::<ProofAnswer>,
            Duration::from_secs(12),
            IN_PROGRESS_DEADLINE,
            || (),
        )
        .await;
        assert_eq!(answer, ProofAnswer::NotHeld);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_that_is_not_in_progress_is_returned_at_once() {
        for given in [ProofAnswer::Held, ProofAnswer::NotHeld] {
            let answer = settle_proof(
                || async move { given },
                Duration::from_secs(12),
                IN_PROGRESS_DEADLINE,
                || panic!("no progress row for an answer"),
            )
            .await;
            assert_eq!(answer, given);
        }
    }
}
