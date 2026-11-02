//! When a redial that is backing off should stop waiting.
//!
//! Every reconnect loop in the daemon (the coordination stream, the sync
//! connection to a peer, the native replication connection to a peer) backs
//! off exponentially to a cap of 30 to 45 seconds so that an unreachable
//! peer is not hammered. The price is that a link which was down for a while
//! and is usable again is not redialled until the backoff that was
//! accumulated *during* the outage runs out: a 30 second network cut left a
//! device waiting up to 35 s after the network was back.
//!
//! The substrate says when the network is back: [`SubstrateNode::watch_arrivals`]
//! moves when this node gains an address it did not have. That is an event,
//! so using it adds no timer and no wakeup to an idle daemon. A loop that is
//! waiting, or whose dial is hanging on a path that no longer exists, wakes
//! on it, forgets the backoff that was earned by the outage and dials now.
//!
//! One nudge never starts more than one attempt per loop, and a flapping
//! interface is paced by [`NUDGE_SETTLE`]: the loop lets the network settle
//! before it dials, and a further arrival during that pause is folded into
//! the same attempt.

use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;

/// How long a loop waits after an arrival before it dials: the interface has
/// an address but its routes and the relay connection are still coming up.
pub(crate) const NUDGE_SETTLE: Duration = Duration::from_millis(300);

/// How long dial number `failures` (0 is the first after a success or an arrival) may take
/// before the keeper gives up on it and dials again: 5 s, 10 s, 20 s, and then no bound of
/// its own (`None`), so that the transport's own handshake deadline (about 33 s) applies.
///
/// A dial that cannot reach its peer does not fail, it waits out the handshake, and one started
/// a moment before the network came back spent all of that time on a path that no longer
/// existed: a 30 s network cut was followed by up to 33 s more of a dial that would have
/// succeeded had it been made again at once. The first attempts are therefore short. A peer
/// that really is slow to answer (a long relay path, a handshake that completes at 31 s) gets
/// attempts that run to the end, so a slow link is slowed by a few retries and never prevented
/// from connecting.
pub(crate) fn dial_timeout(failures: u32) -> Option<Duration> {
    match failures {
        0 => Some(Duration::from_secs(5)),
        1 => Some(Duration::from_secs(10)),
        2 => Some(Duration::from_secs(20)),
        _ => None,
    }
}

/// Runs `dial` for as long as dial number `failures` may take; `None` if that ran out first.
pub(crate) async fn bounded_dial<T>(failures: u32, dial: impl Future<Output = T>) -> Option<T> {
    match dial_timeout(failures) {
        Some(bound) => tokio::time::timeout(bound, dial).await.ok(),
        None => Some(dial.await),
    }
}

/// A loop's view of the arrival counter. `None` (no endpoint yet) never
/// fires.
pub(crate) struct Arrivals(Option<watch::Receiver<u64>>);

/// How a wait ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Wake {
    /// The delay passed.
    Elapsed,
    /// The network came back; the caller should drop its backoff and dial.
    Nudged,
}

impl Arrivals {
    pub(crate) fn new(rx: watch::Receiver<u64>) -> Self {
        Self(Some(rx))
    }

    /// Never fires.
    pub(crate) fn never() -> Self {
        Self(None)
    }

    /// Resolves when an arrival has happened since the last one this view
    /// consumed, after letting the network settle. Pending forever when the
    /// counter's owner is gone.
    async fn arrived(&mut self) {
        let Some(rx) = self.0.as_mut() else { return std::future::pending().await };
        if rx.changed().await.is_err() {
            return std::future::pending().await;
        }
        tokio::time::sleep(NUDGE_SETTLE).await;
        // Arrivals during the pause are the same event.
        rx.borrow_and_update();
    }

    /// Counts only arrivals from now on: one that happened while the caller was busy with
    /// something else (holding a connection for hours) is not news.
    fn forget_past(&mut self) {
        if let Some(rx) = self.0.as_mut() {
            rx.borrow_and_update();
        }
    }

    /// Sleeps `delay`, or until the network comes back.
    pub(crate) async fn sleep(&mut self, delay: Duration) -> Wake {
        self.forget_past();
        tokio::select! {
            () = tokio::time::sleep(delay) => Wake::Elapsed,
            () = self.arrived() => Wake::Nudged,
        }
    }

    /// Runs `work`, abandoning it (dropping the future, which cancels a dial)
    /// when the network comes back: whatever it is waiting on was started
    /// against the network that is gone. `None` means it was abandoned.
    pub(crate) async fn run<T>(&mut self, work: impl Future<Output = T>) -> Option<T> {
        self.forget_past();
        tokio::select! {
            out = work => Some(out),
            () = self.arrived() => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Instant;

    #[test]
    fn dial_timeouts_start_short_and_end_at_the_handshake_time() {
        let schedule: Vec<Option<u64>> =
            (0..6).map(|n| dial_timeout(n).map(|d| d.as_secs())).collect();
        assert_eq!(schedule, [Some(5), Some(10), Some(20), None, None, None]);
    }

    fn pair() -> (watch::Sender<u64>, Arrivals) {
        let (tx, rx) = watch::channel(0u64);
        (tx, Arrivals::new(rx))
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_wait_lasts_the_whole_delay() {
        let (_tx, mut arrivals) = pair();
        let t0 = Instant::now();
        assert_eq!(arrivals.sleep(Duration::from_secs(30)).await, Wake::Elapsed);
        assert_eq!(t0.elapsed(), Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn an_arrival_ends_a_long_backoff_after_the_settle_pause() {
        let (tx, mut arrivals) = pair();
        let t0 = Instant::now();
        let waiter =
            tokio::spawn(
                async move { (arrivals.sleep(Duration::from_secs(30)).await, Instant::now()) },
            );
        tokio::time::sleep(Duration::from_secs(10)).await;
        tx.send_modify(|n| *n += 1);
        let (wake, at) = waiter.await.unwrap();
        assert_eq!(wake, Wake::Nudged);
        assert_eq!(at - t0, Duration::from_secs(10) + NUDGE_SETTLE);
    }

    #[tokio::test(start_paused = true)]
    async fn arrivals_during_the_pause_are_one_event() {
        let (tx, mut arrivals) = pair();
        let first = tokio::spawn(async move {
            let w = arrivals.sleep(Duration::from_secs(30)).await;
            (w, arrivals)
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let t0 = Instant::now();
        tx.send_modify(|n| *n += 1);
        tokio::time::sleep(NUDGE_SETTLE / 2).await;
        tx.send_modify(|n| *n += 1);
        let (wake, mut arrivals) = first.await.unwrap();
        assert_eq!(wake, Wake::Nudged);
        assert_eq!(t0.elapsed(), NUDGE_SETTLE);
        // The second arrival was folded in: the next wait runs its full delay.
        let t1 = Instant::now();
        assert_eq!(arrivals.sleep(Duration::from_secs(5)).await, Wake::Elapsed);
        assert_eq!(t1.elapsed(), Duration::from_secs(5));
    }

    /// A peer whose handshake completes at 31 s: the short attempts give up on it, the first
    /// unbounded one lets it through.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_connects_after_thirty_seconds_is_eventually_reached() {
        let t0 = Instant::now();
        let mut failures = 0;
        let connected_at = loop {
            let attempt_start = Instant::now();
            let handshake = async {
                // Each attempt's handshake takes 31 s from its own start.
                tokio::time::sleep(Duration::from_secs(31)).await;
            };
            match bounded_dial(failures, handshake).await {
                Some(()) => break attempt_start.elapsed() + (attempt_start - t0),
                None => failures += 1,
            }
        };
        assert_eq!(failures, 3, "5, 10 and 20 s attempts gave up; the fourth ran through");
        assert_eq!(connected_at, Duration::from_secs(5 + 10 + 20 + 31));
    }

    #[tokio::test(start_paused = true)]
    async fn an_arrival_from_before_the_wait_began_is_not_news() {
        let (tx, mut arrivals) = pair();
        tx.send_modify(|n| *n += 1);
        let t0 = Instant::now();
        assert_eq!(arrivals.sleep(Duration::from_secs(4)).await, Wake::Elapsed);
        assert_eq!(t0.elapsed(), Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_dial_is_abandoned_when_the_network_returns() {
        let (tx, mut arrivals) = pair();
        let hung = tokio::spawn(async move {
            let out = arrivals.run(std::future::pending::<()>()).await;
            (out, Instant::now())
        });
        let t0 = Instant::now();
        tokio::time::sleep(Duration::from_secs(29)).await;
        tx.send_modify(|n| *n += 1);
        let (out, at) = hung.await.unwrap();
        assert_eq!(out, None);
        assert!(at - t0 <= Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn without_an_endpoint_nothing_fires() {
        let mut arrivals = Arrivals::never();
        assert_eq!(arrivals.sleep(Duration::from_secs(7)).await, Wake::Elapsed);
    }

    /// The shape of every keeper: dial; on failure double the delay (cap 30 s)
    /// and wait it out unless the network comes back. A 30 s outage in which the
    /// dial failed at 0, 1, 3, 7, 15 s leaves the next attempt at 31 s without
    /// the signal; with it, the dial happens one settle pause after the network
    /// returned.
    #[tokio::test(start_paused = true)]
    async fn a_thirty_second_outage_is_recovered_one_settle_pause_after_it_ends() {
        let (tx, mut arrivals) = pair();
        let t0 = Instant::now();
        let outage = Duration::from_secs(30);
        let task = tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                let up = Instant::now() - t0 >= outage;
                if up {
                    return Instant::now() - t0;
                }
                if arrivals.sleep(delay).await == Wake::Nudged {
                    delay = Duration::from_secs(1);
                } else {
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        });
        tokio::time::sleep(outage).await;
        tx.send_modify(|n| *n += 1);
        let recovered = task.await.unwrap();
        assert_eq!(recovered, outage + NUDGE_SETTLE);
    }

    /// Without the signal the same loop only notices at its next scheduled attempt.
    #[tokio::test(start_paused = true)]
    async fn without_the_signal_the_same_loop_waits_out_its_backoff() {
        let (_tx, mut arrivals) = pair();
        let t0 = Instant::now();
        let outage = Duration::from_secs(30);
        let mut delay = Duration::from_secs(1);
        loop {
            if Instant::now() - t0 >= outage {
                break;
            }
            arrivals.sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(30));
        }
        assert_eq!(Instant::now() - t0, Duration::from_secs(31));
    }
}
