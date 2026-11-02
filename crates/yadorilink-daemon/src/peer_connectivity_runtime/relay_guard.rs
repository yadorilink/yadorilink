//! Closes a connection that has no relay path although a relay is available.
//!
//! # Why
//!
//! A connection made before this device or the peer had a relay address (a LAN
//! connection formed while both daemons were still starting, say) carries one
//! IP path and nothing else. iroh looks a peer's addresses up only until it has
//! a selected path, so a relay that becomes known later is never opened on that
//! connection. If its only path then goes silent, QUIC cannot abandon the last
//! open path, and the connection is only ended by its own idle timeout; the
//! redial that follows goes relay-first. Nothing is wrong until that moment,
//! which is why it is worth fixing before it happens.
//!
//! # What
//!
//! When this device's home relay is connected and the coordination plane has told it a
//! relay the peer can be reached through, any live connection to that peer
//! without a relay path is closed once, with its own close code. The keeper
//! redials, and a dial made with the peer's relay known gets a relay path.
//!
//! # Bounds
//!
//! A connection must have lived for [`MIN_AGE`] first: a healthy one opens its
//! relay path within a second of connecting. iroh tries to open the relay path
//! once per connection, when the connection is added, and a try that fails (the
//! relay was unreachable for the first seconds) is not repeated, so the redial
//! is what gives it another go. A peer is not touched again for a backoff that
//! starts at [`FIRST_BACKOFF`] and doubles up to [`MAX_BACKOFF`] each time a
//! close did not produce a connection with a relay path (an advertised relay that
//! turns out to be unusable then costs a few redials, not a loop), so a relay that cannot
//! be used never turns this into a redial loop. Between events the task
//! sleeps; it only wakes on a timer while some connection is waiting out one
//! of those bounds, and then at the moment the wait ends.

use std::collections::{HashMap, HashSet};
use std::sync::Weak;
use std::time::Duration;

use tokio::time::Instant;
use yadorilink_sync_substrate::PeerId;

use crate::sync_adapter::sync_stack::SyncStack;

/// How long a connection must have lived before its missing relay path counts.
const MIN_AGE: Duration = Duration::from_secs(3);

/// How long after the first close here a peer is left alone.
const FIRST_BACKOFF: Duration = Duration::from_secs(15);

/// The longest a peer is left alone.
const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// How many closes in a row may leave a peer without a relay path before the guard stops trying
/// for it. A relay that is named but cannot be used (down, or blocked on this network) would
/// otherwise cost a redial every few minutes for ever; a changed directory record starts it again.
const MAX_FUTILE_CLOSES: u32 = 5;

/// What the guard needs to know about one live connection.
#[derive(Clone, Copy, Debug)]
pub(super) struct LinkFacts {
    pub(super) peer: PeerId,
    pub(super) id: usize,
    pub(super) has_relay_path: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Verdict {
    /// Connections to close, by id.
    pub(super) close: Vec<usize>,
    /// When to look again without waiting for an event, if some connection is waiting out a bound.
    pub(super) recheck_in: Option<Duration>,
}

#[derive(Default)]
pub(super) struct Guard {
    first_seen: HashMap<usize, Instant>,
    /// When a peer was last closed here, how long it is then left alone, and how many closes
    /// in a row have left it without a relay path.
    last_closed: HashMap<PeerId, (Instant, Duration, u32)>,
}

impl Guard {
    /// The directory's record of some peer changed (a relay named, or a different one): what was
    /// given up on may work now.
    pub(super) fn record_changed(&mut self) {
        self.last_closed.clear();
    }

    pub(super) fn evaluate(
        &mut self,
        now: Instant,
        own_relay_online: bool,
        links: &[LinkFacts],
        peer_relay_known: impl Fn(&PeerId) -> bool,
    ) -> Verdict {
        let live: HashSet<usize> = links.iter().map(|link| link.id).collect();
        self.first_seen.retain(|id, _| live.contains(id));
        for link in links {
            self.first_seen.entry(link.id).or_insert(now);
        }
        let mut verdict = Verdict::default();
        // A peer whose connections all have a relay path is working: forget its backoff. One
        // that still has a relay-less duplicate beside a good connection is not.
        let lacking: HashSet<PeerId> =
            links.iter().filter(|link| !link.has_relay_path).map(|link| link.peer).collect();
        let present: HashSet<PeerId> = links.iter().map(|link| link.peer).collect();
        self.last_closed.retain(|peer, (at, _, _)| {
            if present.contains(peer) {
                lacking.contains(peer)
            } else {
                // Gone (revoked, or just not connected): keep the history only as long as it
                // could still hold something off.
                now.saturating_duration_since(*at) < MAX_BACKOFF
            }
        });
        if !own_relay_online {
            return verdict;
        }
        let wait = |verdict: &mut Verdict, d: Duration| {
            verdict.recheck_in = Some(verdict.recheck_in.map_or(d, |old| old.min(d)));
        };
        let mut closing: HashSet<PeerId> = HashSet::new();
        for link in links {
            if link.has_relay_path || !peer_relay_known(&link.peer) {
                continue;
            }
            let age = now.saturating_duration_since(self.first_seen[&link.id]);
            if age < MIN_AGE {
                wait(&mut verdict, MIN_AGE - age);
                continue;
            }
            if !closing.contains(&link.peer) {
                if let Some((at, backoff, closes)) = self.last_closed.get(&link.peer) {
                    if *closes >= MAX_FUTILE_CLOSES {
                        // Given up until a record changes: nothing to wait out.
                        continue;
                    }
                    let since = now.saturating_duration_since(*at);
                    if since < *backoff {
                        wait(&mut verdict, *backoff - since);
                        continue;
                    }
                }
            }
            closing.insert(link.peer);
            verdict.close.push(link.id);
        }
        for peer in closing {
            let (next, closes) = match self.last_closed.get(&peer) {
                Some((_, backoff, closes)) => ((*backoff * 2).min(MAX_BACKOFF), closes + 1),
                None => (FIRST_BACKOFF, 1),
            };
            self.last_closed.insert(peer, (now, next, closes));
        }
        verdict
    }
}

/// Runs until the stack is gone.
pub(super) async fn run(stack: Weak<SyncStack>) {
    let Some(strong) = stack.upgrade() else { return };
    let mut relay = strong.endpoint().watch_home_relay_connected();
    drop(strong);
    let mut guard = Guard::default();
    loop {
        let recheck_in = {
            let Some(stack) = stack.upgrade() else { return };
            let endpoint = stack.endpoint();
            let own_relay_online = *relay.borrow();
            let live = endpoint.live_links();
            let facts: Vec<LinkFacts> = live
                .iter()
                .map(|link| LinkFacts {
                    peer: link.peer(),
                    id: link.connection_id(),
                    has_relay_path: link.has_relay_path(),
                })
                .collect();
            let directory = endpoint.address_directory().clone();
            let verdict = guard.evaluate(Instant::now(), own_relay_online, &facts, |peer| {
                directory.knows_relay_of(peer)
            });
            tracing::debug!(
                own_relay_online,
                links = facts.len(),
                without_relay_path = facts.iter().filter(|link| !link.has_relay_path).count(),
                closing = verdict.close.len(),
                recheck_in = ?verdict.recheck_in,
                "relay guard looked"
            );
            for link in live.iter().filter(|link| verdict.close.contains(&link.connection_id())) {
                tracing::info!(
                    peer = ?link.peer(),
                    "connection has no relay path although both relays are known; closing it so the redial gets one"
                );
                link.close_for_missing_relay_path();
            }
            verdict.recheck_in
        };
        let Some(strong) = stack.upgrade() else { return };
        let endpoint = strong.endpoint();
        let directory = endpoint.address_directory().clone();
        let timer = async {
            match recheck_in {
                Some(wait) => tokio::time::sleep(wait).await,
                None => std::future::pending::<()>().await,
            }
        };
        // The futures borrow the endpoint, which `strong` keeps alive only for this wait.
        tokio::select! {
            changed = relay.changed() => { if changed.is_err() { return; } }
            () = directory.next_record() => guard.record_changed(),
            () = endpoint.next_held_link() => {}
            () = timer => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    fn link(n: u8, id: usize, relay: bool) -> LinkFacts {
        LinkFacts { peer: peer(n), id, has_relay_path: relay }
    }

    #[test]
    fn a_connection_with_a_relay_path_is_left_alone() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let links = [link(1, 10, true)];
        guard.evaluate(now, true, &links, |_| true);
        let verdict = guard.evaluate(now + Duration::from_secs(60), true, &links, |_| true);
        assert_eq!(verdict, Verdict::default());
    }

    #[test]
    fn a_young_connection_is_waited_for_not_closed() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let links = [link(1, 10, false)];
        let verdict = guard.evaluate(now, true, &links, |_| true);
        assert_eq!(verdict, Verdict { close: vec![], recheck_in: Some(MIN_AGE) });
        let verdict = guard.evaluate(now + MIN_AGE, true, &links, |_| true);
        assert_eq!(verdict.close, vec![10]);
    }

    #[test]
    fn nothing_is_closed_until_both_relays_are_known() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let links = [link(1, 10, false)];
        guard.evaluate(now, true, &links, |_| false);
        let later = now + Duration::from_secs(30);
        assert_eq!(guard.evaluate(later, true, &links, |_| false), Verdict::default());
        assert_eq!(guard.evaluate(later, false, &links, |_| true), Verdict::default());
        assert_eq!(guard.evaluate(later, true, &links, |_| true).close, vec![10]);
    }

    #[test]
    fn duplicates_with_and_without_a_relay_path_close_only_the_one_without() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let links = [link(1, 10, true), link(1, 11, false)];
        guard.evaluate(now, true, &links, |_| true);
        let verdict = guard.evaluate(now + MIN_AGE, true, &links, |_| true);
        assert_eq!(verdict.close, vec![11]);
    }

    #[test]
    fn duplicates_that_both_lack_a_relay_path_are_both_closed() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let links = [link(1, 10, false), link(1, 11, false)];
        guard.evaluate(now, true, &links, |_| true);
        let mut close = guard.evaluate(now + MIN_AGE, true, &links, |_| true).close;
        close.sort();
        assert_eq!(close, vec![10, 11]);
    }

    #[test]
    fn a_peer_whose_redial_still_has_no_relay_path_is_backed_off_exponentially() {
        let mut guard = Guard::default();
        let t0 = Instant::now();
        let first = [link(1, 10, false)];
        guard.evaluate(t0, true, &first, |_| true);
        let mut closed_at = t0 + MIN_AGE;
        assert_eq!(guard.evaluate(closed_at, true, &first, |_| true).close, vec![10]);

        let mut backoff = FIRST_BACKOFF;
        for id in 11..(11 + MAX_FUTILE_CLOSES as usize - 1) {
            // The redial appears at once and is still relay-less.
            let links = [link(1, id, false)];
            guard.evaluate(closed_at, true, &links, |_| true);
            let just_before = closed_at + backoff - Duration::from_millis(1);
            let held = guard.evaluate(just_before, true, &links, |_| true);
            assert!(held.close.is_empty(), "closed again inside the {backoff:?} backoff");
            assert!(held.recheck_in.is_some(), "no wake-up scheduled for the end of the backoff");
            closed_at += backoff;
            assert_eq!(guard.evaluate(closed_at, true, &links, |_| true).close, vec![id]);
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        assert!(backoff > FIRST_BACKOFF);
    }

    #[test]
    fn a_peer_is_given_up_on_after_repeated_futile_closes_until_a_record_changes() {
        let mut guard = Guard::default();
        let mut now = Instant::now();
        let mut id = 10;
        let mut backoff = FIRST_BACKOFF;
        for _ in 0..MAX_FUTILE_CLOSES {
            let links = [link(1, id, false)];
            guard.evaluate(now, true, &links, |_| true);
            now += MIN_AGE.max(backoff);
            assert_eq!(guard.evaluate(now, true, &links, |_| true).close, vec![id]);
            backoff = (backoff * 2).min(MAX_BACKOFF);
            id += 1;
        }
        // Every redial since had no relay path, and the limit is reached: nothing more, however long.
        let links = [link(1, id, false)];
        guard.evaluate(now, true, &links, |_| true);
        let much_later = now + MAX_BACKOFF * 10;
        let verdict = guard.evaluate(much_later, true, &links, |_| true);
        assert!(verdict.close.is_empty());
        assert_eq!(verdict.recheck_in, None, "no timer for something given up on");
        // A changed record starts it again.
        guard.record_changed();
        assert_eq!(guard.evaluate(much_later, true, &links, |_| true).close, vec![id]);
    }

    #[test]
    fn a_relay_less_duplicate_beside_a_good_connection_stays_under_the_backoff() {
        let mut guard = Guard::default();
        let t0 = Instant::now();
        let first = [link(1, 10, true), link(1, 11, false)];
        guard.evaluate(t0, true, &first, |_| true);
        let closed_at = t0 + MIN_AGE;
        assert_eq!(guard.evaluate(closed_at, true, &first, |_| true).close, vec![11]);
        // The duplicate is recreated without a relay path; the good connection is still there.
        let again = [link(1, 10, true), link(1, 12, false)];
        guard.evaluate(closed_at, true, &again, |_| true);
        let mut now = closed_at + MIN_AGE;
        for _ in 0..4 {
            assert!(guard.evaluate(now, true, &again, |_| true).close.is_empty());
            now += MIN_AGE;
        }
        assert_eq!(
            guard.evaluate(closed_at + FIRST_BACKOFF, true, &again, |_| true).close,
            vec![12]
        );
    }

    #[test]
    fn history_of_a_peer_that_is_gone_is_dropped_once_it_could_no_longer_hold_anything_off() {
        let mut guard = Guard::default();
        let t0 = Instant::now();
        let links = [link(1, 10, false)];
        guard.evaluate(t0, true, &links, |_| true);
        guard.evaluate(t0 + MIN_AGE, true, &links, |_| true);
        assert_eq!(guard.last_closed.len(), 1);
        // The peer's connections are gone (revoked): the entry stays for a while, then goes.
        guard.evaluate(t0 + MIN_AGE + Duration::from_secs(1), true, &[], |_| true);
        assert_eq!(guard.last_closed.len(), 1);
        guard.evaluate(t0 + MIN_AGE + MAX_BACKOFF + Duration::from_secs(1), true, &[], |_| true);
        assert_eq!(guard.last_closed.len(), 0);
    }

    #[test]
    fn a_peer_that_got_a_relay_path_starts_from_the_short_backoff_again() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let bare = [link(1, 10, false)];
        guard.evaluate(now, true, &bare, |_| true);
        let t1 = now + MIN_AGE;
        assert_eq!(guard.evaluate(t1, true, &bare, |_| true).close, vec![10]);
        // The redial has a relay path: the backoff is forgotten.
        let good = [link(1, 20, true)];
        guard.evaluate(t1, true, &good, |_| true);
        // Later a relay-less connection appears again; it is closed after its age, not after a long wait.
        let t2 = t1 + Duration::from_secs(10);
        let bare2 = [link(1, 30, false)];
        guard.evaluate(t2, true, &bare2, |_| true);
        assert_eq!(guard.evaluate(t2 + MIN_AGE, true, &bare2, |_| true).close, vec![30]);
    }

    #[test]
    fn other_peers_are_not_held_off_by_one_peer_s_backoff() {
        let mut guard = Guard::default();
        let now = Instant::now();
        let links = [link(1, 10, false), link(2, 20, false)];
        guard.evaluate(now, true, &links, |_| true);
        let t1 = now + MIN_AGE;
        let mut close = guard.evaluate(t1, true, &links, |_| true).close;
        close.sort();
        assert_eq!(close, vec![10, 20]);
    }
}
