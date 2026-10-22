//! Settle delay between a sync dial and the first native-replication dial.
//!
//! The first native-replication dial to a peer, started right after the
//! sync connection to the same peer finished its handshake, lost the server's
//! first QUIC flight (1200 B Initial+Handshake) on some IPv4 hairpin paths in
//! about 3-6% of dials, costing 1 s (3 s on a second loss) of PTO. The loss
//! coincides with the sync connection's post-handshake burst; waiting 50 ms
//! removed it entirely (0 of 600 dials, vs 6 of 200 without). Only the first
//! native dial after a sync dial is held back, by whatever remains of the
//! interval; later redials and dials with no recent sync dial do not wait.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::peer::PeerId;

/// How long after a sync dial completes the first native dial to that peer
/// waits. Local scheduling constant, not a transport knob.
pub(crate) const NATIVE_DIAL_SETTLE: Duration = Duration::from_millis(50);

#[derive(Debug, Default)]
pub(crate) struct DialSettle {
    sync_dialed_at: Mutex<HashMap<PeerId, Instant>>,
}

impl DialSettle {
    /// Record that a sync dial to `peer` completed now.
    pub(crate) fn sync_dial_completed(&self, peer: PeerId) {
        let now = Instant::now();
        let mut map = self.sync_dialed_at.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, at| now.saturating_duration_since(*at) < NATIVE_DIAL_SETTLE);
        map.insert(peer, now);
    }

    /// Wait out what remains of the settle interval for the first native dial
    /// to `peer` after its sync dial; consumes the record.
    pub(crate) async fn before_native_dial(&self, peer: PeerId) {
        let at = self.sync_dialed_at.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer);
        if let Some(at) = at {
            tokio::time::sleep_until(at + NATIVE_DIAL_SETTLE).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    async fn waited(s: &DialSettle, p: PeerId) -> Duration {
        let t = Instant::now();
        s.before_native_dial(p).await;
        t.elapsed()
    }

    #[tokio::test(start_paused = true)]
    async fn first_native_dial_waits_out_the_settle_interval() {
        let s = DialSettle::default();
        s.sync_dial_completed(peer(1));
        assert_eq!(waited(&s, peer(1)).await, NATIVE_DIAL_SETTLE);
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_remainder_is_waited() {
        let s = DialSettle::default();
        s.sync_dial_completed(peer(1));
        tokio::time::advance(Duration::from_millis(30)).await;
        assert_eq!(waited(&s, peer(1)).await, NATIVE_DIAL_SETTLE - Duration::from_millis(30));
    }

    #[tokio::test(start_paused = true)]
    async fn no_wait_when_settled_unknown_or_redial() {
        let s = DialSettle::default();
        assert_eq!(waited(&s, peer(1)).await, Duration::ZERO, "no sync dial recorded");
        s.sync_dial_completed(peer(1));
        tokio::time::advance(NATIVE_DIAL_SETTLE * 2).await;
        assert_eq!(waited(&s, peer(1)).await, Duration::ZERO, "already settled");
        s.sync_dial_completed(peer(2));
        assert_eq!(waited(&s, peer(2)).await, NATIVE_DIAL_SETTLE);
        assert_eq!(waited(&s, peer(2)).await, Duration::ZERO, "redial is not delayed");
        assert_eq!(waited(&s, peer(3)).await, Duration::ZERO, "other peer");
    }
}
