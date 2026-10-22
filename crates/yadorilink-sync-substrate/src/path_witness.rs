//! Which network paths actually carried a connection's bytes.
//!
//! # Why a snapshot is not an answer
//!
//! `Connection::paths()` reports the paths open *now*. A connection that comes
//! up on a relay, moves 100 MiB over it, establishes a direct path and then
//! drops the relay leaves a snapshot showing one direct path and nothing else.
//! Read at the end of a transfer it says "direct only", which is exactly the
//! false negative a benchmark cannot afford: the number would be labelled as a
//! direct-path measurement while most of the bytes went through a relay.
//!
//! So this watches for the connection's whole life instead. `path_events()`
//! reports every path opened, every path closed WITH its final statistics, and
//! every change of selected path, so a path that existed only in the middle is
//! still counted.
//!
//! # Why `Lagged` invalidates the run
//!
//! `PathEvent::Lagged` means events were dropped before this subscriber saw
//! them. iroh notes that current state is still recoverable from `paths()` --
//! true, and useless here: the question is not which paths are open now but how
//! many bytes already went where, and a snapshot cannot answer for a path that
//! has since closed. A witness that quietly carried on after a gap would report
//! a total it cannot justify, so the verdict becomes `Incomplete` and the run
//! is invalid rather than optimistic.
//!
//! # Why both directions are counted
//!
//! A path's statistics are one endpoint's view, so `udp_tx` is only what
//! *this* side sent. That is the wrong half for the case that matters most.
//! A block fetch is a small request out and a large payload back, so on the
//! fetching side the payload is entirely RX and the TX total is requests and
//! acknowledgements -- a few kilobytes. "Direct TX greater than zero, relay TX
//! zero" is then satisfied by a connection whose actual payload arrived over a
//! relay, and the claim it appears to support is one it never tested.
//!
//! Counting both directions makes the verdict independent of which side is
//! asking and which is answering.
//!
//! # What this does and does not attribute
//!
//! Bytes are counted per network path at the QUIC layer, so they include
//! everything the connection carried -- every lane, plus acknowledgements and
//! keepalives. That makes it the right instrument for "did any application data
//! traverse a relay" and the wrong one for "how many bytes did this file cost".
//! A relay path that opened but only exchanged path-validation traffic is
//! therefore reported separately from one that carried real volume: a relay
//! that never opened at all is the strongest evidence, a relay that opened and
//! moved nothing is still acceptable, and a relay with bytes on it invalidates
//! the claim.

use std::collections::HashMap;

/// One path-lifecycle update, in this crate's own vocabulary.
///
/// iroh's `PathEvent` is `#[non_exhaustive]`, so a test cannot build one -- and
/// the ordering rule that matters here (every event already emitted is counted
/// before the verdict is taken) is exactly the kind that needs a test able to
/// hold an event unconsumed on purpose. Mapping at the edge keeps that rule
/// testable without a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathUpdate<K> {
    Opened {
        path: K,
        kind: PathKind,
    },
    Closed {
        path: K,
        kind: PathKind,
        bytes: PathBytes,
    },
    Lagged,
    /// Carries no bytes of its own; ignored deliberately.
    Selected,
}

/// What one path carried, in each direction.
///
/// Kept together because they are always read from the same statistics and
/// must always be attributed to the same path: separating them invites
/// counting one and forgetting the other, which is exactly the defect that
/// motivated this type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathBytes {
    pub tx: u64,
    pub rx: u64,
}

impl PathBytes {
    pub fn new(tx: u64, rx: u64) -> Self {
        Self { tx, rx }
    }

    pub fn total(&self) -> u64 {
        self.tx.saturating_add(self.rx)
    }
}

/// How a path reached the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// A direct IP path.
    Direct,
    /// Through a relay server.
    Relay,
    /// Something else the transport offered. Counted separately rather than
    /// folded into either, so a future path type cannot silently be reported as
    /// direct.
    Other,
}

/// What the paths of one connection carried.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathWitness {
    /// Bytes sent over direct IP paths.
    pub direct_tx_bytes: u64,
    /// Bytes received over direct IP paths.
    pub direct_rx_bytes: u64,
    /// Bytes sent over relay paths.
    pub relay_tx_bytes: u64,
    /// Bytes received over relay paths.
    pub relay_rx_bytes: u64,
    /// Bytes sent over paths of any other kind.
    pub other_tx_bytes: u64,
    /// Bytes received over paths of any other kind.
    pub other_rx_bytes: u64,
    /// Whether a direct path was ever open.
    pub direct_path_opened: bool,
    /// Whether a relay path was ever open, even if it carried nothing.
    pub relay_path_opened: bool,
    /// Events were dropped, so these totals are a floor and not a measurement.
    pub incomplete: bool,
}

impl PathWitness {
    /// Bytes carried over direct paths, both directions.
    pub fn direct_bytes(&self) -> u64 {
        self.direct_tx_bytes.saturating_add(self.direct_rx_bytes)
    }

    /// Bytes carried over relay paths, both directions.
    pub fn relay_bytes(&self) -> u64 {
        self.relay_tx_bytes.saturating_add(self.relay_rx_bytes)
    }

    /// Bytes carried over paths of any other kind, both directions.
    pub fn other_bytes(&self) -> u64 {
        self.other_tx_bytes.saturating_add(self.other_rx_bytes)
    }

    /// Whether this connection's bytes went direct, and only direct.
    ///
    /// Deliberately three-valued at the call site: `false` here means either
    /// "a relay carried bytes" or "we cannot say", and a benchmark must treat
    /// those the same way -- as a run that produces no number.
    ///
    /// Both directions count on every path. Asking only about TX would let a
    /// fetching node pass while its payload arrived over a relay, since on
    /// that side the payload is RX and the TX is requests and acks.
    pub fn is_direct_only(&self) -> bool {
        !self.incomplete
            && self.direct_bytes() > 0
            && self.relay_bytes() == 0
            && self.other_bytes() == 0
    }

    /// Whether a direct path carried at least `expected` bytes in some
    /// direction, as well as being the only path used.
    ///
    /// The floor is what separates a transfer from a handshake. `>= 1` is
    /// satisfied by path validation traffic, and a connection that merely
    /// completed setup has passed `is_direct_only` while carrying no payload
    /// at all -- measured here at about 5 KB on a connection the transfer
    /// never touched. A measurement should state the size it expected and
    /// require the witness to have seen it.
    pub fn carried_direct_payload(&self, expected: u64) -> bool {
        self.is_direct_only() && self.direct_bytes() >= expected
    }

    /// Why this witness does not support a direct-only claim, for a result
    /// record that has to say more than "invalid".
    pub fn rejection(&self) -> Option<String> {
        if self.incomplete {
            return Some("path events were dropped, so byte totals are unverifiable".into());
        }
        if self.direct_bytes() == 0 {
            return Some("no direct path carried any bytes".into());
        }
        if self.relay_bytes() > 0 {
            return Some(format!(
                "a relay path carried {} bytes ({} sent, {} received)",
                self.relay_bytes(),
                self.relay_tx_bytes,
                self.relay_rx_bytes
            ));
        }
        if self.other_bytes() > 0 {
            return Some(format!(
                "a non-direct, non-relay path carried {} bytes ({} sent, {} received)",
                self.other_bytes(),
                self.other_tx_bytes,
                self.other_rx_bytes
            ));
        }
        None
    }
}

/// What a whole transfer established, across every connection it used.
///
/// A transfer is not one connection. Reconciliation dials its own, the bulk
/// lanes dial another, and a path that drops mid-transfer is redialled -- so
/// the question "did this transfer stay direct" is only answerable over the
/// set. Judging connections one at a time gets two things wrong, and both
/// were real defects rather than hypotheticals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferVerdict {
    /// Every connection stayed direct, all of them could vouch for their
    /// totals, and together they carried what was expected.
    Direct { direct_bytes: u64 },
    /// A carrier other than a direct path moved bytes, or the expected
    /// volume never appeared. The claim is disproved.
    NotDirect(String),
    /// At least one connection lost events, and nothing else disproved the
    /// claim. This is the absence of an answer, not a negative one.
    Inconclusive(String),
}

/// Judges a whole attempt from every connection it used.
///
/// The order of the checks is the contract, not an implementation detail.
///
/// A relay is decided *first*, across the whole set, because a connection
/// that lost events says nothing while a connection that saw relay bytes has
/// already disproved the claim. Judging per connection and returning early
/// let an earlier connection's gap mask a later connection's relay, which
/// then read as "retry" -- and a measurement that retries past a real relay
/// eventually reports a green run.
///
/// Direct bytes are then summed across connections rather than required of
/// each. A transfer whose path drops and is redialled splits its payload
/// over two connections legitimately, and demanding the full volume from
/// each would reject a run that was correct in every respect.
pub fn verdict_for(witnesses: &[PathWitness], expected_direct_bytes: u64) -> TransferVerdict {
    if witnesses.is_empty() {
        return TransferVerdict::NotDirect(
            "no connection was witnessed, so nothing carried the transfer".into(),
        );
    }

    let relayed: u64 = witnesses.iter().map(PathWitness::relay_bytes).sum();
    let other: u64 = witnesses.iter().map(PathWitness::other_bytes).sum();
    if relayed > 0 || other > 0 {
        return TransferVerdict::NotDirect(format!(
            "{relayed} bytes crossed a relay and {other} crossed another carrier, across {} connections",
            witnesses.len()
        ));
    }

    if let Some(position) = witnesses.iter().position(|witness| witness.incomplete) {
        return TransferVerdict::Inconclusive(format!(
            "connection {position} of {} lost path events, so its totals are a floor and the set cannot be judged",
            witnesses.len()
        ));
    }

    let direct: u64 = witnesses.iter().map(PathWitness::direct_bytes).sum();
    if direct < expected_direct_bytes {
        return TransferVerdict::NotDirect(format!(
            "direct paths carried {direct} bytes across {} connections, short of the {expected_direct_bytes} expected, so the payload did not cross them",
            witnesses.len()
        ));
    }
    if direct == 0 {
        return TransferVerdict::NotDirect("no direct path carried any bytes".into());
    }

    TransferVerdict::Direct { direct_bytes: direct }
}

/// Accumulates [`PathWitness`] from a connection's path events.
///
/// Kept separate from the iroh types so the logic is testable without a
/// network: `observe_*` takes only what a caller can synthesise.
#[derive(Debug)]
pub(crate) struct WitnessAccumulator<K = u64> {
    /// Per open path: its kind, so a `Closed` event can be attributed even
    /// though it is the only place final statistics appear.
    open: HashMap<K, PathKind>,
    /// Paths whose bytes are already in the totals.
    ///
    /// Closing a connection emits `Closed` for every path that was still open
    /// AND leaves those paths in the list a later snapshot reads, so a verdict
    /// taken after close would otherwise count them twice and report roughly
    /// double the traffic. Counting each path exactly once makes the order of
    /// "drain events" and "read snapshot" stop mattering.
    counted: std::collections::HashSet<K>,
    witness: PathWitness,
}

impl<K> Default for WitnessAccumulator<K> {
    fn default() -> Self {
        Self {
            open: HashMap::new(),
            counted: std::collections::HashSet::new(),
            witness: PathWitness::default(),
        }
    }
}

impl<K: std::hash::Hash + Eq> WitnessAccumulator<K> {
    /// A path that already existed when watching began.
    ///
    /// The initial path is registered before the event receiver is handed out,
    /// so its `Opened` has no subscriber and can never be observed -- and on a
    /// relay-mode dial the initial path IS the relay. Without seeding from a
    /// snapshot at subscription time, "a relay path was open" would be
    /// structurally impossible to report for the one path most likely to be a
    /// relay.
    pub(crate) fn seed(&mut self, path: K, kind: PathKind) {
        self.opened(path, kind);
    }

    pub(crate) fn opened(&mut self, path: K, kind: PathKind) {
        match kind {
            PathKind::Direct => self.witness.direct_path_opened = true,
            PathKind::Relay => self.witness.relay_path_opened = true,
            PathKind::Other => {}
        }
        self.open.insert(path, kind);
    }

    /// A path closed, carrying its final byte count.
    pub(crate) fn closed(&mut self, path: K, kind: PathKind, bytes: PathBytes) {
        // The event's own kind is authoritative; the remembered one is a
        // fallback for a path whose open was missed.
        let kind = self.open.remove(&path).unwrap_or(kind);
        if self.counted.insert(path) {
            self.add(kind, bytes);
        }
    }

    /// A path still open when the connection ended. Its statistics come from a
    /// final snapshot rather than a close event, which is why the caller has to
    /// supply them: no `Closed` will ever arrive for it.
    pub(crate) fn still_open(&mut self, path: K, kind: PathKind, bytes: PathBytes) {
        let kind = self.open.remove(&path).unwrap_or(kind);
        if self.counted.insert(path) {
            self.add(kind, bytes);
        }
    }

    pub(crate) fn lagged(&mut self) {
        self.witness.incomplete = true;
    }

    fn add(&mut self, kind: PathKind, bytes: PathBytes) {
        let (tx, rx) = match kind {
            PathKind::Direct => {
                (&mut self.witness.direct_tx_bytes, &mut self.witness.direct_rx_bytes)
            }
            PathKind::Relay => (&mut self.witness.relay_tx_bytes, &mut self.witness.relay_rx_bytes),
            PathKind::Other => (&mut self.witness.other_tx_bytes, &mut self.witness.other_rx_bytes),
        };
        *tx = tx.saturating_add(bytes.tx);
        *rx = rx.saturating_add(bytes.rx);
    }

    pub(crate) fn absorb(&mut self, update: PathUpdate<K>) {
        match update {
            PathUpdate::Opened { path, kind } => self.opened(path, kind),
            PathUpdate::Closed { path, kind, bytes } => self.closed(path, kind, bytes),
            PathUpdate::Lagged => self.lagged(),
            PathUpdate::Selected => {}
        }
    }

    pub(crate) fn finish(self) -> PathWitness {
        self.witness
    }
}

#[cfg(test)]
mod tests;

/// Consumes `updates` until told to stop, then drains everything already
/// emitted before answering.
///
/// The drain is the point. Stopping by dropping or aborting would discard an
/// update the producer had already delivered but this consumer had not yet
/// looked at -- and a relay whose close is discarded is also gone from any
/// later snapshot, so the verdict comes out "direct only". That is not
/// `Lagged`: nothing was dropped by the transport, only by us, so nothing would
/// mark the result incomplete. It would be a false claim with no signal.
///
/// `ready(())` as the losing arm of a `biased` select is exactly "everything
/// currently ready", with no sleep and no assumption about scheduling.
pub(crate) async fn pump_updates<S, K>(
    mut updates: S,
    mut stop: tokio::sync::oneshot::Receiver<()>,
    seed: Vec<(K, PathKind)>,
) -> WitnessAccumulator<K>
where
    S: n0_future::Stream<Item = PathUpdate<K>> + Unpin + Send,
    K: std::hash::Hash + Eq,
{
    use n0_future::StreamExt as _;
    let mut acc: WitnessAccumulator<K> = WitnessAccumulator::default();
    for (path, kind) in seed {
        acc.seed(path, kind);
    }
    loop {
        tokio::select! {
            // Updates first: a stop arriving in the same moment as an update
            // must not win and discard it.
            biased;
            update = updates.next() => match update {
                Some(update) => acc.absorb(update),
                None => break,
            },
            _ = &mut stop => {
                loop {
                    tokio::select! {
                        biased;
                        update = updates.next() => match update {
                            Some(update) => acc.absorb(update),
                            None => break,
                        },
                        () = std::future::ready(()) => break,
                    }
                }
                break;
            }
        }
    }
    acc
}
