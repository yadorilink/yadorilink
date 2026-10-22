//! This device's last-known-good authorization snapshot: the on-disk
//! mirror of what a live netmap last told it about its peers, and the
//! provenance marker that says which of the two a running daemon is
//! currently acting on.
//!
//! # What this is
//!
//! Two devices on the same local network are not broken merely because the
//! coordination plane, the relays or the internet are. The authorization
//! that let them sync was verified against that plane while it WAS
//! reachable; this keeps that last verified answer on disk so a restart
//! taken while the plane is unreachable can rediscover the same peers over
//! the local network and go on syncing.
//!
//! # What this is NOT
//!
//! An authority. Nothing here decides anything. Every row is written by a
//! live netmap application mirroring a decision the plane already made and
//! this device already verified, is replaced wholesale by the next such
//! application, and is deleted when a netmap withdraws the peer. So:
//!
//! - a live netmap always wins -- it overwrites this on the way past;
//! - a peer absent from the snapshot is never authorized while offline,
//!   because offline operation continues an authorization and never starts
//!   one;
//! - a local-network announcement is not authority either: it is matched
//!   against the pinned signing key in the snapshot, and a different key
//!   matches nothing (fail closed);
//! - a revoke withdraws the peer from memory and from disk together, so
//!   restarting does not resurrect it.
//!
//! Detecting a revocation that happens at the plane WHILE this device is
//! offline is explicitly out of scope, and nothing here claims it. The
//! contract is exactly "keep using the last verified authorization while
//! offline", nothing more.
//!
//! # What "never widens" means on the READ path
//!
//! The write path only ever mirrors a live netmap, so nothing written here
//! can be wider than what the plane granted. That says nothing about a row
//! that arrived some other way, so state it plainly: the index database is
//! trusted local state, on the same footing as this device's own signing
//! key and credential store, which sit in the same directory under the same
//! OS user. Anyone who can write it can already forge this device's own
//! change history, so these tables are not a new trust boundary -- but they
//! are not defended by one either, and a reader should not imagine
//! otherwise.
//!
//! Two things keep that from being a blank cheque:
//!
//! - what these rows can confer is bounded. They pin a peer's key and say
//!   which groups it was authorized for; they do not decide what may be
//!   WRITTEN. Change admission takes that from the group's signed policy
//!   chain, which is verified record by record against the pinned
//!   coordination service key (a file outside this database) and against
//!   the persisted rollback watermark -- see
//!   `peer_orchestrator::restore_offline_group_policy_states`. A row
//!   naming a device no policy chain grants buys a dial, not a write.
//! - an authorization is acted on offline only while it is RECENT. See
//!   [`OFFLINE_AUTHORIZATION_HORIZON_SECS`]: past it, a peer is authorized
//!   again only by a live netmap.

use std::sync::{Arc, Mutex, MutexGuard};

use yadorilink_sync_sqlite::{OfflinePeerAuthorization, OfflineSnapshotVersions};

use crate::replica_coordinator::ReplicaCoordinator;

/// How long after a netmap verified an authorization this device will still
/// act on it with no plane to ask -- 7 days.
///
/// This is a security parameter, not a session or cache lifetime: it is the
/// longest a device may keep running on last-known-good authorization alone
/// since it last confirmed that authorization with a live netmap. A
/// revocation the plane recorded while this device was unreachable is
/// undetectable here by construction, so this bound is also the longest a
/// peer revoked at the plane can keep being accepted on the strength of the
/// stored record. The age of the answer is the only thing left to judge.
///
/// It is deliberately not unbounded, and deliberately long enough for the
/// case it exists for: an outage, a flight, a move, a holiday, where the
/// plane is unreachable for days but the authorization it last gave is
/// still the right answer. Past the horizon the device stops acting on the
/// record and waits for a live netmap, which is the fail-closed direction
/// and the only one available. A device that syncs at all re-writes these
/// rows from every netmap it applies, so the horizon is only ever reached
/// by a device that has been away from the plane for a week.
///
/// A stored row can be up to [`SNAPSHOT_REFRESH_INTERVAL_SECS`] older than
/// the last netmap that restated it, so the usable offline window is about
/// six to seven days rather than exactly seven; that is accepted, because
/// the alternative is writing more often only to move the edge.
pub const OFFLINE_AUTHORIZATION_HORIZON_SECS: i64 = 7 * 24 * 60 * 60;

/// Whether an authorization captured at `captured_at_unix` is recent enough
/// to act on offline at `now`.
///
/// A capture time in the future is refused rather than treated as maximally
/// fresh: it means the clock moved, so the age of this record cannot be
/// judged at all, and an unjudgeable record is not one to act on. A little
/// slack absorbs ordinary clock adjustment rather than making a one-second
/// skew look like an attack.
pub fn is_within_offline_horizon(captured_at_unix: i64, now: i64) -> bool {
    /// Ordinary clock drift and NTP correction, not an attack.
    const CLOCK_SLACK_SECS: i64 = 60 * 60;
    let age = now.saturating_sub(captured_at_unix);
    (-CLOCK_SLACK_SECS..=OFFLINE_AUTHORIZATION_HORIZON_SECS).contains(&age)
}

/// Where the peer authorization a running daemon is acting on came from.
///
/// Carried as state rather than left to a comment because the difference is
/// a security difference: [`LiveNetmap`](Self::LiveNetmap) is the
/// coordination plane's current answer, and
/// [`OfflineLastKnownGood`](Self::OfflineLastKnownGood) is this device
/// continuing to act on the last answer it verified, with no way to learn
/// that the plane has since changed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthorizationProvenance {
    /// No netmap has been applied this run and nothing was restored from
    /// disk: this device authorizes no peer at all.
    #[default]
    Unestablished,
    /// Restored from the on-disk snapshot and not yet superseded. The
    /// daemon is running on last-known-good authorization, offline: every
    /// peer it accepts is one a netmap authorized at `captured_at_unix`,
    /// and no peer can be added until a live netmap arrives.
    OfflineLastKnownGood { peer_count: usize, captured_at_unix: i64 },
    /// A live netmap has been applied this run; it is the authority, and
    /// the on-disk snapshot is now only its mirror.
    LiveNetmap,
}

impl AuthorizationProvenance {
    /// Whether the daemon is currently acting on last-known-good
    /// authorization rather than on a netmap it has verified this run --
    /// the question a diagnostic, a status line or a reviewer asks.
    pub fn is_offline_last_known_good(self) -> bool {
        matches!(self, Self::OfflineLastKnownGood { .. })
    }
}

/// The daemon's handle on the persisted snapshot.
///
/// Owns nothing but the coordinator it reads and writes through and the
/// lock that orders its writes. Every method is best-effort and logs rather
/// than propagating: a snapshot this device cannot write is a device that
/// will authorize nobody after its next offline restart, which is the
/// fail-closed direction, and is never a reason to fail the live
/// authorization change being mirrored.
pub(super) struct OfflineAuthorizationCache {
    coordinator: Arc<ReplicaCoordinator>,
    /// Serializes snapshot writes so what lands on disk is in the same
    /// order as the in-memory mutations it mirrors. Lock ordering: this is
    /// taken BEFORE `PeerAuthorityState::peer_netmap_metadata` and never
    /// after, and no read path takes it at all.
    write_order: Mutex<MirroredRows>,
    /// How many durable transactions this cache has actually issued --
    /// what a test measures the write cost of a netmap push with.
    #[cfg(test)]
    durable_writes: std::sync::atomic::AtomicUsize,
}

/// How long a row may go unrewritten while the authorization it carries
/// does not change -- one day.
///
/// The snapshot's write path is a mirror, so rewriting a row whose content
/// is identical to the one already on disk changes nothing anybody reads,
/// and a netmap push re-states every peer whether or not anything about it
/// moved. What a rewrite DOES change is `captured_at_unix`, which is what
/// [`is_within_offline_horizon`] judges, so the rewrites cannot be skipped
/// forever: past this interval the row is written again for its capture
/// time alone. A day is well inside the horizon
/// ([`OFFLINE_AUTHORIZATION_HORIZON_SECS`]), so a device that is talking to
/// the plane at all keeps its snapshot away from the edge, at one
/// transaction per peer per day rather than two per peer per push; the cost
/// is that a row may be a day older than the netmap that restated it.
const SNAPSHOT_REFRESH_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// How far ahead of the generation actually in use each reservation
/// claims -- see [`MirroredRows::reserved_generation`].
///
/// Sized so the reservations are lost in the noise of ordinary operation:
/// a netmap push costs two generations per peer it names, so 4096 covers
/// ten full pushes to two hundred peers before disk is touched for the
/// counter alone. Sized so a run cannot burn through many of them either
/// -- this is a reservation, not a sequence with a gap that matters, and
/// nothing reads the number except the comparison "is this the same
/// authorization version as a moment ago".
///
/// # Why the floor needs a reservation at all, and not just a write
///
/// The guarantee is that a restart never hands out a membership generation
/// the previous run already used, because a version captured before a peer
/// round-trip must not compare equal to one captured after it. Disk is
/// where that survives a restart, so the floor holds only while the number
/// on disk stays at or above every generation memory has reached.
///
/// Writing the current generation on each bump would give that directly,
/// but the bumps and the writes are not one-to-one. `replace_peer_netmap_
/// metadata` bumps the counter whenever a peer's authorization actually
/// changes, and then persists only when its caller asked for the row to be
/// mirrored NOW; the identity-seeding half of a netmap peer entry
/// (`SnapshotMirror::AfterThisNetmapPassSettles`) deliberately writes
/// nothing, because the settling call a few lines later is the one that
/// states the authorization worth persisting. So a bump can be followed by
/// no durable write at all, and several bumps can pass between two writes.
///
/// What closes that is this reservation rather than the write cadence:
/// every write pushes the durable number `GENERATION_RESERVATION` past the
/// generation in use, so disk is already ahead of anything the bumps that
/// persist nothing can reach before the next write catches up. The
/// constant therefore has a correctness role and not only a cost one: it
/// must stay comfortably larger than the number of generations a run can
/// burn between two durable writes. Two per netmap peer entry, bounded by
/// the peer count of a single push, is the quantity to compare it against.
const GENERATION_RESERVATION: u64 = 4096;

/// What this daemon has already written to each peer's row, so a write
/// that would restate it can be skipped, and how far the membership
/// generation on disk has been reserved ahead.
///
/// Lives inside the write-order mutex rather than beside it: it is only
/// ever read and updated by the code holding that lock, so it cannot
/// disagree with the order the writes actually went out in. In-memory
/// only, and deliberately not seeded at startup -- a fresh daemon writes
/// every peer once, which is also what refreshes the capture times of the
/// rows it restored.
#[derive(Default)]
pub(super) struct MirroredRows {
    rows: std::collections::HashMap<String, OfflinePeerAuthorization>,
    /// The membership generation disk has been told about: a ceiling this
    /// run promises to stay under, not a generation anybody used.
    ///
    /// The generation must never go backwards across a restart, and the
    /// peer rows cannot carry that guarantee: the row holding the highest
    /// generation is the one a withdrawal deletes, a restatement is
    /// skipped rather than rewritten, and the identity-seed/settle pair of
    /// a repeated push advances the generation twice while writing
    /// nothing. Reserving a block ahead instead means the number on disk
    /// is already past anything this run will reach, at one write per
    /// [`GENERATION_RESERVATION`] mutations rather than one per mutation.
    reserved_generation: u64,
    /// The coordination plane's snapshot generation the rows written from
    /// here belong to -- the cache's provenance, recorded so a later run
    /// can refuse to let a frame OLDER than its own cache prune it. 0
    /// until a netmap has been applied this run.
    snapshot_generation: u64,
}

impl MirroredRows {
    /// Adopts the reservation the previous run left on disk, so this run
    /// starts under a ceiling that is already durable rather than
    /// reserving again for a number nobody has used yet.
    pub(super) fn seed_reserved_generation(&mut self, reserved: u64) {
        self.reserved_generation = self.reserved_generation.max(reserved);
    }

    /// Records which plane snapshot the rows written from now on come
    /// from. Monotonic: the netmap path admits frames in strictly
    /// increasing generation order, and a lower number here could only
    /// mean a caller out of that order.
    pub(super) fn note_snapshot_generation(&mut self, snapshot_generation: u64) {
        self.snapshot_generation = self.snapshot_generation.max(snapshot_generation);
    }

    /// The versions a write made right now must carry: the generation
    /// ceiling (extended past `generation` when it has caught up with the
    /// last reservation) and the plane snapshot these rows come from.
    fn versions_for(&self, generation: u64) -> OfflineSnapshotVersions {
        let membership_generation = if generation >= self.reserved_generation {
            generation.saturating_add(GENERATION_RESERVATION)
        } else {
            self.reserved_generation
        };
        // The floor this whole mechanism exists for: what a write puts on
        // disk is never below a generation memory has already handed out,
        // or a restart could reissue one. See `GENERATION_RESERVATION` for
        // why the reservation, rather than the write cadence, is what
        // holds this up.
        debug_assert!(
            membership_generation >= generation,
            "a durable membership generation must never sit below the one in use"
        );
        OfflineSnapshotVersions {
            membership_generation,
            snapshot_generation: self.snapshot_generation,
        }
    }
}

/// Whether two rows carry the same authorization -- the same pinned key
/// and the same group sets, order disregarded.
///
/// `membership_generation` and `captured_at_unix` are deliberately not
/// compared: neither says anything about what the peer may do, and
/// comparing the generation would rewrite every peer's row on every push
/// that moved any peer -- the write amplification the skip exists to
/// remove.
///
/// Skipping the restatement is what makes a row's own
/// `membership_generation` an unreliable floor for the run's generation:
/// the row that carried the highest one is exactly the one a withdrawal
/// deletes, and the survivors are not rewritten to restate it. That is why
/// the generation ALSO goes to the snapshot-wide version row
/// ([`OfflineSnapshotVersions`]), which every write advances and no
/// withdrawal can take with it.
fn carries_the_same_authorization(
    stored: &OfflinePeerAuthorization,
    next: &OfflinePeerAuthorization,
) -> bool {
    fn same_groups(left: &[String], right: &[String]) -> bool {
        left.len() == right.len()
            && left.iter().collect::<std::collections::HashSet<_>>()
                == right.iter().collect::<std::collections::HashSet<_>>()
    }
    stored.signing_key == next.signing_key
        && same_groups(&stored.writer_groups, &next.writer_groups)
        && same_groups(&stored.full_replica_groups, &next.full_replica_groups)
}

impl OfflineAuthorizationCache {
    pub(super) fn new(coordinator: Arc<ReplicaCoordinator>) -> Self {
        Self {
            coordinator,
            write_order: Mutex::new(MirroredRows::default()),
            #[cfg(test)]
            durable_writes: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// The number of durable transactions issued so far.
    #[cfg(test)]
    pub(super) fn durable_writes(&self) -> usize {
        self.durable_writes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The membership-generation ceiling this run believes is on disk.
    ///
    /// Test-only, and the observable for one specific property: the
    /// reservation is a claim about what a transaction actually wrote, so
    /// after a write that failed it must still equal the number the
    /// counter row holds.
    #[cfg(test)]
    pub(super) fn reserved_generation(&self) -> u64 {
        self.write_order().reserved_generation
    }

    #[cfg(test)]
    fn count_durable_write(&self) {
        self.durable_writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(not(test))]
    fn count_durable_write(&self) {}

    pub(super) fn write_order(&self) -> MutexGuard<'_, MirroredRows> {
        self.write_order.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Every persisted peer authorization, for a daemon rebuilding its
    /// in-memory peer authority at startup.
    ///
    /// Fails closed: a snapshot that cannot be read in full restores
    /// nothing, because a daemon that authorizes nobody waits for a netmap
    /// while one that authorizes an unexamined subset does not.
    pub(super) fn restore(&self) -> Vec<OfflinePeerAuthorization> {
        match self.coordinator.offline_peer_authorization_repository().all_peer_authorizations() {
            Ok(peers) => peers,
            Err(error) => {
                tracing::error!(
                    %error,
                    "could not read the last-known-good peer authorization snapshot; starting \
                     with no peers authorized until a netmap arrives"
                );
                Vec::new()
            }
        }
    }

    /// The snapshot-wide version counters on disk: the membership
    /// generation the previous run reserved and the plane snapshot
    /// generation its rows were written from.
    ///
    /// Fails closed in both directions if it cannot be read: generation 0
    /// is what a device with no history has, and snapshot generation 0
    /// gates no frame, so an unreadable counter row leaves the run exactly
    /// where a first-ever start would be rather than inventing a floor.
    pub(super) fn snapshot_versions(&self) -> OfflineSnapshotVersions {
        match self.coordinator.offline_peer_authorization_repository().snapshot_versions() {
            Ok(versions) => versions,
            Err(error) => {
                tracing::error!(
                    %error,
                    "could not read the last-known-good snapshot's version counters"
                );
                OfflineSnapshotVersions::default()
            }
        }
    }

    /// Mirrors one peer's authorization, unless the row on disk already
    /// says exactly this and is recent enough not to need its capture time
    /// refreshed -- see [`SNAPSHOT_REFRESH_INTERVAL_SECS`]. Skipping a
    /// restatement cannot weaken what disk says, because the row that
    /// stays is the one this call would have written.
    ///
    /// `mirrored` is the write-order guard's own state, so the record of
    /// what was written is updated in the same critical section as the
    /// write. A failed write drops the record rather than keeping it: the
    /// next attempt must go to disk, since disk no longer holds what this
    /// daemon thinks it does.
    pub(super) fn store(&self, mirrored: &mut MirroredRows, peer: &OfflinePeerAuthorization) {
        let versions = mirrored.versions_for(peer.membership_generation);
        if let Some(stored) = mirrored.rows.get(&peer.device_id) {
            if carries_the_same_authorization(stored, peer)
                && peer.captured_at_unix.saturating_sub(stored.captured_at_unix)
                    < SNAPSHOT_REFRESH_INTERVAL_SECS
                // A restatement is skipped, but not when the generation
                // ceiling on disk has to move with it: the seed/settle
                // pair of a repeated push advances the generation twice
                // and changes no row, so this is the only call that would
                // ever carry the new reservation to disk.
                && versions.membership_generation == mirrored.reserved_generation
            {
                return;
            }
        }
        self.count_durable_write();
        if let Err(error) = self
            .coordinator
            .offline_peer_authorization_repository()
            .store_peer_authorization(peer, versions)
        {
            mirrored.rows.remove(&peer.device_id);
            tracing::error!(
                %error,
                device_id = %peer.device_id,
                "could not record this peer in the last-known-good authorization snapshot; it \
                 will not be authorized after an offline restart"
            );
            return;
        }
        mirrored.rows.insert(peer.device_id.clone(), peer.clone());
        mirrored.reserved_generation = versions.membership_generation;
    }

    /// Withdraws one peer. `generation` is the membership generation in
    /// force at the withdrawal -- carried to disk because this is exactly
    /// the write that would otherwise take the highest generation with it.
    pub(super) fn forget(&self, mirrored: &mut MirroredRows, device_id: &str, generation: u64) {
        mirrored.rows.remove(device_id);
        let versions = mirrored.versions_for(generation);
        self.count_durable_write();
        if let Err(error) = self
            .coordinator
            .offline_peer_authorization_repository()
            .forget_peer_authorization(device_id, versions)
        {
            tracing::error!(
                %error,
                device_id,
                "could not withdraw this peer from the last-known-good authorization snapshot"
            );
            return;
        }
        mirrored.reserved_generation = versions.membership_generation;
    }

    /// Drops the whole snapshot: every peer row, and the stored policy
    /// chains that go with them.
    ///
    /// `generation` is the membership generation in force at the erasure,
    /// carried to disk for the same reason [`forget`](Self::forget)
    /// carries it -- this write is the one that would otherwise take the
    /// highest generation with it.
    ///
    /// The in-memory reservation is advanced only once the write has
    /// landed, exactly as in `store` and `forget`. A reservation is a
    /// promise about what DISK already says; recording one the transaction
    /// did not make would leave this run believing the ceiling had moved
    /// while the counter row still held the old number, and every later
    /// write in the run would then skip carrying it -- so a restart would
    /// resume under a ceiling the run had already passed.
    pub(super) fn forget_all(&self, mirrored: &mut MirroredRows, generation: u64) {
        mirrored.rows.clear();
        let versions = mirrored.versions_for(generation);
        self.count_durable_write();
        if let Err(error) = self
            .coordinator
            .offline_peer_authorization_repository()
            .forget_all_peer_authorizations(versions)
        {
            tracing::error!(
                %error,
                "could not delete the last-known-good peer authorization snapshot"
            );
        } else {
            mirrored.reserved_generation = versions.membership_generation;
        }
        // The stored policy chains go with it. They are signed bytes rather
        // than a grant, but they are still a record of which groups this
        // device belonged to and who was in them, and that must not outlive
        // the account relationship either.
        if let Err(error) =
            self.coordinator.offline_group_policy_log_repository().forget_all_group_policy_logs()
        {
            tracing::error!(
                %error,
                "could not delete the stored group policy logs"
            );
        }
    }
}

/// Whether a netmap-derived mutation mirrors itself onto disk as it
/// happens, or leaves that to the call that settles the same peer's
/// authorization later in the same netmap pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SnapshotMirror {
    /// Write the peer's row now: what this call leaves in memory is the
    /// authorization in force until something else changes it.
    Now,
    /// Write nothing here. This call is the identity-seeding half of one
    /// netmap peer entry, and the groups it withholds are settled a few
    /// lines later by the same pass. This is also the path that bumps the
    /// membership generation without any durable write behind it; see
    /// [`GENERATION_RESERVATION`] for why the generation floor survives
    /// that. Persisting the intermediate would put
    /// a "no groups" row on disk that no netmap ever said, and that
    /// nothing reads unless the process dies inside those few lines -- in
    /// which case what disk keeps instead is the last netmap application
    /// that COMPLETED.
    ///
    /// # The bound, stated exactly
    ///
    /// A crash inside that window leaves disk holding the PREVIOUS
    /// completed netmap application's row, not the one the pass was about
    /// to settle. So the bound is not "never wider than what the plane
    /// granted at this instant" -- it is: **never wider than what the
    /// plane granted at the last netmap application this device
    /// completed.** One push old, and a push is an answer the plane gave
    /// and this device verified.
    ///
    /// Those two differ when the settling call was about to NARROW the
    /// peer. The real case is not a plane-side revocation -- the diff
    /// withdraws a peer the netmap stops naming, and that withdrawal
    /// writes through `Now` -- but a LOCAL narrowing:
    /// `effective_servable_groups` intersects the netmap's groups with
    /// what this device's own policy verification currently admits, so a
    /// group that went policy-stale drops out of the settled set while
    /// the netmap still names it. Crash in the window and the row on disk
    /// still lists that group, and the next offline start restores it.
    ///
    /// Severity, and why this is accepted rather than closed: the stale
    /// group's own fail-closed gate is not this row. A restored group
    /// admits no change until its stored policy chain re-verifies against
    /// the pinned coordination service key and the rollback watermark
    /// (`peer_orchestrator::restore_offline_group_policy_states`), and a
    /// group that went stale is precisely one whose chain does not
    /// verify. So the widened row buys a dial and a pinned key for a peer
    /// the plane does name, and no write admission. Closing it costs a
    /// second durable transaction per peer per push -- the write
    /// amplification `SNAPSHOT_REFRESH_INTERVAL_SECS` and this variant
    /// exist to remove -- to narrow a window of a few lines that is
    /// already gated elsewhere, so the window is accepted rather than
    /// closed.
    AfterThisNetmapPassSettles,
}
