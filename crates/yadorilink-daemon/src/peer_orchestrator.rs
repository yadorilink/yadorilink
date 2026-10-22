//! Connects the daemon to the coordination plane's netmap stream and
//! applies what it says: which peers this device is authorized to reach,
//! which groups it shares with each of them, and which group policies are
//! in force. Peer sessions themselves are not this module's -- one exists
//! because a peer is authorized and the iroh substrate reaches it
//! (`peer_connectivity_runtime::keep_peer_sessions`).
//!
//! The coordination netmap subscription
//! (channel connect, RPC, stream) used to be one-shot: any failure,
//! including one on the very first attempt before the network was up,
//! permanently ended `run` and left the daemon with no P2P sync until a
//! human restarted it.
//! `run` now retries that whole setup forever with backoff (every failure
//! — initial or later — is just another attempt); `run` itself stays up
//! for the daemon's whole lifetime (see its doc comment).
//!
//! That retry loop deliberately runs *inline* in `run`'s own task rather
//! than via `supervise::spawn_restarting`: `spawn_restarting` retries
//! inside a second, independently `tokio::spawn`ed task, so externally
//! aborting the task *running* `run` (as `main.rs`'s graceful
//! shutdown does, via `JoinSet::shutdown`) would only cancel `run`'s
//! `.await` on that task's `JoinHandle` — the detached retry loop
//! underneath would keep running past the abort (confirmed against
//! `supervise::tests::spawn_restarting_stops_when_aborted_from_outside`,
//! which only asserts no *new* attempt starts after abort, not that an
//! *in-flight* one stops). Keeping the loop inline means an external
//! abort of `run`'s task cancels it mid-connect or mid-sleep with nothing
//! left running behind it — see `reconnect_delay`'s doc comment for the
//! resulting small duplication of `BackoffConfig`'s jitter math.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use yadorilink_peer_session::peer_session::PeerSyncSessionDeps;
use yadorilink_transport::{diff_netmap, NetmapDiff, NetmapSnapshot};

use crate::connection_trace::{AddressClass, AttemptOutcome, CandidateSource};
use crate::daemon_state::DaemonState;
use crate::device_config;
use crate::error::DaemonError;
use crate::supervise::{spawn_one_shot, BackoffConfig};

/// What the orchestrator needs to reach the coordination plane.
///
/// `auth` used to be `access_token: String` — one token read out of the OS
/// keyring by `app.rs` at startup and cloned into every subsystem below. That
/// is the shape this cutover exists to remove: an Authorization Server access
/// token lives five minutes, so a daemon holding a startup snapshot is
/// authenticated until its first idle period and then silently 401s on every
/// call, including the netmap reconnect that is supposed to recover from it.
///
/// A [`CoordinationAuth`] is not a token. It is a handle on the one credential
/// manager this process owns, so the token is fetched — and refreshed, under a
/// cross-process lock shared with any CLI running beside it — at the moment
/// each request is made. Cloning it clones an `Arc`, so every subsystem that
/// takes a copy still refreshes through the same cache rather than racing to
/// rotate the stored refresh token.
pub struct OrchestratorConfig {
    pub coordination_addr: String,
    pub auth: yadorilink_fapi_client::CoordinationAuth,
    pub device_id: String,
}

/// Auxiliary, netmap-diff-only bookkeeping that doesn't belong on
/// `DaemonState` (which tracks *connected* sessions, not "the netmap"
/// as such): the previously-held netmap snapshot to diff each new push
/// against (`yadorilink_transport::diff_netmap`), and the newest
/// snapshot generation admitted so far.
///
/// Constructed once in `run` and threaded through every
/// `run_netmap_attempt` call (cheap to `Clone` — every field is an
/// `Arc`) so it survives a coordination-stream reconnect: a
/// revocation observed before a stream drop must still apply after the
/// stream reconnects, and — just as importantly — a fresh reconnect's
/// first snapshot must be diffed against the *last real* netmap, not an
/// empty one (an empty "previous" would report zero removals no matter
/// what changed, silently forgetting any revocation the diff hasn't
/// already acted on).
#[derive(Clone)]
struct NetmapDiffState {
    /// The netmap this device is currently acting on -- which at the start
    /// of a run is the last-known-good snapshot restored from disk, not an
    /// empty map. Starting it empty is what made the restored snapshot
    /// outrank the live netmap: removal is expressed only as "present in
    /// the previous netmap, absent from this one", and everything else
    /// about applying a netmap is per-peer and additive, so a restored peer
    /// the plane had since removed survived the first netmap that omitted
    /// it.
    previous: Arc<StdMutex<NetmapSnapshot>>,
    /// Last authoritative Worker snapshot admitted by this daemon. It lives
    /// across WebSocket reconnects so a delayed/replayed snapshot cannot
    /// restore authorization or full-replica metadata that a newer snapshot
    /// already revoked.
    last_snapshot_generation: Arc<StdMutex<Option<u64>>>,
    /// Whether the run's first authoritative netmap has already reconciled
    /// the on-disk snapshot against itself. One sweep is enough: from then
    /// on every removal reaches disk through the ordinary per-peer
    /// teardown.
    offline_snapshot_reconciled: Arc<std::sync::atomic::AtomicBool>,
    /// The plane snapshot generation the on-disk last-known-good
    /// authorization was written from, read once when this run's diff was
    /// seeded. 0 when no netmap ever wrote it.
    ///
    /// The run's first frame is the one with destructive power -- it
    /// diffs against the restored snapshot, and it owns the one-shot
    /// on-disk sweep -- and it is admitted whatever its generation,
    /// because nothing this run has seen can rank it. This is what ranks
    /// it: a frame older than the cache it would prune is an
    /// authenticated replay of an answer the cache has already moved
    /// past, and acting on what such a frame does NOT say means
    /// permanently deleting authorizations the plane never withdrew.
    persisted_snapshot_generation: u64,
}

impl NetmapDiffState {
    /// Starts this run's diff from the authorization the daemon is holding
    /// -- after an offline restart, the last-known-good snapshot restored
    /// from disk.
    ///
    /// That snapshot is a netmap's answer, one this device verified when it
    /// was live, so it is exactly the right thing to diff the next live
    /// netmap against: a peer it named and the netmap does not is a peer
    /// the plane has removed, and is torn down as if the removal had been
    /// observed while running.
    fn seeded_from_current_authorization(state: &Arc<DaemonState>) -> Self {
        Self {
            previous: Arc::new(StdMutex::new(state.authority.authorized_peer_snapshot())),
            last_snapshot_generation: Arc::new(StdMutex::new(None)),
            offline_snapshot_reconciled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            persisted_snapshot_generation: state.authority.restored_snapshot_generation(),
        }
    }

    /// Whether a frame at `frame_generation` may act on what it does NOT
    /// name: tear down peers missing from it, and delete their persisted
    /// rows.
    ///
    /// Only the run's first frame is ever refused, and only when the
    /// persisted snapshot says it was captured at a LATER plane generation
    /// than this frame carries. Every frame after the first is diffed
    /// against a netmap this run already admitted, and admission itself
    /// requires a strictly increasing generation, so by then the ordering
    /// is already established.
    ///
    /// Refusing is not "apply nothing", and the split is by DIRECTION, not
    /// by which half of the code happens to run. A narrowing is never
    /// withheld: it is the fail-closed direction, and acting on it can
    /// only take away authority this device would otherwise keep granting.
    /// So a refused frame still runs the frame's per-peer half (every peer
    /// it names is applied from it) AND the group-edge revocations in its
    /// diff -- a group this frame stops naming for a peer it DOES name is
    /// that peer being narrowed, stated by the frame itself rather than
    /// inferred from its silence.
    ///
    /// What waits is only what would WIDEN this device's exposure to an
    /// authenticated replay by destroying state: tearing down a peer the
    /// frame is merely silent about, and deleting its persisted row. Both
    /// are permanent, and a frame older than the cache is not evidence
    /// that the plane withdrew anybody. And the guard is not spent by
    /// refusing, so the first frame that does outrank the cache still does
    /// both.
    fn may_withdraw(&self, frame_generation: u64) -> bool {
        if self.offline_snapshot_reconciled.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }
        if self.persisted_snapshot_generation == 0 {
            return true;
        }
        frame_generation >= self.persisted_snapshot_generation
    }

    /// Once per run, after the first authoritative netmap has been diffed:
    /// delete the persisted authorization of every device that netmap does
    /// not name.
    ///
    /// The diff above has already torn down (and un-persisted) every
    /// restored peer the running daemon still held. What is left for this
    /// are rows with no in-memory peer behind them -- an authorization too
    /// old to act on offline is left on disk rather than rewritten at
    /// startup, and nothing else would ever clear it. Together they are
    /// what "a live netmap replaces the snapshot wholesale" means on disk.
    ///
    /// `present` comes from a full authoritative snapshot and nothing
    /// narrower: every netmap frame this daemon applies carries the plane's
    /// entire peer list (a frame may extend a group's POLICY chain rather
    /// than resend it, but never its peer set), and a partial view must
    /// never prune.
    fn reconcile_offline_snapshot_once(&self, state: &Arc<DaemonState>, present: &HashSet<String>) {
        if self.offline_snapshot_reconciled.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        state.forget_offline_peer_authorizations_absent_from(present);
    }
}

/// Applies one full authoritative netmap snapshot's membership: what it
/// removes, relative to the netmap this device was acting on until now, and
/// then the on-disk reconciliation the run's first snapshot owes.
///
/// Peers the snapshot still names are applied by the two-phase pass in
/// `ws_netmap`; this is only the withdrawal half, which is the half the
/// restored snapshot has to be subject to.
fn apply_netmap_membership(
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
    frame_generation: u64,
    current_netmap: NetmapSnapshot,
) {
    let present: HashSet<String> = current_netmap.keys().cloned().collect();
    let may_withdraw = diff_state.may_withdraw(frame_generation);
    let (diff, removed_edges, for_leases) = {
        let mut previous =
            diff_state.previous.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let diff = diff_netmap(&previous, &current_netmap);
        // Every (device, group) edge the netmap this device was acting on had
        // and this one lacks, for the custody leases those devices hold here.
        let removed_edges: Vec<(String, String)> = previous
            .iter()
            .flat_map(|(device, groups)| {
                let listed = current_netmap.get(device);
                groups
                    .iter()
                    .filter(move |group| !listed.is_some_and(|now| now.contains(*group)))
                    .map(move |group| (device.clone(), group.clone()))
            })
            .collect();
        let for_leases = if may_withdraw { current_netmap.clone() } else { NetmapSnapshot::new() };
        if may_withdraw {
            *previous = current_netmap;
        } else {
            // Merged, not replaced. Replacing would drop the restored
            // peers this frame does not name out of the map the NEXT
            // frame is diffed against, and a peer absent from both sides
            // of a diff can never be removed by it -- so a frame too
            // stale to withdraw anybody would have made those peers
            // permanently unwithdrawable instead, which is the same loss
            // in the other direction.
            for (device_id, groups) in current_netmap {
                previous.entry(device_id).or_default().extend(groups);
            }
        }
        (diff, removed_edges, for_leases)
    };
    // A requester this snapshot no longer lists for a group cannot reach this
    // device to release its custody leases there; they end with its place in
    // the group (see `custody_handoff`).
    state.drop_custody_leases_of_departed_requesters(&removed_edges, &for_leases, may_withdraw);
    if !may_withdraw {
        tracing::warn!(
            frame_generation,
            persisted_snapshot_generation = diff_state.persisted_snapshot_generation,
            withdrawals_refused = diff.removed_devices.len(),
            group_edges_revoked = diff.removed_group_edges.len(),
            "this run's first netmap frame is older than the last-known-good authorization on \
             disk; applying the peers it names -- including the groups it takes away from them \
             -- but keeping the peers it does not name, and deleting no persisted row, until a \
             frame at least as new as the snapshot arrives"
        );
        // The narrowing half still runs. A group edge in this diff belongs
        // to a peer the frame NAMES, with a group it no longer lists for
        // it, so acting on it only withdraws authority -- the direction a
        // stale frame is never a reason to withhold. Leaving it for a
        // later frame would let a peer keep serving a group the frame in
        // hand says it has lost.
        apply_netmap_group_edge_revocations(&diff, state);
        return;
    }
    apply_netmap_diff(&diff, state);
    diff_state.reconcile_offline_snapshot_once(state, &present);
}

/// Reacts to an inbound Track Send rendezvous-grant push: records the
/// sender as a grant-derived peer (`DaemonState::send_grant_peers` -- see
/// its own doc comment). That record is what admits the sender's key on
/// Track Send's ALPN (`send_transfer::track_send_admission`) for the
/// grant's lifetime, so the sender's offer dial can complete although this
/// device's sync admission may never name it -- and it never makes the
/// sender a sync peer: the sync ALPN's admission reads only
/// `PeerAuthorityState`, which this does not touch.
///
/// Expiry needs nothing scheduled: the record is TTL-pruned on every read,
/// and admission reads it live on every connection.
fn handle_incoming_send_authorization(
    grant_id: String,
    nonce: String,
    from_device_id: String,
    signing_key: [u8; 32],
    reachability: crate::coordination_client::SubstrateReachability,
    expires_at_unix: i64,
    state: &Arc<DaemonState>,
) {
    state.record_send_grant_peer(crate::daemon_state::SendGrantPeer {
        device_id: from_device_id,
        signing_key,
        reachability,
        grant_id,
        nonce,
        expires_at_unix,
    });
}

/// Applies one peer entry from a full netmap snapshot to every live
/// authorization consumer. This runs for existing sessions too; connection
/// deduplication is deliberately a later concern.
fn apply_authoritative_peer_metadata(
    state: &Arc<DaemonState>,
    device_id: &str,
    signing_key: Option<[u8; 32]>,
    authorized_groups: &HashSet<String>,
    full_replica_groups: &HashSet<String>,
    validation_cache: &std::sync::Mutex<HashMap<String, bool>>,
) -> HashSet<String> {
    // Seed identity only. Group authorization is withheld until the local
    // policy + retained-history validator positively admits it. Not
    // mirrored to the offline snapshot: the settling call below is what
    // this pass leaves behind, and it is what gets persisted.
    state.seed_netmap_peer_identity(device_id, signing_key);

    let effective_groups = crate::change_auth::effective_servable_groups(
        state.clone(),
        authorized_groups,
        validation_cache,
    );
    let effective_full_replica_groups: HashSet<String> =
        full_replica_groups.intersection(&effective_groups).cloned().collect();

    state.replace_peer_netmap_metadata(
        device_id,
        signing_key,
        &effective_groups,
        &effective_full_replica_groups,
    );
    if let Some(session) = state.peers.session(device_id) {
        // Only a change can make a refused round succeed; a snapshot that repeats what the
        // session already has must not wake every connection.
        if session.set_authorized_groups(effective_groups.iter().cloned()) {
            state.native_replication.wake_reconcile();
        }
    }
    // The reconciliation event for a new authorization is raised by
    // `replace_peer_netmap_metadata` itself, not here: that is where the
    // authorization actually comes into existence, and it has callers other
    // than this one.
    effective_groups
}

fn has_duplicate_peer_ids<'a>(peer_ids: impl IntoIterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    peer_ids.into_iter().any(|device_id| !seen.insert(device_id))
}

fn record_group_policy_states(
    state: &Arc<DaemonState>,
    coordination_endpoint: &str,
    service_key_pins: &mut HashMap<String, String>,
    service_public_key: &[u8],
    logs: &[crate::change_policy::GroupPolicyLog],
) -> Result<(), DaemonError> {
    let presented_key = <[u8; 32]>::try_from(service_public_key)
        .map_err(|_| DaemonError::Config("policy service public key is not 32 bytes".into()))?;
    let presented_hex = hex::encode(presented_key);
    let (verification_key, pin_decision) =
        policy_service_key_pin_decision(service_key_pins, coordination_endpoint, presented_key)?;
    // Mirrored onto `DaemonState` (not just this attempt-scoped
    // `service_key_pins` map) so relay-grant verification -- which can
    // happen at any later point, independent of any specific netmap
    // subscription attempt -- has the SAME trust anchor
    // `change_policy::verify_group_policy_log` already uses, without
    // needing its own separate pinning flow.
    state.authority.set_pinned_coordination_service_key(verification_key);

    let mut states = HashMap::new();
    let mut stale_groups: Vec<String> = Vec::new();
    // Groups whose verified policy head moved with this frame.
    let mut advanced_groups: Vec<String> = Vec::new();
    for log in logs {
        let cached = state.authority.group_policy_state(&log.group_id);
        // The coordination plane's policy-send watermark is PER CONNECTION,
        // while this device's cached `GroupPolicyState` is persistent and
        // connection-independent. Every fresh subscription therefore starts
        // the plane's watermark over at zero and its first frame resends the
        // group's whole chain from record 1 -- not the incremental tail an
        // already-established connection sends. Any reconnect, and any
        // hibernation wake that re-runs the subscribe path, produces exactly
        // that frame.
        //
        // `verify_group_policy_log_with_base` has zero prefix tolerance: it
        // requires the first record to be exactly `base.current_seq + 1` and
        // reports anything else as a sequence gap. Verifying a full resend
        // against the cached base would therefore fail a perfectly valid,
        // completely unchanged chain, mark the group policy-stale, and
        // withhold it -- blocking BOTH local emission and remote admission,
        // with nothing on that same connection to undo it.
        //
        // So: a log whose lowest record seq is at or below the cached base's
        // own verified position is a resend-from-scratch rather than a
        // forward extension, and is verified from scratch (`base = None`).
        // That loses nothing security-wise -- the anti-rollback decision was
        // never this function's to make. `watermark_verdict` below owns it,
        // against the PERSISTED watermark, and already handles both an
        // identical resend (accept, watermark unchanged) and a forward
        // extension (accept only if it contains the watermark's head at the
        // watermark's seq) correctly. Today's bug is precisely that
        // verification rejects the frame before `watermark_verdict` ever runs.
        let lowest_incoming_seq = log.records.iter().map(|record| record.seq).min();
        let base = match (&cached, lowest_incoming_seq) {
            (Some(cached_state), Some(lowest)) if lowest <= cached_state.current_seq => None,
            _ => cached.as_ref(),
        };
        // Whether this frame carries the group's whole chain or only the
        // records after the cached base -- what
        // `remember_group_policy_log` needs to know, because a stored TAIL
        // would not verify from scratch after a restart.
        let carries_whole_chain = base.is_none();
        match crate::change_policy::verify_group_policy_log_with_base(&verification_key, base, log)
        {
            Ok(policy) => {
                // A signature-valid chain is not enough: a PAST valid chain is
                // equally signature-valid, so a peer/coordination could replay
                // an old chain (especially right after a restart, when the
                // in-memory verified state is gone) to hide a later revoke.
                // The persisted per-group watermark is the highest chain this
                // device has ever verified and never moves backward; reject any
                // snapshot that would roll it back or fork it.
                let stored = state
                    .replica_coordinator
                    .policy_watermark_repository()
                    .policy_watermark(&log.group_id)
                    .map_err(crate::sync_error::SyncError::from)?;
                match policy.watermark_verdict(stored.as_ref()) {
                    crate::change_policy::WatermarkVerdict::Accept(watermark) => {
                        // Persist the (never-lowered) watermark BEFORE adopting
                        // the snapshot, so the anti-rollback guarantee is
                        // durable even if the daemon dies immediately after —
                        // a restart then still sees the higher watermark and
                        // refuses the old chain.
                        state
                            .replica_coordinator
                            .policy_watermark_repository()
                            .upsert_policy_watermark(&log.group_id, &watermark)
                            .map_err(crate::sync_error::SyncError::from)?;
                        // Kept as the signed bytes it arrived as, so a
                        // restart taken while the plane is unreachable can
                        // verify this exact chain again rather than start
                        // with no policy at all -- see
                        // `restore_offline_group_policy_states`.
                        remember_group_policy_log(state, log, carries_whole_chain);
                        let head_of = |p: &crate::change_policy::GroupPolicyState| {
                            p.to_watermark().highest_verified_head
                        };
                        if cached.as_ref().map(head_of) != Some(head_of(&policy)) {
                            advanced_groups.push(log.group_id.clone());
                        }
                        states.insert(log.group_id.clone(), policy);
                    }
                    crate::change_policy::WatermarkVerdict::Reject(reason) => {
                        tracing::warn!(
                            group_id = %log.group_id,
                            reason = %reason,
                            "policy snapshot rejected by rollback watermark; marking group \
                             policy stale (change admission fails closed until a valid forward \
                             snapshot arrives)"
                        );
                        forget_group_policy_log(state, &log.group_id);
                        stale_groups.push(log.group_id.clone());
                    }
                }
            }
            Err(e) => {
                // One group's snapshot failing verification must not keep its
                // previously-trusted state — that would let a revoke carried
                // in this snapshot be silently ignored, leaving a revoked
                // writer trusted. Nor should it discard the other groups' valid
                // updates in the same snapshot or tear down existing sessions.
                // Drop this group from the trusted set and mark it stale so
                // change admission for it fails closed until a valid snapshot
                // arrives.
                tracing::warn!(
                    group_id = %log.group_id,
                    error = %e,
                    "policy log snapshot failed verification; marking group policy stale \
                     (change admission fails closed until a valid snapshot arrives)"
                );
                forget_group_policy_log(state, &log.group_id);
                stale_groups.push(log.group_id.clone());
            }
        }
    }
    if pin_decision == PolicyServiceKeyPinDecision::RotationRequired {
        if states.is_empty()
            || states.values().any(|policy| policy.final_authority_key != presented_key)
        {
            return Err(DaemonError::Config(
                "policy service key changed without a verified rotation record".into(),
            ));
        }
        service_key_pins.insert(coordination_endpoint.to_string(), presented_hex);
        save_service_key_pins(service_key_pins)?;
    } else if pin_decision == PolicyServiceKeyPinDecision::NewPin {
        service_key_pins.insert(coordination_endpoint.to_string(), presented_hex);
        save_service_key_pins(service_key_pins)?;
    }
    // Marking the failed groups stale, clearing the verified ones and
    // swapping the trusted set happen in one critical section, so admission
    // never sees a gap where a group is neither trusted under the new snapshot
    // nor marked stale. The failed groups are revoked from live sessions only
    // after that switch is visible.
    state.apply_policy_snapshot(states, stale_groups);
    // A checkpoint the plane signs pins its live policy head, and a flush
    // checks it against this device's verified chain, so a batch that
    // failed because the chain lagged becomes publishable exactly when the
    // chain catches up. Nothing else would retry it.
    ws_netmap::spawn_flush_pending_checkpoints(state, Some(advanced_groups));
    // What a fork pass may do depends on the verified policy (the fallback
    // for an author that can no longer act): it looks at the contests again.
    state.reconsider_contests_after_policy_change();
    // Under checkpoint-based admission, orphan promotion is
    // purely ancestry-based (no writer-freshness re-check -- authorization
    // was already fully verified, atomically with the Change itself, at
    // original receipt time) -- `init_dag_schema`'s startup self-heal sweep
    // promotes directly, so there is nothing left for a freshly
    // verified policy frame to unblock here.
    Ok(())
}

/// Keeps `log` as the last-known-good signed policy chain for its group.
///
/// Best-effort: a chain this device cannot write is a device that will have
/// to withhold that group after its next offline restart, which is the
/// fail-closed direction, and is never a reason to fail the live netmap
/// application this mirrors.
/// `carries_whole_chain` says whether `log` is the group's entire chain or
/// only the records after the base it was verified against. A tail is merged
/// onto what is already stored before it is written, because a stored tail
/// is not a chain: a restart verifies from scratch, with no cached base to
/// continue from, and would reject it as starting at the wrong sequence.
fn remember_group_policy_log(
    state: &Arc<DaemonState>,
    log: &crate::change_policy::GroupPolicyLog,
    carries_whole_chain: bool,
) {
    let whole = if carries_whole_chain {
        log.clone()
    } else {
        match merged_with_stored_chain(state, log) {
            Some(whole) => whole,
            None => {
                // Nothing to merge onto, so nothing complete to store.
                // Drop the stored row rather than leave an older chain
                // paired with a newer watermark, which a restart would
                // refuse anyway and more confusingly.
                forget_group_policy_log(state, &log.group_id);
                return;
            }
        }
    };
    let log = &whole;
    let encoded = match serde_json::to_string(log) {
        Ok(encoded) => encoded,
        Err(error) => {
            tracing::warn!(group_id = %log.group_id, %error, "could not encode this group's policy log for offline use");
            return;
        }
    };
    if let Err(error) = state
        .replica_coordinator
        .offline_group_policy_log_repository()
        .store_group_policy_log(&log.group_id, &encoded, crate::daemon_state::now_unix())
    {
        tracing::warn!(
            group_id = %log.group_id,
            %error,
            "could not keep this group's signed policy log; the group will be withheld after \
             an offline restart until a netmap arrives"
        );
    }
}

/// The group's whole chain: the records already stored, with this frame's
/// records laid over them by sequence, and this frame's tip coordinates.
///
/// `None` when there is nothing stored to extend, which is the ordinary
/// case for a daemon that verified its first frame against an in-memory
/// base it had built earlier in the same run without ever storing it.
fn merged_with_stored_chain(
    state: &Arc<DaemonState>,
    log: &crate::change_policy::GroupPolicyLog,
) -> Option<crate::change_policy::GroupPolicyLog> {
    let stored = state
        .replica_coordinator
        .offline_group_policy_log_repository()
        .all_group_policy_logs()
        .ok()?
        .into_iter()
        .find(|entry| entry.group_id == log.group_id)?;
    let stored: crate::change_policy::GroupPolicyLog = serde_json::from_str(&stored.log).ok()?;
    let mut records: std::collections::BTreeMap<u64, crate::change_policy::PolicyRecord> =
        stored.records.into_iter().map(|record| (record.seq, record)).collect();
    for record in &log.records {
        records.insert(record.seq, record.clone());
    }
    Some(crate::change_policy::GroupPolicyLog {
        group_id: log.group_id.clone(),
        current_seq: log.current_seq,
        current_epoch: log.current_epoch,
        policy_head: log.policy_head.clone(),
        records: records.into_values().collect(),
    })
}

/// Drops a group's stored chain, so a restart does not fall back on a chain
/// this device has just stopped trusting.
fn forget_group_policy_log(state: &Arc<DaemonState>, group_id: &str) {
    if let Err(error) = state
        .replica_coordinator
        .offline_group_policy_log_repository()
        .forget_group_policy_log(group_id)
    {
        tracing::warn!(
            group_id,
            %error,
            "could not drop this group's stored policy log after its snapshot was refused"
        );
    }
}

/// Rebuilds this device's verified group policy state from the chains it
/// stored, for a start taken before any netmap of this run has arrived.
///
/// # Why this is not trusting the disk
///
/// Nothing stored is believed. Each chain is re-verified here exactly as a
/// live netmap frame is: signature by signature against the coordination
/// service key this device has PINNED (a file outside the index, written by
/// the pin decision the live path already makes), and then against the
/// persisted anti-rollback watermark, which never moves backward. A chain
/// that was tampered with fails the first check and a chain older than one
/// this device has already adopted fails the second, so this can only ever
/// restore an authorization the plane really granted and this device really
/// verified -- the same "continue the last verified answer, never start a
/// new one" contract the peer snapshot keeps.
///
/// Without it the peer snapshot buys a connection that cannot carry data: a
/// restored peer is dialable, but every linked group resolves to `Withhold`
/// (introduced, no verified policy) and admits nothing until a netmap
/// arrives -- which offline is never.
///
/// A group whose stored chain does not verify is simply not restored: it
/// stays in the ordinary startup state of a group whose policy this run has
/// not resolved, which already fails closed.
pub(crate) fn restore_offline_group_policy_states(
    state: &Arc<DaemonState>,
    coordination_endpoint: &str,
) {
    let pins = match load_service_key_pins() {
        Ok(pins) => pins,
        Err(error) => {
            tracing::warn!(%error, "could not read the pinned coordination service keys");
            return;
        }
    };
    // No pin means this device has never verified a policy frame from this
    // endpoint, so there is no trust anchor to verify a stored chain
    // against and nothing to restore. Fail closed rather than pick one.
    let Some(pinned_key) = pins.get(coordination_endpoint).and_then(|hex_key| {
        hex::decode(hex_key).ok().and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
    }) else {
        tracing::info!(
            coordination_endpoint,
            "no pinned coordination service key for this endpoint; no stored group policy can \
             be verified, so none is restored"
        );
        return;
    };
    restore_group_policy_states_verified_by(state, pinned_key);
}

/// [`restore_offline_group_policy_states`] once the trust anchor is in hand:
/// every stored chain, verified against `pinned_key` and the persisted
/// rollback watermark, and nothing else.
fn restore_group_policy_states_verified_by(state: &Arc<DaemonState>, pinned_key: [u8; 32]) {
    let stored = match state
        .replica_coordinator
        .offline_group_policy_log_repository()
        .all_group_policy_logs()
    {
        Ok(stored) => stored,
        Err(error) => {
            tracing::warn!(%error, "could not read the stored group policy logs");
            return;
        }
    };
    if stored.is_empty() {
        return;
    }

    let mut verified = HashMap::new();
    let mut oldest_capture = i64::MAX;
    let now = crate::daemon_state::now_unix();
    for entry in &stored {
        // The same horizon the peer snapshot is judged against: an answer
        // this device has had no chance to re-verify for a month is no
        // longer one it continues offline.
        if !crate::daemon_state::is_within_offline_horizon(entry.captured_at_unix, now) {
            tracing::warn!(
                group_id = %entry.group_id,
                captured_at_unix = entry.captured_at_unix,
                "this group's stored policy chain is older than this device will act on \
                 offline; it is restored only by a live netmap"
            );
            continue;
        }
        let Ok(log) = serde_json::from_str::<crate::change_policy::GroupPolicyLog>(&entry.log)
        else {
            tracing::warn!(group_id = %entry.group_id, "a stored group policy log could not be decoded; not restoring it");
            continue;
        };
        let policy = match crate::change_policy::verify_group_policy_log_with_base(
            &pinned_key,
            None,
            &log,
        ) {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(group_id = %entry.group_id, %error, "a stored group policy log does not verify against the pinned service key; not restoring it");
                continue;
            }
        };
        let watermark = match state
            .replica_coordinator
            .policy_watermark_repository()
            .policy_watermark(&entry.group_id)
        {
            Ok(watermark) => watermark,
            Err(error) => {
                tracing::warn!(group_id = %entry.group_id, %error, "could not read this group's rollback watermark; not restoring its policy");
                continue;
            }
        };
        // The watermark is only ever READ here. Restoring is not adopting a
        // new answer, so there is nothing to advance; a stored chain that
        // would not be accepted as a live frame is not accepted as a
        // restored one either.
        if let crate::change_policy::WatermarkVerdict::Reject(reason) =
            policy.watermark_verdict(watermark.as_ref())
        {
            tracing::warn!(group_id = %entry.group_id, %reason, "a stored group policy log is behind this device's rollback watermark; not restoring it");
            continue;
        }
        oldest_capture = oldest_capture.min(entry.captured_at_unix);
        verified.insert(entry.group_id.clone(), policy);
    }
    if verified.is_empty() {
        return;
    }
    state.authority.set_pinned_coordination_service_key(pinned_key);
    tracing::info!(
        group_count = verified.len(),
        captured_at_unix = oldest_capture,
        "no netmap yet this run: restored the last group policy chains this device verified, \
         re-checked against the pinned coordination service key and the rollback watermark. \
         This is offline operation on last-known-good authorization; the first live netmap \
         replaces it."
    );
    state.apply_policy_snapshot(verified, Vec::new());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyServiceKeyPinDecision {
    NewPin,
    AlreadyPinned,
    RotationRequired,
}

fn policy_service_key_pin_decision(
    service_key_pins: &HashMap<String, String>,
    coordination_endpoint: &str,
    presented_key: [u8; 32],
) -> Result<([u8; 32], PolicyServiceKeyPinDecision), DaemonError> {
    let presented_hex = hex::encode(presented_key);
    match service_key_pins.get(coordination_endpoint) {
        None => Ok((presented_key, PolicyServiceKeyPinDecision::NewPin)),
        Some(pinned) if pinned == &presented_hex => {
            Ok((presented_key, PolicyServiceKeyPinDecision::AlreadyPinned))
        }
        Some(pinned) => {
            let pinned_bytes = hex::decode(pinned).map_err(|_| {
                DaemonError::Config("stored policy service key pin is malformed".into())
            })?;
            let pinned_key = <[u8; 32]>::try_from(pinned_bytes.as_slice()).map_err(|_| {
                DaemonError::Config("stored policy service key pin is not 32 bytes".into())
            })?;
            Ok((pinned_key, PolicyServiceKeyPinDecision::RotationRequired))
        }
    }
}

/// Establishes this device's coordination-netmap subscription and keeps
/// it up for as long as the daemon runs, applying every snapshot it
/// carries.
///
/// Behavior contract callers (namely `main.rs`) can rely on: this is an
/// `async fn` meant to be spawned exactly once as an essential daemon
/// task. Under normal operation — including every kind of transient
/// failure this module retries (coordination connect, the
/// stream RPC itself) — it does
/// **not** return; the reconnect-with-backoff loop lives inside this
/// function's own task (see the module doc comment for why it's inline
/// rather than a nested spawned task), not in the caller. The only way it
/// stops is the task running it being cancelled from outside (e.g.
/// `main.rs`'s graceful shutdown aborting it) — cleanly, since there is
/// no detached child task left behind to leak.
pub async fn run(config: OrchestratorConfig, state: Arc<DaemonState>) -> Result<(), DaemonError> {
    // Idempotent: `app.rs`'s real bootstrap already records this "once, up
    // front" for control-socket callers (see `DaemonState::coordination_
    // client_config`'s own doc comment), but `on_local_native_commit`'s checkpoint-
    // flush hook needs it
    // available from ANY orchestrator start, including a lightweight test
    // harness that constructs `OrchestratorConfig` directly and never calls
    // `set_coordination_client_config` itself -- this orchestrator already
    // owns both values, so there is no reason a caller should have to.
    state.set_coordination_client_config(config.coordination_addr.clone(), config.auth.clone());
    // Created once here (not per-attempt) so it survives a
    // coordination-stream reconnect — see `NetmapDiffState`'s doc
    // comment.
    let diff_state = NetmapDiffState::seeded_from_current_authorization(&state);

    // Both loops run inline in this task, so an external abort of `run` (what
    // `main.rs`'s graceful shutdown does) cancels both with nothing detached
    // behind them -- see this module's own doc comment on why the netmap
    // retry is not `spawn_restarting`, which applies identically here. The
    // startup loop ends on its own once a stack is up; the netmap loop never
    // does, so this `join!` never returns, exactly as the bare loop did not.
    let startup = retry_until_started(&state, |state| Box::pin(start_reconciliation(state)));
    let netmap = async {
        let mut attempt: u32 = 0;
        loop {
            let started = tokio::time::Instant::now();
            match run_netmap_attempt(&config, &state, &diff_state).await {
                Ok(()) => {
                    tracing::warn!(attempt, "coordination netmap stream ended; reconnecting");
                    // A clean stream end still means the coordination-plane
                    // connection is no longer up (`run` is about to redial),
                    // not a per-peer attempt so `peer_device_id` is empty.
                    state.telemetry.record_connection_attempt(
                        "",
                        CandidateSource::CoordinationPlane,
                        AddressClass::Wan,
                        AttemptOutcome::Failed,
                        0,
                        "stream_ended",
                        false,
                        None,
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        attempt,
                        "coordination netmap subscription attempt failed; reconnecting"
                    );
                    state.telemetry.record_connection_attempt(
                        "",
                        CandidateSource::CoordinationPlane,
                        AddressClass::Wan,
                        AttemptOutcome::Failed,
                        0,
                        "connect_error",
                        false,
                        None,
                    );
                }
            }
            attempt = attempt_after_stream(attempt, started.elapsed());
            let delay = reconnect_delay(attempt);
            tracing::info!(attempt, ?delay, "waiting before next coordination reconnect attempt");
            tokio::time::sleep(delay).await;
            attempt = attempt.saturating_add(1);
        }
    };
    tokio::join!(startup, netmap);
    unreachable!("the netmap loop never returns")
}

/// Calls `start` until `state` has a convergence driver, backing off between
/// attempts, and returns once it does.
///
/// Not a periodic sweep and not a correctness rescue: it terminates for good
/// the moment a driver exists, and while it is running the daemon has no
/// convergence at all, which is the only state it exists to leave.
///
/// Runs concurrently with [`run`]'s netmap loop rather than as a step inside
/// it, which is where this lived first and was wrong: `run_netmap_attempt`
/// returns only when the coordination stream ends, so a daemon whose first
/// start failed on a transient bind and whose coordination connection then
/// stayed healthy would never have retried at all — exactly the case the
/// retry was for. Concurrently and *inline*, not spawned: a detached task
/// would outlive an external abort of `run` and go on holding `DaemonState`
/// through shutdown.
///
/// `start` is a parameter so the "retries, then stops" property can be stated
/// without needing a real endpoint bind to fail.
async fn retry_until_started<F>(state: &Arc<DaemonState>, mut start: F)
where
    F: for<'a> FnMut(
        &'a Arc<DaemonState>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>,
{
    let mut attempt: u32 = 0;
    loop {
        start(state).await;
        if state.peer_session_driver().is_some() {
            return;
        }
        let delay = reconnect_delay(attempt);
        tracing::warn!(
            attempt,
            ?delay,
            "this daemon has no convergence driver yet; retrying the reconciliation stack"
        );
        tokio::time::sleep(delay).await;
        attempt = attempt.saturating_add(1);
    }
}

/// Start the reconciliation stack.
///
/// Unconditional: this is how a daemon converges. It used to be selected by an
/// environment variable, with the legacy `HeadsAnnounce`/`ChangeRequest`/
/// `ChangeBatch` frames as the alternative — a switch that existed so the two
/// could be measured against each other on one build. That path is deleted, so
/// the switch's other position no longer names a second way to converge; it
/// names a daemon that silently cannot converge at all, on the default
/// configuration.
///
/// Failure is not fatal — the daemon still serves its control socket, still
/// materializes what it already holds, and still answers peers — but it is
/// retried by [`spawn_reconciliation_startup`] until it succeeds. Calling it
/// with a driver already installed is a no-op.
async fn start_reconciliation(state: &Arc<DaemonState>) {
    start_reconciliation_with(state, crate::peer_connectivity_runtime::sync_network_config()).await
}

/// [`start_reconciliation`] against an explicit network configuration.
///
/// Split out so a test can state the "no environment variable is required"
/// property without reaching for public relay infrastructure to prove it.
async fn start_reconciliation_with(
    state: &Arc<DaemonState>,
    network: yadorilink_sync_substrate::NetworkConfig,
) {
    if state.peer_session_driver().is_some() {
        return;
    }

    let stack = match crate::sync_adapter::SyncStack::spawn(state.clone(), network).await {
        Ok(stack) => Arc::new(stack),
        Err(error) => {
            tracing::error!(
                %error,
                "could not start the reconciliation stack; this daemon cannot converge until \
                 it does -- retrying on the next coordination reconnect"
            );
            return;
        }
    };

    tracing::info!(
        endpoint = %hex::encode(stack.peer_id().as_bytes()),
        "reconciliation stack serving"
    );

    // Before the driver, and that ordering is load-bearing: this is the last
    // moment at which no link can yet have been dialled, and `link_to`
    // returns a cached link without dialling, so a hook installed any later
    // would silently miss whatever already existed. Inert unless the daemon
    // was started with the path-evidence variable set.
    if let Some(sink) = crate::path_witness_sink::sink() {
        sink.install(&stack);
    }

    let driver = crate::sync_adapter::PeerSessionDriver::start(state.clone(), stack);
    state.install_peer_session_driver(driver);
}

/// A stream that stayed up at least this long was healthy, so its end starts
/// the backoff over rather than continuing the climb of earlier outages.
const HEALTHY_STREAM: Duration = Duration::from_secs(30);

/// The backoff step to redial at after an attempt that ran for `ran_for`
/// (measured before the backoff sleep, which is not stream uptime).
///
/// Without the reset the counter only ever grew, so a daemon that had woken from
/// sleep a handful of times waited the full cap before every later redial.
fn attempt_after_stream(attempt: u32, ran_for: Duration) -> u32 {
    if ran_for >= HEALTHY_STREAM {
        0
    } else {
        attempt
    }
}

/// Mirrors `supervise::BackoffConfig::RECONNECT`'s schedule (exponential
/// doubling from `initial`, capped at `max`, ±25% jitter) for `run`'s own
/// inline loop — `BackoffConfig::next` and its jitter RNG are private to
/// `supervise` (and deliberately not made `pub` for this one caller; see
/// the module doc comment for why this loop can't just reuse
/// `spawn_restarting` instead).
fn reconnect_delay(attempt: u32) -> Duration {
    let backoff = BackoffConfig::RECONNECT;
    let scale = 1u64 << attempt.min(20); // avoid overflow on a long-lived task
    let backed_off = backoff.initial.saturating_mul(scale as u32).min(backoff.max);
    let jitter_frac = jitter_unit_interval(); // [0, 1)
    let jitter_magnitude = backed_off.mul_f64(0.25 * jitter_frac);
    let jittered = if jitter_frac < 0.5 {
        backed_off.saturating_sub(jitter_magnitude)
    } else {
        backed_off.saturating_add(jitter_magnitude)
    };
    jittered.min(backoff.max)
}

/// A small, dependency-free `[0, 1)` PRNG (splitmix64 seeded from the
/// current time) — jitter doesn't need to be cryptographically random,
/// just different across processes/restarts.
fn jitter_unit_interval() -> f64 {
    static STATE: AtomicU64 = AtomicU64::new(0);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    let prev = STATE.fetch_add(seed | 1, Ordering::Relaxed);
    let mut z = prev.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

/// The coordination netmap subscription client: it connects the
/// coordination plane's `/netmap/subscribe` WebSocket route and processes
/// netmap updates. `run`'s inline backoff loop calls `run_netmap_attempt`
/// repeatedly; the downstream diff/spawn-session logic lives below this
/// module.
mod ws_netmap;

use ws_netmap::run_netmap_attempt;

enum PeerKeyDecision {
    AlreadyPinned,
    NewlyPinned,
    Mismatch,
}

fn verify_or_pin_peer_key(
    pins: &mut HashMap<String, String>,
    device_id: &str,
    public_key: &[u8],
) -> PeerKeyDecision {
    let public_key_hex = hex::encode(public_key);
    match pins.get(device_id) {
        Some(pinned) if pinned == &public_key_hex => PeerKeyDecision::AlreadyPinned,
        Some(_) => PeerKeyDecision::Mismatch,
        None => {
            pins.insert(device_id.to_string(), public_key_hex);
            PeerKeyDecision::NewlyPinned
        }
    }
}

/// This device's record of every peer's Ed25519 device key, pinned on first
/// sight and refused on change.
fn load_signing_key_pins() -> Result<HashMap<String, String>, DaemonError> {
    load_key_pins(signing_key_pins_path())
}

fn load_service_key_pins() -> Result<HashMap<String, String>, DaemonError> {
    load_key_pins(service_key_pins_path())
}

fn load_key_pins(path: PathBuf) -> Result<HashMap<String, String>, DaemonError> {
    match std::fs::read_to_string(&path) {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err.into()),
    }
}

/// Decodes a netmap peer's Ed25519 device key, or `None` if it carried
/// nothing usable.
///
/// Absent, empty, not base64, or not 32 bytes are one outcome, not four:
/// this key is what authenticates the peer's transport, so anything that is
/// not a key is a netmap entry describing a peer that cannot connect. The
/// caller rejects the peer and tears down anything it already had.
fn decode_peer_signing_key(encoded: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    if encoded.is_empty() {
        return None;
    }
    let bytes = base64::engine::general_purpose::STANDARD.decode(encoded).ok()?;
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// Pins `device_id`'s Ed25519 device key via `verify_or_pin_peer_key`,
/// returning `true` when the key changed from a previously-pinned value so
/// the caller refuses the peer.
fn pin_peer_signing_key(
    pins: &mut HashMap<String, String>,
    device_id: &str,
    signing_key: &[u8; 32],
) -> Result<bool, DaemonError> {
    match verify_or_pin_peer_key(pins, device_id, signing_key) {
        PeerKeyDecision::AlreadyPinned => Ok(false),
        PeerKeyDecision::NewlyPinned => {
            save_signing_key_pins(pins)?;
            Ok(false)
        }
        PeerKeyDecision::Mismatch => {
            tracing::error!(
                device_id = %device_id,
                "netmap peer device key changed from pinned value; refusing connection"
            );
            Ok(true)
        }
    }
}

/// Writes via a temp file + atomic rename into `path` (rather than
/// truncating and writing `path` in place), so two writers racing this
/// function (multiple devices' orchestrator tasks in the same process
/// sharing one config dir, or — the scenario that actually corrupted this
/// exact file in production use — two entirely separate daemon/test
/// processes pointed at the same `YADORILINK_CONFIG_DIR`) can never
/// observe or produce a file that's half one writer's JSON and half the
/// other's. `truncate(true)` + `Write` alone gives no such guarantee:
/// each writer's own `open` independently truncates to empty, so two
/// interleaved writes can leave the file containing the tail of one
/// writer's bytes appended after the other's, valid JSON followed by
/// "trailing characters" that fails every future parse of the file for
/// every reader, permanently, until something notices and repairs it by
/// hand. `rename` on both Unix and Windows replaces `path` atomically as
/// a single filesystem operation — a concurrent reader either sees the
/// old complete file or the new complete file, never a mix of both.
fn save_signing_key_pins(pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    save_key_pins(signing_key_pins_path(), pins)
}

fn save_service_key_pins(pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    save_key_pins(service_key_pins_path(), pins)
}

fn save_key_pins(path: PathBuf, pins: &HashMap<String, String>) -> Result<(), DaemonError> {
    let Some(parent) = path.parent() else {
        return Err(DaemonError::Config("key pins path has no parent directory".into()));
    };
    std::fs::create_dir_all(parent)?;
    // Unique even for two rapid, same-process calls (e.g. two devices in
    // one test binary saving within the same nanosecond): process id alone
    // isn't enough, so a monotonic per-process counter is folded in too.
    static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_path =
        parent.join(format!("peer_keys.json.tmp.{}.{nanos}.{counter}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600);
        let mut file = options.open(&tmp_path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        serde_json::to_writer_pretty(&mut file, pins)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(&tmp_path)?;
        serde_json::to_writer_pretty(&mut file, pins)?;
        file.sync_all()?;
    }
    // Published by a durable move: a pinned key does not revert after a power loss.
    yadorilink_fs_platform::durable_dir::publish_durably(
        &tmp_path,
        &path,
        yadorilink_fs_platform::durable_dir::Replace::Yes,
    )?;
    Ok(())
}

fn signing_key_pins_path() -> PathBuf {
    device_config::config_dir().join("signing_keys.json")
}

fn service_key_pins_path() -> PathBuf {
    device_config::config_dir().join("coordination_service_keys.json")
}

/// Removes `peer_device_id`'s `PeerSyncSession` from the registry, so
/// nothing holds it (or the substrate transports it carries) past the
/// session's end.
///
/// A peer's reachability is not touched: it is read from the iroh
/// endpoint's own connections, and a session being removed says nothing
/// about whether the device is still reachable.
fn end_session(state: &DaemonState, peer_device_id: &str) {
    state.peers.remove(peer_device_id);
}

/// Tears `device_id` down entirely: its peer session is removed, the
/// netmap metadata that authorized it is cleared, and its signing key is
/// withdrawn from the peer-connectivity runtime, which closes every
/// connection already open to it.
///
/// Removing the session is hydration-candidate pruning as well as cleanup:
/// `hydration::hydrate_inner` reads authorized candidate peers live from
/// `state.peers` on every attempt, so a removed device stops being offered
/// as a candidate in the same update that observed the revocation.
///
/// The order is load-bearing. `clear_peer_netmap_metadata` and
/// `revoke_device` withdraw the key first, so no new connection from the
/// device is admitted, and only then are the ones already up closed --
/// closing first would leave a window in which the peer, seeing its
/// connection drop, reconnects and is accepted. The key is read before it
/// is cleared, and `revoke_device` runs after the withdrawal has returned
/// rather than inside it, so nothing is closed while the authority state
/// is locked.
fn teardown_peer(state: &Arc<DaemonState>, device_id: &str) {
    let withdrawn_signing_key = state.authority.peer_signing_key(device_id);
    end_session(state, device_id);
    state.clear_peer_netmap_metadata(device_id);
    state.peer_connectivity.revoke_device(device_id, withdrawn_signing_key);
}

/// Acts on one netmap update's diff (`diff_netmap`'s output).
/// `PeerSyncSession` has no reference to any daemon-level "current netmap"
/// of its own — `state.peers` is the one place both a `device_id` and its
/// live `Arc<PeerSyncSession>` are available together.
fn apply_netmap_diff(diff: &NetmapDiff, state: &Arc<DaemonState>) {
    apply_netmap_device_removals(diff, state);
    apply_netmap_group_edge_revocations(diff, state);
}

/// The destructive half of a netmap diff: peers the snapshot no longer
/// names at all are torn down, which also un-pins their key and deletes
/// their persisted authorization.
///
/// Split out from the narrowing half below because the two are refusable
/// on different terms. This one acts on the frame's SILENCE -- "the
/// previous netmap listed this device and this one does not" -- and its
/// effects are permanent, so a first frame that cannot be ranked against
/// the last-known-good snapshot does not get to run it
/// (`NetmapDiffState::may_withdraw`).
fn apply_netmap_device_removals(diff: &NetmapDiff, state: &Arc<DaemonState>) {
    for device_id in &diff.removed_devices {
        tracing::warn!(
            peer = %device_id,
            "device no longer present in netmap (device remove, or its last shared group was revoked); tearing down its sync session"
        );
        teardown_peer(state, device_id);
    }
}

/// The narrowing half of a netmap diff: a peer the snapshot still names
/// has lost one of the groups it shared, so that group's authorization is
/// revoked on its live session while the tunnel and the rest of its groups
/// stay up.
///
/// Runs on every frame, including one too stale to be allowed to withdraw
/// anybody. Every edge here belongs to a device the frame itself lists, so
/// this is the frame speaking about a peer rather than being silent about
/// it, and the only thing acting on it can do is take authority away.
/// Withholding a narrowing is the one thing that would leave this device
/// serving a group the netmap in hand says the peer no longer has.
///
/// Re-running it is harmless: revoking a group a session no longer carries
/// changes nothing, which is what lets a refused frame narrow now and the
/// next frame restate the same narrowing.
fn apply_netmap_group_edge_revocations(diff: &NetmapDiff, state: &Arc<DaemonState>) {
    for (device_id, group_id) in &diff.removed_group_edges {
        tracing::info!(
            peer = %device_id,
            group = %group_id,
            "group-share edge revoked but another shared group remains; tunnel stays up, re-validating that group's session-level authorization"
        );
        if let Some(session) = state.peers.session(device_id) {
            // this is the actual enforcement step for the
            // group-edge case — from this call onward, `session`'s
            // `shares_group(group_id)` (consulted fresh by every
            // in-flight/queued block request and index update, per task
            // 4.1/4.2) returns `false`, so requests for this one group
            // over the still-live tunnel start being refused
            // (`not_found`) immediately, without needing to wait for the
            // tunnel itself to be touched.
            session.revoke_group(group_id);
        }
        // No live session found is not a bug: the session keeper may not
        // have dialled this device yet, or its session may have just ended
        // on its own between this diff being computed and this loop
        // running. In either case there is nothing currently live to
        // re-validate,
        // and any future session for this device is constructed fresh
        // from a subsequent (already-diffed-against) netmap snapshot, so
        // it will never pick group_id back up incorrectly.
    }
}

/// Every `PeerSyncSessionDeps` field this device's own daemon state can
/// supply, identical for every `PeerSyncSession` this device constructs.
pub(crate) fn peer_sync_session_deps(state: &Arc<DaemonState>) -> PeerSyncSessionDeps {
    PeerSyncSessionDeps {
        // Every session shares this daemon's one global upload/download
        // token-bucket pair (never an independent per-session copy).
        rate_limiters: state.rate_limiters.clone(),
        block_serve_engine: Some(state.block_serve_engine.clone()),
        // Lets this session answer an incoming peer `HandoffLeaseRequest`
        // by running this device's own target-side lease flow — see
        // `HandoffLeaseResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        handoff_lease_responder: state.clone(),
        // Lets this session answer an incoming peer `HandoffTicketRequest`
        // (from a different device removing/revoking this one) by running
        // this device's own removed-device-ticket flow — see
        // `HandoffTicketResponder for DaemonState`'s doc comment
        // (`daemon_state.rs`).
        handoff_ticket_responder: state.clone(),
        // Lets this session answer a full replica that asks this device to
        // move its custody lease elsewhere -- see
        // `DaemonState::rehome_custody_hold`.
        custody_rehome_responder: state.clone(),
    }
}

/// Resolves each group to its one live sync root. A group that cannot be
/// resolved unambiguously is OMITTED from the map — the peer-apply path then
/// has no write target for it and defers, rather than writing into a folder
/// picked by chance.
///
/// This used to be a `HashMap::insert` loop over `list_links()`, which meant a
/// group with two live links resolved to the LAST row while
/// `link_gate_for_group` — consulted by the very same apply path — resolved it
/// to the FIRST. Two components in one process disagreeing about which folder
/// is "the" root for one group, at the same moment. An orphaned link's
/// coordination-side authorization is gone and must never be handed back as a
/// valid write target; the primitive filters those out.
pub(crate) fn sync_roots_for_groups(
    state: &DaemonState,
    group_ids: &[String],
) -> HashMap<String, PathBuf> {
    let mut roots = HashMap::new();
    for group_id in group_ids {
        match state.replica_coordinator.link_repository().live_link_local_path_for_group(group_id) {
            Ok(Some(local_path)) => {
                roots.insert(group_id.clone(), PathBuf::from(local_path));
            }
            Ok(None) => {}
            // A provider group has no directory: it is replicated natively, never through a root.
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFilesystemRoot(_)) => {}
            Err(e) => {
                tracing::error!(
                    group_id = %group_id,
                    error = %e,
                    "cannot resolve a sync root for this group; its peer changes will not be \
                     applied until this is resolved"
                );
            }
        }
    }
    roots
}

#[cfg(test)]
mod iroh_revocation_tests;
#[cfg(test)]
mod offline_snapshot_supersession_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod version_mismatch_tests;
