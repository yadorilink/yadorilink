//! Making a folder rewind's historical content local, verified, before the
//! rewind changes anything.
//!
//! A thin orchestrator over the ordinary verified block fetch
//! ([`fetch_blocks_from_sessions`]), not a second fetch engine. It adds only
//! what a rewind needs and hydration does not:
//!
//! - a strict local check: every required block must be present, carry this
//!   group's provenance, AND read back with the bytes its hash names, whether
//!   or not any peer is reachable (hydration re-reads local blocks only when
//!   a peer could repair them);
//! - a classification of what could not be fetched. Content is
//!   *unobtainable* only when every device that could hold it was connected
//!   and each explicitly answered that it does not hold it, on every one of a
//!   bounded, spaced re-ask (one "do not hold" can be the server racing its
//!   own index update). Anything else -- a device offline, a timeout, a lost
//!   exchange, a busy or refusing peer, the stall deadline, an unknown
//!   membership -- leaves it *unresolved*: a statement about this attempt,
//!   never about the content;
//! - a stall deadline that stops the fetch lanes and waits for their block
//!   writes to finish, instead of abandoning them.
//!
//! It takes no path lock, no root operation and no write-activity guard: it
//! writes only blocks and their provenance, which change nothing anyone
//! sees.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use yadorilink_peer_session::peer_session::PeerSyncSession;
use yadorilink_replica_domain::file::BlockInfo;

use super::{
    candidate_sessions, fetch_blocks_from_sessions, Dispatched, HydrationStallTracker, LaneStop,
    STALL_BUDGET_MARGIN, STALL_CHECK_INTERVAL,
};
use crate::daemon_state::{DaemonState, GroupPolicyResolution};
use crate::sync_error::SyncError;

/// The label a rewind's block requests and its transfer row carry. A block
/// is requested by hash; the path only lets a server size its credit from a
/// current record naming that block, which historical content has none of.
pub(crate) const REWIND_PREFETCH_LABEL: &str = "folder rewind";

/// How many times still-missing content is asked for. The server answers
/// "do not hold" while its own index may be racing an in-flight write and
/// says a retry may succeed, so a single answer is not evidence; this is
/// the same bound peer sessions use for that race.
const ASK_ROUNDS: u32 = PeerSyncSession::NOT_FOUND_RETRY_ATTEMPTS;

/// Which devices could hold this group's content, as far as this device
/// can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContentHolders {
    /// The group's verified policy names this device and these other
    /// members.
    Known(Vec<String>),
    /// No verified membership that includes this device (no policy yet, a
    /// withheld one, or one that does not name this device): no answer can
    /// be shown to come from every holder.
    Unknown,
}

pub(crate) fn content_holders(state: &DaemonState, group_id: &str) -> ContentHolders {
    match state.resolve_group_policy(group_id) {
        GroupPolicyResolution::Verified(policy) => {
            let members = policy.current_members();
            if !members.iter().any(|member| member.device_id == state.device_id) {
                return ContentHolders::Unknown;
            }
            ContentHolders::Known(
                members
                    .into_iter()
                    .map(|member| member.device_id)
                    .filter(|device_id| *device_id != state.device_id)
                    .collect(),
            )
        }
        GroupPolicyResolution::Bootstrap | GroupPolicyResolution::Withhold => {
            ContentHolders::Unknown
        }
    }
}

/// What could not be made local. Both empty: everything is held and
/// verified.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct PrefetchVerdict {
    /// Blocks every device that could hold them said, every time they were
    /// asked, that they do not hold.
    pub(crate) unobtainable: HashSet<Vec<u8>>,
    /// Every other block still missing.
    pub(crate) unresolved: HashSet<Vec<u8>>,
    /// The member devices that were not connected when content was last
    /// asked for: what a person has to bring online before retrying.
    pub(crate) offline: Vec<String>,
}

/// Per block, how many rounds ended with every holder explicitly declining
/// it. Only a block declined in all [`ASK_ROUNDS`] rounds is unobtainable:
/// a run cut short (the stall deadline) has not asked often enough to rule
/// out the server's index race, whatever the rounds it did run said.
#[derive(Debug)]
struct DeclineEvidence {
    rounds_required: u32,
    declined_rounds: HashMap<Vec<u8>, u32>,
}

impl Default for DeclineEvidence {
    fn default() -> Self {
        Self { rounds_required: ASK_ROUNDS, declined_rounds: HashMap::new() }
    }
}

impl DeclineEvidence {
    /// Records one round that asked for `asked`. `declined` is the subset
    /// every connected candidate explicitly refused; it counts only when
    /// `every_holder_asked`.
    fn record_round(
        &mut self,
        asked: &[BlockInfo],
        declined: &HashSet<Vec<u8>>,
        every_holder_asked: bool,
    ) {
        for block in asked {
            if every_holder_asked && declined.contains(&block.hash) {
                *self.declined_rounds.entry(block.hash.clone()).or_default() += 1;
            }
        }
    }

    fn verdict(&self, still_missing: &[BlockInfo]) -> PrefetchVerdict {
        let mut verdict = PrefetchVerdict::default();
        for block in still_missing {
            let declined = self.declined_rounds.get(&block.hash).copied().unwrap_or(0);
            if declined >= self.rounds_required {
                verdict.unobtainable.insert(block.hash.clone());
            } else {
                verdict.unresolved.insert(block.hash.clone());
            }
        }
        verdict
    }
}

/// Makes every block of `required` (deduplicated by the caller) present,
/// group-provenanced and verified in the local block store, fetching what
/// is missing from connected peers, and reports what could not be.
///
/// `Err` is a local failure (storage, index), never a peer's answer.
pub(crate) async fn prefetch_rewind_content(
    state: &Arc<DaemonState>,
    group_id: &str,
    required: &[BlockInfo],
) -> Result<PrefetchVerdict, SyncError> {
    let mut verified = HashSet::new();
    let mut evidence = DeclineEvidence::default();
    let mut offline = Vec::new();
    for round in 0..ASK_ROUNDS {
        let missing = not_verified_locally(state, group_id, required, &mut verified).await?;
        if missing.is_empty() {
            return Ok(PrefetchVerdict::default());
        }
        if round > 0 {
            tokio::time::sleep(PeerSyncSession::not_found_retry_delay()).await;
        }
        let holders = content_holders(state, group_id);
        let candidates = candidate_sessions(state, group_id);
        offline = match &holders {
            ContentHolders::Known(others) => others
                .iter()
                .filter(|holder| !candidates.iter().any(|(id, _)| id == *holder))
                .cloned()
                .collect(),
            ContentHolders::Unknown => Vec::new(),
        };
        let every_holder_asked = matches!(holders, ContentHolders::Known(_)) && offline.is_empty();
        let (dispatched, stalled) =
            dispatch_until_stalled(state, group_id, &missing, &candidates).await?;
        // With nobody to ask, the only way every holder declined is that
        // there is no other holder at all.
        let declined = if candidates.is_empty() {
            missing.iter().map(|block| block.hash.clone()).collect()
        } else {
            dispatched.declined_everywhere
        };
        evidence.record_round(&missing, &declined, every_holder_asked);
        if stalled {
            break;
        }
    }
    let still_missing = not_verified_locally(state, group_id, required, &mut verified).await?;
    let mut verdict = evidence.verdict(&still_missing);
    if !verdict.unresolved.is_empty() {
        offline.sort();
        verdict.offline = offline;
    }
    Ok(verdict)
}

/// One dispatch of `missing` to `candidates`, stopped (and drained) once no
/// block has completed within the stall budget. Returns whether it stalled.
async fn dispatch_until_stalled(
    state: &Arc<DaemonState>,
    group_id: &str,
    missing: &[BlockInfo],
    candidates: &[(String, Arc<PeerSyncSession>)],
) -> Result<(Dispatched, bool), SyncError> {
    if candidates.is_empty() {
        return Ok((
            Dispatched { remaining: missing.to_vec(), declined_everywhere: HashSet::new() },
            false,
        ));
    }
    let largest = missing.iter().map(|block| block.size as u64).max().unwrap_or(0);
    let stall = Arc::new(HydrationStallTracker::new(
        PeerSyncSession::fetch_response_timeout_for(largest) * 2 + STALL_BUDGET_MARGIN,
    ));
    let bytes_total: u64 = missing.iter().map(|block| block.size as u64).sum();
    let _progress = state.telemetry.begin_transfer(
        group_id,
        REWIND_PREFETCH_LABEL,
        bytes_total,
        missing.len() as u64,
    );
    let stop = LaneStop::new();
    let dispatch = fetch_blocks_from_sessions(
        group_id,
        REWIND_PREFETCH_LABEL,
        missing.to_vec(),
        candidates,
        state.block_store.clone(),
        state.replica_coordinator.clone(),
        state.telemetry.transfer_progress_handle(),
        state.telemetry.recent_errors_handle(),
        Some(stall.clone()),
        stop.clone(),
    );
    tokio::pin!(dispatch);
    let mut stalled = false;
    loop {
        tokio::select! {
            dispatched = &mut dispatch => return Ok((dispatched?, stalled)),
            _ = tokio::time::sleep(STALL_CHECK_INTERVAL), if !stalled => {
                if stall.is_stalled() {
                    // Stop taking work and keep awaiting the call: it
                    // returns once every lane has drained its writes.
                    stalled = true;
                    stop.stop();
                }
            }
        }
    }
}

/// The blocks of `required` not yet known good locally, after checking
/// every one not already in `verified` (and adding the good ones to it).
/// Good means: present, recorded as obtained through this group, and its
/// stored bytes read back to the length and hash the block names. One full
/// read of each block, under the guard that keeps a deletion pass from
/// taking a block while it is read.
async fn not_verified_locally(
    state: &Arc<DaemonState>,
    group_id: &str,
    required: &[BlockInfo],
    verified: &mut HashSet<Vec<u8>>,
) -> Result<Vec<BlockInfo>, SyncError> {
    let unchecked: Vec<BlockInfo> =
        required.iter().filter(|block| !verified.contains(&block.hash)).cloned().collect();
    if unchecked.is_empty() {
        return Ok(Vec::new());
    }
    let store = state.block_store.clone();
    let coordinator = state.replica_coordinator.clone();
    let group_id = group_id.to_string();
    let (good, missing) = tokio::task::spawn_blocking(move || {
        let hex: Vec<String> = unchecked.iter().map(|block| hex::encode(&block.hash)).collect();
        let present = store.present_blocks(&hex)?;
        let hashes: Vec<Vec<u8>> = unchecked.iter().map(|block| block.hash.clone()).collect();
        let provenanced =
            coordinator.sqlite().dag_group_has_block_provenance_batch(&group_id, &hashes)?;
        let _no_block_deletion = coordinator.block_liveness_gate().begin_reference_write_barging();
        let _reads = yadorilink_local_storage::io_diag::attribute_reads(
            yadorilink_local_storage::io_diag::ReadReason::Validate,
        );
        let mut good = Vec::new();
        let mut missing = Vec::new();
        for ((block, hex), present) in unchecked.into_iter().zip(hex).zip(present) {
            let intact = present
                && provenanced.contains(&block.hash)
                && store.get(&hex).is_ok_and(|bytes| bytes.len() == block.size as usize);
            if intact {
                good.push(block.hash);
            } else {
                missing.push(block);
            }
        }
        Ok::<_, SyncError>((good, missing))
    })
    .await
    .map_err(|error| SyncError::CorruptState(format!("rewind content check failed: {error}")))??;
    verified.extend(good);
    Ok(missing)
}

/// Bytes the still-missing blocks of `required` would add to the block
/// store, judged from presence and provenance only (no reads). For an
/// early, cheap disk-space refusal before anything is fetched.
pub(crate) fn missing_bytes_estimate(
    state: &DaemonState,
    group_id: &str,
    required: &[BlockInfo],
) -> Result<u64, SyncError> {
    let hex: Vec<String> = required.iter().map(|block| hex::encode(&block.hash)).collect();
    let present = state.block_store.present_blocks(&hex)?;
    let hashes: Vec<Vec<u8>> = required.iter().map(|block| block.hash.clone()).collect();
    let provenanced = state
        .replica_coordinator
        .sqlite()
        .dag_group_has_block_provenance_batch(group_id, &hashes)?;
    Ok(required
        .iter()
        .zip(present)
        .filter(|(block, present)| !present || !provenanced.contains(&block.hash))
        .map(|(block, _)| block.size as u64)
        .sum())
}

#[cfg(test)]
mod tests;
