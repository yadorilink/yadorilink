//! Measurement-only counters for `VersionPresent` custody-evidence queries.
//!
//! Exists to split one measured number in two. Delivering the same 2000
//! new files to a larger folder was seen to read far more blocks than the
//! new work needs, and every one of those extra reads was attributed to
//! `holds_version_durably` proving custody. That total is the product of
//! two things with different fixes: how many custody queries arrive, and
//! how much each one verifies. A block-read count alone cannot separate
//! "peers ask about versions they already settled" from "each answer is
//! expensive", and those call for changes in completely different places.
//!
//! Armed by the same switch as `io_diag` (and therefore by
//! `YADORILINK_DIAGNOSTIC_IO_COUNTERS=1`), so a production daemon records
//! nothing and pays one relaxed atomic load per query.
//!
//! `unique_versions` is tracked with a set that is never pruned. That is
//! acceptable for a benchmark process answering thousands of queries and
//! is not acceptable for a long-lived production daemon -- which is
//! another reason this stays behind the diagnostic switch.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use yadorilink_local_storage::io_diag;

static REQUESTS: AtomicU64 = AtomicU64::new(0);
static REQUESTS_FOR_HANDOFF: AtomicU64 = AtomicU64::new(0);
static BLOCKS_VERIFIED: AtomicU64 = AtomicU64::new(0);

/// Group-durability-summary RPCs this process has ISSUED.
///
/// Counted on the asking side, unlike every other counter in this file, and
/// the asymmetry is the point. The others measure work a query costs its
/// responder -- block reads, blocks verified -- so they have to be read on
/// the peer that answers. This one measures the fan-out a background cycle
/// performs, which is a property of the asker and of nothing else.
///
/// Reading it on the responder would also be unusable: a cycle stops at the
/// first peer that corroborates and drops the rest, so how many of the
/// requests it sent had been *processed* by the time the counter was read is
/// a race. How many it sent is not.
static SUMMARY_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Every `(group, path, version_hash)` a custody query has ever named in
/// this process. `requests - unique` is how much of the load is re-asking.
///
/// Keyed by group as well as path: `holds_version_durably` evaluates
/// custody per `folder_group_id`, so two groups holding the same relative
/// path at the same version are answering two independent questions.
/// Merging them would report a first-ever query in one group as a repeat
/// of the other's -- which is exactly the quantity this counter exists to
/// measure, reported wrong.
/// `(group_id, file_path, version_hash)` -- the identity a custody query
/// names. Aliased because the nested generic is otherwise unreadable at the
/// two places it appears.
type SeenVersion = (String, String, Vec<u8>);

static SEEN: Mutex<Option<HashSet<SeenVersion>>> = Mutex::new(None);

/// Records one answered `VersionPresent` query.
///
/// `blocks` is what the query asked about, which is what
/// `holds_version_durably` will verify in full if it gets past its earlier
/// checks -- so `blocks_verified / requests` is the per-request
/// verification volume, and comparing it with the custody block-read count
/// says whether queries are being answered before reaching step 6.
pub fn record_query(
    group_id: &str,
    file_path: &str,
    version_hash: &[u8],
    for_handoff: bool,
    blocks: usize,
) {
    if !io_diag::enabled() {
        return;
    }
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    if for_handoff {
        REQUESTS_FOR_HANDOFF.fetch_add(1, Ordering::Relaxed);
    }
    BLOCKS_VERIFIED.fetch_add(blocks as u64, Ordering::Relaxed);
    if let Ok(mut guard) = SEEN.lock() {
        guard.get_or_insert_with(HashSet::new).insert((
            group_id.to_string(),
            file_path.to_string(),
            version_hash.to_vec(),
        ));
    }
}

/// Records one group-durability-summary RPC being issued.
///
/// Called before the round-trip, not after, so the count is what the cycle
/// asked for rather than what happened to come back.
pub fn record_summary_request() {
    if !io_diag::enabled() {
        return;
    }
    SUMMARY_REQUESTS.fetch_add(1, Ordering::Relaxed);
}

/// One reading of the counters. Not atomic across fields; take it when the
/// measured work is finished rather than while it is running.
#[derive(Clone, Copy, Debug, Default)]
pub struct CustodyStats {
    pub requests: u64,
    pub requests_for_handoff: u64,
    pub unique_versions: u64,
    pub blocks_verified: u64,
    /// Group-level summary RPCs issued -- see `SUMMARY_REQUESTS`. Expected
    /// to be one per candidate peer per cycle and independent of how many
    /// durability roots the group holds.
    pub summary_requests: u64,
}

pub fn stats() -> CustodyStats {
    CustodyStats {
        requests: REQUESTS.load(Ordering::Relaxed),
        requests_for_handoff: REQUESTS_FOR_HANDOFF.load(Ordering::Relaxed),
        unique_versions: SEEN
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|s| s.len() as u64))
            .unwrap_or(0),
        blocks_verified: BLOCKS_VERIFIED.load(Ordering::Relaxed),
        summary_requests: SUMMARY_REQUESTS.load(Ordering::Relaxed),
    }
}
