//! Process-wide measurement switches of the capture path.
//!
//! Both are off unless the process arms them. The desktop daemon maps its diagnostic environment
//! variables onto them once at startup; an embedded host never calls these setters, so it always
//! runs the production behaviour and nothing here reads the process environment.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static FORCE_FIXED_CHUNKING: AtomicBool = AtomicBool::new(false);
static SNAPSHOT_DELAY_MS: AtomicU64 = AtomicU64::new(0);

/// Routes a file that would take the content-defined chunking branch through fixed-size chunking
/// instead (same hash-once/bulk-commit pipeline, only the boundary algorithm differs). Isolates
/// whether the rolling-hash cost dominates `capture -> chunk EOF`. Not a chunking-policy change.
pub fn set_force_fixed_chunking(on: bool) {
    FORCE_FIXED_CHUNKING.store(on, Ordering::Relaxed);
}

pub(crate) fn force_fixed_chunking() -> bool {
    FORCE_FIXED_CHUNKING.load(Ordering::Relaxed)
}

/// Holds every reconciliation pass for `delay_ms` after its snapshot (`0` is off): a measurement
/// seam that widens the window in which two passes of one group can overlap.
pub fn set_snapshot_delay_ms(delay_ms: u64) {
    SNAPSHOT_DELAY_MS.store(delay_ms, Ordering::Relaxed);
}

pub(crate) fn snapshot_delay_ms() -> u64 {
    SNAPSHOT_DELAY_MS.load(Ordering::Relaxed)
}
