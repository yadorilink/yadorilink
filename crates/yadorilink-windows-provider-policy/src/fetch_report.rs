//! What a fetch tells the operating system besides the bytes: how far it is, and why it failed.
//!
//! Both are decided here from the daemon's typed answers, without any Win32 call, so the rules
//! run (and are tested) on every platform. The Windows host turns the results into
//! `CfReportProviderProgress` and a completion status.

use std::sync::atomic::{AtomicU64, Ordering};

use yadorilink_ipc_proto::shellipc::MaterializeFailure;

/// Why a fetch failed, as far as the operating system is told. Each kind has its own completion
/// status, so Explorer and applications can tell a full disk from an unreachable device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchFailure {
    /// The volume has no room for the bytes.
    LowDisk,
    /// No reachable device has the bytes (offline, or the peers that have them are away).
    Unreachable,
    /// The version the placeholder stands for is no longer available: it changed or is gone.
    VersionUnavailable,
    /// The reader gave up; the request was cancelled.
    Cancelled,
    /// Anything else, including the daemon not answering.
    Other,
}

impl FetchFailure {
    /// The kind for the `failure` code of a refused materialization (`0`: none given).
    pub fn from_wire(code: i32) -> Self {
        match MaterializeFailure::try_from(code) {
            Ok(MaterializeFailure::LowDisk) => Self::LowDisk,
            Ok(MaterializeFailure::Unobtainable) => Self::Unreachable,
            Ok(
                MaterializeFailure::VersionOutOfDate
                | MaterializeFailure::NotFound
                | MaterializeFailure::PublicationPending,
            ) => Self::VersionUnavailable,
            Ok(MaterializeFailure::Cancelled) => Self::Cancelled,
            _ => Self::Other,
        }
    }
}

/// The progress of serving one range of a file, in bytes of that range, as the operating system
/// is told it.
///
/// Truthful by construction: a byte counts once the daemon verified it (a window is handed over
/// only after that) or once it was handed over, and the reported completion stays below the total
/// until the caller says the whole range was handed over, because the reader is unblocked by the
/// last transfer and not by a report. Reports never go backwards, and one that would repeat the
/// last is dropped.
pub struct RangeProgress {
    first: u64,
    end: u64,
    last: AtomicU64,
}

impl RangeProgress {
    /// Progress of the range `[first, end)`.
    pub fn new(first: u64, end: u64) -> Self {
        Self { first, end, last: AtomicU64::new(0) }
    }

    /// The bytes of the range.
    pub fn total(&self) -> u64 {
        self.end.saturating_sub(self.first)
    }

    /// `(total, completed)` to report while the daemon has verified `verified` of `of` bytes of
    /// the window `[start, end)` of this range, or `None` when there is nothing new to say. The
    /// daemon's units are the bytes it assembles for the window (the blocks that cover it), which
    /// are scaled onto the window.
    pub fn report(&self, start: u64, end: u64, verified: u64, of: u64) -> Option<(u64, u64)> {
        let total = self.total();
        if total == 0 || start < self.first || end <= start {
            return None;
        }
        let window = end - start;
        let in_window = if of == 0 {
            0
        } else {
            u64::try_from(u128::from(verified.min(of)) * u128::from(window) / u128::from(of))
                .unwrap_or(window)
        };
        let completed = (start - self.first).saturating_add(in_window).min(total - 1);
        let previous = self.last.fetch_max(completed, Ordering::Relaxed);
        (completed > previous).then_some((total, completed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    fn code(failure: MaterializeFailure) -> i32 {
        failure as i32
    }

    /// The typed refusals the user can act on keep their meaning; everything else is generic.
    #[test]
    fn typed_refusals_map_to_their_own_kind() {
        use MaterializeFailure as F;
        assert_eq!(FetchFailure::from_wire(code(F::LowDisk)), FetchFailure::LowDisk);
        assert_eq!(FetchFailure::from_wire(code(F::Unobtainable)), FetchFailure::Unreachable);
        for failure in [F::VersionOutOfDate, F::NotFound, F::PublicationPending] {
            assert_eq!(FetchFailure::from_wire(code(failure)), FetchFailure::VersionUnavailable);
        }
        assert_eq!(FetchFailure::from_wire(code(F::Cancelled)), FetchFailure::Cancelled);
        for failure in [F::None, F::NotReady, F::RangeNotSatisfiable] {
            assert_eq!(FetchFailure::from_wire(code(failure)), FetchFailure::Other);
        }
        assert_eq!(FetchFailure::from_wire(9999), FetchFailure::Other);
    }

    /// Windows already handed over count in full, the window being assembled by how far the
    /// daemon is, scaled from the daemon's units onto the window.
    #[test]
    fn progress_adds_the_current_window_to_what_was_handed_over() {
        let progress = RangeProgress::new(0, 32 * MIB);
        assert_eq!(progress.total(), 32 * MIB);
        // The third 8 MiB window; the daemon assembles 12 MiB of blocks for it, 3 MiB are done.
        assert_eq!(
            progress.report(16 * MIB, 24 * MIB, 3 * MIB, 12 * MIB),
            Some((32 * MIB, 16 * MIB + 2 * MIB))
        );
    }

    /// A range that starts inside the file counts from its own start.
    #[test]
    fn progress_counts_from_the_start_of_the_range() {
        let progress = RangeProgress::new(100 * MIB, 108 * MIB);
        assert_eq!(progress.report(100 * MIB, 108 * MIB, 4, 8), Some((8 * MIB, 4 * MIB)));
    }

    /// Never complete before the caller has handed over the last byte, however far the daemon
    /// says it is, and never backwards or repeated.
    #[test]
    fn progress_is_not_complete_monotonic_and_not_repeated() {
        let progress = RangeProgress::new(0, 16 * MIB);
        let mut last = 0;
        for (start, end, verified) in [
            (0, 8 * MIB, 1),
            (0, 8 * MIB, 4),
            (0, 8 * MIB, 8),
            (8 * MIB, 16 * MIB, 2),
            (8 * MIB, 16 * MIB, 8),
        ] {
            if let Some((total, completed)) = progress.report(start, end, verified * MIB, 8 * MIB) {
                assert_eq!(total, 16 * MIB);
                assert!(completed > last && completed < total, "{completed} after {last}");
                last = completed;
            }
        }
        assert_eq!(last, 16 * MIB - 1);
        // The same or an older reading says nothing new.
        assert_eq!(progress.report(8 * MIB, 16 * MIB, 8 * MIB, 8 * MIB), None);
        assert_eq!(progress.report(0, 8 * MIB, 8 * MIB, 8 * MIB), None);
    }

    /// Nothing to report for an empty range or a window outside it, or before the daemon knows
    /// its own total.
    #[test]
    fn progress_ignores_what_it_cannot_place() {
        assert_eq!(RangeProgress::new(5, 5).report(5, 5, 0, 0), None);
        let progress = RangeProgress::new(MIB, 9 * MIB);
        assert_eq!(progress.report(0, MIB, 1, 1), None);
        assert_eq!(progress.report(MIB, 9 * MIB, 0, 0), None);
    }
}
