//! Raises the soft open-file limit at startup.
//!
//! The default soft limit under launchd and most shells is 256. A receive can
//! hold up to 48 assembling files (temp file plus a directory handle each),
//! the block store retains up to 128 segment readers, and databases, sockets
//! and the watcher need theirs on top; 256 would fail writes with EMFILE.

/// The soft limit the daemon asks for, capped by the hard limit.
pub const WANTED_SOFT_NOFILE: u64 = 4096;

#[cfg(unix)]
type Limit = libc::rlim_t;
#[cfg(not(unix))]
type Limit = u64;

/// The lowest effective soft limit the daemon is documented to run with.
/// Measured use is flat in the number of synced files (about 30 descriptors per
/// device at idle and under a burst); the receive path alone can add up to ~100
/// (48 assembling files plus their directory handles) and the segment reader
/// cache up to 128, so 512 leaves headroom and anything lower risks EMFILE.
pub const MIN_SOFT_NOFILE: u64 = 512;

/// Whether `soft` is below [`MIN_SOFT_NOFILE`].
pub fn below_minimum(soft: Limit) -> bool {
    soft < Limit::from(MIN_SOFT_NOFILE as u32)
}

/// The soft limit to set given the current pair, or `None` when it is already
/// high enough.
pub fn target_soft_limit(soft: Limit, hard: Limit) -> Option<Limit> {
    let target = Limit::from(WANTED_SOFT_NOFILE as u32).min(hard);
    (soft < target).then_some(target)
}

/// Raises the soft `RLIMIT_NOFILE` when it is below [`WANTED_SOFT_NOFILE`] and
/// logs the effective limit once. Failure is logged and not fatal.
#[cfg(unix)]
pub fn raise_nofile_soft_limit() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `lim` is a valid, writable rlimit for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        tracing::warn!(error = %std::io::Error::last_os_error(), "could not read the open-file limit");
        return;
    }
    if let Some(target) = target_soft_limit(lim.rlim_cur, lim.rlim_max) {
        let wanted = libc::rlimit { rlim_cur: target, rlim_max: lim.rlim_max };
        // SAFETY: `wanted` is a valid rlimit; only the soft limit changes.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) } != 0 {
            tracing::warn!(
                error = %std::io::Error::last_os_error(),
                soft = lim.rlim_cur,
                "could not raise the open-file limit"
            );
        }
    }
    // SAFETY: as above.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
        tracing::info!(soft = lim.rlim_cur, hard = lim.rlim_max, "open-file limit");
        if below_minimum(lim.rlim_cur) {
            tracing::warn!(
                soft = lim.rlim_cur,
                hard = lim.rlim_max,
                minimum = MIN_SOFT_NOFILE,
                "open-file limit is below the documented minimum; file operations may fail with \
                 'Too many open files'. Raise the process's open-file limit \
                 (for example `ulimit -n`, or LimitNOFILE= in the service unit)"
            );
        }
    }
}

#[cfg(not(unix))]
pub fn raise_nofile_soft_limit() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raises_only_when_lower_and_never_above_the_hard_limit() {
        assert_eq!(target_soft_limit(256, 1_000_000), Some(4096));
        assert_eq!(target_soft_limit(256, 1024), Some(1024));
        assert_eq!(target_soft_limit(4096, 1_000_000), None);
        assert_eq!(target_soft_limit(10_000, 1_000_000), None);
        assert_eq!(target_soft_limit(1024, 1024), None);
    }

    #[test]
    fn warns_only_below_the_documented_minimum() {
        assert!(below_minimum(256));
        assert!(below_minimum(511));
        assert!(!below_minimum(512));
        assert!(!below_minimum(4096));
    }
}
