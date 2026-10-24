//! Caps glibc malloc arenas at startup.
//!
//! glibc gives every thread that contends on the allocator its own arena and
//! keeps freed memory inside it. A daemon with a multi-threaded runtime plus a
//! blocking pool and periodic scan passes ends up holding hundreds of MiB of
//! free but retained heap (a 10k-file idle daemon grew from 76 to 390 MiB, a
//! 100k one to 2.7 GB, while the same workload with two arenas stayed at
//! 116-140 MiB). The cap must be set before the runtime starts its threads, so
//! every install path (systemd, Docker, manual) gets it without an
//! environment variable.

/// Arena count the daemon asks for.
pub const ARENA_MAX: i32 = 2;

/// What startup did about the arena cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaCap {
    /// `mallopt(M_ARENA_MAX, n)` succeeded.
    Applied(i32),
    /// The operator set `MALLOC_ARENA_MAX`; glibc already honours it.
    OperatorSet,
    /// `mallopt` refused the value.
    Failed,
    /// Not glibc (macOS, Windows, musl): nothing to cap.
    NotApplicable,
}

/// Decides what to do given the `MALLOC_ARENA_MAX` environment value.
pub fn plan(env_value: Option<&std::ffi::OsStr>) -> Option<i32> {
    env_value.is_none().then_some(ARENA_MAX)
}

/// Caps arenas unless the operator already set `MALLOC_ARENA_MAX` (`env_value` is its value, which
/// the binary's `main` reads). Call before any thread is spawned.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn cap_arenas(env_value: Option<&std::ffi::OsStr>) -> ArenaCap {
    let Some(n) = plan(env_value) else {
        return ArenaCap::OperatorSet;
    };
    // SAFETY: mallopt only adjusts allocator tunables and is called before
    // the process is multi-threaded.
    if unsafe { libc::mallopt(libc::M_ARENA_MAX, n) } == 1 {
        ArenaCap::Applied(n)
    } else {
        ArenaCap::Failed
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn cap_arenas(_env_value: Option<&std::ffi::OsStr>) -> ArenaCap {
    ArenaCap::NotApplicable
}

/// Logs the startup outcome once the logger exists.
pub fn log(cap: ArenaCap) {
    match cap {
        ArenaCap::Applied(n) => tracing::info!(arena_max = n, "malloc arenas capped"),
        ArenaCap::OperatorSet => tracing::info!("malloc arenas: MALLOC_ARENA_MAX set by operator"),
        ArenaCap::Failed => tracing::warn!("could not cap malloc arenas"),
        ArenaCap::NotApplicable => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_value_wins() {
        assert_eq!(plan(None), Some(ARENA_MAX));
        assert_eq!(plan(Some(std::ffi::OsStr::new("4"))), None);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn mallopt_accepts_the_cap() {
        // Skip when the harness environment already pins it.
        let pinned = std::env::var_os("MALLOC_ARENA_MAX");
        if pinned.is_some() {
            assert_eq!(cap_arenas(pinned.as_deref()), ArenaCap::OperatorSet);
        } else {
            assert_eq!(cap_arenas(None), ArenaCap::Applied(ARENA_MAX));
        }
    }
}
