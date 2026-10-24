//! A process-wide admission limit on receive file assemblies.
//!
//! The per-pass write concurrency bounds one group's settle; the engine runs
//! several groups at once, and hydration writes files outside any pass. This
//! gate bounds the sum, so the number of open temp files does not grow with
//! the number of groups.
//!
//! File descriptor budget. One in-flight assembly holds one temp-file
//! descriptor for the whole write, plus at most one parent-directory handle
//! while the temp is fsynced and published (a short tail, so counted as one
//! more): at most 2 per permit, 96 at the desktop default of 48. The shared block
//! store retains up to 128 segment readers (16 in the embedded build, see
//! `EMBEDDED_CACHED_SEGMENT_READERS`) on top, which the assemblies read
//! through. That is about 224 descriptors before database connections,
//! sockets and the file watcher, which is why daemon startup also raises the
//! soft descriptor limit (see `fd_limit`).
//!
//! The gate belongs to one engine, so an embedded host with several engines in one process
//! multiplies it, against a soft limit it cannot raise (256 on iOS). The embedded build
//! (without `process-model`) therefore defaults to [`EMBEDDED_RECEIVE_WRITE_PERMITS`], 16
//! descriptors per engine, and a host that runs more engines or knows its limit sets
//! `EngineTuning::receive_write_permits` itself.
//!
//! Why a permit cannot deadlock. It is taken only around the assembly of one
//! file (blocks read from the local store into a temp file), a leaf step: the
//! holder never waits on a batch collector, the byte budget, a path lock or
//! another permit while holding it, and releases it when the temp file is
//! complete. An item waiting in a collector has therefore already given its
//! permit back; nothing that holds a permit needs anything a waiter holds.
//! The permit is moved into the blocking task, so it is released when the
//! task ends, including on cancellation of the awaiting future or a panic.

use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Concurrent receive file assemblies of one engine (the replica coordinator owns the
/// semaphore) in the desktop daemon.
pub(crate) const DESKTOP_RECEIVE_WRITE_PERMITS: usize = 48;

/// The default of an embedded engine: a mobile host's descriptor limit is small and shared by
/// every engine it runs.
pub(crate) const EMBEDDED_RECEIVE_WRITE_PERMITS: usize = 8;

/// What an engine with no setting gets.
pub(crate) const DEFAULT_RECEIVE_WRITE_PERMITS: usize = if cfg!(feature = "process-model") {
    DESKTOP_RECEIVE_WRITE_PERMITS
} else {
    EMBEDDED_RECEIVE_WRITE_PERMITS
};

/// Upper bound for the override: 2 descriptors per permit stays far below
/// the raised descriptor limit.
const MAX_RECEIVE_WRITE_PERMITS: usize = 256;

pub(crate) fn parse_permits(raw: Option<&str>) -> usize {
    raw.and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .map_or(DEFAULT_RECEIVE_WRITE_PERMITS, |n| n.min(MAX_RECEIVE_WRITE_PERMITS))
}

/// Waits for an assembly slot. Dropping the future while waiting leaks nothing.
pub(crate) async fn admit(gate: Arc<Semaphore>) -> OwnedSemaphorePermit {
    gate.acquire_owned().await.expect("the receive write gate is never closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    async fn one_writer(gate: Arc<Semaphore>, running: Arc<AtomicUsize>, peak: Arc<AtomicUsize>) {
        let permit = admit(gate).await;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let now = running.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(5));
            running.fetch_sub(1, Ordering::SeqCst);
        })
        .await
        .unwrap();
    }

    #[test]
    fn permits_default_and_clamp() {
        assert_eq!(parse_permits(None), DEFAULT_RECEIVE_WRITE_PERMITS);
        assert_eq!(parse_permits(Some("0")), DEFAULT_RECEIVE_WRITE_PERMITS);
        assert_eq!(parse_permits(Some("x")), DEFAULT_RECEIVE_WRITE_PERMITS);
        assert_eq!(parse_permits(Some("8")), 8);
        assert_eq!(parse_permits(Some("100000")), MAX_RECEIVE_WRITE_PERMITS);
        const _: () = assert!(DEFAULT_RECEIVE_WRITE_PERMITS <= MAX_RECEIVE_WRITE_PERMITS);
    }

    /// An engine of the embedded build gets a small descriptor budget, since a host shares one
    /// soft limit (256 on iOS) among all its engines; the desktop daemon keeps its own.
    #[test]
    fn the_embedded_default_budget_is_small_and_the_desktop_one_unchanged() {
        const _: () = assert!(EMBEDDED_RECEIVE_WRITE_PERMITS * 2 * 8 <= 256 / 2);
        let expected = if cfg!(feature = "process-model") {
            DESKTOP_RECEIVE_WRITE_PERMITS
        } else {
            EMBEDDED_RECEIVE_WRITE_PERMITS
        };
        assert_eq!(DEFAULT_RECEIVE_WRITE_PERMITS, expected);
        assert_eq!(DESKTOP_RECEIVE_WRITE_PERMITS, 48);
    }

    /// More writers than permits: at most N run at once, and all complete,
    /// including with N smaller than a pass's window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn writers_beyond_the_permits_are_admitted_at_most_n_at_a_time() {
        for n in [1usize, 3] {
            let gate = Arc::new(Semaphore::new(n));
            let running = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let mut tasks = Vec::new();
            for _ in 0..40 {
                let (gate, running, peak) = (gate.clone(), running.clone(), peak.clone());
                tasks.push(tokio::spawn(one_writer(gate, running, peak)));
            }
            tokio::time::timeout(std::time::Duration::from_secs(30), async {
                for t in tasks {
                    t.await.unwrap();
                }
            })
            .await
            .expect("all writers complete");
            assert!(
                peak.load(Ordering::SeqCst) <= n,
                "peak {} over {n}",
                peak.load(Ordering::SeqCst)
            );
            assert_eq!(gate.available_permits(), n, "every permit is returned");
        }
    }
}
