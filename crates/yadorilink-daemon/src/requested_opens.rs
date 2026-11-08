//! Opens the user is waiting on that have no `Hydrating` row yet: an On-Demand provider open
//! queued for a daemon-wide assembly slot is still a placeholder on disk, but it is requested
//! content. The daemon counts them per group so `LinkStatus.requested_content_count` can say so.
//!
//! The unit counted is a file, not a request: a whole-file open is served in several windows, each
//! its own request, and they must not read as several files being downloaded. A file whose last
//! request just ended after handing bytes over keeps counting for [`LINGER`]: the host has not yet
//! said they are on this computer, and a count that dropped to nothing for that moment showed a
//! finished-looking folder that was not finished. A request that failed or was cancelled handed
//! nothing over and stops counting at once.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a file keeps counting as requested after its last request ended: the gap between the
/// windows of one open, and the time the host takes to report the file as downloaded.
pub(crate) const LINGER: Duration = Duration::from_secs(3);

type Key = (String, Vec<u8>);

#[derive(Default)]
struct Inner {
    /// Requests in flight per file.
    open: HashMap<Key, u64>,
    /// Files with a request in flight that has handed bytes over: when the last request of the
    /// file ends it keeps counting for a moment, whatever became of that last request.
    served: HashSet<Key>,
    /// Files whose last request ended, with the time they stop counting.
    lingering: HashMap<Key, Instant>,
}

#[derive(Default)]
pub struct RequestedOpens {
    inner: Mutex<Inner>,
}

/// Counts one request from `RequestedOpens::begin` until it is dropped (finished, failed or
/// cancelled).
pub(crate) struct OpenGuard {
    opens: Arc<RequestedOpens>,
    key: Key,
}

impl RequestedOpens {
    pub(crate) fn begin(self: &Arc<Self>, group_id: &str, item: &[u8]) -> OpenGuard {
        let key = (group_id.to_owned(), item.to_vec());
        let mut inner = self.lock();
        inner.lingering.retain(|_, until| *until > Instant::now());
        *inner.open.entry(key.clone()).or_insert(0) += 1;
        drop(inner);
        OpenGuard { opens: self.clone(), key }
    }

    /// The files of `group_id` with a request in flight or one that ended a moment ago.
    pub(crate) fn count(&self, group_id: &str) -> u64 {
        self.count_at(group_id, Instant::now())
    }

    pub(crate) fn count_at(&self, group_id: &str, now: Instant) -> u64 {
        self.count_unless_held_at(group_id, now, |_| false)
    }

    /// [`Self::count`], leaving out the files that only linger and that `held` says the host already
    /// reports as on this computer: such a file would otherwise be both held and downloading for the
    /// length of the linger. A file with a request in flight always counts, whatever the host
    /// last reported of an earlier copy of it.
    pub(crate) fn count_unless_held(&self, group_id: &str, held: impl Fn(&[u8]) -> bool) -> u64 {
        self.count_unless_held_at(group_id, Instant::now(), held)
    }

    fn count_unless_held_at(
        &self,
        group_id: &str,
        now: Instant,
        held: impl Fn(&[u8]) -> bool,
    ) -> u64 {
        let mut inner = self.lock();
        inner.lingering.retain(|_, until| *until > now);
        let open = inner.open.keys().filter(|key| key.0 == group_id);
        let lingering = inner
            .lingering
            .keys()
            .filter(|key| key.0 == group_id && !inner.open.contains_key(*key) && !held(&key.1));
        (open.count() + lingering.count()) as u64
    }

    #[cfg(test)]
    pub(crate) fn lingering_len(&self) -> usize {
        self.lock().lingering.len()
    }

    /// Makes every lingering entry `by` older, as if that much time had passed.
    #[cfg(test)]
    pub(crate) fn age_lingering(&self, by: Duration) {
        for until in self.lock().lingering.values_mut() {
            *until = until.checked_sub(by).expect("a monotonic clock far from its origin");
        }
    }

    #[cfg(test)]
    pub(crate) fn end_lingering(&self) {
        self.lock().lingering.clear();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl OpenGuard {
    /// This request handed bytes over: the file keeps counting for [`LINGER`] after its last
    /// request ends.
    pub(crate) fn served(&mut self) {
        self.opens.lock().served.insert(self.key.clone());
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        let mut inner = self.opens.lock();
        let now = Instant::now();
        inner.lingering.retain(|_, until| *until > now);
        if let Some(n) = inner.open.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                inner.open.remove(&self.key);
                if inner.served.remove(&self.key) {
                    inner.lingering.insert(self.key.clone(), now + LINGER);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn served(opens: &Arc<RequestedOpens>, item: &[u8]) -> OpenGuard {
        let mut guard = opens.begin("g", item);
        guard.served();
        guard
    }

    #[test]
    fn counts_files_with_a_request_in_flight() {
        let opens = Arc::new(RequestedOpens::default());
        let a = served(&opens, b"a");
        let b = served(&opens, b"b");
        assert_eq!(opens.count("g"), 2);
        drop(a);
        // `a` just ended: it still counts for a moment (see the next tests), `b` is in flight.
        opens.end_lingering();
        assert_eq!(opens.count("g"), 1);
        drop(b);
        opens.end_lingering();
        assert_eq!(opens.count("g"), 0);
        assert_eq!(opens.count("other"), 0);
    }

    /// The windows of one whole-file open are separate requests of the same file: they are one file,
    /// and the gap between two of them does not read as nothing being downloaded.
    #[test]
    fn the_windows_of_one_file_are_one_file_and_the_gap_between_them_is_not_idle() {
        let opens = Arc::new(RequestedOpens::default());
        let first = served(&opens, b"big");
        let second = served(&opens, b"big");
        assert_eq!(opens.count("g"), 1, "two requests for one file counted as two files");
        drop(first);
        assert_eq!(opens.count("g"), 1);
        drop(second);
        assert_eq!(opens.count("g"), 1, "the gap after the last window counted as idle");
        let _next = opens.begin("g", b"big");
        assert_eq!(opens.count("g"), 1, "a lingering file and its next request counted twice");
    }

    #[test]
    fn a_finished_file_stops_counting_after_the_linger_not_before() {
        let opens = Arc::new(RequestedOpens::default());
        drop(served(&opens, b"big"));
        let now = Instant::now();
        assert_eq!(opens.count_at("g", now + LINGER - Duration::from_millis(100)), 1);
        assert_eq!(opens.count_at("g", now + LINGER + Duration::from_secs(1)), 0);
        // And it is gone, not merely hidden.
        assert_eq!(opens.count_at("g", now), 0);
    }

    /// A request that failed or was cancelled handed nothing over: it stops counting at once.
    #[test]
    fn a_failed_or_cancelled_open_does_not_linger() {
        let opens = Arc::new(RequestedOpens::default());
        let failed = opens.begin("g", b"failed");
        assert_eq!(opens.count("g"), 1);
        drop(failed);
        assert_eq!(opens.count("g"), 0, "a request that served nothing kept counting");
        assert_eq!(opens.lingering_len(), 0);
    }

    /// Entries that have expired are dropped as requests come and go, not only when the count is read:
    /// a daemon that is never asked for its status does not keep every file it ever served.
    #[test]
    fn expired_entries_are_dropped_without_a_status_read() {
        let opens = Arc::new(RequestedOpens::default());
        for n in 0..20u8 {
            drop(served(&opens, &[n]));
        }
        assert_eq!(opens.lingering_len(), 20);
        opens.age_lingering(LINGER + Duration::from_secs(1));
        drop(served(&opens, b"later"));
        assert_eq!(opens.lingering_len(), 1, "expired entries stayed in the map");
    }

    /// A request that failed after another one of the same file served bytes does not undo the linger
    /// the served one earned, and a failed next window does not end it either.
    #[test]
    fn a_served_window_survives_an_overlapping_or_failed_next_request() {
        let opens = Arc::new(RequestedOpens::default());
        let mut good = opens.begin("g", b"big");
        let bad = opens.begin("g", b"big");
        good.served();
        drop(good);
        drop(bad); // the last to end failed
        assert_eq!(opens.count("g"), 1, "the failed last request erased the served one's linger");

        let mut window = opens.begin("g", b"next");
        window.served();
        drop(window);
        let failed_next = opens.begin("g", b"next");
        drop(failed_next);
        assert_eq!(opens.count("g"), 2, "a failed next window ended the linger");
    }

    /// A download in flight always counts, whatever the host last reported of an earlier copy.
    #[test]
    fn an_open_in_flight_is_not_hidden_by_an_earlier_held_copy() {
        let opens = Arc::new(RequestedOpens::default());
        let _open = opens.begin("g", b"updated");
        assert_eq!(opens.count_unless_held("g", |_| true), 1);
    }

    /// The status leaves out the files the host already reports as on this computer.
    #[test]
    fn files_the_host_reports_as_held_are_left_out_of_the_count() {
        let opens = Arc::new(RequestedOpens::default());
        drop(served(&opens, b"done"));
        let _going = opens.begin("g", b"going");
        assert_eq!(opens.count("g"), 2);
        assert_eq!(opens.count_unless_held("g", |item| item == b"done"), 1);
    }
}
