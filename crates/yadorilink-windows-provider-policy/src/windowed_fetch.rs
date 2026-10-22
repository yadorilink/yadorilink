//! Serving one fetch range of the operating system in bounded windows.
//!
//! The driver may ask for a whole large file at open (an antivirus scan reads it end to end), and
//! one daemon request for all of it cannot finish within a fixed timeout. The range is instead
//! cut into windows of [`WINDOW`] bytes: each window is one ranged request of the exact version
//! the placeholder stands for (the daemon fetches and verifies only the blocks covering it), and
//! each is handed to the operating system as soon as it is complete, in order, until the range is
//! done. A window that fails, a version that moved or a cancel stops the loop at once and leaves
//! the rest of the range undelivered.
//!
//! A ranged answer never makes an item present: the daemon records nothing for a window. When the
//! range is the whole file the operating system now holds every byte, which is exactly what a
//! whole-version request records, so the loop ends by asking for the whole version once more
//! ([`Window::complete`]); the daemon finds the blocks local. That request is what keeps
//! "present" tied to the daemon's own handoff evidence. It is asked only after the last window
//! was delivered, so a partial transfer never produces it.

use crate::provider_client::FetchTarget;

/// The bytes of one window. Large enough that the per-request cost (a connection, an fsynced
/// staging file) is small beside the transfer, small enough that the first bytes reach the
/// reader after a moment and one window always fits well inside a request timeout whatever the
/// size of the file. A multiple of the 4 KiB the driver requires of transferred ranges.
pub const WINDOW: u64 = 8 << 20;

/// What serving one window delivered.
pub struct Served {
    /// The offset of the next byte still to deliver. Past the window's end only when the daemon
    /// answered with the whole file (it predates ranged requests), whose bytes were delivered up
    /// to the end of the range.
    pub next: u64,
    /// The daemon answered a whole-version request (or, an old daemon, the whole file): it
    /// recorded the handoff itself.
    pub whole_version: bool,
}

/// The side effects of serving a range: asking the daemon and handing bytes to the system.
pub trait Window {
    /// The driver cancelled the range, or its pending request is otherwise gone.
    fn cancelled(&self) -> bool;
    /// Fetches `[start, end)` as `target` (`None`: the current whole file, when the version is
    /// not known) and delivers it, and everything up to `range_end` if the answer is the whole
    /// file. `Err` stops the range.
    fn serve(
        &mut self,
        target: Option<FetchTarget>,
        start: u64,
        end: u64,
        range_end: u64,
    ) -> Result<Served, String>;
    /// The whole file was delivered window by window: records the whole version with the daemon.
    fn complete(&mut self, version: [u8; 32]);
}

/// The window `[start, end)` that follows `next` in a range ending at `range_end`.
pub fn next_window(next: u64, range_end: u64) -> (u64, u64) {
    (next, next.saturating_add(WINDOW).min(range_end))
}

/// What to ask the daemon for `[start, end)` of a file of `size` bytes: the exact version, whole
/// when the window is the whole file (the daemon records that as handed over) and ranged
/// otherwise; `None` when the version is not known.
pub fn target_for(
    version: Option<[u8; 32]>,
    start: u64,
    end: u64,
    size: u64,
) -> Option<FetchTarget> {
    version.map(|version| FetchTarget {
        version,
        range: (start != 0 || end != size).then_some((start, end - start)),
    })
}

/// Serves `[*next, range_end)` of a file of `size` bytes whose placeholder stands for `version`
/// (`None`: not known, which is one request for the current whole file, as nothing could pin the
/// windows to one version). `*next` is always the first byte not delivered, also after an error.
pub fn serve_range<W: Window>(
    io: &mut W,
    version: Option<[u8; 32]>,
    size: u64,
    next: &mut u64,
    range_end: u64,
) -> Result<(), String> {
    let first = *next;
    let mut whole_version = false;
    while *next < range_end {
        if io.cancelled() {
            return Err("the request was cancelled".into());
        }
        let (start, end) =
            if version.is_some() { next_window(*next, range_end) } else { (*next, range_end) };
        let served = io.serve(target_for(version, start, end, size), start, end, range_end)?;
        if served.next <= start || served.next > range_end {
            return Err(format!("a window starting at {start} delivered up to {}", served.next));
        }
        *next = served.next;
        whole_version |= served.whole_version;
    }
    if let Some(version) = version {
        if first == 0 && range_end == size && !whole_version {
            if io.cancelled() {
                return Err("the request was cancelled".into());
            }
            io.complete(version);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    const VERSION: [u8; 32] = [7; 32];

    /// What the fake host saw, in order.
    #[derive(Debug, PartialEq)]
    enum Event {
        Served(u64, u64, bool),
        Completed,
    }

    struct Fake {
        events: Vec<Event>,
        /// Cancel once this many windows were served.
        cancel_after: Option<usize>,
        /// Fail the n-th window (0-based).
        fail_at: Option<usize>,
        /// Answer every window with the whole file, like a daemon without ranged requests.
        old_daemon: bool,
    }

    impl Fake {
        fn new() -> Self {
            Self { events: Vec::new(), cancel_after: None, fail_at: None, old_daemon: false }
        }

        fn served(&self) -> usize {
            self.events.iter().filter(|e| matches!(e, Event::Served(..))).count()
        }
    }

    impl Window for Fake {
        fn cancelled(&self) -> bool {
            self.cancel_after.is_some_and(|n| self.served() >= n)
        }

        fn serve(
            &mut self,
            target: Option<FetchTarget>,
            start: u64,
            end: u64,
            range_end: u64,
        ) -> Result<Served, String> {
            if self.fail_at == Some(self.served()) {
                return Err("the item changed since the placeholder was shown".into());
            }
            let ranged = target.is_some_and(|t| t.range.is_some());
            if let Some(range) = target.and_then(|t| t.range) {
                assert_eq!(range, (start, end - start), "the request names the window");
            }
            self.events.push(Event::Served(start, end, ranged));
            if self.old_daemon {
                return Ok(Served { next: range_end, whole_version: true });
            }
            Ok(Served { next: end, whole_version: !ranged })
        }

        fn complete(&mut self, version: [u8; 32]) {
            assert_eq!(version, VERSION);
            self.events.push(Event::Completed);
        }
    }

    fn run(
        io: &mut Fake,
        version: Option<[u8; 32]>,
        size: u64,
        from: u64,
        to: u64,
    ) -> (Result<(), String>, u64) {
        let mut next = from;
        let result = serve_range(io, version, size, &mut next, to);
        (result, next)
    }

    /// The windows tile the range exactly, in order, each bounded and 4 KiB aligned, whatever
    /// the size of the file.
    #[test]
    fn windows_tile_the_range_in_order() {
        for (from, to) in [(0, GIB), (4096, 5 * MIB + 17), (WINDOW, 3 * WINDOW), (0, 1)] {
            let mut next = from;
            while next < to {
                let (start, end) = next_window(next, to);
                assert_eq!(start, next);
                assert!(end > start && end - start <= WINDOW);
                assert!(end == to || end % 4096 == 0);
                next = end;
            }
            assert_eq!(next, to);
        }
    }

    /// A window that is the whole file is a whole-version request, any other a ranged one, and
    /// without a known version nothing is pinned.
    #[test]
    fn the_target_is_whole_only_for_the_whole_file() {
        assert_eq!(target_for(Some(VERSION), 0, 100, 100).unwrap().range, None);
        assert_eq!(target_for(Some(VERSION), 0, 50, 100).unwrap().range, Some((0, 50)));
        assert_eq!(target_for(Some(VERSION), 50, 100, 100).unwrap().range, Some((50, 50)));
        assert_eq!(target_for(None, 0, 100, 100), None);
    }

    /// A whole-file request of a 1 GiB file is served window by window, the first bytes after one
    /// window, in order and each exactly once; the whole version is recorded last, once.
    #[test]
    fn a_gib_whole_file_request_is_served_window_by_window_then_recorded() {
        let mut io = Fake::new();
        let (result, next) = run(&mut io, Some(VERSION), GIB, 0, GIB);
        assert_eq!((result, next), (Ok(()), GIB));
        assert_eq!(io.served() as u64, GIB / WINDOW);
        assert_eq!(io.events.first(), Some(&Event::Served(0, WINDOW, true)));
        assert_eq!(io.events.last(), Some(&Event::Completed));
        let mut at = 0;
        for event in &io.events[..io.events.len() - 1] {
            let Event::Served(start, end, ranged) = event else { panic!("{event:?}") };
            assert!(*ranged && *start == at && end - start <= WINDOW);
            at = *end;
        }
        assert_eq!(at, GIB);
        assert_eq!(io.events.iter().filter(|e| **e == Event::Completed).count(), 1);
    }

    /// A file that fits one window is one whole-version request, which records itself.
    #[test]
    fn a_small_file_is_one_whole_version_request() {
        let mut io = Fake::new();
        let (result, next) = run(&mut io, Some(VERSION), MIB, 0, MIB);
        assert_eq!((result, next), (Ok(()), MIB));
        assert_eq!(io.events, [Event::Served(0, MIB, false)]);
    }

    /// A range that is not the whole file never records the whole version, however many windows
    /// it takes.
    #[test]
    fn a_partial_range_never_records_the_whole_version() {
        let mut io = Fake::new();
        let (result, _) = run(&mut io, Some(VERSION), GIB, 64 * MIB, 200 * MIB);
        assert_eq!(result, Ok(()));
        assert!(io.served() > 1 && !io.events.contains(&Event::Completed));
        // Not the whole file even when it reaches the end: the front was not delivered.
        let mut io = Fake::new();
        let (result, _) = run(&mut io, Some(VERSION), GIB, GIB - 3 * WINDOW, GIB);
        assert_eq!(result, Ok(()));
        assert!(!io.events.contains(&Event::Completed));
    }

    /// A cancel stops the loop before the next window: nothing further is asked or delivered
    /// and the whole version is not recorded.
    #[test]
    fn a_cancel_stops_further_windows() {
        let mut io = Fake::new();
        io.cancel_after = Some(3);
        let (result, next) = run(&mut io, Some(VERSION), GIB, 0, GIB);
        assert!(result.is_err());
        assert_eq!(io.served(), 3);
        assert_eq!(next, 3 * WINDOW, "everything before the cancel was delivered, nothing after");
        assert!(!io.events.contains(&Event::Completed));
    }

    /// A cancel that arrives after the last window still records nothing.
    #[test]
    fn a_cancel_after_the_last_window_records_nothing() {
        let mut io = Fake::new();
        io.cancel_after = Some((GIB / WINDOW) as usize);
        let (result, next) = run(&mut io, Some(VERSION), GIB, 0, GIB);
        assert!(result.is_err());
        assert_eq!(next, GIB);
        assert!(!io.events.contains(&Event::Completed));
    }

    /// A version that moved mid-transfer fails the window: no later window is asked, the
    /// undelivered range starts exactly where the failed window did, and nothing is recorded.
    #[test]
    fn a_version_change_mid_transfer_stops_cleanly() {
        let mut io = Fake::new();
        io.fail_at = Some(5);
        let (result, next) = run(&mut io, Some(VERSION), GIB, 0, GIB);
        assert!(result.is_err());
        assert_eq!(io.served(), 5);
        assert_eq!(next, 5 * WINDOW);
        assert!(!io.events.contains(&Event::Completed));
    }

    /// A daemon that predates ranged requests answers the first window with the whole file: the
    /// rest of the range comes from it, no further request is made, and it recorded the handoff
    /// itself.
    #[test]
    fn an_old_daemon_answers_once_with_the_whole_file() {
        let mut io = Fake::new();
        io.old_daemon = true;
        let (result, next) = run(&mut io, Some(VERSION), GIB, 0, GIB);
        assert_eq!((result, next), (Ok(()), GIB));
        assert_eq!(io.events.len(), 1);
        assert!(!io.events.contains(&Event::Completed));
    }

    /// Without a known version nothing can be pinned to windows: one request for the whole
    /// range, and nothing recorded by the loop.
    #[test]
    fn an_unknown_version_is_one_request() {
        let mut io = Fake::new();
        let (result, next) = run(&mut io, None, GIB, 0, GIB);
        assert_eq!((result, next), (Ok(()), GIB));
        assert_eq!(io.events, [Event::Served(0, GIB, false)]);
    }

    /// An answer that makes no progress, or goes past the range, is refused rather than looped
    /// on.
    #[test]
    fn an_answer_without_progress_is_refused() {
        struct Stuck(u64);
        impl Window for Stuck {
            fn cancelled(&self) -> bool {
                false
            }
            fn serve(
                &mut self,
                _: Option<FetchTarget>,
                _: u64,
                _: u64,
                _: u64,
            ) -> Result<Served, String> {
                Ok(Served { next: self.0, whole_version: false })
            }
            fn complete(&mut self, _: [u8; 32]) {}
        }
        for answer in [0, GIB + 1] {
            let mut next = 0;
            assert!(serve_range(&mut Stuck(answer), Some(VERSION), GIB, &mut next, GIB).is_err());
        }
    }
}
