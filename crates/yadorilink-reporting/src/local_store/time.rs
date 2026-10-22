//! Minimal, dependency-free UTC timestamp helpers for the reporting
//! storage layer. `yadorilink-reporting`'s envelope/queue types deliberately
//! take caller-supplied RFC 3339 strings rather than reading a clock
//! themselves (see that crate's doc comments), and this workspace has no
//! existing `chrono`/`time` dependency, so this module supplies the one
//! thing actually needed: formatting a unix timestamp as RFC 3339 UTC for
//! display in a generated report / queue metadata entry.
//!
//! Retention math (`RetentionPolicy::entries_to_evict`) never parses this
//! string back — every store in this module derives an entry's age from
//! its file's on-disk mtime instead (see `entry_store.rs`), which is both
//! simpler (no RFC 3339 parser needed) and more robust (doesn't trust
//! content a caller could hand-edit).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, saturating to 0 if the system clock is
/// somehow set before 1970 — never worth failing a reporting-storage
/// operation over.
pub fn now_unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn system_time_to_unix_seconds(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Howard Hinnant's `civil_from_days` algorithm (public domain,
/// http://howardhinnant.github.io/date_algorithms.html), used here to
/// avoid pulling in a full calendar crate for one call site.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Formats a unix timestamp (seconds) as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn unix_seconds_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

pub fn now_rfc3339() -> String {
    unix_seconds_to_rfc3339(now_unix_seconds())
}

#[cfg(test)]
mod tests;
