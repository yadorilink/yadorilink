//! This machine's local time: the zone offset at an instant, a printable
//! local time, and the inverse (a typed local wall time to an instant).
//!
//! One definition for `status`, `trash`/version history and `rewind --at`, so
//! the time a command prints is the time the same command accepts.

/// Seconds east of UTC that this machine's local zone has at `unix_secs`.
/// `None` when the platform cannot say.
#[cfg(unix)]
pub(crate) fn utc_offset_secs(unix_secs: i64) -> Option<i64> {
    let t = unix_secs as libc::time_t;
    // SAFETY: `tm` is plain data and `localtime_r` only writes to it.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&t, &mut tm).is_null() {
            return None;
        }
        Some(tm.tm_gmtoff as i64)
    }
}

#[cfg(windows)]
pub(crate) fn utc_offset_secs(unix_secs: i64) -> Option<i64> {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::Time::SystemTimeToTzSpecificLocalTime;

    let (year, month, day, hour, minute, second) = civil_from_unix(unix_secs);
    // SYSTEMTIME starts at 1601.
    if !(1601..=30_000).contains(&year) {
        return None;
    }
    let utc = SYSTEMTIME {
        wYear: year as u16,
        wMonth: month as u16,
        wDayOfWeek: 0,
        wDay: day as u16,
        wHour: hour as u16,
        wMinute: minute as u16,
        wSecond: second as u16,
        wMilliseconds: 0,
    };
    // SAFETY: both pointers are to live, initialized plain data; a null zone
    // means "the active time zone".
    let local = unsafe {
        let mut local: SYSTEMTIME = std::mem::zeroed();
        if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
            return None;
        }
        local
    };
    let local_secs = unix_from_civil(
        i64::from(local.wYear),
        i64::from(local.wMonth),
        i64::from(local.wDay),
        i64::from(local.wHour),
        i64::from(local.wMinute),
        i64::from(local.wSecond),
    );
    Some(local_secs - unix_secs)
}

/// `YYYY-MM-DD HH:MM:SS` for `unix_secs` shifted by `offset_secs`.
pub(crate) fn format_with_offset(unix_secs: i64, offset_secs: i64) -> String {
    let (y, m, d, hh, mm, ss) = civil_from_unix(unix_secs + offset_secs);
    format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")
}

/// Civil date and time of a count of seconds since 1970-01-01 00:00:00
/// (Howard Hinnant's civil-from-days).
fn civil_from_unix(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day, rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Seconds since the epoch of a civil date and time read as UTC.
fn unix_from_civil(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe - 719_468) * 86_400 + hour * 3_600 + minute * 60 + second
}

/// The instant at which this machine's clock reads the given local wall time.
/// `None` when that wall time does not exist (skipped by a clock change) or is
/// ambiguous (repeated by one): either would be read as some other instant.
pub(crate) fn local_to_unix(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    let wall = unix_from_civil(
        i64::from(year),
        i64::from(month),
        i64::from(day),
        i64::from(hour),
        i64::from(minute),
        i64::from(second),
    );
    // The zone offset a day either side bounds any clock change near `wall`.
    let before = utc_offset_secs(wall - 86_400)?;
    let after = utc_offset_secs(wall + 86_400)?;
    let mut hits = [before, after]
        .into_iter()
        .map(|offset| (wall - offset, offset))
        .filter(|(t, offset)| utc_offset_secs(*t) == Some(*offset))
        .map(|(t, _)| t)
        .collect::<Vec<_>>();
    hits.dedup();
    match hits.as_slice() {
        [t] => Some(*t),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_conversion_round_trips() {
        let t = 1_750_000_000;
        let (y, m, d, hh, mm, ss) = civil_from_unix(t);
        assert_eq!(unix_from_civil(y, m, d, hh, mm, ss), t);
        assert_eq!(format_with_offset(t, 0), "2025-06-15 15:06:40");
    }

    /// The offset is the machine's real one, so a wall time typed in it comes
    /// back as the same wall time.
    #[test]
    fn a_local_wall_time_round_trips_through_the_zone() {
        let t = local_to_unix(2026, 1, 2, 3, 4, 5).expect("an ordinary local time");
        let offset = utc_offset_secs(t).expect("the zone offset");
        assert_eq!(format_with_offset(t, offset), "2026-01-02 03:04:05");
    }
}
