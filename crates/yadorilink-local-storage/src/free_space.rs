use std::path::Path;

/// Minimum headroom floor when no explicit override is configured:
/// `max(1 GiB, 5% of the hosting volume)`.
pub const DEFAULT_MIN_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;
/// The percentage half of the same default formula.
pub const DEFAULT_HEADROOM_PERCENT: f64 = 0.05;

/// A volume's free-space state relative to its effective headroom.
/// Ordered from healthiest to worst so a caller that only cares about
/// "is this at least as bad as X" can compare with `>=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FreeSpaceState {
    /// Comfortably above headroom (more than double it free).
    Ok,
    /// Above headroom, but only modestly so (at or below double headroom).
    Low,
    /// At or below headroom.
    Critical,
}

impl FreeSpaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            FreeSpaceState::Ok => "ok",
            FreeSpaceState::Low => "low",
            FreeSpaceState::Critical => "critical",
        }
    }
}

/// A volume's free-space snapshot plus its effective headroom — the single
/// source of truth both the preflight rejection decision and status
/// reporting read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeFreeSpace {
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub headroom_bytes: u64,
}

impl VolumeFreeSpace {
    /// `critical` at or below headroom, `low` up to double
    /// headroom, `ok` beyond that.
    pub fn classify(&self) -> FreeSpaceState {
        if self.available_bytes <= self.headroom_bytes {
            FreeSpaceState::Critical
        } else if self.available_bytes <= self.headroom_bytes.saturating_mul(2) {
            FreeSpaceState::Low
        } else {
            FreeSpaceState::Ok
        }
    }

    /// Would writing `additional_bytes` more bring available space to at or
    /// below the configured headroom? (The preflight predicate —
    /// deliberately the same `<=` boundary `classify`'s `Critical` uses, so
    /// "would breach" and "would become critical" are the same condition.)
    pub fn would_breach(&self, additional_bytes: u64) -> bool {
        self.available_bytes.saturating_sub(additional_bytes) <= self.headroom_bytes
    }
}

/// The effective headroom for a volume of `total_bytes`: the explicit
/// `configured_override` if set, else `max(1 GiB, 5%)` of the volume.
pub fn effective_headroom_bytes(total_bytes: u64, configured_override: Option<u64>) -> u64 {
    configured_override.unwrap_or_else(|| {
        let percent = (total_bytes as f64 * DEFAULT_HEADROOM_PERCENT) as u64;
        percent.max(DEFAULT_MIN_HEADROOM_BYTES)
    })
}

/// Queries the OS for free/total space on the volume hosting `path`
/// (`path` must currently exist) and classifies it against the effective
/// headroom.
///
/// Explicitly stats `path` itself first rather than leaving that to
/// `fs2::available_space`/`total_space` — the two platforms resolve a
/// missing `path` completely differently underneath those calls. On Unix,
/// `fs2` shells out to `statvfs(2)` directly on `path`, which requires the
/// exact directory to exist and fails with `NotFound` otherwise. On
/// Windows, `fs2` first calls `GetVolumePathNameW(path, ..)` to find the
/// containing volume/drive root, then queries THAT root with
/// `GetDiskFreeSpaceW` — a purely syntactic walk up the path that never
/// requires `path` (or any of its ancestors short of the drive itself) to
/// actually exist on disk. A directory tree that was deleted out from
/// under this call — e.g. a faulted or unmounted block-store root, which
/// every caller of this function relies on being surfaced as a `NotFound`
/// (see `is_source_path_vanished_error`'s doc comment in
/// `yadorilink-local-capture`) — is therefore silently invisible on
/// Windows without this guard: `fs2` would happily report the whole
/// volume's free space instead of erroring, and every headroom preflight
/// built on top of "stat the target root" would wrongly proceed as if
/// nothing were wrong. Stating `path` ourselves first makes both platforms
/// fail on the same input the same way.
pub fn classify_volume(
    path: &Path,
    configured_override: Option<u64>,
) -> std::io::Result<VolumeFreeSpace> {
    std::fs::metadata(path)?;
    let available_bytes = fs2::available_space(path)?;
    let total_bytes = fs2::total_space(path)?;
    let headroom_bytes = effective_headroom_bytes(total_bytes, configured_override);
    Ok(VolumeFreeSpace { available_bytes, total_bytes, headroom_bytes })
}

#[cfg(test)]
mod tests;
