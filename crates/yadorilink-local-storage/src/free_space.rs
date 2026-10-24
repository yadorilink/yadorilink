use std::path::Path;

/// Absolute floor of the default headroom: what the OS, other apps and the sync database
/// (SQLite needs room to commit and to grow its WAL) keep, whatever the volume.
pub const DEFAULT_MIN_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;
/// Absolute cap of the default headroom, so a big disk never reserves tens of GiB.
pub const DEFAULT_MAX_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// The default headroom between floor and cap: one hundredth of the volume.
pub const DEFAULT_HEADROOM_DIVISOR: u64 = 100;
/// The floor never exceeds this fraction (1/n) of a volume, so a tiny volume can still receive.
pub const MAX_HEADROOM_VOLUME_FRACTION_DIVISOR: u64 = 4;
/// A volume that refused a write counts as recovered only above its headroom plus
/// 1/n of it (hysteresis): free space hovering at the line does not flip the status.
pub const RESUME_MARGIN_DIVISOR: u64 = 4;

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

    /// Has the volume regained enough room to leave the waiting state it entered by
    /// refusing a write? Strictly above the headroom plus a resume margin, so the
    /// status does not flap while free space hovers at the admission line.
    pub fn recovered(&self) -> bool {
        self.available_bytes
            > self.headroom_bytes.saturating_add(self.headroom_bytes / RESUME_MARGIN_DIVISOR)
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
/// `configured_override` if set, else 1% of the volume clamped to
/// [256 MiB, 2 GiB], and never above a quarter of the volume. This is the margin kept
/// free on top of the bytes already in flight on the volume (see the admission
/// ledger), which callers add through `would_breach`.
pub fn effective_headroom_bytes(total_bytes: u64, configured_override: Option<u64>) -> u64 {
    configured_override.unwrap_or_else(|| {
        (total_bytes / DEFAULT_HEADROOM_DIVISOR)
            .clamp(DEFAULT_MIN_HEADROOM_BYTES, DEFAULT_MAX_HEADROOM_BYTES)
            .min(total_bytes / MAX_HEADROOM_VOLUME_FRACTION_DIVISOR)
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
