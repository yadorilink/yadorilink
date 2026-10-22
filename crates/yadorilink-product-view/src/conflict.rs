//! Conflict-copy detail, derived purely from `ConflictedFileInfo.path`'s
//! own established naming convention — never from a new daemon field.
//!
//! `ConflictedFileInfo` on the wire (`daemon_control.proto`) carries only
//! `local_path`/`path`/`size`/`mtime_unix_nanos`: no explicit "which side
//! is current"/"originating device" field. That detail genuinely exists
//! on the wire today, just embedded in the conflicted-copy filename rather
//! than a separate struct field — the sync engine's own conflict-copy
//! naming convention (`yadorilink-replica-domain`'s `conflict.rs`, a
//! sync-engine module this crate does NOT depend on — see this crate's
//! own top doc comment) always produces
//! `<name> (conflicted copy, <ISO-8601-ish timestamp>, <device_id>[,
//! <content hash hex>]).<ext>` (a native copy omits the timestamp), and the CLI's own
//! `commands::version_history` test
//! fixtures encode the identical shape. Parsing that documented, spec-level
//! convention here (rather than adding a sync-engine dependency just to
//! reuse its private stripping helpers) keeps this crate's
//! no-sync-engine-dependency property intact while still surfacing real data, not
//! fabricated fields.
//!
//! Deliberately defensive: an unparseable `path` (a daemon that changed the
//! convention, or an unrelated file that merely landed in the conflicts
//! list) degrades to `None` fields rather than panicking or guessing.

use yadorilink_ipc_proto::daemonctl::{ConflictReason as WireConflictReason, ConflictedFileInfo};

const MARKER: &str = " (conflicted copy, ";

/// One conflicted-copy file's parsed detail: why the copy is kept
/// (`ConflictedFileInfo.reason`, the one field here the daemon states
/// rather than the name carrying it), the evidence for it (the losing
/// device and when its copy was demoted), and which path still holds the
/// current content -- a caller renders the "why" sentence from
/// [`ConflictReason::explanation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictDetail {
    /// The path (relative to the folder root, same convention as
    /// `ConflictedFileInfo.path`) that stays live as the folder's current,
    /// winning version of this file — the base name the conflicted-copy
    /// name was derived from. Falls back to the conflicted-copy's own path
    /// unchanged if the marker isn't found (see this module's doc comment).
    pub current_path: String,
    /// The device whose edit lost the tie-break and was demoted to this
    /// conflicted-copy file — `None` if the filename doesn't carry the
    /// marker at all (unparseable/unexpected shape).
    pub loser_device_id: Option<String>,
    /// The conflicted copy's embedded timestamp, exactly as the filename
    /// carries it (`YYYY-MM-DD-HHMMSS`) — not reparsed into a real
    /// timestamp type, since its only use is display alongside the raw
    /// `mtime_unix_nanos` the wire already provides.
    pub timestamp: Option<String>,
    /// The content-hash disambiguator, as the filename carries it: the
    /// full lowercase hex encoding of the losing version's hash. It is
    /// what makes two different losing contents unable to share one
    /// conflict-copy path, so it is never truncated by the producer and is
    /// never truncated here either. `None` when the filename does not
    /// carry it at all — a hand-built name (e.g. some test fixtures) may
    /// omit it, so this is optional even when `loser_device_id`/
    /// `timestamp` parsed successfully.
    pub content_hash_hex: Option<String>,
    pub reason: ConflictReason,
}

/// Why a conflict copy is kept under its own name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// Devices changed the same path at the same time; the copy holds the
    /// version that did not keep the name. Also what a sender that did not
    /// state a reason means: until folders took part in conflicts it was
    /// the only one.
    ConcurrentEdit,
    /// The name the copy came from is a folder now, so the file (or link)
    /// was moved aside instead of replacing the folder.
    FolderAtPath,
}

/// Status line for a kept conflict copy whose durability is not yet confirmed
/// by another device. Shared wording for any UI.
pub const WAITING_FOR_CONFIRMATION: &str = "Both versions were kept. This PC is waiting for another device to confirm the copy before updating the file.";

impl ConflictReason {
    fn from_wire(reason: WireConflictReason) -> Self {
        match reason {
            WireConflictReason::Unspecified | WireConflictReason::ConcurrentEdit => {
                Self::ConcurrentEdit
            }
            WireConflictReason::FolderAtPath => Self::FolderAtPath,
        }
    }

    /// One sentence saying why a copy with this reason exists.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::ConcurrentEdit => {
                "Edited on two devices; both versions were kept. This is the other version."
            }
            Self::FolderAtPath => {
                "Its name is a folder now: one device made a folder there while another had a \
                 file at that name. The folder keeps the name and the file was kept here \
                 beside it instead of replacing it."
            }
        }
    }
}

/// Parses one `ConflictedFileInfo` into its `ConflictDetail`.
pub fn conflict_detail(file: &ConflictedFileInfo) -> ConflictDetail {
    parse_conflict_path(&file.path, ConflictReason::from_wire(file.reason()))
}

fn parse_conflict_path(path: &str, reason: ConflictReason) -> ConflictDetail {
    let (dir, filename) = match path.rsplit_once('/') {
        Some((dir, name)) => (Some(dir), name),
        None => (None, path),
    };
    let (stem, ext) = match filename.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (filename, None),
    };

    let Some(marker_idx) = stem.find(MARKER) else {
        // Not shaped like a conflict-copy name at all — nothing to parse,
        // report the path as its own "current" path rather than guessing.
        return ConflictDetail {
            current_path: path.to_string(),
            loser_device_id: None,
            timestamp: None,
            content_hash_hex: None,
            reason,
        };
    };
    let base_stem = &stem[..marker_idx];
    let current_path = join(dir, base_stem, ext);

    // The detail run is everything after the marker, with one trailing
    // `)` stripped if present (the well-formed case — see
    // `conflict_copy_path`'s own doc comment in `yadorilink-replica-domain`
    // for the exact shape this mirrors).
    let after_marker = &stem[marker_idx + MARKER.len()..];
    let detail = after_marker.strip_suffix(')').unwrap_or(after_marker);
    let parts = detail.split(", ").map(str::trim).filter(|s| !s.is_empty());
    // The timestamp is absent from native copy names, so the first field is
    // only taken for one when it has a timestamp's shape.
    let mut parts = parts.peekable();
    let timestamp = parts.next_if(|part| looks_like_timestamp(part)).map(str::to_string);
    let loser_device_id = parts.next().map(str::to_string);
    let content_hash_hex = parts.next().map(str::to_string);

    ConflictDetail { current_path, loser_device_id, timestamp, content_hash_hex, reason }
}

/// `YYYY-MM-DD-HHMMSS`, as `conflict_copy_path` writes it.
fn looks_like_timestamp(part: &str) -> bool {
    part.len() == 17
        && part.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 4 | 7 | 10) {
                b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
}

fn join(dir: Option<&str>, stem: &str, ext: Option<&str>) -> String {
    let name = match ext {
        Some(ext) => format!("{stem}.{ext}"),
        None => stem.to_string(),
    };
    match dir {
        Some(dir) => format!("{dir}/{name}"),
        None => name,
    }
}

#[cfg(test)]
mod tests;
