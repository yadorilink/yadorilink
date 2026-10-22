//! Path normalization and admission policy: wire-path relativization,
//! reserved/ignored path exclusion, and inadmissible-name skips.

use std::path::Path;

use yadorilink_fs_platform::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_fs_platform::reserved_namespace::is_sync_root_lock_relative_path;
use yadorilink_fs_platform::reserved_namespace::path_has_reserved_component;
use yadorilink_root_authority::root_identity::is_root_marker_relative_path;

/// The link-relative, forward-slash-normalized key for `path` under `root` —
/// the exact form the index and the `local_dirty_paths` journal use as a path
/// key, so a journaled dirty row and the record it corresponds to always agree.
/// Mirrors `process_event_with_ignore_at`'s own relativization (canonicalize
/// `root`, `strip_prefix`, then `path_to_wire_relative_string`). Returns
/// `None` when `path` is not under `root`, is the root itself, or cannot be
/// represented losslessly as a wire path — all cases the executor treats as
/// a no-op anyway.
pub(super) fn relative_key(root: &Path, path: &Path) -> Option<String> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let rel = path.strip_prefix(&root).ok()?;
    let rel = path_to_wire_relative_string(rel)?;
    if rel.is_empty() {
        return None;
    }
    Some(rel)
}

/// Why this path can never become a local change, or `None` if it can.
///
/// A thin wrapper over
/// [`yadorilink_fs_platform::reserved_namespace::wire_path_admission_refusal`]
/// -- the single predicate native admission itself reads
/// (`dag_store::serving_authorization_index::validate_no_reserved_paths`,
/// on both the receiving and local-authoring call sites) -- turned into a
/// short reason string for the skip warnings.
///
/// ## Why local capture has to filter these at all
///
/// Because a refusal is not scoped to the path that caused it. Local
/// capture commits a whole debounce batch (`flush_pending_batch`) or scan
/// chunk (`reconcile_disk_with_ignore`) as ONE signed change, so the
/// emission refusing one path fails the entire batch -- every unrelated
/// file in it included. `flush_pending_batch` then logs and returns
/// `Ok(vec![])`, leaving the batch journaled dirty, and the backstop
/// re-drives the identical failing batch on the next sweep, and the next.
///
/// Observed directly on this tree, in `windows_path_hazard_conflict`:
///
/// ```text
/// WARN failed to commit a batched group of local mutations; left journaled
///      dirty for re-drive error=path "CON.txt" has a component that is not
///      portable to every platform this group may sync to
///      group_id="windows-path-hazard-group" batch_len=2
/// ```
///
/// every 5 seconds, indefinitely. The `batch_len=2` is the bug in one
/// number: the second entry was an ordinary file that merely shared a
/// debounce window with `CON.txt`. A POSIX user creating `CON.txt`,
/// `"notes.txt "` or `report<final>.txt` -- all legal on Linux and macOS --
/// silently stops that folder syncing **anything**. Nothing in the refusal
/// is gated on `cfg!(windows)` (deliberately: every peer must reach the
/// same verdict for the same wire path), so it hits every platform.
///
/// Skipping, not holding or erroring, is the right response: refusal is a
/// property of the name alone, so it can never resolve on a later attempt.
/// The file itself is never touched -- it stays exactly as the user wrote
/// it, it is simply not represented in the group's history, which is the
/// same end state admission was always going to enforce.
pub(super) fn skip_reason_for_inadmissible_wire_path(rel_path: &str) -> Option<&'static str> {
    use yadorilink_fs_platform::reserved_namespace::{
        wire_path_admission_refusal, WirePathRefusal,
    };
    match wire_path_admission_refusal(rel_path) {
        Some(WirePathRefusal::ReservedNamespace) => {
            Some("names a reserved-namespace artefact or the sync-root lock file")
        }
        Some(WirePathRefusal::NonPortable) => {
            Some("has a component that is not portable to every platform this group may sync to")
        }
        None => None,
    }
}

/// Converts `rel` (a path already relative to some root) into this crate's
/// canonical forward-slash wire-path string, or `None` if `rel` cannot be
/// represented losslessly as one. It closes two distinct silent-collision
/// hazards in the naive `rel.to_string_lossy().replace('\\', "/")` pattern:
///
/// - That naive code replaces `\` with `/` UNCONDITIONALLY, on every
///   platform. On Windows that's correct (the native separator IS `\`,
///   and the wire form needs `/`) — but on Unix, `\` is an ordinary, legal
///   filename BYTE, not a path separator (the native separator there is
///   already `/`). Blindly replacing it folded two genuinely different
///   real files onto the identical logical path string: a file literally
///   named `a\b.txt` and a nested file at `a/b.txt` both produced the
///   wire string `"a/b.txt"`. `Path::to_str`'s own text already uses each
///   platform's real separator, so gating the `\`→`/` substitution to
///   `#[cfg(windows)]` alone closes this without needing any Unix-side
///   logic at all.
/// - `to_string_lossy()` silently substitutes `�` (U+FFFD) for any
///   invalid UTF-8 byte sequence. Two DIFFERENT real files whose names
///   contain different non-UTF-8 byte sequences (common in practice: any
///   name that isn't valid UTF-8 at all, e.g. legacy Latin-1-encoded
///   filenames, or an archive/zip extracted from a non-UTF-8 locale) can
///   therefore silently collapse onto the identical logical path string.
///   `Path::to_str` returns `None` instead of substituting anything,
///   which every caller here now treats as "cannot safely sync this
///   path" (skip/suppress/no-op) rather than silently proceeding with a
///   corrupted string that might collide with something else.
///
/// This is a bounded mitigation, not a full fix: this crate's index/native state/
/// wire representation is still fundamentally a UTF-8 `String`, so a
/// genuinely non-UTF-8 name still cannot be synced at all — it is now
/// refused outright rather than silently corrupted, which is strictly
/// better (no silent collision) but not the same as actually supporting
/// such names. The full fix — raw-byte (Unix) / WTF-16 (Windows) path
/// representation threaded through the wire protocol, delta encoding, and
/// every index primary key — is a substantially larger redesign, tracked
/// as an open residual rather than attempted here.
pub(super) fn path_to_wire_relative_string(rel: &Path) -> Option<String> {
    let text = rel.to_str()?;
    #[cfg(windows)]
    let text: std::borrow::Cow<'_, str> = text.replace('\\', "/").into();
    #[cfg(not(windows))]
    let text: std::borrow::Cow<'_, str> = {
        // The wire representation is consumed on Windows too, where
        // '\' is a separator. Preserving a literal Unix backslash
        // would let `a\b` and `a/b` remain distinct signed/index
        // paths while materializing onto the same Windows object.
        if text.contains('\\') {
            return None;
        }
        text.into()
    };
    Some(text.into_owned())
}

pub(super) fn is_excluded_from_sync(
    relative_path: impl AsRef<Path>,
    is_dir: bool,
    ignore_set: &EffectiveIgnoreSet,
) -> bool {
    let relative_path = relative_path.as_ref();
    // The reserved artefact namespace is checked before anything else in
    // this function, including the sync-root marker and ignore file
    // special-cases below: a transaction artefact must never become
    // trackable content no matter what a user's ignore file says about it.
    if path_has_reserved_component(relative_path) {
        return true;
    }
    // The sync-root marker is this device's own identity file
    // (`yadorilink_root_authority::root_identity`), not user content: every device mints its own
    // token, so syncing it would overwrite a peer's identity with ours and
    // produce a conflicted copy of the very file that proves which folder this
    // is. Excluded here — the one place scan, watch, and the becoming-ignored
    // index cleanup all consult — rather than as a pattern in the default
    // ignore set, because a user-editable `.yadorilinkignore` can negate a
    // pattern (`!.yadorilink-root`) and must not be able to.
    // The sync-root single-instance lock sidecar (`crate::sync_root_lock`) is
    // likewise this device's own process-management artefact, not user
    // content, and excluded for the identical reason as the identity marker
    // immediately above: it names no fixed identity to disagree over like the
    // marker does, but syncing it would still make it visible to `.yadorilinkignore`
    // negation and conflicted-copy machinery it has no business being subject to.
    is_root_marker_relative_path(relative_path)
        || is_sync_root_lock_relative_path(relative_path)
        || is_ignore_file_relative_path(relative_path)
        || ignore_set.is_ignored(relative_path, is_dir)
}
