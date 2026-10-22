//! `versions`/`restore`/`trash list`/`trash restore` —
//! the CLI surface for `yadorilink-daemon/src/control_socket.rs`'s
//! `ListVersions`/`RestoreVersion`/`ListTrash`/`RestoreTrash` handlers.
//! Mirrors `commands/materialization.rs`'s by-absolute-path resolution
//! pattern (evict), since these commands resolve the same way over
//! the same control socket.

use yadorilink_client_core::ops::files;
use yadorilink_ipc_proto::daemonctl::{
    ConflictedFileInfo, EntryKind, FileVersionInfo, TrashedFileInfo,
};

use yadorilink_client_core::attention as view;

use crate::commands::device_names::DeviceNames;
use crate::error::CliError;

/// Same "best-effort canonicalize, fall back to the given string"
/// resolution `materialization.rs`'s own `absolute_path` helper uses — a
/// trashed file's path doesn't exist on disk to canonicalize, so the
/// fallback is load-bearing here, not just cosmetic.
fn absolute_path(local_path: &str) -> Result<String, CliError> {
    std::fs::canonicalize(local_path)
        .map(|p| p.to_string_lossy().to_string())
        .or_else(|_| Ok(local_path.to_string()))
}

/// `yadorilink versions <path>` — every retained version,
/// newest first, including the current one (spec "List versions of a
/// file").
pub async fn versions(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let versions = files::list_versions(absolute_path).await?;
    if versions.is_empty() {
        println!("No retained versions for {local_path}.");
        return Ok(());
    }
    let devices = DeviceNames::load().await;
    for version in &versions {
        println!("{}", version_line(version, &devices));
    }
    Ok(())
}

fn version_line(v: &FileVersionInfo, devices: &DeviceNames) -> String {
    // A directory version has no size or mtime of its own (both are
    // canonically 0); the line names the kind in their place.
    let content = if v.kind() == EntryKind::Directory {
        "directory".to_string()
    } else {
        format!("{}  size={}", v.mtime_unix_nanos, v.size)
    };
    format!(
        "v{}  {content}  from {}  state={}  mode={}",
        v.version_seq,
        devices.label(&v.origin_device_id),
        v.state,
        // `-` for "no Unix permission info" (e.g. authored on Windows) --
        // never fabricated as a fake octal value.
        v.unix_mode.map(|mode| format!("{mode:#o}")).unwrap_or_else(|| "-".to_string()),
    )
}

/// `yadorilink restore <path> [--version <id>]` — an omitted
/// `--version` resolves daemon-side to the most recent superseded version
/// (spec "Restore without a version defaults to the most recent superseded
/// version"). A missing-blocks failure (`SyncError::VersionContentUnavailable`)
/// arrives here as an ordinary `CliError::Other` (the control-socket client
/// maps every `RespPayload::Error` the same way) carrying that error's own
/// specific message text — already distinguishable from a generic failure
/// (see `error.rs`'s `VersionContentUnavailable` doc comment), so no
/// special-casing is needed here: the message is printed as-is by
/// `main.rs`'s existing `error: {e}` handler, and the non-zero exit code
/// comes from `CliError::Other`'s existing `exit_code` mapping, the same
/// path every other daemon-reported failure already takes.
pub async fn restore(local_path: String, version: Option<i64>) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    files::restore_version(absolute_path, version).await?;
    println!(
        "Restored {local_path}{}",
        version.map(|v| format!(" to version {v}")).unwrap_or_default()
    );
    Ok(())
}

/// `yadorilink trash list` — every deleted file still within its
/// link's retention window.
pub async fn trash_list() -> Result<(), CliError> {
    let trashed = files::list_trash(None).await?;
    if trashed.is_empty() {
        println!("Trash is empty.");
        return Ok(());
    }
    let devices = DeviceNames::load().await;
    for file in &trashed {
        println!("{}", trashed_file_line(file, &devices));
    }
    Ok(())
}

fn trashed_file_line(f: &TrashedFileInfo, devices: &DeviceNames) -> String {
    let origin = devices.label(&f.origin_device_id);
    let line = if f.kind() == EntryKind::Directory {
        format!(
            "{}/{}/  deleted_at={}  directory  from {origin}",
            f.local_path, f.path, f.deleted_at_unix_nanos,
        )
    } else {
        format!(
            "{}/{}  deleted_at={}  last_known_size={}  from {origin}",
            f.local_path, f.path, f.deleted_at_unix_nanos, f.last_known_size,
        )
    };
    match folder_operation_label(&f.deleted_by_operation) {
        Some(label) => format!("{line}  folder_operation={label}"),
        None => line,
    }
}

/// A short, stable label for the recursive operation that removed a
/// trashed entry (`<author>:<hex id>` on the wire): the first eight hex
/// digits of its id, enough to tell a folder's entries apart from another
/// folder's in one listing.
fn folder_operation_label(deleted_by_operation: &str) -> Option<&str> {
    let (_, id) = deleted_by_operation.rsplit_once(':')?;
    id.get(..8)
}

/// `yadorilink conflicts list` — every currently-live conflicted-copy
/// file across every linked folder (the same files `yadorilink status`'s
/// per-link `conflict_count` already tallies, listed here individually).
async fn conflicts_list() -> Result<(), CliError> {
    let conflicts = files::list_conflicts(None).await?;
    if conflicts.is_empty() {
        println!("No conflicted files.");
        return Ok(());
    }
    let devices = DeviceNames::load().await;
    for file in &conflicts {
        println!("{}", conflicted_file_line(file, &devices));
    }
    if conflicts.iter().any(|f| f.resolvable) {
        println!("{CONFLICT_RESOLVE_HINT}");
    }
    Ok(())
}

pub enum ConflictsCommand {
    List,
    Keep(String),
    KeepBoth(String),
}

pub async fn conflicts(command: ConflictsCommand) -> Result<(), CliError> {
    match command {
        ConflictsCommand::List => conflicts_list().await,
        ConflictsCommand::Keep(path) => {
            conflicts_resolve(path, files::ConflictChoice::KeepThis).await
        }
        ConflictsCommand::KeepBoth(path) => {
            conflicts_resolve(path, files::ConflictChoice::KeepBoth).await
        }
    }
}

/// `yadorilink conflicts keep|keep-both <copy>`.
async fn conflicts_resolve(
    copy_path: String,
    choice: files::ConflictChoice,
) -> Result<(), CliError> {
    let absolute_path = absolute_path(&copy_path)?;
    let kept = files::resolve_conflict(&absolute_path, choice).await?;
    match choice {
        files::ConflictChoice::KeepThis => println!("Kept this version as {}", kept.display()),
        files::ConflictChoice::KeepBoth => {
            println!("Kept both versions; this one is now {}", kept.display())
        }
    }
    Ok(())
}

const CONFLICT_RESOLVE_HINT: &str = "To choose, run `yadorilink conflicts keep <copy>` to make \
     a copy the file, or `yadorilink conflicts keep-both <copy>` to keep both as separate files.";

fn conflicted_file_line(f: &ConflictedFileInfo, devices: &DeviceNames) -> String {
    let why = view::conflict_detail(f).reason.explanation();
    let place = format!("{}/{}", f.local_path, f.path);
    let from = devices.label(&f.origin_device_id);
    if f.kind() == EntryKind::Directory {
        format!("{place}/\n  {why}\n  from {from}")
    } else {
        format!(
            "{place}\n  {why}\n  {}, saved {} on {from}",
            super::status::format_bytes(f.size.max(0) as u64),
            format_local_time(f.mtime_unix_nanos)
        )
    }
}

/// `YYYY-MM-DD HH:MM:SS` in this machine's local time.
fn format_local_time(unix_nanos: i64) -> String {
    let secs = unix_nanos.div_euclid(1_000_000_000);
    let offset = super::local_time::utc_offset_secs(secs).unwrap_or(0);
    super::local_time::format_with_offset(secs, offset)
}

/// `yadorilink trash restore <path>` — recovers a deleted file's
/// last version before deletion as a new current version; the file becomes
/// live again.
pub async fn trash_restore(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    files::restore_from_trash(absolute_path).await?;
    println!("Restored {local_path} from trash");
    Ok(())
}

/// `yadorilink trash restore --folder <path>` — recovers, together, every
/// entry removed by the same recursive delete or directory rename that
/// removed `<path>`.
pub async fn trash_restore_folder(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let outcome = files::restore_trash_operation(absolute_path).await?;
    println!(
        "Restored {} entr{} removed together with {local_path}",
        outcome.restored_paths.len(),
        if outcome.restored_paths.len() == 1 { "y" } else { "ies" }
    );
    for path in &outcome.restored_paths {
        println!("  restored  {path}");
    }
    if outcome.partial {
        println!(
            "warning: part of that operation has not reached this device; entries it removed \
             elsewhere in the folder were not restored"
        );
    }
    if outcome.failed.is_empty() {
        return Ok(());
    }
    for failure in &outcome.failed {
        eprintln!("  failed    {}: {}", failure.path, failure.error);
    }
    Err(CliError::Other(format!(
        "{} of the folder's entries could not be restored",
        outcome.failed.len()
    )))
}

#[cfg(test)]
mod tests;
