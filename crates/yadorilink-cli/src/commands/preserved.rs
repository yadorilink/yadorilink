//! `yadorilink preserved list | restore <item-id> | retry <item-id> | discard <item-id> [--yes]`: what a
//! rebootstrap set aside for you. A version another device wrote that the group's replacing
//! state did not contain stays until you restore it (as one ordinary new write) or discard it;
//! your own changes that could not be replayed are listed with where their files are.

use yadorilink_client_core::ops::storage;
use yadorilink_ipc_proto::daemonctl::PreservedItem;

use crate::error::CliError;

pub async fn list() -> Result<(), CliError> {
    let items = storage::list_preserved().await?;
    if items.is_empty() {
        println!("Nothing is preserved.");
        return Ok(());
    }
    for item in &items {
        println!("{}", format_item(item));
    }
    Ok(())
}

pub async fn restore(item_id: &str) -> Result<(), CliError> {
    let group = group_of(item_id).await?;
    storage::restore_preserved(&group, item_id).await?;
    println!("Restored {item_id}: it is written back as a new version; the item is kept.");
    Ok(())
}

pub async fn retry(item_id: &str) -> Result<(), CliError> {
    let group = group_of(item_id).await?;
    storage::retry_preserved(&group, item_id).await?;
    println!(
        "Retried {item_id}: its changes are written as new versions and it is no longer held."
    );
    Ok(())
}

pub async fn discard(item_id: &str, yes: bool) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::Other(format!(
            "discarding {item_id} deletes the only copy kept on this device; \
             re-run with --yes to confirm"
        )));
    }
    let group = group_of(item_id).await?;
    storage::discard_preserved(&group, item_id).await?;
    println!("Discarded {item_id}.");
    Ok(())
}

/// The group an item belongs to: items are named by id alone on the command line.
async fn group_of(item_id: &str) -> Result<String, CliError> {
    storage::list_preserved()
        .await?
        .into_iter()
        .find(|item| item.item_id == item_id)
        .map(|item| item.group_id)
        .ok_or_else(|| CliError::Other(format!("no preserved item {item_id}")))
}

/// One line of `list`: id, group, what it is and where.
pub(crate) fn format_item(item: &PreservedItem) -> String {
    let removed = if item.group_removed { " (group removed)" } else { "" };
    match item.kind.as_str() {
        "own_unit" => format!(
            "{}  group={}{removed}  own changes not replayed: {}{}",
            item.item_id,
            item.group_id,
            item.paths.join(", "),
            if item.originals_quarantined {
                format!(
                    "  (originals moved out of the folder into recovery area {})",
                    item.recovery_id
                )
            } else {
                format!("  (files stay in recovery area {})", item.recovery_id)
            }
        ),
        kind => {
            let content = match item.content.as_str() {
                "complete" => "content complete".to_string(),
                "unavailable" => format!(
                    "content unavailable ({} of {} blocks)",
                    item.blocks_held, item.blocks_total
                ),
                _ => "record unavailable".to_string(),
            };
            format!(
                "{}  group={}{removed}  {}  {kind}  {content}  {} bytes",
                item.item_id, item.group_id, item.path, item.size
            )
        }
    }
}

pub async fn retained_list() -> Result<(), CliError> {
    let items = storage::list_retained_originals().await?;
    if items.is_empty() {
        println!("No originals are kept.");
        return Ok(());
    }
    println!("{RETAINED_EXPLANATION}");
    for item in &items {
        println!("{}", format_retained(item));
    }
    Ok(())
}

/// Tries to release the kept originals of `group`, or of every group that has any.
pub async fn retained_release(group: Option<String>) -> Result<(), CliError> {
    let groups = match group {
        Some(group) => vec![group],
        None => {
            let mut groups: Vec<String> = storage::list_retained_originals()
                .await?
                .into_iter()
                .map(|item| item.group_id)
                .collect();
            groups.dedup();
            groups
        }
    };
    if groups.is_empty() {
        println!("No originals are kept.");
        return Ok(());
    }
    for group in groups {
        println!("group={group}");
        for release in storage::release_retained_originals(&group).await? {
            println!("  {}", format_release(&release));
        }
    }
    Ok(())
}

/// Why the files are kept and when they can go.
const RETAINED_EXPLANATION: &str = "These files were kept as they were because it could not be \
     proved safe to remove them. Each can be released once nothing is writing to it: run \
     `yadorilink preserved retained release`. A file that changed meanwhile is saved first.";

/// One line of `retained list`.
pub(crate) fn format_retained(item: &yadorilink_ipc_proto::daemonctl::RetainedOriginal) -> String {
    let removed = if item.group_removed { " (group removed)" } else { "" };
    let size = if item.reachable {
        super::status::format_bytes(item.size)
    } else {
        "size unknown (the folder is not watched)".to_string()
    };
    format!("group={}{removed}  {}  {size}", item.group_id, item.path)
}

/// One line of `retained release`.
pub(crate) fn format_release(release: &yadorilink_ipc_proto::daemonctl::RetainedRelease) -> String {
    let what = match release.outcome.as_str() {
        "removed" => "released".to_string(),
        "gone" => "nothing was left to release".to_string(),
        "still_retained" => {
            "kept: it may still be written to, or it changed; try again later".to_string()
        }
        "saved_then_removed" => {
            "it had changed: the new bytes are saved (see `yadorilink preserved list`), then it \
             was released"
                .to_string()
        }
        "saved_still_retained" => {
            "it had changed: the new bytes are saved (see `yadorilink preserved list`); the \
             original is still kept"
                .to_string()
        }
        "left" => format!("left as it is: {}", release.detail),
        other => format!("{other} {}", release.detail),
    };
    format!("{}  {what}", release.path)
}

#[cfg(test)]
mod tests;
