//! On-demand CLI commands: evict a file or show its materialization state
//! by its local path, resolved by the daemon against its registered links
//! (the same absolute-path resolution the shell-IPC hydration path uses).

use yadorilink_client_core::ops::files;
use yadorilink_ipc_proto::daemonctl::{
    local_state_word, EvictResponse, RetentionPolicy, RetentionRule, RetentionState,
    SetRetentionRuleResponse,
};

use crate::error::CliError;

fn absolute_path(local_path: &str) -> Result<String, CliError> {
    std::fs::canonicalize(local_path).map(|p| p.to_string_lossy().to_string()).or_else(|_| {
        // A placeholder file, or one not yet materialized, may not
        // resolve via `canonicalize` if the parent itself is missing —
        // but ordinarily the file (even a placeholder) exists on disk
        // with the correct name, so this fallback is mainly for
        // clearer error messages on a genuinely wrong path.
        Ok(local_path.to_string())
    })
}

/// Fetches an on-demand placeholder's content; returns once the daemon has
/// made the file present. Only for a root the daemon hydrates itself: a provider
/// root is hydrated by the OS when the file is opened, and the daemon refuses
/// this request there.
pub async fn hydrate(local_path: String) -> Result<(), CliError> {
    let downloaded = files::hydrate_file(absolute_path(&local_path)?).await?;
    println!("{}", hydrate_report(&local_path, downloaded));
    Ok(())
}

/// A request that fetched nothing (a regular folder keeps every file, so there is nothing to
/// fetch there) must never read as a download.
fn hydrate_report(local_path: &str, downloaded: bool) -> String {
    if downloaded {
        format!("Downloaded {local_path}")
    } else {
        format!("Nothing to download: {local_path} is already on this device.")
    }
}

/// Reads `EvictResponse.dehydrated` and only ever claims success
/// when it's `true` -- a request that daemon-side silently did nothing
/// (the file is busy, not yet fully synced, or was just modified)
/// used to print "Evicted" regardless, an unconditional success claim this
/// daemon never actually backed up. See `EvictResponse`'s own proto doc
/// comment for the exact gap this closes.
pub async fn evict(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let response = files::evict(absolute_path).await?;
    println!("{}", evict_outcome(&local_path, &response)?);
    Ok(())
}

/// The report of an eviction that happened; an eviction that freed nothing is an error, so the
/// exit status tells a script (and the shell) whether the item was evicted.
fn evict_outcome(local_path: &str, response: &EvictResponse) -> Result<String, CliError> {
    let report = evict_report(local_path, response);
    if response.dehydrated {
        Ok(report)
    } else {
        Err(CliError::Other(report))
    }
}

/// What one eviction did, in the user's words. The daemon keeps its cached blocks of a file
/// whenever no full replica took a durable lease on the version, even though the OS copy was
/// dropped; saying only "Evicted" then hides that no disk space was freed and why.
fn evict_report(local_path: &str, response: &EvictResponse) -> String {
    // Why a successful call freed nothing is the more specific answer when the daemon gives it.
    let code = if response.dehydrated || response.not_freed_reason.is_empty() {
        &response.retained_reason
    } else {
        &response.not_freed_reason
    };
    let refusal = files::evict_refusal(code);
    let next = |refusal: &files::EvictRefusal| {
        if refusal.hint.is_empty() {
            String::new()
        } else {
            format!(" {}", refusal.hint)
        }
    };
    match (response.dehydrated, refusal) {
        (true, None) => format!("Evicted {local_path} (converted to a placeholder)"),
        (true, Some(why)) => format!(
            "Evicted {local_path} (converted to a placeholder), but its data is still kept on \
             this device and the file still opens: {}.{} [{}]",
            why.why,
            next(&why),
            response.retained_reason
        ),
        (false, Some(why)) => {
            format!("{local_path} was not evicted: {}.{} [{}]", why.why, next(&why), code)
        }
        (false, None) => format!(
            "{local_path} was not evicted and nothing was freed. If the file was only just \
             downloaded or edited, try again in a few seconds."
        ),
    }
}

/// The per-file analogue of `yadorilink status`'s aggregate
/// hydrated/placeholder/hydrating counts -- what state THIS file is in
/// right now.
pub async fn status(local_path: String) -> Result<(), CliError> {
    let absolute_path = absolute_path(&local_path)?;
    let status = files::materialization_status(absolute_path).await?;
    if status.known {
        let state = local_state_word(status.local_state.as_ref());
        println!("{local_path}: {state}{}", retention_suffix(status.retention.as_ref()));
    } else {
        println!(
            "{local_path}: not currently tracked (not indexed, or not under a linked \
             folder){}",
            retention_suffix(status.retention.as_ref())
        );
    }
    Ok(())
}

/// Keeps a file or folder on this device: the choice is recorded first, then whatever is not
/// here yet is downloaded. A download that fails does not undo the choice.
pub async fn keep(local_path: String) -> Result<(), CliError> {
    let response =
        files::set_retention_rule(absolute_path(&local_path)?, RetentionRule::Keep).await?;
    println!("{}", keep_outcome(&local_path, &response)?);
    Ok(())
}

/// The report of a keep that kept everything it promises. The rule itself is recorded either way,
/// but a script must see that the item is not on this device yet (the daemon keeps retrying and
/// `materialization-status` shows it), and a version that is not yet in the store is only kept by
/// running the command again, so such a keep is an error carrying the same message.
fn keep_outcome(local_path: &str, response: &SetRetentionRuleResponse) -> Result<String, CliError> {
    let report = keep_report(local_path, response);
    if response.download_error.is_empty() && response.history_not_kept_reason.is_empty() {
        Ok(report)
    } else {
        Err(CliError::Other(report))
    }
}

/// Keeps nothing of a file or folder in the folder (File Provider folders): the copies on this
/// device are freed, and the content stays available online.
pub async fn online_only(local_path: String) -> Result<(), CliError> {
    let response =
        files::set_retention_rule(absolute_path(&local_path)?, RetentionRule::OnlineOnly).await?;
    println!("{}", online_only_report(&local_path, &response));
    Ok(())
}

/// Removes the rule set at a file or folder. Nothing is removed from disk.
pub async fn default_rule(local_path: String) -> Result<(), CliError> {
    let response =
        files::set_retention_rule(absolute_path(&local_path)?, RetentionRule::Default).await?;
    println!("{}", default_report(&local_path, &response));
    Ok(())
}

fn policy_of(retention: Option<&RetentionState>) -> Option<(RetentionPolicy, bool)> {
    retention
        .filter(|state| state.policy() != RetentionPolicy::Reclaimable)
        .map(|state| (state.policy(), state.explicit))
}

/// What `materialization-status` appends to the state word.
fn retention_suffix(retention: Option<&RetentionState>) -> &'static str {
    match policy_of(retention) {
        None => "",
        Some((RetentionPolicy::OnlineOnly, true)) => ", online only",
        Some((RetentionPolicy::OnlineOnly, false)) => ", online only (by a folder above)",
        Some((_, true)) => ", always kept on this device",
        Some((_, false)) => ", always kept on this device (by a folder above)",
    }
}

fn keep_report(local_path: &str, response: &SetRetentionRuleResponse) -> String {
    let mut report = if response.download_error.is_empty() {
        format!("{local_path} is always kept on this device")
    } else {
        format!(
            "{local_path} is always kept on this device, but it could not be downloaded yet: {}.",
            response.download_error
        )
    };
    let history = match response.history_not_kept_reason.as_str() {
        "" => None,
        "changing_retry" => Some(
            "Some files were changing, so their previous versions are not safely kept yet; run \
             the command again once they settle.",
        ),
        _ => {
            Some("The previous versions of its files could not be checked; run the command again.")
        }
    };
    if let Some(history) = history {
        report.push_str(". ");
        report.push_str(history);
    }
    report
}

fn online_only_report(local_path: &str, _response: &SetRetentionRuleResponse) -> String {
    format!(
        "{local_path} is now online only. Its copies on this device are being freed; the content \
         stays available online and downloads again when opened."
    )
}

fn default_report(local_path: &str, response: &SetRetentionRuleResponse) -> String {
    match policy_of(response.retention.as_ref()) {
        Some((RetentionPolicy::OnlineOnly, _)) => format!(
            "{local_path} follows a folder above it that is online only. Change that folder's rule \
             to change this one."
        ),
        Some(_) => format!(
            "{local_path} is still kept on this device because a folder above it is. Change that \
             folder's rule to stop keeping it."
        ),
        None => {
            format!("{local_path} has no rule of its own. Its content stays until you free it.")
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod evict_report_tests {
    use super::*;

    fn response(dehydrated: bool, reason: &str) -> EvictResponse {
        EvictResponse {
            dehydrated,
            blocks_reclaimed: 0,
            bytes_reclaimed: 0,
            retained_reason: reason.to_owned(),
            not_freed_reason: String::new(),
        }
    }

    #[test]
    fn an_eviction_that_freed_nothing_is_an_error() {
        let refused = evict_outcome("a.txt", &response(false, "")).unwrap_err();
        assert!(refused.to_string().contains("was not evicted"), "{refused}");
        assert!(evict_outcome("a.txt", &not_freed("busy")).is_err());
        assert!(evict_outcome("a.txt", &response(true, "")).unwrap().starts_with("Evicted"));
    }

    fn not_freed(reason: &str) -> EvictResponse {
        EvictResponse { not_freed_reason: reason.to_owned(), ..response(false, "") }
    }

    #[test]
    fn a_call_that_freed_nothing_says_why_in_the_users_words() {
        let text = evict_report("a.bin", &not_freed("path_changing"));
        assert!(text.contains("being changed or was only just downloaded"), "{text}");
        assert!(text.contains("Try again") && text.contains("path_changing"), "{text}");
        let text = evict_report("a.bin", &not_freed("differs_from_synced"));
        assert!(
            text.contains("not synced yet") && text.contains("Wait until it has synced"),
            "{text}"
        );
    }

    #[test]
    fn a_reason_that_needs_the_person_is_not_called_retryable() {
        let text = evict_report("a.bin", &not_freed("volume_not_durable"));
        assert!(!text.contains("Try again"), "{text}");
    }

    #[test]
    fn a_dropped_os_copy_without_custody_names_the_reason() {
        let text = evict_report("a.bin", &response(true, "custody_not_acquired"));
        assert!(text.contains("custody_not_acquired"), "{text}");
        assert!(text.contains("still kept on this device"), "{text}");
    }

    #[test]
    fn a_clean_eviction_says_only_evicted() {
        assert_eq!(
            evict_report("a.bin", &response(true, "")),
            "Evicted a.bin (converted to a placeholder)"
        );
    }

    #[test]
    fn a_retryable_refusal_says_why_and_when_to_retry() {
        let text = evict_report("a.bin", &response(false, "not_confirmed"));
        assert!(text.contains("not been confirmed") && text.contains("Try again"), "{text}");
        let text = evict_report("a.bin", &response(false, "host_refused"));
        assert!(text.contains("not shared yet") && text.contains("synced"), "{text}");
        let text = evict_report("a.bin", &response(false, "full_replica"));
        assert!(!text.contains("Try again"), "{text}");
    }

    #[test]
    fn every_reason_the_daemon_gives_has_wording() {
        for code in [
            "custody_not_acquired",
            "custody_required",
            "custody_unsupported",
            "full_replica",
            "busy",
            "host_busy",
            "version_moved",
            "nothing_freed",
            "held_as_history",
            "not_downloaded",
            "not_confirmed",
            "host_refused",
        ] {
            let refusal = files::evict_refusal(code).unwrap();
            assert!(!refusal.why.starts_with("the daemon kept"), "{code} has no wording");
            assert_eq!(refusal.retryable, !refusal.hint.is_empty(), "{code}");
        }
    }

    #[test]
    fn a_refusal_names_its_reason() {
        let text = evict_report("a.bin", &response(false, "host_busy"));
        assert!(text.contains("not evicted") && text.contains("host_busy"), "{text}");
    }
}
