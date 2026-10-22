//! On-demand CLI commands: evict a file or show its materialization state
//! by its local path, resolved by the daemon against its registered links
//! (the same absolute-path resolution the shell-IPC hydration path uses).

use yadorilink_client_core::ops::files;
use yadorilink_ipc_proto::daemonctl::{
    local_state_word, EvictResponse, PinItemResponse, RetentionPolicy, RetentionState,
    UnpinItemResponse,
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
    files::hydrate_file(absolute_path(&local_path)?).await?;
    println!("Downloaded {local_path}");
    Ok(())
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
    println!("{}", evict_report(&local_path, &response));
    Ok(())
}

/// What one eviction did, in the user's words. The daemon keeps its cached blocks of a file
/// whenever no full replica took a durable lease on the version, even though the OS copy was
/// dropped; saying only "Evicted" then hides that no disk space was freed and why.
fn evict_report(local_path: &str, response: &EvictResponse) -> String {
    let refusal = files::evict_refusal(&response.retained_reason);
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
        (false, Some(why)) => format!(
            "{local_path} was not evicted: {}.{} [{}]",
            why.why,
            next(&why),
            response.retained_reason
        ),
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
pub async fn pin(local_path: String) -> Result<(), CliError> {
    let response = files::pin(absolute_path(&local_path)?).await?;
    println!("{}", pin_report(&local_path, &response));
    Ok(())
}

/// Stops keeping a file or folder. Nothing is removed; its space can be freed again.
pub async fn unpin(local_path: String) -> Result<(), CliError> {
    let response = files::unpin(absolute_path(&local_path)?).await?;
    println!("{}", unpin_report(&local_path, &response));
    Ok(())
}

fn is_pinned(retention: Option<&RetentionState>) -> Option<&RetentionState> {
    retention.filter(|state| state.policy() == RetentionPolicy::Pinned)
}

/// What `materialization-status` appends to the state word.
fn retention_suffix(retention: Option<&RetentionState>) -> &'static str {
    match is_pinned(retention) {
        None => "",
        Some(state) if state.explicit => ", always kept on this device",
        Some(_) => ", always kept on this device (by a folder above)",
    }
}

fn pin_report(local_path: &str, response: &PinItemResponse) -> String {
    if response.download_error.is_empty() {
        format!("{local_path} is always kept on this device")
    } else {
        format!(
            "{local_path} is always kept on this device, but it could not be downloaded yet: {}. \
             Run `yadorilink pin {local_path}` again to retry.",
            response.download_error
        )
    }
}

fn unpin_report(local_path: &str, response: &UnpinItemResponse) -> String {
    if is_pinned(response.retention.as_ref()).is_some() {
        format!(
            "{local_path} is still kept on this device because a folder above it is. Unpin that \
             folder to stop keeping it."
        )
    } else {
        format!(
            "{local_path} is no longer kept on this device. Its content stays until you free it."
        )
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
        }
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
