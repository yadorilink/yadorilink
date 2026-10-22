use std::io::{BufRead, IsTerminal, Write};

use yadorilink_ipc_proto::daemonctl::{HandoffResult, LinkStatus};
use yadorilink_local_storage::link_preflight::LinkPreflightReport;

use yadorilink_client_core::ops::links as ops;

use crate::error::CliError;

/// The ` skipped_symlinks=N` suffix appended to a link's summary line
/// in `link list` — empty (no suffix) when the link has none, matching
/// the same "no new fields rendered when a link has none" contract
/// (see `status.rs`'s `held_summary_suffix` for the
/// identical pattern used there). Always 0 on a non-Windows daemon
/// (`LinkStatus::skipped_symlink_count`'s own doc comment), so this
/// suffix never appears on this dev/CI environment's own real runs —
/// reviewed by inspection and covered by the unit test below, the same
/// honest limitation already documented for the Windows-only mechanism
/// itself.
fn skipped_symlink_suffix(link: &LinkStatus) -> String {
    if link.skipped_symlink_count == 0 {
        String::new()
    } else {
        format!("  skipped_symlinks={}", link.skipped_symlink_count)
    }
}

/// Supports `yadorilink link [--on-demand]`. Version retention is a fixed built-in policy (10
/// versions / 30 days) applied to every link, with nothing to configure here.
///
/// `--dry-run` runs the local preflight
/// (`yadorilink_local_storage::link_preflight`) and prints its findings
/// without ever contacting the daemon to register a link (so nothing is
/// persisted; no persisted writes occur). Otherwise, the same
/// preflight always runs first and its summary is always printed;
/// if it found a risky condition (non-empty folder, low disk
/// space, or a risky location), the link is only sent on if `--yes` was
/// passed or (in an interactive terminal) the user confirms — a risky link
/// attempted non-interactively without `--yes` exits non-zero instead
/// (spec.md's "Risk acknowledgement" scenario). Nested links are not a
/// risk but an unsupported topology: they are refused even with `--yes`.
pub async fn link(
    local_path: String,
    group_name: String,
    on_demand: bool,
    dry_run: bool,
    yes: bool,
) -> Result<(), CliError> {
    let (absolute, preflight) = ops::run_link_preflight(&local_path).await?;
    print_preflight_report(&preflight);

    if dry_run {
        println!(
            "dry run: no link registered ({})",
            if preflight.is_risky() { "risky conditions found" } else { "looks safe to link" }
        );
        return Ok(());
    }

    let acknowledged = acknowledge_if_risky(&preflight, yes)?;
    ops::link_to_named_group(absolute, &group_name, on_demand, acknowledged).await?;
    println!("Linked {local_path} to {group_name}{}", if on_demand { " (on-demand)" } else { "" },);
    Ok(())
}

/// Preflight a local path and resolve the risk acknowledgement, printing the
/// report. The shared front half of establishing a link, exposed so a caller
/// (e.g. `share create`/`share join`) can preflight BEFORE creating any
/// coordination-plane state. Those callers then commit through the daemon's
/// `CreateAndLink`/`JoinAndLink` commands, which write the link and its
/// pending-enrollment marker atomically.
pub async fn preflight_and_acknowledge(
    local_path: &str,
    yes: bool,
) -> Result<(std::path::PathBuf, bool), CliError> {
    let (absolute, preflight) = ops::run_link_preflight(local_path).await?;
    print_preflight_report(&preflight);
    let acknowledged = acknowledge_if_risky(&preflight, yes)?;
    Ok((absolute, acknowledged))
}

/// always prints a short factual summary of what preflight found
/// (empty/non-empty, ignored-entry count, free-space state), then one
/// `warning:` line per risky condition — printed
/// separately from the factual summary so a risky link's output is
/// unambiguous even when scrolled past quickly.
fn print_preflight_report(report: &LinkPreflightReport) {
    if !report.path_exists {
        for warning in report.warnings() {
            println!("warning: {warning}");
        }
        return;
    }
    println!(
        "preflight: {} ({} entr{}{}{})",
        if report.is_empty_folder() { "empty folder" } else { "non-empty folder" },
        report.entry_count,
        if report.entry_count == 1 { "y" } else { "ies" },
        if report.ignored_entry_count > 0 {
            format!(", {} ignored", report.ignored_entry_count)
        } else {
            String::new()
        },
        if report.scan_truncated { ", scan capped" } else { "" },
    );
    if let Some(space) = report.free_space {
        println!(
            "preflight: {} free space on target volume ({} bytes free, headroom {} bytes)",
            space.classify().as_str(),
            space.available_bytes,
            space.headroom_bytes,
        );
    }
    for warning in report.warnings() {
        println!("warning: {warning}");
    }
}

/// The acknowledgement gate. Returns whether the caller has
/// (or needed to) acknowledge a risky preflight result; only ever
/// `Err`ors when the preflight is risky and there is no way to
/// acknowledge it (non-interactive without `--yes`, or an interactive "no"
/// answer) — spec.md's "Risk acknowledgement" scenario ("exits non-zero
/// unless the matching acknowledgement flag is provided").
fn acknowledge_if_risky(report: &LinkPreflightReport, yes: bool) -> Result<bool, CliError> {
    // An unsupported topology is not a risk: neither `--yes` nor an
    // interactive confirmation reaches past it.
    let prohibitions = report.structural_prohibitions();
    if !prohibitions.is_empty() {
        return Err(CliError::Other(format!(
            "link refused (unsupported link topology): {}. Linked folders cannot be nested or \
             linked twice, and `--yes` does not override this; unlink the other folder first",
            prohibitions.join("; ")
        )));
    }
    if !report.is_risky() {
        return Ok(false);
    }
    if yes {
        return Ok(true);
    }
    if std::io::stdin().is_terminal() && confirm_risky(&report.warnings()) {
        return Ok(true);
    }
    Err(CliError::Other(format!(
        "link preflight found risky condition(s): {} -- re-run with --yes to proceed",
        report.warnings().join("; ")
    )))
}

/// Interactive risky-condition confirmation, factored the same way
/// `commands::report::confirm_with_reader` is: the prompt-reading itself is
/// unit-testable without a real terminal.
fn confirm_risky_with_reader(warnings: &[String], reader: &mut impl BufRead) -> bool {
    println!("This link has {} risk(s) listed above.", warnings.len());
    print!("Proceed with this risky link anyway? [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn confirm_risky(warnings: &[String]) -> bool {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    confirm_risky_with_reader(warnings, &mut lock)
}

/// `yadorilink unlink [--force]`. If this device is an eager full replica for
/// the folder's group, the daemon refuses the unlink fail-closed unless
/// another full replica is confirmed ready to durably hold every file
/// (`control_socket::ensure_unlink_keeps_a_full_replica`) -- without central
/// storage, this device could be giving up the group's only complete copy.
/// `--force` bypasses that gate for a genuinely dead sole replica that would
/// otherwise have no way to ever unlink; the daemon logs every forced
/// override as an audit trail regardless of whether it turned out to be
/// needed.
pub async fn unlink(local_path: String, force: bool) -> Result<(), CliError> {
    if force {
        eprintln!(
            "warning: --force set -- if this device is the sole complete copy for this \
             folder's group with no other confirmed-ready complete copy, unlinking anyway may \
             permanently lose the only copy of that data"
        );
    }
    let handoff_result = ops::send_unlink(&local_path, force).await?;
    println!("Unlinked {local_path}");
    if let Some(result) = handoff_result {
        println!("{}", handoff_line(&result));
    }
    Ok(())
}

pub async fn readopt(local_path: String) -> Result<(), CliError> {
    ops::readopt_volume(&local_path).await?;
    println!("Confirmed the disk at {local_path} as this folder's disk; it syncs again.");
    Ok(())
}

/// The line an unlink prints when it went through a coordination-plane
/// handoff commit.
fn handoff_line(result: &HandoffResult) -> String {
    format!(
        "  handoff completed: target={} membership_generation={}{}",
        result.target_device_id,
        result.membership_generation,
        if result.lease_id.is_empty() {
            String::new()
        } else {
            format!(" lease={}", result.lease_id)
        }
    )
}

fn short(root_id: &str) -> String {
    root_id.chars().take(8).collect()
}

fn links_lines(links: &[LinkStatus]) -> Vec<String> {
    let mut lines = Vec::new();
    if links.is_empty() {
        lines.push("No linked folders.".to_string());
    }
    for link in links {
        // A provider folder has no directory: it is shown by its name, never by its identity key.
        let place = if link.provider_display_name.is_empty() {
            link.local_path.clone()
        } else {
            format!(
                "provider folder '{}' (root {})",
                link.provider_display_name,
                short(&link.provider_root_id)
            )
        };
        lines.push(format!(
            "{}  group={}  {}{}{}{}{}",
            place,
            link.group_id,
            crate::commands::status::link_state_label(link),
            if link.conflict_count > 0 {
                format!("  conflicts={}", link.conflict_count)
            } else {
                String::new()
            },
            if link.conflicts_pending > 0 {
                format!("  conflicts_pending={}", link.conflicts_pending)
            } else {
                String::new()
            },
            // Only show the materialization breakdown for `ondemand` folders
            // -- an `eager` folder's files are always hydrated, so the
            // summary would be pure noise.
            if link.materialization_policy == "ondemand" {
                format!(
                    "  on-demand (hydrated={} placeholder={} hydrating={})",
                    link.hydrated_count, link.placeholder_count, link.hydrating_count
                )
            } else {
                String::new()
            },
            skipped_symlink_suffix(link),
        ));
    }
    lines
}

/// `yadorilink links`.
pub async fn list() -> Result<(), CliError> {
    for line in links_lines(&ops::list_links().await?) {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests;
