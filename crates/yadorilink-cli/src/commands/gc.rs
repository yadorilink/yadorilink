//! `yadorilink gc [--dry-run]`: triggers an immediate block-store
//! mark-and-sweep over the daemon control socket — the same round-trip
//! shape `limits.rs`/`materialization.rs` already establish for a simple
//! single-request-response daemon command.

use yadorilink_client_core::ops::storage;

use crate::error::CliError;

/// prints blocks/bytes actually deleted under a real sweep, or
/// blocks/bytes that *would* be deleted under `--dry-run` — see
/// `GcResponse`'s doc comment for why both share the same two fields.
pub async fn run(dry_run: bool) -> Result<(), CliError> {
    let report = storage::run_gc(dry_run).await?;
    println!("{}", format_gc_report(&report, dry_run));
    Ok(())
}

fn format_gc_report(report: &yadorilink_ipc_proto::daemonctl::GcResponse, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Dry run: would delete {} block(s), reclaiming {} bytes",
            report.blocks_deleted, report.bytes_reclaimed
        )
    } else {
        format!(
            "Deleted {} block(s), reclaimed {} bytes",
            report.blocks_deleted, report.bytes_reclaimed
        )
    }
}

#[cfg(test)]
mod tests;
