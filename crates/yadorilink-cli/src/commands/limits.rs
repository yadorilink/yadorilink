//! `yadorilink limits set --up <RATE> --down <RATE>` / `yadorilink limits
//! show` — global transfer rate limit management over the daemon control
//! socket. Rate arguments are typed as `u64` in `main.rs`'s `clap`
//! definition, so a negative or unparseable value is already rejected by
//! clap itself, with a clear error and a non-zero exit, before this
//! module's code ever runs.

use yadorilink_client_core::ops::storage;

use crate::error::CliError;

/// `0` reads as "unlimited" — mirrors `commands::status::format_rate_bytes_per_sec`'s
/// convention, but plain (no unit scaling): `limits set`/`limits show`
/// report the exact configured byte count, not a human-scaled
/// approximation, since a user setting `--up 1048576` wants to see that
/// value confirmed exactly.
fn format_limit(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        "unlimited".to_string()
    } else {
        format!("{bytes_per_sec} bytes/sec")
    }
}

pub async fn set(up: u64, down: u64) -> Result<(), CliError> {
    let applied = storage::set_bandwidth_limits(up, down).await?;
    println!(
        "Limits updated: up={}  down={}",
        format_limit(applied.upload_bytes_per_sec),
        format_limit(applied.download_bytes_per_sec)
    );
    Ok(())
}

pub async fn show() -> Result<(), CliError> {
    let current = storage::bandwidth_limits().await?;
    println!(
        "up={}  down={}",
        format_limit(current.upload_bytes_per_sec),
        format_limit(current.download_bytes_per_sec)
    );
    Ok(())
}

#[cfg(test)]
mod tests;
