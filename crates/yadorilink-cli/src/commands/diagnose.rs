//! CLI diagnostics bundle preview/export.
//!
//! The bundle comes from `yadorilink_client_core::ops::diagnostics`, which
//! prefers the daemon-assembled bundle and falls back to a limited
//! client-only bundle only when the daemon is not reachable at all. This
//! module prints or writes it.

use std::path::PathBuf;

use yadorilink_client_core::ops::diagnostics::{collect_bundle, BundleRequest};

use crate::error::CliError;

fn included_summary(collection_mode: &str) -> &'static str {
    match collection_mode {
        "daemon" => {
            "daemon-assembled bundle: status, links, recent errors, updates, resources, environment"
        }
        "daemon-partial" => {
            "daemon-assembled bundle (partial: generation hit its bounded time budget)"
        }
        _ => "schema/build/platform metadata, CLI daemon-unavailable fallback state",
    }
}

pub async fn preview() -> Result<(), CliError> {
    let collected = collect_bundle(BundleRequest::Preview).await?;
    println!("{}", serde_json::to_string_pretty(&collected.bundle)?);
    println!();
    println!("Included: {}", included_summary(&collected.collection_mode));
    println!("Redaction categories matched: {}", collected.redaction_count);
    Ok(())
}

pub async fn export(path: PathBuf) -> Result<(), CliError> {
    let collected = collect_bundle(BundleRequest::Export).await?;
    let contents = serde_json::to_string_pretty(&collected.bundle)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, contents)?;
    println!("Wrote diagnostics bundle to {}", path.display());
    println!("Included: {}", included_summary(&collected.collection_mode));
    println!("Redaction categories matched: {}", collected.redaction_count);
    Ok(())
}

#[cfg(test)]
mod tests;
