//! `yadorilink space show|on|off|preview`: automatic space management for provider folders.

use yadorilink_client_core::ops::storage;
use yadorilink_ipc_proto::daemonctl::{SpaceManagementSettings, SpaceReclaimVerdict};

use crate::error::CliError;

fn describe(settings: &SpaceManagementSettings) -> String {
    if settings.enabled {
        "Automatic space management is on: when free disk space gets low, downloaded files that are safe to give back are given back."
            .to_string()
    } else {
        "Automatic space management is off.".to_string()
    }
}

pub async fn show() -> Result<(), CliError> {
    println!("{}", describe(&storage::space_management().await?));
    Ok(())
}

pub async fn set(enabled: bool) -> Result<(), CliError> {
    println!("{}", describe(&storage::set_space_management(enabled).await?));
    Ok(())
}

/// What it would do now; nothing is removed.
pub async fn preview() -> Result<(), CliError> {
    let preview = storage::preview_space_reclaim().await?;
    println!("{}", preview_report(&preview));
    Ok(())
}

fn verdict_text(verdict: i32) -> &'static str {
    match SpaceReclaimVerdict::try_from(verdict) {
        Ok(SpaceReclaimVerdict::Eligible) => "would be given back",
        Ok(SpaceReclaimVerdict::Pinned) => "kept on this device",
        Ok(SpaceReclaimVerdict::UnsupportedRoot) => "this folder never gives space back",
        Ok(SpaceReclaimVerdict::CustodyUnavailable) => "no other device can confirm a copy now",
        Ok(SpaceReclaimVerdict::Busy) => "in use right now",
        Ok(SpaceReclaimVerdict::Changed) => "new or changing",
        Ok(SpaceReclaimVerdict::SafetyBlocked) => "cannot be checked safely now",
        Ok(SpaceReclaimVerdict::Unspecified) | Err(_) => "unknown",
    }
}

fn preview_report(
    preview: &yadorilink_ipc_proto::daemonctl::PreviewSpaceReclaimResponse,
) -> String {
    let mut lines: Vec<String> = preview
        .items
        .iter()
        .map(|item| format!("{}  {}: {}", item.group_id, item.path, verdict_text(item.verdict)))
        .collect();
    if lines.is_empty() {
        lines.push("No downloaded files in provider folders.".to_string());
    }
    if preview.unreadable_roots > 0 {
        lines.push(format!("{} folder(s) could not be read.", preview.unreadable_roots));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_ipc_proto::daemonctl::{PreviewSpaceReclaimResponse, SpaceReclaimPreviewItem};

    #[test]
    fn an_unknown_verdict_never_reads_as_eligible() {
        assert_eq!(verdict_text(0), "unknown");
        assert_eq!(verdict_text(99), "unknown");
        assert_eq!(verdict_text(SpaceReclaimVerdict::Eligible as i32), "would be given back");
    }

    #[test]
    fn the_preview_names_each_item_and_says_when_empty() {
        let empty = PreviewSpaceReclaimResponse::default();
        assert!(preview_report(&empty).contains("No downloaded files"));
        let one = PreviewSpaceReclaimResponse {
            items: vec![SpaceReclaimPreviewItem {
                group_id: "g".into(),
                path: "a.bin".into(),
                verdict: SpaceReclaimVerdict::Pinned as i32,
            }],
            unreadable_roots: 1,
        };
        let text = preview_report(&one);
        assert!(text.contains("a.bin: kept on this device") && text.contains("could not be read"));
    }

    #[test]
    fn the_setting_is_described_in_plain_words() {
        let off = describe(&SpaceManagementSettings { enabled: false });
        assert!(off.contains("off"));
    }
}
