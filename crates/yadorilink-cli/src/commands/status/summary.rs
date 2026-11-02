//! The default `yadorilink status` view: the product state on the first line, availability and
//! protection on the two lines under it, one row per folder, and the problems that need the
//! person, each with its command. Everything else (transfers, devices, limits, raw ids) is the
//! `--details` view. The state, the counts and the action are the daemon's (`ProductStatus`);
//! this module only chooses words, and never derives a state.

use yadorilink_client_core::attention::{
    protection::is_single_copy, Availability, ProductState, ProductStatusSummary, Protection,
};
use yadorilink_ipc_proto::daemonctl::{LinkStatus, StatusResponse};

use super::{
    device_label, folder_label, format_bytes, format_local_time, last_seen_suffix, now_unix,
    preserved_line, provider_root_lines, reason_subject, reasons, retained_line,
    update_summary_lines,
};
use crate::commands::device_names::DeviceNames;

pub(super) fn lines(status: &StatusResponse, names: &DeviceNames) -> Vec<String> {
    let mut lines = Vec::new();
    // A reply that carries no status reads as needing attention, as everywhere else.
    let device = ProductStatusSummary::from_wire(&status.product.clone().unwrap_or_default());

    lines.push(headline(status, &device));
    if !status.links.is_empty() {
        lines.push(availability_line(status, &device, names));
        lines.push(protection_line(status, &device, names));
    }
    lines.push(String::new());

    for group in &status.rebootstrapping_groups {
        lines.push(format!(
            "{}  replacing its state from a peer's sealed state (rebootstrap running); \
             its folder is paused until it ends",
            super::group_label(status, group)
        ));
    }
    lines.extend(preserved_line(status));
    lines.extend(retained_line(status));
    lines.extend(provider_root_lines(status, false));

    if status.links.is_empty() {
        lines.push("No linked folders.".to_string());
    }
    for link in &status.links {
        lines.push(folder_row(link, names));
    }

    let problems = problem_lines(status, names);
    if !problems.is_empty() {
        lines.push(String::new());
        lines.push(if problems.len() == 1 {
            "Needs attention: 1 item".to_string()
        } else {
            format!("Needs attention: {} items", problems.len())
        });
        lines.extend(problems);
    }

    let update = update_summary_lines(status);
    if !update.is_empty() {
        lines.push(String::new());
        lines.extend(update);
    }
    lines
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The state, with what is left to do while syncing.
fn headline(status: &StatusResponse, device: &ProductStatusSummary) -> String {
    match device.state {
        ProductState::UpToDate => "Up to date".to_string(),
        ProductState::Waiting => "Waiting".to_string(),
        ProductState::Paused => "Paused".to_string(),
        ProductState::NeedsAttention => "Needs attention".to_string(),
        ProductState::Syncing => {
            let mut parts = Vec::new();
            if !status.active_transfers.is_empty() {
                parts.push(plural(status.active_transfers.len(), "file", "files"));
            }
            if let Some(bytes) = device.bytes_remaining {
                parts.push(format!("{} left", format_bytes(bytes)));
            }
            if parts.is_empty() {
                "Syncing".to_string()
            } else {
                format!("Syncing {}", parts.join(", "))
            }
        }
    }
}

fn device_names(ids: &[String], names: &DeviceNames) -> String {
    ids.iter().map(|id| device_label(names, id, false)).collect::<Vec<_>>().join(", ")
}

/// "Can I open my files right now?" Offline devices carry when they were last seen, which is
/// information and never a problem.
fn availability_line(
    status: &StatusResponse,
    device: &ProductStatusSummary,
    names: &DeviceNames,
) -> String {
    let availability = &device.availability;
    match availability.availability {
        Availability::Available => {
            let others = availability.reachable_device_ids.len()
                + availability.offline_device_ids.len()
                + availability.update_required_device_ids.len();
            if availability.offline_device_ids.is_empty() {
                "All files available".to_string()
            } else {
                // This device counts as online and as one of the devices.
                format!(
                    "Available · {} of {} devices online",
                    availability.reachable_device_ids.len() + 1,
                    others + 1
                )
            }
        }
        Availability::WaitingForPeer => {
            let now = now_unix();
            let away: Vec<String> = availability
                .offline_device_ids
                .iter()
                .map(|id| {
                    let seen = status
                        .peers
                        .iter()
                        .find(|p| &p.device_id == id)
                        .map(|p| last_seen_suffix(p.last_connected_unix, now))
                        .unwrap_or_default();
                    format!("{} (offline{seen})", device_label(names, id, false))
                })
                .collect();
            format!("Waiting for {}", away.join(", "))
        }
        Availability::WaitingForExactContent => {
            "Waiting for a device that has this version".to_string()
        }
        Availability::UpdateRequired => {
            format!(
                "{} needs an update",
                device_names(&availability.update_required_device_ids, names)
            )
        }
        Availability::Unknown => "Can't tell right now".to_string(),
    }
}

/// "If this device is lost, are my files still elsewhere?"
fn protection_line(
    status: &StatusResponse,
    device: &ProductStatusSummary,
    names: &DeviceNames,
) -> String {
    let protection = &device.protection;
    match protection.protection {
        Protection::Protected if protection.device_ids.is_empty() => "Protected".to_string(),
        Protection::Protected => {
            format!("Protected · also on {}", device_names(&protection.device_ids, names))
        }
        Protection::Pending => {
            // Before the first round has finished nothing is known yet; afterwards a device is
            // catching up.
            if status.links.iter().any(|l| l.durability_check_pending) {
                "Checking".to_string()
            } else {
                "Making a copy…".to_string()
            }
        }
        Protection::AtRisk => {
            let at_risk = status.links.iter().filter(|l| {
                l.durability_status()
                    == yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::AtRisk
            });
            if at_risk.clone().all(is_single_copy) {
                "Only on this device · Add another device".to_string()
            } else {
                "Some files exist nowhere we can reach".to_string()
            }
        }
        Protection::Unknown => "Not confirmed yet".to_string(),
    }
}

/// One folder: its place, its state, and the detail that state is owed.
fn folder_row(link: &LinkStatus, names: &DeviceNames) -> String {
    let product = ProductStatusSummary::from_wire(&link.product.clone().unwrap_or_default());
    let place = folder_label(link);
    let detail = match product.state {
        ProductState::UpToDate => String::new(),
        ProductState::NeedsAttention => String::new(),
        ProductState::Syncing if link.durability_check_pending => "   (getting ready)".to_string(),
        ProductState::Syncing => String::new(),
        ProductState::Paused if link.paused_until_unix > 0 => {
            format!("   Paused until {}", until_text(link.paused_until_unix))
        }
        ProductState::Paused => String::new(),
        ProductState::Waiting => {
            let waiting = match product.availability.availability {
                Availability::WaitingForPeer => {
                    format!(
                        "Waiting for {}",
                        device_names(&product.availability.offline_device_ids, names)
                    )
                }
                Availability::UpdateRequired => format!(
                    "{} needs an update",
                    device_names(&product.availability.update_required_device_ids, names)
                ),
                Availability::WaitingForExactContent => {
                    "Waiting for a device that has this version".to_string()
                }
                // The daemon names no cause: say nothing the availability line does not.
                Availability::Available | Availability::Unknown => String::new(),
            };
            if waiting.is_empty() {
                waiting
            } else {
                format!("   {waiting}")
            }
        }
    };
    format!("  {place}   {}{detail}", product.state.label())
}

/// `HH:MM` on the day, as the local time `status` shows everywhere else, without the seconds.
fn until_text(unix: i64) -> String {
    let full = format_local_time(unix);
    let mut parts = full.splitn(3, ' ');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(date), Some(time), rest) if time.len() >= 5 => {
            let suffix = rest.map(|r| format!(" {r}")).unwrap_or_default();
            format!("{date} {}{suffix}", &time[..5])
        }
        _ => full,
    }
}

/// One numbered row per reason that needs the person: the cause and the command to run.
fn problem_lines(status: &StatusResponse, names: &DeviceNames) -> Vec<String> {
    status
        .attention_reasons
        .iter()
        .enumerate()
        .map(|(i, raw)| {
            let (code, arg) = reasons::split_code(raw);
            let subject = reason_subject(status, code, arg, names, false);
            format!("  {}. {}", i + 1, reasons::explain_reason(raw, &subject, false))
        })
        .collect()
}
