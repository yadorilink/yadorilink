use yadorilink_ipc_proto::daemonctl::{
    DataProtection, FetchAvailability, GroupDurabilityStatus, LinkStatus, LocalStorageState,
    PeerReachability, PeerStatus, ProductAvailability, RouteKind, StatusResponse,
    UnreachableCategory, VolumeFreeSpace,
};

use crate::commands::device_names::DeviceNames;
use crate::error::CliError;

mod reasons;
mod switches;

/// The ` held=N` suffix appended to a link's summary line — empty
/// (rendering no suffix at all) when the link has no held files, so an
/// unaffected link's `status` output is byte-for-byte unchanged from
/// before this functionality was added (to ensure "no new fields rendered
/// when a link has none").
fn held_summary_suffix(link: &LinkStatus) -> String {
    if link.held_file_count == 0 {
        String::new()
    } else {
        format!("  held={}", link.held_file_count)
    }
}

/// One indented detail line per held file (path and reason), printed
/// directly beneath a link's summary line. Empty when the link has no
/// held files.
fn held_file_detail_lines(link: &LinkStatus, verbose: bool) -> Vec<String> {
    link.held_files
        .iter()
        .map(|h| {
            let sentence = reasons::explain_held(&h.reason);
            if verbose {
                format!("    held: {}  {sentence}  (code: {})", h.path, h.reason)
            } else {
                format!("    held: {}  {sentence}", h.path)
            }
        })
        .collect()
}

/// Most unreadable files `status` names per folder; the rest are counted.
const UNREADABLE_FILES_SHOWN: usize = 5;

/// One indented line per unreadable file (path and reason), capped, then a count of the rest.
/// Empty when the folder has none.
fn unreadable_file_detail_lines(link: &LinkStatus) -> Vec<String> {
    let mut lines: Vec<String> = link
        .unreadable_files
        .iter()
        .take(UNREADABLE_FILES_SHOWN)
        .map(|f| format!("    unreadable: {}  ({})", f.path, unreadable_reason_text(&f.reason)))
        .collect();
    let hidden = link.unreadable_file_count.saturating_sub(lines.len() as u64);
    if hidden > 0 {
        lines.push(format!("    ... and {hidden} more unreadable file(s)"));
    }
    lines
}

fn unreadable_reason_text(reason: &str) -> &str {
    match reason {
        "permission_denied" => "permission denied",
        "not_a_regular_file" => "not a regular file",
        "read_failed" => "read error",
        other => other,
    }
}

/// A device for people: "this device", or the name the account gives it, or (a device the account
/// list does not name, for instance another account's) the first eight characters of its id. Under
/// `--verbose` the full id follows a name, so a name can always be matched to an id.
fn device_label(names: &DeviceNames, device_id: &str, verbose: bool) -> String {
    let short = || {
        if verbose || device_id.chars().count() <= 8 {
            device_id.to_string()
        } else {
            format!("{}...", device_id.chars().take(8).collect::<String>())
        }
    };
    if names.is_own(device_id) {
        return if verbose {
            format!("this device ({device_id})")
        } else {
            "this device".to_owned()
        };
    }
    match names.name_of(device_id) {
        Some(name) if verbose => format!("{name} ({device_id})"),
        Some(name) => name.to_owned(),
        None => short(),
    }
}

/// What a link is called: its provider folder name, else its directory.
fn folder_label(link: &LinkStatus) -> String {
    if link.provider_display_name.is_empty() {
        link.local_path.clone()
    } else {
        format!("provider folder '{}'", link.provider_display_name)
    }
}

/// The folder name for a group id, or the id itself when no linked folder carries it.
fn group_label(status: &StatusResponse, group_id: &str) -> String {
    status
        .links
        .iter()
        .find(|l| l.group_id == group_id)
        .map(folder_label)
        .unwrap_or_else(|| group_id.to_string())
}

/// Local-time `YYYY-MM-DD HH:MM:SS` for unix seconds (marked UTC when the
/// platform cannot name its local zone).
pub(crate) fn format_local_time(unix: i64) -> String {
    if unix <= 0 {
        return "unknown time".to_string();
    }
    match super::local_time::utc_offset_secs(unix) {
        Some(offset) => super::local_time::format_with_offset(unix, offset),
        None => format!("{} UTC", super::local_time::format_with_offset(unix, 0)),
    }
}

/// One `    configured full copy: <device>  (available|offline|unknown)`
/// line per device in `link.full_replica_device_ids`.
///
/// Deliberately says "configured full copy," never "complete copy" --
/// `full_replica_device_ids` is a netmap-derived, CONTENT-BLIND
/// structural declaration (see `PeerAuthorityState::full_replica_devices_
/// for_group`'s own doc comment: "a device is DECLARED a full-replica
/// writer"), not the peer-confirmed content custody `durability_status`
/// (via `custody_confirmation_cache`) actually verifies. Labeling a
/// merely-declared, possibly-never-confirmed, still-catching-up peer
/// "complete copy (available)" would read as a stronger durability claim
/// than this daemon can back up -- exactly the kind of per-device
/// overclaim `durability_status` already exists to guard against at the
/// group level. This list is
/// connectivity-layer inventory ONLY; `durability_status` remains the
/// sole source of truth for whether the group is actually protected.
///
/// Per-device state: `available` requires the SAME device to appear in
/// `peers` with `Connected` reachability; `offline` requires it to
/// appear with an explicit `Unreachable` reachability (a POSITIVELY
/// known-down fact); anything else -- absent from `peers` entirely,
/// `Unspecified` or `Connecting` -- reads
/// `unknown`, since this daemon has no positive evidence either way for
/// those (an earlier version
/// conflated "never observed" with "known offline").
fn complete_copies_detail_lines(
    link: &LinkStatus,
    peers: &[PeerStatus],
    names: &DeviceNames,
    verbose: bool,
) -> Vec<String> {
    link.full_replica_device_ids
        .iter()
        .map(|device_id| {
            let reachability =
                peers.iter().find(|p| &p.device_id == device_id).map(|p| p.reachability());
            let incompatible =
                peers.iter().any(|p| &p.device_id == device_id && p.version_incompatible);
            let state = match reachability {
                // Online, but not a copy this device can use until the versions match.
                Some(PeerReachability::Connected) if incompatible => "update required",
                Some(PeerReachability::Connected) => "available",
                Some(PeerReachability::Unreachable) => "offline",
                _ => "unknown",
            };
            format!(
                "    configured full copy: {}  ({state})",
                device_label(names, device_id, verbose)
            )
        })
        .collect()
}

/// The ` degraded (<reason>)` suffix — same "empty unless applicable"
/// discipline as `held_summary_suffix`, so a healthy link's output line
/// is unaffected by this feature existing.
fn degraded_suffix(link: &LinkStatus) -> String {
    if link.degraded {
        format!("  degraded ({})", link.degraded_reason)
    } else {
        String::new()
    }
}

/// The `NOT SYNCING (this folder group is linked at N folders)` suffix — same
/// "empty unless applicable" discipline as `degraded_suffix`.
///
/// This state is not a degradation, it is a full stop: the group syncs nothing
/// at all until the user unlinks all but one of the folders. Without this the
/// refusal is a `tracing` line — loud in the daemon's log, invisible to the
/// person who has to act on it, who would see only a folder that has silently
/// stopped syncing.
///
/// Names every folder involved because unlinking is keyed by path: the paths
/// are the remedy, not decoration.
fn ambiguous_suffix(link: &LinkStatus) -> String {
    if !link.ambiguous {
        return String::new();
    }
    format!(
        "  NOT SYNCING (this folder group is linked at {} folders: {}; \
         unlink all but one to resume)",
        link.ambiguous_local_paths.len(),
        link.ambiguous_local_paths.join(", ")
    )
}

/// The ` durability unknown`/` durability: at risk` suffix — same
/// "empty unless applicable" discipline as `degraded_suffix`, but
/// deliberately the other way around: it renders *nothing extra* only for
/// the two states that are safe to leave as plain "syncing" text
/// (`Protected`, `Protecting`). an unset value always sends
/// `Unspecified`, which is treated exactly like `Unknown` here —
/// never silently shown as fine — so a link can never read as more durable
/// than this daemon can actually back up right now (most notably right
/// after a `--force` override bypassed the durability handoff gate for this
/// group).
fn durability_suffix(link: &LinkStatus) -> String {
    match link.durability_status() {
        GroupDurabilityStatus::Protected | GroupDurabilityStatus::Protecting => String::new(),
        GroupDurabilityStatus::Unknown if link.durability_check_pending => {
            "  durability checking".to_string()
        }
        GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => {
            "  durability unknown".to_string()
        }
        GroupDurabilityStatus::AtRisk => "  durability: at risk".to_string(),
    }
}

/// The ` on-demand (...)` suffix -- reads `link.
/// local_storage_state()` directly, the daemon's own TRUTHFUL derivation
/// (materialization policy AND actual current hydration state), rather
/// than reconstructing an equivalent judgment here from
/// `materialization_policy` plus the raw hydration counts (the earlier
/// version of this function did exactly that, string-comparing
/// `materialization_policy == "ondemand"` -- the anti-pattern the storage-state
/// model exists to eliminate). `PartiallyMaterialized` gets its own distinct
/// label rather than silently reading as either `FullCopy` or `OnDemand`:
/// an eager link still catching up is neither.
///
/// `Unspecified` an unset value
/// falls back to the raw `materialization_policy` string check ONLY for
/// this one legacy case -- rendering it identically to `FullCopy` would
/// silently drop the on-demand indicator for such a daemon. This is a
/// narrow, explicitly-scoped
/// compatibility fallback, not a reversion to reconstructing state from
/// raw fields for the common (current-daemon) case above.
fn local_storage_suffix(link: &LinkStatus) -> String {
    match link.local_storage_state() {
        LocalStorageState::FullCopy => String::new(),
        LocalStorageState::OnDemand => format!(
            "  on-demand (hydrated={} placeholder={} hydrating={})",
            link.hydrated_count, link.placeholder_count, link.hydrating_count
        ),
        LocalStorageState::PartiallyMaterialized => format!(
            "  making full copy (hydrated={} placeholder={} hydrating={})",
            link.hydrated_count, link.placeholder_count, link.hydrating_count
        ),
        // The daemon always sets this; the CLI and daemon ship together and
        // the control protocol version is checked exactly. An unset value is
        // therefore state the daemon could not determine, which is worth
        // saying rather than rendering as a healthy full copy.
        LocalStorageState::Unspecified => "  local storage unknown".to_string(),
    }
}

/// The ` fetch not confirmed`/` fetch availability unknown` suffix --
/// reads `link.fetch_availability()` directly, NEVER reconstructed from
/// peer reachability (that would make it a bare alias for connectivity,
/// exactly what this field exists to NOT be). Silent for `AvailableNow`,
/// the common case, same "empty unless applicable" discipline as
/// `degraded_suffix`. `Unspecified` an unset value reads
/// the same as `Unknown`, never as available.
fn fetch_availability_suffix(link: &LinkStatus) -> String {
    match link.fetch_availability() {
        FetchAvailability::AvailableNow => String::new(),
        FetchAvailability::UnavailableNow => "  fetch not confirmed".to_string(),
        FetchAvailability::Unknown | FetchAvailability::Unspecified => {
            "  fetch availability unknown".to_string()
        }
    }
}

fn device_list(ids: &[String], names: &DeviceNames) -> String {
    ids.iter().map(|id| device_label(names, id, true)).collect::<Vec<_>>().join(", ")
}

/// The `--details` lines for the folder's two product dimensions, read as the daemon derived them
/// (`LinkStatus.availability` / `.protection`), never recomputed from reachability: availability
/// says whether the exact content can be fetched now, protection whether the data would survive
/// losing this device. An unset or unknown value says so; it never reads as available or
/// protected.
fn dimension_detail_lines(link: &LinkStatus, names: &DeviceNames) -> Vec<String> {
    let reachable = &link.availability_reachable_device_ids;
    let offline = &link.availability_offline_device_ids;
    let update = &link.availability_update_required_device_ids;
    let total = reachable.len() + offline.len() + update.len();
    let counts = if total == 0 {
        String::new()
    } else {
        format!(" ({} of {total} other devices available)", reachable.len())
    };
    let availability = match link.availability() {
        ProductAvailability::Available => format!("available{counts}"),
        ProductAvailability::WaitingForPeer => {
            format!("waiting for {} to come online{counts}", device_list(offline, names))
        }
        ProductAvailability::WaitingForExactContent => {
            format!("waiting for a device that has this version{counts}")
        }
        ProductAvailability::UpdateRequired => format!(
            "update required on {} before this can sync{counts}",
            device_list(update, names)
        ),
        ProductAvailability::Unknown | ProductAvailability::Unspecified => {
            "unknown (cannot be confirmed now)".to_string()
        }
    };
    let protection = match link.protection() {
        DataProtection::Protected if link.protection_device_ids.is_empty() => {
            "protected".to_string()
        }
        DataProtection::Protected => {
            format!("protected (also on {})", device_list(&link.protection_device_ids, names))
        }
        DataProtection::AtRisk => "at risk (only this device holds the current content)".into(),
        DataProtection::Pending if link.protection_device_ids.is_empty() => {
            "pending (a copy is being made)".to_string()
        }
        DataProtection::Pending => format!(
            "pending (waiting for {} to confirm)",
            device_list(&link.protection_device_ids, names)
        ),
        DataProtection::Unknown | DataProtection::Unspecified => {
            "unknown (not enough evidence)".to_string()
        }
    };
    vec![format!("    availability: {availability}"), format!("    protection: {protection}")]
}

/// `0` reads as "unlimited" (matching `limits show`'s own convention);
/// otherwise a human-scaled `B/s`/`KiB/s`/`MiB/s`/`GiB/s`
/// value.
pub(crate) fn format_rate_bytes_per_sec(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        return "unlimited".to_string();
    }
    const UNITS: [&str; 4] = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
    let mut value = bytes_per_sec as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes_per_sec} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Renders `StatusResponse.overall_state`/`attention_reasons` — the same
/// daemon-computed rollup every UI client reads
/// — as `status`'s first line, so an automated test (or a user) can read
/// the same aggregate state from the CLI without any UI. Empty
/// `overall_state` an unset value renders nothing
/// at all, matching this file's "absent = no new output" convention for
/// every other additive field.
fn overall_state_lines(status: &StatusResponse, names: &DeviceNames, verbose: bool) -> Vec<String> {
    if status.overall_state.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!("Overall: {}", status.overall_state)];
    for raw in &status.attention_reasons {
        let (code, arg) = reasons::split_code(raw);
        let subject = reason_subject(status, code, arg, names, verbose);
        lines.push(format!("  - {}", reasons::explain_reason(raw, &subject, verbose)));
    }
    lines
}

/// The name a reason refers to: a folder or provider folder name, a short device id, a path or an
/// error category. Raw ids appear only under `--verbose`.
fn reason_subject(
    status: &StatusResponse,
    code: &str,
    arg: &str,
    names: &DeviceNames,
    verbose: bool,
) -> String {
    match code {
        "degraded"
        | "waiting_for_disk_space"
        | "file_watch_limit"
        | "ambiguous"
        | "ownership_lost"
        | "not_joined"
        | "durability_at_risk"
        | "durability_unknown"
        | "fetch_unavailable"
        | "fetch_availability_unknown"
        | "conflict"
        | "approval_pending"
        | "volume_changed"
        | "volume_unconfirmed"
        | "held"
        | "stranded_directory"
        | "unreadable_files" => group_label(status, arg),
        // The removals list that could not be read (see the daemon's `overall_status`).
        "provider_not_ready" if arg == "removals" => "provider folder removals".to_owned(),
        "provider_not_ready" | "provider_stuck" | "kept_edits" => status
            .provider_roots
            .iter()
            .find(|r| r.root_id == arg)
            .map(|r| format!("provider folder '{}'", r.display_name))
            .unwrap_or_default(),
        "peer_disconnected" | "peer_update_required" => device_label(names, arg, verbose),
        "provider_orphan_domain" => {
            if verbose {
                arg.to_string()
            } else {
                String::new()
            }
        }
        _ => arg.to_string(),
    }
}

/// What rebootstraps set aside, when there is any; names `yadorilink preserved list` and
/// `discard` when the total is above the configured size.
/// The provider roots: why one is not ready, its Eager progress and stuck files, and the edits kept
/// beside a file instead of replacing it.
fn provider_root_lines(status: &StatusResponse, verbose: bool) -> Vec<String> {
    let id = |root_id: &str| if verbose { format!(" ({root_id})") } else { String::new() };
    let mut lines = Vec::new();
    for root in &status.provider_roots {
        lines.push(format!(
            "provider folder {}{}: {}",
            root.display_name,
            id(&root.root_id),
            root.readiness
        ));
        if root.counters_unreadable {
            // The zeros below would be "nothing known", not "nothing to do".
            lines.push("  counters: unknown (could not be read)".to_owned());
            continue;
        }
        if root.eager {
            lines.push(format!(
                "  downloading: {}, {} file(s) on this Mac, {} to fetch, {} in progress",
                root.eager_state, root.eager_current, root.eager_remote, root.eager_hydrating
            ));
            for stuck in &root.stuck {
                lines.push(format!(
                    "  stuck: {} ({} failed attempt(s))",
                    stuck.path, stuck.failures
                ));
            }
        }
        if root.pending_publications > 0 {
            lines.push(format!(
                "  waiting for the OS to take the new version (file in use or release pending): {}, oldest: {}",
                root.pending_publications,
                age_text(root.pending_oldest_ms)
            ));
        }
        if root.unconfirmed_publications > 0 {
            lines.push(format!(
                "  released but not yet confirmed by the OS: {}, oldest: {}",
                root.unconfirmed_publications,
                age_text(root.unconfirmed_oldest_ms)
            ));
        }
        if root.kept_edits > 0 {
            lines.push(format!(
                "  edits kept beside the file: {}, oldest: {}",
                root.kept_edits,
                age_text(root.kept_edits_oldest_ms)
            ));
        }
    }
    for removal in &status.provider_removals {
        if removal.unreadable {
            // Stands in for the whole list: nothing is known about removals.
            lines.push(format!("provider folder removals: {}", removal.display_name));
            continue;
        }
        lines.push(if removal.removed {
            if removal.preserved_location.is_empty() {
                format!(
                    "provider folder {}{}: removed; the downloaded files were kept by the operating system",
                    removal.display_name,
                    id(&removal.root_id)
                )
            } else {
                format!(
                    "provider folder {}{}: removed; the downloaded files are kept at {}",
                    removal.display_name,
                    id(&removal.root_id),
                    removal.preserved_location
                )
            }
        } else {
            format!(
                "provider folder {}{}: removing (waiting for the app to remove the domain)",
                removal.display_name,
                id(&removal.root_id)
            )
        });
    }
    for orphan in &status.orphan_domains {
        lines.push(format!(
            "File Provider domain {orphan} belongs to no folder this database knows; it is kept so you can recover it"
        ));
    }
    lines
}

/// An age in milliseconds as a short human text.
fn age_text(ms: u64) -> String {
    match ms / 1000 {
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86_400),
    }
}

/// The disk originals a rebootstrap kept take, when there are any.
fn retained_line(status: &StatusResponse) -> Option<String> {
    let preserved = status.preserved.as_ref()?;
    if preserved.retained_originals == 0 {
        return None;
    }
    Some(format!(
        "Kept originals: {} original(s) kept because removing them could not be proved safe; \
         see `yadorilink preserved retained list` for the disk they take, \
         try `yadorilink preserved retained release`",
        preserved.retained_originals
    ))
}

fn preserved_line(status: &StatusResponse) -> Option<String> {
    let preserved = status.preserved.as_ref()?;
    if preserved.total == 0 && preserved.unreplayed_own_units == 0 {
        return None;
    }
    let mut line = format!(
        "Preserved: {} version(s) ({} bytes, {} with unavailable content, {} without a record), \
         {} own change(s) not replayed",
        preserved.total,
        preserved.bytes,
        preserved.content_unavailable,
        preserved.record_unavailable,
        preserved.unreplayed_own_units
    );
    if preserved.warn {
        line.push_str(&format!(
            "  -- above {} bytes: see `yadorilink preserved list`, discard what you no longer need",
            preserved.warn_bytes
        ));
    }
    Some(line)
}

/// `yadorilink status`'s configured-limits/current-rate summary
/// line.
fn limits_summary_line(status: &StatusResponse) -> String {
    format!(
        "Limits: up={} down={}  (current: up={} down={})",
        format_rate_bytes_per_sec(status.upload_limit_bytes_per_sec),
        format_rate_bytes_per_sec(status.download_limit_bytes_per_sec),
        format_rate_bytes_per_sec(status.current_upload_bytes_per_sec),
        format_rate_bytes_per_sec(status.current_download_bytes_per_sec),
    )
}

/// How a peer's connectivity is shown. A peer is either being connected,
/// connected (directly, or through a relay server when no direct path is
/// up), or honestly cannot be connected — in which case the reason (its
/// failure category) is shown so the user understands why. A daemon that has
/// not yet determined a peer's reachability leaves it unspecified, shown as
/// "unknown".
fn peer_connectivity_label(peer: &PeerStatus) -> String {
    // Online but on another version: never "cannot connect", the fix is to update.
    if peer.version_incompatible && peer.reachability() == PeerReachability::Connected {
        return "reachable, update required".to_string();
    }
    match peer.reachability() {
        PeerReachability::Connected if peer.route_kind() == RouteKind::Relay => {
            "connected (via relay)".to_string()
        }
        PeerReachability::Connected => "connected".to_string(),
        PeerReachability::Connecting => "connecting".to_string(),
        PeerReachability::Unreachable => {
            format!("cannot connect ({})", unreachable_category_label(peer.unreachable_category()))
        }
        PeerReachability::Unspecified => "unknown".to_string(),
    }
}

/// Human-readable form of a `PeerStatus.unreachable_category`.
fn unreachable_category_label(category: UnreachableCategory) -> &'static str {
    match category {
        UnreachableCategory::NoCandidates => "no known address",
        UnreachableCategory::NoResponse => "no response",
        UnreachableCategory::UdpBlocked => "UDP blocked",
        UnreachableCategory::HandshakeRefused => "handshake refused",
        UnreachableCategory::DeviceReplaced => "this device was replaced by another device",
        UnreachableCategory::Unspecified => "unknown reason",
    }
}

/// one line per volume's free-space state.
fn volume_line(volume: &VolumeFreeSpace) -> String {
    format!(
        "  {}  {}  (available={} headroom={})",
        volume.path, volume.state, volume.available_bytes, volume.headroom_bytes
    )
}

/// Byte-count formatter, shared in shape with `format_rate_bytes_per_sec`
/// above minus the `/s` suffix — block-store usage and the reclaimable
/// estimate are point-in-time totals, not rates.
pub(crate) fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// a relative "how long ago" for `StatusResponse.last_gc_unix` —
/// "never" if a real (non-dry-run) sweep has never completed since this
/// daemon's block store was created (`0`, matching `GcState`'s own "0 = no
/// completed sweep" convention).
fn last_gc_summary(last_gc_unix: i64) -> String {
    if last_gc_unix <= 0 {
        return "never".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let elapsed = (now - last_gc_unix).max(0);
    if elapsed < 60 {
        format!("{elapsed}s ago")
    } else if elapsed < 3600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86400 {
        format!("{}h ago", elapsed / 3600)
    } else {
        format!("{}d ago", elapsed / 86400)
    }
}

/// `yadorilink status`'s block-store usage/GC-health summary
/// line — always rendered (unlike this file's "empty unless applicable"
/// suffixes), since usage/last-GC-time is always meaningful, matching
/// `limits_summary_line`'s own "always shown" precedent immediately above.
fn block_store_summary_line(status: &StatusResponse) -> String {
    format!(
        "Block store: {} block(s), {} used  (last GC: {}, ~{} reclaimable)",
        status.block_store_block_count,
        format_bytes(status.block_store_total_bytes),
        last_gc_summary(status.last_gc_unix),
        format_bytes(status.gc_reclaimable_estimate_bytes),
    )
}

/// This link's active-transfer headline — empty unless
/// `has_active_transfer` (this file's established "empty unless
/// applicable" discipline, matching `degraded_suffix`/
/// `held_summary_suffix`). The ETA is explicitly labelled `~`
/// (best-effort) rather than presented as precise.
/// "syncing", "paused", or "paused (resumes in 29m)" for a timed pause.
pub(crate) fn link_state_label(link: &yadorilink_ipc_proto::daemonctl::LinkStatus) -> String {
    if !link.paused {
        return "syncing".to_string();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    timed_pause_label(link.paused_until_unix, now)
}

fn timed_pause_label(paused_until_unix: i64, now_unix: i64) -> String {
    if paused_until_unix <= 0 {
        return "paused".to_string();
    }
    let minutes = ((paused_until_unix - now_unix).max(0) + 59) / 60;
    let left = if minutes >= 60 {
        format!("{}h {}m", minutes / 60, minutes % 60)
    } else {
        format!("{minutes}m")
    };
    format!("paused (resumes in {left})")
}

fn transfer_progress_suffix(link: &LinkStatus) -> String {
    if !link.has_active_transfer {
        return String::new();
    }
    let pct = if link.transfer_bytes_total > 0 {
        (link.transfer_bytes_done as f64 / link.transfer_bytes_total as f64 * 100.0).round() as u64
    } else {
        0
    };
    let eta = if link.transfer_eta_seconds > 0 {
        format!(" eta~{}s", link.transfer_eta_seconds)
    } else {
        String::new()
    };
    format!(
        "  transferring {pct}% ({}/{} bytes, {}/{} blocks){eta}",
        link.transfer_bytes_done,
        link.transfer_bytes_total,
        link.transfer_blocks_done,
        link.transfer_blocks_total,
    )
}

/// One line per currently-active transfer — the per-file
/// detail underlying every link's headline `transfer_progress_suffix`.
fn active_transfer_detail_lines(status: &StatusResponse) -> Vec<String> {
    status
        .active_transfers
        .iter()
        .map(|t| {
            let pct = if t.bytes_total > 0 {
                (t.bytes_done as f64 / t.bytes_total as f64 * 100.0).round() as u64
            } else {
                0
            };
            format!(
                "  {}  {pct}%  ({}/{} bytes, {}/{} blocks)  from={}",
                t.path, t.bytes_done, t.bytes_total, t.blocks_done, t.blocks_total, t.source_peer
            )
        })
        .collect()
}

/// The bounded recent-error feed, newest first (matching the
/// daemon's own `RecentErrorLog::recent` ordering) — every field here is
/// already a coarse category/timestamp/context string (never a path/key/
/// token/IP, satisfying redaction requirements), so this renders it as-is.
fn recent_errors_summary_lines(status: &StatusResponse) -> Vec<String> {
    status
        .recent_errors
        .iter()
        .map(|e| {
            format!(
                "  {}  ({})  {}",
                e.category,
                e.coarse_context,
                format_local_time(e.timestamp_unix)
            )
        })
        .collect()
}

/// Concise update-state lines for `yadorilink status`, only rendered
/// when there's something worth surfacing (spec "Status surfaces
/// available update"/"Status surfaces failed update") — a healthy,
/// up-to-date daemon's `status` output is otherwise unaffected by this
/// feature existing, matching this file's own "empty unless applicable"
/// convention (`held_summary_suffix`, `degraded_suffix`,...).
fn update_summary_lines(status: &StatusResponse) -> Vec<String> {
    let mut lines = Vec::new();
    if !status.update_available_version.is_empty() {
        let install_plan = if status.update_required {
            "required; download it with `yadorilink update download`"
        } else if status.update_mandatory {
            "mandatory; download it with `yadorilink update download`"
        } else if !status.update_holdback_reason.is_empty() {
            "held back"
        } else {
            "available"
        };
        lines.push(format!("Update: {} ({install_plan})", status.update_available_version));
        if !status.update_holdback_reason.is_empty() {
            lines.push(format!("  {}", status.update_holdback_reason));
        }
    }
    if !status.update_last_error_category.is_empty() {
        lines.push(format!(
            "Update error: {}",
            reasons::explain_reason(
                &format!("update_failed:{}", status.update_last_error_category),
                "",
                false
            )
        ));
    }
    lines
}

/// `yadorilink status`, optionally re-polling and re-rendering on an
/// interval (`--watch`) instead of printing one snapshot and exiting —
/// useful for watching a big sync's per-transfer progress live rather
/// than re-running the command by hand. A plain `yadorilink status`
/// (`watch = false`) is byte-for-byte the same single-snapshot behavior
/// as before this flag existed.
pub async fn status(watch: bool, verbose: bool) -> Result<(), CliError> {
    if !watch {
        return render_status_once(verbose).await;
    }
    loop {
        render_status_once(verbose).await?;
        println!();
        println!("--- refreshing every 2s (Ctrl-C to stop) ---");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// `status --json`: the folder list and the overall answer with the availability and protection
/// dimensions, as the stable snake_case names `yadorilink-product-view` documents.
pub async fn status_as_json() -> Result<(), CliError> {
    let status = yadorilink_client_core::ops::folders::status().await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&yadorilink_client_core::dto::status_dimensions_json(
            &status
        ))?
    );
    Ok(())
}

/// `status --pending-items N`: the publications waiting on the OS, oldest first.
pub async fn pending_items(limit: u32, verbose: bool) -> Result<(), CliError> {
    let items = yadorilink_client_core::ops::storage::list_provider_pending(limit).await?;
    if items.is_empty() {
        println!("Nothing is waiting on the operating system.");
    }
    for item in &items {
        if verbose {
            println!("  waiting: {} ({}): {}", item.path, item.root_id, age_text(item.age_ms));
        } else {
            println!("  waiting: {}: {}", item.path, age_text(item.age_ms));
        }
    }
    Ok(())
}

async fn render_status_once(verbose: bool) -> Result<(), CliError> {
    let status = match yadorilink_client_core::ops::folders::status().await {
        Ok(status) => status,
        Err(yadorilink_client_core::CoreError::DaemonNotRunning) => {
            if let Some(hint) = switches::background_service_hint() {
                eprintln!("{hint}");
            }
            return Err(yadorilink_client_core::CoreError::DaemonNotRunning.into());
        }
        Err(e) => return Err(e.into()),
    };
    // Names are looked up only when the output names a device, and never fail the command.
    let names =
        if names_a_device(&status) { DeviceNames::load().await } else { DeviceNames::default() };
    for line in status_lines(&status, &names, verbose) {
        println!("{line}");
    }
    // Blocking, but a few milliseconds; the watch loop calls it every two seconds at most.
    let extensions =
        tokio::task::spawn_blocking(switches::extension_lines).await.unwrap_or_default();
    if !extensions.is_empty() {
        println!();
        for line in extensions {
            println!("{line}");
        }
    }
    Ok(())
}

/// Whether the output has a device to name: a peer, a configured full copy or a reason about a device.
fn names_a_device(status: &StatusResponse) -> bool {
    !status.peers.is_empty()
        || status
            .links
            .iter()
            .any(|l| !l.full_replica_device_ids.is_empty() || !l.protection_device_ids.is_empty())
        || status.attention_reasons.iter().any(|r| {
            matches!(reasons::split_code(r).0, "peer_disconnected" | "peer_update_required")
        })
}

/// Every line one `yadorilink status` rendering prints, in order.
fn status_lines(status: &StatusResponse, names: &DeviceNames, verbose: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let overall = overall_state_lines(status, names, verbose);
    if !overall.is_empty() {
        lines.extend(overall);
        lines.push(String::new());
    }

    for group in &status.rebootstrapping_groups {
        let name = if verbose {
            format!("{} (group={group})", group_label(status, group))
        } else {
            group_label(status, group)
        };
        lines.push(format!(
            "{name}  replacing its state from a peer's sealed state (rebootstrap running); \
             its folder is paused until it ends"
        ));
    }
    if let Some(line) = preserved_line(status) {
        lines.push(line);
    }
    if let Some(line) = retained_line(status) {
        lines.push(line);
    }
    lines.extend(provider_root_lines(status, verbose));
    if status.undecided_uploads > 0 {
        lines.push(format!(
            "undecided uploads: {}, oldest: {}",
            status.undecided_uploads,
            age_text(status.undecided_uploads_oldest_ms)
        ));
    }

    if status.links.is_empty() {
        lines.push("No linked folders.".to_string());
    }
    for link in &status.links {
        let state = link_state_label(link);
        let materialization = local_storage_suffix(link);
        let held = held_summary_suffix(link);
        let degraded = degraded_suffix(link);
        let transfer = transfer_progress_suffix(link);
        let durability = durability_suffix(link);
        let fetch_availability = fetch_availability_suffix(link);
        let ambiguous = ambiguous_suffix(link);
        // A provider folder has no directory: it is named, never shown by its identity key.
        let place = folder_label(link);
        let group = if verbose { format!("  group={}", link.group_id) } else { String::new() };
        let pending = if link.conflicts_pending > 0 {
            format!("  conflicts_pending={}", link.conflicts_pending)
        } else {
            String::new()
        };
        lines.push(format!(
            "{place}{group}  {state}  conflicts={}{pending}{materialization}{held}{degraded}{transfer}{durability}{fetch_availability}{ambiguous}",
            link.conflict_count
        ));
        if !link.conflict_note.is_empty() {
            lines.push(format!("  {}", link.conflict_note));
        }
        lines.extend(held_file_detail_lines(link, verbose));
        lines.extend(unreadable_file_detail_lines(link));
        lines.extend(complete_copies_detail_lines(link, &status.peers, names, verbose));
        if verbose {
            lines.extend(dimension_detail_lines(link, names));
        }
    }

    if !status.peers.is_empty() {
        lines.push(String::new());
        lines.push("Peers:".to_string());
        for peer in &status.peers {
            let connectivity = peer_connectivity_label(peer);
            lines.push(format!(
                "  {}  {connectivity}",
                device_label(names, &peer.device_id, verbose)
            ));
        }
    }

    let transfer_lines = active_transfer_detail_lines(status);
    if !transfer_lines.is_empty() {
        lines.push(String::new());
        lines.push("Active transfers:".to_string());
        lines.extend(transfer_lines);
    }

    lines.push(String::new());
    lines.push(limits_summary_line(status));
    lines.push(block_store_summary_line(status));

    if !status.volumes.is_empty() {
        lines.push("Volumes:".to_string());
        for volume in &status.volumes {
            lines.push(volume_line(volume));
        }
    }

    let update_lines = update_summary_lines(status);
    if !update_lines.is_empty() {
        lines.push(String::new());
        lines.extend(update_lines);
    }

    let error_lines = recent_errors_summary_lines(status);
    if !error_lines.is_empty() {
        lines.push(String::new());
        lines.push("Recent errors:".to_string());
        lines.extend(error_lines);
    }
    lines
}

#[cfg(test)]
mod tests;
