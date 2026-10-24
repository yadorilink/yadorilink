//! Link preflight — the checks that run before a folder is actually
//! linked, so a first-time user gets a clear picture of what's about to
//! happen instead of finding out the hard way. Shared by `yadorilink-cli`
//! (the client-side preflight/dry-run/interactive-confirmation gate,
//! `yadorilink link` and `--dry-run`) and `yadorilink-daemon` (a
//! defense-in-depth re-check at the actual registration point,
//! `control_socket::link`) — a single computed report always backs both,
//! the same "never two independently-computed answers that could
//! disagree" discipline `yadorilink_local_storage::free_space`'s own
//! module doc comment already documents for disk-pressure checks (this
//! module reuses that exact classification rather than re-deriving it).
//!
//! Deliberately local-only and fast ("keep checks local and
//! fast; deep scans can be optional for huge folders"): the directory scan
//! below is capped at [`SCAN_ENTRY_CAP`] entries, so a preflight on a huge
//! folder still returns promptly with `scan_truncated: true` rather than
//! walking the whole tree.

use std::path::Path;

use crate::free_space::{self, FreeSpaceState, VolumeFreeSpace};

use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;

/// Directory-scan cap (handling huge folders by making deep scans optional): once this many entries
/// (ignored or not) have been visited, the scan stops early and
/// `scan_truncated` is set, rather than walking an arbitrarily large tree
/// before a first-run user even sees a preflight result.
pub const SCAN_ENTRY_CAP: u64 = 50_000;

/// Well-known cloud-provider-managed folder names (used to identify risky
/// folder locations). Matched case-insensitively against
/// any path component, not just the last one, since the marker folder is
/// often an ancestor of the folder actually being linked (e.g. linking
/// `~/Dropbox/Photos` rather than `~/Dropbox` itself).
const CLOUD_PROVIDER_MARKERS: &[&str] = &[
    "Dropbox",
    "OneDrive",
    "Google Drive",
    "GoogleDrive",
    "Mobile Documents",
    "com~apple~CloudDocs",
    "Box Sync",
    "pCloud Drive",
    "Nextcloud",
    "Nextcloud Sync Client",
];

/// How an about-to-be-linked path relates to an already-linked path — useful for
/// risky location detection and handling nested-link scenarios (implied by
/// obvious conflict risks in the first-run safety guidelines).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NestedLinkRelation {
    /// The already-linked path is an ancestor of the folder being linked
    /// (linking a subfolder of an existing link).
    Ancestor,
    /// The already-linked path is a descendant of the folder being linked
    /// (linking a folder that already contains an existing link).
    Descendant,
    /// The exact same path is already linked.
    Same,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedLinkConflict {
    pub other_path: String,
    pub relation: NestedLinkRelation,
}

impl NestedLinkConflict {
    /// Whether this relation is an unsupported topology that no
    /// acknowledgement can accept: a linked folder inside or containing
    /// another linked folder. An exact-path match is not decided here -- it
    /// is only a conflict against a link of a DIFFERENT group, which only the
    /// daemon, holding the groups, can tell apart from an idempotent
    /// re-link.
    pub fn is_structural(&self) -> bool {
        matches!(self.relation, NestedLinkRelation::Ancestor | NestedLinkRelation::Descendant)
    }

    /// The refusal text for this conflict, naming the other link.
    pub fn refusal(&self) -> String {
        match self.relation {
            NestedLinkRelation::Ancestor => {
                format!("{} is already linked and is an ancestor of this folder", self.other_path)
            }
            NestedLinkRelation::Descendant => {
                format!("{} is already linked and is nested inside this folder", self.other_path)
            }
            NestedLinkRelation::Same => {
                format!("{} is already linked to a different folder group", self.other_path)
            }
        }
    }
}

/// Risky/unsupported first-run environment conditions (used for risky location
/// detection and generating unsupported environment warnings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskyLocation {
    /// Under a known cloud-provider-managed folder (Dropbox, OneDrive,
    /// Google Drive, iCloud Drive,...) whose own sync client may fight
    /// with this one over the same files.
    CloudProviderFolder(&'static str),
    /// The filesystem root itself (`/`, `C:\`,...).
    FilesystemRoot,
    /// The current user's home directory itself, rather than a folder
    /// inside it.
    HomeDirectory,
}

/// The full preflight model: folder existence, empty/non-empty
/// state, free-space state, ignored-file summary, and risky-location
/// detection, plus nested-link conflicts against the caller-supplied list
/// of already-linked paths.
#[derive(Debug, Clone, Default)]
pub struct LinkPreflightReport {
    pub path_exists: bool,
    pub is_directory: bool,
    /// Count of entries (files and directories, recursive) that are *not*
    /// matched by the link's effective ignore rules — this is what "would
    /// participate in initial reconciliation" per the non-empty-folder
    /// scenario.
    pub entry_count: u64,
    /// Count of entries matched by the effective ignore rules (built-in
    /// defaults plus any `.yadorilinkignore`) — this forms the ignored-file
    /// summary.
    pub ignored_entry_count: u64,
    /// Sum of file sizes among the non-ignored entries counted above.
    pub total_size_bytes: u64,
    /// Set when the scan hit [`SCAN_ENTRY_CAP`] before finishing — the
    /// counts above are a lower bound, not exact, for a folder this large.
    pub scan_truncated: bool,
    /// `None` when the free-space query itself failed (e.g. an
    /// unsupported filesystem) rather than when space is fine — callers
    /// should treat that as "unknown", not "ok".
    pub free_space: Option<VolumeFreeSpace>,
    pub nested_conflicts: Vec<NestedLinkConflict>,
    pub risky_location: Option<RiskyLocation>,
    /// Set when this folder's effective ignore rules could not be read (a
    /// corrupt or unreadable `.yadorilinkignore`). The scan below then falls
    /// back to the built-in defaults, so the ignored/non-ignored counts do
    /// NOT reflect the user's own exclusion rules — files they meant to
    /// exclude may be counted as syncing. Treated as a risky condition so
    /// link setup surfaces it (and requires acknowledgement) rather than
    /// silently proceeding as if no custom ignore rules existed.
    pub ignore_rules_unreadable: bool,
    /// Root-relative paths this scan found that collide with the reserved
    /// artefact namespace (`reserved_namespace`) — a file or directory
    /// existing under this name before the folder is ever linked. Counted
    /// inside `ignored_entry_count` too (a collision never participates in
    /// sync either way), but named here explicitly rather than only
    /// blending into the ordinary ignored-file summary: an ignore-pattern
    /// match is a user choice the user can undo by editing
    /// `.yadorilinkignore`, while this is a naming collision with the
    /// engine's own on-disk protocol that the user cannot undo that way at
    /// all — they can only rename the file. Surfacing it separately, by
    /// path, is what `Blocked(ReservedNamespaceCollision)` means for a
    /// path this preflight discovers before the folder is ever linked, so
    /// it does not read as an ordinary, dismissible ignore-pattern match.
    pub reserved_namespace_blocked_paths: Vec<String>,
}

impl LinkPreflightReport {
    /// Refusals no acknowledgement can override: nested links. Unlike
    /// [`Self::warnings`], these are never accepted with `--yes` or an
    /// interactive confirmation -- two linked folders over the same files
    /// would each treat the other's changes as their own.
    pub fn structural_prohibitions(&self) -> Vec<String> {
        self.nested_conflicts.iter().filter(|c| c.is_structural()).map(|c| c.refusal()).collect()
    }

    pub fn is_empty_folder(&self) -> bool {
        self.entry_count == 0
    }

    fn free_space_state(&self) -> Option<FreeSpaceState> {
        self.free_space.map(|s| s.classify())
    }

    /// whether this preflight found anything that
    /// should require explicit confirmation or an acknowledgement flag
    /// before linking proceeds.
    pub fn is_risky(&self) -> bool {
        !self.path_exists
            || !self.is_empty_folder()
            || matches!(
                self.free_space_state(),
                Some(FreeSpaceState::Low) | Some(FreeSpaceState::Critical)
            )
            || self.nested_conflicts.iter().any(|c| !c.is_structural())
            || self.risky_location.is_some()
            || self.ignore_rules_unreadable
            || !self.reserved_namespace_blocked_paths.is_empty()
    }

    /// Human-readable warning lines, one per risky condition found — used
    /// both for the CLI's printed preflight output and for
    /// the daemon's rejection message.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.path_exists {
            out.push("path does not exist".to_string());
            return out;
        }
        if self.ignore_rules_unreadable {
            out.push(
                "this folder's ignore rules could not be read (corrupt or unreadable \
                 .yadorilinkignore) — files you meant to exclude may sync; fix the file before \
                 linking"
                    .to_string(),
            );
        }
        if !self.is_empty_folder() {
            out.push(format!(
                "folder is not empty ({} existing entr{}{}) — existing files will participate in initial reconciliation",
                self.entry_count,
                if self.entry_count == 1 { "y" } else { "ies" },
                if self.scan_truncated { ", scan capped so there may be more" } else { "" },
            ));
        }
        match self.free_space_state() {
            Some(FreeSpaceState::Critical) => out.push(format!(
                "critically low free space on the target volume ({} bytes free, headroom {} bytes)",
                self.free_space.unwrap().available_bytes,
                self.free_space.unwrap().headroom_bytes,
            )),
            Some(FreeSpaceState::Low) => out.push(format!(
                "low free space on the target volume ({} bytes free, headroom {} bytes)",
                self.free_space.unwrap().available_bytes,
                self.free_space.unwrap().headroom_bytes,
            )),
            _ => {}
        }
        for conflict in self.nested_conflicts.iter().filter(|c| !c.is_structural()) {
            out.push(format!("{} is already linked", conflict.other_path));
        }
        if let Some(loc) = &self.risky_location {
            match loc {
                RiskyLocation::CloudProviderFolder(name) => out.push(format!(
                    "this folder is inside a {name} managed folder — that provider's own sync client may conflict with this one"
                )),
                RiskyLocation::FilesystemRoot => out.push(
                    "this is a filesystem root — linking it would sync the entire volume".to_string(),
                ),
                RiskyLocation::HomeDirectory => out.push(
                    "this is your home directory itself, not a folder inside it — linking it would sync your entire home directory".to_string(),
                ),
            }
        }
        for path in &self.reserved_namespace_blocked_paths {
            out.push(format!(
                "{path:?} collides with the sync engine's reserved internal namespace and will never sync under this name — rename it before linking, or it will be silently left out of every future sync"
            ));
        }
        out
    }
}

/// Runs the local, fast preflight checks for linking
/// `local_path`, given the already-linked paths known to the caller (the
/// CLI fetches these via `ListLinks`; the daemon already owns them). Pure
/// read-only inspection — never creates, modifies, or deletes anything, so
/// it is safe to call for `--dry-run` (ensuring no persisted writes)
/// simply by never following it with an actual link registration.
pub fn run_preflight(
    local_path: &Path,
    existing_link_paths: &[String],
    headroom_override_bytes: Option<u64>,
) -> LinkPreflightReport {
    run_preflight_at_home(local_path, existing_link_paths, headroom_override_bytes, None)
}

/// [`run_preflight`] that also flags `home` (the user's home directory, which the caller
/// knows; a host with no home directory passes `None`) as a risky place to link.
pub fn run_preflight_at_home(
    local_path: &Path,
    existing_link_paths: &[String],
    headroom_override_bytes: Option<u64>,
    home: Option<&Path>,
) -> LinkPreflightReport {
    let mut report = LinkPreflightReport { path_exists: local_path.exists(), ..Default::default() };
    if !report.path_exists {
        return report;
    }
    report.is_directory = local_path.is_dir();
    if report.is_directory {
        let scan = scan_directory(local_path);
        report.entry_count = scan.entry_count;
        report.ignored_entry_count = scan.ignored_entry_count;
        report.total_size_bytes = scan.total_size_bytes;
        report.scan_truncated = scan.scan_truncated;
        report.ignore_rules_unreadable = scan.ignore_rules_unreadable;
        report.reserved_namespace_blocked_paths = scan.reserved_namespace_blocked_paths;
    }
    report.free_space = free_space::classify_volume(local_path, headroom_override_bytes).ok();
    report.nested_conflicts = detect_nested_conflicts(local_path, existing_link_paths);
    report.risky_location = detect_risky_location(local_path, home);
    report
}

struct ScanResult {
    entry_count: u64,
    ignored_entry_count: u64,
    total_size_bytes: u64,
    scan_truncated: bool,
    /// Set when the effective ignore rules could not be loaded and the scan
    /// fell back to defaults-only — surfaced up into
    /// [`LinkPreflightReport::ignore_rules_unreadable`].
    ignore_rules_unreadable: bool,
    /// Surfaced up into
    /// [`LinkPreflightReport::reserved_namespace_blocked_paths`].
    reserved_namespace_blocked_paths: Vec<String>,
}

/// Reuses the real per-link ignore engine (`ignore_patterns`) rather than a
/// second, ad hoc ignore list — the folder's own `.yadorilinkignore` (if
/// any is already present from a previous partial setup) plus the built-in
/// defaults (`.DS_Store`, `.git`, etc.) are what actually determine what
/// would sync, so that's what the preflight's non-empty/ignored counts
/// should reflect too.
fn scan_directory(root: &Path) -> ScanResult {
    // Fail closed: a corrupt/unreadable ignore file must NOT silently drop the
    // user's exclusion rules and let files they meant to keep out start
    // syncing. Fall back to defaults for the scan counts, but flag it so the
    // preflight surfaces it (as a risky condition needing acknowledgement)
    // rather than proceeding as if no custom ignore rules existed.
    let (ignore_set, ignore_rules_unreadable) = match EffectiveIgnoreSet::load_for_link_root(root) {
        Ok(set) => (set, false),
        Err(e) => {
            tracing::warn!(
                root = %root.display(),
                error = %e,
                "could not read this folder's ignore rules; preflight will flag the folder rather \
                 than silently scanning with defaults only"
            );
            (EffectiveIgnoreSet::defaults_only(), true)
        }
    };
    let mut entry_count = 0u64;
    let mut ignored_entry_count = 0u64;
    let mut total_size_bytes = 0u64;
    let mut scan_truncated = false;
    let mut reserved_namespace_blocked_paths = Vec::new();

    let mut walker = walkdir::WalkDir::new(root).min_depth(1).into_iter();
    loop {
        if entry_count + ignored_entry_count >= SCAN_ENTRY_CAP {
            scan_truncated = true;
            break;
        }
        let entry = match walker.next() {
            None => break,
            Some(Ok(entry)) => entry,
            Some(Err(_)) => continue,
        };
        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
        let is_dir = entry.file_type().is_dir();
        // A reserved-namespace artefact (see `reserved_namespace`) never
        // syncs regardless of ignore rules, so it must count the same way
        // an ignored entry does here — otherwise a leftover artefact from
        // a previous partial link/crash would inflate this preview's "how
        // much would sync" counts with something that never will.
        //
        // Named explicitly (not only counted) when it's a genuine
        // artefact-shaped collision — `path_has_artefact_component`, not
        // the broader `path_has_reserved_component` — matching the
        // predicate split documented in `reserved_namespace`: a
        // legacy-marker LOOK-ALIKE user path is excluded the same as an
        // ordinary ignore-pattern match (the user can rename it, but
        // nothing about it collides with a name the engine itself would
        // ever construct), while an artefact-shaped path is a genuine
        // naming collision worth calling out by name before the user
        // links the folder at all — surfacing what is a
        // reserved-namespace collision, rather than folding it
        // silently into the ordinary ignored-file count.
        //
        // The daemon's own top-level files -- the sync-root lock
        // (`sync_root_lock`) and the root identity marker (`root_identity`)
        // -- never sync either, so they count as ignored here too. They are
        // NOT collisions: a folder that was linked before still carries both
        // (the lock file outlives the lock it held, and the marker is the
        // folder's identity), so re-linking it, or linking it again after an
        // unlink, would otherwise always warn about files the user never
        // created and must not rename.
        let is_own_root_file =
            yadorilink_fs_platform::reserved_namespace::is_sync_root_lock_relative_path(relative)
                || yadorilink_root_authority::root_identity::is_root_marker_relative_path(relative);
        if yadorilink_fs_platform::reserved_namespace::path_has_reserved_component(relative)
            || is_own_root_file
        {
            if yadorilink_fs_platform::reserved_namespace::path_has_artefact_component(relative) {
                reserved_namespace_blocked_paths.push(relative.to_string_lossy().into_owned());
            }
            ignored_entry_count += 1;
            if is_dir {
                walker.skip_current_dir();
            }
            continue;
        }
        if ignore_set.is_ignored(relative, is_dir) {
            ignored_entry_count += 1;
            if is_dir {
                walker.skip_current_dir();
            }
            continue;
        }
        entry_count += 1;
        if !is_dir {
            total_size_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }
    ScanResult {
        entry_count,
        ignored_entry_count,
        total_size_bytes,
        scan_truncated,
        ignore_rules_unreadable,
        reserved_namespace_blocked_paths,
    }
}

/// A path as a comparable component list: symlinks resolved (through the
/// deepest ancestor that exists, so a folder not created yet still compares
/// by where it will be), and case-folded where the platform's filesystems
/// fold, so two spellings of one folder never compare as two.
fn comparable_components(path: &Path) -> Vec<String> {
    let mut missing = Vec::new();
    let mut probe = path.to_path_buf();
    let resolved = loop {
        match probe.canonicalize() {
            Ok(real) => break real,
            Err(_) => match (probe.file_name().map(|n| n.to_os_string()), probe.parent()) {
                (Some(name), Some(parent)) => {
                    missing.push(name);
                    probe = parent.to_path_buf();
                }
                _ => break path.to_path_buf(),
            },
        }
    };
    let mut full = resolved;
    full.extend(missing.into_iter().rev());
    full.components()
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => {
                let name = name.to_string_lossy().into_owned();
                Some(if cfg!(any(target_vendor = "apple", windows)) {
                    name.to_lowercase()
                } else {
                    name
                })
            }
            std::path::Component::Prefix(prefix) => {
                Some(prefix.as_os_str().to_string_lossy().to_lowercase())
            }
            _ => None,
        })
        .collect()
}

/// How `other` (an already-linked path) relates to `candidate`, comparing
/// resolved, case-folded components, or `None` when they are unrelated.
fn relation_to(candidate: &[String], other: &Path) -> Option<NestedLinkRelation> {
    let other = comparable_components(other);
    if other == candidate {
        Some(NestedLinkRelation::Same)
    } else if candidate.starts_with(&other) {
        Some(NestedLinkRelation::Ancestor)
    } else if other.starts_with(candidate) {
        Some(NestedLinkRelation::Descendant)
    } else {
        None
    }
}

/// Ancestor/descendant/exact-match detection against every already-linked
/// path, by resolved and case-folded location rather than by spelling.
fn detect_nested_conflicts(
    local_path: &Path,
    existing_link_paths: &[String],
) -> Vec<NestedLinkConflict> {
    let candidate = comparable_components(local_path);
    existing_link_paths
        .iter()
        .filter_map(|other| {
            relation_to(&candidate, Path::new(other))
                .map(|relation| NestedLinkConflict { other_path: other.clone(), relation })
        })
        .collect()
}

/// The conflicts that make linking `local_path` to `group_id` an unsupported
/// topology, given every existing link as `(path, group)`: a link inside or
/// containing another (whatever its group), and the same folder already
/// linked to a different group. The same folder already linked to THIS group
/// is an idempotent re-link, not a conflict. Evaluated by the daemon at the
/// point a link is committed, where no acknowledgement can reach it.
pub fn detect_topology_conflicts(
    local_path: &Path,
    group_id: &str,
    existing_links: &[(String, String)],
) -> Vec<NestedLinkConflict> {
    let candidate = comparable_components(local_path);
    existing_links
        .iter()
        .filter_map(|(other, other_group)| {
            let relation = relation_to(&candidate, Path::new(other))?;
            (relation != NestedLinkRelation::Same || other_group != group_id)
                .then(|| NestedLinkConflict { other_path: other.clone(), relation })
        })
        .collect()
}

fn detect_risky_location(path: &Path, home: Option<&Path>) -> Option<RiskyLocation> {
    if path.parent().is_none() {
        return Some(RiskyLocation::FilesystemRoot);
    }
    if is_home_directory(path, home) {
        return Some(RiskyLocation::HomeDirectory);
    }
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if let Some(marker) =
                CLOUD_PROVIDER_MARKERS.iter().find(|m| name.eq_ignore_ascii_case(m))
            {
                return Some(RiskyLocation::CloudProviderFolder(marker));
            }
        }
    }
    None
}

fn is_home_directory(path: &Path, home: Option<&Path>) -> bool {
    let Some(home) = home else {
        return false;
    };
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let target = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    home == target
}

#[cfg(test)]
mod tests;
