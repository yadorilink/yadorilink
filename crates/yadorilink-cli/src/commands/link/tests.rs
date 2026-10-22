#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::{FetchAvailability, LocalStorageState};
use yadorilink_local_storage::link_preflight;

use super::*;

fn base_link() -> LinkStatus {
    LinkStatus {
        local_path: "/tmp/photos".into(),
        provider_root_id: String::new(),
        provider_display_name: String::new(),
        group_id: "group-1".into(),
        paused: false,
        conflict_count: 0,
        conflicts_pending: 0,
        conflict_note: String::new(),
        materialization_policy: "eager".into(),
        hydrated_count: 0,
        placeholder_count: 0,
        hydrating_count: 0,
        requested_content_count: 0,
        held_file_count: 0,
        held_files: vec![],
        skipped_symlink_count: 0,
        stranded_directory_count: 0,
        degraded: false,
        degraded_reason: String::new(),
        has_active_transfer: false,
        transfer_bytes_done: 0,
        transfer_bytes_total: 0,
        transfer_blocks_done: 0,
        transfer_blocks_total: 0,
        transfer_eta_seconds: 0,
        durability_status: 0,
        durability_evidence: 0,
        durability_check_pending: false,
        policy_stale: false,
        ambiguous: false,
        ambiguous_local_paths: Vec::new(),
        capture_volume_changed: false,
        local_storage_state: LocalStorageState::FullCopy as i32,
        fetch_availability: FetchAvailability::AvailableNow as i32,
        full_replica_device_ids: Vec::new(),
        ..Default::default()
    }
}

/// a link with no skipped symlinks renders no new output.
#[test]
fn no_skipped_symlinks_renders_no_new_output() {
    assert_eq!(skipped_symlink_suffix(&base_link()), "");
}

/// a link with skipped symlinks (the Windows default-skip
/// policy) shows the count alongside the existing sync-state summary.
#[test]
fn skipped_symlinks_render_the_count() {
    let mut link = base_link();
    link.skipped_symlink_count = 3;
    assert_eq!(skipped_symlink_suffix(&link), "  skipped_symlinks=3");
}

// -- acknowledgement gate -------------------------------------------

fn risky_report() -> LinkPreflightReport {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), b"x").unwrap();
    // Leak the tempdir so the returned report's path stays valid for the
    // duration of the calling test; these tests only inspect the report
    // fields the function under test cares about (`is_risky`/
    // `warnings`), not the filesystem itself, so the directory need not
    // be cleaned up.
    let path = dir.keep();
    link_preflight::run_preflight(&path, &[], Some(0))
}

fn safe_report() -> LinkPreflightReport {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep();
    link_preflight::run_preflight(&path, &[], Some(0))
}

/// spec.md "Risk acknowledgement": `--yes` bypasses a risky preflight
/// without needing an interactive prompt at all.
#[test]
fn yes_flag_acknowledges_a_risky_report() {
    let report = risky_report();
    assert!(report.is_risky());
    assert!(acknowledge_if_risky(&report, true).unwrap());
}

/// A non-risky report never needs acknowledgement, `--yes` or not.
#[test]
fn non_risky_report_never_needs_acknowledgement() {
    let report = safe_report();
    assert!(!report.is_risky());
    assert!(!acknowledge_if_risky(&report, false).unwrap());
    assert!(!acknowledge_if_risky(&report, true).unwrap());
}

/// spec.md "Risk acknowledgement": a risky preflight without `--yes`
/// (and, in this unit test, without a real terminal to prompt on)
/// genuinely blocks — `acknowledge_if_risky` returns `Err`, which
/// `commands::link::link` propagates as a non-zero exit.
#[test]
fn risky_report_without_yes_or_a_terminal_is_rejected() {
    let report = risky_report();
    let result = acknowledge_if_risky(&report, false);
    assert!(result.is_err(), "expected risky link without --yes to be rejected");
}

/// A nested link is an unsupported topology, not a risk: `--yes` must not
/// accept it, and the refusal names the conflicting link.
#[test]
fn nested_links_are_refused_with_and_without_yes() {
    let parent = tempfile::tempdir().unwrap();
    let child = parent.path().join("child");
    std::fs::create_dir(&child).unwrap();
    let parent_path = parent.path().to_string_lossy().to_string();
    let child_path = child.to_string_lossy().to_string();

    // Linking inside an existing link, and linking a folder that contains one.
    let inside = link_preflight::run_preflight(&child, std::slice::from_ref(&parent_path), Some(0));
    let containing =
        link_preflight::run_preflight(parent.path(), std::slice::from_ref(&child_path), Some(0));
    for (report, other) in [(inside, &parent_path), (containing, &child_path)] {
        for yes in [false, true] {
            let err = acknowledge_if_risky(&report, yes)
                .expect_err("a nested link must be refused whatever the flag");
            assert!(err.to_string().contains(other.as_str()), "must name {other}: {err}");
        }
    }
}

/// The interactive confirmation prompt itself: "y"/"yes" (any case)
/// acknowledges, anything else (including empty input) does not.
#[test]
fn confirm_risky_reader_accepts_y_or_yes_case_insensitively() {
    let warnings = vec!["folder is not empty".to_string()];
    assert!(confirm_risky_with_reader(&warnings, &mut "y\n".as_bytes()));
    assert!(confirm_risky_with_reader(&warnings, &mut "YES\n".as_bytes()));
    assert!(!confirm_risky_with_reader(&warnings, &mut "n\n".as_bytes()));
    assert!(!confirm_risky_with_reader(&warnings, &mut "\n".as_bytes()));
}

/// `yadorilink links`' full output for an empty list, an eager link, and an
/// on-demand link with conflicts and skipped symlinks.
#[test]
fn links_lines_are_pinned_verbatim() {
    assert_eq!(links_lines(&[]), vec!["No linked folders.".to_string()]);
    let ondemand = LinkStatus {
        local_path: "/tmp/docs".into(),
        group_id: "group-2".into(),
        paused: true,
        conflict_count: 2,
        conflicts_pending: 0,
        conflict_note: String::new(),
        materialization_policy: "ondemand".into(),
        hydrated_count: 3,
        placeholder_count: 4,
        hydrating_count: 1,
        skipped_symlink_count: 5,
        ..base_link()
    };
    assert_eq!(
        links_lines(&[base_link(), ondemand]),
        vec![
            "/tmp/photos  group=group-1  syncing".to_string(),
            "/tmp/docs  group=group-2  paused  conflicts=2  on-demand (hydrated=3 placeholder=4 \
             hydrating=1)  skipped_symlinks=5"
                .to_string(),
        ]
    );
}

#[test]
fn handoff_line_names_the_lease_only_when_there_is_one() {
    let mut result = HandoffResult {
        target_device_id: "dev-2".into(),
        membership_generation: 3,
        ..Default::default()
    };
    assert_eq!(handoff_line(&result), "  handoff completed: target=dev-2 membership_generation=3");
    result.lease_id = "lease-1".into();
    assert_eq!(
        handoff_line(&result),
        "  handoff completed: target=dev-2 membership_generation=3 lease=lease-1"
    );
}
