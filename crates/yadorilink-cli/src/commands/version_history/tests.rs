#![cfg(test)]

use super::*;

/// This device is `device-self`; `device-a` is on the account as "Kitchen Mac";
/// `device-b` is not known here.
fn devices() -> DeviceNames {
    DeviceNames {
        own_device_id: Some("device-self".into()),
        names: [("device-a".to_string(), "Kitchen Mac".to_string())].into_iter().collect(),
    }
}
use crate::commands::local_time::format_with_offset;
use yadorilink_ipc_proto::daemonctl::EntryKind;

/// `versions` output shape — one line per version, newest
/// first is the daemon's own ordering contract (`SyncState::list_versions`'s
/// doc comment), this just checks the per-line rendering.
#[test]
fn version_line_renders_every_field() {
    let v = FileVersionInfo {
        version_seq: 3,
        size: 42,
        mtime_unix_nanos: 12345,
        state: "superseded".into(),
        origin_device_id: "device-a".into(),
        unix_mode: Some(0o755),
        kind: EntryKind::File as i32,
    };
    assert_eq!(
        version_line(&v, &devices()),
        "v3  12345  size=42  from Kitchen Mac  state=superseded  mode=0o755"
    );
}

/// An unknown origin (empty string, see `FileVersionInfo.origin_device_id`'s
/// own doc comment) renders as `unknown`, not a blank field a user
/// could mistake for a rendering bug.
#[test]
fn version_line_renders_unknown_origin() {
    let v = FileVersionInfo {
        version_seq: 1,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: String::new(),
        unix_mode: Some(0o644),
        kind: EntryKind::File as i32,
    };
    assert!(version_line(&v, &devices()).contains("from an unknown device"));
}

/// No Unix permission info (a version authored on Windows) renders as
/// `-`, never a fabricated octal value.
#[test]
fn version_line_renders_absent_unix_mode() {
    let v = FileVersionInfo {
        version_seq: 1,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: "device-a".into(),
        unix_mode: None,
        kind: EntryKind::File as i32,
    };
    assert!(version_line(&v, &devices()).contains("mode=-"));
}

#[test]
fn trashed_file_line_renders_every_field() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "vacation.jpg".into(),
        version_seq: 2,
        last_known_size: 1000,
        origin_device_id: "device-b".into(),
        deleted_at_unix_nanos: 999,
        kind: EntryKind::File as i32,
        deleted_by_operation: String::new(),
    };
    assert_eq!(
        trashed_file_line(&f, &devices()),
        "/tmp/photos/vacation.jpg  deleted_at=999  last_known_size=1000  from another device"
    );
}

#[test]
fn conflicted_file_line_says_what_happened_in_plain_words() {
    let f = ConflictedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "vacation (conflicted copy, 2026-01-01-000000, device-b).jpg".into(),
        size: 1234,
        mtime_unix_nanos: 5678,
        kind: EntryKind::File as i32,
        reason: 0,
        resolvable: false,
        origin_device_id: "device-a".into(),
    };
    let line = conflicted_file_line(&f, &devices());
    assert_eq!(
        line,
        format!(
            "/tmp/photos/vacation (conflicted copy, 2026-01-01-000000, device-b).jpg\n  \
             Edited on two devices; both versions were kept. This is the other version.\n  \
             1.2 KiB, saved {} on Kitchen Mac",
            format_local_time(5678)
        )
    );
    assert!(!line.contains("size=") && !line.contains("modified="));
}

/// A directory version has no size or mtime of its own (both are
/// canonically 0), so printing `size=0` would read as an empty file.
#[test]
fn directory_version_line_does_not_print_size() {
    let v = FileVersionInfo {
        version_seq: 4,
        size: 0,
        mtime_unix_nanos: 0,
        state: "current".into(),
        origin_device_id: "device-a".into(),
        unix_mode: Some(0o755),
        kind: EntryKind::Directory as i32,
    };
    assert_eq!(
        version_line(&v, &devices()),
        "v4  directory  from Kitchen Mac  state=current  mode=0o755"
    );
}

#[test]
fn trashed_directory_line_does_not_print_size() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album".into(),
        version_seq: 2,
        last_known_size: 0,
        origin_device_id: "device-b".into(),
        deleted_at_unix_nanos: 999,
        kind: EntryKind::Directory as i32,
        deleted_by_operation: String::new(),
    };
    assert_eq!(
        trashed_file_line(&f, &devices()),
        "/tmp/photos/album/  deleted_at=999  directory  from another device"
    );
}

#[test]
fn conflicted_directory_line_does_not_print_size() {
    let f = ConflictedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        size: 0,
        mtime_unix_nanos: 0,
        kind: EntryKind::Directory as i32,
        reason: 0,
        resolvable: false,
        origin_device_id: "device-a".into(),
    };
    let line = conflicted_file_line(&f, &devices());
    assert!(line.starts_with("/tmp/photos/album (conflicted copy, 2026-01-01-000000, device-b)/\n"));
    assert!(!line.contains("KiB") && !line.contains(" B"));
}

/// An entry a recursive delete removed says so, with a short form of the
/// operation, so the entries of one folder read as one group.
#[test]
fn trashed_line_names_the_folder_operation_that_removed_it() {
    let f = TrashedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album/cover.jpg".into(),
        version_seq: 2,
        last_known_size: 10,
        origin_device_id: "device-b".into(),
        deleted_at_unix_nanos: 999,
        kind: EntryKind::File as i32,
        deleted_by_operation: format!("device-b:{}", "ab".repeat(16)),
    };
    assert_eq!(
        trashed_file_line(&f, &devices()),
        "/tmp/photos/album/cover.jpg  deleted_at=999  last_known_size=10  from another device  \
         folder_operation=abababab"
    );
}

#[test]
fn conflicted_file_line_names_a_folder_at_its_path() {
    let f = ConflictedFileInfo {
        local_path: "/tmp/photos".into(),
        path: "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        size: 3,
        mtime_unix_nanos: 4,
        kind: EntryKind::File as i32,
        reason: yadorilink_ipc_proto::daemonctl::ConflictReason::FolderAtPath as i32,
        resolvable: false,
        origin_device_id: "device-a".into(),
    };
    assert!(conflicted_file_line(&f, &devices()).contains("Its name is a folder now"));
}

#[test]
fn local_time_formats_calendar_fields_for_an_offset() {
    // 2026-03-01 12:34:56 UTC.
    let secs = 1_772_368_496;
    assert_eq!(format_with_offset(secs, 0), "2026-03-01 12:34:56");
    assert_eq!(format_with_offset(secs, 9 * 3600), "2026-03-01 21:34:56");
    assert_eq!(format_with_offset(secs, -13 * 3600), "2026-02-28 23:34:56");
    assert_eq!(format_with_offset(0, 0), "1970-01-01 00:00:00");
    // 2024-02-29 is a leap day.
    assert_eq!(format_with_offset(1_709_164_800, 0), "2024-02-29 00:00:00");
}

#[test]
fn conflict_hint_says_how_to_resolve() {
    assert!(CONFLICT_RESOLVE_HINT.contains("conflicts keep <copy>"));
    assert!(CONFLICT_RESOLVE_HINT.contains("conflicts keep-both <copy>"));
}

/// Raw device ids are never shown: this device and account devices by name,
/// anything else as "another device".
#[test]
fn device_labels_never_show_an_id() {
    let devices = devices();
    assert_eq!(devices.label("device-self"), "this device");
    assert_eq!(devices.label("device-a"), "Kitchen Mac");
    assert_eq!(devices.label("device-b"), "another device");
    assert_eq!(devices.label(""), "an unknown device");
    assert_eq!(DeviceNames::default().label("device-a"), "another device");
}
