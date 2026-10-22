#![cfg(test)]

use super::*;

fn conflicted(path: &str) -> ConflictedFileInfo {
    ConflictedFileInfo { local_path: "/tmp/photos".into(), path: path.into(), ..Default::default() }
}

/// The full, current naming convention: timestamp, device, and the
/// full content-hash disambiguator all present.
#[test]
fn parses_every_field_from_the_full_naming_convention() {
    let detail = conflict_detail(&conflicted(
        "report (conflicted copy, 2026-01-15-120000, device-a, \
         0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20).txt",
    ));
    assert_eq!(
        detail,
        ConflictDetail {
            current_path: "report.txt".into(),
            loser_device_id: Some("device-a".into()),
            timestamp: Some("2026-01-15-120000".into()),
            content_hash_hex: Some(
                "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".into()
            ),
            reason: ConflictReason::ConcurrentEdit,
        }
    );
}

/// An older/hand-built fixture without the hash disambiguator (the
/// exact shape `yadorilink-cli`'s own `version_history` test fixture
/// uses) still parses the timestamp/device correctly, with the hash
/// simply absent rather than a parse failure.
#[test]
fn parses_without_the_optional_content_hash() {
    let detail =
        conflict_detail(&conflicted("vacation (conflicted copy, 2026-01-01-000000, device-b).jpg"));
    assert_eq!(
        detail,
        ConflictDetail {
            current_path: "vacation.jpg".into(),
            loser_device_id: Some("device-b".into()),
            timestamp: Some("2026-01-01-000000".into()),
            content_hash_hex: None,
            reason: ConflictReason::ConcurrentEdit,
        }
    );
}

/// A directory-scoped conflicted copy keeps its directory in
/// `current_path`.
#[test]
fn preserves_the_directory_component() {
    let detail = conflict_detail(&conflicted(
        "albums/2026/vacation (conflicted copy, 2026-01-01-000000, device-b, \
         0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20).jpg",
    ));
    assert_eq!(detail.current_path, "albums/2026/vacation.jpg");
}

/// A file with no extension (`conflict_copy_path`'s own `None` branch)
/// still parses.
#[test]
fn parses_a_path_with_no_extension() {
    let detail =
        conflict_detail(&conflicted("README (conflicted copy, 2026-02-01-090000, device-c)"));
    assert_eq!(detail.current_path, "README");
    assert_eq!(detail.loser_device_id, Some("device-c".into()));
}

/// A path that doesn't carry the marker at all (unexpected shape, or a
/// daemon that changed the convention) degrades to all-`None` detail
/// fields rather than panicking or fabricating a guess.
#[test]
fn unparseable_path_degrades_gracefully() {
    let detail = conflict_detail(&conflicted("plain-file.txt"));
    assert_eq!(
        detail,
        ConflictDetail {
            current_path: "plain-file.txt".into(),
            loser_device_id: None,
            timestamp: None,
            content_hash_hex: None,
            reason: ConflictReason::ConcurrentEdit,
        }
    );
}

/// The daemon states why a copy is kept; a sender that did not state it
/// means a concurrent edit, the only reason there was before.
#[test]
fn carries_the_reason_the_daemon_states() {
    use yadorilink_ipc_proto::daemonctl::ConflictReason as Wire;
    let mut file = conflicted("album (conflicted copy, 2026-01-01-000000, device-b)");
    assert_eq!(conflict_detail(&file).reason, ConflictReason::ConcurrentEdit);
    file.reason = Wire::FolderAtPath as i32;
    let detail = conflict_detail(&file);
    assert_eq!(detail.reason, ConflictReason::FolderAtPath);
    assert_eq!(detail.current_path, "album");
    assert!(detail.reason.explanation().contains("folder"));
    file.reason = Wire::ConcurrentEdit as i32;
    assert_eq!(conflict_detail(&file).reason, ConflictReason::ConcurrentEdit);
}

/// A native copy name carries a label and a hash prefix but no timestamp; the
/// label must not be read as a timestamp (nor the hash as a device).
#[test]
fn parses_a_name_without_a_timestamp() {
    let detail = conflict_detail(&conflicted(
        "docs/report (conflicted copy, sync, 0102030405060708090a0b0c0d0e0f10).txt",
    ));
    assert_eq!(
        detail,
        ConflictDetail {
            current_path: "docs/report.txt".into(),
            loser_device_id: Some("sync".into()),
            timestamp: None,
            content_hash_hex: Some("0102030405060708090a0b0c0d0e0f10".into()),
            reason: ConflictReason::ConcurrentEdit,
        }
    );
}
