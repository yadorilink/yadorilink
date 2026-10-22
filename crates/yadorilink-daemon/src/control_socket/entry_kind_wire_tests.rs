#![cfg(test)]

//! The kind of each versioned, trashed and conflicted record reaches the
//! control-socket wire, so a surface can tell a directory from a file.

use super::*;
use yadorilink_ipc_proto::daemonctl::EntryKind;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::{TrashedFile, VersionRecord, VersionState};

fn version(record_kind: RecordKind) -> VersionRecord {
    VersionRecord {
        path: "docs".into(),
        version_seq: 2,
        size: 0,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
        state: VersionState::Current,
        origin_device_id: Some("device-a".into()),
        record_kind,
        symlink_target: None,
        unix_mode: Some(0o755),
        xattrs: vec![],
        version_hash: VersionHash([0; 32]),
    }
}

#[test]
fn version_to_proto_carries_record_kind() {
    for (record_kind, wire) in [
        (RecordKind::File, EntryKind::File),
        (RecordKind::Directory, EntryKind::Directory),
        (RecordKind::Symlink, EntryKind::Symlink),
    ] {
        assert_eq!(version_to_proto(version(record_kind)).kind(), wire, "{record_kind:?}");
    }
}

#[test]
fn trashed_and_conflicted_protos_carry_record_kind() {
    let trashed = trashed_file_view_to_proto(crate::queries::file_history::TrashedFileView {
        local_path: "/tmp/photos".into(),
        trashed: TrashedFile {
            path: "album".into(),
            version_seq: 3,
            last_known_size: 0,
            origin_device_id: None,
            deleted_at_unix_nanos: 9,
            deleted_by_operation: None,
            record_kind: RecordKind::Directory,
        },
    });
    assert_eq!(trashed.kind(), EntryKind::Directory);

    let conflicted =
        conflicted_file_view_to_proto(crate::queries::file_history::ConflictedFileView {
            local_path: "/tmp/photos".into(),
            path: "link (conflicted copy, 2026-01-01-000000, device-b)".into(),
            size: 4,
            mtime_unix_nanos: 5,
            record_kind: RecordKind::Symlink,
            reason: crate::queries::file_history::ConflictCopyReason::ConcurrentEdit,
            resolvable: false,
            origin_device_id: None,
        });
    assert_eq!(conflicted.kind(), EntryKind::Symlink);
    assert!(!conflicted.resolvable);
}

/// A trashed entry names the recursive operation that removed it, so a
/// listing can group a folder's entries and restore them together.
#[test]
fn trashed_proto_names_the_operation_that_removed_it() {
    use yadorilink_replica_domain::ids::DeviceId;
    use yadorilink_replica_domain::recursive_operation::{
        RecursiveOperationId, RecursiveOperationRef,
    };
    let view = |deleted_by_operation| crate::queries::file_history::TrashedFileView {
        local_path: "/tmp/photos".into(),
        trashed: TrashedFile {
            path: "album/cover.jpg".into(),
            version_seq: 3,
            last_known_size: 4,
            origin_device_id: None,
            deleted_at_unix_nanos: 9,
            deleted_by_operation,
            record_kind: RecordKind::File,
        },
    };
    let trashed = trashed_file_view_to_proto(view(Some(RecursiveOperationRef {
        author: DeviceId("device-b".into()),
        operation_id: RecursiveOperationId([0xab; 16]),
    })));
    assert_eq!(trashed.deleted_by_operation, format!("device-b:{}", "ab".repeat(16)));
    assert_eq!(trashed_file_view_to_proto(view(None)).deleted_by_operation, "");
}
