#![cfg(test)]

use super::*;

/// a `StorageError::DiskPressure` from the block store
/// converts to `SyncError::DiskPressure`, not the generic `Storage`
/// wrapper — a caller matching on `SyncError` alone (not reaching into
/// the wrapped `StorageError`) can still tell disk pressure apart from
/// every other storage error.
#[test]
fn disk_pressure_survives_conversion_from_storage_error_undisguised() {
    let storage_err = yadorilink_local_storage::StorageError::DiskPressure {
        path: "/root/blocks/ab/cd/abcd".into(),
        volume: "/root/blocks".into(),
        available_bytes: 100,
        headroom_bytes: 1000,
    };
    let sync_err: SyncError = storage_err.into();
    assert!(matches!(sync_err, SyncError::DiskPressure { .. }));
}

#[test]
fn collision_error_carries_the_exact_path() {
    let err = SyncError::ReservedNamespaceCollision("a/.yadorilink-v1-stage.x".to_string());
    assert!(err.to_string().contains("a/.yadorilink-v1-stage.x"));
}

/// The converse: an ordinary storage error (not disk pressure) still
/// wraps as `Storage`, not `DiskPressure` — the conversion only
/// special-cases the one variant it needs to.
#[test]
fn other_storage_errors_still_wrap_as_the_generic_storage_variant() {
    let storage_err = yadorilink_local_storage::StorageError::NotFound("deadbeef".into());
    let sync_err: SyncError = storage_err.into();
    assert!(matches!(sync_err, SyncError::Storage(_)));
    assert!(!matches!(sync_err, SyncError::DiskPressure { .. }));
}

/// Spot-checks the category
/// taxonomy's coarse, stable slugs for a representative sample of
/// variants — these are exactly the strings the recent-error ring
/// buffer and `/metrics` labels surface, so a typo here is a
/// user-visible regression.
#[test]
fn category_returns_stable_coarse_slugs() {
    assert_eq!(
        SyncError::Transport(yadorilink_transport::TransportError::ChannelClosed).category(),
        "peer_unreachable"
    );
    assert_eq!(
        SyncError::DiskPressure {
            path: "a.bin".into(),
            volume: "/root".into(),
            available_bytes: 1,
            headroom_bytes: 2,
        }
        .category(),
        "disk_pressure"
    );
    assert_eq!(SyncError::NotFound("x".into()).category(), "not_found");
    assert_eq!(SyncError::PathEscapesRoot("x".into()).category(), "permission");
    assert_eq!(
        SyncError::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
            .category(),
        "permission"
    );
    assert_eq!(SyncError::Io(std::io::Error::other("transient")).category(), "io");
}

/// `DiskPressure` must never be confused with `Io` — a plain
/// transient I/O error stays `Io`, never `DiskPressure`, so callers can
/// branch on "disk full, back off differently" versus "network/I/O
/// blip, just retry" by matching the `SyncError` variant alone.
#[test]
fn disk_pressure_is_a_distinct_variant_from_io_errors() {
    let io_err: SyncError = std::io::Error::other("transient").into();
    assert!(matches!(io_err, SyncError::Io(_)));
    assert!(!matches!(io_err, SyncError::DiskPressure { .. }));

    let disk_pressure = SyncError::DiskPressure {
        path: "a.bin".into(),
        volume: "/root".into(),
        available_bytes: 1,
        headroom_bytes: 2,
    };
    assert!(!matches!(disk_pressure, SyncError::Io(_)));
}
