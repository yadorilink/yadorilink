#![cfg(test)]

use super::*;
use yadorilink_fs_platform::fs_identity::Timestamp;

fn sample_identity() -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 7 },
        object_id: PlatformObjectId::Unix { inode: 42 },
        object_kind: ObjectKind::RegularFile,
        generation_or_usn: Some(3),
        birth_or_creation_time: Some(Timestamp {
            seconds_since_unix_epoch: 1_700_000_000,
            subsec_nanos: 123,
        }),
        observed_size: 1024,
        metadata_fingerprint: [9; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

#[test]
fn file_identity_round_trips_through_its_stored_encoding() {
    let identity = sample_identity();
    let blob = encode_file_identity(&identity);
    let decoded = decode_file_identity(&blob).unwrap();
    assert_eq!(decoded, identity);
}

#[test]
fn a_real_symlinks_identity_round_trips_through_its_stored_encoding_digest_included() {
    // The round-trip tests above all construct a `FileIdentity` with
    // `symlink_target_digest` already `None`, so they pass regardless
    // of whether this encoding actually carries that field -- they
    // never observe it being anything else. This test exercises a
    // genuine decoded row: a real `FileIdentity::observe_path` call
    // against an actual symlink, which -- unlike every constructed
    // identity above -- populates `symlink_target_digest` with
    // `Some(_)` before encoding. See `MATERIALIZED_GENERATION_ENCODING_
    // VERSION`'s doc (bumped 2 -> 3 for exactly this) for why this
    // field is part of the encoding: it is the only reuse
    // discriminator a symlink identity can ever carry, so a decoded row
    // that lost it left `FileIdentity::compare` unable to conclude
    // `SameObject` for a symlink at all on a coarse-clock volume.
    let dir = tempfile::tempdir().unwrap();
    let link_path = dir.path().join("a-symlink");
    #[cfg(unix)]
    std::os::unix::fs::symlink("wherever-this-points", &link_path).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file("wherever-this-points", &link_path).unwrap();
    let live = FileIdentity::observe_path(&link_path).unwrap();
    assert!(
        live.symlink_target_digest.is_some(),
        "a live observation of a real symlink must populate symlink_target_digest"
    );

    let blob = encode_file_identity(&live);
    let decoded = decode_file_identity(&blob).unwrap();

    assert_eq!(decoded, live);
}

#[test]
fn file_identity_round_trips_with_every_optional_field_absent() {
    let identity = FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 1 },
        object_id: PlatformObjectId::Unix { inode: 1 },
        object_kind: ObjectKind::Directory,
        generation_or_usn: None,
        birth_or_creation_time: None,
        observed_size: 0,
        metadata_fingerprint: [0; 32],
        link_count: None,
        symlink_target_digest: None,
    };
    let blob = encode_file_identity(&identity);
    let decoded = decode_file_identity(&blob).unwrap();
    assert_eq!(decoded, identity);
}

#[test]
fn file_identity_round_trips_the_windows_fallback_variant_even_off_windows() {
    // Pure data encoding, no platform syscalls -- this must hold on
    // every build host, not just Windows, since a peer database could
    // in principle carry a Windows-observed identity.
    let identity = FileIdentity {
        volume_identity: VolumeIdentity::Windows { volume_serial_number: 0xdead_beef },
        object_id: PlatformObjectId::Windows(WindowsObjectId::Fallback {
            file_index: 0x1122_3344_5566_7788,
        }),
        object_kind: ObjectKind::ReparsePoint,
        generation_or_usn: None,
        birth_or_creation_time: None,
        observed_size: 5,
        metadata_fingerprint: [7; 32],
        link_count: None,
        symlink_target_digest: None,
    };
    let blob = encode_file_identity(&identity);
    let decoded = decode_file_identity(&blob).unwrap();
    assert_eq!(decoded, identity);
}

#[test]
fn file_identity_round_trips_the_windows_proven_variant_even_off_windows() {
    // Same premise as the fallback-variant test above, for the proven
    // 128-bit `FILE_ID_INFO` case -- a 64-bit volume serial and a
    // 16-byte file id, both wider than the legacy fallback fields.
    let identity = FileIdentity {
        volume_identity: VolumeIdentity::Windows { volume_serial_number: 0x1122_3344_5566_7788 },
        object_id: PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [0xab; 16] }),
        object_kind: ObjectKind::ReparsePoint,
        generation_or_usn: None,
        birth_or_creation_time: None,
        observed_size: 5,
        metadata_fingerprint: [7; 32],
        link_count: None,
        symlink_target_digest: None,
    };
    let blob = encode_file_identity(&identity);
    let decoded = decode_file_identity(&blob).unwrap();
    assert_eq!(decoded, identity);
}

#[test]
fn decoding_a_truncated_filesystem_identity_blob_fails_closed_not_panics() {
    let identity = sample_identity();
    let blob = encode_file_identity(&identity);
    let truncated = &blob[..blob.len() - 5];
    let result = decode_file_identity(truncated);
    assert!(matches!(result, Err(SyncSqliteError::CorruptState(_))));
}

#[test]
fn decoding_an_unknown_encoding_version_fails_closed() {
    let identity = sample_identity();
    let mut blob = encode_file_identity(&identity);
    blob[0] = 0xff;
    let result = decode_file_identity(&blob);
    assert!(matches!(result, Err(SyncSqliteError::CorruptState(_))));
}
