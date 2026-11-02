#![cfg(test)]

//! `content_identity` ignores the modification time and nothing else (the execute flag is part of it).

use super::*;

fn version(block: u8, meta: impl FnOnce(&mut FileMeta)) -> FileVersion {
    let mut m = FileMeta {
        mtime_unix_nanos: 1,
        exec: false,
        symlink_target: None,
        record_kind: RecordKind::File,
    };
    meta(&mut m);
    FileVersion::new(vec![VersionBlock { hash: BlockHash(vec![block; 32]), size: 4 }], 4, m)
}

#[test]
fn a_different_mtime_is_a_different_version_and_the_same_content() {
    let (a, b) = (version(1, |_| {}), version(1, |m| m.mtime_unix_nanos = 99));
    assert_ne!(a.version_hash, b.version_hash);
    assert_eq!(a.content_identity(), b.content_identity());
}

#[test]
fn every_other_replicated_field_changes_the_identity() {
    let base = version(1, |_| {}).content_identity();
    let others = [
        version(2, |_| {}),
        version(1, |m| m.exec = true),
        version(1, |m| m.symlink_target = Some(b"t".to_vec())),
        version(1, |m| m.record_kind = RecordKind::Symlink),
    ];
    for other in others {
        assert_ne!(other.content_identity(), base);
    }
    // Same total size and block count, different block sizes.
    let resized =
        FileVersion::new(vec![VersionBlock { hash: BlockHash(vec![1; 32]), size: 5 }], 5, {
            version(1, |_| {}).meta
        });
    assert_ne!(resized.content_identity(), base);
}

#[test]
fn the_identity_never_equals_a_version_hash() {
    let v = version(1, |m| m.mtime_unix_nanos = 0);
    assert_ne!(v.content_identity().0, v.version_hash.0);
}
