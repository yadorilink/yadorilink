#![cfg(test)]

use super::*;

fn sample(
    device_id: u64,
    inode: u64,
    generation_or_usn: Option<u128>,
    birth: Option<i64>,
) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id },
        object_id: PlatformObjectId::Unix { inode },
        object_kind: ObjectKind::RegularFile,
        generation_or_usn,
        birth_or_creation_time: birth
            .map(|seconds| Timestamp { seconds_since_unix_epoch: seconds, subsec_nanos: 0 }),
        observed_size: 0,
        metadata_fingerprint: [0; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

#[test]
fn matching_generation_counter_proves_same_object() {
    let a = sample(1, 2, Some(9), None);
    let b = sample(1, 2, Some(9), None);
    // Granularity is irrelevant here: `generation_or_usn` is a
    // counter, not a clock reading, so `Coarse` must not change this.
    assert_eq!(a.compare(&b, TimestampGranularity::Coarse), IdentityComparison::SameObject);
}

#[test]
fn differing_generation_counter_proves_different_object() {
    let a = sample(1, 2, Some(9), None);
    let b = sample(1, 2, Some(10), None);
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
}

#[test]
fn differing_device_is_always_definitely_different() {
    let a = sample(1, 2, Some(9), None);
    let b = sample(2, 2, Some(9), None);
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
}

#[test]
fn differing_inode_is_always_definitely_different() {
    let a = sample(1, 2, None, None);
    let b = sample(1, 3, None, None);
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
}

#[test]
fn no_generation_counter_but_birth_time_moved_is_definitely_different() {
    // Same device+inode, no generation/USN on either side: this is
    // exactly the "inode reuse" shape. A birth-time change still
    // proves it, since birth time cannot move on a live object — at
    // any granularity, which is why this passes `Coarse`.
    let a = sample(1, 2, None, Some(100));
    let b = sample(1, 2, None, Some(200));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
}

#[test]
fn matching_birth_time_on_a_fine_clock_proves_same_object() {
    // Birth time is the second-ranked reuse discriminator: on almost
    // every real Unix filesystem it is the *only* one `stat` exposes,
    // so this is the common case `compare` must actually handle, not
    // the exotic one. Without this, `compare` would report `Ambiguous`
    // for the ordinary "same untouched file, observed twice" case on
    // Linux and macOS alike, which would make every caller that blocks
    // on ambiguity unusable on the platforms that matter most.
    let a = sample(1, 2, None, Some(100));
    let b = sample(1, 2, None, Some(100));
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::SameObject);
}

#[test]
fn matching_birth_time_on_a_coarse_clock_is_ambiguous_not_same() {
    // The R6 case: a coarse clock cannot distinguish "the same object,
    // unchanged" from "a different object created within the same
    // tick as the one it replaced". Equal birth time on such a clock
    // must NOT be read as proof, even though the exact same field
    // comparison proves `SameObject` on a `Fine` clock (previous
    // test). Getting this backwards is a real data-loss path: recovery
    // could mistake fresh user content for the object it's meant to
    // recognize.
    let a = sample(1, 2, None, Some(100));
    let b = sample(1, 2, None, Some(100));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::Ambiguous(AmbiguityReason::CoarseTimestampGranularity)
    );
}

#[test]
fn no_generation_counter_and_no_birth_time_at_all_is_ambiguous() {
    let a = sample(1, 2, None, None);
    let b = sample(1, 2, None, None);
    assert_eq!(
        a.compare(&b, TimestampGranularity::Fine),
        IdentityComparison::Ambiguous(AmbiguityReason::NoStableGenerationOrUsn)
    );
}

fn symlink_sample(
    device_id: u64,
    inode: u64,
    birth: Option<i64>,
    symlink_target_digest: Option<[u8; 32]>,
) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id },
        object_id: PlatformObjectId::Unix { inode },
        object_kind: ObjectKind::Symlink,
        generation_or_usn: None,
        birth_or_creation_time: birth
            .map(|seconds| Timestamp { seconds_since_unix_epoch: seconds, subsec_nanos: 0 }),
        observed_size: 0,
        metadata_fingerprint: [0; 32],
        link_count: Some(1),
        symlink_target_digest,
    }
}

#[test]
fn matching_symlink_target_digest_on_a_coarse_clock_with_no_generation_counter_proves_same_object()
{
    // A digest match rescues it regardless of granularity, since it is
    // content, not a clock reading.
    let a = symlink_sample(1, 2, Some(100), Some([7; 32]));
    let b = symlink_sample(1, 2, Some(100), Some([7; 32]));
    assert_eq!(a.compare(&b, TimestampGranularity::Coarse), IdentityComparison::SameObject);
}

#[test]
fn differing_symlink_target_digest_is_definitely_different_even_with_a_matching_object_id() {
    // Same volume+inode+kind, but the target text differs: since a live
    // symlink's target cannot itself change, this can only mean the
    // inode was reused by a different object -- conclusive, not merely
    // suspicious, exactly like a differing birth time.
    let a = symlink_sample(1, 2, None, Some([7; 32]));
    let b = symlink_sample(1, 2, None, Some([9; 32]));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
}

#[test]
fn symlink_with_no_target_digest_on_either_side_falls_back_to_birth_time() {
    // A decoded-from-storage identity (or any observation this crate
    // did not populate the digest for) must not be treated as if the
    // digest tier ran and failed -- it should simply fall through to
    // the next tier, same as `generation_or_usn` already does.
    let a = symlink_sample(1, 2, Some(100), None);
    let b = symlink_sample(1, 2, Some(100), None);
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::SameObject);
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::Ambiguous(AmbiguityReason::CoarseTimestampGranularity)
    );
}

#[cfg(unix)]
#[test]
fn observe_path_populates_a_symlink_target_digest_and_a_regular_file_never_does() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("/does/not/matter", &link).unwrap();
    let regular = dir.path().join("regular");
    std::fs::write(&regular, b"content").unwrap();

    let link_identity = FileIdentity::observe_path(&link).unwrap();
    assert!(link_identity.symlink_target_digest.is_some());

    let regular_identity = FileIdentity::observe_path(&regular).unwrap();
    assert_eq!(regular_identity.symlink_target_digest, None);
}

#[cfg(unix)]
#[test]
fn two_symlinks_with_different_targets_report_different_digests() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::os::unix::fs::symlink("/target/one", &a).unwrap();
    std::os::unix::fs::symlink("/target/two", &b).unwrap();

    let identity_a = FileIdentity::observe_path(&a).unwrap();
    let identity_b = FileIdentity::observe_path(&b).unwrap();
    assert_ne!(identity_a.symlink_target_digest, identity_b.symlink_target_digest);
}

#[cfg(target_os = "linux")]
#[test]
fn observe_handle_and_observe_path_report_the_same_symlink_target_digest() {
    // The Linux-only path this whole fix depends on: `open_child_no_
    // follow` opens a symlink `O_PATH | O_NOFOLLOW`, and `custody_
    // transfer` holds that handle across a rename, re-deriving identity
    // from it (`observe_handle`) rather than by re-resolving the name.
    // This proves the handle-based digest actually agrees with the
    // path-based one for the same symlink, not just that both are
    // `Some` — the property that matters, independent of which
    // mechanism `symlink_target_digest_from_handle` uses to get there.
    // An earlier version of this test passed with a mechanism
    // (`/proc/self/fd/<fd>` via `read_link`) that read the wrong string
    // entirely -- see that function's doc for what was wrong and why
    // this exact assertion is what caught it.
    use std::os::unix::fs::OpenOptionsExt;

    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink("/does/not/matter", &link).unwrap();

    let from_path = FileIdentity::observe_path(&link).unwrap();
    assert!(from_path.symlink_target_digest.is_some());

    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(&link)
        .unwrap();
    let from_handle = FileIdentity::observe_handle(&handle).unwrap();
    assert_eq!(from_handle.symlink_target_digest, from_path.symlink_target_digest);
}

/// Opens `path` the same `O_PATH | O_NOFOLLOW` way `symlink_target_
/// digest_from_handle`'s real caller does, for tests that drive
/// `read_symlink_target_with_buffer_sizes` directly.
#[cfg(target_os = "linux")]
fn open_no_follow(path: &Path) -> File {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)
        .unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn readlinkat_truncation_is_never_reported_as_a_complete_digest() {
    // The defect this whole fix is for: a real `PATH_MAX` (4096 on
    // Linux) is out of reach for a symlink target on a normal
    // filesystem -- `symlink(2)` itself refuses to create one longer
    // than that. So this drives `read_symlink_target_with_buffer_sizes`
    // directly with a forced 8-byte starting buffer instead, which
    // exercises the exact same truncation/growth logic
    // `read_symlink_target_via_handle` uses against a real handle, just
    // at a threshold a real filesystem symlink can actually cross.
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("link");
    let target = "0123456789abcdef"; // 16 bytes, longer than the 8-byte start
    std::os::unix::fs::symlink(target, &link).unwrap();
    let handle = open_no_follow(&link);

    // A cap equal to the starting buffer size means the first read is
    // already truncated and can never grow past it -- this must report
    // `Unreadable`, never a digest of the truncated first 8 bytes.
    let capped = read_symlink_target_with_buffer_sizes(&handle, 8, 8);
    assert!(matches!(capped, SymlinkTargetRead::Unreadable));

    // The same read with room to grow must recover the complete target
    // and produce a real digest over all 16 bytes, not the first 8.
    let grown = read_symlink_target_with_buffer_sizes(&handle, 8, 64);
    match grown {
        SymlinkTargetRead::Target(bytes) => assert_eq!(bytes, target.as_bytes()),
        other => panic!("expected a complete target, got {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn two_long_shared_prefix_targets_do_not_collide_after_growth() {
    // Two targets that agree on everything an 8-byte truncated read
    // would see must still digest differently once the buffer is
    // allowed to grow far enough to see where they diverge -- proving
    // growth (not just truncation-detection) actually recovers enough
    // of the target to distinguish them, not just enough to notice
    // *something* was cut off.
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    let prefix = "shared-prefix-"; // 14 bytes, already > the 8-byte start
    std::os::unix::fs::symlink(format!("{prefix}one"), &a).unwrap();
    std::os::unix::fs::symlink(format!("{prefix}two"), &b).unwrap();

    let handle_a = open_no_follow(&a);
    let handle_b = open_no_follow(&b);
    let read_a = read_symlink_target_with_buffer_sizes(&handle_a, 8, 64);
    let read_b = read_symlink_target_with_buffer_sizes(&handle_b, 8, 64);

    match (read_a, read_b) {
        (SymlinkTargetRead::Target(bytes_a), SymlinkTargetRead::Target(bytes_b)) => {
            assert_ne!(bytes_a, bytes_b);
        }
        other => panic!("expected two complete, distinct targets, got {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn eintr_is_retried_not_surfaced_as_a_result() {
    // Mirrors `fs_capabilities`'s own `retry_eintr` test: a mock
    // `attempt` that reports `EINTR` twice before succeeding must be
    // called exactly three times and must return the eventual success,
    // never surface the interruption as a result on its own.
    let mut calls = 0;
    let (ret, errno) = retry_eintr(|| {
        calls += 1;
        if calls < 3 {
            (-1, Some(libc::EINTR))
        } else {
            (7, None)
        }
    });
    assert_eq!(calls, 3, "EINTR must be retried, not surfaced as a result");
    assert_eq!((ret, errno), (7, None));
}

#[cfg(target_os = "linux")]
#[test]
fn eintr_retry_does_not_mask_a_real_error() {
    // A `-1` with anything other than `EINTR` is a real result, not a
    // signal interruption, and must be returned immediately rather than
    // retried.
    let mut calls = 0;
    let (ret, errno) = retry_eintr(|| {
        calls += 1;
        (-1, Some(libc::ENOENT))
    });
    assert_eq!(calls, 1, "a non-EINTR error must not be retried");
    assert_eq!((ret, errno), (-1, Some(libc::ENOENT)));
}

/// Builds a `FileIdentity` carrying an unproven `WindowsObjectId::
/// Fallback` id -- the shape a real observation takes when
/// `GetFileInformationByHandleEx(FileIdInfo)` is unavailable.
fn windows_fallback_sample(
    volume_serial_number: u64,
    file_index: u64,
    generation_or_usn: Option<u128>,
    birth: Option<i64>,
) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Windows { volume_serial_number },
        object_id: PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index }),
        object_kind: ObjectKind::Directory,
        generation_or_usn,
        birth_or_creation_time: birth
            .map(|seconds| Timestamp { seconds_since_unix_epoch: seconds, subsec_nanos: 0 }),
        observed_size: 0,
        metadata_fingerprint: [0; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

/// Builds a `FileIdentity` carrying a proven `WindowsObjectId::Proven`
/// id -- the shape a real observation takes when `GetFileInformationBy
/// HandleEx(FileIdInfo)` succeeds.
fn windows_proven_sample(
    volume_serial_number: u64,
    file_id: [u8; 16],
    generation_or_usn: Option<u128>,
    birth: Option<i64>,
) -> FileIdentity {
    FileIdentity {
        volume_identity: VolumeIdentity::Windows { volume_serial_number },
        object_id: PlatformObjectId::Windows(WindowsObjectId::Proven { file_id }),
        object_kind: ObjectKind::Directory,
        generation_or_usn,
        birth_or_creation_time: birth
            .map(|seconds| Timestamp { seconds_since_unix_epoch: seconds, subsec_nanos: 0 }),
        observed_size: 0,
        metadata_fingerprint: [0; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

#[test]
fn windows_fallback_object_id_match_with_matching_generation_is_ambiguous_not_same() {
    // The ReFS defect this guards: `WindowsObjectId::Fallback`'s 64-bit
    // file index is not guaranteed unique on ReFS, so even a matching
    // `generation_or_usn` on top of it must not be read as proof of
    // "same object" -- two distinct, simultaneously live directories
    // could coincidentally share both fields.
    let a = windows_fallback_sample(1, 2, Some(9), None);
    let b = windows_fallback_sample(1, 2, Some(9), None);
    assert_eq!(
        a.compare(&b, TimestampGranularity::Fine),
        IdentityComparison::Ambiguous(AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs)
    );
}

#[test]
fn windows_fallback_object_id_match_with_matching_fine_birth_time_is_ambiguous_not_same() {
    let a = windows_fallback_sample(1, 2, None, Some(100));
    let b = windows_fallback_sample(1, 2, None, Some(100));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Fine),
        IdentityComparison::Ambiguous(AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs)
    );
}

#[test]
fn windows_fallback_object_id_match_still_reports_definitely_different_on_a_real_mismatch() {
    // A conclusive mismatch is unaffected by the ReFS caveat: it does
    // not depend on the object id being trustworthy, only on a field
    // that cannot move backward on a live object.
    let a = windows_fallback_sample(1, 2, None, Some(100));
    let b = windows_fallback_sample(1, 2, None, Some(200));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
    let c = windows_fallback_sample(1, 2, Some(9), None);
    let d = windows_fallback_sample(1, 2, Some(10), None);
    assert_eq!(c.compare(&d, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
}

#[test]
fn windows_fallback_differing_volume_or_object_id_is_still_definitely_different() {
    let a = windows_fallback_sample(1, 2, Some(9), None);
    let b = windows_fallback_sample(2, 2, Some(9), None);
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
    let c = windows_fallback_sample(1, 2, Some(9), None);
    let d = windows_fallback_sample(1, 3, Some(9), None);
    assert_eq!(c.compare(&d, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
}

#[test]
fn windows_proven_object_id_match_with_matching_fine_birth_time_is_same_object() {
    // The whole point of carrying the 128-bit `FILE_ID_INFO` id: unlike
    // the fallback case above, a match here IS trusted, exactly like a
    // Unix inode -- no ReFS collision caveat applies to it.
    let a = windows_proven_sample(1, [7; 16], None, Some(100));
    let b = windows_proven_sample(1, [7; 16], None, Some(100));
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::SameObject);
}

#[test]
fn windows_proven_object_id_match_with_no_generation_and_no_birth_time_is_same_object() {
    // MEASURED regression on a real Windows 11 host: `generation_or_usn`
    // is never populated there, and this is what an observation with no
    // `birth_or_creation_time` either (or one this host's clock probe
    // could not trust) resolves to. A matching `Proven` id needs
    // neither field -- see its own doc for why a match on it is itself
    // a reuse discriminator (the NTFS sequence number embedded in its
    // low 64 bits increments on every MFT record reuse).
    let a = windows_proven_sample(1, [7; 16], None, None);
    let b = windows_proven_sample(1, [7; 16], None, None);
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::SameObject);
}

#[test]
fn windows_proven_object_id_match_with_matching_coarse_birth_time_is_same_object() {
    // The other half of the same regression: this must resolve to
    // `SameObject` even when the volume's clock was measured `Coarse`,
    // unlike the equivalent `Fallback` case just above, which has
    // nothing else to fall back on.
    let a = windows_proven_sample(1, [7; 16], None, Some(100));
    let b = windows_proven_sample(1, [7; 16], None, Some(100));
    assert_eq!(a.compare(&b, TimestampGranularity::Coarse), IdentityComparison::SameObject);
}

#[test]
fn windows_proven_object_id_match_with_differing_birth_time_is_still_definitely_different() {
    // A `Proven` match rescues an otherwise-`Ambiguous` verdict; it
    // never overrides a conclusive mismatch found elsewhere. A live
    // object's birth time cannot move, so two observations sharing a
    // `Proven` id but disagreeing on it are exactly the anomaly this
    // module refuses to paper over.
    let a = windows_proven_sample(1, [7; 16], None, Some(100));
    let b = windows_proven_sample(1, [7; 16], None, Some(200));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
}

#[test]
fn windows_proven_object_id_mismatch_is_definitely_different() {
    let a = windows_proven_sample(1, [7; 16], None, Some(100));
    let b = windows_proven_sample(1, [8; 16], None, Some(100));
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::DefinitelyDifferent);
}

#[test]
fn windows_proven_and_fallback_ids_for_one_comparison_are_ambiguous_not_compared_directly() {
    // See `AmbiguityReason::WindowsIdentityMethodMismatch`'s doc: this
    // shape should not arise from one running process, but `compare`
    // must not silently coerce it into either `SameObject` (it can't
    // prove that) or `DefinitelyDifferent` (a stronger claim than a
    // representation mismatch actually supports).
    let a = windows_proven_sample(1, [7; 16], None, Some(100));
    let b = windows_fallback_sample(1, 2, None, Some(100));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Fine),
        IdentityComparison::Ambiguous(AmbiguityReason::WindowsIdentityMethodMismatch)
    );
}

#[test]
fn windows_proven_and_fallback_with_differing_volume_serial_is_ambiguous_not_different() {
    // The ordering defect this guards: a `Proven` observation's full
    // 64-bit `FILE_ID_INFO::VolumeSerialNumber` and a `Fallback`
    // observation's zero-extended legacy 32-bit serial are not
    // guaranteed to come out byte-identical for the same volume (see
    // `VolumeIdentity::Windows`'s doc). Checking volume equality before
    // the method-mismatch check would make that disagreement report
    // `DefinitelyDifferent` for what could be the very same object --
    // the method mismatch must be caught first and reported `Ambiguous`
    // regardless of whether the volume fields happen to agree.
    let a = windows_proven_sample(0x1_0000_0001, [7; 16], None, Some(100));
    let b = windows_fallback_sample(1, 2, None, Some(100));
    assert_eq!(
        a.compare(&b, TimestampGranularity::Fine),
        IdentityComparison::Ambiguous(AmbiguityReason::WindowsIdentityMethodMismatch)
    );
}

#[test]
fn ambiguous_result_cannot_be_read_as_a_bare_bool() {
    // This test exists to keep the type honest: `IdentityComparison`
    // has no `PartialEq<bool>` or `From<IdentityComparison> for bool`,
    // so this only compiles because callers are forced to match on
    // the variant explicitly.
    let a = sample(1, 2, None, None);
    let b = sample(1, 2, None, None);
    let same = match a.compare(&b, TimestampGranularity::Fine) {
        IdentityComparison::SameObject => true,
        IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => false,
    };
    assert!(!same);
}

#[test]
fn observe_path_and_observe_handle_agree_on_a_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("probe-target");
    std::fs::write(&path, b"content").unwrap();

    let from_path = FileIdentity::observe_path(&path).unwrap();
    let handle = File::open(&path).unwrap();
    let from_handle = FileIdentity::observe_handle(&handle).unwrap();

    assert_eq!(from_path.volume_identity, from_handle.volume_identity);
    assert_eq!(from_path.object_id, from_handle.object_id);
    assert_eq!(from_path.object_kind, ObjectKind::RegularFile);
}

#[test]
fn observing_the_same_untouched_file_twice_compares_same_object_given_a_fine_clock() {
    // A real, host-observed identity, not the synthetic `sample()`
    // fixture above: this is the case that actually exercises whatever
    // reuse discriminator this host's filesystem actually provides —
    // `birth_or_creation_time` on macOS and on any Linux volume without
    // `FS_IOC_GETVERSION` (overlayfs, measured), or `generation_or_usn`
    // on a Linux volume that has it (ext4/XFS, measured — see
    // `linux_inode_generation_is_stable_and_deterministic_when_
    // available` below for a test that pins that path specifically).
    // Whichever one fires, `compare` must still land on `SameObject`
    // for the same untouched file observed twice.
    //
    // `Fine` is asserted here as the premise under test, not measured:
    // measuring a real volume's granularity is `fs_capabilities`'s
    // job (it has the probing infrastructure this module deliberately
    // does not), exercised there against real timing.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("untouched");
    std::fs::write(&path, b"content").unwrap();

    let first = FileIdentity::observe_path(&path).unwrap();
    let second = FileIdentity::observe_path(&path).unwrap();

    assert_eq!(first.compare(&second, TimestampGranularity::Fine), IdentityComparison::SameObject);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_inode_generation_is_stable_and_deterministic_when_available() {
    // Whether `FS_IOC_GETVERSION` is available at all is a property of
    // the volume this test happens to run on (ext4/XFS: yes, measured
    // to work unprivileged and to discriminate every observed inode
    // reuse; overlayfs: no, measured `ENOTTY` even as root with every
    // capability — see `generation_from_path`'s doc), so this does not
    // assert presence unconditionally; CI's own container root is
    // overlayfs and legitimately takes the `None` branch below. What it
    // does assert unconditionally, once the ioctl IS available: two
    // observations of the same untouched file report the identical
    // generation, and `compare` reaches `SameObject` through that field
    // specifically — passing `Coarse` granularity deliberately, so a
    // wrongly-granularity-gated implementation of the generation branch
    // would fail this — and a differing generation on an otherwise
    // identical identity still proves `DefinitelyDifferent` even under
    // `Fine` granularity, showing the generation check really runs
    // before, not after, the birth-time fallback.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("untouched");
    std::fs::write(&path, b"content").unwrap();

    let first = FileIdentity::observe_path(&path).unwrap();
    let second = FileIdentity::observe_path(&path).unwrap();
    eprintln!(
        "linux_inode_generation_is_stable_and_deterministic_when_available: \
         generation_or_usn={:?}",
        first.generation_or_usn
    );

    let (Some(first_generation), Some(second_generation)) =
        (first.generation_or_usn, second.generation_or_usn)
    else {
        // Not available on this volume -- the fallback path is what
        // `observing_the_same_untouched_file_twice_compares_same_
        // object_given_a_fine_clock` above covers.
        return;
    };
    assert_eq!(first_generation, second_generation);
    assert_eq!(
        first.compare(&second, TimestampGranularity::Coarse),
        IdentityComparison::SameObject
    );

    let mut different_generation = second;
    different_generation.generation_or_usn = Some(first_generation.wrapping_add(1));
    assert_eq!(
        first.compare(&different_generation, TimestampGranularity::Fine),
        IdentityComparison::DefinitelyDifferent
    );
}

#[cfg(unix)]
#[test]
fn observe_path_does_not_follow_a_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"content").unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let identity = FileIdentity::observe_path(&link).unwrap();
    assert_eq!(identity.object_kind, ObjectKind::Symlink);
}

#[test]
fn regular_file_is_eligible_for_replacement() {
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::RegularFile, Some(1)),
        ReplacementEligibility::Eligible
    );
}

#[test]
fn hardlinked_file_is_blocked_before_link_count_is_known_to_be_singular() {
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::RegularFile, Some(2)),
        ReplacementEligibility::Blocked(BlockedObjectReason::HardlinkTopologyUnsupported)
    );
}

#[test]
fn unknown_link_count_is_blocked_not_treated_as_unlinked() {
    // R5: an observation that cannot report a link count at all (the
    // shape a Windows `Metadata` produces when `number_of_links`
    // itself is unavailable) must not fall through to `Eligible`.
    // Blocking on `None` is the fail-closed answer for "this platform
    // cannot rule out a hardlink", not a special case to work around.
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::RegularFile, None),
        ReplacementEligibility::Blocked(BlockedObjectReason::UnknownHardlinkTopology)
    );
}

#[test]
fn special_object_kinds_are_blocked_regardless_of_link_count() {
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::Fifo, Some(1)),
        ReplacementEligibility::Blocked(BlockedObjectReason::Fifo)
    );
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::Socket, Some(1)),
        ReplacementEligibility::Blocked(BlockedObjectReason::Socket)
    );
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::BlockDevice, Some(1)),
        ReplacementEligibility::Blocked(BlockedObjectReason::DeviceNode)
    );
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::CharDevice, Some(1)),
        ReplacementEligibility::Blocked(BlockedObjectReason::DeviceNode)
    );
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::ReparsePoint, Some(1)),
        ReplacementEligibility::Blocked(BlockedObjectReason::UnsupportedReparsePoint)
    );
}

#[cfg(unix)]
#[test]
fn real_hardlink_reports_link_count_above_one() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let alias = dir.path().join("alias");
    std::fs::write(&original, b"content").unwrap();
    std::fs::hard_link(&original, &alias).unwrap();

    let identity = FileIdentity::observe_path(&original).unwrap();
    assert_eq!(identity.link_count, Some(2));
    assert_eq!(
        classify_replacement_eligibility(identity.object_kind, identity.link_count),
        ReplacementEligibility::Blocked(BlockedObjectReason::HardlinkTopologyUnsupported)
    );
}

#[test]
fn a_structurally_multi_linked_directory_is_still_eligible() {
    // Regression for a real bug this module shipped: an empty
    // directory's `nlink` is structurally 2 (`.` plus the parent's
    // entry to it) on every mainstream filesystem, which the
    // hardlink-topology check used to read as "more than one path to
    // this object" and block unconditionally — meaning no directory
    // could ever be replaced by this engine at all. The check now
    // only applies to `RegularFile`.
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::Directory, Some(2)),
        ReplacementEligibility::Eligible
    );
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::Directory, None),
        ReplacementEligibility::Eligible
    );
}

#[test]
fn a_symlink_is_eligible_regardless_of_reported_link_count() {
    // A symlink can never itself be hardlinked (its own `nlink` is
    // always 1), but this asserts eligibility is unconditional on the
    // field anyway, matching the directory case above rather than
    // relying on every platform actually reporting 1.
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::Symlink, Some(2)),
        ReplacementEligibility::Eligible
    );
    assert_eq!(
        classify_replacement_eligibility(ObjectKind::Symlink, None),
        ReplacementEligibility::Eligible
    );
}

#[cfg(unix)]
#[test]
fn a_real_freshly_created_directory_reports_the_structural_nlink_and_stays_eligible() {
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("subdir");
    std::fs::create_dir(&subdir).unwrap();

    let identity = FileIdentity::observe_path(&subdir).unwrap();
    assert_eq!(
        identity.link_count,
        Some(2),
        "an empty directory's own structural nlink -- not a hardlink"
    );
    assert_eq!(
        classify_replacement_eligibility(identity.object_kind, identity.link_count),
        ReplacementEligibility::Eligible
    );
}

// --- Defect 1: FILE_ID_INFO sentinel FileId values ------------------
//
// `windows_file_id_is_sentinel` is deliberately not `#[cfg(windows)]`
// (see its doc), so these run on every host even though the FFI call
// that would actually produce a sentinel `FileId` only exists on
// Windows.

#[test]
fn all_zero_file_id_is_a_sentinel_not_a_proven_id() {
    // [MS-FSCC]'s "128-bit file ID": "For file systems that do not
    // support a 128-bit file ID, this field MUST be set to 0."
    assert!(windows_file_id_is_sentinel([0; 16]));
}

#[test]
fn all_ones_file_id_is_a_sentinel_not_a_proven_id() {
    // [MS-FSCC]'s "128-bit file ID": "For files for which a unique
    // 128-bit file ID cannot be established, this field MUST be set to
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF."
    assert!(windows_file_id_is_sentinel([0xff; 16]));
}

#[test]
fn an_ordinary_file_id_is_not_a_sentinel() {
    let mut file_id = [0u8; 16];
    file_id[0] = 1;
    assert!(!windows_file_id_is_sentinel(file_id));

    let mut almost_all_ones = [0xffu8; 16];
    almost_all_ones[15] = 0xfe;
    assert!(!windows_file_id_is_sentinel(almost_all_ones));
}

// --- Defect 2: `DirectoryIdentity::compare` --------------------------

fn directory_sample(
    volume_serial_number: u64,
    object_id: PlatformObjectId,
    generation_or_usn: Option<u128>,
) -> DirectoryIdentity {
    directory_sample_with_birth(volume_serial_number, object_id, generation_or_usn, None)
}

fn directory_sample_with_birth(
    volume_serial_number: u64,
    object_id: PlatformObjectId,
    generation_or_usn: Option<u128>,
    birth_or_creation_time: Option<Timestamp>,
) -> DirectoryIdentity {
    DirectoryIdentity {
        volume_identity: VolumeIdentity::Windows { volume_serial_number },
        object_id,
        generation_or_usn,
        birth_or_creation_time,
    }
}

#[test]
fn directory_matching_fallback_id_is_ambiguous_not_same_object() {
    // The defect this closes: two distinct, simultaneously live
    // directories on one ReFS volume can report the same
    // `WindowsObjectId::Fallback` 64-bit index. A caller reaching for
    // plain `==` (impossible now that the derive is gone) would read
    // this as proof; `compare` must not. Granularity is irrelevant
    // here: `generation_or_usn` is what decides this case.
    let a = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: 99 }),
        Some(5),
    );
    let b = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: 99 }),
        Some(5),
    );
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::Ambiguous(AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs)
    );
}

#[test]
fn directory_matching_proven_id_and_generation_is_same_object() {
    let a = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(5),
    );
    let b = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(5),
    );
    assert_eq!(a.compare(&b, TimestampGranularity::Coarse), IdentityComparison::SameObject);
}

#[test]
fn directory_matching_proven_id_with_no_generation_and_no_birth_time_is_same_object() {
    // The regression this guards: a real Windows observation has no
    // portable `generation_or_usn` source and, on some hosts, too
    // coarse a clock to trust `birth_or_creation_time` either -- the
    // exact shape every identity-dependent operation was measured to
    // refuse under before this fix, for every untouched object, on a
    // real Windows 11 host. A matching `WindowsObjectId::Proven` id
    // needs neither field -- see its own doc for why a match on it is
    // itself a reuse discriminator.
    let a = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
    );
    let b = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
    );
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::SameObject);
}

#[test]
fn directory_matching_birth_time_on_a_fine_clock_with_no_generation_is_same_object() {
    let birth = Some(Timestamp { seconds_since_unix_epoch: 1_700_000_000, subsec_nanos: 0 });
    let a = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
        birth,
    );
    let b = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
        birth,
    );
    assert_eq!(a.compare(&b, TimestampGranularity::Fine), IdentityComparison::SameObject);
}

#[test]
fn directory_matching_proven_id_and_birth_time_on_a_coarse_clock_is_same_object() {
    // The other half of the same regression: a matching `Proven` id
    // must resolve to `SameObject` even on a `Coarse` clock, unlike a
    // matching `Fallback` id or a matching Unix inode, neither of which
    // has anything else to fall back on here -- see the next test.
    let birth = Some(Timestamp { seconds_since_unix_epoch: 1_700_000_000, subsec_nanos: 0 });
    let a = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
        birth,
    );
    let b = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
        birth,
    );
    assert_eq!(a.compare(&b, TimestampGranularity::Coarse), IdentityComparison::SameObject);
}

#[test]
fn directory_matching_fallback_birth_time_on_a_coarse_clock_with_no_generation_is_ambiguous() {
    // The exact overlayfs shape this whole change exists for: no
    // generation counter, and a clock too coarse to trust an equal
    // birth time as proof -- a delete-and-recreate landing in the same
    // tick as the directory it replaced is indistinguishable here, so
    // this must not be read as `SameObject`. Uses `Fallback`, not
    // `Proven`, specifically because a `Proven` id match no longer
    // needs the clock's help at all -- see the previous test.
    let birth = Some(Timestamp { seconds_since_unix_epoch: 1_700_000_000, subsec_nanos: 0 });
    let a = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: 99 }),
        None,
        birth,
    );
    let b = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: 99 }),
        None,
        birth,
    );
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::Ambiguous(AmbiguityReason::CoarseTimestampGranularity)
    );
}

#[test]
fn directory_differing_birth_time_is_definitely_different_regardless_of_granularity() {
    let a = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
        Some(Timestamp { seconds_since_unix_epoch: 1_700_000_000, subsec_nanos: 0 }),
    );
    let b = directory_sample_with_birth(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        None,
        Some(Timestamp { seconds_since_unix_epoch: 1_700_000_001, subsec_nanos: 0 }),
    );
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
}

#[test]
fn directory_matching_proven_id_with_differing_generation_is_definitely_different() {
    // When `generation_or_usn` *is* available on both sides, a
    // difference is still conclusive proof of reuse.
    let a = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(1),
    );
    let b = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(2),
    );
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
}

#[test]
fn directory_differing_volume_serial_is_definitely_different() {
    let a = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(5),
    );
    let b = directory_sample(
        2,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(5),
    );
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::DefinitelyDifferent
    );
}

#[test]
fn directory_mixed_proven_and_fallback_with_differing_serial_width_is_ambiguous() {
    // Defect 3's ordering fix, exercised through `DirectoryIdentity`
    // too: a legacy 32-bit volume serial zero-extended into the 64-bit
    // field (the shape `Fallback` observations report -- see
    // `VolumeIdentity::Windows`'s doc) must not make a mixed-method
    // pair read as `DefinitelyDifferent` before the method mismatch is
    // ever considered.
    let a = directory_sample(
        0x1_0000_0001,
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id: [9; 16] }),
        Some(5),
    );
    let b = directory_sample(
        1,
        PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: 99 }),
        Some(5),
    );
    assert_eq!(
        a.compare(&b, TimestampGranularity::Coarse),
        IdentityComparison::Ambiguous(AmbiguityReason::WindowsIdentityMethodMismatch)
    );
}

#[cfg(unix)]
#[test]
fn directory_matching_unix_inode_and_generation_is_same_object() {
    let a = directory_sample_unix(1, 2, Some(5));
    let b = directory_sample_unix(1, 2, Some(5));
    assert_eq!(a.compare(&b, TimestampGranularity::Coarse), IdentityComparison::SameObject);
}

#[cfg(unix)]
fn directory_sample_unix(
    device_id: u64,
    inode: u64,
    generation_or_usn: Option<u128>,
) -> DirectoryIdentity {
    DirectoryIdentity {
        volume_identity: VolumeIdentity::Unix { device_id },
        object_id: PlatformObjectId::Unix { inode },
        generation_or_usn,
        birth_or_creation_time: None,
    }
}

// --- Real Windows filesystem behavior ------------------------------
//
// Verifies `FileIdentity::from_metadata`'s Windows branch against a
// real NTFS volume: that `MetadataExt::volume_serial_number`/
// `file_index`/`number_of_links` actually populate (not just compile),
// and that two hardlinked paths report the identity a caller needs to
// recognize them as the same object.

#[cfg(windows)]
#[test]
fn windows_volume_serial_and_file_index_actually_populate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.txt");
    std::fs::write(&path, b"content").unwrap();

    let identity = FileIdentity::observe_path(&path).unwrap();
    match identity.volume_identity {
        VolumeIdentity::Windows { volume_serial_number } => {
            assert_ne!(
                volume_serial_number, 0,
                "a real NTFS volume must report a nonzero serial number"
            );
        }
        other => panic!("expected VolumeIdentity::Windows, got {other:?}"),
    }
    // Which of the two cases this host actually takes is a property of
    // its OS version and volume, not something this test can pin down
    // in advance -- see `win_identity::ObjectIdFields`'s doc. Either way
    // the id itself must be nonzero; `eprintln!` records which branch
    // actually ran so a CI log is honest about which case it exercised,
    // matching this module's other host-dependent tests (see
    // `linux_inode_generation_is_stable_and_deterministic_when_
    // available`).
    match identity.object_id {
        PlatformObjectId::Windows(WindowsObjectId::Proven { file_id }) => {
            eprintln!(
                "windows_volume_serial_and_file_index_actually_populate: took the Proven \
                 (FileIdInfo) branch"
            );
            assert_ne!(file_id, [0; 16], "a real file must report a nonzero file id");
        }
        PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index }) => {
            eprintln!(
                "windows_volume_serial_and_file_index_actually_populate: took the Fallback \
                 (BY_HANDLE_FILE_INFORMATION) branch -- FileIdInfo unavailable on this host"
            );
            assert_ne!(file_index, 0, "a real file must report a nonzero file index");
        }
        other => panic!("expected PlatformObjectId::Windows, got {other:?}"),
    }
    assert_eq!(identity.link_count, Some(1), "an ordinary, non-hardlinked file's link count");
}

#[cfg(windows)]
#[test]
fn windows_hardlinked_files_share_identity_and_report_link_count_above_one() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original.txt");
    let alias = dir.path().join("alias.txt");
    std::fs::write(&original, b"content").unwrap();
    std::fs::hard_link(&original, &alias).unwrap();

    let original_identity = FileIdentity::observe_path(&original).unwrap();
    let alias_identity = FileIdentity::observe_path(&alias).unwrap();

    assert_eq!(
        original_identity.volume_identity, alias_identity.volume_identity,
        "both paths name objects on the same volume"
    );
    assert_eq!(
        original_identity.object_id, alias_identity.object_id,
        "a hardlink's two paths must resolve to the same underlying file index -- this is \
         the entire premise `classify_replacement_eligibility` relies on to detect and \
         block hardlinked objects"
    );
    assert_eq!(original_identity.link_count, Some(2));
    assert_eq!(alias_identity.link_count, Some(2));
    assert_eq!(
        classify_replacement_eligibility(
            original_identity.object_kind,
            original_identity.link_count
        ),
        ReplacementEligibility::Blocked(BlockedObjectReason::HardlinkTopologyUnsupported)
    );
}

#[cfg(windows)]
#[test]
fn windows_distinct_files_report_distinct_file_index() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    std::fs::write(&a, b"content-a").unwrap();
    std::fs::write(&b, b"content-b").unwrap();

    let identity_a = FileIdentity::observe_path(&a).unwrap();
    let identity_b = FileIdentity::observe_path(&b).unwrap();
    assert_ne!(identity_a.object_id, identity_b.object_id);
}

/// A directory's size and timestamps follow its entries. Adding, renaming
/// or removing an entry inside it is not a change to the directory, so its
/// fingerprint must not move -- or every child landing in a directory
/// would read as the directory itself having been touched.
#[test]
fn a_directory_fingerprint_ignores_changes_to_its_entries() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("d");
    std::fs::create_dir(&dir).unwrap();
    let before = FileIdentity::observe_path(&dir).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    std::fs::write(dir.join("x"), b"child").unwrap();
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::rename(dir.join("x"), dir.join("y")).unwrap();
    let after = FileIdentity::observe_path(&dir).unwrap();
    assert_eq!(before.metadata_fingerprint, after.metadata_fingerprint);
}

#[cfg(unix)]
#[test]
fn a_directory_fingerprint_follows_its_mode() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("d");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let before = FileIdentity::observe_path(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let after = FileIdentity::observe_path(&dir).unwrap();
    assert_ne!(before.metadata_fingerprint, after.metadata_fingerprint);
}

/// A hook that rewrites a file in place and puts back both its write time and its change time
/// (`FileBasicInfo` lets a caller set either) leaves the length, the write time and the change
/// time as they were. The file's USN, which only the file system's journal moves, still tells.
#[cfg(windows)]
#[test]
fn windows_a_rewrite_that_restores_write_time_and_change_time_is_still_seen() {
    use std::ffi::c_void;
    use std::io::Write as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, SetFileInformationByHandle, FILE_BASIC_INFO,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.bin");
    std::fs::write(&path, b"aaaa").unwrap();
    let before = disk_race_fingerprint(&path).unwrap();
    let before_identity = FileIdentity::observe_path(&path).unwrap();

    let mut file = std::fs::OpenOptions::new().read(true).write(true).open(&path).unwrap();
    let handle = file.as_raw_handle();
    let size = std::mem::size_of::<FILE_BASIC_INFO>() as u32;
    // SAFETY: `handle` is open for the whole block; `original` is a `FILE_BASIC_INFO` of `size`.
    let mut original: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    let got = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut original as *mut FILE_BASIC_INFO).cast::<c_void>(),
            size,
        )
    };
    assert_ne!(got, 0, "reading the times");
    std::thread::sleep(std::time::Duration::from_millis(30));
    file.write_all(b"bbbb").unwrap();
    file.flush().unwrap();
    // SAFETY: as above; the structure carries exactly the times that were read.
    let set = unsafe {
        SetFileInformationByHandle(
            handle,
            FileBasicInfo,
            (&original as *const FILE_BASIC_INFO).cast::<c_void>(),
            size,
        )
    };
    assert_ne!(set, 0, "restoring the times");
    drop(file);
    assert_eq!(std::fs::read(&path).unwrap(), b"bbbb");

    let after = disk_race_fingerprint(&path).unwrap();
    assert_eq!(
        (before.0, before.1, before.2),
        (after.0, after.1, after.2),
        "the rewrite restored the length, the write time and the change time"
    );
    assert_ne!(before, after, "the file's USN moved");
    let after_identity = FileIdentity::observe_path(&path).unwrap();
    assert_ne!(before_identity.metadata_fingerprint, after_identity.metadata_fingerprint);
}

/// An untouched file reads the same twice, on a volume with a change journal and on one without
/// (FAT answers the USN request as unsupported): a fingerprint that never compares equal would
/// make every capture on such a volume read as raced.
#[cfg(windows)]
#[test]
fn windows_an_untouched_file_has_a_stable_race_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.bin");
    std::fs::write(&path, b"aaaa").unwrap();
    let first = disk_race_fingerprint(&path).unwrap();
    let second = disk_race_fingerprint(&path).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        FileIdentity::observe_path(&path).unwrap().metadata_fingerprint,
        FileIdentity::observe_path(&path).unwrap().metadata_fingerprint
    );
}
