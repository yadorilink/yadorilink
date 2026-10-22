use super::*;

const EXT4: u64 = 0xEF53;
const BTRFS: u64 = 0x9123_683E;
const ZFS: u64 = 0x2FC1_2FC1;
const XFS: u64 = 0x5846_5342;
const VFAT: u64 = 0x4d44;
const EXFAT: u64 = 0x2011_BAB0;
const NFS: u64 = 0x6969;
const SMB2: u64 = 0xFE53_4D42;

/// Facts a test controls; a fact the kind must not consult panics.
#[derive(Default)]
struct Facts {
    source: Option<io::Result<String>>,
    uuid: Option<io::Result<Option<[u8; 16]>>>,
    this_mount: Option<Option<String>>,
}

impl LinuxVolumeFacts for Facts {
    fn mount_source(&self) -> io::Result<String> {
        match self.source.as_ref().expect("only a network share reads its mount source") {
            Ok(source) => Ok(source.clone()),
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        }
    }
    fn filesystem_uuid(&self) -> io::Result<Option<[u8; 16]>> {
        match self.uuid.as_ref().expect("only xfs reads its filesystem UUID") {
            Ok(uuid) => Ok(*uuid),
            Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
        }
    }
    fn this_mount(&self) -> io::Result<Option<String>> {
        Ok(self.this_mount.clone().expect("only an unknown volume names its mount"))
    }
}

fn identity(f_type: u64, fsid: u64) -> StableVolumeId {
    LinuxFsKind::from_f_type(f_type).identity(fsid, &Facts::default()).unwrap()
}

fn unknown(f_type: u64, this_mount: Option<&str>) -> StableVolumeId {
    let facts = Facts {
        uuid: Some(Ok(None)),
        this_mount: Some(this_mount.map(str::to_owned)),
        ..Facts::default()
    };
    LinuxFsKind::from_f_type(f_type).identity(0x701, &facts).unwrap()
}

fn matches(recorded: &StableVolumeId, observed: &StableVolumeId) -> VolumeMatch {
    VolumeMatch::of(Some(&recorded.to_string()), &observed.to_string())
}

/// A btrfs or ZFS remount, a btrfs multi-device pool whose udev links point at
/// another member, or a daemon in a container without `/dev/disk`: the
/// filesystem reports the same fsid, so the folder is still on its volume.
/// Nothing but the filesystem itself is consulted, and the recorded form of
/// these kinds is unchanged.
#[test]
fn a_uuid_backed_filesystem_is_identified_by_its_fsid_alone() {
    for f_type in [EXT4, BTRFS, ZFS] {
        let id = identity(f_type, 0x2a4a);
        assert_eq!(id.to_string(), "fsid:2a4a");
        assert_eq!(matches(&id, &identity(f_type, 0x2a4a)), VolumeMatch::Same);
    }
}

/// The empty mountpoint left by an unmounted volume, or another filesystem
/// mounted at the same path, is a different volume.
#[test]
fn a_different_filesystem_at_the_same_path_is_a_different_volume() {
    assert_eq!(matches(&identity(BTRFS, 0x2a4a), &identity(EXT4, 0x1fc0)), VolumeMatch::Other);
    assert_eq!(matches(&identity(ZFS, 0xf5d3), &identity(ZFS, 0x155a)), VolumeMatch::Other);
}

/// xfs is identified by its own UUID, whatever device number (and so fsid) it
/// was given this time.
#[test]
fn xfs_is_identified_by_its_filesystem_uuid() {
    let uuid = [0x5a, 0x1f, 0x3c, 0x9e, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 1, 2, 3];
    let xfs = |fsid| {
        let facts = Facts { uuid: Some(Ok(Some(uuid))), ..Facts::default() };
        LinuxFsKind::from_f_type(XFS).identity(fsid, &facts).unwrap()
    };
    assert_eq!(xfs(0x701).to_string(), "uuid:5a1f3c9e-0123-4567-89ab-cdef00010203");
    assert_eq!(matches(&xfs(0x701), &xfs(0x821)), VolumeMatch::Same);
    let unreadable = Facts { uuid: Some(Err(io::Error::other("EIO"))), ..Facts::default() };
    assert!(LinuxFsKind::from_f_type(XFS).identity(0x701, &unreadable).is_err());
}

/// A replacement vfat/exFAT (or pre-6.5 xfs) disk carrying a copy of the
/// folder, its marker included, mounted where the folder's disk was: nothing
/// tells the two disks apart, so it is never accepted on its own. Only the
/// very mount the user confirmed is the same volume.
#[test]
fn an_unknown_volume_is_never_the_same_as_another_mount() {
    let confirmed = unknown(VFAT, Some("boot-1:57"));
    assert_eq!(confirmed.to_string(), "unknown:boot-1:57");
    assert_eq!(matches(&confirmed, &unknown(VFAT, Some("boot-1:57"))), VolumeMatch::Same);
    for replacement in [
        unknown(VFAT, Some("boot-1:58")),
        unknown(EXFAT, Some("boot-1:58")),
        unknown(XFS, Some("boot-1:58")),
        unknown(VFAT, Some("boot-2:57")),
    ] {
        assert_eq!(matches(&confirmed, &replacement), VolumeMatch::Unconfirmed, "{replacement}");
    }
    // A stable volume mounted over the path is not that mount either.
    assert_eq!(matches(&confirmed, &identity(EXT4, 0x1fc0)), VolumeMatch::Unconfirmed);
    assert_eq!(matches(&identity(EXT4, 0x1fc0), &confirmed), VolumeMatch::Unconfirmed);
}

/// Where the kernel names no mount, an unknown volume matches nothing, not
/// even itself, and is not recorded for a new folder either.
#[test]
fn an_unknown_volume_without_a_mount_name_matches_nothing() {
    let bare = unknown(VFAT, None);
    assert_eq!(bare.to_string(), "unknown");
    assert_eq!(matches(&bare, &bare), VolumeMatch::Unconfirmed);
    assert_eq!(VolumeMatch::of(None, &bare.to_string()), VolumeMatch::Unconfirmed);
    assert_eq!(
        VolumeMatch::of(Some("unknown"), &identity(EXT4, 1).to_string()),
        VolumeMatch::Unconfirmed
    );
    assert_eq!(
        VolumeMatch::of(None, &unknown(VFAT, Some("boot-1:57")).to_string()),
        VolumeMatch::Same
    );
}

/// A kernel upgrade that starts reading an xfs UUID changes what the same
/// disk is recorded as. That is asked of the user, never followed.
#[test]
fn a_change_of_identity_kind_asks_for_re_adoption() {
    let uuid = [7u8; 16];
    let facts = Facts { uuid: Some(Ok(Some(uuid))), ..Facts::default() };
    let upgraded = LinuxFsKind::from_f_type(XFS).identity(0x701, &facts).unwrap();
    let before = unknown(XFS, Some("boot-1:57"));
    assert_eq!(matches(&before, &upgraded), VolumeMatch::Unconfirmed);
    assert_eq!(matches(&upgraded, &before), VolumeMatch::Unconfirmed);
}

/// NFS reports no fsid and a fresh device number per mount; its source names
/// the share.
#[test]
fn a_network_share_is_identified_by_its_source() {
    for f_type in [NFS, SMB2] {
        let facts = Facts { source: Some(Ok("nas:/export/share".to_string())), ..Facts::default() };
        let id = LinuxFsKind::from_f_type(f_type).identity(0, &facts).unwrap();
        assert_eq!(id.to_string(), "mount:nas:/export/share");
    }
}

/// A failed observation is an error to retry, never a weaker identity.
#[test]
fn a_failed_observation_is_an_error_not_a_weaker_identity() {
    let unreadable = Facts { source: Some(Err(io::Error::other("EMFILE"))), ..Facts::default() };
    assert!(LinuxFsKind::from_f_type(NFS).identity(0, &unreadable).is_err());
    let empty = Facts { source: Some(Ok(String::new())), ..Facts::default() };
    assert!(LinuxFsKind::from_f_type(NFS).identity(0, &empty).is_err());
    assert!(LinuxFsKind::from_f_type(EXT4).identity(0, &Facts::default()).is_err());
}

#[test]
fn observing_the_same_directory_twice_agrees() {
    let dir = tempfile::tempdir().unwrap();
    let first = StableVolumeId::observe(dir.path()).unwrap();
    assert_eq!(first.to_string(), StableVolumeId::observe(dir.path()).unwrap().to_string());
    assert!(StableVolumeId::observe(&dir.path().join("missing")).is_err());
}

#[cfg(target_vendor = "apple")]
#[test]
fn a_local_apfs_volume_reports_its_volume_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let id = StableVolumeId::observe(dir.path()).unwrap();
    assert!(matches!(id, StableVolumeId::Uuid(_)), "{id:?}");
}

/// A write path asks for the identity on every operation; after the first
/// observation of a mount it costs a `statx`, not a re-derivation.
#[cfg(target_os = "linux")]
#[test]
fn repeated_observations_of_one_mount_are_served_from_the_cache() {
    use std::sync::atomic::Ordering;
    let dir = tempfile::tempdir().unwrap();
    if linux::mount_key(dir.path()).unwrap().is_none() {
        return; // A kernel without statx mount ids derives every time.
    }
    let first = StableVolumeId::observe(dir.path()).unwrap();
    let before = linux::DERIVATIONS.load(Ordering::Relaxed);
    let started = std::time::Instant::now();
    for _ in 0..10_000 {
        assert_eq!(StableVolumeId::observe(dir.path()).unwrap().to_string(), first.to_string());
    }
    let elapsed = started.elapsed();
    // Other tests in this binary may derive concurrently for their own dirs;
    // this loop alone would add 10 000.
    assert!(linux::DERIVATIONS.load(Ordering::Relaxed) - before < 100);
    eprintln!("10k cached observations: {elapsed:?}");
    let started = std::time::Instant::now();
    for _ in 0..10_000 {
        assert_eq!(linux::derive_uncached(dir.path()).unwrap().to_string(), first.to_string());
    }
    eprintln!("10k uncached derivations: {:?}", started.elapsed());
}

/// A mount id the kernel may hand out again after an unmount (Linux 5.8-6.7)
/// is no cache key: a replacement disk could get the same id and device
/// number as the one it replaced.
#[cfg(target_os = "linux")]
#[test]
fn only_a_unique_mount_id_is_a_cache_key() {
    assert_eq!(linux::cache_key(linux::STATX_MNT_ID, 8, 17, 42), None);
    assert_eq!(linux::cache_key(0, 8, 17, 42), None);
    assert!(linux::cache_key(linux::STATX_MNT_ID_UNIQUE_BIT, 8, 17, 42).is_some());
}

#[cfg(target_os = "linux")]
#[test]
fn mountinfo_picks_the_innermost_mount_and_unescapes_it() {
    let mountinfo = "\
22 1 8:2 / / rw - ext4 /dev/sda2 rw
40 22 0:61 / /mnt/data rw - btrfs /dev/sdb1 rw
41 22 0:62 / /mnt/my\\040share rw - nfs4 nas:/export/a\\040b rw
42 40 0:63 / /mnt/data/sub rw - zfs pool/sub rw
";
    let source = |p: &str| linux::source_of_mount_containing(mountinfo, Path::new(p));
    assert_eq!(source("/mnt/data/folder").as_deref(), Some("/dev/sdb1"));
    assert_eq!(source("/mnt/data/sub/x").as_deref(), Some("pool/sub"));
    assert_eq!(source("/mnt/datax").as_deref(), Some("/dev/sda2"));
    assert_eq!(source("/mnt/my share/f").as_deref(), Some("nas:/export/a b"));
}

/// Real filesystems, for a host that mounts them (a privileged container with
/// loop devices): `YADORILINK_TEST_XFS_DIR` is a directory on xfs, and
/// `YADORILINK_TEST_VFAT_DIR` one on vfat or exFAT. Ignored elsewhere.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs YADORILINK_TEST_XFS_DIR / YADORILINK_TEST_VFAT_DIR on real mounts"]
fn real_xfs_and_vfat_mounts() {
    if let Ok(dir) = std::env::var("YADORILINK_TEST_XFS_DIR") {
        let id = StableVolumeId::observe(Path::new(&dir)).unwrap();
        let uuid = linux::filesystem_uuid(Path::new(&dir)).unwrap();
        eprintln!("xfs {dir}: {id} (FS_IOC_GETFSUUID: {uuid:?})");
        match uuid {
            Some(_) => assert!(matches!(id, StableVolumeId::Uuid(_)), "{id}"),
            None => assert!(matches!(id, StableVolumeId::Unknown { .. }), "{id}"),
        }
        if let Ok(expected) = std::env::var("YADORILINK_TEST_XFS_UUID") {
            assert_eq!(id.to_string(), format!("uuid:{expected}"));
        }
    }
    if let Ok(dir) = std::env::var("YADORILINK_TEST_VFAT_DIR") {
        let id = StableVolumeId::observe(Path::new(&dir)).unwrap();
        eprintln!("vfat {dir}: {id}");
        assert!(matches!(id, StableVolumeId::Unknown { .. }), "{id}");
        if let Ok(previous) = std::env::var("YADORILINK_TEST_VFAT_PREVIOUS") {
            assert_eq!(VolumeMatch::of(Some(&previous), &id.to_string()), VolumeMatch::Unconfirmed);
        }
    }
}
