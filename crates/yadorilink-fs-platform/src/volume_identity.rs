//! Which filesystem a directory lives on, as a value that stays the same across
//! reboots, remounts, device renumbering and the environment the daemon runs
//! in (a container, a sandboxed service), and differs for any other
//! filesystem that carries one.
//!
//! The device number (`st_dev`) is not such a value: Linux hands btrfs, ZFS,
//! NFS and FUSE mounts an anonymous device number at mount time, a USB disk
//! can come back as another block device, and macOS numbers external disks in
//! attach order. The identity is therefore taken from the filesystem itself,
//! chosen by the kind of filesystem so the same filesystem always yields the
//! same kind of value:
//!
//! * Linux ext2/3/4, btrfs and ZFS: `statfs` `f_fsid`, which these derive from
//!   their own on-disk UUID or GUID (btrfs per subvolume).
//! * Linux xfs: its on-disk UUID, read with `FS_IOC_GETFSUUID` (Linux 6.5+).
//! * macOS local volumes: the volume UUID.
//! * Network shares (Linux NFS/SMB, any non-local macOS mount): the mount
//!   source (`server:/export`), which names the share.
//! * Windows: the volume serial number.
//! * Anything else (Linux vfat, exFAT, tmpfs, overlay, FUSE, xfs before 6.5; a
//!   macOS volume without a UUID): [`StableVolumeId::Unknown`]. These offer no
//!   value that survives a remount without depending on udev, the kernel
//!   version or the device numbering, so none is invented.
//!
//! An unknown identity is never the same volume as anything, another unknown
//! one included: a copy of the folder (its marker included) on a replacement
//! disk would otherwise pass for the folder. What it records instead, where
//! the kernel offers one, is the mount it was seen on (the boot and a mount id
//! Linux 6.8+ never reuses within a boot). The user confirms that mount once
//! (by linking the folder, or re-adopting it), and the folder is used while
//! that mount lasts; after every remount or reboot it waits until the user
//! confirms it again. Where no such mount id exists (Linux before 6.8, macOS,
//! other systems) an unknown volume cannot be confirmed at all.
//!
//! An observation that fails is an error for the caller to retry, never a
//! weaker identity: a value recorded once is compared for the life of the link,
//! so a transient failure must not be able to change its kind.

use std::fmt;
use std::io;
use std::path::Path;

/// See the module doc. Deliberately not `PartialEq`: whether a folder is still
/// on its volume is [`VolumeMatch::of`] on the recorded text, which never
/// matches an unknown volume.
#[derive(Clone, Debug)]
pub enum StableVolumeId {
    /// A macOS volume UUID, or a Linux xfs filesystem UUID.
    Uuid(String),
    /// A Linux `f_fsid` derived from the filesystem's own UUID or GUID.
    Fsid(u64),
    /// The source of a network share.
    MountSource(String),
    /// The Windows volume serial number.
    WindowsSerial(u64),
    /// A filesystem with no identity that survives a remount; `this_mount`
    /// names the mount it was seen on, where the kernel offers a mount id that
    /// is never reused.
    Unknown { this_mount: Option<String> },
}

impl StableVolumeId {
    /// The identity of the filesystem `dir` is on.
    pub fn observe(dir: &Path) -> io::Result<Self> {
        observe(dir)
    }
}

/// The recorded form of [`StableVolumeId::Unknown`] (followed by `:<mount>`
/// when the mount it was seen on is known).
const UNKNOWN: &str = "unknown";

impl fmt::Display for StableVolumeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uuid(uuid) => write!(f, "uuid:{uuid}"),
            Self::Fsid(fsid) => write!(f, "fsid:{fsid:x}"),
            Self::MountSource(source) => write!(f, "mount:{source}"),
            Self::WindowsSerial(serial) => write!(f, "windows:{serial}"),
            Self::Unknown { this_mount: Some(mount) } => write!(f, "{UNKNOWN}:{mount}"),
            Self::Unknown { this_mount: None } => f.write_str(UNKNOWN),
        }
    }
}

/// Whether a folder recorded on one volume is on it now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeMatch {
    /// The same volume; or nothing recorded yet, on a volume that can be.
    Same,
    /// Another volume, both identified: the folder's disk is away or replaced.
    Other,
    /// Only the user can tell: the recorded or the current volume has no
    /// stable identity and is not the mount the user confirmed. That includes
    /// a change of kind on the same disk (a newer kernel that reads the UUID
    /// of a filesystem an older one could not). Nothing is accepted until the
    /// user re-adopts the folder.
    Unconfirmed,
}

impl VolumeMatch {
    /// How `observed`, the recorded form of the volume a folder's root is on
    /// now, relates to `recorded`, the one recorded for the folder (`None`:
    /// not yet). Both are [`StableVolumeId`]s as text.
    pub fn of(recorded: Option<&str>, observed: &str) -> Self {
        if observed == UNKNOWN {
            // Nothing can ever be compared against it, so it is not recorded
            // either: the folder waits for a volume that can be confirmed.
            return Self::Unconfirmed;
        }
        match recorded {
            None => Self::Same,
            Some(recorded) if recorded == observed && recorded != UNKNOWN => Self::Same,
            Some(recorded) if is_unknown(recorded) || is_unknown(observed) => Self::Unconfirmed,
            Some(_) => Self::Other,
        }
    }
}

fn is_unknown(recorded: &str) -> bool {
    recorded.split_once(':').map_or(recorded, |(kind, _)| kind) == UNKNOWN
}

/// The kinds of Linux filesystem the identity distinguishes, from `f_type`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxFsKind {
    /// `f_fsid` is derived from the filesystem's own UUID/GUID.
    UuidDerivedFsid,
    /// xfs: `f_fsid` follows the device number, but the kernel reports the
    /// filesystem's UUID (`FS_IOC_GETFSUUID`, Linux 6.5+).
    Xfs,
    /// A network share, named by its mount source.
    NetworkShare,
    /// Nothing stable.
    Other,
}

/// What a Linux identity is derived from beyond `statfs`, read only for the
/// kinds that need it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) trait LinuxVolumeFacts {
    /// The mount source (`server:/export`), for a network share.
    fn mount_source(&self) -> io::Result<String>;
    /// The filesystem UUID; `Ok(None)` where this kernel cannot report it.
    fn filesystem_uuid(&self) -> io::Result<Option<[u8; 16]>>;
    /// A name for the mount itself that no other mount ever gets (`None` on a
    /// kernel without such a mount id).
    fn this_mount(&self) -> io::Result<Option<String>>;
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl LinuxFsKind {
    pub(crate) fn from_f_type(f_type: u64) -> Self {
        const EXT_SUPER_MAGIC: u64 = 0xEF53;
        const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;
        const ZFS_SUPER_MAGIC: u64 = 0x2FC1_2FC1;
        const XFS_SUPER_MAGIC: u64 = 0x5846_5342;
        const NFS_SUPER_MAGIC: u64 = 0x6969;
        const SMB_SUPER_MAGIC: u64 = 0x517B;
        const CIFS_SUPER_MAGIC: u64 = 0xFF53_4D42;
        const SMB2_SUPER_MAGIC: u64 = 0xFE53_4D42;
        match f_type & 0xFFFF_FFFF {
            EXT_SUPER_MAGIC | BTRFS_SUPER_MAGIC | ZFS_SUPER_MAGIC => Self::UuidDerivedFsid,
            XFS_SUPER_MAGIC => Self::Xfs,
            NFS_SUPER_MAGIC | SMB_SUPER_MAGIC | CIFS_SUPER_MAGIC | SMB2_SUPER_MAGIC => {
                Self::NetworkShare
            }
            _ => Self::Other,
        }
    }

    /// The identity for a filesystem of this kind, given its `f_fsid` and the
    /// facts only some kinds consult.
    pub(crate) fn identity(
        self,
        fsid: u64,
        facts: &dyn LinuxVolumeFacts,
    ) -> io::Result<StableVolumeId> {
        match self {
            Self::UuidDerivedFsid if fsid != 0 => Ok(StableVolumeId::Fsid(fsid)),
            Self::UuidDerivedFsid => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the filesystem reported no fsid although its kind always has one",
            )),
            Self::Xfs => match facts.filesystem_uuid()? {
                Some(uuid) if uuid != [0u8; 16] => Ok(StableVolumeId::Uuid(format_uuid(&uuid))),
                Some(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the filesystem reported an empty UUID",
                )),
                None => Ok(StableVolumeId::Unknown { this_mount: facts.this_mount()? }),
            },
            Self::NetworkShare => {
                let source = facts.mount_source()?;
                if source.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the network share has no mount source",
                    ));
                }
                Ok(StableVolumeId::MountSource(source))
            }
            Self::Other => Ok(StableVolumeId::Unknown { this_mount: facts.this_mount()? }),
        }
    }
}

/// The canonical text of a UUID, lower-case and hyphenated.
#[cfg_attr(not(any(target_os = "linux", target_vendor = "apple")), allow(dead_code))]
fn format_uuid(bytes: &[u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

#[cfg(windows)]
fn observe(dir: &Path) -> io::Result<StableVolumeId> {
    use crate::fs_identity::VolumeIdentity;
    match crate::fs_capabilities::observe_volume_identity(dir)? {
        VolumeIdentity::Windows { volume_serial_number } => {
            Ok(StableVolumeId::WindowsSerial(volume_serial_number))
        }
        VolumeIdentity::Unix { .. } => Ok(StableVolumeId::Unknown { this_mount: None }),
    }
}

#[cfg(target_os = "linux")]
fn observe(dir: &Path) -> io::Result<StableVolumeId> {
    linux::cached_identity(dir)
}

#[cfg(target_vendor = "apple")]
fn observe(dir: &Path) -> io::Result<StableVolumeId> {
    let mount = macos::mount_of(dir)?;
    if !mount.local {
        if mount.from.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the share has no mount source",
            ));
        }
        return Ok(StableVolumeId::MountSource(mount.from));
    }
    Ok(match macos::volume_uuid(&mount.on)? {
        Some(uuid) => StableVolumeId::Uuid(uuid),
        None => StableVolumeId::Unknown { this_mount: None },
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_vendor = "apple"))))]
fn observe(dir: &Path) -> io::Result<StableVolumeId> {
    std::fs::metadata(dir)?;
    Ok(StableVolumeId::Unknown { this_mount: None })
}

/// The Linux identity, cached per mount where that is safe. A write path asks
/// for it on every operation; deriving it costs a `statfs` and a `statvfs`, and
/// for a network share also a read of `/proc/self/mountinfo`. The cache key is
/// the `statx` unique mount id (Linux 6.8+, never reused within a boot)
/// together with the device number, so a filesystem mounted at the same path
/// later is a different key. An older kernel only offers a mount id that is
/// reused after an unmount, which with a reused device number could hand a
/// replacement disk the identity of the one it replaced; there the identity is
/// derived on every call instead.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::collections::HashMap;
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::Mutex;

    use super::{LinuxFsKind, LinuxVolumeFacts, StableVolumeId};

    const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
    #[cfg(test)]
    pub(crate) const STATX_MNT_ID: u32 = libc::STATX_MNT_ID;
    #[cfg(test)]
    pub(crate) const STATX_MNT_ID_UNIQUE_BIT: u32 = STATX_MNT_ID_UNIQUE;

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    pub(crate) struct MountKey {
        dev_major: u32,
        dev_minor: u32,
        mount_id: u64,
    }

    static CACHE: Mutex<Option<HashMap<MountKey, StableVolumeId>>> = Mutex::new(None);

    /// How many times the identity was derived rather than served from the
    /// cache, for tests that prove the cache is used.
    #[cfg(any(test, feature = "test-support"))]
    pub static DERIVATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    /// `None` on a kernel without a unique mount id (before 6.8): see the
    /// module doc above.
    pub(crate) fn mount_key(dir: &Path) -> io::Result<Option<MountKey>> {
        let path = c_path(dir)?;
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is NUL-terminated and `stx` is a valid out-pointer.
        let rc =
            unsafe { libc::statx(libc::AT_FDCWD, path.as_ptr(), 0, STATX_MNT_ID_UNIQUE, &mut stx) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(cache_key(stx.stx_mask, stx.stx_dev_major, stx.stx_dev_minor, stx.stx_mnt_id))
    }

    /// Only a unique mount id makes a cache key; a reusable one does not.
    pub(crate) fn cache_key(
        stx_mask: u32,
        dev_major: u32,
        dev_minor: u32,
        mount_id: u64,
    ) -> Option<MountKey> {
        (stx_mask & STATX_MNT_ID_UNIQUE != 0).then_some(MountKey { dev_major, dev_minor, mount_id })
    }

    /// Derives the identity without the cache, for measuring the uncached path.
    #[cfg(test)]
    pub(crate) fn derive_uncached(dir: &Path) -> io::Result<StableVolumeId> {
        derive(dir, mount_key(dir)?)
    }

    pub(crate) fn cached_identity(dir: &Path) -> io::Result<StableVolumeId> {
        let Some(key) = mount_key(dir)? else {
            return derive(dir, None);
        };
        let cached = CACHE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .and_then(|cache| cache.get(&key).cloned());
        if let Some(id) = cached {
            return Ok(id);
        }
        let id = derive(dir, Some(key))?;
        // Re-check the key: the derivation must describe the mount the key
        // names. One that replaced it meanwhile is an observation that failed
        // (retried by the caller), never the old mount's identity.
        if mount_key(dir)? != Some(key) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the mount changed while its volume identity was read",
            ));
        }
        CACHE
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get_or_insert_with(HashMap::new)
            .insert(key, id.clone());
        Ok(id)
    }

    /// `key`: the unique mount `dir` is on, where the kernel names one.
    fn derive(dir: &Path, key: Option<MountKey>) -> io::Result<StableVolumeId> {
        #[cfg(any(test, feature = "test-support"))]
        DERIVATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = c_path(dir)?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `path` is NUL-terminated and `fs` is a valid out-pointer.
        if unsafe { libc::statfs(path.as_ptr(), &mut fs) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut vfs: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::statvfs(path.as_ptr(), &mut vfs) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[allow(clippy::unnecessary_cast)]
        let (f_type, fsid) = (fs.f_type as u64, vfs.f_fsid as u64);
        LinuxFsKind::from_f_type(f_type).identity(fsid, &Facts { dir, key })
    }

    struct Facts<'a> {
        dir: &'a Path,
        key: Option<MountKey>,
    }

    impl LinuxVolumeFacts for Facts<'_> {
        fn mount_source(&self) -> io::Result<String> {
            let canonical = self.dir.canonicalize()?;
            let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")?;
            source_of_mount_containing(&mountinfo, &canonical).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no mount contains the directory")
            })
        }

        fn filesystem_uuid(&self) -> io::Result<Option<[u8; 16]>> {
            filesystem_uuid(self.dir)
        }

        fn this_mount(&self) -> io::Result<Option<String>> {
            let Some(key) = self.key else { return Ok(None) };
            Ok(Some(format!("{}:{}", boot_id()?, key.mount_id)))
        }
    }

    /// `struct fsuuid2` of `linux/fs.h`.
    #[repr(C)]
    struct FsUuid2 {
        len: u8,
        uuid: [u8; 16],
    }

    /// The filesystem's UUID through `FS_IOC_GETFSUUID` (Linux 6.5+, no
    /// privilege needed). `Ok(None)` when the kernel does not know the ioctl
    /// or the filesystem reports no UUID: the same kernel answers the same
    /// way every time, so this is a property of the system, not a failure.
    pub(crate) fn filesystem_uuid(dir: &Path) -> io::Result<Option<[u8; 16]>> {
        const FS_IOC_GETFSUUID: libc::Ioctl = libc::_IOR::<FsUuid2>(0x15, 0);
        let path = c_path(dir)?;
        // SAFETY: `path` is NUL-terminated.
        let fd = unsafe {
            libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just opened and is owned here only.
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let mut reply = FsUuid2 { len: 0, uuid: [0; 16] };
        // SAFETY: `reply` is a valid `struct fsuuid2` for the kernel to fill.
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFSUUID, &mut reply) };
        if rc != 0 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOTTY) => Ok(None),
                _ => Err(error),
            };
        }
        if usize::from(reply.len) != reply.uuid.len() {
            return Ok(None);
        }
        Ok(Some(reply.uuid))
    }

    /// This boot's id: a unique mount id is only unique within one boot.
    fn boot_id() -> io::Result<String> {
        static BOOT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        if let Some(id) = BOOT_ID.get() {
            return Ok(id.clone());
        }
        let id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().to_owned();
        if id.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "empty boot id"));
        }
        Ok(BOOT_ID.get_or_init(|| id).clone())
    }

    /// The source of the mount whose mount point is the longest prefix of
    /// `canonical` (the mount that actually serves it).
    pub(crate) fn source_of_mount_containing(mountinfo: &str, canonical: &Path) -> Option<String> {
        let mut best: Option<(usize, String)> = None;
        for line in mountinfo.lines() {
            let Some((pre, post)) = line.split_once(" - ") else { continue };
            let Some(mount_point) = pre.split(' ').nth(4).map(unescape) else { continue };
            let Some(source) = post.split(' ').nth(1).map(unescape) else { continue };
            if !canonical.starts_with(Path::new(&mount_point)) {
                continue;
            }
            // `>=`: a later line for the same mount point is mounted over the
            // earlier one.
            if best.as_ref().is_none_or(|(len, _)| mount_point.len() >= *len) {
                best = Some((mount_point.len(), source));
            }
        }
        best.map(|(_, source)| source)
    }

    /// mountinfo escapes space, tab, newline and backslash as `\ooo`.
    fn unescape(field: &str) -> String {
        let bytes = field.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\'
                && i + 3 < bytes.len()
                && bytes[i + 1..i + 4].iter().all(|b| (b'0'..=b'7').contains(b))
            {
                out.push(
                    (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0'),
                );
                i += 4;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

#[cfg(target_vendor = "apple")]
mod macos {
    use std::ffi::{CStr, CString};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    pub(super) struct Mount {
        pub(super) on: PathBuf,
        pub(super) from: String,
        pub(super) local: bool,
    }

    /// The mount serving `dir`.
    pub(super) fn mount_of(dir: &Path) -> io::Result<Mount> {
        let c_path = CString::new(dir.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c_path` is NUL-terminated and `buf` is a valid out-pointer.
        if unsafe { libc::statfs(c_path.as_ptr(), &mut buf) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel NUL-terminates both fixed-size name fields.
        let on = unsafe { CStr::from_ptr(buf.f_mntonname.as_ptr()) };
        let from = unsafe { CStr::from_ptr(buf.f_mntfromname.as_ptr()) };
        Ok(Mount {
            on: PathBuf::from(std::ffi::OsStr::from_bytes(on.to_bytes())),
            from: from.to_string_lossy().into_owned(),
            local: buf.f_flags & libc::MNT_LOCAL as u32 != 0,
        })
    }

    /// The volume UUID (`None` for a volume that has none), read from the
    /// mount point: volume attributes are only returned for a volume's root.
    pub(super) fn volume_uuid(mount_on: &Path) -> io::Result<Option<String>> {
        #[repr(C)]
        struct Reply {
            length: u32,
            returned: libc::attribute_set_t,
            uuid: [u8; 16],
        }
        let c_path = CString::new(mount_on.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut request: libc::attrlist = unsafe { std::mem::zeroed() };
        request.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
        request.commonattr = libc::ATTR_CMN_RETURNED_ATTRS;
        request.volattr = libc::ATTR_VOL_INFO | libc::ATTR_VOL_UUID;
        let mut reply: Reply = unsafe { std::mem::zeroed() };
        // SAFETY: `request` and `reply` are valid for the sizes passed, and
        // `c_path` is NUL-terminated.
        let rc = unsafe {
            libc::getattrlist(
                c_path.as_ptr(),
                (&mut request as *mut libc::attrlist).cast(),
                (&mut reply as *mut Reply).cast(),
                std::mem::size_of::<Reply>(),
                0,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        if reply.returned.volattr & libc::ATTR_VOL_UUID == 0 || reply.uuid == [0u8; 16] {
            return Ok(None);
        }
        Ok(Some(super::format_uuid(&reply.uuid)))
    }
}

#[cfg(test)]
mod tests;
