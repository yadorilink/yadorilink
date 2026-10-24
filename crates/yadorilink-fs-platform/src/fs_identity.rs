//! Strong filesystem object identity.
//!
//! A single weak field — an inode number, a path, a modification time — can
//! be reused or forged by ordinary filesystem activity (delete-and-recreate,
//! a volume unmounted and a different one mounted at the same path, a
//! same-second overwrite). None of those fields alone can tell "the same
//! object I saw before" apart from "a different object that happens to share
//! one field with it". [`FileIdentity::compare`] is the one place that
//! judgment is made, and it returns a three-valued
//! [`IdentityComparison`] rather than a `bool` specifically so that
//! "cannot exclude reuse" cannot be silently collapsed into "same object" by
//! a careless `if identity_a == identity_b`.
//!
//! Everything here is *observation only*: reading identity from a path or an
//! open handle, and comparing two observations. Nothing in this module
//! decides what to do with an `Ambiguous` result — that policy belongs to
//! the caller that owns the recovery or replacement decision.

use std::fs::{File, Metadata};
use std::io;
use std::path::Path;
use std::time::SystemTime;

use sha2::{Digest, Sha256};

/// The platform-specific fields threaded through `from_metadata` in
/// addition to `std::fs::Metadata`. On Unix this is nothing — everything
/// `from_metadata` needs comes from `Metadata` itself. On Windows it
/// carries the volume serial number, file index and link count read via a
/// direct `GetFileInformationByHandle` call (see [`win_identity`]) rather
/// than through `std::os::windows::fs::MetadataExt`, whose equivalents sit
/// behind the unstable `windows_by_handle` feature.
///
/// Fetching this is fallible on Windows (see [`platform_fields_from_path`]/
/// [`platform_fields_from_handle`]) precisely because it is not optional:
/// [`VolumeIdentity`] and [`PlatformObjectId`] are the fields `FileIdentity::
/// compare` uses to decide "same object", so a `GetFileInformationByHandle`
/// call that could not determine them must fail the whole observation
/// rather than hand back a substituted value — two observations that both
/// failed to determine their file index would otherwise compare equal on
/// that field, exactly the kind of coincidence this identity type exists to
/// rule out.
#[cfg(unix)]
type PlatformFields = ();
#[cfg(windows)]
type PlatformFields = win_identity::IdentityFields;

#[cfg(unix)]
fn platform_fields_from_path(_path: &Path, _metadata: &Metadata) -> io::Result<PlatformFields> {
    Ok(())
}
#[cfg(windows)]
fn platform_fields_from_path(path: &Path, _metadata: &Metadata) -> io::Result<PlatformFields> {
    #[cfg(feature = "test-support")]
    if IDENTITY_QUERY_UNREADABLE.with(|f| f.get()) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    win_identity::query_path(path)
}

#[cfg(unix)]
fn platform_fields_from_handle(_file: &File, _metadata: &Metadata) -> io::Result<PlatformFields> {
    Ok(())
}
#[cfg(windows)]
fn platform_fields_from_handle(file: &File, _metadata: &Metadata) -> io::Result<PlatformFields> {
    win_identity::query_handle(file)
}

/// A point in time, recorded with the platform's native precision, without
/// depending on the local clock at comparison time. Only ever built by
/// converting a [`SystemTime`] taken from filesystem metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Seconds since the Unix epoch. Negative for times before 1970, which
    /// birth times on some platforms and filesystems can legitimately be.
    pub seconds_since_unix_epoch: i64,
    pub subsec_nanos: u32,
}

impl Timestamp {
    fn from_system_time(time: SystemTime) -> Timestamp {
        match time.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(since_epoch) => Timestamp {
                seconds_since_unix_epoch: since_epoch.as_secs() as i64,
                subsec_nanos: since_epoch.subsec_nanos(),
            },
            Err(before_epoch) => {
                let negative = before_epoch.duration();
                Timestamp {
                    seconds_since_unix_epoch: -(negative.as_secs() as i64) - 1,
                    subsec_nanos: (1_000_000_000 - negative.subsec_nanos()) % 1_000_000_000,
                }
            }
        }
    }
}

/// The volume (mount / drive) a [`FileIdentity`] or [`DirectoryIdentity`]
/// was observed on. Two objects can only be compared for identity when they
/// report the same volume; identity numbers from different volumes can
/// collide by coincidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VolumeIdentity {
    /// `st_dev` from `stat`/`fstat`.
    Unix { device_id: u64 },
    /// The NTFS/ReFS volume serial number. 64 bits wide because
    /// `FILE_ID_INFO::VolumeSerialNumber` — read alongside a proven
    /// [`WindowsObjectId::Proven`] — is a 64-bit value. When only the
    /// legacy `BY_HANDLE_FILE_INFORMATION::dwVolumeSerialNumber` (32-bit,
    /// read alongside a [`WindowsObjectId::Fallback`]) is available, its
    /// value is stored zero-extended here rather than needing a second,
    /// narrower field. Both calls report the same underlying volume
    /// serial, so this widening does not introduce a spurious mismatch
    /// between a proven and a fallback observation of the same volume.
    Windows { volume_serial_number: u64 },
}

/// The platform's stable object identifier within its [`VolumeIdentity`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlatformObjectId {
    /// `st_ino` from `stat`/`fstat`. Reusable after deletion, which is
    /// exactly why [`FileIdentity::compare`] never trusts this field alone.
    Unix {
        inode: u64,
    },
    Windows(WindowsObjectId),
}

/// A Windows object identifier, in one of two forms that
/// [`FileIdentity::compare`] must never conflate: only [`Self::Proven`] is
/// trusted as strongly as a Unix inode. See the module-level FFI doc in
/// [`win_identity`] for how each is obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WindowsObjectId {
    /// The full 128-bit NTFS/ReFS file identifier (`FILE_ID_INFO::FileId`,
    /// from a successful `GetFileInformationByHandleEx(FileIdInfo)` query
    /// whose `FileId` was neither of [MS-FSCC]'s documented sentinels — see
    /// [`win_identity::query_raw_handle`]). Microsoft documents this as the
    /// identifier that IS unique within a volume, including on ReFS —
    /// unlike [`Self::Fallback`]'s 64-bit file index. This is the only
    /// Windows object id [`FileIdentity::compare`] treats as conclusive on
    /// its own.
    ///
    /// [`FileIdentity::compare`] also trusts a matching value here as a
    /// reuse discriminator in its own right, needing no corroborating
    /// `generation_or_usn` or `birth_or_creation_time` — the same standing
    /// a Unix inode gets only once paired with `generation_or_usn`. On
    /// NTFS this is justified by construction, not merely by [MS-FSCC]'s
    /// "SHOULD be unique to the volume" wording: NTFS builds the low 64
    /// bits of this 128-bit value from exactly the same 48-bit MFT record
    /// index plus 16-bit sequence number as [`Self::Fallback`]'s 64-bit
    /// file reference number, and that sequence number is incremented
    /// every time the record is reused for a new file — so a delete-and-
    /// recreate changes this value on the very first reuse, regardless of
    /// clock granularity. (The 16-bit counter can in principle wrap after
    /// 65,536 reuses of the identical MFT record, the same bounded-width
    /// caveat already accepted for `generation_or_usn` elsewhere in this
    /// module.) ReFS's true 128-bit identifier is constructed differently
    /// — a parent-directory index and an intra-directory index, per public
    /// documentation — and no equivalent incrementing component is
    /// documented for it, so this crate cannot independently confirm the
    /// same reuse-safety there.
    ///
    /// Because of that gap, a *real, well-formed* 128-bit id is still not
    /// enough on its own to reach this variant: [`win_identity::query_raw_
    /// handle`] additionally checks which filesystem produced it (`Get
    /// VolumeInformationByHandleW`'s reported name) and only classifies the
    /// id `Proven` on a filesystem it has independently confirmed defeats
    /// reuse this way — NTFS today. A ReFS observation's id, though every
    /// bit as real and unique-within-the-volume as [MS-FSCC] documents,
    /// is recorded as [`Self::Fallback`] instead: a value that reaches
    /// [`FileIdentity::compare`] as `Proven` is one this crate is willing
    /// to call reuse-safe by construction, not by convention, and that
    /// currently means NTFS only.
    Proven { file_id: [u8; 16] },
    /// The legacy NTFS/ReFS file ID (`BY_HANDLE_FILE_INFORMATION::
    /// nFileIndex{Low,High}`), a 64-bit value. Used only when `FileIdInfo`
    /// could not be queried — needs Windows 8 / Server 2012 or later, and
    /// can fail on some filesystems even there (see [`win_identity::
    /// query_raw_handle`]).
    ///
    /// Microsoft documents this value as **not guaranteed unique on ReFS**,
    /// which identifies objects with a 128-bit identifier internally. Two
    /// distinct, simultaneously live objects on the same ReFS volume can
    /// therefore report the same value here. [`FileIdentity::compare`] never
    /// treats an equal value here as sufficient proof of "same object" on
    /// its own — see its doc.
    Fallback { file_index: u64 },
}

/// What kind of filesystem object was observed. Distinct from a POSIX mode
/// bit test so that platforms without a matching concept (FIFOs and device
/// nodes on Windows, for instance) still have a definite answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjectKind {
    RegularFile,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharDevice,
    /// A reparse point (junction, mount point, or other non-symlink
    /// reparse tag) or any object kind this observation could not resolve
    /// to one of the concrete variants above.
    ReparsePoint,
    Other,
}

/// Strong identity for a file-like object, observed from either an open
/// handle or a path (never following a terminal symlink — see
/// [`FileIdentity::observe_path`]).
///
/// No single field here proves two observations name the same object.
/// [`FileIdentity::compare`] is the sanctioned way to ask that question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileIdentity {
    pub volume_identity: VolumeIdentity,
    pub object_id: PlatformObjectId,
    pub object_kind: ObjectKind,
    /// A true anti-reuse counter when the platform exposes one. On Linux,
    /// populated from `FS_IOC_GETVERSION` (the inode generation number) —
    /// measured to work unprivileged and to discriminate every observed
    /// inode reuse on ext4 and XFS, and to return `ENOTTY` (absent, not
    /// merely gated) on overlayfs regardless of privilege. `None` when that
    /// ioctl is unavailable on this volume, or on macOS/Windows, which have
    /// no portable equivalent this phase adds.
    pub generation_or_usn: Option<u128>,
    /// The second-ranked reuse discriminator (see [`FileIdentity::compare`]):
    /// widely available even where `generation_or_usn` is not (`st_birthtime`
    /// on macOS, `statx`'s `STATX_BTIME` on modern Linux filesystems), and
    /// just as conclusive when it can be compared, since a recycled inode
    /// gets a new birth time.
    pub birth_or_creation_time: Option<Timestamp>,
    pub observed_size: u64,
    /// A stable digest over the tracked metadata subset (kind, size, mode
    /// bits, timestamps). Changes whenever a byte of that subset changes;
    /// says nothing about content. For a directory the subset is only its
    /// kind, mode (attributes on Windows) and object address: size and
    /// timestamps there describe its entries, not the directory.
    pub metadata_fingerprint: [u8; 32],
    /// `st_nlink` on Unix; `BY_HANDLE_FILE_INFORMATION::nNumberOfLinks` on
    /// Windows. Always `Some` in practice: on Windows, a `GetFileInformationByHandle`
    /// call that could not determine the link count fails the whole
    /// observation (see `observe_path`/`observe_handle`) rather than
    /// substituting a value here. Kept `Option` because "could not be
    /// determined" is still a real, distinct outcome from "known to be
    /// one" — [`classify_replacement_eligibility`] blocks on `None` for
    /// exactly that reason, not "probably no hardlinks". Not part of
    /// identity comparison.
    pub link_count: Option<u64>,
    /// A SHA-256 digest of the link's target text, when this observation is
    /// a symlink; `None` for every other kind. A digest rather than the raw
    /// target bytes so this field stays `[u8; 32]`, same as `metadata_
    /// fingerprint` — the whole reason [`FileIdentity`] can still derive
    /// `Copy`, which pervasive by-value use elsewhere in this crate depends
    /// on; a `Vec<u8>` field here would silently remove that and ripple into
    /// every caller that currently copies a `FileIdentity` implicitly.
    ///
    /// A symlink is the one object kind [`generation_from_path`]/
    /// [`generation_from_handle`] never open (see their doc: the ioctl is
    /// only attempted for a regular file or directory), and whose birth
    /// time a coarse volume clock cannot use as proof either — so on a
    /// platform with neither a fine clock nor `FS_IOC_GETVERSION` (measured
    /// on Linux/ext4 and Linux/XFS: roughly 4 ms granularity, well inside a
    /// delete-and-recreate's reach), [`FileIdentity::compare`] would have no
    /// reuse discriminator left for a symlink at all and would report
    /// `Ambiguous` for the literal same, untouched object. This field
    /// supplies one: a symlink's target cannot change without destroying
    /// and recreating the object (there is no "edit a symlink in place"),
    /// so two observations of the same volume+inode+kind that also agree on
    /// this digest are the same object by the same standard `compare`
    /// already applies to a matching `generation_or_usn` — see `compare`'s
    /// doc for the one respect in which this is *not* quite as strong as a
    /// true anti-reuse counter, and why that gap is inconsequential for
    /// every caller in this crate.
    ///
    /// Populated by a real `readlink`-family call in `observe_path`/
    /// `observe_handle` (see [`symlink_target_digest_from_path`]/
    /// [`symlink_target_digest_from_handle`]). Also part of
    /// `materialized_generation`'s versioned on-disk encoding as of its
    /// encoding version 3 (`materialized_generation::encode_file_identity`/
    /// `decode_file_identity`) — see that constant's own doc for why an
    /// earlier version omitted it and what that omission actually cost:
    /// this is the only reuse discriminator a symlink identity can ever
    /// carry, so a decoded row missing it left `compare` unable to reach
    /// `SameObject` for a symlink at all on a coarse-clock volume, not
    /// merely weaker than a live observation.
    pub symlink_target_digest: Option<[u8; 32]>,
}

/// Strong identity for a directory. Deliberately a smaller tuple than
/// [`FileIdentity`]: directories are not content-hashed and have no
/// metadata-fidelity contract of their own here.
///
/// Deliberately does **not** derive `PartialEq`/`Eq`. Plain field equality
/// is exactly the ReFS hazard [`DirectoryIdentity::compare`] exists to
/// close: two distinct, simultaneously live directories on one ReFS volume
/// can report the same [`WindowsObjectId::Fallback`] id, and the legacy
/// 32-bit volume serial zero-extends into the same 64-bit
/// [`VolumeIdentity::Windows`] value for two different volumes that happen
/// to share that 32-bit number -- see `compare`'s doc for both. A derived
/// `==` would let a caller silently accept either coincidence as proof.
/// Use [`DirectoryIdentity::compare`], which returns the same three-valued
/// [`IdentityComparison`] as [`FileIdentity::compare`] and applies the same
/// fail-closed rules, and handle its `Ambiguous` case explicitly.
#[derive(Clone, Copy, Debug)]
pub struct DirectoryIdentity {
    pub volume_identity: VolumeIdentity,
    pub object_id: PlatformObjectId,
    pub generation_or_usn: Option<u128>,
    /// The [`FileIdentity`] field of the same name, populated the same way
    /// (`st_birthtime`/`statx`'s `STATX_BTIME` on Unix, `creation_time` on
    /// Windows) -- directories have birth times on APFS and NTFS exactly as
    /// files do; this type previously omitted the field entirely rather
    /// than the platform lacking it. Its absence was the actual defect
    /// behind [`DirectoryIdentity::compare`]'s old unconditional-`SameObject`
    /// shape: with no reuse discriminator to fall back to at all when
    /// `generation_or_usn` was unavailable (true for directories on every
    /// platform this crate runs on except Linux ext4/XFS, including
    /// overlayfs — measured), that method could not express "cannot rule
    /// out reuse" and instead trusted a matching `object_id`+`volume_identity`
    /// unconditionally. Requiring `generation_or_usn` there instead (a
    /// previous attempt) was measured to fail 12 unrelated tests, because it
    /// made every parent-directory check permanently `Ambiguous` on macOS
    /// and Windows — disabling the check, not fixing it. This field gives
    /// `compare` the same three-tier discrimination `FileIdentity` already
    /// has, so the honest `Ambiguous` case is reached only where the
    /// information genuinely does not exist (a coarse clock with no
    /// counter), not everywhere a counter happens to be absent.
    pub birth_or_creation_time: Option<Timestamp>,
}

/// Why [`FileIdentity::compare`] could not exclude that two observations
/// name different objects that happen to share their weak fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmbiguityReason {
    /// Neither observation carries a `generation_or_usn` nor a
    /// `birth_or_creation_time` — no reuse discriminator (see
    /// [`FileIdentity::compare`]'s doc for the ranking) is available on
    /// both sides. Reuse of the underlying object id cannot be excluded.
    /// Never fires when the object id is a matching [`WindowsObjectId::
    /// Proven`] value — that case needs no discriminator here at all.
    NoStableGenerationOrUsn,
    /// The two observations were taken on different platforms' identity
    /// representations (for example one `Unix`, one `Windows`), which
    /// cannot happen for identities gathered on the same running process
    /// and is itself a sign something upstream is wrong.
    CrossPlatformRepresentation,
    /// `birth_or_creation_time` matched on both sides, but this volume's
    /// clock was measured too coarse to trust that as proof (see
    /// [`TimestampGranularity`]): a delete-and-recreate landing inside one
    /// clock tick would be assigned the exact same birth time as the
    /// object it replaced, so equality alone does not exclude reuse here.
    /// Never fires when the object id is a matching [`WindowsObjectId::
    /// Proven`] value — that case does not need the clock's help.
    CoarseTimestampGranularity,
    /// Both observations report the same [`WindowsObjectId::Fallback`]
    /// value, but that 64-bit file index is not guaranteed unique on ReFS
    /// (see its doc). A reuse discriminator matching too (`generation_or_usn`
    /// or `birth_or_creation_time`) does not rescue this: both observations
    /// could equally well be two distinct, simultaneously live objects that
    /// happen to collide on the weak object id, so nothing here excludes
    /// that possibility. This mirrors [`Self::CoarseTimestampGranularity`]'s
    /// standard — an unreliable field is never trusted as proof just
    /// because nothing else contradicts it. Never fires for a
    /// [`WindowsObjectId::Proven`] id, which this reason does not apply to.
    WindowsObjectIdNotProvenUniqueOnRefs,
    /// One observation carries a proven [`WindowsObjectId::Proven`] id and
    /// the other only a [`WindowsObjectId::Fallback`] one, for what is
    /// otherwise the same volume. `FileIdInfo` support is a static property
    /// of the OS version and the volume's filesystem, so this is not
    /// expected from two observations taken by one running process — like
    /// [`Self::CrossPlatformRepresentation`], seeing it at all is itself a
    /// sign something upstream is wrong, not a case worth trying to
    /// reconcile.
    WindowsIdentityMethodMismatch,
}

/// Whether a volume's clock is fine enough that two genuinely distinct
/// creation events, close together in real time, reliably get different
/// [`Timestamp`] values from [`FileIdentity::birth_or_creation_time`].
///
/// This cannot be known from a single observation — it is a property of
/// the volume, established by repeatedly creating objects back-to-back and
/// checking whether their birth times ever collide (see
/// `fs_capabilities`'s granularity probe, which is what actually measures
/// it). [`FileIdentity::compare`] takes it as an explicit argument rather
/// than guessing, because equal birth times are conclusive proof of
/// "same object" on a fine-grained clock and no proof at all on a coarse
/// one: measured at roughly 4 ms on x86_64 Linux/overlayfs, which is
/// comfortably wide enough for an unrelated delete-and-recreate to land in
/// the same tick as the object it replaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampGranularity {
    /// Fine enough that an equal `birth_or_creation_time` on both sides is
    /// trusted as proof of "same object", the same way an equal
    /// `generation_or_usn` is.
    Fine,
    /// Coarse (or unmeasured — see the probe's own doc on how an
    /// inconclusive measurement is handled). An equal
    /// `birth_or_creation_time` is not trusted as proof here; a
    /// *differing* one is still conclusive proof of a different object,
    /// since birth time cannot move backward on a live object regardless
    /// of clock resolution.
    Coarse,
}

/// The result of comparing two [`FileIdentity`] observations. Three-valued
/// on purpose: there is no `bool` conversion, so a caller cannot collapse
/// "cannot tell" into "same" by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityComparison {
    /// A reuse discriminator — `generation_or_usn` if present, otherwise
    /// `birth_or_creation_time` — was available and equal on both sides.
    /// See [`FileIdentity::compare`] for why either one alone is
    /// conclusive.
    SameObject,
    DefinitelyDifferent,
    Ambiguous(AmbiguityReason),
}

impl FileIdentity {
    /// Observes identity from a path without following a terminal symlink
    /// (uses `lstat`/`symlink_metadata`, never `stat`). This is the right
    /// choice whenever the caller cares about the object actually present
    /// at that path, including when that object is itself a symlink.
    /// Whether two equal observations of `path`, the later one taken now,
    /// prove nothing rewrote its bytes in between -- including an in-place
    /// rewrite that keeps the length and restores the modification time.
    ///
    /// On Unix the fingerprint always carries `ctime`, which every write
    /// moves and no API sets back. On Windows it carries `ChangeTime` only
    /// when that query succeeded; when it fails now, an earlier observation
    /// that also lacked it can be equal to this one over different bytes.
    /// (An earlier observation that had it differs from one that does not,
    /// so asking about now is enough.) `false` means the caller must compare
    /// the bytes themselves.
    pub fn in_place_rewrite_visible(path: &Path) -> bool {
        #[cfg(unix)]
        {
            let _ = path;
            true
        }
        #[cfg(windows)]
        {
            // The same condition under which the race fingerprint is not degraded.
            win_identity::query_path(path)
                .is_ok_and(|fields| fields.change_time.is_some() && fields.usn.is_ok())
        }
    }

    // `platform_fields` is `()` on Unix (nothing to bind) and a real
    // struct on Windows -- `clippy::let_unit_value` only fires under the
    // former, so it is allowed here rather than duplicating this function
    // per platform just to satisfy a lint that is correct on one platform
    // and not the other.
    #[allow(clippy::let_unit_value)]
    pub fn observe_path(path: &Path) -> io::Result<FileIdentity> {
        let metadata = std::fs::symlink_metadata(path)?;
        let generation_or_usn = generation_from_path(path, &metadata);
        let symlink_target_digest = symlink_target_digest_from_path(path, &metadata);
        let platform_fields = platform_fields_from_path(path, &metadata)?;
        let mut identity = Self::from_metadata(&metadata, generation_or_usn, platform_fields);
        identity.symlink_target_digest = symlink_target_digest;
        Ok(identity)
    }

    /// Observes identity from an already-open handle. Preferred over
    /// [`Self::observe_path`] whenever a handle is available: it cannot
    /// race a rename or replacement of the path between the syscall and
    /// the caller reading the result.
    #[allow(clippy::let_unit_value)]
    pub fn observe_handle(file: &File) -> io::Result<FileIdentity> {
        let metadata = file.metadata()?;
        let generation_or_usn = generation_from_handle(file, &metadata);
        let symlink_target_digest = symlink_target_digest_from_handle(file, &metadata);
        let platform_fields = platform_fields_from_handle(file, &metadata)?;
        let mut identity = Self::from_metadata(&metadata, generation_or_usn, platform_fields);
        identity.symlink_target_digest = symlink_target_digest;
        Ok(identity)
    }

    #[cfg(unix)]
    fn from_metadata(
        metadata: &Metadata,
        generation_or_usn: Option<u128>,
        _platform_fields: PlatformFields,
    ) -> FileIdentity {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let object_kind = if metadata.is_dir() {
            ObjectKind::Directory
        } else if metadata.file_type().is_symlink() {
            ObjectKind::Symlink
        } else if metadata.file_type().is_fifo() {
            ObjectKind::Fifo
        } else if metadata.file_type().is_socket() {
            ObjectKind::Socket
        } else if metadata.file_type().is_block_device() {
            ObjectKind::BlockDevice
        } else if metadata.file_type().is_char_device() {
            ObjectKind::CharDevice
        } else if metadata.is_file() {
            ObjectKind::RegularFile
        } else {
            ObjectKind::Other
        };

        let birth_or_creation_time = metadata.created().ok().map(Timestamp::from_system_time);

        FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: metadata.dev() },
            object_id: PlatformObjectId::Unix { inode: metadata.ino() },
            object_kind,
            generation_or_usn,
            birth_or_creation_time,
            observed_size: metadata.len(),
            metadata_fingerprint: fingerprint_unix(metadata, object_kind),
            link_count: Some(metadata.nlink()),
            // Overwritten by `observe_path`/`observe_handle` right after
            // this call returns -- see their doc and `symlink_target_digest_
            // from_path`/`symlink_target_digest_from_handle`. Never
            // populated here directly: this function only has `Metadata`,
            // not the path or handle a `readlink`-family call actually
            // needs.
            symlink_target_digest: None,
        }
    }

    #[cfg(windows)]
    fn from_metadata(
        metadata: &Metadata,
        generation_or_usn: Option<u128>,
        platform_fields: PlatformFields,
    ) -> FileIdentity {
        // `creation_time` below is the one `MetadataExt` accessor still used
        // here: unlike the volume serial, file index and link count -- which
        // are `windows_by_handle` and therefore nightly-only, hence the
        // `GetFileInformationByHandle` query in `win_identity` -- the
        // creation time is stable.
        use std::os::windows::fs::{FileTypeExt, MetadataExt};

        let file_type = metadata.file_type();
        let object_kind = if file_type.is_symlink_dir() || file_type.is_symlink_file() {
            ObjectKind::Symlink
        } else if metadata.is_dir() {
            ObjectKind::Directory
        } else if metadata.is_file() {
            ObjectKind::RegularFile
        } else {
            // `std` does not distinguish junctions/mount points from other
            // reparse tags without extra Win32 calls this phase does not
            // add; anything that is not plainly a file, directory or
            // symlink is treated as an unresolved reparse point.
            ObjectKind::ReparsePoint
        };

        let birth_or_creation_time = Some(Timestamp::from_system_time(
            SystemTime::UNIX_EPOCH
                + std::time::Duration::from_nanos(metadata.creation_time().saturating_mul(100)),
        ));

        // Which case this observation landed in -- proven 128-bit id or
        // 64-bit fallback -- is entirely `win_identity::query_path`/
        // `query_handle`'s call: see `win_identity::ObjectIdFields` for how
        // the two are kept distinct rather than merged into one shape here.
        let (volume_identity, object_id) = match platform_fields.object_id {
            win_identity::ObjectIdFields::Proven { volume_serial_number, file_id } => (
                VolumeIdentity::Windows { volume_serial_number },
                PlatformObjectId::Windows(WindowsObjectId::Proven { file_id }),
            ),
            win_identity::ObjectIdFields::Fallback { volume_serial_number, file_index } => (
                VolumeIdentity::Windows { volume_serial_number },
                PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index }),
            ),
        };

        FileIdentity {
            volume_identity,
            object_id,
            object_kind,
            // Always `None` on this platform: obtaining an NTFS USN needs
            // the USN journal API, which this phase does not add (see the
            // struct doc on `generation_or_usn`). Threaded through as a
            // parameter rather than hardcoded so both platforms' `from_
            // metadata` share one signature with `observe_path`/`observe_
            // handle`, which is what actually supplies a real value on
            // Linux.
            generation_or_usn,
            birth_or_creation_time,
            observed_size: metadata.len(),
            metadata_fingerprint: fingerprint_windows(
                metadata,
                object_kind,
                platform_fields.change_time,
                platform_fields.usn,
            ),
            // `platform_fields` came from a single `GetFileInformationByHandle`
            // call that either populated every field it reports or failed
            // outright (see [`win_identity::query_path`]/[`query_handle`]) —
            // `observe_path`/`observe_handle` already propagate that failure
            // as an `Err` before a `FileIdentity` is ever constructed, so by
            // the time this function runs the link count is always known.
            link_count: Some(u64::from(platform_fields.number_of_links)),
            // See the identical comment in the Unix branch above: always
            // overwritten by the caller right after this returns.
            symlink_target_digest: None,
        }
    }

    /// The sanctioned way to ask "are these two observations the same
    /// object". Never returns a bare `bool`: an [`IdentityComparison::
    /// Ambiguous`] result means exactly what it says, and the caller must
    /// handle it explicitly rather than treat it as either answer.
    /// `birth_time_granularity` is the caller's measurement of this
    /// volume's clock resolution (see [`TimestampGranularity`]) — it must
    /// come from actually probing the volume, never assumed `Fine` by
    /// default, since a wrong default in that direction is exactly what
    /// lets a coarse clock's equal-but-meaningless birth times pass as
    /// proof of identity. On Windows, whether this can ever reach
    /// [`IdentityComparison:: SameObject`] depends on which
    /// [`WindowsObjectId`] case both observations landed in: a match on
    /// [`WindowsObjectId::Fallback`]'s 64-bit file index — even combined
    /// with a matching reuse discriminator — is downgraded to
    /// [`IdentityComparison::Ambiguous`]`(
    /// `[`AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs`]`)`
    /// instead, since that field is not guaranteed unique on ReFS. A match
    /// on [`WindowsObjectId::Proven`]'s 128-bit id needs no corroborating
    /// `generation_or_usn` or `birth_or_creation_time` at all — see its
    /// own doc for why a matching value is itself a reuse discriminator —
    /// so it reaches `SameObject` even when neither of those fields is
    /// available or the volume's clock is
    /// [`TimestampGranularity::Coarse`], which is exactly the situation a
    /// real Windows observation is in today (no portable
    /// `generation_or_usn` source, and a system clock coarse enough for
    /// many creates to land in one tick). A conclusive *mismatch* on any
    /// field — including a differing `birth_or_creation_time` when both
    /// sides happen to carry one — is unaffected and still proves
    /// `DefinitelyDifferent` on every platform; a `Proven` match only
    /// rescues an otherwise-`Ambiguous` verdict, never overrides a
    /// conclusive disagreement elsewhere.
    pub fn compare(
        &self,
        other: &FileIdentity,
        birth_time_granularity: TimestampGranularity,
    ) -> IdentityComparison {
        if std::mem::discriminant(&self.volume_identity)
            != std::mem::discriminant(&other.volume_identity)
        {
            return IdentityComparison::Ambiguous(AmbiguityReason::CrossPlatformRepresentation);
        }
        // This method-mismatch check must run *before* the volume-identity
        // equality check below, not after it: `VolumeIdentity::Windows`'s
        // own doc explains that a `Proven` observation's full 64-bit
        // `FILE_ID_INFO::VolumeSerialNumber` and a `Fallback` observation's
        // zero-extended legacy 32-bit `dwVolumeSerialNumber` are assumed to
        // agree for the same volume, but that is exactly the assumption a
        // method mismatch calls into question -- the two calls are reading
        // different Win32 structures, and this crate does not get to also
        // assume they always widen consistently. Checking volume equality
        // first would let a same-object, mixed-method pair that happens to
        // disagree on that assumption fail the volume check and report
        // `DefinitelyDifferent`, a stronger claim than a method mismatch can
        // back -- exactly the ambiguity this check exists to report instead.
        // See `AmbiguityReason::WindowsIdentityMethodMismatch`'s doc for why
        // seeing this shape at all is itself a sign something upstream is
        // wrong, not a case worth trying to reconcile.
        if let (PlatformObjectId::Windows(mine), PlatformObjectId::Windows(theirs)) =
            (self.object_id, other.object_id)
        {
            if std::mem::discriminant(&mine) != std::mem::discriminant(&theirs) {
                return IdentityComparison::Ambiguous(
                    AmbiguityReason::WindowsIdentityMethodMismatch,
                );
            }
        }
        if self.volume_identity != other.volume_identity {
            return IdentityComparison::DefinitelyDifferent;
        }
        if self.object_id != other.object_id {
            return IdentityComparison::DefinitelyDifferent;
        }
        if self.object_kind != other.object_kind {
            return IdentityComparison::DefinitelyDifferent;
        }
        // Reuse discrimination, strongest available field first. What
        // defeats inode reuse is not a generation counter specifically —
        // it is *any* field that a freshly (re)created object is
        // guaranteed to disagree on with whatever previously held that
        // same volume+object id. Ranked by how widely each is available:
        // 1. `generation_or_usn` — a true anti-reuse counter when the
        // platform exposes one. Strongest: on Linux this is `FS_IOC_
        // GETVERSION` on ext4/XFS (measured unprivileged and reuse-
        // discriminating; absent, not merely gated, on overlayfs — see
        // `generation_from_path`'s doc). Not available through a portable
        // `stat` call on any platform, which is why this is still commonly
        // `None`. Not granularity-dependent: it is a counter, not a clock
        // reading. 2. `symlink_target_digest`, for a symlink specifically
        // — see its own doc. Ranked with `generation_or_usn` rather than
        // below `birth_or_creation_time`: it is content, not a clock
        // reading, so it needs no granularity gate, and it is the *only*
        // discriminator a symlink can ever populate `generation_or_usn`
        // with (the ioctl that field comes from is never attempted for
        // this kind — see `generation_from_path`'s doc). 3.
        // `birth_or_creation_time` — widely available (`st_birthtime` on
        // macOS, `statx`'s `STATX_BTIME` on modern Linux filesystems), but
        // only as strong as the clock behind it. A *differing* birth time
        // is unconditionally conclusive (it cannot move backward on a live
        // object, at any granularity). An *equal* one is conclusive only
        // when `birth_time_ granularity` is `Fine`: on a coarse clock, a
        // delete-and- recreate landing in the same tick as the object it
        // replaced would report the exact same value, so equality alone
        // proves nothing there. 4. Neither present on both sides, or birth
        // time matched on a coarse clock — genuinely nothing here excludes
        // reuse, so the answer must be `Ambiguous`. `mtime` is
        // deliberately never used as a fallback here: an ordinary write
        // changes it, so it proves nothing about identity and would turn
        // "the same file, edited" into a false positive for "the same
        // object survived". `object_id` equality was checked above, but a
        // `WindowsObjectId:: Fallback` (unlike `WindowsObjectId::Proven`,
        // and unlike a Unix inode) is not guaranteed unique on ReFS -- see
        // its doc. Neither reuse discriminator below can rescue that: a
        // matching `generation_or_usn` or `birth_or_creation_time` says
        // "these two observations are consistent with being the same
        // object", but says nothing about whether a *different* object
        // could coincidentally share both the weak object id and the
        // discriminator. So a `SameObject` conclusion drawn purely from a
        // `Fallback` object id is downgraded to `Ambiguous` here, the same
        // way an equal birth time is not trusted on a coarse clock. A
        // `Proven` id gets no such downgrade -- it is trusted exactly like
        // a Unix inode.
        let object_id_alone_may_collide_across_distinct_objects =
            matches!(self.object_id, PlatformObjectId::Windows(WindowsObjectId::Fallback { .. }));
        // A matching `WindowsObjectId::Proven` id needs no corroborating
        // discriminator at all -- see its own doc for why a match on it is
        // already a reuse discriminator. Used below only to rescue what
        // would otherwise be an `Ambiguous` verdict (no available
        // discriminator, or a coarse clock); it never overrides a
        // conclusive *mismatch* found by a tier above it, since every such
        // mismatch check runs, and returns, before this flag is consulted.
        let windows_proven_id_needs_no_discriminator =
            matches!(self.object_id, PlatformObjectId::Windows(WindowsObjectId::Proven { .. }));
        if let (Some(mine), Some(theirs)) = (self.generation_or_usn, other.generation_or_usn) {
            return if mine != theirs {
                IdentityComparison::DefinitelyDifferent
            } else if object_id_alone_may_collide_across_distinct_objects {
                IdentityComparison::Ambiguous(AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs)
            } else {
                IdentityComparison::SameObject
            };
        }
        // A symlink-specific discriminator, ranked alongside `generation_or_
        // usn` rather than after `birth_or_creation_time`: unlike a birth
        // time, a symlink's target is not a clock reading a coincidence can
        // land on, it is content the object was created with — and, like a
        // regular file's bytes, it cannot change without destroying and
        // recreating the object (there is no in-place symlink edit). Object
        // kind was already checked equal above, so `self.object_kind ==
        // Symlink` here implies both sides are. Only reached when `generation_
        // or_usn` was unavailable on at least one side, which is every
        // symlink observation on every platform this crate runs on today —
        // see `symlink_target_digest`'s own doc for why the ioctl never
        // applies to this kind. Never fires unless both sides actually carry
        // a digest (see `symlink_target_digest`'s doc on which observations
        // populate it), so a caller that never reads a symlink target —
        // every kind besides `FileIdentity` itself, and any decoded-from-
        // storage identity — is unaffected: this tier is simply skipped for
        // it, same as `generation_or_usn` already is when a platform cannot
        // supply one.
        if self.object_kind == ObjectKind::Symlink {
            if let (Some(mine), Some(theirs)) =
                (self.symlink_target_digest, other.symlink_target_digest)
            {
                return if mine != theirs {
                    // The object id matched (checked above) but the target
                    // digest did not: since a live symlink's target cannot
                    // itself change, this is exactly the "same id, different
                    // object" reuse shape the whole ranked ladder exists to
                    // catch — conclusive, not merely suspicious, the same
                    // way a differing birth time is conclusive regardless of
                    // clock granularity.
                    IdentityComparison::DefinitelyDifferent
                } else if object_id_alone_may_collide_across_distinct_objects {
                    IdentityComparison::Ambiguous(
                        AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs,
                    )
                } else {
                    IdentityComparison::SameObject
                };
            }
        }
        if let (Some(mine), Some(theirs)) =
            (self.birth_or_creation_time, other.birth_or_creation_time)
        {
            if mine != theirs {
                return IdentityComparison::DefinitelyDifferent;
            }
            return match birth_time_granularity {
                TimestampGranularity::Fine
                    if object_id_alone_may_collide_across_distinct_objects =>
                {
                    IdentityComparison::Ambiguous(
                        AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs,
                    )
                }
                TimestampGranularity::Fine => IdentityComparison::SameObject,
                // An equal birth time on a coarse clock proves nothing by
                // itself (see the ranking doc above) -- but a `Proven` id
                // match needs no such corroboration, so it still resolves
                // to `SameObject` here instead of falling back to
                // `Ambiguous`. A *differing* birth time is unaffected: it
                // already returned `DefinitelyDifferent` above, before this
                // match is ever reached.
                TimestampGranularity::Coarse if windows_proven_id_needs_no_discriminator => {
                    IdentityComparison::SameObject
                }
                TimestampGranularity::Coarse => {
                    IdentityComparison::Ambiguous(AmbiguityReason::CoarseTimestampGranularity)
                }
            };
        }
        // Neither `generation_or_usn` nor `birth_or_creation_time` was
        // available on both sides -- the real shape of a Windows
        // observation today, which has no portable source for the former
        // and, on some hosts, too coarse a clock to trust the latter even
        // when present. A `Proven` id match still needs no corroboration
        // here for the same reason as above.
        if windows_proven_id_needs_no_discriminator {
            return IdentityComparison::SameObject;
        }
        IdentityComparison::Ambiguous(AmbiguityReason::NoStableGenerationOrUsn)
    }
}

impl DirectoryIdentity {
    // See the identical comment on `FileIdentity::observe_path` for why
    // `clippy::let_unit_value` is allowed here.
    #[allow(clippy::let_unit_value)]
    pub fn observe_path(path: &Path) -> io::Result<DirectoryIdentity> {
        let metadata = std::fs::symlink_metadata(path)?;
        let generation_or_usn = generation_from_path(path, &metadata);
        let platform_fields = platform_fields_from_path(path, &metadata)?;
        Ok(Self::from_metadata(&metadata, generation_or_usn, platform_fields))
    }

    #[allow(clippy::let_unit_value)]
    pub fn observe_handle(file: &File) -> io::Result<DirectoryIdentity> {
        let metadata = file.metadata()?;
        let generation_or_usn = generation_from_handle(file, &metadata);
        let platform_fields = platform_fields_from_handle(file, &metadata)?;
        Ok(Self::from_metadata(&metadata, generation_or_usn, platform_fields))
    }

    #[cfg(unix)]
    fn from_metadata(
        metadata: &Metadata,
        generation_or_usn: Option<u128>,
        _platform_fields: PlatformFields,
    ) -> DirectoryIdentity {
        use std::os::unix::fs::MetadataExt;
        let birth_or_creation_time = metadata.created().ok().map(Timestamp::from_system_time);
        DirectoryIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: metadata.dev() },
            object_id: PlatformObjectId::Unix { inode: metadata.ino() },
            generation_or_usn,
            birth_or_creation_time,
        }
    }

    #[cfg(windows)]
    fn from_metadata(
        metadata: &Metadata,
        generation_or_usn: Option<u128>,
        platform_fields: PlatformFields,
    ) -> DirectoryIdentity {
        // See `FileIdentity::from_metadata`'s Windows branch for why this
        // dispatches on `platform_fields.object_id` rather than reading a
        // single flat shape.
        use std::os::windows::fs::MetadataExt;
        let (volume_identity, object_id) = match platform_fields.object_id {
            win_identity::ObjectIdFields::Proven { volume_serial_number, file_id } => (
                VolumeIdentity::Windows { volume_serial_number },
                PlatformObjectId::Windows(WindowsObjectId::Proven { file_id }),
            ),
            win_identity::ObjectIdFields::Fallback { volume_serial_number, file_index } => (
                VolumeIdentity::Windows { volume_serial_number },
                PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index }),
            ),
        };
        let birth_or_creation_time = Some(Timestamp::from_system_time(
            SystemTime::UNIX_EPOCH
                + std::time::Duration::from_nanos(metadata.creation_time().saturating_mul(100)),
        ));
        DirectoryIdentity { volume_identity, object_id, generation_or_usn, birth_or_creation_time }
    }

    /// The sanctioned way to ask "are these two observations the same
    /// directory" -- the [`DirectoryIdentity`] counterpart to
    /// [`FileIdentity::compare`], mirroring it exactly now that this type
    /// carries the same `birth_or_creation_time` fallback (see the struct
    /// doc for why an earlier, field-less version of this method could not
    /// express "cannot rule out reuse" at all). Returns the same
    /// three-valued [`IdentityComparison`], takes the same
    /// [`TimestampGranularity`] argument for the same reason (no safe
    /// default -- see [`FileIdentity::compare`]'s doc), and applies the
    /// identical ranked reuse-discrimination sequence: `generation_or_usn`
    /// first, then `birth_or_creation_time` gated on granularity, then
    /// `Ambiguous` when neither is available on both sides.
    ///
    /// - Cross-platform representations never compare — see
    ///   [`AmbiguityReason::CrossPlatformRepresentation`].
    /// - A [`WindowsObjectId::Proven`]/[`WindowsObjectId::Fallback`] method
    ///   mismatch is checked, and reported `Ambiguous`, *before* the volume
    ///   equality check — see the ordering comment in [`FileIdentity::
    ///   compare`], which applies identically here.
    /// - A matching [`WindowsObjectId::Fallback`] id is never trusted alone:
    ///   it is not guaranteed unique on ReFS, so two distinct, simultaneously
    ///   live directories can report the same one. This is the defect this
    ///   method exists to close — [`DirectoryIdentity`] has no `Eq` impl of
    ///   its own precisely so a caller cannot reach for a plain `==` that
    ///   skips this rule.
    /// - A matching [`WindowsObjectId::Proven`] id, by contrast, needs no
    ///   corroborating `generation_or_usn` or `birth_or_creation_time` —
    ///   see its own doc — so it resolves to `SameObject` even with neither
    ///   available or on a [`TimestampGranularity::Coarse`] clock, without
    ///   overriding any conclusive mismatch found above it.
    ///
    /// A conclusive mismatch on any field is `DefinitelyDifferent` on every
    /// platform, exactly as in `FileIdentity::compare`.
    pub fn compare(
        &self,
        other: &DirectoryIdentity,
        birth_time_granularity: TimestampGranularity,
    ) -> IdentityComparison {
        if std::mem::discriminant(&self.volume_identity)
            != std::mem::discriminant(&other.volume_identity)
        {
            return IdentityComparison::Ambiguous(AmbiguityReason::CrossPlatformRepresentation);
        }
        // See `FileIdentity::compare`'s identical check for why this must
        // run before the volume-identity equality check below.
        if let (PlatformObjectId::Windows(mine), PlatformObjectId::Windows(theirs)) =
            (self.object_id, other.object_id)
        {
            if std::mem::discriminant(&mine) != std::mem::discriminant(&theirs) {
                return IdentityComparison::Ambiguous(
                    AmbiguityReason::WindowsIdentityMethodMismatch,
                );
            }
        }
        if self.volume_identity != other.volume_identity {
            return IdentityComparison::DefinitelyDifferent;
        }
        if self.object_id != other.object_id {
            return IdentityComparison::DefinitelyDifferent;
        }
        // Ranked reuse discrimination, identical to `FileIdentity::compare`
        // (see its doc for the full ranking rationale): `generation_or_usn`
        // first when available on both sides, then `birth_or_creation_time`
        // gated on the measured clock granularity, then `Ambiguous` when
        // neither excludes reuse. A `Fallback` object id is never trusted
        // alone regardless of which tier concludes `SameObject` — see the
        // flag below, checked last on every path that would otherwise
        // return `SameObject`.
        let object_id_alone_may_collide_across_distinct_objects =
            matches!(self.object_id, PlatformObjectId::Windows(WindowsObjectId::Fallback { .. }));
        // See the identical flag in `FileIdentity::compare` for why a
        // `Proven` match needs no corroborating discriminator, and why
        // that only ever rescues an `Ambiguous` verdict, never overrides a
        // conclusive mismatch found above.
        let windows_proven_id_needs_no_discriminator =
            matches!(self.object_id, PlatformObjectId::Windows(WindowsObjectId::Proven { .. }));
        if let (Some(mine), Some(theirs)) = (self.generation_or_usn, other.generation_or_usn) {
            return if mine != theirs {
                IdentityComparison::DefinitelyDifferent
            } else if object_id_alone_may_collide_across_distinct_objects {
                IdentityComparison::Ambiguous(AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs)
            } else {
                IdentityComparison::SameObject
            };
        }
        if let (Some(mine), Some(theirs)) =
            (self.birth_or_creation_time, other.birth_or_creation_time)
        {
            if mine != theirs {
                return IdentityComparison::DefinitelyDifferent;
            }
            return match birth_time_granularity {
                TimestampGranularity::Fine
                    if object_id_alone_may_collide_across_distinct_objects =>
                {
                    IdentityComparison::Ambiguous(
                        AmbiguityReason::WindowsObjectIdNotProvenUniqueOnRefs,
                    )
                }
                TimestampGranularity::Fine => IdentityComparison::SameObject,
                TimestampGranularity::Coarse if windows_proven_id_needs_no_discriminator => {
                    IdentityComparison::SameObject
                }
                TimestampGranularity::Coarse => {
                    IdentityComparison::Ambiguous(AmbiguityReason::CoarseTimestampGranularity)
                }
            };
        }
        if windows_proven_id_needs_no_discriminator {
            return IdentityComparison::SameObject;
        }
        IdentityComparison::Ambiguous(AmbiguityReason::NoStableGenerationOrUsn)
    }
}

/// Reads the Linux inode generation number (`FS_IOC_GETVERSION`) for the
/// object at `path`, without following a terminal symlink and without
/// following one to open it either.
///
/// Measured (not assumed): the ioctl succeeds for an unprivileged process
/// with mere read access on ext4 and XFS, and genuinely discriminates inode
/// reuse there (every one of 79,800 observed create/unlink/recreate pairs
/// produced a changed generation, zero collisions). On overlayfs it returns
/// `ENOTTY` — absent, not merely permission-gated: the same call still
/// fails identically as root with every capability. This function does not
/// branch on filesystem type at all; it always attempts the ioctl and
/// reports `None` on any failure, `ENOTTY` included — see [`Self::compare`]
/// on [`FileIdentity`] for why a `None` here just falls back to the
/// birth-time/granularity path rather than needing its own fail-closed
/// classification: the value is read fresh per observation, never cached,
/// so a transient failure costs nothing beyond this one comparison losing
/// its strongest available proof.
#[cfg(target_os = "linux")]
fn generation_from_path(path: &Path, metadata: &Metadata) -> Option<u128> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    // `FS_IOC_GETVERSION` is meaningful only for a regular file or
    // directory; nothing else is worth opening for it, and opening a
    // FIFO/socket/device node here could itself block or have side
    // effects unrelated to identity.
    if !(metadata.is_file() || metadata.is_dir()) {
        return None;
    }
    // `O_NOFOLLOW` even though `path` was already observed via
    // `symlink_metadata`: defense against a TOCTOU swap of the path for a
    // symlink between that stat and this open, matching this module's
    // never-follow rule everywhere else.
    let file =
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).ok()?;
    linux_inode_generation(file.as_raw_fd())
}

#[cfg(not(target_os = "linux"))]
fn generation_from_path(_path: &Path, _metadata: &Metadata) -> Option<u128> {
    None
}

/// Same as [`generation_from_path`], from an already-open handle — no
/// re-open, so no TOCTOU window at all.
#[cfg(target_os = "linux")]
fn generation_from_handle(file: &File, metadata: &Metadata) -> Option<u128> {
    use std::os::unix::io::AsRawFd;
    if !(metadata.is_file() || metadata.is_dir()) {
        return None;
    }
    linux_inode_generation(file.as_raw_fd())
}

#[cfg(not(target_os = "linux"))]
fn generation_from_handle(_file: &File, _metadata: &Metadata) -> Option<u128> {
    None
}

/// Issues `FS_IOC_GETVERSION` on `fd` and returns the generation number on
/// success. `EINTR` is retried (a signal interruption is not a meaningful
/// result); every other failure — `ENOTTY` (the filesystem does not
/// implement it) exactly as much as any transient error — returns `None`,
/// since a single observation has nothing more specific to report and the
/// caller already treats absence and failure identically (see [`generation_
/// from_path`]'s doc).
#[cfg(target_os = "linux")]
fn linux_inode_generation(fd: std::os::unix::io::RawFd) -> Option<u128> {
    let mut generation: libc::c_long = 0;
    loop {
        // SAFETY: `fd` is a valid, open file descriptor for the duration of
        // the call; `generation` is a valid out-parameter of the size
        // `FS_IOC_GETVERSION` expects (a `c_long`).
        let ret = unsafe { libc::ioctl(fd, libc::FS_IOC_GETVERSION, &mut generation) };
        if ret == 0 {
            return Some(generation as u128);
        }
        if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return None;
    }
}

/// Converts a `readlink`-family result to the raw bytes
/// [`symlink_target_digest_from_path`]/[`symlink_target_digest_from_handle`]
/// hash. Bytes rather than `String`/`OsString` specifically because a
/// symlink target is not required to be valid UTF-8 on Unix.
///
/// `pub(crate)` (not private) because this is also the crate's one
/// definition of what a symlink target's captured bytes ARE:
/// `local_change`/`single_pass_capture` reuse it verbatim to build
/// `change::FileMeta::symlink_target`, so a symlink's identity-hash input
/// here and its captured symlink target are always the same bytes rather than
/// two independently-lossy conversions of the same on-disk value. On
/// Windows this serializes the target's UTF-16 code units little-endian via
/// `encode_wide`, which — unlike a UTF-8/UTF-16 conversion — never rejects
/// or replaces an unpaired surrogate, so a Windows target with one still
/// round-trips through these bytes exactly.
#[cfg(unix)]
pub fn target_to_bytes(target: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    target.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
pub fn target_to_bytes(target: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    target.as_os_str().encode_wide().flat_map(u16::to_le_bytes).collect()
}

/// The inverse of [`target_to_bytes`] — reconstructs the `OsString` a
/// captured `change::FileMeta::symlink_target` byte string names, for a
/// caller (`chunker::materialize_symlink`/`materialize_symlink_windows`)
/// that needs to actually pass the target to a real `symlink`/
/// `CreateSymbolicLinkW` call. Kept next to `target_to_bytes` as the other
/// half of this crate's one definition of what these bytes are, rather than
/// each materialization call site growing its own conversion.
#[cfg(unix)]
pub fn bytes_to_target(bytes: &[u8]) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(bytes).to_os_string()
}

/// Windows counterpart of [`bytes_to_target`]. `bytes` is interpreted as
/// UTF-16 code units serialized little-endian (`target_to_bytes`'s own
/// output shape) — `OsString::from_wide` accepts an unpaired surrogate
/// among them the same way `encode_wide` can produce one, so a Windows
/// target with one still reconstructs exactly. A `bytes` length that is
/// odd, or otherwise not actually `target_to_bytes`'s own output, has no
/// well-formed code-unit sequence to decode; rather than panic or silently
/// truncate the trailing byte, this reports it as `None`, and every caller
/// treats that the same as "cannot materialize this target" instead of
/// guessing at a truncated one.
#[cfg(windows)]
pub fn bytes_to_target(bytes: &[u8]) -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> =
        bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    Some(std::ffi::OsString::from_wide(&units))
}

/// Hashes a symlink target's raw bytes into [`FileIdentity::
/// symlink_target_digest`]'s `[u8; 32]` — see that field's doc for why a
/// digest, not the bytes themselves, is what gets stored.
fn hash_symlink_target(target: &Path) -> [u8; 32] {
    hash_symlink_target_bytes(&target_to_bytes(target))
}

/// Same as [`hash_symlink_target`], for callers that already have the raw
/// target bytes in hand (a `readlinkat` buffer) rather than a `Path` --
/// [`symlink_target_digest_from_handle`] on Linux is the one such caller.
fn hash_symlink_target_bytes(target: &[u8]) -> [u8; 32] {
    Sha256::digest(target).into()
}

/// Reads the target text of the symlink observed at `path` and hashes it,
/// or returns `None` if this observation is not a symlink at all.
/// Portable: `std::fs::read_link` needs no platform-specific FFI on either
/// Unix or Windows, unlike [`generation_from_path`]'s ioctl. `path` was
/// already `lstat`ed (`symlink_metadata`) by the caller before this runs;
/// there is a narrow window between that call and this one in which the
/// object at `path` could be replaced by something else entirely.
fn symlink_target_digest_from_path(path: &Path, metadata: &Metadata) -> Option<[u8; 32]> {
    if !metadata.file_type().is_symlink() {
        return None;
    }
    std::fs::read_link(path).ok().map(|target| hash_symlink_target(&target))
}

/// Outcome of [`read_symlink_target_via_handle`]. Kept as its own type,
/// distinct from `Option<[u8; 32]>`, so this module's own logic cannot
/// conflate "not a symlink" with "a symlink whose target could not be
/// proven read in full" -- they reach [`symlink_target_digest_from_handle`]'s
/// `None` the same way, but they are not the same fact: the first has
/// nothing to digest because there was never a target to read; the second
/// has a target that exists but could not be safely hashed (see `read_
/// symlink_target_via_handle`'s doc on why a partial read is never hashed).
/// Both collapse to `None` in the field this feeds because [`FileIdentity::
/// compare`] already treats `None` there as "no digest tier available, fall
/// back to the next one" (see [`FileIdentity::symlink_target_digest`]'s own
/// doc), which is the correct degrade for both cases.
#[cfg_attr(test, derive(Debug))]
#[cfg(target_os = "linux")]
enum SymlinkTargetRead {
    NotASymlink,
    Unreadable,
    Target(Vec<u8>),
}

/// Reads the raw target bytes of the symlink `file` is open on, retrying
/// past the two ways a single `readlinkat` call can mislead a caller that
/// trusts its return value at face value.
///
/// First, truncation: `readlinkat` does not NUL-terminate and does not
/// report truncation -- when the target is longer than the supplied buffer,
/// it silently fills the buffer and returns exactly the buffer's length,
/// indistinguishable from a target that happens to be precisely that long.
/// Hashing that return value without checking for this would let two
/// targets that only share their first `buf_len` bytes digest identically,
/// exactly the collision [`FileIdentity::symlink_target_digest`] exists to
/// rule out. So a return equal to the current buffer length is never
/// accepted as complete: the buffer is grown and the read retried, up to
/// `MAX_TARGET_LEN`. Past that cap this is not a real Linux path (`PATH_MAX`
/// is comfortably inside it, many times over) -- reported [`SymlinkTargetRead::
/// Unreadable`] rather than guessing, which correctly withholds a digest
/// instead of hashing a prefix still not proven to be the whole target.
///
/// Second, `EINTR`: a negative return is a signal interruption exactly as
/// often as it is a real error, and treating it as the latter would
/// permanently give up proving this object's identity over what is often a
/// one-off, retryable interruption. Retried here via [`retry_eintr`]; every
/// other negative return has nothing more specific to report than
/// [`SymlinkTargetRead::Unreadable`].
///
/// 1 MiB, far past any real `PATH_MAX` (4096 on Linux), is the growth cap
/// used against a live handle — see [`read_symlink_target_with_buffer_sizes`]
/// for the parameterized version this delegates to (kept parameterized so
/// this module's tests can exercise the growth/truncation logic against a
/// small threshold without needing a real symlink target that exceeds the
/// platform's actual `PATH_MAX`, which `symlink(2)` itself refuses to
/// create).
#[cfg(target_os = "linux")]
fn read_symlink_target_via_handle(file: &File, metadata: &Metadata) -> SymlinkTargetRead {
    if !metadata.file_type().is_symlink() {
        return SymlinkTargetRead::NotASymlink;
    }
    const MAX_TARGET_LEN: usize = 1 << 20;
    read_symlink_target_with_buffer_sizes(file, libc::PATH_MAX as usize, MAX_TARGET_LEN)
}

/// Does the actual buffered `readlinkat` read backing [`read_symlink_target_
/// via_handle`], parameterized on the starting buffer size and the growth
/// cap so this module's own tests can drive it with thresholds far smaller
/// than a real `PATH_MAX` — see that function's doc for why.
#[cfg(target_os = "linux")]
fn read_symlink_target_with_buffer_sizes(
    file: &File,
    initial_buf_len: usize,
    max_buf_len: usize,
) -> SymlinkTargetRead {
    use std::os::unix::io::AsRawFd;
    // An empty, NUL-terminated pathname -- see `symlink_target_digest_from_
    // handle`'s doc for why that specific input is what makes `readlinkat`
    // operate on `dirfd` itself rather than a name resolved underneath it.
    const EMPTY_PATH: &[u8] = b"\0";
    let mut buf_len = initial_buf_len;
    loop {
        let mut buf = vec![0u8; buf_len];
        // `errno` is only consumed by `retry_eintr` itself to recognize
        // `EINTR`; every other failure is handled below purely from `ret`.
        let (ret, _errno) = retry_eintr(|| {
            // SAFETY: `file`'s descriptor is valid and open for the
            // duration of this call; `EMPTY_PATH` is a valid NUL-terminated
            // C string; `buf` is a valid out-parameter of the length
            // passed.
            let ret = unsafe {
                libc::readlinkat(
                    file.as_raw_fd(),
                    EMPTY_PATH.as_ptr().cast(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            let errno = if ret < 0 { io::Error::last_os_error().raw_os_error() } else { None };
            (ret as i64, errno)
        });
        if ret < 0 {
            return SymlinkTargetRead::Unreadable;
        }
        let n = ret as usize;
        if n < buf_len {
            // Strictly less than the buffer size proves this read captured
            // the complete target -- see [`read_symlink_target_via_handle`]'s
            // doc on why `n == buf_len` is treated as truncation instead.
            buf.truncate(n);
            return SymlinkTargetRead::Target(buf);
        }
        if buf_len >= max_buf_len {
            return SymlinkTargetRead::Unreadable;
        }
        buf_len = (buf_len * 2).min(max_buf_len);
    }
}

/// `EINTR`-retrying wrapper for a raw libc call following the usual C
/// convention (`-1` with `errno` set on failure).
#[cfg(target_os = "linux")]
fn retry_eintr(mut attempt: impl FnMut() -> (i64, Option<i32>)) -> (i64, Option<i32>) {
    loop {
        let (ret, errno) = attempt();
        if ret != -1 || errno != Some(libc::EINTR) {
            return (ret, errno);
        }
    }
}

/// Same as [`symlink_target_digest_from_path`], but reads the target of
/// the object `file` is already open on — no re-resolution of a name
/// against a parent directory, so no TOCTOU window at all, matching
/// [`FileIdentity:: observe_handle`]'s own guarantee over
/// [`FileIdentity::observe_path`]. An earlier version of this function
/// read `/proc/self/fd/<fd>` via `std::fs::read_link` instead of the
/// `readlinkat` call below, on the theory that the magic link's own target
/// reflects what `fd` refers to. Measured wrong on real Linux (ext4, XFS,
/// overlayfs): `/proc/self/fd/<fd>` resolves to the *pathname* of the file
/// the descriptor is open on — for an `O_PATH | O_NOFOLLOW` descriptor on
/// a symlink, that is the symlink's own path (e.g. `/tmp/xyz/link`), not
/// the target text it points at. That bug shipped a digest of the wrong
/// string, which then disagreed with the path-based digest and reported
/// every real symlink transfer as a substitution — caught by this module's
/// own `observe_handle_and_
/// observe_path_report_the_same_symlink_target_digest` test.
/// `readlinkat(fd, "", buf, len)` is the correct primitive: per
/// `readlinkat`'s own man page, an *empty* `pathname` makes the call
/// operate directly on `dirfd` when `dirfd` was opened `O_PATH |
/// O_NOFOLLOW` on a symlink — no `AT_EMPTY_PATH` flag argument exists on
/// this call (unlike `fstatat`/ `linkat`/etc.), the empty-pathname special
/// case is unconditional. This reads the symlink's actual target, exactly
/// matching what a path-based `readlink` on the same object returns. No
/// equivalent trick is implemented for macOS/Windows yet. This does not
/// regress the held- handle comparison on macOS:
/// [`TimestampGranularity::Fine`] already lets `birth_or_creation_time`
/// alone reach `SameObject` for a symlink there (measured: APFS's clock is
/// fine enough), which is what `compare` falls back to when this digest
/// tier is unavailable on one side. A caller with only a path-based
/// [`symlink_target_digest_from_path`] value on such a platform simply has
/// `None` here and falls back to whatever [`FileIdentity::compare`]'s
/// other tiers can prove. The actual read (buffer growth on truncation,
/// `EINTR` retry) is done by [`read_symlink_target_via_handle`] -- see its
/// doc for why a single fixed- size `readlinkat` call is not safe to trust
/// directly.
#[cfg(target_os = "linux")]
fn symlink_target_digest_from_handle(file: &File, metadata: &Metadata) -> Option<[u8; 32]> {
    match read_symlink_target_via_handle(file, metadata) {
        SymlinkTargetRead::Target(bytes) => Some(hash_symlink_target_bytes(&bytes)),
        SymlinkTargetRead::NotASymlink | SymlinkTargetRead::Unreadable => None,
    }
}

#[cfg(not(target_os = "linux"))]
fn symlink_target_digest_from_handle(_file: &File, _metadata: &Metadata) -> Option<[u8; 32]> {
    None
}

/// The metadata fingerprint of a directory with Unix `mode` at `dev`/`ino`.
#[cfg(unix)]
fn directory_fingerprint_unix(mode: u32, dev: u64, ino: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"yadorilink-fs-identity-directory-fingerprint-v1");
    hasher.update([u8_repr(ObjectKind::Directory)]);
    hasher.update((mode & 0o7777).to_le_bytes());
    hasher.update(dev.to_le_bytes());
    hasher.update(ino.to_le_bytes());
    hasher.finalize().into()
}

/// Whether the directory now observed as `metadata` has other permission
/// bits (`mode & 0o777`) than it had when `recorded` was observed, rather
/// than differing, if at all, only in its setuid, setgid or sticky bit.
///
/// A directory's fingerprint covers `mode & 0o7777`, so a special bit
/// alone moves it; the fingerprint is a digest and cannot be read back, so
/// this asks whether any combination of special bits over the observed
/// permission bits yields the recorded fingerprint. Meaningful only for
/// the same object (`recorded` compared as the same object as `metadata`).
#[cfg(unix)]
pub fn directory_permission_bits_changed(recorded: &FileIdentity, metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    let permissions = metadata.mode() & 0o777;
    !(0..8u32).any(|special| {
        directory_fingerprint_unix(permissions | (special << 9), metadata.dev(), metadata.ino())
            == recorded.metadata_fingerprint
    })
}

#[cfg(unix)]
fn fingerprint_unix(metadata: &Metadata, object_kind: ObjectKind) -> [u8; 32] {
    use std::os::unix::fs::MetadataExt;

    let mut hasher = Sha256::new();
    if object_kind == ObjectKind::Directory {
        // A directory's size and timestamps move whenever an entry inside
        // it is added, removed or renamed. None of that is a change to the
        // directory itself as a replicated entry -- its only tracked state
        // is its mode -- so they are left out, or every child landing in a
        // directory would read as the directory having been touched.
        return directory_fingerprint_unix(metadata.mode(), metadata.dev(), metadata.ino());
    }
    hasher.update(b"yadorilink-fs-identity-fingerprint-v1");
    hasher.update([u8_repr(object_kind)]);
    hasher.update(metadata.len().to_le_bytes());
    hasher.update((metadata.mode() & 0o7777).to_le_bytes());
    hasher.update(metadata.mtime().to_le_bytes());
    hasher.update(metadata.mtime_nsec().to_le_bytes());
    hasher.update(metadata.ctime().to_le_bytes());
    hasher.update(metadata.ctime_nsec().to_le_bytes());
    hasher.finalize().into()
}

/// `change_time` is `win_identity::IdentityFields::change_time` -- see its
/// own doc for why it is folded in here (the race-freshness fingerprint)
/// and nowhere near `FileIdentity::compare`. Bumped into the fingerprint
/// as a `v2` domain tag: a `v1`-fingerprinted observation and a
/// `v2`-fingerprinted re-observation of the identical, untouched file must
/// still compare unequal, or a build straddling this change would silently
/// treat every untouched file as "raced" on its first re-check.
#[cfg(windows)]
fn fingerprint_windows(
    metadata: &Metadata,
    object_kind: ObjectKind,
    change_time: Option<i64>,
    usn: Result<Option<i64>, u32>,
) -> [u8; 32] {
    use std::os::windows::fs::MetadataExt;

    let mut hasher = Sha256::new();
    if object_kind == ObjectKind::Directory {
        // As on Unix: a directory's size and write time follow its
        // entries, not the directory itself. Its attributes are what is
        // left of its own state. (The object id is compared separately by
        // `FileIdentity::compare`; `std` exposes no stable file index to
        // fold in here.) `change_time` is excluded for the same reason:
        // NTFS bumps a directory's own `ChangeTime` when an entry inside
        // it is added, removed or renamed, exactly the child traffic this
        // branch already excludes `last_write_time` to avoid.
        hasher.update(b"yadorilink-fs-identity-directory-fingerprint-v2");
        hasher.update([u8_repr(object_kind)]);
        hasher.update(metadata.file_attributes().to_le_bytes());
        return hasher.finalize().into();
    }
    hasher.update(b"yadorilink-fs-identity-fingerprint-v3");
    hasher.update([u8_repr(object_kind)]);
    hasher.update(metadata.len().to_le_bytes());
    hasher.update(metadata.file_attributes().to_le_bytes());
    hasher.update(metadata.last_write_time().to_le_bytes());
    // `None` (the query failed) is its own distinct byte pattern, not
    // silently folded into value `0` -- an `i64::from(0)` is a real,
    // reachable `ChangeTime` (1601-01-01) that must not collide with "this
    // build could not read one".
    match change_time {
        Some(value) => {
            hasher.update([1u8]);
            hasher.update(value.to_le_bytes());
        }
        None => hasher.update([0u8]),
    }
    // The USN, which a writer cannot put back as it can the times. A volume without a journal
    // and an unreadable USN are each their own byte pattern too.
    match usn {
        Ok(Some(value)) => {
            hasher.update([1u8]);
            hasher.update(value.to_le_bytes());
        }
        Ok(None) => hasher.update([2u8]),
        Err(_) => hasher.update([0u8]),
    }
    hasher.finalize().into()
}

/// `std::os::windows::fs::MetadataExt:: {volume_serial_number, file_index,
/// number_of_links}` report the `GetFileInformationByHandle` subset of
/// this data, but sit behind the `windows_by_handle` feature, unstable
/// since 2019 and unavailable on stable Rust; there is no stable `std`
/// path to the `FileIdInfo` data at all. `GetFileInformationByHandle`'s
/// 64-bit file index is not the full 128-bit ReFS-safe identifier — see
/// [`WindowsObjectId::Fallback`](super:: WindowsObjectId::Fallback)'s doc
/// for why, and [`super::FileIdentity:: compare`] for how the comparison
/// stays fail-closed for it. The full identifier needs
/// `GetFileInformationByHandleEx` called with the `FileIdInfo` class
/// (`0x12`), which returns a `FILE_ID_INFO { VolumeSerialNumber: u64,
/// FileId: [u8; 16] }` — a different struct layout from
/// `ByHandleFileInformation` below, not merely an extension of it.
/// [`query_raw_handle`] issues both calls: `GetFileInformationByHandle`
/// for the link count (and as the fallback source of volume serial/file
/// index), and `GetFileInformationByHandleEx(FileIdInfo)` for the proven
/// 128-bit id. A third call, `GetVolumeInformationByHandleW` (see
/// [`reuse_safe_ filesystem`]), gates whether a well-formed 128-bit id is
/// actually classified `Proven` rather than downgraded to `Fallback` --
/// see [`WindowsObjectId::Proven`](super::WindowsObjectId::Proven)'s doc
/// for why that distinction exists on top of the sentinel check above.
#[cfg(windows)]
mod win_identity {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::Path;

    #[repr(C)]
    struct FileTime {
        _low_date_time: u32,
        _high_date_time: u32,
    }

    /// Layout-compatible with Win32's `BY_HANDLE_FILE_INFORMATION`.
    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    /// Layout-compatible with Win32's `FILE_ID_INFO`, the payload
    /// `GetFileInformationByHandleEx` fills when called with the
    /// `FileIdInfo` class (`0x12`). Not layout-compatible with, nor an
    /// extension of, `ByHandleFileInformation` above -- a distinct Win32
    /// struct for a distinct call.
    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    /// Layout-compatible with Win32's `FILE_BASIC_INFO`, the payload
    /// `GetFileInformationByHandleEx` fills when called with the
    /// `FileBasicInfo` class (`0x0`). `change_time` is the field this
    /// struct exists for: NTFS bumps it on every metadata-affecting
    /// change to the file, INCLUDING an in-place content overwrite that
    /// otherwise restores `last_write_time` exactly -- the same role
    /// Unix `ctime` plays for [`fingerprint_unix`](super::fingerprint_unix),
    /// and unlike `last_write_time`, which `SetFileTime` lets a writer put
    /// back. All four times are `i64` 100ns-since-1601 FILETIMEs, not the
    /// two-`u32`-halves `FileTime` layout `ByHandleFileInformation` uses.
    #[repr(C)]
    struct FileBasicInfo {
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        file_attributes: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: *mut c_void,
        ) -> *mut c_void;

        fn CloseHandle(object: *mut c_void) -> i32;

        fn DeviceIoControl(
            device: *mut c_void,
            control_code: u32,
            in_buffer: *const c_void,
            in_size: u32,
            out_buffer: *mut c_void,
            out_size: u32,
            bytes_returned: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;

        fn GetLastError() -> u32;

        fn GetFileInformationByHandle(
            file: *mut c_void,
            file_information: *mut ByHandleFileInformation,
        ) -> i32;

        fn GetFileInformationByHandleEx(
            file: *mut c_void,
            file_information_class: u32,
            file_information: *mut c_void,
            buffer_size: u32,
        ) -> i32;

        /// Every `*Buffer`/`*Number`/`*Length`/`*Flags` out-parameter here
        /// is individually optional -- Microsoft documents each as
        /// accepting `NULL` when the caller does not need it. [`query_raw_
        /// handle`] passes `NULL` for every parameter except the file
        /// system name, the only one it needs (see [`reuse_safe_filesystem`]).
        fn GetVolumeInformationByHandleW(
            file: *mut c_void,
            volume_name_buffer: *mut u16,
            volume_name_size: u32,
            volume_serial_number: *mut u32,
            maximum_component_length: *mut u32,
            file_system_flags: *mut u32,
            file_system_name_buffer: *mut u16,
            file_system_name_size: u32,
        ) -> i32;
    }

    const INVALID_HANDLE_VALUE: isize = -1;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    /// `FILE_INFO_BY_HANDLE_CLASS::FileIdInfo`.
    const FILE_ID_INFO_CLASS: u32 = 0x12;
    /// `FILE_INFO_BY_HANDLE_CLASS::FileBasicInfo`.
    const FILE_BASIC_INFO_CLASS: u32 = 0x0;

    /// The object-id half of a `GetFileInformationByHandle`(`Ex`) query,
    /// kept as an enum rather than an `Option<[u8; 16]>` bolted onto a flat
    /// struct so a caller cannot forget which case it is holding -- see
    /// [`super::WindowsObjectId`], whose two variants this maps directly
    /// onto. [`Self::Proven`] is populated only from a successful
    /// `GetFileInformationByHandleEx(FileIdInfo)` call whose returned
    /// `FileId` is neither of [MS-FSCC]'s documented sentinels; [`Self::
    /// Fallback`] is what [`query_raw_handle`] falls back to both when that
    /// call fails outright -- which needs Windows 8 / Server 2012 or later,
    /// and can still fail on some filesystems there -- and when it
    /// "succeeds" but hands back a sentinel `FileId`. [MS-FSCC]'s "128-bit
    /// file ID" section documents two such values a *successful* call can
    /// still return: all-zero ("For file systems that do not support a
    /// 128-bit file ID, this field MUST be set to 0") and all-ones ("For
    /// files for which a unique 128-bit file ID cannot be established, this
    /// field MUST be set to 0xFFFF...FFFF"), both "MUST be ignored" per the
    /// spec. Treating either as `Proven` would let every object on such a
    /// filesystem -- or every file whose id couldn't be established --
    /// compare as the same object. Neither kind of degradation fails the
    /// observation outright: unlike `GetFileInformationByHandle` itself
    /// (still required unconditionally, for the link count), a missing or
    /// sentinel `FileIdInfo` result degrades what can be proven about
    /// identity, not whether an observation exists at all -- see
    /// [`super::PlatformFields`]'s doc on why "identity unavailable" would
    /// be the bigger regression here.
    pub(super) enum ObjectIdFields {
        Proven { volume_serial_number: u64, file_id: [u8; 16] },
        Fallback { volume_serial_number: u64, file_index: u64 },
    }

    /// The subset of `BY_HANDLE_FILE_INFORMATION`/`FILE_ID_INFO`
    /// [`FileIdentity`](super::FileIdentity)/[`DirectoryIdentity`](super::
    /// DirectoryIdentity) need. Always fully populated: [`query_path`]/
    /// [`query_handle`] return `Err` instead of a partially filled value,
    /// since these are the fields identity comparison relies on to tell
    /// objects apart (see `PlatformFields`'s doc on why a substituted value
    /// would be unsound here). That "always populated" guarantee covers
    /// `number_of_links` and *a* form of `object_id` -- not specifically the
    /// `Proven` one, which [`ObjectIdFields`]'s own doc explains is allowed
    /// to be absent.
    pub(super) struct IdentityFields {
        pub(super) object_id: ObjectIdFields,
        pub(super) number_of_links: u32,
        /// The raw `FILE_BASIC_INFO::ChangeTime` FILETIME, or `None` when
        /// that query itself failed -- unlike `object_id`/`number_of_links`,
        /// this does not fail the whole observation: it feeds only the
        /// race-freshness fingerprint (`fingerprint_windows`), never
        /// `FileIdentity::compare`'s reuse-safety judgment, so degrading to
        /// "this observation cannot see a same-mtime in-place overwrite"
        /// is the right failure mode, not losing the observation outright.
        pub(super) change_time: Option<i64>,
        /// The file's USN (`FSCTL_READ_FILE_USN_DATA`): `Ok(Some)` when the volume's change
        /// journal gave it one, `Ok(None)` when the volume has no usable journal, and `Err`
        /// (the Win32 error) when it could not be read. Unlike `ChangeTime` and the write time,
        /// which `FileBasicInfo` lets a writer put back, only the file system moves it, so a
        /// rewrite that restores both times still moves it. It feeds only the race-freshness
        /// fingerprints, never `FileIdentity::compare`.
        pub(super) usn: Result<Option<i64>, u32>,
    }

    /// Deliberately NOT cached, even keyed by `FILE_ID_INFO::
    /// VolumeSerialNumber`. This crate previously cached this answer
    /// process-wide by serial number, reasoning that a volume's filesystem
    /// does not change while mounted and that a different volume later
    /// reusing the same serial was already an accepted collision (see
    /// `VolumeIdentity`'s doc). That reasoning conflated two different
    /// risks. `VolumeIdentity`'s accepted collision is about two distinct
    /// object-id numbers coincidentally matching across two different
    /// volumes that share a serial -- a comparison-time risk, gated by
    /// requiring the caller to already believe both observations name the
    /// same tree. Caching this answer is a different, stronger claim: that
    /// serial number alone identifies *this mount instance* well enough to
    /// skip re-deriving whether it is safe to promote a match to `Proven`.
    /// Microsoft documents `VolumeSerialNumber` as a volume serial, not a
    /// mount-instance identifier, and a cloned volume carries the
    /// original's serial by construction -- so a remount (a different or
    /// cloned volume, possibly ReFS or something this crate has never
    /// classified) can reuse a serial a prior mount already earned a
    /// `true` answer for. Nothing in `FILE_ID_INFO` or
    /// `BY_HANDLE_FILE_INFORMATION` distinguishes that remount from the
    /// original mount, so no cached entry can be verified valid against
    /// the handle in hand -- there is no data to check it against. A stale
    /// `true` would silently promote a `Fallback`-only id (e.g. from an
    /// unrecognized or ReFS volume) to `Proven`, which [`FileIdentity::
    /// compare`] then treats as decisive with no corroborating evidence.
    /// The call this avoids is one `GetVolumeInformationByHandleW` on a
    /// handle [`query_raw_handle`] already has open and has already spent
    /// two other syscalls on (`GetFileInformationByHandle` and
    /// `GetFileInformationByHandleEx`); it adds no new handle open, no
    /// path re-resolution, and no I/O beyond what those two calls already
    /// paid for. That marginal cost does not justify a cache with no way
    /// to fail closed on a stale entry, so this crate always re-derives
    /// the answer per observation instead.
    ///
    /// The only Windows filesystem this crate has independently confirmed
    /// defeats [`super::WindowsObjectId::Proven`] id reuse: NTFS builds the
    /// low 64 bits of the 128-bit id from the same 48-bit MFT record index
    /// plus 16-bit sequence number as the legacy 64-bit file reference
    /// number, and that sequence number increments on every record reuse
    /// (see `WindowsObjectId::Proven`'s doc). `GetVolumeInformationByHandleW`
    /// reports this name in all-uppercase.
    const REUSE_SAFE_FILESYSTEM_NAME: &str = "NTFS";

    /// Whether `handle`'s volume is one this crate has confirmed makes a
    /// matching [`super::WindowsObjectId::Proven`] id trustworthy without a
    /// corroborating `generation_or_usn`/`birth_or_creation_time` --
    /// currently NTFS only (see [`REUSE_SAFE_FILESYSTEM_NAME`]'s doc).
    /// ReFS's true 128-bit id is constructed differently (a parent-
    /// directory index and an intra-directory index, per public
    /// documentation) with no documented incrementing component, so this
    /// crate cannot make the same claim for it yet -- it is deliberately
    /// *not* included here, even though [MS-FSCC] documents the weaker
    /// "unique within the volume" property for ReFS too (which is what
    /// already lets a `Proven` id skip the `Fallback`-only ReFS live-
    /// collision downgrade regardless of this check -- see `FileIdentity::
    /// compare`'s doc).
    ///
    /// Fails closed: a query failure, a truncated or unrecognized name, or
    /// any name other than exactly [`REUSE_SAFE_FILESYSTEM_NAME`] all
    /// answer `false`, the same answer an as-yet-unknown filesystem gets.
    /// [`query_raw_handle`] downgrades the object id to [`super::
    /// WindowsObjectId::Fallback`] whenever this returns `false`, even if
    /// the 128-bit `FileIdInfo` query itself succeeded.
    ///
    /// The filesystem name is read fresh from `handle` on every call --
    /// see this function's own doc for why a cache keyed on
    /// `volume_serial_number` could not be trusted valid for the mount
    /// `handle` actually names.
    fn reuse_safe_filesystem(handle: *mut c_void) -> bool {
        // Every out-parameter below is documented optional; only the file
        // system name is requested. Comfortably larger than any real
        // filesystem name Windows reports (`NTFS`, `ReFS`, `FAT32`,
        // `exFAT`, ...) -- MS-FSCC's own maximum is `MAX_PATH+1`, but
        // nothing this crate cares about is anywhere near that long, and a
        // name that did not fit would fail the call and answer `false`
        // regardless.
        let mut name_buffer = [0u16; 32];
        // SAFETY: `handle` is a valid, open file handle for the duration
        // of the call. Every pointer parameter left null is documented
        // optional by `GetVolumeInformationByHandleW`; `name_buffer` is a
        // valid out-parameter of exactly `name_buffer.len()` `WCHAR`s.
        let ok = unsafe {
            GetVolumeInformationByHandleW(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                name_buffer.as_mut_ptr(),
                name_buffer.len() as u32,
            )
        };
        ok != 0 && {
            let end = name_buffer.iter().position(|&c| c == 0).unwrap_or(name_buffer.len());
            String::from_utf16_lossy(&name_buffer[..end]) == REUSE_SAFE_FILESYSTEM_NAME
        }
    }

    fn query_raw_handle(handle: *mut c_void) -> io::Result<IdentityFields> {
        let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` is a valid, open file handle for the duration
        // of the call; `info` is a valid out-parameter matching
        // `GetFileInformationByHandle`'s expected layout and size.
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let fallback_volume_serial_number = u64::from(info.volume_serial_number);
        let fallback_file_index =
            (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low);
        let number_of_links = info.number_of_links;

        // The proven 128-bit id is a strictly-better-when-available upgrade
        // over the fields just read, not a required one: a failure here
        // (missing OS support, or a filesystem that does not implement the
        // class) falls back to what `GetFileInformationByHandle` already
        // gave us above, rather than failing this whole observation -- see
        // `ObjectIdFields`'s doc.
        let mut file_id_info: FileIdInfo = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` is the same valid, open file handle as above;
        // `file_id_info` is a valid out-parameter matching `FILE_ID_INFO`'s
        // layout and size for the `FileIdInfo` information class.
        let ex_ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FILE_ID_INFO_CLASS,
                (&mut file_id_info as *mut FileIdInfo).cast::<c_void>(),
                std::mem::size_of::<FileIdInfo>() as u32,
            )
        };
        // [MS-FSCC] documents two sentinel values a *successful*
        // `GetFileInformationByHandleEx(FileIdInfo)` call can still return
        // in `FileId`, neither of which is an identifier at all:
        // all-zero ("For file systems that do not support a 128-bit file
        // ID, this field MUST be set to 0") and all-ones ("For files for
        // which a unique 128-bit file ID cannot be established, this field
        // MUST be set to 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"). Both are
        // documented "MUST be ignored" -- i.e. not proof of anything, let
        // alone proof two objects are distinct or the same. Treating either
        // as `Proven` would let two unrelated objects on a filesystem that
        // doesn't support 128-bit ids (both all-zero) or that couldn't
        // establish one (both all-ones) compare as the same object. Fall
        // back to the `BY_HANDLE_FILE_INFORMATION` fields already read
        // above, exactly as if the `FileIdInfo` call itself had failed.
        //
        // A well-formed, non-sentinel `FileId` is still not enough on its
        // own to classify as `Proven`: that variant is a promise this
        // crate can compare a match on it without any corroborating
        // discriminator (see `WindowsObjectId::Proven`'s doc), and that
        // promise is confirmed only for a filesystem `reuse_safe_
        // filesystem` recognizes -- currently NTFS. A `FileId` from any
        // other filesystem (including ReFS, whose 128-bit id this crate
        // cannot yet confirm the same claim for) is real and well-formed,
        // but is recorded as `Fallback` here rather than `Proven`,
        // downgrading it to the same corroborated-match treatment a
        // `Fallback` id already gets -- strictly more conservative than
        // trusting it outright, and the same fail-closed default this
        // module applies everywhere else an assumption cannot be checked.
        let object_id = if ex_ok != 0
            && !super::windows_file_id_is_sentinel(file_id_info.file_id)
            && reuse_safe_filesystem(handle)
        {
            ObjectIdFields::Proven {
                volume_serial_number: file_id_info.volume_serial_number,
                file_id: file_id_info.file_id,
            }
        } else {
            ObjectIdFields::Fallback {
                volume_serial_number: fallback_volume_serial_number,
                file_index: fallback_file_index,
            }
        };

        // Best-effort, on the same already-open handle those two calls
        // above already paid for: a third `GetFileInformationByHandleEx`
        // class, `FileBasicInfo`, for `ChangeTime` alone. Its failure
        // (unsupported filesystem, or any other reason) degrades to
        // `None` rather than failing this observation -- see `change_time`'s
        // own doc on why.
        let mut basic_info: FileBasicInfo = unsafe { std::mem::zeroed() };
        // SAFETY: `handle` is the same valid, open file handle as above;
        // `basic_info` is a valid out-parameter matching `FILE_BASIC_INFO`'s
        // layout and size for the `FileBasicInfo` information class.
        let basic_ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FILE_BASIC_INFO_CLASS,
                (&mut basic_info as *mut FileBasicInfo).cast::<c_void>(),
                std::mem::size_of::<FileBasicInfo>() as u32,
            )
        };
        let change_time = change_time_from_basic_info(basic_ok != 0, basic_info.change_time);

        Ok(IdentityFields { object_id, number_of_links, change_time, usn: file_usn(handle) })
    }

    /// The usable `ChangeTime`: `None` when the query failed OR answered `0`. A volume with no
    /// change time (FAT/FAT32: `FileBasicInfo` succeeds and returns `0`) is as unreadable as a
    /// failed query: a zero would otherwise read as a real, "strict" sample that is
    /// bit-identical to the stat-only one, and a 2 s write-time granularity hides an ordinary
    /// same-size save. A genuine `ChangeTime` of 0 (1601-01-01) does not occur on a live file.
    pub(super) fn change_time_from_basic_info(query_ok: bool, raw: i64) -> Option<i64> {
        (query_ok && raw != 0).then_some(raw)
    }

    /// The USN of the file behind `handle`; see [`IdentityFields::usn`].
    fn file_usn(handle: *mut c_void) -> Result<Option<i64>, u32> {
        const FSCTL_READ_FILE_USN_DATA: u32 = 0x0009_00EB;
        crate::usn::read_usn(|out| {
            // READ_FILE_USN_DATA: accept record versions 2 and 3.
            let request: [u16; 2] = [2, 3];
            let mut returned = 0u32;
            // SAFETY: `handle` is a valid, open file handle; the buffers outlive the call and
            // their sizes are passed alongside.
            let ok = unsafe {
                DeviceIoControl(
                    handle,
                    FSCTL_READ_FILE_USN_DATA,
                    request.as_ptr().cast(),
                    std::mem::size_of_val(&request) as u32,
                    out.as_mut_ptr().cast(),
                    out.len() as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: a plain thread-local read.
                return Err(unsafe { GetLastError() });
            }
            Ok(returned as usize)
        })
    }

    /// Queries identity fields from an already-open handle. Preferred
    /// whenever a handle is available, for the same reason `FileIdentity::
    /// observe_handle` is preferred over `observe_path`: it cannot race a
    /// rename or replacement of the path between the syscall and the
    /// caller reading the result.
    pub(super) fn query_handle(file: &File) -> io::Result<IdentityFields> {
        query_raw_handle(file.as_raw_handle())
    }

    /// Queries identity fields from a path, opening a handle to exactly
    /// the object named there without following a terminal symlink
    /// (`FILE_FLAG_OPEN_REPARSE_POINT`) and without requesting content
    /// access (`dwDesiredAccess == 0`, a metadata-only open) — matching
    /// this crate's directory-relative, never-follow discipline elsewhere.
    /// `FILE_FLAG_BACKUP_SEMANTICS` is required for `CreateFileW` to open
    /// a directory at all.
    pub(super) fn query_path(path: &Path) -> io::Result<IdentityFields> {
        let path = crate::long_path::for_win32(path);
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // SAFETY: `wide` is a valid NUL-terminated UTF-16 string kept
        // alive for the duration of the call; the remaining pointer
        // arguments are null, which this metadata-only usage requires
        // neither of.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let result = query_raw_handle(handle);
        // SAFETY: `handle` was just returned by a successful `CreateFileW`
        // and is not used again after this call.
        unsafe {
            CloseHandle(handle);
        }
        result
    }
}

/// Whether a `FILE_ID_INFO::FileId` value is one of [MS-FSCC]'s two
/// documented sentinels rather than an actual identifier: all-zero ("the
/// file system does not support a 128-bit file ID") or all-ones ("a unique
/// 128-bit file ID could not be established"). See [`win_identity::
/// query_raw_handle`] for where this gates `ObjectIdFields::Proven` versus
/// `Fallback`.
///
/// Deliberately not `#[cfg(windows)]`: the sentinel values are a documented
/// Win32 contract, not FFI, so this stays a plain, host-independent
/// function that the test suite can exercise on every platform even though
/// the FFI call that produces a real `FileId` only runs on Windows.
// Unused on a non-Windows, non-test build: the only non-test caller is
// `win_identity`, which is `#[cfg(windows)]`.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn windows_file_id_is_sentinel(file_id: [u8; 16]) -> bool {
    file_id == [0u8; 16] || file_id == [0xffu8; 16]
}

fn u8_repr(kind: ObjectKind) -> u8 {
    match kind {
        ObjectKind::RegularFile => 0,
        ObjectKind::Directory => 1,
        ObjectKind::Symlink => 2,
        ObjectKind::Fifo => 3,
        ObjectKind::Socket => 4,
        ObjectKind::BlockDevice => 5,
        ObjectKind::CharDevice => 6,
        ObjectKind::ReparsePoint => 7,
        ObjectKind::Other => 8,
    }
}

/// Whether an object of this kind, with this link count, may be replaced at
/// all by the transaction engine's atomic-swap primitives.
///
/// Pure classification: this function does not perform or schedule any
/// filesystem operation, it only answers "would replacing this object be
/// safe to attempt".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplacementEligibility {
    Eligible,
    Blocked(BlockedObjectReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockedObjectReason {
    /// More than one directory entry names this object. The engine has no
    /// hardlink-topology model yet, so replacing one alias would silently
    /// desynchronize the others.
    HardlinkTopologyUnsupported,
    /// The link count could not be determined at all. Treated the same as
    /// a known-plural link count, not as "probably one": a platform or
    /// observation path that cannot answer "is this hardlinked" cannot
    /// prove it is *not*, and defaulting an unknown topology to safe is
    /// exactly the fail-open bug this classification exists to prevent.
    UnknownHardlinkTopology,
    Fifo,
    Socket,
    DeviceNode,
    UnsupportedReparsePoint,
    /// The object kind could not be resolved to any of the concrete kinds
    /// above; fidelity of a replacement cannot be guaranteed for a kind
    /// this module does not recognize.
    UnclassifiedObjectKind,
}

/// Fail-closed classification per the engine's hardlink-and-special-object
/// policy: `link_count > 1`, FIFOs, sockets, device nodes and unresolved
/// reparse points are all blocked before any replacement is attempted, never
/// followed or coerced into a regular-file replacement.
pub fn classify_replacement_eligibility(
    object_kind: ObjectKind,
    link_count: Option<u64>,
) -> ReplacementEligibility {
    // The "more than one directory entry names this object" hardlink-
    // topology concern applies only to regular files. A directory's own
    // `nlink` structurally counts `.` plus one `..` per immediate
    // subdirectory — a freshly created, otherwise-unremarkable EMPTY
    // directory already reports `nlink == 2` on every mainstream
    // filesystem (confirmed: APFS, and this is standard POSIX directory
    // bookkeeping, not filesystem-specific) — which is not "multiple
    // paths to the same directory" in the sense this check exists to
    // catch; true directory hardlinks are effectively disallowed by every
    // mainstream filesystem outside of `.`/`..` themselves. A symlink can
    // never be hardlinked at all (its own `nlink` is always 1). Gating on
    // raw `nlink` for those two kinds would block every directory and
    // every symlink unconditionally, which is not what this check is for.
    if object_kind == ObjectKind::RegularFile {
        match link_count {
            Some(count) if count > 1 => {
                return ReplacementEligibility::Blocked(
                    BlockedObjectReason::HardlinkTopologyUnsupported,
                );
            }
            Some(_) => {}
            // An unknown link count is blocked exactly like a known-plural
            // one — see `BlockedObjectReason::UnknownHardlinkTopology`. This
            // is the platform reporting reduced capability, not a reason to
            // assume the object is unlinked.
            None => {
                return ReplacementEligibility::Blocked(
                    BlockedObjectReason::UnknownHardlinkTopology,
                );
            }
        }
    }
    match object_kind {
        ObjectKind::RegularFile | ObjectKind::Directory | ObjectKind::Symlink => {
            ReplacementEligibility::Eligible
        }
        ObjectKind::Fifo => ReplacementEligibility::Blocked(BlockedObjectReason::Fifo),
        ObjectKind::Socket => ReplacementEligibility::Blocked(BlockedObjectReason::Socket),
        ObjectKind::BlockDevice | ObjectKind::CharDevice => {
            ReplacementEligibility::Blocked(BlockedObjectReason::DeviceNode)
        }
        ObjectKind::ReparsePoint => {
            ReplacementEligibility::Blocked(BlockedObjectReason::UnsupportedReparsePoint)
        }
        ObjectKind::Other => {
            ReplacementEligibility::Blocked(BlockedObjectReason::UnclassifiedObjectKind)
        }
    }
}

/// Size, mtime and (on Unix) ctime: the cheap stat-derived signature two
/// observations of one path are compared on to decide whether anything
/// touched it in between. Deliberately includes ctime, which a `chmod` or
/// `setxattr` bumps even though it leaves size, mtime and content alone.
pub type DiskRaceFingerprint = (u64, Option<SystemTime>, i64, i64);

/// Cheap "did anything else write to this path" fingerprint, sampled either
/// side of a read or a block fetch. `None` means the path does not exist;
/// comparing two samples answers "did this file change underneath us", never
/// "what does it contain".
///
/// This is the one definition every bracket shares: the peer session's
/// eager materialize, the daemon's hydration, local capture's
/// commit-time re-check, and eviction all compare samples taken here, so a
/// change to what the fingerprint covers changes every one of them together.
///
/// **What it can and cannot catch.** Length plus mtime is not a content hash,
/// and deliberately so: hashing would mean a full extra read of the target on
/// every eager materialize, on the hot path, to defend a narrow race. The
/// limits, checked rather than assumed:
///
/// - Under the DST harnesses this is exact. `dst_support::clock::HarnessClock::
///   next_mtime` is strictly monotonic (its own `next_mtime_is_strictly_
///   monotonic` test asserts it) and `fs_ops::write` stamps every local write
///   through it, so a racing write always moves the mtime — a same-length
///   overwrite can never slip past.
/// - In production the residual is a same-length write landing inside the
///   filesystem's mtime granularity. `ctime` closes most of that on unix: a
///   real write always advances it, and unlike mtime it cannot be back-dated
///   by ordinary means, so a same-length same-mtime overwrite still trips this.
///   What remains uncovered is a same-length write on a non-unix filesystem
///   whose mtime granularity is coarser than the write window.
///
/// Erring toward *over*-detection is the safe direction here: a false positive
/// costs one `RetryRequired` round trip, while a false negative silently
/// destroys a user's edit. That is also why `ctime` moving for a reason other
/// than a data write (a `chmod`, a rename into place) is deliberately treated
/// as "something touched this path, decline and re-resolve" rather than
/// filtered out.
pub fn disk_race_fingerprint(path: &Path) -> Option<DiskRaceFingerprint> {
    Some(disk_race_fingerprint_of_at(&std::fs::symlink_metadata(path).ok()?, path))
}

/// The fingerprint for a caller that holds the `lstat` AND the
/// path it came from. Identical on Unix. On Windows the std `Metadata` carries
/// no change time, so the path is asked for NTFS `ChangeTime` and the file's
/// USN. `ChangeTime` moves with every write but `FileBasicInfo` lets a writer
/// set it back (a rewrite can restore the write time and the change time
/// both); the USN only the volume's change journal moves, so it closes that
/// rewrite. When either cannot be read the fingerprint carries a value that
/// equals no other sample, so a comparison involving it never reports
/// "unchanged" (fail-closed: the cost is a re-capture, never a missed edit).
/// A volume without a change journal has no USN: the fingerprint is then as
/// strong as the change time alone. (The journal merges the records of
/// writes that a writer makes through one open handle, so a rewrite that is
/// still open when it is sampled can keep the USN; it is not a proof for
/// `in_place_rewrite_visible`, which stays as it was.)
pub fn disk_race_fingerprint_of_at(meta: &Metadata, path: &Path) -> DiskRaceFingerprint {
    #[cfg(not(windows))]
    {
        let _ = path;
        stat_fingerprint(meta)
    }
    #[cfg(windows)]
    {
        windows_fingerprint(meta, query_fingerprint_fields(path), true)
    }
}

/// [`disk_race_fingerprint_of_at`] for a baseline compared later by a retry loop (hydration):
/// where the change time or USN cannot be read it is the size and write time alone instead of a
/// value equal to no other sample, because "never equal" there would refuse every attempt on a
/// volume that cannot answer.
pub fn disk_race_fingerprint_of_at_or_stat(meta: &Metadata, path: &Path) -> DiskRaceFingerprint {
    #[cfg(not(windows))]
    {
        let _ = path;
        stat_fingerprint(meta)
    }
    #[cfg(windows)]
    {
        windows_fingerprint(meta, query_fingerprint_fields(path), false)
    }
}

/// [`disk_race_fingerprint_or_stat`] and, from the same single query, whether the sample is the
/// size and write time alone because the change time or USN could not be read (Windows). Such a
/// fingerprint cannot show a same-size rewrite with a restored mtime, so a caller that needs more
/// asks the bytes. Deriving both from one sample keeps the decision and the fingerprint from
/// disagreeing after a transient query failure. The flag is always `false` on Unix.
pub fn disk_race_fingerprint_or_stat_observed(path: &Path) -> Option<(DiskRaceFingerprint, bool)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    #[cfg(not(windows))]
    {
        let _ = path;
        Some((stat_fingerprint(&meta), false))
    }
    #[cfg(windows)]
    {
        let fields = query_fingerprint_fields(path).ok();
        let observed = fields
            .as_ref()
            .and_then(|fields| fields.change_time.zip(fields.usn.ok()))
            .map(|(change_time, usn)| (change_time, usn.unwrap_or(0)));
        let degraded = observed.is_none();
        Some((compose_fingerprint(stat_fingerprint(&meta), observed, false), degraded))
    }
}

#[cfg(all(windows, feature = "test-support"))]
thread_local! {
    static CHANGE_TIME_UNREADABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Until the guard drops, on this thread the path-based fingerprints behave as on a volume whose
/// change time and USN cannot be read (Windows only; elsewhere the fingerprint is the stat alone,
/// so this changes nothing).
#[cfg(feature = "test-support")]
pub fn change_time_unreadable_for_test() -> ChangeTimeUnreadableGuardForTest {
    #[cfg(windows)]
    CHANGE_TIME_UNREADABLE.with(|f| f.set(true));
    ChangeTimeUnreadableGuardForTest(())
}

#[cfg(all(windows, feature = "test-support"))]
thread_local! {
    static IDENTITY_QUERY_UNREADABLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Until the guard drops, on this thread `FileIdentity::observe_path` fails as on a volume whose
/// whole identity query errors (Windows only; a no-op elsewhere). Independent of
/// [`change_time_unreadable_for_test`].
#[cfg(feature = "test-support")]
pub fn identity_query_unreadable_for_test() -> IdentityQueryUnreadableGuardForTest {
    #[cfg(windows)]
    IDENTITY_QUERY_UNREADABLE.with(|f| f.set(true));
    IdentityQueryUnreadableGuardForTest(())
}

/// Restores the identity query on drop.
#[cfg(feature = "test-support")]
pub struct IdentityQueryUnreadableGuardForTest(());

#[cfg(feature = "test-support")]
impl Drop for IdentityQueryUnreadableGuardForTest {
    fn drop(&mut self) {
        #[cfg(windows)]
        IDENTITY_QUERY_UNREADABLE.with(|f| f.set(false));
    }
}

/// Restores the readable change time on drop.
#[cfg(feature = "test-support")]
pub struct ChangeTimeUnreadableGuardForTest(());

#[cfg(feature = "test-support")]
impl Drop for ChangeTimeUnreadableGuardForTest {
    fn drop(&mut self) {
        #[cfg(windows)]
        CHANGE_TIME_UNREADABLE.with(|f| f.set(false));
    }
}

#[cfg(windows)]
fn query_fingerprint_fields(path: &Path) -> io::Result<win_identity::IdentityFields> {
    #[cfg(feature = "test-support")]
    if CHANGE_TIME_UNREADABLE.with(|f| f.get()) {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    win_identity::query_path(path)
}

/// [`disk_race_fingerprint`] for a pre/post bracket that a retry loop compares (the eager
/// materialize's fetch and assemble windows, eviction's revalidation): the path's `lstat` through
/// [`disk_race_fingerprint_of_at_or_stat`], so where the change time or USN cannot be read both
/// samples are the size and write time alone and still compare equal for an untouched file. Only
/// for a bracket whose caller also verifies the bytes or the dirty journal; evidence that must
/// not miss an edit uses [`disk_race_fingerprint`].
pub fn disk_race_fingerprint_or_stat(path: &Path) -> Option<DiskRaceFingerprint> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    Some(disk_race_fingerprint_of_at_or_stat(&meta, path))
}

/// [`disk_race_fingerprint_of_at`] for a caller that holds the open file
/// `meta` came from (`file.metadata()`): the change time and USN are read
/// from that handle, so the sample describes the object the caller is
/// reading even when the path has since been swapped for another file. Where the change time or
/// USN cannot be read it is the size and write time alone (unlike [`disk_race_fingerprint_of_at`],
/// which then never compares equal): it brackets one read, where "never equal" would starve it.
pub fn disk_race_fingerprint_of_handle(meta: &Metadata, file: &File) -> DiskRaceFingerprint {
    #[cfg(not(windows))]
    {
        let _ = file;
        stat_fingerprint(meta)
    }
    #[cfg(windows)]
    {
        windows_fingerprint(meta, win_identity::query_handle(file), false)
    }
}

/// The Windows fingerprint of an `lstat` plus whatever the change-time/USN query answered.
#[cfg(windows)]
fn windows_fingerprint(
    meta: &Metadata,
    fields: io::Result<win_identity::IdentityFields>,
    fail_closed: bool,
) -> DiskRaceFingerprint {
    let fields = fields.ok();
    // A volume without a change journal has no USN (`None`): the fingerprint is then as strong as
    // the change time alone.
    let observed = fields
        .as_ref()
        .and_then(|fields| fields.change_time.zip(fields.usn.ok()))
        .map(|(change_time, usn)| (change_time, usn.unwrap_or(0)));
    compose_fingerprint(stat_fingerprint(meta), observed, fail_closed)
}

/// Adds the change time and USN to a stat fingerprint. When they could not be read
/// (`observed == None`): with `fail_closed` the result carries a value that equals no other
/// sample (a comparison never reports "unchanged": the cost is a re-capture, never a missed
/// edit), otherwise it is the stat fingerprint unchanged.
#[cfg_attr(not(windows), allow(dead_code))]
fn compose_fingerprint(
    stat: DiskRaceFingerprint,
    observed: Option<(i64, i64)>,
    fail_closed: bool,
) -> DiskRaceFingerprint {
    use std::sync::atomic::{AtomicI64, Ordering};
    static UNOBSERVABLE: AtomicI64 = AtomicI64::new(0);
    let (len, mtime, _, _) = stat;
    match observed {
        Some((change_time, usn)) => (len, mtime, change_time, usn),
        None if fail_closed => (len, mtime, i64::MIN, UNOBSERVABLE.fetch_add(1, Ordering::Relaxed)),
        None => stat,
    }
}

/// Size, mtime and (on Unix) ctime of an `lstat`: what every fingerprint starts from. Private on
/// purpose: on Windows these alone cannot see a same-size rewrite inside one timestamp tick, so
/// every caller goes through [`disk_race_fingerprint_of_at`] or
/// [`disk_race_fingerprint_of_handle`].
fn stat_fingerprint(meta: &Metadata) -> DiskRaceFingerprint {
    #[cfg(unix)]
    let (ctime, ctime_nsec) = {
        use std::os::unix::fs::MetadataExt as _;
        (meta.ctime(), meta.ctime_nsec())
    };
    #[cfg(not(unix))]
    let (ctime, ctime_nsec) = (0i64, 0i64);
    (meta.len(), meta.modified().ok(), ctime, ctime_nsec)
}

/// True when a filesystem `Metadata`'s mtime equals the mtime an index row
/// recorded (`FileRecord::mtime_unix_nanos`, stored as nanoseconds since the
/// Unix epoch). Deriving this in one place keeps the "unchanged file" verdict
/// identical no matter which path reaches it: local capture's per-file fast
/// path and its bulk startup/offline reconcile scan MUST agree, or a same-size edit one path treats as a no-op another
/// would silently keep at the stale version.
pub fn metadata_mtime_matches(metadata: &Metadata, indexed_mtime_unix_nanos: i64) -> bool {
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        == Some(indexed_mtime_unix_nanos)
}

/// Whether `a` and `b` currently name one filesystem object (a hard link counts as the
/// same object), neither followed if it is a symlink. This is identity, not change detection:
/// size and times say nothing about it (two siblings written together share both). Any failure
/// to observe either path answers `false`.
pub fn same_live_object(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        match (std::fs::symlink_metadata(a), std::fs::symlink_metadata(b)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        match (FileIdentity::observe_path(a), FileIdentity::observe_path(b)) {
            (Ok(a), Ok(b)) => {
                a.volume_identity == b.volume_identity
                    && a.object_id == b.object_id
                    && a.object_kind == b.object_kind
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
