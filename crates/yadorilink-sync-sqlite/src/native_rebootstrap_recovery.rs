//! The rebootstrap recovery area: a directory outside every synced root that
//! holds what a rebootstrap must not lose, in a form that can be read back with
//! nothing else (no database, no sync root, no peer).
//!
//! Layout, one directory per rebootstrap, `<root>/<group>/<recovery id>/`:
//!
//! ```text
//! target.bundle            the exact target bundle
//! target.bundle.sha256     its digest
//! target.verification.json the local verification record
//! verification-material/  what the verification was answered from
//! versions/<hex hash>      the bytes of one file version
//! deltas/<hex hash>.bin    the exact signed bytes of one own delta
//! manifest.json            canonical, versioned, self-hashed; written last
//! ```
//!
//! The area holds the user's file contents, so it is local security state:
//!
//! * every directory is created `0700` and every file `0600` (a protected
//!   current-user-only DACL on Windows), with the mode given at creation;
//! * nothing is reached through a symlink or reparse point, and a root that is
//!   one is refused;
//! * a file is written under a reserved Stage name beside its final name,
//!   fsynced, and published by a durable move (`durable_dir`), so a crash
//!   leaves either no file or a whole one; a directory is the same with an
//!   empty Stage directory, so every name that leads to the area is published
//!   before the manifest that makes the area count;
//! * every name in the area is a fixed name or a hex digest. A manifest path is
//!   a validated relative sync-root path used as data only: it is never joined
//!   to a directory here, so a hostile manifest cannot name anything outside the
//!   area;
//! * a version file is a byte copy, never a link into the sync root.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use yadorilink_fs_platform::durable_dir::{
    DiscardOutcome, DurableNamespace, NoLedger, NsError, Replace,
};

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, VersionHash};
use yadorilink_replica_domain::native_state::DeltaHash;
use yadorilink_replica_domain::signed_delta::NativeDelta;

/// Why the recovery area could not be used.
#[derive(Debug)]
pub enum AreaError {
    /// The location cannot hold the area: a link, not private, inside or around
    /// a synced root, or a name that is not content-addressed.
    Unavailable(String),
    /// A file operation failed.
    Io(io::Error),
    /// What is on disk contradicts the manifest, or the manifest contradicts
    /// itself.
    Inconsistent(String),
}

impl std::fmt::Display for AreaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(f, "recovery area unavailable: {detail}"),
            Self::Io(error) => write!(f, "recovery area i/o: {error}"),
            Self::Inconsistent(detail) => write!(f, "recovery area inconsistent: {detail}"),
        }
    }
}

impl std::error::Error for AreaError {}

impl From<io::Error> for AreaError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

const MANIFEST_FILE: &str = "manifest.json";
const TARGET_BUNDLE: &str = "target.bundle";
const TARGET_DIGEST: &str = "target.bundle.sha256";
const VERIFICATION_RECORD: &str = "target.verification.json";
const MATERIAL_DIR: &str = "verification-material";
const MATERIAL_FILE: &str = "policy-answers.json";
const VERSIONS_DIR: &str = "versions";
const DELTAS_DIR: &str = "deltas";

pub(crate) const MANIFEST_FORMAT_VERSION: u64 = 3;

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The size of the one fixed buffer every whole-file read or copy on the rebootstrap path uses:
/// file contents are streamed through it, never held whole.
pub const IO_CHUNK: usize = 64 * 1024;

#[cfg(test)]
thread_local! {
    /// Forces a tiny buffer so tests cross chunk boundaries with small files.
    pub(crate) static IO_CHUNK_OVERRIDE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

/// The buffer size in effect: [`IO_CHUNK`], or a test's forced one.
pub(crate) fn io_chunk() -> usize {
    #[cfg(test)]
    if let Some(chunk) = IO_CHUNK_OVERRIDE.with(|c| c.get()) {
        return chunk;
    }
    IO_CHUNK
}

/// Reads `reader` to its end through one `chunk`-sized buffer, passing each filled piece to
/// `each`. Returns the number of bytes read.
pub(crate) fn for_each_chunk(
    reader: &mut dyn Read,
    chunk: usize,
    mut each: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut buf = vec![0u8; chunk.max(1)];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        each(&buf[..n])?;
        total += n as u64;
    }
}

/// The SHA-256 and length of everything `reader` yields, streamed through a `chunk` buffer.
pub(crate) fn sha256_stream(reader: &mut dyn Read, chunk: usize) -> io::Result<([u8; 32], u64)> {
    let mut hasher = Sha256::new();
    let len = for_each_chunk(reader, chunk, |piece| {
        hasher.update(piece);
        Ok(())
    })?;
    Ok((hasher.finalize().into(), len))
}

/// Copies `reader` to `out` through one fixed buffer, succeeding only if it yielded exactly
/// `size` bytes with digest `sha256`. A source that runs past `size` is stopped at once, so a
/// lying source cannot fill the disk; the caller publishes nothing unless this succeeds.
pub(crate) fn copy_checked(
    reader: &mut dyn Read,
    out: &mut dyn Write,
    size: u64,
    sha256: &[u8; 32],
) -> Result<(), AreaError> {
    let mut hasher = Sha256::new();
    let mut seen = 0u64;
    for_each_chunk(reader, io_chunk(), |piece| {
        seen += piece.len() as u64;
        if seen > size {
            return Err(io::Error::other("the content is longer than it was observed to be"));
        }
        hasher.update(piece);
        out.write_all(piece)
    })?;
    let digest: [u8; 32] = hasher.finalize().into();
    if seen != size || digest != *sha256 {
        return Err(inconsistent("the content is not what was observed"));
    }
    Ok(())
}

/// `hash` as lowercase hex, the only spelling a name in the area may have.
fn is_hex32(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn unavailable(detail: impl Into<String>) -> AreaError {
    AreaError::Unavailable(detail.into())
}

fn inconsistent(detail: impl Into<String>) -> AreaError {
    AreaError::Inconsistent(detail.into())
}

// --- the file layer ---------------------------------------------------------------------

fn is_link(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

/// The metadata of `path` itself (a link is not followed), or `None` if absent.
/// A link or reparse point is refused.
pub(crate) fn lstat_no_link(path: &Path) -> Result<Option<fs::Metadata>, AreaError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if is_link(&meta) => {
            Err(unavailable(format!("{} is a symlink or reparse point", path.display())))
        }
        Ok(meta) => Ok(Some(meta)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn require_private(meta: &fs::Metadata, want: u32, what: &Path) -> Result<(), AreaError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mode = meta.permissions().mode() & 0o777;
    if mode != want {
        return Err(unavailable(format!("{} is mode {mode:o}, want {want:o}", what.display())));
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    require_owner(meta.uid(), unsafe { libc::geteuid() }, what)
}

/// An area owned by another user is theirs to change, whatever its mode says now.
#[cfg(unix)]
pub(crate) fn require_owner(owner: u32, user: u32, what: &Path) -> Result<(), AreaError> {
    if owner != user {
        return Err(unavailable(format!(
            "{} is owned by user {owner}, not by user {user}",
            what.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_private(_meta: &fs::Metadata, _want: u32, _what: &Path) -> Result<(), AreaError> {
    Ok(())
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        fs::DirBuilder::new().create(path)?;
        windows_acl::restrict_to_current_user(path, true)
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::DirBuilder::new().create(path)
    }
}

/// Makes `path` a private directory that is not a link: created `0700` if it
/// is absent (an empty Stage directory with that mode, published by a durable
/// move), otherwise checked to be exactly that.
pub(crate) fn ensure_private_dir_durably(path: &Path) -> Result<(), AreaError> {
    if lstat_no_link(path)?.is_none() {
        let ns = namespace_for(path)?;
        let stage = ns.stage_path(path).map_err(ns_error)?;
        create_private_dir(&stage)?;
        match ns.publish(&stage, path, Replace::No, &NoLedger) {
            Ok(()) | Err(NsError::AlreadyExists) => {}
            Err(error) => return Err(ns_error(error)),
        }
    }
    let meta = lstat_no_link(path)?.ok_or_else(|| unavailable("the directory vanished"))?;
    if !meta.is_dir() {
        return Err(unavailable(format!("{} is not a directory", path.display())));
    }
    require_private(&meta, 0o700, path)
}

fn open_no_follow(options: &mut fs::OpenOptions) -> &mut fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
    }
    #[cfg(not(any(unix, windows)))]
    options
}

fn create_private_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    open_no_follow(&mut options).open(path)
}

/// What the tests inject and count: a write that lands damaged, and the number of
/// fsyncs asked for.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::{Cell, RefCell};
    use std::path::Path;

    thread_local! {
        /// A written path containing this text lands with its first byte changed.
        pub static CORRUPT_PATH_CONTAINING: RefCell<Option<String>> =
            const { RefCell::new(None) };
        /// Files whose fsync succeeded.
        pub static FILE_SYNCS: Cell<usize> = const { Cell::new(0) };
        /// An fsync of a file under a path containing this text fails once.
        pub static FAIL_FILE_SYNC_CONTAINING: RefCell<Option<String>> =
            const { RefCell::new(None) };
        /// Stands in for a platform without directory-entry durability.
        pub static NO_DIRECTORY_DURABILITY: Cell<bool> = const { Cell::new(false) };
    }

    /// A writer that changes the first byte it is given (or writes one, for an empty file) when
    /// the path is one the test asked to corrupt.
    pub struct Corrupting<'a> {
        file: &'a mut std::fs::File,
        hit: bool,
        wrote: bool,
    }

    impl<'a> Corrupting<'a> {
        pub fn new(path: &Path, file: &'a mut std::fs::File) -> Self {
            Self { file, hit: corrupts(path), wrote: false }
        }

        pub fn finish(self) -> std::io::Result<()> {
            use std::io::Write;
            if self.hit && !self.wrote {
                self.file.write_all(&[1])?;
            }
            Ok(())
        }
    }

    impl std::io::Write for Corrupting<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.hit && !self.wrote && !buf.is_empty() {
                self.wrote = true;
                let mut first = buf.to_vec();
                first[0] ^= 0xff;
                self.file.write_all(&first)?;
                return Ok(buf.len());
            }
            self.wrote |= !buf.is_empty();
            self.file.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.file.flush()
        }
    }

    fn corrupts(path: &Path) -> bool {
        CORRUPT_PATH_CONTAINING.with(|text| {
            text.borrow()
                .as_deref()
                .is_some_and(|t| path.to_string_lossy().replace('\\', "/").contains(t))
        })
    }
}

fn fsync_file(file: &fs::File, path: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        let fail = test_hooks::FAIL_FILE_SYNC_CONTAINING.with(|text| {
            let hit = text
                .borrow()
                .as_deref()
                .is_some_and(|t| path.to_string_lossy().replace('\\', "/").contains(t));
            if hit {
                *text.borrow_mut() = None;
            }
            hit
        });
        if fail {
            return Err(io::Error::other("injected fsync failure"));
        }
    }
    #[cfg(not(test))]
    let _ = path;
    yadorilink_fs_platform::flush::sync_file(file)?;
    #[cfg(test)]
    test_hooks::FILE_SYNCS.with(|n| n.set(n.get() + 1));
    Ok(())
}

/// Whether this platform can make a directory-entry change (a create or a
/// rename) durable at all, which the preserved barrier depends on: Unix
/// always, Windows once its gate is open.
pub const fn platform_supports_directory_durability() -> bool {
    yadorilink_fs_platform::durable_dir::platform_offers_durable_namespace()
}

/// [`platform_supports_directory_durability`] for the recovery root `root`, with
/// a test seam to stand in for a platform that lacks it. The volume holding
/// `root` must be one `DurableNamespace::open` trusts: on Windows only a volume
/// on which the shapes were seen to work, whatever its file system is called.
pub(crate) fn directory_durability_available(root: &Path) -> bool {
    // Under test the rebootstrap logic is exercised on every platform, so
    // Windows runs it too; whether a platform really offers durable namespace
    // changes is asserted separately by `only_unix_and_windows_claim_directory_durability`
    // and the refusal by `a_platform_without_directory_durability_starts_nothing`.
    #[cfg(test)]
    {
        let _ = root;
        !test_hooks::NO_DIRECTORY_DURABILITY.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        existing_ancestor(root).is_some_and(|dir| match DurableNamespace::open(dir) {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(%error, ?dir, "directory durability is not available here");
                false
            }
        })
    }
}

/// The nearest ancestor of `path` (itself included) that exists: the root may
/// not exist yet, and its volume is that of that ancestor.
#[cfg(not(test))]
fn existing_ancestor(path: &Path) -> Option<&Path> {
    path.ancestors().find(|dir| dir.is_dir())
}

/// The handle for durable namespace changes under `path`, whose nearest
/// existing ancestor decides the volume.
fn namespace_for(path: &Path) -> Result<DurableNamespace, AreaError> {
    #[cfg(test)]
    {
        let _ = path;
        Ok(DurableNamespace::unchecked_for_tests())
    }
    #[cfg(not(test))]
    {
        let dir = existing_ancestor(path).ok_or_else(|| unavailable("no existing ancestor"))?;
        DurableNamespace::open(dir)
            .map_err(|e| unavailable(format!("durable namespace changes are unavailable: {e}")))
    }
}

fn ns_error(error: NsError) -> AreaError {
    match error {
        NsError::Io(error) => AreaError::Io(error),
        other => AreaError::Io(io::Error::other(other.to_string())),
    }
}

fn record_file_name(version: &VersionHash) -> String {
    format!("{}.record", hex::encode(version.0))
}

/// `dir` is a real directory, not a link: a write or read below it would
/// otherwise follow the link out of the area.
pub(crate) fn require_real_dir(dir: &Path) -> Result<(), AreaError> {
    match lstat_no_link(dir)? {
        Some(meta) if meta.is_dir() => Ok(()),
        _ => Err(unavailable(format!("{} is not a directory of the area", dir.display()))),
    }
}

/// Writes `bytes` as `dir/name`: a Stage file beside it, fsynced, then published
/// by a durable move that replaces any earlier file of that name.
pub(crate) fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), AreaError> {
    write_durable_with(dir, name, |file| Ok(file.write_all(bytes)?))
}

/// [`write_durable`] for content produced piece by piece: `fill` writes the file's bytes, and
/// nothing is published unless it succeeds.
pub(crate) fn write_durable_with(
    dir: &Path,
    name: &str,
    fill: impl FnOnce(&mut dyn Write) -> Result<(), AreaError>,
) -> Result<(), AreaError> {
    require_real_dir(dir)?;
    let ns = namespace_for(dir)?;
    let target = dir.join(name);
    let stage = ns.stage_path(&target).map_err(ns_error)?;
    let staged = (|| -> Result<(), AreaError> {
        let mut file = create_private_file(&stage)?;
        #[cfg(test)]
        {
            let mut writer = test_hooks::Corrupting::new(&target, &mut file);
            fill(&mut writer)?;
            writer.finish()?;
        }
        #[cfg(not(test))]
        fill(&mut file)?;
        fsync_file(&file, &stage)?;
        drop(file);
        #[cfg(windows)]
        windows_acl::restrict_to_current_user(&stage, false)?;
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = fs::remove_file(&stage);
        return Err(error);
    }
    ns.publish(&stage, &target, Replace::Yes, &NoLedger).map_err(ns_error)
}

/// A regular file under the area opened for reading, never through a link.
pub(crate) fn open_regular(path: &Path) -> Result<fs::File, AreaError> {
    if let Some(parent) = path.parent() {
        require_real_dir(parent)?;
    }
    let meta = lstat_no_link(path)?
        .ok_or_else(|| inconsistent(format!("{} is missing", path.display())))?;
    if !meta.is_file() {
        return Err(inconsistent(format!("{} is not a regular file", path.display())));
    }
    require_private(&meta, 0o600, path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    Ok(open_no_follow(&mut options).open(path)?)
}

/// The bytes of a regular file under the area, never through a link.
pub(crate) fn read_regular(path: &Path) -> Result<Vec<u8>, AreaError> {
    let mut file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The SHA-256 and length of a regular file under the area, read through one fixed buffer.
pub(crate) fn sha256_regular(path: &Path) -> Result<([u8; 32], u64), AreaError> {
    let mut file = open_regular(path)?;
    Ok(sha256_stream(&mut file, io_chunk())?)
}

// --- the area ---------------------------------------------------------------------------

/// The directory name of `group` under the recovery root: a digest, so no group
/// id is ever a path component.
pub(crate) fn group_dir_name(group: &FolderGroupId) -> String {
    hex::encode(sha256(group.as_str().as_bytes()))
}

fn is_recovery_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A fresh recovery id.
pub fn new_recovery_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// The directory of one rebootstrap's recovery area.
#[derive(Debug, Clone)]
pub struct RecoveryArea {
    dir: PathBuf,
}

impl RecoveryArea {
    /// Creates the (empty) area for `recovery_id`, refusing a location that is a
    /// link, that is not private, or that is inside or around any of
    /// `sync_roots`.
    pub fn create(
        recovery_root: &Path,
        group: &FolderGroupId,
        recovery_id: &str,
        sync_roots: &[PathBuf],
    ) -> Result<Self, AreaError> {
        if !is_recovery_id(recovery_id) {
            return Err(unavailable("a recovery id is 32 lowercase hex digits"));
        }
        if let Some(parent) = recovery_root.parent() {
            create_dirs_durably(parent)?;
        }
        ensure_private_dir_durably(recovery_root)?;
        refuse_synced_location(recovery_root, sync_roots)?;
        let group_dir = recovery_root.join(group_dir_name(group));
        ensure_private_dir_durably(&group_dir)?;
        let dir = group_dir.join(recovery_id);
        if lstat_no_link(&dir)?.is_some() {
            return Err(unavailable("a recovery id is never reused"));
        }
        ensure_private_dir_durably(&dir)?;
        for sub in [VERSIONS_DIR, DELTAS_DIR, MATERIAL_DIR] {
            ensure_private_dir_durably(&dir.join(sub))?;
        }
        Ok(Self { dir })
    }

    /// The existing area of `recovery_id`.
    pub fn open_existing(
        recovery_root: &Path,
        group: &FolderGroupId,
        recovery_id: &str,
    ) -> Result<Self, AreaError> {
        if !is_recovery_id(recovery_id) {
            return Err(unavailable("a recovery id is 32 lowercase hex digits"));
        }
        lstat_no_link(recovery_root)?;
        let dir = recovery_root.join(group_dir_name(group)).join(recovery_id);
        let meta = lstat_no_link(&dir)?.ok_or_else(|| inconsistent("the area is missing"))?;
        if !meta.is_dir() {
            return Err(unavailable("the area is not a directory"));
        }
        Ok(Self { dir })
    }

    /// The area opened from a directory path, as a reader that has only that
    /// directory (the root, the group and the id are not known to it).
    pub fn open_dir(dir: &Path) -> Result<Self, AreaError> {
        let meta = lstat_no_link(dir)?.ok_or_else(|| inconsistent("the area is missing"))?;
        if !meta.is_dir() {
            return Err(unavailable("the area is not a directory"));
        }
        Ok(Self { dir: dir.to_path_buf() })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Removes the area. Idempotent; nothing is followed out of it. The area
    /// leaves its parent by a durable move (see [`remove_private_tree`]).
    pub fn remove(
        recovery_root: &Path,
        group: &FolderGroupId,
        recovery_id: &str,
    ) -> Result<(), AreaError> {
        if !is_recovery_id(recovery_id) {
            return Err(unavailable("a recovery id is 32 lowercase hex digits"));
        }
        let dir = recovery_root.join(group_dir_name(group)).join(recovery_id);
        match lstat_no_link(&dir)? {
            None => Ok(()),
            Some(meta) if meta.is_dir() => remove_private_tree(&dir),
            Some(_) => Err(unavailable("the area is not a directory")),
        }
    }

    /// The recovery ids under `group` that are not complete (no manifest),
    /// i.e. what a crash before the barrier left.
    pub fn incomplete_ids(
        recovery_root: &Path,
        group: &FolderGroupId,
    ) -> Result<Vec<String>, AreaError> {
        let group_dir = recovery_root.join(group_dir_name(group));
        let Some(meta) = lstat_no_link(&group_dir)? else { return Ok(Vec::new()) };
        if !meta.is_dir() {
            return Err(unavailable("the group directory is not a directory"));
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(&group_dir)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if is_recovery_id(&name) && lstat_no_link(&entry.path().join(MANIFEST_FILE))?.is_none()
            {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    /// Whether a manifest exists at all, readable or not: the mark of an area that
    /// reached the barrier, which must never be discarded because it is hard to read.
    pub fn has_manifest(&self) -> bool {
        matches!(lstat_no_link(&self.dir.join(MANIFEST_FILE)), Ok(Some(_)) | Err(_))
    }

    // The fixed names.

    pub fn write_target_bundle(&self, bytes: &[u8]) -> Result<[u8; 32], AreaError> {
        write_durable(&self.dir, TARGET_BUNDLE, bytes)?;
        let digest = sha256(bytes);
        write_durable(&self.dir, TARGET_DIGEST, hex::encode(digest).as_bytes())?;
        Ok(digest)
    }

    pub fn read_target_bundle(&self) -> Result<Vec<u8>, AreaError> {
        read_regular(&self.dir.join(TARGET_BUNDLE))
    }

    pub fn read_target_digest(&self) -> Result<[u8; 32], AreaError> {
        let text = read_regular(&self.dir.join(TARGET_DIGEST))?;
        let text = String::from_utf8(text).map_err(|_| inconsistent("the digest is not text"))?;
        parse_hex32(text.trim())
    }

    pub fn write_verification_record(&self, bytes: &[u8]) -> Result<(), AreaError> {
        write_durable(&self.dir, VERIFICATION_RECORD, bytes)
    }

    pub fn read_verification_record(&self) -> Result<Vec<u8>, AreaError> {
        read_regular(&self.dir.join(VERIFICATION_RECORD))
    }

    pub fn write_material(&self, bytes: &[u8]) -> Result<(), AreaError> {
        write_durable(&self.dir.join(MATERIAL_DIR), MATERIAL_FILE, bytes)
    }

    pub fn read_material(&self) -> Result<Vec<u8>, AreaError> {
        read_regular(&self.dir.join(MATERIAL_DIR).join(MATERIAL_FILE))
    }

    pub fn write_manifest(&self, manifest: &Manifest) -> Result<[u8; 32], AreaError> {
        let bytes = manifest.to_bytes();
        write_durable(&self.dir, MANIFEST_FILE, &bytes)?;
        Ok(sha256(&bytes))
    }

    pub fn read_manifest_bytes(&self) -> Result<Vec<u8>, AreaError> {
        read_regular(&self.dir.join(MANIFEST_FILE))
    }

    // The content-addressed names.

    pub fn write_version(&self, version: &VersionHash, bytes: &[u8]) -> Result<(), AreaError> {
        write_durable(&self.dir.join(VERSIONS_DIR), &hex::encode(version.0), bytes)
    }

    pub fn read_version(&self, version: &VersionHash) -> Result<Vec<u8>, AreaError> {
        read_regular(&self.dir.join(VERSIONS_DIR).join(hex::encode(version.0)))
    }

    /// Stores `version`'s bytes from `reader`, which must yield exactly `size` bytes with digest
    /// `sha256`: streamed through one fixed buffer, and published only if it did.
    pub fn write_version_from(
        &self,
        version: &VersionHash,
        reader: &mut dyn Read,
        size: u64,
        sha256: &[u8; 32],
    ) -> Result<(), AreaError> {
        write_durable_with(&self.dir.join(VERSIONS_DIR), &hex::encode(version.0), |out| {
            copy_checked(reader, out, size, sha256)
        })
    }

    /// The stored copy of `version` opened for streaming; check it with [`Self::version_matches`]
    /// first when its digest matters.
    pub fn open_version(&self, version: &VersionHash) -> Result<fs::File, AreaError> {
        open_regular(&self.dir.join(VERSIONS_DIR).join(hex::encode(version.0)))
    }

    /// Whether the stored copy of `version` hashes to `sha256` and is `size` bytes, read through
    /// one fixed buffer: the copy is never held whole.
    pub fn version_matches(
        &self,
        version: &VersionHash,
        sha256: &[u8; 32],
        size: u64,
    ) -> Result<bool, AreaError> {
        let (digest, len) =
            sha256_regular(&self.dir.join(VERSIONS_DIR).join(hex::encode(version.0)))?;
        Ok(digest == *sha256 && len == size)
    }

    /// Stores the canonical encoding of a version's whole record (block list and
    /// extended attributes included), so the version can be rebuilt and its hash
    /// recomputed from the area alone.
    pub fn write_record(&self, record: &FileVersion) -> Result<(), AreaError> {
        write_durable(
            &self.dir.join(VERSIONS_DIR),
            &record_file_name(&record.version_hash),
            &record.canonical_encoding(),
        )
    }

    /// The record stored for `version`, decoded and verified to hash to it.
    pub fn read_record(&self, version: &VersionHash) -> Result<FileVersion, AreaError> {
        let bytes = read_regular(&self.dir.join(VERSIONS_DIR).join(record_file_name(version)))?;
        let record = FileVersion::from_canonical_encoding(&bytes)
            .map_err(|e| inconsistent(format!("a version record does not decode: {e:?}")))?;
        if record.version_hash != *version || record.verify_hash().is_err() {
            return Err(inconsistent("a version record does not hash to its version"));
        }
        Ok(record)
    }

    pub fn write_delta(&self, delta: &DeltaHash, wire: &[u8]) -> Result<(), AreaError> {
        write_durable(&self.dir.join(DELTAS_DIR), &format!("{}.bin", hex::encode(delta.0)), wire)
    }

    pub fn read_delta(&self, delta: &DeltaHash) -> Result<Vec<u8>, AreaError> {
        read_regular(&self.dir.join(DELTAS_DIR).join(format!("{}.bin", hex::encode(delta.0))))
    }
}

/// Creates `path` and any missing ancestors, each as its own published
/// directory. The first ancestor that exists is trusted as it is.
pub(crate) fn create_dirs_durably(path: &Path) -> Result<(), AreaError> {
    let ns = namespace_for(path)?;
    match ns.create_dir_all(path, &NoLedger) {
        Ok(()) => Ok(()),
        Err(error) => Err(ns_error(error)),
    }
}

/// Removes the private directory `dir` and everything below it, never
/// recursively in one step: everything below is unlinked (a subdirectory only
/// once it is empty), and `dir` itself, once empty, leaves its parent by a
/// durable move to a Discard name. Its removal is what is committed; nothing
/// below it is relied on after that.
pub(crate) fn remove_private_tree(dir: &Path) -> Result<(), AreaError> {
    empty_directory(dir)?;
    let ns = namespace_for(dir)?;
    let discarded = ns.discard(dir, &NoLedger).map_err(ns_error)?;
    match discarded.finish(&ns, &NoLedger) {
        DiscardOutcome::Removed => Ok(()),
        other => Err(unavailable(format!("{} was not removed: {other:?}", dir.display()))),
    }
}

/// Unlinks everything below `dir`, a link as a link and a subdirectory only
/// once it is empty.
fn empty_directory(dir: &Path) -> Result<(), AreaError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            empty_directory(&path)?;
            fs::remove_dir(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    Ok(())
}

/// The recovery root must not be inside, or an ancestor of, a synced root.
pub(crate) fn refuse_synced_location(
    recovery_root: &Path,
    sync_roots: &[PathBuf],
) -> Result<(), AreaError> {
    let recovery = fs::canonicalize(recovery_root)?;
    for root in sync_roots {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        if recovery.starts_with(&root) || root.starts_with(&recovery) {
            return Err(unavailable(format!(
                "the recovery root {} is inside or around the synced root {}",
                recovery.display(),
                root.display()
            )));
        }
    }
    Ok(())
}

// --- the manifest -------------------------------------------------------------------------

/// A manifest path is relative sync-root data: the same validation as any
/// path a delta may carry, plus the forms only a filesystem would honour.
pub fn validate_manifest_path(path: &str) -> Result<(), AreaError> {
    if let Some(reason) = crate::native_bootstrap::projection_name_refusal(path) {
        return Err(inconsistent(format!("manifest path {path:?}: {reason}")));
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(inconsistent(format!("manifest path {path:?} has a drive prefix")));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRemoval {
    pub author: AuthorId,
    pub seq: u64,
    pub header: DeltaHash,
}

/// One op of an own delta that the target does not cover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestItem {
    pub delta: DeltaHash,
    pub op_index: usize,
    pub path: String,
    pub put_version: Option<VersionHash>,
    pub removes: Vec<ManifestRemoval>,
    /// The planning-time classification of the unit this op belongs to: a label
    /// that decides what is copied and what is quarantined, never an
    /// authorization.
    pub reassertable: bool,
    pub unit: usize,
}

/// The recursive operation an old delta was one part of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestRecursive {
    pub operation_id: [u8; 16],
    pub part_index: u32,
    pub part_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestDelta {
    pub hash: DeltaHash,
    pub author: AuthorId,
    pub seq: u64,
    pub wire_size: u64,
    pub wire_sha256: [u8; 32],
    pub unit: usize,
    pub recursive: Option<ManifestRecursive>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestUnit {
    pub deltas: Vec<DeltaHash>,
    pub reassertable: bool,
    pub reason: Option<String>,
}

/// One file version's bytes and metadata, as a copy handed back to the user
/// needs them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestVersion {
    pub version: VersionHash,
    pub record_kind: String,
    pub has_bytes: bool,
    pub size: u64,
    pub sha256: [u8; 32],
    pub mtime_unix_nanos: i64,
    pub unix_mode: Option<u32>,
    pub symlink_target: Option<Vec<u8>>,
}

/// One head this replica holds that the target does not contain, and the recovery
/// item that keeps it. The barrier is not crossed until every entry is a durable item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRemoteOnly {
    pub item_id: String,
    pub kind: String,
    pub path: String,
    pub author: AuthorId,
    pub seq: u64,
    pub provenance: DeltaHash,
    pub version: VersionHash,
    /// `complete`, `unavailable` or `record_unavailable`.
    pub content: String,
    pub size: u64,
    pub content_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub group_id: String,
    pub recovery_id: String,
    pub created_at: i64,
    pub target_checkpoint_hash: [u8; 32],
    pub target_bundle_sha256: [u8; 32],
    pub target_bundle_size: u64,
    pub verification_record_sha256: [u8; 32],
    pub material_sha256: [u8; 32],
    pub old_authors: Vec<AuthorId>,
    pub delta_order: Vec<DeltaHash>,
    pub deltas: Vec<ManifestDelta>,
    pub units: Vec<ManifestUnit>,
    pub versions: Vec<ManifestVersion>,
    pub items: Vec<ManifestItem>,
    pub remote_only: Vec<ManifestRemoteOnly>,
}

fn hex_value(bytes: &[u8]) -> Value {
    Value::String(hex::encode(bytes))
}

fn author_value(author: &AuthorId) -> Value {
    let mut map = Map::new();
    map.insert("device".into(), Value::String(author.device.0.clone()));
    map.insert("incarnation".into(), hex_value(&author.incarnation.0));
    Value::Object(map)
}

/// JSON with every object's keys in sorted order, no insignificant whitespace.
pub(crate) fn canonical_json_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push(b'{');
            for (index, (key, value)) in sorted.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(Value::String(key.clone()).to_string().as_bytes());
                out.push(b':');
                canonical_json_into(value, out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                canonical_json_into(item, out);
            }
            out.push(b']');
        }
        other => out.extend_from_slice(other.to_string().as_bytes()),
    }
}

/// `value` as canonical bytes, with its own `manifest_hash` member.
fn seal_object(mut map: Map<String, Value>) -> Vec<u8> {
    map.remove("manifest_hash");
    let mut body = Vec::new();
    canonical_json_into(&Value::Object(map.clone()), &mut body);
    map.insert("manifest_hash".into(), hex_value(&sha256(&body)));
    let mut out = Vec::new();
    canonical_json_into(&Value::Object(map), &mut out);
    out
}

impl Manifest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert("format_version".into(), Value::from(MANIFEST_FORMAT_VERSION));
        map.insert("group_id".into(), Value::String(self.group_id.clone()));
        map.insert("recovery_id".into(), Value::String(self.recovery_id.clone()));
        map.insert("created_at".into(), Value::from(self.created_at));
        map.insert("target_checkpoint_hash".into(), hex_value(&self.target_checkpoint_hash));
        map.insert("target_bundle_sha256".into(), hex_value(&self.target_bundle_sha256));
        map.insert("target_bundle_size".into(), Value::from(self.target_bundle_size));
        map.insert(
            "verification_record_sha256".into(),
            hex_value(&self.verification_record_sha256),
        );
        map.insert("material_sha256".into(), hex_value(&self.material_sha256));
        map.insert(
            "old_authors".into(),
            Value::Array(self.old_authors.iter().map(author_value).collect()),
        );
        map.insert(
            "delta_order".into(),
            Value::Array(self.delta_order.iter().map(|hash| hex_value(&hash.0)).collect()),
        );
        map.insert("deltas".into(), Value::Array(self.deltas.iter().map(delta_value).collect()));
        map.insert("units".into(), Value::Array(self.units.iter().map(unit_value).collect()));
        map.insert(
            "versions".into(),
            Value::Array(self.versions.iter().map(version_value).collect()),
        );
        map.insert("items".into(), Value::Array(self.items.iter().map(item_value).collect()));
        map.insert(
            "remote_only".into(),
            Value::Array(self.remote_only.iter().map(remote_only_value).collect()),
        );
        seal_object(map)
    }

    /// Parses and fully validates a manifest: format, self-hash, every hash and
    /// name spelling, every path, and the references between its parts.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AreaError> {
        let Value::Object(mut map) =
            serde_json::from_slice(bytes).map_err(|e| inconsistent(format!("manifest: {e}")))?
        else {
            return Err(inconsistent("the manifest is not an object"));
        };
        let claimed = parse_hex32(get_str(&map, "manifest_hash")?)?;
        map.remove("manifest_hash");
        let mut body = Vec::new();
        canonical_json_into(&Value::Object(map.clone()), &mut body);
        if sha256(&body) != claimed {
            return Err(inconsistent("the manifest does not match its own hash"));
        }
        if get_u64(&map, "format_version")? != MANIFEST_FORMAT_VERSION {
            return Err(inconsistent("unsupported manifest version"));
        }
        let manifest = Self {
            group_id: get_str(&map, "group_id")?.to_owned(),
            recovery_id: get_str(&map, "recovery_id")?.to_owned(),
            created_at: get_i64(&map, "created_at")?,
            target_checkpoint_hash: parse_hex32(get_str(&map, "target_checkpoint_hash")?)?,
            target_bundle_sha256: parse_hex32(get_str(&map, "target_bundle_sha256")?)?,
            target_bundle_size: get_u64(&map, "target_bundle_size")?,
            verification_record_sha256: parse_hex32(get_str(&map, "verification_record_sha256")?)?,
            material_sha256: parse_hex32(get_str(&map, "material_sha256")?)?,
            old_authors: get_arr(&map, "old_authors")?
                .iter()
                .map(parse_author)
                .collect::<Result<_, _>>()?,
            delta_order: get_arr(&map, "delta_order")?
                .iter()
                .map(|v| parse_hash_value(v).map(DeltaHash))
                .collect::<Result<_, _>>()?,
            deltas: get_arr(&map, "deltas")?.iter().map(parse_delta).collect::<Result<_, _>>()?,
            units: get_arr(&map, "units")?.iter().map(parse_unit).collect::<Result<_, _>>()?,
            versions: get_arr(&map, "versions")?
                .iter()
                .map(parse_version)
                .collect::<Result<_, _>>()?,
            items: get_arr(&map, "items")?.iter().map(parse_item).collect::<Result<_, _>>()?,
            remote_only: get_arr(&map, "remote_only")?
                .iter()
                .map(parse_remote_only)
                .collect::<Result<_, _>>()?,
        };
        manifest.check_references()?;
        Ok(manifest)
    }

    fn check_references(&self) -> Result<(), AreaError> {
        if !is_recovery_id(&self.recovery_id) {
            return Err(inconsistent("the recovery id is not a recovery id"));
        }
        let listed: BTreeSet<DeltaHash> = self.deltas.iter().map(|d| d.hash).collect();
        let ordered: BTreeSet<DeltaHash> = self.delta_order.iter().copied().collect();
        if listed != ordered
            || listed.len() != self.deltas.len()
            || ordered.len() != self.delta_order.len()
        {
            return Err(inconsistent("the delta order does not list the deltas exactly once"));
        }
        for delta in &self.deltas {
            if delta.unit >= self.units.len() {
                return Err(inconsistent("a delta names a unit that does not exist"));
            }
        }
        for unit in &self.units {
            if unit.deltas.iter().any(|hash| !listed.contains(hash)) {
                return Err(inconsistent("a unit names a delta that is not listed"));
            }
        }
        let versions: BTreeSet<VersionHash> = self.versions.iter().map(|v| v.version).collect();
        for item in &self.items {
            validate_manifest_path(&item.path)?;
            if !listed.contains(&item.delta) || item.unit >= self.units.len() {
                return Err(inconsistent("an item names a delta or unit that does not exist"));
            }
            if item.put_version.is_some_and(|version| !versions.contains(&version)) {
                return Err(inconsistent("an item names a version that is not listed"));
            }
        }
        let mut seen = BTreeSet::new();
        for entry in &self.remote_only {
            validate_manifest_path(&entry.path)?;
            if !is_hex32(&entry.item_id) || !seen.insert(&entry.item_id) {
                return Err(inconsistent("a remote-only item id is malformed or repeated"));
            }
        }
        Ok(())
    }
}

fn remote_only_value(entry: &ManifestRemoteOnly) -> Value {
    let mut map = Map::new();
    map.insert("item_id".into(), Value::String(entry.item_id.clone()));
    map.insert("kind".into(), Value::String(entry.kind.clone()));
    map.insert("path".into(), Value::String(entry.path.clone()));
    map.insert("author".into(), author_value(&entry.author));
    map.insert("seq".into(), Value::from(entry.seq));
    map.insert("provenance".into(), hex_value(&entry.provenance.0));
    map.insert("version".into(), hex_value(&entry.version.0));
    map.insert("content".into(), Value::String(entry.content.clone()));
    map.insert("size".into(), Value::from(entry.size));
    map.insert("content_sha256".into(), hex_value(&entry.content_sha256));
    Value::Object(map)
}

fn parse_remote_only(value: &Value) -> Result<ManifestRemoteOnly, AreaError> {
    let map = as_obj(value)?;
    Ok(ManifestRemoteOnly {
        item_id: get_str(map, "item_id")?.to_owned(),
        kind: get_str(map, "kind")?.to_owned(),
        path: get_str(map, "path")?.to_owned(),
        author: parse_author(get(map, "author")?)?,
        seq: get_u64(map, "seq")?,
        provenance: DeltaHash(parse_hex32(get_str(map, "provenance")?)?),
        version: VersionHash(parse_hex32(get_str(map, "version")?)?),
        content: get_str(map, "content")?.to_owned(),
        size: get_u64(map, "size")?,
        content_sha256: parse_hex32(get_str(map, "content_sha256")?)?,
    })
}

fn delta_value(delta: &ManifestDelta) -> Value {
    let mut map = Map::new();
    map.insert("hash".into(), hex_value(&delta.hash.0));
    map.insert("author".into(), author_value(&delta.author));
    map.insert("seq".into(), Value::from(delta.seq));
    map.insert("wire_size".into(), Value::from(delta.wire_size));
    map.insert("wire_sha256".into(), hex_value(&delta.wire_sha256));
    map.insert("unit".into(), Value::from(delta.unit));
    map.insert(
        "recursive".into(),
        delta.recursive.map_or(Value::Null, |part| {
            let mut object = Map::new();
            object.insert("operation_id".into(), hex_value(&part.operation_id));
            object.insert("part_index".into(), Value::from(part.part_index));
            object.insert("part_count".into(), Value::from(part.part_count));
            Value::Object(object)
        }),
    );
    Value::Object(map)
}

fn unit_value(unit: &ManifestUnit) -> Value {
    let mut map = Map::new();
    map.insert(
        "deltas".into(),
        Value::Array(unit.deltas.iter().map(|h| hex_value(&h.0)).collect()),
    );
    map.insert("reassertable".into(), Value::Bool(unit.reassertable));
    map.insert("reason".into(), unit.reason.clone().map_or(Value::Null, Value::String));
    Value::Object(map)
}

fn version_value(version: &ManifestVersion) -> Value {
    let mut map = Map::new();
    map.insert("version".into(), hex_value(&version.version.0));
    map.insert("record_kind".into(), Value::String(version.record_kind.clone()));
    map.insert("has_bytes".into(), Value::Bool(version.has_bytes));
    map.insert("size".into(), Value::from(version.size));
    map.insert("sha256".into(), hex_value(&version.sha256));
    map.insert("mtime_unix_nanos".into(), Value::from(version.mtime_unix_nanos));
    map.insert("unix_mode".into(), version.unix_mode.map_or(Value::Null, Value::from));
    map.insert(
        "symlink_target".into(),
        version.symlink_target.as_deref().map_or(Value::Null, hex_value),
    );
    Value::Object(map)
}

fn item_value(item: &ManifestItem) -> Value {
    let mut map = Map::new();
    map.insert("delta".into(), hex_value(&item.delta.0));
    map.insert("op_index".into(), Value::from(item.op_index));
    map.insert("path".into(), Value::String(item.path.clone()));
    map.insert("put_version".into(), item.put_version.map_or(Value::Null, |v| hex_value(&v.0)));
    map.insert(
        "removes".into(),
        Value::Array(
            item.removes
                .iter()
                .map(|removal| {
                    let mut r = Map::new();
                    r.insert("author".into(), author_value(&removal.author));
                    r.insert("seq".into(), Value::from(removal.seq));
                    r.insert("header".into(), hex_value(&removal.header.0));
                    Value::Object(r)
                })
                .collect(),
        ),
    );
    map.insert("reassertable".into(), Value::Bool(item.reassertable));
    map.insert("unit".into(), Value::from(item.unit));
    Value::Object(map)
}

// Parsing helpers.

pub(crate) fn parse_hex32(text: &str) -> Result<[u8; 32], AreaError> {
    if !is_hex32(text) {
        return Err(inconsistent(format!("{text:?} is not a 32-byte lowercase hex digest")));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).map_err(|e| inconsistent(e.to_string()))?;
    Ok(out)
}

fn parse_hash_value(value: &Value) -> Result<[u8; 32], AreaError> {
    parse_hex32(value.as_str().ok_or_else(|| inconsistent("a hash is not text"))?)
}

fn get<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value, AreaError> {
    map.get(key).ok_or_else(|| inconsistent(format!("the manifest has no `{key}`")))
}

fn get_str<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, AreaError> {
    get(map, key)?.as_str().ok_or_else(|| inconsistent(format!("`{key}` is not text")))
}

fn get_u64(map: &Map<String, Value>, key: &str) -> Result<u64, AreaError> {
    get(map, key)?.as_u64().ok_or_else(|| inconsistent(format!("`{key}` is not a number")))
}

fn get_i64(map: &Map<String, Value>, key: &str) -> Result<i64, AreaError> {
    get(map, key)?.as_i64().ok_or_else(|| inconsistent(format!("`{key}` is not a number")))
}

fn get_bool(map: &Map<String, Value>, key: &str) -> Result<bool, AreaError> {
    get(map, key)?.as_bool().ok_or_else(|| inconsistent(format!("`{key}` is not a boolean")))
}

fn get_arr<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, AreaError> {
    get(map, key)?.as_array().ok_or_else(|| inconsistent(format!("`{key}` is not a list")))
}

fn as_obj(value: &Value) -> Result<&Map<String, Value>, AreaError> {
    value.as_object().ok_or_else(|| inconsistent("an entry is not an object"))
}

fn parse_author(value: &Value) -> Result<AuthorId, AreaError> {
    let map = as_obj(value)?;
    let incarnation = get_str(map, "incarnation")?;
    let mut bytes = [0u8; 16];
    if incarnation.len() != 32
        || hex::decode_to_slice(incarnation, &mut bytes).is_err()
        || incarnation.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(inconsistent("an incarnation is 16 bytes of lowercase hex"));
    }
    Ok(AuthorId {
        device: DeviceId(get_str(map, "device")?.to_owned()),
        incarnation: IncarnationId(bytes),
    })
}

fn parse_delta(value: &Value) -> Result<ManifestDelta, AreaError> {
    let map = as_obj(value)?;
    Ok(ManifestDelta {
        hash: DeltaHash(parse_hex32(get_str(map, "hash")?)?),
        author: parse_author(get(map, "author")?)?,
        seq: get_u64(map, "seq")?,
        wire_size: get_u64(map, "wire_size")?,
        wire_sha256: parse_hex32(get_str(map, "wire_sha256")?)?,
        unit: get_u64(map, "unit")? as usize,
        recursive: match get(map, "recursive")? {
            Value::Null => None,
            other => {
                let part = as_obj(other)?;
                let id = hex::decode(get_str(part, "operation_id")?)
                    .ok()
                    .and_then(|bytes| <[u8; 16]>::try_from(bytes.as_slice()).ok())
                    .ok_or_else(|| inconsistent("an operation id is not 16 bytes of hex"))?;
                Some(ManifestRecursive {
                    operation_id: id,
                    part_index: get_u64(part, "part_index")? as u32,
                    part_count: get_u64(part, "part_count")? as u32,
                })
            }
        },
    })
}

fn parse_unit(value: &Value) -> Result<ManifestUnit, AreaError> {
    let map = as_obj(value)?;
    Ok(ManifestUnit {
        deltas: get_arr(map, "deltas")?
            .iter()
            .map(|v| parse_hash_value(v).map(DeltaHash))
            .collect::<Result<_, _>>()?,
        reassertable: get_bool(map, "reassertable")?,
        reason: get(map, "reason")?.as_str().map(str::to_owned),
    })
}

fn parse_version(value: &Value) -> Result<ManifestVersion, AreaError> {
    let map = as_obj(value)?;
    let symlink_target = match get(map, "symlink_target")? {
        Value::Null => None,
        Value::String(text) => {
            Some(hex::decode(text).map_err(|_| inconsistent("a symlink target is not hex"))?)
        }
        _ => return Err(inconsistent("a symlink target is not text")),
    };
    Ok(ManifestVersion {
        version: VersionHash(parse_hex32(get_str(map, "version")?)?),
        record_kind: get_str(map, "record_kind")?.to_owned(),
        has_bytes: get_bool(map, "has_bytes")?,
        size: get_u64(map, "size")?,
        sha256: parse_hex32(get_str(map, "sha256")?)?,
        mtime_unix_nanos: get_i64(map, "mtime_unix_nanos")?,
        unix_mode: get(map, "unix_mode")?.as_u64().map(|mode| mode as u32),
        symlink_target,
    })
}

fn parse_item(value: &Value) -> Result<ManifestItem, AreaError> {
    let map = as_obj(value)?;
    let put_version = match get(map, "put_version")? {
        Value::Null => None,
        other => Some(VersionHash(parse_hash_value(other)?)),
    };
    let removes = get_arr(map, "removes")?
        .iter()
        .map(|v| {
            let r = as_obj(v)?;
            Ok(ManifestRemoval {
                author: parse_author(get(r, "author")?)?,
                seq: get_u64(r, "seq")?,
                header: DeltaHash(parse_hex32(get_str(r, "header")?)?),
            })
        })
        .collect::<Result<_, AreaError>>()?;
    Ok(ManifestItem {
        delta: DeltaHash(parse_hex32(get_str(map, "delta")?)?),
        op_index: get_u64(map, "op_index")? as usize,
        path: get_str(map, "path")?.to_owned(),
        put_version,
        removes,
        reassertable: get_bool(map, "reassertable")?,
        unit: get_u64(map, "unit")? as usize,
    })
}

// --- reading everything back ------------------------------------------------------------

/// Everything a protected intent consists of, read from the area alone.
#[derive(Debug)]
pub struct RecoveredIntent {
    pub manifest: Manifest,
    /// The own deltas the target does not cover, in the manifest's replay order,
    /// each with its exact signed bytes.
    pub deltas: Vec<(NativeDelta, Vec<u8>)>,
    /// The full record of every version the manifest lists, each verified to hash
    /// to its version.
    pub records: BTreeMap<VersionHash, FileVersion>,
    pub target_bundle: Vec<u8>,
}

impl RecoveryArea {
    /// Reads and verifies the whole area: the manifest against itself, every file
    /// against the manifest, the bundle against its recorded digest, every delta
    /// against its hash. It reads nothing but this directory.
    pub fn read_intent(&self) -> Result<RecoveredIntent, AreaError> {
        let manifest = Manifest::from_bytes(&self.read_manifest_bytes()?)?;
        let target_bundle = self.read_target_bundle()?;
        let digest = sha256(&target_bundle);
        if digest != manifest.target_bundle_sha256
            || digest != self.read_target_digest()?
            || target_bundle.len() as u64 != manifest.target_bundle_size
        {
            return Err(inconsistent("the target bundle does not match its recorded digest"));
        }
        if sha256(&self.read_verification_record()?) != manifest.verification_record_sha256
            || sha256(&self.read_material()?) != manifest.material_sha256
        {
            return Err(inconsistent("the verification record does not match the manifest"));
        }
        let mut deltas = Vec::new();
        for hash in &manifest.delta_order {
            let entry = manifest
                .deltas
                .iter()
                .find(|d| d.hash == *hash)
                .ok_or_else(|| inconsistent("an ordered delta is not listed"))?;
            let wire = self.read_delta(hash)?;
            let decoded = NativeDelta::from_wire_bytes(&wire)
                .map_err(|e| inconsistent(format!("a delta does not decode: {e:?}")))?;
            if sha256(&wire) != entry.wire_sha256
                || wire.len() as u64 != entry.wire_size
                || decoded.delta_hash() != *hash
                || decoded.author != entry.author
                || decoded.seq != AuthorSeq(entry.seq)
            {
                return Err(inconsistent("a delta does not match the manifest"));
            }
            deltas.push((decoded, wire));
        }
        let mut records = BTreeMap::new();
        for version in &manifest.versions {
            let record = self.read_record(&version.version)?;
            let meta = &record.meta;
            if version.record_kind != meta.record_kind.as_db_str()
                || version.mtime_unix_nanos != meta.mtime_unix_nanos
                || version.unix_mode != meta.unix_mode
                || version.symlink_target != meta.symlink_target
            {
                return Err(inconsistent("a version record does not match the manifest"));
            }
            records.insert(version.version, record);
        }
        // Each copy is checked against the manifest by streaming; none is held.
        for version in manifest.versions.iter().filter(|v| v.has_bytes) {
            if !self.version_matches(&version.version, &version.sha256, version.size)? {
                return Err(inconsistent("a version does not match the manifest"));
            }
        }
        Ok(RecoveredIntent { manifest, deltas, records, target_bundle })
    }
}

#[cfg(windows)]
mod windows_acl {
    //! A protected DACL that grants the current user alone, set by path. The
    //! directory form is inherited by what is created under it. Not exercised by
    //! the test suite on the platforms that build it today.
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub(super) fn restrict_to_current_user(path: &Path, directory: bool) -> std::io::Result<()> {
        let sid = current_user_sid_string()?;
        let inherit = if directory { "OICI" } else { "" };
        let sddl: Vec<u16> = format!("D:P(A;{inherit};FA;;;{sid})")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: `sddl` is NUL terminated and outlives the call; the returned
        // descriptor is freed with `LocalFree` below.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let result = apply(path, descriptor);
        // SAFETY: `descriptor` was allocated by the call above.
        unsafe { LocalFree(descriptor) };
        result
    }

    fn apply(path: &Path, descriptor: *mut c_void) -> std::io::Result<()> {
        let (mut present, mut defaulted) = (0i32, 0i32);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: `descriptor` is a valid security descriptor.
        let ok = unsafe {
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut wide: Vec<u16> = yadorilink_fs_platform::long_path::for_win32(path)
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is NUL terminated; `dacl` points into `descriptor`.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn current_user_sid_string() -> std::io::Result<String> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the out pointer is valid.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `token` is a valid token handle until closed below.
        let sid = unsafe { sid_string(token) };
        // SAFETY: `token` was opened above.
        unsafe { CloseHandle(token) };
        sid
    }

    /// The token's user SID (not its owner: for an elevated process the owner is
    /// the Administrators group).
    unsafe fn sid_string(token: HANDLE) -> std::io::Result<String> {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; len as usize];
        if GetTokenInformation(token, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_text: *mut u16 = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_text) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut length = 0;
        while *sid_text.add(length) != 0 {
            length += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid_text, length));
        LocalFree(sid_text.cast());
        Ok(text)
    }
}
