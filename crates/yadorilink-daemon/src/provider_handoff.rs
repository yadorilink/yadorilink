//! The daemon's one fixed temp root for handing provider items to the OS.
//!
//! A file written by the daemon into the app-group container is taken over by the OS (it is moved
//! or cloned and the original path disappears); a path outside the container is not accepted, and
//! a file still being written when it is returned is snapshotted at that moment. So the root has
//! two directories and one rule:
//!
//! * `staging/` is where bytes are assembled. Nothing here is ever named to anyone.
//! * `handoff/` receives a file only by RENAME from `staging/`, after it was fully written,
//!   verified and fsynced, and the directory is fsynced before the name is returned. A partially
//!   written file is therefore never reachable from `handoff/`.
//!
//! The root comes from the daemon's own configuration; no request ever names a directory. A file
//! still in `handoff/` a fixed time after its response went out was not taken over (the OS
//! abandoned the call) and is deleted; at startup everything in `staging/` and every stale entry
//! of `handoff/` is deleted too.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use yadorilink_local_storage::StorageError;

/// How long an unconsumed handoff file may live after its response was sent.
pub(crate) const HANDOFF_LIFETIME: Duration = Duration::from_secs(60);

/// A finished upload nothing used for this long is abandoned (a long safety age: the bytes of a
/// refused or undecided operation must survive a delayed retry or a restart).
pub(crate) const INGEST_FINISHED_LIFETIME: Duration = Duration::from_secs(7 * 24 * 3600);
/// A partial upload untouched for this long is abandoned.
pub(crate) const INGEST_PARTIAL_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// The longest request id (in bytes) a handoff name is built from.
const MAX_REQUEST_ID_BYTES: usize = 64;

/// Delivered handoff file names per (root, item).
type DeliveredFiles = std::collections::HashMap<(String, [u8; 16]), Vec<String>>;

/// Creates the temp root and its directories (`staging`, `handoff`, `ingest`, `domains`) with mode
/// 0700 and checks the layout: each is a real directory (never a symlink), owned by this user, and
/// not group or world accessible (a looser mode is tightened). Anything else refuses the root: a
/// swapped or shared directory would let another party read or replace user bytes.
pub(crate) fn prepare_layout(root: &Path) -> std::io::Result<()> {
    for dir in [
        root.to_path_buf(),
        root.join("staging"),
        root.join("handoff"),
        root.join("ingest"),
        root.join("domains"),
    ] {
        match std::fs::symlink_metadata(&dir) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
                }
                #[cfg(windows)]
                crate::windows_fs_security::create_private_dir_all(&dir)?;
                #[cfg(not(any(unix, windows)))]
                std::fs::create_dir_all(&dir)?;
            }
            Err(error) => return Err(error),
        }
        let metadata = std::fs::symlink_metadata(&dir)?;
        let invalid = |what: &str| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{} {what}", dir.display()),
            )
        };
        if metadata.file_type().is_symlink() {
            return Err(invalid("is a symlink"));
        }
        if !metadata.is_dir() {
            return Err(invalid("is not a directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // SAFETY: `geteuid` has no preconditions and cannot fail.
            if metadata.uid() != unsafe { libc::geteuid() } {
                return Err(invalid("is owned by another user"));
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        #[cfg(windows)]
        {
            // The same two rules as above: a directory owned by another account is refused, and
            // anything looser than "the current user only" is tightened to a protected DACL.
            use crate::windows_fs_security::{
                directory_owned_by_current_user, restrict_to_current_user,
            };
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid("is a reparse point"));
            }
            if !directory_owned_by_current_user(&dir)? {
                return Err(invalid("is owned by another user"));
            }
            restrict_to_current_user(&dir)?;
        }
    }
    Ok(())
}

/// Where the daemon's handoff root comes from. A fresh install has no app group container until the
/// host app has run, so the root is resolved LAZILY: every access that finds no root asks the
/// resolver again and opens it the first time it answers, with no daemon restart.
type OnOpen = Arc<dyn Fn(&Arc<HandoffRoot>) + Send + Sync>;

pub(crate) struct HandoffSlot {
    root: std::sync::Mutex<Option<Arc<HandoffRoot>>>,
    /// The app group container the host app told the daemon about (adopted once).
    adopted: std::sync::Mutex<Option<PathBuf>>,
    resolver: Option<Arc<dyn Fn() -> Option<PathBuf> + Send + Sync>>,
    on_open: Option<OnOpen>,
}

impl HandoffSlot {
    /// A slot with no root and nothing to resolve (a daemon without provider roots).
    pub(crate) fn empty() -> Arc<Self> {
        Arc::new(Self {
            root: Default::default(),
            adopted: Default::default(),
            resolver: None,
            on_open: None,
        })
    }

    /// A slot that already holds `root`.
    #[cfg(test)]
    pub(crate) fn fixed(root: Option<Arc<HandoffRoot>>) -> Arc<Self> {
        Arc::new(Self {
            root: std::sync::Mutex::new(root),
            adopted: Default::default(),
            resolver: None,
            on_open: None,
        })
    }

    /// A slot that opens the root the first time `resolver` names a usable directory, then runs
    /// `on_open` once (the journal-aware sweep and the report of retained uploads).
    pub(crate) fn lazy(
        resolver: Arc<dyn Fn() -> Option<PathBuf> + Send + Sync>,
        on_open: OnOpen,
    ) -> Arc<Self> {
        Arc::new(Self {
            root: Default::default(),
            adopted: Default::default(),
            resolver: Some(resolver),
            on_open: Some(on_open),
        })
    }

    /// Adopts the app group container the host app reported, ONCE (the first valid one stays): it must
    /// be an absolute path naming a real directory owned by this user. Returns whether `container` is
    /// the adopted one.
    pub(crate) fn adopt(&self, container: &str) -> bool {
        let mut adopted = self.adopted.lock().unwrap_or_else(|p| p.into_inner());
        let path = PathBuf::from(container);
        if let Some(existing) = adopted.as_ref() {
            return *existing == path;
        }
        if !path.is_absolute() || !is_own_directory(&path) {
            tracing::warn!(
                "ignoring an app group container that is not an absolute directory of this user"
            );
            return false;
        }
        *adopted = Some(path);
        true
    }

    /// The root, opening it now when it can be.
    pub(crate) fn get(&self) -> Option<Arc<HandoffRoot>> {
        let mut slot = self.root.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(root) = slot.as_ref() {
            return Some(root.clone());
        }
        let adopted = self.adopted.lock().unwrap_or_else(|p| p.into_inner()).clone();
        // An explicitly configured path wins; otherwise the container the host app reported.
        let path = self
            .resolver
            .as_ref()
            .and_then(|resolve| resolve())
            .or(adopted.map(|c| c.join("provider")))?;
        match HandoffRoot::open(&path) {
            Ok(root) => {
                if let Some(hook) = &self.on_open {
                    hook(&root);
                }
                *slot = Some(root.clone());
                Some(root)
            }
            Err(error) => {
                tracing::debug!(%error, "the provider temp root is not usable yet");
                None
            }
        }
    }
}

/// A real directory (not a symlink) owned by the current user.
fn is_own_directory(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return false };
    if !meta.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        meta.uid() == unsafe { libc::geteuid() }
    }
    #[cfg(windows)]
    {
        crate::windows_fs_security::directory_owned_by_current_user(path).unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    true
}

pub(crate) struct HandoffRoot {
    staging: PathBuf,
    handoff: PathBuf,
    /// Where the extension puts the bytes of a write for the daemon to ingest.
    ingest: PathBuf,
    lifetime: Duration,
    /// Handoff files delivered to the OS and not yet known to be taken, per item: what a newer
    /// version of the item must revoke before it evicts (see [`HandoffRoot::revoke_unconsumed`]).
    delivered: std::sync::Mutex<DeliveredFiles>,
    /// What makes a handoff name unique across the whole daemon: a value fixed at start-up and a
    /// counter, so no name is ever issued twice and nobody can delete a file it did not publish.
    nonce: u64,
    sequence: std::sync::atomic::AtomicU64,
    /// Test seam: makes this root's directory syncs fail.
    #[cfg(test)]
    pub(crate) fail_directory_sync: std::sync::atomic::AtomicBool,
}

impl HandoffRoot {
    /// Creates the two directories under `root` and sweeps what a previous run left behind.
    pub(crate) fn open(root: &Path) -> std::io::Result<Arc<Self>> {
        Self::open_with_lifetime(root, HANDOFF_LIFETIME)
    }

    pub(crate) fn open_with_lifetime(
        root: &Path,
        lifetime: Duration,
    ) -> std::io::Result<Arc<Self>> {
        let this = Self {
            staging: root.join("staging"),
            handoff: root.join("handoff"),
            ingest: root.join("ingest"),
            lifetime,
            delivered: std::sync::Mutex::default(),
            nonce: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64)
                ^ (u64::from(std::process::id()) << 40),
            sequence: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            fail_directory_sync: std::sync::atomic::AtomicBool::new(false),
        };
        prepare_layout(root)?;
        this.sweep_after_restart();
        this.sweep_ingest(None);
        Ok(Arc::new(this))
    }

    /// The directory the staging area lives on (the volume a handoff needs space on).
    pub(crate) fn staging_dir(&self) -> &Path {
        &self.staging
    }

    /// The directory of one domain under the temp root, where its authoring lease takes its OS
    /// lock (so a second process cannot author for the domain).
    pub(crate) fn domain_dir(&self, root_id: &str) -> PathBuf {
        self.ingest.with_file_name("domains").join(root_id)
    }

    pub(crate) fn ingest_dir(&self) -> &Path {
        &self.ingest
    }

    /// Removes abandoned uploads by AGE only. A JOURNALED upload (named in `keep`: an undecided
    /// operation's bytes) is NEVER removed by age: it stays until the operation is decided or
    /// resolved. An unjournaled partial copy ages out after a day; an unjournaled finished copy (one
    /// no request ever claimed) after the long safety age, logged. `keep` is `None` when the
    /// journal is not known yet (at open): then only partial copies are swept.
    pub(crate) fn sweep_ingest(&self, keep: Option<&std::collections::HashSet<String>>) {
        self.sweep_ingest_at(keep, SystemTime::now());
    }

    pub(crate) fn sweep_ingest_at(
        &self,
        keep: Option<&std::collections::HashSet<String>>,
        now: SystemTime,
    ) {
        let older_than =
            |at: SystemTime, limit: Duration| now.duration_since(at).is_ok_and(|age| age >= limit);
        let Ok(entries) = std::fs::read_dir(&self.ingest) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let partial = name.starts_with('.');
            let limit = if partial { INGEST_PARTIAL_LIFETIME } else { INGEST_FINISHED_LIFETIME };
            let stale = entry
                .metadata()
                .ok()
                .and_then(|m| copied_at(&m))
                .is_some_and(|at| older_than(at, limit));
            let sweepable =
                if partial { true } else { keep.is_some_and(|keep| !keep.contains(&name)) };
            if stale && sweepable {
                if !partial {
                    tracing::warn!(%name, "an upload no operation claimed for the safety age was removed");
                }
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// A new handoff name for a request: the hex of its id and a daemon-wide unique suffix, one
    /// path component by construction. Never issued twice (not even to a retry of the same
    /// request id, nor on another connection), so a cleanup of one publish cannot delete the
    /// file of another. `None` for an empty or oversized id.
    pub(crate) fn name_for(&self, request_id: &[u8]) -> Option<String> {
        (!request_id.is_empty() && request_id.len() <= MAX_REQUEST_ID_BYTES).then(|| {
            let sequence = self.sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            format!("{}-{:x}-{sequence:x}", hex::encode(request_id), self.nonce)
        })
    }

    /// Where the assembly of `name` is built (a temp file next to it carries the bytes).
    pub(crate) fn staging_file(&self, name: &str) -> PathBuf {
        self.staging.join(format!("{name}.partial"))
    }

    pub(crate) fn handoff_file(&self, name: &str) -> PathBuf {
        self.handoff.join(name)
    }

    /// Moves a complete, verified, fsynced staging file into `handoff/` and fsyncs the directory.
    /// Only after this returns may the name be given to anyone. On ANY failure nothing is left:
    /// a failed rename removes the staging file, and a failed directory sync after a successful
    /// rename removes the destination too (and syncs again), so no untracked handoff file stays.
    pub(crate) fn publish(&self, assembled: &Path, name: &str) -> Result<(), StorageError> {
        let destination = self.handoff_file(name);
        // Never replacing: a name that is taken is somebody else's handoff.
        if let Err(error) = yadorilink_local_storage::rename_no_replace(assembled, &destination) {
            let _ = std::fs::remove_file(assembled);
            return Err(error.into());
        }
        if let Err(error) = self.sync_handoff_directory() {
            let _ = std::fs::remove_file(&destination);
            let _ = sync_directory(&self.handoff);
            return Err(error.into());
        }
        Ok(())
    }

    fn sync_handoff_directory(&self) -> std::io::Result<()> {
        #[cfg(test)]
        if self.fail_directory_sync.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("injected directory fsync failure"));
        }
        sync_directory(&self.handoff)
    }

    /// Remembers that handoff file `name` of `item` was delivered to the OS.
    pub(crate) fn note_delivered(&self, root_id: &str, item: [u8; 16], name: &str) {
        self.delivered
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry((root_id.to_owned(), item))
            .or_default()
            .push(name.to_owned());
    }

    /// Stops tracking handoff file `name` of `item` (its file was removed by the caller).
    pub(crate) fn forget_delivered(&self, root_id: &str, item: &[u8; 16], name: &str) {
        let mut delivered = self.delivered.lock().unwrap_or_else(|p| p.into_inner());
        let key = (root_id.to_owned(), *item);
        if let Some(names) = delivered.get_mut(&key) {
            names.retain(|tracked| tracked != name);
            if names.is_empty() {
                delivered.remove(&key);
            }
        }
    }

    /// Deletes every delivered handoff file of `item` the OS has not taken (a file it did take
    /// is gone from `handoff/` already). A newer version of the item calls this BEFORE it
    /// evicts: otherwise the OS could take the old file after the eviction found nothing to
    /// evict and the new version was published, and hold old bytes with no fence left. A file
    /// taken at this very moment is materialized by the time the eviction runs, which evicts it.
    ///
    /// A file that could not be removed stays tracked and the call fails: the caller must not
    /// publish over a handoff it could not take back, and retries.
    pub(crate) fn revoke_unconsumed(
        &self,
        root_id: &str,
        item: &[u8; 16],
    ) -> std::io::Result<usize> {
        let key = (root_id.to_owned(), *item);
        let names = self
            .delivered
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key)
            .unwrap_or_default();
        let mut revoked = 0;
        let mut failed = Vec::new();
        let mut first_error = None;
        for name in names {
            match std::fs::remove_file(self.handoff_file(&name)) {
                Ok(()) => revoked += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                    failed.push(name);
                }
            }
        }
        if let Some(error) = first_error {
            self.delivered
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(key)
                .or_default()
                .extend(failed);
            return Err(error);
        }
        Ok(revoked)
    }

    /// Deletes the handoff file `name` of `item` once its lifetime has passed, if the OS has not
    /// taken it, and stops tracking it (a file gone by then was taken: nothing is left to
    /// revoke). A file that cannot be removed stays tracked for a later revocation.
    pub(crate) fn sweep_later(self: &Arc<Self>, root_id: String, item: [u8; 16], name: String) {
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(this.lifetime).await;
            match std::fs::remove_file(this.handoff_file(&name)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return,
            }
            let mut delivered = this.delivered.lock().unwrap_or_else(|p| p.into_inner());
            let key = (root_id, item);
            if let Some(names) = delivered.get_mut(&key) {
                names.retain(|tracked| *tracked != name);
                if names.is_empty() {
                    delivered.remove(&key);
                }
            }
        });
    }

    /// How many delivered handoff files are tracked (a test reads this).
    #[cfg(test)]
    pub(crate) fn tracked_handoffs(&self) -> usize {
        self.delivered.lock().unwrap_or_else(|p| p.into_inner()).values().map(Vec::len).sum()
    }

    fn sweep_after_restart(&self) {
        remove_entries(&self.staging, |_| true);
        let lifetime = self.lifetime;
        remove_entries(&self.handoff, |handed_over| {
            SystemTime::now().duration_since(handed_over).is_ok_and(|age| age >= lifetime)
        });
    }
}

/// fsync of a directory (a no-op where directories cannot be opened).
fn sync_directory(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// When a handoff file entered `handoff/`: its status-change time (the rename into the directory
/// sets it, and user space cannot set it), never its modification time, which carries the
/// replicated mtime of the content and can be anything, including the future. Where there is no
/// such time the entry counts as stale at the next start.
fn handed_over_at(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let nanos = u32::try_from(metadata.ctime_nsec()).ok()?;
        let seconds = u64::try_from(metadata.ctime()).ok()?;
        Some(SystemTime::UNIX_EPOCH + Duration::new(seconds, nanos))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

/// When a copy in `ingest/` was last written. Where the file system has a status-change time
/// that is what ages the copy (as for a handoff file); Windows has none, and the copy's own
/// modification time is the age: the host writes a copy once, under a name that starts with a dot
/// until it is complete, and never touches it again.
fn copied_at(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    #[cfg(windows)]
    {
        metadata.modified().ok()
    }
    #[cfg(not(windows))]
    {
        handed_over_at(metadata)
    }
}

/// Removes the entries of `dir` whose handoff time `stale` accepts (an unreadable time counts as
/// stale: nothing in these directories is worth keeping across a restart).
fn remove_entries(dir: &Path, stale: impl Fn(SystemTime) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let at = entry.metadata().ok().and_then(|m| handed_over_at(&m));
        if at.is_none_or(&stale) {
            let path = entry.path();
            let _ = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
        }
    }
}

#[cfg(test)]
mod tests;
