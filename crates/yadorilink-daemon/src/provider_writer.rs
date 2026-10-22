//! What the provider write path needs from the daemon: the author identity, the block store,
//! and the per-root lease that authorizes authoring for a root with no directory.
//!
//! A plain root's authoring runs under a `RootLease` that wraps an OS lock on the linked
//! directory. A provider root has none, so each domain gets a directory of its own under the
//! fixed temp root (`domains/<root_id>`) and the lease wraps the ordinary `SyncRootLock` on THAT
//! directory: an exclusive OS lock held for the life of the lease, so a second PROCESS cannot
//! author for the same domain, and the lease's stop/drain gate still orders shutdown.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use yadorilink_root_authority::root_commit::RootLease;
use yadorilink_root_authority::sync_root_lock::SyncRootLock;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;

use crate::adapters::block_store_ports::BlockStorePortsAdapter;
use crate::daemon_state::DaemonState;

/// A root's lease with the identity of the directory its OS lock was taken in: a later request
/// re-checks that the path still names that very directory, so a retargeted path can never split
/// the lock between two directories.
struct HeldLease {
    lease: Arc<RootLease>,
    identity: Option<(u64, u64)>,
}

/// `(dev, ino)` of `dir` itself (never through a symlink), or an error when it is not a plain
/// directory.
fn plain_directory_identity(dir: &Path) -> Result<Option<(u64, u64)>, String> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{} is not a plain directory", dir.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(Some((metadata.dev(), metadata.ino())))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

/// Creates `dir` (mode 0700) when missing and requires it to be a plain directory, not a symlink.
fn ensure_plain_directory(dir: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(windows)]
            let created = crate::windows_fs_security::create_private_dir_all(dir);
            #[cfg(not(windows))]
            let created = {
                let mut builder = std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(dir)
            };
            match created {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("{}: {e}", dir.display())),
            }
        }
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    }
    plain_directory_identity(dir).map(|_| ())
}

pub(crate) struct ProviderWriter {
    state: Arc<DaemonState>,
    leases: Mutex<HashMap<String, HeldLease>>,
    #[cfg(test)]
    follow_ups: std::sync::atomic::AtomicU64,
}

impl ProviderWriter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self {
            state,
            leases: Mutex::default(),
            #[cfg(test)]
            follow_ups: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn device_id(&self) -> String {
        self.state.device_id.clone()
    }

    pub(crate) fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64)
    }

    pub(crate) fn store(&self) -> BlockStorePortsAdapter {
        BlockStorePortsAdapter::new(self.state.block_store.clone())
    }

    /// Whether this device may author into `group_id` now: a writer of the group's verified
    /// policy (or any member while the group has no policy yet). A Viewer's change would be
    /// rejected by every peer, so it is refused here, before anything is read or committed.
    pub(crate) fn may_author(&self, group_id: &str) -> bool {
        crate::native_rebootstrap::is_writer(
            &self.state,
            &yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned()),
        )
    }

    /// The author handle this device signs with.
    pub(crate) fn author(&self, _group_id: &str) -> Result<Arc<LocalAuthorKey>, String> {
        self.state.local_author().ok_or_else(|| {
            "this device has no signing key; refusing to author provider changes".to_string()
        })
    }

    /// Follow-up for a change that just committed: publishes the group's pending native checkpoint
    /// (a peer can only be sent a delta that is published) and wakes replication. Without it a
    /// provider-authored change stays unpublished until the next reconnect.
    pub(crate) async fn after_commit(&self, group_id: &str) {
        #[cfg(test)]
        self.follow_ups.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.state.on_local_native_commit(group_id).await;
    }

    /// Test-only: how many committed changes were followed up.
    #[cfg(test)]
    pub(crate) fn follow_ups(&self) -> u64 {
        self.follow_ups.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn record_provenance(
        &self,
        group_id: &str,
        hashes: &[Vec<u8>],
    ) -> Result<(), String> {
        self.state
            .replica_coordinator
            .record_block_provenance(group_id, hashes)
            .map_err(|e| e.to_string())
    }

    /// The root's lease, created on first use over its domain directory (`domain_dir`) and kept
    /// until the root is no longer declared.
    pub(crate) fn lease(
        &self,
        root_id: &str,
        group_id: &str,
        domain_dir: &Path,
    ) -> Result<Arc<RootLease>, String> {
        let mut leases = self.leases.lock().unwrap_or_else(|p| p.into_inner());
        // Leases of roots that were replaced or removed are released (and their locks with them).
        if let Ok(declared) =
            self.state.replica_coordinator.provider_repository().list_declared_roots()
        {
            leases.retain(|id, _| declared.iter().any(|r| &r.root_id == id));
        }
        if let Some(held) = leases.get(root_id) {
            // The path must still name the directory the lock was taken in.
            if plain_directory_identity(domain_dir)? != held.identity {
                return Err(format!(
                    "{} no longer names the locked directory",
                    domain_dir.display()
                ));
            }
            return Ok(held.lease.clone());
        }
        static GENERATION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        // No symlink anywhere below the temp root on the way to the lock: the domains directory
        // and the domain's own directory are plain directories.
        if let Some(parent) = domain_dir.parent() {
            ensure_plain_directory(parent)?;
        }
        ensure_plain_directory(domain_dir)?;
        let lock = SyncRootLock::acquire(domain_dir).map_err(|e| e.to_string())?;
        // The lock is on the canonical path; it must be the directory just checked.
        let expected = domain_dir
            .parent()
            .and_then(|p| p.canonicalize().ok())
            .zip(domain_dir.file_name())
            .map(|(parent, name)| parent.join(name));
        if expected.as_deref() != Some(lock.root()) {
            return Err(format!("{} changed while it was being locked", domain_dir.display()));
        }
        let identity = plain_directory_identity(domain_dir)?;
        let lease = Arc::new(RootLease::new(
            lock,
            group_id.to_owned(),
            GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        ));
        leases.insert(root_id.to_owned(), HeldLease { lease: lease.clone(), identity });
        Ok(lease)
    }
}
