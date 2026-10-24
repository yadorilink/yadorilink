//! `yadorilink-daemon`'s own `ReplicaCoordinator` is the composition root
//! that legitimately composes every subsystem this enum's variants wrap
//! (`yadorilink-sync-sqlite`, `yadorilink-replica-engine`,
//! `yadorilink-filesystem-sync`, `yadorilink-root-authority`,
//! `yadorilink-transport`, ...) and needs one error type to `?`-propagate
//! from whichever subsystem failed at its own call sites -- the same
//! composition-root shape that already justified hosting
//! `ReplicaCoordinator` here. Nearly every variant
//! already has a narrower, subsystem-owned equivalent (`SyncSqliteError`,
//! `RootAuthorityError`, `MaterializationExecutionError`, ...); this type
//! is the union those narrower types feed into at the one place that
//! legitimately needs the union. Every production call site in this crate
//! (and `yadorilink-cli`, which had none) uses
//! this type.

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    // No longer `#[from]`-derived — see
    // the manual `From<StorageError>` impl below, which special-cases
    // `StorageError::DiskPressure` into `SyncError::DiskPressure` instead of
    // burying it in this generic variant, so a caller can still tell "disk
    // is full" from every other storage error by matching on `SyncError`
    // alone, regardless of which layer (this crate's own preflight, or
    // `yadorilink-local-storage`'s block-store preflight) detected it.
    #[error("storage error: {0}")]
    Storage(yadorilink_local_storage::StorageError),

    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("db error: {0}")]
    Db(#[from] rusqlite::Error),

    /// `SyncState` checks out a connection from a
    /// pool (`r2d2`) for every call instead of locking one shared
    /// `Connection`, so a checkout can now fail on its own (pool
    /// exhausted past its wait timeout, or the pool's own setup/teardown
    /// erroring) in a way the old `Mutex<Connection>` never could — that
    /// lock always eventually succeeded (or ran the poison-recovery path)
    /// rather than returning an error.
    #[error("db connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("filesystem watcher error: {0}")]
    Watch(#[from] yadorilink_filesystem_sync::watcher::WatchError),

    #[error("protobuf decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    /// content-defined-chunking: an error from the `fastcdc` streaming
    /// chunker (I/O failure reading the source file, or an internal
    /// chunker error) — distinct from `Io` since it's specifically about
    /// the CDC chunk-boundary-finding process, not a bare filesystem call.
    #[error("content-defined chunking error: {0}")]
    Chunking(String),

    #[error("not found: {0}")]
    NotFound(String),

    /// The link at the path belongs to a different group than the caller expected. Nothing
    /// was changed.
    #[error("the folder at {0} belongs to a different group than expected")]
    GroupMismatch(String),

    /// A caller (or a value threaded in from an untrusted source, e.g. a
    /// coordination-plane JSON response) supplied an argument that is
    /// structurally invalid for the operation — rejected up front, fail
    /// closed, before any state is written. Distinct from `NotFound` (the
    /// referent is absent) and `CorruptState` (locally-stored data is
    /// malformed): here the *input* is the problem.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Two or more live links share one `group_id`. The index is group-scoped
    /// and path-relative but every scan is root-scoped and authoritative, so
    /// each root's scan reads the other root's files as missing and tombstones
    /// them — signed deltas that then replicate to every device.
    /// Refused per-group, loudly, at every seam that would otherwise have to
    /// pick a root. Never guess a root: the two folders are not
    /// interchangeable, and choosing wrong deletes the other one's files
    /// everywhere.
    ///
    /// Carries the paths rather than a count because removal is keyed by
    /// `local_path` everywhere, so the paths *are* the remedy the user needs.
    /// Every path carried here is LIVE: each producer enumerates live rows only,
    /// so every folder named is one an `unlink` actually acts on. Naming an
    /// orphaned row would send the user to unlink a folder whose removal changes
    /// nothing about the refusal.
    ///
    /// The message previously opened with "Move any files you want to keep into
    /// ONE of them FIRST". That stated a precondition that does not exist —
    /// `remove_link` deletes a row and never a file, and an orphaned link's
    /// on-disk files are documented as never touched — and it read as "unlinking
    /// will destroy files". A user who believes moving is mandatory but cannot
    /// tell which of the named folders to keep guesses, and the guess is what
    /// destroys data. The wording below instead states the non-destructive
    /// guarantee outright, gives the remedy as a command, scopes the refusal to
    /// this one group (it is not the app being broken), and is honest about the
    /// ONE real consequence: the additive-scan window the unlink handler arms on
    /// the survivor is best-effort, so a file no other device holds must be
    /// copied across by hand. Pinned by
    /// `the_ambiguous_link_message_names_the_real_remedy`.
    #[error(
        "folder group {group_id} is linked to {} folders on this device ({}); sync is stopped \
         for this folder group until exactly one remains. Decide which folder is this group's \
         sync root and run `yadorilink unlink` on the other(s) — unlinking removes a folder from \
         sync and does not delete any files from it. Any file that exists only in a folder you \
         unlink will be copied into the folder you keep if another device still has it; if no \
         other device has it, copy it into the folder you keep yourself, or a later scan will \
         delete it everywhere.",
        local_paths.len(),
        local_paths.join(", ")
    )]
    AmbiguousLink { group_id: String, local_paths: Vec<String> },

    /// A value read back from the local database has an impossible shape
    /// (e.g. a fixed-width hash blob that is not its declared length) — a sign
    /// of on-disk corruption or external tampering, not a normal runtime
    /// condition. Distinct from `Db` so callers can tell "the row is there but
    /// malformed" from a bare SQLite failure.
    #[error("corrupt local state: {0}")]
    CorruptState(String),

    /// Hydration request that couldn't obtain
    /// all of a file's blocks within the bounded timeout, either because
    /// the peer never responded or explicitly reported some as not found.
    #[error("hydration of {0:?} timed out or failed: no reachable peer holds all required blocks")]
    HydrationFailed(String),

    /// The "Restore With Missing Blocks Fails
    /// Clearly" spec requirement: a restore (`yadorilink restore`/`trash restore`) whose
    /// chosen version needs blocks that are missing locally and
    /// unavailable from every currently-reachable, authorized peer.
    /// Deliberately a distinct variant from `HydrationFailed` — both are
    /// "couldn't get these blocks from a peer in time," but callers (the
    /// CLI, the control-socket IPC layer) need to tell "restoring version
    /// content specifically failed" apart from "this on-demand file's
    /// current content failed to hydrate," since the two surface with
    /// different, specific user-facing messages (spec: "an error that
    /// specifically identifies unavailable version content, rather than a
    /// generic I/O or not-found error"). The payload identifies the
    /// specific version that failed to resolve (`"<group_id>/<path>@
    /// <version_seq>"`).
    #[error(
        "restoring {0:?} failed: the chosen version's content is unavailable — required blocks \
         are missing locally and no reachable, authorized peer holds them"
    )]
    VersionContentUnavailable(String),

    /// A restore declined because the path holds local state capture has not
    /// recorded, or changed on disk while the restore was being prepared.
    /// Nothing was written over it; the path is journaled so capture takes
    /// it, after which the restore can be asked again.
    #[error("not restoring {0:?}: it holds local changes that have not been captured yet")]
    PathChangedLocally(String),

    /// The direct-filesystem pipeline was asked to act on a provider-backed root (or one with
    /// inconsistent provider state, "rebootstrap required"): refused, never read as a plain
    /// directory.
    #[error("{0}")]
    NotFilesystemRoot(String),

    /// on-demand-sync spec "Pinned files cannot be evicted".
    #[error("cannot evict {0:?}: it is pinned")]
    EvictionRejected(String),

    /// Mirrors `MaterializationExecutionError::
    /// EvictionOutcomeAmbiguous`'s own doc comment exactly -- a Windows
    /// native dehydrate call's outcome could not be confirmed (transport
    /// failure after the real call may have already succeeded), so unlike
    /// `EvictionRejected` this must NOT be treated as "the file is still
    /// materialized".
    #[error("eviction outcome for {0:?} could not be confirmed")]
    EvictionOutcomeAmbiguous(String),

    /// defense-in-depth: after resolving a peer-advertised path
    /// under a folder group's sync root, canonicalizing the resolved
    /// parent directory landed outside that root — most likely because a
    /// pre-existing symlink at an intermediate path component was
    /// followed. `is_safe_relative_path` already rejects `..` and
    /// absolute-path components, but can't (without an actual filesystem
    /// check) catch a symlink a local actor planted in advance.
    #[error(
        "materialization target {0:?} resolved outside its sync root (symlinked path component?)"
    )]
    PathEscapesRoot(String),

    /// A distinct disk-pressure error,
    /// carrying the affected path and volume — constructed directly by this
    /// crate's own hydration/materialization preflight, which calls
    /// `yadorilink_local_storage::check_disk_headroom` and converts its
    /// `StorageError::DiskPressure` via the same `?`-triggered `From`
    /// impl below when the block store's own preflight rejects a write.
    /// Never produced via a generic `?`-conversion from an ordinary I/O
    /// error — requires this stay distinguishable from a
    /// transient/network failure so callers (the daemon's Degraded-state
    /// tracking, in particular) can back off differently for "disk is
    /// full" than for "peer/network blip, just retry".
    #[error(
        "insufficient free space to write {path:?}: {available_bytes} bytes available on \
         {volume:?}, headroom requires at least {headroom_bytes} bytes free"
    )]
    DiskPressure { path: String, volume: String, available_bytes: u64, headroom_bytes: u64 },

    /// The sync-root lock sidecar is gone or replaced; terminal for the link
    /// (see `RootAuthorityError::OwnershipLost`).
    #[error("{0}")]
    OwnershipLost(String),

    /// This local database's stamped
    /// `PRAGMA user_version` is newer than the schema version this binary
    /// supports — it was opened (and migrated) by a newer build. Refusing
    /// to proceed here is deliberate: an older binary blindly continuing
    /// could reinterpret or overwrite columns it has no knowledge of.
    /// Callers (daemon startup) should surface this as a clear "downgrade
    /// not supported, reinstall the newer version" message rather than a
    /// generic database error.
    #[error(
        "database schema version {on_disk_version} is newer than this build supports \
         (supports up to version {supported_version}) — this looks like an unsupported \
         downgrade; reinstall the version that last wrote this data, or a newer one"
    )]
    UnsupportedSchemaDowngrade { on_disk_version: i32, supported_version: i32 },

    /// A local edit could not be stamped with a real authorization context
    /// because the group's policy is unavailable: its most recent policy
    /// snapshot failed verification, so the group is *stale* and change
    /// admission for it fails closed. Emitting a placeholder-auth change in
    /// that window would create a local native head every valid-policy peer
    /// rejects, stranding an un-replicable branch, so the local emit path
    /// returns this instead of emitting. It is a *transient, expected*
    /// condition, not a failure: the caller leaves the path journaled dirty so
    /// a startup/backstop re-drive re-emits it — with a real stamp — once a
    /// valid policy snapshot is admitted. See
    /// [`yadorilink_replica_domain::local_op::PolicyUnavailable`].
    #[error(
        "group policy is unavailable (stale or failed verification); withholding the local \
         change until a valid policy snapshot is admitted"
    )]
    PolicyUnavailable,

    /// A path names a component reserved for transaction artefacts (see
    /// `yadorilink_fs_platform::reserved_namespace`) somewhere it must not: a peer delta
    /// naming one before native admission, a collision detected at artefact
    /// creation, or one found unexpectedly at startup. Fail-closed and
    /// carries the exact path — the offending path is never admitted,
    /// materialized or deleted; see `reserved_namespace`'s module doc
    /// comment for the ownership rule this enforces.
    #[error("path {0:?} names a reserved artefact component and cannot be used here")]
    ReservedNamespaceCollision(String),

    /// A path component would not survive a Windows peer's own path
    /// normalization: Windows silently drops a trailing `.` or ` ` from a
    /// path component in most Win32 APIs, so a component typed with one is
    /// not the same bytes as what actually lands on disk once a Windows
    /// device materializes it (see
    /// [`yadorilink_fs_platform::reserved_namespace::path_has_non_portable_wire_component`]).
    /// Whether a path is safe cannot depend on which platform happens to be
    /// running the check — the same reasoning `dag_store`'s wire-vs-host
    /// path handling already applies to reserved-artefact aliasing — so
    /// this is checked and refused identically by every peer, at admission,
    /// rather than left to silently alias a different on-disk name on
    /// whichever member's device happens to be Windows. Fail-closed: the
    /// offending path is never admitted, materialized, or trusted as
    /// faithfully represented on disk.
    #[error(
        "path {0:?} has a component that is not portable to every platform this group may sync \
         to (Windows silently strips a trailing '.' or ' ') and cannot be used here"
    )]
    NonPortablePath(String),
}

impl From<yadorilink_replica_domain::local_op::PolicyUnavailable> for SyncError {
    fn from(_: yadorilink_replica_domain::local_op::PolicyUnavailable) -> Self {
        SyncError::PolicyUnavailable
    }
}

impl SyncError {
    /// The link refusal a client can branch on: the disk (or the database's
    /// volume) is full.
    pub(crate) fn link_refusal(&self) -> Option<crate::application::model::LinkRefusal> {
        use crate::application::model::LinkRefusal;
        match self {
            SyncError::DiskPressure { .. } => Some(LinkRefusal::DiskFull),
            SyncError::Io(e) if e.kind() == std::io::ErrorKind::StorageFull => {
                Some(LinkRefusal::DiskFull)
            }
            SyncError::Db(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::DiskFull =>
            {
                Some(LinkRefusal::DiskFull)
            }
            _ => None,
        }
    }

    /// A coarse, stable,
    /// privacy-safe category slug for this error — the recent-error
    /// ring buffer's (`yadorilink-daemon::recent_errors`) and the
    /// `/metrics` endpoint's `yadorilink_sync_errors_total{category}`
    /// taxonomy, mirroring the sync
    /// engine's error taxonomy (e.g. peer-unreachable, block-integrity,
    /// disk-pressure, permission). Deliberately derived only from the
    /// variant/kind itself, never from `Display`/`to_string` — this
    /// crate's error messages can embed a path, volume, or hash (see e.g.
    /// `DiskPressure`'s own fields), exactly what the recent-error buffer
    /// and metrics labels must never carry (a redaction
    /// requirement). "block_integrity" (a peer returning block data that
    /// fails its expected hash/size) has no dedicated variant here — it's
    /// recorded directly by the daemon's hydration dispatcher at the point
    /// that check happens, not through this method.
    pub fn category(&self) -> &'static str {
        match self {
            // `Io`'s `Display` can embed a path (e.g. a `NotFound` for a
            // specific file) — only the stable `ErrorKind` is ever used
            // here, never the message text.
            SyncError::Io(e) => match e.kind() {
                std::io::ErrorKind::PermissionDenied => "permission",
                _ => "io",
            },
            SyncError::Storage(_) => "storage",
            SyncError::Transport(_) => "peer_unreachable",
            SyncError::Hex(_) => "protocol",
            SyncError::Db(_) => "storage",
            SyncError::Pool(_) => "storage",
            SyncError::Json(_) => "protocol",
            SyncError::Watch(_) => "io",
            SyncError::Decode(_) => "protocol",
            SyncError::Chunking(_) => "io",
            SyncError::NotFound(_) => "not_found",
            SyncError::GroupMismatch(_) => "conflict",
            SyncError::InvalidInput(_) => "invalid_input",
            SyncError::AmbiguousLink { .. } => "config",
            SyncError::OwnershipLost(_) => "config",
            SyncError::CorruptState(_) => "storage",
            SyncError::HydrationFailed(_) => "peer_unreachable",
            SyncError::VersionContentUnavailable(_) => "peer_unreachable",
            SyncError::PathChangedLocally(_) => "conflict",
            SyncError::EvictionRejected(_) => "policy",
            SyncError::NotFilesystemRoot(_) => "policy",
            SyncError::EvictionOutcomeAmbiguous(_) => "policy",
            SyncError::PathEscapesRoot(_) => "permission",
            SyncError::DiskPressure { .. } => "disk_pressure",
            SyncError::UnsupportedSchemaDowngrade { .. } => "storage",
            SyncError::PolicyUnavailable => "policy",
            SyncError::ReservedNamespaceCollision(_) => "permission",
            SyncError::NonPortablePath(_) => "invalid_input",
        }
    }
}

impl From<yadorilink_sqlite_runtime::DatabaseError> for SyncError {
    fn from(err: yadorilink_sqlite_runtime::DatabaseError) -> Self {
        match err {
            yadorilink_sqlite_runtime::DatabaseError::Sqlite(e) => SyncError::Db(e),
            yadorilink_sqlite_runtime::DatabaseError::Pool(e) => SyncError::Pool(e),
            yadorilink_sqlite_runtime::DatabaseError::UnsupportedSchemaDowngrade {
                on_disk_version,
                supported_version,
            } => SyncError::UnsupportedSchemaDowngrade { on_disk_version, supported_version },
            yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(msg) => {
                SyncError::CorruptState(msg)
            }
            // Another writer owns the data area: the same "in use" outcome as an OS lock held
            // elsewhere.
            refused @ (yadorilink_sqlite_runtime::DatabaseError::WriterLease(_)
            | yadorilink_sqlite_runtime::DatabaseError::StaleWriter { .. }) => SyncError::Io(
                std::io::Error::new(std::io::ErrorKind::ResourceBusy, refused.to_string()),
            ),
        }
    }
}

impl From<yadorilink_sync_sqlite::SyncSqliteError> for SyncError {
    fn from(err: yadorilink_sync_sqlite::SyncSqliteError) -> Self {
        match err {
            yadorilink_sync_sqlite::SyncSqliteError::Sqlite(e) => SyncError::Db(e),
            yadorilink_sync_sqlite::SyncSqliteError::Pool(e) => SyncError::Pool(e),
            yadorilink_sync_sqlite::SyncSqliteError::NotFound(msg) => SyncError::NotFound(msg),
            yadorilink_sync_sqlite::SyncSqliteError::GroupMismatch { local_path } => {
                SyncError::GroupMismatch(local_path)
            }
            yadorilink_sync_sqlite::SyncSqliteError::CorruptState(msg) => {
                SyncError::CorruptState(msg)
            }
            // `materialization_jobs::transition`/`mark_backoff`/
            // `reschedule_after_skip`'s illegal-job-state-transition guard --
            // see `SyncSqliteError::InvalidInput`'s own doc comment.
            yadorilink_sync_sqlite::SyncSqliteError::InvalidInput(msg) => {
                SyncError::InvalidInput(msg)
            }
            yadorilink_sync_sqlite::SyncSqliteError::Io(e) => SyncError::Io(e),
            // `dag_store`'s reserved-namespace/portable-path admission
            // checks -- see `SyncSqliteError`'s own doc
            // comments on these variants.
            yadorilink_sync_sqlite::SyncSqliteError::ReservedNamespaceCollision(m) => {
                SyncError::ReservedNamespaceCollision(m)
            }
            yadorilink_sync_sqlite::SyncSqliteError::NonPortablePath(m) => {
                SyncError::NonPortablePath(m)
            }
            // `file_index`'s `blocks_json` encode -- see
            // `SyncSqliteError::Json`'s own doc comment.
            yadorilink_sync_sqlite::SyncSqliteError::Json(e) => SyncError::Json(e),
            yadorilink_sync_sqlite::SyncSqliteError::Hex(e) => SyncError::Hex(e),
            yadorilink_sync_sqlite::SyncSqliteError::Chunking(s) => SyncError::Chunking(s),
            yadorilink_sync_sqlite::SyncSqliteError::Storage(e) => SyncError::Storage(e),
            // `link.rs`'s errors from yadorilink-sync-sqlite -- lossless, not flattened to a message string, for
            // the same reason `SyncError::AmbiguousLink`'s own doc comment
            // already requires for its round trip through
            // `RootAuthorityError`: callers match on the structured variant.
            yadorilink_sync_sqlite::SyncSqliteError::AmbiguousLink { group_id, local_paths } => {
                SyncError::AmbiguousLink { group_id, local_paths }
            }
            yadorilink_sync_sqlite::SyncSqliteError::NotFilesystemRoot(group) => {
                SyncError::NotFilesystemRoot(group)
            }
            // A change-emitting write's `local_emission_auth` pre-check --
            // see `SyncSqliteError::PolicyUnavailable`'s own doc comment.
            yadorilink_sync_sqlite::SyncSqliteError::PolicyUnavailable => {
                SyncError::PolicyUnavailable
            }
            // A local authoring refused because the path's disk state has not
            // been reconciled yet -- see
            // `SyncSqliteError::PathAwaitingHeldPathReconciliation`.
            // Nothing is written; the edit is refused as an operation this
            // path cannot take right now, and flattened to a message for
            // the same reason as the arms around it.
            error @ yadorilink_sync_sqlite::SyncSqliteError::PathAwaitingHeldPathReconciliation {
                ..
            } => SyncError::InvalidInput(error.to_string()),
            // A local authoring refused at the commit because the path is under a
            // paused item -- see `SyncSqliteError::PathPaused`. Nothing is written;
            // the edit stays on disk until the item is resumed.
            error @ yadorilink_sync_sqlite::SyncSqliteError::PathPaused { .. } => {
                SyncError::InvalidInput(error.to_string())
            }
            // A write or delta refused because a rebootstrap froze the group -- see
            // `SyncSqliteError::GroupFrozen`. Nothing is written; the work is deferred
            // and the edit is captured again once the freeze ends. Flattened to a
            // message for the same reason as the arms around it.
            error @ yadorilink_sync_sqlite::SyncSqliteError::ClosureRefused(_) => {
                SyncError::InvalidInput(error.to_string())
            }
            error @ yadorilink_sync_sqlite::SyncSqliteError::GroupFrozen { .. } => {
                SyncError::InvalidInput(error.to_string())
            }
            // A local write whose row changed between capture and commit --
            // see `SyncSqliteError::LocalWriteCaptureStale`. Nothing was
            // written; the path is captured again. Flattened to a message
            // for the same reason as the arms around it.
            error @ yadorilink_sync_sqlite::SyncSqliteError::LocalWriteCaptureStale { .. } => {
                SyncError::InvalidInput(error.to_string())
            }
            // A local authoring refused by an authoring rule
            // -- see `SyncSqliteError::AuthoringRefused`. Nothing was
            // written. Flattened to a message for the same reason as the
            // arms around it; the author-rotation reaction matches the
            // store error before it reaches this conversion.
            error @ yadorilink_sync_sqlite::SyncSqliteError::AuthoringRefused { .. } => {
                SyncError::InvalidInput(error.to_string())
            }
        }
    }
}

/// The forward direction: the replica-state operations in
/// `replica_coordinator/peer_replica_state.rs` delegate to
/// `SyncError`-returning repository methods but return `PeerSessionError`
/// -- this is the conversion every one of those delegates uses via
/// `?`/`.map_err`.
impl From<SyncError> for yadorilink_peer_session::PeerSessionError {
    fn from(error: SyncError) -> Self {
        use yadorilink_peer_session::PeerSessionError as E;
        match error {
            SyncError::Io(e) => E::Io(e),
            SyncError::NotFound(m) => E::NotFound(m),
            SyncError::CorruptState(m) => E::CorruptState(m),
            SyncError::InvalidInput(m) => E::InvalidInput(m),
            SyncError::HydrationFailed(m) => E::HydrationFailed(m),
            SyncError::PathEscapesRoot(m) => E::PathEscapesRoot(m),
            SyncError::ReservedNamespaceCollision(m) => E::ReservedNamespaceCollision(m),
            SyncError::NonPortablePath(m) => E::NonPortablePath(m),
            SyncError::DiskPressure { path, volume, available_bytes, headroom_bytes } => {
                E::DiskPressure { path, volume, available_bytes, headroom_bytes }
            }
            SyncError::Hex(e) => E::Hex(e),
            SyncError::Transport(e) => E::Transport(e),
            other => E::CorruptState(other.to_string()),
        }
    }
}

impl From<yadorilink_replica_domain::codec::ChangeError> for SyncError {
    fn from(error: yadorilink_replica_domain::codec::ChangeError) -> Self {
        SyncError::CorruptState(error.to_string())
    }
}

/// `native_snapshot` lives in
/// `yadorilink-replica-engine` -- callers in this crate
/// (`ReplicaCoordinator`'s own `SyncError`-returning methods) need this at
/// their own `?`-propagation sites. `ReplicaEngineError::Storage` has no
/// matching `SyncError` variant carrying a bare message (`SyncError::
/// Storage` wraps a concrete `yadorilink_local_storage::StorageError`, not a
/// string), so it collapses to `CorruptState` -- the same catch-all choice
/// this file already makes for every other foreign error with no exact
/// `SyncError` counterpart.
impl From<yadorilink_replica_engine::error::ReplicaEngineError> for SyncError {
    fn from(err: yadorilink_replica_engine::error::ReplicaEngineError) -> Self {
        use yadorilink_replica_engine::error::ReplicaEngineError as E;
        match err {
            E::Storage(msg) => SyncError::CorruptState(msg),
            E::CorruptState(msg) => SyncError::CorruptState(msg),
            E::InvalidInput(msg) => SyncError::InvalidInput(msg),
        }
    }
}

impl From<yadorilink_root_authority::RootAuthorityError> for SyncError {
    fn from(err: yadorilink_root_authority::RootAuthorityError) -> Self {
        match err {
            yadorilink_root_authority::RootAuthorityError::Io(e) => SyncError::Io(e),
            yadorilink_root_authority::RootAuthorityError::NotFound(msg) => {
                SyncError::NotFound(msg)
            }
            yadorilink_root_authority::RootAuthorityError::CorruptState(msg) => {
                SyncError::CorruptState(msg)
            }
            yadorilink_root_authority::RootAuthorityError::ReservedNamespaceCollision(msg) => {
                SyncError::ReservedNamespaceCollision(msg)
            }
            // A `root_identity::VerifiedRoot` mismatch (yadorilink-root-
            // authority) maps to `SyncError::InvalidInput`
            // (`root_identity_mismatch`'s own doc: rejected before any state
            // is written, never a transient/retriable condition).
            yadorilink_root_authority::RootAuthorityError::RootIdentityMismatch(msg) => {
                SyncError::InvalidInput(msg)
            }
            yadorilink_root_authority::RootAuthorityError::OwnershipLost(msg) => {
                SyncError::OwnershipLost(msg)
            }
            // A fenced-out writer can no longer prove it owns the data area: terminal, like a
            // lost sidecar.
            yadorilink_root_authority::RootAuthorityError::StaleWriter(msg) => {
                SyncError::OwnershipLost(msg)
            }
            yadorilink_root_authority::RootAuthorityError::WriterLeaseHeld(msg) => {
                SyncError::Io(std::io::Error::other(msg))
            }
            // A pause that will lift: retryable, and not `NotFound` ("nothing there").
            yadorilink_root_authority::RootAuthorityError::Quiescing(msg) => {
                SyncError::Io(std::io::Error::other(msg))
            }
            // Lossless: `yadorilink-local-capture`'s own tests match on
            // `SyncError::AmbiguousLink { .. }` after a round trip through
            // `RootVerificationStatePort`'s `SyncState`/`ReplicaCoordinator`
            // implementation, so this must reconstruct the exact variant, not
            // collapse to a message string the way this conversion's other
            // arms do.
            yadorilink_root_authority::RootAuthorityError::AmbiguousLink {
                group_id,
                local_paths,
            } => SyncError::AmbiguousLink { group_id, local_paths },
        }
    }
}

/// The reverse direction: `impl RootVerificationStatePort for
/// ReplicaCoordinator` (`replica_coordinator/materialization_state.rs`)
/// calls straight through to `ReplicaCoordinator`'s own already-`SyncError`-
/// returning methods, so its trait methods (which must return
/// `Result<_, RootAuthorityError>`) need this conversion at their own
/// `?`-propagation sites. Allowed under Rust's orphan rules despite
/// `RootAuthorityError` being a foreign type: `SyncError`, the trait's local
/// type parameter, is what makes this impl local to this crate.
impl From<SyncError> for yadorilink_root_authority::RootAuthorityError {
    fn from(err: SyncError) -> Self {
        use yadorilink_root_authority::RootAuthorityError as E;
        match err {
            SyncError::Io(e) => E::Io(e),
            SyncError::NotFound(msg) => E::NotFound(msg),
            SyncError::AmbiguousLink { group_id, local_paths } => {
                E::AmbiguousLink { group_id, local_paths }
            }
            SyncError::ReservedNamespaceCollision(msg) => E::ReservedNamespaceCollision(msg),
            SyncError::OwnershipLost(msg) => E::OwnershipLost(msg),
            other => E::CorruptState(other.to_string()),
        }
    }
}

/// `impl MaterializationExecutionPort for ReplicaCoordinator`
/// (`replica_coordinator/materialization_execution.rs`) calls straight
/// through to `ReplicaCoordinator`'s own already-`SyncError`-returning
/// methods, so its trait methods (which must return `Result<_,
/// yadorilink_filesystem_sync::materialization_execution::
/// MaterializationExecutionError>`) need this conversion at their own
/// `?`-propagation sites. Allowed under Rust's orphan rules despite
/// `MaterializationExecutionError` being a foreign type: `SyncError`, the
/// trait's local type parameter, is what makes this impl local to this
/// crate. Mirrors `From<SyncError> for RootAuthorityError` above.
impl From<SyncError>
    for yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError
{
    fn from(err: SyncError) -> Self {
        use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError as E;
        match err {
            SyncError::Io(e) => E::Io(e),
            SyncError::Storage(e) => E::from(e),
            SyncError::NotFound(msg) => E::NotFound(msg),
            SyncError::CorruptState(msg) => E::CorruptState(msg),
            SyncError::EvictionRejected(msg) => E::EvictionRejected(msg),
            SyncError::EvictionOutcomeAmbiguous(msg) => E::EvictionOutcomeAmbiguous(msg),
            SyncError::PathEscapesRoot(msg) => E::PathEscapesRoot(msg),
            SyncError::DiskPressure { path, volume, available_bytes, headroom_bytes } => {
                E::DiskPressure { path, volume, available_bytes, headroom_bytes }
            }
            SyncError::PolicyUnavailable => E::PolicyUnavailable,
            SyncError::OwnershipLost(msg) => {
                E::RootAuthority(yadorilink_root_authority::RootAuthorityError::OwnershipLost(msg))
            }
            other => E::CorruptState(other.to_string()),
        }
    }
}

/// The reverse direction: any caller of the `evict_file`-family functions
/// (which live in `yadorilink-filesystem-sync` and return
/// `MaterializationExecutionError`) that still needs a plain `SyncError`
/// (e.g. `?`-propagating into a function whose own signature predates this
/// port) converts here, losslessly for every variant this type already
/// carries an equivalent for.
impl From<yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError>
    for SyncError
{
    fn from(
        err: yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError,
    ) -> Self {
        use yadorilink_filesystem_sync::materialization_execution::MaterializationExecutionError as E;
        match err {
            E::Io(e) => SyncError::Io(e),
            E::NotFound(msg) => SyncError::NotFound(msg),
            E::CorruptState(msg) => SyncError::CorruptState(msg),
            E::EvictionRejected(msg) => SyncError::EvictionRejected(msg),
            E::EvictionOutcomeAmbiguous(msg) => SyncError::EvictionOutcomeAmbiguous(msg),
            // The same outcome access hydration reports for attributes it set
            // but could not confirm: no proof, retry later.
            E::ReplicatedXattrsNotProven(msg) => SyncError::HydrationFailed(msg),
            E::PolicyUnavailable => SyncError::PolicyUnavailable,
            E::PathEscapesRoot(msg) => SyncError::PathEscapesRoot(msg),
            E::DiskPressure { path, volume, available_bytes, headroom_bytes } => {
                SyncError::DiskPressure { path, volume, available_bytes, headroom_bytes }
            }
            E::Storage(e) => SyncError::from(e),
            E::RootAuthority(e) => SyncError::from(e),
        }
    }
}

/// `watcher.rs`'s real implementation lives at
/// `yadorilink_filesystem_sync::watcher`; its `WatcherError` cannot itself be
/// `SyncError` (that crate cannot depend back on this one), so any caller
/// that still needs `SyncError` converts here, losslessly -- this reproduces
/// exactly the `SyncError::Io`/`SyncError::Watch` split
/// (`std::io::Error` via `SyncError::from`, `WatchError` via the same
/// `#[from]`-derived path), just crossing one extra conversion step.
impl From<yadorilink_filesystem_sync::watcher::WatcherError> for SyncError {
    fn from(err: yadorilink_filesystem_sync::watcher::WatcherError) -> Self {
        use yadorilink_filesystem_sync::watcher::WatcherError as E;
        match err {
            E::Io(e) => SyncError::Io(e),
            E::Watch(e) => SyncError::Watch(e),
        }
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for SyncError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            SyncError::Db(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}

impl From<yadorilink_local_storage::StorageError> for SyncError {
    fn from(err: yadorilink_local_storage::StorageError) -> Self {
        match err {
            yadorilink_local_storage::StorageError::DiskPressure {
                path,
                volume,
                available_bytes,
                headroom_bytes,
            } => SyncError::DiskPressure {
                path: path.display().to_string(),
                volume: volume.display().to_string(),
                available_bytes,
                headroom_bytes,
            },
            yadorilink_local_storage::StorageError::PathEscapesRoot(path) => {
                SyncError::PathEscapesRoot(path)
            }
            // `chunker::chunk_file`/`chunk_file_content_defined` (in
            // `yadorilink-local-storage`) -- these two map back onto this
            // type's own pre-existing `Hex`/`Chunking` variants (rather than
            // the generic `Storage` wrapper) so `SyncError::category()` and
            // every existing match on these variants sees byte-identical
            // behavior.
            yadorilink_local_storage::StorageError::Hex(e) => SyncError::Hex(e),
            yadorilink_local_storage::StorageError::Chunking(s) => SyncError::Chunking(s),
            other => SyncError::Storage(other),
        }
    }
}

#[cfg(test)]
mod tests;
