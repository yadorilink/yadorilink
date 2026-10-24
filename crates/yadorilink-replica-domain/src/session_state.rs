// apple-cfg-file: macos-only only macOS has a provider adapter today; an iOS build refuses provider links until it has one
//! Pure value types describing a link's write-gate state, a hydration
//! hold, materialization state/policy, a startup-readiness failure, and a
//! current-version snapshot.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::file::{BlockInfo, FileRecord, FileVersion, RecordKind, VersionBlock};
use crate::ids::VersionHash;
use crate::local_op::Op;
use crate::native_state::NativeCaptureWitness;

fn unknown_persisted_enum(kind: &str, value: &str) -> ! {
    panic!("corrupt local state: unknown persisted {kind} value {value:?}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationState {
    /// No local object exists in the user tree for this path.
    Remote,
    /// A local object is being produced.
    Hydrating,
    /// A physical local object exists. This does NOT mean the object equals
    /// the current version: exactness lives in the version and
    /// materialization evidence, never in this state.
    Present,
    /// The local object is being removed.
    Evicting,
}

impl MaterializationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Remote => "remote",
            Self::Hydrating => "hydrating",
            Self::Evicting => "evicting",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "present" => Self::Present,
            "remote" => Self::Remote,
            "hydrating" => Self::Hydrating,
            "evicting" => Self::Evicting,
            other => unknown_persisted_enum("materialization state", other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaterializationPolicy {
    Eager,
    OnDemand,
}

impl MaterializationPolicy {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::OnDemand => "ondemand",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "eager" => Self::Eager,
            "ondemand" => Self::OnDemand,
            other => unknown_persisted_enum("materialization policy", other),
        }
    }
}

/// What serves a root's local copy: a declared, per-root kind (not a global
/// switch). `None` is the direct-filesystem path (Linux, headless, tests) and a
/// permanent declared kind; a provider kind means the OS owns the local copy and
/// the root is usable only while its provider is ready. A kind is never a
/// fallback for another: a not-ready provider root fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    None,
    MacFileProvider,
    /// The Windows Cloud Files (CfAPI) sync root. Like `MacFileProvider` it is an OS adapter
    /// kind, not a sync-model kind: the root is served through the same provider model (root id,
    /// item ids, readiness, publication, fetch gate).
    WindowsCfapi,
    /// The iOS replicated File Provider extension. A kind of its own, not `MacFileProvider`:
    /// the extension, its enumeration and its readiness evidence are a different host
    /// implementation, and the persisted string never has to be reinterpreted later.
    IosFileProvider,
}

impl ProviderKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::MacFileProvider => "mac_file_provider",
            Self::WindowsCfapi => "windows_cfapi",
            Self::IosFileProvider => "ios_file_provider",
        }
    }

    /// The provider kind this build's operating system serves, or `None` where the OS has no
    /// provider adapter (such a platform refuses provider links). iOS has its own kind.
    pub const fn for_host_platform() -> Option<Self> {
        // apple-cfg: ios-explicit iOS serves its own File Provider kind
        if cfg!(target_os = "ios") {
            Some(Self::IosFileProvider)
        } else if cfg!(target_vendor = "apple") {
            Some(Self::MacFileProvider)
        } else if cfg!(windows) {
            Some(Self::WindowsCfapi)
        } else {
            None
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "none" => Self::None,
            "mac_file_provider" => Self::MacFileProvider,
            "windows_cfapi" => Self::WindowsCfapi,
            "ios_file_provider" => Self::IosFileProvider,
            other => unknown_persisted_enum("provider kind", other),
        }
    }
}

/// Why a provider root is not ready.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotReady {
    /// The host has not reported the domain registered (or reported it removed).
    DomainNotRegistered,
    /// Registered, but the extension has not completed a handshake since: the
    /// first-run state ("enable File Provider").
    ExtensionNotEnabled,
    /// The extension reported an explicit, fatal provider condition.
    ProviderError(String),
}

/// A root's provider readiness, from persisted evidence only (no timers).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Readiness {
    Ready,
    NotReady(NotReady),
}

/// Whether a folder group's link currently accepts peer-applied writes at
/// all. No permissive default: a caller that wants to write must match
/// [`LinkGate::Live`] and thereby prove a live link exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkGate {
    /// A live, unpaused, non-orphaned link. `local_path` is the root the
    /// apply must write under.
    Live { local_path: String, policy: MaterializationPolicy },
    /// A live link the user paused. Pause stops both directions, but is
    /// reversible and leaves the link -- and its root -- in place.
    Paused { local_path: String },
    /// No live link for this group on this device: never linked, unlinked,
    /// or orphaned. The apply must not touch the filesystem.
    NoLiveLink,
}

/// Which of a path's retained rows this one is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionState {
    /// The live version of the file at this path right now (or, if the
    /// file is deleted, the tombstone itself).
    Current,
    /// A version this file had before a later edit (local or adopted)
    /// superseded it.
    Superseded,
    /// The file's last live content before it was deleted — recoverable
    /// via `trash restore` until retention expires.
    Trashed,
}

impl VersionState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            VersionState::Current => "current",
            VersionState::Superseded => "superseded",
            VersionState::Trashed => "trashed",
        }
    }

    /// Strict: an unrecognized persisted state is corruption, not a
    /// `Current` row. Coercing it to `Current` would promote an
    /// unparseable row to the live version of its path.
    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "current" => Ok(VersionState::Current),
            "superseded" => Ok(VersionState::Superseded),
            "trashed" => Ok(VersionState::Trashed),
            other => Err(format!("unknown version state: {other}")),
        }
    }
}

/// One retained version of a file, as returned by `SyncState::list_versions`/
/// `SyncState::get_version` — the CLI's `yadorilink versions <path>` and the
/// restore engine's per-version lookup.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionRecord {
    pub path: String,
    pub version_seq: i64,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub blocks: Vec<BlockInfo>,
    pub deleted: bool,
    pub state: VersionState,
    pub origin_device_id: Option<String>,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
    pub version_hash: VersionHash,
}

/// Why a path is held (excluded from materialization-state transitions)
/// and since when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldState {
    pub reason: String,
    pub since_unix_nanos: i64,
}

/// Prefix of a hold recorded against a file that IS on disk: its replicated
/// metadata cannot be confirmed or applied because the existing file denies
/// its owner read access. Unlike a hazard hold, nothing was withheld from
/// the path's name.
pub const HELD_REASON_METADATA_UNPROVABLE: &str = "metadata_unprovable";

impl HeldState {
    /// Whether this hold means this device deliberately keeps nothing on
    /// disk under the path's name (a hazard hold, such as a name collision),
    /// so a missing file there must not be read as a deletion. A
    /// metadata-unprovable hold is recorded against a file that was present,
    /// so that file's disappearance is a real deletion.
    pub fn keeps_the_name_empty(&self) -> bool {
        !self.reason.starts_with(HELD_REASON_METADATA_UNPROVABLE)
    }
}

/// The `state = 'current'` row of a file, read as one atomic statement --
/// every column a `FileVersion` identity binds, from a single coherent row
/// so the derived `change::VersionHash` can never be a torn hybrid of two
/// rows.
#[derive(Debug, Clone, PartialEq)]
pub struct CurrentVersionRecord {
    pub blocks: Vec<BlockInfo>,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub deleted: bool,
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub unix_mode: Option<u32>,
    pub xattrs: Vec<(String, Vec<u8>)>,
}

impl CurrentVersionRecord {
    /// Reconstructs the exact `FileVersion` this current row describes and
    /// derives its `change::VersionHash` via `FileVersion::compute_hash()`.
    /// Because every field came from one atomic read, the returned identity
    /// is always one a single row actually held.
    pub fn to_file_version(&self) -> FileVersion {
        FileVersion::from_index_row(
            self.blocks.clone(),
            self.size,
            self.mtime_unix_nanos,
            self.record_kind,
            self.unix_mode,
            self.symlink_target.clone(),
            self.xattrs.clone(),
        )
    }
}

/// Returned when a group's latest startup ended in `Failed`. Peer-apply
/// callers must treat this as "do NOT admit the change" (defer / skip),
/// never as permission to apply against the half-built index a failed
/// startup left behind.
#[derive(Clone, Debug)]
pub struct StartupFailed {
    pub group_id: String,
    pub reason: String,
}

impl std::fmt::Display for StartupFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "group {} startup did not complete: {}", self.group_id, self.reason)
    }
}

impl std::error::Error for StartupFailed {}

/// One path's fully-prepared local mutation for a bounded batched commit
/// (`commit_local_mutations_batch`) — content already read, chunked, and
/// hashed; the `FileRecord`/`Op`/`FileVersion`/metadata it will become
/// already decided; not yet written anywhere. Deliberately minimal: no
/// lock, no disk fingerprint, no staleness bookkeeping — those require a
/// filesystem/tokio dependency this crate does not have, so
/// `yadorilink-local-capture` (which prepares these and knows the caller's
/// per-path lock) owns that half, revalidating a mutation is still current
/// before including it in a batch. Each variant still becomes its own
/// signed change when committed — a batch of N of these must never
/// collapse into one multi-op change (that changes causal/apply
/// granularity for what were N independent local edits).
///
/// `native_witness` is what native state showed at `record.path` when the
/// mutation was prepared: a commit refuses the mutation when the row no
/// longer shows it, since a head that replaced the row in between was never
/// seen by the writer and must not be superseded.
#[derive(Debug, Clone)]
pub enum PreparedLocalMutation {
    Upsert {
        record: FileRecord,
        op: Op,
        version: FileVersion,
        meta: Option<LocalFileMetaColumns>,
        native_witness: Option<NativeCaptureWitness>,
    },
    Delete {
        record: FileRecord,
        op: Op,
        native_witness: Option<NativeCaptureWitness>,
    },
}

impl PreparedLocalMutation {
    pub fn record(&self) -> &FileRecord {
        match self {
            PreparedLocalMutation::Upsert { record, .. } => record,
            PreparedLocalMutation::Delete { record, .. } => record,
        }
    }

    /// The op this mutation authors.
    pub fn op(&self) -> &Op {
        match self {
            PreparedLocalMutation::Upsert { op, .. } => op,
            PreparedLocalMutation::Delete { op, .. } => op,
        }
    }

    /// What native state showed at `record.path` when the mutation was
    /// captured. The commit refuses the mutation when the row no longer
    /// shows it. `None` means no earlier observation exists (the commit
    /// then reads the row as it stands in its own transaction).
    pub fn native_witness(&self) -> Option<&NativeCaptureWitness> {
        match self {
            PreparedLocalMutation::Upsert { native_witness, .. } => native_witness.as_ref(),
            PreparedLocalMutation::Delete { native_witness, .. } => native_witness.as_ref(),
        }
    }
}

/// The local-only per-file metadata columns a local content emission writes
/// alongside its `FileRecord`. Folded into the emitting transaction (rather
/// than applied as separate post-commit `set_record_kind`/`set_symlink_*`/
/// `set_unix_mode` updates) so the materialized index row can never lag the
/// `FileVersion` the emitted change carries across a crash between the
/// commit and the setters. The kind/target/exec-bit values mirror exactly
/// the [`crate::file::FileMeta`] the emitted `FileVersion` carries;
/// `symlink_out_of_root` is an additional purely-local classification
/// never sent on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalFileMetaColumns {
    pub record_kind: RecordKind,
    pub symlink_target: Option<Vec<u8>>,
    pub symlink_out_of_root: bool,
    pub unix_mode: Option<u32>,
    /// See `FileMeta::xattrs`'s own doc comment -- already sorted by
    /// name and filtered to the capture-side allow-list by the caller.
    pub xattrs: Vec<(String, Vec<u8>)>,
}

impl LocalFileMetaColumns {
    /// The columns a row shows for the version whose metadata is `meta`. A
    /// version does not carry the out-of-root flag (advisory, never gated
    /// on), so it is recorded as false.
    pub fn from_version_meta(meta: &crate::file::FileMeta) -> Self {
        Self {
            record_kind: meta.record_kind,
            symlink_target: meta.symlink_target.clone(),
            symlink_out_of_root: false,
            unix_mode: meta.unix_mode,
            xattrs: meta.xattrs.clone(),
        }
    }
}

/// One user-recoverable durability root — one retained version at `path`
/// (current, superseded, or trashed) a full-replica handoff must be able to
/// hand off. `version_hash` is the [`crate::local_op::VersionHash`] — the
/// SHA-256 of this version's canonical `FileVersion` encoding (its ordered
/// block list with each block's size, its total size, and its metadata:
/// mtime, exec bit, symlink target, record kind) — computed by
/// reconstructing a `FileVersion` from this row via
/// [`FileVersion::from_index_row`] and calling `compute_hash()`. This is
/// the SAME hash used elsewhere to identify a version;
/// durability never invents a separate wire identifier. `blocks` is
/// carried alongside (not folded away once the hash is known) because a
/// peer confirmation still needs the ordered block list — with per-block
/// sizes — for its own explicit block/size check and its `get()`
/// checksum-verification loop. See
/// `SyncState::enumerate_group_durability_roots`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityRoot {
    pub path: String,
    pub blocks: Vec<VersionBlock>,
    pub version_hash: VersionHash,
}

/// The result of `SyncState::enumerate_group_durability_roots`: the full
/// root set plus a stable digest over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityRoots {
    pub roots: Vec<DurabilityRoot>,
    /// SHA-256 over the roots sorted by `(path, version_hash)`. Stable
    /// regardless of the order SQL returns rows in, so two enumerations of
    /// the same underlying set produce the same digest. `version_hash`
    /// binds the ordered block list, each block's size, and the version's
    /// metadata, so a chunk reorder or a metadata-only change (mtime, exec
    /// bit, symlink target, record kind) changes the digest exactly as it
    /// changes the version identity a peer confirms against. See
    /// `yadorilink_sync_sqlite::file_index::durability_roots_digest`.
    pub digest: [u8; 32],
}

/// Canonicalizes `roots` and hashes the length-prefixed concatenation.
/// Order-independence is applied only ACROSS roots (sorted by `(path,
/// version_hash)`), so the caller's collection order does not affect the
/// digest. Each root's identity is its `version_hash` alone — the SHA-256 of
/// its canonical `FileVersion` encoding, which already binds the ordered
/// block list, each block's declared size, and the version's metadata, so
/// any real change to the underlying content or metadata (including a block
/// reorder) changes `version_hash` and therefore this digest. This is the
/// property the digest re-confirm before a daemon-driven role-loss commit
/// relies on: the same underlying set (same paths, same per-file version
/// identities) always digests the same, and any real change changes it.
pub fn durability_roots_digest(roots: &[DurabilityRoot]) -> [u8; 32] {
    let mut canonical: Vec<(&str, &[u8; 32])> =
        roots.iter().map(|r| (r.path.as_str(), r.version_hash.as_bytes())).collect();
    canonical.sort_unstable_by(|a, b| a.0.cmp(b.0).then_with(|| a.1.cmp(b.1)));

    let mut hasher = Sha256::new();
    for (path, version_hash) in &canonical {
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(version_hash.as_slice());
    }
    hasher.finalize().into()
}

/// A group's durable state reduced to what fits in one message: two
/// digests, three counts, and the generation the reduction was taken at.
///
/// This is what a background custody check exchanges instead of one
/// round-trip per durability root. Every field comes from the `files`
/// index — no block is read and no payload is hashed to produce one — which
/// is exactly the difference between the background check and the handoff
/// proof, and the reason the two must never be confused.
///
/// # What comparing two of these establishes, and what it does not
///
/// **`current_digest` is the field a positive rests on**, over
/// `state = 'current'` alone. That is the set the sync protocol actually
/// converges on, so two caught-up replicas agree about it, and disagreement
/// means something real.
///
/// **`roots_digest` covers the full durability-root set — current plus
/// retained superseded plus trash-restorable — and equality on it is NOT
/// expected**, so nothing requires it. Two honest eager replicas routinely
/// retain different history and go on doing so indefinitely:
///
/// * a device that links a group it did not originate starts from a local
///   history floor, and never reconstructs versions from before it;
/// * retention expiry keeps a version while it is within *either* the
///   count bound or the age bound, so a version inside the count bound is
///   retained forever no matter how old it gets — a device holding one
///   extra historical version of an untouched file keeps it permanently;
/// * `version_seq` is device-local, expiry runs on each device's own
///   clock, and each device's outstanding handoff leases pin different
///   rows.
///
/// Requiring `roots_digest` equality would therefore have made the common
/// two-device topology — one device joins a folder another already had —
/// permanently uncorroborated. It is carried as an *observation*: when it
/// does match, more is true, and that is worth recording and reporting.
/// The handoff proof still covers the whole root set, at the moment it
/// matters.
///
/// `unmaterialized_current_count` is what stops the comparison from being
/// vacuous. A `files` row exists as soon as its change is projected, long
/// before the content behind it has been fetched — so a peer that has
/// caught up on metadata and downloaded nothing at all has an identical
/// `current_digest`. Without this count, a second device that joined a
/// minute ago and is still transferring would corroborate instantly, and
/// the group would report itself protected while exactly one device held
/// the data.
///
/// It is a **working-tree fact standing in for a block-store one**, and
/// that substitution is deliberate. Durability is about whether a peer's
/// block store holds the bytes; materialization is about whether that peer
/// has written them out into its folder. For an eager replica the second
/// implies the first, so this is sufficient — and it is not necessary: a
/// peer mid-hydration holds every block and still reports rows
/// unmaterialized, and will not be corroborated until it finishes.
///
/// That error direction is the reason for the choice. A false negative here
/// costs a transient `Unknown` on a group that is, accurately, still being
/// taken custody of. The alternative — asking the block store directly
/// whether it holds every current root's blocks — answers the exact
/// question, but its answer changes without any `files` write, so
/// [`Self::generation`] would not invalidate a memo of it and a stale hit
/// would be a false *positive*. That is the one direction this whole design
/// exists to exclude, and buying precision with it is not a trade worth
/// making for a health indicator.
///
/// Even with it, this remains an index-level claim the peer makes about
/// itself: it says the peer believes it has the content, not that the bytes
/// are on its disk and intact. Only the handoff proof establishes that, and
/// only latent-corruption scrubbing looks for it at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootSetSummary {
    /// Over `state = 'current'` alone — the convergent subset, and the only
    /// digest a positive may rest on.
    pub current_digest: [u8; 32],
    pub current_count: u64,
    /// How many `state = 'current'` rows are not yet `Present` — still a
    /// placeholder, or mid-hydration. Non-zero means the device this
    /// summary describes does not yet hold all of the group's current
    /// content, whatever its index lists.
    pub unmaterialized_current_count: u64,
    /// Over `state IN ('current', 'superseded', 'trashed')`, the full
    /// durability-root set: the same digest function, over the same rows,
    /// that the handoff proof enumerates. An observation, never a
    /// requirement — see this type's own doc comment for why equality here
    /// is not an invariant between honest replicas.
    pub roots_digest: [u8; 32],
    pub roots_count: u64,
    /// The `file_root_set_generation` counter this summary was computed at,
    /// on the device that computed it.
    ///
    /// Meaningful only to that device. A remote peer's value is recorded
    /// for diagnostics and is never compared, never used as a freshness
    /// bound, and never an input to whether a reply is trusted: a number a
    /// peer reports about its own state, inside a window that peer also
    /// controls, establishes nothing. Freshness belongs to the asking side
    /// — its own monotonic clock, its own membership generation, and its
    /// own re-derivation of its own digest.
    pub generation: u64,
}

impl RootSetSummary {
    /// Whether every current row on the device this describes is
    /// materialized locally.
    pub fn fully_materialized(&self) -> bool {
        self.unmaterialized_current_count == 0
    }
}

/// spec "CLI Trash Commands": one deleted-but-still-recoverable file, as
/// returned by `SyncState::list_trashed`.
#[derive(Debug, Clone, PartialEq)]
pub struct TrashedFile {
    pub path: String,
    /// The `version_seq` of the retained last-live-content row — what
    /// `trash restore` restores to by default.
    pub version_seq: i64,
    pub last_known_size: u64,
    pub origin_device_id: Option<String>,
    /// When the deletion itself (the tombstone's own `current` row) was
    /// recorded.
    pub deleted_at_unix_nanos: i64,
    /// The recursive delete or directory rename this deletion was a part
    /// of, when it was one: every trashed file sharing it was removed by
    /// the same user operation, and restoring the folder restores them
    /// together.
    pub deleted_by_operation: Option<crate::recursive_operation::RecursiveOperationRef>,
    /// The kind of the trashed (last live) version.
    pub record_kind: crate::file::RecordKind,
}

/// One currently-live conflicted-copy file, as returned by
/// `SyncState::list_live_conflict_copies` — the single source of truth
/// both `FileHistoryQueryService::list_conflicts` and
/// `LinkStatusReadPort::list_links`'s `conflict_count` read from, so the
/// two can never disagree about which paths count.
#[derive(Debug, Clone, PartialEq)]
pub struct ConflictCopyFile {
    pub path: String,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    pub record_kind: crate::file::RecordKind,
}

/// One journaled local edit awaiting durable processing into the index +
/// replicated state — see the `local_dirty_paths` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirtyPath {
    pub path: String,
    pub change_kind: String,
    pub observed_at_unix_nanos: i64,
    pub attempts: u32,
}

/// The fields of a role-loss operation row not already carried by its
/// `(operation_id, group_id)` key.
pub struct RoleLossOperationParams<'a> {
    pub source_device_id: &'a str,
    pub target_device_id: &'a str,
    /// Required: a journal row without the lease it was opened against
    /// cannot be compensated, so there is no useful row to write.
    pub lease_id: &'a str,
    pub action: RoleLossAction,
    pub local_path: Option<&'a str>,
    pub now_unix: i64,
}

/// Where a link's content lives. A folder link has a real directory; a provider link has none (its
/// authority is the group and the OS-managed domain), so it can NEVER yield a path: the only way to
/// get one is [`FolderLink::folder_path`], which is `None` for a provider link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkLocation {
    Folder(String),
    /// The synthetic key of a provider link (never a path) and the root it declared.
    Provider {
        locator: String,
        root_id: String,
    },
}

impl LinkLocation {
    /// The directory, for a folder link only.
    pub fn folder_path(&self) -> Option<&str> {
        match self {
            Self::Folder(path) => Some(path),
            Self::Provider { .. } => None,
        }
    }

    /// The link's identity string (the `links` key): a path for a folder link, the locator for a
    /// provider link. For display and keying only, NEVER for a filesystem call.
    pub fn key(&self) -> &str {
        match self {
            Self::Folder(path) => path,
            Self::Provider { locator, .. } => locator,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderLink {
    pub location: LinkLocation,
    pub group_id: String,
    pub paused: bool,
    pub materialization_policy: MaterializationPolicy,
    /// Whether this link's coordination-side authorization has been
    /// confirmed permanently gone (its group/ACL row was cancelled or
    /// removed server-side) -- distinct from `paused`, which is a
    /// reversible, user-chosen sync gate that leaves the coordination-side
    /// authorization intact. Set only once reconciliation confirms the
    /// activation for this link's [`PendingEnrollment`] came back `Deleted`
    /// -- see [`SyncState::mark_link_orphaned`]. An orphaned link's on-disk
    /// files are never touched or deleted; only its participation in sync
    /// stops.
    pub orphaned: bool,
}

impl FolderLink {
    /// The directory of a folder link; `None` for a provider link.
    pub fn folder_path(&self) -> Option<&str> {
        self.location.folder_path()
    }

    /// The `links` key (see [`LinkLocation::key`]).
    pub fn key(&self) -> &str {
        self.location.key()
    }
}

/// What committing a link did to the `links` row for its path, so that a
/// link whose post-commit setup fails can undo exactly that and nothing
/// more. A path that was already linked to the same group is re-linked by
/// updating its existing row (keeping its adopted root token); deleting that
/// row on a failed setup would destroy a link this call never created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRowWrite {
    /// No row existed for the path; the commit inserted it.
    Inserted,
    /// A row for the same path and group already existed; the commit updated
    /// it. Carries the row as it was before, so the columns the commit and
    /// its setup may change can be put back.
    Updated(FolderLink),
}

/// A durable journal row for an in-flight full-replica role-loss operation
/// (demote/unlink) this device is driving as the SOURCE device. Written
/// before the coordination service role-loss commit
/// (`coordination_client::commit_handoff_role_loss`) and only removed once
/// the operation's outcome is fully settled, so a crash — or a local
/// failure landing AFTER the Worker commit already succeeded — is always
/// reconciled automatically instead of left as a silent split state (Worker
/// thinks this device demoted; local storage still thinks it's eager).
///
/// State machine:
///
/// ```text
/// Prepared ──(Worker returns definite 4xx rejection)──> [row deleted]
///     │
///     │ (Worker commit succeeds OR response is ambiguous/lost)
///     v
/// WorkerCommitted/Prepared ──(local commit succeeds)──> LocalCommitted ──> [row deleted]
///     │
///     │ (local commit fails: digest mismatch or a storage error)
///     v
/// Compensating ──(Worker revert succeeds)──> Completed ──> [row deleted]
///     │
///     │ (Worker revert fails / unreachable)
///     v
/// Compensating (retried by the reconciliation sweep, never abandoned)
/// ```
///
/// `LocalCommitted` and `Completed` are terminal and are deleted
/// immediately after being written on the normal path; they only persist
/// across a restart if the process crashed in the narrow window between
/// that write and the follow-up delete, in which case the reconciliation
/// sweep's own handling of them is a plain delete (see that sweep's doc
/// comment) — the operation's real outcome was already reached by the
/// preceding write.
#[derive(Debug, Clone, PartialEq)]
pub struct RoleLossOperation {
    pub operation_id: String,
    pub group_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub lease_id: String,
    pub worker_membership_generation: Option<i64>,
    pub action: RoleLossAction,
    pub state: RoleLossOperationState,
    /// The local link path this operation concerns, when known (unlink
    /// always has one; demote does too, since it also flips a specific
    /// link's materialization policy).
    pub local_path: Option<String>,
    pub attempts: i64,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Which local operation this device was performing when it drove the
/// Worker-side role-loss commit — recorded for diagnosis/logging.
/// `commit_handoff_role_loss`'s Worker-side statement is `"demote"` for
/// both `Demote` and `Unlink` today (both only narrow this device's
/// `storage_mode` to on-demand; unlink does not remove group membership),
/// so both compensate identically — reverting `storage_mode` back to
/// `eager` — see the daemon's `ReplicaRoleService::compensate_role_loss_operation`. `Revoke`
/// is reserved for `durability_force`'s cross-device removal path, which
/// this change does not wire to this journal (that path still uses the
/// pre-existing plain `/revoke` call, not `commit_handoff_role_loss`); a
/// row is never written with this action today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossAction {
    Demote,
    Unlink,
    Revoke,
}

impl RoleLossAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RoleLossAction::Demote => "demote",
            RoleLossAction::Unlink => "unlink",
            RoleLossAction::Revoke => "revoke",
        }
    }

    /// An unrecognized action is corruption. There is deliberately no
    /// lenient counterpart: the previous one coerced anything unknown to
    /// `Demote`, so a row the code could not parse still drove a
    /// destructive action.
    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "demote" => Ok(RoleLossAction::Demote),
            "unlink" => Ok(RoleLossAction::Unlink),
            "revoke" => Ok(RoleLossAction::Revoke),
            other => Err(format!("unknown role-loss action: {other}")),
        }
    }
}

/// Which state a [`RoleLossOperation`] is in — see its doc comment for the
/// full state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossOperationState {
    /// Journal row written; the coordination service role-loss commit has
    /// not yet been attempted (or its outcome is not yet known to this
    /// process — e.g. a crash mid-request). The reconciliation sweep
    /// treats a `Prepared` row found at startup the same as
    /// `WorkerCommitted`: it cannot locally distinguish "the request never
    /// reached the Worker" from "it reached and committed but the reply
    /// was lost", and asserting `eager` on the Worker is safe either way
    /// (a no-op if the Worker never committed, a correcting revert if it
    /// did) — see that sweep's doc comment.
    Prepared,
    /// The coordination service role-loss commit succeeded; the matching
    /// local policy/link change has not yet been attempted (or its outcome
    /// is not yet known — the crash-between-Worker-commit-and-local-commit
    /// case the whole journal exists for).
    WorkerCommitted,
    /// The local policy/link change also succeeded — the operation
    /// completed normally. Terminal; the row is deleted immediately after
    /// this state is written.
    LocalCommitted,
    /// The local change failed (digest mismatch or a storage error) after
    /// the Worker commit already succeeded; a compensating revert (Worker
    /// `storage_mode` back to `eager`) is in flight or pending retry.
    /// Never abandoned: the reconciliation sweep retries a `Compensating`
    /// row indefinitely until the revert is confirmed.
    Compensating,
    /// The compensating revert succeeded — the split state was corrected
    /// and the source device is confirmed `eager` again, both locally and
    /// on the Worker. Terminal; the row is deleted immediately after this
    /// state is written.
    Completed,
}

impl RoleLossOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            RoleLossOperationState::Prepared => "prepared",
            RoleLossOperationState::WorkerCommitted => "worker_committed",
            RoleLossOperationState::LocalCommitted => "local_committed",
            RoleLossOperationState::Compensating => "compensating",
            RoleLossOperationState::Completed => "completed",
        }
    }

    /// An unrecognized state is corruption -- see
    /// [`RoleLossAction::try_from_db_str`].
    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "prepared" => Ok(RoleLossOperationState::Prepared),
            "worker_committed" => Ok(RoleLossOperationState::WorkerCommitted),
            "local_committed" => Ok(RoleLossOperationState::LocalCommitted),
            "compensating" => Ok(RoleLossOperationState::Compensating),
            "completed" => Ok(RoleLossOperationState::Completed),
            other => Err(format!("unknown role-loss operation state: {other}")),
        }
    }
}

/// A durable journal row for an account-membership operation this device
/// drives against ANOTHER device (revoke from one group, or remove from the
/// whole account) — see the `membership_operations` table's own migration
/// comment for the full rationale. One row can span several groups at once
/// (account-wide removal), unlike [`RoleLossOperation`]; `group_ids`,
/// `target_device_ids`, and `lease_ids` are index-parallel.
#[derive(Debug, Clone, PartialEq)]
pub struct MembershipOperation {
    pub operation_id: String,
    pub action: MembershipOperationAction,
    pub commit_mode: MembershipCommitMode,
    pub removed_device_id: String,
    pub group_ids: Vec<String>,
    pub target_device_ids: Vec<String>,
    pub lease_ids: Vec<Option<String>>,
    pub state: MembershipOperationState,
    /// Whether the set of folder groups this operation puts at risk is
    /// known -- separate from `state` (which tracks only the REMOTE
    /// mutation's own outcome). A `--force` removal whose eager-group
    /// enumeration failed is `Unknown` regardless of what its remote
    /// mutation is currently doing (`Prepared`, `Ambiguous`, ...); an
    /// ordinary ticket-bound or plain mutation is always `Known`. Remote
    /// outcome and durability scope are deliberately separate concepts.
    pub durability_scope: MembershipDurabilityScope,
    /// Folder groups to latch [`GroupDurabilityStatus::Unknown`]
    /// once (and only once) this operation's remote mutation is CONFIRMED
    /// committed -- never latched pre-commit, so a definitely-rejected or
    /// conflicting mutation never leaves a false-positive latch behind.
    /// Empty for every mode except a `--force` plain revoke/remove that
    /// proceeded past a KNOWN but unready set of groups (unrelated to
    /// `durability_scope`, which tracks the separate "the group LIST itself
    /// is unknown" case).
    pub latch_group_ids: Vec<String>,
    pub last_error: Option<String>,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOperationAction {
    Revoke,
    RemoveDevice,
}

impl MembershipOperationAction {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipOperationAction::Revoke => "revoke",
            MembershipOperationAction::RemoveDevice => "remove-device",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "revoke" => Ok(MembershipOperationAction::Revoke),
            "remove-device" => Ok(MembershipOperationAction::RemoveDevice),
            other => Err(format!("unknown membership operation action: {other}")),
        }
    }
}

/// Which remote request shape a [`MembershipOperation`] row's commit
/// actually sends -- distinct from `action` (which side of membership
/// changed) because the SAME action can be driven two different ways
/// (e.g. `Revoke` via a plain unguarded call or via a ticket/lease-guarded
/// one). A reconciler that needs to resend the original request (see
/// `membership_operations`' own migration comment on the Worker side)
/// needs this to know which endpoint/body shape to reconstruct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipCommitMode {
    /// `POST /shares/groups/:groupId/revoke` -- no ticket/lease.
    PlainRevoke,
    /// `POST /shares/groups/:groupId/handoff/commit` (action `"revoke"`) --
    /// ticket/lease-guarded, single group.
    GuardedRevoke,
    /// `DELETE /devices/:deviceId` -- no ticket/lease, no group list
    /// (unverified or verified-empty scope).
    PlainRemoveDevice,
    /// `POST /devices/:deviceId/handoff-remove` -- one ticket/lease per
    /// group, all-or-nothing.
    HandoffRemoveDevice,
}

impl MembershipCommitMode {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipCommitMode::PlainRevoke => "plain-revoke",
            MembershipCommitMode::GuardedRevoke => "guarded-revoke",
            MembershipCommitMode::PlainRemoveDevice => "plain-remove-device",
            MembershipCommitMode::HandoffRemoveDevice => "handoff-remove-device",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "plain-revoke" => Ok(MembershipCommitMode::PlainRevoke),
            "guarded-revoke" => Ok(MembershipCommitMode::GuardedRevoke),
            "plain-remove-device" => Ok(MembershipCommitMode::PlainRemoveDevice),
            "handoff-remove-device" => Ok(MembershipCommitMode::HandoffRemoveDevice),
            other => Err(format!("unknown membership commit mode: {other}")),
        }
    }
}

/// Whether the blast radius (which folder groups) a [`MembershipOperation`]
/// puts at risk is known. See [`MembershipOperation::durability_scope`]'s
/// own doc comment for why this is tracked separately from `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipDurabilityScope {
    Known,
    Unknown,
}

impl MembershipDurabilityScope {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipDurabilityScope::Known => "known",
            MembershipDurabilityScope::Unknown => "unknown",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "known" => Ok(MembershipDurabilityScope::Known),
            "unknown" => Ok(MembershipDurabilityScope::Unknown),
            other => Err(format!("unknown membership durability scope: {other}")),
        }
    }
}

/// Which state a [`MembershipOperation`]'s REMOTE mutation is in -- see
/// [`MembershipOperation::durability_scope`] for the separate blast-radius
/// axis.
///
/// ```text
/// Prepared ── (commit outcome could not be confirmed) ──> Ambiguous
///     │                                                        │
///     │                                     (a later lookup/resend resolves it)
///     v                                                        v
/// Committed, but a post-commit local            Completed / DefinitelyRejected
/// step (e.g. a force latch) failed:                    (row deleted)
///     v
/// LocalSettlementPending ── (retried by the next sweep) ──> Completed
///
/// A local/remote request-identity mismatch, a malformed journal row, or an
/// operation_id conflict moves a row to RecoveryBlocked instead of any of
/// the above -- never settled automatically, always left for operator
/// attention.
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipOperationState {
    /// The journal row has been durably written; the coordination-plane
    /// commit itself has not yet been attempted (or its outcome is not yet
    /// known to this process — e.g. a crash mid-request). Written BEFORE
    /// the commit call, so a crash between "Worker received the commit" and
    /// "daemon advances this row" still leaves a `Prepared` row behind
    /// rather than nothing at all — mirrors
    /// [`RoleLossOperationState::Prepared`]'s own reasoning exactly.
    Prepared,
    /// The coordination-plane commit's outcome could not be confirmed
    /// (transport failure, 5xx, or an unparseable success body) — it may
    /// already have committed. Tickets stay held and the caller must not
    /// fall through to a plain revoke/remove until this is resolved.
    Ambiguous,
    /// The remote mutation is confirmed committed, but a REQUIRED local
    /// follow-up (e.g. latching a forced group's durability as unknown)
    /// failed and must be retried -- the row must not be discarded until
    /// that local step also succeeds.
    LocalSettlementPending,
    /// The operation is confirmed to have completed on the coordination
    /// plane. Terminal; the row is deleted once observed.
    Completed,
    /// The operation is confirmed to have been rejected before any commit
    /// happened. Terminal; the row is deleted once observed.
    DefinitelyRejected,
    /// Automatic recovery has been refused: an operation_id conflict, a
    /// local/remote request-identity mismatch, or a malformed journal row.
    /// Excluded from periodic resend/settlement; requires operator
    /// attention to clear.
    RecoveryBlocked,
}

impl MembershipOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            MembershipOperationState::Prepared => "prepared",
            MembershipOperationState::Ambiguous => "ambiguous",
            MembershipOperationState::LocalSettlementPending => "local-settlement-pending",
            MembershipOperationState::Completed => "completed",
            MembershipOperationState::DefinitelyRejected => "definitely_rejected",
            MembershipOperationState::RecoveryBlocked => "recovery-blocked",
        }
    }

    pub fn try_from_db_str(s: &str) -> Result<Self, String> {
        match s {
            "prepared" => Ok(MembershipOperationState::Prepared),
            "ambiguous" => Ok(MembershipOperationState::Ambiguous),
            "local-settlement-pending" => Ok(MembershipOperationState::LocalSettlementPending),
            "completed" => Ok(MembershipOperationState::Completed),
            "definitely_rejected" => Ok(MembershipOperationState::DefinitelyRejected),
            "recovery-blocked" => Ok(MembershipOperationState::RecoveryBlocked),
            other => Err(format!("unknown membership operation state: {other}")),
        }
    }
}

/// A `membership_operations` row whose contents could not be decoded --
/// e.g. an unrecognized enum string, or a group/target/lease shape that
/// doesn't match its `commit_mode`. Carries just enough to let the caller
/// mark it `RecoveryBlocked` without ever having successfully parsed it.
#[derive(Debug, Clone)]
pub struct InvalidMembershipOperation {
    pub operation_id: String,
    /// See [`InvalidEnrollmentOperation::raw_state`]'s doc comment.
    pub raw_state: Option<String>,
    pub detail: String,
}

/// The result of scanning `membership_operations` for a set of states: rows
/// that decoded successfully, and rows that didn't -- kept separate so ONE
/// malformed row can never abort recovery for every other, valid row in the
/// same sweep. See [`SyncState::scan_membership_operations_in_states`].
#[derive(Debug, Clone, Default)]
pub struct MembershipOperationScan {
    pub valid: Vec<MembershipOperation>,
    pub invalid: Vec<InvalidMembershipOperation>,
}

/// Which local action opened a `pending_enrollments`/`enrollment_operations`
/// row -- a brand-new folder group (`Create`) or joining one an invitation
/// named (`Join`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollmentKind {
    Create,
    Join,
}

impl EnrollmentKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Join => "join",
        }
    }

    pub fn from_db_str(value: &str) -> Self {
        match value {
            "create" => Self::Create,
            "join" => Self::Join,
            other => unknown_persisted_enum("enrollment kind", other),
        }
    }

    /// Same mapping as [`Self::from_db_str`], but returns `Err` instead of
    /// panicking -- for a caller (the `enrollment_operations` journal) that
    /// must isolate one malformed row to `RecoveryBlocked` rather than
    /// crashing the whole reconciliation sweep on it.
    pub fn try_from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "create" => Ok(Self::Create),
            "join" => Ok(Self::Join),
            other => Err(format!("unknown enrollment kind: {other}")),
        }
    }
}

/// One outstanding local link with an unconfirmed coordination-plane
/// activation -- the crash-safety net for a create/join whose local link
/// is already committed but whose matching server-side activation was
/// never confirmed (the caller was killed in that exact window). Persisted
/// in the same SQLite database as `FolderLink` so the two can be written in
/// a single transaction (`SyncState::add_link_with_pending_enrollment`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEnrollment {
    pub operation_id: String,
    pub kind: EnrollmentKind,
    pub group_id: String,
    pub device_id: String,
    pub local_path: String,
}

/// A `pending_enrollments` row whose contents could not be decoded (an
/// unrecognized `kind` string) -- mirrors [`InvalidEnrollmentOperation`].
#[derive(Debug, Clone)]
pub struct InvalidPendingEnrollment {
    pub operation_id: String,
    pub detail: String,
}

/// The result of scanning `pending_enrollments`: rows that decoded
/// successfully, and rows that didn't -- mirrors [`EnrollmentOperationScan`]
/// so one malformed marker can never abort reconciliation for every other
/// marker in the same sweep.
#[derive(Debug, Clone, Default)]
pub struct PendingEnrollmentScan {
    pub valid: Vec<PendingEnrollment>,
    pub invalid: Vec<InvalidPendingEnrollment>,
}

/// The durable pre-prepare enrollment journal -- opened BEFORE the first
/// coordination-plane prepare call and carrying enough request identity to
/// replay prepare or cancel safely, not just a late `CancelPending`
/// backstop for a `link()` failure. See `enrollment_operations`' own
/// migration comment for the full state-machine rationale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentOperation {
    pub operation_id: String,
    pub kind: EnrollmentKind,
    /// `None` until coordination prepare confirms one (only possible for a
    /// `Create` row still in `PreparePending`; a `Join` row always has one
    /// from the moment its journal row is opened).
    pub group_id: Option<String>,
    /// Only meaningful for a `Create` row in `PreparePending` -- needed to
    /// resend the exact same prepare request. Always `None` for `Join`.
    pub group_name: Option<String>,
    pub device_id: String,
    pub local_path: String,
    /// `"eager"` or `"on-demand"`.
    pub storage_mode: String,
    pub state: EnrollmentOperationState,
    pub last_error: Option<String>,
    pub attempts: i64,
    pub created_at_unix: i64,
    pub updated_at_unix: i64,
}

/// Which stage of the create/join enrollment saga a journal row is in.
///
/// ```text
/// PreparePending ── (prepare confirmed) ──> Prepared
///     │                                         │
///     │                        (link + pending_enrollment commit atomically)
///     │                                         v
///     │                                LocalSetupPending ── (setup confirmed) ──> ActivationPending
///     │                                         │                                        │
///     │                              (setup failed, rolled back)                (activation reconciler
///     │                                         v                                  owns this row now)
///     │                                    CancelPending                                  │
///     │                                         ^                                         │
///     │                                         └──────────── (link/marker lost) ─────────┘
///     │                                                                                    │
///     │                                                                          (row cleanup) ──> (deleted)
///     │
///     └─ (no local link exists) ──> CancelPending ── (cancel confirmed) ──> (deleted)
///
/// A malformed row, an operation_id conflict, or a local/remote identity
/// mismatch moves a row to RecoveryBlocked instead of any of the above --
/// never settled automatically, always left for operator attention.
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentOperationState {
    /// Written before the first coordination prepare call.
    PreparePending,
    /// Coordination prepare is confirmed; `group_id` is known. No local
    /// link handoff has been confirmed yet.
    Prepared,
    /// The local link + `pending_enrollments` marker were committed
    /// atomically, but the fallible post-commit setup (watcher
    /// registration, on-demand materialization config) has not yet been
    /// confirmed. Remote activation must NEVER be attempted while a row is
    /// in this state -- see `EnrollmentOperationState`'s own module-level
    /// doc for the phantom-full-replica race this state exists to close.
    LocalSetupPending,
    /// Local setup is confirmed complete; remote activation may now be
    /// attempted. Responsibility has moved to `pending_enrollments`.
    ActivationPending,
    /// The local link was not committed (or a committed setup was rolled
    /// back); the remote Pending authorization must be cancelled.
    CancelPending,
    /// Automatic recovery is forbidden.
    RecoveryBlocked,
}

impl EnrollmentOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            EnrollmentOperationState::PreparePending => "prepare_pending",
            EnrollmentOperationState::Prepared => "prepared",
            EnrollmentOperationState::LocalSetupPending => "local_setup_pending",
            EnrollmentOperationState::ActivationPending => "activation_pending",
            EnrollmentOperationState::CancelPending => "cancel_pending",
            EnrollmentOperationState::RecoveryBlocked => "recovery_blocked",
        }
    }

    pub fn try_from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "prepare_pending" => Ok(EnrollmentOperationState::PreparePending),
            "prepared" => Ok(EnrollmentOperationState::Prepared),
            "local_setup_pending" => Ok(EnrollmentOperationState::LocalSetupPending),
            "activation_pending" => Ok(EnrollmentOperationState::ActivationPending),
            "cancel_pending" => Ok(EnrollmentOperationState::CancelPending),
            "recovery_blocked" => Ok(EnrollmentOperationState::RecoveryBlocked),
            other => Err(format!("unknown enrollment operation state: {other}")),
        }
    }
}

/// An `enrollment_operations` row whose contents could not be decoded (an
/// unrecognized enum string, or a shape that doesn't match its own `kind`/
/// `state`) -- mirrors [`InvalidMembershipOperation`].
#[derive(Debug, Clone)]
pub struct InvalidEnrollmentOperation {
    pub operation_id: String,
    /// The raw, un-decoded `state` column value, when the row itself could
    /// still be read (`None` only if reading the column itself failed).
    /// Diagnostic-only -- lets `recovery show` display the exact persisted
    /// state of a forward-version or corrupt row instead of just `detail`'s
    /// prose.
    pub raw_state: Option<String>,
    pub detail: String,
}

/// The result of scanning `enrollment_operations`: rows that decoded
/// successfully, and rows that didn't -- mirrors [`MembershipOperationScan`]
/// so one malformed row can never abort recovery for every other row in the
/// same sweep.
#[derive(Debug, Clone, Default)]
pub struct EnrollmentOperationScan {
    pub valid: Vec<EnrollmentOperation>,
    pub invalid: Vec<InvalidEnrollmentOperation>,
}

/// One restore whose replacement file and index update have not both been
/// durably committed yet. The intended new record is persisted before the
/// filesystem rename so startup recovery can finish the exact same version
/// instead of manufacturing a second version-vector increment.
#[derive(Debug, Clone, PartialEq)]
pub struct RestoreOperation {
    pub operation_id: String,
    pub group_id: String,
    pub path: String,
    pub target_version_seq: i64,
    pub expected_current_version_seq: Option<i64>,
    pub state: RestoreOperationState,
    pub record: FileRecord,
    pub origin_device_id: String,
    /// The restored version's own classification columns — carried
    /// alongside `record` (a bare `FileRecord`, which has no room for
    /// these) so `commit_restore_operation` can apply them to the
    /// `current` row via [`LocalFileMetaColumns`]/
    /// `apply_local_meta_columns_in_tx`, the SAME atomic in-transaction
    /// counterpart every other local content emission already uses.
    pub meta: LocalFileMetaColumns,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RestoreCommitOutcome {
    Committed(FileRecord),
    Missing,
    Superseded,
    /// The restore performed its own physical write, captured the fence
    /// epoch before it, and something else advanced that fence before this
    /// commit -- so this attempt no longer knows what is on disk. Nothing
    /// was written, the journal row included: it is the only record that
    /// the write happened at all, and startup recovery re-verifies the
    /// bytes and decides again from there.
    FenceLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOperationState {
    Prepared,
    DiskCommitted,
}

impl RestoreOperationState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::DiskCommitted => "disk_committed",
        }
    }

    pub fn from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "disk_committed" => Ok(Self::DiskCommitted),
            other => Err(format!("unknown restore operation state: {other}")),
        }
    }
}

#[cfg(test)]
mod tests;

/// A path whose object on disk belongs to no row this device placed and has
/// not yet been reconciled: a local edit native could not author there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldPath {
    pub path: String,
    /// Moves every time the path is held again. A reconciliation releases the
    /// hold only at the generation it read, so it cannot release a hold that
    /// was renewed for a row it never saw.
    pub generation: i64,
}
