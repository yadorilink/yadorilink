//! Probed, per-volume filesystem safety capabilities.
//!
//! Every capability here is established by *attempting the real operation*
//! against a caller-supplied directory and observing the actual syscall
//! result — never by reading a filesystem-type string and looking up what
//! that type is "supposed to" support. A network mount can present as
//! `ext4` over NFS re-export, a container bind-mount can silently strip a
//! primitive its host supports, and a removable drive can be reformatted
//! between two probes of the "same" path. Only the syscall result is ground
//! truth.
//!
//! # The cache is advisory, never authoritative
//!
//! [`CapabilityCache`] exists so that expensive repeated probing (creating
//! and exchanging real files, issuing real `ioctl`s) is not required on
//! every commit. It is keyed by [`CapabilityCacheKey`] — volume identity,
//! operation kind, adapter version and a mount-options fingerprint — never
//! by a single global "probed once at startup" flag, because that shape is
//! wrong on every removable and network volume: the volume behind a given
//! path can change without any code here observing it.
//!
//! Even so, **a cache hit must never be used to skip interpreting the real
//! result of an actual filesystem operation at the moment it happens.** The
//! cache may tell a caller which primitive is worth attempting first, or
//! back a status report; it must never stand in for checking what a commit
//! attempt's own return value says. Treating a cached `Supported` as a
//! license to assume success is exactly the bug this module exists to
//! prevent.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fs_identity::{
    DirectoryIdentity, FileIdentity, IdentityComparison, TimestampGranularity, VolumeIdentity,
};

/// The current shape of the probes below. Bumped whenever a probe's method
/// changes in a way that could change its answer for a volume that was
/// already cached — a [`CapabilityCacheKey`] embeds this, so a version bump
/// invalidates every existing cache entry rather than reusing a stale
/// answer against new probe logic.
pub const ADAPTER_VERSION: u32 = 1;

/// Whether a capability is known to work, known not to work, or has not
/// been probed. There is deliberately no way to read `Unknown` as
/// `Supported`: [`Capability::is_supported`] is the only query method, and
/// it returns `false` for both `Unsupported` and `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    Supported,
    Unsupported,
    /// Not yet probed, or the probe itself could not run (for example the
    /// caller-supplied directory was not writable). Distinct from
    /// `Unsupported`, which means the probe ran and the operation failed.
    Unknown,
}

impl Capability {
    /// The only sanctioned way to ask "can I rely on this". `Unknown` is
    /// not `Supported` — an unprobed capability must be treated the same as
    /// a confirmed-absent one until it is actually probed.
    pub fn is_supported(self) -> bool {
        matches!(self, Capability::Supported)
    }
}

/// Everything the transaction engine needs to know about what a volume can
/// actually do, each field probed independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemSafetyCapabilities {
    /// Atomic two-object exchange (`renameat2(RENAME_EXCHANGE)` on Linux,
    /// `renamex_np(RENAME_SWAP)` on macOS).
    pub atomic_exchange: Capability,
    /// A durable flush of file content using the platform's strongest
    /// available primitive — `F_FULLFSYNC` on macOS, not plain `fsync`,
    /// since plain `fsync` there does not flush the drive's write cache.
    pub durable_file_flush: Capability,
    /// A durable flush of a directory's own metadata (needed so a rename
    /// or exchange within it survives a crash). On Windows this reports
    /// whether `durable_dir::DurableNamespace` trusts the volume (a
    /// write-through move, not a directory flush): `Unsupported` while the
    /// Windows gate is closed.
    pub durable_directory_flush: Capability,
    /// Whether an EXTERNALLY supplied file's identity — a file the engine
    /// did not itself create, e.g. a source file already present in a sync
    /// root — can be relied on across rename, replacement and copy-up.
    ///
    /// This is deliberately **not measured**, only **inferred**: the engine
    /// has no way to manufacture a lower-layer file of its own to probe
    /// with; therefore the capability probe must be split.
    /// The inference this field stands for is a conjunction of (a) a
    /// layer-independent reuse discriminator existing — `generation_or_usn`
    /// or a fine-grained `birth_or_creation_time`, the same evidence
    /// [`FileIdentity::compare`] itself requires, read for free from the
    /// probe [`probe_stable_identity`] already runs — and (b) this mount
    /// being POSITIVELY identified as a stacking filesystem (overlayfs or
    /// similar), which would otherwise make even a fine-grained
    /// discriminator observed on an upper-only probe artefact meaningless
    /// evidence about a lower-layer source file's identity.
    ///
    /// No mount-option or filesystem-type introspection exists anywhere in
    /// this module in this phase (see [`CapabilityCacheKey::mount_options_
    /// hint`]'s own doc), so condition (b) can never be shown true today —
    /// this field's value is therefore driven entirely by (a), exactly the
    /// same discriminator check the old, unsplit `stable_file_identity`
    /// probe performed. That is what keeps this a **behaviour-preserving
    /// split**: every value this field reports today is byte-identical to
    /// what the old field reported, because the "positively stacking"
    /// branch of the inference is dead code until mount detection exists.
    ///
    /// **Cost of being wrong in each direction**, since this is inferred
    /// rather than measured: reporting `Supported` when a source file's
    /// identity is not actually stable risks trusting a substituted or
    /// reused object as the same one a caller expected (a `SameObject`
    /// answer for what should have been `Ambiguous`) — the unsafe
    /// direction. Reporting `Unsupported`/`Unknown` when it would actually
    /// have been safe only costs a caller falling back to a more
    /// conservative path (or D1a's fail-closed tier) on a volume that could
    /// have supported more — safe, merely pessimistic. This field is built
    /// to err toward the second cost, never the first: absent positive
    /// proof of non-stacking, it never upgrades a missing discriminator
    /// into `Supported`.
    pub stable_source_identity: Capability,
    /// For a marker file the ENGINE ITSELF created on this same mount, can
    /// sameness be confirmed after a rename and a hardlink?
    ///
    /// **Provisional in this increment**: this reuses the exact probe
    /// [`stable_source_identity`](Self::stable_source_identity) reuses —
    /// create a fresh file, rename it in place, and require
    /// [`FileIdentity::compare`] to report
    /// [`crate::fs_identity::IdentityComparison::SameObject`] — because no
    /// consumer of this field exists yet to require anything stronger (see
    /// `decisions.md` D1). Per D1b, routing this question through `compare`
    /// makes it answer `Unsupported` on overlayfs regardless, since
    /// `compare` needs a reuse discriminator overlayfs never supplies — even
    /// though V-D1b measured that a WEAKER predicate (same-boot `(st_dev,
    /// st_ino)` sameness among simultaneously live objects: hardlink,
    /// rename, `readdir` vs `stat`) is sound for exactly this question, for
    /// an object the engine created directly in the upper layer and never
    /// copied up. **This field is the one the weaker predicate will answer**
    /// once it is implemented (a later increment, not this one) — this
    /// increment only carves out the name and the doc boundary; it does not
    /// yet change what computes the value. When that lands, this field's
    /// probe stops sharing an implementation with
    /// [`stable_source_identity`](Self::stable_source_identity) and starts
    /// answering `Supported` on overlayfs where today both fields answer
    /// `Unsupported`.
    pub stable_owned_marker_identity: Capability,
    /// Whether an already-open handle keeps working after its path is
    /// unlinked (POSIX delete-on-close semantics; not universal on every
    /// remote filesystem or on Windows without explicit share flags).
    pub stale_handle_preservation: Capability,
    /// Whether a written metadata change (the tracked POSIX mode subset)
    /// round-trips exactly.
    pub metadata_fidelity: Capability,
    /// Whole-file reflink/clone (`FICLONE` on Linux, `clonefile` on
    /// macOS).
    pub reflink_or_clone: Capability,
    /// Byte-range clone/copy (`copy_file_range` on Linux). No portable
    /// primitive exists on macOS or Windows in this phase, so this is
    /// `Unsupported` there by construction rather than by a failed probe.
    pub range_clone: Capability,
}

/// The declared durability guarantee, derived from probed capabilities.
/// Never upgraded beyond what was actually observed: `PowerLossSafe` is
/// only reachable through [`FilesystemSafetyCapabilities::durable_file_flush`]
/// having used the platform's strongest flush primitive, never from a
/// plain `fsync` success alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DurabilityLevel {
    /// Survives a process crash; not confirmed to survive a power loss.
    ProcessCrashSafe,
    /// Survives a power loss, to the extent the strongest available local
    /// flush primitive can confirm it.
    PowerLossSafe,
    /// The volume responded to every probe, but is known or asserted to be
    /// a network/remote filesystem, where a successful flush response does
    /// not necessarily mean the server has persisted the data.
    BestEffortRemoteFilesystem,
    Unsupported,
}

/// Which probed operation a [`CapabilityCacheKey`] identifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperationKind {
    AtomicExchange,
    DurableFileFlush,
    DurableDirectoryFlush,
    StableSourceIdentity,
    StableOwnedMarkerIdentity,
    StaleHandlePreservation,
    MetadataFidelity,
    ReflinkOrClone,
    RangeClone,
}

/// The cache key for one probed capability. Two probes only share a cache
/// entry when they agree on all four fields — in particular, a volume
/// change (a different [`VolumeIdentity`] observed at what is otherwise the
/// same path) always misses the cache and re-probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapabilityCacheKey {
    pub volume_identity: VolumeIdentity,
    pub operation_kind: OperationKind,
    pub adapter_version: u32,
    /// Reserved for a fingerprint of relevant mount options (for example
    /// whether a network mount was remounted with different flags). Not
    /// populated by any probe in this module yet — no mount-option
    /// introspection exists in this phase — so every key currently carries
    /// `0`. Kept as a real field rather than added later so the key's
    /// discrimination shape does not change out from under existing
    /// entries once that introspection lands.
    pub mount_options_hint: u64,
}

impl CapabilityCacheKey {
    pub fn new(
        volume_identity: VolumeIdentity,
        operation_kind: OperationKind,
        adapter_version: u32,
    ) -> CapabilityCacheKey {
        CapabilityCacheKey {
            volume_identity,
            operation_kind,
            adapter_version,
            mount_options_hint: 0,
        }
    }
}

/// How many consecutive `Unknown` results [`CapabilityCache::get_or_probe`]
/// will re-probe for one key before giving up and returning `Unknown`
/// without calling `probe` again. `Unknown` is "not yet established", not
/// a settled answer, so it must never be cached as if it were one — but
/// re-probing on every single call is its own problem if a directory is
/// durably broken (permanently read-only, permanently out of space): an
/// unbounded retry loop at the call site would spin forever paying real
/// I/O cost for an answer that was never going to change. Below the cap,
/// every call still re-probes, so a real answer as soon as one is
/// available always gets through and is cached as settled — but once the
/// cap is reached, `get_or_probe` alone stops calling `probe` again for
/// that key for the rest of this `CapabilityCache` instance's lifetime; it
/// does not retry later or self-heal automatically. A caller that wants a
/// fresh look after conditions might have changed starts a new
/// `CapabilityCache` or calls [`CapabilityCache::record`] directly, which
/// always resets the streak (see its doc).
const MAX_CONSECUTIVE_UNKNOWN_REPROBES: u32 = 3;

#[derive(Clone, Copy, Debug)]
struct CachedCapability {
    value: Capability,
    /// How many times in a row `get_or_probe` has re-probed this key and
    /// gotten `Unknown` back. Reset to `0` the moment any probe (or an
    /// explicit `record`) returns something other than `Unknown`.
    consecutive_unknown_probes: u32,
}

/// An advisory cache of probe results. See the module doc: a hit here must
/// never substitute for interpreting a real operation's actual result.
#[derive(Default)]
pub struct CapabilityCache {
    entries: Mutex<HashMap<CapabilityCacheKey, CachedCapability>>,
}

impl CapabilityCache {
    pub fn new() -> CapabilityCache {
        CapabilityCache { entries: Mutex::new(HashMap::new()) }
    }

    /// Returns the cached value, or `Unknown` if this key has never been
    /// recorded. Never blocks on probing, and never re-probes — unlike
    /// [`Self::get_or_probe`], this is a pure read.
    pub fn get(&self, key: &CapabilityCacheKey) -> Capability {
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .map(|entry| entry.value)
            .unwrap_or(Capability::Unknown)
    }

    /// Records a freshly probed value, as an explicit assertion from the
    /// caller rather than through [`Self::get_or_probe`]'s own re-probe
    /// bookkeeping. Overwrites whatever was cached before for this exact
    /// key and resets its re-probe count to `0`, so a `record`ed `Unknown`
    /// still gets the full re-probe allowance on the next `get_or_probe`
    /// call.
    pub fn record(&self, key: CapabilityCacheKey, value: Capability) {
        self.entries
            .lock()
            .unwrap()
            .insert(key, CachedCapability { value, consecutive_unknown_probes: 0 });
    }

    /// Returns the cached value if it is a settled (non-`Unknown`) hit,
    /// otherwise runs `probe`, records its result, and returns it —
    /// bounded by [`MAX_CONSECUTIVE_UNKNOWN_REPROBES`] consecutive
    /// `Unknown` results, past which this stops re-probing and returns
    /// `Unknown` directly. `probe` is never called for a settled hit; this
    /// method exists purely to avoid redundant probing, not to gate any
    /// actual filesystem operation (see the module doc).
    pub fn get_or_probe(
        &self,
        key: CapabilityCacheKey,
        probe: impl FnOnce() -> Capability,
    ) -> Capability {
        {
            let entries = self.entries.lock().unwrap();
            if let Some(entry) = entries.get(&key) {
                if entry.value != Capability::Unknown {
                    return entry.value;
                }
                if entry.consecutive_unknown_probes >= MAX_CONSECUTIVE_UNKNOWN_REPROBES {
                    return Capability::Unknown;
                }
            }
        }
        let value = probe();
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key).or_insert(CachedCapability {
            value: Capability::Unknown,
            consecutive_unknown_probes: 0,
        });
        if value == Capability::Unknown {
            entry.value = Capability::Unknown;
            entry.consecutive_unknown_probes = entry.consecutive_unknown_probes.saturating_add(1);
        } else {
            entry.value = value;
            entry.consecutive_unknown_probes = 0;
        }
        value
    }
}

/// Observes the [`VolumeIdentity`] of the volume hosting `dir`, for building
/// a [`CapabilityCacheKey`].
pub fn observe_volume_identity(dir: &Path) -> io::Result<VolumeIdentity> {
    Ok(DirectoryIdentity::observe_path(dir)?.volume_identity)
}

/// Runs every probe in this module against `dir`, which must already exist
/// and be writable. Each probe creates and removes its own throwaway
/// artefacts, always named under the engine's reserved on-disk namespace
/// (`.yadorilink-v1-probe.<id>`, [`crate::reserved_namespace::ArtefactKind::Probe`])
/// — see [`probe_artefact_name`]'s doc for why an unreserved name here was
/// a defect, not merely a cosmetic gap.
pub fn probe_all(dir: &Path) -> io::Result<FilesystemSafetyCapabilities> {
    if !dir.is_dir() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "probe directory does not exist"));
    }
    // Probed once, not twice, and the one result is used for both fields.
    // See `stable_owned_marker_identity`'s doc: in this increment the two
    // capabilities are answered by the literal same procedure (no mount-
    // stacking detection exists to diverge `stable_source_identity`'s
    // inference, and the weaker same-boot marker predicate `stable_owned_
    // marker_identity` is meant to grow into does not exist yet either).
    // Probing twice would double the real file-create/rename I/O this
    // probe does for a value that is, today, provably identical either way.
    let stable_identity = probe_stable_identity(dir);
    Ok(FilesystemSafetyCapabilities {
        atomic_exchange: probe_atomic_exchange(dir),
        durable_file_flush: probe_durable_file_flush(dir),
        durable_directory_flush: probe_durable_directory_flush(dir),
        stable_source_identity: stable_identity,
        stable_owned_marker_identity: stable_identity,
        stale_handle_preservation: probe_stale_handle_preservation(dir),
        metadata_fidelity: probe_metadata_fidelity(dir),
        reflink_or_clone: probe_reflink_or_clone(dir),
        range_clone: probe_range_clone(dir),
    })
}

// `durable_claim_store` — deliberately not a field of
// `FilesystemSafetyCapabilities`. D1a's design analysis introduces it as "do
// claim records survive a restart", for the future nonce-and-claim marker
// mechanism (see `stable_owned_marker_identity`'s doc above). That is not a
// property this module's probing methodology can establish: every field in
// this struct is answered by attempting a real syscall against a
// caller-supplied directory and observing its result (see this module's own
// top-level doc) — but "does this location survive a restart" is not
// observable from inside one process's one run. A claim area sitting inside
// a container's writable layer looks, to every syscall this module could
// issue, identical to a genuinely durable one right up until the container
// is recreated and it is gone; no probe run before that moment can
// distinguish the two without fabricating an answer this module's own
// discipline forbids (see the module doc's "only the syscall result is
// ground truth"). It belongs instead to whatever decides deployment
// topology for a sync root — e.g. daemon/container configuration that
// already knows whether the reserved claim area lives on a bind-mounted,
// host-durable path or inside an ephemeral writable layer — not to a
// per-volume filesystem capability probe. No such caller exists yet in this
// crate (the marker/claim mechanism itself is a later increment), so this
// module deliberately adds no field, no probe and no placeholder for it
// rather than inventing an observation it cannot make.

/// Derives the declared durability guarantee from probed capabilities.
/// `assume_remote_filesystem` is supplied by the caller, not detected
/// here: distinguishing a local from a network filesystem generally
/// requires reading a filesystem-type string, which this module
/// deliberately avoids for capability probing (see the module doc). A
/// caller with independent evidence (an explicit mount table lookup, user
/// configuration) may pass `true`; this function never infers it from
/// syscall behavior alone. **This has no caller in the workspace.** They do not need to,
/// *provided* the granularity those comparisons use is always freshly,
/// correctly measured: every one of those call sites now probes
/// `probe_birth_time_granularity` itself rather than accepting a
/// caller-supplied value (see their own docs) — the real hazard is a
/// hardcoded/stale granularity, not a missing capability check, and `compare`'s own
/// `Ambiguous`-on-no-discriminator logic already fails closed once given a
/// true value. This function's remaining, distinct job is coarser: whether
/// to attempt syncing a volume **at all** (it also folds in
/// `atomic_exchange` and the flush capabilities, not just identity), which
/// is a decision no code in this crate makes yet because nothing here
/// decides "start syncing this root" — that lives in whatever future
/// daemon/CLI wiring calls into this engine. **Reads both
/// `stable_source_identity` and `stable_owned_marker_identity`, requiring
/// both `Supported`.** The nine `FileIdentity`/`DirectoryIdentity`
/// `compare()` call sites this function's doc lists above are a mixed bag
/// against the source/marker split (some compare an engine-written stage
/// artefact within one process run, some compare a directory or an object
/// whose creator cannot be shown from the call site alone, some span a
/// restart) — seven of the nine do not classify unambiguously as depending
/// on only one of the two fields. A single "attempt syncing at all" gate
/// with no real caller yet has no way to pick a side of that ambiguity
/// correctly, so it requires both rather than guessing one is sufficient —
/// the conservative reading, and (today) also the behaviour-preserving
/// one: [`probe_all`] currently derives both fields from the same probe,
/// so they always agree, and this conjunction evaluates identically to the
/// pre-split single-field check for every value either field can currently
/// take. Wiring it in now was considered and rejected: there is no real
/// caller to wire it into, and inventing one purely to hold this check
/// would be scope no one asked for and code with no real integration to
/// validate it against.
pub fn derive_durability_level(
    caps: &FilesystemSafetyCapabilities,
    assume_remote_filesystem: bool,
) -> DurabilityLevel {
    let stable_identity = caps.stable_source_identity.is_supported()
        && caps.stable_owned_marker_identity.is_supported();
    if assume_remote_filesystem {
        return if caps.atomic_exchange.is_supported()
            && caps.durable_file_flush.is_supported()
            && stable_identity
        {
            DurabilityLevel::BestEffortRemoteFilesystem
        } else {
            DurabilityLevel::Unsupported
        };
    }
    if !caps.atomic_exchange.is_supported() || !stable_identity {
        return DurabilityLevel::Unsupported;
    }
    if caps.durable_file_flush.is_supported() && caps.durable_directory_flush.is_supported() {
        DurabilityLevel::PowerLossSafe
    } else if caps.durable_file_flush.is_supported() {
        DurabilityLevel::ProcessCrashSafe
    } else {
        DurabilityLevel::Unsupported
    }
}

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A filename inside the engine's reserved on-disk namespace
/// ([`crate::reserved_namespace::ArtefactKind::Probe`]), unique enough for
/// one-shot probe use within a process. Uniqueness here is only
/// probabilistic — see [`create_probe_artefact`] and
/// [`reserve_probe_artefact_path`], which are what actually establish
/// ownership before anything is deleted.
///
/// **Must** be reserved-namespace-shaped, not merely collision-avoidant: a
/// probe artefact is created directly inside the caller's sync directory,
/// beside real user content, for the same reason a stage or preimage
/// artefact is. An earlier version of this function generated an
/// unreserved name (`.yl-fscap-probe-<pid>-<nanos>-<counter>-<label>`) on
/// the theory that avoiding the exact `.yadorilink-v1-*` prefix was enough
/// to keep it out of the way. It was not: `is_reserved_component` — the
/// predicate the watcher, the initial scan and local change processing all
/// consult *before* indexing anything — only ever recognized that prefix,
/// so an unreserved probe name was ordinary content to every one of those
/// entry points for the whole window between this function creating it and
/// the probe's own cleanup removing it. Each `probe_all` call creates and
/// removes 32 such artefacts (see [`GRANULARITY_SAMPLE_COUNT`]); on the
/// commit path, that is 32 enqueued creates and 32 enqueued deletes per
/// commit, racing this function's own unlink — worst case, a create wins
/// that race and a probe artefact gets signed into native state and replicated
/// to every peer. Building the name through
/// [`crate::reserved_namespace::artefact_component_name`] instead makes
/// that unreachable: every one of those entry points excludes a reserved
/// component before it ever reaches an ignore rule or the index.
///
/// `pub(crate)`: `hazard`'s two volume-behaviour probes (case-insensitivity
/// and normalization-insensitivity) mint their on-disk artefacts through
/// this same function rather than growing a second name scheme, for exactly
/// the reason the previous paragraph describes — they too create artefacts
/// directly inside the caller's sync directory, from a production
/// materialization path, and an unreserved name there is indexable content.
pub fn probe_artefact_name(
    label: &str,
) -> Result<String, crate::reserved_namespace::ArtefactNameError> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let counter = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let id = format!("{}-{}-{}-{}", std::process::id(), nanos, counter, label);
    crate::reserved_namespace::artefact_component_name(
        crate::reserved_namespace::ArtefactKind::Probe,
        &id,
    )
}

/// How many fresh names a probe will try before giving up on
/// [`create_probe_artefact`] or [`reserve_probe_artefact_path`]. A single
/// collision is plausible noise; this many in a row means something is
/// actually wrong with the directory, not bad luck.
pub const MAX_ARTEFACT_NAME_ATTEMPTS: u32 = 8;

// Thread-local rather than a `static`: the test harness runs tests in
// parallel, and several of them create probe artefacts, so a process-wide
// flag is consumed by whichever test happens to call first -- measured, not
// hypothesised. Scoping it to the setting thread makes the injection reach
// exactly the call the test then makes itself.
#[cfg(test)]
thread_local! {
    static FAIL_NEXT_PROBE_WRITE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// The write half of [`create_probe_artefact`], behind a seam so a test can
/// make it fail.
///
/// The failure being guarded against — `ENOSPC`, a quota, an I/O error part
/// way through the write — cannot be provoked portably from a test without
/// contriving a full or failing filesystem, and the property at stake is
/// specifically what happens on the error path. A test-only injection point
/// is narrower than the alternatives (a closure parameter threaded through
/// every call site, or no test at all) and leaves the production path a
/// plain `write_all`.
fn write_probe_content(file: &mut File, content: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_PROBE_WRITE.with(|f| f.replace(false)) {
        return Err(io::Error::new(io::ErrorKind::StorageFull, "injected probe write failure"));
    }
    std::io::Write::write_all(file, content)
}

/// Creates a brand-new probe artefact file containing `content`, retrying
/// under a fresh name on any collision. [`probe_artefact_name`] is only
/// probabilistically unique, so `create_new` — which fails rather than
/// truncating or following an existing entry — is what actually proves this
/// call, and not some unrelated writer, created the returned path. Only a
/// path this function returned `Ok` for may later be removed by its caller;
/// this is the same "never delete an artefact you don't own" rule the
/// engine's reserved namespace enforces elsewhere.
fn create_probe_artefact(dir: &Path, label: &str, content: &[u8]) -> io::Result<(PathBuf, File)> {
    for _ in 0..MAX_ARTEFACT_NAME_ATTEMPTS {
        let name = probe_artefact_name(label)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let path = dir.join(name);
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                // The write is the only step between `create_new` proving
                // this process owns `path` and the caller receiving it, and
                // it is exactly the step that fails under disk pressure
                // (`ENOSPC`, a quota, an I/O error). Returning the error
                // bare would strand the artefact: the caller never sees the
                // path, so it cannot remove what it does not know about,
                // and no other owner exists. Removing it here is safe for
                // the same reason the caller's own cleanup is -- `create_new`
                // succeeded, so this call, and nothing else, put it there.
                if let Err(err) = write_probe_content(&mut file, content) {
                    drop(file);
                    let _ = std::fs::remove_file(&path);
                    return Err(err);
                }
                return Ok((path, file));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique probe artefact name",
    ))
}

/// Reserves a path this process has just confirmed does not exist, for an
/// operation (a clone target or a rename target) that must create the path
/// itself rather than through [`create_probe_artefact`]'s `create_new`.
/// Retries under a fresh name on collision.
///
/// This only narrows the ownership race to the gap between the check and
/// the caller's own operation — exclusive reservation of an as-yet
/// nonexistent path has no portable API — so callers must still only treat
/// the returned path as theirs to remove once their own operation is what
/// put something there (see call sites for the exact reasoning per probe).
fn reserve_probe_artefact_path(dir: &Path, label: &str) -> io::Result<PathBuf> {
    for _ in 0..MAX_ARTEFACT_NAME_ATTEMPTS {
        let name = probe_artefact_name(label)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let path = dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => continue,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(path),
            Err(err) => return Err(err),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique probe artefact name",
    ))
}

/// Classifies a failed raw syscall as either definite feature absence
/// (`Unsupported`) or a transient/unrelated failure (`Unknown`), given the
/// operation-specific errno set that call documents as meaning "this
/// feature does not exist here". Anything else — `EPERM`, `EIO`, `ENOSPC`,
/// a path race, or any errno not in that set — stays `Unknown`: it says
/// nothing about whether the feature exists, and reading it as
/// `Unsupported` would let one transient failure permanently poison this
/// volume's cached capability (see the module doc on `CapabilityCache`).
///
/// Must be called with the `errno` captured immediately after the failing
/// return value, before any other libc call — `errno` is only valid until
/// the next one.
///
/// Takes its `feature_absent` set from the caller: a commit's
/// feature-absence errno is not necessarily the set a capability probe
/// uses, and one looser classification for both would be wrong for each.
#[cfg(unix)]
pub fn classify_errno(errno: Option<i32>, feature_absent: &[i32]) -> Capability {
    match errno {
        Some(code) if feature_absent.contains(&code) => Capability::Unsupported,
        _ => Capability::Unknown,
    }
}

/// Retries a raw libc call that follows the usual C convention (`-1` with
/// `errno` set on failure) across `EINTR`. A signal interruption is not a
/// meaningful result for any probe in this module — the underlying
/// operation was never actually attempted — so it must never surface as
/// either `Supported` or `Unsupported`.
///
/// `attempt` returns `(return_value, errno_if_failed)` rather than this
/// function reading `errno` itself: the caller already has to capture it
/// immediately after its own syscall (see [`classify_errno`]'s doc on
/// staleness), so folding that capture into the same closure means there is
/// only ever one read of `errno` per attempt, taken at the only point it is
/// guaranteed valid.
#[cfg(unix)]
fn retry_eintr(mut attempt: impl FnMut() -> (i32, Option<i32>)) -> (i32, Option<i32>) {
    loop {
        let (ret, errno) = attempt();
        if ret != -1 || errno != Some(libc::EINTR) {
            return (ret, errno);
        }
    }
}

/// Same as [`retry_eintr`] for calls made through the raw `syscall(2)`
/// wrapper, which returns `c_long` rather than `c_int`.
#[cfg(target_os = "linux")]
fn retry_eintr_syscall(mut attempt: impl FnMut() -> (i64, Option<i32>)) -> (i64, Option<i32>) {
    loop {
        let (ret, errno) = attempt();
        if ret != -1 || errno != Some(libc::EINTR) {
            return (ret, errno);
        }
    }
}

/// Runs a raw libc call and captures `errno` in the same expression when it
/// fails, so the two are never separated by anything else that could
/// change it. Intended to be used as the body of a [`retry_eintr`] /
/// [`retry_eintr_syscall`] closure.
#[cfg(unix)]
macro_rules! call_and_capture_errno {
    ($ret:expr) => {{
        let ret = $ret;
        let errno = if ret == -1 { io::Error::last_os_error().raw_os_error() } else { None };
        (ret, errno)
    }};
}

fn probe_atomic_exchange(dir: &Path) -> Capability {
    let Ok((a, _)) = create_probe_artefact(dir, "exchange-a", b"a") else {
        return Capability::Unknown;
    };
    let Ok((b, _)) = create_probe_artefact(dir, "exchange-b", b"b") else {
        let _ = std::fs::remove_file(&a);
        return Capability::Unknown;
    };

    let result = platform_atomic_exchange(&a, &b);

    // The exchange only swaps the two paths' contents, never removes
    // either path, so both are still owned artefacts to clean up
    // regardless of whether the exchange itself succeeded.
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    result
}

#[cfg(target_os = "linux")]
fn platform_atomic_exchange(a: &Path, b: &Path) -> Capability {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let (Some(a_c), Some(b_c)) =
        (CString::new(a.as_os_str().as_bytes()).ok(), CString::new(b.as_os_str().as_bytes()).ok())
    else {
        return Capability::Unknown;
    };
    // Called through the raw syscall number rather than `libc::renameat2`:
    // glibc only exports that symbol from 2.28, and uClibc does not export
    // it at all, so calling the symbol directly would fail to link on
    // either. The syscall itself has existed since Linux 3.15.
    // SAFETY: `a_c`/`b_c` are valid NUL-terminated paths kept alive for
    // the duration of the call; the two `AT_FDCWD` values and the flag are
    // plain integers with no memory behind them.
    let (ret, errno) = retry_eintr_syscall(|| {
        // SAFETY: `a_c`/`b_c` remain valid for the duration of this call.
        call_and_capture_errno!(unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                a_c.as_ptr(),
                libc::AT_FDCWD,
                b_c.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        })
    });
    if ret == 0 {
        return Capability::Supported;
    }
    // `renameat2(2)` documents `EINVAL` as the filesystem not supporting
    // one of the given flags; `ENOSYS` covers a kernel older than 3.15,
    // where the syscall does not exist at all.
    classify_errno(errno, &[libc::ENOSYS, libc::EINVAL])
}

#[cfg(target_vendor = "apple")]
fn platform_atomic_exchange(a: &Path, b: &Path) -> Capability {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let (Some(a_c), Some(b_c)) =
        (CString::new(a.as_os_str().as_bytes()).ok(), CString::new(b.as_os_str().as_bytes()).ok())
    else {
        return Capability::Unknown;
    };
    // SAFETY: `a_c`/`b_c` are valid NUL-terminated paths owned for the
    // duration of the call.
    let (ret, errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe {
            libc::renamex_np(a_c.as_ptr(), b_c.as_ptr(), libc::RENAME_SWAP)
        })
    });
    if ret == 0 {
        return Capability::Supported;
    }
    // `renamex_np(2)` documents `ENOTSUP` as "the underlying filesystem
    // does not support the `RENAME_SWAP` flag".
    classify_errno(errno, &[libc::ENOSYS, libc::ENOTSUP])
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn platform_atomic_exchange(_a: &Path, _b: &Path) -> Capability {
    // No portable atomic-exchange primitive is wired up on this platform
    // in this phase (Windows uses `ReplaceFileW`, handled by the commit
    // adapter, not this probe).
    Capability::Unsupported
}

fn probe_reflink_or_clone(dir: &Path) -> Capability {
    let Ok((src, _)) = create_probe_artefact(dir, "clone-src", b"reflink probe content") else {
        return Capability::Unknown;
    };
    let Ok(dst) = reserve_probe_artefact_path(dir, "clone-dst") else {
        let _ = std::fs::remove_file(&src);
        return Capability::Unknown;
    };

    // `dst_created_by_us` is the platform function's own attestation, not
    // an assumption from `dst` merely existing afterward: if a different
    // actor won a race and created something at `dst` between the
    // reservation check above and the platform call, that call reports it
    // did NOT create `dst`, and this probe must not delete a path it never
    // produced (the same "never remove an artefact you don't own" rule
    // `create_probe_artefact` enforces via `create_new`).
    let (result, dst_created_by_us) = platform_reflink_or_clone(&src, &dst);

    let _ = std::fs::remove_file(&src);
    if dst_created_by_us {
        let _ = std::fs::remove_file(&dst);
    }
    result
}

#[cfg(target_os = "linux")]
fn platform_reflink_or_clone(src: &Path, dst: &Path) -> (Capability, bool) {
    use std::os::unix::io::AsRawFd;

    let Ok(src_file) = File::open(src) else {
        return (Capability::Unknown, false);
    };
    let Ok(dst_file) = OpenOptions::new().write(true).create_new(true).open(dst) else {
        // Either genuine I/O trouble, or something else claimed this name
        // between the reservation check and here — either way this
        // process did not create `dst`.
        return (Capability::Unknown, false);
    };
    // SAFETY: both file descriptors are valid and kept alive for the
    // duration of the call.
    let (ret, errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe {
            libc::ioctl(dst_file.as_raw_fd(), libc::FICLONE, src_file.as_raw_fd())
        })
    });
    // `create_new` above succeeded, so `dst` exists and is ours to remove
    // regardless of whether the clone itself worked.
    if ret == 0 {
        return (Capability::Supported, true);
    }
    // `ioctl_ficlone(2)`: `ENOTTY` means the kernel/filesystem predates
    // this ioctl entirely ("inappropriate ioctl for device" is the
    // kernel's generic answer for an unrecognized request on this fd);
    // `EOPNOTSUPP` means the filesystem recognizes the request but does
    // not implement reflinking.
    (classify_errno(errno, &[libc::ENOTTY, libc::EOPNOTSUPP]), true)
}

#[cfg(target_vendor = "apple")]
fn platform_reflink_or_clone(src: &Path, dst: &Path) -> (Capability, bool) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let (Some(src_c), Some(dst_c)) = (
        CString::new(src.as_os_str().as_bytes()).ok(),
        CString::new(dst.as_os_str().as_bytes()).ok(),
    ) else {
        return (Capability::Unknown, false);
    };
    // SAFETY: both paths are valid NUL-terminated strings; `dst` was just
    // confirmed absent by `reserve_probe_artefact_path`.
    let (ret, errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe { libc::clonefile(src_c.as_ptr(), dst_c.as_ptr(), 0) })
    });
    if ret == 0 {
        // `clonefile(2)` only creates `dst` on success.
        return (Capability::Supported, true);
    }
    // `clonefile(2)` documents `ENOTSUP` as "the underlying filesystem
    // does not support this call".
    (classify_errno(errno, &[libc::ENOTSUP, libc::ENOSYS]), false)
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn platform_reflink_or_clone(_src: &Path, _dst: &Path) -> (Capability, bool) {
    (Capability::Unsupported, false)
}

fn probe_range_clone(dir: &Path) -> Capability {
    let Ok((src, _)) = create_probe_artefact(dir, "range-clone-src", b"0123456789abcdef") else {
        return Capability::Unknown;
    };
    let Ok(dst) = reserve_probe_artefact_path(dir, "range-clone-dst") else {
        let _ = std::fs::remove_file(&src);
        return Capability::Unknown;
    };

    let (result, dst_created_by_us) = platform_range_clone(&src, &dst);

    let _ = std::fs::remove_file(&src);
    if dst_created_by_us {
        let _ = std::fs::remove_file(&dst);
    }
    result
}

#[cfg(target_os = "linux")]
fn platform_range_clone(src: &Path, dst: &Path) -> (Capability, bool) {
    use std::os::unix::io::AsRawFd;

    const PROBE_CONTENT: &[u8] = b"0123456789abcdef";

    let Ok(src_file) = File::open(src) else {
        return (Capability::Unknown, false);
    };
    let Ok(dst_file) = OpenOptions::new().write(true).create_new(true).open(dst) else {
        return (Capability::Unknown, false);
    };
    // `create_new` above succeeded: `dst` exists and is ours from here on,
    // regardless of how the copy loop below turns out.

    // `libc` does not expose a `copy_file_range` wrapper for every target,
    // so this goes through the raw syscall number directly. Looped: a
    // single call is not obligated to copy every requested byte, and a
    // `0`-byte return with bytes still remaining means nothing was
    // actually copied — that demonstrates nothing about support either
    // way, so it must not be read as success (see below).
    let mut copied = 0usize;
    while copied < PROBE_CONTENT.len() {
        let remaining = PROBE_CONTENT.len() - copied;
        // SAFETY: null offsets mean "use and advance each fd's current
        // file position", which both `src_file`/`dst_file` start at for
        // this freshly opened probe pair; both fds are valid and kept
        // alive for the duration of the call.
        let (ret, errno) = retry_eintr_syscall(|| {
            call_and_capture_errno!(unsafe {
                libc::syscall(
                    libc::SYS_copy_file_range,
                    src_file.as_raw_fd(),
                    std::ptr::null_mut::<libc::loff_t>(),
                    dst_file.as_raw_fd(),
                    std::ptr::null_mut::<libc::loff_t>(),
                    remaining,
                    0u32,
                )
            })
        });
        if ret < 0 {
            // `copy_file_range(2)` documents `EOPNOTSUPP` as the
            // filesystem not implementing the call at all. `EXDEV`
            // ("different filesystems") is deliberately excluded: `src`
            // and `dst` are both freshly created in the same
            // caller-supplied directory, so it cannot legitimately mean
            // that here — if it occurs anyway, that is a probe-environment
            // surprise, not proof of feature absence.
            return (classify_errno(errno, &[libc::ENOSYS, libc::EOPNOTSUPP]), true);
        }
        if ret == 0 {
            return (Capability::Unknown, true);
        }
        copied += ret as usize;
    }

    let capability = match std::fs::read(dst) {
        Ok(observed) if observed == PROBE_CONTENT => Capability::Supported,
        Ok(_) => Capability::Unsupported,
        Err(_) => Capability::Unknown,
    };
    (capability, true)
}

#[cfg(not(target_os = "linux"))]
fn platform_range_clone(_src: &Path, _dst: &Path) -> (Capability, bool) {
    // No portable byte-range clone primitive exists on macOS or Windows in
    // this phase; there is nothing to attempt, so this is a deliberate
    // classification, not an unattempted probe.
    (Capability::Unsupported, false)
}

fn probe_durable_file_flush(dir: &Path) -> Capability {
    match create_probe_artefact(dir, "durable-flush", b"durability probe") {
        Ok((path, file)) => {
            let capability = platform_durable_file_flush(&file);
            let _ = std::fs::remove_file(&path);
            capability
        }
        Err(_) => Capability::Unknown,
    }
}

#[cfg(target_vendor = "apple")]
fn platform_durable_file_flush(file: &File) -> Capability {
    use std::os::unix::io::AsRawFd;
    platform_full_fsync(file.as_raw_fd())
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn platform_durable_file_flush(file: &File) -> Capability {
    match file.sync_all() {
        Ok(()) => Capability::Supported,
        // `fsync(2)`'s only documented "this fd doesn't support
        // synchronization" case is a non-regular-file special file, which
        // cannot apply here since `file` is a plain regular file this
        // function just created — so the sole feature-absence signal left
        // is a kernel/libc lacking the call at all.
        Err(err) => classify_errno(err.raw_os_error(), &[libc::ENOSYS]),
    }
}

#[cfg(windows)]
fn platform_durable_file_flush(file: &File) -> Capability {
    match file.sync_all() {
        Ok(()) => Capability::Supported,
        // `sync_all` on Windows maps to `FlushFileBuffers`, which has no
        // portable errno-style signal this module can use to distinguish
        // "this filesystem/driver doesn't support flush" from any other
        // failure — unlike the Unix `classify_errno` path above, there is
        // no known feature-absence error code to check for. Reporting
        // every failure as `Unknown` rather than guessing `Unsupported`
        // keeps this fail-closed the same way `classify_errno` is: a
        // transient failure must never poison this volume's cached
        // capability with a wrong "definitely absent" answer.
        Err(_) => Capability::Unknown,
    }
}

/// Issues `F_FULLFSYNC` on `fd` and classifies the result. Shared by both
/// [`platform_durable_file_flush`] and [`platform_durable_directory_flush`]
/// on macOS so there is exactly one place that primitive is invoked: plain
/// `fsync` does not flush the drive's write cache on this platform
/// regardless of whether the fd names a file or a directory, and the file
/// probe already exists specifically to avoid that unsound claim — routing
/// the directory probe through a *different* implementation would silently
/// reopen the same hole through `durable_directory_flush`, which is the
/// other required input to `derive_durability_level`'s `PowerLossSafe`
/// decision.
#[cfg(target_vendor = "apple")]
fn platform_full_fsync(fd: std::os::unix::io::RawFd) -> Capability {
    // SAFETY: `fd` is a valid, open file descriptor for the duration of
    // the call (both callers hold the owning `File` alive across it).
    let (ret, errno) =
        retry_eintr(|| call_and_capture_errno!(unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) }));
    if ret == 0 {
        return Capability::Supported;
    }
    // `fcntl(2)` documents `ENOTSUP` for `F_FULLFSYNC` when the underlying
    // device does not support it (seen on some older/external drives).
    classify_errno(errno, &[libc::ENOTSUP, libc::ENOSYS])
}

#[cfg(unix)]
fn probe_durable_directory_flush(dir: &Path) -> Capability {
    match File::open(dir) {
        Ok(handle) => platform_durable_directory_flush(&handle),
        Err(_) => Capability::Unknown,
    }
}

#[cfg(target_vendor = "apple")]
fn platform_durable_directory_flush(handle: &File) -> Capability {
    use std::os::unix::io::AsRawFd;
    platform_full_fsync(handle.as_raw_fd())
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn platform_durable_directory_flush(handle: &File) -> Capability {
    match handle.sync_all() {
        Ok(()) => Capability::Supported,
        Err(err) => classify_errno(err.raw_os_error(), &[libc::ENOSYS]),
    }
}

#[cfg(windows)]
fn probe_durable_directory_flush(dir: &Path) -> Capability {
    // Win32 documents no contract that flushing a directory handle makes
    // directory entries durable, so this does not ask for one. What a
    // namespace change on Windows relies on is the write-through move
    // (`crate::durable_dir`); this reports whether `DurableNamespace::open`
    // trusts the volume: `Unsupported` while the global gate is closed, and
    // afterwards the per-volume probe's verdict.
    use crate::durable_dir::{DurableNamespace, NsError, UnavailableReason};
    match DurableNamespace::open(dir) {
        Ok(_) => Capability::Supported,
        Err(NsError::Unavailable(UnavailableReason::Unknown)) => Capability::Unknown,
        Err(_) => Capability::Unsupported,
    }
}

#[cfg(not(any(unix, windows)))]
fn probe_durable_directory_flush(_dir: &Path) -> Capability {
    // No platform-specific probe is wired up here yet. Genuinely
    // unprobed, not a negative result.
    Capability::Unknown
}

/// How many back-to-back artefact creates [`probe_birth_time_granularity`]
/// samples. More samples raise the odds of ever catching two creates that
/// land inside the same clock tick — the only signal this probe treats as
/// proof of coarseness — at the cost of more real time and I/O per call.
/// 32 was chosen so that even a clock coarse enough to matter (multiple
/// milliseconds, per the measured overlayfs case this probe exists to
/// catch) reliably collides at least once across the run, while staying
/// cheap enough to run as part of one capability probe.
const GRANULARITY_SAMPLE_COUNT: usize = 32;

/// Measures whether `dir`'s volume assigns `birth_or_creation_time` finely
/// enough to trust an equal value as proof of "same object" — see
/// [`TimestampGranularity`]. Creates [`GRANULARITY_SAMPLE_COUNT`] probe
/// artefacts back-to-back with as little work between them as this module
/// can manage, and observes each one's birth time immediately after.
///
/// The only signal this trusts is a direct collision: two **consecutive**
/// samples reporting the exact same birth time proves two genuinely
/// distinct creation events were indistinguishable, which is exactly the
/// failure mode `Coarse` exists to catch — that is deliberately the sole
/// proof accepted, rather than also accepting "the smallest observed
/// delta between two *different* values was small". Comparing an absolute
/// delta against a fixed threshold would conflate the clock's real
/// resolution with this loop's own per-iteration overhead (each iteration
/// does a real file create and a `stat`, easily tens of microseconds on
/// its own): a genuinely fine (even nanosecond-resolution) clock will
/// still show inter-sample deltas dominated by that overhead and never
/// approach nanosecond scale, so a delta-based threshold would misjudge a
/// fine clock as coarse. Collision is the only observation a coarse clock
/// can produce that a fine one cannot.
///
/// Fewer than two usable samples (artefact creation failed, or the
/// platform reports no birth time here at all) leaves no data to trust
/// either way, so it is treated the same as a proven-coarse result rather
/// than left as an unresolved case that might later be read as `Fine` by
/// accident — the unsafe direction to get wrong here is assuming `Fine`.
///
/// Count of real invocations of this function (not the cached wrapper's
/// hits), process-wide -- cheap enough (one relaxed atomic increment) to
/// leave on unconditionally rather than gating it behind `cfg(test)`, and
/// exposed for tests via [`probe_birth_time_granularity_call_count_for_test`]
/// so a regression can prove an actual call chain (not just the pure
/// caching decision) triggers at most one real probe per volume.
static PROBE_BIRTH_TIME_GRANULARITY_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(any(test, feature = "test-support"))]
pub fn probe_birth_time_granularity_call_count_for_test() -> u64 {
    PROBE_BIRTH_TIME_GRANULARITY_CALLS.load(Ordering::SeqCst)
}

pub fn probe_birth_time_granularity(dir: &Path) -> TimestampGranularity {
    PROBE_BIRTH_TIME_GRANULARITY_CALLS.fetch_add(1, Ordering::Relaxed);
    let mut created = Vec::with_capacity(GRANULARITY_SAMPLE_COUNT);
    let mut timestamps = Vec::with_capacity(GRANULARITY_SAMPLE_COUNT);
    for i in 0..GRANULARITY_SAMPLE_COUNT {
        let label = format!("granularity-{i}");
        match create_probe_artefact(dir, &label, b"g") {
            Ok((path, _file)) => {
                if let Ok(identity) = FileIdentity::observe_path(&path) {
                    if let Some(birth) = identity.birth_or_creation_time {
                        timestamps.push(birth);
                    }
                }
                created.push(path);
            }
            Err(_) => break,
        }
    }
    for path in &created {
        let _ = std::fs::remove_file(path);
    }

    if timestamps.len() < 2 {
        return TimestampGranularity::Coarse;
    }

    if timestamps.windows(2).any(|pair| pair[0] == pair[1]) {
        return TimestampGranularity::Coarse;
    }
    TimestampGranularity::Fine
}

/// Whether the filesystem holding the process temp dir can prove object identity across
/// observations (an anti-reuse generation, or a fine-grained birth time). tmpfs offers
/// neither, so the sync code correctly treats an unchanged object as `Ambiguous` and declines
/// to author or replace it. Tests whose premise is "the same object is recognised again" call
/// this first and skip on such a volume instead of failing for an environment reason; point
/// `TMPDIR` at a disk-backed directory to run them. Prints the reason when it answers `false`.
#[cfg(any(test, feature = "test-support"))]
pub fn temp_dir_proves_object_identity_for_test() -> bool {
    let dir = std::env::temp_dir();
    let granularity = probe_birth_time_granularity(&dir);
    let proven = match create_probe_artefact(&dir, "identity-proof", b"x") {
        Ok((path, _file)) => {
            let proven =
                match (FileIdentity::observe_path(&path), FileIdentity::observe_path(&path)) {
                    (Ok(a), Ok(b)) => a.compare(&b, granularity) == IdentityComparison::SameObject,
                    _ => false,
                };
            let _ = std::fs::remove_file(&path);
            proven
        }
        Err(_) => false,
    };
    if !proven {
        eprintln!(
            "SKIPPED: the temp filesystem cannot prove object identity (e.g. tmpfs); \
             set TMPDIR to a disk-backed directory to run this test"
        );
    }
    proven
}

/// Process-wide cache for [`probe_birth_time_granularity`]'s result, keyed
/// by [`VolumeIdentity`] rather than path for the same reason
/// [`CapabilityCacheKey`] already is: a path is not a stable proxy for a
/// filesystem (a removable drive can be reformatted at the same mountpoint;
/// a network/container mount can be replaced entirely), so a path-keyed
/// cache could silently keep serving a stale volume's granularity after a
/// remount. A real probe performs genuine physical work -- creating,
/// stat'ing and unlinking `GRANULARITY_SAMPLE_COUNT` artefacts -- so callers
/// on a hot path must not pay it on every call. `verify_still_owns`
/// (`sync_root_lock.rs`) is called from [`crate::root_commit::RootLease::
/// begin_operation`], which fires on essentially every local capture,
/// materialize, and hydration operation; uncached, it would re-probe on
/// every single one -- a real, measurable per-operation tax (~96 syscalls
/// per probe, all inside the sync root the filesystem watcher is itself
/// watching, thousands of probes in a short 2,000-file burst). Falls back to an uncached probe
/// (never a stale
/// answer) if the volume identity itself cannot even be observed.
static BIRTH_TIME_GRANULARITY_CACHE: std::sync::OnceLock<
    Mutex<HashMap<VolumeIdentity, TimestampGranularity>>,
> = std::sync::OnceLock::new();

/// Cached wrapper for [`probe_birth_time_granularity`]. Prefer this over the
/// raw probe for any caller invoked more than once per process lifetime for
/// the same root (which is every caller outside this module's own tests).
pub fn cached_probe_birth_time_granularity(dir: &Path) -> TimestampGranularity {
    let Ok(volume_identity) = observe_volume_identity(dir) else {
        return probe_birth_time_granularity(dir);
    };
    cached_granularity_for_volume(volume_identity, || probe_birth_time_granularity(dir))
}

/// The pure caching decision [`cached_probe_birth_time_granularity`]
/// delegates to, factored out so a test can exercise "same volume identity
/// reuses the cached probe; a different one re-probes" directly with
/// synthetic identities, without needing to actually remount a real volume.
///
/// Holds the lock across `probe` itself (matching `yadorilink-daemon`'s
/// `peer_replica_state.rs::cached_granularity_for_volume`, the precedent
/// this mirrors) rather than releasing it for the probe and re-locking to
/// record the result: the latter shape is single-flight only after the
/// first successful probe, not on it -- N concurrent first callers for the
/// same volume would all miss the cache and all pay the full uncached probe
/// cost, a thundering herd of exactly the syscall storm this cache exists
/// to remove. `RootLease::begin_operation` is reachable concurrently from
/// many in-flight operations, so the first-probe race is not theoretical.
fn cached_granularity_for_volume(
    volume_identity: VolumeIdentity,
    probe: impl FnOnce() -> TimestampGranularity,
) -> TimestampGranularity {
    let cache = BIRTH_TIME_GRANULARITY_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard.entry(volume_identity).or_insert_with(probe)
}

/// The outcome of [`rename_no_replace`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RenameOutcome {
    /// The move happened; the source path is gone and the destination now
    /// holds what the source held.
    Renamed,
    /// The move did not happen, for any reason (the destination was
    /// occupied, the no-replace primitive is unavailable on this volume,
    /// or an unrelated I/O error). Both the source and destination are
    /// exactly as they were before the call.
    NotRenamed,
}

/// Moves `from` to `to` without ever touching a preexisting object at
/// `to`, using the platform's own no-replace rename primitive where this
/// module has one available.
///
/// On Linux and macOS this uses `renameat2(RENAME_NOREPLACE)` /
/// `renamex_np(RENAME_EXCL)` — the same two syscalls
/// [`platform_atomic_exchange`] already uses, with a different flag — and
/// reports [`RenameOutcome::NotRenamed`] on *any* failure. A racing actor
/// occupying `to` (`EEXIST`) and the primitive itself being unavailable on
/// this volume (a feature-absence errno, per [`classify_errno`]'s usual
/// set) are deliberately not distinguished: the caller's response to
/// either is identical (do not touch `to`, treat the whole operation as
/// `Unknown`), and unlike the other probes in this module there is no
/// `Unsupported` for this primitive to report — a capability probe that
/// cannot attempt an operation safely must not fall back to an unsafe one
/// just to produce a more specific answer. It never falls back to a
/// clobbering rename.
///
/// **Windows is a known, accepted residual — see the platform-specific
/// implementation below.**
#[cfg(target_os = "linux")]
fn rename_no_replace(from: &Path, to: &Path) -> RenameOutcome {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let (Some(from_c), Some(to_c)) = (
        CString::new(from.as_os_str().as_bytes()).ok(),
        CString::new(to.as_os_str().as_bytes()).ok(),
    ) else {
        return RenameOutcome::NotRenamed;
    };
    // Called through the raw syscall number for the same reason
    // `platform_atomic_exchange` is: glibc only exports `renameat2` from
    // 2.28, and uClibc does not export it at all.
    // SAFETY: `from_c`/`to_c` are valid NUL-terminated paths kept alive
    // for the duration of the call.
    let (ret, _errno) = retry_eintr_syscall(|| {
        call_and_capture_errno!(unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from_c.as_ptr(),
                libc::AT_FDCWD,
                to_c.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        })
    });
    // The errno is deliberately discarded — see the doc comment on why
    // `EEXIST` and feature-absence are not distinguished here.
    if ret == 0 {
        RenameOutcome::Renamed
    } else {
        RenameOutcome::NotRenamed
    }
}

/// See [`rename_no_replace`]'s doc (the Linux implementation) for the
/// shared reasoning. macOS side: `renamex_np(RENAME_EXCL)`.
#[cfg(target_vendor = "apple")]
fn rename_no_replace(from: &Path, to: &Path) -> RenameOutcome {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let (Some(from_c), Some(to_c)) = (
        CString::new(from.as_os_str().as_bytes()).ok(),
        CString::new(to.as_os_str().as_bytes()).ok(),
    ) else {
        return RenameOutcome::NotRenamed;
    };
    // SAFETY: `from_c`/`to_c` are valid NUL-terminated paths owned for the
    // duration of the call.
    let (ret, _errno) = retry_eintr(|| {
        call_and_capture_errno!(unsafe {
            libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL)
        })
    });
    if ret == 0 {
        RenameOutcome::Renamed
    } else {
        RenameOutcome::NotRenamed
    }
}

/// **Accepted residual on Windows and any other platform.** A true
/// no-replace primitive here (`ReplaceFileW`/`SetFileInformationByHandle`
/// with `FILE_RENAME_FLAG_POSIX_SEMANTICS`, depending on Windows version)
/// would need a `windows-sys`/`winapi` dependency this phase does not add.
/// This falls back to a plain `std::fs::rename`, which — unlike the
/// Linux/macOS path above — CAN silently overwrite an unrelated file a
/// racing actor placed at `to` between [`reserve_probe_artefact_path`]'s
/// check and this call. That is a possible *clobber*, not merely a
/// possible wrongful delete (the class of bug the rest of this module's
/// ownership discipline otherwise avoids). It is accepted here only
/// because eliminating it needs a dependency this phase does not add, and
/// is called out here explicitly rather than left silent.
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn rename_no_replace(from: &Path, to: &Path) -> RenameOutcome {
    match std::fs::rename(from, to) {
        Ok(()) => RenameOutcome::Renamed,
        Err(_) => RenameOutcome::NotRenamed,
    }
}

/// Shared probe body for [`FilesystemSafetyCapabilities::stable_source_
/// identity`] and [`FilesystemSafetyCapabilities::stable_owned_marker_
/// identity`] — see both fields' docs for why this increment answers them
/// with the identical procedure and result. Creates a fresh file, renames
/// it in place, and asks [`FileIdentity::compare`] whether the before/after
/// observation is `SameObject`.
fn probe_stable_identity(dir: &Path) -> Capability {
    let Ok((before_path, before_file)) =
        create_probe_artefact(dir, "identity-before", b"identity probe")
    else {
        return Capability::Unknown;
    };
    drop(before_file);
    let Ok(after_path) = reserve_probe_artefact_path(dir, "identity-after") else {
        let _ = std::fs::remove_file(&before_path);
        return Capability::Unknown;
    };

    let before = match FileIdentity::observe_path(&before_path) {
        Ok(identity) => identity,
        Err(_) => {
            let _ = std::fs::remove_file(&before_path);
            return Capability::Unknown;
        }
    };

    if rename_no_replace(&before_path, &after_path) == RenameOutcome::NotRenamed {
        // Either a racing actor occupies `after_path`, or this volume has
        // no safe way to attempt the move at all — either way `to` was
        // never touched (see `rename_no_replace`'s doc) and must not be
        // removed; `before_path` is still exactly what this probe created
        // and is still its to clean up.
        let _ = std::fs::remove_file(&before_path);
        return Capability::Unknown;
    }

    let result = (|| -> io::Result<Capability> {
        let after = FileIdentity::observe_path(&after_path)?;
        // Measured against this same directory, not assumed `Fine`: a
        // coarse clock is exactly the condition under which a rename-only
        // check (no discriminator-availability awareness) would have
        // wrongly reported `Supported` before this fix — see
        // `TimestampGranularity`'s doc.
        let granularity = probe_birth_time_granularity(dir);
        // Ask the exact question the capability advertises: does
        // `FileIdentity::compare` — the primitive callers will actually
        // use — treat this as the same object. Checking the raw fields by
        // hand here would let this probe and `compare`'s own rule drift
        // apart silently.
        Ok(match before.compare(&after, granularity) {
            IdentityComparison::SameObject => Capability::Supported,
            IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
                Capability::Unsupported
            }
        })
    })();

    // The rename succeeded: `before_path` no longer exists (it *is*
    // `after_path` now, which this call produced), so only `after_path`
    // needs cleanup.
    let _ = std::fs::remove_file(&after_path);
    result.unwrap_or(Capability::Unknown)
}

/// Classifies a failed `remove_file` on a path this probe still holds an
/// open handle to. Only Windows' documented "can't unlink an open file
/// under the default sharing mode" errno counts as the definite negative
/// answer this capability probes for; any other failure (a permission
/// race, a transient I/O error) says nothing about whether stale-handle
/// preservation is supported here and must stay `Unknown` — the same
/// errno discipline `classify_errno` applies to the raw-syscall probes,
/// applied to a `std`-returned `io::Error` instead.
fn classify_unlink_while_open_failure(err: &io::Error) -> Capability {
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION: the file is open without
        // FILE_SHARE_DELETE, which is Windows' default and exactly the
        // condition this probe exists to detect.
        const ERROR_SHARING_VIOLATION: i32 = 32;
        if err.raw_os_error() == Some(ERROR_SHARING_VIOLATION) {
            return Capability::Unsupported;
        }
    }
    let _ = err;
    Capability::Unknown
}

fn probe_stale_handle_preservation(dir: &Path) -> Capability {
    let Ok((path, mut file)) = create_probe_artefact(dir, "stale-handle", b"before") else {
        return Capability::Unknown;
    };

    let result = (|| -> io::Result<Capability> {
        // If the platform will not even let the path be removed while the
        // handle is open, that is only the accurate negative answer for
        // this capability when the failure is specifically the
        // sharing-violation Windows uses to signal it — see
        // `classify_unlink_while_open_failure`.
        if let Err(err) = std::fs::remove_file(&path) {
            return Ok(classify_unlink_while_open_failure(&err));
        }

        std::io::Write::write_all(&mut file, b"-after")?;
        std::io::Write::flush(&mut file)?;
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        Ok(if buf == b"before-after" { Capability::Supported } else { Capability::Unsupported })
    })();

    // Reached only when the `remove_file` above failed (the success path
    // already removed it), in which case the artefact is genuinely still
    // there and still this probe's to clean up.
    let _ = std::fs::remove_file(&path);
    result.unwrap_or(Capability::Unknown)
}

#[cfg(unix)]
fn probe_metadata_fidelity(dir: &Path) -> Capability {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok((path, _)) = create_probe_artefact(dir, "metadata-fidelity", b"metadata probe") else {
        return Capability::Unknown;
    };
    let result = (|| -> io::Result<Capability> {
        let probe_mode = 0o741;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(probe_mode))?;
        let observed = std::fs::metadata(&path)?.mode() & 0o777;
        Ok(if observed == probe_mode { Capability::Supported } else { Capability::Unsupported })
    })();
    let _ = std::fs::remove_file(&path);
    result.unwrap_or(Capability::Unknown)
}

#[cfg(windows)]
fn probe_metadata_fidelity(dir: &Path) -> Capability {
    let Ok((path, _)) = create_probe_artefact(dir, "metadata-fidelity", b"metadata probe") else {
        return Capability::Unknown;
    };
    let result = (|| -> io::Result<Capability> {
        let mut permissions = std::fs::metadata(&path)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions)?;
        let observed_readonly = std::fs::metadata(&path)?.permissions().readonly();
        Ok(if observed_readonly { Capability::Supported } else { Capability::Unsupported })
    })();
    // Clear the readonly bit unconditionally, regardless of which branch
    // above returned or errored, so the artefact is never left behind in a
    // state where an ordinary `remove_file` cannot delete it — every exit
    // path above reaches this, not just the success path.
    if let Ok(metadata) = std::fs::metadata(&path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            // The read-only attribute is the Windows file attribute here; the
            // lint's Unix world-writable concern does not apply to a probe
            // artefact this process created.
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(&path, permissions);
        }
    }
    if std::fs::remove_file(&path).is_err() {
        tracing::warn!(
            path = %path.display(),
            "failed to remove filesystem-capability probe artefact"
        );
    }
    result.unwrap_or(Capability::Unknown)
}

#[cfg(test)]
mod tests;
