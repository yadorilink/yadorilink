//! The reserved on-disk artefact namespace.
//!
//! Filesystem-transaction artefacts (staged writes, captured preimages,
//! backups, retained-custody copies and filesystem-capability probe
//! artefacts) live *beside* the user object they belong to, under the same
//! parent directory, so their commit — or, for a probe, the operation it
//! measures — can share the same filesystem and volume as the object
//! itself. That only works if every path-consuming entry point in this
//! crate — the watcher, local change processing, the initial scan,
//! peer admission and stale-file cleanup — agrees on exactly which
//! names are reserved, and agrees on it *before* user ignore rules run: a
//! user can configure `.yadorilinkignore` to un-ignore anything, but must
//! never be able to make an artefact name eligible for ordinary indexing.
//!
//! This module is that single shared predicate. It is a naming *protocol*,
//! not a convention a caller can opt out of: a path component that matches
//! is never content, regardless of what created it or what any ignore file
//! says.
//!
//! # Ownership rule
//!
//! Recognizing a name as reserved is not the same as owning it. A component
//! matching this predicate that no journal row (or, for the legacy marker,
//! no in-flight writer this process itself started) claims is an unknown
//! artefact: leftover from a crash, a different process, or a future
//! version this build doesn't understand. An unknown reserved-looking file
//! must never be deleted, imported, indexed or treated as user content —
//! see `SyncError::ReservedNamespaceCollision` for the
//! fail-closed signal a caller raises when it finds one somewhere it did
//! not expect one.
//!
//! This module only recognizes names. It does not yet track which artefact
//! a given journal row owns — that arrives with the journal itself.
//!
//! # Two predicates, not one
//!
//! There are two different questions a caller can ask, and they must not be
//! collapsed into a single function:
//!
//! - **"Should this stay out of ordinary sync?"** — [`is_reserved_component`]
//!   / [`path_has_reserved_component`]. True for both a versioned artefact
//!   and the legacy marker. Used by the watcher, the initial scan, local
//!   change processing: every place that decides what to
//!   index or track. `fs_capabilities`'s probe artefacts rely on exactly
//!   this predicate to stay invisible to those entry points for the brief
//!   window between their creation and their own removal — see
//!   [`ArtefactKind::Probe`].
//! - **"May a peer or a local writer *name* this path at all?"** —
//!   [`is_artefact_component`] / [`path_has_artefact_component`]. True only
//!   for a versioned artefact, never for the legacy marker. Used by native
//!   admission and peer materialization: every place that fails a whole
//!   operation closed.
//!
//! The legacy marker is exclusion-only by design (see
//! [`ReservedComponent::Legacy`]): `contains_legacy_marker` is a substring
//! test within a component, deliberately looser than the versioned kinds'
//! whole-component match, because arbitrary user content can precede it
//! (`report.yadorilink-tmp.old`) — `materialization::cleanup_stale_temp_
//! files` already refuses to delete exactly such a look-alike. Two things
//! follow from that looseness, and both are why the legacy marker must
//! never reach a rejection site:
//!
//! - A change or a peer write naming a legacy-marked path is not
//!   necessarily an artefact at all — it can be an ordinary user file that
//!   merely contains the substring, and rejecting it would make a real file
//!   permanently un-syncable, in direct conflict with the GC's own
//!   preservation of that same file.
//! - History predating this module can already contain a legacy-marked
//!   path, admitted back when nothing excluded it (that gap is exactly the
//!   latent bug this module closes at the exclusion sites). If admission
//!   used the exclusion predicate, an upgraded peer would refuse that
//!   already-signed change forever — turning a client-side fix into a
//!   group-wide sync stall.
//!
//! So exclusion is deliberately over-inclusive (better to skip indexing a
//! look-alike than risk treating a real artefact as content), while
//! rejection is deliberately narrow (only a name this module itself can
//! construct is grounds for refusing an entire operation).

use std::ffi::OsStr;
use std::path::Path;
use yadorilink_replica_domain::reserved_paths::SYNC_ROOT_LOCK_FILE_NAME;

/// Every reserved-component name (including the legacy marker) is bounded
/// by this length, in bytes, once encoded — the portable floor most
/// filesystems enforce for a single path component (`NAME_MAX` on Linux,
/// `_PC_NAME_MAX` elsewhere, ext4/APFS/NTFS all at or above it). A
/// generated name that would exceed this is a construction error, never a
/// silently truncated one: a truncated artefact name could collide with
/// another truncated name, or with unrelated user content.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Identifies exactly which version of this module's rejection rules —
/// `path_has_artefact_component_in_wire_path` and
/// `path_has_non_portable_wire_component`, and everything either calls —
/// produced a verdict. **Bump this whenever those rules change** — the
/// legacy/artefact predicate split, the Windows trailing-dot/space
/// normalization, the ADS-suffix/dual-separator wire canonicalization,
/// `path_has_non_portable_wire_component`'s general portability predicate
/// (trailing dot/space, `:`, reserved Windows device names, and the other
/// Win32-reserved filename characters, for *any* path, not only
/// reserved-artefact look-alikes), and (this bump) that same predicate's
/// short-name-alias-shape, superscript-device-name and control-character
/// checks — each changed which paths this module considers reserved —
/// exactly the situation this constant exists for.
///
/// `dag_store::rejected_changes` stamps every durable rejection PRODUCED BY
/// THESE RULES with this value and refuses to trust a row stamped with an
/// older one as a settled, permanent verdict — see that module's doc
/// comment. Rejections from other rule domains, such as a change refused by
/// its own author's chain, carry their own domain's version and are neither
/// invalidated by a bump here nor kept current by the absence of one.
/// Forgetting
/// to bump this when the rules change reintroduces the same failure mode as
/// the silent-stranding bug this namespace's exclusion sites were fixed to
/// avoid, arriving through a different door: a change rejected under
/// yesterday's rules stays permanently unadmittable even after today's
/// rules would accept it, because nothing ever re-evaluates a "settled"
/// verdict.
///
/// Bumped again for [`ArtefactKind::Discard`] for the same reason: a wire
/// path shaped `.yadorilink-v1-discard.<id>` is now a reserved name.
///
/// Also bumped for [`ArtefactKind::Probe`]: adding a kind to
/// [`ArtefactKind::ALL`] widens `parse_artefact_component`, which backs
/// both the host and the wire predicates — a wire path shaped
/// `.yadorilink-v1-probe.<id>` now classifies as
/// [`ReservedComponent::Artefact`] where it previously classified as
/// ordinary content, exactly the "which paths this module considers
/// reserved" change this constant exists to version. No legitimate change
/// ever wants that literal path (a probe artefact is never journaled or put
/// on the wire), so the practical effect is only that a peer can no longer
/// name a file that shape — but the verdict for that shape changed, so the
/// version must too.
pub const RULES_VERSION: u32 = 5;

/// The versioned artefact kinds from the reserved namespace. Each maps to a
/// literal ASCII prefix that appears in `.yadorilink-v1-<kind>.<id>` — see
/// [`ReservedComponent::kind_prefix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtefactKind {
    /// A write staged beside its eventual target, not yet committed.
    Stage,
    /// A captured preimage of an object about to be replaced or removed.
    Preimage,
    /// A backup produced by a platform commit adapter as part of an atomic
    /// replace (e.g. Windows `ReplaceFileW`'s backup file).
    Backup,
    /// A preimage retained past its transaction's commit, held for later
    /// custody/repair purposes rather than GC'd immediately.
    Retained,
    /// A throwaway artefact created and removed within a single
    /// [`crate::fs_capabilities`] probe call (a birth-time-granularity
    /// sample, an exchange/clone/flush probe target, and so on). Distinct
    /// from the other three kinds in one respect: no journal row ever
    /// claims one, by design — a probe artefact's whole lifetime is
    /// contained inside one function call on this process, so there is
    /// nothing for a journal to record. It still needs its own reserved
    /// name, for the same reason the others do: it is created inside a
    /// live sync directory, beside real user content, and must be invisible
    /// to the watcher, the initial scan and local change processing for the
    /// window between its creation and its own removal — an unreserved name
    /// there would let a race admit it as an ordinary file (see
    /// `fs_capabilities::probe_artefact_name`'s doc for the concrete
    /// mechanism this closes).
    Probe,
    /// An object the product has decided to remove, moved aside beside its
    /// former path by a write-through move (the commit point of the removal)
    /// and not yet physically deleted. Like [`ArtefactKind::Stage`] it is
    /// owned only by a durable ledger row that names it; a name found without
    /// such a row is never inferred to be ours and is left alone.
    Discard,
}

impl ArtefactKind {
    const ALL: [ArtefactKind; 6] = [
        ArtefactKind::Stage,
        ArtefactKind::Preimage,
        ArtefactKind::Backup,
        ArtefactKind::Retained,
        ArtefactKind::Probe,
        ArtefactKind::Discard,
    ];

    /// The lowercase ASCII token that follows `.yadorilink-v1-` in a
    /// generated name, e.g. `"stage"` for [`ArtefactKind::Stage`].
    fn kind_prefix(self) -> &'static str {
        match self {
            ArtefactKind::Stage => "stage",
            ArtefactKind::Preimage => "preimage",
            ArtefactKind::Backup => "backup",
            ArtefactKind::Retained => "retained",
            ArtefactKind::Probe => "probe",
            ArtefactKind::Discard => "discard",
        }
    }
}

/// Prefix shared by every versioned artefact name, before the kind token.
const V1_PREFIX: &str = ".yadorilink-v1-";

/// The temp-file marker materialization writers use: older builds appended
/// `.yadorilink-tmp.<pid>.<counter>` to the file's own name, current ones
/// name the temp `.yadorilink-tmp.<random hex>`. Both contain it. It predates
/// this module and keeps its own strict-suffix shape and is removed by name from the
/// writers' durable temp-file records, not by pattern, rather than being folded
/// into the versioned namespace — see [`ReservedComponent::Legacy`]'s doc
/// comment for why.
const LEGACY_MARKER: &str = ".yadorilink-tmp.";

/// A path component recognized by the reserved namespace, distinguishing an
/// artefact this module can name and construct from the legacy marker it
/// only recognizes for exclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedComponent<'a> {
    /// A `.yadorilink-v1-<kind>.<id>` artefact this module owns the naming
    /// scheme for.
    Artefact { kind: ArtefactKind, id: &'a str },
    /// The `.yadorilink-tmp.` marker (`<name>.yadorilink-tmp.<pid>.<counter>`
    /// from older builds, `.yadorilink-tmp.<random hex>` now). Additive:
    /// this module recognizes it purely so it is excluded from indexing
    /// alongside the versioned kinds, but does not construct, parse or own
    /// it beyond that — the materialization writers still mint it and
    /// the recorded-temp-file recovery still removes it by its record. A daemon upgrade must not
    /// orphan an in-flight temp file from the previous version with no
    /// collector, so the legacy marker keeps working exactly as it always
    /// has; this variant only ever appears for **exclusion**, never for
    /// construction.
    Legacy,
}

/// Why `artefact_component_name` refused to build a name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtefactNameError {
    /// The constructed name would exceed [`MAX_COMPONENT_BYTES`] once
    /// encoded. Returned instead of silently truncating, since a truncated
    /// name could collide with another artefact or with unrelated user
    /// content.
    #[error(
        "reserved artefact name for id {id:?} is {actual_bytes} bytes, exceeding the \
         {MAX_COMPONENT_BYTES}-byte portable component limit"
    )]
    TooLong { id: String, actual_bytes: usize },
    /// `id` contains a byte outside the reserved namespace's token
    /// alphabet (ASCII alphanumeric, `-` and `_`). In particular `id` may
    /// not contain `.` or `/`: allowing either would make the boundary
    /// between "kind token" and "id" ambiguous when re-parsing the name
    /// with [`parse_artefact_component`], and a `/` could be misread as a
    /// path separator by a caller that treats the returned string as a
    /// single component without checking.
    #[error(
        "reserved artefact id {id:?} contains a byte outside [A-Za-z0-9_-]; \
         constructed component names must stay unambiguous to re-parse"
    )]
    InvalidId { id: String },
}

/// Whether every byte of `id` is in the reserved namespace's token
/// alphabet — see [`ArtefactNameError::InvalidId`].
fn is_valid_id(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Builds the on-disk component name for `(kind, id)`: exactly
/// `.yadorilink-v1-<kind>.<id>`. `id` must be a non-empty run of ASCII
/// alphanumerics, `-` and `_` (e.g. hex or base32 both fit) — see
/// [`ArtefactNameError::InvalidId`] for why the alphabet is restricted.
pub fn artefact_component_name(kind: ArtefactKind, id: &str) -> Result<String, ArtefactNameError> {
    if !is_valid_id(id) {
        return Err(ArtefactNameError::InvalidId { id: id.to_string() });
    }
    let name = format!("{V1_PREFIX}{}.{id}", kind.kind_prefix());
    if name.len() > MAX_COMPONENT_BYTES {
        return Err(ArtefactNameError::TooLong { id: id.to_string(), actual_bytes: name.len() });
    }
    Ok(name)
}

/// Parses a path component's name back into `(kind, id)`, or `None` if it
/// does not match any versioned artefact kind. ASCII case-folded, matching
/// [`is_reserved_component`] — `.YADORILINK-V1-STAGE.x` parses the same as
/// `.yadorilink-v1-stage.x`. Returns a borrow of `id` from `name`, so the
/// id is returned exactly as spelled on disk (not case-folded). `id` must
/// pass [`is_valid_id`]; anything else (in particular, a `.`-separated
/// trailer after what looks like an id) is not a well-formed artefact name
/// and is treated as ordinary content rather than guessed at.
pub fn parse_artefact_component(name: &str) -> Option<(ArtefactKind, &str)> {
    let lower_prefix_len = V1_PREFIX.len();
    if name.len() < lower_prefix_len || !name.is_char_boundary(lower_prefix_len) {
        return None;
    }
    if !name[..lower_prefix_len].eq_ignore_ascii_case(V1_PREFIX) {
        return None;
    }
    let rest = &name[lower_prefix_len..];
    for kind in ArtefactKind::ALL {
        let prefix = kind.kind_prefix();
        let Some(len) = prefix.len().checked_add(1) else { continue };
        if rest.len() < len || !rest.is_char_boundary(prefix.len()) || !rest.is_char_boundary(len) {
            continue;
        }
        if rest[..prefix.len()].eq_ignore_ascii_case(prefix)
            && rest.as_bytes()[prefix.len()] == b'.'
        {
            let id = &rest[len..];
            if !is_valid_id(id) {
                continue;
            }
            return Some((kind, id));
        }
    }
    None
}

/// Whether `name` carries the temp-file marker the materialization writers
/// generate, recognized only for exclusion — see [`ReservedComponent::Legacy`].
/// ASCII case-folded and component-exact in the same sense as
/// [`is_reserved_component`]: it requires the literal marker to appear as a
/// substring (matching the older shape
/// `<original-name>.yadorilink-tmp.<pid>.<counter>`, where arbitrary user
/// content precedes the marker within the same component), not that the
/// whole component equal it. No deletion decision is made from the
/// name; this function only decides "exclude from
/// indexing," which must be at least as permissive as that stricter check
/// so nothing importable slips through the gap between the two.
fn contains_legacy_marker(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains(&LEGACY_MARKER.to_ascii_lowercase())
}

/// Windows silently drops trailing `.` and ` ` characters from a path
/// component in most Win32 APIs (`CreateFileW` and friends): a caller that
/// asks for `"foo. "` or `"foo.."` gets a file literally named `"foo"` on
/// disk. Applied here, on every platform, before matching against the
/// versioned artefact shape — this predicate is a wire-facing security
/// boundary (a peer on any platform authors the path; the device that
/// eventually materializes it may be a Windows device regardless of which
/// platform is running this check right now), so a peer-supplied
/// `".yadorilink-v1-stage.<id> "` (one trailing space) or
/// `".yadorilink-v1-stage.<id>."` (trailing dot) must classify exactly the
/// same as the un-suffixed name: neither is component-exact as *typed*, but
/// both land on disk, on Windows, as the literal reserved name. Matching
/// only the untrimmed name here would let a peer plant — or later collide
/// with, or falsely block via `ReservedNamespaceCollision` — an artefact
/// this module owns, without ever spelling its exact name on the wire.
///
/// Deliberately NOT applied to the legacy-marker substring check below:
/// `contains_legacy_marker` already matches through arbitrary trailing
/// content (it is a substring test, not a full match), so trailing
/// dots/spaces on a legacy-shaped name change nothing about whether the
/// marker is present.
fn strip_windows_trailing_normalization(name: &str) -> &str {
    name.trim_end_matches(['.', ' '])
}

/// Truncates at the first `:` — strips an NTFS alternate-data-stream
/// suffix. `filename::$DATA` addresses `filename`'s own default stream
/// (they are the same on-disk object), and `filename:stream:$DATA`
/// addresses a named stream *on* `filename` — both mutate `filename`
/// itself, not some other file. `:` is not a legal NTFS filename
/// character outside this syntax, but `change::validate_path` (the wire
/// validator) permits it — it only rejects a drive-qualified first
/// segment — and a POSIX filesystem allows a literal `:` in a name, so a
/// peer can spell `".yadorilink-v1-stage.<id>::$DATA"` or
/// `".yadorilink-v1-stage.<id>:payload:$DATA"` and have neither
/// `validate_path` nor a naive component-exact match ever notice it is an
/// alias for the reserved artefact `<id>`. Truncating before matching is
/// what makes `parse_artefact_component` see the same name a Windows
/// materializer's disk actually resolves to.
pub(crate) fn strip_alternate_data_stream_suffix(name: &str) -> &str {
    name.split(':').next().unwrap_or(name)
}

/// Core classification shared by every predicate in this module: matches
/// `normalized` against the versioned artefact shape, and `raw` against
/// the legacy substring marker. Callers differ only in how they arrive at
/// `normalized` (host-`Path`-component callers strip Windows trailing
/// dot/space; wire-path callers additionally strip an ADS suffix and split
/// on both separators before ever reaching here) — the match itself, and
/// the ASCII-only case folding it performs, must be identical either way.
/// `raw` is deliberately never normalized for the legacy check: it is
/// already a substring test, permissive by design (see
/// [`contains_legacy_marker`]), so trimming its input can only ever widen
/// what it matches, never narrow it, and there is no bypass to close.
fn classify_normalized_component<'a>(
    normalized: &'a str,
    raw: &'a str,
) -> Option<ReservedComponent<'a>> {
    if let Some((kind, id)) = parse_artefact_component(normalized) {
        return Some(ReservedComponent::Artefact { kind, id });
    }
    if contains_legacy_marker(raw) {
        return Some(ReservedComponent::Legacy);
    }
    None
}

/// Classifies a single path component (a `Path::components()` item's
/// `.as_os_str()`, or any other single filename/directory-name string —
/// never a multi-segment path), or `None` if it is ordinary user content.
///
/// This is the **host** form: it consults this process's own
/// `std::path::Path` (via its `OsStr` input) to have already found the
/// component boundary, and applies Windows trailing-dot/space
/// normalization but NOT alternate-data-stream stripping (a real
/// directory listing, on any OS, never hands back an ADS-suffixed entry
/// name — that syntax only exists at the point a caller opens a path, not
/// as a name anything enumerates). Suitable for a path that this
/// process itself walked off a real, local directory tree: the watcher,
/// the initial scan, local change processing, `link_preflight`, stale-file
/// cleanup. NOT suitable for a peer-authored path string — see
/// [`path_has_artefact_component_in_wire_path`] for why that needs the
/// separate wire form.
///
/// ASCII case-folded (never Unicode case folding — the reserved names are
/// pure ASCII, and Unicode case folding could map an unrelated user
/// filename onto one of them in some locale/normalization forms).
/// Component-exact for the versioned kinds, up to Windows's trailing
/// dot/space normalization (see [`strip_windows_trailing_normalization`]):
/// `notes.yadorilink-v1-stage.x` does not match, only a component that *is*
/// the artefact name (modulo that trailing-character stripping). This
/// mirrors the rule that recovery never deletes by name: it
/// deliberately rejects treating a user file that merely
/// *contains* `.yadorilink-tmp.` as one of its own temp files.
pub fn classify_component(name: &OsStr) -> Option<ReservedComponent<'_>> {
    let name = name.to_str()?;
    let normalized = strip_windows_trailing_normalization(name);
    classify_normalized_component(normalized, name)
}

/// Whether a single path component is reserved, in either sense
/// ([`ReservedComponent::Artefact`] or [`ReservedComponent::Legacy`]) — the
/// predicate every entry point applies before user ignore rules. See
/// [`classify_component`] for case-folding and component-exactness details.
pub fn is_reserved_component(name: &OsStr) -> bool {
    classify_component(name).is_some()
}

/// Whether any component of `relative_path` is reserved. `relative_path`
/// must already be root-relative (this makes no attempt to resolve `..` or
/// symlinks — callers combine this with their own root-confinement checks).
/// This is the path-level form of [`is_reserved_component`]: a reserved
/// component anywhere in the path — not only the final one — makes the
/// whole path reserved, since a transaction artefact used as an
/// intermediate directory is exactly as impermissible as one used as a
/// leaf.
pub fn path_has_reserved_component(relative_path: &Path) -> bool {
    relative_path.components().any(|c| is_reserved_component(c.as_os_str()))
}

/// Like [`path_has_reserved_component`], but returns the specific
/// component found, for callers that want to report or classify it rather
/// than only exclude it.
pub fn find_reserved_component(relative_path: &Path) -> Option<ReservedComponent<'_>> {
    relative_path.components().find_map(|c| classify_component(c.as_os_str()))
}

/// Whether a single path component is a versioned artefact this module
/// owns the naming scheme for — `false` for the legacy marker. This is the
/// **rejection** predicate for a **host**-sourced component (one this
/// process itself walked off a real local directory tree — see
/// [`classify_component`]'s doc comment on that distinction). See the
/// module doc's "Two predicates, not one" section for why the legacy
/// marker must not reach a rejection site, and [`is_reserved_component`]
/// for the (deliberately broader) exclusion predicate used everywhere
/// else.
pub fn is_artefact_component(name: &OsStr) -> bool {
    matches!(classify_component(name), Some(ReservedComponent::Artefact { .. }))
}

/// The path-level form of [`is_artefact_component`] — true if any component
/// of `relative_path` is a versioned artefact. Never true for a
/// legacy-marked path; see [`is_artefact_component`].
///
/// `relative_path` must be a **host** path this process itself produced
/// (from an actual `Path::components()` walk) — NOT a raw path string that
/// arrived off the wire. For that, use
/// [`path_has_artefact_component_in_wire_path`] instead; see its doc
/// comment for why the two must not be interchanged.
pub fn path_has_artefact_component(relative_path: &Path) -> bool {
    relative_path.components().any(|c| is_artefact_component(c.as_os_str()))
}

/// Splits a peer-authored path **string** into components the same way
/// `change::validate_path` accepts it: on **both** `/` and `\`, regardless
/// of which OS is evaluating it right now.
///
/// A path string reaching this function was authored on an arbitrary
/// remote peer and will be evaluated — and, once the transaction engine
/// lands, ultimately materialized — on an arbitrary local platform. Using
/// this process's own `std::path::Path` to find component boundaries (as
/// [`path_has_artefact_component`] correctly does for a path this process
/// itself walked off disk) would silently make admission depend on which
/// OS happens to be running the check: `safe\.yadorilink-v1-stage.x` is
/// ONE component on Unix (so it is admitted) and TWO on Windows (so the
/// second, `.yadorilink-v1-stage.x`, is rejected) — an authorized peer's
/// signed change would then be admitted by every Unix peer and refused
/// forever by every Windows peer, permanently splitting the group along
/// platform lines behind a `Path` that never actually got resolved on
/// either device. This function is the canonical, host-independent
/// definition of "a path component" for reserved-namespace REJECTION of a
/// wire path; nothing here consults `std::path::Path`, and nothing in this
/// module's wire-path functions should.
pub(crate) fn wire_path_components(path: &str) -> impl Iterator<Item = &str> {
    path.split(['/', '\\'])
}

/// [`classify_component`]'s wire-path counterpart: same ASCII case-folded,
/// component-exact match, but additionally strips an alternate-data-stream
/// suffix (see [`strip_alternate_data_stream_suffix`]) before matching,
/// since a wire component was never enumerated off a real directory (where
/// that syntax cannot appear) — it was typed by a peer, which can spell
/// one.
fn classify_wire_component(component: &str) -> Option<ReservedComponent<'_>> {
    let ads_stripped = strip_alternate_data_stream_suffix(component);
    let normalized = strip_windows_trailing_normalization(ads_stripped);
    classify_normalized_component(normalized, component)
}

/// Whether a single wire-path component is a versioned artefact — the
/// wire-path counterpart to [`is_artefact_component`]. See
/// [`classify_wire_component`] and [`wire_path_components`] for what makes
/// this different from (and required instead of) the host form.
fn is_artefact_wire_component(component: &str) -> bool {
    matches!(classify_wire_component(component), Some(ReservedComponent::Artefact { .. }))
}

/// Whether any component of a peer-authored path **string** is a versioned
/// reserved-namespace artefact — the **rejection** predicate for
/// wire-sourced paths, paralleling [`path_has_artefact_component`] for
/// host-sourced ones.
///
/// Use this (never the host-`Path` form) at every site that rejects a
/// whole operation because of a path a peer supplied, rather than one this
/// process discovered on its own disk: native admission
/// (`dag_store::admit_change`) and peer materialization
/// (`PeerSyncSession::materialize`) are the two such sites today. Splits
/// on both `/` and `\` (see [`wire_path_components`]) and strips an
/// NTFS alternate-data-stream suffix per component (see
/// [`strip_alternate_data_stream_suffix`]) before matching, so
/// `".yadorilink-v1-stage.<id>::$DATA"`, `"safe\.yadorilink-v1-stage.<id>"`
/// and ordinary `".yadorilink-v1-stage.<id>"` are all rejected identically,
/// on every platform running the check, regardless of which platform
/// authored the path or will eventually materialize it.
pub fn path_has_artefact_component_in_wire_path(path: &str) -> bool {
    wire_path_components(path).any(is_artefact_wire_component)
}

/// Windows reserves these device names as a whole filename component,
/// case-insensitively, matched against the component's **stem** — the
/// part before its first `.` — not its whole name: `"CON"`, `"con.txt"`
/// and `"COM1.tar.gz"` are all reserved (Windows resolves the device by
/// stem alone; the rest of the name is never reached). Creating a file
/// under one of these names fails outright, every time, on every Windows
/// device — deterministic, not a silent alias, but the same "one
/// platform can never do this, another does it without complaint"
/// property as everything else in this module. A file literally named
/// `"CON"` is perfectly legal on Linux/macOS. Includes `CONIN$` and
/// `CONOUT$`, the console input/output device names, alongside the more
/// commonly listed `CON`/`PRN`/`AUX`/`NUL`/`COM*`/`LPT*` set.
const WINDOWS_RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "CONIN$",
    "CONOUT$",
];

/// Windows additionally reserves these device-name spellings using the
/// Unicode superscript-digit forms — `COM¹` (U+00B9), `COM²` (U+00B2),
/// `COM³` (U+00B3), and the `LPT` equivalents — as aliases for
/// `COM1`-`COM3` and `LPT1`-`LPT3` respectively; see
/// <https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file>.
/// Matched against the component's **stem**, exactly like
/// [`WINDOWS_RESERVED_DEVICE_NAMES`], but as an exact Unicode string rather
/// than ASCII case-folded: a digit has no case variant, so there is nothing
/// to fold.
const WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS: &[&str] =
    &["COM\u{00B9}", "COM\u{00B2}", "COM\u{00B3}", "LPT\u{00B9}", "LPT\u{00B2}", "LPT\u{00B3}"];

/// See [`WINDOWS_RESERVED_DEVICE_NAMES`] and
/// [`WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS`]. ASCII case-folded for the
/// former, exact-match for the latter, matching this module's other
/// predicates.
fn is_windows_reserved_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    WINDOWS_RESERVED_DEVICE_NAMES.iter().any(|reserved| stem.eq_ignore_ascii_case(reserved))
        || WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS.contains(&stem)
}

/// Every character Win32's `CreateFile` family refuses outright in a
/// filename, everywhere, on every Windows version — `<`, `>`, `"`, `|`,
/// `?`, `*` — plus `:`, which Win32 accepts syntactically but reinterprets
/// as the alternate-data-stream separator rather than an ordinary
/// character (see [`wire_component_is_non_portable`]'s doc comment for why
/// `:` is grouped with these rather than treated identically to them).
/// Each of `< > " | ? *` is a perfectly ordinary, legal character in a
/// Linux/macOS filename. Deliberately narrow: this is exactly Win32's own
/// reserved set, not every character a cautious tool might avoid (a
/// forward slash or backslash can never reach this function at all — see
/// [`wire_path_components`]). ASCII control characters are a distinct,
/// separately documented check below (see
/// [`contains_ascii_control_character`]) rather than folded into this list,
/// since they are a whole class rather than a fixed set of symbols.
const WINDOWS_RESERVED_FILENAME_CHARS: &[char] = &['<', '>', '"', '|', '?', '*'];

/// Whether `component` contains a byte in `U+0001`..=`U+001F` — every ASCII
/// control character except NUL (`U+0000`; already excluded from a wire
/// path elsewhere, and not a printable filename character on any
/// platform). Win32's `CreateFile` family refuses every one of these in a
/// filename outright, on every Windows version, the same "permanent
/// platform split, no aliasing" hazard as
/// [`is_windows_reserved_device_name`]: a path containing one materializes
/// on Linux/macOS (where control characters are legal, if unusual, filename
/// bytes) but can never be created on any Windows device.
fn contains_ascii_control_character(component: &str) -> bool {
    component.bytes().any(|b| (0x01..=0x1f).contains(&b))
}

/// Whether `component`'s stem (the part before its first `.`) has the
/// *shape* Windows generates for an 8.3 short-name alias of a long
/// filename: `NAME~N`, where `NAME~N` together is at most 8 characters,
/// `N` is one or more ASCII digits, and everything before the last `~` is
/// non-empty. The optional extension (the part after the first `.`, if
/// any) must itself be a single component of at most 3 ASCII characters
/// with no further `.` — 8.3 names have exactly one dot.
///
/// This is a **shape** match, not a computation of the actual alias: see
/// [`wire_component_is_non_portable`]'s doc comment for why the real
/// algorithm cannot be evaluated host-independently, and why refusing the
/// shape is the predicate this module can actually stand behind. It is
/// deliberately over-inclusive within that shape (it does not further
/// restrict which characters may appear before the `~`, and accepts any
/// digit run after it, even lengths Windows would never actually generate)
/// — the false-positive cost of that breadth is exactly what this
/// function's caller's doc comment weighs and accepts.
fn has_short_name_alias_shape(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    if stem.is_empty() || stem.len() > 8 || !stem.is_ascii() {
        return false;
    }
    let Some(tilde_pos) = stem.rfind('~') else { return false };
    if tilde_pos == 0 {
        return false;
    }
    let digits = &stem[tilde_pos + 1..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let rest = &component[stem.len()..];
    if rest.is_empty() {
        return true;
    }
    let Some(ext) = rest.strip_prefix('.') else { return false };
    !ext.is_empty() && ext.len() <= 3 && ext.is_ascii() && !ext.contains('.')
}

/// Whether a single wire-path component cannot be faithfully, unambiguously
/// stored on every platform this group may sync to. Several independent
/// Windows-specific hazards, all folded into one predicate because they
/// share the same fix (refuse identically, regardless of which platform
/// runs the check), even though they split into two different harm
/// classes:
///
/// **Aliasing** — two distinct peer-authored paths land on ONE Windows
/// on-disk object, so admitting both as independent index rows lets
/// whichever materializes second silently overwrite the other with no
/// conflict ever detected (see [`path_has_non_portable_wire_component`]'s
/// doc comment for the full mechanism):
/// - A literal `:` anywhere in the component. Windows parses `:` as the
///   alternate-data-stream separator (`filename:stream`), addressing a
///   stream *on* `filename` — not a distinct file. Two independent-looking
///   peer-authored paths `"notes"` and `"notes:draft"` are both ordinary,
///   independent files on Linux/macOS (where `:` is just a character), but
///   a Windows materializer resolves the second one onto the first one's
///   own data stream. (A drive-qualified first segment such as `"C:"` or
///   `"C:foo"` is already rejected earlier, by `change::validate_path`;
///   this check is broader — it also catches a `:` anywhere inside a
///   component, not only that one position-specific shape.)
/// - Trailing `.`/` ` stripping (see
///   [`strip_windows_trailing_normalization`]): a component that is not
///   byte-identical to its own stripped form is not portable — a Windows
///   materializer stores it under a *different* name than the one on the
///   wire, which is how e.g. `"a"` and `"a "` collide.
/// - [`has_short_name_alias_shape`]: on an NTFS volume with 8.3 short-name
///   generation enabled (still the default on the Windows system volume),
///   materializing a long filename also creates an automatically generated
///   short alias for it, and a *separate* peer-authored path equal to that
///   alias then resolves to the same on-disk object as the long name — two
///   independent-looking index rows collide into one file the moment the
///   long name materializes on Windows, exactly the same harm as the
///   trailing-dot/space case, just triggered by a second, unrelated path
///   rather than a suffix on the same one. Unlike every other check here,
///   the actual generated alias is not something this predicate can
///   compute: the algorithm depends on the numeric-tail collision count
///   already present in the target directory (state a peer proposing a
///   change cannot observe) and on whether 8.3 generation is even enabled
///   on the eventual target volume (a per-volume, changeable setting, not
///   a property of the path). Neither is available, or stable, at
///   admission time, and a check that could disagree with itself across
///   peers or across time would violate this module's basic contract that
///   every peer reach the identical verdict for the identical wire path.
///   So instead of computing the alias, this refuses any component with
///   the *shape* an alias always has (`NAME~N` or `NAME~N.EXT`, at most 8
///   characters before the extension): no long name can ever coincide with
///   an authored path in that shape, so no alias of it can either. The
///   cost is real and accepted deliberately: a POSIX file genuinely named
///   e.g. `REPORT~1.TXT` is not exotic, and this makes it permanently
///   unsyncable for the whole group, forever, even for a group with no
///   Windows member and no 8.3 generation anywhere in it. That is the same
///   trade this module already makes for a reserved device name or a
///   trailing dot — refuse a look-alike rather than risk the silent
///   collision — applied to a shape that is admittedly far more likely to
///   occur in real, intentional filenames than `CON` or a trailing space
///   is.
///
/// **Permanent platform split, no aliasing** — Windows does not
/// silently rename these, it refuses to create them at all,
/// deterministically, every time. There is no on-disk collision to cause,
/// but admitting the path still splits the group along platform lines
/// exactly as [`wire_path_components`]'s own doc comment reasons about for
/// a drive-qualified path: a change every non-Windows member accepts and
/// materializes forever is one every Windows member can never materialize,
/// forever — and (separately) the index row it leaves behind on that
/// Windows device can never match a disk entry, the identical
/// index/disk-divergence shape as the aliasing cases, just triggered by an
/// outright creation failure instead of a silent rename:
/// - [`is_windows_reserved_device_name`]: the component names a reserved
///   Windows device, including the Unicode superscript-digit spellings of
///   `COM1`-`COM3`/`LPT1`-`LPT3` (see
///   [`WINDOWS_RESERVED_DEVICE_NAME_SUPERSCRIPTS`]) as well as the ASCII
///   ones.
/// - [`WINDOWS_RESERVED_FILENAME_CHARS`]: the component contains a
///   character Win32 refuses in a filename outright.
/// - [`contains_ascii_control_character`]: the component contains an ASCII
///   control character (`U+0001`-`U+001F`), which Win32 also refuses
///   outright in a filename.
///
/// General portability predicate, not specific to the reserved-artefact
/// namespace the rest of this module owns: it applies to *any*
/// peer-authored path, not only look-alikes of a reserved name. The
/// artefact predicate ([`is_artefact_wire_component`]) only asks "does
/// this look like one of our own reserved names"; this one asks "can this
/// path be faithfully, unambiguously stored on every member's platform at
/// all."
///
/// Deliberately does NOT reject: a case-only collision (`"Notes.txt"` vs
/// `"notes.txt"`, which collide on Windows/macOS's default case-insensitive
/// filesystems but not on Linux) — a real, but different-shaped hazard
/// this codebase already has dedicated machinery for (see `hazard.rs`'s
/// and `peer_session.rs`'s case-fold-sibling handling), not a "refuse the
/// path outright" fix. Nor a path-length limit (historic Windows `MAX_PATH`
/// is opt-in-extendable per-device today, so unlike every check above it
/// does not fail identically on every Windows install — rejecting for it
/// here would sacrifice a file for a group whose Windows members may all
/// have long-path support enabled). Nor a leading or interior space/dot,
/// or any other whitespace: Win32 only strips a *trailing* one; everything
/// else round-trips exactly and is left alone.
fn wire_component_is_non_portable(component: &str) -> bool {
    if component.contains(':')
        || component.chars().any(|c| WINDOWS_RESERVED_FILENAME_CHARS.contains(&c))
        || contains_ascii_control_character(component)
    {
        return true;
    }
    if is_windows_reserved_device_name(component) {
        return true;
    }
    if has_short_name_alias_shape(component) {
        return true;
    }
    strip_windows_trailing_normalization(component) != component
}

/// Whether any component of a peer-authored path **string** cannot be
/// faithfully, unambiguously stored on every platform this group may sync
/// to — see [`wire_component_is_non_portable`] for the hazards (two harm
/// classes) this folds together. Splits on both `/` and `\` (see
/// [`wire_path_components`])
/// for the same host-independence reason as
/// [`path_has_artefact_component_in_wire_path`]: whether a path is
/// portable cannot depend on which platform happens to be running the
/// check, so every peer in a group — native admission
/// (`dag_store::admit_change`) and, as defense-in-depth, peer
/// materialization (`PeerSyncSession::materialize`) — must reach the
/// identical verdict for the identical wire path.
///
/// Without the trailing-dot/space and colon checks specifically, two
/// distinct logical paths that alias to one Windows filesystem name (e.g.
/// `"a"` / `"a "`, or `"notes"` / `"notes:draft"`) are both admitted as
/// independent index rows, and silently collide onto the same on-disk
/// object the moment either one materializes on a Windows device —
/// whichever writes second overwrites the other's bytes with no conflict
/// ever detected (they are different paths, so no conflict machinery
/// ever compares them), while the index keeps believing both are
/// correctly, independently `Present`. Refusing the path at admission is
/// what prevents that divergence from ever being created in the first
/// place.
pub fn path_has_non_portable_wire_component(path: &str) -> bool {
    wire_path_components(path).any(wire_component_is_non_portable)
}

/// Why a wire path can never enter a group's change history.
///
/// Kept as a type rather than a bool so a caller that has to explain
/// itself to a user -- local capture's skip warning -- can say which rule
/// it hit without re-deriving it from the predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirePathRefusal {
    /// The path names something this crate's own namespace owns -- an
    /// artefact component, or the sync-root lock file.
    ReservedNamespace,
    /// The path carries a component that cannot survive every platform the
    /// group may sync to (a Windows reserved device name, a trailing dot or
    /// space, a colon, ...).
    NonPortable,
}

/// Whether `path` is one native admission will refuse **permanently**, and
/// why -- the single predicate every site that must agree with admission
/// reads, so none of them can drift narrower than it.
///
/// Two sites must agree, and they sit on opposite sides of the wire:
///
/// - `yadorilink_sync_sqlite::dag_store::serving_authorization_index::
///   validate_no_reserved_paths`, which refuses such a path on BOTH
///   `admit_change` (a peer's incoming change) and the local-authoring
///   emission path.
/// - `yadorilink_local_capture`'s own pre-emission filter, which must
///   never hand that emission a path it is going to refuse.
///
/// The second site is not redundant belt-and-braces. Local capture commits
/// a whole debounce batch (or scan chunk) as ONE signed change, so a single
/// refused path fails the entire batch -- every other path in it included
/// -- and the dirty-journal backstop then re-drives the same batch, with
/// the same refused path still in it, on every sweep forever. Observed
/// directly on this tree before the filter existed, in
/// `windows_path_hazard_conflict`:
///
/// ```text
/// WARN failed to commit a batched group of local mutations; left journaled
///      dirty for re-drive error=path "CON.txt" has a component that is not
///      portable ... batch_len=2
/// ```
///
/// repeating every 5s indefinitely. `batch_len=2` is the whole bug: the
/// other entry was an ordinary file that simply shared a debounce window.
/// One filename a POSIX user is perfectly entitled to create (`CON.txt`,
/// `"notes.txt "`, `report<final>.txt`) stops that folder syncing anything
/// at all, permanently and silently, on every platform.
///
/// Refusal is a property of the path alone: it never becomes admissible
/// later, which is what makes skipping (rather than retrying) correct.
pub fn wire_path_admission_refusal(path: &str) -> Option<WirePathRefusal> {
    if path_has_artefact_component_in_wire_path(path) || wire_path_names_sync_root_lock(path) {
        return Some(WirePathRefusal::ReservedNamespace);
    }
    if path_has_non_portable_wire_component(path) {
        return Some(WirePathRefusal::NonPortable);
    }
    None
}

#[cfg(test)]
mod tests;

/// True for exactly `<root>/.yadorilink-root.lock` and nothing else —
/// the same top-level-only rule as the root marker's, so the same-named
/// file nested in a subdirectory (ordinary user content) keeps syncing
/// normally.
pub fn is_sync_root_lock_relative_path(relative_path: impl AsRef<Path>) -> bool {
    let mut segments =
        relative_path.as_ref().components().filter(|c| !matches!(c, std::path::Component::CurDir));
    match (segments.next(), segments.next()) {
        (Some(std::path::Component::Normal(only)), None) => {
            only == std::ffi::OsStr::new(SYNC_ROOT_LOCK_FILE_NAME)
        }
        _ => false,
    }
}

/// The **wire-path** counterpart to [`is_sync_root_lock_relative_path`], for
/// a path **string** that arrived off the wire (a peer-authored path this
/// process never walked off its own directory tree) — a change's `Put`/
/// `Delete`/`Move` path, or a peer-supplied `FileRecord::path` about to be
/// materialized.
///
/// Top-level-only and exact, matching [`is_sync_root_lock_relative_path`]'s
/// semantics exactly — this is deliberately NOT the same shape as
/// [`path_has_artefact_component_in_wire_path`],
/// which matches the reserved name at *any* depth because a versioned
/// artefact name is reserved wherever it appears, including as an
/// intermediate directory. The sync-root lock is different: like the
/// identity marker, a same-named file *nested* in a subdirectory is
/// ordinary user content that must keep syncing (see
/// [`is_sync_root_lock_relative_path`]'s doc comment) — only a peer path
/// that is *exactly* the lock file at the root is a genuine collision, so
/// only a single-component path is checked here.
///
/// Must be used instead of the host-`Path` form at every site that rejects a
/// remote-authored path, for the identical reason
/// [`path_has_artefact_component_in_wire_path`]
/// documents: resolving a peer's raw path string through this process's own
/// `std::path::Path` finds component boundaries only where THIS platform's
/// separator convention says to, so a peer path shaped like
/// `"safe\\.yadorilink-root.lock"` would be one component (not a match) on
/// Unix and two (a match on the second, still correctly excluded here since
/// it is no longer the *only* component) on Windows — an admission decision
/// must not depend on which platform is running the check. Reuses
/// `reserved_namespace`'s own portable component splitter and
/// alternate-data-stream stripper so this agrees with the versioned-artefact
/// wire check on what counts as "the same component" in every case, rather
/// than defining that afresh here and risking the two silently diverging on
/// the exact NTFS-ADS/backslash edge cases that check's tests already pin
/// down. ASCII case-folded: this name is fixed ASCII, and the target
/// folder's filesystem may itself be case-insensitive (NTFS default, APFS
/// default), so a peer path differing only in case still names the same
/// on-disk file this device's lock lives at.
pub fn wire_path_names_sync_root_lock(path: &str) -> bool {
    let mut components = wire_path_components(path);
    match (components.next(), components.next()) {
        (Some(only), None) => {
            strip_alternate_data_stream_suffix(only).eq_ignore_ascii_case(SYNC_ROOT_LOCK_FILE_NAME)
        }
        _ => false,
    }
}
