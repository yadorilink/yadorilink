//! Sync-root identity: proving that the directory a scan is about to treat
//! as authoritative really is the folder this link was established
//! against. The failure this exists to prevent: a sync root that lives on
//! a removable or network volume, unmounted. On every mainstream platform
//! the mountpoint is an ordinary directory that *survives* the unmount, so
//! every existence check (`Path::exists`, `fs::metadata`, even
//! `canonicalize`) still succeeds and the scanner walks a bare, empty
//! directory. A full scan is authoritative by design, so every indexed
//! file then looks deleted and those deletions propagate as tombstones to
//! every other device. Unplugging a drive silently destroys the folder
//! everywhere. An existence check cannot see this, because the thing that
//! vanished is the *filesystem*, not the path. The guard is a marker file
//! ([`ROOT_MARKER_FILE_NAME`]) written inside the root, naming the group
//! and an opaque per-link `root_token` that is also persisted in the local
//! `links` table. The marker rides on the same filesystem as the content,
//! so it disappears exactly when the content does: a bare mountpoint has
//! no marker, the token cannot be corroborated, and the check fails
//! closed. THE MARKER IS THE AUTHORITY — deliberately, in preference to a
//! filesystem identity such as `st_dev`. A device number is neither
//! portable across platforms nor stable across remounts: a USB volume
//! routinely gets a different `st_dev` on each plug, so an `st_dev` check
//! would reject the very folder it is meant to protect, on the ordinary
//! happy path. It is recorded in the marker as a human diagnostic for bug
//! reports and is never compared — see [`RootMarker::st_dev_hint`].
//! `root_token` is an opaque identity nonce, never a digest of the
//! folder's contents or paths. It answers "is this the same folder I
//! adopted?", a question whose answer must stay `true` across every
//! legitimate edit to that folder — so binding it to content would make it
//! self-invalidating. It is orthogonal to exact-version binding (a
//! change's content hash), which is the construct for "are these the same
//! bytes". # The `RootVerificationStatePort` split Every
//! constructor below needs two things from the durable index that this
//! crate itself cannot see: "does this group currently have more than one
//! live link" and "what root token, if any, did this device already
//! persist for this link" (plus, on the unmarked-adoption path, "does
//! every live indexed row still corroborate on disk").
//! [`RootVerificationStatePort`] is the narrow, semantic port that answers
//! exactly those questions — deliberately not a generic CRUD surface, and
//! deliberately not folded into [`VerifiedRoot`] itself: `VerifiedRoot`
//! stays a plain, private-field proof value with no borrowed state and no
//! trait-object indirection, per this phase's own non-negotiable
//! constraint (see its own doc below).

use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use yadorilink_replica_domain::file::FileRecord;

use crate::error::RootAuthorityError;

/// The marker file's name, at the top level of a sync root. Excluded from sync
/// so it is never indexed, never transmitted, and can never spawn a
/// conflicted copy: each device mints its own token, so a synced marker would
/// overwrite a peer's identity with ours — the exact confusion this module
/// exists to detect. Owned by `yadorilink_replica_domain::reserved_paths`.
use yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME;

/// Written into every marker so a user who finds this file in their folder can
/// tell what it is and why deleting it is not harmless.
const MARKER_COMMENT: &str = concat!(
    "YadoriLink sync-root marker. Identifies this folder to YadoriLink so that an unmounted ",
    "or replaced volume is not mistaken for a folder whose files you deleted. ",
    "Do not edit, move, or delete it.",
);

/// True for exactly `<root>/.yadorilink-root` and nothing else. A
/// `.yadorilink-root` nested in a subdirectory is ordinary user content and
/// syncs normally — only the root-level marker is this module's, mirroring
/// `ignore_patterns::is_ignore_file_relative_path`'s identical top-level-only
/// rule for `.yadorilinkignore`.
///
/// Allocation-free: this runs once per directory entry on the scan's walk, so
/// it is a hot path and must not build a `Vec` to answer a question about at
/// most one path segment.
pub fn is_root_marker_relative_path(relative_path: impl AsRef<Path>) -> bool {
    let mut segments =
        relative_path.as_ref().components().filter(|c| !matches!(c, Component::CurDir));
    match (segments.next(), segments.next()) {
        // Exactly one segment, and it is the marker. Anything with a second
        // segment is nested; anything non-`Normal` (`..`, a root, a Windows
        // prefix) is not a plain top-level name and so is not the marker.
        (Some(Component::Normal(only)), None) => {
            only == std::ffi::OsStr::new(ROOT_MARKER_FILE_NAME)
        }
        _ => false,
    }
}

/// The on-disk marker. Plain JSON, and deliberately human-legible: a user who
/// opens it should be able to see what it is without tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RootMarker {
    /// Explanatory text for a human reader only. `default`ed on read so an
    /// older or hand-trimmed marker still parses — it carries no identity and
    /// is never compared.
    #[serde(default, rename = "_comment")]
    comment: String,
    group_id: String,
    root_token: String,
    /// The `st_dev` of the root when the marker was written, on Unix. A
    /// **diagnostic hint only** — never read back for the identity check, and
    /// deliberately so: see this module's doc comment on why a device number
    /// changes across ordinary remounts. It exists to make "which volume was
    /// this folder on when it was adopted?" answerable from a bug report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    st_dev_hint: Option<u64>,
}

/// The narrow, semantic capability surface [`VerifiedRoot`]'s constructors
/// need from the durable index — never a generic CRUD surface. See this
/// module's own doc for why this exists and where its production
/// implementation lives.
pub trait RootVerificationStatePort: Send + Sync {
    /// Serializes the read-marker-then-adopt-if-unmarked decision in
    /// [`VerifiedRoot::open`]/[`VerifiedRoot::readopt`] against a concurrent
    /// adoption of the same root. Held only across a synchronous section
    /// (never across an await), so a plain `Mutex` is the right primitive —
    /// see `VerifiedRoot::open`'s own doc comment for the race this closes.
    fn root_adoption_lock(&self) -> &Mutex<()>;

    /// The root token this device has already persisted for `group_id`'s
    /// link, if any.
    fn link_root_token_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, RootAuthorityError>;

    /// Persists `root_token` as the token this device has adopted for
    /// `group_id`'s link.
    fn set_link_root_token_for_group(
        &self,
        group_id: &str,
        root_token: &str,
    ) -> Result<(), RootAuthorityError>;

    /// Whether `root` is on the volume recorded for `group_id`'s link (true
    /// while none is recorded yet, unless the volume can never be confirmed).
    /// A folder off its recorded volume is an unmounted or replaced disk, or a
    /// disk without a stable identity since it was mounted again: nothing may
    /// be written into it, and what is missing from it is not a deletion.
    fn root_on_recorded_volume(
        &self,
        root: &Path,
        group_id: &str,
    ) -> Result<bool, RootAuthorityError>;

    /// Refuses (with a fail-closed error) a group that currently has more
    /// than one live link — see [`ensure_single_root`]'s own doc for why
    /// every constructor gates on this before touching disk or the index.
    fn ensure_unambiguous_group(&self, group_id: &str) -> Result<(), RootAuthorityError>;

    /// Every currently live (non-tombstoned) indexed file row for
    /// `group_id` — the corroboration baseline for automatic adoption of an
    /// unmarked root.
    fn live_files(&self, group_id: &str) -> Result<Vec<FileRecord>, RootAuthorityError>;

    /// Whether `record` is represented on disk (under `root`) by the same
    /// kind and content the index believes it has: directory-for-directory,
    /// matching symlink target, or matching file bytes. Kept as
    /// one port method rather than several finer-grained state accessors
    /// because its file-content branch needs a real disk-byte comparison
    /// against indexed block hashes — a capability that lives in
    /// `yadorilink-local-storage`, which this crate cannot depend on without
    /// creating a cycle (`yadorilink-local-storage` already depends on this
    /// crate). The production implementation performs that comparison
    /// directly; this crate only ever consumes the yes/no answer.
    fn indexed_path_is_corroborated(
        &self,
        root: &Path,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, RootAuthorityError>;

    /// Whether `record`'s row has no local object by definition (`Remote`):
    /// its absence from disk is expected, so it needs no corroboration, and it
    /// cannot supply any either.
    fn indexed_path_expects_no_object(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, RootAuthorityError>;
}

/// A sync root whose identity has been verified against this link's persisted
/// `root_token`. Holding one is proof the check ran and passed.
///
/// The field is private on purpose: that is the anti-recurrence guard. The bug
/// this type exists to close has recurred along independent code paths (the
/// disk scan and the interrupted-materialization repair each grew their own
/// root check, and each checked only existence). Making the *type* — not a call
/// at each site — carry the guarantee means a future scan entry point cannot
/// forget it: there is no way to name a root to those functions without
/// producing one of these first.
///
/// **A plain value type, never a trait object or callback**: the state query this type's
/// constructors need is
/// factored out to [`RootVerificationStatePort`] instead, so this type itself
/// stays exactly as narrow as a canonicalized path and nothing else.
///
/// The guarantee every constructor must uphold, and which any constructor added
/// later inherits as a requirement rather than an option:
///
/// 1. `ensure_single_root` — the group has at most one live link. A group with
///    two live roots has no answerable "which folder is this?", and guessing
///    tombstones the other root's files on every device.
/// 2. The volume check — the root is on the volume recorded for the link. A
///    copy of the folder (marker included) on another disk mounted at the same
///    path is not the folder the index describes.
/// 3. The marker check — this really is that link's folder, not a bare
///    mountpoint or another device's copy.
///
/// All three, in that order, before anything is written. A constructor that skips
/// either is not a `VerifiedRoot` constructor; it is the bug wearing the type.
/// Do not add a `from_path`/`new_unchecked` escape hatch; a caller that
/// genuinely means "re-establish this folder's identity" wants
/// [`VerifiedRoot::readopt`], which still ends in the same checked constructor.
#[derive(Debug, Clone)]
pub struct VerifiedRoot {
    /// Canonical. Callers relativize walked entries against this, so it must be
    /// the same resolution the caller's own scan performs internally or every
    /// `strip_prefix` silently fails.
    path: PathBuf,
}

/// What the index says about a root that carries no marker — the input to the
/// adoption decision below.
enum AdoptionEvidence {
    /// Every indexed, live path is present on disk.
    Corroborated,
    /// The index has live rows and at least one is absent. A partially reused
    /// bare mountpoint and a genuine local deletion are indistinguishable.
    IndexedFilesAllMissing,
    /// The index has no live rows: a first link, or a group whose every file is
    /// already a tombstone. Nothing can be lost by adopting.
    IndexEmpty,
}

impl VerifiedRoot {
    /// Verify an already-adopted root without changing either disk or index.
    /// Peer-driven writes must use this path: unlike [`Self::open`], it never
    /// creates a marker and never backfills a missing token, so an unmounted or
    /// replaced folder cannot be silently adopted merely because a peer had
    /// data to write into it.
    pub fn verify(
        root: &Path,
        group_id: &str,
        state: &dyn RootVerificationStatePort,
    ) -> Result<Self, RootAuthorityError> {
        let path = root.canonicalize()?;
        crate::sync_root_lock::verify_registered_root_ownership(&path)?;
        ensure_single_root(group_id, state)?;
        ensure_on_recorded_volume(&path, group_id, state)?;
        // Same lock `open` takes: without it, a `verify` racing a concurrent
        // `open`'s in-progress adoption (marker just written, DB persist not
        // yet committed, or vice versa) could read a transiently torn pair
        // and fail spuriously. `verify` never writes, so this only ever
        // waits for an adoption in flight, never contends against another
        // `verify`.
        let _adoption_guard = state.root_adoption_lock().lock().unwrap_or_else(|p| p.into_inner());
        let persisted = state.link_root_token_for_group(group_id)?.ok_or_else(|| {
            root_identity_mismatch(&path, group_id, "the link has no previously-adopted root token")
        })?;
        let marker = read_marker(&path)?.ok_or_else(|| {
            root_identity_mismatch(&path, group_id, "the folder has no root identity marker")
        })?;
        if marker.group_id != group_id {
            return Err(root_identity_mismatch(
                &path,
                group_id,
                &format!("it carries the marker of group {}", marker.group_id),
            ));
        }
        if marker.root_token != persisted {
            // The token values are logged (not just "they differ") because a
            // future recurrence of this is exactly the shape of bug
            // `root_adoption_lock` was added to close (two concurrent
            // adoptions minting different tokens) -- seeing two genuinely
            // different, well-formed hex tokens here means that race is back,
            // versus e.g. an empty/malformed value pointing at a different
            // cause entirely.
            tracing::warn!(
                ?path,
                group_id,
                persisted_token = %persisted,
                marker_token = %marker.root_token,
                "root identity check failed: marker's root token does not match the persisted one"
            );
            return Err(root_identity_mismatch(
                &path,
                group_id,
                "its marker's root token is not the one this link adopted",
            ));
        }
        Ok(Self { path })
    }

    /// Canonicalize `root`, then prove it is this group's folder by matching the
    /// marker it carries against the `root_token` persisted for the link.
    ///
    /// Fails closed. `Err` means "this scan's view of the folder is not
    /// authoritative", never "the folder is empty" — the whole point is that
    /// those two are indistinguishable by inspection, so the ambiguous case must
    /// not resolve to the destructive one.
    ///
    /// Adoption (see this type's `open` body) is what makes the check
    /// deployable on an existing install, where no link has a marker yet.
    pub fn open(
        root: &Path,
        group_id: &str,
        state: &dyn RootVerificationStatePort,
    ) -> Result<Self, RootAuthorityError> {
        // A root that cannot be canonicalized is absent or unreadable. This
        // subsumes a bare `root.canonicalize()?` guard, which catches the
        // root-*removed* case; the marker check below is what additionally
        // catches the root-*emptied* case that guard could not see.
        let path = root.canonicalize()?;
        // Before the token lookup, and before the adoption dispatch below: both
        // of those WRITE. `adopt_unmarked_root` reuses the token already
        // persisted for the group, so on an ambiguous group it would stamp the
        // FIRST root's token into the SECOND root's marker — after which both
        // folders verify successfully, forever, and their mutual tombstoning is
        // permanent and invisible. Refusing here is what keeps that from being
        // laundered into a "valid" state.
        ensure_single_root(group_id, state)?;
        ensure_on_recorded_volume(&path, group_id, state)?;
        // Serializes the read-marker-then-adopt-if-unmarked decision below.
        // Without this, two concurrent `open()` calls for the same root that
        // both observe no marker and no persisted token (e.g. this device's
        // own startup scan racing an early peer reconcile, both opening the
        // link for the first time) each mint their own fresh token and each
        // write it to disk and to the DB independently — `write_marker` and
        // `set_link_root_token_for_group` are two separate, non-atomic
        // writes, so with two concurrent writers the *final* marker-on-disk
        // and the *final* persisted-in-DB token can come from different
        // callers and disagree forever afterward (root adoption has no
        // automatic recovery from that state — `readopt` is explicit-user-
        // action only). Held only across this synchronous section (a DB
        // read, a marker read, and — on the unmarked path — a marker write
        // and a DB write), never across an await, so a `std::sync::Mutex` is
        // safe here.
        let _adoption_guard = state.root_adoption_lock().lock().unwrap_or_else(|p| p.into_inner());
        let persisted = state.link_root_token_for_group(group_id)?;

        let Some(marker) = read_marker(&path)? else {
            return Self::adopt_unmarked_root(path, group_id, state, persisted);
        };

        // A marker for a different group means this path is some *other* link's
        // root — a mount landed in the wrong place, or two links were swapped.
        // Refuse regardless of what the index says.
        if marker.group_id != group_id {
            return Err(root_identity_mismatch(
                &path,
                group_id,
                &format!("it carries the marker of group {}", marker.group_id),
            ));
        }
        match persisted {
            Some(token) if token != marker.root_token => {
                // See `verify`'s identical log line: the actual token values
                // matter for telling a `root_adoption_lock` regression (two
                // different well-formed tokens) apart from any other cause.
                tracing::warn!(
                    ?path,
                    group_id,
                    persisted_token = %token,
                    marker_token = %marker.root_token,
                    "root identity check failed: marker's root token does not match the persisted one"
                );
                Err(root_identity_mismatch(
                    &path,
                    group_id,
                    "its marker's root token is not the one this link adopted, so this is a \
                     different folder for the same group (a restored backup, a re-created folder, \
                     or another device's copy)",
                ))
            }
            Some(_) => Ok(Self { path }),
            // A marker with nothing persisted to check it against: the token
            // column was added after this link was created, or a previous
            // adoption wrote the marker and was killed before committing the
            // row. Trust the marker (it is the authority) and backfill, so the
            // next open verifies the pair fully.
            None => {
                state.set_link_root_token_for_group(group_id, &marker.root_token)?;
                Ok(Self { path })
            }
        }
    }

    /// Re-establish this folder's identity: mint a fresh token, write the
    /// marker, and verify. This is the deliberate, explicit way past a refusal —
    /// including the legitimate "I really did delete every file in this folder"
    /// case, which is otherwise indistinguishable from an unmounted volume and
    /// so is refused by [`VerifiedRoot::open`].
    ///
    /// Not an escape hatch from the check: it *changes the persisted state* so
    /// the check passes, then runs the check. It must only ever be reached from
    /// an explicit user action, never from a scan, a repair, or a retry — an
    /// automatic caller would re-adopt the bare mountpoint and reintroduce the
    /// whole-folder loss this module prevents.
    pub fn readopt(
        root: &Path,
        group_id: &str,
        state: &dyn RootVerificationStatePort,
    ) -> Result<Self, RootAuthorityError> {
        // At the very top: everything below this line mutates. Minting, writing
        // the marker and persisting the token all happen BEFORE the `Self::open`
        // that would otherwise catch an ambiguous group, so relying on `open`'s
        // check alone would fan a fresh token onto BOTH of the group's rows and
        // only then refuse — deepening the exact state it means to reject.
        ensure_single_root(group_id, state)?;
        let path = root.canonicalize()?;
        let token = mint_root_token();
        write_marker(&path, group_id, &token)?;
        state.set_link_root_token_for_group(group_id, &token)?;
        Self::open(root, group_id, state)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The upgrade/backfill path: a root with no marker. Every link on an
    /// existing install starts here exactly once, so a naive fail-closed rule
    /// would break every install on upgrade — but blanket-adopting would equally
    /// happily adopt a bare mountpoint and re-arm the bug. The index is the
    /// tiebreaker: adopt only when the folder on disk corroborates what we
    /// already believe is in it.
    ///
    /// Two cheaper-looking discriminators are deliberately NOT used here, and
    /// both are traps a future reader will otherwise re-derive and get wrong:
    ///
    /// - **`st_dev` / "is this still a mountpoint?"** cannot be the check. A
    ///   device number is not stable across remounts (a USB volume gets a fresh
    ///   one on each plug), so comparing it rejects the healthy folder. Nor can
    ///   the weaker "the root is not a mountpoint, so it is ordinary local
    ///   storage, so adopt" work — after a disconnect the bare mountpoint is
    ///   exactly a plain directory on the parent filesystem and is no longer a
    ///   mountpoint. That rule fires *precisely* in the disconnect case it is
    ///   meant to exclude.
    ///
    /// - **An open materialization intent** cannot vouch for the root either.
    ///   Intents live in SQLite on the system disk, not on the sync volume, so
    ///   they survive an unmount exactly as they survive a crash and carry zero
    ///   signal about whether the volume is present. Worse, letting one
    ///   intent-bearing path vouch for the root would then bless the bare
    ///   mountpoint for every OTHER indexed file — all of them absent because
    ///   unmounted, and intent-free — and the scan that follows would tombstone
    ///   the lot. That trades a recoverable stall for the whole-folder loss this
    ///   module exists to prevent.
    ///
    /// What is left is the on-disk evidence. Every live indexed row must still
    /// be present before an unmarked root can be adopted automatically. A
    /// single survivor is not sufficient corroboration: it can be an unrelated
    /// file in a reused mountpoint while the actual volume is absent.
    fn adopt_unmarked_root(
        path: PathBuf,
        group_id: &str,
        state: &dyn RootVerificationStatePort,
        persisted: Option<String>,
    ) -> Result<Self, RootAuthorityError> {
        match adoption_evidence(&path, group_id, state)? {
            AdoptionEvidence::Corroborated => {}
            // A first adoption: nothing indexed, nothing to lose.
            AdoptionEvidence::IndexEmpty if persisted.is_none() => {}
            // This link already adopted a folder, and that folder's marker is
            // gone while nothing indexed is on disk to vouch for this one. That
            // is what the empty mountpoint of an unmounted volume looks like;
            // marking it would let every later write land on the volume
            // underneath, and the files written there would read as deleted
            // once the real volume is back.
            AdoptionEvidence::IndexEmpty => {
                return Err(root_identity_mismatch(
                    &path,
                    group_id,
                    "the folder this link adopted had a sync-root marker and this one has none, \
                     with nothing indexed on disk to show it is the same folder. Its storage may \
                     not be mounted. Connect it and retry, or relink the folder",
                ));
            }
            AdoptionEvidence::IndexedFilesAllMissing => {
                return Err(root_identity_mismatch(
                    &path,
                    group_id,
                    "it has no sync-root marker, and not every one of this folder's known files is \
                     present in it. Two different situations look identical from here: the \
                     folder's storage may not be mounted (an unmounted volume leaves its \
                     mountpoint behind as an empty directory), or the files may never have been \
                     written to this device. Syncing either one would delete this folder's \
                     contents on every device, so it is left untouched until the situation is \
                     confirmed. If the storage should be connected, connect it and retry. If \
                     this folder really is meant to be empty, re-adopt it explicitly to confirm \
                     that, which will then propagate the deletions",
                ));
            }
        }
        // Reuse the persisted token when there is one: the marker was lost from
        // an otherwise-healthy folder (e.g. a user cleaned it out), so
        // re-minting would gratuitously invalidate a token other state may
        // already reference.
        let had_persisted = persisted.is_some();
        let token = persisted.unwrap_or_else(mint_root_token);
        tracing::debug!(
            ?path,
            group_id,
            token = %token,
            had_persisted,
            "adopting an unmarked root: writing a fresh identity marker"
        );
        write_marker(&path, group_id, &token)?;
        state.set_link_root_token_for_group(group_id, &token)?;
        Ok(Self { path })
    }
}

/// Refuses a group that has more than one live link, before any constructor
/// touches disk or the index.
///
/// Shared free function called EXPLICITLY from every `VerifiedRoot`
/// constructor, rather than left to happen transitively via whichever token
/// lookup each one performs. Coverage that rides on a constructor incidentally
/// calling a hardened reader is coverage by coincidence: it silently lapses the
/// moment a constructor is reordered or a new one is added. A named call at the
/// top of each constructor is what a future constructor's author has to
/// deliberately delete.
///
/// This is the gate that stops the dominant harm. A disk-reconcile scan that
/// takes a `&VerifiedRoot` cannot even start its tombstone-emitting loop
/// without one, and this type's field is private — so no `VerifiedRoot` means
/// no tombstones, by type rather than by discipline.
fn ensure_single_root(
    group_id: &str,
    state: &dyn RootVerificationStatePort,
) -> Result<(), RootAuthorityError> {
    state.ensure_unambiguous_group(group_id)
}

/// Refuses a root that is not on the volume recorded for its link. Every
/// constructor runs it, so every write a `VerifiedRoot` admits (and every
/// re-verification right before a physical write) stops while the folder's
/// disk is unmounted or replaced, including the window in which a long
/// operation started before the outage.
fn ensure_on_recorded_volume(
    root: &Path,
    group_id: &str,
    state: &dyn RootVerificationStatePort,
) -> Result<(), RootAuthorityError> {
    if state.root_on_recorded_volume(root, group_id)? {
        return Ok(());
    }
    Err(root_identity_mismatch(
        root,
        group_id,
        "it is not on the volume this folder was recorded on: the folder's disk may be \
         unmounted (leaving its mountpoint behind as a directory on another volume) or \
         replaced, or it is a disk without a stable identity that was mounted again. Nothing \
         is written into it until that volume is back or the user re-adopts the disk",
    ))
}

/// Single pass over the index. Automatic adoption is intentionally strict:
/// every live indexed path must be present on disk.
fn adoption_evidence(
    root: &Path,
    group_id: &str,
    state: &dyn RootVerificationStatePort,
) -> Result<AdoptionEvidence, RootAuthorityError> {
    let mut has_live_rows = false;
    let mut has_disk_backed_row = false;
    for record in state.live_files(group_id)? {
        has_live_rows = true;
        // A row with no object to find does not count against the root, but
        // it is no evidence for it either unless an object that matches it
        // happens to stand on disk.
        if state.indexed_path_is_corroborated(root, group_id, &record)? {
            has_disk_backed_row = true;
        } else if !state.indexed_path_expects_no_object(group_id, &record)? {
            return Ok(AdoptionEvidence::IndexedFilesAllMissing);
        }
    }
    Ok(match (has_live_rows, has_disk_backed_row) {
        (false, _) => AdoptionEvidence::IndexEmpty,
        // Only rows without objects: nothing on disk says this directory is
        // the link's folder, so it is not adopted automatically.
        (true, false) => AdoptionEvidence::IndexedFilesAllMissing,
        (true, true) => AdoptionEvidence::Corroborated,
    })
}

/// An opaque 256-bit nonce. Not derived from the path, the group, the device,
/// or the folder's contents: two folders that agree on all of those must still
/// get different tokens, since telling such folders apart (a restored backup, a
/// duplicated copy) is exactly what the token is for.
fn mint_root_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    hex::encode(bytes)
}

/// `Ok(None)` only for a marker that is genuinely absent. Every other outcome —
/// unreadable, truncated, malformed JSON — is an `Err`: a marker we cannot read
/// is not a marker we can say matches, and this check exists precisely to not
/// resolve ambiguity in the destructive direction.
fn read_marker(root: &Path) -> Result<Option<RootMarker>, RootAuthorityError> {
    match std::fs::read(root.join(ROOT_MARKER_FILE_NAME)) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .map_err(|e| RootAuthorityError::corrupt_state(format!("root marker: {e}")))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// A plain (non-atomic) write: the marker is a single small buffer, and the
/// failure mode of a torn write is a malformed marker, which `read_marker`
/// fails closed on. Deliberately not written via a temp file + rename — the
/// link root is swept for stale temp files on startup by the materialization
/// engine, and a marker in flight is exactly the kind of thing that sweep
/// would race.
fn write_marker(root: &Path, group_id: &str, root_token: &str) -> Result<(), RootAuthorityError> {
    let marker = RootMarker {
        comment: MARKER_COMMENT.to_string(),
        group_id: group_id.to_string(),
        root_token: root_token.to_string(),
        st_dev_hint: st_dev_hint(root),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|e| RootAuthorityError::corrupt_state(format!("root marker: {e}")))?;
    std::fs::write(root.join(ROOT_MARKER_FILE_NAME), bytes)?;
    Ok(())
}

/// Writes a marker through the REAL writer, for tests that need a root already
/// carrying a given identity (notably the already-duplicated "two rows, one
/// token" state, which is what the pre-fix by-`group_id` token writer produced
/// and where the read-side gate is the only remaining protection).
///
/// Deliberately routed through `write_marker` rather than letting each test
/// hand-roll the JSON: a test that writes its own marker format silently stops
/// exercising the real one the moment the struct changes, and this marker's
/// whole job is to be read back by `read_marker`.
#[cfg(any(test, feature = "test-support"))]
pub fn write_root_marker_for_test(root: &Path, group_id: &str, root_token: &str) {
    write_marker(root, group_id, root_token).expect("test setup: writing a root marker");
}

/// Reads back `(group_id, root_token)` from a root's on-disk marker, for
/// tests that need to inspect what a real adoption/readopt wrote (an
/// external integration test cannot reach the private `RootMarker`/
/// `read_marker` directly). `None` for a genuinely absent marker; panics on
/// any other read/parse failure, since a test asking this question wants a
/// marker that is there.
#[cfg(any(test, feature = "test-support"))]
pub fn read_root_marker_for_test(root: &Path) -> Option<(String, String)> {
    read_marker(root)
        .expect("test assertion: reading a root marker")
        .map(|m| (m.group_id, m.root_token))
}

/// Diagnostic only — see [`RootMarker::st_dev_hint`]. Never fails the write: a
/// hint we could not collect is simply absent.
fn st_dev_hint(root: &Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(root).ok().map(|m| m.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = root;
        None
    }
}

/// `RootIdentityMismatch` rather than a generic I/O variant: the root path
/// handed to the operation is the thing that is wrong, and it is rejected
/// before any state is written. It is deliberately NOT surfaced as a plain
/// I/O error: that would read as "transient, retry", and a caller that
/// retries this condition retries it against the same wrong folder forever.
fn root_identity_mismatch(root: &Path, group_id: &str, why: &str) -> RootAuthorityError {
    RootAuthorityError::RootIdentityMismatch(format!(
        "refusing to treat {root:?} as the sync root for group {group_id}: {why}. No file was \
         indexed and no deletion was emitted"
    ))
}

#[cfg(test)]
mod tests;
