//! Filename hazard detection: pure detection logic for the three
//! name-based hazards a materialization/
//! hydration write must never proceed past —
//!
//! - a **case-fold collision** with an existing sibling on a
//!   case-insensitive filesystem: two paths that differ only by
//!   case (`Photo.jpg` vs. `photo.jpg`) can coexist in the index (two
//!   peers, or a case-sensitive filesystem, can legally hold both), but
//!   writing both to the same case-insensitive directory clobbers one with
//!   the other.
//! - a **Unicode normalization collision** with an existing sibling on a
//!   filesystem whose name resolution is normalization-insensitive: two
//!   paths that are two different Unicode encodings of the same logical
//!   string (`"\u{e9}.txt"`, composed, vs. `"e\u{301}.txt"`, `e` plus a
//!   combining acute accent, decomposed) are two distinct byte sequences —
//!   and so, like a case-fold collision, can legally coexist in the index —
//!   but a filesystem that resolves both spellings to one on-disk object
//!   clobbers one with the other the same way a case-insensitive one does
//!   for a case-only difference. See [`normalization_collision`]'s doc
//!   comment for which normalization form this compares under and why, and
//!   [`is_normalization_insensitive_filesystem`]'s for how "does this
//!   volume actually alias them" is answered rather than assumed.
//! - a **platform-invalid name**: the documented Windows-
//!   reserved device basenames, a trailing `.`/` `, or any of `<>:"|?*`.
//!
//! Kept in its own module rather than folded into `peer_session.rs` because
//! almost all of it — `invalid_name_reason`, `case_fold_collision`,
//! `normalization_collision` — is pure string/path logic with no
//! `SyncState`/filesystem dependency at all, directly unit-testable on its
//! own. `is_case_insensitive_filesystem` and `is_normalization_insensitive_
//! filesystem` are the two real filesystem probes in this module; see their
//! doc comments.
//!
//! `peer_session::PeerSyncSession::hazard_reason_for` is the only caller:
//! it composes all three checks and turns a hazard into the free-form
//! `held_reason` string `SyncState::set_held` (section 1's schema) records.
//! Per a hazard here **never** produces an automatic rename or
//! escape — the record is held, exactly as-is, under its original path, or
//! not held at all. See `peer_session.rs`'s
//! `no_hazard_ever_writes_under_any_alternate_name` regression test (task
//! 4.5), which the normalization-collision hazard is bound by identically —
//! it reuses the same `held_reason`-only outcome shape as the case-fold
//! hazard rather than introducing a second one (see
//! [`normalization_collision`]'s doc comment for why).

use std::path::Path;

use yadorilink_replica_domain::file::FileRecord;

/// `SyncState::set_held`'s own doc comment in `index.rs`
/// already documents these two exact reason-string prefixes as its
/// canonical examples (`"case_collision"`, `"invalid_name"`) — this module
/// is what actually produces them, so the constants live here as the
/// single source of truth. Both are prefixes: the full `held_reason`
/// stored also carries a human-readable detail after a `": "` separator
/// (e.g. `"case_collision: collides with existing 'Photo.jpg'"`), but
/// `held_reason.starts_with(HELD_REASON_CASE_COLLISION)` is the stable
/// thing to match against — the detail text is for humans (CLI display),
/// not for programmatic dispatch.
pub const HELD_REASON_CASE_COLLISION: &str = "case_collision";
pub const HELD_REASON_INVALID_NAME: &str = "invalid_name";
/// See [`normalization_collision`]'s doc comment for the judgement call on
/// why this hazard is reported the same way (`held_reason`, never an
/// automatic rename) as [`HELD_REASON_CASE_COLLISION`].
pub const HELD_REASON_NORMALIZATION_COLLISION: &str = "normalization_collision";
/// See [`case_and_normalization_collision`]'s doc comment: a pair that
/// differs on both the case-fold AND normalization axes at once, which
/// [`HELD_REASON_CASE_COLLISION`]/[`HELD_REASON_NORMALIZATION_COLLISION`]'s
/// own single-axis checks cannot catch independently.
pub const HELD_REASON_CASE_AND_NORMALIZATION_COLLISION: &str = "case_and_normalization_collision";
/// Not a filename hazard: a path whose file is already on disk with a mode
/// that denies its owner read access (for example `0o200`), where the
/// version to be installed needs replicated metadata this device can
/// neither read back nor set on that file. The file is left exactly as it
/// is, content and inode included, and the path is held rather than
/// retried: nothing changes until its mode, its content or the desired
/// version does. See [`metadata_unprovable_reason`] for the stored text.
pub use yadorilink_replica_domain::session_state::HELD_REASON_METADATA_UNPROVABLE;

/// The full `held_reason` recorded for [`HELD_REASON_METADATA_UNPROVABLE`].
pub fn metadata_unprovable_reason() -> String {
    format!(
        "{HELD_REASON_METADATA_UNPROVABLE}: replicated xattrs cannot be confirmed or applied \
         because the existing file is owner-unreadable"
    )
}

/// Which platform's filename rules gate materialization ("gated
/// on the local platform" — a Windows peer holds a `CON.txt`, a POSIX peer
/// materializing the exact same index record does not, since the name is
/// completely valid there). A real materializing device always uses
/// [`NamePolicy::local`]; tests exercise both variants directly against
/// identical index state to prove exactly that asymmetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamePolicy {
    Posix,
    Windows,
}

impl NamePolicy {
    /// The policy this actual running device's platform implies.
    #[cfg(windows)]
    pub fn local() -> Self {
        NamePolicy::Windows
    }

    /// See the `#[cfg(windows)]` variant above.
    #[cfg(not(windows))]
    pub fn local() -> Self {
        NamePolicy::Posix
    }
}

/// The documented Windows-reserved device basenames, compared
/// case-insensitively against a filename's stem (the part before its
/// *first* `.` — see `windows_invalid_name_detail`'s doc comment for why
/// `CON.txt` is still reserved).
const RESERVED_BASENAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The documented forbidden-character set.
const FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

/// the Windows-invalid-name reason `final_component` (a single
/// path component — the file's own name, not a full path) would be held
/// for, or `None` if it's fine under Windows' documented naming rules.
/// Pure string analysis; never touches the filesystem. Checks, in order:
/// any of `<>:"|?*` anywhere in the name; a trailing `.` or ` `; and the
/// reserved-basename list, checked against the name *without* its
/// extension (`stem`, the substring before the first `.`) — Windows
/// reserves `CON` as a device name regardless of what follows it, so
/// `CON.txt` and `CON.tar.gz` are both still reserved, exactly as `CON`
/// itself is.
fn windows_invalid_name_detail(final_component: &str) -> Option<String> {
    if final_component.is_empty() {
        return None;
    }
    if let Some(bad) = final_component.chars().find(|c| FORBIDDEN_CHARS.contains(c)) {
        return Some(format!("forbidden character '{bad}'"));
    }
    if final_component.ends_with('.') || final_component.ends_with(' ') {
        return Some("trailing dot or space".to_string());
    }
    let stem = final_component.split('.').next().unwrap_or(final_component);
    if RESERVED_BASENAMES.iter().any(|reserved| reserved.eq_ignore_ascii_case(stem)) {
        return Some(format!("reserved device name '{}'", stem.to_uppercase()));
    }
    None
}

/// `path`'s held reason under `policy`, or `None` if
/// materializing it under `policy` is safe. Always `None` under
/// [`NamePolicy::Posix`] — the Windows-only rule set never gates a POSIX
/// materialization, since a name like `CON.txt` is completely valid on a
/// POSIX filesystem ("gated on the local platform"). Only the
/// *final* path component (`path`'s own filename) is checked, matching the
/// task's framing ("checked against the filename") — an intermediate
/// directory component happening to be named `CON` is out of scope here,
/// same as `case_fold_collision` below only ever compares siblings within
/// one directory.
pub fn invalid_name_reason(policy: NamePolicy, path: &str) -> Option<String> {
    if policy == NamePolicy::Posix {
        return None;
    }
    let final_component = final_component_of(path);
    windows_invalid_name_detail(final_component)
        .map(|detail| format!("{HELD_REASON_INVALID_NAME}: {detail}"))
}

/// `path`'s final path component (its own file/directory name).
fn final_component_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// the already-indexed sibling in `siblings` that `path` collides
/// with case-insensitively, if any — a non-deleted record whose FULL path
/// (every component, not just the final one) case-folds identically to
/// `path`'s own but is not byte-identical to it (so updating a file at its
/// own unchanged path is never flagged as colliding with itself).
/// `siblings` is expected to be every record currently indexed for the
/// group (`SyncState::list_files`) — this function does the case-fold
/// comparison itself (including the `deleted` filter), so it stays a pure,
/// directly testable function with no `SyncState` dependency of its own.
///
/// Compares the WHOLE path, not parent-byte-exact plus leaf-case-folded:
/// an earlier version split into `parent_of` (compared with `==`) and
/// `final_component_of` (case-folded), which missed a collision where the
/// PARENT directories themselves alias under case-fold, e.g.
/// `Docs/Report.txt` vs `docs/report.txt` on a case-insensitive volume --
/// `"Docs" != "docs"` excluded the pair before the leaf comparison could
/// even run, even though they resolve to one physical directory. Case-
/// folding the full path (both sides, including every `/`-separated
/// component) and comparing as ordinary strings catches this without
/// needing separate parent/leaf logic: `/` is not itself case-folded, so
/// component boundaries stay exactly where they were, and two paths with a
/// genuinely different component structure still cannot fold equal.
///
/// O(siblings.len) per call — this module doesn't index siblings by
/// case-folded path, since section 4 isn't scoped as a
/// performance-sensitive path the way, e.g., ``/`` in
/// `peer_session.rs` are; a large single folder group could make this a
/// real cost worth revisiting, but that's a follow-on, not this section's
/// job.
///
/// Uses `caseless::default_case_fold_str` (Unicode's own `CaseFolding.txt`
/// algorithm), not `str::to_lowercase`: those are different operations that mostly agree but not
/// always --
/// `to_lowercase` is Unicode's *lowercase mapping*, meant for display, and
/// applies context-sensitive special-casing (e.g. Greek sigma at the end
/// of a word lowercases to the final form `ς`), while case folding is
/// meant specifically for case-INSENSITIVE COMPARISON and deliberately
/// ignores that context, always mapping every sigma to the same fold
/// target. A case-insensitive filesystem (the majority default on both
/// macOS and Windows) folds names the second way, not the first: `"ΟΔΟΣ"`
/// and a name ending in a literal (non-final) `"σ"` collide to the same
/// physical file on such a filesystem, but `to_lowercase` alone (which
/// turns the all-caps form into the *final*-sigma spelling) would not
/// have recognized them as the same path.
pub fn case_fold_collision<'a>(path: &str, siblings: &'a [FileRecord]) -> Option<&'a FileRecord> {
    let folded = caseless::default_case_fold_str(path);
    siblings.iter().find(|sibling| {
        !sibling.deleted
            && sibling.path != path
            && caseless::default_case_fold_str(&sibling.path) == folded
    })
}

/// the already-indexed sibling in `siblings` that `path` collides
/// with under Unicode canonical-equivalence, if any — the [`case_fold_
/// collision`] structure, extended to a different equivalence relation
/// rather than duplicated: same directory-scoping, same non-deleted filter,
/// same "not colliding with its own unchanged path" exclusion, same
/// `O(siblings.len)` shape and cost trade-off (see that function's doc
/// comment; a second `O(n)` pass over the same `siblings` slice doubles
/// this hazard-checking pass's constant factor, not its asymptotic cost —
/// the same "a missed collision check corrupts user data; an extra scan
/// does not" trade this module already makes for the case-fold check
/// applies unchanged here).
///
/// # Which normalization form, and why
///
/// Compares under **NFC** (Unicode Normalization Form C, canonical
/// composition): both `path`'s and each candidate sibling's final path
/// component are normalized to NFC before comparing. NFC, not NFD or any
/// other form, because of what NFC actually guarantees: it is a canonical
/// mapping, so any two canonically-equivalent input strings — regardless of
/// which of the (in general many) equivalent byte sequences either one
/// started as — produce the *identical* NFC output. That property, not any
/// claim about matching what a particular filesystem stores on disk, is
/// what makes NFC the right comparison basis: this function is answering
/// "are these two path strings the same logical name", a property of the
/// two strings alone, not "what byte sequence will this specific volume
/// store them as".
///
/// That is a deliberate, and important, difference from
/// [`is_normalization_insensitive_filesystem`]'s job. This function's
/// answer does not depend on which volume the result will be materialized
/// to; **whether the collision matters** does, which is why the probe is a
/// separate function and this comparison does not attempt to replicate any
/// one filesystem's exact on-disk normalization algorithm. That distinction
/// matters concretely for macOS, whose two shipping filesystems do not
/// agree with each other or with NFC/NFD: HFS+ decomposes every filename it
/// stores using Apple's own canonical-decomposition table, which is close
/// to, but is documented by Apple as *not identical to*, Unicode NFD (a
/// handful of currently-obscure characters decompose differently); APFS by
/// contrast stores whatever bytes were given and instead performs
/// normalization-*insensitive comparison* at lookup time, using yet another
/// internal algorithm neither this crate nor its `unicode-normalization`
/// dependency has an independent implementation of. Reproducing either
/// exactly is not attempted — see [`is_normalization_insensitive_
/// filesystem`]'s doc for why probing the volume for the *effect* (does it
/// alias two spellings that a straightforward NFC/NFD encoder would
/// produce) is the honest substitute for reproducing algorithms this crate
/// cannot independently confirm. What NFC comparison here does guarantee is
/// catching the overwhelmingly common real-world case this hazard exists
/// for: a composed-vs-decomposed spelling of an ordinary accented name,
/// which is canonically equivalent under standard Unicode normalization
/// (and, in every case this crate's own tests can construct, under HFS+'s
/// decomposition too, since Apple's table is a near-superset of NFD's
/// common-Latin coverage) — not a claim that every possible macOS-specific
/// aliasing shape is covered.
///
/// # Held, not auto-resolved — and why
///
/// Exactly like [`case_fold_collision`]: a colliding record is reported
/// (via [`HELD_REASON_NORMALIZATION_COLLISION`], composed by
/// `peer_session::hazard_reason_for_policy`) so the caller can hold it —
/// leave it unmaterialized, under its own original path, exactly as the
/// index already has it — never silently renamed to some disambiguated
/// spelling. The reasoning is identical to the case-fold hazard's, restated
/// here because it is easy to assume Unicode normalization specifically
/// calls for "just normalize it and materialize the normalized form": doing
/// that would mean every peer choosing its own arbitrary normalization
/// convention for materializing an inherited path, which is exactly the
/// kind of automatic-rename-under-a-different-name this module's own doc
/// comment already rules out for every hazard it detects (see the module
/// doc's "the record is held, exactly as-is, under its original path, or
/// not held at all"), and `peer_session.rs`'s `no_hazard_ever_writes_
/// under_any_alternate_name` regression test already pins that invariant
/// for every hazard reported through `hazard_reason_for` — this one
/// included, not exempted. What the user sees is the same as any other
/// held record: it does not appear on disk at this path until the
/// collision is resolved by hand (renaming one of the two paths at the
/// source, which is then a normal, unheld sync), reported through whatever
/// surface already lists held records by `held_reason`.
///
/// # A pair admitted before this check existed
///
/// If both spellings were already accepted into the index before this
/// function existed (nothing rejected either one at admission time; this is
/// purely a materialization-time hold, like [`case_fold_collision`]), this
/// function's first real effect is the next time either path is
/// (re-)materialized on a volume [`is_normalization_insensitive_
/// filesystem`] reports `true` for — exactly the same "next reconcile
/// catches it, nothing retroactively rescans already-held state" answer
/// `peer_session::hazard_reason_for_policy`'s own doc comment already gives
/// for the case-fold hazard, extended here rather than re-derived, since
/// the mechanism (this function is only ever consulted from that same call
/// site, on the same "materialize a specific record now" path) is
/// unchanged. If the two had *already* both materialized to disk on such a
/// volume before this check shipped, the second write already silently
/// clobbered the first at that time — this function cannot undo a
/// collision that already happened, only prevent this device from creating
/// a new one from this point on; the same residual [`case_fold_collision`]
/// has always had for a pre-existing case collision, now stated explicitly
/// for this hazard rather than left implicit.
///
/// Compares the WHOLE path under NFC, not parent-byte-exact plus
/// leaf-normalized — see [`case_fold_collision`]'s doc comment for why a
/// byte-exact parent comparison misses a collision where the parent
/// directories themselves are the ones that alias (there, under case-fold;
/// here, under Unicode normalization), and why comparing the full,
/// component-boundary-preserving path string is the fix for both.
pub fn normalization_collision<'a>(
    path: &str,
    siblings: &'a [FileRecord],
) -> Option<&'a FileRecord> {
    use unicode_normalization::UnicodeNormalization;

    let nfc: String = path.nfc().collect();
    siblings.iter().find(|sibling| {
        !sibling.deleted && sibling.path != path && sibling.path.nfc().collect::<String>() == nfc
    })
}

/// A combination of both equivalence relations this module detects on its
/// own: NFC-normalize, lowercase, then NFC-normalize again (lowercasing
/// can introduce fresh combining sequences a prior NFC pass had no reason
/// to compose; re-normalizing after is the safe default rather than
/// assuming it never matters for any input). Neither `case_fold_collision`
/// (raw `to_lowercase`, no normalization) nor `normalization_collision`
/// (raw NFC, no case-folding) alone can catch a pair that differs on BOTH
/// axes at once -- verified with `"Café.txt"` (capital `C`, composed `é`)
/// vs `"café.txt"` (lowercase `c`, decomposed `é`): `case_fold_collision`
/// misses it because lowercasing alone never reconciles the differing `é`
/// encodings, and `normalization_collision` misses it because NFC alone
/// never reconciles the differing `C`/`c` case (`case_and_normalization_
/// collision_tests::detects_a_pair_differing_in_both_case_and_
/// normalization_at_once` asserts both negatives as its own precondition,
/// not just the positive). On a volume that is simultaneously
/// case-insensitive AND normalization-insensitive (the macOS default, both
/// HFS+ and APFS), that pair collides to one physical file despite
/// differing on every axis tested independently.
pub use yadorilink_fs_platform::canonical_fold::canonical_fold;

/// the already-indexed sibling in `siblings` that `path` collides with
/// under the COMBINED case-fold-and-normalization equivalence
/// [`canonical_fold`] computes, if any -- catches a pair that differs on
/// both axes at once, which neither [`case_fold_collision`] nor
/// [`normalization_collision`] alone can (see [`canonical_fold`]'s doc
/// comment for a concrete pair). Same directory-scoping-by-whole-path,
/// non-deleted filter, and self-exclusion as both of those.
pub fn case_and_normalization_collision<'a>(
    path: &str,
    siblings: &'a [FileRecord],
) -> Option<&'a FileRecord> {
    let folded = canonical_fold(path);
    siblings.iter().find(|sibling| {
        !sibling.deleted && sibling.path != path && canonical_fold(&sibling.path) == folded
    })
}

/// Deliberately NOT cached, even keyed by the canonicalized directory
/// path. An earlier version of this function cached its answer process-wide
/// per canonicalized `dir`, reasoning that a probe is a real filesystem
/// round trip (worth paying once per sync root rather than once per
/// materialized record) and that a directory's filesystem does not change
/// while mounted. That reasoning is the same one this crate already
/// retracted for `fs_identity`'s per-volume filesystem-name cache: a path
/// is not a mount instance. A volume can be unmounted and a different (or
/// differently formatted) one mounted at the exact same path — a case-
/// sensitive volume replaced by a case-insensitive one, or vice versa — and
/// nothing observable from `dir` alone distinguishes that remount from the
/// mount that earned a cached entry. A path is in fact a *weaker* key than
/// the volume serial number `fs_identity` already rejected for this same
/// reason: a serial number at least changes across a reformat, while a path
/// does not change at all across a remount.
///
/// A per-platform mount identifier was considered instead of dropping the
/// cache outright — `st_dev` on Unix does change across a remount of a
/// different device at the same path, cheaply obtainable from a `stat` this
/// function already pays for via `canonicalize`. But `fs_identity` already
/// established, for the identical class of problem, that Windows has no
/// such identifier: `VolumeSerialNumber` is documented as identifying a
/// volume, not a mount instance, and a cloned or reformatted volume can
/// carry a prior volume's serial by construction. A cache keyed on a real
/// mount identifier on Unix and on a value already known not to be one on
/// Windows would fail closed on exactly one platform, not both — worse than
/// no cache, since a caller could reasonably assume revalidation actually
/// happens everywhere it's compiled. Where there is no way to tell a
/// remount from the mount that earned the entry on every platform this
/// runs on, the honest answer is not to cache on any of them.
///
/// What this costs is small relative to its caller. This is the one real
/// filesystem probe `hazard_reason_for_policy` in `peer_session.rs` makes,
/// but it is not the dominant cost on that path: it runs after
/// `VerifiedRoot::verify` and gates a `SyncState::list_files` call that
/// scans and deserializes every currently-indexed record for the whole
/// group, and (when the record is not itself held) is followed by an
/// actual block fetch and file write to materialize the record's content.
/// Against a full group index scan and a real content write already
/// happening on the same call, one scratch-directory create + small file
/// create + existence check + removal is a marginal addition, not a new
/// order of cost.
///
/// Probes for real rather than assuming from `cfg!(target_os = ...)`, since
/// neither direction of that assumption holds: macOS APFS can be formatted
/// either case-sensitive or case-insensitive (case-insensitive is only the
/// *default*), and a case-insensitive volume (a mounted exFAT/NTFS share,
/// for instance) can exist on a case-sensitive-by-default OS too. Probes by
/// creating a file with mixed-case letters inside a scratch directory this
/// call has just created under `dir` (see [`probe_in_named_dir`] for why the
/// scratch directory exists and how it is owned), then checking whether an
/// all-uppercase variant of that exact name resolves to the same entry.
///
/// On any probe I/O failure (can't create `dir`, can't canonicalize it,
/// can't write the probe file — e.g. a not-yet-existing or read-only
/// root), this conservatively assumes case-**insensitive**: the stricter
/// of the two answers, since it never lets a possible collision through
/// unheld — the opposite default (case-sensitive) would let a real
/// collision through unheld on a filesystem this device simply couldn't
/// successfully probe, which is the failure mode this exists to
/// prevent. The same asymmetry is why this must never be allowed to serve
/// a stale cached answer either: caching "case-sensitive" across a remount
/// to an actually case-insensitive volume silently disables the collision
/// check (two logical paths land on one physical name); caching the
/// opposite direction only costs an unnecessary `list_files` scan. A
/// missed collision check corrupts user data; an extra scan does not — so
/// where a cache cannot be proven valid, correctness has to lean toward
/// re-probing, never toward reusing a possibly-stale `true`.
pub fn is_case_insensitive_filesystem(dir: &Path) -> bool {
    probed_case_insensitivity(dir).unwrap_or(true) // conservative default — see doc comment
}

/// [`is_case_insensitive_filesystem`] without its default: `None` when the probe could not run.
/// For a caller that may act only on a known answer (the conservative default holds a
/// collision; it must never be read as permission to drop one name for another).
pub fn probed_case_insensitivity(dir: &Path) -> Option<bool> {
    let canonical = std::fs::create_dir_all(dir).and_then(|_| std::fs::canonicalize(dir)).ok()?;
    probe_case_insensitive_filesystem(&canonical).ok()
}

/// Bumped once per real probe round trip. Not a uniqueness source — probe
/// artefact names are minted by `fs_capabilities::probe_artefact_name`, and
/// ownership is established by `create_dir` failing rather than by the name
/// being unguessable (see [`probe_in_named_dir`]). Read only by
/// `case_insensitive_probe_tests::second_call_on_the_same_directory_
/// performs_a_second_real_probe_not_a_cached_lookup` as the only externally
/// observable proof that nothing memoizes the answer across calls.
static PROBE_CALL_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn probe_call_count_for_test() -> u64 {
    PROBE_CALL_COUNTER.load(std::sync::atomic::Ordering::Relaxed)
}

/// The lower-case spelling both halves of the case probe are built from.
/// Mixed-case-able ASCII letters, so `to_uppercase` below actually changes
/// the string — a name with no letters (or one already all-uppercase) would
/// make this probe meaningless.
const CASE_PROBE_LEAF_NAME: &str = "case-probe-a";

/// The composed spelling the normalization probe writes. `\u{e9}` is a
/// composed Latin small letter e with acute accent — the textbook
/// composed/decomposed pair this hazard exists for; `.nfd()` turns it into
/// the canonically-equivalent decomposed spelling, `e` (U+0065) followed by
/// the combining acute accent (U+0301).
const NORMALIZATION_PROBE_LEAF_NAME: &str = "nfc-probe-\u{e9}";

/// Runs `probe` inside a scratch directory this call has just created, at
/// `probe_dir_name` under `parent`, and removes that directory again on
/// every exit path.
///
/// Both volume-behaviour probes in this module have to put a real artefact
/// on the caller's volume, and that volume is the user's sync directory:
/// whatever they create sits beside real user content, reachable from a
/// production materialization path (`hazard_reason_for_policy`), with no
/// execution gate in front of it. Two properties therefore have to hold, and
/// neither is optional:
///
/// 1. **The artefact must not be indexable content.** `probe_dir_name` comes
///    from [`yadorilink_fs_platform::fs_capabilities::probe_artefact_name`], which builds a
///    name in the engine's reserved namespace
///    (`.yadorilink-v1-probe.<id>`). That is the exact predicate — via
///    `reserved_namespace::path_has_reserved_component` — that the watcher,
///    the initial scan and local change processing all consult *before*
///    indexing anything, and it matches on any component of a relative path,
///    so everything this function creates *inside* the directory is excluded
///    by the directory's own name without needing a reserved name of its
///    own. An unreserved probe name is ordinary content to every one of
///    those entry points for the whole window between creation and cleanup,
///    and can be signed into native state and replicated to peers if a scan wins
///    that race. See `fs_capabilities::probe_artefact_name`'s doc comment,
///    which records the same defect and the same fix for that module's
///    probes.
///
/// 2. **Nothing this process did not itself create may be removed.**
///    `create_dir` fails with `AlreadyExists` rather than adopting or
///    truncating an existing entry, so an `Ok` return is proof that this
///    call, and not some unrelated writer, put the directory there — the
///    same "never delete an artefact you don't own" rule the reserved
///    namespace enforces elsewhere, and the reason `create_dir` is used
///    instead of `create_dir_all` (which succeeds on an existing directory)
///    and instead of an unconditional pre-emptive remove. The
///    `AlreadyExists` error is propagated to [`probe_in_owned_dir`], which
///    retries under a *fresh* name; a colliding entry is left exactly as it
///    was found, contents included.
///
/// The scratch directory also removes a constraint the probes would
/// otherwise be stuck with. Both need a *second* spelling of the name they
/// create (an all-uppercase variant; a decomposed variant) to test whether
/// the volume aliases the two. That second spelling cannot be built through
/// the reserved namespace itself: reserved ids are restricted to
/// `[A-Za-z0-9_-]`, which cannot express a non-ASCII composed character at
/// all, so a flat normalization probe has no reserved name available to it.
/// Inside a directory this call has just created — necessarily empty, and
/// unreachable to any writer that does not know the freshly minted name —
/// no leaf name of either spelling can collide with a user file, so the leaf
/// names are free to be whatever the probe actually needs to measure.
fn probe_in_named_dir<T>(
    parent: &Path,
    probe_dir_name: &str,
    probe: impl FnOnce(&Path) -> std::io::Result<T>,
) -> std::io::Result<T> {
    let probe_dir = parent.join(probe_dir_name);
    std::fs::create_dir(&probe_dir)?;
    let result = probe(&probe_dir);
    // Unconditional, including on the error path: this call created the
    // directory, so it owns it, and a probe that failed halfway still must
    // not leave an artefact behind in the user's sync directory.
    let _ = std::fs::remove_dir_all(&probe_dir);
    result
}

/// Runs `probe` in a freshly created reserved-namespace scratch directory
/// under `parent`, retrying under a new name if the minted one is already
/// taken. See [`probe_in_named_dir`] for why a collision must never be
/// resolved by removing whatever is already there.
fn probe_in_owned_dir<T>(
    parent: &Path,
    label: &str,
    probe: impl Fn(&Path) -> std::io::Result<T>,
) -> std::io::Result<T> {
    for _ in 0..yadorilink_fs_platform::fs_capabilities::MAX_ARTEFACT_NAME_ATTEMPTS {
        let name = yadorilink_fs_platform::fs_capabilities::probe_artefact_name(label)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        match probe_in_named_dir(parent, &name, &probe) {
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            other => return other,
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique probe artefact name",
    ))
}

/// Creates the lower-case spelling and reports whether the all-uppercase
/// spelling of that same name resolves to it. Creates with `create_new`, not
/// `create`: `create` truncates an existing entry, and while `probe_dir` is
/// this process's own freshly created directory, using the non-truncating
/// call is what keeps that property a local one rather than something a
/// future caller of this helper has to re-derive.
fn case_insensitivity_within(probe_dir: &Path) -> std::io::Result<bool> {
    let lower_path = probe_dir.join(CASE_PROBE_LEAF_NAME);
    let upper_path = probe_dir.join(CASE_PROBE_LEAF_NAME.to_uppercase());
    std::fs::OpenOptions::new().write(true).create_new(true).open(&lower_path)?;
    Ok(upper_path.exists())
}

fn probe_case_insensitive_filesystem(canonical_dir: &Path) -> std::io::Result<bool> {
    use std::sync::atomic::Ordering;

    PROBE_CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    probe_in_owned_dir(canonical_dir, "case", case_insensitivity_within)
}

/// Whether `dir`'s volume resolves two different Unicode normalization
/// forms of the same logical filename to one on-disk object — the
/// [`normalization_collision`] counterpart to [`is_case_insensitive_
/// filesystem`], extending the identical structure (real probe, not an
/// assumption; conservative fail-closed default; never cached) to a
/// different axis rather than folding the two together, since a volume can
/// independently be case-sensitive-yet-normalization-insensitive, the
/// reverse, both, or neither — mounting an exFAT share on Linux is
/// case-insensitive but byte-exact (normalization-sensitive) for example,
/// and this crate has no basis to assume the two axes move together on any
/// volume it has not itself probed.
///
/// Not assumed from `cfg!(target_os = ...)` for the same reason
/// [`is_case_insensitive_filesystem`] is not: macOS's own two shipping
/// filesystems do not even agree with *each other*. HFS+ decomposes every
/// filename it stores, so this reliably reports `true` there for ordinary
/// Latin-script accented names regardless of how the two peers spelled
/// them. APFS instead performs normalization-insensitive *comparison* at
/// lookup time while preserving whatever bytes were originally written —
/// which behaves identically from this probe's point of view (the
/// decomposed spelling still resolves to the composed one's dentry) even
/// though the two filesystems reach that outcome by different mechanisms,
/// which is exactly why this function measures the observable effect
/// rather than branching on which of the two is mounted. See
/// [`normalization_collision`]'s doc comment for the companion point: that
/// function's own NFC comparison basis does not attempt to replicate
/// either filesystem's internal algorithm either — the two functions
/// divide the problem the same way [`case_fold_collision`] and
/// [`is_case_insensitive_filesystem`] already do, one deciding "are these
/// two strings the same name" and the other deciding "does this volume
/// care".
///
/// Fails closed exactly like [`is_case_insensitive_filesystem`]: any probe
/// I/O failure conservatively reports `true` (normalization-insensitive),
/// since a missed collision check corrupts user data on the volumes this
/// function got wrong, while an unnecessary extra sibling scan on the
/// volumes it got right costs nothing but a little time — the identical
/// asymmetry that function's own doc comment already argues for, restated
/// here because getting the direction backwards here fails exactly as
/// silently as it would there. Not cached, for the identical remount
/// argument in that function's doc comment (a path is not a mount
/// instance, on either axis).
///
/// # Cost
///
/// One additional real filesystem round trip per `hazard_reason_for_policy`
/// call beyond [`is_case_insensitive_filesystem`]'s own probe — a second
/// small file create + existence check + removal, the same cost class as
/// that probe, not a new order of cost against the same call's
/// already-dominant `SyncState::list_files` scan and (when not held) block
/// fetch and content write (see that function's own "What this costs" for
/// the baseline this is added on top of). When both probes report their
/// respective hazard's volume-sensitivity `true`, the call additionally
/// pays a *second* `O(siblings.len)` scan over the same slice
/// [`case_fold_collision`] already scanned once, for
/// [`normalization_collision`]'s own pass — doubling that scan's constant
/// factor, not its asymptotic cost, and not the dominant term on this call
/// either.
pub fn is_normalization_insensitive_filesystem(dir: &Path) -> bool {
    probed_normalization_insensitivity(dir).unwrap_or(true) // conservative default
}

/// [`is_normalization_insensitive_filesystem`] without its default: `None` when the probe could
/// not run.
pub fn probed_normalization_insensitivity(dir: &Path) -> Option<bool> {
    let canonical = std::fs::create_dir_all(dir).and_then(|_| std::fs::canonicalize(dir)).ok()?;
    probe_normalization_insensitive_filesystem(&canonical).ok()
}

/// Bumped once per real probe round trip, the [`PROBE_CALL_COUNTER`]
/// counterpart for [`is_normalization_insensitive_filesystem`]'s own probe
/// — kept as a separate counter (not sharing `PROBE_CALL_COUNTER`) so a
/// test that wants to observe one probe's call count is never confused by
/// the other axis's probe also advancing it.
static NORMALIZATION_PROBE_CALL_COUNTER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn normalization_probe_call_count_for_test() -> u64 {
    NORMALIZATION_PROBE_CALL_COUNTER.load(std::sync::atomic::Ordering::Relaxed)
}

/// The [`case_insensitivity_within`] counterpart on the normalization axis:
/// creates the composed spelling and reports whether the canonically
/// equivalent decomposed spelling resolves to it. Same `create_new`
/// discipline, same freshly created scratch directory — see
/// [`probe_in_named_dir`], whose doc comment also records why this probe in
/// particular cannot use a flat reserved name (a reserved id is
/// ASCII-only and so has no composed/decomposed pair to compare).
fn normalization_insensitivity_within(probe_dir: &Path) -> std::io::Result<bool> {
    use unicode_normalization::UnicodeNormalization;

    let decomposed_name: String = NORMALIZATION_PROBE_LEAF_NAME.nfd().collect();
    let composed_path = probe_dir.join(NORMALIZATION_PROBE_LEAF_NAME);
    let decomposed_path = probe_dir.join(&decomposed_name);
    std::fs::OpenOptions::new().write(true).create_new(true).open(&composed_path)?;
    Ok(decomposed_path.exists())
}

fn probe_normalization_insensitive_filesystem(canonical_dir: &Path) -> std::io::Result<bool> {
    use std::sync::atomic::Ordering;

    NORMALIZATION_PROBE_CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    probe_in_owned_dir(canonical_dir, "nfc", normalization_insensitivity_within)
}

/// Whether `path` (a `/`-separated record path under `root`) is observably
/// absent when every component is compared by its own name, not resolved
/// through this volume's case/normalization folding.
///
/// For a path already found to collide with a live sibling: on a folding
/// volume, looking the whole path up resolves to the sibling's entry, so a
/// lookup can never report this path absent while the sibling lives. The
/// collision may sit in ANY component (`Docs/report.txt` against a live
/// `docs/report.txt` collides through the parent, not the leaf -- the
/// hazard checks fold the whole path), so each component is looked for in
/// its parent's listing, from `root` down. The first component no entry
/// could be proves the path absent. Every component matched means some
/// entry may be this exact path: not absent.
///
/// An entry "may be" a component when its name is byte-identical to it,
/// or -- only when `normalization_insensitive` (the volume's own probe
/// result, see [`is_normalization_insensitive_filesystem`]) -- canonically
/// equivalent to it under Unicode normalization while still differing in
/// case. The second arm is because such a directory does not always record
/// a name as it was created: HFS+ decomposes every name it stores, so an
/// entry created as a composed `Caf\u{e9}.jpg` is listed decomposed, and a
/// byte comparison would call it absent. Whether an equivalent-but-not-
/// identical entry is this name's stored form or a distinct sibling cannot
/// be told from the listing on such a volume, so it counts as present: the
/// failure direction is a retry, never a claimed absence. On a
/// normalization-sensitive volume (APFS keeps both spellings as created) an
/// equivalent spelling is a distinct file, so it is not this name and must
/// not keep a redelivered tombstone retrying forever. Case is compared
/// exactly either way, because no filesystem rewrites a name's case when
/// storing it.
///
/// Anything the listing cannot answer -- an unreadable directory, an
/// unreadable entry, a component that is not a directory -- is not an
/// observed absence.
pub fn observably_absent_by_exact_name(
    root: &Path,
    path: &str,
    normalization_insensitive: bool,
) -> bool {
    exact_name_absent_with(root, path, normalization_insensitive, |dir| {
        std::fs::read_dir(dir).map(|entries| entries.map(|entry| entry.map(|e| e.file_name())))
    })
}

/// [`observably_absent_by_exact_name`] over an injected directory lister,
/// so its fail-closed arms can be driven without a filesystem that fails
/// on cue.
fn exact_name_absent_with<L, I>(
    root: &Path,
    path: &str,
    normalization_insensitive: bool,
    mut list: L,
) -> bool
where
    L: FnMut(&Path) -> std::io::Result<I>,
    I: Iterator<Item = std::io::Result<std::ffi::OsString>>,
{
    let mut dir = root.to_path_buf();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        let Ok(entries) = list(&dir) else {
            return false;
        };
        let mut matched = false;
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            if entry_may_be_named(&entry, component, normalization_insensitive) {
                matched = true;
                break;
            }
        }
        if !matched {
            return true;
        }
        dir.push(component);
    }
    false
}

/// See [`observably_absent_by_exact_name`] for why canonical equivalence
/// counts and case-folding does not.
fn entry_may_be_named(
    entry: &std::ffi::OsStr,
    component: &str,
    normalization_insensitive: bool,
) -> bool {
    use unicode_normalization::UnicodeNormalization;
    if entry.as_encoded_bytes() == component.as_bytes() {
        return true;
    }
    if !normalization_insensitive {
        return false;
    }
    match entry.to_str() {
        Some(entry) => entry.nfd().eq(component.nfd()),
        None => false,
    }
}

#[cfg(test)]
mod exact_name_absence_tests;

#[cfg(test)]
mod invalid_name_tests;

#[cfg(test)]
mod case_fold_collision_tests;

#[cfg(test)]
mod normalization_collision_tests;

#[cfg(test)]
mod case_and_normalization_collision_tests;

#[cfg(test)]
mod case_insensitive_probe_tests;

#[cfg(test)]
mod probe_artefact_ownership_tests;

#[cfg(test)]
mod normalization_insensitive_probe_tests;

/// Pure, filesystem-independent tests of `case_fold_collision`/
/// `canonical_fold`'s own folding algorithm -- unlike the case-insensitive
/// hazard tests above (which need and skip without a real case-insensitive
/// tempdir), these exercise the fold function directly, so they run
/// identically on every CI host regardless of the local filesystem's own
/// case sensitivity.
#[cfg(test)]
mod case_folding_correctness_tests;
