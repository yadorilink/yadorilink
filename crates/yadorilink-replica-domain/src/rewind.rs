//! Folder Rewind's read-only plan: a deterministic description of what
//! *would* have to change, per path, to bring a group's desired state back
//! to what this device held at some wall-clock time T.
//!
//! Pure data. Nothing here emits a signed [`crate::local_op::Change`], touches
//! a filesystem, creates a materialization obligation, or otherwise
//! commits to anything -- a [`RewindPlan`] is a preview a caller renders
//! and a human decides about. The types deliberately carry enough to
//! render that decision honestly, including an explicit "this device
//! cannot answer for this path" outcome ([`RewindPathAction::Unavailable`])
//! that must never be quietly folded into "nothing to do".

use sha2::{Digest, Sha256};

use crate::codec::{put_i64, put_str, put_u64};
use crate::ids::VersionHash;

/// Domain tag of [`RewindPlan::plan_id`]'s encoding. A local digest, never
/// sent to a peer or stored as a native object, so it carries its own
/// version byte rather than the native protocol generation.
const REWIND_PLAN_ID_DOMAIN_TAG: &[u8; 8] = b"YLNKrwp\x01";

/// What a person is told when the folder no longer matches the plan they
/// approved. Nothing was started.
pub const PLAN_STALE_MESSAGE: &str = "the folder changed since the rewind preview; preview again";

/// What a rewind to `target_unix_nanos` would have to do to `group_id`'s
/// desired state, path by path.
///
/// `entries` is the authoritative part: exactly one entry per path this
/// device has ever indexed for this group, each carrying an independent
/// per-path verdict. `rename_candidates` is a purely auxiliary annotation
/// derived from `entries` afterwards -- see its own field comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindPlan {
    pub group_id: String,
    /// The rewind target, in nanoseconds since the Unix epoch, on the
    /// clock of the device that computed the plan. A plan is only ever
    /// meaningful against the device that produced it: the admission
    /// timestamps it is computed from are that device's own local
    /// observations, deliberately not a replicated value (see
    /// `files.admitted_at_unix_nanos`'s migration comment).
    pub target_unix_nanos: i64,
    pub entries: Vec<RewindPathEntry>,
    /// Best-effort "this looks like it was a rename" pairings between the
    /// [`RewindPathAction::Create`] and [`RewindPathAction::Delete`]
    /// entries above, matched purely on identical content
    /// ([`VersionHash`]). Advisory only, and always overridable: two
    /// unrelated paths that genuinely happen to hold byte-identical
    /// content produce a false pairing here, which is expected and
    /// harmless precisely because nothing in `entries` depends on this
    /// list. A renderer may present a pairing instead of its two separate
    /// entries; an executor (which does not exist in this read-only layer)
    /// would still have to act on `entries`, never on this.
    pub rename_candidates: Vec<RewindRenameCandidate>,
}

/// One path's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindPathEntry {
    /// Group-relative path, exactly as the index stores it.
    pub path: String,
    /// `version_seq` and [`VersionHash`] of the path's `current` row when the
    /// plan was computed (a tombstone's own for a path that is absent now):
    /// the "now" side of the verdict. A path written after the preview
    /// changes the plan's identity through these even when its action stays
    /// the same (an edited `Delete` target is still a `Delete`). Both are
    /// needed: an ordinary write advances the seq, but a path dropped from
    /// the index (it became ignored) and indexed again restarts its
    /// numbering, so only the hash tells its new content from the old.
    /// A path with no row at all now (its rows were erased and it was not
    /// indexed again) has `0` and the all-zero hash; such an entry is always
    /// `Unavailable`.
    pub current_version_seq: i64,
    pub current_version_hash: VersionHash,
    pub action: RewindPathAction,
}

/// What would have to happen to one path.
///
/// Every variant is a statement about this device's own index, not about
/// any filesystem: "present" means a non-tombstone version row, "absent"
/// means either a tombstone or no row at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewindPathAction {
    /// Present at T, absent now -- the path would come back, restored to
    /// the version identified here.
    Create { version_seq: i64, version_hash: VersionHash },
    /// Absent at T, present now -- the path would go away again.
    Delete,
    /// Present in both states but holding different content -- the path
    /// would be rolled back from its current version
    /// ([`RewindPathEntry::current_version_seq`]) to `to_version_seq`.
    Replace { to_version_seq: i64, to_version_hash: VersionHash },
    /// Present in both states with the identical [`VersionHash`], or
    /// absent in both. Nothing to do.
    Unchanged,
    /// This device cannot honestly say what this path held at T.
    ///
    /// A real, distinct outcome -- never a soft synonym for [`Self::
    /// Unchanged`] and never silently rounded to the nearest surviving
    /// version. Three things produce it: the evidence needed to answer is
    /// gone (the path's history at that point fell out of the retention
    /// window); this device never held any history reaching back that far
    /// in the first place (it joined the group late, or its own local
    /// history was replaced wholesale by a re-bootstrap more recently than
    /// the target); or the evidence was never recorded (a row predating the
    /// admission-timestamp column). All three are genuine "no answer exists
    /// here", and a rewind that quietly treated them as "leave it alone"
    /// would be presenting a guess as a plan.
    ///
    /// "Here" is the operative word for the middle one: another device that
    /// does hold the history can still answer it.
    Unavailable { reason: RewindUnavailableReason },
}

/// Why this device cannot answer for a path at the target time. Closed, so
/// a preview can group the paths by cause, and so the words a person reads
/// live in one place ([`Self::message`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RewindUnavailableReason {
    /// This device's continuous history of the group starts after the
    /// target: it joined the group later, or its history was replaced
    /// wholesale by a re-establishment since. Another device can answer.
    JoinedAfter,
    /// The versions of the path from that time were removed by version
    /// retention.
    RemovedByRetention,
    /// This device dropped its record of the path when the path was
    /// excluded from sync, then indexed it again.
    ExcludedFromSync,
    /// A retained version of the path carries no admission time.
    NoAdmissionTime,
    /// No history of the path at all (not reachable from a consistent
    /// index; reported rather than assumed).
    NoHistory,
}

impl RewindUnavailableReason {
    /// What a person is told about the paths unavailable for this reason.
    pub fn message(self) -> &'static str {
        match self {
            Self::JoinedAfter => {
                "this device joined after that time; run the rewind from a device that has the \
                 history (e.g. your NAS)"
            }
            Self::RemovedByRetention => "older versions were removed by retention",
            Self::ExcludedFromSync => {
                "this device dropped its earlier record when the path was excluded from sync"
            }
            Self::NoAdmissionTime => {
                "a kept version has no recorded arrival time, so what the path held then is unknown"
            }
            Self::NoHistory => "this device has no history of the path",
        }
    }
}

/// The unavailable paths of a plan, counted by cause. A rewind with any of
/// them cannot start (no partial rewind).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RewindUnavailable {
    /// Each cause that occurs, with how many paths it applies to, in the
    /// enum's order.
    pub by_reason: Vec<(RewindUnavailableReason, u64)>,
}

impl RewindUnavailable {
    pub fn total(&self) -> u64 {
        self.by_reason.iter().map(|(_, count)| count).sum()
    }

    /// "N files unavailable; rewind cannot start", followed by each cause
    /// and how many files it covers.
    pub fn message(&self) -> String {
        let mut out = format!("{} files unavailable; rewind cannot start", self.total());
        for (index, (reason, count)) in self.by_reason.iter().enumerate() {
            out.push_str(if index == 0 { ": " } else { "; " });
            out.push_str(&format!("{count} because {}", reason.message()));
        }
        out
    }
}

/// One heuristic rename pairing. See [`RewindPlan::rename_candidates`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindRenameCandidate {
    /// The path that would be deleted -- i.e. where this content lives now.
    pub from_path: String,
    /// The path that would be created -- i.e. where this content lived at T.
    pub to_path: String,
    /// The content both sides share, which is the entire basis for the
    /// guess.
    pub version_hash: VersionHash,
}

impl RewindPlan {
    /// The plan's unavailable paths, counted by cause.
    pub fn unavailable(&self) -> RewindUnavailable {
        let mut counts: std::collections::BTreeMap<RewindUnavailableReason, u64> =
            std::collections::BTreeMap::new();
        for entry in &self.entries {
            if let RewindPathAction::Unavailable { reason } = &entry.action {
                *counts.entry(*reason).or_default() += 1;
            }
        }
        RewindUnavailable { by_reason: counts.into_iter().collect() }
    }

    /// Per-action tallies, in the fixed order a renderer wants them:
    /// creates, deletes, replaces, unchanged, unavailable.
    pub fn action_counts(&self) -> RewindActionCounts {
        let mut counts = RewindActionCounts::default();
        for entry in &self.entries {
            match entry.action {
                RewindPathAction::Create { .. } => counts.create += 1,
                RewindPathAction::Delete => counts.delete += 1,
                RewindPathAction::Replace { .. } => counts.replace += 1,
                RewindPathAction::Unchanged => counts.unchanged += 1,
                RewindPathAction::Unavailable { .. } => counts.unavailable += 1,
            }
        }
        counts
    }

    /// The plan's stable identity: what a person approves when they confirm
    /// a preview, and what an execution re-derives from the current index
    /// before it may act.
    ///
    /// SHA-256 over a canonical encoding of the WHOLE plan, never of a
    /// trimmed listing, so every rendering of one plan carries the same id.
    /// Covered: the group, the target time, and every actionable entry
    /// (`Create`, `Delete`, `Replace`, `Unavailable`) with its path, action,
    /// current version (seq and hash) and -- for `Create`/`Replace` -- the
    /// exact historical version it would restore. Entries are hashed in path byte order
    /// whatever order they arrive in.
    ///
    /// Deliberately not covered, because none of it changes what an
    /// execution would do: `Unchanged` entries, `rename_candidates`
    /// (advisory), the prose `Unavailable` reason, and the tallies (derived
    /// from the entries).
    ///
    /// ```text
    /// tag || str(group_id) || i64(target_unix_nanos) || u64(actionable count)
    /// per actionable entry, by path:
    ///   str(path) || u8(action) || i64(current_version_seq) || current_version_hash[32]
    ///   create (0), replace (2): || i64(to_version_seq) || version_hash[32]
    ///   delete (1), unavailable (3): nothing more
    /// ```
    pub fn plan_id(&self) -> RewindPlanId {
        /// An actionable entry, its action tag, and the historical version
        /// it would restore (`Create`/`Replace` only).
        type Hashed<'a> = (&'a RewindPathEntry, u8, Option<(i64, &'a VersionHash)>);
        let mut actionable: Vec<Hashed<'_>> = self
            .entries
            .iter()
            .filter_map(|entry| {
                let (tag, restores) = match &entry.action {
                    RewindPathAction::Unchanged => return None,
                    RewindPathAction::Create { version_seq, version_hash } => {
                        (0u8, Some((*version_seq, version_hash)))
                    }
                    RewindPathAction::Delete => (1, None),
                    RewindPathAction::Replace { to_version_seq, to_version_hash } => {
                        (2, Some((*to_version_seq, to_version_hash)))
                    }
                    RewindPathAction::Unavailable { .. } => (3, None),
                };
                Some((entry, tag, restores))
            })
            .collect();
        actionable.sort_unstable_by(|a, b| a.0.path.as_bytes().cmp(b.0.path.as_bytes()));

        let mut hasher = Sha256::new();
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(REWIND_PLAN_ID_DOMAIN_TAG);
        put_str(&mut buf, &self.group_id);
        put_i64(&mut buf, self.target_unix_nanos);
        put_u64(&mut buf, actionable.len() as u64);
        hasher.update(&buf);
        for (entry, tag, restores) in actionable {
            buf.clear();
            put_str(&mut buf, &entry.path);
            buf.push(tag);
            put_i64(&mut buf, entry.current_version_seq);
            buf.extend_from_slice(&entry.current_version_hash.0);
            if let Some((version_seq, version_hash)) = restores {
                put_i64(&mut buf, version_seq);
                buf.extend_from_slice(&version_hash.0);
            }
            hasher.update(&buf);
        }
        RewindPlanId(hasher.finalize().into())
    }
}

/// See [`RewindPlan::plan_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RewindPlanId(pub [u8; 32]);

/// How many paths fall into each [`RewindPathAction`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RewindActionCounts {
    pub create: u64,
    pub delete: u64,
    pub replace: u64,
    pub unchanged: u64,
    pub unavailable: u64,
}

/// Where one rewind execution stands, as its journal row records it.
///
/// The journal is progress, never namespace truth: what a rewind changed is
/// the ordinary signed changes it authored, and nothing here is ever used
/// to resume or to infer what is on disk. An interrupted run is not
/// continued; see [`RewindRunState::NeedsReplan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RewindRunState {
    /// The approved plan was re-verified and the run recorded; its
    /// historical content is being made local.
    Planned,
    /// Every byte the plan needs is held locally and verified. Nothing has
    /// been changed yet.
    Prefetched,
    /// Changes are being authored, one chunk per transaction.
    Committing,
    /// Every chunk was committed.
    Done,
    /// The run stopped after at least one chunk was committed. Those
    /// changes stay as ordinary changes; the person previews again from the
    /// current state.
    NeedsReplan,
    /// The run stopped before changing anything; [`RewindFailureKind`]
    /// says why.
    Failed,
}

impl RewindRunState {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Prefetched => "prefetched",
            Self::Committing => "committing",
            Self::Done => "done",
            Self::NeedsReplan => "needs_replan",
            Self::Failed => "failed",
        }
    }

    pub fn from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "planned" => Ok(Self::Planned),
            "prefetched" => Ok(Self::Prefetched),
            "committing" => Ok(Self::Committing),
            "done" => Ok(Self::Done),
            "needs_replan" => Ok(Self::NeedsReplan),
            "failed" => Ok(Self::Failed),
            other => Err(format!("unknown rewind run state: {other}")),
        }
    }

    /// Whether the run has not ended yet. A group has at most one such run.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Planned | Self::Prefetched | Self::Committing)
    }
}

/// Why a rewind ended [`RewindRunState::Failed`]. Every failed run changed
/// nothing, but the person has to act differently on each kind, and the run
/// ends long after the request that started it was answered, so the kind
/// is recorded rather than left to a reply. [`Self::message`] is the one
/// place each kind's wording lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RewindFailureKind {
    /// Historical content the plan needs cannot be obtained: every device
    /// that could hold it said it does not.
    ContentUnavailable,
    /// The content could not all be gathered this time: a device that could
    /// hold it was offline or did not answer, a transfer failed, a holder
    /// refused or was busy. Never a statement that the content is gone.
    Transient,
    /// The folder changed before the first chunk was committed.
    FolderChanged,
    /// The commit path refused the first chunk: this device is no longer a
    /// writer, its own-head cap, a held path, or the group frozen.
    CommitRefused,
    /// The daemon stopped (or the run was dropped) before the first chunk.
    /// No device failed.
    Interrupted,
}

impl RewindFailureKind {
    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::ContentUnavailable => "content_unavailable",
            Self::Transient => "transient",
            Self::FolderChanged => "folder_changed",
            Self::CommitRefused => "commit_refused",
            Self::Interrupted => "interrupted",
        }
    }

    pub fn from_db_str(value: &str) -> Result<Self, String> {
        match value {
            "content_unavailable" => Ok(Self::ContentUnavailable),
            "transient" => Ok(Self::Transient),
            "folder_changed" => Ok(Self::FolderChanged),
            "commit_refused" => Ok(Self::CommitRefused),
            "interrupted" => Ok(Self::Interrupted),
            other => Err(format!("unknown rewind failure kind: {other}")),
        }
    }

    /// What a person is told. `unavailable_files` is the run's
    /// [`RewindRun::unavailable_files`] (used by `ContentUnavailable` only);
    /// `offline_devices` its [`RewindRun::offline_devices`] (used by
    /// `Transient` only).
    pub fn message(self, unavailable_files: u64, offline_devices: &[String]) -> String {
        match self {
            Self::ContentUnavailable => {
                format!("{unavailable_files} files unavailable; rewind cannot start")
            }
            Self::Transient => match offline_devices {
                [] => "Rewind could not be prepared; retry when the required devices are \
                       available."
                    .to_string(),
                [device] => format!(
                    "Rewind could not be prepared: {device} is offline. Retry when it is \
                     available."
                ),
                devices => format!(
                    "Rewind could not be prepared: {} are offline. Retry when they are \
                     available.",
                    devices.join(", ")
                ),
            },
            Self::FolderChanged => {
                "The folder changed; wait for sync to settle, then preview again.".to_string()
            }
            Self::CommitRefused => {
                "This folder cannot be changed from this device right now; resolve that, then \
                 preview again."
                    .to_string()
            }
            Self::Interrupted => {
                "Rewind was interrupted before anything changed; you can run it again.".to_string()
            }
        }
    }
}

/// One rewind execution's journal row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewindRun {
    pub run_id: String,
    pub group_id: String,
    pub target_unix_nanos: i64,
    pub plan_id: RewindPlanId,
    pub state: RewindRunState,
    /// Chunks committed so far. For progress display, and for telling an
    /// interruption that changed something from one that did not; never a
    /// resume position.
    pub chunks_done: u64,
    /// For [`RewindFailureKind::ContentUnavailable`]: how many of the
    /// plan's files cannot be obtained. Zero otherwise.
    pub unavailable_files: u64,
    /// Set exactly when `state` is [`RewindRunState::Failed`].
    pub failure_kind: Option<RewindFailureKind>,
    /// For [`RewindFailureKind::Transient`]: the member devices that were
    /// not connected when the content could not be gathered. Empty
    /// otherwise.
    pub offline_devices: Vec<String>,
    /// How many chunks the run commits in all; set once its content is
    /// prefetched (zero before).
    pub chunks_total: u64,
    /// Paths brought back (created or rolled back) by committed chunks.
    pub restored: u64,
    /// Paths removed by committed chunks.
    pub deleted: u64,
    pub created_at_unix_nanos: i64,
}

impl RewindRun {
    /// What a person is told about the run as it stands. The one place a
    /// run's wording lives, together with [`RewindFailureKind::message`].
    pub fn message(&self) -> String {
        match self.state {
            RewindRunState::Planned => "Gathering the content this rewind needs.".to_string(),
            RewindRunState::Prefetched | RewindRunState::Committing => {
                format!("Rewinding: {} of {} steps done.", self.chunks_done, self.chunks_total)
            }
            RewindRunState::Done => format!(
                "Rewind finished: {} files restored, {} files removed.",
                self.restored, self.deleted
            ),
            RewindRunState::NeedsReplan => {
                "Rewind was interrupted. Review the current state and preview again.".to_string()
            }
            RewindRunState::Failed => match self.failure_kind {
                Some(kind) => kind.message(self.unavailable_files, &self.offline_devices),
                None => "Rewind failed.".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests;
