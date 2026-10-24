//! `ReplacementConfirmJob` -- finishes a start over whose replacement the service called
//! unconfirmed (`replacement-unconfirmed.json` in the state directory, see
//! `yadorilink_local_storage::replacement_unconfirmed`).
//!
//! The service ends `replacement-unconfirmed` only when the NEW device calls
//! `POST /devices/supersessions/:oldDeviceId/confirm`. It checks what it can see (the new device is
//! an active eager member of every group the old device solely covered); that the data behind the
//! membership is really here is this device's claim by calling, so the call is made only once each
//! such group has been proven locally complete (see [`group_is_synced`]). Fail closed throughout:
//! anything unclear is "not yet", and nothing here deletes a file.
//!
//! One pass per tick, no waiting inside a pass:
//!
//! * no record: ask the service (at startup, then hourly) whether it still lists an unconfirmed
//!   replacement whose new device is this one, and re-create the record from it (see
//!   `recover_lost_record`); otherwise nothing to do;
//! * a record for another device id than this daemon's own: left alone (a leftover of an identity
//!   this daemon is not);
//! * a provider folder (its bytes live with the OS) is judged by the provider side's own
//!   evidence instead of a disk read: Eager, running, and the root's Eager scan complete (every
//!   wanted file present on the OS by the daemon's handoff ledger plus the host app's report, see
//!   `provider_status::root_content_complete`); anything else waits;
//! * a group that is not linked here, whose link has not finished startup, or not yet fully materialized as an eager replica: wait;
//! * a group whose files are not all verified on disk against the index (see [`content_check`]):
//!   wait. The verification is incremental across ticks and its progress is the pass's `Waiting`
//!   reason. A completed verification never authorizes a confirm: every confirm call is preceded
//!   by a fresh stat check of every entry (re-hashing what changed), so a file damaged after the
//!   verification (while the service answered 409, say) stops the confirm;
//! * all groups complete but the person has not acknowledged that changes made after the backup
//!   may be missing: wait ([`Outcome::AwaitingAcknowledgement`]). Nothing this device holds can
//!   prove those groups complete (the index is the restored one, and the old device was by
//!   definition the only complete replica), so the confirm is never automatic;
//! * all groups complete and acknowledged: confirm, carrying the acknowledgement. `409` means the service does not see the eager membership yet
//!   (wait), `401`/`403` means the sign-in is not good enough (the person is told through the
//!   sign-in marker next to the record), anything else, a network failure included, is retried
//!   next tick. A `200` is the only success, and it is idempotent, so a confirm that landed before
//!   a crash simply answers again;
//! * the record (and the marker) are removed only after that `200`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use yadorilink_local_storage::replacement_unconfirmed::{self, Record};

use crate::coordination_client::{CoordinationCallError, SendAuthorized};
use crate::daemon_state::DaemonState;
use crate::queries::link_status::{LinkStatusReadPort, LinkStatusView, LocalStorageState};

mod content_check;
use content_check::{ExpectedEntry, GroupState, Step};

/// How often a pass runs. The pass is a single `exists()` while no record is pending.
pub(crate) const TICK: Duration = Duration::from_secs(60);

/// How the service answered a confirm call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmAnswer {
    /// `200` with the supersession reported healthy.
    Confirmed,
    /// `409`: the service does not (yet) see this device as an active eager member of every group.
    NotYetEagerMember,
    /// `401`/`403`, or no credential could be minted: a fresh sign-in is needed.
    SignInRequired,
    /// Anything else, including an unreachable service. Try again next tick.
    Retry,
}

/// How often a pass without a record asks the service whether it still lists an unconfirmed
/// replacement for this device (the record may have been lost). Once at startup, then this often.
pub(crate) const RECOVERY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// One entry of `GET /devices/supersessions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Supersession {
    pub(crate) old_device_id: String,
    pub(crate) new_device_id: String,
    /// `"healthy"` or `"replacement-unconfirmed"`.
    pub(crate) protection: String,
    pub(crate) unconfirmed_group_ids: Vec<String>,
}

/// How the service answered the supersessions listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SupersessionsAnswer {
    Listed(Vec<Supersession>),
    /// `401`/`403`, or no credential could be minted.
    SignInRequired,
    /// Not signed in to a service at all, or anything else (an unreachable service included).
    Unavailable,
}

/// What one pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    NoRecord,
    /// There was no record, but the service lists an unconfirmed replacement of this device; the
    /// record was re-created from it and the next pass confirms it.
    Recovered,
    /// The record names another device than this daemon's own, or could not be read.
    RecordNotUsable,
    /// Not every group is complete here yet (the reason names the first one that is not).
    Waiting(String),
    /// Every group is complete here, but completeness against the latest state cannot be proven;
    /// the confirm waits for the person's acknowledgement.
    AwaitingAcknowledgement,
    /// Every group is complete but the service does not see the eager membership yet.
    WaitingForMembership,
    SignInRequired,
    /// The confirm failed for a reason that may pass.
    RetryLater,
    /// Confirmed, and the record removed.
    Confirmed,
    /// Confirmed, but the record could not be removed; the next pass confirms again (idempotent).
    ConfirmedRecordKept,
}

#[cfg(test)]
type RefreshHook = Box<dyn Fn(&str) + Send + Sync>;

type EntryLoader = Box<dyn FnOnce() -> Result<Vec<ExpectedEntry>, String> + Send>;

/// Everything a pass touches outside the state directory.
pub(crate) trait ConfirmPorts: Send + Sync {
    fn own_device_id(&self) -> String;
    fn links(&self) -> Result<Vec<LinkStatusView>, String>;
    /// Whether the group's link finished its startup (repair and disk scan) successfully. Until
    /// then the index's bookkeeping may not match the disk.
    fn group_startup_ready(&self, group_id: &str) -> bool;
    /// Whether the provider folder `root_id` holds all its content on the OS, by the provider
    /// side's own evidence; the error says what is missing.
    fn provider_content_complete(&self, root_id: &str) -> Result<(), String>;
    /// A reader of the group's current, non-deleted index entries, sorted by path: what the disk
    /// must hold. It is run on a blocking thread.
    fn entry_loader(&self, group_id: &str) -> EntryLoader;
    async fn confirm(&self, old_device_id: &str) -> ConfirmAnswer;
    async fn supersessions(&self) -> SupersessionsAnswer;
}

pub(crate) struct ReplacementConfirmJob<P: ConfirmPorts> {
    ports: P,
    dir: PathBuf,
    /// Where each group's on-disk verification stands. In memory only: a restart verifies again.
    verification: Mutex<HashMap<String, GroupState>>,
    byte_budget: u64,
    entry_budget: usize,
    recovery_interval: Duration,
    /// When the service was last asked for the supersessions without a record. In memory only, so
    /// a restart asks again.
    last_recovery_check: Mutex<Option<Instant>>,
    /// Test seam: runs after a group's pre-confirm refresh finished, with the group id.
    #[cfg(test)]
    after_refresh: Mutex<Option<RefreshHook>>,
}

impl<P: ConfirmPorts> ReplacementConfirmJob<P> {
    pub(crate) fn new(ports: P, dir: PathBuf) -> Self {
        Self {
            ports,
            dir,
            verification: Mutex::new(HashMap::new()),
            byte_budget: content_check::BYTE_BUDGET_PER_PASS,
            entry_budget: content_check::ENTRY_BUDGET_PER_PASS,
            recovery_interval: RECOVERY_INTERVAL,
            last_recovery_check: Mutex::new(None),
            #[cfg(test)]
            after_refresh: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_recovery_interval(mut self, interval: Duration) -> Self {
        self.recovery_interval = interval;
        self
    }

    #[cfg(test)]
    fn with_budgets(mut self, byte_budget: u64, entry_budget: usize) -> Self {
        self.byte_budget = byte_budget;
        self.entry_budget = entry_budget;
        self
    }

    /// One pass, then what status shows about it: the reason the confirm is still waiting.
    pub(crate) async fn run_once(&self) -> Outcome {
        let outcome = self.pass().await;
        self.publish_wait_reason(&outcome);
        outcome
    }

    /// Keeps the wait reason beside the record in step with the pass, and logs it when it
    /// changes. Outcomes whose cause status already names by another code (sign-in, the
    /// acknowledgement) or that end the wait carry no reason.
    fn publish_wait_reason(&self, outcome: &Outcome) {
        let reason: Option<String> = match outcome {
            Outcome::Waiting(reason) => Some(reason.clone()),
            Outcome::WaitingForMembership => Some(
                "the service does not yet list this device as an active full-copy member of every \
                 folder group; retrying"
                    .to_owned(),
            ),
            Outcome::RetryLater => Some(
                "the service did not give a usable answer to the confirmation; retrying".to_owned(),
            ),
            Outcome::ConfirmedRecordKept => {
                Some("confirmed, but the record could not be removed; retrying".to_owned())
            }
            Outcome::RecordNotUsable => {
                Some("the record names another device or cannot be read".to_owned())
            }
            Outcome::NoRecord
            | Outcome::Recovered
            | Outcome::AwaitingAcknowledgement
            | Outcome::SignInRequired
            | Outcome::Confirmed => None,
        };
        match replacement_unconfirmed::set_waiting_reason(&self.dir, reason.as_deref()) {
            Ok(true) => {
                if let Some(reason) = &reason {
                    tracing::info!(%reason, "the device replacement is waiting");
                }
            }
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, "could not record why the device replacement is waiting");
            }
        }
    }

    async fn pass(&self) -> Outcome {
        if !replacement_unconfirmed::pending(&self.dir) {
            return self.recover_lost_record().await;
        }
        let record = match replacement_unconfirmed::read(&self.dir) {
            Ok(Some(record)) => record,
            Ok(None) => return Outcome::NoRecord,
            Err(error) => {
                tracing::warn!(%error, "the replacement record cannot be read; not confirming");
                return Outcome::RecordNotUsable;
            }
        };
        let own = self.ports.own_device_id();
        if own.is_empty() || record.new_device_id != own {
            return Outcome::RecordNotUsable;
        }
        if let Some(reason) = self.first_group_not_synced(&record).await {
            return Outcome::Waiting(reason);
        }
        if !record.acknowledged_possible_loss {
            return Outcome::AwaitingAcknowledgement;
        }
        match self.ports.confirm(&record.old_device_id).await {
            ConfirmAnswer::Confirmed => match replacement_unconfirmed::clear(&self.dir) {
                Ok(()) => {
                    self.verification.lock().unwrap().clear();
                    // Another unconfirmed replacement may be listed: look again at once.
                    *self.last_recovery_check.lock().unwrap() = None;
                    Outcome::Confirmed
                }
                Err(error) => {
                    tracing::warn!(%error, "confirmed, but the replacement record could not be removed");
                    Outcome::ConfirmedRecordKept
                }
            },
            ConfirmAnswer::NotYetEagerMember => {
                self.mark_sign_in(false);
                Outcome::WaitingForMembership
            }
            ConfirmAnswer::SignInRequired => {
                self.mark_sign_in(true);
                Outcome::SignInRequired
            }
            // Inconclusive (network, server error): says nothing about the sign-in, so a request
            // for one that is outstanding stays until an authenticated answer replaces it.
            ConfirmAnswer::Retry => Outcome::RetryLater,
        }
    }

    /// Without a record: asks the service (at startup, then hourly) whether it still lists an
    /// unconfirmed replacement whose NEW device is this one, and re-creates the record from it.
    /// Only that: a supersession of another device, or one already healthy, is never touched, and
    /// an existing record is never overwritten (this is not reached then). The service's listing
    /// is the source of truth only for the obligation; whether the data is here is still decided
    /// by the confirm checks. A refused sign-in cannot show an obligation and has no record to
    /// carry the sign-in attention, so it is retried at the next interval.
    async fn recover_lost_record(&self) -> Outcome {
        let own = self.ports.own_device_id();
        if own.is_empty() {
            return Outcome::NoRecord;
        }
        {
            let last = self.last_recovery_check.lock().unwrap();
            if last.is_some_and(|at| at.elapsed() < self.recovery_interval) {
                return Outcome::NoRecord;
            }
        }
        let listed = match self.ports.supersessions().await {
            SupersessionsAnswer::Listed(listed) => listed,
            SupersessionsAnswer::SignInRequired => {
                *self.last_recovery_check.lock().unwrap() = Some(Instant::now());
                return Outcome::NoRecord;
            }
            // Not signed in or unreachable: ask again next tick.
            SupersessionsAnswer::Unavailable => return Outcome::NoRecord,
        };
        *self.last_recovery_check.lock().unwrap() = Some(Instant::now());
        let Some(found) = listed
            .into_iter()
            .find(|s| s.new_device_id == own && s.protection == "replacement-unconfirmed")
        else {
            return Outcome::NoRecord;
        };
        let record = Record {
            old_device_id: found.old_device_id,
            new_device_id: found.new_device_id,
            unconfirmed_group_ids: found.unconfirmed_group_ids,
            // A recovered record is as unproven as the original: the person acknowledges again.
            acknowledged_possible_loss: false,
        };
        match replacement_unconfirmed::write(&self.dir, &record) {
            Ok(()) => {
                tracing::info!("re-created the lost replacement record from the service");
                Outcome::Recovered
            }
            Err(error) => {
                tracing::warn!(%error, "could not re-create the replacement record");
                // Ask again next tick.
                *self.last_recovery_check.lock().unwrap() = None;
                Outcome::NoRecord
            }
        }
    }

    /// Why the record cannot be confirmed yet, or `None` when every group is complete AND its
    /// content was just re-checked on disk. The re-check runs on every call that returns `None`,
    /// so a verification that finished earlier never authorizes a confirm by itself.
    async fn first_group_not_synced(&self, record: &Record) -> Option<String> {
        let views = match self.ports.links() {
            Ok(views) => views,
            Err(error) => return Some(format!("link state unreadable: {error}")),
        };
        let mut targets = Vec::new();
        for group_id in &record.unconfirmed_group_ids {
            let Some(view) = views.iter().find(|view| &view.group_id == group_id) else {
                return Some(format!("{group_id}: not linked on this device"));
            };
            if let Some((root_id, _)) = &view.provider {
                // A provider folder's bytes live with the OS, not under a path this daemon can
                // read, so neither the startup gate nor the on-disk verification applies. The
                // provider side's own evidence of the OS copy stands in for them.
                if let Err(why) = provider_group_is_synced(view) {
                    return Some(format!("{group_id}: {why}"));
                }
                if let Err(why) = self.ports.provider_content_complete(root_id) {
                    return Some(format!("{group_id}: {why}"));
                }
                continue;
            }
            if !self.ports.group_startup_ready(group_id) {
                self.verification.lock().unwrap().remove(group_id);
                return Some(format!("{group_id}: startup has not finished"));
            }
            // A transient failure (a transfer in flight, say) leaves the progress alone: the
            // pre-confirm refresh re-checks everything anyway.
            if let Err(why) = group_is_synced(view) {
                return Some(format!("{group_id}: {why}"));
            }
            targets.push((group_id.clone(), PathBuf::from(&view.local_path)));
        }
        self.verify_content(&targets).await
    }

    /// One bounded pass of the on-disk verification over all groups (the budget is shared, so
    /// every unfinished group advances each pass), then, when all are complete, the fresh check.
    async fn verify_content(&self, targets: &[(String, PathBuf)]) -> Option<String> {
        let unfinished = targets
            .iter()
            .filter(|(id, _)| self.verification.lock().unwrap().get(id).is_none_or(|s| !s.done))
            .count();
        let share = unfinished.max(1);
        let bytes = (self.byte_budget / share as u64).max(1);
        let entries = (self.entry_budget / share).max(1);
        let mut first_message = None;
        for (group_id, root) in targets {
            let taken = self.verification.lock().unwrap().remove(group_id);
            let mut state = match taken {
                None => match self.load(group_id).await {
                    Ok(entries) => GroupState::fresh(entries),
                    Err(message) => {
                        first_message.get_or_insert(format!("{group_id}: {message}"));
                        continue;
                    }
                },
                Some(mut state) => {
                    if state.resume_at.is_some() {
                        match self.load(group_id).await {
                            Ok(entries) => state.reload(entries),
                            Err(message) => {
                                self.verification.lock().unwrap().insert(group_id.clone(), state);
                                first_message.get_or_insert(format!("{group_id}: {message}"));
                                continue;
                            }
                        }
                    }
                    state
                }
            };
            if !state.done {
                let root = root.clone();
                let joined = tokio::task::spawn_blocking(move || {
                    let step = content_check::verify_step(&root, &mut state, bytes, entries);
                    (state, step)
                })
                .await;
                let Ok((returned, step)) = joined else {
                    first_message
                        .get_or_insert(format!("{group_id}: the verification could not run"));
                    continue;
                };
                state = returned;
                if let Some(message) = Self::note_step(group_id, &mut state, step) {
                    first_message.get_or_insert(message);
                }
            }
            self.verification.lock().unwrap().insert(group_id.clone(), state);
        }
        if first_message.is_some() {
            return first_message;
        }
        // Every group verified. The fresh check, immediately before the confirm call.
        for (group_id, root) in targets {
            let Some(mut state) = self.verification.lock().unwrap().remove(group_id) else {
                return Some(format!("{group_id}: not verified"));
            };
            // The index may have changed since the snapshot: one read, and a reload (which keeps
            // every unchanged entry's fingerprint) when it did.
            match self.load(group_id).await {
                Ok(entries) if entries != state.entries => {
                    state.resume_at = Some(String::new());
                    state.reload(entries);
                    self.verification.lock().unwrap().insert(group_id.clone(), state);
                    return Some(format!("{group_id}: the index changed; verifying again"));
                }
                Ok(_) => {}
                Err(message) => {
                    self.verification.lock().unwrap().insert(group_id.clone(), state);
                    return Some(format!("{group_id}: {message}"));
                }
            }
            let root = root.clone();
            let joined = tokio::task::spawn_blocking(move || {
                let step = content_check::refresh(&root, &mut state);
                (state, step)
            })
            .await;
            let Ok((mut state, step)) = joined else {
                return Some(format!("{group_id}: the verification could not run"));
            };
            let message = match step {
                Step::Complete => None,
                other => Self::note_step(group_id, &mut state, other),
            };
            self.verification.lock().unwrap().insert(group_id.clone(), state);
            if message.is_some() {
                return message;
            }
            #[cfg(test)]
            if let Some(hook) = self.after_refresh.lock().unwrap().as_ref() {
                hook(group_id);
            }
        }
        // The refresh above may re-hash a later group for a long time, which would widen the
        // window of the groups checked before it. Close it: one more stat-only look at every
        // group, which is short and never hashes. Anything that moved meanwhile is "not yet" (the
        // next pass re-hashes it); nothing is skipped and nothing here authorizes by itself.
        for (group_id, root) in targets {
            let Some(state) = self.verification.lock().unwrap().remove(group_id) else {
                return Some(format!("{group_id}: not verified"));
            };
            let root = root.clone();
            let joined = tokio::task::spawn_blocking(move || {
                let step = content_check::still_unchanged(&root, &state);
                (state, step)
            })
            .await;
            let Ok((mut state, step)) = joined else {
                return Some(format!("{group_id}: the verification could not run"));
            };
            let message = match step {
                Step::Complete => None,
                other => Self::note_step(group_id, &mut state, other),
            };
            self.verification.lock().unwrap().insert(group_id.clone(), state);
            if message.is_some() {
                return message;
            }
        }
        None
    }

    async fn load(&self, group_id: &str) -> Result<Vec<ExpectedEntry>, String> {
        let loader = self.ports.entry_loader(group_id);
        match tokio::task::spawn_blocking(loader).await {
            Ok(Ok(entries)) => Ok(entries),
            Ok(Err(error)) => Err(format!("the index cannot be read for verification: {error}")),
            Err(error) => Err(format!("the verification could not run: {error}")),
        }
    }

    /// Records a step's outcome on the state; the message to report while the group is not done.
    fn note_step(group_id: &str, state: &mut GroupState, step: Step) -> Option<String> {
        match step {
            Step::Complete => None,
            Step::Progress { next } => {
                tracing::info!(
                    group_id,
                    next,
                    total = state.entries.len(),
                    "replacement content verification in progress"
                );
                Some(format!(
                    "{group_id}: verifying the files on disk ({next} of {} checked)",
                    state.entries.len()
                ))
            }
            Step::Failed { index, why } => {
                tracing::warn!(group_id, %why, "replacement content verification failed");
                // Progress is kept: the next pass takes a fresh snapshot and resumes here.
                state.done = false;
                state.next = index;
                state.resume_at = Some(state.entries[index].path.clone());
                Some(format!("{group_id}: a file on disk does not match the index ({why})"))
            }
        }
    }

    fn mark_sign_in(&self, required: bool) {
        if let Err(error) = replacement_unconfirmed::set_sign_in_required(&self.dir, required) {
            tracing::warn!(%error, "could not update the sign-in marker of the replacement record");
        }
    }
}

/// Whether the folder group is fully here, as an eager replica that is running.
///
/// This is the minimal predicate; no existing one says "caught up" for the case at hand. The
/// retained replica database of a start over already holds the group's whole index, so what can
/// still be missing is the content on disk and a link that is running. It is built only from state
/// the status already reports (`FullCopy` is "eager and every current file recorded hydrated"):
///
/// * the link is a folder (a provider folder is judged by [`provider_group_is_synced`] and the
///   provider's own evidence instead);
/// * the policy is eager and `FullCopy`: no placeholder, hydrating or evicting file;
/// * nothing is requested or in flight, and nothing is waiting on a conflict or an unreadable
///   file;
/// * the link runs: not paused, not degraded, not ambiguous, volume known, policy not stale.
///
/// It rests on the index's bookkeeping, not on a disk read (see the note on `LocalStorageState`),
/// so the confirm also waits for [`content_check`], which reads the disk;
/// drift between the two is owned by the startup repair and disk-reconcile scan, which is why a
/// group counts only once its link's startup gate is `Ready`.
///
/// Peer agreement is deliberately not required: the old device is gone, so there may be no peer to
/// agree with, and the claim is about this device's own copy.
pub(crate) fn group_is_synced(view: &LinkStatusView) -> Result<(), &'static str> {
    if view.provider.is_some() {
        return Err("a provider folder cannot be proven complete here");
    }
    if view.materialization_policy != "eager" {
        return Err("not an eager replica yet");
    }
    if view.local_storage_state != LocalStorageState::FullCopy {
        return Err("files are not all materialized yet");
    }
    if view.placeholder_count != 0 || view.hydrating_count != 0 {
        return Err("files are still placeholders or downloading");
    }
    if view.requested_content_count != 0 || view.transfer.is_some() {
        return Err("a transfer is in progress");
    }
    if view.paused {
        return Err("the folder is paused");
    }
    if view.degraded.is_some() {
        return Err("the folder is degraded");
    }
    // The list holds every live folder registered for the group, this one included: a group
    // linked once has exactly one entry, and only a second one is the ambiguous state.
    if view.ambiguous_local_paths.len() > 1 {
        return Err("the group is linked twice");
    }
    if view.capture_volume_changed || view.capture_volume_unconfirmed {
        return Err("the folder's volume is not confirmed");
    }
    if view.policy_stale {
        return Err("the group's membership is not current");
    }
    if view.conflicts_pending != 0 {
        return Err("a conflict is unresolved");
    }
    if !view.unreadable_files.is_empty() {
        return Err("a file cannot be read");
    }
    Ok(())
}

/// The link-level half of "a provider folder is synced": the same running-link conditions as
/// [`group_is_synced`] where they apply to a provider root. The folder-only parts (index rows
/// hydrated, volume, startup gate, a path to read) do not exist for a provider root; its content
/// is judged by the provider's own evidence instead (`ConfirmPorts::provider_content_complete`).
pub(crate) fn provider_group_is_synced(view: &LinkStatusView) -> Result<(), &'static str> {
    if view.provider.is_none() {
        return Err("not a provider folder");
    }
    if view.materialization_policy != "eager" {
        return Err("the provider folder is not kept downloaded (Eager) on this device");
    }
    if view.hydrating_count != 0 || view.requested_content_count != 0 || view.transfer.is_some() {
        return Err("a transfer is in progress");
    }
    if view.paused {
        return Err("the folder is paused");
    }
    if view.degraded.is_some() {
        return Err("the folder is degraded");
    }
    if view.policy_stale {
        return Err("the group's membership is not current");
    }
    if view.conflicts_pending != 0 {
        return Err("a conflict is unresolved");
    }
    if !view.unreadable_files.is_empty() {
        return Err("a file cannot be read");
    }
    if !view.held_files.is_empty() {
        return Err("some files are held back");
    }
    Ok(())
}

/// The real machine: the daemon's link state and the coordination service.
pub(crate) struct DaemonConfirmPorts {
    state: Arc<DaemonState>,
}

impl DaemonConfirmPorts {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl ConfirmPorts for DaemonConfirmPorts {
    fn own_device_id(&self) -> String {
        self.state.device_id.clone()
    }

    fn links(&self) -> Result<Vec<LinkStatusView>, String> {
        crate::adapters::query::link_status::DaemonLinkStatusReader::new(self.state.clone())
            .list_links()
            .map_err(|error| error.to_string())
    }

    fn group_startup_ready(&self, group_id: &str) -> bool {
        self.state.replica_coordinator.startup_readiness().group_startup_ready(group_id)
    }

    fn provider_content_complete(&self, root_id: &str) -> Result<(), String> {
        self.state.provider_content_complete(root_id)
    }

    fn entry_loader(&self, group_id: &str) -> EntryLoader {
        let state = self.state.clone();
        let group_id = group_id.to_owned();
        Box::new(move || {
            let entries = state
                .replica_coordinator
                .file_index_repository()
                .list_current_entries(&group_id)
                .map_err(|e| e.to_string())?;
            Ok(entries
                .into_iter()
                .map(|e| ExpectedEntry {
                    path: e.path,
                    kind: e.kind,
                    blocks: e.blocks,
                    symlink_target: e.symlink_target,
                })
                .collect())
        })
    }

    async fn confirm(&self, old_device_id: &str) -> ConfirmAnswer {
        let Some(config) = self.state.coordination_client_config() else {
            return ConfirmAnswer::Retry;
        };
        confirm_supersession(&config.addr, &config.auth, old_device_id).await
    }

    async fn supersessions(&self) -> SupersessionsAnswer {
        let Some(config) = self.state.coordination_client_config() else {
            return SupersessionsAnswer::Unavailable;
        };
        fetch_supersessions(&config.addr, &config.auth).await
    }
}

/// `GET /devices/supersessions`, as this (the replacement) device.
pub(crate) async fn fetch_supersessions(
    addr: &str,
    auth: &yadorilink_fapi_client::CoordinationAuth,
) -> SupersessionsAnswer {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Entry {
        old_device_id: String,
        new_device_id: String,
        protection: String,
        #[serde(default)]
        unconfirmed_group_ids: Vec<String>,
    }
    #[derive(serde::Deserialize)]
    struct Body {
        supersessions: Vec<Entry>,
    }
    let url = format!("{addr}/devices/supersessions");
    let response = match reqwest::Client::new().get(&url).send_authorized(auth).await {
        Ok(response) => response,
        Err(CoordinationCallError::Unauthenticated(_)) => {
            return SupersessionsAnswer::SignInRequired
        }
        Err(error) => {
            tracing::debug!(%error, "listing the supersessions failed; will retry");
            return SupersessionsAnswer::Unavailable;
        }
    };
    let status = response.status();
    if status.is_success() {
        return match response.json::<Body>().await {
            Ok(body) => SupersessionsAnswer::Listed(
                body.supersessions
                    .into_iter()
                    .map(|e| Supersession {
                        old_device_id: e.old_device_id,
                        new_device_id: e.new_device_id,
                        protection: e.protection,
                        unconfirmed_group_ids: e.unconfirmed_group_ids,
                    })
                    .collect(),
            ),
            Err(_) => SupersessionsAnswer::Unavailable,
        };
    }
    match status.as_u16() {
        401 | 403 => SupersessionsAnswer::SignInRequired,
        _ => SupersessionsAnswer::Unavailable,
    }
}

/// `POST /devices/supersessions/:oldDeviceId/confirm`, as this (the replacement) device. The body
/// carries `acknowledgedPossibleLoss`: this is only called after the person acknowledged it, and
/// the service refuses a confirm without it.
pub(crate) async fn confirm_supersession(
    addr: &str,
    auth: &yadorilink_fapi_client::CoordinationAuth,
    old_device_id: &str,
) -> ConfirmAnswer {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Confirmed {
        protection: String,
        #[serde(default)]
        unconfirmed_group_ids: Vec<String>,
    }
    let url = format!("{addr}/devices/supersessions/{old_device_id}/confirm");
    let response = match reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "acknowledgedPossibleLoss": true }))
        .send_authorized(auth)
        .await
    {
        Ok(response) => response,
        Err(CoordinationCallError::Unauthenticated(_)) => return ConfirmAnswer::SignInRequired,
        Err(error) => {
            tracing::debug!(%error, "confirming the replacement failed; will retry");
            return ConfirmAnswer::Retry;
        }
    };
    let status = response.status();
    if status.is_success() {
        // Only an explicit healthy answer counts; anything else keeps the record.
        return match response.json::<Confirmed>().await {
            Ok(body) if body.protection == "healthy" && body.unconfirmed_group_ids.is_empty() => {
                ConfirmAnswer::Confirmed
            }
            _ => ConfirmAnswer::Retry,
        };
    }
    match status.as_u16() {
        409 => ConfirmAnswer::NotYetEagerMember,
        401 | 403 => ConfirmAnswer::SignInRequired,
        _ => ConfirmAnswer::Retry,
    }
}

impl ReplacementConfirmJob<DaemonConfirmPorts> {
    pub(crate) fn for_daemon(state: Arc<DaemonState>) -> Self {
        let dir = state.config_dir().to_path_buf();
        Self::new(DaemonConfirmPorts::new(state), dir)
    }
}

#[cfg(test)]
mod tests;

/// How often the account's replaced-device list is refreshed, whatever else is pending.
pub(crate) const SUPERSESSION_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// One refresh: asks the service for the supersessions and applies them, so peers refuse every
/// replaced device (`DaemonState::apply_supersessions`). Independent of any confirmation record.
pub(crate) async fn refresh_superseded_devices(state: &Arc<DaemonState>) {
    let Some(config) = state.coordination_client_config() else { return };
    if let SupersessionsAnswer::Listed(listed) =
        fetch_supersessions(&config.addr, &config.auth).await
    {
        state.apply_supersessions(
            listed.into_iter().map(|s| (s.old_device_id, s.new_device_id)).collect(),
        );
    }
}
