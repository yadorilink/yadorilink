//! The apply pass of an `online_only` retention rule: it frees the OS copies of the files under
//! the rule, the way a person's "Free up space" does, and records how far it got on the rule.
//!
//! A rule is written `pending` with its generation. A pass claims it (a claim older than the
//! lease is reclaimable, so a pass that died strands nothing), walks the live files under it, and
//! before EACH file re-reads the rule: it acts only while the path is still `online_only` at the
//! generation it claimed. Every file ends as one of three outcomes, persisted as counts on the
//! rule row for the status line:
//!
//! * done: freed, or already without an OS copy;
//! * skipped (deliberate, not an error): unsynced local edits, held or conflicted, open, refused by
//!   the eviction path. Re-armed by a clean-up event or a folder-level Free Up Space, never
//!   silently dropped from the count;
//! * retryable: the host is not connected or the download has not been confirmed yet. The rule
//!   stays `pending` and a later pass retries it.
//!
//! The pass completes `pending(generation, rearm_seq) -> done` with a compare-and-set on both, so
//! a later `keep` then `online_only` is never completed by the older pass, and a download that
//! settles after the pass found nothing present (which re-arms the rule) runs it again.
//!
//! All freeing goes through [`ProviderEvictor`]: the pass selects and counts, the eviction path
//! decides (custody, version, host). Rate limited with a pause between files.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_sqlite::provider::{ItemId, ProviderDeclaration, ProviderRoot};
use yadorilink_sync_sqlite::{ApplyCounts, PendingRule, Rule, RuleClaim};

use crate::daemon_state::DaemonState;
use crate::provider_evict::{ProviderEvictor, RuleHold};
use crate::provider_evidence::{os_copy, OsCopy, ProviderMembership};
use crate::provider_reclaim::Retained;
use crate::sync_error::SyncError;

/// How often the loop looks for pending rules.
pub(crate) const PASS_INTERVAL: Duration = Duration::from_secs(20);
/// How long a claim holds a rule before another pass may take it over.
pub(crate) const CLAIM_LEASE: Duration = Duration::from_secs(10 * 60);
/// The pause between two files of a pass.
pub(crate) const PACE: Duration = Duration::from_millis(25);

/// What the pass needs to know about the machine.
pub(crate) trait ApplyEnvironment: Send + Sync {
    fn now_unix_nanos(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64)
    }
}

/// The real clock.
pub(crate) struct SystemEnvironment;
impl ApplyEnvironment for SystemEnvironment {}

/// How one file's turn came out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileOutcome {
    Done,
    Skipped,
    Retryable,
}

/// What a pass did with one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuleOutcome {
    /// Every file is freed or deliberately skipped, and the rule is `done`.
    Completed(ApplyCounts),
    /// Some files could not be tried yet, or something re-armed the rule: it stays pending.
    Pending(ApplyCounts),
    /// The rule changed or went away while the pass ran: nothing was recorded.
    Superseded,
    /// Another pass holds it, it is not a provider folder's rule, or nobody could claim it.
    NotApplied,
}

pub(crate) struct RetentionApply {
    state: Arc<DaemonState>,
    evictor: Arc<ProviderEvictor>,
    membership: Arc<ProviderMembership>,
    environment: Arc<dyn ApplyEnvironment>,
    pace: Duration,
}

impl RetentionApply {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        evictor: Arc<ProviderEvictor>,
        membership: Arc<ProviderMembership>,
        environment: Arc<dyn ApplyEnvironment>,
    ) -> Self {
        Self { state, evictor, membership, environment, pace: PACE }
    }

    #[cfg(test)]
    pub(crate) fn with_pace(mut self, pace: Duration) -> Self {
        self.pace = pace;
        self
    }

    /// One pass over every pending rule.
    pub(crate) async fn run_pass(&self) -> Vec<(PendingRule, RuleOutcome)> {
        let pending = match self.state.replica_coordinator.retention_rules().pending_rules() {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(%error, "retention rules could not be listed for the apply pass");
                return Vec::new();
            }
        };
        let mut outcomes = Vec::new();
        for rule in pending {
            let outcome = self.apply_rule(&rule).await;
            outcomes.push((rule, outcome));
        }
        outcomes
    }

    /// Applies one rule as read at `rule.generation`.
    pub(crate) async fn apply_rule(&self, rule: &PendingRule) -> RuleOutcome {
        let coordinator = &self.state.replica_coordinator;
        let rules = coordinator.retention_rules();
        // Only a provider folder's copies are the OS's to drop.
        let root = match coordinator.provider_repository().declaration_for_group(&rule.group_id) {
            Ok(ProviderDeclaration::Provider(root)) => root,
            _ => return RuleOutcome::NotApplied,
        };
        let claim = match rules.claim_rule(
            &rule.group_id,
            &rule.path,
            rule.generation,
            self.environment.now_unix_nanos(),
            CLAIM_LEASE,
        ) {
            Ok(Some(claim)) => claim,
            Ok(None) => return RuleOutcome::NotApplied,
            Err(error) => {
                tracing::warn!(%error, group_id = %rule.group_id, path = %rule.path, "could not claim a retention rule");
                return RuleOutcome::NotApplied;
            }
        };
        let files = match self.files_under(rule) {
            Ok(files) => files,
            Err(error) => {
                // Listing failed: nothing was tried; the rule stays pending.
                tracing::warn!(%error, group_id = %rule.group_id, path = %rule.path, "could not list the files of a retention rule");
                let counts = ApplyCounts { done: 0, skipped: 0, retryable: 1 };
                let _ = rules.release_rule(&rule.group_id, &rule.path, claim, counts);
                return RuleOutcome::Pending(counts);
            }
        };
        let mut counts = ApplyCounts::default();
        for path in files {
            if !self.still_claimed(rule, claim) {
                return RuleOutcome::Superseded;
            }
            // A kept exception (or a nearer rule) under this one is not this rule's to free.
            let Ok(set) = rules.rules(&rule.group_id) else {
                counts.retryable += 1;
                continue;
            };
            if set.nearest(&path) != Some((rule.path.as_str(), Rule::OnlineOnly)) {
                continue;
            }
            match self.free_one(&root, &rule.group_id, &path, &rule.path, rule.generation).await {
                FileOutcome::Done => counts.done += 1,
                FileOutcome::Skipped => counts.skipped += 1,
                FileOutcome::Retryable => counts.retryable += 1,
            }
            if !self.pace.is_zero() {
                tokio::time::sleep(self.pace).await;
            }
        }
        if !self.still_claimed(rule, claim) {
            return RuleOutcome::Superseded;
        }
        if counts.retryable > 0 {
            let _ = rules.release_rule(&rule.group_id, &rule.path, claim, counts);
            return RuleOutcome::Pending(counts);
        }
        match rules.complete_rule(&rule.group_id, &rule.path, claim, counts) {
            Ok(true) => RuleOutcome::Completed(counts),
            // Re-armed during the pass (or changed): the counts are recorded, it runs again.
            Ok(false) => RuleOutcome::Pending(counts),
            Err(error) => {
                tracing::warn!(%error, group_id = %rule.group_id, path = %rule.path, "could not finish a retention rule");
                RuleOutcome::Pending(counts)
            }
        }
    }

    /// The rule is still the one this pass claimed: online-only, at its generation.
    fn still_claimed(&self, rule: &PendingRule, claim: RuleClaim) -> bool {
        matches!(
            self.state.replica_coordinator.retention_rules().rule_row(&rule.group_id, &rule.path),
            Ok(Some(row)) if row.rule == Rule::OnlineOnly && row.generation == claim.generation
        )
    }

    /// The live files at and beneath the rule's path.
    fn files_under(&self, rule: &PendingRule) -> Result<Vec<String>, SyncError> {
        let index = self.state.replica_coordinator.file_index_repository();
        let mut files = index.list_live_files_under(&rule.group_id, &rule.path)?;
        // A rule on a single file names the file itself.
        if !rule.path.is_empty() {
            let record = self
                .state
                .replica_coordinator
                .sqlite()
                .dag_get_current_version_record(&rule.group_id, &rule.path)?;
            if record.is_some_and(|record| {
                !record.deleted
                    && record.record_kind == yadorilink_replica_domain::file::RecordKind::File
            }) {
                files.insert(0, rule.path.clone());
            }
        }
        Ok(files)
    }

    async fn free_one(
        &self,
        root: &ProviderRoot,
        group_id: &str,
        path: &str,
        rule_path: &str,
        generation: i64,
    ) -> FileOutcome {
        let coordinator = &self.state.replica_coordinator;
        let repo = coordinator.provider_repository();
        let item: ItemId = match repo.item_for_path(&root.root_id, path) {
            Ok(Some(item)) => item,
            // No item yet: there is no OS copy to free.
            Ok(None) => return FileOutcome::Done,
            Err(_) => return FileOutcome::Retryable,
        };
        match os_copy(coordinator, &self.membership, &root.root_id, &item) {
            // Nothing on the OS side to drop.
            OsCopy::Absent => return FileOutcome::Done,
            OsCopy::Current | OsCopy::Windows | OsCopy::Unconfirmed => {}
        }
        let version = match repo.current_version_hash(&root.root_id, &item) {
            Ok(Some(version)) => version,
            Ok(None) => return FileOutcome::Done,
            Err(_) => return FileOutcome::Retryable,
        };
        let hold = RuleHold { rule_path, generation };
        match self.evictor.evict_applying(group_id, path, Some((item, version)), Some(hold)).await {
            Ok(done) if done.dehydrated => FileOutcome::Done,
            Ok(done) => match done.retained {
                // The OS holds no copy any more: nothing was left to free here.
                None
                | Some(
                    Retained::NotDownloaded
                    | Retained::NothingFreed
                    | Retained::HeldAsHistory
                    | Retained::FullReplica
                    | Retained::CustodyUnsupported,
                ) => FileOutcome::Done,
                // The download has only just finished: look again later.
                Some(Retained::NotConfirmed) => FileOutcome::Retryable,
                // Unsynced edits, held or conflicted, open, a newer version, no lease: left as
                // it is, on purpose.
                Some(_) => FileOutcome::Skipped,
            },
            Err(SyncError::EvictionRejected(reason)) if reason.contains("not connected") => {
                FileOutcome::Retryable
            }
            Err(SyncError::EvictionRejected(_)) => FileOutcome::Skipped,
            Err(_) => FileOutcome::Retryable,
        }
    }
}

/// The background loop.
pub(crate) async fn run(apply: Arc<RetentionApply>) {
    let mut interval = tokio::time::interval(PASS_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        apply.run_pass().await;
    }
}

#[cfg(test)]
mod tests;
