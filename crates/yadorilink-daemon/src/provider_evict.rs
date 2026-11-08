//! Freeing the local copy of a file in a provider folder on request (`yadorilink evict <path>`).
//!
//! The operating system owns what a provider folder holds locally; the daemon asks the host to
//! drop its copy, and then frees its own cached blocks of the version, which is what returns real
//! disk space. The first is safe on its own (the daemon keeps the blocks, so the next open is a
//! local hand-over); the second needs a full replica's durable custody lease on exactly this
//! version, taken BEFORE the OS drops anything and checked again before any block is removed
//! (see [`crate::provider_reclaim`]). Without that lease the OS copy is still dropped and the
//! answer says why the blocks stayed.
//!
//! The host refuses to dehydrate a file the user has changed and not yet shared (the placeholder
//! is no longer in sync), so a local edit is never lost by this path.

use std::sync::{Arc, OnceLock};

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::provider::{ItemId, ProviderDeclaration};

use crate::application::ports::BoxFuture;
use crate::daemon_state::DaemonState;
use crate::provider_evidence::{os_copy, OsCopy, ProviderMembership};
use crate::provider_host_link::PinAnswer;
use crate::provider_host_link::ProviderHostLink;
use crate::provider_publication::EvictOutcome as HostAnswer;
use crate::provider_reclaim::{ProviderReclaim, Reclaimed, Retained};
use crate::sync_error::SyncError;
use yadorilink_ipc_proto::shellipc::PinChoice;

/// The host side an eviction needs: a fake in tests, the attached menu-bar app in production.
pub(crate) trait EvictHost: Send + Sync {
    fn connected(&self) -> bool;

    /// Whether the attached host serves the root (it reported the root registered).
    fn serves_root(&self, root_id: &str) -> bool;

    /// Tells the host the pins the rules ask for. Not acknowledged; false when no host is attached.
    fn send_pin_plan(&self, root_id: &str, entries: Vec<(Option<ItemId>, PinChoice)>) -> bool;

    /// Asks the host to apply the person's keep-on-this-device choice for an item (`None`: the
    /// folder's root) in the operating system.
    fn pin_item<'a>(
        &'a self,
        root_id: &'a str,
        item: Option<ItemId>,
        choice: PinChoice,
    ) -> BoxFuture<'a, PinAnswer>;

    /// Drops the OS copy only while the host shows exactly `target`.
    fn evict_shown_version<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, HostAnswer>;
}

impl EvictHost for ProviderHostLink {
    fn serves_root(&self, root_id: &str) -> bool {
        ProviderHostLink::serves_root(self, root_id)
    }

    fn send_pin_plan(&self, root_id: &str, entries: Vec<(Option<ItemId>, PinChoice)>) -> bool {
        ProviderHostLink::send_pin_plan(self, root_id, entries)
    }

    fn pin_item<'a>(
        &'a self,
        root_id: &'a str,
        item: Option<ItemId>,
        choice: PinChoice,
    ) -> BoxFuture<'a, PinAnswer> {
        ProviderHostLink::pin_item(self, root_id, item, choice)
    }

    fn connected(&self) -> bool {
        self.host_connected()
    }

    fn evict_shown_version<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, HostAnswer> {
        ProviderHostLink::evict_shown_version(self, root_id, item, target)
    }
}

/// The `online_only` rule an eviction is applying. The OS copy is dropped only while the path is
/// still freed by exactly this rule at this generation, checked under the item lock right before
/// the host is asked.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RuleHold<'a> {
    pub(crate) rule_path: &'a str,
    pub(crate) generation: i64,
}

/// What one eviction request did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderEvictOutcome {
    /// The OS dropped its copy.
    pub dehydrated: bool,
    /// The daemon's cached blocks that were physically freed.
    pub reclaimed: Reclaimed,
    /// Why the blocks stayed, when they did.
    pub retained: Option<Retained>,
}

pub(crate) struct ProviderEvictor {
    state: Arc<DaemonState>,
    host: Arc<dyn EvictHost>,
    reclaim: Arc<ProviderReclaim>,
    membership: Arc<ProviderMembership>,
}

impl ProviderEvictor {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        host: Arc<dyn EvictHost>,
        reclaim: Arc<ProviderReclaim>,
        membership: Arc<ProviderMembership>,
    ) -> Self {
        Self { state, host, reclaim, membership }
    }

    /// Runs the online-only rules that cover `path` again; how many there are.
    pub(crate) fn reapply_rules(&self, group_id: &str, path: &str) -> Result<usize, SyncError> {
        let path = path.trim_end_matches('/');
        let rules = self.state.replica_coordinator.retention_rules();
        // The folder's own root names every rule of the group.
        Ok(if path.is_empty() {
            rules.rearm_group(group_id)?
        } else {
            rules.rearm(group_id, path)?
        })
    }

    /// Why no block of this group is ever reclaimed, if so (see
    /// [`ProviderReclaim::standing_blocker`]).
    pub(crate) fn standing_blocker(&self, group_id: &str) -> Option<Retained> {
        self.reclaim.standing_blocker(group_id)
    }

    /// What the person's change of the pin mark of the item `item` (`None`: the sync root itself) of root
    /// `root_id`, seen by the host,
    /// asks of the rules: the group, the path and the rule to set, or `None` when the rules already say
    /// it, the root is unknown or not served, or the item is not in the namespace.
    pub(crate) fn rule_for_observed(
        &self,
        root_id: &str,
        item: Option<&ItemId>,
        observed: PinChoice,
    ) -> Result<Option<(String, String, crate::application::ports::RuleChoice)>, SyncError> {
        let repository = self.state.replica_coordinator.provider_repository();
        let Some(group_id) = repository.group_of_root(root_id)? else { return Ok(None) };
        if !self.host.serves_root(root_id) {
            return Ok(None);
        }
        // No item is the sync root itself, whose rule sits at the empty path.
        let path = match item {
            None => String::new(),
            Some(item) => match repository.path_for_item(root_id, item)? {
                Some((path, _)) => path,
                None => return Ok(None),
            },
        };
        let rules = self.state.replica_coordinator.retention_rules().rules(&group_id)?;
        let nearest = rules.nearest(&path).map(|(at, rule)| (at == path, rule));
        Ok(rule_for_observed_pin(nearest, observed).map(|rule| (group_id, path, rule)))
    }

    /// Whether the attached host serves the provider root of `group_id`.
    pub(crate) fn host_serves_group(&self, group_id: &str) -> bool {
        let repository = self.state.replica_coordinator.provider_repository();
        matches!(
            repository.declaration_for_group(group_id),
            Ok(ProviderDeclaration::Provider(root)) if self.host.serves_root(&root.root_id)
        )
    }

    /// The pins the group's explicit rules ask for, shallowest first (an item under no rule is not
    /// mentioned). A rule whose path names no item of the folder (yet) is left out; the plan is sent
    /// again when the namespace changes.
    pub(crate) fn pin_plan_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<(Option<ItemId>, PinChoice)>, SyncError> {
        let repository = self.state.replica_coordinator.provider_repository();
        let ProviderDeclaration::Provider(root) = repository.declaration_for_group(group_id)?
        else {
            return Ok(Vec::new());
        };
        let rules = self.state.replica_coordinator.retention_rules().rules(group_id)?;
        let mut plan = Vec::new();
        for (path, choice) in rule_pins(&rules) {
            if path.is_empty() {
                plan.push((None, choice));
            } else if let Some(item) = repository.item_for_path(&root.root_id, &path)? {
                plan.push((Some(item), choice));
            }
        }
        Ok(plan)
    }

    /// Sends the host the plan of the group that owns `root_id` (hex), if it has any rule. A host
    /// that is not attached is told nothing: it is sent the plan when it attaches.
    pub(crate) fn push_pin_plan(&self, root_id: &str) {
        let group =
            match self.state.replica_coordinator.provider_repository().group_of_root(root_id) {
                Ok(Some(group)) => group,
                Ok(None) => return,
                Err(error) => {
                    tracing::debug!(%error, "could not look up the provider root for its pin plan");
                    return;
                }
            };
        match self.pin_plan_for_group(&group) {
            Ok(plan) if !plan.is_empty() => {
                self.host.send_pin_plan(root_id, plan);
            }
            Ok(_) => {}
            Err(error) => tracing::debug!(%error, "could not build the pin plan"),
        }
    }

    /// Makes the operating system's pins agree with the rules after the rule at `path` changed.
    /// The pin at `path` follows the retention that now holds there (the nearest rule, so a
    /// `default` beneath a kept folder stays pinned), and because a folder's pin overwrites
    /// everything beneath it the explicit rules beneath `path` are applied again afterwards,
    /// shallowest first. Returns the choice made for `path` and the host's answer to it, or the
    /// first failure among the later ones.
    pub(crate) async fn apply_pins(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(PinChoice, PinAnswer), SyncError> {
        let path = path.trim_end_matches('/');
        let rules = self.state.replica_coordinator.retention_rules().rules(group_id)?;
        let plan = pin_plan(&rules, path);
        let (first_path, first_choice) = plan[0].clone();
        let first = self.apply_pin(group_id, &first_path, first_choice).await?;
        // A host that is absent, cannot pin or failed on the first request is not asked again.
        if !matches!(first, PinAnswer::Done | PinAnswer::Downloading) {
            return Ok((first_choice, first));
        }
        let mut answer = first;
        for (later_path, choice) in plan.into_iter().skip(1) {
            let later = self.apply_pin(group_id, &later_path, choice).await?;
            if matches!(later, PinAnswer::Error(_) | PinAnswer::NotConnected) {
                return Ok((first_choice, later));
            }
            if answer == PinAnswer::Done && later == PinAnswer::Downloading {
                answer = PinAnswer::Downloading;
            }
        }
        Ok((first_choice, answer))
    }

    pub(crate) async fn evict(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ProviderEvictOutcome, SyncError> {
        self.evict_expecting(group_id, path, None).await
    }

    /// Asks the host to make the operating system agree with the person's choice for `path`
    /// (already recorded). A path that names no item of the folder is [`PinAnswer::NotFound`];
    /// the folder's own path is the root.
    pub(crate) async fn apply_pin(
        &self,
        group_id: &str,
        path: &str,
        choice: PinChoice,
    ) -> Result<PinAnswer, SyncError> {
        let path = path.trim_end_matches('/');
        let repository = self.state.replica_coordinator.provider_repository();
        let ProviderDeclaration::Provider(root) = repository.declaration_for_group(group_id)?
        else {
            return Err(SyncError::EvictionRejected(format!("{path}: not in a provider folder")));
        };
        let item = if path.is_empty() {
            None
        } else {
            match repository.item_for_path(&root.root_id, path)? {
                Some(item) => Some(item),
                None => return Ok(PinAnswer::NotFound),
            }
        };
        Ok(self.host.pin_item(&root.root_id, item, choice).await)
    }

    /// [`Self::evict`] for a caller that decided about one item at one version: a different item
    /// at the path or a different current version is [`Retained::VersionMoved`] and nothing is
    /// touched.
    pub(crate) async fn evict_expecting(
        &self,
        group_id: &str,
        path: &str,
        expect: Option<(ItemId, VersionHash)>,
    ) -> Result<ProviderEvictOutcome, SyncError> {
        self.evict_applying(group_id, path, expect, None).await
    }

    /// [`Self::evict_expecting`] on behalf of an `online_only` rule: nothing is dropped once the
    /// rule is no longer what frees the path.
    pub(crate) async fn evict_applying(
        &self,
        group_id: &str,
        path: &str,
        expect: Option<(ItemId, VersionHash)>,
        hold: Option<RuleHold<'_>>,
    ) -> Result<ProviderEvictOutcome, SyncError> {
        let result = self.evict_inner(group_id, path, expect, hold).await;
        // A refusal is always logged with its reason: the answer the user sees is one line.
        match &result {
            Ok(ProviderEvictOutcome { dehydrated, retained: Some(why), .. }) => tracing::info!(
                group_id,
                path,
                reason = why.code(),
                retryable = why.retryable(),
                dehydrated,
                "provider eviction kept something on this device"
            ),
            Err(error) => {
                tracing::info!(group_id, path, %error, "provider eviction refused");
            }
            Ok(_) => {}
        }
        // The item has settled, whatever the outcome: a lease taken for an eviction that did not
        // complete is released by the reconciler now rather than at the next restart.
        self.state.nudge_custody_hold_reconciler();
        result
    }

    async fn evict_inner(
        &self,
        group_id: &str,
        path: &str,
        expect: Option<(ItemId, VersionHash)>,
        hold: Option<RuleHold<'_>>,
    ) -> Result<ProviderEvictOutcome, SyncError> {
        let path = path.trim_end_matches('/');
        let coordinator = &self.state.replica_coordinator;
        let repository = coordinator.provider_repository();
        let ProviderDeclaration::Provider(root) = repository.declaration_for_group(group_id)?
        else {
            return Err(SyncError::EvictionRejected(format!("{path}: not in a provider folder")));
        };
        let Some(item) = repository.item_for_path(&root.root_id, path)? else {
            return Err(SyncError::EvictionRejected(format!("{path}: not an item of the folder")));
        };
        let record = coordinator
            .sqlite()
            .dag_get_current_version_record(group_id, path)?
            .filter(|record| !record.deleted)
            .ok_or_else(|| SyncError::EvictionRejected(format!("{path}: no current version")))?;
        if record.record_kind != RecordKind::File {
            return Err(SyncError::EvictionRejected(format!(
                "{path} is not a regular file and cannot be evicted"
            )));
        }
        // Before any lease is taken or the host is asked; checked again, under the item lock,
        // right before the host drops its copy.
        self.refuse_if_kept(group_id, path)?;
        if !self.host.connected() {
            return Err(not_connected());
        }
        let version = record.to_file_version().version_hash;
        if expect
            .is_some_and(|(expected_item, expected)| expected != version || expected_item != item)
        {
            return Ok(ProviderEvictOutcome {
                retained: Some(Retained::VersionMoved),
                ..Default::default()
            });
        }
        // The lease comes first, and its item lock stays held until the blocks are settled: the
        // OS copy is dropped only when this device knows whether the blocks can follow.
        let mut _local_copy = None;
        let prepared = match self.reclaim.prepare(group_id, path, Some(version)).await {
            Ok(prepared) => Ok(prepared),
            // Another operation holds the item, or it is not the version the request was about:
            // leave everything as it is.
            Err(why @ (Retained::Busy | Retained::VersionMoved)) => {
                return Ok(ProviderEvictOutcome { retained: Some(why), ..Default::default() });
            }
            // No lease: the OS copy may go only if the next open can be served from this
            // device's own blocks, proven by reading and hashing every one of them. The item
            // lock taken for the proof stays held until the host has answered.
            Err(why) => {
                match self.reclaim.hold_verified_local_copy(group_id, path, version).await {
                    Ok(copy) => {
                        _local_copy = Some(copy);
                        Err(why)
                    }
                    Err(refused @ (Retained::Busy | Retained::VersionMoved)) => {
                        return Ok(ProviderEvictOutcome {
                            retained: Some(refused),
                            ..Default::default()
                        });
                    }
                    Err(refused) => {
                        tracing::info!(
                            reason = why.code(),
                            "provider eviction refused: no lease, local blocks not verified"
                        );
                        return Ok(ProviderEvictOutcome {
                            retained: Some(refused),
                            ..Default::default()
                        });
                    }
                }
            }
        };
        // Under the item lock the path must still name the item this request is about.
        if repository.item_for_path(&root.root_id, path)? != Some(item) {
            return Ok(ProviderEvictOutcome {
                retained: Some(Retained::VersionMoved),
                ..Default::default()
            });
        }
        let answer =
            self.drop_os_copy(group_id, path, &root.root_id, item, version.0, hold).await?;
        let (dehydrated, host_retained) = match answer {
            Some(HostAnswer::Evicted) => (true, None),
            // Already without its data: the blocks may still be freed.
            Some(HostAnswer::NotMaterialized) => (false, None),
            Some(HostAnswer::Busy) => (false, Some(Retained::HostBusy)),
            Some(HostAnswer::NotConnected) => return Err(not_connected()),
            Some(HostAnswer::Error(reason)) => {
                tracing::info!(group_id, path, %reason, "the host declined to drop its copy");
                (false, Some(Retained::HostRefused))
            }
            // Nothing shows the OS holds the current content (or nothing at all): neither its
            // copy nor the blocks are touched.
            None => (false, Some(Retained::NotConfirmed)),
        };
        let prepared = match (prepared, host_retained) {
            (Ok(prepared), None) => prepared,
            (_, Some(why)) | (Err(why), None) => {
                return Ok(ProviderEvictOutcome {
                    dehydrated,
                    retained: Some(why),
                    ..Default::default()
                });
            }
        };
        let cached_before = self.reclaim.has_cached_blocks(group_id, path);
        let reclaimed = self.reclaim.reclaim(prepared).await?;
        let retained = (reclaimed.blocks == 0).then_some(if !cached_before {
            Retained::NotDownloaded
        } else if self.reclaim.history_holds_blocks(group_id, path) {
            Retained::HeldAsHistory
        } else {
            Retained::NothingFreed
        });
        Ok(ProviderEvictOutcome { dehydrated, reclaimed, retained })
    }

    /// A path the user asked to keep on this device is never freed. A policy that cannot be read
    /// refuses too.
    fn refuse_if_kept(&self, group_id: &str, path: &str) -> Result<(), SyncError> {
        let retention =
            self.state.replica_coordinator.retention_rules().retention(group_id, path)?;
        if retention.policy == yadorilink_sync_sqlite::RetentionPolicy::Pinned {
            return Err(SyncError::EvictionRejected(format!(
                "{path} is kept on this device; stop keeping it first to free up its space"
            )));
        }
        Ok(())
    }

    /// Asks the host to drop its copy, but only for an item the daemon's own evidence shows the OS
    /// holds with the CURRENT content (see [`crate::provider_evidence::os_holds_current_content`]), or
    /// some of it from windows it was served (see [`OsCopy::Windows`]).
    ///
    /// `None`: the evidence does not settle what the OS holds, so nothing was asked of the host.
    async fn drop_os_copy(
        &self,
        group_id: &str,
        path: &str,
        root_id: &str,
        item: ItemId,
        version: [u8; 32],
        hold: Option<RuleHold<'_>>,
    ) -> Result<Option<HostAnswer>, SyncError> {
        self.refuse_if_kept(group_id, path)?;
        if let Some(hold) = hold {
            let rules = self.state.replica_coordinator.retention_rules();
            let still = rules.rule_row(group_id, hold.rule_path)?.is_some_and(|row| {
                row.rule == yadorilink_sync_sqlite::Rule::OnlineOnly
                    && row.generation == hold.generation
            }) && rules.rules(group_id)?.nearest(path)
                == Some((hold.rule_path, yadorilink_sync_sqlite::Rule::OnlineOnly));
            if !still {
                return Err(SyncError::EvictionRejected(format!(
                    "{path}: the rule that frees it changed; nothing was dropped"
                )));
            }
        }
        match os_copy(&self.state.replica_coordinator, &self.membership, root_id, &item) {
            OsCopy::Current | OsCopy::Windows => {
                Ok(Some(self.host.evict_shown_version(root_id, item, version).await))
            }
            OsCopy::Absent => Ok(Some(HostAnswer::NotMaterialized)),
            OsCopy::Unconfirmed => Ok(None),
        }
    }
}

/// The one table that relates a retention rule to an operating-system pin mark, used in both
/// directions so the engine's pins and the person's cannot disagree about what a mark means:
/// keep is the pinned mark, online only the unpinned mark, no rule neither.
pub(crate) fn pin_of_rule(rule: yadorilink_sync_sqlite::Rule) -> PinChoice {
    use yadorilink_sync_sqlite::Rule;
    match rule {
        Rule::Keep => PinChoice::Keep,
        Rule::OnlineOnly => PinChoice::OnlineOnly,
    }
}

/// What the person's change of a pin mark, seen in the operating system, asks of the rules, given
/// the rule that holds at the item now (`nearest`: whether it is set at exactly this item, and
/// which). `None` when the rules already say it (so the pin the engine itself sent, coming back as
/// a signal, changes nothing and cannot start a loop). A mark of neither kind removes the rule only
/// where the item has one of its own: an item that merely inherits has no choice to take back.
pub(crate) fn rule_for_observed_pin(
    nearest: Option<(bool, yadorilink_sync_sqlite::Rule)>,
    observed: PinChoice,
) -> Option<crate::application::ports::RuleChoice> {
    use crate::application::ports::RuleChoice;
    use yadorilink_sync_sqlite::Rule;
    match (observed, nearest) {
        (PinChoice::Keep, Some((_, Rule::Keep))) => None,
        (PinChoice::Keep, _) => Some(RuleChoice::Keep),
        (PinChoice::OnlineOnly, Some((_, Rule::OnlineOnly))) => None,
        (PinChoice::OnlineOnly, _) => Some(RuleChoice::OnlineOnly),
        (PinChoice::Clear, Some((true, _))) => Some(RuleChoice::Default),
        (PinChoice::Clear, _) | (PinChoice::Unspecified, _) => None,
    }
}

/// The pin each explicit rule asks for, shallowest first (the root rule, path empty, first).
fn rule_pins(rules: &yadorilink_sync_sqlite::RuleSet) -> Vec<(String, PinChoice)> {
    let mut all = rules.beneath("");
    // `beneath("")` leaves out a rule on the root itself.
    let root = rules.nearest("").filter(|(at, _)| at.is_empty());
    all.sort_by_key(|(at, _)| (at.matches('/').count(), *at));
    root.into_iter().chain(all).map(|(at, rule)| (at.to_owned(), pin_of_rule(rule))).collect()
}

/// The pins to set after the rule at `path` changed, in the order to set them: first `path` itself,
/// as the retention that holds there says (the nearest rule at or above it; none means no choice),
/// then each explicit rule strictly beneath it as it stands, shallowest first. A folder's pin
/// overwrites everything beneath it, so the later ones put back what the rules below it say.
fn pin_plan(rules: &yadorilink_sync_sqlite::RuleSet, path: &str) -> Vec<(String, PinChoice)> {
    use yadorilink_sync_sqlite::Rule;
    let choice_of = pin_of_rule;
    let own = rules.nearest(path).map_or(PinChoice::Clear, |(_, rule)| choice_of(rule));
    let mut plan = vec![(path.to_owned(), own)];
    let mut beneath: Vec<(&str, Rule)> = rules.beneath(path);
    beneath.sort_by_key(|(at, _)| (at.matches('/').count(), *at));
    plan.extend(beneath.into_iter().map(|(at, rule)| (at.to_owned(), choice_of(rule))));
    plan
}

fn not_connected() -> SyncError {
    SyncError::EvictionRejected("the File Provider host is not connected".into())
}

/// The evictor, installed by the shell side once it exists (the control socket is built first).
#[derive(Default)]
pub(crate) struct ProviderEvictSlot(OnceLock<Arc<ProviderEvictor>>);

impl ProviderEvictSlot {
    pub(crate) fn install(&self, evictor: Arc<ProviderEvictor>) {
        let _ = self.0.set(evictor);
    }

    pub(crate) fn reapply_rules(&self, group_id: &str, path: &str) -> Result<usize, SyncError> {
        match self.0.get() {
            Some(evictor) => evictor.reapply_rules(group_id, path),
            None => Err(SyncError::EvictionRejected(
                "provider folders are not available in this daemon".into(),
            )),
        }
    }

    /// Whether the attached host serves the provider root of `group_id` (false while no evictor is
    /// installed, and for a group that is no provider root).
    pub(crate) fn host_serves_group(&self, group_id: &str) -> bool {
        self.0.get().is_some_and(|evictor| evictor.host_serves_group(group_id))
    }

    pub(crate) async fn apply_pins(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(PinChoice, PinAnswer), SyncError> {
        match self.0.get() {
            Some(evictor) => evictor.apply_pins(group_id, path).await,
            None => Err(SyncError::EvictionRejected(
                "provider folders are not available in this daemon".into(),
            )),
        }
    }

    pub(crate) async fn evict(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<ProviderEvictOutcome, SyncError> {
        match self.0.get() {
            Some(evictor) => evictor.evict(group_id, path).await,
            None => Err(SyncError::EvictionRejected(
                "provider folders are not available in this daemon".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
