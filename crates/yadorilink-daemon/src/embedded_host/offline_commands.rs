//! Keeping items on the device, for the embedding app: pin, unpin, the policy of one item, freeing
//! the local copy, and what automatic space management would free.
//!
//! Each call runs the service the daemon's control socket runs for the same request
//! (`application.materialization`, `provider_evict`, `auto_reclaim`); an item is named the way the
//! provider surface names it (`root_id`, `item_id`) and resolved to the group and path those
//! services take. Downloading is not a command here: the operating system downloads a provider
//! folder's item when it is opened, and the daemon refuses an explicit download there too.

use yadorilink_sync_sqlite::provider::ItemId;

use super::{CommandError, EngineCommands};

/// The retention policy in force at one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemRetention {
    /// Local space for the item must not be reclaimed.
    pub pinned: bool,
    /// The folder holds no copy of the item (an online-only rule).
    pub online_only: bool,
    /// The rule was set at exactly this item; otherwise it is inherited from a folder above.
    pub explicit: bool,
}

/// What a person chose for an item's copy on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionRule {
    Keep,
    OnlineOnly,
    /// Remove the rule set at exactly this item.
    Default,
}

/// What pinning an item did. The pin stands even when `download_error` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinOutcome {
    pub retention: ItemRetention,
    /// Why the content could not be fetched just now, when it could not.
    pub download_error: Option<String>,
    /// Why a file beneath the item is not yet held in the block store (`changing_retry` or
    /// `not_kept_error`), when one is not.
    pub history_not_kept_reason: Option<String>,
}

/// What freeing the local copy of one item did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvictOutcome {
    /// The operating system dropped its copy.
    pub dehydrated: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
    /// Why the engine's cached blocks stayed, when they did (a stable code).
    pub retained_reason: Option<String>,
}

/// What automatic space management would do with one item now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceReclaimItem {
    pub root_id: Vec<u8>,
    pub item_id: Vec<u8>,
    /// The group-relative path.
    pub path: String,
    /// A stable code: `eligible`, `pinned`, `unsupported_root`, `custody_unavailable`, `busy`,
    /// `changed` or `safety_blocked`.
    pub verdict: String,
}

/// What automatic space management would free now, without freeing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceReclaimPreview {
    pub items: Vec<SpaceReclaimItem>,
    /// Folders that could not be read; their items are missing from `items`.
    pub unreadable_roots: u32,
}

impl EngineCommands {
    /// The group and path of one provider item.
    pub(super) fn resolve_item(
        &self,
        root_id: &[u8],
        item_id: &[u8],
    ) -> Result<(String, String), CommandError> {
        let coordinator = &self.shell.replica_coordinator;
        let root = hex::encode(root_id);
        let group = coordinator
            .provider_repository()
            .group_of_root(&root)
            .map_err(|e| CommandError::from_error(&e))?
            .ok_or_else(|| CommandError::failed("unknown provider root"))?;
        let item = ItemId::try_from(item_id)
            .map_err(|_| CommandError::failed("an item id is not 16 bytes"))?;
        let (path, live) = coordinator
            .provider_repository()
            .path_for_item(&root, &item)
            .map_err(|e| CommandError::from_error(&e))?
            .ok_or_else(|| CommandError::failed("unknown item"))?;
        // A retired id still resolves to its old path, which a new item may now hold: acting on
        // that path would change the other item.
        if !live {
            return Err(CommandError::failed("the item was deleted"));
        }
        Ok((group, path))
    }

    /// Sets the retention rule at an item: keep it on this device, keep nothing of it in the
    /// folder (provider folders only), or remove the rule set there. A rule is recorded first and
    /// stands even when a download it starts fails.
    ///
    /// # Errors
    /// [`CommandError`] when the root or item is unknown, the rule does not apply to the folder,
    /// or it cannot be recorded.
    pub async fn set_retention_rule(
        &self,
        root_id: &[u8],
        item_id: &[u8],
        rule: RetentionRule,
    ) -> Result<PinOutcome, CommandError> {
        let (group, path) = self.resolve_item(root_id, item_id)?;
        let choice = match rule {
            RetentionRule::Keep => crate::application::ports::RuleChoice::Keep,
            RetentionRule::OnlineOnly => crate::application::ports::RuleChoice::OnlineOnly,
            RetentionRule::Default => crate::application::ports::RuleChoice::Default,
        };
        let outcome = self
            .context
            .application
            .materialization
            .set_rule(&group, &path, choice)
            .await
            .map_err(|e| CommandError::from_error(&e))?;
        Ok(PinOutcome {
            retention: retention(outcome.retention),
            download_error: outcome.download_error,
            history_not_kept_reason: outcome.history_not_kept_reason.map(str::to_owned),
        })
    }

    /// The retention policy in force at one item. A policy that cannot be read is an error, never
    /// "reclaimable".
    ///
    /// # Errors
    /// [`CommandError`] when the root or item is unknown, or the policy cannot be read.
    pub fn item_retention(
        &self,
        root_id: &[u8],
        item_id: &[u8],
    ) -> Result<ItemRetention, CommandError> {
        let (group, path) = self.resolve_item(root_id, item_id)?;
        self.context
            .application
            .materialization
            .retention(&group, &path)
            .map(retention)
            .map_err(|e| CommandError::from_error(&e))
    }

    /// Frees the local copy of one item: the host drops its copy and the engine frees its cached
    /// blocks when a full replica holds the version.
    ///
    /// # Errors
    /// [`CommandError`] when the root or item is unknown or the eviction is refused.
    pub async fn evict_item(
        &self,
        root_id: &[u8],
        item_id: &[u8],
    ) -> Result<EvictOutcome, CommandError> {
        let (group, path) = self.resolve_item(root_id, item_id)?;
        let outcome = self
            .context
            .provider_evict
            .evict(&group, &path)
            .await
            .map_err(|e| CommandError::from_error(&e))?;
        Ok(EvictOutcome {
            dehydrated: outcome.dehydrated,
            blocks_reclaimed: outcome.reclaimed.blocks,
            bytes_reclaimed: outcome.reclaimed.bytes,
            retained_reason: outcome.retained.map(|why| why.code().to_owned()),
        })
    }

    /// What automatic space management would free now.
    ///
    /// # Errors
    /// [`CommandError`] when automatic space management is not available in this engine.
    pub async fn preview_space_reclaim(&self) -> Result<SpaceReclaimPreview, CommandError> {
        let scan = self.context.auto_reclaim.preview().await.ok_or_else(|| {
            CommandError::failed("automatic space management is not available in this engine")
        })?;
        let items = scan
            .entries
            .iter()
            .filter_map(|entry| {
                Some(SpaceReclaimItem {
                    root_id: hex::decode(&entry.root_id).ok()?,
                    item_id: entry.item.to_vec(),
                    path: entry.path.clone(),
                    verdict: entry.verdict.code().to_owned(),
                })
            })
            .collect();
        Ok(SpaceReclaimPreview {
            items,
            unreadable_roots: u32::try_from(scan.unreadable_roots).unwrap_or(u32::MAX),
        })
    }
}

fn retention(state: crate::application::ports::RetentionState) -> ItemRetention {
    ItemRetention { pinned: state.pinned, online_only: state.online_only, explicit: state.explicit }
}
