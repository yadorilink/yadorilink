//! The write operations an embedding app (the iOS app) needs: stage a file, apply a change to a
//! provider folder, discard a staged file, and ask whether authored versions have reached a
//! device that keeps a full replica.
//!
//! None of them is a new write path. `apply_change` is the provider write path the Mac File
//! Provider uses (`shell_ipc::provider_apply`): one request is one logical operation, idempotent
//! by its `(session_id, operation_seq)` pair, decided and committed by the engine and answered
//! from the committed rows. The app owns that pair: it persists it with its pending operation so
//! that a retry after a lost response, a kill or a restart carries the same pair and gets the
//! stored outcome instead of a second write. The change is durable before it is acknowledged.
//!
//! Refusals are results, not call failures: a reader's write, a stale view, a name collision
//! and the rest come back as the wire's [`ProviderApplyFailure`] code.

use yadorilink_ipc_proto::shellipc::{
    ProviderApplyChangeRequest, ProviderApplyChangeResponse, ProviderApplyFailure,
};

use super::{CommandError, EngineCommands};
pub use crate::provider_delivery::{
    DeliveryItem, DeliveryReport, DeliveryState, ItemDelivery, MAX_DELIVERY_ITEMS,
};
pub use crate::provider_stage::{StageMode, StageSource, StagedHow, StagedUpload};

/// One change for a provider folder, in the wire's shape (`ProviderApplyChangeRequest`): create a
/// file or folder, modify (new contents, rename, move), or delete.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ApplyChange(pub ProviderApplyChangeRequest);

// Plain data without floats: equality is total.
impl Eq for ApplyChange {}

/// The engine's answer to an [`ApplyChange`], in the wire's shape
/// (`ProviderApplyChangeResponse`): `ok` with the outcome and the item, or a refusal `failure`.
#[derive(Debug, Clone, PartialEq)]
pub struct ApplyResponse(pub ProviderApplyChangeResponse);

impl Eq for ApplyResponse {}

/// Why a file could not be staged. `code` is one of `LowDisk`, `IngestRejected`,
/// `IngestUnstable`, `NotReady` (no temp root) or `Retry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRefused {
    pub code: ProviderApplyFailure,
    pub message: String,
}

fn refused(error: crate::provider_ingest::IngestError) -> StageRefused {
    use crate::provider_ingest::IngestError;
    match error {
        IngestError::Rejected(message) => {
            StageRefused { code: ProviderApplyFailure::IngestRejected, message }
        }
        IngestError::Unstable(message) => {
            StageRefused { code: ProviderApplyFailure::IngestUnstable, message }
        }
        IngestError::TooLarge => {
            StageRefused { code: ProviderApplyFailure::TooLarge, message: "too many blocks".into() }
        }
        IngestError::LowDisk(message) => {
            StageRefused { code: ProviderApplyFailure::LowDisk, message }
        }
        IngestError::Store(message) => StageRefused { code: ProviderApplyFailure::Retry, message },
    }
}

impl EngineCommands {
    /// Applies one change to a provider folder and waits for the engine's decision. See the
    /// module docs; a refusal is the response's `failure`, never an error of the call.
    pub async fn apply_change(&self, change: ApplyChange) -> ApplyResponse {
        ApplyResponse(crate::shell_ipc::apply_for_app(&self.shell, &change.0).await)
    }

    /// Puts a file into the engine's `ingest/` directory for a following `apply_change` to name,
    /// moving or cloning it rather than copying where it can, and returns the name, size and
    /// SHA-256 to put in the request's content. The file is flushed before this returns. A
    /// copy is refused with `LowDisk` before the first byte is read when the volume cannot take
    /// it.
    ///
    /// # Errors
    /// [`StageRefused`] with why.
    pub async fn stage_upload(
        &self,
        source: StageSource,
        mode: StageMode,
    ) -> Result<StagedUpload, StageRefused> {
        let Some(handoff) = self.shell.handoff.get() else {
            return Err(StageRefused {
                code: ProviderApplyFailure::NotReady,
                message: "no temp root is configured".into(),
            });
        };
        let name = handoff.new_upload_name();
        let shell = self.shell.clone();
        let dir = handoff.ingest_dir().to_path_buf();
        tokio::task::spawn_blocking(move || {
            // Only a copy writes bytes into `ingest/`; the free space it needs is that volume's.
            let reserve = |bytes: u64| {
                shell
                    .writer
                    .reserve_space_on(Some(&dir), bytes)
                    .map(drop)
                    .map_err(crate::provider_ingest::IngestError::LowDisk)
            };
            crate::provider_stage::stage_upload(&dir, &name, &source, mode, &reserve)
        })
        .await
        .map_err(|e| StageRefused { code: ProviderApplyFailure::Retry, message: e.to_string() })?
        .map_err(refused)
    }

    /// Removes a staged file no change will use (the user cancelled, or the app gave up). Only a
    /// name `stage_upload` issued is accepted; a missing file is fine.
    ///
    /// # Errors
    /// [`StageRefused`] for a name that is not a staged upload's, or when removing failed.
    pub fn discard_staged_upload(&self, ingest_name: &str) -> Result<(), StageRefused> {
        let Some(handoff) = self.shell.handoff.get() else {
            return Ok(());
        };
        crate::provider_stage::discard_staged(handoff.ingest_dir(), ingest_name).map_err(refused)
    }

    /// Marks a provider folder publish-only on this device, or clears it. Takes effect for the
    /// next change; one already past its refusal check still commits.
    ///
    /// # Errors
    /// [`CommandError`] for an unknown root or an unreadable index.
    pub fn set_publish_only(&self, root_id: &[u8], publish_only: bool) -> Result<(), CommandError> {
        let found = self
            .shell
            .replica_coordinator
            .provider_repository()
            .set_publish_only(&hex::encode(root_id), publish_only)
            .map_err(|e| CommandError::from_error(&e))?;
        if found {
            Ok(())
        } else {
            Err(CommandError::failed("unknown provider root"))
        }
    }

    /// For each item this device authored, whether a device that keeps a full replica holds
    /// exactly that version now. Asked afresh every time; see the module `provider_delivery`.
    ///
    /// # Errors
    /// [`CommandError`] when more than [`MAX_DELIVERY_ITEMS`] are asked about.
    pub async fn version_delivery(
        &self,
        items: Vec<DeliveryItem>,
    ) -> Result<DeliveryReport, CommandError> {
        crate::provider_delivery::version_delivery(&self.shell, items)
            .await
            .map_err(|_| CommandError::failed("too many items in one delivery check"))
    }
}
