//! Narrow, per-link dependency bundle threaded through this module tree
//! (`link_runtime.rs` and `link_runtime/operations/*.rs`) in place of a
//! handle to the daemon's full runtime state -- so this module tree names
//! only what the per-link watch/capture/repair machinery actually uses,
//! not every other subsystem (peer sessions, governance config, update
//! management, ...) that lives alongside it at the daemon-wide level.
//!
//! Constructed once per relevant call from the daemon-wide state (see that
//! type's own `link_runtime_dependencies` constructor) and threaded down
//! into [`super::LinkRuntime`]'s construction, its per-link operations, and
//! every one of the per-link background tasks the daemon's own `LinkRuntimeController` spawns.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use yadorilink_local_storage::BlockStore;

use crate::replica_coordinator::ReplicaCoordinator;

/// The handful of operations this per-link dependency bundle cannot itself
/// perform without reaching into daemon-wide coordination state that has no
/// per-link narrowing: following up a durable local commit (publishing its
/// checkpoint and waking reconciliation, `on_local_native_commit`), marking daemon-wide write activity
/// for the idle-GC scheduler and the "Safe Update Windows" write-safe-point
/// signal (`begin_write_activity`), and reading this device's change-history
/// signing key (`device_signing_key`). Implemented by the daemon's runtime
/// state itself, elsewhere in this crate, so [`LinkRuntimeDependencies`] can
/// still reach these three without naming that type.
pub(crate) trait LinkRuntimeHostPort: Send + Sync {
    fn on_local_native_commit<'a>(
        &'a self,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

    /// An opaque write-activity RAII guard, released on drop. Boxed and
    /// type-erased because its real return type borrows fields of the
    /// implementor that this bundle has no business naming -- the same
    /// erasure `yadorilink_peer_session::peer_session::BlockWriteActivityProvider`
    /// already uses for the identical guard.
    fn begin_write_activity(&self) -> Box<dyn Send + '_>;

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey>;

    /// A capture flush finished, so this group's local capture barriers may
    /// have settled and staged Changes blocked behind them may now be
    /// admissible.
    ///
    /// Deliberately separate from `on_local_native_commit`, and deliberately
    /// not conditioned on any record: a flush that produces NO record still
    /// clears the dirty rows that were the barrier. Following up a commit is
    /// about telling peers what changed; this is about re-asking a question
    /// whose answer may have changed. Tying the second to the first is what
    /// left verified Changes staged forever -- `announce_local_change`
    /// returns at `records.is_empty()`, before anything that could re-ask.
    ///
    /// The port exists so this crate's capture path does not depend on the
    /// admission coordinator; the daemon side decides what to do with it.
    ///
    /// # Which call sites owe this signal
    ///
    /// The population is "every production path that durably clears a
    /// `local_dirty_paths` row", NOT "every path that announces records" --
    /// counting announce sites is what let the live watcher slip through
    /// twice. There is exactly one repository call that clears durably:
    /// `flush_pending_clears` inside `LocalChangeProcessor::
    /// process_flush_with_ignore`'s `DebounceFlush::Paths` arm
    /// (`clear_dirty_paths_conditional_batch`). Everything below is a caller
    /// of that one arm:
    ///
    /// | Production path                          | Reaches the clear via                             | Signal |
    /// |------------------------------------------|---------------------------------------------------|--------|
    /// | live debounce executor, `Paths` flush     | `process_flush_with_ignore(Paths)`                | `tasks.rs` flush loop |
    /// | startup dirty-journal redrive             | `redrive_dirty_journal` -> `process_flush(Paths)` | `tasks.rs` startup |
    /// | periodic dirty-journal redrive backstop   | same                                              | `tasks.rs` redrive task |
    /// | peer-triggered targeted flush (one path)  | `LinkFlushHandle::process_flush(Paths)`           | `capture_local_change.rs` |
    /// | peer-triggered case-fold sibling flush    | same                                              | `capture_local_change.rs` |
    /// | drained accumulator flush                 | same                                              | `capture_local_change.rs` |
    /// | paused-item resume catch-up               | `capture_resumed_item` -> `process_flush(Paths)`  | `capture_local_change.rs` |
    ///
    /// Three paths write the index and owe nothing, because none of them can
    /// CLEAR a row -- which is the predicate, not "does not touch the dirty
    /// journal". The initial scan and the periodic disk-reconcile backstop
    /// both go through `reconcile_disk_with_ignore`, which does reach the
    /// journal: its withheld-tail branch calls `record_dirty_path` so a
    /// policy-withheld chunk is re-driven later. That is a write, never a
    /// delete, so it opens barriers and never closes one. The executor's
    /// streaming arm reaches the same scan and no further: it runs only under
    /// `burst_fallback`, which is `DebounceFlush::RescanRequired`, and
    /// `process_flush_with_ignore_streaming` routes `RescanRequired` there --
    /// its `Paths` case is unreachable, because a `Paths` flush never takes
    /// the streaming arm. The initial scan signals anyway: harmless
    /// over-notification.
    ///
    /// So when adding a caller, the question to ask is not whether it names
    /// the dirty journal. It is whether it can reach
    /// `clear_dirty_paths_conditional_batch`.
    ///
    /// This enumeration is the fragile part. Making the durable clear itself
    /// the producer would remove it; until then, adding a caller of that arm
    /// means adding a row here.
    fn note_capture_settled(&self, group_id: &str);
}

/// Everything the per-link runtime machinery actually needs, narrowed down
/// from the daemon's full runtime state. Cheap to clone (every field is an
/// `Arc`/`String`/trait-object handle), so it is passed around freely and
/// captured into every per-link background task the same way a full state
/// handle used to be.
#[derive(Clone)]
pub(crate) struct LinkRuntimeDependencies {
    /// The one replica/native-state/materialization composition-root handle this
    /// bundle threads down into the per-link runtime machinery
    /// (`factory.rs`/`startup.rs`'s startup-readiness calls/`tasks.rs`/
    /// `operations/repair_materialization.rs`, `startup.rs`'s
    /// `build_change_processor`).
    pub(crate) replica_coordinator: Arc<ReplicaCoordinator>,
    pub(crate) block_store: Arc<dyn BlockStore + Send + Sync>,
    pub(crate) telemetry: Arc<crate::runtime_telemetry::RuntimeTelemetry>,
    pub(crate) device_id: String,
    /// Reaches the three daemon-wide operations `LinkRuntimeHostPort`
    /// covers -- see that trait's own doc for why they cannot be plain
    /// fields on this bundle.
    pub(crate) host: Arc<dyn LinkRuntimeHostPort>,
}

impl LinkRuntimeDependencies {
    pub(crate) async fn on_local_native_commit(&self, group_id: &str) {
        self.host.on_local_native_commit(group_id).await;
    }

    pub(crate) fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        self.host.begin_write_activity()
    }

    /// See [`LinkRuntimeHostPort::note_capture_settled`].
    pub(crate) fn note_capture_settled(&self, group_id: &str) {
        self.host.note_capture_settled(group_id);
    }

    pub(crate) fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        self.host.device_signing_key()
    }
}
