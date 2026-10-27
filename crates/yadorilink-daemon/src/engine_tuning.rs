//! The engine's tuning and measurement settings, handed to it explicitly.
//!
//! An embedded host runs one or more engines inside its own process, so what an engine does
//! cannot depend on the process environment: two engines would share it, and a host has no
//! reason to own the variables a desktop daemon reads. Every switch the engine honours is a field
//! here. [`EngineTuning::default`] is the production behaviour; the desktop daemon maps its
//! `YADORILINK_*` variables once, at its composition root ([`EngineTuning::from_lookup`], fed
//! with the process environment by `app.rs`), and an embedded host leaves the defaults.
//!
//! Nothing in this module reads the environment: [`EngineTuning::from_lookup`] takes the lookup
//! as an argument, so the mapping is tested without touching process-global state.

use yadorilink_local_storage::ReceivedFlushMode;

/// Variable names the desktop daemon maps (the same names it has always read).
pub mod vars {
    pub const RECONCILE_PATHS: &str = "YADORILINK_DIAGNOSTIC_RECONCILE_PATHS";
    pub const RECEIVE_WRITE_PERMITS: &str = "YADORILINK_RECEIVE_WRITE_PERMITS";
    pub const RECEIVE_WRITE_CONCURRENCY: &str = "YADORILINK_RECEIVE_WRITE_CONCURRENCY";
    pub const COLLECTOR_FLUSH_CAP: &str = "YADORILINK_RECEIVE_COLLECTOR_CAP";
    pub const BATCH_COMPLETION: &str = "YADORILINK_RECEIVE_BATCH_COMPLETION";
    pub const BATCH_OPEN: &str = "YADORILINK_RECEIVE_BATCH_OPEN";
    pub const DEFERRED_FSYNC: &str = "YADORILINK_RECEIVE_DEFERRED_FSYNC";
    pub const ASYNC_COMMIT: &str = "YADORILINK_RECEIVE_ASYNC_COMMIT";
    pub const PROJECTOR_BATCH: &str = "YADORILINK_PROVIDER_PROJECTOR_BATCH";
    pub const RECOVERY_ITEMS_WARN_BYTES: &str = "YADORILINK_RECOVERY_ITEMS_WARN_BYTES";
    pub const SYNC_RELAYS: &str = "YADORILINK_SYNC_RELAYS";
    pub const BLOCK_FETCH_CONCURRENCY: &str = "YADORILINK_BLOCK_FETCH_CONCURRENCY";
    pub const UPDATE_MANIFEST_URL: &str = "YADORILINK_UPDATE_MANIFEST_URL";
    pub const INSTALL_SOURCE: &str = "YADORILINK_INSTALL_SOURCE";
    pub const NAS_ADMIN_OFFER: &str = "YADORILINK_NAS_ADMIN";
}

/// The relay selection of a tuning. A test build is kept off public relay infrastructure unless
/// it names relays itself: a suite whose result depends on reachable third-party servers
/// reports the network's state as often as the code's, and a test that quietly relays through
/// public infrastructure tells that infrastructure who is running it. A test that needs a relay
/// runs one in-process (`yadorilink_sync_substrate::testing::InProcessRelay`) and configures it.
fn sync_relays(configured: Option<String>) -> Option<String> {
    if cfg!(any(test, feature = "test-support")) {
        configured.or_else(|| Some("none".to_owned()))
    } else {
        configured
    }
}

/// Segment handles an embedded engine caches by default: a host's descriptor limit (256 on iOS)
/// is shared by every engine it runs, and the cache only saves reopens.
pub const EMBEDDED_CACHED_SEGMENT_READERS: usize = 16;

/// The block store's group-commit bounds, with the embedded build's smaller handle cache unless
/// the lookup names one.
fn group_commit(
    lookup: &dyn Fn(&str) -> Option<String>,
) -> yadorilink_local_storage::GroupCommitLimits {
    let mut limits = yadorilink_local_storage::GroupCommitLimits::from_lookup(lookup);
    if !cfg!(feature = "process-model") && lookup("YADORILINK_DIAGNOSTIC_SEGMENT_READERS").is_none()
    {
        limits.max_cached_readers = EMBEDDED_CACHED_SEGMENT_READERS;
    }
    limits
}

/// What one engine is tuned to. See the module documentation.
#[derive(Debug, Clone)]
pub struct EngineTuning {
    /// Paths one reconciliation attempt carries at most.
    pub reconcile_paths_per_attempt: usize,
    /// Concurrent receive file assemblies of one engine.
    pub receive_write_permits: usize,
    /// Own-name entries of a receive pass settled at once.
    pub receive_write_concurrency: usize,
    /// Items a collector batch may carry.
    pub collector_flush_cap: usize,
    /// Whether file completions are batched.
    pub batch_completion: bool,
    /// Whether the open of a file's write is batched.
    pub batch_open: bool,
    /// How received files are flushed when not one by one.
    pub deferred_flush: Option<ReceivedFlushMode>,
    /// Whether the receive path's commits run on the blocking pool.
    pub receive_async_commit: bool,
    /// Obligations the provider projector handles per transaction.
    pub provider_projector_batch: usize,
    /// The total size of recovery items above which status warns.
    pub recovery_items_warn_bytes: u64,
    /// Relay selection for the substrate: `None` keeps the default relays, `Some("none")` turns
    /// relaying off, anything else is a comma-separated URL list.
    pub sync_relays: Option<String>,
    /// Block fetches in flight at once while a file is made present.
    pub block_fetch_concurrency: usize,
    /// Where the installation witness lives. The desktop daemon resolves the platform's
    /// location; an embedded host must name a directory outside the data area and outside what a
    /// backup restores and the system does not purge (`Persistent`), or opt into `BesideDatabase`. The default is
    /// `Unset`, which an embedded engine refuses to start with.
    pub witness: crate::install_witness::WitnessPlacement,
    /// The host's keychain holding the instance nonce that detects a copied or restored data area
    /// ([`crate::instance_nonce`]). `None` (the default): no such check.
    pub instance_nonce: Option<std::sync::Arc<dyn crate::instance_nonce::InstanceNonceKeychain>>,
    /// Group-commit bounds of the block store (a measurement seam).
    pub group_commit: yadorilink_local_storage::GroupCommitLimits,
    /// The user's home directory, which linking is warned about; `None` where the host has none.
    pub home_dir: Option<std::path::PathBuf>,
    /// Desktop only: the update manifest URL; `None` is the built-in channel.
    pub update_manifest_url: Option<String>,
    /// Desktop only: the install source an image declares for itself.
    pub install_source: Option<String>,
    /// Desktop only: whether this device offers management over the NAS admin service.
    pub offer_nas_admin: bool,
}

impl Default for EngineTuning {
    /// The production behaviour: what an unset environment selects.
    fn default() -> Self {
        Self::from_lookup(|_| None)
    }
}

impl EngineTuning {
    /// The tuning `lookup` selects, a setting it does not name staying at its default. Values
    /// that do not parse fall back to the default, as the variables always did.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let text = |name: &str| lookup(name);
        let deferred_raw = text(vars::DEFERRED_FSYNC);
        // A test build flushes per file unless the variable asks otherwise, so the many tests
        // that settle a received file by itself do not depend on the host's default. The default
        // itself is pinned through `parse_deferred_flush`.
        #[cfg(any(test, feature = "test-support"))]
        let deferred_flush = deferred_raw
            .as_deref()
            .and_then(|value| crate::local_convergence::parse_deferred_flush(Some(value)));
        #[cfg(not(any(test, feature = "test-support")))]
        let deferred_flush =
            crate::local_convergence::parse_deferred_flush(deferred_raw.as_deref());
        Self {
            reconcile_paths_per_attempt: crate::convergence::parse_reconcile_paths(
                text(vars::RECONCILE_PATHS).as_deref(),
            ),
            receive_write_permits: crate::local_convergence::parse_permits(
                text(vars::RECEIVE_WRITE_PERMITS).as_deref(),
            ),
            receive_write_concurrency: crate::local_convergence::parse_receive_write_concurrency(
                text(vars::RECEIVE_WRITE_CONCURRENCY).as_deref(),
            ),
            collector_flush_cap: crate::local_convergence::parse_collector_flush_cap(
                text(vars::COLLECTOR_FLUSH_CAP).as_deref(),
            ),
            batch_completion: crate::local_convergence::parse_batch_completion(
                text(vars::BATCH_COMPLETION).as_deref(),
            ),
            batch_open: crate::local_convergence::parse_batch_completion(
                text(vars::BATCH_OPEN).as_deref(),
            ),
            deferred_flush,
            receive_async_commit: text(vars::ASYNC_COMMIT).as_deref().map(str::trim) != Some("0"),
            provider_projector_batch: crate::provider_projector::batch_from(
                text(vars::PROJECTOR_BATCH).as_deref(),
            ),
            recovery_items_warn_bytes: text(vars::RECOVERY_ITEMS_WARN_BYTES)
                .and_then(|value| value.parse().ok())
                .unwrap_or(crate::preserved_items::RECOVERY_ITEMS_WARN_BYTES_DEFAULT),
            sync_relays: sync_relays(text(vars::SYNC_RELAYS)),
            block_fetch_concurrency:
                yadorilink_peer_session::peer_session::parse_block_fetch_concurrency(
                    text(vars::BLOCK_FETCH_CONCURRENCY).as_deref(),
                ),
            group_commit: group_commit(&lookup),
            home_dir: text("HOME").or_else(|| text("USERPROFILE")).map(std::path::PathBuf::from),
            witness: crate::install_witness::WitnessPlacement::default(),
            instance_nonce: None,
            update_manifest_url: text(vars::UPDATE_MANIFEST_URL),
            install_source: text(vars::INSTALL_SOURCE),
            // Only `1` or `true` turn it on; anything else, unset included, leaves it off.
            offer_nas_admin: text(vars::NAS_ADMIN_OFFER).is_some_and(|v| {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true")
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuned(pairs: &[(&str, &str)]) -> EngineTuning {
        EngineTuning::from_lookup(|name| {
            pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| (*value).to_owned())
        })
    }

    /// An engine nobody configured runs the production behaviour: what the compiled constants
    /// say, and nothing from the process environment.
    #[test]
    fn the_default_is_the_production_behaviour() {
        let defaults = EngineTuning::default();
        assert_eq!(
            defaults.reconcile_paths_per_attempt,
            crate::convergence::parse_reconcile_paths(None)
        );
        assert_eq!(defaults.receive_write_permits, crate::local_convergence::parse_permits(None));
        assert!(defaults.batch_completion);
        assert!(defaults.batch_open);
        assert!(defaults.receive_async_commit);
        // A test build is kept off public relays; a production build has no override.
        assert_eq!(
            defaults.sync_relays,
            cfg!(any(test, feature = "test-support")).then(|| "none".to_owned())
        );
        assert_eq!(
            defaults.block_fetch_concurrency,
            yadorilink_peer_session::peer_session::DEFAULT_BLOCK_FETCH_CONCURRENCY
        );
        assert_eq!(
            defaults.recovery_items_warn_bytes,
            crate::preserved_items::RECOVERY_ITEMS_WARN_BYTES_DEFAULT
        );
        assert_eq!(
            defaults.group_commit.max_cached_readers,
            if cfg!(feature = "process-model") {
                yadorilink_local_storage::DEFAULT_CACHED_SEGMENT_READERS
            } else {
                EMBEDDED_CACHED_SEGMENT_READERS
            }
        );
        assert!(!defaults.offer_nas_admin);
        assert_eq!(defaults.update_manifest_url, None);
        assert_eq!(defaults.install_source, None);
        assert_eq!(defaults.home_dir, None);
        // No placement is guessed: a host names one (or opts into beside-the-database).
        assert_eq!(defaults.witness, crate::install_witness::WitnessPlacement::Unset);
    }

    /// Each variable the desktop daemon always honoured selects its setting.
    #[test]
    fn every_variable_selects_its_setting() {
        let t = tuned(&[
            (vars::RECONCILE_PATHS, "24"),
            (vars::RECEIVE_WRITE_PERMITS, "7"),
            (vars::RECEIVE_WRITE_CONCURRENCY, "3"),
            (vars::COLLECTOR_FLUSH_CAP, "5"),
            (vars::BATCH_COMPLETION, "0"),
            (vars::BATCH_OPEN, "0"),
            (vars::ASYNC_COMMIT, "0"),
            (vars::PROJECTOR_BATCH, "11"),
            (vars::RECOVERY_ITEMS_WARN_BYTES, "4096"),
            (vars::SYNC_RELAYS, "none"),
            (vars::BLOCK_FETCH_CONCURRENCY, "9"),
            (vars::UPDATE_MANIFEST_URL, "https://updates.example.test/manifest.json"),
            (vars::INSTALL_SOURCE, "container"),
            (vars::NAS_ADMIN_OFFER, "true"),
            ("HOME", "/home/someone"),
        ]);
        assert_eq!(t.reconcile_paths_per_attempt, 24);
        assert_eq!(t.receive_write_permits, 7);
        assert_eq!(t.receive_write_concurrency, 3);
        assert_eq!(t.collector_flush_cap, 5);
        assert!(!t.batch_completion);
        assert!(!t.batch_open);
        assert!(!t.receive_async_commit);
        assert_eq!(t.provider_projector_batch, 11);
        assert_eq!(t.recovery_items_warn_bytes, 4096);
        assert_eq!(t.sync_relays.as_deref(), Some("none"));
        assert_eq!(t.block_fetch_concurrency, 9);
        assert_eq!(
            t.update_manifest_url.as_deref(),
            Some("https://updates.example.test/manifest.json")
        );
        assert_eq!(t.install_source.as_deref(), Some("container"));
        assert!(t.offer_nas_admin);
        assert_eq!(t.home_dir, Some(std::path::PathBuf::from("/home/someone")));
    }

    /// A value that does not parse keeps the default, as the variables always did.
    #[test]
    fn an_unusable_value_keeps_the_default() {
        let defaults = EngineTuning::default();
        let t = tuned(&[
            (vars::RECONCILE_PATHS, "not a number"),
            (vars::RECEIVE_WRITE_PERMITS, "0"),
            (vars::BLOCK_FETCH_CONCURRENCY, "-3"),
            (vars::RECOVERY_ITEMS_WARN_BYTES, "lots"),
        ]);
        assert_eq!(t.reconcile_paths_per_attempt, defaults.reconcile_paths_per_attempt);
        assert_eq!(t.receive_write_permits, defaults.receive_write_permits);
        assert_eq!(t.block_fetch_concurrency, defaults.block_fetch_concurrency);
        assert_eq!(t.recovery_items_warn_bytes, defaults.recovery_items_warn_bytes);
    }

    /// The setting reaches the code that uses it, with no environment involved: a state built
    /// over a coordinator tuned to one value sees that value, and an untuned one the default.
    #[test]
    fn a_coordinator_carries_its_own_tuning() {
        let dir = tempfile::tempdir().unwrap();
        let tuning = EngineTuning { receive_write_permits: 3, ..EngineTuning::default() };
        let coordinator = crate::replica_coordinator::ReplicaCoordinator::open_with(
            dir.path().join("a.db"),
            tuning,
        )
        .unwrap();
        assert_eq!(coordinator.tuning().receive_write_permits, 3);
        assert_eq!(coordinator.receive_write_gate().available_permits(), 3);
        let untuned =
            crate::replica_coordinator::ReplicaCoordinator::open(dir.path().join("b.db")).unwrap();
        assert_eq!(
            untuned.receive_write_gate().available_permits(),
            EngineTuning::default().receive_write_permits
        );
    }
}
