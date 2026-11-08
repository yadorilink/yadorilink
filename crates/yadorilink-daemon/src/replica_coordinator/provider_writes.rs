//! The provider-root writes of an engine, as one capability.
//!
//! Provider state (declared roots, minted items, announcements, download evidence) is changed
//! only through [`ProviderWrites`]; reads stay on [`super::ReplicaCoordinator::provider_repository`].
//! A guard test keeps these writes off the raw repository handle in production code. Applying a
//! File Provider change is not here: it already requires a root-commit permit.

use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_sync_sqlite::provider::{Announced, DownloadFailure, ItemId, ProviderRepository};
use yadorilink_sync_sqlite::SyncSqliteError;

/// Writes to the provider rows of one engine's database.
pub(crate) struct ProviderWrites<'a>(pub(super) &'a ProviderRepository);

type Result<T> = std::result::Result<T, SyncSqliteError>;

impl ProviderWrites<'_> {
    #[cfg(test)]
    pub(crate) fn declare_root(
        &self,
        group_id: &str,
        kind: yadorilink_replica_domain::session_state::ProviderKind,
        display_name: &str,
    ) -> Result<String> {
        self.0.declare_root(group_id, kind, display_name)
    }

    pub(crate) fn set_domain_registered(&self, root_id: &str, registered: bool) -> Result<bool> {
        self.0.set_domain_registered(root_id, registered)
    }

    pub(crate) fn domain_removed(&self, root_id: &str, preserved_location: &str) -> Result<bool> {
        self.0.domain_removed(root_id, preserved_location)
    }

    pub(crate) fn record_extension_handshake(
        &self,
        root_id: &str,
        now_unix_nanos: i64,
    ) -> Result<bool> {
        self.0.record_extension_handshake(root_id, now_unix_nanos)
    }

    pub(crate) fn record_provider_error(&self, root_id: &str, description: &str) -> Result<bool> {
        self.0.record_provider_error(root_id, description)
    }

    pub(crate) fn set_namespace_ready(&self, root_id: &str, ready: bool) -> Result<bool> {
        self.0.set_namespace_ready(root_id, ready)
    }

    pub(crate) fn rebootstrap_root(&self, group_id: &str) -> Result<String> {
        self.0.rebootstrap_root(group_id)
    }

    pub(crate) fn mint_item(&self, root_id: &str, path: &str) -> Result<ItemId> {
        self.0.mint_item(root_id, path)
    }

    pub(crate) fn record_handoff(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
    ) -> Result<Option<u64>> {
        self.0.record_handoff(root_id, item_id, version)
    }

    pub(crate) fn record_window_serve(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
    ) -> Result<Option<u64>> {
        self.0.record_window_serve(root_id, item_id, version)
    }

    pub(crate) fn announce_version(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
        now_ms: i64,
    ) -> Result<Option<Announced>> {
        self.0.announce_version(root_id, item_id, version, now_ms)
    }

    pub(crate) fn release_expired(
        &self,
        root_id: &str,
        item_id: &ItemId,
        now_ms: i64,
        release_after_ms: i64,
    ) -> Result<bool> {
        self.0.release_expired(root_id, item_id, now_ms, release_after_ms)
    }

    pub(crate) fn record_download_failure(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
        now_ms: i64,
        delay_ms: impl Fn(u32) -> i64,
    ) -> Result<Option<DownloadFailure>> {
        self.0.record_download_failure(root_id, item_id, version, now_ms, delay_ms)
    }

    pub(crate) fn record_download_rejection(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
        next_attempt_ms: i64,
    ) -> Result<()> {
        self.0.record_download_rejection(root_id, item_id, version, next_attempt_ms)
    }

    pub(crate) fn clear_download_failure(&self, root_id: &str, item_id: &ItemId) -> Result<()> {
        self.0.clear_download_failure(root_id, item_id)
    }

    pub(crate) fn reopen_stale_handoff(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
    ) -> Result<bool> {
        self.0.reopen_stale_handoff(root_id, item_id, version)
    }

    pub(crate) fn project_batch(&self, group_id: &str, limit: usize) -> Result<usize> {
        self.0.project_batch(group_id, limit)
    }

    pub(crate) fn mark_announced(&self, root_id: &str, changes: u64) -> Result<()> {
        self.0.mark_announced(root_id, changes)
    }
}

#[cfg(test)]
mod tests {
    /// The raw-handle writes named in `production`, chained or through a `repo` binding.
    fn raw_writes(rel: &str, production: &str, mutators: &[&str]) -> Vec<String> {
        let squeezed: String = production.split_whitespace().collect();
        let mut found = Vec::new();
        for name in mutators {
            for receiver in [".provider_repository().", "repo.", "(repo."] {
                let call = format!("{receiver}{name}(");
                if squeezed.contains(&call) {
                    found.push(format!("{rel}: {receiver}{name}"));
                }
            }
        }
        found
    }

    /// Provider state is written only through the capability in production code outside the
    /// coordinator module, chained or through a `repo` binding.
    #[test]
    fn production_code_writes_provider_rows_only_through_the_capability() {
        const MUTATORS: &[&str] = &[
            "declare_root",
            "declare_empty_root",
            "set_domain_registered",
            "domain_removed",
            "record_extension_handshake",
            "record_provider_error",
            "set_namespace_ready",
            "mark_install_done",
            "rebootstrap_root",
            "mint_item",
            "record_handoff",
            "record_window_serve",
            "announce_version",
            "release_expired",
            "record_download_failure",
            "record_download_rejection",
            "clear_download_failure",
            "reopen_stale_handoff",
            "mark_announced",
            "retire_item",
            "retention_changed",
            "project_batch",
            "publish_first",
        ];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let (mut offenders, mut scanned) = (Vec::new(), 0usize);
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
                if !rel.ends_with(".rs")
                    || rel.ends_with("tests.rs")
                    || rel.ends_with("_tests.rs")
                    || rel.contains("/tests/")
                    || rel.starts_with("test_support")
                    || rel.starts_with("replica_coordinator")
                {
                    continue;
                }
                scanned += 1;
                let text = std::fs::read_to_string(&path).unwrap();
                let production = text.split("#[cfg(test)]").next().unwrap();
                offenders.extend(raw_writes(&rel, production, MUTATORS));
            }
        }
        assert!(scanned > 50, "the scan found only {scanned} production files");
        assert!(
            offenders.is_empty(),
            "provider rows written through the raw handle: {offenders:?}"
        );
    }
}
