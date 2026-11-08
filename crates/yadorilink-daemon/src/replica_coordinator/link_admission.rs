//! The link-row writes of an engine, as one capability.
//!
//! A link row decides which folders and providers an engine serves, so writing one is an
//! admission decision, not a repository convenience. Everything outside the coordinator that
//! adds, removes, pauses or re-policies a link goes through [`LinkAdmission`]; reads stay on
//! [`super::ReplicaCoordinator::link_repository`]. A guard test keeps these writes off the raw
//! repository handle.

use yadorilink_replica_domain::session_state::LinkRowWrite;
use yadorilink_sync_sqlite::link::LinkRepository;
use yadorilink_sync_sqlite::SyncSqliteError;

use yadorilink_replica_domain::session_state::MaterializationPolicy;

/// Writes to the link rows of one engine's database.
pub(crate) struct LinkAdmission<'a>(pub(super) &'a LinkRepository);

type Result<T> = std::result::Result<T, SyncSqliteError>;

impl LinkAdmission<'_> {
    pub(crate) fn add_link(&self, local_path: &str, group_id: &str) -> Result<LinkRowWrite> {
        self.0.add_link(local_path, group_id)
    }

    pub(crate) fn add_provider_link(
        &self,
        local_path: &str,
        group_id: &str,
        provider: &yadorilink_sync_sqlite::provider::ProviderLinkSpec,
    ) -> Result<LinkRowWrite> {
        self.0.add_provider_link(local_path, group_id, provider)
    }

    pub(crate) fn undo_link_row(
        &self,
        local_path: &str,
        group_id: &str,
        write: &LinkRowWrite,
    ) -> Result<&'static str> {
        self.0.undo_link_row(local_path, group_id, write)
    }

    pub(crate) fn mark_link_orphaned(&self, local_path: &str) -> Result<()> {
        self.0.mark_link_orphaned(local_path)
    }

    pub(crate) fn set_materialization_policy(
        &self,
        local_path: &str,
        policy: MaterializationPolicy,
    ) -> Result<()> {
        self.0.set_materialization_policy(local_path, policy)
    }

    pub(crate) fn set_paused_expecting_group(
        &self,
        local_path: &str,
        paused: bool,
        expected_group: Option<&str>,
    ) -> Result<()> {
        self.0.set_paused_expecting_group(local_path, paused, expected_group)
    }

    pub(crate) fn confirm_capture_volume_identity(
        &self,
        local_path: &str,
        group_id: &str,
        identity: &str,
    ) -> Result<bool> {
        self.0.confirm_capture_volume_identity(local_path, group_id, identity)
    }

    pub(crate) fn pause_until_expecting_group(
        &self,
        local_path: &str,
        resume_at_unix: i64,
        expected_group: Option<&str>,
    ) -> Result<()> {
        self.0.pause_until_expecting_group(local_path, resume_at_unix, expected_group)
    }

    pub(crate) fn set_suppress_tombstones(&self, local_path: &str, suppress: bool) -> Result<()> {
        self.0.set_suppress_tombstones(local_path, suppress)
    }

    pub(crate) fn arm_duplicate_recovery_paths(&self, group_id: &str) -> Result<()> {
        self.0.arm_duplicate_recovery_paths(group_id)
    }

    pub(crate) fn resolve_duplicate_recovery_path(&self, group_id: &str, path: &str) -> Result<()> {
        self.0.resolve_duplicate_recovery_path(group_id, path)
    }

    pub(crate) fn remove_link_expecting_group(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<bool> {
        self.0.remove_link_expecting_group(local_path, group_id)
    }

    pub(crate) fn recheck_digest_then_set_materialization_policy(
        &self,
        group_id: &str,
        local_path: &str,
        policy: MaterializationPolicy,
        expected_digest: [u8; 32],
    ) -> Result<bool> {
        self.0.recheck_digest_then_set_materialization_policy(
            group_id,
            local_path,
            policy,
            expected_digest,
        )
    }

    pub(crate) fn recheck_digest_then_remove_link(
        &self,
        group_id: &str,
        local_path: &str,
        expected_digest: [u8; 32],
    ) -> Result<bool> {
        self.0.recheck_digest_then_remove_link(group_id, local_path, expected_digest)
    }
}

#[cfg(test)]
mod tests {
    /// The link-row writes the capability carries stay off the raw repository handle in
    /// production code outside the coordinator module. A `let links = ...link_repository();`
    /// binding is not seen; the chained form is what the code uses.
    #[test]
    fn production_code_writes_link_rows_only_through_the_capability() {
        const MUTATORS: &[&str] = &[
            "add_link",
            "add_provider_link",
            "undo_link_row",
            "mark_link_orphaned",
            "set_materialization_policy",
            "set_paused_expecting_group",
            "pause_until_expecting_group",
            "set_suppress_tombstones",
            "arm_duplicate_recovery_paths",
            "resolve_duplicate_recovery_path",
            "remove_link_expecting_group",
            "recheck_digest_then_set_materialization_policy",
            "recheck_digest_then_remove_link",
            "confirm_capture_volume_identity",
            "remove_link",
            "set_paused",
            "pause_until",
            "insert_link_row",
            "set_link_root_token_for_group",
            "set_windows_symlink_opt_in",
            "set_capture_volume_identity_for_group",
        ];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        let mut stack = vec![src.clone()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
                let is_test_file = rel.ends_with("tests.rs")
                    || rel.ends_with("_tests.rs")
                    || rel.contains("/tests/")
                    || rel.starts_with("test_support")
                    || rel.starts_with("replica_coordinator");
                if !rel.ends_with(".rs") || is_test_file {
                    continue;
                }
                scanned += 1;
                let text = std::fs::read_to_string(&path).unwrap();
                let production = text.split("#[cfg(test)]").next().unwrap();
                let squeezed: String = production.split_whitespace().collect();
                for name in MUTATORS {
                    if squeezed.contains(&format!(".link_repository().{name}(")) {
                        offenders.push(format!("{rel}: link_repository().{name}"));
                    }
                }
            }
        }
        assert!(scanned > 50, "the scan found only {scanned} production files");
        assert!(offenders.is_empty(), "link rows written through the raw handle: {offenders:?}");
    }
}
