//! What the control socket's `DeleteGroupCommand` calls, directly, to
//! terminally delete a folder group this account owns -- the coordination
//! plane's own `deleteFolderGroup`, not subject to the last-full-replica
//! guard `revoke` is (the group ceases to exist, so there is no group left
//! to protect). Exists so a device that is
//! the sole remaining full replica for an abandoned group -- one it can
//! never `share revoke` itself out of, by design -- has a way back to a
//! clean state: delete the group outright rather than leave it authorized
//! and unreachable forever.

use super::common::BoxFuture;

pub(crate) trait GroupAdministration: Send + Sync {
    /// Deletes `group_id` outright: the group and every ACL edge on it,
    /// gone, with an updated netmap pushed to every former member. `Err`
    /// carries the coordination plane's own reason, most commonly an
    /// unacknowledged cross-account member (see the CLI's own
    /// `--acknowledge-cross-account-members` flag).
    fn delete_folder_group<'a>(
        &'a self,
        group_id: &'a str,
        acknowledge_cross_account_members: bool,
    ) -> BoxFuture<'a, Result<(), String>>;
}
