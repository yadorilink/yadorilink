//! `ResolveFolder`: the folder a command line names, found by the resolver every path-taking command uses,
//! for a plain linked folder and for a File Provider folder at its place in the file manager. A rewind runs
//! on the group it names, so the match is strict: an existing directory, in its canonical spelling, in the
//! place the file manager puts a File Provider folder, and the folder itself, not a path inside it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{DaemonControlRequest, ResolveFolderRequest};
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

fn state_with(links: &[(&str, &str)]) -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    for (path, group) in links {
        sync_state.link_repository().add_link(path, group).unwrap();
    }
    DaemonState::new("device-a".into(), sync_state, store)
}

async fn resolve(state: &Arc<DaemonState>, path: &Path) -> Result<String, String> {
    let context = crate::control_context::ControlContext::from_state(state.clone());
    let response = super::handle_request(
        &context,
        DaemonControlRequest {
            payload: Some(ReqPayload::ResolveFolder(ResolveFolderRequest {
                path: path.to_string_lossy().into_owned(),
            })),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await;
    match response.payload.expect("a response payload") {
        RespPayload::ResolveFolder(found) => Ok(found.group_id),
        RespPayload::Error(message) => Err(message),
        other => panic!("unexpected {other:?}"),
    }
}

fn canonical_tmp() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    (dir, root)
}

#[tokio::test]
async fn a_plain_linked_folder_resolves_to_its_group_and_a_path_inside_it_is_refused() {
    let (_guard, root) = canonical_tmp();
    std::fs::create_dir(root.join("sub")).unwrap();
    let state = state_with(&[(root.to_str().unwrap(), "group-plain")]);
    assert_eq!(resolve(&state, &root).await, Ok("group-plain".to_string()));
    assert_eq!(resolve(&state, &root.join(".")).await, Ok("group-plain".to_string()));
    let inside = resolve(&state, &root.join("sub")).await.unwrap_err();
    assert!(inside.contains("not the folder itself"), "{inside}");
    let elsewhere = resolve(&state, Path::new("/definitely/not/linked")).await.unwrap_err();
    assert!(elsewhere.contains("is not a linked folder"), "{elsewhere}");
}

// macOS locations only: a Windows provider folder is found through the host's record of its sync roots.
#[cfg(not(windows))]
mod file_provider {
    use super::*;
    use yadorilink_replica_domain::session_state::ProviderKind;

    /// Two provider folders, Photos and Docs, with their locations made where the file manager puts them
    /// (inside a temporary stand-in for the home directory).
    fn fixture() -> (tempfile::TempDir, PathBuf, Arc<DaemonState>) {
        let (guard, home) = canonical_tmp();
        let cloud = home.join("Library/CloudStorage");
        std::fs::create_dir_all(cloud.join("YadoriLink-Photos/trips")).unwrap();
        std::fs::create_dir_all(cloud.join("YadoriLink-Docs")).unwrap();
        let state =
            state_with(&[("provider://t1", "group-photos"), ("provider://t2", "group-docs")]);
        let repo = state.replica_coordinator.provider_repository();
        repo.declare_root("group-photos", ProviderKind::MacFileProvider, "Photos").unwrap();
        repo.declare_root("group-docs", ProviderKind::MacFileProvider, "Docs").unwrap();
        (guard, cloud, state)
    }

    #[tokio::test]
    async fn the_folder_itself_resolves_and_a_path_inside_it_is_refused() {
        let (_guard, cloud, state) = fixture();
        let photos = cloud.join("YadoriLink-Photos");
        assert_eq!(resolve(&state, &photos).await, Ok("group-photos".to_string()));
        assert_eq!(resolve(&state, &photos.join("trips/..")).await, Ok("group-photos".to_string()));
        assert_eq!(
            resolve(&state, &cloud.join("YadoriLink-Docs")).await,
            Ok("group-docs".to_string())
        );
        let inside = resolve(&state, &photos.join("trips")).await.unwrap_err();
        assert!(inside.contains("not the folder itself"), "{inside}");
    }

    #[tokio::test]
    async fn a_look_alike_elsewhere_is_not_the_folder() {
        let (_guard, cloud, state) = fixture();
        // an ordinary directory (and a file) named like a provider folder, outside the file manager's place
        let (_other_guard, other) = canonical_tmp();
        std::fs::create_dir_all(other.join("CloudStorage/Backup-Photos")).unwrap();
        std::fs::write(other.join("CloudStorage/Notes-Photos"), b"x").unwrap();
        for path in
            [other.join("CloudStorage/Backup-Photos"), other.join("CloudStorage/Notes-Photos")]
        {
            let refused = resolve(&state, &path).await.unwrap_err();
            assert!(refused.contains("is not a linked folder"), "{}: {refused}", path.display());
        }
        // a file in the right place, a location of no provider folder, and one that only ends alike
        std::fs::write(cloud.join("YadoriLink-Photos/a.txt"), b"x").unwrap();
        std::fs::create_dir_all(cloud.join("YadoriLinkPhotos")).unwrap();
        // another provider's folder in the same place whose name ends in the same display name
        std::fs::create_dir_all(cloud.join("OneDrive-Photos")).unwrap();
        for path in [
            cloud.join("YadoriLink-Photos/a.txt"),
            cloud.join("YadoriLinkPhotos"),
            cloud.join("OneDrive-Photos"),
        ] {
            let refused = resolve(&state, &path).await.unwrap_err();
            assert!(refused.contains("is not a linked folder"), "{}: {refused}", path.display());
        }
    }

    #[tokio::test]
    async fn a_symlink_names_the_folder_it_points_to_not_its_own_spelling() {
        let (_guard, cloud, state) = fixture();
        // `Alias-Photos` is spelled like the Photos folder but points at Docs
        std::os::unix::fs::symlink(cloud.join("YadoriLink-Docs"), cloud.join("Alias-Photos"))
            .unwrap();
        assert_eq!(
            resolve(&state, &cloud.join("Alias-Photos")).await,
            Ok("group-docs".to_string())
        );
        // and a link from elsewhere to the Photos folder names Photos
        let (_other_guard, other) = canonical_tmp();
        std::os::unix::fs::symlink(cloud.join("YadoriLink-Photos"), other.join("p")).unwrap();
        assert_eq!(resolve(&state, &other.join("p")).await, Ok("group-photos".to_string()));
    }
}
