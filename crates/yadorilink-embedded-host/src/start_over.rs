//! Starting over as a new device on an embedded engine: the way out of a refused
//! (`database_restored`) replica database.
//!
//! It is the client layer's own operation (`yadorilink_client_core::ops::start_over`, the one the
//! desktop runs) over the engine's state directory, with this engine's ports:
//!
//! * the precondition (the database is refused as restored) is read from the running engine's
//!   own status, and the engine's link table is what is marked;
//! * nothing is restarted by the operation. The desktop restarts or launches its daemon process
//!   around the steps; an embedded engine is restarted by its host (`EmbeddedHost::suspend`,
//!   then `resume`), which no command can do from inside the engine's own runtime. The engine
//!   that is running while the operation runs keeps its old identity and refuses to author with
//!   it, so nothing is written as the retired device meanwhile. Every account step reads the
//!   credential store, the key and `device.json` of the state directory itself, never the
//!   engine's loaded copies, so none of them needs the restart;
//! * a folder is never joined again by this operation (an embedded engine's folders are provider
//!   folders, linked from the provider folder list): each linked folder is marked as needing the
//!   person instead, which stops it taking part in sync and keeps it visible across restarts
//!   until it is linked again. Files are never touched.
//!
//! The engine's installation witness needs no step of its own: the engine opens the database as
//! the new device, which holds no author of the database's old device, and the witness starts
//! over there (`install_witness::judge_with`), in the database and in the host's witness
//! directory, so the next start is clean.

use std::path::{Path, PathBuf};

use yadorilink_client_core::coordination::credential_store::{self, CredentialSettings};
use yadorilink_client_core::error::CoreError;
use yadorilink_client_core::ops::device_supersede::{
    supersede_device_in, SupersedeError, SupersedeResponse,
};
use yadorilink_client_core::ops::start_over::{LinkedFolder, StartOverPorts};
use yadorilink_daemon::embedded_host::EngineCommands;

/// The embedded engine as the start over's ports.
pub(crate) struct EmbeddedPorts<'a> {
    pub(crate) dir: &'a Path,
    pub(crate) settings: &'a CredentialSettings,
    pub(crate) commands: &'a EngineCommands,
}

fn core(error: impl std::fmt::Display) -> CoreError {
    CoreError::Other(error.to_string())
}

impl StartOverPorts for EmbeddedPorts<'_> {
    fn state_dir(&self) -> Result<PathBuf, CoreError> {
        Ok(self.dir.to_path_buf())
    }

    async fn database_restored(&self) -> Result<bool, CoreError> {
        let status = self.commands.status().map_err(core)?;
        Ok(status.attention_reasons.iter().any(|reason| reason.starts_with("database_restored")))
    }

    fn registered_device_id(&self) -> Option<String> {
        yadorilink_client_core::coordination::device_config::load_in(self.dir)
            .ok()
            .map(|config| config.device_id)
    }

    fn installation_id(&self) -> Result<Option<String>, CoreError> {
        Ok(credential_store::installation_in(self.dir, self.settings)?
            .map(|credentials| credentials.client_id().to_owned()))
    }

    async fn sign_out(&self) -> Result<(), CoreError> {
        // The key-mirror cleanup warning is dropped on purpose: the retired identity is already
        // revoked, and the new device key is written over the same entry right after.
        yadorilink_client_core::ops::auth::sign_out_in(self.dir, self.settings).await.map(|_| ())
    }

    fn replace_signing_key(&self, key: &Path, retired_key: &Path) -> Result<(), CoreError> {
        yadorilink_transport::DeviceSigningKeyPair::replace_retiring(
            key,
            retired_key,
            self.settings.key_mirror,
        )
        .map(|_| ())
        .map_err(core)
    }

    fn can_rejoin(&self) -> bool {
        false
    }

    async fn restart_daemon_if_running(&self) -> Result<(), CoreError> {
        // The host restarts the engine (module docs): nothing to restart from inside it.
        Ok(())
    }

    async fn ensure_daemon_running(&self) -> Result<(), CoreError> {
        // The engine is the process that is running this call.
        Ok(())
    }

    async fn register(&self, name: String) -> Result<String, CoreError> {
        yadorilink_client_core::ops::devices::register_device_in(self.dir, self.settings, name)
            .await
    }

    async fn supersede(
        &self,
        retired_device_id: &str,
        new_device_id: &str,
    ) -> Result<SupersedeResponse, SupersedeError> {
        supersede_device_in(self.dir, self.settings, retired_device_id, new_device_id).await
    }

    async fn linked_folders(&self) -> Result<Vec<LinkedFolder>, CoreError> {
        Ok(self
            .commands
            .linked_folders()
            .map_err(core)?
            .into_iter()
            .map(|folder| LinkedFolder {
                local_path: folder.key,
                group_id: folder.group_id,
                on_demand: folder.on_demand,
            })
            .collect())
    }

    async fn joinable_group_names(&self) -> Result<Vec<(String, String)>, CoreError> {
        // Not called while `can_rejoin` is false; empty rather than a guess if that ever changes.
        Ok(Vec::new())
    }

    async fn rejoin(&self, _folder: &LinkedFolder, _group_name: &str) -> Result<(), CoreError> {
        Err(core("an embedded engine does not join a folder group again by itself"))
    }

    async fn promote_to_eager(
        &self,
        _folder: &LinkedFolder,
        _group_name: &str,
    ) -> Result<(), CoreError> {
        Err(core("an embedded engine does not join a folder group again by itself"))
    }

    async fn mark_not_rejoined(&self, folder: &LinkedFolder) -> Result<(), CoreError> {
        self.commands.mark_not_rejoined(&folder.local_path).await.map_err(core)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};

    use yadorilink_client_core::dto::StartOverProgress;
    use yadorilink_client_core::DesktopError;

    use yadorilink_client_core::error::RefusalReason;

    use super::*;
    use crate::account::AccountCommands;

    /// A machine with a refused database whose start over can run to its end offline.
    struct Machine {
        dir: tempfile::TempDir,
        installation: Mutex<Option<String>>,
        calls: Mutex<Vec<&'static str>>,
    }

    impl Machine {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("device.json"), "{}").unwrap();
            Self {
                dir,
                installation: Mutex::new(Some("install-0".into())),
                calls: Mutex::new(Vec::new()),
            }
        }
        fn log(&self, call: &'static str) {
            self.calls.lock().unwrap().push(call);
        }
        fn calls(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    impl StartOverPorts for Machine {
        fn state_dir(&self) -> Result<PathBuf, CoreError> {
            Ok(self.dir.path().to_path_buf())
        }
        // The engine's stale report: refused until it is restarted, whatever was done since.
        async fn database_restored(&self) -> Result<bool, CoreError> {
            Ok(true)
        }
        fn registered_device_id(&self) -> Option<String> {
            self.dir.path().join("device.json").exists().then(|| "device".to_owned())
        }
        fn installation_id(&self) -> Result<Option<String>, CoreError> {
            Ok(self.installation.lock().unwrap().clone())
        }
        async fn sign_out(&self) -> Result<(), CoreError> {
            self.log("sign_out");
            *self.installation.lock().unwrap() = None;
            Ok(())
        }
        fn replace_signing_key(&self, _: &Path, _: &Path) -> Result<(), CoreError> {
            self.log("replace_signing_key");
            Ok(())
        }
        fn can_rejoin(&self) -> bool {
            false
        }
        async fn restart_daemon_if_running(&self) -> Result<(), CoreError> {
            Ok(())
        }
        async fn ensure_daemon_running(&self) -> Result<(), CoreError> {
            Ok(())
        }
        async fn register(&self, _: String) -> Result<String, CoreError> {
            self.log("register");
            std::fs::write(self.dir.path().join("device.json"), "{}").unwrap();
            Ok("new-device".into())
        }
        async fn supersede(
            &self,
            old: &str,
            new: &str,
        ) -> Result<SupersedeResponse, SupersedeError> {
            Ok(SupersedeResponse {
                old_device_id: old.into(),
                new_device_id: new.into(),
                superseded_at_unix: 1,
                protection: "healthy".into(),
                unconfirmed_group_ids: Vec::new(),
            })
        }
        async fn linked_folders(&self) -> Result<Vec<LinkedFolder>, CoreError> {
            Ok(Vec::new())
        }
        async fn joinable_group_names(&self) -> Result<Vec<(String, String)>, CoreError> {
            Ok(Vec::new())
        }
        async fn rejoin(&self, _: &LinkedFolder, _: &str) -> Result<(), CoreError> {
            unreachable!()
        }
        async fn promote_to_eager(&self, _: &LinkedFolder, _: &str) -> Result<(), CoreError> {
            unreachable!()
        }
        async fn mark_not_rejoined(&self, _: &LinkedFolder) -> Result<(), CoreError> {
            Ok(())
        }
    }

    fn commands_over(dir: &Path) -> AccountCommands {
        let settings = CredentialSettings::new(
            yadorilink_daemon::embedded_host::CredentialBackend::File(dir.join("credentials.json")),
            yadorilink_daemon::embedded_host::KeyMirror::Disabled,
        );
        AccountCommands::new(
            dir.to_path_buf(),
            settings.clone(),
            crate::account::product_sign_in(settings),
            Arc::new(AtomicU64::new(1)),
        )
    }

    fn refused_as(
        result: Result<StartOverProgress, DesktopError>,
        expected: yadorilink_client_core::error::RefusalReason,
    ) -> bool {
        matches!(result, Err(DesktopError::Refused { reason, .. }) if reason == expected)
    }

    /// The invariant: after a start over finished, the engine (whose report of the refused
    /// database is stale until it restarts) starts no other: a repeated call (a retry after a
    /// deadline, a double tap, a host that did not restart) is refused and changes nothing. A new
    /// engine (the restart) starts over again when its database is refused again.
    #[tokio::test]
    async fn no_second_start_over_on_an_engine_that_has_not_restarted_since_one_finished() {
        let machine = Machine::new();
        let engine = commands_over(machine.dir.path());

        let first = engine.start_over_with(&machine, true, "phone".into()).await.unwrap();
        assert!(matches!(first, StartOverProgress::SignInRequired { .. }), "{first:?}");
        // A continuation after the sign-in finishes it.
        *machine.installation.lock().unwrap() = Some("install-1".into());
        let done = engine.start_over_with(&machine, false, "phone".into()).await.unwrap();
        assert!(matches!(done, StartOverProgress::Finished { ref report } if report.complete));
        let calls = machine.calls();

        // Retry / double call: refused, nothing was touched (no sign-out of the new sign-in, no
        // key replaced, no journal, the new device record stays).
        assert!(refused_as(
            engine.start_over_with(&machine, true, "phone".into()).await,
            RefusalReason::StartOverRestartRequired
        ));
        assert!(refused_as(
            engine.start_over_with(&machine, true, "phone".into()).await,
            RefusalReason::StartOverRestartRequired
        ));
        assert_eq!(machine.calls(), calls);
        assert_eq!(machine.installation.lock().unwrap().as_deref(), Some("install-1"));
        assert!(machine.dir.path().join("device.json").exists());
        assert!(!yadorilink_client_core::ops::start_over::pending_in(machine.dir.path()));

        // The restart: a new engine over the same directory (refused again) may start over.
        let restarted = commands_over(machine.dir.path());
        let again = restarted.start_over_with(&machine, true, "phone".into()).await.unwrap();
        assert!(matches!(again, StartOverProgress::SignInRequired { .. }), "{again:?}");
    }

    /// An unfinished start over is continued, never refused by the restart rule.
    #[tokio::test]
    async fn an_unfinished_start_over_is_continued_on_the_same_engine() {
        let machine = Machine::new();
        let engine = commands_over(machine.dir.path());
        let first = engine.start_over_with(&machine, true, "phone".into()).await.unwrap();
        assert!(matches!(first, StartOverProgress::SignInRequired { .. }));
        // Signed out still: the same call answers the same, and is not refused.
        let again = engine.start_over_with(&machine, false, "phone".into()).await.unwrap();
        assert!(matches!(again, StartOverProgress::SignInRequired { .. }), "{again:?}");
    }

    /// The engine-side ports on a real engine whose database is refused: the precondition reads
    /// the engine's own status, linked folders map their key, group and storage mode, and marking
    /// is reported as needing the person without touching a file inside it (that the folder's sync
    /// itself stops is not verified here: no runtime runs over a bare link row).
    #[test]
    fn marking_a_linked_folder_on_a_refused_engine_keeps_its_files() {
        use crate::{CallOptions, Command, CommandOutput, EmbeddedHost};
        use yadorilink_daemon::embedded_host::{
            CredentialBackend, CredentialConfig, EngineConfig, EngineTuning, KeyMirror,
            WitnessPlacement,
        };

        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        std::fs::create_dir_all(root.path().join("data")).unwrap();
        let settings = CredentialSettings::new(
            CredentialBackend::File(state.join("credentials.json")),
            KeyMirror::Disabled,
        );
        let witness = root.path().join("witness");
        let config = EngineConfig {
            credentials: CredentialConfig::new(
                CredentialBackend::File(state.join("credentials.json")),
                KeyMirror::Disabled,
            ),
            config_dir: state.clone(),
            block_store_root: root.path().join("blocks"),
            sync_db_path: root.path().join("data/sync.sqlite3"),
            provider_temp_root: None,
            machine_id: Some("start-over-ports-test".to_owned()),
            tuning: EngineTuning {
                witness: WitnessPlacement::Persistent(witness.clone()),
                ..EngineTuning::default()
            },
        };
        std::fs::create_dir_all(&state).unwrap();
        yadorilink_transport::DeviceSigningKeyPair::load_or_generate(
            state.join("signing_key"),
            yadorilink_transport::KeyMirror::Disabled,
        )
        .unwrap();
        yadorilink_client_core::coordination::device_config::save_in(
            &state,
            &yadorilink_client_core::coordination::device_config::DeviceConfig {
                device_id: "device-1".into(),
                coordination_addr: "http://127.0.0.1:1".into(),
                signing_public_key: String::new(),
                config_version: yadorilink_client_core::coordination::device_config::CONFIG_VERSION,
            },
        )
        .unwrap();
        let linked = root.path().join("linked");
        std::fs::create_dir_all(&linked).unwrap();
        std::fs::write(linked.join("photo.jpg"), b"my photo").unwrap();
        let options = CallOptions::default;

        // A healthy start records the witness; a link row (an on-demand one) is added on it.
        let host = EmbeddedHost::new(config);
        host.start().unwrap();
        host.add_link_row_for_test(&linked.to_string_lossy(), "g1", true).unwrap();
        host.stop().unwrap();

        // The persistent copy goes missing: the next engine is refused.
        for entry in std::fs::read_dir(&witness).unwrap() {
            std::fs::remove_file(entry.unwrap().path()).unwrap();
        }
        host.start().unwrap();
        let CommandOutput::Folders(before) =
            host.execute(Command::ListFolders, &options()).unwrap()
        else {
            panic!("folders")
        };
        assert_eq!(before[0].degraded, None, "not marked before");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = seen.clone();
        let (dir, ports_settings) = (state.clone(), settings);
        host.execute_owning_for_test(
            false,
            || {},
            move |commands| async move {
                let ports =
                    EmbeddedPorts { dir: &dir, settings: &ports_settings, commands: &commands };
                let restored = ports.database_restored().await.unwrap();
                let folders = ports.linked_folders().await.unwrap();
                for folder in &folders {
                    ports.mark_not_rejoined(folder).await.unwrap();
                    // Again: idempotent.
                    ports.mark_not_rejoined(folder).await.unwrap();
                }
                record.lock().unwrap().push((restored, folders));
                Ok(CommandOutput::Done)
            },
            &options(),
        )
        .unwrap();
        let seen = seen.lock().unwrap();
        let (restored, folders) = &seen[0];
        assert!(restored, "the refused engine reports it");
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].local_path, linked.to_string_lossy());
        assert_eq!(folders[0].group_id, "g1");
        assert!(folders[0].on_demand, "the storage mode is mapped");
        assert_eq!(std::fs::read(linked.join("photo.jpg")).unwrap(), b"my photo");
        let CommandOutput::Folders(after) = host.execute(Command::ListFolders, &options()).unwrap()
        else {
            panic!("folders")
        };
        assert_eq!(after.len(), 1, "the row stays");
        assert!(
            after[0].degraded.as_deref().is_some_and(|reason| reason.contains("not joined")),
            "marked as needing the person: {:?}",
            after[0].degraded
        );
        host.stop().unwrap();
    }
}
