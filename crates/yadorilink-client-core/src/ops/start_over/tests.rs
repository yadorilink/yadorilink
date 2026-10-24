#![cfg(test)]

use std::sync::Mutex;

use super::*;

/// What the fake service answers to the supersede claim.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Supersede {
    Healthy,
    Unconfirmed,
    /// Unconfirmed for the on-demand folder `g2`.
    UnconfirmedOnDemand,
    Reauthenticate,
    AlreadyReplaced,
    Offline,
    Mismatch,
    /// Decides like the service: by the installation the new device is registered to and by
    /// which installations signed out or hold a stale sign-in.
    ByBinding,
}

struct Fake {
    /// The installation the new device is registered to (`ByBinding`).
    bound_to: Mutex<Option<String>>,
    /// Installations that were signed out (their authority is revoked).
    signed_out: Mutex<Vec<String>>,
    /// Installations whose sign-in is older than the service accepts.
    stale: Mutex<Vec<String>>,
    supersede_mode: Mutex<Supersede>,
    dir: tempfile::TempDir,
    calls: Mutex<Vec<String>>,
    restored: Mutex<Result<bool, String>>,
    /// The installation the credential store holds, if any.
    installation: Mutex<Option<String>>,
    sign_ins: Mutex<u32>,
    device_id: Mutex<Option<String>>,
    sign_out_fails: Mutex<bool>,
    replace_key_fails: Mutex<bool>,
    folders: Vec<LinkedFolder>,
    owned_groups: Vec<(String, String)>,
    failing_group: Mutex<Option<String>>,
    mark_fails: Mutex<bool>,
    mark_fails_for: Mutex<Option<String>>,
    marked: Mutex<Vec<String>>,
    promote_fails: Mutex<bool>,
    /// The installation the running daemon authenticates as: fixed when it starts.
    daemon_installation: Mutex<Option<String>>,
    restart_fails: Mutex<bool>,
    /// Whether the host joins folders again itself (false: the embedded engine).
    rejoins: bool,
}

impl Fake {
    fn restored_sole_device() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("device.json"), "{}").unwrap();
        std::fs::write(dir.path().join("signing_key"), "old").unwrap();
        Self {
            bound_to: Mutex::new(None),
            signed_out: Mutex::new(Vec::new()),
            stale: Mutex::new(Vec::new()),
            supersede_mode: Mutex::new(Supersede::Healthy),
            dir,
            calls: Mutex::new(Vec::new()),
            restored: Mutex::new(Ok(true)),
            installation: Mutex::new(Some("install-0".into())),
            sign_ins: Mutex::new(0),
            device_id: Mutex::new(Some("old-device".into())),
            sign_out_fails: Mutex::new(false),
            replace_key_fails: Mutex::new(false),
            folders: vec![
                LinkedFolder {
                    local_path: "/data/docs".into(),
                    group_id: "g1".into(),
                    on_demand: false,
                },
                LinkedFolder {
                    local_path: "/data/photos".into(),
                    group_id: "g2".into(),
                    on_demand: true,
                },
            ],
            owned_groups: vec![("g1".into(), "docs".into()), ("g2".into(), "photos".into())],
            failing_group: Mutex::new(None),
            mark_fails: Mutex::new(false),
            mark_fails_for: Mutex::new(None),
            marked: Mutex::new(Vec::new()),
            promote_fails: Mutex::new(false),
            daemon_installation: Mutex::new(Some("install-0".into())),
            restart_fails: Mutex::new(false),
            rejoins: true,
        }
    }

    fn log(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The person signs in again; the next registration is a new device.
    fn sign_in(&self) {
        let mut sign_ins = self.sign_ins.lock().unwrap();
        *sign_ins += 1;
        *self.installation.lock().unwrap() = Some(format!("install-{sign_ins}"));
    }
}

impl StartOverPorts for Fake {
    fn state_dir(&self) -> Result<PathBuf, CoreError> {
        Ok(self.dir.path().to_path_buf())
    }

    async fn database_restored(&self) -> Result<bool, CoreError> {
        self.log("database_restored");
        self.restored.lock().unwrap().clone().map_err(|_| CoreError::DaemonNotRunning)
    }

    fn registered_device_id(&self) -> Option<String> {
        // `device.json` is the record of the registration.
        if self.path("device.json").exists() {
            self.device_id.lock().unwrap().clone()
        } else {
            None
        }
    }

    fn installation_id(&self) -> Result<Option<String>, CoreError> {
        Ok(self.installation.lock().unwrap().clone())
    }

    async fn sign_out(&self) -> Result<(), CoreError> {
        self.log("sign_out");
        if *self.sign_out_fails.lock().unwrap() {
            return Err(CoreError::AuthFailed("cannot confirm".into()));
        }
        if let Some(installation) = self.installation.lock().unwrap().take() {
            self.signed_out.lock().unwrap().push(installation);
        }
        Ok(())
    }

    fn replace_signing_key(&self, key: &Path, retired_key: &Path) -> Result<(), CoreError> {
        self.log("replace_signing_key");
        if *self.replace_key_fails.lock().unwrap() {
            return Err(CoreError::Other("write error".into()));
        }
        // Like the real replacement: running it again never retires the new key.
        if !retired_key.exists() {
            std::fs::write(retired_key, std::fs::read(key)?)?;
        }
        std::fs::write(key, "new")?;
        Ok(())
    }

    fn can_rejoin(&self) -> bool {
        self.rejoins
    }

    async fn restart_daemon_if_running(&self) -> Result<(), CoreError> {
        self.log("restart_daemon");
        if *self.restart_fails.lock().unwrap() {
            // What the real restart reports (`ops::daemon`): the text and the next step.
            return Err(CoreError::Other("the running daemon did not stop".into())
                .hinted(crate::error::Hint::StopThenStartDaemon));
        }
        // The restarted daemon reads the stored sign-in.
        *self.daemon_installation.lock().unwrap() = self.installation.lock().unwrap().clone();
        Ok(())
    }

    async fn ensure_daemon_running(&self) -> Result<(), CoreError> {
        self.log("ensure_daemon");
        Ok(())
    }

    async fn register(&self, name: String) -> Result<String, CoreError> {
        self.log(format!("register:{name}"));
        std::fs::write(self.path("device.json"), "{}")?;
        *self.device_id.lock().unwrap() = Some("new-device".into());
        *self.bound_to.lock().unwrap() = self.installation.lock().unwrap().clone();
        Ok("new-device".into())
    }

    async fn supersede(
        &self,
        retired_device_id: &str,
        new_device_id: &str,
    ) -> Result<SupersedeResponse, SupersedeError> {
        self.log(format!("supersede:{retired_device_id}:{new_device_id}"));
        let mode = *self.supersede_mode.lock().unwrap();
        let answer = |protection: &str, groups: &[&str]| SupersedeResponse {
            old_device_id: retired_device_id.into(),
            new_device_id: new_device_id.into(),
            superseded_at_unix: 7,
            protection: protection.into(),
            unconfirmed_group_ids: groups.iter().map(|g| (*g).to_owned()).collect(),
        };
        match mode {
            Supersede::Healthy => Ok(answer("healthy", &[])),
            Supersede::Mismatch => Ok(SupersedeResponse {
                old_device_id: "someone-else".into(),
                ..answer("healthy", &[])
            }),
            Supersede::Unconfirmed => Ok(answer("replacement-unconfirmed", &["g1"])),
            Supersede::UnconfirmedOnDemand => Ok(answer("replacement-unconfirmed", &["g2"])),
            Supersede::Reauthenticate => Err(SupersedeError::ReauthenticationRequired),
            Supersede::AlreadyReplaced => Err(SupersedeError::AlreadyReplaced),
            Supersede::ByBinding => {
                let current = self.installation.lock().unwrap().clone().unwrap();
                if self.stale.lock().unwrap().contains(&current) {
                    return Err(SupersedeError::ReauthenticationRequired);
                }
                let mut bound = self.bound_to.lock().unwrap();
                let bound_to = bound.clone().unwrap();
                if bound_to != current && !self.signed_out.lock().unwrap().contains(&bound_to) {
                    return Err(SupersedeError::InstallationNotSignedOut);
                }
                *bound = Some(current);
                Ok(answer("healthy", &[]))
            }
            Supersede::Offline => Err(SupersedeError::Failed(
                CoreError::CoordinationPlaneUnreachable("offline".into()),
            )),
        }
    }

    async fn linked_folders(&self) -> Result<Vec<LinkedFolder>, CoreError> {
        Ok(self.folders.clone())
    }

    async fn joinable_group_names(&self) -> Result<Vec<(String, String)>, CoreError> {
        Ok(self.owned_groups.clone())
    }

    async fn rejoin(&self, folder: &LinkedFolder, group_name: &str) -> Result<(), CoreError> {
        self.log(format!(
            "rejoin:{}:{}:{}",
            group_name,
            folder.local_path,
            if folder.on_demand { "on-demand" } else { "eager" }
        ));
        if self.failing_group.lock().unwrap().as_deref() == Some(folder.group_id.as_str()) {
            return Err(CoreError::CoordinationPlaneUnreachable("offline".into()));
        }
        // A daemon that kept an earlier sign-in is refused, as the real one is.
        if *self.daemon_installation.lock().unwrap() != *self.installation.lock().unwrap() {
            return Err(CoreError::Other(
                "the sign-in changed after it started, so restart it".into(),
            ));
        }
        Ok(())
    }

    async fn promote_to_eager(
        &self,
        folder: &LinkedFolder,
        group_name: &str,
    ) -> Result<(), CoreError> {
        self.log(format!("promote:{}:{}", group_name, folder.local_path));
        if *self.promote_fails.lock().unwrap() {
            return Err(CoreError::DaemonNotRunning);
        }
        Ok(())
    }

    async fn mark_not_rejoined(&self, folder: &LinkedFolder) -> Result<(), CoreError> {
        if *self.mark_fails.lock().unwrap()
            || self.mark_fails_for.lock().unwrap().as_deref() == Some(folder.local_path.as_str())
        {
            return Err(CoreError::DaemonNotRunning);
        }
        self.marked.lock().unwrap().push(folder.local_path.clone());
        Ok(())
    }
}

fn refusal(result: Result<StartOverProgress, CoreError>) -> StartOverRefusal {
    match result {
        Err(CoreError::StartOverRefused(refusal)) => refusal,
        other => panic!("expected a typed refusal, got {other:?}"),
    }
}

/// The user-visible contract of every refusal: nothing was touched.
fn assert_untouched(fake: &Fake) {
    assert!(fake.path("device.json").exists());
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "old");
    assert!(!fake.path(JOURNAL).exists());
    assert!(!fake.calls().iter().any(|c| c == "sign_out" || c == "replace_signing_key"));
}

#[tokio::test]
async fn it_is_refused_without_a_confirmation_and_changes_nothing() {
    let fake = Fake::restored_sole_device();
    let result = start_over(&fake, false, "laptop".into()).await;
    assert_eq!(refusal(result), StartOverRefusal::NotConfirmed);
    assert_untouched(&fake);
}

#[tokio::test]
async fn it_is_refused_when_the_database_is_not_reported_as_restored() {
    let fake = Fake::restored_sole_device();
    *fake.restored.lock().unwrap() = Ok(false);
    let result = start_over(&fake, true, "laptop".into()).await;
    assert_eq!(refusal(result), StartOverRefusal::NotRestored);
    assert_untouched(&fake);
}

#[tokio::test]
async fn it_fails_closed_when_the_daemon_cannot_be_asked() {
    let fake = Fake::restored_sole_device();
    *fake.restored.lock().unwrap() = Err("down".into());
    let result = start_over(&fake, true, "laptop".into()).await;
    assert!(matches!(result, Err(CoreError::DaemonNotRunning)), "{result:?}");
    assert_untouched(&fake);
}

#[tokio::test]
async fn a_restored_sole_device_retires_its_identity_and_keeps_it() {
    let fake = Fake::restored_sole_device();
    let progress = start_over(&fake, true, "laptop".into()).await.unwrap();

    assert_eq!(
        progress,
        StartOverProgress::SignInRequired { retired_device_id: "old-device".into() }
    );
    // The condition is read when the operation starts, then the old authority is revoked before
    // anything local moves.
    assert_eq!(
        fake.calls(),
        ["database_restored", "sign_out", "replace_signing_key", "restart_daemon"]
    );
    // Kept, not deleted.
    let retired = fake.path("retired-devices/old-device");
    assert!(retired.join("device.json").exists());
    assert_eq!(std::fs::read_to_string(retired.join("signing_key")).unwrap(), "old");
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "new");
    assert!(!fake.path("device.json").exists(), "the machine is unregistered");
    assert!(pending_in(fake.dir.path()));
}

#[tokio::test]
async fn after_signing_in_it_registers_and_joins_every_folder_again_in_its_storage_mode() {
    let fake = Fake::restored_sole_device();
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();
    fake.calls.lock().unwrap().clear();
    // The restored state is gone once the identity is retired; a continuation needs no new check
    // and no new confirmation.
    *fake.restored.lock().unwrap() = Ok(false);

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert_eq!(report.new_device_id, "new-device");
    assert_eq!(report.retired_device_id, "old-device");
    assert_eq!(report.rejoined, ["/data/docs", "/data/photos"]);
    assert!(report.complete && report.not_rejoined.is_empty());
    assert_eq!(
        fake.calls(),
        [
            "restart_daemon",
            "register:laptop",
            "supersede:old-device:new-device",
            "ensure_daemon",
            "rejoin:docs:/data/docs:eager",
            "rejoin:photos:/data/photos:on-demand"
        ]
    );
    assert!(!pending_in(fake.dir.path()));
    // The retired identity is still there.
    assert!(fake.path("retired-devices/old-device/signing_key").exists());
}

#[tokio::test]
async fn it_waits_for_a_sign_in_instead_of_registering_with_a_revoked_installation() {
    let fake = Fake::restored_sole_device();
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.calls.lock().unwrap().clear();

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    assert!(matches!(progress, StartOverProgress::SignInRequired { .. }));
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn a_sign_out_that_cannot_be_confirmed_moves_nothing() {
    let fake = Fake::restored_sole_device();
    *fake.sign_out_fails.lock().unwrap() = true;

    let result = start_over(&fake, true, "laptop".into()).await;

    assert!(matches!(result, Err(CoreError::AuthFailed(_))), "{result:?}");
    assert!(fake.path("device.json").exists());
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "old");

    // The journal was written first, so the next call continues without a second check.
    *fake.sign_out_fails.lock().unwrap() = false;
    *fake.restored.lock().unwrap() = Ok(false);
    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
    assert!(matches!(progress, StartOverProgress::SignInRequired { .. }));
    assert!(fake.path("retired-devices/old-device/device.json").exists());
}

#[tokio::test]
async fn a_folder_that_cannot_be_joined_keeps_the_start_over_open_for_a_retry() {
    let fake = Fake::restored_sole_device();
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();
    *fake.failing_group.lock().unwrap() = Some("g2".into());

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(!report.complete);
    assert_eq!(report.rejoined, ["/data/docs"]);
    assert_eq!(report.not_rejoined[0].local_path, "/data/photos");
    assert!(pending_in(fake.dir.path()));

    *fake.failing_group.lock().unwrap() = None;
    fake.calls.lock().unwrap().clear();
    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(report.complete);
    // Already registered: no second registration.
    assert!(!fake.calls().iter().any(|c| c.starts_with("register")));
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn a_group_the_account_does_not_own_is_reported_and_does_not_block_the_rest() {
    let mut fake = Fake::restored_sole_device();
    fake.owned_groups.retain(|(id, _)| id == "g1");
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };

    assert_eq!(report.rejoined, ["/data/docs"]);
    assert_eq!(report.not_rejoined.len(), 1);
    assert_eq!(report.not_rejoined[0].group_id, "g2");
    assert!(report.complete, "nothing a retry can fix");
    assert!(!pending_in(fake.dir.path()));
    // The report is gone after a restart; the daemon's link state keeps the folder visible.
    assert_eq!(*fake.marked.lock().unwrap(), ["/data/photos"]);
}

/// A retry must not mark again: the person may have accepted the invite for a folder meanwhile,
/// and a second mark would take it out of sync.
#[tokio::test]
async fn a_retry_does_not_mark_a_folder_the_person_has_linked_again_meanwhile() {
    let mut fake = Fake::restored_sole_device();
    fake.owned_groups.retain(|(id, _)| id == "g1");
    *fake.failing_group.lock().unwrap() = Some("g1".into());
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(!report.complete, "g1 can be retried");
    assert_eq!(*fake.marked.lock().unwrap(), ["/data/photos"]);

    // The person accepts the invite for the folder; then the start over is run again.
    fake.marked.lock().unwrap().clear();
    *fake.failing_group.lock().unwrap() = None;
    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(report.complete);
    assert_eq!(report.rejoined, ["/data/docs"]);
    assert!(fake.marked.lock().unwrap().is_empty(), "a second mark would unsync the folder");
}

/// Marks already made are remembered one by one: when a later folder cannot be marked, a retry
/// skips the folders that were, so one the person linked again meanwhile stays in sync.
#[tokio::test]
async fn a_retry_after_a_partly_made_marking_skips_the_folders_already_marked() {
    let mut fake = Fake::restored_sole_device();
    fake.owned_groups.retain(|(id, _)| id == "g1");
    fake.folders.push(LinkedFolder {
        local_path: "/data/music".into(),
        group_id: "g3".into(),
        on_demand: false,
    });
    *fake.mark_fails_for.lock().unwrap() = Some("/data/music".into());
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(!report.complete);
    assert_eq!(*fake.marked.lock().unwrap(), ["/data/photos"]);

    // The person accepts the invite for photos; the daemon can be asked again for music.
    fake.marked.lock().unwrap().clear();
    *fake.mark_fails_for.lock().unwrap() = None;
    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(report.complete);
    assert_eq!(*fake.marked.lock().unwrap(), ["/data/music"], "photos must not be marked again");
}

/// A mark that cannot be written must not let the journal go: the report would be the only record.
#[tokio::test]
async fn a_folder_that_cannot_be_marked_keeps_the_start_over_open_and_a_retry_marks_it() {
    let mut fake = Fake::restored_sole_device();
    fake.owned_groups.retain(|(id, _)| id == "g1");
    *fake.mark_fails.lock().unwrap() = true;
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(!report.complete);
    assert!(pending_in(fake.dir.path()));
    assert!(fake.marked.lock().unwrap().is_empty());

    *fake.mark_fails.lock().unwrap() = false;
    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(report.complete);
    assert!(!pending_in(fake.dir.path()));
    assert_eq!(*fake.marked.lock().unwrap(), ["/data/photos"]);
}

/// An interrupted run that already signed the old installation out must not sign out the sign-in
/// the person made afterwards.
#[tokio::test]
async fn a_resumed_run_never_signs_out_the_new_sign_in() {
    let fake = Fake::restored_sole_device();
    // Interrupted right after the sign-out: the journal says so, the old identity is still in place.
    write_journal(
        fake.dir.path(),
        &Journal {
            retired_device_id: "old-device".into(),
            retiring_installation: RetiringInstallation::Recorded(None),
            stage: Stage::SignedOut,
            marked: Vec::new(),
        },
    )
    .unwrap();
    fake.sign_in();

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    assert!(matches!(progress, StartOverProgress::Finished(_)), "{progress:?}");
    assert!(!fake.calls().iter().any(|c| c == "sign_out"), "{:?}", fake.calls());
    assert!(fake.path("retired-devices/old-device/signing_key").exists());
}

/// The process stopped after the old installation was signed out and before the journal said so.
/// The person then signed in again; the retry must see that the installation it was retiring is
/// gone and leave the new sign-in alone.
#[tokio::test]
async fn a_retry_after_an_unrecorded_sign_out_never_signs_out_the_new_sign_in() {
    let fake = Fake::restored_sole_device();
    write_journal(
        fake.dir.path(),
        &Journal {
            retired_device_id: "old-device".into(),
            retiring_installation: RetiringInstallation::Recorded(Some("install-0".into())),
            stage: Stage::Retiring,
            marked: Vec::new(),
        },
    )
    .unwrap();
    // The sign-out went through (the old credential is gone), then the person signed in again.
    fake.sign_out().await.unwrap();
    fake.sign_in();
    let new_sign_in = fake.installation_id().unwrap();
    fake.calls.lock().unwrap().clear();

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    assert!(matches!(progress, StartOverProgress::Finished(_)), "{progress:?}");
    assert!(!fake.calls().iter().any(|c| c == "sign_out"), "{:?}", fake.calls());
    assert_eq!(fake.installation_id().unwrap(), new_sign_in);
}

/// A retry that still finds the recorded installation signs it out.
#[tokio::test]
async fn a_retry_signs_out_the_recorded_installation_if_it_is_still_signed_in() {
    let fake = Fake::restored_sole_device();
    write_journal(
        fake.dir.path(),
        &Journal {
            retired_device_id: "old-device".into(),
            retiring_installation: RetiringInstallation::Recorded(Some("install-0".into())),
            stage: Stage::Retiring,
            marked: Vec::new(),
        },
    )
    .unwrap();

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    assert!(matches!(progress, StartOverProgress::SignInRequired { .. }), "{progress:?}");
    assert!(fake.calls().iter().any(|c| c == "sign_out"));
}

/// The journal records the installation being retired, before anything is signed out.
#[tokio::test]
async fn the_journal_records_the_installation_being_retired() {
    let fake = Fake::restored_sole_device();
    *fake.sign_out_fails.lock().unwrap() = true;
    assert!(start_over(&fake, true, "laptop".into()).await.is_err());
    let journal = read_journal(fake.dir.path()).unwrap().unwrap();
    assert_eq!(
        journal.retiring_installation,
        RetiringInstallation::Recorded(Some("install-0".into()))
    );
    assert_eq!(journal.stage, Stage::Retiring);
}

/// A provider folder has no path to join again; it is reported and never keeps the start over open.
#[tokio::test]
async fn a_provider_folder_is_reported_and_does_not_keep_the_start_over_open() {
    let mut fake = Fake::restored_sole_device();
    fake.folders.push(LinkedFolder {
        local_path: "provider://token-1".into(),
        group_id: "g1".into(),
        on_demand: true,
    });
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };

    assert!(report.complete);
    assert_eq!(report.not_rejoined.len(), 1);
    assert_eq!(report.not_rejoined[0].local_path, "provider://token-1");
    assert!(!fake.calls().iter().any(|c| c.starts_with("rejoin") && c.contains("provider://")));
    assert_eq!(*fake.marked.lock().unwrap(), ["provider://token-1"]);
    assert!(!pending_in(fake.dir.path()));
}

fn assert_registration_refused(fake: &Fake) {
    assert!(matches!(
        ensure_registration_allowed(fake.dir.path()),
        Err(CoreError::StartOverRefused(StartOverRefusal::InProgress))
    ));
}

#[tokio::test]
async fn registering_is_allowed_with_no_start_over_and_once_the_identity_is_retired() {
    let fake = Fake::restored_sole_device();
    ensure_registration_allowed(fake.dir.path()).unwrap();
    start_over(&fake, true, "laptop".into()).await.unwrap();
    ensure_registration_allowed(fake.dir.path()).unwrap();
}

#[tokio::test]
async fn registering_is_refused_at_every_stage_before_the_identity_is_retired() {
    let fake = Fake::restored_sole_device();
    for stage in [Stage::Retiring, Stage::SignedOut] {
        write_journal(
            fake.dir.path(),
            &Journal {
                retired_device_id: "old-device".into(),
                retiring_installation: RetiringInstallation::Recorded(None),
                stage,
                marked: Vec::new(),
            },
        )
        .unwrap();
        assert_registration_refused(&fake);
    }
}

/// The key cannot be replaced after the sign-out: the machine is signed out and still registered
/// as the old device with the old key, a registration is refused, and resuming finishes with a
/// fresh key that the new registration then uses.
#[tokio::test]
async fn a_stop_before_the_key_is_replaced_refuses_registering_and_resumes_to_a_fresh_key() {
    let fake = Fake::restored_sole_device();
    *fake.replace_key_fails.lock().unwrap() = true;
    assert!(start_over(&fake, true, "laptop".into()).await.is_err());
    assert!(fake.path("device.json").exists());
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "old");
    assert_registration_refused(&fake);

    *fake.replace_key_fails.lock().unwrap() = false;
    *fake.restored.lock().unwrap() = Ok(false);
    fake.sign_in();
    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert_eq!(report.new_device_id, "new-device");
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "new");
    let retired = fake.path("retired-devices/old-device");
    assert_eq!(std::fs::read_to_string(retired.join("signing_key")).unwrap(), "old");
    assert!(retired.join("device.json").exists());
    ensure_registration_allowed(fake.dir.path()).unwrap();
}

/// Stopped after the key was replaced and before `device.json` moved: still refused, and resuming
/// moves `device.json` without retiring the new key.
#[tokio::test]
async fn a_stop_after_the_key_is_replaced_resumes_without_retiring_the_new_key() {
    let fake = Fake::restored_sole_device();
    let retired = fake.path("retired-devices/old-device");
    std::fs::create_dir_all(&retired).unwrap();
    fake.replace_signing_key(&fake.path("signing_key"), &retired.join("signing_key")).unwrap();
    write_journal(
        fake.dir.path(),
        &Journal {
            retired_device_id: "old-device".into(),
            retiring_installation: RetiringInstallation::Recorded(None),
            stage: Stage::SignedOut,
            marked: Vec::new(),
        },
    )
    .unwrap();
    assert_registration_refused(&fake);
    fake.sign_in();

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    assert!(matches!(progress, StartOverProgress::Finished(_)), "{progress:?}");
    assert_eq!(std::fs::read_to_string(retired.join("signing_key")).unwrap(), "old");
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "new");
    assert!(retired.join("device.json").exists());
}

/// The public entry point itself, not only the guard: nothing is created and the service is not
/// asked while a start over is mid-way.
#[test]
fn register_device_is_refused_while_a_start_over_is_mid_way() {
    let _guard = crate::coordination::device_config::CONFIG_DIR_ENV_LOCK
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    write_journal(
        dir.path(),
        &Journal {
            retired_device_id: "old-device".into(),
            retiring_installation: RetiringInstallation::Recorded(None),
            stage: Stage::SignedOut,
            marked: Vec::new(),
        },
    )
    .unwrap();

    let result =
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
            crate::ops::devices::register_device(
                "laptop".into(),
                &crate::ops::daemon::default_launch(),
            ),
        );

    std::env::remove_var("YADORILINK_CONFIG_DIR");
    assert!(
        matches!(result, Err(CoreError::StartOverRefused(StartOverRefusal::InProgress))),
        "{result:?}"
    );
    assert!(!dir.path().join("signing_key").exists());
    assert!(!dir.path().join("device.json").exists());
}

/// Clearing the journal is repeatable (a crash can leave it either way) and a write replaces a
/// stray staged copy a killed run left behind.
#[test]
fn clearing_the_journal_is_repeatable_and_a_write_replaces_a_stray_staged_copy() {
    let dir = tempfile::tempdir().unwrap();
    let stray = dir.path().join(format!(".{JOURNAL}.tmp-{}", std::process::id()));
    std::fs::write(&stray, "{ torn").unwrap();
    write_journal(
        dir.path(),
        &Journal {
            retired_device_id: "old".into(),
            retiring_installation: RetiringInstallation::Recorded(None),
            stage: Stage::Retired,
            marked: Vec::new(),
        },
    )
    .unwrap();
    assert!(!stray.exists());
    assert!(pending_in(dir.path()));
    clear_journal(dir.path()).unwrap();
    assert!(!pending_in(dir.path()));
    clear_journal(dir.path()).unwrap();
}

/// The journal as the earlier schema wrote it (before `retiring_installation` existed). It is a
/// copy of that struct, not today's, so these fixtures cannot drift with the current one.
mod earlier_schema {
    use serde::Serialize;

    #[derive(Serialize)]
    pub struct Journal {
        pub retired_device_id: String,
        pub stage: &'static str,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub marked: Vec<String>,
    }

    pub fn bytes(stage: &'static str) -> Vec<u8> {
        serde_json::to_vec_pretty(&Journal {
            retired_device_id: "old-device".into(),
            stage,
            marked: Vec::new(),
        })
        .unwrap()
    }
}

const LEGACY_RETIRING: &[u8] = br#"{"retired_device_id":"old-device","stage":"retiring"}"#;

/// Nothing a refused resume may touch has changed.
fn assert_refused_unchanged(fake: &Fake, journal: &[u8], installation: Option<&str>) {
    assert_eq!(std::fs::read(fake.path(JOURNAL)).unwrap(), journal);
    assert_eq!(fake.installation_id().unwrap().as_deref(), installation);
    assert!(fake.path("device.json").exists());
    assert_eq!(std::fs::read_to_string(fake.path("signing_key")).unwrap(), "old");
    assert!(!fake.path("retired-devices").exists());
    let calls = fake.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c == "sign_out" || c == "replace_signing_key" || c == "ensure_daemon"),
        "{calls:?}"
    );
}

#[tokio::test]
async fn a_legacy_retiring_journal_with_the_original_installation_is_refused_unchanged() {
    let fake = Fake::restored_sole_device();
    std::fs::write(fake.path(JOURNAL), LEGACY_RETIRING).unwrap();

    let result = start_over(&fake, false, "laptop".into()).await;

    let Err(CoreError::Other(message)) = result else { panic!("{result:?}") };
    assert!(message.contains("does not record which installation"), "{message}");
    assert_refused_unchanged(&fake, LEGACY_RETIRING, Some("install-0"));
    // Still mid-way: registering stays refused.
    assert_registration_refused(&fake);
}

#[tokio::test]
async fn a_legacy_retiring_journal_is_refused_whether_or_not_the_original_was_revoked() {
    // Already revoked, nobody signed in since.
    let fake = Fake::restored_sole_device();
    std::fs::write(fake.path(JOURNAL), LEGACY_RETIRING).unwrap();
    *fake.installation.lock().unwrap() = None;
    assert!(start_over(&fake, false, "laptop".into()).await.is_err());
    assert_refused_unchanged(&fake, LEGACY_RETIRING, None);

    // Already revoked and a newer sign-in exists: it is neither revoked nor adopted.
    let fake = Fake::restored_sole_device();
    std::fs::write(fake.path(JOURNAL), LEGACY_RETIRING).unwrap();
    fake.sign_in();
    assert!(start_over(&fake, false, "laptop".into()).await.is_err());
    assert_refused_unchanged(&fake, LEGACY_RETIRING, Some("install-1"));
}

/// A journal produced by the earlier schema's own serializer, not by today's struct.
#[tokio::test]
async fn an_earlier_schema_retiring_journal_survives_the_upgrade_by_refusing() {
    let fake = Fake::restored_sole_device();
    let bytes = earlier_schema::bytes("retiring");
    std::fs::write(fake.path(JOURNAL), &bytes).unwrap();
    assert!(start_over(&fake, false, "laptop".into()).await.is_err());
    assert_refused_unchanged(&fake, &bytes, Some("install-0"));
}

/// Later stages need no revocation, so an earlier-schema journal there continues as before and is
/// never written back with a claim about the installation.
#[tokio::test]
async fn an_earlier_schema_signed_out_journal_continues_without_a_sign_out() {
    let fake = Fake::restored_sole_device();
    std::fs::write(fake.path(JOURNAL), earlier_schema::bytes("signed_out")).unwrap();
    *fake.installation.lock().unwrap() = None;

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    assert!(matches!(progress, StartOverProgress::SignInRequired { .. }), "{progress:?}");
    assert!(!fake.calls().iter().any(|c| c == "sign_out"));
    assert!(fake.path("retired-devices/old-device/signing_key").exists());
    let text = std::fs::read_to_string(fake.path(JOURNAL)).unwrap();
    assert!(!text.contains("retiring_installation"), "{text}");
}

/// The repair the error describes works: recording the installation (or `null`) continues.
#[tokio::test]
async fn recording_the_installation_in_a_legacy_journal_lets_it_continue() {
    let fake = Fake::restored_sole_device();
    std::fs::write(
        fake.path(JOURNAL),
        br#"{"retired_device_id":"old-device","stage":"retiring","retiring_installation":"install-0"}"#,
    )
    .unwrap();
    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
    assert!(matches!(progress, StartOverProgress::SignInRequired { .. }), "{progress:?}");
    assert!(fake.calls().iter().any(|c| c == "sign_out"));
}

/// A journal that explicitly records no installation is a proof, not a missing field: resuming
/// signs nothing out, including a sign-in made since.
#[tokio::test]
async fn an_explicit_no_installation_journal_resumes_without_a_sign_out() {
    let bytes =
        br#"{"retired_device_id":"old-device","retiring_installation":null,"stage":"retiring"}"#;
    for signed_in_since in [false, true] {
        let fake = Fake::restored_sole_device();
        std::fs::write(fake.path(JOURNAL), bytes).unwrap();
        *fake.installation.lock().unwrap() = None;
        if signed_in_since {
            fake.sign_in();
        }
        let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
        assert!(!fake.calls().iter().any(|c| c == "sign_out"), "{:?}", fake.calls());
        assert_eq!(
            matches!(progress, StartOverProgress::SignInRequired { .. }),
            !signed_in_since,
            "{progress:?}"
        );
    }
}

/// The recorded installation is never confused with a different current one.
#[tokio::test]
async fn a_recorded_installation_never_revokes_a_different_current_one() {
    let fake = Fake::restored_sole_device();
    std::fs::write(
        fake.path(JOURNAL),
        br#"{"retired_device_id":"old-device","retiring_installation":"install-0","stage":"retiring"}"#,
    )
    .unwrap();
    *fake.installation.lock().unwrap() = Some("install-9".into());
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert!(!fake.calls().iter().any(|c| c == "sign_out"), "{:?}", fake.calls());
    assert_eq!(fake.installation_id().unwrap().as_deref(), Some("install-9"));
}

#[tokio::test]
async fn a_corrupt_or_unknown_stage_journal_stays_fail_closed_and_unchanged() {
    let cases: [&[u8]; 3] = [
        br#"{"retired_device_id":"old-device","stage":"revoking"}"#,
        br#"{"retired_device_id":"old-device","stage":"retiring""#,
        br#"{"retired_device_id":"old-device","stage":"retiring","extra":1}"#,
    ];
    for bytes in cases {
        let fake = Fake::restored_sole_device();
        std::fs::write(fake.path(JOURNAL), bytes).unwrap();
        assert!(start_over(&fake, true, "laptop".into()).await.is_err());
        assert_refused_unchanged(&fake, bytes, Some("install-0"));
    }
}

/// A start over that retired the identity, then the person signed in again.
async fn signed_in_after_retiring() -> Fake {
    let fake = Fake::restored_sole_device();
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();
    fake.calls.lock().unwrap().clear();
    *fake.restored.lock().unwrap() = Ok(false);
    fake
}

fn journal_stage(fake: &Fake) -> String {
    let journal: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fake.path(JOURNAL)).unwrap()).unwrap();
    journal["stage"].as_str().unwrap().to_owned()
}

fn count(fake: &Fake, prefix: &str) -> usize {
    fake.calls().iter().filter(|c| c.starts_with(prefix)).count()
}

#[tokio::test]
async fn the_supersede_claim_names_the_old_and_the_new_device_after_registering() {
    let fake = signed_in_after_retiring().await;
    start_over(&fake, false, "laptop".into()).await.unwrap();
    let calls = fake.calls();
    let position = |what: &str| calls.iter().position(|c| c == what).unwrap();
    assert!(position("register:laptop") < position("supersede:old-device:new-device"));
    assert!(position("supersede:old-device:new-device") < position("rejoin:docs:/data/docs:eager"));
    assert!(!pending_in(fake.dir.path()));
    assert!(!yadorilink_local_storage::replacement_unconfirmed::pending(fake.dir.path()));
}

#[tokio::test]
async fn an_interrupted_claim_is_sent_again_unchanged_and_ends_with_one_new_device() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::Offline;
    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    assert!(matches!(error, CoreError::CoordinationPlaneUnreachable(_)), "{error:?}");
    // Kept for the retry: the journal, the new registration and every file.
    assert_eq!(journal_stage(&fake), "retired");
    assert_eq!(count(&fake, "rejoin"), 0);
    assert_eq!(count(&fake, "ensure_daemon"), 0);

    *fake.supersede_mode.lock().unwrap() = Supersede::Healthy;
    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert!(report.complete);
    // One registration, the same claim twice.
    assert_eq!(count(&fake, "register"), 1);
    let claims: Vec<_> = fake.calls().into_iter().filter(|c| c.starts_with("supersede")).collect();
    assert_eq!(claims, ["supersede:old-device:new-device"; 2]);
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn a_claim_that_landed_is_not_sent_again_when_only_the_rejoin_is_left() {
    let fake = signed_in_after_retiring().await;
    *fake.failing_group.lock().unwrap() = Some("g2".into());
    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert!(!report.complete);
    assert_eq!(journal_stage(&fake), "superseded");

    *fake.failing_group.lock().unwrap() = None;
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "supersede"), 1);
    assert_eq!(count(&fake, "register"), 1);
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn a_stale_sign_in_asks_for_a_new_one_and_a_later_run_succeeds() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::Reauthenticate;
    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    let CoreError::Forbidden(message) = &error else { panic!("{error:?}") };
    assert!(message.contains("sign in again"), "{message}");
    assert!(message.contains("run the start over again"), "{message}");
    assert_eq!(journal_stage(&fake), "retired");
    assert_eq!(count(&fake, "rejoin"), 0);
    assert!(fake.path("retired-devices/old-device/signing_key").exists());

    *fake.supersede_mode.lock().unwrap() = Supersede::Healthy;
    fake.sign_in();
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn a_device_replaced_by_another_is_a_clear_error_that_keeps_every_file() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::AlreadyReplaced;
    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    let CoreError::Other(message) = &error else { panic!("{error:?}") };
    assert!(message.contains("already replaced by another device"), "{message}");
    assert_eq!(journal_stage(&fake), "retired");
    // Nothing was joined, marked, removed or signed out on the way.
    assert_eq!(count(&fake, "rejoin"), 0);
    assert!(fake.marked.lock().unwrap().is_empty());
    assert_eq!(count(&fake, "sign_out"), 0);
    assert!(fake.path("retired-devices/old-device/signing_key").exists());
    assert!(!yadorilink_local_storage::replacement_unconfirmed::pending(fake.dir.path()));
}

#[tokio::test]
async fn an_unconfirmed_replacement_is_recorded_for_status_and_survives_the_finished_start_over() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::Unconfirmed;
    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert!(report.complete);
    assert!(!pending_in(fake.dir.path()), "the journal is cleared");
    let record: yadorilink_local_storage::replacement_unconfirmed::Record = serde_json::from_slice(
        &std::fs::read(fake.path(yadorilink_local_storage::replacement_unconfirmed::FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(record.old_device_id, "old-device");
    assert_eq!(record.new_device_id, "new-device");
    assert_eq!(record.unconfirmed_group_ids, ["g1"]);
    assert!(!record.acknowledged_possible_loss, "a start over never acknowledges by itself");
    assert!(acknowledge_possible_loss_in(fake.dir.path()).unwrap());
    assert!(!yadorilink_local_storage::replacement_unconfirmed::acknowledgement_required(
        fake.dir.path()
    ));
}

#[tokio::test]
async fn a_journal_written_before_the_claim_existed_continues_by_sending_it() {
    let fake = signed_in_after_retiring().await;
    // The journal an earlier build left at the same point: retired, registered, no claim yet.
    assert_eq!(journal_stage(&fake), "retired");
    *fake.device_id.lock().unwrap() = Some("new-device".into());
    std::fs::write(fake.path("device.json"), "{}").unwrap();
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "register"), 0);
    assert_eq!(count(&fake, "supersede"), 1);
}

#[tokio::test]
async fn a_superseded_journal_allows_registering_and_is_not_claimed_again() {
    let fake = Fake::restored_sole_device();
    std::fs::remove_file(fake.path("device.json")).unwrap();
    std::fs::write(
        fake.path(JOURNAL),
        br#"{"retired_device_id":"old-device","retiring_installation":"install-0","stage":"superseded"}"#,
    )
    .unwrap();
    ensure_registration_allowed(fake.dir.path()).unwrap();
    *fake.installation.lock().unwrap() = Some("install-1".into());
    *fake.device_id.lock().unwrap() = Some("new-device".into());
    std::fs::write(fake.path("device.json"), "{}").unwrap();
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "supersede"), 0);
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn an_answer_for_other_devices_is_refused_and_nothing_is_recorded() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::Mismatch;
    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    assert!(error.to_string().contains("different pair of devices"), "{error}");
    assert_eq!(journal_stage(&fake), "retired");
    assert!(!yadorilink_local_storage::replacement_unconfirmed::pending(fake.dir.path()));
}

#[tokio::test]
async fn a_stale_sign_in_then_sign_out_and_sign_in_again_lets_the_claim_succeed() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::ByBinding;
    let first = fake.installation.lock().unwrap().clone().unwrap();
    fake.stale.lock().unwrap().push(first.clone());

    // The new device is registered under the sign-in the service then calls stale.
    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    assert!(matches!(error, CoreError::Forbidden(_)), "{error:?}");
    assert_eq!(journal_stage(&fake), "retired");
    assert_eq!(fake.bound_to.lock().unwrap().as_deref(), Some(first.as_str()));

    // Sign out and in again: a new installation, while device.json still names the new device.
    fake.sign_out().await.unwrap();
    assert!(matches!(
        start_over(&fake, false, "laptop".into()).await.unwrap(),
        StartOverProgress::SignInRequired { .. }
    ));
    fake.sign_in();
    let second = fake.installation.lock().unwrap().clone().unwrap();
    assert_ne!(first, second);

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();
    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert!(report.complete);
    // Registered once; the claim was sent twice, the second landed and moved the binding.
    assert_eq!(count(&fake, "register"), 1);
    assert_eq!(count(&fake, "supersede"), 2);
    assert_eq!(fake.bound_to.lock().unwrap().as_deref(), Some(second.as_str()));
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn a_new_sign_in_without_signing_out_the_registering_installation_is_told_so_and_can_recover()
{
    let fake = signed_in_after_retiring().await;
    // Registers under the first sign-in, whose claim is refused as stale ...
    *fake.supersede_mode.lock().unwrap() = Supersede::Reauthenticate;
    start_over(&fake, false, "laptop".into()).await.unwrap_err();
    let first = fake.installation.lock().unwrap().clone().unwrap();
    // ... then a newer installation sends it while the first is still signed in.
    *fake.supersede_mode.lock().unwrap() = Supersede::ByBinding;
    fake.sign_in();

    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    let CoreError::Forbidden(message) = &error else { panic!("{error:?}") };
    assert!(message.contains("sign out"), "{message}");
    assert_eq!(journal_stage(&fake), "retired");
    assert_eq!(count(&fake, "rejoin"), 0);

    // The registering installation is signed out (by whoever holds it); the same run now succeeds.
    fake.signed_out.lock().unwrap().push(first);
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert!(!pending_in(fake.dir.path()));
    assert_eq!(count(&fake, "register"), 1);
}

#[tokio::test]
async fn an_interrupted_claim_after_the_binding_moved_is_resent_without_registering_again() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::ByBinding;
    let first = fake.installation.lock().unwrap().clone().unwrap();
    fake.stale.lock().unwrap().push(first);
    start_over(&fake, false, "laptop".into()).await.unwrap_err();
    fake.sign_out().await.unwrap();
    fake.sign_in();

    // The claim reaches the service and lands, but the answer is lost.
    *fake.supersede_mode.lock().unwrap() = Supersede::Offline;
    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();
    assert!(matches!(error, CoreError::CoordinationPlaneUnreachable(_)), "{error:?}");
    assert_eq!(journal_stage(&fake), "retired");

    *fake.supersede_mode.lock().unwrap() = Supersede::ByBinding;
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "register"), 1);
    assert!(!pending_in(fake.dir.path()));
}

/// An on-demand folder of a group the service named as solely covered is promoted to eager after
/// it is joined; other folders (eager ones, and on-demand ones of groups not named) are not touched.
#[tokio::test]
async fn an_unconfirmed_group_that_was_on_demand_is_promoted_to_eager() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::UnconfirmedOnDemand;
    let StartOverProgress::Finished(report) =
        start_over(&fake, false, "laptop".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(report.complete);
    let calls = fake.calls();
    let join = calls.iter().position(|c| c == "rejoin:photos:/data/photos:on-demand").unwrap();
    let promote = calls.iter().position(|c| c == "promote:photos:/data/photos").unwrap();
    assert!(join < promote, "promoted only after it was joined: {calls:?}");
    assert_eq!(count(&fake, "promote"), 1, "{calls:?}");
}

#[tokio::test]
async fn nothing_is_promoted_when_the_replacement_is_confirmed_or_the_group_is_not_named() {
    let fake = signed_in_after_retiring().await;
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "promote"), 0);

    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::Unconfirmed; // names g1, which is eager
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "promote"), 0);
}

/// A promotion that fails keeps the start over open, and running it again promotes.
#[tokio::test]
async fn a_failed_promotion_keeps_the_start_over_open_until_it_works() {
    let fake = signed_in_after_retiring().await;
    *fake.supersede_mode.lock().unwrap() = Supersede::UnconfirmedOnDemand;
    *fake.promote_fails.lock().unwrap() = true;
    let StartOverProgress::Finished(report) =
        start_over(&fake, false, "laptop".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(!report.complete);
    assert_eq!(report.not_rejoined.len(), 1);
    assert!(pending_in(fake.dir.path()));

    *fake.promote_fails.lock().unwrap() = false;
    let StartOverProgress::Finished(report) =
        start_over(&fake, false, "laptop".into()).await.unwrap()
    else {
        panic!()
    };
    assert!(report.complete);
    assert_eq!(count(&fake, "promote"), 2);
    assert_eq!(count(&fake, "supersede"), 1);
}

#[tokio::test]
async fn a_daemon_that_kept_the_previous_sign_in_is_restarted_before_the_new_device_is_registered()
{
    let fake = signed_in_after_retiring().await;
    // The person signed out and in again while the daemon kept running.
    *fake.daemon_installation.lock().unwrap() = Some("install-0".into());

    let progress = start_over(&fake, false, "laptop".into()).await.unwrap();

    let StartOverProgress::Finished(report) = progress else { panic!("{progress:?}") };
    assert!(report.complete && report.not_rejoined.is_empty(), "{report:?}");
    let calls = fake.calls();
    let position = |what: &str| calls.iter().position(|c| c == what).unwrap();
    assert!(position("restart_daemon") < position("register:laptop"), "{calls:?}");
}

#[tokio::test]
async fn a_daemon_that_cannot_be_restarted_refuses_before_any_device_is_registered() {
    let fake = signed_in_after_retiring().await;
    *fake.restart_fails.lock().unwrap() = true;

    let error = start_over(&fake, false, "laptop".into()).await.unwrap_err();

    assert!(error.to_string().contains("nothing was registered or changed"), "{error}");
    assert!(error.to_string().ends_with("the running daemon did not stop"), "{error}");
    assert_eq!(
        error.hint(),
        Some(crate::error::Hint::StopThenStartDaemon),
        "the restart's next step reaches the front end"
    );
    assert_eq!(count(&fake, "register"), 0, "{:?}", fake.calls());
    assert_eq!(count(&fake, "supersede"), 0);
    assert_eq!(journal_stage(&fake), "retired");
    assert_eq!(fake.registered_device_id(), None);

    // Once the daemon can be restarted, running it again completes with one device.
    *fake.restart_fails.lock().unwrap() = false;
    start_over(&fake, false, "laptop".into()).await.unwrap();
    assert_eq!(count(&fake, "register"), 1);
    assert!(!pending_in(fake.dir.path()));
}

#[tokio::test]
async fn repeating_a_start_over_after_a_failed_join_keeps_one_device_and_one_claim() {
    let fake = signed_in_after_retiring().await;
    *fake.failing_group.lock().unwrap() = Some("g1".into());
    let first = start_over(&fake, false, "laptop".into()).await.unwrap();
    let StartOverProgress::Finished(first) = first else { panic!("{first:?}") };
    assert!(!first.complete);
    assert_eq!(journal_stage(&fake), "superseded");

    // Repeating changes nothing but the folder that failed.
    for _ in 0..2 {
        let again = start_over(&fake, false, "laptop".into()).await.unwrap();
        let StartOverProgress::Finished(again) = again else { panic!("{again:?}") };
        assert_eq!(again.new_device_id, first.new_device_id);
        assert!(!again.complete);
        assert_eq!(journal_stage(&fake), "superseded");
    }
    assert_eq!(count(&fake, "register"), 1);
    assert_eq!(count(&fake, "supersede"), 1);

    *fake.failing_group.lock().unwrap() = None;
    let done = start_over(&fake, false, "laptop".into()).await.unwrap();
    let StartOverProgress::Finished(done) = done else { panic!("{done:?}") };
    assert!(done.complete);
    assert_eq!(count(&fake, "register"), 1);
    assert!(!pending_in(fake.dir.path()));
}

/// A host that does not join folders again itself marks every linked folder as needing the
/// person, joins and promotes nothing, and the start
/// over still completes.
#[tokio::test]
async fn a_host_that_cannot_rejoin_marks_every_folder_and_still_completes() {
    let mut fake = Fake::restored_sole_device();
    fake.rejoins = false;
    start_over(&fake, true, "laptop".into()).await.unwrap();
    fake.sign_in();

    let StartOverProgress::Finished(report) = start_over(&fake, false, "l".into()).await.unwrap()
    else {
        panic!()
    };

    assert!(report.complete);
    assert!(report.rejoined.is_empty());
    assert_eq!(report.not_rejoined.len(), 2);
    // The host's own reason, not the "account does not own the group" one an empty group list
    // would also produce.
    assert!(
        report.not_rejoined.iter().all(|f| f.message.contains("does not join a folder again")),
        "{report:?}"
    );
    assert_eq!(*fake.marked.lock().unwrap(), ["/data/docs", "/data/photos"]);
    let calls = fake.calls();
    assert!(
        !calls.iter().any(|c| c.starts_with("rejoin") || c.starts_with("promote")),
        "{calls:?}"
    );
    assert!(!pending_in(fake.dir.path()));
}
