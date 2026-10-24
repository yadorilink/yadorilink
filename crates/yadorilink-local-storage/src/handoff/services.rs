//! Moving the OS registrations of the previous owner aside, and back.
//!
//! Every operation here is idempotent: the journal records the intent before an operation runs,
//! so after a crash the same operation runs again and must recognise what it already did. A
//! definition is never deleted: it is moved into the hand-off backup directory (the Windows task
//! is exported there before it is deleted), and restoring puts it back where the OS keeps it.

use std::path::Path;

use yadorilink_fs_platform::durable_dir::{move_durably, Replace};

use super::journal::RegistrationPlan;
use crate::service_registrations::Kind;

/// What a program run by [`CommandRunner`] answered.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

/// Runs the OS's own service tools; injected so tests record the calls instead of making them.
pub trait CommandRunner {
    /// # Errors
    /// The program could not be run at all (not a non-zero exit, which is `success: false`).
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String>;
}

impl<T: CommandRunner + ?Sized> CommandRunner for &T {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
        (**self).run(program, args)
    }
}

/// Runs the programs for real.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput, String> {
        let output = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("cannot run {program}: {e}"))?;
        Ok(CommandOutput {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// The operations the hand-off needs from the OS's service manager.
pub trait ServiceManager {
    /// Whether the manager has the registration active (loaded, enabled) right now.
    ///
    /// # Errors
    /// The manager could not be asked.
    fn is_active(&self, plan: &RegistrationPlan) -> Result<bool, String>;
    /// Stops the manager from starting the daemon and moves the definition aside.
    ///
    /// # Errors
    /// The registration could not be disabled; whatever was done is undone by [`Self::restore`].
    fn disable(&self, plan: &RegistrationPlan) -> Result<(), String>;
    /// Puts the definition back and, when it was active before, makes the manager use it again.
    /// Does not start the daemon.
    ///
    /// # Errors
    /// The registration could not be restored.
    fn restore(&self, plan: &RegistrationPlan) -> Result<(), String>;
}

/// The real service manager of this machine: the tools differ by [`Kind`], not by compile-time
/// target, so the same code is exercised by tests on every host.
pub struct OsServices<R: CommandRunner> {
    pub runner: R,
    /// The user id launchd addresses (`gui/<uid>`); unused where there is no launchd.
    pub uid: u32,
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

impl<R: CommandRunner> OsServices<R> {
    fn run_ok(&self, program: &str, a: &[&str]) -> Result<CommandOutput, String> {
        let out = self.runner.run(program, &args(a))?;
        if out.success {
            Ok(out)
        } else {
            Err(format!("`{program} {}` failed: {}", a.join(" "), out.stderr))
        }
    }

    fn launchd_target(&self, plan: &RegistrationPlan) -> String {
        format!("gui/{}/{}", self.uid, plan.name)
    }

    fn windows_run_ok(&self, a: &[&str]) -> Result<CommandOutput, String> {
        self.run_ok("schtasks", a)
    }
}

fn move_aside(from: &Path, to: &Path) -> Result<(), String> {
    if let Some(dir) = to.parent() {
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    move_durably(from, to, Replace::No)
        .map_err(|e| format!("cannot move {} to {}: {e}", from.display(), to.display()))
}

impl<R: CommandRunner> ServiceManager for OsServices<R> {
    fn is_active(&self, plan: &RegistrationPlan) -> Result<bool, String> {
        match plan.kind {
            Kind::LaunchAgent => Ok(self
                .runner
                .run("launchctl", &args(&["print", &self.launchd_target(plan)]))?
                .success),
            Kind::SystemdUserUnit => Ok(self
                .runner
                .run("systemctl", &args(&["--user", "is-enabled", &plan.name]))?
                .success),
            Kind::WindowsTask => Ok(true),
            Kind::BundledLaunchAgent | Kind::SystemdSystemUnit => {
                Err(format!("{} cannot be moved aside by this program", plan.name))
            }
        }
    }

    fn disable(&self, plan: &RegistrationPlan) -> Result<(), String> {
        let defined = plan.definition.exists();
        let kept = plan.backup.exists();
        match (plan.kind, defined, kept) {
            // Already done by an earlier run.
            (Kind::LaunchAgent | Kind::SystemdUserUnit, false, true) => Ok(()),
            (Kind::WindowsTask, _, true) if !defined => Ok(()),
            (_, false, false) => Err(format!(
                "the definition of {} ({}) disappeared; refusing to guess",
                plan.name,
                plan.definition.display()
            )),
            (Kind::LaunchAgent, true, _) => {
                // A run that died after the unload finds the agent unloaded: that is done, not an
                // error.
                if plan.was_active && self.is_active(plan)? {
                    self.run_ok("launchctl", &["bootout", &self.launchd_target(plan)])?;
                }
                move_aside(&plan.definition, &plan.backup)
            }
            (Kind::SystemdUserUnit, true, _) => {
                if plan.was_active {
                    self.run_ok("systemctl", &["--user", "disable", "--now", &plan.name])?;
                }
                move_aside(&plan.definition, &plan.backup)?;
                self.run_ok("systemctl", &["--user", "daemon-reload"]).map(|_| ())
            }
            (Kind::WindowsTask, _, _) => {
                // Export first; the task is deleted only after its XML is on disk.
                if !kept {
                    let xml = self.windows_run_ok(&["/Query", "/TN", &plan.name, "/XML"])?;
                    if let Some(dir) = plan.backup.parent() {
                        yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)
                            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
                    }
                    write_atomically(&plan.backup, &xml.stdout)?;
                }
                self.windows_run_ok(&["/Delete", "/TN", &plan.name, "/F"]).map(|_| ())
            }
            (Kind::BundledLaunchAgent | Kind::SystemdSystemUnit, _, _) => {
                Err(format!("{} cannot be moved aside by this program", plan.name))
            }
        }
    }

    fn restore(&self, plan: &RegistrationPlan) -> Result<(), String> {
        let defined = plan.definition.exists();
        let kept = plan.backup.exists();
        match plan.kind {
            Kind::LaunchAgent | Kind::SystemdUserUnit => {
                if !defined {
                    if !kept {
                        return Err(format!(
                            "neither {} nor its backup {} exists; cannot restore {}",
                            plan.definition.display(),
                            plan.backup.display(),
                            plan.name
                        ));
                    }
                    move_aside(&plan.backup, &plan.definition)?;
                } else if kept {
                    return Err(format!(
                        "both {} and its backup {} exist; refusing to choose",
                        plan.definition.display(),
                        plan.backup.display()
                    ));
                }
                // Re-activation is repeated on every restore: it is idempotent and a crash may
                // have come between the move and it.
                if plan.kind == Kind::LaunchAgent {
                    if plan.was_active {
                        let target = self.launchd_target(plan);
                        let loaded = self.runner.run("launchctl", &args(&["print", &target]))?;
                        if !loaded.success {
                            self.run_ok(
                                "launchctl",
                                &[
                                    "bootstrap",
                                    &format!("gui/{}", self.uid),
                                    &plan.definition.display().to_string(),
                                ],
                            )?;
                        }
                    }
                } else {
                    self.run_ok("systemctl", &["--user", "daemon-reload"])?;
                    if plan.was_active {
                        self.run_ok("systemctl", &["--user", "enable", &plan.name])?;
                    }
                }
                Ok(())
            }
            Kind::WindowsTask => {
                if kept {
                    self.windows_run_ok(&[
                        "/Create",
                        "/TN",
                        &plan.name,
                        "/XML",
                        &plan.backup.display().to_string(),
                        "/F",
                    ])?;
                    yadorilink_fs_platform::durable_dir::remove_file_durably(&plan.backup)
                        .map_err(|e| format!("cannot remove {}: {e}", plan.backup.display()))?;
                    Ok(())
                } else if defined {
                    Ok(())
                } else {
                    Err(format!("no export of task {} exists; cannot restore it", plan.name))
                }
            }
            Kind::BundledLaunchAgent | Kind::SystemdSystemUnit => {
                Err(format!("{} cannot be moved aside by this program", plan.name))
            }
        }
    }
}

/// Writes `bytes` to a side name and publishes it as `path`, so a crash never leaves a partial
/// export under the name that means "the export is complete".
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let partial = path.with_extension("partial");
    let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&partial);
    let mut file = std::fs::File::create(&partial)
        .map_err(|e| format!("cannot write {}: {e}", partial.display()))?;
    file.write_all(bytes).map_err(|e| format!("cannot write {}: {e}", partial.display()))?;
    yadorilink_fs_platform::flush::sync_file(&file)
        .map_err(|e| format!("cannot flush {}: {e}", partial.display()))?;
    drop(file);
    yadorilink_fs_platform::durable_dir::publish_durably(&partial, path, Replace::No)
        .map_err(|e| format!("cannot publish {}: {e}", path.display()))
}
