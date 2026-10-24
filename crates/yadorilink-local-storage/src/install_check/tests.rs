use super::*;
use crate::ownership::{Owner, OwnershipRecord};
use crate::service_registrations::Kind;
use std::path::PathBuf;

fn record(owner: Owner, source: &str, root: &str) -> RecordState {
    RecordState::Present(OwnershipRecord {
        owner,
        install_source: source.into(),
        install_root: root.into(),
        release_id: "c:d".into(),
        written_at: 1,
    })
}

fn running(source: &str, root: &str) -> RunningInstall {
    RunningInstall {
        install_source: source.into(),
        install_root: root.into(),
        version: "1.0.0".into(),
        release_id: "c:d".into(),
        engine_api_version: 1,
    }
}

fn local(release_id: &str, api: u32) -> Result<ReleaseDescriptor, DescriptorProblem> {
    Ok(ReleaseDescriptor {
        version: "1.0.0".into(),
        channel: String::new(),
        install_source: String::new(),
        release_id: release_id.into(),
        engine_api_version: api,
        state_schema: None,
    })
}

struct Machine {
    home: tempfile::TempDir,
    roots: Roots,
}

fn machine() -> Machine {
    let home = tempfile::tempdir().unwrap();
    let roots = Roots {
        home: home.path().to_path_buf(),
        system_root: home.path().join("win"),
        app_bundles: vec![home.path().join("Applications/YadoriLink.app")],
    };
    Machine { home, roots }
}

fn run(
    m: &Machine,
    state: &RecordState,
    lock: &LockProbe,
    running: Option<&RunningInstall>,
) -> Vec<Finding> {
    run_with(m, state, lock, running, &local("c:d", 1))
}

fn run_with(
    m: &Machine,
    state: &RecordState,
    lock: &LockProbe,
    running: Option<&RunningInstall>,
    local: &Result<ReleaseDescriptor, DescriptorProblem>,
) -> Vec<Finding> {
    check(&Facts {
        config_dir: Path::new("/cfg"),
        record: state,
        lock,
        running,
        local,
        roots: &m.roots,
    })
}

fn errors(rows: &[Finding]) -> Vec<&Finding> {
    rows.iter().filter(|r| r.severity == Severity::Error).collect()
}

#[test]
fn a_consistent_script_install_reports_no_problem() {
    let m = machine();
    let state = record(Owner::Cli, "script", "/home/u/.local/lib/yadorilink/1.0");
    let daemon = running("script", "/home/u/.local/lib/yadorilink/1.1");
    let rows = run(&m, &state, &LockProbe::Held, Some(&daemon));
    assert!(errors(&rows).is_empty(), "{rows:?}");
    assert!(rows.iter().any(|r| r.check == "update channel" && r.detail.contains("script")));
}

/// The owner record path as the messages print it (the separator is the platform's).
fn owner_file() -> String {
    Path::new("/cfg").join("install-owner.json").display().to_string()
}

#[test]
fn a_consistent_app_bundle_install_reports_no_problem() {
    let m = machine();
    let state = record(Owner::Gui, "app_bundle", "/Applications/YadoriLink.app");
    let rows = run(&m, &state, &LockProbe::Free, None);
    assert!(errors(&rows).is_empty(), "{rows:?}");
}

#[test]
fn a_record_that_claims_a_bundle_the_path_is_not_is_an_error_with_the_fix() {
    let m = machine();
    for (source, root) in [
        ("app_bundle", "/usr/local/bin"),
        ("microsoft_store", "/usr/local/bin"),
        ("script", "/Applications/YadoriLink.app"),
        ("apt", "C:/Program Files/WindowsApps/Y_1.0"),
    ] {
        let rows = run(
            &m,
            &record(Owner::for_install_source(source), source, root),
            &LockProbe::Free,
            None,
        );
        let errs = errors(&rows);
        assert_eq!(errs.len(), 1, "{source} {root}: {rows:?}");
        assert_eq!(errs[0].check, "install source");
        assert!(errs[0].detail.contains(&format!("delete {}", owner_file())), "{}", errs[0].detail);
    }
}

#[test]
fn a_daemon_that_is_not_the_recorded_installation_is_an_error() {
    let m = machine();
    let state = record(Owner::Cli, "script", "/home/u/.local/lib/yadorilink/1.0");
    let daemon = running("apt", "/usr/bin");
    let rows = run(&m, &state, &LockProbe::Held, Some(&daemon));
    let errs = errors(&rows);
    assert_eq!(errs.len(), 1, "{rows:?}");
    assert_eq!(errs[0].check, "update channel");
    assert!(errs[0].detail.contains("apt") && errs[0].detail.contains("script"));
}

#[test]
fn a_registration_of_another_installation_is_an_error_naming_the_fix() {
    let m = machine();
    let reg =
        service_registrations::TABLE.iter().find(|r| r.kind == Kind::BundledLaunchAgent).unwrap();
    let path = reg.definition_paths(&m.roots).remove(0);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"x").unwrap();
    let state = record(Owner::Cli, "standalone", "/usr/local/bin");
    let rows = run(&m, &state, &LockProbe::Free, None);
    let errs = errors(&rows);
    assert_eq!(errs.len(), 1, "{rows:?}");
    assert_eq!(errs[0].check, "service registrations");
    assert!(errs[0].detail.contains("com.juntaki.yadorilink.daemon"), "{}", errs[0].detail);
    assert!(errs[0].detail.contains("Fix:"), "{}", errs[0].detail);
    // The recorded installation's own registration is not a conflict.
    let own = record(Owner::Gui, "app_bundle", "/Applications/YadoriLink.app");
    assert!(errors(&run(&m, &own, &LockProbe::Free, None)).is_empty());
}

#[test]
fn a_missing_record_is_a_warning_and_an_unreadable_one_an_error() {
    let m = machine();
    let rows = run(&m, &RecordState::Missing, &LockProbe::Free, None);
    assert!(errors(&rows).is_empty());
    assert!(rows.iter().any(|r| r.check == "ownership record" && r.severity == Severity::Warn));
    let rows = run(&m, &RecordState::Unreadable("bad".into()), &LockProbe::Free, None);
    let errs = errors(&rows);
    assert_eq!(errs.len(), 1);
    assert!(errs[0].detail.contains(&format!("delete {}", owner_file())));
}

#[test]
fn without_a_record_the_running_daemon_decides_which_registrations_conflict() {
    let m = machine();
    let reg =
        service_registrations::TABLE.iter().find(|r| r.kind == Kind::BundledLaunchAgent).unwrap();
    let path = reg.definition_paths(&m.roots).remove(0);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"x").unwrap();
    let daemon = running("apt", "/usr/bin");
    let rows = run(&m, &RecordState::Missing, &LockProbe::Held, Some(&daemon));
    assert_eq!(errors(&rows).len(), 1, "{rows:?}");
}

#[test]
fn the_lock_rows_tell_a_wedged_daemon_from_a_running_one() {
    let m = machine();
    let state = record(Owner::Cli, "script", "/x");
    let wedged = run(&m, &state, &LockProbe::Held, None);
    assert!(wedged.iter().any(|r| r.check == "daemon lock" && r.severity == Severity::Warn));
    let unknown = run(&m, &state, &LockProbe::Unknown("denied".into()), None);
    assert!(unknown.iter().any(|r| r.check == "daemon lock" && r.detail.contains("denied")));
}

#[test]
fn the_check_changes_nothing_on_disk() {
    let m = machine();
    let before: Vec<PathBuf> =
        std::fs::read_dir(m.home.path()).unwrap().map(|e| e.unwrap().path()).collect();
    let _ = run(&m, &record(Owner::Gui, "app_bundle", "/usr"), &LockProbe::Free, None);
    let after: Vec<PathBuf> =
        std::fs::read_dir(m.home.path()).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(before, after);
}

#[test]
fn an_owner_that_contradicts_its_install_source_is_an_error_even_with_a_matching_layout() {
    let m = machine();
    let state = record(Owner::Cli, "app_bundle", "/Applications/YadoriLink.app");
    let rows = run(&m, &state, &LockProbe::Free, None);
    let errs = errors(&rows);
    assert_eq!(errs.len(), 1, "{rows:?}");
    assert!(errs[0].detail.contains("owner cli") && errs[0].detail.contains("belongs to gui"));
    assert!(errs[0].detail.contains(&format!("delete {}", owner_file())));
}

fn descriptor_rows(rows: &[Finding]) -> Vec<&Finding> {
    rows.iter().filter(|r| r.check == "release descriptor").collect()
}

#[test]
fn the_same_release_reports_ok_and_no_daemon_reports_nothing() {
    let m = machine();
    let state = record(Owner::Cli, "script", "/opt/y");
    let daemon = running("script", "/opt/y");
    let rows = run(&m, &state, &LockProbe::Held, Some(&daemon));
    let shown = descriptor_rows(&rows);
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0].severity, Severity::Ok);
    assert!(descriptor_rows(&run(&m, &state, &LockProbe::Free, None)).is_empty());
}

#[test]
fn a_daemon_of_another_build_or_api_is_an_error_naming_the_fix() {
    let m = machine();
    let state = record(Owner::Gui, "app_bundle", "/Applications/YadoriLink.app");
    let daemon = RunningInstall {
        release_id: "x:y".into(),
        ..running("app_bundle", "/Applications/YadoriLink.app")
    };
    let rows = run(&m, &state, &LockProbe::Held, Some(&daemon));
    let shown = descriptor_rows(&rows);
    assert_eq!(shown[0].severity, Severity::Error, "{rows:?}");
    assert!(shown[0].detail.contains("x:y") && shown[0].detail.contains("YadoriLink app"));

    let newer = RunningInstall { engine_api_version: 2, ..running("script", "/opt/y") };
    let rows = run(&m, &record(Owner::Cli, "script", "/opt/y"), &LockProbe::Held, Some(&newer));
    assert_eq!(descriptor_rows(&rows)[0].severity, Severity::Error);
}

#[test]
fn an_unusable_own_descriptor_is_an_error_even_without_a_daemon() {
    let m = machine();
    let bad = Err(DescriptorProblem::Unreadable { reason: "garbled".into() });
    let rows = run_with(&m, &RecordState::Missing, &LockProbe::Free, None, &bad);
    let shown = descriptor_rows(&rows);
    assert_eq!(shown[0].severity, Severity::Error);
    assert!(shown[0].detail.contains("garbled"));
}

#[test]
fn a_record_of_another_release_than_the_running_daemon_is_an_error_naming_the_fix() {
    let m = machine();
    let stale = RecordState::Present(OwnershipRecord {
        release_id: "a:b".into(),
        ..match record(Owner::Cli, "script", "/opt/y") {
            RecordState::Present(r) => r,
            _ => unreachable!(),
        }
    });
    let rows = run(&m, &stale, &LockProbe::Held, Some(&running("script", "/opt/y")));
    let found = errors(&rows);
    assert_eq!(found.len(), 1, "{rows:?}");
    assert_eq!(found[0].check, "ownership record");
    assert!(found[0].detail.contains("a:b") && found[0].detail.contains("c:d"), "{:?}", found[0]);
    assert!(found[0].detail.contains("restart"), "{:?}", found[0]);
    // The same release, or no daemon to compare with, reports nothing.
    let same = record(Owner::Cli, "script", "/opt/y");
    assert!(
        errors(&run(&m, &same, &LockProbe::Held, Some(&running("script", "/opt/y")))).is_empty()
    );
    assert!(errors(&run(&m, &stale, &LockProbe::Free, None)).is_empty());
}
