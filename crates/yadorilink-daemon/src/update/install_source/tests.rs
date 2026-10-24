#![cfg(test)]

use std::cell::RefCell;
use std::process::{ExitStatus, Output};

use super::*;

struct MockRunner {
    stdout: &'static str,
    succeed: bool,
    calls: RefCell<Vec<(String, Vec<String>)>>,
}

#[cfg(unix)]
fn mock_exit_status(succeed: bool) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    ExitStatus::from_raw(if succeed { 0 } else { 1 << 8 })
}
#[cfg(windows)]
fn mock_exit_status(succeed: bool) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(if succeed { 0 } else { 1 })
}

impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> std::io::Result<Output> {
        self.calls
            .borrow_mut()
            .push((program.to_string(), args.iter().map(|s| s.to_string()).collect()));
        Ok(Output {
            status: mock_exit_status(self.succeed),
            stdout: self.stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        })
    }
}

/// A real file so `canonicalize` succeeds and the mocked `dpkg-query -S`
/// output can be built against the exact resolved path, matching how
/// real dpkg output is keyed.
fn temp_binary() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("yadorilink");
    std::fs::write(&path, b"x").unwrap();
    let canonical = std::fs::canonicalize(&path).unwrap();
    (dir, canonical)
}

#[test]
fn dpkg_owning_the_exact_running_binary_reports_apt() {
    let (_dir, exe) = temp_binary();
    let stdout: &'static str =
        Box::leak(format!("yadorilink: {}\n", exe.display()).into_boxed_str());
    let runner = MockRunner { stdout, succeed: true, calls: RefCell::new(vec![]) };
    assert_eq!(detect_linux_install_source(&runner, &exe), "apt");
    assert_eq!(
        runner.calls.borrow()[0],
        ("dpkg-query".to_string(), vec!["-S".to_string(), exe.to_str().unwrap().to_string(),])
    );
}

#[test]
fn dpkg_not_owning_this_path_reports_standalone() {
    // This is the coexisting-installs case the path-scoping fix
    // targets: a `.deb` may have put a *different* binary at
    // /usr/bin/yadorilink, but dpkg-query -S has no record of *this*
    // path at all (e.g. a standalone tarball extraction under
    // ~/.local/bin), so it exits non-zero ("no path found matching
    // pattern") regardless of whether the yadorilink package is
    // installed somewhere else.
    let (_dir, exe) = temp_binary();
    let runner = MockRunner { stdout: "", succeed: false, calls: RefCell::new(vec![]) };
    assert_eq!(detect_linux_install_source(&runner, &exe), "standalone");
}

#[test]
fn path_owned_by_a_different_package_reports_standalone() {
    let (_dir, exe) = temp_binary();
    let stdout: &'static str =
        Box::leak(format!("some-other-package: {}\n", exe.display()).into_boxed_str());
    let runner = MockRunner { stdout, succeed: true, calls: RefCell::new(vec![]) };
    assert_eq!(detect_linux_install_source(&runner, &exe), "standalone");
}

#[test]
fn missing_dpkg_query_reports_standalone() {
    struct MissingRunner;
    impl CommandRunner for MissingRunner {
        fn run(&self, _program: &str, _args: &[&str]) -> std::io::Result<Output> {
            Err(std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }
    let (_dir, exe) = temp_binary();
    assert_eq!(detect_linux_install_source(&MissingRunner, &exe), "standalone");
}

#[test]
fn nonexistent_exe_falls_back_to_the_given_path_rather_than_erroring() {
    // canonicalize() fails for a path that doesn't exist (a deleted/
    // replaced binary) -- must fall back to the given path, not panic.
    let runner = MockRunner { stdout: "", succeed: false, calls: RefCell::new(vec![]) };
    let missing = Path::new("/nonexistent/path/to/yadorilink");
    assert_eq!(detect_linux_install_source(&runner, missing), "standalone");
    assert_eq!(runner.calls.borrow()[0].1[1], "/nonexistent/path/to/yadorilink");
}

#[test]
fn missing_marker_reports_standalone() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("install_source");
    assert_eq!(detect_macos_install_source_at(&marker), "standalone");
}

#[test]
fn homebrew_marker_reports_homebrew() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("install_source");
    std::fs::write(&marker, "homebrew\n").unwrap();
    assert_eq!(detect_macos_install_source_at(&marker), "homebrew");
}

#[test]
fn unrecognized_marker_contents_report_standalone() {
    // A marker file must contain exactly "homebrew" to count -- garbage
    // or a future package-manager name this build doesn't know about
    // must fail closed to "standalone", not be trusted verbatim.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("install_source");
    std::fs::write(&marker, "not-homebrew").unwrap();
    assert_eq!(detect_macos_install_source_at(&marker), "standalone");
}

#[test]
fn windowsapps_path_detects_as_store() {
    let source = detect_windows_install_source(Path::new(
        r"C:\Program Files\WindowsApps\Yadorilink_1.0\yadorilink.exe",
    ));
    assert_eq!(source, InstallSource::MicrosoftStore);
}

#[test]
fn program_files_path_detects_as_standalone() {
    let source =
        detect_windows_install_source(Path::new(r"C:\Program Files\yadorilink\yadorilink.exe"));
    assert_eq!(source, InstallSource::Standalone);
}

#[test]
fn guidance_points_package_managed_installs_at_their_manager() {
    assert!(manual_update_guidance("homebrew").contains("brew upgrade"));
    assert!(manual_update_guidance("apt").contains("apt install --only-upgrade"));
    assert!(manual_update_guidance("winget").contains("winget upgrade"));
    assert!(manual_update_guidance("microsoft_store").contains("Microsoft Store"));
    assert!(manual_update_guidance("app_store").contains("App Store"));
}

#[test]
fn an_app_store_install_is_managed_and_never_offered_a_download() {
    assert_eq!(InstallSource::AppStore.as_str(), "app_store");
    assert_eq!(manual_update_page("app_store"), None);
    assert!(!manual_update_guidance("app_store").contains(DOWNLOAD_PAGE_URL));
}

#[test]
fn guidance_for_a_standalone_install_is_the_download_page() {
    let g = manual_update_guidance("standalone");
    assert!(g.starts_with("Download the new version"));
    assert!(g.contains(DOWNLOAD_PAGE_URL));
}

#[test]
fn the_page_to_open_is_set_only_for_installs_nobody_else_manages() {
    for managed in ["homebrew", "apt", "winget", "microsoft_store", "app_store"] {
        assert_eq!(manual_update_page(managed), None, "{managed}");
    }
    for own in ["standalone", "unknown", ""] {
        assert_eq!(manual_update_page(own), Some(DOWNLOAD_PAGE_URL), "{own}");
    }
}

#[test]
fn an_executable_inside_an_app_bundle_is_an_app_bundle_install() {
    for exe in [
        "/Applications/YadoriLink.app/Contents/MacOS/yadorilink",
        "/Applications/YadoriLink.app/Contents/Helpers/yadorilink-daemon",
        "/Applications/YadoriLink.app/Contents/Library/LoginItems/Daemon.app/Contents/MacOS/yadorilink-daemon",
    ] {
        // Whatever the platform's own detection found, the bundle layout wins.
        for detected in ["standalone", "homebrew"] {
            assert_eq!(refine(detected.into(), Path::new(exe), None), "app_bundle", "{exe}");
        }
    }
}

#[test]
fn a_loose_executable_keeps_the_platform_detection() {
    for detected in ["standalone", "homebrew", "apt", "winget", "microsoft_store"] {
        assert_eq!(
            refine(detected.into(), Path::new("/usr/local/bin/yadorilink-daemon"), None),
            detected
        );
    }
}

#[test]
fn only_container_is_honoured_from_the_environment() {
    let exe = Path::new("/usr/local/bin/yadorilink-daemon");
    assert_eq!(refine("standalone".into(), exe, Some("container")), "container");
    assert_eq!(refine("standalone".into(), exe, Some("homebrew")), "standalone");
    assert_eq!(refine("standalone".into(), exe, Some("app_bundle")), "standalone");
}

#[test]
fn a_one_liner_receipt_beside_the_binary_marks_a_script_install() {
    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("yadorilink-daemon");
    assert_eq!(refine("standalone".into(), &exe, None), "standalone");
    std::fs::write(dir.path().join(SCRIPT_RECEIPT_FILE), br#"{"source":"script","version":"1"}"#)
        .unwrap();
    assert_eq!(refine("standalone".into(), &exe, None), "script");
    // A package manager's own marker is never overridden by a receipt.
    assert_eq!(refine("apt".into(), &exe, None), "apt");
    // An unreadable or foreign receipt is not a script install.
    std::fs::write(dir.path().join(SCRIPT_RECEIPT_FILE), b"nonsense").unwrap();
    assert_eq!(refine("standalone".into(), &exe, None), "standalone");
    std::fs::write(dir.path().join(SCRIPT_RECEIPT_FILE), br#"{"source":"other"}"#).unwrap();
    assert_eq!(refine("standalone".into(), &exe, None), "standalone");
}

#[cfg(unix)]
#[test]
fn the_installed_link_is_resolved_before_looking_for_the_receipt() {
    // `<prefix>/bin/yadorilink-daemon` -> `<prefix>/share/yadorilink/versions/1/yadorilink-daemon`,
    // the receipt sits beside the real program. Resolution is `running_exe`'s job (macOS reports
    // the link path); `refine` is given the resolved path.
    let dir = tempfile::tempdir().unwrap();
    let version = dir.path().join("share/yadorilink/versions/1");
    std::fs::create_dir_all(&version).unwrap();
    std::fs::create_dir_all(dir.path().join("bin")).unwrap();
    std::fs::write(version.join("yadorilink-daemon"), b"").unwrap();
    std::fs::write(version.join(SCRIPT_RECEIPT_FILE), br#"{"source":"script"}"#).unwrap();
    let link = dir.path().join("bin/yadorilink-daemon");
    std::os::unix::fs::symlink(version.join("yadorilink-daemon"), &link).unwrap();
    assert_eq!(
        refine("standalone".into(), &link, None),
        "standalone",
        "the link path alone has no receipt"
    );
    let resolved = std::fs::canonicalize(&link).unwrap();
    assert_eq!(refine("standalone".into(), &resolved, None), "script");
}

#[test]
fn guidance_for_app_and_container_installs_names_their_owner() {
    assert!(manual_update_guidance("app_bundle").contains("Check for Updates"));
    assert!(manual_update_guidance("container").contains("image"));
    assert_eq!(manual_update_page("app_bundle"), None);
    assert_eq!(manual_update_page("container"), None);
}
