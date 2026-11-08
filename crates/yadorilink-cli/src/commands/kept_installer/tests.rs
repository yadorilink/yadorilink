use super::*;

fn plan(share: &Path) -> Plan {
    plan_in(share)
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// An install directory whose receipt records `script` as the kept installer (or none).
fn share_with(script: Option<&[u8]>, recorded: Option<String>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let share = dir.path();
    std::fs::create_dir_all(share.join("installer")).unwrap();
    let mut receipt = String::from("version=0.2.0\ninstall_source=script\n");
    if let Some(hash) = recorded {
        receipt.push_str(&format!("installer_sha256={hash}\n"));
    }
    std::fs::write(share.join("install-receipt"), receipt).unwrap();
    if let Some(bytes) = script {
        std::fs::write(share.join("installer/install.sh"), bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                share.join("installer/install.sh"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
    }
    dir
}

#[test]
fn an_install_without_a_recorded_installer_prints_the_command_as_before() {
    let dir = share_with(None, None);
    assert_eq!(plan(dir.path()), Plan::Print);
    // no receipt at all
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(plan(empty.path()), Plan::Print);
}

#[test]
fn a_kept_installer_that_still_has_its_recorded_hash_is_run_as_the_bytes_that_were_checked() {
    let script = b"#!/bin/sh\necho hello\n";
    let dir = share_with(Some(script), Some(sha(script)));
    assert_eq!(plan(dir.path()), Plan::Run(script.to_vec()));
}

fn refused(plan: Plan) -> String {
    match plan {
        Plan::Refuse(text) => text,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_rewritten_kept_installer_is_not_run_and_the_way_out_is_the_one_liner() {
    let script = b"#!/bin/sh\necho hello\n";
    let dir = share_with(Some(script), Some(sha(script)));
    std::fs::write(dir.path().join("installer/install.sh"), b"#!/bin/sh\nrm -rf ~\n").unwrap();
    let text = refused(plan(dir.path()));
    assert!(text.contains("its contents changed"), "{text}");
    assert!(text.contains("nothing was run"), "{text}");
    assert!(text.contains("curl -fsSL https://yadori.link/install.sh | sh"), "{text}");
}

#[test]
fn a_missing_kept_installer_is_not_replaced_by_anything() {
    let script = b"#!/bin/sh\n";
    let dir = share_with(None, Some(sha(script)));
    let text = refused(plan(dir.path()));
    assert!(text.contains("the file is missing"), "{text}");
}

#[cfg(unix)]
#[test]
fn a_symlink_in_place_of_the_kept_installer_is_refused_even_when_its_target_matches() {
    let script = b"#!/bin/sh\necho hello\n";
    let dir = share_with(None, Some(sha(script)));
    let elsewhere = dir.path().join("elsewhere.sh");
    std::fs::write(&elsewhere, script).unwrap();
    std::os::unix::fs::symlink(&elsewhere, dir.path().join("installer/install.sh")).unwrap();
    let text = refused(plan(dir.path()));
    assert!(text.contains("not a regular file"), "{text}");
}

#[cfg(unix)]
#[test]
fn a_kept_installer_other_users_can_write_to_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let script = b"#!/bin/sh\n";
    let dir = share_with(Some(script), Some(sha(script)));
    std::fs::set_permissions(
        dir.path().join("installer/install.sh"),
        std::fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    let text = refused(plan(dir.path()));
    assert!(text.contains("other users can write"), "{text}");
}

#[test]
fn a_malformed_recorded_hash_is_a_refusal_not_a_fallback() {
    let dir = share_with(Some(b"#!/bin/sh\n"), Some("not-a-hash".into()));
    let text = refused(plan(dir.path()));
    assert!(text.contains("malformed"), "{text}");
}

#[cfg(unix)]
#[test]
fn the_verified_bytes_run_with_the_arguments_and_the_status_comes_back() {
    let script = b"#!/bin/sh\nprintf '%s ' \"$@\" > \"$OUT\"\nexit 7\n";
    let out = tempfile::tempdir().unwrap();
    let file = out.path().join("args.txt");
    std::env::set_var("OUT", &file);
    let status =
        run(script, &Call { args: vec!["--version".into(), "0.3.0".into(), "--yes".into()] })
            .unwrap();
    std::env::remove_var("OUT");
    assert_eq!(status, 7);
    assert_eq!(std::fs::read_to_string(file).unwrap().trim(), "--version 0.3.0 --yes");
}

#[test]
fn only_the_unpinned_key_status_has_a_standing_answer() {
    let text = guidance_for(STATUS_KEY_NOT_PINNED).expect("guidance");
    assert!(text.contains("too far behind"), "{text}");
    assert!(text.contains("curl -fsSL https://yadori.link/install.sh | sh"), "{text}");
    assert_eq!(guidance_for(4), None);
    assert_eq!(guidance_for(0), None);
}

#[test]
fn the_installer_keeps_its_receipt_and_copy_under_share_yadorilink() {
    assert_eq!(
        install_dir(std::path::Path::new("/p")),
        std::path::Path::new("/p/share/yadorilink")
    );
}
