use super::*;

const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn write_identity(dir: &Path, api: u32) {
    std::fs::write(
        dir.join(ENGINE_IDENTITY_FILE),
        format!(
            r#"{{"public_commit_sha":"{COMMIT}","build_config_digest":"{DIGEST}","engine_api_version":{api},"channel":"beta"}}"#
        ),
    )
    .unwrap();
}

fn descriptor(release_id: &str, api: u32, source: &str) -> ReleaseDescriptor {
    ReleaseDescriptor {
        version: "1.2.3".into(),
        channel: String::new(),
        install_source: source.into(),
        release_id: release_id.into(),
        engine_api_version: api,
        state_schema: None,
    }
}

#[test]
fn a_matching_identity_gives_the_full_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    write_identity(dir.path(), 1);
    let d = ReleaseDescriptor::of_program("1.2.3", "script", 1, Some(dir.path())).unwrap();
    assert_eq!(d.release_id, format!("{COMMIT}:{DIGEST}"));
    assert_eq!(
        (d.channel.as_str(), d.engine_api_version, d.install_source.as_str()),
        ("beta", 1, "script")
    );
}

#[test]
fn a_missing_identity_is_an_unversioned_build_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let d = ReleaseDescriptor::of_program("1.2.3", "script", 1, Some(dir.path())).unwrap();
    assert_eq!(d.release_id, "");
    assert_eq!(ReleaseDescriptor::of_program("1", "s", 1, None).unwrap().release_id, "");
}

#[test]
fn an_unreadable_identity_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    for body in [
        &b"garbage"[..],
        br#"{"public_commit_sha":"a"}"#,
        br#"{"public_commit_sha":"a","build_config_digest":"b"}"#,
        br#"{"public_commit_sha":"a","build_config_digest":"b","engine_api_version":"1"}"#,
        br#"{"public_commit_sha":"a","build_config_digest":"b","engine_api_version":-1}"#,
    ] {
        std::fs::write(dir.path().join(ENGINE_IDENTITY_FILE), body).unwrap();
        let problem =
            ReleaseDescriptor::of_program("1", "script", 1, Some(dir.path())).unwrap_err();
        assert!(matches!(problem, DescriptorProblem::Unreadable { .. }), "{body:?}");
        assert!(problem.message().contains("nothing was started"));
    }
    // A directory in the file's place cannot be read either.
    std::fs::remove_file(dir.path().join(ENGINE_IDENTITY_FILE)).unwrap();
    std::fs::create_dir(dir.path().join(ENGINE_IDENTITY_FILE)).unwrap();
    assert!(matches!(
        ReleaseDescriptor::of_program("1", "script", 1, Some(dir.path())),
        Err(DescriptorProblem::Unreadable { .. })
    ));
}

#[test]
fn an_identity_for_another_api_is_a_mixed_bundle() {
    let dir = tempfile::tempdir().unwrap();
    write_identity(dir.path(), 2);
    let problem = ReleaseDescriptor::of_program("1", "script", 1, Some(dir.path())).unwrap_err();
    assert!(matches!(
        problem,
        DescriptorProblem::MixedBundle { identity_api: 2, binary_api: 1, .. }
    ));
    assert!(problem.message().contains("mixes two builds"));
}

#[test]
fn matching_descriptors_pair() {
    let a = descriptor("c:d", 1, "script");
    assert_eq!(check_pair(&a, &descriptor("c:d", 1, "script")), Ok(()));
    // The install source is not compared: a bundled CLI may talk to the app's daemon.
    assert_eq!(check_pair(&a, &descriptor("c:d", 1, "app_bundle")), Ok(()));
    // A caller with no identity is judged by the API version alone.
    assert_eq!(check_pair(&descriptor("", 1, "script"), &descriptor("c:d", 1, "script")), Ok(()));
    assert_eq!(check_pair(&descriptor("", 1, "script"), &descriptor("", 1, "script")), Ok(()));
}

#[test]
fn different_apis_or_builds_do_not_pair() {
    let caller = descriptor("c:d", 1, "script");
    let other_api = descriptor("c:d", 2, "script");
    assert_eq!(
        check_pair(&caller, &other_api),
        Err(PairMismatch::EngineApi { caller: 1, daemon: 2 })
    );
    let other_build = descriptor("x:y", 1, "app_bundle");
    let mismatch = check_pair(&caller, &other_build).unwrap_err();
    assert!(matches!(mismatch, PairMismatch::Build { .. }));
    let text = mismatch.message(&caller, &other_build);
    assert!(
        text.contains("x:y") && text.contains("c:d") && text.contains("Nothing was changed"),
        "{text}"
    );
    assert!(text.contains("YadoriLink app"), "{text}");
    // A daemon with no identity cannot match a caller that has one.
    assert!(check_pair(&caller, &descriptor("", 1, "script")).is_err());
    assert!(mismatch.message(&caller, &descriptor("x:y", 1, "apt")).contains("apt installation"));
}

#[test]
fn the_identity_is_found_beside_the_program_or_at_the_macos_bundle_root() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let exe = bin.join("yadorilink");
    // No identity anywhere: the directory beside the program.
    assert_eq!(identity_dir(&exe).as_deref(), Some(bin.as_path()));
    // The published macOS layout keeps it at the bundle root.
    write_identity(root.path(), 1);
    assert_eq!(identity_dir(&exe).as_deref(), Some(root.path()));
    let d =
        ReleaseDescriptor::of_program("1", "app_bundle", 1, identity_dir(&exe).as_deref()).unwrap();
    assert_eq!(d.release_id, format!("{COMMIT}:{DIGEST}"));
    // One beside the program wins, and a directory not named bin is not searched upwards.
    write_identity(&bin, 1);
    assert_eq!(identity_dir(&exe).as_deref(), Some(bin.as_path()));
    let other = root.path().join("sbin");
    std::fs::create_dir(&other).unwrap();
    assert_eq!(identity_dir(&other.join("yadorilink")).as_deref(), Some(other.as_path()));
}

const BUILT: EmbeddedBuild = EmbeddedBuild {
    release_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    channel: "stable",
};

#[test]
fn a_program_names_its_build_without_an_identity_file() {
    // The desktop host loading the facade, or a program run outside the published layout.
    let dir = tempfile::tempdir().unwrap();
    for identity_dir in [Some(dir.path()), None] {
        let d =
            ReleaseDescriptor::of_build("1", "app_bundle", 1, identity_dir, Some(BUILT)).unwrap();
        assert_eq!(d.release_id, BUILT.release_id);
        assert_eq!(d.channel, "stable");
    }
}

#[test]
fn the_embedded_build_decides_and_the_file_beside_it_may_only_confirm() {
    let dir = tempfile::tempdir().unwrap();
    write_identity(dir.path(), 1);
    let d = ReleaseDescriptor::of_build("1", "script", 1, Some(dir.path()), Some(BUILT)).unwrap();
    assert_eq!((d.release_id.as_str(), d.channel.as_str()), (BUILT.release_id, "stable"));
    // Another build's identity file beside this program is a mixed install, never trusted.
    std::fs::write(
        dir.path().join(ENGINE_IDENTITY_FILE),
        format!(
            r#"{{"public_commit_sha":"{}","build_config_digest":"{DIGEST}","engine_api_version":1}}"#,
            "c".repeat(40)
        ),
    )
    .unwrap();
    let problem =
        ReleaseDescriptor::of_build("1", "script", 1, Some(dir.path()), Some(BUILT)).unwrap_err();
    assert!(matches!(problem, DescriptorProblem::BuildMismatch { .. }), "{problem:?}");
    assert!(
        problem.message().contains("mixes two builds")
            && problem.message().contains("nothing was started")
    );
    // An unreadable file stays unusable even for a program that knows its build.
    std::fs::write(dir.path().join(ENGINE_IDENTITY_FILE), b"garbage").unwrap();
    assert!(matches!(
        ReleaseDescriptor::of_build("1", "script", 1, Some(dir.path()), Some(BUILT)),
        Err(DescriptorProblem::Unreadable { .. })
    ));
}

#[test]
fn without_an_embedded_build_the_identity_file_is_still_the_statement() {
    let dir = tempfile::tempdir().unwrap();
    write_identity(dir.path(), 1);
    let d = ReleaseDescriptor::of_build("1", "script", 1, Some(dir.path()), None).unwrap();
    assert_eq!(d.release_id, format!("{COMMIT}:{DIGEST}"));
}

#[test]
fn an_embedded_build_pairs_with_the_daemon_of_the_same_build_only() {
    let mine = ReleaseDescriptor::of_build("1", "", 1, None, Some(BUILT)).unwrap();
    assert!(check_pair(&mine, &descriptor(BUILT.release_id, 1, "script")).is_ok());
    assert!(matches!(
        check_pair(&mine, &descriptor("other:build", 1, "script")),
        Err(PairMismatch::Build { .. })
    ));
}

fn write_identity_with(dir: &Path, extra: &str) {
    std::fs::write(
        dir.join(ENGINE_IDENTITY_FILE),
        format!(
            r#"{{"public_commit_sha":"{COMMIT}","build_config_digest":"{DIGEST}","engine_api_version":1,"channel":"beta"{extra}}}"#
        ),
    )
    .unwrap();
}

fn state_of(dir: &Path) -> Option<StateSchema> {
    ReleaseDescriptor::of_program("1", "script", 1, Some(dir)).unwrap().state_schema
}

#[test]
fn an_old_identity_without_the_state_fields_still_parses() {
    let dir = tempfile::tempdir().unwrap();
    write_identity(dir.path(), 1);
    assert_eq!(state_of(dir.path()), None);
}

#[test]
fn a_new_identity_declares_what_it_writes_and_reads() {
    let dir = tempfile::tempdir().unwrap();
    write_identity_with(
        dir.path(),
        r#","state_schema_version":132,"state_schema_min_readable":130"#,
    );
    assert_eq!(state_of(dir.path()), Some(StateSchema { writes: 132, reads_from: 130 }));
    // The oldest readable defaults to the written version.
    write_identity_with(dir.path(), r#","state_schema_version":132"#);
    assert_eq!(state_of(dir.path()), Some(StateSchema { writes: 132, reads_from: 132 }));
}

#[test]
fn a_malformed_state_declaration_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    for extra in [
        r#","state_schema_min_readable":5"#,
        r#","state_schema_version":"132""#,
        r#","state_schema_version":0"#,
        r#","state_schema_version":-3"#,
        r#","state_schema_version":5,"state_schema_min_readable":6"#,
        r#","state_schema_version":5,"state_schema_min_readable":null"#,
    ] {
        write_identity_with(dir.path(), extra);
        let problem =
            ReleaseDescriptor::of_program("1", "script", 1, Some(dir.path())).unwrap_err();
        assert!(matches!(problem, DescriptorProblem::Unreadable { .. }), "{extra}");
    }
}

#[test]
fn an_incompatible_upgrade_or_downgrade_is_refused() {
    let target = Some(StateSchema { writes: 10, reads_from: 8 });
    // Equal and older (within the readable range) are accepted.
    for on_disk in [8, 9, 10] {
        assert_eq!(StateSchema::check_readable(on_disk, target), Ok(()), "{on_disk}");
    }
    // A downgrade onto state written by a newer build is refused, with a plain message.
    let refusal = StateSchema::check_readable(11, target).unwrap_err();
    assert_eq!(refusal, StateRefusal::NewerThanReadable { on_disk: 11, newest_readable: 10 });
    assert!(
        refusal.message().contains("downgrading")
            && refusal.message().contains("nothing was changed")
    );
    // An upgrade across a gap the target cannot read is refused too.
    assert_eq!(
        StateSchema::check_readable(7, target),
        Err(StateRefusal::OlderThanReadable { on_disk: 7, oldest_readable: 8 })
    );
}

#[test]
fn a_target_that_declares_nothing_is_not_judged() {
    assert_eq!(StateSchema::check_readable(9999, None), Ok(()));
}

#[test]
fn a_binary_that_writes_another_state_version_than_its_identity_declares_is_a_mixed_bundle() {
    let dir = tempfile::tempdir().unwrap();
    write_identity_with(dir.path(), r#","state_schema_version":132"#);
    let d = ReleaseDescriptor::of_program("1", "script", 1, Some(dir.path())).unwrap();
    assert!(d.clone().confirm_state_schema(132, Some(dir.path())).is_ok());
    let problem = d.confirm_state_schema(133, Some(dir.path())).unwrap_err();
    assert!(matches!(problem, DescriptorProblem::StateSchemaMismatch { .. }));
    assert!(problem.message().contains("nothing was started"));
    // An identity without the declaration confirms nothing and refuses nothing.
    write_identity(dir.path(), 1);
    let d = ReleaseDescriptor::of_program("1", "script", 1, Some(dir.path())).unwrap();
    assert!(d.confirm_state_schema(133, Some(dir.path())).is_ok());
}
