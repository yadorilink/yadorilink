use super::*;

fn win(packaged: bool) -> Env {
    Env {
        userprofile: Some(r"C:\Users\ann".into()),
        appdata: Some(r"C:\Users\ann\AppData\Roaming".into()),
        localappdata: Some(r"C:\Users\ann\AppData\Local".into()),
        packaged,
        ..Env::default()
    }
}

#[test]
fn windows_default_is_outside_appdata_for_every_install_type() {
    for packaged in [false, true] {
        let env = win(packaged);
        let dir = default_dir_for(&env, true).unwrap();
        assert_eq!(dir, PathBuf::from(r"C:\Users\ann").join(".yadorilink"));
        check_placement(&env, &dir).unwrap();
    }
}

#[test]
fn override_wins_and_unpackaged_may_use_any_place() {
    let mut env = win(false);
    env.config_dir = Some(r"C:\Users\ann\AppData\Roaming\yadorilink".into());
    assert_eq!(resolve(&env).unwrap(), PathBuf::from(r"C:\Users\ann\AppData\Roaming\yadorilink"));
    check_placement(&env, &resolve(&env).unwrap()).unwrap();
}

#[test]
fn packaged_refuses_appdata_in_any_spelling() {
    let env = win(true);
    for dir in [
        r"C:\Users\ann\AppData\Roaming\yadorilink",
        r"c:/users/ANN/appdata/local/yadorilink/",
        r"C:\Users\ann\AppData\LocalLow\x",
        r"C:\Users\ann\AppData\Local",
    ] {
        let err = check_placement(&env, Path::new(dir)).unwrap_err();
        assert!(matches!(err, StateDirError::UnderAppDataWhilePackaged { .. }), "{dir}");
        assert!(err.to_string().contains(r".yadorilink"), "names the way out: {err}");
    }
}

#[test]
fn packaged_allows_places_that_only_look_like_appdata() {
    let env = win(true);
    for dir in [r"C:\Users\ann\AppDataX\yl", r"C:\Users\ann\.yadorilink", r"D:\data\yl"] {
        check_placement(&env, Path::new(dir)).unwrap();
    }
}

#[test]
fn no_home_is_an_error_not_a_guess() {
    assert_eq!(default_dir_for(&Env::default(), true), Err(StateDirError::NoHome));
    assert_eq!(default_dir_for(&Env::default(), false), Err(StateDirError::NoHome));
}

#[test]
fn legacy_dir_is_named_but_never_the_current_one() {
    let env = win(false);
    let legacy = legacy_windows_dir(&env).unwrap();
    assert_eq!(legacy, PathBuf::from(r"C:\Users\ann\AppData\Roaming").join("yadorilink"));
    assert_ne!(Some(legacy.clone()), default_dir_for(&env, true).ok());
    assert!(legacy_notice(&legacy, Path::new("X")).contains("not used"));
}

#[test]
fn endpoint_names_follow_the_directory() {
    let a = pipe_name("ctl", "ann", Path::new(r"C:\Users\ann\.yadorilink"));
    assert_eq!(a, pipe_name("ctl", "ann", Path::new(r"c:/users/ann/.YADORILINK/")));
    assert_ne!(a, pipe_name("ctl", "ann", Path::new(r"D:\other")));
    assert_ne!(a, pipe_name("shell", "ann", Path::new(r"C:\Users\ann\.yadorilink")));
    let d = pipe_name("dehydrate", "ann", Path::new(r"C:\Users\ann\.yadorilink"));
    assert_eq!(d, pipe_name("dehydrate", "ann", Path::new(r"c:/users/ann/.YADORILINK/")));
    assert_ne!(d, pipe_name("dehydrate", "ann", Path::new(r"D:\other")));
    assert_ne!(d, a);
    assert!(a.starts_with(r"\\.\pipe\yadorilink-ctl-ann-"));
}

#[test]
fn unix_default_is_the_per_os_data_dir() {
    let env = Env { home: Some("/home/u".into()), ..Env::default() };
    let dir = default_dir_for(&env, false).unwrap();
    assert!(dir.ends_with("yadorilink"));
    assert!(dir.starts_with("/home/u"));
}

#[test]
fn packaged_refuses_prefixed_dotted_and_padded_appdata_spellings() {
    let env = win(true);
    for dir in [
        r"\\?\C:\Users\ann\AppData\Roaming\yl",
        r"\\.\C:\Users\ann\AppData\Local\yl",
        r"\??\C:\Users\ann\AppData\Local\yl",
        r"C:\Users\ann\.yadorilink\..\AppData\Roaming\yl",
        r"C:\Users\ann\AppData\.\Roaming\yl",
        r"C:\Users\ann\AppData.\Roaming. \yl",
        r"C:\Users\ann\AppData\Roaming\..\LocalLow\yl",
        r"C:\\Users\\ann\\APPDATA\\ROAMING\\yl",
    ] {
        let err = check_placement(&env, Path::new(dir));
        assert!(matches!(err, Err(StateDirError::UnderAppDataWhilePackaged { .. })), "{dir}");
    }
}

#[test]
fn packaged_refuses_appdata_even_when_the_variables_are_missing_or_moved() {
    // The profile alone names AppData.
    let mut env =
        Env { userprofile: Some(r"C:\Users\ann".into()), packaged: true, ..Env::default() };
    assert!(check_placement(&env, Path::new(r"C:\Users\ann\AppData\Roaming\yl")).is_err());
    // A redirected APPDATA still refuses its own subtree, and the profile's AppData.
    env.appdata = Some(r"D:\redirected\Roaming".into());
    assert!(check_placement(&env, Path::new(r"D:\redirected\Roaming\yl")).is_err());
    assert!(check_placement(&env, Path::new(r"C:\Users\ann\AppData\Local\yl")).is_err());
}

#[test]
fn a_misplaced_appdata_variable_does_not_refuse_a_whole_drive() {
    let env = Env {
        userprofile: Some(r"C:\Users\ann".into()),
        appdata: Some(r"C:\Roaming".into()),
        localappdata: Some(r"C:\Stuff".into()),
        packaged: true,
        ..Env::default()
    };
    check_placement(&env, Path::new(r"C:\data\yl")).unwrap();
    check_placement(&env, Path::new(r"C:\Users\ann\.yadorilink")).unwrap();
    assert!(check_placement(&env, Path::new(r"C:\Roaming\yl")).is_err());
}

#[test]
fn endpoint_names_agree_across_spellings_of_one_directory() {
    let a = pipe_name("ctl", "ann", Path::new(r"C:\Users\ann\.yadorilink"));
    for spelling in [
        r"\\?\C:\Users\ann\.yadorilink",
        r"C:\Users\ann\x\..\.yadorilink\",
        r"C:\Users\ann\.\.yadorilink",
        r"C:\Users\ann\.yadorilink.",
        r"C:\\Users\\ann\\.yadorilink",
    ] {
        assert_eq!(a, pipe_name("ctl", "ann", Path::new(spelling)), "{spelling}");
    }
}

#[cfg(windows)]
#[test]
fn packaged_refuses_a_junction_and_a_short_name_into_appdata() {
    let root = tempfile::tempdir().unwrap();
    let profile = root.path().canonicalize().unwrap();
    let roaming = profile.join("AppData").join("Roaming");
    std::fs::create_dir_all(roaming.join("Some Long Folder Name")).unwrap();
    let env = Env {
        userprofile: Some(profile.clone().into()),
        appdata: Some(roaming.clone().into()),
        packaged: true,
        ..Env::default()
    };
    // A junction outside AppData that points into it.
    let link = profile.join("elsewhere");
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&roaming)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    assert!(check_placement(&env, &link.join("yl")).is_err(), "junction");
    // The 8.3 spelling of a folder under AppData (when the volume makes short names).
    let short = std::process::Command::new("cmd")
        .args(["/C", "for", "%I", "in"])
        .arg(format!("(\"{}\")", roaming.join("Some Long Folder Name").display()))
        .args(["do", "@echo", "%~sI"])
        .output()
        .unwrap();
    let short = String::from_utf8_lossy(&short.stdout).trim().to_string();
    if !short.is_empty()
        && short.to_lowercase()
            != roaming.join("some long folder name").to_string_lossy().to_lowercase()
    {
        assert!(check_placement(&env, Path::new(&short)).is_err(), "short name {short}");
    }
    // A relative override resolves against the working directory.
    let rel = Env { config_dir: Some("rel-state".into()), ..Env::default() };
    assert!(resolve(&rel).unwrap().is_absolute());
}

#[test]
fn the_same_directory_is_recognised_in_any_spelling() {
    assert!(same_dir(
        Path::new(r"C:\Users\ann\AppData\Roaming\yadorilink"),
        Path::new(r"c:/users/ANN/appdata/roaming/yadorilink/")
    ));
    assert!(!same_dir(Path::new(r"C:\a"), Path::new(r"C:\b")));
}

fn override_env(which: PathOverride, path: &str, packaged: bool) -> Env {
    let mut env = win(packaged);
    env.overrides[PathOverride::ALL.iter().position(|w| *w == which).unwrap()] = Some(path.into());
    env
}

#[test]
fn a_packaged_process_gets_a_refusal_not_an_appdata_state_directory() {
    let mut env = win(true);
    env.config_dir = Some(r"C:\Users\ann\AppData\Local\yl".into());
    assert!(matches!(
        checked_state_dir(&env),
        Err(StateDirError::UnderAppDataWhilePackaged { .. })
    ));
    // Unpackaged keeps the choice; the default is fine for both.
    env.packaged = false;
    assert_eq!(checked_state_dir(&env).unwrap(), PathBuf::from(r"C:\Users\ann\AppData\Local\yl"));
    env.config_dir = None;
    env.packaged = true;
    env.home = Some("/home/ann".into());
    assert_eq!(checked_state_dir(&env).unwrap(), default_dir(&env).unwrap());
}

#[test]
fn every_per_path_override_is_refused_under_appdata_when_packaged() {
    for which in PathOverride::ALL {
        for dir in [r"C:\Users\ann\AppData\Roaming\x", r"c:/users/ann/appdata/local/x/blocks"] {
            let err = checked_override(&override_env(which, dir, true), which).unwrap_err();
            let StateDirError::OverrideUnderAppDataWhilePackaged { variable, .. } = &err else {
                panic!("{err:?}")
            };
            assert_eq!(*variable, which.variable());
            assert!(err.to_string().contains(which.variable()));
            // Unpackaged and outside-AppData spellings are honored; unset is None.
            let unpackaged = override_env(which, dir, false);
            assert_eq!(checked_override(&unpackaged, which).unwrap(), Some(PathBuf::from(dir)));
        }
        let outside = override_env(which, r"D:\data\x", true);
        assert_eq!(checked_override(&outside, which).unwrap(), Some(PathBuf::from(r"D:\data\x")));
        assert_eq!(checked_override(&win(true), which).unwrap(), None);
    }
}

#[test]
fn the_override_table_matches_the_variables_the_environment_reads() {
    let names: Vec<_> = PathOverride::ALL.iter().map(|w| w.variable()).collect();
    assert_eq!(
        names,
        [
            "YADORILINK_BLOCK_STORE",
            "YADORILINK_SYNC_DB",
            "YADORILINK_PROVIDER_TEMP_ROOT",
            "YADORILINK_WITNESS_DIR",
            "YADORILINK_CREDENTIAL_FILE",
            "YADORILINK_LOG_FILE"
        ]
    );
    for (i, which) in PathOverride::ALL.iter().enumerate() {
        assert_eq!(which.index(), i);
    }
}

/// No code outside this module may turn a state-placement variable into a path: the resolver is
/// the one place that checks it. Reads in `src/` of any crate that name one of these variables, or
/// an application data variable, fail this test.
#[test]
fn no_source_file_outside_the_resolver_reads_a_placement_variable() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let names: Vec<String> = ["YADORILINK_CONFIG_DIR", "APPDATA", "LOCALAPPDATA"]
        .into_iter()
        .map(String::from)
        .chain(PathOverride::ALL.iter().map(|w| w.variable().to_string()))
        .collect();
    let mut offenders = Vec::new();
    let mut stack = vec![crates.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            let file = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if !["target", "tests", "examples", "benches"].contains(&file.as_str()) {
                    stack.push(path);
                }
                continue;
            }
            if !file.ends_with(".rs")
                || file.ends_with("tests.rs")
                || file.ends_with("_tests.rs")
                || path.ends_with("fs-platform/src/state_dir.rs")
                || path.components().any(|c| c.as_os_str() == "state_dir")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            for (n, line) in text.lines().enumerate() {
                let reads =
                    line.contains("env::var") || line.contains("env!(") || line.contains("var_os(");
                if reads && names.iter().any(|name| line.contains(&format!("\"{name}\""))) {
                    offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "read through the state_dir resolver instead:\n{}",
        offenders.join("\n")
    );
}

/// Spellings that stress byte-offset assumptions: multi-byte, 4-byte, combining and full-width
/// characters at every position a resolver might slice, plus degenerate short inputs.
const TRICKY: &[&str] = &[
    "",
    "\\",
    "\\\\",
    "\\\\?\\",
    "\\\\.\\",
    "\\??\\",
    "\\\\?\\UNC\\",
    "\\\\?\\UNC",
    "C:",
    "C:\\",
    "C:\\\\",
    "C:\\Users\\",
    r"C:\Users\日本語\.yadorilink",
    r"\\?\C:\Users\日本語\AppData\Roaming",
    r"\\?\日本語\x",
    r"\\?\UNC\サーバー\共有\x",
    r"\\サーバー\共有\x",
    r"日本語",
    r"日\x",
    r"あ",
    "é\\x",
    "e\u{301}\u{301}\\x",
    "\u{1F600}",
    "\u{1F600}\\x",
    "\\\u{1F600}",
    "\\\\\u{1F600}",
    "\\\\?\u{1F600}",
    "\\\\?\\\u{1F600}",
    "\\??\u{1F600}",
    "uü\\x",
    "unÿ\\x",
    "Ｃ：＼Ｕｓｅｒｓ",
    "ＵＮＣ\\x",
    "C:\\Users\\ユーザー\\AppData\\Roaming\\",
    "C:\\Users\\ユーザー\\AppData\\Local\\yadorilink ",
    "C:/Users/ユーザー/appdata/local/x/../..",
    "..\\..\\..",
    "...",
    "\\\\?\\unc\\ü",
];

#[test]
fn no_resolver_function_panics_on_any_spelling() {
    for text in TRICKY {
        let path = Path::new(text);
        let _ = components(path);
        let _ = same_dir(path, path);
        let _ = endpoint_suffix(path);
        let _ = pipe_name("ctl", "ユーザー", path);
        for packaged in [false, true] {
            let env = Env {
                userprofile: Some((*text).into()),
                appdata: Some((*text).into()),
                localappdata: Some((*text).into()),
                home: Some((*text).into()),
                packaged,
                ..Env::default()
            };
            let _ = app_data_roots(&env);
            let _ = check_placement(&env, path);
            let _ = default_dir_for(&env, true);
            let _ = default_dir_for(&env, false);
            let _ = legacy_windows_dir(&env);
            let _ = is_within(path, path);
            let _ = checked_state_dir(&env);
        }
        // Every prefix cut at every char boundary, too.
        for (at, _) in text.char_indices() {
            let _ = components(Path::new(&text[..at]));
            let _ = endpoint_suffix(Path::new(&text[at..]));
        }
    }
}

#[test]
fn a_non_ascii_profile_resolves_and_is_placed_outside_appdata() {
    let env = Env {
        userprofile: Some(r"C:\Users\日本語".into()),
        appdata: Some(r"C:\Users\日本語\AppData\Roaming".into()),
        localappdata: Some(r"C:\Users\日本語\AppData\Local".into()),
        packaged: true,
        ..Env::default()
    };
    let dir = default_dir_for(&env, true).unwrap();
    assert_eq!(dir, PathBuf::from(r"C:\Users\日本語").join(".yadorilink"));
    check_placement(&env, &dir).unwrap();
    for under in [
        r"C:\Users\日本語\AppData\Roaming\yadorilink",
        r"c:/users/日本語/appdata/local/x/",
        r"\\?\C:\Users\日本語\AppData\Local",
    ] {
        assert!(check_placement(&env, Path::new(under)).is_err(), "{under}");
    }
}

#[test]
fn unc_prefixes_are_recognised_with_non_ascii_names() {
    assert_eq!(
        components(Path::new(r"\\?\UNC\サーバー\共有\x")),
        components(Path::new(r"\\サーバー\共有\x"))
    );
    assert_eq!(components(Path::new(r"\\?\C:\日本語")), components(Path::new(r"c:\日本語")));
    // A name that merely starts with `unc` plus a multi-byte character is not a UNC prefix.
    assert_eq!(components(Path::new("uncé\\x")), vec!["uncé".to_string(), "x".to_string()]);
}

#[test]
fn the_endpoint_suffix_is_stable_for_a_non_ascii_directory() {
    let a = endpoint_suffix(Path::new(r"C:\Users\日本語\.yadorilink"));
    assert_eq!(a, endpoint_suffix(Path::new(r"c:/users/日本語/.yadorilink/")));
    assert_eq!(a.len(), 8);
    assert_ne!(a, endpoint_suffix(Path::new(r"C:\Users\日本人\.yadorilink")));
}

#[test]
fn an_earlier_builds_sync_root_record_is_found_only_while_it_holds_roots() {
    use crate::generation;
    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("Local");
    let old = local.join("yadorilink");
    let record = old.join("cfapi_sync_roots.txt");
    let env = Env { localappdata: Some(local.clone().into()), ..Env::default() };
    let current = tmp.path().join("state");
    assert_eq!(legacy_sync_roots_record(&env), Some(record.clone()));
    assert_eq!(legacy_sync_roots_record_in_use(&env, &current), None);
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("device.json"), "{}").unwrap();
    assert_eq!(legacy_sync_roots_record_in_use(&env, &current), None);
    let body = format!("{}\tC:\\Users\\ann\\YadoriLink\\Photos\n", "a".repeat(32));
    generation::publish_next(&record, &generation::seal(&body)).unwrap();
    assert_eq!(legacy_sync_roots_record_in_use(&env, &current), Some(record.clone()));
    // The same folder as the current state directory is that directory's own record.
    assert_eq!(legacy_sync_roots_record_in_use(&env, &old), None);
    // Once cleanup retired it, nothing is reported any more.
    generation::remove_all(&record).unwrap();
    assert_eq!(legacy_sync_roots_record_in_use(&env, &current), None);
    assert!(legacy_sync_roots_notice(&record).contains("--unregister-legacy-roots"));
    assert!(!legacy_sync_roots_notice(&record).contains("  "));
    assert_eq!(legacy_sync_roots_record(&Env::default()), None);
}
