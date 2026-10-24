//! The installation witness of an embedded engine is kept where the host says, never guessed:
//! an engine given no placement is refused, an explicit directory is the one used, and beside
//! the database is an explicit choice.

use yadorilink_embedded_host::{
    EmbeddedHost, EngineTuning, HostError, StartError, WitnessPlacement,
};

mod support;
use support::{area, serialized};

#[test]
fn a_start_without_a_witness_placement_is_refused_and_an_explicit_one_is_honoured() {
    let _serial = serialized();

    let unset = area();
    let mut config = unset.config.clone();
    config.tuning = EngineTuning::default();
    assert_eq!(config.tuning.witness, WitnessPlacement::Unset);
    let error = EmbeddedHost::new(config).start().expect_err("no placement, no start");
    assert!(
        matches!(error, HostError::Start(StartError::WitnessPlacementRequired)),
        "a typed refusal: {error:?}"
    );
    assert!(error.to_string().contains("witness"), "{error}");
    assert!(!unset.config.config_dir.exists(), "a refused start created nothing");

    // A location the system may clear is not a persistent one: refused the same way.
    let cache = area();
    let mut config = cache.config.clone();
    config.tuning.witness = WitnessPlacement::At(cache._dir.path().join("cache"));
    assert!(matches!(
        EmbeddedHost::new(config).start(),
        Err(HostError::Start(StartError::WitnessPlacementRequired))
    ));

    let named = area();
    let host = EmbeddedHost::new(named.config.clone());
    host.start().expect("a named directory starts");
    host.stop().unwrap();

    let beside = area();
    let mut config = beside.config.clone();
    config.tuning.witness = WitnessPlacement::BesideDatabase;
    let host = EmbeddedHost::new(config);
    host.start().expect("beside the database starts when chosen explicitly");
    host.stop().unwrap();
}

/// A `Persistent` directory that is not a usable one is refused at start with a typed error and
/// nothing is created: a relative path (the process's working directory), or one equal to or
/// inside the state directory, the database's directory or the block store.
#[test]
fn a_persistent_directory_inside_the_data_area_or_relative_is_refused() {
    let _serial = serialized();

    let mut probe = area();
    let provider_temp = probe._dir.path().join("provider-temp");
    probe.config.provider_temp_root = Some(provider_temp.clone());
    let state = probe.config.config_dir.clone();
    let db_dir = probe.config.sync_db_path.parent().unwrap().to_path_buf();
    let blocks = probe.config.block_store_root.clone();
    let bad = [
        std::path::PathBuf::new(),
        "relative-witness".into(),
        state.clone(),
        state.join("witness"),
        db_dir.clone(),
        db_dir.join("witness"),
        blocks.join("witness"),
        provider_temp.join("witness"),
    ];
    // A symlink into the state directory (unix only: creating one needs privilege on Windows).
    #[cfg(unix)]
    let linked = {
        std::fs::create_dir_all(&state).unwrap();
        let link = db_dir.join("link-into-state");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        Some(link.join("witness"))
    };
    #[cfg(not(unix))]
    let linked: Option<std::path::PathBuf> = None;
    for dir in bad.into_iter().chain(linked) {
        let mut config = probe.config.clone();
        config.tuning.witness = WitnessPlacement::Persistent(dir.clone());
        let error = EmbeddedHost::new(config).start().expect_err(&format!("{dir:?} is refused"));
        assert!(
            matches!(error, HostError::Start(StartError::WitnessDirUnusable(_))),
            "{dir:?}: a typed refusal: {error:?}"
        );
    }
    // The refused starts wrote no witness into the working directory.
    assert!(!std::path::Path::new("relative-witness").exists());
}
