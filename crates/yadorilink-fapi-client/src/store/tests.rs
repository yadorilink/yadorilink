#![cfg(test)]

use super::*;

fn sample() -> Credentials {
    Credentials {
        issuer: "https://as.test".into(),
        client_id: "ylk-abc".into(),
        client_key_jwk: r#"{"kty":"EC"}"#.into(),
        refresh_token: "rt-1".into(),
    }
}

fn file_store(dir: &Path) -> CredentialStore {
    CredentialStore::with_backend(Backend::File(dir.join(CREDENTIALS_FILE)), dir)
}

/// Acquires the rotation lock synchronously, for a test whose only need of
/// an async runtime is to obtain the proof-of-possession token every
/// mutating method now requires.
fn locked(store: &CredentialStore) -> CredentialLock {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime")
        .block_on(store.lock(std::time::Duration::from_secs(5)))
        .expect("lock")
}

#[test]
fn an_absent_store_reads_as_not_enrolled_rather_than_as_an_error() {
    let dir = tempfile::tempdir().expect("temp dir");
    assert!(file_store(dir.path()).load().expect("absent is not an error").is_none());
}

#[test]
fn a_saved_credential_round_trips() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    store.save(&locked(&store), &sample()).expect("save");
    assert_eq!(store.load().expect("load"), Some(sample()));
}

/// The whole point of the separate rotation path: it must not be able to
/// disturb the client key, which is the credential a rotation has no
/// business touching.
#[test]
fn rotating_the_refresh_token_leaves_the_client_key_and_id_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    store.save(&locked(&store), &sample()).expect("save");

    store.rotate_refresh_token(&locked(&store), &sample().client_id, "rt-2").expect("rotate");

    let loaded = store.load().expect("load").expect("still enrolled");
    assert_eq!(loaded.refresh_token, "rt-2");
    assert_eq!(loaded.client_id, sample().client_id);
    assert_eq!(loaded.client_key_jwk, sample().client_key_jwk);
}

#[test]
fn rotating_with_nothing_enrolled_is_refused_rather_than_creating_a_partial_record() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    let err = store
        .rotate_refresh_token(&locked(&store), "ylk-anything", "rt-2")
        .expect_err("no enrolment");
    assert!(matches!(err, StoreError::NotEnrolled), "got {err}");
}

/// The second, independent check the doc comment promises: even under the
/// lock, a rotation computed for one `client_id` must not be applied to a
/// record that -- sequentially, not by a race the lock already closes --
/// now names a different one, such as a logout followed by a fresh
/// enrolment between when this rotation's caller read the old credential
/// and when it tries to persist the rotation.
#[test]
fn rotating_against_a_replaced_client_id_is_refused_rather_than_applied() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    store.save(&locked(&store), &sample()).expect("save");

    let err = store
        .rotate_refresh_token(&locked(&store), "ylk-a-different-installation", "rt-2")
        .expect_err("the stored client_id does not match");
    assert!(matches!(&err, StoreError::ClientIdChanged { .. }), "got {err}");
    assert_eq!(
        store.load().expect("load").expect("still enrolled").refresh_token(),
        sample().refresh_token(),
        "a refused rotation must not have touched the stored refresh token"
    );
}

/// THE PROPERTY EVERY MUTATION'S `&CredentialLock` PARAMETER EXISTS FOR.
/// A `CredentialLock` proves its holder took the lock at ONE path; taking
/// that lock and presenting it to a DIFFERENT store's `save` /
/// `rotate_refresh_token` / `clear` must not compile-and-run as if the
/// two agreed on anything, because `flock` on path A never contended with
/// anything writing to path B. Two independent stores over two
/// independent config directories are the shape this closes: their lock
/// files are different files, so a lock from one is worthless proof
/// against the other, and this is the check that makes it a refusal
/// rather than a mutation that ran with no real mutual exclusion at all.
#[test]
fn a_lock_acquired_for_one_store_cannot_mutate_a_different_store() {
    let dir_a = tempfile::tempdir().expect("temp dir");
    let dir_b = tempfile::tempdir().expect("temp dir");
    let store_a = file_store(dir_a.path());
    let store_b = file_store(dir_b.path());

    let lock_a = locked(&store_a);

    let err = store_b.save(&lock_a, &sample()).expect_err("a foreign lock must be refused");
    assert!(matches!(&err, StoreError::WrongLock { .. }), "got {err}");
    assert!(store_b.load().expect("load").is_none(), "the mutation must not have run");

    // And the store the lock actually belongs to is unaffected by the
    // attempt -- this is a refusal, not a lock transfer.
    store_a.save(&lock_a, &sample()).expect("the lock's own store still accepts it");
}

/// A stored document is a whole credential or it is not a document. The
/// backend holding nothing is the *only* representation of "not enrolled";
/// a document that exists and carries no `client` is a store that was
/// written and then damaged, and reading it as absence would send the
/// caller to `yadorilink login` to paper over corruption.
#[test]
fn a_document_with_no_client_is_refused_rather_than_read_as_not_enrolled() {
    let dir = tempfile::tempdir().expect("temp dir");
    file::write(&dir.path().join(CREDENTIALS_FILE), r#"{"format":2}"#).expect("write");
    let err = file_store(dir.path()).load().expect_err("a clientless document is not absence");
    assert!(matches!(err, StoreError::Unreadable(_)), "got {err}");
    assert!(format!("{err}").contains("client"), "the refusal must name what is missing: {err}");
}

/// The deleted legacy coordination plane must not be able to come back as
/// data. A document carrying `legacy_session` is refused outright rather
/// than silently stripped down to its new-plane half, whatever `format`
/// it claims.
#[test]
fn a_document_carrying_the_deleted_legacy_session_member_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let smuggled = concat!(
        r#"{"format":2,"client":{"issuer":"https://as.test","client_id":"ylk-abc","#,
        r#""client_key_jwk":"{}","refresh_token":"rt-1"},"#,
        r#""legacy_session":{"access_token":"legacy-at","refresh_token":"legacy-rt"}}"#
    );
    file::write(&dir.path().join(CREDENTIALS_FILE), smuggled).expect("write");
    let err = file_store(dir.path()).load().expect_err("the legacy plane is not readable");
    assert!(matches!(err, StoreError::Unreadable(_)), "got {err}");
    assert!(
        format!("{err}").contains("legacy_session"),
        "the refusal must name the member it rejected: {err}"
    );
}

#[test]
fn a_document_with_an_arbitrary_unknown_field_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let extra = concat!(
        r#"{"format":2,"client":{"issuer":"https://as.test","client_id":"ylk-abc","#,
        r#""client_key_jwk":"{}","refresh_token":"rt-1"},"invented":true}"#
    );
    file::write(&dir.path().join(CREDENTIALS_FILE), extra).expect("write");
    let err = file_store(dir.path()).load().expect_err("an unknown member is not ignorable");
    assert!(matches!(err, StoreError::Unreadable(_)), "got {err}");
}

/// The same rule one level down. An access token smuggled into the client
/// record is exactly the shape this store exists to make impossible.
#[test]
fn an_unknown_member_inside_the_client_record_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let extra = concat!(
        r#"{"format":2,"client":{"issuer":"https://as.test","client_id":"ylk-abc","#,
        r#""client_key_jwk":"{}","refresh_token":"rt-1","access_token":"at-1"}}"#
    );
    file::write(&dir.path().join(CREDENTIALS_FILE), extra).expect("write");
    let err = file_store(dir.path()).load().expect_err("an unknown member is not ignorable");
    assert!(matches!(err, StoreError::Unreadable(_)), "got {err}");
    assert!(format!("{err}").contains("access_token"), "got {err}");
}

#[test]
fn a_document_with_no_format_is_refused_rather_than_assumed_current() {
    let dir = tempfile::tempdir().expect("temp dir");
    let no_format = concat!(
        r#"{"client":{"issuer":"https://as.test","client_id":"ylk-abc","#,
        r#""client_key_jwk":"{}","refresh_token":"rt-1"}}"#
    );
    file::write(&dir.path().join(CREDENTIALS_FILE), no_format).expect("write");
    let err = file_store(dir.path()).load().expect_err("an unversioned document is refused");
    assert!(matches!(err, StoreError::Unreadable(_)), "got {err}");
    assert!(format!("{err}").contains("format"), "got {err}");
}

/// Refusing to *read* a pre-release document only helps if the documented
/// answer -- re-enrol -- can actually be carried out. Enrolment replaces
/// the document; it does not have to parse the one it is replacing.
#[test]
fn enrolling_over_an_unreadable_pre_release_document_replaces_it() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    let pre_cutover = r#"{"format":1,"legacy_session":{"access_token":"legacy-at"}}"#;
    file::write(&dir.path().join(CREDENTIALS_FILE), pre_cutover).expect("write");
    assert!(store.load().is_err(), "the pre-release document must not be readable");

    store
        .save(&locked(&store), &sample())
        .expect("re-enrolment must not be blocked by the store it replaces");
    assert_eq!(store.load().expect("load"), Some(sample()));
}

/// A record with a missing field is a damaged store. Reading it as "not
/// enrolled" would send the caller to `yadorilink login`, which would
/// succeed and leave the account holding two registrations, one of them
/// unreachable.
#[test]
fn a_record_missing_a_field_is_refused_rather_than_read_as_absent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    store.save(&locked(&store), &sample()).expect("save");
    // Through the backend, so the file keeps the owner-only mode the
    // permission check demands and this test exercises the field check
    // rather than tripping over 0644 from a bare `fs::write`.
    file::write(
        &dir.path().join(CREDENTIALS_FILE),
        r#"{"format":2,"client":{"issuer":"https://as.test","client_id":"ylk-abc","client_key_jwk":"","refresh_token":"rt-1"}}"#,
    )
    .expect("overwrite");

    let err = store.load().expect_err("a damaged record is not an absent one");
    assert!(
        matches!(&err, StoreError::HalfConfigured(f) if f.contains("client_key_jwk")),
        "got {err}"
    );
}

/// The product-level guarantee, not only the backend's: a credential file
/// anyone else can read stops the store, so a caller cannot end up
/// authenticated from a secret that has already leaked.
#[cfg(unix)]
#[test]
fn a_credential_file_others_can_read_stops_the_store_rather_than_being_used() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    store.save(&locked(&store), &sample()).expect("save");
    std::fs::set_permissions(
        dir.path().join(CREDENTIALS_FILE),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("widen the mode");

    let err = store.load().expect_err("an exposed credential is not usable");
    assert!(matches!(err, StoreError::Permissions { .. }), "got {err}");
}

#[test]
fn a_document_from_a_future_format_is_refused_rather_than_guessed_at() {
    let dir = tempfile::tempdir().expect("temp dir");
    file::write(&dir.path().join(CREDENTIALS_FILE), r#"{"format":99}"#).expect("write");
    let err = file_store(dir.path()).load().expect_err("unknown format");
    assert!(matches!(err, StoreError::UnsupportedFormat { found: 99 }), "got {err}");
}

/// A store written by a build that still had the legacy coordination plane
/// is refused, not imported and not silently stripped down to its new-plane
/// half. The old document is format 1 and carries `legacy_session`; the
/// user re-enrols rather than this build inventing a migration for a
/// pre-release credential.
#[test]
fn a_pre_cutover_document_is_refused_rather_than_migrated() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pre_cutover =
        r#"{"format":1,"legacy_session":{"access_token":"legacy-at","refresh_token":"legacy-rt"}}"#;
    file::write(&dir.path().join(CREDENTIALS_FILE), pre_cutover).expect("write");
    let err = file_store(dir.path()).load().expect_err("a pre-cutover store is not readable");
    assert!(matches!(err, StoreError::UnsupportedFormat { found: 1 }), "got {err}");
}

#[test]
fn an_unknown_backend_name_is_refused_rather_than_defaulted() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::store::tests::env_lock();
    std::env::set_var(STORE_VAR, "gnome-keyring");
    let err = Backend::from_env(dir.path()).expect_err("unknown backend");
    std::env::remove_var(STORE_VAR);
    assert!(matches!(err, StoreError::UnknownBackend(_)), "got {err}");
}

#[test]
fn naming_a_credential_file_while_selecting_the_keyring_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::store::tests::env_lock();
    std::env::set_var(STORE_VAR, "keyring");
    std::env::set_var(FILE_VAR, dir.path().join("creds.json"));
    let err = Backend::from_env(dir.path()).expect_err("conflict");
    std::env::remove_var(STORE_VAR);
    std::env::remove_var(FILE_VAR);
    assert!(matches!(err, StoreError::ConflictingConfiguration), "got {err}");
}

#[test]
fn naming_a_credential_file_alone_selects_the_file_backend() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::store::tests::env_lock();
    std::env::remove_var(STORE_VAR);
    std::env::set_var(FILE_VAR, dir.path().join("creds.json"));
    let backend = Backend::from_env(dir.path()).expect("file backend");
    std::env::remove_var(FILE_VAR);
    assert_eq!(backend, Backend::File(dir.path().join("creds.json")));
}

#[test]
fn the_environment_maps_to_the_same_backend_as_the_explicit_selection() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::store::tests::env_lock();
    let cases: [(Option<&str>, Option<&str>); 5] = [
        (None, None),
        (Some("file"), None),
        (Some("file"), Some("elsewhere.json")),
        (Some("keyring"), None),
        (None, Some("only-file.json")),
    ];
    for (selected, file) in cases {
        match selected {
            Some(v) => std::env::set_var(STORE_VAR, v),
            None => std::env::remove_var(STORE_VAR),
        }
        match file {
            Some(v) => std::env::set_var(FILE_VAR, dir.path().join(v)),
            None => std::env::remove_var(FILE_VAR),
        }
        let from_env = Backend::from_env(dir.path()).expect("valid combination");
        let explicit =
            Backend::select(selected, file.map(|v| dir.path().join(v)), dir.path()).unwrap();
        assert_eq!(from_env, explicit, "{selected:?} {file:?}");
    }
    std::env::remove_var(STORE_VAR);
    std::env::remove_var(FILE_VAR);
    assert_eq!(
        Backend::select(Some("file"), None, dir.path()).unwrap(),
        Backend::File(dir.path().join(CREDENTIALS_FILE))
    );
    assert_eq!(
        Backend::select(Some("keyring"), None, dir.path()).unwrap(),
        Backend::Keyring { scope: None }
    );
}

#[test]
fn a_scoped_keyring_is_its_own_entry_and_a_bad_scope_is_refused() {
    for good in ["engine-a", "a.b_c-9", &"x".repeat(64)] {
        let backend = Backend::scoped_keyring(good).expect(good);
        assert!(matches!(backend.claim_entry(), Ok(EntryClaim::Keyring { scope: Some(_) })));
    }
    // Uppercase and mixed case are refused, not lowered: one credential, one spelling.
    for bad in ["", "a b", "a/b", "../x", &"x".repeat(65), "ENGINE-A", "Engine-a", "engine-A", "é"]
    {
        assert!(
            matches!(Backend::scoped_keyring(bad), Err(StoreError::InvalidKeyringScope(_))),
            "{bad:?}"
        );
    }
    // A scope built by hand (the field is public) is held to the same spelling.
    let raw = Backend::Keyring { scope: Some("ENGINE-A".into()) };
    assert!(matches!(raw.claim_entry(), Err(StoreError::InvalidKeyringScope(_))));
}

/// `YADORILINK_CREDENTIAL_STORE` and `YADORILINK_CREDENTIAL_FILE` are
/// process-global, and Rust runs tests in one process concurrently.
pub(super) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn a_local_purge_removes_the_credential_and_succeeds_when_there_is_none() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = file_store(dir.path());
    store.purge_local(&locked(&store)).expect("nothing stored is success");
    store.save(&locked(&store), &sample()).expect("save");
    store.purge_local(&locked(&store)).expect("purge");
    assert!(store.load().expect("load").is_none());
}

fn file_backend(path: &std::path::Path) -> Backend {
    Backend::File(path.to_path_buf())
}

fn in_use(result: StoreResult<EntryClaim>) -> bool {
    matches!(result, Err(StoreError::EntryInUse(_)))
}

#[test]
fn a_credential_file_is_claimed_by_what_the_os_resolves_not_how_it_is_spelled() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let target = real.join("credentials.json");

    // The file does not exist yet: the claim still resolves dot segments and symlinked parents.
    let first = file_backend(&target).claim_entry().expect("the first claim");
    assert!(in_use(file_backend(&real.join(".").join("credentials.json")).claim_entry()));
    assert!(in_use(
        file_backend(&real.join("..").join("real").join("credentials.json")).claim_entry()
    ));
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(in_use(file_backend(&link.join("credentials.json")).claim_entry()));
    }
    // Another file in the same directory is another entry.
    let other = file_backend(&real.join("other.json")).claim_entry().expect("another entry");
    drop(other);

    // Releasing the claim frees the entry.
    drop(first);
    file_backend(&target).claim_entry().expect("free again");
}

#[cfg(unix)]
#[test]
fn a_hard_link_to_an_existing_credential_file_is_the_same_entry() {
    let dir = tempfile::tempdir().expect("temp dir");
    let original = dir.path().join("original.json");
    std::fs::write(&original, "{}").unwrap();
    let hard = dir.path().join("hard.json");
    std::fs::hard_link(&original, &hard).unwrap();

    let held = file_backend(&original).claim_entry().expect("the first claim");
    assert!(in_use(file_backend(&hard).claim_entry()), "a hard link");
    drop(held);
    file_backend(&hard).claim_entry().expect("free again");
}

#[cfg(windows)]
#[test]
fn a_hard_linked_credential_file_is_refused_until_the_link_is_gone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let original = dir.path().join("original.json");
    std::fs::write(&original, "{}").unwrap();
    let hard = dir.path().join("hard.json");
    std::fs::hard_link(&original, &hard).unwrap();

    for name in [&original, &hard] {
        let err = file_backend(name).claim_entry().expect_err("a hard-linked credential");
        assert!(matches!(err, StoreError::CredentialFileIsHardLinked(_)), "{err:?}");
    }
    std::fs::remove_file(&hard).unwrap();
    file_backend(&original).claim_entry().expect("a single link is claimable");
}

#[cfg(unix)]
#[test]
fn a_credential_path_that_is_a_symlink_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real = dir.path().join("real.json");
    std::fs::write(&real, "{}").unwrap();
    let live = dir.path().join("live.json");
    std::os::unix::fs::symlink(&real, &live).unwrap();
    let dangling = dir.path().join("dangling.json");
    std::os::unix::fs::symlink(dir.path().join("not-yet.json"), &dangling).unwrap();
    for link in [&live, &dangling] {
        let err = file_backend(link).claim_entry().expect_err("a symlink is not a credential path");
        assert!(matches!(err, StoreError::CredentialFileIsSymlink(_)), "{link:?}: {err}");
    }
}

/// Whether the volume of `dir` treats names that differ only by case as one file.
fn is_case_insensitive(dir: &std::path::Path) -> bool {
    let probe = dir.join("case-probe");
    std::fs::write(&probe, b"").unwrap();
    let insensitive = dir.join("CASE-PROBE").exists();
    std::fs::remove_file(&probe).unwrap();
    insensitive
}

#[test]
fn case_aliases_of_a_credential_file_are_one_entry_where_the_volume_says_so() {
    let dir = tempfile::tempdir().expect("temp dir");
    if !is_case_insensitive(dir.path()) {
        eprintln!("skipped: this volume is case-sensitive, so the two names are two files");
        return;
    }
    // Neither credential file exists, only the lock file beside it does.
    let held = file_backend(&dir.path().join("credentials.json")).claim_entry().expect("first");
    assert!(in_use(file_backend(&dir.path().join("Credentials.json")).claim_entry()));
    drop(held);
}

#[test]
fn a_credential_file_whose_directory_does_not_exist_is_refused_not_assumed_distinct() {
    let dir = tempfile::tempdir().expect("temp dir");
    let err = file_backend(&dir.path().join("missing").join("credentials.json"))
        .claim_entry()
        .expect_err("unclaimable");
    assert!(matches!(err, StoreError::UnresolvableCredentialPath(_)), "got {err}");
}

#[cfg(unix)]
#[test]
fn a_directory_alias_is_still_refused_after_the_credential_is_created_and_replaced_by_saves() {
    let dir = tempfile::tempdir().expect("temp dir");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&real).unwrap();
    let alias_dir = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias_dir).unwrap();
    let target = real.join("credentials.json");
    let alias = alias_dir.join("credentials.json");

    // Absent at claim, created afterwards, then replaced by rename as every save does.
    let held = file_backend(&target).claim_entry().expect("the first claim");
    let store = CredentialStore::with_backend(file_backend(&target), &real);
    store.save(&locked(&store), &sample()).expect("created after the claim");
    assert!(in_use(file_backend(&alias).claim_entry()), "alias of the created file");
    store.save(&locked(&store), &sample()).expect("replaced by rename");
    assert!(in_use(file_backend(&alias).claim_entry()), "alias after the rename-over save");
    assert!(in_use(file_backend(&target).claim_entry()), "the file itself");
    drop(held);
    file_backend(&alias).claim_entry().expect("free again");
}

#[test]
fn the_entry_claim_does_not_take_the_rotation_lock_of_a_file_named_credentials() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = file_backend(&dir.path().join("credentials"));
    let _held = backend.claim_entry().expect("claim");
    // The rotation lock is `credentials.lock` in the config directory; the claim leaves it free.
    let store = CredentialStore::with_backend(backend, dir.path());
    let lock = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(store.lock(std::time::Duration::from_millis(200)));
    assert!(lock.is_ok(), "the engine's own rotation lock must stay available");
}

#[test]
fn a_credential_file_named_with_other_casing_does_not_contend_with_its_own_claim() {
    let dir = tempfile::tempdir().expect("temp dir");
    if !is_case_insensitive(dir.path()) {
        eprintln!("skipped: this volume is case-sensitive");
        return;
    }
    std::fs::write(dir.path().join("credentials.json"), "{}").unwrap();
    // The resolved name has the file's own casing, the literal one the host's: one lock file.
    let held = file_backend(&dir.path().join("Credentials.json"))
        .claim_entry()
        .expect("an engine must not conflict with itself");
    assert!(in_use(file_backend(&dir.path().join("credentials.json")).claim_entry()));
    drop(held);
}

#[test]
fn a_credential_file_named_like_a_lock_file_is_refused_whatever_its_case() {
    let dir = tempfile::tempdir().expect("temp dir");
    for name in [LOCK_FILE, "Credentials.lock", "CREDENTIALS.LOCK", "x.entry-lock", "X.Entry-Lock"]
    {
        let err = file_backend(&dir.path().join(name)).claim_entry().expect_err(name);
        assert!(matches!(err, StoreError::CredentialFileIsRotationLock(_)), "{name}: {err}");
    }
    for name in ["credentials.json", "credentials", "my.lock", "credentials.lock.json"] {
        file_backend(&dir.path().join(name)).claim_entry().expect(name);
    }
}
