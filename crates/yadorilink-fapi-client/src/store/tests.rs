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
    let err = CredentialStore::configure_from_env(dir.path()).expect_err("unknown backend");
    std::env::remove_var(STORE_VAR);
    assert!(matches!(err, StoreError::UnknownBackend(_)), "got {err}");
}

#[test]
fn naming_a_credential_file_while_selecting_the_keyring_is_refused() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::store::tests::env_lock();
    std::env::set_var(STORE_VAR, "keyring");
    std::env::set_var(FILE_VAR, dir.path().join("creds.json"));
    let err = CredentialStore::configure_from_env(dir.path()).expect_err("conflict");
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
    let store = CredentialStore::configure_from_env(dir.path()).expect("file backend");
    std::env::remove_var(FILE_VAR);
    assert_eq!(store.backend(), &Backend::File(dir.path().join("creds.json")));
    assert_eq!(store.lock_path(), dir.path().join(LOCK_FILE));
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
