#![cfg(test)]

use super::*;

/// Serializes this module's tests against each other: they set the
/// process-global credential-store environment variables. A
/// `tokio::sync::Mutex` because the guard is deliberately held across the
/// `coordination_auth().await` those variables have to stay stable for,
/// which is exactly what `clippy::await_holding_lock` flags on the `std`
/// one.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The daemon half of that requirement. An installation that has not enrolled gets
/// `None`, and getting there does not touch the network -- the
/// Authorization Server address is pointed at a dead port, so any attempt
/// to reach one would surface as an error rather than as `None`.
#[tokio::test]
async fn an_empty_credential_store_is_not_enrolled_and_reaches_no_network() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));
    std::env::set_var(AUTH_SERVER_ADDR_VAR, "http://127.0.0.1:1");

    let result = coordination_auth().await;

    std::env::remove_var(AUTH_SERVER_ADDR_VAR);
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    match result {
        Ok(None) => {}
        other => panic!("expected Ok(None) for an unenrolled installation, got {other:?}"),
    }
}

/// A store this process cannot read is an error, not a `None`. Starting a
/// daemon anyway would be the fall-back-to-anonymity the store exists to
/// refuse, and a document from the build that still had the legacy plane
/// is exactly that case.
#[tokio::test]
async fn a_pre_cutover_store_stops_the_daemon_rather_than_reading_as_signed_out() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("credentials.json");
    std::fs::write(
        &path,
        r#"{"format":1,"legacy_session":{"access_token":"at","refresh_token":"rt"}}"#,
    )
    .expect("write a pre-cutover document");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
    }

    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", &path);

    let result = coordination_auth().await;

    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    assert!(result.is_err(), "a pre-cutover store was accepted: {result:?}");
}

/// The discovery document of a deployment that lives at `socket`, written the
/// way [`remember_discovery_document`] writes it.
fn write_remembered_discovery_document(dir: &std::path::Path, socket: &str) {
    let document = serde_json::json!({
        "base_url": socket,
        "metadata": {
            "issuer": socket,
            "authorization_endpoint": format!("{socket}/auth"),
            "token_endpoint": format!("{socket}/token"),
            "pushed_authorization_request_endpoint": format!("{socket}/request"),
            "require_pushed_authorization_requests": true,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
        }
    });
    std::fs::write(
        dir.join("coordination_discovery.json"),
        serde_json::to_vec_pretty(&document).expect("a serializable document"),
    )
    .expect("write the remembered discovery document");
}

/// Writes an enrolled installation's credential for `issuer` into `path`.
async fn write_enrolled_credential(path: &std::path::Path, issuer: &str) {
    let store = CredentialStore::with_backend(
        yadorilink_fapi_client::Backend::File(path.to_path_buf()),
        path.parent().expect("a parent directory"),
    );
    let credentials = Credentials::new(
        issuer,
        "ylk-offline-start-test",
        yadorilink_fapi_client::Es256Key::generate().to_jwk_json(),
        "refresh-token-no-server-ever-issued",
    );
    let lock =
        store.lock(yadorilink_fapi_client::DEFAULT_LOCK_TIMEOUT).await.expect("the rotation lock");
    store.save(&lock, &credentials).expect("write the credential");
}

/// The daemon must start while the Authorization Server is unreachable.
///
/// This is the first step of the offline restart the last-known-good peer
/// authorization exists for: a device whose internet is out is not a device
/// with a broken installation, and refusing to start takes its local folders
/// and its already-authorized peers on the same network down with the
/// outage. `127.0.0.1:1` is a socket nothing listens on, so the discovery
/// fetch fails at the transport layer exactly as an outage makes it.
#[tokio::test]
async fn an_unreachable_authorization_server_starts_from_the_remembered_document() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = "http://127.0.0.1:1";
    let credential_path = dir.path().join("credentials.json");
    write_enrolled_credential(&credential_path, socket).await;
    write_remembered_discovery_document(dir.path(), socket);

    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", &credential_path);
    std::env::set_var(AUTH_SERVER_ADDR_VAR, socket);

    let result = coordination_auth().await;

    std::env::remove_var(AUTH_SERVER_ADDR_VAR);
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");
    std::env::remove_var("YADORILINK_CONFIG_DIR");

    match result {
        Ok(Some(_)) => {}
        other => panic!(
            "an enrolled device whose Authorization Server is merely unreachable must still \
             start; got {other:?}"
        ),
    }
}

/// The document is not a way around the server saying something. Without one,
/// an unreachable server is still fatal: this device has never successfully
/// spoken to that deployment, so it has nothing to continue.
#[tokio::test]
async fn an_unreachable_authorization_server_with_no_remembered_document_still_refuses() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = "http://127.0.0.1:1";
    let credential_path = dir.path().join("credentials.json");
    write_enrolled_credential(&credential_path, socket).await;

    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", &credential_path);
    std::env::set_var(AUTH_SERVER_ADDR_VAR, socket);

    let result = coordination_auth().await;

    std::env::remove_var(AUTH_SERVER_ADDR_VAR);
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");
    std::env::remove_var("YADORILINK_CONFIG_DIR");

    assert!(
        result.is_err(),
        "a device that has never reached this deployment must not start as if it had: \
         {result:?}"
    );
}

/// A document remembered for a different Authorization Server socket is not
/// this one's. Pointing a device at another deployment must not silently
/// reuse the previous deployment's endpoints.
#[tokio::test]
async fn a_document_remembered_for_another_socket_is_not_used() {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = "http://127.0.0.1:1";
    let credential_path = dir.path().join("credentials.json");
    write_enrolled_credential(&credential_path, socket).await;
    write_remembered_discovery_document(dir.path(), "http://127.0.0.1:2");

    let _guard = ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", &credential_path);
    std::env::set_var(AUTH_SERVER_ADDR_VAR, socket);

    let result = coordination_auth().await;

    std::env::remove_var(AUTH_SERVER_ADDR_VAR);
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");
    std::env::remove_var("YADORILINK_CONFIG_DIR");

    assert!(
        result.is_err(),
        "a document fetched from a different socket was accepted for this one: {result:?}"
    );
}
