//! Two real OS processes rotating one refresh token, with and without the
//! cross-process lock.
//!
//! # The hazard
//!
//! A refresh response rotates the refresh token and kills the one presented.
//! Replaying a spent one is not a harmless 400: it is the canonical signal that
//! a refresh token has been stolen, so the server revokes the whole grant
//! family (RFC 9700 section 4.14.2; `oidc-provider` implements this as
//! `RefreshToken.consumed` plus family revocation). The user is then signed out
//! everywhere, from nothing worse than having run a CLI command while the
//! daemon happened to refresh.
//!
//! And that interleaving is the ordinary case, not a corner: `yadorilink` and
//! `yadorilinkd` run on the same machine, read the same credential store, and
//! each keep their own in-memory cache of a five-minute token. The window in
//! which both decide to refresh is one minute wide (`DEFAULT_REFRESH_SKEW`)
//! out of every five.
//!
//! # Why this test spawns processes instead of tasks
//!
//! The lock is `flock`/`LockFileEx` on a file
//! (`yadorilink_fapi_client::store::lock`). Two tasks in one process would
//! contend on separate file descriptors and so would exercise something --
//! but "cross-process" is the actual claim, and a claim about processes is
//! worth one `fork`. Each child below is this same test binary re-executed
//! with `YL_ROTATION_ROLE` set, so what is measured is two independent address
//! spaces racing on one store, exactly as the CLI and the daemon do.
//!
//! # The two runs, and why the failing one comes first
//!
//! `rotation_without_the_lock_destroys_the_grant` reproduces the damage: the
//! children perform the same read-refresh-persist sequence with no lock held,
//! and the Authorization Server's reuse defence fires. It is not a
//! demonstration of a hypothetical -- it is the exact sequence
//! `CredentialManager::refresh_now` performs, minus one line.
//!
//! `rotation_under_the_lock_keeps_the_grant_alive` then runs the same race
//! through `CredentialManager::force_refresh`, which holds the store lock
//! across the whole read-refresh-persist sequence, and the grant survives.
//!
//! A test that only showed the second would not distinguish "the lock works"
//! from "the race never happened in this run". The first run is the control.
//!
//! # Why the control is a rendezvous and not a repeated attempt
//!
//! The interleaving being reproduced is precise: *both processes read the same
//! refresh token, and only then does either present it.* An earlier shape of
//! this test approximated that by widening the gap between the read and the
//! presentation with a 40ms sleep and rotating twelve times, on the theory that
//! one of the twelve would land. That makes the control's verdict a property of
//! the scheduler -- it passes on an idle laptop and is a coin flip on a loaded
//! CI runner, and a coin flip that comes up green is indistinguishable from a
//! working lock.
//!
//! So the two children synchronise on a file rendezvous in the shared store
//! directory instead:
//!
//! ```text
//! cli    : read rt-N ---> [ rendezvous ] ---> present rt-N
//! daemon : read rt-N ---> [ rendezvous ] ---> present rt-N
//! ```
//!
//! Neither side leaves the rendezvous until both have arrived, and nothing
//! rotates the token while both are waiting, so both provably hold the same
//! `rt-N` before either spends it. Exactly one presentation wins; the other is
//! a spent token by construction, not by luck. One round is then enough, and
//! the assertions can be exact (`issued == 1`) rather than existential.
//!
//! The locked run keeps the same rendezvous at the top of every round, where it
//! does the opposite job: it guarantees that both processes are trying to
//! rotate at the same instant on all twelve rounds, so the lock is genuinely
//! contended every time rather than whenever the timing happened to overlap.

use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use yadorilink_fapi_client::store::{Backend, CredentialStore, Credentials};
use yadorilink_fapi_client::{Es256Key, FapiClient};

/// Set on a child process to tell it which half of the race it is.
const ROLE_VAR: &str = "YL_ROTATION_ROLE";
/// The Authorization Server the child dials.
const AS_VAR: &str = "YL_ROTATION_AS";
/// The directory holding `credentials.json` and `credentials.lock`.
const DIR_VAR: &str = "YL_ROTATION_DIR";
/// `"locked"` or `"unlocked"`.
const MODE_VAR: &str = "YL_ROTATION_MODE";

/// Rotations each child attempts under the lock. Twelve rather than one
/// because what the locked run measures is that serialization *keeps* working:
/// every round is a fresh contended acquire, and a lock that leaked its file
/// descriptor, or released early, or deadlocked on the second acquire, shows up
/// here and not in a single round.
const ROTATIONS_PER_CHILD: u32 = 12;

/// Rotations each child attempts without the lock. One, because the rendezvous
/// makes the reuse certain: repeating it would only be re-presenting tokens to
/// a family the first round has already revoked.
const UNLOCKED_ROTATIONS_PER_CHILD: u32 = 1;

/// How long a child waits at the rendezvous before deciding the other process
/// is never coming. Generous, because a debug-build child still has to start,
/// fetch the discovery document and build a `CredentialManager` before it
/// arrives. Reaching it is a failed test and never a "carry on alone":
/// proceeding alone is precisely the interleaving the rendezvous exists to
/// force.
const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(60);

/// How often a waiting child looks for the other's marker. This affects only
/// how quickly the pair is released. It cannot affect whether both had arrived
/// first -- that is what the marker files decide -- which is the whole reason
/// the rendezvous replaced a sleep.
const RENDEZVOUS_POLL: Duration = Duration::from_millis(5);

/// What the Authorization Server remembers about one grant family.
#[derive(Default)]
struct Grant {
    /// The only refresh token that may be presented next.
    live: String,
    /// Every refresh token this family has ever issued and then rotated away.
    /// Presenting one of these is the reuse signal.
    spent: HashSet<String>,
    /// Set once the reuse defence has fired. Terminal: nothing revives a
    /// revoked family, which is the whole reason the lock exists.
    revoked: bool,
    issued: u32,
    /// How many requests were refused because the family was already dead.
    refusals_after_revocation: u32,
    /// Whether a spent token was ever presented at all.
    reuse_detected: bool,
}

struct TokenEndpoint(Arc<Mutex<Grant>>);

impl Respond for TokenEndpoint {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body = String::from_utf8_lossy(&request.body).into_owned();
        let presented = url::form_urlencoded::parse(body.as_bytes())
            .find(|(k, _)| k == "refresh_token")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();

        let mut grant = self.0.lock().expect("the grant mutex");

        if grant.revoked {
            grant.refusals_after_revocation += 1;
            return invalid_grant("the grant family has been revoked");
        }

        if grant.spent.contains(&presented) {
            // RFC 9700 section 4.14.2. A refresh token presented twice is
            // indistinguishable from a stolen one, so the family dies.
            grant.reuse_detected = true;
            grant.revoked = true;
            return invalid_grant("refresh token reuse detected; the grant family is revoked");
        }

        if presented != grant.live {
            return invalid_grant("unknown refresh token");
        }

        grant.issued += 1;
        let issued = grant.issued;
        let previous = std::mem::replace(&mut grant.live, format!("rt-{issued}"));
        grant.spent.insert(previous);

        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": format!("at-{issued}"),
            "token_type": "DPoP",
            "expires_in": 300,
            "refresh_token": format!("rt-{issued}"),
        }))
    }
}

/// Blocks until both children have reached round `round`.
///
/// Each side creates its own marker and then waits for the other's, so the
/// ordering guarantee is absolute rather than probabilistic: no child returns
/// from here until both have called it. The polling interval decides only how
/// long the second arrival waits, never who arrived first.
///
/// The markers live in a subdirectory of the shared store directory so they
/// cannot be mistaken for the credential document or the lock file, and they
/// are keyed by round so a later round can never be released by an earlier
/// round's marker.
async fn rendezvous(dir: &Path, round: u32, me: &str, other: &str) {
    let gate = dir.join("rendezvous");
    // Both children create this; `create_dir_all` is content with losing.
    std::fs::create_dir_all(&gate).expect("the rendezvous directory");
    std::fs::write(gate.join(format!("{round}-{me}")), b"arrived")
        .expect("drop the rendezvous marker");

    let theirs = gate.join(format!("{round}-{other}"));
    let deadline = Instant::now() + RENDEZVOUS_TIMEOUT;
    while !theirs.exists() {
        assert!(
            Instant::now() < deadline,
            "the {other} process never reached round {round}'s rendezvous, so the two-process \
             interleaving this test measures did not happen and its verdict would mean nothing"
        );
        tokio::time::sleep(RENDEZVOUS_POLL).await;
    }
}

fn invalid_grant(description: &str) -> ResponseTemplate {
    ResponseTemplate::new(400).set_body_json(
        serde_json::json!({ "error": "invalid_grant", "error_description": description }),
    )
}

/// Stands up the Authorization Server and a credential store, runs both
/// children in `mode`, and returns what the server saw.
async fn race(mode: &str) -> (Arc<Mutex<Grant>>, Vec<std::process::Output>) {
    let grant = Arc::new(Mutex::new(Grant { live: "rt-0".to_owned(), ..Grant::default() }));

    let server = MockServer::start().await;
    let issuer = server.uri();

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        // The deployed server's profile, not a three-member minimum. Discovery
        // requires the whole profile -- PAR required, PKCE S256,
        // `private_key_jwt`, ES256 for assertions and for DPoP, the
        // authorization-code and refresh-token grants -- and a mock that
        // advertised less would exercise a client this product cannot build.
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "pushed_authorization_request_endpoint": format!("{issuer}/request"),
            "require_pushed_authorization_requests": true,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(TokenEndpoint(grant.clone()))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let store = CredentialStore::with_backend(
        Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    );
    let client_key = Es256Key::generate();
    let lock = store.lock(Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &Credentials::new(
                issuer.clone(),
                "ylk-rotation".to_owned(),
                client_key.to_jwk_json(),
                "rt-0".to_owned(),
            ),
        )
        .expect("seed the store");
    drop(lock);

    let children: Vec<_> = ["cli", "daemon"]
        .into_iter()
        .map(|role| {
            std::process::Command::new(std::env::current_exe().expect("the test binary"))
                .args(["rotation_child", "--exact", "--nocapture", "--test-threads=1"])
                .env(ROLE_VAR, role)
                .env(AS_VAR, &issuer)
                .env(DIR_VAR, dir.path())
                .env(MODE_VAR, mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn the child process")
        })
        .collect();

    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().expect("wait for the child"))
        .collect();

    (grant, outputs)
}

fn report(label: &str, outputs: &[std::process::Output]) {
    for (role, output) in ["cli", "daemon"].iter().zip(outputs) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // The child's first line shares libtest's "running 1 test" line, so
        // match on the round marker rather than on the start of the line.
        for line in stdout.lines().filter(|l| l.contains(": round ") || l.contains(" round ")) {
            let line = line.rsplit("child ").next().unwrap_or(line);
            println!("{label}: {role}: {line}");
        }
    }
}

/// The control. Without the lock the two processes both read `rt-0`, both
/// present it, and the server kills the family. This is a RED-shaped assertion
/// deliberately written as a passing test: what it asserts is that the damage
/// happens, so that the next test's green is attributable to the lock rather
/// than to the race never having occurred.
///
/// Because the rendezvous forces the interleaving rather than waiting for it,
/// the outcome is a single determined value and the assertions say so: one
/// rotation issued, one spent token presented, one dead family. An assertion
/// that merely said "reuse happened at least once" would still pass if the
/// rendezvous silently stopped working and the old timing race took over.
#[tokio::test(flavor = "multi_thread")]
async fn rotation_without_the_lock_destroys_the_grant() {
    let (grant, outputs) = race("unlocked").await;
    report("unlocked", &outputs);

    let grant = grant.lock().expect("the grant mutex");
    println!(
        "unlocked: issued={} reuse_detected={} revoked={} refused_after_revocation={}",
        grant.issued, grant.reuse_detected, grant.revoked, grant.refusals_after_revocation
    );

    assert!(
        grant.reuse_detected,
        "both processes read the same refresh token and presented it after the rendezvous, yet \
         no spent token was ever seen; the interleaving did not happen, so the locked run below \
         would prove nothing"
    );
    assert!(grant.revoked, "the reuse defence fired without revoking the family");
    assert_eq!(
        grant.issued, 1,
        "exactly one of the two presentations of rt-0 may rotate the grant; the other is the \
         reuse. A different count means the two children did not present the same token, which \
         is the one thing the rendezvous exists to guarantee"
    );
}

/// The same race, through `CredentialManager::force_refresh`, which holds the
/// cross-process lock across read-refresh-persist. Every rotation is serialized
/// against the other process, no spent token is ever presented, and the grant
/// is still usable at the end.
#[tokio::test(flavor = "multi_thread")]
async fn rotation_under_the_lock_keeps_the_grant_alive() {
    let (grant, outputs) = race("locked").await;
    report("locked", &outputs);

    for (role, output) in ["cli", "daemon"].iter().zip(&outputs) {
        assert!(
            output.status.success(),
            "the {role} process failed under the lock:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let grant = grant.lock().expect("the grant mutex");
    println!(
        "locked: issued={} reuse_detected={} revoked={} refused_after_revocation={}",
        grant.issued, grant.reuse_detected, grant.revoked, grant.refusals_after_revocation
    );

    assert!(!grant.reuse_detected, "a spent refresh token was presented despite the lock");
    assert!(!grant.revoked, "the grant family was revoked despite the lock");
    assert_eq!(
        grant.issued,
        ROTATIONS_PER_CHILD * 2,
        "every rotation both processes attempted should have succeeded exactly once"
    );
}

/// The child half of both tests. A no-op in an ordinary run: it does something
/// only when the parent has set [`ROLE_VAR`], which nothing but `race` above
/// ever does.
#[tokio::test]
async fn rotation_child() {
    let Ok(role) = std::env::var(ROLE_VAR) else { return };
    let issuer = std::env::var(AS_VAR).expect("the parent sets the AS URL");
    let dir = std::path::PathBuf::from(std::env::var(DIR_VAR).expect("the parent sets the store"));
    let mode = std::env::var(MODE_VAR).expect("the parent sets the mode");

    let store =
        Arc::new(CredentialStore::with_backend(Backend::File(dir.join("credentials.json")), &dir));
    let credentials = store.load().expect("read the store").expect("the parent seeded it");
    let client_key = Es256Key::from_jwk_json(credentials.client_key_jwk()).expect("the client key");
    let client = FapiClient::discover(
        reqwest::Client::new(),
        &issuer,
        credentials.client_id().to_owned(),
        client_key,
        Es256Key::generate(),
    )
    .await
    .expect("discovery");
    let manager = yadorilink_fapi_client::test_support::manager_over(client, store.clone());

    let other_role = match role.as_str() {
        "cli" => "daemon",
        "daemon" => "cli",
        unknown => panic!("unknown role {unknown}"),
    };
    let rounds = match mode.as_str() {
        "locked" => ROTATIONS_PER_CHILD,
        "unlocked" => UNLOCKED_ROTATIONS_PER_CHILD,
        unknown => panic!("unknown mode {unknown}"),
    };

    for round in 0..rounds {
        let outcome = match mode.as_str() {
            // The product path: the lock is taken inside `refresh_now` and
            // held across reading the stored token, spending it, and writing
            // the rotated one back.
            //
            // The rendezvous sits before the whole sequence, so both processes
            // enter `force_refresh` together and the lock is contended on every
            // round rather than on whichever rounds happened to overlap.
            "locked" => {
                rendezvous(&dir, round, &role, other_role).await;
                manager.force_refresh().await.map(|_| ()).map_err(|e| e.to_string())
            }

            // The same sequence with the lock held only around the final
            // write rather than across the whole read-refresh-persist
            // sequence, which is what this code looked like before
            // `store::lock` was threaded through every mutation. The store no
            // longer offers a way to call `rotate_refresh_token` with no lock
            // at all -- that gap is exactly what this crate's public API is
            // no longer able to express -- but a caller can still take the
            // lock too late, immediately before the write, and that is the
            // race this mode exists to demonstrate: reading the refresh token
            // and presenting it are two steps, and the other process can
            // rotate in between.
            "unlocked" => {
                let stored = store.load().expect("read the store").expect("enrolled");
                // The rendezvous stands exactly where the lock would, between
                // the read and the presentation. Both children have now read
                // the same refresh token -- nothing has rotated it, because
                // neither has presented anything yet -- and neither proceeds
                // until both are here. The second presentation is therefore a
                // spent token by construction rather than by timing.
                rendezvous(&dir, round, &role, other_role).await;
                match manager.client().refresh(stored.refresh_token()).await {
                    Ok(tokens) => {
                        // Unconditional: a refresh that did not rotate is an
                        // `Err` now, so there is no branch in which this
                        // process holds a token response and no successor.
                        let lock = store
                            .lock(std::time::Duration::from_secs(5))
                            .await
                            .expect("the write-only lock is never contended for long");
                        store
                            .rotate_refresh_token(
                                &lock,
                                credentials.client_id(),
                                tokens.refresh_token(),
                            )
                            .expect("persist the rotation");
                        Ok(())
                    }
                    Err(e) => Err(e.to_string()),
                }
            }
            unknown => panic!("unknown mode {unknown}"),
        };

        match outcome {
            Ok(()) => println!("child {role} round {round}: rotated"),
            Err(e) => {
                println!("child {role} round {round}: refused: {e}");
                // Under the lock this is a failure and the parent asserts on
                // the exit status; without it, it is the damage being
                // demonstrated, so the child stops rather than hammering a
                // dead grant.
                if mode == "locked" {
                    panic!("a locked rotation was refused: {e}");
                }
                return;
            }
        }
    }
}
