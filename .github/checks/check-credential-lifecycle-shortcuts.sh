#!/usr/bin/env bash
#
# Proves, by compiling it, that a product caller cannot assemble an
# authenticated Coordination credential except through the canonical lifecycle.
#
# WHY THIS IS A SEPARATE CRATE AND NOT A `#[test]`
#
# The property is "this does not compile", and the only honest way to check it
# is to try to compile it. That cannot be done from inside the workspace, for
# two reasons that are not stylistic:
#
#   * an integration test under `crates/yadorilink-fapi-client/tests/` is an
#     external crate, but its target enables that crate's `test-support`
#     feature -- so it sees `test_support::manager_over`, which a product caller
#     does not. A probe compiled there would be testing the wrong visibility;
#   * `yadorilink-cli` and `yadorilink-daemon` also enable `test-support`, in
#     their `[dev-dependencies]`, and cargo unifies features per build. Every
#     test target in this workspace therefore sees more of the crate than the
#     shipped binaries do.
#
# So the probe is generated OUTSIDE the workspace, in a scratch directory, as a
# crate whose `[dependencies]` name `yadorilink-fapi-client` with default
# features -- the same way `yadorilink-cli` names it in the dependency table
# that actually ships.
#
# WHAT IT ASSERTS
#
# Not merely "the build failed": a probe with a typo in it also fails. Each
# attempt below is expected to be refused for a NAMED reason, and the script
# requires every one of those reasons to appear in the compiler's output. A
# refusal that changes character -- say, `seed` becoming public again while some
# unrelated line still fails to compile -- is a failure here.
#
# Run from anywhere; it operates on this repository.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
probe="$(mktemp -d)"
trap 'rm -rf "$probe"' EXIT

mkdir -p "$probe/src"

cat >"$probe/Cargo.toml" <<EOF
[package]
name = "credential-lifecycle-probe"
version = "0.0.0"
edition = "2021"
publish = false

# Its own workspace: this crate deliberately does not join the one it points at.
[workspace]

[dependencies]
yadorilink-fapi-client = { path = "$repo/crates/yadorilink-fapi-client" }
reqwest = "0.12"
url = "2"
EOF

# Each attempt is its own file, compiled on its own. One file would do, but
# rustc stops reporting some errors once others in the same pass have fired --
# which silently turns "this attempt was refused" into "this attempt was not
# reached". Ask about one thing at a time.

# 1a. Build a manager over a client the caller assembled: the rung that turns a
#     FapiClient into something a CoordinationAuth can be built from.
cat >"$probe/src/with_client.rs" <<'EOF'
use std::sync::Arc;
use yadorilink_fapi_client::store::{Backend, CredentialStore};
use yadorilink_fapi_client::{CredentialManager, Es256Key, FapiClient, Metadata};

pub fn attempt(metadata: Metadata) -> CredentialManager {
    let client = FapiClient::from_metadata(
        reqwest::Client::new(),
        url::Url::parse("https://as.test").unwrap(),
        metadata,
        "ylk-attacker",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .unwrap();
    let store = Arc::new(CredentialStore::with_backend(
        Backend::File(std::env::temp_dir().join("probe.json")),
        &std::env::temp_dir(),
    ));
    CredentialManager::with_client(client, store)
}
EOF

# 1b. Put a token of the caller's choosing into a manager's cache, which is what
#     makes a manager -- and so a CoordinationAuth -- authenticated.
#
#     The manager and the token response are PARAMETERS. An earlier version of
#     this probe built them here, and both rungs it was meant to test were
#     masked: rustc stopped at `with_client`, the expected-reason check matched
#     that error's "private", and the gate reported `seed` refused while `seed`
#     was in fact public. Every attempt asks about exactly one symbol, and the
#     expected string below names that symbol.
cat >"$probe/src/seed.rs" <<'EOF'
use std::sync::Arc;
use yadorilink_fapi_client::{CoordinationAuth, CredentialManager, TokenResponse};

pub fn attempt(manager: CredentialManager, tokens: &TokenResponse) -> CoordinationAuth {
    manager.seed(tokens);
    CoordinationAuth::new(Arc::new(manager)).unwrap()
}
EOF

# 2. Skip the checked response: build a TokenResponse as a struct literal.
cat >"$probe/src/token_literal.rs" <<'EOF'
use yadorilink_fapi_client::TokenResponse;

pub fn attempt() -> TokenResponse {
    TokenResponse {
        access_token: "an-access-token-i-chose".to_owned(),
        expires_in: std::time::Duration::from_secs(3600),
        refresh_token: "whatever".to_owned(),
        scope: None,
        id_token: None,
    }
}
EOF

# 3. Skip the struct literal: reach the crate-internal constructor.
cat >"$probe/src/token_assembled.rs" <<'EOF'
use yadorilink_fapi_client::TokenResponse;

pub fn attempt() -> TokenResponse {
    TokenResponse::assembled(
        "an-access-token-i-chose",
        std::time::Duration::from_secs(3600),
        "whatever",
    )
}
EOF

# 4. Reach the construction seams through the test-support module, without
#    enabling the feature that is supposed to gate them.
cat >"$probe/src/test_support.rs" <<'EOF'
pub fn attempt() -> yadorilink_fapi_client::CoordinationAuth {
    yadorilink_fapi_client::test_support::offline_auth()
}
EOF

# 5. Take a credential record and re-point one member, so it names a different
#    registration from the key that authenticates it.
cat >"$probe/src/repoint.rs" <<'EOF'
use yadorilink_fapi_client::store::Credentials;

pub fn attempt() -> Credentials {
    let mut stolen = Credentials::new("https://as.test", "ylk-victim", "{}", "rt-victim");
    stolen.client_id = "ylk-attacker".to_owned();
    stolen
}
EOF

# 6. Forge the two headers directly, bypassing the credential entirely.
cat >"$probe/src/forge_headers.rs" <<'EOF'
use yadorilink_fapi_client::RequestAuthorization;

pub fn attempt() -> RequestAuthorization {
    RequestAuthorization {
        authorization: "DPoP an-access-token-i-chose".to_owned(),
        dpop: "a.b.c".to_owned(),
    }
}
EOF

# 7. The bare-string constructor the cutover deleted.
cat >"$probe/src/legacy_session.rs" <<'EOF'
pub fn attempt() -> yadorilink_fapi_client::CoordinationAuth {
    yadorilink_fapi_client::CoordinationAuth::legacy_session("an-access-token-i-chose")
}
EOF

# 8. Reach the manager behind a `CoordinationAuth`, which used to hand back
#    the `CredentialManager` -- and with it raw access-token acquisition and
#    direct refresh -- to any caller that only ever held the wrapper.
cat >"$probe/src/via_manager.rs" <<'EOF'
use yadorilink_fapi_client::CoordinationAuth;

pub async fn attempt(auth: &CoordinationAuth) -> String {
    auth.manager().access_token().await.unwrap()
}
EOF

# attempt : the substring that must appear in that attempt's compiler output
attempts=(
  "with_client:associated function \`with_client\` is private"
  "seed:method \`seed\` is private"
  "token_literal:of struct \`TokenResponse\` are private"
  "token_assembled:no associated function or constant named \`assembled\`"
  "test_support:could not find \`test_support\`"
  "repoint:field \`client_id\` of struct \`Credentials\` is private"
  "forge_headers:of struct \`RequestAuthorization\` are private"
  "legacy_session:no associated function or constant named \`legacy_session\`"
  "via_manager:no method named \`manager\`"
)

failures=0
for entry in "${attempts[@]}"; do
  name="${entry%%:*}"
  expected="${entry#*:}"

  cp "$probe/src/$name.rs" "$probe/src/lib.rs"
  output="$(cd "$probe" && cargo build 2>&1 || true)"

  if ! grep -q '^error' <<<"$output"; then
    echo "FAIL  $name: the compiler ACCEPTED it."
    echo "      This attempt is supposed to be impossible. The shortcut is open."
    failures=$((failures + 1))
    continue
  fi

  if ! grep -qF -- "$expected" <<<"$output"; then
    echo "FAIL  $name: refused, but not for the expected reason."
    echo "      expected to see: $expected"
    echo "$output" | grep '^error' | sed 's/^/      /'
    failures=$((failures + 1))
    continue
  fi

  echo "ok    $name: refused -- $(grep -m1 '^error' <<<"$output")"
done

if [ "$failures" -ne 0 ]; then
  echo
  echo "credential lifecycle: $failures shortcut(s) reachable from a product caller"
  exit 1
fi

echo
echo "credential lifecycle: ok (${#attempts[@]} shortcuts refused by the compiler)"
