//! End-to-end check of the release manifest pipeline, run exactly the way
//! the release workflow runs it, on a stand-in artifact and a throwaway key
//! generated here (never a real release key):
//!
//!   artifact + `.sha256` sidecar (`generate-release-checksums.py`)
//!   -> `.github/release/build-channel-manifest.sh` (drives
//!      `generate-update-manifest.py` and the `yadorilink-sign-manifest` signer)
//!   -> parse and verify with the client's own `verify_and_parse_with_keys`
//!   -> `verify-update-manifest.py` with the explicit key and the artifacts
//!      directory, which is the release workflow's publish gate
//!
//! It goes red if the manifest loses `artifact_size`, if a recorded size or
//! hash does not match the artifact bytes, or if the manifest verifies under
//! a key other than the one that signed it.
//!
//! Unix only: the release jobs that run this pipeline are Linux jobs.
//! Needs `bash`, `python3` and the Python `cryptography` package.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use yadorilink_daemon::update::manifest::{self, ManifestError, TrustedKey};

const KEY_ID: &str = "throwaway-test-key";
const ARTIFACT: &str = "yadorilink-macos.pkg";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn signer() -> &'static str {
    env!("CARGO_BIN_EXE_yadorilink-sign-manifest")
}

struct Keypair {
    signing: SigningKey,
    private_hex: String,
    public_hex: String,
}

fn throwaway_key() -> Keypair {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    Keypair {
        signing: key.clone(),
        private_hex: hex::encode(seed),
        public_hex: hex::encode(key.verifying_key().to_bytes()),
    }
}

fn trust(public_hex: &str) -> Vec<TrustedKey> {
    vec![TrustedKey {
        key_id: KEY_ID,
        public_key_hex: Box::leak(public_hex.to_owned().into_boxed_str()),
    }]
}

fn describe(what: &str, out: &Output) -> String {
    format!(
        "{what}: exit {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn run(cmd: &mut Command) -> Output {
    cmd.current_dir(repo_root()).output().expect("spawn")
}

fn require_python_cryptography() {
    let out = run(Command::new("python3").args(["-c", "import cryptography"]));
    assert!(
        out.status.success(),
        "the release manifest verifier needs the Python `cryptography` package \
         (python3 -m pip install cryptography): {}",
        describe("import cryptography", &out)
    );
}

/// Stand-in for a built installer plus the checksum sidecar the release job
/// writes next to it.
fn build_stand_in_artifact(dist: &Path) -> PathBuf {
    let artifact = dist.join(ARTIFACT);
    let bytes: Vec<u8> = (0..10_007u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&artifact, bytes).unwrap();
    let out = run(Command::new("python3")
        .arg(".github/release/generate-release-checksums.py")
        .arg("--sidecars")
        .arg(&artifact));
    assert!(out.status.success(), "{}", describe("generate-release-checksums.py", &out));
    artifact
}

const NIGHTLY_VERSION: &str = "0.1.0-nightly.20260101000000";
const BETA_VERSION: &str = "0.1.0-beta.3";
const MIN_VERSION: &str = "0.0.5";

fn build_channel_manifest(dist: &Path, key: &Keypair, out_path: &Path) -> Output {
    build_manifest_for(dist, key, "nightly", NIGHTLY_VERSION, out_path)
}

fn build_manifest_for(
    dist: &Path,
    key: &Keypair,
    channel: &str,
    version: &str,
    out_path: &Path,
) -> Output {
    // The throwaway key is the root here, so the chain published for the real root cannot apply.
    let empty_chain = out_path.with_extension("chain.json");
    std::fs::write(&empty_chain, "[]").unwrap();
    run(Command::new("bash")
        .arg(".github/release/build-channel-manifest.sh")
        .args(["--channel", channel])
        .args(["--version", version])
        .args(["--min-version", MIN_VERSION])
        .args(["--notes-url", "https://example.invalid/notes"])
        .arg("--dist")
        .arg(dist)
        .args(["--base-url", "https://example.invalid/download"])
        .arg("--out")
        .arg(out_path)
        .arg("--trust-chain")
        .arg(&empty_chain)
        .env("MANIFEST_SIGNING_KEY", &key.private_hex)
        .env("MANIFEST_SIGNING_KEY_ID", KEY_ID)
        .env("YADORILINK_SIGN_MANIFEST", signer()))
}

fn verify_with_script(envelope: &Path, extra: &[&str]) -> Output {
    run(Command::new("python3")
        .arg(".github/release/verify-update-manifest.py")
        .arg(envelope)
        .args(extra))
}

/// Signs `body` with the real signer, which refuses a body the client could
/// not parse.
fn sign_body(body: &serde_json::Value, key: &Keypair, dir: &Path, name: &str) -> PathBuf {
    let out_path = dir.join(format!("{name}.signed.json"));
    let out = run_signer(body, key, dir, name);
    assert!(out.status.success(), "{}", describe("yadorilink-sign-manifest sign", &out));
    out_path
}

fn run_signer(body: &serde_json::Value, key: &Keypair, dir: &Path, name: &str) -> Output {
    let body_path = dir.join(format!("{name}.body.json"));
    let out_path = dir.join(format!("{name}.signed.json"));
    std::fs::write(&body_path, serde_json::to_string_pretty(body).unwrap() + "\n").unwrap();
    run(Command::new(signer())
        .arg("sign")
        .args(["--key-hex", &key.private_hex])
        .args(["--key-id", KEY_ID])
        .arg("--manifest")
        .arg(&body_path)
        .arg("--out")
        .arg(&out_path))
}

/// Signs `body` directly, bypassing the signer's own parse check, to model a
/// validly signed manifest that is nonetheless malformed.
fn sign_body_unchecked(body: &serde_json::Value, key: &Keypair, dir: &Path, name: &str) -> PathBuf {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let manifest_json = serde_json::to_string_pretty(body).unwrap() + "\n";
    let signature = key.signing.sign(manifest_json.as_bytes());
    let envelope = serde_json::json!({
        "key_id": KEY_ID,
        "manifest_json": manifest_json,
        "signature_base64": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    });
    let out_path = dir.join(format!("{name}.signed.json"));
    std::fs::write(&out_path, serde_json::to_string_pretty(&envelope).unwrap()).unwrap();
    out_path
}

fn signed_body(envelope_path: &Path) -> serde_json::Value {
    let envelope: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(envelope_path).unwrap()).unwrap();
    serde_json::from_str(envelope["manifest_json"].as_str().unwrap()).unwrap()
}

fn local_context(entry: &manifest::ReleaseEntry, channel: &str) -> manifest::LocalContext {
    manifest::LocalContext {
        current_version: semver::Version::parse("0.0.6").unwrap(),
        channel: channel.to_owned(),
        platform: entry.platform.clone(),
        arch: entry.arch.clone(),
        install_source: entry.install_source.clone(),
        rollout_bucket: 0,
    }
}

#[test]
fn stand_in_nightly_release_is_signed_and_verifies_end_to_end() {
    release_is_signed_and_verifies_end_to_end("nightly", NIGHTLY_VERSION, "beta");
}

#[test]
fn stand_in_beta_release_is_signed_and_verifies_end_to_end() {
    release_is_signed_and_verifies_end_to_end("beta", BETA_VERSION, "nightly");
}

fn release_is_signed_and_verifies_end_to_end(channel: &str, version: &str, other_channel: &str) {
    require_python_cryptography();
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    std::fs::create_dir(&dist).unwrap();
    let artifact = build_stand_in_artifact(&dist);
    let key = throwaway_key();
    let envelope_path = tmp.path().join(format!("manifest-{channel}.json"));

    let out = build_manifest_for(&dist, &key, channel, version, &envelope_path);
    assert!(out.status.success(), "{}", describe("build-channel-manifest.sh", &out));

    // The client's own parse and signature check, against the throwaway key.
    let envelope = std::fs::read_to_string(&envelope_path).unwrap();
    let parsed = manifest::verify_and_parse_with_keys(&envelope, &trust(&key.public_hex))
        .expect("the client must accept the manifest the pipeline signed");
    assert_eq!(parsed.releases.len(), 1);
    let entry = &parsed.releases[0];
    let bytes = std::fs::read(&artifact).unwrap();
    assert_eq!(entry.platform, "macos");
    assert_eq!(entry.artifact_url, format!("https://example.invalid/download/{ARTIFACT}"));
    assert_eq!(
        entry.artifact_size,
        bytes.len() as u64,
        "artifact_size must be the artifact's byte count"
    );
    assert_eq!(entry.artifact_sha256, hex::encode(Sha256::digest(&bytes)));
    // The signature binds the channel and versions the release job asked for.
    assert_eq!(entry.channel, channel);
    assert_eq!(entry.version, version);
    assert_eq!(entry.minimum_supported_version, MIN_VERSION);
    assert!(
        matches!(
            manifest::select_applicable(&parsed, &local_context(entry, channel)),
            manifest::Applicability::Available { mandatory: false, .. }
        ),
        "a {channel} install must be offered the {channel} release"
    );
    assert!(
        matches!(
            manifest::select_applicable(&parsed, &local_context(entry, other_channel)),
            manifest::Applicability::UpToDate
        ),
        "a {other_channel} install must not be offered the {channel} release"
    );

    // The release workflow's publish gate, with the signing key and the dist.
    let pub_args = ["--key-id", KEY_ID, "--public-key-hex", &key.public_hex];
    let dist_str = dist.to_str().unwrap();
    let gate = [&pub_args[..], &["--artifacts-dir", dist_str]].concat();
    let out = verify_with_script(&envelope_path, &gate);
    assert!(out.status.success(), "{}", describe("verify-update-manifest.py", &out));
}

#[test]
fn a_manifest_verified_under_the_wrong_key_is_rejected() {
    require_python_cryptography();
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    std::fs::create_dir(&dist).unwrap();
    build_stand_in_artifact(&dist);
    let key = throwaway_key();
    let other = throwaway_key();
    let envelope_path = tmp.path().join("manifest-nightly.json");
    let out = build_channel_manifest(&dist, &key, &envelope_path);
    assert!(out.status.success(), "{}", describe("build-channel-manifest.sh", &out));
    let envelope = std::fs::read_to_string(&envelope_path).unwrap();

    assert!(matches!(
        manifest::verify_and_parse_with_keys(&envelope, &trust(&other.public_hex)),
        Err(ManifestError::SignatureVerificationFailed)
    ));
    assert!(matches!(manifest::verify_and_parse(&envelope), Err(ManifestError::UnknownKey(_))));

    let out = verify_with_script(
        &envelope_path,
        &["--key-id", KEY_ID, "--public-key-hex", &other.public_hex],
    );
    assert!(!out.status.success(), "wrong public key accepted: {}", describe("verify", &out));
    // No silent fallback to a built-in key: without an explicit key the
    // verifier refuses to run (usage error) rather than checking against the
    // development key.
    let out = verify_with_script(&envelope_path, &[]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "verifier must demand an explicit key: {}",
        describe("verify", &out)
    );
}

#[test]
fn a_missing_or_wrong_artifact_size_or_hash_is_rejected() {
    require_python_cryptography();
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    std::fs::create_dir(&dist).unwrap();
    let artifact = build_stand_in_artifact(&dist);
    let key = throwaway_key();
    let envelope_path = tmp.path().join("manifest-nightly.json");
    let out = build_channel_manifest(&dist, &key, &envelope_path);
    assert!(out.status.success(), "{}", describe("build-channel-manifest.sh", &out));
    let body = signed_body(&envelope_path);
    let dist_str = dist.to_str().unwrap();
    let gate = [
        "--key-id",
        KEY_ID,
        "--public-key-hex",
        key.public_hex.as_str(),
        "--artifacts-dir",
        dist_str,
    ];

    // Correctly signed, but artifact_size dropped.
    let mut no_size = body.clone();
    no_size["releases"][0].as_object_mut().unwrap().remove("artifact_size");
    let out = run_signer(&no_size, &key, tmp.path(), "no-size-signer");
    assert!(!out.status.success(), "the signer signed a manifest without artifact_size");
    let signed = sign_body_unchecked(&no_size, &key, tmp.path(), "no-size");
    let envelope = std::fs::read_to_string(&signed).unwrap();
    assert!(
        manifest::verify_and_parse_with_keys(&envelope, &trust(&key.public_hex)).is_err(),
        "the client must refuse a manifest without artifact_size"
    );
    let out = verify_with_script(&signed, &gate);
    assert!(!out.status.success(), "missing artifact_size accepted: {}", describe("verify", &out));

    // Correctly signed, but artifact_size off by one.
    let mut bad_size = body.clone();
    let size = bad_size["releases"][0]["artifact_size"].as_u64().unwrap();
    bad_size["releases"][0]["artifact_size"] = serde_json::json!(size + 1);
    let signed = sign_body(&bad_size, &key, tmp.path(), "bad-size");
    let out = verify_with_script(&signed, &gate);
    assert!(!out.status.success(), "wrong artifact_size accepted: {}", describe("verify", &out));

    // The published artifact differs from the one the manifest was built for.
    let mut bytes = std::fs::read(&artifact).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&artifact, bytes).unwrap();
    let out = verify_with_script(&envelope_path, &gate);
    assert!(!out.status.success(), "wrong artifact hash accepted: {}", describe("verify", &out));
}

#[test]
fn the_dev_trust_root_is_exclusive_and_rejects_a_release_manifest() {
    require_python_cryptography();
    let tmp = tempfile::tempdir().unwrap();
    let dist = tmp.path().join("dist");
    std::fs::create_dir(&dist).unwrap();
    build_stand_in_artifact(&dist);
    let key = throwaway_key();
    let envelope_path = tmp.path().join("manifest-nightly.json");
    let out = build_channel_manifest(&dist, &key, &envelope_path);
    assert!(out.status.success(), "{}", describe("build-channel-manifest.sh", &out));

    // The development root is a mode of its own, never mixed with a key.
    let out = verify_with_script(
        &envelope_path,
        &["--dev-trust-root", "--key-id", KEY_ID, "--public-key-hex", &key.public_hex],
    );
    assert_eq!(out.status.code(), Some(2), "{}", describe("verify", &out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot be combined"),
        "{}",
        describe("verify", &out)
    );

    // A manifest signed by another key does not verify under the dev root.
    let out = verify_with_script(&envelope_path, &["--dev-trust-root"]);
    assert_eq!(out.status.code(), Some(1), "{}", describe("verify", &out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("unknown signing key id"),
        "{}",
        describe("verify", &out)
    );
}

/// Planned rotation and emergency revocation with the real offline signer
/// tools, checked by the client's verifier and by the CI verifier script.
/// `KEY_ID`/`key` is the compiled-in root; `rotated-key` is announced by a
/// record the root signs and later retires the root.
#[test]
fn rotation_and_revocation_with_the_real_signer_verify_in_client_and_script() {
    require_python_cryptography();
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    let dist = dir.join("dist");
    std::fs::create_dir(&dist).unwrap();
    build_stand_in_artifact(&dist);
    let root = throwaway_key();
    let next = throwaway_key();
    let rogue = throwaway_key();
    let base_path = dir.join("manifest-nightly.json");
    let out = build_channel_manifest(&dist, &root, &base_path);
    assert!(out.status.success(), "{}", describe("build-channel-manifest.sh", &out));
    let body_path = dir.join("body.json");
    std::fs::write(&body_path, serde_json::to_string(&signed_body(&base_path)).unwrap()).unwrap();

    let anchor = ["--anchor-key-id", KEY_ID, "--anchor-public-key-hex", root.public_hex.as_str()];
    let trust_cmd = |sub: &str, key: &Keypair, id: &str, rest: &[&str]| {
        run(Command::new(signer())
            .arg(sub)
            .args(["--key-hex", &key.private_hex, "--key-id", id])
            .args(anchor)
            .args(rest))
    };
    let sign_as = |key: &Keypair, id: &str, chain: Option<&Path>, name: &str| -> PathBuf {
        let out_path = dir.join(format!("{name}.json"));
        let mut cmd = Command::new(signer());
        cmd.arg("sign")
            .args(["--key-hex", &key.private_hex, "--key-id", id])
            .arg("--manifest")
            .arg(&body_path)
            .arg("--out")
            .arg(&out_path);
        if let Some(chain) = chain {
            cmd.arg("--trust-chain").arg(chain);
        }
        let out = run(&mut cmd);
        assert!(out.status.success(), "{}", describe("sign", &out));
        out_path
    };
    let client_accepts = |envelope: &Path| {
        let text = std::fs::read_to_string(envelope).unwrap();
        manifest::verify_and_parse_with_keys(&text, &trust(&root.public_hex))
    };
    let script_accepts = |envelope: &Path| {
        verify_with_script(envelope, &["--key-id", KEY_ID, "--public-key-hex", &root.public_hex])
            .status
            .success()
    };

    // The signer will not build a chain no client accepts.
    let chain1 = dir.join("chain1.json");
    let add_next = format!("rotated-key:{}", next.public_hex);
    let out = trust_cmd(
        "trust-set",
        &rogue,
        "rogue",
        &["--add", &add_next, "--out", chain1.to_str().unwrap()],
    );
    assert!(!out.status.success(), "{}", describe("untrusted signer", &out));
    let out = trust_cmd(
        "revoke",
        &root,
        KEY_ID,
        &["--add", &add_next, "--out", chain1.to_str().unwrap()],
    );
    assert!(!out.status.success(), "revoke must not take --add");
    let out = trust_cmd(
        "trust-set",
        &root,
        KEY_ID,
        &["--add", &add_next, "--out", chain1.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", describe("announce", &out));

    // Overlap: both keys verify when the chain is published; without it the
    // new key is unknown.
    let by_root = sign_as(&root, KEY_ID, Some(&chain1), "by-root");
    let by_next = sign_as(&next, "rotated-key", Some(&chain1), "by-next");
    let by_next_bare = sign_as(&next, "rotated-key", None, "by-next-bare");
    assert!(client_accepts(&by_root).is_ok() && script_accepts(&by_root));
    assert!(client_accepts(&by_next).is_ok() && script_accepts(&by_next));
    assert!(matches!(client_accepts(&by_next_bare), Err(ManifestError::UnknownKey(_))));
    assert!(!script_accepts(&by_next_bare));

    // Emergency revocation of the root, signed by the next key.
    let chain2 = dir.join("chain2.json");
    let out = trust_cmd(
        "revoke",
        &next,
        "rotated-key",
        &[
            "--chain",
            chain1.to_str().unwrap(),
            "--revoke",
            KEY_ID,
            "--out",
            chain2.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", describe("revoke", &out));
    let revoked_root = sign_as(&root, KEY_ID, Some(&chain2), "revoked-root");
    let next_after = sign_as(&next, "rotated-key", Some(&chain2), "next-after");
    assert!(matches!(client_accepts(&revoked_root), Err(ManifestError::RevokedKey(_))));
    assert!(
        !script_accepts(&revoked_root),
        "a revoked key's valid signature must fail the CI gate"
    );
    assert!(client_accepts(&next_after).is_ok() && script_accepts(&next_after));

    // The signer preflight: only currently trusted ids may sign.
    let check = |id: &str| {
        run(Command::new("python3")
            .arg(".github/release/verify-update-manifest.py")
            .args(["--key-id", KEY_ID, "--public-key-hex", &root.public_hex])
            .args(["--trust-chain", chain2.to_str().unwrap(), "--check-signer-id", id]))
        .status
        .success()
    };
    assert!(check("rotated-key"));
    assert!(!check(KEY_ID), "a revoked signer id must fail the preflight");
    assert!(!check("never-announced"));
}
