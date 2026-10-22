//! Offline release-manifest signing tool.
//!
//! Maintainer-only — never shipped as part of an end-user install (see
//! the macOS installer's `build-pkg.sh`/the Windows installer's `yadorilink.iss`,
//! neither of which package this binary). Reuses
//! `yadorilink_daemon::update::manifest`'s exact types and wire format
//! rather than a second, independent implementation, so a manifest this
//! tool signs is guaranteed to be exactly what the daemon's own
//! `manifest::verify_and_parse` accepts.
//!
//! Usage:
//!  # Generate a new Ed25519 keypair for a release-signing trust root.
//!  yadorilink-sign-manifest keygen
//!
//!  # Sign a manifest body (a JSON file matching `UpdateManifest`'s
//!  # shape) with a private key, producing a `SignedManifestEnvelope`.
//!  yadorilink-sign-manifest sign \
//!  --key-hex <64-hex-char private key seed> \
//!  --key-id <key id, must match a `manifest::TRUSTED_KEYS` entry> \
//!  --manifest path/to/manifest-body.json \
//!  --out path/to/signed-manifest.json
//!
//!  # Extend the trust set offline (planned rotation: announce the next key;
//!  # retire or emergency-revoke a key). Appends one record, signed by a key
//!  # already trusted at that point, to the chain in --chain (omit for the
//!  # first record) and verifies the whole chain against the compiled-in
//!  # anchor key before writing --out.
//!  yadorilink-sign-manifest trust-set \
//!  --key-hex <signer seed> --key-id <signer key id> \
//!  --anchor-key-id <compiled-in key id> --anchor-public-key-hex <hex> \
//!  [--chain prev-chain.json] [--add <key id>:<public key hex>]... \
//!  [--revoke <key id>]... --out chain.json
//!  yadorilink-sign-manifest revoke ...   # trust-set restricted to --revoke
//!
//!  # `sign` also takes --trust-chain chain.json to publish the chain on the
//!  # manifest envelope (the chain is verified by every client).
//!
//! Keep the signing key outside the repository and inject it only when
//! generating a release manifest.

use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use yadorilink_daemon::update::manifest::{SignedManifestEnvelope, TrustedKey, UpdateManifest};
use yadorilink_daemon::update::trust::{
    self, KeyEntry, SignedTrustRecord, TrustRecord, TrustState,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("sign") => sign(&args[2..]),
        Some("trust-set") => trust_set(&args[2..], true),
        Some("revoke") => trust_set(&args[2..], false),
        _ => {
            eprintln!("usage: yadorilink-sign-manifest <keygen|sign|trust-set|revoke> [args...]");
            std::process::exit(2);
        }
    }
}

fn keygen() {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    println!("private_key_hex: {}", hex::encode(seed));
    println!("public_key_hex: {}", hex::encode(verifying_key.to_bytes()));
    println!(
        "\nBuild release clients with this public key and a stable key id before signing \
         any manifest with the matching private key. Never commit the private key \
         or store it outside the protected release-signing environment."
    );
}

struct SignArgs {
    key_hex: String,
    key_id: String,
    manifest_path: PathBuf,
    out_path: PathBuf,
    trust_chain_path: Option<PathBuf>,
}

fn parse_sign_args(args: &[String]) -> SignArgs {
    let mut key_hex = None;
    let mut key_id = None;
    let mut manifest_path = None;
    let mut out_path = None;
    let mut trust_chain_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--key-hex" => {
                key_hex = args.get(i + 1).cloned();
                i += 2;
            }
            "--key-id" => {
                key_id = args.get(i + 1).cloned();
                i += 2;
            }
            "--manifest" => {
                manifest_path = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--out" => {
                out_path = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--trust-chain" => {
                trust_chain_path = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            other => {
                eprintln!("unrecognized argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let missing = |name: &str| -> ! {
        eprintln!("missing required argument: --{name}");
        std::process::exit(2);
    };
    SignArgs {
        key_hex: key_hex.unwrap_or_else(|| missing("key-hex")),
        key_id: key_id.unwrap_or_else(|| missing("key-id")),
        manifest_path: manifest_path.unwrap_or_else(|| missing("manifest")),
        out_path: out_path.unwrap_or_else(|| missing("out")),
        trust_chain_path,
    }
}

fn sign(args: &[String]) {
    let args = parse_sign_args(args);

    let key_bytes = hex::decode(&args.key_hex).unwrap_or_else(|e| {
        eprintln!("error: --key-hex is not valid hex: {e}");
        std::process::exit(1);
    });
    let key_bytes: [u8; 32] = key_bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        eprintln!("error: --key-hex must decode to exactly 32 bytes, got {}", v.len());
        std::process::exit(1);
    });
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let manifest_json = std::fs::read_to_string(&args.manifest_path).unwrap_or_else(|e| {
        eprintln!("error: failed to read {}: {e}", args.manifest_path.display());
        std::process::exit(1);
    });
    // Validate it actually parses as an `UpdateManifest` before signing —
    // signing a document nothing can ever verify_and_parse successfully
    // is a maintainer mistake worth catching here, not on a beta user's
    // machine.
    if let Err(e) = serde_json::from_str::<UpdateManifest>(&manifest_json) {
        eprintln!("error: manifest does not parse as UpdateManifest: {e}");
        std::process::exit(1);
    }

    let signature = signing_key.sign(manifest_json.as_bytes());
    let envelope = SignedManifestEnvelope {
        key_id: args.key_id,
        manifest_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        trust_chain: args.trust_chain_path.as_deref().map(read_chain).unwrap_or_default(),
    };

    let out_json = serde_json::to_string_pretty(&envelope).expect("envelope always serializes");
    std::fs::write(&args.out_path, out_json).unwrap_or_else(|e| {
        eprintln!("error: failed to write {}: {e}", args.out_path.display());
        std::process::exit(1);
    });
    println!("wrote signed manifest envelope to {}", args.out_path.display());
}

fn die(msg: String) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn read_chain(path: &std::path::Path) -> Vec<SignedTrustRecord> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("failed to read {}: {e}", path.display())));
    serde_json::from_str(&text)
        .unwrap_or_else(|e| die(format!("{} is not a trust chain: {e}", path.display())))
}

fn signing_key_from_hex(key_hex: &str) -> SigningKey {
    let bytes =
        hex::decode(key_hex).unwrap_or_else(|e| die(format!("--key-hex is not valid hex: {e}")));
    let bytes: [u8; 32] = bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        die(format!("--key-hex must decode to 32 bytes, got {}", v.len()))
    });
    SigningKey::from_bytes(&bytes)
}

/// Appends one signed record to a trust chain and verifies the result.
fn trust_set(args: &[String], allow_add: bool) {
    let (mut key_hex, mut key_id, mut anchor_id, mut anchor_hex) = (None, None, None, None);
    let (mut chain_path, mut out_path) = (None, None);
    let (mut add, mut revoke) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < args.len() {
        let value =
            args.get(i + 1).cloned().unwrap_or_else(|| die(format!("{} needs a value", args[i])));
        match args[i].as_str() {
            "--key-hex" => key_hex = Some(value),
            "--key-id" => key_id = Some(value),
            "--anchor-key-id" => anchor_id = Some(value),
            "--anchor-public-key-hex" => anchor_hex = Some(value),
            "--chain" => chain_path = Some(PathBuf::from(value)),
            "--out" => out_path = Some(PathBuf::from(value)),
            "--revoke" => revoke.push(value),
            "--add" if allow_add => {
                let (id, hex) = value
                    .split_once(':')
                    .unwrap_or_else(|| die("--add must be <key id>:<public key hex>".into()));
                add.push(KeyEntry { key_id: id.to_string(), public_key_hex: hex.to_string() });
            }
            other => die(format!("unrecognized argument: {other}")),
        }
        i += 2;
    }
    let need = |v: Option<String>, name: &str| {
        v.unwrap_or_else(|| die(format!("missing required argument: --{name}")))
    };
    let signing_key = signing_key_from_hex(&need(key_hex, "key-hex"));
    let key_id = need(key_id, "key-id");
    let anchor = [TrustedKey {
        key_id: Box::leak(need(anchor_id, "anchor-key-id").into_boxed_str()),
        public_key_hex: Box::leak(need(anchor_hex, "anchor-public-key-hex").into_boxed_str()),
    }];
    let out_path = out_path.unwrap_or_else(|| die("missing required argument: --out".into()));

    let mut chain = chain_path.as_deref().map(read_chain).unwrap_or_default();
    // The previous chain must already verify: never extend a broken chain.
    let state = TrustState::replay(&anchor, &chain)
        .unwrap_or_else(|e| die(format!("the existing chain does not verify: {e}")));
    let record = TrustRecord {
        schema_version: trust::TRUST_RECORD_SCHEMA_VERSION,
        serial: state.serial + 1,
        add,
        revoke,
    };
    let record_json = serde_json::to_string(&record).expect("record always serializes");
    let signature = signing_key.sign(&trust::signing_bytes(&record_json));
    chain.push(SignedTrustRecord {
        key_id,
        record_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
    });
    // Same code the client runs: refuse to write a chain no client accepts.
    let state = TrustState::replay(&anchor, &chain)
        .unwrap_or_else(|e| die(format!("the new record is not acceptable to clients: {e}")));

    let out_json = serde_json::to_string_pretty(&chain).expect("chain always serializes");
    std::fs::write(&out_path, out_json + "\n")
        .unwrap_or_else(|e| die(format!("failed to write {}: {e}", out_path.display())));
    println!(
        "wrote trust chain (serial {}) to {}; trusted key ids after this record: {}",
        state.serial,
        out_path.display(),
        state.active_key_ids().join(", ")
    );
}
