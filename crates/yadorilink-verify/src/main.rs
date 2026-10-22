//! `yadorilink-verify <public-key-hex> <message-file> <signature-file>`
//!
//! Exit status 0 only when the 64-byte signature file is a valid Ed25519 signature of the
//! message file under the 32-byte public key given as 64 hex characters. Anything else,
//! including every usage or I/O problem, is a non-zero exit and prints nothing to stdout, so a
//! caller that only checks the exit status fails closed.
//!
//! Verification is strict (RFC 8032 plus rejection of non-canonical and small-order inputs): an
//! honest signer never produces a signature this refuses.

use std::io::Read;
use std::process::ExitCode;

use ed25519_dalek::{Signature, VerifyingKey};

/// A manifest body is a few kilobytes; this only bounds a wrong file being read into memory.
const MAX_MESSAGE_BYTES: u64 = 16 * 1024 * 1024;

const EXIT_NOT_VERIFIED: u8 = 1;
const EXIT_USAGE: u8 = 2;

fn decode_public_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    // `from_str_radix` accepts a leading '+', which is not hex.
    hex.bytes().all(|b| b.is_ascii_hexdigit()).then_some(out)
}

fn read_bounded(path: &str, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(limit + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= limit).then_some(bytes)
}

/// Whether `signature` is a valid signature of `message` under the hex public key.
fn verify(public_key_hex: &str, message: &[u8], signature: &[u8]) -> bool {
    let Some(key_bytes) = decode_public_key(public_key_hex) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else { return false };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else { return false };
    key.verify_strict(message, &Signature::from_bytes(&sig_bytes)).is_ok()
}

fn run(args: &[String]) -> u8 {
    let [_, key, message_path, signature_path] = args else { return EXIT_USAGE };
    let Some(message) = read_bounded(message_path, MAX_MESSAGE_BYTES) else {
        return EXIT_NOT_VERIFIED;
    };
    let Some(signature) = read_bounded(signature_path, 64) else { return EXIT_NOT_VERIFIED };
    if verify(key, &message, &signature) {
        0
    } else {
        EXIT_NOT_VERIFIED
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    ExitCode::from(run(&args))
}

#[cfg(test)]
mod tests;
