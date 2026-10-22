use super::*;

// RFC 8032 section 7.1 test vectors 1 to 3 (public key, message, signature), all hex.
const VECTORS: &[(&str, &str, &str)] = &[
    (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
];

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn rfc_8032_known_answers_verify() {
    for (pk, msg, sig) in VECTORS {
        assert!(verify(pk, &unhex(msg), &unhex(sig)), "vector {pk}");
    }
}

#[test]
fn a_corrupted_signature_message_or_key_does_not_verify() {
    let (pk, msg, sig) = VECTORS[1];
    let mut bad_sig = unhex(sig);
    bad_sig[63] ^= 1;
    assert!(!verify(pk, &unhex(msg), &bad_sig));
    assert!(!verify(pk, &unhex("73"), &unhex(sig)));
    assert!(!verify(VECTORS[0].0, &unhex(msg), &unhex(sig)));
}

#[test]
fn malformed_inputs_never_verify() {
    let (pk, msg, sig) = VECTORS[1];
    let (msg, sig) = (unhex(msg), unhex(sig));
    assert!(!verify(&pk[..62], &msg, &sig));
    assert!(!verify(&format!("{pk}00"), &msg, &sig));
    assert!(!verify(&pk.replace('3', "+"), &msg, &sig));
    assert!(!verify("", &msg, &sig));
    assert!(!verify(pk, &msg, &sig[..63]));
    assert!(!verify(pk, &msg, &[sig.clone(), vec![0]].concat()));
    assert!(!verify(pk, &msg, &[]));
}

#[test]
fn the_exit_status_follows_the_files() {
    let dir = std::env::temp_dir().join(format!("yl-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (pk, msg, sig) = VECTORS[1];
    let (m, s, long) = (dir.join("m"), dir.join("s"), dir.join("long"));
    std::fs::write(&m, unhex(msg)).unwrap();
    std::fs::write(&s, unhex(sig)).unwrap();
    std::fs::write(&long, vec![0u8; 65]).unwrap();
    let arg = |p: &std::path::Path| p.to_str().unwrap().to_string();
    let call = |k: &str, a: &std::path::Path, b: &std::path::Path| {
        run(&["v".into(), k.into(), arg(a), arg(b)])
    };
    assert_eq!(call(pk, &m, &s), 0);
    assert_eq!(call(pk, &m, &long), EXIT_NOT_VERIFIED);
    assert_eq!(call(pk, &dir.join("missing"), &s), EXIT_NOT_VERIFIED);
    assert_eq!(run(&["v".into(), pk.into(), arg(&m)]), EXIT_USAGE);
    std::fs::remove_dir_all(&dir).unwrap();
}
