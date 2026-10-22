#![cfg(test)]

use super::*;

/// RFC 7636 appendix B's worked example.
#[test]
fn the_challenge_matches_the_specifications_own_vector() {
    let pkce = Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_owned());
    assert_eq!(pkce.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
}

#[test]
fn a_generated_verifier_is_within_the_length_the_specification_allows() {
    let pkce = Pkce::generate();
    assert_eq!(pkce.verifier().len(), 64);
    assert!((43..=128).contains(&pkce.verifier().len()));
    assert_ne!(pkce.verifier(), Pkce::generate().verifier());
}
