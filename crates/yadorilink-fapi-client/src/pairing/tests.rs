#![cfg(test)]

use super::*;

#[test]
fn a_typed_code_is_normalised_whatever_its_case_and_separators() {
    for typed in
        ["BCDF-GHJK-LMNP", "bcdfghjklmnp", "bcdf ghjk lmnp", "  Bcdf-ghjk-LMNP\n", "BCDF GHJK-LMNP"]
    {
        let code = PairingCode::parse(typed).expect(typed);
        assert_eq!(code.as_str(), "BCDFGHJKLMNP");
        assert_eq!(code.formatted(), "BCDF-GHJK-LMNP");
    }
}

#[test]
fn input_that_cannot_be_a_code_is_refused_without_echoing_it() {
    for bad in [
        "",
        "BCDF-GHJK-LMN",
        "BCDF-GHJK-LMNPQ",
        "AEIO-UAEI-OUAE",
        "BCDF-GHJK-LMN\u{0}",
        "BCDF-GHJK-LMN1",
        &"B".repeat(100),
        "ＢＣＤＦ-GHJK-LMNP",
    ] {
        let error = PairingCode::parse(bad).expect_err(bad);
        assert!(!error.to_string().contains("GHJK"), "{error}");
    }
}

#[test]
fn a_scanned_link_or_a_bare_code_yields_the_code() {
    for scanned in [
        "https://auth.example.test/account/devices/pair?code=BCDF-GHJK-LMNP",
        "https://auth.example.test/account/devices/pair?x=1&code=bcdfghjklmnp#frag",
        "BCDF-GHJK-LMNP",
        " BCDF GHJK LMNP ",
    ] {
        assert_eq!(
            PairingCode::from_scanned(scanned).expect(scanned).formatted(),
            "BCDF-GHJK-LMNP"
        );
    }
    for bad in [
        "https://auth.example.test/account/devices/pair",
        "https://auth.example.test/account/devices/pair?code=nonsense",
        "https://auth.example.test/pair?code=",
        "not a url://",
    ] {
        assert!(PairingCode::from_scanned(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_code_is_not_in_the_debug_output() {
    let code = PairingCode::parse("BCDF-GHJK-LMNP").expect("a code");
    let rendered = format!("{code:?} {:?}", Some(&code));
    assert!(!rendered.contains("BCDF") && !rendered.contains("LMNP"), "{rendered}");
}
