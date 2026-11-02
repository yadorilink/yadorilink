#![cfg(test)]

use super::*;

fn headers(lines: &[&str]) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for line in lines {
        map.append(reqwest::header::SET_COOKIE, line.parse().expect("a header value"));
    }
    map
}

#[test]
fn cookies_are_scoped_by_path_and_removed_by_max_age_zero() {
    let mut jar = Jar::default();
    jar.absorb(&headers(&[
        "_interaction=abc; path=/interaction/uid1; httponly",
        "_session=def; path=/; Max-Age=600",
    ]));
    assert_eq!(
        jar.header_for("/interaction/uid1").as_deref(),
        Some("_interaction=abc; _session=def")
    );
    assert_eq!(jar.header_for("/auth").as_deref(), Some("_session=def"));
    jar.absorb(&headers(&["_interaction=; path=/interaction/uid1; Max-Age=0"]));
    assert_eq!(jar.header_for("/interaction/uid1").as_deref(), Some("_session=def"));
}

#[test]
fn a_cookie_with_the_same_name_and_path_is_replaced() {
    let mut jar = Jar::default();
    jar.absorb(&headers(&["a=1; path=/", "a=2; path=/"]));
    assert_eq!(jar.header_for("/x").as_deref(), Some("a=2"));
}
