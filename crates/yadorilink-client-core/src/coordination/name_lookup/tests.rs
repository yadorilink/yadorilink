use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn v4() -> Vec<SocketAddr> {
    vec![SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 0)]
}
fn v6() -> Vec<SocketAddr> {
    vec![SocketAddr::new(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), 0)]
}
const FIVE_SECONDS: Duration = Duration::from_secs(5);
const GRACE: Duration = Duration::from_millis(250);

async fn after(
    delay: Duration,
    answer: io::Result<Vec<SocketAddr>>,
) -> io::Result<Vec<SocketAddr>> {
    tokio::time::sleep(delay).await;
    answer
}

/// The router that answers one of the two queries and drops the other: the answer comes at once
/// from the family that was answered, not after the resolver's own five-second wait.
#[tokio::test(start_paused = true)]
async fn an_unanswered_family_does_not_hold_up_the_other() {
    let started = tokio::time::Instant::now();
    let found = first_answer(after(Duration::ZERO, Ok(v4())), after(FIVE_SECONDS, Ok(v6())), GRACE)
        .await
        .unwrap();
    assert_eq!(found, v4());
    assert!(started.elapsed() <= GRACE, "waited {:?}", started.elapsed());

    let started = tokio::time::Instant::now();
    let found = first_answer(after(FIVE_SECONDS, Ok(v4())), after(Duration::ZERO, Ok(v6())), GRACE)
        .await
        .unwrap();
    assert_eq!(found, v6());
    assert!(started.elapsed() <= GRACE, "waited {:?}", started.elapsed());
}

/// Both families answering close together are both offered, so the connector can fall back from an
/// IPv6 address that does not route to the IPv4 one.
#[tokio::test(start_paused = true)]
async fn both_families_are_offered_when_they_answer_together() {
    let found = first_answer(
        after(Duration::from_millis(20), Ok(v4())),
        after(Duration::from_millis(5), Ok(v6())),
        GRACE,
    )
    .await
    .unwrap();
    assert_eq!(found.len(), 2);
    assert!(found.contains(&v4()[0]) && found.contains(&v6()[0]));
}

/// A name with only one kind of address: the family with nothing is not an answer, the other is.
#[tokio::test(start_paused = true)]
async fn a_family_with_no_address_is_not_an_answer() {
    let found = first_answer(
        after(Duration::ZERO, Ok(Vec::new())),
        after(Duration::from_millis(30), Ok(v6())),
        GRACE,
    )
    .await
    .unwrap();
    assert_eq!(found, v6());
    let found = first_answer(
        after(Duration::from_millis(30), Err(io::Error::other("no data"))),
        after(Duration::ZERO, Ok(v4())),
        GRACE,
    )
    .await
    .unwrap();
    assert_eq!(found, v4());
}

#[tokio::test(start_paused = true)]
async fn no_address_in_either_family_is_an_error() {
    let err = first_answer(
        after(Duration::ZERO, Err(io::Error::other("v4 failed"))),
        after(Duration::from_millis(5), Ok(Vec::new())),
        GRACE,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("v4 failed"), "{err}");
}

/// The real system lookup, one family at a time: `localhost` resolves to the loopback address.
#[cfg(unix)]
#[test]
fn the_system_lookup_resolves_a_family_on_its_own() {
    let found = lookup_family("localhost", libc::AF_INET).unwrap();
    assert!(
        found.iter().all(|a| a.is_ipv4() && a.ip().is_loopback() && a.port() == 0),
        "{found:?}"
    );
    assert!(!found.is_empty());
    assert!(lookup_family("name-that-does-not-exist.invalid", libc::AF_INET).is_err());
}
