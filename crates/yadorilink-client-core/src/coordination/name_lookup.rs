//! Looking up the coordination service's address without waiting on a resolver quirk.
//!
//! The system lookup (`getaddrinfo` with no address family) asks for the IPv4 and the IPv6 address
//! in the same moment, over one socket. Some home routers answer only one of the two queries; the
//! system resolver then waits out its first timeout (five seconds with glibc's defaults) before the
//! lookup finishes, on every connection. `curl`-style tools look fine on such a network only
//! because they ask differently. Here the two families are looked up separately, each over its own
//! socket, and the first answer that carries addresses is used, so one unanswered query costs
//! nothing. On other platforms the system lookup is left as it is.

#[cfg(any(unix, test))]
use std::future::Future;
#[cfg(any(unix, test))]
use std::io;
#[cfg(any(unix, test))]
use std::net::SocketAddr;
#[cfg(any(unix, test))]
use std::time::Duration;

/// How long to keep waiting for the second family once the first has answered with addresses, so
/// that a name with both an IPv4 and an IPv6 address is offered with both (the connector then falls
/// back from one to the other) without waiting for a family that is not answering.
#[cfg(unix)]
const SECOND_FAMILY_GRACE: Duration = Duration::from_millis(250);

/// Combines the two per-family lookups into one answer: the first family that returns addresses,
/// plus the other's if it answers within [`SECOND_FAMILY_GRACE`]. A family that returns nothing
/// (the name has no such address) is not an answer; when neither has addresses, an error.
#[cfg(any(unix, test))]
pub(crate) async fn first_answer(
    v4: impl Future<Output = io::Result<Vec<SocketAddr>>>,
    v6: impl Future<Output = io::Result<Vec<SocketAddr>>>,
    grace: Duration,
) -> io::Result<Vec<SocketAddr>> {
    tokio::pin!(v4, v6);
    let mut v4_done = false;
    let mut v6_done = false;
    let mut error: Option<io::Error> = None;
    let mut found: Vec<SocketAddr> = Vec::new();
    while found.is_empty() && !(v4_done && v6_done) {
        let outcome = tokio::select! {
            r = &mut v4, if !v4_done => { v4_done = true; r }
            r = &mut v6, if !v6_done => { v6_done = true; r }
        };
        match outcome {
            Ok(addrs) => found = addrs,
            Err(e) => error = Some(e),
        }
    }
    if found.is_empty() {
        return Err(error.unwrap_or_else(|| io::Error::other("the name has no address")));
    }
    // The other family, if it is still to come: a short wait, then go without it.
    let late = if !v4_done {
        tokio::time::timeout(grace, &mut v4).await
    } else if !v6_done {
        tokio::time::timeout(grace, &mut v6).await
    } else {
        return Ok(found);
    };
    if let Ok(Ok(more)) = late {
        found.extend(more);
    }
    Ok(found)
}

/// The resolver the coordination client uses on Unix. A lookup that is abandoned (the connect budget
/// ran out) still occupies its blocking thread until the system call returns, at most the system
/// resolver's own timeout; a process that is exiting waits for it.
#[cfg(unix)]
pub(crate) struct SplitResolver;

#[cfg(unix)]
impl reqwest::dns::Resolve for SplitResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let lookup = |family: i32, host: String| async move {
                tokio::task::spawn_blocking(move || lookup_family(&host, family))
                    .await
                    .unwrap_or_else(|e| Err(io::Error::other(e)))
            };
            let addrs = first_answer(
                lookup(libc::AF_INET, host.clone()),
                lookup(libc::AF_INET6, host),
                SECOND_FAMILY_GRACE,
            )
            .await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// `getaddrinfo` for one address family. The port is 0: the client puts the URL's port in.
#[cfg(unix)]
fn lookup_family(host: &str, family: i32) -> io::Result<Vec<SocketAddr>> {
    use std::ffi::CString;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let node = CString::new(host).map_err(io::Error::other)?;
    // SAFETY: `hints` is zeroed and then given plain integer fields; `result` is only read while
    // `getaddrinfo` has filled it in and is released with `freeaddrinfo` on every path.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_family = family;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut result: *mut libc::addrinfo = std::ptr::null_mut();
        let code = libc::getaddrinfo(node.as_ptr(), std::ptr::null(), &hints, &mut result);
        if code != 0 {
            // EAI_NONAME / EAI_NODATA / EAI_AGAIN and the rest: the family has no answer.
            let text =
                std::ffi::CStr::from_ptr(libc::gai_strerror(code)).to_string_lossy().into_owned();
            return Err(io::Error::other(format!("name lookup failed for {host}: {text}")));
        }
        let mut out = Vec::new();
        let mut cursor = result;
        while !cursor.is_null() {
            let entry = &*cursor;
            if !entry.ai_addr.is_null() {
                match i32::from((*entry.ai_addr).sa_family) {
                    libc::AF_INET => {
                        let a = &*(entry.ai_addr as *const libc::sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
                        out.push(SocketAddr::new(IpAddr::V4(ip), 0));
                    }
                    libc::AF_INET6 => {
                        let a = &*(entry.ai_addr as *const libc::sockaddr_in6);
                        out.push(SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::from(a.sin6_addr.s6_addr)),
                            0,
                        ));
                    }
                    _ => {}
                }
            }
            cursor = entry.ai_next;
        }
        libc::freeaddrinfo(result);
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
