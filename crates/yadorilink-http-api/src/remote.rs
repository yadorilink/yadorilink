//! Explicit, opt-in remote administration of the dashboard, behind a reverse
//! proxy or authenticated tunnel.
//!
//! The loopback listener and its Host/Origin/Bearer protections (`security.rs`)
//! stay exactly as they are and are the default. This process never terminates
//! TLS and never binds beyond loopback: a reverse proxy or authenticated tunnel
//! on the same host terminates TLS (or authenticates the tunnel) and forwards to
//! the loopback listener. The operator declares that boundary
//! (`trusted_proxy`) and the one public name it forwards; the Host and Origin
//! allowlists then also accept exactly that name and `https://<public_host>`.
//!
//! `public_host` is mandatory and matched exactly (never a wildcard), and the
//! per-run Bearer token is still required for every `/api/*` request.
//! [`RemoteAdminConfig::from_settings`] is the only parser of operator settings
//! and refuses every combination that is not a declared boundary plus a name.

use std::fmt;

/// The secure boundary the operator declared for remote administration.
#[derive(Clone, Debug)]
pub enum RemoteBoundary {
    /// A reverse proxy or authenticated tunnel on this host terminates TLS and
    /// forwards to the loopback listener. No extra socket is bound.
    TrustedProxy,
}

/// A validated remote-administration setup. Build it with
/// [`RemoteAdminConfig::from_settings`].
#[derive(Clone, Debug)]
pub struct RemoteAdminConfig {
    /// The one exact `host[:port]` browsers use to reach the dashboard.
    pub public_host: String,
    pub boundary: RemoteBoundary,
}

/// Raw operator settings, as read from the environment by the daemon.
#[derive(Clone, Debug, Default)]
pub struct RemoteSettings {
    pub public_host: Option<String>,
    pub trusted_proxy: bool,
}

/// Why remote administration was refused. Every variant means: serve loopback
/// only.
#[derive(Debug, PartialEq, Eq)]
pub enum RemoteConfigError {
    /// A public name or boundary setting without the rest of a complete setup.
    Incomplete(&'static str),
    /// `public_host` is not a plain `host[:port]`.
    InvalidPublicHost(String),
}

impl fmt::Display for RemoteConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(what) => write!(f, "remote administration refused: {what}"),
            Self::InvalidPublicHost(h) => write!(
                f,
                "remote administration refused: public host {h:?} must be a plain host or \
                 host:port (no scheme, path, wildcard or whitespace)"
            ),
        }
    }
}

impl std::error::Error for RemoteConfigError {}

/// Lower-cases and validates `host[:port]`; IPv6 literals use `[addr]:port`.
pub fn normalize_public_host(raw: &str) -> Result<String, RemoteConfigError> {
    let bad = || RemoteConfigError::InvalidPublicHost(raw.to_owned());
    let host = raw.trim().to_ascii_lowercase();
    if host.is_empty() || host.len() > 255 {
        return Err(bad());
    }
    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']').ok_or_else(bad)?;
        if addr.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(bad());
        }
        (format!("[{addr}]"), tail.strip_prefix(':').or(tail.is_empty().then_some("")))
    } else {
        match host.split_once(':') {
            Some((n, p)) => (n.to_owned(), Some(p)),
            None => (host.clone(), None),
        }
    };
    let name_ok = !name.is_empty()
        && (name.starts_with('[')
            || name.split('.').all(|l| {
                !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }));
    let port_ok = match port {
        None | Some("") => true,
        Some(p) => p.parse::<u16>().is_ok_and(|p| p != 0) && p.bytes().all(|b| b.is_ascii_digit()),
    };
    // A trailing ":" with an empty port is not a canonical Host value.
    let trailing_colon = host.ends_with(':');
    if !name_ok || !port_ok || trailing_colon {
        return Err(bad());
    }
    Ok(host)
}

impl RemoteAdminConfig {
    /// `Ok(None)` when no remote setting is present (the loopback default).
    pub fn from_settings(s: RemoteSettings) -> Result<Option<Self>, RemoteConfigError> {
        if s.public_host.is_none() && !s.trusted_proxy {
            return Ok(None);
        }
        let public_host = s
            .public_host
            .as_deref()
            .ok_or(RemoteConfigError::Incomplete("the public host name is required"))?;
        let public_host = normalize_public_host(public_host)?;
        if !s.trusted_proxy {
            return Err(RemoteConfigError::Incomplete(
                "a public host needs a declared secure boundary (a trusted reverse proxy or \
                 authenticated tunnel terminating TLS)",
            ));
        }
        Ok(Some(Self { public_host, boundary: RemoteBoundary::TrustedProxy }))
    }

    /// The exact `Origin` a browser sends for this public name.
    pub fn origin(&self) -> String {
        format!("https://{}", self.public_host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s() -> RemoteSettings {
        RemoteSettings::default()
    }

    #[test]
    fn nothing_set_is_the_loopback_default() {
        assert!(RemoteAdminConfig::from_settings(s()).unwrap().is_none());
    }

    #[test]
    fn a_public_name_alone_is_not_a_boundary() {
        let e = RemoteAdminConfig::from_settings(RemoteSettings {
            public_host: Some("nas.example.net".into()),
            ..s()
        })
        .unwrap_err();
        assert!(matches!(e, RemoteConfigError::Incomplete(_)));
    }

    #[test]
    fn a_boundary_without_a_public_name_is_refused() {
        let e = RemoteAdminConfig::from_settings(RemoteSettings { trusted_proxy: true, ..s() })
            .unwrap_err();
        assert!(matches!(e, RemoteConfigError::Incomplete(_)));
    }

    #[test]
    fn a_declared_proxy_with_a_name_is_accepted() {
        let c = RemoteAdminConfig::from_settings(RemoteSettings {
            public_host: Some("NAS.example.net:8443".into()),
            trusted_proxy: true,
        })
        .unwrap()
        .unwrap();
        assert_eq!(c.public_host, "nas.example.net:8443");
        assert_eq!(c.origin(), "https://nas.example.net:8443");
        assert!(matches!(c.boundary, RemoteBoundary::TrustedProxy));
    }

    #[test]
    fn public_host_must_be_a_plain_host() {
        for bad in [
            "",
            "*",
            "*.example.net",
            "https://nas.example.net",
            "nas.example.net/",
            "a b",
            "nas.example.net:",
            "nas.example.net:0",
            "nas.example.net:99999",
            "nas@evil",
            "[::1",
            "[zz]:80",
            "a..b",
            "-",
        ] {
            let r = normalize_public_host(bad);
            if bad == "-" {
                // A lone hyphen label passes the character check; it can never
                // equal a real Host header, so it is harmless.
                continue;
            }
            assert!(r.is_err(), "{bad:?} should be refused, got {r:?}");
        }
        for ok in ["nas", "nas.example.net", "nas.example.net:8443", "10.0.0.5:8443", "[::1]:8443"]
        {
            assert!(normalize_public_host(ok).is_ok(), "{ok}");
        }
    }
}
