use super::*;

#[test]
fn every_status_round_trips_through_its_byte_and_no_other_byte_decodes() {
    let all = [NasAdminStatus::Ready, NasAdminStatus::Unavailable, NasAdminStatus::Busy];
    for status in all {
        assert_eq!(NasAdminStatus::from_byte(status.to_byte()), Some(status));
    }
    let defined: Vec<u8> = all.iter().map(|s| s.to_byte()).collect();
    for byte in 0..=u8::MAX {
        if !defined.contains(&byte) {
            assert_eq!(NasAdminStatus::from_byte(byte), None, "byte {byte} must not decode");
        }
    }
}

#[test]
fn the_alpn_names_the_service_and_its_version_and_nothing_else() {
    assert_eq!(YADORI_NAS_ADMIN_ALPN, b"yadorilink/nas-admin/v1");
}

/// The module that answers this protocol must never open a socket of its
/// own or take an address: the stream is handed to `NasAdminEndpoint`, which
/// has no parameter that could name one.
#[test]
fn the_protocol_module_takes_no_host_or_port() {
    let source = include_str!("../nas_admin.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["SocketAddr", "TcpStream", "TcpListener", "ToSocketAddrs", "UnixStream"] {
        assert!(!code.contains(forbidden), "nas_admin.rs must not use {forbidden}");
    }
}
