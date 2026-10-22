//! Pins the engine API version. Changing it is a deliberate, reviewed act:
//! update this test, the engine identity files and every host app together.

#[test]
fn host_api_version_is_pinned() {
    assert_eq!(yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION, 1);
}
