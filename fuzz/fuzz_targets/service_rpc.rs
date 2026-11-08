#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_peer_session::service_rpc::decode_request(data).ok();
    yadorilink_peer_session::service_rpc::decode_response(data).ok();
});
