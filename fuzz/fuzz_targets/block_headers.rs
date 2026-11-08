#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codec = yadorilink_sync_wire::ProtobufPeerWireCodec;
    codec.decode_block_request_header(data).ok();
    codec.decode_block_response_header(data).ok();
});
