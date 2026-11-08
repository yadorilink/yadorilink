#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_sync_protocol::wire::decode_hello(data).ok();
});
