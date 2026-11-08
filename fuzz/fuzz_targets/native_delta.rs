#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_replica_domain::signed_delta::NativeDelta::from_wire_bytes(data).ok();
});
