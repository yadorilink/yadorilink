#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_replica_domain::protocol5::decode_proof(data).ok();
});
