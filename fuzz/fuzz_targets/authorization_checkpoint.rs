#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use yadorilink_replica_domain::authorization_checkpoint as a;
    a::decode_checkpoint(data).ok();
    a::decode_merkle_proof(data).ok();
});
