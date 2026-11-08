#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_replica_domain::native_plan::NativeRowIdentity::from_bytes(data).ok();
});
