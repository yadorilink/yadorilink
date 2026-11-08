#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_daemon::change_policy::fuzz_policy_log(data);
});
