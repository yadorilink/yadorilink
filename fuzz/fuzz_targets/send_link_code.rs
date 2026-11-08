#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    yadorilink_daemon::coordination_client::fuzz_send_code(data);
});
