#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    // Whatever a person (or a synced file) puts in an ignore file is parsed without a panic.
    let _ = yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet::from_text(text);
});
