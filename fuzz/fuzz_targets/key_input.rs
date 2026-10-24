#![no_main]

use gpg_import::gpg::decode_key_input;
use libfuzzer_sys::fuzz_target;

// The key as the user supplies it: armored, or base64 with any whitespace
fuzz_target!(|data: &str| {
    let _ = decode_key_input(data);
});
