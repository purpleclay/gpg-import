#![no_main]

use gpg_import::gpg::GpgPrivateKey;
use libfuzzer_sys::fuzz_target;

// gpg's `--with-colons` output, parsed and then printed. Printing covers the
// timestamp formatting, which has panicked on values the parser accepted.
// primary_uid() expects the parser to reject a key without a uid
fuzz_target!(|data: &str| {
    if let Ok(key) = data.parse::<GpgPrivateKey>() {
        let _ = key.primary_uid();
        let _ = key.to_string();
    }
});
