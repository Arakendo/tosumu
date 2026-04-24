//! Fuzz target: `fuzz_page_decode`
//!
//! Feeds arbitrary bytes through `decrypt_page` and asserts it never panics.
//! Any `Ok` or `Err` result is acceptable; a panic is a bug.
//!
//! Run with:
//!   cargo +nightly fuzz run fuzz_page_decode
//!   (from the workspace root, requires `cargo-fuzz` on nightly)

#![no_main]

use libfuzzer_sys::fuzz_target;
use tosumu_core::format::PAGE_SIZE;

fuzz_target!(|data: &[u8]| {
    // Layout: [key: 32][pgno: 8][frame: 4096]
    const KEY_LEN: usize = 32;
    const PGNO_LEN: usize = 8;
    const MIN_LEN: usize = KEY_LEN + PGNO_LEN + PAGE_SIZE;

    if data.len() < MIN_LEN {
        return;
    }

    let key: [u8; 32]       = data[..32].try_into().unwrap();
    let pgno                 = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let frame: [u8; PAGE_SIZE] = data[40..40 + PAGE_SIZE].try_into().unwrap();

    // Must not panic — Ok or Err are both fine.
    let _ = tosumu_core::crypto::decrypt_page(&key, pgno, &frame);
});
