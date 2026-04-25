// Fuzz target: fuzz_aead_frame
//
// Feed arbitrary bytes as an "encrypted page frame" to the decrypt_page path.
// The target must never panic — every input must either decrypt successfully
// (extremely rare) or return AuthFailed. UB, panics, and OOMs are bugs.
//
// Also exercises encrypt_page → decrypt_page round-trip with fuzz-controlled
// pgno and page_version to ensure no integer-overflow or allocation panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tosumu_core::crypto::{decrypt_page, encrypt_page, derive_subkeys};
use tosumu_core::error::TosumuError;
use tosumu_core::format::{PAGE_SIZE, PAGE_PLAINTEXT_SIZE};

fuzz_target!(|data: &[u8]| {
    // ── Path 1: decrypt a fuzz-supplied frame ────────────────────────────────
    if data.len() >= PAGE_SIZE + 8 {
        let page_key_bytes: [u8; 32] = {
            let mut k = [0u8; 32];
            // Derive key from first 32 bytes of input (or zeros if short)
            let n = data.len().min(32);
            k[..n].copy_from_slice(&data[..n]);
            k
        };
        let (page_key, _, _) = derive_subkeys(&page_key_bytes);

        let pgno = u64::from_le_bytes(data[PAGE_SIZE..PAGE_SIZE + 8].try_into().unwrap());
        let frame: [u8; PAGE_SIZE] = data[..PAGE_SIZE].try_into().unwrap();

        match decrypt_page(&page_key, pgno, &frame) {
            Ok(_) | Err(TosumuError::AuthFailed { .. }) => {}
            Err(e) => panic!("unexpected error from decrypt_page: {e:?}"),
        }
    }

    // ── Path 2: encrypt then decrypt round-trip ───────────────────────────────
    if data.len() >= 48 {
        let mut dek = [0u8; 32];
        let copy_len = data.len().min(32);
        dek[..copy_len].copy_from_slice(&data[..copy_len]);
        let (page_key, _, _) = derive_subkeys(&dek);

        let pgno = if data.len() >= 40 {
            u64::from_le_bytes(data[32..40].try_into().unwrap())
        } else {
            1
        };
        let page_version = if data.len() >= 48 {
            u64::from_le_bytes(data[40..48].try_into().unwrap())
        } else {
            0
        };

        let mut plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        let fill_len = (data.len().saturating_sub(48)).min(PAGE_PLAINTEXT_SIZE);
        plaintext[..fill_len].copy_from_slice(&data[48..48 + fill_len]);

        match encrypt_page(&page_key, pgno, page_version, &plaintext) {
            Ok(frame) => {
                match decrypt_page(&page_key, pgno, &frame) {
                    Ok((pt, pv)) => {
                        assert_eq!(pt, plaintext, "decrypt must round-trip plaintext");
                        assert_eq!(pv, page_version, "decrypt must round-trip page_version");
                    }
                    Err(e) => panic!("encrypt-then-decrypt failed: {e:?}"),
                }
            }
            Err(TosumuError::EncryptFailed) => {} // AEAD library error — acceptable
            Err(e) => panic!("unexpected encrypt_page error: {e:?}"),
        }
    }
});
