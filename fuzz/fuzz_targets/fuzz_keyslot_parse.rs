// Fuzz target: fuzz_keyslot_parse
//
// Feed arbitrary bytes as a keyslot region and attempt to open a database
// constructed with those bytes.  The target must never panic, produce UB,
// or leak memory.  Only `NotATosumFile`, `WrongKey`, `AuthFailed`,
// `NewerFormat`, `PageSizeMismatch`, and `Io` are expected errors.
//
// Strategy: build a minimal but structurally valid page 0 (correct magic,
// format version, page size), then overwrite the keyslot region with fuzz
// data and attempt `Pager::open`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;
use tosumu_core::error::TosumuError;
use tosumu_core::format::{
    PAGE_SIZE, MAGIC, OFF_MAGIC, OFF_FORMAT_VERSION, OFF_PAGE_SIZE,
    OFF_MIN_READER_VERSION, OFF_FLAGS, OFF_PAGE_COUNT, OFF_FREELIST_HEAD,
    OFF_ROOT_PAGE, OFF_WAL_CHECKPOINT_LSN, OFF_DEK_ID, OFF_KEYSLOT_COUNT,
    OFF_KEYSLOT_REGION_PAGES, KEYSLOT_REGION_OFFSET, KEYSLOT_SIZE, FORMAT_VERSION,
};

fuzz_target!(|data: &[u8]| {
    // Build a syntactically valid page 0.
    let mut page0 = [0u8; PAGE_SIZE];

    // Fixed header fields
    page0[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(MAGIC);
    page0[OFF_FORMAT_VERSION..OFF_FORMAT_VERSION + 2]
        .copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    page0[OFF_PAGE_SIZE..OFF_PAGE_SIZE + 2]
        .copy_from_slice(&(PAGE_SIZE as u16).to_le_bytes());
    page0[OFF_MIN_READER_VERSION..OFF_MIN_READER_VERSION + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    page0[OFF_FLAGS..OFF_FLAGS + 2].copy_from_slice(&0x0003u16.to_le_bytes());
    page0[OFF_PAGE_COUNT..OFF_PAGE_COUNT + 8].copy_from_slice(&1u64.to_le_bytes());
    page0[OFF_FREELIST_HEAD..OFF_FREELIST_HEAD + 8].copy_from_slice(&0u64.to_le_bytes());
    page0[OFF_ROOT_PAGE..OFF_ROOT_PAGE + 8].copy_from_slice(&0u64.to_le_bytes());
    page0[OFF_WAL_CHECKPOINT_LSN..OFF_WAL_CHECKPOINT_LSN + 8].copy_from_slice(&0u64.to_le_bytes());
    page0[OFF_DEK_ID..OFF_DEK_ID + 8].copy_from_slice(&1u64.to_le_bytes());
    page0[OFF_KEYSLOT_COUNT..OFF_KEYSLOT_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    page0[OFF_KEYSLOT_REGION_PAGES..OFF_KEYSLOT_REGION_PAGES + 2]
        .copy_from_slice(&0u16.to_le_bytes());

    // Overwrite the keyslot region with fuzz data.
    let ks_len = (data.len()).min(KEYSLOT_SIZE);
    page0[KEYSLOT_REGION_OFFSET..KEYSLOT_REGION_OFFSET + ks_len]
        .copy_from_slice(&data[..ks_len]);

    // Write to a tempfile and attempt to open.
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "tosumu_fuzz_ks_{:x}.tsm",
        u64::from_le_bytes(std::process::id().to_le_bytes()[..8].try_into().unwrap_or([0; 8]))
    ));
    {
        let mut f = match std::fs::File::create(&path) {
            Ok(f) => f,
            Err(_) => return,
        };
        if f.write_all(&page0).is_err() {
            let _ = std::fs::remove_file(&path);
            return;
        }
    }

    // Attempt to open — must not panic regardless of keyslot contents.
    let result = tosumu_core::pager::Pager::open(&path);
    match result {
        Ok(_) | Err(TosumuError::NotATosumFile)
        | Err(TosumuError::WrongKey)
        | Err(TosumuError::AuthFailed { .. })
        | Err(TosumuError::NewerFormat { .. })
        | Err(TosumuError::PageSizeMismatch { .. })
        | Err(TosumuError::Io(_))
        | Err(TosumuError::Corrupt { .. }) => {}
        Err(e) => panic!("unexpected error from Pager::open on fuzz keyslot: {e:?}"),
    }

    let _ = std::fs::remove_file(&path);

    // Also try open_with_passphrase with fuzz-derived passphrase.
    if data.len() >= 4 {
        let pw_len = (data[0] as usize).min(data.len().saturating_sub(1)).min(64);
        let passphrase = std::str::from_utf8(&data[1..1 + pw_len]).unwrap_or("");

        // Rebuild the file
        {
            let mut f = match std::fs::File::create(&path) {
                Ok(f) => f,
                Err(_) => return,
            };
            if f.write_all(&page0).is_err() {
                let _ = std::fs::remove_file(&path);
                return;
            }
        }

        let result = tosumu_core::pager::Pager::open_with_passphrase(&path, passphrase);
        match result {
            Ok(_) | Err(TosumuError::NotATosumFile)
            | Err(TosumuError::WrongKey)
            | Err(TosumuError::AuthFailed { .. })
            | Err(TosumuError::NewerFormat { .. })
            | Err(TosumuError::PageSizeMismatch { .. })
            | Err(TosumuError::Io(_))
            | Err(TosumuError::Corrupt { .. })
            | Err(TosumuError::InvalidArgument(_)) => {}
            Err(e) => panic!("unexpected error from open_with_passphrase on fuzz keyslot: {e:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }
});
