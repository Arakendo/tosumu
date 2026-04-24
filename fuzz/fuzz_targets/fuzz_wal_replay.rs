#![no_main]

// Fuzz target: fuzz_wal_replay
//
// Feed arbitrary bytes as WAL content and verify that neither the reader nor
// the recovery path panics. Tests two code paths:
//   1. WalReader::read_all — raw record parsing on arbitrary bytes.
//   2. wal::recover        — full recovery against a real .tsm file.
//
// This ensures the WAL parsing code is panic-free on any input.

use libfuzzer_sys::fuzz_target;
use std::io::Write;
use std::path::PathBuf;
use tosumu_core::wal;

fuzz_target!(|data: &[u8]| {
    // --- path 1: parse arbitrary bytes as WAL records ---
    let wal_path = {
        let tid = std::thread::current().id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        PathBuf::from(format!("/tmp/fuzz_wal_{tid:?}_{ts}.wal"))
    };

    // Write arbitrary bytes as the WAL file.
    if let Ok(mut f) = std::fs::File::create(&wal_path) {
        let _ = f.write_all(data);
        let _ = f.sync_all();
    }

    // read_all must not panic regardless of content.
    let _ = wal::WalReader::read_all(&wal_path);

    // --- path 2: recover against a valid .tsm file ---
    let db_path = PathBuf::from(format!("{}.tsm", wal_path.display()));

    // Create a minimal valid database, then clobber its WAL with fuzz data.
    let created = tosumu_core::page_store::PageStore::create(&db_path).is_ok();
    if created {
        // Overwrite the WAL sidecar with fuzz data.
        let sidecar = wal::wal_path(&db_path);
        if let Ok(mut f) = std::fs::File::create(&sidecar) {
            let _ = f.write_all(data);
            let _ = f.sync_all();
        }

        // recover must not panic.
        let _ = wal::recover(&db_path, &sidecar);
    }

    // Clean up.
    let _ = std::fs::remove_file(&wal_path);
    let _ = std::fs::remove_file(&db_path);
    let sidecar = wal::wal_path(&db_path);
    let _ = std::fs::remove_file(&sidecar);
});
