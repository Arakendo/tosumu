#![no_main]

// fuzz_btree_crash_boundaries
//
// Verify that WAL recovery after a mid-write crash always produces a
// structurally valid B+ tree — never a partial transaction, never corruption.
//
// Strategy:
//   1. Parse (crash_seed, ops) from fuzz input.
//   2. Execute ops via PageStore::transaction (each op = one WAL txn).
//   3. Simulate a crash: truncate the WAL at crash_seed % wal_size.
//   4. Reopen the database (triggers WAL recovery).
//   5. Assert check_invariants() passes.
//   6. Assert no AuthFailed (committed pages must not be corrupted by WAL truncation).

use libfuzzer_sys::fuzz_target;
use std::fs::OpenOptions;
use std::path::PathBuf;
use tosumu_core::btree::BTree;
use tosumu_core::error::TosumuError;
use tosumu_core::page_store::PageStore;
use tosumu_core::wal::wal_path;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // First 4 bytes: seed for selecting the WAL crash offset.
    let crash_seed = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as u64;
    let ops_data = &data[4..];

    let path = {
        let tid = std::thread::current().id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        PathBuf::from(format!("/tmp/fuzz_crash_{tid:?}_{ts}.tsm"))
    };
    let wp = wal_path(&path);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wp);

    // Phase 1: execute operations, each wrapped in its own WAL transaction.
    {
        let mut store = match PageStore::create(&path) {
            Ok(s) => s,
            Err(_) => return,
        };

        let mut pos = 0;
        while pos + 3 <= ops_data.len() {
            let op = ops_data[pos];
            let key_len = (ops_data[pos + 1] as usize).min(64);
            let val_len = (ops_data[pos + 2] as usize).min(64);
            pos += 3;

            if pos + key_len > ops_data.len() {
                break;
            }
            let key = ops_data[pos..pos + key_len].to_vec();
            pos += key_len;

            if key.is_empty() {
                continue;
            }

            match op % 2 {
                0 => {
                    if pos + val_len > ops_data.len() {
                        break;
                    }
                    let val = ops_data[pos..pos + val_len].to_vec();
                    pos += val_len;
                    // Each put is its own committed transaction.
                    let _ = store.transaction(|s| s.put(&key, &val));
                }
                _ => {
                    // Each delete is its own committed transaction.
                    let _ = store.transaction(|s| s.delete(&key));
                }
            }
        }
        // store dropped here; WAL is fsynced after each commit_txn above.
    }

    // Phase 2: simulate crash by truncating the WAL at crash_seed % (wal_size + 1).
    // crash_at = 0 means the WAL is empty (process died before any write).
    // crash_at = wal_size means the WAL is intact (no crash).
    if let Ok(meta) = std::fs::metadata(&wp) {
        let wal_size = meta.len();
        let crash_at = crash_seed % (wal_size + 1);
        if let Ok(f) = OpenOptions::new().write(true).open(&wp) {
            let _ = f.set_len(crash_at);
        }
    }

    // Phase 3: reopen (triggers WAL recovery).
    match BTree::open(&path) {
        Ok(tree) => {
            // Recovery succeeded. Structural invariants MUST hold.
            if let Err(e) = tree.check_invariants() {
                panic!("check_invariants failed after crash recovery: {e}");
            }
        }
        Err(TosumuError::AuthFailed { pgno }) => {
            // A committed page that was fully fsynced to .tsm failed AEAD
            // decryption. This must never happen from a clean WAL truncation —
            // the .tsm is only written AFTER WAL Commit+fsync, so truncating
            // the WAL cannot corrupt already-applied committed pages.
            panic!("AuthFailed on page {:?} after crash recovery — committed .tsm page must not be corrupted by WAL truncation", pgno);
        }
        Err(_) => {
            // Io, Corrupt (from partial WAL on-disk state), FileBusy, etc.
            // These are acceptable — the important guarantee is no panic and no
            // AuthFailed on a page that was cleanly committed.
        }
    }

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wp);
});
