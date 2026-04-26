// PageStore — put/get/delete/scan backed by the B+ tree.
//
// Source of truth: DESIGN.md §12.0 (MVP +3).
//
// PageStore is a thin facade over BTree. The B+ tree handles page
// allocation, splitting, and sorted leaf-chain iteration.
// The public API is unchanged from MVP +1 so all existing tests pass.
//
// Record encoding inside slotted pages:
//   Live record:  [0x01: u8][key_len: u16 LE][val_len: u16 LE][key...][val...]
//   Tombstone:    [0x02: u8][key_len: u16 LE][key...]
//
// Slot entry: { offset: u16 LE, length: u16 LE } — 4 bytes per slot.
// Offsets are relative to the start of the decrypted page body (0..PAGE_PLAINTEXT_SIZE).
//
// ── Read-path semantics ──────────────────────────────────────────────────────
//
// Scan / get correctness relies on two ordering invariants (see btree.rs):
//
//   1. Page-order = write-order: records are always appended; pages are
//      always scanned in ascending pgno order.  A later write for the same
//      key always lands on the same or a higher pgno.  Last-write-wins is
//      therefore equivalent to last-pgno-wins.
//
//   2. Slot-order = write-order within a page: within a single leaf page,
//      slots are appended; a later slot for the same key (live or tombstone)
//      is always at a higher slot index.
//
// These invariants must be preserved if freelist reuse or compaction is
// added in future stages — any violation makes get/scan silently incorrect.

use std::path::Path;

use crate::btree::BTree;
use crate::error::{Result, TosumuError};

/// High-level key-value store backed by the B+ tree.
pub struct PageStore {
    tree: BTree,
}

/// Summary information about the store. Returned by `stat()`.
pub struct StoreStat {
    pub page_count: u64,
    pub data_pages: u64,
    /// Height of the B+ tree (1 = root is a single leaf).
    pub tree_height: usize,
}

impl PageStore {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create a new `.tsm` file. Fails if `path` already exists.
    pub fn create(path: &Path) -> Result<Self> {
        Ok(PageStore { tree: BTree::create(path)? })
    }

    /// Open an existing `.tsm` file.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(PageStore { tree: BTree::open(path)? })
    }

    /// Open an existing `.tsm` file in read-only mode.
    pub fn open_readonly(path: &Path) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_readonly(path)? })
    }

    /// Create a new passphrase-protected `.tsm` file.
    pub fn create_encrypted(path: &Path, passphrase: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::create_encrypted(path, passphrase)? })
    }

    /// Open a passphrase-protected `.tsm` file.
    pub fn open_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_passphrase(path, passphrase)? })
    }

    /// Open a passphrase-protected `.tsm` file in read-only mode.
    pub fn open_with_passphrase_readonly(path: &Path, passphrase: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_passphrase_readonly(path, passphrase)? })
    }

    /// Open a recovery-key-protected `.tsm` file.
    pub fn open_with_recovery_key(path: &Path, recovery_str: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_recovery_key(path, recovery_str)? })
    }

    /// Open a recovery-key-protected `.tsm` file in read-only mode.
    pub fn open_with_recovery_key_readonly(path: &Path, recovery_str: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_recovery_key_readonly(path, recovery_str)? })
    }

    /// Open a keyfile-protected `.tsm` file.
    pub fn open_with_keyfile(path: &Path, keyfile_path: &Path) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_keyfile(path, keyfile_path)? })
    }

    /// Open a keyfile-protected `.tsm` file in read-only mode.
    pub fn open_with_keyfile_readonly(path: &Path, keyfile_path: &Path) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_keyfile_readonly(path, keyfile_path)? })
    }

    // ── Key management ───────────────────────────────────────────────────────

    /// Add a passphrase protector. Returns the slot index used.
    pub fn add_passphrase_protector(path: &Path, unlock_passphrase: &str, new_passphrase: &str) -> Result<u16> {
        BTree::add_passphrase_protector(path, unlock_passphrase, new_passphrase)
    }

    /// Add a passphrase protector, unlocking the DEK with a recovery key.
    pub fn add_passphrase_protector_with_recovery_key(path: &Path, recovery_str: &str, new_passphrase: &str) -> Result<u16> {
        BTree::add_passphrase_protector_with_recovery_key(path, recovery_str, new_passphrase)
    }

    /// Add a passphrase protector, unlocking the DEK with a keyfile protector.
    pub fn add_passphrase_protector_with_keyfile(path: &Path, keyfile_path: &Path, new_passphrase: &str) -> Result<u16> {
        BTree::add_passphrase_protector_with_keyfile(path, keyfile_path, new_passphrase)
    }

    /// Add a recovery-key protector. Returns the one-time recovery string.
    pub fn add_recovery_key_protector(path: &Path, unlock_passphrase: &str) -> Result<String> {
        BTree::add_recovery_key_protector(path, unlock_passphrase)
    }

    /// Add a recovery-key protector, unlocking the DEK with an existing recovery key.
    pub fn add_recovery_key_protector_with_recovery_key(path: &Path, recovery_str: &str) -> Result<String> {
        BTree::add_recovery_key_protector_with_recovery_key(path, recovery_str)
    }

    /// Add a recovery-key protector, unlocking the DEK with a keyfile protector.
    pub fn add_recovery_key_protector_with_keyfile(path: &Path, keyfile_path: &Path) -> Result<String> {
        BTree::add_recovery_key_protector_with_keyfile(path, keyfile_path)
    }

    /// Add a recovery-key protector using a caller-supplied recovery string.
    pub fn add_recovery_key_protector_with_secret(path: &Path, unlock_passphrase: &str, recovery_str: &str) -> Result<()> {
        BTree::add_recovery_key_protector_with_secret(path, unlock_passphrase, recovery_str)
    }

    /// Add a recovery-key protector using an existing recovery key and caller-supplied secret.
    pub fn add_recovery_key_protector_with_recovery_key_and_secret(path: &Path, recovery_str: &str, new_recovery_str: &str) -> Result<()> {
        BTree::add_recovery_key_protector_with_recovery_key_and_secret(path, recovery_str, new_recovery_str)
    }

    /// Add a recovery-key protector using a keyfile unlock and caller-supplied secret.
    pub fn add_recovery_key_protector_with_keyfile_and_secret(path: &Path, keyfile_path: &Path, recovery_str: &str) -> Result<()> {
        BTree::add_recovery_key_protector_with_keyfile_and_secret(path, keyfile_path, recovery_str)
    }

    /// Add a keyfile protector. Returns the slot index used.
    pub fn add_keyfile_protector(path: &Path, unlock_passphrase: &str, keyfile_path: &Path) -> Result<u16> {
        BTree::add_keyfile_protector(path, unlock_passphrase, keyfile_path)
    }

    /// Add a keyfile protector, unlocking with an existing recovery key.
    pub fn add_keyfile_protector_with_recovery_key(path: &Path, recovery_str: &str, keyfile_path: &Path) -> Result<u16> {
        BTree::add_keyfile_protector_with_recovery_key(path, recovery_str, keyfile_path)
    }

    /// Add a keyfile protector, unlocking with another keyfile protector.
    pub fn add_keyfile_protector_with_keyfile(path: &Path, unlock_keyfile_path: &Path, keyfile_path: &Path) -> Result<u16> {
        BTree::add_keyfile_protector_with_keyfile(path, unlock_keyfile_path, keyfile_path)
    }

    /// Remove the keyslot at `slot_idx` (must not be the last active slot).
    pub fn remove_keyslot(path: &Path, unlock_passphrase: &str, slot_idx: u16) -> Result<()> {
        BTree::remove_keyslot(path, unlock_passphrase, slot_idx)
    }

    /// Remove a keyslot, unlocking the DEK with a recovery key.
    pub fn remove_keyslot_with_recovery_key(path: &Path, recovery_str: &str, slot_idx: u16) -> Result<()> {
        BTree::remove_keyslot_with_recovery_key(path, recovery_str, slot_idx)
    }

    /// Remove a keyslot, unlocking the DEK with a keyfile protector.
    pub fn remove_keyslot_with_keyfile(path: &Path, keyfile_path: &Path, slot_idx: u16) -> Result<()> {
        BTree::remove_keyslot_with_keyfile(path, keyfile_path, slot_idx)
    }

    /// Rotate the KEK for the Passphrase slot at `slot_idx`.
    pub fn rekey_kek(path: &Path, slot_idx: u16, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        BTree::rekey_kek(path, slot_idx, old_passphrase, new_passphrase)
    }

    /// Rotate a Passphrase slot using a recovery key to unlock the DEK.
    pub fn rekey_kek_with_recovery_key(path: &Path, slot_idx: u16, recovery_str: &str, new_passphrase: &str) -> Result<()> {
        BTree::rekey_kek_with_recovery_key(path, slot_idx, recovery_str, new_passphrase)
    }

    /// Rotate a Passphrase slot using a keyfile protector to unlock the DEK.
    pub fn rekey_kek_with_keyfile(path: &Path, slot_idx: u16, keyfile_path: &Path, new_passphrase: &str) -> Result<()> {
        BTree::rekey_kek_with_keyfile(path, slot_idx, keyfile_path, new_passphrase)
    }

    /// List active keyslots. Returns `Vec<(slot_index, kind_byte)>`.
    pub fn list_keyslots(path: &Path) -> Result<Vec<(u16, u8)>> {
        BTree::list_keyslots(path)
    }

    // ── Writes ───────────────────────────────────────────────────────────────

    /// Insert or update a key-value pair.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;
        self.tree.put(key, value)
    }

    /// Delete a key. No-op if the key does not exist.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        validate_key(key)?;
        self.tree.delete(key)
    }

    // ── Reads ─────────────────────────────────────────────────────────────────

    /// Retrieve the current value for `key`, or `None` if not present.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        validate_key(key)?;
        self.tree.get(key)
    }

    /// Return all live key-value pairs, sorted by key.
    pub fn scan(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.tree.scan_physical()
    }

    /// Return all live key-value pairs where `start <= key <= end`, sorted by key.
    pub fn scan_range(&self, start: &[u8], end: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if start.is_empty() {
            return Err(TosumuError::InvalidArgument("start key must not be empty"));
        }
        if end.is_empty() {
            return Err(TosumuError::InvalidArgument("end key must not be empty"));
        }
        self.tree.scan_by_key(start, end)
    }

    /// Return summary statistics.
    pub fn stat(&self) -> Result<StoreStat> {
        let page_count = self.tree.page_count();
        Ok(StoreStat {
            page_count,
            data_pages: page_count.saturating_sub(1),
            tree_height: self.tree.tree_height()?,
        })
    }

    /// Execute a write transaction atomically.
    ///
    /// The closure receives `&mut PageStore`. All `put` / `delete` calls inside
    /// the closure are buffered and written to the WAL. On `Ok(())` the
    /// transaction is committed (WAL fsynced, dirty pages flushed to `.tsm`).
    /// On `Err(_)` the transaction is rolled back (dirty pages discarded).
    ///
    /// Commit semantics: if the process crashes after `commit_txn` returns but
    /// before the dirty-page flush completes, recovery will replay the WAL on
    /// next open and restore the committed state.
    pub fn transaction<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut PageStore) -> Result<T>,
    {
        self.tree.begin_txn()?;
        match f(self) {
            Ok(v) => {
                self.tree.commit_txn()?;
                Ok(v)
            }
            Err(e) => {
                self.tree.rollback_txn();
                Err(e)
            }
        }
    }

    #[cfg(test)]
    fn transaction_with_crash_file<F, T>(
        &mut self,
        f: F,
        crash_file: &mut crate::test_helpers::CrashFile,
    ) -> Result<T>
    where
        F: FnOnce(&mut PageStore) -> Result<T>,
    {
        self.tree.begin_txn()?;
        match f(self) {
            Ok(v) => {
                self.tree.commit_txn_with_crash_file(crash_file)?;
                Ok(v)
            }
            Err(e) => {
                self.tree.rollback_txn();
                Err(e)
            }
        }
    }
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(TosumuError::InvalidArgument("key must not be empty"));
    }
    if key.len() > u16::MAX as usize {
        return Err(TosumuError::InvalidArgument("key exceeds u16 maximum"));
    }
    Ok(())
}

fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(TosumuError::InvalidArgument("value exceeds u16 maximum"));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::fs::OpenOptions;
    use tempfile;

    fn temp_path(name: &str) -> PathBuf {
        // Use tempfile to get a collision-free OS-assigned path.
        // We immediately close the placeholder file so the store can create it fresh.
        let f = tempfile::Builder::new()
            .prefix(&format!("tosumu_{name}_"))
            .suffix(".tsm")
            .tempfile()
            .expect("tempfile allocation failed");
        let path = f.path().to_path_buf();
        drop(f);
        path
    }

    fn model_scan(model: &BTreeMap<Vec<u8>, Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
        model
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    fn diff_key(index: usize) -> Vec<u8> {
        format!("key-{index:02}").into_bytes()
    }

    fn diff_value(step: usize, salt: usize) -> Vec<u8> {
        let repeat = 1 + ((step + salt) % 5);
        format!("value-{step:03}-{salt:02}-{}", "x".repeat(repeat * 12)).into_bytes()
    }

    fn diff_wal_path(path: &std::path::Path) -> PathBuf {
        crate::wal::wal_path(path)
    }

    #[derive(Debug, Clone)]
    enum DiffOp {
        Put(Vec<u8>, Vec<u8>),
        Delete(Vec<u8>),
        CrashReopen,
        TxnPutPair(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>),
    }

    fn arb_diff_key() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(0u8..16, 1..=4)
    }

    fn arb_diff_value() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..=24)
    }

    fn assert_model_matches_store(
        store: &PageStore,
        model: &BTreeMap<Vec<u8>, Vec<u8>>,
        context: &str)
    {
        store.tree.check_invariants().unwrap();
        assert_eq!(store.scan().unwrap(), model_scan(model), "model mismatch after {context}");
    }

    #[test]
    fn create_open_round_trip() {
        let path = temp_path("round_trip");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create(&path).unwrap();
            store.put(b"hello", b"world").unwrap();
            store.put(b"foo", b"bar").unwrap();
        }

        let store = PageStore::open(&path).unwrap();
        assert_eq!(store.get(b"hello").unwrap(), Some(b"world".to_vec()));
        assert_eq!(store.get(b"foo").unwrap(), Some(b"bar".to_vec()));
        assert_eq!(store.get(b"missing").unwrap(), None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_opens_cleanly() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);

        let store = PageStore::create(&path).unwrap();
        assert_eq!(store.stat().unwrap().data_pages, 1);
        let pairs = store.scan().unwrap();
        assert!(pairs.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    /// The fresh root leaf must have slot_count == 0, and the B+ tree must
    /// report height 1. This guards against any init_page regression where
    /// free_start is set incorrectly (would cause ghost-slot reads).
    #[test]
    fn fresh_leaf_has_correct_header_state() {
        let path = temp_path("fresh_leaf");

        let store = PageStore::create(&path).unwrap();
        // Empty store: exactly one data page (the root leaf), height 1.
        assert_eq!(store.stat().unwrap().data_pages, 1, "expected exactly one data page");
        assert_eq!(store.tree.tree_height().unwrap(), 1, "expected tree height 1 for empty store");
        // Invariant checker also validates slot array bounds and free_start sanity.
        store.tree.check_invariants().unwrap();
        // No records should be readable.
        assert!(store.scan().unwrap().is_empty(), "fresh store must scan as empty");
    }

    #[test]
    fn delete_removes_key() {
        let path = temp_path("delete");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        store.put(b"k", b"v").unwrap();
        store.delete(b"k").unwrap();
        assert_eq!(store.get(b"k").unwrap(), None);

        // Survives reopen.
        let store2 = PageStore::open(&path).unwrap();
        assert_eq!(store2.get(b"k").unwrap(), None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn overwrite_key() {
        let path = temp_path("overwrite");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        store.put(b"k", b"v1").unwrap();
        store.put(b"k", b"v2").unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v2".to_vec()));

        let store2 = PageStore::open(&path).unwrap();
        assert_eq!(store2.get(b"k").unwrap(), Some(b"v2".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scan_sorted() {
        let path = temp_path("scan");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        store.put(b"c", b"3").unwrap();
        store.put(b"a", b"1").unwrap();
        store.put(b"b", b"2").unwrap();
        store.delete(b"b").unwrap();

        let pairs = store.scan().unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], (b"a".to_vec(), b"1".to_vec()));
        assert_eq!(pairs[1], (b"c".to_vec(), b"3".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auth_failure_on_corrupted_page() {
        let path = temp_path("corrupt");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create(&path).unwrap();
            store.put(b"key", b"val").unwrap();
        }

        // Corrupt the first data page (byte 4096 + 100 = inside the ciphertext).
        let mut raw = std::fs::read(&path).unwrap();
        raw[4096 + 100] ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();

        let store = PageStore::open(&path).unwrap();
        let err = store.get(b"key").unwrap_err();
        assert!(matches!(err, crate::error::TosumuError::AuthFailed { .. }));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn transaction_commit_visible_after_reopen() {
        let path = temp_path("txn_commit");
        let _ = std::fs::remove_file(&path);
        // Remove the WAL sidecar too.
        let wal = std::path::PathBuf::from(format!("{}.wal", path.display()));
        let _ = std::fs::remove_file(&wal);

        {
            let mut store = PageStore::create(&path).unwrap();
            store.transaction(|tx| {
                tx.put(b"a", b"1")?;
                tx.put(b"b", b"2")?;
                Ok(())
            }).unwrap();
        }

        let store = PageStore::open(&path).unwrap();
        assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(store.get(b"b").unwrap(), Some(b"2".to_vec()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
    }

    #[test]
    fn transaction_rollback_leaves_no_data() {
        let path = temp_path("txn_rollback");
        let _ = std::fs::remove_file(&path);
        let wal = std::path::PathBuf::from(format!("{}.wal", path.display()));
        let _ = std::fs::remove_file(&wal);

        let mut store = PageStore::create(&path).unwrap();
        let result: Result<()> = store.transaction(|tx| {
            tx.put(b"x", b"lost")?;
            Err(crate::error::TosumuError::InvalidArgument("deliberate rollback"))
        });
        assert!(result.is_err());
        assert_eq!(store.get(b"x").unwrap(), None, "rolled-back write must not be visible");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
    }

    #[test]
    fn transaction_propagates_committed_but_flush_failed_and_recovers_on_reopen() {
        use crate::test_helpers::{CrashFile, CrashPhase};

        let path = temp_path("txn_flush_fail");
        let wal = diff_wal_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);

        let mut store = PageStore::create(&path).unwrap();
        let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let mut crash_file = CrashFile::new(file, CrashPhase::AfterWrite);

        let err = store.transaction_with_crash_file(|tx| {
            tx.put(b"outer-a", b"1")?;
            tx.put(b"outer-b", b"2")?;
            Ok(())
        }, &mut crash_file).unwrap_err();
        assert!(matches!(err, TosumuError::CommittedButFlushFailed { .. }));

        drop(store);

        let reopened = PageStore::open(&path).unwrap();
        assert_eq!(reopened.get(b"outer-a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(reopened.get(b"outer-b").unwrap(), Some(b"2".to_vec()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
    }

    #[test]
    fn transaction_propagates_committed_but_partial_write_failed_and_recovers_on_reopen() {
        use crate::test_helpers::{CrashFile, CrashPhase};

        let path = temp_path("txn_partial_flush_fail");
        let wal = diff_wal_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);

        let mut store = PageStore::create(&path).unwrap();
        let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let mut crash_file = CrashFile::new(
            file,
            CrashPhase::MidWrite { fail_after_bytes: (crate::format::PAGE_SIZE / 2) as u64 },
        );

        let err = store.transaction_with_crash_file(|tx| {
            tx.put(b"outer-mid-a", b"1")?;
            tx.put(b"outer-mid-b", b"2")?;
            Ok(())
        }, &mut crash_file).unwrap_err();
        assert!(matches!(err, TosumuError::CommittedButFlushFailed { .. }));

        drop(store);

        let reopened = PageStore::open(&path).unwrap();
        assert_eq!(reopened.get(b"outer-mid-a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(reopened.get(b"outer-mid-b").unwrap(), Some(b"2".to_vec()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
    }

    #[test]
    fn spans_multiple_pages() {
        let path = temp_path("multipage");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        // Each record: 5 + 10 + 100 = 115 bytes + 4 slot = 119 bytes.
        // Usable space per page: 4038 bytes ≈ 33 records per page.
        // Insert 100 to ensure we span at least 3 pages.
        for i in 0u32..100 {
            let k = format!("key{i:05}");
            let v = format!("value{i:05}-{}", "x".repeat(90));
            store.put(k.as_bytes(), v.as_bytes()).unwrap();
        }

        let before_pages = store.stat().unwrap().data_pages;
        assert!(before_pages > 1, "expected multiple pages, got {before_pages}");

        let store2 = PageStore::open(&path).unwrap();
        for i in 0u32..100 {
            let k = format!("key{i:05}");
            let v = format!("value{i:05}-{}", "x".repeat(90));
            assert_eq!(store2.get(k.as_bytes()).unwrap(), Some(v.into_bytes()));
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── Passphrase-encryption tests ───────────────────────────────────────────

    #[test]
    fn encrypted_create_open_roundtrip() {
        let path = temp_path("enc_roundtrip");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "correct-horse").unwrap();
            store.put(b"secret", b"value").unwrap();
        }

        let store = PageStore::open_with_passphrase(&path, "correct-horse").unwrap();
        assert_eq!(store.get(b"secret").unwrap(), Some(b"value".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_wrong_passphrase_returns_wrong_key() {
        let path = temp_path("enc_wrongkey");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "correct-horse").unwrap();

        let err = PageStore::open_with_passphrase(&path, "wrong-horse").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey),
            "expected WrongKey, got {err:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_open_without_passphrase_returns_wrong_key() {
        let path = temp_path("enc_nopw");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "somepass").unwrap();

        // Plain open() must refuse, not panic or silently succeed.
        let err = PageStore::open(&path).err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey),
            "expected WrongKey, got {err:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_data_is_not_plaintext_in_file() {
        let path = temp_path("enc_notplain");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "p4ssw0rd").unwrap();
            store.put(b"confidential", b"secret_value_123").unwrap();
        }

        // The raw bytes of the file must not contain the plaintext value.
        let raw = std::fs::read(&path).unwrap();
        let needle = b"secret_value_123";
        let found = raw.windows(needle.len()).any(|w| w == needle);
        assert!(!found, "plaintext found in encrypted file — encryption is broken");

        let _ = std::fs::remove_file(&path);
    }

    // ── MVP +7: key-management tests ──────────────────────────────────────────

    #[test]
    fn multi_slot_second_passphrase_can_unlock() {
        let path = temp_path("multi_slot");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "pass-a").unwrap();
            store.put(b"key", b"val").unwrap();
        }
        let slot = PageStore::add_passphrase_protector(&path, "pass-a", "pass-b").unwrap();
        assert!(slot >= 1, "second protector should be in slot ≥1");

        // Both passphrases can open the DB.
        let store_a = PageStore::open_with_passphrase(&path, "pass-a").unwrap();
        assert_eq!(store_a.get(b"key").unwrap(), Some(b"val".to_vec()));
        let store_b = PageStore::open_with_passphrase(&path, "pass-b").unwrap();
        assert_eq!(store_b.get(b"key").unwrap(), Some(b"val".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recovery_key_roundtrip() {
        let path = temp_path("recovery_roundtrip");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "main-pass").unwrap();
            store.put(b"secret", b"data").unwrap();
        }
        let recovery = PageStore::add_recovery_key_protector(&path, "main-pass").unwrap();

        // Recovery key must look like XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
        let parts: Vec<&str> = recovery.split('-').collect();
        assert_eq!(parts.len(), 4, "recovery key should have 4 groups");
        assert!(parts.iter().all(|p| p.len() == 8), "each group should be 8 chars");

        // Must open with recovery key.
        let store = PageStore::open_with_recovery_key(&path, &recovery).unwrap();
        assert_eq!(store.get(b"secret").unwrap(), Some(b"data".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keyfile_roundtrip() {
        use crate::format::KEYSLOT_KIND_KEYFILE;

        let path = temp_path("keyfile_roundtrip");
        let keyfile = temp_path("keyfile_roundtrip.bin");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&keyfile);

        std::fs::write(&keyfile, [0xA5u8; 32]).unwrap();

        {
            let mut store = PageStore::create_encrypted(&path, "p").unwrap();
            store.put(b"secret", b"data").unwrap();
        }

        let slot = PageStore::add_keyfile_protector(&path, "p", &keyfile).unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert!(slots.iter().any(|&(idx, kind)| idx == slot && kind == KEYSLOT_KIND_KEYFILE));

        let store = PageStore::open_with_keyfile(&path, &keyfile).unwrap();
        assert_eq!(store.get(b"secret").unwrap(), Some(b"data".to_vec()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&keyfile);
    }

    #[test]
    fn wrong_recovery_key_returns_wrong_key() {
        let path = temp_path("wrong_recovery");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p").unwrap();
        let _real = PageStore::add_recovery_key_protector(&path, "p").unwrap();

        let err = PageStore::open_with_recovery_key(&path, "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD")
            .err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "got {err:?}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_last_slot_is_rejected() {
        let path = temp_path("remove_last");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "only-pass").unwrap();

        let err = PageStore::remove_keyslot(&path, "only-pass", 0).err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_second_slot_original_pass_still_works() {
        let path = temp_path("remove_second");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "orig").unwrap();
        let slot = PageStore::add_passphrase_protector(&path, "orig", "extra").unwrap();
        PageStore::remove_keyslot(&path, "orig", slot).unwrap();

        // Original pass still works.
        let store = PageStore::open_with_passphrase(&path, "orig").unwrap();
        drop(store);
        // Removed pass no longer works.
        let err = PageStore::open_with_passphrase(&path, "extra").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "got {err:?}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rekey_kek_old_fails_new_succeeds() {
        let path = temp_path("rekey_kek");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "old-pass").unwrap();
        PageStore::rekey_kek(&path, 0, "old-pass", "new-pass").unwrap();

        let err = PageStore::open_with_passphrase(&path, "old-pass").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "old pass still works: {err:?}");

        PageStore::open_with_passphrase(&path, "new-pass").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_keyslots_returns_active_slots() {
        let path = temp_path("list_slots");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p").unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].0, 0);

        PageStore::add_passphrase_protector(&path, "p", "p2").unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn protector_swap_attack_rejected() {
        // Write two databases with different passphrases. Manually copy the
        // wrapped DEK from slot 0 of DB B into slot 0 of DB A. The MAC should
        // now fail on DB A.
        use std::fs;
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_WRAPPED_DEK};

        let path_a = temp_path("swap_a");
        let path_b = temp_path("swap_b");
        let _ = fs::remove_file(&path_a);
        let _ = fs::remove_file(&path_b);

        PageStore::create_encrypted(&path_a, "pass-a").unwrap();
        PageStore::create_encrypted(&path_b, "pass-b").unwrap();

        // Corrupt DB A by splicing the wrapped DEK from DB B.
        let mut bytes_a = fs::read(&path_a).unwrap();
        let bytes_b = fs::read(&path_b).unwrap();
        let ks0 = KEYSLOT_REGION_OFFSET;
        let wdek_off = ks0 + KS_OFF_WRAPPED_DEK;
        bytes_a[wdek_off..wdek_off + 48].copy_from_slice(&bytes_b[wdek_off..wdek_off + 48]);
        fs::write(&path_a, &bytes_a).unwrap();

        // Opening with pass-a must fail (MAC or DEK unwrap mismatch).
        let err = PageStore::open_with_passphrase(&path_a, "pass-a").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "expected auth failure, got {err:?}"
        );

        let _ = fs::remove_file(&path_a);
        let _ = fs::remove_file(&path_b);
    }

    // ── Corruption tests ──────────────────────────────────────────────────────

    #[test]
    fn corrupt_magic_returns_not_a_tosum_file() {
        let path = temp_path("corrupt_magic");
        let _ = std::fs::remove_file(&path);
        PageStore::create(&path).unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        raw[0] ^= 0xFF; // flip first magic byte
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open(&path).err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::NotATosumFile),
            "expected NotATosumFile, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_header_mac_on_encrypted_db_rejected() {
        use crate::format::OFF_HEADER_MAC;

        let path = temp_path("corrupt_mac");
        let _ = std::fs::remove_file(&path);
        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        raw[OFF_HEADER_MAC] ^= 0x01; // flip one bit in the header MAC
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open_with_passphrase(&path, "pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::AuthFailed { .. } | crate::error::TosumuError::WrongKey),
            "expected AuthFailed or WrongKey, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_kcv_returns_wrong_key() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_KCV};

        let path = temp_path("corrupt_kcv");
        let _ = std::fs::remove_file(&path);
        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        raw[KEYSLOT_REGION_OFFSET + KS_OFF_KCV] ^= 0xFF; // corrupt KCV for slot 0
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open_with_passphrase(&path, "pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "expected WrongKey or AuthFailed, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_wrapped_dek_returns_wrong_key() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_WRAPPED_DEK};

        let path = temp_path("corrupt_wdek");
        let _ = std::fs::remove_file(&path);
        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        raw[KEYSLOT_REGION_OFFSET + KS_OFF_WRAPPED_DEK + 5] ^= 0xAB;
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open_with_passphrase(&path, "pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "expected WrongKey or AuthFailed, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corrupt_ciphertext_page_in_encrypted_db_auth_fails() {
        use crate::format::PAGE_SIZE;

        let path = temp_path("corrupt_enc_page");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "p").unwrap();
            store.put(b"key", b"value").unwrap();
        }

        // Corrupt a byte deep inside the first data page ciphertext.
        let mut raw = std::fs::read(&path).unwrap();
        raw[PAGE_SIZE + 64] ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();

        let store = PageStore::open_with_passphrase(&path, "p").unwrap();
        let err = store.get(b"key").unwrap_err();
        assert!(
            matches!(err, crate::error::TosumuError::AuthFailed { .. }),
            "expected AuthFailed, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_file_rejected() {
        use crate::format::PAGE_SIZE;

        let path = temp_path("truncated");
        let _ = std::fs::remove_file(&path);
        PageStore::create(&path).unwrap();

        // Truncate to half a page.
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len((PAGE_SIZE / 2) as u64).unwrap();
        drop(f);

        // Must error, not panic.
        let result = PageStore::open(&path);
        assert!(result.is_err(), "expected error opening truncated file");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_rejected() {
        let path = temp_path("zero_bytes");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"").unwrap();

        let err = PageStore::open(&path).err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::NotATosumFile | crate::error::TosumuError::Io(_)),
            "expected NotATosumFile or Io, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_magic_length_rejected() {
        // Write only the magic without a full header.
        let path = temp_path("short_magic");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, b"TOSUMUv0").unwrap();

        let err = PageStore::open(&path).err().unwrap();
        assert!(result_is_err_io_or_not_tosum(&err));
        let _ = std::fs::remove_file(&path);
    }

    fn result_is_err_io_or_not_tosum(e: &crate::error::TosumuError) -> bool {
        matches!(e, crate::error::TosumuError::NotATosumFile | crate::error::TosumuError::Io(_))
    }

    // ── Key management edge cases ─────────────────────────────────────────────

    #[test]
    #[ignore = "runs Argon2id 8 times — slow (~100 s); run with `cargo test keyslot_exhaustion -- --ignored`"]
    fn keyslot_exhaustion_9th_add_fails() {
        let path = temp_path("slot_exhaust");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p0").unwrap();
        // Fill slots 1–7 (slot 0 already used by create_encrypted).
        for i in 1..=7u16 {
            let slot = PageStore::add_passphrase_protector(&path, "p0", &format!("p{i}")).unwrap();
            assert_eq!(slot, i, "slot index should be sequential");
        }
        // 9th add must fail.
        let err = PageStore::add_passphrase_protector(&path, "p0", "p8").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::InvalidArgument(_)),
            "expected InvalidArgument (full), got {err:?}"
        );
        // All 8 original passphrases still work.
        for i in 0..=7u16 {
            let pass = format!("p{i}");
            PageStore::open_with_passphrase(&path, &pass).expect(&format!("slot {i} passphrase failed"));
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recovery_key_survives_passphrase_rekey() {
        let path = temp_path("rk_after_rekey");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "orig").unwrap();
            store.put(b"k", b"v").unwrap();
        }
        let recovery = PageStore::add_recovery_key_protector(&path, "orig").unwrap();
        PageStore::rekey_kek(&path, 0, "orig", "new-pass").unwrap();

        // Old passphrase must fail.
        let err = PageStore::open_with_passphrase(&path, "orig").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "old pass still works: {err:?}");
        // New passphrase works.
        PageStore::open_with_passphrase(&path, "new-pass").unwrap();
        // Recovery key still works.
        let store = PageStore::open_with_recovery_key(&path, &recovery).unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rekey_kek_wrong_old_passphrase_returns_wrong_key() {
        let path = temp_path("rekey_wrong");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "correct").unwrap();
        let err = PageStore::rekey_kek(&path, 0, "wrong", "new").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "got {err:?}");

        // Original passphrase still works after failed rekey.
        PageStore::open_with_passphrase(&path, "correct").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rekey_kek_twice_in_a_row() {
        let path = temp_path("rekey_twice");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "v1").unwrap();
        PageStore::rekey_kek(&path, 0, "v1", "v2").unwrap();
        PageStore::rekey_kek(&path, 0, "v2", "v3").unwrap();

        // Only v3 works.
        assert!(PageStore::open_with_passphrase(&path, "v1").is_err());
        assert!(PageStore::open_with_passphrase(&path, "v2").is_err());
        PageStore::open_with_passphrase(&path, "v3").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_out_of_range_slot_fails() {
        let path = temp_path("rm_oob");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p").unwrap();
        PageStore::add_passphrase_protector(&path, "p", "p2").unwrap();

        // Slot 99 doesn't exist — should fail without removing anything.
        let err = PageStore::remove_keyslot(&path, "p", 99).err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::InvalidArgument(_) | crate::error::TosumuError::WrongKey),
            "expected InvalidArgument or WrongKey, got {err:?}"
        );
        // Both slots still work.
        PageStore::open_with_passphrase(&path, "p").unwrap();
        PageStore::open_with_passphrase(&path, "p2").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_empty_slot_is_a_noop() {
        // Removing an already-empty slot within the valid range is accepted
        // (it zeroes an already-zero region and updates the MAC). The important
        // invariant is that it does NOT panic and both active slots still work.
        let path = temp_path("rm_empty_slot");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p").unwrap();
        PageStore::add_passphrase_protector(&path, "p", "p2").unwrap();

        // Slot 2 is empty but in-range (keyslot_count = MAX_KEYSLOTS = 8).
        // The remove should succeed (no-op on empty slot).
        PageStore::remove_keyslot(&path, "p", 2).unwrap();

        // Both active protectors still work.
        PageStore::open_with_passphrase(&path, "p").unwrap();
        PageStore::open_with_passphrase(&path, "p2").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn header_mac_tampered_keyslot_region_rejected() {
        // Manually zero out a byte inside the keyslot region (but NOT the wrapped DEK or KCV)
        // so the Argon2 + KCV check succeeds but the header MAC fails.
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_CREATED_UNIX};

        let path = temp_path("mac_ks_tamper");
        let _ = std::fs::remove_file(&path);
        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        // Flip a reserved/timestamp byte in slot 0 — MAC should catch it.
        raw[KEYSLOT_REGION_OFFSET + KS_OFF_CREATED_UNIX] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open_with_passphrase(&path, "pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::AuthFailed { .. } | crate::error::TosumuError::WrongKey),
            "expected auth failure, got {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ── Data boundary & stress tests ──────────────────────────────────────────

    #[test]
    fn empty_value_is_valid() {
        let path = temp_path("empty_val");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        store.put(b"k", b"").unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"".to_vec()));

        let store2 = PageStore::open(&path).unwrap();
        assert_eq!(store2.get(b"k").unwrap(), Some(b"".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_key_rejected() {
        let path = temp_path("empty_key");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        let err = store.put(b"", b"v").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::InvalidArgument(_)));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn binary_keys_with_null_bytes() {
        let path = temp_path("binary_keys");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        store.put(b"\x00abc\x00", b"null-interior").unwrap();
        store.put(b"\xff\xff\xff", b"all-ff").unwrap();
        store.put(b"\x00", b"single-null").unwrap();

        assert_eq!(store.get(b"\x00abc\x00").unwrap(), Some(b"null-interior".to_vec()));
        assert_eq!(store.get(b"\xff\xff\xff").unwrap(), Some(b"all-ff".to_vec()));
        assert_eq!(store.get(b"\x00").unwrap(), Some(b"single-null".to_vec()));

        let store2 = PageStore::open(&path).unwrap();
        assert_eq!(store2.get(b"\x00abc\x00").unwrap(), Some(b"null-interior".to_vec()));
        assert_eq!(store2.get(b"\xff\xff\xff").unwrap(), Some(b"all-ff".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn large_value_forces_overflow_pages() {
        use crate::format::RECORD_MAX_KV;

        let path = temp_path("overflow_val");
        let _ = std::fs::remove_file(&path);

        // A value just beyond the inline record limit requires overflow pages.
        let big_val: Vec<u8> = (0u8..=255u8).cycle().take(RECORD_MAX_KV + 1).collect();

        let mut store = PageStore::create(&path).unwrap();
        store.put(b"big", &big_val).unwrap();
        assert_eq!(store.get(b"big").unwrap().as_deref(), Some(big_val.as_slice()));

        let store2 = PageStore::open(&path).unwrap();
        assert_eq!(store2.get(b"big").unwrap().as_deref(), Some(big_val.as_slice()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn many_overwrites_same_key_final_value_correct() {
        let path = temp_path("overwrite_stress");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        for i in 0u32..500 {
            store.put(b"x", format!("value-{i}").as_bytes()).unwrap();
        }
        assert_eq!(store.get(b"x").unwrap(), Some(b"value-499".to_vec()));

        let store2 = PageStore::open(&path).unwrap();
        assert_eq!(store2.get(b"x").unwrap(), Some(b"value-499".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_all_scan_returns_empty() {
        let path = temp_path("delete_all");
        let _ = std::fs::remove_file(&path);

        let mut store = PageStore::create(&path).unwrap();
        for i in 0u32..50 {
            store.put(format!("key-{i:04}").as_bytes(), b"val").unwrap();
        }
        for i in 0u32..50 {
            store.delete(format!("key-{i:04}").as_bytes()).unwrap();
        }
        assert!(store.scan().unwrap().is_empty(), "scan should be empty after delete-all");

        let store2 = PageStore::open(&path).unwrap();
        assert!(store2.scan().unwrap().is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn freelist_reuse_bounds_page_count() {
        // Write N keys, delete them all, write N keys again.
        // The second round should reuse freelist pages, so final page_count
        // should be close to (not double) the single-round count.
        let path = temp_path("freelist_reuse");
        let _ = std::fs::remove_file(&path);

        let n = 200u32;
        let mut store = PageStore::create(&path).unwrap();
        for i in 0..n {
            store.put(format!("k{i:04}").as_bytes(), b"data").unwrap();
        }
        let pages_after_first = store.stat().unwrap().page_count;

        for i in 0..n {
            store.delete(format!("k{i:04}").as_bytes()).unwrap();
        }
        for i in 0..n {
            store.put(format!("k{i:04}").as_bytes(), b"data2").unwrap();
        }
        let pages_after_second = store.stat().unwrap().page_count;

        // Second round must not have grown by more than the first round did
        // (some slack for compaction overhead is ok, but not 2x).
        assert!(
            pages_after_second <= pages_after_first * 2,
            "page_count blew up: {pages_after_first} → {pages_after_second}"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_transaction_commit_survives_reopen() {
        let path = temp_path("enc_txn");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "txn-pass").unwrap();
            store.transaction(|s| {
                s.put(b"a", b"1")?;
                s.put(b"b", b"2")?;
                s.put(b"c", b"3")?;
                Ok(())
            }).unwrap();
        }

        let store = PageStore::open_with_passphrase(&path, "txn-pass").unwrap();
        assert_eq!(store.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(store.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(store.get(b"c").unwrap(), Some(b"3".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn encrypted_autocommit_after_transaction_survives_reopen() {
        let path = temp_path("enc_txn_then_put");
        let wal = diff_wal_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);

        {
            let mut store = PageStore::create_encrypted(&path, "txn-put-pass").unwrap();
            store.transaction(|tx| {
                tx.put(b"a", b"1")?;
                tx.put(b"a", b"2")?;
                Ok(())
            }).unwrap();
            store.put(b"b", b"3").unwrap();
        }

        let reopened = PageStore::open_with_passphrase(&path, "txn-put-pass").unwrap();
        assert_eq!(reopened.get(b"a").unwrap(), Some(b"2".to_vec()));
        assert_eq!(reopened.get(b"b").unwrap(), Some(b"3".to_vec()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
    }

    #[test]
    fn differential_crash_recovery_matches_btreemap_model() {
        let path = temp_path("diff_crash_recovery");
        let wal = diff_wal_path(&path);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);

        let mut model = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut store = PageStore::create_encrypted(&path, "diff-pass").unwrap();

        for step in 0..100usize {
            match step % 10 {
                0 => {
                    drop(store);
                    store = PageStore::open_with_passphrase(&path, "diff-pass").unwrap();
                }
                1 | 2 | 3 | 4 | 5 => {
                    let key_index = (step * 7) % 41;
                    let key = diff_key(key_index);
                    let value = diff_value(step, key_index);
                    model.insert(key.clone(), value.clone());
                    store.put(&key, &value).unwrap();
                }
                6 | 7 => {
                    let key_index = (step * 11) % 41;
                    let key = diff_key(key_index);
                    model.remove(&key);
                    store.delete(&key).unwrap();
                }
                _ => {
                    let key_a_index = (step * 5) % 41;
                    let key_b_index = (step * 13 + 3) % 41;
                    let key_a = diff_key(key_a_index);
                    let key_b = diff_key(key_b_index);
                    let value_a = diff_value(step, key_a_index + 50);
                    let value_b = diff_value(step, key_b_index + 75);

                    model.insert(key_a.clone(), value_a.clone());
                    model.insert(key_b.clone(), value_b.clone());

                    store.transaction(|tx| {
                        tx.put(&key_a, &value_a)?;
                        tx.put(&key_b, &value_b)?;
                        Ok(())
                    }).unwrap();
                }
            }

            assert_model_matches_store(&store, &model, &format!("step {step}"));
        }

        drop(store);
        let reopened = PageStore::open_with_passphrase(&path, "diff-pass").unwrap();
        assert_model_matches_store(&reopened, &model, "final reopen");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&wal);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn prop_differential_crash_recovery_matches_btreemap_model(
            ops in prop::collection::vec(
                prop_oneof![
                    (arb_diff_key(), arb_diff_value()).prop_map(|(key, value)| DiffOp::Put(key, value)),
                    arb_diff_key().prop_map(DiffOp::Delete),
                    Just(DiffOp::CrashReopen),
                    (arb_diff_key(), arb_diff_value(), arb_diff_key(), arb_diff_value())
                        .prop_map(|(key_a, value_a, key_b, value_b)| DiffOp::TxnPutPair(key_a, value_a, key_b, value_b)),
                ],
                1..=60,
            )
        ) {
            let path = temp_path("prop_diff_crash_recovery");
            let wal = diff_wal_path(&path);
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&wal);

            let mut model = BTreeMap::<Vec<u8>, Vec<u8>>::new();
            let mut store = PageStore::create_encrypted(&path, "prop-diff-pass").unwrap();

            for (step, op) in ops.iter().enumerate() {
                match op {
                    DiffOp::Put(key, value) => {
                        model.insert(key.clone(), value.clone());
                        store.put(key, value).unwrap();
                    }
                    DiffOp::Delete(key) => {
                        model.remove(key);
                        store.delete(key).unwrap();
                    }
                    DiffOp::CrashReopen => {
                        drop(store);
                        store = PageStore::open_with_passphrase(&path, "prop-diff-pass").unwrap();
                    }
                    DiffOp::TxnPutPair(key_a, value_a, key_b, value_b) => {
                        model.insert(key_a.clone(), value_a.clone());
                        model.insert(key_b.clone(), value_b.clone());
                        store.transaction(|tx| {
                            tx.put(key_a, value_a)?;
                            tx.put(key_b, value_b)?;
                            Ok(())
                        }).unwrap();
                    }
                }

                prop_assert!(
                    store.tree.check_invariants().is_ok(),
                    "check_invariants failed after step {}: {:?}",
                    step,
                    op
                );

                let actual = store.scan().unwrap();
                let expected = model_scan(&model);
                prop_assert_eq!(actual, expected, "model mismatch after step {}: {:?}", step, op);
            }

            drop(store);
            let reopened = PageStore::open_with_passphrase(&path, "prop-diff-pass").unwrap();
            prop_assert!(reopened.tree.check_invariants().is_ok(), "check_invariants failed after final reopen");
            prop_assert_eq!(reopened.scan().unwrap(), model_scan(&model), "model mismatch after final reopen");

            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&wal);
        }
    }

    #[test]
    fn two_encrypted_dbs_keys_are_independent() {
        // DEK of DB A must not unlock DB B — cross-DB confusion attack.
        let path_a = temp_path("xdb_a");
        let path_b = temp_path("xdb_b");
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);

        // Same passphrase, different DBs → different DEKs → can't cross-open.
        PageStore::create_encrypted(&path_a, "shared-pass").unwrap();
        PageStore::create_encrypted(&path_b, "shared-pass").unwrap();

        // Read the wrapped DEK from A and patch it into B's page-0.
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_WRAPPED_DEK, OFF_HEADER_MAC};
        let mut raw_b = std::fs::read(&path_b).unwrap();
        let raw_a = std::fs::read(&path_a).unwrap();
        let wdek_off = KEYSLOT_REGION_OFFSET + KS_OFF_WRAPPED_DEK;
        raw_b[wdek_off..wdek_off + 48].copy_from_slice(&raw_a[wdek_off..wdek_off + 48]);
        // Also copy the MAC from A so the MAC check passes.
        raw_b[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&raw_a[OFF_HEADER_MAC..OFF_HEADER_MAC + 32]);
        std::fs::write(&path_b, &raw_b).unwrap();

        // Opening B with the shared passphrase must fail — MAC was computed over A's keyslot data.
        let err = PageStore::open_with_passphrase(&path_b, "shared-pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "cross-DB splice must be rejected, got {err:?}"
        );

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    #[test]
    fn encrypted_db_with_1000_keys_survives_reopen() {
        let path = temp_path("enc_1000");
        let _ = std::fs::remove_file(&path);

        let n = 1000u32;
        {
            let mut store = PageStore::create_encrypted(&path, "stress-pass").unwrap();
            for i in 0..n {
                store.put(format!("key-{i:06}").as_bytes(), format!("val-{i}").as_bytes()).unwrap();
            }
        }
        let store = PageStore::open_with_passphrase(&path, "stress-pass").unwrap();
        for i in 0..n {
            let expected = format!("val-{i}").into_bytes();
            assert_eq!(
                store.get(format!("key-{i:06}").as_bytes()).unwrap(),
                Some(expected),
                "key {i} missing after reopen"
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: crash simulation ─────────────────────────────────────────

    /// Simulates crash-before-write during rekey: snapshot page0, run rekey, restore snapshot.
    /// Old passphrase must still work; new passphrase must not.
    #[test]
    fn crash_before_rekey_write_old_passphrase_recovers() {
        let path = temp_path("crash_before_rekey");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "old").unwrap();

        // Snapshot the page0 before rekey.
        let snapshot = std::fs::read(&path).unwrap();

        // Run rekey successfully.
        PageStore::rekey_kek(&path, 0, "old", "new").unwrap();

        // Restore the pre-rekey snapshot (simulates crash before write_page0 succeeded).
        std::fs::write(&path, &snapshot).unwrap();

        // Old passphrase must still work.
        PageStore::open_with_passphrase(&path, "old").unwrap();
        // New passphrase must not.
        let err = PageStore::open_with_passphrase(&path, "new").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "got {err:?}");

        let _ = std::fs::remove_file(&path);
    }

    /// Simulates torn page0 write during rekey (first 2048 bytes from new state,
    /// remaining 2048 from old state). Must be rejected cleanly — no panic, no wrong-key accept.
    #[test]
    fn crash_mid_rekey_torn_page_rejected() {
        let path = temp_path("crash_mid_rekey");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "old").unwrap();
        let old_bytes = std::fs::read(&path).unwrap();

        // Run rekey to get the "new" page0.
        PageStore::rekey_kek(&path, 0, "old", "new").unwrap();
        let new_bytes = std::fs::read(&path).unwrap();

        // Simulate a torn write: keyslots from the new state but MAC from the old state.
        // This represents a crash after slot 0 was updated on disk but before the MAC
        // field was written — the most dangerous torn-write scenario.
        use crate::format::OFF_HEADER_MAC;
        let mut torn = new_bytes.clone();
        torn[OFF_HEADER_MAC..OFF_HEADER_MAC + 32]
            .copy_from_slice(&old_bytes[OFF_HEADER_MAC..OFF_HEADER_MAC + 32]);
        std::fs::write(&path, &torn).unwrap();

        // old pass: AEAD unwrap of new slot with old KEK fails → WrongKey.
        let err = PageStore::open_with_passphrase(&path, "old").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey),
            "old pass on torn page should be WrongKey, got {err:?}"
        );
        // new pass: DEK unwraps fine from the new slot, but old MAC doesn't match → AuthFailed.
        let err2 = PageStore::open_with_passphrase(&path, "new").err().unwrap();
        assert!(
            matches!(err2, crate::error::TosumuError::AuthFailed { .. }),
            "new pass on torn page should be AuthFailed (stale MAC), got {err2:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Simulates crash-before-write during add_passphrase_protector.
    /// Original passphrase must still work; new slot must not appear.
    #[test]
    fn crash_before_add_protector_write_original_still_works() {
        let path = temp_path("crash_before_add");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "main").unwrap();
        let snapshot = std::fs::read(&path).unwrap();

        PageStore::add_passphrase_protector(&path, "main", "extra").unwrap();

        // Restore pre-add snapshot.
        std::fs::write(&path, &snapshot).unwrap();

        // Original works, extra does not.
        PageStore::open_with_passphrase(&path, "main").unwrap();
        let err = PageStore::open_with_passphrase(&path, "extra").err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "got {err:?}");

        // Only 1 slot listed.
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 1);

        let _ = std::fs::remove_file(&path);
    }

    /// Recovery key must survive a crash-before-write of a second add_passphrase operation.
    #[test]
    fn crash_before_second_add_recovery_key_still_works() {
        let path = temp_path("crash_before_second");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "main").unwrap();
        let recovery = PageStore::add_recovery_key_protector(&path, "main").unwrap();
        let snapshot = std::fs::read(&path).unwrap();

        // Attempt to add another slot — then crash.
        PageStore::add_passphrase_protector(&path, "main", "extra").unwrap();
        std::fs::write(&path, &snapshot).unwrap();

        // Recovery key still works (was in the snapshot).
        PageStore::open_with_recovery_key(&path, &recovery).unwrap();
        // 'extra' never made it.
        assert!(PageStore::open_with_passphrase(&path, "extra").is_err());

        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: slot reuse and stale AAD ─────────────────────────────────

    /// Add A (slot 0), add B (slot 1), remove A.
    /// Add C — should land in slot 0.
    /// B still works, C works via slot 0 (new AAD), old A wrapped blob rejected.
    #[test]
    fn slot_reuse_aad_binding_rejects_old_blob() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_WRAPPED_DEK};
        use std::fs;

        let path = temp_path("slot_reuse_aad");
        let _ = fs::remove_file(&path);

        // Create: slot 0 = A.
        PageStore::create_encrypted(&path, "pass-a").unwrap();
        // Snapshot the wrapped DEK from slot 0 while A occupies it.
        let bytes_with_a = fs::read(&path).unwrap();
        let a_wrapped_blob: [u8; 48] = bytes_with_a[KEYSLOT_REGION_OFFSET + KS_OFF_WRAPPED_DEK
            ..KEYSLOT_REGION_OFFSET + KS_OFF_WRAPPED_DEK + 48]
            .try_into().unwrap();

        // Add B → slot 1.
        let slot_b = PageStore::add_passphrase_protector(&path, "pass-a", "pass-b").unwrap();
        assert_eq!(slot_b, 1);

        // Remove A → slot 0 emptied.
        PageStore::remove_keyslot(&path, "pass-b", 0).unwrap();

        // Add C → should reuse slot 0.
        let slot_c = PageStore::add_passphrase_protector(&path, "pass-b", "pass-c").unwrap();
        assert_eq!(slot_c, 0, "expected C to reuse slot 0");

        // Normal paths work.
        PageStore::open_with_passphrase(&path, "pass-b").unwrap();
        PageStore::open_with_passphrase(&path, "pass-c").unwrap();
        // A is gone.
        assert!(PageStore::open_with_passphrase(&path, "pass-a").is_err());

        // Now splice A's old wrapped DEK blob back into slot 0, keeping C's other fields.
        // The AEAD tag was bound to A's Argon2id KEK; the KCV will now mismatch.
        let mut raw = fs::read(&path).unwrap();
        raw[KEYSLOT_REGION_OFFSET + KS_OFF_WRAPPED_DEK
            ..KEYSLOT_REGION_OFFSET + KS_OFF_WRAPPED_DEK + 48]
            .copy_from_slice(&a_wrapped_blob);
        fs::write(&path, &raw).unwrap();

        // C must now fail (KCV or unwrap mismatch), B may still work (different slot).
        // The interesting case: does A's blob accidentally unlock with A's passphrase?
        // It must not — the MAC is now broken.
        let err = PageStore::open_with_passphrase(&path, "pass-a").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "stale blob in reused slot must not unlock: {err:?}"
        );

        let _ = fs::remove_file(&path);
    }

    /// Add and remove slots many times; only the currently-valid passphrase must work.
    #[test]
    fn add_remove_cycle_only_current_pass_works() {
        let path = temp_path("cycle_slots");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p0").unwrap();

        for round in 0..5u32 {
            let new_pass = format!("round-{round}");
            PageStore::add_passphrase_protector(&path, "p0", &new_pass).unwrap();
            // p0 and new_pass both work now.
            PageStore::open_with_passphrase(&path, "p0").unwrap();
            PageStore::open_with_passphrase(&path, &new_pass).unwrap();

            // Remove the round pass (slot != 0, since p0 is in slot 0).
            let slots = PageStore::list_keyslots(&path).unwrap();
            let round_slot = slots.iter()
                .find(|&&(idx, kind)| idx != 0 && kind == crate::format::KEYSLOT_KIND_PASSPHRASE)
                .map(|&(idx, _)| idx)
                .expect("round slot not found");
            PageStore::remove_keyslot(&path, "p0", round_slot).unwrap();

            // new_pass must no longer work.
            assert!(PageStore::open_with_passphrase(&path, &new_pass).is_err(),
                "round-{round} pass still works after removal");
        }
        // p0 still works after all the churn.
        PageStore::open_with_passphrase(&path, "p0").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: slot order invariance ────────────────────────────────────

    /// Passphrase in slot 1 (not 0) can still unlock.
    #[test]
    fn passphrase_in_non_zero_slot_unlocks() {
        let path = temp_path("non_zero_slot");
        let _ = std::fs::remove_file(&path);

        // slot 0 = "p0", slot 1 = "p1"
        PageStore::create_encrypted(&path, "p0").unwrap();
        PageStore::add_passphrase_protector(&path, "p0", "p1").unwrap();
        // Remove slot 0, so slot 1 is the only protector.
        PageStore::remove_keyslot(&path, "p1", 0).unwrap();

        // Only p1 should work now, accessed via slot 1.
        let store = PageStore::open_with_passphrase(&path, "p1").unwrap();
        drop(store);
        assert!(PageStore::open_with_passphrase(&path, "p0").is_err());

        let _ = std::fs::remove_file(&path);
    }

    /// After removing slot 0, re-adding produces slot 0 again; data is intact.
    #[test]
    fn slot_zero_reuse_data_intact() {
        let path = temp_path("slot0_reuse");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "p0").unwrap();
            store.put(b"sentinel", b"value").unwrap();
        }
        PageStore::add_passphrase_protector(&path, "p0", "p1").unwrap();
        PageStore::remove_keyslot(&path, "p1", 0).unwrap();
        // Add p2 — should reuse slot 0.
        let slot = PageStore::add_passphrase_protector(&path, "p1", "p2").unwrap();
        assert_eq!(slot, 0, "expected slot 0 reuse");

        // Both p1 and p2 work, data intact.
        let s1 = PageStore::open_with_passphrase(&path, "p1").unwrap();
        assert_eq!(s1.get(b"sentinel").unwrap(), Some(b"value".to_vec()));
        let s2 = PageStore::open_with_passphrase(&path, "p2").unwrap();
        assert_eq!(s2.get(b"sentinel").unwrap(), Some(b"value".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: targeted header field corruption ─────────────────────────

    /// Flip the kind byte of keyslot 0. Must be rejected (MAC covers keyslot region).
    #[test]
    fn corrupt_keyslot_kind_byte_rejected() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_KIND};

        let path = temp_path("corrupt_kind");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        raw[KEYSLOT_REGION_OFFSET + KS_OFF_KIND] ^= 0x01;
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open_with_passphrase(&path, "pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::AuthFailed { .. } | crate::error::TosumuError::WrongKey),
            "kind byte flip must be caught by MAC: {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Corrupt the keyslot_count field in the header (OFF_KEYSLOT_COUNT).
    /// System must reject (MAC covers that field) or handle gracefully without panic.
    #[test]
    fn corrupt_keyslot_count_field_rejected_or_graceful() {
        use crate::format::OFF_KEYSLOT_COUNT;

        let path = temp_path("corrupt_ks_count");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        // Set count to 255 (way above MAX_KEYSLOTS=8).
        raw[OFF_KEYSLOT_COUNT] = 0xFF;
        raw[OFF_KEYSLOT_COUNT + 1] = 0xFF;
        std::fs::write(&path, &raw).unwrap();

        // Must not panic; either reject via MAC or clamp.
        let result = PageStore::open_with_passphrase(&path, "pass");
        // If it succeeds, the clamping worked and data is accessible.
        // If it fails, the MAC caught the tampered count field.
        if let Err(e) = &result {
            assert!(
                matches!(
                    e,
                    crate::error::TosumuError::AuthFailed { .. }
                        | crate::error::TosumuError::WrongKey
                        | crate::error::TosumuError::Corrupt { .. }
                ),
                "unexpected error: {e:?}"
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    /// Flip the nonce bytes inside the keyslot (KS_OFF_WRAP_NONCE).
    /// AEAD unwrap must fail → WrongKey.
    #[test]
    fn corrupt_wrap_nonce_causes_aead_failure() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KS_OFF_WRAP_NONCE};

        let path = temp_path("corrupt_nonce");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "pass").unwrap();

        let mut raw = std::fs::read(&path).unwrap();
        raw[KEYSLOT_REGION_OFFSET + KS_OFF_WRAP_NONCE] ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();

        let err = PageStore::open_with_passphrase(&path, "pass").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "nonce flip must fail: {err:?}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Flip single bits across every byte of the full keyslot region.
    /// Every single-bit flip must be rejected (not panic, not silently succeed).
    #[test]
    #[ignore = "slow: 256 bytes × 8 bits = 2048 Argon2id calls; run with --include-ignored"]
    fn single_bit_flip_in_keyslot_region_always_rejected() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KEYSLOT_SIZE};

        let path = temp_path("bitflip_sweep");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "pass").unwrap();
        let original = std::fs::read(&path).unwrap();

        // Only sweep the single occupied slot (256 bytes) to keep test fast.
        let slot_region = KEYSLOT_REGION_OFFSET..KEYSLOT_REGION_OFFSET + KEYSLOT_SIZE;

        for byte_off in slot_region {
            for bit in 0u8..8 {
                let mut raw = original.clone();
                raw[byte_off] ^= 1 << bit;
                std::fs::write(&path, &raw).unwrap();

                let result = PageStore::open_with_passphrase(&path, "pass");
                assert!(
                    result.is_err(),
                    "bit flip at byte {byte_off} bit {bit} was silently accepted"
                );
                let e = result.err().unwrap();
                assert!(
                    !matches!(e, crate::error::TosumuError::Corrupt { .. }),
                    "bit flip at byte {byte_off} bit {bit} caused Corrupt (should be AuthFailed/WrongKey): {e:?}"
                );
            }
        }
        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: cross-DB full slot splice ────────────────────────────────

    /// Copy *entire* slot 0 from DB A into slot 0 of DB B (same passphrase).
    /// Must fail because DEK_ID differs → AEAD AAD mismatch on unwrap.
    #[test]
    fn cross_db_full_slot_splice_rejected() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KEYSLOT_SIZE};

        let path_a = temp_path("xdb_full_a");
        let path_b = temp_path("xdb_full_b");
        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);

        PageStore::create_encrypted(&path_a, "shared").unwrap();
        PageStore::create_encrypted(&path_b, "shared").unwrap();

        // Copy entire slot 0 from A into B.
        let raw_a = std::fs::read(&path_a).unwrap();
        let mut raw_b = std::fs::read(&path_b).unwrap();
        let slot_start = KEYSLOT_REGION_OFFSET;
        raw_b[slot_start..slot_start + KEYSLOT_SIZE]
            .copy_from_slice(&raw_a[slot_start..slot_start + KEYSLOT_SIZE]);
        // Also copy A's MAC so the header MAC check passes.
        use crate::format::OFF_HEADER_MAC;
        raw_b[OFF_HEADER_MAC..OFF_HEADER_MAC + 32]
            .copy_from_slice(&raw_a[OFF_HEADER_MAC..OFF_HEADER_MAC + 32]);
        std::fs::write(&path_b, &raw_b).unwrap();

        // Opening B with shared passphrase must fail — DEK_ID in B's header
        // differs from the DEK_ID baked into A's AEAD ciphertext.
        let err = PageStore::open_with_passphrase(&path_b, "shared").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::WrongKey | crate::error::TosumuError::AuthFailed { .. }),
            "full slot splice from different DB must be rejected: {err:?}"
        );

        let _ = std::fs::remove_file(&path_a);
        let _ = std::fs::remove_file(&path_b);
    }

    // ── Adversarial: header snapshot rollback ─────────────────────────────────

    /// Snapshot header before adding a recovery key, restore it after.
    /// Recovery key must no longer work (not in snapshot), original pass still works.
    #[test]
    fn snapshot_rollback_removes_recovery_key() {
        let path = temp_path("rollback_rk");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "main").unwrap();
        let snapshot = std::fs::read(&path).unwrap();

        let recovery = PageStore::add_recovery_key_protector(&path, "main").unwrap();

        // Verify recovery works before rollback.
        PageStore::open_with_recovery_key(&path, &recovery).unwrap();

        // Roll back to pre-add snapshot.
        std::fs::write(&path, &snapshot).unwrap();

        // Recovery key is gone.
        let err = PageStore::open_with_recovery_key(&path, &recovery).err().unwrap();
        assert!(matches!(err, crate::error::TosumuError::WrongKey), "got {err:?}");

        // Main passphrase still works (was in snapshot).
        PageStore::open_with_passphrase(&path, "main").unwrap();

        let _ = std::fs::remove_file(&path);
    }

    /// Snapshot after rekey, restore before rekey. Old passphrase should work again
    /// because the file is literally back to the old state (not a hybrid).
    #[test]
    fn snapshot_pre_rekey_restores_old_passphrase() {
        let path = temp_path("rollback_rekey");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "v1").unwrap();
        let snapshot = std::fs::read(&path).unwrap();

        PageStore::rekey_kek(&path, 0, "v1", "v2").unwrap();
        // v2 works now.
        PageStore::open_with_passphrase(&path, "v2").unwrap();

        // Roll back to pre-rekey.
        std::fs::write(&path, &snapshot).unwrap();

        // v1 works again, v2 does not.
        PageStore::open_with_passphrase(&path, "v1").unwrap();
        assert!(PageStore::open_with_passphrase(&path, "v2").is_err());

        let _ = std::fs::remove_file(&path);
    }

    /// Hybrid: header from new state, keyslot data from old state (torn cross-operation).
    #[test]
    fn hybrid_header_new_slots_old_rejected() {
        use crate::format::{KEYSLOT_REGION_OFFSET, KEYSLOT_SIZE, MAX_KEYSLOTS};

        let path = temp_path("hybrid_torn");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p").unwrap();
        let old_bytes = std::fs::read(&path).unwrap();

        PageStore::rekey_kek(&path, 0, "p", "p2").unwrap();
        let new_bytes = std::fs::read(&path).unwrap();

        // Hybrid: take new fixed-header fields (page_count etc.) but keep old keyslot bytes.
        let mut hybrid = new_bytes.clone();
        hybrid[KEYSLOT_REGION_OFFSET..KEYSLOT_REGION_OFFSET + KEYSLOT_SIZE * MAX_KEYSLOTS]
            .copy_from_slice(&old_bytes[KEYSLOT_REGION_OFFSET..KEYSLOT_REGION_OFFSET + KEYSLOT_SIZE * MAX_KEYSLOTS]);
        // Keep new MAC so it's technically "authenticated" — but MAC was computed over new slots.
        // This means the MAC will not match the old slot data → should be caught.
        std::fs::write(&path, &hybrid).unwrap();

        let err = PageStore::open_with_passphrase(&path, "p").err().unwrap();
        assert!(
            matches!(err, crate::error::TosumuError::AuthFailed { .. } | crate::error::TosumuError::WrongKey),
            "hybrid header+keyslot must be rejected by MAC: {err:?}"
        );
        let err2 = PageStore::open_with_passphrase(&path, "p2").err().unwrap();
        assert!(
            matches!(err2, crate::error::TosumuError::AuthFailed { .. } | crate::error::TosumuError::WrongKey),
            "hybrid must reject new pass too: {err2:?}"
        );

        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: user stupidity / failed ops leave file unchanged ─────────

    /// Wrong passphrase many times → file is bitwise identical each time.
    #[test]
    fn failed_open_does_not_mutate_file() {
        let path = temp_path("no_mutate_open");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "real").unwrap();
        let original = std::fs::read(&path).unwrap();

        for _ in 0..5 {
            let _ = PageStore::open_with_passphrase(&path, "wrong");
        }

        assert_eq!(std::fs::read(&path).unwrap(), original, "read-only open mutated the file");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn open_readonly_works_on_readonly_file() {
        let path = temp_path("readonly_file_open");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create(&path).unwrap();
            store.put(b"k", b"v").unwrap();
        }

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&path, perms).unwrap();

        let store = PageStore::open_readonly(&path).unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v".to_vec()));
        assert_eq!(store.scan().unwrap(), vec![(b"k".to_vec(), b"v".to_vec())]);
        assert_eq!(store.stat().unwrap().page_count, 2);

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(&path, perms).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Failed rekey (wrong old passphrase) → file is bitwise identical.
    #[test]
    fn failed_rekey_does_not_mutate_file() {
        let path = temp_path("no_mutate_rekey");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "real").unwrap();
        let original = std::fs::read(&path).unwrap();

        for _ in 0..3 {
            let _ = PageStore::rekey_kek(&path, 0, "wrong", "new");
        }

        assert_eq!(std::fs::read(&path).unwrap(), original, "failed rekey mutated the file");
        PageStore::open_with_passphrase(&path, "real").unwrap();
        let _ = std::fs::remove_file(&path);
    }

    /// Failed add_passphrase_protector (wrong unlock passphrase) → file unchanged.
    #[test]
    fn failed_add_protector_does_not_mutate_file() {
        let path = temp_path("no_mutate_add");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "real").unwrap();
        let original = std::fs::read(&path).unwrap();

        let _ = PageStore::add_passphrase_protector(&path, "wrong", "new");

        assert_eq!(std::fs::read(&path).unwrap(), original, "failed add_protector mutated the file");
        let _ = std::fs::remove_file(&path);
    }

    /// Wrong recovery key → file unchanged, real passphrase still works.
    #[test]
    fn failed_recovery_open_does_not_mutate_file() {
        let path = temp_path("no_mutate_recovery");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "real").unwrap();
        let original = std::fs::read(&path).unwrap();

        for _ in 0..3 {
            let _ = PageStore::open_with_recovery_key(&path, "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD");
        }

        assert_eq!(std::fs::read(&path).unwrap(), original, "failed recovery open mutated the file");
        PageStore::open_with_passphrase(&path, "real").unwrap();
        let _ = std::fs::remove_file(&path);
    }

    // ── Adversarial: invariant check after every key-management op ────────────

    /// After each of: create, add, remove, rekey, add recovery — verify:
    ///   1. list_keyslots returns sane slot count
    ///   2. db closes and reopens successfully
    ///   3. put/get round-trips correctly through each reopen
    #[test]
    fn invariants_hold_after_every_key_management_op() {
        let path = temp_path("invariants_km");
        let _ = std::fs::remove_file(&path);

        // Step 1: create.
        {
            let mut s = PageStore::create_encrypted(&path, "p0").unwrap();
            s.put(b"marker", b"created").unwrap();
        }
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 1, "after create");
        assert_eq!(PageStore::open_with_passphrase(&path, "p0").unwrap()
            .get(b"marker").unwrap(), Some(b"created".to_vec()));

        // Step 2: add passphrase.
        let slot1 = PageStore::add_passphrase_protector(&path, "p0", "p1").unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 2, "after add passphrase");
        PageStore::open_with_passphrase(&path, "p0").unwrap();
        PageStore::open_with_passphrase(&path, "p1").unwrap();

        // Step 3: add recovery key.
        let recovery = PageStore::add_recovery_key_protector(&path, "p0").unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 3, "after add recovery key");
        PageStore::open_with_recovery_key(&path, &recovery).unwrap();

        // Step 4: rekey slot 1.
        PageStore::rekey_kek(&path, slot1, "p1", "p1-new").unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 3, "after rekey (count unchanged)");
        assert!(PageStore::open_with_passphrase(&path, "p1").is_err());
        PageStore::open_with_passphrase(&path, "p1-new").unwrap();

        // Step 5: remove slot 1 (p1-new).
        PageStore::remove_keyslot(&path, "p0", slot1).unwrap();
        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 2, "after remove slot 1");
        assert!(PageStore::open_with_passphrase(&path, "p1-new").is_err());
        PageStore::open_with_passphrase(&path, "p0").unwrap();
        PageStore::open_with_recovery_key(&path, &recovery).unwrap();

        // Step 6: data is still intact.
        let s = PageStore::open_with_passphrase(&path, "p0").unwrap();
        assert_eq!(s.get(b"marker").unwrap(), Some(b"created".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn recovery_key_only_database_can_still_manage_protectors() {
        let path = temp_path("recovery_only_manage");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = PageStore::create_encrypted(&path, "main").unwrap();
            store.put(b"marker", b"ok").unwrap();
        }

        let recovery = PageStore::add_recovery_key_protector(&path, "main").unwrap();
        PageStore::remove_keyslot(&path, "main", 0).unwrap();

        let slot = PageStore::add_passphrase_protector_with_recovery_key(&path, &recovery, "p1").unwrap();
        PageStore::open_with_passphrase(&path, "p1").unwrap();

        let recovery2 = PageStore::add_recovery_key_protector_with_recovery_key(&path, &recovery).unwrap();
        PageStore::open_with_recovery_key(&path, &recovery2).unwrap();

        PageStore::rekey_kek_with_recovery_key(&path, slot, &recovery, "p1-new").unwrap();
        assert!(PageStore::open_with_passphrase(&path, "p1").is_err());
        PageStore::open_with_passphrase(&path, "p1-new").unwrap();

        PageStore::remove_keyslot_with_recovery_key(&path, &recovery, slot).unwrap();
        assert!(PageStore::open_with_passphrase(&path, "p1-new").is_err());
        PageStore::open_with_recovery_key(&path, &recovery).unwrap();
        PageStore::open_with_recovery_key(&path, &recovery2).unwrap();

        let slots = PageStore::list_keyslots(&path).unwrap();
        assert_eq!(slots.len(), 2);

        let store = PageStore::open_with_recovery_key(&path, &recovery).unwrap();
        assert_eq!(store.get(b"marker").unwrap(), Some(b"ok".to_vec()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn keyfile_only_database_can_still_manage_protectors() {
        let path = temp_path("keyfile_only_manage");
        let keyfile = temp_path("keyfile_only_manage.bin");
        let keyfile2 = temp_path("keyfile_only_manage_2.bin");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&keyfile);
        let _ = std::fs::remove_file(&keyfile2);

        std::fs::write(&keyfile, [0x11u8; 32]).unwrap();
        std::fs::write(&keyfile2, [0x22u8; 32]).unwrap();

        {
            let mut store = PageStore::create_encrypted(&path, "main").unwrap();
            store.put(b"marker", b"ok").unwrap();
        }

        let key_slot = PageStore::add_keyfile_protector(&path, "main", &keyfile).unwrap();
        PageStore::remove_keyslot(&path, "main", 0).unwrap();

        let slot = PageStore::add_passphrase_protector_with_keyfile(&path, &keyfile, "p1").unwrap();
        PageStore::open_with_passphrase(&path, "p1").unwrap();

        PageStore::add_recovery_key_protector_with_keyfile_and_secret(&path, &keyfile, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH").unwrap();
        PageStore::open_with_recovery_key(&path, "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH").unwrap();

        let slot2 = PageStore::add_keyfile_protector_with_keyfile(&path, &keyfile, &keyfile2).unwrap();
        PageStore::open_with_keyfile(&path, &keyfile2).unwrap();

        PageStore::rekey_kek_with_keyfile(&path, slot, &keyfile, "p1-new").unwrap();
        assert!(PageStore::open_with_passphrase(&path, "p1").is_err());
        PageStore::open_with_passphrase(&path, "p1-new").unwrap();

        PageStore::remove_keyslot_with_keyfile(&path, &keyfile, slot).unwrap();
        PageStore::remove_keyslot_with_keyfile(&path, &keyfile, key_slot).unwrap();
        assert!(PageStore::open_with_keyfile(&path, &keyfile).is_err());
        PageStore::open_with_keyfile(&path, &keyfile2).unwrap();

        let slots = PageStore::list_keyslots(&path).unwrap();
        assert!(slots.iter().any(|&(idx, _)| idx == slot2));

        let store = PageStore::open_with_keyfile(&path, &keyfile2).unwrap();
        assert_eq!(store.get(b"marker").unwrap(), Some(b"ok".to_vec()));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&keyfile);
        let _ = std::fs::remove_file(&keyfile2);
    }
}
