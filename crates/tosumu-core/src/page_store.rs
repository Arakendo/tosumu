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

use std::path::Path;

use crate::btree::BTree;
use crate::error::{Result, TosumError};

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

    /// Return summary statistics.
    pub fn stat(&self) -> StoreStat {
        let page_count = self.tree.page_count();
        StoreStat {
            page_count,
            data_pages: page_count.saturating_sub(1),
            tree_height: self.tree.tree_height().unwrap_or(0),
        }
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
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(TosumError::InvalidArgument("key must not be empty"));
    }
    if key.len() > u16::MAX as usize {
        return Err(TosumError::InvalidArgument("key exceeds u16 maximum"));
    }
    Ok(())
}

fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > u16::MAX as usize {
        return Err(TosumError::InvalidArgument("value exceeds u16 maximum"));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tosumu_page_test_{name}_{}.tsm", std::process::id()))
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
        assert_eq!(store.stat().data_pages, 1);
        let pairs = store.scan().unwrap();
        assert!(pairs.is_empty());

        let _ = std::fs::remove_file(&path);
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
        assert!(matches!(err, crate::error::TosumError::AuthFailed { .. }));

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
            Err(crate::error::TosumError::InvalidArgument("deliberate rollback"))
        });
        assert!(result.is_err());
        assert_eq!(store.get(b"x").unwrap(), None, "rolled-back write must not be visible");

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

        let before_pages = store.stat().data_pages;
        assert!(before_pages > 1, "expected multiple pages, got {before_pages}");

        let store2 = PageStore::open(&path).unwrap();
        for i in 0u32..100 {
            let k = format!("key{i:05}");
            let v = format!("value{i:05}-{}", "x".repeat(90));
            assert_eq!(store2.get(k.as_bytes()).unwrap(), Some(v.into_bytes()));
        }

        let _ = std::fs::remove_file(&path);
    }
}
