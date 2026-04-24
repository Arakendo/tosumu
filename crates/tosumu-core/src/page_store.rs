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

    /// Create a new passphrase-protected `.tsm` file.
    pub fn create_encrypted(path: &Path, passphrase: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::create_encrypted(path, passphrase)? })
    }

    /// Open a passphrase-protected `.tsm` file.
    pub fn open_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_passphrase(path, passphrase)? })
    }

    /// Open a recovery-key-protected `.tsm` file.
    pub fn open_with_recovery_key(path: &Path, recovery_str: &str) -> Result<Self> {
        Ok(PageStore { tree: BTree::open_with_recovery_key(path, recovery_str)? })
    }

    // ── Key management ───────────────────────────────────────────────────────

    /// Add a passphrase protector. Returns the slot index used.
    pub fn add_passphrase_protector(path: &Path, unlock_passphrase: &str, new_passphrase: &str) -> Result<u16> {
        BTree::add_passphrase_protector(path, unlock_passphrase, new_passphrase)
    }

    /// Add a recovery-key protector. Returns the one-time recovery string.
    pub fn add_recovery_key_protector(path: &Path, unlock_passphrase: &str) -> Result<String> {
        BTree::add_recovery_key_protector(path, unlock_passphrase)
    }

    /// Remove the keyslot at `slot_idx` (must not be the last active slot).
    pub fn remove_keyslot(path: &Path, unlock_passphrase: &str, slot_idx: u16) -> Result<()> {
        BTree::remove_keyslot(path, unlock_passphrase, slot_idx)
    }

    /// Rotate the KEK for the Passphrase slot at `slot_idx`.
    pub fn rekey_kek(path: &Path, slot_idx: u16, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        BTree::rekey_kek(path, slot_idx, old_passphrase, new_passphrase)
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
            matches!(err, crate::error::TosumError::WrongKey),
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
            matches!(err, crate::error::TosumError::WrongKey),
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
    fn wrong_recovery_key_returns_wrong_key() {
        let path = temp_path("wrong_recovery");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "p").unwrap();
        let _real = PageStore::add_recovery_key_protector(&path, "p").unwrap();

        let err = PageStore::open_with_recovery_key(&path, "AAAAAAAA-BBBBBBBB-CCCCCCCC-DDDDDDDD")
            .err().unwrap();
        assert!(matches!(err, crate::error::TosumError::WrongKey), "got {err:?}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn remove_last_slot_is_rejected() {
        let path = temp_path("remove_last");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "only-pass").unwrap();

        let err = PageStore::remove_keyslot(&path, "only-pass", 0).err().unwrap();
        assert!(
            matches!(err, crate::error::TosumError::InvalidArgument(_)),
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
        assert!(matches!(err, crate::error::TosumError::WrongKey), "got {err:?}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rekey_kek_old_fails_new_succeeds() {
        let path = temp_path("rekey_kek");
        let _ = std::fs::remove_file(&path);

        PageStore::create_encrypted(&path, "old-pass").unwrap();
        PageStore::rekey_kek(&path, 0, "old-pass", "new-pass").unwrap();

        let err = PageStore::open_with_passphrase(&path, "old-pass").err().unwrap();
        assert!(matches!(err, crate::error::TosumError::WrongKey), "old pass still works: {err:?}");

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
            matches!(err, crate::error::TosumError::WrongKey | crate::error::TosumError::AuthFailed { .. }),
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
            matches!(err, crate::error::TosumError::NotATosumFile),
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
            matches!(err, crate::error::TosumError::AuthFailed { .. } | crate::error::TosumError::WrongKey),
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
            matches!(err, crate::error::TosumError::WrongKey | crate::error::TosumError::AuthFailed { .. }),
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
            matches!(err, crate::error::TosumError::WrongKey | crate::error::TosumError::AuthFailed { .. }),
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
            matches!(err, crate::error::TosumError::AuthFailed { .. }),
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
            matches!(err, crate::error::TosumError::NotATosumFile | crate::error::TosumError::Io(_)),
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

    fn result_is_err_io_or_not_tosum(e: &crate::error::TosumError) -> bool {
        matches!(e, crate::error::TosumError::NotATosumFile | crate::error::TosumError::Io(_))
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
            matches!(err, crate::error::TosumError::InvalidArgument(_)),
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
        assert!(matches!(err, crate::error::TosumError::WrongKey), "old pass still works: {err:?}");
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
        assert!(matches!(err, crate::error::TosumError::WrongKey), "got {err:?}");

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
            matches!(err, crate::error::TosumError::InvalidArgument(_) | crate::error::TosumError::WrongKey),
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
            matches!(err, crate::error::TosumError::AuthFailed { .. } | crate::error::TosumError::WrongKey),
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
        assert!(matches!(err, crate::error::TosumError::InvalidArgument(_)));

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
        let pages_after_first = store.stat().page_count;

        for i in 0..n {
            store.delete(format!("k{i:04}").as_bytes()).unwrap();
        }
        for i in 0..n {
            store.put(format!("k{i:04}").as_bytes(), b"data2").unwrap();
        }
        let pages_after_second = store.stat().page_count;

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
            matches!(err, crate::error::TosumError::WrongKey | crate::error::TosumError::AuthFailed { .. }),
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
}
