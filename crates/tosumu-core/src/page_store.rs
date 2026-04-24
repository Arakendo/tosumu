// PageStore — put/get/delete/scan on top of the pager.
//
// Source of truth: DESIGN.md §12.0 (MVP +1).
//
// Stage 1 uses a linear scan: no B+ tree, no index. Pages are append-only
// within a session; writes always go to the current "active" leaf page.
// Reads scan all data pages and use last-write-wins semantics.
//
// Record encoding inside slotted pages:
//   Live record:  [0x01: u8][key_len: u16 LE][val_len: u16 LE][key...][val...]
//   Tombstone:    [0x02: u8][key_len: u16 LE][key...]
//
// Slot entry: { offset: u16 LE, length: u16 LE } — 4 bytes per slot.
// Offsets are relative to the start of the decrypted page body (0..PAGE_PLAINTEXT_SIZE).

use std::collections::HashMap;
use std::path::Path;

use crate::error::{Result, TosumError};
use crate::format::*;
use crate::pager::Pager;

const RECORD_OVERHEAD_LIVE: usize = 5; // type(1) + key_len(2) + val_len(2)
const RECORD_OVERHEAD_TOMB: usize = 3; // type(1) + key_len(2)

/// High-level key-value store backed by the pager.
pub struct PageStore {
    pager: Pager,
    /// Page number of the leaf page currently accepting new writes.
    active_leaf: u64,
}

/// Summary information about the store. Returned by `stat()`.
pub struct StoreStat {
    pub page_count: u64,
    pub data_pages: u64,
}

impl PageStore {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create a new `.tsm` file. Fails if `path` already exists.
    pub fn create(path: &Path) -> Result<Self> {
        let mut pager = Pager::create(path)?;
        // Allocate the first data page (page 1).
        let active_leaf = pager.allocate()?;
        pager.init_page(active_leaf, PAGE_TYPE_LEAF)?;
        Ok(PageStore { pager, active_leaf })
    }

    /// Open an existing `.tsm` file.
    pub fn open(path: &Path) -> Result<Self> {
        let pager = Pager::open(path)?;
        let page_count = pager.page_count();
        // Active leaf is the last allocated page (pages are monotonically allocated).
        let active_leaf = if page_count > 1 { page_count - 1 } else {
            // File has only the header. This shouldn't happen with a file created by
            // PageStore::create, but handle gracefully.
            return Err(TosumError::Corrupt { pgno: 0, reason: "no data pages" });
        };
        Ok(PageStore { pager, active_leaf })
    }

    // ── Writes ───────────────────────────────────────────────────────────────

    /// Insert or update a key-value pair.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;
        if key.len() + value.len() > RECORD_MAX_KV {
            return Err(TosumError::InvalidArgument("key + value exceeds maximum record size"));
        }

        let record = encode_live(key, value);
        self.append_record(&record)
    }

    /// Delete a key. No-op (but still appends a tombstone) to maintain
    /// the append-only audit trail. The tombstone is persisted even if the
    /// key doesn't currently exist.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        validate_key(key)?;
        let record = encode_tombstone(key);
        self.append_record(&record)
    }

    // ── Reads (full linear scan) ──────────────────────────────────────────────

    /// Retrieve the current value for `key`, or `None` if not present.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let map = self.build_map()?;
        Ok(map.into_values_for_key(key))
    }

    /// Return all live key-value pairs, sorted by key.
    pub fn scan(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let map = self.build_map()?;
        let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = map.into_pairs();
        pairs.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        Ok(pairs)
    }

    /// Return summary statistics.
    pub fn stat(&self) -> StoreStat {
        StoreStat {
            page_count: self.pager.page_count(),
            data_pages: self.pager.page_count().saturating_sub(1),
        }
    }

    // ── private ──────────────────────────────────────────────────────────────

    /// Append `record` to the active leaf page, allocating a new page if needed.
    fn append_record(&mut self, record: &[u8]) -> Result<()> {
        let needed = SLOT_SIZE + record.len();
        let fits = self.pager.with_page(self.active_leaf, |page| {
            Ok(free_space(page) >= needed)
        })?;

        if !fits {
            // Allocate a fresh leaf page and make it active.
            let new_pgno = self.pager.allocate()?;
            self.pager.init_page(new_pgno, PAGE_TYPE_LEAF)?;
            self.active_leaf = new_pgno;
        }

        let pgno = self.active_leaf;
        let record_owned = record.to_vec();
        self.pager.with_page_mut(pgno, |page| {
            append_to_leaf(page, &record_owned)
        })
    }

    /// Scan all data pages (1..page_count) and build a last-write-wins map.
    fn build_map(&self) -> Result<LiveMap> {
        let mut map = LiveMap::default();
        for pgno in 1..self.pager.page_count() {
            self.pager.with_page(pgno, |page| {
                scan_leaf(page, pgno, &mut map)
            })?;
        }
        Ok(map)
    }
}

// ── Slotted page operations ───────────────────────────────────────────────────

fn free_space(page: &[u8; PAGE_PLAINTEXT_SIZE]) -> usize {
    let free_start = read_u16(page, 4) as usize; // slot array end
    let free_end = read_u16(page, 6) as usize;   // heap start
    free_end.saturating_sub(free_start)
}

fn append_to_leaf(page: &mut [u8; PAGE_PLAINTEXT_SIZE], record: &[u8]) -> Result<()> {
    let slot_count = read_u16(page, 2) as usize;
    let free_start = read_u16(page, 4) as usize;
    let free_end = read_u16(page, 6) as usize;
    let needed = SLOT_SIZE + record.len();

    if free_end.saturating_sub(free_start) < needed {
        return Err(TosumError::OutOfSpace);
    }

    // Write record into the heap (growing down).
    let record_offset = free_end - record.len();
    page[record_offset..record_offset + record.len()].copy_from_slice(record);

    // Write slot entry (offset, length) growing up.
    let slot_pos = free_start;
    write_u16_mut(page, slot_pos, record_offset as u16);
    write_u16_mut(page, slot_pos + 2, record.len() as u16);

    // Update page header.
    write_u16_mut(page, 2, (slot_count + 1) as u16);
    write_u16_mut(page, 4, (free_start + SLOT_SIZE) as u16);
    write_u16_mut(page, 6, record_offset as u16);

    Ok(())
}

/// Walk all slot entries in a leaf page and apply records to `map`.
fn scan_leaf(page: &[u8; PAGE_PLAINTEXT_SIZE], pgno: u64, map: &mut LiveMap) -> Result<()> {
    if page[0] != PAGE_TYPE_LEAF {
        // Not a leaf; skip (shouldn't happen for MVP+1 but be defensive).
        return Ok(());
    }
    let slot_count = read_u16(page, 2) as usize;

    for i in 0..slot_count {
        let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
        let offset = read_u16(page, slot_pos) as usize;
        let length = read_u16(page, slot_pos + 2) as usize;

        if offset + length > PAGE_PLAINTEXT_SIZE {
            return Err(TosumError::Corrupt { pgno, reason: "slot points outside page" });
        }
        let record = &page[offset..offset + length];
        if record.is_empty() {
            return Err(TosumError::Corrupt { pgno, reason: "zero-length record" });
        }

        match record[0] {
            RECORD_LIVE => {
                if record.len() < RECORD_OVERHEAD_LIVE {
                    return Err(TosumError::Corrupt { pgno, reason: "truncated live record" });
                }
                let key_len = u16::from_le_bytes([record[1], record[2]]) as usize;
                let val_len = u16::from_le_bytes([record[3], record[4]]) as usize;
                if 5 + key_len + val_len > record.len() {
                    return Err(TosumError::Corrupt { pgno, reason: "live record key/value overflow" });
                }
                let key = record[5..5 + key_len].to_vec();
                let val = record[5 + key_len..5 + key_len + val_len].to_vec();
                map.insert(key, val);
            }
            RECORD_TOMBSTONE => {
                if record.len() < RECORD_OVERHEAD_TOMB {
                    return Err(TosumError::Corrupt { pgno, reason: "truncated tombstone" });
                }
                let key_len = u16::from_le_bytes([record[1], record[2]]) as usize;
                if 3 + key_len > record.len() {
                    return Err(TosumError::Corrupt { pgno, reason: "tombstone key overflow" });
                }
                let key = record[3..3 + key_len].to_vec();
                map.remove(&key);
            }
            _ => return Err(TosumError::Corrupt { pgno, reason: "unknown record type" }),
        }
    }
    Ok(())
}

// ── Record encoding ───────────────────────────────────────────────────────────

fn encode_live(key: &[u8], value: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(RECORD_OVERHEAD_LIVE + key.len() + value.len());
    r.push(RECORD_LIVE);
    r.extend_from_slice(&(key.len() as u16).to_le_bytes());
    r.extend_from_slice(&(value.len() as u16).to_le_bytes());
    r.extend_from_slice(key);
    r.extend_from_slice(value);
    r
}

fn encode_tombstone(key: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(RECORD_OVERHEAD_TOMB + key.len());
    r.push(RECORD_TOMBSTONE);
    r.extend_from_slice(&(key.len() as u16).to_le_bytes());
    r.extend_from_slice(key);
    r
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

// ── LiveMap ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct LiveMap {
    inner: HashMap<Vec<u8>, Vec<u8>>,
}

impl LiveMap {
    fn insert(&mut self, key: Vec<u8>, val: Vec<u8>) {
        self.inner.insert(key, val);
    }

    fn remove(&mut self, key: &[u8]) {
        self.inner.remove(key);
    }

    fn into_values_for_key(mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.remove(key)
    }

    fn into_pairs(self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner.into_iter().collect()
    }
}

// ── Page header read/write helpers ────────────────────────────────────────────

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
}

fn write_u16_mut(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
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
