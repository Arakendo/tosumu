// MVP 0 — append-only log store.
//
// On-disk format (little-endian):
//   [key_len: u32][val_len: u32][key bytes][val bytes]
//
// A delete is encoded as val_len == u32::MAX with no value bytes.
// The in-memory HashMap is rebuilt by replaying every record on open.
//
// This is intentionally disposable. MVP +1 replaces it with the real
// page-based format (DESIGN.md §5). Nothing here is load-bearing beyond
// proving the CLI and round-trip logic work.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::Path;

use crate::error::{Result, TosumuError};

const DELETE_SENTINEL: u32 = u32::MAX;

/// Maximum key length accepted at the API boundary.
const MAX_KEY_LEN: usize = 65535;
/// Maximum value length accepted at the API boundary.
const MAX_VAL_LEN: usize = 1024 * 1024; // 1 MiB — generous for MVP 0

/// Append-only log store.
///
/// All writes are immediately appended and fsynced.
/// The in-memory map is the authoritative read path.
pub struct LogStore {
    map: HashMap<Vec<u8>, Vec<u8>>,
    file: File,
}

impl LogStore {
    /// Open (or create) a log store at `path`.
    ///
    /// Replays the entire log to reconstruct the in-memory map.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let map = replay(&file)?;

        Ok(Self { map, file })
    }

    /// Insert or update a key-value pair.
    pub fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        validate_key(key)?;
        validate_value(value)?;

        append_record(&mut self.file, key, Some(value))?;
        self.map.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    /// Retrieve the value for `key`, or `None` if not present.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.map.get(key).map(|v| v.as_slice())
    }

    /// Delete `key`. No-op if the key does not exist.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        validate_key(key)?;

        if self.map.remove(key).is_some() {
            append_record(&mut self.file, key, None)?;
        }
        Ok(())
    }

    /// Iterate all key-value pairs in arbitrary order.
    pub fn scan(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.map.iter().map(|(k, v)| (k.as_slice(), v.as_slice()))
    }

    /// Number of live key-value pairs.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ── internal helpers ──────────────────────────────────────────────────────────

fn validate_key(key: &[u8]) -> Result<()> {
    if key.is_empty() {
        return Err(TosumuError::InvalidArgument("key must not be empty"));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(TosumuError::InvalidArgument("key exceeds maximum length"));
    }
    Ok(())
}

fn validate_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_VAL_LEN {
        return Err(TosumuError::InvalidArgument("value exceeds maximum length"));
    }
    Ok(())
}

/// Append one record to `file` and fsync.
fn append_record(file: &mut File, key: &[u8], value: Option<&[u8]>) -> Result<()> {
    let key_len = key.len() as u32;
    let val_len = value.map(|v| v.len() as u32).unwrap_or(DELETE_SENTINEL);

    // Build the record in a small stack buffer to minimise syscalls.
    let mut header = [0u8; 8];
    header[0..4].copy_from_slice(&key_len.to_le_bytes());
    header[4..8].copy_from_slice(&val_len.to_le_bytes());

    // Seek to end before every append so concurrent opens don't corrupt each
    // other (best-effort for MVP 0; proper locking is a Stage 3+ concern).
    use std::io::Seek;
    file.seek(std::io::SeekFrom::End(0))?;
    file.write_all(&header)?;
    file.write_all(key)?;
    if let Some(v) = value {
        file.write_all(v)?;
    }
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

/// Replay the log file and return the final key-value map.
fn replay(file: &File) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    let mut reader = BufReader::new(file);
    let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut offset: u64 = 0;

    loop {
        let mut header = [0u8; 8];
        match read_exact_or_eof(&mut reader, &mut header) {
            Ok(false) => break, // clean EOF
            Ok(true) => {}
            Err(e) => return Err(e),
        }

        let key_len = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let val_len_raw = u32::from_le_bytes(header[4..8].try_into().unwrap());

        if key_len == 0 || key_len > MAX_KEY_LEN {
            return Err(TosumuError::CorruptRecord {
                offset,
                reason: "key_len out of range",
            });
        }

        let mut key = vec![0u8; key_len];
        reader.read_exact(&mut key).map_err(|_| TosumuError::CorruptRecord {
            offset,
            reason: "unexpected EOF reading key",
        })?;

        if val_len_raw == DELETE_SENTINEL {
            map.remove(&key);
        } else {
            let val_len = val_len_raw as usize;
            if val_len > MAX_VAL_LEN {
                return Err(TosumuError::CorruptRecord {
                    offset,
                    reason: "val_len out of range",
                });
            }
            let mut value = vec![0u8; val_len];
            reader.read_exact(&mut value).map_err(|_| TosumuError::CorruptRecord {
                offset,
                reason: "unexpected EOF reading value",
            })?;
            map.insert(key, value);
        }

        offset += 8 + key_len as u64 + if val_len_raw == DELETE_SENTINEL { 0 } else { val_len_raw as u64 };
    }

    Ok(map)
}

/// Read exactly `buf.len()` bytes. Returns `Ok(true)` on success,
/// `Ok(false)` if the file is at EOF before any bytes were read.
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => {
                if total == 0 {
                    return Ok(false); // clean EOF
                }
                return Err(TosumuError::CorruptRecord {
                    offset: total as u64,
                    reason: "unexpected EOF in record header",
                });
            }
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(TosumuError::Io(e)),
        }
    }
    Ok(true)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("tosumu_test_{name}_{}.log", std::process::id()))
    }

    #[test]
    fn put_get_round_trip() {
        let path = temp_path("put_get");
        let _ = std::fs::remove_file(&path);

        let mut store = LogStore::open(&path).unwrap();
        store.put(b"hello", b"world").unwrap();
        assert_eq!(store.get(b"hello"), Some(b"world".as_slice()));
        assert_eq!(store.get(b"missing"), None);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reopen_returns_same_data() {
        let path = temp_path("reopen");
        let _ = std::fs::remove_file(&path);

        {
            let mut store = LogStore::open(&path).unwrap();
            store.put(b"key1", b"val1").unwrap();
            store.put(b"key2", b"val2").unwrap();
        }

        let store = LogStore::open(&path).unwrap();
        assert_eq!(store.get(b"key1"), Some(b"val1".as_slice()));
        assert_eq!(store.get(b"key2"), Some(b"val2".as_slice()));
        assert_eq!(store.len(), 2);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_opens_cleanly() {
        let path = temp_path("empty");
        let _ = std::fs::remove_file(&path);

        let store = LogStore::open(&path).unwrap();
        assert!(store.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn delete_removes_key() {
        let path = temp_path("delete");
        let _ = std::fs::remove_file(&path);

        let mut store = LogStore::open(&path).unwrap();
        store.put(b"k", b"v").unwrap();
        store.delete(b"k").unwrap();
        assert_eq!(store.get(b"k"), None);

        // delete survives reopen
        let store2 = LogStore::open(&path).unwrap();
        assert_eq!(store2.get(b"k"), None);
        assert!(store2.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn put_overwrites_existing_key() {
        let path = temp_path("overwrite");
        let _ = std::fs::remove_file(&path);

        let mut store = LogStore::open(&path).unwrap();
        store.put(b"k", b"v1").unwrap();
        store.put(b"k", b"v2").unwrap();
        assert_eq!(store.get(b"k"), Some(b"v2".as_slice()));

        let store2 = LogStore::open(&path).unwrap();
        assert_eq!(store2.get(b"k"), Some(b"v2".as_slice()));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn scan_returns_all_live_keys() {
        let path = temp_path("scan");
        let _ = std::fs::remove_file(&path);

        let mut store = LogStore::open(&path).unwrap();
        store.put(b"a", b"1").unwrap();
        store.put(b"b", b"2").unwrap();
        store.put(b"c", b"3").unwrap();
        store.delete(b"b").unwrap();

        let mut keys: Vec<&[u8]> = store.scan().map(|(k, _)| k).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec![b"a".as_slice(), b"c".as_slice()]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_empty_key() {
        let path = temp_path("empty_key");
        let _ = std::fs::remove_file(&path);

        let mut store = LogStore::open(&path).unwrap();
        assert!(store.put(b"", b"v").is_err());

        let _ = std::fs::remove_file(&path);
    }
}
