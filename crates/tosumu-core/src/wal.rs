// Write-Ahead Log (WAL) — durability for MVP +4.
//
// Source of truth: DESIGN.md §7.2–§7.3.
//
// Wire format per record:
//   lsn:         u64 LE  (8 bytes)
//   record_type: u8      (1 byte)
//   payload_len: u32 LE  (4 bytes)
//   payload:     [u8]    (payload_len bytes)
//   crc32:       u32 LE  (4 bytes) — crc32fast over [lsn..payload]
//
// Record types:
//   0x01 = Begin     { txn_id: u64 }
//   0x02 = PageWrite { pgno: u64, page_version: u64, frame: [u8; PAGE_SIZE] }
//   0x03 = Commit    { txn_id: u64 }
//   0x04 = Checkpoint{ up_to_lsn: u64 }
//
// Physical logging: PageWrite stores the full encrypted frame (PAGE_SIZE bytes).
// Recovery applies PageWrite records from committed transactions only.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, ErrorKind, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Result, TosumError};
use crate::format::PAGE_SIZE;

// ── Transient-lock retry ─────────────────────────────────────────────────────

/// Maximum number of retry attempts when a transient file-lock error is
/// encountered before giving up with `TosumError::FileBusy`.
const MAX_RETRIES: u32 = 5;

/// Returns `true` if `e` is a transient file-lock error that may resolve on retry.
///
/// - Windows: ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33).
/// - Test mode: OS error 32 is accepted as a fault-injection signal on all platforms.
fn is_transient_lock(e: &std::io::Error) -> bool {
    #[cfg(windows)]
    if matches!(e.raw_os_error(), Some(32) | Some(33)) { return true; }
    // Fault injection in tests synthesises OS error 32 on any platform.
    #[cfg(test)]
    if e.raw_os_error() == Some(32) { return true; }
    let _ = e;
    false
}

/// In non-test builds: delegate directly to `open_fn`.
#[cfg(not(test))]
fn inject_or_open(open_fn: &impl Fn() -> std::io::Result<File>) -> std::io::Result<File> {
    open_fn()
}

/// In test builds: consume a fault-injection ticket before calling `open_fn`.
#[cfg(test)]
fn inject_or_open(open_fn: &impl Fn() -> std::io::Result<File>) -> std::io::Result<File> {
    if fault_injection::should_inject() {
        Err(std::io::Error::from_raw_os_error(32))
    } else {
        open_fn()
    }
}

/// Open a file with bounded retry on transient lock errors.
///
/// Makes up to `MAX_RETRIES + 1` attempts.  Each transient failure (lock held
/// by another process) waits 10 ms before retrying.  After exhausting all
/// attempts returns `TosumError::FileBusy { path, operation }`.
///
/// Non-transient errors (permission denied, file not found, …) propagate
/// immediately without retrying.
fn open_file_retrying<F>(path: &Path, open_fn: F, operation: &'static str) -> Result<File>
where
    F: Fn() -> std::io::Result<File>,
{
    for attempt in 0..=MAX_RETRIES {
        match inject_or_open(&open_fn) {
            Ok(f) => return Ok(f),
            Err(e) if is_transient_lock(&e) && attempt < MAX_RETRIES => {
                // Brief pause to let the lock holder release.
                // Skipped in tests to keep the suite fast.
                #[cfg(not(test))]
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) if is_transient_lock(&e) => {
                // Retries exhausted — report as FileBusy.
                return Err(TosumError::FileBusy {
                    path: path.to_path_buf(),
                    operation,
                });
            }
            Err(e) => return Err(e.into()),
        }
    }
    unreachable!("loop exits via Ok or FileBusy")
}

// ── Fault injection (test-only) ───────────────────────────────────────────────

/// Fault injection state for lock-error simulation in tests.
///
/// Tests that use fault injection MUST hold `LOCK` for their duration to
/// prevent the fault counter from bleeding into parallel tests.
#[cfg(test)]
pub(crate) mod fault_injection {
    use std::sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    };

    /// Serialises all fault-injection tests.
    pub static LOCK: Mutex<()> = Mutex::new(());
    static FAULTS: AtomicU32 = AtomicU32::new(0);

    /// Set the number of lock faults to inject.
    pub fn arm(n: u32) { FAULTS.store(n, Ordering::SeqCst); }

    /// Clear all pending faults (called by `FaultGuard` on drop).
    pub fn disarm() { FAULTS.store(0, Ordering::SeqCst); }

    /// Atomically consume one fault ticket.  Returns `true` iff a fault should
    /// be injected (counter was > 0 and was decremented).
    pub fn should_inject() -> bool {
        FAULTS
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                if v > 0 { Some(v - 1) } else { None }
            })
            .is_ok()
    }
}

/// RAII guard that clears fault injection state on drop (normal exit *and* panic).
#[cfg(test)]
struct FaultGuard;
#[cfg(test)]
impl Drop for FaultGuard {
    fn drop(&mut self) { fault_injection::disarm(); }
}

// ── Record type discriminants ─────────────────────────────────────────────────

const RT_BEGIN:      u8 = 0x01;
const RT_PAGE_WRITE: u8 = 0x02;
const RT_COMMIT:     u8 = 0x03;
const RT_CHECKPOINT: u8 = 0x04;

// ── Header sizes ─────────────────────────────────────────────────────────────

/// Fixed overhead per record: lsn(8) + type(1) + payload_len(4) + crc32(4) = 17 bytes.
pub const RECORD_HEADER_SIZE: usize = 17;

// ── WalRecord ────────────────────────────────────────────────────────────────

/// A decoded WAL record.
#[derive(Debug, Clone)]
pub enum WalRecord {
    Begin      { txn_id: u64 },
    PageWrite  { pgno: u64, page_version: u64, frame: Box<[u8; PAGE_SIZE]> },
    Commit     { txn_id: u64 },
    Checkpoint { up_to_lsn: u64 },
}

impl WalRecord {
    /// Encode this record into `out` with the given `lsn`.
    ///
    /// Layout: [lsn u64][type u8][payload_len u32][payload][crc32 u32]
    pub fn encode(&self, lsn: u64, out: &mut Vec<u8>) {
        let payload = self.encode_payload();
        let payload_len = payload.len() as u32;

        let header_start = out.len();
        out.extend_from_slice(&lsn.to_le_bytes());
        out.push(self.type_byte());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&payload);

        // CRC32 covers [lsn..end-of-payload].
        let crc = crc32fast::hash(&out[header_start..]);
        out.extend_from_slice(&crc.to_le_bytes());
    }

    fn type_byte(&self) -> u8 {
        match self {
            WalRecord::Begin { .. }      => RT_BEGIN,
            WalRecord::PageWrite { .. }  => RT_PAGE_WRITE,
            WalRecord::Commit { .. }     => RT_COMMIT,
            WalRecord::Checkpoint { .. } => RT_CHECKPOINT,
        }
    }

    fn encode_payload(&self) -> Vec<u8> {
        match self {
            WalRecord::Begin { txn_id } => {
                txn_id.to_le_bytes().to_vec()
            }
            WalRecord::PageWrite { pgno, page_version, frame } => {
                let mut p = Vec::with_capacity(8 + 8 + PAGE_SIZE);
                p.extend_from_slice(&pgno.to_le_bytes());
                p.extend_from_slice(&page_version.to_le_bytes());
                p.extend_from_slice(frame.as_ref());
                p
            }
            WalRecord::Commit { txn_id } => {
                txn_id.to_le_bytes().to_vec()
            }
            WalRecord::Checkpoint { up_to_lsn } => {
                up_to_lsn.to_le_bytes().to_vec()
            }
        }
    }
}

// ── WalWriter ────────────────────────────────────────────────────────────────

/// Appends WAL records to the `.wal` sidecar file.
pub struct WalWriter {
    file: File,
    /// LSN to assign to the next record written.
    next_lsn: u64,
}

impl WalWriter {
    /// Create a new WAL file. Fails if the file already exists.
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        Ok(WalWriter { file, next_lsn: 1 })
    }

    /// Open an existing WAL file for appending.
    ///
    /// Scans all existing records to determine `next_lsn`.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        // Determine next LSN by scanning existing records.
        let next_lsn = scan_max_lsn(&file)? + 1;
        let mut w = WalWriter { file, next_lsn };
        // Seek to end for appending.
        w.file.seek(SeekFrom::End(0))?;
        Ok(w)
    }

    /// Open or create: if the WAL does not exist, create it; otherwise open for append.
    pub fn open_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::open(path)
        } else {
            Self::create(path)
        }
    }

    /// Write one record to the WAL. Does NOT fsync — call `sync()` after a full transaction.
    pub fn append(&mut self, record: &WalRecord) -> Result<u64> {
        let lsn = self.next_lsn;
        let mut buf = Vec::with_capacity(RECORD_HEADER_SIZE + PAGE_SIZE);
        record.encode(lsn, &mut buf);
        self.file.write_all(&buf)?;
        self.next_lsn += 1;
        Ok(lsn)
    }

    /// Flush OS buffers to durable storage.
    pub fn sync(&mut self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    /// The LSN that will be assigned to the next appended record.
    pub fn next_lsn(&self) -> u64 { self.next_lsn }

    /// Truncate the WAL to zero bytes (used after a full checkpoint).
    pub fn truncate(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(0))?;
        self.file.set_len(0)?;
        self.file.sync_data()?;
        self.next_lsn = 1;
        Ok(())
    }
}

// ── WalReader ────────────────────────────────────────────────────────────────

/// Reads WAL records sequentially from a `.wal` file.
pub struct WalReader {
    reader: BufReader<File>,
}

impl WalReader {
    /// Open a WAL file for reading from the beginning.
    pub fn open(path: &Path) -> Result<Self> {
        let file = open_file_retrying(
            path,
            || OpenOptions::new().read(true).open(path),
            "reading WAL",
        )?;
        Ok(WalReader { reader: BufReader::new(file) })
    }

    /// Read the next record. Returns `None` at clean EOF; error on truncation/CRC failure.
    pub fn next_record(&mut self) -> Result<Option<(u64, WalRecord)>> {
        // Read fixed header: lsn(8) + type(1) + payload_len(4).
        let mut hdr = [0u8; 13];
        match self.reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let lsn         = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let record_type = hdr[8];
        let payload_len = u32::from_le_bytes(hdr[9..13].try_into().unwrap()) as usize;

        let mut payload = vec![0u8; payload_len];
        self.reader.read_exact(&mut payload).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                TosumError::CorruptRecord { offset: 0, reason: "WAL record truncated in payload" }
            } else { e.into() }
        })?;

        let mut crc_bytes = [0u8; 4];
        self.reader.read_exact(&mut crc_bytes).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                TosumError::CorruptRecord { offset: 0, reason: "WAL record truncated in CRC" }
            } else { e.into() }
        })?;
        let stored_crc = u32::from_le_bytes(crc_bytes);

        // Verify CRC: covers [lsn..end-of-payload].
        let mut covered = Vec::with_capacity(13 + payload_len);
        covered.extend_from_slice(&hdr);
        covered.extend_from_slice(&payload);
        let computed_crc = crc32fast::hash(&covered);
        if computed_crc != stored_crc {
            return Err(TosumError::CorruptRecord {
                offset: 0,
                reason: "WAL record CRC mismatch",
            });
        }

        let record = decode_payload(record_type, &payload)?;
        Ok(Some((lsn, record)))
    }

    /// Collect all valid records from the WAL, stopping at the first CRC error or EOF.
    pub fn read_all(path: &Path) -> Result<Vec<(u64, WalRecord)>> {
        let mut rdr = Self::open(path)?;
        let mut out = Vec::new();
        loop {
            match rdr.next_record() {
                Ok(Some(r)) => out.push(r),
                Ok(None) => break,
                // Stop on corruption — the tail may be a partial write.
                Err(TosumError::CorruptRecord { .. }) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

// ── Recovery ─────────────────────────────────────────────────────────────────

/// Apply all committed WAL transactions from `wal_path` into `db_path`.
///
/// For each committed transaction (Begin … Commit pair), every `PageWrite`
/// record is written into the main `.tsm` file at the correct page offset.
/// Uncommitted records (no matching `Commit`) are discarded.
///
/// Returns the LSN of the last checkpoint record seen (0 if none).
pub fn recover(db_path: &Path, wal_path: &Path) -> Result<u64> {
    if !wal_path.exists() {
        return Ok(0);
    }

    let records = WalReader::read_all(wal_path)?;

    // Find all committed txn_ids.
    let committed: std::collections::HashSet<u64> = records.iter()
        .filter_map(|(_, r)| if let WalRecord::Commit { txn_id } = r { Some(*txn_id) } else { None })
        .collect();

    // Track the last active txn_id for Begin records.
    let mut last_checkpoint_lsn = 0u64;

    // Open the main file for writing page frames.
    let mut db_file = open_file_retrying(
        db_path,
        || OpenOptions::new().read(true).write(true).open(db_path),
        "applying WAL recovery to database",
    )?;

    for (lsn, record) in &records {
        match record {
            WalRecord::PageWrite { pgno, frame, .. } => {
                // Only apply if this write's transaction was committed.
                // We need to know which txn this PageWrite belongs to.
                // Simple approach: apply all PageWrites whose txn committed.
                // Since we process in order, every PageWrite before a Commit belongs to that txn.
                // We'll do a two-pass approach handled by the `apply_committed` helper below.
                let _ = (lsn, pgno, frame); // handled in second pass below
            }
            WalRecord::Checkpoint { up_to_lsn } => {
                last_checkpoint_lsn = *up_to_lsn;
            }
            _ => {}
        }
    }

    // Second pass: apply PageWrites from committed transactions.
    apply_committed_writes(&records, &committed, &mut db_file)?;

    db_file.sync_data()?;
    Ok(last_checkpoint_lsn)
}

/// Walk records in order, tracking the current txn_id.
/// Apply PageWrite records that belong to committed transactions.
fn apply_committed_writes(
    records: &[(u64, WalRecord)],
    committed: &std::collections::HashSet<u64>,
    db_file: &mut File,
) -> Result<()> {
    let mut current_txn: Option<u64> = None;

    for (_, record) in records {
        match record {
            WalRecord::Begin { txn_id } => {
                current_txn = Some(*txn_id);
            }
            WalRecord::PageWrite { pgno, frame, .. } => {
                if let Some(tid) = current_txn {
                    if committed.contains(&tid) {
                        let offset = pgno * PAGE_SIZE as u64;
                        db_file.seek(SeekFrom::Start(offset))?;
                        db_file.write_all(frame.as_ref())?;
                    }
                }
            }
            WalRecord::Commit { txn_id } => {
                if current_txn == Some(*txn_id) {
                    current_txn = None;
                }
            }
            WalRecord::Checkpoint { .. } => {}
        }
    }
    Ok(())
}

// ── Checkpoint ───────────────────────────────────────────────────────────────

/// Checkpoint: copy committed WAL frames into the main `.tsm` file, then truncate the WAL.
///
/// Equivalent to a full checkpoint (`CheckpointMode::Truncate` in §7.8).
/// For MVP+4 there is no reader LSN pinning — the WAL is always fully truncated.
pub fn checkpoint(db_path: &Path, wal_path: &Path) -> Result<()> {
    recover(db_path, wal_path)?;
    // Truncate WAL — only reached if recovery succeeded, so safe to overwrite.
    let file = open_file_retrying(
        wal_path,
        || OpenOptions::new().write(true).open(wal_path),
        "truncating WAL during checkpoint",
    )?;
    file.set_len(0)?;
    file.sync_data()?;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Return the path of the WAL sidecar for a given `.tsm` database path.
pub fn wal_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.as_os_str().to_owned();
    p.push(".wal");
    PathBuf::from(p)
}

fn decode_payload(record_type: u8, payload: &[u8]) -> Result<WalRecord> {
    match record_type {
        RT_BEGIN => {
            if payload.len() < 8 {
                return Err(TosumError::CorruptRecord { offset: 0, reason: "Begin payload too short" });
            }
            Ok(WalRecord::Begin { txn_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()) })
        }
        RT_PAGE_WRITE => {
            let expected = 8 + 8 + PAGE_SIZE;
            if payload.len() < expected {
                return Err(TosumError::CorruptRecord { offset: 0, reason: "PageWrite payload too short" });
            }
            let pgno         = u64::from_le_bytes(payload[0..8].try_into().unwrap());
            let page_version = u64::from_le_bytes(payload[8..16].try_into().unwrap());
            let mut frame = Box::new([0u8; PAGE_SIZE]);
            frame.copy_from_slice(&payload[16..16 + PAGE_SIZE]);
            Ok(WalRecord::PageWrite { pgno, page_version, frame })
        }
        RT_COMMIT => {
            if payload.len() < 8 {
                return Err(TosumError::CorruptRecord { offset: 0, reason: "Commit payload too short" });
            }
            Ok(WalRecord::Commit { txn_id: u64::from_le_bytes(payload[0..8].try_into().unwrap()) })
        }
        RT_CHECKPOINT => {
            if payload.len() < 8 {
                return Err(TosumError::CorruptRecord { offset: 0, reason: "Checkpoint payload too short" });
            }
            Ok(WalRecord::Checkpoint { up_to_lsn: u64::from_le_bytes(payload[0..8].try_into().unwrap()) })
        }
        _ => Err(TosumError::CorruptRecord { offset: 0, reason: "unknown WAL record type" }),
    }
}

/// Scan the file to find the highest LSN. Used by `WalWriter::open`.
fn scan_max_lsn(file: &File) -> Result<u64> {
    let mut reader = BufReader::new(file.try_clone()?);
    let mut max_lsn = 0u64;
    loop {
        let mut hdr = [0u8; 13];
        match reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let lsn         = u64::from_le_bytes(hdr[0..8].try_into().unwrap());
        let payload_len = u32::from_le_bytes(hdr[9..13].try_into().unwrap()) as usize;
        max_lsn = max_lsn.max(lsn);
        // Skip payload + crc.
        let skip = payload_len + 4;
        let mut buf = vec![0u8; skip];
        match reader.read_exact(&mut buf) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(max_lsn)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tosumu_wal_{name}_{}.wal",
            std::process::id()
        ))
    }

    fn tmp_db(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tosumu_wal_{name}_{}.tsm",
            std::process::id()
        ))
    }

    #[test]
    fn write_and_read_all_record_types() {
        let p = tmp("all_types");
        let _ = std::fs::remove_file(&p);

        let mut writer = WalWriter::create(&p).unwrap();
        writer.append(&WalRecord::Begin { txn_id: 1 }).unwrap();

        let mut frame = Box::new([0u8; PAGE_SIZE]);
        frame[0] = 0xAB;
        writer.append(&WalRecord::PageWrite { pgno: 5, page_version: 7, frame }).unwrap();
        writer.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
        writer.append(&WalRecord::Checkpoint { up_to_lsn: 3 }).unwrap();
        writer.sync().unwrap();

        let records = WalReader::read_all(&p).unwrap();
        assert_eq!(records.len(), 4);

        assert!(matches!(records[0].1, WalRecord::Begin { txn_id: 1 }));
        if let WalRecord::PageWrite { pgno, page_version, ref frame } = records[1].1 {
            assert_eq!(pgno, 5);
            assert_eq!(page_version, 7);
            assert_eq!(frame[0], 0xAB);
        } else { panic!("expected PageWrite"); }
        assert!(matches!(records[2].1, WalRecord::Commit { txn_id: 1 }));
        assert!(matches!(records[3].1, WalRecord::Checkpoint { up_to_lsn: 3 }));

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn lsn_increments() {
        let p = tmp("lsn");
        let _ = std::fs::remove_file(&p);

        let mut w = WalWriter::create(&p).unwrap();
        let l1 = w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
        let l2 = w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
        assert_eq!(l1, 1);
        assert_eq!(l2, 2);
        w.sync().unwrap();

        let records = WalReader::read_all(&p).unwrap();
        assert_eq!(records[0].0, 1);
        assert_eq!(records[1].0, 2);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn open_continues_lsn() {
        let p = tmp("open_lsn");
        let _ = std::fs::remove_file(&p);

        {
            let mut w = WalWriter::create(&p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
            w.sync().unwrap();
        }

        let mut w2 = WalWriter::open(&p).unwrap();
        assert_eq!(w2.next_lsn(), 3);
        let l3 = w2.append(&WalRecord::Begin { txn_id: 2 }).unwrap();
        assert_eq!(l3, 3);
        w2.sync().unwrap();

        let records = WalReader::read_all(&p).unwrap();
        assert_eq!(records.len(), 3);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn crc_corruption_stops_read() {
        let p = tmp("crc");
        let _ = std::fs::remove_file(&p);

        let mut w = WalWriter::create(&p).unwrap();
        w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
        w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
        w.sync().unwrap();

        // Flip a byte in the second record's payload.
        let mut raw = std::fs::read(&p).unwrap();
        let second_record_start = RECORD_HEADER_SIZE + 8; // first record: 17 hdr + 8 payload
        if raw.len() > second_record_start + 5 {
            raw[second_record_start + 5] ^= 0xFF;
        }
        std::fs::write(&p, &raw).unwrap();

        // read_all stops at the corruption (first record still valid).
        let records = WalReader::read_all(&p).unwrap();
        assert_eq!(records.len(), 1);

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn recover_applies_committed_page_writes() {
        let wal_p = tmp("recover_wal");
        let db_p  = tmp_db("recover_db");
        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);

        // Write a dummy "db" file: 3 pages of zeros.
        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 3]).unwrap();

        // Write a WAL with one committed transaction that writes to page 2.
        let mut w = WalWriter::create(&wal_p).unwrap();
        w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
        let mut frame = Box::new([0u8; PAGE_SIZE]);
        frame[0] = 0xBE;
        frame[1] = 0xEF;
        w.append(&WalRecord::PageWrite { pgno: 2, page_version: 1, frame }).unwrap();
        w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
        w.sync().unwrap();

        recover(&db_p, &wal_p).unwrap();

        // Verify page 2 was updated.
        let raw = std::fs::read(&db_p).unwrap();
        assert_eq!(raw[PAGE_SIZE * 2], 0xBE);
        assert_eq!(raw[PAGE_SIZE * 2 + 1], 0xEF);

        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);
    }

    #[test]
    fn recover_ignores_uncommitted() {
        let wal_p = tmp("uncommitted_wal");
        let db_p  = tmp_db("uncommitted_db");
        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 3]).unwrap();

        // Write WAL with Begin + PageWrite but NO Commit (simulates crash mid-write).
        let mut w = WalWriter::create(&wal_p).unwrap();
        w.append(&WalRecord::Begin { txn_id: 42 }).unwrap();
        let mut frame = Box::new([0u8; PAGE_SIZE]);
        frame[0] = 0xFF;
        w.append(&WalRecord::PageWrite { pgno: 1, page_version: 1, frame }).unwrap();
        w.sync().unwrap();

        recover(&db_p, &wal_p).unwrap();

        // Page 1 must remain zero — the transaction was never committed.
        let raw = std::fs::read(&db_p).unwrap();
        assert_eq!(raw[PAGE_SIZE], 0x00, "uncommitted write must not be applied");

        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);
    }

    #[test]
    fn integration_recover_real_pager_frame() {
        // Proves that a real encrypted page frame written to the WAL is replayed
        // correctly into .tsm on recovery — using actual Pager/BTree output.
        use crate::btree::BTree;

        let db_p  = tmp_db("integ_rec");
        let wal_p = tmp("integ_rec");
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        // 1. Create a real BTree DB and insert a key.
        {
            let mut t = BTree::create(&db_p).unwrap();
            t.put(b"hello", b"world").unwrap();
        }

        // 2. Re-open, read the encrypted frame for page 1 (the first data page).
        let frame = {
            let t = BTree::open(&db_p).unwrap();
            t.pager.read_raw_frame(1).unwrap()
        };
        let page_count = {
            let t = BTree::open(&db_p).unwrap();
            t.page_count()
        };

        // 3. Take a snapshot of .tsm BEFORE the write (all-zeros page 1).
        let snapshot = std::fs::read(&db_p).unwrap();

        // 4. Write a WAL with: Begin → PageWrite(page 1, frame) → Commit.
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 99 }).unwrap();
            let page_version = 1u64;
            w.append(&WalRecord::PageWrite {
                pgno: 1,
                page_version,
                frame: Box::new(frame),
            }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 99 }).unwrap();
            w.sync().unwrap();
        }

        // 5. Reset .tsm to the pre-insert snapshot (simulate crash before .tsm write).
        // We need page 1 to look like zeros; keep page 0 (header) intact.
        let mut reset = snapshot.clone();
        // Zero out page 1.
        if reset.len() >= PAGE_SIZE * 2 {
            for b in &mut reset[PAGE_SIZE..PAGE_SIZE * 2] { *b = 0; }
        } else {
            reset.resize(PAGE_SIZE * (page_count as usize).max(2), 0);
        }
        std::fs::write(&db_p, &reset).unwrap();

        // 6. Recover: replay WAL into .tsm.
        recover(&db_p, &wal_p).unwrap();

        // 7. Open the DB and assert the key is visible.
        let t = BTree::open(&db_p).unwrap();
        assert_eq!(t.get(b"hello").unwrap(), Some(b"world".to_vec()),
            "key must be visible after WAL recovery");

        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }

    #[test]
    fn checkpoint_truncates_wal() {
        let wal_p = tmp("ckpt_wal");
        let db_p  = tmp_db("ckpt_db");
        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE]).unwrap();

        let mut w = WalWriter::create(&wal_p).unwrap();
        w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
        w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
        w.sync().unwrap();

        checkpoint(&db_p, &wal_p).unwrap();

        assert_eq!(std::fs::metadata(&wal_p).unwrap().len(), 0, "WAL must be empty after checkpoint");

        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);
    }

    // ── adversarial / correctness-under-failure tests ────────────────────────

    /// Truncate a WAL record in half — recovery must ignore the partial tail and
    /// not panic, corrupt the database, or misreport an error.
    #[test]
    fn partial_record_at_tail_is_ignored() {
        let wal_p = tmp("partial_wal");
        let db_p  = tmp_db("partial_db");
        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 3]).unwrap();

        // Write txn 1 completely and fsync so we know the exact safe size.
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
            let mut frame = Box::new([0u8; PAGE_SIZE]);
            frame[0] = 0xAA;
            w.append(&WalRecord::PageWrite { pgno: 1, page_version: 1, frame }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
            w.sync().unwrap();
        }
        // Capture the offset where txn 1 ends — everything before this is valid.
        let safe_len = std::fs::metadata(&wal_p).unwrap().len();

        // Append txn 2 (Begin + PageWrite, no Commit — simulates crash before commit).
        {
            let mut w = WalWriter::open(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 2 }).unwrap();
            let mut frame2 = Box::new([0u8; PAGE_SIZE]);
            frame2[0] = 0xBB;
            w.append(&WalRecord::PageWrite { pgno: 2, page_version: 1, frame: frame2 }).unwrap();
            w.sync().unwrap();
        }

        // Truncate to safe_len + 30 bytes — cuts mid-way through the PageWrite record
        // of txn 2, which must be ignored on recovery.
        let partial_len = safe_len + 30;
        {
            let f = std::fs::OpenOptions::new().write(true).open(&wal_p).unwrap();
            f.set_len(partial_len).unwrap();
        }

        recover(&db_p, &wal_p).unwrap();

        let raw = std::fs::read(&db_p).unwrap();
        assert_eq!(raw[PAGE_SIZE],     0xAA, "committed txn 1 page 1 must be applied");
        assert_eq!(raw[PAGE_SIZE * 2], 0x00, "partial txn 2 page 2 must NOT be applied");

        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);
    }

    /// WAL contains two transactions: txn 1 fully committed, txn 2 incomplete
    /// (no Commit record — simulates crash mid-second-transaction).
    /// Only txn 1's writes may appear in the recovered file.
    #[test]
    fn multi_txn_only_committed_applied() {
        let wal_p = tmp("multi_txn_wal");
        let db_p  = tmp_db("multi_txn_db");
        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 4]).unwrap();

        let mut w = WalWriter::create(&wal_p).unwrap();

        // Txn 1: committed — writes page 1.
        w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
        let mut f1 = Box::new([0u8; PAGE_SIZE]);
        f1[0] = 0x11;
        w.append(&WalRecord::PageWrite { pgno: 1, page_version: 1, frame: f1 }).unwrap();
        w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();

        // Txn 2: crash before commit — writes page 2.
        w.append(&WalRecord::Begin { txn_id: 2 }).unwrap();
        let mut f2 = Box::new([0u8; PAGE_SIZE]);
        f2[0] = 0x22;
        w.append(&WalRecord::PageWrite { pgno: 2, page_version: 1, frame: f2 }).unwrap();
        // NO Commit — simulates crash.
        w.sync().unwrap();

        recover(&db_p, &wal_p).unwrap();

        let raw = std::fs::read(&db_p).unwrap();
        assert_eq!(raw[PAGE_SIZE],     0x11, "committed txn 1 must be applied to page 1");
        assert_eq!(raw[PAGE_SIZE * 2], 0x00, "uncommitted txn 2 must NOT be applied to page 2");

        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);
    }

    /// Calling recover() twice on the same WAL + db must produce identical
    /// results. Pages must not accumulate extra writes or change values.
    #[test]
    fn recover_is_idempotent() {
        let wal_p = tmp("idem_wal");
        let db_p  = tmp_db("idem_db");
        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 3]).unwrap();

        let mut w = WalWriter::create(&wal_p).unwrap();
        w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
        let mut frame = Box::new([0u8; PAGE_SIZE]);
        frame[42] = 0xCC;
        w.append(&WalRecord::PageWrite { pgno: 1, page_version: 1, frame }).unwrap();
        w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
        w.sync().unwrap();

        recover(&db_p, &wal_p).unwrap();
        let after_first  = std::fs::read(&db_p).unwrap();

        recover(&db_p, &wal_p).unwrap();
        let after_second = std::fs::read(&db_p).unwrap();

        assert_eq!(after_first, after_second, "recover() must be idempotent");

        let _ = std::fs::remove_file(&wal_p);
        let _ = std::fs::remove_file(&db_p);
    }

    /// Simulate crash *after* WAL Commit is written but before dirty pages are
    /// flushed to .tsm. On reopen, recovery must restore the committed state.
    #[test]
    fn crash_after_commit_before_flush_recovered_on_reopen() {
        use crate::btree::BTree;

        let db_p  = tmp_db("crash_commit");
        // The WAL sidecar that BTree::open will look for is wal_path(&db_p).
        let wal_p = wal_path(&db_p);
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        // 1. Create a DB and insert a key so we have a real encrypted frame.
        {
            let mut t = BTree::create(&db_p).unwrap();
            t.put(b"survive", b"yes").unwrap();
        }

        // 2. Capture the real encrypted frame from .tsm.
        let real_frame = {
            let t = BTree::open(&db_p).unwrap();
            t.pager.read_raw_frame(1).unwrap()
        };

        // 3. Simulate crash: zero out page 1 in .tsm (flush never completed).
        let db_bytes = std::fs::read(&db_p).unwrap();
        let mut reset = db_bytes;
        for b in &mut reset[PAGE_SIZE..PAGE_SIZE * 2] { *b = 0; }
        std::fs::write(&db_p, &reset).unwrap();

        // Remove the WAL that was created by create()/open() so we can write our own.
        let _ = std::fs::remove_file(&wal_p);

        // 4. Write a WAL representing the committed-but-unflushed transaction.
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 7 }).unwrap();
            w.append(&WalRecord::PageWrite {
                pgno: 1,
                page_version: 1,
                frame: Box::new(real_frame),
            }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 7 }).unwrap();
            w.sync().unwrap();
        }

        // 5. Reopen — recovery replays the WAL automatically inside open().
        let t = BTree::open(&db_p).unwrap();
        assert_eq!(
            t.get(b"survive").unwrap(),
            Some(b"yes".to_vec()),
            "key must survive crash-after-commit via WAL recovery",
        );

        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }
    /// Insert enough keys inside a single transaction to force B+ tree root
    /// splits, then simulate a crash by zeroing all data pages in .tsm while
    /// leaving the committed WAL intact. On reopen, WAL recovery must restore
    /// every key exactly.
    ///
    /// This exercises the interaction between:
    ///   - allocate() + init_page() writing new split nodes directly to .tsm
    ///   - with_page_mut() WAL-buffering the final content of each node
    ///
    /// Recovery is sound because every init_page() within a transaction is
    /// always followed by with_page_mut() on the same page, so the WAL holds
    /// the complete final frame for every page touched by the split. Recovery
    /// writes those frames unconditionally, restoring the full committed state.
    #[test]
    fn btree_root_split_survives_wal_recovery() {
        use crate::page_store::PageStore;

        let db_p = tmp_db("split_recovery");
        let wal_p = wal_path(&db_p);
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        // 1. Create DB and insert enough keys via a single transaction to force
        //    at least one root split. 200 inserts reliably produces height >= 2.
        {
            let mut store = PageStore::create(&db_p).unwrap();
            store.transaction(|tx| {
                for i in 0u32..500 {
                    tx.put(
                        format!("key{i:05}").as_bytes(),
                        format!("val{i:05}").as_bytes(),
                    )?;
                }
                Ok(())
            }).unwrap();
            // Confirm the tree actually split before we stress recovery.
            assert!(
                store.stat().tree_height >= 2,
                "expected root split, got height {}; adjust insert count",
                store.stat().tree_height,
            );
        }

        // 2. Simulate crash: zero every data page (1..page_count) in .tsm.
        //    Page 0 (plaintext header) is preserved — it holds page_count and
        //    root_page so the pager can seek to the right offsets during replay.
        //    The WAL sidecar (fsynced inside commit_txn) remains on disk.
        let mut raw = std::fs::read(&db_p).unwrap();
        for b in &mut raw[PAGE_SIZE..] { *b = 0; }
        std::fs::write(&db_p, &raw).unwrap();

        // 3. Reopen — Pager::open detects the WAL sidecar and replays all
        //    committed PageWrite frames before returning.
        let store = PageStore::open(&db_p).unwrap();

        // 4. Every key inserted in the transaction must be visible.
        for i in 0u32..500 {
            let k = format!("key{i:05}");
            let v = format!("val{i:05}");
            assert_eq!(
                store.get(k.as_bytes()).unwrap(),
                Some(v.into_bytes()),
                "key {k} missing after WAL recovery of root-split transaction",
            );
        }

        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }

    // ── Lock-retry / FileBusy tests ───────────────────────────────────────────

    /// After all retry attempts are exhausted with injected lock errors,
    /// `recover()` must return `TosumError::FileBusy` and leave both the
    /// database file and the WAL sidecar byte-for-byte unchanged.
    ///
    /// This verifies the invariant: lock errors are not corruption.
    /// A failed recovery leaves files intact so the next `open()` can retry.
    #[test]
    fn recovery_returns_file_busy_after_exhausted_retries() {
        let _fi_lock = fault_injection::LOCK.lock().unwrap();
        let _cleanup = FaultGuard;

        let db_p  = tmp_db("fi_file_busy");
        let wal_p = tmp("fi_file_busy");
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 2]).unwrap();
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
            let mut frame = Box::new([0u8; PAGE_SIZE]);
            frame[0] = 0xAB;
            w.append(&WalRecord::PageWrite { pgno: 1, page_version: 1, frame }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
            w.sync().unwrap();
        }

        let db_before  = std::fs::read(&db_p).unwrap();
        let wal_before = std::fs::read(&wal_p).unwrap();

        // Exhaust all MAX_RETRIES+1 attempts.
        fault_injection::arm(MAX_RETRIES + 1);

        let err = recover(&db_p, &wal_p).unwrap_err();
        assert!(
            matches!(err, TosumError::FileBusy { .. }),
            "expected FileBusy, got {err:?}",
        );

        // Both files must be byte-for-byte unchanged — no partial application.
        assert_eq!(std::fs::read(&db_p).unwrap(),  db_before,  "database must be unchanged");
        assert_eq!(std::fs::read(&wal_p).unwrap(), wal_before, "WAL must be unchanged");

        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }

    /// When the injected fault count is fewer than MAX_RETRIES, `recover()`
    /// retries successfully and applies the committed writes.
    #[test]
    fn recovery_retries_and_succeeds_after_transient_faults() {
        let _fi_lock = fault_injection::LOCK.lock().unwrap();
        let _cleanup = FaultGuard;

        let db_p  = tmp_db("fi_retry_ok");
        let wal_p = tmp("fi_retry_ok");
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE * 2]).unwrap();
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
            let mut frame = Box::new([0u8; PAGE_SIZE]);
            frame[0] = 0xCC;
            w.append(&WalRecord::PageWrite { pgno: 1, page_version: 1, frame }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
            w.sync().unwrap();
        }

        // Fewer faults than MAX_RETRIES — recovery retries and succeeds.
        fault_injection::arm(MAX_RETRIES - 1);
        recover(&db_p, &wal_p).expect("recovery must succeed after transient faults");

        let raw = std::fs::read(&db_p).unwrap();
        assert_eq!(raw[PAGE_SIZE], 0xCC, "committed write must be applied after retry recovery");

        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }

    /// `TosumError::FileBusy` must carry the path of the locked file and a
    /// non-empty operation description — not silently swallowed as `Corrupt`.
    #[test]
    fn file_busy_error_contains_path_and_operation() {
        let _fi_lock = fault_injection::LOCK.lock().unwrap();
        let _cleanup = FaultGuard;

        let db_p  = tmp_db("fi_path_check");
        let wal_p = tmp("fi_path_check");
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        std::fs::write(&db_p, vec![0u8; PAGE_SIZE]).unwrap();
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin  { txn_id: 1 }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
            w.sync().unwrap();
        }

        fault_injection::arm(MAX_RETRIES + 1);

        // recover() opens the WAL first — FileBusy path must be the WAL path.
        match recover(&db_p, &wal_p).unwrap_err() {
            TosumError::FileBusy { path, operation } => {
                assert_eq!(path, wal_p, "FileBusy must identify the locked file");
                assert!(!operation.is_empty(), "operation string must not be empty");
            }
            other => panic!("expected FileBusy, got {other:?}"),
        }

        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }

    /// Simulate an AV-scanner-style exclusive lock on the WAL sidecar using a
    /// real Windows OS file lock (`FILE_SHARE_NONE`).  The background thread
    /// holds the lock for 25 ms; with MAX_RETRIES × 10 ms = 50 ms total budget,
    /// `Pager::open` should retry and ultimately succeed.
    ///
    /// Run manually: `cargo test -- av_style_lock --ignored`
    #[test]
    #[cfg(windows)]
    #[ignore = "requires Windows file-locking semantics; run manually"]
    fn av_style_lock_during_recovery_retries_then_succeeds() {
        use std::os::windows::fs::OpenOptionsExt;
        use crate::btree::BTree;

        let db_p  = tmp_db("av_lock");
        let wal_p = wal_path(&db_p);
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);

        // Create a real DB so we have a valid header and a real encrypted frame.
        {
            let mut t = BTree::create(&db_p).unwrap();
            t.put(b"av_key", b"av_val").unwrap();
        }
        let real_frame = {
            let t = BTree::open(&db_p).unwrap();
            t.pager.read_raw_frame(1).unwrap()
        };
        // Simulate crash: zero page 1, rebuild WAL manually.
        let mut raw = std::fs::read(&db_p).unwrap();
        for b in &mut raw[PAGE_SIZE..PAGE_SIZE * 2] { *b = 0; }
        std::fs::write(&db_p, &raw).unwrap();
        let _ = std::fs::remove_file(&wal_p);
        {
            let mut w = WalWriter::create(&wal_p).unwrap();
            w.append(&WalRecord::Begin { txn_id: 1 }).unwrap();
            w.append(&WalRecord::PageWrite {
                pgno: 1, page_version: 1, frame: Box::new(real_frame),
            }).unwrap();
            w.append(&WalRecord::Commit { txn_id: 1 }).unwrap();
            w.sync().unwrap();
        }

        // Hold an exclusive OS lock on the WAL for 25 ms from a background thread.
        let wal_clone = wal_p.clone();
        let lock_thread = std::thread::spawn(move || {
            let _locked = OpenOptions::new()
                .read(true)
                .share_mode(0) // FILE_SHARE_NONE — exclusive
                .open(&wal_clone)
                .expect("test setup: failed to acquire exclusive OS lock on WAL");
            std::thread::sleep(std::time::Duration::from_millis(25));
            // Lock released on drop.
        });

        // Give the lock thread a moment to acquire before recovery starts.
        std::thread::sleep(std::time::Duration::from_millis(2));

        // Pager::open triggers WAL recovery with retry — must survive the lock.
        let t = BTree::open(&db_p).unwrap();
        assert_eq!(
            t.get(b"av_key").unwrap(),
            Some(b"av_val".to_vec()),
            "key must be visible after AV-style transient OS lock + retry recovery",
        );

        lock_thread.join().unwrap();
        let _ = std::fs::remove_file(&db_p);
        let _ = std::fs::remove_file(&wal_p);
    }
}
