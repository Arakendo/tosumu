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
        let file = OpenOptions::new().read(true).open(path)?;
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
    let mut db_file = OpenOptions::new().read(true).write(true).open(db_path)?;

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
    // Truncate WAL.
    let file = OpenOptions::new().write(true).open(wal_path)?;
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
}
