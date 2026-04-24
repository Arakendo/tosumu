// Inspection and verification utilities for tosumu database files.
//
// Used by: `tosumu dump`, `tosumu hex`, `tosumu verify` CLI commands.
// Source of truth: DESIGN.md §12.1 (MVP +2).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Result, TosumError};
use crate::format::*;
use crate::pager::Pager;

// ── File header ───────────────────────────────────────────────────────────────

/// Parsed contents of the page-0 file header.
///
/// Does not require decryption — only validates the magic bytes.
pub struct HeaderInfo {
    pub format_version: u16,
    pub page_size: u16,
    pub min_reader_version: u16,
    pub flags: u16,
    pub page_count: u64,
    pub freelist_head: u64,
    pub root_page: u64,
    pub wal_checkpoint_lsn: u64,
    pub dek_id: u64,
    pub keyslot_count: u16,
    pub keyslot_region_pages: u16,
    /// Kind byte of the first keyslot.
    pub ks0_kind: u8,
    /// Version byte of the first keyslot.
    pub ks0_version: u8,
}

/// Read and parse the file header from `path`.
///
/// Only validates the magic bytes; does not authenticate or decrypt anything.
pub fn read_header_info(path: &Path) -> Result<HeaderInfo> {
    let mut file = File::open(path)?;
    let mut page0 = [0u8; PAGE_SIZE];
    file.read_exact(&mut page0)?;

    if !check_magic(&page0) {
        return Err(TosumError::NotATosumFile);
    }

    let ks = KEYSLOT_REGION_OFFSET;
    Ok(HeaderInfo {
        format_version:       read_u16(&page0, OFF_FORMAT_VERSION),
        page_size:            read_u16(&page0, OFF_PAGE_SIZE),
        min_reader_version:   read_u16(&page0, OFF_MIN_READER_VERSION),
        flags:                read_u16(&page0, OFF_FLAGS),
        page_count:           read_u64(&page0, OFF_PAGE_COUNT),
        freelist_head:        read_u64(&page0, OFF_FREELIST_HEAD),
        root_page:            read_u64(&page0, OFF_ROOT_PAGE),
        wal_checkpoint_lsn:   read_u64(&page0, OFF_WAL_CHECKPOINT_LSN),
        dek_id:               read_u64(&page0, OFF_DEK_ID),
        keyslot_count:        read_u16(&page0, OFF_KEYSLOT_COUNT),
        keyslot_region_pages: read_u16(&page0, OFF_KEYSLOT_REGION_PAGES),
        ks0_kind:             page0[ks + KS_OFF_KIND],
        ks0_version:          page0[ks + KS_OFF_VERSION],
    })
}

// ── Raw frame ─────────────────────────────────────────────────────────────────

/// Read the raw (encrypted) 4096-byte frame for page `pgno`.
///
/// Page 0 is the plaintext file header; pages ≥ 1 are encrypted frames.
/// Does not decrypt or authenticate.
pub fn read_raw_frame(path: &Path, pgno: u64) -> Result<[u8; PAGE_SIZE]> {
    let offset = pgno
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(TosumError::InvalidArgument("page number overflow"))?;
    let mut file = File::open(path)?;
    let mut frame = [0u8; PAGE_SIZE];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut frame)?;
    Ok(frame)
}

// ── Page inspection ───────────────────────────────────────────────────────────

/// A single decoded record entry from a slotted leaf page.
pub enum RecordInfo {
    Live { key: Vec<u8>, value: Vec<u8> },
    Tombstone { key: Vec<u8> },
    /// Could not be decoded — carries slot index and raw record-type byte.
    Unknown { slot: u16, record_type: u8 },
}

/// Decoded summary of an encrypted data page.
pub struct PageSummary {
    pub pgno: u64,
    pub page_version: u64,
    pub page_type: u8,
    pub slot_count: u16,
    pub free_start: u16,
    pub free_end: u16,
    pub records: Vec<RecordInfo>,
}

/// Decrypt and parse page `pgno`.
///
/// Returns `Err(InvalidArgument)` when `pgno` is 0 or out of range.
/// Opens the pager internally (read-write, matching `Pager::open`).
pub fn inspect_page(path: &Path, pgno: u64) -> Result<PageSummary> {
    if pgno == 0 {
        return Err(TosumError::InvalidArgument(
            "page 0 is the file header; use `dump` without --page to view it",
        ));
    }

    let pager = Pager::open(path)?;
    if pgno >= pager.page_count() {
        return Err(TosumError::InvalidArgument("page number out of range"));
    }

    let (plaintext, page_version) = pager.read_page(pgno)?;
    let page_type  = plaintext[0];
    let slot_count = read_u16(&plaintext, 2);
    let free_start = read_u16(&plaintext, 4);
    let free_end   = read_u16(&plaintext, 6);

    let mut records = Vec::with_capacity(slot_count as usize);
    for i in 0..slot_count as usize {
        let slot_pos = PAGE_HEADER_SIZE + i * SLOT_SIZE;
        if slot_pos + SLOT_SIZE > PAGE_PLAINTEXT_SIZE {
            records.push(RecordInfo::Unknown { slot: i as u16, record_type: 0 });
            break;
        }
        let offset = read_u16(&plaintext, slot_pos) as usize;
        let length = read_u16(&plaintext, slot_pos + 2) as usize;

        if length == 0 || offset + length > PAGE_PLAINTEXT_SIZE {
            records.push(RecordInfo::Unknown { slot: i as u16, record_type: 0 });
            continue;
        }

        let record = &plaintext[offset..offset + length];
        match record[0] {
            RECORD_LIVE if record.len() >= 5 => {
                let key_len = u16::from_le_bytes([record[1], record[2]]) as usize;
                let val_len = u16::from_le_bytes([record[3], record[4]]) as usize;
                if 5 + key_len + val_len <= record.len() {
                    records.push(RecordInfo::Live {
                        key:   record[5..5 + key_len].to_vec(),
                        value: record[5 + key_len..5 + key_len + val_len].to_vec(),
                    });
                } else {
                    records.push(RecordInfo::Unknown {
                        slot: i as u16,
                        record_type: RECORD_LIVE,
                    });
                }
            }
            RECORD_TOMBSTONE if record.len() >= 3 => {
                let key_len = u16::from_le_bytes([record[1], record[2]]) as usize;
                if 3 + key_len <= record.len() {
                    records.push(RecordInfo::Tombstone {
                        key: record[3..3 + key_len].to_vec(),
                    });
                } else {
                    records.push(RecordInfo::Unknown {
                        slot: i as u16,
                        record_type: RECORD_TOMBSTONE,
                    });
                }
            }
            rt => records.push(RecordInfo::Unknown { slot: i as u16, record_type: rt }),
        }
    }

    Ok(PageSummary {
        pgno,
        page_version,
        page_type,
        slot_count,
        free_start,
        free_end,
        records,
    })
}

// ── Verification ─────────────────────────────────────────────────────────────

/// A single integrity problem found during `verify_file`.
pub struct VerifyIssue {
    pub pgno: u64,
    pub description: String,
}

/// Summary returned by `verify_file`.
pub struct VerifyReport {
    pub pages_checked: u64,
    pub pages_ok: u64,
    pub issues: Vec<VerifyIssue>,
}

/// Open `path` and authenticate every data page (1..page_count).
///
/// Does not short-circuit on first error — all pages are checked and all
/// failures are collected. Returns `Err` only for fatal header-level errors
/// (bad magic, I/O failure reading page 0, etc.).
pub fn verify_file(path: &Path) -> Result<VerifyReport> {
    let pager = Pager::open(path)?;
    let page_count = pager.page_count();
    let pages_to_check = page_count.saturating_sub(1); // skip page 0

    let mut pages_ok = 0u64;
    let mut issues   = Vec::new();

    for pgno in 1..page_count {
        match pager.with_page(pgno, |_| Ok(())) {
            Ok(()) => pages_ok += 1,
            Err(TosumError::AuthFailed { .. }) => issues.push(VerifyIssue {
                pgno,
                description: "authentication tag mismatch (page corrupted or tampered)"
                    .to_owned(),
            }),
            Err(TosumError::Corrupt { reason, .. }) => issues.push(VerifyIssue {
                pgno,
                description: format!("corrupt: {reason}"),
            }),
            Err(e) => issues.push(VerifyIssue {
                pgno,
                description: format!("I/O error: {e}"),
            }),
        }
    }

    Ok(VerifyReport { pages_checked: pages_to_check, pages_ok, issues })
}
