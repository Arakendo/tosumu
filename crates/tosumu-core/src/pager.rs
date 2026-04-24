// Pager — page-level I/O with AEAD encryption/decryption.
//
// Source of truth: DESIGN.md §6.
//
// The pager owns the file handle and the page_key. It exposes a
// closure-based API (§28.9): the caller never holds a reference to
// page bytes beyond the closure call.
//
// For MVP+1 there is no in-memory cache (every read hits the file).
// Cache is a Stage 2 concern.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::crypto::{decrypt_page, encrypt_page, generate_dek, derive_subkeys};
use crate::error::{Result, TosumError};
use crate::format::*;
use crate::wal::{WalRecord, WalWriter, wal_path};

/// The pager. Holds an open file and the derived page key.
pub struct Pager {
    file: File,
    page_key: [u8; 32],
    // Cached from the file header. Written back on allocate / flush_header.
    page_count: u64,
    freelist_head: u64,
    /// B+ tree root page number (0 = not yet set). Persisted at OFF_ROOT_PAGE.
    root_page: u64,
    // ── WAL / transaction state ───────────────────────────────────────────
    /// WAL writer, open for the lifetime of this Pager.
    wal: Option<WalWriter>,
    /// Whether a transaction is currently active.
    txn_active: bool,
    /// txn_id of the current open transaction.
    txn_id: u64,
    /// Counter for generating unique txn_ids.
    next_txn_id: u64,
    /// Dirty page frames buffered during the current transaction.
    /// Entries are (pgno, encrypted_frame). Latest write wins for the same pgno.
    dirty_pages: Vec<(u64, Box<[u8; PAGE_SIZE]>)>,
}

impl Pager {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Create a new database file at `path`.
    ///
    /// Generates a DEK, writes the file header (page 0) with a Sentinel
    /// keyslot, and returns a ready-to-use Pager.
    pub fn create(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        let dek = generate_dek();
        let (page_key, _header_mac_key, _audit_key) = derive_subkeys(&dek);

        // Build page 0 (plaintext file header + Sentinel keyslot).
        let mut page0 = [0u8; PAGE_SIZE];
        write_file_header(&mut page0, &dek);

        file.write_all(&page0)?;
        file.sync_data()?;

        // Open/create WAL sidecar.
        let wal = WalWriter::open_or_create(&wal_path(path)).ok();

        Ok(Pager {
            file,
            page_key,
            page_count: 1,
            freelist_head: 0,
            root_page: 0,
            wal,
            txn_active: false,
            txn_id: 0,
            next_txn_id: 1,
            dirty_pages: Vec::new(),
        })
    }

    /// Open an existing database file at `path`.
    ///
    /// Reads the Sentinel keyslot to recover the DEK, verifies the header.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let mut page0 = [0u8; PAGE_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut page0)?;

        // Validate magic.
        if !check_magic(&page0) {
            return Err(TosumError::NotATosumFile);
        }

        // Validate format version.
        let fv = read_u16(&page0, OFF_FORMAT_VERSION);
        if fv > FORMAT_VERSION {
            return Err(TosumError::NewerFormat { found: fv, supported_max: FORMAT_VERSION });
        }

        // Validate page size.
        let ps = read_u16(&page0, OFF_PAGE_SIZE);
        if ps as usize != PAGE_SIZE {
            return Err(TosumError::PageSizeMismatch { found: ps, expected: PAGE_SIZE as u16 });
        }

        // Read DEK from Sentinel keyslot.
        let ks_start = KEYSLOT_REGION_OFFSET;
        let ks_kind = page0[ks_start + KS_OFF_KIND];
        if ks_kind != KEYSLOT_KIND_SENTINEL {
            return Err(TosumError::NotATosumFile);
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(
            &page0[ks_start + KS_OFF_WRAPPED_DEK..ks_start + KS_OFF_WRAPPED_DEK + 32],
        );

        let (page_key, _header_mac_key, _audit_key) = derive_subkeys(&dek);

        let page_count = read_u64(&page0, OFF_PAGE_COUNT);
        let freelist_head = read_u64(&page0, OFF_FREELIST_HEAD);
        let root_page = read_u64(&page0, OFF_ROOT_PAGE);

        // Recover from WAL before returning to caller.
        let wp = wal_path(path);
        if wp.exists() {
            crate::wal::recover(path, &wp)?;
        }

        // Open/create WAL sidecar for future writes.
        let wal = WalWriter::open_or_create(&wp).ok();

        Ok(Pager {
            file,
            page_key,
            page_count,
            freelist_head,
            root_page,
            wal,
            txn_active: false,
            txn_id: 0,
            next_txn_id: 1,
            dirty_pages: Vec::new(),
        })
    }

    // ── Page access ──────────────────────────────────────────────────────────

    /// Decrypt page `pgno` and return `(plaintext, page_version)`.
    ///
    /// Prefer `with_page` for normal reads; this is for inspection tooling that
    /// also needs the page_version field.
    pub fn read_page(&self, pgno: u64) -> Result<([u8; PAGE_PLAINTEXT_SIZE], u64)> {
        assert!(pgno != 0, "pgno 0 is the file header, not an encrypted page");
        let frame = self.read_frame(pgno)?;
        decrypt_page(&self.page_key, pgno, &frame)
    }

    /// Read-only access to page `pgno`. Closure receives the decrypted plaintext.
    pub fn with_page<F, T>(&self, pgno: u64, f: F) -> Result<T>
    where
        F: FnOnce(&[u8; PAGE_PLAINTEXT_SIZE]) -> Result<T>,
    {
        assert!(pgno != 0, "pgno 0 is the file header, not an encrypted page");
        let frame = self.read_frame(pgno)?;
        let (plaintext, _version) = decrypt_page(&self.page_key, pgno, &frame)?;
        f(&plaintext)
    }

    /// Read-write access to page `pgno`. Closure receives a mutable plaintext
    /// buffer; on return the page is re-encrypted with a new nonce and
    /// incremented page_version.
    ///
    /// - Outside a transaction: writes directly to `.tsm` (auto-commit, for
    ///   internal ops like `init_page` and header flushes).
    /// - Inside a transaction (`begin_txn` called): buffers the encrypted frame
    ///   in memory and appends a `PageWrite` to the WAL; `.tsm` is not touched
    ///   until `commit_txn` flushes the dirty pages.
    pub fn with_page_mut<F>(&mut self, pgno: u64, f: F) -> Result<()>
    where
        F: FnOnce(&mut [u8; PAGE_PLAINTEXT_SIZE]) -> Result<()>,
    {
        assert!(pgno != 0, "pgno 0 is the file header, not an encrypted page");

        // For reads: check dirty buffer first (read-your-own-writes).
        let frame = if let Some(pos) = self.dirty_pages.iter().rposition(|(p, _)| *p == pgno) {
            *self.dirty_pages[pos].1.clone()
        } else {
            self.read_frame(pgno)?
        };

        let (mut plaintext, version) = decrypt_page(&self.page_key, pgno, &frame)?;

        f(&mut plaintext)?;

        let new_frame = encrypt_page(&self.page_key, pgno, version + 1, &plaintext)?;

        if self.txn_active {
            // WAL path: buffer the frame, append PageWrite.
            let txn_id = self.txn_id;
            if let Some(ref mut wal) = self.wal {
                wal.append(&WalRecord::PageWrite {
                    pgno,
                    page_version: version + 1,
                    frame: Box::new(new_frame),
                })?;
            }
            // Update dirty buffer (replace existing entry for same pgno).
            if let Some(pos) = self.dirty_pages.iter().position(|(p, _)| *p == pgno) {
                self.dirty_pages[pos].1 = Box::new(new_frame);
            } else {
                self.dirty_pages.push((pgno, Box::new(new_frame)));
            }
            let _ = txn_id; // used via self.txn_id above
        } else {
            // Auto-commit path: write directly to .tsm.
            self.write_frame(pgno, &new_frame)?;
        }
        Ok(())
    }

    /// Allocate a new page. Returns its page number.
    ///
    /// For MVP+1 the freelist is not yet checked; pages grow monotonically.
    pub fn allocate(&mut self) -> Result<u64> {
        let pgno = self.page_count;
        self.page_count += 1;
        self.flush_header()?;
        Ok(pgno)
    }

    /// Initialize a newly allocated page and write it to disk.
    pub fn init_page(&mut self, pgno: u64, page_type: u8) -> Result<()> {
        assert!(pgno != 0);
        let mut plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        // Set page header: type, free_start, free_end.
        plaintext[0] = page_type;
        // flags=0, slot_count=0 (already 0)
        write_u16_buf(&mut plaintext, 2, 0u16);               // slot_count
        write_u16_buf(&mut plaintext, 4, PAGE_HEADER_SIZE as u16); // free_start
        write_u16_buf(&mut plaintext, 6, PAGE_PLAINTEXT_SIZE as u16); // free_end
        // fragmented_bytes=0, reserved=0, next_leaf=0 — already zero
        let frame = encrypt_page(&self.page_key, pgno, 1, &plaintext)?;
        self.write_frame(pgno, &frame)?;
        Ok(())
    }

    pub fn page_count(&self) -> u64 {
        self.page_count
    }

    // ── Transaction API ───────────────────────────────────────────────────────

    /// Begin a write transaction. Must not be called while one is already open.
    pub fn begin_txn(&mut self) -> Result<()> {
        assert!(!self.txn_active, "nested transactions are not supported");
        self.txn_id = self.next_txn_id;
        self.next_txn_id += 1;
        self.txn_active = true;
        if let Some(ref mut wal) = self.wal {
            wal.append(&WalRecord::Begin { txn_id: self.txn_id })?;
        }
        Ok(())
    }

    /// Commit the current transaction: write Commit record, fsync WAL, flush dirty pages to .tsm.
    pub fn commit_txn(&mut self) -> Result<()> {
        assert!(self.txn_active, "commit_txn called with no active transaction");
        if let Some(ref mut wal) = self.wal {
            wal.append(&WalRecord::Commit { txn_id: self.txn_id })?;
            wal.sync()?;
        }
        // Flush dirty pages to .tsm.
        let pages: Vec<(u64, Box<[u8; PAGE_SIZE]>)> = self.dirty_pages.drain(..).collect();
        for (pgno, frame) in pages {
            self.write_frame(pgno, &frame)?;
        }
        self.txn_active = false;
        Ok(())
    }

    /// Roll back the current transaction: discard dirty pages (no commit in WAL).
    pub fn rollback_txn(&mut self) {
        self.dirty_pages.clear();
        self.txn_active = false;
    }

    /// Return the B+ tree root page number (0 if not yet set).
    pub fn root_page(&self) -> u64 {
        self.root_page
    }

    /// Persist a new B+ tree root page number.
    pub fn set_root_page(&mut self, pgno: u64) -> Result<()> {
        self.root_page = pgno;
        self.flush_header()
    }

    // ── Header flush ─────────────────────────────────────────────────────────

    /// Write updated page_count and freelist_head back to page 0.
    ///
    /// NOTE: The header_mac is NOT updated in MVP+1. See DESIGN.md §8.5.
    /// TODO Stage 4: compute and verify HMAC-SHA256 over header + keyslot region.
    pub fn flush_header(&mut self) -> Result<()> {
        // Read current page 0, update the two mutable fields, write back.
        let mut page0 = [0u8; PAGE_SIZE];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut page0)?;

        write_u64(&mut page0, OFF_PAGE_COUNT, self.page_count);
        write_u64(&mut page0, OFF_FREELIST_HEAD, self.freelist_head);
        write_u64(&mut page0, OFF_ROOT_PAGE, self.root_page);
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&page0)?;
        self.file.sync_data()?;
        Ok(())
    }

    // ── private ──────────────────────────────────────────────────────────────

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_raw_frame(&self, pgno: u64) -> Result<[u8; PAGE_SIZE]> {
        self.read_frame(pgno)
    }

    fn read_frame(&self, pgno: u64) -> Result<[u8; PAGE_SIZE]> {
        let mut frame = [0u8; PAGE_SIZE];
        let offset = pgno * PAGE_SIZE as u64;
        // Need interior mutability to seek — cast the shared ref to mut via a re-open
        // workaround: File::seek requires &mut self, so we use try_clone.
        // This is acceptable for MVP+1 (no cache, rare).
        let mut f = self.file.try_clone()?;
        f.seek(SeekFrom::Start(offset))?;
        f.read_exact(&mut frame)?;
        Ok(frame)
    }

    fn write_frame(&mut self, pgno: u64, frame: &[u8; PAGE_SIZE]) -> Result<()> {
        let offset = pgno * PAGE_SIZE as u64;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(frame)?;
        self.file.sync_data()?;
        Ok(())
    }
}

// ── Page header helpers ───────────────────────────────────────────────────────

fn write_u16_buf(buf: &mut [u8], offset: usize, v: u16) {
    buf[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
}

// ── File header construction ──────────────────────────────────────────────────

fn write_file_header(page0: &mut [u8; PAGE_SIZE], dek: &[u8; 32]) {
    // Magic (8 bytes) + 8 bytes padding.
    page0[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(MAGIC.as_slice());
    write_u16(page0, OFF_FORMAT_VERSION, FORMAT_VERSION);
    write_u16(page0, OFF_PAGE_SIZE, PAGE_SIZE as u16);
    write_u16(page0, OFF_MIN_READER_VERSION, MIN_READER_VERSION);
    write_u16(page0, OFF_FLAGS, 0x0003u16); // bit0=reserved(1), bit1=has_keyslots
    write_u64(page0, OFF_PAGE_COUNT, 1);    // just page 0 for now
    write_u64(page0, OFF_FREELIST_HEAD, 0);
    write_u64(page0, OFF_ROOT_PAGE, 0);
    write_u64(page0, OFF_WAL_CHECKPOINT_LSN, 0);
    write_u64(page0, OFF_DEK_ID, 1);
    // dek_kat: leave as zero for MVP+1 (TODO Stage 4)
    write_u16(page0, OFF_KEYSLOT_COUNT, 1);
    write_u16(page0, OFF_KEYSLOT_REGION_PAGES, 0); // keyslots embedded in page 0
    // header_mac: leave as zero for MVP+1 (TODO Stage 4)

    // Sentinel keyslot at offset KEYSLOT_REGION_OFFSET.
    let ks = KEYSLOT_REGION_OFFSET;
    page0[ks + KS_OFF_KIND] = KEYSLOT_KIND_SENTINEL;
    page0[ks + KS_OFF_VERSION] = 1;
    // Store DEK plaintext in wrapped_dek[0..32] (Sentinel = no encryption).
    // See DESIGN.md §8.11: Sentinel provides authentication, not confidentiality.
    page0[ks + KS_OFF_WRAPPED_DEK..ks + KS_OFF_WRAPPED_DEK + 32].copy_from_slice(dek);
}
