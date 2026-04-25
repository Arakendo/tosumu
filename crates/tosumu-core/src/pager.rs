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

use crate::crypto::{decrypt_page, encrypt_page, generate_dek, derive_subkeys,
    derive_passphrase_kek, pack_kdf_params, wrap_dek, unwrap_dek, compute_kcv, verify_kcv,
    compute_header_mac, verify_header_mac, generate_recovery_secret, derive_recovery_kek,
    ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST};
use crate::error::{Result, TosumError};
use crate::format::*;
use crate::wal::{WalRecord, WalWriter, wal_path};

/// The pager. Holds an open file and the derived page key.
pub struct Pager {
    file: File,
    page_key: [u8; 32],
    /// For passphrase-protected databases: the HMAC key used to MAC page0.
    /// None for Sentinel databases (no header MAC).
    header_mac_key: Option<[u8; 32]>,
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

        let dek = generate_dek()?;
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
            header_mac_key: None,
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

        let page0 = read_page0(&mut file)?;
        validate_header(&page0)?;

        // Read DEK from keyslot.  Sentinel = plaintext DEK; Passphrase/Recovery = return WrongKey.
        let ks_start = KEYSLOT_REGION_OFFSET;
        let ks_kind = page0[ks_start + KS_OFF_KIND];
        let dek = match ks_kind {
            KEYSLOT_KIND_SENTINEL => {
                let mut dek = [0u8; 32];
                dek.copy_from_slice(
                    &page0[ks_start + KS_OFF_WRAPPED_DEK..ks_start + KS_OFF_WRAPPED_DEK + 32],
                );
                dek
            }
            KEYSLOT_KIND_PASSPHRASE | KEYSLOT_KIND_RECOVERY_KEY => {
                // Caller must use open_with_passphrase() or open_with_recovery_key().
                return Err(TosumError::WrongKey);
            }
            _ => return Err(TosumError::NotATosumFile),
        };

        let (page_key, _header_mac_key, _audit_key) = derive_subkeys(&dek);
        finish_open(file, page_key, None, &page0, path)
    }

    /// Create a new passphrase-protected database file at `path`.
    ///
    /// Generates a DEK, wraps it with Argon2id-derived KEK, stores the wrapped DEK
    /// in keyslot 0 (Passphrase kind), and writes a header MAC over the full keyslot region.
    /// The keyslot region is pre-allocated to MAX_KEYSLOTS so future protectors can be added
    /// without a page rewrite.
    pub fn create_encrypted(path: &Path, passphrase: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        let dek = generate_dek()?;
        let (page_key, header_mac_key, _audit_key) = derive_subkeys(&dek);

        // Random 16-byte salt for this slot.
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| TosumError::RngFailed)?;

        // Derive KEK from passphrase.
        let kdf_params = pack_kdf_params(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST);
        let kek = derive_passphrase_kek(passphrase, &salt, &kdf_params)?;

        // Generate a unique per-database DEK_ID so that a full-slot splice from a
        // different database fails AEAD unwrap even when the same passphrase is used.
        let mut dek_id_buf = [0u8; 8];
        getrandom::getrandom(&mut dek_id_buf).map_err(|_| TosumError::RngFailed)?;
        let dek_id = u64::from_le_bytes(dek_id_buf) | 1; // ensure non-zero

        // Wrap the DEK.
        let (wrap_nonce, wrapped_dek) = wrap_dek(&kek, &dek, 0, dek_id, KEYSLOT_KIND_PASSPHRASE)?;

        // Compute KCV.
        let kcv = compute_kcv(&kek);

        // Build page 0.
        let mut page0 = [0u8; PAGE_SIZE];
        write_file_header(&mut page0, &dek); // writes sentinel slot 0; we overwrite below
        write_u64(&mut page0, OFF_DEK_ID, dek_id); // overwrite hardcoded 1 with per-DB random id
        // Set keyslot count to MAX_KEYSLOTS so the full region is MAC'd.
        write_u16(&mut page0, OFF_KEYSLOT_COUNT, MAX_KEYSLOTS as u16);

        // Overwrite slot 0 with passphrase data.
        write_keyslot(&mut page0, 0, KEYSLOT_KIND_PASSPHRASE, dek_id, &salt, &kdf_params,
                      &wrap_nonce, &wrapped_dek, &kcv);

        // Zero slots 1..MAX_KEYSLOTS (they're already zero from the array init, just ensure).
        for i in 1..MAX_KEYSLOTS {
            let ks = KEYSLOT_REGION_OFFSET + i * KEYSLOT_SIZE;
            page0[ks..ks + KEYSLOT_SIZE].fill(0);
        }

        // Compute and store the header MAC (covers header plain region + full keyslot region).
        let mac = compute_header_mac(&header_mac_key, &page0, MAX_KEYSLOTS);
        page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);

        file.write_all(&page0)?;
        file.sync_data()?;

        // Open/create WAL sidecar.
        let wal = WalWriter::open_or_create(&wal_path(path)).ok();

        Ok(Pager {
            file,
            page_key,
            header_mac_key: Some(header_mac_key),
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

    /// Open a passphrase-protected database file.
    ///
    /// Scans all keyslots, trying the passphrase against every Passphrase slot.
    /// If any slot accepts, the DEK is unwrapped and the header MAC is verified.
    /// Also accepts Sentinel databases (passphrase is ignored).
    pub fn open_with_passphrase(path: &Path, passphrase: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let mut page0 = [0u8; PAGE_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut page0)?;

        validate_header(&page0)?;

        let dek_id = read_u64(&page0, OFF_DEK_ID);
        let keyslot_count = read_u16(&page0, OFF_KEYSLOT_COUNT) as usize;
        let keyslot_count = keyslot_count.max(1).min(MAX_KEYSLOTS);

        // Try to unlock: scan all slots.
        let (dek, is_encrypted) = try_unlock_passphrase(&page0, passphrase, dek_id, keyslot_count)?;

        let (page_key, derived_hmk, _) = derive_subkeys(&dek);
        let header_mac_key = if is_encrypted {
            // Verify header MAC before handing out the pager.
            let stored_mac: [u8; 32] = page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].try_into().unwrap();
            verify_header_mac(&derived_hmk, &page0, keyslot_count, &stored_mac)?;
            Some(derived_hmk)
        } else {
            None
        };

        finish_open(file, page_key, header_mac_key, &page0, path)
    }

    /// Open a database using a recovery key string.
    ///
    /// Scans all keyslots, trying the recovery key against every RecoveryKey slot.
    pub fn open_with_recovery_key(path: &Path, recovery_str: &str) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;

        let mut page0 = [0u8; PAGE_SIZE];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut page0)?;

        validate_header(&page0)?;

        let dek_id = read_u64(&page0, OFF_DEK_ID);
        let keyslot_count = (read_u16(&page0, OFF_KEYSLOT_COUNT) as usize).max(1).min(MAX_KEYSLOTS);

        let kek = derive_recovery_kek(recovery_str)?;
        let dek = try_unlock_with_kek(&page0, &kek, dek_id, keyslot_count, KEYSLOT_KIND_RECOVERY_KEY)?;

        let (page_key, derived_hmk, _) = derive_subkeys(&dek);
        let stored_mac: [u8; 32] = page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].try_into().unwrap();
        verify_header_mac(&derived_hmk, &page0, keyslot_count, &stored_mac)?;

        finish_open(file, page_key, Some(derived_hmk), &page0, path)
    }

    // ── Key management ───────────────────────────────────────────────────────

    /// Add a passphrase protector to an existing database.
    ///
    /// `unlock` is called first to open the database (it must already be unlockable).
    /// Then a new Passphrase keyslot is written in the first empty slot.
    /// Returns the slot index used.
    pub fn add_passphrase_protector(path: &Path, unlock_passphrase: &str, new_passphrase: &str) -> Result<u16> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut page0 = read_page0(&mut file)?;
        validate_header(&page0)?;

        let dek_id = read_u64(&page0, OFF_DEK_ID);
        let keyslot_count = (read_u16(&page0, OFF_KEYSLOT_COUNT) as usize).max(1).min(MAX_KEYSLOTS);
        let (dek, _) = try_unlock_passphrase(&page0, unlock_passphrase, dek_id, keyslot_count)?;
        let (_, hmk, _) = derive_subkeys(&dek);

        let slot_idx = find_empty_slot(&page0, keyslot_count)?;

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).map_err(|_| TosumError::RngFailed)?;
        let kdf_params = pack_kdf_params(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST);
        let kek = derive_passphrase_kek(new_passphrase, &salt, &kdf_params)?;
        let (wrap_nonce, wrapped_dek) = wrap_dek(&kek, &dek, slot_idx, dek_id, KEYSLOT_KIND_PASSPHRASE)?;
        let kcv = compute_kcv(&kek);

        write_keyslot(&mut page0, slot_idx as usize, KEYSLOT_KIND_PASSPHRASE, dek_id,
                      &salt, &kdf_params, &wrap_nonce, &wrapped_dek, &kcv);

        let mac = compute_header_mac(&hmk, &page0, keyslot_count);
        page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);

        write_page0(&mut file, &page0)?;
        Ok(slot_idx)
    }

    /// Add a recovery-key protector to an existing database.
    ///
    /// Returns the one-time recovery string that must be shown to the user.
    pub fn add_recovery_key_protector(path: &Path, unlock_passphrase: &str) -> Result<String> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut page0 = read_page0(&mut file)?;
        validate_header(&page0)?;

        let dek_id = read_u64(&page0, OFF_DEK_ID);
        let keyslot_count = (read_u16(&page0, OFF_KEYSLOT_COUNT) as usize).max(1).min(MAX_KEYSLOTS);
        let (dek, _) = try_unlock_passphrase(&page0, unlock_passphrase, dek_id, keyslot_count)?;
        let (_, hmk, _) = derive_subkeys(&dek);

        let slot_idx = find_empty_slot(&page0, keyslot_count)?;

        let recovery_str = generate_recovery_secret();
        let kek = derive_recovery_kek(&recovery_str)?;
        let (wrap_nonce, wrapped_dek) = wrap_dek(&kek, &dek, slot_idx, dek_id, KEYSLOT_KIND_RECOVERY_KEY)?;
        let kcv = compute_kcv(&kek);

        // Recovery key has no KDF params (HKDF, not Argon2id); salt field is zeroed.
        let zero_salt = [0u8; 16];
        let zero_kdf_params = [0u8; 32];
        write_keyslot(&mut page0, slot_idx as usize, KEYSLOT_KIND_RECOVERY_KEY, dek_id,
                      &zero_salt, &zero_kdf_params, &wrap_nonce, &wrapped_dek, &kcv);

        let mac = compute_header_mac(&hmk, &page0, keyslot_count);
        page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);

        write_page0(&mut file, &page0)?;
        Ok(recovery_str)
    }

    /// Remove the keyslot at `slot_idx`, zeroing it.
    ///
    /// Refuses to remove the last active slot (that would brick the database).
    pub fn remove_keyslot(path: &Path, unlock_passphrase: &str, slot_idx: u16) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut page0 = read_page0(&mut file)?;
        validate_header(&page0)?;

        let dek_id = read_u64(&page0, OFF_DEK_ID);
        let keyslot_count = (read_u16(&page0, OFF_KEYSLOT_COUNT) as usize).max(1).min(MAX_KEYSLOTS);
        let (dek, _) = try_unlock_passphrase(&page0, unlock_passphrase, dek_id, keyslot_count)?;
        let (_, hmk, _) = derive_subkeys(&dek);

        if slot_idx as usize >= keyslot_count {
            return Err(TosumError::InvalidArgument("slot index out of range"));
        }

        // Count active slots before removal.
        let active: usize = (0..keyslot_count).filter(|&i| {
            let ks = KEYSLOT_REGION_OFFSET + i * KEYSLOT_SIZE;
            page0[ks + KS_OFF_KIND] != KEYSLOT_KIND_EMPTY && page0[ks + KS_OFF_KIND] != KEYSLOT_KIND_SENTINEL
        }).count();

        if active <= 1 {
            return Err(TosumError::InvalidArgument("cannot remove the last active keyslot"));
        }

        // Zero the slot.
        let ks = KEYSLOT_REGION_OFFSET + slot_idx as usize * KEYSLOT_SIZE;
        page0[ks..ks + KEYSLOT_SIZE].fill(0);

        let mac = compute_header_mac(&hmk, &page0, keyslot_count);
        page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);

        write_page0(&mut file, &page0)
    }

    /// Rotate the KEK for the Passphrase slot at `slot_idx`.
    ///
    /// Re-wraps the DEK under a new KEK derived from `new_passphrase`.
    pub fn rekey_kek(path: &Path, slot_idx: u16, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut page0 = read_page0(&mut file)?;
        validate_header(&page0)?;

        let dek_id = read_u64(&page0, OFF_DEK_ID);
        let keyslot_count = (read_u16(&page0, OFF_KEYSLOT_COUNT) as usize).max(1).min(MAX_KEYSLOTS);

        if slot_idx as usize >= keyslot_count {
            return Err(TosumError::InvalidArgument("slot index out of range"));
        }

        // Verify target slot is Passphrase kind.
        let ks = KEYSLOT_REGION_OFFSET + slot_idx as usize * KEYSLOT_SIZE;
        if page0[ks + KS_OFF_KIND] != KEYSLOT_KIND_PASSPHRASE {
            return Err(TosumError::InvalidArgument("slot is not a Passphrase slot"));
        }

        // Unlock target slot with old passphrase.
        let salt: [u8; 16] = page0[ks + KS_OFF_SALT..ks + KS_OFF_SALT + 16].try_into().unwrap();
        let kdf_params: [u8; 32] = page0[ks + KS_OFF_KDF_PARAMS..ks + KS_OFF_KDF_PARAMS + 32].try_into().unwrap();
        let wrap_nonce: [u8; 12] = page0[ks + KS_OFF_WRAP_NONCE..ks + KS_OFF_WRAP_NONCE + 12].try_into().unwrap();
        let wrapped_dek: [u8; 48] = page0[ks + KS_OFF_WRAPPED_DEK..ks + KS_OFF_WRAPPED_DEK + 48].try_into().unwrap();
        let kcv: [u8; 32] = page0[ks + KS_OFF_KCV..ks + KS_OFF_KCV + 32].try_into().unwrap();

        let old_kek = derive_passphrase_kek(old_passphrase, &salt, &kdf_params)?;
        verify_kcv(&old_kek, &kcv)?;
        let dek = unwrap_dek(&old_kek, &wrap_nonce, &wrapped_dek, slot_idx, dek_id, KEYSLOT_KIND_PASSPHRASE)?;
        let (_, hmk, _) = derive_subkeys(&dek);

        // Wrap under new passphrase with fresh salt.
        let mut new_salt = [0u8; 16];
        getrandom::getrandom(&mut new_salt).map_err(|_| TosumError::RngFailed)?;
        let new_kdf_params = pack_kdf_params(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST);
        let new_kek = derive_passphrase_kek(new_passphrase, &new_salt, &new_kdf_params)?;
        let (new_nonce, new_wrapped) = wrap_dek(&new_kek, &dek, slot_idx, dek_id, KEYSLOT_KIND_PASSPHRASE)?;
        let new_kcv = compute_kcv(&new_kek);

        write_keyslot(&mut page0, slot_idx as usize, KEYSLOT_KIND_PASSPHRASE, dek_id,
                      &new_salt, &new_kdf_params, &new_nonce, &new_wrapped, &new_kcv);

        let mac = compute_header_mac(&hmk, &page0, keyslot_count);
        page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);

        write_page0(&mut file, &page0)
    }

    /// List active keyslots. Returns `Vec<(slot_index, kind_byte)>`.
    pub fn list_keyslots(path: &Path) -> Result<Vec<(u16, u8)>> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        let page0 = read_page0(&mut file)?;
        validate_header(&page0)?;

        let keyslot_count = (read_u16(&page0, OFF_KEYSLOT_COUNT) as usize).max(1).min(MAX_KEYSLOTS);
        let mut result = Vec::new();
        for i in 0..keyslot_count {
            let ks = KEYSLOT_REGION_OFFSET + i * KEYSLOT_SIZE;
            let kind = page0[ks + KS_OFF_KIND];
            if kind != KEYSLOT_KIND_EMPTY {
                result.push((i as u16, kind));
            }
        }
        Ok(result)
    }



    /// Decrypt page `pgno` and return `(plaintext, page_version)`.
    ///
    /// Prefer `with_page` for normal reads; this is for inspection tooling that
    /// also needs the page_version field.
    pub fn read_page(&self, pgno: u64) -> Result<([u8; PAGE_PLAINTEXT_SIZE], u64)> {
        self.validate_data_pgno(pgno)?;
        let frame = self.read_frame(pgno)?;
        decrypt_page(&self.page_key, pgno, &frame)
    }

    /// Read-only access to page `pgno`. Closure receives the decrypted plaintext.
    ///
    /// Also checks the dirty-page buffer so that read-your-own-writes works
    /// correctly inside a transaction (navigating tree structure after splits).
    pub fn with_page<F, T>(&self, pgno: u64, f: F) -> Result<T>
    where
        F: FnOnce(&[u8; PAGE_PLAINTEXT_SIZE]) -> Result<T>,
    {
        self.validate_data_pgno(pgno)?;
        // Read-your-own-writes: check dirty buffer first when inside a transaction.
        let frame = if let Some(pos) = self.dirty_pages.iter().rposition(|(p, _)| *p == pgno) {
            *self.dirty_pages[pos].1
        } else {
            self.read_frame(pgno)?
        };
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
        self.validate_data_pgno(pgno)?;

        // For reads: check dirty buffer first (read-your-own-writes).
        let frame = if let Some(pos) = self.dirty_pages.iter().rposition(|(p, _)| *p == pgno) {
            *self.dirty_pages[pos].1.clone()
        } else {
            self.read_frame(pgno)?
        };

        let (mut plaintext, version) = decrypt_page(&self.page_key, pgno, &frame)?;

        f(&mut plaintext)?;

        let new_frame = encrypt_page(&self.page_key, pgno, version + 1, plaintext[0], &plaintext)?;

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

    /// Allocate and initialise a new page. Returns its page number.
    ///
    /// The page frame is written to disk *before* `page_count` is incremented
    /// and the header is flushed. A crash after the frame write but before the
    /// header flush leaves `page_count` unchanged, so the new page is simply
    /// unreachable on recovery — no partial state is visible.
    ///
    /// For MVP+1 the freelist is not yet checked; pages grow monotonically.
    pub fn allocate(&mut self, page_type: u8) -> Result<u64> {
        let pgno = self.page_count;
        // Write the initialised frame first, so the file is extended before
        // page_count advertises the new page.
        self.init_page(pgno, page_type)?;
        self.page_count += 1;
        self.flush_header()?;
        Ok(pgno)
    }

    /// Initialize a newly allocated page and write it to disk.
    ///
    /// `pgno` must be > 0 and <= `page_count` (i.e. the next page to be
    /// allocated, or an existing page being re-initialised).
    pub fn init_page(&mut self, pgno: u64, page_type: u8) -> Result<()> {
        if pgno == 0 || pgno > self.page_count {
            return Err(TosumError::InvalidArgument("invalid page number for initialization"));
        }
        let mut plaintext = [0u8; PAGE_PLAINTEXT_SIZE];
        // Set page header: type, free_start, free_end.
        plaintext[0] = page_type;
        // flags=0, slot_count=0 (already 0)
        write_u16_buf(&mut plaintext, 2, 0u16);               // slot_count
        write_u16_buf(&mut plaintext, 4, PAGE_HEADER_SIZE as u16); // free_start
        write_u16_buf(&mut plaintext, 6, PAGE_PLAINTEXT_SIZE as u16); // free_end
        // fragmented_bytes=0, reserved=0, next_leaf=0 — already zero
        let frame = encrypt_page(&self.page_key, pgno, 1, page_type, &plaintext)?;
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

    /// Write updated page_count, freelist_head and root_page back to page 0.
    ///
    /// For passphrase-protected databases the header MAC is recomputed over the
    /// updated page 0 so it remains valid after every header mutation.
    pub fn flush_header(&mut self) -> Result<()> {
        // Read current page 0, update the mutable fields, recompute MAC if needed.
        let mut page0 = [0u8; PAGE_SIZE];
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut page0)?;

        write_u64(&mut page0, OFF_PAGE_COUNT, self.page_count);
        write_u64(&mut page0, OFF_FREELIST_HEAD, self.freelist_head);
        write_u64(&mut page0, OFF_ROOT_PAGE, self.root_page);

        if let Some(ref hmk) = self.header_mac_key {
            let mac = compute_header_mac(hmk, &page0, MAX_KEYSLOTS);
            page0[OFF_HEADER_MAC..OFF_HEADER_MAC + 32].copy_from_slice(&mac);
        }

        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&page0)?;
        self.file.sync_data()?;
        Ok(())
    }

    // ── private ──────────────────────────────────────────────────────────────

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Validate that `pgno` is a data page: non-zero and within the allocated range.
    fn validate_data_pgno(&self, pgno: u64) -> Result<()> {
        if pgno == 0 {
            return Err(TosumError::InvalidArgument("page 0 is the file header, not a data page"));
        }
        if pgno >= self.page_count {
            return Err(TosumError::InvalidArgument("page number out of range"));
        }
        Ok(())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn read_raw_frame(&self, pgno: u64) -> Result<[u8; PAGE_SIZE]> {
        self.read_frame(pgno)
    }

    fn read_frame(&self, pgno: u64) -> Result<[u8; PAGE_SIZE]> {
        let mut frame = [0u8; PAGE_SIZE];
        let offset = pgno * PAGE_SIZE as u64;
        // File::seek needs &mut File. For MVP+1, clone the handle for reads
        // instead of adding interior mutability or a page cache.
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

// ── Keyslot helpers ───────────────────────────────────────────────────────────

/// Validate magic, format version and page size from a page-0 buffer.
fn validate_header(page0: &[u8; PAGE_SIZE]) -> Result<()> {
    if !check_magic(page0) {
        return Err(TosumError::NotATosumFile);
    }
    let fv = read_u16(page0, OFF_FORMAT_VERSION);
    if fv > FORMAT_VERSION {
        return Err(TosumError::NewerFormat { found: fv, supported_max: FORMAT_VERSION });
    }
    let ps = read_u16(page0, OFF_PAGE_SIZE);
    if ps as usize != PAGE_SIZE {
        return Err(TosumError::PageSizeMismatch { found: ps, expected: PAGE_SIZE as u16 });
    }
    Ok(())
}

/// Read the full page-0 from an open file.
fn read_page0(file: &mut File) -> Result<[u8; PAGE_SIZE]> {
    let mut page0 = [0u8; PAGE_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut page0)?;
    Ok(page0)
}

/// Write page-0 back to an open file and fsync.
fn write_page0(file: &mut File, page0: &[u8; PAGE_SIZE]) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(page0)?;
    file.sync_data()?;
    Ok(())
}

/// Write a single keyslot into `page0` at `slot_idx`.
fn write_keyslot(
    page0: &mut [u8; PAGE_SIZE],
    slot_idx: usize,
    kind: u8,
    dek_id: u64,
    salt: &[u8; 16],
    kdf_params: &[u8; 32],
    wrap_nonce: &[u8; 12],
    wrapped_dek: &[u8; 48],
    kcv: &[u8; 32],
) {
    let ks = KEYSLOT_REGION_OFFSET + slot_idx * KEYSLOT_SIZE;
    // Zero the slot first (clears any previous data / reserved bytes).
    page0[ks..ks + KEYSLOT_SIZE].fill(0);
    page0[ks + KS_OFF_KIND] = kind;
    page0[ks + KS_OFF_VERSION] = 1;
    write_u64(page0, ks + KS_OFF_DEK_ID, dek_id);
    page0[ks + KS_OFF_SALT..ks + KS_OFF_SALT + 16].copy_from_slice(salt);
    page0[ks + KS_OFF_KDF_PARAMS..ks + KS_OFF_KDF_PARAMS + 32].copy_from_slice(kdf_params);
    page0[ks + KS_OFF_WRAP_NONCE..ks + KS_OFF_WRAP_NONCE + 12].copy_from_slice(wrap_nonce);
    page0[ks + KS_OFF_WRAPPED_DEK..ks + KS_OFF_WRAPPED_DEK + 48].copy_from_slice(wrapped_dek);
    page0[ks + KS_OFF_KCV..ks + KS_OFF_KCV + 32].copy_from_slice(kcv);
}

/// Find the first empty keyslot in the region. Returns `WrongKey` (slot region full) if none found.
fn find_empty_slot(page0: &[u8; PAGE_SIZE], keyslot_count: usize) -> Result<u16> {
    for i in 0..keyslot_count {
        let ks = KEYSLOT_REGION_OFFSET + i * KEYSLOT_SIZE;
        if page0[ks + KS_OFF_KIND] == KEYSLOT_KIND_EMPTY {
            return Ok(i as u16);
        }
    }
    Err(TosumError::InvalidArgument("keyslot region is full (all 8 slots occupied)"))
}

/// Try to unlock the database using a passphrase, scanning all keyslots.
///
/// Returns `(dek, is_encrypted)`. For Sentinel DBs, `is_encrypted` is false.
fn try_unlock_passphrase(
    page0: &[u8; PAGE_SIZE],
    passphrase: &str,
    dek_id: u64,
    keyslot_count: usize,
) -> Result<([u8; 32], bool)> {
    // First check slot 0 for Sentinel (unencrypted DB).
    let ks0 = KEYSLOT_REGION_OFFSET;
    if page0[ks0 + KS_OFF_KIND] == KEYSLOT_KIND_SENTINEL {
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&page0[ks0 + KS_OFF_WRAPPED_DEK..ks0 + KS_OFF_WRAPPED_DEK + 32]);
        return Ok((dek, false));
    }

    // Scan all Passphrase slots.
    for i in 0..keyslot_count {
        let ks = KEYSLOT_REGION_OFFSET + i * KEYSLOT_SIZE;
        if page0[ks + KS_OFF_KIND] != KEYSLOT_KIND_PASSPHRASE {
            continue;
        }
        let salt: [u8; 16] = page0[ks + KS_OFF_SALT..ks + KS_OFF_SALT + 16].try_into().unwrap();
        let kdf_params: [u8; 32] = page0[ks + KS_OFF_KDF_PARAMS..ks + KS_OFF_KDF_PARAMS + 32].try_into().unwrap();
        let kcv: [u8; 32] = page0[ks + KS_OFF_KCV..ks + KS_OFF_KCV + 32].try_into().unwrap();
        let wrap_nonce: [u8; 12] = page0[ks + KS_OFF_WRAP_NONCE..ks + KS_OFF_WRAP_NONCE + 12].try_into().unwrap();
        let wrapped_dek: [u8; 48] = page0[ks + KS_OFF_WRAPPED_DEK..ks + KS_OFF_WRAPPED_DEK + 48].try_into().unwrap();

        let kek = match derive_passphrase_kek(passphrase, &salt, &kdf_params) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if verify_kcv(&kek, &kcv).is_err() {
            continue;
        }
        if let Ok(dek) = unwrap_dek(&kek, &wrap_nonce, &wrapped_dek, i as u16, dek_id, KEYSLOT_KIND_PASSPHRASE) {
            return Ok((dek, true));
        }
    }
    Err(TosumError::WrongKey)
}

/// Try to unlock the database with a pre-derived KEK, scanning for a specific kind.
fn try_unlock_with_kek(
    page0: &[u8; PAGE_SIZE],
    kek: &[u8; 32],
    dek_id: u64,
    keyslot_count: usize,
    kind: u8,
) -> Result<[u8; 32]> {
    for i in 0..keyslot_count {
        let ks = KEYSLOT_REGION_OFFSET + i * KEYSLOT_SIZE;
        if page0[ks + KS_OFF_KIND] != kind {
            continue;
        }
        let kcv: [u8; 32] = page0[ks + KS_OFF_KCV..ks + KS_OFF_KCV + 32].try_into().unwrap();
        if verify_kcv(kek, &kcv).is_err() {
            continue;
        }
        let wrap_nonce: [u8; 12] = page0[ks + KS_OFF_WRAP_NONCE..ks + KS_OFF_WRAP_NONCE + 12].try_into().unwrap();
        let wrapped_dek: [u8; 48] = page0[ks + KS_OFF_WRAPPED_DEK..ks + KS_OFF_WRAPPED_DEK + 48].try_into().unwrap();
        if let Ok(dek) = unwrap_dek(kek, &wrap_nonce, &wrapped_dek, i as u16, dek_id, kind) {
            return Ok(dek);
        }
    }
    Err(TosumError::WrongKey)
}

/// Complete a Pager open given a derived page_key + optional MAC key.
fn finish_open(
    mut file: File,
    page_key: [u8; 32],
    header_mac_key: Option<[u8; 32]>,
    page0: &[u8; PAGE_SIZE],
    path: &Path,
) -> Result<Pager> {
    let page_count = read_u64(page0, OFF_PAGE_COUNT);

    // Sanity-check the file length against the advertised page count.
    // A truncated file means the header is lying; reject rather than trust it.
    let file_len = file.metadata()?.len();
    let expected_len = page_count
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(TosumError::Corrupt { pgno: 0, reason: "page_count overflow" })?;
    if file_len < expected_len {
        return Err(TosumError::Corrupt { pgno: 0, reason: "file is truncated" });
    }

    let freelist_head = read_u64(page0, OFF_FREELIST_HEAD);
    let root_page = read_u64(page0, OFF_ROOT_PAGE);

    let wp = wal_path(path);
    if wp.exists() {
        crate::wal::recover(path, &wp)?;
        // Re-read page0 after WAL recovery so page_count/root_page are current.
        file.seek(SeekFrom::Start(0))?;
        let mut refreshed = [0u8; PAGE_SIZE];
        file.read_exact(&mut refreshed)?;
        let page_count = read_u64(&refreshed, OFF_PAGE_COUNT);
        let freelist_head = read_u64(&refreshed, OFF_FREELIST_HEAD);
        let root_page = read_u64(&refreshed, OFF_ROOT_PAGE);
        let wal = WalWriter::open_or_create(&wp).ok();
        return Ok(Pager {
            file, page_key, header_mac_key,
            page_count, freelist_head, root_page,
            wal, txn_active: false, txn_id: 0, next_txn_id: 1, dirty_pages: Vec::new(),
        });
    }
    let wal = WalWriter::open_or_create(&wp).ok();
    Ok(Pager {
        file, page_key, header_mac_key,
        page_count, freelist_head, root_page,
        wal, txn_active: false, txn_id: 0, next_txn_id: 1, dirty_pages: Vec::new(),
    })
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
    // Sentinel stores the DEK as plaintext in the wrapped_dek field — it is NOT
    // wrapped. The field name is shared with encrypted protectors for layout
    // compatibility. See DESIGN.md §8.11: Sentinel provides no confidentiality.
    // Only the first 32 bytes are used (vs 48 for AEAD-wrapped DEKs).
    //
    // MVP+1 note: page 0 is trusted for magic/version/page-size checks only.
    // Data pages are fully authenticated (AEAD + page_version). Page 0 fields
    // such as page_count, freelist_head and root_page are not MAC'd in MVP+1;
    // the header MAC is added for encrypted databases only (Passphrase/Recovery slots).
    page0[ks + KS_OFF_WRAPPED_DEK..ks + KS_OFF_WRAPPED_DEK + 32].copy_from_slice(dek);
}
