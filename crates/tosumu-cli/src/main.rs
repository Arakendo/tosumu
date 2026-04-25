//! `tosumu` command-line interface — MVP +7.
//!
//! Key management (multiple protectors, recovery key, KEK rotation) on top of MVP +6.
//! See DESIGN.md §12.0 (MVP +7).

use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand};
use tosumu_core::error::TosumuError;
use tosumu_core::pager::Pager;
use tosumu_core::page_store::PageStore;

enum UnlockSecret {
    Passphrase(String),
    RecoveryKey(String),
}

#[derive(Parser)]
#[command(name = tosumu_core::NAME, version, about = "tosumu key-value store (MVP +7)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new database file.
    Init {
        path: PathBuf,
        /// Protect the database with a passphrase (Argon2id).
        #[arg(long)]
        encrypt: bool,
    },
    /// Insert or update a key-value pair.
    Put {
        path: PathBuf,
        key: String,
        value: String,
    },
    /// Retrieve the value for a key.
    Get {
        path: PathBuf,
        key: String,
    },
    /// Delete a key.
    Delete {
        path: PathBuf,
        key: String,
    },
    /// Print all key-value pairs, sorted by key.
    Scan {
        path: PathBuf,
    },
    /// Show database statistics.
    Stat {
        path: PathBuf,
    },
    /// Pretty-print the file header, and optionally a decoded page.
    Dump {
        path: PathBuf,
        /// Page number to decode and display (omit to show only the file header).
        #[arg(long)]
        page: Option<u64>,
    },
    /// Hex-dump the raw encrypted frame of a single page.
    Hex {
        path: PathBuf,
        /// Page number to dump (0 = plaintext file header, ≥1 = encrypted frame).
        #[arg(long)]
        page: u64,
    },
    /// Authenticate every data page and report any integrity failures.
    Verify {
        path: PathBuf,
        /// Show per-page integrity / freshness / epistemic status.
        #[arg(long)]
        explain: bool,
    },
    /// Copy a database file (and its WAL sidecar if present) to a destination.
    Backup {
        /// Source database path.
        src: PathBuf,
        /// Destination path for the backup copy.
        dest: PathBuf,
    },
    /// Manage key protectors (add, remove, list).
    Protector {
        #[command(subcommand)]
        action: ProtectorAction,
    },
    /// Rotate the KEK for a passphrase protector slot (cheap — rewraps DEK only).
    RekeyKek {
        path: PathBuf,
        /// Slot index to rotate (use `protector list` to see slot indices).
        #[arg(long, default_value = "0")]
        slot: u16,
    },
}

#[derive(Subcommand)]
enum ProtectorAction {
    /// Add a new passphrase protector.
    AddPassphrase { path: PathBuf },
    /// Add a recovery-key protector (prints one-time recovery key).
    AddRecoveryKey { path: PathBuf },
    /// Remove a keyslot by index.
    Remove {
        path: PathBuf,
        /// Slot index to remove.
        slot: u16,
    },
    /// List all active keyslots.
    List { path: PathBuf },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Open a `PageStore`, automatically prompting for a passphrase if required.
fn open_store_readonly(path: &Path) -> Result<PageStore, TosumuError> {
    match PageStore::open_readonly(path) {
        Ok(store) => Ok(store),
        Err(TosumuError::WrongKey) => {
            let pass = prompt_passphrase("passphrase: ")?;
            match PageStore::open_with_passphrase_readonly(path, &pass) {
                Ok(store) => Ok(store),
                Err(TosumuError::WrongKey) => {
                    let recovery = prompt_passphrase("recovery key: ")?;
                    PageStore::open_with_recovery_key_readonly(path, &recovery)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn open_store_writable(path: &Path) -> Result<PageStore, TosumuError> {
    match PageStore::open(path) {
        Ok(store) => Ok(store),
        Err(TosumuError::WrongKey) => {
            let pass = prompt_passphrase("passphrase: ")?;
            match PageStore::open_with_passphrase(path, &pass) {
                Ok(store) => Ok(store),
                Err(TosumuError::WrongKey) => {
                    let recovery = prompt_passphrase("recovery key: ")?;
                    PageStore::open_with_recovery_key(path, &recovery)
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn open_pager(path: &Path) -> Result<(Pager, Option<UnlockSecret>), TosumuError> {
    match Pager::open_readonly(path) {
        Ok(pager) => Ok((pager, None)),
        Err(TosumuError::WrongKey) => {
            let pass = prompt_passphrase("passphrase: ")?;
            match Pager::open_with_passphrase_readonly(path, &pass) {
                Ok(pager) => Ok((pager, Some(UnlockSecret::Passphrase(pass)))),
                Err(TosumuError::WrongKey) => {
                    let recovery = prompt_passphrase("recovery key: ")?;
                    let pager = Pager::open_with_recovery_key_readonly(path, &recovery)?;
                    Ok((pager, Some(UnlockSecret::RecoveryKey(recovery))))
                }
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn open_btree_with_unlock(path: &Path, unlock: Option<&UnlockSecret>) -> Result<tosumu_core::btree::BTree, TosumuError> {
    match unlock {
        None => tosumu_core::btree::BTree::open_readonly(path),
        Some(UnlockSecret::Passphrase(pass)) => tosumu_core::btree::BTree::open_with_passphrase_readonly(path, pass),
        Some(UnlockSecret::RecoveryKey(recovery)) => tosumu_core::btree::BTree::open_with_recovery_key_readonly(path, recovery),
    }
}

/// Prompt for a passphrase without echoing.
fn prompt_passphrase(prompt: &str) -> Result<String, TosumuError> {
    rpassword::prompt_password(prompt)
        .map_err(|e| TosumuError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
}

fn run(cli: Cli) -> Result<(), TosumuError> {
    match cli.command {
        Command::Init { path, encrypt } => {
            if encrypt {
                let pass = prompt_passphrase("new passphrase: ")?;
                let confirm = prompt_passphrase("confirm passphrase: ")?;
                if pass != confirm {
                    eprintln!("error: passphrases do not match");
                    std::process::exit(1);
                }
                PageStore::create_encrypted(&path, &pass)?;
                println!("initialized {} (passphrase-protected)", path.display());
                println!();
                println!("NOTE: Tosumu is always authenticated. With a passphrase protector,");
                println!("      the database is also confidential. Without one, it provides");
                println!("      integrity only — a local reader with file access can read the data.");
            } else {
                PageStore::create(&path)?;
                println!("initialized {} (sentinel protector — authentication only, no passphrase)", path.display());
            }
        }
        Command::Put { path, key, value } => {
            let mut store = open_store_writable(&path)?;
            store.put(key.as_bytes(), value.as_bytes())?;
        }
        Command::Get { path, key } => {
            let store = open_store_readonly(&path)?;
            match store.get(key.as_bytes())? {
                Some(v) => println!("{}", String::from_utf8_lossy(&v)),
                None => {
                    eprintln!("not found");
                    std::process::exit(1);
                }
            }
        }
        Command::Delete { path, key } => {
            let mut store = open_store_writable(&path)?;
            store.delete(key.as_bytes())?;
        }
        Command::Scan { path } => {
            let store = open_store_readonly(&path)?;
            for (k, v) in store.scan()? {
                println!("{}\t{}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v));
            }
        }
        Command::Stat { path } => {
            let store = open_store_readonly(&path)?;
            let s = store.stat()?;
            println!("page_count:  {}", s.page_count);
            println!("data_pages:  {}", s.data_pages);
            println!("tree_height: {}", s.tree_height);
        }
        Command::Dump { path, page } => cmd_dump(&path, page)?,
        Command::Hex  { path, page } => cmd_hex(&path, page)?,
        Command::Verify { path, explain } => cmd_verify(&path, explain)?,
        Command::Backup { src, dest } => cmd_backup(&src, &dest)?,
        Command::Protector { action } => match action {
            ProtectorAction::AddPassphrase { path } => {
                let unlock = prompt_passphrase("current passphrase: ")?;
                let new1   = prompt_passphrase("new passphrase: ")?;
                let new2   = prompt_passphrase("confirm new passphrase: ")?;
                if new1 != new2 {
                    eprintln!("passphrases do not match");
                    std::process::exit(1);
                }
                let slot = match PageStore::add_passphrase_protector(&path, &unlock, &new1) {
                    Ok(slot) => slot,
                    Err(TosumuError::WrongKey) => {
                        let recovery = prompt_passphrase("recovery key: ")?;
                        PageStore::add_passphrase_protector_with_recovery_key(&path, &recovery, &new1)?
                    }
                    Err(e) => return Err(e),
                };
                println!("protector added at slot {slot}");
            }
            ProtectorAction::AddRecoveryKey { path } => {
                let unlock = prompt_passphrase("current passphrase: ")?;
                let key = match PageStore::add_recovery_key_protector(&path, &unlock) {
                    Ok(key) => key,
                    Err(TosumuError::WrongKey) => {
                        let recovery = prompt_passphrase("recovery key: ")?;
                        PageStore::add_recovery_key_protector_with_recovery_key(&path, &recovery)?
                    }
                    Err(e) => return Err(e),
                };
                println!();
                println!("=== RECOVERY KEY — save this somewhere safe ===");
                println!();
                println!("  {key}");
                println!();
                println!("This key will NOT be shown again.");
            }
            ProtectorAction::Remove { path, slot } => {
                let unlock = prompt_passphrase("passphrase: ")?;
                match PageStore::remove_keyslot(&path, &unlock, slot) {
                    Ok(()) => {}
                    Err(TosumuError::WrongKey) => {
                        let recovery = prompt_passphrase("recovery key: ")?;
                        PageStore::remove_keyslot_with_recovery_key(&path, &recovery, slot)?;
                    }
                    Err(e) => return Err(e),
                }
                println!("slot {slot} removed");
            }
            ProtectorAction::List { path } => {
                use tosumu_core::format::{
                    KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_SENTINEL,
                    KEYSLOT_KIND_PASSPHRASE, KEYSLOT_KIND_RECOVERY_KEY,
                };
                let slots = PageStore::list_keyslots(&path)?;
                if slots.is_empty() {
                    println!("no active keyslots");
                } else {
                    println!("{:>5}  {}", "SLOT", "KIND");
                    for (idx, kind) in &slots {
                        let name = match *kind {
                            KEYSLOT_KIND_EMPTY        => "Empty",
                            KEYSLOT_KIND_SENTINEL     => "Sentinel (plaintext)",
                            KEYSLOT_KIND_PASSPHRASE   => "Passphrase",
                            KEYSLOT_KIND_RECOVERY_KEY => "RecoveryKey",
                            _                         => "Unknown",
                        };
                        println!("{idx:>5}  {name}");
                    }
                }
            }
        },
        Command::RekeyKek { path, slot } => {
            let old_pass = prompt_passphrase("old passphrase: ")?;
            let new1     = prompt_passphrase("new passphrase: ")?;
            let new2     = prompt_passphrase("confirm new passphrase: ")?;
            if new1 != new2 {
                eprintln!("passphrases do not match");
                std::process::exit(1);
            }
            match PageStore::rekey_kek(&path, slot, &old_pass, &new1) {
                Ok(()) => {}
                Err(TosumuError::WrongKey) => {
                    let recovery = prompt_passphrase("recovery key: ")?;
                    PageStore::rekey_kek_with_recovery_key(&path, slot, &recovery, &new1)?;
                }
                Err(e) => return Err(e),
            }
            println!("slot {slot} KEK rotated");
        }
    }
    Ok(())
}

// ── dump ─────────────────────────────────────────────────────────────────────

fn cmd_dump(path: &std::path::Path, page: Option<u64>) -> tosumu_core::error::Result<()> {
    use tosumu_core::format::{
        PAGE_TYPE_LEAF, PAGE_TYPE_INTERNAL, PAGE_TYPE_OVERFLOW, PAGE_TYPE_FREE,
        KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_SENTINEL, KEYSLOT_KIND_PASSPHRASE,
    };
    use tosumu_core::inspect::{inspect_page_from_pager, read_header_info, RecordInfo};

    match page {
        None => {
            let h = read_header_info(path)?;
            println!("=== file header: {} ===", path.display());
            println!("magic:                TOSUMUv0");
            println!("format_version:       {}", h.format_version);
            println!("min_reader_version:   {}", h.min_reader_version);
            println!("page_size:            {}", h.page_size);
            let fl = h.flags;
            println!("flags:                {fl:#06x}  [reserved={}  has_keyslots={}]",
                fl & 1, (fl >> 1) & 1);
            let fl_note = if h.freelist_head == 0 { "  (none)" } else { "" };
            let rp_note = if h.root_page      == 0 { "  (none)" } else { "" };
            println!("page_count:           {}", h.page_count);
            println!("freelist_head:        {}{fl_note}", h.freelist_head);
            println!("root_page:            {}{rp_note}", h.root_page);
            println!("wal_checkpoint_lsn:   {}", h.wal_checkpoint_lsn);
            println!("dek_id:               {}", h.dek_id);
            println!("keyslot_count:        {}", h.keyslot_count);
            println!("keyslot_region_pages: {}", h.keyslot_region_pages);
            println!();
            println!("=== keyslot 0 ===");
            let kind_name = match h.ks0_kind {
                KEYSLOT_KIND_EMPTY      => "Empty",
                KEYSLOT_KIND_SENTINEL   => "Sentinel",
                KEYSLOT_KIND_PASSPHRASE => "Passphrase",
                _                       => "Unknown",
            };
            let kind_note = match h.ks0_kind {
                KEYSLOT_KIND_SENTINEL   => "  (plaintext DEK — authentication only, no confidentiality)",
                KEYSLOT_KIND_PASSPHRASE => "  (Argon2id KDF — authentication + confidentiality)",
                _ => "",
            };
            println!("kind:    {kind_name}{kind_note}");
            println!("version: {}", h.ks0_version);
        }
        Some(pgno) => {
            let (pager, _) = open_pager(path)?;
            let s = inspect_page_from_pager(&pager, pgno)?;
            let type_name = match s.page_type {
                PAGE_TYPE_LEAF     => "Leaf",
                PAGE_TYPE_INTERNAL => "Internal",
                PAGE_TYPE_OVERFLOW => "Overflow",
                PAGE_TYPE_FREE     => "Free",
                _                  => "Unknown",
            };
            println!("=== page {pgno}: {} ===", path.display());
            println!("page_version: {}", s.page_version);
            println!("page_type:    {type_name} (0x{:02x})", s.page_type);
            println!("slot_count:   {}", s.slot_count);
            println!("free_start:   {}", s.free_start);
            println!("free_end:     {}", s.free_end);
            println!("free_bytes:   {}", s.free_end.saturating_sub(s.free_start));
            if !s.records.is_empty() {
                println!();
            }
            for (i, rec) in s.records.iter().enumerate() {
                match rec {
                    RecordInfo::Live { key, value } => {
                        println!("  slot {i:3}  Live       key={}  value={}",
                            fmt_bytes(key), fmt_bytes(value));
                    }
                    RecordInfo::Tombstone { key } => {
                        println!("  slot {i:3}  Tombstone  key={}", fmt_bytes(key));
                    }
                    RecordInfo::Unknown { slot, record_type } => {
                        println!("  slot {slot:3}  Unknown    record_type=0x{record_type:02x}");
                    }
                }
            }
        }
    }
    Ok(())
}

// ── hex ──────────────────────────────────────────────────────────────────────

fn cmd_hex(path: &std::path::Path, pgno: u64) -> tosumu_core::error::Result<()> {
    use tosumu_core::format::{
        NONCE_SIZE, PAGE_VERSION_SIZE, CIPHERTEXT_OFFSET, PAGE_SIZE, TAG_SIZE,
    };
    use tosumu_core::inspect::read_raw_frame;

    let frame = read_raw_frame(path, pgno)?;
    println!("=== raw frame: page {pgno}  {}  ({PAGE_SIZE} bytes) ===", path.display());
    println!();

    print_hex_section("nonce · 12 bytes · offset 0x0000", &frame[..NONCE_SIZE], 0);

    let pv_label = format!("page_version · {PAGE_VERSION_SIZE} bytes · offset 0x{NONCE_SIZE:04x}");
    print_hex_section(&pv_label, &frame[NONCE_SIZE..CIPHERTEXT_OFFSET], NONCE_SIZE);

    let ct_len   = PAGE_SIZE - CIPHERTEXT_OFFSET - TAG_SIZE;
    let ct_label = format!("ciphertext · {ct_len} bytes · offset 0x{CIPHERTEXT_OFFSET:04x}");
    print_hex_section(&ct_label, &frame[CIPHERTEXT_OFFSET..PAGE_SIZE - TAG_SIZE], CIPHERTEXT_OFFSET);

    let tag_off   = PAGE_SIZE - TAG_SIZE;
    let tag_label = format!("auth tag (Poly1305) · {TAG_SIZE} bytes · offset 0x{tag_off:04x}");
    print_hex_section(&tag_label, &frame[tag_off..], tag_off);

    Ok(())
}

// ── verify ────────────────────────────────────────────────────────────────────

fn cmd_verify(path: &std::path::Path, explain: bool) -> tosumu_core::error::Result<()> {
    use tosumu_core::inspect::verify_pager;

    let (pager, unlock) = open_pager(path)?;
    let report = verify_pager(&pager)?;
    println!("verifying {} ({} data pages) ...", path.display(), report.pages_checked);

    if explain {
        // Per-page breakdown across the three epistemic dimensions (DESIGN.md §29.2).
        println!();
        for r in &report.page_results {
            println!("page {}:", r.pgno);
            if r.auth_ok {
                let ver = r.page_version.unwrap_or(0);
                println!("  integrity:   OK     — AEAD tag verified (page_version {ver})");
                println!("  freshness:   unanchored — LSN witness not configured (§23, Stage 6)");
                println!("  epistemic:   OK     — no overclaiming");
            } else {
                let reason = r.issue.as_deref().unwrap_or("unknown");
                println!("  integrity:   FAIL   — {reason}");
                println!("  freshness:   N/A");
                println!("  epistemic:   FAIL   — cannot verify page {} is what was written",
                    r.pgno);
            }
            println!();
        }
    } else {
        for issue in &report.issues {
            eprintln!("  page {} ... FAILED: {}", issue.pgno, issue.description);
        }
    }

    if report.issues.is_empty() {
        // Page integrity passed — also check B-tree structural invariants.
        match open_btree_with_unlock(path, unlock.as_ref()) {
            Ok(tree) => match tree.check_invariants() {
                Ok(()) => {
                    if explain {
                        println!("  btree:       OK     — keys sorted, routing correct, leaf chain ordered");
                    }
                }
                Err(e) => {
                    eprintln!("  btree:       FAIL   — {e}");
                    eprintln!("FAILED: btree structural invariant violated");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                if explain {
                    eprintln!("  btree:       SKIP   — could not open as BTree: {e}");
                }
            }
        }
        println!("all pages ok: {}/{}", report.pages_ok, report.pages_checked);
    } else {
        if !explain {
            // issues were already printed above in the explain branch
            eprintln!("FAILED: {}/{} pages ok, {} issue(s)",
                report.pages_ok, report.pages_checked, report.issues.len());
        } else {
            println!("FAILED: {}/{} pages ok, {} issue(s)",
                report.pages_ok, report.pages_checked, report.issues.len());
        }
        std::process::exit(1);
    }
    Ok(())
}

// ── backup ───────────────────────────────────────────────────────────────────

fn cmd_backup(
    src: &std::path::Path,
    dest: &std::path::Path,
) -> tosumu_core::error::Result<()> {
    use tosumu_core::wal::wal_path;
    use tosumu_core::error::TosumuError;

    const MAX_BACKUP_ATTEMPTS: u32 = 5;

    let dest_wal = wal_path(dest);
    if dest.exists() || dest_wal.exists() {
        return Err(TosumuError::InvalidArgument(
            "backup destination already exists; choose a new path",
        ));
    }

    let staged_main = backup_temp_path(dest, "main");
    let staged_wal = backup_temp_path(&dest_wal, "wal");
    let probe_main = backup_temp_path(dest, "main-probe");
    let probe_wal = backup_temp_path(&dest_wal, "wal-probe");
    let _ = std::fs::remove_file(&staged_main);
    let _ = std::fs::remove_file(&staged_wal);
    let _ = std::fs::remove_file(&probe_main);
    let _ = std::fs::remove_file(&probe_wal);

    let src_wal = wal_path(src);
    let mut copied_wal = false;
    let mut stable = false;

    for _ in 0..MAX_BACKUP_ATTEMPTS {
        cleanup_backup_temp(&staged_main, &staged_wal);
        cleanup_backup_temp(&probe_main, &probe_wal);

        std::fs::copy(src, &staged_main)
            .map_err(TosumuError::Io)?;
        let copied_wal_a = copy_optional_file(&src_wal, &staged_wal)?;

        std::fs::copy(src, &probe_main)
            .map_err(|e| {
                cleanup_backup_temp(&staged_main, &staged_wal);
                TosumuError::Io(e)
            })?;
        let copied_wal_b = copy_optional_file(&src_wal, &probe_wal).map_err(|e| {
            cleanup_backup_temp(&staged_main, &staged_wal);
            cleanup_backup_temp(&probe_main, &probe_wal);
            e
        })?;

        let wal_matches = copied_wal_a == copied_wal_b
            && (!copied_wal_a || files_equal(&staged_wal, &probe_wal).map_err(TosumuError::Io)?);
        let main_matches = files_equal(&staged_main, &probe_main).map_err(|e| {
            cleanup_backup_temp(&staged_main, &staged_wal);
            cleanup_backup_temp(&probe_main, &probe_wal);
            TosumuError::Io(e)
        })?;

        if main_matches && wal_matches {
            copied_wal = copied_wal_a;
            stable = true;
            break;
        }
    }

    cleanup_backup_temp(&probe_main, &probe_wal);

    if !stable {
        cleanup_backup_temp(&staged_main, &staged_wal);
        return Err(TosumuError::FileBusy {
            path: src.to_path_buf(),
            operation: "capturing a stable backup snapshot",
        });
    }

    if copied_wal {
        std::fs::rename(&staged_wal, &dest_wal).map_err(|e| {
            let _ = std::fs::remove_file(&staged_main);
            let _ = std::fs::remove_file(&staged_wal);
            TosumuError::Io(e)
        })?;
    }

    std::fs::rename(&staged_main, dest).map_err(|e| {
        let _ = std::fs::remove_file(&staged_main);
        if copied_wal {
            let _ = std::fs::remove_file(&dest_wal);
        }
        TosumuError::Io(e)
    })?;

    println!("backed up {} → {}", src.display(), dest.display());
    if src_wal.exists() {
        println!("backed up {} → {}", src_wal.display(), dest_wal.display());
    }
    Ok(())
}

fn backup_temp_path(dest: &Path, kind: &str) -> PathBuf {
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup");
    dest.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), kind))
}

fn copy_optional_file(src: &Path, dest: &Path) -> Result<bool, TosumuError> {
    let _ = std::fs::remove_file(dest);
    if src.exists() {
        std::fs::copy(src, dest).map_err(TosumuError::Io)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn cleanup_backup_temp(main: &Path, wal: &Path) {
    let _ = std::fs::remove_file(main);
    let _ = std::fs::remove_file(wal);
}

fn files_equal(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::fs::File;
    use std::io::Read;

    let meta_a = std::fs::metadata(a)?;
    let meta_b = std::fs::metadata(b)?;
    if meta_a.len() != meta_b.len() {
        return Ok(false);
    }

    let mut fa = File::open(a)?;
    let mut fb = File::open(b)?;
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];

    loop {
        let read_a = fa.read(&mut buf_a)?;
        let read_b = fb.read(&mut buf_b)?;
        if read_a != read_b {
            return Ok(false);
        }
        if read_a == 0 {
            return Ok(true);
        }
        if buf_a[..read_a] != buf_b[..read_b] {
            return Ok(false);
        }
    }
}

// ── display helpers ───────────────────────────────────────────────────────────

/// Format a byte slice as a quoted UTF-8 string, or hex if non-UTF-8.
fn fmt_bytes(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => format!("{s:?}"),
        Err(_) => {
            let hex: String = b.iter().take(48).map(|x| format!("{x:02x}")).collect();
            if b.len() > 48 { format!("0x{hex}…") } else { format!("0x{hex}") }
        }
    }
}

/// Print an annotated hex+ASCII section of a byte slice.
fn print_hex_section(label: &str, data: &[u8], base_offset: usize) {
    println!("[{label}]");
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = base_offset + i * 16;
        let hex_col: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
            .collect();
        println!("{offset:04x}: {:<47}  |{ascii}|", hex_col.join(" "));
    }
    println!();
}
