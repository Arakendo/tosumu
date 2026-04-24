//! `tosumu` command-line interface — MVP +2.
//!
//! Inspect tooling (dump, hex, verify) on top of MVP +1.
//! See DESIGN.md §12.1 (MVP +2).

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tosumu_core::page_store::PageStore;

#[derive(Parser)]
#[command(name = tosumu_core::NAME, version, about = "tosumu key-value store (MVP +1)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new database file.
    Init {
        path: PathBuf,
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
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), tosumu_core::error::TosumError> {
    match cli.command {
        Command::Init { path } => {
            PageStore::create(&path)?;
            println!("initialized {}", path.display());
        }
        Command::Put { path, key, value } => {
            let mut store = PageStore::open(&path)?;
            store.put(key.as_bytes(), value.as_bytes())?;
        }
        Command::Get { path, key } => {
            let store = PageStore::open(&path)?;
            match store.get(key.as_bytes())? {
                Some(v) => println!("{}", String::from_utf8_lossy(&v)),
                None => {
                    eprintln!("not found");
                    std::process::exit(1);
                }
            }
        }
        Command::Delete { path, key } => {
            let mut store = PageStore::open(&path)?;
            store.delete(key.as_bytes())?;
        }
        Command::Scan { path } => {
            let store = PageStore::open(&path)?;
            for (k, v) in store.scan()? {
                println!("{}\t{}", String::from_utf8_lossy(&k), String::from_utf8_lossy(&v));
            }
        }
        Command::Stat { path } => {
            let store = PageStore::open(&path)?;
            let s = store.stat();
            println!("page_count:  {}", s.page_count);
            println!("data_pages:  {}", s.data_pages);
        }
        Command::Dump { path, page } => cmd_dump(&path, page)?,
        Command::Hex  { path, page } => cmd_hex(&path, page)?,
        Command::Verify { path }     => cmd_verify(&path)?,
    }
    Ok(())
}

// ── dump ─────────────────────────────────────────────────────────────────────

fn cmd_dump(path: &std::path::Path, page: Option<u64>) -> tosumu_core::error::Result<()> {
    use tosumu_core::format::{
        PAGE_TYPE_LEAF, PAGE_TYPE_INTERNAL, PAGE_TYPE_OVERFLOW, PAGE_TYPE_FREE,
        KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_SENTINEL,
    };
    use tosumu_core::inspect::{read_header_info, inspect_page, RecordInfo};

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
                KEYSLOT_KIND_EMPTY    => "Empty",
                KEYSLOT_KIND_SENTINEL => "Sentinel",
                _                    => "Unknown",
            };
            let kind_note = if h.ks0_kind == KEYSLOT_KIND_SENTINEL {
                "  (plaintext DEK — authentication only, no confidentiality)"
            } else {
                ""
            };
            println!("kind:    {kind_name}{kind_note}");
            println!("version: {}", h.ks0_version);
        }
        Some(pgno) => {
            let s = inspect_page(path, pgno)?;
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

fn cmd_verify(path: &std::path::Path) -> tosumu_core::error::Result<()> {
    use tosumu_core::inspect::verify_file;

    let report = verify_file(path)?;
    println!("verifying {} ({} data pages) ...", path.display(), report.pages_checked);

    for issue in &report.issues {
        eprintln!("  page {} ... FAILED: {}", issue.pgno, issue.description);
    }

    if report.issues.is_empty() {
        println!("all pages ok: {}/{}", report.pages_ok, report.pages_checked);
    } else {
        eprintln!("FAILED: {}/{} pages ok, {} issue(s)",
            report.pages_ok, report.pages_checked, report.issues.len());
        std::process::exit(1);
    }
    Ok(())
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
