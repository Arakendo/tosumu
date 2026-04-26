//! `tosumu` command-line interface — MVP +8.
//!
//! Key management plus the first interactive inspection slice.
//! See DESIGN.md §12.0 (MVP +8).

use std::path::{Path, PathBuf};
use clap::{ArgGroup, Args, Parser, Subcommand};
use serde::Serialize;
use tosumu_core::error::TosumuError;
use tosumu_core::pager::Pager;
use tosumu_core::page_store::PageStore;

mod view;

enum UnlockSecret {
    Passphrase(String),
    RecoveryKey(String),
    Keyfile(PathBuf),
}

#[derive(Args, Clone, Default)]
#[command(group(
    ArgGroup::new("inspect_unlock")
        .args(["stdin_passphrase", "stdin_recovery_key", "keyfile"])
        .multiple(false)
))]
struct InspectUnlockArgs {
    /// Do not fall back to interactive prompts if unlock is required.
    #[arg(long)]
    no_prompt: bool,
    /// Read a passphrase from stdin for this inspect command.
    #[arg(long)]
    stdin_passphrase: bool,
    /// Read a recovery key from stdin for this inspect command.
    #[arg(long)]
    stdin_recovery_key: bool,
    /// Use a raw 32-byte keyfile for this inspect command.
    #[arg(long)]
    keyfile: Option<PathBuf>,
}

#[derive(Parser)]
#[command(name = tosumu_core::NAME, version, about = "tosumu key-value store (MVP +8)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn json_error_command(&self) -> Option<&'static str> {
        match &self.command {
            Command::Inspect {
                action: InspectAction::Header { json: true, .. },
            } => Some("inspect.header"),
            Command::Inspect {
                action: InspectAction::Verify { json: true, .. },
            } => Some("inspect.verify"),
            Command::Inspect {
                action: InspectAction::Pages { json: true, .. },
            } => Some("inspect.pages"),
            Command::Inspect {
                action: InspectAction::Page { json: true, .. },
            } => Some("inspect.page"),
            Command::Inspect {
                action: InspectAction::Protectors { json: true, .. },
            } => Some("inspect.protectors"),
            _ => None,
        }
    }
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
    /// Open the read-only interactive inspection view.
    View {
        path: PathBuf,
    },
    /// Structured inspection commands intended for machine consumption.
    Inspect {
        #[command(subcommand)]
        action: InspectAction,
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
enum InspectAction {
    /// Inspect the file header.
    Header {
        path: PathBuf,
        /// Emit a structured JSON envelope.
        #[arg(long)]
        json: bool,
    },
    /// Inspect page-auth verification results.
    Verify {
        path: PathBuf,
        /// Emit a structured JSON envelope.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect lightweight summaries for every data page.
    Pages {
        path: PathBuf,
        /// Emit a structured JSON envelope.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect a single decoded page.
    Page {
        path: PathBuf,
        /// Page number to inspect.
        #[arg(long)]
        page: u64,
        /// Emit a structured JSON envelope.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect the B-tree structure rooted at the current root page.
    Tree {
        path: PathBuf,
        /// Emit a structured JSON envelope.
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect configured protectors / keyslots.
    Protectors {
        path: PathBuf,
        /// Emit a structured JSON envelope.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Serialize)]
struct InspectEnvelope<T> {
    schema_version: u32,
    command: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<InspectErrorPayload>,
}

#[derive(Serialize)]
struct InspectHeaderPayload {
    format_version: u16,
    page_size: u16,
    min_reader_version: u16,
    flags: u16,
    page_count: u64,
    freelist_head: u64,
    root_page: u64,
    wal_checkpoint_lsn: u64,
    dek_id: u64,
    keyslot_count: u16,
    keyslot_region_pages: u16,
    slot0: InspectKeyslotPayload,
}

#[derive(Serialize)]
struct InspectVerifyPayload {
    pages_checked: u64,
    pages_ok: u64,
    issue_count: usize,
    issues: Vec<InspectVerifyIssuePayload>,
    page_results: Vec<InspectPageVerifyPayload>,
    btree: InspectBtreeVerifyPayload,
}

#[derive(Serialize)]
struct InspectPagePayload {
    pgno: u64,
    page_version: u64,
    page_type: u8,
    page_type_name: &'static str,
    slot_count: u16,
    free_start: u16,
    free_end: u16,
    records: Vec<InspectRecordPayload>,
}

#[derive(Serialize)]
struct InspectPagesPayload {
    pages: Vec<InspectPagesEntryPayload>,
}

#[derive(Serialize)]
struct InspectPagesEntryPayload {
    pgno: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_type_name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot_count: Option<u16>,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    issue: Option<String>,
}

#[derive(Serialize)]
struct InspectTreePayload {
    root_pgno: u64,
    root: InspectTreeNodePayload,
}

#[derive(Serialize)]
struct InspectTreeNodePayload {
    pgno: u64,
    page_version: u64,
    page_type: u8,
    page_type_name: &'static str,
    slot_count: u16,
    free_start: u16,
    free_end: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_leaf: Option<u64>,
    children: Vec<InspectTreeChildPayload>,
}

#[derive(Serialize)]
struct InspectTreeChildPayload {
    relation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    separator_key_hex: Option<String>,
    child: Box<InspectTreeNodePayload>,
}

#[derive(Serialize)]
struct InspectProtectorsPayload {
    slot_count: usize,
    slots: Vec<InspectProtectorSlotPayload>,
}

#[derive(Serialize)]
struct InspectRecordPayload {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    record_type: Option<u8>,
}

#[derive(Serialize)]
struct InspectVerifyIssuePayload {
    pgno: u64,
    description: String,
}

#[derive(Serialize)]
struct InspectPageVerifyPayload {
    pgno: u64,
    page_version: Option<u64>,
    auth_ok: bool,
    issue: Option<String>,
}

#[derive(Serialize)]
struct InspectProtectorSlotPayload {
    slot: u16,
    kind: &'static str,
    kind_byte: u8,
}

#[derive(Serialize)]
struct InspectBtreeVerifyPayload {
    checked: bool,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Serialize)]
struct InspectKeyslotPayload {
    kind: &'static str,
    kind_byte: u8,
    version: u8,
}

#[derive(Serialize)]
struct InspectErrorPayload {
    kind: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pgno: Option<u64>,
}

#[derive(Subcommand)]
enum ProtectorAction {
    /// Add a new passphrase protector.
    AddPassphrase { path: PathBuf },
    /// Add a recovery-key protector (prints one-time recovery key).
    AddRecoveryKey { path: PathBuf },
    /// Add a keyfile protector from a raw 32-byte file.
    AddKeyfile { path: PathBuf, keyfile: PathBuf },
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
    let json_error_command = cli.json_error_command();

    if let Err(e) = run(cli) {
        if let Some(command) = json_error_command {
            println!("{}", render_inspect_error_json(command, &e));
        } else {
            eprintln!("error: {e}");
        }
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
                    match PageStore::open_with_recovery_key_readonly(path, &recovery) {
                        Ok(store) => Ok(store),
                        Err(TosumuError::WrongKey) => {
                            let keyfile = prompt_keyfile_path("keyfile path: ")?;
                            PageStore::open_with_keyfile_readonly(path, &keyfile)
                        }
                        Err(e) => Err(e),
                    }
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
                    match PageStore::open_with_recovery_key(path, &recovery) {
                        Ok(store) => Ok(store),
                        Err(TosumuError::WrongKey) => {
                            let keyfile = prompt_keyfile_path("keyfile path: ")?;
                            PageStore::open_with_keyfile(path, &keyfile)
                        }
                        Err(e) => Err(e),
                    }
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
                    match Pager::open_with_recovery_key_readonly(path, &recovery) {
                        Ok(pager) => Ok((pager, Some(UnlockSecret::RecoveryKey(recovery)))),
                        Err(TosumuError::WrongKey) => {
                            let keyfile = prompt_keyfile_path("keyfile path: ")?;
                            let pager = Pager::open_with_keyfile_readonly(path, &keyfile)?;
                            Ok((pager, Some(UnlockSecret::Keyfile(keyfile))))
                        }
                        Err(e) => Err(e),
                    }
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
        Some(UnlockSecret::Keyfile(keyfile)) => tosumu_core::btree::BTree::open_with_keyfile_readonly(path, keyfile),
    }
}

fn read_secret_from_stdin(empty_message: &'static str) -> Result<String, TosumuError> {
    use std::io::Read as _;

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).map_err(TosumuError::Io)?;
    let secret = input.trim_end_matches(&['\r', '\n'][..]).to_string();
    if secret.is_empty() {
        return Err(TosumuError::InvalidArgument(empty_message));
    }
    Ok(secret)
}

fn resolve_inspect_unlock(unlock: InspectUnlockArgs) -> Result<(Option<UnlockSecret>, bool), TosumuError> {
    let no_prompt = unlock.no_prompt;

    if unlock.stdin_passphrase {
        return Ok((Some(UnlockSecret::Passphrase(read_secret_from_stdin(
            "stdin passphrase must not be empty",
        )?)), no_prompt));
    }

    if unlock.stdin_recovery_key {
        return Ok((Some(UnlockSecret::RecoveryKey(read_secret_from_stdin(
            "stdin recovery key must not be empty",
        )?)), no_prompt));
    }

    if let Some(keyfile) = unlock.keyfile {
        return Ok((Some(UnlockSecret::Keyfile(keyfile)), no_prompt));
    }

    Ok((None, no_prompt))
}

fn open_pager_with_unlock(path: &Path, unlock: Option<UnlockSecret>, no_prompt: bool) -> Result<(Pager, Option<UnlockSecret>), TosumuError> {
    match unlock {
        None => {
            if no_prompt {
                let pager = Pager::open_readonly(path)?;
                Ok((pager, None))
            } else {
                open_pager(path)
            }
        }
        Some(UnlockSecret::Passphrase(pass)) => {
            let pager = Pager::open_with_passphrase_readonly(path, &pass)?;
            Ok((pager, Some(UnlockSecret::Passphrase(pass))))
        }
        Some(UnlockSecret::RecoveryKey(recovery)) => {
            let pager = Pager::open_with_recovery_key_readonly(path, &recovery)?;
            Ok((pager, Some(UnlockSecret::RecoveryKey(recovery))))
        }
        Some(UnlockSecret::Keyfile(keyfile)) => {
            let pager = Pager::open_with_keyfile_readonly(path, &keyfile)?;
            Ok((pager, Some(UnlockSecret::Keyfile(keyfile))))
        }
    }
}

/// Prompt for a passphrase without echoing.
fn prompt_passphrase(prompt: &str) -> Result<String, TosumuError> {
    rpassword::prompt_password(prompt)
        .map_err(|e| TosumuError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))
}

fn prompt_line(prompt: &str) -> Result<String, TosumuError> {
    let mut stdout = std::io::stdout();
    use std::io::Write as _;
    write!(stdout, "{prompt}").map_err(TosumuError::Io)?;
    stdout.flush().map_err(TosumuError::Io)?;

    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(TosumuError::Io)?;
    Ok(input.trim().to_string())
}

fn prompt_keyfile_path(prompt: &str) -> Result<PathBuf, TosumuError> {
    let input = prompt_line(prompt)?;
    if input.is_empty() {
        return Err(TosumuError::InvalidArgument("keyfile path must not be empty"));
    }
    Ok(PathBuf::from(input))
}

fn recovery_words(secret: &str) -> Vec<String> {
    secret
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect()
}

fn format_recovery_key_for_display(secret: &str) -> String {
    recovery_words(secret).join("-")
}

fn confirm_recovery_words(secret: &str, word3: &str, word7: &str) -> Result<(), TosumuError> {
    let words = recovery_words(secret);
    if words.len() < 7 {
        return Err(TosumuError::InvalidArgument("recovery key format is invalid"));
    }

    if word3.trim().to_ascii_uppercase() != words[2] || word7.trim().to_ascii_uppercase() != words[6] {
        return Err(TosumuError::InvalidArgument("recovery key confirmation failed"));
    }

    Ok(())
}

fn confirm_recovery_key_saved(secret: &str) -> Result<(), TosumuError> {
    println!();
    println!("=== RECOVERY KEY — save this somewhere safe ===");
    println!();
    println!("  {}", format_recovery_key_for_display(secret));
    println!();
    println!("This key will NOT be shown again.");
    println!("Confirm you recorded it.");

    let word3 = prompt_line("Type word 3: ")?.to_ascii_uppercase();
    let word7 = prompt_line("Type word 7: ")?.to_ascii_uppercase();
    confirm_recovery_words(secret, &word3, &word7)
}

fn render_json<T: Serialize>(value: &T) -> Result<String, TosumuError> {
    serde_json::to_string_pretty(value)
        .map_err(|e| TosumuError::Io(std::io::Error::other(e.to_string())))
}

fn keyslot_kind_name(kind: u8) -> &'static str {
    match kind {
        tosumu_core::format::KEYSLOT_KIND_EMPTY => "Empty",
        tosumu_core::format::KEYSLOT_KIND_SENTINEL => "Sentinel",
        tosumu_core::format::KEYSLOT_KIND_PASSPHRASE => "Passphrase",
        tosumu_core::format::KEYSLOT_KIND_RECOVERY_KEY => "RecoveryKey",
        tosumu_core::format::KEYSLOT_KIND_KEYFILE => "Keyfile",
        _ => "Unknown",
    }
}

fn page_type_name(page_type: u8) -> &'static str {
    match page_type {
        tosumu_core::format::PAGE_TYPE_LEAF => "Leaf",
        tosumu_core::format::PAGE_TYPE_INTERNAL => "Internal",
        tosumu_core::format::PAGE_TYPE_OVERFLOW => "Overflow",
        tosumu_core::format::PAGE_TYPE_FREE => "Free",
        _ => "Unknown",
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn inspect_error_payload(error: &TosumuError) -> InspectErrorPayload {
    match error {
        TosumuError::WrongKey => InspectErrorPayload {
            kind: "wrong_key",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::AuthFailed { pgno } => InspectErrorPayload {
            kind: "auth_failed",
            message: error.to_string(),
            pgno: *pgno,
        },
        TosumuError::Corrupt { pgno, .. } => InspectErrorPayload {
            kind: "corrupt",
            message: error.to_string(),
            pgno: Some(*pgno),
        },
        TosumuError::InvalidArgument(_) => InspectErrorPayload {
            kind: "invalid_argument",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::FileBusy { .. } => InspectErrorPayload {
            kind: "file_busy",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::NotATosumFile
        | TosumuError::NewerFormat { .. }
        | TosumuError::PageSizeMismatch { .. } => InspectErrorPayload {
            kind: "unsupported",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::CorruptRecord { .. }
        | TosumuError::Io(_)
        | TosumuError::EncryptFailed
        | TosumuError::RngFailed
        | TosumuError::FileTruncated { .. }
        | TosumuError::Poisoned
        | TosumuError::OutOfSpace
        | TosumuError::CommittedButFlushFailed { .. } => InspectErrorPayload {
            kind: "io",
            message: error.to_string(),
            pgno: None,
        },
        _ => InspectErrorPayload {
            kind: "unsupported",
            message: error.to_string(),
            pgno: None,
        },
    }
}

fn render_inspect_error_json(command: &'static str, error: &TosumuError) -> String {
    render_json(&InspectEnvelope::<()> {
        schema_version: 1,
        command,
        ok: false,
        payload: None,
        error: Some(inspect_error_payload(error)),
    }).unwrap_or_else(|serialization_error| {
        format!(
            "{{\"schema_version\":1,\"command\":\"{command}\",\"ok\":false,\"error\":{{\"kind\":\"io\",\"message\":{:?}}}}}",
            serialization_error.to_string()
        )
    })
}

fn cmd_inspect_header_json(path: &Path) -> Result<String, TosumuError> {
    let header = tosumu_core::inspect::read_header_info(path)?;
    render_json(&InspectEnvelope {
        schema_version: 1,
        command: "inspect.header",
        ok: true,
        payload: Some(InspectHeaderPayload {
            format_version: header.format_version,
            page_size: header.page_size,
            min_reader_version: header.min_reader_version,
            flags: header.flags,
            page_count: header.page_count,
            freelist_head: header.freelist_head,
            root_page: header.root_page,
            wal_checkpoint_lsn: header.wal_checkpoint_lsn,
            dek_id: header.dek_id,
            keyslot_count: header.keyslot_count,
            keyslot_region_pages: header.keyslot_region_pages,
            slot0: InspectKeyslotPayload {
                kind: keyslot_kind_name(header.ks0_kind),
                kind_byte: header.ks0_kind,
                version: header.ks0_version,
            },
        }),
        error: None,
    })
}

struct VerifySnapshot {
    report: tosumu_core::inspect::VerifyReport,
    btree: InspectBtreeVerifyPayload,
}

fn collect_verify_snapshot(path: &Path, unlock: Option<UnlockSecret>, no_prompt: bool) -> Result<VerifySnapshot, TosumuError> {
    let (pager, unlock) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let report = tosumu_core::inspect::verify_pager(&pager)?;
    let btree = if report.issues.is_empty() {
        match open_btree_with_unlock(path, unlock.as_ref()) {
            Ok(tree) => match tree.check_invariants() {
                Ok(()) => InspectBtreeVerifyPayload {
                    checked: true,
                    ok: true,
                    message: None,
                },
                Err(error) => InspectBtreeVerifyPayload {
                    checked: true,
                    ok: false,
                    message: Some(error.to_string()),
                },
            },
            Err(error) => InspectBtreeVerifyPayload {
                checked: false,
                ok: false,
                message: Some(format!("could not open as BTree: {error}")),
            },
        }
    } else {
        InspectBtreeVerifyPayload {
            checked: false,
            ok: false,
            message: Some("skipped because page integrity issues were found".to_string()),
        }
    };

    Ok(VerifySnapshot { report, btree })
}

fn cmd_inspect_verify_json(path: &Path, unlock: Option<UnlockSecret>, no_prompt: bool) -> Result<String, TosumuError> {
    let snapshot = collect_verify_snapshot(path, unlock, no_prompt)?;
    render_json(&InspectEnvelope {
        schema_version: 1,
        command: "inspect.verify",
        ok: snapshot.report.issues.is_empty() && (!snapshot.btree.checked || snapshot.btree.ok),
        payload: Some(InspectVerifyPayload {
            pages_checked: snapshot.report.pages_checked,
            pages_ok: snapshot.report.pages_ok,
            issue_count: snapshot.report.issues.len(),
            issues: snapshot.report.issues.into_iter().map(|issue| InspectVerifyIssuePayload {
                pgno: issue.pgno,
                description: issue.description,
            }).collect(),
            page_results: snapshot.report.page_results.into_iter().map(|result| InspectPageVerifyPayload {
                pgno: result.pgno,
                page_version: result.page_version,
                auth_ok: result.auth_ok,
                issue: result.issue,
            }).collect(),
            btree: snapshot.btree,
        }),
        error: None,
    })
}

fn cmd_inspect_page_json(path: &Path, pgno: u64, unlock: Option<UnlockSecret>, no_prompt: bool) -> Result<String, TosumuError> {
    let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let page = tosumu_core::inspect::inspect_page_from_pager(&pager, pgno)?;
    render_json(&InspectEnvelope {
        schema_version: 1,
        command: "inspect.page",
        ok: true,
        payload: Some(InspectPagePayload {
            pgno: page.pgno,
            page_version: page.page_version,
            page_type: page.page_type,
            page_type_name: page_type_name(page.page_type),
            slot_count: page.slot_count,
            free_start: page.free_start,
            free_end: page.free_end,
            records: page.records.into_iter().map(|record| match record {
                tosumu_core::inspect::RecordInfo::Live { key, value } => InspectRecordPayload {
                    kind: "Live",
                    key_hex: Some(bytes_to_hex(&key)),
                    value_hex: Some(bytes_to_hex(&value)),
                    slot: None,
                    record_type: None,
                },
                tosumu_core::inspect::RecordInfo::Tombstone { key } => InspectRecordPayload {
                    kind: "Tombstone",
                    key_hex: Some(bytes_to_hex(&key)),
                    value_hex: None,
                    slot: None,
                    record_type: None,
                },
                tosumu_core::inspect::RecordInfo::Unknown { slot, record_type } => InspectRecordPayload {
                    kind: "Unknown",
                    key_hex: None,
                    value_hex: None,
                    slot: Some(slot),
                    record_type: Some(record_type),
                },
            }).collect(),
        }),
        error: None,
    })
}

fn cmd_inspect_pages_json(path: &Path, unlock: Option<UnlockSecret>, no_prompt: bool) -> Result<String, TosumuError> {
    let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let pages = tosumu_core::inspect::inspect_pages_from_pager(&pager)?;
    render_json(&InspectEnvelope {
        schema_version: 1,
        command: "inspect.pages",
        ok: pages.pages.iter().all(|page| matches!(page.state, tosumu_core::inspect::PageInspectState::Ok)),
        payload: Some(InspectPagesPayload {
            pages: pages.pages.into_iter().map(|page| InspectPagesEntryPayload {
                pgno: page.pgno,
                page_version: page.page_version,
                page_type: page.page_type,
                page_type_name: page.page_type.map(page_type_name),
                slot_count: page.slot_count,
                state: match page.state {
                    tosumu_core::inspect::PageInspectState::Ok => "ok",
                    tosumu_core::inspect::PageInspectState::AuthFailed => "auth_failed",
                    tosumu_core::inspect::PageInspectState::Corrupt => "corrupt",
                    tosumu_core::inspect::PageInspectState::Io => "io",
                },
                issue: page.issue,
            }).collect(),
        }),
        error: None,
    })
}

fn map_tree_node_payload(node: tosumu_core::inspect::TreeNodeSummary) -> InspectTreeNodePayload {
    InspectTreeNodePayload {
        pgno: node.pgno,
        page_version: node.page_version,
        page_type: node.page_type,
        page_type_name: page_type_name(node.page_type),
        slot_count: node.slot_count,
        free_start: node.free_start,
        free_end: node.free_end,
        next_leaf: node.next_leaf,
        children: node.children.into_iter().map(|child| InspectTreeChildPayload {
            relation: match child.relation {
                tosumu_core::inspect::TreeChildRelation::Leftmost => "leftmost",
                tosumu_core::inspect::TreeChildRelation::Separator => "separator",
            },
            separator_key_hex: child.separator_key.as_ref().map(|key| bytes_to_hex(key)),
            child: Box::new(map_tree_node_payload(*child.child)),
        }).collect(),
    }
}

fn cmd_inspect_tree_json(path: &Path, unlock: Option<UnlockSecret>, no_prompt: bool) -> Result<String, TosumuError> {
    let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let tree = tosumu_core::inspect::inspect_tree_from_pager(&pager)?;
    render_json(&InspectEnvelope {
        schema_version: 1,
        command: "inspect.tree",
        ok: true,
        payload: Some(InspectTreePayload {
            root_pgno: tree.root_pgno,
            root: map_tree_node_payload(tree.root),
        }),
        error: None,
    })
}

fn cmd_inspect_protectors_json(path: &Path) -> Result<String, TosumuError> {
    let slots = PageStore::list_keyslots(path)?;
    render_json(&InspectEnvelope {
        schema_version: 1,
        command: "inspect.protectors",
        ok: true,
        payload: Some(InspectProtectorsPayload {
            slot_count: slots.len(),
            slots: slots.into_iter().map(|(slot, kind)| InspectProtectorSlotPayload {
                slot,
                kind: keyslot_kind_name(kind),
                kind_byte: kind,
            }).collect(),
        }),
        error: None,
    })
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
        Command::Dump { path, page } => cmd_dump(&path, page, None, false)?,
        Command::Hex  { path, page } => cmd_hex(&path, page)?,
        Command::Verify { path, explain } => cmd_verify(&path, explain, None, false)?,
        Command::View { path } => view::run(&path)?,
        Command::Inspect { action } => match action {
            InspectAction::Header { path, json } => {
                if json {
                    println!("{}", cmd_inspect_header_json(&path)?);
                } else {
                    cmd_dump(&path, None, None, false)?;
                }
            }
            InspectAction::Verify { path, json, unlock } => {
                let (unlock, no_prompt) = resolve_inspect_unlock(unlock)?;
                if json {
                    println!("{}", cmd_inspect_verify_json(&path, unlock, no_prompt)?);
                } else {
                    cmd_verify(&path, false, unlock, no_prompt)?;
                }
            }
            InspectAction::Pages { path, json, unlock } => {
                let (unlock, no_prompt) = resolve_inspect_unlock(unlock)?;
                let pages_json = cmd_inspect_pages_json(&path, unlock, no_prompt)?;
                if json {
                    println!("{pages_json}");
                } else {
                    println!("{pages_json}");
                }
            }
            InspectAction::Page { path, page, json, unlock } => {
                let (unlock, no_prompt) = resolve_inspect_unlock(unlock)?;
                if json {
                    println!("{}", cmd_inspect_page_json(&path, page, unlock, no_prompt)?);
                } else {
                    cmd_dump(&path, Some(page), unlock, no_prompt)?;
                }
            }
            InspectAction::Tree { path, json, unlock } => {
                let (unlock, no_prompt) = resolve_inspect_unlock(unlock)?;
                let tree_json = cmd_inspect_tree_json(&path, unlock, no_prompt)?;
                if json {
                    println!("{tree_json}");
                } else {
                    println!("{tree_json}");
                }
            }
            InspectAction::Protectors { path, json } => {
                if json {
                    println!("{}", cmd_inspect_protectors_json(&path)?);
                } else {
                    cmd_dump(&path, None, None, false)?;
                }
            }
        },
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
                let key = tosumu_core::crypto::generate_recovery_secret();
                confirm_recovery_key_saved(&key)?;
                match PageStore::add_recovery_key_protector_with_secret(&path, &unlock, &key) {
                    Ok(()) => {}
                    Err(TosumuError::WrongKey) => {
                        let recovery = prompt_passphrase("recovery key: ")?;
                        match PageStore::add_recovery_key_protector_with_recovery_key_and_secret(&path, &recovery, &key) {
                            Ok(()) => {}
                            Err(TosumuError::WrongKey) => {
                                let current_keyfile = prompt_keyfile_path("current keyfile path: ")?;
                                PageStore::add_recovery_key_protector_with_keyfile_and_secret(&path, &current_keyfile, &key)?;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(e) => return Err(e),
                }
                println!("recovery protector added");
            }
            ProtectorAction::AddKeyfile { path, keyfile } => {
                let unlock = prompt_passphrase("current passphrase: ")?;
                let slot = match PageStore::add_keyfile_protector(&path, &unlock, &keyfile) {
                    Ok(slot) => slot,
                    Err(TosumuError::WrongKey) => {
                        let recovery = prompt_passphrase("recovery key: ")?;
                        match PageStore::add_keyfile_protector_with_recovery_key(&path, &recovery, &keyfile) {
                            Ok(slot) => slot,
                            Err(TosumuError::WrongKey) => {
                                let current_keyfile = prompt_keyfile_path("current keyfile path: ")?;
                                PageStore::add_keyfile_protector_with_keyfile(&path, &current_keyfile, &keyfile)?
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(e) => return Err(e),
                };
                println!("protector added at slot {slot}");
            }
            ProtectorAction::Remove { path, slot } => {
                let unlock = prompt_passphrase("passphrase: ")?;
                match PageStore::remove_keyslot(&path, &unlock, slot) {
                    Ok(()) => {}
                    Err(TosumuError::WrongKey) => {
                        let recovery = prompt_passphrase("recovery key: ")?;
                        match PageStore::remove_keyslot_with_recovery_key(&path, &recovery, slot) {
                            Ok(()) => {}
                            Err(TosumuError::WrongKey) => {
                                let keyfile = prompt_keyfile_path("keyfile path: ")?;
                                PageStore::remove_keyslot_with_keyfile(&path, &keyfile, slot)?;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    Err(e) => return Err(e),
                }
                println!("slot {slot} removed");
            }
            ProtectorAction::List { path } => {
                use tosumu_core::format::{
                    KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_SENTINEL,
                    KEYSLOT_KIND_PASSPHRASE, KEYSLOT_KIND_RECOVERY_KEY, KEYSLOT_KIND_KEYFILE,
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
                            KEYSLOT_KIND_KEYFILE      => "Keyfile",
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
                    match PageStore::rekey_kek_with_recovery_key(&path, slot, &recovery, &new1) {
                        Ok(()) => {}
                        Err(TosumuError::WrongKey) => {
                            let keyfile = prompt_keyfile_path("keyfile path: ")?;
                            PageStore::rekey_kek_with_keyfile(&path, slot, &keyfile, &new1)?;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
            println!("slot {slot} KEK rotated");
        }
    }
    Ok(())
}

// ── dump ─────────────────────────────────────────────────────────────────────

fn cmd_dump(path: &std::path::Path, page: Option<u64>, unlock: Option<UnlockSecret>, no_prompt: bool) -> tosumu_core::error::Result<()> {
    use tosumu_core::format::{
        PAGE_TYPE_LEAF, PAGE_TYPE_INTERNAL, PAGE_TYPE_OVERFLOW, PAGE_TYPE_FREE,
        KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_SENTINEL, KEYSLOT_KIND_PASSPHRASE,
        KEYSLOT_KIND_RECOVERY_KEY, KEYSLOT_KIND_KEYFILE,
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
                KEYSLOT_KIND_RECOVERY_KEY => "RecoveryKey",
                KEYSLOT_KIND_KEYFILE    => "Keyfile",
                _                       => "Unknown",
            };
            let kind_note = match h.ks0_kind {
                KEYSLOT_KIND_SENTINEL   => "  (plaintext DEK — authentication only, no confidentiality)",
                KEYSLOT_KIND_PASSPHRASE => "  (Argon2id KDF — authentication + confidentiality)",
                KEYSLOT_KIND_RECOVERY_KEY => "  (Base32 recovery secret → HKDF-derived KEK)",
                KEYSLOT_KIND_KEYFILE    => "  (raw 32-byte KEK loaded from a file)",
                _ => "",
            };
            println!("kind:    {kind_name}{kind_note}");
            println!("version: {}", h.ks0_version);
        }
        Some(pgno) => {
            let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
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

fn cmd_verify(path: &std::path::Path, explain: bool, unlock: Option<UnlockSecret>, no_prompt: bool) -> tosumu_core::error::Result<()> {
    let snapshot = collect_verify_snapshot(path, unlock, no_prompt)?;
    let report = snapshot.report;
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
        if snapshot.btree.checked && snapshot.btree.ok {
            if explain {
                println!("  btree:       OK     — keys sorted, routing correct, leaf chain ordered");
            }
        } else if let Some(message) = &snapshot.btree.message {
            if snapshot.btree.checked {
                eprintln!("  btree:       FAIL   — {message}");
                eprintln!("FAILED: btree structural invariant violated");
                std::process::exit(1);
            } else if explain {
                eprintln!("  btree:       SKIP   — {message}");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_words_rechunk_into_eight_groups_of_four() {
        let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
        let words = recovery_words(secret);
        assert_eq!(words, vec![
            "ABCD", "EFGH", "IJKL", "MNOP", "QRST", "UVWX", "YZ23", "4567",
        ]);
    }

    #[test]
    fn recovery_display_uses_eight_groups_of_four() {
        let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
        assert_eq!(
            format_recovery_key_for_display(secret),
            "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"
        );
    }

    #[test]
    fn recovery_confirmation_accepts_correct_words() {
        let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
        confirm_recovery_words(secret, "ijkl", "yz23").unwrap();
    }

    #[test]
    fn recovery_confirmation_rejects_wrong_words() {
        let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
        let err = confirm_recovery_words(secret, "WRONG", "YZ23").unwrap_err();
        assert!(matches!(err, TosumuError::InvalidArgument("recovery key confirmation failed")));
    }

    #[test]
    fn cli_parses_add_keyfile_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "protector",
            "add-keyfile",
            "db.tsm",
            "db.key",
        ]).unwrap();

        match cli.command {
            Command::Protector { action: ProtectorAction::AddKeyfile { path, keyfile } } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert_eq!(keyfile, PathBuf::from("db.key"));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_add_recovery_key_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "protector",
            "add-recovery-key",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Protector { action: ProtectorAction::AddRecoveryKey { path } } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_header_json_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "header",
            "--json",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Header { path, json },
            } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert!(json);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_verify_json_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "verify",
            "--json",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Verify { path, json, unlock },
            } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert!(json);
                assert!(!unlock.no_prompt);
                assert!(!unlock.stdin_passphrase);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_pages_json_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "pages",
            "--json",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Pages { path, json, unlock },
            } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert!(json);
                assert!(!unlock.no_prompt);
                assert!(!unlock.stdin_passphrase);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_page_json_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "page",
            "--page",
            "1",
            "--json",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Page { path, page, json, unlock },
            } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert_eq!(page, 1);
                assert!(json);
                assert!(!unlock.no_prompt);
                assert!(!unlock.stdin_passphrase);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_protectors_json_subcommand() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "protectors",
            "--json",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Protectors { path, json },
            } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert!(json);
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_verify_with_stdin_passphrase() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "verify",
            "--json",
            "--stdin-passphrase",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Verify { path, json, unlock },
            } => {
                assert_eq!(path, PathBuf::from("db.tsm"));
                assert!(json);
                assert!(unlock.stdin_passphrase);
                assert!(!unlock.no_prompt);
                assert!(!unlock.stdin_recovery_key);
                assert!(unlock.keyfile.is_none());
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn cli_parses_inspect_verify_with_no_prompt() {
        let cli = Cli::try_parse_from([
            "tosumu",
            "inspect",
            "verify",
            "--json",
            "--no-prompt",
            "db.tsm",
        ]).unwrap();

        match cli.command {
            Command::Inspect {
                action: InspectAction::Verify { unlock, .. },
            } => {
                assert!(unlock.no_prompt);
                assert!(!unlock.stdin_passphrase);
                assert!(!unlock.stdin_recovery_key);
                assert!(unlock.keyfile.is_none());
            }
            _ => panic!("unexpected command variant"),
        }
    }

    #[test]
    fn inspect_header_json_uses_structured_success_envelope() {
        let path = temp_path("inspect_header_json_success");
        let _ = std::fs::remove_file(&path);
        PageStore::create(&path).unwrap();

        let rendered = cmd_inspect_header_json(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.header");
        assert_eq!(json["ok"], true);
        assert_eq!(json["payload"]["page_size"], 4096);
        assert_eq!(json["payload"]["slot0"]["kind"], "Sentinel");
        assert_eq!(json["payload"]["slot0"]["kind_byte"], 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_error_json_uses_structured_error_envelope() {
        let rendered = render_inspect_error_json(
            "inspect.header",
            &TosumuError::InvalidArgument("page number out of range"),
        );
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.header");
        assert_eq!(json["ok"], false);
        assert_eq!(json["error"]["kind"], "invalid_argument");
        assert_eq!(json["error"]["message"], "invalid argument: page number out of range");
        assert!(json["payload"].is_null());
    }

    #[test]
    fn inspect_verify_json_uses_structured_success_envelope() {
        let path = temp_path("inspect_verify_json_success");
        let _ = std::fs::remove_file(&path);
        PageStore::create(&path).unwrap();

        let rendered = cmd_inspect_verify_json(&path, None, false).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.verify");
        assert_eq!(json["ok"], true);
        assert_eq!(json["payload"]["issues"].as_array().unwrap().len(), 0);
        assert_eq!(json["payload"]["btree"]["checked"], true);
        assert_eq!(json["payload"]["btree"]["ok"], true);
        assert!(json["payload"]["btree"]["message"].is_null());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_page_json_uses_structured_success_envelope() {
        let path = temp_path("inspect_page_json_success");
        let _ = std::fs::remove_file(&path);
        let mut store = PageStore::create(&path).unwrap();
        store.put(b"alpha", b"one").unwrap();

        let rendered = cmd_inspect_page_json(&path, 1, None, false).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.page");
        assert_eq!(json["ok"], true);
        assert_eq!(json["payload"]["pgno"], 1);
        assert_eq!(json["payload"]["page_type_name"], "Leaf");
        assert!(json["payload"]["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|record| record["kind"] == "Live"
                && record["key_hex"] == "616c706861"
                && record["value_hex"] == "6f6e65"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_protectors_json_uses_structured_success_envelope() {
        let path = temp_path("inspect_protectors_json_success");
        let _ = std::fs::remove_file(&path);
        PageStore::create_encrypted(&path, "correct-horse").unwrap();

        let rendered = cmd_inspect_protectors_json(&path).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.protectors");
        assert_eq!(json["ok"], true);
        assert_eq!(json["payload"]["slot_count"], 1);
        assert_eq!(json["payload"]["slots"][0]["slot"], 0);
        assert_eq!(json["payload"]["slots"][0]["kind"], "Passphrase");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_verify_json_accepts_explicit_passphrase_unlock() {
        let path = temp_path("inspect_verify_json_passphrase_unlock");
        let _ = std::fs::remove_file(&path);
        let mut store = PageStore::create_encrypted(&path, "correct-horse").unwrap();
        store.put(b"alpha", b"one").unwrap();

        let rendered = cmd_inspect_verify_json(&path, Some(UnlockSecret::Passphrase("correct-horse".to_string())), false).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.verify");
        assert_eq!(json["ok"], true);
        assert_eq!(json["payload"]["issue_count"], 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_page_json_accepts_explicit_passphrase_unlock() {
        let path = temp_path("inspect_page_json_passphrase_unlock");
        let _ = std::fs::remove_file(&path);
        let mut store = PageStore::create_encrypted(&path, "correct-horse").unwrap();
        store.put(b"alpha", b"one").unwrap();

        let rendered = cmd_inspect_page_json(&path, 1, Some(UnlockSecret::Passphrase("correct-horse".to_string())), false).unwrap();
        let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["command"], "inspect.page");
        assert_eq!(json["ok"], true);
        assert_eq!(json["payload"]["page_type_name"], "Leaf");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_verify_json_no_prompt_returns_wrong_key_for_encrypted_db() {
        let path = temp_path("inspect_verify_json_no_prompt_wrong_key");
        let _ = std::fs::remove_file(&path);
        PageStore::create_encrypted(&path, "correct-horse").unwrap();

        let err = cmd_inspect_verify_json(&path, None, true).err().unwrap();

        assert!(matches!(err, TosumuError::WrongKey));

        let _ = std::fs::remove_file(&path);
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tosumu-cli-{name}-{}-{}.tsm",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
