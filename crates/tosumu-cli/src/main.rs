//! `tosumu` command-line interface — MVP +8.
//!
//! Key management plus the first interactive inspection slice.
//! See DESIGN.md §12.0 (MVP +8).

use std::path::PathBuf;
use clap::{ArgGroup, Args, Parser, Subcommand};
use tosumu_core::error::ErrorValue;

mod commands;
mod error_boundary;
mod inspect_contract;
#[cfg(test)]
mod inspect_cli_tests;
mod unlock;
mod view;
#[cfg(test)]
mod cli_tests;

use commands::run;
use error_boundary::CliError;
use inspect_contract::*;

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

#[derive(Args, Clone, Default)]
struct InspectJsonArgs {
    /// Emit a structured JSON envelope.
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Copy)]
struct InspectJsonContract {
    command: &'static str,
}

#[derive(Parser)]
#[command(name = tosumu_core::NAME, version, about = "tosumu key-value store (MVP +8)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn json_error_contract(&self) -> Option<InspectJsonContract> {
        match &self.command {
            Command::Inspect {
                action: InspectAction::Header {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.header" }),
            Command::Inspect {
                action: InspectAction::Verify {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.verify" }),
            Command::Inspect {
                action: InspectAction::Pages {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.pages" }),
            Command::Inspect {
                action: InspectAction::Wal {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.wal" }),
            Command::Inspect {
                action: InspectAction::Page {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.page" }),
            Command::Inspect {
                action: InspectAction::Tree {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.tree" }),
            Command::Inspect {
                action: InspectAction::Protectors {
                    json: InspectJsonArgs { json: true },
                    ..
                },
            } => Some(InspectJsonContract { command: "inspect.protectors" }),
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
    #[command(
        long_about = "Open the read-only interactive inspection view.\n\nThe viewer shows header, page detail, verify, tree, WAL, and protector panels for an existing database. It never mutates the database.\n\nUse --watch to periodically refresh the current snapshot when the database or WAL changes.",
        after_help = "Interactive keys:\n  /      filter the page list using page metadata and decoded record text\n  n/N    move to the next or previous filter match\n  :      jump to a page number\n  Tab    switch focus between the page list and the active panel\n  j/k    move within the active pane (arrows also work)\n  PgUp/PgDn, g/G, Home/End navigate faster\n  1-6    switch panels\n  w      toggle watch mode\n  q      quit"
    )]
    /// Open the read-only interactive inspection view.
    View {
        path: PathBuf,
        /// Periodically reload header, page, tree, WAL, and verification data.
        #[arg(long)]
        watch: bool,
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
        #[command(flatten)]
        json: InspectJsonArgs,
    },
    /// Inspect page-auth verification results.
    Verify {
        path: PathBuf,
        #[command(flatten)]
        json: InspectJsonArgs,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect lightweight summaries for every data page.
    Pages {
        path: PathBuf,
        #[command(flatten)]
        json: InspectJsonArgs,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect a single decoded page.
    Page {
        path: PathBuf,
        /// Page number to inspect.
        #[arg(long)]
        page: u64,
        #[command(flatten)]
        json: InspectJsonArgs,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect the WAL sidecar if present.
    Wal {
        path: PathBuf,
        #[command(flatten)]
        json: InspectJsonArgs,
    },
    /// Inspect the B-tree structure rooted at the current root page.
    Tree {
        path: PathBuf,
        #[command(flatten)]
        json: InspectJsonArgs,
        #[command(flatten)]
        unlock: InspectUnlockArgs,
    },
    /// Inspect configured protectors / keyslots.
    Protectors {
        path: PathBuf,
        #[command(flatten)]
        json: InspectJsonArgs,
    },
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
    let json_error_contract = cli.json_error_contract();
    let operation = cli.operation_name();

    match run(cli) {
        Ok(outcome) => {
            let exit_code = outcome.exit_code();
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Err(e) => {
            log_cli_error(&e, operation);
            if let Some(contract) = json_error_contract {
                println!(
                    "{}",
                    render_inspect_error_report_json(
                        contract.command,
                        &e.error_report(),
                    )
                );
            } else {
                eprintln!("{}", render_cli_error(&e));
            }
            std::process::exit(exit_code_for_error(&e));
        }
    }
}

impl Cli {
    fn operation_name(&self) -> &'static str {
        match &self.command {
            Command::Init { .. } => "init",
            Command::Put { .. } => "put",
            Command::Get { .. } => "get",
            Command::Delete { .. } => "delete",
            Command::Scan { .. } => "scan",
            Command::Stat { .. } => "stat",
            Command::Dump { .. } => "dump",
            Command::Hex { .. } => "hex",
            Command::Verify { .. } => "verify",
            Command::View { .. } => "view",
            Command::Backup { .. } => "backup",
            Command::Protector { action } => match action {
                ProtectorAction::AddPassphrase { .. } => "protector.add-passphrase",
                ProtectorAction::AddRecoveryKey { .. } => "protector.add-recovery-key",
                ProtectorAction::AddKeyfile { .. } => "protector.add-keyfile",
                ProtectorAction::Remove { .. } => "protector.remove",
                ProtectorAction::List { .. } => "protector.list",
            },
            Command::RekeyKek { .. } => "rekey-kek",
            Command::Inspect { action } => match action {
                InspectAction::Header { .. } => "inspect.header",
                InspectAction::Verify { .. } => "inspect.verify",
                InspectAction::Pages { .. } => "inspect.pages",
                InspectAction::Page { .. } => "inspect.page",
                InspectAction::Wal { .. } => "inspect.wal",
                InspectAction::Tree { .. } => "inspect.tree",
                InspectAction::Protectors { .. } => "inspect.protectors",
            },
        }
    }
}

fn exit_code_for_error(error: &CliError) -> i32 {
    match error.error_report().status {
        tosumu_core::error::ErrorStatus::InvalidInput => 2,
        tosumu_core::error::ErrorStatus::NotFound => 4,
        tosumu_core::error::ErrorStatus::PermissionDenied => 5,
        tosumu_core::error::ErrorStatus::Conflict => 6,
        tosumu_core::error::ErrorStatus::Unsupported => 7,
        tosumu_core::error::ErrorStatus::Busy => 8,
        tosumu_core::error::ErrorStatus::ExternalFailure => 9,
        tosumu_core::error::ErrorStatus::IntegrityFailure => 10,
        tosumu_core::error::ErrorStatus::Internal => 1,
    }
}

fn render_cli_error(error: &CliError) -> String {
    let report = error.error_report();
    format!("error [{}]: {}", report.code, report.message)
}

fn log_cli_error(error: &CliError, operation: &'static str) {
    if !cli_error_logging_enabled() {
        return;
    }

    eprintln!("{}", render_cli_error_log(error, operation));
}

fn cli_error_logging_enabled() -> bool {
    matches!(
        std::env::var("TOSUMU_LOG_ERRORS").ok().as_deref(),
        Some(value) if cli_error_logging_enabled_value(value)
    )
}

fn cli_error_logging_enabled_value(value: &str) -> bool {
    value.eq_ignore_ascii_case("1")
        || value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value.eq_ignore_ascii_case("on")
}

fn render_cli_error_log(error: &CliError, operation: &'static str) -> String {
    let report = error.error_report();
    let mut parts = vec![
        "event=boundary_error".to_string(),
        format!("code={}", report.code),
        format!("status={}", report.status.as_str()),
        format!("message={}", log_string_value(&report.message)),
        format!("operation={operation}"),
    ];

    for detail in &report.details {
        let key = match detail.key {
            "event" | "code" | "status" | "message" | "operation" | "source" => {
                format!("detail_{}", detail.key)
            }
            _ => detail.key.to_string(),
        };
        parts.push(format!("{}={}", key, log_error_value(&detail.value)));
    }

    if let Some(source) = cli_error_source(error) {
        parts.push(format!("source={}", log_string_value(&source)));
    }

    parts.join(" ")
}

fn cli_error_source(error: &CliError) -> Option<String> {
    match error {
        CliError::Core(tosumu_core::error::TosumuError::Io(source)) => Some(source.to_string()),
        _ => None,
    }
}

fn log_error_value(value: &ErrorValue) -> String {
    match value {
        ErrorValue::Bool(value) => value.to_string(),
        ErrorValue::Str(value) => log_string_value(value),
        ErrorValue::U16(value) => value.to_string(),
        ErrorValue::U64(value) => value.to_string(),
    }
}

fn log_string_value(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}
