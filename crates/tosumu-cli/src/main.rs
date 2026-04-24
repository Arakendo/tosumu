//! `tosumu` command-line interface — MVP 0.
//!
//! Append-only log store. No pages, no AEAD. See DESIGN.md §12.0 (MVP 0).

use std::path::PathBuf;
use clap::{Parser, Subcommand};
use tosumu_core::log_store::LogStore;

#[derive(Parser)]
#[command(name = tosumu_core::NAME, version, about = "tosumu key-value store (MVP 0)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
        Command::Put { path, key, value } => {
            let mut store = LogStore::open(&path)?;
            store.put(key.as_bytes(), value.as_bytes())?;
        }
        Command::Get { path, key } => {
            let store = LogStore::open(&path)?;
            match store.get(key.as_bytes()) {
                Some(v) => println!("{}", String::from_utf8_lossy(v)),
                None => {
                    eprintln!("not found");
                    std::process::exit(1);
                }
            }
        }
        Command::Delete { path, key } => {
            let mut store = LogStore::open(&path)?;
            store.delete(key.as_bytes())?;
        }
        Command::Scan { path } => {
            let store = LogStore::open(&path)?;
            let mut pairs: Vec<(&[u8], &[u8])> = store.scan().collect();
            pairs.sort_unstable_by_key(|(k, _)| *k);
            for (k, v) in pairs {
                println!("{}\t{}", String::from_utf8_lossy(k), String::from_utf8_lossy(v));
            }
        }
    }
    Ok(())
}

