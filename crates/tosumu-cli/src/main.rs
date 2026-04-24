//! `tosumu` command-line interface — MVP +1.
//!
//! Real page-based format with Sentinel AEAD. See DESIGN.md §12.0 (MVP +1).

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
    }
    Ok(())
}

