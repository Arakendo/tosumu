use std::path::Path;

use crate::error_boundary::CliError;
use tosumu_core::page_store::PageStore;

use crate::unlock::{open_store_readonly, open_store_writable, prompt_passphrase};

pub(crate) fn run_init(path: &Path, encrypt: bool) -> Result<(), CliError> {
    if encrypt {
        let pass = prompt_passphrase("new passphrase: ")?;
        let confirm = prompt_passphrase("confirm passphrase: ")?;
        if pass != confirm {
            return Err(CliError::passphrases_do_not_match());
        }
        PageStore::create_encrypted(path, &pass)?;
        println!("initialized {} (passphrase-protected)", path.display());
        println!();
        println!("NOTE: Tosumu is always authenticated. With a passphrase protector,");
        println!("      the database is also confidential. Without one, it provides");
        println!("      integrity only — a local reader with file access can read the data.");
    } else {
        PageStore::create(path)?;
        println!(
            "initialized {} (sentinel protector — authentication only, no passphrase)",
            path.display()
        );
    }

    Ok(())
}

pub(crate) fn run_put(path: &Path, key: &str, value: &str) -> Result<(), CliError> {
    let mut store = open_store_writable(path)?;
    store.put(key.as_bytes(), value.as_bytes())?;
    Ok(())
}

pub(crate) fn run_get(path: &Path, key: &str) -> Result<(), CliError> {
    let store = open_store_readonly(path)?;
    match store.get(key.as_bytes())? {
        Some(value) => println!("{}", String::from_utf8_lossy(&value)),
        None => return Err(CliError::key_not_found(key)),
    }

    Ok(())
}

pub(crate) fn run_delete(path: &Path, key: &str) -> Result<(), CliError> {
    let mut store = open_store_writable(path)?;
    store.delete(key.as_bytes())?;
    Ok(())
}

pub(crate) fn run_scan(path: &Path) -> Result<(), CliError> {
    let store = open_store_readonly(path)?;
    for (key, value) in store.scan()? {
        println!(
            "{}\t{}",
            String::from_utf8_lossy(&key),
            String::from_utf8_lossy(&value)
        );
    }
    Ok(())
}

pub(crate) fn run_stat(path: &Path) -> Result<(), CliError> {
    let store = open_store_readonly(path)?;
    let stats = store.stat()?;
    println!("page_count:  {}", stats.page_count);
    println!("data_pages:  {}", stats.data_pages);
    println!("tree_height: {}", stats.tree_height);
    Ok(())
}
