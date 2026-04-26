use std::path::Path;

use tosumu_core::error::TosumuError;
use tosumu_core::page_store::PageStore;

use crate::error_boundary::CliError;
use crate::unlock::{prompt_keyfile_path, prompt_line, prompt_passphrase};
use crate::ProtectorAction;

pub(crate) fn recovery_words(secret: &str) -> Vec<String> {
    secret
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect()
}

pub(crate) fn format_recovery_key_for_display(secret: &str) -> String {
    recovery_words(secret).join("-")
}

pub(crate) fn confirm_recovery_words(
    secret: &str,
    word3: &str,
    word7: &str,
) -> Result<(), CliError> {
    let words = recovery_words(secret);
    if words.len() < 7 {
        return Err(CliError::recovery_key_format_invalid());
    }

    if word3.trim().to_ascii_uppercase() != words[2]
        || word7.trim().to_ascii_uppercase() != words[6]
    {
        return Err(CliError::recovery_key_confirmation_failed());
    }

    Ok(())
}

fn confirm_recovery_key_saved(secret: &str) -> Result<(), CliError> {
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

pub(crate) fn run_protector_action(action: ProtectorAction) -> Result<(), CliError> {
    match action {
        ProtectorAction::AddPassphrase { path } => {
            let unlock = prompt_passphrase("current passphrase: ")?;
            let new1 = prompt_passphrase("new passphrase: ")?;
            let new2 = prompt_passphrase("confirm new passphrase: ")?;
            ensure_matching_passphrases(&new1, &new2)?;

            let slot = match PageStore::add_passphrase_protector(&path, &unlock, &new1) {
                Ok(slot) => slot,
                Err(TosumuError::WrongKey) => {
                    let recovery = prompt_passphrase("recovery key: ")?;
                    PageStore::add_passphrase_protector_with_recovery_key(&path, &recovery, &new1)?
                }
                Err(error) => return Err(error.into()),
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
                    match PageStore::add_recovery_key_protector_with_recovery_key_and_secret(
                        &path, &recovery, &key,
                    ) {
                        Ok(()) => {}
                        Err(TosumuError::WrongKey) => {
                            let current_keyfile = prompt_keyfile_path("current keyfile path: ")?;
                            PageStore::add_recovery_key_protector_with_keyfile_and_secret(
                                &path,
                                &current_keyfile,
                                &key,
                            )?;
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
            println!("recovery protector added");
        }
        ProtectorAction::AddKeyfile { path, keyfile } => {
            let unlock = prompt_passphrase("current passphrase: ")?;
            let slot = match PageStore::add_keyfile_protector(&path, &unlock, &keyfile) {
                Ok(slot) => slot,
                Err(TosumuError::WrongKey) => {
                    let recovery = prompt_passphrase("recovery key: ")?;
                    match PageStore::add_keyfile_protector_with_recovery_key(
                        &path, &recovery, &keyfile,
                    ) {
                        Ok(slot) => slot,
                        Err(TosumuError::WrongKey) => {
                            let current_keyfile = prompt_keyfile_path("current keyfile path: ")?;
                            PageStore::add_keyfile_protector_with_keyfile(
                                &path,
                                &current_keyfile,
                                &keyfile,
                            )?
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
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
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
            println!("slot {slot} removed");
        }
        ProtectorAction::List { path } => {
            use tosumu_core::format::{
                KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_KEYFILE, KEYSLOT_KIND_PASSPHRASE,
                KEYSLOT_KIND_RECOVERY_KEY, KEYSLOT_KIND_SENTINEL,
            };

            let slots = PageStore::list_keyslots(&path)?;
            if slots.is_empty() {
                println!("no active keyslots");
            } else {
                println!("{:>5}  {}", "SLOT", "KIND");
                for (idx, kind) in &slots {
                    let name = match *kind {
                        KEYSLOT_KIND_EMPTY => "Empty",
                        KEYSLOT_KIND_SENTINEL => "Sentinel (plaintext)",
                        KEYSLOT_KIND_PASSPHRASE => "Passphrase",
                        KEYSLOT_KIND_RECOVERY_KEY => "RecoveryKey",
                        KEYSLOT_KIND_KEYFILE => "Keyfile",
                        _ => "Unknown",
                    };
                    println!("{idx:>5}  {name}");
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn run_rekey_kek(path: &Path, slot: u16) -> Result<(), CliError> {
    let old_pass = prompt_passphrase("old passphrase: ")?;
    let new1 = prompt_passphrase("new passphrase: ")?;
    let new2 = prompt_passphrase("confirm new passphrase: ")?;
    ensure_matching_passphrases(&new1, &new2)?;

    match PageStore::rekey_kek(path, slot, &old_pass, &new1) {
        Ok(()) => {}
        Err(TosumuError::WrongKey) => {
            let recovery = prompt_passphrase("recovery key: ")?;
            match PageStore::rekey_kek_with_recovery_key(path, slot, &recovery, &new1) {
                Ok(()) => {}
                Err(TosumuError::WrongKey) => {
                    let keyfile = prompt_keyfile_path("keyfile path: ")?;
                    PageStore::rekey_kek_with_keyfile(path, slot, &keyfile, &new1)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }

    println!("slot {slot} KEK rotated");
    Ok(())
}

fn ensure_matching_passphrases(first: &str, second: &str) -> Result<(), CliError> {
    if first != second {
        return Err(CliError::passphrases_do_not_match());
    }

    Ok(())
}
