use std::path::{Path, PathBuf};

use tosumu_core::btree::BTree;
use tosumu_core::error::TosumuError;
use tosumu_core::page_store::PageStore;
use tosumu_core::pager::Pager;

use crate::error_boundary::CliError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UnlockSecret {
    Passphrase(String),
    RecoveryKey(String),
    Keyfile(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UnlockKind {
    Passphrase,
    RecoveryKey,
    Keyfile,
}

fn open_with_unlock_secret<T>(
    unlock: Option<&UnlockSecret>,
    open_unencrypted: impl FnOnce() -> Result<T, TosumuError>,
    open_passphrase: impl FnOnce(&str) -> Result<T, TosumuError>,
    open_recovery_key: impl FnOnce(&str) -> Result<T, TosumuError>,
    open_keyfile: impl FnOnce(&Path) -> Result<T, TosumuError>,
) -> Result<T, TosumuError> {
    match unlock {
        None => open_unencrypted(),
        Some(UnlockSecret::Passphrase(pass)) => open_passphrase(pass),
        Some(UnlockSecret::RecoveryKey(recovery)) => open_recovery_key(recovery),
        Some(UnlockSecret::Keyfile(keyfile)) => open_keyfile(keyfile),
    }
}

fn prompt_unlock_secret(kind: UnlockKind) -> Result<UnlockSecret, CliError> {
    match kind {
        UnlockKind::Passphrase => Ok(UnlockSecret::Passphrase(prompt_passphrase("passphrase: ")?)),
        UnlockKind::RecoveryKey => Ok(UnlockSecret::RecoveryKey(prompt_passphrase(
            "recovery key: ",
        )?)),
        UnlockKind::Keyfile => Ok(UnlockSecret::Keyfile(prompt_keyfile_path(
            "keyfile path: ",
        )?)),
    }
}

fn open_with_unlock_fallback<T, F, P>(
    mut open: F,
    mut prompt_for_unlock: P,
) -> Result<(T, Option<UnlockSecret>), CliError>
where
    F: FnMut(Option<&UnlockSecret>) -> Result<T, TosumuError>,
    P: FnMut(UnlockKind) -> Result<UnlockSecret, CliError>,
{
    match open(None) {
        Ok(value) => return Ok((value, None)),
        Err(TosumuError::WrongKey) => {}
        Err(error) => return Err(error.into()),
    }

    for kind in [
        UnlockKind::Passphrase,
        UnlockKind::RecoveryKey,
        UnlockKind::Keyfile,
    ] {
        let unlock = prompt_for_unlock(kind)?;
        match open(Some(&unlock)) {
            Ok(value) => return Ok((value, Some(unlock))),
            Err(TosumuError::WrongKey) => continue,
            Err(error) => return Err(error.into()),
        }
    }

    Err(TosumuError::WrongKey.into())
}

fn open_with_resolved_unlock<T, F>(
    mut open: F,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<(T, Option<UnlockSecret>), CliError>
where
    F: FnMut(Option<&UnlockSecret>) -> Result<T, TosumuError>,
{
    match unlock {
        None if no_prompt => open(None).map(|value| (value, None)).map_err(Into::into),
        None => open_with_unlock_fallback(open, prompt_unlock_secret),
        Some(unlock) => open(Some(&unlock))
            .map(|value| (value, Some(unlock)))
            .map_err(Into::into),
    }
}

fn open_page_store_readonly(
    path: &Path,
    unlock: Option<&UnlockSecret>,
) -> Result<PageStore, TosumuError> {
    open_with_unlock_secret(
        unlock,
        || PageStore::open_readonly(path),
        |pass| PageStore::open_with_passphrase_readonly(path, pass),
        |recovery| PageStore::open_with_recovery_key_readonly(path, recovery),
        |keyfile| PageStore::open_with_keyfile_readonly(path, keyfile),
    )
}

fn open_page_store_writable(
    path: &Path,
    unlock: Option<&UnlockSecret>,
) -> Result<PageStore, TosumuError> {
    open_with_unlock_secret(
        unlock,
        || PageStore::open(path),
        |pass| PageStore::open_with_passphrase(path, pass),
        |recovery| PageStore::open_with_recovery_key(path, recovery),
        |keyfile| PageStore::open_with_keyfile(path, keyfile),
    )
}

fn open_pager_readonly(path: &Path, unlock: Option<&UnlockSecret>) -> Result<Pager, TosumuError> {
    open_with_unlock_secret(
        unlock,
        || Pager::open_readonly(path),
        |pass| Pager::open_with_passphrase_readonly(path, pass),
        |recovery| Pager::open_with_recovery_key_readonly(path, recovery),
        |keyfile| Pager::open_with_keyfile_readonly(path, keyfile),
    )
}

pub(crate) fn open_store_readonly(path: &Path) -> Result<PageStore, CliError> {
    open_with_unlock_fallback(
        |unlock| open_page_store_readonly(path, unlock),
        prompt_unlock_secret,
    )
    .map(|(store, _)| store)
}

pub(crate) fn open_store_writable(path: &Path) -> Result<PageStore, CliError> {
    open_with_unlock_fallback(
        |unlock| open_page_store_writable(path, unlock),
        prompt_unlock_secret,
    )
    .map(|(store, _)| store)
}

pub(crate) fn open_pager(path: &Path) -> Result<(Pager, Option<UnlockSecret>), CliError> {
    open_with_unlock_fallback(
        |unlock| open_pager_readonly(path, unlock),
        prompt_unlock_secret,
    )
}

pub(crate) fn open_btree_with_unlock(
    path: &Path,
    unlock: Option<&UnlockSecret>,
) -> Result<BTree, TosumuError> {
    open_with_unlock_secret(
        unlock,
        || BTree::open_readonly(path),
        |pass| BTree::open_with_passphrase_readonly(path, pass),
        |recovery| BTree::open_with_recovery_key_readonly(path, recovery),
        |keyfile| BTree::open_with_keyfile_readonly(path, keyfile),
    )
}

pub(crate) fn open_pager_with_unlock(
    path: &Path,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<(Pager, Option<UnlockSecret>), CliError> {
    open_with_resolved_unlock(
        |resolved_unlock| open_pager_readonly(path, resolved_unlock),
        unlock,
        no_prompt,
    )
}

pub(crate) fn prompt_passphrase(prompt: &str) -> Result<String, TosumuError> {
    rpassword::prompt_password(prompt).map_err(|e| {
        TosumuError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    })
}

pub(crate) fn prompt_line(prompt: &str) -> Result<String, TosumuError> {
    let mut stdout = std::io::stdout();
    use std::io::Write as _;
    write!(stdout, "{prompt}").map_err(TosumuError::Io)?;
    stdout.flush().map_err(TosumuError::Io)?;

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .map_err(TosumuError::Io)?;
    Ok(input.trim().to_string())
}

pub(crate) fn prompt_keyfile_path(prompt: &str) -> Result<PathBuf, CliError> {
    let input = prompt_line(prompt)?;
    if input.is_empty() {
        return Err(CliError::keyfile_path_empty());
    }
    Ok(PathBuf::from(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlock_fallback_returns_first_successful_prompted_secret() {
        let mut prompted = Vec::new();
        let (value, unlock) = open_with_unlock_fallback(
            |candidate| match candidate {
                None => Err(TosumuError::WrongKey),
                Some(UnlockSecret::Passphrase(_)) => Err(TosumuError::WrongKey),
                Some(UnlockSecret::RecoveryKey(secret)) => Ok(secret.clone()),
                Some(UnlockSecret::Keyfile(_)) => panic!("unexpected keyfile attempt"),
            },
            |kind| {
                prompted.push(kind);
                Ok(match kind {
                    UnlockKind::Passphrase => {
                        UnlockSecret::Passphrase("passphrase-secret".to_string())
                    }
                    UnlockKind::RecoveryKey => {
                        UnlockSecret::RecoveryKey("recovery-secret".to_string())
                    }
                    UnlockKind::Keyfile => UnlockSecret::Keyfile(PathBuf::from("secret.key")),
                })
            },
        )
        .unwrap();

        assert_eq!(value, "recovery-secret");
        assert_eq!(
            unlock,
            Some(UnlockSecret::RecoveryKey("recovery-secret".to_string()))
        );
        assert_eq!(
            prompted,
            vec![UnlockKind::Passphrase, UnlockKind::RecoveryKey]
        );
    }

    #[test]
    fn resolved_unlock_uses_explicit_secret_without_prompting() {
        let explicit_unlock = UnlockSecret::Passphrase("correct-horse".to_string());
        let (value, used_unlock) = open_with_resolved_unlock(
            |candidate| match candidate {
                Some(UnlockSecret::Passphrase(secret)) => Ok(secret.clone()),
                _ => panic!("unexpected unlock candidate"),
            },
            Some(explicit_unlock.clone()),
            false,
        )
        .unwrap();

        assert_eq!(value, "correct-horse");
        assert_eq!(used_unlock, Some(explicit_unlock));
    }
}
