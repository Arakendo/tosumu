use std::path::Path;

use tosumu_core::wal::wal_path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileFingerprint {
    len: u64,
    modified: Option<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WatchFingerprint {
    db: FileFingerprint,
    wal: Option<FileFingerprint>,
}

fn file_fingerprint(path: &Path) -> std::io::Result<Option<FileFingerprint>> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(FileFingerprint {
            len: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_nanos()),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn capture_watch_fingerprint(path: &Path) -> std::io::Result<WatchFingerprint> {
    let db = file_fingerprint(path)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "database file missing during watch",
        )
    })?;
    Ok(WatchFingerprint {
        db,
        wal: file_fingerprint(&wal_path(path))?,
    })
}

pub(super) fn watch_refresh_needed(
    path: &Path,
    previous: Option<&WatchFingerprint>,
) -> std::io::Result<bool> {
    let current = capture_watch_fingerprint(path)?;
    Ok(match previous {
        Some(previous) => previous != &current,
        None => true,
    })
}
