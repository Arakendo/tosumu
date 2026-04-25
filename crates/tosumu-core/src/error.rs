use thiserror::Error;

/// Top-level error type for tosumu-core.
///
/// The full variant taxonomy is in DESIGN.md §9.
#[derive(Debug, Error)]
pub enum TosumError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupt record at byte offset {offset}: {reason}")]
    CorruptRecord { offset: u64, reason: &'static str },

    #[error("corrupt page {pgno}: {reason}")]
    Corrupt { pgno: u64, reason: &'static str },

    #[error("AEAD authentication failed on page {}", pgno.map(|n| n.to_string()).unwrap_or_else(|| "?".into()))]
    AuthFailed { pgno: Option<u64> },

    #[error("page encryption failed")]
    EncryptFailed,

    #[error("OS RNG unavailable — cannot generate key material")]
    RngFailed,

    #[error("not a tosumu file: bad magic or header")]
    NotATosumFile,

    #[error("format version {found} is not supported (max supported: {supported_max})")]
    NewerFormat { found: u16, supported_max: u16 },

    #[error("page size in header ({found}) does not match engine page size ({expected})")]
    PageSizeMismatch { found: u16, expected: u16 },

    #[error("out of space")]
    OutOfSpace,

    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// A file needed for a database operation is temporarily locked by another
    /// process (e.g. AV scanner, backup tool).  The caller should retry later.
    #[error("file temporarily locked by another process during {operation}: {path:?}")]
    FileBusy {
        path: std::path::PathBuf,
        operation: &'static str,
    },

    /// The supplied passphrase (or other protector secret) is wrong.
    ///
    /// Distinct from `AuthFailed` which indicates page-level AEAD corruption.
    /// `WrongKey` means "your passphrase was rejected by the keyslot KCV before
    /// we even attempted to decrypt any data pages."
    #[error("wrong passphrase or key — could not unlock any keyslot")]
    WrongKey,
}

pub type Result<T> = std::result::Result<T, TosumError>;
