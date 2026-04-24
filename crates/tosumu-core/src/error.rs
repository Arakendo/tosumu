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
}

pub type Result<T> = std::result::Result<T, TosumError>;
