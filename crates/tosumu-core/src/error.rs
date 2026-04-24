use thiserror::Error;

/// Top-level error type for tosumu-core (MVP 0 subset).
///
/// The full variant taxonomy is in DESIGN.md §9.
#[derive(Debug, Error)]
pub enum TosumError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("corrupt record at byte offset {offset}: {reason}")]
    CorruptRecord { offset: u64, reason: &'static str },

    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
}

pub type Result<T> = std::result::Result<T, TosumError>;
