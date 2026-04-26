pub mod codes;

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorStatus {
    InvalidInput,
    NotFound,
    Conflict,
    PermissionDenied,
    Busy,
    IntegrityFailure,
    ExternalFailure,
    Unsupported,
    Internal,
}

impl ErrorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorStatus::InvalidInput => "invalid_input",
            ErrorStatus::NotFound => "not_found",
            ErrorStatus::Conflict => "conflict",
            ErrorStatus::PermissionDenied => "permission_denied",
            ErrorStatus::Busy => "busy",
            ErrorStatus::IntegrityFailure => "integrity_failure",
            ErrorStatus::ExternalFailure => "external_failure",
            ErrorStatus::Unsupported => "unsupported",
            ErrorStatus::Internal => "internal",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorValue {
    Bool(bool),
    Str(String),
    U16(u16),
    U64(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorDetail {
    pub key: &'static str,
    pub value: ErrorValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorReport {
    pub code: &'static str,
    pub status: ErrorStatus,
    pub message: String,
    pub details: Vec<ErrorDetail>,
}

impl ErrorReport {
    pub fn detail_u64(&self, key: &'static str) -> Option<u64> {
        self.details.iter().find_map(|detail| {
            if detail.key != key {
                return None;
            }

            match detail.value {
                ErrorValue::U64(value) => Some(value),
                _ => None,
            }
        })
    }
}

/// Top-level error type for tosumu-core.
///
/// The full variant taxonomy is in DESIGN.md §9.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TosumuError {
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

    #[error("file is truncated: expected {expected} bytes, found {found}")]
    FileTruncated { expected: u64, found: u64 },

    /// Database handle is unusable after an unrecoverable corruption or auth failure.
    /// The caller must close and re-open (or restore from backup).
    #[error("database handle is poisoned after corruption or authentication failure")]
    Poisoned,

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

    #[error("page number out of range: requested {pgno}, page_count {page_count}")]
    InspectPageOutOfRange { pgno: u64, page_count: u64 },

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

    /// The transaction was successfully committed to the WAL (data is safe and
    /// will be replayed on next open), but writing the dirty pages back to the
    /// main `.tsm` file failed.
    ///
    /// **The handle is now unusable.**  The caller must close and reopen the
    /// database; WAL recovery will apply the committed transaction automatically.
    /// Do *not* treat this as a rollback — the transaction IS committed.
    #[error("transaction committed to WAL but flush to .tsm failed: {source}")]
    CommittedButFlushFailed {
        #[source]
        source: std::io::Error,
    },
}

impl TosumuError {
    pub fn error_report(&self) -> ErrorReport {
        match self {
            TosumuError::Io(error) => ErrorReport {
                code: codes::FILE_IO_FAILED,
                status: ErrorStatus::ExternalFailure,
                message: self.to_string(),
                details: vec![ErrorDetail {
                    key: "source",
                    value: ErrorValue::Str(error.to_string()),
                }],
            },
            TosumuError::CorruptRecord { offset, reason } => ErrorReport {
                code: codes::RECORD_CORRUPT,
                status: ErrorStatus::IntegrityFailure,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "offset",
                        value: ErrorValue::U64(*offset),
                    },
                    ErrorDetail {
                        key: "reason",
                        value: ErrorValue::Str((*reason).to_string()),
                    },
                ],
            },
            TosumuError::Corrupt { pgno, reason } => ErrorReport {
                code: codes::PAGE_DECODE_CORRUPT,
                status: ErrorStatus::IntegrityFailure,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "pgno",
                        value: ErrorValue::U64(*pgno),
                    },
                    ErrorDetail {
                        key: "reason",
                        value: ErrorValue::Str((*reason).to_string()),
                    },
                ],
            },
            TosumuError::AuthFailed { pgno } => {
                let mut details = Vec::new();
                if let Some(pgno) = pgno {
                    details.push(ErrorDetail {
                        key: "pgno",
                        value: ErrorValue::U64(*pgno),
                    });
                }

                ErrorReport {
                    code: codes::PAGE_AUTH_TAG_FAILED,
                    status: ErrorStatus::IntegrityFailure,
                    message: self.to_string(),
                    details,
                }
            }
            TosumuError::EncryptFailed => ErrorReport {
                code: codes::PAGE_ENCRYPT_FAILED,
                status: ErrorStatus::Internal,
                message: self.to_string(),
                details: Vec::new(),
            },
            TosumuError::RngFailed => ErrorReport {
                code: codes::RNG_UNAVAILABLE,
                status: ErrorStatus::ExternalFailure,
                message: self.to_string(),
                details: Vec::new(),
            },
            TosumuError::FileTruncated { expected, found } => ErrorReport {
                code: codes::FILE_TRUNCATED,
                status: ErrorStatus::IntegrityFailure,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "expected",
                        value: ErrorValue::U64(*expected),
                    },
                    ErrorDetail {
                        key: "found",
                        value: ErrorValue::U64(*found),
                    },
                ],
            },
            TosumuError::Poisoned => ErrorReport {
                code: codes::HANDLE_POISONED,
                status: ErrorStatus::Internal,
                message: self.to_string(),
                details: Vec::new(),
            },
            TosumuError::NotATosumFile => ErrorReport {
                code: codes::FORMAT_NOT_TOSUMU,
                status: ErrorStatus::Unsupported,
                message: self.to_string(),
                details: Vec::new(),
            },
            TosumuError::NewerFormat {
                found,
                supported_max,
            } => ErrorReport {
                code: codes::FORMAT_VERSION_UNSUPPORTED,
                status: ErrorStatus::Unsupported,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "found",
                        value: ErrorValue::U16(*found),
                    },
                    ErrorDetail {
                        key: "supported_max",
                        value: ErrorValue::U16(*supported_max),
                    },
                ],
            },
            TosumuError::PageSizeMismatch { found, expected } => ErrorReport {
                code: codes::PAGE_SIZE_MISMATCH,
                status: ErrorStatus::Unsupported,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "found",
                        value: ErrorValue::U16(*found),
                    },
                    ErrorDetail {
                        key: "expected",
                        value: ErrorValue::U16(*expected),
                    },
                ],
            },
            TosumuError::OutOfSpace => ErrorReport {
                code: codes::STORAGE_OUT_OF_SPACE,
                status: ErrorStatus::ExternalFailure,
                message: self.to_string(),
                details: Vec::new(),
            },
            TosumuError::InvalidArgument(reason) => ErrorReport {
                code: codes::ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: self.to_string(),
                details: vec![ErrorDetail {
                    key: "reason",
                    value: ErrorValue::Str((*reason).to_string()),
                }],
            },
            TosumuError::InspectPageOutOfRange { pgno, page_count } => ErrorReport {
                code: codes::INSPECT_PAGE_OUT_OF_RANGE,
                status: ErrorStatus::InvalidInput,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "pgno",
                        value: ErrorValue::U64(*pgno),
                    },
                    ErrorDetail {
                        key: "page_count",
                        value: ErrorValue::U64(*page_count),
                    },
                ],
            },
            TosumuError::FileBusy { path, operation } => ErrorReport {
                code: codes::FILE_OPEN_BUSY,
                status: ErrorStatus::Busy,
                message: self.to_string(),
                details: vec![
                    ErrorDetail {
                        key: "path",
                        value: ErrorValue::Str(path.display().to_string()),
                    },
                    ErrorDetail {
                        key: "operation",
                        value: ErrorValue::Str((*operation).to_string()),
                    },
                ],
            },
            TosumuError::WrongKey => ErrorReport {
                code: codes::PROTECTOR_UNLOCK_WRONG_KEY,
                status: ErrorStatus::PermissionDenied,
                message: self.to_string(),
                details: Vec::new(),
            },
            TosumuError::CommittedButFlushFailed { source } => ErrorReport {
                code: codes::COMMITTED_FLUSH_FAILED,
                status: ErrorStatus::ExternalFailure,
                message: self.to_string(),
                details: vec![ErrorDetail {
                    key: "source",
                    value: ErrorValue::Str(source.to_string()),
                }],
            },
        }
    }
}

pub type Result<T> = std::result::Result<T, TosumuError>;

#[cfg(test)]
mod tests {
    use super::{codes, ErrorStatus, TosumuError};

    #[test]
    fn error_report_maps_wrong_key_to_permission_denied() {
        let report = TosumuError::WrongKey.error_report();
        assert_eq!(report.code, codes::PROTECTOR_UNLOCK_WRONG_KEY);
        assert_eq!(report.status, ErrorStatus::PermissionDenied);
        assert_eq!(
            report.message,
            "wrong passphrase or key — could not unlock any keyslot"
        );
    }

    #[test]
    fn error_report_exposes_pgno_for_auth_failure() {
        let report = TosumuError::AuthFailed { pgno: Some(42) }.error_report();
        assert_eq!(report.code, codes::PAGE_AUTH_TAG_FAILED);
        assert_eq!(report.detail_u64("pgno"), Some(42));
    }

    #[test]
    fn error_report_maps_inspect_page_out_of_range_to_specific_code() {
        let report = TosumuError::InspectPageOutOfRange {
            pgno: 9,
            page_count: 4,
        }
        .error_report();

        assert_eq!(report.code, codes::INSPECT_PAGE_OUT_OF_RANGE);
        assert_eq!(report.status, ErrorStatus::InvalidInput);
        assert_eq!(report.detail_u64("pgno"), Some(9));
        assert_eq!(report.detail_u64("page_count"), Some(4));
    }
}
