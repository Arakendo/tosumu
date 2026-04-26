use tosumu_core::error::{ErrorDetail, ErrorReport, ErrorStatus, ErrorValue, TosumuError};

pub(crate) mod codes {
    pub const CLI_ARGUMENT_INVALID: &str = "CLI_ARGUMENT_INVALID";
    pub const CLI_KEY_NOT_FOUND: &str = "CLI_KEY_NOT_FOUND";

    pub const PUBLIC_CODES: &[&str] = &[CLI_ARGUMENT_INVALID, CLI_KEY_NOT_FOUND];
}

#[derive(Debug)]
pub(crate) enum CliError {
    Core(TosumuError),
    InspectStdinSecretEmpty {
        argument: &'static str,
        secret_kind: &'static str,
    },
    RecoveryKeyFormatInvalid,
    RecoveryKeyConfirmationFailed,
    KeyfilePathEmpty,
    PassphrasesDoNotMatch,
    KeyNotFound {
        key: String,
    },
    BackupDestinationExists {
        path: std::path::PathBuf,
    },
}

impl CliError {
    pub(crate) fn inspect_stdin_secret_empty(
        argument: &'static str,
        secret_kind: &'static str,
    ) -> Self {
        Self::InspectStdinSecretEmpty {
            argument,
            secret_kind,
        }
    }

    pub(crate) fn recovery_key_format_invalid() -> Self {
        Self::RecoveryKeyFormatInvalid
    }

    pub(crate) fn recovery_key_confirmation_failed() -> Self {
        Self::RecoveryKeyConfirmationFailed
    }

    pub(crate) fn backup_destination_exists(path: &std::path::Path) -> Self {
        Self::BackupDestinationExists {
            path: path.to_path_buf(),
        }
    }

    pub(crate) fn keyfile_path_empty() -> Self {
        Self::KeyfilePathEmpty
    }

    pub(crate) fn passphrases_do_not_match() -> Self {
        Self::PassphrasesDoNotMatch
    }

    pub(crate) fn key_not_found(key: &str) -> Self {
        Self::KeyNotFound {
            key: key.to_string(),
        }
    }

    pub(crate) fn error_report(&self) -> ErrorReport {
        match self {
            CliError::Core(error) => error.error_report(),
            CliError::InspectStdinSecretEmpty {
                argument,
                secret_kind,
            } => ErrorReport {
                code: codes::CLI_ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: format!("stdin {secret_kind} must not be empty"),
                details: vec![
                    ErrorDetail {
                        key: "argument",
                        value: ErrorValue::Str((*argument).to_string()),
                    },
                    ErrorDetail {
                        key: "secret_kind",
                        value: ErrorValue::Str((*secret_kind).to_string()),
                    },
                    ErrorDetail {
                        key: "input_source",
                        value: ErrorValue::Str("stdin".to_string()),
                    },
                ],
            },
            CliError::RecoveryKeyFormatInvalid => ErrorReport {
                code: codes::CLI_ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: "recovery key format is invalid".to_string(),
                details: vec![
                    ErrorDetail {
                        key: "field",
                        value: ErrorValue::Str("recovery_key".to_string()),
                    },
                    ErrorDetail {
                        key: "validation",
                        value: ErrorValue::Str("format".to_string()),
                    },
                ],
            },
            CliError::RecoveryKeyConfirmationFailed => ErrorReport {
                code: codes::CLI_ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: "recovery key confirmation failed".to_string(),
                details: vec![
                    ErrorDetail {
                        key: "field",
                        value: ErrorValue::Str("recovery_key".to_string()),
                    },
                    ErrorDetail {
                        key: "validation",
                        value: ErrorValue::Str("confirmation".to_string()),
                    },
                ],
            },
            CliError::KeyfilePathEmpty => ErrorReport {
                code: codes::CLI_ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: "keyfile path must not be empty".to_string(),
                details: vec![
                    ErrorDetail {
                        key: "field",
                        value: ErrorValue::Str("keyfile_path".to_string()),
                    },
                    ErrorDetail {
                        key: "validation",
                        value: ErrorValue::Str("required".to_string()),
                    },
                ],
            },
            CliError::PassphrasesDoNotMatch => ErrorReport {
                code: codes::CLI_ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: "passphrases do not match".to_string(),
                details: vec![
                    ErrorDetail {
                        key: "field",
                        value: ErrorValue::Str("passphrase_confirmation".to_string()),
                    },
                    ErrorDetail {
                        key: "validation",
                        value: ErrorValue::Str("match".to_string()),
                    },
                ],
            },
            CliError::KeyNotFound { key } => ErrorReport {
                code: codes::CLI_KEY_NOT_FOUND,
                status: ErrorStatus::NotFound,
                message: "key not found".to_string(),
                details: vec![
                    ErrorDetail {
                        key: "key",
                        value: ErrorValue::Str(key.clone()),
                    },
                    ErrorDetail {
                        key: "operation",
                        value: ErrorValue::Str("get".to_string()),
                    },
                ],
            },
            CliError::BackupDestinationExists { path } => ErrorReport {
                code: codes::CLI_ARGUMENT_INVALID,
                status: ErrorStatus::InvalidInput,
                message: "backup destination already exists; choose a new path".to_string(),
                details: vec![
                    ErrorDetail {
                        key: "path",
                        value: ErrorValue::Str(path.display().to_string()),
                    },
                    ErrorDetail {
                        key: "operation",
                        value: ErrorValue::Str("backup".to_string()),
                    },
                ],
            },
        }
    }
}

impl From<TosumuError> for CliError {
    fn from(value: TosumuError) -> Self {
        CliError::Core(value)
    }
}

#[cfg(test)]
mod tests {
    use super::codes::PUBLIC_CODES;

    #[test]
    fn documented_cli_public_codes_match_exported_constants() {
        let errors_md_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("ERRORS.md");
        let errors_md = std::fs::read_to_string(&errors_md_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", errors_md_path.display()));

        let documented = extract_marked_code_block(
            &errors_md,
            "<!-- BEGIN_CLI_PUBLIC_CODES -->",
            "<!-- END_CLI_PUBLIC_CODES -->",
        );

        assert_eq!(documented, PUBLIC_CODES);
    }

    fn extract_marked_code_block<'a>(
        document: &'a str,
        start_marker: &str,
        end_marker: &str,
    ) -> Vec<&'a str> {
        let after_start = document
            .split_once(start_marker)
            .unwrap_or_else(|| panic!("missing start marker {start_marker}"))
            .1;
        let before_end = after_start
            .split_once(end_marker)
            .unwrap_or_else(|| panic!("missing end marker {end_marker}"))
            .0;
        let code_block = before_end
            .split_once("```txt")
            .unwrap_or_else(|| panic!("missing txt code block after {start_marker}"))
            .1
            .split_once("```")
            .unwrap_or_else(|| panic!("missing closing code fence before {end_marker}"))
            .0;

        code_block
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect()
    }
}
