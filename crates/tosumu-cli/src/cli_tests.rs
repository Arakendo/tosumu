use super::*;
use crate::commands::protector::{
    confirm_recovery_words, format_recovery_key_for_display, recovery_words,
};
use crate::commands::store::run_get;
use crate::commands::text::cmd_backup;
use crate::error_boundary::{codes as cli_codes, CliError};
use clap::error::ErrorKind;
use tosumu_core::error::TosumuError;

#[test]
fn recovery_words_rechunk_into_eight_groups_of_four() {
    let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
    let words = recovery_words(secret);
    assert_eq!(
        words,
        vec!["ABCD", "EFGH", "IJKL", "MNOP", "QRST", "UVWX", "YZ23", "4567",]
    );
}

#[test]
fn recovery_display_uses_eight_groups_of_four() {
    let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
    assert_eq!(
        format_recovery_key_for_display(secret),
        "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567"
    );
}

#[test]
fn recovery_confirmation_accepts_correct_words() {
    let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
    confirm_recovery_words(secret, "ijkl", "yz23").unwrap();
}

#[test]
fn recovery_confirmation_rejects_wrong_words() {
    let secret = "ABCDEFGH-IJKLMNOP-QRSTUVWX-YZ234567";
    let err = confirm_recovery_words(secret, "WRONG", "YZ23").unwrap_err();
    let report = err.error_report();
    assert_eq!(report.code, cli_codes::CLI_ARGUMENT_INVALID);
    assert_eq!(report.message, "recovery key confirmation failed");
}

#[test]
fn recovery_confirmation_rejects_malformed_secret_as_cli_argument_invalid() {
    let err = confirm_recovery_words("ABCD-EFGH", "ABCD", "EFGH").unwrap_err();
    let report = err.error_report();
    assert_eq!(report.code, cli_codes::CLI_ARGUMENT_INVALID);
    assert_eq!(report.message, "recovery key format is invalid");
}

#[test]
fn cli_parses_add_keyfile_subcommand() {
    let cli =
        Cli::try_parse_from(["tosumu", "protector", "add-keyfile", "db.tsm", "db.key"]).unwrap();

    match cli.command {
        Command::Protector {
            action: ProtectorAction::AddKeyfile { path, keyfile },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert_eq!(keyfile, PathBuf::from("db.key"));
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_add_recovery_key_subcommand() {
    let cli = Cli::try_parse_from(["tosumu", "protector", "add-recovery-key", "db.tsm"]).unwrap();

    match cli.command {
        Command::Protector {
            action: ProtectorAction::AddRecoveryKey { path },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_inspect_header_json_subcommand() {
    let cli = Cli::try_parse_from(["tosumu", "inspect", "header", "--json", "db.tsm"]).unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Header { path, json },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(json.json);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_rejects_inspect_schema_version_flag() {
    let result = Cli::try_parse_from([
        "tosumu",
        "inspect",
        "header",
        "--json",
        "--schema-version",
        "db.tsm",
    ]);

    assert!(result.is_err());
}

#[test]
fn cli_parses_inspect_verify_json_subcommand() {
    let cli = Cli::try_parse_from(["tosumu", "inspect", "verify", "--json", "db.tsm"]).unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Verify { path, json, unlock },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(json.json);
            assert!(!unlock.no_prompt);
            assert!(!unlock.stdin_passphrase);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_inspect_pages_json_subcommand() {
    let cli = Cli::try_parse_from(["tosumu", "inspect", "pages", "--json", "db.tsm"]).unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Pages { path, json, unlock },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(json.json);
            assert!(!unlock.no_prompt);
            assert!(!unlock.stdin_passphrase);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_inspect_wal_json_subcommand() {
    let cli = Cli::try_parse_from(["tosumu", "inspect", "wal", "--json", "db.tsm"]).unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Wal { path, json },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(json.json);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_inspect_page_json_subcommand() {
    let cli = Cli::try_parse_from([
        "tosumu", "inspect", "page", "--page", "1", "--json", "db.tsm",
    ])
    .unwrap();

    match cli.command {
        Command::Inspect {
            action:
                InspectAction::Page {
                    path,
                    page,
                    json,
                    unlock,
                },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert_eq!(page, 1);
            assert!(json.json);
            assert!(!unlock.no_prompt);
            assert!(!unlock.stdin_passphrase);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_inspect_protectors_json_subcommand() {
    let cli = Cli::try_parse_from(["tosumu", "inspect", "protectors", "--json", "db.tsm"]).unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Protectors { path, json },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(json.json);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_view_watch_flag() {
    let cli = Cli::try_parse_from(["tosumu", "view", "--watch", "db.tsm"]).unwrap();

    match cli.command {
        Command::View { path, watch } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(watch);
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_view_help_lists_interactive_keys() {
    let err = match Cli::try_parse_from(["tosumu", "view", "--help"]) {
        Ok(_) => panic!("expected clap to render help"),
        Err(err) => err,
    };

    assert_eq!(err.kind(), ErrorKind::DisplayHelp);

    let help = err.to_string();
    assert!(help.contains("Open the read-only interactive inspection view."));
    assert!(help.contains("Interactive keys:"));
    assert!(help.contains("n/N    move to the next or previous filter match"));
    assert!(help.contains("w      toggle watch mode"));
}

#[test]
fn cli_parses_inspect_verify_with_stdin_passphrase() {
    let cli = Cli::try_parse_from([
        "tosumu",
        "inspect",
        "verify",
        "--json",
        "--stdin-passphrase",
        "db.tsm",
    ])
    .unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Verify { path, json, unlock },
        } => {
            assert_eq!(path, PathBuf::from("db.tsm"));
            assert!(json.json);
            assert!(unlock.stdin_passphrase);
            assert!(!unlock.no_prompt);
            assert!(!unlock.stdin_recovery_key);
            assert!(unlock.keyfile.is_none());
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_parses_inspect_verify_with_no_prompt() {
    let cli = Cli::try_parse_from([
        "tosumu",
        "inspect",
        "verify",
        "--json",
        "--no-prompt",
        "db.tsm",
    ])
    .unwrap();

    match cli.command {
        Command::Inspect {
            action: InspectAction::Verify { unlock, .. },
        } => {
            assert!(unlock.no_prompt);
            assert!(!unlock.stdin_passphrase);
            assert!(!unlock.stdin_recovery_key);
            assert!(unlock.keyfile.is_none());
        }
        _ => panic!("unexpected command variant"),
    }
}

#[test]
fn cli_exit_code_maps_invalid_argument_to_two() {
    assert_eq!(
        exit_code_for_error(&CliError::from(TosumuError::InvalidArgument("bad flag"))),
        2
    );
}

#[test]
fn cli_exit_code_maps_cli_argument_invalid_to_two() {
    assert_eq!(
        exit_code_for_error(&CliError::inspect_stdin_secret_empty(
            "stdin_passphrase",
            "passphrase",
        )),
        2
    );
}

#[test]
fn cli_exit_code_maps_wrong_key_to_permission_denied() {
    assert_eq!(
        exit_code_for_error(&CliError::from(TosumuError::WrongKey)),
        5
    );
}

#[test]
fn cli_exit_code_maps_file_busy_to_busy_code() {
    let error = TosumuError::FileBusy {
        path: PathBuf::from("db.tsm"),
        operation: "open database",
    };

    assert_eq!(exit_code_for_error(&CliError::from(error)), 8);
}

#[test]
fn cli_error_render_includes_stable_error_code() {
    let rendered = render_cli_error(&CliError::from(TosumuError::WrongKey));
    assert_eq!(
        rendered,
        "error [PROTECTOR_UNLOCK_WRONG_KEY]: wrong passphrase or key — could not unlock any keyslot"
    );
}

#[test]
fn cli_error_render_uses_argument_invalid_code() {
    let rendered = render_cli_error(&CliError::from(TosumuError::InvalidArgument("bad flag")));
    assert_eq!(
        rendered,
        "error [ARGUMENT_INVALID]: invalid argument: bad flag"
    );
}

#[test]
fn cli_error_render_uses_cli_argument_invalid_for_empty_stdin_secret() {
    let rendered = render_cli_error(&CliError::inspect_stdin_secret_empty(
        "stdin_passphrase",
        "passphrase",
    ));
    assert_eq!(
        rendered,
        "error [CLI_ARGUMENT_INVALID]: stdin passphrase must not be empty"
    );
}

#[test]
fn cli_error_report_uses_cli_argument_invalid_code_for_empty_stdin_secret() {
    let report =
        CliError::inspect_stdin_secret_empty("stdin_passphrase", "passphrase").error_report();
    assert_eq!(report.code, cli_codes::CLI_ARGUMENT_INVALID);
    assert_eq!(report.status.as_str(), "invalid_input");
    assert_eq!(report.message, "stdin passphrase must not be empty");
    assert_eq!(report.detail_u64("pgno"), None);
}

#[test]
fn cli_error_report_uses_cli_argument_invalid_for_backup_destination_exists() {
    let src = std::env::temp_dir().join("tosumu_cli_backup_src.tsm");
    let dest = std::env::temp_dir().join("tosumu_cli_backup_dest.tsm");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dest);

    std::fs::write(&src, b"src").unwrap();
    std::fs::write(&dest, b"dest").unwrap();

    let err = cmd_backup(&src, &dest).unwrap_err();
    let report = err.error_report();

    assert_eq!(report.code, cli_codes::CLI_ARGUMENT_INVALID);
    assert_eq!(
        report.message,
        "backup destination already exists; choose a new path"
    );

    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn cli_error_report_uses_cli_argument_invalid_for_empty_keyfile_path() {
    let report = CliError::keyfile_path_empty().error_report();

    assert_eq!(report.code, cli_codes::CLI_ARGUMENT_INVALID);
    assert_eq!(report.message, "keyfile path must not be empty");
}

#[test]
fn cli_error_render_uses_cli_argument_invalid_for_passphrase_mismatch() {
    let rendered = render_cli_error(&CliError::passphrases_do_not_match());

    assert_eq!(
        rendered,
        "error [CLI_ARGUMENT_INVALID]: passphrases do not match"
    );
}

#[test]
fn cli_exit_code_maps_passphrase_mismatch_to_two() {
    assert_eq!(
        exit_code_for_error(&CliError::passphrases_do_not_match()),
        2
    );
}

#[test]
fn cli_error_render_uses_cli_key_not_found_for_missing_key() {
    let rendered = render_cli_error(&CliError::key_not_found("alpha"));

    assert_eq!(rendered, "error [CLI_KEY_NOT_FOUND]: key not found");
}

#[test]
fn cli_error_log_renders_structured_fields_and_details() {
    let rendered = render_cli_error_log(
        &CliError::from(TosumuError::InspectPageOutOfRange {
            pgno: 9,
            page_count: 4,
        }),
        "inspect.page",
    );

    assert_eq!(
        rendered,
        "event=boundary_error code=INSPECT_PAGE_OUT_OF_RANGE status=invalid_input message=\"page number out of range: requested 9, page_count 4\" operation=inspect.page pgno=9 page_count=4"
    );
}

#[test]
fn cli_error_log_includes_string_details_and_source_when_available() {
    let rendered = render_cli_error_log(
        &CliError::inspect_stdin_secret_empty("stdin_passphrase", "passphrase"),
        "inspect.verify",
    );

    assert_eq!(
        rendered,
        "event=boundary_error code=CLI_ARGUMENT_INVALID status=invalid_input message=\"stdin passphrase must not be empty\" operation=inspect.verify argument=\"stdin_passphrase\" secret_kind=\"passphrase\" input_source=\"stdin\""
    );
}

#[test]
fn cli_error_logging_enabled_value_accepts_truthy_flags() {
    assert!(cli_error_logging_enabled_value("1"));
    assert!(cli_error_logging_enabled_value("true"));
    assert!(cli_error_logging_enabled_value("YES"));
    assert!(cli_error_logging_enabled_value("on"));
    assert!(!cli_error_logging_enabled_value("0"));
    assert!(!cli_error_logging_enabled_value("false"));
}

#[test]
fn cli_exit_code_maps_missing_key_to_four() {
    assert_eq!(exit_code_for_error(&CliError::key_not_found("alpha")), 4);
}

#[test]
fn run_get_returns_cli_key_not_found_error_for_missing_key() {
    let path = std::env::temp_dir().join(format!(
        "tosumu_cli_get_missing_key_{}.tsm",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();

    let err = run_get(&path, "alpha").unwrap_err();
    let report = err.error_report();

    assert_eq!(report.code, cli_codes::CLI_KEY_NOT_FOUND);
    assert_eq!(report.status.as_str(), "not_found");
    assert_eq!(report.message, "key not found");

    let _ = std::fs::remove_file(&path);
}
