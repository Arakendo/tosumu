use std::process::Command;

#[test]
fn cli_logs_structured_boundary_error_when_enabled() {
    let path = temp_path("cli_error_logging_missing_key");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_tosumu"))
        .env("TOSUMU_LOG_ERRORS", "1")
        .arg("get")
        .arg(&path)
        .arg("alpha")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());

    let stderr = normalize_newlines(&String::from_utf8(output.stderr).unwrap());
    let mut lines = stderr.lines();

    assert_eq!(
        lines.next().unwrap(),
        "event=boundary_error code=CLI_KEY_NOT_FOUND status=not_found message=\"key not found\" operation=get key=\"alpha\" detail_operation=\"get\""
    );
    assert_eq!(
        lines.next().unwrap(),
        "error [CLI_KEY_NOT_FOUND]: key not found"
    );
    assert_eq!(lines.next(), None);

    let _ = std::fs::remove_file(&path);
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tosumu_cli_{tag}_{nanos}.tsm"))
}

fn normalize_newlines(value: &str) -> String {
    value.replace("\r\n", "\n")
}