use super::*;
use crate::commands::inspect::{
    cmd_inspect_header_json, cmd_inspect_page_json, cmd_inspect_pages_json,
    cmd_inspect_protectors_json, cmd_inspect_tree_json, cmd_inspect_verify_json,
    cmd_inspect_wal_json,
};
use crate::error_boundary::CliError;
use crate::inspect_contract::verify_payload_codes;
use crate::unlock::UnlockSecret;
use std::io::{Seek, SeekFrom, Write};
use tosumu_core::error::TosumuError;

#[test]
fn inspect_header_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_header_json_success");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();

    let rendered = cmd_inspect_header_json(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.header");
    assert_eq!(json["ok"], true);
    assert_eq!(json["payload"]["page_size"], 4096);
    assert_eq!(json["payload"]["slot0"]["kind"], "Sentinel");
    assert_eq!(json["payload"]["slot0"]["kind_byte"], 1);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_error_json_uses_structured_error_envelope() {
    let rendered = render_inspect_error_json(
        "inspect.header",
        &TosumuError::InspectPageOutOfRange {
            pgno: 9,
            page_count: 4,
        },
    );
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.header");
    assert_eq!(json["ok"], false);
    assert!(json["error"].as_object().unwrap().get("kind").is_none());
    assert_eq!(
        json["error"]["message"],
        "page number out of range: requested 9, page_count 4"
    );
    assert_eq!(json["error"]["code"], "INSPECT_PAGE_OUT_OF_RANGE");
    assert_eq!(json["error"]["status"], "invalid_input");
    assert_eq!(json["error"]["details"]["pgno"], 9);
    assert!(json["payload"].is_null());
}

#[test]
fn inspect_error_json_includes_code_status_and_details() {
    let rendered = render_inspect_error_json(
        "inspect.header",
        &TosumuError::InspectPageOutOfRange {
            pgno: 9,
            page_count: 4,
        },
    );
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert!(json["error"].as_object().unwrap().get("kind").is_none());
    assert_eq!(json["error"]["code"], "INSPECT_PAGE_OUT_OF_RANGE");
    assert_eq!(json["error"]["status"], "invalid_input");
    assert_eq!(
        json["error"]["message"],
        "page number out of range: requested 9, page_count 4"
    );
    assert_eq!(json["error"]["details"]["pgno"], 9);
    assert_eq!(json["error"]["details"]["page_count"], 4);
}

#[test]
fn inspect_error_report_json_includes_cli_argument_invalid_code() {
    let report =
        CliError::inspect_stdin_secret_empty("stdin_passphrase", "passphrase").error_report();
    let rendered = render_inspect_error_report_json("inspect.verify", &report);
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert!(json["error"].as_object().unwrap().get("kind").is_none());
    assert_eq!(json["error"]["code"], "CLI_ARGUMENT_INVALID");
    assert_eq!(json["error"]["status"], "invalid_input");
    assert_eq!(
        json["error"]["message"],
        "stdin passphrase must not be empty"
    );
    assert_eq!(json["error"]["details"]["argument"], "stdin_passphrase");
    assert_eq!(json["error"]["details"]["secret_kind"], "passphrase");
    assert_eq!(json["error"]["details"]["input_source"], "stdin");
}

#[test]
fn inspect_page_json_out_of_range_uses_specific_structured_code() {
    let path = temp_path("inspect_page_json_out_of_range_code");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();

    let err = cmd_inspect_page_json(&path, 9, None, false).err().unwrap();
    let rendered = render_inspect_error_report_json("inspect.page", &err.error_report());
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json["error"].as_object().unwrap().get("kind").is_none());
    assert_eq!(json["error"]["code"], "INSPECT_PAGE_OUT_OF_RANGE");
    assert_eq!(json["error"]["details"]["pgno"], 9);
    assert_eq!(json["error"]["details"]["page_count"], 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_verify_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_verify_json_success");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();

    let rendered = cmd_inspect_verify_json(&path, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.verify");
    assert_eq!(json["ok"], true);
    assert_eq!(json["payload"]["issues"].as_array().unwrap().len(), 0);
    assert_eq!(json["payload"]["btree"]["checked"], true);
    assert_eq!(json["payload"]["btree"]["ok"], true);
    assert!(json["payload"]["btree"]["message"].is_null());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_verify_json_keeps_incomplete_btree_state_in_payload() {
    let path = temp_path("inspect_verify_json_incomplete_btree_payload");
    let _ = std::fs::remove_file(&path);

    let mut store = tosumu_core::page_store::PageStore::create(&path).unwrap();
    store.put(b"alpha", b"one").unwrap();
    drop(store);

    overwrite_root_page(&path, 0);

    let rendered = cmd_inspect_verify_json(&path, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(json["command"], "inspect.verify");
    assert_eq!(json["ok"], false);
    assert!(json["error"].is_null());
    assert_eq!(json["payload"]["issue_count"], 0);
    assert_eq!(json["payload"]["btree"]["checked"], false);
    assert_eq!(json["payload"]["btree"]["ok"], false);
    assert!(json["payload"]["btree"]["message"]
        .as_str()
        .unwrap()
        .contains("root_page is 0 — not a BTree file"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_verify_json_includes_payload_issue_codes_for_auth_failure() {
    let path = temp_path("inspect_verify_json_payload_codes_auth_failure");
    let _ = std::fs::remove_file(&path);

    let mut store = tosumu_core::page_store::PageStore::create(&path).unwrap();
    store.put(b"alpha", b"one").unwrap();
    drop(store);

    flip_byte_at(&path, tosumu_core::format::PAGE_SIZE as u64);

    let rendered = cmd_inspect_verify_json(&path, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["ok"], false);
    assert_eq!(
        json["payload"]["issues"][0]["code"],
        verify_payload_codes::VERIFY_PAGE_AUTH_FAILED
    );
    assert_eq!(
        json["payload"]["page_results"][0]["issue_code"],
        verify_payload_codes::VERIFY_PAGE_AUTH_FAILED
    );
    assert_eq!(
        json["payload"]["btree"]["code"],
        verify_payload_codes::VERIFY_BTREE_INCOMPLETE
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_verify_json_includes_incomplete_btree_code_for_partial_report() {
    let path = temp_path("inspect_verify_json_incomplete_btree_code");
    let _ = std::fs::remove_file(&path);

    let mut store = tosumu_core::page_store::PageStore::create(&path).unwrap();
    store.put(b"alpha", b"one").unwrap();
    drop(store);

    overwrite_root_page(&path, 0);

    let rendered = cmd_inspect_verify_json(&path, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(json["ok"], false);
    assert!(json["error"].is_null());
    assert_eq!(
        json["payload"]["btree"]["code"],
        verify_payload_codes::VERIFY_BTREE_INCOMPLETE
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_page_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_page_json_success");
    let _ = std::fs::remove_file(&path);
    let mut store = tosumu_core::page_store::PageStore::create(&path).unwrap();
    store.put(b"alpha", b"one").unwrap();

    let rendered = cmd_inspect_page_json(&path, 1, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.page");
    assert_eq!(json["ok"], true);
    assert_eq!(json["payload"]["pgno"], 1);
    assert_eq!(json["payload"]["page_type_name"], "Leaf");
    assert!(json["payload"]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["kind"] == "Live"
            && record["key_hex"] == "616c706861"
            && record["value_hex"] == "6f6e65"));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_pages_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_pages_json_success");
    let _ = std::fs::remove_file(&path);
    let mut store = tosumu_core::page_store::PageStore::create(&path).unwrap();
    store.put(b"alpha", b"one").unwrap();

    let rendered = cmd_inspect_pages_json(&path, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.pages");
    assert_eq!(json["ok"], true);
    assert!(json["payload"]["pages"].as_array().unwrap().len() >= 1);
    assert_eq!(json["payload"]["pages"][0]["pgno"], 1);
    assert_eq!(json["payload"]["pages"][0]["page_type_name"], "Leaf");
    assert_eq!(json["payload"]["pages"][0]["state"], "ok");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_wal_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_wal_json_success");
    let wal_path = tosumu_core::wal::wal_path(&path);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wal_path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();
    let _ = std::fs::remove_file(&wal_path);

    {
        let mut writer = tosumu_core::wal::WalWriter::create(&wal_path).unwrap();
        writer
            .append(&tosumu_core::wal::WalRecord::Begin { txn_id: 9 })
            .unwrap();
        writer
            .append(&tosumu_core::wal::WalRecord::PageWrite {
                pgno: 1,
                page_version: 7,
                frame: Box::new([0u8; tosumu_core::format::PAGE_SIZE]),
            })
            .unwrap();
        writer
            .append(&tosumu_core::wal::WalRecord::Commit { txn_id: 9 })
            .unwrap();
        writer.sync().unwrap();
    }

    let rendered = cmd_inspect_wal_json(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.wal");
    assert_eq!(json["ok"], true);
    assert_eq!(json["payload"]["wal_exists"], true);
    assert_eq!(json["payload"]["record_count"], 3);
    assert_eq!(json["payload"]["records"][0]["kind"], "begin");
    assert_eq!(json["payload"]["records"][0]["txn_id"], 9);
    assert_eq!(json["payload"]["records"][1]["kind"], "page_write");
    assert_eq!(json["payload"]["records"][1]["pgno"], 1);
    assert_eq!(json["payload"]["records"][1]["page_version"], 7);
    assert_eq!(json["payload"]["records"][2]["kind"], "commit");
    assert_eq!(json["payload"]["records"][2]["txn_id"], 9);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wal_path);
}

#[test]
fn inspect_tree_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_tree_json_success");
    let _ = std::fs::remove_file(&path);

    let mut store = tosumu_core::page_store::PageStore::create(&path).unwrap();
    for i in 0u32..500 {
        store
            .put(
                format!("tree-key-{i:05}").as_bytes(),
                format!("tree-val-{i:05}").as_bytes(),
            )
            .unwrap();
    }
    assert!(
        store.stat().unwrap().tree_height >= 2,
        "expected test fixture to force a root split"
    );

    let rendered = cmd_inspect_tree_json(&path, None, false).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.tree");
    assert_eq!(json["ok"], true);
    assert_eq!(json["payload"]["root"]["page_type_name"], "Internal");
    assert!(
        json["payload"]["root"]["children"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_protectors_json_uses_structured_success_envelope() {
    let path = temp_path("inspect_protectors_json_success");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create(&path).unwrap();

    let rendered = cmd_inspect_protectors_json(&path).unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert!(json.as_object().unwrap().get("schema_version").is_none());
    assert_eq!(json["command"], "inspect.protectors");
    assert_eq!(json["ok"], true);
    assert_eq!(json["payload"]["slot_count"], 0);
    assert_eq!(json["payload"]["slots"].as_array().unwrap().len(), 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_verify_json_accepts_explicit_passphrase_unlock() {
    let path = temp_path("inspect_verify_json_passphrase_unlock");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();

    let rendered = cmd_inspect_verify_json(
        &path,
        Some(UnlockSecret::Passphrase("correct-horse".to_string())),
        false,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(json["ok"], true);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_page_json_accepts_explicit_passphrase_unlock() {
    let path = temp_path("inspect_page_json_passphrase_unlock");
    let _ = std::fs::remove_file(&path);
    let mut store =
        tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();
    store.put(b"alpha", b"one").unwrap();

    let rendered = cmd_inspect_page_json(
        &path,
        1,
        Some(UnlockSecret::Passphrase("correct-horse".to_string())),
        false,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(json["ok"], true);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_pages_json_accepts_explicit_passphrase_unlock() {
    let path = temp_path("inspect_pages_json_passphrase_unlock");
    let _ = std::fs::remove_file(&path);
    let mut store =
        tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();
    store.put(b"alpha", b"one").unwrap();

    let rendered = cmd_inspect_pages_json(
        &path,
        Some(UnlockSecret::Passphrase("correct-horse".to_string())),
        false,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(json["ok"], true);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_tree_json_accepts_explicit_passphrase_unlock() {
    let path = temp_path("inspect_tree_json_passphrase_unlock");
    let _ = std::fs::remove_file(&path);

    let mut store =
        tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();
    for i in 0u32..500 {
        store
            .put(
                format!("tree-key-{i:05}").as_bytes(),
                format!("tree-val-{i:05}").as_bytes(),
            )
            .unwrap();
    }

    let rendered = cmd_inspect_tree_json(
        &path,
        Some(UnlockSecret::Passphrase("correct-horse".to_string())),
        false,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(json["ok"], true);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_verify_json_no_prompt_returns_wrong_key_for_encrypted_db() {
    let path = temp_path("inspect_verify_json_no_prompt_wrong_key");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();

    let err = cmd_inspect_verify_json(&path, None, true).err().unwrap();
    assert!(matches!(err, CliError::Core(TosumuError::WrongKey)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_tree_json_no_prompt_returns_wrong_key_for_encrypted_db() {
    let path = temp_path("inspect_tree_json_no_prompt_wrong_key");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();

    let err = cmd_inspect_tree_json(&path, None, true).err().unwrap();
    assert!(matches!(err, CliError::Core(TosumuError::WrongKey)));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_tree_wrong_key_uses_structured_error_envelope() {
    let path = temp_path("inspect_tree_json_wrong_key_envelope");
    let _ = std::fs::remove_file(&path);
    tosumu_core::page_store::PageStore::create_encrypted(&path, "correct-horse").unwrap();

    let err = cmd_inspect_tree_json(&path, None, true).err().unwrap();
    let rendered = render_inspect_error_report_json("inspect.tree", &err.error_report());
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(json["ok"], false);
    assert!(json["error"].as_object().unwrap().get("kind").is_none());
    assert_eq!(json["error"]["code"], "PROTECTOR_UNLOCK_WRONG_KEY");
    assert_eq!(
        json["error"]["message"],
        "wrong passphrase or key — could not unlock any keyslot"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn inspect_tree_corrupt_error_uses_corrupt_structured_envelope() {
    let rendered = render_inspect_error_json(
        "inspect.tree",
        &TosumuError::Corrupt {
            pgno: 9,
            reason: "tree node page number out of range",
        },
    );
    let json: serde_json::Value = serde_json::from_str(&rendered).unwrap();

    assert_eq!(json["ok"], false);
    assert!(json["error"].as_object().unwrap().get("kind").is_none());
    assert_eq!(json["error"]["code"], "PAGE_DECODE_CORRUPT");
    assert_eq!(json["error"]["status"], "integrity_failure");
    assert_eq!(json["error"]["pgno"], 9);
    assert_eq!(
        json["error"]["details"]["reason"],
        "tree node page number out of range"
    );
}

fn temp_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tosumu_cli_{tag}_{nanos}.tsm"))
}

fn overwrite_root_page(path: &std::path::Path, root_page: u64) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(tosumu_core::format::OFF_ROOT_PAGE as u64))
        .unwrap();
    file.write_all(&root_page.to_le_bytes()).unwrap();
    file.flush().unwrap();
}

fn flip_byte_at(path: &std::path::Path, offset: u64) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();

    let mut byte = [0u8; 1];
    std::io::Read::read_exact(&mut file, &mut byte).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    byte[0] ^= 0x01;
    file.write_all(&byte).unwrap();
    file.flush().unwrap();
}
