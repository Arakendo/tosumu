use serde::Serialize;
use serde_json::{Map, Value};
use tosumu_core::error::{codes, ErrorReport, ErrorValue, TosumuError};
use tosumu_core::inspect::VerifyIssueKind;

pub(crate) mod verify_payload_codes {
    pub const VERIFY_PAGE_AUTH_FAILED: &str = "VERIFY_PAGE_AUTH_FAILED";
    pub const VERIFY_PAGE_CORRUPT: &str = "VERIFY_PAGE_CORRUPT";
    pub const VERIFY_PAGE_IO: &str = "VERIFY_PAGE_IO";
    pub const VERIFY_BTREE_INVALID: &str = "VERIFY_BTREE_INVALID";
    pub const VERIFY_BTREE_INCOMPLETE: &str = "VERIFY_BTREE_INCOMPLETE";
}

#[derive(Serialize)]
pub(crate) struct InspectEnvelope<T> {
    pub(crate) command: &'static str,
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payload: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<InspectErrorPayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectHeaderPayload {
    pub(crate) format_version: u16,
    pub(crate) page_size: u16,
    pub(crate) min_reader_version: u16,
    pub(crate) flags: u16,
    pub(crate) page_count: u64,
    pub(crate) freelist_head: u64,
    pub(crate) root_page: u64,
    pub(crate) wal_checkpoint_lsn: u64,
    pub(crate) dek_id: u64,
    pub(crate) keyslot_count: u16,
    pub(crate) keyslot_region_pages: u16,
    pub(crate) slot0: InspectKeyslotPayload,
}

#[derive(Serialize)]
pub(crate) struct InspectVerifyPayload {
    pub(crate) pages_checked: u64,
    pub(crate) pages_ok: u64,
    pub(crate) issue_count: usize,
    pub(crate) issues: Vec<InspectVerifyIssuePayload>,
    pub(crate) page_results: Vec<InspectPageVerifyPayload>,
    pub(crate) btree: InspectBtreeVerifyPayload,
}

#[derive(Serialize)]
pub(crate) struct InspectPagePayload {
    pub(crate) pgno: u64,
    pub(crate) page_version: u64,
    pub(crate) page_type: u8,
    pub(crate) page_type_name: &'static str,
    pub(crate) slot_count: u16,
    pub(crate) free_start: u16,
    pub(crate) free_end: u16,
    pub(crate) records: Vec<InspectRecordPayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectPagesPayload {
    pub(crate) pages: Vec<InspectPagesEntryPayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectPagesEntryPayload {
    pub(crate) pgno: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) page_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) page_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) page_type_name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) slot_count: Option<u16>,
    pub(crate) state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issue: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct InspectWalPayload {
    pub(crate) wal_exists: bool,
    pub(crate) wal_path: String,
    pub(crate) record_count: usize,
    pub(crate) records: Vec<InspectWalRecordPayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectWalRecordPayload {
    pub(crate) lsn: u64,
    pub(crate) kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) txn_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pgno: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) page_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) up_to_lsn: Option<u64>,
}

#[derive(Serialize)]
pub(crate) struct InspectTreePayload {
    pub(crate) root_pgno: u64,
    pub(crate) root: InspectTreeNodePayload,
}

#[derive(Serialize)]
pub(crate) struct InspectTreeNodePayload {
    pub(crate) pgno: u64,
    pub(crate) page_version: u64,
    pub(crate) page_type: u8,
    pub(crate) page_type_name: &'static str,
    pub(crate) slot_count: u16,
    pub(crate) free_start: u16,
    pub(crate) free_end: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) next_leaf: Option<u64>,
    pub(crate) children: Vec<InspectTreeChildPayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectTreeChildPayload {
    pub(crate) relation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) separator_key_hex: Option<String>,
    pub(crate) child: Box<InspectTreeNodePayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectProtectorsPayload {
    pub(crate) slot_count: usize,
    pub(crate) slots: Vec<InspectProtectorSlotPayload>,
}

#[derive(Serialize)]
pub(crate) struct InspectRecordPayload {
    pub(crate) kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) value_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) slot: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) record_type: Option<u8>,
}

#[derive(Serialize)]
pub(crate) struct InspectVerifyIssuePayload {
    pub(crate) pgno: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<&'static str>,
    pub(crate) description: String,
}

#[derive(Serialize)]
pub(crate) struct InspectPageVerifyPayload {
    pub(crate) pgno: u64,
    pub(crate) page_version: Option<u64>,
    pub(crate) auth_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issue_code: Option<&'static str>,
    pub(crate) issue: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct InspectProtectorSlotPayload {
    pub(crate) slot: u16,
    pub(crate) kind: &'static str,
    pub(crate) kind_byte: u8,
}

#[derive(Serialize)]
pub(crate) struct InspectBtreeVerifyPayload {
    pub(crate) checked: bool,
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

pub(crate) fn inspect_verify_issue_code(kind: VerifyIssueKind) -> &'static str {
    match kind {
        VerifyIssueKind::AuthFailed => verify_payload_codes::VERIFY_PAGE_AUTH_FAILED,
        VerifyIssueKind::Corrupt => verify_payload_codes::VERIFY_PAGE_CORRUPT,
        VerifyIssueKind::Io => verify_payload_codes::VERIFY_PAGE_IO,
    }
}

pub(crate) fn inspect_btree_verify_code(
    checked: bool,
    ok: bool,
    has_message: bool,
) -> Option<&'static str> {
    if !has_message {
        return None;
    }

    if checked && !ok {
        Some(verify_payload_codes::VERIFY_BTREE_INVALID)
    } else if !checked {
        Some(verify_payload_codes::VERIFY_BTREE_INCOMPLETE)
    } else {
        None
    }
}

#[derive(Serialize)]
pub(crate) struct InspectKeyslotPayload {
    pub(crate) kind: &'static str,
    pub(crate) kind_byte: u8,
    pub(crate) version: u8,
}

#[derive(Serialize)]
pub(crate) struct InspectErrorPayload {
    pub(crate) code: &'static str,
    pub(crate) status: &'static str,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) details: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pgno: Option<u64>,
}

pub(crate) fn render_json<T: Serialize>(value: &T) -> Result<String, TosumuError> {
    serde_json::to_string_pretty(value)
        .map_err(|e| TosumuError::Io(std::io::Error::other(e.to_string())))
}

pub(crate) fn keyslot_kind_name(kind: u8) -> &'static str {
    match kind {
        tosumu_core::format::KEYSLOT_KIND_EMPTY => "Empty",
        tosumu_core::format::KEYSLOT_KIND_SENTINEL => "Sentinel",
        tosumu_core::format::KEYSLOT_KIND_PASSPHRASE => "Passphrase",
        tosumu_core::format::KEYSLOT_KIND_RECOVERY_KEY => "RecoveryKey",
        tosumu_core::format::KEYSLOT_KIND_KEYFILE => "Keyfile",
        _ => "Unknown",
    }
}

pub(crate) fn page_type_name(page_type: u8) -> &'static str {
    match page_type {
        tosumu_core::format::PAGE_TYPE_LEAF => "Leaf",
        tosumu_core::format::PAGE_TYPE_INTERNAL => "Internal",
        tosumu_core::format::PAGE_TYPE_OVERFLOW => "Overflow",
        tosumu_core::format::PAGE_TYPE_FREE => "Free",
        _ => "Unknown",
    }
}

pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn inspect_error_payload_from_report(report: &ErrorReport) -> InspectErrorPayload {
    InspectErrorPayload {
        code: report.code,
        status: report.status.as_str(),
        message: report.message.clone(),
        details: inspect_error_details(report),
        pgno: report.detail_u64("pgno"),
    }
}

fn inspect_error_details(report: &ErrorReport) -> Option<Map<String, Value>> {
    if report.details.is_empty() {
        return None;
    }

    let mut details = Map::new();
    for detail in &report.details {
        details.insert(detail.key.to_string(), inspect_error_value(&detail.value));
    }
    Some(details)
}

fn inspect_error_value(value: &ErrorValue) -> Value {
    match value {
        ErrorValue::Bool(value) => Value::Bool(*value),
        ErrorValue::Str(value) => Value::String(value.clone()),
        ErrorValue::U16(value) => Value::Number((*value).into()),
        ErrorValue::U64(value) => Value::Number((*value).into()),
    }
}

pub(crate) fn render_inspect_error_json(command: &'static str, error: &TosumuError) -> String {
    render_inspect_error_report_json(command, &error.error_report())
}

pub(crate) fn render_inspect_error_report_json(
    command: &'static str,
    report: &ErrorReport,
) -> String {
    render_json(&InspectEnvelope::<()> {
        command,
        ok: false,
        payload: None,
        error: Some(inspect_error_payload_from_report(report)),
    }).unwrap_or_else(|serialization_error| {
        let message = format!("{:?}", serialization_error.to_string());
        format!(
            "{{\"command\":\"{command}\",\"ok\":false,\"error\":{{\"code\":\"{}\",\"status\":\"external_failure\",\"message\":{message}}}}}",
            codes::FILE_IO_FAILED,
        )
    })
}
