use serde::Serialize;
use tosumu_core::error::TosumuError;

pub(crate) const INSPECT_SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
pub(crate) struct InspectEnvelope<T> {
    pub(crate) schema_version: u32,
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
    pub(crate) description: String,
}

#[derive(Serialize)]
pub(crate) struct InspectPageVerifyPayload {
    pub(crate) pgno: u64,
    pub(crate) page_version: Option<u64>,
    pub(crate) auth_ok: bool,
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
    pub(crate) message: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct InspectKeyslotPayload {
    pub(crate) kind: &'static str,
    pub(crate) kind_byte: u8,
    pub(crate) version: u8,
}

#[derive(Serialize)]
pub(crate) struct InspectErrorPayload {
    pub(crate) kind: &'static str,
    pub(crate) message: String,
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

pub(crate) fn inspect_error_payload(error: &TosumuError) -> InspectErrorPayload {
    match error {
        TosumuError::WrongKey => InspectErrorPayload {
            kind: "wrong_key",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::AuthFailed { pgno } => InspectErrorPayload {
            kind: "auth_failed",
            message: error.to_string(),
            pgno: *pgno,
        },
        TosumuError::Corrupt { pgno, .. } => InspectErrorPayload {
            kind: "corrupt",
            message: error.to_string(),
            pgno: Some(*pgno),
        },
        TosumuError::InvalidArgument(_) => InspectErrorPayload {
            kind: "invalid_argument",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::FileBusy { .. } => InspectErrorPayload {
            kind: "file_busy",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::NotATosumFile
        | TosumuError::NewerFormat { .. }
        | TosumuError::PageSizeMismatch { .. } => InspectErrorPayload {
            kind: "unsupported",
            message: error.to_string(),
            pgno: None,
        },
        TosumuError::CorruptRecord { .. }
        | TosumuError::Io(_)
        | TosumuError::EncryptFailed
        | TosumuError::RngFailed
        | TosumuError::FileTruncated { .. }
        | TosumuError::Poisoned
        | TosumuError::OutOfSpace
        | TosumuError::CommittedButFlushFailed { .. } => InspectErrorPayload {
            kind: "io",
            message: error.to_string(),
            pgno: None,
        },
        _ => InspectErrorPayload {
            kind: "unsupported",
            message: error.to_string(),
            pgno: None,
        },
    }
}

pub(crate) fn render_inspect_error_json(command: &'static str, error: &TosumuError) -> String {
    render_json(&InspectEnvelope::<()> {
        schema_version: INSPECT_SCHEMA_VERSION,
        command,
        ok: false,
        payload: None,
        error: Some(inspect_error_payload(error)),
    }).unwrap_or_else(|serialization_error| {
        format!(
            "{{\"schema_version\":{INSPECT_SCHEMA_VERSION},\"command\":\"{command}\",\"ok\":false,\"error\":{{\"kind\":\"io\",\"message\":{:?}}}}}",
            serialization_error.to_string()
        )
    })
}