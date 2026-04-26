use std::path::Path;

use crate::error_boundary::CliError;
use tosumu_core::error::TosumuError;
use tosumu_core::page_store::PageStore;

use crate::inspect_contract::{
    bytes_to_hex, inspect_btree_verify_code, inspect_verify_issue_code, keyslot_kind_name,
    page_type_name, render_json, InspectBtreeVerifyPayload, InspectEnvelope, InspectHeaderPayload,
    InspectKeyslotPayload, InspectPagePayload, InspectPageVerifyPayload, InspectPagesEntryPayload,
    InspectPagesPayload, InspectProtectorSlotPayload, InspectProtectorsPayload,
    InspectRecordPayload, InspectTreeChildPayload, InspectTreeNodePayload, InspectTreePayload,
    InspectVerifyIssuePayload, InspectVerifyPayload, InspectWalPayload, InspectWalRecordPayload,
};
use crate::unlock::{open_btree_with_unlock, open_pager_with_unlock, UnlockSecret};

pub(crate) fn cmd_inspect_header_json(path: &Path) -> Result<String, TosumuError> {
    let header = tosumu_core::inspect::read_header_info(path)?;
    render_json(&InspectEnvelope {
        command: "inspect.header",
        ok: true,
        payload: Some(InspectHeaderPayload {
            format_version: header.format_version,
            page_size: header.page_size,
            min_reader_version: header.min_reader_version,
            flags: header.flags,
            page_count: header.page_count,
            freelist_head: header.freelist_head,
            root_page: header.root_page,
            wal_checkpoint_lsn: header.wal_checkpoint_lsn,
            dek_id: header.dek_id,
            keyslot_count: header.keyslot_count,
            keyslot_region_pages: header.keyslot_region_pages,
            slot0: InspectKeyslotPayload {
                kind: keyslot_kind_name(header.ks0_kind),
                kind_byte: header.ks0_kind,
                version: header.ks0_version,
            },
        }),
        error: None,
    })
}

pub(crate) struct VerifySnapshot {
    pub(crate) report: tosumu_core::inspect::VerifyReport,
    pub(crate) btree: InspectBtreeVerifyPayload,
    pub(crate) btree_error: Option<CliError>,
}

pub(crate) fn collect_verify_snapshot(
    path: &Path,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<VerifySnapshot, CliError> {
    let (pager, unlock) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let report = tosumu_core::inspect::verify_pager(&pager)?;
    let (btree, btree_error) = if report.issues.is_empty() {
        match open_btree_with_unlock(path, unlock.as_ref()) {
            Ok(tree) => match tree.check_invariants() {
                Ok(()) => (
                    InspectBtreeVerifyPayload {
                        checked: true,
                        ok: true,
                        code: None,
                        message: None,
                    },
                    None,
                ),
                Err(error) => (
                    InspectBtreeVerifyPayload {
                        checked: true,
                        ok: false,
                        code: None,
                        message: Some(error.to_string()),
                    },
                    None,
                ),
            },
            Err(error) => (
                InspectBtreeVerifyPayload {
                    checked: false,
                    ok: false,
                    code: None,
                    message: Some(format!("could not open as BTree: {error}")),
                },
                Some(error.into()),
            ),
        }
    } else {
        (
            InspectBtreeVerifyPayload {
                checked: false,
                ok: false,
                code: None,
                message: Some("skipped because page integrity issues were found".to_string()),
            },
            None,
        )
    };

    Ok(VerifySnapshot {
        report,
        btree,
        btree_error,
    })
}

pub(crate) fn cmd_inspect_verify_json(
    path: &Path,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<String, CliError> {
    let snapshot = collect_verify_snapshot(path, unlock, no_prompt)?;
    let btree = InspectBtreeVerifyPayload {
        checked: snapshot.btree.checked,
        ok: snapshot.btree.ok,
        code: inspect_btree_verify_code(
            snapshot.btree.checked,
            snapshot.btree.ok,
            snapshot.btree.message.is_some(),
        ),
        message: snapshot.btree.message,
    };
    Ok(render_json(&InspectEnvelope {
        command: "inspect.verify",
        ok: snapshot.report.issues.is_empty()
            && snapshot.btree_error.is_none()
            && (!btree.checked || btree.ok),
        payload: Some(InspectVerifyPayload {
            pages_checked: snapshot.report.pages_checked,
            pages_ok: snapshot.report.pages_ok,
            issue_count: snapshot.report.issues.len(),
            issues: snapshot
                .report
                .issues
                .into_iter()
                .map(|issue| InspectVerifyIssuePayload {
                    pgno: issue.pgno,
                    code: Some(inspect_verify_issue_code(issue.kind)),
                    description: issue.description,
                })
                .collect(),
            page_results: snapshot
                .report
                .page_results
                .into_iter()
                .map(|result| InspectPageVerifyPayload {
                    pgno: result.pgno,
                    page_version: result.page_version,
                    auth_ok: result.auth_ok,
                    issue_code: result.issue_kind.map(inspect_verify_issue_code),
                    issue: result.issue,
                })
                .collect(),
            btree,
        }),
        error: None,
    })?)
}

pub(crate) fn cmd_inspect_page_json(
    path: &Path,
    pgno: u64,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<String, CliError> {
    let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let page = tosumu_core::inspect::inspect_page_from_pager(&pager, pgno)?;
    Ok(render_json(&InspectEnvelope {
        command: "inspect.page",
        ok: true,
        payload: Some(InspectPagePayload {
            pgno: page.pgno,
            page_version: page.page_version,
            page_type: page.page_type,
            page_type_name: page_type_name(page.page_type),
            slot_count: page.slot_count,
            free_start: page.free_start,
            free_end: page.free_end,
            records: page
                .records
                .into_iter()
                .enumerate()
                .map(|(slot, record)| match record {
                    tosumu_core::inspect::RecordInfo::Live { key, value } => InspectRecordPayload {
                        kind: "Live",
                        key_hex: Some(bytes_to_hex(&key)),
                        value_hex: Some(bytes_to_hex(&value)),
                        slot: Some(slot as u16),
                        record_type: None,
                    },
                    tosumu_core::inspect::RecordInfo::Tombstone { key } => InspectRecordPayload {
                        kind: "Tombstone",
                        key_hex: Some(bytes_to_hex(&key)),
                        value_hex: None,
                        slot: Some(slot as u16),
                        record_type: None,
                    },
                    tosumu_core::inspect::RecordInfo::Unknown { slot, record_type } => {
                        InspectRecordPayload {
                            kind: "Unknown",
                            key_hex: None,
                            value_hex: None,
                            slot: Some(slot),
                            record_type: Some(record_type),
                        }
                    }
                })
                .collect(),
        }),
        error: None,
    })?)
}

pub(crate) fn cmd_inspect_pages_json(
    path: &Path,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<String, CliError> {
    let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let pages = tosumu_core::inspect::inspect_pages_from_pager(&pager)?;
    Ok(render_json(&InspectEnvelope {
        command: "inspect.pages",
        ok: pages
            .pages
            .iter()
            .all(|page| matches!(page.state, tosumu_core::inspect::PageInspectState::Ok)),
        payload: Some(InspectPagesPayload {
            pages: pages
                .pages
                .into_iter()
                .map(|page| InspectPagesEntryPayload {
                    pgno: page.pgno,
                    page_version: page.page_version,
                    page_type: page.page_type,
                    page_type_name: page.page_type.map(page_type_name),
                    slot_count: page.slot_count,
                    state: match page.state {
                        tosumu_core::inspect::PageInspectState::Ok => "ok",
                        tosumu_core::inspect::PageInspectState::AuthFailed => "auth_failed",
                        tosumu_core::inspect::PageInspectState::Corrupt => "corrupt",
                        tosumu_core::inspect::PageInspectState::Io => "io",
                    },
                    issue: page.issue,
                })
                .collect(),
        }),
        error: None,
    })?)
}

pub(crate) fn cmd_inspect_wal_json(path: &Path) -> Result<String, TosumuError> {
    let wal = tosumu_core::inspect::inspect_wal(path)?;
    let records = wal
        .records
        .into_iter()
        .map(|record| match record.kind {
            tosumu_core::inspect::WalRecordSummaryKind::Begin { txn_id } => {
                InspectWalRecordPayload {
                    lsn: record.lsn,
                    kind: "begin",
                    txn_id: Some(txn_id),
                    pgno: None,
                    page_version: None,
                    up_to_lsn: None,
                }
            }
            tosumu_core::inspect::WalRecordSummaryKind::PageWrite { pgno, page_version } => {
                InspectWalRecordPayload {
                    lsn: record.lsn,
                    kind: "page_write",
                    txn_id: None,
                    pgno: Some(pgno),
                    page_version: Some(page_version),
                    up_to_lsn: None,
                }
            }
            tosumu_core::inspect::WalRecordSummaryKind::Commit { txn_id } => {
                InspectWalRecordPayload {
                    lsn: record.lsn,
                    kind: "commit",
                    txn_id: Some(txn_id),
                    pgno: None,
                    page_version: None,
                    up_to_lsn: None,
                }
            }
            tosumu_core::inspect::WalRecordSummaryKind::Checkpoint { up_to_lsn } => {
                InspectWalRecordPayload {
                    lsn: record.lsn,
                    kind: "checkpoint",
                    txn_id: None,
                    pgno: None,
                    page_version: None,
                    up_to_lsn: Some(up_to_lsn),
                }
            }
        })
        .collect::<Vec<_>>();

    render_json(&InspectEnvelope {
        command: "inspect.wal",
        ok: true,
        payload: Some(InspectWalPayload {
            wal_exists: wal.wal_exists,
            wal_path: wal.wal_path,
            record_count: records.len(),
            records,
        }),
        error: None,
    })
}

fn map_tree_node_payload(node: tosumu_core::inspect::TreeNodeSummary) -> InspectTreeNodePayload {
    InspectTreeNodePayload {
        pgno: node.pgno,
        page_version: node.page_version,
        page_type: node.page_type,
        page_type_name: page_type_name(node.page_type),
        slot_count: node.slot_count,
        free_start: node.free_start,
        free_end: node.free_end,
        next_leaf: node.next_leaf,
        children: node
            .children
            .into_iter()
            .map(|child| InspectTreeChildPayload {
                relation: match child.relation {
                    tosumu_core::inspect::TreeChildRelation::Leftmost => "leftmost",
                    tosumu_core::inspect::TreeChildRelation::Separator => "separator",
                },
                separator_key_hex: child.separator_key.as_ref().map(|key| bytes_to_hex(key)),
                child: Box::new(map_tree_node_payload(*child.child)),
            })
            .collect(),
    }
}

pub(crate) fn cmd_inspect_tree_json(
    path: &Path,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<String, CliError> {
    let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
    let tree = tosumu_core::inspect::inspect_tree_from_pager(&pager)?;
    Ok(render_json(&InspectEnvelope {
        command: "inspect.tree",
        ok: true,
        payload: Some(InspectTreePayload {
            root_pgno: tree.root_pgno,
            root: map_tree_node_payload(tree.root),
        }),
        error: None,
    })?)
}

pub(crate) fn cmd_inspect_protectors_json(path: &Path) -> Result<String, TosumuError> {
    let slots = PageStore::list_keyslots(path)?;
    render_json(&InspectEnvelope {
        command: "inspect.protectors",
        ok: true,
        payload: Some(InspectProtectorsPayload {
            slot_count: slots.len(),
            slots: slots
                .into_iter()
                .map(|(slot, kind)| InspectProtectorSlotPayload {
                    slot,
                    kind: keyslot_kind_name(kind),
                    kind_byte: kind,
                })
                .collect(),
        }),
        error: None,
    })
}
