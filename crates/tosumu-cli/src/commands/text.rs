use std::path::{Path, PathBuf};

use tosumu_core::error::TosumuError;

use super::inspect::collect_verify_snapshot;
use crate::error_boundary::CliError;
use crate::inspect_contract::InspectBtreeVerifyPayload;
use crate::unlock::{open_pager_with_unlock, UnlockSecret};

pub(crate) enum VerifyCommandOutcome {
    Clean,
    IssuesFound,
}

pub(crate) fn cmd_dump(
    path: &Path,
    page: Option<u64>,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<(), CliError> {
    use tosumu_core::format::{
        KEYSLOT_KIND_EMPTY, KEYSLOT_KIND_KEYFILE, KEYSLOT_KIND_PASSPHRASE,
        KEYSLOT_KIND_RECOVERY_KEY, KEYSLOT_KIND_SENTINEL, PAGE_TYPE_FREE, PAGE_TYPE_INTERNAL,
        PAGE_TYPE_LEAF, PAGE_TYPE_OVERFLOW,
    };
    use tosumu_core::inspect::{inspect_page_from_pager, read_header_info, RecordInfo};

    match page {
        None => {
            let h = read_header_info(path)?;
            println!("=== file header: {} ===", path.display());
            println!("magic:                TOSUMUv0");
            println!("format_version:       {}", h.format_version);
            println!("min_reader_version:   {}", h.min_reader_version);
            println!("page_size:            {}", h.page_size);
            let fl = h.flags;
            println!(
                "flags:                {fl:#06x}  [reserved={}  has_keyslots={}]",
                fl & 1,
                (fl >> 1) & 1
            );
            let fl_note = if h.freelist_head == 0 { "  (none)" } else { "" };
            let rp_note = if h.root_page == 0 { "  (none)" } else { "" };
            println!("page_count:           {}", h.page_count);
            println!("freelist_head:        {}{fl_note}", h.freelist_head);
            println!("root_page:            {}{rp_note}", h.root_page);
            println!("wal_checkpoint_lsn:   {}", h.wal_checkpoint_lsn);
            println!("dek_id:               {}", h.dek_id);
            println!("keyslot_count:        {}", h.keyslot_count);
            println!("keyslot_region_pages: {}", h.keyslot_region_pages);
            println!();
            println!("=== keyslot 0 ===");
            let kind_name = match h.ks0_kind {
                KEYSLOT_KIND_EMPTY => "Empty",
                KEYSLOT_KIND_SENTINEL => "Sentinel",
                KEYSLOT_KIND_PASSPHRASE => "Passphrase",
                KEYSLOT_KIND_RECOVERY_KEY => "RecoveryKey",
                KEYSLOT_KIND_KEYFILE => "Keyfile",
                _ => "Unknown",
            };
            let kind_note = match h.ks0_kind {
                KEYSLOT_KIND_SENTINEL => {
                    "  (plaintext DEK — authentication only, no confidentiality)"
                }
                KEYSLOT_KIND_PASSPHRASE => "  (Argon2id KDF — authentication + confidentiality)",
                KEYSLOT_KIND_RECOVERY_KEY => "  (Base32 recovery secret → HKDF-derived KEK)",
                KEYSLOT_KIND_KEYFILE => "  (raw 32-byte KEK loaded from a file)",
                _ => "",
            };
            println!("kind:    {kind_name}{kind_note}");
            println!("version: {}", h.ks0_version);
        }
        Some(pgno) => {
            let (pager, _) = open_pager_with_unlock(path, unlock, no_prompt)?;
            let s = inspect_page_from_pager(&pager, pgno)?;
            let type_name = match s.page_type {
                PAGE_TYPE_LEAF => "Leaf",
                PAGE_TYPE_INTERNAL => "Internal",
                PAGE_TYPE_OVERFLOW => "Overflow",
                PAGE_TYPE_FREE => "Free",
                _ => "Unknown",
            };
            println!("=== page {pgno}: {} ===", path.display());
            println!("page_version: {}", s.page_version);
            println!("page_type:    {type_name} (0x{:02x})", s.page_type);
            println!("slot_count:   {}", s.slot_count);
            println!("free_start:   {}", s.free_start);
            println!("free_end:     {}", s.free_end);
            println!("free_bytes:   {}", s.free_end.saturating_sub(s.free_start));
            if !s.records.is_empty() {
                println!();
            }
            for (i, rec) in s.records.iter().enumerate() {
                match rec {
                    RecordInfo::Live { key, value } => {
                        println!(
                            "  slot {i:3}  Live       key={}  value={}",
                            fmt_bytes(key),
                            fmt_bytes(value)
                        );
                    }
                    RecordInfo::Tombstone { key } => {
                        println!("  slot {i:3}  Tombstone  key={}", fmt_bytes(key));
                    }
                    RecordInfo::Unknown { slot, record_type } => {
                        println!("  slot {slot:3}  Unknown    record_type=0x{record_type:02x}");
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn cmd_hex(path: &Path, pgno: u64) -> tosumu_core::error::Result<()> {
    use tosumu_core::format::{
        CIPHERTEXT_OFFSET, NONCE_SIZE, PAGE_SIZE, PAGE_VERSION_SIZE, TAG_SIZE,
    };
    use tosumu_core::inspect::read_raw_frame;

    let frame = read_raw_frame(path, pgno)?;
    println!(
        "=== raw frame: page {pgno}  {}  ({PAGE_SIZE} bytes) ===",
        path.display()
    );
    println!();

    print_hex_section("nonce · 12 bytes · offset 0x0000", &frame[..NONCE_SIZE], 0);

    let pv_label = format!("page_version · {PAGE_VERSION_SIZE} bytes · offset 0x{NONCE_SIZE:04x}");
    print_hex_section(&pv_label, &frame[NONCE_SIZE..CIPHERTEXT_OFFSET], NONCE_SIZE);

    let ct_len = PAGE_SIZE - CIPHERTEXT_OFFSET - TAG_SIZE;
    let ct_label = format!("ciphertext · {ct_len} bytes · offset 0x{CIPHERTEXT_OFFSET:04x}");
    print_hex_section(
        &ct_label,
        &frame[CIPHERTEXT_OFFSET..PAGE_SIZE - TAG_SIZE],
        CIPHERTEXT_OFFSET,
    );

    let tag_off = PAGE_SIZE - TAG_SIZE;
    let tag_label = format!("auth tag (Poly1305) · {TAG_SIZE} bytes · offset 0x{tag_off:04x}");
    print_hex_section(&tag_label, &frame[tag_off..], tag_off);

    Ok(())
}

pub(crate) fn cmd_verify(
    path: &Path,
    explain: bool,
    unlock: Option<UnlockSecret>,
    no_prompt: bool,
) -> Result<VerifyCommandOutcome, CliError> {
    let snapshot = collect_verify_snapshot(path, unlock, no_prompt)?;
    if let Some(error) = snapshot.btree_error {
        return Err(error);
    }
    let report = snapshot.report;
    let outcome = verify_command_outcome(report.issues.len(), &snapshot.btree);
    println!(
        "verifying {} ({} data pages) ...",
        path.display(),
        report.pages_checked
    );

    if explain {
        println!();
        for r in &report.page_results {
            println!("page {}:", r.pgno);
            if r.auth_ok {
                let ver = r.page_version.unwrap_or(0);
                println!("  integrity:   OK     — AEAD tag verified (page_version {ver})");
                println!("  freshness:   unanchored — LSN witness not configured (§23, Stage 6)");
                println!("  epistemic:   OK     — no overclaiming");
            } else {
                let reason = r.issue.as_deref().unwrap_or("unknown");
                println!("  integrity:   FAIL   — {reason}");
                println!("  freshness:   N/A");
                println!(
                    "  epistemic:   FAIL   — cannot verify page {} is what was written",
                    r.pgno
                );
            }
            println!();
        }
    } else {
        for issue in &report.issues {
            eprintln!("  page {} ... FAILED: {}", issue.pgno, issue.description);
        }
    }

    if report.issues.is_empty() {
        if snapshot.btree.checked && snapshot.btree.ok {
            if explain {
                println!(
                    "  btree:       OK     — keys sorted, routing correct, leaf chain ordered"
                );
            }
        } else if let Some(message) = &snapshot.btree.message {
            if snapshot.btree.checked {
                eprintln!("  btree:       FAIL   — {message}");
                eprintln!("FAILED: btree structural invariant violated");
            } else if explain {
                eprintln!("  btree:       SKIP   — {message}");
            }
        }
        println!("all pages ok: {}/{}", report.pages_ok, report.pages_checked);
    } else {
        if !explain {
            eprintln!(
                "FAILED: {}/{} pages ok, {} issue(s)",
                report.pages_ok,
                report.pages_checked,
                report.issues.len()
            );
        } else {
            println!(
                "FAILED: {}/{} pages ok, {} issue(s)",
                report.pages_ok,
                report.pages_checked,
                report.issues.len()
            );
        }
    }
    Ok(outcome)
}

fn verify_command_outcome(
    issue_count: usize,
    btree: &InspectBtreeVerifyPayload,
) -> VerifyCommandOutcome {
    if issue_count > 0 || (btree.checked && !btree.ok) {
        VerifyCommandOutcome::IssuesFound
    } else {
        VerifyCommandOutcome::Clean
    }
}

pub(crate) fn cmd_backup(src: &Path, dest: &Path) -> Result<(), CliError> {
    use tosumu_core::wal::wal_path;

    const MAX_BACKUP_ATTEMPTS: u32 = 5;

    let dest_wal = wal_path(dest);
    if dest.exists() || dest_wal.exists() {
        return Err(CliError::backup_destination_exists(dest));
    }

    let staged_main = backup_temp_path(dest, "main");
    let staged_wal = backup_temp_path(&dest_wal, "wal");
    let probe_main = backup_temp_path(dest, "main-probe");
    let probe_wal = backup_temp_path(&dest_wal, "wal-probe");
    let _ = std::fs::remove_file(&staged_main);
    let _ = std::fs::remove_file(&staged_wal);
    let _ = std::fs::remove_file(&probe_main);
    let _ = std::fs::remove_file(&probe_wal);

    let src_wal = wal_path(src);
    let mut copied_wal = false;
    let mut stable = false;

    for _ in 0..MAX_BACKUP_ATTEMPTS {
        cleanup_backup_temp(&staged_main, &staged_wal);
        cleanup_backup_temp(&probe_main, &probe_wal);

        std::fs::copy(src, &staged_main).map_err(TosumuError::Io)?;
        let copied_wal_a = copy_optional_file(&src_wal, &staged_wal)?;

        std::fs::copy(src, &probe_main).map_err(|e| {
            cleanup_backup_temp(&staged_main, &staged_wal);
            TosumuError::Io(e)
        })?;
        let copied_wal_b = copy_optional_file(&src_wal, &probe_wal).map_err(|e| {
            cleanup_backup_temp(&staged_main, &staged_wal);
            cleanup_backup_temp(&probe_main, &probe_wal);
            e
        })?;

        let wal_matches = copied_wal_a == copied_wal_b
            && (!copied_wal_a || files_equal(&staged_wal, &probe_wal).map_err(TosumuError::Io)?);
        let main_matches = files_equal(&staged_main, &probe_main).map_err(|e| {
            cleanup_backup_temp(&staged_main, &staged_wal);
            cleanup_backup_temp(&probe_main, &probe_wal);
            TosumuError::Io(e)
        })?;

        if main_matches && wal_matches {
            copied_wal = copied_wal_a;
            stable = true;
            break;
        }
    }

    cleanup_backup_temp(&probe_main, &probe_wal);

    if !stable {
        cleanup_backup_temp(&staged_main, &staged_wal);
        return Err(TosumuError::FileBusy {
            path: src.to_path_buf(),
            operation: "capturing a stable backup snapshot",
        }
        .into());
    }

    if copied_wal {
        std::fs::rename(&staged_wal, &dest_wal).map_err(|e| {
            let _ = std::fs::remove_file(&staged_main);
            let _ = std::fs::remove_file(&staged_wal);
            TosumuError::Io(e)
        })?;
    }

    std::fs::rename(&staged_main, dest).map_err(|e| {
        let _ = std::fs::remove_file(&staged_main);
        if copied_wal {
            let _ = std::fs::remove_file(&dest_wal);
        }
        TosumuError::Io(e)
    })?;

    println!("backed up {} → {}", src.display(), dest.display());
    if src_wal.exists() {
        println!("backed up {} → {}", src_wal.display(), dest_wal.display());
    }
    Ok(())
}

fn backup_temp_path(dest: &Path, kind: &str) -> PathBuf {
    let file_name = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("backup");
    dest.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), kind))
}

fn copy_optional_file(src: &Path, dest: &Path) -> Result<bool, TosumuError> {
    let _ = std::fs::remove_file(dest);
    if src.exists() {
        std::fs::copy(src, dest).map_err(TosumuError::Io)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn cleanup_backup_temp(main: &Path, wal: &Path) {
    let _ = std::fs::remove_file(main);
    let _ = std::fs::remove_file(wal);
}

fn files_equal(a: &Path, b: &Path) -> std::io::Result<bool> {
    use std::fs::File;
    use std::io::Read;

    let meta_a = std::fs::metadata(a)?;
    let meta_b = std::fs::metadata(b)?;
    if meta_a.len() != meta_b.len() {
        return Ok(false);
    }

    let mut fa = File::open(a)?;
    let mut fb = File::open(b)?;
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];

    loop {
        let read_a = fa.read(&mut buf_a)?;
        let read_b = fb.read(&mut buf_b)?;
        if read_a != read_b {
            return Ok(false);
        }
        if read_a == 0 {
            return Ok(true);
        }
        if buf_a[..read_a] != buf_b[..read_b] {
            return Ok(false);
        }
    }
}

fn fmt_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => format!("{text:?}"),
        Err(_) => {
            let hex: String = bytes
                .iter()
                .take(48)
                .map(|byte| format!("{byte:02x}"))
                .collect();
            if bytes.len() > 48 {
                format!("0x{hex}…")
            } else {
                format!("0x{hex}")
            }
        }
    }
}

fn print_hex_section(label: &str, data: &[u8], base_offset: usize) {
    println!("[{label}]");
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = base_offset + i * 16;
        let hex_col: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("{offset:04x}: {:<47}  |{ascii}|", hex_col.join(" "));
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::{verify_command_outcome, VerifyCommandOutcome};
    use crate::inspect_contract::InspectBtreeVerifyPayload;

    #[test]
    fn verify_command_outcome_reports_page_issues_as_findings() {
        let btree = InspectBtreeVerifyPayload {
            checked: true,
            ok: true,
            code: None,
            message: None,
        };

        assert!(matches!(
            verify_command_outcome(1, &btree),
            VerifyCommandOutcome::IssuesFound
        ));
    }

    #[test]
    fn verify_command_outcome_reports_btree_failure_as_findings() {
        let btree = InspectBtreeVerifyPayload {
            checked: true,
            ok: false,
            code: None,
            message: Some("btree structural invariant violated".to_string()),
        };

        assert!(matches!(
            verify_command_outcome(0, &btree),
            VerifyCommandOutcome::IssuesFound
        ));
    }

    #[test]
    fn verify_command_outcome_reports_clean_verify_as_clean() {
        let btree = InspectBtreeVerifyPayload {
            checked: true,
            ok: true,
            code: None,
            message: None,
        };

        assert!(matches!(
            verify_command_outcome(0, &btree),
            VerifyCommandOutcome::Clean
        ));
    }
}
