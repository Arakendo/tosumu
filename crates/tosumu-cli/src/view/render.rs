use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use tosumu_core::format::{PAGE_TYPE_FREE, PAGE_TYPE_INTERNAL, PAGE_TYPE_LEAF, PAGE_TYPE_OVERFLOW};
use tosumu_core::inspect::{
    PageVerifyResult, RecordInfo, TreeChildRelation, TreeNodeSummary, VerifyIssueKind,
    VerifyReport, WalRecordSummary, WalRecordSummaryKind,
};

use super::state::{FocusPane, PageStatus, SelectedPageDetail, ViewApp, ViewMode};

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, app: &ViewApp) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(44), Constraint::Min(40)])
        .split(root[1]);

    frame.render_widget(title_widget(app), root[0]);
    frame.render_stateful_widget(page_list_widget(app), body[0], &mut app.list_state());
    frame.render_widget(panel_widget(app), body[1]);
    frame.render_widget(help_widget(app), root[2]);
}

fn title_widget(app: &ViewApp) -> Paragraph<'static> {
    let mut spans = vec![
        Span::styled(
            "tosumu view",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::raw(app.path.display().to_string()),
        Span::raw("  "),
    ];
    for (index, mode) in ViewMode::ALL.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(" "));
        }
        let label = format!("{}:{}", index + 1, mode.label());
        let style = if *mode == app.mode {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(label, style));
    }
    Paragraph::new(Line::from(spans)).block(Block::default().borders(Borders::ALL))
}

fn page_list_widget(app: &ViewApp) -> List<'static> {
    let items = app
        .page_list_window()
        .into_iter()
        .map(page_list_item)
        .collect::<Vec<_>>();
    let title = app.page_list_title();

    List::new(items)
        .block(focus_block(&title, app.focus == FocusPane::Pages))
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ")
}

fn panel_widget(app: &ViewApp) -> Paragraph<'static> {
    match app.mode {
        ViewMode::Header => header_widget(app),
        ViewMode::Detail => detail_widget(app),
        ViewMode::Verify => verify_widget(app),
        ViewMode::Tree => tree_widget(app),
        ViewMode::Wal => wal_widget(app),
        ViewMode::Protectors => protectors_widget(app),
    }
}

fn header_widget(app: &ViewApp) -> Paragraph<'static> {
    panel_paragraph("Header", header_lines(app), app)
}

fn verify_widget(app: &ViewApp) -> Paragraph<'static> {
    panel_paragraph("Verify", verify_lines(app), app)
}

fn detail_widget(app: &ViewApp) -> Paragraph<'static> {
    panel_paragraph("Page Detail", detail_lines(app), app)
}

fn tree_widget(app: &ViewApp) -> Paragraph<'static> {
    panel_paragraph("B+ Tree", tree_lines(app), app)
}

fn wal_widget(app: &ViewApp) -> Paragraph<'static> {
    panel_paragraph("WAL", wal_lines(app), app)
}

fn protectors_widget(app: &ViewApp) -> Paragraph<'static> {
    panel_paragraph("Protectors", protectors_lines(app), app)
}

fn help_widget(app: &ViewApp) -> Paragraph<'static> {
    let watch = if app.watch_enabled { "on" } else { "off" };
    let text = format!(
        "Tab or Left/Right switches focus • j/k and arrows act on active pane • PgUp/PgDn jumps pages or scrolls panel • / starts filter • n/N move between matches • : starts goto-page • K/J scroll panel • 1-6 or h/d/v/t/l/p for panels • current={} • focus={} • scroll={} • watch={}{}",
        app.mode.label(),
        app.focus.label(),
        app.panel_scroll,
        watch,
        app.footer_status(),
    );
    Paragraph::new(text).block(Block::default().borders(Borders::ALL))
}

fn panel_paragraph(
    title: &'static str,
    lines: Vec<Line<'static>>,
    app: &ViewApp,
) -> Paragraph<'static> {
    Paragraph::new(Text::from(lines))
        .block(focus_block(title, app.focus == FocusPane::Panel))
        .scroll((app.panel_scroll, 0))
        .wrap(Wrap { trim: false })
}

fn header_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let header = &app.header;
    vec![
        Line::from(format!("format_version:       {}", header.format_version)),
        Line::from(format!("page_size:            {}", header.page_size)),
        Line::from(format!(
            "min_reader_version:   {}",
            header.min_reader_version
        )),
        Line::from(format!("flags:                0x{:04x}", header.flags)),
        Line::from(format!("page_count:           {}", header.page_count)),
        Line::from(format!("root_page:            {}", header.root_page)),
        Line::from(format!("freelist_head:        {}", header.freelist_head)),
        Line::from(format!(
            "wal_checkpoint_lsn:   {}",
            header.wal_checkpoint_lsn
        )),
        Line::from(format!("dek_id:               {}", header.dek_id)),
        Line::from(format!("keyslot_count:        {}", header.keyslot_count)),
        Line::from(format!(
            "keyslot_region_pages: {}",
            header.keyslot_region_pages
        )),
        Line::from(format!(
            "slot0_kind:           {}",
            keyslot_kind_label(header.ks0_kind)
        )),
        Line::from(format!("slot0_version:        {}", header.ks0_version)),
    ]
}

fn verify_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("pages_checked: {}", app.verify.pages_checked)),
        Line::from(format!("pages_ok:      {}", app.verify.pages_ok)),
        Line::from(format!("issues:        {}", app.verify.issues.len())),
        Line::from(if app.verify.issues.is_empty() {
            "status:        clean".to_string()
        } else {
            format!("status:        {} issue(s)", app.verify.issues.len())
        }),
    ];

    if app.verify.issues.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("No verification anomalies detected."));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("Issues:"));
        for issue in app.verify.issues.iter().take(10) {
            lines.push(Line::from(format!(
                "pg {:>4}: {}",
                issue.pgno, issue.description
            )));
        }
        if app.verify.issues.len() > 10 {
            lines.push(Line::from(format!(
                "... {} more issue(s)",
                app.verify.issues.len() - 10
            )));
        }
    }

    lines
}

fn detail_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &app.selected_detail {
        Some(SelectedPageDetail::Decoded(detail)) => {
            lines.push(Line::from(format!("page:         {}", detail.pgno)));
            lines.push(Line::from(format!(
                "type:         {}",
                page_type_label(detail.page_type)
            )));
            lines.push(Line::from(format!("page_version: {}", detail.page_version)));
            lines.push(Line::from(format!("slot_count:   {}", detail.slot_count)));
            lines.push(Line::from(format!("free_start:   {}", detail.free_start)));
            lines.push(Line::from(format!("free_end:     {}", detail.free_end)));
            lines.push(Line::from(""));

            if detail.records.is_empty() {
                lines.push(Line::from("(no decoded records)"));
            } else {
                for (index, record) in detail.records.iter().enumerate().take(12) {
                    lines.push(Line::from(format!(
                        "slot {index:>2}: {}",
                        record_summary(record)
                    )));
                }
                if detail.records.len() > 12 {
                    lines.push(Line::from(format!(
                        "... {} more record(s)",
                        detail.records.len() - 12
                    )));
                }
            }
        }
        Some(SelectedPageDetail::Unavailable {
            pgno,
            status,
            issue,
        }) => {
            lines.push(Line::from(format!("page:    {pgno}")));
            lines.push(Line::from(format!(
                "status:  {}",
                page_status_label(*status)
            )));
            lines.push(Line::from(""));
            if let Some(issue) = issue {
                lines.push(Line::from(issue.clone()));
            } else {
                lines.push(Line::from("No decoded detail is available for this page."));
            }
        }
        None => lines.push(Line::from(
            "page 0 is the file header; no data pages to inspect yet",
        )),
    }

    lines
}

fn tree_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &app.tree {
        Ok(tree) => {
            lines.push(Line::from(format!("root_pgno: {}", tree.root_pgno)));
            lines.push(Line::from(""));
            push_tree_lines(&tree.root, 0, "root", None, &mut lines);
        }
        Err(error) => lines.push(Line::from(error.clone())),
    }

    lines
}

fn wal_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &app.wal {
        Ok(wal) => {
            lines.push(Line::from(format!("wal_exists: {}", wal.wal_exists)));
            lines.push(Line::from(format!("wal_path:   {}", wal.wal_path)));
            lines.push(Line::from(format!("records:    {}", wal.records.len())));
            lines.push(Line::from(""));
            if wal.records.is_empty() {
                lines.push(Line::from("No WAL records found."));
            } else {
                for record in wal.records.iter().take(16) {
                    lines.push(Line::from(format_wal_record(record)));
                }
                if wal.records.len() > 16 {
                    lines.push(Line::from(format!(
                        "... {} more record(s)",
                        wal.records.len() - 16
                    )));
                }
            }
        }
        Err(error) => lines.push(Line::from(error.clone())),
    }

    lines
}

fn protectors_lines(app: &ViewApp) -> Vec<Line<'static>> {
    let auth = summarize_page_auth(&app.verify);
    let mut lines = vec![
        Line::from(format!(
            "protection:           {}",
            protection_mode_label(app.header.dek_id, app.header.keyslot_count)
        )),
        Line::from(format!("dek_id:               {}", app.header.dek_id)),
        Line::from(format!(
            "header keyslot_count: {}",
            app.header.keyslot_count
        )),
        Line::from(format!(
            "region pages:         {}",
            app.header.keyslot_region_pages
        )),
        Line::from(format!(
            "slot0:                {} v{}",
            keyslot_kind_label(app.header.ks0_kind),
            app.header.ks0_version
        )),
        Line::from(""),
        Line::from("Page auth:"),
        Line::from(format!(
            "ok: {}  auth_failed: {}  corrupt: {}  io: {}",
            auth.ok, auth.auth_failed, auth.corrupt, auth.io
        )),
    ];

    if let Some(selected_pgno) = app
        .selected
        .and_then(|index| app.pages.get(index).map(|page| page.pgno))
    {
        lines.push(Line::from(format!(
            "selected: {}",
            selected_page_auth_summary(&app.verify, selected_pgno)
        )));
    }

    let failures = app
        .verify
        .page_results
        .iter()
        .filter(|result| !result.auth_ok)
        .take(6)
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from("Failures:"));
        for result in &failures {
            lines.push(Line::from(format_page_auth_result(result)));
        }
        if auth.failed_pages() > failures.len() {
            lines.push(Line::from(format!(
                "... {} more failed page(s)",
                auth.failed_pages() - failures.len()
            )));
        }
    }

    lines.push(Line::from(""));
    lines.push(Line::from("Configured keyslots:"));

    match &app.keyslots {
        Ok(keyslots) => {
            if keyslots.is_empty() {
                lines.push(Line::from("No active keyslots found."));
            } else {
                for (slot, kind) in keyslots {
                    lines.push(Line::from(format!(
                        "slot {slot:>2}: {}",
                        keyslot_kind_label(*kind)
                    )));
                }
            }
        }
        Err(error) => lines.push(Line::from(error.clone())),
    }

    lines
}

fn focus_block(title: &str, focused: bool) -> Block<'static> {
    let title = if focused {
        format!("{title} [active]")
    } else {
        title.to_string()
    };
    let mut block = Block::default().title(title).borders(Borders::ALL);
    if focused {
        block = block.border_style(Style::default().fg(Color::Cyan));
    }
    block
}

pub(super) fn page_type_label(page_type: u8) -> &'static str {
    match page_type {
        PAGE_TYPE_LEAF => "Leaf",
        PAGE_TYPE_INTERNAL => "Internal",
        PAGE_TYPE_OVERFLOW => "Overflow",
        PAGE_TYPE_FREE => "Free",
        _ => "Unknown",
    }
}

pub(super) fn keyslot_kind_label(kind: u8) -> &'static str {
    match kind {
        0 => "Empty",
        1 => "Sentinel",
        2 => "Passphrase",
        3 => "RecoveryKey",
        4 => "Keyfile",
        _ => "Unknown",
    }
}

fn protection_mode_label(dek_id: u64, keyslot_count: u16) -> &'static str {
    if dek_id == 0 || keyslot_count == 0 {
        "plaintext"
    } else {
        "protected"
    }
}

fn format_page_auth_result(result: &PageVerifyResult) -> String {
    let issue = result.issue.as_deref().unwrap_or("no issue text");
    format!(
        "pg {:>4}: {} - {}",
        result.pgno,
        page_verify_state_label(result),
        issue
    )
}

pub(super) fn selected_page_auth_summary(report: &VerifyReport, pgno: u64) -> String {
    report
        .page_results
        .iter()
        .find(|result| result.pgno == pgno)
        .map(|result| {
            if result.auth_ok {
                match result.page_version {
                    Some(version) => format!("pg {pgno} ok (v{version})"),
                    None => format!("pg {pgno} ok"),
                }
            } else {
                format!("pg {pgno} {}", page_verify_state_label(result))
            }
        })
        .unwrap_or_else(|| format!("pg {pgno} not in verify report"))
}

fn page_verify_state_label(result: &PageVerifyResult) -> &'static str {
    if result.auth_ok {
        "ok"
    } else {
        match result.issue_kind {
            Some(VerifyIssueKind::AuthFailed) => "auth_failed",
            Some(VerifyIssueKind::Corrupt) => "corrupt",
            Some(VerifyIssueKind::Io) => "io",
            None => "unknown",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct PageAuthSummary {
    pub(super) ok: u64,
    pub(super) auth_failed: usize,
    pub(super) corrupt: usize,
    pub(super) io: usize,
}

impl PageAuthSummary {
    fn failed_pages(&self) -> usize {
        self.auth_failed + self.corrupt + self.io
    }
}

pub(super) fn summarize_page_auth(report: &VerifyReport) -> PageAuthSummary {
    let mut summary = PageAuthSummary::default();
    for result in &report.page_results {
        if result.auth_ok {
            summary.ok += 1;
            continue;
        }

        match result.issue_kind {
            Some(VerifyIssueKind::AuthFailed) => summary.auth_failed += 1,
            Some(VerifyIssueKind::Corrupt) => summary.corrupt += 1,
            Some(VerifyIssueKind::Io) => summary.io += 1,
            None => summary.io += 1,
        }
    }
    summary
}

fn page_status_label(status: PageStatus) -> &'static str {
    match status {
        PageStatus::Ok => "ok",
        PageStatus::AuthFailed => "auth",
        PageStatus::Corrupt => "corrupt",
        PageStatus::Io => "io",
    }
}

fn page_status_style(status: PageStatus) -> Style {
    match status {
        PageStatus::Ok => Style::default().fg(Color::Green),
        PageStatus::AuthFailed => Style::default().fg(Color::Red),
        PageStatus::Corrupt => Style::default().fg(Color::Yellow),
        PageStatus::Io => Style::default().fg(Color::Magenta),
    }
}

fn record_summary(record: &RecordInfo) -> String {
    match record {
        RecordInfo::Live { key, value } => format!(
            "live key={} value={}",
            preview_bytes(key),
            preview_bytes(value)
        ),
        RecordInfo::Tombstone { key } => format!("tombstone key={}", preview_bytes(key)),
        RecordInfo::Unknown { slot, record_type } => {
            format!("unknown slot={slot} record_type=0x{record_type:02x}")
        }
    }
}

pub(super) fn preview_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => {
            let shortened = text.chars().take(24).collect::<String>();
            if text.chars().count() > 24 {
                format!("{shortened:?}...")
            } else {
                format!("{shortened:?}")
            }
        }
        Err(_) => {
            let hex = bytes
                .iter()
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            if bytes.len() > 16 {
                format!("0x{hex}...")
            } else {
                format!("0x{hex}")
            }
        }
    }
}

fn push_tree_lines(
    node: &TreeNodeSummary,
    depth: usize,
    relation: &str,
    separator_key: Option<&[u8]>,
    lines: &mut Vec<Line<'static>>,
) {
    let indent = "  ".repeat(depth);
    let separator = separator_key
        .map(preview_bytes)
        .map(|key| format!(" sep={key}"))
        .unwrap_or_default();
    lines.push(Line::from(format!(
        "{indent}{relation} pg={} {} v{} slots={}{}",
        node.pgno,
        page_type_label(node.page_type),
        node.page_version,
        node.slot_count,
        separator,
    )));
    if let Some(next_leaf) = node.next_leaf {
        lines.push(Line::from(format!("{indent}  next_leaf={next_leaf}")));
    }
    for child in &node.children {
        let relation = match child.relation {
            TreeChildRelation::Leftmost => "left",
            TreeChildRelation::Separator => "right",
        };
        push_tree_lines(
            &child.child,
            depth + 1,
            relation,
            child.separator_key.as_deref(),
            lines,
        );
    }
}

pub(super) fn format_wal_record(record: &WalRecordSummary) -> String {
    match &record.kind {
        WalRecordSummaryKind::Begin { txn_id } => {
            format!("lsn {:>4}: begin txn={txn_id}", record.lsn)
        }
        WalRecordSummaryKind::PageWrite { pgno, page_version } => {
            format!(
                "lsn {:>4}: page_write pg={} v{}",
                record.lsn, pgno, page_version
            )
        }
        WalRecordSummaryKind::Commit { txn_id } => {
            format!("lsn {:>4}: commit txn={txn_id}", record.lsn)
        }
        WalRecordSummaryKind::Checkpoint { up_to_lsn } => {
            format!("lsn {:>4}: checkpoint up_to={up_to_lsn}", record.lsn)
        }
    }
}

fn page_list_item(page: &super::state::PageRow) -> ListItem<'static> {
    ListItem::new(Line::from(vec![
        Span::styled("■", page_status_style(page.status)),
        Span::raw(page_list_summary(page)),
    ]))
}

pub(super) fn page_list_summary(page: &super::state::PageRow) -> String {
    let page_version = page
        .page_version
        .map(|value| value.to_string())
        .unwrap_or_else(|| "--".to_string());
    let slot_count = page
        .slot_count
        .map(|value| value.to_string())
        .unwrap_or_else(|| "--".to_string());
    format!(
        " {:>4}  {:<8}  {:<7}  v{:>3}  slots {:>3}",
        page.pgno,
        page.page_type.map(page_type_label).unwrap_or("?"),
        page_status_label(page.status),
        page_version,
        slot_count,
    )
}
