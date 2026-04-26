use std::path::Path;
use std::time::{Duration, Instant};

use ratatui::widgets::ListState;
use tosumu_core::format::{PAGE_TYPE_FREE, PAGE_TYPE_INTERNAL, PAGE_TYPE_LEAF, PAGE_TYPE_OVERFLOW};
use tosumu_core::inspect::{
    inspect_page_from_pager,
    inspect_pages_from_pager,
    HeaderInfo,
    PageInspectState,
    PageSummary,
    RecordInfo,
    TreeSummary,
    VerifyReport,
    WalSummary,
};
use tosumu_core::pager::Pager;

use crate::error_boundary::CliError;

use super::watch::{capture_watch_fingerprint, watch_refresh_needed, WatchFingerprint};

pub(super) const PANEL_SCROLL_PAGE: u16 = 8;
pub(super) const PAGE_LIST_JUMP: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FocusPane {
    Pages,
    Panel,
}

impl FocusPane {
    pub(super) fn toggle(self) -> Self {
        match self {
            FocusPane::Pages => FocusPane::Panel,
            FocusPane::Panel => FocusPane::Pages,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            FocusPane::Pages => "pages",
            FocusPane::Panel => "panel",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ViewMode {
    Header,
    Detail,
    Verify,
    Tree,
    Wal,
    Protectors,
}

impl ViewMode {
    pub(super) const ALL: [ViewMode; 6] = [
        ViewMode::Header,
        ViewMode::Detail,
        ViewMode::Verify,
        ViewMode::Tree,
        ViewMode::Wal,
        ViewMode::Protectors,
    ];

    pub(super) fn from_key(code: crossterm::event::KeyCode) -> Option<Self> {
        match code {
            crossterm::event::KeyCode::Char('1') | crossterm::event::KeyCode::Char('h') => Some(ViewMode::Header),
            crossterm::event::KeyCode::Char('2') | crossterm::event::KeyCode::Char('d') => Some(ViewMode::Detail),
            crossterm::event::KeyCode::Char('3') | crossterm::event::KeyCode::Char('v') => Some(ViewMode::Verify),
            crossterm::event::KeyCode::Char('4') | crossterm::event::KeyCode::Char('t') => Some(ViewMode::Tree),
            crossterm::event::KeyCode::Char('5') | crossterm::event::KeyCode::Char('l') => Some(ViewMode::Wal),
            crossterm::event::KeyCode::Char('6') | crossterm::event::KeyCode::Char('p') => Some(ViewMode::Protectors),
            _ => None,
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            ViewMode::Header => "Header",
            ViewMode::Detail => "Detail",
            ViewMode::Verify => "Verify",
            ViewMode::Tree => "Tree",
            ViewMode::Wal => "WAL",
            ViewMode::Protectors => "Protectors",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PageStatus {
    Ok,
    AuthFailed,
    Corrupt,
    Io,
}

#[derive(Clone)]
pub(super) struct PageRow {
    pub(super) pgno: u64,
    pub(super) page_type: Option<u8>,
    pub(super) page_version: Option<u64>,
    pub(super) slot_count: Option<u16>,
    pub(super) status: PageStatus,
    pub(super) issue: Option<String>,
    pub(super) search_text: String,
}

pub(super) enum SelectedPageDetail {
    Decoded(PageSummary),
    Unavailable {
        pgno: u64,
        status: PageStatus,
        issue: Option<String>,
    },
}

pub(super) struct ViewApp<'a> {
    pub(super) path: &'a Path,
    pub(super) header: HeaderInfo,
    pub(super) verify: VerifyReport,
    pub(super) pages: Vec<PageRow>,
    pub(super) mode: ViewMode,
    pub(super) focus: FocusPane,
    pub(super) watch_enabled: bool,
    pub(super) panel_scroll: u16,
    pub(super) last_refresh: Instant,
    pub(super) last_watch_fingerprint: Option<WatchFingerprint>,
    pub(super) status_message: Option<String>,
    pub(super) tree: Result<TreeSummary, String>,
    pub(super) wal: Result<WalSummary, String>,
    pub(super) keyslots: Result<Vec<(u16, u8)>, String>,
    pub(super) selected: Option<usize>,
    pub(super) selected_detail: Option<SelectedPageDetail>,
    pub(super) pending_page_jump: Option<String>,
    pub(super) filter_query: String,
    pub(super) pending_filter_query: Option<String>,
}

impl<'a> ViewApp<'a> {
    pub(super) fn new(
        path: &'a Path,
        header: HeaderInfo,
        verify: VerifyReport,
        pages: Vec<PageRow>,
        tree: Result<TreeSummary, String>,
        wal: Result<WalSummary, String>,
        keyslots: Result<Vec<(u16, u8)>, String>,
        watch_enabled: bool,
    ) -> Self {
        Self {
            path,
            header,
            verify,
            pages,
            mode: ViewMode::Detail,
            focus: FocusPane::Pages,
            watch_enabled,
            panel_scroll: 0,
            last_refresh: Instant::now(),
            last_watch_fingerprint: capture_watch_fingerprint(path).ok(),
            status_message: None,
            tree,
            wal,
            keyslots,
            selected: None,
            selected_detail: None,
            pending_page_jump: None,
            filter_query: String::new(),
            pending_filter_query: None,
        }
    }

    pub(super) fn list_state(&self) -> ListState {
        let mut state = ListState::default();
        state.select(self.selected_visible_index());
        state
    }

    pub(super) fn select_first(&mut self, pager: &Pager) -> Result<(), CliError> {
        let visible = self.visible_page_indices();
        let Some(index) = visible.first().copied() else {
            self.selected = None;
            self.selected_detail = None;
            return Ok(());
        };
        self.selected = Some(index);
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)
    }

    pub(super) fn select_last(&mut self, pager: &Pager) -> Result<(), CliError> {
        let visible = self.visible_page_indices();
        let Some(index) = visible.last().copied() else {
            self.selected = None;
            self.selected_detail = None;
            return Ok(());
        };
        self.selected = Some(index);
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)
    }

    pub(super) fn select_next(&mut self, pager: &Pager) -> Result<(), CliError> {
        let visible = self.visible_page_indices();
        if visible.is_empty() {
            self.selected = None;
            self.selected_detail = None;
            return Ok(());
        }

        let next_visible = match self.selected_visible_index() {
            Some(index) if index + 1 < visible.len() => index + 1,
            _ => visible.len() - 1,
        };
        self.selected = Some(visible[next_visible]);
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)
    }

    pub(super) fn select_previous(&mut self, pager: &Pager) -> Result<(), CliError> {
        let visible = self.visible_page_indices();
        if visible.is_empty() {
            self.selected = None;
            self.selected_detail = None;
            return Ok(());
        }

        let next_visible = match self.selected_visible_index() {
            Some(index) if index > 0 => index - 1,
            _ => 0,
        };
        self.selected = Some(visible[next_visible]);
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)
    }

    pub(super) fn select_index(&mut self, pager: &Pager, visible_index: usize) -> Result<(), CliError> {
        let visible = self.visible_page_indices();
        if visible.is_empty() {
            self.selected = None;
            self.selected_detail = None;
            return Ok(());
        }

        self.selected = Some(visible[visible_index.min(visible.len() - 1)]);
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)
    }

    pub(super) fn select_pgno(&mut self, pager: &Pager, pgno: u64) -> Result<bool, CliError> {
        if self.pages.is_empty() {
            self.status_message = Some("no data pages available".to_string());
            return Ok(false);
        }

        if let Some(index) = self.pages.iter().position(|page| page.pgno == pgno) {
            self.selected = Some(index);
            self.panel_scroll = 0;
            self.refresh_selected_detail(pager)?;
            self.status_message = Some(format!("jumped to page {pgno}"));
            return Ok(true);
        }

        self.status_message = Some(format!("page {pgno} not found"));
        Ok(false)
    }

    pub(super) fn move_down(&mut self, pager: &Pager) -> Result<(), CliError> {
        match self.focus {
            FocusPane::Pages => self.select_next(pager),
            FocusPane::Panel => {
                self.scroll_panel_down(1);
                Ok(())
            }
        }
    }

    pub(super) fn move_up(&mut self, pager: &Pager) -> Result<(), CliError> {
        match self.focus {
            FocusPane::Pages => self.select_previous(pager),
            FocusPane::Panel => {
                self.scroll_panel_up(1);
                Ok(())
            }
        }
    }

    pub(super) fn move_home(&mut self, pager: &Pager) -> Result<(), CliError> {
        match self.focus {
            FocusPane::Pages => self.select_first(pager),
            FocusPane::Panel => {
                self.panel_scroll = 0;
                Ok(())
            }
        }
    }

    pub(super) fn move_end(&mut self, pager: &Pager) -> Result<(), CliError> {
        match self.focus {
            FocusPane::Pages => self.select_last(pager),
            FocusPane::Panel => {
                self.panel_scroll = u16::MAX;
                Ok(())
            }
        }
    }

    pub(super) fn move_page_down(&mut self, pager: &Pager) -> Result<(), CliError> {
        match self.focus {
            FocusPane::Pages => {
                let next_index = self.selected_visible_index().unwrap_or(0).saturating_add(PAGE_LIST_JUMP);
                self.select_index(pager, next_index)
            }
            FocusPane::Panel => {
                self.scroll_panel_down(PANEL_SCROLL_PAGE);
                Ok(())
            }
        }
    }

    pub(super) fn move_page_up(&mut self, pager: &Pager) -> Result<(), CliError> {
        match self.focus {
            FocusPane::Pages => {
                let next_index = self.selected_visible_index().unwrap_or(0).saturating_sub(PAGE_LIST_JUMP);
                self.select_index(pager, next_index)
            }
            FocusPane::Panel => {
                self.scroll_panel_up(PANEL_SCROLL_PAGE);
                Ok(())
            }
        }
    }

    pub(super) fn toggle_focus(&mut self) {
        self.focus = self.focus.toggle();
    }

    pub(super) fn set_mode(&mut self, mode: ViewMode) {
        if self.mode != mode {
            self.mode = mode;
            self.panel_scroll = 0;
        }
    }

    pub(super) fn scroll_panel_down(&mut self, amount: u16) {
        self.panel_scroll = self.panel_scroll.saturating_add(amount);
    }

    pub(super) fn scroll_panel_up(&mut self, amount: u16) {
        self.panel_scroll = self.panel_scroll.saturating_sub(amount);
    }

    pub(super) fn refresh_selected_detail(&mut self, pager: &Pager) -> Result<(), CliError> {
        self.selected_detail = match self.selected.and_then(|index| self.pages.get(index).cloned()) {
            Some(page) if matches!(page.status, PageStatus::Ok) => {
                Some(SelectedPageDetail::Decoded(inspect_page_from_pager(pager, page.pgno)?))
            }
            Some(page) => Some(SelectedPageDetail::Unavailable {
                pgno: page.pgno,
                status: page.status,
                issue: page.issue,
            }),
            None => None,
        };
        Ok(())
    }

    pub(super) fn restore_selection(&mut self, selected_pgno: Option<u64>, pager: &Pager) -> Result<(), CliError> {
        if self.pages.is_empty() {
            self.selected = None;
            self.selected_detail = None;
            return Ok(());
        }

        self.selected = selected_pgno
            .and_then(|pgno| self.pages.iter().position(|page| page.pgno == pgno))
            .or(Some(0));
        self.normalize_selection();
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)
    }

    pub(super) fn should_refresh(&self) -> bool {
        self.watch_enabled && self.last_refresh.elapsed() >= Duration::from_secs(1)
    }

    pub(super) fn watch_refresh_needed(&self, path: &Path) -> std::io::Result<bool> {
        watch_refresh_needed(path, self.last_watch_fingerprint.as_ref())
    }

    pub(super) fn note_watch_check(&mut self) {
        self.last_refresh = Instant::now();
    }

    pub(super) fn toggle_watch(&mut self) {
        self.watch_enabled = !self.watch_enabled;
        self.last_refresh = Instant::now();
        self.status_message = Some(if self.watch_enabled {
            "watch enabled".to_string()
        } else {
            "watch paused".to_string()
        });
    }

    pub(super) fn page_jump_active(&self) -> bool {
        self.pending_page_jump.is_some()
    }

    pub(super) fn filter_prompt_active(&self) -> bool {
        self.pending_filter_query.is_some()
    }

    pub(super) fn start_page_jump(&mut self) {
        self.pending_filter_query = None;
        self.pending_page_jump = Some(String::new());
    }

    pub(super) fn push_page_jump_digit(&mut self, digit: char) {
        if let Some(input) = &mut self.pending_page_jump {
            input.push(digit);
        }
    }

    pub(super) fn pop_page_jump_digit(&mut self) {
        if let Some(input) = &mut self.pending_page_jump {
            input.pop();
        }
    }

    pub(super) fn cancel_page_jump(&mut self) {
        self.pending_page_jump = None;
        self.status_message = Some("page jump canceled".to_string());
    }

    pub(super) fn start_filter_prompt(&mut self) {
        self.pending_page_jump = None;
        self.pending_filter_query = Some(self.filter_query.clone());
    }

    pub(super) fn push_filter_char(&mut self, ch: char) {
        if let Some(input) = &mut self.pending_filter_query {
            input.push(ch);
        }
    }

    pub(super) fn pop_filter_char(&mut self) {
        if let Some(input) = &mut self.pending_filter_query {
            input.pop();
        }
    }

    pub(super) fn cancel_filter_prompt(&mut self) {
        self.pending_filter_query = None;
        self.status_message = Some("filter canceled".to_string());
    }

    pub(super) fn confirm_filter_prompt(&mut self, pager: &Pager) -> Result<(), CliError> {
        let Some(input) = self.pending_filter_query.take() else {
            return Ok(());
        };

        self.filter_query = input.trim().to_string();
        self.normalize_selection();
        self.panel_scroll = 0;
        self.refresh_selected_detail(pager)?;

        if self.filter_query.is_empty() {
            self.status_message = Some("filter cleared".to_string());
        } else {
            self.status_message = Some(format!(
                "filter matched {} page(s)",
                self.visible_page_count()
            ));
        }

        Ok(())
    }

    pub(super) fn visible_pages(&self) -> Vec<&PageRow> {
        self.visible_page_indices()
            .into_iter()
            .map(|index| &self.pages[index])
            .collect()
    }

    pub(super) fn visible_page_count(&self) -> usize {
        self.visible_page_indices().len()
    }

    fn selected_visible_index(&self) -> Option<usize> {
        let selected = self.selected?;
        self.visible_page_indices()
            .into_iter()
            .position(|index| index == selected)
    }

    fn visible_page_indices(&self) -> Vec<usize> {
        match self.active_filter_query() {
            Some(query) => self
                .pages
                .iter()
                .enumerate()
                .filter(|(_, page)| page_matches_filter(page, query))
                .map(|(index, _)| index)
                .collect(),
            None => (0..self.pages.len()).collect(),
        }
    }

    fn active_filter_query(&self) -> Option<&str> {
        let query = self.filter_query.trim();
        if query.is_empty() {
            None
        } else {
            Some(query)
        }
    }

    fn normalize_selection(&mut self) {
        let visible = self.visible_page_indices();
        match (self.selected, visible.first().copied()) {
            (_, None) => {
                self.selected = None;
                self.selected_detail = None;
            }
            (Some(selected), _) if visible.contains(&selected) => {}
            (_, Some(first)) => {
                self.selected = Some(first);
            }
        }
    }

    pub(super) fn confirm_page_jump(&mut self, pager: &Pager) -> Result<(), CliError> {
        let Some(input) = self.pending_page_jump.take() else {
            return Ok(());
        };

        if input.is_empty() {
            self.status_message = Some("enter a page number".to_string());
            return Ok(());
        }

        match input.parse::<u64>() {
            Ok(pgno) if pgno > 0 => {
                self.select_pgno(pager, pgno)?;
            }
            Ok(_) => {
                self.status_message = Some("page 0 is the file header".to_string());
            }
            Err(_) => {
                self.status_message = Some(format!("invalid page number: {input}"));
            }
        }

        Ok(())
    }

    pub(super) fn footer_status(&self) -> String {
        if let Some(input) = &self.pending_filter_query {
            return format!(" • filter: {input}");
        }

        if let Some(input) = &self.pending_page_jump {
            return format!(" • goto page: {input}");
        }

        let mut parts = Vec::new();
        if let Some(query) = self.active_filter_query() {
            parts.push(format!("filter: {query} ({})", self.visible_page_count()));
        }
        let status = self.status_suffix();
        if !status.is_empty() {
            parts.push(status.trim_start_matches(" • ").to_string());
        }

        if parts.is_empty() {
            String::new()
        } else {
            format!(" • {}", parts.join(" • "))
        }
    }

    pub(super) fn status_suffix(&self) -> String {
        self.status_message
            .as_ref()
            .map(|message| format!(" • {message}"))
            .unwrap_or_default()
    }
}

pub(super) fn load_page_rows(pager: &Pager) -> Result<Vec<PageRow>, CliError> {
    let pages = inspect_pages_from_pager(pager)?;
    Ok(pages
        .pages
        .into_iter()
        .map(|page| {
            let search_text = if matches!(page.state, PageInspectState::Ok) {
                inspect_page_from_pager(pager, page.pgno)
                    .map(|summary| page_record_search_text(&summary))
                    .unwrap_or_default()
            } else {
                String::new()
            };

            PageRow {
                pgno: page.pgno,
                page_type: page.page_type,
                page_version: page.page_version,
                slot_count: page.slot_count,
                status: match page.state {
                    PageInspectState::Ok => PageStatus::Ok,
                    PageInspectState::AuthFailed => PageStatus::AuthFailed,
                    PageInspectState::Corrupt => PageStatus::Corrupt,
                    PageInspectState::Io => PageStatus::Io,
                },
                issue: page.issue,
                search_text,
            }
        })
        .collect())
}

fn page_matches_filter(page: &PageRow, query: &str) -> bool {
    let query = query.to_ascii_lowercase();
    let page_type = page
        .page_type
        .map(|value| match value {
            PAGE_TYPE_LEAF => "leaf",
            PAGE_TYPE_INTERNAL => "internal",
            PAGE_TYPE_OVERFLOW => "overflow",
            PAGE_TYPE_FREE => "free",
            _ => "unknown",
        })
        .unwrap_or("unknown");
    let status = match page.status {
        PageStatus::Ok => "ok",
        PageStatus::AuthFailed => "auth",
        PageStatus::Corrupt => "corrupt",
        PageStatus::Io => "io",
    };

    let mut haystacks = vec![
        page.pgno.to_string(),
        page_type.to_string(),
        status.to_string(),
    ];

    if let Some(page_version) = page.page_version {
        haystacks.push(page_version.to_string());
    }
    if let Some(slot_count) = page.slot_count {
        haystacks.push(slot_count.to_string());
    }
    if let Some(issue) = &page.issue {
        haystacks.push(issue.to_ascii_lowercase());
    }
    if !page.search_text.is_empty() {
        haystacks.push(page.search_text.clone());
    }

    haystacks
        .into_iter()
        .any(|value| value.to_ascii_lowercase().contains(&query))
}

fn page_record_search_text(summary: &PageSummary) -> String {
    summary
        .records
        .iter()
        .map(record_search_text)
        .collect::<Vec<_>>()
        .join(" ")
}

fn record_search_text(record: &RecordInfo) -> String {
    match record {
        RecordInfo::Live { key, value } => format!(
            "live {} {} {} {}",
            searchable_bytes(key),
            searchable_hex(key),
            searchable_bytes(value),
            searchable_hex(value)
        ),
        RecordInfo::Tombstone { key } => format!(
            "tombstone {} {}",
            searchable_bytes(key),
            searchable_hex(key)
        ),
        RecordInfo::Unknown { slot, record_type } => {
            format!("unknown slot {slot} type {record_type:02x}")
        }
    }
}

fn searchable_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_ascii_lowercase()
}

fn searchable_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}