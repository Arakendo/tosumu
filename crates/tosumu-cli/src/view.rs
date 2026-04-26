use std::path::Path;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tosumu_core::error::TosumuError;
use tosumu_core::inspect::{inspect_tree_from_pager, inspect_wal, read_header_info, verify_pager};
use tosumu_core::page_store::PageStore;
use tosumu_core::pager::Pager;

use crate::error_boundary::CliError;
use crate::unlock::{open_pager, open_pager_with_unlock, UnlockSecret};

mod render;
mod state;
mod watch;

#[cfg(test)]
mod tests;

use render::draw;
use state::{load_page_rows, ViewApp, ViewMode, PANEL_SCROLL_PAGE};
use watch::capture_watch_fingerprint;

pub fn run(path: &Path, watch: bool) -> Result<(), CliError> {
    let header = read_header_info(path)?;
    let (mut pager, unlock) = open_pager(path)?;
    let verify = verify_pager(&pager)?;
    let pages = load_page_rows(&pager)?;
    let tree = inspect_tree_from_pager(&pager).map_err(|error| error.to_string());
    let wal = inspect_wal(path).map_err(|error| error.to_string());
    let keyslots = PageStore::list_keyslots(path).map_err(|error| error.to_string());
    let mut app = ViewApp::new(path, header, verify, pages, tree, wal, keyslots, watch);
    app.select_first(&pager)?;

    enable_raw_mode().map_err(TosumuError::Io)?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(TosumuError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(TosumuError::Io)?;

    let run_result = run_loop(&mut terminal, path, &mut pager, &unlock, &mut app);

    let mut restore_error = None;
    if let Err(error) = disable_raw_mode().map_err(TosumuError::Io) {
        restore_error = Some(error);
    }
    if let Err(error) =
        execute!(terminal.backend_mut(), LeaveAlternateScreen).map_err(TosumuError::Io)
    {
        restore_error = restore_error.or(Some(error));
    }
    if let Err(error) = terminal.show_cursor().map_err(TosumuError::Io) {
        restore_error = restore_error.or(Some(error));
    }

    match (run_result, restore_error) {
        (Err(error), _) => Err(error),
        (Ok(()), Some(error)) => Err(error.into()),
        (Ok(()), None) => Ok(()),
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    path: &Path,
    pager: &mut Pager,
    unlock: &Option<UnlockSecret>,
    app: &mut ViewApp,
) -> Result<(), CliError> {
    loop {
        terminal
            .draw(|frame| draw(frame, app))
            .map_err(TosumuError::Io)?;

        if !event::poll(Duration::from_millis(200)).map_err(TosumuError::Io)? {
            if app.should_refresh() {
                match app.watch_refresh_needed(path) {
                    Ok(true) => refresh_view(path, pager, unlock, app),
                    Ok(false) => app.note_watch_check(),
                    Err(_) => refresh_view(path, pager, unlock, app),
                }
            }
            continue;
        }

        let Event::Key(key) = event::read().map_err(TosumuError::Io)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        if app.filter_prompt_active() {
            match key.code {
                KeyCode::Esc => app.cancel_filter_prompt(),
                KeyCode::Enter => app.confirm_filter_prompt(pager)?,
                KeyCode::Backspace => app.pop_filter_char(),
                KeyCode::Char(ch) if !ch.is_control() => app.push_filter_char(ch),
                _ => {}
            }
            continue;
        }

        if app.page_jump_active() {
            match key.code {
                KeyCode::Esc => app.cancel_page_jump(),
                KeyCode::Enter => app.confirm_page_jump(pager)?,
                KeyCode::Backspace => app.pop_page_jump_digit(),
                KeyCode::Char(digit) if digit.is_ascii_digit() => app.push_page_jump_digit(digit),
                _ => {}
            }
            continue;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Char('/') => app.start_filter_prompt(),
            KeyCode::Char(':') => app.start_page_jump(),
            KeyCode::Char('n') => app.next_match(pager)?,
            KeyCode::Char('N') => app.previous_match(pager)?,
            KeyCode::Tab | KeyCode::Right | KeyCode::Left => app.toggle_focus(),
            KeyCode::Down | KeyCode::Char('j') => app.move_down(pager)?,
            KeyCode::Up | KeyCode::Char('k') => app.move_up(pager)?,
            KeyCode::Home | KeyCode::Char('g') => app.move_home(pager)?,
            KeyCode::End | KeyCode::Char('G') => app.move_end(pager)?,
            KeyCode::PageDown => app.move_page_down(pager)?,
            KeyCode::PageUp => app.move_page_up(pager)?,
            KeyCode::Char('J') => app.scroll_panel_down(PANEL_SCROLL_PAGE),
            KeyCode::Char('K') => app.scroll_panel_up(PANEL_SCROLL_PAGE),
            KeyCode::Char('r') => refresh_view(path, pager, unlock, app),
            KeyCode::Char('w') => app.toggle_watch(),
            code => {
                if let Some(mode) = ViewMode::from_key(code) {
                    app.set_mode(mode);
                }
            }
        }
    }
}

fn refresh_view(path: &Path, pager: &mut Pager, unlock: &Option<UnlockSecret>, app: &mut ViewApp) {
    let selected_pgno = app
        .selected
        .and_then(|index| app.pages.get(index).map(|page| page.pgno));

    match refresh_view_result(path, pager, unlock, app, selected_pgno) {
        Ok(()) => app.status_message = Some("refreshed".to_string()),
        Err(error) => {
            app.status_message = Some(format!("refresh failed: {error:?}"));
            app.last_refresh = std::time::Instant::now();
        }
    }
}

fn refresh_view_result(
    path: &Path,
    pager: &mut Pager,
    unlock: &Option<UnlockSecret>,
    app: &mut ViewApp,
    selected_pgno: Option<u64>,
) -> Result<(), CliError> {
    let (next_pager, _) = open_pager_with_unlock(path, unlock.clone(), true)?;
    app.header = read_header_info(path)?;
    app.verify = verify_pager(&next_pager)?;
    app.pages = load_page_rows(&next_pager)?;
    app.tree = inspect_tree_from_pager(&next_pager).map_err(|error| error.to_string());
    app.wal = inspect_wal(path).map_err(|error| error.to_string());
    app.keyslots = PageStore::list_keyslots(path).map_err(|error| error.to_string());
    app.last_watch_fingerprint = capture_watch_fingerprint(path).ok();
    *pager = next_pager;
    app.restore_selection(selected_pgno, pager)?;
    app.last_refresh = std::time::Instant::now();
    Ok(())
}
