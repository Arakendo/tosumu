use std::path::Path;

use tosumu_core::format::{PAGE_TYPE_FREE, PAGE_TYPE_INTERNAL, PAGE_TYPE_LEAF, PAGE_TYPE_OVERFLOW};
use tosumu_core::inspect::{
    HeaderInfo,
    PageVerifyResult,
    TreeNodeSummary,
    TreeSummary,
    VerifyIssueKind,
    VerifyReport,
    WalRecordSummary,
    WalRecordSummaryKind,
    WalSummary,
};
use tosumu_core::pager::Pager;
use tosumu_core::page_store::PageStore;

use super::render::{
    format_wal_record,
    keyslot_kind_label,
    page_list_summary,
    page_type_label,
    preview_bytes,
    selected_page_auth_summary,
    summarize_page_auth,
    PageAuthSummary,
};
use super::state::{
    FocusPane,
    PageRow,
    PageStatus,
    ViewApp,
    ViewMode,
    PAGE_LIST_JUMP,
    PANEL_SCROLL_PAGE,
};
use super::watch::{capture_watch_fingerprint, watch_refresh_needed};

fn header(page_count: u64) -> HeaderInfo {
    HeaderInfo {
        format_version: 1,
        page_size: 4096,
        min_reader_version: 1,
        flags: 0,
        page_count,
        freelist_head: 0,
        root_page: if page_count > 1 { 1 } else { 0 },
        wal_checkpoint_lsn: 0,
        dek_id: 0,
        keyslot_count: 0,
        keyslot_region_pages: 0,
        ks0_kind: 0,
        ks0_version: 0,
    }
}

fn empty_verify() -> VerifyReport {
    VerifyReport {
        pages_checked: 0,
        pages_ok: 0,
        issues: Vec::new(),
        page_results: Vec::new(),
    }
}

fn test_tree() -> Result<TreeSummary, String> {
    Ok(TreeSummary {
        root_pgno: 1,
        root: TreeNodeSummary {
            pgno: 1,
            page_version: 1,
            page_type: PAGE_TYPE_LEAF,
            slot_count: 0,
            free_start: 0,
            free_end: 0,
            next_leaf: None,
            children: Vec::new(),
        },
    })
}

fn test_wal() -> Result<WalSummary, String> {
    Ok(WalSummary {
        wal_exists: false,
        wal_path: "db.tsm.wal".to_string(),
        records: Vec::new(),
    })
}

fn new_app(page_count: u64, pages: Vec<PageRow>) -> ViewApp<'static> {
    ViewApp::new(
        Path::new("db.tsm"),
        header(page_count),
        empty_verify(),
        pages,
        test_tree(),
        test_wal(),
        Ok(Vec::new()),
        false,
    )
}

fn corrupt_page(pgno: u64) -> PageRow {
    PageRow {
        pgno,
        page_type: Some(PAGE_TYPE_LEAF),
        page_version: Some(pgno),
        slot_count: Some(0),
        status: PageStatus::Corrupt,
        issue: Some("corrupt".to_string()),
        search_text: String::new(),
    }
}

fn with_temp_db<T>(test_name: &str, test: impl FnOnce(&Path, &Pager) -> T) -> T {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("tosumu_{test_name}_{nanos}.tsm"));
    let wal = tosumu_core::wal::wal_path(&path);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&wal);

    PageStore::create(&path).unwrap();
    let pager = Pager::open_readonly(&path).unwrap();
    let result = test(&path, &pager);

    drop(pager);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&path);

    result
}

#[test]
fn page_type_labels_cover_known_types() {
    assert_eq!(page_type_label(PAGE_TYPE_LEAF), "Leaf");
    assert_eq!(page_type_label(PAGE_TYPE_INTERNAL), "Internal");
    assert_eq!(page_type_label(PAGE_TYPE_OVERFLOW), "Overflow");
    assert_eq!(page_type_label(PAGE_TYPE_FREE), "Free");
    assert_eq!(page_type_label(0xff), "Unknown");
}

#[test]
fn keyslot_kind_labels_cover_known_types() {
    assert_eq!(keyslot_kind_label(0), "Empty");
    assert_eq!(keyslot_kind_label(1), "Sentinel");
    assert_eq!(keyslot_kind_label(2), "Passphrase");
    assert_eq!(keyslot_kind_label(3), "RecoveryKey");
    assert_eq!(keyslot_kind_label(4), "Keyfile");
    assert_eq!(keyslot_kind_label(9), "Unknown");
}

#[test]
fn preview_bytes_formats_utf8_and_binary() {
    assert_eq!(preview_bytes(b"alpha"), "\"alpha\"");
    assert_eq!(preview_bytes(&[0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
}

#[test]
fn view_mode_keys_cover_all_panels() {
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('1')), Some(ViewMode::Header));
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('d')), Some(ViewMode::Detail));
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('v')), Some(ViewMode::Verify));
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('t')), Some(ViewMode::Tree));
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('l')), Some(ViewMode::Wal));
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('p')), Some(ViewMode::Protectors));
    assert_eq!(ViewMode::from_key(crossterm::event::KeyCode::Char('x')), None);
}

#[test]
fn format_wal_record_renders_page_write() {
    let record = WalRecordSummary {
        lsn: 12,
        kind: WalRecordSummaryKind::PageWrite {
            pgno: 7,
            page_version: 3,
        },
    };

    assert_eq!(format_wal_record(&record), "lsn   12: page_write pg=7 v3");
}

#[test]
fn page_list_summary_formats_missing_fields() {
    let page = PageRow {
        pgno: 9,
        page_type: None,
        page_version: None,
        slot_count: None,
        status: PageStatus::AuthFailed,
        issue: Some("auth failed".to_string()),
        search_text: String::new(),
    };

    assert_eq!(page_list_summary(&page), "    9  ?         auth     v --  slots  --");
}

#[test]
fn page_jump_prompt_overrides_footer_status() {
    let mut app = new_app(1, Vec::new());

    app.toggle_watch();
    app.start_page_jump();
    app.push_page_jump_digit('4');

    assert_eq!(app.footer_status(), " • goto page: 4");
}

#[test]
fn filter_prompt_overrides_footer_status() {
    let mut app = new_app(1, Vec::new());

    app.start_filter_prompt();
    app.push_filter_char('a');
    app.push_filter_char('u');

    assert_eq!(app.footer_status(), " • filter: au");
}

#[test]
fn watch_toggle_updates_status() {
    let mut app = new_app(1, Vec::new());

    app.toggle_watch();

    assert!(app.watch_enabled);
    assert_eq!(app.status_suffix(), " • watch enabled");
}

#[test]
fn summarize_page_auth_counts_clean_and_failed_pages() {
    let report = VerifyReport {
        pages_checked: 4,
        pages_ok: 1,
        issues: Vec::new(),
        page_results: vec![
            PageVerifyResult {
                pgno: 1,
                page_version: Some(7),
                auth_ok: true,
                issue_kind: None,
                issue: None,
            },
            PageVerifyResult {
                pgno: 2,
                page_version: None,
                auth_ok: false,
                issue_kind: Some(VerifyIssueKind::AuthFailed),
                issue: Some("authentication tag mismatch".to_string()),
            },
            PageVerifyResult {
                pgno: 3,
                page_version: None,
                auth_ok: false,
                issue_kind: Some(VerifyIssueKind::Corrupt),
                issue: Some("corrupt: bad slot".to_string()),
            },
            PageVerifyResult {
                pgno: 4,
                page_version: None,
                auth_ok: false,
                issue_kind: Some(VerifyIssueKind::Io),
                issue: Some("I/O error: failed".to_string()),
            },
        ],
    };

    assert_eq!(
        summarize_page_auth(&report),
        PageAuthSummary {
            ok: 1,
            auth_failed: 1,
            corrupt: 1,
            io: 1,
        }
    );
    assert_eq!(selected_page_auth_summary(&report, 1), "pg 1 ok (v7)");
    assert_eq!(selected_page_auth_summary(&report, 2), "pg 2 auth_failed");
}

#[test]
fn panel_scroll_resets_on_mode_change() {
    let mut app = new_app(1, Vec::new());

    app.scroll_panel_down(12);
    assert_eq!(app.panel_scroll, 12);

    app.set_mode(ViewMode::Tree);
    assert_eq!(app.panel_scroll, 0);

    app.scroll_panel_down(5);
    app.scroll_panel_up(2);
    assert_eq!(app.panel_scroll, 3);

    app.scroll_panel_up(10);
    assert_eq!(app.panel_scroll, 0);
}

#[test]
fn focus_toggle_switches_between_pages_and_panel() {
    let mut app = new_app(1, Vec::new());

    assert_eq!(app.focus, FocusPane::Pages);
    app.toggle_focus();
    assert_eq!(app.focus, FocusPane::Panel);
    app.toggle_focus();
    assert_eq!(app.focus, FocusPane::Pages);
}

#[test]
fn focus_routed_movement_uses_active_pane() {
    with_temp_db("view_focus_test", |_, pager| {
        let mut app = new_app(2, vec![corrupt_page(1), corrupt_page(2)]);

        app.selected = Some(0);
        app.move_down(pager).unwrap();
        assert_eq!(app.selected, Some(1));

        app.focus = FocusPane::Panel;
        app.move_down(pager).unwrap();
        assert_eq!(app.panel_scroll, 1);
    });
}

#[test]
fn page_jump_uses_active_focus() {
    with_temp_db("view_page_jump_test", |_, pager| {
        let pages = (1..=25).map(corrupt_page).collect::<Vec<_>>();
        let mut app = new_app(25, pages);

        app.selected = Some(0);
        app.move_page_down(pager).unwrap();
        assert_eq!(app.selected, Some(PAGE_LIST_JUMP));

        app.focus = FocusPane::Panel;
        app.move_page_down(pager).unwrap();
        assert_eq!(app.panel_scroll, PANEL_SCROLL_PAGE);
    });
}

#[test]
fn confirm_page_jump_selects_matching_page() {
    with_temp_db("view_confirm_jump", |_, pager| {
        let pages = (1..=10).map(corrupt_page).collect::<Vec<_>>();
        let mut app = new_app(10, pages);

        app.start_page_jump();
        app.push_page_jump_digit('7');
        app.confirm_page_jump(pager).unwrap();

        assert_eq!(app.selected, Some(6));
        assert_eq!(app.status_suffix(), " • jumped to page 7");
        assert!(!app.page_jump_active());
    });
}

#[test]
fn confirm_page_jump_reports_missing_page() {
    with_temp_db("view_missing_jump", |_, pager| {
        let pages = (1..=3).map(corrupt_page).collect::<Vec<_>>();
        let mut app = new_app(3, pages);
        app.selected = Some(0);

        app.start_page_jump();
        app.push_page_jump_digit('9');
        app.confirm_page_jump(pager).unwrap();

        assert_eq!(app.selected, Some(0));
        assert_eq!(app.status_suffix(), " • page 9 not found");
    });
}

#[test]
fn watch_refresh_needed_only_when_db_or_wal_changes() {
    with_temp_db("view_watch_fingerprint", |path, _| {
        let wal = tosumu_core::wal::wal_path(path);
        let fingerprint = capture_watch_fingerprint(path).unwrap();

        assert!(!watch_refresh_needed(path, Some(&fingerprint)).unwrap());

        std::fs::write(&wal, [0u8, 1u8, 2u8]).unwrap();

        assert!(watch_refresh_needed(path, Some(&fingerprint)).unwrap());
    });
}

#[test]
fn confirm_filter_limits_visible_pages_and_selection() {
    with_temp_db("view_filter_selection", |_, pager| {
        let pages = vec![
            PageRow {
                pgno: 1,
                page_type: Some(PAGE_TYPE_LEAF),
                page_version: Some(1),
                slot_count: Some(0),
                status: PageStatus::Ok,
                issue: None,
                search_text: "alpha key value".to_string(),
            },
            PageRow {
                pgno: 2,
                page_type: Some(PAGE_TYPE_LEAF),
                page_version: Some(2),
                slot_count: Some(0),
                status: PageStatus::AuthFailed,
                issue: Some("auth failed".to_string()),
                search_text: String::new(),
            },
            corrupt_page(3),
        ];
        let mut app = new_app(3, pages);
        app.selected = Some(0);

        app.start_filter_prompt();
        app.push_filter_char('a');
        app.push_filter_char('u');
        app.push_filter_char('t');
        app.push_filter_char('h');
        app.confirm_filter_prompt(pager).unwrap();

        assert_eq!(app.visible_page_count(), 1);
        assert_eq!(app.selected, Some(1));
        assert_eq!(app.footer_status(), " • filter: auth (1) • filter matched 1 page(s)");
    });
}

#[test]
fn page_jump_uses_visible_page_indices_when_filtered() {
    with_temp_db("view_filtered_page_jump", |_, pager| {
        let pages = vec![
            corrupt_page(1),
            PageRow {
                pgno: 2,
                page_type: Some(PAGE_TYPE_LEAF),
                page_version: Some(2),
                slot_count: Some(0),
                status: PageStatus::AuthFailed,
                issue: Some("auth failed".to_string()),
                search_text: String::new(),
            },
            PageRow {
                pgno: 3,
                page_type: Some(PAGE_TYPE_LEAF),
                page_version: Some(3),
                slot_count: Some(0),
                status: PageStatus::AuthFailed,
                issue: Some("auth failed".to_string()),
                search_text: String::new(),
            },
        ];
        let mut app = new_app(3, pages);

        app.start_filter_prompt();
        app.push_filter_char('a');
        app.push_filter_char('u');
        app.push_filter_char('t');
        app.push_filter_char('h');
        app.confirm_filter_prompt(pager).unwrap();

        app.selected = Some(1);
        app.select_next(pager).unwrap();

        assert_eq!(app.selected, Some(2));
    });
}

#[test]
fn confirm_filter_matches_record_search_text() {
    with_temp_db("view_filter_record_text", |_, pager| {
        let pages = vec![
            PageRow {
                pgno: 1,
                page_type: Some(PAGE_TYPE_LEAF),
                page_version: Some(1),
                slot_count: Some(0),
                status: PageStatus::Ok,
                issue: None,
                search_text: "customer-id welcome".to_string(),
            },
            PageRow {
                pgno: 2,
                page_type: Some(PAGE_TYPE_LEAF),
                page_version: Some(2),
                slot_count: Some(0),
                status: PageStatus::Ok,
                issue: None,
                search_text: "invoice archived".to_string(),
            },
        ];
        let mut app = new_app(2, pages);

        app.start_filter_prompt();
        for ch in "welcome".chars() {
            app.push_filter_char(ch);
        }
        app.confirm_filter_prompt(pager).unwrap();

        assert_eq!(app.visible_page_count(), 1);
        assert_eq!(app.selected, Some(0));
    });
}