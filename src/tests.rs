#[cfg(any())]
mod legacy {
use crate::*;
use rusqlite::Connection;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

fn test_app() -> RoadmapApp {
    RoadmapApp {
        quarters: Vec::new(),
        db: test_db(),
        current_roadmap_id: None,
        roadmap_list: Vec::new(),
        status_text: String::new(),
        dialog_state: DialogState::None,
        encrypted: false,
        offline: true,
        use_keychain: false,
        db_key: None,
        undo_stack: Vec::new(),
        redo_stack: Vec::new(),
        new_roadmap_name: String::new(),
        current_tab: String::new(),
        show_open_dialog: false,
        show_new_dialog: false,
        rename_roadmap_id: None,
        rename_roadmap_name: String::new(),
        show_timeline_labels: true,
        timeline_zoom: 1.0,
        timeline_scroll: 0.0,
        timeline_hovered_feature: None,
        timeline_tooltip_close_at: None,
        timeline_visible_roadmaps: Vec::new(),
        timeline_visible_status_buttons: false,
        timeline_status_buttons_close_at: None,
        timeline_visible_status: Vec::new(),
        timeline_visible_roadmap_buttons: false,
        timeline_roadmap_buttons_close_at: None,
        org_list: Vec::new(),
        current_org_id: None,
        org_members: Vec::new(),
        org_chart_links: Vec::new(),
        org_settings: OrgSettings {
            org_id: 0,
            mode: "hierarchy".to_string(),
            updated_at: String::new(),
        },
        org_joined: false,
        org_is_owner: false,
        org_dialog_state: OrgDialogState::None,
        org_chart_scroll: 0.0,
        org_chart_scroll_x: 0.0,
        org_chart_zoom: 1.0,
        org_selected_user_id: None,
        show_org_list_dialog: false,
        org_right_click_target: None,
        org_right_click_pos: None,
        org_move_under_target: None,
        task_assign_feature_id: None,
        task_assign_feature_title: String::new(),
        task_assign_user_id: None,
        task_assign_user_name: String::new(),
        sync_config: NetworkConfig {
            node_id: String::new(),
            server_url: String::new(),
            use_proxy: false,
            proxy_mode: "none".to_string(),
            proxy_url: String::new(),
        },
        network_edit_config: NetworkConfig {
            node_id: String::new(),
            server_url: String::new(),
            use_proxy: false,
            proxy_mode: "none".to_string(),
            proxy_url: String::new(),
        },
        show_network_settings: false,
        network_settings_view: NetworkSettingsView::Server,
        sync_running: false,
        sync_status_rx: None,
        sync_stop_flag: None,
        sync_pending_send: Arc::new(AtomicBool::new(false)),
        sync_pending_token: Arc::new(Mutex::new(None)),
        completion_dialog: None,
        status_text_set_at: None,
        status_text_value: None,
        current_user_id: None,
        current_user_role: "member".to_string(),
        last_seen_log_id: 0,
        edit_base_log_id: None,
        edit_base_snapshot: None,
        conflict_dialog: None,
    }
}

fn test_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "
        CREATE TABLE org_roadmap_editor (
            org_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            can_edit INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (org_id, user_id)
        );
        CREATE TABLE task_assignment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feature_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            assigned_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        "
    )
    .unwrap();
    conn
}

fn feature(id: &str, title: &str, status: &str) -> Feature {
    Feature {
        id: id.to_string(),
        title: title.to_string(),
        description: String::new(),
        completed: false,
        status: status.to_string(),
        color: "#fff".to_string(),
        days: None,
        weeks: None,
        start_date: None,
        started_at: None,
        paused_at: None,
        completed_at: None,
        subtasks: Vec::new(),
    }
}

fn subtask(id: &str, title: &str, status: &str) -> Subtask {
    Subtask {
        id: id.to_string(),
        title: title.to_string(),
        description: String::new(),
        completed: status == "Completed",
        status: status.to_string(),
        color: "#9E9E9E".to_string(),
        started_at: None,
        completed_at: None,
    }
}

fn quarter(year: u32, quarter: u32, features: Vec<Feature>) -> Quarter {
    Quarter { year, quarter, features }
}

#[test]
fn merge_roadmap_changes_combines_non_conflicting_edits() {
    let app = test_app();
    let base = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned")])];
    let local = vec![quarter(2026, 1, vec![feature("f1", "Title", "Developing")])];
    let remote = vec![quarter(2026, 1, vec![feature("f1", "Title v2", "Planned")])];

    let (merged, conflicts) = app.merge_roadmap_changes(&base, &local, &remote);
    assert_eq!(conflicts, 0);
    let merged_feature = &merged[0].features[0];
    assert_eq!(merged_feature.title, "Title v2");
    assert_eq!(merged_feature.status, "Developing");
}

#[test]
fn merge_roadmap_changes_prefers_remote_on_conflict() {
    let app = test_app();
    let base = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned")])];
    let local = vec![quarter(2026, 1, vec![feature("f1", "Title", "Developing")])];
    let remote = vec![quarter(2026, 1, vec![feature("f1", "Title", "Paused")])];

    let (merged, conflicts) = app.merge_roadmap_changes(&base, &local, &remote);
    assert_eq!(conflicts, 1);
    let merged_feature = &merged[0].features[0];
    assert_eq!(merged_feature.status, "Paused");
}

#[test]
fn build_change_preview_lists_local_and_remote_diffs() {
    let app = test_app();
    let base = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned")])];
    let local = vec![quarter(2026, 1, vec![feature("f1", "Title", "Developing")])];
    let remote = vec![quarter(2026, 1, vec![feature("f1", "Title v2", "Planned")])];

    let preview = app.build_change_preview(&base, &local, &remote);
    assert!(preview.iter().any(|line| line.contains("LOCAL changed status")));
    assert!(preview.iter().any(|line| line.contains("REMOTE changed title")));
}

#[test]
fn can_edit_roadmap_allows_owner_without_user_id() {
    let mut app = test_app();
    app.org_joined = true;
    app.org_is_owner = true;
    assert!(app.can_edit_roadmap());
}

#[test]
fn can_edit_roadmap_denies_when_not_joined_user() {
    let mut app = test_app();
    app.org_joined = true;
    app.org_is_owner = false;
    app.current_org_id = Some(1);
    app.current_user_id = None;
    app.current_user_role = "member".to_string();
    assert!(!app.can_edit_roadmap());
}

#[test]
fn can_edit_roadmap_allows_default_roles() {
    let mut app = test_app();
    app.org_joined = true;
    app.org_is_owner = false;
    app.current_org_id = Some(1);
    app.current_user_id = Some(7);

    app.current_user_role = "admin".to_string();
    assert!(app.can_edit_roadmap());

    app.current_user_role = "leader".to_string();
    assert!(app.can_edit_roadmap());
}

#[test]
fn can_edit_roadmap_uses_editor_override() {
    let mut app = test_app();
    app.org_joined = true;
    app.org_is_owner = false;
    app.current_org_id = Some(1);
    app.current_user_id = Some(9);
    app.current_user_role = "member".to_string();

    assert!(!app.can_edit_roadmap());

    app.db.execute(
        "INSERT INTO org_roadmap_editor (org_id, user_id, can_edit, updated_at) VALUES (1, 9, 1, 'now')",
        [],
    )
    .unwrap();

    assert!(app.can_edit_roadmap());
}

#[test]
fn can_update_task_status_allows_assignee() {
    let mut app = test_app();
    app.org_joined = true;
    app.org_is_owner = false;
    app.current_org_id = Some(1);
    app.current_user_id = Some(42);
    app.current_user_role = "member".to_string();

    app.db.execute(
        "INSERT INTO task_assignment (feature_id, user_id, status, assigned_at, updated_at) VALUES ('f1', 42, 'Assigned', 'now', 'now')",
        [],
    )
    .unwrap();

    assert!(app.can_update_task_status("f1"));
}

#[test]
fn can_update_task_status_denies_unassigned_non_editor() {
    let mut app = test_app();
    app.org_joined = true;
    app.org_is_owner = false;
    app.current_org_id = Some(1);
    app.current_user_id = Some(42);
    app.current_user_role = "member".to_string();

    assert!(!app.can_update_task_status("f1"));
}

#[test]
fn merge_roadmap_changes_keeps_local_additions() {
    let app = test_app();
    let base = vec![quarter(2026, 1, vec![])];
    let local = vec![quarter(2026, 1, vec![feature("f2", "New", "Planned")])];
    let remote = vec![quarter(2026, 1, vec![])];

    let (merged, conflicts) = app.merge_roadmap_changes(&base, &local, &remote);
    assert_eq!(conflicts, 0);
    assert_eq!(merged[0].features.len(), 1);
    assert_eq!(merged[0].features[0].id, "f2");
}

#[test]
fn merge_roadmap_changes_keeps_remote_deletions() {
    let app = test_app();
    let base = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned")])];
    let local = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned")])];
    let remote = vec![quarter(2026, 1, vec![])];

    let (merged, conflicts) = app.merge_roadmap_changes(&base, &local, &remote);
    assert_eq!(conflicts, 1);
    assert!(merged[0].features.is_empty());
}

#[test]
fn build_change_preview_detects_add_remove() {
    let app = test_app();
    let base = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned")])];
    let local = vec![quarter(2026, 1, vec![feature("f1", "Title", "Planned"), feature("f2", "New", "Planned")])];
    let remote = vec![quarter(2026, 1, vec![])];

    let preview = app.build_change_preview(&base, &local, &remote);
    assert!(preview.iter().any(|line| line.contains("LOCAL added feature")));
    assert!(preview.iter().any(|line| line.contains("REMOTE removed feature")));
}

#[test]
fn merge_subtasks_combines_non_conflicting_edits() {
    let app = test_app();
    let mut base_feature = feature("f1", "Title", "Planned");
    base_feature.subtasks = vec![subtask("s1", "Task", "Planned")];

    let mut local_feature = feature("f1", "Title", "Planned");
    local_feature.subtasks = vec![subtask("s1", "Task", "Developing")];

    let mut remote_feature = feature("f1", "Title", "Planned");
    remote_feature.subtasks = vec![subtask("s1", "Task v2", "Planned")];

    let base = vec![quarter(2026, 1, vec![base_feature])];
    let local = vec![quarter(2026, 1, vec![local_feature])];
    let remote = vec![quarter(2026, 1, vec![remote_feature])];

    let (merged, conflicts) = app.merge_roadmap_changes(&base, &local, &remote);
    assert_eq!(conflicts, 0);
    let merged_task = &merged[0].features[0].subtasks[0];
    assert_eq!(merged_task.title, "Task v2");
    assert_eq!(merged_task.status, "Developing");
}

#[test]
fn merge_subtasks_prefers_remote_on_conflict() {
    let app = test_app();
    let mut base_feature = feature("f1", "Title", "Planned");
    base_feature.subtasks = vec![subtask("s1", "Task", "Planned")];

    let mut local_feature = feature("f1", "Title", "Planned");
    local_feature.subtasks = vec![subtask("s1", "Task", "Developing")];

    let mut remote_feature = feature("f1", "Title", "Planned");
    remote_feature.subtasks = vec![subtask("s1", "Task", "Paused")];

    let base = vec![quarter(2026, 1, vec![base_feature])];
    let local = vec![quarter(2026, 1, vec![local_feature])];
    let remote = vec![quarter(2026, 1, vec![remote_feature])];

    let (merged, conflicts) = app.merge_roadmap_changes(&base, &local, &remote);
    assert_eq!(conflicts, 1);
    let merged_task = &merged[0].features[0].subtasks[0];
    assert_eq!(merged_task.status, "Paused");
}

#[test]
fn build_change_preview_includes_subtask_diffs() {
    let app = test_app();
    let mut base_feature = feature("f1", "Title", "Planned");
    base_feature.subtasks = vec![subtask("s1", "Task", "Planned")];

    let mut local_feature = feature("f1", "Title", "Planned");
    local_feature.subtasks = vec![subtask("s1", "Task", "Developing")];

    let mut remote_feature = feature("f1", "Title", "Planned");
    remote_feature.subtasks = vec![subtask("s1", "Task v2", "Planned")];

    let base = vec![quarter(2026, 1, vec![base_feature])];
    let local = vec![quarter(2026, 1, vec![local_feature])];
    let remote = vec![quarter(2026, 1, vec![remote_feature])];

    let preview = app.build_change_preview(&base, &local, &remote);
    assert!(preview.iter().any(|line| line.contains("LOCAL changed subtask.status")));
    assert!(preview.iter().any(|line| line.contains("REMOTE changed subtask.title")));
}
}

use crate::*;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rusqlite::Connection;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn template_features_exist_for_all_builtin_types() {
    assert!(!get_template("web").is_empty());
    assert!(!get_template("mobile").is_empty());
    assert!(!get_template("api").is_empty());
}

#[test]
fn template_subtasks_are_two_or_three_items() {
    for template in ["web", "mobile", "api"] {
        for feature in get_template(template) {
            let subtasks = get_template_subtasks(template, feature);
            assert!((2..=3).contains(&subtasks.len()));
        }
    }
}

#[test]
fn parse_color_handles_valid_and_invalid_hex() {
    let valid = parse_color("#4CAF50");
    assert_eq!(valid.r(), 76);
    assert_eq!(valid.g(), 175);
    assert_eq!(valid.b(), 80);

    let fallback = parse_color("not-a-color");
    assert_eq!(fallback.r(), 33);
    assert_eq!(fallback.g(), 150);
    assert_eq!(fallback.b(), 243);
}

fn temp_db_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("allroads-{}-{}-{}.db", prefix, std::process::id(), nanos))
}

#[test]
fn extract_migration_switch_url_parses_expected_message() {
    let message = "org migrated; switch_to=wss://new.example:59901";
    assert_eq!(
        extract_migration_switch_url(message),
        Some("wss://new.example:59901".to_string())
    );
    assert_eq!(extract_migration_switch_url("no redirect here"), None);
}

#[test]
fn open_connection_migrates_org_sync_columns_for_existing_db() {
    let path = temp_db_path("org-sync-migration");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "
            CREATE TABLE org_sync (
                org_id INTEGER PRIMARY KEY,
                joined INTEGER NOT NULL DEFAULT 0,
                is_owner INTEGER NOT NULL DEFAULT 0,
                token TEXT,
                owner_token TEXT,
                updated_at TEXT NOT NULL
            );
            INSERT INTO org_sync (org_id, joined, is_owner, token, owner_token, updated_at)
            VALUES (1, 1, 1, 'u', 'o', 'now');
            ",
        )
        .unwrap();
    }

    let (conn, _key) = open_connection_at_path(&path, false, false).unwrap();
    let mut stmt = conn.prepare("PRAGMA table_info(org_sync)").unwrap();
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    assert!(columns.contains(&"migrated_target_server_url".to_string()));
    assert!(columns.contains(&"migrated_target_server_identity".to_string()));
    let defaults: (String, String) = conn
        .query_row(
            "SELECT migrated_target_server_url, migrated_target_server_identity FROM org_sync WHERE org_id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(defaults.0, "");
    assert_eq!(defaults.1, "");
    std::fs::remove_file(&path).ok();
}

#[test]
fn decrypt_snapshot_round_trip_works() {
    let session_key = BASE64.encode([9u8; 32]);
    let key_bytes = BASE64.decode(session_key.as_bytes()).unwrap();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce_bytes = [7u8; 12];
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = b"snapshot-bytes".to_vec();
    let encrypted = cipher.encrypt(nonce, payload.as_slice()).unwrap();
    let data_b64 = BASE64.encode(encrypted);
    let nonce_b64 = BASE64.encode(nonce_bytes);

    let decrypted = decrypt_snapshot(&session_key, &data_b64, &nonce_b64).unwrap();
    assert_eq!(decrypted, payload);
}

#[test]
fn db_set_org_sync_state_round_trips_join_flags() {
    let path = temp_db_path("sync-state");
    let (conn, _key) = open_connection_at_path(&path, false, false).unwrap();
    conn.execute(
        "INSERT INTO org (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![42_i64, "Test Org", "now", "now"],
    )
    .unwrap();

    db_set_org_sync_state(&conn, 42, false, false);
    let state = db_load_org_sync_state(&conn, 42);
    assert!(!state.joined);
    assert!(!state.is_owner);

    db_set_org_sync_state(&conn, 42, true, true);
    let state = db_load_org_sync_state(&conn, 42);
    assert!(state.joined);
    assert!(state.is_owner);

    drop(conn);
    std::fs::remove_file(&path).ok();
}
