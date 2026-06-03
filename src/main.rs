use eframe::egui;
use chrono::Datelike;
use rusqlite::Connection;
use std::fs;

fn get_template(template_type: &str) -> Vec<&'static str> {
    match template_type {
        "web" => vec![
            "Planning & Design", "Backend Setup", "Frontend Development",
            "Authentication System", "Payment Integration", "Testing & QA", "Deployment",
        ],
        "mobile" => vec![
            "UI/UX Design", "Core Architecture", "User Authentication",
            "Main Features", "Push Notifications", "App Store Submission", "Marketing Launch",
        ],
        "api" => vec![
            "API Specification", "Database Design", "Authentication & Auth",
            "Core Endpoints", "Documentation", "Testing Suite", "Monitoring Setup",
        ],
        _ => vec![],
    }
}

#[derive(Clone, Debug)]
struct Feature {
    id: String,
    title: String,
    description: String,
    completed: bool,
    status: String,
    color: String,
    days: Option<u32>,
    weeks: Option<u32>,
    start_date: Option<String>,
    started_at: Option<String>,
    paused_at: Option<String>,
    completed_at: Option<String>,
}

const DB_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS roadmap (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarter (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    roadmap_id INTEGER NOT NULL REFERENCES roadmap(id) ON DELETE CASCADE,
    year INTEGER NOT NULL,
    quarter INTEGER NOT NULL,
    sort_order INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS feature (
    id TEXT PRIMARY KEY,
    quarter_id INTEGER NOT NULL REFERENCES quarter(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Planned',
    color TEXT NOT NULL DEFAULT '#FF9800',
    sort_order INTEGER NOT NULL,
    days INTEGER,
    weeks INTEGER,
    start_date TEXT,
    started_at TEXT,
    paused_at TEXT,
    completed_at TEXT
);
";

fn db_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".allroads")
}

fn key_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home).join(".allroads.key")
}

fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    hex::encode(bytes)
}

fn load_or_create_key() -> Result<String, String> {
    let path = key_path();
    if path.exists() {
        fs::read_to_string(&path).map_err(|e| format!("Error reading key: {}", e))
    } else {
        let key = generate_key();
        fs::write(&path, &key).map_err(|e| format!("Error writing key: {}", e))?;
        Ok(key)
    }
}

const KEYCHAIN_SERVICE: &str = "allroads";
const KEYCHAIN_USERNAME: &str = "db-encryption-key";

fn keyring_entry() -> keyring::Entry {
    keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_USERNAME).expect("Failed to create keyring entry")
}

fn load_key_from_keychain() -> Result<String, String> {
    let entry = keyring_entry();
    entry.get_password().map_err(|e| format!("Error reading key from keychain: {}", e))
}

fn save_key_to_keychain(key: &str) -> Result<(), String> {
    let entry = keyring_entry();
    entry.set_password(key).map_err(|e| format!("Error saving key to keychain: {}", e))
}

fn delete_key_from_keychain() -> Result<(), String> {
    let entry = keyring_entry();
    entry.delete_password().map_err(|e| format!("Error deleting key from keychain: {}", e))
}

fn load_or_create_key_with_keychain(use_keychain: bool) -> Result<String, String> {
    if use_keychain {
        match load_key_from_keychain() {
            Ok(key) => Ok(key),
            Err(_) => {
                let key = if key_path().exists() {
                    load_or_create_key()?
                } else {
                    generate_key()
                };
                save_key_to_keychain(&key)?;
                Ok(key)
            }
        }
    } else {
        load_or_create_key()
    }
}

fn open_connection(encrypted: bool, use_keychain: bool) -> Result<(Connection, Option<String>), String> {
    open_connection_at_path(&db_path(), encrypted, use_keychain)
}

fn open_connection_at_path(path: &std::path::PathBuf, encrypted: bool, use_keychain: bool) -> Result<(Connection, Option<String>), String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA foreign_keys = ON;").map_err(|e| e.to_string())?;
    let mut db_key = None;
    if encrypted {
        let key = load_or_create_key_with_keychain(use_keychain)?;
        conn.execute_batch(&format!("PRAGMA key = \"{}\";", key)).map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA cipher = 'aes-256-cbc';").map_err(|e| e.to_string())?;
        db_key = Some(key);
    }
    conn.execute_batch(DB_SCHEMA).map_err(|e| e.to_string())?;
    conn.execute_batch("ALTER TABLE feature ADD COLUMN days INTEGER").ok();
    conn.execute_batch("ALTER TABLE feature ADD COLUMN weeks INTEGER").ok();
    conn.execute_batch("ALTER TABLE feature ADD COLUMN started_at TEXT").ok();
    conn.execute_batch("ALTER TABLE feature ADD COLUMN paused_at TEXT").ok();
    conn.execute_batch("ALTER TABLE feature ADD COLUMN completed_at TEXT").ok();
    conn.execute_batch("ALTER TABLE feature ADD COLUMN start_date TEXT").ok();
    Ok((conn, db_key))
}

fn db_list_roadmaps(conn: &Connection) -> Vec<(i64, String)> {
    let mut stmt = conn.prepare("SELECT id, name FROM roadmap ORDER BY updated_at DESC").unwrap();
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_create_roadmap(conn: &Connection, name: &str) -> i64 {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute("INSERT INTO roadmap (name, created_at, updated_at) VALUES (?1, ?2, ?3)", rusqlite::params![name, now, now]).unwrap();
    conn.last_insert_rowid()
}

fn db_delete_roadmap(conn: &Connection, id: i64) {
    conn.execute("DELETE FROM roadmap WHERE id = ?1", rusqlite::params![id]).unwrap();
}

fn db_rename_roadmap(conn: &Connection, id: i64, name: &str) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute("UPDATE roadmap SET name = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![name, now, id]).unwrap();
}

fn db_save_roadmap(conn: &Connection, roadmap_id: i64, quarters: &[Quarter]) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute("UPDATE roadmap SET updated_at = ?1 WHERE id = ?2", rusqlite::params![now, roadmap_id]).unwrap();
    conn.execute("DELETE FROM quarter WHERE roadmap_id = ?1", rusqlite::params![roadmap_id]).unwrap();
    for (qi, q) in quarters.iter().enumerate() {
        conn.execute(
            "INSERT INTO quarter (roadmap_id, year, quarter, sort_order) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![roadmap_id, q.year, q.quarter, qi as i64],
        ).unwrap();
        let quarter_id = conn.last_insert_rowid();
        for (fi, f) in q.features.iter().enumerate() {
            conn.execute(
                "INSERT OR REPLACE INTO feature (id, quarter_id, title, description, completed, status, color, sort_order, days, weeks, start_date, started_at, paused_at, completed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![f.id, quarter_id, f.title, f.description, f.completed as i32, f.status, f.color, fi as i64, f.days, f.weeks, f.start_date, f.started_at, f.paused_at, f.completed_at],
            ).unwrap();
        }
    }
}

fn db_load_roadmap(conn: &Connection, roadmap_id: i64) -> Vec<Quarter> {
    let mut q_stmt = conn.prepare("SELECT id, year, quarter FROM quarter WHERE roadmap_id = ?1 ORDER BY sort_order").unwrap();
    let q_rows: Vec<_> = q_stmt.query_map(rusqlite::params![roadmap_id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?))
    }).unwrap().filter_map(|r| r.ok()).collect();

    let mut quarters = Vec::new();
    for (qid, year, quarter) in q_rows {
        let mut f_stmt = conn.prepare("SELECT id, title, description, completed, status, color, days, weeks, start_date, started_at, paused_at, completed_at FROM feature WHERE quarter_id = ?1 ORDER BY sort_order").unwrap();
        let features: Vec<Feature> = f_stmt.query_map(rusqlite::params![qid], |row| {
            let completed: i32 = row.get(3)?;
            let days: Option<i32> = row.get(6)?;
            let weeks: Option<i32> = row.get(7)?;
            let start_date: Option<String> = row.get(8)?;
            let started_at: Option<String> = row.get(9)?;
            let paused_at: Option<String> = row.get(10)?;
            let completed_at: Option<String> = row.get(11)?;
            Ok(Feature {
                id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                completed: completed != 0,
                status: row.get(4)?,
                color: row.get(5)?,
                days: days.map(|d| d as u32),
                weeks: weeks.map(|w| w as u32),
                start_date,
                started_at,
                paused_at,
                completed_at,
            })
        }).unwrap().filter_map(|r| r.ok()).collect();
        quarters.push(Quarter { year, quarter, features });
    }
    quarters
}

#[derive(Clone, Debug)]
struct Quarter {
    year: u32,
    quarter: u32,
    features: Vec<Feature>,
}

impl Quarter {
    fn new(year: u32, quarter: u32) -> Self {
        Self { year, quarter, features: Vec::new() }
    }

    fn name(&self) -> String {
        format!("Q{} {}", self.quarter, self.year)
    }

    fn date_range(&self) -> String {
        let months: [(u32, u32); 4] = [(1, 3), (4, 6), (7, 9), (10, 12)];
        let (start_month, end_month) = months[(self.quarter - 1) as usize];
        let start = chrono::NaiveDate::from_ymd_opt(self.year as i32, start_month, 1).unwrap();
        let end = if end_month == 12 {
            chrono::NaiveDate::from_ymd_opt(self.year as i32, 12, 31).unwrap()
        } else {
            chrono::NaiveDate::from_ymd_opt(self.year as i32, end_month + 1, 1).unwrap()
                - chrono::Duration::days(1)
        };
        format!("{} - {}", start.format("%b %d"), end.format("%b %d"))
    }
}

struct FeatureDialogState {
    title: String,
    description: String,
    status: String,
    color: String,
    days: String,
    weeks: String,
    start_date: String,
    started_at: Option<String>,
    paused_at: Option<String>,
    completed_at: Option<String>,
}

impl Default for FeatureDialogState {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            status: "Planned".into(),
            color: "#FF9800".into(),
            days: String::new(),
            weeks: String::new(),
            start_date: String::new(),
            started_at: None,
            paused_at: None,
            completed_at: None,
        }
    }
}

impl FeatureDialogState {
    fn from_feature(f: &Feature) -> Self {
        Self {
            title: f.title.clone(),
            description: f.description.clone(),
            status: f.status.clone(),
            color: f.color.clone(),
            days: f.days.map(|d| d.to_string()).unwrap_or_default(),
            weeks: f.weeks.map(|w| w.to_string()).unwrap_or_default(),
            start_date: f.start_date.clone().unwrap_or_default(),
            started_at: f.started_at.clone(),
            paused_at: f.paused_at.clone(),
            completed_at: f.completed_at.clone(),
        }
    }

    fn show(&mut self, ui: &mut egui::Ui) -> bool {
        let mut ok = false;
        ui.vertical(|ui| {
            ui.label("Title:");
            ui.add(egui::TextEdit::singleline(&mut self.title).desired_width(350.0));
            ui.add_space(4.0);

            ui.label("Description:");
            ui.add(egui::TextEdit::multiline(&mut self.description).desired_rows(6).desired_width(350.0));
            ui.add_space(4.0);

            ui.label("Status:");
            ui.columns(4, |cols| {
                let statuses = ["Planned", "Developing", "Testing", "Completed", "Stalled", "Paused", "Cancelled", "Deferred"];
                for chunk in statuses.chunks(4) {
                    for (j, s) in chunk.iter().enumerate() {
                        if cols[j].radio(self.status == *s, *s).clicked() {
                            self.status = s.to_string();
                        }
                    }
                }
            });
            ui.add_space(4.0);

            ui.label("Start Date:");
            ui.add(egui::TextEdit::singleline(&mut self.start_date).desired_width(120.0).hint_text("YYYY-MM-DD"));
            ui.add_space(4.0);

            ui.label("Estimate:");
            ui.horizontal(|ui| {
                ui.label("Days:");
                ui.add(egui::TextEdit::singleline(&mut self.days).desired_width(40.0));
                ui.label("Weeks:");
                ui.add(egui::TextEdit::singleline(&mut self.weeks).desired_width(40.0));
            });
            ui.add_space(4.0);

            ui.label("Color:");
            ui.horizontal(|ui| {
                let colors = [
                    ("#F44336", egui::Color32::from_rgb(244, 67, 54)),   // Red
                    ("#FF9800", egui::Color32::from_rgb(255, 152, 0)),   // Orange
                    ("#FFEB3B", egui::Color32::from_rgb(255, 235, 59)),  // Yellow
                    ("#4CAF50", egui::Color32::from_rgb(76, 175, 80)),   // Green
                    ("#2196F3", egui::Color32::from_rgb(33, 150, 243)),  // Blue
                    ("#9C27B0", egui::Color32::from_rgb(156, 39, 176)),  // Purple
                    ("#E91E63", egui::Color32::from_rgb(233, 30, 99)),   // Pink
                    ("#00BCD4", egui::Color32::from_rgb(0, 188, 212)),   // Cyan
                    ("#FFFFFF", egui::Color32::from_rgb(255, 255, 255)), // White
                    ("#9E9E9E", egui::Color32::from_rgb(158, 158, 158)), // Grey
                ];
                for (hex, egui_color) in &colors {
                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(20.0, 20.0),
                        egui::Sense::click(),
                    );
                    ui.painter().rect_filled(rect, 2.0, *egui_color);
                    if self.color == *hex {
                        ui.painter().rect_stroke(rect, 2.0, egui::Stroke::new(2.0_f32, egui::Color32::WHITE));
                    }
                    if response.clicked() {
                        self.color = hex.to_string();
                    }
                    ui.add_space(4.0);
                }
            });
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label("Hex:");
                ui.add(egui::TextEdit::singleline(&mut self.color).desired_width(70.0));
            });
            ui.add_space(8.0);

            if self.started_at.is_some() || self.paused_at.is_some() || self.completed_at.is_some() {
                ui.separator();
                ui.label(egui::RichText::new("Timestamps").strong());
                if let Some(ref t) = self.started_at {
                    ui.colored_label(egui::Color32::from_rgb(76, 175, 80), format!("Started: {}", format_timestamp(t)));
                }
                if let Some(ref t) = self.paused_at {
                    ui.colored_label(egui::Color32::from_rgb(255, 152, 0), format!("Paused: {}", format_timestamp(t)));
                }
                if let Some(ref t) = self.completed_at {
                    ui.colored_label(egui::Color32::from_rgb(33, 150, 243), format!("Completed: {}", format_timestamp(t)));
                }
                ui.add_space(8.0);
            }

            if ui.button("OK").clicked() {
                ok = true;
            }
        });
        ok
    }

    fn to_feature(&self, id: &str) -> Option<Feature> {
        if self.title.trim().is_empty() {
            return None;
        }
        let days = self.days.trim().parse::<u32>().ok();
        let weeks = self.weeks.trim().parse::<u32>().ok();
        Some(Feature {
            id: id.to_string(),
            title: self.title.trim().to_string(),
            description: self.description.trim().to_string(),
            completed: self.status == "Completed",
            status: self.status.clone(),
            color: self.color.clone(),
            days: if self.days.trim().is_empty() { None } else { days },
            weeks: if self.weeks.trim().is_empty() { None } else { weeks },
            start_date: if self.start_date.trim().is_empty() { None } else { Some(self.start_date.trim().to_string()) },
            started_at: self.started_at.clone(),
            paused_at: self.paused_at.clone(),
            completed_at: self.completed_at.clone(),
        })
    }
}

#[derive(Default)]
enum DialogState {
    #[default]
    None,
    AddFeature {
        quarter_idx: usize,
        dialog: FeatureDialogState,
    },
    EditFeature {
        quarter_idx: usize,
        feature_idx: usize,
        dialog: FeatureDialogState,
    },
}

enum DialogAction {
    OpenAddFeature(usize),
    OpenEditFeature(usize, usize),
}

struct RoadmapApp {
    quarters: Vec<Quarter>,
    db: Connection,
    current_roadmap_id: Option<i64>,
    roadmap_list: Vec<(i64, String)>,
    status_text: String,
    dialog_state: DialogState,
    encrypted: bool,
    offline: bool,
    use_keychain: bool,
    db_key: Option<String>,
    undo_stack: Vec<Vec<Quarter>>,
    redo_stack: Vec<Vec<Quarter>>,
    new_roadmap_name: String,
    current_tab: String,
    show_open_dialog: bool,
    show_new_dialog: bool,
    rename_roadmap_id: Option<i64>,
    rename_roadmap_name: String,
    show_timeline_labels: bool,
    timeline_zoom: f32,
    timeline_scroll: f32,
    timeline_hovered_feature: Option<(usize, usize)>,
    timeline_tooltip_close_at: Option<std::time::Instant>,
    timeline_visible_roadmaps: Vec<(i64, bool, String)>,
    timeline_visible_status_buttons: bool,
    timeline_status_buttons_close_at: Option<std::time::Instant>,
    timeline_visible_status: Vec<(String, bool)>,
}

impl RoadmapApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Result<Self, String> {
        let key_file = key_path();
        let (conn, encrypted, use_keychain, db_key) = if key_file.exists() {
            let (conn, key) = open_connection(true, false)?;
            (conn, true, false, key)
        } else if let Ok((conn, _)) = open_connection(false, false) {
            (conn, false, false, None)
        } else if let Ok((conn, key)) = open_connection(true, true) {
            (conn, true, true, key)
        } else {
            return Err("Could not open database: not unencrypted, no key file, no keychain entry".into());
        };
        let roadmap_list = db_list_roadmaps(&conn);
        let mut app = Self {
            quarters: Vec::new(),
            db: conn,
            current_roadmap_id: None,
            roadmap_list,
            status_text: "Ready".into(),
            dialog_state: DialogState::None,
            encrypted,
            offline: true,
            use_keychain,
            db_key,
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            new_roadmap_name: String::new(),
            current_tab: "Quarters".into(),
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
            timeline_visible_status: vec![
                ("Planned".into(), true),
                ("Developing".into(), true),
                ("Testing".into(), true),
                ("Completed".into(), true),
                ("Stalled".into(), true),
                ("Paused".into(), true),
                ("Cancelled".into(), true),
                ("Deferred".into(), true),
            ],
        };
        app.initialize_quarters();
        app.new_roadmap_name = "default".into();
        Ok(app)
    }

    fn save_snapshot(&mut self) {
        self.undo_stack.push(self.quarters.clone());
        self.undo_stack.truncate(20);
        self.redo_stack.clear();
    }

    fn undo(&mut self) {
        if let Some(snapshot) = self.undo_stack.pop() {
            self.redo_stack.push(std::mem::replace(&mut self.quarters, snapshot));
            self.status_text = "Undo Action".into();
        }
    }

    fn redo(&mut self) {
        if let Some(snapshot) = self.redo_stack.pop() {
            self.undo_stack.push(std::mem::replace(&mut self.quarters, snapshot));
            self.status_text = "Redo Action".into();
        }
    }

    fn show_all_status(&mut self) {
        for i in 0..self.timeline_visible_status.len() {
            self.timeline_visible_status[i].1 = true;
        }
    }

    fn switch_tab(&mut self, tab: Option<&str>) {
        if let Some(name) = tab {
            self.current_tab = name.to_string();
        } else {
            if self.current_tab == "Quarters" {
                self.current_tab = "Timeline".into();
            } else if self.current_tab == "Timeline" {
                self.current_tab = "Quarters".into();
            } else if self.current_tab == "Org Chart" {
                /* org chart currently disabled (wip) */
                self.current_tab = "Quarters".into();
            }
        }
    }

    fn toggle_encryption(&mut self) {
        let want_encrypted = self.encrypted;
        let use_keychain = self.use_keychain;
        let new_path = std::path::PathBuf::from(format!("{}.new", db_path().display()));
        if new_path.exists() {
            let _ = std::fs::remove_file(&new_path);
        }

        let mut roadmaps: Vec<(i64, String, String, String)> = Vec::new();
        {
            let mut stmt = self.db.prepare("SELECT id, name, created_at, updated_at FROM roadmap").unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).unwrap();
            for r in rows.flatten() { roadmaps.push(r); }
        }

        let mut quarters: Vec<(i64, i64, u32, u32, i64)> = Vec::new();
        {
            let mut stmt = self.db.prepare("SELECT id, roadmap_id, year, quarter, sort_order FROM quarter ORDER BY sort_order").unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).unwrap();
            for r in rows.flatten() { quarters.push(r); }
        }

        let mut features: Vec<(String, i64, String, String, i32, String, String, i64)> = Vec::new();
        {
            let mut stmt = self.db.prepare("SELECT id, quarter_id, title, description, completed, status, color, sort_order FROM feature ORDER BY sort_order").unwrap();
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?))).unwrap();
            for r in rows.flatten() { features.push(r); }
        }

        let old_db = std::mem::replace(&mut self.db, Connection::open_in_memory().unwrap());
        drop(old_db);

        match open_connection_at_path(&new_path, want_encrypted, use_keychain) {
            Ok((new_conn, _)) => {
                for (id, name, created, updated) in &roadmaps {
                    new_conn.execute("INSERT INTO roadmap (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)", rusqlite::params![id, name, created, updated]).unwrap();
                }
                for (id, roadmap_id, year, quarter, sort_order) in &quarters {
                    new_conn.execute("INSERT INTO quarter (id, roadmap_id, year, quarter, sort_order) VALUES (?1, ?2, ?3, ?4, ?5)", rusqlite::params![id, roadmap_id, year, quarter, sort_order]).unwrap();
                }
                for (id, quarter_id, title, desc, completed, status, color, sort_order) in &features {
                    new_conn.execute("INSERT INTO feature (id, quarter_id, title, description, completed, status, color, sort_order) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", rusqlite::params![id, quarter_id, title, desc, completed, status, color, sort_order]).unwrap();
                }

                new_conn.close().unwrap();

                let old_path = db_path();
                let _ = std::fs::remove_file(&old_path);
                std::fs::rename(&new_path, &old_path).unwrap();

                match open_connection(want_encrypted, use_keychain) {
                    Ok((conn, key)) => {
                        self.encrypted = want_encrypted;
                        self.db = conn;
                        self.db_key = key;
                        self.roadmap_list = db_list_roadmaps(&self.db);
                        self.status_text = if self.encrypted { "Encryption enabled".into() } else { "Encryption disabled".into() };
                    }
                    Err(e) => {
                        self.status_text = format!("Error reopening DB: {}", e);
                    }
                }
            }
            Err(e) => {
                let _ = std::fs::remove_file(&new_path);
                match open_connection(self.encrypted, self.use_keychain) {
                    Ok((conn, _)) => { self.db = conn; }
                    Err(_) => {}
                }
                self.status_text = format!("Error migrating DB: {}", e);
            }
        }
    }

    fn toggle_keychain(&mut self) {
        let want_keychain = self.use_keychain;
        if want_keychain {
            let key = match &self.db_key {
                Some(k) => k.clone(),
                None => match load_or_create_key() {
                    Ok(k) => k,
                    Err(e) => {
                        self.use_keychain = false;
                        self.status_text = format!("Error reading key for keychain: {}", e);
                        return;
                    }
                }
            };
            if let Err(e) = save_key_to_keychain(&key) {
                self.use_keychain = false;
                self.status_text = e;
                return;
            }
            self.db_key = Some(key);
            let _ = fs::remove_file(key_path());
            self.status_text = "Key stored in system keychain".into();
        } else {
            let key = match &self.db_key {
                Some(k) => k.clone(),
                None => {
                    self.use_keychain = true;
                    self.status_text = "No cached key available".into();
                    return;
                }
            };
            if let Err(e) = fs::write(key_path(), &key) {
                self.use_keychain = true;
                self.status_text = format!("Error writing key to file: {}", e);
                return;
            }
            let _ = delete_key_from_keychain();
            self.status_text = "Key removed from system keychain".into();
        }
    }

    fn initialize_quarters(&mut self) {
        let now = chrono::Local::now();
        let current_year = now.year() as u32;
        let current_quarter = (now.month() - 1) / 3 + 1;
        for i in 0..4 {
            let mut q = current_quarter + i;
            let mut year = current_year;
            if q > 4 { q -= 4; year += 1; }
            self.quarters.push(Quarter::new(year, q));
        }
    }

    fn add_quarter(&mut self) {
        self.save_snapshot();
        let (year, quarter) = if let Some(last) = self.quarters.last() {
            if last.quarter == 4 { (last.year + 1, 1) } else { (last.year, last.quarter + 1) }
        } else {
            let now = chrono::Local::now();
            (now.year() as u32, 1)
        };
        self.quarters.push(Quarter::new(year, quarter));
        self.status_text = format!("Added Q{} {}", quarter, year);
    }

    fn remove_quarter(&mut self, index: usize) {
        self.save_snapshot();
        if index < self.quarters.len() {
            let removed = self.quarters.remove(index);
            self.status_text = format!("Removed {}", removed.name());
        }
    }

    fn clear_all(&mut self) {
        self.save_snapshot();
        self.quarters.clear();
        self.status_text = "Cleared all quarters".into();
    }

    fn new_roadmap(&mut self) {
        if self.new_roadmap_name.trim().is_empty() {
            self.status_text = "Enter a roadmap name first".into();
            return;
        }
        self.save_snapshot();
        let id = db_create_roadmap(&self.db, &self.new_roadmap_name);
        self.quarters.clear();
        self.initialize_quarters();
        self.current_roadmap_id = Some(id);
        db_save_roadmap(&self.db, id, &self.quarters);
        self.roadmap_list = db_list_roadmaps(&self.db);
        self.status_text = format!("Created roadmap: {}", self.new_roadmap_name);
        self.new_roadmap_name.clear();
    }

    fn open_roadmap(&mut self) {
        self.roadmap_list = db_list_roadmaps(&self.db);
        self.show_open_dialog = true;
    }

    fn open_roadmap_by_id(&mut self, id: i64) {
        self.save_snapshot();
        self.quarters = db_load_roadmap(&self.db, id);
        self.current_roadmap_id = Some(id);
        if let Some(name) = self.roadmap_list.iter().find(|(rid, _)| *rid == id).map(|(_, n)| n.clone()) {
            self.status_text = format!("Opened: {}", name);
        }
        self.show_open_dialog = false;
    }

    fn save_roadmap(&mut self) {
        if let Some(id) = self.current_roadmap_id {
            db_save_roadmap(&self.db, id, &self.quarters);
            self.status_text = "Saved roadmap".into();
        } else {
            let name = if self.new_roadmap_name.trim().is_empty() { "new_roadmap".to_string() } else { self.new_roadmap_name.trim().to_string() };
            let id = db_create_roadmap(&self.db, &name);
            db_save_roadmap(&self.db, id, &self.quarters);
            self.current_roadmap_id = Some(id);
            self.roadmap_list = db_list_roadmaps(&self.db);
            self.status_text = format!("Created and saved roadmap: {}", name);
        }
    }

    fn start_task(&mut self, qi: usize, fi: usize) {
        self.save_snapshot();
        let now = chrono::Local::now();
        let feature = &mut self.quarters[qi].features[fi];
        feature.started_at = Some(now.clone().to_rfc3339());
        if feature.start_date.is_none() {
            feature.start_date = Some(now.date_naive().format("%Y-%m-%d").to_string());
        }
        feature.paused_at = None;
        feature.status = "Developing".into();
        feature.completed = false;
        feature.completed_at = None;
        self.status_text = format!("Started: {}", feature.title);
    }

    fn pause_task(&mut self, qi: usize, fi: usize) {
        self.save_snapshot();
        let now = chrono::Local::now().to_rfc3339();
        let feature = &mut self.quarters[qi].features[fi];
        feature.paused_at = Some(now);
        feature.status = "Paused".into();
        self.status_text = format!("Paused: {}", feature.title);
    }

    fn complete_task(&mut self, qi: usize, fi: usize) {
        self.save_snapshot();
        let now = chrono::Local::now().to_rfc3339();
        let feature = &mut self.quarters[qi].features[fi];
        feature.completed_at = Some(now);
        feature.completed = true;
        feature.status = "Completed".into();
        self.status_text = format!("Completed: {}", feature.title);
    }

    fn load_template(&mut self, template_type: &str) {
        self.save_snapshot();
        self.quarters.clear();
        let now = chrono::Local::now();
        let year = now.year() as u32;
        let features = get_template(template_type);
        let per_q = 2;
        let num_q = (features.len() + per_q - 1) / per_q;
        for i in 0..num_q {
            let mut q = Quarter::new(year, (i as u32) + 1);
            let start = i * per_q;
            let end = std::cmp::min(start + per_q, features.len());
            for (j, title) in features[start..end].iter().enumerate() {
                let colors = ["#4CAF50", "#2196F3", "#FF9800", "#9C27B0"];
                q.features.push(Feature {
                    id: format!("feature_{}_{}_{}", template_type, i, j),
                    title: title.to_string(),
                    description: format!("Implementation of {}", title),
                    completed: false,
                    status: "Planned".into(),
                    color: colors[i % colors.len()].into(),
                    days: None,
                    weeks: None,
                    start_date: None,
                    started_at: None,
                    paused_at: None,
                    completed_at: None,
                });
            }
            self.quarters.push(q);
        }
        self.status_text = format!("Loaded {} template", template_type);
    }
}

fn parse_color(hex: &str) -> egui::Color32 {
    let hex = hex.trim_start_matches('#');
    if hex.len() == 6 {
        if let Ok(r) = u8::from_str_radix(&hex[0..2], 16) {
            if let Ok(g) = u8::from_str_radix(&hex[2..4], 16) {
                if let Ok(b) = u8::from_str_radix(&hex[4..6], 16) {
                    return egui::Color32::from_rgb(r, g, b);
                }
            }
        }
    }
    egui::Color32::from_rgb(33, 150, 243)
}

fn format_timestamp(iso: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(iso)
        .map(|dt| dt.format("%b %d, %Y %H:%M").to_string())
        .unwrap_or_else(|_| iso.to_string())
}

fn quarter_start_date(year: u32, quarter: u32) -> chrono::NaiveDate {
    let months: [u32; 4] = [1, 4, 7, 10];
    let month = months[(quarter - 1) as usize];
    chrono::NaiveDate::from_ymd_opt(year as i32, month, 1).unwrap()
}

fn quarter_end_date(year: u32, quarter: u32) -> chrono::NaiveDate {
    let months: [(u32, u32); 4] = [(1, 3), (4, 6), (7, 9), (10, 12)];
    let (_, end_month) = months[(quarter - 1) as usize];
    if end_month == 12 {
        chrono::NaiveDate::from_ymd_opt(year as i32, 12, 31).unwrap()
    } else {
        chrono::NaiveDate::from_ymd_opt(year as i32, end_month + 1, 1).unwrap()
            - chrono::Duration::days(1)
    }
}

fn feature_duration_days(f: &Feature) -> u32 {
    let w = f.weeks.unwrap_or(0);
    let d = f.days.unwrap_or(0);
    (w * 7) + d
}

impl eframe::App for RoadmapApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("title_bar").show(ctx, |ui| {
            let available = ui.available_rect_before_wrap();
            let drag_rect = available.intersect(ui.max_rect());
            let drag_response = ui.interact(drag_rect, ui.id().with("drag_area"), egui::Sense::drag());

            if drag_response.dragged() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }

            ctx.input_mut(|i| {
                if i.consume_key(egui::Modifiers::COMMAND, egui::Key::Z) {
                    if i.modifiers.shift { self.redo(); } else { self.undo(); }
                }
            });

            ctx.input_mut(|i| {
                if i.consume_key(egui::Modifiers::COMMAND, egui::Key::S) {
                    self.save_roadmap();
                }
            });

            egui::menu::bar(ui, |ui| {
                ui.label(egui::RichText::new("allroads").strong().size(14.0));
                ui.add_space(16.0);
                ui.menu_button("File", |ui| {
                    if ui.button("New").clicked() { self.show_new_dialog = true; ui.close_menu(); }
                    if ui.button("Open").clicked() { self.open_roadmap(); ui.close_menu(); }
                    if ui.button("Save").clicked() { self.save_roadmap(); ui.close_menu(); }
                    if ui.button("Exit").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    ui.separator();
                    ui.menu_button("Templates", |ui| {
                        if ui.button("Web Application").clicked() { self.load_template("web"); ui.close_menu(); }
                        if ui.button("Mobile App").clicked() { self.load_template("mobile"); ui.close_menu(); }
                        if ui.button("API Development").clicked() { self.load_template("api"); ui.close_menu(); }
                    });
                });
                ui.menu_button("Edit", |ui| {
                    if ui.button("Undo").clicked() { self.undo(); ui.close_menu(); }
                    if ui.button("Redo").clicked() { self.redo(); ui.close_menu(); }
                    ui.separator();
                    if ui.button("Rename Roadmap").clicked() {
                        if let Some(id) = self.current_roadmap_id {
                            self.rename_roadmap_id = Some(id);
                            if let Some(name) = self.roadmap_list.iter().find(|(rid, _)| *rid == id).map(|(_, n)| n.clone()) {
                                self.rename_roadmap_name = name;
                            }
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.menu_button("Encryption", |ui| {
                        if ui.checkbox(&mut self.encrypted, "Enable AES Encryption").changed() {
                            self.toggle_encryption();
                        }
                        let keychain_enabled = self.encrypted;
                        let mut use_keychain = self.use_keychain;
                        let response = ui.add_enabled(keychain_enabled, egui::Checkbox::new(&mut use_keychain, "Use System Keychain"));
                        let response = if !keychain_enabled {
                            response.on_hover_text("Enable encryption first")
                        } else {
                            response
                        };
                        if response.changed() {
                            self.use_keychain = use_keychain;
                            self.toggle_keychain();
                        }
                    });
                    ui.menu_button("Organizations", |ui| {
                        if ui.button("Join").clicked() {
                            if self.offline == true {
                                self.status_text = "Disable offline mode before joining an organization".into();
                                ui.close_menu();
                            }
                        }
                        if ui.button("Create").clicked() {}
                        ui.separator();
                        if ui.button("Settings").clicked() {}
                    });
                });
                ui.menu_button("View", |ui| {
                    if ui.button("Timeline").clicked() { self.switch_tab(Some("Timeline")); ui.close_menu(); }
                    if ui.button("Org Chart").clicked() { self.switch_tab(Some("Org Chart")); ui.close_menu(); }
                    if ui.button("Quarters").clicked() { self.switch_tab(Some("Quarters")); ui.close_menu(); }
                    ui.separator();
                    ui.checkbox(&mut self.show_timeline_labels, "Show Labels");
                });
                ui.menu_button("Network", |ui| {
                    if ui.checkbox(&mut self.offline, "Offline Mode").changed() {}
                    if ui.button("Proxy").clicked() {}
                    if ui.button("Server").clicked() {}
                    ui.separator();
                    if ui.button("Sync now").clicked() {}
                }); 

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.button("Minimize").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.colored_label(egui::Color32::GRAY, "v1.2.0");
                });
            });
        });

        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading(&self.current_tab);
                ui.add_space(10.0);
                if ui.button("Add Quarter").clicked() { self.add_quarter(); }
                if ui.button("Clear All").clicked() { self.clear_all(); }
                if ui.button("Change View").clicked() { self.switch_tab(None); }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if self.current_tab == "Quarters" {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut dialog_action: Option<DialogAction> = None;
                    let mut remove_action: Option<(usize, usize)> = None;
                    let mut move_up_action: Option<(usize, usize)> = None;
                    let mut move_down_action: Option<(usize, usize)> = None;
                    let mut quarter_remove_idx: Option<usize> = None;

                    for (qi, quarter) in &mut self.quarters.iter_mut().enumerate() {
                        egui::Frame::group(ui.style())
                            .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(180, 180, 180)))
                            .show(ui, |ui| {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.heading(quarter.name());
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.small_button("x").clicked() {
                                                quarter_remove_idx = Some(qi);
                                            }
                                        });
                                    });
                                    ui.label(quarter.date_range());
                                    ui.separator();

                                    if ui.button("+ Add Feature").clicked() {
                                        dialog_action = Some(DialogAction::OpenAddFeature(qi));
                                    }

                                    ui.add_space(4.0);

                                    for (fi, feature) in quarter.features.iter().enumerate() {
                                        egui::Frame::none()
                                            .stroke(egui::Stroke::new(0.5_f32, egui::Color32::from_rgb(200, 200, 200)))
                                            .inner_margin(4.0)
                                            .outer_margin(0.0)
                                            .show(ui, |ui| {
                                            let available = ui.available_width();
                                            ui.allocate_ui(egui::vec2(available, 36.0), |ui| {
                                                ui.horizontal(|ui| {
                                                    let color = parse_color(&feature.color);
                                                    let (rect, _) = ui.allocate_exact_size(
                                                        egui::vec2(6.0, 28.0),
                                                        egui::Sense::hover(),
                                                    );
                                                    ui.painter().rect_filled(rect, 0.0, color);

                                                    if feature.completed {
                                                        ui.colored_label(egui::Color32::GRAY, &feature.title);
                                                    } else {
                                                        ui.label(&feature.title);
                                                    }

                                                    let status_color = if feature.completed {
                                                        egui::Color32::from_rgb(76, 175, 80)
                                                    } else {
                                                        egui::Color32::from_rgb(180, 180, 180)
                                                    };
                                                    ui.colored_label(status_color, format!("[{}]", feature.status));
                                                    ui.colored_label(egui::Color32::GRAY, &feature.description);

                                                    let mut time_parts = Vec::new();
                                                    if let Some(w) = feature.weeks { time_parts.push(format!("{}w", w)); }
                                                    if let Some(d) = feature.days { time_parts.push(format!("{}d", d)); }
                                                    if !time_parts.is_empty() {
                                                        ui.colored_label(egui::Color32::GRAY, time_parts.join(" "));
                                                    }

                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if ui.small_button("Down").clicked() {
                                                            move_down_action = Some((qi, fi));
                                                        }
                                                        if ui.small_button("Up").clicked() {
                                                            move_up_action = Some((qi, fi));
                                                        }
                                                        if ui.small_button("Delete").clicked() {
                                                            remove_action = Some((qi, fi));
                                                        }
                                                        if ui.small_button("Edit").clicked() {
                                                            dialog_action = Some(DialogAction::OpenEditFeature(qi, fi));
                                                        }
                                                    });
                                                });
                                            });
                                        });
                                    }
                                });
                            });
                        ui.add_space(8.0);
                    }

                    if let Some(qi) = quarter_remove_idx {
                        self.remove_quarter(qi);
                    }

                    if let Some((qi, fi)) = remove_action {
                        self.save_snapshot();
                        self.quarters[qi].features.remove(fi);
                    }
                    if let Some((qi, fi)) = move_up_action {
                        self.save_snapshot();
                        if fi > 0 {
                            self.quarters[qi].features.swap(fi, fi - 1);
                        } else if qi > 0 {
                            let feature = self.quarters[qi].features.remove(fi);
                            self.quarters[qi - 1].features.push(feature);
                        }
                    }
                    if let Some((qi, fi)) = move_down_action {
                        self.save_snapshot();
                        if fi < self.quarters[qi].features.len() - 1 {
                            self.quarters[qi].features.swap(fi, fi + 1);
                        } else if qi < self.quarters.len() - 1 {
                            let feature = self.quarters[qi].features.remove(fi);
                            self.quarters[qi + 1].features.insert(0, feature);
                        }
                    }

                    if let Some(action) = dialog_action {
                        match action {
                            DialogAction::OpenAddFeature(qi) => {
                                self.dialog_state = DialogState::AddFeature {
                                    quarter_idx: qi,
                                    dialog: FeatureDialogState::default(),
                                };
                            }
                            DialogAction::OpenEditFeature(qi, fi) => {
                                let existing = &self.quarters[qi].features[fi];
                                self.dialog_state = DialogState::EditFeature {
                                    quarter_idx: qi,
                                    feature_idx: fi,
                                    dialog: FeatureDialogState::from_feature(existing),
                                };
                            }
                        }
                    }
                });
            } else if self.current_tab == "Timeline" {
                for (id, name) in &self.roadmap_list.clone() {
                    if !self.timeline_visible_roadmaps.iter().any(|(rid, _, _)| rid == id) {
                        let visible = self.current_roadmap_id.map_or(true, |cur| cur == *id);
                        self.timeline_visible_roadmaps.push((*id, visible, name.clone()));
                    }
                }
                self.timeline_visible_roadmaps.retain(|(id, _, _)| self.roadmap_list.iter().any(|(rid, _)| rid == id));

                ui.horizontal(|ui| {
                    ui.label("Roadmaps:");
                    for i in 0..self.timeline_visible_roadmaps.len() {
                        let (_rid, vis, name) = &mut self.timeline_visible_roadmaps[i];
                        let mut checked = *vis;
                        if ui.checkbox(&mut checked, &*name).changed() {
                            self.timeline_visible_roadmaps[i].1 = checked;
                        }
                    }

                });

                let mut all_quarters: Vec<(i64, Vec<Quarter>)> = Vec::new();
                for (rid, visible, _) in &self.timeline_visible_roadmaps {
                    if *visible {
                        if self.current_roadmap_id == Some(*rid) {
                            all_quarters.push((*rid, self.quarters.clone()));
                        } else {
                            all_quarters.push((*rid, db_load_roadmap(&self.db, *rid)));
                        }
                    }
                }

                if all_quarters.is_empty() || all_quarters.iter().all(|(_, q)| q.is_empty()) {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.label("No quarters to show. Check a roadmap.");
                    });
                } else {
                    let flat_qs: Vec<&Quarter> = all_quarters.iter().flat_map(|(_, qs)| qs.iter()).collect();
                    let first_q = flat_qs.iter().min_by_key(|q| (q.year, q.quarter)).unwrap();
                    let last_q = flat_qs.iter().max_by_key(|q| (q.year, q.quarter)).unwrap();
                    let timeline_start = quarter_start_date(first_q.year, first_q.quarter);
                    let timeline_end = quarter_end_date(last_q.year, last_q.quarter);
                    let total_days = (timeline_end - timeline_start).num_days() as i64 + 1;

                    if total_days <= 0 {
                        ui.label("Invalid date range.");
                    } else {
                        if ui.input(|i| i.pointer.primary_down()) == false {
                            let scroll = ui.input(|i| i.raw_scroll_delta);
                            self.timeline_scroll -= scroll.x;
                            let zoom_delta = ui.input(|i| i.zoom_delta());
                            if zoom_delta != 1.0 {
                                self.timeline_zoom = (self.timeline_zoom * zoom_delta).clamp(0.50, 20.0);
                            }
                        }
                        ui.ctx().input(|i| {
                            for ev in &i.raw.events {
                                if let egui::Event::MouseWheel { delta, .. } = ev {
                                    self.timeline_scroll -= delta.x;
                                }
                            }
                        });

                        let bar_height = 4.0_f32;
                        let (response, painter) = ui.allocate_painter(
                            ui.available_size(),
                            egui::Sense::hover(),
                        );
                        let rect = response.rect;
                        let center_y = rect.center().y;

                        let base_timeline_left = rect.left() + 20.0;
                        let base_timeline_right = rect.right() - 20.0;
                        let base_timeline_width = base_timeline_right - base_timeline_left;
                        let zoomed_width = base_timeline_width * self.timeline_zoom;
                        let zoom_extra = (zoomed_width - base_timeline_width) / 2.0;
                        let scroll_limit = zoom_extra.max(0.0) + 50.0;
                        self.timeline_scroll = self.timeline_scroll.clamp(-scroll_limit, scroll_limit);
                        let timeline_left = base_timeline_left - zoom_extra - self.timeline_scroll;
                        let timeline_right = timeline_left + zoomed_width;
                        let timeline_width = zoomed_width;

                        painter.line_segment(
                            [egui::pos2(timeline_left, center_y), egui::pos2(timeline_right, center_y)],
                            egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(180, 180, 180)),
                        );

                        let mut all_bars: Vec<(egui::Rect, usize, usize)> = Vec::new();

                        let mut merged_quarters: std::collections::BTreeMap<(u32, u32), Vec<&Feature>> = std::collections::BTreeMap::new();
                        for (_, qs) in &all_quarters {
                            for q in qs {
                                merged_quarters.entry((q.year, q.quarter)).or_default().extend(q.features.iter());
                            }
                        }
                        let merged_keys: Vec<(u32, u32)> = merged_quarters.keys().copied().collect();
                        for (qi, key) in merged_keys.iter().enumerate() {
                            let features = &merged_quarters[key];
                            let year = key.0;
                            let quarter = key.1;
                            let q_start = quarter_start_date(year, quarter);
                            let q_end = quarter_end_date(year, quarter);
                            let q_start_offset = (q_start - timeline_start).num_days() as f32;
                            let q_end_offset = (q_end - timeline_start).num_days() as f32 + 1.0;

                            let x_start = timeline_left + (q_start_offset / total_days as f32) * timeline_width;
                            let x_end = timeline_left + (q_end_offset / total_days as f32) * timeline_width;

                            painter.line_segment(
                                [egui::pos2(x_start, center_y - 8.0), egui::pos2(x_start, center_y + 8.0)],
                                egui::Stroke::new(2.0_f32, egui::Color32::from_rgb(255, 255, 255)),
                            );

                            painter.text(
                                egui::pos2((x_start + x_end) / 2.0, center_y + 24.0),
                                egui::Align2::CENTER_TOP,
                                format!("Q{} {}", quarter, year),
                                egui::FontId::proportional(12.0),
                                egui::Color32::from_rgb(200, 200, 200),
                            );

                            let mut day = q_start;
                            let mut day_num = 0u32;
                            while day <= q_end {
                                let day_offset = (day - timeline_start).num_days() as f32;
                                let x = timeline_left + (day_offset / total_days as f32) * timeline_width;
                                let is_week = day_num % 7 == 0;

                                if is_week {
                                    painter.line_segment(
                                        [egui::pos2(x, center_y + 8.0), egui::pos2(x, center_y + 20.0)],
                                        egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(120, 120, 120)),
                                    );
                                } else {
                                    painter.line_segment(
                                        [egui::pos2(x, center_y + 8.0), egui::pos2(x, center_y + 14.0)],
                                        egui::Stroke::new(0.5_f32, egui::Color32::from_rgb(50, 50, 50)),
                                    );
                                }
                                day = day + chrono::Duration::days(1);
                                day_num += 1;
                            }

                            for (fi, feature) in features.iter().enumerate() {
                                if !self.timeline_visible_status.iter().any(|(s, v)| s == &feature.status && *v) {
                                    continue;
                                }
                                let has_estimate = feature.weeks.unwrap_or(0) > 0 || feature.days.unwrap_or(0) > 0;
                                let duration = if has_estimate {
                                    feature_duration_days(feature).max(1)
                                } else {
                                    ((q_end - q_start).num_days() + 1).max(1) as u32
                                };

                                let feature_start_date = feature.start_date.as_ref()
                                    .and_then(|s| chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
                                    .unwrap_or(q_start);
                                let feature_start_offset = (feature_start_date - timeline_start).num_days().max(0) as f32;
                                let feature_x_start = timeline_left + (feature_start_offset / total_days as f32) * timeline_width;
                                let feature_x_start = feature_x_start.max(x_start).min(x_end);

                                let feature_bar_width = (duration as f32 / total_days as f32) * timeline_width;
                                let feature_bar_width = feature_bar_width.max(20.0);
                                let feature_x_end = (feature_x_start + feature_bar_width).min(x_end);

                                let bar_gap: f32;
                                if self.show_timeline_labels {
                                    bar_gap = 14.0;
                                } else {
                                    bar_gap = 2.0;
                                }
                                let feature_y = center_y - 10.0 - (features.len() - fi) as f32 * (bar_height + bar_gap);

                                let color = parse_color(&feature.color);
                                let mut bar_color = color;
                                if feature.status == "Paused" {
                                    bar_color = egui::Color32::from_rgb(
                                        (color.r() as f32 * 0.6) as u8,
                                        (color.g() as f32 * 0.6) as u8,
                                        (color.b() as f32 * 0.6) as u8,
                                    );
                                }

                                let bar_rect = egui::Rect::from_min_max(
                                    egui::pos2(feature_x_start, feature_y),
                                    egui::pos2(feature_x_end, feature_y + bar_height),
                                );
                                painter.rect_filled(bar_rect, 2.0, bar_color);

                                if feature.completed {
                                    painter.rect_stroke(bar_rect, 2.0_f32, egui::Stroke::new(0.5_f32, egui::Color32::WHITE));
                                } else if feature.status == "Paused" {
                                    let dash_len = 3.0;
                                    let mut dx = bar_rect.left();
                                    while dx < bar_rect.right() {
                                        let seg_end = (dx + dash_len).min(bar_rect.right());
                                        painter.line_segment(
                                            [egui::pos2(dx, bar_rect.bottom()), egui::pos2(seg_end, bar_rect.bottom())],
                                            egui::Stroke::new(0.5_f32, egui::Color32::WHITE),
                                        );
                                        dx += dash_len * 2.0;
                                    }
                                }

                                if self.show_timeline_labels {
                                    painter.text(
                                        egui::pos2(feature_x_start, feature_y - 2.0),
                                        egui::Align2::LEFT_BOTTOM,
                                        &feature.title,
                                        egui::FontId::proportional(9.0),
                                        egui::Color32::from_rgb(180, 180, 180),
                                    );
                                }

                                all_bars.push((bar_rect, qi, fi));
                            }

                            if qi < merged_keys.len() - 1 {
                                let next_key = merged_keys[qi + 1];
                                let next_start = quarter_start_date(next_key.0, next_key.1);
                                let next_offset = (next_start - timeline_start).num_days() as f32;
                                let x_next = timeline_left + (next_offset / total_days as f32) * timeline_width;
                                painter.line_segment(
                                    [egui::pos2(x_next, center_y - 20.0), egui::pos2(x_next, center_y + 20.0)],
                                    egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(80, 80, 80)),
                                );
                            }
                        }

                        let hover_pos = response.hover_pos();
                        if let Some(pos) = hover_pos {
                            let mut found = false;
                            for (bar_rect, qi, fi) in &all_bars {
                                if bar_rect.contains(pos) {
                                    self.timeline_hovered_feature = Some((*qi, *fi));
                                    self.timeline_tooltip_close_at = None;
                                    found = true;
                                    break;
                                }
                            }
                            if !found && self.timeline_hovered_feature.is_some() && self.timeline_tooltip_close_at.is_none() {
                                self.timeline_tooltip_close_at = Some(std::time::Instant::now() + (std::time::Duration::from_secs(1) / 2));
                            }
                        } else if self.timeline_hovered_feature.is_some() && self.timeline_tooltip_close_at.is_none() {
                            self.timeline_tooltip_close_at = Some(std::time::Instant::now() + (std::time::Duration::from_secs(1) / 2));
                        }

                        if let Some(deadline) = self.timeline_tooltip_close_at {
                            if std::time::Instant::now() >= deadline {
                                self.timeline_hovered_feature = None;
                                self.timeline_tooltip_close_at = None;
                            }
                        }
                        if let Some((qi, fi)) = self.timeline_hovered_feature {
                            if let Some(features) = merged_keys.get(qi).and_then(|k| merged_quarters.get(k)) {
                                if fi < features.len() {
                                    let feature = &features[fi];
                                    let f_title = feature.title.clone();
                                    let f_desc = feature.description.clone();
                                    let f_status = feature.status.clone();
                                    let f_weeks = feature.weeks;
                                    let f_days = feature.days;
                                    let f_started = feature.started_at.clone();
                                    let f_paused = feature.paused_at.clone();
                                    let f_completed = feature.completed_at.clone();
                                    let f_start_date = feature.start_date.clone();

                                    let own_idx = self.quarters.iter().enumerate()
                                        .find_map(|(qi, q)| q.features.iter().position(|f| f.id == feature.id).map(|fi| (qi, fi)));

                                    let tooltip_pos = all_bars.iter()
                                        .find(|(_, q, f)| *q == qi && *f == fi)
                                        .map(|(r, _, _)| egui::pos2(r.left(), r.top() - 4.0))
                                        .unwrap_or(rect.left_top());

                                    let tooltip_id = egui::Id::new("timeline_tooltip_area");
                                    egui::Area::new(tooltip_id)
                                        .pivot(egui::Align2::LEFT_BOTTOM)
                                        .fixed_pos(tooltip_pos)
                                        .order(egui::Order::Foreground)
                                        .show(ctx, |ui| {
                                            ui.set_min_width(240.0);
                                            let frame = egui::Frame::popup(ui.style());
                                            frame.show(ui, |ui| {
                                                ui.vertical(|ui| {
                                                    ui.label(egui::RichText::new(&f_title).strong().size(13.0));
                                                    ui.add_space(2.0);
                                                    ui.colored_label(egui::Color32::GRAY, &f_desc);
                                                    ui.add_space(4.0);

                                                    let status_color = match f_status.as_str() {
                                                        "Developing" => egui::Color32::from_rgb(76, 175, 80),
                                                        "Completed" => egui::Color32::from_rgb(33, 150, 243),
                                                        "Paused" => egui::Color32::from_rgb(255, 152, 0),
                                                        _ => egui::Color32::from_rgb(180, 180, 180),
                                                    };
                                                    ui.colored_label(status_color, format!("[{}]", f_status));

                                                    let mut est = Vec::new();
                                                    if let Some(w) = f_weeks { est.push(format!("{}w", w)); }
                                                    if let Some(d) = f_days { est.push(format!("{}d", d)); }
                                                    if !est.is_empty() {
                                                        ui.colored_label(egui::Color32::GRAY, format!("Estimate: {}", est.join(" ")));
                                                    }

                                                    if let Some(ref sd) = f_start_date {
                                                        ui.colored_label(egui::Color32::from_rgb(200, 200, 200), format!("Start date: {}", sd));
                                                    }

                                                    if let Some(t) = f_started {
                                                        ui.colored_label(egui::Color32::from_rgb(76, 175, 80), format!("Started: {}", format_timestamp(&t)));
                                                    }
                                                    if let Some(t) = f_paused {
                                                        ui.colored_label(egui::Color32::from_rgb(255, 152, 0), format!("Paused: {}", format_timestamp(&t)));
                                                    }
                                                    if let Some(t) = f_completed {
                                                        ui.colored_label(egui::Color32::from_rgb(33, 150, 243), format!("Completed: {}", format_timestamp(&t)));
                                                    }
                                                    if let Some((qi_val, fi_val)) = own_idx {
                                                        ui.separator();
                                                        ui.horizontal(|ui| {
                                                            if f_status == "Planned" || f_status == "Paused" || f_status == "Stalled" || f_status == "Blocked" {
                                                                if ui.small_button("Start").clicked() {
                                                                    ctx.data_mut(|d| d.insert_temp(egui::Id::new("tooltip_action"), Some((qi_val, fi_val, "start".to_string()))));
                                                                }
                                                            }
                                                            if f_status == "Developing" {
                                                                if ui.small_button("Pause").clicked() {
                                                                    ctx.data_mut(|d| d.insert_temp(egui::Id::new("tooltip_action"), Some((qi_val, fi_val, "pause".to_string()))));
                                                                }
                                                            }
                                                            if f_status == "Developing" || f_status == "Testing" {
                                                                if ui.small_button("Complete").clicked() {
                                                                    ctx.data_mut(|d| d.insert_temp(egui::Id::new("tooltip_action"), Some((qi_val, fi_val, "complete".to_string()))));
                                                                }
                                                            }
                                                        });
                                                    }
                                                });
                                            });
                                        });
                                    }
                            }
                        }

                        ui.add_space(-20.0);
                        let outer_resp = ui.horizontal(|ui|{
                            let label_resp = ui.label("Status:");
                            if label_resp.hovered() {
                                self.timeline_visible_status_buttons = true;
                                self.timeline_status_buttons_close_at = None;
                            }
                            if self.timeline_visible_status_buttons {
                                ui.horizontal(|ui| {
                                    for i in 0..self.timeline_visible_status.len() {
                                        let (s, v) = &mut self.timeline_visible_status[i];
                                        let mut checked = *v;
                                        if ui.checkbox(&mut checked, &*s).changed() {
                                            self.timeline_visible_status[i].1 = checked;
                                        }

                                    }  
                                    if ui.button("Show All").clicked() {
                                        self.show_all_status();
                                    }
                                });
                            }
                        }).response;
                        if self.timeline_visible_status_buttons {  
                            let pointer_in_row = ui.ctx().pointer_hover_pos()
                                .map_or(false, |p| outer_resp.rect.contains(p));
                            if pointer_in_row {
                                self.timeline_status_buttons_close_at = None;
                            } else if self.timeline_status_buttons_close_at.is_none()
                                && !outer_resp.hovered() {
                                    self.timeline_status_buttons_close_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(500));
                            }
                            if let Some(deadline) = self.timeline_status_buttons_close_at {
                                if std::time::Instant::now() >= deadline {
                                    self.timeline_visible_status_buttons = false;
                                    self.timeline_status_buttons_close_at = None;
                                }
                            }
                        }
                        
                        let tooltip_action: Option<(usize, usize, String)> = ctx.data(|d| d.get_temp(egui::Id::new("tooltip_action")).unwrap_or(None));
                        ctx.data_mut(|d| d.remove::<Option<(usize, usize, String)>>(egui::Id::new("tooltip_action")));

                        if let Some((qi, fi, action)) = tooltip_action {
                            match action.as_str() {
                                "start" => self.start_task(qi, fi),
                                "pause" => self.pause_task(qi, fi),
                                "complete" => self.complete_task(qi, fi),
                                _ => {}
                            }
                        }
                    }
                }
            }
        });

        let mut close_dialog = false;

        match &mut self.dialog_state {
            DialogState::AddFeature { quarter_idx, dialog } => {
                let qi = *quarter_idx;
                egui::Window::new("Add Feature").default_width(350.0).collapsible(false).resizable(false).show(ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(feat) = dialog.to_feature(&format!("f_{}", rand::random::<u64>())) {
                            self.undo_stack.push(self.quarters.clone());
                            self.undo_stack.truncate(20);
                            self.redo_stack.clear();
                            self.quarters[qi].features.push(feat);
                            self.status_text = format!("Added feature: {}", self.quarters[qi].features.last().unwrap().title);
                        }
                        close_dialog = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_dialog = true;
                    }
                });
            }

            DialogState::EditFeature { quarter_idx, feature_idx, dialog } => {
                let (qi, fi) = (*quarter_idx, *feature_idx);
                let existing_id = self.quarters[qi].features[fi].id.clone();
                egui::Window::new("Edit Feature").default_width(350.0).collapsible(false).resizable(false).show(ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(feat) = dialog.to_feature(&existing_id) {
                            self.undo_stack.push(self.quarters.clone());
                            self.undo_stack.truncate(20);
                            self.redo_stack.clear();
                            self.quarters[qi].features[fi] = feat;
                            self.status_text = format!("Updated feature: {}", self.quarters[qi].features[fi].title);
                        }
                        close_dialog = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_dialog = true;
                    }
                });
            }
            DialogState::None => {} 
        }

        if close_dialog {
            self.dialog_state = DialogState::None;
        }

        if self.show_open_dialog {
            let mut open_id = None;
            let mut delete_id = None;
            egui::Window::new("Open Roadmap").collapsible(false).resizable(false).show(ctx, |ui| {
                if self.roadmap_list.is_empty() {
                    ui.label("No roadmaps found.");
                }
                for (id, name) in &self.roadmap_list.clone() {
                    ui.horizontal(|ui| {
                        if ui.button(name).clicked() {
                            open_id = Some(*id);
                        }
                        if ui.small_button("Delete").clicked() {
                            delete_id = Some(*id);
                        }
                    });
                }
                ui.separator();
                if ui.button("Cancel").clicked() {
                    self.show_open_dialog = false;
                }
            });
            if let Some(id) = delete_id {
                self.save_snapshot();
                db_delete_roadmap(&self.db, id);
                self.roadmap_list = db_list_roadmaps(&self.db);
                if self.current_roadmap_id == Some(id) {
                    self.current_roadmap_id = None;
                    self.quarters.clear();
                }
            }
            if let Some(id) = open_id {
                self.open_roadmap_by_id(id);
            }
        }

        if self.show_new_dialog {
            egui::Window::new("New Roadmap").collapsible(false).resizable(false).show(ctx, |ui| {
                ui.label("Roadmap name:");
                ui.text_edit_singleline(&mut self.new_roadmap_name);
                ui.horizontal(|ui| {
                    if ui.button("Create").clicked() {
                        self.new_roadmap();
                        self.show_new_dialog = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.show_new_dialog = false;
                    }
                });
            });
        }

        if let Some(rid) = self.rename_roadmap_id {
            egui::Window::new("Rename Roadmap").collapsible(false).resizable(false).show(ctx, |ui| {
                ui.label("New name:");
                ui.text_edit_singleline(&mut self.rename_roadmap_name);
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        self.save_snapshot();
                        db_rename_roadmap(&self.db, rid, &self.rename_roadmap_name);
                        self.roadmap_list = db_list_roadmaps(&self.db);
                        self.rename_roadmap_id = None;
                    }
                    if ui.button("Cancel").clicked() {
                        self.rename_roadmap_id = None;
                    }
                });
            });
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 700.0])
            .with_title("allroads v1.2.0")
            .with_decorations(false)
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../icon.icns"))
                    .unwrap_or_default(),
            ),
        ..Default::default()
    };
    eframe::run_native(
        "AllRoads",
        options,
        Box::new(|cc| match RoadmapApp::new(cc) {
            Ok(app) => Ok(Box::new(app)),
            Err(e) => { eprintln!("Error: {}", e); std::process::exit(1); }
        }),
    )
}
