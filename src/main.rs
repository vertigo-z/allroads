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
    sort_order INTEGER NOT NULL
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
                "INSERT INTO feature (id, quarter_id, title, description, completed, status, color, sort_order) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![f.id, quarter_id, f.title, f.description, f.completed as i32, f.status, f.color, fi as i64],
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
        let mut f_stmt = conn.prepare("SELECT id, title, description, completed, status, color FROM feature WHERE quarter_id = ?1 ORDER BY sort_order").unwrap();
        let features: Vec<Feature> = f_stmt.query_map(rusqlite::params![qid], |row| {
            let completed: i32 = row.get(3)?;
            Ok(Feature {
                id: row.get(0)?,
                title: row.get(1)?,
                description: row.get(2)?,
                completed: completed != 0,
                status: row.get(4)?,
                color: row.get(5)?,
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
}

impl Default for FeatureDialogState {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            status: "Planned".into(),
            color: "#FF9800".into(),
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
        }
    }

    fn show(&mut self, ui: &mut egui::Ui) -> bool {
        let mut ok = false;
        ui.vertical(|ui| {
            ui.label("Title:");
            ui.text_edit_singleline(&mut self.title);
            ui.add_space(4.0);

            ui.label("Description:");
            ui.add(egui::TextEdit::multiline(&mut self.description).desired_rows(6));
            ui.add_space(4.0);

            ui.label("Status:");
            ui.horizontal(|ui| {
                for s in &["Planned", "Developing", "Testing", "Completed"] {
                    if ui.radio(self.status == *s, *s).clicked() {
                        self.status = s.to_string();
                    }
                }
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
            ui.add_space(8.0);

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
        Some(Feature {
            id: id.to_string(),
            title: self.title.trim().to_string(),
            description: self.description.trim().to_string(),
            completed: self.status == "Completed",
            status: self.status.clone(),
            color: self.color.clone(),
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
    EditStatus {
        quarter_idx: usize,
        feature_idx: usize,
    },
}

enum DialogAction {
    OpenAddFeature(usize),
    OpenEditFeature(usize, usize),
    OpenEditStatus(usize, usize),
}

struct RoadmapApp {
    quarters: Vec<Quarter>,
    db: Connection,
    current_roadmap_id: Option<i64>,
    roadmap_list: Vec<(i64, String)>,
    status_text: String,
    dialog_state: DialogState,
    encrypted: bool,
    use_keychain: bool,
    db_key: Option<String>,
    new_roadmap_name: String,
    show_open_dialog: bool,
    show_new_dialog: bool,
    rename_roadmap_id: Option<i64>,
    rename_roadmap_name: String,
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
            use_keychain,
            db_key,
            new_roadmap_name: String::new(),
            show_open_dialog: false,
            show_new_dialog: false,
            rename_roadmap_id: None,
            rename_roadmap_name: String::new(),
        };
        app.initialize_quarters();
        app.new_roadmap_name = "default".into();
        Ok(app)
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
        if index < self.quarters.len() {
            let removed = self.quarters.remove(index);
            self.status_text = format!("Removed {}", removed.name());
        }
    }

    fn clear_all(&mut self) {
        self.quarters.clear();
        self.status_text = "Cleared all quarters".into();
    }

    fn new_roadmap(&mut self) {
        if self.new_roadmap_name.trim().is_empty() {
            self.status_text = "Enter a roadmap name first".into();
            return;
        }
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
            let name = if self.new_roadmap_name.trim().is_empty() { "default".to_string() } else { self.new_roadmap_name.trim().to_string() };
            let id = db_create_roadmap(&self.db, &name);
            db_save_roadmap(&self.db, id, &self.quarters);
            self.current_roadmap_id = Some(id);
            self.roadmap_list = db_list_roadmaps(&self.db);
            self.status_text = format!("Created and saved roadmap: {}", name);
        }
    }

    fn load_template(&mut self, template_type: &str) {
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

impl eframe::App for RoadmapApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("title_bar").show(ctx, |ui| {
            let available = ui.available_rect_before_wrap();
            let drag_rect = available.intersect(ui.max_rect());
            let drag_response = ui.interact(drag_rect, ui.id().with("drag_area"), egui::Sense::drag());

            if drag_response.dragged() {
                ctx.send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }

            egui::menu::bar(ui, |ui| {
                ui.label(egui::RichText::new("allroads").strong().size(14.0));
                ui.add_space(16.0);
                ui.menu_button("File", |ui| {
                    if ui.button("New").clicked() { self.show_new_dialog = true; ui.close_menu(); }
                    if ui.button("Open").clicked() { self.open_roadmap(); ui.close_menu(); }
                    if ui.button("Save").clicked() { self.save_roadmap(); ui.close_menu(); }
                    ui.separator();
                    ui.menu_button("Settings", |ui| {
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
                        if ui.button("Rename Roadmap").clicked() {
                            if let Some(id) = self.current_roadmap_id {
                                self.rename_roadmap_id = Some(id);
                                if let Some(name) = self.roadmap_list.iter().find(|(rid, _)| *rid == id).map(|(_, n)| n.clone()) {
                                    self.rename_roadmap_name = name;
                                }
                            }
                            ui.close_menu();
                        }
                    });
                    ui.separator();
                    if ui.button("Exit").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                });
                ui.menu_button("Templates", |ui| {
                    if ui.button("Web Application").clicked() { self.load_template("web"); ui.close_menu(); }
                    if ui.button("Mobile App").clicked() { self.load_template("mobile"); ui.close_menu(); }
                    if ui.button("API Development").clicked() { self.load_template("api"); ui.close_menu(); }
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
            ui.label(&self.status_text);
        });

        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Timeline");
                ui.add_space(10.0);
                if ui.button("Add Quarter").clicked() { self.add_quarter(); }
                if ui.button("Clear All").clicked() { self.clear_all(); }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
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
                                                    egui::Color32::from_rgb(100, 100, 100)
                                                };
                                                let status_response = ui.colored_label(status_color, format!("[{}]", feature.status));
                                                if status_response.clicked() {
                                                    dialog_action = Some(DialogAction::OpenEditStatus(qi, fi));
                                                }

                                                ui.colored_label(egui::Color32::GRAY, &feature.description);

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
                    self.quarters[qi].features.remove(fi);
                }
                if let Some((qi, fi)) = move_up_action {
                    if fi > 0 {
                        self.quarters[qi].features.swap(fi, fi - 1);
                    } else if qi > 0 {
                        let feature = self.quarters[qi].features.remove(fi);
                        self.quarters[qi - 1].features.push(feature);
                    }
                }
                if let Some((qi, fi)) = move_down_action {
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
                        DialogAction::OpenEditStatus(qi, fi) => {
                            self.dialog_state = DialogState::EditStatus {
                                quarter_idx: qi,
                                feature_idx: fi,
                            };
                        }
                    }
                }
            });
        });

        let mut close_dialog = false;
        let mut new_status = None;

        match &mut self.dialog_state {
            DialogState::AddFeature { quarter_idx, dialog } => {
                let qi = *quarter_idx;
                egui::Window::new("Add Feature").collapsible(false).resizable(false).show(ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(feat) = dialog.to_feature(&format!("f_{}", rand::random::<u64>())) {
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
                egui::Window::new("Edit Feature").collapsible(false).resizable(false).show(ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(feat) = dialog.to_feature(&existing_id) {
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

            DialogState::EditStatus { quarter_idx, feature_idx } => {
                let (qi, fi) = (*quarter_idx, *feature_idx);
                let mut status = self.quarters[qi].features[fi].status.clone();
                egui::Window::new("Edit Status").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.vertical(|ui| {
                        for s in &["Planned", "Developing", "Testing", "Completed"] {
                            if ui.radio(status == *s, *s).clicked() {
                                status = s.to_string();
                            }
                        }
                        ui.horizontal(|ui| {
                            if ui.button("OK").clicked() {
                                new_status = Some((qi, fi, status.clone()));
                                close_dialog = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close_dialog = true;
                            }
                        });
                    });
                });
            }
            DialogState::None => {}
        }

        if close_dialog {
            self.dialog_state = DialogState::None;
        }
        
        if let Some((qi, fi, status)) = new_status {
            self.quarters[qi].features[fi].status = status.clone();
            self.quarters[qi].features[fi].completed = status == "Completed";
            self.status_text = format!("Updated status to: {}", status);
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
            .with_title("allroads v1.1")
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
