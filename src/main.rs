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
CREATE TABLE IF NOT EXISTS org (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    owner_token TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_settings (
    org_id INTEGER PRIMARY KEY REFERENCES org(id) ON DELETE CASCADE,
    mode TEXT NOT NULL DEFAULT 'hierarchy',
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_owner (
    org_id INTEGER PRIMARY KEY REFERENCES org(id) ON DELETE CASCADE,
    owner_user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_chart (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    manager_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    report_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS org_chart_unique_link ON org_chart(org_id, manager_id, report_id);
CREATE TABLE IF NOT EXISTS task_assignment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feature_id TEXT NOT NULL REFERENCES feature(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'Assigned',
    assigned_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
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
    conn.execute_batch("CREATE TABLE IF NOT EXISTS org (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, owner_token TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").ok();
    conn.execute_batch("ALTER TABLE org ADD COLUMN owner_token TEXT NOT NULL DEFAULT ''").ok();
    conn.execute_batch("CREATE TABLE IF NOT EXISTS org_settings (org_id INTEGER PRIMARY KEY REFERENCES org(id) ON DELETE CASCADE, mode TEXT NOT NULL DEFAULT 'hierarchy', updated_at TEXT NOT NULL)").ok();
    conn.execute_batch("CREATE TABLE IF NOT EXISTS org_user (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE, display_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)").ok();
    conn.execute_batch("CREATE TABLE IF NOT EXISTS org_owner (org_id INTEGER PRIMARY KEY REFERENCES org(id) ON DELETE CASCADE, owner_user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE, created_at TEXT NOT NULL)").ok();
    conn.execute_batch("CREATE TABLE IF NOT EXISTS org_chart (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE, manager_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE, report_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE, created_at TEXT NOT NULL)").ok();
    conn.execute_batch("DELETE FROM org_chart WHERE id NOT IN (SELECT MIN(id) FROM org_chart GROUP BY org_id, manager_id, report_id)").ok();
    conn.execute_batch("CREATE UNIQUE INDEX IF NOT EXISTS org_chart_unique_link ON org_chart(org_id, manager_id, report_id)").ok();
    conn.execute_batch("UPDATE org_user SET role = 'lead' WHERE role = 'member' AND id IN (SELECT DISTINCT manager_id FROM org_chart)").ok();
    conn.execute_batch("CREATE TABLE IF NOT EXISTS task_assignment (id INTEGER PRIMARY KEY AUTOINCREMENT, feature_id TEXT NOT NULL REFERENCES feature(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'Assigned', assigned_at TEXT NOT NULL, updated_at TEXT NOT NULL)").ok();
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

fn db_list_orgs(conn: &Connection) -> Vec<Org> {
    let mut stmt = conn.prepare("SELECT id, name FROM org ORDER BY updated_at DESC").unwrap();
    let rows = stmt.query_map([], |row| {
        Ok(Org {
            id: row.get(0)?,
            name: row.get(1)?,
        })
    }).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_create_org(conn: &Connection, name: &str) -> i64 {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT INTO org (name, owner_token, created_at, updated_at) VALUES (?1, '', ?2, ?3)",
        rusqlite::params![name, now, now],
    ).unwrap();
    let org_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO org_user (org_id, display_name, role, created_at, updated_at) VALUES (?1, 'Owner', 'owner', ?2, ?3)",
        rusqlite::params![org_id, now, now],
    ).unwrap();
    let owner_user_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO org_owner (org_id, owner_user_id, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![org_id, owner_user_id, now],
    ).unwrap();
    conn.execute(
        "INSERT INTO org_settings (org_id, mode, updated_at) VALUES (?1, 'hierarchy', ?2)",
        rusqlite::params![org_id, now],
    ).unwrap();
    org_id
}

fn db_delete_org(conn: &Connection, id: i64) {
    conn.execute("DELETE FROM org WHERE id = ?1", rusqlite::params![id]).unwrap();
}

fn db_rename_org(conn: &Connection, id: i64, name: &str) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute("UPDATE org SET name = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![name, now, id]).unwrap();
}


fn db_load_org_users(conn: &Connection, org_id: i64) -> Vec<OrgUser> {
    let mut stmt = conn.prepare(
        "SELECT id, org_id, display_name, role, created_at, updated_at FROM org_user WHERE org_id = ?1 ORDER BY id",
    ).unwrap();
    let rows = stmt.query_map(rusqlite::params![org_id], |row| {
        Ok(OrgUser {
            id: row.get(0)?,
            org_id: row.get(1)?,
            display_name: row.get(2)?,
            role: row.get(3)?,
            created_at: row.get(4)?,
            updated_at: row.get(5)?,
        })
    }).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_add_org_user(conn: &Connection, org_id: i64, display_name: &str, role: &str) -> i64 {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT INTO org_user (org_id, display_name, role, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![org_id, display_name, role, now, now],
    ).unwrap();
    conn.last_insert_rowid()
}

fn db_update_org_user(conn: &Connection, user_id: i64, display_name: &str, role: &str) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "UPDATE org_user SET display_name = ?1, role = ?2, updated_at = ?3 WHERE id = ?4",
        rusqlite::params![display_name, role, now, user_id],
    ).unwrap();
}

fn db_promote_lead_if_needed(conn: &Connection, user_id: i64) {
    let role: Option<String> = conn.query_row(
        "SELECT role FROM org_user WHERE id = ?1",
        rusqlite::params![user_id],
        |row| row.get(0),
    ).ok();
    if let Some(role) = role {
        if role == "member" {
            let now = chrono::Local::now().to_rfc3339();
            conn.execute(
                "UPDATE org_user SET role = 'lead', updated_at = ?1 WHERE id = ?2",
                rusqlite::params![now, user_id],
            ).unwrap();
        }
    }
}

fn db_remove_org_user(conn: &Connection, user_id: i64, org_id: i64) {
    let reports: Vec<i64> = {
        let mut stmt = conn.prepare("SELECT report_id FROM org_chart WHERE manager_id = ?1").unwrap();
        stmt.query_map(rusqlite::params![user_id], |row| row.get(0)).unwrap()
            .filter_map(|r| r.ok()).collect()
    };
    let new_manager: Option<i64> = {
        let mut stmt = conn.prepare("SELECT manager_id FROM org_chart WHERE report_id = ?1").unwrap();
        stmt.query_row(rusqlite::params![user_id], |row| row.get(0)).ok()
    };
    if let Some(mgr) = new_manager {
        for rid in &reports {
            db_add_chart_link(conn, org_id, mgr, *rid);
        }
    }
    conn.execute("DELETE FROM org_chart WHERE manager_id = ?1 OR report_id = ?1", rusqlite::params![user_id]).unwrap();
    conn.execute("DELETE FROM task_assignment WHERE user_id = ?1", rusqlite::params![user_id]).unwrap();
    conn.execute("DELETE FROM org_user WHERE id = ?1", rusqlite::params![user_id]).unwrap();
}

fn db_load_org_chart(conn: &Connection, org_id: i64) -> Vec<OrgChartLink> {
    let mut stmt = conn.prepare(
        "SELECT id, org_id, manager_id, report_id, created_at FROM org_chart WHERE org_id = ?1 ORDER BY id",
    ).unwrap();
    let rows = stmt.query_map(rusqlite::params![org_id], |row| {
        Ok(OrgChartLink {
            id: row.get(0)?,
            org_id: row.get(1)?,
            manager_id: row.get(2)?,
            report_id: row.get(3)?,
            created_at: row.get(4)?,
        })
    }).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_add_chart_link(conn: &Connection, org_id: i64, manager_id: i64, report_id: i64) -> i64 {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT OR IGNORE INTO org_chart (org_id, manager_id, report_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![org_id, manager_id, report_id, now],
    ).unwrap();
    db_promote_lead_if_needed(conn, manager_id);
    conn.last_insert_rowid()
}

fn db_remove_chart_link(conn: &Connection, link_id: i64) {
    conn.execute("DELETE FROM org_chart WHERE id = ?1", rusqlite::params![link_id]).unwrap();
}

fn db_load_task_assignments(conn: &Connection, feature_id: &str) -> Vec<TaskAssignment> {
    let mut stmt = conn.prepare(
        "SELECT id, user_id FROM task_assignment WHERE feature_id = ?1",
    ).unwrap();
    let rows = stmt.query_map(rusqlite::params![feature_id], |row| {
        Ok(TaskAssignment {
            id: row.get(0)?,
            user_id: row.get(1)?,
        })
    }).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_assign_task(conn: &Connection, feature_id: &str, user_id: i64) -> i64 {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT INTO task_assignment (feature_id, user_id, status, assigned_at, updated_at) VALUES (?1, ?2, 'Assigned', ?3, ?4)",
        rusqlite::params![feature_id, user_id, now, now],
    ).unwrap();
    conn.last_insert_rowid()
}

fn db_unassign_task(conn: &Connection, assignment_id: i64) {
    conn.execute("DELETE FROM task_assignment WHERE id = ?1", rusqlite::params![assignment_id]).unwrap();
}

fn db_org_owner_id(conn: &Connection, org_id: i64) -> Option<i64> {
    conn.query_row(
        "SELECT owner_user_id FROM org_owner WHERE org_id = ?1",
        rusqlite::params![org_id],
        |row| row.get(0),
    ).ok()
}

fn db_update_org_owner(conn: &Connection, org_id: i64, new_owner_id: i64) {
    let old_owner_id = db_org_owner_id(conn, org_id);
    if old_owner_id == Some(new_owner_id) {
        return;
    }
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "UPDATE org_owner SET owner_user_id = ?1 WHERE org_id = ?2",
        rusqlite::params![new_owner_id, org_id],
    ).unwrap();
    conn.execute(
        "UPDATE org_user SET role = 'owner', updated_at = ?1 WHERE id = ?2",
        rusqlite::params![now, new_owner_id],
    ).unwrap();
    if let Some(old_id) = old_owner_id {
        conn.execute(
            "UPDATE org_user SET role = 'admin', updated_at = ?1 WHERE id = ?2",
            rusqlite::params![now, old_id],
        ).unwrap();
    }
}

fn db_load_org_settings(conn: &Connection, org_id: i64) -> OrgSettings {
    conn.query_row(
        "SELECT org_id, mode, updated_at FROM org_settings WHERE org_id = ?1",
        rusqlite::params![org_id],
        |row| {
            Ok(OrgSettings {
                org_id: row.get(0)?,
                mode: row.get(1)?,
                updated_at: row.get(2)?,
            })
        },
    ).unwrap_or(OrgSettings {
        org_id,
        mode: "hierarchy".to_string(),
        updated_at: String::new(),
    })
}

fn db_update_org_settings(conn: &Connection, org_id: i64, mode: &str) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "UPDATE org_settings SET mode = ?1, updated_at = ?2 WHERE org_id = ?3",
        rusqlite::params![mode, now, org_id],
    ).unwrap();
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

#[derive(Clone, Debug)]
struct Org {
    id: i64,
    name: String,
}

#[derive(Clone, Debug)]
struct OrgUser {
    id: i64,
    org_id: i64,
    display_name: String,
    role: String,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Debug)]
struct OrgChartLink {
    id: i64,
    org_id: i64,
    manager_id: i64,
    report_id: i64,
    created_at: String,
}

#[derive(Clone, Debug)]
struct TaskAssignment {
    id: i64,
    user_id: i64,
}

#[derive(Clone, Debug)]
struct OrgSettings {
    org_id: i64,
    mode: String,
    updated_at: String,
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

#[derive(Default)]
enum OrgDialogState {
    #[default]
    None,
    CreateOrg {
        name: String,
    },
    AddMember {
        display_name: String,
        role: String,
        report_to: Option<i64>,
    },
    EditMember {
        user_id: i64,
        display_name: String,
        role: String,
    },
    AddReport {
        manager_id: i64,
    },
    Settings {
        org_id: i64,
        name: String,
        owner_id: Option<i64>,
        mode: String,
        allow_edit: bool,
    },
}

#[derive(Clone)]
struct AppSnapshot {
    quarters: Vec<Quarter>,
    org_members: Vec<OrgUser>,
    org_chart_links: Vec<OrgChartLink>,
    org_settings: OrgSettings,
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
    undo_stack: Vec<AppSnapshot>,
    redo_stack: Vec<AppSnapshot>,
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
    org_list: Vec<Org>,
    current_org_id: Option<i64>,
    org_members: Vec<OrgUser>,
    org_chart_links: Vec<OrgChartLink>,
    org_settings: OrgSettings,
    org_dialog_state: OrgDialogState,
    org_chart_scroll: f32,
    org_chart_scroll_x: f32,
    org_chart_zoom: f32,
    org_selected_user_id: Option<i64>,
    show_org_list_dialog: bool,
    org_right_click_target: Option<i64>,
    org_right_click_pos: Option<egui::Pos2>,
    org_move_under_target: Option<i64>,
    task_assign_feature_id: Option<String>,
    task_assign_feature_title: String,
    task_assign_user_id: Option<i64>,
    task_assign_user_name: String,
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
        let org_list = db_list_orgs(&conn);
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
            org_list,
            current_org_id: None,
            org_members: Vec::new(),
            org_chart_links: Vec::new(),
            org_settings: OrgSettings {
                org_id: 0,
                mode: "hierarchy".into(),
                updated_at: String::new(),
            },
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
        };
        app.initialize_quarters();
        app.new_roadmap_name = "default".into();
        if let Some(first_org) = app.org_list.first() {
            app.current_org_id = Some(first_org.id);
            app.org_members = db_load_org_users(&app.db, first_org.id);
            app.org_chart_links = db_load_org_chart(&app.db, first_org.id);
            app.org_settings = db_load_org_settings(&app.db, first_org.id);
            app.org_selected_user_id = db_org_owner_id(&app.db, first_org.id);
        }
        Ok(app)
    }

    fn save_snapshot(&mut self) {
        self.undo_stack.push(AppSnapshot {
            quarters: self.quarters.clone(),
            org_members: self.org_members.clone(),
            org_chart_links: self.org_chart_links.clone(),
            org_settings: self.org_settings.clone(),
        });
        self.undo_stack.truncate(20);
        self.redo_stack.clear();
    }

    fn undo(&mut self) {
        if let Some(snapshot) = self.undo_stack.pop() {
            self.redo_stack.push(AppSnapshot {
                quarters: self.quarters.clone(),
                org_members: self.org_members.clone(),
                org_chart_links: self.org_chart_links.clone(),
                org_settings: self.org_settings.clone(),
            });
            self.quarters = snapshot.quarters;
            self.org_members = snapshot.org_members;
            self.org_chart_links = snapshot.org_chart_links;
            self.org_settings = snapshot.org_settings;
            self.restore_snapshot_to_db();
            self.status_text = "Undo Action".into();
        }
    }

    fn redo(&mut self) {
        if let Some(snapshot) = self.redo_stack.pop() {
            self.undo_stack.push(AppSnapshot {
                quarters: self.quarters.clone(),
                org_members: self.org_members.clone(),
                org_chart_links: snapshot.org_chart_links.clone(),
                org_settings: self.org_settings.clone(),
            });
            self.quarters = snapshot.quarters;
            self.org_members = snapshot.org_members;
            self.org_chart_links = snapshot.org_chart_links;
            self.org_settings = snapshot.org_settings;
            self.restore_snapshot_to_db();
            self.status_text = "Redo Action".into();
        }
    }

    fn restore_snapshot_to_db(&self) {
        if let Some(org_id) = self.current_org_id {
            self.db.execute("DELETE FROM org_chart WHERE org_id = ?1", rusqlite::params![org_id]).ok();
            for link in &self.org_chart_links {
                self.db.execute(
                    "INSERT OR IGNORE INTO org_chart (id, org_id, manager_id, report_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![link.id, link.org_id, link.manager_id, link.report_id, link.created_at],
                ).ok();
            }
            let existing_ids: std::collections::HashSet<i64> = {
                let mut stmt = self.db.prepare("SELECT id FROM org_user WHERE org_id = ?1").unwrap();
                stmt.query_map(rusqlite::params![org_id], |row| row.get(0)).unwrap()
                    .filter_map(|r| r.ok()).collect()
            };
            let snapshot_ids: std::collections::HashSet<i64> = self.org_members.iter().map(|m| m.id).collect();
            for &id in existing_ids.difference(&snapshot_ids) {
                self.db.execute("DELETE FROM org_user WHERE id = ?1", rusqlite::params![id]).ok();
            }
            for m in &self.org_members {
                if !existing_ids.contains(&m.id) {
                    self.db.execute(
                        "INSERT INTO org_user (id, org_id, display_name, role, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![m.id, m.org_id, m.display_name, m.role, m.created_at, m.updated_at],
                    ).ok();
                } else {
                    self.db.execute(
                        "UPDATE org_user SET display_name = ?1, role = ?2, updated_at = ?3 WHERE id = ?4",
                        rusqlite::params![m.display_name, m.role, m.updated_at, m.id],
                    ).ok();
                }
            }
            if self.org_settings.org_id == org_id {
                self.db.execute(
                    "UPDATE org_settings SET mode = ?1, updated_at = ?2 WHERE org_id = ?3",
                    rusqlite::params![self.org_settings.mode, self.org_settings.updated_at, org_id],
                ).ok();
            }
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
                self.current_tab = "Org Chart".into();
            } else if self.current_tab == "Org Chart" {
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
        let has_features = self.quarters.iter().any(|q| !q.features.is_empty());
        if !has_features {
            self.status_text = "No features to save".into();
            return;
        }
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
                        if ui.button("Switch").clicked() {
                            self.show_org_list_dialog = true;
                            ui.close_menu();
                        }
                        if ui.button("Create").clicked() {
                            self.org_dialog_state = OrgDialogState::CreateOrg { name: String::new() };
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Join").clicked() {
                            self.status_text = "Join requires sync (paid version)".into();
                            ui.close_menu();
                        }
                        if ui.button("Settings").clicked() {
                            if let Some(org_id) = self.current_org_id {
                                let owner_id = db_org_owner_id(&self.db, org_id);
                                let allow_edit = owner_id.is_some();
                                self.org_selected_user_id = owner_id;
                                let org_name = self.org_list.iter().find(|o| o.id == org_id).map(|o| o.name.clone()).unwrap_or_default();
                                let settings = db_load_org_settings(&self.db, org_id);
                                self.org_dialog_state = OrgDialogState::Settings {
                                    org_id,
                                    name: org_name,
                                    owner_id,
                                    mode: settings.mode,
                                    allow_edit,
                                };
                            } else {
                                self.status_text = "No organization selected".into();
                            }
                            ui.close_menu();
                        }
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
                    ui.colored_label(egui::Color32::GRAY, "v1.3.0");
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
                                            let feature_id = feature.id.clone();
                                            let feature_title = feature.title.clone();
                                            let response = ui.allocate_ui(egui::vec2(available, 36.0), |ui| {
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
                                            }).response;
                                            response.context_menu(|ui| {
                                                if ui.button("Assign Tasks").clicked() {
                                                    self.task_assign_feature_id = Some(feature_id.clone());
                                                    self.task_assign_feature_title = feature_title.clone();
                                                    ui.close_menu();
                                                }
                                            });
                                        });
                                    }
                                });
                            });
                        ui.add_space(8.0);
                    }

                    if let Some(qi) = quarter_remove_idx {
                        self.save_snapshot();
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
                        ui.label("No quarters to show. Save a roadmap to view here.");
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
            } else if self.current_tab == "Org Chart" {
                if self.org_list.is_empty() {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.label("No organization created yet.");
                        ui.add_space(8.0);
                        if ui.button("Create Organization").clicked() {
                            self.org_dialog_state = OrgDialogState::CreateOrg { name: String::new() };
                        }
                    });
                } else {
                    let current_org_name = self.org_list.iter()
                        .find(|o| Some(o.id) == self.current_org_id)
                        .map(|o| o.name.clone())
                        .unwrap_or_default();

                    let owner_id = self.current_org_id.and_then(|oid| db_org_owner_id(&self.db, oid));

                    ui.horizontal(|ui| {
                        ui.heading(&current_org_name);
                        ui.add_space(8.0);
                        if ui.small_button("Switch Org").clicked() {
                            self.show_org_list_dialog = true;
                        }
                        if ui.small_button("+ Member").clicked() {
                            self.org_dialog_state = OrgDialogState::AddMember {
                                display_name: String::new(),
                                role: "member".to_string(),
                                report_to: None,
                            };
                        }
                        if ui.small_button("+ Link").clicked() {
                            if self.org_selected_user_id.is_some() {
                                self.org_dialog_state = OrgDialogState::AddReport {
                                    manager_id: self.org_selected_user_id.unwrap(),
                                };
                            } else {
                                self.status_text = "Select a manager first".into();
                            }
                        }
                        if ui.small_button("Settings").clicked() {
                            if let Some(org_id) = self.current_org_id {
                                let allow_edit = owner_id.is_some();
                                self.org_selected_user_id = owner_id;
                                let org_name = self.org_list.iter().find(|o| o.id == org_id).map(|o| o.name.clone()).unwrap_or_default();
                                let owner_id = db_org_owner_id(&self.db, org_id);
                                let settings = db_load_org_settings(&self.db, org_id);
                                self.org_dialog_state = OrgDialogState::Settings {
                                    org_id,
                                    name: org_name,
                                    owner_id,
                                    mode: settings.mode,
                                    allow_edit,
                                };
                            }
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("+ Org").clicked() {
                                self.org_dialog_state = OrgDialogState::CreateOrg { name: String::new() };
                            }
                        });
                    });
                    ui.separator();

                    if self.org_members.is_empty() {
                        ui.vertical_centered(|ui| {
                            ui.add_space(40.0);
                            ui.label("No members. Add someone to get started.");
                        });
                    } else {
                        let user_map: std::collections::HashMap<i64, OrgUser> = self.org_members.iter().map(|m| (m.id, m.clone())).collect();

                        let node_w: f32 = 160.0;
                        let node_h: f32 = 48.0;
                        let h_gap: f32 = 24.0;
                        let v_gap: f32 = 64.0;
                        let mut positions: Vec<(i64, f32, f32)> = Vec::new();
                        let mut unlinked: Vec<i64> = Vec::new();
                        let mut draw_links = true;

                        let is_flat = self.org_settings.mode == "flat";
                        if is_flat {
                            draw_links = false;
                            let count = self.org_members.len();
                            if count > 0 {
                                let radius = ((count as f32) * (node_w + h_gap)) / (2.0 * std::f32::consts::PI);
                                let radius = radius.max(node_w * 1.5);
                                for (idx, member) in self.org_members.iter().enumerate() {
                                    let angle = (idx as f32) * std::f32::consts::TAU / (count as f32);
                                    let x = radius * angle.cos();
                                    let y = radius * angle.sin();
                                    positions.push((member.id, x, y));
                                }
                            }
                        } else {
                            let reports_of: std::collections::HashMap<i64, Vec<i64>> = {
                                let mut map: std::collections::HashMap<i64, Vec<i64>> = std::collections::HashMap::new();
                                for link in &self.org_chart_links {
                                    let entry = map.entry(link.manager_id).or_default();
                                    if !entry.contains(&link.report_id) {
                                        entry.push(link.report_id);
                                    }
                                }
                                map
                            };
                            let is_report: std::collections::HashSet<i64> = self.org_chart_links.iter().map(|l| l.report_id).collect();

                            let linked_ids: std::collections::HashSet<i64> = {
                                let mut set = std::collections::HashSet::new();
                                for link in &self.org_chart_links {
                                    set.insert(link.manager_id);
                                    set.insert(link.report_id);
                                }
                                if let Some(oid) = owner_id {
                                    set.insert(oid);
                                }
                                set
                            };

                            unlinked = self.org_members.iter()
                                .filter(|m| !linked_ids.contains(&m.id))
                                .map(|m| m.id)
                                .collect();

                            let roots: Vec<i64> = if let Some(oid) = owner_id {
                                vec![oid]
                            } else {
                                self.org_members.iter()
                                    .filter(|m| !is_report.contains(&m.id))
                                    .map(|m| m.id)
                                    .collect()
                            };

                            fn subtree_width(id: i64, reports_of: &std::collections::HashMap<i64, Vec<i64>>, nw: f32, hg: f32) -> f32 {
                                let children = reports_of.get(&id).cloned().unwrap_or_default();
                                if children.is_empty() { return nw; }
                                let cw: f32 = children.iter().map(|c| subtree_width(*c, reports_of, nw, hg)).sum::<f32>() + hg * (children.len().max(1) - 1) as f32;
                                cw.max(nw)
                            }

                            fn layout_tree(
                                id: i64,
                                x: f32,
                                y: f32,
                                reports_of: &std::collections::HashMap<i64, Vec<i64>>,
                                positions: &mut Vec<(i64, f32, f32)>,
                                nw: f32, nh: f32, vg: f32, hg: f32,
                            ) {
                                let children = reports_of.get(&id).cloned().unwrap_or_default();
                                if children.is_empty() {
                                    let w = subtree_width(id, reports_of, nw, hg);
                                    positions.push((id, x + w / 2.0, y));
                                } else {
                                    let mut cx = x;
                                    for child in &children {
                                        let cw = subtree_width(*child, reports_of, nw, hg);
                                        layout_tree(*child, cx, y + nh + vg, reports_of, positions, nw, nh, vg, hg);
                                        cx += cw + hg;
                                    }
                                    let cset: std::collections::HashSet<i64> = children.into_iter().collect();
                                    let leftmost = positions.iter().filter(|(c, _, _)| cset.contains(c)).map(|(_, px, _)| *px).fold(f32::INFINITY, f32::min);
                                    let rightmost = positions.iter().filter(|(c, _, _)| cset.contains(c)).map(|(_, px, _)| *px).fold(f32::NEG_INFINITY, f32::max);
                                    positions.push((id, (leftmost + rightmost) / 2.0, y));
                                }
                            }

                            let mut ox = 0.0_f32;
                            for root_id in &roots {
                                let w = subtree_width(*root_id, &reports_of, node_w, h_gap);
                                layout_tree(*root_id, ox, 0.0, &reports_of, &mut positions, node_w, node_h, v_gap, h_gap);
                                ox += w + h_gap;
                            }
                            for (i, uid) in unlinked.iter().enumerate() {
                                positions.push((*uid, ox + (i as f32) * (node_w + h_gap) + node_w / 2.0, 0.0));
                            }
                        }

                        if positions.is_empty() {
                            return;
                        }

                        let tree_min_x = positions.iter().map(|(_, x, _)| *x).fold(f32::INFINITY, f32::min);
                        let tree_max_x = positions.iter().map(|(_, x, _)| *x).fold(f32::NEG_INFINITY, f32::max);
                        let tree_max_y = positions.iter().map(|(_, _, y)| *y).fold(f32::NEG_INFINITY, f32::max);

                        let owner_cx = if let Some(oid) = owner_id {
                            positions.iter().find(|(id, _, _)| *id == oid).map(|(_, x, _)| *x).unwrap_or((tree_min_x + tree_max_x) / 2.0)
                        } else {
                            (tree_min_x + tree_max_x) / 2.0
                        };

                        if !ui.input(|i| i.pointer.primary_down()) {
                            let sd = ui.input(|i| i.raw_scroll_delta);
                            self.org_chart_scroll -= sd.y * 0.8;
                            self.org_chart_scroll_x += sd.x * 0.8;
                            let zoom_delta = ui.input(|i| i.zoom_delta());
                            if zoom_delta != 1.0 {
                                self.org_chart_zoom = (self.org_chart_zoom * zoom_delta).clamp(0.3, 5.0);
                            }
                        }
                        ui.ctx().input(|i| {
                            for ev in &i.raw.events {
                                if let egui::Event::MouseWheel { delta, .. } = ev {
                                    self.org_chart_scroll -= delta.y * 0.8;
                                    self.org_chart_scroll_x += delta.x * 0.8;
                                }
                            }
                        });

                        let zoom = self.org_chart_zoom;
                        let (response, painter) = ui.allocate_painter(
                            ui.available_size(),
                            egui::Sense::click(),
                        );
                        let rect = response.rect;
                        let view_cx = rect.center().x;
                        let view_top = rect.top() + 30.0;

                        let total_h = (tree_max_y + node_h + 60.0) * zoom;
                        let scroll_limit_y = ((total_h - rect.height()) / 2.0).max(0.0) + 50.0;
                        self.org_chart_scroll = self.org_chart_scroll.clamp(-scroll_limit_y, scroll_limit_y);

                        let total_w = (tree_max_x - tree_min_x + node_w + 40.0) * zoom;
                        let scroll_limit_x = (((total_w - rect.width()) / 2.0).max(0.0) + 50.0) * 3.0;
                        self.org_chart_scroll_x = self.org_chart_scroll_x.clamp(-scroll_limit_x, scroll_limit_x);

                        let (ox, oy) = if is_flat {
                            (
                                rect.center().x + self.org_chart_scroll_x,
                                rect.center().y - (node_h * zoom * 0.5) - self.org_chart_scroll,
                            )
                        } else {
                            (
                                view_cx - owner_cx * zoom + self.org_chart_scroll_x,
                                view_top - self.org_chart_scroll,
                            )
                        };

                        if draw_links {
                            for link in &self.org_chart_links {
                                if let (Some((_, mx, my)), Some((_, rx, ry))) = (
                                    positions.iter().find(|(id, _, _)| *id == link.manager_id),
                                    positions.iter().find(|(id, _, _)| *id == link.report_id),
                                ) {
                                    let x1 = ox + mx * zoom;
                                    let y1 = oy + my * zoom + node_h * zoom;
                                    let x2 = ox + rx * zoom;
                                    let y2 = oy + ry * zoom;
                                    let mid = y1 + (y2 - y1) / 2.0;
                                    painter.line_segment([egui::pos2(x1, y1), egui::pos2(x1, mid)], egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(120, 120, 120)));
                                    painter.line_segment([egui::pos2(x1, mid), egui::pos2(x2, mid)], egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(120, 120, 120)));
                                    painter.line_segment([egui::pos2(x2, mid), egui::pos2(x2, y2)], egui::Stroke::new(1.5_f32, egui::Color32::from_rgb(120, 120, 120)));
                                }
                            }
                        } else {
                            let stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(90, 90, 90));
                            for i in 0..positions.len() {
                                for j in (i + 1)..positions.len() {
                                    let (_, x1, y1) = positions[i];
                                    let (_, x2, y2) = positions[j];
                                    let p1 = egui::pos2(ox + x1 * zoom, oy + y1 * zoom + node_h * zoom * 0.5);
                                    let p2 = egui::pos2(ox + x2 * zoom, oy + y2 * zoom + node_h * zoom * 0.5);
                                    painter.line_segment([p1, p2], stroke);
                                }
                            }
                        }

                        for (uid, px, py) in &positions {
                            if let Some(user) = user_map.get(uid) {
                                let nw = node_w * zoom;
                                let nh = node_h * zoom;
                                let cx = ox + px * zoom - nw / 2.0;
                                let cy = oy + py * zoom;
                                let nr = egui::Rect::from_min_max(egui::pos2(cx, cy), egui::pos2(cx + nw, cy + nh));

                                let is_selected = self.org_selected_user_id == Some(*uid);
                                let is_owner = user.role == "owner";
                                let is_unlinked = unlinked.contains(uid);
                                let bg = if is_selected {
                                    egui::Color32::from_rgb(50, 70, 100)
                                } else if is_owner {
                                    egui::Color32::from_rgb(60, 50, 30)
                                } else if is_unlinked {
                                    egui::Color32::from_rgb(35, 35, 40)
                                } else {
                                    egui::Color32::from_rgb(45, 45, 50)
                                };
                                let border = if is_owner {
                                    egui::Color32::from_rgb(255, 193, 7)
                                } else if is_selected {
                                    egui::Color32::from_rgb(100, 150, 255)
                                } else if is_unlinked {
                                    egui::Color32::from_rgb(60, 60, 60)
                                } else {
                                    egui::Color32::from_rgb(80, 80, 80)
                                };

                                painter.rect_filled(nr, 4.0 * zoom, bg);
                                painter.rect_stroke(nr, 4.0 * zoom, egui::Stroke::new(1.0_f32, border));

                                painter.text(
                                    egui::pos2(cx + nw / 2.0, cy + nh * 0.3),
                                    egui::Align2::CENTER_CENTER,
                                    &user.display_name,
                                    egui::FontId::proportional(13.0 * zoom),
                                    egui::Color32::WHITE,
                                );

                                let role_color = if is_owner {
                                    egui::Color32::from_rgb(255, 193, 7)
                                } else if user.role == "member" {
                                    egui::Color32::from_rgb(180, 180, 180)
                                } else {
                                    egui::Color32::from_rgb(76, 175, 80)
                                };
                                painter.text(
                                    egui::pos2(cx + nw / 2.0, cy + nh * 0.7),
                                    egui::Align2::CENTER_CENTER,
                                    &user.role,
                                    egui::FontId::proportional(10.0 * zoom),
                                    role_color,
                                );

                                if response.clicked() {
                                    if let Some(pos) = response.hover_pos() {
                                        if nr.contains(pos) {
                                            self.org_selected_user_id = Some(*uid);
                                        }
                                    }
                                }
                                if response.secondary_clicked() {
                                    if let Some(pos) = response.hover_pos() {
                                        if nr.contains(pos) {
                                            self.org_right_click_target = Some(*uid);
                                            self.org_right_click_pos = Some(pos);
                                            self.org_selected_user_id = Some(*uid);
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(rc_uid) = self.org_right_click_target {
                            let mut close_menu = false;
                            let menu_pos = self.org_right_click_pos.unwrap_or(egui::pos2(0.0, 0.0));

                            egui::Area::new(egui::Id::new("org_ctx_menu"))
                                .fixed_pos(menu_pos)
                                .order(egui::Order::Foreground)
                                .show(ui.ctx(), |ui| {
                                    egui::Frame::popup(ui.style()).show(ui, |ui| {
                                        ui.set_min_width(200.0);
                                        let rc_user = self.org_members.iter().find(|m| m.id == rc_uid).cloned();
                                        let rc_name = rc_user.as_ref().map(|u| u.display_name.clone()).unwrap_or_default();
                                        let rc_role = rc_user.as_ref().map(|u| u.role.clone()).unwrap_or_default();
                                        let is_owner = rc_role == "owner";

                                        ui.label(egui::RichText::new(&rc_name).strong());
                                        ui.colored_label(egui::Color32::GRAY, format!("Role: {}", rc_role));
                                        ui.separator();

                                        if ui.button("Edit Name / Role").clicked() {
                                            self.org_dialog_state = OrgDialogState::EditMember {
                                                user_id: rc_uid,
                                                display_name: rc_name.clone(),
                                                role: rc_role,
                                            };
                                            close_menu = true;
                                        }

                                        if ui.button("Add Report Under").clicked() {
                                            self.org_dialog_state = OrgDialogState::AddReport {
                                                manager_id: rc_uid,
                                            };
                                            close_menu = true;
                                        }

                                        if ui.button("Assign Tasks").clicked() {
                                            self.task_assign_user_id = Some(rc_uid);
                                            self.task_assign_user_name = rc_name.clone();
                                            close_menu = true;
                                        }

                                        if ui.button("Move Under...").clicked() {
                                            self.org_move_under_target = Some(rc_uid);
                                            close_menu = true;
                                        }

                                        let managed: Vec<i64> = self.org_chart_links.iter()
                                            .filter(|l| l.manager_id == rc_uid)
                                            .map(|l| l.report_id)
                                            .collect();
                                        if !managed.is_empty() {
                                            ui.separator();
                                            ui.colored_label(egui::Color32::GRAY, "Direct Reports:");
                                            for rid in &managed {
                                                if let Some(name) = user_map.get(rid).map(|u| u.display_name.clone()) {
                                                    ui.horizontal(|ui| {
                                                        ui.label(&name);
                                                        if ui.small_button("Unlink").clicked() {
                                                            let link_id = self.org_chart_links.iter().find(|l| l.manager_id == rc_uid && l.report_id == *rid).map(|l| l.id);
                                                            if let Some(link_id) = link_id {
                                                                self.save_snapshot();
                                                                db_remove_chart_link(&self.db, link_id);
                                                                self.org_chart_links = self.current_org_id.map_or(Vec::new(), |oid| db_load_org_chart(&self.db, oid));
                                                            }
                                                            close_menu = true;
                                                        }
                                                    });
                                                }
                                            }
                                        }

                                        let reports_to: Option<i64> = self.org_chart_links.iter()
                                            .find(|l| l.report_id == rc_uid)
                                            .map(|l| l.manager_id);
                                        if let Some(mgr_id) = reports_to {
                                            if let Some(mgr_name) = user_map.get(&mgr_id).map(|u| u.display_name.clone()) {
                                                ui.separator();
                                                ui.horizontal(|ui| {
                                                    ui.label(format!("Reports to: {}", mgr_name));
                                                    if ui.small_button("Unlink").clicked() {
                                                        let link_id = self.org_chart_links.iter().find(|l| l.report_id == rc_uid).map(|l| l.id);
                                                        if let Some(link_id) = link_id {
                                                            self.save_snapshot();
                                                            db_remove_chart_link(&self.db, link_id);
                                                            self.org_chart_links = self.current_org_id.map_or(Vec::new(), |oid| db_load_org_chart(&self.db, oid));
                                                        }
                                                        close_menu = true;
                                                    }
                                                });
                                            }
                                        }

                                        if !is_owner {
                                            ui.separator();
                                            ui.colored_label(egui::Color32::from_rgb(220, 80, 80), "Danger");
                                            if ui.button("Remove Member").clicked() {
                                                self.save_snapshot();
                                                db_remove_org_user(&self.db, rc_uid, self.current_org_id.unwrap_or(0));
                                                self.org_members = self.current_org_id.map_or(Vec::new(), |oid| db_load_org_users(&self.db, oid));
                                                self.org_chart_links = self.current_org_id.map_or(Vec::new(), |oid| db_load_org_chart(&self.db, oid));
                                                self.org_selected_user_id = None;
                                                self.status_text = "Removed member".into();
                                                close_menu = true;
                                            }
                                        }

                                        ui.separator();
                                        if ui.button("Close").clicked() {
                                            close_menu = true;
                                        }
                                    });
                                });

                            let menu_area = ui.ctx().memory(|m| m.area_rect(egui::Id::new("org_ctx_menu")));
                            if let Some(mr) = menu_area {
                                let mouse = ui.ctx().input(|i| i.pointer.latest_pos().unwrap_or(egui::pos2(-9999.0, -9999.0)));
                                let anchor = self.org_right_click_pos.unwrap_or(egui::pos2(-9999.0, -9999.0));
                                if !mr.contains(mouse) && ((mouse.x - anchor.x).abs() > 80.0 || (mouse.y - anchor.y).abs() > 80.0) {
                                    close_menu = true;
                                }
                            }

                            if close_menu || ui.ctx().input(|i| i.pointer.primary_clicked()) {
                                self.org_right_click_target = None;
                            }
                        }

                        if let Some(move_uid) = self.org_move_under_target {
                            let mut close_move = false;
                            let move_name = self.org_members.iter().find(|m| m.id == move_uid).map(|m| m.display_name.clone()).unwrap_or_default();
                            let candidates: Vec<(i64, String)> = self.org_members.iter()
                                .filter(|m| m.id != move_uid)
                                .map(|m| (m.id, m.display_name.clone()))
                                .collect();
                            egui::Window::new(format!("Move {} under...", move_name)).collapsible(false).resizable(false).show(ctx, |ui| {
                                if candidates.is_empty() {
                                    ui.colored_label(egui::Color32::GRAY, "No other members.");
                                }
                                for c in &candidates {
                                    if ui.button(&c.1).clicked() {
                                        if let Some(org_id) = self.current_org_id {
                                            let old_link_id = self.org_chart_links.iter().find(|l| l.report_id == move_uid).map(|l| l.id);
                                            self.save_snapshot();
                                            if let Some(old_link_id) = old_link_id {
                                                db_remove_chart_link(&self.db, old_link_id);
                                            }
                                            if !self.org_chart_links.iter().any(|l| l.manager_id == c.0 && l.report_id == move_uid) {
                                                db_add_chart_link(&self.db, org_id, c.0, move_uid);
                                            }
                                            self.org_chart_links = db_load_org_chart(&self.db, org_id);
                                            self.org_members = db_load_org_users(&self.db, org_id);
                                            self.status_text = format!("Moved {} under {}", move_name, c.1);
                                        }
                                        close_move = true;
                                    }
                                }
                                ui.separator();
                                if ui.button("Cancel").clicked() {
                                    close_move = true;
                                }
                            });
                            if close_move {
                                self.org_move_under_target = None;
                            }
                        }

                        ui.separator();
                        ui.horizontal(|ui| {
                            if let Some(uid) = self.org_selected_user_id {
                                if let Some(user) = self.org_members.iter().find(|m| m.id == uid) {
                                    ui.label(egui::RichText::new(&user.display_name).strong());
                                    ui.colored_label(egui::Color32::GRAY, format!("[{}]", user.role));
                                }
                            } else {
                                ui.colored_label(egui::Color32::GRAY, "Click a node to select · Right-click for actions");
                            }
                        });
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
                            self.undo_stack.push(AppSnapshot {
                                quarters: self.quarters.clone(),
                                org_members: self.org_members.clone(),
                                org_chart_links: self.org_chart_links.clone(),
                                org_settings: self.org_settings.clone(),
                            });
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
                            self.undo_stack.push(AppSnapshot {
                                quarters: self.quarters.clone(),
                                org_members: self.org_members.clone(),
                                org_chart_links: self.org_chart_links.clone(),
                                org_settings: self.org_settings.clone(),
                            });
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

        enum OrgAction {
            CreateOrg { name: String },
            AddMember { display_name: String, role: String, report_to: Option<i64> },
            EditMember { user_id: i64, display_name: String, role: String },
            AddReport { manager_id: i64, report_id: i64, report_name: String },
            UpdateSettings { org_id: i64, name: String, owner_id: Option<i64>, mode: String },
        }

        let mut close_org_dialog = false;
        let mut org_action: Option<OrgAction> = None;
        match &mut self.org_dialog_state {
            OrgDialogState::CreateOrg { name } => {
                egui::Window::new("Create Organization").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.label("Organization name:");
                    ui.text_edit_singleline(name);
                    ui.horizontal(|ui| {
                        if ui.button("Create").clicked() {
                            if !name.trim().is_empty() {
                                org_action = Some(OrgAction::CreateOrg { name: name.trim().to_string() });
                            }
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::AddMember { display_name, role, report_to } => {
                let members_snapshot = self.org_members.clone();
                egui::Window::new("Add Member").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.label("Display name:");
                    ui.text_edit_singleline(display_name);
                    ui.label("Role:");
                    let roles = ["member", "lead", "admin"];
                    for r in &roles {
                        if ui.radio(*role == *r, *r).clicked() {
                            *role = r.to_string();
                        }
                    }
                    ui.label("Reports to:");
                    let current_name = report_to.and_then(|id| members_snapshot.iter().find(|m| m.id == id).map(|m| m.display_name.clone())).unwrap_or_else(|| "Owner (default)".to_string());
                    egui::ComboBox::from_id_salt("report_to_select")
                        .selected_text(&current_name)
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(report_to.is_none(), "Owner (default)").clicked() {
                                *report_to = None;
                            }
                            if ui.selectable_label(false, "None (unlinked)").clicked() {
                                *report_to = None;
                            }
                            for m in &members_snapshot {
                                if ui.selectable_label(*report_to == Some(m.id), &m.display_name).clicked() {
                                    *report_to = Some(m.id);
                                }
                            }
                        });
                    ui.horizontal(|ui| {
                        if ui.button("Add").clicked() {
                            if !display_name.trim().is_empty() {
                                org_action = Some(OrgAction::AddMember {
                                    display_name: display_name.trim().to_string(),
                                    role: role.clone(),
                                    report_to: *report_to,
                                });
                            }
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::EditMember { user_id, display_name, role } => {
                let uid = *user_id;
                egui::Window::new("Edit Member").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.label("Display name:");
                    ui.text_edit_singleline(display_name);
                    ui.label("Role:");
                    let roles = ["member", "lead", "admin", "owner"];
                    for r in &roles {
                        if ui.radio(*role == *r, *r).clicked() {
                            *role = r.to_string();
                        }
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            if !display_name.trim().is_empty() {
                                org_action = Some(OrgAction::EditMember {
                                    user_id: uid,
                                    display_name: display_name.trim().to_string(),
                                    role: role.clone(),
                                });
                            }
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::AddReport { manager_id } => {
                let mgr = *manager_id;
                let candidates: Vec<(i64, String)> = self.org_members.iter()
                    .filter(|m| m.id != mgr)
                    .filter(|m| !self.org_chart_links.iter().any(|l| l.manager_id == mgr && l.report_id == m.id))
                    .map(|m| (m.id, m.display_name.clone()))
                    .collect();
                let mgr_name = self.org_members.iter().find(|m| m.id == mgr).map(|m| m.display_name.clone()).unwrap_or_default();
                egui::Window::new(format!("Add Report under {}", mgr_name)).collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.label("Select a member to report to this manager:");
                    for user in &candidates {
                        let name = user.1.clone();
                        if ui.button(&name).clicked() {
                            org_action = Some(OrgAction::AddReport { manager_id: mgr, report_id: user.0, report_name: name });
                            close_org_dialog = true;
                        }
                    }
                    if candidates.is_empty() {
                        ui.colored_label(egui::Color32::GRAY, "No available members to add.");
                    }
                    ui.separator();
                    if ui.button("Cancel").clicked() {
                        close_org_dialog = true;
                    }
                });
            }
            OrgDialogState::Settings { org_id, name, owner_id, mode, allow_edit } => {
                let can_edit = *allow_edit;
                let members_snapshot = self.org_members.clone();
                let org_settings_snapshot: Vec<(i64, String, Option<i64>, String)> = self.org_list.iter()
                    .map(|org| {
                        let settings = db_load_org_settings(&self.db, org.id);
                        (org.id, org.name.clone(), db_org_owner_id(&self.db, org.id), settings.mode)
                    })
                    .collect();
                egui::Window::new("Organization Settings").collapsible(false).resizable(false).show(ctx, |ui| {
                    ui.label("Organization:");
                    egui::ComboBox::from_id_salt("org_settings_select")
                        .selected_text(name.as_str())
                        .show_ui(ui, |ui| {
                            for (oid, oname, oowner, omode) in &org_settings_snapshot {
                                if ui.selectable_label(*oid == *org_id, oname).clicked() {
                                    *org_id = *oid;
                                    *name = oname.clone();
                                    *owner_id = *oowner;
                                    *mode = omode.clone();
                                    *allow_edit = owner_id.is_some();
                                }
                            }
                        });
                    ui.separator();
                    ui.label("Organization name:");
                    ui.add_enabled_ui(can_edit, |ui| {
                        ui.text_edit_singleline(name);
                    });
                    ui.label("Owner:");
                    ui.add_enabled_ui(can_edit, |ui| {
                        let current_owner = owner_id.and_then(|id| members_snapshot.iter().find(|m| m.id == id).map(|m| m.display_name.clone())).unwrap_or_else(|| "Owner".to_string());
                        egui::ComboBox::from_id_salt("org_settings_owner")
                            .selected_text(current_owner)
                            .show_ui(ui, |ui| {
                                for member in &members_snapshot {
                                    if ui.selectable_label(Some(member.id) == *owner_id, &member.display_name).clicked() {
                                        *owner_id = Some(member.id);
                                    }
                                }
                            });
                    });
                    ui.label("Org chart mode:");
                    ui.add_enabled_ui(can_edit, |ui| {
                        if ui.radio(mode.as_str() == "hierarchy", "Hierarchical").clicked() {
                            *mode = "hierarchy".to_string();
                        }
                        if ui.radio(mode.as_str() == "flat", "Non hierarchical").clicked() {
                            *mode = "flat".to_string();
                        }
                    });
                    if !can_edit {
                        ui.colored_label(egui::Color32::GRAY, "Only the owner can change settings.");
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            if can_edit {
                                org_action = Some(OrgAction::UpdateSettings {
                                    org_id: *org_id,
                                    name: name.trim().to_string(),
                                    owner_id: *owner_id,
                                    mode: mode.clone(),
                                });
                            }
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::None => {}
        }
        if let Some(action) = org_action {
            match action {
                OrgAction::CreateOrg { name } => {
                    self.save_snapshot();
                    let id = db_create_org(&self.db, name.trim());
                    self.org_list = db_list_orgs(&self.db);
                    self.current_org_id = Some(id);
                    self.org_members = db_load_org_users(&self.db, id);
                    self.org_chart_links = db_load_org_chart(&self.db, id);
                    self.org_settings = db_load_org_settings(&self.db, id);
                    self.status_text = format!("Created org: {}", name.trim());
                }
                OrgAction::AddMember { display_name, role, report_to } => {
                    if let Some(org_id) = self.current_org_id {
                        self.save_snapshot();
                        let new_user_id = db_add_org_user(&self.db, org_id, display_name.trim(), &role);
                        let manager = report_to.or_else(|| db_org_owner_id(&self.db, org_id));
                        if let Some(mgr_id) = manager {
                            if mgr_id != new_user_id {
                                db_add_chart_link(&self.db, org_id, mgr_id, new_user_id);
                            }
                        }
                        self.org_members = db_load_org_users(&self.db, org_id);
                        self.org_chart_links = db_load_org_chart(&self.db, org_id);
                        self.status_text = format!("Added member: {}", display_name.trim());
                    }
                }
                OrgAction::EditMember { user_id, display_name, role } => {
                    self.save_snapshot();
                    db_update_org_user(&self.db, user_id, display_name.trim(), &role);
                    if let Some(org_id) = self.current_org_id {
                        self.org_members = db_load_org_users(&self.db, org_id);
                    }
                    self.status_text = format!("Updated member: {}", display_name.trim());
                }
                OrgAction::AddReport { manager_id, report_id, report_name } => {
                    if let Some(org_id) = self.current_org_id {
                        self.save_snapshot();
                        db_add_chart_link(&self.db, org_id, manager_id, report_id);
                        self.org_chart_links = db_load_org_chart(&self.db, org_id);
                        self.org_members = db_load_org_users(&self.db, org_id);
                        let mgr_name = self.org_members.iter().find(|m| m.id == manager_id).map(|m| m.display_name.clone()).unwrap_or_default();
                        self.status_text = format!("Linked {} → {}", mgr_name, report_name);
                    }
                }
                OrgAction::UpdateSettings { org_id, name, owner_id, mode } => {
                    self.save_snapshot();
                    if !name.trim().is_empty() {
                        db_rename_org(&self.db, org_id, name.trim());
                    }
                    if let Some(owner_id) = owner_id {
                        db_update_org_owner(&self.db, org_id, owner_id);
                    }
                    db_update_org_settings(&self.db, org_id, &mode);
                    self.org_list = db_list_orgs(&self.db);
                    self.current_org_id = Some(org_id);
                    self.org_members = db_load_org_users(&self.db, org_id);
                    self.org_chart_links = db_load_org_chart(&self.db, org_id);
                    self.org_settings = db_load_org_settings(&self.db, org_id);
                    self.org_selected_user_id = db_org_owner_id(&self.db, org_id);
                    self.status_text = format!("Updated org settings: {}", self.org_settings.mode);
                }
            }
        }

        if close_org_dialog {
            self.org_dialog_state = OrgDialogState::None;
        }

        enum TaskAssignAction {
            Assign { feature_id: String, user_id: i64, user_name: String },
            Unassign { assignment_id: i64, user_name: String },
        }

        let mut task_assign_action: Option<TaskAssignAction> = None;
        if let Some(feature_id) = self.task_assign_feature_id.clone() {
            let mut close_task_dialog = false;
            let feature_title = self.task_assign_feature_title.clone();
            let members_snapshot = self.org_members.clone();
            let assignments = db_load_task_assignments(&self.db, &feature_id);
            let mut assignment_map: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
            for assignment in &assignments {
                assignment_map.insert(assignment.user_id, assignment.id);
            }
            let owner_id = self.current_org_id.and_then(|oid| db_org_owner_id(&self.db, oid));
            let allow_assign = self.org_settings.mode == "flat" || self.org_selected_user_id == owner_id;
            egui::Window::new(format!("Assign Tasks: {}", feature_title)).collapsible(false).resizable(false).show(ctx, |ui| {
                if members_snapshot.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No org members available.");
                } else {
                    for member in &members_snapshot {
                        ui.horizontal(|ui| {
                            ui.label(&member.display_name);
                            if let Some(assignment_id) = assignment_map.get(&member.id) {
                                ui.colored_label(egui::Color32::GRAY, "Assigned");
                                ui.add_enabled_ui(allow_assign, |ui| {
                                    if ui.small_button("Unassign").clicked() {
                                        task_assign_action = Some(TaskAssignAction::Unassign {
                                            assignment_id: *assignment_id,
                                            user_name: member.display_name.clone(),
                                        });
                                    }
                                });
                            } else {
                                ui.add_enabled_ui(allow_assign, |ui| {
                                    if ui.small_button("Assign").clicked() {
                                        task_assign_action = Some(TaskAssignAction::Assign {
                                            feature_id: feature_id.clone(),
                                            user_id: member.id,
                                            user_name: member.display_name.clone(),
                                        });
                                    }
                                });
                            }
                        });
                    }
                }
                if !allow_assign {
                    ui.colored_label(egui::Color32::GRAY, "Select the owner to change assignments.");
                }
                ui.separator();
                if ui.button("Close").clicked() {
                    close_task_dialog = true;
                }
            });
            if close_task_dialog {
                self.task_assign_feature_id = None;
                self.task_assign_feature_title.clear();
            }
        }
        if let Some(user_id) = self.task_assign_user_id {
            let mut close_task_dialog = false;
            let user_name = self.task_assign_user_name.clone();
            let owner_id = self.current_org_id.and_then(|oid| db_org_owner_id(&self.db, oid));
            let allow_assign = self.org_settings.mode == "flat" || self.org_selected_user_id == owner_id;
            let mut features: Vec<(String, String)> = Vec::new();
            for quarter in &self.quarters {
                for feature in &quarter.features {
                    features.push((feature.id.clone(), feature.title.clone()));
                }
            }
            egui::Window::new(format!("Assign Tasks to {}", user_name)).collapsible(false).resizable(false).show(ctx, |ui| {
                if features.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No features available.");
                } else {
                    for (feature_id, feature_title) in &features {
                        let assignments = db_load_task_assignments(&self.db, feature_id);
                        let assigned = assignments.iter().find(|a| a.user_id == user_id).map(|a| a.id);
                        ui.horizontal(|ui| {
                            ui.label(feature_title);
                            if let Some(assignment_id) = assigned {
                                ui.colored_label(egui::Color32::GRAY, "Assigned");
                                ui.add_enabled_ui(allow_assign, |ui| {
                                    if ui.small_button("Unassign").clicked() {
                                        task_assign_action = Some(TaskAssignAction::Unassign {
                                            assignment_id,
                                            user_name: user_name.clone(),
                                        });
                                    }
                                });
                            } else {
                                ui.add_enabled_ui(allow_assign, |ui| {
                                    if ui.small_button("Assign").clicked() {
                                        task_assign_action = Some(TaskAssignAction::Assign {
                                            feature_id: feature_id.clone(),
                                            user_id,
                                            user_name: user_name.clone(),
                                        });
                                    }
                                });
                            }
                        });
                    }
                }
                if !allow_assign {
                    ui.colored_label(egui::Color32::GRAY, "Select the owner to change assignments.");
                }
                ui.separator();
                if ui.button("Close").clicked() {
                    close_task_dialog = true;
                }
            });
            if close_task_dialog {
                self.task_assign_user_id = None;
                self.task_assign_user_name.clear();
            }
        }
        if let Some(action) = task_assign_action {
            match action {
                TaskAssignAction::Assign { feature_id, user_id, user_name } => {
                    db_assign_task(&self.db, &feature_id, user_id);
                    self.status_text = format!("Assigned {}", user_name);
                }
                TaskAssignAction::Unassign { assignment_id, user_name } => {
                    db_unassign_task(&self.db, assignment_id);
                    self.status_text = format!("Unassigned {}", user_name);
                }
            }
        }

        if self.show_org_list_dialog {
            let mut switch_id = None;
            let mut delete_id = None;
            egui::Window::new("Organizations").collapsible(false).resizable(false).show(ctx, |ui| {
                if self.org_list.is_empty() {
                    ui.label("No organizations.");
                }
                for org in &self.org_list.clone() {
                    ui.horizontal(|ui| {
                        let is_current = self.current_org_id == Some(org.id);
                        if ui.selectable_label(is_current, &org.name).clicked() {
                            switch_id = Some(org.id);
                        }
                        if ui.small_button("Delete").clicked() {
                            delete_id = Some(org.id);
                        }
                    });
                }
                ui.separator();
                if ui.button("Cancel").clicked() {
                    self.show_org_list_dialog = false;
                }
            });
            if let Some(id) = delete_id {
                self.save_snapshot();
                db_delete_org(&self.db, id);
                self.org_list = db_list_orgs(&self.db);
                if self.current_org_id == Some(id) {
                    self.current_org_id = self.org_list.first().map(|o| o.id);
                    if let Some(oid) = self.current_org_id {
                        self.org_members = db_load_org_users(&self.db, oid);
                        self.org_chart_links = db_load_org_chart(&self.db, oid);
                        self.org_settings = db_load_org_settings(&self.db, oid);
                    } else {
                        self.org_members.clear();
                        self.org_chart_links.clear();
                        self.org_settings = OrgSettings {
                            org_id: 0,
                            mode: "hierarchy".into(),
                            updated_at: String::new(),
                        };
                        self.org_selected_user_id = None;
                    }
                }
            }
            if let Some(id) = switch_id {
                self.current_org_id = Some(id);
                self.org_members = db_load_org_users(&self.db, id);
                self.org_chart_links = db_load_org_chart(&self.db, id);
                self.org_settings = db_load_org_settings(&self.db, id);
                self.org_selected_user_id = db_org_owner_id(&self.db, id);
                self.show_org_list_dialog = false;
            }
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
            .with_title("allroads v1.3.0")
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
