use crate::change::{Change, ChangeOp};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension, Transaction};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct TableSpec {
    pub name: String,
    pub primary_key: String,
    pub columns: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub db_path: String,
    pub node_id: String,
    pub encryption_key: String,
    pub tables: Vec<TableSpec>,
    pub max_orgs: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("encryption key required")]
    MissingKey,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("unknown table: {0}")]
    UnknownTable(String),
    #[error("invalid payload")]
    InvalidPayload,
}

pub struct SyncEngine {
    config: SyncConfig,
    table_map: HashMap<String, TableSpec>,
}

impl SyncEngine {
    pub fn new(config: SyncConfig) -> Self {
        let table_map = config
            .tables
            .iter()
            .cloned()
            .map(|t| (t.name.clone(), t))
            .collect();
        Self { config, table_map }
    }

    pub fn open(&self) -> Result<Connection, SyncError> {
        if self.config.encryption_key.trim().is_empty() {
            return Err(SyncError::MissingKey);
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let conn = Connection::open_with_flags(Path::new(&self.config.db_path), flags)?;
        apply_encryption_key(&conn, &self.config.encryption_key)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(conn)
    }

    pub fn init_db(&self, conn: &Connection) -> Result<(), SyncError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS sync_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                node_id TEXT NOT NULL,
                schema_version INTEGER NOT NULL DEFAULT 1,
                last_snapshot_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS sync_context (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                suppress_triggers INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sync_peer_state (
                peer_id TEXT PRIMARY KEY,
                last_acked_id INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                change_id TEXT NOT NULL UNIQUE,
                timestamp_ms INTEGER NOT NULL,
                origin_node TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                op TEXT NOT NULL,
                payload TEXT NOT NULL,
                hlc TEXT NOT NULL,
                applied INTEGER NOT NULL DEFAULT 0,
                sent INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO sync_meta (id, node_id) VALUES (1, '');
            INSERT OR IGNORE INTO sync_context (id, suppress_triggers) VALUES (1, 0);
            ",
        )?;

        conn.execute(
            "UPDATE sync_meta SET node_id = ?1 WHERE id = 1;",
            params![self.config.node_id],
        )?;

        for table in &self.config.tables {
            create_triggers(conn, table)?;
        }

        Ok(())
    }

    pub fn ensure_logged_table(&self, conn: &Connection, table_name: &str) -> Result<(), SyncError> {
        let table = self
            .table_map
            .get(table_name)
            .ok_or_else(|| SyncError::UnknownTable(table_name.to_string()))?;
        let payload = json_object_for_columns(&table.columns, "t");
        let sql = format!(
            "
            INSERT INTO sync_log (change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc)
            SELECT
                lower(hex(randomblob(16))),
                CAST(strftime('%s','now') AS INTEGER) * 1000,
                ?1,
                '{table}',
                CAST(t.{pk} AS TEXT),
                'insert',
                {payload},
                printf('%lld-%s', CAST(strftime('%s','now') AS INTEGER) * 1000, ?1)
            FROM {table} t
            LEFT JOIN sync_log l
                ON l.entity = '{table}'
                AND l.entity_id = CAST(t.{pk} AS TEXT)
                AND l.origin_node = ?1
                AND l.op = 'insert'
            WHERE l.change_id IS NULL;
            ",
            table = table.name,
            pk = table.primary_key,
            payload = payload
        );
        conn.execute(&sql, params![self.config.node_id])?;
        Ok(())
    }

    pub fn ensure_logged_all_inserts(&self, conn: &Connection) -> Result<(), SyncError> {
        for table in &self.config.tables {
            self.ensure_logged_table(conn, &table.name)?;
        }
        Ok(())
    }

    pub fn list_outgoing(&self, conn: &Connection, limit: usize) -> Result<Vec<Change>, SyncError> {
        let mut stmt = conn.prepare(
            "
            SELECT change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc
            FROM sync_log
            WHERE origin_node = ?1 AND sent = 0
            ORDER BY id ASC
            LIMIT ?2;
            ",
        )?;
        let rows = stmt.query_map(params![self.config.node_id, limit as i64], |row| {
            let op_str: String = row.get(5)?;
            let op = match op_str.as_str() {
                "insert" => ChangeOp::Insert,
                "update" => ChangeOp::Update,
                "delete" => ChangeOp::Delete,
                _ => ChangeOp::Update,
            };
            let payload_text: String = row.get(6)?;
            let payload: Value = serde_json::from_str(&payload_text).unwrap_or(Value::Null);
            Ok(Change {
                change_id: row.get(0)?,
                timestamp_ms: row.get(1)?,
                origin_node: row.get(2)?,
                entity: row.get(3)?,
                entity_id: row.get(4)?,
                op,
                payload,
                hlc: row.get(7)?,
            })
        })?;

        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn list_since(
        &self,
        conn: &Connection,
        after_id: i64,
        limit: usize,
    ) -> Result<(Vec<Change>, i64), SyncError> {
        let mut stmt = conn.prepare(
            "
            SELECT id, change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc
            FROM sync_log
            WHERE id > ?1
            ORDER BY id ASC
            LIMIT ?2;
            ",
        )?;

        let rows = stmt.query_map(params![after_id, limit as i64], |row| {
            let op_str: String = row.get(6)?;
            let op = match op_str.as_str() {
                "insert" => ChangeOp::Insert,
                "update" => ChangeOp::Update,
                "delete" => ChangeOp::Delete,
                _ => ChangeOp::Update,
            };
            let payload_text: String = row.get(7)?;
            let payload: Value = serde_json::from_str(&payload_text).unwrap_or(Value::Null);
            Ok((
                row.get::<_, i64>(0)?,
                Change {
                    change_id: row.get(1)?,
                    timestamp_ms: row.get(2)?,
                    origin_node: row.get(3)?,
                    entity: row.get(4)?,
                    entity_id: row.get(5)?,
                    op,
                    payload,
                    hlc: row.get(8)?,
                },
            ))
        })?;

        let mut out = Vec::new();
        let mut last_id = after_id;
        for row in rows {
            let (id, change) = row?;
            last_id = id;
            out.push(change);
        }
        Ok((out, last_id))
    }

    pub fn get_peer_last_ack(&self, conn: &Connection, peer_id: &str) -> Result<i64, SyncError> {
        let last: Option<i64> = conn
            .query_row(
                "SELECT last_acked_id FROM sync_peer_state WHERE peer_id = ?1;",
                params![peer_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(last.unwrap_or(0))
    }

    pub fn set_peer_last_ack(
        &self,
        conn: &Connection,
        peer_id: &str,
        last_acked_id: i64,
    ) -> Result<(), SyncError> {
        conn.execute(
            "
            INSERT INTO sync_peer_state (peer_id, last_acked_id, updated_at)
            VALUES (?1, ?2, CAST(strftime('%s','now') AS INTEGER))
            ON CONFLICT(peer_id) DO UPDATE SET
                last_acked_id = excluded.last_acked_id,
                updated_at = excluded.updated_at;
            ",
            params![peer_id, last_acked_id],
        )?;
        Ok(())
    }

    pub fn export_snapshot(&self) -> Result<(Vec<u8>, String), SyncError> {
        let source = self.open()?;
        let temp_path = format!("{}.snapshot", self.config.db_path);
        let escaped = temp_path.replace('\'', "''");
        let vacuum_sql = format!("VACUUM INTO '{}';", escaped);
        source.execute_batch(&vacuum_sql)?;
        let bytes = fs::read(&temp_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = format!("{:x}", hasher.finalize());
        fs::remove_file(&temp_path)?;
        Ok((bytes, hash))
    }

    pub fn export_scoped_snapshot(&self, org_id: i64, roadmap_id: Option<i64>) -> Result<(Vec<u8>, String), SyncError> {
        let source = self.open()?;
        let scope = roadmap_id.unwrap_or(0);
        let temp_path = if scope > 0 {
            format!("{}.snapshot.org{}.roadmap{}", self.config.db_path, org_id, scope)
        } else {
            format!("{}.snapshot.org{}", self.config.db_path, org_id)
        };
        let escaped = temp_path.replace('\'', "''");
        let vacuum_sql = format!("VACUUM INTO '{}';", escaped);
        source.execute_batch(&vacuum_sql)?;
        drop(source);

        let scoped = Connection::open_with_flags(Path::new(&temp_path), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        apply_encryption_key(&scoped, &self.config.encryption_key)?;
        scoped.execute_batch("PRAGMA foreign_keys = ON;")?;

        scoped.execute("DELETE FROM sync_session;", [])?;
        scoped.execute("DELETE FROM sync_peer_state;", [])?;
        scoped.execute("DELETE FROM sync_log;", [])?;

        scoped.execute(
            "DELETE FROM org_roadmap WHERE org_id != ?1;",
            params![org_id],
        )?;
        if let Some(roadmap_id) = roadmap_id {
            scoped.execute(
                "DELETE FROM org_roadmap WHERE roadmap_id != ?1;",
                params![roadmap_id],
            )?;
        }

        scoped.execute(
            "DELETE FROM roadmap WHERE id NOT IN (SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1);",
            params![org_id],
        )?;
        scoped.execute(
            "DELETE FROM org WHERE id != ?1;",
            params![org_id],
        )?;

        if table_exists(&scoped, "org_settings")? {
            scoped.execute("DELETE FROM org_settings WHERE org_id != ?1;", params![org_id])?;
        }
        if table_exists(&scoped, "org_user")? {
            scoped.execute("DELETE FROM org_user WHERE org_id != ?1;", params![org_id])?;
        }
        if table_exists(&scoped, "org_owner")? {
            scoped.execute("DELETE FROM org_owner WHERE org_id != ?1;", params![org_id])?;
        }
        if table_exists(&scoped, "org_chart")? {
            scoped.execute("DELETE FROM org_chart WHERE org_id != ?1;", params![org_id])?;
        }
        if table_exists(&scoped, "org_roadmap_editor")? {
            scoped.execute(
                "DELETE FROM org_roadmap_editor WHERE org_id != ?1;",
                params![org_id],
            )?;
        }
        if table_exists(&scoped, "quarter")? {
            scoped.execute(
                "DELETE FROM quarter WHERE roadmap_id NOT IN (SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1);",
                params![org_id],
            )?;
        }
        if table_exists(&scoped, "feature")? {
            scoped.execute(
                "DELETE FROM feature WHERE quarter_id NOT IN (SELECT id FROM quarter);",
                [],
            )?;
        }
        if table_exists(&scoped, "subtask")? {
            scoped.execute(
                "DELETE FROM subtask WHERE feature_id NOT IN (SELECT id FROM feature);",
                [],
            )?;
        }
        if table_exists(&scoped, "task_assignment")? {
            scoped.execute(
                "DELETE FROM task_assignment WHERE feature_id NOT IN (SELECT id FROM feature);",
                [],
            )?;
        }

        let bytes = fs::read(&temp_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash = format!("{:x}", hasher.finalize());
        fs::remove_file(&temp_path)?;
        Ok((bytes, hash))
    }

    pub fn compute_org_scope_logical_hash(&self, org_id: i64) -> Result<String, SyncError> {
        let conn = self.open()?;
        let table_defs = org_scope_table_defs();
        let mut hasher = Sha256::new();
        hasher.update(format!("org:{}\n", org_id).as_bytes());

        for table in table_defs {
            let sql = format!(
                "SELECT {} FROM {} WHERE {} ORDER BY {};",
                table.columns.join(", "),
                table.name,
                table.filter_sql,
                table.order_sql
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query(params![org_id])?;
            hasher.update(format!("table:{}\n", table.name).as_bytes());
            while let Some(row) = rows.next()? {
                for idx in 0..table.columns.len() {
                    let col = table.columns[idx];
                    hasher.update(col.as_bytes());
                    hasher.update(b"=");
                    let encoded = match row.get_ref(idx)? {
                        rusqlite::types::ValueRef::Null => "null".to_string(),
                        rusqlite::types::ValueRef::Integer(v) => format!("i:{}", v),
                        rusqlite::types::ValueRef::Real(v) => format!("r:{:.17}", v),
                        rusqlite::types::ValueRef::Text(v) => {
                            format!("t:{}", String::from_utf8_lossy(v))
                        }
                        rusqlite::types::ValueRef::Blob(v) => format!("b:{}", BASE64.encode(v)),
                    };
                    hasher.update(encoded.as_bytes());
                    hasher.update(b"|");
                }
                hasher.update(b"\n");
            }
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn export_migration_snapshot(&self, org_id: i64) -> Result<(Vec<u8>, String), SyncError> {
        let (bytes, _byte_hash) = self.export_scoped_snapshot(org_id, None)?;
        let logical_hash = self.compute_org_scope_logical_hash(org_id)?;
        Ok((bytes, logical_hash))
    }

    pub fn import_snapshot(&self, bytes: &[u8]) -> Result<(), SyncError> {
        let temp_path = format!("{}.incoming", self.config.db_path);
        fs::write(&temp_path, bytes)?;
        let result = (|| {
            let incoming = Connection::open_with_flags(Path::new(&temp_path), OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            apply_encryption_key(&incoming, &self.config.encryption_key)?;
            incoming.execute_batch("PRAGMA foreign_keys = ON;")?;

            let mut target = self.open()?;
            self.init_db(&target)?;
            let tx = target.transaction()?;
            tx.execute_batch("PRAGMA defer_foreign_keys = ON;")?;
            tx.execute(
                "UPDATE sync_context SET suppress_triggers = 1 WHERE id = 1;",
                [],
            )
            .ok();

            if let Some(scope) = detect_snapshot_scope(&incoming)? {
                clear_target_scope(&tx, &scope)?;
            }

            for table in &self.config.tables {
                merge_snapshot_table(&incoming, &tx, table)?;
            }

            tx.execute(
                "UPDATE sync_context SET suppress_triggers = 0 WHERE id = 1;",
                [],
            )
            .ok();
            tx.commit()?;
            Ok(())
        })();

        fs::remove_file(&temp_path).ok();
        result
    }

    pub fn mark_sent(&self, conn: &mut Connection, change_ids: &[String]) -> Result<(), SyncError> {
        let tx = conn.transaction()?;
        for change_id in change_ids {
            tx.execute(
                "UPDATE sync_log SET sent = 1 WHERE change_id = ?1;",
                params![change_id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn apply_incoming(&self, conn: &mut Connection, changes: &[Change]) -> Result<(), SyncError> {
        let tx = conn.transaction()?;
        tx.execute_batch("PRAGMA defer_foreign_keys = ON;")?;
        tx.execute("UPDATE sync_context SET suppress_triggers = 1 WHERE id = 1;", [])?;

        for change in changes {
            self.validate_change(change)?;
            let exists: Option<String> = tx
                .query_row(
                    "SELECT change_id FROM sync_log WHERE change_id = ?1;",
                    params![change.change_id],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_some() {
                continue;
            }

            self.apply_change(&tx, change).map_err(|err| {
                let payload_text = serde_json::to_string(&change.payload)
                    .unwrap_or_else(|_| "<invalid-payload>".to_string());
                eprintln!(
                    "[sync_apply_error] entity={} op={} id={} change_id={} payload={} err={}",
                    change.entity,
                    op_to_str(change.op.clone()),
                    change.entity_id,
                    change.change_id,
                    payload_text,
                    err
                );
                err
            })?;
            insert_incoming_log(&tx, change).map_err(|err| {
                let payload_text = serde_json::to_string(&change.payload)
                    .unwrap_or_else(|_| "<invalid-payload>".to_string());
                eprintln!(
                    "[sync_log_error] entity={} op={} id={} change_id={} payload={} err={}",
                    change.entity,
                    op_to_str(change.op.clone()),
                    change.entity_id,
                    change.change_id,
                    payload_text,
                    err
                );
                err
            })?;
        }

        tx.execute("UPDATE sync_context SET suppress_triggers = 0 WHERE id = 1;", [])?;
        log_foreign_key_violations(&tx)?;
        tx.commit()?;
        Ok(())
    }


    fn apply_change(&self, tx: &Transaction<'_>, change: &Change) -> Result<(), SyncError> {
        let table = self
            .table_map
            .get(&change.entity)
            .ok_or_else(|| SyncError::UnknownTable(change.entity.clone()))?;

        if change.entity == "org" && matches!(change.op, ChangeOp::Insert) {
            let count: i64 = tx.query_row("SELECT COUNT(*) FROM org;", [], |row| row.get(0))?;
            if count >= self.config.max_orgs {
                return Err(SyncError::InvalidPayload);
            }
        }

        if !should_apply_change(tx, table, change)? {
            return Ok(());
        }

        match change.op {
            ChangeOp::Insert => apply_insert(tx, table, change),
            ChangeOp::Update => apply_update(tx, table, change),
            ChangeOp::Delete => apply_delete(tx, table, change),
        }
    }

    fn validate_change(&self, change: &Change) -> Result<(), SyncError> {
        if change.entity_id.trim().is_empty() {
            return Err(SyncError::InvalidPayload);
        }
        match change.op {
            ChangeOp::Insert | ChangeOp::Update => {
                if !change.payload.is_object() {
                    return Err(SyncError::InvalidPayload);
                }
            }
            ChangeOp::Delete => {}
        }
        Ok(())
    }
}

fn apply_encryption_key(conn: &Connection, key: &str) -> Result<(), SyncError> {
    let escaped = key.replace('"', "\"").replace('\'', "''");
    let pragma = format!("PRAGMA key = '{}';", escaped);
    conn.execute_batch(&pragma)?;
    conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;
    Ok(())
}

fn create_triggers(conn: &Connection, table: &TableSpec) -> Result<(), SyncError> {
    let payload_new = json_object_for_columns(&table.columns, "NEW");
    let payload_old = json_object_for_columns(&table.columns, "OLD");
    let insert_trigger = format!(
        "
        CREATE TRIGGER IF NOT EXISTS sync_{table}_insert
        AFTER INSERT ON {table}
        WHEN (SELECT suppress_triggers FROM sync_context WHERE id = 1) = 0
        BEGIN
            INSERT INTO sync_log (change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc)
            VALUES (
                lower(hex(randomblob(16))),
                CAST(strftime('%s','now') AS INTEGER) * 1000,
                (SELECT node_id FROM sync_meta WHERE id = 1),
                '{table}',
                CAST(NEW.{pk} AS TEXT),
                'insert',
                {payload},
                printf('%lld-%s', CAST(strftime('%s','now') AS INTEGER) * 1000, (SELECT node_id FROM sync_meta WHERE id = 1))
            );
        END;
        ",
        table = table.name,
        pk = table.primary_key,
        payload = payload_new
    );

    let update_trigger = format!(
        "
        CREATE TRIGGER IF NOT EXISTS sync_{table}_update
        AFTER UPDATE ON {table}
        WHEN (SELECT suppress_triggers FROM sync_context WHERE id = 1) = 0
        BEGIN
            INSERT INTO sync_log (change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc)
            VALUES (
                lower(hex(randomblob(16))),
                CAST(strftime('%s','now') AS INTEGER) * 1000,
                (SELECT node_id FROM sync_meta WHERE id = 1),
                '{table}',
                CAST(NEW.{pk} AS TEXT),
                'update',
                {payload},
                printf('%lld-%s', CAST(strftime('%s','now') AS INTEGER) * 1000, (SELECT node_id FROM sync_meta WHERE id = 1))
            );
        END;
        ",
        table = table.name,
        pk = table.primary_key,
        payload = payload_new
    );

    let delete_trigger = format!(
        "
        CREATE TRIGGER IF NOT EXISTS sync_{table}_delete
        AFTER DELETE ON {table}
        WHEN (SELECT suppress_triggers FROM sync_context WHERE id = 1) = 0
        BEGIN
            INSERT INTO sync_log (change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc)
            VALUES (
                lower(hex(randomblob(16))),
                CAST(strftime('%s','now') AS INTEGER) * 1000,
                (SELECT node_id FROM sync_meta WHERE id = 1),
                '{table}',
                CAST(OLD.{pk} AS TEXT),
                'delete',
                {payload},
                printf('%lld-%s', CAST(strftime('%s','now') AS INTEGER) * 1000, (SELECT node_id FROM sync_meta WHERE id = 1))
            );
        END;
        ",
        table = table.name,
        pk = table.primary_key,
        payload = payload_old
    );

    conn.execute_batch(&insert_trigger)?;
    conn.execute_batch(&update_trigger)?;
    conn.execute_batch(&delete_trigger)?;
    Ok(())
}

fn json_object_for_columns(columns: &[String], prefix: &str) -> String {
    let mut parts = Vec::new();
    for col in columns {
        parts.push(format!("'{}', {}.{}", col, prefix, col));
    }
    format!("json_object({})", parts.join(", "))
}

fn insert_incoming_log(tx: &Transaction<'_>, change: &Change) -> Result<(), SyncError> {
    let payload_text = serde_json::to_string(&change.payload).unwrap_or_else(|_| "null".to_string());
    tx.execute(
        "
        INSERT INTO sync_log
            (change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc, applied, sent)
        VALUES
            (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, 0);
        ",
        params![
            change.change_id,
            change.timestamp_ms,
            change.origin_node,
            change.entity,
            change.entity_id,
            op_to_str(change.op.clone()),
            payload_text,
            change.hlc
        ],
    )?;
    Ok(())
}

fn op_to_str(op: ChangeOp) -> &'static str {
    match op {
        ChangeOp::Insert => "insert",
        ChangeOp::Update => "update",
        ChangeOp::Delete => "delete",
    }
}

fn apply_insert(tx: &Transaction<'_>, table: &TableSpec, change: &Change) -> Result<(), SyncError> {
    let payload = change.payload.as_object().ok_or(SyncError::InvalidPayload)?;
    let mut payload = payload.clone();
    if !payload.contains_key(&table.primary_key) {
        payload.insert(
            table.primary_key.clone(),
            Value::String(change.entity_id.clone()),
        );
    }
    let mut cols = Vec::new();
    let mut vals = Vec::new();
    for col in &table.columns {
        if let Some(value) = payload.get(col) {
            cols.push(col.clone());
            vals.push(value.clone());
        }
    }

    let placeholders: Vec<String> = (0..vals.len()).map(|i| format!("?{}", i + 1)).collect();
    let mut update_sets = Vec::new();
    for col in &cols {
        if col == &table.primary_key {
            continue;
        }
        update_sets.push(format!("{} = excluded.{}", col, col));
    }
    let sql = if update_sets.is_empty() {
        format!(
            "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT({}) DO NOTHING;",
            table.name,
            cols.join(", "),
            placeholders.join(", "),
            table.primary_key
        )
    } else {
        format!(
            "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT({}) DO UPDATE SET {};",
            table.name,
            cols.join(", "),
            placeholders.join(", "),
            table.primary_key,
            update_sets.join(", ")
        )
    };
    let params = values_to_params(vals);
    tx.execute(&sql, params_from_iter(params))?;
    Ok(())
}

fn apply_update(tx: &Transaction<'_>, table: &TableSpec, change: &Change) -> Result<(), SyncError> {
    let payload = change.payload.as_object().ok_or(SyncError::InvalidPayload)?;
    let mut sets = Vec::new();
    let mut vals = Vec::new();

    for col in &table.columns {
        if col == &table.primary_key {
            continue;
        }
        if let Some(value) = payload.get(col) {
            sets.push(format!("{} = ?{}", col, vals.len() + 1));
            vals.push(value.clone());
        }
    }

    if sets.is_empty() {
        return Ok(());
    }

    vals.push(Value::String(change.entity_id.clone()));
    let sql = format!(
        "UPDATE {} SET {} WHERE {} = ?{};",
        table.name,
        sets.join(", "),
        table.primary_key,
        vals.len()
    );
    let params = values_to_params(vals);
    let updated = tx.execute(&sql, params_from_iter(params))?;
    if updated == 0 {
        apply_insert(tx, table, change)?;
    }
    Ok(())
}

fn apply_delete(tx: &Transaction<'_>, table: &TableSpec, change: &Change) -> Result<(), SyncError> {
    let sql = format!(
        "DELETE FROM {} WHERE {} = ?1;",
        table.name, table.primary_key
    );
    tx.execute(&sql, params![change.entity_id])?;
    Ok(())
}

fn should_apply_change(
    tx: &Transaction<'_>,
    table: &TableSpec,
    change: &Change,
) -> Result<bool, SyncError> {
    if !table.columns.iter().any(|c| c == "updated_at") {
        return Ok(true);
    }
    let incoming = match change.payload.get("updated_at") {
        Some(Value::String(value)) => value.clone(),
        _ => return Ok(true),
    };

    let sql = format!(
        "SELECT updated_at FROM {} WHERE {} = ?1;",
        table.name, table.primary_key
    );
    let existing: Option<String> = tx
        .query_row(&sql, params![change.entity_id], |row| row.get(0))
        .optional()?;
    Ok(existing.map(|v| incoming >= v).unwrap_or(true))
}

fn values_to_params(values: Vec<Value>) -> Vec<rusqlite::types::Value> {
    values
        .into_iter()
        .map(|v| match v {
            Value::Null => rusqlite::types::Value::Null,
            Value::Bool(b) => rusqlite::types::Value::Integer(if b { 1 } else { 0 }),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    rusqlite::types::Value::Integer(i)
                } else if let Some(f) = n.as_f64() {
                    rusqlite::types::Value::Real(f)
                } else {
                    rusqlite::types::Value::Null
                }
            }
            Value::String(s) => rusqlite::types::Value::Text(s),
            other => rusqlite::types::Value::Text(other.to_string()),
        })
        .collect()
}

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, SyncError> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1;",
            params![table_name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
}

#[derive(Debug)]
struct SnapshotScope {
    org_id: i64,
    roadmap_ids: Vec<i64>,
}

#[derive(Clone, Copy)]
struct OrgScopeTableDef {
    name: &'static str,
    columns: &'static [&'static str],
    filter_sql: &'static str,
    order_sql: &'static str,
}

fn org_scope_table_defs() -> &'static [OrgScopeTableDef] {
    &[
        OrgScopeTableDef {
            name: "org",
            columns: &[
                "id",
                "name",
                "token_hash",
                "token_salt",
                "owner_hash",
                "owner_salt",
                "created_at",
                "updated_at",
            ],
            filter_sql: "id = ?1",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "org_settings",
            columns: &["org_id", "mode", "updated_at"],
            filter_sql: "org_id = ?1",
            order_sql: "org_id ASC",
        },
        OrgScopeTableDef {
            name: "org_user",
            columns: &["id", "link_id", "org_id", "display_name", "role", "created_at", "updated_at"],
            filter_sql: "org_id = ?1",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "org_owner",
            columns: &["org_id", "owner_user_id", "created_at"],
            filter_sql: "org_id = ?1",
            order_sql: "org_id ASC",
        },
        OrgScopeTableDef {
            name: "org_chart",
            columns: &["id", "org_id", "manager_id", "report_id", "created_at"],
            filter_sql: "org_id = ?1",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "org_roadmap",
            columns: &["org_id", "roadmap_id", "created_at"],
            filter_sql: "org_id = ?1",
            order_sql: "roadmap_id ASC",
        },
        OrgScopeTableDef {
            name: "org_roadmap_editor",
            columns: &["org_id", "user_id", "can_edit", "updated_at"],
            filter_sql: "org_id = ?1",
            order_sql: "user_id ASC",
        },
        OrgScopeTableDef {
            name: "roadmap",
            columns: &["id", "name", "created_at", "updated_at"],
            filter_sql: "id IN (SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1)",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "quarter",
            columns: &["id", "roadmap_id", "year", "quarter", "sort_order"],
            filter_sql:
                "roadmap_id IN (SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1)",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "feature",
            columns: &[
                "id",
                "quarter_id",
                "title",
                "description",
                "completed",
                "status",
                "color",
                "sort_order",
                "days",
                "weeks",
                "start_date",
                "started_at",
                "paused_at",
                "completed_at",
            ],
            filter_sql:
                "quarter_id IN (SELECT q.id FROM quarter q JOIN org_roadmap orp ON orp.roadmap_id = q.roadmap_id WHERE orp.org_id = ?1)",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "subtask",
            columns: &[
                "id",
                "feature_id",
                "title",
                "description",
                "completed",
                "status",
                "color",
                "sort_order",
                "started_at",
                "completed_at",
            ],
            filter_sql:
                "feature_id IN (SELECT f.id FROM feature f JOIN quarter q ON q.id = f.quarter_id JOIN org_roadmap orp ON orp.roadmap_id = q.roadmap_id WHERE orp.org_id = ?1)",
            order_sql: "id ASC",
        },
        OrgScopeTableDef {
            name: "task_assignment",
            columns: &["id", "feature_id", "user_id", "user_link_id", "status", "assigned_at", "updated_at"],
            filter_sql:
                "feature_id IN (SELECT f.id FROM feature f JOIN quarter q ON q.id = f.quarter_id JOIN org_roadmap orp ON orp.roadmap_id = q.roadmap_id WHERE orp.org_id = ?1)",
            order_sql: "id ASC",
        },
    ]
}

fn detect_snapshot_scope(conn: &Connection) -> Result<Option<SnapshotScope>, SyncError> {
    let org_id: Option<i64> = conn
        .query_row("SELECT id FROM org LIMIT 1;", [], |row| row.get(0))
        .optional()?;
    let Some(org_id) = org_id else {
        return Ok(None);
    };

    let mut stmt = conn.prepare("SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1;")?;
    let rows = stmt.query_map(params![org_id], |row| row.get(0))?;
    let mut roadmap_ids = Vec::new();
    for row in rows {
        roadmap_ids.push(row?);
    }

    Ok(Some(SnapshotScope { org_id, roadmap_ids }))
}

fn clear_target_scope(tx: &Transaction<'_>, scope: &SnapshotScope) -> Result<(), SyncError> {
    let mut roadmap_ids = scope.roadmap_ids.clone();

    let mut existing_stmt = tx.prepare("SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1;")?;
    let existing_rows = existing_stmt.query_map(params![scope.org_id], |row| row.get(0))?;
    for row in existing_rows {
        let id: i64 = row?;
        if !roadmap_ids.contains(&id) {
            roadmap_ids.push(id);
        }
    }

    for roadmap_id in roadmap_ids {
        tx.execute(
            "
            DELETE FROM task_assignment
            WHERE feature_id IN (
                SELECT f.id
                FROM feature f
                JOIN quarter q ON q.id = f.quarter_id
                WHERE q.roadmap_id = ?1
            );
            ",
            params![roadmap_id],
        )
        .ok();
        tx.execute(
            "
            DELETE FROM subtask
            WHERE feature_id IN (
                SELECT f.id
                FROM feature f
                JOIN quarter q ON q.id = f.quarter_id
                WHERE q.roadmap_id = ?1
            );
            ",
            params![roadmap_id],
        )
        .ok();
        tx.execute(
            "DELETE FROM feature WHERE quarter_id IN (SELECT id FROM quarter WHERE roadmap_id = ?1);",
            params![roadmap_id],
        )
        .ok();
        tx.execute("DELETE FROM quarter WHERE roadmap_id = ?1;", params![roadmap_id])
            .ok();
        tx.execute("DELETE FROM roadmap WHERE id = ?1;", params![roadmap_id])
            .ok();
    }

    tx.execute(
        "DELETE FROM org_roadmap_editor WHERE org_id = ?1;",
        params![scope.org_id],
    )
    .ok();
    tx.execute("DELETE FROM org_chart WHERE org_id = ?1;", params![scope.org_id])
        .ok();
    tx.execute("DELETE FROM org_owner WHERE org_id = ?1;", params![scope.org_id])
        .ok();
    tx.execute("DELETE FROM org_user WHERE org_id = ?1;", params![scope.org_id])
        .ok();
    tx.execute(
        "DELETE FROM org_settings WHERE org_id = ?1;",
        params![scope.org_id],
    )
    .ok();
    tx.execute("DELETE FROM org_roadmap WHERE org_id = ?1;", params![scope.org_id])
        .ok();

    Ok(())
}

fn merge_snapshot_table(
    incoming: &Connection,
    tx: &Transaction<'_>,
    table: &TableSpec,
) -> Result<(), SyncError> {
    if table.columns.is_empty() {
        return Ok(());
    }

    let table_exists: Option<i64> = incoming
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1 LIMIT 1;",
            params![table.name],
            |row| row.get(0),
        )
        .optional()?;
    if table_exists.is_none() {
        return Ok(());
    }

    let select_sql = format!("SELECT {} FROM {};", table.columns.join(", "), table.name);
    let mut stmt = incoming.prepare(&select_sql)?;
    let mut rows = stmt.query([])?;

    let placeholders: Vec<String> = (0..table.columns.len()).map(|i| format!("?{}", i + 1)).collect();
    let insert_sql = format!(
        "INSERT INTO {} ({}) VALUES ({});",
        table.name,
        table.columns.join(", "),
        placeholders.join(", ")
    );
    let pk_idx = table
        .columns
        .iter()
        .position(|c| c == &table.primary_key)
        .ok_or(SyncError::InvalidPayload)?;
    let update_cols: Vec<&String> = table
        .columns
        .iter()
        .filter(|c| *c != &table.primary_key)
        .collect();
    let update_sql = if update_cols.is_empty() {
        None
    } else {
        Some(format!(
            "UPDATE {} SET {} WHERE {} = ?{};",
            table.name,
            update_cols
                .iter()
                .enumerate()
                .map(|(idx, col)| format!("{} = ?{}", col, idx + 1))
                .collect::<Vec<_>>()
                .join(", "),
            table.primary_key,
            update_cols.len() + 1
        ))
    };

    while let Some(row) = rows.next()? {
        let mut values = Vec::<rusqlite::types::Value>::with_capacity(table.columns.len());
        for idx in 0..table.columns.len() {
            let mapped = match row.get_ref(idx)? {
                rusqlite::types::ValueRef::Null => rusqlite::types::Value::Null,
                rusqlite::types::ValueRef::Integer(v) => rusqlite::types::Value::Integer(v),
                rusqlite::types::ValueRef::Real(v) => rusqlite::types::Value::Real(v),
                rusqlite::types::ValueRef::Text(v) => {
                    rusqlite::types::Value::Text(String::from_utf8_lossy(v).to_string())
                }
                rusqlite::types::ValueRef::Blob(v) => rusqlite::types::Value::Blob(v.to_vec()),
            };
            values.push(mapped);
        }
        let mut updated = 0usize;
        if let Some(update_sql) = &update_sql {
            let mut update_vals = Vec::with_capacity(update_cols.len() + 1);
            for col in &update_cols {
                let idx = table
                    .columns
                    .iter()
                    .position(|c| c == *col)
                    .ok_or(SyncError::InvalidPayload)?;
                update_vals.push(values[idx].clone());
            }
            update_vals.push(values[pk_idx].clone());
            updated = tx.execute(update_sql, params_from_iter(update_vals))?;
        }
        if updated == 0 {
            tx.execute(&insert_sql, params_from_iter(values))?;
        }
    }

    Ok(())
}

fn log_foreign_key_violations(tx: &Transaction<'_>) -> Result<(), SyncError> {
    let mut stmt = tx.prepare("PRAGMA foreign_key_check;")?;
    let rows = stmt.query_map([], |row| {
        let table: String = row.get(0)?;
        let row_id: i64 = row.get(1)?;
        let parent: String = row.get(2)?;
        let fkid: i64 = row.get(3)?;
        Ok((table, row_id, parent, fkid))
    })?;
    for row in rows {
        let (table, row_id, parent, fkid) = row?;
        eprintln!(
            "[fk_violation] table={} row_id={} parent={} fkid={}",
            table, row_id, parent, fkid
        );
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn roadmap_spec() -> TableSpec {
        TableSpec {
            name: "roadmap".to_string(),
            primary_key: "id".to_string(),
            columns: vec!["id", "name", "created_at", "updated_at"]
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }

    fn sync_specs() -> Vec<TableSpec> {
        vec![
            TableSpec { name: "org".to_string(), primary_key: "id".to_string(), columns: vec!["id", "name", "created_at", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "org_settings".to_string(), primary_key: "org_id".to_string(), columns: vec!["org_id", "mode", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "org_user".to_string(), primary_key: "id".to_string(), columns: vec!["id", "link_id", "org_id", "display_name", "role", "created_at", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "org_owner".to_string(), primary_key: "org_id".to_string(), columns: vec!["org_id", "owner_user_id", "created_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "org_roadmap".to_string(), primary_key: "org_id".to_string(), columns: vec!["org_id", "roadmap_id", "created_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "org_chart".to_string(), primary_key: "id".to_string(), columns: vec!["id", "org_id", "manager_id", "report_id", "created_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "org_roadmap_editor".to_string(), primary_key: "user_id".to_string(), columns: vec!["org_id", "user_id", "can_edit", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "roadmap".to_string(), primary_key: "id".to_string(), columns: vec!["id", "name", "created_at", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "quarter".to_string(), primary_key: "id".to_string(), columns: vec!["id", "roadmap_id", "year", "quarter", "sort_order"].into_iter().map(String::from).collect() },
            TableSpec { name: "feature".to_string(), primary_key: "id".to_string(), columns: vec!["id", "quarter_id", "title", "description", "completed", "status", "color", "sort_order", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "subtask".to_string(), primary_key: "id".to_string(), columns: vec!["id", "feature_id", "title", "description", "completed", "status", "color", "sort_order", "updated_at"].into_iter().map(String::from).collect() },
            TableSpec { name: "task_assignment".to_string(), primary_key: "id".to_string(), columns: vec!["id", "feature_id", "user_id", "user_link_id", "status", "assigned_at", "updated_at"].into_iter().map(String::from).collect() },
        ]
    }

    fn test_db_path(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("allroads-sync-test-{}-{}.db", tag, nanos))
    }

    fn test_engine(path: &PathBuf) -> SyncEngine {
        SyncEngine::new(SyncConfig {
            db_path: path.to_string_lossy().to_string(),
            node_id: "node-test".to_string(),
            encryption_key: "test-key".to_string(),
            tables: sync_specs(),
            max_orgs: 5,
        })
    }

    fn create_scope_schema(conn: &Connection) {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS org (id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL, token_salt TEXT NOT NULL, owner_hash TEXT NOT NULL, owner_salt TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS org_settings (org_id INTEGER PRIMARY KEY, mode TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS org_user (id INTEGER PRIMARY KEY, link_id TEXT NOT NULL DEFAULT '', org_id INTEGER NOT NULL, display_name TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS org_owner (org_id INTEGER PRIMARY KEY, owner_user_id INTEGER NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS roadmap (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS org_roadmap (org_id INTEGER NOT NULL, roadmap_id INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (org_id, roadmap_id));
            CREATE UNIQUE INDEX IF NOT EXISTS org_roadmap_org_unique ON org_roadmap(org_id);
            CREATE TABLE IF NOT EXISTS quarter (id INTEGER PRIMARY KEY, roadmap_id INTEGER NOT NULL, year INTEGER NOT NULL, quarter INTEGER NOT NULL, sort_order INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS feature (id TEXT PRIMARY KEY, quarter_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, completed INTEGER NOT NULL, status TEXT NOT NULL, color TEXT NOT NULL, sort_order INTEGER NOT NULL, days INTEGER, weeks INTEGER, start_date TEXT, started_at TEXT, paused_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS subtask (id TEXT PRIMARY KEY, feature_id TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, completed INTEGER NOT NULL, status TEXT NOT NULL, color TEXT NOT NULL, sort_order INTEGER NOT NULL, started_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS task_assignment (id INTEGER PRIMARY KEY, feature_id TEXT NOT NULL, user_id INTEGER NOT NULL, user_link_id TEXT NOT NULL, status TEXT NOT NULL, assigned_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS org_chart (id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, manager_id INTEGER NOT NULL, report_id INTEGER NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS org_roadmap_editor (org_id INTEGER NOT NULL, user_id INTEGER NOT NULL, can_edit INTEGER NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY (org_id, user_id));
            CREATE UNIQUE INDEX IF NOT EXISTS org_roadmap_editor_user_unique ON org_roadmap_editor(user_id);
            CREATE TABLE IF NOT EXISTS sync_meta (id INTEGER PRIMARY KEY CHECK(id = 1), node_id TEXT NOT NULL, schema_version INTEGER NOT NULL DEFAULT 1, last_snapshot_hash TEXT);
            CREATE TABLE IF NOT EXISTS sync_context (id INTEGER PRIMARY KEY CHECK(id = 1), suppress_triggers INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS sync_session (session_id TEXT PRIMARY KEY, org_id INTEGER NOT NULL, user_id INTEGER NOT NULL, is_owner INTEGER NOT NULL, session_key TEXT NOT NULL, created_at TEXT NOT NULL, last_seen TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sync_peer_state (peer_id TEXT PRIMARY KEY, last_acked_id INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sync_log (id INTEGER PRIMARY KEY AUTOINCREMENT, change_id TEXT NOT NULL UNIQUE, timestamp_ms INTEGER NOT NULL, origin_node TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT NOT NULL, op TEXT NOT NULL, payload TEXT NOT NULL, hlc TEXT NOT NULL, applied INTEGER NOT NULL DEFAULT 0, sent INTEGER NOT NULL DEFAULT 0);
            INSERT OR IGNORE INTO sync_meta (id, node_id) VALUES (1, 'node-test');
            INSERT OR IGNORE INTO sync_context (id, suppress_triggers) VALUES (1, 0);
            "
        ).unwrap();
    }

    fn seed_two_orgs(conn: &Connection) {
        conn.execute("INSERT INTO org (id, name, token_hash, token_salt, owner_hash, owner_salt, created_at, updated_at) VALUES (1, 'A', 'th1', 'ts1', 'oh1', 'os1', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org (id, name, token_hash, token_salt, owner_hash, owner_salt, created_at, updated_at) VALUES (2, 'B', 'th2', 'ts2', 'oh2', 'os2', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org_settings (org_id, mode, updated_at) VALUES (1, 'flat', 't');", []).unwrap();
        conn.execute("INSERT INTO org_settings (org_id, mode, updated_at) VALUES (2, 'flat', 't');", []).unwrap();
        conn.execute("INSERT INTO org_user (id, link_id, org_id, display_name, role, created_at, updated_at) VALUES (11, 'usr-11', 1, 'Owner A', 'owner', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org_user (id, link_id, org_id, display_name, role, created_at, updated_at) VALUES (12, 'usr-12', 1, 'Member A', 'member', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org_user (id, link_id, org_id, display_name, role, created_at, updated_at) VALUES (21, 'usr-21', 2, 'Owner B', 'owner', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org_owner (org_id, owner_user_id, created_at) VALUES (1, 11, 't');", []).unwrap();
        conn.execute("INSERT INTO org_owner (org_id, owner_user_id, created_at) VALUES (2, 21, 't');", []).unwrap();
        conn.execute("INSERT INTO roadmap (id, name, created_at, updated_at) VALUES (101, 'OrgA Roadmap', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO roadmap (id, name, created_at, updated_at) VALUES (201, 'OrgB Roadmap', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO roadmap (id, name, created_at, updated_at) VALUES (999, 'Local Personal', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org_roadmap (org_id, roadmap_id, created_at) VALUES (1, 101, 't');", []).unwrap();
        conn.execute("INSERT INTO org_roadmap (org_id, roadmap_id, created_at) VALUES (2, 201, 't');", []).unwrap();
        conn.execute("INSERT INTO quarter (id, roadmap_id, year, quarter, sort_order) VALUES (1001, 101, 2026, 1, 0);", []).unwrap();
        conn.execute("INSERT INTO quarter (id, roadmap_id, year, quarter, sort_order) VALUES (2001, 201, 2026, 1, 0);", []).unwrap();
        conn.execute("INSERT INTO feature (id, quarter_id, title, description, completed, status, color, sort_order, days, weeks, start_date, started_at, paused_at, completed_at, updated_at) VALUES ('fA', 1001, 'A', 'A', 0, 'Planned', '#fff', 0, NULL, NULL, NULL, NULL, NULL, NULL, 't');", []).unwrap();
        conn.execute("INSERT INTO feature (id, quarter_id, title, description, completed, status, color, sort_order, days, weeks, start_date, started_at, paused_at, completed_at, updated_at) VALUES ('fB', 2001, 'B', 'B', 0, 'Planned', '#fff', 0, NULL, NULL, NULL, NULL, NULL, NULL, 't');", []).unwrap();
        conn.execute("INSERT INTO subtask (id, feature_id, title, description, completed, status, color, sort_order, started_at, completed_at, updated_at) VALUES ('sA', 'fA', 'sA', 'sA', 0, 'Planned', '#aaa', 0, NULL, NULL, 't');", []).unwrap();
        conn.execute("INSERT INTO subtask (id, feature_id, title, description, completed, status, color, sort_order, started_at, completed_at, updated_at) VALUES ('sB', 'fB', 'sB', 'sB', 0, 'Planned', '#aaa', 0, NULL, NULL, 't');", []).unwrap();
        conn.execute("INSERT INTO task_assignment (id, feature_id, user_id, user_link_id, status, assigned_at, updated_at) VALUES (1, 'fA', 12, 'usr-12', 'Assigned', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO task_assignment (id, feature_id, user_id, user_link_id, status, assigned_at, updated_at) VALUES (2, 'fB', 21, 'usr-21', 'Assigned', 't', 't');", []).unwrap();
        conn.execute("INSERT INTO org_chart (id, org_id, manager_id, report_id, created_at) VALUES (1, 1, 11, 12, 't');", []).unwrap();
        conn.execute("INSERT INTO org_roadmap_editor (org_id, user_id, can_edit, updated_at) VALUES (1, 12, 1, 't');", []).unwrap();
    }

    fn mk_change(op: ChangeOp, payload: serde_json::Value) -> Change {
        Change {
            change_id: "c1".to_string(),
            timestamp_ms: 1,
            origin_node: "node-test".to_string(),
            entity: "roadmap".to_string(),
            entity_id: "1".to_string(),
            op,
            payload,
            hlc: "1-node".to_string(),
        }
    }

    #[test]
    fn apply_update_falls_back_to_insert_when_row_missing() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE roadmap (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            ",
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        let table = roadmap_spec();
        let change = mk_change(
            ChangeOp::Update,
            serde_json::json!({"id":1,"name":"Roadmap A","created_at":"a","updated_at":"b"}),
        );
        apply_update(&tx, &table, &change).unwrap();
        tx.commit().unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM roadmap WHERE id = 1;", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn ensure_logged_table_adds_insert_when_only_update_exists() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE roadmap (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                change_id TEXT NOT NULL UNIQUE,
                timestamp_ms INTEGER NOT NULL,
                origin_node TEXT NOT NULL,
                entity TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                op TEXT NOT NULL,
                payload TEXT NOT NULL,
                hlc TEXT NOT NULL,
                applied INTEGER NOT NULL DEFAULT 0,
                sent INTEGER NOT NULL DEFAULT 0
            );
            ",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO roadmap (id, name, created_at, updated_at) VALUES (1, 'R1', 'a', 'b');",
            [],
        )
        .unwrap();
        conn.execute(
            "
            INSERT INTO sync_log (change_id, timestamp_ms, origin_node, entity, entity_id, op, payload, hlc, applied, sent)
            VALUES ('u1', 1, 'node-test', 'roadmap', '1', 'update', '{}', '1-node', 1, 0);
            ",
            [],
        )
        .unwrap();

        let engine = SyncEngine::new(SyncConfig {
            db_path: "unused.db".to_string(),
            node_id: "node-test".to_string(),
            encryption_key: "k".to_string(),
            tables: vec![roadmap_spec()],
            max_orgs: 5,
        });

        engine.ensure_logged_table(&conn, "roadmap").unwrap();
        engine.ensure_logged_table(&conn, "roadmap").unwrap();

        let inserts: i64 = conn
            .query_row(
                "
                SELECT COUNT(*)
                FROM sync_log
                WHERE origin_node = 'node-test' AND entity = 'roadmap' AND entity_id = '1' AND op = 'insert';
                ",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(inserts, 1);
    }

    #[test]
    fn export_scoped_snapshot_contains_only_requested_org() {
        let path = test_db_path("export-scope");
        let engine = test_engine(&path);
        {
            let conn = engine.open().unwrap();
            create_scope_schema(&conn);
            seed_two_orgs(&conn);
        }

        let (bytes, _hash) = engine.export_scoped_snapshot(1, None).unwrap();
        let snapshot_path = test_db_path("snapshot-inspect");
        std::fs::write(&snapshot_path, &bytes).unwrap();
        let snap = Connection::open_with_flags(&snapshot_path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
        apply_encryption_key(&snap, "test-key").unwrap();

        let org1: i64 = snap.query_row("SELECT COUNT(*) FROM org WHERE id = 1;", [], |r| r.get(0)).unwrap();
        let org2: i64 = snap.query_row("SELECT COUNT(*) FROM org WHERE id = 2;", [], |r| r.get(0)).unwrap();
        let rb: i64 = snap.query_row("SELECT COUNT(*) FROM roadmap WHERE id = 201;", [], |r| r.get(0)).unwrap();
        let local: i64 = snap.query_row("SELECT COUNT(*) FROM roadmap WHERE id = 999;", [], |r| r.get(0)).unwrap();
        let fa: i64 = snap.query_row("SELECT COUNT(*) FROM feature WHERE id = 'fA';", [], |r| r.get(0)).unwrap();
        let fb: i64 = snap.query_row("SELECT COUNT(*) FROM feature WHERE id = 'fB';", [], |r| r.get(0)).unwrap();

        assert_eq!(org1, 1);
        assert_eq!(org2, 0);
        assert_eq!(rb, 0);
        assert_eq!(local, 0);
        assert_eq!(fa, 1);
        assert_eq!(fb, 0);

        std::fs::remove_file(&snapshot_path).ok();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn import_snapshot_replaces_org_scope_but_preserves_other_org_and_local() {
        let source_path = test_db_path("source");
        let source_engine = test_engine(&source_path);
        {
            let conn = source_engine.open().unwrap();
            create_scope_schema(&conn);
            seed_two_orgs(&conn);
            conn.execute("UPDATE feature SET title = 'A-fresh' WHERE id = 'fA';", []).unwrap();
        }
        let (bytes, _hash) = source_engine.export_scoped_snapshot(1, None).unwrap();

        let target_path = test_db_path("target");
        let target_engine = test_engine(&target_path);
        {
            let conn = target_engine.open().unwrap();
            create_scope_schema(&conn);
            seed_two_orgs(&conn);
            conn.execute("UPDATE feature SET title = 'A-stale' WHERE id = 'fA';", []).unwrap();
            conn.execute("INSERT INTO feature (id, quarter_id, title, description, completed, status, color, sort_order, updated_at) VALUES ('fA_stale_extra', 1001, 'old', 'old', 0, 'Planned', '#fff', 1, 't');", []).unwrap();
        }

        target_engine.import_snapshot(&bytes).unwrap();

        let conn = target_engine.open().unwrap();
        let fresh_title: String = conn
            .query_row("SELECT title FROM feature WHERE id = 'fA';", [], |r| r.get(0))
            .unwrap();
        let stale_extra: i64 = conn
            .query_row("SELECT COUNT(*) FROM feature WHERE id = 'fA_stale_extra';", [], |r| r.get(0))
            .unwrap();
        let org_b_feature: i64 = conn
            .query_row("SELECT COUNT(*) FROM feature WHERE id = 'fB';", [], |r| r.get(0))
            .unwrap();
        let local_roadmap: i64 = conn
            .query_row("SELECT COUNT(*) FROM roadmap WHERE id = 999;", [], |r| r.get(0))
            .unwrap();

        assert_eq!(fresh_title, "A-fresh");
        assert_eq!(stale_extra, 0);
        assert_eq!(org_b_feature, 1);
        assert_eq!(local_roadmap, 1);

        std::fs::remove_file(&source_path).ok();
        std::fs::remove_file(&target_path).ok();
    }

    #[test]
    fn logical_hash_stable_for_equivalent_org_content() {
        let path_a = test_db_path("hash-a");
        let engine_a = test_engine(&path_a);
        {
            let conn = engine_a.open().unwrap();
            create_scope_schema(&conn);
            seed_two_orgs(&conn);
        }

        let path_b = test_db_path("hash-b");
        let engine_b = test_engine(&path_b);
        {
            let conn = engine_b.open().unwrap();
            create_scope_schema(&conn);
            seed_two_orgs(&conn);
        }

        let hash1 = engine_a.compute_org_scope_logical_hash(1).unwrap();
        let hash2 = engine_b.compute_org_scope_logical_hash(1).unwrap();
        assert_eq!(hash1, hash2);

        std::fs::remove_file(&path_a).ok();
        std::fs::remove_file(&path_b).ok();
    }

    #[test]
    fn logical_hash_changes_when_org_content_changes() {
        let path = test_db_path("hash-change");
        let engine = test_engine(&path);
        {
            let conn = engine.open().unwrap();
            create_scope_schema(&conn);
            seed_two_orgs(&conn);
        }

        let before = engine.compute_org_scope_logical_hash(1).unwrap();
        {
            let conn = engine.open().unwrap();
            conn.execute("UPDATE feature SET title = 'A++' WHERE id = 'fA';", [])
                .unwrap();
        }
        let after = engine.compute_org_scope_logical_hash(1).unwrap();
        assert_ne!(before, after);

        std::fs::remove_file(&path).ok();
    }
}
