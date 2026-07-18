use eframe::egui;
use chrono::Datelike;
use rusqlite::Connection;
use std::fs;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}, mpsc};
use std::thread;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sync_engine::{Change, SyncConfig as EngineSyncConfig, SyncEngine, SyncMessage, SignedEnvelope, TableSpec, WebSocketTransport};

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

fn get_template_subtasks(template_type: &str, feature_title: &str) -> Vec<&'static str> {
    match (template_type, feature_title) {
        ("web", "Planning & Design") => vec!["Define product scope", "Create wireframes"],
        ("web", "Backend Setup") => vec!["Create API skeleton", "Configure database", "Set up CI pipeline"],
        ("web", "Frontend Development") => vec!["Build layout", "Implement navigation", "Connect API client"],
        ("web", "Authentication System") => vec!["Implement signup/login", "Enforce route guards"],
        ("web", "Payment Integration") => vec!["Configure provider", "Build checkout flow", "Handle webhooks"],
        ("web", "Testing & QA") => vec!["Write core tests", "Run regression pass"],
        ("web", "Deployment") => vec!["Provision hosting", "Configure secrets", "Run production smoke test"],

        ("mobile", "UI/UX Design") => vec!["Design core screens", "Review interaction flows"],
        ("mobile", "Core Architecture") => vec!["Set app structure", "Configure state management", "Set up navigation"],
        ("mobile", "User Authentication") => vec!["Implement auth screens", "Add token storage"],
        ("mobile", "Main Features") => vec!["Build primary flows", "Implement offline cache", "Add error states"],
        ("mobile", "Push Notifications") => vec!["Register device tokens", "Create notification handlers", "Test delivery paths"],
        ("mobile", "App Store Submission") => vec!["Prepare assets", "Complete metadata"],
        ("mobile", "Marketing Launch") => vec!["Draft launch copy", "Schedule campaign", "Track launch metrics"],

        ("api", "API Specification") => vec!["Define endpoint contracts", "Review payload schemas"],
        ("api", "Database Design") => vec!["Model core entities", "Add indexes", "Write migration plan"],
        ("api", "Authentication & Auth") => vec!["Implement token validation", "Define roles/permissions"],
        ("api", "Core Endpoints") => vec!["Implement CRUD routes", "Add validation", "Return consistent errors"],
        ("api", "Documentation") => vec!["Write usage examples", "Publish developer guide"],
        ("api", "Testing Suite") => vec!["Add unit tests", "Add integration tests", "Run load sanity test"],
        ("api", "Monitoring Setup") => vec!["Add structured logging", "Create dashboards", "Set alert thresholds"],

        _ => vec!["Define scope", "Implement core work"],
    }
}

fn compute_sig(session_key: &str, session_id: &str, nonce: u64, body: &SyncMessage) -> Option<String> {
    let body_cbor = serde_cbor::to_vec(body).ok()?;
    let mut data = Vec::new();
    data.extend_from_slice(session_id.as_bytes());
    data.push(b':');
    data.extend_from_slice(nonce.to_string().as_bytes());
    data.push(b':');
    data.extend_from_slice(&body_cbor);
    let key_bytes = BASE64.decode(session_key.as_bytes()).ok()?;
    if key_bytes.len() != 32 { return None; }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key_bytes).ok()?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    Some(BASE64.encode(result))
}

fn verify_envelope(session_id: &str, session_key: &str, last_nonce_in: &mut u64, env: &SignedEnvelope) -> bool {
    if env.session_id != session_id {
        return false;
    }
    if env.nonce <= *last_nonce_in {
        return false;
    }
    let sig = match compute_sig(session_key, session_id, env.nonce, &env.body) {
        Some(sig) => sig,
        None => return false,
    };
    if sig != env.sig {
        return false;
    }
    *last_nonce_in = env.nonce;
    true
}

async fn send_signed(
    transport: &mut WebSocketTransport,
    session_id: &str,
    session_key: &str,
    next_nonce_out: &mut u64,
    body: SyncMessage,
) -> Result<(), String> {
    let sealed_body = seal_sync_message(session_key, body).ok_or("sealing failed".to_string())?;
    let nonce = *next_nonce_out;
    *next_nonce_out = next_nonce_out.saturating_add(1);
    let sig = compute_sig(session_key, session_id, nonce, &sealed_body).ok_or("signing failed".to_string())?;
    let env = SignedEnvelope {
        session_id: session_id.to_string(),
        nonce,
        sig,
        body: sealed_body,
    };
    transport.send_json(&env).await.map_err(|e| e.to_string())?;
    Ok(())
}

fn seal_sync_message(session_key: &str, body: SyncMessage) -> Option<SyncMessage> {
    if matches!(body, SyncMessage::Sealed { .. }) {
        return Some(body);
    }
    let key_bytes = BASE64.decode(session_key.as_bytes()).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plain = serde_cbor::to_vec(&body).ok()?;
    let cipher_bytes = cipher.encrypt(&nonce, plain.as_slice()).ok()?;
    Some(SyncMessage::Sealed {
        nonce_b64: BASE64.encode(nonce),
        data_b64: BASE64.encode(cipher_bytes),
    })
}

fn unseal_sync_message(session_key: &str, body: SyncMessage) -> Result<SyncMessage, String> {
    let SyncMessage::Sealed { nonce_b64, data_b64 } = body else {
        return Ok(body);
    };
    let key_bytes = BASE64.decode(session_key.as_bytes()).map_err(|e| e.to_string())?;
    if key_bytes.len() != 32 {
        return Err("session key length invalid".to_string());
    }
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = BASE64.decode(nonce_b64.as_bytes()).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = BASE64.decode(data_b64.as_bytes()).map_err(|e| e.to_string())?;
    let plain = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "decrypt failed".to_string())?;
    serde_cbor::from_slice::<SyncMessage>(&plain).map_err(|e| e.to_string())
}

fn decrypt_snapshot(session_key: &str, data_b64: &str, nonce_b64: &str) -> Result<Vec<u8>, String> {
    let key_bytes = BASE64.decode(session_key.as_bytes()).map_err(|e| e.to_string())?;
    if key_bytes.len() != 32 {
        return Err("session key length invalid".to_string());
    }
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce_bytes = BASE64.decode(nonce_b64.as_bytes()).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = BASE64.decode(data_b64.as_bytes()).map_err(|e| e.to_string())?;
    cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| "snapshot decrypt failed".to_string())
}

fn normalize_outgoing_changes(changes: &mut Vec<Change>) {
    changes.retain(|change| change.entity != "org_owner");
    for change in changes.iter_mut() {
        if change.entity == "org_settings" {
            if let Some(mode) = change.payload.get_mut("mode") {
                if mode.as_str() == Some("hierarchy") {
                    *mode = serde_json::Value::String("hierarchical".to_string());
                }
            }
        }
    }
}

fn populate_task_assignment_user_link_ids(conn: &Connection, changes: &mut Vec<Change>) {
    for change in changes.iter_mut() {
        if change.entity != "task_assignment" {
            continue;
        }
        let Some(payload) = change.payload.as_object_mut() else {
            continue;
        };
        let has_link_id = payload
            .get("user_link_id")
            .and_then(|v| v.as_str())
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false);
        if has_link_id {
            continue;
        }

        let payload_user_id = match payload.get("user_id") {
            Some(serde_json::Value::Number(n)) => n.as_i64(),
            Some(serde_json::Value::String(s)) => s.parse::<i64>().ok(),
            _ => None,
        };

        let resolved_user = if let Some(user_id) = payload_user_id {
            conn.query_row(
                    "SELECT id, COALESCE(NULLIF(link_id, ''), 'usr-' || id) FROM org_user WHERE id = ?1 LIMIT 1;",
                    rusqlite::params![user_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .ok()
        } else if let Ok(assignment_id) = change.entity_id.parse::<i64>() {
            conn.query_row(
                    "
                    SELECT ta.user_id, COALESCE(NULLIF(ou.link_id, ''), 'usr-' || ou.id)
                    FROM task_assignment ta
                    JOIN org_user ou ON ou.id = ta.user_id
                    WHERE ta.id = ?1
                    LIMIT 1;
                    ",
                    rusqlite::params![assignment_id],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .ok()
        } else {
            None
        };

        if let Some((user_id, user_link_id)) = resolved_user {
            payload.insert("user_id".to_string(), serde_json::Value::from(user_id));
            payload.insert("user_link_id".to_string(), serde_json::Value::from(user_link_id));
        }
    }
}

fn normalize_incoming_changes(changes: &mut Vec<Change>) {
    for change in changes {
        if change.entity == "org_settings" {
            if let Some(mode) = change.payload.get_mut("mode") {
                if mode.as_str() == Some("hierarchical") {
                    *mode = serde_json::Value::String("hierarchy".to_string());
                }
            }
        }
    }
}

fn extract_migration_switch_url(message: &str) -> Option<String> {
    let marker = "switch_to=";
    let idx = message.find(marker)?;
    let url = message[idx + marker.len()..].trim();
    if url.is_empty() {
        return None;
    }
    Some(url.to_string())
}

async fn open_transport_with_config(cfg: &NetworkConfig) -> Result<WebSocketTransport, String> {
    if !cfg.use_proxy || cfg.proxy_mode == "none" {
        return WebSocketTransport::connect(&cfg.server_url)
            .await
            .map_err(|e| e.to_string());
    }
    let stream = connect_via_proxy(cfg, &cfg.server_url).await?;
    WebSocketTransport::connect_with_stream(&cfg.server_url, stream)
        .await
        .map_err(|e| e.to_string())
}

struct SyncConn {
    transport: WebSocketTransport,
    session_id: String,
    session_key: String,
    is_owner: bool,
    server_ack: i64,
    peer_id: String,
    last_nonce_in: u64,
    next_nonce_out: u64,
}

#[derive(Clone, Debug)]
struct PendingTokenRotation {
    token: String,
    user_id: Option<i64>,
}

async fn sync_connect(
    engine: Arc<SyncEngine>,
    cfg: &NetworkConfig,
    org_id: i64,
    token: String,
    owner_token: Option<String>,
    status_tx: &mpsc::Sender<SyncEvent>,
) -> Result<SyncConn, String> {
    let peer_id = "server".to_string();
    let last_ack = tokio::task::spawn_blocking({
        let engine = engine.clone();
        let peer_id = peer_id.clone();
        move || {
            let conn = engine.open().map_err(|e| e.to_string())?;
            conn.execute_batch(
                "
                DROP TRIGGER IF EXISTS sync_org_roadmap_editor_insert;
                DROP TRIGGER IF EXISTS sync_org_roadmap_editor_update;
                DROP TRIGGER IF EXISTS sync_org_roadmap_editor_delete;
                ",
            )
            .ok();
            engine.init_db(&conn).map_err(|e| e.to_string())?;
            engine.get_peer_last_ack(&conn, &peer_id).map_err(|e| e.to_string())
        }
    })
    .await
    .map_err(|_| "sync init failed".to_string())??;

    let mut transport = open_transport_with_config(cfg).await?;
    transport
        .send_msg(&SyncMessage::Hello {
            node_id: cfg.node_id.clone(),
            schema_version: 1,
            last_log_id: last_ack,
            token,
            owner_token: owner_token.clone(),
            client_kind: None,
        })
        .await
        .map_err(|e| e.to_string())?;

    let (session_id, session_key, is_owner, server_ack) = loop {
        let text = transport.next_text_limit(1024 * 1024).await.map_err(|e| e.to_string())?;
        let Some(text) = text else { return Err("connection closed".to_string()); };
        if let Ok(SyncMessage::AuthOk {
            session_id: sid,
            session_key: sk,
            after_log_id,
            server_node_id,
            is_owner: auth_owner,
            ..
        }) = serde_json::from_str(&text)
        {
            tokio::task::spawn_blocking({
                let engine = engine.clone();
                let peer_id = peer_id.clone();
                move || {
                    let conn = engine.open().map_err(|e| e.to_string())?;
                    engine.set_peer_last_ack(&conn, &peer_id, after_log_id).map_err(|e| e.to_string())
                }
            })
            .await
            .map_err(|_| "sync ack store failed".to_string())??;
            let _ = status_tx.send(SyncEvent::Auth {
                org_id,
                is_owner: auth_owner,
                server_node_id: server_node_id.clone(),
            });
            break (sid, sk, auth_owner, after_log_id);
        } else if let Ok(SyncMessage::Error { message }) = serde_json::from_str(&text) {
            return Err(message);
        }
    };

    Ok(SyncConn {
        transport,
        session_id,
        session_key,
        is_owner,
        server_ack,
        peer_id,
        last_nonce_in: 0,
        next_nonce_out: 1,
    })
}

async fn run_sync_session(
    engine: Arc<SyncEngine>,
    cfg: &NetworkConfig,
    org_id: i64,
    token: String,
    owner_token: Option<String>,
    status_tx: &mpsc::Sender<SyncEvent>,
    stop_flag: Arc<AtomicBool>,
    pending_send: Arc<AtomicBool>,
    pending_token: Arc<Mutex<Option<PendingTokenRotation>>>,
    request_snapshot: bool,
) -> Result<(), String> {
    let mut conn = sync_connect(engine.clone(), cfg, org_id, token, owner_token, status_tx).await?;
    let _ = status_tx.send(SyncEvent::Status("Sync connected".into()));
    if request_snapshot {
        send_signed(
            &mut conn.transport,
            &conn.session_id,
            &conn.session_key,
            &mut conn.next_nonce_out,
            SyncMessage::SnapshotReq { reason: "first_join".into() },
        )
        .await?;
    }
    send_signed(
        &mut conn.transport,
        &conn.session_id,
        &conn.session_key,
        &mut conn.next_nonce_out,
        SyncMessage::Resume { after_log_id: conn.server_ack },
    ).await?;

    let mut work_tick = tokio::time::interval(std::time::Duration::from_millis(800));
    let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_secs(25));
    loop {
        if stop_flag.load(Ordering::Relaxed) {
            return Ok(());
        }
        tokio::select! {
            _ = work_tick.tick() => {
                if let Some(rotation) = pending_token.lock().ok().and_then(|mut guard| guard.take()) {
                    send_signed(
                        &mut conn.transport,
                        &conn.session_id,
                        &conn.session_key,
                        &mut conn.next_nonce_out,
                        SyncMessage::RotateToken {
                            token: rotation.token.clone(),
                            user_id: rotation.user_id,
                        },
                    ).await?;
                    let _ = status_tx.send(SyncEvent::TokenRotated {
                        org_id,
                        token: rotation.token,
                        user_id: rotation.user_id,
                    });
                }
                if pending_send.swap(false, Ordering::Relaxed) {
                    let (mut outgoing, outgoing_ids) = tokio::task::spawn_blocking({
                        let engine = engine.clone();
                        move || {
                            let conn = engine.open().map_err(|e| e.to_string())?;
                            engine.ensure_logged_all_inserts(&conn).map_err(|e| e.to_string())?;
                            let mut changes = engine.list_outgoing(&conn, 200).map_err(|e| e.to_string())?;
                            populate_task_assignment_user_link_ids(&conn, &mut changes);
                            let ids = changes.iter().map(|c| c.change_id.clone()).collect::<Vec<_>>();
                            Ok::<_, String>((changes, ids))
                        }
                    }).await.map_err(|_| "sync list failed".to_string())??;
                    normalize_outgoing_changes(&mut outgoing);
                    if !outgoing.is_empty() {
                        send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Changeset { changes: outgoing, last_log_id: conn.server_ack }).await?;
                        tokio::task::spawn_blocking({
                            let engine = engine.clone();
                            let outgoing_ids = outgoing_ids.clone();
                            move || {
                                let mut conn = engine.open().map_err(|e| e.to_string())?;
                                engine.mark_sent(&mut conn, &outgoing_ids).map_err(|e| e.to_string())
                            }
                        }).await.map_err(|_| "sync mark sent failed".to_string())??;
                    }
                }
            }
            _ = heartbeat_tick.tick() => {
                send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Ping).await?;
            }
            msg = conn.transport.next_text_limit(1024 * 1024) => {
                let text = msg.map_err(|e| e.to_string())?;
                let Some(text) = text else { return Err("connection closed".to_string()); };
                if let Ok(env) = serde_json::from_str::<SignedEnvelope>(&text) {
                    if !verify_envelope(&conn.session_id, &conn.session_key, &mut conn.last_nonce_in, &env) {
                        continue;
                    }
                    let body = unseal_sync_message(&conn.session_key, env.body).map_err(|e| e.to_string())?;
                    match body {
                        SyncMessage::Changeset { mut changes, last_log_id } => {
                            normalize_incoming_changes(&mut changes);
                            let peer_id = conn.peer_id.clone();
                            tokio::task::spawn_blocking({
                                let engine = engine.clone();
                                move || {
                                    let mut conn = engine.open().map_err(|e| e.to_string())?;
                                    engine.apply_incoming(&mut conn, &changes).map_err(|e| e.to_string())?;
                                    engine.set_peer_last_ack(&conn, &peer_id, last_log_id).map_err(|e| e.to_string())
                                }
                            }).await.map_err(|_| "sync apply failed".to_string())??;
                            conn.server_ack = last_log_id;
                            send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Ack { last_log_id }).await?;
                        }
                        SyncMessage::Ack { last_log_id } => {
                            conn.server_ack = last_log_id;
                        }
                        SyncMessage::Ping => {
                            send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Pong).await?;
                        }
                        SyncMessage::SnapshotData { data_b64, nonce_b64, .. } => {
                            let bytes = decrypt_snapshot(&conn.session_key, &data_b64, &nonce_b64)?;
                            tokio::task::spawn_blocking({
                                let engine = engine.clone();
                                move || engine.import_snapshot(&bytes).map_err(|e| e.to_string())
                            })
                            .await
                            .map_err(|_| "snapshot import failed".to_string())??;
                            let _ = status_tx.send(SyncEvent::Status("Snapshot applied".into()));
                            let _ = status_tx.send(SyncEvent::SnapshotApplied { org_id });
                        }
                        SyncMessage::Error { message } => {
                            let _ = status_tx.send(SyncEvent::Status(format!("Sync server error: {}", message)));
                        }
                        _ => {}
                    }
                } else if let Ok(SyncMessage::Error { message }) = serde_json::from_str::<SyncMessage>(&text) {
                    let _ = status_tx.send(SyncEvent::Status(format!("Sync server error: {}", message)));
                }
            }
        }
    }
}

async fn run_sync_once(
    engine: Arc<SyncEngine>,
    cfg: &NetworkConfig,
    org_id: i64,
    token: String,
    owner_token: Option<String>,
    status_tx: &mpsc::Sender<SyncEvent>,
    pending_token: Arc<Mutex<Option<PendingTokenRotation>>>,
    request_snapshot: bool,
) -> Result<bool, String> {
    let mut conn = sync_connect(engine.clone(), cfg, org_id, token, owner_token, status_tx).await?;

    if let Some(rotation) = pending_token.lock().ok().and_then(|mut guard| guard.take()) {
        send_signed(
            &mut conn.transport,
            &conn.session_id,
            &conn.session_key,
            &mut conn.next_nonce_out,
            SyncMessage::RotateToken {
                token: rotation.token.clone(),
                user_id: rotation.user_id,
            },
        ).await?;
        let _ = status_tx.send(SyncEvent::TokenRotated {
            org_id,
            token: rotation.token,
            user_id: rotation.user_id,
        });
    }

    if request_snapshot {
        send_signed(
            &mut conn.transport,
            &conn.session_id,
            &conn.session_key,
            &mut conn.next_nonce_out,
            SyncMessage::SnapshotReq { reason: "first_join".into() },
        )
        .await?;
    }

    send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Resume { after_log_id: conn.server_ack }).await?;

    let (mut outgoing, outgoing_ids) = tokio::task::spawn_blocking({
        let engine = engine.clone();
        move || {
            let conn = engine.open().map_err(|e| e.to_string())?;
            engine.ensure_logged_all_inserts(&conn).map_err(|e| e.to_string())?;
            let mut changes = engine.list_outgoing(&conn, 200).map_err(|e| e.to_string())?;
            populate_task_assignment_user_link_ids(&conn, &mut changes);
            let ids = changes.iter().map(|c| c.change_id.clone()).collect::<Vec<_>>();
            Ok::<_, String>((changes, ids))
        }
    })
    .await
    .map_err(|_| "sync list failed".to_string())??;
    normalize_outgoing_changes(&mut outgoing);
    if !outgoing.is_empty() {
        send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Changeset { changes: outgoing, last_log_id: conn.server_ack }).await?;
        tokio::task::spawn_blocking({
            let engine = engine.clone();
            let outgoing_ids = outgoing_ids.clone();
            move || {
                let mut conn = engine.open().map_err(|e| e.to_string())?;
                engine.mark_sent(&mut conn, &outgoing_ids).map_err(|e| e.to_string())
            }
        })
        .await
        .map_err(|_| "sync mark sent failed".to_string())??;
    }

    for _ in 0..20 {
        let text = match tokio::time::timeout(std::time::Duration::from_millis(250), conn.transport.next_text_limit(1024 * 1024)).await {
            Ok(res) => res.map_err(|e| e.to_string())?,
            Err(_) => break,
        };
        let Some(text) = text else { break; };
        if let Ok(env) = serde_json::from_str::<SignedEnvelope>(&text) {
            if !verify_envelope(&conn.session_id, &conn.session_key, &mut conn.last_nonce_in, &env) {
                continue;
            }
            let body = unseal_sync_message(&conn.session_key, env.body).map_err(|e| e.to_string())?;
            match body {
                SyncMessage::Changeset { mut changes, last_log_id } => {
                    normalize_incoming_changes(&mut changes);
                    let peer_id = conn.peer_id.clone();
                    tokio::task::spawn_blocking({
                        let engine = engine.clone();
                        move || {
                            let mut conn = engine.open().map_err(|e| e.to_string())?;
                            engine.apply_incoming(&mut conn, &changes).map_err(|e| e.to_string())?;
                            engine.set_peer_last_ack(&conn, &peer_id, last_log_id).map_err(|e| e.to_string())
                        }
                    })
                    .await
                    .map_err(|_| "sync apply failed".to_string())??;
                    conn.server_ack = last_log_id;
                    send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Ack { last_log_id }).await?;
                }
                SyncMessage::Ack { last_log_id } => {
                    conn.server_ack = last_log_id;
                }
                SyncMessage::Ping => {
                    send_signed(&mut conn.transport, &conn.session_id, &conn.session_key, &mut conn.next_nonce_out, SyncMessage::Pong).await?;
                }
                SyncMessage::SnapshotData { data_b64, nonce_b64, .. } => {
                    let bytes = decrypt_snapshot(&conn.session_key, &data_b64, &nonce_b64)?;
                    tokio::task::spawn_blocking({
                        let engine = engine.clone();
                        move || engine.import_snapshot(&bytes).map_err(|e| e.to_string())
                    })
                    .await
                    .map_err(|_| "snapshot import failed".to_string())??;
                    let _ = status_tx.send(SyncEvent::Status("Snapshot applied".into()));
                    let _ = status_tx.send(SyncEvent::SnapshotApplied { org_id });
                }
                SyncMessage::Error { message } => return Err(message),
                _ => {}
            }
        } else if let Ok(SyncMessage::Error { message }) = serde_json::from_str::<SyncMessage>(&text) {
            return Err(message);
        }
    }

    let final_ack = conn.server_ack;
    let peer_id = conn.peer_id.clone();
    tokio::task::spawn_blocking({
        let engine = engine.clone();
        move || {
            let conn = engine.open().map_err(|e| e.to_string())?;
            engine.set_peer_last_ack(&conn, &peer_id, final_ack).map_err(|e| e.to_string())
        }
    })
    .await
    .map_err(|_| "sync ack store failed".to_string())??;

    Ok(conn.is_owner)
}

async fn request_share_token(
    engine: Arc<SyncEngine>,
    cfg: &NetworkConfig,
    org_id: i64,
    token: String,
    owner_token: Option<String>,
    roadmap_id: i64,
) -> Result<String, String> {
    let (status_tx, _status_rx) = mpsc::channel();
    let mut conn = sync_connect(engine, cfg, org_id, token, owner_token, &status_tx).await?;
    send_signed(
        &mut conn.transport,
        &conn.session_id,
        &conn.session_key,
        &mut conn.next_nonce_out,
        SyncMessage::GenerateShareToken { roadmap_id },
    )
    .await?;

    loop {
        let text = conn.transport.next_text_limit(1024 * 1024).await.map_err(|e| e.to_string())?;
        let Some(text) = text else { return Err("connection closed".to_string()); };
        if let Ok(env) = serde_json::from_str::<SignedEnvelope>(&text) {
            if !verify_envelope(&conn.session_id, &conn.session_key, &mut conn.last_nonce_in, &env) {
                continue;
            }
            let body = unseal_sync_message(&conn.session_key, env.body)?;
            match body {
                SyncMessage::ShareToken { token, .. } => return Ok(token),
                SyncMessage::Ping => {
                    send_signed(
                        &mut conn.transport,
                        &conn.session_id,
                        &conn.session_key,
                        &mut conn.next_nonce_out,
                        SyncMessage::Pong,
                    )
                    .await?;
                }
                SyncMessage::Error { message } => return Err(message),
                _ => {}
            }
        }
    }
}

async fn download_share_snapshot(cfg: &NetworkConfig, token: String) -> Result<Vec<u8>, String> {
    let mut transport = open_transport_with_config(cfg).await?;
    transport
        .send_msg(&SyncMessage::ShareSnapshotReq { token })
        .await
        .map_err(|e| e.to_string())?;
    let text = transport
        .next_text_limit(50 * 1024 * 1024)
        .await
        .map_err(|e| e.to_string())?;
    let Some(text) = text else { return Err("connection closed".to_string()); };
    if let Ok(SyncMessage::ShareSnapshotData { data_b64, .. }) = serde_json::from_str::<SyncMessage>(&text) {
        return BASE64.decode(data_b64.as_bytes()).map_err(|e| e.to_string());
    }
    if let Ok(SyncMessage::Error { message }) = serde_json::from_str::<SyncMessage>(&text) {
        return Err(message);
    }
    Err("invalid share snapshot response".to_string())
}

async fn request_server_node_id(cfg: &NetworkConfig, server_url: String) -> Result<String, String> {
    let mut req_cfg = cfg.clone();
    req_cfg.server_url = server_url;
    let mut transport = open_transport_with_config(&req_cfg).await?;
    transport
        .send_msg(&SyncMessage::NodeIdReq)
        .await
        .map_err(|e| e.to_string())?;
    let text = transport
        .next_text_limit(1024 * 1024)
        .await
        .map_err(|e| e.to_string())?;
    let Some(text) = text else {
        return Err("connection closed".to_string());
    };
    if let Ok(SyncMessage::NodeIdOk { node_id }) = serde_json::from_str::<SyncMessage>(&text) {
        return Ok(node_id);
    }
    if let Ok(SyncMessage::Error { message }) = serde_json::from_str::<SyncMessage>(&text) {
        return Err(message);
    }
    Err("invalid node id response".to_string())
}

async fn request_org_migration_start(
    cfg: &NetworkConfig,
    owner_token: String,
    old_server_url: String,
    new_server_url: String,
    org_id: i64,
    target_server_identity: String,
) -> Result<(), String> {
    let mut req_cfg = cfg.clone();
    req_cfg.server_url = new_server_url.clone();
    let mut transport = open_transport_with_config(&req_cfg).await?;
    transport
        .send_msg(&SyncMessage::MigrationStartReq {
            owner_token,
            old_server_url,
            new_server_url,
            org_id,
            target_server_identity,
        })
        .await
        .map_err(|e| e.to_string())?;

    let text = transport
        .next_text_limit(50 * 1024 * 1024)
        .await
        .map_err(|e| e.to_string())?;
    let Some(text) = text else {
        return Err("connection closed".to_string());
    };
    if let Ok(SyncMessage::MigrationStartOk { .. }) = serde_json::from_str::<SyncMessage>(&text) {
        return Ok(());
    }
    if let Ok(SyncMessage::Error { message }) = serde_json::from_str::<SyncMessage>(&text) {
        return Err(message);
    }
    Err("invalid migration start response".to_string())
}

async fn connect_via_proxy(cfg: &NetworkConfig, server_url: &str) -> Result<TcpStream, String> {
    let url = Url::parse(server_url).map_err(|_| "invalid server url".to_string())?;
    let scheme = url.scheme();
    if scheme != "ws" {
        return Err("only ws:// supported with proxy".to_string());
    }
    let host = url.host_str().ok_or_else(|| "missing host".to_string())?;
    let port = url.port().unwrap_or(80);
    let (proxy_host, proxy_port) = parse_proxy_host(&cfg.proxy_url, &cfg.proxy_mode)?;
    let mut stream = TcpStream::connect((proxy_host.as_str(), proxy_port))
        .await
        .map_err(|e| e.to_string())?;
    match cfg.proxy_mode.as_str() {
        "http" => {
            http_proxy_connect(&mut stream, host, port).await?;
        }
        "socks5" | "tor" => {
            socks5_connect(&mut stream, host, port).await?;
        }
        _ => return Err("unsupported proxy mode".to_string()),
    }
    Ok(stream)
}

fn parse_proxy_host(proxy_url: &str, mode: &str) -> Result<(String, u16), String> {
    let url = Url::parse(proxy_url).map_err(|_| "invalid proxy url".to_string())?;
    let host = url.host_str().ok_or_else(|| "missing proxy host".to_string())?.to_string();
    let port = url.port().unwrap_or(match mode {
        "http" => 8080,
        "socks5" | "tor" => 9050,
        _ => 0,
    });
    if port == 0 {
        return Err("invalid proxy port".to_string());
    }
    Ok((host, port))
}

async fn http_proxy_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    let req = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        host, port, host, port
    );
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut temp = [0u8; 1024];
    loop {
        let n = stream.read(&mut temp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("proxy closed".to_string());
        }
        buf.extend_from_slice(&temp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err("proxy response too large".to_string());
        }
    }
    let resp = String::from_utf8_lossy(&buf);
    if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err("proxy connect failed".to_string())
    }
}

async fn socks5_connect(stream: &mut TcpStream, host: &str, port: u16) -> Result<(), String> {
    stream.write_all(&[0x05, 0x01, 0x00]).await.map_err(|e| e.to_string())?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.map_err(|e| e.to_string())?;
    if resp != [0x05, 0x00] {
        return Err("socks5 auth failed".to_string());
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err("host too long".to_string());
    }
    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.push(0x05);
    req.push(0x01);
    req.push(0x00);
    req.push(0x03);
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    stream.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|e| e.to_string())?;
    if header[1] != 0x00 {
        return Err("socks5 connect failed".to_string());
    }
    let addr_type = header[3];
    let skip = match addr_type {
        0x01 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;
            len[0] as usize
        }
        0x04 => 16,
        _ => return Err("socks5 invalid address".to_string()),
    };
    if skip > 0 {
        let mut buf = vec![0u8; skip];
        stream.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
    }
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await.map_err(|e| e.to_string())?;
    Ok(())
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
    subtasks: Vec<Subtask>,
}

#[derive(Clone, Debug)]
struct Subtask {
    id: String,
    title: String,
    description: String,
    completed: bool,
    status: String,
    color: String,
    started_at: Option<String>,
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
    sort_order INTEGER NOT NULL,
    status_view INTEGER NOT NULL DEFAULT 0,
    hide_not_progressing INTEGER NOT NULL DEFAULT 1
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
CREATE TABLE IF NOT EXISTS subtask (
    id TEXT PRIMARY KEY,
    feature_id TEXT NOT NULL REFERENCES feature(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'Planned',
    color TEXT NOT NULL DEFAULT '#9E9E9E',
    sort_order INTEGER NOT NULL,
    started_at TEXT,
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
CREATE TABLE IF NOT EXISTS org_sync (
    org_id INTEGER PRIMARY KEY REFERENCES org(id) ON DELETE CASCADE,
    joined INTEGER NOT NULL DEFAULT 0,
    is_owner INTEGER NOT NULL DEFAULT 0,
    token TEXT,
    owner_token TEXT,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id TEXT NOT NULL DEFAULT '',
    org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    is_ai INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_owner (
    org_id INTEGER PRIMARY KEY REFERENCES org(id) ON DELETE CASCADE,
    owner_user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS org_roadmap (
    org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    roadmap_id INTEGER NOT NULL REFERENCES roadmap(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    PRIMARY KEY (org_id, roadmap_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS org_roadmap_org_unique ON org_roadmap(org_id);
CREATE TABLE IF NOT EXISTS org_chart (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    manager_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    report_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS org_chart_unique_link ON org_chart(org_id, manager_id, report_id);
CREATE TABLE IF NOT EXISTS org_roadmap_editor (
    org_id INTEGER NOT NULL REFERENCES org(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    can_edit INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS org_roadmap_editor_user_unique ON org_roadmap_editor(user_id);
CREATE TABLE IF NOT EXISTS task_assignment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feature_id TEXT NOT NULL REFERENCES feature(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES org_user(id) ON DELETE CASCADE,
    user_link_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'Assigned',
    assigned_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sync_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    node_id TEXT NOT NULL DEFAULT '',
    server_url TEXT NOT NULL,
    server_node_id TEXT NOT NULL DEFAULT '',
    use_proxy INTEGER NOT NULL DEFAULT 0,
    proxy_mode TEXT NOT NULL DEFAULT 'none',
    proxy_url TEXT NOT NULL DEFAULT ''
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

fn generate_owner_token() -> String {
    generate_key()
}

fn generate_user_token() -> String {
    generate_key()
}

fn generate_user_link_id() -> String {
    format!("usr-{}", generate_key())
}

fn generate_node_id() -> String {
    let mut bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    format!("client-{}", hex::encode(bytes))
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
    entry.delete_credential().map_err(|e| format!("Error deleting key from keychain: {}", e))
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
    conn.execute_batch("ALTER TABLE org_user ADD COLUMN is_ai INTEGER NOT NULL DEFAULT 0").ok();
    conn.execute_batch("ALTER TABLE quarter ADD COLUMN status_view INTEGER NOT NULL DEFAULT 0").ok();
    conn.execute_batch("ALTER TABLE quarter ADD COLUMN hide_not_progressing INTEGER NOT NULL DEFAULT 1").ok();
    Ok((conn, db_key))
}

fn copy_table(from: &Connection, to: &Connection, table: &str, cols: &[&str]) {
    let collist = cols.join(", ");
    let placeholders = cols.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let rows: Vec<Vec<rusqlite::types::Value>> = {
        let mut stmt = from.prepare(&format!("SELECT {} FROM {}", collist, table)).unwrap();
        stmt.query_map([], |row| {
            (0..cols.len()).map(|i| row.get::<_, rusqlite::types::Value>(i)).collect()
        }).unwrap().filter_map(|r| r.ok()).collect()
    };
    let sql = format!("INSERT INTO {} ({}) VALUES ({})", table, collist, placeholders);
    for row in &rows {
        to.execute(&sql, rusqlite::params_from_iter(row.iter())).unwrap();
    }
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
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    conn.execute("UPDATE roadmap SET updated_at = ?1 WHERE id = ?2", rusqlite::params![now, roadmap_id]).unwrap();

    let mut existing_quarters = std::collections::HashMap::new();
    let mut q_stmt = conn.prepare("SELECT id, year, quarter FROM quarter WHERE roadmap_id = ?1").unwrap();
    let q_rows = q_stmt
        .query_map(rusqlite::params![roadmap_id], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?))
        })
        .unwrap();
    for row in q_rows.flatten() {
        existing_quarters.insert((row.1, row.2), row.0);
    }

    let mut keep_quarter_ids: Vec<i64> = Vec::new();
    let mut desired_feature_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    for (qi, q) in quarters.iter().enumerate() {
        let quarter_id = if let Some(id) = existing_quarters.get(&(q.year, q.quarter)) {
            conn.execute(
                "UPDATE quarter SET sort_order = ?1, status_view = ?2, hide_not_progressing = ?3 WHERE id = ?4",
                rusqlite::params![qi as i64, q.status_view as i32, q.hide_not_progressing as i32, id],
            ).unwrap();
            *id
        } else {
            conn.execute(
                "INSERT INTO quarter (roadmap_id, year, quarter, sort_order, status_view, hide_not_progressing) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![roadmap_id, q.year, q.quarter, qi as i64, q.status_view as i32, q.hide_not_progressing as i32],
            ).unwrap();
            conn.last_insert_rowid()
        };
        keep_quarter_ids.push(quarter_id);

        for (fi, f) in q.features.iter().enumerate() {
            desired_feature_ids.insert(f.id.clone());
            conn.execute(
                "INSERT INTO feature (id, quarter_id, title, description, completed, status, color, sort_order, days, weeks, start_date, started_at, paused_at, completed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
                 ON CONFLICT(id) DO UPDATE SET
                 quarter_id = excluded.quarter_id,
                 title = excluded.title,
                 description = excluded.description,
                 completed = excluded.completed,
                 status = excluded.status,
                 color = excluded.color,
                 sort_order = excluded.sort_order,
                 days = excluded.days,
                 weeks = excluded.weeks,
                 start_date = excluded.start_date,
                 started_at = excluded.started_at,
                 paused_at = excluded.paused_at,
                 completed_at = excluded.completed_at",
                rusqlite::params![f.id, quarter_id, f.title, f.description, f.completed as i32, f.status, f.color, fi as i64, f.days, f.weeks, f.start_date, f.started_at, f.paused_at, f.completed_at],
            ).unwrap();
            conn.execute(
                "DELETE FROM subtask WHERE feature_id = ?1",
                rusqlite::params![f.id],
            ).unwrap();
            for (si, s) in f.subtasks.iter().enumerate() {
                conn.execute(
                    "INSERT INTO subtask (id, feature_id, title, description, completed, status, color, sort_order, started_at, completed_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    rusqlite::params![s.id, f.id, s.title, s.description, s.completed as i32, s.status, s.color, si as i64, s.started_at, s.completed_at],
                ).unwrap();
            }
        }
    }

    if desired_feature_ids.is_empty() {
        conn.execute(
            "DELETE FROM feature WHERE quarter_id IN (SELECT id FROM quarter WHERE roadmap_id = ?1)",
            rusqlite::params![roadmap_id],
        ).unwrap();
    } else {
        let placeholders = vec!["?"; desired_feature_ids.len()].join(",");
        let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(desired_feature_ids.len() + 1);
        params.push(rusqlite::types::Value::from(roadmap_id));
        params.extend(
            desired_feature_ids
                .iter()
                .cloned()
                .map(rusqlite::types::Value::from),
        );
        let sql = format!(
            "DELETE FROM feature WHERE quarter_id IN (SELECT id FROM quarter WHERE roadmap_id = ?1) AND id NOT IN ({})",
            placeholders
        );
        let params_iter = rusqlite::params_from_iter(params);
        conn.execute(&sql, params_iter).unwrap();
    }

    if keep_quarter_ids.is_empty() {
        conn.execute(
            "DELETE FROM quarter WHERE roadmap_id = ?1",
            rusqlite::params![roadmap_id],
        ).unwrap();
    } else {
        let placeholders = vec!["?"; keep_quarter_ids.len()].join(",");
        let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(keep_quarter_ids.len() + 1);
        params.push(rusqlite::types::Value::from(roadmap_id));
        params.extend(
            keep_quarter_ids
                .iter()
                .copied()
                .map(rusqlite::types::Value::from),
        );
        let sql = format!(
            "DELETE FROM quarter WHERE roadmap_id = ?1 AND id NOT IN ({})",
            placeholders
        );
        let params_iter = rusqlite::params_from_iter(params);
        conn.execute(&sql, params_iter).unwrap();
    }

    conn.execute_batch("COMMIT").unwrap();
}

fn db_load_roadmap(conn: &Connection, roadmap_id: i64) -> Vec<Quarter> {
    let mut q_stmt = conn.prepare("SELECT id, year, quarter, status_view, hide_not_progressing FROM quarter WHERE roadmap_id = ?1 ORDER BY sort_order").unwrap();
    let q_rows: Vec<_> = q_stmt.query_map(rusqlite::params![roadmap_id], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, u32>(1)?, row.get::<_, u32>(2)?, row.get::<_, i32>(3)?, row.get::<_, i32>(4)?))
    }).unwrap().filter_map(|r| r.ok()).collect();

    let mut quarters = Vec::new();
    for (qid, year, quarter, sv, hnp) in q_rows {
        let mut f_stmt = conn.prepare("SELECT id, title, description, completed, status, color, days, weeks, start_date, started_at, paused_at, completed_at FROM feature WHERE quarter_id = ?1 ORDER BY sort_order").unwrap();
        let features: Vec<Feature> = f_stmt.query_map(rusqlite::params![qid], |row| {
            let fid: String = row.get(0)?;
            let mut s_stmt = conn.prepare("SELECT id, title, description, completed, status, color, started_at, completed_at FROM subtask WHERE feature_id = ?1 ORDER BY sort_order").unwrap();
            let subtasks: Vec<Subtask> = s_stmt
                .query_map(rusqlite::params![fid.clone()], |s_row| {
                    let s_completed: i32 = s_row.get(3)?;
                    Ok(Subtask {
                        id: s_row.get(0)?,
                        title: s_row.get(1)?,
                        description: s_row.get(2)?,
                        completed: s_completed != 0,
                        status: s_row.get(4)?,
                        color: s_row.get(5)?,
                        started_at: s_row.get(6)?,
                        completed_at: s_row.get(7)?,
                    })
                })
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();
            let completed: i32 = row.get(3)?;
            let days: Option<i32> = row.get(6)?;
            let weeks: Option<i32> = row.get(7)?;
            let start_date: Option<String> = row.get(8)?;
            let started_at: Option<String> = row.get(9)?;
            let paused_at: Option<String> = row.get(10)?;
            let completed_at: Option<String> = row.get(11)?;
            Ok(Feature {
                id: fid,
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
                subtasks,
            })
        }).unwrap().filter_map(|r| r.ok()).collect();
        quarters.push(Quarter { year, quarter, features, status_view: sv != 0, hide_not_progressing: hnp != 0 });
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
        "INSERT INTO org_user (link_id, org_id, display_name, role, created_at, updated_at) VALUES (?1, ?2, 'Owner', 'owner', ?3, ?4)",
        rusqlite::params![generate_user_link_id(), org_id, now, now],
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
    db_set_org_sync_state(conn, org_id, false, true);
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
        "SELECT id, org_id, display_name, role, is_ai, created_at, updated_at FROM org_user WHERE org_id = ?1 ORDER BY id",
    ).unwrap();
    let rows = stmt.query_map(rusqlite::params![org_id], |row| {
        Ok(OrgUser {
            id: row.get(0)?,
            org_id: row.get(1)?,
            display_name: row.get(2)?,
            role: row.get(3)?,
            is_ai: row.get::<_, i64>(4)? != 0,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
        })
    }).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_add_org_user(conn: &Connection, org_id: i64, display_name: &str, role: &str) -> i64 {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT INTO org_user (link_id, org_id, display_name, role, is_ai, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
        rusqlite::params![generate_user_link_id(), org_id, display_name, role, now, now],
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
                "UPDATE org_user SET role = 'leader', updated_at = ?1 WHERE id = ?2",
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
    let user_link_id: String = conn
        .query_row(
            "SELECT COALESCE(NULLIF(link_id, ''), 'usr-' || id) FROM org_user WHERE id = ?1",
            rusqlite::params![user_id],
            |row| row.get(0),
        )
        .unwrap_or_default();
    conn.execute(
        "INSERT INTO task_assignment (feature_id, user_id, user_link_id, status, assigned_at, updated_at) VALUES (?1, ?2, ?3, 'Assigned', ?4, ?5)",
        rusqlite::params![feature_id, user_id, user_link_id, now, now],
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

fn db_load_org_roadmap_links(conn: &Connection, org_id: i64) -> Vec<i64> {
    let mut stmt = conn.prepare("SELECT roadmap_id FROM org_roadmap WHERE org_id = ?1").unwrap();
    let rows = stmt.query_map(rusqlite::params![org_id], |row| row.get(0)).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_set_org_roadmap_links(conn: &Connection, org_id: i64, roadmap_ids: &[i64]) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute("DELETE FROM org_roadmap WHERE org_id = ?1", rusqlite::params![org_id]).unwrap();
    for rid in roadmap_ids {
        conn.execute(
            "INSERT INTO org_roadmap (org_id, roadmap_id, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![org_id, rid, now],
        ).unwrap();
    }
}

fn db_load_org_roadmap_editors(conn: &Connection, org_id: i64) -> std::collections::HashSet<i64> {
    let mut stmt = conn.prepare(
        "SELECT user_id FROM org_roadmap_editor WHERE org_id = ?1 AND can_edit = 1",
    ).unwrap();
    let rows = stmt.query_map(rusqlite::params![org_id], |row| row.get(0)).unwrap();
    rows.filter_map(|r| r.ok()).collect()
}

fn db_set_org_roadmap_editors(conn: &Connection, org_id: i64, editor_ids: &std::collections::HashSet<i64>) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute("DELETE FROM org_roadmap_editor WHERE org_id = ?1", rusqlite::params![org_id]).unwrap();
    for user_id in editor_ids {
        conn.execute(
            "INSERT INTO org_roadmap_editor (org_id, user_id, can_edit, updated_at) VALUES (?1, ?2, 1, ?3)",
            rusqlite::params![org_id, user_id, now],
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
struct OrgSyncState {
    joined: bool,
    is_owner: bool,
}

fn db_load_org_sync_state(conn: &Connection, org_id: i64) -> OrgSyncState {
    conn.query_row(
        "SELECT joined, is_owner FROM org_sync WHERE org_id = ?1",
        rusqlite::params![org_id],
        |row| {
            Ok(OrgSyncState {
                joined: row.get::<_, i64>(0)? != 0,
                is_owner: row.get::<_, i64>(1)? != 0,
            })
        },
    ).unwrap_or(OrgSyncState {
        joined: false,
        is_owner: true,
    })
}

fn db_set_org_sync_state(conn: &Connection, org_id: i64, joined: bool, is_owner: bool) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT INTO org_sync (org_id, joined, is_owner, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(org_id) DO UPDATE SET joined = excluded.joined, is_owner = excluded.is_owner, updated_at = excluded.updated_at",
        rusqlite::params![org_id, if joined { 1 } else { 0 }, if is_owner { 1 } else { 0 }, now],
    ).unwrap();
}

fn db_load_org_tokens(conn: &Connection, org_id: i64) -> (Option<String>, Option<String>) {
    conn.query_row(
        "SELECT token, owner_token FROM org_sync WHERE org_id = ?1",
        rusqlite::params![org_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).unwrap_or((None, None))
}

fn db_save_org_tokens(conn: &Connection, org_id: i64, token: &str, owner_token: &str) {
    let now = chrono::Local::now().to_rfc3339();
    conn.execute(
        "INSERT INTO org_sync (org_id, token, owner_token, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(org_id) DO UPDATE SET token = excluded.token, owner_token = excluded.owner_token, updated_at = excluded.updated_at",
        rusqlite::params![org_id, token, owner_token, now],
    ).unwrap();
}

const SYNC_KEYCHAIN_SERVICE: &str = "allroads-sync";

fn sync_keyring_entry(org_id: i64, kind: &str) -> keyring::Entry {
    let username = format!("org-{}-{}", org_id, kind);
    keyring::Entry::new(SYNC_KEYCHAIN_SERVICE, &username).expect("Failed to create keyring entry")
}

fn load_sync_token(use_keychain: bool, conn: &Connection, org_id: i64, kind: &str) -> Option<String> {
    if use_keychain {
        let entry = sync_keyring_entry(org_id, kind);
        entry.get_password().ok()
    } else {
        let (token, owner_token) = db_load_org_tokens(conn, org_id);
        if kind == "owner" { owner_token } else { token }
    }
}

fn save_sync_token(use_keychain: bool, conn: &Connection, org_id: i64, token: &str, owner_token: &str) {
    if use_keychain {
        let entry = sync_keyring_entry(org_id, "token");
        let _ = entry.set_password(token);
        let entry = sync_keyring_entry(org_id, "owner");
        let _ = entry.set_password(owner_token);
    } else {
        db_save_org_tokens(conn, org_id, token, owner_token);
    }
}

#[derive(Clone, Debug)]
struct NetworkConfig {
    node_id: String,
    server_url: String,
    server_node_id: String,
    use_proxy: bool,
    proxy_mode: String,
    proxy_url: String,
}

fn db_load_sync_config(conn: &Connection) -> NetworkConfig {
    conn.query_row(
        "SELECT node_id, server_url, server_node_id, use_proxy, proxy_mode, proxy_url FROM sync_config WHERE id = 1",
        [],
        |row| {
            Ok(NetworkConfig {
                node_id: row.get(0)?,
                server_url: row.get(1)?,
                server_node_id: row.get(2)?,
                use_proxy: row.get::<_, i64>(3)? != 0,
                proxy_mode: row.get(4)?,
                proxy_url: row.get(5)?,
            })
        },
    ).unwrap_or_else(|_| NetworkConfig {
        node_id: String::new(),
        server_url: "wss://obsidian.st:59901".to_string(),
        server_node_id: String::new(),
        use_proxy: false,
        proxy_mode: "none".to_string(),
        proxy_url: String::new(),
    })
}

fn db_save_sync_config(conn: &Connection, cfg: &NetworkConfig) {
    conn.execute(
        "INSERT INTO sync_config (id, node_id, server_url, server_node_id, use_proxy, proxy_mode, proxy_url)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET node_id = excluded.node_id, server_url = excluded.server_url, server_node_id = excluded.server_node_id, use_proxy = excluded.use_proxy, proxy_mode = excluded.proxy_mode, proxy_url = excluded.proxy_url",
        rusqlite::params![cfg.node_id, cfg.server_url, cfg.server_node_id, if cfg.use_proxy { 1 } else { 0 }, cfg.proxy_mode, cfg.proxy_url],
    ).unwrap();
}

#[derive(Clone, Debug)]
struct Quarter {
    year: u32,
    quarter: u32,
    features: Vec<Feature>,
    status_view: bool,
    hide_not_progressing: bool,
}

impl Quarter {
    fn new(year: u32, quarter: u32) -> Self {
        Self { year, quarter, features: Vec::new(), status_view: false, hide_not_progressing: true }
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
    is_ai: bool,
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

enum SyncEvent {
    Status(String),
    Auth { org_id: i64, is_owner: bool, server_node_id: String },
    TokenRotated { org_id: i64, token: String, user_id: Option<i64> },
    SnapshotApplied { org_id: i64 },
    Stopped,
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

struct CompletionDialogState {
    quarter_idx: usize,
    feature_idx: usize,
    notes: String,
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
            ui.add(egui::TextEdit::singleline(&mut self.title).desired_width(380.0));
            ui.add_space(4.0);

            ui.label("Description:");
            ui.add(egui::TextEdit::multiline(&mut self.description).desired_rows(6).desired_width(380.0));
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
                        ui.painter().rect_stroke(rect, 2.0, egui::Stroke::new(2.0_f32, egui::Color32::WHITE), egui::StrokeKind::Inside);
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
            subtasks: Vec::new(),
        })
    }
}

struct SubtaskDialogState {
    title: String,
    description: String,
    status: String,
    color: String,
    started_at: Option<String>,
    completed_at: Option<String>,
}

impl Default for SubtaskDialogState {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            status: "Planned".into(),
            color: "#9E9E9E".into(),
            started_at: None,
            completed_at: None,
        }
    }
}

impl SubtaskDialogState {
    fn from_subtask(t: &Subtask) -> Self {
        Self {
            title: t.title.clone(),
            description: t.description.clone(),
            status: t.status.clone(),
            color: t.color.clone(),
            started_at: t.started_at.clone(),
            completed_at: t.completed_at.clone(),
        }
    }

    fn show(&mut self, ui: &mut egui::Ui) -> bool {
        let mut ok = false;
        ui.vertical(|ui| {
            ui.label("Title:");
            ui.add(egui::TextEdit::singleline(&mut self.title).desired_width(320.0));
            ui.add_space(4.0);
            ui.label("Description:");
            ui.add(egui::TextEdit::multiline(&mut self.description).desired_rows(4).desired_width(320.0));
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
            ui.label("Color:");
            ui.horizontal(|ui| {
                let colors = [
                    ("#F44336", egui::Color32::from_rgb(244, 67, 54)),
                    ("#FF9800", egui::Color32::from_rgb(255, 152, 0)),
                    ("#FFEB3B", egui::Color32::from_rgb(255, 235, 59)),
                    ("#4CAF50", egui::Color32::from_rgb(76, 175, 80)),
                    ("#2196F3", egui::Color32::from_rgb(33, 150, 243)),
                    ("#9C27B0", egui::Color32::from_rgb(156, 39, 176)),
                    ("#E91E63", egui::Color32::from_rgb(233, 30, 99)),
                    ("#00BCD4", egui::Color32::from_rgb(0, 188, 212)),
                    ("#FFFFFF", egui::Color32::from_rgb(255, 255, 255)),
                    ("#9E9E9E", egui::Color32::from_rgb(158, 158, 158)),
                ];
                for (hex, egui_color) in &colors {
                    let (rect, response) = ui.allocate_exact_size(
                        egui::vec2(20.0, 20.0),
                        egui::Sense::click(),
                    );
                    ui.painter().rect_filled(rect, 2.0, *egui_color);
                    if self.color == *hex {
                        ui.painter().rect_stroke(rect, 2.0, egui::Stroke::new(2.0_f32, egui::Color32::WHITE), egui::StrokeKind::Inside);
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
                ui.add(egui::TextEdit::singleline(&mut self.color).desired_width(90.0));
            });
            if ui.button("OK").clicked() {
                ok = true;
            }
        });
        ok
    }

    fn to_subtask(&self, id: &str) -> Option<Subtask> {
        if self.title.trim().is_empty() {
            return None;
        }
        Some(Subtask {
            id: id.to_string(),
            title: self.title.trim().to_string(),
            description: self.description.trim().to_string(),
            completed: self.status == "Completed",
            status: self.status.clone(),
            color: self.color.clone(),
            started_at: self.started_at.clone(),
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
    AddSubtask {
        quarter_idx: usize,
        feature_idx: usize,
        dialog: SubtaskDialogState,
    },
    EditSubtask {
        quarter_idx: usize,
        feature_idx: usize,
        subtask_idx: usize,
        dialog: SubtaskDialogState,
    },
}

enum DialogAction {
    OpenAddFeature(usize),
    OpenEditFeature(usize, usize),
    OpenAddSubtask(usize, usize),
    OpenEditSubtask(usize, usize, usize),
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
        owner_token: String,
        roadmap_ids: Vec<i64>,
        roadmap_editors: std::collections::HashSet<i64>,
    },
    JoinOrg {
        token: String,
    },
    JoinSharedRoadmap {
        token: String,
    },
    ConfirmRemoveMember {
        user_id: i64,
        display_name: String,
    },
    ShareCurrentRoadmap,
    Migration {
        owner_token: String,
        old_server_url: String,
        new_server_url: String,
        org_id: i64,
        target_server_identity: String,
    },
    ShowToken {
        title: String,
        token: String,
    },
}

#[derive(Clone, Copy)]
enum NetworkSettingsView {
    Server,
    Proxy,
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
    timeline_visible_roadmap_buttons: bool,
    timeline_roadmap_buttons_close_at: Option<std::time::Instant>,
    org_list: Vec<Org>,
    current_org_id: Option<i64>,
    org_members: Vec<OrgUser>,
    org_chart_links: Vec<OrgChartLink>,
    org_settings: OrgSettings,
    org_joined: bool,
    org_is_owner: bool,
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
    sync_config: NetworkConfig,
    network_edit_config: NetworkConfig,
    show_network_settings: bool,
    network_settings_view: NetworkSettingsView,
    sync_running: bool,
    sync_status_rx: Option<mpsc::Receiver<SyncEvent>>,
    sync_stop_flag: Option<Arc<AtomicBool>>,
    sync_pending_send: Arc<AtomicBool>,
    sync_pending_token: Arc<Mutex<Option<PendingTokenRotation>>>,
    pending_server_switch_url: Option<String>,
    completion_dialog: Option<CompletionDialogState>,
    status_text_set_at: Option<std::time::Instant>,
    status_text_value: Option<String>,
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
        let mut sync_config = db_load_sync_config(&conn);
        if sync_config.node_id.trim().is_empty() {
            sync_config.node_id = generate_node_id();
            db_save_sync_config(&conn, &sync_config);
        }
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
            timeline_visible_roadmap_buttons: false,
            timeline_roadmap_buttons_close_at: None,
            org_list,
            current_org_id: None,
            org_members: Vec::new(),
            org_chart_links: Vec::new(),
            org_settings: OrgSettings {
                org_id: 0,
                mode: "hierarchy".into(),
                updated_at: String::new(),
            },
            org_joined: false,
            org_is_owner: true,
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
            sync_config: sync_config.clone(),
            network_edit_config: sync_config,
            show_network_settings: false,
            network_settings_view: NetworkSettingsView::Server,
            sync_running: false,
            sync_status_rx: None,
            sync_stop_flag: None,
            sync_pending_send: Arc::new(AtomicBool::new(false)),
            sync_pending_token: Arc::new(Mutex::new(None)),
            pending_server_switch_url: None,
                    completion_dialog: None,
            status_text_set_at: None,
            status_text_value: None,
        };
        if let Some((id, name)) = app.roadmap_list.first().cloned() {
            app.current_roadmap_id = Some(id);
            app.quarters = db_load_roadmap(&app.db, id);
            app.status_text = format!("Opened: {}", name);
        } else {
            app.initialize_quarters();
            app.new_roadmap_name = "default".into();
        }
        if let Some(first_org) = app.org_list.first() {
            app.current_org_id = Some(first_org.id);
            app.org_members = db_load_org_users(&app.db, first_org.id);
            app.org_chart_links = db_load_org_chart(&app.db, first_org.id);
            app.org_settings = db_load_org_settings(&app.db, first_org.id);
            app.org_selected_user_id = db_org_owner_id(&app.db, first_org.id);
            let sync_state = db_load_org_sync_state(&app.db, first_org.id);
            app.org_joined = sync_state.joined;
            app.org_is_owner = sync_state.is_owner;
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
                        "INSERT INTO org_user (id, link_id, org_id, display_name, role, is_ai, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        rusqlite::params![m.id, format!("usr-{}", m.id), m.org_id, m.display_name, m.role, if m.is_ai { 1 } else { 0 }, m.created_at, m.updated_at],
                    ).ok();
                } else {
                    self.db.execute(
                        "UPDATE org_user SET display_name = ?1, role = ?2, is_ai = ?3, updated_at = ?4 WHERE id = ?5",
                        rusqlite::params![m.display_name, m.role, if m.is_ai { 1 } else { 0 }, m.updated_at, m.id],
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

        match open_connection_at_path(&new_path, want_encrypted, use_keychain) {
            Ok((new_conn, _)) => {
                new_conn.execute_batch("PRAGMA foreign_keys = OFF").ok();
                copy_table(&self.db, &new_conn, "roadmap", &["id", "name", "created_at", "updated_at"]);
                copy_table(&self.db, &new_conn, "quarter", &["id", "roadmap_id", "year", "quarter", "sort_order"]);
                copy_table(&self.db, &new_conn, "feature", &["id", "quarter_id", "title", "description", "completed", "status", "color", "sort_order", "days", "weeks", "start_date", "started_at", "paused_at", "completed_at"]);
                copy_table(&self.db, &new_conn, "subtask", &["id", "feature_id", "title", "description", "completed", "status", "color", "sort_order", "started_at", "completed_at"]);
                copy_table(&self.db, &new_conn, "org", &["id", "name", "owner_token", "created_at", "updated_at"]);
                copy_table(&self.db, &new_conn, "org_settings", &["org_id", "mode", "updated_at"]);
                copy_table(&self.db, &new_conn, "org_sync", &["org_id", "joined", "is_owner", "token", "owner_token", "updated_at"]);
                copy_table(&self.db, &new_conn, "org_user", &["id", "link_id", "org_id", "display_name", "role", "is_ai", "created_at", "updated_at"]);
                copy_table(&self.db, &new_conn, "org_owner", &["org_id", "owner_user_id", "created_at"]);
                copy_table(&self.db, &new_conn, "org_roadmap", &["org_id", "roadmap_id", "created_at"]);
                copy_table(&self.db, &new_conn, "org_chart", &["id", "org_id", "manager_id", "report_id", "created_at"]);
                copy_table(&self.db, &new_conn, "org_roadmap_editor", &["org_id", "user_id", "can_edit", "updated_at"]);
                copy_table(&self.db, &new_conn, "task_assignment", &["id", "feature_id", "user_id", "user_link_id", "status", "assigned_at", "updated_at"]);
                copy_table(&self.db, &new_conn, "sync_config", &["id", "node_id", "server_url", "server_node_id", "use_proxy", "proxy_mode", "proxy_url"]);
                new_conn.execute_batch("PRAGMA foreign_keys = ON").ok();

                new_conn.close().unwrap();

                let old_db = std::mem::replace(&mut self.db, Connection::open_in_memory().unwrap());
                drop(old_db);

                let old_path = db_path();
                let _ = std::fs::remove_file(&old_path);
                std::fs::rename(&new_path, &old_path).unwrap();

                match open_connection(want_encrypted, use_keychain) {
                    Ok((conn, key)) => {
                        self.encrypted = want_encrypted;
                        self.db = conn;
                        self.db_key = key;
                        self.roadmap_list = db_list_roadmaps(&self.db);
                        self.org_list = db_list_orgs(&self.db);
                        if let Some(org_id) = self.current_org_id {
                            self.org_members = db_load_org_users(&self.db, org_id);
                            self.org_chart_links = db_load_org_chart(&self.db, org_id);
                        }
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
        if !has_features && self.org_list.is_empty() {
            self.status_text = "No features to save".into();
            return;
        }
        if let Some(id) = self.current_roadmap_id {
            db_save_roadmap(&self.db, id, &self.quarters);
            self.status_text = "Saved".into();
            self.sync_pending_send.store(true, Ordering::Relaxed);
        } else {
            let name = if self.new_roadmap_name.trim().is_empty() { "new_roadmap".to_string() } else { self.new_roadmap_name.trim().to_string() };
            let id = db_create_roadmap(&self.db, &name);
            db_save_roadmap(&self.db, id, &self.quarters);
            self.current_roadmap_id = Some(id);
            self.roadmap_list = db_list_roadmaps(&self.db);
            self.status_text = format!("Created roadmap and saved: {}", name);
            self.sync_pending_send.store(true, Ordering::Relaxed);
        }
        if !self.offline && !self.sync_running && self.current_org_id.is_some() {
            self.start_sync_worker();
        }
    }

    fn can_edit_org(&self) -> bool {
        if !self.org_joined {
            return true;
        }
        self.org_is_owner
    }

    fn ensure_can_edit_org(&mut self) -> bool {
        if self.can_edit_org() {
            true
        } else {
            self.status_text = "Owner required for synced org".into();
            false
        }
    }

    fn poll_sync_events(&mut self) {
        let mut stopped = false;
        if let Some(rx) = self.sync_status_rx.as_mut() {
            while let Ok(event) = rx.try_recv() {
                match event {
                    SyncEvent::Status(text) => {
                        self.status_text = text;
                        if let Some(url) = extract_migration_switch_url(&self.status_text) {
                            self.pending_server_switch_url = Some(url);
                        }
                    }
                    SyncEvent::Auth { org_id, is_owner, server_node_id } => {
                        db_set_org_sync_state(&self.db, org_id, true, is_owner);
                        if !server_node_id.trim().is_empty() && self.sync_config.server_node_id != server_node_id {
                            self.sync_config.server_node_id = server_node_id.clone();
                            self.network_edit_config.server_node_id = server_node_id;
                            db_save_sync_config(&self.db, &self.sync_config);
                        }
                        if self.current_org_id == Some(org_id) {
                            let sync_state = db_load_org_sync_state(&self.db, org_id);
                            self.org_joined = sync_state.joined;
                            self.org_is_owner = sync_state.is_owner;
                        }
                    }
                    SyncEvent::TokenRotated { org_id, token, user_id } => {
                        if user_id.is_none() {
                            let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner").unwrap_or_default();
                            save_sync_token(self.use_keychain, &self.db, org_id, &token, &owner_token);
                        }
                        if self.current_org_id == Some(org_id) {
                            self.status_text = "User token updated".into();
                        }
                    }
                    SyncEvent::SnapshotApplied { org_id } => {
                        if let Ok((conn, _)) = open_connection(self.encrypted, self.use_keychain) {
                            self.db = conn;
                            self.roadmap_list = db_list_roadmaps(&self.db);
                            self.org_list = db_list_orgs(&self.db);
                            if self.current_org_id == Some(org_id) {
                                self.org_members = db_load_org_users(&self.db, org_id);
                                self.org_chart_links = db_load_org_chart(&self.db, org_id);
                                self.org_settings = db_load_org_settings(&self.db, org_id);
                            }
                            if let Some(rid) = self.current_roadmap_id {
                                self.quarters = db_load_roadmap(&self.db, rid);
                            }
                        }
                    }
                    SyncEvent::Stopped => {
                        stopped = true;
                    }
                }
            }
        }
        if stopped {
            self.sync_running = false;
            self.sync_status_rx = None;
            self.sync_stop_flag = None;
        }
    }

    fn sync_table_specs() -> Vec<TableSpec> {
        vec![
            TableSpec {
                name: "roadmap".to_string(),
                primary_key: "id".to_string(),
                columns: vec!["id", "name", "created_at", "updated_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "quarter".to_string(),
                primary_key: "id".to_string(),
                columns: vec!["id", "roadmap_id", "year", "quarter", "sort_order"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "feature".to_string(),
                primary_key: "id".to_string(),
                columns: vec![
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
                ]
                .into_iter()
                .map(String::from)
                .collect(),
            },
            TableSpec {
                name: "subtask".to_string(),
                primary_key: "id".to_string(),
                columns: vec![
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
                ]
                .into_iter()
                .map(String::from)
                .collect(),
            },
            TableSpec {
                name: "org".to_string(),
                primary_key: "id".to_string(),
                columns: vec!["id", "name", "created_at", "updated_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "org_settings".to_string(),
                primary_key: "org_id".to_string(),
                columns: vec!["org_id", "mode", "updated_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "org_user".to_string(),
                primary_key: "id".to_string(),
                columns: vec!["id", "link_id", "org_id", "display_name", "role", "is_ai", "created_at", "updated_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "org_owner".to_string(),
                primary_key: "org_id".to_string(),
                columns: vec!["org_id", "owner_user_id", "created_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "org_roadmap".to_string(),
                primary_key: "org_id".to_string(),
                columns: vec!["org_id", "roadmap_id", "created_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "org_chart".to_string(),
                primary_key: "id".to_string(),
                columns: vec!["id", "org_id", "manager_id", "report_id", "created_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "org_roadmap_editor".to_string(),
                primary_key: "user_id".to_string(),
                columns: vec!["org_id", "user_id", "can_edit", "updated_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
            TableSpec {
                name: "task_assignment".to_string(),
                primary_key: "id".to_string(),
                columns: vec!["id", "feature_id", "user_id", "user_link_id", "status", "assigned_at", "updated_at"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            },
        ]
    }

    fn build_sync_engine(&self) -> Result<SyncEngine, String> {
        let db_key = self.db_key.clone().ok_or_else(|| "Missing encryption key".to_string())?;
        let cfg = EngineSyncConfig {
            db_path: db_path().to_string_lossy().to_string(),
            node_id: self.sync_config.node_id.clone(),
            encryption_key: db_key,
            tables: Self::sync_table_specs(),
            max_orgs: 5,
        };
        Ok(SyncEngine::new(cfg))
    }


    fn sync_now(&mut self) {
        self.sync_once();
    }

    fn sync_once(&mut self) {
        if !self.encrypted {
            self.status_text = "Enable encryption before syncing".into();
            return;
        }
        let Some(org_id) = self.current_org_id else {
            self.status_text = "No organization selected".into();
            return;
        };
        let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner")
            .and_then(|t| if t.trim().is_empty() { None } else { Some(t) });
        let mut token = load_sync_token(self.use_keychain, &self.db, org_id, "token").unwrap_or_default();
        if token.trim().is_empty() {
            if owner_token.is_some() && !self.org_joined {
                token = generate_user_token();
                let owner_token_value = owner_token.clone().unwrap_or_default();
                save_sync_token(self.use_keychain, &self.db, org_id, &token, &owner_token_value);
                if let Ok(mut guard) = self.sync_pending_token.lock() {
                    *guard = Some(PendingTokenRotation {
                        token: token.clone(),
                        user_id: None,
                    });
                }
                self.status_text = "Generated user token for first sync".into();
            } else {
                self.status_text = "User token required (owner generates)".into();
                return;
            }
        }
        let network_config = self.sync_config.clone();
        let engine = match self.build_sync_engine() {
            Ok(engine) => engine,
            Err(err) => {
                self.status_text = err;
                return;
            }
        };
        let result = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| {
                let engine = Arc::new(engine);
                let pending_token = self.sync_pending_token.clone();
                let request_snapshot = !self.org_joined && !self.org_is_owner;
                rt.block_on(async move {
                    let (status_tx, _status_rx) = mpsc::channel();
                    run_sync_once(engine, &network_config, org_id, token, owner_token, &status_tx, pending_token, request_snapshot).await
                })
            });
        match result {
            Ok(is_owner) => {
                db_set_org_sync_state(&self.db, org_id, true, is_owner);
                self.org_list = db_list_orgs(&self.db);
                self.org_members = db_load_org_users(&self.db, org_id);
                self.org_chart_links = db_load_org_chart(&self.db, org_id);
                self.org_settings = db_load_org_settings(&self.db, org_id);
                let sync_state = db_load_org_sync_state(&self.db, org_id);
                self.org_joined = sync_state.joined;
                self.org_is_owner = sync_state.is_owner;
                if let Some(rid) = self.current_roadmap_id {
                    self.quarters = db_load_roadmap(&self.db, rid);
                }
                self.status_text = "Sync complete".into();
            }
            Err(err) => {
                self.status_text = format!("Sync failed: {}", err);
                if let Some(url) = extract_migration_switch_url(&self.status_text) {
                    self.pending_server_switch_url = Some(url);
                }
            }
        }
    }

    fn stop_sync_worker(&mut self) {
        if let Some(flag) = &self.sync_stop_flag {
            flag.store(true, Ordering::Relaxed);
        }
        self.sync_running = false;
    }

    fn start_sync_worker(&mut self) {
        if self.sync_running {
            return;
        }
        if self.offline {
            self.status_text = "Offline mode enabled".into();
            return;
        }
        if !self.encrypted {
            self.status_text = "Enable encryption before syncing".into();
            return;
        }
        let Some(org_id) = self.current_org_id else {
            self.status_text = "No organization selected".into();
            return;
        };
        let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner")
            .and_then(|t| if t.trim().is_empty() { None } else { Some(t) });
        let mut token = load_sync_token(self.use_keychain, &self.db, org_id, "token").unwrap_or_default();
        if token.trim().is_empty() {
            if owner_token.is_some() && !self.org_joined {
                token = generate_user_token();
                let owner_token_value = owner_token.clone().unwrap_or_default();
                save_sync_token(self.use_keychain, &self.db, org_id, &token, &owner_token_value);
                if let Ok(mut guard) = self.sync_pending_token.lock() {
                    *guard = Some(PendingTokenRotation {
                        token: token.clone(),
                        user_id: None,
                    });
                }
                self.status_text = "Generated user token for first sync".into();
            } else {
                self.status_text = "User token required (owner generates)".into();
                return;
            }
        }
        let network_config = self.sync_config.clone();
        let engine = match self.build_sync_engine() {
            Ok(engine) => engine,
            Err(err) => {
                self.status_text = err;
                return;
            }
        };
        let (status_tx, status_rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let stop_flag_thread = stop_flag.clone();
        let pending_flag = self.sync_pending_send.clone();
        let pending_token = self.sync_pending_token.clone();
        let request_snapshot = !self.org_joined && !self.org_is_owner;
        self.sync_status_rx = Some(status_rx);
        self.sync_stop_flag = Some(stop_flag);
        self.sync_running = true;

        thread::spawn(move || {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(err) => {
                    let _ = status_tx.send(SyncEvent::Status(format!("Sync failed: {}", err)));
                    let _ = status_tx.send(SyncEvent::Stopped);
                    return;
                }
            };
            let engine = Arc::new(engine);
            rt.block_on(async move {
                let mut need_snapshot = request_snapshot;
                loop {
                    if stop_flag_thread.load(Ordering::Relaxed) {
                        let _ = status_tx.send(SyncEvent::Stopped);
                        break;
                    }
                    let result = run_sync_session(
                        engine.clone(),
                        &network_config,
                        org_id,
                        token.clone(),
                        owner_token.clone(),
                        &status_tx,
                        stop_flag_thread.clone(),
                        pending_flag.clone(),
                        pending_token.clone(),
                        need_snapshot,
                    )
                    .await;
                    if let Err(err) = result {
                        if err.contains("FOREIGN KEY constraint failed") {
                            need_snapshot = true;
                        }
                        let _ = status_tx.send(SyncEvent::Status(format!("Sync error: {}", err)));
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    } else {
                        need_snapshot = false;
                    }
                }
            });
        });
    }

    fn share_current_roadmap(&mut self) {
        if !self.encrypted {
            self.status_text = "Enable encryption before sharing roadmap".into();
            return;
        }
        let Some(org_id) = self.current_org_id else {
            self.status_text = "No organization selected".into();
            return;
        };
        let Some(roadmap_id) = self.current_roadmap_id else {
            self.status_text = "No roadmap selected".into();
            return;
        };
        let token = load_sync_token(self.use_keychain, &self.db, org_id, "token").unwrap_or_default();
        if token.trim().is_empty() {
            self.status_text = "User token required".into();
            return;
        }
        let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner")
            .and_then(|t| if t.trim().is_empty() { None } else { Some(t) });
        let engine = match self.build_sync_engine() {
            Ok(engine) => Arc::new(engine),
            Err(err) => {
                self.status_text = err;
                return;
            }
        };
        let cfg = self.sync_config.clone();
        let result = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(async move { request_share_token(engine, &cfg, org_id, token, owner_token, roadmap_id).await }));
        match result {
            Ok(share_token) => {
                self.org_dialog_state = OrgDialogState::ShowToken {
                    title: "Roadmap Share Token".into(),
                    token: share_token,
                };
                self.status_text = "Share token generated".into();
            }
            Err(err) => {
                self.status_text = format!("Share token failed: {}", err);
            }
        }
    }

    fn open_shared_roadmap(&mut self, token: String) {
        if !self.encrypted {
            self.status_text = "Enable encryption before importing shared roadmap".into();
            return;
        }
        let cfg = self.sync_config.clone();
        let bytes_result = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| rt.block_on(async move { download_share_snapshot(&cfg, token).await }));
        let bytes = match bytes_result {
            Ok(bytes) => bytes,
            Err(err) => {
                self.status_text = format!("Shared roadmap fetch failed: {}", err);
                return;
            }
        };
        let engine = match self.build_sync_engine() {
            Ok(engine) => engine,
            Err(err) => {
                self.status_text = err;
                return;
            }
        };
        if let Err(err) = engine.import_snapshot(&bytes).map_err(|e| e.to_string()) {
            self.status_text = format!("Shared roadmap import failed: {}", err);
            return;
        }
        self.roadmap_list = db_list_roadmaps(&self.db);
        self.org_list = db_list_orgs(&self.db);
        if let Some((rid, _)) = self.roadmap_list.first().cloned() {
            self.current_roadmap_id = Some(rid);
            self.quarters = db_load_roadmap(&self.db, rid);
        }
        if let Some(org) = self.org_list.first() {
            self.current_org_id = Some(org.id);
            self.org_members = db_load_org_users(&self.db, org.id);
            self.org_chart_links = db_load_org_chart(&self.db, org.id);
            self.org_settings = db_load_org_settings(&self.db, org.id);
        }
        self.status_text = "Shared roadmap imported".into();
    }

    fn migrate_org(
        &mut self,
        owner_token: String,
        old_server_url: String,
        new_server_url: String,
        org_id: i64,
        target_server_identity: String,
    ) {
        if !self.encrypted {
            self.status_text = "Enable encryption before migration".into();
            return;
        }
        if owner_token.trim().is_empty() {
            self.status_text = "Owner token required for migration".into();
            return;
        }
        self.status_text = "Migration in progress...".into();

        let cfg = self.sync_config.clone();
        let result = tokio::runtime::Runtime::new()
            .map_err(|e| e.to_string())
            .and_then(|rt| {
                rt.block_on(async move {
                    request_org_migration_start(
                        &cfg,
                        owner_token,
                        old_server_url,
                        new_server_url.clone(),
                        org_id,
                        target_server_identity,
                    )
                    .await
                    .map(|_| new_server_url)
                })
            });

        match result {
            Ok(server_url) => {
                self.sync_config.server_url = server_url.clone();
                self.sync_config.server_node_id.clear();
                self.network_edit_config.server_url = server_url;
                self.network_edit_config.server_node_id.clear();
                db_save_sync_config(&self.db, &self.sync_config);
                db_set_org_sync_state(&self.db, org_id, false, false);
                if self.current_org_id == Some(org_id) {
                    let sync_state = db_load_org_sync_state(&self.db, org_id);
                    self.org_joined = sync_state.joined;
                    self.org_is_owner = sync_state.is_owner;
                    if self.sync_running {
                        self.stop_sync_worker();
                        self.start_sync_worker();
                    }
                }
                self.status_text = "Migration complete".into();
            }
            Err(err) => {
                self.status_text = format!("Migration failed: {}", err);
            }
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
        let existing_description = self.quarters[qi].features[fi].description.clone();
        self.completion_dialog = Some(CompletionDialogState {
            quarter_idx: qi,
            feature_idx: fi,
            notes: existing_description,
        });
    }

    fn apply_task_completion(&mut self, qi: usize, fi: usize, notes: String) {
        self.save_snapshot();
        let now = chrono::Local::now().to_rfc3339();
        let feature = &mut self.quarters[qi].features[fi];
        feature.completed_at = Some(now.clone());
        feature.completed = true;
        feature.status = "Completed".into();
        feature.description = notes;
        for subtask in feature.subtasks.iter_mut() {
            subtask.completed = true;
            subtask.status = "Completed".into();
            subtask.completed_at = Some(now.clone());
        }
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
                let feature_color = colors[i % colors.len()].to_string();
                let subtask_titles = get_template_subtasks(template_type, title);
                let subtasks = subtask_titles
                    .iter()
                    .enumerate()
                    .map(|(si, subtask_title)| Subtask {
                        id: format!("subtask_{}_{}_{}_{}", template_type, i, j, si),
                        title: (*subtask_title).to_string(),
                        description: format!("{} for {}", subtask_title, title),
                        completed: false,
                        status: "Planned".into(),
                        color: feature_color.clone(),
                        started_at: None,
                        completed_at: None,
                    })
                    .collect();
                q.features.push(Feature {
                    id: format!("feature_{}_{}_{}", template_type, i, j),
                    title: title.to_string(),
                    description: format!("Implementation of {}", title),
                    completed: false,
                    status: "Planned".into(),
                    color: feature_color,
                    days: None,
                    weeks: None,
                    start_date: None,
                    started_at: None,
                    paused_at: None,
                    completed_at: None,
                    subtasks,
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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_sync_events();
        let now = std::time::Instant::now();
        if self.status_text != "Ready" {
            let need_reset = match &self.status_text_value {
                None => true,
                Some(v) => v != &self.status_text,
            };
            if need_reset {
                self.status_text_set_at = Some(now);
                self.status_text_value = Some(self.status_text.clone());
            } else if let Some(set_at) = self.status_text_set_at {
                if now.duration_since(set_at) >= std::time::Duration::from_secs(10) {
                    self.status_text = "Ready".into();
                    self.status_text_set_at = None;
                    self.status_text_value = None;
                }
            }
        } else {
            self.status_text_set_at = None;
            self.status_text_value = None;
        }
        let ctx = ui.ctx().clone();
        egui::Panel::top("title_bar").show(ui, |ui| {
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

            egui::MenuBar::new().ui(ui, |ui| {
                ui.label(egui::RichText::new("allroads").strong().size(14.0));
                ui.add_space(16.0);
                ui.menu_button("File", |ui| {
                    if ui.button("New").clicked() { self.show_new_dialog = true; ui.close(); }
                    if ui.button("Open").clicked() { self.open_roadmap(); ui.close(); }
                    if ui.button("Save").clicked() { self.save_roadmap(); ui.close(); }
                    if ui.button("Exit").clicked() { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }
                    ui.separator();
                    ui.menu_button("Templates", |ui| {
                        if ui.button("Web Application").clicked() { self.load_template("web"); ui.close(); }
                        if ui.button("Mobile App").clicked() { self.load_template("mobile"); ui.close(); }
                        if ui.button("API Development").clicked() { self.load_template("api"); ui.close(); }
                    });
                });
                ui.menu_button("Edit", |ui| {
                    if ui.button("Undo").clicked() { self.undo(); ui.close(); }
                    if ui.button("Redo").clicked() { self.redo(); ui.close(); }
                    ui.separator();
                    if ui.button("Rename Roadmap").clicked() {
                        if let Some(id) = self.current_roadmap_id {
                            self.rename_roadmap_id = Some(id);
                            if let Some(name) = self.roadmap_list.iter().find(|(rid, _)| *rid == id).map(|(_, n)| n.clone()) {
                                self.rename_roadmap_name = name;
                            }
                        }
                        ui.close();
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
                            ui.close();
                        }
                        if ui.button("Create").clicked() {
                            self.org_dialog_state = OrgDialogState::CreateOrg { name: String::new() };
                            ui.close();
                        }
                        ui.separator();
                        if ui.button("Join").clicked() {
                            self.org_dialog_state = OrgDialogState::JoinOrg { token: String::new() };
                            ui.close();
                        }
                        if ui.button("Settings").clicked() {
                            if let Some(org_id) = self.current_org_id {
                                let owner_id = db_org_owner_id(&self.db, org_id);
                                let allow_edit = self.can_edit_org();
                                let org_name = self.org_list.iter().find(|o| o.id == org_id).map(|o| o.name.clone()).unwrap_or_default();
                                let settings = db_load_org_settings(&self.db, org_id);
                                let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner").unwrap_or_default();
                                let roadmap_ids = db_load_org_roadmap_links(&self.db, org_id);
                                let mut roadmap_editors = db_load_org_roadmap_editors(&self.db, org_id);
                                if roadmap_editors.is_empty() {
                                    for member in db_load_org_users(&self.db, org_id) {
                                        if matches!(member.role.as_str(), "owner" | "admin" | "leader") {
                                            roadmap_editors.insert(member.id);
                                        }
                                    }
                                }
                                self.org_dialog_state = OrgDialogState::Settings {
                                    org_id,
                                    name: org_name,
                                    owner_id,
                                    mode: settings.mode,
                                    allow_edit,
                                    owner_token,
                                    roadmap_ids,
                                    roadmap_editors,
                                };
                            } else {
                                self.status_text = "No organization selected".into();
                            }
                            ui.close();
                        }
                    });
                    ui.separator();
                    if ui.button("Open Shared Roadmap").clicked() {
                        self.org_dialog_state = OrgDialogState::JoinSharedRoadmap { token: String::new() };
                        ui.close();
                    }
                    if ui.button("Share Current Roadmap").clicked() {
                        self.org_dialog_state = OrgDialogState::ShareCurrentRoadmap;
                        ui.close();
                    }
                });
                ui.menu_button("View", |ui| {
                    if ui.button("Timeline").clicked() { self.switch_tab(Some("Timeline")); ui.close(); }
                    if ui.button("Org Chart").clicked() { self.switch_tab(Some("Org Chart")); ui.close(); }
                    if ui.button("Quarters").clicked() { self.switch_tab(Some("Quarters")); ui.close(); }
                    ui.separator();
                    ui.checkbox(&mut self.show_timeline_labels, "Show Labels");
                    ui.separator();
                    ui.menu_button("Quarters", |ui| {
                        let mut all_sv = self.quarters.iter().all(|q| q.status_view);
                        if ui.checkbox(&mut all_sv, "View by Status").changed() {
                            for q in &mut self.quarters { q.status_view = all_sv; }
                        }
                        let mut all_hide = self.quarters.iter().all(|q| q.hide_not_progressing);
                        if ui.checkbox(&mut all_hide, "Hide Not Progressing").changed() {
                            for q in &mut self.quarters { q.hide_not_progressing = all_hide; }
                        }
                    });
                });
                ui.menu_button("Network", |ui| {
                    if ui.checkbox(&mut self.offline, "Offline Mode").changed() {
                        if !self.offline && !self.encrypted {
                            self.offline = true;
                            self.status_text = "Enable encryption before networking".into();
                        } else if self.offline {
                            self.status_text = "Disabled networking".into();
                            self.stop_sync_worker();
                        } else {
                            self.status_text = "Enabled networking for this session".into();
                            self.start_sync_worker();
                        }
                    }
                    if ui.button("Proxy").clicked() {
                        self.network_edit_config = self.sync_config.clone();
                        self.network_settings_view = NetworkSettingsView::Proxy;
                        self.show_network_settings = true;
                        ui.close();
                    }
                    if ui.button("Server").clicked() {
                        self.network_edit_config = self.sync_config.clone();
                        self.network_settings_view = NetworkSettingsView::Server;
                        self.show_network_settings = true;
                        ui.close();
                    }
                    ui.separator();
                    if ui.button("Sync now").clicked() {
                        self.sync_now();
                        ui.close();
                    }
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

        egui::Panel::bottom("status_bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.colored_label(egui::Color32::GRAY, "v2.1.1");
                });
            });
        });

        egui::Panel::top("controls").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(&self.current_tab);
                ui.add_space(10.0);
                if ui.button("Add Quarter").clicked() { self.add_quarter(); }
                if ui.button("Clear All").clicked() { self.clear_all(); }
                if ui.button("Change View").clicked() { self.switch_tab(None); }
            });
        });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.current_tab == "Quarters" {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut dialog_action: Option<DialogAction> = None;
                    let mut remove_action: Option<(usize, usize)> = None;
                    let mut subtask_remove_action: Option<(usize, usize, usize)> = None;
                    let mut subtask_complete_action: Option<(usize, usize, usize)> = None;
                    let mut move_up_action: Option<(usize, usize)> = None;
                    let mut move_down_action: Option<(usize, usize)> = None;
                    let mut complete_action: Option<(usize, usize)> = None;
                    let mut start_action: Option<(usize, usize)> = None;
                    let mut pause_action: Option<(usize, usize)> = None;
                    let mut quarter_remove_idx: Option<usize> = None;
                    let mut status_move_action: Option<(usize, usize, i32)> = None;
                    let member_name_by_id: std::collections::HashMap<i64, String> = self
                        .org_members
                        .iter()
                        .map(|member| (member.id, member.display_name.clone()))
                        .collect();

                    for (qi, quarter) in &mut self.quarters.iter_mut().enumerate() {
                        let is_status_view = quarter.status_view;
                        let hide_np = quarter.hide_not_progressing;
                        egui::Frame::group(ui.style())
                            .stroke(egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(180, 180, 180)))
                            .show(ui, |ui| {
                                ui.vertical(|ui| {
                                    ui.horizontal(|ui| {
                                        ui.heading(quarter.name());
                                        ui.label(quarter.date_range());
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.small_button("x").clicked() {
                                                quarter_remove_idx = Some(qi);
                                            }
                                        });
                                    });
                                    ui.separator();

                                    if ui.button("+ Add Feature").clicked() {
                                        dialog_action = Some(DialogAction::OpenAddFeature(qi));
                                    }

                                    ui.add_space(4.0);

                                    if is_status_view {
                                        let col_labels = ["Planned", "Developing", "Testing", "Completed", "Not Progressing"];
                                        let num_cols = if hide_np { 4 } else { 5 };
                                        let status_col = |s: &str| -> usize {
                                            match s {
                                                "Planned" => 0,
                                                "Developing" => 1,
                                                "Testing" => 2,
                                                "Completed" => 3,
                                                _ => 4,
                                            }
                                        };
                                        let total_w = ui.available_width();
                                        let col_w = (total_w - num_cols as f32 * 7.0) / num_cols as f32;
                                        ui.horizontal(|ui| {
                                            for col in 0..num_cols {
                                                let count = quarter.features.iter().filter(|f| status_col(&f.status) == col).count();
                                                ui.allocate_ui_with_layout(
                                                    egui::vec2(col_w, ui.available_height()),
                                                    egui::Layout::top_down_justified(egui::Align::LEFT),
                                                    |ui| {
                                                        egui::Frame::new()
                                                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(180, 180, 180)))
                                                            .inner_margin(6.0)
                                                            .show(ui, |ui| {
                                                                ui.set_min_width(col_w - 16.0);
                                                                ui.heading(format!("{} ({})", col_labels[col], count));
                                                                ui.separator();
                                                                for (fi, feature) in quarter.features.iter().enumerate() {
                                                                    if status_col(&feature.status) != col { continue; }
                                                                    let color = parse_color(&feature.color);
                                                                    let feature_id = feature.id.clone();
                                                                    let feature_title = feature.title.clone();
                                                                    let feature_desc = feature.description.clone();
                                                                    let mut time_parts = Vec::new();
                                                                    if let Some(w) = feature.weeks { time_parts.push(format!("{}w", w)); }
                                                                    if let Some(d) = feature.days { time_parts.push(format!("{}d", d)); }
                                                                    let assigned = {
                                                                        let assignments = db_load_task_assignments(&self.db, &feature.id);
                                                                        let mut names: Vec<String> = assignments.iter().filter_map(|a| member_name_by_id.get(&a.user_id).cloned()).collect();
                                                                        names.sort(); names.dedup();
                                                                        names.join(", ")
                                                                    };
                                                                     let card_resp = egui::Frame::new()
                                                                         .stroke(egui::Stroke::new(0.5, egui::Color32::from_rgb(200, 200, 200)))
                                                                         .inner_margin(4.0)
                                                                         .show(ui, |ui| {
                                                                             let card_w = col_w - 26.0;
                                                                             ui.set_min_width(card_w);
                                                                             ui.set_max_width(card_w);
                                                                             ui.horizontal(|ui| {
                                                                                 let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 16.0), egui::Sense::hover());
                                                                                 ui.painter().rect_filled(rect, 0.0, color);
                                                                                 let btn_w = 28.0 * (1 + (col > 0) as u32 + (col < num_cols - 1) as u32) as f32;
                                                                                 let title_w = (card_w - 12.0 - btn_w).max(20.0);
                                                                                  ui.allocate_ui_with_layout(egui::vec2(title_w, 16.0), egui::Layout::left_to_right(egui::Align::Center), |ui| {
                                                                                      ui.set_min_width(title_w);
                                                                                      ui.set_max_width(title_w);
                                                                                      let title_display: String = if feature.title.chars().count() > 30 { feature.title.chars().take(30).collect::<String>() + "..." } else { feature.title.clone() };
                                                                                      if feature.completed {
                                                                                          ui.add(egui::Label::new(egui::RichText::new(title_display).color(egui::Color32::GRAY)).truncate());
                                                                                      } else {
                                                                                          ui.add(egui::Label::new(title_display).truncate());
                                                                                      }
                                                                                  });
                                                                                 if col > 0 {
                                                                                     if ui.small_button("<").clicked() {
                                                                                         status_move_action = Some((qi, fi, -1));
                                                                                     }
                                                                                 }
                                                                                 if col < num_cols - 1 {
                                                                                     if ui.small_button(">").clicked() {
                                                                                         status_move_action = Some((qi, fi, 1));
                                                                                     }
                                                                                 }
                                                                                 if ui.small_button("Edit").clicked() {
                                                                                     dialog_action = Some(DialogAction::OpenEditFeature(qi, fi));
                                                                                 }
                                                                             });
                                                                            if !feature_desc.trim().is_empty() {
                                                                                ui.add(egui::Label::new(egui::RichText::new(&feature_desc).color(egui::Color32::GRAY).size(11.0)).truncate());
                                                                            }
                                                                            ui.horizontal(|ui| {
                                                                                if !time_parts.is_empty() {
                                                                                    ui.label(egui::RichText::new(time_parts.join(" ")).color(egui::Color32::GRAY).size(11.0));
                                                                                }
                                                                                if !assigned.is_empty() {
                                                                                    ui.label(egui::RichText::new(assigned).color(egui::Color32::from_rgb(0, 188, 212)).size(11.0));
                                                                                }
                                                                            });
                                                                        });
                                                                    card_resp.response.context_menu(|ui| {
                                                                        if ui.button("Start").clicked() {
                                                                            start_action = Some((qi, fi));
                                                                            ui.close();
                                                                        }
                                                                        if ui.button("Pause").clicked() {
                                                                            pause_action = Some((qi, fi));
                                                                            ui.close();
                                                                        }
                                                                        ui.separator();
                                                                        if ui.button("Delete Feature").clicked() {
                                                                            remove_action = Some((qi, fi));
                                                                            ui.close();
                                                                        }
                                                                        if ui.button("Add Subtask").clicked() {
                                                                            dialog_action = Some(DialogAction::OpenAddSubtask(qi, fi));
                                                                            ui.close();
                                                                        }
                                                                        if ui.button("Assign Task").clicked() {
                                                                            self.task_assign_feature_id = Some(feature_id.clone());
                                                                            self.task_assign_feature_title = feature_title.clone();
                                                                            ui.close();
                                                                        }
                                                                    });
                                                                }
                                                            });
                                                    });
                                            }
                                        });
                                    } else {

                                    for (fi, feature) in quarter.features.iter().enumerate() {
                                        let assigned_display = {
                                            let assignments = db_load_task_assignments(&self.db, &feature.id);
                                            let mut names: Vec<String> = assignments
                                                .iter()
                                                .filter_map(|assignment| member_name_by_id.get(&assignment.user_id).cloned())
                                                .collect();
                                            names.sort();
                                            names.dedup();
                                            if names.is_empty() {
                                                String::new()
                                            } else {
                                                format!("{}", names.join(", "))
                                            }
                                        };
                                        egui::Frame::NONE
                                            .stroke(egui::Stroke::new(0.5_f32, egui::Color32::from_rgb(200, 200, 200)))
                                            .inner_margin(4.0)
                                            .outer_margin(0.0)
                                            .show(ui, |ui| {
                                            let available = ui.available_width();
                                            let feature_id = feature.id.clone();
                                            let feature_title = feature.title.clone();
                                            let feature_status = feature.status.clone();
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

                                                    let status_color = match feature.status.as_str() {
                                                        "Completed" => egui::Color32::from_rgb(76, 175, 80),
                                                        _ => egui::Color32::from_rgb(180, 180, 180),
                                                    };
                                                    let status_text: egui::RichText = if feature.status == "Completed" {
                                                        egui::RichText::new("\u{2714}")
                                                    } else {
                                                        egui::RichText::new(format!("{}", feature.status))
                                                    };
                                                    ui.colored_label(status_color, status_text);

                                                    let right_reserve = 300.0 + if assigned_display.is_empty() { 0.0 } else { assigned_display.len() as f32 * 8.0 + 20.0 };
                                                    let desc_width = (ui.available_width() - right_reserve).max(20.0);
                                                    ui.allocate_ui_with_layout(
                                                        egui::vec2(desc_width, 16.0),
                                                        egui::Layout::left_to_right(egui::Align::Center),
                                                        |ui| {
                                                            ui.add(egui::Label::new(egui::RichText::new(&feature.description).color(egui::Color32::GRAY)).truncate());
                                                        },
                                                    );

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
                                                        if ui.small_button("Edit").clicked() {
                                                            dialog_action = Some(DialogAction::OpenEditFeature(qi, fi));
                                                        }
                                                        if ui.small_button("Complete").clicked() {
                                                            complete_action = Some((qi, fi));
                                                        }
                                                        if !assigned_display.is_empty() {
                                                            ui.colored_label(egui::Color32::from_rgb(180, 180, 180), assigned_display.clone());
                                                        }
                                                    });
                                                });
                                            }).response;
                                            response.interact(egui::Sense::click()).context_menu(|ui| {
                                                if feature_status == "Planned" || feature_status == "Paused" || feature_status == "Stalled" || feature_status == "Blocked" {
                                                    if ui.button("Start").clicked() {
                                                        start_action = Some((qi, fi));
                                                        ui.close();
                                                    }
                                                }
                                                if feature_status == "Developing" {
                                                    if ui.button("Pause").clicked() {
                                                        pause_action = Some((qi, fi));
                                                        ui.close();
                                                    }
                                                }
                                                ui.separator();
                                                if ui.button("Delete Feature").clicked() {
                                                    remove_action = Some((qi, fi));
                                                    ui.close();
                                                }
                                                if ui.button("Add Subtask").clicked() {
                                                    dialog_action = Some(DialogAction::OpenAddSubtask(qi, fi));
                                                    ui.close();
                                                }
                                                if ui.button("Assign Task").clicked() {
                                                    self.task_assign_feature_id = Some(feature_id.clone());
                                                    self.task_assign_feature_title = feature_title.clone();
                                                    ui.close();
                                                }
                                            });
                                        });

                                        if !feature.subtasks.is_empty() {
                                            let line_indent = 4.0;
                                            let line_width = 12.0;
                                            let row_height = 28.0;
                                            let row_gap = 2.0;
                                            let total_height = (feature.subtasks.len() as f32 * row_height)
                                                + ((feature.subtasks.len().saturating_sub(1)) as f32 * row_gap);
                                            let line_color = egui::Color32::from_rgb(150, 150, 150);
                                            let mut row_centers: Vec<f32> = Vec::new();

                                            ui.horizontal(|ui| {
                                                ui.add_space(line_indent);
                                                let (line_rect, _) = ui.allocate_exact_size(
                                                    egui::vec2(line_width, total_height),
                                                    egui::Sense::hover(),
                                                );
                                                let line_x = line_rect.right();
                                                ui.vertical(|ui| {
                                                    for (si, subtask) in feature.subtasks.iter().enumerate() {
                                                        if si > 0 {
                                                            ui.add_space(row_gap);
                                                        }
                                                        let subtask_status_color = match subtask.status.as_str() {
                                                            "Completed" => egui::Color32::from_rgb(76, 175, 80),
                                                            "Developing" => egui::Color32::from_rgb(0, 188, 212),
                                                            "Testing" => egui::Color32::from_rgb(138, 43, 226),
                                                            "Planned" => egui::Color32::from_rgb(160, 160, 160),
                                                            "Stalled" => egui::Color32::from_rgb(255, 152, 0),
                                                            "Paused" => egui::Color32::from_rgb(156, 39, 176),
                                                            "Cancelled" => egui::Color32::from_rgb(244, 67, 54),
                                                            "Deferred" => egui::Color32::from_rgb(121, 85, 72),
                                                            _ => egui::Color32::from_rgb(160, 160, 160),
                                                        };
                                                        let response = ui.allocate_ui(egui::vec2(ui.available_width(), row_height), |ui| {
                                                            egui::Frame::NONE
                                                                .stroke(egui::Stroke::new(0.5_f32, egui::Color32::from_rgb(190, 190, 190)))
                                                                .inner_margin(4.0)
                                                                .outer_margin(0.0)
                                                                .show(ui, |ui| {
                                                                    ui.horizontal(|ui| {
                                                                    let (rect, _) = ui.allocate_exact_size(
                                                                        egui::vec2(4.0, 18.0),
                                                                        egui::Sense::hover(),
                                                                    );
                                                                    let task_color = parse_color(&subtask.color);
                                                                    ui.painter().rect_filled(rect, 0.0, task_color);
                                                                        ui.label(&subtask.title);
                                                                        let subtask_text: egui::RichText = if subtask.status == "Completed" {
                                                                            egui::RichText::new("\u{2714}")
                                                                        } else {
                                                                            egui::RichText::new(format!("{}", subtask.status))
                                                                        };
                                                                        ui.colored_label(subtask_status_color, subtask_text);
                                                                        if !subtask.description.trim().is_empty() {
                                                                            ui.colored_label(egui::Color32::GRAY, &subtask.description);
                                                                        }
                                                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                                            if ui.small_button("Delete").clicked() {
                                                                                subtask_remove_action = Some((qi, fi, si));
                                                                            }
                                                                            if ui.small_button("Edit").clicked() {
                                                                                dialog_action = Some(DialogAction::OpenEditSubtask(qi, fi, si));
                                                                            }
                                                                            if ui.small_button("Complete").clicked() {
                                                                                subtask_complete_action = Some((qi, fi, si));
                                                                            }
                                                                        });
                                                                    });
                                                                });
                                                        });

                                                        let row_center = response.response.rect.center().y;
                                                        let row_left = response.response.rect.left();
                                                        row_centers.push(row_center);
                                                        ui.painter().line_segment(
                                                            [egui::pos2(line_x, row_center), egui::pos2(row_left, row_center)],
                                                            egui::Stroke::new(1.0_f32, line_color),
                                                        );
                                                    }
                                                });

                                                if let Some(first_center) = row_centers.first().copied() {
                                                    let end_center = if row_centers.len() > 1 {
                                                        *row_centers.last().unwrap_or(&first_center)
                                                    } else {
                                                        first_center
                                                    };
                                                    ui.painter().line_segment(
                                                        [egui::pos2(line_x, line_rect.top()), egui::pos2(line_x, end_center)],
                                                        egui::Stroke::new(1.0_f32, line_color),
                                                    );
                                                }
                                            });
                                            ui.add_space(8.0);
                                        }
                                    }
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
                    if let Some((qi, fi, si)) = subtask_remove_action {
                        self.save_snapshot();
                        self.quarters[qi].features[fi].subtasks.remove(si);
                    }
                    if let Some((qi, fi, si)) = subtask_complete_action {
                        self.save_snapshot();
                        let now = chrono::Local::now().to_rfc3339();
                        let subtask = &mut self.quarters[qi].features[fi].subtasks[si];
                        subtask.completed = true;
                        subtask.status = "Completed".into();
                        subtask.completed_at = Some(now);
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

                    if let Some((qi, fi)) = complete_action {
                        self.complete_task(qi, fi);
                    }

                    if let Some((qi, fi)) = start_action {
                        self.start_task(qi, fi);
                    }
                    if let Some((qi, fi)) = pause_action {
                        self.pause_task(qi, fi);
                    }

                    if let Some((qi, fi, dir)) = status_move_action {
                        self.save_snapshot();
                        let feature = &mut self.quarters[qi].features[fi];
                        let col = match feature.status.as_str() {
                            "Planned" => 0usize,
                            "Developing" => 1,
                            "Testing" => 2,
                            "Completed" => 3,
                            _ => 4,
                        };
                        let new_col = (col as i32 + dir).clamp(0, 4) as usize;
                        feature.status = match new_col {
                            0 => "Planned".into(),
                            1 => "Developing".into(),
                            2 => "Testing".into(),
                            3 => "Completed".into(),
                            _ => "Stalled".into(),
                        };
                        if new_col == 3 {
                            feature.completed = true;
                            feature.completed_at = Some(chrono::Local::now().to_rfc3339());
                        } else if feature.completed && new_col != 3 {
                            feature.completed = false;
                            feature.completed_at = None;
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
                            DialogAction::OpenAddSubtask(qi, fi) => {
                                let feature_color = self.quarters[qi].features[fi].color.clone();
                                self.dialog_state = DialogState::AddSubtask {
                                    quarter_idx: qi,
                                    feature_idx: fi,
                                    dialog: SubtaskDialogState {
                                        color: feature_color,
                                        ..SubtaskDialogState::default()
                                    },
                                };
                            }
                            DialogAction::OpenEditSubtask(qi, fi, si) => {
                                let existing = &self.quarters[qi].features[fi].subtasks[si];
                                self.dialog_state = DialogState::EditSubtask {
                                    quarter_idx: qi,
                                    feature_idx: fi,
                                    subtask_idx: si,
                                    dialog: SubtaskDialogState::from_subtask(existing),
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

                let roadmaps_resp = ui.horizontal(|ui| {
                    let label_resp = ui.label("Roadmaps:");
                    if label_resp.hovered() {
                        self.timeline_visible_roadmap_buttons = true;
                        self.timeline_roadmap_buttons_close_at = None;
                    }
                    let max_visible = 4usize;
                    let total = self.timeline_visible_roadmaps.len();
                    let visible_count = total.min(max_visible);
                    for i in 0..visible_count {
                        let (_rid, vis, name) = &mut self.timeline_visible_roadmaps[i];
                        let mut checked = *vis;
                        if ui.checkbox(&mut checked, &*name).changed() {
                            self.timeline_visible_roadmaps[i].1 = checked;
                        }
                    }
                    if total > max_visible {
                        let more_resp = ui.label("More...");
                        if more_resp.hovered() || more_resp.clicked() {
                            self.timeline_visible_roadmap_buttons = true;
                            self.timeline_roadmap_buttons_close_at = None;
                        }
                    }
                }).response;
                if self.timeline_visible_roadmap_buttons {
                    ui.horizontal(|ui| {
                        let max_visible = 4usize;
                        for i in max_visible..self.timeline_visible_roadmaps.len() {
                            let (_rid, vis, name) = &mut self.timeline_visible_roadmaps[i];
                            let mut checked = *vis;
                            if ui.checkbox(&mut checked, &*name).changed() {
                                self.timeline_visible_roadmaps[i].1 = checked;
                            }
                        }
                    });
                }
                if self.timeline_visible_roadmap_buttons {
                    let pointer_in_row = ui.ctx().pointer_hover_pos()
                        .map_or(false, |p| roadmaps_resp.rect.contains(p));
                    if pointer_in_row {
                        self.timeline_roadmap_buttons_close_at = None;
                    } else if self.timeline_roadmap_buttons_close_at.is_none()
                        && !roadmaps_resp.hovered() {
                            self.timeline_roadmap_buttons_close_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(500));
                    }
                    if let Some(deadline) = self.timeline_roadmap_buttons_close_at {
                        if std::time::Instant::now() >= deadline {
                            self.timeline_visible_roadmap_buttons = false;
                            self.timeline_roadmap_buttons_close_at = None;
                        }
                    }
                }

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
                            let scroll = ui.input(|i| i.smooth_scroll_delta);
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
                                    painter.rect_stroke(bar_rect, 2.0_f32, egui::Stroke::new(0.5_f32, egui::Color32::WHITE), egui::StrokeKind::Inside);
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

                        let mut timeline_tooltip_hovered = false;
                        let hover_pos = response.hover_pos();
                        if let Some(pos) = hover_pos {
                            let mut found = false;
                            for (bar_rect, qi, fi) in &all_bars {
                                let hit_rect = bar_rect.expand2(egui::vec2(8.0, 10.0));
                                if hit_rect.contains(pos) {
                                    self.timeline_hovered_feature = Some((*qi, *fi));
                                    self.timeline_tooltip_close_at = None;
                                    found = true;
                                    break;
                                }
                            }
                            if !found && self.timeline_hovered_feature.is_some() && self.timeline_tooltip_close_at.is_none() {
                                self.timeline_tooltip_close_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(900));
                            }
                        } else if self.timeline_hovered_feature.is_some() && self.timeline_tooltip_close_at.is_none() {
                            self.timeline_tooltip_close_at = Some(std::time::Instant::now() + std::time::Duration::from_millis(900));
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
                                    let area = egui::Area::new(tooltip_id)
                                        .pivot(egui::Align2::LEFT_BOTTOM)
                                        .fixed_pos(tooltip_pos)
                                        .order(egui::Order::Foreground);
                                    let area_resp = area
                                        .show(&ctx, |ui| {
                                            ui.set_min_width(240.0);
                                            let frame = egui::Frame::popup(ui.style());
                                            frame.show(ui, |ui| {
                                                ui.vertical(|ui| {
                                                    ui.label(egui::RichText::new(&f_title).strong().size(13.0));
                                                    ui.add_space(2.0);
                                                    ui.colored_label(egui::Color32::GRAY, &f_desc);
                                                    ui.add_space(4.0);

                                                    let status_color = match f_status.as_str() {
                                                        "Developing" => egui::Color32::from_rgb(0, 188, 212),
                                                        "Testing" => egui::Color32::from_rgb(138, 43, 226),
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
                                    timeline_tooltip_hovered = area_resp.response.hovered();
                                    }
                            }
                        }

                        if timeline_tooltip_hovered {
                            self.timeline_tooltip_close_at = None;
                        }
                        if let Some(deadline) = self.timeline_tooltip_close_at {
                            if std::time::Instant::now() >= deadline {
                                self.timeline_hovered_feature = None;
                                self.timeline_tooltip_close_at = None;
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
                        let can_edit_org = self.can_edit_org();
                        ui.add_enabled_ui(can_edit_org, |ui| {
                            if ui.small_button("+ Member").clicked() {
                                self.org_dialog_state = OrgDialogState::AddMember {
                                    display_name: String::new(),
                                    role: "member".to_string(),
                                    report_to: None,
                                };
                            }
                        });
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
                                let allow_edit = self.can_edit_org();
                                let org_name = self.org_list.iter().find(|o| o.id == org_id).map(|o| o.name.clone()).unwrap_or_default();
                                let owner_id = db_org_owner_id(&self.db, org_id);
                                let settings = db_load_org_settings(&self.db, org_id);
                                let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner").unwrap_or_default();
                                let roadmap_ids = db_load_org_roadmap_links(&self.db, org_id);
                                let mut roadmap_editors = db_load_org_roadmap_editors(&self.db, org_id);
                                if roadmap_editors.is_empty() {
                                    for member in db_load_org_users(&self.db, org_id) {
                                        if matches!(member.role.as_str(), "owner" | "admin" | "leader") {
                                            roadmap_editors.insert(member.id);
                                        }
                                    }
                                }
                                self.org_dialog_state = OrgDialogState::Settings {
                                    org_id,
                                    name: org_name,
                                    owner_id,
                                    mode: settings.mode,
                                    allow_edit,
                                    owner_token,
                                    roadmap_ids,
                                    roadmap_editors,
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

                        let mut wheel_lines: f32 = 0.0;
                        let mut has_line_wheel = false;
                        ui.ctx().input(|i| {
                            for ev in &i.raw.events {
                                if let egui::Event::MouseWheel { delta, unit, .. } = ev {
                                    match unit {
                                        egui::MouseWheelUnit::Line | egui::MouseWheelUnit::Page => {
                                            has_line_wheel = true;
                                            wheel_lines += delta.y;
                                        }
                                        egui::MouseWheelUnit::Point => {}
                                    }
                                }
                            }
                        });

                        if !ui.input(|i| i.pointer.primary_down()) {
                            if has_line_wheel {
                                let factor = 1.1_f32.powf(wheel_lines);
                                self.org_chart_zoom = (self.org_chart_zoom * factor).clamp(0.65, 3.0);
                            } else {
                                let sd = ui.input(|i| i.smooth_scroll_delta);
                                self.org_chart_scroll -= sd.y * 0.8;
                                self.org_chart_scroll_x += sd.x * 0.8;
                            }
                            let zoom_delta = ui.input(|i| i.zoom_delta());
                            if zoom_delta != 1.0 {
                                self.org_chart_zoom = (self.org_chart_zoom * zoom_delta).clamp(0.65, 3.0);
                            }
                        }

                        let zoom = self.org_chart_zoom;
                        let (response, painter) = ui.allocate_painter(
                            ui.available_size(),
                            egui::Sense::click_and_drag(),
                        );
                        let rect = response.rect;
                        if response.dragged_by(egui::PointerButton::Primary) {
                            let d = response.drag_delta();
                            self.org_chart_scroll -= d.y;
                            self.org_chart_scroll_x += d.x;
                        }
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
                                painter.rect_stroke(nr, 4.0 * zoom, egui::Stroke::new(1.0_f32, border), egui::StrokeKind::Inside);

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
                                    if user.is_ai { "ai" } else { &user.role },
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
                                        let rc_is_ai = rc_user.as_ref().map(|u| u.is_ai).unwrap_or(false);
                                        let is_owner = rc_role == "owner";

                                        ui.label(egui::RichText::new(&rc_name).strong());
                                        ui.colored_label(
                                            egui::Color32::GRAY,
                                            if rc_is_ai {
                                                format!("Role: {} · AI", rc_role)
                                            } else {
                                                format!("Role: {}", rc_role)
                                            },
                                        );
                                        ui.separator();

                                        ui.add_enabled_ui(self.can_edit_org(), |ui| {
                                            if ui.button("Edit Name / Role").clicked() {
                                                self.org_dialog_state = OrgDialogState::EditMember {
                                                    user_id: rc_uid,
                                                    display_name: rc_name.clone(),
                                                    role: rc_role,
                                                };
                                                close_menu = true;
                                            }
                                        });

                                        ui.add_enabled_ui(self.can_edit_org(), |ui| {
                                            if ui.button("Add Report Under").clicked() {
                                                if self.ensure_can_edit_org() {
                                                    self.org_dialog_state = OrgDialogState::AddReport {
                                                        manager_id: rc_uid,
                                                    };
                                                }
                                                close_menu = true;
                                            }
                                        });

                                        if ui.button("Assign Tasks").clicked() {
                                            self.task_assign_user_id = Some(rc_uid);
                                            self.task_assign_user_name = rc_name.clone();
                                            close_menu = true;
                                        }

                                        if ui.button("Generate User Token").clicked() {
                                            if self.ensure_can_edit_org() {
                                                if let Some(org_id) = self.current_org_id {
                                                    let existing_token = load_sync_token(self.use_keychain, &self.db, org_id, "token").unwrap_or_default();
                                                    if existing_token.trim().is_empty() {
                                                        self.status_text = "Set current token via Join Org first".into();
                                                    } else {
                                                        let token = generate_user_token();
                                                        if let Ok(mut guard) = self.sync_pending_token.lock() {
                                                            *guard = Some(PendingTokenRotation {
                                                                token: token.clone(),
                                                                user_id: Some(rc_uid),
                                                            });
                                                        }
                                                        if self.offline || self.sync_running {
                                                            self.status_text = "User token queued for sync".into();
                                                        } else {
                                                            self.status_text = "User token ready; run Sync now".into();
                                                        }
                                                        self.org_dialog_state = OrgDialogState::ShowToken {
                                                            title: "User Token".into(),
                                                            token,
                                                        };
                                                    }
                                                }
                                            }
                                            close_menu = true;
                                        }

                                        ui.add_enabled_ui(self.can_edit_org(), |ui| {
                                            if ui.button("Move Under...").clicked() {
                                                if self.ensure_can_edit_org() {
                                                    self.org_move_under_target = Some(rc_uid);
                                                }
                                                close_menu = true;
                                            }
                                        });

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
                                                        ui.add_enabled_ui(self.can_edit_org(), |ui| {
                                                            if ui.small_button("Unlink").clicked() {
                                                                if self.ensure_can_edit_org() {
                                                                    let link_id = self.org_chart_links.iter().find(|l| l.manager_id == rc_uid && l.report_id == *rid).map(|l| l.id);
                                                                    if let Some(link_id) = link_id {
                                                                        self.save_snapshot();
                                                                        db_remove_chart_link(&self.db, link_id);
                                                                        self.org_chart_links = self.current_org_id.map_or(Vec::new(), |oid| db_load_org_chart(&self.db, oid));
                                                                    }
                                                                }
                                                                close_menu = true;
                                                            }
                                                        });
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
                                                    ui.add_enabled_ui(self.can_edit_org(), |ui| {
                                                        if ui.small_button("Unlink").clicked() {
                                                            if self.ensure_can_edit_org() {
                                                                let link_id = self.org_chart_links.iter().find(|l| l.report_id == rc_uid).map(|l| l.id);
                                                                if let Some(link_id) = link_id {
                                                                    self.save_snapshot();
                                                                    db_remove_chart_link(&self.db, link_id);
                                                                    self.org_chart_links = self.current_org_id.map_or(Vec::new(), |oid| db_load_org_chart(&self.db, oid));
                                                                }
                                                            }
                                                            close_menu = true;
                                                        }
                                                    });
                                                });
                                            }
                                        }

                                        if !is_owner {
                                            ui.separator();
                                            ui.colored_label(egui::Color32::from_rgb(220, 80, 80), "Danger");
                                            ui.add_enabled_ui(self.can_edit_org(), |ui| {
                                                if ui.button("Remove Member").clicked() {
                                                    if self.ensure_can_edit_org() {
                                                        let display_name = rc_name.clone();
                                                        self.org_dialog_state = OrgDialogState::ConfirmRemoveMember {
                                                            user_id: rc_uid,
                                                            display_name,
                                                        };
                                                    }
                                                    close_menu = true;
                                                }
                                            });
                                        }

                                        ui.separator();
                                        if ui.button("Close").clicked() {
                                            close_menu = true;
                                        }
                                    });
                                });

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
                            egui::Window::new(format!("Move {} under...", move_name)).collapsible(false).resizable(false).show(&ctx, |ui| {
                                if candidates.is_empty() {
                                    ui.colored_label(egui::Color32::GRAY, "No other members.");
                                }
                                for c in &candidates {
                                    if ui.button(&c.1).clicked() {
                                        if let Some(org_id) = self.current_org_id {
                                            if self.ensure_can_edit_org() {
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

                        ui.add_space(-20.0);
                        ui.horizontal(|ui| {
                            if let Some(uid) = self.org_selected_user_id {
                                if let Some(user) = self.org_members.iter().find(|m| m.id == uid) {
                                    ui.label(egui::RichText::new(&user.display_name).strong());
                                    ui.colored_label(
                                        egui::Color32::GRAY,
                                        if user.is_ai {
                                            format!("[{} · AI]", user.role)
                                        } else {
                                            format!("[{}]", user.role)
                                        },
                                    );
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
                egui::Window::new("Add Feature").default_width(380.0).collapsible(false).resizable(false).show(&ctx, |ui| {
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
                let existing_subtasks = self.quarters[qi].features[fi].subtasks.clone();
                egui::Window::new("Edit Feature").default_width(380.0).collapsible(false).resizable(false).show(&ctx, |ui| {
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
                            let mut updated = feat;
                            updated.subtasks = existing_subtasks.clone();
                            self.quarters[qi].features[fi] = updated;
                            self.status_text = format!("Updated feature: {}", self.quarters[qi].features[fi].title);
                        }
                        close_dialog = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_dialog = true;
                    }
                });
            }
            DialogState::AddSubtask { quarter_idx, feature_idx, dialog } => {
                let (qi, fi) = (*quarter_idx, *feature_idx);
                egui::Window::new("Add Subtask").default_width(420.0).collapsible(false).resizable(false).show(&ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(task) = dialog.to_subtask(&format!("s_{}", rand::random::<u64>())) {
                            self.undo_stack.push(AppSnapshot {
                                quarters: self.quarters.clone(),
                                org_members: self.org_members.clone(),
                                org_chart_links: self.org_chart_links.clone(),
                                org_settings: self.org_settings.clone(),
                            });
                            self.undo_stack.truncate(20);
                            self.redo_stack.clear();
                            self.quarters[qi].features[fi].subtasks.push(task);
                            self.status_text = format!("Added subtask: {}", self.quarters[qi].features[fi].subtasks.last().unwrap().title);
                        }
                        close_dialog = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_dialog = true;
                    }
                });
            }
            DialogState::EditSubtask { quarter_idx, feature_idx, subtask_idx, dialog } => {
                let (qi, fi, si) = (*quarter_idx, *feature_idx, *subtask_idx);
                let existing_id = self.quarters[qi].features[fi].subtasks[si].id.clone();
                egui::Window::new("Edit Subtask").default_width(420.0).collapsible(false).resizable(false).show(&ctx, |ui| {
                    if dialog.show(ui) {
                        if let Some(task) = dialog.to_subtask(&existing_id) {
                            self.undo_stack.push(AppSnapshot {
                                quarters: self.quarters.clone(),
                                org_members: self.org_members.clone(),
                                org_chart_links: self.org_chart_links.clone(),
                                org_settings: self.org_settings.clone(),
                            });
                            self.undo_stack.truncate(20);
                            self.redo_stack.clear();
                            self.quarters[qi].features[fi].subtasks[si] = task;
                            self.status_text = format!("Updated subtask: {}", self.quarters[qi].features[fi].subtasks[si].title);
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

        if let Some((qi, fi)) = self
            .completion_dialog
            .as_ref()
            .map(|d| (d.quarter_idx, d.feature_idx))
        {
            let mut complete_now = false;
            let mut close_complete_dialog = false;
            let title = self.quarters
                .get(qi)
                .and_then(|q| q.features.get(fi))
                .map(|f| format!("Complete Task: {}", f.title))
                .unwrap_or_else(|| "Complete Task".to_string());
            let dialog = self.completion_dialog.as_mut().unwrap();
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .show(&ctx, |ui| {
                    ui.label("Completion notes (replaces description in Quarters view):");
                    ui.add(
                        egui::TextEdit::multiline(&mut dialog.notes)
                            .desired_width(420.0)
                            .desired_rows(5),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("Complete").clicked() {
                            complete_now = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_complete_dialog = true;
                        }
                    });
                });
            if complete_now {
                let notes = dialog.notes.trim().to_string();
                self.apply_task_completion(qi, fi, notes);
                self.completion_dialog = None;
            } else if close_complete_dialog {
                self.completion_dialog = None;
            }
        }

        enum OrgAction {
            CreateOrg { name: String },
            AddMember { display_name: String, role: String, report_to: Option<i64> },
            EditMember { user_id: i64, display_name: String, role: String },
            AddReport { manager_id: i64, report_id: i64, report_name: String },
            RemoveMember { user_id: i64, display_name: String },
            UpdateSettings { org_id: i64, name: String, owner_id: Option<i64>, mode: String, owner_token: String, roadmap_ids: Vec<i64>, roadmap_editors: std::collections::HashSet<i64> },
            JoinOrg { token: String },
            JoinSharedRoadmap { token: String },
            ShareCurrentRoadmap,
            MigrateOrg {
                owner_token: String,
                old_server_url: String,
                new_server_url: String,
                org_id: i64,
                target_server_identity: String,
            },
        }

        let mut close_org_dialog = false;
        let mut org_action: Option<OrgAction> = None;
        match &mut self.org_dialog_state {
            OrgDialogState::CreateOrg { name } => {
                egui::Window::new("Create Organization").collapsible(false).resizable(false).show(&ctx, |ui| {
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
                egui::Window::new("Add Member").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("Display name:");
                    ui.text_edit_singleline(display_name);
                    ui.label("Role:");
                    let roles = ["member", "leader", "admin"];
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
                egui::Window::new("Edit Member").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("Display name:");
                    ui.text_edit_singleline(display_name);
                    ui.label("Role:");
                    let roles = ["member", "leader", "admin", "owner"];
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
                egui::Window::new(format!("Add Report under {}", mgr_name)).collapsible(false).resizable(false).show(&ctx, |ui| {
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
            OrgDialogState::JoinOrg { token } => {
                egui::Window::new("Join Organization").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("User token:");
                    ui.text_edit_singleline(token);
                    ui.horizontal(|ui| {
                        if ui.button("Join").clicked() {
                            if !token.trim().is_empty() {
                                org_action = Some(OrgAction::JoinOrg { token: token.trim().to_string() });
                            }
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::JoinSharedRoadmap { token } => {
                egui::Window::new("Open Shared Roadmap").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("Share token:");
                    ui.text_edit_singleline(token);
                    ui.horizontal(|ui| {
                        if ui.button("Open").clicked() {
                            if !token.trim().is_empty() {
                                org_action = Some(OrgAction::JoinSharedRoadmap { token: token.trim().to_string() });
                            }
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::ShareCurrentRoadmap => {
                let roadmap_name = self
                    .current_roadmap_id
                    .and_then(|rid| self.roadmap_list.iter().find(|(id, _)| *id == rid).map(|(_, n)| n.clone()))
                    .unwrap_or_else(|| "No roadmap selected".to_string());
                egui::Window::new("Share Current Roadmap").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label(format!("Roadmap: {}", roadmap_name));
                    ui.horizontal(|ui| {
                        if ui.button("Generate Share Token").clicked() {
                            org_action = Some(OrgAction::ShareCurrentRoadmap);
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::Migration {
                owner_token,
                old_server_url,
                new_server_url,
                org_id,
                target_server_identity,
            } => {
                let migration_org_snapshot: Vec<(i64, String, bool)> = self
                    .org_list
                    .iter()
                    .map(|org| {
                        let sync_state = db_load_org_sync_state(&self.db, org.id);
                        (org.id, org.name.clone(), sync_state.is_owner)
                    })
                    .collect();
                let current_org_name = migration_org_snapshot
                    .iter()
                    .find(|(oid, _, _)| *oid == *org_id)
                    .map(|(_, name, _)| name.clone())
                    .unwrap_or_else(|| format!("Org {}", org_id));
                let selected_org_is_owner = migration_org_snapshot
                    .iter()
                    .find(|(oid, _, _)| *oid == *org_id)
                    .map(|(_, _, is_owner)| *is_owner)
                    .unwrap_or(false);
                egui::Window::new("Migrate Organization").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("Organization:");
                    egui::ComboBox::from_id_salt("org_migration_select")
                        .selected_text(current_org_name)
                        .show_ui(ui, |ui| {
                            for (oid, oname, _is_owner) in &migration_org_snapshot {
                                if ui.selectable_label(*oid == *org_id, oname).clicked() {
                                    *org_id = *oid;
                                    *owner_token = load_sync_token(self.use_keychain, &self.db, *oid, "owner").unwrap_or_default();
                                }
                            }
                        });
                    ui.label("Owner token:");
                    ui.text_edit_singleline(owner_token);
                    ui.label("Old server address:");
                    ui.add_enabled(false, egui::TextEdit::singleline(old_server_url));
                    ui.label("New server address:");
                    ui.text_edit_singleline(new_server_url);
                    ui.label("Target server identity token:");
                    ui.add_enabled(false, egui::TextEdit::singleline(target_server_identity));
                    if !selected_org_is_owner {
                        ui.colored_label(egui::Color32::GRAY, "You must be the owner of the selected org to migrate it.");
                    }
                    ui.separator();
                    let current_server_url = self.sync_config.server_url.trim();
                    let can_start_migration = !owner_token.trim().is_empty()
                        && !current_server_url.is_empty()
                        && !new_server_url.trim().is_empty()
                        && !target_server_identity.trim().is_empty()
                        && old_server_url.trim() == current_server_url
                        && new_server_url.trim() != current_server_url
                        && selected_org_is_owner;
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(can_start_migration, egui::Button::new("Start Migration"))
                            .clicked()
                        {
                            org_action = Some(OrgAction::MigrateOrg {
                                owner_token: owner_token.trim().to_string(),
                                old_server_url: current_server_url.to_string(),
                                new_server_url: new_server_url.trim().to_string(),
                                org_id: *org_id,
                                target_server_identity: target_server_identity.trim().to_string(),
                            });
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::ConfirmRemoveMember { user_id, display_name } => {
                let uid = *user_id;
                let name = display_name.clone();
                egui::Window::new("Confirm Remove Member").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 80, 80),
                        format!("Remove {} from this organization?", name),
                    );
                    ui.label("This also revokes existing user-token access and rotates token.");
                    ui.horizontal(|ui| {
                        if ui.button("Remove").clicked() {
                            org_action = Some(OrgAction::RemoveMember {
                                user_id: uid,
                                display_name: name.clone(),
                            });
                            close_org_dialog = true;
                        }
                        if ui.button("Cancel").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::ShowToken { title, token } => {
                egui::Window::new(title.as_str()).collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("Copy this token:");
                    ui.add_enabled(false, egui::TextEdit::singleline(token).desired_width(360.0));
                    ui.horizontal(|ui| {
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(token.clone());
                        }
                        if ui.button("Close").clicked() {
                            close_org_dialog = true;
                        }
                    });
                });
            }
            OrgDialogState::Settings { org_id, name, owner_id, mode, allow_edit, owner_token, roadmap_ids, roadmap_editors } => {
                let can_edit = *allow_edit;
                let members_snapshot = db_load_org_users(&self.db, *org_id);
                let org_settings_snapshot: Vec<(i64, String, Option<i64>, String, bool, bool)> = self.org_list.iter()
                    .map(|org| {
                        let settings = db_load_org_settings(&self.db, org.id);
                        let sync_state = db_load_org_sync_state(&self.db, org.id);
                        (org.id, org.name.clone(), db_org_owner_id(&self.db, org.id), settings.mode, sync_state.joined, sync_state.is_owner)
                    })
                    .collect();
                egui::Window::new("Organization Settings").collapsible(false).resizable(false).show(&ctx, |ui| {
                    ui.label("Organization:");
                    egui::ComboBox::from_id_salt("org_settings_select")
                        .selected_text(name.as_str())
                        .show_ui(ui, |ui| {
                            for (oid, oname, oowner, omode, joined, is_owner) in &org_settings_snapshot {
                                if ui.selectable_label(*oid == *org_id, oname).clicked() {
                                    *org_id = *oid;
                                    *name = oname.clone();
                                    *owner_id = *oowner;
                                    *mode = omode.clone();
                                    *allow_edit = if *joined { *is_owner } else { true };
                                    *owner_token = load_sync_token(self.use_keychain, &self.db, *oid, "owner").unwrap_or_default();
                                    *roadmap_ids = db_load_org_roadmap_links(&self.db, *oid);
                                    *roadmap_editors = db_load_org_roadmap_editors(&self.db, *oid);
                                    if roadmap_editors.is_empty() {
                                        for member in db_load_org_users(&self.db, *oid) {
                                            if matches!(member.role.as_str(), "owner" | "admin" | "leader") {
                                                roadmap_editors.insert(member.id);
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    ui.separator();
                    ui.label("Organization name:");
                    ui.add_enabled_ui(can_edit, |ui| {
                        ui.text_edit_singleline(name);
                    });
                    ui.label("Owner token:");
                    ui.add_enabled_ui(can_edit, |ui| {
                        ui.text_edit_singleline(owner_token);
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
                    ui.label("Linked roadmaps:");
                    for (rid, name) in &self.roadmap_list {
                        let mut linked = roadmap_ids.contains(rid);
                        ui.add_enabled_ui(can_edit, |ui| {
                            if ui.checkbox(&mut linked, name).changed() {
                                if linked {
                                    roadmap_ids.push(*rid);
                                } else {
                                    roadmap_ids.retain(|id| id != rid);
                                }
                            }
                        });
                    }
                    ui.separator();
                    ui.label("Roadmap editors:");
                    for member in &members_snapshot {
                        let mut enabled = roadmap_editors.contains(&member.id);
                        ui.add_enabled_ui(can_edit, |ui| {
                            if ui.checkbox(&mut enabled, &member.display_name).changed() {
                                if enabled {
                                    roadmap_editors.insert(member.id);
                                } else {
                                    roadmap_editors.remove(&member.id);
                                }
                            }
                        });
                    }
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
                                    owner_token: owner_token.trim().to_string(),
                                    roadmap_ids: roadmap_ids.clone(),
                                    roadmap_editors: roadmap_editors.clone(),
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
                    let sync_state = db_load_org_sync_state(&self.db, id);
                    self.org_joined = sync_state.joined;
                    self.org_is_owner = sync_state.is_owner;
                    let owner_token = load_sync_token(self.use_keychain, &self.db, id, "owner").unwrap_or_default();
                    if owner_token.trim().is_empty() {
                        let new_owner_token = generate_owner_token();
                        save_sync_token(self.use_keychain, &self.db, id, "", &new_owner_token);
                    }
                    self.status_text = format!("Created org: {}", name.trim());
                }
                OrgAction::AddMember { display_name, role, report_to } => {
                    if self.ensure_can_edit_org() {
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
                }
                OrgAction::EditMember { user_id, display_name, role } => {
                    if self.ensure_can_edit_org() {
                        self.save_snapshot();
                        db_update_org_user(&self.db, user_id, display_name.trim(), &role);
                        if let Some(org_id) = self.current_org_id {
                            self.org_members = db_load_org_users(&self.db, org_id);
                        }
                        self.status_text = format!("Updated member: {}", display_name.trim());
                    }
                }
                OrgAction::AddReport { manager_id, report_id, report_name } => {
                    if self.ensure_can_edit_org() {
                        if let Some(org_id) = self.current_org_id {
                            self.save_snapshot();
                            db_add_chart_link(&self.db, org_id, manager_id, report_id);
                            self.org_chart_links = db_load_org_chart(&self.db, org_id);
                            self.org_members = db_load_org_users(&self.db, org_id);
                            let mgr_name = self.org_members.iter().find(|m| m.id == manager_id).map(|m| m.display_name.clone()).unwrap_or_default();
                            self.status_text = format!("Linked {} → {}", mgr_name, report_name);
                        }
                    }
                }
                OrgAction::RemoveMember { user_id, display_name } => {
                    if self.ensure_can_edit_org() {
                        if let Some(org_id) = self.current_org_id {
                            self.save_snapshot();
                            db_remove_org_user(&self.db, user_id, org_id);
                            self.org_members = db_load_org_users(&self.db, org_id);
                            self.org_chart_links = db_load_org_chart(&self.db, org_id);
                            self.org_selected_user_id = None;

                            if self.org_joined && self.org_is_owner {
                                let new_token = generate_user_token();
                                let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner").unwrap_or_default();
                                save_sync_token(self.use_keychain, &self.db, org_id, &new_token, &owner_token);
                                if let Ok(mut guard) = self.sync_pending_token.lock() {
                                    *guard = Some(PendingTokenRotation {
                                        token: new_token.clone(),
                                        user_id: db_org_owner_id(&self.db, org_id),
                                    });
                                }
                                if !self.offline && !self.sync_running {
                                    self.start_sync_worker();
                                }
                                self.status_text = format!(
                                    "Removed {} and rotated user token to revoke access",
                                    display_name
                                );
                            } else {
                                self.status_text = format!("Removed member: {}", display_name);
                            }
                        }
                    }
                }
                OrgAction::UpdateSettings { org_id, name, owner_id, mode, owner_token, roadmap_ids, roadmap_editors } => {
                    if self.ensure_can_edit_org() {
                        self.save_snapshot();
                        if !name.trim().is_empty() {
                            db_rename_org(&self.db, org_id, name.trim());
                        }
                        if let Some(owner_id) = owner_id {
                            db_update_org_owner(&self.db, org_id, owner_id);
                        }
                        let existing_token = load_sync_token(self.use_keychain, &self.db, org_id, "token").unwrap_or_default();
                        save_sync_token(self.use_keychain, &self.db, org_id, &existing_token, &owner_token);
                        db_update_org_settings(&self.db, org_id, &mode);
                        db_set_org_roadmap_links(&self.db, org_id, &roadmap_ids);
                        db_set_org_roadmap_editors(&self.db, org_id, &roadmap_editors);
                        self.org_list = db_list_orgs(&self.db);
                        self.current_org_id = Some(org_id);
                        self.org_members = db_load_org_users(&self.db, org_id);
                        self.org_chart_links = db_load_org_chart(&self.db, org_id);
                        self.org_settings = db_load_org_settings(&self.db, org_id);
                        self.org_selected_user_id = db_org_owner_id(&self.db, org_id);
                        let sync_state = db_load_org_sync_state(&self.db, org_id);
                        self.org_joined = sync_state.joined;
                        self.org_is_owner = sync_state.is_owner;
                        self.sync_pending_send.store(true, Ordering::Relaxed);
                        self.status_text = format!("Updated org settings: {}", self.org_settings.mode);
                    }
                }
                OrgAction::JoinOrg { token } => {
                    if let Some(org_id) = self.current_org_id {
                        let owner_token = load_sync_token(self.use_keychain, &self.db, org_id, "owner").unwrap_or_default();
                        save_sync_token(self.use_keychain, &self.db, org_id, &token, &owner_token);
                        db_set_org_sync_state(&self.db, org_id, false, false);
                        let sync_state = db_load_org_sync_state(&self.db, org_id);
                        self.org_joined = sync_state.joined;
                        self.org_is_owner = sync_state.is_owner;
                        self.status_text = "Saved user token; snapshot will sync on first join".into();
                    } else {
                        self.status_text = "No organization selected".into();
                    }
                }
                OrgAction::JoinSharedRoadmap { token } => {
                    self.open_shared_roadmap(token);
                }
                OrgAction::ShareCurrentRoadmap => {
                    self.share_current_roadmap();
                }
                OrgAction::MigrateOrg {
                    owner_token,
                    old_server_url,
                    new_server_url,
                    org_id,
                    target_server_identity,
                } => {
                    self.migrate_org(
                        owner_token,
                        old_server_url,
                        new_server_url,
                        org_id,
                        target_server_identity,
                    );
                }
            }
        }

        if close_org_dialog {
            self.org_dialog_state = OrgDialogState::None;
        }

        if self.show_network_settings {
            let mut save_network = false;
            let mut close_network = false;
            let mut open_migration_dialog = false;
            let title = match self.network_settings_view {
                NetworkSettingsView::Server => "Server Settings",
                NetworkSettingsView::Proxy => "Proxy Settings",
            };
            egui::Window::new(title).collapsible(false).resizable(false).show(&ctx, |ui| {
                match self.network_settings_view {
                    NetworkSettingsView::Server => {
                        let mut scheme = if self.network_edit_config.server_url.starts_with("wss://") {
                            "wss://".to_string()
                        } else {
                            "ws://".to_string()
                        };
                        let mut address = self
                            .network_edit_config
                            .server_url
                            .strip_prefix("wss://")
                            .or_else(|| self.network_edit_config.server_url.strip_prefix("ws://"))
                            .unwrap_or(self.network_edit_config.server_url.as_str())
                            .to_string();

                        let shown_server_node_id = if self.network_edit_config.server_node_id.trim().is_empty() {
                            "unknown".to_string()
                        } else {
                            self.network_edit_config.server_node_id.clone()
                        };
                        ui.label(format!("Node ID: {}", shown_server_node_id));
                        ui.label("Server:");
                        ui.horizontal(|ui| {
                            egui::ComboBox::from_id_salt("server_scheme_select")
                                .selected_text(&scheme)
                                .show_ui(ui, |ui| {
                                    if ui.selectable_label(scheme == "ws://", "ws://").clicked() {
                                        scheme = "ws://".to_string();
                                    }
                                    if ui.selectable_label(scheme == "wss://", "wss://").clicked() {
                                        scheme = "wss://".to_string();
                                    }
                                });
                            ui.text_edit_singleline(&mut address);
                        });
                        self.network_edit_config.server_url = format!("{}{}", scheme, address.trim());
                        if self.network_edit_config.server_url != self.sync_config.server_url {
                            self.network_edit_config.server_node_id.clear();
                        }
                    }
                    NetworkSettingsView::Proxy => {
                        ui.checkbox(&mut self.network_edit_config.use_proxy, "Use proxy");
                        ui.add_enabled_ui(self.network_edit_config.use_proxy, |ui| {
                            ui.label("Proxy mode:");
                            if ui.radio(self.network_edit_config.proxy_mode == "none", "None").clicked() {
                                self.network_edit_config.proxy_mode = "none".into();
                            }
                            if ui.radio(self.network_edit_config.proxy_mode == "http", "HTTP").clicked() {
                                self.network_edit_config.proxy_mode = "http".into();
                            }
                            if ui.radio(self.network_edit_config.proxy_mode == "socks5", "SOCKS5").clicked() {
                                self.network_edit_config.proxy_mode = "socks5".into();
                            }
                            if ui.radio(self.network_edit_config.proxy_mode == "tor", "Tor").clicked() {
                                self.network_edit_config.proxy_mode = "tor".into();
                                if self.network_edit_config.proxy_url.trim().is_empty() {
                                    self.network_edit_config.proxy_url = "socks5://127.0.0.1:9050".into();
                                }
                            }
                            if self.network_edit_config.proxy_mode == "tor" {
                                ui.colored_label(egui::Color32::GRAY, "Tor must already be running.");
                            }
                            ui.label("Proxy URL:");
                            ui.text_edit_singleline(&mut self.network_edit_config.proxy_url);
                        });
                    }
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        save_network = true;
                        close_network = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close_network = true;
                    }
                    if matches!(self.network_settings_view, NetworkSettingsView::Server)
                        && ui.button("Migrate").clicked()
                    {
                        open_migration_dialog = true;
                    }
                });
            });
            if open_migration_dialog {
                let default_org_id = self.current_org_id.unwrap_or(1);
                let owner_token = load_sync_token(self.use_keychain, &self.db, default_org_id, "owner").unwrap_or_default();
                let new_server_url = self.network_edit_config.server_url.clone();
                let target_server_identity = tokio::runtime::Runtime::new()
                    .map_err(|e| e.to_string())
                    .and_then(|rt| rt.block_on(request_server_node_id(&self.network_edit_config, new_server_url.clone())))
                    .unwrap_or_else(|err| {
                        self.status_text = format!("Failed to read target server node id: {}", err);
                        String::new()
                    });
                self.org_dialog_state = OrgDialogState::Migration {
                    owner_token,
                    old_server_url: self.sync_config.server_url.clone(),
                    new_server_url,
                    org_id: default_org_id,
                    target_server_identity,
                };
                self.show_network_settings = false;
            }
            if save_network {
                let server_changed = self.sync_config.server_url != self.network_edit_config.server_url;
                self.sync_config = self.network_edit_config.clone();
                if server_changed {
                    self.sync_config.server_node_id.clear();
                    self.network_edit_config.server_node_id.clear();
                }
                db_save_sync_config(&self.db, &self.sync_config);
                self.status_text = "Saved network settings".into();
            }
            if close_network {
                self.show_network_settings = false;
            }
        }

        if let Some(url) = self.pending_server_switch_url.clone() {
            let mut switch_now = false;
            let mut dismiss = false;
            egui::Window::new("Organization Migrated")
                .collapsible(false)
                .resizable(false)
                .show(&ctx, |ui| {
                    ui.label("This organization has migrated to a new server.");
                    ui.label(format!("New server: {}", url));
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui.button("Switch Server").clicked() {
                            switch_now = true;
                        }
                        if ui.button("Not now").clicked() {
                            dismiss = true;
                        }
                    });
                });
            if switch_now {
                self.sync_config.server_url = url.clone();
                self.sync_config.server_node_id.clear();
                self.network_edit_config.server_url = url;
                self.network_edit_config.server_node_id.clear();
                db_save_sync_config(&self.db, &self.sync_config);
                if let Some(org_id) = self.current_org_id {
                    db_set_org_sync_state(&self.db, org_id, false, false);
                    let sync_state = db_load_org_sync_state(&self.db, org_id);
                    self.org_joined = sync_state.joined;
                    self.org_is_owner = sync_state.is_owner;
                    if self.sync_running {
                        self.stop_sync_worker();
                        self.start_sync_worker();
                    }
                }
                self.pending_server_switch_url = None;
                self.status_text = "Switched to migrated server".into();
            } else if dismiss {
                self.pending_server_switch_url = None;
            }
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
            let allow_assign = if self.org_joined {
                self.org_is_owner
            } else {
                self.org_settings.mode == "flat" || self.org_selected_user_id == owner_id
            };
            egui::Window::new(format!("Assign Tasks: {}", feature_title)).collapsible(false).resizable(false).show(&ctx, |ui| {
                if members_snapshot.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No org members available.");
                } else {
                    for member in &members_snapshot {
                        ui.horizontal(|ui| {
                            if member.is_ai {
                                ui.label(format!("{} [AI]", member.display_name));
                            } else {
                                ui.label(&member.display_name);
                            }
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
            let allow_assign = if self.org_joined {
                self.org_is_owner
            } else {
                self.org_settings.mode == "flat" || self.org_selected_user_id == owner_id
            };
            let mut features: Vec<(String, String)> = Vec::new();
            for quarter in &self.quarters {
                for feature in &quarter.features {
                    features.push((feature.id.clone(), feature.title.clone()));
                }
            }
            egui::Window::new(format!("Assign Tasks to {}", user_name)).collapsible(false).resizable(false).show(&ctx, |ui| {
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
            egui::Window::new("Organizations").collapsible(false).resizable(false).show(&ctx, |ui| {
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
                        let sync_state = db_load_org_sync_state(&self.db, oid);
                        self.org_joined = sync_state.joined;
                        self.org_is_owner = sync_state.is_owner;
                    } else {
                        self.org_members.clear();
                        self.org_chart_links.clear();
                        self.org_settings = OrgSettings {
                            org_id: 0,
                            mode: "hierarchy".into(),
                            updated_at: String::new(),
                        };
                        self.org_joined = false;
                        self.org_is_owner = true;
                        self.org_selected_user_id = None;
                    }
                }
            }
            if let Some(id) = switch_id {
                self.current_org_id = Some(id);
                self.org_members = db_load_org_users(&self.db, id);
                self.org_chart_links = db_load_org_chart(&self.db, id);
                self.org_settings = db_load_org_settings(&self.db, id);
                let sync_state = db_load_org_sync_state(&self.db, id);
                self.org_joined = sync_state.joined;
                self.org_is_owner = sync_state.is_owner;
                self.org_selected_user_id = db_org_owner_id(&self.db, id);
                self.show_org_list_dialog = false;
            }
        }

        if self.show_open_dialog {
            let mut open_id = None;
            let mut delete_id = None;
            egui::Window::new("Open Roadmap").collapsible(false).resizable(false).show(&ctx, |ui| {
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
            egui::Window::new("New Roadmap").collapsible(false).resizable(false).show(&ctx, |ui| {
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
            egui::Window::new("Rename Roadmap").collapsible(false).resizable(false).show(&ctx, |ui| {
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
            .with_title("allroads")
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

#[cfg(test)]
mod tests;
