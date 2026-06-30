use crate::change::Change;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncMessage {
    Hello {
        node_id: String,
        schema_version: i64,
        last_log_id: i64,
        token: String,
        owner_token: Option<String>,
        client_kind: Option<String>,
    },
    AuthOk {
        session_id: String,
        session_key: String,
        after_log_id: i64,
        server_node_id: String,
        is_owner: bool,
        user_id: i64,
        user_role: String,
        is_ai: bool,
    },
    NodeIdReq,
    NodeIdOk {
        node_id: String,
    },
    SnapshotReq {
        reason: String,
    },
    SnapshotData {
        data_b64: String,
        hash: String,
        nonce_b64: String,
    },
    GenerateShareToken {
        roadmap_id: i64,
    },
    ShareToken {
        token: String,
        roadmap_id: i64,
    },
    ShareSnapshotReq {
        token: String,
    },
    ShareSnapshotData {
        data_b64: String,
        hash: String,
    },
    MigrationStartReq {
        owner_token: String,
        old_server_url: String,
        new_server_url: String,
        org_id: i64,
        target_server_identity: String,
    },
    MigrationStartOk {
        org_id: i64,
    },
    MigrationSnapshotReq {
        owner_token: String,
        org_id: i64,
        target_server_url: String,
        target_server_identity: String,
    },
    MigrationSnapshotData {
        data_b64: String,
        source_logical_hash: String,
    },
    MigrationFinalizeReq {
        owner_token: String,
        org_id: i64,
        target_logical_hash: String,
        target_server_url: String,
        target_server_identity: String,
    },
    MigrationFinalizeOk {
        org_id: i64,
        delete_after_unix: i64,
    },
    Sealed {
        nonce_b64: String,
        data_b64: String,
    },
    Changeset {
        changes: Vec<Change>,
        last_log_id: i64,
    },
    RotateToken {
        token: String,
        user_id: Option<i64>,
    },
    Ack {
        last_log_id: i64,
    },
    Resume {
        after_log_id: i64,
    },
    Ping,
    Pong,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub session_id: String,
    pub nonce: u64,
    pub sig: String,
    pub body: SyncMessage,
}

pub trait Transport {
    fn is_open(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_snapshot_message_round_trip_json() {
        let msg = SyncMessage::ShareSnapshotReq {
            token: "share-token-1".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SyncMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            SyncMessage::ShareSnapshotReq { token } => assert_eq!(token, "share-token-1"),
            _ => panic!("wrong message variant"),
        }
    }

    #[test]
    fn sealed_message_round_trip_json() {
        let msg = SyncMessage::Sealed {
            nonce_b64: "nonce".to_string(),
            data_b64: "cipher".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SyncMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            SyncMessage::Sealed { nonce_b64, data_b64 } => {
                assert_eq!(nonce_b64, "nonce");
                assert_eq!(data_b64, "cipher");
            }
            _ => panic!("wrong message variant"),
        }
    }

    #[test]
    fn migration_start_round_trip_json() {
        let msg = SyncMessage::MigrationStartReq {
            owner_token: "owner-1".to_string(),
            old_server_url: "ws://old.example:59901".to_string(),
            new_server_url: "ws://new.example:59901".to_string(),
            org_id: 7,
            target_server_identity: "new-node-1".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SyncMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            SyncMessage::MigrationStartReq {
                owner_token,
                old_server_url,
                new_server_url,
                org_id,
                target_server_identity,
            } => {
                assert_eq!(owner_token, "owner-1");
                assert_eq!(old_server_url, "ws://old.example:59901");
                assert_eq!(new_server_url, "ws://new.example:59901");
                assert_eq!(org_id, 7);
                assert_eq!(target_server_identity, "new-node-1");
            }
            _ => panic!("wrong message variant"),
        }
    }

    #[test]
    fn migration_snapshot_round_trip_json() {
        let msg = SyncMessage::MigrationSnapshotReq {
            owner_token: "owner-1".to_string(),
            org_id: 4,
            target_server_url: "ws://new.example:59901".to_string(),
            target_server_identity: "new-node".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SyncMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            SyncMessage::MigrationSnapshotReq {
                owner_token,
                org_id,
                target_server_url,
                target_server_identity,
            } => {
                assert_eq!(owner_token, "owner-1");
                assert_eq!(org_id, 4);
                assert_eq!(target_server_url, "ws://new.example:59901");
                assert_eq!(target_server_identity, "new-node");
            }
            _ => panic!("wrong message variant"),
        }
    }

    #[test]
    fn migration_finalize_round_trip_json() {
        let msg = SyncMessage::MigrationFinalizeReq {
            owner_token: "owner-1".to_string(),
            org_id: 4,
            target_logical_hash: "abc123".to_string(),
            target_server_url: "ws://new.example:59901".to_string(),
            target_server_identity: "new-node".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SyncMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            SyncMessage::MigrationFinalizeReq {
                owner_token,
                org_id,
                target_logical_hash,
                target_server_url,
                target_server_identity,
            } => {
                assert_eq!(owner_token, "owner-1");
                assert_eq!(org_id, 4);
                assert_eq!(target_logical_hash, "abc123");
                assert_eq!(target_server_url, "ws://new.example:59901");
                assert_eq!(target_server_identity, "new-node");
            }
            _ => panic!("wrong message variant"),
        }
    }
}
