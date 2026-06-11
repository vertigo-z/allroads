use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChangeOp {
    Insert,
    Update,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub change_id: String,
    pub timestamp_ms: i64,
    pub origin_node: String,
    pub entity: String,
    pub entity_id: String,
    pub op: ChangeOp,
    pub payload: serde_json::Value,
    pub hlc: String,
}
