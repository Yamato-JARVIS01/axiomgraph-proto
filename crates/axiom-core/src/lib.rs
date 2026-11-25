//! Common domain models and audit log primitives for AxiomGraph (思兼 / OMOIKANE).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Core domain error types shared across crates.
#[derive(Debug, Error)]
pub enum AxiomError {
    #[error("invalid ontology attribute: {0}")]
    InvalidOntologyAttr(String),
    #[error("audit chain verification failed at seq {seq}: {reason}")]
    AuditChainBroken { seq: u64, reason: String },
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Canonical ontology attributes for manufacturing BOM / Drawing / ERP tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OntologyAttr {
    PartNumber,
    ParentPartNumber,
    PartName,
    Quantity,
    DrawingId,
    Revision,
    Status,
}

impl OntologyAttr {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PartNumber => "part_number",
            Self::ParentPartNumber => "parent_part_number",
            Self::PartName => "part_name",
            Self::Quantity => "quantity",
            Self::DrawingId => "drawing_id",
            Self::Revision => "revision",
            Self::Status => "status",
        }
    }

    pub fn parse(s: &str) -> Result<Self, AxiomError> {
        match s.trim() {
            "part_number" => Ok(Self::PartNumber),
            "parent_part_number" => Ok(Self::ParentPartNumber),
            "part_name" => Ok(Self::PartName),
            "quantity" => Ok(Self::Quantity),
            "drawing_id" => Ok(Self::DrawingId),
            "revision" => Ok(Self::Revision),
            "status" => Ok(Self::Status),
            other => Err(AxiomError::InvalidOntologyAttr(other.to_string())),
        }
    }

    pub fn all() -> &'static [OntologyAttr] {
        &[
            Self::PartNumber,
            Self::ParentPartNumber,
            Self::PartName,
            Self::Quantity,
            Self::DrawingId,
            Self::Revision,
            Self::Status,
        ]
    }
}

/// Manufacturing Part entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    pub part_number: String,
    pub name: String,
    pub drawing_id: String,
    pub drawing_rev: String,
    pub status: String,
}

/// BOM Parent-Child relationship edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BomEdge {
    pub parent_part_number: String,
    pub child_part_number: String,
    pub quantity: i64,
}

/// Engineering Drawing entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drawing {
    pub drawing_id: String,
    pub title: String,
    pub latest_rev: String,
    pub status: String,
}

/// ERP Purchase Order entity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurchaseOrder {
    pub order_id: String,
    pub part_number: String,
    pub quantity: i64,
    pub target_rev: String,
    pub status: String,
}

/// The 4 major structural/semantic inconsistencies detected in the ontology graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InconsistencyKind {
    DanglingReference,
    CircularReference,
    RevisionMismatch,
    ObsoletePartReference,
}

/// Detailed inconsistency finding from LadybugDB / DataFusion analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inconsistency {
    pub kind: InconsistencyKind,
    pub severity: String,
    pub entity_id: String,
    pub related_id: Option<String>,
    pub path: Vec<String>,
    pub description: String,
}

/// Grammar-constrained typed actions allowed for Write-back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action_type")]
pub enum TypedAction {
    CreatePurchaseOrderDraft {
        part_number: String,
        quantity: i64,
        target_rev: String,
        reason: String,
        idempotency_key: String,
        expected_erp_version: i64,
    },
    CreateBomRevisionRequest {
        parent_part_number: String,
        child_part_number: String,
        new_rev: String,
        reason: String,
        idempotency_key: String,
        expected_erp_version: i64,
    },
}

impl TypedAction {
    pub fn action_kind(&self) -> &'static str {
        match self {
            Self::CreatePurchaseOrderDraft { .. } => "CreatePurchaseOrderDraft",
            Self::CreateBomRevisionRequest { .. } => "CreateBomRevisionRequest",
        }
    }

    pub fn idempotency_key(&self) -> &str {
        match self {
            Self::CreatePurchaseOrderDraft { idempotency_key, .. }
            | Self::CreateBomRevisionRequest { idempotency_key, .. } => idempotency_key,
        }
    }

    pub fn expected_erp_version(&self) -> i64 {
        match self {
            Self::CreatePurchaseOrderDraft {
                expected_erp_version, ..
            }
            | Self::CreateBomRevisionRequest {
                expected_erp_version, ..
            } => *expected_erp_version,
        }
    }
}

/// Dry-run diff preview before human approval and commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunDiff {
    pub target_table: String,
    pub operation: String,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}

/// Audit log event categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    CfgRejected,
    CfgValidated,
    CedarDenied,
    CedarAllowed,
    BusinessConstraintFailed,
    BusinessConstraintPassed,
    DryRunCompleted,
    HumanApproved,
    HumanRejected,
    WriteBackCommitted,
    WriteBackFailed,
}

/// Hash-chained structured audit log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub event_kind: AuditEventKind,
    pub actor: String,
    pub action_id: String,
    pub details: serde_json::Value,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl AuditLogEntry {
    /// Create a new hash-chained audit entry.
    pub fn new(
        seq: u64,
        event_kind: AuditEventKind,
        actor: impl Into<String>,
        action_id: impl Into<String>,
        details: serde_json::Value,
        prev_hash: impl Into<String>,
    ) -> Self {
        let timestamp = Utc::now();
        let actor = actor.into();
        let action_id = action_id.into();
        let prev_hash = prev_hash.into();
        let entry_hash =
            Self::compute_hash(seq, &timestamp, event_kind, &actor, &action_id, &details, &prev_hash);
        Self {
            seq,
            timestamp,
            event_kind,
            actor,
            action_id,
            details,
            prev_hash,
            entry_hash,
        }
    }

    /// Compute deterministic SHA-256 hash over entry fields and previous hash.
    pub fn compute_hash(
        seq: u64,
        timestamp: &DateTime<Utc>,
        event_kind: AuditEventKind,
        actor: &str,
        action_id: &str,
        details: &serde_json::Value,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        let payload = serde_json::json!({
            "seq": seq,
            "timestamp": timestamp.to_rfc3339(),
            "event_kind": event_kind,
            "actor": actor,
            "action_id": action_id,
            "details": details,
            "prev_hash": prev_hash,
        });
        hasher.update(payload.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify a sequence of audit log entries for intact hash chaining.
    pub fn verify_chain(entries: &[AuditLogEntry]) -> Result<(), AxiomError> {
        let mut expected_prev = "GENESIS".to_string();
        for entry in entries {
            if entry.prev_hash != expected_prev {
                return Err(AxiomError::AuditChainBroken {
                    seq: entry.seq,
                    reason: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        expected_prev, entry.prev_hash
                    ),
                });
            }
            let recomputed = Self::compute_hash(
                entry.seq,
                &entry.timestamp,
                entry.event_kind,
                &entry.actor,
                &entry.action_id,
                &entry.details,
                &entry.prev_hash,
            );
            if entry.entry_hash != recomputed {
                return Err(AxiomError::AuditChainBroken {
                    seq: entry.seq,
                    reason: "entry_hash tampered or corrupted".to_string(),
                });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }
}
