//! Asymmetric safe Write-back pipeline:
//! Typestate-enforced execution (`ProposedAction -> CfgValidatedAction -> PolicyAuthorizedAction
//! -> BusinessCheckedAction -> DryRunVerifiedAction -> HumanApprovedAction`),
//! Wasmtime sandbox isolation, SQLite simulated ERP (idempotency + optimistic locking),
//! and hash-chained JSONL audit logging.

use axiom_authz::{AuthzError, AxiomAuthorizer, PrincipalKind};
use axiom_cfg::{ActionCfgParser, CfgError};
use axiom_core::{AuditEventKind, AuditLogEntry, DryRunDiff, TypedAction};
use axiom_data::{DataError, OntologyGraphStore};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use wasmtime::{Caller, Engine, Linker, Module, Store};

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("CFG validation failed: {0}")]
    Cfg(#[from] CfgError),
    #[error("Cedar authorization failed: {0}")]
    Authz(#[from] AuthzError),
    #[error("Cedar policy denied action: {0}")]
    PolicyDenied(String),
    #[error("Business constraint failed: {0}")]
    BusinessConstraint(String),
    #[error("Data store error: {0}")]
    Data(#[from] DataError),
    #[error("Wasmtime sandbox error: {0}")]
    Wasm(String),
    #[error("ERP database error: {0}")]
    Erp(String),
    #[error("Duplicate idempotency key: {0}")]
    DuplicateIdempotencyKey(String),
    #[error("Optimistic lock conflict: expected version {expected}, actual {actual}")]
    OptimisticLockConflict { expected: i64, actual: i64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Abstract ERP repository trait (swappable for PostgreSQL / MySQL in production).
pub trait ErpRepository: Send + Sync {
    fn current_version(&self) -> Result<i64, ActionError>;
    fn dry_run(&self, action: &TypedAction) -> Result<DryRunDiff, ActionError>;
    fn commit(&self, action: &TypedAction) -> Result<serde_json::Value, ActionError>;
}

/// SQLite-backed simulated ERP database with idempotency keys & optimistic locking.
pub struct SqliteErpRepository {
    conn: Mutex<Connection>,
}

impl SqliteErpRepository {
    pub fn new(db_path: Option<&Path>) -> Result<Self, ActionError> {
        let conn = match db_path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Connection::open(p).map_err(|e| ActionError::Erp(e.to_string()))?
            }
            None => Connection::open_in_memory().map_err(|e| ActionError::Erp(e.to_string()))?,
        };

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS erp_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO erp_meta (id, version) VALUES (1, 1);
            CREATE TABLE IF NOT EXISTS purchase_orders (
                order_id TEXT PRIMARY KEY,
                part_number TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                target_rev TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bom_revisions (
                rev_req_id TEXT PRIMARY KEY,
                parent_part_number TEXT NOT NULL,
                child_part_number TEXT NOT NULL,
                new_rev TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                idem_key TEXT PRIMARY KEY,
                committed_at TEXT NOT NULL
            );",
        )
        .map_err(|e| ActionError::Erp(e.to_string()))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl ErpRepository for SqliteErpRepository {
    fn current_version(&self) -> Result<i64, ActionError> {
        let conn = self.conn.lock().unwrap();
        let ver: i64 = conn
            .query_row("SELECT version FROM erp_meta WHERE id = 1", [], |r| r.get(0))
            .map_err(|e| ActionError::Erp(e.to_string()))?;
        Ok(ver)
    }

    fn dry_run(&self, action: &TypedAction) -> Result<DryRunDiff, ActionError> {
        let ver = self.current_version()?;
        let diff = match action {
            TypedAction::CreatePurchaseOrderDraft {
                part_number,
                quantity,
                target_rev,
                reason,
                ..
            } => DryRunDiff {
                target_table: "purchase_orders".to_string(),
                operation: "INSERT_DRAFT".to_string(),
                before: serde_json::json!({ "erp_version": ver, "draft_exists": false }),
                after: serde_json::json!({
                    "erp_version": ver + 1,
                    "part_number": part_number,
                    "quantity": quantity,
                    "target_rev": target_rev,
                    "reason": reason,
                    "status": "DRAFT"
                }),
            },
            TypedAction::CreateBomRevisionRequest {
                parent_part_number,
                child_part_number,
                new_rev,
                reason,
                ..
            } => DryRunDiff {
                target_table: "bom_revisions".to_string(),
                operation: "INSERT_REVISION_REQUEST".to_string(),
                before: serde_json::json!({ "erp_version": ver, "request_exists": false }),
                after: serde_json::json!({
                    "erp_version": ver + 1,
                    "parent_part_number": parent_part_number,
                    "child_part_number": child_part_number,
                    "new_rev": new_rev,
                    "reason": reason,
                    "status": "REQUESTED"
                }),
            },
        };
        Ok(diff)
    }

    fn commit(&self, action: &TypedAction) -> Result<serde_json::Value, ActionError> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn
            .transaction()
            .map_err(|e| ActionError::Erp(e.to_string()))?;

        // 1. Idempotency check
        let idem_key = action.idempotency_key();
        let exists: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM idempotency_keys WHERE idem_key = ?1",
                params![idem_key],
                |r| r.get(0),
            )
            .map_err(|e| ActionError::Erp(e.to_string()))?;
        if exists > 0 {
            return Err(ActionError::DuplicateIdempotencyKey(idem_key.to_string()));
        }

        // 2. Optimistic locking check
        let actual_ver: i64 = tx
            .query_row("SELECT version FROM erp_meta WHERE id = 1", [], |r| r.get(0))
            .map_err(|e| ActionError::Erp(e.to_string()))?;
        let expected_ver = action.expected_erp_version();
        if actual_ver != expected_ver {
            return Err(ActionError::OptimisticLockConflict {
                expected: expected_ver,
                actual: actual_ver,
            });
        }

        let new_ver = actual_ver + 1;
        tx.execute("UPDATE erp_meta SET version = ?1 WHERE id = 1", params![new_ver])
            .map_err(|e| ActionError::Erp(e.to_string()))?;
        tx.execute(
            "INSERT INTO idempotency_keys (idem_key, committed_at) VALUES (?1, ?2)",
            params![idem_key, chrono::Utc::now().to_rfc3339()],
        )
        .map_err(|e| ActionError::Erp(e.to_string()))?;

        let record_id = format!("ERP-{}", uuid::Uuid::new_v4().simple());
        match action {
            TypedAction::CreatePurchaseOrderDraft {
                part_number,
                quantity,
                target_rev,
                reason,
                ..
            } => {
                tx.execute(
                    "INSERT INTO purchase_orders (order_id, part_number, quantity, target_rev, reason, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'DRAFT')",
                    params![record_id, part_number, quantity, target_rev, reason],
                )
                .map_err(|e| ActionError::Erp(e.to_string()))?;
            }
            TypedAction::CreateBomRevisionRequest {
                parent_part_number,
                child_part_number,
                new_rev,
                reason,
                ..
            } => {
                tx.execute(
                    "INSERT INTO bom_revisions (rev_req_id, parent_part_number, child_part_number, new_rev, reason, status)
                     VALUES (?1, ?2, ?3, ?4, ?5, 'REQUESTED')",
                    params![record_id, parent_part_number, child_part_number, new_rev, reason],
                )
                .map_err(|e| ActionError::Erp(e.to_string()))?;
            }
        }

        tx.commit().map_err(|e| ActionError::Erp(e.to_string()))?;

        Ok(serde_json::json!({
            "record_id": record_id,
            "new_erp_version": new_ver,
            "idempotency_key": idem_key,
        }))
    }
}

/// Hash-chained JSONL audit logger.
pub struct AuditLogger {
    log_path: Option<PathBuf>,
    entries: Mutex<Vec<AuditLogEntry>>,
}

impl AuditLogger {
    pub fn new(log_path: Option<PathBuf>) -> Result<Self, ActionError> {
        if let Some(p) = &log_path {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Ok(Self {
            log_path,
            entries: Mutex::new(Vec::new()),
        })
    }

    pub fn record(
        &self,
        event_kind: AuditEventKind,
        actor: &str,
        action_id: &str,
        details: serde_json::Value,
    ) -> AuditLogEntry {
        let mut guard = self.entries.lock().unwrap();
        let seq = (guard.len() as u64) + 1;
        let prev_hash = guard
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "GENESIS".to_string());
        let entry = AuditLogEntry::new(seq, event_kind, actor, action_id, details, prev_hash);
        if let Some(p) = &self.log_path {
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(file, "{}", serde_json::to_string(&entry).unwrap_or_default());
            }
        }
        guard.push(entry.clone());
        entry
    }

    pub fn entries(&self) -> Vec<AuditLogEntry> {
        self.entries.lock().unwrap().clone()
    }
}

struct HostState {
    erp: Arc<dyn ErpRepository>,
    dry_run_result: Option<Result<DryRunDiff, ActionError>>,
    commit_result: Option<Result<serde_json::Value, ActionError>>,
}

/// Wasmtime sandbox executor that loads the compiled `wasm32-wasip1` guest module
/// and exposes ONLY `host_erp_dry_run` and `host_erp_commit`.
pub struct WasmActionExecutor {
    engine: Engine,
    module: Module,
}

impl WasmActionExecutor {
    pub fn from_wasm_file(path: &Path) -> Result<Self, ActionError> {
        let engine = Engine::default();
        let module = Module::from_file(&engine, path).map_err(|e| ActionError::Wasm(e.to_string()))?;
        Ok(Self { engine, module })
    }

    /// Locate the compiled `axiom_wasm_worker.wasm` in `target/wasm32-wasip1/release/`
    /// or via `AXIOM_WASM_PATH`.
    pub fn from_default_workspace_build() -> Result<Self, ActionError> {
        if let Ok(p) = std::env::var("AXIOM_WASM_PATH") {
            let path = PathBuf::from(p);
            if path.exists() {
                return Self::from_wasm_file(&path);
            }
        }
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = manifest_dir
            .join("../../target/wasm32-wasip1/release/axiom_wasm_worker.wasm");
        if candidate.exists() {
            return Self::from_wasm_file(&candidate);
        }
        let debug_candidate = manifest_dir
            .join("../../target/wasm32-wasip1/debug/axiom_wasm_worker.wasm");
        if debug_candidate.exists() {
            return Self::from_wasm_file(&debug_candidate);
        }
        Err(ActionError::Wasm(format!(
            "axiom_wasm_worker.wasm not found at {} (run `cargo build -p axiom-wasm-worker --target wasm32-wasip1 --release`)",
            candidate.display()
        )))
    }

    fn run_in_sandbox(
        &self,
        erp: Arc<dyn ErpRepository>,
        action: &TypedAction,
        is_dry_run: bool,
    ) -> Result<HostState, ActionError> {
        let mut linker: Linker<HostState> = Linker::new(&self.engine);

        linker
            .func_wrap(
                "axiom_host",
                "host_erp_dry_run",
                |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                        return -10;
                    };
                    let mut buf = vec![0u8; len as usize];
                    if mem.read(&caller, ptr as usize, &mut buf).is_err() {
                        return -11;
                    }
                    let Ok(act) = serde_json::from_slice::<TypedAction>(&buf) else {
                        return -12;
                    };
                    let res = caller.data().erp.dry_run(&act);
                    let ok = res.is_ok();
                    caller.data_mut().dry_run_result = Some(res);
                    if ok { 0 } else { -13 }
                },
            )
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        linker
            .func_wrap(
                "axiom_host",
                "host_erp_commit",
                |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                    let Some(mem) = caller.get_export("memory").and_then(|e| e.into_memory()) else {
                        return -20;
                    };
                    let mut buf = vec![0u8; len as usize];
                    if mem.read(&caller, ptr as usize, &mut buf).is_err() {
                        return -21;
                    }
                    let Ok(act) = serde_json::from_slice::<TypedAction>(&buf) else {
                        return -22;
                    };
                    let res = caller.data().erp.commit(&act);
                    let ok = res.is_ok();
                    caller.data_mut().commit_result = Some(res);
                    if ok { 0 } else { -23 }
                },
            )
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        let mut store = Store::new(
            &self.engine,
            HostState {
                erp,
                dry_run_result: None,
                commit_result: None,
            },
        );

        linker
            .define_unknown_imports_as_default_values(&mut store, &self.module)
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        let payload = serde_json::to_vec(action).map_err(|e| ActionError::Wasm(e.to_string()))?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|e| ActionError::Wasm(e.to_string()))?;
        let ptr = alloc
            .call(&mut store, payload.len() as i32)
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        let mem = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| ActionError::Wasm("guest missing memory export".to_string()))?;
        mem.write(&mut store, ptr as usize, &payload)
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        let fn_name = if is_dry_run {
            "execute_dry_run"
        } else {
            "execute_commit"
        };
        let entry = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, fn_name)
            .map_err(|e| ActionError::Wasm(e.to_string()))?;
        let _rc = entry
            .call(&mut store, (ptr, payload.len() as i32))
            .map_err(|e| ActionError::Wasm(e.to_string()))?;

        Ok(store.into_data())
    }

    pub fn execute_dry_run(
        &self,
        erp: Arc<dyn ErpRepository>,
        action: &TypedAction,
    ) -> Result<DryRunDiff, ActionError> {
        let state = self.run_in_sandbox(erp, action, true)?;
        state
            .dry_run_result
            .unwrap_or_else(|| Err(ActionError::Wasm("guest did not invoke host_erp_dry_run".into())))
    }

    pub fn execute_commit(
        &self,
        erp: Arc<dyn ErpRepository>,
        action: &TypedAction,
    ) -> Result<serde_json::Value, ActionError> {
        let state = self.run_in_sandbox(erp, action, false)?;
        state
            .commit_result
            .unwrap_or_else(|| Err(ActionError::Wasm("guest did not invoke host_erp_commit".into())))
    }
}

// ============================================================================
// Typestate Pipeline: Enforces asymmetric safety at compile time
// ============================================================================

/// Stage 1: Raw proposed action text (untrusted).
pub struct ProposedAction {
    pub action_id: String,
    pub actor: String,
    pub raw_dsl_or_json: String,
}

/// Stage 2: Validated by strict Context-Free Grammar (CFG).
pub struct CfgValidatedAction {
    pub action_id: String,
    pub actor: String,
    pub action: TypedAction,
}

/// Stage 3: Authorized by Cedar policy (proposal or write-back check).
pub struct PolicyAuthorizedAction {
    pub action_id: String,
    pub actor: String,
    pub action: TypedAction,
}

/// Stage 4: Verified against LadybugDB business constraints.
pub struct BusinessCheckedAction {
    pub action_id: String,
    pub actor: String,
    pub action: TypedAction,
}

/// Stage 5: Dry-run executed inside Wasmtime sandbox, diff captured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunVerifiedAction {
    pub action_id: String,
    pub actor: String,
    pub action: TypedAction,
    pub diff: DryRunDiff,
}

/// Stage 6: Approved by human User + Cedar Write-back policy verified.
/// ONLY this type can invoke `commit_via_wasmtime`.
pub struct HumanApprovedAction {
    pub action_id: String,
    pub approver: String,
    pub action: TypedAction,
    pub diff: DryRunDiff,
}

impl ProposedAction {
    pub fn new(
        action_id: impl Into<String>,
        actor: impl Into<String>,
        raw_dsl_or_json: impl Into<String>,
    ) -> Self {
        Self {
            action_id: action_id.into(),
            actor: actor.into(),
            raw_dsl_or_json: raw_dsl_or_json.into(),
        }
    }

    /// Parse & constrain against the CFG grammar.
    pub fn validate_cfg(self, audit: &AuditLogger) -> Result<CfgValidatedAction, ActionError> {
        match ActionCfgParser::parse(&self.raw_dsl_or_json) {
            Ok(action) => {
                audit.record(
                    AuditEventKind::CfgValidated,
                    &self.actor,
                    &self.action_id,
                    serde_json::json!({ "action_kind": action.action_kind() }),
                );
                Ok(CfgValidatedAction {
                    action_id: self.action_id,
                    actor: self.actor,
                    action,
                })
            }
            Err(e) => {
                audit.record(
                    AuditEventKind::CfgRejected,
                    &self.actor,
                    &self.action_id,
                    serde_json::json!({ "error": e.to_string(), "raw": self.raw_dsl_or_json }),
                );
                Err(ActionError::Cfg(e))
            }
        }
    }
}

impl CfgValidatedAction {
    /// Verify Cedar authorization. If `approval_status != "APPROVED"`, Cedar MUST deny.
    pub fn authorize_policy(
        self,
        authorizer: &AxiomAuthorizer,
        principal_kind: PrincipalKind,
        approval_status: &str,
        dry_run_passed: bool,
        audit: &AuditLogger,
    ) -> Result<PolicyAuthorizedAction, ActionError> {
        let outcome = authorizer.authorize(
            principal_kind,
            &self.actor,
            self.action.action_kind(),
            self.action.idempotency_key(),
            approval_status,
            dry_run_passed,
            self.action.action_kind(),
        )?;
        if !outcome.allowed {
            audit.record(
                AuditEventKind::CedarDenied,
                &self.actor,
                &self.action_id,
                serde_json::json!({
                    "action": self.action.action_kind(),
                    "approval_status": approval_status,
                    "dry_run_passed": dry_run_passed,
                    "reasons": outcome.reasons,
                }),
            );
            return Err(ActionError::PolicyDenied(format!(
                "{} denied with approval_status={approval_status}, dry_run_passed={dry_run_passed}",
                self.action.action_kind()
            )));
        }
        audit.record(
            AuditEventKind::CedarAllowed,
            &self.actor,
            &self.action_id,
            serde_json::json!({ "action": self.action.action_kind() }),
        );
        Ok(PolicyAuthorizedAction {
            action_id: self.action_id,
            actor: self.actor,
            action: self.action,
        })
    }

    /// Proceed to business check before human approval (used when staging a draft for human review).
    pub fn stage_for_business_check(self) -> PolicyAuthorizedAction {
        PolicyAuthorizedAction {
            action_id: self.action_id,
            actor: self.actor,
            action: self.action,
        }
    }
}

impl PolicyAuthorizedAction {
    /// Verify manufacturing business constraints against LadybugDB.
    pub fn check_business(
        self,
        store: &OntologyGraphStore,
        audit: &AuditLogger,
    ) -> Result<BusinessCheckedAction, ActionError> {
        let check_res = match &self.action {
            TypedAction::CreatePurchaseOrderDraft {
                part_number,
                quantity,
                target_rev,
                ..
            } => {
                if *quantity <= 0 {
                    Err(ActionError::BusinessConstraint(format!(
                        "quantity must be > 0, got {quantity}"
                    )))
                } else {
                    match store.lookup_part_and_drawing(part_number)? {
                        None => Err(ActionError::BusinessConstraint(format!(
                            "Part '{part_number}' does not exist in ontology graph"
                        ))),
                        Some((part, drawing)) => {
                            if part.status == "OBSOLETE" {
                                Err(ActionError::BusinessConstraint(format!(
                                    "Part '{part_number}' is OBSOLETE"
                                )))
                            } else if let Some(dwg) = drawing {
                                if dwg.status == "OBSOLETE" {
                                    Err(ActionError::BusinessConstraint(format!(
                                        "Drawing '{}' for Part '{part_number}' is OBSOLETE",
                                        dwg.drawing_id
                                    )))
                                } else if dwg.latest_rev != *target_rev {
                                    Err(ActionError::BusinessConstraint(format!(
                                        "Revision mismatch: target_rev '{target_rev}' != Drawing latest_rev '{}'",
                                        dwg.latest_rev
                                    )))
                                } else {
                                    Ok(())
                                }
                            } else {
                                Err(ActionError::BusinessConstraint(format!(
                                    "Part '{part_number}' has no valid Drawing in graph"
                                )))
                            }
                        }
                    }
                }
            }
            TypedAction::CreateBomRevisionRequest {
                parent_part_number,
                child_part_number,
                new_rev,
                ..
            } => {
                if new_rev.trim().is_empty() {
                    Err(ActionError::BusinessConstraint("new_rev cannot be empty".into()))
                } else {
                    let p = store.lookup_part_and_drawing(parent_part_number)?;
                    let c = store.lookup_part_and_drawing(child_part_number)?;
                    match (p, c) {
                        (Some((parent, _)), Some((child, _))) => {
                            if parent.status == "OBSOLETE" || child.status == "OBSOLETE" {
                                Err(ActionError::BusinessConstraint(
                                    "Cannot revise BOM involving OBSOLETE part".into(),
                                ))
                            } else {
                                Ok(())
                            }
                        }
                        _ => Err(ActionError::BusinessConstraint(format!(
                            "Parent '{parent_part_number}' or child '{child_part_number}' missing from graph"
                        ))),
                    }
                }
            }
        };

        match check_res {
            Ok(()) => {
                audit.record(
                    AuditEventKind::BusinessConstraintPassed,
                    &self.actor,
                    &self.action_id,
                    serde_json::json!({ "action": self.action.action_kind() }),
                );
                Ok(BusinessCheckedAction {
                    action_id: self.action_id,
                    actor: self.actor,
                    action: self.action,
                })
            }
            Err(e) => {
                audit.record(
                    AuditEventKind::BusinessConstraintFailed,
                    &self.actor,
                    &self.action_id,
                    serde_json::json!({ "error": e.to_string() }),
                );
                Err(e)
            }
        }
    }
}

impl BusinessCheckedAction {
    /// Execute dry-run inside the Wasmtime sandbox and produce Before/After diff.
    pub fn dry_run(
        self,
        wasm: &WasmActionExecutor,
        erp: Arc<dyn ErpRepository>,
        audit: &AuditLogger,
    ) -> Result<DryRunVerifiedAction, ActionError> {
        let diff = wasm.execute_dry_run(erp, &self.action)?;
        audit.record(
            AuditEventKind::DryRunCompleted,
            &self.actor,
            &self.action_id,
            serde_json::json!({ "diff": diff }),
        );
        Ok(DryRunVerifiedAction {
            action_id: self.action_id,
            actor: self.actor,
            action: self.action,
            diff,
        })
    }
}

impl DryRunVerifiedAction {
    /// Require human User approval (Cedar `ApproveAction`) AND Cedar Write-back Allow (`APPROVED`).
    pub fn approve_by_human(
        self,
        authorizer: &AxiomAuthorizer,
        approver_kind: PrincipalKind,
        approver_id: &str,
        audit: &AuditLogger,
    ) -> Result<HumanApprovedAction, ActionError> {
        let approve_outcome = authorizer.authorize(
            approver_kind,
            approver_id,
            "ApproveAction",
            &self.action_id,
            "PENDING",
            true,
            "ApproveAction",
        )?;
        if !approve_outcome.allowed {
            audit.record(
                AuditEventKind::CedarDenied,
                approver_id,
                &self.action_id,
                serde_json::json!({ "action": "ApproveAction", "reasons": approve_outcome.reasons }),
            );
            return Err(ActionError::PolicyDenied(format!(
                "Principal '{approver_id}' is not authorized to ApproveAction"
            )));
        }

        let wb_outcome = authorizer.authorize(
            approver_kind,
            approver_id,
            self.action.action_kind(),
            self.action.idempotency_key(),
            "APPROVED",
            true,
            self.action.action_kind(),
        )?;
        if !wb_outcome.allowed {
            audit.record(
                AuditEventKind::CedarDenied,
                approver_id,
                &self.action_id,
                serde_json::json!({ "action": self.action.action_kind(), "reasons": wb_outcome.reasons }),
            );
            return Err(ActionError::PolicyDenied(format!(
                "Write-back '{}' denied by Cedar",
                self.action.action_kind()
            )));
        }

        audit.record(
            AuditEventKind::HumanApproved,
            approver_id,
            &self.action_id,
            serde_json::json!({ "action": self.action.action_kind() }),
        );

        Ok(HumanApprovedAction {
            action_id: self.action_id,
            approver: approver_id.to_string(),
            action: self.action,
            diff: self.diff,
        })
    }
}

impl HumanApprovedAction {
    /// Execute the final Write-back commit inside the Wasmtime sandbox.
    pub fn commit_via_wasmtime(
        self,
        wasm: &WasmActionExecutor,
        erp: Arc<dyn ErpRepository>,
        audit: &AuditLogger,
    ) -> Result<serde_json::Value, ActionError> {
        match wasm.execute_commit(erp, &self.action) {
            Ok(res) => {
                audit.record(
                    AuditEventKind::WriteBackCommitted,
                    &self.approver,
                    &self.action_id,
                    res.clone(),
                );
                Ok(res)
            }
            Err(e) => {
                audit.record(
                    AuditEventKind::WriteBackFailed,
                    &self.approver,
                    &self.action_id,
                    serde_json::json!({ "error": e.to_string() }),
                );
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_data::extract_parts_and_bom_from_rows;
    use axiom_pcfg::preprocess_messy_csv;
    use std::path::PathBuf;

    async fn setup_store() -> OntologyGraphStore {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let bom_csv = std::fs::read_to_string(fixtures_dir.join("bom_sample_messy.csv")).unwrap();
        let table = preprocess_messy_csv(&bom_csv).unwrap();
        let (parts, bom_edges) = extract_parts_and_bom_from_rows(&table.rows);
        let mut store = OntologyGraphStore::new(None).unwrap();
        store
            .ingest_csv_with_bom(
                parts,
                bom_edges,
                &fixtures_dir.join("drawings_sample.csv"),
                &fixtures_dir.join("erp_orders_sample.csv"),
            )
            .await
            .unwrap();
        store
    }

    fn setup_authorizer() -> AxiomAuthorizer {
        let schema = include_str!("../../../policies/axiom.cedarschema");
        let policy = include_str!("../../../policies/axiom.cedar");
        AxiomAuthorizer::from_str(schema, policy).unwrap()
    }

    #[tokio::test]
    async fn test_full_writeback_pipeline_and_guards() {
        let store = setup_store().await;
        let authz = setup_authorizer();
        let wasm = WasmActionExecutor::from_default_workspace_build().unwrap();
        let erp: Arc<dyn ErpRepository> = Arc::new(SqliteErpRepository::new(None).unwrap());
        let audit = AuditLogger::new(None).unwrap();

        // 1. CFG rejects undefined action
        let bad = ProposedAction::new("act-bad", "agent-1", r#"ExecuteShell { cmd: "id" }"#);
        assert!(matches!(bad.validate_cfg(&audit), Err(ActionError::Cfg(_))));

        // 2. Cedar denies unapproved Write-back
        let valid_dsl = r#"CreatePurchaseOrderDraft {
            part_number: "PRT-1001",
            quantity: 5,
            target_rev: "Rev.C",
            reason: "Replenish motor A1",
            idempotency_key: "idem-test-001",
            expected_erp_version: 1
        }"#;
        let cfg_ok = ProposedAction::new("act-1", "agent-1", valid_dsl)
            .validate_cfg(&audit)
            .unwrap();
        assert!(matches!(
            cfg_ok.authorize_policy(&authz, PrincipalKind::Agent, "PENDING", true, &audit),
            Err(ActionError::PolicyDenied(_))
        ));

        // 3. Business constraint blocks obsolete part (PRT-1003) and revision mismatch (PRT-1002 Rev.B vs Rev.D)
        let obs_dsl = r#"CreatePurchaseOrderDraft {
            part_number: "PRT-1003",
            quantity: 2,
            target_rev: "Rev.A",
            reason: "Should fail obsolete",
            idempotency_key: "idem-obs",
            expected_erp_version: 1
        }"#;
        let obs_res = ProposedAction::new("act-obs", "agent-1", obs_dsl)
            .validate_cfg(&audit)
            .unwrap()
            .stage_for_business_check()
            .check_business(&store, &audit);
        assert!(matches!(obs_res, Err(ActionError::BusinessConstraint(_))));

        // 4. Happy path through Wasmtime sandbox -> Commit
        let dry_run = ProposedAction::new("act-ok", "agent-1", valid_dsl)
            .validate_cfg(&audit)
            .unwrap()
            .stage_for_business_check()
            .check_business(&store, &audit)
            .unwrap()
            .dry_run(&wasm, erp.clone(), &audit)
            .unwrap();

        // Agent cannot approve
        assert!(dry_run
            .clone()
            .approve_by_human(&authz, PrincipalKind::Agent, "agent-1", &audit)
            .is_err());

        // Human User approves and commits via Wasmtime
        let approved = dry_run
            .approve_by_human(&authz, PrincipalKind::User, "tanaka", &audit)
            .unwrap();
        let commit_res = approved.commit_via_wasmtime(&wasm, erp.clone(), &audit).unwrap();
        assert_eq!(commit_res["new_erp_version"], 2);

        // 5. Idempotency key prevents duplicate execution
        let dup = ProposedAction::new("act-dup", "agent-1", valid_dsl)
            .validate_cfg(&audit)
            .unwrap()
            .stage_for_business_check()
            .check_business(&store, &audit)
            .unwrap()
            .dry_run(&wasm, erp.clone(), &audit)
            .unwrap()
            .approve_by_human(&authz, PrincipalKind::User, "tanaka", &audit)
            .unwrap()
            .commit_via_wasmtime(&wasm, erp.clone(), &audit);
        assert!(matches!(dup, Err(ActionError::DuplicateIdempotencyKey(_))));

        // 6. Optimistic lock conflict when expected_erp_version is stale (1 instead of 2)
        let stale_dsl = r#"CreatePurchaseOrderDraft {
            part_number: "PRT-1001",
            quantity: 3,
            target_rev: "Rev.C",
            reason: "Stale version test",
            idempotency_key: "idem-test-002",
            expected_erp_version: 1
        }"#;
        let stale = ProposedAction::new("act-stale", "agent-1", stale_dsl)
            .validate_cfg(&audit)
            .unwrap()
            .stage_for_business_check()
            .check_business(&store, &audit)
            .unwrap()
            .dry_run(&wasm, erp.clone(), &audit)
            .unwrap()
            .approve_by_human(&authz, PrincipalKind::User, "tanaka", &audit)
            .unwrap()
            .commit_via_wasmtime(&wasm, erp.clone(), &audit);
        assert!(matches!(
            stale,
            Err(ActionError::OptimisticLockConflict { expected: 1, actual: 2 })
        ));

        // Verify audit hash chain integrity
        AuditLogEntry::verify_chain(&audit.entries()).unwrap();
    }
}
