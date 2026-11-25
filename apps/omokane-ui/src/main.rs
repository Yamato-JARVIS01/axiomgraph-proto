//! OMOIKANE (思兼) UI & Headless Axum API Server.
//! Binds to 127.0.0.1:8787 by default (designed for Tailscale Serve / Tauri v2 WebView).

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Html,
    routing::{get, post},
    Json, Router,
};
use axiom_action::{
    AuditLogger, ErpRepository, ProposedAction, SqliteErpRepository, WasmActionExecutor,
};
use axiom_authz::{AxiomAuthorizer, PrincipalKind};
use axiom_core::{AuditEventKind, DryRunDiff, Inconsistency, OntologyAttr, TypedAction};
use axiom_data::{extract_parts_and_bom_from_rows, OntologyGraphStore};
use axiom_pcfg::{preprocess_messy_csv, FeedbackSample, MappingResolution, PcfgGrammar};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

#[derive(Clone, Serialize)]
struct StagedActionItem {
    action_id: String,
    status: String,
    action: TypedAction,
    diff: DryRunDiff,
}

type ColumnEntry = (usize, String, Vec<String>, Vec<String>);

struct AppState {
    inbox_dir: String,
    grammar: Mutex<PcfgGrammar>,
    columns: Mutex<Vec<ColumnEntry>>,
    pcfg_results: Mutex<Vec<MappingResolution>>,
    store: Mutex<OntologyGraphStore>,
    inconsistencies: Mutex<Vec<Inconsistency>>,
    authorizer: AxiomAuthorizer,
    wasm: WasmActionExecutor,
    erp: Arc<dyn ErpRepository>,
    audit: AuditLogger,
    staged_actions: Mutex<Vec<StagedActionItem>>,
}

#[derive(Deserialize)]
struct FeedbackRequest {
    column_index: usize,
    chosen_attr: OntologyAttr,
}

#[derive(Deserialize)]
struct ActionDecisionRequest {
    action_id: String,
    approver: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let fixtures = root.join("fixtures");
    let policies = root.join("policies");

    let bom_csv = std::fs::read_to_string(fixtures.join("bom_sample_messy.csv"))?;
    let table = preprocess_messy_csv(&bom_csv)?;
    let (parts, bom_edges) = extract_parts_and_bom_from_rows(&table.rows);

    let mut store = OntologyGraphStore::new(None)?;
    store
        .ingest_csv_with_bom(
            parts,
            bom_edges,
            &fixtures.join("drawings_sample.csv"),
            &fixtures.join("erp_orders_sample.csv"),
        )
        .await?;
    let inconsistencies = store.detect_inconsistencies().await?;

    let grammar = PcfgGrammar::default();
    let mut columns = Vec::new();
    for (idx, hdr) in table.headers.iter().enumerate() {
        let vals: Vec<String> = table.rows.iter().map(|r| r[idx].clone()).collect();
        columns.push((idx, hdr.clone(), table.header_token_lists[idx].clone(), vals));
    }
    // Include one unfamiliar column to showcase Unknown -> Human Feedback -> Re-score in UI
    columns.push((
        7,
        "X_Vendor_Ref".to_string(),
        vec!["x_vendor_ref".to_string()],
        vec!["PRT-1001".to_string(), "PRT-1002".to_string()],
    ));

    let pcfg_results: Vec<MappingResolution> = columns
        .iter()
        .map(|(idx, hdr, toks, vals)| grammar.resolve_column(*idx, hdr, toks, vals, 3))
        .collect();

    let authorizer = AxiomAuthorizer::from_files(
        &policies.join("axiom.cedarschema"),
        &policies.join("axiom.cedar"),
    )?;
    let wasm = WasmActionExecutor::from_default_workspace_build()?;
    let erp: Arc<dyn ErpRepository> = Arc::new(SqliteErpRepository::new(None)?);
    let audit = AuditLogger::new(None)?;

    let po_dsl = r#"CreatePurchaseOrderDraft {
        part_number: "PRT-1001",
        quantity: 10,
        target_rev: "Rev.C",
        reason: "Replenish servo motor A1",
        idempotency_key: "ui-po-001",
        expected_erp_version: 1
    }"#;
    let dry_run = ProposedAction::new("UI-ACT-001", "omoikane-agent", po_dsl)
        .validate_cfg(&audit)?
        .stage_for_business_check()
        .check_business(&store, &audit)?
        .dry_run(&wasm, erp.clone(), &audit)?;

    let staged = vec![StagedActionItem {
        action_id: dry_run.action_id,
        status: "PENDING_APPROVAL".to_string(),
        action: dry_run.action,
        diff: dry_run.diff,
    }];

    let state = Arc::new(AppState {
        inbox_dir: fixtures.display().to_string(),
        grammar: Mutex::new(grammar),
        columns: Mutex::new(columns),
        pcfg_results: Mutex::new(pcfg_results),
        store: Mutex::new(store),
        inconsistencies: Mutex::new(inconsistencies),
        authorizer,
        wasm,
        erp,
        audit,
        staged_actions: Mutex::new(staged),
    });

    let app = Router::new()
        .route("/", get(|| async { Html(include_str!("ui.html")) }))
        .route("/api/status", get(get_status))
        .route("/api/pcfg", get(get_pcfg))
        .route("/api/pcfg/feedback", post(post_pcfg_feedback))
        .route("/api/inconsistencies", get(get_inconsistencies))
        .route("/api/actions", get(get_actions))
        .route("/api/actions/approve", post(post_approve_action))
        .route("/api/actions/reject", post(post_reject_action))
        .route("/api/audit", get(get_audit))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let bind_addr = std::env::var("AXIOM_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    println!("OMOIKANE UI / API listening on http://{bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_status(State(s): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let ver = s.erp.current_version().unwrap_or(0);
    let parts = s.store.lock().unwrap().list_parts().len();
    Json(serde_json::json!({
        "inbox_dir": s.inbox_dir,
        "erp_version": ver,
        "parts_count": parts,
    }))
}

async fn get_pcfg(State(s): State<Arc<AppState>>) -> Json<Vec<MappingResolution>> {
    Json(s.pcfg_results.lock().unwrap().clone())
}

async fn post_pcfg_feedback(
    State(s): State<Arc<AppState>>,
    Json(req): Json<FeedbackRequest>,
) -> StatusCode {
    let cols = s.columns.lock().unwrap();
    if let Some((_, _, toks, vals)) = cols.iter().find(|(i, _, _, _)| *i == req.column_index) {
        let mut g = s.grammar.lock().unwrap();
        g.apply_feedback(&FeedbackSample {
            header_tokens: toks.clone(),
            sample_values: vals.clone(),
            chosen_attr: req.chosen_attr,
        });
        let updated: Vec<MappingResolution> = cols
            .iter()
            .map(|(idx, hdr, t, v)| g.resolve_column(*idx, hdr, t, v, 3))
            .collect();
        *s.pcfg_results.lock().unwrap() = updated;
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn get_inconsistencies(State(s): State<Arc<AppState>>) -> Json<Vec<Inconsistency>> {
    Json(s.inconsistencies.lock().unwrap().clone())
}

async fn get_actions(State(s): State<Arc<AppState>>) -> Json<Vec<StagedActionItem>> {
    Json(s.staged_actions.lock().unwrap().clone())
}

async fn post_approve_action(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ActionDecisionRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut list = s.staged_actions.lock().unwrap();
    let Some(item) = list.iter_mut().find(|a| a.action_id == req.action_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "action not found"})),
        );
    };
    let dsl = axiom_cfg::ActionCfgParser::format_dsl(&item.action);
    let res = ProposedAction::new(&item.action_id, "omoikane-agent", dsl)
        .validate_cfg(&s.audit)
        .and_then(|c| {
            let store = s.store.lock().unwrap();
            c.stage_for_business_check().check_business(&store, &s.audit)
        })
        .and_then(|b| b.dry_run(&s.wasm, s.erp.clone(), &s.audit))
        .and_then(|d| {
            d.approve_by_human(&s.authorizer, PrincipalKind::User, &req.approver, &s.audit)
        })
        .and_then(|a| a.commit_via_wasmtime(&s.wasm, s.erp.clone(), &s.audit));

    match res {
        Ok(val) => {
            item.status = "COMMITTED".to_string();
            (StatusCode::OK, Json(val))
        }
        Err(e) => {
            item.status = "FAILED".to_string();
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        }
    }
}

async fn post_reject_action(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ActionDecisionRequest>,
) -> StatusCode {
    let mut list = s.staged_actions.lock().unwrap();
    if let Some(item) = list.iter_mut().find(|a| a.action_id == req.action_id) {
        item.status = "REJECTED".to_string();
        s.audit.record(
            AuditEventKind::HumanRejected,
            &req.approver,
            &req.action_id,
            serde_json::json!({ "reason": "rejected by human operator" }),
        );
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn get_audit(State(s): State<Arc<AppState>>) -> Json<Vec<axiom_core::AuditLogEntry>> {
    Json(s.audit.entries())
}
