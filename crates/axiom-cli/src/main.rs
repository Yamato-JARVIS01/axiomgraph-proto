//! AxiomGraph (思兼 / OMOIKANE) CLI:
//! - `demo`: End-to-end asymmetric safe ontology & write-back demonstration
//! - `eval-pcfg`: Precision / Recall / F1 / Unknown rate & self-improvement evaluation
//! - `bench`: Large-scale (20k+ nodes, 100k+ edges) ingestion, Cypher p50/p95/p99, and RSS benchmark
//! - `verify-policies`: Cedar SymCC formal invariant verification

use anyhow::Result;
use axiom_action::{
    AuditLogger, ErpRepository, ProposedAction, SqliteErpRepository, WasmActionExecutor,
};
use axiom_authz::{AxiomAuthorizer, PrincipalKind};
use axiom_cfg::{ActionGenerator, LocalLlmConfig};
use axiom_core::{AuditLogEntry, BomEdge, Drawing, OntologyAttr, Part, PurchaseOrder, TypedAction};
use axiom_data::{extract_parts_and_bom_from_rows, OntologyGraphStore};
use axiom_pcfg::{preprocess_messy_csv, FeedbackSample, MappingResolution, PcfgGrammar};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "axiom-cli", about = "AxiomGraph (思兼 / OMOIKANE) Prototype CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full E2E demo (PCFG -> DataFusion/LadybugDB -> CFG -> Cedar -> Wasmtime -> AuditLog)
    Demo,
    /// Evaluate PCFG Accuracy / Precision / Recall / F1 / Unknown rate before & after feedback
    EvalPcfg,
    /// Benchmark ingestion, Cypher p50/p95/p99 latency, and RSS memory
    Bench {
        #[arg(long, default_value_t = 20000)]
        nodes: usize,
    },
    /// Run Cedar SymCC formal policy invariant verification
    VerifyPolicies,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Demo => run_demo().await?,
        Commands::EvalPcfg => run_eval_pcfg()?,
        Commands::Bench { nodes } => run_bench(nodes).await?,
        Commands::VerifyPolicies => run_verify_policies().await?,
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

async fn run_demo() -> Result<()> {
    println!("=== AxiomGraph (思兼 / OMOIKANE) v0.1 E2E Demo ===");
    let root = workspace_root();
    let fixtures = root.join("fixtures");
    let policies = root.join("policies");

    // 1. PCFG ingestion & Unknown detection + feedback loop
    println!("\n[1/7] Loading & preprocessing messy manufacturing BOM CSV...");
    let bom_csv = std::fs::read_to_string(fixtures.join("bom_sample_messy.csv"))?;
    let table = preprocess_messy_csv(&bom_csv)?;
    println!(
        "  -> Flattened {} columns, {} clean rows (dropped {} noise/blank rows)",
        table.headers.len(),
        table.rows.len(),
        table.dropped_rows
    );

    let mut grammar = PcfgGrammar::default();
    for (idx, hdr) in table.headers.iter().enumerate() {
        let vals: Vec<String> = table.rows.iter().map(|r| r[idx].clone()).collect();
        let res = grammar.resolve_column(idx, hdr, &table.header_token_lists[idx], &vals, 2);
        match res {
            MappingResolution::Resolved {
                attr, confidence, ..
            } => println!("  -> Col {idx} '{hdr}' => {} (conf={confidence:.3})", attr.as_str()),
            MappingResolution::Unknown { reason, .. } => {
                println!("  -> Col {idx} '{hdr}' => UNKNOWN ({reason})")
            }
        }
    }

    // Demonstrate Unknown preservation + human feedback self-improvement
    let unk_tokens = vec!["x_vendor_pn".to_string()];
    let unk_vals = vec!["PRT-1001".to_string(), "PRT-1002".to_string()];
    let before = grammar.resolve_column(99, "X_Vendor_PN", &unk_tokens, &unk_vals, 2);
    println!("  -> Unfamiliar column 'X_Vendor_PN' before feedback: {:?}", match &before {
        MappingResolution::Unknown { reason, .. } => format!("UNKNOWN ({reason})"),
        MappingResolution::Resolved { attr, confidence, .. } => format!("{} ({confidence:.3})", attr.as_str()),
    });
    grammar.apply_feedback(&FeedbackSample {
        header_tokens: unk_tokens.clone(),
        sample_values: unk_vals.clone(),
        chosen_attr: OntologyAttr::PartNumber,
    });
    let after = grammar.resolve_column(99, "X_Vendor_PN", &unk_tokens, &unk_vals, 2);
    if let MappingResolution::Resolved {
        attr, confidence, ..
    } = after
    {
        println!(
            "  -> After human feedback: 'X_Vendor_PN' => {} (conf={confidence:.3})",
            attr.as_str()
        );
    }

    // 2. DataFusion + Arrow -> LadybugDB ingestion & 4-category inconsistency detection
    println!("\n[2/7] Ingesting via DataFusion + Arrow into LadybugDB (`lbug`)...");
    let (parts, bom_edges) = extract_parts_and_bom_from_rows(&table.rows);
    let mut store = OntologyGraphStore::new(None)?;
    let stats = store
        .ingest_csv_with_bom(
            parts,
            bom_edges,
            &fixtures.join("drawings_sample.csv"),
            &fixtures.join("erp_orders_sample.csv"),
        )
        .await?;
    println!(
        "  -> Loaded {} Parts, {} Drawings, {} Orders, {} BOM edges ({} dangling)",
        stats.parts_count,
        stats.drawings_count,
        stats.orders_count,
        stats.bom_edges_count,
        stats.dangling_bom_edges
    );

    let inconsistencies = store.detect_inconsistencies().await?;
    println!("  -> Detected {} inconsistencies:", inconsistencies.len());
    for inc in &inconsistencies {
        println!("     * [{:?} | {}] {}", inc.kind, inc.severity, inc.description);
    }

    // 3. CFG Action generation & rejection of forbidden actions
    println!("\n[3/7] Generating CFG-constrained TypedActions...");
    let audit_path = std::env::temp_dir().join("axiom_demo_audit_log.jsonl");
    let _ = std::fs::remove_file(&audit_path);
    let audit = AuditLogger::new(Some(audit_path.clone()))?;

    let bad_action = ProposedAction::new("act-bad", "omoikane-agent", r#"ExecuteShell { cmd: "whoami" }"#);
    println!(
        "  -> Forbidden action 'ExecuteShell' CFG check: {:?}",
        bad_action.validate_cfg(&audit).err().map(|e| e.to_string())
    );

    let gen = ActionGenerator::new(LocalLlmConfig::default());
    let (po_action, po_src) = gen
        .generate_action_or_fallback(
            "Create PO draft for PRT-1001",
            TypedAction::CreatePurchaseOrderDraft {
                part_number: "PRT-1001".into(),
                quantity: 10,
                target_rev: "Rev.C".into(),
                reason: "Safety stock replenishment".into(),
                idempotency_key: format!("demo-po-{}", uuid::Uuid::new_v4().simple()),
                expected_erp_version: 1,
            },
        )
        .await;
    let (bom_action, bom_src) = gen
        .generate_action_or_fallback(
            "Create BOM revision request for PRT-1002",
            TypedAction::CreateBomRevisionRequest {
                parent_part_number: "ASM-9000".into(),
                child_part_number: "PRT-1002".into(),
                new_rev: "Rev.D".into(),
                reason: "Resolve RevisionMismatch against DWG-1002 Rev.D".into(),
                idempotency_key: format!("demo-bom-{}", uuid::Uuid::new_v4().simple()),
                expected_erp_version: 2,
            },
        )
        .await;
    println!("  -> Generated PO action via {po_src}, BOM action via {bom_src}");

    // 4. Cedar authorization check (PENDING -> Deny, APPROVED -> Allow)
    println!("\n[4/7] Evaluating Cedar authorization policies...");
    let authz = AxiomAuthorizer::from_files(
        &policies.join("axiom.cedarschema"),
        &policies.join("axiom.cedar"),
    )?;
    let pending = authz.authorize(
        PrincipalKind::Agent,
        "omoikane-agent",
        "CreatePurchaseOrderDraft",
        "PRT-1001",
        "PENDING",
        true,
        "CreatePurchaseOrderDraft",
    )?;
    println!("  -> Unapproved (PENDING) Cedar decision: allowed={}", pending.allowed);
    assert!(!pending.allowed);

    // 5. Wasmtime sandbox dry-run + human approval + commit
    println!("\n[5/7] Running Wasmtime-isolated dry-run & Write-back...");
    let wasm = WasmActionExecutor::from_default_workspace_build()?;
    let erp: Arc<dyn ErpRepository> = Arc::new(SqliteErpRepository::new(None)?);

    for (idx, act) in [po_action, bom_action].into_iter().enumerate() {
        let dsl = axiom_cfg::ActionCfgParser::format_dsl(&act);
        let dry_run = ProposedAction::new(format!("demo-act-{}", idx + 1), "omoikane-agent", dsl)
            .validate_cfg(&audit)?
            .stage_for_business_check()
            .check_business(&store, &audit)?
            .dry_run(&wasm, erp.clone(), &audit)?;
        println!(
            "  -> Dry-run diff [{}]: before={} after={}",
            dry_run.diff.target_table, dry_run.diff.before, dry_run.diff.after
        );
        let approved =
            dry_run.approve_by_human(&authz, PrincipalKind::User, "tanaka", &audit)?;
        let committed = approved.commit_via_wasmtime(&wasm, erp.clone(), &audit)?;
        println!("  -> Wasmtime commit succeeded: {committed}");
    }

    // 6. Audit log verification
    println!("\n[6/7] Verifying SHA-256 hash-chained audit log...");
    let entries = audit.entries();
    AuditLogEntry::verify_chain(&entries)?;
    println!(
        "  -> {} audit entries verified (chain intact) at {}",
        entries.len(),
        audit_path.display()
    );

    println!("\n[7/7] Demo completed successfully.");
    Ok(())
}

fn run_eval_pcfg() -> Result<()> {
    println!("=== AxiomGraph PCFG Evaluation ===");
    let dataset: Vec<(Vec<&str>, Vec<&str>, OntologyAttr)> = vec![
        (vec!["部品番号"], vec!["PRT-101"], OntologyAttr::PartNumber),
        (vec!["品目cd"], vec!["PRT-102"], OntologyAttr::PartNumber),
        (vec!["p/n"], vec!["PRT-103"], OntologyAttr::PartNumber),
        (vec!["親品番"], vec!["ASM-100"], OntologyAttr::ParentPartNumber),
        (vec!["assy", "no."], vec!["ASM-200"], OntologyAttr::ParentPartNumber),
        (vec!["員数"], vec!["4"], OntologyAttr::Quantity),
        (vec!["qty"], vec!["12"], OntologyAttr::Quantity),
        (vec!["図番"], vec!["DWG-101"], OntologyAttr::DrawingId),
        (vec!["dwg", "no."], vec!["DWG-102"], OntologyAttr::DrawingId),
        (vec!["版数"], vec!["Rev.A"], OntologyAttr::Revision),
        (vec!["rev"], vec!["Rev.B"], OntologyAttr::Revision),
        (vec!["部品名称"], vec!["サーボモータ"], OntologyAttr::PartName),
        // Unfamiliar site-specific abbreviations that should initially be Unknown
        (vec!["社内型番x"], vec!["PRT-901"], OntologyAttr::PartNumber),
        (vec!["親ユニット記号"], vec!["ASM-901"], OntologyAttr::ParentPartNumber),
        (vec!["手配数x"], vec!["8"], OntologyAttr::Quantity),
        (vec!["図面コードx"], vec!["DWG-901"], OntologyAttr::DrawingId),
    ];

    let mut grammar = PcfgGrammar::default();
    let (acc1, f1_1, unk1) = evaluate_dataset(&grammar, &dataset);
    println!(
        "Before feedback -> Accuracy: {:.3}, Macro-F1: {:.3}, Unknown Rate: {:.3}",
        acc1, f1_1, unk1
    );

    // Apply human feedback for the unfamiliar columns
    for (hdr, vals, attr) in &dataset[12..] {
        grammar.apply_feedback(&FeedbackSample {
            header_tokens: hdr.iter().map(|s| s.to_string()).collect(),
            sample_values: vals.iter().map(|s| s.to_string()).collect(),
            chosen_attr: *attr,
        });
    }

    let (acc2, f1_2, unk2) = evaluate_dataset(&grammar, &dataset);
    println!(
        "After feedback  -> Accuracy: {:.3}, Macro-F1: {:.3}, Unknown Rate: {:.3}",
        acc2, f1_2, unk2
    );
    println!(
        "Improvement     -> Accuracy +{:.3}, Macro-F1 +{:.3}, Unknown Rate -{:.3}",
        acc2 - acc1,
        f1_2 - f1_1,
        unk1 - unk2
    );
    Ok(())
}

fn evaluate_dataset(
    grammar: &PcfgGrammar,
    dataset: &[(Vec<&str>, Vec<&str>, OntologyAttr)],
) -> (f64, f64, f64) {
    let mut correct = 0usize;
    let mut unknown = 0usize;
    let mut tp: HashMap<OntologyAttr, usize> = HashMap::new();
    let mut fp: HashMap<OntologyAttr, usize> = HashMap::new();
    let mut fn_cnt: HashMap<OntologyAttr, usize> = HashMap::new();

    for (idx, (hdr, vals, truth)) in dataset.iter().enumerate() {
        let h: Vec<String> = hdr.iter().map(|s| s.to_string()).collect();
        let v: Vec<String> = vals.iter().map(|s| s.to_string()).collect();
        match grammar.resolve_column(idx, &h.join(" "), &h, &v, 3) {
            MappingResolution::Resolved { attr, .. } => {
                if attr == *truth {
                    correct += 1;
                    *tp.entry(*truth).or_default() += 1;
                } else {
                    *fp.entry(attr).or_default() += 1;
                    *fn_cnt.entry(*truth).or_default() += 1;
                }
            }
            MappingResolution::Unknown { .. } => {
                unknown += 1;
                *fn_cnt.entry(*truth).or_default() += 1;
            }
        }
    }

    let total = dataset.len() as f64;
    let acc = correct as f64 / total;
    let unk_rate = unknown as f64 / total;

    let mut f1_sum = 0.0;
    let mut classes = 0usize;
    for attr in OntologyAttr::all() {
        let t = *tp.get(attr).unwrap_or(&0) as f64;
        let f_p = *fp.get(attr).unwrap_or(&0) as f64;
        let f_n = *fn_cnt.get(attr).unwrap_or(&0) as f64;
        if t + f_p + f_n > 0.0 {
            classes += 1;
            let p = if t + f_p > 0.0 { t / (t + f_p) } else { 0.0 };
            let r = if t + f_n > 0.0 { t / (t + f_n) } else { 0.0 };
            if p + r > 0.0 {
                f1_sum += 2.0 * p * r / (p + r);
            }
        }
    }
    let macro_f1 = if classes > 0 {
        f1_sum / classes as f64
    } else {
        0.0
    };
    (acc, macro_f1, unk_rate)
}

async fn run_bench(nodes: usize) -> Result<()> {
    println!("=== AxiomGraph Benchmark (nodes={nodes}) ===");
    let t_gen = Instant::now();
    eprintln!("[bench 1/4] Generating synthetic BOM/Drawing/Order dataset (O(N))...");
    let drawings_count = (nodes / 5).max(10);
    let orders_count = (nodes / 10).max(10);

    let drawings: Vec<Drawing> = (0..drawings_count)
        .map(|i| Drawing {
            drawing_id: format!("DWG-{i:06}"),
            title: format!("Drawing {i}"),
            latest_rev: "Rev.A".into(),
            status: "ACTIVE".into(),
        })
        .collect();

    let parts: Vec<Part> = (0..nodes)
        .map(|i| Part {
            part_number: format!("PRT-{i:06}"),
            name: format!("Part {i}"),
            drawing_id: format!("DWG-{:06}", i % drawings_count),
            drawing_rev: "Rev.A".into(),
            status: "ACTIVE".into(),
        })
        .collect();

    let orders: Vec<PurchaseOrder> = (0..orders_count)
        .map(|i| PurchaseOrder {
            order_id: format!("PO-{i:06}"),
            part_number: format!("PRT-{:06}", i % nodes),
            quantity: 10,
            target_rev: "Rev.A".into(),
            status: "OPEN".into(),
        })
        .collect();

    // ~5 edges per node (DAG hierarchy, O(N))
    let mut bom_edges = Vec::with_capacity(nodes * 5);
    for i in 0..nodes {
        for k in 1..=5 {
            let child = i + k;
            if child < nodes {
                bom_edges.push(BomEdge {
                    parent_part_number: format!("PRT-{i:06}"),
                    child_part_number: format!("PRT-{child:06}"),
                    quantity: k as i64,
                });
            }
        }
    }
    let edge_count = bom_edges.len();
    eprintln!(
        "[bench 1/4] Done in {:.2} ms ({nodes} parts, {drawings_count} drawings, {orders_count} orders, {edge_count} edges).",
        t_gen.elapsed().as_secs_f64() * 1000.0
    );

    eprintln!("[bench 2/4 & 3/4] Running DataFusion Arrow pipeline + LadybugDB COPY FROM bulk load...");
    let mut store = OntologyGraphStore::new(None)?;
    let t0 = Instant::now();
    store
        .ingest_records(parts, bom_edges, drawings, orders)
        .await?;
    let ingest_ms = t0.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[bench 2/4 & 3/4] Ingestion done in {ingest_ms:.2} ms.");

    eprintln!("[bench 4/4] Measuring 100 Cypher 3-hop BOM traversal queries...");
    let t_q = Instant::now();
    let mut latencies_ms = Vec::with_capacity(100);
    for i in 0..100 {
        let root = format!("PRT-{:06}", (i * 97) % nodes);
        let q0 = Instant::now();
        let _ = store.query_bom_descendants(&root)?;
        latencies_ms.push(q0.elapsed().as_secs_f64() * 1000.0);
    }
    eprintln!(
        "[bench 4/4] Queries done in {:.2} ms.",
        t_q.elapsed().as_secs_f64() * 1000.0
    );
    latencies_ms.sort_by(|a, b| a.total_cmp(b));
    let p50 = latencies_ms[50];
    let p95 = latencies_ms[95];
    let p99 = latencies_ms[99];

    let rss_kb = current_rss_kb().unwrap_or(0);
    println!("Nodes: {nodes}, BOM Edges: {edge_count}");
    println!("Ingestion time (DataFusion -> Arrow -> LadybugDB COPY FROM): {ingest_ms:.2} ms");
    println!("Cypher 3-hop BOM query latency (100 runs): p50={p50:.2} ms, p95={p95:.2} ms, p99={p99:.2} ms");
    println!("Process RSS memory: {:.2} MB", rss_kb as f64 / 1024.0);
    Ok(())
}

fn current_rss_kb() -> Option<u64> {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } == 0 {
        #[cfg(target_os = "macos")]
        {
            Some((usage.ru_maxrss as u64) / 1024)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(usage.ru_maxrss as u64)
        }
    } else {
        None
    }
}

async fn run_verify_policies() -> Result<()> {
    println!("=== Cedar Analysis (SymCC) Invariant Verification ===");
    let policies = workspace_root().join("policies");
    let authz = AxiomAuthorizer::from_files(
        &policies.join("axiom.cedarschema"),
        &policies.join("axiom.cedar"),
    )?;
    let report = authz.verify_invariants_with_symcc(None).await?;
    println!("cvc5 available: {} ({:?})", report.cvc5_available, report.cvc5_path);
    for chk in report.checks {
        println!("  [{}] {}: {}", chk.status, chk.name, chk.detail);
    }
    Ok(())
}
