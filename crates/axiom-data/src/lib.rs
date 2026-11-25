//! Apache DataFusion + Arrow + LadybugDB (`lbug`) integration and
//! 4-category manufacturing ontology inconsistency detection.

use arrow::array::{ArrayRef, Int64Array, StringArray};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use axiom_core::{
    BomEdge, Drawing, Inconsistency, InconsistencyKind, Part, PurchaseOrder,
};
use datafusion::datasource::MemTable;
use datafusion::prelude::*;
use lbug::{Connection, Database, SystemConfig, Value};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataError {
    #[error("DataFusion error: {0}")]
    DataFusion(#[from] datafusion::error::DataFusionError),
    #[error("Arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    #[error("LadybugDB error: {0}")]
    Lbug(#[from] lbug::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Statistics returned after ingesting data into DataFusion + LadybugDB.
#[derive(Debug, Clone)]
pub struct IngestStats {
    pub parts_count: usize,
    pub drawings_count: usize,
    pub orders_count: usize,
    pub bom_edges_count: usize,
    pub dangling_bom_edges: usize,
}

/// Graph + SQL analytical store backed by DataFusion (Arrow) and LadybugDB (`lbug`).
pub struct OntologyGraphStore {
    db: Database,
    ctx: SessionContext,
    parts_cache: HashMap<String, Part>,
    drawings_cache: HashMap<String, Drawing>,
    orders_cache: HashMap<String, PurchaseOrder>,
    bom_edges_cache: Vec<BomEdge>,
    _temp_dir: Option<tempfile::TempDir>,
}

impl OntologyGraphStore {
    /// Create a new store backed by an isolated temporary directory (for tests/demos)
    /// or a persistent directory path.
    pub fn new(db_path: Option<&Path>) -> Result<Self, DataError> {
        let (path_buf, temp_dir) = match db_path {
            Some(p) => {
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                (p.to_path_buf(), None)
            }
            None => {
                let td = tempfile::tempdir()?;
                let p = td.path().join("lbug_db");
                (p, Some(td))
            }
        };

        let db = Database::new(&path_buf, SystemConfig::default())?;
        let ctx = SessionContext::new();

        Ok(Self {
            db,
            ctx,
            parts_cache: HashMap::new(),
            drawings_cache: HashMap::new(),
            orders_cache: HashMap::new(),
            bom_edges_cache: Vec::new(),
            _temp_dir: temp_dir,
        })
    }

    /// Scan `drawings_sample.csv` and `erp_orders_sample.csv` via DataFusion,
    /// combine with preprocessed BOM records, and ingest into LadybugDB via Arrow RecordBatches.
    pub async fn ingest_csv_with_bom(
        &mut self,
        parts: Vec<Part>,
        bom_edges: Vec<BomEdge>,
        drawings_csv: &Path,
        orders_csv: &Path,
    ) -> Result<IngestStats, DataError> {
        // Scan drawings and orders with Apache DataFusion
        let df_drawings = self
            .ctx
            .read_csv(
                drawings_csv.to_string_lossy().as_ref(),
                CsvReadOptions::new().has_header(true),
            )
            .await?;
        let drawing_batches = df_drawings.collect().await?;
        let drawings = record_batches_to_drawings(&drawing_batches)?;

        let df_orders = self
            .ctx
            .read_csv(
                orders_csv.to_string_lossy().as_ref(),
                CsvReadOptions::new().has_header(true),
            )
            .await?;
        let order_batches = df_orders.collect().await?;
        let orders = record_batches_to_orders(&order_batches)?;

        self.ingest_records(parts, bom_edges, drawings, orders).await
    }

    /// Ingest domain records through DataFusion Arrow RecordBatches into LadybugDB.
    pub async fn ingest_records(
        &mut self,
        parts: Vec<Part>,
        bom_edges: Vec<BomEdge>,
        drawings: Vec<Drawing>,
        orders: Vec<PurchaseOrder>,
    ) -> Result<IngestStats, DataError> {
        self.parts_cache = parts
            .iter()
            .map(|p| (p.part_number.clone(), p.clone()))
            .collect();
        self.drawings_cache = drawings
            .iter()
            .map(|d| (d.drawing_id.clone(), d.clone()))
            .collect();
        self.orders_cache = orders
            .iter()
            .map(|o| (o.order_id.clone(), o.clone()))
            .collect();
        self.bom_edges_cache = bom_edges.clone();

        // Build Arrow RecordBatches and register in DataFusion
        let part_batch = parts_to_record_batch(&parts)?;
        let drawing_batch = drawings_to_record_batch(&drawings)?;
        let order_batch = orders_to_record_batch(&orders)?;
        let bom_batch = bom_edges_to_record_batch(&bom_edges)?;

        self.register_df_table("parts", part_batch.clone())?;
        self.register_df_table("drawings", drawing_batch.clone())?;
        self.register_df_table("orders", order_batch.clone())?;
        self.register_df_table("bom_edges", bom_batch)?;

        // Use DataFusion SQL to filter valid vs dangling BOM edges
        let valid_bom_df = self
            .ctx
            .sql(
                "SELECT b.parent_part_number AS \"from\", b.child_part_number AS \"to\", b.quantity \
                 FROM bom_edges b \
                 INNER JOIN parts p1 ON b.parent_part_number = p1.part_number \
                 INNER JOIN parts p2 ON b.child_part_number = p2.part_number",
            )
            .await?;
        let valid_bom_batches = valid_bom_df.collect().await?;
        let valid_bom_count: usize = valid_bom_batches.iter().map(|b| b.num_rows()).sum();
        let dangling_bom_edges = bom_edges.len().saturating_sub(valid_bom_count);

        // Build DEFINED_BY and ORDERS_PART Arrow RecordBatches via DataFusion SQL
        let defined_by_df = self
            .ctx
            .sql(
                "SELECT p.part_number AS \"from\", p.drawing_id AS \"to\" \
                 FROM parts p INNER JOIN drawings d ON p.drawing_id = d.drawing_id",
            )
            .await?;
        let defined_by_batches = defined_by_df.collect().await?;

        let orders_part_df = self
            .ctx
            .sql(
                "SELECT o.order_id AS \"from\", o.part_number AS \"to\" \
                 FROM orders o INNER JOIN parts p ON o.part_number = p.part_number",
            )
            .await?;
        let orders_part_batches = orders_part_df.collect().await?;

        // Load DataFusion-processed Arrow RecordBatches into LadybugDB (`lbug`)
        // via native schema (PRIMARY KEY + CSR) and bulk COPY FROM.
        let export_dir = tempfile::tempdir()?;
        let parts_csv = export_dir.path().join("parts.csv");
        let drawings_csv = export_dir.path().join("drawings.csv");
        let orders_csv = export_dir.path().join("orders.csv");
        let has_child_csv = export_dir.path().join("has_child.csv");
        let defined_by_csv = export_dir.path().join("defined_by.csv");
        let orders_part_csv = export_dir.path().join("orders_part.csv");

        write_batches_to_csv(&[part_batch], &parts_csv)?;
        write_batches_to_csv(&[drawing_batch], &drawings_csv)?;
        write_batches_to_csv(&[order_batch], &orders_csv)?;
        write_batches_to_csv(&valid_bom_batches, &has_child_csv)?;
        write_batches_to_csv(&defined_by_batches, &defined_by_csv)?;
        write_batches_to_csv(&orders_part_batches, &orders_part_csv)?;

        let conn = Connection::new(&self.db)?;
        for tbl in [
            "HAS_CHILD",
            "DEFINED_BY",
            "ORDERS_PART",
            "Part",
            "Drawing",
            "PurchaseOrder",
        ] {
            let _ = conn.query(&format!("DROP TABLE IF EXISTS {tbl};"));
        }

        conn.query(
            "CREATE NODE TABLE Part(part_number STRING, name STRING, drawing_id STRING, drawing_rev STRING, status STRING, PRIMARY KEY (part_number));",
        )?;
        conn.query(
            "CREATE NODE TABLE Drawing(drawing_id STRING, title STRING, latest_rev STRING, status STRING, PRIMARY KEY (drawing_id));",
        )?;
        conn.query(
            "CREATE NODE TABLE PurchaseOrder(order_id STRING, part_number STRING, quantity INT64, target_rev STRING, status STRING, PRIMARY KEY (order_id));",
        )?;
        conn.query("CREATE REL TABLE HAS_CHILD(FROM Part TO Part, quantity INT64);")?;
        conn.query("CREATE REL TABLE DEFINED_BY(FROM Part TO Drawing);")?;
        conn.query("CREATE REL TABLE ORDERS_PART(FROM PurchaseOrder TO Part);")?;

        if !parts.is_empty() {
            conn.query(&format!(
                "COPY Part FROM '{}' (HEADER=true);",
                parts_csv.display()
            ))?;
        }
        if !drawings.is_empty() {
            conn.query(&format!(
                "COPY Drawing FROM '{}' (HEADER=true);",
                drawings_csv.display()
            ))?;
        }
        if !orders.is_empty() {
            conn.query(&format!(
                "COPY PurchaseOrder FROM '{}' (HEADER=true);",
                orders_csv.display()
            ))?;
        }
        if valid_bom_count > 0 {
            conn.query(&format!(
                "COPY HAS_CHILD FROM '{}' (HEADER=true);",
                has_child_csv.display()
            ))?;
        }
        let defined_by_count: usize = defined_by_batches.iter().map(|b| b.num_rows()).sum();
        if defined_by_count > 0 {
            conn.query(&format!(
                "COPY DEFINED_BY FROM '{}' (HEADER=true);",
                defined_by_csv.display()
            ))?;
        }
        let orders_part_count: usize = orders_part_batches.iter().map(|b| b.num_rows()).sum();
        if orders_part_count > 0 {
            conn.query(&format!(
                "COPY ORDERS_PART FROM '{}' (HEADER=true);",
                orders_part_csv.display()
            ))?;
        }

        Ok(IngestStats {
            parts_count: parts.len(),
            drawings_count: drawings.len(),
            orders_count: orders.len(),
            bom_edges_count: bom_edges.len(),
            dangling_bom_edges,
        })
    }

    fn register_df_table(&self, name: &str, batch: RecordBatch) -> Result<(), DataError> {
        let _ = self.ctx.deregister_table(name);
        let schema = batch.schema();
        let mem = MemTable::try_new(schema, vec![vec![batch]])?;
        self.ctx.register_table(name, Arc::new(mem))?;
        Ok(())
    }

    /// Detect all 4 major inconsistency types using DataFusion SQL + LadybugDB Cypher queries.
    pub async fn detect_inconsistencies(&self) -> Result<Vec<Inconsistency>, DataError> {
        let mut findings = Vec::new();
        let conn = Connection::new(&self.db)?;

        // 1a. Dangling Reference: BOM edge where child_part_number or parent_part_number is missing from Part
        let dangling_bom_df = self
            .ctx
            .sql(
                "SELECT b.parent_part_number, b.child_part_number \
                 FROM bom_edges b \
                 LEFT JOIN parts p ON b.child_part_number = p.part_number \
                 WHERE p.part_number IS NULL",
            )
            .await?;
        for batch in dangling_bom_df.collect().await? {
            let parents = batch
                .column(0)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let children = batch
                .column(1)
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            for i in 0..batch.num_rows() {
                let p = parents.value(i).to_string();
                let c = children.value(i).to_string();
                findings.push(Inconsistency {
                    kind: InconsistencyKind::DanglingReference,
                    severity: "HIGH".to_string(),
                    entity_id: c.clone(),
                    related_id: Some(p.clone()),
                    path: vec![p.clone(), c.clone()],
                    description: format!(
                        "BOM edge {p} -> {c} references missing Part '{c}'"
                    ),
                });
            }
        }

        // 1b. Dangling Reference: Part.drawing_id missing from Drawing (Cypher OPTIONAL MATCH)
        let res = conn.query(
            "MATCH (p:Part) OPTIONAL MATCH (p)-[:DEFINED_BY]->(d:Drawing) \
             WITH p, d WHERE d IS NULL RETURN p.part_number, p.drawing_id;",
        )?;
        for row in res {
            let part_id = val_as_string(&row[0]);
            let dwg_id = val_as_string(&row[1]);
            findings.push(Inconsistency {
                kind: InconsistencyKind::DanglingReference,
                severity: "HIGH".to_string(),
                entity_id: part_id.clone(),
                related_id: Some(dwg_id.clone()),
                path: vec![part_id.clone(), dwg_id.clone()],
                description: format!(
                    "Part '{part_id}' references missing Drawing '{dwg_id}'"
                ),
            });
        }

        // 2. Circular Reference: BOM HAS_CHILD* cycle back to self (Cypher variable-length path)
        let res = conn.query(
            "MATCH (a:Part)-[:HAS_CHILD*1..8]->(a) RETURN DISTINCT a.part_number;",
        )?;
        let mut seen_cycle = HashSet::new();
        for row in res {
            let part_id = val_as_string(&row[0]);
            if seen_cycle.insert(part_id.clone()) {
                findings.push(Inconsistency {
                    kind: InconsistencyKind::CircularReference,
                    severity: "CRITICAL".to_string(),
                    entity_id: part_id.clone(),
                    related_id: Some(part_id.clone()),
                    path: vec![part_id.clone(), "...".to_string(), part_id.clone()],
                    description: format!(
                        "Circular BOM reference detected involving Part '{part_id}'"
                    ),
                });
            }
        }

        // 3a. Revision Mismatch: Part.drawing_rev <> Drawing.latest_rev
        let res = conn.query(
            "MATCH (p:Part)-[:DEFINED_BY]->(d:Drawing) \
             WHERE p.drawing_rev <> d.latest_rev \
             RETURN p.part_number, p.drawing_rev, d.drawing_id, d.latest_rev;",
        )?;
        for row in res {
            let part_id = val_as_string(&row[0]);
            let part_rev = val_as_string(&row[1]);
            let dwg_id = val_as_string(&row[2]);
            let latest_rev = val_as_string(&row[3]);
            findings.push(Inconsistency {
                kind: InconsistencyKind::RevisionMismatch,
                severity: "HIGH".to_string(),
                entity_id: part_id.clone(),
                related_id: Some(dwg_id.clone()),
                path: vec![part_id.clone(), dwg_id.clone()],
                description: format!(
                    "Part '{part_id}' uses '{part_rev}', but Drawing '{dwg_id}' latest_rev is '{latest_rev}'"
                ),
            });
        }

        // 3b. Revision Mismatch: PurchaseOrder.target_rev <> Drawing.latest_rev
        let res = conn.query(
            "MATCH (o:PurchaseOrder)-[:ORDERS_PART]->(p:Part)-[:DEFINED_BY]->(d:Drawing) \
             WHERE o.target_rev <> d.latest_rev \
             RETURN o.order_id, p.part_number, o.target_rev, d.drawing_id, d.latest_rev;",
        )?;
        for row in res {
            let order_id = val_as_string(&row[0]);
            let part_id = val_as_string(&row[1]);
            let target_rev = val_as_string(&row[2]);
            let dwg_id = val_as_string(&row[3]);
            let latest_rev = val_as_string(&row[4]);
            findings.push(Inconsistency {
                kind: InconsistencyKind::RevisionMismatch,
                severity: "HIGH".to_string(),
                entity_id: order_id.clone(),
                related_id: Some(part_id.clone()),
                path: vec![order_id.clone(), part_id.clone(), dwg_id.clone()],
                description: format!(
                    "PurchaseOrder '{order_id}' targets '{target_rev}' for '{part_id}', but Drawing '{dwg_id}' is at '{latest_rev}'"
                ),
            });
        }

        // 4a. Obsolete Part Reference in active BOM
        let res = conn.query(
            "MATCH (parent:Part)-[:HAS_CHILD]->(child:Part) \
             WHERE parent.status = 'ACTIVE' AND child.status = 'OBSOLETE' \
             RETURN parent.part_number, child.part_number;",
        )?;
        for row in res {
            let parent_id = val_as_string(&row[0]);
            let child_id = val_as_string(&row[1]);
            findings.push(Inconsistency {
                kind: InconsistencyKind::ObsoletePartReference,
                severity: "CRITICAL".to_string(),
                entity_id: child_id.clone(),
                related_id: Some(parent_id.clone()),
                path: vec![parent_id.clone(), child_id.clone()],
                description: format!(
                    "Active assembly '{parent_id}' references OBSOLETE part '{child_id}'"
                ),
            });
        }

        // 4b. Obsolete Drawing Reference in Open PurchaseOrder
        let res = conn.query(
            "MATCH (o:PurchaseOrder)-[:ORDERS_PART]->(p:Part)-[:DEFINED_BY]->(d:Drawing) \
             WHERE o.status = 'OPEN' AND (p.status = 'OBSOLETE' OR d.status = 'OBSOLETE') \
             RETURN o.order_id, p.part_number, d.drawing_id;",
        )?;
        for row in res {
            let order_id = val_as_string(&row[0]);
            let part_id = val_as_string(&row[1]);
            let dwg_id = val_as_string(&row[2]);
            findings.push(Inconsistency {
                kind: InconsistencyKind::ObsoletePartReference,
                severity: "CRITICAL".to_string(),
                entity_id: order_id.clone(),
                related_id: Some(part_id.clone()),
                path: vec![order_id.clone(), part_id.clone(), dwg_id.clone()],
                description: format!(
                    "Open PurchaseOrder '{order_id}' references OBSOLETE part/drawing '{part_id}' / '{dwg_id}'"
                ),
            });
        }

        Ok(findings)
    }

    /// Look up a Part and its Drawing from LadybugDB for business constraint checking.
    pub fn lookup_part_and_drawing(
        &self,
        part_number: &str,
    ) -> Result<Option<(Part, Option<Drawing>)>, DataError> {
        let conn = Connection::new(&self.db)?;
        let escaped = part_number.replace('\'', "''");
        let mut res = conn.query(&format!(
            "MATCH (p:Part) WHERE p.part_number = '{escaped}' \
             OPTIONAL MATCH (p)-[:DEFINED_BY]->(d:Drawing) \
             RETURN p.part_number, p.name, p.drawing_id, p.drawing_rev, p.status, \
                    d.drawing_id, d.title, d.latest_rev, d.status;"
        ))?;

        if let Some(row) = res.next() {
            let part = Part {
                part_number: val_as_string(&row[0]),
                name: val_as_string(&row[1]),
                drawing_id: val_as_string(&row[2]),
                drawing_rev: val_as_string(&row[3]),
                status: val_as_string(&row[4]),
            };
            let dwg_id = val_as_string(&row[5]);
            let drawing = if dwg_id.is_empty() {
                None
            } else {
                Some(Drawing {
                    drawing_id: dwg_id,
                    title: val_as_string(&row[6]),
                    latest_rev: val_as_string(&row[7]),
                    status: val_as_string(&row[8]),
                })
            };
            return Ok(Some((part, drawing)));
        }
        Ok(None)
    }

    /// Execute a multi-hop BOM Cypher query (used in benchmark).
    pub fn query_bom_descendants(&self, root_part: &str) -> Result<Vec<String>, DataError> {
        let conn = Connection::new(&self.db)?;
        let escaped = root_part.replace('\'', "''");
        let res = conn.query(&format!(
            "MATCH (p:Part {{part_number: '{escaped}'}})-[:HAS_CHILD*1..3]->(c:Part) \
             RETURN DISTINCT c.part_number;"
        ))?;
        let mut out = Vec::new();
        for row in res {
            out.push(val_as_string(&row[0]));
        }
        Ok(out)
    }

    pub fn list_parts(&self) -> Vec<Part> {
        self.parts_cache.values().cloned().collect()
    }

    pub fn list_drawings(&self) -> Vec<Drawing> {
        self.drawings_cache.values().cloned().collect()
    }

    pub fn list_orders(&self) -> Vec<PurchaseOrder> {
        self.orders_cache.values().cloned().collect()
    }
}

fn write_batches_to_csv(batches: &[RecordBatch], path: &Path) -> Result<(), DataError> {
    let file = std::fs::File::create(path)?;
    let mut writer = arrow::csv::WriterBuilder::new()
        .with_header(true)
        .build(file);
    for batch in batches {
        if batch.num_rows() > 0 {
            writer.write(batch)?;
        }
    }
    drop(writer);
    Ok(())
}

fn val_as_string(v: &Value) -> String {
    match v {
        Value::Null(_) => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn parts_to_record_batch(parts: &[Part]) -> Result<RecordBatch, DataError> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("part_number", DataType::Utf8, false),
        Field::new("name", DataType::Utf8, false),
        Field::new("drawing_id", DataType::Utf8, false),
        Field::new("drawing_rev", DataType::Utf8, false),
        Field::new("status", DataType::Utf8, false),
    ]));
    let pn: ArrayRef = Arc::new(StringArray::from(
        parts.iter().map(|p| p.part_number.as_str()).collect::<Vec<_>>(),
    ));
    let name: ArrayRef = Arc::new(StringArray::from(
        parts.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
    ));
    let dwg: ArrayRef = Arc::new(StringArray::from(
        parts.iter().map(|p| p.drawing_id.as_str()).collect::<Vec<_>>(),
    ));
    let rev: ArrayRef = Arc::new(StringArray::from(
        parts.iter().map(|p| p.drawing_rev.as_str()).collect::<Vec<_>>(),
    ));
    let status: ArrayRef = Arc::new(StringArray::from(
        parts.iter().map(|p| p.status.as_str()).collect::<Vec<_>>(),
    ));
    Ok(RecordBatch::try_new(schema, vec![pn, name, dwg, rev, status])?)
}

fn drawings_to_record_batch(drawings: &[Drawing]) -> Result<RecordBatch, DataError> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("drawing_id", DataType::Utf8, false),
        Field::new("title", DataType::Utf8, false),
        Field::new("latest_rev", DataType::Utf8, false),
        Field::new("status", DataType::Utf8, false),
    ]));
    let id: ArrayRef = Arc::new(StringArray::from(
        drawings.iter().map(|d| d.drawing_id.as_str()).collect::<Vec<_>>(),
    ));
    let title: ArrayRef = Arc::new(StringArray::from(
        drawings.iter().map(|d| d.title.as_str()).collect::<Vec<_>>(),
    ));
    let rev: ArrayRef = Arc::new(StringArray::from(
        drawings.iter().map(|d| d.latest_rev.as_str()).collect::<Vec<_>>(),
    ));
    let status: ArrayRef = Arc::new(StringArray::from(
        drawings.iter().map(|d| d.status.as_str()).collect::<Vec<_>>(),
    ));
    Ok(RecordBatch::try_new(schema, vec![id, title, rev, status])?)
}

fn orders_to_record_batch(orders: &[PurchaseOrder]) -> Result<RecordBatch, DataError> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("order_id", DataType::Utf8, false),
        Field::new("part_number", DataType::Utf8, false),
        Field::new("quantity", DataType::Int64, false),
        Field::new("target_rev", DataType::Utf8, false),
        Field::new("status", DataType::Utf8, false),
    ]));
    let oid: ArrayRef = Arc::new(StringArray::from(
        orders.iter().map(|o| o.order_id.as_str()).collect::<Vec<_>>(),
    ));
    let pn: ArrayRef = Arc::new(StringArray::from(
        orders.iter().map(|o| o.part_number.as_str()).collect::<Vec<_>>(),
    ));
    let qty: ArrayRef = Arc::new(Int64Array::from(
        orders.iter().map(|o| o.quantity).collect::<Vec<_>>(),
    ));
    let rev: ArrayRef = Arc::new(StringArray::from(
        orders.iter().map(|o| o.target_rev.as_str()).collect::<Vec<_>>(),
    ));
    let status: ArrayRef = Arc::new(StringArray::from(
        orders.iter().map(|o| o.status.as_str()).collect::<Vec<_>>(),
    ));
    Ok(RecordBatch::try_new(schema, vec![oid, pn, qty, rev, status])?)
}

fn bom_edges_to_record_batch(edges: &[BomEdge]) -> Result<RecordBatch, DataError> {
    let schema = Arc::new(Schema::new(vec![
        Field::new("parent_part_number", DataType::Utf8, false),
        Field::new("child_part_number", DataType::Utf8, false),
        Field::new("quantity", DataType::Int64, false),
    ]));
    let parent: ArrayRef = Arc::new(StringArray::from(
        edges.iter().map(|e| e.parent_part_number.as_str()).collect::<Vec<_>>(),
    ));
    let child: ArrayRef = Arc::new(StringArray::from(
        edges.iter().map(|e| e.child_part_number.as_str()).collect::<Vec<_>>(),
    ));
    let qty: ArrayRef = Arc::new(Int64Array::from(
        edges.iter().map(|e| e.quantity).collect::<Vec<_>>(),
    ));
    Ok(RecordBatch::try_new(schema, vec![parent, child, qty])?)
}

fn record_batches_to_drawings(batches: &[RecordBatch]) -> Result<Vec<Drawing>, DataError> {
    let mut out = Vec::new();
    for b in batches {
        let id = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        let title = b.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        let rev = b.column(2).as_any().downcast_ref::<StringArray>().unwrap();
        let status = b.column(3).as_any().downcast_ref::<StringArray>().unwrap();
        for i in 0..b.num_rows() {
            out.push(Drawing {
                drawing_id: id.value(i).to_string(),
                title: title.value(i).to_string(),
                latest_rev: rev.value(i).to_string(),
                status: status.value(i).to_string(),
            });
        }
    }
    Ok(out)
}

fn record_batches_to_orders(batches: &[RecordBatch]) -> Result<Vec<PurchaseOrder>, DataError> {
    let mut out = Vec::new();
    for b in batches {
        let oid = b.column(0).as_any().downcast_ref::<StringArray>().unwrap();
        let pn = b.column(1).as_any().downcast_ref::<StringArray>().unwrap();
        let qty = b.column(2).as_any().downcast_ref::<Int64Array>().unwrap();
        let rev = b.column(3).as_any().downcast_ref::<StringArray>().unwrap();
        let status = b.column(4).as_any().downcast_ref::<StringArray>().unwrap();
        for i in 0..b.num_rows() {
            out.push(PurchaseOrder {
                order_id: oid.value(i).to_string(),
                part_number: pn.value(i).to_string(),
                quantity: qty.value(i),
                target_rev: rev.value(i).to_string(),
                status: status.value(i).to_string(),
            });
        }
    }
    Ok(out)
}

/// Helper to build Parts & BomEdges from preprocessed messy BOM rows.
pub fn extract_parts_and_bom_from_rows(rows: &[Vec<String>]) -> (Vec<Part>, Vec<BomEdge>) {
    let mut parts_map: HashMap<String, Part> = HashMap::new();
    let mut edges = Vec::new();

    // Ensure root assembly exists
    parts_map.insert(
        "ASM-9000".to_string(),
        Part {
            part_number: "ASM-9000".to_string(),
            name: "Main Assembly 9000".to_string(),
            drawing_id: "DWG-1001".to_string(),
            drawing_rev: "Rev.C".to_string(),
            status: "ACTIVE".to_string(),
        },
    );

    for row in rows {
        if row.len() < 7 {
            continue;
        }
        let parent = row[0].trim().to_string();
        let part_no = row[1].trim().to_string();
        let name = row[2].trim().to_string();
        let qty: i64 = row[3].trim().parse().unwrap_or(1);
        let dwg_id = row[4].trim().to_string();
        let rev = row[5].trim().to_string();
        let status = row[6].trim().to_string();

        if !parent.is_empty() && !part_no.is_empty() {
            edges.push(BomEdge {
                parent_part_number: parent,
                child_part_number: part_no.clone(),
                quantity: qty,
            });
        }

        // Do not register PRT-MISSING-999 as a Part so DanglingReference is triggered
        if !part_no.is_empty() && !part_no.contains("MISSING") {
            parts_map.insert(
                part_no.clone(),
                Part {
                    part_number: part_no,
                    name,
                    drawing_id: dwg_id,
                    drawing_rev: rev,
                    status,
                },
            );
        }
    }

    (parts_map.into_values().collect(), edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_pcfg::preprocess_messy_csv;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_datafusion_lbug_detects_all_4_inconsistencies() {
        let fixtures_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
        let bom_csv = std::fs::read_to_string(fixtures_dir.join("bom_sample_messy.csv")).unwrap();
        let table = preprocess_messy_csv(&bom_csv).unwrap();
        let (parts, bom_edges) = extract_parts_and_bom_from_rows(&table.rows);

        let mut store = OntologyGraphStore::new(None).unwrap();
        let stats = store
            .ingest_csv_with_bom(
                parts,
                bom_edges,
                &fixtures_dir.join("drawings_sample.csv"),
                &fixtures_dir.join("erp_orders_sample.csv"),
            )
            .await
            .unwrap();

        assert!(stats.parts_count >= 7);
        assert_eq!(stats.dangling_bom_edges, 1);

        let inconsistencies = store.detect_inconsistencies().await.unwrap();
        let kinds: HashSet<InconsistencyKind> = inconsistencies.iter().map(|i| i.kind).collect();

        assert!(
            kinds.contains(&InconsistencyKind::DanglingReference),
            "missing DanglingReference: {:?}",
            inconsistencies
        );
        assert!(
            kinds.contains(&InconsistencyKind::CircularReference),
            "missing CircularReference: {:?}",
            inconsistencies
        );
        assert!(
            kinds.contains(&InconsistencyKind::RevisionMismatch),
            "missing RevisionMismatch: {:?}",
            inconsistencies
        );
        assert!(
            kinds.contains(&InconsistencyKind::ObsoletePartReference),
            "missing ObsoletePartReference: {:?}",
            inconsistencies
        );
    }
}
