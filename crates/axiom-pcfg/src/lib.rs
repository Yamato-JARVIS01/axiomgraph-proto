//! Probabilistic Context-Free Grammar (PCFG) with CYK parsing for autonomous
//! manufacturing schema resolution and human-feedback weight learning.

use axiom_core::OntologyAttr;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcfgError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("empty input")]
    EmptyInput,
}

/// A binary CNF production: `lhs -> rhs_left rhs_right` with log-probability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryRule {
    pub lhs: String,
    pub rhs_left: String,
    pub rhs_right: String,
    pub log_prob: f64,
}

/// A unary production: `lhs -> rhs` with log-probability (used for CNF closure).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnaryRule {
    pub lhs: String,
    pub rhs: String,
    pub log_prob: f64,
}

/// A lexical production: `lhs -> terminal` with log-probability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexicalRule {
    pub lhs: String,
    pub terminal: String,
    pub log_prob: f64,
}

/// Parse tree node produced by the CYK parser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParseNode {
    pub symbol: String,
    pub log_prob: f64,
    pub terminal: Option<String>,
    pub children: Vec<ParseNode>,
}

/// Candidate ontology mapping with normalized probability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MappingCandidate {
    pub attr: OntologyAttr,
    pub confidence: f64,
    pub log_prob: f64,
    pub parse_tree: ParseNode,
}

/// Result of resolving a single column. Never forces conversion below threshold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MappingResolution {
    Resolved {
        column_index: usize,
        raw_header: String,
        attr: OntologyAttr,
        confidence: f64,
        candidates: Vec<MappingCandidate>,
    },
    Unknown {
        column_index: usize,
        raw_header: String,
        reason: String,
        candidates: Vec<MappingCandidate>,
    },
}

/// Human feedback for self-improvement loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackSample {
    pub header_tokens: Vec<String>,
    pub sample_values: Vec<String>,
    pub chosen_attr: OntologyAttr,
}

/// Preprocessed table extracted from messy manufacturing CSV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreprocessedTable {
    pub headers: Vec<String>,
    pub header_token_lists: Vec<Vec<String>>,
    pub rows: Vec<Vec<String>>,
    pub dropped_rows: usize,
}

/// PCFG grammar + CYK parser with persistable weights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcfgGrammar {
    pub confidence_threshold: f64,
    pub margin_threshold: f64,
    pub binary_rules: Vec<BinaryRule>,
    pub unary_rules: Vec<UnaryRule>,
    pub lexical_rules: Vec<LexicalRule>,
}

impl Default for PcfgGrammar {
    fn default() -> Self {
        Self::new_manufacturing_default()
    }
}

impl PcfgGrammar {
    /// Construct the default manufacturing ontology PCFG.
    pub fn new_manufacturing_default() -> Self {
        let mut binary_rules = Vec::new();
        let mut unary_rules = Vec::new();
        let mut lexical_rules = Vec::new();

        // Root non-terminals S_<attr> combine HeaderPhrase + ValueFeature
        let attr_specs = [
            (OntologyAttr::PartNumber, "S_PartNumber", "HP_Part", "VF_Part"),
            (
                OntologyAttr::ParentPartNumber,
                "S_ParentPartNumber",
                "HP_Parent",
                "VF_Part",
            ),
            (OntologyAttr::PartName, "S_PartName", "HP_Name", "VF_Text"),
            (OntologyAttr::Quantity, "S_Quantity", "HP_Qty", "VF_Qty"),
            (OntologyAttr::DrawingId, "S_DrawingId", "HP_Dwg", "VF_Dwg"),
            (OntologyAttr::Revision, "S_Revision", "HP_Rev", "VF_Rev"),
            (OntologyAttr::Status, "S_Status", "HP_Status", "VF_Status"),
        ];

        for (_attr, root, hp, vf) in &attr_specs {
            // Primary combination: HeaderPhrase + ValueFeature
            binary_rules.push(BinaryRule {
                lhs: (*root).to_string(),
                rhs_left: (*hp).to_string(),
                rhs_right: (*vf).to_string(),
                log_prob: -0.15,
            });
            // Fallback combination: HeaderPhrase + generic ValueFeature
            binary_rules.push(BinaryRule {
                lhs: (*root).to_string(),
                rhs_left: (*hp).to_string(),
                rhs_right: "VF_Any".to_string(),
                log_prob: -1.40,
            });
            // Weak fallback: Unknown header + strong ValueFeature
            binary_rules.push(BinaryRule {
                lhs: (*root).to_string(),
                rhs_left: "HP_Unknown".to_string(),
                rhs_right: (*vf).to_string(),
                log_prob: -2.20,
            });
            // Multi-token header phrase composition: HP -> HP HP
            binary_rules.push(BinaryRule {
                lhs: (*hp).to_string(),
                rhs_left: (*hp).to_string(),
                rhs_right: (*hp).to_string(),
                log_prob: -0.35,
            });
            // Allow modifier/noise token to attach to a specific HP
            binary_rules.push(BinaryRule {
                lhs: (*hp).to_string(),
                rhs_left: (*hp).to_string(),
                rhs_right: "HP_Modifier".to_string(),
                log_prob: -0.45,
            });
            binary_rules.push(BinaryRule {
                lhs: (*hp).to_string(),
                rhs_left: "HP_Modifier".to_string(),
                rhs_right: (*hp).to_string(),
                log_prob: -0.45,
            });
            // Allow unknown/noisy token to attach to a specific HP with penalty
            binary_rules.push(BinaryRule {
                lhs: (*hp).to_string(),
                rhs_left: (*hp).to_string(),
                rhs_right: "HP_Unknown".to_string(),
                log_prob: -1.20,
            });
            binary_rules.push(BinaryRule {
                lhs: (*hp).to_string(),
                rhs_left: "HP_Unknown".to_string(),
                rhs_right: (*hp).to_string(),
                log_prob: -1.20,
            });
        }

        // Compound manufacturing phrases: "part name" -> HP_Name, "drawing no" -> HP_Dwg, etc.
        binary_rules.push(BinaryRule {
            lhs: "HP_Name".to_string(),
            rhs_left: "HP_Part".to_string(),
            rhs_right: "HP_Name".to_string(),
            log_prob: -0.25,
        });
        binary_rules.push(BinaryRule {
            lhs: "HP_Part".to_string(),
            rhs_left: "HP_Parent".to_string(),
            rhs_right: "HP_Part".to_string(),
            log_prob: -1.50,
        });

        // Allow unknown header phrases to compose
        binary_rules.push(BinaryRule {
            lhs: "HP_Unknown".to_string(),
            rhs_left: "HP_Unknown".to_string(),
            rhs_right: "HP_Unknown".to_string(),
            log_prob: -0.50,
        });
        binary_rules.push(BinaryRule {
            lhs: "HP_Modifier".to_string(),
            rhs_left: "HP_Modifier".to_string(),
            rhs_right: "HP_Modifier".to_string(),
            log_prob: -0.50,
        });

        // Unary rules from ValueFeature_* to VF_Any
        for vf in [
            "VF_Part",
            "VF_Qty",
            "VF_Dwg",
            "VF_Rev",
            "VF_Status",
            "VF_Text",
        ] {
            unary_rules.push(UnaryRule {
                lhs: "VF_Any".to_string(),
                rhs: vf.to_string(),
                log_prob: -0.80,
            });
        }
        // Part value can also serve as Text weakly
        unary_rules.push(UnaryRule {
            lhs: "VF_Text".to_string(),
            rhs: "VF_Part".to_string(),
            log_prob: -2.50,
        });

        // Lexical rules for Header tokens
        let header_lexicon: &[(&str, &[(&str, f64)])] = &[
            (
                "HP_Part",
                &[
                    ("部品番号", -0.15),
                    ("品目cd", -0.18),
                    ("品目コード", -0.18),
                    ("品番", -0.20),
                    ("p/n", -0.22),
                    ("pn", -0.35),
                    ("part_number", -0.10),
                    ("part", -0.85),
                    ("item", -0.90),
                    ("子品番", -0.20),
                    ("child", -0.70),
                ],
            ),
            (
                "HP_Parent",
                &[
                    ("親品番", -0.12),
                    ("上位品目", -0.15),
                    ("assy", -0.25),
                    ("親品目", -0.15),
                    ("parent_part_number", -0.10),
                    ("parent", -0.45),
                ],
            ),
            (
                "HP_Name",
                &[
                    ("部品名称", -0.12),
                    ("品名", -0.15),
                    ("名称", -0.25),
                    ("part_name", -0.10),
                    ("name", -0.55),
                    ("description", -0.40),
                    ("型式", -0.65),
                ],
            ),
            (
                "HP_Qty",
                &[
                    ("員数", -0.12),
                    ("数量", -0.15),
                    ("使用数", -0.18),
                    ("qty", -0.15),
                    ("quantity", -0.10),
                    ("count", -0.50),
                ],
            ),
            (
                "HP_Dwg",
                &[
                    ("図番", -0.12),
                    ("図面番号", -0.12),
                    ("dwg", -0.20),
                    ("drawing_id", -0.10),
                    ("drawing", -0.35),
                ],
            ),
            (
                "HP_Rev",
                &[
                    ("版数", -0.12),
                    ("改訂", -0.18),
                    ("rev", -0.15),
                    ("revision", -0.10),
                    ("ver", -0.45),
                ],
            ),
            (
                "HP_Status",
                &[
                    ("ステータス", -0.15),
                    ("状態", -0.20),
                    ("備考", -0.55),
                    ("status", -0.12),
                    ("note", -0.75),
                ],
            ),
            (
                "HP_Modifier",
                &[
                    ("no", -0.30),
                    ("no.", -0.30),
                    ("number", -0.35),
                    ("id", -0.40),
                    ("cd", -0.40),
                    ("code", -0.40),
                    ("/", -0.30),
                ],
            ),
        ];

        for (lhs, entries) in header_lexicon {
            for (term, lp) in *entries {
                lexical_rules.push(LexicalRule {
                    lhs: (*lhs).to_string(),
                    terminal: (*term).to_string(),
                    log_prob: *lp,
                });
            }
        }

        // Lexical rules for value-pattern terminals
        let val_lexicon = [
            ("VF_Part", "__VAL_PART__", -0.10),
            ("VF_Dwg", "__VAL_DWG__", -0.10),
            ("VF_Rev", "__VAL_REV__", -0.10),
            ("VF_Qty", "__VAL_QTY__", -0.10),
            ("VF_Status", "__VAL_STATUS__", -0.10),
            ("VF_Text", "__VAL_TEXT__", -0.10),
            ("VF_Any", "__VAL_EMPTY__", -1.50),
        ];
        for (lhs, term, lp) in val_lexicon {
            lexical_rules.push(LexicalRule {
                lhs: lhs.to_string(),
                terminal: term.to_string(),
                log_prob: lp,
            });
        }

        Self {
            confidence_threshold: 0.75,
            margin_threshold: 0.15,
            binary_rules,
            unary_rules,
            lexical_rules,
        }
    }

    pub fn load_from_json(path: impl AsRef<Path>) -> Result<Self, PcfgError> {
        let content = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save_to_json(&self, path: impl AsRef<Path>) -> Result<(), PcfgError> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Resolve a column using CYK parsing over header tokens + value feature token.
    pub fn resolve_column(
        &self,
        column_index: usize,
        raw_header: &str,
        header_tokens: &[String],
        sample_values: &[String],
        top_k: usize,
    ) -> MappingResolution {
        let mut tokens: Vec<String> = header_tokens
            .iter()
            .map(|t| normalize_token(t))
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.is_empty() {
            tokens.push("__empty_header__".to_string());
        }
        let val_token = classify_sample_values(sample_values);
        tokens.push(val_token.to_string());

        let candidates = self.cyk_score_candidates(&tokens, top_k.max(2));

        if candidates.is_empty() {
            return MappingResolution::Unknown {
                column_index,
                raw_header: raw_header.to_string(),
                reason: "no valid PCFG parse tree found".to_string(),
                candidates,
            };
        }

        let top1 = &candidates[0];
        let margin = if candidates.len() >= 2 {
            top1.confidence - candidates[1].confidence
        } else {
            top1.confidence
        };

        if top1.confidence < self.confidence_threshold {
            return MappingResolution::Unknown {
                column_index,
                raw_header: raw_header.to_string(),
                reason: format!(
                    "confidence {:.3} < threshold {:.3}",
                    top1.confidence, self.confidence_threshold
                ),
                candidates,
            };
        }

        if margin < self.margin_threshold {
            return MappingResolution::Unknown {
                column_index,
                raw_header: raw_header.to_string(),
                reason: format!(
                    "ambiguous top-1/top-2 margin {:.3} < {:.3}",
                    margin, self.margin_threshold
                ),
                candidates,
            };
        }

        MappingResolution::Resolved {
            column_index,
            raw_header: raw_header.to_string(),
            attr: top1.attr,
            confidence: top1.confidence,
            candidates,
        }
    }

    /// Run CYK dynamic programming over `tokens` and return top-K normalized candidates.
    fn cyk_score_candidates(&self, tokens: &[String], top_k: usize) -> Vec<MappingCandidate> {
        let n = tokens.len();
        if n == 0 {
            return Vec::new();
        }

        // chart[len-1][start] -> map<symbol, ParseNode>
        let mut chart: Vec<Vec<HashMap<String, ParseNode>>> = vec![vec![HashMap::new(); n]; n];

        // 1. Base case: lexical rules for span length 1
        for (i, tok) in tokens.iter().enumerate() {
            let mut matched_any = false;
            for rule in &self.lexical_rules {
                if rule.terminal == *tok {
                    matched_any = true;
                    Self::insert_best(
                        &mut chart[0][i],
                        ParseNode {
                            symbol: rule.lhs.clone(),
                            log_prob: rule.log_prob,
                            terminal: Some(tok.clone()),
                            children: Vec::new(),
                        },
                    );
                }
            }
            if !matched_any && !tok.starts_with("__VAL_") {
                Self::insert_best(
                    &mut chart[0][i],
                    ParseNode {
                        symbol: "HP_Unknown".to_string(),
                        log_prob: -3.50,
                        terminal: Some(tok.clone()),
                        children: Vec::new(),
                    },
                );
            }
            self.apply_unary_closure(&mut chart[0][i]);
        }

        // 2. CYK inductive step: span length 2..=n
        for span in 2..=n {
            for start in 0..=(n - span) {
                for split in 1..span {
                    let left_cell = &chart[split - 1][start];
                    let right_cell = &chart[span - split - 1][start + split];
                    if left_cell.is_empty() || right_cell.is_empty() {
                        continue;
                    }
                    let mut updates = Vec::new();
                    for rule in &self.binary_rules {
                        if let (Some(left_node), Some(right_node)) = (
                            left_cell.get(&rule.rhs_left),
                            right_cell.get(&rule.rhs_right),
                        ) {
                            let lp = rule.log_prob + left_node.log_prob + right_node.log_prob;
                            updates.push(ParseNode {
                                symbol: rule.lhs.clone(),
                                log_prob: lp,
                                terminal: None,
                                children: vec![left_node.clone(), right_node.clone()],
                            });
                        }
                    }
                    for node in updates {
                        Self::insert_best(&mut chart[span - 1][start], node);
                    }
                }
                self.apply_unary_closure(&mut chart[span - 1][start]);
            }
        }

        let top_cell = &chart[n - 1][0];
        let root_to_attr = [
            ("S_PartNumber", OntologyAttr::PartNumber),
            ("S_ParentPartNumber", OntologyAttr::ParentPartNumber),
            ("S_PartName", OntologyAttr::PartName),
            ("S_Quantity", OntologyAttr::Quantity),
            ("S_DrawingId", OntologyAttr::DrawingId),
            ("S_Revision", OntologyAttr::Revision),
            ("S_Status", OntologyAttr::Status),
        ];

        let mut raw_hits: Vec<(OntologyAttr, ParseNode)> = Vec::new();
        for (sym, attr) in root_to_attr {
            if let Some(node) = top_cell.get(sym) {
                raw_hits.push((attr, node.clone()));
            }
        }

        if raw_hits.is_empty() {
            return Vec::new();
        }

        // Softmax normalization over log-probabilities
        let max_lp = raw_hits
            .iter()
            .map(|(_, n)| n.log_prob)
            .fold(f64::NEG_INFINITY, f64::max);
        let sum_exp: f64 = raw_hits
            .iter()
            .map(|(_, n)| (n.log_prob - max_lp).exp())
            .sum();

        let mut candidates: Vec<MappingCandidate> = raw_hits
            .into_iter()
            .map(|(attr, node)| {
                let conf = (node.log_prob - max_lp).exp() / sum_exp;
                MappingCandidate {
                    attr,
                    confidence: conf,
                    log_prob: node.log_prob,
                    parse_tree: node,
                }
            })
            .collect();

        candidates.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
        candidates.truncate(top_k);
        candidates
    }

    fn apply_unary_closure(&self, cell: &mut HashMap<String, ParseNode>) {
        let mut changed = true;
        while changed {
            changed = false;
            let mut updates = Vec::new();
            for rule in &self.unary_rules {
                if let Some(child) = cell.get(&rule.rhs) {
                    let lp = rule.log_prob + child.log_prob;
                    let should_update = cell
                        .get(&rule.lhs)
                        .map(|existing| lp > existing.log_prob)
                        .unwrap_or(true);
                    if should_update {
                        updates.push(ParseNode {
                            symbol: rule.lhs.clone(),
                            log_prob: lp,
                            terminal: None,
                            children: vec![child.clone()],
                        });
                    }
                }
            }
            for node in updates {
                if Self::insert_best(cell, node) {
                    changed = true;
                }
            }
        }
    }

    fn insert_best(cell: &mut HashMap<String, ParseNode>, node: ParseNode) -> bool {
        match cell.get(&node.symbol) {
            Some(existing) if existing.log_prob >= node.log_prob => false,
            _ => {
                cell.insert(node.symbol.clone(), node);
                true
            }
        }
    }

    /// Update PCFG lexical weights from human correction feedback (self-improvement loop).
    pub fn apply_feedback(&mut self, feedback: &FeedbackSample) {
        let target_hp = attr_to_hp(feedback.chosen_attr);
        let tokens: Vec<String> = feedback
            .header_tokens
            .iter()
            .map(|t| normalize_token(t))
            .filter(|t| !t.is_empty())
            .collect();

        for tok in tokens {
            // Penalize competing lexical rules for this exact token
            for rule in &mut self.lexical_rules {
                if rule.terminal == tok && rule.lhs != target_hp {
                    rule.log_prob = (rule.log_prob - 1.50).max(-8.0);
                }
            }
            // Boost or insert target lexical rule
            if let Some(existing) = self
                .lexical_rules
                .iter_mut()
                .find(|r| r.terminal == tok && r.lhs == target_hp)
            {
                existing.log_prob = (existing.log_prob + 1.25).min(-0.05);
            } else {
                self.lexical_rules.push(LexicalRule {
                    lhs: target_hp.to_string(),
                    terminal: tok,
                    log_prob: -0.15,
                });
            }
        }

        // Also reinforce binary rule for (target_hp, val_feature) if present
        let val_tok = classify_sample_values(&feedback.sample_values);
        let val_nt = match val_tok {
            "__VAL_PART__" => "VF_Part",
            "__VAL_DWG__" => "VF_Dwg",
            "__VAL_REV__" => "VF_Rev",
            "__VAL_QTY__" => "VF_Qty",
            "__VAL_STATUS__" => "VF_Status",
            _ => "VF_Text",
        };
        let root_sym = attr_to_root(feedback.chosen_attr);
        if let Some(rule) = self
            .binary_rules
            .iter_mut()
            .find(|r| r.lhs == root_sym && r.rhs_left == target_hp && r.rhs_right == val_nt)
        {
            rule.log_prob = (rule.log_prob + 0.25).min(-0.02);
        } else {
            self.binary_rules.push(BinaryRule {
                lhs: root_sym.to_string(),
                rhs_left: target_hp.to_string(),
                rhs_right: val_nt.to_string(),
                log_prob: -0.25,
            });
        }
    }
}

fn attr_to_hp(attr: OntologyAttr) -> &'static str {
    match attr {
        OntologyAttr::PartNumber => "HP_Part",
        OntologyAttr::ParentPartNumber => "HP_Parent",
        OntologyAttr::PartName => "HP_Name",
        OntologyAttr::Quantity => "HP_Qty",
        OntologyAttr::DrawingId => "HP_Dwg",
        OntologyAttr::Revision => "HP_Rev",
        OntologyAttr::Status => "HP_Status",
    }
}

fn attr_to_root(attr: OntologyAttr) -> &'static str {
    match attr {
        OntologyAttr::PartNumber => "S_PartNumber",
        OntologyAttr::ParentPartNumber => "S_ParentPartNumber",
        OntologyAttr::PartName => "S_PartName",
        OntologyAttr::Quantity => "S_Quantity",
        OntologyAttr::DrawingId => "S_DrawingId",
        OntologyAttr::Revision => "S_Revision",
        OntologyAttr::Status => "S_Status",
    }
}

fn normalize_token(tok: &str) -> String {
    tok.trim().to_lowercase()
}

/// Tokenize a raw header string (including multi-line / space / punctuation separated).
pub fn tokenize_header(header: &str) -> Vec<String> {
    header
        .split(|c: char| c.is_whitespace() || matches!(c, '|' | ',' | ':' | '(' | ')'))
        .map(normalize_token)
        .filter(|t| !t.is_empty())
        .collect()
}

/// Classify sample cell values into a canonical value-feature terminal.
pub fn classify_sample_values(values: &[String]) -> &'static str {
    let non_empty: Vec<&str> = values
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if non_empty.is_empty() {
        return "__VAL_EMPTY__";
    }

    let re_dwg = Regex::new(r"(?i)^DWG[-_][A-Z0-9-]+$").unwrap();
    let re_part = Regex::new(r"(?i)^(PRT|ASM|CMP|MAT)[-_][A-Z0-9-]+$").unwrap();
    let re_rev = Regex::new(r"(?i)^(Rev\.?[A-Z0-9]+|R[0-9]+|[A-Z])$").unwrap();
    let re_qty = Regex::new(r"^[0-9]+(\.[0-9]+)?$").unwrap();
    let re_status = Regex::new(r"(?i)^(ACTIVE|OBSOLETE|DRAFT|OPEN|CLOSED)$").unwrap();

    let n = non_empty.len() as f64;
    let dwg_ratio = non_empty.iter().filter(|v| re_dwg.is_match(v)).count() as f64 / n;
    let part_ratio = non_empty.iter().filter(|v| re_part.is_match(v)).count() as f64 / n;
    let rev_ratio = non_empty.iter().filter(|v| re_rev.is_match(v)).count() as f64 / n;
    let qty_ratio = non_empty.iter().filter(|v| re_qty.is_match(v)).count() as f64 / n;
    let status_ratio = non_empty.iter().filter(|v| re_status.is_match(v)).count() as f64 / n;

    if dwg_ratio >= 0.5 {
        "__VAL_DWG__"
    } else if part_ratio >= 0.5 {
        "__VAL_PART__"
    } else if rev_ratio >= 0.5 {
        "__VAL_REV__"
    } else if qty_ratio >= 0.5 {
        "__VAL_QTY__"
    } else if status_ratio >= 0.5 {
        "__VAL_STATUS__"
    } else {
        "__VAL_TEXT__"
    }
}

/// Preprocess messy manufacturing CSV:
/// - Drops title/stamp/empty rows
/// - Flattens 2-row headers (e.g. Japanese + English sub-headers)
/// - Drops merged-cell blank data rows
pub fn preprocess_messy_csv(csv_text: &str) -> Result<PreprocessedTable, PcfgError> {
    let mut parsed_rows: Vec<Vec<String>> = csv_text
        .lines()
        .map(parse_csv_line)
        .filter(|r| !r.is_empty())
        .collect();

    if parsed_rows.is_empty() {
        return Err(PcfgError::EmptyInput);
    }

    let mut dropped_rows = 0usize;

    // Drop leading banner/stamp/blank rows (fewer than 2 non-empty cells)
    while let Some(first) = parsed_rows.first() {
        let non_empty = first.iter().filter(|c| !c.trim().is_empty()).count();
        if non_empty < 2 {
            parsed_rows.remove(0);
            dropped_rows += 1;
        } else {
            break;
        }
    }

    if parsed_rows.is_empty() {
        return Err(PcfgError::EmptyInput);
    }

    let header_row_1 = parsed_rows.remove(0);
    let col_count = header_row_1.len();

    // Detect if the next row is a secondary header row (no numeric/part-code data)
    let mut headers = header_row_1.clone();
    if let Some(second) = parsed_rows.first() {
        if looks_like_secondary_header(second) {
            let header_row_2 = parsed_rows.remove(0);
            for (idx, cell) in header_row_2.into_iter().enumerate() {
                if idx < headers.len() && !cell.trim().is_empty() {
                    if headers[idx].trim().is_empty() {
                        headers[idx] = cell.trim().to_string();
                    } else {
                        headers[idx] = format!("{} | {}", headers[idx].trim(), cell.trim());
                    }
                }
            }
        }
    }

    // Filter out merged-cell blank data rows (where <= 2 non-empty cells or placeholder text)
    let mut clean_rows = Vec::new();
    for mut row in parsed_rows {
        row.resize(col_count, String::new());
        let non_empty = row
            .iter()
            .filter(|c| {
                let t = c.trim();
                !t.is_empty() && !t.contains("空白行")
            })
            .count();
        if non_empty <= 2 {
            dropped_rows += 1;
            continue;
        }
        clean_rows.push(row);
    }

    let header_token_lists = headers.iter().map(|h| tokenize_header(h)).collect();

    Ok(PreprocessedTable {
        headers,
        header_token_lists,
        rows: clean_rows,
        dropped_rows,
    })
}

fn looks_like_secondary_header(row: &[String]) -> bool {
    let re_data_code = Regex::new(r"(?i)^(PRT|ASM|DWG|PO)[-_][A-Z0-9-]+$").unwrap();
    let has_data_code = row.iter().any(|c| re_data_code.is_match(c.trim()));
    let has_pure_number = row.iter().any(|c| c.trim().parse::<f64>().is_ok());
    !has_data_code && !has_pure_number
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocess_messy_csv_flattens_headers_and_drops_blanks() {
        let csv = include_str!("../../../fixtures/bom_sample_messy.csv");
        let table = preprocess_messy_csv(csv).expect("should preprocess messy csv");
        assert_eq!(table.headers.len(), 7);
        assert!(table.headers[0].contains("親品番") && table.headers[0].contains("Assy No."));
        assert!(table.headers[1].contains("品目CD") && table.headers[1].contains("P/N"));
        assert!(table.dropped_rows >= 4, "should drop title, stamp, empty, and merged-blank rows");
        assert_eq!(table.rows.len(), 8);
    }

    #[test]
    fn test_cyk_resolves_standard_manufacturing_aliases() {
        let csv = include_str!("../../../fixtures/bom_sample_messy.csv");
        let table = preprocess_messy_csv(csv).unwrap();
        let grammar = PcfgGrammar::default();

        let expected = [
            OntologyAttr::ParentPartNumber,
            OntologyAttr::PartNumber,
            OntologyAttr::PartName,
            OntologyAttr::Quantity,
            OntologyAttr::DrawingId,
            OntologyAttr::Revision,
            OntologyAttr::Status,
        ];

        for (idx, exp) in expected.iter().enumerate() {
            let vals: Vec<String> = table.rows.iter().map(|r| r[idx].clone()).collect();
            let res = grammar.resolve_column(idx, &table.headers[idx], &table.header_token_lists[idx], &vals, 3);
            match res {
                MappingResolution::Resolved { attr, confidence, .. } => {
                    assert_eq!(attr, *exp, "col {} ({}) mismatch", idx, table.headers[idx]);
                    assert!(confidence >= 0.75);
                }
                MappingResolution::Unknown { reason, .. } => {
                    panic!("col {} ({}) unexpectedly Unknown: {}", idx, table.headers[idx], reason);
                }
            }
        }
    }

    #[test]
    fn test_unknown_column_is_preserved_and_feedback_improves_score() {
        let mut grammar = PcfgGrammar::default();
        let header_tokens = vec!["x_vendor_ref".to_string()];
        let sample_values = vec!["PRT-5001".to_string(), "PRT-5002".to_string()];

        // Before feedback: unfamiliar header should stay Unknown (confidence < 0.75 or ambiguous)
        let before = grammar.resolve_column(0, "X_Vendor_Ref", &header_tokens, &sample_values, 3);
        let before_conf = match &before {
            MappingResolution::Unknown { candidates, .. } => {
                candidates.first().map(|c| c.confidence).unwrap_or(0.0)
            }
            MappingResolution::Resolved { .. } => {
                panic!("expected Unknown before feedback for unfamiliar column");
            }
        };

        // Apply human feedback + persist to JSON + reload
        let tmp = std::env::temp_dir().join("axiom_pcfg_feedback_test.json");
        grammar.apply_feedback(&FeedbackSample {
            header_tokens: header_tokens.clone(),
            sample_values: sample_values.clone(),
            chosen_attr: OntologyAttr::PartNumber,
        });
        grammar.save_to_json(&tmp).unwrap();
        let reloaded = PcfgGrammar::load_from_json(&tmp).unwrap();
        let _ = std::fs::remove_file(&tmp);

        let after = reloaded.resolve_column(0, "X_Vendor_Ref", &header_tokens, &sample_values, 3);
        match after {
            MappingResolution::Resolved { attr, confidence, .. } => {
                assert_eq!(attr, OntologyAttr::PartNumber);
                assert!(
                    confidence > before_conf && confidence >= 0.75,
                    "confidence should improve: before={:.3}, after={:.3}",
                    before_conf,
                    confidence
                );
            }
            MappingResolution::Unknown { reason, .. } => {
                panic!("expected Resolved after feedback, got Unknown: {}", reason);
            }
        }
    }
}
