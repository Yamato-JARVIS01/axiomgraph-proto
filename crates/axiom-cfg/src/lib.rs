//! Grammar-Constrained Decoding (CFG) parser & validator for TypedAction,
//! plus optional OpenAI-compatible local LLM client with deterministic fallback.

use axiom_core::TypedAction;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CfgError {
    #[error("CFG syntax error: {0}")]
    Syntax(String),
    #[error("forbidden or unknown action '{0}' rejected by CFG")]
    ForbiddenAction(String),
    #[error("missing required field '{0}' in CFG production")]
    MissingField(String),
    #[error("type mismatch for field '{field}': expected {expected}, got {got}")]
    TypeMismatch {
        field: String,
        expected: String,
        got: String,
    },
    #[error("unexpected extra field '{0}' rejected by strict CFG")]
    UnexpectedField(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Str(String),
    Int(i64),
    LBrace,
    RBrace,
    Colon,
    Comma,
}

#[derive(Debug, Clone)]
enum ArgVal {
    Str(String),
    Int(i64),
}

/// Formal Context-Free Grammar (CFG) validator for Write-back actions.
///
/// Grammar:
/// ```text
/// Action   := "CreatePurchaseOrderDraft" "{" PoArgs "}"
///           | "CreateBomRevisionRequest" "{" BomArgs "}"
/// PoArgs   := part_number, quantity, target_rev, reason, idempotency_key, expected_erp_version
/// BomArgs  := parent_part_number, child_part_number, new_rev, reason, idempotency_key, expected_erp_version
/// ```
pub struct ActionCfgParser;

impl ActionCfgParser {
    /// Parse a CFG-constrained DSL string (e.g. `CreatePurchaseOrderDraft { part_number: "PRT-1001", ... }`)
    /// or strict JSON object into `TypedAction`. Any unknown action, extra field, or type deviation
    /// is rejected at the CFG stage.
    pub fn parse(input: &str) -> Result<TypedAction, CfgError> {
        let trimmed = input.trim();
        if trimmed.starts_with('{') {
            return Self::parse_json_constrained(trimmed);
        }
        Self::parse_dsl(trimmed)
    }

    fn parse_json_constrained(json_str: &str) -> Result<TypedAction, CfgError> {
        let val: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| CfgError::Syntax(e.to_string()))?;
        let obj = val
            .as_object()
            .ok_or_else(|| CfgError::Syntax("expected JSON object".to_string()))?;
        let action_type = obj
            .get("action_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CfgError::MissingField("action_type".to_string()))?;

        let mut args = HashMap::new();
        for (k, v) in obj {
            if k == "action_type" {
                continue;
            }
            if let Some(s) = v.as_str() {
                args.insert(k.clone(), ArgVal::Str(s.to_string()));
            } else if let Some(n) = v.as_i64() {
                args.insert(k.clone(), ArgVal::Int(n));
            } else {
                return Err(CfgError::TypeMismatch {
                    field: k.clone(),
                    expected: "String or Int64".to_string(),
                    got: v.to_string(),
                });
            }
        }
        Self::build_action(action_type, args)
    }

    fn parse_dsl(input: &str) -> Result<TypedAction, CfgError> {
        let tokens = tokenize_dsl(input)?;
        let mut pos = 0;

        let action_name = match tokens.get(pos) {
            Some(Token::Ident(s)) => {
                pos += 1;
                s.clone()
            }
            _ => return Err(CfgError::Syntax("expected ActionName identifier".to_string())),
        };

        if !matches!(
            action_name.as_str(),
            "CreatePurchaseOrderDraft" | "CreateBomRevisionRequest"
        ) {
            return Err(CfgError::ForbiddenAction(action_name));
        }

        if tokens.get(pos) != Some(&Token::LBrace) {
            return Err(CfgError::Syntax("expected '{' after ActionName".to_string()));
        }
        pos += 1;

        let mut args = HashMap::new();
        while pos < tokens.len() && tokens[pos] != Token::RBrace {
            let key = match tokens.get(pos) {
                Some(Token::Ident(k)) => {
                    pos += 1;
                    k.clone()
                }
                _ => return Err(CfgError::Syntax("expected field name".to_string())),
            };
            if tokens.get(pos) != Some(&Token::Colon) {
                return Err(CfgError::Syntax(format!("expected ':' after field '{key}'")));
            }
            pos += 1;

            let val = match tokens.get(pos) {
                Some(Token::Str(s)) => {
                    pos += 1;
                    ArgVal::Str(s.clone())
                }
                Some(Token::Int(n)) => {
                    pos += 1;
                    ArgVal::Int(*n)
                }
                _ => {
                    return Err(CfgError::Syntax(format!(
                        "expected string or integer literal for '{key}'"
                    )))
                }
            };

            if args.insert(key.clone(), val).is_some() {
                return Err(CfgError::Syntax(format!("duplicate field '{key}'")));
            }

            if tokens.get(pos) == Some(&Token::Comma) {
                pos += 1;
            } else if tokens.get(pos) != Some(&Token::RBrace) {
                return Err(CfgError::Syntax("expected ',' or '}'".to_string()));
            }
        }

        if tokens.get(pos) != Some(&Token::RBrace) {
            return Err(CfgError::Syntax("expected closing '}'".to_string()));
        }
        pos += 1;
        if pos != tokens.len() {
            return Err(CfgError::Syntax("unexpected trailing tokens after '}'".to_string()));
        }

        Self::build_action(&action_name, args)
    }

    fn build_action(
        action_name: &str,
        mut args: HashMap<String, ArgVal>,
    ) -> Result<TypedAction, CfgError> {
        let take_str = |map: &mut HashMap<String, ArgVal>, k: &str| -> Result<String, CfgError> {
            match map.remove(k) {
                Some(ArgVal::Str(s)) => Ok(s),
                Some(ArgVal::Int(n)) => Err(CfgError::TypeMismatch {
                    field: k.to_string(),
                    expected: "String".to_string(),
                    got: n.to_string(),
                }),
                None => Err(CfgError::MissingField(k.to_string())),
            }
        };

        let take_int = |map: &mut HashMap<String, ArgVal>, k: &str| -> Result<i64, CfgError> {
            match map.remove(k) {
                Some(ArgVal::Int(n)) => Ok(n),
                Some(ArgVal::Str(s)) => Err(CfgError::TypeMismatch {
                    field: k.to_string(),
                    expected: "Int64".to_string(),
                    got: format!("\"{s}\""),
                }),
                None => Err(CfgError::MissingField(k.to_string())),
            }
        };

        let action = match action_name {
            "CreatePurchaseOrderDraft" => {
                let part_number = take_str(&mut args, "part_number")?;
                let quantity = take_int(&mut args, "quantity")?;
                let target_rev = take_str(&mut args, "target_rev")?;
                let reason = take_str(&mut args, "reason")?;
                let idempotency_key = take_str(&mut args, "idempotency_key")?;
                let expected_erp_version = take_int(&mut args, "expected_erp_version")?;
                TypedAction::CreatePurchaseOrderDraft {
                    part_number,
                    quantity,
                    target_rev,
                    reason,
                    idempotency_key,
                    expected_erp_version,
                }
            }
            "CreateBomRevisionRequest" => {
                let parent_part_number = take_str(&mut args, "parent_part_number")?;
                let child_part_number = take_str(&mut args, "child_part_number")?;
                let new_rev = take_str(&mut args, "new_rev")?;
                let reason = take_str(&mut args, "reason")?;
                let idempotency_key = take_str(&mut args, "idempotency_key")?;
                let expected_erp_version = take_int(&mut args, "expected_erp_version")?;
                TypedAction::CreateBomRevisionRequest {
                    parent_part_number,
                    child_part_number,
                    new_rev,
                    reason,
                    idempotency_key,
                    expected_erp_version,
                }
            }
            other => return Err(CfgError::ForbiddenAction(other.to_string())),
        };

        if let Some(extra) = args.keys().next() {
            return Err(CfgError::UnexpectedField(extra.clone()));
        }

        Ok(action)
    }

    /// Format a `TypedAction` back into canonical CFG DSL.
    pub fn format_dsl(action: &TypedAction) -> String {
        match action {
            TypedAction::CreatePurchaseOrderDraft {
                part_number,
                quantity,
                target_rev,
                reason,
                idempotency_key,
                expected_erp_version,
            } => format!(
                "CreatePurchaseOrderDraft {{ part_number: \"{part_number}\", quantity: {quantity}, target_rev: \"{target_rev}\", reason: \"{reason}\", idempotency_key: \"{idempotency_key}\", expected_erp_version: {expected_erp_version} }}"
            ),
            TypedAction::CreateBomRevisionRequest {
                parent_part_number,
                child_part_number,
                new_rev,
                reason,
                idempotency_key,
                expected_erp_version,
            } => format!(
                "CreateBomRevisionRequest {{ parent_part_number: \"{parent_part_number}\", child_part_number: \"{child_part_number}\", new_rev: \"{new_rev}\", reason: \"{reason}\", idempotency_key: \"{idempotency_key}\", expected_erp_version: {expected_erp_version} }}"
            ),
        }
    }
}

fn tokenize_dsl(input: &str) -> Result<Vec<Token>, CfgError> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
        } else if c == '{' {
            tokens.push(Token::LBrace);
            chars.next();
        } else if c == '}' {
            tokens.push(Token::RBrace);
            chars.next();
        } else if c == ':' {
            tokens.push(Token::Colon);
            chars.next();
        } else if c == ',' {
            tokens.push(Token::Comma);
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut s = String::new();
            let mut closed = false;
            while let Some(ch) = chars.next() {
                if ch == '"' {
                    closed = true;
                    break;
                } else if ch == '\\' {
                    if let Some(esc) = chars.next() {
                        s.push(esc);
                    }
                } else {
                    s.push(ch);
                }
            }
            if !closed {
                return Err(CfgError::Syntax("unterminated string literal".to_string()));
            }
            tokens.push(Token::Str(s));
        } else if c == '-' || c.is_ascii_digit() {
            let mut num_str = String::new();
            num_str.push(c);
            chars.next();
            while let Some(&nc) = chars.peek() {
                if nc.is_ascii_digit() {
                    num_str.push(nc);
                    chars.next();
                } else {
                    break;
                }
            }
            let n = num_str
                .parse::<i64>()
                .map_err(|_| CfgError::Syntax(format!("invalid integer '{num_str}'")))?;
            tokens.push(Token::Int(n));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let mut ident = String::new();
            while let Some(&ic) = chars.peek() {
                if ic.is_ascii_alphanumeric() || ic == '_' {
                    ident.push(ic);
                    chars.next();
                } else {
                    break;
                }
            }
            tokens.push(Token::Ident(ident));
        } else {
            return Err(CfgError::Syntax(format!("unexpected character '{c}'")));
        }
    }

    Ok(tokens)
}

/// Optional OpenAI-compatible local LLM client (e.g., MLX `mlx-openai-server`)
/// with deterministic CFG-compliant offline fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalLlmConfig {
    pub endpoint_url: Option<String>,
    pub model: String,
}

impl Default for LocalLlmConfig {
    fn default() -> Self {
        Self {
            endpoint_url: std::env::var("AXIOM_LLM_ENDPOINT").ok(),
            model: "mlx-community/Qwen2.5-7B-Instruct-4bit".to_string(),
        }
    }
}

pub struct ActionGenerator {
    config: LocalLlmConfig,
    http: reqwest::Client,
}

impl ActionGenerator {
    pub fn new(config: LocalLlmConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
        }
    }

    /// Attempt to generate a CFG-constrained action via local OpenAI-compatible LLM,
    /// falling back deterministically if no endpoint is configured or reachable.
    pub async fn generate_action_or_fallback(
        &self,
        prompt: &str,
        deterministic_fallback: TypedAction,
    ) -> (TypedAction, &'static str) {
        if let Some(url) = &self.config.endpoint_url {
            let body = serde_json::json!({
                "model": self.config.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "Output ONLY a single CFG-valid action: CreatePurchaseOrderDraft { ... } or CreateBomRevisionRequest { ... }."
                    },
                    { "role": "user", "content": prompt }
                ],
                "temperature": 0.0
            });
            if let Ok(resp) = self.http.post(url).json(&body).send().await {
                if let Ok(json) = resp.json::<serde_json::Value>().await {
                    if let Some(text) = json["choices"][0]["message"]["content"].as_str() {
                        if let Ok(parsed) = ActionCfgParser::parse(text) {
                            return (parsed, "local_llm");
                        }
                    }
                }
            }
        }
        (deterministic_fallback, "deterministic_cfg_mock")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_accepts_valid_actions() {
        let dsl_po = r#"CreatePurchaseOrderDraft {
            part_number: "PRT-1001",
            quantity: 10,
            target_rev: "Rev.C",
            reason: "Safety stock replenishment",
            idempotency_key: "idem-po-001",
            expected_erp_version: 1
        }"#;
        let parsed = ActionCfgParser::parse(dsl_po).unwrap();
        assert_eq!(parsed.action_kind(), "CreatePurchaseOrderDraft");

        let dsl_bom = r#"CreateBomRevisionRequest {
            parent_part_number: "ASM-9000",
            child_part_number: "PRT-1002",
            new_rev: "Rev.D",
            reason: "Align with latest Drawing DWG-1002",
            idempotency_key: "idem-bom-001",
            expected_erp_version: 1
        }"#;
        let parsed_bom = ActionCfgParser::parse(dsl_bom).unwrap();
        assert_eq!(parsed_bom.action_kind(), "CreateBomRevisionRequest");
    }

    #[test]
    fn test_cfg_rejects_undefined_actions_and_type_deviations() {
        let forbidden_1 = r#"DeleteAllOrders { confirm: "yes" }"#;
        assert!(matches!(
            ActionCfgParser::parse(forbidden_1),
            Err(CfgError::ForbiddenAction(_))
        ));

        let forbidden_2 = r#"ExecuteShell { cmd: "rm -rf /" }"#;
        assert!(matches!(
            ActionCfgParser::parse(forbidden_2),
            Err(CfgError::ForbiddenAction(_))
        ));

        // Type deviation: quantity as String instead of Int64
        let bad_type = r#"CreatePurchaseOrderDraft {
            part_number: "PRT-1001",
            quantity: "ten",
            target_rev: "Rev.C",
            reason: "test",
            idempotency_key: "k1",
            expected_erp_version: 1
        }"#;
        assert!(matches!(
            ActionCfgParser::parse(bad_type),
            Err(CfgError::TypeMismatch { .. })
        ));
    }
}
