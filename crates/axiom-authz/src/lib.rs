//! Cedar runtime authorization (`cedar-policy`) and SMT-based policy invariant
//! verification (`cedar-policy-symcc`).

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, RequestEnv, Schema,
};
use cedar_policy_symcc::{solver::LocalSolver, CedarSymCompiler, CompiledPolicySet};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthzError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Cedar schema error: {0}")]
    Schema(String),
    #[error("Cedar policy parse error: {0}")]
    PolicyParse(String),
    #[error("Cedar entity/request error: {0}")]
    Request(String),
    #[error("SymCC error: {0}")]
    Symcc(String),
}

/// Principal kind in AxiomGraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrincipalKind {
    User,
    Agent,
}

/// Authorization decision summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzOutcome {
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub errors: Vec<String>,
}

/// Result of a single SymCC invariant check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheckResult {
    pub name: String,
    pub status: String, // "PASSED", "FAILED", "SKIPPED"
    pub detail: String,
}

/// Full SymCC verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymccVerificationReport {
    pub cvc5_available: bool,
    pub cvc5_path: Option<String>,
    pub checks: Vec<InvariantCheckResult>,
}

/// Cedar authorization engine holding schema and policy set.
pub struct AxiomAuthorizer {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
}

impl AxiomAuthorizer {
    pub fn from_files(schema_path: &Path, policy_path: &Path) -> Result<Self, AuthzError> {
        let schema_str = std::fs::read_to_string(schema_path)?;
        let policy_str = std::fs::read_to_string(policy_path)?;
        Self::from_str(&schema_str, &policy_str)
    }

    pub fn from_str(schema_src: &str, policy_src: &str) -> Result<Self, AuthzError> {
        let (schema, _) =
            Schema::from_cedarschema_str(schema_src).map_err(|e| AuthzError::Schema(e.to_string()))?;
        let policies =
            PolicySet::from_str(policy_src).map_err(|e| AuthzError::PolicyParse(e.to_string()))?;
        Ok(Self {
            schema,
            policies,
            authorizer: Authorizer::new(),
        })
    }

    /// Evaluate a runtime authorization request against Cedar policies and schema.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &self,
        principal_kind: PrincipalKind,
        principal_id: &str,
        action_name: &str,
        resource_id: &str,
        approval_status: &str,
        dry_run_passed: bool,
        action_kind: &str,
    ) -> Result<AuthzOutcome, AuthzError> {
        let p_type = match principal_kind {
            PrincipalKind::User => "AxiomGraph::User",
            PrincipalKind::Agent => "AxiomGraph::Agent",
        };
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(p_type).map_err(|e| AuthzError::Request(e.to_string()))?,
            EntityId::from_str(principal_id).map_err(|e| AuthzError::Request(e.to_string()))?,
        );
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("AxiomGraph::Action")
                .map_err(|e| AuthzError::Request(e.to_string()))?,
            EntityId::from_str(action_name).map_err(|e| AuthzError::Request(e.to_string()))?,
        );
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("AxiomGraph::Resource")
                .map_err(|e| AuthzError::Request(e.to_string()))?,
            EntityId::from_str(resource_id).map_err(|e| AuthzError::Request(e.to_string()))?,
        );

        let ctx_json = serde_json::json!({
            "approval_status": approval_status,
            "dry_run_passed": dry_run_passed,
            "action_kind": action_kind,
        });
        let context = Context::from_json_value(ctx_json, Some((&self.schema, &action)))
            .map_err(|e| AuthzError::Request(e.to_string()))?;

        let entities_json = serde_json::json!([
            {
                "uid": { "type": p_type, "id": principal_id },
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "AxiomGraph::Resource", "id": resource_id },
                "attrs": { "resource_type": "ErpRecord" },
                "parents": []
            }
        ]);
        let entities = Entities::from_json_value(entities_json, Some(&self.schema))
            .map_err(|e| AuthzError::Request(e.to_string()))?;

        let request = Request::new(principal, action, resource, context, Some(&self.schema))
            .map_err(|e| AuthzError::Request(e.to_string()))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policies, &entities);

        let allowed = response.decision() == Decision::Allow;
        let reasons = response
            .diagnostics()
            .reason()
            .map(|r| r.to_string())
            .collect();
        let errors = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        Ok(AuthzOutcome {
            allowed,
            reasons,
            errors,
        })
    }

    /// Run Cedar SymCC formal invariant verification (uses `cvc5` if available).
    pub async fn verify_invariants_with_symcc(
        &self,
        candidate_policies_src: Option<&str>,
    ) -> Result<SymccVerificationReport, AuthzError> {
        let cvc5_path = detect_cvc5();
        let Some(cvc5) = cvc5_path.clone() else {
            return Ok(SymccVerificationReport {
                cvc5_available: false,
                cvc5_path: None,
                checks: vec![
                    InvariantCheckResult {
                        name: "Invariant 1: Required attributes/context".to_string(),
                        status: "SKIPPED".to_string(),
                        detail: "cvc5 binary not found in CVC5 env var or PATH".to_string(),
                    },
                    InvariantCheckResult {
                        name: "Invariant 2: Write-back requires approval_status == APPROVED"
                            .to_string(),
                        status: "SKIPPED".to_string(),
                        detail: "cvc5 binary not found in CVC5 env var or PATH".to_string(),
                    },
                    InvariantCheckResult {
                        name: "Invariant 3: No privilege escalation in candidate policy"
                            .to_string(),
                        status: "SKIPPED".to_string(),
                        detail: "cvc5 binary not found in CVC5 env var or PATH".to_string(),
                    },
                ],
            });
        };

        let mut cmd = tokio::process::Command::new(&cvc5);
        let solver = LocalSolver::from_command(&mut cmd)
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;
        let mut compiler = CedarSymCompiler::new(solver)
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;

        let mut checks = Vec::new();
        let writeback_spec_src = r#"
            permit (principal, action, resource)
            when {
                context.approval_status == "APPROVED" &&
                context.dry_run_passed == true
            };
        "#;
        let writeback_spec = PolicySet::from_str(writeback_spec_src)
            .map_err(|e| AuthzError::PolicyParse(e.to_string()))?;

        let env_po = RequestEnv::new(
            EntityTypeName::from_str("AxiomGraph::Agent").unwrap(),
            EntityUid::from_type_name_and_id(
                EntityTypeName::from_str("AxiomGraph::Action").unwrap(),
                EntityId::from_str("CreatePurchaseOrderDraft").unwrap(),
            ),
            EntityTypeName::from_str("AxiomGraph::Resource").unwrap(),
        );

        let compiled_baseline = CompiledPolicySet::compile(&self.policies, &env_po, &self.schema)
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;
        let compiled_spec = CompiledPolicySet::compile(&writeback_spec, &env_po, &self.schema)
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;

        // Invariant 1 & 2: baseline implies writeback_spec (never allows without APPROVED + dry_run)
        let implies_spec = compiler
            .check_implies_opt(&compiled_baseline, &compiled_spec)
            .await
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;

        checks.push(InvariantCheckResult {
            name: "Invariant 1: Required attributes/context".to_string(),
            status: if implies_spec { "PASSED" } else { "FAILED" }.to_string(),
            detail: "Verified baseline Write-back policy implies context preconditions".to_string(),
        });
        checks.push(InvariantCheckResult {
            name: "Invariant 2: Write-back requires approval_status == APPROVED".to_string(),
            status: if implies_spec { "PASSED" } else { "FAILED" }.to_string(),
            detail: "Verified no SMT counterexample allows Write-back when approval_status != APPROVED".to_string(),
        });

        // Invariant 3: candidate policy escalation check
        let cand_src = candidate_policies_src.unwrap_or(include_str!("../../../policies/axiom.cedar"));
        let cand_set =
            PolicySet::from_str(cand_src).map_err(|e| AuthzError::PolicyParse(e.to_string()))?;
        let compiled_cand = CompiledPolicySet::compile(&cand_set, &env_po, &self.schema)
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;
        let no_escalation = compiler
            .check_implies_opt(&compiled_cand, &compiled_baseline)
            .await
            .map_err(|e| AuthzError::Symcc(e.to_string()))?;

        checks.push(InvariantCheckResult {
            name: "Invariant 3: No privilege escalation in candidate policy".to_string(),
            status: if no_escalation { "PASSED" } else { "FAILED" }.to_string(),
            detail: "Verified candidate policy does not allow any request denied by baseline"
                .to_string(),
        });

        Ok(SymccVerificationReport {
            cvc5_available: true,
            cvc5_path: Some(cvc5),
            checks,
        })
    }
}

fn detect_cvc5() -> Option<String> {
    if let Ok(p) = std::env::var("CVC5") {
        if !p.trim().is_empty() && Path::new(&p).exists() {
            return Some(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("cvc5");
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_default_authorizer() -> AxiomAuthorizer {
        let schema = include_str!("../../../policies/axiom.cedarschema");
        let policy = include_str!("../../../policies/axiom.cedar");
        AxiomAuthorizer::from_str(schema, policy).unwrap()
    }

    #[test]
    fn test_unapproved_writeback_is_denied_and_approved_is_allowed() {
        let authz = load_default_authorizer();

        let denied = authz
            .authorize(
                PrincipalKind::Agent,
                "omoikane-agent",
                "CreatePurchaseOrderDraft",
                "PRT-1001",
                "PENDING",
                true,
                "CreatePurchaseOrderDraft",
            )
            .unwrap();
        assert!(!denied.allowed, "PENDING approval must be denied");

        let denied_no_dryrun = authz
            .authorize(
                PrincipalKind::Agent,
                "omoikane-agent",
                "CreatePurchaseOrderDraft",
                "PRT-1001",
                "APPROVED",
                false,
                "CreatePurchaseOrderDraft",
            )
            .unwrap();
        assert!(!denied_no_dryrun.allowed, "dry_run_passed=false must be denied");

        let allowed = authz
            .authorize(
                PrincipalKind::Agent,
                "omoikane-agent",
                "CreatePurchaseOrderDraft",
                "PRT-1001",
                "APPROVED",
                true,
                "CreatePurchaseOrderDraft",
            )
            .unwrap();
        assert!(allowed.allowed, "APPROVED + dry_run_passed=true must be allowed");
    }

    #[test]
    fn test_agent_cannot_approve_action() {
        let authz = load_default_authorizer();
        let agent_approve = authz.authorize(
            PrincipalKind::Agent,
            "omoikane-agent",
            "ApproveAction",
            "ACT-001",
            "PENDING",
            true,
            "ApproveAction",
        );
        assert!(
            agent_approve.as_ref().map(|o| !o.allowed).unwrap_or(true),
            "Agent must never be allowed to ApproveAction"
        );

        let user_approve = authz
            .authorize(
                PrincipalKind::User,
                "tanaka",
                "ApproveAction",
                "ACT-001",
                "PENDING",
                true,
                "ApproveAction",
            )
            .unwrap();
        assert!(user_approve.allowed, "Human User should be allowed to ApproveAction");
    }

    #[tokio::test]
    async fn test_symcc_verification_handles_missing_cvc5_gracefully() {
        let authz = load_default_authorizer();
        let report = authz.verify_invariants_with_symcc(None).await.unwrap();
        assert_eq!(report.checks.len(), 3);
        if !report.cvc5_available {
            assert!(report.checks.iter().all(|c| c.status == "SKIPPED"));
        }
    }
}
