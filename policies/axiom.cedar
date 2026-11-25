// AxiomGraph (思兼 / OMOIKANE) Authorization Policies

// 1. Write-back actions are permitted for User or Agent ONLY when:
//    - context.approval_status == "APPROVED"
//    - context.dry_run_passed == true
//    - context.action_kind matches the action
permit (
    principal,
    action in [
        AxiomGraph::Action::"CreatePurchaseOrderDraft",
        AxiomGraph::Action::"CreateBomRevisionRequest"
    ],
    resource
)
when {
    (principal is AxiomGraph::User || principal is AxiomGraph::Agent) &&
    context.approval_status == "APPROVED" &&
    context.dry_run_passed == true &&
    (context.action_kind == "CreatePurchaseOrderDraft" ||
     context.action_kind == "CreateBomRevisionRequest")
};

// Explicit forbid: never allow Write-back if approval_status is not APPROVED or dry_run_passed is false
forbid (
    principal,
    action in [
        AxiomGraph::Action::"CreatePurchaseOrderDraft",
        AxiomGraph::Action::"CreateBomRevisionRequest"
    ],
    resource
)
unless {
    context.approval_status == "APPROVED" &&
    context.dry_run_passed == true
};

// 2. Only human Users can ApproveAction
permit (
    principal is AxiomGraph::User,
    action == AxiomGraph::Action::"ApproveAction",
    resource
)
when {
    context.dry_run_passed == true
};

// Explicit forbid: Agents can NEVER approve actions
forbid (
    principal is AxiomGraph::Agent,
    action == AxiomGraph::Action::"ApproveAction",
    resource
);

// 3. Users and Agents can propose/update PCFG mappings
permit (
    principal,
    action == AxiomGraph::Action::"UpdateMapping",
    resource
)
when {
    context.action_kind == "UpdateMapping"
};
