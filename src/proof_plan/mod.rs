//! Covenant ProofPlan metadata for CKB trigger/scope/coverage auditing.

use crate::ast::{AggregateInvariantKind, AggregateRelation, ParamSource};
use crate::ir::{self, IrInstruction};
use crate::{CkbRuntimeAccessMetadata, PoolPrimitiveMetadata, VerifierObligationMetadata};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanSourceSpanMetadata {
    pub start: usize,
    pub end: usize,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanDiagnosticMetadata {
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanMetadata {
    pub name: String,
    pub origin: String,
    pub category: String,
    pub feature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_span: Option<ProofPlanSourceSpanMetadata>,
    pub trigger: String,
    pub scope: String,
    pub reads: Vec<String>,
    pub coverage: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_output_relation_checks: Vec<String>,
    pub group_cardinality: String,
    pub identity_lifecycle_policy: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lock_args_fields: Vec<String>,
    pub on_chain_checked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub on_chain_checked_obligations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub builder_assumptions: Vec<String>,
    pub codegen_coverage_status: String,
    pub status: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<ProofPlanDiagnosticMetadata>,
}

pub fn build_for_body(
    scope_kind: &str,
    name: &str,
    body: &ir::IrBody,
    params: &[ir::IrParam],
    obligations: &[VerifierObligationMetadata],
    runtime_accesses: &[CkbRuntimeAccessMetadata],
    pool_primitives: &[PoolPrimitiveMetadata],
) -> Vec<ProofPlanMetadata> {
    let origin = format!("{}:{}", scope_kind, name);
    let body_reads = body_reads(body, params, runtime_accesses);
    let body_coverage = body_coverage(scope_kind, name, body);
    let preserved_fields = preserved_fields(body);
    let witness_fields = witness_fields(params, runtime_accesses);
    let lock_args_fields = lock_args_fields(params, runtime_accesses);
    let mut plans = Vec::new();
    let mut seen = BTreeSet::new();

    for obligation in obligations {
        let key = (obligation.scope.clone(), obligation.category.clone(), obligation.feature.clone(), obligation.status.clone());
        if seen.insert(key) {
            plans.push(plan_from_obligation(
                scope_kind,
                &origin,
                obligation,
                &body_reads,
                &body_coverage,
                &preserved_fields,
                &witness_fields,
                &lock_args_fields,
                pool_primitives,
            ));
        }
    }

    for primitive in pool_primitives {
        let key = (primitive.scope.clone(), "pool-primitive".to_string(), primitive.feature.clone(), primitive.status.clone());
        if seen.insert(key) {
            let obligation = VerifierObligationMetadata {
                scope: primitive.scope.clone(),
                category: "pool-primitive".to_string(),
                feature: primitive.feature.clone(),
                status: primitive.status.clone(),
                detail: format!(
                    "Pool primitive {}:{} checked components [{}]; runtime-required components [{}]",
                    primitive.operation,
                    primitive.ty,
                    primitive.checked_components.join(", "),
                    primitive.runtime_required_components.join(", ")
                ),
            };
            plans.push(plan_from_obligation(
                scope_kind,
                &origin,
                &obligation,
                &body_reads,
                &body_coverage,
                &preserved_fields,
                &witness_fields,
                &lock_args_fields,
                pool_primitives,
            ));
        }
    }

    plans
}

pub fn build_for_invariant(invariant: &ir::IrInvariant) -> Vec<ProofPlanMetadata> {
    let mut plans = vec![summary_plan_for_invariant(invariant)];
    plans.extend(
        invariant.aggregates.iter().enumerate().map(|(index, aggregate)| plan_for_aggregate_invariant(invariant, index, aggregate)),
    );
    plans
}

fn summary_plan_for_invariant(invariant: &ir::IrInvariant) -> ProofPlanMetadata {
    let trigger = invariant.trigger.clone().unwrap_or_else(|| "explicit_entry".to_string());
    let scope = invariant.scope.clone().unwrap_or_else(|| "selected_cells".to_string());
    let mut coverage = vec![format!("declared_invariant_assertions:{}", invariant.assert_count)];
    coverage.extend(invariant.aggregates.iter().map(aggregate_coverage_label));
    coverage.extend(coverage_notes(&trigger, &scope));
    dedup(&mut coverage);

    let mut reads = invariant.reads.clone();
    for aggregate in &invariant.aggregates {
        reads.extend(aggregate_reads(aggregate));
    }
    dedup(&mut reads);

    let mut input_output_relation_checks = invariant.aggregates.iter().map(aggregate_relation_check_label).collect::<Vec<_>>();
    dedup(&mut input_output_relation_checks);

    let mut builder_assumptions = vec![
        "declared(metadata-only invariant not yet lowered to executable verifier code)".to_string(),
        format!("declared(assert_invariant_count:{})", invariant.assert_count),
    ];
    if !invariant.aggregates.is_empty() {
        builder_assumptions.push(format!("declared(aggregate_invariant_count:{})", invariant.aggregates.len()));
    }
    if trigger == "lock_group" && scope == "transaction" {
        builder_assumptions.push(
            "declared(lock transaction scan only protects the lock group unless the builder constrains every relevant cell)"
                .to_string(),
        );
    }
    dedup(&mut builder_assumptions);

    let mut diagnostics = vec![ProofPlanDiagnosticMetadata {
        severity: "warning".to_string(),
        message: "declared invariant is metadata-only until executable lowering covers it".to_string(),
    }];
    if trigger == "lock_group" && scope == "transaction" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message:
                "transaction scans from a lock do not imply type-group conservation; only inputs sharing the lock trigger this verifier"
                    .to_string(),
        });
    }

    ProofPlanMetadata {
        name: invariant.name.clone(),
        origin: format!("invariant:{}", invariant.name),
        category: "declared-invariant".to_string(),
        feature: invariant.name.clone(),
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: invariant.span.start,
            end: invariant.span.end,
            line: invariant.span.line,
            column: invariant.span.column,
        }),
        trigger,
        scope,
        reads: reads.clone(),
        coverage,
        input_output_relation_checks,
        group_cardinality: declared_group_cardinality(invariant).to_string(),
        identity_lifecycle_policy: declared_identity_lifecycle_policy(invariant).to_string(),
        preserved_fields: Vec::new(),
        witness_fields: declared_witness_fields(&reads),
        lock_args_fields: declared_lock_args_fields(&reads),
        on_chain_checked: false,
        on_chain_checked_obligations: Vec::new(),
        builder_assumptions,
        codegen_coverage_status: "gap:metadata-only".to_string(),
        status: "runtime-required".to_string(),
        detail: format!(
            "explicit source invariant declaration captured for ProofPlan auditing; aggregate_primitives={}",
            invariant.aggregates.len()
        ),
        diagnostics,
    }
}

fn plan_for_aggregate_invariant(invariant: &ir::IrInvariant, index: usize, aggregate: &ir::IrAggregateInvariant) -> ProofPlanMetadata {
    let trigger = invariant.trigger.clone().unwrap_or_else(|| "explicit_entry".to_string());
    let scope = aggregate.scope.clone();
    let reads = aggregate_reads(aggregate);
    let relation_check = aggregate_relation_check_label(aggregate);
    let mut coverage = vec![aggregate_coverage_label(aggregate)];
    coverage.extend(coverage_notes(&trigger, &scope));
    dedup(&mut coverage);
    let mut builder_assumptions = vec![
        "declared(metadata-only aggregate invariant not yet lowered to executable verifier code)".to_string(),
        format!("declared(parent_invariant:{})", invariant.name),
    ];
    if trigger == "lock_group" && scope == "transaction" {
        builder_assumptions.push(
            "declared(lock transaction scan only protects the lock group unless the builder constrains every relevant cell)"
                .to_string(),
        );
    }
    dedup(&mut builder_assumptions);

    let mut diagnostics = vec![ProofPlanDiagnosticMetadata {
        severity: "warning".to_string(),
        message: "aggregate invariant primitive is metadata-only until executable lowering covers it".to_string(),
    }];
    if trigger == "lock_group" && scope == "transaction" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message:
                "transaction scans from a lock do not imply type-group conservation; only inputs sharing the lock trigger this verifier"
                    .to_string(),
        });
    }

    ProofPlanMetadata {
        name: format!("{}#aggregate{}", invariant.name, index),
        origin: format!("invariant:{}#aggregate:{}", invariant.name, index),
        category: "aggregate-invariant".to_string(),
        feature: aggregate_feature_label(aggregate),
        source_span: Some(ProofPlanSourceSpanMetadata {
            start: aggregate.span.start,
            end: aggregate.span.end,
            line: aggregate.span.line,
            column: aggregate.span.column,
        }),
        trigger,
        scope,
        reads: reads.clone(),
        coverage,
        input_output_relation_checks: vec![relation_check],
        group_cardinality: aggregate_group_cardinality(aggregate).to_string(),
        identity_lifecycle_policy: aggregate_identity_lifecycle_policy(aggregate).to_string(),
        preserved_fields: Vec::new(),
        witness_fields: declared_witness_fields(&reads),
        lock_args_fields: declared_lock_args_fields(&reads),
        on_chain_checked: false,
        on_chain_checked_obligations: Vec::new(),
        builder_assumptions,
        codegen_coverage_status: "gap:metadata-only".to_string(),
        status: "runtime-required".to_string(),
        detail: format!("aggregate invariant primitive declared under invariant '{}'", invariant.name),
        diagnostics,
    }
}

fn plan_from_obligation(
    scope_kind: &str,
    origin: &str,
    obligation: &VerifierObligationMetadata,
    body_reads: &[String],
    body_coverage: &[String],
    preserved_fields: &[String],
    witness_fields: &[String],
    lock_args_fields: &[String],
    pool_primitives: &[PoolPrimitiveMetadata],
) -> ProofPlanMetadata {
    let trigger = trigger_for_scope_kind(scope_kind).to_string();
    let scope = proof_scope(scope_kind, obligation, body_reads).to_string();
    let reads = reads_for_obligation(obligation, body_reads);
    let mut coverage = body_coverage.to_vec();
    coverage.extend(coverage_notes(&trigger, &scope));
    coverage.extend(macro_expansion_provenance(obligation));
    dedup(&mut coverage);
    let on_chain_checked = on_chain_checked(&obligation.status);
    let input_output_relation_checks = input_output_relation_checks(obligation, pool_primitives);
    let on_chain_checked_obligations =
        if on_chain_checked { checked_obligation_labels(obligation, &input_output_relation_checks) } else { Vec::new() };
    let builder_assumptions = builder_assumptions(obligation, &trigger, &scope, on_chain_checked);
    let diagnostics = diagnostics_for_plan(&trigger, &scope, obligation, &builder_assumptions);

    ProofPlanMetadata {
        name: obligation.feature.clone(),
        origin: origin.to_string(),
        category: obligation.category.clone(),
        feature: obligation.feature.clone(),
        source_span: None,
        trigger,
        scope,
        reads,
        coverage,
        input_output_relation_checks,
        group_cardinality: group_cardinality(obligation, scope_kind).to_string(),
        identity_lifecycle_policy: identity_lifecycle_policy(obligation).to_string(),
        preserved_fields: preserved_fields.to_vec(),
        witness_fields: witness_fields.to_vec(),
        lock_args_fields: lock_args_fields.to_vec(),
        on_chain_checked,
        on_chain_checked_obligations,
        builder_assumptions,
        codegen_coverage_status: codegen_coverage_status(&obligation.status, on_chain_checked).to_string(),
        status: obligation.status.clone(),
        detail: obligation.detail.clone(),
        diagnostics,
    }
}

fn trigger_for_scope_kind(scope_kind: &str) -> &'static str {
    match scope_kind {
        "lock" => "lock_group",
        _ => "explicit_entry",
    }
}

fn proof_scope<'a>(scope_kind: &str, obligation: &'a VerifierObligationMetadata, reads: &'a [String]) -> &'static str {
    if obligation.category == "transaction-invariant"
        || obligation.feature.contains("transfer-output")
        || obligation.feature.contains("destroy-output-scan")
        || obligation.feature.contains("resource-conservation")
    {
        "transaction"
    } else if reads.iter().any(|read| read.starts_with("group_")) || scope_kind == "lock" {
        "group"
    } else {
        "selected_cells"
    }
}

fn body_reads(body: &ir::IrBody, params: &[ir::IrParam], runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<String> {
    let mut reads = BTreeSet::new();
    for access in runtime_accesses {
        if let Some(read) = read_for_source(&access.source) {
            reads.insert(read.to_string());
        }
    }
    if !body.consume_set.is_empty() {
        reads.insert("input".to_string());
    }
    if !body.create_set.is_empty() {
        reads.insert("output".to_string());
    }
    if !body.read_refs.is_empty() {
        reads.insert("cell_dep".to_string());
    }
    if !body.mutate_set.is_empty() {
        reads.insert("input".to_string());
        reads.insert("output".to_string());
    }
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                IrInstruction::Transfer { .. } | IrInstruction::Claim { .. } | IrInstruction::Settle { .. } => {
                    reads.insert("input".to_string());
                    reads.insert("output".to_string());
                }
                IrInstruction::Destroy { .. } => {
                    reads.insert("input".to_string());
                    reads.insert("output".to_string());
                }
                _ => {}
            }
        }
    }
    for param in params {
        match param.source {
            ParamSource::Protected => {
                reads.insert("group_input".to_string());
            }
            ParamSource::Witness => {
                reads.insert("witness".to_string());
            }
            ParamSource::LockArgs => {
                reads.insert("lock_args".to_string());
            }
            ParamSource::Default => {}
        }
    }
    reads.into_iter().collect()
}

fn read_for_source(source: &str) -> Option<&'static str> {
    match source {
        "Input" => Some("input"),
        "Output" => Some("output"),
        "GroupInput" => Some("group_input"),
        "GroupOutput" => Some("group_output"),
        "CellDep" => Some("cell_dep"),
        "HeaderDep" => Some("header_dep"),
        "Witness" => Some("witness"),
        "ScriptArgs" => Some("lock_args"),
        _ => None,
    }
}

fn reads_for_obligation(obligation: &VerifierObligationMetadata, body_reads: &[String]) -> Vec<String> {
    let mut reads = body_reads.to_vec();
    if obligation.category == "cell-access" {
        if let Some(source) = obligation.feature.split(':').nth(1).and_then(|source| source.split('#').next()) {
            if let Some(read) = read_for_source(source) {
                reads.push(read.to_string());
            }
        }
    }
    if obligation.detail.contains("witness") || obligation.feature.contains("witness") {
        reads.push("witness".to_string());
    }
    if obligation.detail.contains("header") || obligation.feature.contains("header") {
        reads.push("header_dep".to_string());
    }
    dedup(&mut reads);
    reads
}

fn body_coverage(scope_kind: &str, name: &str, body: &ir::IrBody) -> Vec<String> {
    let mut coverage = vec![format!("entry:{}:{}", scope_kind, name)];
    if !body.consume_set.is_empty() {
        coverage.push(format!(
            "covered_cells(inputs:{})",
            body.consume_set.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    if !body.create_set.is_empty() {
        coverage.push(format!(
            "covered_cells(outputs:{})",
            body.create_set.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    if !body.read_refs.is_empty() {
        coverage.push(format!(
            "observed_cells(cell_deps:{})",
            body.read_refs.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    if !body.mutate_set.is_empty() {
        coverage.push(format!(
            "covered_cells(replacements:{})",
            body.mutate_set.iter().map(|pattern| pattern.binding.as_str()).collect::<Vec<_>>().join(",")
        ));
    }
    coverage
}

fn coverage_notes(trigger: &str, scope: &str) -> Vec<String> {
    match (trigger, scope) {
        ("lock_group", "transaction") => vec![
            "only inputs sharing this lock script trigger the verifier".to_string(),
            "transaction scans from a lock do not imply type-group conservation".to_string(),
        ],
        ("lock_group", _) => vec!["lock ScriptGroup coverage: inputs sharing this lock script".to_string()],
        ("type_group", _) => vec!["type ScriptGroup coverage: cells sharing this type script".to_string()],
        (_, "transaction") => vec!["transaction-scoped relation over explicit input/output views".to_string()],
        (_, "selected_cells") => vec!["selected cell coverage from explicit consume/read_ref/create/mutate summaries".to_string()],
        _ => Vec::new(),
    }
}

fn preserved_fields(body: &ir::IrBody) -> Vec<String> {
    let mut fields = Vec::new();
    for pattern in &body.mutate_set {
        for field in &pattern.preserved_fields {
            fields.push(format!("{}.{}", pattern.binding, field));
        }
        if pattern.preserve_type_hash {
            fields.push(format!("{}.type_script_hash", pattern.binding));
        }
        if pattern.preserve_lock_hash {
            fields.push(format!("{}.lock_script_hash", pattern.binding));
        }
    }
    dedup(&mut fields);
    fields
}

fn witness_fields(params: &[ir::IrParam], runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<String> {
    let mut fields = Vec::new();
    for param in params {
        match param.source {
            ParamSource::Witness => fields.push(format!("witness.{}", param.name)),
            ParamSource::Default | ParamSource::Protected | ParamSource::LockArgs => {}
        }
    }
    for access in runtime_accesses {
        if access.source == "Witness" || access.operation.contains("witness") {
            fields.push(format!("{}#{}:{}", access.source, access.index, access.binding));
        }
    }
    dedup(&mut fields);
    fields
}

fn lock_args_fields(params: &[ir::IrParam], runtime_accesses: &[CkbRuntimeAccessMetadata]) -> Vec<String> {
    let mut fields = Vec::new();
    for param in params {
        if param.source == ParamSource::LockArgs {
            fields.push(format!("lock_args.{}", param.name));
        }
    }
    for access in runtime_accesses {
        if access.source == "ScriptArgs" || access.operation.contains("lock-args") {
            fields.push(format!("{}#{}:{}", access.source, access.index, access.binding));
        }
    }
    dedup(&mut fields);
    fields
}

fn on_chain_checked(status: &str) -> bool {
    matches!(status, "checked-runtime" | "checked-static" | "ckb-runtime")
}

fn input_output_relation_checks(obligation: &VerifierObligationMetadata, pool_primitives: &[PoolPrimitiveMetadata]) -> Vec<String> {
    let mut checks = checked_runtime_subconditions(&obligation.detail);
    if obligation.category == "transaction-invariant" && obligation.status == "checked-runtime" {
        checks.push(format!("{}=checked-runtime", obligation.feature));
    }
    for primitive in pool_primitives.iter().filter(|primitive| primitive.feature == obligation.feature) {
        checks.extend(primitive.checked_components.iter().cloned());
        checks.extend(primitive.runtime_required_components.iter().map(|component| format!("{}=runtime-required", component)));
    }
    dedup(&mut checks);
    checks
}

fn macro_expansion_provenance(obligation: &VerifierObligationMetadata) -> Vec<String> {
    if obligation.feature.starts_with("transfer-output:") || obligation.feature.starts_with("transfer-input:") {
        vec!["macro_expansion:transfer=consume-input+create-output".to_string()]
    } else if obligation.feature.starts_with("create-output:") {
        vec!["macro_expansion:create=create-output".to_string()]
    } else if obligation.feature.starts_with("claim-output:") || obligation.feature.starts_with("claim-input:") {
        vec!["macro_expansion:claim=consume-receipt+create-output".to_string()]
    } else if obligation.feature.starts_with("settle-output:") || obligation.feature.starts_with("settle-input:") {
        vec!["macro_expansion:settle=consume-pending+create-output".to_string()]
    } else if obligation.feature.starts_with("consume-input:") {
        vec!["macro_expansion:consume=consume-input".to_string()]
    } else if obligation.feature.starts_with("destroy-input:") {
        vec!["macro_expansion:destroy=consume-input+no-output".to_string()]
    } else if obligation.feature.starts_with("pool-create:") {
        vec!["macro_expansion:pool-create=shared-cell-create+pool-protocol-metadata".to_string()]
    } else if obligation.feature.starts_with("pool-mutation-invariants:") {
        vec!["macro_expansion:pool-mutation=shared-cell-mutate+invariant-metadata".to_string()]
    } else if obligation.feature.starts_with("pool-composition:") {
        vec!["macro_expansion:pool-composition=cross-call+pool-protocol-metadata".to_string()]
    } else {
        Vec::new()
    }
}

fn checked_runtime_subconditions(detail: &str) -> Vec<String> {
    let mut out = Vec::new();
    for segment in detail.split([',', ';']) {
        let trimmed = segment.trim();
        if let Some((prefix, _)) = trimmed.split_once("=checked-runtime") {
            let label = prefix.split_whitespace().last().unwrap_or(prefix).trim_matches(['.', ':']);
            if !label.is_empty() {
                out.push(label.to_string());
            }
        }
        if let Some((prefix, _)) = trimmed.split_once("=checked-static") {
            let label = prefix.split_whitespace().last().unwrap_or(prefix).trim_matches(['.', ':']);
            if !label.is_empty() {
                out.push(label.to_string());
            }
        }
    }
    dedup(&mut out);
    out
}

fn checked_obligation_labels(obligation: &VerifierObligationMetadata, relation_checks: &[String]) -> Vec<String> {
    let mut labels = vec![format!("{}:{}={}", obligation.category, obligation.feature, obligation.status)];
    labels.extend(relation_checks.iter().cloned());
    dedup(&mut labels);
    labels
}

fn builder_assumptions(obligation: &VerifierObligationMetadata, trigger: &str, scope: &str, on_chain_checked: bool) -> Vec<String> {
    let mut assumptions = Vec::new();
    if !on_chain_checked {
        assumptions.push(format!("declared({}: {})", obligation.status, obligation.detail));
    }
    if trigger == "lock_group" && scope == "transaction" {
        assumptions.push(
            "declared(lock transaction scan only protects the lock group unless the builder constrains every relevant cell)"
                .to_string(),
        );
    }
    assumptions
}

fn diagnostics_for_plan(
    trigger: &str,
    scope: &str,
    obligation: &VerifierObligationMetadata,
    builder_assumptions: &[String],
) -> Vec<ProofPlanDiagnosticMetadata> {
    let mut diagnostics = Vec::new();
    if trigger == "lock_group" && scope == "transaction" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message:
                "transaction scans from a lock do not imply type-group conservation; only inputs sharing the lock trigger this verifier"
                    .to_string(),
        });
    }
    if obligation.status == "runtime-required" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "warning".to_string(),
            message: "obligation is not fully covered by generated on-chain code".to_string(),
        });
    }
    if !builder_assumptions.is_empty() && obligation.status == "fail-closed" {
        diagnostics.push(ProofPlanDiagnosticMetadata {
            severity: "error".to_string(),
            message: "generated code fail-closes this obligation instead of accepting a metadata-only proof".to_string(),
        });
    }
    diagnostics
}

fn group_cardinality(obligation: &VerifierObligationMetadata, scope_kind: &str) -> &'static str {
    let text = format!("{} {}", obligation.feature, obligation.detail).to_ascii_lowercase();
    if text.contains("type_id") || text.contains("type-id") {
        "ckb_type_id: at-most-one-input-and-one-output"
    } else if scope_kind == "lock" {
        "ckb lock ScriptGroup cardinality"
    } else if text.contains("group") {
        "ckb ScriptGroup cardinality"
    } else {
        "not a script-group cardinality obligation"
    }
}

fn identity_lifecycle_policy(obligation: &VerifierObligationMetadata) -> &'static str {
    let text = format!("{} {}", obligation.feature, obligation.detail).to_ascii_lowercase();
    if text.contains("type_id") || text.contains("type-id") {
        "identity ckb_type_id"
    } else if text.contains("destroy-output-scan") || text.contains("same type") || text.contains("typehash absence") {
        "destroy_singleton_type compatibility policy"
    } else if text.contains("destroy") {
        "explicit destruction policy required"
    } else if text.contains("lifecycle") || text.contains("settle-finalization") {
        "identity lifecycle transition policy"
    } else if text.contains("transfer") || text.contains("preserve") || text.contains("replacement") {
        "preserve_identity(input, output)"
    } else {
        "none"
    }
}

fn codegen_coverage_status(status: &str, on_chain_checked: bool) -> &str {
    if on_chain_checked {
        "covered"
    } else if status == "runtime-required" {
        "gap:runtime-required"
    } else if status == "fail-closed" {
        "fail-closed"
    } else {
        status
    }
}

fn aggregate_coverage_label(aggregate: &ir::IrAggregateInvariant) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "aggregate_assertion:{}{}{} scope={}",
            aggregate.target,
            aggregate.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            aggregate.rhs.as_deref().unwrap_or("?"),
            aggregate.scope
        ),
        AggregateInvariantKind::Conserved => format!("aggregate_assertion:conserved({}) scope={}", aggregate.target, aggregate.scope),
        AggregateInvariantKind::Delta => format!(
            "aggregate_assertion:delta({},{}) scope={}",
            aggregate.target,
            aggregate.argument.as_deref().unwrap_or("?"),
            aggregate.scope
        ),
        AggregateInvariantKind::Distinct => format!("aggregate_assertion:distinct({}) scope={}", aggregate.target, aggregate.scope),
        AggregateInvariantKind::Singleton => format!("aggregate_assertion:singleton({}) scope={}", aggregate.target, aggregate.scope),
    }
}

fn aggregate_relation_check_label(aggregate: &ir::IrAggregateInvariant) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "assert_sum:{}{}{}=metadata-only",
            aggregate.target,
            aggregate.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            aggregate.rhs.as_deref().unwrap_or("?")
        ),
        AggregateInvariantKind::Conserved => format!("assert_conserved:{}=metadata-only", aggregate.target),
        AggregateInvariantKind::Delta => {
            format!("assert_delta:{}:{}=metadata-only", aggregate.target, aggregate.argument.as_deref().unwrap_or("?"))
        }
        AggregateInvariantKind::Distinct => format!("assert_distinct:{}=metadata-only", aggregate.target),
        AggregateInvariantKind::Singleton => format!("assert_singleton:{}=metadata-only", aggregate.target),
    }
}

fn aggregate_feature_label(aggregate: &ir::IrAggregateInvariant) -> String {
    match aggregate.kind {
        AggregateInvariantKind::Sum => format!(
            "assert_sum:{}{}{}",
            aggregate.target,
            aggregate.relation.map(aggregate_relation_symbol).unwrap_or("?"),
            aggregate.rhs.as_deref().unwrap_or("?")
        ),
        AggregateInvariantKind::Conserved => format!("assert_conserved:{}", aggregate.target),
        AggregateInvariantKind::Delta => format!("assert_delta:{}:{}", aggregate.target, aggregate.argument.as_deref().unwrap_or("?")),
        AggregateInvariantKind::Distinct => format!("assert_distinct:{}", aggregate.target),
        AggregateInvariantKind::Singleton => format!("assert_singleton:{}", aggregate.target),
    }
}

fn aggregate_reads(aggregate: &ir::IrAggregateInvariant) -> Vec<String> {
    let mut reads = Vec::new();
    reads.extend(reads_from_aggregate_target(&aggregate.target));
    if let Some(rhs) = &aggregate.rhs {
        reads.extend(reads_from_aggregate_target(rhs));
    }
    if reads.is_empty() {
        match aggregate.scope.as_str() {
            "group" => {
                reads.push("group_input".to_string());
                reads.push("group_output".to_string());
            }
            "transaction" => {
                reads.push("input".to_string());
                reads.push("output".to_string());
            }
            _ => {}
        }
    }
    dedup(&mut reads);
    reads
}

fn reads_from_aggregate_target(target: &str) -> Vec<String> {
    let base = target.split(['<', '.']).next().unwrap_or(target);
    match base {
        "input" | "inputs" => vec!["input".to_string()],
        "output" | "outputs" => vec!["output".to_string()],
        "group_input" | "group_inputs" => vec!["group_input".to_string()],
        "group_output" | "group_outputs" => vec!["group_output".to_string()],
        _ => Vec::new(),
    }
}

fn aggregate_group_cardinality(aggregate: &ir::IrAggregateInvariant) -> &'static str {
    match aggregate.scope.as_str() {
        "group" => "ckb ScriptGroup cardinality",
        "transaction" => "transaction input/output cardinality",
        "selected_cells" => "selected cell-set cardinality",
        _ => "not a script-group cardinality obligation",
    }
}

fn aggregate_identity_lifecycle_policy(aggregate: &ir::IrAggregateInvariant) -> &'static str {
    match aggregate.kind {
        AggregateInvariantKind::Conserved => "aggregate conservation policy",
        AggregateInvariantKind::Delta => "aggregate delta policy",
        AggregateInvariantKind::Distinct => "aggregate uniqueness policy",
        AggregateInvariantKind::Singleton => "aggregate singleton policy",
        AggregateInvariantKind::Sum => "aggregate sum relation policy",
    }
}

fn aggregate_relation_symbol(relation: AggregateRelation) -> &'static str {
    match relation {
        AggregateRelation::Lt => "<",
        AggregateRelation::Le => "<=",
        AggregateRelation::Eq => "==",
        AggregateRelation::Ge => ">=",
        AggregateRelation::Gt => ">",
    }
}

fn declared_group_cardinality(invariant: &ir::IrInvariant) -> &'static str {
    match invariant.trigger.as_deref() {
        Some("type_group") => "ckb type ScriptGroup cardinality",
        Some("lock_group") => "ckb lock ScriptGroup cardinality",
        _ if invariant.scope.as_deref() == Some("group") => "ckb ScriptGroup cardinality",
        _ => "not a script-group cardinality obligation",
    }
}

fn declared_identity_lifecycle_policy(invariant: &ir::IrInvariant) -> &'static str {
    if invariant.aggregates.iter().any(|aggregate| {
        matches!(aggregate.kind, AggregateInvariantKind::Conserved | AggregateInvariantKind::Delta | AggregateInvariantKind::Singleton)
    }) {
        "aggregate invariant policy"
    } else {
        "declared invariant policy"
    }
}

fn declared_witness_fields(reads: &[String]) -> Vec<String> {
    let mut fields = reads.iter().filter(|read| read.starts_with("witness")).cloned().collect::<Vec<_>>();
    dedup(&mut fields);
    fields
}

fn declared_lock_args_fields(reads: &[String]) -> Vec<String> {
    let mut fields = reads.iter().filter(|read| read.starts_with("lock_args")).cloned().collect::<Vec<_>>();
    dedup(&mut fields);
    fields
}

fn dedup(values: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    values.retain(|value| seen.insert(value.clone()));
}
