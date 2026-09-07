//! ProofPlan soundness checks for v0.16 assurance metadata.

use crate::error::{CompileError, Result};
use crate::{CompileMetadata, EvidenceTier, ProofPlanMetadata, VerifierObligationMetadata};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanSoundnessReport {
    pub status: String,
    pub strict: bool,
    pub checked_records: usize,
    pub checked_obligations: usize,
    pub issue_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issues: Vec<ProofPlanSoundnessIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPlanSoundnessIssue {
    pub severity: String,
    pub code: String,
    pub origin: String,
    pub feature: String,
    pub message: String,
}

pub fn check_metadata(metadata: &CompileMetadata, strict: bool) -> ProofPlanSoundnessReport {
    let mut issues = Vec::new();
    let proof_plan = &metadata.runtime.proof_plan;
    let obligations = &metadata.runtime.verifier_obligations;

    if proof_plan.is_empty() && !obligations.is_empty() {
        push_issue(
            &mut issues,
            "error",
            "PP0001",
            "runtime",
            "*",
            "runtime verifier obligations exist but runtime.proof_plan is empty",
        );
    }

    let mut proof_index = BTreeMap::<String, Vec<&ProofPlanMetadata>>::new();
    for plan in proof_plan {
        proof_index
            .entry(obligation_key(&plan.origin, &plan.category, &plan.feature, &plan.status, &plan.detail))
            .or_default()
            .push(plan);
    }
    for (key, records) in &proof_index {
        if records.len() > 1 {
            push_issue(
                &mut issues,
                "error",
                "PP0003",
                &records[0].origin,
                &records[0].feature,
                &format!("duplicate ProofPlan obligation key {key} appears {} times", records.len()),
            );
        }
    }

    let mut obligation_index = BTreeMap::<String, Vec<&VerifierObligationMetadata>>::new();
    for obligation in obligations {
        obligation_index
            .entry(obligation_key(
                &obligation.scope,
                &obligation.category,
                &obligation.feature,
                &obligation.status,
                &obligation.detail,
            ))
            .or_default()
            .push(obligation);
    }
    for (key, records) in &obligation_index {
        if records.len() > 1 {
            push_issue(
                &mut issues,
                "error",
                "PP0004",
                &records[0].scope,
                &records[0].feature,
                &format!("duplicate runtime verifier obligation key {key} appears {} times", records.len()),
            );
        }
    }

    for obligation in obligations {
        let key = obligation_key(&obligation.scope, &obligation.category, &obligation.feature, &obligation.status, &obligation.detail);
        if !proof_index.contains_key(&key) {
            push_issue(
                &mut issues,
                "error",
                "PP0002",
                &obligation.scope,
                &obligation.feature,
                "runtime verifier obligation has no matching ProofPlan record with the same origin/scope, category, feature, status, and detail",
            );
        }
    }

    check_local_runtime_plan_consistency(metadata, &mut issues);

    for plan in proof_plan {
        check_plan_record(plan, strict, &mut issues);
    }

    let issue_count = issues.len();
    let status = if issues.iter().any(|issue| issue.severity == "error") { "failed" } else { "passed" };

    ProofPlanSoundnessReport {
        status: status.to_string(),
        strict,
        checked_records: proof_plan.len(),
        checked_obligations: obligations.len(),
        issue_count,
        issues,
    }
}

pub fn validate_metadata(metadata: &CompileMetadata, strict: bool) -> Result<()> {
    let report = check_metadata(metadata, strict);
    if report.status == "passed" {
        return Ok(());
    }

    let messages = report
        .issues
        .iter()
        .filter(|issue| issue.severity == "error")
        .map(|issue| format!("{} {}:{} - {}", issue.code, issue.origin, issue.feature, issue.message))
        .collect::<Vec<_>>();
    Err(CompileError::without_span(format!("ProofPlan soundness check failed:\n  - {}", messages.join("\n  - "))))
}

fn check_plan_record(plan: &ProofPlanMetadata, strict: bool, issues: &mut Vec<ProofPlanSoundnessIssue>) {
    if plan.on_chain_checked != plan.evidence_tier.is_checked() {
        push_issue(issues, "error", "PP0005", &plan.origin, &plan.feature, "ProofPlan evidence_tier must agree with on_chain_checked");
    }

    if plan.codegen_coverage_status == "gap:metadata-only" && plan.evidence_tier != EvidenceTier::MetadataOnly {
        push_issue(
            issues,
            "error",
            "PP0006",
            &plan.origin,
            &plan.feature,
            "metadata-only codegen gap must use evidence_tier='metadata-only'",
        );
    }

    if plan.codegen_coverage_status == "gap:runtime-helper-required" && plan.evidence_tier != EvidenceTier::RuntimeHelperRequired {
        push_issue(
            issues,
            "error",
            "PP0007",
            &plan.origin,
            &plan.feature,
            "runtime-helper codegen gap must use evidence_tier='runtime-helper-required'",
        );
    }

    if plan.on_chain_checked && plan.status == "runtime-required" {
        push_issue(
            issues,
            "error",
            "PP0101",
            &plan.origin,
            &plan.feature,
            "ProofPlan marks a runtime-required obligation as on-chain checked",
        );
    }

    if plan.on_chain_checked && plan.codegen_coverage_status != "covered" {
        push_issue(
            issues,
            "error",
            "PP0102",
            &plan.origin,
            &plan.feature,
            "on-chain checked ProofPlan record must have codegen_coverage_status='covered'",
        );
    }

    if matches!(plan.status.as_str(), "checked-runtime" | "checked-static" | "ckb-runtime") && !plan.on_chain_checked {
        push_issue(
            issues,
            "error",
            "PP0103",
            &plan.origin,
            &plan.feature,
            "checked ProofPlan status is not reflected in on_chain_checked",
        );
    }

    if plan.codegen_coverage_status.starts_with("gap:") && plan.on_chain_checked {
        push_issue(issues, "error", "PP0104", &plan.origin, &plan.feature, "ProofPlan coverage gap cannot be marked on-chain checked");
    }

    if strict
        && (plan.status == "runtime-required"
            || plan.codegen_coverage_status == "gap:metadata-only"
            || plan.evidence_tier == EvidenceTier::MetadataOnly)
    {
        push_issue(
            issues,
            "error",
            "PP0150",
            &plan.origin,
            &plan.feature,
            "strict v0.16 ProofPlan mode rejects metadata-only or runtime-required obligations",
        );
    }

    if !plan.lock_args_fields.is_empty() && !plan.reads.iter().any(|read| read == "lock_args") {
        push_issue(
            issues,
            "error",
            "PP0201",
            &plan.origin,
            &plan.feature,
            "ProofPlan exposes lock_args fields but reads does not include lock_args",
        );
    }

    if !plan.witness_fields.is_empty() && !plan.reads.iter().any(|read| read == "witness") {
        push_issue(
            issues,
            "error",
            "PP0202",
            &plan.origin,
            &plan.feature,
            "ProofPlan exposes witness fields but reads does not include witness",
        );
    }

    for expected_read in expected_reads_for_cell_access(plan) {
        if !plan.reads.iter().any(|read| read == expected_read) {
            push_issue(
                issues,
                "error",
                "PP0212",
                &plan.origin,
                &plan.feature,
                &format!("cell-access ProofPlan source requires reads to include '{expected_read}'"),
            );
        }
    }

    if plan.trigger.trim().is_empty() {
        push_issue(issues, "error", "PP0203", &plan.origin, &plan.feature, "ProofPlan trigger must not be empty");
    }

    if plan.scope.trim().is_empty() {
        push_issue(issues, "error", "PP0204", &plan.origin, &plan.feature, "ProofPlan scope must not be empty");
    }

    if plan.group_cardinality.trim().is_empty() {
        push_issue(issues, "error", "PP0205", &plan.origin, &plan.feature, "ProofPlan group_cardinality must not be empty");
    }

    if plan.on_chain_checked && plan.reads.is_empty() && proof_plan_requires_concrete_reads(plan) {
        push_issue(
            issues,
            "error",
            "PP0206",
            &plan.origin,
            &plan.feature,
            "on-chain checked ProofPlan record must declare concrete reads",
        );
    }

    if plan.on_chain_checked && plan.coverage.is_empty() {
        push_issue(
            issues,
            "error",
            "PP0207",
            &plan.origin,
            &plan.feature,
            "on-chain checked ProofPlan record must declare coverage evidence",
        );
    }

    if plan.on_chain_checked && plan.on_chain_checked_obligations.is_empty() {
        push_issue(
            issues,
            "error",
            "PP0208",
            &plan.origin,
            &plan.feature,
            "on-chain checked ProofPlan record must list checked obligation labels",
        );
    }

    let expected_obligation_label = format!("{}:{}={}", plan.category, plan.feature, plan.status);
    if plan.on_chain_checked && !plan.on_chain_checked_obligations.iter().any(|label| label == &expected_obligation_label) {
        push_issue(
            issues,
            "error",
            "PP0209",
            &plan.origin,
            &plan.feature,
            "on-chain checked ProofPlan record is missing its category:feature=status obligation label",
        );
    }

    if strict && plan.origin.starts_with("invariant:") && plan.source_span.is_none() {
        push_issue(
            issues,
            "error",
            "PP0210",
            &plan.origin,
            &plan.feature,
            "source-declared invariant ProofPlan records must carry a source span in strict mode",
        );
    }

    if let Some(span) = &plan.source_span
        && (span.end <= span.start || span.line == 0)
    {
        push_issue(
            issues,
            "error",
            "PP0211",
            &plan.origin,
            &plan.feature,
            "ProofPlan source span must have end > start and a one-based line",
        );
    }

    if plan.on_chain_checked
        && plan
            .builder_assumptions
            .iter()
            .any(|assumption| assumption.contains("runtime-required") || assumption.contains("metadata-only"))
    {
        push_issue(
            issues,
            "error",
            "PP0301",
            &plan.origin,
            &plan.feature,
            "on-chain checked ProofPlan record carries unchecked runtime/metadata-only builder assumptions",
        );
    }
}

fn check_local_runtime_plan_consistency(metadata: &CompileMetadata, issues: &mut Vec<ProofPlanSoundnessIssue>) {
    let mut runtime_by_identity = BTreeMap::<String, Vec<&ProofPlanMetadata>>::new();
    for plan in &metadata.runtime.proof_plan {
        runtime_by_identity.entry(plan_identity_key(plan)).or_default().push(plan);
    }
    let runtime_identities = runtime_by_identity.keys().cloned().collect::<BTreeSet<_>>();
    let runtime_full = metadata.runtime.proof_plan.iter().map(plan_full_key).collect::<BTreeSet<_>>();

    let mut local_by_identity = BTreeMap::<String, Vec<&ProofPlanMetadata>>::new();

    for action in &metadata.actions {
        for plan in &action.proof_plan {
            local_by_identity.entry(plan_identity_key(plan)).or_default().push(plan);
        }
    }
    for function in &metadata.functions {
        for plan in &function.proof_plan {
            local_by_identity.entry(plan_identity_key(plan)).or_default().push(plan);
        }
    }
    for lock in &metadata.locks {
        for plan in &lock.proof_plan {
            local_by_identity.entry(plan_identity_key(plan)).or_default().push(plan);
        }
    }
    let local_identities = local_by_identity.keys().cloned().collect::<BTreeSet<_>>();
    let local_full = local_by_identity.values().flat_map(|plans| plans.iter().copied()).map(plan_full_key).collect::<BTreeSet<_>>();

    for key in &local_identities {
        if !runtime_identities.contains(key) {
            let (origin, feature, status) = split_plan_identity_key(key);
            push_issue(
                issues,
                "error",
                "PP0401",
                origin,
                feature,
                &format!("local ProofPlan record with status '{}' is missing from runtime.proof_plan", status),
            );
        } else if let Some(plans) = local_by_identity.get(key) {
            for plan in plans {
                if !runtime_full.contains(&plan_full_key(plan)) {
                    push_issue(
                        issues,
                        "error",
                        "PP0403",
                        &plan.origin,
                        &plan.feature,
                        "local ProofPlan record differs from runtime.proof_plan in trigger, scope, reads, coverage, assumptions, detail, or codegen coverage",
                    );
                }
            }
        }
    }

    for key in runtime_identities {
        let (origin, feature, status) = split_plan_identity_key(&key);
        if origin.starts_with("invariant:") || origin.starts_with("validity:") {
            continue;
        }
        if !local_identities.contains(&key) {
            push_issue(
                issues,
                "error",
                "PP0402",
                origin,
                feature,
                &format!("runtime ProofPlan record with status '{}' is missing from local action/function/lock metadata", status),
            );
        } else if let Some(plans) = runtime_by_identity.get(&key) {
            for plan in plans {
                if !local_full.contains(&plan_full_key(plan)) {
                    push_issue(
                        issues,
                        "error",
                        "PP0404",
                        &plan.origin,
                        &plan.feature,
                        "runtime ProofPlan record differs from local action/function/lock metadata in trigger, scope, reads, coverage, assumptions, detail, or codegen coverage",
                    );
                }
            }
        }
    }
}

fn obligation_key(origin: &str, category: &str, feature: &str, status: &str, detail: &str) -> String {
    format!("{origin}\u{1f}{category}\u{1f}{feature}\u{1f}{status}\u{1f}{detail}")
}

fn plan_identity_key(plan: &ProofPlanMetadata) -> String {
    format!("{}\u{1f}{}\u{1f}{}", plan.origin, plan.feature, plan.status)
}

fn split_plan_identity_key(key: &str) -> (&str, &str, &str) {
    let mut parts = key.split('\u{1f}');
    (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""))
}

fn plan_full_key(plan: &ProofPlanMetadata) -> String {
    serde_json::to_string(plan).unwrap_or_else(|_| format!("{plan:?}"))
}

fn proof_plan_requires_concrete_reads(plan: &ProofPlanMetadata) -> bool {
    if plan.category == "cell-access" {
        return plan.feature.split(':').nth(1).and_then(|source| source.split('#').next()).is_some_and(|source| {
            matches!(
                source,
                "Input"
                    | "Output"
                    | "CellDep"
                    | "HeaderDep"
                    | "GroupInput"
                    | "GroupOutput"
                    | "GroupInput/GroupOutput"
                    | "CurrentScript/Input/GroupInput/GroupOutput"
                    | "Input/Output"
                    | "Input/HeaderDep"
                    | "SourceView"
                    | "Transaction"
            )
        });
    }
    if matches!(plan.category.as_str(), "transaction-invariant" | "output-verification") {
        return true;
    }
    let text = format!("{} {} {}", plan.category, plan.feature, plan.detail).to_ascii_lowercase();
    ["input", "output", "cell", "header", "witness", "lock_args", "group", "capacity", "type_id", "type-id"]
        .iter()
        .any(|needle| text.contains(needle))
}

fn expected_reads_for_cell_access(plan: &ProofPlanMetadata) -> &'static [&'static str] {
    if plan.category != "cell-access" {
        return &[];
    }
    let Some(source) = plan.feature.split(':').nth(1).and_then(|source| source.split('#').next()) else {
        return &[];
    };
    match source {
        "Transaction" => &["transaction"],
        "Input" => &["input"],
        "Output" => &["output"],
        "GroupInput" => &["group_input"],
        "GroupOutput" => &["group_output"],
        "GroupInput/GroupOutput" => &["group_input", "group_output"],
        "Input/Output" => &["input", "output", "source_view"],
        "Input/HeaderDep" => &["input", "header_dep"],
        "CellDep" => &["cell_dep"],
        "HeaderDep" => &["header_dep"],
        "Witness" => &["witness"],
        "ScriptArgs" => &["lock_args"],
        "SourceView" => &["source_view"],
        _ => &[],
    }
}

fn push_issue(issues: &mut Vec<ProofPlanSoundnessIssue>, severity: &str, code: &str, origin: &str, feature: &str, message: &str) {
    issues.push(ProofPlanSoundnessIssue {
        severity: severity.to_string(),
        code: code.to_string(),
        origin: origin.to_string(),
        feature: feature.to_string(),
        message: message.to_string(),
    });
}
