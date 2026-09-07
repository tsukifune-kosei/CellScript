//! Builder assumption schema and transaction-shape validation for v0.16.

use crate::{ckb_blake2b256, hex_encode, CompileMetadata, EvidenceTier, ParamMetadata, ProofPlanMetadata};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuilderAssumptionMetadata {
    pub assumption_id: String,
    pub kind: String,
    pub origin: String,
    pub feature: String,
    pub proof_plan_status: String,
    pub required_inputs: Vec<String>,
    pub required_outputs: Vec<String>,
    pub required_cell_deps: Vec<String>,
    pub required_witness_fields: Vec<String>,
    pub capacity_policy: String,
    pub fee_policy: String,
    pub change_policy: String,
    pub signature_policy: String,
    pub failure_mode: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxValidationReport {
    pub status: String,
    pub assumption_count: usize,
    pub checked_assumptions: Vec<String>,
    pub input_count: usize,
    pub output_count: usize,
    pub cell_dep_count: usize,
    pub witness_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<TxValidationViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxValidationViolation {
    pub assumption_id: String,
    pub kind: String,
    pub message: String,
}

enum EvidenceValidation {
    Valid,
    Missing,
    Invalid(String),
}

pub fn builder_assumptions_from_metadata(metadata: &CompileMetadata) -> Vec<BuilderAssumptionMetadata> {
    let mut assumptions = Vec::new();
    let mut seen = BTreeSet::new();

    for plan in &metadata.runtime.proof_plan {
        for assumption in &plan.builder_assumptions {
            push_assumption(&mut assumptions, &mut seen, plan, classify_plan_assumption(plan, assumption), assumption.clone());
        }

        let local_boundary = format!("{} {}", plan.detail, plan.feature).to_ascii_lowercase();
        if plan.feature.starts_with("create-unique-identity:")
            && (local_boundary.contains("global field uniqueness")
                || local_boundary.contains("script-args")
                || local_boundary.contains("script_args")
                || local_boundary.contains("singleton-type")
                || local_boundary.contains("singleton_type")
                || local_boundary.contains("builder/indexer"))
        {
            push_assumption(
                &mut assumptions,
                &mut seen,
                plan,
                "create_unique_global_uniqueness",
                "builder/indexer must prove chain-wide uniqueness for this create_unique identity policy".to_string(),
            );
        }

        if plan.detail.to_ascii_lowercase().contains("type_id uniqueness remains bound") {
            push_assumption(
                &mut assumptions,
                &mut seen,
                plan,
                "type_id_builder_plan",
                "builder must construct the CKB TYPE_ID output from the declared first-input/output-index rule".to_string(),
            );
        }
    }

    if metadata.constraints.ckb.as_ref().is_some_and(|ckb| ckb.capacity_planning_required) {
        let detail = "builder must satisfy occupied-capacity and transaction-size limits for created or mutated outputs";
        let synthetic = ProofPlanMetadata {
            name: "ckb_capacity_planning".to_string(),
            origin: "constraints.ckb".to_string(),
            category: "builder-assumption".to_string(),
            feature: "capacity-planning".to_string(),
            evidence_tier: EvidenceTier::ChainEvidenceRequired,
            source_span: None,
            trigger: "builder".to_string(),
            scope: "transaction".to_string(),
            reads: vec!["output".to_string()],
            coverage: Vec::new(),
            input_output_relation_checks: Vec::new(),
            group_cardinality: "not a script-group cardinality obligation".to_string(),
            identity_lifecycle_policy: "none".to_string(),
            preserved_fields: Vec::new(),
            witness_fields: Vec::new(),
            lock_args_fields: Vec::new(),
            on_chain_checked: false,
            on_chain_checked_obligations: Vec::new(),
            builder_assumptions: vec![detail.to_string()],
            codegen_coverage_status: "builder-required".to_string(),
            status: "builder-required".to_string(),
            detail: detail.to_string(),
            diagnostics: Vec::new(),
        };
        push_assumption(&mut assumptions, &mut seen, &synthetic, "capacity_policy", detail.to_string());
    }

    assumptions
}

pub fn validate_transaction_against_metadata(metadata: &CompileMetadata, tx: &Value) -> TxValidationReport {
    let assumptions = if metadata.runtime.builder_assumptions.is_empty() {
        builder_assumptions_from_metadata(metadata)
    } else {
        metadata.runtime.builder_assumptions.clone()
    };
    let mut report = validate_transaction_against_assumptions(&assumptions, tx);
    validate_exact_handle_parameter_bindings(metadata, tx, &assumptions, &mut report.violations);
    report.status = if report.violations.is_empty() { "ok".to_string() } else { "failed".to_string() };
    report
}

pub fn validate_transaction_against_assumptions(assumptions: &[BuilderAssumptionMetadata], tx: &Value) -> TxValidationReport {
    let input_count = json_array_len(tx, "inputs");
    let output_count = json_array_len(tx, "outputs");
    let cell_dep_count = json_array_len(tx, "cell_deps");
    let witness_count = json_array_len(tx, "witnesses");
    let mut violations = Vec::new();
    let mut checked_assumptions = Vec::new();

    for assumption in assumptions {
        checked_assumptions.push(assumption.assumption_id.clone());
        if !assumption.required_inputs.is_empty() && input_count == 0 {
            push_violation(&mut violations, assumption, "transaction has no inputs required by this assumption");
        }
        if !assumption.required_outputs.is_empty() && output_count == 0 {
            push_violation(&mut violations, assumption, "transaction has no outputs required by this assumption");
        }
        if !assumption.required_cell_deps.is_empty() && cell_dep_count == 0 {
            push_violation(&mut violations, assumption, "transaction has no cell_deps required by this assumption");
        }
        if !assumption.required_witness_fields.is_empty() && witness_count == 0 {
            push_violation(&mut violations, assumption, "transaction has no witnesses required by this assumption");
        }
        if requires_explicit_evidence(&assumption.kind) {
            match validate_assumption_evidence(tx, assumption) {
                EvidenceValidation::Valid => {}
                EvidenceValidation::Missing => {
                    push_violation(
                        &mut violations,
                        assumption,
                        "missing builder_assumption_evidence entry for this non-structural assumption",
                    );
                }
                EvidenceValidation::Invalid(message) => push_violation(&mut violations, assumption, &message),
            }
        }
    }

    let status = if violations.is_empty() { "ok" } else { "failed" };
    TxValidationReport {
        status: status.to_string(),
        assumption_count: assumptions.len(),
        checked_assumptions,
        input_count,
        output_count,
        cell_dep_count,
        witness_count,
        violations,
    }
}

fn push_assumption(
    assumptions: &mut Vec<BuilderAssumptionMetadata>,
    seen: &mut BTreeSet<String>,
    plan: &ProofPlanMetadata,
    kind: &str,
    detail: String,
) {
    let assumption_id = assumption_id(plan, kind, &detail);
    if !seen.insert(assumption_id.clone()) {
        return;
    }
    assumptions.push(BuilderAssumptionMetadata {
        assumption_id,
        kind: kind.to_string(),
        origin: plan.origin.clone(),
        feature: plan.feature.clone(),
        proof_plan_status: plan.status.clone(),
        required_inputs: required_reads(plan, &["input", "group_input"]),
        required_outputs: required_reads(plan, &["output", "group_output"]),
        required_cell_deps: required_reads(plan, &["cell_dep"]),
        required_witness_fields: plan.witness_fields.clone(),
        capacity_policy: if plan.reads.iter().any(|read| read == "output" || read == "group_output") {
            "occupied-capacity-and-tx-size-evidence-required".to_string()
        } else {
            "none".to_string()
        },
        fee_policy: "builder-balances-fee-before-signing".to_string(),
        change_policy: "change-outputs-must-not-violate-proof-plan-shape".to_string(),
        signature_policy: if plan.reads.iter().any(|read| read == "witness" || read == "lock_args") {
            "signature-material-explicit-no-implicit-signer-authority".to_string()
        } else {
            "none".to_string()
        },
        failure_mode: "reject-before-signing".to_string(),
        detail,
    });
}

fn classify_plan_assumption(plan: &ProofPlanMetadata, assumption: &str) -> &'static str {
    let text = format!("{} {} {}", plan.feature, plan.detail, assumption).to_ascii_lowercase();
    if plan.category == "exact-script-handle" {
        "exact_script_handle"
    } else if text.contains("lock transaction scan") || text.contains("only protects the lock group") {
        "lock_group_transaction_scope"
    } else if text.contains("runtime-required") {
        "runtime_required_proof_plan"
    } else if text.contains("metadata-only") {
        "metadata_only_gap"
    } else if text.contains("type_id") || text.contains("type-id") {
        "type_id_builder_plan"
    } else if text.contains("global") || text.contains("builder/indexer") {
        "create_unique_global_uniqueness"
    } else {
        "builder_evidence"
    }
}

fn assumption_id(plan: &ProofPlanMetadata, kind: &str, detail: &str) -> String {
    let material = format!("{}|{}|{}|{}|{}", plan.origin, plan.feature, plan.status, kind, detail);
    let hash = hex_encode(&ckb_blake2b256(material.as_bytes()));
    format!("ba-{}", &hash[..16])
}

fn required_reads(plan: &ProofPlanMetadata, reads: &[&str]) -> Vec<String> {
    reads.iter().filter(|read| plan.reads.iter().any(|actual| actual == **read)).map(|read| format!("{}:*", read)).collect()
}

fn json_array_len(tx: &Value, key: &str) -> usize {
    tx.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

fn validate_assumption_evidence(tx: &Value, assumption: &BuilderAssumptionMetadata) -> EvidenceValidation {
    let mut invalid = None;
    for key in ["builder_assumption_evidence", "builder_assumptions"] {
        let Some(value) = tx.get(key) else { continue };
        match value {
            Value::Array(items) => {
                for item in items {
                    match validate_evidence_item(item, None, assumption, tx) {
                        EvidenceValidation::Valid => return EvidenceValidation::Valid,
                        EvidenceValidation::Missing => {}
                        EvidenceValidation::Invalid(message) => {
                            invalid.get_or_insert(message);
                        }
                    }
                }
            }
            Value::Object(object) => {
                if let Some(value) = object.get(&assumption.assumption_id) {
                    match validate_evidence_item(value, Some(&assumption.assumption_id), assumption, tx) {
                        EvidenceValidation::Valid => return EvidenceValidation::Valid,
                        EvidenceValidation::Missing => {}
                        EvidenceValidation::Invalid(message) => {
                            invalid.get_or_insert(message);
                        }
                    }
                }
                match validate_evidence_item(value, None, assumption, tx) {
                    EvidenceValidation::Valid => return EvidenceValidation::Valid,
                    EvidenceValidation::Missing => {}
                    EvidenceValidation::Invalid(message) => {
                        invalid.get_or_insert(message);
                    }
                }
            }
            _ => {}
        }
    }
    invalid.map(EvidenceValidation::Invalid).unwrap_or(EvidenceValidation::Missing)
}

fn validate_evidence_item(
    item: &Value,
    map_key: Option<&str>,
    assumption: &BuilderAssumptionMetadata,
    tx: &Value,
) -> EvidenceValidation {
    match item {
        Value::String(id) if id == &assumption.assumption_id => EvidenceValidation::Invalid(
            "builder_assumption_evidence must be an object with assumption_id, kind, origin, feature, proof_plan_status, and evidence payload"
                .to_string(),
        ),
        Value::Object(object) => validate_evidence_object(object, map_key, assumption, tx),
        Value::Bool(true) if map_key == Some(assumption.assumption_id.as_str()) => EvidenceValidation::Invalid(
            "builder_assumption_evidence map values must be evidence objects, not booleans".to_string(),
        ),
        _ => EvidenceValidation::Missing,
    }
}

fn validate_evidence_object(
    object: &serde_json::Map<String, Value>,
    map_key: Option<&str>,
    assumption: &BuilderAssumptionMetadata,
    tx: &Value,
) -> EvidenceValidation {
    let id = object.get("assumption_id").and_then(Value::as_str).or(map_key);
    let Some(id) = id else {
        return EvidenceValidation::Missing;
    };
    if id != assumption.assumption_id {
        return if map_key == Some(assumption.assumption_id.as_str()) {
            EvidenceValidation::Invalid("builder_assumption_evidence object assumption_id does not match its map key".to_string())
        } else {
            EvidenceValidation::Missing
        };
    }

    let mut mismatches = Vec::new();
    push_evidence_mismatch(&mut mismatches, object, "kind", &assumption.kind);
    push_evidence_mismatch(&mut mismatches, object, "origin", &assumption.origin);
    push_evidence_mismatch(&mut mismatches, object, "feature", &assumption.feature);

    let status = object.get("proof_plan_status").or_else(|| object.get("status")).and_then(Value::as_str).unwrap_or("");
    if status != assumption.proof_plan_status {
        mismatches
            .push(format!("proof_plan_status must be '{}' for assumption {}", assumption.proof_plan_status, assumption.assumption_id));
    }

    let payload = object.get("evidence").or_else(|| object.get("payload"));
    if !payload.is_some_and(non_empty_evidence_payload) {
        mismatches
            .push(format!("builder_assumption_evidence for {} must include non-empty evidence or payload", assumption.assumption_id));
    } else if let Some(payload) = payload {
        validate_evidence_payload_shape(&mut mismatches, payload, assumption, tx);
    }

    if mismatches.is_empty() {
        EvidenceValidation::Valid
    } else {
        EvidenceValidation::Invalid(mismatches.join("; "))
    }
}

fn validate_evidence_payload_shape(mismatches: &mut Vec<String>, payload: &Value, assumption: &BuilderAssumptionMetadata, tx: &Value) {
    let Some(object) = payload.as_object() else {
        mismatches.push("evidence payload must be an object with concrete transaction evidence".to_string());
        return;
    };

    if assumption.kind == "exact_script_handle" {
        validate_exact_handle_evidence(mismatches, object, assumption, tx);
        return;
    }

    if !assumption.required_inputs.is_empty() {
        require_payload_array(
            mismatches,
            object,
            &["inputs", "input_cells", "required_inputs"],
            "input evidence for required input or group_input reads",
        );
        validate_payload_array_items(
            mismatches,
            object,
            &["inputs", "input_cells", "required_inputs"],
            "inputs",
            tx,
            "input evidence",
            &["index", "out_point", "type_hash", "lock_hash", "capacity"],
            None,
        );
    }
    if !assumption.required_outputs.is_empty() {
        require_payload_array(
            mismatches,
            object,
            &["outputs", "output_cells", "required_outputs"],
            "output evidence for required output or group_output reads",
        );
        validate_payload_array_items(
            mismatches,
            object,
            &["outputs", "output_cells", "required_outputs"],
            "outputs",
            tx,
            "output evidence",
            &["index", "type_hash", "lock_hash", "capacity", "data"],
            None,
        );
    }
    if !assumption.required_cell_deps.is_empty() {
        require_payload_array(
            mismatches,
            object,
            &["cell_deps", "required_cell_deps"],
            "cell_dep evidence for required cell dependency reads",
        );
        validate_payload_array_items(
            mismatches,
            object,
            &["cell_deps", "required_cell_deps"],
            "cell_deps",
            tx,
            "cell_dep evidence",
            &["index", "name", "out_point", "code_hash", "tx_hash", "dep_type"],
            None,
        );
    }
    if !assumption.required_witness_fields.is_empty() {
        require_payload_array(
            mismatches,
            object,
            &["witnesses", "witness_fields", "required_witness_fields"],
            "witness evidence for required witness fields",
        );
        validate_payload_array_items(
            mismatches,
            object,
            &["witnesses", "witness_fields", "required_witness_fields"],
            "witnesses",
            tx,
            "witness evidence",
            &["index", "field", "lock", "input_type", "output_type", "bytes"],
            Some("field"),
        );
    }

    if assumption.kind == "capacity_policy" || assumption.capacity_policy != "none" {
        require_payload_u64(mismatches, object, "occupied_capacity_shannons");
        require_payload_u64(mismatches, object, "tx_size_bytes");
        require_payload_array_present(mismatches, object, &["under_capacity_output_indexes"], "under-capacity output index evidence");
        if let Some(indexes) = object.get("under_capacity_output_indexes").and_then(Value::as_array) {
            if !indexes.is_empty() {
                mismatches.push("capacity evidence reports under-capacity outputs; transaction is not valid".to_string());
            }
            validate_index_values(mismatches, indexes, json_array_len(tx, "outputs"), "under_capacity_output_indexes");
        }
    }

    if assumption.kind == "type_id_builder_plan" {
        let has_type_id_object = object.get("type_id").is_some_and(|value| value.as_object().is_some_and(|object| !object.is_empty()));
        let has_flat_fields = object.get("first_input_out_point").is_some()
            && object.get("output_index").and_then(Value::as_u64).is_some()
            && object.get("expected_type_id_args").and_then(Value::as_str).is_some_and(|value| !value.is_empty());
        if !has_type_id_object && !has_flat_fields {
            mismatches.push(
                "type_id_builder_plan evidence must include type_id object or first_input_out_point/output_index/expected_type_id_args"
                    .to_string(),
            );
        }
        if let Some(type_id) = object.get("type_id").and_then(Value::as_object) {
            validate_type_id_evidence(mismatches, type_id, tx);
        } else {
            validate_flat_type_id_evidence(mismatches, object, tx);
        }
    }

    if assumption.kind == "create_unique_global_uniqueness" {
        let checked = object.get("uniqueness_checked").and_then(Value::as_bool) == Some(true);
        let proof = object.get("uniqueness_proof").or_else(|| object.get("unique_cell")).is_some_and(non_empty_evidence_payload);
        if !checked && !proof {
            mismatches.push(
                "create_unique_global_uniqueness evidence must include uniqueness_checked=true or uniqueness_proof/unique_cell payload"
                    .to_string(),
            );
        }
    }

    if assumption.kind == "lock_group_transaction_scope" {
        let reviewed = object.get("transaction_scope_reviewed").and_then(Value::as_bool) == Some(true);
        let groups = object.get("covered_lock_groups").is_some_and(non_empty_evidence_payload);
        if !reviewed && !groups {
            mismatches.push(
                "lock_group_transaction_scope evidence must include transaction_scope_reviewed=true or covered_lock_groups"
                    .to_string(),
            );
        }
    }

    if matches!(assumption.kind.as_str(), "metadata_only_gap" | "runtime_required_proof_plan") {
        let manual_review = object.get("manual_review").is_some_and(non_empty_evidence_payload);
        let checked = object.get("checked").and_then(Value::as_bool) == Some(true);
        if !manual_review && !checked {
            mismatches.push("metadata/runtime ProofPlan gap evidence must include manual_review payload or checked=true".to_string());
        }
    }
}

fn validate_exact_handle_evidence(
    mismatches: &mut Vec<String>,
    object: &serde_json::Map<String, Value>,
    assumption: &BuilderAssumptionMetadata,
    tx: &Value,
) {
    let Some((role, expected_hash)) = exact_handle_feature(&assumption.feature) else {
        mismatches.push("exact_script_handle feature must be <lock|type|spawned-verifier>:<64 lowercase hex handle hash>".to_string());
        return;
    };
    let handle = match object.get("handle").and_then(Value::as_str) {
        Some(value) => match canonical_lower_hex_bytes(value, crate::script_handle_contract::EXACT_SCRIPT_HANDLE_BYTES) {
            Ok(bytes) => Some(bytes),
            Err(message) => {
                mismatches.push(format!("exact handle evidence {message}"));
                None
            }
        },
        None => {
            mismatches.push("exact_script_handle evidence must include canonical handle bytes".to_string());
            None
        }
    };

    if let Some(handle) = handle.as_deref() {
        validate_exact_handle_value(mismatches, handle, role, expected_hash);
    }

    let expected_source = exact_handle_expected_source(assumption);
    let source = object.get("source").and_then(Value::as_object);
    match source {
        Some(source) => validate_exact_handle_source(mismatches, source, expected_source, role, handle.as_deref(), tx),
        None => mismatches.push(
            "exact_script_handle evidence must include source { location: input|output|cell_dep, index: <transaction index> }"
                .to_string(),
        ),
    }

    let witness = object.get("witness").and_then(Value::as_object);
    match witness {
        Some(witness) => validate_exact_handle_witness(mismatches, witness, handle.as_deref(), tx),
        None => mismatches
            .push("exact_script_handle evidence must include witness { index: <transaction index>, field: input_type }".to_string()),
    }
}

fn exact_handle_feature(feature: &str) -> Option<(&str, &str)> {
    let (role, handle_hash) = feature.split_once(':')?;
    if !matches!(role, "lock" | "type" | "spawned-verifier") || !canonical_lower_hash(handle_hash) {
        return None;
    }
    Some((role, handle_hash))
}

fn exact_handle_expected_source(assumption: &BuilderAssumptionMetadata) -> Option<&'static str> {
    match (assumption.required_inputs.is_empty(), assumption.required_outputs.is_empty(), assumption.required_cell_deps.is_empty()) {
        (false, true, true) => Some("input"),
        (true, false, true) => Some("output"),
        (true, true, false) => Some("cell_dep"),
        _ => None,
    }
}

fn validate_exact_handle_value(mismatches: &mut Vec<String>, handle: &[u8], role: &str, expected_hash: &str) {
    use crate::script_handle_contract::{
        EXACT_SCRIPT_HANDLE_CLASS_OFFSET, EXACT_SCRIPT_HANDLE_CLASS_SCRIPT, EXACT_SCRIPT_HANDLE_CLASS_VERIFIER,
        EXACT_SCRIPT_HANDLE_MAGIC, EXACT_SCRIPT_HANDLE_ROLE_LOCK, EXACT_SCRIPT_HANDLE_ROLE_OFFSET,
        EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER, EXACT_SCRIPT_HANDLE_ROLE_TYPE,
    };

    if handle.get(..EXACT_SCRIPT_HANDLE_MAGIC.len()) != Some(EXACT_SCRIPT_HANDLE_MAGIC.as_slice()) {
        mismatches.push("exact handle has invalid CSHDLv1 encoding magic".to_string());
    }
    let (expected_class, expected_role) = match role {
        "lock" => (EXACT_SCRIPT_HANDLE_CLASS_SCRIPT, EXACT_SCRIPT_HANDLE_ROLE_LOCK),
        "type" => (EXACT_SCRIPT_HANDLE_CLASS_SCRIPT, EXACT_SCRIPT_HANDLE_ROLE_TYPE),
        "spawned-verifier" => (EXACT_SCRIPT_HANDLE_CLASS_VERIFIER, EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER),
        _ => return,
    };
    if handle.get(EXACT_SCRIPT_HANDLE_CLASS_OFFSET).copied() != Some(expected_class) {
        mismatches.push(format!("exact handle class does not match {role} role"));
    }
    if handle.get(EXACT_SCRIPT_HANDLE_ROLE_OFFSET).copied() != Some(expected_role) {
        mismatches.push(format!("exact handle role tag does not match {role} role"));
    }
    let actual_hash = hex_encode(&ckb_blake2b256(handle));
    if actual_hash != expected_hash {
        mismatches.push("exact handle bytes do not match the compile-time full-handle commitment".to_string());
    }
}

fn validate_exact_handle_source(
    mismatches: &mut Vec<String>,
    source: &serde_json::Map<String, Value>,
    expected_source: Option<&str>,
    role: &str,
    handle: Option<&[u8]>,
    tx: &Value,
) {
    let location = source.get("location").and_then(Value::as_str).unwrap_or("");
    if !matches!(location, "input" | "output" | "cell_dep") {
        mismatches.push("exact handle source.location must be input, output, or cell_dep".to_string());
        return;
    }
    if let Some(expected) = expected_source {
        if location != expected {
            mismatches.push(format!("exact handle source.location must be {expected} for this compiled source view"));
        }
    } else {
        mismatches.push("exact handle metadata does not identify one concrete transaction source kind".to_string());
    }
    if role == "spawned-verifier" && location != "cell_dep" {
        mismatches.push("spawned-verifier exact handles must bind a cell_dep transaction source".to_string());
    }

    let Some(index) = source.get("index").and_then(Value::as_u64) else {
        mismatches.push("exact handle source must include numeric transaction index".to_string());
        return;
    };
    let tx_field = match location {
        "input" => "inputs",
        "output" => "outputs",
        "cell_dep" => "cell_deps",
        _ => return,
    };
    let Some(tx_item) = tx.get(tx_field).and_then(Value::as_array).and_then(|items| items.get(index as usize)) else {
        mismatches.push(format!("exact handle source index {index} is out of range for transaction {tx_field}"));
        return;
    };
    let Some(handle) = handle else {
        return;
    };
    let expected_identity = match exact_handle_identity(handle, role) {
        Ok(identity) => identity,
        Err(message) => {
            mismatches.push(message);
            return;
        }
    };
    match transaction_source_identity(tx_item, role) {
        Ok(actual) if actual == expected_identity => {}
        Ok(_) => mismatches.push(format!("exact handle {role} identity does not match transaction {tx_field}[{index}]")),
        Err(message) => mismatches.push(format!("transaction {tx_field}[{index}] {message}")),
    }
}

fn exact_handle_identity(handle: &[u8], role: &str) -> Result<[u8; 32], String> {
    let offset = match role {
        "lock" | "type" => crate::script_handle_contract::EXACT_SCRIPT_HANDLE_SCRIPT_HASH_OFFSET,
        "spawned-verifier" => crate::script_handle_contract::EXACT_SCRIPT_HANDLE_ARTIFACT_HASH_OFFSET,
        _ => return Err(format!("unsupported exact handle role {role}")),
    };
    handle
        .get(offset..offset + crate::script_handle_contract::EXACT_SCRIPT_HANDLE_HASH_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "exact handle is too short to contain its selected identity".to_string())
}

fn transaction_source_identity(item: &Value, role: &str) -> Result<[u8; 32], String> {
    let cell = resolved_transaction_cell(item);
    match role {
        "lock" | "type" => transaction_script_identity(cell, role),
        "spawned-verifier" => transaction_data_identity(cell),
        _ => Err(format!("has unsupported exact handle role {role}")),
    }
}

fn resolved_transaction_cell(item: &Value) -> &Value {
    for key in ["resolved_cell", "resolved_output", "cell", "output"] {
        if let Some(value) = item.get(key) {
            return value;
        }
    }
    item
}

fn transaction_script_identity(cell: &Value, role: &str) -> Result<[u8; 32], String> {
    let direct_field = if role == "lock" { "lock_hash" } else { "type_hash" };
    let direct = match cell.get(direct_field).and_then(Value::as_str) {
        Some(value) => Some(canonical_lower_hash32(value).map_err(|message| format!("has invalid {direct_field}: {message}"))?),
        None => None,
    };
    let script = if role == "lock" {
        cell.get("lock").or_else(|| cell.get("lock_script"))
    } else {
        cell.get("type").or_else(|| cell.get("type_script"))
    };
    let computed = match script {
        Some(Value::Null) | None => None,
        Some(script) => Some(ckb_script_hash_json(script)?),
    };
    match (direct, computed) {
        (Some(direct), Some(computed)) if direct != computed => {
            Err(format!("has inconsistent {direct_field} and concrete {role} Script"))
        }
        (Some(direct), _) => Ok(direct),
        (_, Some(computed)) => Ok(computed),
        _ => Err(format!("must expose concrete {direct_field} or {role} Script identity")),
    }
}

fn transaction_data_identity(cell: &Value) -> Result<[u8; 32], String> {
    let direct = match cell.get("data_hash").and_then(Value::as_str) {
        Some(value) => Some(canonical_lower_hash32(value).map_err(|message| format!("has invalid data_hash: {message}"))?),
        None => None,
    };
    let computed = match cell.get("data").and_then(Value::as_str) {
        Some(value) => {
            Some(ckb_blake2b256(&canonical_lower_variable_hex(value).map_err(|message| format!("has invalid data: {message}"))?))
        }
        None => None,
    };
    match (direct, computed) {
        (Some(direct), Some(computed)) if direct != computed => Err("has inconsistent data_hash and concrete data bytes".to_string()),
        (Some(direct), _) => Ok(direct),
        (_, Some(computed)) => Ok(computed),
        _ => Err("must expose concrete data_hash or resolved data bytes".to_string()),
    }
}

fn ckb_script_hash_json(script: &Value) -> Result<[u8; 32], String> {
    let Some(script) = script.as_object() else {
        return Err("Script identity must be an object".to_string());
    };
    let code_hash = script
        .get("code_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "Script identity must include code_hash".to_string())
        .and_then(canonical_lower_hash32)?;
    let hash_type = match script.get("hash_type").and_then(Value::as_str) {
        Some("data") => 0u8,
        Some("type") => 1u8,
        Some("data1") => 2u8,
        Some("data2") => 4u8,
        Some(other) => return Err(format!("Script identity has unsupported hash_type {other}")),
        None => return Err("Script identity must include hash_type".to_string()),
    };
    let args = script
        .get("args")
        .and_then(Value::as_str)
        .ok_or_else(|| "Script identity must include args".to_string())
        .and_then(canonical_lower_variable_hex)?;
    let args_field_size = 4usize.checked_add(args.len()).ok_or_else(|| "Script args size overflow".to_string())?;
    let total_size = 49usize.checked_add(args_field_size).ok_or_else(|| "Script serialization size overflow".to_string())?;
    let total_size = u32::try_from(total_size).map_err(|_| "Script serialization exceeds Molecule u32 size".to_string())?;
    let args_count = u32::try_from(args.len()).map_err(|_| "Script args exceed Molecule u32 size".to_string())?;
    let mut bytes = Vec::with_capacity(total_size as usize);
    bytes.extend_from_slice(&total_size.to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&48u32.to_le_bytes());
    bytes.extend_from_slice(&49u32.to_le_bytes());
    bytes.extend_from_slice(&code_hash);
    bytes.push(hash_type);
    bytes.extend_from_slice(&args_count.to_le_bytes());
    bytes.extend_from_slice(&args);
    Ok(ckb_blake2b256(&bytes))
}

fn validate_exact_handle_witness(
    mismatches: &mut Vec<String>,
    witness: &serde_json::Map<String, Value>,
    handle: Option<&[u8]>,
    tx: &Value,
) {
    if witness.get("field").and_then(Value::as_str) != Some("input_type") {
        mismatches.push("exact handle witness.field must be input_type".to_string());
    }
    let Some(index) = witness.get("index").and_then(Value::as_u64) else {
        mismatches.push("exact handle witness must include numeric transaction index".to_string());
        return;
    };
    let input_type = match transaction_witness_input_type(tx, index as usize) {
        Ok(bytes) => bytes,
        Err(message) => {
            mismatches.push(format!("transaction witnesses[{index}] {message}"));
            return;
        }
    };
    if let Some(handle) = handle
        && !input_type.windows(handle.len()).any(|window| window == handle)
    {
        mismatches.push(format!("transaction witnesses[{index}].input_type does not contain the committed exact handle bytes"));
    }
}

fn transaction_witness_input_type(tx: &Value, index: usize) -> Result<Vec<u8>, String> {
    let witness = tx
        .get("witnesses")
        .and_then(Value::as_array)
        .and_then(|items| items.get(index))
        .ok_or_else(|| format!("is out of range for transaction witnesses at index {index}"))?;
    match witness {
        Value::String(raw) => parse_witness_args_input_type(&canonical_lower_variable_hex(raw)?),
        Value::Object(object) => {
            let value = object
                .get("input_type")
                .or_else(|| object.get("input_type_bytes"))
                .and_then(Value::as_str)
                .ok_or_else(|| "must expose canonical input_type bytes".to_string())?;
            canonical_lower_variable_hex(value)
        }
        _ => Err("must be a raw WitnessArgs hex string or an object with input_type bytes".to_string()),
    }
}

fn parse_witness_args_input_type(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() < 16 {
        return Err("raw WitnessArgs is shorter than its 16-byte table header".to_string());
    }
    let word = |offset: usize| -> u32 { u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("bounded u32 slice")) };
    let total = word(0) as usize;
    let lock_offset = word(4) as usize;
    let input_type_offset = word(8) as usize;
    let output_type_offset = word(12) as usize;
    if total != bytes.len()
        || lock_offset != 16
        || !(lock_offset <= input_type_offset && input_type_offset <= output_type_offset && output_type_offset <= total)
    {
        return Err("raw WitnessArgs has invalid Molecule table offsets".to_string());
    }
    if input_type_offset == output_type_offset {
        return Err("raw WitnessArgs has no input_type field".to_string());
    }
    if output_type_offset - input_type_offset < 4 {
        return Err("raw WitnessArgs input_type Bytes is truncated".to_string());
    }
    let length = word(input_type_offset) as usize;
    if length != output_type_offset - input_type_offset - 4 {
        return Err("raw WitnessArgs input_type Bytes length does not match its field span".to_string());
    }
    Ok(bytes[input_type_offset + 4..output_type_offset].to_vec())
}

fn canonical_lower_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_lower_hash32(value: &str) -> Result<[u8; 32], String> {
    let bytes = canonical_lower_hex_bytes(value, 32)?;
    bytes.try_into().map_err(|_| "must contain exactly 32 bytes".to_string())
}

fn canonical_lower_hex_bytes(value: &str, expected_bytes: usize) -> Result<Vec<u8>, String> {
    let bytes = canonical_lower_variable_hex(value)?;
    if bytes.len() != expected_bytes {
        return Err(format!("must contain exactly {expected_bytes} bytes"));
    }
    Ok(bytes)
}

fn canonical_lower_variable_hex(value: &str) -> Result<Vec<u8>, String> {
    let Some(raw) = value.strip_prefix("0x") else {
        return Err("must be 0x-prefixed lowercase hexadecimal".to_string());
    };
    if !raw.len().is_multiple_of(2) || !raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err("must be canonical lowercase hexadecimal".to_string());
    }
    hex::decode(raw).map_err(|error| format!("contains invalid hexadecimal: {error}"))
}

fn validate_exact_handle_parameter_bindings(
    metadata: &CompileMetadata,
    tx: &Value,
    assumptions: &[BuilderAssumptionMetadata],
    violations: &mut Vec<TxValidationViolation>,
) {
    for assumption in assumptions.iter().filter(|assumption| assumption.kind == "exact_script_handle") {
        let Some(payload) = matching_evidence_payload(tx, assumption) else {
            continue;
        };
        let Some(handle_text) = payload.get("handle").and_then(Value::as_str) else {
            continue;
        };
        let Ok(handle) = canonical_lower_hex_bytes(handle_text, crate::script_handle_contract::EXACT_SCRIPT_HANDLE_BYTES) else {
            continue;
        };
        let Some(witness_index) =
            payload.get("witness").and_then(Value::as_object).and_then(|witness| witness.get("index")).and_then(Value::as_u64)
        else {
            continue;
        };
        let Ok(input_type) = transaction_witness_input_type(tx, witness_index as usize) else {
            continue;
        };
        let Some((plan, params)) = exact_handle_plan_and_params(metadata, assumption) else {
            push_violation(violations, assumption, "exact handle ProofPlan cannot be resolved to its compiled action or lock entry");
            continue;
        };
        let Some(parameter) = plan.coverage.iter().find_map(|item| item.strip_prefix("parameter:")) else {
            push_violation(violations, assumption, "exact handle ProofPlan is missing its entry parameter binding");
            continue;
        };
        match entry_payload_parameter(&input_type, params, parameter) {
            Ok(actual) if actual == handle => {}
            Ok(_) => push_violation(
                violations,
                assumption,
                "exact handle evidence does not match the declared parameter position in WitnessArgs.input_type",
            ),
            Err(message) => push_violation(violations, assumption, &message),
        }
    }
}

fn matching_evidence_payload<'a>(tx: &'a Value, assumption: &BuilderAssumptionMetadata) -> Option<&'a serde_json::Map<String, Value>> {
    for key in ["builder_assumption_evidence", "builder_assumptions"] {
        let Some(value) = tx.get(key) else {
            continue;
        };
        match value {
            Value::Object(object) => {
                if let Some(payload) = object
                    .get(&assumption.assumption_id)
                    .and_then(Value::as_object)
                    .and_then(|item| item.get("evidence").or_else(|| item.get("payload")))
                    .and_then(Value::as_object)
                {
                    return Some(payload);
                }
                if object.get("assumption_id").and_then(Value::as_str) == Some(assumption.assumption_id.as_str())
                    && let Some(payload) = object.get("evidence").or_else(|| object.get("payload")).and_then(Value::as_object)
                {
                    return Some(payload);
                }
            }
            Value::Array(items) => {
                if let Some(payload) = items.iter().find_map(|item| {
                    let item = item.as_object()?;
                    (item.get("assumption_id").and_then(Value::as_str) == Some(assumption.assumption_id.as_str()))
                        .then(|| item.get("evidence").or_else(|| item.get("payload")))
                        .flatten()
                        .and_then(Value::as_object)
                }) {
                    return Some(payload);
                }
            }
            _ => {}
        }
    }
    None
}

fn exact_handle_plan_and_params<'a>(
    metadata: &'a CompileMetadata,
    assumption: &BuilderAssumptionMetadata,
) -> Option<(&'a ProofPlanMetadata, &'a [ParamMetadata])> {
    if let Some(origin) = assumption.origin.strip_prefix("action:") {
        let name = origin.split('#').next()?;
        let action = metadata.actions.iter().find(|action| action.name == name)?;
        let plan = action.proof_plan.iter().find(|plan| plan.origin == assumption.origin && plan.feature == assumption.feature)?;
        return Some((plan, &action.params));
    }
    if let Some(origin) = assumption.origin.strip_prefix("lock:") {
        let name = origin.split('#').next()?;
        let lock = metadata.locks.iter().find(|lock| lock.name == name)?;
        let plan = lock.proof_plan.iter().find(|plan| plan.origin == assumption.origin && plan.feature == assumption.feature)?;
        return Some((plan, &lock.params));
    }
    None
}

fn entry_payload_parameter<'a>(payload: &'a [u8], params: &[ParamMetadata], target: &str) -> Result<&'a [u8], String> {
    if !payload.starts_with(crate::ENTRY_WITNESS_ABI_MAGIC) {
        return Err("WitnessArgs.input_type must start with the compiled CSARGv1 entry ABI magic".to_string());
    }
    let mut cursor = crate::ENTRY_WITNESS_ABI_MAGIC.len();
    let mut selected = None;
    for param in params {
        if !param_consumes_entry_payload(param) {
            continue;
        }
        let start = cursor;
        if param.schema_pointer_abi || param.schema_length_abi {
            let length_bytes = payload
                .get(cursor..)
                .and_then(|remaining| remaining.get(..4))
                .ok_or_else(|| format!("WitnessArgs.input_type truncates schema parameter '{}' length", param.name))?;
            let length = u32::from_le_bytes(length_bytes.try_into().expect("bounded u32 slice")) as usize;
            cursor = cursor
                .checked_add(4)
                .and_then(|cursor| cursor.checked_add(length))
                .ok_or_else(|| format!("WitnessArgs.input_type schema parameter '{}' length overflows", param.name))?;
        } else if let Some(width) = param.fixed_byte_len {
            cursor = cursor
                .checked_add(width)
                .ok_or_else(|| format!("WitnessArgs.input_type parameter '{}' length overflows", param.name))?;
        } else if let Some(width) = crate::entry_witness_scalar_param_width(&param.ty) {
            cursor = cursor
                .checked_add(width)
                .ok_or_else(|| format!("WitnessArgs.input_type parameter '{}' length overflows", param.name))?;
        } else {
            return Err(format!("compiled entry parameter '{}' has no deterministic witness width", param.name));
        }
        let bytes = payload
            .get(start..cursor)
            .ok_or_else(|| format!("WitnessArgs.input_type truncates compiled parameter '{}'", param.name))?;
        if param.name == target {
            if param.ty != crate::script_handle_contract::EXACT_SCRIPT_HANDLE_TYPE
                || param.fixed_byte_len != Some(crate::script_handle_contract::EXACT_SCRIPT_HANDLE_BYTES)
            {
                return Err(format!("compiled parameter '{target}' is not a fixed exact Script handle"));
            }
            selected = Some(bytes);
        }
    }
    if cursor != payload.len() {
        return Err("WitnessArgs.input_type has trailing bytes outside the compiled entry ABI".to_string());
    }
    selected.ok_or_else(|| format!("exact handle ProofPlan parameter '{target}' is not present in the compiled entry ABI"))
}

fn param_consumes_entry_payload(param: &ParamMetadata) -> bool {
    !param.lock_args_data_source
        && !param.cell_bound_abi
        && !param.is_ref
        && !param.ty.starts_with('&')
        && param.bounded_runtime_contract.as_deref() != Some(crate::ir::BOUNDED_TYPE_GROUP_INPUTS_V1)
}

fn require_payload_array(mismatches: &mut Vec<String>, object: &serde_json::Map<String, Value>, fields: &[&str], label: &str) {
    if fields.iter().any(|field| object.get(*field).is_some_and(|value| value.as_array().is_some_and(|items| !items.is_empty()))) {
        return;
    }
    mismatches.push(format!("evidence payload must include non-empty {label} ({})", fields.join(" or ")));
}

fn require_payload_array_present(mismatches: &mut Vec<String>, object: &serde_json::Map<String, Value>, fields: &[&str], label: &str) {
    if fields.iter().any(|field| object.get(*field).is_some_and(|value| value.as_array().is_some())) {
        return;
    }
    mismatches.push(format!("evidence payload must include {label} array ({})", fields.join(" or ")));
}

fn require_payload_u64(mismatches: &mut Vec<String>, object: &serde_json::Map<String, Value>, field: &str) {
    match object.get(field).and_then(Value::as_u64) {
        Some(value) if value > 0 => {}
        Some(_) => mismatches.push(format!("evidence payload numeric {field} must be greater than zero")),
        None => mismatches.push(format!("evidence payload must include numeric {field}")),
    }
}

fn validate_payload_array_items(
    mismatches: &mut Vec<String>,
    object: &serde_json::Map<String, Value>,
    fields: &[&str],
    tx_field: &str,
    tx: &Value,
    label: &str,
    concrete_fields: &[&str],
    required_string_field: Option<&str>,
) {
    let Some(items) = fields.iter().find_map(|field| object.get(*field).and_then(Value::as_array)) else {
        return;
    };
    let tx_len = json_array_len(tx, tx_field);
    for (position, item) in items.iter().enumerate() {
        let Some(item_object) = item.as_object() else {
            mismatches.push(format!("{label} item {position} must be an object with concrete transaction fields"));
            continue;
        };
        if !concrete_fields.iter().any(|field| item_object.get(*field).is_some_and(non_empty_evidence_payload)) {
            mismatches.push(format!("{label} item {position} must include one of {}", concrete_fields.join(", ")));
        }
        if let Some(required) = required_string_field
            && item_object.get(required).and_then(Value::as_str).is_none_or(|value| value.is_empty())
        {
            mismatches.push(format!("{label} item {position} must include non-empty {required}"));
        }
        match item_object.get("index").and_then(Value::as_u64) {
            Some(index) => {
                validate_single_index(mismatches, index, tx_len, &format!("{label} index"));
                validate_evidence_item_matches_tx(mismatches, item_object, tx, tx_field, index as usize, label, position);
            }
            None => mismatches.push(format!("{label} item {position} must include numeric index binding to transaction {tx_field}")),
        }
    }
}

fn validate_index_values(mismatches: &mut Vec<String>, indexes: &[Value], tx_len: usize, label: &str) {
    for (position, index) in indexes.iter().enumerate() {
        match index.as_u64() {
            Some(index) => validate_single_index(mismatches, index, tx_len, label),
            None => mismatches.push(format!("{label} entry {position} must be a numeric output index")),
        }
    }
}

fn validate_single_index(mismatches: &mut Vec<String>, index: u64, tx_len: usize, label: &str) {
    if index as usize >= tx_len {
        mismatches.push(format!("{label} {index} is out of range for transaction array length {tx_len}"));
    }
}

fn validate_evidence_item_matches_tx(
    mismatches: &mut Vec<String>,
    evidence: &serde_json::Map<String, Value>,
    tx: &Value,
    tx_field: &str,
    index: usize,
    label: &str,
    position: usize,
) {
    let Some(tx_item) = tx.get(tx_field).and_then(Value::as_array).and_then(|items| items.get(index)) else {
        return;
    };
    let Some(tx_object) = tx_item.as_object() else {
        mismatches.push(format!("transaction {tx_field}[{index}] referenced by {label} item {position} must be an object"));
        return;
    };
    for field in [
        "source",
        "out_point",
        "type_hash",
        "lock_hash",
        "capacity",
        "data",
        "name",
        "dep_type",
        "code_hash",
        "tx_hash",
        "field",
        "lock",
        "input_type",
        "output_type",
        "bytes",
    ] {
        validate_matching_field(mismatches, evidence, tx_object, field, tx_field, index, label, position);
    }
    validate_matching_alias(mismatches, evidence, tx_object, "capacity", "capacity_shannons", tx_field, index, label, position);
}

fn validate_matching_field(
    mismatches: &mut Vec<String>,
    evidence: &serde_json::Map<String, Value>,
    tx_object: &serde_json::Map<String, Value>,
    field: &str,
    tx_field: &str,
    index: usize,
    label: &str,
    position: usize,
) {
    let Some(expected) = evidence.get(field) else {
        return;
    };
    let Some(actual) = tx_object.get(field) else {
        return;
    };
    if expected != actual {
        mismatches.push(format!("{label} item {position} {field} does not match transaction {tx_field}[{index}].{field}"));
    }
}

fn validate_matching_alias(
    mismatches: &mut Vec<String>,
    evidence: &serde_json::Map<String, Value>,
    tx_object: &serde_json::Map<String, Value>,
    evidence_field: &str,
    tx_field_name: &str,
    tx_field: &str,
    index: usize,
    label: &str,
    position: usize,
) {
    let Some(expected) = evidence.get(evidence_field) else {
        return;
    };
    let Some(actual) = tx_object.get(tx_field_name) else {
        return;
    };
    if expected != actual {
        mismatches
            .push(format!("{label} item {position} {evidence_field} does not match transaction {tx_field}[{index}].{tx_field_name}"));
    }
}

fn validate_type_id_evidence(mismatches: &mut Vec<String>, type_id: &serde_json::Map<String, Value>, tx: &Value) {
    if type_id.get("first_input_out_point").and_then(Value::as_str).is_none_or(|value| value.is_empty()) {
        mismatches.push("type_id evidence must include first_input_out_point".to_string());
    }
    match type_id.get("output_index").and_then(Value::as_u64) {
        Some(index) => {
            validate_single_index(mismatches, index, json_array_len(tx, "outputs"), "type_id output_index");
            validate_type_id_matches_output(mismatches, type_id, tx, index as usize);
        }
        None => mismatches.push("type_id evidence must include numeric output_index".to_string()),
    }
    match type_id.get("expected_type_id_args").and_then(Value::as_str) {
        Some(args) if canonical_hex_32(args) => {}
        Some(_) => mismatches.push("type_id expected_type_id_args must be a canonical 0x-prefixed 32-byte hex string".to_string()),
        None => mismatches.push("type_id evidence must include expected_type_id_args".to_string()),
    }
}

fn validate_flat_type_id_evidence(mismatches: &mut Vec<String>, object: &serde_json::Map<String, Value>, tx: &Value) {
    if object.get("first_input_out_point").is_some()
        || object.get("output_index").is_some()
        || object.get("expected_type_id_args").is_some()
    {
        validate_type_id_evidence(mismatches, object, tx);
    }
}

fn validate_type_id_matches_output(
    mismatches: &mut Vec<String>,
    type_id: &serde_json::Map<String, Value>,
    tx: &Value,
    output_index: usize,
) {
    let Some(expected_args) = type_id.get("expected_type_id_args").and_then(Value::as_str) else {
        return;
    };
    let Some(output) = tx.get("outputs").and_then(Value::as_array).and_then(|items| items.get(output_index)) else {
        return;
    };
    let Some(actual_args) = output_type_args(output) else {
        return;
    };
    if actual_args != expected_args {
        mismatches.push(format!("type_id expected_type_id_args does not match transaction outputs[{output_index}] type args"));
    }
}

fn output_type_args(output: &Value) -> Option<&str> {
    output
        .get("type_args")
        .or_else(|| output.get("type").and_then(|ty| ty.get("args")))
        .or_else(|| output.get("type_script").and_then(|ty| ty.get("args")))
        .and_then(Value::as_str)
}

fn canonical_hex_32(value: &str) -> bool {
    value.len() == 66 && value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn push_evidence_mismatch(mismatches: &mut Vec<String>, object: &serde_json::Map<String, Value>, field: &str, expected: &str) {
    match object.get(field).and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        _ => mismatches.push(format!("{field} must be '{expected}'")),
    }
}

fn non_empty_evidence_payload(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
    }
}

fn requires_explicit_evidence(kind: &str) -> bool {
    matches!(
        kind,
        "create_unique_global_uniqueness"
            | "type_id_builder_plan"
            | "metadata_only_gap"
            | "runtime_required_proof_plan"
            | "lock_group_transaction_scope"
            | "capacity_policy"
            | "exact_script_handle"
    )
}

fn push_violation(violations: &mut Vec<TxValidationViolation>, assumption: &BuilderAssumptionMetadata, message: &str) {
    violations.push(TxValidationViolation {
        assumption_id: assumption.assumption_id.clone(),
        kind: assumption.kind.clone(),
        message: message.to_string(),
    });
}
