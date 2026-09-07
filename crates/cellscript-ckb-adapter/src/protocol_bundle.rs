//! Packed CKB transaction materialization for checked ProtocolBundle reports.
//!
//! The compiler owns artifact admission and deterministic conflict checking.
//! This adapter module independently rechecks the resolved bundle hash, turns
//! the concrete portion of its transaction skeleton into Molecule values, and
//! attributes the resulting byte-identical transaction to each selected Script
//! Group. It performs no signing, RPC, or CKB-VM execution.

use anyhow::{bail, Context, Result};
use cellscript_artifact_checker::canonical_hash;
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::EstimateCycles;
use ckb_sdk::core::TransactionBuilder;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

const PROTOCOL_BUNDLE_REPORT_SCHEMA: &str = "cellscript-protocol-bundle-report-v1";
const PROTOCOL_BUNDLE_SCHEMA: &str = "cellscript-protocol-bundle-v1";
const PROTOCOL_BUNDLE_HASH_DOMAIN: &str = "cellscript-protocol-bundle-v1";
const PROTOCOL_BUNDLE_MATERIALIZATION_SCHEMA: &str = "cellscript-protocol-bundle-materialization-v1";
const MAX_PROTOCOL_BUNDLE_REPORT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleIndexBinding {
    pub global_index: u32,
    pub group_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleScriptGroupEvidence {
    pub artifact: String,
    pub entry_kind: String,
    pub entry: String,
    pub script_role: String,
    pub script_hash: String,
    pub direct_script_group: bool,
    pub input_indexes: Vec<ProtocolBundleIndexBinding>,
    pub output_indexes: Vec<ProtocolBundleIndexBinding>,
    pub code_cell_dep_index: u32,
    pub transaction_bytes_hash: String,
    pub execution: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleMaterializationEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub serialized_transaction_hash: String,
    pub serialized_transaction_size_bytes: usize,
    pub input_capacity_shannons: u64,
    pub output_capacity_shannons: u64,
    pub occupied_output_capacity_shannons: u64,
    pub fee_shannons: u64,
    pub capacity_source: &'static str,
    pub transaction_serialization: &'static str,
    pub script_groups: Vec<ProtocolBundleScriptGroupEvidence>,
    pub ckb_vm_execution: &'static str,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleGroupDryRunEvidence {
    pub artifact: String,
    pub script_role: String,
    pub script_hash: String,
    pub transaction_bytes_hash: String,
    pub acceptance: String,
    pub cycles: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleDryRunEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub serialized_transaction_hash: String,
    pub serialized_transaction_size_bytes: usize,
    pub aggregate_cycles: u64,
    pub direct_script_group_count: usize,
    pub groups: Vec<ProtocolBundleGroupDryRunEvidence>,
    pub ckb_vm_execution: &'static str,
    pub cycle_attribution: &'static str,
    pub tx_pool_acceptance: bool,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Deserialize)]
struct ReportWire {
    schema: String,
    status: String,
    bundle_hash: String,
    bundle: Value,
    #[serde(default)]
    conflicts: Vec<Value>,
    evidence: Value,
}

#[derive(Debug, Deserialize)]
struct BundleWire {
    schema: String,
    artifacts: Vec<ArtifactWire>,
    transaction: TransactionWire,
    #[serde(default)]
    roles: Vec<RoleWire>,
}

#[derive(Debug, Deserialize)]
struct ArtifactWire {
    id: String,
    entry: EntryWire,
    script_role: ScriptRoleWire,
    deployment: DeploymentWire,
}

#[derive(Debug, Deserialize)]
struct EntryWire {
    kind: String,
    name: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ScriptRoleWire {
    Lock,
    Type,
    SpawnedVerifier,
}

#[derive(Debug, Deserialize)]
struct DeploymentWire {
    script: ScriptWire,
    code_cell_dep: CellDepWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionWire {
    version: u32,
    inputs: Vec<CellWire>,
    outputs: Vec<CellWire>,
    witnesses: Vec<WitnessWire>,
    cell_deps: Vec<CellDepWire>,
    header_deps: Vec<String>,
    fee_policy_hash: String,
    change_policy_hash: String,
    #[serde(default)]
    builder_assumption_evidence: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CellWire {
    cell_commitment: String,
    capacity: u64,
    lock: ScriptWire,
    #[serde(rename = "type", default)]
    type_script: Option<ScriptWire>,
    #[serde(default)]
    out_point: Option<OutPointWire>,
    #[serde(default)]
    since: Option<u64>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessWire {
    #[serde(default)]
    lock: Option<String>,
    #[serde(default)]
    input_type: Option<String>,
    #[serde(default)]
    output_type: Option<String>,
    #[serde(default)]
    lock_bytes: Option<String>,
    #[serde(default)]
    input_type_bytes: Option<String>,
    #[serde(default)]
    output_type_bytes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptWire {
    code_hash: String,
    hash_type: String,
    args: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutPointWire {
    tx_hash: String,
    index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct CellDepWire {
    out_point: OutPointWire,
    dep_type: String,
}

#[derive(Debug, Deserialize)]
struct RoleWire {
    artifact: String,
    location: CellLocationWire,
    index: u32,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CellLocationWire {
    Input,
    Output,
}

/// Materialize a successful offline ProtocolBundle report into one packed CKB
/// transaction and a serialization evidence record.
///
/// The report must still carry `not-executed` runtime evidence. This function
/// verifies its canonical bundle hash, requires concrete input OutPoints and
/// output data, verifies every supplied witness commitment, preserves the
/// exact dependency/header/witness ordering, and proves that each selected
/// Lock or Type artifact belongs to a concrete Script Group in the transaction.
pub fn materialize_protocol_bundle_report(bytes: &[u8]) -> Result<(TransactionView, ProtocolBundleMaterializationEvidence)> {
    if bytes.len() > MAX_PROTOCOL_BUNDLE_REPORT_BYTES {
        bail!("ProtocolBundle report exceeds {MAX_PROTOCOL_BUNDLE_REPORT_BYTES} bytes");
    }
    let report: ReportWire = serde_json::from_slice(bytes).context("failed to parse ProtocolBundle report")?;
    validate_report_boundary(&report)?;
    let expected_hash = canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &report.bundle)
        .map_err(|error| anyhow::anyhow!("failed to recompute ProtocolBundle hash: {error}"))?;
    if expected_hash != report.bundle_hash {
        bail!("ProtocolBundle report bundle_hash does not match the canonical resolved bundle");
    }

    let bundle: BundleWire = serde_json::from_value(report.bundle).context("failed to parse resolved ProtocolBundle")?;
    if bundle.schema != PROTOCOL_BUNDLE_SCHEMA {
        bail!("unsupported resolved ProtocolBundle schema {}", bundle.schema);
    }
    if bundle.artifacts.len() < 2 {
        bail!("ProtocolBundle materialization requires at least two artifacts");
    }
    validate_evidence_coverage(&report.evidence, &bundle.artifacts)?;
    if bundle.transaction.version != 0 {
        bail!("ProtocolBundle materialization supports only transaction version 0");
    }

    let (tx, capacities) = materialize_transaction(&bundle.transaction)?;
    let packed_transaction = tx.data();
    let serialized = packed_transaction.as_slice();
    let serialized_transaction_hash = hash_hex(serialized);
    let raw_transaction_hash = format!("0x{}", hex::encode(tx.hash().as_slice()));
    let script_groups = resolve_script_groups(&bundle, &serialized_transaction_hash)?;

    Ok((
        tx,
        ProtocolBundleMaterializationEvidence {
            schema: PROTOCOL_BUNDLE_MATERIALIZATION_SCHEMA,
            state: "MaterializedProtocolBundleTx",
            bundle_hash: report.bundle_hash,
            raw_transaction_hash,
            serialized_transaction_hash,
            serialized_transaction_size_bytes: serialized.len(),
            input_capacity_shannons: capacities.input,
            output_capacity_shannons: capacities.output,
            occupied_output_capacity_shannons: capacities.occupied_output,
            fee_shannons: capacities.fee,
            capacity_source: "bundle-skeleton-not-live-resolved",
            transaction_serialization: "verified",
            script_groups,
            ckb_vm_execution: "not-executed",
            chain_evidence: "not-executed",
        },
    ))
}

/// Bind a successful node `estimate_cycles` response to the exact packed
/// transaction and its ProtocolBundle materialization evidence.
///
/// CKB's RPC result proves aggregate execution of all direct Script Groups in
/// the transaction but does not expose per-group cycles. This report therefore
/// records per-artifact acceptance against one byte hash while leaving each
/// group's `cycles` value empty. Spawned-verifier entries remain separately
/// unresolved because transaction-level success does not prove that a
/// particular spawn path executed.
pub fn protocol_bundle_dry_run_evidence(
    tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    estimate: &EstimateCycles,
) -> Result<ProtocolBundleDryRunEvidence> {
    let packed_transaction = tx.data();
    let serialized = packed_transaction.as_slice();
    let serialized_hash = hash_hex(serialized);
    let raw_hash = format!("0x{}", hex::encode(tx.hash().as_slice()));
    if serialized_hash != materialization.serialized_transaction_hash
        || raw_hash != materialization.raw_transaction_hash
        || serialized.len() != materialization.serialized_transaction_size_bytes
    {
        bail!("ProtocolBundle dry-run transaction does not match materialization evidence");
    }
    if materialization.transaction_serialization != "verified" {
        bail!("ProtocolBundle transaction serialization is not verified");
    }
    let mut groups = Vec::with_capacity(materialization.script_groups.len());
    let mut direct_script_group_count = 0usize;
    for group in &materialization.script_groups {
        if group.transaction_bytes_hash != serialized_hash {
            bail!("ProtocolBundle Script Group '{}' is bound to another transaction byte hash", group.artifact);
        }
        let acceptance = if group.direct_script_group {
            direct_script_group_count += 1;
            "accepted-by-aggregate-estimate-cycles"
        } else {
            "not-independently-observed"
        };
        groups.push(ProtocolBundleGroupDryRunEvidence {
            artifact: group.artifact.clone(),
            script_role: group.script_role.clone(),
            script_hash: group.script_hash.clone(),
            transaction_bytes_hash: serialized_hash.clone(),
            acceptance: acceptance.to_string(),
            cycles: None,
        });
    }
    if direct_script_group_count == 0 {
        bail!("ProtocolBundle dry-run evidence contains no direct Script Group");
    }
    Ok(ProtocolBundleDryRunEvidence {
        schema: "cellscript-protocol-bundle-dry-run-v1",
        state: "DryRunProtocolBundleTx",
        bundle_hash: materialization.bundle_hash.clone(),
        raw_transaction_hash: raw_hash,
        serialized_transaction_hash: serialized_hash,
        serialized_transaction_size_bytes: serialized.len(),
        aggregate_cycles: estimate.cycles.value(),
        direct_script_group_count,
        groups,
        ckb_vm_execution: "verified-aggregate",
        cycle_attribution: "aggregate-only-rpc-does-not-report-per-group-cycles",
        tx_pool_acceptance: false,
        chain_evidence: "node-dry-run-uncommitted",
    })
}

fn validate_report_boundary(report: &ReportWire) -> Result<()> {
    if report.schema != PROTOCOL_BUNDLE_REPORT_SCHEMA {
        bail!("unsupported ProtocolBundle report schema {}", report.schema);
    }
    if report.status != "ok" || !report.conflicts.is_empty() {
        bail!("ProtocolBundle must pass offline conflict checking before materialization");
    }
    if report.evidence.get("structural_verification").and_then(Value::as_str) != Some("verified") {
        bail!("ProtocolBundle structural verification is not verified");
    }
    if report.evidence.get("transaction_serialization").and_then(Value::as_str) != Some("not-executed") {
        bail!("ProtocolBundle report is not at the offline pre-materialization boundary");
    }
    let validations = report
        .evidence
        .get("metadata_transaction_validation")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("ProtocolBundle report is missing per-artifact metadata transaction validation"))?;
    if validations.is_empty() || validations.values().any(|validation| validation.get("status").and_then(Value::as_str) != Some("ok"))
    {
        bail!("ProtocolBundle contains a failed or missing metadata transaction validation");
    }
    Ok(())
}

fn validate_evidence_coverage(evidence: &Value, artifacts: &[ArtifactWire]) -> Result<()> {
    let artifact_ids = artifacts.iter().map(|artifact| artifact.id.as_str()).collect::<HashSet<_>>();
    if artifact_ids.len() != artifacts.len() {
        bail!("resolved ProtocolBundle contains duplicate artifact identities");
    }
    let admissions = evidence
        .get("artifact_admission")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("ProtocolBundle report is missing artifact admission evidence"))?;
    let validations = evidence
        .get("metadata_transaction_validation")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("ProtocolBundle report is missing metadata transaction validation evidence"))?;
    if admissions.len() != artifacts.len() || validations.len() != artifacts.len() {
        bail!("ProtocolBundle evidence does not cover every selected artifact exactly once");
    }
    for artifact in artifacts {
        let admission = admissions
            .get(&artifact.id)
            .ok_or_else(|| anyhow::anyhow!("artifact '{}' is missing standalone admission evidence", artifact.id))?;
        for field in
            ["binding_verification", "structural_verification", "lowering_record_verification", "typed_semantics_verification"]
        {
            if admission.get(field).and_then(Value::as_str) != Some("verified") {
                bail!("artifact '{}' admission field '{}' is not verified", artifact.id, field);
            }
        }
        if validations.get(&artifact.id).and_then(|validation| validation.get("status")).and_then(Value::as_str) != Some("ok") {
            bail!("artifact '{}' metadata transaction validation is not ok", artifact.id);
        }
    }
    if admissions.keys().any(|id| !artifact_ids.contains(id.as_str()))
        || validations.keys().any(|id| !artifact_ids.contains(id.as_str()))
    {
        bail!("ProtocolBundle evidence contains an unknown artifact identity");
    }
    Ok(())
}

struct CapacityEvidence {
    input: u64,
    output: u64,
    occupied_output: u64,
    fee: u64,
}

fn materialize_transaction(transaction: &TransactionWire) -> Result<(TransactionView, CapacityEvidence)> {
    let _policy_bindings = (
        require_hash32("fee_policy_hash", &transaction.fee_policy_hash)?,
        require_hash32("change_policy_hash", &transaction.change_policy_hash)?,
        &transaction.builder_assumption_evidence,
    );
    if transaction.inputs.is_empty() {
        bail!("ProtocolBundle materialization requires at least one input");
    }
    let mut builder = TransactionBuilder::default();
    let mut seen_inputs = HashSet::new();
    let mut input_capacity = 0u64;
    for (index, cell) in transaction.inputs.iter().enumerate() {
        require_hash32(&format!("inputs[{index}].cell_commitment"), &cell.cell_commitment)?;
        let out_point = cell.out_point.as_ref().ok_or_else(|| anyhow::anyhow!("inputs[{index}] is missing concrete out_point"))?;
        let packed_out_point = parse_out_point(&format!("inputs[{index}].out_point"), out_point)?;
        if !seen_inputs.insert(packed_out_point.as_slice().to_vec()) {
            bail!("ProtocolBundle contains duplicate input OutPoint at inputs[{index}]");
        }
        let input = CellInput::new_builder().previous_output(packed_out_point).since(cell.since.unwrap_or(0)).build();
        builder.input(input);
        input_capacity = input_capacity
            .checked_add(cell.capacity)
            .ok_or_else(|| anyhow::anyhow!("ProtocolBundle input capacity total overflow"))?;
    }

    let mut output_capacity = 0u64;
    let mut occupied_output_capacity = 0u64;
    for (index, cell) in transaction.outputs.iter().enumerate() {
        require_hash32(&format!("outputs[{index}].cell_commitment"), &cell.cell_commitment)?;
        if cell.out_point.is_some() || cell.since.is_some() {
            bail!("outputs[{index}] must not contain input-only out_point or since fields");
        }
        let data_hex = cell.data.as_deref().ok_or_else(|| anyhow::anyhow!("outputs[{index}] is missing concrete data bytes"))?;
        let data = Bytes::from(parse_hex(&format!("outputs[{index}].data"), data_hex)?);
        let mut output_builder =
            CellOutput::new_builder().capacity(cell.capacity).lock(parse_script(&format!("outputs[{index}].lock"), &cell.lock)?);
        if let Some(type_script) = &cell.type_script {
            output_builder = output_builder.type_(Some(parse_script(&format!("outputs[{index}].type"), type_script)?).pack());
        }
        let output = output_builder.build();
        let occupied = output.occupied_capacity(Capacity::bytes(data.len())?)?.as_u64();
        if cell.capacity < occupied {
            bail!("outputs[{index}] capacity {} is below occupied capacity {occupied}", cell.capacity);
        }
        output_capacity = output_capacity
            .checked_add(cell.capacity)
            .ok_or_else(|| anyhow::anyhow!("ProtocolBundle output capacity total overflow"))?;
        occupied_output_capacity = occupied_output_capacity
            .checked_add(occupied)
            .ok_or_else(|| anyhow::anyhow!("ProtocolBundle occupied output capacity total overflow"))?;
        builder.output(output);
        builder.output_data(data.pack());
    }

    for (index, witness) in transaction.witnesses.iter().enumerate() {
        let packed = parse_witness(index, witness)?;
        builder.witness(packed.as_bytes().pack());
    }
    for (index, dep) in transaction.cell_deps.iter().enumerate() {
        builder.cell_dep(parse_cell_dep(&format!("cell_deps[{index}]"), dep)?);
    }
    for (index, header) in transaction.header_deps.iter().enumerate() {
        builder.header_dep(parse_byte32(&format!("header_deps[{index}]"), header)?.pack());
    }

    let fee = input_capacity
        .checked_sub(output_capacity)
        .ok_or_else(|| anyhow::anyhow!("ProtocolBundle output capacity {output_capacity} exceeds input capacity {input_capacity}"))?;
    Ok((
        builder.build(),
        CapacityEvidence { input: input_capacity, output: output_capacity, occupied_output: occupied_output_capacity, fee },
    ))
}

fn resolve_script_groups(bundle: &BundleWire, transaction_bytes_hash: &str) -> Result<Vec<ProtocolBundleScriptGroupEvidence>> {
    let input_locks = bundle
        .transaction
        .inputs
        .iter()
        .enumerate()
        .map(|(index, cell)| parse_script(&format!("inputs[{index}].lock"), &cell.lock).map(|script| (index, script)))
        .collect::<Result<Vec<_>>>()?;
    let input_types = bundle
        .transaction
        .inputs
        .iter()
        .enumerate()
        .map(|(index, cell)| {
            cell.type_script
                .as_ref()
                .map(|script| parse_script(&format!("inputs[{index}].type"), script))
                .transpose()
                .map(|script| (index, script))
        })
        .collect::<Result<Vec<_>>>()?;
    let output_types = bundle
        .transaction
        .outputs
        .iter()
        .enumerate()
        .map(|(index, cell)| {
            cell.type_script
                .as_ref()
                .map(|script| parse_script(&format!("outputs[{index}].type"), script))
                .transpose()
                .map(|script| (index, script))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut groups = Vec::with_capacity(bundle.artifacts.len());
    for artifact in &bundle.artifacts {
        let selected = parse_script(&format!("artifact '{}'.deployment.script", artifact.id), &artifact.deployment.script)?;
        let selected_bytes = selected.as_slice();
        let input_indexes = match artifact.script_role {
            ScriptRoleWire::Lock => input_locks
                .iter()
                .filter(|(_, script)| script.as_slice() == selected_bytes)
                .map(|(index, _)| *index)
                .collect::<Vec<_>>(),
            ScriptRoleWire::Type => input_types
                .iter()
                .filter_map(|(index, script)| script.as_ref().filter(|script| script.as_slice() == selected_bytes).map(|_| *index))
                .collect::<Vec<_>>(),
            ScriptRoleWire::SpawnedVerifier => Vec::new(),
        };
        let output_indexes = match artifact.script_role {
            ScriptRoleWire::Type => output_types
                .iter()
                .filter_map(|(index, script)| script.as_ref().filter(|script| script.as_slice() == selected_bytes).map(|_| *index))
                .collect::<Vec<_>>(),
            ScriptRoleWire::Lock | ScriptRoleWire::SpawnedVerifier => Vec::new(),
        };
        let direct_script_group = !matches!(artifact.script_role, ScriptRoleWire::SpawnedVerifier);
        if direct_script_group && input_indexes.is_empty() && output_indexes.is_empty() {
            bail!("artifact '{}' selected Script does not occur in a concrete transaction Script Group", artifact.id);
        }
        if direct_script_group && !artifact_has_matching_role_claim(artifact, &bundle.roles, &input_indexes, &output_indexes) {
            bail!("artifact '{}' has no role claim bound to its selected Script Group", artifact.id);
        }
        let code_cell_dep_index =
            bundle.transaction.cell_deps.iter().position(|dep| dep == &artifact.deployment.code_cell_dep).ok_or_else(|| {
                anyhow::anyhow!("artifact '{}' deployment code CellDep is absent from the concrete transaction", artifact.id)
            })?;
        let code_cell_dep_index = u32::try_from(code_cell_dep_index)
            .map_err(|_| anyhow::anyhow!("artifact '{}' code CellDep index does not fit in u32", artifact.id))?;
        groups.push(ProtocolBundleScriptGroupEvidence {
            artifact: artifact.id.clone(),
            entry_kind: artifact.entry.kind.clone(),
            entry: artifact.entry.name.clone(),
            script_role: script_role_name(artifact.script_role).to_string(),
            script_hash: format!("0x{}", hex::encode(selected.calc_script_hash().as_slice())),
            direct_script_group,
            input_indexes: index_bindings(&input_indexes)?,
            output_indexes: index_bindings(&output_indexes)?,
            code_cell_dep_index,
            transaction_bytes_hash: transaction_bytes_hash.to_string(),
            execution: "not-executed".to_string(),
        });
    }
    groups.sort_by(|left, right| left.artifact.cmp(&right.artifact));
    Ok(groups)
}

fn artifact_has_matching_role_claim(
    artifact: &ArtifactWire,
    roles: &[RoleWire],
    input_indexes: &[usize],
    output_indexes: &[usize],
) -> bool {
    roles.iter().any(|role| {
        if role.artifact != artifact.id {
            return false;
        }
        let Ok(index) = usize::try_from(role.index) else {
            return false;
        };
        match role.location {
            CellLocationWire::Input => input_indexes.contains(&index),
            CellLocationWire::Output => output_indexes.contains(&index),
        }
    })
}

fn index_bindings(indexes: &[usize]) -> Result<Vec<ProtocolBundleIndexBinding>> {
    indexes
        .iter()
        .enumerate()
        .map(|(group_index, global_index)| {
            Ok(ProtocolBundleIndexBinding {
                global_index: u32::try_from(*global_index).context("global Script Group index does not fit in u32")?,
                group_index: u32::try_from(group_index).context("group-relative Script index does not fit in u32")?,
            })
        })
        .collect()
}

fn parse_witness(index: usize, witness: &WitnessWire) -> Result<WitnessArgs> {
    let mut builder = WitnessArgs::new_builder();
    for (field, commitment, bytes) in [
        ("lock", witness.lock.as_deref(), witness.lock_bytes.as_deref()),
        ("input_type", witness.input_type.as_deref(), witness.input_type_bytes.as_deref()),
        ("output_type", witness.output_type.as_deref(), witness.output_type_bytes.as_deref()),
    ] {
        let materialized = match (commitment, bytes) {
            (Some(_), None) => bail!("witnesses[{index}].{field} is committed but has no materialized bytes"),
            (_, Some(bytes)) => {
                let raw = parse_hex(&format!("witnesses[{index}].{field}_bytes"), bytes)?;
                if let Some(commitment) = commitment {
                    require_hash32(&format!("witnesses[{index}].{field}"), commitment)?;
                    if hash_hex(&raw) != commitment {
                        bail!("witnesses[{index}].{field}_bytes does not match its commitment");
                    }
                }
                Some(Bytes::from(raw))
            }
            (None, None) => None,
        };
        match field {
            "lock" => builder = builder.lock(materialized.pack()),
            "input_type" => builder = builder.input_type(materialized.pack()),
            "output_type" => builder = builder.output_type(materialized.pack()),
            _ => unreachable!(),
        }
    }
    Ok(builder.build())
}

fn parse_script(label: &str, script: &ScriptWire) -> Result<Script> {
    let code_hash = parse_byte32(&format!("{label}.code_hash"), &script.code_hash)?;
    let hash_type = match script.hash_type.as_str() {
        "data" => ScriptHashType::Data,
        "type" => ScriptHashType::Type,
        "data1" => ScriptHashType::Data1,
        "data2" => ScriptHashType::Data2,
        other => bail!("unsupported {label}.hash_type '{other}'"),
    };
    let args = Bytes::from(parse_hex(&format!("{label}.args"), &script.args)?);
    Ok(Script::new_builder().code_hash(code_hash.pack()).hash_type(hash_type).args(args.pack()).build())
}

fn parse_out_point(label: &str, out_point: &OutPointWire) -> Result<OutPoint> {
    Ok(OutPoint::new_builder()
        .tx_hash(parse_byte32(&format!("{label}.tx_hash"), &out_point.tx_hash)?.pack())
        .index(out_point.index)
        .build())
}

fn parse_cell_dep(label: &str, dep: &CellDepWire) -> Result<CellDep> {
    let dep_type = match dep.dep_type.as_str() {
        "code" => DepType::Code,
        "dep_group" => DepType::DepGroup,
        other => bail!("unsupported {label}.dep_type '{other}'"),
    };
    Ok(CellDep::new_builder().out_point(parse_out_point(&format!("{label}.out_point"), &dep.out_point)?).dep_type(dep_type).build())
}

fn parse_byte32(label: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex(label, value)?;
    if bytes.len() != 32 {
        bail!("{label} must be exactly 32 bytes");
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn parse_hex(label: &str, value: &str) -> Result<Vec<u8>> {
    let Some(raw) = value.strip_prefix("0x") else {
        bail!("{label} must use canonical 0x-prefixed lowercase hex");
    };
    if !raw.len().is_multiple_of(2) || !raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        bail!("{label} must use canonical even-length lowercase hex");
    }
    hex::decode(raw).with_context(|| format!("failed to decode {label}"))
}

fn require_hash32(label: &str, value: &str) -> Result<[u8; 32]> {
    parse_byte32(label, value)
}

fn hash_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(blake2b_256(bytes)))
}

fn script_role_name(role: ScriptRoleWire) -> &'static str {
    match role {
        ScriptRoleWire::Lock => "lock",
        ScriptRoleWire::Type => "type",
        ScriptRoleWire::SpawnedVerifier => "spawned-verifier",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(byte: &str) -> Value {
        serde_json::json!({
            "code_hash": format!("0x{}", byte.repeat(64)),
            "hash_type": "data2",
            "args": "0x",
        })
    }

    fn cell_dep(byte: &str) -> Value {
        serde_json::json!({
            "out_point": { "tx_hash": format!("0x{}", byte.repeat(64)), "index": 0 },
            "dep_type": "code",
        })
    }

    fn report() -> Value {
        let lock = script("1");
        let type_script = script("2");
        let lock_dep = cell_dep("3");
        let type_dep = cell_dep("4");
        let witness_bytes = "0x0102";
        let witness_commitment = hash_hex(&[1, 2]);
        let bundle = serde_json::json!({
            "schema": PROTOCOL_BUNDLE_SCHEMA,
            "network": { "chain_id": "ckb-testnet", "genesis_hash": format!("0x{}", "0".repeat(64)) },
            "artifacts": [
                {
                    "id": "auth",
                    "package_coordinate": "example/auth@1.0.0",
                    "lock_node_id": "auth-node",
                    "entry": { "kind": "lock", "name": "authorize" },
                    "script_role": "lock",
                    "deployment": {
                        "network": { "chain_id": "ckb-testnet", "genesis_hash": format!("0x{}", "0".repeat(64)) },
                        "artifact_hash": "1".repeat(64),
                        "script": lock.clone(),
                        "code_cell_dep": lock_dep.clone(),
                    },
                    "compiler_version": "0.26.0",
                    "edition": "2026",
                    "metadata_schema_version": 71,
                    "artifact_hash": "1".repeat(64),
                    "metadata_hash": "2".repeat(64),
                    "typed_semantics_hash": "3".repeat(64),
                    "lowering_record_hash": "4".repeat(64),
                    "source_map_hash": "5".repeat(64),
                    "interface_hash": "6".repeat(64),
                    "target_profile_hash": "7".repeat(64),
                    "verified_bundle_id": "8".repeat(64),
                },
                {
                    "id": "token",
                    "package_coordinate": "example/token@1.0.0",
                    "lock_node_id": "token-node",
                    "entry": { "kind": "action", "name": "transfer" },
                    "script_role": "type",
                    "deployment": {
                        "network": { "chain_id": "ckb-testnet", "genesis_hash": format!("0x{}", "0".repeat(64)) },
                        "artifact_hash": "9".repeat(64),
                        "script": type_script.clone(),
                        "code_cell_dep": type_dep.clone(),
                    },
                    "compiler_version": "0.26.0",
                    "edition": "2026",
                    "metadata_schema_version": 71,
                    "artifact_hash": "9".repeat(64),
                    "metadata_hash": "a".repeat(64),
                    "typed_semantics_hash": "b".repeat(64),
                    "lowering_record_hash": "c".repeat(64),
                    "source_map_hash": "d".repeat(64),
                    "interface_hash": "e".repeat(64),
                    "target_profile_hash": "7".repeat(64),
                    "builder_manifest_hash": "f".repeat(64),
                    "verified_bundle_id": "0".repeat(64),
                },
            ],
            "transaction": {
                "version": 0,
                "inputs": [{
                    "cell_commitment": format!("0x{}", "5".repeat(64)),
                    "capacity": 120_000_000_000u64,
                    "lock": lock,
                    "type": type_script.clone(),
                    "out_point": { "tx_hash": format!("0x{}", "6".repeat(64)), "index": 0 },
                    "since": 0,
                    "data": "0x",
                }],
                "outputs": [{
                    "cell_commitment": format!("0x{}", "7".repeat(64)),
                    "capacity": 100_000_000_000u64,
                    "lock": script("1"),
                    "type": type_script,
                    "data": "0x0102",
                }],
                "witnesses": [{ "lock": witness_commitment, "lock_bytes": witness_bytes }],
                "cell_deps": [lock_dep, type_dep],
                "header_deps": [],
                "fee_policy_hash": format!("0x{}", "8".repeat(64)),
                "change_policy_hash": format!("0x{}", "9".repeat(64)),
                "builder_assumption_evidence": {},
            },
            "roles": [
                { "artifact": "auth", "name": "auth-input", "location": "input", "index": 0, "ownership": "shared-read" },
                { "artifact": "token", "name": "token-input", "location": "input", "index": 0, "ownership": "exclusive" },
            ],
            "witnesses": [],
            "cell_deps": [],
            "header_deps": [],
            "policies": [],
        });
        let bundle_hash = canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &bundle).unwrap();
        serde_json::json!({
            "schema": PROTOCOL_BUNDLE_REPORT_SCHEMA,
            "status": "ok",
            "bundle_hash": bundle_hash,
            "bundle": bundle,
            "conflicts": [],
            "evidence": {
                "schema": "cellscript-protocol-bundle-evidence-v1",
                "structural_verification": "verified",
                "artifact_admission": {
                    "auth": {
                        "binding_verification": "verified",
                        "structural_verification": "verified",
                        "lowering_record_verification": "verified",
                        "typed_semantics_verification": "verified",
                    },
                    "token": {
                        "binding_verification": "verified",
                        "structural_verification": "verified",
                        "lowering_record_verification": "verified",
                        "typed_semantics_verification": "verified",
                    },
                },
                "metadata_transaction_validation": {
                    "auth": { "status": "ok" },
                    "token": { "status": "ok" },
                },
                "transaction_serialization": "not-executed",
                "ckb_vm_execution": "not-executed",
                "chain_evidence": "not-executed",
                "exact_transaction_hash": null,
                "note": "offline",
            },
        })
    }

    fn rebind_bundle_hash(report: &mut Value) {
        report["bundle_hash"] = Value::String(canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &report["bundle"]).unwrap());
    }

    #[test]
    fn materializes_exact_bytes_and_group_relative_indexes() {
        let report = report();
        let (transaction, evidence) = materialize_protocol_bundle_report(&serde_json::to_vec(&report).unwrap()).unwrap();

        assert_eq!(transaction.inputs().len(), 1);
        assert_eq!(transaction.outputs().len(), 1);
        assert_eq!(evidence.fee_shannons, 20_000_000_000);
        assert_eq!(evidence.script_groups.len(), 2);
        assert!(evidence.script_groups.iter().all(|group| group.transaction_bytes_hash == evidence.serialized_transaction_hash));
        assert!(evidence
            .script_groups
            .iter()
            .all(|group| group.input_indexes == vec![ProtocolBundleIndexBinding { global_index: 0, group_index: 0 }]));
        assert_eq!(evidence.transaction_serialization, "verified");
        assert_eq!(evidence.ckb_vm_execution, "not-executed");
    }

    #[test]
    fn rejects_report_and_witness_mutations_at_separate_boundaries() {
        let mut report = report();
        report["bundle"]["transaction"]["outputs"][0]["data"] = Value::String("0x03".to_string());
        let error = materialize_protocol_bundle_report(&serde_json::to_vec(&report).unwrap()).unwrap_err().to_string();
        assert!(error.contains("bundle_hash"), "{error}");

        rebind_bundle_hash(&mut report);
        report["bundle"]["transaction"]["witnesses"][0]["lock_bytes"] = Value::String("0x03".to_string());
        rebind_bundle_hash(&mut report);
        let error = materialize_protocol_bundle_report(&serde_json::to_vec(&report).unwrap()).unwrap_err().to_string();
        assert!(error.contains("does not match its commitment"), "{error}");
    }

    #[test]
    fn aggregate_dry_run_preserves_each_group_and_rejects_another_transaction() {
        let report = report();
        let (transaction, materialization) = materialize_protocol_bundle_report(&serde_json::to_vec(&report).unwrap()).unwrap();
        let estimate = EstimateCycles { cycles: 45_000u64.into() };
        let dry_run = protocol_bundle_dry_run_evidence(&transaction, &materialization, &estimate).unwrap();

        assert_eq!(dry_run.aggregate_cycles, 45_000);
        assert_eq!(dry_run.direct_script_group_count, 2);
        assert!(dry_run.groups.iter().all(|group| group.acceptance == "accepted-by-aggregate-estimate-cycles"));
        assert!(dry_run.groups.iter().all(|group| group.cycles.is_none()));

        let changed = transaction.as_advanced_builder().set_witnesses(vec![Bytes::from_static(b"changed").pack()]).build();
        let error = protocol_bundle_dry_run_evidence(&changed, &materialization, &estimate).unwrap_err().to_string();
        assert!(error.contains("does not match materialization evidence"), "{error}");
    }
}
