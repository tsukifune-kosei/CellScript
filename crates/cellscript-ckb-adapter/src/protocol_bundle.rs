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
use ckb_jsonrpc_types::{EntryCompleted, EstimateCycles};
use ckb_sdk::core::TransactionBuilder;
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionView},
    packed::{CellDep, CellInput, CellOutput, OutPoint, OutPointVec, Script, WitnessArgs},
    prelude::*,
    H256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

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
pub struct ProtocolBundleLiveInputExpectation {
    pub index: u32,
    pub out_point_tx_hash: String,
    pub out_point_index: u32,
    pub capacity_shannons: u64,
    pub cell_output_hash: String,
    pub data_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleCodeCellDepExpectation {
    pub artifact: String,
    pub transaction_cell_dep_index: u32,
    pub out_point_tx_hash: String,
    pub out_point_index: u32,
    pub dep_type: String,
    pub artifact_hash: String,
    pub script_code_hash: String,
    pub script_hash_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleMaterializationEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub network_chain_id: String,
    pub network_genesis_hash: String,
    pub raw_transaction_hash: String,
    pub serialized_transaction_hash: String,
    pub serialized_transaction_size_bytes: usize,
    pub input_capacity_shannons: u64,
    pub output_capacity_shannons: u64,
    pub occupied_output_capacity_shannons: u64,
    pub fee_shannons: u64,
    pub capacity_source: &'static str,
    pub live_input_expectations: Vec<ProtocolBundleLiveInputExpectation>,
    pub code_cell_dep_expectations: Vec<ProtocolBundleCodeCellDepExpectation>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleLiveInputEvidence {
    pub index: u32,
    pub out_point_tx_hash: String,
    pub out_point_index: u32,
    pub capacity_shannons: u64,
    pub cell_output_hash: String,
    pub data_hash: String,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleLiveResolutionEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub serialized_transaction_hash: String,
    pub serialized_transaction_size_bytes: usize,
    pub network_chain_id: String,
    pub network_genesis_hash: String,
    pub inputs: Vec<ProtocolBundleLiveInputEvidence>,
    pub input_capacity_shannons: u64,
    pub output_capacity_shannons: u64,
    pub fee_shannons: u64,
    pub capacity_source: &'static str,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone)]
pub struct ProtocolBundleLiveCellObservation {
    pub out_point: OutPoint,
    pub output: CellOutput,
    pub data: Bytes,
}

#[derive(Debug, Clone)]
pub struct ProtocolBundleCellDepObservation {
    pub transaction_cell_dep_index: u32,
    pub root: ProtocolBundleLiveCellObservation,
    pub dep_group_members: Vec<ProtocolBundleLiveCellObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleCodeCellEvidence {
    pub artifact: String,
    pub transaction_cell_dep_index: u32,
    pub dep_type: String,
    pub root_out_point_tx_hash: String,
    pub root_out_point_index: u32,
    pub root_data_hash: String,
    pub resolved_code_out_point_tx_hash: String,
    pub resolved_code_out_point_index: u32,
    pub artifact_hash: String,
    pub code_data_hash: String,
    pub script_code_hash: String,
    pub script_hash_type: String,
    pub status: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleDependencyResolutionEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub serialized_transaction_hash: String,
    pub serialized_transaction_size_bytes: usize,
    pub network_chain_id: String,
    pub network_genesis_hash: String,
    pub cell_deps: Vec<ProtocolBundleCodeCellEvidence>,
    pub artifact_count: usize,
    pub unique_cell_dep_count: usize,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleReadyToSignEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub unsigned_serialized_transaction_hash: String,
    pub unsigned_serialized_transaction_size_bytes: usize,
    pub network_chain_id: String,
    pub network_genesis_hash: String,
    pub live_input_count: usize,
    pub verified_artifact_dependency_count: usize,
    pub signing_authority: &'static str,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleSignedTransactionEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub unsigned_serialized_transaction_hash: String,
    pub signed_serialized_transaction_hash: String,
    pub signed_serialized_transaction_size_bytes: usize,
    pub witness_count: usize,
    pub changed_lock_witness_indexes: Vec<u32>,
    pub entry_witness_fields_preserved: bool,
    pub sdk_unlocker_count: usize,
    pub all_lock_groups_processed: bool,
    pub signature_verification: &'static str,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleSignedDryRunEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub signed_serialized_transaction_hash: String,
    pub signed_serialized_transaction_size_bytes: usize,
    pub aggregate_cycles: u64,
    pub groups: Vec<ProtocolBundleGroupDryRunEvidence>,
    pub ckb_vm_execution: &'static str,
    pub cycle_attribution: &'static str,
    pub signature_verification: &'static str,
    pub tx_pool_acceptance: bool,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleTxPoolEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub signed_serialized_transaction_hash: String,
    pub aggregate_dry_run_cycles: u64,
    pub tx_pool_cycles: u64,
    pub fee_shannons: u64,
    pub tx_pool_accepted: bool,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleSubmissionEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub signed_serialized_transaction_hash: String,
    pub submitted_transaction_hash: String,
    pub tx_pool_accepted: bool,
    pub committed: bool,
    pub chain_evidence: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolBundleConfirmationEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub bundle_hash: String,
    pub raw_transaction_hash: String,
    pub signed_serialized_transaction_hash: String,
    pub submitted_transaction_hash: String,
    pub network_chain_id: String,
    pub network_genesis_hash: String,
    pub block_hash: String,
    pub block_number: u64,
    pub transaction_index: u32,
    pub observed_tip_hash: String,
    pub observed_tip_number: u64,
    pub confirmation_count: u64,
    pub required_confirmation_count: u64,
    pub reorgs_observed: u32,
    pub canonical_status: &'static str,
    pub confirmation_status: &'static str,
    pub finality_claim: &'static str,
    pub committed: bool,
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
    network: NetworkWire,
    artifacts: Vec<ArtifactWire>,
    transaction: TransactionWire,
    #[serde(default)]
    roles: Vec<RoleWire>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkWire {
    chain_id: String,
    genesis_hash: String,
}

#[derive(Debug, Deserialize)]
struct ArtifactWire {
    id: String,
    entry: EntryWire,
    script_role: ScriptRoleWire,
    deployment: DeploymentWire,
    artifact_hash: String,
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
    artifact_hash: String,
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

    if bundle.network.chain_id.trim().is_empty() {
        bail!("ProtocolBundle network chain_id must not be empty");
    }
    require_hash32("ProtocolBundle network genesis_hash", &bundle.network.genesis_hash)?;
    let (tx, capacities) = materialize_transaction(&bundle.transaction)?;
    let packed_transaction = tx.data();
    let serialized = packed_transaction.as_slice();
    let serialized_transaction_hash = hash_hex(serialized);
    let raw_transaction_hash = format!("0x{}", hex::encode(tx.hash().as_slice()));
    let script_groups = resolve_script_groups(&bundle, &serialized_transaction_hash)?;
    let code_cell_dep_expectations = resolve_code_cell_dep_expectations(&bundle)?;

    Ok((
        tx,
        ProtocolBundleMaterializationEvidence {
            schema: PROTOCOL_BUNDLE_MATERIALIZATION_SCHEMA,
            state: "MaterializedProtocolBundleTx",
            bundle_hash: report.bundle_hash,
            network_chain_id: bundle.network.chain_id,
            network_genesis_hash: bundle.network.genesis_hash,
            raw_transaction_hash,
            serialized_transaction_hash,
            serialized_transaction_size_bytes: serialized.len(),
            input_capacity_shannons: capacities.input,
            output_capacity_shannons: capacities.output,
            occupied_output_capacity_shannons: capacities.occupied_output,
            fee_shannons: capacities.fee,
            capacity_source: "bundle-skeleton-not-live-resolved",
            live_input_expectations: capacities.live_input_expectations,
            code_cell_dep_expectations,
            transaction_serialization: "verified",
            script_groups,
            ckb_vm_execution: "not-executed",
            chain_evidence: "not-executed",
        },
    ))
}

/// Verify materialized ProtocolBundle input expectations against live Cell
/// outputs already fetched from a node with data included.
///
/// The caller is responsible for rejecting non-live RPC statuses. This pure
/// boundary verifies the connected chain identity, exact transaction identity,
/// input ordering, packed CellOutput/data hashes, capacities, and resulting
/// fee before it emits live-resolution evidence.
pub fn protocol_bundle_live_resolution_evidence(
    tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    observed_chain_id: &str,
    observed_genesis_hash: &str,
    live_inputs: &[(CellOutput, Bytes)],
) -> Result<ProtocolBundleLiveResolutionEvidence> {
    validate_materialized_transaction(tx, materialization, "live resolution")?;
    if observed_chain_id != materialization.network_chain_id || observed_genesis_hash != materialization.network_genesis_hash {
        bail!("connected CKB network identity does not match the ProtocolBundle materialization");
    }
    if live_inputs.len() != materialization.live_input_expectations.len() || live_inputs.len() != tx.inputs().len() {
        bail!("live input evidence does not cover every transaction input exactly once");
    }
    let transaction_inputs = tx.inputs();
    let mut inputs = Vec::with_capacity(live_inputs.len());
    let mut input_capacity_shannons = 0u64;
    for (position, ((output, data), expected)) in live_inputs.iter().zip(materialization.live_input_expectations.iter()).enumerate() {
        let index = u32::try_from(position).context("live input index does not fit in u32")?;
        if expected.index != index {
            bail!("live input expectation order is not canonical at index {index}");
        }
        let out_point = transaction_inputs
            .get(position)
            .ok_or_else(|| anyhow::anyhow!("transaction input {position} disappeared during live resolution"))?
            .previous_output();
        let out_point_tx_hash = format!("0x{}", hex::encode(out_point.tx_hash().as_slice()));
        let out_point_index: u32 = out_point.index().unpack();
        if out_point_tx_hash != expected.out_point_tx_hash || out_point_index != expected.out_point_index {
            bail!("live input expectation at index {index} is bound to another OutPoint");
        }
        let capacity_shannons: u64 = output.capacity().unpack();
        let cell_output_hash = hash_hex(output.as_slice());
        let data_hash = hash_hex(data);
        if capacity_shannons != expected.capacity_shannons
            || cell_output_hash != expected.cell_output_hash
            || data_hash != expected.data_hash
        {
            bail!("live Cell at input index {index} differs from the ProtocolBundle expectation");
        }
        input_capacity_shannons = input_capacity_shannons
            .checked_add(capacity_shannons)
            .ok_or_else(|| anyhow::anyhow!("live input capacity total overflow"))?;
        inputs.push(ProtocolBundleLiveInputEvidence {
            index,
            out_point_tx_hash,
            out_point_index,
            capacity_shannons,
            cell_output_hash,
            data_hash,
            status: "live-verified",
        });
    }
    let fee_shannons = input_capacity_shannons
        .checked_sub(materialization.output_capacity_shannons)
        .ok_or_else(|| anyhow::anyhow!("live input capacity is below materialized output capacity"))?;
    if fee_shannons != materialization.fee_shannons {
        bail!("live input capacities produce a different fee from the materialized ProtocolBundle");
    }
    Ok(ProtocolBundleLiveResolutionEvidence {
        schema: "cellscript-protocol-bundle-live-resolution-v1",
        state: "LiveResolvedProtocolBundleTx",
        bundle_hash: materialization.bundle_hash.clone(),
        raw_transaction_hash: materialization.raw_transaction_hash.clone(),
        serialized_transaction_hash: materialization.serialized_transaction_hash.clone(),
        serialized_transaction_size_bytes: materialization.serialized_transaction_size_bytes,
        network_chain_id: observed_chain_id.to_string(),
        network_genesis_hash: observed_genesis_hash.to_string(),
        inputs,
        input_capacity_shannons,
        output_capacity_shannons: materialization.output_capacity_shannons,
        fee_shannons,
        capacity_source: "live-node",
        chain_evidence: "live-cell-resolution-uncommitted",
    })
}

/// Verify every artifact's deployed code CellDep against live node Cells.
///
/// Direct code deps must resolve to an exact admitted ELF data hash. Dep-group
/// deps must resolve their canonical Molecule OutPointVec and provide every
/// referenced live member before the selected code identity is accepted. The
/// result is bound to both the materialized transaction and its live-input
/// resolution evidence.
pub fn protocol_bundle_dependency_resolution_evidence(
    tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    live_resolution: &ProtocolBundleLiveResolutionEvidence,
    observations: &[ProtocolBundleCellDepObservation],
) -> Result<ProtocolBundleDependencyResolutionEvidence> {
    validate_materialized_transaction(tx, materialization, "dependency resolution")?;
    validate_live_resolution_binding(materialization, live_resolution)?;

    let expected_indexes =
        materialization.code_cell_dep_expectations.iter().map(|expected| expected.transaction_cell_dep_index).collect::<HashSet<_>>();
    let mut observed_by_index = HashMap::with_capacity(observations.len());
    for observation in observations {
        if observed_by_index.insert(observation.transaction_cell_dep_index, observation).is_some() {
            bail!("duplicate live CellDep observation for transaction index {}", observation.transaction_cell_dep_index);
        }
    }
    if expected_indexes.len() != observed_by_index.len() || expected_indexes.iter().any(|index| !observed_by_index.contains_key(index))
    {
        bail!("live CellDep observations do not cover every artifact code CellDep exactly once");
    }

    let transaction_cell_deps = tx.cell_deps();
    let mut cell_deps = Vec::with_capacity(materialization.code_cell_dep_expectations.len());
    for expected in &materialization.code_cell_dep_expectations {
        let observation = observed_by_index
            .get(&expected.transaction_cell_dep_index)
            .ok_or_else(|| anyhow::anyhow!("missing live CellDep observation for artifact '{}'", expected.artifact))?;
        let transaction_dep = transaction_cell_deps.get(expected.transaction_cell_dep_index as usize).ok_or_else(|| {
            anyhow::anyhow!("artifact '{}' CellDep index is outside the materialized transaction", expected.artifact)
        })?;
        let transaction_dep_type = dep_type_name(transaction_dep.dep_type())?;
        let (transaction_tx_hash, transaction_index) = out_point_identity(&transaction_dep.out_point());
        if transaction_dep_type != expected.dep_type
            || transaction_tx_hash != expected.out_point_tx_hash
            || transaction_index != expected.out_point_index
        {
            bail!("artifact '{}' CellDep expectation differs from the materialized transaction", expected.artifact);
        }
        let (root_tx_hash, root_index) = out_point_identity(&observation.root.out_point);
        if root_tx_hash != expected.out_point_tx_hash || root_index != expected.out_point_index {
            bail!("artifact '{}' live CellDep root is bound to another OutPoint", expected.artifact);
        }

        let resolved_code = match expected.dep_type.as_str() {
            "code" => {
                if !observation.dep_group_members.is_empty() {
                    bail!(
                        "direct code CellDep {} must not contain dep-group member observations",
                        expected.transaction_cell_dep_index
                    );
                }
                &observation.root
            }
            "dep_group" => {
                let declared_members = OutPointVec::from_slice(observation.root.data.as_ref()).map_err(|error| {
                    anyhow::anyhow!("CellDep {} has malformed dep-group data: {error}", expected.transaction_cell_dep_index)
                })?;
                if declared_members.len() != observation.dep_group_members.len() {
                    bail!(
                        "CellDep {} dep-group observation does not cover every declared member",
                        expected.transaction_cell_dep_index
                    );
                }
                for (member_index, (declared, observed)) in
                    declared_members.into_iter().zip(&observation.dep_group_members).enumerate()
                {
                    if declared.as_slice() != observed.out_point.as_slice() {
                        bail!(
                            "CellDep {} dep-group member {member_index} is bound to another OutPoint",
                            expected.transaction_cell_dep_index
                        );
                    }
                }
                observation.dep_group_members.iter().find(|member| code_cell_matches_expectation(member, expected)).ok_or_else(
                    || anyhow::anyhow!("artifact '{}' admitted ELF is absent from its live dep group", expected.artifact),
                )?
            }
            other => bail!("unsupported ProtocolBundle CellDep type '{other}'"),
        };
        if !code_cell_matches_expectation(resolved_code, expected) {
            bail!("artifact '{}' live code Cell does not match its admitted ELF and Script identity", expected.artifact);
        }
        let (resolved_tx_hash, resolved_index) = out_point_identity(&resolved_code.out_point);
        cell_deps.push(ProtocolBundleCodeCellEvidence {
            artifact: expected.artifact.clone(),
            transaction_cell_dep_index: expected.transaction_cell_dep_index,
            dep_type: expected.dep_type.clone(),
            root_out_point_tx_hash: root_tx_hash,
            root_out_point_index: root_index,
            root_data_hash: hash_hex(&observation.root.data),
            resolved_code_out_point_tx_hash: resolved_tx_hash,
            resolved_code_out_point_index: resolved_index,
            artifact_hash: expected.artifact_hash.clone(),
            code_data_hash: hash_hex(&resolved_code.data),
            script_code_hash: expected.script_code_hash.clone(),
            script_hash_type: expected.script_hash_type.clone(),
            status: "live-code-verified",
        });
    }
    cell_deps.sort_by(|left, right| left.artifact.cmp(&right.artifact));
    Ok(ProtocolBundleDependencyResolutionEvidence {
        schema: "cellscript-protocol-bundle-dependency-resolution-v1",
        state: "LiveDependenciesResolvedProtocolBundleTx",
        bundle_hash: materialization.bundle_hash.clone(),
        raw_transaction_hash: materialization.raw_transaction_hash.clone(),
        serialized_transaction_hash: materialization.serialized_transaction_hash.clone(),
        serialized_transaction_size_bytes: materialization.serialized_transaction_size_bytes,
        network_chain_id: live_resolution.network_chain_id.clone(),
        network_genesis_hash: live_resolution.network_genesis_hash.clone(),
        artifact_count: cell_deps.len(),
        unique_cell_dep_count: expected_indexes.len(),
        cell_deps,
        chain_evidence: "live-input-and-code-cell-resolution-uncommitted",
    })
}

/// Advance an exact transaction to the adapter-owned signing boundary only
/// after live inputs and artifact code dependencies have both been verified.
pub fn protocol_bundle_ready_to_sign_evidence(
    tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    live_resolution: &ProtocolBundleLiveResolutionEvidence,
    dependency_resolution: &ProtocolBundleDependencyResolutionEvidence,
) -> Result<ProtocolBundleReadyToSignEvidence> {
    validate_materialized_transaction(tx, materialization, "signing preparation")?;
    validate_live_resolution_binding(materialization, live_resolution)?;
    validate_dependency_resolution_binding(materialization, dependency_resolution)?;
    Ok(ProtocolBundleReadyToSignEvidence {
        schema: "cellscript-protocol-bundle-ready-to-sign-v1",
        state: "ReadyToSignProtocolBundleTx",
        bundle_hash: materialization.bundle_hash.clone(),
        raw_transaction_hash: materialization.raw_transaction_hash.clone(),
        unsigned_serialized_transaction_hash: materialization.serialized_transaction_hash.clone(),
        unsigned_serialized_transaction_size_bytes: materialization.serialized_transaction_size_bytes,
        network_chain_id: materialization.network_chain_id.clone(),
        network_genesis_hash: materialization.network_genesis_hash.clone(),
        live_input_count: live_resolution.inputs.len(),
        verified_artifact_dependency_count: dependency_resolution.cell_deps.len(),
        signing_authority: "adapter-supplied-sdk-unlockers",
        chain_evidence: "live-input-and-code-cell-resolution-uncommitted",
    })
}

/// Bind the result of SDK unlockers to the prepared raw transaction while
/// requiring all compiler-owned WitnessArgs fields to remain byte-identical.
/// Lock fields may change; inputs, outputs, deps, headers, and the raw
/// transaction hash may not.
pub(crate) fn protocol_bundle_signed_transaction_evidence(
    unsigned_tx: &TransactionView,
    signed_tx: &TransactionView,
    preparation: &ProtocolBundleReadyToSignEvidence,
    sdk_unlocker_count: usize,
) -> Result<ProtocolBundleSignedTransactionEvidence> {
    validate_prepared_unsigned_transaction(unsigned_tx, preparation)?;
    let signed_raw_hash = format!("0x{}", hex::encode(signed_tx.hash().as_slice()));
    if signed_raw_hash != preparation.raw_transaction_hash {
        bail!("ProtocolBundle signing changed the raw transaction");
    }
    let unsigned_witnesses = unsigned_tx.witnesses();
    let signed_witnesses = signed_tx.witnesses();
    if unsigned_witnesses.len() != signed_witnesses.len() {
        bail!("ProtocolBundle signing changed the witness count");
    }
    let mut changed_lock_witness_indexes = Vec::new();
    for index in 0..unsigned_witnesses.len() {
        let unsigned = WitnessArgs::from_slice(unsigned_witnesses.get(index).expect("bounded witness index").raw_data().as_ref())
            .map_err(|error| anyhow::anyhow!("unsigned ProtocolBundle witness {index} is not canonical WitnessArgs: {error}"))?;
        let signed = WitnessArgs::from_slice(signed_witnesses.get(index).expect("bounded witness index").raw_data().as_ref())
            .map_err(|error| anyhow::anyhow!("signed ProtocolBundle witness {index} is not canonical WitnessArgs: {error}"))?;
        if unsigned.input_type().as_slice() != signed.input_type().as_slice()
            || unsigned.output_type().as_slice() != signed.output_type().as_slice()
        {
            bail!("ProtocolBundle signing changed compiler-owned witness fields at index {index}");
        }
        if unsigned.lock().as_slice() != signed.lock().as_slice() {
            changed_lock_witness_indexes
                .push(u32::try_from(index).context("changed ProtocolBundle witness index does not fit in u32")?);
        }
    }
    let signed_serialized = signed_tx.data();
    Ok(ProtocolBundleSignedTransactionEvidence {
        schema: "cellscript-protocol-bundle-signed-transaction-v1",
        state: "SignedProtocolBundleTx",
        bundle_hash: preparation.bundle_hash.clone(),
        raw_transaction_hash: preparation.raw_transaction_hash.clone(),
        unsigned_serialized_transaction_hash: preparation.unsigned_serialized_transaction_hash.clone(),
        signed_serialized_transaction_hash: hash_hex(signed_serialized.as_slice()),
        signed_serialized_transaction_size_bytes: signed_serialized.as_slice().len(),
        witness_count: signed_witnesses.len(),
        changed_lock_witness_indexes,
        entry_witness_fields_preserved: true,
        sdk_unlocker_count,
        all_lock_groups_processed: true,
        signature_verification: "pending-node-execution",
        chain_evidence: "signed-uncommitted",
    })
}

/// Bind successful node execution of the signed transaction to all direct
/// Script Groups. This is the first evidence tier that verifies signatures.
pub fn protocol_bundle_signed_dry_run_evidence(
    signed_tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    signing: &ProtocolBundleSignedTransactionEvidence,
    estimate: &EstimateCycles,
) -> Result<ProtocolBundleSignedDryRunEvidence> {
    validate_signed_transaction(signed_tx, materialization, signing, "signed dry-run")?;
    let mut groups = Vec::with_capacity(materialization.script_groups.len());
    for group in &materialization.script_groups {
        groups.push(ProtocolBundleGroupDryRunEvidence {
            artifact: group.artifact.clone(),
            script_role: group.script_role.clone(),
            script_hash: group.script_hash.clone(),
            transaction_bytes_hash: signing.signed_serialized_transaction_hash.clone(),
            acceptance: if group.direct_script_group {
                "accepted-by-signed-aggregate-estimate-cycles".to_string()
            } else {
                "not-independently-observed".to_string()
            },
            cycles: None,
        });
    }
    if !groups.iter().any(|group| group.acceptance == "accepted-by-signed-aggregate-estimate-cycles") {
        bail!("ProtocolBundle signed dry-run evidence contains no direct Script Group");
    }
    Ok(ProtocolBundleSignedDryRunEvidence {
        schema: "cellscript-protocol-bundle-signed-dry-run-v1",
        state: "SignedDryRunProtocolBundleTx",
        bundle_hash: materialization.bundle_hash.clone(),
        raw_transaction_hash: materialization.raw_transaction_hash.clone(),
        signed_serialized_transaction_hash: signing.signed_serialized_transaction_hash.clone(),
        signed_serialized_transaction_size_bytes: signing.signed_serialized_transaction_size_bytes,
        aggregate_cycles: estimate.cycles.value(),
        groups,
        ckb_vm_execution: "accepted-by-node-estimate-cycles",
        cycle_attribution: "aggregate-only-rpc-does-not-report-per-group-cycles",
        signature_verification: "verified-by-node-execution",
        tx_pool_acceptance: false,
        chain_evidence: "node-signed-dry-run-uncommitted",
    })
}

/// Bind a successful `test_tx_pool_accept` result to the exact signed and
/// dry-run transaction. The node-computed fee must equal the live input fee.
pub fn protocol_bundle_tx_pool_evidence(
    signed_tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    signing: &ProtocolBundleSignedTransactionEvidence,
    dry_run: &ProtocolBundleSignedDryRunEvidence,
    accepted: &EntryCompleted,
) -> Result<ProtocolBundleTxPoolEvidence> {
    validate_signed_transaction(signed_tx, materialization, signing, "tx-pool acceptance")?;
    if dry_run.schema != "cellscript-protocol-bundle-signed-dry-run-v1"
        || dry_run.state != "SignedDryRunProtocolBundleTx"
        || dry_run.bundle_hash != signing.bundle_hash
        || dry_run.raw_transaction_hash != signing.raw_transaction_hash
        || dry_run.signed_serialized_transaction_hash != signing.signed_serialized_transaction_hash
        || dry_run.signed_serialized_transaction_size_bytes != signing.signed_serialized_transaction_size_bytes
        || dry_run.signature_verification != "verified-by-node-execution"
        || dry_run.groups.iter().any(|group| group.transaction_bytes_hash != signing.signed_serialized_transaction_hash)
    {
        bail!("ProtocolBundle signed dry-run evidence is not bound to the signed transaction");
    }
    let fee_shannons = accepted.fee.value();
    if fee_shannons != materialization.fee_shannons {
        bail!("ProtocolBundle tx-pool fee differs from the live-resolved transaction fee");
    }
    Ok(ProtocolBundleTxPoolEvidence {
        schema: "cellscript-protocol-bundle-tx-pool-v1",
        state: "TxPoolAcceptedProtocolBundleTx",
        bundle_hash: signing.bundle_hash.clone(),
        raw_transaction_hash: signing.raw_transaction_hash.clone(),
        signed_serialized_transaction_hash: signing.signed_serialized_transaction_hash.clone(),
        aggregate_dry_run_cycles: dry_run.aggregate_cycles,
        tx_pool_cycles: accepted.cycles.value(),
        fee_shannons,
        tx_pool_accepted: true,
        chain_evidence: "tx-pool-accepted-uncommitted",
    })
}

/// Bind the node-returned submission hash to the exact tx-pool-accepted
/// ProtocolBundle transaction. This record does not claim commitment.
pub fn protocol_bundle_submission_evidence(
    signed_tx: &TransactionView,
    signing: &ProtocolBundleSignedTransactionEvidence,
    tx_pool: &ProtocolBundleTxPoolEvidence,
    submitted_hash: &H256,
) -> Result<ProtocolBundleSubmissionEvidence> {
    let raw_transaction_hash = format!("0x{}", hex::encode(signed_tx.hash().as_slice()));
    let submitted_transaction_hash = format!("0x{}", hex::encode(submitted_hash.as_bytes()));
    if signing.state != "SignedProtocolBundleTx"
        || signing.raw_transaction_hash != raw_transaction_hash
        || tx_pool.schema != "cellscript-protocol-bundle-tx-pool-v1"
        || tx_pool.state != "TxPoolAcceptedProtocolBundleTx"
        || tx_pool.bundle_hash != signing.bundle_hash
        || tx_pool.raw_transaction_hash != raw_transaction_hash
        || tx_pool.signed_serialized_transaction_hash != signing.signed_serialized_transaction_hash
        || !tx_pool.tx_pool_accepted
        || submitted_transaction_hash != raw_transaction_hash
    {
        bail!("ProtocolBundle submission result is not bound to the tx-pool-accepted signed transaction");
    }
    Ok(ProtocolBundleSubmissionEvidence {
        schema: "cellscript-protocol-bundle-submission-v1",
        state: "SubmittedProtocolBundleTx",
        bundle_hash: signing.bundle_hash.clone(),
        raw_transaction_hash: raw_transaction_hash.clone(),
        signed_serialized_transaction_hash: signing.signed_serialized_transaction_hash.clone(),
        submitted_transaction_hash: raw_transaction_hash,
        tx_pool_accepted: true,
        committed: false,
        chain_evidence: "submitted-uncommitted",
    })
}

/// Bind a canonical-chain inclusion and bounded confirmation-depth observation
/// to one exact submitted ProtocolBundle transaction.
///
/// This is an observation at `observed_tip_hash`, not a claim of absolute
/// finality. The RPC-facing adapter rechecks `get_transaction` after observing
/// the required depth and restarts the depth count when a reorg changes or
/// removes an earlier inclusion.
#[allow(clippy::too_many_arguments)]
pub fn protocol_bundle_confirmation_evidence(
    submission: &ProtocolBundleSubmissionEvidence,
    materialization: &ProtocolBundleMaterializationEvidence,
    observed_chain_id: &str,
    observed_genesis_hash: &str,
    block_hash: &str,
    block_number: u64,
    transaction_index: u32,
    observed_tip_hash: &str,
    observed_tip_number: u64,
    required_confirmation_count: u64,
    reorgs_observed: u32,
) -> Result<ProtocolBundleConfirmationEvidence> {
    if submission.schema != "cellscript-protocol-bundle-submission-v1"
        || submission.state != "SubmittedProtocolBundleTx"
        || submission.bundle_hash != materialization.bundle_hash
        || submission.raw_transaction_hash != materialization.raw_transaction_hash
        || submission.submitted_transaction_hash != submission.raw_transaction_hash
        || !submission.tx_pool_accepted
        || submission.committed
        || submission.chain_evidence != "submitted-uncommitted"
        || materialization.schema != PROTOCOL_BUNDLE_MATERIALIZATION_SCHEMA
        || materialization.state != "MaterializedProtocolBundleTx"
    {
        bail!("ProtocolBundle confirmation is not bound to the submitted materialized transaction");
    }
    if observed_chain_id != materialization.network_chain_id || observed_genesis_hash != materialization.network_genesis_hash {
        bail!("connected CKB network identity does not match the submitted ProtocolBundle");
    }
    require_hash32("ProtocolBundle submitted transaction hash", &submission.submitted_transaction_hash)?;
    require_hash32("ProtocolBundle confirmation block hash", block_hash)?;
    require_hash32("ProtocolBundle confirmation tip hash", observed_tip_hash)?;
    if required_confirmation_count == 0 {
        bail!("ProtocolBundle required confirmation count must be at least one");
    }
    let confirmation_count = observed_tip_number
        .checked_sub(block_number)
        .and_then(|distance| distance.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("ProtocolBundle confirmation tip precedes its inclusion block"))?;
    if confirmation_count < required_confirmation_count {
        bail!("ProtocolBundle confirmation depth {confirmation_count} is below required depth {required_confirmation_count}");
    }
    Ok(ProtocolBundleConfirmationEvidence {
        schema: "cellscript-protocol-bundle-confirmation-v1",
        state: "ConfirmedProtocolBundleTx",
        bundle_hash: submission.bundle_hash.clone(),
        raw_transaction_hash: submission.raw_transaction_hash.clone(),
        signed_serialized_transaction_hash: submission.signed_serialized_transaction_hash.clone(),
        submitted_transaction_hash: submission.submitted_transaction_hash.clone(),
        network_chain_id: observed_chain_id.to_string(),
        network_genesis_hash: observed_genesis_hash.to_string(),
        block_hash: block_hash.to_string(),
        block_number,
        transaction_index,
        observed_tip_hash: observed_tip_hash.to_string(),
        observed_tip_number,
        confirmation_count,
        required_confirmation_count,
        reorgs_observed,
        canonical_status: "committed-in-canonical-chain",
        confirmation_status: "required-depth-observed",
        finality_claim: "bounded-observation-not-absolute-finality",
        committed: true,
        chain_evidence: "node-committed-confirmation-depth-observed",
    })
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
    validate_materialized_transaction(tx, materialization, "dry-run")?;
    let packed_transaction = tx.data();
    let serialized = packed_transaction.as_slice();
    let serialized_hash = materialization.serialized_transaction_hash.clone();
    let raw_hash = materialization.raw_transaction_hash.clone();
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

fn validate_materialized_transaction(
    tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    operation: &str,
) -> Result<()> {
    let packed_transaction = tx.data();
    let serialized = packed_transaction.as_slice();
    let serialized_hash = hash_hex(serialized);
    let raw_hash = format!("0x{}", hex::encode(tx.hash().as_slice()));
    if serialized_hash != materialization.serialized_transaction_hash
        || raw_hash != materialization.raw_transaction_hash
        || serialized.len() != materialization.serialized_transaction_size_bytes
    {
        bail!("ProtocolBundle {operation} transaction does not match materialization evidence");
    }
    Ok(())
}

fn validate_live_resolution_binding(
    materialization: &ProtocolBundleMaterializationEvidence,
    live_resolution: &ProtocolBundleLiveResolutionEvidence,
) -> Result<()> {
    if live_resolution.schema != "cellscript-protocol-bundle-live-resolution-v1"
        || live_resolution.state != "LiveResolvedProtocolBundleTx"
        || live_resolution.bundle_hash != materialization.bundle_hash
        || live_resolution.raw_transaction_hash != materialization.raw_transaction_hash
        || live_resolution.serialized_transaction_hash != materialization.serialized_transaction_hash
        || live_resolution.serialized_transaction_size_bytes != materialization.serialized_transaction_size_bytes
        || live_resolution.network_chain_id != materialization.network_chain_id
        || live_resolution.network_genesis_hash != materialization.network_genesis_hash
        || live_resolution.input_capacity_shannons != materialization.input_capacity_shannons
        || live_resolution.output_capacity_shannons != materialization.output_capacity_shannons
        || live_resolution.fee_shannons != materialization.fee_shannons
        || live_resolution.capacity_source != "live-node"
        || live_resolution.inputs.iter().any(|input| input.status != "live-verified")
    {
        bail!("ProtocolBundle live-input evidence is not bound to the materialized transaction");
    }
    if live_resolution.inputs.len() != materialization.live_input_expectations.len()
        || live_resolution.inputs.iter().zip(&materialization.live_input_expectations).any(|(observed, expected)| {
            observed.index != expected.index
                || observed.out_point_tx_hash != expected.out_point_tx_hash
                || observed.out_point_index != expected.out_point_index
                || observed.capacity_shannons != expected.capacity_shannons
                || observed.cell_output_hash != expected.cell_output_hash
                || observed.data_hash != expected.data_hash
        })
    {
        bail!("ProtocolBundle live-input evidence does not preserve every exact input observation");
    }
    Ok(())
}

fn validate_dependency_resolution_binding(
    materialization: &ProtocolBundleMaterializationEvidence,
    dependency_resolution: &ProtocolBundleDependencyResolutionEvidence,
) -> Result<()> {
    let expected_unique_count = materialization
        .code_cell_dep_expectations
        .iter()
        .map(|expected| expected.transaction_cell_dep_index)
        .collect::<HashSet<_>>()
        .len();
    if dependency_resolution.schema != "cellscript-protocol-bundle-dependency-resolution-v1"
        || dependency_resolution.state != "LiveDependenciesResolvedProtocolBundleTx"
        || dependency_resolution.bundle_hash != materialization.bundle_hash
        || dependency_resolution.raw_transaction_hash != materialization.raw_transaction_hash
        || dependency_resolution.serialized_transaction_hash != materialization.serialized_transaction_hash
        || dependency_resolution.serialized_transaction_size_bytes != materialization.serialized_transaction_size_bytes
        || dependency_resolution.network_chain_id != materialization.network_chain_id
        || dependency_resolution.network_genesis_hash != materialization.network_genesis_hash
        || dependency_resolution.artifact_count != materialization.code_cell_dep_expectations.len()
        || dependency_resolution.unique_cell_dep_count != expected_unique_count
        || dependency_resolution.cell_deps.len() != materialization.code_cell_dep_expectations.len()
    {
        bail!("ProtocolBundle dependency evidence is not bound to the materialized transaction");
    }
    for expected in &materialization.code_cell_dep_expectations {
        let Some(observed) = dependency_resolution.cell_deps.iter().find(|observed| observed.artifact == expected.artifact) else {
            bail!("ProtocolBundle dependency evidence is missing artifact '{}'", expected.artifact);
        };
        if observed.transaction_cell_dep_index != expected.transaction_cell_dep_index
            || observed.dep_type != expected.dep_type
            || observed.root_out_point_tx_hash != expected.out_point_tx_hash
            || observed.root_out_point_index != expected.out_point_index
            || observed.artifact_hash != expected.artifact_hash
            || observed.code_data_hash != expected.artifact_hash
            || observed.script_code_hash != expected.script_code_hash
            || observed.script_hash_type != expected.script_hash_type
            || observed.status != "live-code-verified"
            || (observed.dep_type == "code"
                && (observed.resolved_code_out_point_tx_hash != observed.root_out_point_tx_hash
                    || observed.resolved_code_out_point_index != observed.root_out_point_index))
        {
            bail!("ProtocolBundle dependency evidence for artifact '{}' is inconsistent", expected.artifact);
        }
    }
    Ok(())
}

fn validate_prepared_unsigned_transaction(tx: &TransactionView, preparation: &ProtocolBundleReadyToSignEvidence) -> Result<()> {
    let serialized = tx.data();
    if preparation.schema != "cellscript-protocol-bundle-ready-to-sign-v1"
        || preparation.state != "ReadyToSignProtocolBundleTx"
        || format!("0x{}", hex::encode(tx.hash().as_slice())) != preparation.raw_transaction_hash
        || hash_hex(serialized.as_slice()) != preparation.unsigned_serialized_transaction_hash
        || serialized.as_slice().len() != preparation.unsigned_serialized_transaction_size_bytes
        || preparation.signing_authority != "adapter-supplied-sdk-unlockers"
    {
        bail!("ProtocolBundle signing preparation is not bound to the unsigned transaction");
    }
    Ok(())
}

fn validate_signed_transaction(
    signed_tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
    signing: &ProtocolBundleSignedTransactionEvidence,
    operation: &str,
) -> Result<()> {
    let serialized = signed_tx.data();
    if signing.schema != "cellscript-protocol-bundle-signed-transaction-v1"
        || signing.state != "SignedProtocolBundleTx"
        || signing.bundle_hash != materialization.bundle_hash
        || signing.raw_transaction_hash != materialization.raw_transaction_hash
        || signing.unsigned_serialized_transaction_hash != materialization.serialized_transaction_hash
        || format!("0x{}", hex::encode(signed_tx.hash().as_slice())) != signing.raw_transaction_hash
        || hash_hex(serialized.as_slice()) != signing.signed_serialized_transaction_hash
        || serialized.as_slice().len() != signing.signed_serialized_transaction_size_bytes
        || signed_tx.witnesses().len() != signing.witness_count
        || !signing.entry_witness_fields_preserved
        || !signing.all_lock_groups_processed
    {
        bail!("ProtocolBundle {operation} transaction does not match signing evidence");
    }
    Ok(())
}

fn code_cell_matches_expectation(
    observation: &ProtocolBundleLiveCellObservation,
    expected: &ProtocolBundleCodeCellDepExpectation,
) -> bool {
    let data_hash = hash_hex(&observation.data);
    if data_hash != expected.artifact_hash {
        return false;
    }
    match expected.script_hash_type.as_str() {
        "data" | "data1" | "data2" => data_hash == expected.script_code_hash,
        "type" => observation.output.type_().to_opt().is_some_and(|type_script| {
            format!("0x{}", hex::encode(type_script.calc_script_hash().as_slice())) == expected.script_code_hash
        }),
        _ => false,
    }
}

fn out_point_identity(out_point: &OutPoint) -> (String, u32) {
    (format!("0x{}", hex::encode(out_point.tx_hash().as_slice())), out_point.index().unpack())
}

fn dep_type_name(dep_type: ckb_types::packed::Byte) -> Result<&'static str> {
    match dep_type.as_slice().first().copied() {
        Some(0) => Ok("code"),
        Some(1) => Ok("dep_group"),
        _ => bail!("materialized transaction contains an unsupported CellDep type"),
    }
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
    live_input_expectations: Vec<ProtocolBundleLiveInputExpectation>,
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
    let mut live_input_expectations = Vec::with_capacity(transaction.inputs.len());
    for (index, cell) in transaction.inputs.iter().enumerate() {
        require_hash32(&format!("inputs[{index}].cell_commitment"), &cell.cell_commitment)?;
        let out_point = cell.out_point.as_ref().ok_or_else(|| anyhow::anyhow!("inputs[{index}] is missing concrete out_point"))?;
        let packed_out_point = parse_out_point(&format!("inputs[{index}].out_point"), out_point)?;
        if !seen_inputs.insert(packed_out_point.as_slice().to_vec()) {
            bail!("ProtocolBundle contains duplicate input OutPoint at inputs[{index}]");
        }
        let input = CellInput::new_builder().previous_output(packed_out_point).since(cell.since.unwrap_or(0)).build();
        builder.input(input);
        let input_data = Bytes::from(parse_hex(
            &format!("inputs[{index}].data"),
            cell.data.as_deref().ok_or_else(|| anyhow::anyhow!("inputs[{index}] is missing exact live Cell data"))?,
        )?);
        let mut expected_output =
            CellOutput::new_builder().capacity(cell.capacity).lock(parse_script(&format!("inputs[{index}].lock"), &cell.lock)?);
        if let Some(type_script) = &cell.type_script {
            expected_output = expected_output.type_(Some(parse_script(&format!("inputs[{index}].type"), type_script)?).pack());
        }
        let expected_output = expected_output.build();
        live_input_expectations.push(ProtocolBundleLiveInputExpectation {
            index: u32::try_from(index).context("ProtocolBundle input index does not fit in u32")?,
            out_point_tx_hash: out_point.tx_hash.clone(),
            out_point_index: out_point.index,
            capacity_shannons: cell.capacity,
            cell_output_hash: hash_hex(expected_output.as_slice()),
            data_hash: hash_hex(&input_data),
        });
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
        CapacityEvidence {
            input: input_capacity,
            output: output_capacity,
            occupied_output: occupied_output_capacity,
            fee,
            live_input_expectations,
        },
    ))
}

fn resolve_code_cell_dep_expectations(bundle: &BundleWire) -> Result<Vec<ProtocolBundleCodeCellDepExpectation>> {
    let mut expectations = Vec::with_capacity(bundle.artifacts.len());
    for artifact in &bundle.artifacts {
        let artifact_hash = parse_raw_hash32(&format!("artifact '{}'.artifact_hash", artifact.id), &artifact.artifact_hash)?;
        let deployment_hash =
            parse_raw_hash32(&format!("artifact '{}'.deployment.artifact_hash", artifact.id), &artifact.deployment.artifact_hash)?;
        if artifact_hash != deployment_hash {
            bail!("artifact '{}' deployment hash differs from its admitted artifact hash", artifact.id);
        }
        let script = parse_script(&format!("artifact '{}'.deployment.script", artifact.id), &artifact.deployment.script)?;
        let script_code_hash = format!("0x{}", hex::encode(script.code_hash().as_slice()));
        let artifact_hash = format!("0x{}", hex::encode(artifact_hash));
        if artifact.deployment.script.hash_type != "type" && script_code_hash != artifact_hash {
            bail!("artifact '{}' data-hash Script identity differs from its admitted ELF hash", artifact.id);
        }
        let transaction_cell_dep_index =
            bundle.transaction.cell_deps.iter().position(|dep| dep == &artifact.deployment.code_cell_dep).ok_or_else(|| {
                anyhow::anyhow!("artifact '{}' deployment code CellDep is absent from the concrete transaction", artifact.id)
            })?;
        expectations.push(ProtocolBundleCodeCellDepExpectation {
            artifact: artifact.id.clone(),
            transaction_cell_dep_index: u32::try_from(transaction_cell_dep_index)
                .map_err(|_| anyhow::anyhow!("artifact '{}' code CellDep index does not fit in u32", artifact.id))?,
            out_point_tx_hash: artifact.deployment.code_cell_dep.out_point.tx_hash.clone(),
            out_point_index: artifact.deployment.code_cell_dep.out_point.index,
            dep_type: artifact.deployment.code_cell_dep.dep_type.clone(),
            artifact_hash,
            script_code_hash,
            script_hash_type: artifact.deployment.script.hash_type.clone(),
        });
    }
    expectations.sort_by(|left, right| left.artifact.cmp(&right.artifact));
    Ok(expectations)
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

fn parse_raw_hash32(label: &str, value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        bail!("{label} must use canonical 32-byte lowercase hex without a prefix");
    }
    let bytes = hex::decode(value).with_context(|| format!("failed to decode {label}"))?;
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
                        "artifact_hash": "2".repeat(64),
                        "script": type_script.clone(),
                        "code_cell_dep": type_dep.clone(),
                    },
                    "compiler_version": "0.26.0",
                    "edition": "2026",
                    "metadata_schema_version": 71,
                    "artifact_hash": "2".repeat(64),
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

    fn bind_artifact_to_code_data(report: &mut Value, artifact_index: usize, data: &[u8]) {
        let code_hash = hash_hex(data);
        let raw_hash = code_hash.trim_start_matches("0x").to_string();
        report["bundle"]["artifacts"][artifact_index]["artifact_hash"] = Value::String(raw_hash.clone());
        report["bundle"]["artifacts"][artifact_index]["deployment"]["artifact_hash"] = Value::String(raw_hash);
        report["bundle"]["artifacts"][artifact_index]["deployment"]["script"]["code_hash"] = Value::String(code_hash.clone());
        match artifact_index {
            0 => {
                report["bundle"]["transaction"]["inputs"][0]["lock"]["code_hash"] = Value::String(code_hash.clone());
                report["bundle"]["transaction"]["outputs"][0]["lock"]["code_hash"] = Value::String(code_hash);
            }
            1 => {
                report["bundle"]["transaction"]["inputs"][0]["type"]["code_hash"] = Value::String(code_hash.clone());
                report["bundle"]["transaction"]["outputs"][0]["type"]["code_hash"] = Value::String(code_hash);
            }
            _ => panic!("test helper only supports the two-artifact fixture"),
        }
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

    #[test]
    fn live_resolution_replaces_skeleton_capacity_with_exact_node_cells() {
        let report = report();
        let (transaction, materialization) = materialize_protocol_bundle_report(&serde_json::to_vec(&report).unwrap()).unwrap();
        let lock: ScriptWire = serde_json::from_value(report["bundle"]["transaction"]["inputs"][0]["lock"].clone()).unwrap();
        let type_script: ScriptWire = serde_json::from_value(report["bundle"]["transaction"]["inputs"][0]["type"].clone()).unwrap();
        let live_output = CellOutput::new_builder()
            .capacity(120_000_000_000u64)
            .lock(parse_script("live.lock", &lock).unwrap())
            .type_(Some(parse_script("live.type", &type_script).unwrap()).pack())
            .build();
        let live_inputs = vec![(live_output.clone(), Bytes::new())];
        let genesis_hash = format!("0x{}", "0".repeat(64));

        let evidence =
            protocol_bundle_live_resolution_evidence(&transaction, &materialization, "ckb-testnet", &genesis_hash, &live_inputs)
                .unwrap();
        assert_eq!(evidence.capacity_source, "live-node");
        assert_eq!(evidence.fee_shannons, 20_000_000_000);
        assert_eq!(evidence.inputs[0].status, "live-verified");

        let error =
            protocol_bundle_live_resolution_evidence(&transaction, &materialization, "ckb-mainnet", &genesis_hash, &live_inputs)
                .unwrap_err()
                .to_string();
        assert!(error.contains("network identity"), "{error}");

        let changed_inputs = vec![(live_output, Bytes::from_static(b"changed"))];
        let error =
            protocol_bundle_live_resolution_evidence(&transaction, &materialization, "ckb-testnet", &genesis_hash, &changed_inputs)
                .unwrap_err()
                .to_string();
        assert!(error.contains("differs from the ProtocolBundle expectation"), "{error}");
    }

    #[test]
    fn live_dependency_resolution_checks_direct_and_dep_group_code_cells() {
        let auth_code = Bytes::from_static(b"auth-elf");
        let token_code = Bytes::from_static(b"token-elf");
        let mut report = report();
        bind_artifact_to_code_data(&mut report, 0, &auth_code);
        bind_artifact_to_code_data(&mut report, 1, &token_code);
        let code_type_script = Script::new_builder()
            .code_hash([0x77u8; 32].pack())
            .hash_type(ScriptHashType::Data1)
            .args(Bytes::from_static(b"code-type").pack())
            .build();
        let type_code_hash = format!("0x{}", hex::encode(code_type_script.calc_script_hash().as_slice()));
        report["bundle"]["artifacts"][1]["deployment"]["script"]["code_hash"] = Value::String(type_code_hash.clone());
        report["bundle"]["artifacts"][1]["deployment"]["script"]["hash_type"] = Value::String("type".to_string());
        report["bundle"]["transaction"]["inputs"][0]["type"]["code_hash"] = Value::String(type_code_hash.clone());
        report["bundle"]["transaction"]["inputs"][0]["type"]["hash_type"] = Value::String("type".to_string());
        report["bundle"]["transaction"]["outputs"][0]["type"]["code_hash"] = Value::String(type_code_hash);
        report["bundle"]["transaction"]["outputs"][0]["type"]["hash_type"] = Value::String("type".to_string());
        report["bundle"]["artifacts"][1]["deployment"]["code_cell_dep"]["dep_type"] = Value::String("dep_group".to_string());
        report["bundle"]["transaction"]["cell_deps"][1]["dep_type"] = Value::String("dep_group".to_string());
        rebind_bundle_hash(&mut report);

        let (transaction, materialization) = materialize_protocol_bundle_report(&serde_json::to_vec(&report).unwrap()).unwrap();
        let lock: ScriptWire = serde_json::from_value(report["bundle"]["transaction"]["inputs"][0]["lock"].clone()).unwrap();
        let type_script: ScriptWire = serde_json::from_value(report["bundle"]["transaction"]["inputs"][0]["type"].clone()).unwrap();
        let live_input = CellOutput::new_builder()
            .capacity(120_000_000_000u64)
            .lock(parse_script("live.lock", &lock).unwrap())
            .type_(Some(parse_script("live.type", &type_script).unwrap()).pack())
            .build();
        let live_resolution = protocol_bundle_live_resolution_evidence(
            &transaction,
            &materialization,
            "ckb-testnet",
            &format!("0x{}", "0".repeat(64)),
            &[(live_input, Bytes::new())],
        )
        .unwrap();

        let code_cell_output =
            CellOutput::new_builder().capacity(10_000_000_000u64).lock(parse_script("code.lock", &lock).unwrap()).build();
        let deps = transaction.cell_deps();
        let dep_group_member_out_point = OutPoint::new_builder().tx_hash([0x55u8; 32].pack()).index(1u32).build();
        let dep_group_data = vec![dep_group_member_out_point.clone()].pack().as_bytes();
        let observations = vec![
            ProtocolBundleCellDepObservation {
                transaction_cell_dep_index: 0,
                root: ProtocolBundleLiveCellObservation {
                    out_point: deps.get(0).unwrap().out_point(),
                    output: code_cell_output.clone(),
                    data: auth_code,
                },
                dep_group_members: Vec::new(),
            },
            ProtocolBundleCellDepObservation {
                transaction_cell_dep_index: 1,
                root: ProtocolBundleLiveCellObservation {
                    out_point: deps.get(1).unwrap().out_point(),
                    output: code_cell_output.clone(),
                    data: dep_group_data,
                },
                dep_group_members: vec![ProtocolBundleLiveCellObservation {
                    out_point: dep_group_member_out_point,
                    output: code_cell_output.as_builder().type_(Some(code_type_script).pack()).build(),
                    data: token_code,
                }],
            },
        ];
        let evidence =
            protocol_bundle_dependency_resolution_evidence(&transaction, &materialization, &live_resolution, &observations).unwrap();
        assert_eq!(evidence.artifact_count, 2);
        assert_eq!(evidence.unique_cell_dep_count, 2);
        assert!(evidence.cell_deps.iter().all(|dep| dep.status == "live-code-verified"));

        let preparation = protocol_bundle_ready_to_sign_evidence(&transaction, &materialization, &live_resolution, &evidence).unwrap();
        let unsigned_witness = WitnessArgs::from_slice(transaction.witnesses().get(0).unwrap().raw_data().as_ref()).unwrap();
        let signed_witness = unsigned_witness.clone().as_builder().lock(Some(Bytes::from(vec![0xabu8; 65])).pack()).build();
        let signed_transaction = transaction.as_advanced_builder().set_witnesses(vec![signed_witness.as_bytes().pack()]).build();
        let signing = protocol_bundle_signed_transaction_evidence(&transaction, &signed_transaction, &preparation, 1).unwrap();
        assert_eq!(signing.changed_lock_witness_indexes, vec![0]);
        assert_eq!(signing.signature_verification, "pending-node-execution");
        let dry_run = protocol_bundle_signed_dry_run_evidence(
            &signed_transaction,
            &materialization,
            &signing,
            &EstimateCycles { cycles: 45_000u64.into() },
        )
        .unwrap();
        assert_eq!(dry_run.signature_verification, "verified-by-node-execution");
        let tx_pool = protocol_bundle_tx_pool_evidence(
            &signed_transaction,
            &materialization,
            &signing,
            &dry_run,
            &EntryCompleted { cycles: 45_100u64.into(), fee: materialization.fee_shannons.into() },
        )
        .unwrap();
        assert!(tx_pool.tx_pool_accepted);
        let mut submitted_hash = [0u8; 32];
        submitted_hash.copy_from_slice(signed_transaction.hash().as_slice());
        let submission =
            protocol_bundle_submission_evidence(&signed_transaction, &signing, &tx_pool, &H256::from(submitted_hash)).unwrap();
        assert_eq!(submission.state, "SubmittedProtocolBundleTx");
        assert!(!submission.committed);
        let confirmation = protocol_bundle_confirmation_evidence(
            &submission,
            &materialization,
            &materialization.network_chain_id,
            &materialization.network_genesis_hash,
            &format!("0x{}", "6".repeat(64)),
            100,
            2,
            &format!("0x{}", "7".repeat(64)),
            104,
            5,
            1,
        )
        .unwrap();
        assert_eq!(confirmation.state, "ConfirmedProtocolBundleTx");
        assert_eq!(confirmation.confirmation_count, 5);
        assert_eq!(confirmation.reorgs_observed, 1);
        assert!(confirmation.committed);
        assert_eq!(confirmation.finality_claim, "bounded-observation-not-absolute-finality");

        let error = protocol_bundle_confirmation_evidence(
            &submission,
            &materialization,
            &materialization.network_chain_id,
            &materialization.network_genesis_hash,
            &format!("0x{}", "6".repeat(64)),
            100,
            2,
            &format!("0x{}", "7".repeat(64)),
            103,
            5,
            0,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("below required depth"), "{error}");

        let error = protocol_bundle_confirmation_evidence(
            &submission,
            &materialization,
            "another-chain",
            &materialization.network_genesis_hash,
            &format!("0x{}", "6".repeat(64)),
            100,
            2,
            &format!("0x{}", "7".repeat(64)),
            104,
            5,
            0,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("network identity"), "{error}");

        let error = protocol_bundle_submission_evidence(&signed_transaction, &signing, &tx_pool, &H256::from([0xffu8; 32]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not bound"), "{error}");

        let changed_payload = unsigned_witness
            .as_builder()
            .lock(Some(Bytes::from(vec![0xabu8; 65])).pack())
            .input_type(Some(Bytes::from_static(b"changed-entry-payload")).pack())
            .build();
        let changed_payload_transaction =
            transaction.as_advanced_builder().set_witnesses(vec![changed_payload.as_bytes().pack()]).build();
        let error = protocol_bundle_signed_transaction_evidence(&transaction, &changed_payload_transaction, &preparation, 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("compiler-owned witness fields"), "{error}");

        let mut changed_live_resolution = live_resolution.clone();
        changed_live_resolution.inputs[0].data_hash = format!("0x{}", "f".repeat(64));
        let error =
            protocol_bundle_dependency_resolution_evidence(&transaction, &materialization, &changed_live_resolution, &observations)
                .unwrap_err()
                .to_string();
        assert!(error.contains("does not preserve every exact input observation"), "{error}");

        let mut changed = observations;
        changed[1].dep_group_members[0].data = Bytes::from_static(b"changed-token-elf");
        let error = protocol_bundle_dependency_resolution_evidence(&transaction, &materialization, &live_resolution, &changed)
            .unwrap_err()
            .to_string();
        assert!(error.contains("admitted ELF is absent"), "{error}");
    }
}
