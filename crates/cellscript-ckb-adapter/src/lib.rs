use anyhow::{bail, Result};
use ckb_hash::blake2b_256;
use ckb_jsonrpc_types::{
    EntryCompleted, EstimateCycles, OutputsValidator, Status, Transaction as RpcTransaction, TransactionWithStatusResponse,
};
use ckb_sdk::{core::TransactionBuilder, traits::CellDepResolver, unlock::SecpSighashScriptSigner, CkbRpcClient};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionView},
    packed::{self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H160, H256,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
};

pub mod policy_witness;
mod protocol_bundle;

pub use protocol_bundle::{
    materialize_protocol_bundle_report, protocol_bundle_dry_run_evidence, protocol_bundle_live_resolution_evidence,
    ProtocolBundleDryRunEvidence, ProtocolBundleGroupDryRunEvidence, ProtocolBundleIndexBinding, ProtocolBundleLiveInputEvidence,
    ProtocolBundleLiveInputExpectation, ProtocolBundleLiveResolutionEvidence, ProtocolBundleMaterializationEvidence,
    ProtocolBundleScriptGroupEvidence,
};

pub const ACTION_PLAN_POLICY: &str = "cellscript-action-builder-plan-v1";
pub const ADAPTER_CONTRACT_SCHEMA: &str = "cellscript-ckb-adapter-contract-v0.19";
pub const ACTION_ACCEPTANCE_REPORT_SCHEMA: &str = "cellscript-ckb-action-acceptance-report-v0.19";
pub const ACTION_SCAN_SELECTORS_SCHEMA: &str = "cellscript-action-scan-selectors-v0.21";
pub const SCRIPT_EVIDENCE_SCHEMA: &str = "cellscript-ckb-script-evidence-v0.19";
pub const SCRIPT_REF_EVIDENCE_SCHEMA: &str = "cellscript-ckb-script-ref-evidence-v0.19";
pub const SCRIPT_CODE_DEP_EVIDENCE_SCHEMA: &str = "cellscript-ckb-script-code-dep-evidence-v0.19";
pub const DEPLOYMENT_MANIFEST_SCHEMA: &str = "cellscript-ckb-deployment-manifest-v0.19";
pub const DEPLOY_EVIDENCE_SCHEMA: &str = "cellscript-ckb-deploy-evidence-v0.19";

#[derive(Debug, Clone, Deserialize)]
pub struct ActionPlan {
    pub policy: String,
    pub action: String,
    pub artifact_hash: Option<String>,
    #[serde(default)]
    pub metadata_hash: Option<String>,
    #[serde(default)]
    pub action_scan_selectors: Option<ActionScanSelectors>,
    pub transaction_draft: TransactionDraft,
    pub adapter_contract: AdapterContract,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransactionDraft {
    pub state: String,
    pub can_submit: bool,
    pub requires_packed_materialization: bool,
    #[serde(default)]
    pub metadata_hash: Option<String>,
    #[serde(default)]
    pub fee_shannons: Option<u64>,
    #[serde(default)]
    pub inputs: Vec<ActionInputDraft>,
    #[serde(default)]
    pub outputs: Vec<ActionOutputDraft>,
    #[serde(default)]
    pub outputs_data: Vec<String>,
    #[serde(default)]
    pub witnesses: Vec<ActionWitnessDraft>,
    #[serde(default)]
    pub cell_deps: Vec<ActionCellDepDraft>,
    #[serde(default)]
    pub header_deps: Vec<String>,
    #[serde(default)]
    pub lineage: Vec<ActionLineageDraft>,
    #[serde(default, alias = "scanSelectorEvidence")]
    pub scan_selector_evidence: Vec<ScanSelectorEvidenceDraft>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionScanSelectors {
    pub schema: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub selector_count: Option<usize>,
    #[serde(default)]
    pub selectors: Vec<ActionScanSelectorDraft>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionScanSelectorDraft {
    #[serde(default)]
    pub selector_index: Option<usize>,
    #[serde(default)]
    pub ckb_source: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub feature: Option<String>,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub script_field: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanSelectorEvidenceDraft {
    pub selector_index: usize,
    pub status: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub binding: Option<String>,
    #[serde(default)]
    pub feature: Option<String>,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub script_field: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdapterContract {
    pub schema: String,
    pub compiler_core_dependency: String,
    pub transaction_realizer: String,
    pub resolved_tx_required_fields: Vec<String>,
    #[serde(default)]
    pub acceptance_report_template: Option<AcceptanceReportTemplate>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcceptanceReportTemplate {
    #[serde(default)]
    pub metadata_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionInputDraft {
    pub previous_output: OutPointDraft,
    #[serde(default)]
    pub since: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionOutputDraft {
    pub capacity: Value,
    pub lock: ScriptDraft,
    #[serde(rename = "type", default)]
    pub type_script: Option<ScriptDraft>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptDraft {
    pub code_hash: String,
    pub hash_type: String,
    #[serde(default)]
    pub args: String,
    #[serde(default)]
    pub args_parts: Vec<ScriptArgsPartDraft>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptArgsPartDraft {
    #[serde(alias = "encoding")]
    pub kind: String,
    pub value: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionCellDepDraft {
    pub out_point: OutPointDraft,
    pub dep_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutPointDraft {
    pub tx_hash: String,
    pub index: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionLineageDraft {
    pub from: OutPointDraft,
    pub to_output_index: u32,
    pub relation: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ActionWitnessDraft {
    Hex(String),
    WitnessArgs {
        #[serde(default)]
        lock: Option<String>,
        #[serde(default)]
        input_type: Option<String>,
        #[serde(default)]
        output_type: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ResolvedActionTx {
    pub metadata_hash: String,
    pub artifact_hash: Option<String>,
    pub action_selector: String,
    pub inputs: Vec<CellInput>,
    pub outputs: Vec<CellOutputWithData>,
    pub witnesses: Vec<WitnessArgs>,
    pub cell_deps: Vec<CellDep>,
    pub header_deps: Vec<Byte32>,
    pub lineage: Vec<LiveOutputLineage>,
    pub fee_shannons: u64,
}

#[derive(Debug, Clone)]
pub struct CellOutputWithData {
    pub output: CellOutput,
    pub data: Bytes,
}

#[derive(Debug, Clone)]
pub struct LiveOutputLineage {
    pub from: packed::OutPoint,
    pub to_output_index: u32,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LineageEvidence {
    pub from_tx_hash: Vec<u8>,
    pub from_index: u32,
    pub to_output_index: u32,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionPreview {
    pub schema: &'static str,
    pub action: String,
    pub summary: String,
    pub consumes: Vec<PreviewCell>,
    pub creates: Vec<PreviewCell>,
    pub transitions: Vec<PreviewTransition>,
    pub witnesses: PreviewWitnesses,
    pub warnings: Vec<String>,
    pub estimated_fee: Option<u64>,
    pub required_signers: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewCell {
    pub role: &'static str,
    pub out_point_tx_hash: Option<Vec<u8>>,
    pub out_point_index: Option<u32>,
    pub output_index: Option<u32>,
    pub capacity_shannons: Option<u64>,
    pub data_len: Option<usize>,
    pub lock_hash: Option<Vec<u8>>,
    pub type_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewTransition {
    pub from_tx_hash: Vec<u8>,
    pub from_index: u32,
    pub to_output_index: u32,
    pub relation: String,
    pub changes: Vec<String>,
    pub preserves: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewWitnesses {
    pub selector: String,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct ScriptSpec {
    pub code_hash: [u8; 32],
    pub hash_type: ScriptHashType,
    pub args: Bytes,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptEvidence {
    pub schema: &'static str,
    pub hash_type: String,
    pub code_hash: Vec<u8>,
    pub args_len: usize,
    pub args_hash: Vec<u8>,
    pub script_hash: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptArgsPattern {
    Exact(Bytes),
    Prefix(Bytes),
    Suffix(Bytes),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ScriptRole {
    Lock,
    Type,
}

#[derive(Debug, Clone)]
pub struct ScriptRef {
    pub role: ScriptRole,
    pub script: Script,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptRefEvidence {
    pub schema: &'static str,
    pub role: ScriptRole,
    pub hash_type_byte: u8,
    pub code_hash: Vec<u8>,
    pub args_len: usize,
    pub args_hash: Vec<u8>,
    pub script_hash: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ScriptCodeDep {
    pub code_hash: [u8; 32],
    pub hash_type: ScriptHashType,
    pub out_point: packed::OutPoint,
    pub dep_type: DepType,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptCodeDepEvidence {
    pub schema: &'static str,
    pub code_hash: Vec<u8>,
    pub hash_type_byte: u8,
    pub out_point_tx_hash: Vec<u8>,
    pub out_point_index: u32,
    pub dep_type: String,
}

pub const ENTRY_WITNESS_PLACEMENT_ABI: &str = "cellscript-witnessargs-input-type-v2";
pub const ENTRY_WITNESS_PAYLOAD_MAGIC: &[u8; 8] = b"CSARGv1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EntryWitnessPlacementAbi {
    WitnessArgsInputTypeV2,
}

impl EntryWitnessPlacementAbi {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WitnessArgsInputTypeV2 => ENTRY_WITNESS_PLACEMENT_ABI,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedActionEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub metadata_hash: String,
    pub artifact_hash: Option<String>,
    pub action_selector: String,
    pub cell_deps: usize,
    pub inputs: usize,
    pub outputs: usize,
    pub outputs_data: usize,
    pub witnesses: usize,
    pub lineage: Vec<LineageEvidence>,
    pub occupied_capacity_shannons: u64,
    pub serialized_tx_size_bytes: usize,
    pub fee_shannons: u64,
    pub ckb_vm_execution: bool,
    pub tx_pool_acceptance: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcceptedActionReport {
    pub schema: &'static str,
    pub state: &'static str,
    pub metadata_hash: String,
    pub artifact_hash: Option<String>,
    pub action_selector: String,
    pub ckb_vm_execution: bool,
    pub estimate_cycles: u64,
    pub tx_pool_acceptance: bool,
    pub tx_pool_cycles: u64,
    pub serialized_tx_size_bytes: usize,
    pub occupied_capacity_shannons: u64,
    pub fee_shannons: u64,
    pub submitted_tx_hash: Option<Vec<u8>>,
    pub lineage: Vec<LineageEvidence>,
    pub known_limitations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentManifest {
    pub schema: String,
    pub version: u32,
    pub deployments: Vec<DeploymentRef>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentRef {
    pub name: String,
    pub code_hash: String,
    pub hash_type: String,
    pub args: String,
    pub dep_type: String,
    pub out_point: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeploymentEvidence {
    pub schema: &'static str,
    pub deployments: usize,
    pub names: Vec<String>,
}

pub fn load_action_plan(path: impl AsRef<Path>) -> Result<ActionPlan> {
    parse_action_plan(&fs::read(path)?)
}

pub fn parse_action_plan(bytes: &[u8]) -> Result<ActionPlan> {
    let plan: ActionPlan = serde_json::from_slice(bytes)?;
    if plan.policy != ACTION_PLAN_POLICY {
        bail!("unsupported action plan policy {}", plan.policy);
    }
    if plan.transaction_draft.state != "ActionPlan" {
        bail!("compiler output must be ActionPlan, got {}", plan.transaction_draft.state);
    }
    if plan.transaction_draft.can_submit {
        bail!("compiler ActionPlan must not be directly submittable");
    }
    if !plan.transaction_draft.requires_packed_materialization {
        bail!("ActionPlan must require packed CKB materialization");
    }
    if plan.adapter_contract.schema != ADAPTER_CONTRACT_SCHEMA {
        bail!("unsupported adapter contract {}", plan.adapter_contract.schema);
    }
    if plan.adapter_contract.compiler_core_dependency != "no-ckb-sdk-rust" {
        bail!("compiler core must remain free of ckb-sdk-rust");
    }
    for required in ["outputs_data", "cell_deps", "lineage"] {
        if !plan.adapter_contract.resolved_tx_required_fields.iter().any(|field| field == required) {
            bail!("adapter contract is missing required field {required}");
        }
    }
    validate_action_scan_selectors_schema(&plan)?;
    Ok(plan)
}

fn validate_action_scan_selectors_schema(plan: &ActionPlan) -> Result<()> {
    let Some(scan_selectors) = plan.action_scan_selectors.as_ref() else {
        return Ok(());
    };
    if scan_selectors.schema != ACTION_SCAN_SELECTORS_SCHEMA {
        bail!("unsupported action_scan_selectors schema {}", scan_selectors.schema);
    }
    if scan_selectors.source.as_deref() != Some("transaction_runtime_input_requirements") {
        bail!("action_scan_selectors.source must be transaction_runtime_input_requirements, got {:?}", scan_selectors.source);
    }
    if let Some(selector_count) = scan_selectors.selector_count
        && selector_count != scan_selectors.selectors.len()
    {
        bail!(
            "action_scan_selectors.selector_count {} does not match selectors length {}",
            selector_count,
            scan_selectors.selectors.len()
        );
    }
    let mut indexes = HashMap::new();
    for (fallback_index, selector) in scan_selectors.selectors.iter().enumerate() {
        let selector_index = selector.selector_index.unwrap_or(fallback_index);
        if indexes.insert(selector_index, fallback_index).is_some() {
            bail!("action_scan_selectors contains duplicate selector_index {selector_index}");
        }
    }
    Ok(())
}

pub fn load_deployment_manifest(path: impl AsRef<Path>) -> Result<DeploymentManifest> {
    parse_deployment_manifest(&fs::read(path)?)
}

pub fn parse_deployment_manifest(bytes: &[u8]) -> Result<DeploymentManifest> {
    let manifest: DeploymentManifest = serde_json::from_slice(bytes)?;
    if manifest.schema != DEPLOYMENT_MANIFEST_SCHEMA {
        bail!("unsupported deployment manifest schema {}", manifest.schema);
    }
    if manifest.version != 1 {
        bail!("unsupported deployment manifest version {}", manifest.version);
    }
    for deployment in &manifest.deployments {
        if deployment.name.trim().is_empty() {
            bail!("deployment name must not be empty");
        }
        if deployment.code_hash.trim().is_empty() {
            bail!("deployment {} is missing code_hash", deployment.name);
        }
        if deployment.hash_type.trim().is_empty() {
            bail!("deployment {} is missing hash_type", deployment.name);
        }
        if deployment.dep_type.trim().is_empty() {
            bail!("deployment {} is missing dep_type", deployment.name);
        }
        if deployment.out_point.trim().is_empty() {
            bail!("deployment {} is missing out_point", deployment.name);
        }
    }
    Ok(manifest)
}

pub fn deployment_evidence(manifest: &DeploymentManifest) -> DeploymentEvidence {
    DeploymentEvidence {
        schema: DEPLOYMENT_MANIFEST_SCHEMA,
        deployments: manifest.deployments.len(),
        names: manifest.deployments.iter().map(|deployment| deployment.name.clone()).collect(),
    }
}

// ---- Deploy probe types ----

/// Specification for deploying a compiled CellScript artifact as an on-chain code cell.
///
/// The caller provides the artifact binary, the deployer lock script, and the
/// capacity input cell. The adapter constructs either a TYPE_ID-backed code Cell
/// or an immutable data Cell, validates occupied capacity, and builds an unsigned
/// CKB transaction.
#[derive(Debug, Clone)]
pub struct DeployArtifactSpec {
    /// Name for the deployment (used in manifest and evidence).
    pub name: String,
    /// Raw compiled artifact bytes (RISC-V binary / ELF).
    pub artifact_binary: Bytes,
    /// Hash of the artifact binary (hex, 64 chars). Must match the compiler output.
    pub artifact_hash: String,
    /// Lock script for the deployed code cell (and change output).
    pub deployer_lock: Script,
    /// Capacity input cell that funds the deployment.
    pub capacity_input: CellInput,
    /// Capacity of the input cell in shannons.
    pub capacity_input_shannons: u64,
    /// Optional data of the capacity input cell (for change calculation).
    pub capacity_input_data: Bytes,
    /// Hash type used by Scripts that execute this deployed artifact.
    /// `Type` requires a code-cell Type Script; data hash types use the artifact data hash.
    pub type_id_hash_type: ScriptHashType,
    /// Optional explicit type script for the code cell.
    /// When set, uses this Type Script on the code Cell.
    /// When `None` and `type_id_hash_type` is `Type`, the canonical CKB TYPE_ID
    /// Script is constructed from the first input. When `None` and a data hash
    /// type is selected, the deployment is data-only.
    pub type_script: Option<Script>,
    /// CellDeps required by the deployed artifact.
    pub cell_deps: Vec<CellDep>,
    /// HeaderDeps required by the deployed artifact.
    pub header_deps: Vec<Byte32>,
    /// Fee in shannons to allocate from the input capacity.
    pub fee_shannons: u64,
}

/// Resolved deploy transaction with the code cell output and change output.
#[derive(Debug, Clone)]
pub struct ResolvedDeployTx {
    pub name: String,
    pub artifact_hash: String,
    pub deployer_lock: Script,
    pub code_output: CellOutputWithData,
    pub change_output: CellOutputWithData,
    pub capacity_input: CellInput,
    pub cell_deps: Vec<CellDep>,
    pub header_deps: Vec<Byte32>,
    pub witnesses: Vec<WitnessArgs>,
    pub type_id_args: [u8; 32],
    pub fee_shannons: u64,
}

/// Evidence record for a resolved deploy transaction (headless, no node interaction).
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedDeployEvidence {
    pub schema: &'static str,
    pub state: &'static str,
    pub name: String,
    pub artifact_hash: String,
    pub code_output_index: u32,
    pub change_output_index: u32,
    pub type_id_args: Vec<u8>,
    pub code_hash: Vec<u8>,
    pub hash_type: String,
    pub occupied_capacity_shannons: u64,
    pub change_capacity_shannons: u64,
    pub serialized_tx_size_bytes: usize,
    pub fee_shannons: u64,
    pub cell_deps: usize,
    pub ckb_vm_execution: bool,
    pub tx_pool_acceptance: bool,
}

/// Build an unsigned CKB transaction that deploys a CellScript artifact as an
/// on-chain code Cell.
///
/// The function:
/// 1. Computes TYPE_ID args when `type_id_hash_type` is `Type`.
/// 2. Constructs the optional Type Script and lock script for the code Cell.
/// 3. Calculates occupied capacity for the code cell from artifact size.
/// 4. Constructs a change output with remaining capacity minus fee.
/// 5. Validates that both outputs meet occupied-capacity floors.
/// 6. Assembles the transaction and returns evidence.
///
/// This is headless: no RPC, no live-cell selection, no signing. The caller
/// provides a pre-resolved capacity input and every required CellDep. The first
/// witness contains the standard 65-byte zeroed secp-sighash placeholder; an
/// external signer must replace it before submission.
pub fn build_deploy_transaction(spec: &DeployArtifactSpec) -> Result<(TransactionView, ResolvedDeployEvidence)> {
    // Validate artifact is non-empty.
    if spec.artifact_binary.is_empty() {
        bail!("artifact binary must be non-empty");
    }
    let calculated_artifact_hash = hex::encode(blake2b_256(&spec.artifact_binary));
    let supplied_artifact_hash = spec.artifact_hash.strip_prefix("0x").unwrap_or(&spec.artifact_hash);
    if !supplied_artifact_hash.eq_ignore_ascii_case(&calculated_artifact_hash) {
        bail!("artifact hash mismatch: supplied {}, calculated {}", spec.artifact_hash, calculated_artifact_hash);
    }
    if spec.capacity_input_shannons == 0 {
        bail!("capacity input must have non-zero capacity");
    }

    // Step 1+2: Construct the optional type script for the code cell.
    let calculated_type_id_args = type_id_args_from_first_input(&spec.capacity_input, 0);
    let type_script = if let Some(ref script) = spec.type_script {
        Some(script.clone())
    } else if spec.type_id_hash_type == ScriptHashType::Type {
        let mut type_id_code_hash = [0u8; 32];
        type_id_code_hash[25..].copy_from_slice(b"TYPE_ID");
        Some(construct_script(&ScriptSpec::new(type_id_code_hash, ScriptHashType::Type, calculated_type_id_args.to_vec())))
    } else {
        None
    };
    let type_id_args = type_script.as_ref().map(|script| script.args().raw_data().to_vec()).unwrap_or_default();

    // Step 3: Build the code Cell output with the optional Type Script.
    let code_data_capacity = Capacity::bytes(spec.artifact_binary.len())?;
    // We need to compute the actual code_hash which is blake2b of the artifact.
    let data_hash = blake2b_256(&spec.artifact_binary);
    // Build the code output with a placeholder capacity (we'll compute exact occupied first).
    let code_output_builder = CellOutput::new_builder().lock(spec.deployer_lock.clone()).type_(type_script.clone().pack());
    // Compute occupied capacity for the code cell.
    let code_occupied = code_output_builder.clone().build().occupied_capacity(code_data_capacity)?;
    let code_capacity_shannons = code_occupied.as_u64();

    // Build the final code output with the exact occupied capacity.
    let code_output = code_output_builder.capacity(code_capacity_shannons).build();

    // Step 4: Build change output.
    let change_capacity_shannons = spec
        .capacity_input_shannons
        .checked_sub(code_capacity_shannons)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "input capacity {} shannons is insufficient for code cell occupied capacity {} shannons",
                spec.capacity_input_shannons,
                code_capacity_shannons
            )
        })?
        .checked_sub(spec.fee_shannons)
        .ok_or_else(|| {
            anyhow::anyhow!("remaining capacity after code cell is insufficient for fee of {} shannons", spec.fee_shannons)
        })?;

    // Validate change output meets its own occupied capacity floor.
    let change_data_capacity = Capacity::bytes(spec.capacity_input_data.len())?;
    let change_output = CellOutput::new_builder().capacity(change_capacity_shannons).lock(spec.deployer_lock.clone()).build();
    let change_occupied = change_output.occupied_capacity(change_data_capacity)?;
    if change_capacity_shannons < change_occupied.as_u64() {
        bail!(
            "change capacity {} shannons is below occupied capacity {} shannons",
            change_capacity_shannons,
            change_occupied.as_u64()
        );
    }

    // Step 5: Assemble the transaction.
    let mut builder = TransactionBuilder::default();
    builder.input(spec.capacity_input.clone());
    builder.output(code_output.clone());
    builder.output_data(spec.artifact_binary.clone().pack());
    builder.output(change_output.clone());
    builder.output_data(spec.capacity_input_data.clone().pack());
    for dep in &spec.cell_deps {
        builder.dedup_cell_dep(dep.clone());
    }
    for dep in &spec.header_deps {
        builder.dedup_header_dep(dep.clone());
    }
    // Standard secp256k1-sighash-all signing placeholder. External wallets sign
    // against this shape and replace the zero bytes with a recoverable signature.
    let placeholder_witness = WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; 65])).pack()).build();
    builder.witness(placeholder_witness.as_bytes().pack());

    let tx = builder.build();
    let serialized_tx_size_bytes = tx.data().serialized_size_in_block();
    // CKB's default relay policy is 1,000 shannons per 1,000 bytes, so the
    // numeric minimum at that rate equals the serialized byte count.
    let minimum_fee_shannons = u64::try_from(serialized_tx_size_bytes)?;
    if spec.fee_shannons < minimum_fee_shannons {
        bail!(
            "fee {} shannons is below the 1,000 shannons/KB policy floor of {} shannons for a {}-byte transaction",
            spec.fee_shannons,
            minimum_fee_shannons,
            serialized_tx_size_bytes
        );
    }

    // Verify outputs/outputs_data pairing.
    assert_eq!(tx.outputs().len(), 2, "deploy tx must have 2 outputs");
    assert_eq!(tx.outputs_data().len(), 2, "deploy tx must have 2 outputs_data entries");

    let code_hash = if spec.type_id_hash_type == ScriptHashType::Type {
        type_script
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("type-hash deployment requires a code-cell Type Script"))?
            .calc_script_hash()
            .as_slice()
            .to_vec()
    } else {
        data_hash.to_vec()
    };
    let evidence = ResolvedDeployEvidence {
        schema: DEPLOY_EVIDENCE_SCHEMA,
        state: "ResolvedDeployTx",
        name: spec.name.clone(),
        artifact_hash: calculated_artifact_hash,
        code_output_index: 0,
        change_output_index: 1,
        type_id_args,
        code_hash,
        hash_type: format!("{:?}", spec.type_id_hash_type).to_ascii_lowercase(),
        occupied_capacity_shannons: code_capacity_shannons,
        change_capacity_shannons,
        serialized_tx_size_bytes,
        fee_shannons: spec.fee_shannons,
        cell_deps: spec.cell_deps.len(),
        ckb_vm_execution: false,
        tx_pool_acceptance: false,
    };
    Ok((tx, evidence))
}

/// Build a deployment manifest from a completed deploy evidence record.
///
/// This creates the `DeploymentManifest` that records the on-chain code cell
/// reference after a successful deployment. The caller must provide the actual
/// tx_hash and output_index from the committed transaction.
pub fn build_deployment_manifest_from_evidence(
    evidence: &ResolvedDeployEvidence,
    tx_hash: &[u8; 32],
    output_index: u32,
) -> DeploymentManifest {
    let code_hash_hex = evidence.code_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let out_point = format!("0x{}:{}", tx_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>(), output_index);
    DeploymentManifest {
        schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
        version: 1,
        deployments: vec![DeploymentRef {
            name: evidence.name.clone(),
            code_hash: format!("0x{}", code_hash_hex),
            hash_type: evidence.hash_type.clone(),
            // Deployment manifests bind code identity and CellDep location.
            // Concrete asset Script args are resolved separately from an
            // ActionPlan or a verified live asset Cell.
            args: "0x".to_string(),
            dep_type: "code".to_string(),
            out_point,
        }],
    }
}

pub fn resolve_materialized_action_plan(plan: &ActionPlan) -> Result<ResolvedActionTx> {
    resolve_materialized_action_plan_with_manifest(plan, None)
}

pub fn resolve_materialized_action_plan_with_manifest(
    plan: &ActionPlan,
    manifest: Option<&DeploymentManifest>,
) -> Result<ResolvedActionTx> {
    if !has_materialized_action_draft(&plan.transaction_draft) {
        bail!(
            "ActionPlan '{}' is a semantic template and contains no materialized CKB inputs/outputs; \
             a builder runtime must resolve live cells and fill transaction_draft.inputs, outputs, outputs_data, witnesses, cell_deps, and lineage",
            plan.action
        );
    }
    if plan.transaction_draft.outputs.len() != plan.transaction_draft.outputs_data.len() {
        bail!(
            "materialized ActionPlan outputs/outputs_data length mismatch: {} outputs, {} outputs_data",
            plan.transaction_draft.outputs.len(),
            plan.transaction_draft.outputs_data.len()
        );
    }
    validate_scan_selector_evidence(plan)?;

    let metadata_hash = plan
        .metadata_hash
        .clone()
        .or_else(|| plan.transaction_draft.metadata_hash.clone())
        .or_else(|| plan.adapter_contract.acceptance_report_template.as_ref().and_then(|template| template.metadata_hash.clone()))
        .ok_or_else(|| anyhow::anyhow!("materialized ActionPlan is missing metadata_hash"))?;

    let inputs = plan.transaction_draft.inputs.iter().map(parse_action_input_draft).collect::<Result<Vec<_>>>()?;
    let outputs = plan
        .transaction_draft
        .outputs
        .iter()
        .zip(plan.transaction_draft.outputs_data.iter())
        .enumerate()
        .map(|(index, (output, data))| parse_action_output_draft(index, output, data))
        .collect::<Result<Vec<_>>>()?;
    let witnesses = plan.transaction_draft.witnesses.iter().map(parse_action_witness_draft).collect::<Result<Vec<_>>>()?;
    let mut cell_deps = plan.transaction_draft.cell_deps.iter().map(parse_action_cell_dep_draft).collect::<Result<Vec<_>>>()?;
    if let Some(manifest) = manifest {
        add_manifest_cell_deps(&mut cell_deps, &outputs, manifest)?;
    }
    let header_deps = plan
        .transaction_draft
        .header_deps
        .iter()
        .enumerate()
        .map(|(index, dep)| parse_byte32_hex(&format!("header_deps[{index}]"), dep).map(|bytes| bytes.pack()))
        .collect::<Result<Vec<_>>>()?;
    let lineage = plan.transaction_draft.lineage.iter().map(parse_action_lineage_draft).collect::<Result<Vec<_>>>()?;

    Ok(ResolvedActionTx {
        metadata_hash,
        artifact_hash: plan.artifact_hash.clone(),
        action_selector: plan.action.clone(),
        inputs,
        outputs,
        witnesses,
        cell_deps,
        header_deps,
        lineage,
        fee_shannons: plan.transaction_draft.fee_shannons.unwrap_or(0),
    })
}

fn validate_scan_selector_evidence(plan: &ActionPlan) -> Result<()> {
    let evidence = &plan.transaction_draft.scan_selector_evidence;
    let Some(scan_selectors) = plan.action_scan_selectors.as_ref() else {
        if !evidence.is_empty() {
            bail!("transaction_draft.scan_selector_evidence was supplied without action_scan_selectors");
        }
        return Ok(());
    };
    if scan_selectors.selectors.is_empty() {
        if !evidence.is_empty() {
            bail!("transaction_draft.scan_selector_evidence was supplied but action_scan_selectors declares no selectors");
        }
        return Ok(());
    }
    if evidence.len() != scan_selectors.selectors.len() {
        bail!(
            "transaction_draft.scan_selector_evidence length {} does not match action_scan_selectors.selector_count {}",
            evidence.len(),
            scan_selectors.selectors.len()
        );
    }
    let selectors_by_index = scan_selectors
        .selectors
        .iter()
        .enumerate()
        .map(|(fallback_index, selector)| (selector.selector_index.unwrap_or(fallback_index), selector))
        .collect::<HashMap<_, _>>();
    let mut seen_selector_indexes = HashSet::new();
    for item in evidence {
        if !seen_selector_indexes.insert(item.selector_index) {
            bail!("transaction_draft.scan_selector_evidence contains duplicate selector_index {}", item.selector_index);
        }
        let selector = selectors_by_index.get(&item.selector_index).ok_or_else(|| {
            anyhow::anyhow!(
                "transaction_draft.scan_selector_evidence selector_index {} is not declared by action_scan_selectors",
                item.selector_index
            )
        })?;
        if item.status != "resolved" {
            bail!(
                "transaction_draft.scan_selector_evidence status for selector {} must be 'resolved', got '{}'",
                item.selector_index,
                item.status
            );
        }
        compare_scan_selector_evidence_field(item.selector_index, "source", item.source.as_deref(), selector.ckb_source.as_deref())?;
        compare_scan_selector_evidence_field(item.selector_index, "role", item.role.as_deref(), selector.role.as_deref())?;
        compare_scan_selector_evidence_field(item.selector_index, "binding", item.binding.as_deref(), selector.binding.as_deref())?;
        compare_scan_selector_evidence_field(item.selector_index, "feature", item.feature.as_deref(), selector.feature.as_deref())?;
        compare_scan_selector_evidence_field(
            item.selector_index,
            "component",
            item.component.as_deref(),
            selector.component.as_deref(),
        )?;
        compare_scan_selector_evidence_field(
            item.selector_index,
            "script_field",
            item.script_field.as_deref(),
            selector.script_field.as_deref(),
        )?;
    }
    for selector_index in selectors_by_index.keys() {
        if !seen_selector_indexes.contains(selector_index) {
            bail!(
                "transaction_draft.scan_selector_evidence is missing selector_index {} declared by action_scan_selectors",
                selector_index
            );
        }
    }
    Ok(())
}

fn compare_scan_selector_evidence_field(
    selector_index: usize,
    field: &str,
    actual: Option<&str>,
    expected: Option<&str>,
) -> Result<()> {
    match (actual, expected) {
        (Some(actual), Some(expected)) if actual == expected => Ok(()),
        (Some(actual), Some(expected)) => bail!(
            "transaction_draft.scan_selector_evidence.{field} mismatch for selector {selector_index}: got '{actual}', expected '{expected}'"
        ),
        (None, Some(expected)) => bail!(
            "transaction_draft.scan_selector_evidence.{field} missing for selector {selector_index}: expected '{expected}'"
        ),
        (Some(actual), None) => bail!(
            "transaction_draft.scan_selector_evidence.{field} unexpected for selector {selector_index}: got '{actual}', expected null"
        ),
        (None, None) => Ok(()),
    }
}

fn has_materialized_action_draft(draft: &TransactionDraft) -> bool {
    !draft.inputs.is_empty()
        || !draft.outputs.is_empty()
        || !draft.outputs_data.is_empty()
        || !draft.witnesses.is_empty()
        || !draft.cell_deps.is_empty()
        || !draft.header_deps.is_empty()
        || !draft.lineage.is_empty()
}

fn parse_action_input_draft(input: &ActionInputDraft) -> Result<CellInput> {
    let previous_output = parse_out_point_draft("inputs[].previous_output", &input.previous_output)?;
    let since = parse_optional_u64("inputs[].since", input.since.as_ref())?.unwrap_or(0);
    Ok(CellInput::new_builder().previous_output(previous_output).since(since).build())
}

fn parse_action_output_draft(index: usize, output: &ActionOutputDraft, data: &str) -> Result<CellOutputWithData> {
    let capacity = parse_required_u64(&format!("outputs[{index}].capacity"), &output.capacity)?;
    let lock = parse_script_draft(&format!("outputs[{index}].lock"), &output.lock)?;
    let type_script =
        output.type_script.as_ref().map(|script| parse_script_draft(&format!("outputs[{index}].type"), script)).transpose()?;
    let mut builder = CellOutput::new_builder().capacity(capacity).lock(lock);
    if let Some(script) = type_script {
        builder = builder.type_(Some(script).pack());
    }
    Ok(CellOutputWithData { output: builder.build(), data: Bytes::from(parse_hex_bytes(&format!("outputs_data[{index}]"), data)?) })
}

fn parse_action_witness_draft(witness: &ActionWitnessDraft) -> Result<WitnessArgs> {
    match witness {
        ActionWitnessDraft::Hex(hex) => {
            let bytes = parse_hex_bytes("witnesses[]", hex)?;
            WitnessArgs::from_slice(&bytes).map_err(|error| anyhow::anyhow!("invalid serialized WitnessArgs in witnesses[]: {error}"))
        }
        ActionWitnessDraft::WitnessArgs { lock, input_type, output_type } => {
            let mut builder = WitnessArgs::new_builder();
            if let Some(lock) = lock {
                builder = builder.lock(Some(Bytes::from(parse_hex_bytes("witnesses[].lock", lock)?)).pack());
            }
            if let Some(input_type) = input_type {
                builder = builder.input_type(Some(Bytes::from(parse_hex_bytes("witnesses[].input_type", input_type)?)).pack());
            }
            if let Some(output_type) = output_type {
                builder = builder.output_type(Some(Bytes::from(parse_hex_bytes("witnesses[].output_type", output_type)?)).pack());
            }
            Ok(builder.build())
        }
    }
}

fn parse_action_cell_dep_draft(dep: &ActionCellDepDraft) -> Result<CellDep> {
    let out_point = parse_out_point_draft("cell_deps[].out_point", &dep.out_point)?;
    let dep_type = parse_dep_type("cell_deps[].dep_type", &dep.dep_type)?;
    Ok(CellDep::new_builder().out_point(out_point).dep_type(dep_type).build())
}

fn parse_action_lineage_draft(edge: &ActionLineageDraft) -> Result<LiveOutputLineage> {
    Ok(LiveOutputLineage {
        from: parse_out_point_draft("lineage[].from", &edge.from)?,
        to_output_index: edge.to_output_index,
        relation: edge.relation.clone(),
    })
}

fn parse_out_point_draft(label: &str, out_point: &OutPointDraft) -> Result<OutPoint> {
    let tx_hash = parse_byte32_hex(&format!("{label}.tx_hash"), &out_point.tx_hash)?;
    let index = parse_required_u64(&format!("{label}.index"), &out_point.index)?;
    let index = u32::try_from(index).map_err(|_| anyhow::anyhow!("{label}.index does not fit in u32"))?;
    Ok(OutPoint::new_builder().tx_hash(tx_hash.pack()).index(index).build())
}

fn parse_script_draft(label: &str, script: &ScriptDraft) -> Result<Script> {
    let code_hash = parse_byte32_hex(&format!("{label}.code_hash"), &script.code_hash)?;
    let hash_type = parse_hash_type(&format!("{label}.hash_type"), &script.hash_type)?;
    let args = parse_script_args_draft(label, script)?;
    Ok(Script::new_builder().code_hash(code_hash.pack()).hash_type(hash_type).args(Bytes::from(args).pack()).build())
}

fn parse_script_args_draft(label: &str, script: &ScriptDraft) -> Result<Vec<u8>> {
    if script.args_parts.is_empty() {
        return parse_hex_bytes(&format!("{label}.args"), &script.args);
    }
    let args = script.args.trim();
    if !args.is_empty() && args != "0x" {
        bail!("{label}.args cannot be combined with {label}.args_parts; put every ScriptArgs byte in args_parts");
    }
    let mut bytes = Vec::new();
    for (index, part) in script.args_parts.iter().enumerate() {
        bytes.extend(parse_script_args_part(&format!("{label}.args_parts[{index}]"), part)?);
    }
    Ok(bytes)
}

fn parse_script_args_part(label: &str, part: &ScriptArgsPartDraft) -> Result<Vec<u8>> {
    match normalise_ckb_tag(&part.kind).as_str() {
        "hex" | "bytes" => {
            let value = value_as_str(label, &part.value)?;
            parse_hex_bytes(&format!("{label}.value"), value)
        }
        "utf8" | "text" => Ok(value_as_str(label, &part.value)?.as_bytes().to_vec()),
        "u8" => {
            let value = parse_required_u64(&format!("{label}.value"), &part.value)?;
            let byte = u8::try_from(value).map_err(|_| anyhow::anyhow!("{label}.value does not fit in u8"))?;
            Ok(vec![byte])
        }
        "u32le" => {
            let value = parse_required_u64(&format!("{label}.value"), &part.value)?;
            let value = u32::try_from(value).map_err(|_| anyhow::anyhow!("{label}.value does not fit in u32"))?;
            Ok(value.to_le_bytes().to_vec())
        }
        "u64le" => Ok(parse_required_u64(&format!("{label}.value"), &part.value)?.to_le_bytes().to_vec()),
        _ => bail!("unsupported {label}.kind '{}'; expected hex, utf8, u8, u32_le, or u64_le", part.kind),
    }
}

fn value_as_str<'a>(label: &str, value: &'a Value) -> Result<&'a str> {
    value.as_str().ok_or_else(|| anyhow::anyhow!("{label}.value must be a string"))
}

fn parse_byte32_hex(label: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_bytes(label, value)?;
    if bytes.len() != 32 {
        bail!("{label} must be 32 bytes, got {}", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_hex_bytes(label: &str, value: &str) -> Result<Vec<u8>> {
    let hex = value.trim().strip_prefix("0x").unwrap_or(value.trim());
    if !hex.len().is_multiple_of(2) {
        bail!("{label} hex must have an even number of digits");
    }
    hex::decode(hex).map_err(|error| anyhow::anyhow!("invalid {label} hex: {error}"))
}

fn parse_required_u64(label: &str, value: &Value) -> Result<u64> {
    parse_optional_u64(label, Some(value))?.ok_or_else(|| anyhow::anyhow!("{label} is required"))
}

fn parse_optional_u64(label: &str, value: Option<&Value>) -> Result<Option<u64>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        Value::Number(number) => number.as_u64().map(Some).ok_or_else(|| anyhow::anyhow!("{label} must be a non-negative u64")),
        Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            let parsed =
                if let Some(hex) = trimmed.strip_prefix("0x") { u64::from_str_radix(hex, 16) } else { trimmed.parse::<u64>() }
                    .map_err(|error| anyhow::anyhow!("invalid {label}: {error}"))?;
            Ok(Some(parsed))
        }
        _ => bail!("{label} must be a u64 number or string"),
    }
}

fn parse_hash_type(label: &str, value: &str) -> Result<ScriptHashType> {
    match normalise_ckb_tag(value).as_str() {
        "data" => Ok(ScriptHashType::Data),
        "type" => Ok(ScriptHashType::Type),
        "data1" => Ok(ScriptHashType::Data1),
        "data2" => Ok(ScriptHashType::Data2),
        _ => bail!("unknown {label} '{}'", value),
    }
}

fn parse_dep_type(label: &str, value: &str) -> Result<DepType> {
    match normalise_ckb_tag(value).as_str() {
        "code" => Ok(DepType::Code),
        "depgroup" => Ok(DepType::DepGroup),
        _ => bail!("unknown {label} '{}'", value),
    }
}

fn normalise_ckb_tag(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['_', '-'], "")
}

fn add_manifest_cell_deps(cell_deps: &mut Vec<CellDep>, outputs: &[CellOutputWithData], manifest: &DeploymentManifest) -> Result<()> {
    let resolver = ManifestCellDepResolver::from_manifest(manifest)?;
    for output in outputs {
        add_manifest_cell_dep(cell_deps, resolver.resolve_for_script(&output.output.lock()));
        if let Some(type_script) = output.output.type_().to_opt() {
            add_manifest_cell_dep(cell_deps, resolver.resolve_for_script(&type_script));
        }
    }
    Ok(())
}

fn add_manifest_cell_dep(cell_deps: &mut Vec<CellDep>, dep: Option<CellDep>) {
    let Some(dep) = dep else {
        return;
    };
    if !cell_deps.iter().any(|existing| existing.as_slice() == dep.as_slice()) {
        cell_deps.push(dep);
    }
}

pub fn build_action_transaction(resolved: &ResolvedActionTx) -> Result<(TransactionView, ResolvedActionEvidence)> {
    materialize_with_ckb_sdk(resolved)
}

pub fn materialize_with_ckb_sdk(resolved: &ResolvedActionTx) -> Result<(TransactionView, ResolvedActionEvidence)> {
    if resolved.outputs.is_empty() {
        bail!("resolved action must create or continue at least one output");
    }

    let mut occupied_capacity_shannons = 0u64;
    let mut builder = TransactionBuilder::default();
    for dep in &resolved.cell_deps {
        builder.dedup_cell_dep(dep.clone());
    }
    for dep in &resolved.header_deps {
        builder.dedup_header_dep(dep.clone());
    }
    for input in &resolved.inputs {
        builder.input(input.clone());
    }
    for output in &resolved.outputs {
        let data_capacity = Capacity::bytes(output.data.len())?;
        let occupied = output.output.occupied_capacity(data_capacity)?.as_u64();
        let declared_capacity: u64 = output.output.capacity().unpack();
        if declared_capacity < occupied {
            bail!("output capacity is below occupied capacity");
        }
        occupied_capacity_shannons = occupied_capacity_shannons.saturating_add(occupied);
        builder.output(output.output.clone());
        builder.output_data(output.data.clone().pack());
    }
    for witness in &resolved.witnesses {
        builder.witness(witness.as_bytes().pack());
    }
    for edge in &resolved.lineage {
        if edge.to_output_index as usize >= resolved.outputs.len() {
            bail!("lineage target output index is out of range");
        }
    }

    let tx = builder.build();
    let serialized_tx_size_bytes = tx.data().as_slice().len();
    let evidence = ResolvedActionEvidence {
        schema: ACTION_ACCEPTANCE_REPORT_SCHEMA,
        state: "ResolvedActionTx",
        metadata_hash: resolved.metadata_hash.clone(),
        artifact_hash: resolved.artifact_hash.clone(),
        action_selector: resolved.action_selector.clone(),
        cell_deps: resolved.cell_deps.len(),
        inputs: resolved.inputs.len(),
        outputs: resolved.outputs.len(),
        outputs_data: resolved.outputs.len(),
        witnesses: resolved.witnesses.len(),
        lineage: resolved.lineage.iter().map(LineageEvidence::from).collect(),
        occupied_capacity_shannons,
        serialized_tx_size_bytes,
        fee_shannons: resolved.fee_shannons,
        ckb_vm_execution: false,
        tx_pool_acceptance: false,
    };
    Ok((tx, evidence))
}

pub fn emit_acceptance_report(
    evidence: &ResolvedActionEvidence,
    estimate_cycles: &EstimateCycles,
    tx_pool_acceptance: &EntryCompleted,
    submitted_tx_hash: Option<H256>,
) -> AcceptedActionReport {
    accepted_action_report(evidence, estimate_cycles, tx_pool_acceptance, submitted_tx_hash)
}

pub fn accepted_action_report(
    evidence: &ResolvedActionEvidence,
    estimate_cycles: &EstimateCycles,
    tx_pool_acceptance: &EntryCompleted,
    submitted_tx_hash: Option<H256>,
) -> AcceptedActionReport {
    AcceptedActionReport {
        schema: ACTION_ACCEPTANCE_REPORT_SCHEMA,
        state: "AcceptedActionTx",
        metadata_hash: evidence.metadata_hash.clone(),
        artifact_hash: evidence.artifact_hash.clone(),
        action_selector: evidence.action_selector.clone(),
        ckb_vm_execution: true,
        estimate_cycles: estimate_cycles.cycles.value(),
        tx_pool_acceptance: true,
        tx_pool_cycles: tx_pool_acceptance.cycles.value(),
        serialized_tx_size_bytes: evidence.serialized_tx_size_bytes,
        occupied_capacity_shannons: evidence.occupied_capacity_shannons,
        fee_shannons: tx_pool_acceptance.fee.value(),
        submitted_tx_hash: submitted_tx_hash.map(|hash| hash.as_bytes().to_vec()),
        lineage: evidence.lineage.clone(),
        known_limitations: vec![
            "Report is adapter-generated; external audit and mainnet-value certification are separate evidence.".to_string()
        ],
    }
}

impl From<&LiveOutputLineage> for LineageEvidence {
    fn from(edge: &LiveOutputLineage) -> Self {
        Self {
            from_tx_hash: edge.from.tx_hash().as_slice().to_vec(),
            from_index: edge.from.index().unpack(),
            to_output_index: edge.to_output_index,
            relation: edge.relation.clone(),
        }
    }
}

pub fn preview_resolved_action(resolved: &ResolvedActionTx) -> ActionPreview {
    ActionPreview {
        schema: "cellscript-action-preview-v1",
        action: resolved.action_selector.clone(),
        summary: format!("Build a CKB transaction for CellScript action {}", resolved.action_selector),
        consumes: resolved.inputs.iter().map(preview_input_cell).collect(),
        creates: resolved.outputs.iter().enumerate().map(|(index, output)| preview_output_cell(index, output)).collect(),
        transitions: resolved.lineage.iter().map(preview_transition).collect(),
        witnesses: PreviewWitnesses { selector: resolved.action_selector.clone(), count: resolved.witnesses.len() },
        warnings: vec![
            "Preview is adapter-local; live cell freshness, final capacity, fee, cycles, and tx-pool acceptance require node checks."
                .to_string(),
        ],
        estimated_fee: Some(resolved.fee_shannons),
        required_signers: Vec::new(),
    }
}

fn preview_input_cell(input: &CellInput) -> PreviewCell {
    let out_point = input.previous_output();
    PreviewCell {
        role: "consume",
        out_point_tx_hash: Some(out_point.tx_hash().as_slice().to_vec()),
        out_point_index: Some(out_point.index().unpack()),
        output_index: None,
        capacity_shannons: None,
        data_len: None,
        lock_hash: None,
        type_hash: None,
    }
}

fn preview_output_cell(index: usize, output: &CellOutputWithData) -> PreviewCell {
    PreviewCell {
        role: "create-or-continue",
        out_point_tx_hash: None,
        out_point_index: None,
        output_index: Some(index as u32),
        capacity_shannons: Some(output.output.capacity().unpack()),
        data_len: Some(output.data.len()),
        lock_hash: Some(output.output.lock().calc_script_hash().as_slice().to_vec()),
        type_hash: output.output.type_().to_opt().map(|script| script.calc_script_hash().as_slice().to_vec()),
    }
}

fn preview_transition(edge: &LiveOutputLineage) -> PreviewTransition {
    PreviewTransition {
        from_tx_hash: edge.from.tx_hash().as_slice().to_vec(),
        from_index: edge.from.index().unpack(),
        to_output_index: edge.to_output_index,
        relation: edge.relation.clone(),
        changes: vec!["adapter must materialize output data matching compiler metadata".to_string()],
        preserves: Vec::new(),
    }
}

impl ScriptSpec {
    pub fn new(code_hash: [u8; 32], hash_type: ScriptHashType, args: impl Into<Bytes>) -> Self {
        Self { code_hash, hash_type, args: args.into() }
    }

    pub fn to_packed(&self) -> Script {
        Script::new_builder().code_hash(self.code_hash.pack()).hash_type(self.hash_type).args(self.args.clone().pack()).build()
    }

    pub fn script_hash(&self) -> Byte32 {
        self.to_packed().calc_script_hash()
    }

    pub fn args_hash(&self) -> [u8; 32] {
        blake2b_256(&self.args)
    }

    pub fn evidence(&self) -> ScriptEvidence {
        ScriptEvidence {
            schema: SCRIPT_EVIDENCE_SCHEMA,
            hash_type: format!("{:?}", self.hash_type).to_ascii_lowercase(),
            code_hash: self.code_hash.to_vec(),
            args_len: self.args.len(),
            args_hash: self.args_hash().to_vec(),
            script_hash: self.script_hash().as_slice().to_vec(),
        }
    }
}

pub fn construct_script(spec: &ScriptSpec) -> Script {
    spec.to_packed()
}

pub fn matches_script_args(script: &Script, pattern: &ScriptArgsPattern) -> bool {
    let args = script.args().raw_data();
    match pattern {
        ScriptArgsPattern::Exact(expected) => args == *expected,
        ScriptArgsPattern::Prefix(prefix) => args.starts_with(prefix),
        ScriptArgsPattern::Suffix(suffix) => args.ends_with(suffix),
    }
}

pub fn owner_mode_args_from_lock(lock: &Script) -> Bytes {
    Bytes::copy_from_slice(lock.calc_script_hash().as_slice())
}

impl ScriptRef {
    pub fn new(role: ScriptRole, script: Script) -> Self {
        Self { role, script }
    }

    pub fn evidence(&self) -> ScriptRefEvidence {
        let args = self.script.args().raw_data();
        ScriptRefEvidence {
            schema: SCRIPT_REF_EVIDENCE_SCHEMA,
            role: self.role,
            hash_type_byte: self.script.hash_type().as_slice()[0],
            code_hash: self.script.code_hash().as_slice().to_vec(),
            args_len: args.len(),
            args_hash: blake2b_256(&args).to_vec(),
            script_hash: self.script.calc_script_hash().as_slice().to_vec(),
        }
    }
}

pub fn lock_script_ref(output: &CellOutput) -> ScriptRef {
    ScriptRef::new(ScriptRole::Lock, output.lock())
}

pub fn type_script_ref(output: &CellOutput) -> Option<ScriptRef> {
    output.type_().to_opt().map(|script| ScriptRef::new(ScriptRole::Type, script))
}

pub fn require_script_ref_matches(script_ref: &ScriptRef, expected: &ScriptSpec) -> Result<()> {
    if script_ref.script.code_hash().as_slice() != expected.code_hash.as_slice() {
        bail!("{} script code_hash mismatch", script_role_name(script_ref.role));
    }
    if script_ref.script.hash_type() != expected.hash_type.into() {
        bail!("{} script hash_type mismatch", script_role_name(script_ref.role));
    }
    if script_ref.script.args().raw_data() != expected.args {
        bail!("{} script args mismatch", script_role_name(script_ref.role));
    }
    Ok(())
}

fn script_role_name(role: ScriptRole) -> &'static str {
    match role {
        ScriptRole::Lock => "lock",
        ScriptRole::Type => "type",
    }
}

impl ScriptCodeDep {
    pub fn new(code_hash: [u8; 32], hash_type: ScriptHashType, out_point: packed::OutPoint, dep_type: DepType) -> Self {
        Self { code_hash, hash_type, out_point, dep_type }
    }

    pub fn from_script(script: &Script, out_point: packed::OutPoint, dep_type: DepType) -> Self {
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(script.code_hash().as_slice());
        let hash_type = ScriptHashType::from_repr(script.hash_type().as_slice()[0]).unwrap_or(ScriptHashType::Data);
        Self::new(code_hash, hash_type, out_point, dep_type)
    }

    pub fn to_cell_dep(&self) -> CellDep {
        CellDep::new_builder().out_point(self.out_point.clone()).dep_type(self.dep_type).build()
    }

    pub fn matches_script(&self, script: &Script) -> bool {
        script.code_hash().as_slice() == self.code_hash.as_slice() && script.hash_type() == self.hash_type.into()
    }

    pub fn evidence(&self) -> ScriptCodeDepEvidence {
        let hash_type_byte: u8 = self.hash_type.into();
        ScriptCodeDepEvidence {
            schema: SCRIPT_CODE_DEP_EVIDENCE_SCHEMA,
            code_hash: self.code_hash.to_vec(),
            hash_type_byte,
            out_point_tx_hash: self.out_point.tx_hash().as_slice().to_vec(),
            out_point_index: self.out_point.index().unpack(),
            dep_type: format!("{:?}", self.dep_type),
        }
    }
}

pub fn require_script_code_dep(script: &Script, deps: &[ScriptCodeDep]) -> Result<CellDep> {
    let Some(dep) = deps.iter().find(|dep| dep.matches_script(script)) else {
        bail!("missing CellDep for script code_hash/hash_type");
    };
    Ok(dep.to_cell_dep())
}

/// Places a CellScript entry payload before any lock-script signing occurs.
///
/// `base.lock` may contain an SDK placeholder, but it must not contain live
/// signatures. CKB lock signers commit to the complete serialized
/// `WitnessArgs`, including `input_type`; mutating this field after signing
/// invalidates the signatures.
pub fn place_entry_witness_payload_before_signing(
    base: &WitnessArgs,
    placement: EntryWitnessPlacementAbi,
    payload: Bytes,
) -> Result<WitnessArgs> {
    if !payload.starts_with(ENTRY_WITNESS_PAYLOAD_MAGIC) {
        bail!("CellScript entry witness payload must start with CSARGv1\\0");
    }

    match placement {
        EntryWitnessPlacementAbi::WitnessArgsInputTypeV2 => {
            if base.input_type().to_opt().is_some() {
                bail!("refusing to overwrite WitnessArgs.input_type");
            }
            Ok(base.clone().as_builder().input_type(Some(payload).pack()).build())
        }
    }
}

pub fn type_id_args_from_first_input(first_input: &CellInput, output_index: u64) -> [u8; 32] {
    let mut material = first_input.as_slice().to_vec();
    material.extend_from_slice(&output_index.to_le_bytes());
    blake2b_256(material)
}

pub fn verify_type_id_output_args(first_input: &CellInput, output_index: u64, output: &CellOutput) -> Result<()> {
    let expected = type_id_args_from_first_input(first_input, output_index);
    let Some(type_script) = output.type_().to_opt() else {
        bail!("TYPE_ID output is missing type script");
    };
    let args = type_script.args().raw_data();
    if args.as_ref() != expected.as_slice() {
        bail!("TYPE_ID output args do not match first input and output index");
    }
    Ok(())
}

pub fn to_rpc_transaction(tx: &TransactionView) -> RpcTransaction {
    tx.data().into()
}

pub struct CkbSdkAcceptance<'a> {
    client: &'a CkbRpcClient,
}

impl<'a> CkbSdkAcceptance<'a> {
    pub fn new(client: &'a CkbRpcClient) -> Self {
        Self { client }
    }

    pub fn estimate_cycles(&self, tx: &TransactionView) -> std::result::Result<EstimateCycles, ckb_sdk::RpcError> {
        self.client.estimate_cycles(to_rpc_transaction(tx))
    }

    pub fn dry_run_protocol_bundle(
        &self,
        tx: &TransactionView,
        materialization: &ProtocolBundleMaterializationEvidence,
    ) -> Result<ProtocolBundleDryRunEvidence> {
        let estimate = self.estimate_cycles(tx)?;
        protocol_bundle_dry_run_evidence(tx, materialization, &estimate)
    }

    pub fn verify_protocol_bundle_live_inputs(
        &self,
        tx: &TransactionView,
        materialization: &ProtocolBundleMaterializationEvidence,
    ) -> Result<ProtocolBundleLiveResolutionEvidence> {
        verify_protocol_bundle_live_inputs_with_client(self.client, tx, materialization)
    }

    pub fn test_tx_pool_accept(&self, tx: &TransactionView) -> std::result::Result<EntryCompleted, ckb_sdk::RpcError> {
        self.client.test_tx_pool_accept(to_rpc_transaction(tx), Some(OutputsValidator::Passthrough))
    }

    pub fn send_transaction(&self, tx: &TransactionView) -> std::result::Result<H256, ckb_sdk::RpcError> {
        self.client.send_transaction(to_rpc_transaction(tx), Some(OutputsValidator::Passthrough))
    }
}

// ---- Full transaction lifecycle bridge ----

/// Deployment-backed CellDep resolver that maps code_hash + hash_type to
/// concrete on-chain CellDeps from a `DeploymentManifest`.
///
/// This implements `ckb_sdk::traits::CellDepResolver` so it can be used
/// directly with SDK transaction builders and `unlock_tx`.
#[derive(Debug)]
pub struct ManifestCellDepResolver {
    /// Maps (code_hash_bytes, hash_type_byte) -> CellDep.
    deps: HashMap<([u8; 32], u8), CellDep>,
}

impl ManifestCellDepResolver {
    /// Build a resolver from a deployment manifest.
    pub fn from_manifest(manifest: &DeploymentManifest) -> Result<Self> {
        let mut deps = HashMap::new();
        for deployment in &manifest.deployments {
            let code_hash = hex::decode(deployment.code_hash.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("invalid code_hash hex for {}: {e}", deployment.name))?;
            if code_hash.len() != 32 {
                bail!("code_hash for {} must be 32 bytes, got {}", deployment.name, code_hash.len());
            }
            let mut code_hash_arr = [0u8; 32];
            code_hash_arr.copy_from_slice(&code_hash);
            let hash_type_byte = match deployment.hash_type.as_str() {
                "data" => 0u8,
                "type" => 1u8,
                "data1" => 2u8,
                "data2" => 4u8,
                other => bail!("unknown hash_type '{}' for {}", other, deployment.name),
            };
            // Parse out_point "0x<tx_hash>:<index>".
            let (tx_hash_hex, index_str) = deployment
                .out_point
                .rsplit_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid out_point format for {}: expected 0x<hash>:<index>", deployment.name))?;
            let tx_hash_bytes = hex::decode(tx_hash_hex.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("invalid out_point tx_hash for {}: {e}", deployment.name))?;
            if tx_hash_bytes.len() != 32 {
                bail!("out_point tx_hash for {} must be 32 bytes", deployment.name);
            }
            let mut tx_hash_arr = [0u8; 32];
            tx_hash_arr.copy_from_slice(&tx_hash_bytes);
            let index: u32 = index_str.parse().map_err(|e| anyhow::anyhow!("invalid out_point index for {}: {e}", deployment.name))?;
            let out_point = OutPoint::new_builder().tx_hash(tx_hash_arr.pack()).index(index).build();
            let dep_type = match deployment.dep_type.as_str() {
                "code" => DepType::Code,
                "dep_group" => DepType::DepGroup,
                other => bail!("unknown dep_type '{}' for {}", other, deployment.name),
            };
            let cell_dep = CellDep::new_builder().out_point(out_point).dep_type(dep_type).build();
            deps.insert((code_hash_arr, hash_type_byte), cell_dep);
        }
        Ok(Self { deps })
    }

    /// Look up a CellDep by script's code_hash and hash_type.
    pub fn resolve_for_script(&self, script: &Script) -> Option<CellDep> {
        let mut code_hash = [0u8; 32];
        code_hash.copy_from_slice(script.code_hash().as_slice());
        let hash_type_byte: u8 = script.hash_type().as_slice().first().copied().unwrap_or(0);
        self.deps.get(&(code_hash, hash_type_byte)).cloned()
    }

    /// Number of deployment entries in the resolver.
    pub fn len(&self) -> usize {
        self.deps.len()
    }

    /// Whether the resolver has any entries.
    pub fn is_empty(&self) -> bool {
        self.deps.is_empty()
    }
}

impl CellDepResolver for ManifestCellDepResolver {
    fn resolve(&self, script: &Script) -> Option<CellDep> {
        self.resolve_for_script(script)
    }
}

/// Transaction submission and status tracking.
///
/// Wraps `CkbRpcClient` to provide submit + confirm + evidence workflow.
pub struct TransactionSubmitter<'a> {
    client: &'a CkbRpcClient,
}

impl<'a> TransactionSubmitter<'a> {
    pub fn new(client: &'a CkbRpcClient) -> Self {
        Self { client }
    }

    /// Submit a transaction to the CKB node's tx-pool.
    pub fn submit(&self, tx: &TransactionView) -> std::result::Result<H256, ckb_sdk::RpcError> {
        self.client.send_transaction(to_rpc_transaction(tx), Some(OutputsValidator::Passthrough))
    }

    /// Query the status of a previously submitted transaction.
    ///
    /// Returns `Some(TransactionWithStatusResponse)` if the node has a record,
    /// or `None` if the transaction is unknown.
    pub fn get_transaction_status(
        &self,
        tx_hash: &H256,
    ) -> std::result::Result<Option<TransactionWithStatusResponse>, ckb_sdk::RpcError> {
        self.client.get_transaction(tx_hash.clone())
    }

    /// Wait for a transaction to be committed, polling up to `max_attempts` times
    /// with `delay_ms` between attempts.
    pub fn wait_committed(&self, tx_hash: &H256, max_attempts: u32, delay_ms: u64) -> Result<CommittedEvidence> {
        for _ in 0..max_attempts {
            if let Some(response) = self.get_transaction_status(tx_hash)? {
                let tx_status = response.tx_status;
                if tx_status.status == Status::Committed {
                    let block_hash = tx_status.block_hash.unwrap_or_default();
                    return Ok(CommittedEvidence { tx_hash: tx_hash.clone(), block_hash, status: "committed".to_string() });
                }
                if tx_status.status == Status::Rejected {
                    bail!("transaction {:?} was rejected by the node", tx_hash);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        }
        bail!("transaction {:?} was not committed within {} attempts", tx_hash, max_attempts)
    }

    /// Get the tip block number from the node.
    pub fn get_tip_block_number(&self) -> std::result::Result<u64, ckb_sdk::RpcError> {
        let header = self.client.get_tip_header()?;
        Ok(header.inner.number.value())
    }
}

/// Evidence that a transaction has been committed on-chain.
#[derive(Debug, Clone, Serialize)]
pub struct CommittedEvidence {
    pub tx_hash: H256,
    pub block_hash: H256,
    pub status: String,
}

/// Adapter-level signing boundary that wraps `ckb_sdk::traits::Signer`.
///
/// This struct does not implement signing itself; it provides typed evidence
/// that signing is an adapter-owned concern. Use `ckb_sdk::unlock_tx` with
/// concrete `ScriptUnlocker` implementations (SecpSighash, OmniLock, etc.)
/// for actual signing.
pub struct SigningAdapter {
    /// Signer identity labels (e.g., lock script hash prefixes).
    pub signer_labels: Vec<String>,
    /// Whether the signing step has been completed.
    pub signed: bool,
}

impl SigningAdapter {
    /// Create a new signing adapter with the given signer labels.
    pub fn new(signer_labels: Vec<String>) -> Self {
        Self { signer_labels, signed: false }
    }

    /// Create a signing adapter for a single secp256k1 sighash signer.
    pub fn for_secp_sighash(lock_arg: H160) -> Self {
        Self { signer_labels: vec![format!("secp256k1-sighash:{}", lock_arg)], signed: false }
    }

    /// Mark the signing step as complete.
    pub fn mark_signed(&mut self) {
        self.signed = true;
    }

    /// Evidence of the signing adapter state.
    pub fn evidence(&self) -> SigningAdapterEvidence {
        SigningAdapterEvidence {
            schema: "cellscript-ckb-signing-adapter-v0.19",
            signer_count: self.signer_labels.len(),
            signed: self.signed,
        }
    }
}

/// Evidence record for the signing adapter.
#[derive(Debug, Clone, Serialize)]
pub struct SigningAdapterEvidence {
    pub schema: &'static str,
    pub signer_count: usize,
    pub signed: bool,
}

/// Adapter-level capacity balancing that wraps `ckb_sdk::CapacityBalancer`.
///
/// Provides a typed interface for the common pattern of funding a transaction
/// with additional capacity inputs and producing change.
pub struct CapacityBridge {
    /// Lock script for change outputs.
    pub change_lock: Script,
    /// Fee rate in shannons per kilobyte.
    pub fee_rate: u64,
}

impl CapacityBridge {
    /// Create a new capacity bridge with the given change lock and fee rate.
    pub fn new(change_lock: Script, fee_rate: u64) -> Self {
        Self { change_lock, fee_rate }
    }

    /// Build a `ckb_sdk::tx_builder::CapacityBalancer` from this bridge configuration.
    pub fn to_balancer(&self) -> ckb_sdk::tx_builder::CapacityBalancer {
        let placeholder = WitnessArgs::new_builder().build();
        ckb_sdk::tx_builder::CapacityBalancer::new_simple(self.change_lock.clone(), placeholder, self.fee_rate)
    }

    /// Evidence for the capacity bridge configuration.
    pub fn evidence(&self) -> CapacityBridgeEvidence {
        CapacityBridgeEvidence {
            schema: "cellscript-ckb-capacity-bridge-v0.19",
            change_lock_hash: self.change_lock.calc_script_hash().as_slice().to_vec(),
            fee_rate: self.fee_rate,
        }
    }
}

/// Evidence record for the capacity bridge.
#[derive(Debug, Clone, Serialize)]
pub struct CapacityBridgeEvidence {
    pub schema: &'static str,
    pub change_lock_hash: Vec<u8>,
    pub fee_rate: u64,
}

/// Full end-to-end transaction lifecycle result.
#[derive(Debug, Clone, Serialize)]
pub struct TransactionLifecycleEvidence {
    pub schema: &'static str,
    pub deploy_evidence: Option<ResolvedDeployEvidence>,
    pub action_evidence: Option<ResolvedActionEvidence>,
    pub signing: SigningAdapterEvidence,
    pub capacity: Option<CapacityBridgeEvidence>,
    pub estimate_cycles: Option<u64>,
    pub tx_pool_accepted: bool,
    pub submitted: bool,
    pub committed: Option<CommittedEvidence>,
}

pub fn signing_boundary_type() -> &'static str {
    std::any::type_name::<SecpSighashScriptSigner>()
}

// ---- High-level facade ----

/// High-level adapter facade that connects to a CKB node and provides
/// one-call workflows for common CellScript operations.
///
/// # Quick start
///
/// ```no_run
/// # fn main() -> anyhow::Result<()> {
/// use cellscript_ckb_adapter::CellScriptAdapter;
///
/// // Connect to a CKB node
/// let adapter = CellScriptAdapter::connect("http://127.0.0.1:8114")?;
/// let tip = adapter.get_tip_block_number()?;
/// println!("CKB tip: {tip}");
/// # Ok(())
/// # }
/// ```
pub struct CellScriptAdapter {
    client: CkbRpcClient,
}

impl std::fmt::Debug for CellScriptAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CellScriptAdapter").finish_non_exhaustive()
    }
}

impl CellScriptAdapter {
    /// Connect to a CKB node at the given RPC URL.
    pub fn connect(rpc_url: &str) -> Result<Self> {
        let client = CkbRpcClient::new(rpc_url);
        // Verify connectivity.
        let _tip = client.get_tip_header().map_err(|e| anyhow::anyhow!("cannot connect to CKB node at {}: {e}", rpc_url))?;
        Ok(Self { client })
    }

    // ---- Action workflow ----

    /// Load an action plan from a file path.
    pub fn load_action_plan(&self, path: impl AsRef<Path>) -> Result<ActionPlan> {
        load_action_plan(path)
    }

    /// Load a deployment manifest from a file path.
    pub fn load_deployment_manifest(&self, path: impl AsRef<Path>) -> Result<DeploymentManifest> {
        load_deployment_manifest(path)
    }

    /// Resolve a materialized action plan into a CKB transaction candidate.
    ///
    /// Compiler-produced `ActionPlan` templates still fail closed here until a
    /// builder runtime fills the concrete inputs, outputs, witnesses, CellDeps,
    /// output data, and lineage. The method does not infer protocol semantics
    /// or select live cells from action names.
    pub fn resolve_action(&self, plan: &ActionPlan) -> Result<ResolvedActionTx> {
        resolve_materialized_action_plan(plan)
    }

    // ---- Node interaction helpers ----

    /// Estimate cycles for a transaction.
    pub fn estimate_cycles(&self, tx: &TransactionView) -> std::result::Result<EstimateCycles, ckb_sdk::RpcError> {
        self.client.estimate_cycles(to_rpc_transaction(tx))
    }

    /// Run the exact materialized ProtocolBundle transaction through the node
    /// and bind its aggregate cycle result to every direct Script Group.
    pub fn dry_run_protocol_bundle(
        &self,
        tx: &TransactionView,
        materialization: &ProtocolBundleMaterializationEvidence,
    ) -> Result<ProtocolBundleDryRunEvidence> {
        let estimate = self.estimate_cycles(tx)?;
        protocol_bundle_dry_run_evidence(tx, materialization, &estimate)
    }

    /// Resolve every input through `get_live_cell`, verify the exact expected
    /// CellOutput/data and network identity, and replace skeleton-sourced
    /// capacity/fee claims with live node evidence.
    pub fn verify_protocol_bundle_live_inputs(
        &self,
        tx: &TransactionView,
        materialization: &ProtocolBundleMaterializationEvidence,
    ) -> Result<ProtocolBundleLiveResolutionEvidence> {
        verify_protocol_bundle_live_inputs_with_client(&self.client, tx, materialization)
    }

    /// Test tx-pool acceptance for a transaction.
    pub fn test_tx_pool_accept(&self, tx: &TransactionView) -> std::result::Result<EntryCompleted, ckb_sdk::RpcError> {
        self.client.test_tx_pool_accept(to_rpc_transaction(tx), Some(OutputsValidator::Passthrough))
    }

    /// Submit a transaction to the CKB node's tx-pool.
    pub fn submit_transaction(&self, tx: &TransactionView) -> std::result::Result<H256, ckb_sdk::RpcError> {
        self.client.send_transaction(to_rpc_transaction(tx), Some(OutputsValidator::Passthrough))
    }

    /// Wait for a transaction to be committed on-chain.
    pub fn wait_for_commitment(&self, tx_hash: &H256, max_attempts: u32, delay_ms: u64) -> Result<CommittedEvidence> {
        let submitter = TransactionSubmitter::new(&self.client);
        submitter.wait_committed(tx_hash, max_attempts, delay_ms)
    }

    /// Get the tip block number.
    pub fn get_tip_block_number(&self) -> std::result::Result<u64, ckb_sdk::RpcError> {
        let header = self.client.get_tip_header()?;
        Ok(header.inner.number.value())
    }

    /// Query transaction status from the node.
    pub fn get_transaction_status(
        &self,
        tx_hash: &H256,
    ) -> std::result::Result<Option<TransactionWithStatusResponse>, ckb_sdk::RpcError> {
        self.client.get_transaction(tx_hash.clone())
    }

    /// Fail closed unless the connected node is CKB mainnet.
    pub fn require_mainnet(&self) -> Result<()> {
        let consensus = self.client.get_consensus()?;
        if consensus.genesis_hash != ckb_sdk::constants::GENESIS_BLOCK_HASH_MAINNET {
            bail!(
                "mainnet required: connected chain {} has genesis {}, expected {}",
                consensus.id,
                consensus.genesis_hash,
                ckb_sdk::constants::GENESIS_BLOCK_HASH_MAINNET
            );
        }
        Ok(())
    }

    /// Resolve and validate a live, pure-capacity input owned by `expected_lock`.
    ///
    /// State-bearing Cells are rejected: the deployment flow must not silently
    /// discard a Type Script or transform non-empty input data into untyped data.
    pub fn resolve_pure_capacity_input(&self, out_point: &OutPoint, expected_lock: &Script) -> Result<(u64, Bytes)> {
        let response = self.client.get_live_cell(out_point.clone().into(), true)?;
        if response.status != "live" {
            bail!("capacity input is not live (status: {})", response.status);
        }
        let cell = response.cell.ok_or_else(|| anyhow::anyhow!("live capacity input response is missing cell data"))?;
        let output: CellOutput = cell.output.into();
        if output.lock() != *expected_lock {
            bail!("capacity input lock does not match the requested deployer lock");
        }
        if output.type_().to_opt().is_some() {
            bail!("capacity input must not have a Type Script");
        }
        let data = cell.data.ok_or_else(|| anyhow::anyhow!("capacity input RPC response omitted cell data"))?.content.into_bytes();
        if !data.is_empty() {
            bail!("capacity input must have empty data");
        }
        Ok((output.capacity().unpack(), data))
    }

    // ---- Internal helpers ----
}

fn verify_protocol_bundle_live_inputs_with_client(
    client: &CkbRpcClient,
    tx: &TransactionView,
    materialization: &ProtocolBundleMaterializationEvidence,
) -> Result<ProtocolBundleLiveResolutionEvidence> {
    let consensus = client.get_consensus()?;
    let observed_chain_id = consensus.id;
    let observed_genesis_hash = format!("0x{}", hex::encode(consensus.genesis_hash.as_bytes()));
    let mut live_inputs = Vec::with_capacity(tx.inputs().len());
    for (index, input) in tx.inputs().into_iter().enumerate() {
        let response = client.get_live_cell(input.previous_output().into(), true)?;
        if response.status != "live" {
            bail!("ProtocolBundle input {index} is not live (status: {})", response.status);
        }
        let cell = response.cell.ok_or_else(|| anyhow::anyhow!("ProtocolBundle live input {index} response omitted the cell"))?;
        let output: CellOutput = cell.output.into();
        let data = cell
            .data
            .ok_or_else(|| anyhow::anyhow!("ProtocolBundle live input {index} response omitted cell data"))?
            .content
            .into_bytes();
        live_inputs.push((output, data));
    }
    protocol_bundle_live_resolution_evidence(tx, materialization, &observed_chain_id, &observed_genesis_hash, &live_inputs)
}

pub fn sample_resolved_action_tx() -> ResolvedActionTx {
    let input_out_point = packed::OutPoint::new_builder().tx_hash([0x11u8; 32].pack()).index(0u32).build();
    let dep_out_point = packed::OutPoint::new_builder().tx_hash([0x22u8; 32].pack()).index(1u32).build();
    let lock = construct_script(&ScriptSpec::new([0x33u8; 32], ScriptHashType::Data1, vec![0x44u8; 20]));
    let output = CellOutput::new_builder().capacity(100_000_000_000u64).lock(lock).build();
    let witness = WitnessArgs::new_builder().input_type(Some(Bytes::from(b"mint".to_vec())).pack()).build();

    ResolvedActionTx {
        metadata_hash: "0".repeat(64),
        artifact_hash: Some("1".repeat(64)),
        action_selector: "mint".to_string(),
        inputs: vec![CellInput::new_builder().previous_output(input_out_point.clone()).build()],
        outputs: vec![CellOutputWithData { output, data: Bytes::from(vec![0x55u8; 16]) }],
        witnesses: vec![witness],
        cell_deps: vec![CellDep::new_builder().out_point(dep_out_point).dep_type(DepType::Code).build()],
        header_deps: Vec::new(),
        lineage: vec![LiveOutputLineage { from: input_out_point, to_output_index: 0, relation: "state-continuation".to_string() }],
        fee_shannons: 1_000,
    }
}

/// Sample deploy spec for testing. Uses a 64-byte pseudo-artifact and a
/// generous capacity input (10 CKB = 10_000_000_000 shannons).
pub fn sample_deploy_spec() -> DeployArtifactSpec {
    let input_out_point = packed::OutPoint::new_builder().tx_hash([0xaau8; 32].pack()).index(0u32).build();
    let lock = construct_script(&ScriptSpec::new([0xbbu8; 32], ScriptHashType::Data1, vec![0xccu8; 20]));
    let artifact = Bytes::from(vec![0xddu8; 64]);
    let artifact_hash = blake2b_256(&artifact).iter().map(|b| format!("{:02x}", b)).collect::<String>();

    DeployArtifactSpec {
        name: "test-token".to_string(),
        artifact_binary: artifact,
        artifact_hash,
        deployer_lock: lock,
        capacity_input: CellInput::new_builder().previous_output(input_out_point).build(),
        capacity_input_shannons: 200_000_000_000,
        capacity_input_data: Bytes::new(),
        type_id_hash_type: ScriptHashType::Type,
        type_script: None,
        cell_deps: Vec::new(),
        header_deps: Vec::new(),
        fee_shannons: 1_000,
    }
}

/// Sample action plan for testing.
pub fn sample_action_plan() -> ActionPlan {
    ActionPlan {
        policy: ACTION_PLAN_POLICY.to_string(),
        action: "mint".to_string(),
        artifact_hash: Some("0".repeat(64)),
        metadata_hash: Some("1".repeat(64)),
        action_scan_selectors: None,
        transaction_draft: TransactionDraft {
            state: "resolved".to_string(),
            can_submit: true,
            requires_packed_materialization: false,
            metadata_hash: None,
            fee_shannons: Some(1_000),
            inputs: Vec::new(),
            outputs: Vec::new(),
            outputs_data: Vec::new(),
            witnesses: Vec::new(),
            cell_deps: Vec::new(),
            header_deps: Vec::new(),
            lineage: Vec::new(),
            scan_selector_evidence: Vec::new(),
        },
        adapter_contract: AdapterContract {
            schema: ADAPTER_CONTRACT_SCHEMA.to_string(),
            compiler_core_dependency: "cellscript-core-v0.19".to_string(),
            transaction_realizer: "headless".to_string(),
            resolved_tx_required_fields: vec!["inputs".to_string(), "outputs".to_string(), "witnesses".to_string()],
            acceptance_report_template: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compiler_action_plan_boundary() {
        let plan = serde_json::json!({
            "policy": "cellscript-action-builder-plan-v1",
            "action": "mint",
            "artifact_hash": "1".repeat(64),
            "transaction_draft": {
                "state": "ActionPlan",
                "can_submit": false,
                "requires_packed_materialization": true
            },
            "adapter_contract": {
                "schema": "cellscript-ckb-adapter-contract-v0.19",
                "compiler_core_dependency": "no-ckb-sdk-rust",
                "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
                "resolved_tx_required_fields": [
                    "outputs_data",
                    "cell_deps",
                    "lineage"
                ]
            }
        });
        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        assert_eq!(parsed.action, "mint");
        assert_eq!(parsed.adapter_contract.transaction_realizer, "ckb-sdk-rust-or-CCC-adapter");
    }

    #[test]
    fn loads_action_plan_and_deployment_manifest_contracts() {
        let plan = serde_json::json!({
            "policy": ACTION_PLAN_POLICY,
            "action": "mint",
            "artifact_hash": "1".repeat(64),
            "transaction_draft": {
                "state": "ActionPlan",
                "can_submit": false,
                "requires_packed_materialization": true
            },
            "adapter_contract": {
                "schema": ADAPTER_CONTRACT_SCHEMA,
                "compiler_core_dependency": "no-ckb-sdk-rust",
                "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
                "resolved_tx_required_fields": ["outputs_data", "cell_deps", "lineage"]
            }
        });
        let manifest = serde_json::json!({
            "schema": DEPLOYMENT_MANIFEST_SCHEMA,
            "version": 1,
            "deployments": [{
                "name": "token",
                "code_hash": "0x11",
                "hash_type": "type",
                "args": "0x22",
                "dep_type": "code",
                "out_point": "0x33:0"
            }]
        });
        let dir = std::env::temp_dir();
        let unique = format!("cellscript-ckb-adapter-{}", std::process::id());
        let plan_path = dir.join(format!("{unique}-action-plan.json"));
        let manifest_path = dir.join(format!("{unique}-deployment-manifest.json"));
        std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let loaded_plan = load_action_plan(&plan_path).unwrap();
        let loaded_manifest = load_deployment_manifest(&manifest_path).unwrap();
        let evidence = deployment_evidence(&loaded_manifest);

        assert_eq!(loaded_plan.action, "mint");
        assert_eq!(loaded_manifest.deployments[0].name, "token");
        assert_eq!(evidence.schema, DEPLOYMENT_MANIFEST_SCHEMA);
        assert_eq!(evidence.deployments, 1);
        assert_eq!(evidence.names, vec!["token".to_string()]);

        let _ = std::fs::remove_file(plan_path);
        let _ = std::fs::remove_file(manifest_path);
    }

    #[test]
    fn materializes_resolved_action_with_ckb_sdk_transaction_builder() {
        let resolved = sample_resolved_action_tx();
        let (tx, evidence) = build_action_transaction(&resolved).unwrap();
        assert_eq!(evidence.state, "ResolvedActionTx");
        assert_eq!(evidence.outputs, 1);
        assert_eq!(evidence.outputs_data, 1);
        assert_eq!(evidence.cell_deps, 1);
        assert_eq!(evidence.lineage.len(), 1);
        assert_eq!(evidence.lineage[0].to_output_index, 0);
        assert_eq!(evidence.lineage[0].relation, "state-continuation");
        assert!(evidence.occupied_capacity_shannons > 0);
        assert!(evidence.serialized_tx_size_bytes > 0);
        assert!(!evidence.ckb_vm_execution);
        assert!(!evidence.tx_pool_acceptance);
        assert_eq!(tx.outputs().len(), tx.outputs_data().len());
        assert_eq!(to_rpc_transaction(&tx).outputs.len(), 1);
    }

    #[test]
    fn resolves_materialized_action_plan_into_packed_transaction_candidate() {
        let plan = materialized_action_plan_json(true);
        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let resolved = resolve_materialized_action_plan(&parsed).unwrap();

        assert_eq!(resolved.action_selector, "mint");
        assert_eq!(resolved.metadata_hash, "0".repeat(64));
        assert_eq!(resolved.inputs.len(), 1);
        assert_eq!(resolved.outputs.len(), 1);
        assert_eq!(resolved.outputs[0].data, Bytes::from(vec![0x55u8; 16]));
        assert_eq!(resolved.witnesses.len(), 1);
        assert_eq!(resolved.cell_deps.len(), 1);
        assert_eq!(resolved.lineage.len(), 1);
        assert_eq!(resolved.fee_shannons, 1_000);

        let (tx, evidence) = build_action_transaction(&resolved).unwrap();
        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.outputs().len(), tx.outputs_data().len());
        assert_eq!(evidence.state, "ResolvedActionTx");
        assert_eq!(evidence.outputs_data, 1);
    }

    #[test]
    fn materialized_action_plan_constructs_variable_length_script_args_from_parts() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([
            { "kind": "utf8", "value": "CS" },
            { "kind": "u8", "value": 7 },
            { "kind": "u32_le", "value": 42 },
            { "kind": "hex", "value": "0xaa55" }
        ]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let resolved = resolve_materialized_action_plan(&parsed).unwrap();
        let args = resolved.outputs[0].output.lock().args().raw_data();

        assert_eq!(args, Bytes::from(vec![b'C', b'S', 7, 42, 0, 0, 0, 0xaa, 0x55]));
    }

    #[test]
    fn materialized_action_plan_rejects_ambiguous_script_args_parts() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0xff");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([{ "kind": "hex", "value": "0xaa" }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();

        assert!(error.contains("args cannot be combined"), "{error}");
    }

    #[test]
    fn resolve_action_template_fails_closed_until_runtime_fills_live_cells() {
        let plan = serde_json::json!({
            "policy": ACTION_PLAN_POLICY,
            "action": "mint",
            "artifact_hash": "1".repeat(64),
            "transaction_draft": {
                "state": "ActionPlan",
                "can_submit": false,
                "requires_packed_materialization": true
            },
            "adapter_contract": {
                "schema": ADAPTER_CONTRACT_SCHEMA,
                "compiler_core_dependency": "no-ckb-sdk-rust",
                "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
                "resolved_tx_required_fields": ["outputs_data", "cell_deps", "lineage"]
            }
        });
        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("semantic template"), "{error}");
        assert!(error.contains("transaction_draft.inputs"), "{error}");
    }

    #[test]
    fn materialized_action_plan_uses_manifest_to_complete_matching_cell_deps() {
        let code_hash = [0x33u8; 32];
        let tx_hash = [0xeeu8; 32];
        let plan = materialized_action_plan_json(false);
        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let manifest = DeploymentManifest {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
            version: 1,
            deployments: vec![DeploymentRef {
                name: "mint-lock".to_string(),
                code_hash: format!("0x{}", hex::encode(code_hash)),
                hash_type: "data1".to_string(),
                args: "0x".to_string(),
                dep_type: "code".to_string(),
                out_point: format!("0x{}:3", hex::encode(tx_hash)),
            }],
        };

        let resolved = resolve_materialized_action_plan_with_manifest(&parsed, Some(&manifest)).unwrap();
        assert_eq!(resolved.cell_deps.len(), 1);
        assert_eq!(resolved.cell_deps[0].out_point().tx_hash().as_slice(), &tx_hash);
        let resolved_index: u32 = resolved.cell_deps[0].out_point().index().unpack();
        assert_eq!(resolved_index, 3u32);
    }

    #[test]
    fn materialized_action_plan_requires_scan_selector_evidence_when_selectors_are_declared() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"].as_object_mut().expect("transaction draft").remove("scan_selector_evidence");
        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence length 0"), "{error}");
        assert!(error.contains("action_scan_selectors.selector_count 1"), "{error}");
    }

    #[test]
    fn materialized_action_plan_rejects_mismatched_scan_selector_role() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["scan_selector_evidence"][0]["role"] = serde_json::json!("wrong-role");
        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.role mismatch"), "{error}");
        assert!(error.contains("transaction-output"), "{error}");
    }

    #[test]
    fn rejects_under_capacity_output_before_rpc_submission() {
        let mut resolved = sample_resolved_action_tx();
        resolved.outputs[0].output = resolved.outputs[0].output.clone().as_builder().capacity(1u64).build();
        let error = materialize_with_ckb_sdk(&resolved).unwrap_err().to_string();
        assert!(error.contains("below occupied capacity"), "{error}");
    }

    #[test]
    fn rejects_lineage_to_missing_output() {
        let mut resolved = sample_resolved_action_tx();
        resolved.lineage[0].to_output_index = 99;
        let error = materialize_with_ckb_sdk(&resolved).unwrap_err().to_string();
        assert!(error.contains("lineage target output index is out of range"), "{error}");
    }

    #[test]
    fn emits_accepted_action_report_from_node_evidence() {
        let resolved = sample_resolved_action_tx();
        let (_tx, evidence) = materialize_with_ckb_sdk(&resolved).unwrap();
        let estimate = EstimateCycles { cycles: 45_000u64.into() };
        let tx_pool = EntryCompleted { cycles: 45_100u64.into(), fee: 1_234u64.into() };
        let report = emit_acceptance_report(&evidence, &estimate, &tx_pool, Some(H256::from([0xabu8; 32])));

        assert_eq!(report.schema, "cellscript-ckb-action-acceptance-report-v0.19");
        assert_eq!(report.state, "AcceptedActionTx");
        assert!(report.ckb_vm_execution);
        assert!(report.tx_pool_acceptance);
        assert_eq!(report.estimate_cycles, 45_000);
        assert_eq!(report.tx_pool_cycles, 45_100);
        assert_eq!(report.fee_shannons, 1_234);
        assert_eq!(report.submitted_tx_hash.as_ref().expect("tx hash").len(), 32);
        assert_eq!(report.lineage.len(), 1);

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["submitted_tx_hash"].as_array().expect("submitted hash").len(), 32);
        assert_eq!(json["known_limitations"].as_array().expect("limitations").len(), 1);
    }

    #[test]
    fn emits_frontend_ready_headless_action_preview() {
        let resolved = sample_resolved_action_tx();
        let preview = preview_resolved_action(&resolved);
        assert_eq!(preview.schema, "cellscript-action-preview-v1");
        assert_eq!(preview.action, "mint");
        assert_eq!(preview.consumes.len(), 1);
        assert_eq!(preview.creates.len(), 1);
        assert_eq!(preview.transitions.len(), 1);
        assert_eq!(preview.witnesses.selector, "mint");
        assert_eq!(preview.witnesses.count, 1);
        assert_eq!(preview.estimated_fee, Some(1_000));
        assert!(preview.required_signers.is_empty());
        assert_eq!(preview.consumes[0].out_point_index, Some(0));
        assert_eq!(preview.creates[0].output_index, Some(0));
        assert!(preview.creates[0].lock_hash.as_ref().is_some_and(|hash| hash.len() == 32));
        assert!(preview.warnings.iter().any(|warning| warning.contains("tx-pool acceptance")));

        let json = serde_json::to_value(&preview).unwrap();
        assert_eq!(json["requiredSigners"], serde_json::json!([]));
        assert_eq!(json["estimatedFee"], serde_json::json!(1_000));
        assert_eq!(json["creates"][0]["dataLen"], serde_json::json!(16));
    }

    #[test]
    fn places_cellscript_entry_payload_before_signing() {
        let base = WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; 65])).pack()).build();
        let payload = Bytes::from(b"CSARGv1\0\x4d\0\0\0\0\0\0\0".to_vec());
        let placement = EntryWitnessPlacementAbi::WitnessArgsInputTypeV2;
        assert_eq!(placement.name(), "cellscript-witnessargs-input-type-v2");
        let witness = place_entry_witness_payload_before_signing(&base, placement, payload.clone()).unwrap();
        assert_eq!(witness.lock().to_opt().expect("lock preserved").raw_data().len(), 65);
        assert_eq!(witness.input_type().to_opt().expect("entry payload").raw_data(), payload);
        assert!(witness.output_type().to_opt().is_none());

        let occupied = witness;
        let error = place_entry_witness_payload_before_signing(&occupied, placement, payload.clone()).unwrap_err().to_string();
        assert!(error.contains("refusing to overwrite WitnessArgs.input_type"), "{error}");

        let error = place_entry_witness_payload_before_signing(&base, placement, Bytes::from_static(b"not-cellscript"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("must start with CSARGv1"), "{error}");
    }

    #[test]
    fn computes_and_checks_type_id_args_from_packed_input_and_output_index() {
        let mut resolved = sample_resolved_action_tx();
        let first_input = resolved.inputs.remove(0);
        let output_index = 3u64;
        let args = type_id_args_from_first_input(&first_input, output_index);
        let lock = construct_script(&ScriptSpec::new([0x33u8; 32], ScriptHashType::Data1, vec![0x44u8; 20]));
        let type_script = construct_script(&ScriptSpec::new([0x55u8; 32], ScriptHashType::Type, args.to_vec()));
        let output = CellOutput::new_builder().capacity(100_000_000_000u64).lock(lock.clone()).type_(Some(type_script).pack()).build();

        verify_type_id_output_args(&first_input, output_index, &output).unwrap();
        let wrong_type_script = construct_script(&ScriptSpec::new([0x55u8; 32], ScriptHashType::Type, vec![0x99u8; 32]));
        let wrong_output = output.as_builder().type_(Some(wrong_type_script).pack()).build();
        let error = verify_type_id_output_args(&first_input, output_index, &wrong_output).unwrap_err().to_string();
        assert!(error.contains("TYPE_ID output args do not match"), "{error}");
    }

    #[test]
    fn constructs_arbitrary_scripts_with_ckb_types_hash_and_args_evidence() {
        let spec = ScriptSpec::new([0xabu8; 32], ScriptHashType::Data2, vec![1u8, 2, 3, 4, 5]);
        let script = construct_script(&spec);
        assert_eq!(script.code_hash().as_slice(), &[0xabu8; 32]);
        assert_eq!(script.hash_type(), ScriptHashType::Data2.into());
        assert_eq!(script.args().raw_data(), Bytes::from(vec![1u8, 2, 3, 4, 5]));

        let evidence = spec.evidence();
        assert_eq!(evidence.schema, "cellscript-ckb-script-evidence-v0.19");
        assert_eq!(evidence.hash_type, "data2");
        assert_eq!(evidence.args_len, 5);
        assert_eq!(evidence.script_hash, script.calc_script_hash().as_slice().to_vec());

        let changed = ScriptSpec::new([0xabu8; 32], ScriptHashType::Data2, vec![1u8, 2, 3, 4, 6]);
        assert_ne!(spec.script_hash(), changed.script_hash());
    }

    #[test]
    fn checks_script_args_patterns_and_owner_mode_args() {
        let owner = construct_script(&ScriptSpec::new([0x33u8; 32], ScriptHashType::Data1, vec![0x44u8; 20]));
        let owner_args = owner_mode_args_from_lock(&owner);
        assert_eq!(owner_args.as_ref(), owner.calc_script_hash().as_slice());

        let script = construct_script(&ScriptSpec::new([0x77u8; 32], ScriptHashType::Type, vec![1u8, 2, 3, 4, 5]));
        assert!(matches_script_args(&script, &ScriptArgsPattern::Exact(Bytes::from(vec![1u8, 2, 3, 4, 5]))));
        assert!(matches_script_args(&script, &ScriptArgsPattern::Prefix(Bytes::from(vec![1u8, 2, 3]))));
        assert!(matches_script_args(&script, &ScriptArgsPattern::Suffix(Bytes::from(vec![4u8, 5]))));
        assert!(!matches_script_args(&script, &ScriptArgsPattern::Exact(Bytes::from(vec![1u8, 2]))));
    }

    #[test]
    fn reads_lock_and_type_script_refs_from_outputs() {
        let lock_spec = ScriptSpec::new([0x11u8; 32], ScriptHashType::Data1, vec![0x22u8; 20]);
        let type_spec = ScriptSpec::new([0x33u8; 32], ScriptHashType::Type, vec![0x44u8; 32]);
        let output = CellOutput::new_builder()
            .capacity(100_000_000_000u64)
            .lock(construct_script(&lock_spec))
            .type_(Some(construct_script(&type_spec)).pack())
            .build();

        let lock_ref = lock_script_ref(&output);
        let type_ref = type_script_ref(&output).expect("type script ref");
        require_script_ref_matches(&lock_ref, &lock_spec).unwrap();
        require_script_ref_matches(&type_ref, &type_spec).unwrap();

        let evidence = type_ref.evidence();
        assert_eq!(evidence.schema, "cellscript-ckb-script-ref-evidence-v0.19");
        assert_eq!(evidence.role, ScriptRole::Type);
        assert_eq!(evidence.code_hash, vec![0x33u8; 32]);
        assert_eq!(evidence.args_len, 32);

        let wrong_spec = ScriptSpec::new([0x33u8; 32], ScriptHashType::Type, vec![0x45u8; 32]);
        let error = require_script_ref_matches(&type_ref, &wrong_spec).unwrap_err().to_string();
        assert!(error.contains("type script args mismatch"), "{error}");
    }

    #[test]
    fn missing_type_script_ref_is_explicit() {
        let mut resolved = sample_resolved_action_tx();
        let output = resolved.outputs.remove(0).output;
        assert!(type_script_ref(&output).is_none());
        assert_eq!(lock_script_ref(&output).role, ScriptRole::Lock);
    }

    #[test]
    fn binds_scripts_to_explicit_cell_deps() {
        let script = construct_script(&ScriptSpec::new([0x88u8; 32], ScriptHashType::Data1, vec![0x99u8; 20]));
        let out_point = packed::OutPoint::new_builder().tx_hash([0xaau8; 32].pack()).index(7u32).build();
        let dep = ScriptCodeDep::from_script(&script, out_point.clone(), DepType::DepGroup);
        let cell_dep = require_script_code_dep(&script, std::slice::from_ref(&dep)).unwrap();
        assert_eq!(cell_dep.out_point(), out_point);
        assert_eq!(cell_dep.dep_type(), DepType::DepGroup.into());

        let evidence = dep.evidence();
        assert_eq!(evidence.schema, "cellscript-ckb-script-code-dep-evidence-v0.19");
        assert_eq!(evidence.hash_type_byte, 2);
        assert_eq!(evidence.out_point_index, 7);
        assert_eq!(evidence.dep_type, "DepGroup");
    }

    #[test]
    fn rejects_missing_or_wrong_hash_type_script_deps() {
        let script = construct_script(&ScriptSpec::new([0x88u8; 32], ScriptHashType::Data1, vec![0x99u8; 20]));
        let out_point = packed::OutPoint::new_builder().tx_hash([0xaau8; 32].pack()).index(7u32).build();
        let wrong_dep = ScriptCodeDep::new([0x88u8; 32], ScriptHashType::Type, out_point, DepType::Code);

        let missing = require_script_code_dep(&script, &[]).unwrap_err().to_string();
        assert!(missing.contains("missing CellDep"), "{missing}");

        let wrong = require_script_code_dep(&script, &[wrong_dep]).unwrap_err().to_string();
        assert!(wrong.contains("missing CellDep"), "{wrong}");
    }

    #[test]
    fn binds_ckb_sdk_signing_boundary_without_compiler_dependency() {
        assert!(signing_boundary_type().contains("SecpSighashScriptSigner"));
    }

    // ---- Deploy probe tests ----

    #[test]
    fn builds_deploy_transaction_with_type_id_code_cell() {
        let spec = sample_deploy_spec();
        let (tx, evidence) = build_deploy_transaction(&spec).unwrap();

        // Evidence checks.
        assert_eq!(evidence.schema, DEPLOY_EVIDENCE_SCHEMA);
        assert_eq!(evidence.state, "ResolvedDeployTx");
        assert_eq!(evidence.name, "test-token");
        assert_eq!(evidence.code_output_index, 0);
        assert_eq!(evidence.change_output_index, 1);
        assert_eq!(evidence.hash_type, "type");
        assert_eq!(evidence.type_id_args.len(), 32);
        assert_eq!(evidence.code_hash.len(), 32);
        assert!(evidence.occupied_capacity_shannons > 0);
        assert!(evidence.change_capacity_shannons > 0);
        assert!(evidence.serialized_tx_size_bytes > 0);
        assert!(!evidence.ckb_vm_execution);
        assert!(!evidence.tx_pool_acceptance);

        // Transaction shape checks.
        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.outputs().len(), 2);
        assert_eq!(tx.outputs_data().len(), 2);

        // Code output has a type script (TYPE_ID).
        let code_output = tx.outputs().get(0).unwrap();
        assert!(code_output.type_().is_some(), "code output must have type script for TYPE_ID");

        // Change output has no type script.
        let change_output = tx.outputs().get(1).unwrap();
        assert!(change_output.type_().is_none(), "change output should not have type script");

        // Artifact data is in the first output_data.
        let code_data = tx.outputs_data().get(0).unwrap().raw_data();
        assert_eq!(code_data.len(), 64);
    }

    #[test]
    fn deploy_type_id_args_match_first_input_and_output_index() {
        let spec = sample_deploy_spec();
        let (_tx, evidence) = build_deploy_transaction(&spec).unwrap();

        // TYPE_ID args = blake2b(first_input || output_index_le)
        let expected_args = type_id_args_from_first_input(&spec.capacity_input, 0);
        assert_eq!(evidence.type_id_args, expected_args.to_vec());
    }

    #[test]
    fn deploy_type_hash_is_live_code_cell_type_script_hash() {
        let spec = sample_deploy_spec();
        let (tx, evidence) = build_deploy_transaction(&spec).unwrap();

        let type_script = tx.outputs().get(0).unwrap().type_().to_opt().unwrap();
        let mut expected_type_id_code_hash = [0u8; 32];
        expected_type_id_code_hash[25..].copy_from_slice(b"TYPE_ID");
        assert_eq!(type_script.code_hash().as_slice(), expected_type_id_code_hash);
        assert_eq!(evidence.code_hash, type_script.calc_script_hash().as_slice());
    }

    #[test]
    fn deploy_data_hash_type_uses_artifact_hash_and_no_type_script() {
        let mut spec = sample_deploy_spec();
        spec.type_id_hash_type = ScriptHashType::Data1;
        let (tx, evidence) = build_deploy_transaction(&spec).unwrap();

        assert!(tx.outputs().get(0).unwrap().type_().to_opt().is_none());
        assert_eq!(evidence.code_hash, blake2b_256(&spec.artifact_binary).to_vec());
        assert_eq!(evidence.hash_type, "data1");
        assert!(evidence.type_id_args.is_empty());
    }

    #[test]
    fn deploy_rejects_artifact_hash_mismatch() {
        let mut spec = sample_deploy_spec();
        spec.artifact_hash = "00".repeat(32);
        let error = build_deploy_transaction(&spec).unwrap_err().to_string();
        assert!(error.contains("artifact hash mismatch"), "{error}");
    }

    #[test]
    fn deploy_canonicalizes_equivalent_artifact_hash_text() {
        let mut spec = sample_deploy_spec();
        spec.artifact_hash = format!("0x{}", spec.artifact_hash.to_ascii_uppercase());
        let (_, evidence) = build_deploy_transaction(&spec).unwrap();
        assert_eq!(evidence.artifact_hash, hex::encode(blake2b_256(&spec.artifact_binary)));
    }

    #[test]
    fn deploy_uses_standard_secp_signing_placeholder() {
        let spec = sample_deploy_spec();
        let (tx, _) = build_deploy_transaction(&spec).unwrap();
        let witness = WitnessArgs::from_slice(tx.witnesses().get(0).unwrap().raw_data().as_ref()).unwrap();
        let lock = witness.lock().to_opt().expect("secp placeholder lock").raw_data();
        assert_eq!(lock.as_ref(), &[0u8; 65]);
    }

    #[test]
    fn deploy_rejects_fee_below_default_relay_floor() {
        let mut spec = sample_deploy_spec();
        spec.fee_shannons = 1;
        let error = build_deploy_transaction(&spec).unwrap_err().to_string();
        assert!(error.contains("policy floor"), "{error}");
    }

    #[test]
    fn deploy_rejects_empty_artifact() {
        let mut spec = sample_deploy_spec();
        spec.artifact_binary = Bytes::new();
        let error = build_deploy_transaction(&spec).unwrap_err().to_string();
        assert!(error.contains("artifact binary must be non-empty"), "{error}");
    }

    #[test]
    fn deploy_rejects_zero_capacity_input() {
        let mut spec = sample_deploy_spec();
        spec.capacity_input_shannons = 0;
        let error = build_deploy_transaction(&spec).unwrap_err().to_string();
        assert!(error.contains("non-zero capacity"), "{error}");
    }

    #[test]
    fn deploy_rejects_insufficient_input_capacity() {
        let mut spec = sample_deploy_spec();
        spec.capacity_input_shannons = 1; // far too small
        let error = build_deploy_transaction(&spec).unwrap_err().to_string();
        assert!(error.contains("insufficient"), "{error}");
    }

    #[test]
    fn deploy_rejects_insufficient_remaining_for_fee() {
        let mut spec = sample_deploy_spec();
        // Set fee to more than the entire input.
        spec.fee_shannons = spec.capacity_input_shannons;
        let error = build_deploy_transaction(&spec).unwrap_err().to_string();
        assert!(error.contains("insufficient for fee"), "{error}");
    }

    #[test]
    fn deploy_builds_deployment_manifest_from_evidence() {
        let spec = sample_deploy_spec();
        let (_tx, evidence) = build_deploy_transaction(&spec).unwrap();

        let tx_hash = [0xeeu8; 32];
        let manifest = build_deployment_manifest_from_evidence(&evidence, &tx_hash, 0);

        assert_eq!(manifest.schema, DEPLOYMENT_MANIFEST_SCHEMA);
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.deployments.len(), 1);

        let dep = &manifest.deployments[0];
        assert_eq!(dep.name, "test-token");
        assert!(dep.code_hash.starts_with("0x"));
        assert_eq!(dep.hash_type, "type");
        assert_eq!(dep.args, "0x");
        assert_eq!(dep.dep_type, "code");
        assert!(dep.out_point.contains(":0"));

        // Verify the manifest parses back correctly.
        let manifest_json = serde_json::to_vec(&manifest).unwrap();
        let reloaded = parse_deployment_manifest(&manifest_json).unwrap();
        assert_eq!(reloaded.deployments[0].name, "test-token");
    }

    #[test]
    fn deploy_with_cell_deps_includes_them_in_transaction() {
        let mut spec = sample_deploy_spec();
        let dep_out_point = packed::OutPoint::new_builder().tx_hash([0xffu8; 32].pack()).index(2u32).build();
        spec.cell_deps = vec![CellDep::new_builder().out_point(dep_out_point).dep_type(DepType::Code).build()];

        let (tx, evidence) = build_deploy_transaction(&spec).unwrap();
        assert_eq!(evidence.cell_deps, 1);
        assert_eq!(tx.cell_deps().len(), 1);
    }

    // ---- ManifestCellDepResolver tests ----

    #[test]
    fn manifest_resolver_resolves_deps_from_deployment_manifest() {
        let code_hash = blake2b_256([0xddu8; 64]);
        let tx_hash = [0xeeu8; 32];
        let manifest = DeploymentManifest {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
            version: 1,
            deployments: vec![DeploymentRef {
                name: "test-token".to_string(),
                code_hash: format!("0x{}", hex::encode(code_hash)),
                hash_type: "type".to_string(),
                args: "0x22".to_string(),
                dep_type: "code".to_string(),
                out_point: format!("0x{}:0", hex::encode(tx_hash)),
            }],
        };

        let resolver = ManifestCellDepResolver::from_manifest(&manifest).unwrap();
        assert_eq!(resolver.len(), 1);
        assert!(!resolver.is_empty());

        // Resolve by constructing a matching script.
        let script = Script::new_builder()
            .code_hash(code_hash.pack())
            .hash_type(ScriptHashType::Type)
            .args(Bytes::from(vec![0x22]).pack())
            .build();
        let dep = resolver.resolve_for_script(&script).expect("should resolve");
        assert_eq!(dep.dep_type(), DepType::Code.into());

        // Non-matching script should return None.
        let wrong_script = Script::new_builder()
            .code_hash([0x99u8; 32].pack())
            .hash_type(ScriptHashType::Data1)
            .args(Bytes::from(vec![0x22]).pack())
            .build();
        assert!(resolver.resolve_for_script(&wrong_script).is_none());
    }

    #[test]
    fn manifest_resolver_rejects_invalid_manifest_entries() {
        // Invalid code_hash (not 32 bytes).
        let manifest = DeploymentManifest {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
            version: 1,
            deployments: vec![DeploymentRef {
                name: "bad".to_string(),
                code_hash: "0x11".to_string(),
                hash_type: "type".to_string(),
                args: "0x22".to_string(),
                dep_type: "code".to_string(),
                out_point: format!("0x{}:0", hex::encode([0xeeu8; 32])),
            }],
        };
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("must be 32 bytes"), "{error}");
    }

    #[test]
    fn manifest_resolver_supports_data_and_type_hash_types() {
        let code_hash_data = blake2b_256([0x11u8; 32]);
        let code_hash_type = blake2b_256([0x22u8; 32]);
        let code_hash_data1 = blake2b_256([0x33u8; 32]);
        let code_hash_data2 = blake2b_256([0x44u8; 32]);
        let tx_hash = [0xeeu8; 32];
        let manifest = DeploymentManifest {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
            version: 1,
            deployments: vec![
                DeploymentRef {
                    name: "data-dep".to_string(),
                    code_hash: format!("0x{}", hex::encode(code_hash_data)),
                    hash_type: "data".to_string(),
                    args: "0x".to_string(),
                    dep_type: "code".to_string(),
                    out_point: format!("0x{}:0", hex::encode(tx_hash)),
                },
                DeploymentRef {
                    name: "type-dep".to_string(),
                    code_hash: format!("0x{}", hex::encode(code_hash_type)),
                    hash_type: "type".to_string(),
                    args: "0x".to_string(),
                    dep_type: "dep_group".to_string(),
                    out_point: format!("0x{}:1", hex::encode(tx_hash)),
                },
                DeploymentRef {
                    name: "data1-dep".to_string(),
                    code_hash: format!("0x{}", hex::encode(code_hash_data1)),
                    hash_type: "data1".to_string(),
                    args: "0x".to_string(),
                    dep_type: "code".to_string(),
                    out_point: format!("0x{}:2", hex::encode(tx_hash)),
                },
                DeploymentRef {
                    name: "data2-dep".to_string(),
                    code_hash: format!("0x{}", hex::encode(code_hash_data2)),
                    hash_type: "data2".to_string(),
                    args: "0x".to_string(),
                    dep_type: "dep_group".to_string(),
                    out_point: format!("0x{}:3", hex::encode(tx_hash)),
                },
            ],
        };

        let resolver = ManifestCellDepResolver::from_manifest(&manifest).unwrap();
        assert_eq!(resolver.len(), 4);

        let data_script =
            Script::new_builder().code_hash(code_hash_data.pack()).hash_type(ScriptHashType::Data).args(Bytes::new().pack()).build();
        let dep = resolver.resolve_for_script(&data_script).expect("data dep");
        assert_eq!(dep.dep_type(), DepType::Code.into());

        let type_script =
            Script::new_builder().code_hash(code_hash_type.pack()).hash_type(ScriptHashType::Type).args(Bytes::new().pack()).build();
        let dep = resolver.resolve_for_script(&type_script).expect("type dep");
        assert_eq!(dep.dep_type(), DepType::DepGroup.into());

        let data1_script =
            Script::new_builder().code_hash(code_hash_data1.pack()).hash_type(ScriptHashType::Data1).args(Bytes::new().pack()).build();
        let dep = resolver.resolve_for_script(&data1_script).expect("data1 dep");
        assert_eq!(dep.dep_type(), DepType::Code.into());

        let data2_script =
            Script::new_builder().code_hash(code_hash_data2.pack()).hash_type(ScriptHashType::Data2).args(Bytes::new().pack()).build();
        let dep = resolver.resolve_for_script(&data2_script).expect("data2 dep");
        assert_eq!(dep.dep_type(), DepType::DepGroup.into());
    }

    // ---- SigningAdapter tests ----

    #[test]
    fn signing_adapter_tracks_signer_labels_and_state() {
        let mut adapter = SigningAdapter::new(vec!["secp256k1-sighash".to_string()]);
        assert!(!adapter.signed);
        assert_eq!(adapter.signer_labels.len(), 1);

        let evidence = adapter.evidence();
        assert_eq!(evidence.schema, "cellscript-ckb-signing-adapter-v0.19");
        assert_eq!(evidence.signer_count, 1);
        assert!(!evidence.signed);

        adapter.mark_signed();
        assert!(adapter.signed);
        assert!(adapter.evidence().signed);
    }

    #[test]
    fn signing_adapter_for_secp_sighash() {
        let lock_arg = H160::from([0x44u8; 20]);
        let adapter = SigningAdapter::for_secp_sighash(lock_arg);
        assert!(adapter.signer_labels[0].contains("secp256k1-sighash"));
        assert!(adapter.signer_labels[0].contains("4444"));
    }

    // ---- CapacityBridge tests ----

    #[test]
    fn capacity_bridge_builds_balancer_and_evidence() {
        let change_lock = construct_script(&ScriptSpec::new([0x33u8; 32], ScriptHashType::Data1, vec![0x44u8; 20]));
        let bridge = CapacityBridge::new(change_lock.clone(), 1000);
        let balancer = bridge.to_balancer();
        // CapacityBalancer fields are private; just verify it doesn't panic.
        drop(balancer);

        let evidence = bridge.evidence();
        assert_eq!(evidence.schema, "cellscript-ckb-capacity-bridge-v0.19");
        assert_eq!(evidence.change_lock_hash, change_lock.calc_script_hash().as_slice().to_vec());
        assert_eq!(evidence.fee_rate, 1000);
    }

    // ---- TransactionLifecycleEvidence test ----

    #[test]
    fn lifecycle_evidence_records_full_transaction_flow() {
        let mut signing = SigningAdapter::new(vec!["test-signer".to_string()]);
        signing.mark_signed();

        let lifecycle = TransactionLifecycleEvidence {
            schema: "cellscript-ckb-tx-lifecycle-v0.19",
            deploy_evidence: None,
            action_evidence: None,
            signing: signing.evidence(),
            capacity: None,
            estimate_cycles: Some(45_000),
            tx_pool_accepted: true,
            submitted: true,
            committed: None,
        };

        assert!(lifecycle.signing.signed);
        assert_eq!(lifecycle.estimate_cycles, Some(45_000));
        assert!(lifecycle.tx_pool_accepted);
        assert!(lifecycle.submitted);

        let json = serde_json::to_value(&lifecycle).unwrap();
        assert_eq!(json["schema"], "cellscript-ckb-tx-lifecycle-v0.19");
        assert!(json["signing"]["signed"].as_bool().unwrap());
    }

    // ---- CellScriptAdapter facade tests ----

    #[test]
    fn adapter_connect_fails_on_unreachable_node() {
        let result = CellScriptAdapter::connect("http://127.0.0.1:19999");
        assert!(result.is_err(), "should fail connecting to non-existent node");
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("cannot connect"), "{msg}");
    }

    #[test]
    fn adapter_build_deploy_works_via_low_level_api() {
        let spec = sample_deploy_spec();
        let result = build_deploy_transaction(&spec);
        assert!(result.is_ok(), "low-level build_deploy_transaction should work without a node");
    }

    #[test]
    fn adapter_sample_action_plan_is_valid() {
        let plan = sample_action_plan();
        assert_eq!(plan.action, "mint");
        assert_eq!(plan.policy, ACTION_PLAN_POLICY);
        assert!(plan.artifact_hash.is_some());
        assert!(plan.transaction_draft.can_submit);
    }

    #[test]
    fn adapter_sample_deployment_manifest_round_trips() {
        // Verify a manifest can be created from deploy evidence and parsed back.
        let spec = sample_deploy_spec();
        let (_, evidence) = build_deploy_transaction(&spec).unwrap();
        let manifest = build_deployment_manifest_from_evidence(&evidence, &[0xabu8; 32], 0);
        assert_eq!(manifest.deployments.len(), 1);
        assert_eq!(manifest.deployments[0].name, "test-token");
    }

    fn materialized_action_plan_json(include_cell_dep: bool) -> serde_json::Value {
        let cell_deps = if include_cell_dep {
            serde_json::json!([{
                "out_point": {
                    "tx_hash": format!("0x{}", hex::encode([0x22u8; 32])),
                    "index": 1
                },
                "dep_type": "code"
            }])
        } else {
            serde_json::json!([])
        };
        serde_json::json!({
            "policy": ACTION_PLAN_POLICY,
            "action": "mint",
            "artifact_hash": "1".repeat(64),
            "metadata_hash": "0".repeat(64),
            "action_scan_selectors": {
                "schema": ACTION_SCAN_SELECTORS_SCHEMA,
                "source": "transaction_runtime_input_requirements",
                "selector_count": 1,
                "selectors": [{
                    "selector_index": 0,
                    "feature": "create-output:Token:create_Token",
                    "component": "create-output-fields",
                    "ckb_source": "Output",
                    "role": "transaction-output",
                    "binding": "create_Token",
                    "script_field": null
                }]
            },
            "transaction_draft": {
                "state": "ActionPlan",
                "can_submit": false,
                "requires_packed_materialization": true,
                "fee_shannons": 1_000,
                "inputs": [{
                    "previous_output": {
                        "tx_hash": format!("0x{}", hex::encode([0x11u8; 32])),
                        "index": "0x0"
                    },
                    "since": "0x0"
                }],
                "outputs": [{
                    "capacity": 100_000_000_000u64,
                    "lock": {
                        "code_hash": format!("0x{}", hex::encode([0x33u8; 32])),
                        "hash_type": "data1",
                        "args": format!("0x{}", hex::encode([0x44u8; 20]))
                    }
                }],
                "outputs_data": [format!("0x{}", hex::encode([0x55u8; 16]))],
                "witnesses": [{
                    "input_type": "0x6d696e74"
                }],
                "cell_deps": cell_deps,
                "header_deps": [],
                "lineage": [{
                    "from": {
                        "tx_hash": format!("0x{}", hex::encode([0x11u8; 32])),
                        "index": 0
                    },
                    "to_output_index": 0,
                    "relation": "state-continuation"
                }],
                "scan_selector_evidence": [{
                    "selector_index": 0,
                    "status": "resolved",
                    "source": "Output",
                    "role": "transaction-output",
                    "binding": "create_Token",
                    "feature": "create-output:Token:create_Token",
                    "component": "create-output-fields",
                    "script_field": null
                }]
            },
            "adapter_contract": {
                "schema": ADAPTER_CONTRACT_SCHEMA,
                "compiler_core_dependency": "no-ckb-sdk-rust",
                "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
                "resolved_tx_required_fields": ["outputs_data", "cell_deps", "lineage"]
            }
        })
    }

    fn manifest_with_single_deployment(code_hash: [u8; 32], hash_type: &str, dep_type: &str, out_point: &str) -> DeploymentManifest {
        DeploymentManifest {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
            version: 1,
            deployments: vec![DeploymentRef {
                name: "test-dep".to_string(),
                code_hash: format!("0x{}", hex::encode(code_hash)),
                hash_type: hash_type.to_string(),
                args: "0x".to_string(),
                dep_type: dep_type.to_string(),
                out_point: out_point.to_string(),
            }],
        }
    }

    #[test]
    fn materialized_action_plan_args_parts_concatenates_all_kinds_in_order() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([
            { "kind": "utf8", "value": "CS" },
            { "kind": "u8", "value": 7 },
            { "kind": "u32_le", "value": 42 },
            { "kind": "u64_le", "value": serde_json::json!(0x0102030405060708u64) },
            { "kind": "hex", "value": "0xaa55" }
        ]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let resolved = resolve_materialized_action_plan(&parsed).unwrap();
        let args = resolved.outputs[0].output.lock().args().raw_data();

        // utf8("CS") + u8(7) + u32_le(42) + u64_le(0x0102030405060708) + hex(aa55)
        assert_eq!(args, Bytes::from(vec![b'C', b'S', 7, 42, 0, 0, 0, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0xaa, 0x55]));
    }

    #[test]
    fn materialized_action_plan_rejects_unsupported_args_part_kind() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([{ "kind": "u128", "value": "1" }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();

        assert!(error.contains("unsupported"), "{error}");
        assert!(error.contains("expected hex, utf8, u8, u32_le, or u64_le"), "{error}");
    }

    #[test]
    fn materialized_action_plan_rejects_u8_overflow_args_part() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([{ "kind": "u8", "value": 300 }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();

        assert!(error.contains("does not fit in u8"), "{error}");
    }

    #[test]
    fn materialized_action_plan_rejects_u32_overflow_args_part() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] =
            serde_json::json!([{ "kind": "u32_le", "value": 4294967296u64 }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();

        assert!(error.contains("does not fit in u32"), "{error}");
    }

    #[test]
    fn materialized_action_plan_rejects_odd_length_hex_args_part() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([{ "kind": "hex", "value": "0xabc" }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();

        assert!(error.contains("even number of digits"), "{error}");
    }

    #[test]
    fn materialized_action_plan_rejects_non_string_args_part_value() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["outputs"][0]["lock"]["args"] = serde_json::json!("0x");
        plan["transaction_draft"]["outputs"][0]["lock"]["args_parts"] = serde_json::json!([{ "kind": "utf8", "value": 7 }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();

        assert!(error.contains("value must be a string"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_invalid_code_hash_hex() {
        let manifest = DeploymentManifest {
            schema: DEPLOYMENT_MANIFEST_SCHEMA.to_string(),
            version: 1,
            deployments: vec![DeploymentRef {
                name: "bad-hex".to_string(),
                code_hash: "0xnothex".to_string(),
                hash_type: "type".to_string(),
                args: "0x".to_string(),
                dep_type: "code".to_string(),
                out_point: format!("0x{}:0", hex::encode([0xeeu8; 32])),
            }],
        };
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("invalid code_hash hex"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_unknown_hash_type() {
        let code_hash = blake2b_256([0xf0u8; 64]);
        let manifest = manifest_with_single_deployment(code_hash, "data3", "code", &format!("0x{}:0", hex::encode([0xeeu8; 32])));
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("unknown hash_type 'data3'"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_malformed_out_point() {
        let code_hash = blake2b_256([0xf1u8; 64]);
        // Missing the colon-delimited index suffix.
        let manifest = manifest_with_single_deployment(code_hash, "type", "code", "0xdeadbeef");
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("invalid out_point format"), "{error}");
        assert!(error.contains("expected 0x<hash>:<index>"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_unknown_dep_type() {
        let code_hash = blake2b_256([0xf2u8; 64]);
        let manifest = manifest_with_single_deployment(code_hash, "type", "delegate", &format!("0x{}:0", hex::encode([0xeeu8; 32])));
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("unknown dep_type 'delegate'"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_non_u32_out_point_index() {
        let code_hash = blake2b_256([0xf3u8; 64]);
        let manifest =
            manifest_with_single_deployment(code_hash, "type", "code", &format!("0x{}:not-a-number", hex::encode([0xeeu8; 32])));
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("invalid out_point index"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_evidence_without_declared_selectors() {
        let mut plan = materialized_action_plan_json(true);
        // Drop the declared selectors but keep the runtime evidence: the adapter must
        // fail closed rather than silently accepting evidence it cannot match.
        plan["action_scan_selectors"] = serde_json::Value::Null;

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence was supplied without action_scan_selectors"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_length_mismatch() {
        let mut plan = materialized_action_plan_json(true);
        // Declare one selector (the default) but supply two evidence rows.
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([
            { "selector_index": 0, "status": "resolved", "source": "Output", "role": "transaction-output", "binding": "create_Token", "feature": "create-output:Token:create_Token", "component": "create-output-fields", "script_field": null },
            { "selector_index": 0, "status": "resolved", "source": "Output", "role": "transaction-output", "binding": "create_Token", "feature": "create-output:Token:create_Token", "component": "create-output-fields", "script_field": null }
        ]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("does not match action_scan_selectors.selector_count"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_undeclared_selector_index() {
        let mut plan = materialized_action_plan_json(true);
        // The declared selectors only include index 0; evidence for index 7 is undeclared.
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 7,
            "status": "resolved",
            "source": "Output",
            "role": "transaction-output",
            "binding": "create_Token",
            "feature": "create-output:Token:create_Token",
            "component": "create-output-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("selector_index 7 is not declared by action_scan_selectors"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_duplicate_selector_index_even_with_matching_length() {
        let mut plan = materialized_action_plan_json(true);
        let mut second_selector = plan["action_scan_selectors"]["selectors"][0].clone();
        second_selector["selector_index"] = serde_json::json!(1);
        second_selector["binding"] = serde_json::json!("create_Token_again");
        plan["action_scan_selectors"]["selector_count"] = serde_json::json!(2);
        plan["action_scan_selectors"]["selectors"].as_array_mut().unwrap().push(second_selector);
        let evidence = plan["transaction_draft"]["scan_selector_evidence"][0].clone();
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([evidence.clone(), evidence]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("duplicate selector_index 0"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_missing_declared_field() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["scan_selector_evidence"][0].as_object_mut().unwrap().remove("source");

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.source missing"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_unresolved_status() {
        let mut plan = materialized_action_plan_json(true);
        // Status must be exactly "resolved"; a pending scan must fail closed.
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 0,
            "status": "pending",
            "source": "Output",
            "role": "transaction-output",
            "binding": "create_Token",
            "feature": "create-output:Token:create_Token",
            "component": "create-output-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("must be 'resolved'"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_field_mismatch_source() {
        let mut plan = materialized_action_plan_json(true);
        // The declared selector reports ckb_source = "Output"; evidence disagrees.
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 0,
            "status": "resolved",
            "source": "Input",
            "role": "transaction-output",
            "binding": "create_Token",
            "feature": "create-output:Token:create_Token",
            "component": "create-output-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.source mismatch"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_field_mismatch_binding() {
        let mut plan = materialized_action_plan_json(true);
        // The declared selector binds to "create_Token"; evidence names a different binding.
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 0,
            "status": "resolved",
            "source": "Output",
            "role": "transaction-output",
            "binding": "create_Wei",
            "feature": "create-output:Token:create_Token",
            "component": "create-output-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.binding mismatch"), "{error}");
    }

    #[test]
    fn materialized_action_plan_fails_closed_on_empty_semantic_template() {
        // A semantic-template ActionPlan with no materialised inputs/outputs/cell_deps
        // must fail closed and instruct the builder runtime to resolve live cells.
        let plan = serde_json::json!({
            "policy": ACTION_PLAN_POLICY,
            "action": "mint",
            "artifact_hash": "1".repeat(64),
            "metadata_hash": "0".repeat(64),
            "transaction_draft": {
                "state": "ActionPlan",
                "can_submit": false,
                "requires_packed_materialization": true
            },
            "adapter_contract": {
                "schema": ADAPTER_CONTRACT_SCHEMA,
                "compiler_core_dependency": "no-ckb-sdk-rust",
                "transaction_realizer": "ckb-sdk-rust-or-CCC-adapter",
                "resolved_tx_required_fields": ["outputs_data", "cell_deps", "lineage"]
            }
        });

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("a builder runtime must resolve live cells"), "{error}");
        assert!(error.contains("ActionPlan 'mint'"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_short_out_point_tx_hash() {
        let code_hash = blake2b_256([0xf4u8; 64]);
        // out_point tx_hash is only 16 bytes; resolver must reject it.
        let manifest = manifest_with_single_deployment(code_hash, "type", "code", &format!("0x{}:0", hex::encode([0xeeu8; 16])));
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("out_point tx_hash for test-dep must be 32 bytes"), "{error}");
    }

    #[test]
    fn manifest_resolver_rejects_invalid_out_point_tx_hash_hex() {
        let code_hash = blake2b_256([0xf5u8; 64]);
        // out_point tx_hash is not valid hex.
        let manifest = manifest_with_single_deployment(code_hash, "type", "code", "0xnothex:0");
        let error = ManifestCellDepResolver::from_manifest(&manifest).unwrap_err().to_string();
        assert!(error.contains("invalid out_point tx_hash for test-dep"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_field_mismatch_feature() {
        let mut plan = materialized_action_plan_json(true);
        // The declared selector reports feature "create-output:Token:create_Token";
        // evidence names a different feature.
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 0,
            "status": "resolved",
            "source": "Output",
            "role": "transaction-output",
            "binding": "create_Token",
            "feature": "create-output:Token:create_Wei",
            "component": "create-output-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.feature mismatch"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_field_mismatch_component() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 0,
            "status": "resolved",
            "source": "Output",
            "role": "transaction-output",
            "binding": "create_Token",
            "feature": "create-output:Token:create_Token",
            "component": "consume-input-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.component mismatch"), "{error}");
    }

    #[test]
    fn scan_selector_evidence_rejects_field_mismatch_role() {
        let mut plan = materialized_action_plan_json(true);
        plan["transaction_draft"]["scan_selector_evidence"] = serde_json::json!([{
            "selector_index": 0,
            "status": "resolved",
            "source": "Output",
            "role": "transaction-input",
            "binding": "create_Token",
            "feature": "create-output:Token:create_Token",
            "component": "create-output-fields",
            "script_field": null
        }]);

        let parsed = parse_action_plan(serde_json::to_vec(&plan).unwrap().as_slice()).unwrap();
        let error = resolve_materialized_action_plan(&parsed).unwrap_err().to_string();
        assert!(error.contains("scan_selector_evidence.role mismatch"), "{error}");
    }
}
