//! Deterministic, artifact-only composition for multiple CKB Script artifacts.
//!
//! This module owns the offline ProtocolBundle boundary. It verifies each ELF
//! with the standalone artifact checker, binds exact deployment identities,
//! and rejects conflicting transaction-role claims before any signing or RPC
//! work. It deliberately does not link ELF files or model calls between CKB
//! Scripts.

use crate::assumptions::validate_transaction_against_metadata;
use crate::deployment_line_handle::{validate_deployment_line_admission_evidence, DeploymentLineAdmissionEvidence};
use crate::error::{CompileError, Result};
use crate::script_handle::{
    build_exact_script_handle, compile_metadata_abi_hash, exact_script_handle_value_hash, ExactScriptHandleReceipt,
    ExactScriptHandleReceiptInput, ExactScriptHandleValue,
};
use crate::{ckb_blake2b256, hex_encode, validate_artifact_metadata, CompileMetadata, TxValidationReport};
use cellscript_artifact_checker::{canonical_hash, check_bundle, CheckerBudgets, CheckerReport, EvidenceState};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const PROTOCOL_BUNDLE_SCHEMA: &str = "cellscript-protocol-bundle-v1";
pub const PROTOCOL_BUNDLE_INPUT_SCHEMA: &str = "cellscript-protocol-bundle-input-v1";
pub const PROTOCOL_BUNDLE_REPORT_SCHEMA: &str = "cellscript-protocol-bundle-report-v1";
pub const PROTOCOL_BUNDLE_EVIDENCE_SCHEMA: &str = "cellscript-protocol-bundle-evidence-v1";
pub const PROTOCOL_BUNDLE_HASH_DOMAIN: &str = "cellscript-protocol-bundle-v1";
pub const PROTOCOL_CLOSED_ROLE_SCHEMA: &str = "cellscript-protocol-closed-role-v1";

const MAX_ARTIFACTS: usize = 64;
const MAX_ROLE_BINDINGS: usize = 4_096;
const MAX_CLOSED_ROLE_BINDINGS: usize = 1_024;
const MAX_WITNESS_CLAIMS: usize = 4_096;
const MAX_DEP_CLAIMS: usize = 4_096;
const MAX_POLICY_CLAIMS: usize = 256;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolNetworkIdentity {
    pub chain_id: String,
    pub genesis_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolScriptRole {
    Lock,
    Type,
    SpawnedVerifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolEntryKind {
    Action,
    Lock,
    Function,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolEntryIdentity {
    pub kind: ProtocolEntryKind,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolArtifactFiles {
    pub artifact: String,
    pub metadata: String,
    pub lowering_record: String,
    pub source_map: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_manifest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolOutPoint {
    pub tx_hash: String,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDepType {
    Code,
    DepGroup,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolCellDep {
    pub out_point: ProtocolOutPoint,
    pub dep_type: ProtocolDepType,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolScriptIdentity {
    pub code_hash: String,
    pub hash_type: String,
    pub args: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolDeploymentIdentity {
    pub network: ProtocolNetworkIdentity,
    /// CKB default Blake2b-256 hash of the exact admitted ELF bytes, without
    /// a `0x` prefix. This is distinct from a Type-hash code identity.
    pub artifact_hash: String,
    pub script: ProtocolScriptIdentity,
    pub code_cell_dep: ProtocolCellDep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolArtifactInput {
    pub id: String,
    pub package_coordinate: String,
    pub lock_node_id: String,
    pub entry: ProtocolEntryIdentity,
    pub script_role: ProtocolScriptRole,
    pub files: ProtocolArtifactFiles,
    pub deployment: ProtocolDeploymentIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolCellLocation {
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolRoleOwnership {
    Exclusive,
    SharedRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRoleBinding {
    pub artifact: String,
    pub name: String,
    pub location: ProtocolCellLocation,
    pub index: u32,
    pub ownership: ProtocolRoleOwnership,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lock: Option<ProtocolScriptIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_type: Option<ProtocolScriptIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cell_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_capacity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_capacity: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRoleSchemaIdentity {
    pub type_name: String,
    /// Canonical Molecule schema hash from checked compile metadata.
    pub schema_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolClosedRoleKind {
    Cell,
    Witness,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolPhysicalRoleRef {
    pub artifact: String,
    pub claim: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolRoleCorrespondence {
    ExactPhysicalBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolRoleLocality {
    ClosedForeign,
}

/// Artifact-only declaration that one checked participant owns a typed Cell or
/// witness role and other checked participants consume the identical physical
/// value. Open/runtime-selected participants belong to the Script-handle
/// contract and are intentionally outside this closed-role record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolClosedRoleBinding {
    pub schema: String,
    pub role_id: String,
    pub kind: ProtocolClosedRoleKind,
    pub schema_identity: ProtocolRoleSchemaIdentity,
    pub provider: ProtocolPhysicalRoleRef,
    pub consumers: Vec<ProtocolPhysicalRoleRef>,
    pub correspondence: ProtocolRoleCorrespondence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolWitnessField {
    Lock,
    InputType,
    OutputType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolWitnessOwnership {
    ExclusiveWrite,
    SharedRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolWitnessClaim {
    pub artifact: String,
    pub name: String,
    pub index: u32,
    pub field: ProtocolWitnessField,
    pub ownership: ProtocolWitnessOwnership,
    pub abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolCellDepClaim {
    pub artifact: String,
    pub name: String,
    pub index: u32,
    pub cell_dep: ProtocolCellDep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolHeaderDepClaim {
    pub artifact: String,
    pub name: String,
    pub index: u32,
    pub header_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolPolicyKind {
    Fee,
    Change,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolPolicyOwnership {
    Exclusive,
    Shared,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolPolicyClaim {
    pub artifact: String,
    pub kind: ProtocolPolicyKind,
    pub ownership: ProtocolPolicyOwnership,
    pub policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolCellSlot {
    pub cell_commitment: String,
    pub capacity: u64,
    pub lock: ProtocolScriptIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<ProtocolScriptIdentity>,
    /// Concrete input identity for adapter materialization. Offline-only
    /// skeletons may omit it; the runtime adapter fails closed when it is
    /// absent from an input slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_point: Option<ProtocolOutPoint>,
    /// Concrete input `since` value. This is ignored for output slots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// Exact live-input or output data bytes. Output data is required by the
    /// runtime adapter before a packed transaction can be emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolWitnessSlot {
    /// CKB Blake2b-256 commitment to the exact field bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<String>,
    /// CKB Blake2b-256 commitment to the exact field bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    /// CKB Blake2b-256 commitment to the exact field bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_type: Option<String>,
    /// Exact field bytes used by runtime transaction materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock_bytes: Option<String>,
    /// Exact field bytes used by runtime transaction materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type_bytes: Option<String>,
    /// Exact field bytes used by runtime transaction materialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_type_bytes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolTransactionSkeleton {
    pub version: u32,
    pub inputs: Vec<ProtocolCellSlot>,
    pub outputs: Vec<ProtocolCellSlot>,
    pub witnesses: Vec<ProtocolWitnessSlot>,
    pub cell_deps: Vec<ProtocolCellDep>,
    pub header_deps: Vec<String>,
    pub fee_policy_hash: String,
    pub change_policy_hash: String,
    #[serde(default)]
    pub builder_assumption_evidence: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolBundleInput {
    pub schema: String,
    pub network: ProtocolNetworkIdentity,
    pub artifacts: Vec<ProtocolArtifactInput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_lines: Vec<DeploymentLineAdmissionEvidence>,
    pub transaction: ProtocolTransactionSkeleton,
    #[serde(default)]
    pub roles: Vec<ProtocolRoleBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed_roles: Vec<ProtocolClosedRoleBinding>,
    #[serde(default)]
    pub witnesses: Vec<ProtocolWitnessClaim>,
    #[serde(default)]
    pub cell_deps: Vec<ProtocolCellDepClaim>,
    #[serde(default)]
    pub header_deps: Vec<ProtocolHeaderDepClaim>,
    #[serde(default)]
    pub policies: Vec<ProtocolPolicyClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolArtifactIdentity {
    pub id: String,
    pub package_coordinate: String,
    pub lock_node_id: String,
    pub entry: ProtocolEntryIdentity,
    pub script_role: ProtocolScriptRole,
    pub deployment: ProtocolDeploymentIdentity,
    pub compiler_version: String,
    pub edition: String,
    pub metadata_schema_version: u32,
    pub artifact_hash: String,
    pub metadata_hash: String,
    pub typed_semantics_hash: String,
    pub lowering_record_hash: String,
    pub source_map_hash: String,
    pub interface_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_contracts: Vec<ProtocolRoleSchemaIdentity>,
    pub target_profile: String,
    pub target_profile_hash: String,
    pub runtime_abi_hash: String,
    pub exact_handle_receipt: ExactScriptHandleReceipt,
    pub exact_handle: ExactScriptHandleValue,
    pub exact_handle_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_manifest_hash: Option<String>,
    pub verified_bundle_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolClosedRoleParticipant {
    pub artifact: String,
    pub package_coordinate: String,
    pub entry: ProtocolEntryIdentity,
    pub script_role: ProtocolScriptRole,
    pub claim: String,
    pub interface_hash: String,
    pub artifact_hash: String,
    pub deployment: ProtocolDeploymentIdentity,
    pub exact_handle: ExactScriptHandleValue,
    pub exact_handle_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum ProtocolClosedRoleSource {
    Cell { location: ProtocolCellLocation, index: u32 },
    Witness { index: u32, field: ProtocolWitnessField },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedProtocolClosedRoleBinding {
    pub schema: String,
    pub role_id: String,
    pub locality: ProtocolRoleLocality,
    pub kind: ProtocolClosedRoleKind,
    pub schema_identity: ProtocolRoleSchemaIdentity,
    pub source: ProtocolClosedRoleSource,
    pub provider: ProtocolClosedRoleParticipant,
    pub consumers: Vec<ProtocolClosedRoleParticipant>,
    pub correspondence: ProtocolRoleCorrespondence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedProtocolBundle {
    pub schema: String,
    pub network: ProtocolNetworkIdentity,
    pub artifacts: Vec<ProtocolArtifactIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_lines: Vec<DeploymentLineAdmissionEvidence>,
    pub transaction: ProtocolTransactionSkeleton,
    pub roles: Vec<ProtocolRoleBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub closed_roles: Vec<ResolvedProtocolClosedRoleBinding>,
    pub witnesses: Vec<ProtocolWitnessClaim>,
    pub cell_deps: Vec<ProtocolCellDepClaim>,
    pub header_deps: Vec<ProtocolHeaderDepClaim>,
    pub policies: Vec<ProtocolPolicyClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolBundleConflict {
    pub code: String,
    pub class: String,
    pub key: String,
    pub artifacts: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolBundleEvidenceTemplate {
    pub schema: String,
    pub structural_verification: EvidenceState,
    pub artifact_admission: BTreeMap<String, CheckerReport>,
    pub metadata_transaction_validation: BTreeMap<String, TxValidationReport>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub deployment_line_admission: BTreeMap<String, EvidenceState>,
    pub transaction_serialization: EvidenceState,
    pub ckb_vm_execution: EvidenceState,
    pub chain_evidence: EvidenceState,
    pub exact_transaction_hash: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolBundleReport {
    pub schema: String,
    pub status: String,
    pub bundle_hash: String,
    pub bundle: ResolvedProtocolBundle,
    pub conflicts: Vec<ProtocolBundleConflict>,
    pub evidence: ProtocolBundleEvidenceTemplate,
}

/// Load, independently check, and compose one artifact-only ProtocolBundle.
pub fn check_protocol_bundle_file(path: &Path) -> Result<ProtocolBundleReport> {
    let bytes = read_bounded_file(path, MAX_MANIFEST_BYTES, "ProtocolBundle manifest")?;
    let input: ProtocolBundleInput = serde_json::from_slice(&bytes)
        .map_err(|error| CompileError::without_span(format!("failed to parse ProtocolBundle '{}': {}", path.display(), error)))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    check_protocol_bundle(&input, base)
}

/// Check an already parsed bundle using file paths relative to `base`.
pub fn check_protocol_bundle(input: &ProtocolBundleInput, base: &Path) -> Result<ProtocolBundleReport> {
    validate_input_shape(input)?;
    let base = std::fs::canonicalize(base).map_err(|error| {
        CompileError::without_span(format!("failed to canonicalize ProtocolBundle base '{}': {}", base.display(), error))
    })?;

    let mut identities = Vec::with_capacity(input.artifacts.len());
    let mut reports = BTreeMap::new();
    let mut metadata_validation = BTreeMap::new();
    let mut required_deployment_lines = BTreeSet::new();
    let transaction_value = serde_json::to_value(&input.transaction).map_err(|error| {
        CompileError::without_span(format!("failed to materialize ProtocolBundle transaction validation view: {error}"))
    })?;
    for artifact in &input.artifacts {
        let (identity, report, metadata) = admit_artifact(artifact, &base)?;
        if metadata.target_profile.name == "ckb-type-hash" {
            required_deployment_lines.insert(artifact.id.clone());
        }
        metadata_validation.insert(artifact.id.clone(), validate_transaction_against_metadata(&metadata, &transaction_value));
        reports.insert(artifact.id.clone(), report);
        identities.push(identity);
    }
    identities.sort_by(|left, right| left.id.cmp(&right.id));
    let mut deployment_line_admission = BTreeMap::new();
    let mut bound_deployment_lines = BTreeSet::new();
    for evidence in &input.deployment_lines {
        if !bound_deployment_lines.insert(evidence.artifact.clone()) {
            return Err(CompileError::without_span(format!(
                "duplicate deployment-line admission evidence for ProtocolBundle artifact '{}'",
                evidence.artifact
            )));
        }
        if !required_deployment_lines.contains(&evidence.artifact) {
            return Err(CompileError::without_span(format!(
                "deployment-line admission evidence targets artifact '{}' outside the ckb-type-hash profile",
                evidence.artifact
            )));
        }
        let artifact = identities.iter().find(|artifact| artifact.id == evidence.artifact).ok_or_else(|| {
            CompileError::without_span(format!(
                "deployment-line admission evidence references unknown ProtocolBundle artifact '{}'",
                evidence.artifact
            ))
        })?;
        validate_deployment_line_admission_evidence(evidence, &artifact.exact_handle_receipt, &input.transaction)?;
        deployment_line_admission.insert(evidence.artifact.clone(), EvidenceState::Verified);
    }
    if bound_deployment_lines != required_deployment_lines {
        let missing = required_deployment_lines.difference(&bound_deployment_lines).cloned().collect::<Vec<_>>().join(", ");
        return Err(CompileError::without_span(format!(
            "ckb-type-hash ProtocolBundle artifacts require exact active deployment-line admission evidence; missing: {missing}"
        )));
    }
    let closed_roles = resolve_closed_roles(&input.closed_roles, &identities, &input.roles, &input.witnesses)?;

    let mut bundle = ResolvedProtocolBundle {
        schema: PROTOCOL_BUNDLE_SCHEMA.to_string(),
        network: normalized_network(&input.network)?,
        artifacts: identities,
        deployment_lines: input.deployment_lines.clone(),
        transaction: input.transaction.clone(),
        roles: input.roles.clone(),
        closed_roles,
        witnesses: input.witnesses.clone(),
        cell_deps: input.cell_deps.clone(),
        header_deps: input.header_deps.clone(),
        policies: input.policies.clone(),
    };
    canonicalize_bundle(&mut bundle);
    let mut conflicts = detect_conflicts(&bundle)?;
    for (artifact, validation) in &metadata_validation {
        if validation.status != "ok" {
            push_conflict(
                &mut conflicts,
                "PB212",
                "builder-validation",
                format!("artifact:{artifact}"),
                vec![artifact.clone()],
                format!("candidate transaction violates {} metadata builder assumption(s)", validation.violations.len()),
            );
        }
    }
    conflicts.sort();
    conflicts.dedup();
    let bundle_hash_value = serde_json::to_value(&bundle)
        .map_err(|error| CompileError::without_span(format!("failed to canonicalize ProtocolBundle for hashing: {error}")))?;
    let bundle_hash = canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &bundle_hash_value)
        .map_err(|error| CompileError::without_span(format!("failed to hash ProtocolBundle: {error}")))?;
    let status = if conflicts.is_empty() { "ok" } else { "failed" };
    Ok(ProtocolBundleReport {
        schema: PROTOCOL_BUNDLE_REPORT_SCHEMA.to_string(),
        status: status.to_string(),
        bundle_hash,
        bundle,
        conflicts,
        evidence: ProtocolBundleEvidenceTemplate {
            schema: PROTOCOL_BUNDLE_EVIDENCE_SCHEMA.to_string(),
            structural_verification: if status == "ok" { EvidenceState::Verified } else { EvidenceState::NotProvided },
            artifact_admission: reports,
            metadata_transaction_validation: metadata_validation,
            deployment_line_admission,
            transaction_serialization: EvidenceState::NotExecuted,
            ckb_vm_execution: EvidenceState::NotExecuted,
            chain_evidence: EvidenceState::NotExecuted,
            exact_transaction_hash: None,
            note: "offline composition only; the runtime adapter must materialize one transaction and execute every Script Group against identical bytes"
                .to_string(),
        },
    })
}

fn validate_input_shape(input: &ProtocolBundleInput) -> Result<()> {
    if input.schema != PROTOCOL_BUNDLE_INPUT_SCHEMA {
        return Err(CompileError::without_span(format!(
            "unsupported ProtocolBundle schema '{}'; expected '{}'",
            input.schema, PROTOCOL_BUNDLE_INPUT_SCHEMA
        )));
    }
    validate_network(&input.network, "bundle network")?;
    if !(2..=MAX_ARTIFACTS).contains(&input.artifacts.len()) {
        return Err(CompileError::without_span(format!("ProtocolBundle must contain between 2 and {MAX_ARTIFACTS} artifacts")));
    }
    bounded_count("deployment-line admissions", input.deployment_lines.len(), MAX_ARTIFACTS)?;
    bounded_count("role bindings", input.roles.len(), MAX_ROLE_BINDINGS)?;
    bounded_count("closed role bindings", input.closed_roles.len(), MAX_CLOSED_ROLE_BINDINGS)?;
    bounded_count("witness claims", input.witnesses.len(), MAX_WITNESS_CLAIMS)?;
    bounded_count("CellDep claims", input.cell_deps.len(), MAX_DEP_CLAIMS)?;
    bounded_count("HeaderDep claims", input.header_deps.len(), MAX_DEP_CLAIMS)?;
    bounded_count("policy claims", input.policies.len(), MAX_POLICY_CLAIMS)?;

    let mut ids = BTreeSet::new();
    for artifact in &input.artifacts {
        validate_name(&artifact.id, "artifact id")?;
        if !ids.insert(artifact.id.clone()) {
            return Err(CompileError::without_span(format!("duplicate ProtocolBundle artifact id '{}'", artifact.id)));
        }
        validate_name(&artifact.package_coordinate, "package coordinate")?;
        validate_name(&artifact.lock_node_id, "Cell.lock node identity")?;
        validate_name(&artifact.entry.name, "entry name")?;
        validate_deployment(&artifact.deployment)?;
    }
    validate_transaction(&input.transaction)?;
    Ok(())
}

fn bounded_count(label: &str, actual: usize, maximum: usize) -> Result<()> {
    if actual > maximum {
        Err(CompileError::without_span(format!("ProtocolBundle {label} count {actual} exceeds {maximum}")))
    } else {
        Ok(())
    }
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(CompileError::without_span(format!("ProtocolBundle {label} must be a non-empty bounded string")))
    } else {
        Ok(())
    }
}

fn validate_network(network: &ProtocolNetworkIdentity, label: &str) -> Result<()> {
    validate_name(&network.chain_id, &format!("{label} chain_id"))?;
    canonical_hash32(&network.genesis_hash, &format!("{label} genesis_hash"))?;
    Ok(())
}

fn normalized_network(network: &ProtocolNetworkIdentity) -> Result<ProtocolNetworkIdentity> {
    Ok(ProtocolNetworkIdentity {
        chain_id: network.chain_id.clone(),
        genesis_hash: canonical_hash32(&network.genesis_hash, "network genesis_hash")?,
    })
}

pub(crate) fn validate_deployment(deployment: &ProtocolDeploymentIdentity) -> Result<()> {
    validate_network(&deployment.network, "artifact deployment network")?;
    canonical_raw_hash32(&deployment.artifact_hash, "deployment artifact_hash")?;
    validate_script(&deployment.script, "deployment script")?;
    validate_cell_dep(&deployment.code_cell_dep, "deployment code CellDep")?;
    Ok(())
}

fn validate_script(script: &ProtocolScriptIdentity, label: &str) -> Result<()> {
    canonical_hash32(&script.code_hash, &format!("{label} code_hash"))?;
    if !matches!(script.hash_type.as_str(), "data" | "data1" | "data2" | "type") {
        return Err(CompileError::without_span(format!("{label} hash_type must be data, data1, data2, or type")));
    }
    canonical_hex_bytes(&script.args, &format!("{label} args"))?;
    Ok(())
}

fn validate_cell_dep(cell_dep: &ProtocolCellDep, label: &str) -> Result<()> {
    canonical_hash32(&cell_dep.out_point.tx_hash, &format!("{label} tx_hash"))?;
    Ok(())
}

fn validate_transaction(transaction: &ProtocolTransactionSkeleton) -> Result<()> {
    if transaction.version != 0 {
        return Err(CompileError::without_span("ProtocolBundle transaction version must be 0"));
    }
    bounded_count("transaction inputs", transaction.inputs.len(), MAX_ROLE_BINDINGS)?;
    bounded_count("transaction outputs", transaction.outputs.len(), MAX_ROLE_BINDINGS)?;
    bounded_count("transaction witnesses", transaction.witnesses.len(), MAX_WITNESS_CLAIMS)?;
    bounded_count("transaction CellDeps", transaction.cell_deps.len(), MAX_DEP_CLAIMS)?;
    bounded_count("transaction HeaderDeps", transaction.header_deps.len(), MAX_DEP_CLAIMS)?;
    for (index, cell) in transaction.inputs.iter().enumerate() {
        validate_cell_slot(cell, &format!("input[{index}]"))?;
        if let Some(out_point) = &cell.out_point {
            canonical_hash32(&out_point.tx_hash, &format!("input[{index}].out_point.tx_hash"))?;
        }
    }
    for (index, cell) in transaction.outputs.iter().enumerate() {
        validate_cell_slot(cell, &format!("output[{index}]"))?;
    }
    for (index, witness) in transaction.witnesses.iter().enumerate() {
        for (field, commitment, bytes) in [
            ("lock", witness.lock.as_deref(), witness.lock_bytes.as_deref()),
            ("input_type", witness.input_type.as_deref(), witness.input_type_bytes.as_deref()),
            ("output_type", witness.output_type.as_deref(), witness.output_type_bytes.as_deref()),
        ] {
            validate_witness_materialization(index, field, commitment, bytes)?;
        }
    }
    for (index, cell_dep) in transaction.cell_deps.iter().enumerate() {
        validate_cell_dep(cell_dep, &format!("cell_deps[{index}]"))?;
    }
    for (index, header) in transaction.header_deps.iter().enumerate() {
        canonical_hash32(header, &format!("header_deps[{index}]"))?;
    }
    canonical_hash32(&transaction.fee_policy_hash, "fee_policy_hash")?;
    canonical_hash32(&transaction.change_policy_hash, "change_policy_hash")?;
    Ok(())
}

fn validate_cell_slot(cell: &ProtocolCellSlot, label: &str) -> Result<()> {
    canonical_hash32(&cell.cell_commitment, &format!("{label} cell_commitment"))?;
    validate_script(&cell.lock, &format!("{label} lock"))?;
    if let Some(script) = &cell.r#type {
        validate_script(script, &format!("{label} type"))?;
    }
    if let Some(data) = &cell.data {
        canonical_hex_bytes(data, &format!("{label} data"))?;
    }
    Ok(())
}

fn validate_witness_materialization(index: usize, field: &str, commitment: Option<&str>, bytes: Option<&str>) -> Result<()> {
    if let Some(commitment) = commitment {
        canonical_hash32(commitment, &format!("witness[{index}].{field}"))?;
    }
    let Some(bytes) = bytes else {
        return Ok(());
    };
    canonical_hex_bytes(bytes, &format!("witness[{index}].{field}_bytes"))?;
    if let Some(commitment) = commitment {
        let raw = hex::decode(&bytes[2..]).map_err(|error| {
            CompileError::without_span(format!("failed to decode witness[{index}].{field}_bytes after validation: {error}"))
        })?;
        let actual = format!("0x{}", hex_encode(&ckb_blake2b256(&raw)));
        if actual != commitment {
            return Err(CompileError::without_span(format!(
                "witness[{index}].{field}_bytes does not match its CKB Blake2b-256 commitment"
            )));
        }
    }
    Ok(())
}

fn canonical_raw_hash32(value: &str, label: &str) -> Result<String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        Ok(value.to_string())
    } else {
        Err(CompileError::without_span(format!("{label} must be exactly 32 bytes of lowercase hex without 0x")))
    }
}

fn canonical_hash32(value: &str, label: &str) -> Result<String> {
    let Some(raw) = value.strip_prefix("0x") else {
        return Err(CompileError::without_span(format!("{label} must use canonical 0x-prefixed lowercase hex")));
    };
    canonical_raw_hash32(raw, label)?;
    Ok(value.to_string())
}

fn canonical_hex_bytes(value: &str, label: &str) -> Result<()> {
    let Some(raw) = value.strip_prefix("0x") else {
        return Err(CompileError::without_span(format!("{label} must use canonical 0x-prefixed lowercase hex")));
    };
    if raw.len() % 2 != 0 || !raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(CompileError::without_span(format!("{label} must contain an even number of lowercase hex digits")));
    }
    Ok(())
}

fn read_bounded_file(path: &Path, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| CompileError::without_span(format!("failed to inspect {label} '{}': {}", path.display(), error)))?;
    if !metadata.is_file() {
        return Err(CompileError::without_span(format!("{label} '{}' is not a regular file", path.display())));
    }
    if metadata.len() > maximum {
        return Err(CompileError::without_span(format!("{label} '{}' exceeds {} bytes", path.display(), maximum)));
    }
    std::fs::read(path).map_err(|error| CompileError::without_span(format!("failed to read {label} '{}': {}", path.display(), error)))
}

fn confined_path(base: &Path, value: &str, label: &str) -> Result<PathBuf> {
    let relative = Path::new(value);
    if relative.is_absolute() {
        return Err(CompileError::without_span(format!("ProtocolBundle {label} path must be relative")));
    }
    let path = std::fs::canonicalize(base.join(relative))
        .map_err(|error| CompileError::without_span(format!("failed to resolve ProtocolBundle {label} '{}': {}", value, error)))?;
    if !path.starts_with(base) {
        return Err(CompileError::without_span(format!("ProtocolBundle {label} path '{}' escapes the bundle directory", value)));
    }
    Ok(path)
}

fn admit_artifact(input: &ProtocolArtifactInput, base: &Path) -> Result<(ProtocolArtifactIdentity, CheckerReport, CompileMetadata)> {
    let artifact_path = confined_path(base, &input.files.artifact, "artifact")?;
    let metadata_path = confined_path(base, &input.files.metadata, "metadata")?;
    let lowering_path = confined_path(base, &input.files.lowering_record, "lowering record")?;
    let source_map_path = confined_path(base, &input.files.source_map, "source map")?;
    let artifact_bytes = read_bounded_file(&artifact_path, MAX_ARTIFACT_BYTES, "artifact")?;
    let metadata_bytes = read_bounded_file(&metadata_path, MAX_METADATA_BYTES, "metadata")?;
    let lowering_bytes = read_bounded_file(&lowering_path, MAX_RECORD_BYTES, "lowering record")?;
    let source_map_bytes = read_bounded_file(&source_map_path, MAX_RECORD_BYTES, "source map")?;

    let report = check_bundle(&artifact_bytes, &metadata_bytes, &lowering_bytes, &source_map_bytes, &CheckerBudgets::default())
        .map_err(|error| {
            CompileError::without_span(format!("ProtocolBundle artifact '{}' failed standalone checking: {error}", input.id))
        })?;
    if report.binding_verification != EvidenceState::Verified
        || report.structural_verification != EvidenceState::Verified
        || report.lowering_record_verification != EvidenceState::Verified
        || report.typed_semantics_verification != EvidenceState::Verified
    {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' does not carry complete checked ELF evidence",
            input.id
        )));
    }

    let metadata: CompileMetadata = serde_json::from_slice(&metadata_bytes).map_err(|error| {
        CompileError::without_span(format!("failed to parse ProtocolBundle metadata '{}': {}", metadata_path.display(), error))
    })?;
    if metadata.artifact_format != "RISC-V ELF" {
        return Err(CompileError::without_span(format!("ProtocolBundle artifact '{}' must be a RISC-V ELF", input.id)));
    }
    let validated = validate_artifact_metadata(artifact_bytes, metadata)?;
    let metadata = validated.metadata;
    validate_entry(input, &metadata)?;

    let artifact_hash = metadata
        .artifact_hash
        .as_deref()
        .ok_or_else(|| CompileError::without_span(format!("ProtocolBundle artifact '{}' metadata has no artifact_hash", input.id)))?;
    if artifact_hash != input.deployment.artifact_hash || artifact_hash != report.artifact_hash {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' deployment artifact_hash does not match the checked ELF",
            input.id
        )));
    }
    if input.deployment.script.hash_type != "type" && input.deployment.script.code_hash.strip_prefix("0x") != Some(artifact_hash) {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' data-hash deployment code_hash does not match the checked ELF",
            input.id
        )));
    }
    if !metadata.target_profile.deployment_hash_types.contains(&input.deployment.script.hash_type) {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' deployment hash_type '{}' is outside target profile '{}'",
            input.id, input.deployment.script.hash_type, metadata.target_profile.name
        )));
    }

    let metadata_hash = canonical_hash("cellscript-compile-metadata", &metadata)
        .map_err(|error| CompileError::without_span(format!("failed to hash metadata for '{}': {error}", input.id)))?;
    let target_profile_hash = canonical_hash("cellscript-target-profile", &metadata.target_profile)
        .map_err(|error| CompileError::without_span(format!("failed to hash target profile for '{}': {error}", input.id)))?;
    let runtime_abi_hash = compile_metadata_abi_hash(&metadata)?;
    let verified_bundle_id = metadata.verified_artifact.verified_bundle_id.clone().ok_or_else(|| {
        CompileError::without_span(format!("ProtocolBundle artifact '{}' metadata has no verified_bundle_id", input.id))
    })?;
    if input.entry.kind == ProtocolEntryKind::Action && input.files.builder_manifest.is_none() {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle action artifact '{}' requires a generated builder manifest",
            input.id
        )));
    }
    let builder_manifest_hash =
        input.files.builder_manifest.as_deref().map(|path| validate_builder_manifest(input, &metadata, base, path)).transpose()?;
    let mut schema_contracts = metadata
        .molecule_schema_manifest
        .entries
        .iter()
        .map(|entry| ProtocolRoleSchemaIdentity { type_name: entry.type_name.clone(), schema_hash: entry.schema_hash.clone() })
        .collect::<Vec<_>>();
    schema_contracts.sort();
    schema_contracts.dedup();
    let (exact_handle_receipt, exact_handle) = build_exact_script_handle(ExactScriptHandleReceiptInput {
        package_coordinate: &input.package_coordinate,
        lock_node_id: &input.lock_node_id,
        entry: &input.entry,
        script_role: input.script_role,
        interface_hash: &metadata.interface_hash,
        typed_semantics_hash: &metadata.typed_semantics_hash,
        artifact_hash,
        target_profile_hash: &target_profile_hash,
        runtime_abi_hash: &runtime_abi_hash,
        verified_bundle_id: &verified_bundle_id,
        deployment: &input.deployment,
    })?;
    let exact_handle_hash = exact_script_handle_value_hash(&exact_handle)?;
    Ok((
        ProtocolArtifactIdentity {
            id: input.id.clone(),
            package_coordinate: input.package_coordinate.clone(),
            lock_node_id: input.lock_node_id.clone(),
            entry: input.entry.clone(),
            script_role: input.script_role,
            deployment: input.deployment.clone(),
            compiler_version: metadata.compiler_version.clone(),
            edition: metadata.edition.to_string(),
            metadata_schema_version: metadata.metadata_schema_version,
            artifact_hash: artifact_hash.to_string(),
            metadata_hash,
            typed_semantics_hash: metadata.typed_semantics_hash.clone(),
            lowering_record_hash: report.lowering_record_hash.clone(),
            source_map_hash: report.source_map_hash.clone(),
            interface_hash: metadata.interface_hash.clone(),
            schema_contracts,
            target_profile: metadata.target_profile.name.clone(),
            target_profile_hash,
            runtime_abi_hash,
            exact_handle_receipt,
            exact_handle,
            exact_handle_hash,
            builder_manifest_hash,
            verified_bundle_id,
        },
        report,
        metadata,
    ))
}

fn validate_builder_manifest(input: &ProtocolArtifactInput, metadata: &CompileMetadata, base: &Path, path: &str) -> Result<String> {
    let path = confined_path(base, path, "builder manifest")?;
    let bytes = read_bounded_file(&path, MAX_METADATA_BYTES, "builder manifest")?;
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        CompileError::without_span(format!("failed to parse ProtocolBundle builder manifest '{}': {}", path.display(), error))
    })?;
    if manifest.get("schema").and_then(serde_json::Value::as_str) != Some("cellscript-generated-action-builder-v0.23-edition-2026") {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' builder manifest has an unsupported schema",
            input.id
        )));
    }
    let expected_metadata_hash = hex_encode(&ckb_blake2b256(
        &serde_json::to_vec(metadata)
            .map_err(|error| CompileError::without_span(format!("failed to hash metadata for builder validation: {error}")))?,
    ));
    let expected_runtime_abi_hash = compile_metadata_abi_hash(metadata)?;
    let expected_target_profile_hash = canonical_hash("cellscript-target-profile", &metadata.target_profile)
        .map_err(|error| CompileError::without_span(format!("failed to hash builder target profile: {error}")))?;
    let checks = [
        ("metadata_hash", Some(expected_metadata_hash.as_str())),
        ("artifact_hash", metadata.artifact_hash.as_deref()),
        ("compiler_version", Some(metadata.compiler_version.as_str())),
        ("target_profile", Some(metadata.target_profile.name.as_str())),
        ("target_profile_hash", Some(expected_target_profile_hash.as_str())),
        ("runtime_abi_hash", Some(expected_runtime_abi_hash.as_str())),
        ("interface_hash", Some(metadata.interface_hash.as_str())),
        ("typed_semantics_hash", Some(metadata.typed_semantics_hash.as_str())),
        ("verified_bundle_id", metadata.verified_artifact.verified_bundle_id.as_deref()),
    ];
    for (field, expected) in checks {
        if manifest.get(field).and_then(serde_json::Value::as_str) != expected {
            return Err(CompileError::without_span(format!(
                "ProtocolBundle artifact '{}' builder manifest field '{}' does not match checked metadata",
                input.id, field
            )));
        }
    }
    let structural_checks = [
        ("edition", serde_json::to_value(metadata.edition)),
        ("metadata_schema_version", serde_json::to_value(metadata.metadata_schema_version)),
        ("compatibility_profile", serde_json::to_value(&metadata.compatibility_profile)),
        ("molecule_schema_manifest", serde_json::to_value(&metadata.molecule_schema_manifest)),
        ("cell_data_codec_manifest", serde_json::to_value(&metadata.cell_data_codec_manifest)),
        ("transaction_view_handles", serde_json::to_value(&metadata.runtime.transaction_view_handles)),
        ("signing_message_domains", serde_json::to_value(&metadata.runtime.signing_message_domains)),
        (
            "protocol_bundle_contract",
            Ok(serde_json::json!({
                "schema": "cellscript-protocol-bundle-v1",
                "report_schema": "cellscript-protocol-bundle-report-v1",
                "artifact_binding_schema": "cellscript-protocol-bundle-artifact-binding-v1",
                "closed_role_schema": "cellscript-protocol-closed-role-v1",
                "deployment_line_admission_evidence_schema": "cellscript-deployment-line-admission-evidence-v1",
                "deployment_line_admission_transition_schema": "cellscript-deployment-line-admission-transition-v1",
                "requires_deployment_line_admission": metadata.target_profile.name == "ckb-type-hash",
                "exact_handle_receipt_schema": "cellscript-exact-script-handle-receipt-v1",
                "exact_handle_value_schema": "cellscript-exact-script-handle-value-v1",
                "exact_handle_encoding": "CSHDLv1-fixed-202",
                "exact_handle_hash_algorithm": "ckb-blake2b-256",
                "exact_handle_hash_personalization": "ckb-default-hash",
                "runtime_adapter": "cellscript-ckb-adapter",
                "states": [
                    "MaterializedProtocolBundleTx",
                    "LiveResolvedProtocolBundleTx",
                    "LiveDependenciesResolvedProtocolBundleTx",
                    "ReadyToSignProtocolBundleTx",
                    "SignedProtocolBundleTx",
                    "SignedDryRunProtocolBundleTx",
                    "TxPoolAcceptedProtocolBundleTx",
                    "SubmittedProtocolBundleTx",
                    "ConfirmedProtocolBundleTx"
                ],
                "private_keys": "never-in-bundle-or-evidence"
            })),
        ),
    ];
    for (field, expected) in structural_checks {
        let expected = expected.map_err(|error| {
            CompileError::without_span(format!("failed to project metadata field '{field}' for builder validation: {error}"))
        })?;
        if manifest.get(field) != Some(&expected) {
            return Err(CompileError::without_span(format!(
                "ProtocolBundle artifact '{}' builder manifest field '{}' does not match checked metadata",
                input.id, field
            )));
        }
    }
    if manifest.pointer("/runtime_contract/runtime_access_provenance").and_then(serde_json::Value::as_str)
        != Some(metadata.runtime.ckb_runtime_access_provenance_contract.as_str())
    {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' builder runtime-access provenance does not match checked metadata",
            input.id
        )));
    }
    if input.entry.kind == ProtocolEntryKind::Action {
        let action = metadata.actions.iter().find(|action| action.name == input.entry.name).ok_or_else(|| {
            CompileError::without_span(format!("ProtocolBundle artifact '{}' selected action disappeared from metadata", input.id))
        })?;
        let projected = manifest
            .get("actions")
            .and_then(serde_json::Value::as_array)
            .and_then(|actions| {
                actions.iter().find(|candidate| candidate.get("name").and_then(serde_json::Value::as_str) == Some(&input.entry.name))
            })
            .ok_or_else(|| {
                CompileError::without_span(format!(
                    "ProtocolBundle artifact '{}' builder manifest does not expose selected action '{}'",
                    input.id, input.entry.name
                ))
            })?;
        let action_checks = [
            ("params", serde_json::to_value(&action.params)),
            ("created_outputs", serde_json::to_value(action.create_set.len())),
            ("mutated_outputs", serde_json::to_value(action.mutate_set.len())),
            ("runtime_input_requirements", serde_json::to_value(action.transaction_runtime_input_requirements.len())),
            ("runtime_accesses", serde_json::to_value(&action.ckb_runtime_accesses)),
        ];
        for (field, expected) in action_checks {
            let expected = expected.map_err(|error| {
                CompileError::without_span(format!("failed to project action field '{field}' for builder validation: {error}"))
            })?;
            if projected.get(field) != Some(&expected) {
                return Err(CompileError::without_span(format!(
                    "ProtocolBundle artifact '{}' builder action '{}' field '{}' does not match checked metadata",
                    input.id, input.entry.name, field
                )));
            }
        }
    }
    canonical_hash("cellscript-generated-action-builder-v0.23-edition-2026", &manifest)
        .map_err(|error| CompileError::without_span(format!("failed to hash builder manifest for '{}': {error}", input.id)))
}

fn validate_entry(input: &ProtocolArtifactInput, metadata: &CompileMetadata) -> Result<()> {
    let exists = match input.entry.kind {
        ProtocolEntryKind::Action => metadata.actions.iter().any(|entry| entry.name == input.entry.name),
        ProtocolEntryKind::Lock => metadata.locks.iter().any(|entry| entry.name == input.entry.name),
        ProtocolEntryKind::Function => metadata.functions.iter().any(|entry| entry.name == input.entry.name),
    };
    if !exists {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' metadata does not expose {:?} entry '{}'",
            input.id, input.entry.kind, input.entry.name
        )));
    }
    let compatible = matches!(
        (input.script_role, input.entry.kind),
        (ProtocolScriptRole::Lock, ProtocolEntryKind::Lock)
            | (ProtocolScriptRole::Type, ProtocolEntryKind::Action)
            | (ProtocolScriptRole::SpawnedVerifier, _)
    );
    if !compatible {
        return Err(CompileError::without_span(format!(
            "ProtocolBundle artifact '{}' Script role {:?} is incompatible with {:?} entry '{}'",
            input.id, input.script_role, input.entry.kind, input.entry.name
        )));
    }
    Ok(())
}

fn resolve_closed_roles(
    bindings: &[ProtocolClosedRoleBinding],
    artifacts: &[ProtocolArtifactIdentity],
    roles: &[ProtocolRoleBinding],
    witnesses: &[ProtocolWitnessClaim],
) -> Result<Vec<ResolvedProtocolClosedRoleBinding>> {
    let mut role_ids = BTreeSet::new();
    let mut resolved = Vec::with_capacity(bindings.len());
    for binding in bindings {
        if binding.schema != PROTOCOL_CLOSED_ROLE_SCHEMA {
            return Err(CompileError::without_span(format!(
                "unsupported ProtocolBundle closed role schema '{}'; expected '{}'",
                binding.schema, PROTOCOL_CLOSED_ROLE_SCHEMA
            )));
        }
        validate_name(&binding.role_id, "closed role id")?;
        validate_name(&binding.schema_identity.type_name, "closed role schema type_name")?;
        canonical_raw_hash32(&binding.schema_identity.schema_hash, "closed role schema_hash")?;
        if !role_ids.insert(binding.role_id.clone()) {
            return Err(CompileError::without_span(format!("duplicate ProtocolBundle closed role id '{}'", binding.role_id)));
        }
        if binding.consumers.is_empty() {
            return Err(CompileError::without_span(format!(
                "ProtocolBundle closed role '{}' requires at least one consumer",
                binding.role_id
            )));
        }
        bounded_count(&format!("closed role '{}' consumers", binding.role_id), binding.consumers.len(), MAX_ARTIFACTS - 1)?;

        let (provider, source) =
            resolve_closed_role_participant(&binding.provider, binding.kind, artifacts, roles, witnesses, &binding.role_id)?;
        let mut consumers = Vec::with_capacity(binding.consumers.len());
        let mut participant_artifacts = BTreeSet::new();
        participant_artifacts.insert(binding.provider.artifact.as_str());
        for consumer_ref in &binding.consumers {
            if !participant_artifacts.insert(consumer_ref.artifact.as_str()) {
                return Err(CompileError::without_span(format!(
                    "ProtocolBundle closed role '{}' repeats participant artifact '{}'",
                    binding.role_id, consumer_ref.artifact
                )));
            }
            let (consumer, _) =
                resolve_closed_role_participant(consumer_ref, binding.kind, artifacts, roles, witnesses, &binding.role_id)?;
            consumers.push(consumer);
        }
        consumers.sort_by(|left, right| {
            (left.artifact.as_str(), left.claim.as_str()).cmp(&(right.artifact.as_str(), right.claim.as_str()))
        });
        resolved.push(ResolvedProtocolClosedRoleBinding {
            schema: binding.schema.clone(),
            role_id: binding.role_id.clone(),
            locality: ProtocolRoleLocality::ClosedForeign,
            kind: binding.kind,
            schema_identity: binding.schema_identity.clone(),
            source,
            provider,
            consumers,
            correspondence: binding.correspondence,
        });
    }
    resolved.sort_by(|left, right| left.role_id.cmp(&right.role_id));
    Ok(resolved)
}

fn resolve_closed_role_participant(
    reference: &ProtocolPhysicalRoleRef,
    kind: ProtocolClosedRoleKind,
    artifacts: &[ProtocolArtifactIdentity],
    roles: &[ProtocolRoleBinding],
    witnesses: &[ProtocolWitnessClaim],
    role_id: &str,
) -> Result<(ProtocolClosedRoleParticipant, ProtocolClosedRoleSource)> {
    validate_name(&reference.artifact, "closed role participant artifact")?;
    validate_name(&reference.claim, "closed role participant claim")?;
    let artifact = artifacts.iter().find(|artifact| artifact.id == reference.artifact).ok_or_else(|| {
        CompileError::without_span(format!(
            "ProtocolBundle closed role '{role_id}' references unknown artifact '{}'",
            reference.artifact
        ))
    })?;
    let source = match kind {
        ProtocolClosedRoleKind::Cell => {
            let matches =
                roles.iter().filter(|claim| claim.artifact == reference.artifact && claim.name == reference.claim).collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(CompileError::without_span(format!(
                    "ProtocolBundle closed role '{role_id}' requires exactly one cell claim '{}:{}'",
                    reference.artifact, reference.claim
                )));
            }
            ProtocolClosedRoleSource::Cell { location: matches[0].location, index: matches[0].index }
        }
        ProtocolClosedRoleKind::Witness => {
            let matches = witnesses
                .iter()
                .filter(|claim| claim.artifact == reference.artifact && claim.name == reference.claim)
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(CompileError::without_span(format!(
                    "ProtocolBundle closed role '{role_id}' requires exactly one witness claim '{}:{}'",
                    reference.artifact, reference.claim
                )));
            }
            ProtocolClosedRoleSource::Witness { index: matches[0].index, field: matches[0].field }
        }
    };
    Ok((
        ProtocolClosedRoleParticipant {
            artifact: artifact.id.clone(),
            package_coordinate: artifact.package_coordinate.clone(),
            entry: artifact.entry.clone(),
            script_role: artifact.script_role,
            claim: reference.claim.clone(),
            interface_hash: artifact.interface_hash.clone(),
            artifact_hash: artifact.artifact_hash.clone(),
            deployment: artifact.deployment.clone(),
            exact_handle: artifact.exact_handle.clone(),
            exact_handle_hash: artifact.exact_handle_hash.clone(),
        },
        source,
    ))
}

fn canonicalize_bundle(bundle: &mut ResolvedProtocolBundle) {
    bundle.deployment_lines.sort_by(|left, right| left.artifact.cmp(&right.artifact));
    bundle.roles.sort_by(|left, right| {
        (left.location, left.index, left.artifact.as_str(), left.name.as_str()).cmp(&(
            right.location,
            right.index,
            right.artifact.as_str(),
            right.name.as_str(),
        ))
    });
    for role in &mut bundle.closed_roles {
        role.consumers.sort_by(|left, right| {
            (left.artifact.as_str(), left.claim.as_str()).cmp(&(right.artifact.as_str(), right.claim.as_str()))
        });
    }
    bundle.closed_roles.sort_by(|left, right| left.role_id.cmp(&right.role_id));
    bundle.witnesses.sort_by(|left, right| {
        (left.index, left.field, left.artifact.as_str(), left.name.as_str()).cmp(&(
            right.index,
            right.field,
            right.artifact.as_str(),
            right.name.as_str(),
        ))
    });
    bundle.cell_deps.sort_by(|left, right| {
        (left.index, left.artifact.as_str(), left.name.as_str()).cmp(&(right.index, right.artifact.as_str(), right.name.as_str()))
    });
    bundle.header_deps.sort_by(|left, right| {
        (left.index, left.artifact.as_str(), left.name.as_str()).cmp(&(right.index, right.artifact.as_str(), right.name.as_str()))
    });
    bundle.policies.sort_by(|left, right| {
        (left.kind, left.artifact.as_str(), left.policy_hash.as_str()).cmp(&(
            right.kind,
            right.artifact.as_str(),
            right.policy_hash.as_str(),
        ))
    });
}

fn detect_conflicts(bundle: &ResolvedProtocolBundle) -> Result<Vec<ProtocolBundleConflict>> {
    let artifact_ids = bundle.artifacts.iter().map(|artifact| artifact.id.as_str()).collect::<BTreeSet<_>>();
    validate_claim_references(bundle, &artifact_ids)?;
    let mut conflicts = Vec::new();
    detect_artifact_conflicts(bundle, &mut conflicts);
    detect_role_conflicts(bundle, &mut conflicts)?;
    detect_closed_role_conflicts(bundle, &mut conflicts);
    detect_witness_conflicts(bundle, &mut conflicts)?;
    detect_cell_dep_conflicts(bundle, &mut conflicts)?;
    detect_header_dep_conflicts(bundle, &mut conflicts)?;
    detect_policy_conflicts(bundle, &mut conflicts)?;
    conflicts.sort();
    conflicts.dedup();
    Ok(conflicts)
}

fn validate_claim_references(bundle: &ResolvedProtocolBundle, artifact_ids: &BTreeSet<&str>) -> Result<()> {
    let mut names = BTreeSet::new();
    for (kind, artifact, name) in bundle
        .roles
        .iter()
        .map(|claim| ("role", claim.artifact.as_str(), claim.name.as_str()))
        .chain(bundle.witnesses.iter().map(|claim| ("witness", claim.artifact.as_str(), claim.name.as_str())))
        .chain(bundle.cell_deps.iter().map(|claim| ("cell_dep", claim.artifact.as_str(), claim.name.as_str())))
        .chain(bundle.header_deps.iter().map(|claim| ("header_dep", claim.artifact.as_str(), claim.name.as_str())))
    {
        if !artifact_ids.contains(artifact) {
            return Err(CompileError::without_span(format!(
                "ProtocolBundle {kind} claim '{name}' references unknown artifact '{artifact}'"
            )));
        }
        validate_name(name, &format!("{kind} claim name"))?;
        if !names.insert((kind, artifact, name)) {
            return Err(CompileError::without_span(format!("duplicate ProtocolBundle {kind} claim '{artifact}:{name}'")));
        }
    }
    for claim in &bundle.policies {
        if !artifact_ids.contains(claim.artifact.as_str()) {
            return Err(CompileError::without_span(format!(
                "ProtocolBundle policy claim references unknown artifact '{}'",
                claim.artifact
            )));
        }
    }
    Ok(())
}

fn detect_closed_role_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) {
    for binding in &bundle.closed_roles {
        let mut participants = Vec::with_capacity(binding.consumers.len() + 1);
        participants.push((&binding.provider, true));
        participants.extend(binding.consumers.iter().map(|consumer| (consumer, false)));
        let artifacts = participants.iter().map(|(participant, _)| participant.artifact.clone()).collect::<Vec<_>>();

        for (participant, is_provider) in participants {
            let Some(artifact) = bundle.artifacts.iter().find(|artifact| artifact.id == participant.artifact) else {
                continue;
            };
            if !artifact.schema_contracts.contains(&binding.schema_identity) {
                push_conflict(
                    conflicts,
                    "PB213",
                    "closed-role-type",
                    format!("closed_role:{}.schema", binding.role_id),
                    vec![participant.artifact.clone()],
                    format!(
                        "participant metadata does not expose Molecule type '{}' with schema hash '{}'",
                        binding.schema_identity.type_name, binding.schema_identity.schema_hash
                    ),
                );
            }
            if !is_provider && participant.deployment.script == binding.provider.deployment.script {
                push_conflict(
                    conflicts,
                    "PB213",
                    "closed-role-identity",
                    format!("closed_role:{}.participant", binding.role_id),
                    vec![binding.provider.artifact.clone(), participant.artifact.clone()],
                    "closed-foreign participants resolve to the same deployed Script identity",
                );
            }

            match binding.kind {
                ProtocolClosedRoleKind::Cell => {
                    let Some(claim) =
                        bundle.roles.iter().find(|claim| claim.artifact == participant.artifact && claim.name == participant.claim)
                    else {
                        continue;
                    };
                    let source = ProtocolClosedRoleSource::Cell { location: claim.location, index: claim.index };
                    if source != binding.source {
                        push_conflict(
                            conflicts,
                            "PB213",
                            "closed-role-correspondence",
                            format!("closed_role:{}.source", binding.role_id),
                            artifacts.clone(),
                            "provider and consumers do not reference the identical Cell slot",
                        );
                    }
                    let ownership_ok = if is_provider {
                        claim.ownership == ProtocolRoleOwnership::Exclusive
                    } else {
                        claim.ownership == ProtocolRoleOwnership::SharedRead
                    };
                    if !ownership_ok {
                        push_conflict(
                            conflicts,
                            "PB213",
                            "closed-role-ownership",
                            format!("closed_role:{}.ownership", binding.role_id),
                            vec![participant.artifact.clone()],
                            if is_provider {
                                "closed Cell-role provider must hold the exclusive physical claim"
                            } else {
                                "closed Cell-role consumer must hold a shared-read physical claim"
                            },
                        );
                    }
                    if claim.resource_identity.as_deref() != Some(binding.schema_identity.type_name.as_str()) {
                        push_conflict(
                            conflicts,
                            "PB213",
                            "closed-role-type",
                            format!("closed_role:{}.resource", binding.role_id),
                            vec![participant.artifact.clone()],
                            "physical Cell claim resource_identity does not match the closed-role type name",
                        );
                    }
                }
                ProtocolClosedRoleKind::Witness => {
                    let Some(claim) = bundle
                        .witnesses
                        .iter()
                        .find(|claim| claim.artifact == participant.artifact && claim.name == participant.claim)
                    else {
                        continue;
                    };
                    let source = ProtocolClosedRoleSource::Witness { index: claim.index, field: claim.field };
                    if source != binding.source {
                        push_conflict(
                            conflicts,
                            "PB213",
                            "closed-role-correspondence",
                            format!("closed_role:{}.source", binding.role_id),
                            artifacts.clone(),
                            "provider and consumers do not reference the identical WitnessArgs field",
                        );
                    }
                    let ownership_ok = if is_provider {
                        claim.ownership == ProtocolWitnessOwnership::ExclusiveWrite
                    } else {
                        claim.ownership == ProtocolWitnessOwnership::SharedRead
                    };
                    if !ownership_ok {
                        push_conflict(
                            conflicts,
                            "PB213",
                            "closed-role-ownership",
                            format!("closed_role:{}.ownership", binding.role_id),
                            vec![participant.artifact.clone()],
                            if is_provider {
                                "closed witness-role provider must hold the exclusive-write physical claim"
                            } else {
                                "closed witness-role consumer must hold a shared-read physical claim"
                            },
                        );
                    }
                    if claim.abi != binding.schema_identity.type_name {
                        push_conflict(
                            conflicts,
                            "PB213",
                            "closed-role-type",
                            format!("closed_role:{}.abi", binding.role_id),
                            vec![participant.artifact.clone()],
                            "physical witness claim ABI does not match the closed-role type name",
                        );
                    }
                }
            }
        }
    }
}

fn detect_artifact_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) {
    let Some(first) = bundle.artifacts.first() else { return };
    for artifact in &bundle.artifacts {
        if artifact.deployment.network != bundle.network {
            push_conflict(
                conflicts,
                "PB208",
                "network-deployment",
                format!("artifact:{}", artifact.id),
                vec![artifact.id.clone()],
                "artifact deployment network differs from the ProtocolBundle network",
            );
        }
        if artifact.target_profile_hash != first.target_profile_hash {
            push_conflict(
                conflicts,
                "PB209",
                "profile-version",
                "target-profile".to_string(),
                vec![first.id.clone(), artifact.id.clone()],
                "artifacts have incompatible target/VM/ABI profiles",
            );
        }
    }
}

fn detect_role_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) -> Result<()> {
    let mut groups: BTreeMap<(ProtocolCellLocation, u32), Vec<&ProtocolRoleBinding>> = BTreeMap::new();
    for claim in &bundle.roles {
        let cells = match claim.location {
            ProtocolCellLocation::Input => &bundle.transaction.inputs,
            ProtocolCellLocation::Output => &bundle.transaction.outputs,
        };
        let key = format!("{:?}[{}]", claim.location, claim.index).to_ascii_lowercase();
        let Some(cell) = cells.get(claim.index as usize) else {
            push_conflict(
                conflicts,
                "PB211",
                "skeleton-binding",
                key,
                vec![claim.artifact.clone()],
                "role index is outside the transaction skeleton",
            );
            continue;
        };
        if let Some(expected) = &claim.expected_lock {
            validate_script(expected, "role expected_lock")?;
            if expected != &cell.lock {
                push_conflict(
                    conflicts,
                    "PB204",
                    "script-identity",
                    format!("{key}.lock"),
                    vec![claim.artifact.clone()],
                    "role lock identity differs from the transaction skeleton",
                );
            }
        }
        if let Some(expected) = &claim.expected_type {
            validate_script(expected, "role expected_type")?;
            if cell.r#type.as_ref() != Some(expected) {
                push_conflict(
                    conflicts,
                    "PB204",
                    "script-identity",
                    format!("{key}.type"),
                    vec![claim.artifact.clone()],
                    "role type identity differs from the transaction skeleton",
                );
            }
        }
        if let Some(commitment) = &claim.cell_commitment {
            canonical_hash32(commitment, "role cell_commitment")?;
            if commitment != &cell.cell_commitment {
                push_conflict(
                    conflicts,
                    "PB201",
                    "output-placement",
                    key.clone(),
                    vec![claim.artifact.clone()],
                    "role cell commitment differs from the transaction skeleton",
                );
            }
        }
        if let Some(exact) = claim.exact_capacity
            && exact != cell.capacity
        {
            push_conflict(
                conflicts,
                "PB206",
                "capacity",
                key.clone(),
                vec![claim.artifact.clone()],
                format!("role requires exact capacity {exact}, skeleton contains {}", cell.capacity),
            );
        }
        if let Some(minimum) = claim.minimum_capacity
            && cell.capacity < minimum
        {
            push_conflict(
                conflicts,
                "PB206",
                "capacity",
                key.clone(),
                vec![claim.artifact.clone()],
                format!("role requires minimum capacity {minimum}, skeleton contains {}", cell.capacity),
            );
        }
        groups.entry((claim.location, claim.index)).or_default().push(claim);
    }

    for ((location, index), claims) in groups {
        let artifacts = claim_artifacts(claims.iter().map(|claim| claim.artifact.as_str()));
        if claims.iter().filter(|claim| claim.ownership == ProtocolRoleOwnership::Exclusive).count() > 1 {
            push_conflict(
                conflicts,
                "PB200",
                "input-ownership",
                format!("{:?}[{index}]", location).to_ascii_lowercase(),
                artifacts.clone(),
                "an exclusive cell role is also claimed by another artifact",
            );
        }
        detect_distinct_claim_values(
            conflicts,
            "PB204",
            "script-identity",
            format!("{:?}[{index}].lock", location).to_ascii_lowercase(),
            &claims,
            |claim| claim.expected_lock.as_ref(),
        );
        detect_distinct_claim_values(
            conflicts,
            "PB204",
            "script-identity",
            format!("{:?}[{index}].type", location).to_ascii_lowercase(),
            &claims,
            |claim| claim.expected_type.as_ref(),
        );
        detect_distinct_claim_values(
            conflicts,
            "PB205",
            "resource-identity",
            format!("{:?}[{index}].resource", location).to_ascii_lowercase(),
            &claims,
            |claim| claim.resource_identity.as_ref(),
        );
        detect_distinct_claim_values(
            conflicts,
            "PB201",
            "output-placement",
            format!("{:?}[{index}].cell", location).to_ascii_lowercase(),
            &claims,
            |claim| claim.cell_commitment.as_ref(),
        );
    }
    Ok(())
}

fn detect_witness_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) -> Result<()> {
    let mut groups: BTreeMap<(u32, ProtocolWitnessField), Vec<&ProtocolWitnessClaim>> = BTreeMap::new();
    for claim in &bundle.witnesses {
        validate_name(&claim.abi, "witness ABI")?;
        let key = format!("witness[{}].{:?}", claim.index, claim.field).to_ascii_lowercase();
        let Some(witness) = bundle.transaction.witnesses.get(claim.index as usize) else {
            push_conflict(
                conflicts,
                "PB211",
                "skeleton-binding",
                key,
                vec![claim.artifact.clone()],
                "witness index is outside the transaction skeleton",
            );
            continue;
        };
        let actual = match claim.field {
            ProtocolWitnessField::Lock => witness.lock.as_ref(),
            ProtocolWitnessField::InputType => witness.input_type.as_ref(),
            ProtocolWitnessField::OutputType => witness.output_type.as_ref(),
        };
        if let Some(commitment) = &claim.value_commitment {
            canonical_hash32(commitment, "witness value_commitment")?;
            if actual != Some(commitment) {
                push_conflict(
                    conflicts,
                    "PB202",
                    "witness-abi",
                    key.clone(),
                    vec![claim.artifact.clone()],
                    "witness field commitment differs from the transaction skeleton",
                );
            }
        }
        groups.entry((claim.index, claim.field)).or_default().push(claim);
    }
    for ((index, field), claims) in groups {
        let artifacts = claim_artifacts(claims.iter().map(|claim| claim.artifact.as_str()));
        if artifacts.len() > 1 && claims.iter().filter(|claim| claim.ownership == ProtocolWitnessOwnership::ExclusiveWrite).count() > 1
        {
            push_conflict(
                conflicts,
                "PB202",
                "witness-abi",
                format!("witness[{index}].{:?}", field).to_ascii_lowercase(),
                artifacts.clone(),
                "multiple artifacts claim exclusive write ownership of one WitnessArgs field",
            );
        }
        detect_distinct_claim_values(
            conflicts,
            "PB202",
            "witness-abi",
            format!("witness[{index}].{:?}.abi", field).to_ascii_lowercase(),
            &claims,
            |claim| Some(&claim.abi),
        );
        detect_distinct_claim_values(
            conflicts,
            "PB202",
            "witness-abi",
            format!("witness[{index}].{:?}.value", field).to_ascii_lowercase(),
            &claims,
            |claim| claim.value_commitment.as_ref(),
        );
        detect_distinct_claim_values(
            conflicts,
            "PB210",
            "signature-policy",
            format!("witness[{index}].{:?}.signing-domain", field).to_ascii_lowercase(),
            &claims,
            |claim| claim.signing_domain.as_ref(),
        );
    }
    Ok(())
}

fn detect_cell_dep_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) -> Result<()> {
    let mut names: BTreeMap<&str, Vec<&ProtocolCellDepClaim>> = BTreeMap::new();
    for claim in &bundle.cell_deps {
        validate_cell_dep(&claim.cell_dep, "CellDep claim")?;
        let key = format!("cell_deps[{}]", claim.index);
        match bundle.transaction.cell_deps.get(claim.index as usize) {
            Some(actual) if actual == &claim.cell_dep => {}
            Some(_) => push_conflict(
                conflicts,
                "PB203",
                "celldep-ordering",
                key,
                vec![claim.artifact.clone()],
                "CellDep claim differs from the exact dependency at this position",
            ),
            None => push_conflict(
                conflicts,
                "PB211",
                "skeleton-binding",
                key,
                vec![claim.artifact.clone()],
                "CellDep index is outside the transaction skeleton",
            ),
        }
        names.entry(&claim.name).or_default().push(claim);
    }
    for (name, claims) in names {
        let indexes = claims.iter().map(|claim| claim.index).collect::<BTreeSet<_>>();
        if indexes.len() > 1 {
            push_conflict(
                conflicts,
                "PB203",
                "celldep-ordering",
                format!("cell_dep:{name}"),
                claim_artifacts(claims.iter().map(|claim| claim.artifact.as_str())),
                "the same logical CellDep name is assigned to different positions",
            );
        }
    }
    Ok(())
}

fn detect_header_dep_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) -> Result<()> {
    let mut names: BTreeMap<&str, Vec<&ProtocolHeaderDepClaim>> = BTreeMap::new();
    for claim in &bundle.header_deps {
        canonical_hash32(&claim.header_hash, "HeaderDep claim")?;
        let key = format!("header_deps[{}]", claim.index);
        match bundle.transaction.header_deps.get(claim.index as usize) {
            Some(actual) if actual == &claim.header_hash => {}
            Some(_) => push_conflict(
                conflicts,
                "PB203",
                "celldep-ordering",
                key,
                vec![claim.artifact.clone()],
                "HeaderDep claim differs from the exact header at this position",
            ),
            None => push_conflict(
                conflicts,
                "PB211",
                "skeleton-binding",
                key,
                vec![claim.artifact.clone()],
                "HeaderDep index is outside the transaction skeleton",
            ),
        }
        names.entry(&claim.name).or_default().push(claim);
    }
    for (name, claims) in names {
        let indexes = claims.iter().map(|claim| claim.index).collect::<BTreeSet<_>>();
        if indexes.len() > 1 {
            push_conflict(
                conflicts,
                "PB203",
                "celldep-ordering",
                format!("header_dep:{name}"),
                claim_artifacts(claims.iter().map(|claim| claim.artifact.as_str())),
                "the same logical HeaderDep name is assigned to different positions",
            );
        }
    }
    Ok(())
}

fn detect_policy_conflicts(bundle: &ResolvedProtocolBundle, conflicts: &mut Vec<ProtocolBundleConflict>) -> Result<()> {
    let mut groups: BTreeMap<ProtocolPolicyKind, Vec<&ProtocolPolicyClaim>> = BTreeMap::new();
    for claim in &bundle.policies {
        canonical_hash32(&claim.policy_hash, "policy_hash")?;
        let expected = match claim.kind {
            ProtocolPolicyKind::Fee => &bundle.transaction.fee_policy_hash,
            ProtocolPolicyKind::Change => &bundle.transaction.change_policy_hash,
        };
        if &claim.policy_hash != expected {
            push_conflict(
                conflicts,
                "PB207",
                "fee-change",
                format!("{:?}-policy", claim.kind).to_ascii_lowercase(),
                vec![claim.artifact.clone()],
                "artifact policy differs from the transaction skeleton policy",
            );
        }
        groups.entry(claim.kind).or_default().push(claim);
    }
    for (kind, claims) in groups {
        let artifacts = claim_artifacts(claims.iter().map(|claim| claim.artifact.as_str()));
        if artifacts.len() > 1 && claims.iter().filter(|claim| claim.ownership == ProtocolPolicyOwnership::Exclusive).count() > 0 {
            push_conflict(
                conflicts,
                "PB207",
                "fee-change",
                format!("{:?}-policy", kind).to_ascii_lowercase(),
                artifacts.clone(),
                "an exclusive remainder policy is claimed by multiple artifacts",
            );
        }
        detect_distinct_claim_values(
            conflicts,
            "PB207",
            "fee-change",
            format!("{:?}-policy", kind).to_ascii_lowercase(),
            &claims,
            |claim| Some(&claim.policy_hash),
        );
    }
    Ok(())
}

fn detect_distinct_claim_values<'a, T, V, F>(
    conflicts: &mut Vec<ProtocolBundleConflict>,
    code: &str,
    class: &str,
    key: String,
    claims: &[&'a T],
    value: F,
) where
    V: Ord + ?Sized + 'a,
    F: Fn(&'a T) -> Option<&'a V>,
    T: ClaimArtifact,
{
    let values = claims.iter().filter_map(|claim| value(*claim)).collect::<BTreeSet<_>>();
    if values.len() > 1 {
        push_conflict(
            conflicts,
            code,
            class,
            key,
            claim_artifacts(claims.iter().map(|claim| claim.artifact())),
            "artifacts declare incompatible values for the same transaction role",
        );
    }
}

trait ClaimArtifact {
    fn artifact(&self) -> &str;
}

impl ClaimArtifact for ProtocolRoleBinding {
    fn artifact(&self) -> &str {
        &self.artifact
    }
}

impl ClaimArtifact for ProtocolWitnessClaim {
    fn artifact(&self) -> &str {
        &self.artifact
    }
}

impl ClaimArtifact for ProtocolPolicyClaim {
    fn artifact(&self) -> &str {
        &self.artifact
    }
}

fn claim_artifacts<'a>(artifacts: impl Iterator<Item = &'a str>) -> Vec<String> {
    artifacts.map(str::to_string).collect::<BTreeSet<_>>().into_iter().collect()
}

fn push_conflict(
    conflicts: &mut Vec<ProtocolBundleConflict>,
    code: &str,
    class: &str,
    key: String,
    mut artifacts: Vec<String>,
    detail: impl Into<String>,
) {
    artifacts.sort();
    artifacts.dedup();
    conflicts.push(ProtocolBundleConflict { code: code.to_string(), class: class.to_string(), key, artifacts, detail: detail.into() });
}

/// CKB default hash of a canonical JSON value, exposed for bundle fixtures and
/// SDKs that need stable skeleton commitments.
pub fn protocol_json_commitment<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| CompileError::without_span(format!("failed to serialize ProtocolBundle commitment: {error}")))?;
    Ok(format!("0x{}", hex_encode(&ckb_blake2b256(&bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: &str) -> String {
        format!("0x{}", byte.repeat(64))
    }

    fn raw_hash(byte: &str) -> String {
        byte.repeat(64)
    }

    fn script(byte: &str) -> ProtocolScriptIdentity {
        ProtocolScriptIdentity { code_hash: hash(byte), hash_type: "type".to_string(), args: "0x".to_string() }
    }

    fn cell_dep(byte: &str, index: u32) -> ProtocolCellDep {
        ProtocolCellDep { out_point: ProtocolOutPoint { tx_hash: hash(byte), index }, dep_type: ProtocolDepType::Code }
    }

    fn network(chain_id: &str, byte: &str) -> ProtocolNetworkIdentity {
        ProtocolNetworkIdentity { chain_id: chain_id.to_string(), genesis_hash: hash(byte) }
    }

    fn artifact(id: &str, network: ProtocolNetworkIdentity) -> ProtocolArtifactIdentity {
        let deployment_byte = if id == "order" { "a" } else { "b" };
        let package_coordinate = format!("org/{id}@1.0.0");
        let lock_node_id = format!("{id}@1.0.0|path:{id}|env=default|features=default");
        let entry = ProtocolEntryIdentity { kind: ProtocolEntryKind::Action, name: "main".to_string() };
        let deployment = ProtocolDeploymentIdentity {
            network,
            artifact_hash: raw_hash(deployment_byte),
            script: script(deployment_byte),
            code_cell_dep: cell_dep(deployment_byte, 0),
        };
        let interface_hash = raw_hash("f");
        let typed_semantics_hash = raw_hash("c");
        let target_profile_hash = raw_hash("1");
        let runtime_abi_hash = raw_hash("8");
        let verified_bundle_id = raw_hash("2");
        let (exact_handle_receipt, exact_handle) = build_exact_script_handle(ExactScriptHandleReceiptInput {
            package_coordinate: &package_coordinate,
            lock_node_id: &lock_node_id,
            entry: &entry,
            script_role: ProtocolScriptRole::Type,
            interface_hash: &interface_hash,
            typed_semantics_hash: &typed_semantics_hash,
            artifact_hash: &deployment.artifact_hash,
            target_profile_hash: &target_profile_hash,
            runtime_abi_hash: &runtime_abi_hash,
            verified_bundle_id: &verified_bundle_id,
            deployment: &deployment,
        })
        .unwrap();
        let exact_handle_hash = exact_script_handle_value_hash(&exact_handle).unwrap();
        ProtocolArtifactIdentity {
            id: id.to_string(),
            package_coordinate,
            lock_node_id,
            entry,
            script_role: ProtocolScriptRole::Type,
            deployment,
            compiler_version: "0.26.0".to_string(),
            edition: "2026".to_string(),
            metadata_schema_version: 71,
            artifact_hash: raw_hash(deployment_byte),
            metadata_hash: raw_hash("b"),
            typed_semantics_hash,
            lowering_record_hash: raw_hash("d"),
            source_map_hash: raw_hash("e"),
            interface_hash,
            schema_contracts: vec![ProtocolRoleSchemaIdentity { type_name: "SharedRecord".to_string(), schema_hash: raw_hash("7") }],
            target_profile: "ckb".to_string(),
            target_profile_hash,
            runtime_abi_hash,
            exact_handle_receipt,
            exact_handle,
            exact_handle_hash,
            builder_manifest_hash: None,
            verified_bundle_id,
        }
    }

    fn role(artifact: &str, name: &str, location: ProtocolCellLocation, ownership: ProtocolRoleOwnership) -> ProtocolRoleBinding {
        ProtocolRoleBinding {
            artifact: artifact.to_string(),
            name: name.to_string(),
            location,
            index: 0,
            ownership,
            expected_lock: None,
            expected_type: None,
            resource_identity: None,
            cell_commitment: None,
            exact_capacity: None,
            minimum_capacity: None,
        }
    }

    fn bundle() -> ResolvedProtocolBundle {
        let network = network("ckb-testnet", "0");
        ResolvedProtocolBundle {
            schema: PROTOCOL_BUNDLE_SCHEMA.to_string(),
            network: network.clone(),
            artifacts: vec![artifact("order", network.clone()), artifact("token", network)],
            deployment_lines: Vec::new(),
            transaction: ProtocolTransactionSkeleton {
                version: 0,
                inputs: vec![ProtocolCellSlot {
                    cell_commitment: hash("3"),
                    capacity: 1_000,
                    lock: script("4"),
                    r#type: Some(script("5")),
                    out_point: None,
                    since: None,
                    data: None,
                }],
                outputs: vec![ProtocolCellSlot {
                    cell_commitment: hash("6"),
                    capacity: 900,
                    lock: script("4"),
                    r#type: Some(script("5")),
                    out_point: None,
                    since: None,
                    data: None,
                }],
                witnesses: vec![ProtocolWitnessSlot {
                    lock: Some(hash("7")),
                    input_type: None,
                    output_type: None,
                    lock_bytes: None,
                    input_type_bytes: None,
                    output_type_bytes: None,
                }],
                cell_deps: vec![cell_dep("8", 0)],
                header_deps: vec![hash("9")],
                fee_policy_hash: hash("a"),
                change_policy_hash: hash("b"),
                builder_assumption_evidence: BTreeMap::new(),
            },
            roles: Vec::new(),
            closed_roles: Vec::new(),
            witnesses: Vec::new(),
            cell_deps: Vec::new(),
            header_deps: Vec::new(),
            policies: Vec::new(),
        }
    }

    #[test]
    fn conflict_matrix_is_deterministic_and_covers_every_phase_zero_class() {
        let mut bundle = bundle();
        bundle.artifacts[1].deployment.network = network("ckb-mainnet", "f");
        bundle.artifacts[1].target_profile_hash = raw_hash("9");

        let mut input_owner = role("order", "order-input", ProtocolCellLocation::Input, ProtocolRoleOwnership::Exclusive);
        input_owner.resource_identity = Some("order-v1".to_string());
        let mut input_observer = role("token", "token-observer", ProtocolCellLocation::Input, ProtocolRoleOwnership::Exclusive);
        input_observer.resource_identity = Some("token-v1".to_string());
        input_observer.expected_lock = Some(script("c"));
        bundle.roles.extend([input_owner, input_observer]);

        let mut bad_output = role("order", "order-output", ProtocolCellLocation::Output, ProtocolRoleOwnership::Exclusive);
        bad_output.cell_commitment = Some(hash("d"));
        bad_output.minimum_capacity = Some(901);
        bundle.roles.push(bad_output);
        let mut outside = role("token", "missing-output", ProtocolCellLocation::Output, ProtocolRoleOwnership::SharedRead);
        outside.index = 5;
        bundle.roles.push(outside);

        bundle.witnesses.extend([
            ProtocolWitnessClaim {
                artifact: "order".to_string(),
                name: "order-signature".to_string(),
                index: 0,
                field: ProtocolWitnessField::Lock,
                ownership: ProtocolWitnessOwnership::ExclusiveWrite,
                abi: "abi-a".to_string(),
                value_commitment: Some(hash("7")),
                signing_domain: Some("domain-a".to_string()),
            },
            ProtocolWitnessClaim {
                artifact: "token".to_string(),
                name: "token-signature".to_string(),
                index: 0,
                field: ProtocolWitnessField::Lock,
                ownership: ProtocolWitnessOwnership::ExclusiveWrite,
                abi: "abi-b".to_string(),
                value_commitment: Some(hash("e")),
                signing_domain: Some("domain-b".to_string()),
            },
        ]);
        bundle.cell_deps.push(ProtocolCellDepClaim {
            artifact: "order".to_string(),
            name: "code".to_string(),
            index: 0,
            cell_dep: cell_dep("f", 0),
        });
        bundle.header_deps.push(ProtocolHeaderDepClaim {
            artifact: "order".to_string(),
            name: "settlement-header".to_string(),
            index: 0,
            header_hash: hash("e"),
        });
        bundle.policies.extend([
            ProtocolPolicyClaim {
                artifact: "order".to_string(),
                kind: ProtocolPolicyKind::Fee,
                ownership: ProtocolPolicyOwnership::Exclusive,
                policy_hash: hash("c"),
            },
            ProtocolPolicyClaim {
                artifact: "token".to_string(),
                kind: ProtocolPolicyKind::Fee,
                ownership: ProtocolPolicyOwnership::Shared,
                policy_hash: hash("d"),
            },
        ]);

        let first = detect_conflicts(&bundle).unwrap();
        let second = detect_conflicts(&bundle).unwrap();
        assert_eq!(first, second);
        let codes = first.iter().map(|conflict| conflict.code.as_str()).collect::<BTreeSet<_>>();
        assert_eq!(
            codes,
            BTreeSet::from([
                "PB200", "PB201", "PB202", "PB203", "PB204", "PB205", "PB206", "PB207", "PB208", "PB209", "PB210", "PB211"
            ])
        );
    }

    #[test]
    fn compatible_shared_observation_has_a_stable_canonical_hash() {
        let mut left = bundle();
        left.roles.extend([
            role("token", "observe", ProtocolCellLocation::Input, ProtocolRoleOwnership::SharedRead),
            role("order", "own", ProtocolCellLocation::Input, ProtocolRoleOwnership::SharedRead),
        ]);
        let mut right = left.clone();
        right.roles.reverse();
        canonicalize_bundle(&mut left);
        canonicalize_bundle(&mut right);
        assert_eq!(left, right);
        assert!(detect_conflicts(&left).unwrap().is_empty());
        assert_eq!(
            canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &left).unwrap(),
            canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &right).unwrap()
        );
    }

    #[test]
    fn closed_cell_role_binds_type_interface_artifact_and_deployment_identity() {
        let mut bundle = bundle();
        let mut provider = role("order", "shared-output", ProtocolCellLocation::Output, ProtocolRoleOwnership::Exclusive);
        provider.resource_identity = Some("SharedRecord".to_string());
        let mut consumer = role("token", "shared-output", ProtocolCellLocation::Output, ProtocolRoleOwnership::SharedRead);
        consumer.resource_identity = Some("SharedRecord".to_string());
        bundle.roles.extend([provider, consumer]);

        let declared = ProtocolClosedRoleBinding {
            schema: PROTOCOL_CLOSED_ROLE_SCHEMA.to_string(),
            role_id: "settlement-record".to_string(),
            kind: ProtocolClosedRoleKind::Cell,
            schema_identity: ProtocolRoleSchemaIdentity { type_name: "SharedRecord".to_string(), schema_hash: raw_hash("7") },
            provider: ProtocolPhysicalRoleRef { artifact: "order".to_string(), claim: "shared-output".to_string() },
            consumers: vec![ProtocolPhysicalRoleRef { artifact: "token".to_string(), claim: "shared-output".to_string() }],
            correspondence: ProtocolRoleCorrespondence::ExactPhysicalBinding,
        };
        bundle.closed_roles = resolve_closed_roles(&[declared], &bundle.artifacts, &bundle.roles, &bundle.witnesses).unwrap();

        assert!(detect_conflicts(&bundle).unwrap().is_empty());
        let resolved = &bundle.closed_roles[0];
        assert_eq!(resolved.locality, ProtocolRoleLocality::ClosedForeign);
        assert_eq!(resolved.source, ProtocolClosedRoleSource::Cell { location: ProtocolCellLocation::Output, index: 0 });
        assert_eq!(resolved.provider.interface_hash, bundle.artifacts[0].interface_hash);
        assert_eq!(resolved.provider.artifact_hash, bundle.artifacts[0].artifact_hash);
        assert_eq!(resolved.provider.deployment, bundle.artifacts[0].deployment);
        assert_eq!(resolved.consumers[0].deployment, bundle.artifacts[1].deployment);

        let original_hash = canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &bundle).unwrap();
        bundle.closed_roles[0].schema_identity.schema_hash = raw_hash("8");
        assert_ne!(original_hash, canonical_hash(PROTOCOL_BUNDLE_HASH_DOMAIN, &bundle).unwrap());
        assert!(detect_conflicts(&bundle).unwrap().iter().any(|conflict| conflict.code == "PB213"));
    }

    #[test]
    fn closed_witness_role_requires_one_writer_and_identical_typed_field() {
        let mut bundle = bundle();
        bundle.witnesses.extend([
            ProtocolWitnessClaim {
                artifact: "order".to_string(),
                name: "shared-envelope".to_string(),
                index: 0,
                field: ProtocolWitnessField::InputType,
                ownership: ProtocolWitnessOwnership::ExclusiveWrite,
                abi: "SharedRecord".to_string(),
                value_commitment: None,
                signing_domain: None,
            },
            ProtocolWitnessClaim {
                artifact: "token".to_string(),
                name: "shared-envelope".to_string(),
                index: 0,
                field: ProtocolWitnessField::InputType,
                ownership: ProtocolWitnessOwnership::SharedRead,
                abi: "SharedRecord".to_string(),
                value_commitment: None,
                signing_domain: None,
            },
        ]);
        let declared = ProtocolClosedRoleBinding {
            schema: PROTOCOL_CLOSED_ROLE_SCHEMA.to_string(),
            role_id: "settlement-envelope".to_string(),
            kind: ProtocolClosedRoleKind::Witness,
            schema_identity: ProtocolRoleSchemaIdentity { type_name: "SharedRecord".to_string(), schema_hash: raw_hash("7") },
            provider: ProtocolPhysicalRoleRef { artifact: "order".to_string(), claim: "shared-envelope".to_string() },
            consumers: vec![ProtocolPhysicalRoleRef { artifact: "token".to_string(), claim: "shared-envelope".to_string() }],
            correspondence: ProtocolRoleCorrespondence::ExactPhysicalBinding,
        };
        bundle.closed_roles = resolve_closed_roles(&[declared], &bundle.artifacts, &bundle.roles, &bundle.witnesses).unwrap();

        assert!(detect_conflicts(&bundle).unwrap().is_empty());
        assert_eq!(
            bundle.closed_roles[0].source,
            ProtocolClosedRoleSource::Witness { index: 0, field: ProtocolWitnessField::InputType }
        );

        bundle.witnesses[1].field = ProtocolWitnessField::OutputType;
        let conflicts = detect_conflicts(&bundle).unwrap();
        assert!(conflicts.iter().any(|conflict| conflict.class == "closed-role-correspondence"));
    }

    #[test]
    fn closed_role_rejects_unknown_or_repeated_participants_before_hashing() {
        let mut bundle = bundle();
        let declared = ProtocolClosedRoleBinding {
            schema: PROTOCOL_CLOSED_ROLE_SCHEMA.to_string(),
            role_id: "bad-role".to_string(),
            kind: ProtocolClosedRoleKind::Cell,
            schema_identity: ProtocolRoleSchemaIdentity { type_name: "SharedRecord".to_string(), schema_hash: raw_hash("7") },
            provider: ProtocolPhysicalRoleRef { artifact: "missing".to_string(), claim: "shared".to_string() },
            consumers: vec![ProtocolPhysicalRoleRef { artifact: "token".to_string(), claim: "shared".to_string() }],
            correspondence: ProtocolRoleCorrespondence::ExactPhysicalBinding,
        };
        let error = resolve_closed_roles(&[declared], &bundle.artifacts, &bundle.roles, &bundle.witnesses).unwrap_err();
        assert!(error.to_string().contains("unknown artifact 'missing'"), "{error}");

        bundle.roles.extend([
            role("order", "shared", ProtocolCellLocation::Output, ProtocolRoleOwnership::Exclusive),
            role("token", "shared", ProtocolCellLocation::Output, ProtocolRoleOwnership::SharedRead),
        ]);
        let repeated = ProtocolClosedRoleBinding {
            schema: PROTOCOL_CLOSED_ROLE_SCHEMA.to_string(),
            role_id: "bad-role".to_string(),
            kind: ProtocolClosedRoleKind::Cell,
            schema_identity: ProtocolRoleSchemaIdentity { type_name: "SharedRecord".to_string(), schema_hash: raw_hash("7") },
            provider: ProtocolPhysicalRoleRef { artifact: "order".to_string(), claim: "shared".to_string() },
            consumers: vec![
                ProtocolPhysicalRoleRef { artifact: "token".to_string(), claim: "shared".to_string() },
                ProtocolPhysicalRoleRef { artifact: "token".to_string(), claim: "second".to_string() },
            ],
            correspondence: ProtocolRoleCorrespondence::ExactPhysicalBinding,
        };
        let error = resolve_closed_roles(&[repeated], &bundle.artifacts, &bundle.roles, &bundle.witnesses).unwrap_err();
        assert!(error.to_string().contains("repeats participant artifact 'token'"), "{error}");
    }

    #[test]
    fn unknown_artifact_claims_fail_closed_before_composition() {
        let mut bundle = bundle();
        bundle.roles.push(role("missing", "input", ProtocolCellLocation::Input, ProtocolRoleOwnership::SharedRead));
        let error = detect_conflicts(&bundle).unwrap_err();
        assert!(error.to_string().contains("unknown artifact 'missing'"), "{error}");
    }

    #[test]
    fn protocol_json_commitments_are_domain_stable_and_canonical() {
        let value = BTreeMap::from([("a", 1_u64), ("b", 2_u64)]);
        assert_eq!(protocol_json_commitment(&value).unwrap(), protocol_json_commitment(&value).unwrap());
        assert!(protocol_json_commitment(&value).unwrap().starts_with("0x"));
        assert_eq!(protocol_json_commitment(&value).unwrap().len(), 66);
    }

    #[test]
    fn concrete_witness_bytes_must_match_their_ckb_commitment() {
        let mut transaction = bundle().transaction;
        transaction.witnesses[0].lock = Some(format!("0x{}", hex_encode(&ckb_blake2b256(&[1, 2]))));
        transaction.witnesses[0].lock_bytes = Some("0x0102".to_string());
        validate_transaction(&transaction).unwrap();

        transaction.witnesses[0].lock_bytes = Some("0x03".to_string());
        let error = validate_transaction(&transaction).unwrap_err();
        assert!(error.to_string().contains("does not match its CKB Blake2b-256 commitment"), "{error}");
    }
}
