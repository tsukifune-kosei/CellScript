//! Versioned deployment-line receipts and fixed-width handle values.
//!
//! This module establishes the off-chain admission contract for Type-hash
//! upgrades. A Type ID or Type-hash Script is never treated as compatibility
//! evidence by itself: every selected version retains an exact checked handle,
//! a derived six-dimensional interface report, and a hash-linked predecessor.

use crate::error::{CompileError, Result};
use crate::interface::{self, InterfaceCompatibilityReport, PackageInterface, COMPATIBILITY_SCHEMA};
use crate::protocol_bundle::{ProtocolEntryIdentity, ProtocolNetworkIdentity, ProtocolScriptIdentity, ProtocolScriptRole};
use crate::script_handle::{
    exact_script_handle_value_from_receipt, exact_script_handle_value_hash, ExactCodeIdentityPolicy, ExactHandleClass,
    ExactScriptHandleReceipt,
};
use crate::script_handle_contract::{
    DEPLOYMENT_LINE_HANDLE_ADMISSION_TYPE_HASH_OFFSET, DEPLOYMENT_LINE_HANDLE_CLASS_OFFSET,
    DEPLOYMENT_LINE_HANDLE_EXACT_HANDLE_OFFSET, DEPLOYMENT_LINE_HANDLE_LINE_ID_OFFSET, DEPLOYMENT_LINE_HANDLE_MAGIC,
    DEPLOYMENT_LINE_HANDLE_POLICY_HASH_OFFSET, DEPLOYMENT_LINE_HANDLE_PREVIOUS_RECEIPT_HASH_OFFSET,
    DEPLOYMENT_LINE_HANDLE_RECEIPT_HASH_OFFSET, DEPLOYMENT_LINE_HANDLE_RESERVED_BYTES, DEPLOYMENT_LINE_HANDLE_RESERVED_OFFSET,
    DEPLOYMENT_LINE_HANDLE_ROLE_OFFSET, DEPLOYMENT_LINE_HANDLE_SEQUENCE_OFFSET, DEPLOYMENT_LINE_HANDLE_STATUS_ACTIVE,
    DEPLOYMENT_LINE_HANDLE_STATUS_OFFSET, DEPLOYMENT_LINE_HANDLE_STATUS_YANKED, EXACT_SCRIPT_HANDLE_CLASS_SCRIPT,
    EXACT_SCRIPT_HANDLE_CLASS_VERIFIER, EXACT_SCRIPT_HANDLE_ROLE_LOCK, EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER,
    EXACT_SCRIPT_HANDLE_ROLE_TYPE,
};
pub use crate::script_handle_contract::{DEPLOYMENT_LINE_HANDLE_BYTES, DEPLOYMENT_LINE_HANDLE_ENCODING};
use crate::{ckb_blake2b256, hex_encode};
use cellscript_artifact_checker::canonical_hash;
use serde::{Deserialize, Serialize};

pub const DEPLOYMENT_LINE_RECEIPT_SCHEMA: &str = "cellscript-deployment-line-receipt-v1";
pub const DEPLOYMENT_LINE_VALUE_SCHEMA: &str = "cellscript-deployment-line-handle-value-v1";
pub const DEPLOYMENT_LINE_POLICY_SCHEMA: &str = "cellscript-deployment-line-policy-v1";
pub const DEPLOYMENT_LINE_RECEIPT_HASH_DOMAIN: &str = "cellscript-deployment-line-receipt-v1";
pub const DEPLOYMENT_LINE_ID_HASH_DOMAIN: &str = "cellscript-deployment-line-id-v1";
pub const DEPLOYMENT_LINE_POLICY_HASH_DOMAIN: &str = "cellscript-deployment-line-policy-v1";
pub const DEPLOYMENT_LINE_COMMITMENT_MAGIC: &[u8; 7] = b"CSREGv1";

const COMPATIBILITY_DIMENSIONS: [&str; 6] =
    ["source_api", "serialized_layout", "runtime_abi", "effects_capabilities", "builder", "deployment"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentLineStatus {
    Active,
    Yanked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentLinePolicy {
    pub schema: String,
    pub version: u32,
    pub compatibility_report_schema: String,
    pub required_dimensions: Vec<String>,
    pub upgrade_authorization: String,
    pub admission_commitment: String,
    pub stale_version_policy: String,
    pub yank_policy: String,
    pub require_type_hash_code_identity: bool,
    pub require_exact_version_receipt: bool,
    pub require_same_script_identity: bool,
    pub require_same_target_profile: bool,
    pub require_same_runtime_abi: bool,
}

impl Default for DeploymentLinePolicy {
    fn default() -> Self {
        Self {
            schema: DEPLOYMENT_LINE_POLICY_SCHEMA.to_string(),
            version: 1,
            compatibility_report_schema: COMPATIBILITY_SCHEMA.to_string(),
            required_dimensions: COMPATIBILITY_DIMENSIONS.iter().map(|dimension| (*dimension).to_string()).collect(),
            upgrade_authorization: "separate-unique-admission-cell-replacement-v1".to_string(),
            admission_commitment: "CSREGv1-plus-ckb-blake2b256-full-line-handle".to_string(),
            stale_version_policy: "only-current-live-admission-cell-is-acceptable".to_string(),
            yank_policy: "active-only-runtime-selection".to_string(),
            require_type_hash_code_identity: true,
            require_exact_version_receipt: true,
            require_same_script_identity: true,
            require_same_target_profile: true,
            require_same_runtime_abi: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentLineReceipt {
    pub schema: String,
    pub version: u32,
    pub line_id: String,
    pub package_line: String,
    pub sequence: u64,
    pub status: DeploymentLineStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_receipt_hash: Option<String>,
    pub class: ExactHandleClass,
    pub script_role: ProtocolScriptRole,
    pub entry: ProtocolEntryIdentity,
    pub network: ProtocolNetworkIdentity,
    pub stable_script: ProtocolScriptIdentity,
    pub baseline_interface_hash: String,
    pub previous_interface_hash: String,
    pub current_interface_hash: String,
    pub predecessor_compatibility: InterfaceCompatibilityReport,
    pub baseline_compatibility: InterfaceCompatibilityReport,
    pub policy: DeploymentLinePolicy,
    pub policy_hash: String,
    pub admission_cell_type_hash: String,
    pub current_exact_receipt: ExactScriptHandleReceipt,
    pub current_exact_handle_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentLineHandleValue {
    pub schema: String,
    pub version: u32,
    pub encoding: String,
    pub encoded: String,
}

pub fn begin_deployment_line(
    current_exact_receipt: &ExactScriptHandleReceipt,
    current_interface: &PackageInterface,
    admission_cell_type_hash: &str,
) -> Result<(DeploymentLineReceipt, DeploymentLineHandleValue)> {
    validate_interface_matches_exact(current_interface, current_exact_receipt, "initial")?;
    validate_type_hash_exact_receipt(current_exact_receipt)?;
    let package_line = package_line(&current_exact_receipt.package_coordinate)?;
    let policy = DeploymentLinePolicy::default();
    let policy_hash = deployment_line_policy_hash(&policy)?;
    let admission_cell_type_hash = prefixed_hash32(admission_cell_type_hash, "admission Cell Type Script hash")?;
    let baseline_interface_hash = interface::hash(current_interface);
    let compatibility = interface::compare(current_interface, current_interface);
    let line_id =
        deployment_line_id(&package_line, current_exact_receipt, &baseline_interface_hash, &policy_hash, &admission_cell_type_hash)?;
    let current_exact_handle = exact_script_handle_value_from_receipt(current_exact_receipt)?;
    let current_exact_handle_hash = exact_script_handle_value_hash(&current_exact_handle)?;
    let receipt = DeploymentLineReceipt {
        schema: DEPLOYMENT_LINE_RECEIPT_SCHEMA.to_string(),
        version: 1,
        line_id,
        package_line,
        sequence: 0,
        status: DeploymentLineStatus::Active,
        previous_receipt_hash: None,
        class: current_exact_receipt.class,
        script_role: current_exact_receipt.script_role,
        entry: current_exact_receipt.entry.clone(),
        network: current_exact_receipt.deployment.network.clone(),
        stable_script: current_exact_receipt.deployment.script.clone(),
        baseline_interface_hash: baseline_interface_hash.clone(),
        previous_interface_hash: baseline_interface_hash.clone(),
        current_interface_hash: baseline_interface_hash,
        predecessor_compatibility: compatibility.clone(),
        baseline_compatibility: compatibility,
        policy,
        policy_hash,
        admission_cell_type_hash: format!("0x{}", hex_encode(&admission_cell_type_hash)),
        current_exact_receipt: current_exact_receipt.clone(),
        current_exact_handle_hash,
    };
    let value = encode_deployment_line_handle(&receipt)?;
    Ok((receipt, value))
}

pub fn advance_deployment_line(
    previous: &DeploymentLineReceipt,
    baseline_interface: &PackageInterface,
    previous_interface: &PackageInterface,
    current_exact_receipt: &ExactScriptHandleReceipt,
    current_interface: &PackageInterface,
) -> Result<(DeploymentLineReceipt, DeploymentLineHandleValue)> {
    validate_deployment_line_receipt(previous)?;
    if previous.status != DeploymentLineStatus::Active {
        return Err(CompileError::without_span("a yanked deployment-line receipt cannot authorize a later upgrade"));
    }
    validate_interface_hash(baseline_interface, &previous.baseline_interface_hash, "baseline")?;
    validate_interface_hash(previous_interface, &previous.current_interface_hash, "predecessor")?;
    validate_interface_matches_exact(current_interface, current_exact_receipt, "candidate")?;
    validate_type_hash_exact_receipt(current_exact_receipt)?;
    validate_stable_line_identity(previous, current_exact_receipt)?;
    require_monotonic_line_version(&previous.current_exact_receipt.package_coordinate, &current_exact_receipt.package_coordinate)?;

    let predecessor_compatibility = interface::compare(previous_interface, current_interface);
    let baseline_compatibility = interface::compare(baseline_interface, current_interface);
    require_compatible_report(&predecessor_compatibility, "predecessor")?;
    require_compatible_report(&baseline_compatibility, "baseline")?;
    let current_exact_handle = exact_script_handle_value_from_receipt(current_exact_receipt)?;
    let current_exact_handle_hash = exact_script_handle_value_hash(&current_exact_handle)?;
    let receipt = DeploymentLineReceipt {
        schema: DEPLOYMENT_LINE_RECEIPT_SCHEMA.to_string(),
        version: 1,
        line_id: previous.line_id.clone(),
        package_line: previous.package_line.clone(),
        sequence: previous.sequence.checked_add(1).ok_or_else(|| CompileError::without_span("deployment-line sequence overflow"))?,
        status: DeploymentLineStatus::Active,
        previous_receipt_hash: Some(deployment_line_receipt_hash(previous)?),
        class: previous.class,
        script_role: previous.script_role,
        entry: previous.entry.clone(),
        network: previous.network.clone(),
        stable_script: previous.stable_script.clone(),
        baseline_interface_hash: previous.baseline_interface_hash.clone(),
        previous_interface_hash: previous.current_interface_hash.clone(),
        current_interface_hash: interface::hash(current_interface),
        predecessor_compatibility,
        baseline_compatibility,
        policy: previous.policy.clone(),
        policy_hash: previous.policy_hash.clone(),
        admission_cell_type_hash: previous.admission_cell_type_hash.clone(),
        current_exact_receipt: current_exact_receipt.clone(),
        current_exact_handle_hash,
    };
    validate_deployment_line_successor(previous, &receipt)?;
    let value = encode_deployment_line_handle(&receipt)?;
    Ok((receipt, value))
}

pub fn yank_deployment_line(
    previous: &DeploymentLineReceipt,
    current_interface: &PackageInterface,
) -> Result<(DeploymentLineReceipt, DeploymentLineHandleValue)> {
    validate_deployment_line_receipt(previous)?;
    if previous.status != DeploymentLineStatus::Active {
        return Err(CompileError::without_span("deployment line is already yanked"));
    }
    validate_interface_hash(current_interface, &previous.current_interface_hash, "current")?;
    let mut receipt = previous.clone();
    receipt.sequence =
        receipt.sequence.checked_add(1).ok_or_else(|| CompileError::without_span("deployment-line sequence overflow"))?;
    receipt.status = DeploymentLineStatus::Yanked;
    receipt.previous_receipt_hash = Some(deployment_line_receipt_hash(previous)?);
    receipt.previous_interface_hash = previous.current_interface_hash.clone();
    receipt.predecessor_compatibility = interface::compare(current_interface, current_interface);
    validate_deployment_line_successor(previous, &receipt)?;
    let value = encode_deployment_line_handle(&receipt)?;
    Ok((receipt, value))
}

pub fn validate_deployment_line_receipt(receipt: &DeploymentLineReceipt) -> Result<()> {
    if receipt.schema != DEPLOYMENT_LINE_RECEIPT_SCHEMA || receipt.version != 1 {
        return Err(CompileError::without_span("unsupported deployment-line receipt schema/version"));
    }
    validate_type_hash_exact_receipt(&receipt.current_exact_receipt)?;
    if receipt.class != receipt.current_exact_receipt.class
        || receipt.script_role != receipt.current_exact_receipt.script_role
        || receipt.entry != receipt.current_exact_receipt.entry
        || receipt.network != receipt.current_exact_receipt.deployment.network
        || receipt.stable_script != receipt.current_exact_receipt.deployment.script
    {
        return Err(CompileError::without_span("deployment-line receipt stable identity disagrees with its exact version receipt"));
    }
    if receipt.package_line != package_line(&receipt.current_exact_receipt.package_coordinate)? {
        return Err(CompileError::without_span("deployment-line package compatibility line does not match the current exact receipt"));
    }
    validate_policy(&receipt.policy)?;
    if receipt.policy_hash != deployment_line_policy_hash(&receipt.policy)? {
        return Err(CompileError::without_span("deployment-line policy hash does not match the canonical policy"));
    }
    let admission_hash = prefixed_hash32(&receipt.admission_cell_type_hash, "admission Cell Type Script hash")?;
    let expected_line_id = deployment_line_id(
        &receipt.package_line,
        &receipt.current_exact_receipt,
        &receipt.baseline_interface_hash,
        &receipt.policy_hash,
        &admission_hash,
    )?;
    if receipt.line_id != expected_line_id {
        return Err(CompileError::without_span("deployment-line id does not match its immutable line identity"));
    }
    for (label, value) in [
        ("line_id", receipt.line_id.as_str()),
        ("baseline_interface_hash", receipt.baseline_interface_hash.as_str()),
        ("previous_interface_hash", receipt.previous_interface_hash.as_str()),
        ("current_interface_hash", receipt.current_interface_hash.as_str()),
        ("policy_hash", receipt.policy_hash.as_str()),
        ("current_exact_handle_hash", receipt.current_exact_handle_hash.as_str()),
    ] {
        raw_hash32(value, label)?;
    }
    if receipt.sequence == 0 {
        if receipt.previous_receipt_hash.is_some() || receipt.status != DeploymentLineStatus::Active {
            return Err(CompileError::without_span("initial deployment-line receipt must be active and have no predecessor"));
        }
    } else {
        raw_hash32(
            receipt
                .previous_receipt_hash
                .as_deref()
                .ok_or_else(|| CompileError::without_span("non-initial deployment-line receipt must retain its predecessor hash"))?,
            "previous_receipt_hash",
        )?;
    }
    validate_compatibility_report(
        &receipt.predecessor_compatibility,
        &receipt.previous_interface_hash,
        &receipt.current_interface_hash,
        "predecessor",
    )?;
    validate_compatibility_report(
        &receipt.baseline_compatibility,
        &receipt.baseline_interface_hash,
        &receipt.current_interface_hash,
        "baseline",
    )?;
    let exact_value = exact_script_handle_value_from_receipt(&receipt.current_exact_receipt)?;
    if receipt.current_exact_handle_hash != exact_script_handle_value_hash(&exact_value)? {
        return Err(CompileError::without_span("deployment-line receipt exact handle hash does not match its exact receipt"));
    }
    Ok(())
}

pub fn validate_deployment_line_successor(previous: &DeploymentLineReceipt, current: &DeploymentLineReceipt) -> Result<()> {
    validate_deployment_line_receipt(previous)?;
    validate_deployment_line_receipt(current)?;
    if current.line_id != previous.line_id
        || current.package_line != previous.package_line
        || current.class != previous.class
        || current.script_role != previous.script_role
        || current.entry != previous.entry
        || current.network != previous.network
        || current.stable_script != previous.stable_script
        || current.baseline_interface_hash != previous.baseline_interface_hash
        || current.policy_hash != previous.policy_hash
        || current.admission_cell_type_hash != previous.admission_cell_type_hash
    {
        return Err(CompileError::without_span("deployment-line successor changed an immutable line identity"));
    }
    let next_sequence = previous
        .sequence
        .checked_add(1)
        .ok_or_else(|| CompileError::without_span("deployment-line predecessor sequence cannot be extended"))?;
    if current.sequence != next_sequence
        || current.previous_receipt_hash.as_deref() != Some(deployment_line_receipt_hash(previous)?.as_str())
        || current.previous_interface_hash != previous.current_interface_hash
    {
        return Err(CompileError::without_span("deployment-line successor does not extend the exact predecessor"));
    }
    match current.status {
        DeploymentLineStatus::Active => {
            if previous.status != DeploymentLineStatus::Active {
                return Err(CompileError::without_span(
                    "a yanked deployment line cannot return to active without a new policy version",
                ));
            }
            require_monotonic_line_version(
                &previous.current_exact_receipt.package_coordinate,
                &current.current_exact_receipt.package_coordinate,
            )?;
        }
        DeploymentLineStatus::Yanked => {
            if previous.status != DeploymentLineStatus::Active
                || current.current_exact_receipt != previous.current_exact_receipt
                || current.current_interface_hash != previous.current_interface_hash
            {
                return Err(CompileError::without_span(
                    "yanking may only replace the current active receipt without changing its version",
                ));
            }
        }
    }
    Ok(())
}

pub fn deployment_line_receipt_hash(receipt: &DeploymentLineReceipt) -> Result<String> {
    validate_deployment_line_receipt(receipt)?;
    canonical_hash(DEPLOYMENT_LINE_RECEIPT_HASH_DOMAIN, receipt)
        .map_err(|error| CompileError::without_span(format!("failed to hash deployment-line receipt: {error}")))
}

pub fn deployment_line_policy_hash(policy: &DeploymentLinePolicy) -> Result<String> {
    validate_policy(policy)?;
    canonical_hash(DEPLOYMENT_LINE_POLICY_HASH_DOMAIN, policy)
        .map_err(|error| CompileError::without_span(format!("failed to hash deployment-line policy: {error}")))
}

pub fn deployment_line_handle_value_hash(value: &DeploymentLineHandleValue) -> Result<String> {
    if value.schema != DEPLOYMENT_LINE_VALUE_SCHEMA || value.version != 1 || value.encoding != DEPLOYMENT_LINE_HANDLE_ENCODING {
        return Err(CompileError::without_span("unsupported deployment-line handle value schema/version/encoding"));
    }
    let bytes = canonical_hex_bytes(&value.encoded, "deployment-line handle value")?;
    if bytes.len() != DEPLOYMENT_LINE_HANDLE_BYTES {
        return Err(CompileError::without_span(format!(
            "deployment-line handle value must contain exactly {DEPLOYMENT_LINE_HANDLE_BYTES} bytes"
        )));
    }
    Ok(hex_encode(&ckb_blake2b256(&bytes)))
}

pub fn deployment_line_commitment_data(value: &DeploymentLineHandleValue) -> Result<String> {
    let hash = raw_hash32(&deployment_line_handle_value_hash(value)?, "deployment-line handle hash")?;
    let mut bytes = Vec::with_capacity(DEPLOYMENT_LINE_COMMITMENT_MAGIC.len() + hash.len());
    bytes.extend_from_slice(DEPLOYMENT_LINE_COMMITMENT_MAGIC);
    bytes.extend_from_slice(&hash);
    Ok(format!("0x{}", hex_encode(&bytes)))
}

pub fn validate_deployment_line_handle(receipt: &DeploymentLineReceipt, value: &DeploymentLineHandleValue) -> Result<()> {
    let expected = encode_deployment_line_handle(receipt)?;
    if value != &expected {
        return Err(CompileError::without_span("deployment-line handle value does not match its receipt and exact version"));
    }
    Ok(())
}

fn encode_deployment_line_handle(receipt: &DeploymentLineReceipt) -> Result<DeploymentLineHandleValue> {
    validate_deployment_line_receipt(receipt)?;
    let receipt_hash = raw_hash32(&deployment_line_receipt_hash_unchecked(receipt)?, "deployment-line receipt hash")?;
    let line_id = raw_hash32(&receipt.line_id, "line_id")?;
    let policy_hash = raw_hash32(&receipt.policy_hash, "policy_hash")?;
    let previous_receipt_hash = match receipt.previous_receipt_hash.as_deref() {
        Some(hash) => raw_hash32(hash, "previous_receipt_hash")?,
        None => [0u8; 32],
    };
    let admission_type_hash = prefixed_hash32(&receipt.admission_cell_type_hash, "admission Cell Type Script hash")?;
    let exact_value = exact_script_handle_value_from_receipt(&receipt.current_exact_receipt)?;
    let exact_bytes = canonical_hex_bytes(&exact_value.encoded, "exact Script handle value")?;
    let mut bytes = vec![0u8; DEPLOYMENT_LINE_HANDLE_BYTES];
    bytes[..DEPLOYMENT_LINE_HANDLE_MAGIC.len()].copy_from_slice(DEPLOYMENT_LINE_HANDLE_MAGIC);
    bytes[DEPLOYMENT_LINE_HANDLE_CLASS_OFFSET] = match receipt.class {
        ExactHandleClass::Script => EXACT_SCRIPT_HANDLE_CLASS_SCRIPT,
        ExactHandleClass::Verifier => EXACT_SCRIPT_HANDLE_CLASS_VERIFIER,
    };
    bytes[DEPLOYMENT_LINE_HANDLE_ROLE_OFFSET] = role_tag(receipt.script_role);
    bytes[DEPLOYMENT_LINE_HANDLE_STATUS_OFFSET] = match receipt.status {
        DeploymentLineStatus::Active => DEPLOYMENT_LINE_HANDLE_STATUS_ACTIVE,
        DeploymentLineStatus::Yanked => DEPLOYMENT_LINE_HANDLE_STATUS_YANKED,
    };
    bytes[DEPLOYMENT_LINE_HANDLE_RESERVED_OFFSET..DEPLOYMENT_LINE_HANDLE_RESERVED_OFFSET + DEPLOYMENT_LINE_HANDLE_RESERVED_BYTES]
        .fill(0);
    bytes[DEPLOYMENT_LINE_HANDLE_SEQUENCE_OFFSET..DEPLOYMENT_LINE_HANDLE_SEQUENCE_OFFSET + 8]
        .copy_from_slice(&receipt.sequence.to_le_bytes());
    for (offset, hash) in [
        (DEPLOYMENT_LINE_HANDLE_LINE_ID_OFFSET, line_id),
        (DEPLOYMENT_LINE_HANDLE_POLICY_HASH_OFFSET, policy_hash),
        (DEPLOYMENT_LINE_HANDLE_RECEIPT_HASH_OFFSET, receipt_hash),
        (DEPLOYMENT_LINE_HANDLE_PREVIOUS_RECEIPT_HASH_OFFSET, previous_receipt_hash),
        (DEPLOYMENT_LINE_HANDLE_ADMISSION_TYPE_HASH_OFFSET, admission_type_hash),
    ] {
        bytes[offset..offset + hash.len()].copy_from_slice(&hash);
    }
    if exact_bytes.len() != crate::script_handle_contract::EXACT_SCRIPT_HANDLE_BYTES {
        return Err(CompileError::without_span("deployment-line exact version has invalid fixed handle width"));
    }
    bytes[DEPLOYMENT_LINE_HANDLE_EXACT_HANDLE_OFFSET..].copy_from_slice(&exact_bytes);
    Ok(DeploymentLineHandleValue {
        schema: DEPLOYMENT_LINE_VALUE_SCHEMA.to_string(),
        version: 1,
        encoding: DEPLOYMENT_LINE_HANDLE_ENCODING.to_string(),
        encoded: format!("0x{}", hex_encode(&bytes)),
    })
}

fn validate_stable_line_identity(previous: &DeploymentLineReceipt, current: &ExactScriptHandleReceipt) -> Result<()> {
    if previous.class != current.class
        || previous.script_role != current.script_role
        || previous.entry != current.entry
        || previous.network != current.deployment.network
        || previous.stable_script != current.deployment.script
        || previous.package_line != package_line(&current.package_coordinate)?
        || previous.current_exact_receipt.target_profile_hash != current.target_profile_hash
        || previous.current_exact_receipt.runtime_abi_hash != current.runtime_abi_hash
    {
        return Err(CompileError::without_span(
            "candidate deployment changes the line, role, entry, network, Script, target profile, or runtime ABI",
        ));
    }
    Ok(())
}

fn validate_type_hash_exact_receipt(receipt: &ExactScriptHandleReceipt) -> Result<()> {
    let value = exact_script_handle_value_from_receipt(receipt)?;
    crate::script_handle::validate_exact_script_handle(receipt, &value)?;
    if receipt.deployment.script.hash_type != "type" || receipt.code_identity_policy != ExactCodeIdentityPolicy::TypeHashExactCodeCell
    {
        return Err(CompileError::without_span(
            "deployment-line handles require a Type-hash Script and retain the concrete code Cell artifact separately",
        ));
    }
    Ok(())
}

fn validate_interface_matches_exact(interface: &PackageInterface, exact: &ExactScriptHandleReceipt, label: &str) -> Result<()> {
    validate_interface_shape(interface, label)?;
    let hash = interface::hash(interface);
    if hash != exact.interface_hash {
        return Err(CompileError::without_span(format!("{label} package interface hash does not match its exact checked receipt")));
    }
    Ok(())
}

fn validate_interface_hash(interface: &PackageInterface, expected: &str, label: &str) -> Result<()> {
    validate_interface_shape(interface, label)?;
    if interface::hash(interface) != expected {
        return Err(CompileError::without_span(format!("{label} package interface does not match the retained deployment-line hash")));
    }
    Ok(())
}

fn validate_interface_shape(interface: &PackageInterface, label: &str) -> Result<()> {
    if interface.schema != crate::interface::INTERFACE_SCHEMA || interface.version != crate::interface::INTERFACE_SCHEMA_VERSION {
        return Err(CompileError::without_span(format!(
            "{label} deployment-line interface must use the current canonical package-interface schema"
        )));
    }
    Ok(())
}

fn require_compatible_report(report: &InterfaceCompatibilityReport, label: &str) -> Result<()> {
    if !report.compatible || report.dimensions.len() != COMPATIBILITY_DIMENSIONS.len() {
        return Err(CompileError::without_span(format!("candidate deployment is incompatible with the {label} interface")));
    }
    for expected in COMPATIBILITY_DIMENSIONS {
        let Some(dimension) = report.dimensions.iter().find(|dimension| dimension.dimension == expected) else {
            return Err(CompileError::without_span(format!("{label} compatibility report is missing dimension {expected}")));
        };
        if dimension.classification != "compatible" || dimension.breaking_changes != 0 {
            return Err(CompileError::without_span(format!("{label} compatibility dimension {expected} is breaking")));
        }
    }
    Ok(())
}

fn validate_compatibility_report(report: &InterfaceCompatibilityReport, old_hash: &str, new_hash: &str, label: &str) -> Result<()> {
    if report.schema != COMPATIBILITY_SCHEMA
        || report.version != 1
        || report.old_interface_hash != old_hash
        || report.new_interface_hash != new_hash
    {
        return Err(CompileError::without_span(format!("{label} compatibility report identity does not match the deployment line")));
    }
    require_compatible_report(report, label)
}

fn validate_policy(policy: &DeploymentLinePolicy) -> Result<()> {
    if policy != &DeploymentLinePolicy::default() {
        return Err(CompileError::without_span("unsupported deployment-line compatibility or authorization policy"));
    }
    Ok(())
}

fn deployment_line_id(
    package_line: &str,
    receipt: &ExactScriptHandleReceipt,
    baseline_interface_hash: &str,
    policy_hash: &str,
    admission_cell_type_hash: &[u8; 32],
) -> Result<String> {
    let identity = serde_json::json!({
        "schema": "cellscript-deployment-line-id-v1",
        "package_line": package_line,
        "class": receipt.class,
        "script_role": receipt.script_role,
        "entry": receipt.entry,
        "network": receipt.deployment.network,
        "stable_script": receipt.deployment.script,
        "baseline_interface_hash": baseline_interface_hash,
        "policy_hash": policy_hash,
        "admission_cell_type_hash": format!("0x{}", hex_encode(admission_cell_type_hash)),
    });
    canonical_hash(DEPLOYMENT_LINE_ID_HASH_DOMAIN, &identity)
        .map_err(|error| CompileError::without_span(format!("failed to hash deployment-line identity: {error}")))
}

fn deployment_line_receipt_hash_unchecked(receipt: &DeploymentLineReceipt) -> Result<String> {
    canonical_hash(DEPLOYMENT_LINE_RECEIPT_HASH_DOMAIN, receipt)
        .map_err(|error| CompileError::without_span(format!("failed to hash deployment-line receipt: {error}")))
}

fn package_line(coordinate: &str) -> Result<String> {
    let (name, version) = coordinate
        .rsplit_once('@')
        .ok_or_else(|| CompileError::without_span("deployment-line package coordinate must end in @<semver>"))?;
    if name.is_empty() {
        return Err(CompileError::without_span("deployment-line package coordinate has an empty package name"));
    }
    let version = semver::Version::parse(version)
        .map_err(|error| CompileError::without_span(format!("deployment-line package coordinate has invalid SemVer: {error}")))?;
    if version.major == 0 {
        Ok(format!("{name}@0.{}", version.minor))
    } else {
        Ok(format!("{name}@{}", version.major))
    }
}

fn require_monotonic_line_version(previous: &str, current: &str) -> Result<()> {
    let (previous_name, previous_version) = split_coordinate(previous)?;
    let (current_name, current_version) = split_coordinate(current)?;
    if previous_name != current_name || package_line(previous)? != package_line(current)? || current_version <= previous_version {
        return Err(CompileError::without_span(
            "deployment-line upgrade must increase SemVer within the same package compatibility line",
        ));
    }
    Ok(())
}

fn split_coordinate(coordinate: &str) -> Result<(&str, semver::Version)> {
    let (name, version) = coordinate
        .rsplit_once('@')
        .ok_or_else(|| CompileError::without_span("deployment-line package coordinate must end in @<semver>"))?;
    let version = semver::Version::parse(version)
        .map_err(|error| CompileError::without_span(format!("deployment-line package coordinate has invalid SemVer: {error}")))?;
    Ok((name, version))
}

fn role_tag(role: ProtocolScriptRole) -> u8 {
    match role {
        ProtocolScriptRole::Lock => EXACT_SCRIPT_HANDLE_ROLE_LOCK,
        ProtocolScriptRole::Type => EXACT_SCRIPT_HANDLE_ROLE_TYPE,
        ProtocolScriptRole::SpawnedVerifier => EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER,
    }
}

fn raw_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(CompileError::without_span(format!("deployment-line {label} must be 64 lowercase hexadecimal characters")));
    }
    let bytes = hex::decode(value)
        .map_err(|error| CompileError::without_span(format!("failed to decode deployment-line {label}: {error}")))?;
    bytes.try_into().map_err(|_| CompileError::without_span(format!("deployment-line {label} must contain 32 bytes")))
}

fn prefixed_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(CompileError::without_span(format!("deployment-line {label} must be 0x-prefixed lowercase hexadecimal")));
    };
    raw_hash32(value, label)
}

fn canonical_hex_bytes(value: &str, label: &str) -> Result<Vec<u8>> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(CompileError::without_span(format!("deployment-line {label} must be 0x-prefixed")));
    };
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(CompileError::without_span(format!("deployment-line {label} must be canonical lowercase hex")));
    }
    hex::decode(value).map_err(|error| CompileError::without_span(format!("failed to decode deployment-line {label}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::{InterfaceCallable, InterfaceRuntimeContract};
    use crate::protocol_bundle::{ProtocolCellDep, ProtocolDepType, ProtocolDeploymentIdentity, ProtocolEntryKind, ProtocolOutPoint};
    use crate::script_handle::{build_exact_script_handle, ExactScriptHandleReceiptInput};

    fn raw_hash(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn interface(additive: bool) -> PackageInterface {
        let mut interface = PackageInterface {
            schema: crate::interface::INTERFACE_SCHEMA.to_string(),
            version: crate::interface::INTERFACE_SCHEMA_VERSION,
            module: "line::token".to_string(),
            module_identity: "blake2b:line-token".to_string(),
            edition: "2027".to_string(),
            visibility_default: "private".to_string(),
            runtime_contract: InterfaceRuntimeContract {
                target_profile: "ckb".to_string(),
                vm_abi: "ckb-vm2".to_string(),
                witness_abi: "CSARGv1".to_string(),
                lock_args_abi: "ckb-script-args".to_string(),
                source_encoding: "ckb-source-group-high-bit".to_string(),
                spawn_ipc_abi: "cellscript-spawn-ipc-v1".to_string(),
                compatibility_profile_id: "ckb-vm2-data2".to_string(),
                temporal: Default::default(),
            },
            builder_contract_hash: raw_hash(0x11),
            deployment_contract_hash: raw_hash(0x12),
            ..Default::default()
        };
        interface.callables.push(InterfaceCallable {
            identity: "line::token::transfer".to_string(),
            name: "transfer".to_string(),
            kind: "action".to_string(),
            visibility: "public".to_string(),
            effect: "mutating".to_string(),
            builder_contract_hash: raw_hash(0x13),
            ..Default::default()
        });
        if additive {
            interface.callables.push(InterfaceCallable {
                identity: "line::token::inspect".to_string(),
                name: "inspect".to_string(),
                kind: "function".to_string(),
                visibility: "public".to_string(),
                effect: "read-only".to_string(),
                builder_contract_hash: raw_hash(0x14),
                ..Default::default()
            });
        }
        interface
    }

    fn exact_receipt(version: &str, artifact_byte: u8, interface: &PackageInterface) -> ExactScriptHandleReceipt {
        let artifact_hash = raw_hash(artifact_byte);
        let entry = ProtocolEntryIdentity { kind: ProtocolEntryKind::Action, name: "transfer".to_string() };
        let deployment = ProtocolDeploymentIdentity {
            network: ProtocolNetworkIdentity { chain_id: "ckb-testnet".to_string(), genesis_hash: format!("0x{}", raw_hash(0x21)) },
            artifact_hash: artifact_hash.clone(),
            script: ProtocolScriptIdentity {
                code_hash: format!("0x{}", raw_hash(0x22)),
                hash_type: "type".to_string(),
                args: "0x0102".to_string(),
            },
            code_cell_dep: ProtocolCellDep {
                out_point: ProtocolOutPoint { tx_hash: format!("0x{}", raw_hash(artifact_byte)), index: 0 },
                dep_type: ProtocolDepType::Code,
            },
        };
        build_exact_script_handle(ExactScriptHandleReceiptInput {
            package_coordinate: &format!("example/token@{version}"),
            lock_node_id: &format!("token@{version}|path:token|env=testnet|features=default"),
            entry: &entry,
            script_role: ProtocolScriptRole::Type,
            interface_hash: &interface::hash(interface),
            typed_semantics_hash: &raw_hash(artifact_byte.wrapping_add(1)),
            artifact_hash: &artifact_hash,
            target_profile_hash: &raw_hash(0x23),
            runtime_abi_hash: &raw_hash(0x24),
            verified_bundle_id: &raw_hash(artifact_byte.wrapping_add(2)),
            deployment: &deployment,
        })
        .unwrap()
        .0
    }

    #[test]
    fn fixed_line_handle_binds_initial_exact_receipt_and_admission_commitment() {
        let baseline = interface(false);
        let exact = exact_receipt("1.0.0", 0x31, &baseline);
        let (receipt, value) = begin_deployment_line(&exact, &baseline, &format!("0x{}", raw_hash(0x41))).unwrap();
        assert_eq!(receipt.package_line, "example/token@1");
        assert_eq!(receipt.sequence, 0);
        assert_eq!(receipt.status, DeploymentLineStatus::Active);
        assert!(receipt.previous_receipt_hash.is_none());
        assert!(receipt.predecessor_compatibility.compatible);
        assert!(receipt.baseline_compatibility.compatible);
        assert_eq!(value.encoding, DEPLOYMENT_LINE_HANDLE_ENCODING);
        assert_eq!(value.encoded.len(), 2 + DEPLOYMENT_LINE_HANDLE_BYTES * 2);
        validate_deployment_line_handle(&receipt, &value).unwrap();
        let bytes = canonical_hex_bytes(&value.encoded, "test line value").unwrap();
        assert_eq!(&bytes[..8], DEPLOYMENT_LINE_HANDLE_MAGIC);
        assert_eq!(bytes[DEPLOYMENT_LINE_HANDLE_STATUS_OFFSET], DEPLOYMENT_LINE_HANDLE_STATUS_ACTIVE);
        assert!(bytes
            [DEPLOYMENT_LINE_HANDLE_RESERVED_OFFSET..DEPLOYMENT_LINE_HANDLE_RESERVED_OFFSET + DEPLOYMENT_LINE_HANDLE_RESERVED_BYTES]
            .iter()
            .all(|byte| *byte == 0));
        assert_eq!(deployment_line_commitment_data(&value).unwrap().len(), 2 + (7 + 32) * 2);

        let mut changed = value.clone();
        changed.encoded.replace_range(2..4, "ff");
        assert!(validate_deployment_line_handle(&receipt, &changed).is_err());
    }

    #[test]
    fn additive_upgrade_is_hash_linked_while_breaking_stale_and_yanked_versions_reject() {
        let baseline = interface(false);
        let additive = interface(true);
        let first_exact = exact_receipt("1.0.0", 0x51, &baseline);
        let (first, _) = begin_deployment_line(&first_exact, &baseline, &format!("0x{}", raw_hash(0x61))).unwrap();
        let next_exact = exact_receipt("1.1.0", 0x52, &additive);
        let (next, next_value) = advance_deployment_line(&first, &baseline, &baseline, &next_exact, &additive).unwrap();
        assert_eq!(next.sequence, 1);
        assert_eq!(next.previous_receipt_hash, Some(deployment_line_receipt_hash(&first).unwrap()));
        assert_eq!(next.previous_interface_hash, interface::hash(&baseline));
        assert_eq!(next.current_interface_hash, interface::hash(&additive));
        assert!(next.predecessor_compatibility.compatible && next.baseline_compatibility.compatible);
        validate_deployment_line_successor(&first, &next).unwrap();
        validate_deployment_line_handle(&next, &next_value).unwrap();

        let same_version = exact_receipt("1.0.0", 0x53, &additive);
        assert!(advance_deployment_line(&first, &baseline, &baseline, &same_version, &additive).is_err());

        let mut breaking = additive.clone();
        breaking.runtime_contract.witness_abi = "different-witness-abi".to_string();
        let breaking_exact = exact_receipt("1.2.0", 0x54, &breaking);
        assert!(advance_deployment_line(&next, &baseline, &additive, &breaking_exact, &breaking).is_err());

        let mut changed_script = exact_receipt("1.2.0", 0x55, &additive);
        changed_script.deployment.script.args = "0x03".to_string();
        assert!(advance_deployment_line(&next, &baseline, &additive, &changed_script, &additive).is_err());

        let (yanked, yanked_value) = yank_deployment_line(&next, &additive).unwrap();
        assert_eq!(yanked.status, DeploymentLineStatus::Yanked);
        assert_eq!(yanked.sequence, 2);
        validate_deployment_line_successor(&next, &yanked).unwrap();
        validate_deployment_line_handle(&yanked, &yanked_value).unwrap();
        assert!(advance_deployment_line(&yanked, &baseline, &additive, &next_exact, &additive).is_err());

        let mut stale = next.clone();
        stale.previous_receipt_hash = Some(raw_hash(0x99));
        assert!(validate_deployment_line_successor(&first, &stale).is_err());
    }

    #[test]
    fn data_hash_deployment_cannot_be_promoted_to_an_upgrade_line() {
        let baseline = interface(false);
        let mut exact = exact_receipt("1.0.0", 0x71, &baseline);
        exact.deployment.script.hash_type = "data2".to_string();
        exact.deployment.script.code_hash = format!("0x{}", exact.artifact_hash);
        exact.code_identity_policy = ExactCodeIdentityPolicy::DataHashExactArtifact;
        assert!(begin_deployment_line(&exact, &baseline, &format!("0x{}", raw_hash(0x72))).is_err());
    }
}
