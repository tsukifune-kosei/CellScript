//! Canonical exact-artifact Script and verifier handles.
//!
//! A handle is an ordinary fixed-width value. It grants no Cell lifecycle or
//! authorization capability. The full receipt remains audit evidence; the
//! handle commits to that receipt and the complete deployed Script identity.

use crate::error::{CompileError, Result};
use crate::protocol_bundle::{
    validate_deployment, ProtocolDeploymentIdentity, ProtocolEntryIdentity, ProtocolScriptIdentity, ProtocolScriptRole,
};
use crate::script_handle_contract::{
    EXACT_SCRIPT_HANDLE_ARTIFACT_HASH_OFFSET, EXACT_SCRIPT_HANDLE_CLASS_OFFSET, EXACT_SCRIPT_HANDLE_CLASS_SCRIPT,
    EXACT_SCRIPT_HANDLE_CLASS_VERIFIER, EXACT_SCRIPT_HANDLE_INTERFACE_HASH_OFFSET, EXACT_SCRIPT_HANDLE_MAGIC,
    EXACT_SCRIPT_HANDLE_RECEIPT_HASH_OFFSET, EXACT_SCRIPT_HANDLE_ROLE_LOCK, EXACT_SCRIPT_HANDLE_ROLE_OFFSET,
    EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER, EXACT_SCRIPT_HANDLE_ROLE_TYPE, EXACT_SCRIPT_HANDLE_RUNTIME_ABI_HASH_OFFSET,
    EXACT_SCRIPT_HANDLE_SCRIPT_HASH_OFFSET, EXACT_SCRIPT_HANDLE_TARGET_PROFILE_HASH_OFFSET,
};
pub use crate::script_handle_contract::{EXACT_SCRIPT_HANDLE_BYTES, EXACT_SCRIPT_HANDLE_ENCODING};
use crate::{ckb_blake2b256, hex_encode, CompileMetadata};
use cellscript_artifact_checker::canonical_hash;
use serde::{Deserialize, Serialize};

pub const EXACT_SCRIPT_HANDLE_RECEIPT_SCHEMA: &str = "cellscript-exact-script-handle-receipt-v1";
pub const EXACT_SCRIPT_HANDLE_VALUE_SCHEMA: &str = "cellscript-exact-script-handle-value-v1";
pub const EXACT_SCRIPT_HANDLE_RECEIPT_HASH_DOMAIN: &str = "cellscript-exact-script-handle-receipt-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExactHandleClass {
    Script,
    Verifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExactCodeIdentityPolicy {
    DataHashExactArtifact,
    TypeHashExactCodeCell,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExactUpgradePolicy {
    ExactArtifact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactScriptHandleReceipt {
    pub schema: String,
    pub version: u32,
    pub class: ExactHandleClass,
    pub script_role: ProtocolScriptRole,
    pub package_coordinate: String,
    pub lock_node_id: String,
    pub entry: ProtocolEntryIdentity,
    pub interface_hash: String,
    pub typed_semantics_hash: String,
    pub artifact_hash: String,
    pub target_profile_hash: String,
    pub runtime_abi_hash: String,
    pub verified_bundle_id: String,
    pub deployment: ProtocolDeploymentIdentity,
    pub code_identity_policy: ExactCodeIdentityPolicy,
    pub upgrade_policy: ExactUpgradePolicy,
}

/// Canonical runtime representation.
///
/// `encoded` is always `0x` plus exactly 202 bytes:
/// magic(8), class(1), role(1), then receipt, Script, interface, artifact,
/// target-profile, and runtime-ABI hashes (6 * 32).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactScriptHandleValue {
    pub schema: String,
    pub version: u32,
    pub encoding: String,
    pub encoded: String,
}

pub struct ExactScriptHandleReceiptInput<'a> {
    pub package_coordinate: &'a str,
    pub lock_node_id: &'a str,
    pub entry: &'a ProtocolEntryIdentity,
    pub script_role: ProtocolScriptRole,
    pub interface_hash: &'a str,
    pub typed_semantics_hash: &'a str,
    pub artifact_hash: &'a str,
    pub target_profile_hash: &'a str,
    pub runtime_abi_hash: &'a str,
    pub verified_bundle_id: &'a str,
    pub deployment: &'a ProtocolDeploymentIdentity,
}

/// Canonical ABI digest already used by package locks and Registry records.
/// Exact handles reuse this identity instead of defining a parallel ABI hash.
pub fn compile_metadata_abi_hash(metadata: &CompileMetadata) -> Result<String> {
    let abi = serde_json::json!({
        "metadata_schema_version": metadata.metadata_schema_version,
        "metadata_schema_versions": {
            "metadata": metadata.metadata_schema_version,
            "source": metadata.source_metadata_schema_version,
            "artifact": metadata.artifact_metadata_schema_version,
            "constraints": metadata.constraints_metadata_schema_version,
        },
        "edition": metadata.edition,
        "compatibility_profile": &metadata.compatibility_profile,
        "target_profile": metadata.target_profile.name.as_str(),
        "types": &metadata.types,
        "actions": &metadata.actions,
        "functions": &metadata.functions,
        "locks": &metadata.locks,
        "molecule_schema_manifest": &metadata.molecule_schema_manifest,
        "cell_data_codec_manifest": &metadata.cell_data_codec_manifest,
    });
    let bytes = serde_json::to_vec(&abi)
        .map_err(|error| CompileError::without_span(format!("failed to serialize compile metadata ABI for digest: {error}")))?;
    Ok(hex_encode(&ckb_blake2b256(&bytes)))
}

pub fn build_exact_script_handle(
    input: ExactScriptHandleReceiptInput<'_>,
) -> Result<(ExactScriptHandleReceipt, ExactScriptHandleValue)> {
    validate_name(input.package_coordinate, "package coordinate")?;
    validate_name(input.lock_node_id, "Cell.lock node identity")?;
    validate_name(&input.entry.name, "entry name")?;
    for (label, value) in [
        ("interface_hash", input.interface_hash),
        ("typed_semantics_hash", input.typed_semantics_hash),
        ("artifact_hash", input.artifact_hash),
        ("target_profile_hash", input.target_profile_hash),
        ("runtime_abi_hash", input.runtime_abi_hash),
        ("verified_bundle_id", input.verified_bundle_id),
    ] {
        raw_hash32(value, label)?;
    }
    if input.deployment.artifact_hash != input.artifact_hash {
        return Err(CompileError::without_span("exact Script handle deployment artifact hash differs from the checked artifact"));
    }
    let class = match input.script_role {
        ProtocolScriptRole::Lock | ProtocolScriptRole::Type => ExactHandleClass::Script,
        ProtocolScriptRole::SpawnedVerifier => ExactHandleClass::Verifier,
    };
    let code_identity_policy = match input.deployment.script.hash_type.as_str() {
        "data" | "data1" | "data2" => {
            if input.deployment.script.code_hash.strip_prefix("0x") != Some(input.artifact_hash) {
                return Err(CompileError::without_span("exact data-hash Script handle code hash differs from the checked artifact"));
            }
            ExactCodeIdentityPolicy::DataHashExactArtifact
        }
        "type" => ExactCodeIdentityPolicy::TypeHashExactCodeCell,
        other => return Err(CompileError::without_span(format!("exact Script handle has unsupported Script hash type '{other}'"))),
    };
    let receipt = ExactScriptHandleReceipt {
        schema: EXACT_SCRIPT_HANDLE_RECEIPT_SCHEMA.to_string(),
        version: 1,
        class,
        script_role: input.script_role,
        package_coordinate: input.package_coordinate.to_string(),
        lock_node_id: input.lock_node_id.to_string(),
        entry: input.entry.clone(),
        interface_hash: input.interface_hash.to_string(),
        typed_semantics_hash: input.typed_semantics_hash.to_string(),
        artifact_hash: input.artifact_hash.to_string(),
        target_profile_hash: input.target_profile_hash.to_string(),
        runtime_abi_hash: input.runtime_abi_hash.to_string(),
        verified_bundle_id: input.verified_bundle_id.to_string(),
        deployment: input.deployment.clone(),
        code_identity_policy,
        upgrade_policy: ExactUpgradePolicy::ExactArtifact,
    };
    let value = encode_exact_script_handle(&receipt)?;
    Ok((receipt, value))
}

pub fn exact_script_handle_receipt_hash(receipt: &ExactScriptHandleReceipt) -> Result<String> {
    validate_receipt_shape(receipt)?;
    canonical_hash(EXACT_SCRIPT_HANDLE_RECEIPT_HASH_DOMAIN, receipt)
        .map_err(|error| CompileError::without_span(format!("failed to hash exact Script handle receipt: {error}")))
}

pub fn validate_exact_script_handle(receipt: &ExactScriptHandleReceipt, value: &ExactScriptHandleValue) -> Result<()> {
    let expected = encode_exact_script_handle(receipt)?;
    if value != &expected {
        return Err(CompileError::without_span("exact Script handle value does not match its interface/artifact/deployment receipt"));
    }
    Ok(())
}

/// Rebuild the canonical fixed-width value from an independently retained
/// exact receipt.
pub fn exact_script_handle_value_from_receipt(receipt: &ExactScriptHandleReceipt) -> Result<ExactScriptHandleValue> {
    encode_exact_script_handle(receipt)
}

/// CKB Blake2b-256 commitment consumed by the on-chain exact-handle helpers.
///
/// Binding the complete 202-byte value makes substitutions of the receipt,
/// interface, artifact, target profile, runtime ABI, Script identity, class,
/// role, or encoding fail as one closed runtime check.
pub fn exact_script_handle_value_hash(value: &ExactScriptHandleValue) -> Result<String> {
    if value.schema != EXACT_SCRIPT_HANDLE_VALUE_SCHEMA || value.version != 1 || value.encoding != EXACT_SCRIPT_HANDLE_ENCODING {
        return Err(CompileError::without_span("unsupported exact Script handle value schema/version/encoding"));
    }
    let bytes = canonical_hex_bytes(&value.encoded, "exact Script handle value")?;
    if bytes.len() != EXACT_SCRIPT_HANDLE_BYTES {
        return Err(CompileError::without_span(format!(
            "exact Script handle value must contain exactly {EXACT_SCRIPT_HANDLE_BYTES} bytes"
        )));
    }
    Ok(hex_encode(&ckb_blake2b256(&bytes)))
}

pub fn ckb_script_identity_hash(script: &ProtocolScriptIdentity) -> Result<String> {
    let code_hash = prefixed_hash32(&script.code_hash, "Script code_hash")?;
    let hash_type = match script.hash_type.as_str() {
        "data" => 0u8,
        "type" => 1u8,
        "data1" => 2u8,
        "data2" => 4u8,
        other => return Err(CompileError::without_span(format!("unsupported CKB Script hash_type '{other}'"))),
    };
    let args = canonical_hex_bytes(&script.args, "Script args")?;
    let args_field_size = 4usize.checked_add(args.len()).ok_or_else(|| CompileError::without_span("CKB Script args size overflow"))?;
    let total_size =
        49usize.checked_add(args_field_size).ok_or_else(|| CompileError::without_span("CKB Script serialization size overflow"))?;
    let total_size = u32::try_from(total_size).map_err(|_| CompileError::without_span("CKB Script is too large to serialize"))?;
    let args_count = u32::try_from(args.len()).map_err(|_| CompileError::without_span("CKB Script args are too large"))?;

    let mut bytes = Vec::with_capacity(total_size as usize);
    bytes.extend_from_slice(&total_size.to_le_bytes());
    bytes.extend_from_slice(&16u32.to_le_bytes());
    bytes.extend_from_slice(&48u32.to_le_bytes());
    bytes.extend_from_slice(&49u32.to_le_bytes());
    bytes.extend_from_slice(&code_hash);
    bytes.push(hash_type);
    bytes.extend_from_slice(&args_count.to_le_bytes());
    bytes.extend_from_slice(&args);
    Ok(format!("0x{}", hex_encode(&ckb_blake2b256(&bytes))))
}

fn encode_exact_script_handle(receipt: &ExactScriptHandleReceipt) -> Result<ExactScriptHandleValue> {
    validate_receipt_shape(receipt)?;
    let receipt_hash = raw_hash32(&exact_script_handle_receipt_hash_unchecked(receipt)?, "receipt hash")?;
    let script_hash = prefixed_hash32(&ckb_script_identity_hash(&receipt.deployment.script)?, "Script hash")?;
    let interface_hash = raw_hash32(&receipt.interface_hash, "interface_hash")?;
    let artifact_hash = raw_hash32(&receipt.artifact_hash, "artifact_hash")?;
    let target_profile_hash = raw_hash32(&receipt.target_profile_hash, "target_profile_hash")?;
    let runtime_abi_hash = raw_hash32(&receipt.runtime_abi_hash, "runtime_abi_hash")?;

    let mut bytes = vec![0u8; EXACT_SCRIPT_HANDLE_BYTES];
    bytes[..EXACT_SCRIPT_HANDLE_MAGIC.len()].copy_from_slice(EXACT_SCRIPT_HANDLE_MAGIC);
    bytes[EXACT_SCRIPT_HANDLE_CLASS_OFFSET] = match receipt.class {
        ExactHandleClass::Script => EXACT_SCRIPT_HANDLE_CLASS_SCRIPT,
        ExactHandleClass::Verifier => EXACT_SCRIPT_HANDLE_CLASS_VERIFIER,
    };
    bytes[EXACT_SCRIPT_HANDLE_ROLE_OFFSET] = match receipt.script_role {
        ProtocolScriptRole::Lock => EXACT_SCRIPT_HANDLE_ROLE_LOCK,
        ProtocolScriptRole::Type => EXACT_SCRIPT_HANDLE_ROLE_TYPE,
        ProtocolScriptRole::SpawnedVerifier => EXACT_SCRIPT_HANDLE_ROLE_SPAWNED_VERIFIER,
    };
    for (offset, hash) in [
        (EXACT_SCRIPT_HANDLE_RECEIPT_HASH_OFFSET, receipt_hash),
        (EXACT_SCRIPT_HANDLE_SCRIPT_HASH_OFFSET, script_hash),
        (EXACT_SCRIPT_HANDLE_INTERFACE_HASH_OFFSET, interface_hash),
        (EXACT_SCRIPT_HANDLE_ARTIFACT_HASH_OFFSET, artifact_hash),
        (EXACT_SCRIPT_HANDLE_TARGET_PROFILE_HASH_OFFSET, target_profile_hash),
        (EXACT_SCRIPT_HANDLE_RUNTIME_ABI_HASH_OFFSET, runtime_abi_hash),
    ] {
        bytes[offset..offset + hash.len()].copy_from_slice(&hash);
    }
    Ok(ExactScriptHandleValue {
        schema: EXACT_SCRIPT_HANDLE_VALUE_SCHEMA.to_string(),
        version: 1,
        encoding: EXACT_SCRIPT_HANDLE_ENCODING.to_string(),
        encoded: format!("0x{}", hex_encode(&bytes)),
    })
}

fn exact_script_handle_receipt_hash_unchecked(receipt: &ExactScriptHandleReceipt) -> Result<String> {
    canonical_hash(EXACT_SCRIPT_HANDLE_RECEIPT_HASH_DOMAIN, receipt)
        .map_err(|error| CompileError::without_span(format!("failed to hash exact Script handle receipt: {error}")))
}

fn validate_receipt_shape(receipt: &ExactScriptHandleReceipt) -> Result<()> {
    if receipt.schema != EXACT_SCRIPT_HANDLE_RECEIPT_SCHEMA || receipt.version != 1 {
        return Err(CompileError::without_span("unsupported exact Script handle receipt schema/version"));
    }
    let expected_class = match receipt.script_role {
        ProtocolScriptRole::Lock | ProtocolScriptRole::Type => ExactHandleClass::Script,
        ProtocolScriptRole::SpawnedVerifier => ExactHandleClass::Verifier,
    };
    if receipt.class != expected_class {
        return Err(CompileError::without_span("exact Script handle class disagrees with its Script role"));
    }
    if receipt.upgrade_policy != ExactUpgradePolicy::ExactArtifact {
        return Err(CompileError::without_span("exact Script handle must use the exact-artifact upgrade policy"));
    }
    validate_name(&receipt.package_coordinate, "package coordinate")?;
    validate_name(&receipt.lock_node_id, "Cell.lock node identity")?;
    validate_name(&receipt.entry.name, "entry name")?;
    validate_deployment(&receipt.deployment)?;
    if receipt.deployment.artifact_hash != receipt.artifact_hash {
        return Err(CompileError::without_span("exact Script handle receipt has inconsistent artifact hashes"));
    }
    let expected_policy = match receipt.deployment.script.hash_type.as_str() {
        "data" | "data1" | "data2" => ExactCodeIdentityPolicy::DataHashExactArtifact,
        "type" => ExactCodeIdentityPolicy::TypeHashExactCodeCell,
        other => return Err(CompileError::without_span(format!("unsupported CKB Script hash_type '{other}'"))),
    };
    if receipt.code_identity_policy != expected_policy {
        return Err(CompileError::without_span("exact Script handle code identity policy disagrees with its deployment hash type"));
    }
    if receipt.code_identity_policy == ExactCodeIdentityPolicy::DataHashExactArtifact
        && receipt.deployment.script.code_hash.strip_prefix("0x") != Some(receipt.artifact_hash.as_str())
    {
        return Err(CompileError::without_span("exact data-hash Script handle code hash differs from the checked artifact"));
    }
    for (label, value) in [
        ("interface_hash", receipt.interface_hash.as_str()),
        ("typed_semantics_hash", receipt.typed_semantics_hash.as_str()),
        ("artifact_hash", receipt.artifact_hash.as_str()),
        ("target_profile_hash", receipt.target_profile_hash.as_str()),
        ("runtime_abi_hash", receipt.runtime_abi_hash.as_str()),
        ("verified_bundle_id", receipt.verified_bundle_id.as_str()),
    ] {
        raw_hash32(value, label)?;
    }
    Ok(())
}

fn validate_name(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(CompileError::without_span(format!("exact Script handle {label} must be a non-empty bounded string")))
    } else {
        Ok(())
    }
}

fn raw_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(CompileError::without_span(format!("exact Script handle {label} must be 64 lowercase hexadecimal characters")));
    }
    decode_hash(value, label)
}

fn prefixed_hash32(value: &str, label: &str) -> Result<[u8; 32]> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(CompileError::without_span(format!("exact Script handle {label} must be 0x-prefixed lowercase hexadecimal")));
    };
    raw_hash32(value, label)
}

fn decode_hash(value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)
        .map_err(|error| CompileError::without_span(format!("failed to decode exact Script handle {label}: {error}")))?;
    bytes.try_into().map_err(|_| CompileError::without_span(format!("exact Script handle {label} must contain 32 bytes")))
}

fn canonical_hex_bytes(value: &str, label: &str) -> Result<Vec<u8>> {
    let Some(value) = value.strip_prefix("0x") else {
        return Err(CompileError::without_span(format!("exact Script handle {label} must be 0x-prefixed")));
    };
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return Err(CompileError::without_span(format!("exact Script handle {label} must be canonical lowercase hex")));
    }
    hex::decode(value).map_err(|error| CompileError::without_span(format!("failed to decode exact Script handle {label}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_bundle::{
        ProtocolCellDep, ProtocolDepType, ProtocolNetworkIdentity, ProtocolOutPoint, ProtocolScriptIdentity,
    };
    use ckb_types::{core::ScriptHashType, packed, prelude::*};

    fn hash(byte: &str) -> String {
        byte.repeat(64)
    }

    fn deployment(hash_type: &str, args: &str) -> ProtocolDeploymentIdentity {
        let artifact_hash = hash("a");
        ProtocolDeploymentIdentity {
            network: ProtocolNetworkIdentity { chain_id: "ckb-testnet".to_string(), genesis_hash: format!("0x{}", hash("0")) },
            artifact_hash: artifact_hash.clone(),
            script: ProtocolScriptIdentity {
                code_hash: if hash_type == "type" { format!("0x{}", hash("b")) } else { format!("0x{artifact_hash}") },
                hash_type: hash_type.to_string(),
                args: args.to_string(),
            },
            code_cell_dep: ProtocolCellDep {
                out_point: ProtocolOutPoint { tx_hash: format!("0x{}", hash("c")), index: 0 },
                dep_type: ProtocolDepType::Code,
            },
        }
    }

    fn build(deployment: &ProtocolDeploymentIdentity) -> (ExactScriptHandleReceipt, ExactScriptHandleValue) {
        let entry = ProtocolEntryIdentity { kind: crate::protocol_bundle::ProtocolEntryKind::Action, name: "transfer".to_string() };
        let interface_hash = hash("1");
        let typed_semantics_hash = hash("2");
        let target_profile_hash = hash("3");
        let runtime_abi_hash = hash("4");
        let verified_bundle_id = hash("5");
        build_exact_script_handle(ExactScriptHandleReceiptInput {
            package_coordinate: "example/token@1.0.0",
            lock_node_id: "token@1.0.0|path:token|env=default|features=default",
            entry: &entry,
            script_role: ProtocolScriptRole::Type,
            interface_hash: &interface_hash,
            typed_semantics_hash: &typed_semantics_hash,
            artifact_hash: &deployment.artifact_hash,
            target_profile_hash: &target_profile_hash,
            runtime_abi_hash: &runtime_abi_hash,
            verified_bundle_id: &verified_bundle_id,
            deployment,
        })
        .unwrap()
    }

    #[test]
    fn script_identity_hash_matches_ckb_types_molecule_hash() {
        for (hash_type, packed_hash_type) in [
            ("data", ScriptHashType::Data),
            ("data1", ScriptHashType::Data1),
            ("data2", ScriptHashType::Data2),
            ("type", ScriptHashType::Type),
        ] {
            let script = deployment(hash_type, "0x010203").script;
            let packed = packed::Script::new_builder()
                .code_hash(packed::Byte32::from_slice(&hex::decode(&script.code_hash[2..]).unwrap()).unwrap())
                .hash_type(packed_hash_type)
                .args([1u8, 2, 3].pack())
                .build();
            assert_eq!(ckb_script_identity_hash(&script).unwrap(), format!("0x{}", hex::encode(packed.calc_script_hash().as_slice())));
        }
    }

    #[test]
    fn exact_handle_is_fixed_width_and_binds_every_identity_axis() {
        let deployment = deployment("data2", "0x010203");
        let (receipt, value) = build(&deployment);
        assert_eq!(receipt.code_identity_policy, ExactCodeIdentityPolicy::DataHashExactArtifact);
        assert_eq!(value.encoding, EXACT_SCRIPT_HANDLE_ENCODING);
        assert_eq!(value.encoded.len(), 2 + EXACT_SCRIPT_HANDLE_BYTES * 2);
        validate_exact_script_handle(&receipt, &value).unwrap();
        let value_bytes = hex::decode(value.encoded.strip_prefix("0x").unwrap()).unwrap();
        assert_eq!(exact_script_handle_value_hash(&value).unwrap(), hex_encode(&ckb_blake2b256(&value_bytes)));

        let mut changed_value = value.clone();
        changed_value.encoded.replace_range(2..4, "ff");
        assert_ne!(exact_script_handle_value_hash(&changed_value).unwrap(), exact_script_handle_value_hash(&value).unwrap());

        for mutate in [
            |receipt: &mut ExactScriptHandleReceipt| receipt.interface_hash = hash("6"),
            |receipt: &mut ExactScriptHandleReceipt| receipt.typed_semantics_hash = hash("6"),
            |receipt: &mut ExactScriptHandleReceipt| receipt.target_profile_hash = hash("6"),
            |receipt: &mut ExactScriptHandleReceipt| receipt.runtime_abi_hash = hash("6"),
        ] {
            let mut changed = receipt.clone();
            mutate(&mut changed);
            assert!(validate_exact_script_handle(&changed, &value).is_err());
        }

        let mut substituted_code = receipt.clone();
        substituted_code.deployment.script.code_hash = format!("0x{}", hash("6"));
        assert!(validate_exact_script_handle(&substituted_code, &value).is_err());
    }

    #[test]
    fn type_hash_handle_keeps_exact_code_cell_policy_separate() {
        let deployment = deployment("type", "0x");
        let (receipt, value) = build(&deployment);
        assert_eq!(receipt.code_identity_policy, ExactCodeIdentityPolicy::TypeHashExactCodeCell);
        validate_exact_script_handle(&receipt, &value).unwrap();

        let mut wrong = receipt.clone();
        wrong.code_identity_policy = ExactCodeIdentityPolicy::DataHashExactArtifact;
        assert!(validate_exact_script_handle(&wrong, &value).is_err());
    }
}
