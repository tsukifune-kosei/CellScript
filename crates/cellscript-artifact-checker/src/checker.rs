use crate::elf::{parse_elf, DecodedControlFlowKind, ElfErrorKind, ElfParseError, ElfSummary, ParsedElf};
use crate::schema::*;
use crate::{ckb_blake2b256, hex_encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckerRejectionCode {
    V2400BudgetExceeded,
    V2401MalformedJson,
    V2402NonCanonicalJson,
    V2403UnsupportedSchema,
    V2404CanonicalOrder,
    V2405ReferentialIntegrity,
    V2406CfgInvalid,
    V2407AbiOrStackInvalid,
    V2408ProofCoverageInvalid,
    V2409ArtifactIdentityMismatch,
    V2410MetadataBindingMismatch,
    V2411ElfFormatInvalid,
    V2412ElfSectionInvalid,
    V2413InstructionInvalid,
    V2414ControlFlowInvalid,
    V2415BlockDigestMismatch,
    V2416SourceMapInvalid,
    V2417SyscallContractInvalid,
    V2418RecursionPolicyInvalid,
    V2419TypedSemanticsInvalid,
    V2420TypedMachineBindingInvalid,
}

impl CheckerRejectionCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V2400BudgetExceeded => "V2400",
            Self::V2401MalformedJson => "V2401",
            Self::V2402NonCanonicalJson => "V2402",
            Self::V2403UnsupportedSchema => "V2403",
            Self::V2404CanonicalOrder => "V2404",
            Self::V2405ReferentialIntegrity => "V2405",
            Self::V2406CfgInvalid => "V2406",
            Self::V2407AbiOrStackInvalid => "V2407",
            Self::V2408ProofCoverageInvalid => "V2408",
            Self::V2409ArtifactIdentityMismatch => "V2409",
            Self::V2410MetadataBindingMismatch => "V2410",
            Self::V2411ElfFormatInvalid => "V2411",
            Self::V2412ElfSectionInvalid => "V2412",
            Self::V2413InstructionInvalid => "V2413",
            Self::V2414ControlFlowInvalid => "V2414",
            Self::V2415BlockDigestMismatch => "V2415",
            Self::V2416SourceMapInvalid => "V2416",
            Self::V2417SyscallContractInvalid => "V2417",
            Self::V2418RecursionPolicyInvalid => "V2418",
            Self::V2419TypedSemanticsInvalid => "V2419",
            Self::V2420TypedMachineBindingInvalid => "V2420",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckerError {
    pub code: CheckerRejectionCode,
    pub message: String,
}

impl CheckerError {
    pub(crate) fn new(code: CheckerRejectionCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    fn bounded(mut self, max_bytes: u32) -> Self {
        let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
        if self.message.len() > max_bytes {
            let mut end = max_bytes.min(self.message.len());
            while end > 0 && !self.message.is_char_boundary(end) {
                end -= 1;
            }
            self.message.truncate(end);
        }
        self
    }
}

impl std::fmt::Display for CheckerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for CheckerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceState {
    Verified,
    NotProvided,
    NotExecuted,
    NotClaimed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckerReport {
    pub schema: String,
    pub checker_name: String,
    pub checker_version: String,
    pub checker_policy_schema: String,
    pub artifact_hash: String,
    pub lowering_record_hash: String,
    pub source_map_hash: String,
    pub binding_verification: EvidenceState,
    pub structural_verification: EvidenceState,
    pub lowering_record_verification: EvidenceState,
    pub typed_semantics_verification: EvidenceState,
    pub ckb_vm_evidence: EvidenceState,
    pub chain_evidence: EvidenceState,
    pub semantic_equivalence_claimed: bool,
    pub elf: ElfSummary,
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CheckerError> {
    serde_json::to_vec(value).map_err(|error| {
        CheckerError::new(CheckerRejectionCode::V2401MalformedJson, format!("failed to serialize canonical checker value: {error}"))
    })
}

pub fn canonical_hash<T: Serialize>(domain: &str, value: &T) -> Result<String, CheckerError> {
    let bytes = canonical_bytes(value)?;
    let mut material = Vec::with_capacity(domain.len() + 1 + bytes.len());
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    material.extend_from_slice(&bytes);
    Ok(hex_encode(&ckb_blake2b256(&material)))
}

pub fn parse_lowering_record(bytes: &[u8], budgets: &CheckerBudgets) -> Result<VerifiedLoweringRecord, CheckerError> {
    ensure_byte_budget("lowering record", bytes.len(), budgets.record_bytes)?;
    let record: VerifiedLoweringRecord = serde_json::from_slice(bytes).map_err(|error| {
        CheckerError::new(CheckerRejectionCode::V2401MalformedJson, format!("failed to parse lowering record: {error}"))
    })?;
    ensure_canonical("lowering record", bytes, &record)?;
    Ok(record)
}

pub fn parse_source_map(bytes: &[u8], budgets: &CheckerBudgets) -> Result<SourceArtifactMap, CheckerError> {
    ensure_byte_budget("source map", bytes.len(), budgets.source_map_bytes)?;
    let source_map: SourceArtifactMap = serde_json::from_slice(bytes).map_err(|error| {
        CheckerError::new(CheckerRejectionCode::V2401MalformedJson, format!("failed to parse source map: {error}"))
    })?;
    ensure_canonical("source map", bytes, &source_map)?;
    Ok(source_map)
}

pub fn check_bundle(
    artifact: &[u8],
    metadata_bytes: &[u8],
    lowering_record_bytes: &[u8],
    source_map_bytes: &[u8],
    budgets: &CheckerBudgets,
) -> Result<CheckerReport, CheckerError> {
    let result = (|| {
        if budgets.schema != CHECKER_POLICY_SCHEMA {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2403UnsupportedSchema,
                format!("unsupported checker policy schema '{}'", budgets.schema),
            ));
        }
        ensure_byte_budget("artifact", artifact.len(), budgets.artifact_bytes)?;
        let metadata: Value = serde_json::from_slice(metadata_bytes).map_err(|error| {
            CheckerError::new(CheckerRejectionCode::V2401MalformedJson, format!("failed to parse compile metadata: {error}"))
        })?;
        let record = parse_lowering_record(lowering_record_bytes, budgets)?;
        let source_map = parse_source_map(source_map_bytes, budgets)?;
        check_bundle_values(artifact, &metadata, &record, &source_map, budgets)
    })();
    result.map_err(|error| error.bounded(budgets.diagnostic_bytes))
}

pub fn check_bundle_values(
    artifact: &[u8],
    metadata: &Value,
    record: &VerifiedLoweringRecord,
    source_map: &SourceArtifactMap,
    budgets: &CheckerBudgets,
) -> Result<CheckerReport, CheckerError> {
    validate_record_schema(record)?;
    validate_declared_limits(&record.limits, budgets)?;
    validate_counts(record, source_map, budgets)?;
    validate_metadata_binding(artifact, metadata, record, source_map)?;
    validate_record_graph(record, budgets)?;
    validate_typed_semantics(record)?;

    let elf = parse_elf(artifact, budgets.instructions).map_err(map_elf_error)?;
    validate_elf_binding(artifact, record, &elf)?;
    validate_block_digests(artifact, record, &elf)?;
    validate_control_flow(record, &elf)?;
    validate_machine_terminators(record, &elf)?;
    let terminal_sink = crate::failure::validate_verifier_failures(record, &elf)?;
    validate_stack_discipline(record, &elf, terminal_sink)?;
    validate_syscalls(record, &elf)?;
    validate_source_map(source_map, record, artifact, &elf)?;

    Ok(CheckerReport {
        schema: CHECKER_REPORT_SCHEMA.to_string(),
        checker_name: "cellscript-artifact-checker".to_string(),
        checker_version: CHECKER_VERSION.to_string(),
        checker_policy_schema: budgets.schema.clone(),
        artifact_hash: record.artifact_hash.clone(),
        lowering_record_hash: canonical_hash(LOWERING_RECORD_SCHEMA, record)?,
        source_map_hash: canonical_hash(SOURCE_MAP_SCHEMA, source_map)?,
        binding_verification: EvidenceState::Verified,
        structural_verification: EvidenceState::Verified,
        lowering_record_verification: EvidenceState::Verified,
        typed_semantics_verification: EvidenceState::Verified,
        ckb_vm_evidence: EvidenceState::NotExecuted,
        chain_evidence: EvidenceState::NotProvided,
        semantic_equivalence_claimed: false,
        elf: elf.summary(),
    })
}

fn validate_record_schema(record: &VerifiedLoweringRecord) -> Result<(), CheckerError> {
    if record.schema != LOWERING_RECORD_SCHEMA || record.version != LOWERING_RECORD_VERSION {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2403UnsupportedSchema,
            format!("unsupported lowering record '{}'/{}", record.schema, record.version),
        ));
    }
    if record.claim.lowering_record != "binding-verified"
        || record.claim.machine_code != "structurally-verified"
        || record.claim.semantic_equivalence
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2403UnsupportedSchema,
            "lowering record overclaims or mislabels the v1 verification boundary",
        ));
    }
    if record.artifact_format != "RISC-V ELF" || record.target_profile != "ckb" {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2403UnsupportedSchema,
            "v1 checker accepts only the CKB RISC-V ELF profile",
        ));
    }
    if record.compatibility_profile.target_profile != record.target_profile
        || record.compatibility_profile.edition != record.edition
        || record.compatibility_profile.raw_entry_witness_payload_compatible
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            "record compatibility profile disagrees with edition/target or accepts raw entry witnesses",
        ));
    }
    let profile_hash = canonical_hash("cellscript-compatibility-profile-identity-v1", &record.compatibility_profile)?;
    if profile_hash != record.compatibility_profile_hash {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            "record compatibility profile hash does not match its canonical identity",
        ));
    }
    let typed_hash = canonical_hash(TYPED_SEMANTICS_SCHEMA, &record.typed_semantics)?;
    if typed_hash != record.typed_semantics_hash {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2419TypedSemanticsInvalid,
            "typed semantic record hash does not match its canonical contents",
        ));
    }
    Ok(())
}

fn validate_declared_limits(declared: &DeclaredLimits, budgets: &CheckerBudgets) -> Result<(), CheckerError> {
    let checks = [
        ("artifact_bytes", declared.artifact_bytes, budgets.artifact_bytes),
        ("record_bytes", declared.record_bytes, budgets.record_bytes),
        ("source_map_bytes", declared.source_map_bytes, budgets.source_map_bytes),
        ("entries", u64::from(declared.entries), u64::from(budgets.entries)),
        ("blocks", u64::from(declared.blocks), u64::from(budgets.blocks)),
        ("edges", u64::from(declared.edges), u64::from(budgets.edges)),
        ("instructions", declared.instructions, budgets.instructions),
        ("call_depth", u64::from(declared.call_depth), u64::from(budgets.call_depth)),
        ("stack_frame_bytes", u64::from(declared.stack_frame_bytes), u64::from(budgets.stack_frame_bytes)),
        ("proof_records", u64::from(declared.proof_records), u64::from(budgets.proof_records)),
        ("source_map_intervals", u64::from(declared.source_map_intervals), u64::from(budgets.source_map_intervals)),
        ("diagnostic_bytes", u64::from(declared.diagnostic_bytes), u64::from(budgets.diagnostic_bytes)),
    ];
    for (name, value, limit) in checks {
        if value > limit {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2400BudgetExceeded,
                format!("record-declared {name} limit {value} exceeds checker policy {limit}"),
            ));
        }
    }
    Ok(())
}

fn validate_counts(
    record: &VerifiedLoweringRecord,
    source_map: &SourceArtifactMap,
    budgets: &CheckerBudgets,
) -> Result<(), CheckerError> {
    ensure_count("entries", record.entries.len(), budgets.entries)?;
    ensure_count("blocks", record.blocks.len(), budgets.blocks)?;
    ensure_count("edges", record.edges.len(), budgets.edges)?;
    ensure_count("proof records", record.proof_records.len(), budgets.proof_records)?;
    ensure_count("verifier failure exits", record.verifier_failure_exits.len(), budgets.blocks)?;
    ensure_count("source-map intervals", source_map.intervals.len(), budgets.source_map_intervals)?;
    if artifact_declared_too_large(record.artifact_size_bytes, budgets.artifact_bytes) {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2400BudgetExceeded,
            "record-declared artifact size exceeds checker policy",
        ));
    }
    Ok(())
}

fn validate_metadata_binding(
    artifact: &[u8],
    metadata: &Value,
    record: &VerifiedLoweringRecord,
    source_map: &SourceArtifactMap,
) -> Result<(), CheckerError> {
    crate::policy::validate_policy_metadata(metadata, &record.typed_semantics)?;
    validate_ckb_vm2_target_contract(metadata)?;
    let artifact_hash = hex_encode(&ckb_blake2b256(artifact));
    if artifact_hash != record.artifact_hash || artifact.len() as u64 != record.artifact_size_bytes {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2409ArtifactIdentityMismatch,
            "artifact bytes do not match the lowering record identity",
        ));
    }
    let record_hash = canonical_hash(LOWERING_RECORD_SCHEMA, record)?;
    let source_map_hash = canonical_hash(SOURCE_MAP_SCHEMA, source_map)?;
    let comparisons = [
        (
            "verified_artifact.boundary_schema",
            json_string(metadata, &["verified_artifact", "boundary_schema"]),
            VERIFIED_ARTIFACT_BOUNDARY_SCHEMA,
        ),
        ("verified_artifact.state", json_string(metadata, &["verified_artifact", "state"]), "emitted"),
        (
            "verified_artifact.lowering_record_schema",
            json_string(metadata, &["verified_artifact", "lowering_record_schema"]),
            LOWERING_RECORD_SCHEMA,
        ),
        ("verified_artifact.source_map_schema", json_string(metadata, &["verified_artifact", "source_map_schema"]), SOURCE_MAP_SCHEMA),
        ("compiler_version", json_string(metadata, &["compiler_version"]), record.compiler_version.as_str()),
        ("module", json_string(metadata, &["module"]), record.module.as_str()),
        ("edition", json_string(metadata, &["edition"]), record.edition.as_str()),
        ("target_profile.name", json_string(metadata, &["target_profile", "name"]), record.target_profile.as_str()),
        ("artifact_format", json_string(metadata, &["artifact_format"]), record.artifact_format.as_str()),
        ("artifact_hash", json_string(metadata, &["artifact_hash"]), record.artifact_hash.as_str()),
        ("source_content_hash", json_string(metadata, &["source_content_hash"]), record.source_content_hash.as_str()),
        (
            "verified_artifact.lowering_record_hash",
            json_string(metadata, &["verified_artifact", "lowering_record_hash"]),
            record_hash.as_str(),
        ),
        (
            "verified_artifact.source_map_hash",
            json_string(metadata, &["verified_artifact", "source_map_hash"]),
            source_map_hash.as_str(),
        ),
    ];
    for (field, actual, expected) in comparisons {
        if actual != Some(expected) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2410MetadataBindingMismatch,
                format!("compile metadata field '{field}' does not match lowering boundary"),
            ));
        }
    }
    let identities = &record.typed_semantics.foundation.identities;
    let expected_bundle_id = canonical_hash(
        "cellscript-verified-bundle-id-v1",
        &(
            record.artifact_hash.as_str(),
            record.typed_semantics_hash.as_str(),
            record.compatibility_profile_hash.as_str(),
            record_hash.as_str(),
            source_map_hash.as_str(),
            source_map.source_digest.as_str(),
        ),
    )?;
    let identity_comparisons = [
        (
            "verified_artifact.source_digest",
            json_string(metadata, &["verified_artifact", "source_digest"]),
            source_map.source_digest.as_str(),
        ),
        (
            "verified_artifact.core_semantic_id",
            json_string(metadata, &["verified_artifact", "core_semantic_id"]),
            identities.core_semantic_id.as_str(),
        ),
        (
            "verified_artifact.entry_contract_id",
            json_string(metadata, &["verified_artifact", "entry_contract_id"]),
            identities.entry_contract_id.as_str(),
        ),
        (
            "verified_artifact.artifact_contract_id",
            json_string(metadata, &["verified_artifact", "artifact_contract_id"]),
            identities.artifact_contract_id.as_str(),
        ),
        (
            "verified_artifact.deployable_artifact_id",
            json_string(metadata, &["verified_artifact", "deployable_artifact_id"]),
            record.artifact_hash.as_str(),
        ),
        (
            "verified_artifact.verified_bundle_id",
            json_string(metadata, &["verified_artifact", "verified_bundle_id"]),
            expected_bundle_id.as_str(),
        ),
    ];
    for (field, actual, expected) in identity_comparisons {
        if actual != Some(expected) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2410MetadataBindingMismatch,
                format!("compile metadata field '{field}' does not match the layered artifact identity"),
            ));
        }
    }
    if json_u64(metadata, &["artifact_size_bytes"]) != Some(record.artifact_size_bytes) {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            "compile metadata artifact_size_bytes does not match lowering record",
        ));
    }
    let profile_value = metadata.get("compatibility_profile").cloned().ok_or_else(|| {
        CheckerError::new(CheckerRejectionCode::V2410MetadataBindingMismatch, "compile metadata has no compatibility_profile")
    })?;
    let profile: CompatibilityProfileIdentity = serde_json::from_value(profile_value).map_err(|error| {
        CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            format!("compile metadata compatibility_profile shape is invalid: {error}"),
        )
    })?;
    if profile != record.compatibility_profile {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            "compile metadata compatibility profile differs from lowering record",
        ));
    }
    for (field, expected) in [
        ("metadata_schema_version", profile.metadata_schema_version),
        ("source_metadata_schema_version", profile.source_metadata_schema_version),
        ("artifact_metadata_schema_version", profile.artifact_metadata_schema_version),
        ("constraints_metadata_schema_version", profile.constraints_metadata_schema_version),
    ] {
        if json_u64(metadata, &[field]) != Some(u64::from(expected)) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2410MetadataBindingMismatch,
                format!("compile metadata field '{field}' differs from the resolved compatibility profile"),
            ));
        }
    }
    let typed_value = metadata.get("typed_semantics").cloned().ok_or_else(|| {
        CheckerError::new(CheckerRejectionCode::V2420TypedMachineBindingInvalid, "compile metadata has no typed_semantics record")
    })?;
    let typed: TypedSemanticRecord = serde_json::from_value(typed_value).map_err(|error| {
        CheckerError::new(
            CheckerRejectionCode::V2420TypedMachineBindingInvalid,
            format!("compile metadata typed_semantics shape is invalid: {error}"),
        )
    })?;
    if typed != record.typed_semantics
        || json_string(metadata, &["typed_semantics_hash"]) != Some(record.typed_semantics_hash.as_str())
        || json_string(metadata, &["interface_hash"]) != Some(record.typed_semantics.interface_hash.as_str())
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2420TypedMachineBindingInvalid,
            "compile metadata typed semantics or interface identity differs from the lowering record",
        ));
    }
    let runtime_trusted = metadata
        .get("runtime")
        .and_then(|runtime| runtime.get("trusted_external_verifiers"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let runtime_trusted: Vec<TrustedExternalVerifierRecord> = serde_json::from_value(runtime_trusted).map_err(|error| {
        CheckerError::new(
            CheckerRejectionCode::V2420TypedMachineBindingInvalid,
            format!("compile metadata trusted external verifier shape is invalid: {error}"),
        )
    })?;
    let constraints_trusted = metadata
        .get("constraints")
        .and_then(|constraints| constraints.get("ckb"))
        .and_then(|ckb| ckb.get("trusted_external_verifiers"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let constraints_trusted: Vec<TrustedExternalVerifierRecord> = serde_json::from_value(constraints_trusted).map_err(|error| {
        CheckerError::new(
            CheckerRejectionCode::V2420TypedMachineBindingInvalid,
            format!("compile metadata CKB trusted external verifier shape is invalid: {error}"),
        )
    })?;
    if runtime_trusted != record.typed_semantics.trusted_external_verifiers
        || constraints_trusted != record.typed_semantics.trusted_external_verifiers
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2420TypedMachineBindingInvalid,
            "compile metadata runtime/CKB trusted external verifier bindings differ from typed semantics",
        ));
    }
    if source_map.lowering_record_hash != record_hash
        || source_map.artifact_hash != record.artifact_hash
        || source_map.source_set_hash != record.source_set_hash
        || source_map.source_digest != record.source_content_hash
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2416SourceMapInvalid,
            "source map identity does not bind to record, artifact, and source set",
        ));
    }
    Ok(())
}

fn validate_ckb_vm2_target_contract(metadata: &Value) -> Result<(), CheckerError> {
    let deployment_hash_types = metadata
        .pointer("/target_profile/deployment_hash_types")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str());
    let constraints_hash_types = metadata
        .pointer("/constraints/ckb/profile_abi_contract/deployment_hash_types")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .and_then(|values| values[0].as_str());
    if json_u64(metadata, &["target_profile", "minimum_vm_version"]) != Some(2)
        || json_string(metadata, &["target_profile", "riscv_isa"]) != Some("rv64imac_zbb")
        || deployment_hash_types != Some("data2")
        || json_u64(metadata, &["constraints", "ckb", "profile_abi_contract", "minimum_vm_version"]) != Some(2)
        || json_string(metadata, &["constraints", "ckb", "profile_abi_contract", "riscv_isa"]) != Some("rv64imac_zbb")
        || constraints_hash_types != Some("data2")
        || json_string(metadata, &["constraints", "ckb", "hash_type_policy", "default_script_hash_type"]) != Some("data2")
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            "compile metadata does not bind the CKB VM2, rv64imac_zbb, data2 deployment contract",
        ));
    }
    Ok(())
}

fn validate_typed_semantics(record: &VerifiedLoweringRecord) -> Result<(), CheckerError> {
    let typed = &record.typed_semantics;
    if typed.schema != TYPED_SEMANTICS_SCHEMA
        || typed.version != TYPED_SEMANTICS_VERSION
        || typed.module != record.module
        || typed.interface_hash.is_empty()
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2419TypedSemanticsInvalid,
            "typed semantic record has an invalid schema, module, or interface identity",
        ));
    }
    ensure_sorted_unique(&typed.types, |item| item.name.as_str(), "typed type")?;
    ensure_sorted_unique(&typed.entries, |item| item.id.as_str(), "typed entry")?;
    ensure_sorted_unique(&typed.instantiations, |item| item.identity.as_str(), "typed instantiation")?;
    if typed.trusted_external_verifiers.len() > 1_024 {
        return typed_error("trusted external verifier record count exceeds 1024");
    }
    if typed.trusted_external_verifiers.windows(2).any(|pair| {
        (&pair[0].scope, &pair[0].operation, &pair[0].adapter, &pair[0].code_hash, &pair[0].name)
            >= (&pair[1].scope, &pair[1].operation, &pair[1].adapter, &pair[1].code_hash, &pair[1].name)
    }) {
        return typed_error("trusted external verifier records are not strictly sorted and unique");
    }
    validate_semantic_foundation(typed, record)?;
    let lowering_entries = record.entries.iter().map(|entry| (entry.id.as_str(), entry)).collect::<BTreeMap<_, _>>();
    let typed_types = typed.types.iter().map(|ty| (ty.name.as_str(), ty)).collect::<BTreeMap<_, _>>();
    let typed_entries_by_name = typed.entries.iter().map(|entry| (entry.name.as_str(), entry)).collect::<BTreeMap<_, _>>();
    let called_targets = typed
        .entries
        .iter()
        .flat_map(|entry| entry.blocks.iter())
        .flat_map(|block| block.operations.iter())
        .filter_map(|operation| operation.call.as_ref())
        .map(|call| call.target.as_str())
        .collect::<BTreeSet<_>>();
    let proof_ids = record.proof_records.iter().map(|proof| proof.id.as_str()).collect::<BTreeSet<_>>();
    validate_trusted_external_verifiers(typed, record)?;
    for ty in &typed.types {
        validate_typed_type(ty)?;
    }
    for instantiation in &typed.instantiations {
        if instantiation.identity.is_empty()
            || instantiation.module.is_empty()
            || instantiation.template.is_empty()
            || instantiation.type_arguments.is_empty()
            || !instantiation.constraints_verified
            || !matches!(instantiation.kind.as_str(), "struct" | "enum" | "function")
            || instantiation.value_ability_registry_version != 1
            || !instantiation.identity_includes_phantom_arguments
            || instantiation.cell_backed_layout_rejected != instantiation.fixed_layout_required
        {
            return typed_error(format!("generic instantiation '{}' is incomplete or unchecked", instantiation.identity));
        }
        let canonical_arguments = instantiation.type_arguments.join(",");
        let expected_concrete = format!("{}__mono__{}", instantiation.template, hex_encode(canonical_arguments.as_bytes()));
        let expected_identity = format!("{}::{}<{}>", instantiation.module, instantiation.template, canonical_arguments);
        if instantiation.concrete_name != expected_concrete || instantiation.identity != expected_identity {
            return typed_error(format!("generic instantiation '{}' has a non-canonical identity", instantiation.identity));
        }
    }
    for entry in &typed.entries {
        let Some(lowering) = lowering_entries.get(entry.id.as_str()) else {
            if entry.kind == "helper" && !called_targets.contains(entry.name.as_str()) {
                continue;
            }
            return Err(CheckerError::new(
                CheckerRejectionCode::V2420TypedMachineBindingInvalid,
                format!("typed entry '{}' has no machine lowering entry", entry.id),
            ));
        };
        if entry.name != lowering.name
            || entry.kind != lowering_entry_kind(lowering.kind)
            || canonical_abi_type(&entry.return_type) != canonical_abi_type(&lowering.return_type)
            || normalize_effect(&entry.effect) != normalize_effect(&lowering.effect)
            || entry.params.len() != lowering.params.len()
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2420TypedMachineBindingInvalid,
                format!("typed entry '{}' signature/effect differs from its machine entry", entry.id),
            ));
        }
        for (typed_param, lowered_param) in entry.params.iter().zip(&lowering.params) {
            if typed_param.index != lowered_param.index
                || typed_param.name != lowered_param.name
                || canonical_abi_type(&typed_param.ty) != canonical_abi_type(&lowered_param.ty)
            {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2420TypedMachineBindingInvalid,
                    format!("typed entry '{}' parameter {} differs from its machine ABI", entry.id, typed_param.index),
                ));
            }
        }
        let locals = entry.locals.iter().map(|local| (local.id, local)).collect::<BTreeMap<_, _>>();
        if locals.len() != entry.locals.len() || entry.locals.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return typed_error(format!("typed entry '{}' locals are not strictly ordered and unique", entry.id));
        }
        for param in &entry.params {
            if locals.get(&param.binding_id).is_none_or(|local| local.name != param.name || local.ty != param.ty) {
                return typed_error(format!("typed entry '{}' parameter '{}' has no matching local", entry.id, param.name));
            }
        }
        let block_ids = entry.blocks.iter().map(|block| block.id).collect::<BTreeSet<_>>();
        if block_ids.len() != entry.blocks.len() || entry.blocks.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return typed_error(format!("typed entry '{}' blocks are not strictly ordered and unique", entry.id));
        }
        if !block_ids.contains(&entry.entry_block) {
            return typed_error(format!("typed entry '{}' references a missing entry block", entry.id));
        }
        for block in &entry.blocks {
            if block.successors.iter().any(|successor| !block_ids.contains(successor)) {
                return typed_error(format!("typed entry '{}' block {} references a missing successor", entry.id, block.id));
            }
            for (index, operation) in block.operations.iter().enumerate() {
                if operation.index != u32::try_from(index).unwrap_or(u32::MAX) {
                    return typed_error(format!("typed entry '{}' block {} has non-canonical operation indices", entry.id, block.id));
                }
                for destination in &operation.destinations {
                    if !locals.contains_key(destination) {
                        return typed_error(format!("typed operation '{}' defines unknown local {}", operation.opcode, destination));
                    }
                }
                for operand in &operation.operands {
                    if operand.ty.is_empty()
                        || (operand.local.is_some() == operand.constant.is_some())
                        || operand.local.is_some_and(|local_id| locals.get(&local_id).is_none_or(|local| local.ty != operand.ty))
                        || operand.constant.as_ref().is_some_and(|constant| constant_type(constant).is_none_or(|ty| ty != operand.ty))
                    {
                        return typed_error(format!("typed operation '{}' uses an unknown local or wrong type", operation.opcode));
                    }
                }
                validate_typed_operation(operation, &locals, &typed_types, &typed_entries_by_name, entry, block)?;
                if let Some(call) = &operation.call
                    && (call.target.is_empty()
                        || call.contract.is_empty()
                        || call.params.len() != operation.operands.len()
                        || call
                            .params
                            .iter()
                            .zip(&operation.operands)
                            .any(|(param, operand)| !typed_call_operand_matches(entry, param, operand)))
                {
                    return typed_error(format!("typed call '{}' has an invalid signature contract", call.target));
                }
                if let Some(call) = &operation.call {
                    match operation.destinations.as_slice() {
                        [] if call.return_type != "unit" => {
                            return typed_error(format!("typed call '{}' discards a non-unit return value", call.target));
                        }
                        [destination] if locals.get(destination).is_none_or(|local| local.ty != call.return_type) => {
                            return typed_error(format!("typed call '{}' return type differs from its destination", call.target));
                        }
                        destinations if destinations.len() > 1 => {
                            return typed_error(format!("typed call '{}' has multiple destinations", call.target));
                        }
                        _ => {}
                    }
                }
            }
        }
        validate_typed_cfg_and_dataflow(entry, &locals)?;
        validate_typed_effect(entry)?;
        for borrow in &entry.borrows {
            let root_matches =
                locals.values().any(|local| local.name == borrow.root && strip_reference(&local.ty) == borrow.root_type);
            let binding_matches = locals.values().any(|local| local.name == borrow.binding && local.ty == borrow.view_type);
            let path_type = typed_borrow_path_type(&borrow.root_type, &borrow.path, &typed_types);
            let start_valid = entry
                .blocks
                .iter()
                .find(|block| block.id == borrow.start_block)
                .is_some_and(|block| usize::try_from(borrow.start_operation).is_ok_and(|index| index <= block.operations.len()));
            let end_valid = match (borrow.end_block, borrow.end_operation) {
                (Some(block_id), Some(operation)) => entry
                    .blocks
                    .iter()
                    .find(|block| block.id == block_id)
                    .is_some_and(|block| usize::try_from(operation).is_ok_and(|index| index <= block.operations.len())),
                (None, None) => true,
                _ => false,
            };
            if borrow.root.is_empty()
                || borrow.binding.is_empty()
                || borrow.root_type.is_empty()
                || !borrow.view_type.starts_with('&')
                || borrow.escapes
                || !root_matches
                || !binding_matches
                || path_type.as_deref() != Some(strip_reference(&borrow.view_type))
                || !start_valid
                || !end_valid
            {
                return typed_error(format!("typed borrow '{} -> {}' is invalid or escaping", borrow.root, borrow.binding));
            }
        }
        for ownership in &entry.ownership {
            let valid = match ownership.operation.as_str() {
                "read_ref" | "mutate" => ownership.initial_state == "available" && ownership.final_state == "available",
                "consume" => ownership.initial_state == "available" && ownership.final_state == "consumed",
                "input" => ownership.initial_state == "available" && ownership.final_state == "consumed",
                "destroy" => ownership.initial_state == "available" && ownership.final_state == "destroyed",
                "transfer" => {
                    (ownership.initial_state == "available" && ownership.final_state == "transferred")
                        || (ownership.initial_state == "unbound" && ownership.final_state == "available")
                }
                "replace_unique" => {
                    (ownership.initial_state == "available" && ownership.final_state == "replaced")
                        || (ownership.initial_state == "unbound" && ownership.final_state == "available")
                }
                "claim" => {
                    (ownership.initial_state == "available" && ownership.final_state == "claimed")
                        || (ownership.initial_state == "unbound" && ownership.final_state == "available")
                }
                "settle" => {
                    (ownership.initial_state == "available" && ownership.final_state == "settled")
                        || (ownership.initial_state == "unbound" && ownership.final_state == "available")
                }
                "create" | "create_unique" | "output" => ownership.initial_state == "unbound" && ownership.final_state == "available",
                _ => false,
            };
            if !valid || ownership.binding.is_empty() || ownership.ty.is_empty() {
                return typed_error(format!("typed ownership transition for '{}' is invalid", ownership.binding));
            }
        }
        if entry.obligations.iter().any(|obligation| !proof_ids.contains(obligation.as_str())) {
            return typed_error(format!("typed entry '{}' references an undischarged obligation", entry.id));
        }
        validate_ownership_bindings(entry, &locals)?;

        if lowering.typed_blocks.len() != entry.blocks.len() || lowering.typed_blocks.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2420TypedMachineBindingInvalid,
                format!("typed entry '{}' does not have one canonical lowering binding per typed block", entry.id),
            ));
        }
        for typed_block in &entry.blocks {
            let expected_hash = canonical_hash("cellscript-typed-block-v1", typed_block)?;
            let mapped = record
                .blocks
                .iter()
                .filter(|block| block.owner_entry == entry.id && block.lowering_block_id == Some(typed_block.id))
                .collect::<Vec<_>>();
            let Some(binding) = lowering.typed_blocks.iter().find(|binding| binding.id == typed_block.id) else {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2420TypedMachineBindingInvalid,
                    format!("typed entry '{}' block {} has no lowering binding", entry.id, typed_block.id),
                ));
            };
            let mapped_ids = mapped.iter().map(|block| block.id.as_str()).collect::<Vec<_>>();
            if binding.hash != expected_hash
                || binding.machine_block_ids.iter().map(String::as_str).ne(mapped_ids)
                || mapped.iter().any(|block| block.typed_block_hash.as_deref() != Some(expected_hash.as_str()))
            {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2420TypedMachineBindingInvalid,
                    format!("typed entry '{}' block {} has an invalid machine lowering binding", entry.id, typed_block.id),
                ));
            }
        }
    }
    Ok(())
}

fn validate_trusted_external_verifiers(typed: &TypedSemanticRecord, lowering: &VerifiedLoweringRecord) -> Result<(), CheckerError> {
    let binding_for_delegate =
        |block: &crate::schema::TypedSemanticBlock, delegate_index: usize| -> Option<(&'static str, &'static str, String)> {
            let [source_operation, hash_operation, delegate_operation] =
                block.operations.get(delegate_index.checked_sub(2)?..=delegate_index)?
            else {
                return None;
            };
            let source_call = source_operation.call.as_ref()?;
            let hash_call = hash_operation.call.as_ref()?;
            let delegate_call = delegate_operation.call.as_ref()?;
            let source_local = *source_operation.destinations.as_slice().first()?;
            if source_operation.destinations.len() != 1
                || source_call.target != "__ckb_source_cell_dep"
                || hash_call.target != "__ckb_require_cell_data_hash"
                || hash_operation.operands.first()?.local != Some(source_local)
                || source_operation.operands.first()? != delegate_operation.operands.first()?
            {
                return None;
            }
            let (operation, adapter) = match delegate_call.target.as_str() {
                "__ckb_exec_cell_dep_u8_args" => ("exec", "u8-args-v1"),
                "__ckb_exec_cell_dep_hex4" => ("exec", "hex4-v1"),
                "__ckb_spawn_wait_cell_dep_hex4" => ("spawn-wait", "hex4-v1"),
                _ => return None,
            };
            let hash = match hash_operation.operands.get(1)?.constant.as_ref()? {
                TypedSemanticConstant::Hash(hash) => hash.clone(),
                _ => return None,
            };
            Some((operation, adapter, hash))
        };

    for verifier in &typed.trusted_external_verifiers {
        let canonical_hash = verifier.code_hash.len() == 64
            && verifier.code_hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if verifier.schema != "cellscript-trusted-external-verifier-v1"
            || verifier.version != 1
            || verifier.name.trim().is_empty()
            || verifier.scope.trim().is_empty()
            || !matches!(verifier.operation.as_str(), "exec" | "spawn-wait")
            || !matches!(
                (verifier.operation.as_str(), verifier.adapter.as_str()),
                ("exec", "u8-args-v1" | "hex4-v1") | ("spawn-wait", "hex4-v1")
            )
            || !canonical_hash
            || verifier.hash_type != "data"
            || verifier.source_identity.trim().is_empty()
            || verifier.source_identity.len() > 4_096
            || verifier.applicability.trim().is_empty()
            || verifier.applicability.len() > 4_096
            || verifier.trust_basis.trim().is_empty()
            || verifier.trust_basis.len() > 4_096
            || verifier.name.len() > 4_096
            || verifier.scope.len() > 4_096
            || verifier.guarantees.is_empty()
            || verifier.guarantees.len() > 64
            || verifier.guarantees.iter().any(|item| item.trim().is_empty() || item.len() > 4_096)
            || !verifier.guarantees.windows(2).all(|pair| pair[0] < pair[1])
            || verifier.identity_binding != "runtime-load-cell-data-hash-before-delegation-v1"
            || verifier.evidence_tier != "trusted-external"
            || verifier.compiler_proves_internal_semantics
        {
            return typed_error(format!("trusted external verifier '{}' has an invalid or overstated trust record", verifier.name));
        }
        let Some(entry) = typed.entries.iter().find(|entry| entry.id == verifier.scope) else {
            return typed_error(format!(
                "trusted external verifier '{}' references missing scope '{}'",
                verifier.name, verifier.scope
            ));
        };
        let sequence_bound = entry.blocks.iter().any(|block| {
            block.operations.iter().enumerate().any(|(index, _)| {
                binding_for_delegate(block, index).is_some_and(|(operation, adapter, hash)| {
                    operation == verifier.operation && adapter == verifier.adapter && hash == verifier.code_hash
                })
            })
        });
        let (feature, category) = if verifier.operation == "exec" {
            ("exec-target-and-replaced-continuation", "exec-delegation")
        } else {
            ("spawn-target-and-checked-child-exit", "spawn-delegation")
        };
        let proof_bound = lowering.proof_records.iter().any(|proof| {
            proof.entry_id == verifier.scope
                && proof.evidence_tier == "trusted-external"
                && proof.obligation == format!("{feature}:{category}:trusted-external")
        });
        if !sequence_bound || !proof_bound {
            return typed_error(format!(
                "trusted external verifier '{}' is not jointly bound to an exact data-hash check, delegated call, and trusted-external ProofPlan",
                verifier.name
            ));
        }
    }
    for entry in &typed.entries {
        let declared = typed.trusted_external_verifiers.iter().filter(|verifier| verifier.scope == entry.id).collect::<Vec<_>>();
        if declared.is_empty() {
            continue;
        }
        for block in &entry.blocks {
            for (index, operation) in block.operations.iter().enumerate() {
                let Some(call) = operation.call.as_ref() else { continue };
                if !matches!(
                    call.target.as_str(),
                    "__ckb_exec_cell_dep_u8_args" | "__ckb_exec_cell_dep_hex4" | "__ckb_spawn_wait_cell_dep_hex4"
                ) {
                    continue;
                }
                let Some((delegation, adapter, hash)) = binding_for_delegate(block, index) else {
                    return typed_error(format!(
                        "typed entry '{}' contains delegated execution outside the required source/hash/delegate sequence",
                        entry.id
                    ));
                };
                if !declared
                    .iter()
                    .any(|verifier| verifier.operation == delegation && verifier.adapter == adapter && verifier.code_hash == hash)
                {
                    return typed_error(format!(
                        "typed entry '{}' delegates to an identity absent from its trusted external verifier records",
                        entry.id
                    ));
                }
            }
        }
    }
    let trusted_proof_count = lowering.proof_records.iter().filter(|proof| proof.evidence_tier == "trusted-external").count();
    if typed.trusted_external_verifiers.is_empty() != (trusted_proof_count == 0) {
        return typed_error("trusted-external ProofPlan evidence and typed verifier records do not agree");
    }
    Ok(())
}

fn validate_semantic_foundation(typed: &TypedSemanticRecord, record: &VerifiedLoweringRecord) -> Result<(), CheckerError> {
    crate::bindings::validate(typed)?;
    let foundation = &typed.foundation;
    if foundation.schema != SEMANTIC_FOUNDATION_SCHEMA
        || foundation.version != SEMANTIC_FOUNDATION_VERSION
        || foundation.provenance.schema != PROVENANCE_GRAPH_SCHEMA
        || foundation.provenance.version != PROVENANCE_GRAPH_VERSION
    {
        return typed_error("semantic foundation or provenance DAG uses an unsupported schema".to_string());
    }
    if foundation.provenance.nodes.len() > 65_536 || foundation.provenance.bindings.len() > 262_144 {
        return typed_error("semantic foundation provenance DAG exceeds its bounded contract".to_string());
    }
    ensure_sorted_unique(&foundation.provenance.nodes, |node| node.id.as_str(), "provenance node")?;
    let node_ids = foundation.provenance.nodes.iter().map(|node| node.id.as_str()).collect::<BTreeSet<_>>();
    for node in &foundation.provenance.nodes {
        if node.id != canonical_hash("cellscript-value-provenance-node-v1", &node.provenance)? {
            return typed_error(format!("provenance node '{}' does not match its canonical contents", node.id));
        }
        if let ValueProvenance::Derived { operation, inputs } = &node.provenance
            && (operation.is_empty() || inputs.iter().any(|input| input == &node.id || !node_ids.contains(input.as_str())))
        {
            return typed_error(format!("derived provenance node '{}' has an invalid operation or input", node.id));
        }
    }
    let root_node_ids = foundation
        .provenance
        .nodes
        .iter()
        .filter(|node| !matches!(node.provenance, ValueProvenance::Derived { .. }))
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    validate_provenance_acyclic(&foundation.provenance.nodes)?;
    let entry_locals = typed
        .entries
        .iter()
        .flat_map(|entry| entry.locals.iter().map(move |local| ((entry.id.as_str(), local.id), local)))
        .collect::<BTreeMap<_, _>>();
    let required_locals =
        typed
            .entries
            .iter()
            .flat_map(|entry| {
                let entry_id = entry.id.as_str();
                entry.params.iter().map(move |param| (entry_id, param.binding_id)).chain(entry.blocks.iter().flat_map(move |block| {
                    block.operations.iter().flat_map(move |operation| {
                        operation.destinations.iter().copied().map(move |local_id| (entry_id, local_id)).chain(
                            operation.operands.iter().filter_map(move |operand| operand.local.map(|local_id| (entry_id, local_id))),
                        )
                    })
                }))
            })
            .collect::<BTreeSet<_>>();
    let mut bound_locals = BTreeSet::new();
    let mut previous_binding = None::<(&str, u32, &str)>;
    for binding in &foundation.provenance.bindings {
        let key = (binding.entry_id.as_str(), binding.local_id, binding.node_id.as_str());
        if previous_binding.is_some_and(|previous| previous >= key)
            || !node_ids.contains(binding.node_id.as_str())
            || !entry_locals.contains_key(&(binding.entry_id.as_str(), binding.local_id))
        {
            return typed_error("provenance bindings are not canonical or reference unknown typed locals".to_string());
        }
        bound_locals.insert((binding.entry_id.as_str(), binding.local_id));
        previous_binding = Some(key);
    }
    if !required_locals.is_subset(&bound_locals) {
        let missing = required_locals.difference(&bound_locals).map(|(entry, local)| format!("{entry}:{local}")).collect::<Vec<_>>();
        return typed_error(format!(
            "not every value-bearing typed local has at least one provenance binding: {}",
            missing.join(", ")
        ));
    }

    let contract = &foundation.entry_contract;
    let dispatch_label = match &contract.dispatch {
        EntryDispatchContract::SingleEntry => "single-entry",
        EntryDispatchContract::PolicyWitnessV1(policy) => {
            crate::policy::validate_policy_contract(policy, typed)?;
            if contract.script_role != "type"
                || contract.trigger != format!("type-group<{}>", policy.resource)
                || contract.exact_entry != "wrapper:_cellscript_entry"
                || contract.entry_payload_abi != crate::POLICY_PAYLOAD_ABI
                || contract.witness_placement_abi != crate::POLICY_PLACEMENT_ABI
                || contract.witness_placement_field != "input_type"
                || contract.witness_placement_source != crate::POLICY_WITNESS_SOURCE
                || !record.entries.iter().any(|entry| entry.id == contract.exact_entry && entry.kind == EntryKind::Wrapper)
            {
                return typed_error("policy dispatch entry does not bind its Type wrapper and witness ABI".to_string());
            }
            "policy-witness-v1"
        }
        EntryDispatchContract::ExplicitVersionedDispatch { selector_node_id, selector_type, variants, unknown_selector } => {
            if !root_node_ids.contains(selector_node_id.as_str())
                || selector_type.is_empty()
                || variants.is_empty()
                || unknown_selector != "reject"
                || variants.windows(2).any(|pair| (&pair[0].tag, &pair[0].entry_id) >= (&pair[1].tag, &pair[1].entry_id))
                || variants
                    .iter()
                    .any(|variant| !typed.entries.iter().any(|entry| entry.id == variant.entry_id) || variant.tag.is_empty())
            {
                return typed_error("explicit entry dispatch contract is incomplete or non-canonical".to_string());
            }
            "explicit-versioned-dispatch"
        }
    };
    let expected_contract_node = if matches!(contract.dispatch, EntryDispatchContract::PolicyWitnessV1(_)) {
        canonical_hash(
            "cellscript-semantic-node-entry-contract-v2",
            &(
                contract.script_role.as_str(),
                contract.trigger.as_str(),
                contract.exact_entry.as_str(),
                &contract.dispatch,
                contract.entry_payload_abi.as_str(),
                contract.witness_placement_abi.as_str(),
                contract.witness_placement_field.as_str(),
                contract.witness_placement_source.as_str(),
            ),
        )?
    } else {
        canonical_hash(
            "cellscript-semantic-node-entry-contract-v1",
            &(
                contract.script_role.as_str(),
                contract.trigger.as_str(),
                contract.exact_entry.as_str(),
                dispatch_label,
                contract.entry_payload_abi.as_str(),
                contract.witness_placement_abi.as_str(),
                contract.witness_placement_field.as_str(),
                contract.witness_placement_source.as_str(),
            ),
        )?
    };
    let trigger_valid = match contract.script_role.as_str() {
        "type" => {
            contract.trigger == "type-group"
                || contract
                    .trigger
                    .strip_prefix("type-group<")
                    .and_then(|trigger| trigger.strip_suffix('>'))
                    .is_some_and(|trigger| !trigger.is_empty())
        }
        "lock" => contract.trigger == "lock-group",
        "none" => contract.trigger == "none",
        _ => false,
    };
    if contract.semantic_node_id != expected_contract_node
        || !trigger_valid
        || (contract.exact_entry != "none"
            && !matches!(contract.dispatch, EntryDispatchContract::PolicyWitnessV1(_))
            && !typed.entries.iter().any(|entry| entry.id == contract.exact_entry))
        || contract.entry_payload_abi.is_empty()
        || contract.witness_placement_abi.is_empty()
        || contract.witness_placement_field.is_empty()
        || contract.witness_placement_source.is_empty()
    {
        return typed_error("artifact entry-selection contract is invalid".to_string());
    }

    ensure_sorted_unique(&foundation.roles, |role| role.role_id.as_str(), "semantic role")?;
    let role_ids = foundation.roles.iter().map(|role| role.role_id.as_str()).collect::<BTreeSet<_>>();
    let typed_types = typed.types.iter().map(|ty| (ty.name.as_str(), ty)).collect::<BTreeMap<_, _>>();
    for role in &foundation.roles {
        let expected_node = canonical_hash(
            "cellscript-semantic-node-role-v1",
            &(
                role.role_id.as_str(),
                role.entry_id.as_str(),
                role.binding.as_str(),
                role.ty.as_str(),
                role.direction.as_str(),
                role.source.as_str(),
                role.selector.as_str(),
                role.cardinality.as_str(),
                role.lock_or_type_role.as_str(),
                role.script_identity_policy.as_str(),
                role.schema_identity.as_str(),
                role.correspondence_policy.as_str(),
            ),
        )?;
        let schema_type = role.ty.strip_prefix('&').map(str::trim).unwrap_or(role.ty.as_str());
        let schema_type = bounded_collection_element(schema_type).unwrap_or(schema_type);
        if role.semantic_node_id != expected_node
            || !typed.entries.iter().any(|entry| entry.id == role.entry_id)
            || role.binding.is_empty()
            || !matches!(role.direction.as_str(), "input" | "output" | "read-only-dependency")
            || role.locality != "local"
            || role.selector.is_empty()
            || role.cardinality.is_empty()
            || !matches!(role.lock_or_type_role.as_str(), "lock" | "type")
            || typed_types.get(schema_type).is_none_or(|layout| layout.layout_hash != role.schema_identity)
        {
            return typed_error(format!("semantic role '{}' is incomplete or not schema-bound", role.role_id));
        }
    }

    ensure_sorted_unique(&foundation.dispositions, |item| item.id.as_str(), "Cell disposition")?;
    let mut disposed_roles = BTreeSet::new();
    for disposition in &foundation.dispositions {
        let expected_node = canonical_hash(
            "cellscript-semantic-node-disposition-v1",
            &(
                disposition.id.as_str(),
                disposition.entry_id.as_str(),
                disposition.input_role.as_deref(),
                disposition.output_role.as_deref(),
                &disposition.input,
                &disposition.output,
                &disposition.envelope,
                disposition.enforcement.as_str(),
            ),
        )?;
        let input_shape_valid = match &disposition.input {
            None => true,
            Some(InputDisposition::Successor { output_role }) => !output_role.is_empty(),
            Some(InputDisposition::Pooled { pool_id, accounting_obligation }) => {
                !pool_id.is_empty() && !accounting_obligation.is_empty()
            }
            Some(InputDisposition::Retired { absence_policy }) => !absence_policy.is_empty(),
            Some(InputDisposition::AuthorizationOnly { disposition_owner }) => !disposition_owner.is_empty(),
            Some(InputDisposition::LegacyConsumed { operation, migration }) => !operation.is_empty() && !migration.is_empty(),
        };
        let output_shape_valid = match &disposition.output {
            None => true,
            Some(OutputOrigin::SuccessorOf { input_role }) => !input_role.is_empty(),
            Some(OutputOrigin::Fresh { identity_policy }) => !identity_policy.is_empty(),
            Some(OutputOrigin::PoolResult { pool_id, accounting_obligation }) => {
                !pool_id.is_empty() && !accounting_obligation.is_empty()
            }
            Some(OutputOrigin::LegacyCreated { operation }) => !operation.is_empty(),
        };
        let schema_role = disposition
            .output_role
            .as_ref()
            .or(disposition.input_role.as_ref())
            .and_then(|role_id| foundation.roles.iter().find(|role| &role.role_id == role_id));
        let exhaustive_fields_valid = schema_role.is_none_or(|role| {
            let schema_type = role.ty.strip_prefix('&').map(str::trim).unwrap_or(role.ty.as_str());
            let schema_type = bounded_collection_element(schema_type).unwrap_or(schema_type);
            let expected = typed_types
                .get(schema_type)
                .map(|layout| layout.fields.iter().map(|field| field.name.as_str()).collect::<BTreeSet<_>>())
                .unwrap_or_default();
            let actual = disposition.envelope.data_fields.iter().map(|field| field.field.as_str()).collect::<BTreeSet<_>>();
            disposition.envelope.completeness != "exhaustive" || actual == expected
        });
        if disposition.semantic_node_id != expected_node
            || !typed.entries.iter().any(|entry| entry.id == disposition.entry_id)
            || !input_shape_valid
            || !output_shape_valid
            || !exhaustive_fields_valid
            || disposition.input_role.is_none() != disposition.input.is_none()
            || disposition.output_role.is_none() != disposition.output.is_none()
            || disposition
                .input_role
                .iter()
                .chain(disposition.output_role.iter())
                .any(|role| !role_ids.contains(role.as_str()) || !disposed_roles.insert(role.as_str()))
            || disposition.envelope.completeness.is_empty()
            || disposition.envelope.logical_identity.is_empty()
            || disposition.envelope.lock_script.is_empty()
            || disposition.envelope.type_script.is_empty()
            || disposition.envelope.capacity.is_empty()
            || disposition.envelope.cardinality.is_empty()
            || disposition.envelope.correspondence.is_empty()
            || disposition.envelope.data_fields.windows(2).any(|pair| pair[0].field >= pair[1].field)
            || disposition.envelope.data_fields.iter().any(|field| field.field.is_empty() || field.treatment.is_empty())
            || !matches!(
                disposition.enforcement.as_str(),
                "checked-static"
                    | "checked-runtime"
                    | "trusted-external"
                    | "runtime-helper-required"
                    | "builder-evidence-required"
                    | "metadata-only"
                    | "chain-evidence-required"
            )
        {
            return typed_error(format!("Cell disposition '{}' is incomplete, duplicated, or malformed", disposition.id));
        }
        match (&disposition.input, &disposition.output) {
            (Some(InputDisposition::Successor { output_role }), Some(OutputOrigin::SuccessorOf { input_role }))
                if disposition.output_role.as_deref() == Some(output_role)
                    && disposition.input_role.as_deref() == Some(input_role) => {}
            (Some(InputDisposition::Successor { .. }), _) | (_, Some(OutputOrigin::SuccessorOf { .. })) => {
                return typed_error(format!("successor disposition '{}' is not bidirectionally linked", disposition.id));
            }
            _ => {}
        }
    }
    for role in &foundation.roles {
        if role.direction != "read-only-dependency" && !disposed_roles.contains(role.role_id.as_str()) {
            return typed_error(format!("Cell role '{}' has no exhaustive disposition record", role.role_id));
        }
    }
    let mut pooled_inputs = BTreeMap::new();
    let mut pooled_outputs = BTreeMap::new();
    for disposition in &foundation.dispositions {
        if let Some(InputDisposition::Pooled { pool_id, accounting_obligation }) = &disposition.input {
            if !valid_pool_accounting_contract(pool_id, accounting_obligation) {
                return typed_error(format!("pooled input '{}' has a malformed accounting contract", pool_id));
            }
            if pooled_inputs
                .insert(pool_id.as_str(), accounting_obligation.as_str())
                .is_some_and(|existing| existing != accounting_obligation.as_str())
            {
                return typed_error(format!("pooled input '{}' changes its accounting obligation", pool_id));
            }
        }
        if let Some(OutputOrigin::PoolResult { pool_id, accounting_obligation }) = &disposition.output {
            if !valid_pool_accounting_contract(pool_id, accounting_obligation) {
                return typed_error(format!("pooled output '{}' has a malformed accounting contract", pool_id));
            }
            if pooled_outputs
                .insert(pool_id.as_str(), accounting_obligation.as_str())
                .is_some_and(|existing| existing != accounting_obligation.as_str())
            {
                return typed_error(format!("pooled output '{}' changes its accounting obligation", pool_id));
            }
        }
    }
    if pooled_inputs != pooled_outputs {
        return typed_error("pooled dispositions must have matching input/output pools and accounting obligations");
    }

    ensure_sorted_unique(&foundation.claims, |claim| claim.id.as_str(), "semantic claim")?;
    for claim in &foundation.claims {
        let expected_node = canonical_hash(
            "cellscript-semantic-node-claim-v1",
            &(
                claim.id.as_str(),
                claim.entry_id.as_str(),
                claim.category.as_str(),
                claim.statement.as_str(),
                claim.enforcement.as_str(),
                claim.on_chain_checked,
                claim.evidence_reference.as_str(),
                &claim.execution,
            ),
        )?;
        let evidence_valid = match &claim.execution {
            Some(execution) => validate_claim_execution(claim, execution, typed, foundation),
            None if claim.category == "audit" => {
                let prefix = "expected external policy evidence for ";
                claim.enforcement == "metadata-only"
                    && !claim.on_chain_checked
                    && claim.evidence_reference == "audit:external-policy"
                    && claim.statement.starts_with(prefix)
                    && claim.statement.len() > prefix.len()
            }
            None => claim.evidence_reference.starts_with("proof-plan:") && claim.evidence_reference.len() > "proof-plan:".len(),
        };
        if claim.semantic_node_id != expected_node
            || !typed.entries.iter().any(|entry| entry.id == claim.entry_id)
            || claim.category.is_empty()
            || claim.statement.is_empty()
            || claim.evidence_reference.is_empty()
            || !evidence_valid
            || !matches!(
                claim.enforcement.as_str(),
                "checked-static"
                    | "checked-runtime"
                    | "trusted-external"
                    | "runtime-helper-required"
                    | "builder-evidence-required"
                    | "metadata-only"
                    | "chain-evidence-required"
            )
            || (claim.on_chain_checked
                && !matches!(claim.enforcement.as_str(), "checked-static" | "checked-runtime" | "trusted-external"))
        {
            return typed_error(format!("semantic claim '{}' has an invalid enforcement classification", claim.id));
        }
    }

    ensure_sorted_unique(&foundation.legacy_nodes, |legacy| legacy.id.as_str(), "legacy semantic node")?;
    for legacy in &foundation.legacy_nodes {
        let expected_node = canonical_hash(
            "cellscript-semantic-node-legacy-v1",
            &(legacy.id.as_str(), legacy.kind.as_str(), legacy.meaning.as_str(), legacy.migration.as_str()),
        )?;
        if legacy.semantic_node_id != expected_node
            || legacy.kind.is_empty()
            || legacy.meaning.is_empty()
            || legacy.migration.is_empty()
        {
            return typed_error(format!("legacy semantic node '{}' is incomplete", legacy.id));
        }
    }

    let core_semantic_id = canonical_hash(
        "cellscript-core-semantic-id-v2",
        &(
            typed.failure_semantics,
            &typed.types,
            &foundation.roles,
            &foundation.dispositions,
            &foundation.claims,
            &foundation.legacy_nodes,
        ),
    )?;
    let provenance_roots = foundation
        .provenance
        .nodes
        .iter()
        .filter(|node| !matches!(node.provenance, ValueProvenance::Derived { .. }))
        .map(|node| node.id.as_str())
        .collect::<Vec<_>>();
    let entry_contract_id = canonical_hash(
        "cellscript-entry-contract-id-v1",
        &(
            core_semantic_id.as_str(),
            &foundation.entry_contract,
            provenance_roots,
            foundation.entry_contract.entry_payload_abi.as_str(),
            foundation.entry_contract.witness_placement_abi.as_str(),
        ),
    )?;
    let artifact_contract_id =
        canonical_hash("cellscript-artifact-contract-id-v1", &(entry_contract_id.as_str(), &foundation.artifact_contract))?;
    if foundation.identities.core_semantic_id != core_semantic_id
        || foundation.identities.entry_contract_id != entry_contract_id
        || foundation.identities.artifact_contract_id != artifact_contract_id
        || foundation.artifact_contract.target_profile != record.target_profile
        || foundation.artifact_contract.artifact_format != record.artifact_format
        || foundation.artifact_contract.lowering_record_schema != LOWERING_RECORD_SCHEMA
        || foundation.artifact_contract.typed_semantics_schema != TYPED_SEMANTICS_SCHEMA
    {
        return typed_error("layered semantic identities do not match their canonical projections".to_string());
    }
    Ok(())
}

fn valid_pool_accounting_contract(pool_id: &str, accounting_obligation: &str) -> bool {
    let pool_parts = pool_id.split(':').collect::<Vec<_>>();
    if pool_parts.len() != 3 || pool_parts[0] != "pool" || pool_parts[1..].iter().any(|part| part.is_empty()) {
        return false;
    }
    let prefix = "checked-u128-field-sum-equality:";
    accounting_obligation.split('+').all(|obligation| obligation.strip_prefix(prefix).is_some_and(|field| !field.is_empty()))
}

fn validate_claim_execution(
    claim: &SemanticClaim,
    execution: &ClaimExecutionBinding,
    typed: &TypedSemanticRecord,
    foundation: &SemanticFoundationRecord,
) -> bool {
    if claim.category != "entry-condition"
        || claim.enforcement != "checked-runtime"
        || !claim.on_chain_checked
        || !claim.statement.starts_with("require ")
        || claim.evidence_reference != format!("typed-entry:{}:block:{}:branch-condition", claim.entry_id, execution.condition_block)
    {
        return false;
    }
    let Some(entry) = typed.entries.iter().find(|entry| entry.id == claim.entry_id) else {
        return false;
    };
    let Some(condition_block) = entry.blocks.iter().find(|block| block.id == execution.condition_block) else {
        return false;
    };
    let Some(success_block) = entry.blocks.iter().find(|block| block.id == execution.success_block) else {
        return false;
    };
    let Some(failure_block) = entry.blocks.iter().find(|block| block.id == execution.failure_block) else {
        return false;
    };
    if condition_block.terminator != "branch"
        || condition_block.successors != [execution.success_block, execution.failure_block]
        || success_block.id == failure_block.id
        || failure_block.terminator != "verifier-failure"
        || failure_block
            .runtime_error
            .as_ref()
            .is_none_or(|error| error.code != execution.failure_error_code || error.name != "assertion-failed")
    {
        return false;
    }
    let Some(condition) = condition_block
        .operations
        .iter()
        .rev()
        .find(|operation| operation.opcode == "branch-condition")
        .and_then(|operation| operation.operands.as_slice().first().filter(|_| operation.operands.len() == 1))
    else {
        return false;
    };
    let node_matches = if let Some(local_id) = condition.local {
        foundation.provenance.bindings.iter().any(|binding| {
            binding.entry_id == claim.entry_id && binding.local_id == local_id && binding.node_id == execution.condition_node_id
        })
    } else if let Some(constant) = &condition.constant {
        canonical_hash("cellscript-value-provenance-node-v1", &ValueProvenance::Constant { declaration: format!("{constant:?}") })
            .is_ok_and(|node_id| node_id == execution.condition_node_id)
    } else {
        false
    };
    node_matches
        && foundation.provenance.nodes.iter().any(|node| node.id == execution.condition_node_id)
        && execution.failure_error_code != 0
}

fn validate_provenance_acyclic(nodes: &[ProvenanceNode]) -> Result<(), CheckerError> {
    let edges = nodes
        .iter()
        .map(|node| {
            let inputs = match &node.provenance {
                ValueProvenance::Derived { inputs, .. } => inputs.iter().map(String::as_str).collect(),
                _ => Vec::new(),
            };
            (node.id.as_str(), inputs)
        })
        .collect::<BTreeMap<_, Vec<_>>>();
    let mut complete = BTreeSet::new();
    for root in edges.keys() {
        let mut active = BTreeSet::new();
        let mut stack = vec![(*root, false, 0usize)];
        while let Some((node, exiting, depth)) = stack.pop() {
            if depth > 256 {
                return typed_error("provenance DAG exceeds the maximum depth of 256".to_string());
            }
            if exiting {
                active.remove(node);
                complete.insert(node);
                continue;
            }
            if complete.contains(node) {
                continue;
            }
            if !active.insert(node) {
                return typed_error(format!("provenance DAG contains a cycle at '{node}'"));
            }
            stack.push((node, true, depth));
            if let Some(inputs) = edges.get(node) {
                for input in inputs.iter().rev() {
                    stack.push((*input, false, depth + 1));
                }
            }
        }
    }
    Ok(())
}

fn bounded_collection_element(ty: &str) -> Option<&str> {
    ty.strip_prefix("BoundedCellSet<")
        .and_then(|value| value.strip_suffix('>'))
        .and_then(|value| value.rsplit_once(','))
        .map(|(element, _)| element.trim())
}

fn validate_typed_type(ty: &TypedSemanticType) -> Result<(), CheckerError> {
    if ty.name.is_empty()
        || ty.layout_hash.is_empty()
        || !matches!(ty.kind.as_str(), "resource" | "shared" | "receipt" | "struct" | "enum")
        || ty.identity_policy.is_empty()
    {
        return typed_error(format!("typed type '{}' has an invalid kind or layout identity", ty.name));
    }
    if !strictly_sorted(&ty.capabilities) && !ty.capabilities.is_empty() {
        return typed_error(format!("typed type '{}' capabilities are not canonical", ty.name));
    }
    if !matches!(ty.identity_policy.as_str(), "none" | "ckb-type-id" | "script-args" | "singleton-type")
        && !ty.identity_policy.starts_with("field:")
    {
        return typed_error(format!("typed type '{}' has an invalid identity policy", ty.name));
    }

    if ty.kind == "enum" {
        if !ty.fields.is_empty() || ty.tag_width_bytes.is_none_or(|width| width == 0) || ty.variants.is_empty() {
            return typed_error(format!("typed enum '{}' has an incomplete tagged layout", ty.name));
        }
        let mut names = BTreeSet::new();
        let mut tags = BTreeSet::new();
        for variant in &ty.variants {
            if variant.name.is_empty() || !names.insert(variant.name.as_str()) || !tags.insert(variant.tag) {
                return typed_error(format!("typed enum '{}' has duplicate or empty variants", ty.name));
            }
            for (index, field) in variant.fields.iter().enumerate() {
                if field.index != u32::try_from(index).unwrap_or(u32::MAX)
                    || field.ty.is_empty()
                    || field.width_bytes == 0
                    || ty.encoded_size.is_none_or(|size| field.offset.saturating_add(field.width_bytes) > size)
                {
                    return typed_error(format!("typed enum '{}::{}' has an invalid payload layout", ty.name, variant.name));
                }
            }
        }
    } else {
        if ty.tag_width_bytes.is_some() || !ty.variants.is_empty() {
            return typed_error(format!("non-enum typed type '{}' carries enum layout state", ty.name));
        }
        let fixed_layout = ty.encoded_size.is_some() && ty.fields.iter().all(|field| field.width_bytes.is_some());
        let mut previous_end = 0u32;
        for field in &ty.fields {
            if field.name.is_empty() || field.ty.is_empty() || (fixed_layout && field.offset < previous_end) {
                return typed_error(format!("typed type '{}' has overlapping or incomplete field layout", ty.name));
            }
            previous_end = field.offset.saturating_add(field.width_bytes.unwrap_or(0));
        }
        if fixed_layout && ty.encoded_size.is_some_and(|size| previous_end > size) {
            return typed_error(format!("typed type '{}' fields exceed its encoded size", ty.name));
        }
    }

    let expected_layout_hash = canonical_hash(
        "cellscript-typed-layout-v2",
        &(ty.kind.as_str(), ty.encoded_size, &ty.fields, ty.tag_width_bytes, &ty.variants, &ty.capabilities, &ty.identity_policy),
    )?;
    if ty.layout_hash != expected_layout_hash {
        return typed_error(format!("typed type '{}' layout hash does not match its canonical layout", ty.name));
    }
    Ok(())
}

fn lowering_entry_kind(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Action => "action",
        EntryKind::Lock => "lock",
        EntryKind::Helper => "helper",
        EntryKind::Runtime => "runtime",
        EntryKind::Wrapper => "wrapper",
    }
}

fn constant_type(constant: &TypedSemanticConstant) -> Option<String> {
    let scalar = |value: &String, max: u128, ty: &str| {
        value.parse::<u128>().ok().filter(|parsed| *parsed <= max && parsed.to_string() == *value).map(|_| ty.to_string())
    };
    match constant {
        TypedSemanticConstant::Unit => Some("unit".to_string()),
        TypedSemanticConstant::U8(value) => scalar(value, u8::MAX.into(), "u8"),
        TypedSemanticConstant::U16(value) => scalar(value, u16::MAX.into(), "u16"),
        TypedSemanticConstant::U32(value) => scalar(value, u32::MAX.into(), "u32"),
        TypedSemanticConstant::U64(value) => scalar(value, u64::MAX.into(), "u64"),
        TypedSemanticConstant::U128(value) => scalar(value, u128::MAX, "u128"),
        TypedSemanticConstant::Bool(_) => Some("bool".to_string()),
        TypedSemanticConstant::Address(value) | TypedSemanticConstant::Hash(value)
            if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Some(if matches!(constant, TypedSemanticConstant::Address(_)) { "address" } else { "hash" }.to_string())
        }
        TypedSemanticConstant::Address(_) | TypedSemanticConstant::Hash(_) => None,
        TypedSemanticConstant::Array(values) => {
            let first = match values.first() {
                Some(value) => constant_type(value)?,
                None => "unit".to_string(),
            };
            if values.iter().all(|value| constant_type(value).as_deref() == Some(first.as_str())) {
                Some(format!("[{first}; {}]", values.len()))
            } else {
                None
            }
        }
    }
}

fn validate_typed_operation(
    operation: &TypedSemanticOperation,
    locals: &BTreeMap<u32, &TypedSemanticLocal>,
    types: &BTreeMap<&str, &TypedSemanticType>,
    entries: &BTreeMap<&str, &TypedSemanticEntry>,
    entry: &TypedSemanticEntry,
    block: &TypedSemanticBlock,
) -> Result<(), CheckerError> {
    let shape =
        |destinations: usize, operands: usize| operation.destinations.len() == destinations && operation.operands.len() == operands;
    let destination_type =
        |index: usize| operation.destinations.get(index).and_then(|id| locals.get(id)).map(|local| local.ty.as_str());
    let operand_type = |index: usize| operation.operands.get(index).map(|operand| operand.ty.as_str());
    let none_detail = matches!(operation.detail, TypedSemanticOperationDetail::None);
    let fail = || typed_error(format!("typed operation '{}' has an invalid shape, detail, or type rule", operation.opcode));

    match operation.opcode.as_str() {
        "load-const" => {
            let TypedSemanticOperationDetail::Constant { value } = &operation.detail else { return fail() };
            let constant_type = constant_type(value);
            let destination_type = destination_type(0);
            let encoded_unit_enum = destination_type.and_then(|ty| types.get(ty)).is_some_and(|layout| {
                layout.kind == "enum"
                    && matches!(value, TypedSemanticConstant::U64(tag) if tag.parse::<u32>().ok().is_some_and(|tag| {
                        layout.variants.iter().any(|variant| variant.tag == tag && variant.fields.is_empty())
                    }))
            });
            let context_typed_empty_array = matches!(value, TypedSemanticConstant::Array(values) if values.is_empty())
                && destination_type.is_some_and(is_zero_length_array_type);
            if !shape(1, 0)
                || operation.call.is_some()
                || (constant_type.as_deref() != destination_type && !encoded_unit_enum && !context_typed_empty_array)
            {
                return typed_error(format!(
                    "typed load-const has an invalid shape or type: constant type {:?}, destination type {:?}",
                    constant_type, destination_type
                ));
            }
        }
        "load-var" => {
            let TypedSemanticOperationDetail::Binding { name } = &operation.detail else { return fail() };
            if !shape(1, 0) || name.is_empty() || operation.call.is_some() {
                return fail();
            }
        }
        "store-var" => {
            let TypedSemanticOperationDetail::Binding { name } = &operation.detail else { return fail() };
            if !shape(0, 1) || name.is_empty() || operation.call.is_some() {
                return fail();
            }
        }
        "binary" => {
            let TypedSemanticOperationDetail::BinaryOperator { operator } = &operation.detail else { return fail() };
            let encoded_unit_enum_comparison = matches!(operator.as_str(), "eq" | "ne")
                && destination_type(0) == Some("bool")
                && operation.operands.iter().enumerate().any(|(enum_index, operand)| {
                    let Some(layout) = types.get(operand.ty.as_str()).filter(|layout| layout.kind == "enum") else {
                        return false;
                    };
                    let Some(TypedSemanticConstant::U64(tag)) =
                        operation.operands.get(1_usize.saturating_sub(enum_index)).and_then(|operand| operand.constant.as_ref())
                    else {
                        return false;
                    };
                    tag.parse::<u32>()
                        .ok()
                        .is_some_and(|tag| layout.variants.iter().any(|variant| variant.tag == tag && variant.fields.is_empty()))
                });
            if !shape(1, 2)
                || operation.call.is_some()
                || (!validate_binary_types(operator, operand_type(0), operand_type(1), destination_type(0))
                    && !encoded_unit_enum_comparison)
            {
                return typed_error(format!(
                    "typed binary '{}' has invalid operands {:?}, {:?} or destination {:?}",
                    operator,
                    operand_type(0),
                    operand_type(1),
                    destination_type(0)
                ));
            }
        }
        "unary" => {
            let TypedSemanticOperationDetail::UnaryOperator { operator } = &operation.detail else { return fail() };
            if !shape(1, 1) || operation.call.is_some() || !validate_unary_types(operator, operand_type(0), destination_type(0)) {
                return fail();
            }
        }
        "field-access" => {
            let TypedSemanticOperationDetail::Field { name } = &operation.detail else { return fail() };
            let owner_type = operand_type(0).map(strip_reference).unwrap_or_default();
            let owner = types.get(owner_type);
            let named_field_type =
                owner.and_then(|owner| owner.fields.iter().find(|field| field.name == *name)).map(|field| field.ty.as_str());
            let tuple_field_type = tuple_field_type(owner_type, name);
            let builtin_bytes_field_type =
                (name == "0" && matches!(canonical_abi_type(owner_type).as_str(), "address" | "hash")).then_some("[u8; 32]");
            let field_type = named_field_type.or(tuple_field_type.as_deref()).or(builtin_bytes_field_type);
            if !shape(1, 1) || !optional_types_equivalent(field_type, destination_type(0)) || operation.call.is_some() {
                return fail();
            }
        }
        "index" => {
            let element = collection_element_type(operand_type(0).unwrap_or_default());
            if !shape(1, 2)
                || !none_detail
                || operation.call.is_some()
                || !is_integer_type(operand_type(1).unwrap_or_default())
                || !optional_types_equivalent(element.as_deref(), destination_type(0))
            {
                return fail();
            }
        }
        "length" | "collection-capacity" => {
            if !shape(1, 1) || !none_detail || destination_type(0) != Some("u64") || operation.call.is_some() {
                return fail();
            }
        }
        "type-hash" => {
            if !shape(1, 1) || !none_detail || destination_type(0) != Some("hash") || operation.call.is_some() {
                return fail();
            }
        }
        "collection-new" => {
            let TypedSemanticOperationDetail::Collection { declared_type } = &operation.detail else { return fail() };
            if operation.destinations.len() != 1
                || operation.operands.len() > 1
                || !declared_collection_type_matches(declared_type, destination_type(0).unwrap_or_default())
                || operation.operands.first().is_some_and(|operand| !is_integer_type(&operand.ty))
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "collection-push" | "collection-contains" => {
            let expected_destinations = usize::from(operation.opcode == "collection-contains");
            let element = collection_element_type(operand_type(0).unwrap_or_default());
            if !shape(expected_destinations, 2)
                || !none_detail
                || !optional_types_equivalent(element.as_deref(), operand_type(1))
                || (operation.opcode == "collection-contains" && destination_type(0) != Some("bool"))
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "collection-extend" => {
            let collection_element = collection_element_type(operand_type(0).unwrap_or_default());
            let slice_element = collection_element_type(operand_type(1).unwrap_or_default());
            if !shape(0, 2)
                || !none_detail
                || !optional_types_equivalent(collection_element.as_deref(), slice_element.as_deref())
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "collection-clear" | "collection-reverse" => {
            if !shape(0, 1) || !none_detail || operation.call.is_some() {
                return fail();
            }
        }
        "collection-remove" => {
            if !shape(1, 2)
                || !none_detail
                || !is_integer_type(operand_type(1).unwrap_or_default())
                || !optional_types_equivalent(
                    collection_element_type(operand_type(0).unwrap_or_default()).as_deref(),
                    destination_type(0),
                )
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "collection-insert" | "collection-set" => {
            if !shape(0, 3)
                || !none_detail
                || !is_integer_type(operand_type(1).unwrap_or_default())
                || !optional_types_equivalent(collection_element_type(operand_type(0).unwrap_or_default()).as_deref(), operand_type(2))
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "collection-pop" => {
            if !shape(1, 1)
                || !none_detail
                || !optional_types_equivalent(
                    collection_element_type(operand_type(0).unwrap_or_default()).as_deref(),
                    destination_type(0),
                )
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "collection-truncate" => {
            if !shape(0, 2) || !none_detail || !is_integer_type(operand_type(1).unwrap_or_default()) || operation.call.is_some() {
                return fail();
            }
        }
        "collection-swap" => {
            if !shape(0, 3)
                || !none_detail
                || !is_integer_type(operand_type(1).unwrap_or_default())
                || !is_integer_type(operand_type(2).unwrap_or_default())
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "bounded-cell-load" => {
            let TypedSemanticOperationDetail::Collection { declared_type } = &operation.detail else { return fail() };
            let element_type = destination_type(0).unwrap_or_default();
            let declared_contract = declared_type
                .strip_prefix("BoundedCellSet<")
                .and_then(|value| value.strip_suffix('>'))
                .and_then(|value| value.rsplit_once(','))
                .is_some_and(|(element, maximum)| {
                    element.trim() == element_type
                        && maximum.trim().parse::<usize>().is_ok_and(|maximum| (1..=1024).contains(&maximum))
                });
            let fixed_resource = types
                .get(element_type)
                .is_some_and(|ty| ty.kind == "resource" && ty.encoded_size.is_some_and(|width| (1..=512).contains(&width)));
            if !shape(2, 1)
                || destination_type(1) != Some("bool")
                || !is_integer_type(operand_type(0).unwrap_or_default())
                || !declared_contract
                || !fixed_resource
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "bounded-plan-load" => {
            let TypedSemanticOperationDetail::Collection { declared_type } = &operation.detail else { return fail() };
            let element_type = destination_type(0).unwrap_or_default();
            let declared_contract = declared_type
                .strip_prefix("BoundedList<")
                .and_then(|value| value.strip_suffix('>'))
                .and_then(|value| value.rsplit_once(','))
                .is_some_and(|(element, maximum)| {
                    element.trim() == element_type
                        && maximum.trim().parse::<usize>().is_ok_and(|maximum| (1..=1024).contains(&maximum))
                });
            let plan_operand_matches =
                operation.operands.first().map(|operand| operand.ty.as_str()).is_some_and(|ty| ty == declared_type);
            let fixed_struct =
                types.get(element_type).is_some_and(|ty| ty.kind == "struct" && ty.encoded_size.is_some_and(|width| width > 0));
            if !shape(2, 2)
                || destination_type(1) != Some("bool")
                || !plan_operand_matches
                || !is_integer_type(operand_type(1).unwrap_or_default())
                || !declared_contract
                || !fixed_struct
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "bounded-output-verify" => {
            let TypedSemanticOperationDetail::Create { pattern } = &operation.detail else { return fail() };
            let Some(layout) = types.get(pattern.ty.as_str()).filter(|layout| layout.kind == "resource") else { return fail() };
            if !operation.destinations.is_empty()
                || operation.operands.is_empty()
                || !is_integer_type(operand_type(0).unwrap_or_default())
                || pattern.operation != "bounded-create"
                || pattern.binding.is_empty()
                || pattern.identity != "none"
                || !pattern.has_lock
                || pattern.field_names.len() + 2 != operation.operands.len()
                || operation.call.is_some()
            {
                return fail();
            }
            let mut names = BTreeSet::new();
            for (field_index, field_name) in pattern.field_names.iter().enumerate() {
                let Some(field) = layout.fields.iter().find(|field| field.name == *field_name) else { return fail() };
                if !names.insert(field_name.as_str())
                    || canonical_abi_type(&operation.operands[field_index + 1].ty) != canonical_abi_type(&field.ty)
                {
                    return fail();
                }
            }
            if names.len() != layout.fields.len()
                || !layout.fields.iter().all(|field| names.contains(field.name.as_str()))
                || !matches!(
                    canonical_abi_type(&operation.operands.last().expect("non-empty operands").ty).as_str(),
                    "address" | "hash"
                )
            {
                return fail();
            }
        }
        "bounded-output-end" => {
            if !shape(0, 1) || !none_detail || !is_integer_type(operand_type(0).unwrap_or_default()) || operation.call.is_some() {
                return fail();
            }
        }
        "call" => {
            if !none_detail {
                return fail();
            }
            let Some(call) = &operation.call else { return fail() };
            // This known helper has no executable digest contract in this
            // schema. It must not be relabelled as an ordinary value-producing
            // helper after rebinding the enclosing artifact hashes.
            if call.target == "__ckb_sighash_all"
                && (call.contract != "versioned-runtime-helper"
                    || call.effect != "deferred-runtime-fail-closed:66:ckb-sighash-all-deferred")
            {
                return typed_error("deferred sighash call does not declare its canonical failure contract".to_string());
            }
            if call.contract == "typed-local" {
                let Some(callee) = entries.get(call.target.as_str()) else { return fail() };
                if call.params != callee.params.iter().map(|param| param.ty.clone()).collect::<Vec<_>>()
                    || call.return_type != callee.return_type
                    || normalize_effect(&call.effect) != normalize_effect(&callee.effect)
                {
                    return fail();
                }
            } else if call.contract != "versioned-runtime-helper" {
                return fail();
            }
        }
        "read-ref" => {
            let TypedSemanticOperationDetail::Reference { declared_type } = &operation.detail else { return fail() };
            if !shape(1, 0)
                || strip_reference(destination_type(0).unwrap_or_default()) != strip_reference(declared_type)
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "move" => {
            let zero_sized_aggregate_sentinel = matches!(
                operation.operands.first().and_then(|operand| operand.constant.as_ref()),
                Some(TypedSemanticConstant::U64(value)) if value == "0"
            ) && destination_type(0).is_some_and(is_zero_length_array_type);
            let move_types_match = operand_type(0)
                .zip(destination_type(0))
                .is_some_and(|(source, destination)| typed_value_assignable(source, destination))
                || (operand_type(0) == Some("Vec")
                    && destination_type(0).is_some_and(|destination| collection_element_type(destination).is_some()))
                || checked_unsigned_narrowing_move(entry, block, operation, locals)
                || zero_sized_aggregate_sentinel;
            if !shape(1, 1) || !none_detail || !move_types_match || operation.call.is_some() {
                return fail();
            }
        }
        "tuple" => {
            let expected =
                format!("({})", operation.operands.iter().map(|operand| operand.ty.as_str()).collect::<Vec<_>>().join(", "));
            let named_layout_matches = destination_type(0).and_then(|name| types.get(name)).is_some_and(|layout| {
                operation.operands.iter().map(|operand| operand.ty.as_str()).eq(layout.fields.iter().map(|field| field.ty.as_str()))
            });
            let builtin_layout_matches =
                destination_type(0).is_some_and(|destination| builtin_tuple_contract_matches(destination, &operation.operands));
            if operation.destinations.len() != 1
                || !none_detail
                || (destination_type(0) != Some(expected.as_str()) && !named_layout_matches && !builtin_layout_matches)
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "enum-construct" => {
            let TypedSemanticOperationDetail::EnumConstruct { enum_name, variant } = &operation.detail else { return fail() };
            let Some(layout) = types.get(enum_name.as_str()).filter(|ty| ty.kind == "enum") else { return fail() };
            let Some(variant) = layout.variants.iter().find(|item| item.name == *variant) else { return fail() };
            if operation.destinations.len() != 1
                || destination_type(0) != Some(enum_name.as_str())
                || operation
                    .operands
                    .iter()
                    .map(|operand| operand.ty.as_str())
                    .ne(variant.fields.iter().map(|field| field.ty.as_str()))
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "enum-tag" => {
            let TypedSemanticOperationDetail::EnumTag { enum_name } = &operation.detail else { return fail() };
            if !shape(1, 1)
                || operand_type(0).map(strip_reference) != Some(enum_name.as_str())
                || destination_type(0) != Some("u8")
                || !types.get(enum_name.as_str()).is_some_and(|ty| ty.kind == "enum")
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "enum-payload" => {
            let TypedSemanticOperationDetail::EnumPayload { enum_name, variant, field_index } = &operation.detail else {
                return fail();
            };
            let field_type = types
                .get(enum_name.as_str())
                .and_then(|ty| ty.variants.iter().find(|item| item.name == *variant))
                .and_then(|variant| variant.fields.iter().find(|field| field.index == *field_index))
                .map(|field| field.ty.as_str());
            if !shape(1, 1)
                || operand_type(0).map(strip_reference) != Some(enum_name.as_str())
                || destination_type(0) != field_type
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "consume" | "destroy" => {
            if !shape(0, 1) || operation.call.is_some() {
                return fail();
            }
            match (&*operation.opcode, &operation.detail) {
                ("consume", TypedSemanticOperationDetail::None) => {}
                ("destroy", TypedSemanticOperationDetail::Destroy { policy }) if valid_destruction_policy(policy) => {}
                _ => return fail(),
            }
        }
        "create" | "create-unique" | "replace-unique" => {
            validate_create_operation(operation, locals, types)?;
        }
        "transfer" => {
            if !shape(1, 2) || !none_detail || destination_type(0) != operand_type(0) || operation.call.is_some() {
                return fail();
            }
        }
        "claim" | "settle" => {
            if !shape(1, 1) || !none_detail || operation.call.is_some() {
                return fail();
            }
        }
        "cell-metadata-equality" => {
            let TypedSemanticOperationDetail::CellMetadata { field } = &operation.detail else { return fail() };
            if !shape(0, 2)
                || !matches!(field.as_str(), "lock-hash" | "capacity")
                || operand_type(0) != operand_type(1)
                || operation.call.is_some()
            {
                return fail();
            }
        }
        "verifier-failure" => {
            let code = operation.operands.first().and_then(|operand| match &operand.constant {
                Some(TypedSemanticConstant::U64(value)) => value.parse::<u64>().ok(),
                _ => None,
            });
            if !shape(0, 1)
                || !none_detail
                || operation.call.is_some()
                || operand_type(0) != Some("u64")
                || block.terminator != "verifier-failure"
                || !block.successors.is_empty()
                || usize::try_from(operation.index).ok() != block.operations.len().checked_sub(1)
                || block
                    .runtime_error
                    .as_ref()
                    .is_none_or(|error| !(1..=255).contains(&error.code) || error.name.is_empty() || code != Some(error.code))
            {
                return fail();
            }
        }
        "return" => {
            let valid_return = match operation.operands.as_slice() {
                [] => canonical_abi_type(&entry.return_type) == "unit",
                [operand] => {
                    canonical_abi_type(&operand.ty) == canonical_abi_type(&entry.return_type)
                        || (operand.ty == "u64" && matches!(operand.constant, Some(TypedSemanticConstant::U64(_))))
                }
                _ => false,
            };
            if !operation.destinations.is_empty() || !none_detail || !valid_return || operation.call.is_some() {
                return fail();
            }
        }
        "branch-condition" => {
            if !shape(0, 1) || !none_detail || operand_type(0) != Some("bool") || operation.call.is_some() {
                return fail();
            }
        }
        _ => return typed_error(format!("typed operation uses unknown opcode '{}'", operation.opcode)),
    }
    Ok(())
}

fn validate_create_operation(
    operation: &TypedSemanticOperation,
    locals: &BTreeMap<u32, &TypedSemanticLocal>,
    types: &BTreeMap<&str, &TypedSemanticType>,
) -> Result<(), CheckerError> {
    let (pattern, identity, source_offset) = match (&*operation.opcode, &operation.detail) {
        ("create", TypedSemanticOperationDetail::Create { pattern }) => (pattern, None, 0usize),
        ("create-unique", TypedSemanticOperationDetail::CreateUnique { pattern, identity }) => (pattern, Some(identity.as_str()), 0),
        ("replace-unique", TypedSemanticOperationDetail::ReplaceUnique { pattern, identity }) => (pattern, Some(identity.as_str()), 1),
        _ => return typed_error(format!("typed operation '{}' has mismatched create detail", operation.opcode)),
    };
    if operation.destinations.len() != 1 || operation.call.is_some() || pattern.binding.is_empty() || pattern.operation.is_empty() {
        return typed_error(format!("typed operation '{}' has an incomplete create pattern", operation.opcode));
    }
    let destination = locals.get(&operation.destinations[0]).map(|local| local.ty.as_str());
    let Some(layout) = types.get(pattern.ty.as_str()) else {
        return typed_error(format!("typed operation '{}' creates unknown type '{}'", operation.opcode, pattern.ty));
    };
    if destination != Some(pattern.ty.as_str())
        || identity.is_some_and(|identity| identity != pattern.identity)
        || pattern.field_names.len() + usize::from(pattern.has_lock) + source_offset != operation.operands.len()
    {
        return typed_error(format!("typed operation '{}' create identity or operand shape is invalid", operation.opcode));
    }
    if source_offset == 1 && operation.operands.first().map(|operand| strip_reference(&operand.ty)) != Some(pattern.ty.as_str()) {
        return typed_error("typed replace-unique source type differs from its create pattern");
    }
    let mut names = BTreeSet::new();
    for (field_index, field_name) in pattern.field_names.iter().enumerate() {
        let Some(field) = layout.fields.iter().find(|field| field.name == *field_name) else {
            return typed_error(format!("typed create pattern names unknown field '{}::{}'", pattern.ty, field_name));
        };
        let operand = operation.operands.get(source_offset + field_index);
        let encoded_unit_enum = operand.is_some_and(|operand| {
            types.get(field.ty.as_str()).is_some_and(|layout| {
                layout.kind == "enum"
                    && matches!(&operand.constant, Some(TypedSemanticConstant::U64(tag)) if tag.parse::<u32>().ok().is_some_and(
                        |tag| layout.variants.iter().any(|variant| variant.tag == tag && variant.fields.is_empty())
                    ))
            })
        });
        if !names.insert(field_name.as_str())
            || (!operand.is_some_and(|operand| typed_value_assignable(&operand.ty, &field.ty)) && !encoded_unit_enum)
        {
            return typed_error(format!("typed create pattern field '{}::{}' has an invalid type", pattern.ty, field_name));
        }
    }
    if pattern.field_names.len() != layout.fields.len() {
        return typed_error(format!("typed create pattern for '{}' does not initialize every field", pattern.ty));
    }
    Ok(())
}

fn validate_binary_types(operator: &str, left: Option<&str>, right: Option<&str>, destination: Option<&str>) -> bool {
    let (Some(left), Some(right), Some(destination)) = (left, right, destination) else { return false };
    match operator {
        "add" | "sub" | "mul" | "div" | "mod" | "bit-and" | "bit-or" | "bit-xor" => {
            arithmetic_result_type(left, right).as_deref() == Some(destination)
        }
        "shl" | "shr" => is_integer_type(left) && is_integer_type(right) && destination == left,
        "eq" | "ne" => left == right && destination == "bool",
        "lt" | "le" | "gt" | "ge" => {
            (arithmetic_result_type(left, right).is_some() || left == right && is_ckb_temporal_ordered_type(left))
                && destination == "bool"
        }
        "and" | "or" => left == "bool" && right == "bool" && destination == "bool",
        _ => false,
    }
}

fn arithmetic_result_type(left: &str, right: &str) -> Option<String> {
    if left == right && is_integer_type(left) {
        return Some(left.to_string());
    }
    let unsigned_width = |ty: &str| match ty {
        "u8" => Some(8_u16),
        "u16" => Some(16),
        "u32" => Some(32),
        "u64" | "usize" => Some(64),
        "u128" => Some(128),
        _ => None,
    };
    let width = unsigned_width(left)?.max(unsigned_width(right)?);
    Some(format!("u{width}"))
}

fn validate_unary_types(operator: &str, operand: Option<&str>, destination: Option<&str>) -> bool {
    let (Some(operand), Some(destination)) = (operand, destination) else { return false };
    match operator {
        "neg" => operand == destination && is_integer_type(operand),
        "not" => operand == "bool" && destination == "bool",
        // Reference conversions are pointer-preserving no-ops in the current IR
        // and machine ABI. The opcode retains the semantic coercion so calls can
        // still prove that a reference parameter did not receive an uncoerced
        // value.
        "ref" | "deref" => operand == destination,
        _ => false,
    }
}

fn typed_call_operand_matches(entry: &TypedSemanticEntry, param: &str, operand: &TypedSemanticOperand) -> bool {
    if canonical_abi_type(param) == canonical_abi_type(&operand.ty) {
        return true;
    }
    let Some(local_id) = operand.local else { return false };
    let param_pointee = strip_reference(param);
    let operand_pointee = strip_reference(&operand.ty);
    let coercion = if param_pointee != param && canonical_abi_type(param_pointee) == canonical_abi_type(&operand.ty) {
        "ref"
    } else if operand_pointee != operand.ty && canonical_abi_type(param) == canonical_abi_type(operand_pointee) {
        "deref"
    } else {
        return false;
    };
    entry.blocks.iter().flat_map(|block| &block.operations).any(|operation| {
        operation.destinations.as_slice() == [local_id]
            && matches!(
                &operation.detail,
                TypedSemanticOperationDetail::UnaryOperator { operator } if operator == coercion
            )
    })
}

fn is_integer_type(ty: &str) -> bool {
    matches!(ty, "u8" | "u16" | "u32" | "i32" | "u64" | "u128")
}

fn is_ckb_temporal_ordered_type(ty: &str) -> bool {
    matches!(
        ty,
        "EpochNumber"
            | "EpochDuration"
            | "BlockNumber"
            | "EpochLength"
            | "AbsoluteBlockSince"
            | "AbsoluteEpochSince"
            | "AbsoluteTimestampSince"
            | "RelativeBlockSince"
            | "RelativeEpochSince"
            | "RelativeTimestampSince"
    ) || ty.starts_with("Since<Absolute, ")
        || ty.starts_with("Since<Relative, ")
}

fn strip_reference(ty: &str) -> &str {
    ty.strip_prefix("&mut ").or_else(|| ty.strip_prefix('&')).unwrap_or(ty)
}

fn collection_element_type(ty: &str) -> Option<String> {
    let ty = strip_reference(ty);
    if let Some(inner) = ty.strip_prefix("Vec<").and_then(|value| value.strip_suffix('>')) {
        return Some(inner.to_string());
    }
    if let Some(inner) = ty.strip_prefix('[').and_then(|value| value.strip_suffix(']')) {
        return inner.rsplit_once(';').map(|(element, _)| element.trim().to_string());
    }
    None
}

fn is_zero_length_array_type(ty: &str) -> bool {
    ty.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.rsplit_once(';'))
        .is_some_and(|(element, len)| !element.trim().is_empty() && len.trim() == "0")
}

fn declared_collection_type_matches(declared: &str, destination: &str) -> bool {
    declared == destination || (declared == "Vec" && destination.starts_with("Vec<") && collection_element_type(destination).is_some())
}

fn optional_types_equivalent(left: Option<&str>, right: Option<&str>) -> bool {
    left.zip(right).is_some_and(|(left, right)| canonical_abi_type(left) == canonical_abi_type(right))
}

fn typed_value_assignable(actual: &str, expected: &str) -> bool {
    canonical_abi_type(actual) == canonical_abi_type(expected)
        || arithmetic_result_type(actual, expected).as_deref() == Some(expected)
        || unsigned_integer_width(actual).zip(unsigned_integer_width(expected)).is_some_and(|(actual, expected)| actual <= expected)
}

fn checked_unsigned_narrowing_move(
    entry: &TypedSemanticEntry,
    block: &TypedSemanticBlock,
    operation: &TypedSemanticOperation,
    locals: &BTreeMap<u32, &TypedSemanticLocal>,
) -> bool {
    let Some(source) = operation.operands.first() else { return false };
    let Some(source_id) = source.local else { return false };
    let Some(destination_id) = operation.destinations.first() else { return false };
    let Some(destination) = locals.get(destination_id) else { return false };
    let Some(source_width) = unsigned_integer_width(&source.ty) else { return false };
    let Some(destination_width) = unsigned_integer_width(&destination.ty) else { return false };
    if source_width <= destination_width {
        return false;
    }
    let maximum = (1_u128 << destination_width) - 1;

    entry.blocks.iter().any(|predecessor| {
        let [success, failure] = predecessor.successors.as_slice() else { return false };
        if predecessor.terminator != "branch" || *success != block.id {
            return false;
        }
        let Some(failure_block) = entry.blocks.iter().find(|candidate| candidate.id == *failure) else {
            return false;
        };
        if !failure_block
            .runtime_error
            .as_ref()
            .is_some_and(|error| error.code == 20 && error.name == "numeric-or-discriminant-invalid")
        {
            return false;
        }
        let Some(condition_id) = predecessor.operations.last().and_then(|terminator| {
            if terminator.opcode == "branch-condition" {
                terminator.operands.first().and_then(|operand| operand.local)
            } else {
                None
            }
        }) else {
            return false;
        };
        predecessor.operations.iter().any(|candidate| {
            matches!(
                &candidate.detail,
                TypedSemanticOperationDetail::BinaryOperator { operator } if operator == "le"
            ) && candidate.destinations.as_slice() == [condition_id]
                && candidate.operands.first().is_some_and(|operand| operand.local == Some(source_id))
                && candidate.operands.get(1).and_then(|operand| operand.constant.as_ref()).and_then(typed_constant_unsigned_value)
                    == Some(maximum)
        })
    })
}

fn unsigned_integer_width(ty: &str) -> Option<u32> {
    match ty {
        "u8" => Some(8),
        "u16" => Some(16),
        "u32" => Some(32),
        "u64" | "usize" => Some(64),
        "u128" => Some(128),
        _ => None,
    }
}

fn typed_constant_unsigned_value(constant: &TypedSemanticConstant) -> Option<u128> {
    match constant {
        TypedSemanticConstant::U8(value)
        | TypedSemanticConstant::U16(value)
        | TypedSemanticConstant::U32(value)
        | TypedSemanticConstant::U64(value)
        | TypedSemanticConstant::U128(value) => value.parse().ok(),
        _ => None,
    }
}

fn tuple_field_type(ty: &str, field: &str) -> Option<String> {
    let index = field.parse::<usize>().ok()?;
    let inner = ty.strip_prefix('(')?.strip_suffix(')')?;
    let mut depth = 0_u32;
    let mut start = 0;
    let mut fields = Vec::new();
    for (offset, character) in inner.char_indices() {
        match character {
            '(' | '[' | '<' => depth = depth.checked_add(1)?,
            ')' | ']' | '>' => depth = depth.checked_sub(1)?,
            ',' if depth == 0 => {
                fields.push(inner[start..offset].trim());
                start = offset + character.len_utf8();
            }
            _ => {}
        }
    }
    fields.push(inner[start..].trim());
    fields.get(index).filter(|field| !field.is_empty()).map(|field| (*field).to_string())
}

fn builtin_tuple_contract_matches(destination: &str, operands: &[TypedSemanticOperand]) -> bool {
    match (destination, operands) {
        ("ScriptArgs", [bytes, len, is_empty]) => {
            bytes.ty.starts_with('[')
                && collection_element_type(&bytes.ty).as_deref() == Some("u8")
                && len.ty == "u64"
                && is_empty.ty == "bool"
        }
        ("Script", [code_hash, hash_type, args]) => {
            canonical_abi_type(&code_hash.ty) == "hash" && hash_type.ty == "u64" && args.ty == "ScriptArgs"
        }
        _ => false,
    }
}

fn typed_borrow_path_type(root_type: &str, path: &[String], types: &BTreeMap<&str, &TypedSemanticType>) -> Option<String> {
    let mut current = root_type.to_string();
    for segment in path {
        current = types.get(strip_reference(&current))?.fields.iter().find(|field| field.name == *segment)?.ty.clone();
    }
    Some(current)
}

fn valid_destruction_policy(policy: &str) -> bool {
    matches!(policy, "default" | "singleton-type")
        || ["unique:", "instance:", "burn-amount:"]
            .iter()
            .any(|prefix| policy.strip_prefix(prefix).is_some_and(|value| !value.is_empty()))
}

fn validate_typed_cfg_and_dataflow(
    entry: &TypedSemanticEntry,
    locals: &BTreeMap<u32, &TypedSemanticLocal>,
) -> Result<(), CheckerError> {
    let blocks = entry.blocks.iter().map(|block| (block.id, block)).collect::<BTreeMap<_, _>>();
    let mut predecessors = blocks.keys().map(|id| (*id, Vec::<u32>::new())).collect::<BTreeMap<_, _>>();
    for block in &entry.blocks {
        let terminal_opcode = block.operations.last().map(|operation| operation.opcode.as_str());
        let valid_terminator = match block.terminator.as_str() {
            "return" => block.successors.is_empty() && terminal_opcode == Some("return"),
            "verifier-failure" => {
                block.successors.is_empty() && terminal_opcode == Some("verifier-failure") && block.runtime_error.is_some()
            }
            "jump" => {
                block.successors.len() == 1 && !matches!(terminal_opcode, Some("return" | "branch-condition" | "verifier-failure"))
            }
            "branch" => block.successors.len() == 2 && terminal_opcode == Some("branch-condition"),
            _ => false,
        };
        if !valid_terminator {
            return typed_error(format!("typed entry '{}' block {} has an invalid terminator contract", entry.id, block.id));
        }
        if let Some(runtime_error) = &block.runtime_error {
            let error_return = block.operations.last().and_then(|operation| operation.operands.first());
            let encoded_code = error_return.and_then(|operand| match &operand.constant {
                Some(TypedSemanticConstant::U64(value)) => value.parse::<u64>().ok(),
                _ => None,
            });
            if block.terminator != "verifier-failure"
                || runtime_error.code == 0
                || runtime_error.code > 255
                || runtime_error.name.is_empty()
                || encoded_code != Some(runtime_error.code)
            {
                return typed_error(format!("typed entry '{}' block {} has an invalid terminal verifier failure", entry.id, block.id));
            }
        } else if block.terminator == "return" {
            let return_type =
                block.operations.last().and_then(|operation| operation.operands.first()).map_or("unit", |operand| operand.ty.as_str());
            if canonical_abi_type(return_type) != canonical_abi_type(&entry.return_type) {
                return typed_error(format!("typed entry '{}' block {} returns the wrong type", entry.id, block.id));
            }
        }
        for successor in &block.successors {
            predecessors.entry(*successor).or_default().push(block.id);
        }
    }

    let mut reachable = BTreeSet::from([entry.entry_block]);
    let mut pending = vec![entry.entry_block];
    while let Some(block_id) = pending.pop() {
        for successor in &blocks[&block_id].successors {
            if reachable.insert(*successor) {
                pending.push(*successor);
            }
        }
    }
    let universe = locals.keys().copied().collect::<BTreeSet<_>>();
    let params = entry.params.iter().map(|param| param.binding_id).collect::<BTreeSet<_>>();
    let mut borrow_starts = BTreeMap::<(u32, u32), Vec<(u32, u32)>>::new();
    let mut borrow_ends = BTreeMap::<(u32, u32), Vec<u32>>::new();
    for borrow in &entry.borrows {
        let binding_id = locals
            .iter()
            .find_map(|(id, local)| (local.name == borrow.binding && local.ty == borrow.view_type).then_some(*id))
            .ok_or_else(|| {
                CheckerError::new(
                    CheckerRejectionCode::V2419TypedSemanticsInvalid,
                    format!("typed borrow binding '{}' has no local identity", borrow.binding),
                )
            })?;
        let root_id = locals
            .iter()
            .find_map(|(id, local)| (local.name == borrow.root && strip_reference(&local.ty) == borrow.root_type).then_some(*id))
            .ok_or_else(|| {
                CheckerError::new(
                    CheckerRejectionCode::V2419TypedSemanticsInvalid,
                    format!("typed borrow root '{}' has no local identity", borrow.root),
                )
            })?;
        borrow_starts.entry((borrow.start_block, borrow.start_operation)).or_default().push((binding_id, root_id));
        if let (Some(block), Some(operation)) = (borrow.end_block, borrow.end_operation) {
            borrow_ends.entry((block, operation)).or_default().push(binding_id);
        }
    }
    let block_outgoing = |block_id: u32, incoming: &BTreeSet<u32>| {
        let block = blocks[&block_id];
        let mut available = incoming.clone();
        for position in 0..=block.operations.len() {
            let position = u32::try_from(position).unwrap_or(u32::MAX);
            if let Some(bindings) = borrow_ends.get(&(block_id, position)) {
                for binding in bindings {
                    available.remove(binding);
                }
            }
            if let Some(bindings) = borrow_starts.get(&(block_id, position)) {
                available.extend(bindings.iter().map(|(binding, _)| *binding));
            }
            if let Some(operation) = usize::try_from(position).ok().and_then(|index| block.operations.get(index)) {
                available.extend(operation.destinations.iter().copied());
            }
        }
        available
    };
    let mut incoming = blocks
        .keys()
        .map(|id| {
            let initial = if *id == entry.entry_block {
                params.clone()
            } else if reachable.contains(id) {
                universe.clone()
            } else {
                BTreeSet::new()
            };
            (*id, initial)
        })
        .collect::<BTreeMap<_, _>>();
    loop {
        let mut changed = false;
        for block_id in blocks.keys().copied().filter(|id| *id != entry.entry_block && reachable.contains(id)) {
            let preds = predecessors.get(&block_id).into_iter().flatten().filter(|id| reachable.contains(id));
            let mut merged = universe.clone();
            let mut saw_predecessor = false;
            for predecessor in preds {
                saw_predecessor = true;
                let outgoing = block_outgoing(*predecessor, &incoming[predecessor]);
                merged = merged.intersection(&outgoing).copied().collect();
            }
            if !saw_predecessor {
                merged.clear();
            }
            if incoming[&block_id] != merged {
                incoming.insert(block_id, merged);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for block_id in reachable {
        let mut available = incoming[&block_id].clone();
        let block = blocks[&block_id];
        for position in 0..=block.operations.len() {
            let position = u32::try_from(position).unwrap_or(u32::MAX);
            if let Some(bindings) = borrow_ends.get(&(block_id, position)) {
                for binding in bindings {
                    available.remove(binding);
                }
            }
            if let Some(bindings) = borrow_starts.get(&(block_id, position)) {
                for (binding, root) in bindings {
                    if !available.contains(root) {
                        return typed_error(format!(
                            "typed entry '{}' borrow at block {} operation {} starts from an unavailable root",
                            entry.id, block_id, position
                        ));
                    }
                    available.insert(*binding);
                }
            }
            let Some(operation) = usize::try_from(position).ok().and_then(|index| block.operations.get(index)) else {
                continue;
            };
            if operation.operands.iter().filter_map(|operand| operand.local).any(|local| !available.contains(&local)) {
                return typed_error(format!(
                    "typed entry '{}' block {} operation {} uses a local not defined on every incoming path",
                    entry.id, block_id, operation.index
                ));
            }
            available.extend(operation.destinations.iter().copied());
        }
    }
    Ok(())
}

fn validate_typed_effect(entry: &TypedSemanticEntry) -> Result<(), CheckerError> {
    if entry.kind == "lock" {
        return if entry.effect == "lock-predicate" {
            Ok(())
        } else {
            typed_error(format!("typed lock '{}' has an invalid effect label", entry.id))
        };
    }
    let mut has_read = entry.params.iter().any(|param| param.source == "read");
    let mut has_consume = false;
    let mut has_create = false;
    for operation in entry.blocks.iter().flat_map(|block| &block.operations) {
        match operation.opcode.as_str() {
            "read-ref" | "type-hash" | "cell-metadata-equality" => has_read = true,
            "consume" | "destroy" => has_consume = true,
            "create" | "create-unique" => has_create = true,
            "transfer" | "claim" | "settle" | "replace-unique" => {
                has_consume = true;
                has_create = true;
            }
            "call" => {
                if let Some(call) = &operation.call {
                    match normalize_effect(&call.effect).as_str() {
                        "readonly" => has_read = true,
                        "creating" => has_create = true,
                        "destroying" => has_consume = true,
                        "mutating" => {
                            has_consume = true;
                            has_create = true;
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    let inferred = match (has_consume, has_create, has_read) {
        (true, true, _) => "mutating",
        (true, false, _) => "destroying",
        (false, true, _) => "creating",
        (false, false, true) => "readonly",
        (false, false, false) => "pure",
    };
    let declared = normalize_effect(&entry.effect);
    let covers = matches!(
        (declared.as_str(), inferred),
        ("pure", "pure")
            | ("readonly", "pure" | "readonly")
            | ("creating", "pure" | "readonly" | "creating")
            | ("destroying", "pure" | "readonly" | "destroying")
            | ("mutating", _)
    );
    if !covers {
        return typed_error(format!(
            "typed entry '{}' effect '{}' does not cover inferred effect '{inferred}'",
            entry.id, entry.effect
        ));
    }
    Ok(())
}

fn validate_ownership_bindings(entry: &TypedSemanticEntry, locals: &BTreeMap<u32, &TypedSemanticLocal>) -> Result<(), CheckerError> {
    for ownership in &entry.ownership {
        if !locals.values().any(|local| local.name == ownership.binding)
            && !entry.params.iter().any(|param| param.name == ownership.binding)
        {
            return typed_error(format!("typed ownership transition references unknown binding '{}'", ownership.binding));
        }
    }
    let has_transition = |binding: &str, operation: &str, initial: &str| {
        entry.ownership.iter().any(|item| item.binding == binding && item.operation == operation && item.initial_state == initial)
    };
    for operation in entry.blocks.iter().flat_map(|block| &block.operations) {
        let local_name =
            |operand: &TypedSemanticOperand| operand.local.and_then(|id| locals.get(&id)).map(|local| local.name.as_str());
        match operation.opcode.as_str() {
            "consume" | "destroy" => {
                let Some(binding) = operation.operands.first().and_then(local_name) else { continue };
                if !has_transition(binding, &operation.opcode, "available") {
                    return typed_error(format!("typed {} operation for '{}' has no ownership transition", operation.opcode, binding));
                }
            }
            "transfer" | "claim" | "settle" | "replace-unique" => {
                let Some(binding) = operation.operands.first().and_then(local_name) else { continue };
                if !has_transition(binding, &operation.opcode.replace('-', "_"), "available") {
                    return typed_error(format!(
                        "typed {} operation for '{}' has no consume-side ownership transition",
                        operation.opcode, binding
                    ));
                }
                if operation.opcode == "replace-unique"
                    && let TypedSemanticOperationDetail::ReplaceUnique { pattern, .. } = &operation.detail
                    && !has_transition(&pattern.binding, &pattern.operation, "unbound")
                {
                    return typed_error(format!(
                        "typed replace-unique operation for '{}' has no create-side ownership transition",
                        pattern.binding
                    ));
                }
            }
            "read-ref" => {
                let Some(binding) = operation.destinations.first().and_then(|id| locals.get(id)).map(|local| local.name.as_str())
                else {
                    continue;
                };
                if !has_transition(binding, "read_ref", "available") {
                    return typed_error(format!("typed read-ref operation for '{}' has no ownership transition", binding));
                }
            }
            "create" | "create-unique" => {
                let pattern = match &operation.detail {
                    TypedSemanticOperationDetail::Create { pattern }
                    | TypedSemanticOperationDetail::CreateUnique { pattern, .. }
                    | TypedSemanticOperationDetail::ReplaceUnique { pattern, .. } => pattern,
                    _ => continue,
                };
                if !has_transition(&pattern.binding, &pattern.operation, "unbound") {
                    return typed_error(format!(
                        "typed {} operation for '{}' has no create-side ownership transition",
                        operation.opcode, pattern.binding
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn normalize_effect(effect: &str) -> String {
    effect.chars().filter(|character| character.is_ascii_alphanumeric()).flat_map(char::to_lowercase).collect()
}

pub(crate) fn canonical_abi_type(ty: &str) -> String {
    if ty.trim() == "()" {
        return "unit".to_string();
    }
    let mut canonical = String::with_capacity(ty.len());
    let mut identifier = String::new();
    let flush_identifier = |canonical: &mut String, identifier: &mut String| {
        if identifier.is_empty() {
            return;
        }
        canonical.push_str(match identifier.as_str() {
            "Address" | "address" => "address",
            "Hash" | "hash" => "hash",
            "Bool" | "bool" => "bool",
            "String" | "string" => "string",
            value => value,
        });
        identifier.clear();
    };
    for character in ty.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            identifier.push(character);
        } else {
            flush_identifier(&mut canonical, &mut identifier);
            if !character.is_ascii_whitespace() {
                canonical.push(character);
            }
        }
    }
    flush_identifier(&mut canonical, &mut identifier);
    canonical
}

fn typed_error(message: impl Into<String>) -> Result<(), CheckerError> {
    Err(CheckerError::new(CheckerRejectionCode::V2419TypedSemanticsInvalid, message))
}

fn validate_record_graph(record: &VerifiedLoweringRecord, budgets: &CheckerBudgets) -> Result<(), CheckerError> {
    if record.entries.is_empty() || record.blocks.is_empty() || record.text_range.is_empty() {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2405ReferentialIntegrity,
            "lowering record requires at least one entry, one block, and a non-empty text range",
        ));
    }
    ensure_sorted_unique(&record.entries, |entry| entry.id.as_str(), "entry")?;
    ensure_sorted_unique(&record.blocks, |block| block.id.as_str(), "block")?;
    ensure_sorted_unique(&record.proof_records, |proof| proof.id.as_str(), "proof")?;
    if !record.edges.windows(2).all(|pair| (&pair[0].from, &pair[0].kind, &pair[0].to) < (&pair[1].from, &pair[1].kind, &pair[1].to)) {
        return Err(CheckerError::new(CheckerRejectionCode::V2404CanonicalOrder, "lowering edges are not strictly sorted and unique"));
    }

    let entries = record.entries.iter().map(|entry| (entry.id.as_str(), entry)).collect::<BTreeMap<_, _>>();
    let blocks = record.blocks.iter().map(|block| (block.id.as_str(), block)).collect::<BTreeMap<_, _>>();
    let proofs = record.proof_records.iter().map(|proof| (proof.id.as_str(), proof)).collect::<BTreeMap<_, _>>();
    for entry in &record.entries {
        let Some(block) = blocks.get(entry.entry_block.as_str()) else {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2405ReferentialIntegrity,
                format!("entry '{}' references missing block '{}'", entry.id, entry.entry_block),
            ));
        };
        if block.owner_entry != entry.id {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2405ReferentialIntegrity,
                format!("entry '{}' begins in block owned by '{}'", entry.id, block.owner_entry),
            ));
        }
        validate_entry_abi(entry, budgets)?;
        if !strictly_sorted(&entry.capabilities)
            || entry.capabilities.iter().any(String::is_empty)
            || !strictly_sorted(&entry.proof_ids)
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2404CanonicalOrder,
                format!("entry '{}' has non-canonical capabilities or ProofPlan links", entry.id),
            ));
        }
        for proof_id in &entry.proof_ids {
            let Some(proof) = proofs.get(proof_id.as_str()) else {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2408ProofCoverageInvalid,
                    format!("entry '{}' references missing proof '{}'", entry.id, proof_id),
                ));
            };
            if proof.entry_id != entry.id {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2408ProofCoverageInvalid,
                    format!("proof '{}' is not owned by entry '{}'", proof_id, entry.id),
                ));
            }
        }
    }
    for proof in &record.proof_records {
        if !entries.contains_key(proof.entry_id.as_str())
            || proof.obligation.is_empty()
            || !matches!(
                proof.evidence_tier.as_str(),
                "checked-static"
                    | "checked-runtime"
                    | "trusted-external"
                    | "runtime-helper-required"
                    | "builder-evidence-required"
                    | "metadata-only"
                    | "chain-evidence-required"
            )
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2408ProofCoverageInvalid,
                format!("proof '{}' has an invalid owner or empty enforcement fields", proof.id),
            ));
        }
    }

    if !record
        .runtime_error_exits
        .windows(2)
        .all(|pair| (&pair[0].block_id, pair[0].code, pair[0].address) < (&pair[1].block_id, pair[1].code, pair[1].address))
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2404CanonicalOrder,
            "runtime-error exits are not strictly sorted and unique",
        ));
    }
    for exit in &record.runtime_error_exits {
        if exit.code <= 0
            || exit.code > 255
            || exit.name.is_empty()
            || blocks.get(exit.block_id.as_str()).is_none_or(|block| !block.range.contains(exit.address))
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2406CfgInvalid,
                format!("runtime-error exit {} ({}) is outside its declared block", exit.code, exit.name),
            ));
        }
    }

    let mut expected_start = record.text_range.start;
    for block in &record.blocks {
        if !entries.contains_key(block.owner_entry.as_str()) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2405ReferentialIntegrity,
                format!("block '{}' has missing owner '{}'", block.id, block.owner_entry),
            ));
        }
        if block.range.start != expected_start || block.range.is_empty() || block.range.start % 4 != 0 || block.range.end % 4 != 0 {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2406CfgInvalid,
                format!("block '{}' does not form aligned contiguous text coverage", block.id),
            ));
        }
        expected_start = block.range.end;
        validate_block_abi(block, entries[block.owner_entry.as_str()], &proofs, budgets)?;
    }
    if expected_start != record.text_range.end {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2406CfgInvalid,
            "lowering blocks do not cover the declared text range exactly",
        ));
    }

    let mut outgoing = BTreeMap::<&str, Vec<&LoweringEdge>>::new();
    for edge in &record.edges {
        if !blocks.contains_key(edge.from.as_str()) || !blocks.contains_key(edge.to.as_str()) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2405ReferentialIntegrity,
                format!("edge '{} -> {}' references a missing block", edge.from, edge.to),
            ));
        }
        outgoing.entry(edge.from.as_str()).or_default().push(edge);
    }
    for block in &record.blocks {
        validate_terminator_edges(block, outgoing.get(block.id.as_str()).map(Vec::as_slice).unwrap_or(&[]))?;
    }
    validate_reachability(record, &outgoing)?;
    validate_call_graph(record, &entries, &blocks, budgets.call_depth)?;
    Ok(())
}

fn validate_entry_abi(entry: &LoweringEntry, budgets: &CheckerBudgets) -> Result<(), CheckerError> {
    if entry.name.is_empty()
        || entry.return_type.is_empty()
        || entry.effect.is_empty()
        || entry.frame_size_bytes > budgets.stack_frame_bytes
        || entry.outgoing_argument_bytes > entry.frame_size_bytes
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2407AbiOrStackInvalid,
            format!("entry '{}' has an invalid name/frame/outgoing-argument area", entry.id),
        ));
    }
    let mut expected_index = 0u32;
    for param in &entry.params {
        if param.index != expected_index
            || param.name.is_empty()
            || param.ty.is_empty()
            || param.width_bytes == 0
            || !valid_alignment(param.alignment_bytes)
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2407AbiOrStackInvalid,
                format!("entry '{}' has an invalid typed parameter at index {}", entry.id, param.index),
            ));
        }
        expected_index = expected_index.saturating_add(1);
    }
    Ok(())
}

fn validate_block_abi(
    block: &LoweringBlock,
    entry: &LoweringEntry,
    proofs: &BTreeMap<&str, &ProofRecord>,
    budgets: &CheckerBudgets,
) -> Result<(), CheckerError> {
    if block.frame_size_bytes != entry.frame_size_bytes
        || block.outgoing_argument_bytes != entry.outgoing_argument_bytes
        || block.effect != entry.effect
        || block.capabilities != entry.capabilities
        || block.frame_size_bytes > budgets.stack_frame_bytes
        || block.outgoing_argument_bytes > block.frame_size_bytes
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2407AbiOrStackInvalid,
            format!("block '{}' frame contract disagrees with owner entry", block.id),
        ));
    }
    let valid_registers = [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
        "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6",
    ];
    if !strictly_sorted(&block.scratch_register_avoid)
        || block.scratch_register_avoid.iter().any(|register| !valid_registers.contains(&register.as_str()))
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2407AbiOrStackInvalid,
            format!("block '{}' has invalid scratch-register declarations", block.id),
        ));
    }
    let mut last_end = block.outgoing_argument_bytes;
    for slot in &block.stack_slots {
        if slot.name.is_empty()
            || slot.width_bytes == 0
            || !valid_alignment(slot.alignment_bytes)
            || slot.offset % slot.alignment_bytes != 0
            || slot.offset < last_end
            || slot.offset.saturating_add(slot.width_bytes) > block.frame_size_bytes
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2407AbiOrStackInvalid,
                format!("block '{}' has overlapping, misaligned, or out-of-frame stack slot '{}'", block.id, slot.name),
            ));
        }
        last_end = slot.offset.saturating_add(slot.width_bytes);
    }
    if !strictly_sorted(&block.proof_ids)
        || block.proof_ids.iter().any(|proof_id| proofs.get(proof_id.as_str()).is_none_or(|proof| proof.entry_id != block.owner_entry))
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2408ProofCoverageInvalid,
            format!("block '{}' has invalid ProofPlan links", block.id),
        ));
    }
    Ok(())
}

fn validate_reachability(record: &VerifiedLoweringRecord, outgoing: &BTreeMap<&str, Vec<&LoweringEdge>>) -> Result<(), CheckerError> {
    let mut reachable = BTreeSet::new();
    let mut pending = record.entries.iter().map(|entry| entry.entry_block.as_str()).collect::<Vec<_>>();
    while let Some(block_id) = pending.pop() {
        if !reachable.insert(block_id) {
            continue;
        }
        if let Some(edges) = outgoing.get(block_id) {
            pending.extend(edges.iter().map(|edge| edge.to.as_str()));
        }
    }
    if let Some(block) = record.blocks.iter().find(|block| block.reachable != reachable.contains(block.id.as_str())) {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2406CfgInvalid,
            format!(
                "block '{}' declared reachable={} but CFG reachability is {}",
                block.id,
                block.reachable,
                reachable.contains(block.id.as_str())
            ),
        ));
    }
    Ok(())
}

fn validate_terminator_edges(block: &LoweringBlock, edges: &[&LoweringEdge]) -> Result<(), CheckerError> {
    let non_call = edges.iter().filter(|edge| edge.kind != EdgeKind::Call).map(|edge| edge.kind).collect::<Vec<_>>();
    let valid = match block.terminator {
        MachineTerminator::Fallthrough => non_call == [EdgeKind::Fallthrough],
        MachineTerminator::Jump => non_call == [EdgeKind::Jump],
        MachineTerminator::ConditionalBranch => {
            non_call == [EdgeKind::ConditionalTaken, EdgeKind::ConditionalFallthrough]
                || non_call == [EdgeKind::ConditionalFallthrough, EdgeKind::ConditionalTaken]
        }
        MachineTerminator::Return => non_call.is_empty(),
    };
    if !valid {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2406CfgInvalid,
            format!("block '{}' terminator does not match its CFG edges", block.id),
        ));
    }
    Ok(())
}

fn validate_call_graph(
    record: &VerifiedLoweringRecord,
    entries: &BTreeMap<&str, &LoweringEntry>,
    blocks: &BTreeMap<&str, &LoweringBlock>,
    max_depth: u32,
) -> Result<(), CheckerError> {
    let mut graph = BTreeMap::<&str, BTreeSet<&str>>::new();
    for edge in record.edges.iter().filter(|edge| edge.kind == EdgeKind::Call) {
        let from = blocks[edge.from.as_str()].owner_entry.as_str();
        let to = blocks[edge.to.as_str()].owner_entry.as_str();
        if from != to {
            graph.entry(from).or_default().insert(to);
        }
    }
    for root in entries.keys() {
        let mut active = BTreeSet::new();
        validate_call_depth(root, &graph, &mut active, 1, max_depth)?;
    }
    Ok(())
}

fn validate_call_depth<'a>(
    current: &'a str,
    graph: &BTreeMap<&'a str, BTreeSet<&'a str>>,
    active: &mut BTreeSet<&'a str>,
    depth: u32,
    max_depth: u32,
) -> Result<(), CheckerError> {
    if depth > max_depth {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2400BudgetExceeded,
            format!("static call depth exceeds checker budget {max_depth}"),
        ));
    }
    if !active.insert(current) {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2418RecursionPolicyInvalid,
            format!("recursive call cycle reaches entry '{current}'"),
        ));
    }
    if let Some(children) = graph.get(current) {
        for child in children {
            validate_call_depth(child, graph, active, depth.saturating_add(1), max_depth)?;
        }
    }
    active.remove(current);
    Ok(())
}

fn validate_elf_binding(artifact: &[u8], record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    if !elf.text.range().contains_range(record.text_range) {
        return Err(CheckerError::new(CheckerRejectionCode::V2412ElfSectionInvalid, "record text range is outside ELF .text"));
    }
    if record.artifact_size_bytes != artifact.len() as u64 || record.text_range.start < elf.entry {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2409ArtifactIdentityMismatch,
            "record artifact size/text identity disagrees with ELF",
        ));
    }
    Ok(())
}

fn validate_block_digests(artifact: &[u8], record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    for block in &record.blocks {
        let bytes = elf.bytes_for_range(artifact, block.range).map_err(map_elf_error)?;
        let digest = domain_hash_bytes("cellscript-machine-block-v1", bytes);
        if digest != block.byte_digest {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2415BlockDigestMismatch,
                format!("machine bytes for block '{}' do not match its digest", block.id),
            ));
        }
    }
    Ok(())
}

fn validate_control_flow(record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    let blocks = record.blocks.iter().map(|block| (block.id.as_str(), block)).collect::<BTreeMap<_, _>>();
    let find_block = |address| record.blocks.iter().find(|block| block.range.contains(address));
    for flow in elf.control_flow.iter().filter(|flow| record.text_range.contains(flow.address)) {
        let Some(from) = find_block(flow.address) else {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2414ControlFlowInvalid,
                format!("instruction at {:#x} is not covered by a lowering block", flow.address),
            ));
        };
        let Some(to) = find_block(flow.target) else {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2414ControlFlowInvalid,
                format!("target {:#x} is outside lowering blocks", flow.target),
            ));
        };
        let allowed_kinds: &[EdgeKind] = match flow.kind {
            DecodedControlFlowKind::ConditionalBranch => {
                &[EdgeKind::ConditionalTaken, EdgeKind::ConditionalFallthrough, EdgeKind::Fallthrough]
            }
            DecodedControlFlowKind::DirectJump => &[EdgeKind::Jump, EdgeKind::Call, EdgeKind::ConditionalTaken],
        };
        let edge_exists = from.id == to.id
            || record.edges.iter().any(|edge| edge.from == from.id && edge.to == to.id && allowed_kinds.contains(&edge.kind));
        if !edge_exists || !blocks.contains_key(to.id.as_str()) {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2414ControlFlowInvalid,
                format!("decoded flow '{} -> {}' is absent from the lowering CFG", from.id, to.id),
            ));
        }
    }
    Ok(())
}

fn validate_machine_terminators(record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    let instructions = elf.instructions.iter().map(|instruction| (instruction.address, instruction.word)).collect::<BTreeMap<_, _>>();
    for block in &record.blocks {
        let address = block.range.end.checked_sub(4).ok_or_else(|| {
            CheckerError::new(
                CheckerRejectionCode::V2414ControlFlowInvalid,
                format!("block '{}' is too short for a terminator", block.id),
            )
        })?;
        let word = instructions.get(&address).copied().ok_or_else(|| {
            CheckerError::new(
                CheckerRejectionCode::V2414ControlFlowInvalid,
                format!("block '{}' end does not address a decoded instruction", block.id),
            )
        })?;
        let opcode = word & 0x7f;
        let rd = (word >> 7) & 0x1f;
        let valid = match block.terminator {
            MachineTerminator::Return => word == 0x0000_8067,
            MachineTerminator::Jump => opcode == 0x6f && rd == 0,
            MachineTerminator::ConditionalBranch => opcode == 0x63 || (opcode == 0x6f && rd == 0),
            MachineTerminator::Fallthrough => word != 0x0000_8067 && !matches!(opcode, 0x63 | 0x6f),
        };
        if !valid {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2414ControlFlowInvalid,
                format!("decoded final instruction of block '{}' disagrees with its terminator", block.id),
            ));
        }
    }
    Ok(())
}

fn validate_stack_discipline(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    terminal_sink: Option<&str>,
) -> Result<(), CheckerError> {
    let blocks = record.blocks.iter().map(|block| (block.id.as_str(), block)).collect::<BTreeMap<_, _>>();
    let mut outgoing = BTreeMap::<&str, Vec<&LoweringEdge>>::new();
    for edge in &record.edges {
        outgoing.entry(edge.from.as_str()).or_default().push(edge);
    }
    let mut entry_delta = BTreeMap::<&str, i64>::new();
    let mut pending = record.entries.iter().map(|entry| (entry.entry_block.as_str(), 0_i64)).collect::<Vec<_>>();
    while let Some((block_id, incoming_delta)) = pending.pop() {
        // This exception is granted only after decoding the complete, memory-free,
        // non-returning EXIT sink. Arbitrary named runtime helpers get no exemption.
        if terminal_sink == Some(block_id) {
            continue;
        }
        if let Some(previous) = entry_delta.insert(block_id, incoming_delta) {
            if previous != incoming_delta {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2407AbiOrStackInvalid,
                    format!("block '{block_id}' has inconsistent incoming stack-pointer deltas {previous} and {incoming_delta}"),
                ));
            }
            continue;
        }
        let block = blocks[block_id];
        let mut delta = incoming_delta;
        for adjustment in elf.stack_adjustments.iter().filter(|adjustment| block.range.contains(adjustment.address)) {
            delta = delta.checked_add(adjustment.delta).ok_or_else(|| {
                CheckerError::new(
                    CheckerRejectionCode::V2407AbiOrStackInvalid,
                    format!("stack-pointer delta overflows in block '{block_id}'"),
                )
            })?;
            if delta > 0 || delta.unsigned_abs() > u64::from(block.frame_size_bytes) {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2407AbiOrStackInvalid,
                    format!("stack-pointer delta {delta} in block '{block_id}' exceeds declared frame {}", block.frame_size_bytes),
                ));
            }
        }
        if block.terminator == MachineTerminator::Return && delta != 0 {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2407AbiOrStackInvalid,
                format!("return block '{block_id}' leaves stack-pointer delta {delta}"),
            ));
        }
        for edge in outgoing.get(block_id).into_iter().flatten() {
            pending.push((edge.to.as_str(), if edge.kind == EdgeKind::Call { 0 } else { delta }));
        }
    }
    Ok(())
}

fn validate_syscalls(record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    let actual = elf.syscall_addresses.iter().copied().filter(|address| record.text_range.contains(*address)).collect::<Vec<_>>();
    let declared = record.syscall_sites.iter().map(|site| site.address).collect::<Vec<_>>();
    if actual != declared {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2417SyscallContractInvalid,
            "declared syscall sites do not exactly match decoded ecall instructions",
        ));
    }
    let blocks = record.blocks.iter().map(|block| (block.id.as_str(), block)).collect::<BTreeMap<_, _>>();
    for site in &record.syscall_sites {
        if site.contract.is_empty()
            || site.source_domain.is_empty()
            || site.index_domain.is_empty()
            || site.buffer_limit_bytes == 0
            || !site.return_code_checked
            || blocks.get(site.block_id.as_str()).is_none_or(|block| !block.range.contains(site.address))
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2417SyscallContractInvalid,
                format!("syscall site at {:#x} has an invalid bounded contract", site.address),
            ));
        }
    }
    Ok(())
}

fn validate_source_map(
    source_map: &SourceArtifactMap,
    record: &VerifiedLoweringRecord,
    artifact: &[u8],
    elf: &ParsedElf,
) -> Result<(), CheckerError> {
    if source_map.schema != SOURCE_MAP_SCHEMA
        || source_map.version != SOURCE_MAP_VERSION
        || source_map.module != record.module
        || source_map.text_range != record.text_range
        || source_map.source_digest != record.source_content_hash
        || source_map.coverage_claim.source_semantic_equivalence
        || !source_map.coverage_claim.mapped_instruction_ranges_only
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2416SourceMapInvalid,
            "source map schema, identity, or bounded claim is invalid",
        ));
    }
    let blocks = record.blocks.iter().map(|block| (block.id.as_str(), block)).collect::<BTreeMap<_, _>>();
    let entries = record.entries.iter().map(|entry| entry.id.as_str()).collect::<BTreeSet<_>>();
    let mut previous_end = None;
    let mut mapped_ranges = Vec::new();
    for interval in &source_map.intervals {
        if !safe_source_path(&interval.source_path)
            || interval.source_start > interval.source_end
            || interval.machine_range.is_empty()
            || interval.machine_range.start % 4 != 0
            || interval.machine_range.end % 4 != 0
            || previous_end.is_some_and(|end| interval.machine_range.start < end)
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2416SourceMapInvalid,
                format!("source-map interval for block '{}' overlaps, escapes, or is malformed", interval.block_id),
            ));
        }
        let Some(block) = blocks.get(interval.block_id.as_str()) else {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2416SourceMapInvalid,
                format!("source-map interval references missing block '{}'", interval.block_id),
            ));
        };
        if interval.entry_id != block.owner_entry
            || !entries.contains(interval.entry_id.as_str())
            || !block.range.contains_range(interval.machine_range)
            || interval.lowering_block_id != block.lowering_block_id
            || interval.proof_ids.iter().any(|proof| !block.proof_ids.contains(proof))
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2416SourceMapInvalid,
                format!("source-map interval for '{}' disagrees with its lowering block", interval.block_id),
            ));
        }
        elf.bytes_for_range(artifact, interval.machine_range).map_err(map_elf_error)?;
        previous_end = Some(interval.machine_range.end);
        mapped_ranges.push(interval.machine_range);
    }
    let foundation = &record.typed_semantics.foundation;
    let mut semantic_ids = foundation.provenance.nodes.iter().map(|node| node.id.as_str()).collect::<BTreeSet<_>>();
    semantic_ids.insert(foundation.entry_contract.semantic_node_id.as_str());
    semantic_ids.extend(foundation.roles.iter().map(|role| role.semantic_node_id.as_str()));
    semantic_ids.extend(foundation.dispositions.iter().map(|item| item.semantic_node_id.as_str()));
    semantic_ids.extend(foundation.claims.iter().map(|claim| claim.semantic_node_id.as_str()));
    semantic_ids.extend(foundation.legacy_nodes.iter().map(|legacy| legacy.semantic_node_id.as_str()));
    if source_map.semantic_mappings.len() > 262_144
        || source_map.semantic_mappings.windows(2).any(|pair| {
            (&pair[0].semantic_node_id, &pair[0].source_path, pair[0].source_start, pair[0].source_end)
                >= (&pair[1].semantic_node_id, &pair[1].source_path, pair[1].source_start, pair[1].source_end)
        })
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2416SourceMapInvalid,
            "semantic source mappings exceed their bound or are not canonical",
        ));
    }
    let mut mapped_semantic_ids = BTreeSet::new();
    for mapping in &source_map.semantic_mappings {
        if !semantic_ids.contains(mapping.semantic_node_id.as_str())
            || !safe_source_path(&mapping.source_path)
            || mapping.source_start > mapping.source_end
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2416SourceMapInvalid,
                format!("semantic source mapping '{}' is malformed or references an unknown node", mapping.semantic_node_id),
            ));
        }
        mapped_semantic_ids.insert(mapping.semantic_node_id.as_str());
    }
    if mapped_semantic_ids != semantic_ids {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2416SourceMapInvalid,
            "semantic source mappings do not cover every semantic node",
        ));
    }
    if source_map.coverage_claim.complete_text_coverage {
        let mut expected = record.text_range.start;
        for range in mapped_ranges {
            if range.start != expected {
                return Err(CheckerError::new(
                    CheckerRejectionCode::V2416SourceMapInvalid,
                    "source map claims complete text coverage but contains a gap",
                ));
            }
            expected = range.end;
        }
        if expected != record.text_range.end {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2416SourceMapInvalid,
                "source map claims complete text coverage but does not reach text end",
            ));
        }
    }
    Ok(())
}

fn safe_source_path(path: &str) -> bool {
    if path == "<memory>" {
        return true;
    }
    if path.is_empty() || path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return false;
    }
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return false;
    }
    path.split('/').all(|component| !matches!(component, "" | "." | ".."))
}

fn ensure_canonical<T: Serialize>(label: &str, input: &[u8], value: &T) -> Result<(), CheckerError> {
    let canonical = canonical_bytes(value)?;
    if canonical != input {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2402NonCanonicalJson,
            format!("{label} is not byte-for-byte canonical JSON"),
        ));
    }
    Ok(())
}

fn ensure_byte_budget(label: &str, actual: usize, limit: u64) -> Result<(), CheckerError> {
    if actual as u64 > limit {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2400BudgetExceeded,
            format!("{label} bytes {actual} exceed budget {limit}"),
        ));
    }
    Ok(())
}

fn ensure_count(label: &str, actual: usize, limit: u32) -> Result<(), CheckerError> {
    if actual as u64 > u64::from(limit) {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2400BudgetExceeded,
            format!("{label} count {actual} exceeds budget {limit}"),
        ));
    }
    Ok(())
}

fn ensure_sorted_unique<'a, T, F>(values: &'a [T], key: F, label: &str) -> Result<(), CheckerError>
where
    F: Fn(&'a T) -> &'a str,
{
    if values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1])) {
        Ok(())
    } else {
        Err(CheckerError::new(
            CheckerRejectionCode::V2404CanonicalOrder,
            format!("{label} identifiers are not strictly sorted and unique"),
        ))
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_alignment(value: u32) -> bool {
    value.is_power_of_two() && value <= 16
}

fn artifact_declared_too_large(actual: u64, limit: u64) -> bool {
    actual > limit
}

fn json_string<'a>(root: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(root, |value, key| value.get(*key)).and_then(Value::as_str)
}

fn json_u64(root: &Value, path: &[&str]) -> Option<u64> {
    path.iter().try_fold(root, |value, key| value.get(*key)).and_then(Value::as_u64)
}

pub fn domain_hash_bytes(domain: &str, bytes: &[u8]) -> String {
    let mut material = Vec::with_capacity(domain.len() + 1 + bytes.len());
    material.extend_from_slice(domain.as_bytes());
    material.push(0);
    material.extend_from_slice(bytes);
    hex_encode(&ckb_blake2b256(&material))
}

fn map_elf_error(error: ElfParseError) -> CheckerError {
    let code = match error.kind {
        ElfErrorKind::BudgetExceeded => CheckerRejectionCode::V2400BudgetExceeded,
        ElfErrorKind::InvalidSection | ElfErrorKind::ProhibitedLinkState | ElfErrorKind::MissingText => {
            CheckerRejectionCode::V2412ElfSectionInvalid
        }
        ElfErrorKind::InvalidInstruction => CheckerRejectionCode::V2413InstructionInvalid,
        ElfErrorKind::InvalidBranchTarget => CheckerRejectionCode::V2414ControlFlowInvalid,
        _ => CheckerRejectionCode::V2411ElfFormatInvalid,
    };
    CheckerError::new(code, error.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_parser_rejects_whitespace_and_unknown_fields() {
        let budgets = CheckerBudgets::default();
        let unknown = br#"{"schema":"cellscript-source-artifact-map-v1","version":1,"module":"m","artifact_hash":"h","lowering_record_hash":"r","source_set_hash":"s","text_range":{"start":1,"end":2},"intervals":[],"coverage_claim":{"mapped_instruction_ranges_only":true,"complete_text_coverage":false,"source_semantic_equivalence":false},"unknown":true}"#;
        assert_eq!(parse_source_map(unknown, &budgets).unwrap_err().code, CheckerRejectionCode::V2401MalformedJson);

        let map = SourceArtifactMap {
            schema: SOURCE_MAP_SCHEMA.to_string(),
            version: SOURCE_MAP_VERSION,
            module: "m".to_string(),
            artifact_hash: "h".to_string(),
            lowering_record_hash: "r".to_string(),
            source_set_hash: "s".to_string(),
            source_digest: "d".to_string(),
            text_range: MachineRange { start: 1, end: 2 },
            intervals: Vec::new(),
            semantic_mappings: Vec::new(),
            coverage_claim: SourceMapCoverageClaim {
                mapped_instruction_ranges_only: true,
                complete_text_coverage: false,
                source_semantic_equivalence: false,
            },
        };
        let mut pretty = serde_json::to_vec_pretty(&map).unwrap();
        pretty.push(b'\n');
        assert_eq!(parse_source_map(&pretty, &budgets).unwrap_err().code, CheckerRejectionCode::V2402NonCanonicalJson);
    }

    #[test]
    fn checker_error_diagnostics_are_utf8_bounded() {
        let error = CheckerError::new(CheckerRejectionCode::V2401MalformedJson, "边界".repeat(100)).bounded(10);
        assert!(error.message.len() <= 10);
        assert!(std::str::from_utf8(error.message.as_bytes()).is_ok());
    }

    #[test]
    fn malformed_corpus_is_bounded_and_never_panics() {
        let budgets = CheckerBudgets {
            artifact_bytes: 4_096,
            record_bytes: 4_096,
            source_map_bytes: 4_096,
            diagnostic_bytes: 64,
            ..CheckerBudgets::default()
        };
        let corpus = [
            Vec::new(),
            vec![0xff],
            b"{".to_vec(),
            vec![b'{'; 4_097],
            (0..4_096).map(|index| (index % 251) as u8).collect::<Vec<_>>(),
        ];
        for bytes in corpus {
            let outcome = std::panic::catch_unwind(|| check_bundle(&bytes, &bytes, &bytes, &bytes, &budgets));
            let error = outcome.expect("checker must not panic on malformed bounded corpus").unwrap_err();
            assert!(error.message.len() <= budgets.diagnostic_bytes as usize);
        }
    }

    #[test]
    fn source_paths_are_confined() {
        assert!(safe_source_path("src/main.cell"));
        assert!(safe_source_path("<memory>"));
        assert!(!safe_source_path("../main.cell"));
        assert!(!safe_source_path("/tmp/main.cell"));
        assert!(!safe_source_path("C:/main.cell"));
    }

    #[test]
    fn canonical_abi_types_normalize_nested_builtin_names() {
        assert_eq!(canonical_abi_type("[(Address, u64); 2]"), canonical_abi_type("[(address, u64); 2]"));
        assert_ne!(canonical_abi_type("&[Hash; 4]"), canonical_abi_type("[hash; 4]"));
        assert_ne!(canonical_abi_type("Pair<u64>"), canonical_abi_type("Pair<u128>"));
        assert_ne!(canonical_abi_type("AddressBook"), canonical_abi_type("addressBook"));
    }

    #[test]
    fn lossless_unsigned_moves_include_the_rv64_usize_alias() {
        assert!(typed_value_assignable("u8", "usize"));
        assert!(typed_value_assignable("usize", "u64"));
        assert_eq!(arithmetic_result_type("u8", "usize").as_deref(), Some("u64"));
        assert!(!typed_value_assignable("u128", "usize"));
        assert!(!typed_value_assignable("i32", "usize"));
    }
}
