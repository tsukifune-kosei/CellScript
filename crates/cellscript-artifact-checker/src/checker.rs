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

const CKB_RUNTIME_ACCESS_PROVENANCE_CONTRACT: &str = "cellscript-ckb-runtime-access-provenance-v1";
const CKB_RUNTIME_ACCESS_PROVENANCE_METADATA_SCHEMA: u64 = 69;
const BOUNDED_WITNESS_METADATA_SCHEMA: u64 = 70;
const SIGHASH_ZERO_LOCK_METADATA_SCHEMA: u64 = 71;
const BOUNDED_OUTPUT_PLAN_METADATA_SCHEMA: u64 = 72;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeScalarProvenance {
    kind: String,
    value: Option<u64>,
    binding: Option<String>,
    max_inclusive: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSourceProvenance {
    resolved_source: String,
    origin: String,
    binding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRangeProvenance {
    kind: String,
    offset: RuntimeScalarProvenance,
    length: RuntimeScalarProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAccessProvenance {
    contract: String,
    source: RuntimeSourceProvenance,
    index: RuntimeScalarProvenance,
    range: RuntimeRangeProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeAccess {
    operation: String,
    syscall: String,
    source: String,
    index: u64,
    binding: String,
    provenance: RuntimeAccessProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeTransactionViewHandle {
    scope_kind: String,
    scope_name: String,
    binding: String,
    handle_type: String,
    source: String,
    provenance: RuntimeAccessProvenance,
    ownership: String,
    witness_owner: Option<String>,
    max_bytes: Option<u64>,
    lifecycle_authority: bool,
    typing_evidence_tier: String,
    read_evidence_tier: String,
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
    validate_script_hash_machine_contract(record, &elf)?;
    validate_bounded_group_input_machine_contract(record, &elf)?;
    validate_bounded_output_plan_machine_contract(metadata, record, &elf)?;
    validate_policy_dispatch_machine_contract(record, &elf)?;
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
    if record.artifact_format != "RISC-V ELF" || ckb_deployment_hash_type(&record.target_profile).is_none() {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2403UnsupportedSchema,
            "v1 checker accepts only the ckb or ckb-type-hash RISC-V ELF profiles",
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
    validate_runtime_access_provenance_metadata(metadata, &record.typed_semantics)?;
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
    validate_public_interface_metadata(metadata, &record.module, &typed.interface_hash)?;
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
    let target_profile = json_string(metadata, &["target_profile", "name"])
        .and_then(ckb_deployment_hash_type)
        .ok_or_else(|| metadata_binding_error("compile metadata has an unsupported CKB target profile"))?;
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
        || deployment_hash_types != Some(target_profile)
        || json_u64(metadata, &["constraints", "ckb", "profile_abi_contract", "minimum_vm_version"]) != Some(2)
        || json_string(metadata, &["constraints", "ckb", "profile_abi_contract", "riscv_isa"]) != Some("rv64imac_zbb")
        || constraints_hash_types != Some(target_profile)
        || json_string(metadata, &["constraints", "ckb", "hash_type_policy", "default_script_hash_type"]) != Some(target_profile)
    {
        return Err(CheckerError::new(
            CheckerRejectionCode::V2410MetadataBindingMismatch,
            format!("compile metadata does not bind the CKB VM2, rv64imac_zbb, {target_profile} deployment contract"),
        ));
    }
    Ok(())
}

fn ckb_deployment_hash_type(target_profile: &str) -> Option<&'static str> {
    match target_profile {
        "ckb" => Some("data2"),
        "ckb-type-hash" => Some("type"),
        _ => None,
    }
}

fn validate_runtime_access_provenance_metadata(metadata: &Value, typed_semantics: &TypedSemanticRecord) -> Result<(), CheckerError> {
    let schema = json_u64(metadata, &["metadata_schema_version"])
        .ok_or_else(|| metadata_binding_error("compile metadata has no numeric metadata_schema_version"))?;
    if schema < CKB_RUNTIME_ACCESS_PROVENANCE_METADATA_SCHEMA {
        return Ok(());
    }
    if json_string(metadata, &["runtime", "ckb_runtime_access_provenance_contract"]) != Some(CKB_RUNTIME_ACCESS_PROVENANCE_CONTRACT) {
        return Err(metadata_binding_error("compile metadata does not bind the current CKB runtime access provenance contract"));
    }

    let mut module_accesses =
        parse_runtime_accesses(metadata.pointer("/runtime/ckb_runtime_accesses"), "runtime.ckb_runtime_accesses")?;
    let mut entry_accesses = Vec::new();
    for collection in ["actions", "functions", "locks"] {
        let entries = metadata
            .get(collection)
            .and_then(Value::as_array)
            .ok_or_else(|| metadata_binding_error(format!("compile metadata field '{collection}' is not an array")))?;
        for (entry_index, entry) in entries.iter().enumerate() {
            let entry_name = entry.get("name").and_then(Value::as_str).unwrap_or("<unnamed>");
            let label = format!("{collection}[{entry_index}] '{entry_name}'.ckb_runtime_accesses");
            entry_accesses.extend(parse_runtime_accesses(entry.get("ckb_runtime_accesses"), &label)?);
        }
    }
    module_accesses.sort();
    entry_accesses.sort();
    if module_accesses != entry_accesses {
        return Err(metadata_binding_error(
            "compile metadata module runtime accesses differ from action/function/lock runtime accesses",
        ));
    }

    let handles = match metadata.pointer("/runtime/transaction_view_handles") {
        Some(value) => value
            .as_array()
            .ok_or_else(|| metadata_binding_error("compile metadata runtime.transaction_view_handles is not an array"))?
            .as_slice(),
        None => &[],
    };
    let mut typed_handles = Vec::new();
    for (index, handle) in handles.iter().enumerate() {
        let source = handle
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| metadata_binding_error(format!("runtime.transaction_view_handles[{index}].source is invalid")))?;
        let provenance = handle
            .get("provenance")
            .cloned()
            .ok_or_else(|| metadata_binding_error(format!("runtime.transaction_view_handles[{index}].provenance is missing")))?;
        let provenance: RuntimeAccessProvenance = serde_json::from_value(provenance).map_err(|error| {
            metadata_binding_error(format!("runtime.transaction_view_handles[{index}].provenance has an invalid shape: {error}"))
        })?;
        validate_runtime_access_provenance(&format!("runtime.transaction_view_handles[{index}]"), source, None, &provenance)?;
        if schema >= BOUNDED_WITNESS_METADATA_SCHEMA {
            let typed: RuntimeTransactionViewHandle = serde_json::from_value(handle.clone()).map_err(|error| {
                metadata_binding_error(format!("runtime.transaction_view_handles[{index}] has an invalid schema-70 shape: {error}"))
            })?;
            validate_runtime_transaction_view_handle(&format!("runtime.transaction_view_handles[{index}]"), &typed)?;
            typed_handles.push(typed);
        }
    }
    if schema >= BOUNDED_WITNESS_METADATA_SCHEMA {
        for access in &module_accesses {
            let Some((owner, maximum)) = validate_bounded_witness_runtime_access(access)? else {
                continue;
            };
            if !typed_handles.iter().any(|handle| {
                bounded_witness_view_parts(&handle.handle_type) == Some((owner.as_str(), maximum))
                    && handle.provenance.source.resolved_source == access.provenance.source.resolved_source
                    && handle.provenance.index == access.provenance.index
            }) {
                return Err(metadata_binding_error(format!(
                    "bounded witness runtime access '{}' has no matching transaction-view handle",
                    access.operation
                )));
            }
        }
        validate_header_dep_runtime_accesses(&module_accesses, &typed_handles, typed_semantics)?;
        validate_script_hash_runtime_accesses(&module_accesses, typed_semantics)?;
    }
    if schema >= SIGHASH_ZERO_LOCK_METADATA_SCHEMA {
        validate_sighash_zero_lock_domains(metadata, &module_accesses, typed_semantics)?;
    }
    Ok(())
}

fn validate_sighash_zero_lock_domains(
    metadata: &Value,
    accesses: &[RuntimeAccess],
    typed_semantics: &TypedSemanticRecord,
) -> Result<(), CheckerError> {
    let domains = match metadata.pointer("/runtime/signing_message_domains") {
        Some(value) => {
            value.as_array().ok_or_else(|| metadata_binding_error("runtime.signing_message_domains is not an array"))?.as_slice()
        }
        None => &[],
    };
    let canonical_accesses = accesses.iter().filter(|access| access.operation == "sighash-all-zero-lock-v1").collect::<Vec<_>>();
    if domains.len() != canonical_accesses.len() {
        return Err(metadata_binding_error("runtime.signing_message_domains do not match bounded sighash runtime accesses"));
    }
    let mut semantic_calls = typed_semantics
        .entries
        .iter()
        .flat_map(|entry| {
            entry.blocks.iter().flat_map(move |block| {
                block.operations.iter().filter_map(move |operation| {
                    let call = operation.call.as_ref()?;
                    (call.target == "__ckb_sighash_all_zero_lock").then(|| {
                        let bounds = operation
                            .operands
                            .iter()
                            .map(|operand| match operand.constant.as_ref() {
                                Some(TypedSemanticConstant::U64(value)) => value.parse::<u64>().ok(),
                                _ => None,
                            })
                            .collect::<Option<Vec<_>>>();
                        (entry.kind.clone(), entry.name.clone(), bounds)
                    })
                })
            })
        })
        .collect::<Vec<_>>();
    if semantic_calls.len() != domains.len()
        || semantic_calls.iter().any(|(_, _, bounds)| bounds.as_ref().is_none_or(|values| values.len() != 4))
    {
        return Err(metadata_binding_error("runtime.signing_message_domains do not match typed bounded sighash calls"));
    }
    let mut unmatched = canonical_accesses;
    for (index, domain) in domains.iter().enumerate() {
        let label = format!("runtime.signing_message_domains[{index}]");
        let u64_field = |field: &str| domain.get(field).and_then(Value::as_u64);
        let string_field = |field: &str| domain.get(field).and_then(Value::as_str);
        let max_group_inputs = u64_field("max_group_inputs");
        let max_inputs = u64_field("max_inputs");
        let max_extra_witnesses = u64_field("max_extra_witnesses");
        let max_witness_bytes = u64_field("max_witness_bytes");
        let scope_kind = string_field("scope_kind");
        let scope_name = string_field("scope_name");
        let scope_exists = scope_kind.zip(scope_name).is_some_and(|(kind, name)| {
            let collection = match kind {
                "action" => "actions",
                "function" => "functions",
                "lock" => "locks",
                _ => return false,
            };
            metadata
                .get(collection)
                .and_then(Value::as_array)
                .is_some_and(|entries| entries.iter().any(|entry| entry.get("name").and_then(Value::as_str) == Some(name)))
        });
        if !scope_exists
            || string_field("contract") != Some("cellscript-ckb-sighash-all-zero-lock-v1")
            || string_field("binding") != Some("env::sighash_all_zero_lock")
            || string_field("digest_type") != Some("SighashAllDigest")
            || string_field("hash_algorithm") != Some("ckb-default-hash-blake2b-256")
            || string_field("transaction_hash_source") != Some("LOAD_TX_HASH-exact-32")
            || string_field("group_scope") != Some("current-input-script-group")
            || string_field("first_witness_source") != Some("GroupInput[0]-WitnessArgs")
            || string_field("first_witness_lock_transform") != Some("replace-entire-lock-payload-with-equal-length-zero-bytes")
            || string_field("witness_length_prefix") != Some("u64-little-endian-byte-length")
            || string_field("later_group_witness_order") != Some("GroupInput[1..]-script-group-order-if-present")
            || string_field("extra_witness_source") != Some("Input[input_count..witness_count]-transaction-order")
            || !max_group_inputs.is_some_and(|value| (1..=64).contains(&value))
            || !max_inputs.is_some_and(|value| (1..=256).contains(&value))
            || max_group_inputs.zip(max_inputs).is_none_or(|(group, inputs)| group > inputs)
            || !max_extra_witnesses.is_some_and(|value| value <= 64)
            || !max_witness_bytes.is_some_and(|value| (1..=65_536).contains(&value))
            || string_field("runtime_helper") != Some("__ckb_sighash_all_zero_lock")
            || string_field("evidence_tier") != Some("checked-runtime")
        {
            return Err(metadata_binding_error(format!("{label} does not match the canonical zero-lock signing domain")));
        }
        let Some(position) = unmatched.iter().position(|access| {
            access.provenance.index.max_inclusive == max_group_inputs.map(|value| value - 1)
                && access.provenance.range.length.max_inclusive == max_witness_bytes
        }) else {
            return Err(metadata_binding_error(format!("{label} has no runtime access with matching group and witness bounds")));
        };
        unmatched.remove(position);
        let domain_bounds = [max_group_inputs, max_inputs, max_extra_witnesses, max_witness_bytes];
        let Some(position) = semantic_calls.iter().position(|(kind, name, bounds)| {
            let kind = if kind == "helper" { "function" } else { kind.as_str() };
            Some(kind) == scope_kind
                && Some(name.as_str()) == scope_name
                && bounds.as_ref().is_some_and(|values| values.iter().copied().map(Some).eq(domain_bounds))
        }) else {
            return Err(metadata_binding_error(format!("{label} has no typed bounded sighash call with matching scope and bounds")));
        };
        semantic_calls.remove(position);
    }
    Ok(())
}

fn bounded_witness_view_parts(handle_type: &str) -> Option<(&str, u64)> {
    let payload = handle_type.strip_prefix("WitnessBytesView<")?.strip_suffix('>')?;
    let (owner, maximum) = payload.split_once(',')?;
    let owner = owner.trim();
    if !matches!(owner, "raw" | "lock" | "entry" | "output_type") {
        return None;
    }
    let maximum = maximum.trim().parse::<u64>().ok()?;
    (maximum <= 65_536).then_some((owner, maximum))
}

fn validate_runtime_transaction_view_handle(prefix: &str, handle: &RuntimeTransactionViewHandle) -> Result<(), CheckerError> {
    for (field, value) in [
        ("scope_kind", handle.scope_kind.as_str()),
        ("scope_name", handle.scope_name.as_str()),
        ("binding", handle.binding.as_str()),
        ("handle_type", handle.handle_type.as_str()),
        ("source", handle.source.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(metadata_binding_error(format!("{prefix}.{field} must not be empty")));
        }
    }
    let base_type = handle.handle_type.split('<').next().unwrap_or(handle.handle_type.as_str());
    if !matches!(
        base_type,
        "InputView"
            | "OutputView"
            | "CellDepView"
            | "HeaderDepView"
            | "WitnessArgsView"
            | "WitnessBytesView"
            | "OutPoint"
            | "ScriptView"
    ) {
        return Err(metadata_binding_error(format!(
            "{prefix}.handle_type '{}' is not a supported transaction view",
            handle.handle_type
        )));
    }
    if handle.ownership != "read-only-view"
        || handle.lifecycle_authority
        || handle.typing_evidence_tier != "checked-static"
        || handle.read_evidence_tier != "checked-runtime"
    {
        return Err(metadata_binding_error(format!("{prefix} has an invalid ownership or evidence contract")));
    }
    if base_type != "WitnessBytesView" {
        if handle.witness_owner.is_some() || handle.max_bytes.is_some() {
            return Err(metadata_binding_error(format!("{prefix} non-witness handle carries bounded witness fields")));
        }
        return Ok(());
    }

    let Some((owner, maximum)) = bounded_witness_view_parts(&handle.handle_type) else {
        return Err(metadata_binding_error(format!("{prefix}.handle_type has an invalid bounded witness owner or maximum")));
    };
    if handle.witness_owner.as_deref() != Some(owner) || handle.max_bytes != Some(maximum) {
        return Err(metadata_binding_error(format!("{prefix} owner and maximum do not match handle_type")));
    }
    let source_matches = match handle.source.as_str() {
        "WitnessArgs/Input" => handle.provenance.source.resolved_source == "Input",
        "Input" | "Output" | "GroupInput" | "GroupOutput" => handle.provenance.source.resolved_source == handle.source,
        _ => false,
    };
    if !source_matches {
        return Err(metadata_binding_error(format!("{prefix} has an invalid bounded witness source")));
    }
    let expected_range = RuntimeRangeProvenance {
        kind: "bounded-range".to_string(),
        offset: RuntimeScalarProvenance { kind: "static".to_string(), value: Some(0), binding: None, max_inclusive: Some(maximum) },
        length: RuntimeScalarProvenance {
            kind: "dynamic".to_string(),
            value: None,
            binding: Some(format!("{}.size", handle.binding)),
            max_inclusive: Some(maximum),
        },
    };
    if handle.provenance.range != expected_range {
        return Err(metadata_binding_error(format!("{prefix} bounded witness range does not match its declared maximum")));
    }
    Ok(())
}

fn validate_bounded_witness_runtime_access(access: &RuntimeAccess) -> Result<Option<(String, u64)>, CheckerError> {
    if !access.operation.starts_with("witness-bounded-") {
        return Ok(None);
    }
    let mut contract = None;
    for owner in ["raw", "lock", "entry", "output_type"] {
        for (suffix, width) in [("size", None), ("u8", Some(1)), ("u32-le", Some(4)), ("u64-le", Some(8)), ("blake2b", None)] {
            if access.operation == format!("witness-bounded-{owner}-{suffix}") {
                contract = Some((owner, suffix, width));
            }
        }
    }
    let Some((owner, suffix, width)) = contract else {
        return Err(metadata_binding_error(format!("bounded witness runtime operation '{}' is not canonical", access.operation)));
    };
    if access.syscall != "LOAD_WITNESS"
        || access.source != "Witness"
        || access.binding != format!("witness::bounded_{owner}")
        || !matches!(access.provenance.source.resolved_source.as_str(), "Input" | "Output" | "GroupInput" | "GroupOutput")
        || access.provenance.source.origin != "inherited-source-view"
    {
        return Err(metadata_binding_error(format!(
            "bounded witness runtime access '{}' has an invalid source contract",
            access.operation
        )));
    }
    let maximum = if matches!(suffix, "size" | "blake2b") {
        let range = &access.provenance.range;
        if range.kind != "bounded-range"
            || range.offset.kind != "static"
            || range.offset.value != Some(0)
            || range.offset.binding.is_some()
            || range.length.kind != "dynamic"
            || range.length.value.is_some()
            || range.length.binding.as_deref() != Some(format!("bounded_{owner}.size").as_str())
            || range.offset.max_inclusive != range.length.max_inclusive
        {
            return Err(metadata_binding_error(format!(
                "bounded witness runtime access '{}' has an invalid whole-view range",
                access.operation
            )));
        }
        range.length.max_inclusive
    } else {
        let width = width.expect("bounded scalar width");
        let range = &access.provenance.range;
        if range.kind != "bounded-range"
            || !matches!(range.offset.kind.as_str(), "static" | "dynamic")
            || range.length.kind != "static"
            || range.length.value != Some(width)
            || range.length.binding.is_some()
            || range.length.max_inclusive != Some(width)
        {
            return Err(metadata_binding_error(format!(
                "bounded witness runtime access '{}' has an invalid scalar range",
                access.operation
            )));
        }
        range.offset.max_inclusive
    };
    let Some(maximum) = maximum.filter(|maximum| *maximum <= 65_536) else {
        return Err(metadata_binding_error(format!(
            "bounded witness runtime access '{}' exceeds the maximum byte domain",
            access.operation
        )));
    };
    Ok(Some((owner.to_string(), maximum)))
}

fn parse_runtime_accesses(value: Option<&Value>, label: &str) -> Result<Vec<RuntimeAccess>, CheckerError> {
    let value = value.cloned().ok_or_else(|| metadata_binding_error(format!("compile metadata field '{label}' is missing")))?;
    let accesses: Vec<RuntimeAccess> = serde_json::from_value(value)
        .map_err(|error| metadata_binding_error(format!("compile metadata field '{label}' has an invalid shape: {error}")))?;
    for (index, access) in accesses.iter().enumerate() {
        let prefix = format!("{label}[{index}]");
        for (field, value) in [
            ("operation", access.operation.as_str()),
            ("syscall", access.syscall.as_str()),
            ("source", access.source.as_str()),
            ("binding", access.binding.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(metadata_binding_error(format!("{prefix}.{field} must not be empty")));
            }
        }
        if !known_runtime_source(&access.source)
            || !known_runtime_syscall(&access.syscall)
            || !runtime_syscall_allows_source(&access.syscall, &access.source)
        {
            return Err(metadata_binding_error(format!(
                "{prefix} has an unknown or incompatible CKB runtime syscall/source pair '{}/{}'",
                access.syscall, access.source
            )));
        }
        validate_runtime_access_provenance(&prefix, &access.source, Some(access.index), &access.provenance)?;
        validate_canonical_transaction_hash_runtime_access(&prefix, access)?;
        validate_canonical_sighash_zero_lock_runtime_access(&prefix, access)?;
        validate_canonical_script_hash_runtime_access(&prefix, access)?;
        validate_canonical_header_dep_runtime_access(&prefix, access)?;
    }
    Ok(accesses)
}

#[derive(Clone, Copy)]
struct HeaderDepAccessContract {
    target: &'static str,
    operation: &'static str,
    syscall: &'static str,
    binding: &'static str,
    return_type: &'static str,
    width: u64,
}

const HEADER_DEP_ACCESS_CONTRACTS: [HeaderDepAccessContract; 5] = [
    HeaderDepAccessContract {
        target: "__ckb_header_dep_epoch_number",
        operation: "header-dep-epoch-number",
        syscall: "LOAD_HEADER_BY_FIELD",
        binding: "HeaderDepView.epoch_number",
        return_type: "EpochNumber",
        width: 8,
    },
    HeaderDepAccessContract {
        target: "__ckb_header_dep_epoch_start_block_number",
        operation: "header-dep-epoch-start-block-number",
        syscall: "LOAD_HEADER_BY_FIELD",
        binding: "HeaderDepView.epoch_start_block_number",
        return_type: "BlockNumber",
        width: 8,
    },
    HeaderDepAccessContract {
        target: "__ckb_header_dep_epoch_length",
        operation: "header-dep-epoch-length",
        syscall: "LOAD_HEADER_BY_FIELD",
        binding: "HeaderDepView.epoch_length",
        return_type: "EpochLength",
        width: 8,
    },
    HeaderDepAccessContract {
        target: "__ckb_header_dep_block_number",
        operation: "header-dep-block-number",
        syscall: "LOAD_HEADER",
        binding: "HeaderDepView.block_number",
        return_type: "BlockNumber",
        width: 208,
    },
    HeaderDepAccessContract {
        target: "__ckb_header_dep_timestamp_millis",
        operation: "header-dep-timestamp-millis",
        syscall: "LOAD_HEADER",
        binding: "HeaderDepView.timestamp",
        return_type: "TimestampMillis",
        width: 208,
    },
];

fn validate_canonical_header_dep_runtime_access(prefix: &str, access: &RuntimeAccess) -> Result<(), CheckerError> {
    let expected = HEADER_DEP_ACCESS_CONTRACTS.iter().find(|contract| contract.operation == access.operation);
    let identifies_header_field =
        expected.is_some() || access.operation.starts_with("header-dep-") || access.binding.starts_with("HeaderDepView.");
    if !identifies_header_field {
        return Ok(());
    }
    let Some(expected) = expected else {
        return Err(metadata_binding_error(format!("{prefix} names an unknown HeaderDep field contract")));
    };
    let range = &access.provenance.range;
    if access.syscall != expected.syscall
        || access.source != "HeaderDep"
        || access.binding != expected.binding
        || access.provenance.source.resolved_source != "HeaderDep"
        || access.provenance.source.origin != "inherited-source-view"
        || access.provenance.source.binding.as_deref().is_none_or(str::is_empty)
        || !matches!(access.provenance.index.kind.as_str(), "static" | "dynamic")
        || access.provenance.index.max_inclusive != Some(u64::from(u32::MAX))
        || range.kind != "fixed-width"
        || range.offset.kind != "not-applicable"
        || range.length.kind != "static"
        || range.length.value != Some(expected.width)
        || range.length.max_inclusive != Some(expected.width)
    {
        return Err(metadata_binding_error(format!("{prefix} does not match the canonical {} contract", expected.binding)));
    }
    Ok(())
}

fn validate_header_dep_runtime_accesses(
    accesses: &[RuntimeAccess],
    handles: &[RuntimeTransactionViewHandle],
    typed_semantics: &TypedSemanticRecord,
) -> Result<(), CheckerError> {
    for expected in HEADER_DEP_ACCESS_CONTRACTS {
        let matching_accesses = accesses.iter().filter(|access| access.operation == expected.operation).collect::<Vec<_>>();
        let matching_calls = typed_semantics
            .entries
            .iter()
            .flat_map(|entry| &entry.blocks)
            .flat_map(|block| &block.operations)
            .filter(|operation| operation.call.as_ref().is_some_and(|call| call.target == expected.target))
            .collect::<Vec<_>>();
        if matching_accesses.len() != matching_calls.len() {
            return Err(metadata_binding_error(format!(
                "HeaderDep runtime access '{}' does not match typed helper calls",
                expected.operation
            )));
        }
        for operation in matching_calls {
            let call = operation.call.as_ref().expect("filtered typed call");
            if call.params != ["HeaderDepView"]
                || call.return_type != expected.return_type
                || operation.operands.len() != 1
                || operation.operands[0].ty != "HeaderDepView"
            {
                return Err(metadata_binding_error(format!(
                    "typed helper '{}' does not preserve the canonical HeaderDep operand and result types",
                    expected.target
                )));
            }
        }
        for access in matching_accesses {
            if !handles.iter().any(|handle| {
                handle.handle_type == "HeaderDepView"
                    && handle.source == "HeaderDep"
                    && access.provenance.source.binding.as_deref() == Some(handle.binding.as_str())
                    && access.provenance.index == handle.provenance.index
            }) {
                return Err(metadata_binding_error(format!(
                    "HeaderDep runtime access '{}' has no matching typed source-view handle",
                    expected.operation
                )));
            }
        }
    }
    Ok(())
}

fn validate_script_hash_runtime_accesses(
    accesses: &[RuntimeAccess],
    typed_semantics: &TypedSemanticRecord,
) -> Result<(), CheckerError> {
    const MAX_ARGS_BYTES: u64 = 459;
    const MOLECULE_SCRIPT_PREFIX_BYTES: u64 = 53;
    let mut matching_accesses = accesses.iter().filter(|access| access.operation == "script-hash-v1").collect::<Vec<_>>();
    let matching_calls = typed_semantics
        .entries
        .iter()
        .flat_map(|entry| &entry.blocks)
        .flat_map(|block| &block.operations)
        .filter(|operation| operation.call.as_ref().is_some_and(|call| call.target == "__ckb_script_hash"))
        .collect::<Vec<_>>();
    if matching_accesses.len() != matching_calls.len() {
        return Err(metadata_binding_error("canonical Script hash runtime accesses do not match typed helper calls"));
    }
    for operation in matching_calls {
        let call = operation.call.as_ref().expect("filtered typed call");
        let args_width = operation.operands.get(2).and_then(|operand| script_hash_args_width(&operand.ty));
        if operation.destinations.len() != 1
            || operation.operands.len() != 3
            || call.params != operation.operands.iter().map(|operand| operand.ty.clone()).collect::<Vec<_>>()
            || call.return_type != "hash"
            || operation.operands.first().is_none_or(|operand| canonical_abi_type(&operand.ty) != "hash")
            || operation.operands.get(1).is_none_or(|operand| operand.ty != "u64")
            || args_width.is_none_or(|width| width > MAX_ARGS_BYTES)
        {
            return Err(metadata_binding_error(
                "typed __ckb_script_hash call does not preserve the canonical code-hash, hash-type, args, and result domains",
            ));
        }
        let encoded_width = MOLECULE_SCRIPT_PREFIX_BYTES + args_width.expect("validated Script args width");
        let Some(position) = matching_accesses.iter().position(|access| access.provenance.range.length.value == Some(encoded_width))
        else {
            return Err(metadata_binding_error(
                "typed __ckb_script_hash call has no runtime access with its canonical Molecule width",
            ));
        };
        matching_accesses.remove(position);
    }
    Ok(())
}

fn fixed_u8_array_width(ty: &str) -> Option<u64> {
    let inner = ty.strip_prefix('[')?.strip_suffix(']')?;
    let (element, width) = inner.rsplit_once(';')?;
    (element.trim() == "u8").then(|| width.trim().parse().ok()).flatten()
}

fn script_hash_args_width(ty: &str) -> Option<u64> {
    (canonical_abi_type(ty) == "hash").then_some(32).or_else(|| fixed_u8_array_width(ty))
}

fn validate_canonical_transaction_hash_runtime_access(prefix: &str, access: &RuntimeAccess) -> Result<(), CheckerError> {
    let identifies_transaction_hash =
        access.operation == "transaction-hash" || access.syscall == "LOAD_TX_HASH" || access.binding == "ckb::transaction_hash";
    if !identifies_transaction_hash {
        return Ok(());
    }
    let not_applicable =
        RuntimeScalarProvenance { kind: "not-applicable".to_string(), value: None, binding: None, max_inclusive: None };
    let fixed_32 = RuntimeRangeProvenance {
        kind: "fixed-width".to_string(),
        offset: not_applicable.clone(),
        length: RuntimeScalarProvenance { kind: "static".to_string(), value: Some(32), binding: None, max_inclusive: Some(32) },
    };
    if access.operation != "transaction-hash"
        || access.syscall != "LOAD_TX_HASH"
        || access.source != "Transaction"
        || access.index != 0
        || access.binding != "ckb::transaction_hash"
        || access.provenance.source.resolved_source != "Transaction"
        || access.provenance.source.origin != "implicit-lowering"
        || access.provenance.source.binding.is_some()
        || access.provenance.index != not_applicable
        || access.provenance.range != fixed_32
    {
        return Err(metadata_binding_error(format!("{prefix} does not match the canonical 32-byte LOAD_TX_HASH contract")));
    }
    Ok(())
}

fn validate_canonical_sighash_zero_lock_runtime_access(prefix: &str, access: &RuntimeAccess) -> Result<(), CheckerError> {
    let identifies_domain = access.operation == "sighash-all-zero-lock-v1"
        || access.syscall == "CKB_SIGHASH_ALL_ZERO_LOCK_V1"
        || access.binding == "env::sighash_all_zero_lock";
    if !identifies_domain {
        return Ok(());
    }
    let range = &access.provenance.range;
    if access.operation != "sighash-all-zero-lock-v1"
        || access.syscall != "CKB_SIGHASH_ALL_ZERO_LOCK_V1"
        || access.source != "GroupInput"
        || access.index != 0
        || access.binding != "env::sighash_all_zero_lock"
        || access.provenance.source.resolved_source != "GroupInput"
        || access.provenance.source.origin != "bounded-scan"
        || access.provenance.source.binding.is_some()
        || access.provenance.index.kind != "bounded-scan"
        || access.provenance.index.value.is_some()
        || access.provenance.index.binding.is_some()
        || access.provenance.index.max_inclusive.is_none_or(|maximum| maximum > 63)
        || range.kind != "bounded-range"
        || range.offset.kind != "static"
        || range.offset.value != Some(0)
        || range.offset.binding.is_some()
        || range.length.kind != "dynamic"
        || range.length.value.is_some()
        || range.length.binding.as_deref() != Some("sighash_all_zero_lock.witness_size")
        || range.offset.max_inclusive != range.length.max_inclusive
        || range.length.max_inclusive.is_none_or(|maximum| maximum == 0 || maximum > 65_536)
    {
        return Err(metadata_binding_error(format!("{prefix} does not match the bounded CKB sighash-all zero-lock runtime contract")));
    }
    Ok(())
}

fn validate_canonical_script_hash_runtime_access(prefix: &str, access: &RuntimeAccess) -> Result<(), CheckerError> {
    const MAX_ARGS_BYTES: u64 = 459;
    let identifies_script_hash = access.operation == "script-hash-v1"
        || access.binding == "script::hash"
        || (access.syscall == "CKB_BLAKE2B" && access.source == "Script");
    if !identifies_script_hash {
        return Ok(());
    }
    let range = &access.provenance.range;
    if access.operation != "script-hash-v1"
        || access.syscall != "CKB_BLAKE2B"
        || access.source != "Script"
        || access.index != 0
        || access.binding != "script::hash"
        || access.provenance.source.resolved_source != "Script"
        || access.provenance.source.origin != "constructed-script"
        || access.provenance.source.binding.is_some()
        || access.provenance.index.kind != "not-applicable"
        || access.provenance.index.value.is_some()
        || access.provenance.index.binding.is_some()
        || access.provenance.index.max_inclusive.is_some()
        || range.kind != "fixed-width"
        || range.offset.kind != "not-applicable"
        || range.offset.value.is_some()
        || range.offset.binding.is_some()
        || range.offset.max_inclusive.is_some()
        || range.length.kind != "static"
        || range.length.value.is_none_or(|width| !(53..=53 + MAX_ARGS_BYTES).contains(&width))
        || range.length.value != range.length.max_inclusive
        || range.length.binding.is_some()
    {
        return Err(metadata_binding_error(format!("{prefix} does not match the canonical bounded Molecule Script hash contract")));
    }
    Ok(())
}

fn validate_runtime_access_provenance(
    prefix: &str,
    declared_source: &str,
    compatibility_index: Option<u64>,
    provenance: &RuntimeAccessProvenance,
) -> Result<(), CheckerError> {
    if provenance.contract != CKB_RUNTIME_ACCESS_PROVENANCE_CONTRACT
        || provenance.source.resolved_source.trim().is_empty()
        || !known_runtime_source(&provenance.source.resolved_source)
    {
        return Err(metadata_binding_error(format!("{prefix}.provenance has an invalid contract or resolved source")));
    }
    if !matches!(
        provenance.source.origin.as_str(),
        "explicit-source-view"
            | "inherited-source-view"
            | "implicit-lowering"
            | "bounded-scan"
            | "constructed-script"
            | "metadata-summary"
            | "external-adapter"
    ) {
        return Err(metadata_binding_error(format!(
            "{prefix}.provenance.source.origin '{}' is not admitted",
            provenance.source.origin
        )));
    }
    match provenance.source.origin.as_str() {
        "inherited-source-view" if provenance.source.binding.as_deref().is_none_or(str::is_empty) => {
            return Err(metadata_binding_error(format!(
                "{prefix}.provenance.source.binding is required for an inherited source view"
            )));
        }
        "inherited-source-view" => {}
        _ if provenance.source.binding.is_some() => {
            return Err(metadata_binding_error(format!(
                "{prefix}.provenance.source.binding is only valid for an inherited source view"
            )));
        }
        _ => {}
    }
    validate_runtime_scalar(&format!("{prefix}.provenance.index"), &provenance.index)?;
    if matches!(provenance.source.origin.as_str(), "explicit-source-view" | "inherited-source-view")
        && (!matches!(provenance.index.kind.as_str(), "static" | "dynamic")
            || provenance.index.max_inclusive != Some(u64::from(u32::MAX)))
    {
        return Err(metadata_binding_error(format!(
            "{prefix}.provenance.index must bind a static or dynamic 32-bit source-view index"
        )));
    }
    if let Some(compatibility_index) = compatibility_index {
        let expected = provenance.index.value.unwrap_or(0);
        if compatibility_index != expected {
            return Err(metadata_binding_error(format!(
                "{prefix}.index does not match the structured provenance compatibility projection"
            )));
        }
    }
    validate_runtime_range(&format!("{prefix}.provenance.range"), &provenance.range)?;
    if declared_source == "SourceView"
        && !matches!(
            provenance.source.resolved_source.as_str(),
            "Input" | "Output" | "CellDep" | "GroupInput" | "GroupOutput" | "SourceView"
        )
    {
        return Err(metadata_binding_error(format!("{prefix}.provenance resolved source is incompatible with declared SourceView")));
    }
    Ok(())
}

fn validate_runtime_scalar(prefix: &str, value: &RuntimeScalarProvenance) -> Result<(), CheckerError> {
    let valid = match value.kind.as_str() {
        "not-applicable" => value.value.is_none() && value.binding.is_none() && value.max_inclusive.is_none(),
        "static" | "metadata-ordinal" => {
            value.value.is_some()
                && value.binding.is_none()
                && !value.value.zip(value.max_inclusive).is_some_and(|(actual, maximum)| actual > maximum)
        }
        "dynamic" => value.value.is_none() && value.binding.as_deref().is_some_and(|binding| !binding.is_empty()),
        "bounded-scan" => value.value.is_none() && value.binding.is_none() && value.max_inclusive.is_some(),
        _ => false,
    };
    if !valid {
        return Err(metadata_binding_error(format!("{prefix} has invalid scalar provenance")));
    }
    Ok(())
}

fn validate_runtime_range(prefix: &str, range: &RuntimeRangeProvenance) -> Result<(), CheckerError> {
    validate_runtime_scalar(&format!("{prefix}.offset"), &range.offset)?;
    validate_runtime_scalar(&format!("{prefix}.length"), &range.length)?;
    let valid = match range.kind.as_str() {
        "not-applicable" | "whole-value" => range.offset.kind == "not-applicable" && range.length.kind == "not-applicable",
        "fixed-width" => {
            range.offset.kind == "not-applicable"
                && range.length.kind == "static"
                && range.length.value.is_some_and(|length| length > 0)
        }
        "bounded-range" => {
            matches!(range.offset.kind.as_str(), "static" | "dynamic") && matches!(range.length.kind.as_str(), "static" | "dynamic")
        }
        _ => false,
    };
    if !valid {
        return Err(metadata_binding_error(format!("{prefix} has invalid range provenance")));
    }
    Ok(())
}

fn known_runtime_source(source: &str) -> bool {
    matches!(
        source,
        "Input"
            | "Output"
            | "CellDep"
            | "HeaderDep"
            | "GroupInput"
            | "GroupOutput"
            | "GroupCellDep"
            | "GroupHeaderDep"
            | "Witness"
            | "ScriptArgs"
            | "Script"
            | "Expression"
            | "SourceView"
            | "Input/Output"
            | "Input/GroupInput"
            | "Input/HeaderDep"
            | "GroupInput/GroupOutput"
            | "CurrentScript"
            | "CurrentScript/Output"
            | "CurrentScript/SourceView"
            | "CurrentScript/Input/GroupInput/GroupOutput"
            | "Process"
            | "Profile"
            | "Transaction"
    )
}

fn known_runtime_syscall(syscall: &str) -> bool {
    matches!(
        syscall,
        "LOAD_CELL"
            | "LOAD_TRANSACTION"
            | "LOAD_TX_HASH"
            | "LOAD_CELL_BY_FIELD"
            | "LOAD_CELL_DATA"
            | "LOAD_HEADER"
            | "LOAD_HEADER_BY_FIELD"
            | "LOAD_INPUT_BY_FIELD"
            | "LOAD_SCRIPT"
            | "LOAD_SCRIPT_HASH"
            | "LOAD_SCRIPT_ARGS"
            | "SOURCE_VIEW"
            | "CKB_SINCE_ENCODING"
            | "CKB_EPOCH_ARITHMETIC"
            | "LOAD_CELL_BY_FIELD+LOAD_CELL_DATA"
            | "LOAD_CELL_BY_FIELD+LOAD_CELL_DATA+LOAD_WITNESS"
            | "LOAD_INPUT_BY_FIELD/SOURCE_VIEW"
            | "LOAD_SCRIPT+LOAD_CELL_BY_FIELD"
            | "LOAD_SCRIPT+LOAD_CELL_BY_FIELD+LOAD_CELL_DATA"
            | "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD"
            | "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD+LOAD_INPUT_BY_FIELD/SOURCE_VIEW"
            | "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD+LOAD_CELL_DATA+LOAD_INPUT_BY_FIELD"
            | "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD+LOAD_CELL_DATA+LOAD_INPUT_BY_FIELD/SOURCE_VIEW"
            | "LOAD_WITNESS"
            | "LOAD_WITNESS_ARGS_LOCK"
            | "LOAD_WITNESS_ARGS_INPUT_TYPE"
            | "LOAD_WITNESS_ARGS_OUTPUT_TYPE"
            | "CKB_SIGHASH_ALL_ZERO_LOCK_V1"
            | "EXIT"
            | "CAPACITY_POLICY"
            | "CKB_BLAKE2B"
            | "SHA256"
            | "SPAWN"
            | "EXEC"
            | "WAIT"
            | "PROCESS_ID"
            | "PIPE"
            | "PIPE_WRITE"
            | "PIPE_READ"
            | "INHERITED_FD"
            | "CLOSE"
    )
}

fn runtime_syscall_allows_source(syscall: &str, source: &str) -> bool {
    match syscall {
        "LOAD_TRANSACTION" | "LOAD_TX_HASH" => source == "Transaction",
        "LOAD_CELL" => matches!(source, "Input" | "Output" | "CellDep" | "GroupInput" | "GroupOutput"),
        "LOAD_CELL_BY_FIELD" => {
            matches!(source, "Input" | "Output" | "GroupInput" | "GroupOutput" | "CellDep" | "SourceView")
        }
        "LOAD_CELL_DATA" => {
            matches!(source, "Input" | "Output" | "GroupInput" | "GroupOutput" | "SourceView" | "GroupInput/GroupOutput")
        }
        "LOAD_HEADER" => matches!(source, "HeaderDep" | "Input/GroupInput" | "Input/HeaderDep"),
        "LOAD_HEADER_BY_FIELD" => source == "HeaderDep",
        "LOAD_INPUT_BY_FIELD" => matches!(source, "GroupInput" | "SourceView" | "Input/GroupInput"),
        "LOAD_SCRIPT" | "LOAD_SCRIPT_HASH" => source == "CurrentScript",
        "CKB_SIGHASH_ALL_ZERO_LOCK_V1" => source == "GroupInput",
        "EXIT" => source == "Process",
        "LOAD_SCRIPT_ARGS" => source == "ScriptArgs",
        "SOURCE_VIEW" => {
            matches!(source, "Input" | "Output" | "CellDep" | "HeaderDep" | "GroupInput" | "GroupOutput" | "SourceView" | "Expression")
        }
        "CKB_SINCE_ENCODING" | "CKB_EPOCH_ARITHMETIC" => source == "Expression",
        "LOAD_CELL_BY_FIELD+LOAD_CELL_DATA" | "LOAD_CELL_BY_FIELD+LOAD_CELL_DATA+LOAD_WITNESS" => source == "SourceView",
        "LOAD_INPUT_BY_FIELD/SOURCE_VIEW" => source == "Input/Output",
        "LOAD_SCRIPT+LOAD_CELL_BY_FIELD" => source == "CurrentScript/Output",
        "LOAD_SCRIPT+LOAD_CELL_BY_FIELD+LOAD_CELL_DATA" => source == "CurrentScript/Input/GroupInput/GroupOutput",
        "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD" => source == "CurrentScript/SourceView",
        "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD+LOAD_INPUT_BY_FIELD/SOURCE_VIEW"
        | "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD+LOAD_CELL_DATA+LOAD_INPUT_BY_FIELD/SOURCE_VIEW"
        | "LOAD_SCRIPT_HASH+LOAD_CELL_BY_FIELD+LOAD_CELL_DATA+LOAD_INPUT_BY_FIELD" => source == "Input/Output",
        "LOAD_WITNESS" => source == "Witness",
        "LOAD_WITNESS_ARGS_LOCK" | "LOAD_WITNESS_ARGS_INPUT_TYPE" => source == "GroupInput",
        "LOAD_WITNESS_ARGS_OUTPUT_TYPE" => source == "GroupOutput",
        "CAPACITY_POLICY" => source == "Output",
        "CKB_BLAKE2B" => matches!(source, "Profile" | "Script"),
        "SHA256" => source == "Profile",
        "SPAWN" | "EXEC" => source == "CellDep",
        "WAIT" | "PROCESS_ID" | "PIPE" | "PIPE_WRITE" | "PIPE_READ" | "INHERITED_FD" | "CLOSE" => source == "Process",
        _ => false,
    }
}

fn metadata_binding_error(message: impl Into<String>) -> CheckerError {
    CheckerError::new(CheckerRejectionCode::V2410MetadataBindingMismatch, message)
}

fn validate_public_interface_metadata(metadata: &Value, module: &str, expected_hash: &str) -> Result<(), CheckerError> {
    let interface = metadata
        .get("public_interface")
        .and_then(Value::as_object)
        .ok_or_else(|| metadata_binding_error("compile metadata has no canonical public_interface object"))?;
    if interface.get("schema").and_then(Value::as_str) != Some("cellscript-package-interface-v3")
        || interface.get("version").and_then(Value::as_u64) != Some(3)
        || interface.get("module").and_then(Value::as_str) != Some(module)
    {
        return Err(metadata_binding_error("compile metadata public interface has an invalid schema, version, or module identity"));
    }
    let canonical = canonical_json_value(&Value::Object(interface.clone()));
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|error| metadata_binding_error(format!("failed to serialize canonical public interface: {error}")))?;
    let actual_hash = hex_encode(&ckb_blake2b256(&canonical_bytes));
    if actual_hash != expected_hash {
        return Err(metadata_binding_error("compile metadata public interface does not match its interface_hash"));
    }

    let types = validate_public_interface_items(interface.get("types"), "type")?;
    validate_public_interface_items(interface.get("constants"), "constant")?;
    let callables = validate_public_interface_items(interface.get("callables"), "callable")?;
    for item in types {
        let identity = item.get("identity").and_then(Value::as_str).unwrap_or("<unknown>");
        validate_public_type_parameters(item.get("type_parameters"), &format!("{identity}.type_parameters"), true)?;
        validate_public_value_abilities(item.get("value_abilities"), &format!("{identity}.value_abilities"))?;
    }
    for item in callables {
        let identity = item.get("identity").and_then(Value::as_str).unwrap_or("<unknown>");
        validate_public_type_parameters(item.get("type_parameters"), &format!("{identity}.type_parameters"), false)?;
    }
    Ok(())
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut canonical = serde_json::Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonical_json_value(&object[key]));
            }
            Value::Object(canonical)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_json_value).collect()),
        other => other.clone(),
    }
}

fn validate_public_interface_items<'a>(
    value: Option<&'a Value>,
    kind: &str,
) -> Result<Vec<&'a serde_json::Map<String, Value>>, CheckerError> {
    let items =
        value.and_then(Value::as_array).ok_or_else(|| metadata_binding_error(format!("public interface {kind}s must be an array")))?;
    let mut validated = Vec::with_capacity(items.len());
    let mut previous = None::<&str>;
    for item in items {
        let object = item.as_object().ok_or_else(|| metadata_binding_error(format!("public interface {kind} must be an object")))?;
        let identity = object
            .get("identity")
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| metadata_binding_error(format!("public interface {kind} has no identity")))?;
        if previous.is_some_and(|previous| previous >= identity) {
            return Err(metadata_binding_error(format!("public interface {kind} identities must be unique and canonically ordered")));
        }
        previous = Some(identity);
        validated.push(object);
    }
    Ok(validated)
}

fn validate_public_type_parameters(value: Option<&Value>, label: &str, layout_type: bool) -> Result<(), CheckerError> {
    let params = value.and_then(Value::as_array).ok_or_else(|| metadata_binding_error(format!("{label} must be an array")))?;
    let mut names = BTreeSet::new();
    for param in params {
        let param = param.as_object().ok_or_else(|| metadata_binding_error(format!("{label} parameter must be an object")))?;
        let name = param.get("name").and_then(Value::as_str).unwrap_or("");
        let valid_name = !name.is_empty()
            && name.chars().next().is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            && name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !valid_name || !names.insert(name) {
            return Err(metadata_binding_error(format!("{label} has an invalid or duplicate parameter '{name}'")));
        }
        let phantom = param
            .get("phantom")
            .and_then(Value::as_bool)
            .ok_or_else(|| metadata_binding_error(format!("{label}.{name}.phantom must be boolean")))?;
        let constraints = validate_public_value_abilities(param.get("constraints"), &format!("{label}.{name}.constraints"))?;
        if layout_type
            && !phantom
            && ["fixed", "serializable", "non_linear"].into_iter().any(|required| !constraints.contains(&required))
        {
            return Err(metadata_binding_error(format!(
                "{label}.{name} must preserve the fixed, serializable, non_linear public layout boundary"
            )));
        }
    }
    Ok(())
}

fn validate_public_value_abilities<'a>(value: Option<&'a Value>, label: &str) -> Result<Vec<&'a str>, CheckerError> {
    const ORDER: [&str; 7] = ["copy", "drop", "store", "fixed", "serializable", "non_linear", "cell"];
    let values = value.and_then(Value::as_array).ok_or_else(|| metadata_binding_error(format!("{label} must be an array")))?;
    let abilities = values
        .iter()
        .map(|value| value.as_str().ok_or_else(|| metadata_binding_error(format!("{label} must contain only value abilities"))))
        .collect::<Result<Vec<_>, _>>()?;
    let canonical = ORDER.into_iter().filter(|ability| abilities.contains(ability)).collect::<Vec<_>>();
    if canonical != abilities {
        return Err(metadata_binding_error(format!("{label} must contain unique, known value abilities in canonical order")));
    }
    if abilities.contains(&"cell") && abilities.contains(&"non_linear") {
        return Err(metadata_binding_error(format!("{label} cannot combine cell and non_linear")));
    }
    Ok(abilities)
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
            let is_exact_handle_call = matches!(
                call.target.as_str(),
                "__ckb_require_cell_lock_exact_handle"
                    | "__ckb_require_cell_type_exact_handle"
                    | "__ckb_require_cell_dep_exact_verifier_handle"
            );
            let is_deployment_line_handle_call = matches!(
                call.target.as_str(),
                "__ckb_require_cell_lock_deployment_line_handle"
                    | "__ckb_require_cell_type_deployment_line_handle"
                    | "__ckb_require_cell_dep_deployment_line_verifier_handle"
            );
            if operation.operands.iter().any(|operand| operand.ty == "ExactScriptHandle") && !is_exact_handle_call {
                return typed_error("ExactScriptHandle operand is passed to an unrecognized runtime helper".to_string());
            }
            if operation.operands.iter().any(|operand| operand.ty == "DeploymentLineHandle") && !is_deployment_line_handle_call {
                return typed_error("DeploymentLineHandle operand is passed to an unrecognized runtime helper".to_string());
            }
            // This known helper has no executable digest contract in this
            // schema. It must not be relabelled as an ordinary value-producing
            // helper after rebinding the enclosing artifact hashes.
            if call.target == "__ckb_sighash_all"
                && (call.contract != "versioned-runtime-helper"
                    || call.effect != "deferred-runtime-fail-closed:66:ckb-sighash-all-deferred")
            {
                return typed_error("deferred sighash call does not declare its canonical failure contract".to_string());
            }
            if call.target == "__ckb_sighash_all_zero_lock" {
                let bounds = operation
                    .operands
                    .iter()
                    .map(|operand| match operand.constant.as_ref() {
                        Some(TypedSemanticConstant::U64(value)) => value.parse::<u64>().ok(),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>();
                let valid_bounds = bounds.as_deref().is_some_and(|values| {
                    values.len() == 4
                        && (1..=64).contains(&values[0])
                        && (1..=256).contains(&values[1])
                        && values[0] <= values[1]
                        && values[2] <= 64
                        && (1..=65_536).contains(&values[3])
                });
                if call.contract != "versioned-runtime-helper"
                    || call.effect != "runtime-contract"
                    || call.params != ["u64", "u64", "u64", "u64"]
                    || call.return_type != "hash"
                    || !valid_bounds
                {
                    return typed_error("bounded zero-lock sighash call does not declare its canonical runtime contract".to_string());
                }
            }
            if is_exact_handle_call {
                let first_type = call.params.first().map(String::as_str).unwrap_or_default();
                let source_type_valid = if call.target == "__ckb_require_cell_dep_exact_verifier_handle" {
                    first_type == "CellDepView"
                } else {
                    matches!(first_type.split('<').next().unwrap_or(first_type), "InputView" | "OutputView" | "CellDepView")
                };
                let handle_hash_is_constant = matches!(
                    operation.operands.get(2).and_then(|operand| operand.constant.as_ref()),
                    Some(TypedSemanticConstant::Hash(_))
                );
                if call.contract != "versioned-runtime-helper"
                    || call.effect != "runtime-contract"
                    || call.return_type != "unit"
                    || !operation.destinations.is_empty()
                    || operation.operands.len() != 3
                    || !source_type_valid
                    || call.params.get(1).map(String::as_str) != Some("ExactScriptHandle")
                    || canonical_abi_type(call.params.get(2).map(String::as_str).unwrap_or_default()) != "hash"
                    || !handle_hash_is_constant
                {
                    return typed_error(
                        "exact Script handle call does not declare its canonical full-handle commitment and runtime contract"
                            .to_string(),
                    );
                }
            }
            if is_deployment_line_handle_call {
                let verifier = call.target == "__ckb_require_cell_dep_deployment_line_verifier_handle";
                let expected_len = if verifier { 4 } else { 5 };
                let handle_index = if verifier { 2 } else { 3 };
                let hash_index = handle_index + 1;
                let source_type_valid = if verifier {
                    call.params.first().map(String::as_str) == Some("CellDepView")
                } else {
                    call.params.first().map(String::as_str).is_some_and(|first| {
                        matches!(first.split('<').next().unwrap_or(first), "InputView" | "OutputView" | "CellDepView")
                    })
                };
                let deps_valid = if verifier {
                    call.params.first().map(String::as_str) == Some("CellDepView")
                        && call.params.get(1).map(String::as_str) == Some("CellDepView")
                } else {
                    call.params.get(1).map(String::as_str) == Some("CellDepView")
                        && call.params.get(2).map(String::as_str) == Some("CellDepView")
                };
                let handle_hash_is_constant = matches!(
                    operation.operands.get(hash_index).and_then(|operand| operand.constant.as_ref()),
                    Some(TypedSemanticConstant::Hash(_))
                );
                if call.contract != "versioned-runtime-helper"
                    || call.effect != "runtime-contract"
                    || call.return_type != "unit"
                    || !operation.destinations.is_empty()
                    || operation.operands.len() != expected_len
                    || call.params.len() != expected_len
                    || !source_type_valid
                    || !deps_valid
                    || call.params.get(handle_index).map(String::as_str) != Some("DeploymentLineHandle")
                    || canonical_abi_type(call.params.get(hash_index).map(String::as_str).unwrap_or_default()) != "hash"
                    || !handle_hash_is_constant
                {
                    return typed_error(
                        "deployment line handle call does not declare its canonical active-admission, exact-code, and full-handle runtime contract"
                            .to_string(),
                    );
                }
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
                || operand_type(0)
                    .zip(destination_type(0))
                    .is_some_and(|(source, destination)| bounded_witness_view_retyping_move(source, destination))
                || operand_type(0)
                    .zip(destination_type(0))
                    .is_some_and(|(source, destination)| semantic_hash_domain_retyping_move(source, destination))
                || (operand_type(0) == Some("Vec")
                    && destination_type(0).is_some_and(|destination| collection_element_type(destination).is_some()))
                || checked_unsigned_narrowing_move(entry, block, operation, locals)
                || zero_sized_aggregate_sentinel;
            if !shape(1, 1) || !none_detail || !move_types_match || operation.call.is_some() {
                return typed_error(format!(
                    "typed move has an invalid shape or type: source {:?}, destination {:?}",
                    operand_type(0),
                    destination_type(0)
                ));
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
            | "TimestampMillis"
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

fn bounded_witness_view_retyping_move(actual: &str, expected: &str) -> bool {
    if !matches!(actual, "u64" | "WitnessArgsView") {
        return false;
    }
    let Some(payload) = expected.strip_prefix("WitnessBytesView<").and_then(|value| value.strip_suffix('>')) else {
        return false;
    };
    let Some((owner, maximum)) = payload.split_once(',') else {
        return false;
    };
    matches!(owner.trim(), "raw" | "lock" | "entry" | "output_type")
        && maximum.trim().parse::<u64>().is_ok_and(|maximum| maximum <= 65_536)
}

fn semantic_hash_domain_retyping_move(actual: &str, expected: &str) -> bool {
    (canonical_abi_type(actual) == "hash" && matches!(expected, "ScriptHash" | "SighashAllDigest"))
        || (actual == "SighashAllDigest" && canonical_abi_type(expected) == "hash")
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
            (canonical_abi_type(&bytes.ty) == "hash"
                || (bytes.ty.starts_with('[') && collection_element_type(&bytes.ty).as_deref() == Some("u8")))
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
        let block = blocks.get(site.block_id.as_str()).copied();
        if site.contract.is_empty()
            || site.source_domain.is_empty()
            || site.index_domain.is_empty()
            || site.buffer_limit_bytes == 0
            || !site.return_code_checked
            || block.is_none_or(|block| !block.range.contains(site.address))
        {
            return Err(CheckerError::new(
                CheckerRejectionCode::V2417SyscallContractInvalid,
                format!("syscall site at {:#x} has an invalid bounded contract", site.address),
            ));
        }
        validate_header_dep_syscall_site(record, elf, site, block.expect("validated syscall block"))?;
    }
    Ok(())
}

fn validate_script_hash_machine_contract(record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    let call_count = record
        .typed_semantics
        .entries
        .iter()
        .flat_map(|entry| &entry.blocks)
        .flat_map(|block| &block.operations)
        .filter(|operation| operation.call.as_ref().is_some_and(|call| call.target == "__ckb_script_hash"))
        .count();
    if call_count == 0 {
        return Ok(());
    }

    let entry = record
        .entries
        .iter()
        .find(|entry| entry.id == "runtime:__ckb_script_hash")
        .ok_or_else(|| script_hash_machine_error("missing __ckb_script_hash runtime entry"))?;
    let entry_block = record
        .blocks
        .iter()
        .find(|block| block.id == entry.entry_block)
        .ok_or_else(|| script_hash_machine_error("missing __ckb_script_hash entry block"))?;
    let blake_entry = record
        .entries
        .iter()
        .find(|entry| entry.id == "runtime:__ckb_hash_blake2b_var")
        .ok_or_else(|| script_hash_machine_error("missing bounded Blake2b runtime entry"))?;
    let blake_block = record
        .blocks
        .iter()
        .find(|block| block.id == blake_entry.entry_block)
        .ok_or_else(|| script_hash_machine_error("missing bounded Blake2b entry block"))?;
    if entry.frame_size_bytes != 560
        || entry.outgoing_argument_bytes != 0
        || entry_block.machine_label.as_deref() != Some("__ckb_script_hash")
        || entry_block.frame_size_bytes != 560
        || record.blocks.iter().filter(|block| block.owner_entry == entry.id).any(|block| block.frame_size_bytes != 560)
    {
        return Err(script_hash_machine_error("runtime entry no longer declares the bounded 512-byte preimage frame"));
    }

    let base = entry_block.range.start;
    let word = |delta: u64| -> Result<u32, CheckerError> {
        let address = base.checked_add(delta).ok_or_else(|| script_hash_machine_error("instruction address overflow"))?;
        elf.instructions
            .iter()
            .find(|instruction| instruction.address == address)
            .map(|instruction| instruction.word)
            .ok_or_else(|| script_hash_machine_error(format!("missing instruction at {address:#x}")))
    };
    let flow_targets = |delta: u64, target: u64| {
        base.checked_add(delta)
            .is_some_and(|address| elf.control_flow.iter().any(|edge| edge.address == address && edge.target == target))
    };
    let invalid = base + 300;
    let valid_hash_type = base + 100;
    if !is_addi(word(0)?, 2, 2, -560)
        || !is_sd(word(4)?, 1, 2, 552)
        || !is_sd(word(8)?, 10, 2, 512)
        || !is_sd(word(12)?, 11, 2, 520)
        || !is_sd(word(16)?, 12, 2, 528)
        || !is_sd(word(20)?, 13, 2, 536)
        || !is_sd(word(24)?, 14, 2, 544)
        || !is_beq(word(28)?, 10, 0)
        || !flow_targets(28, invalid)
        || !is_beq(word(32)?, 14, 0)
        || !flow_targets(32, invalid)
        || !is_addi(word(36)?, 5, 0, 460)
        || !is_sltu(word(40)?, 6, 13, 5)
        || !is_beq(word(44)?, 6, 0)
        || !flow_targets(44, invalid)
        || !is_beq(word(48)?, 13, 0)
        || !flow_targets(48, base + 56)
        || !is_beq(word(52)?, 12, 0)
        || !flow_targets(52, invalid)
    {
        return Err(script_hash_machine_error("pointer, output, or 459-byte Script args bound changed"));
    }
    if !is_beq(word(56)?, 11, 0)
        || !flow_targets(56, valid_hash_type)
        || !is_addi(word(60)?, 5, 0, 1)
        || !is_sub(word(64)?, 6, 11, 5)
        || !is_beq(word(68)?, 6, 0)
        || !flow_targets(68, valid_hash_type)
        || !is_addi(word(72)?, 5, 0, 2)
        || !is_sub(word(76)?, 6, 11, 5)
        || !is_beq(word(80)?, 6, 0)
        || !flow_targets(80, valid_hash_type)
        || !is_addi(word(84)?, 5, 0, 4)
        || !is_sub(word(88)?, 6, 11, 5)
        || !is_beq(word(92)?, 6, 0)
        || !flow_targets(92, valid_hash_type)
        || !is_jal_zero(word(96)?)
        || !flow_targets(96, invalid)
    {
        return Err(script_hash_machine_error("admitted CKB Script hash_type set changed"));
    }
    if !is_ld(word(100)?, 5, 2, 536)
        || !is_addi(word(104)?, 5, 5, 53)
        || !is_sw(word(108)?, 5, 2, 0)
        || !is_addi(word(112)?, 5, 0, 16)
        || !is_sw(word(116)?, 5, 2, 4)
        || !is_addi(word(120)?, 5, 0, 48)
        || !is_sw(word(124)?, 5, 2, 8)
        || !is_addi(word(128)?, 5, 0, 49)
        || !is_sw(word(132)?, 5, 2, 12)
    {
        return Err(script_hash_machine_error("canonical Molecule Script total size or table offsets changed"));
    }
    if !is_ld(word(136)?, 7, 2, 512)
        || !is_addi(word(140)?, 5, 0, 0)
        || !is_addi(word(144)?, 6, 0, 32)
        || !is_sltu(word(148)?, 6, 5, 6)
        || !is_beq(word(152)?, 6, 0)
        || !flow_targets(152, base + 184)
        || !is_add(word(156)?, 28, 7, 5)
        || !is_lbu(word(160)?, 29, 28, 0)
        || !is_addi(word(164)?, 28, 2, 16)
        || !is_add(word(168)?, 28, 28, 5)
        || !is_sb(word(172)?, 29, 28, 0)
        || !is_addi(word(176)?, 5, 5, 1)
        || !is_jal_zero(word(180)?)
        || !flow_targets(180, base + 144)
    {
        return Err(script_hash_machine_error("32-byte code_hash serialization changed"));
    }
    if !is_ld(word(184)?, 5, 2, 520)
        || !is_sb(word(188)?, 5, 2, 48)
        || !is_ld(word(192)?, 5, 2, 536)
        || !is_sb(word(196)?, 5, 2, 49)
        || !is_srli(word(200)?, 5, 5, 8)
        || !is_sb(word(204)?, 5, 2, 50)
        || !is_srli(word(208)?, 5, 5, 8)
        || !is_sb(word(212)?, 5, 2, 51)
        || !is_srli(word(216)?, 5, 5, 8)
        || !is_sb(word(220)?, 5, 2, 52)
    {
        return Err(script_hash_machine_error("hash_type or little-endian Bytes length serialization changed"));
    }
    if !is_ld(word(224)?, 7, 2, 528)
        || !is_ld(word(228)?, 30, 2, 536)
        || !is_addi(word(232)?, 5, 0, 0)
        || !is_sltu(word(236)?, 6, 5, 30)
        || !is_beq(word(240)?, 6, 0)
        || !flow_targets(240, base + 272)
        || !is_add(word(244)?, 28, 7, 5)
        || !is_lbu(word(248)?, 29, 28, 0)
        || !is_addi(word(252)?, 28, 2, 53)
        || !is_add(word(256)?, 28, 28, 5)
        || !is_sb(word(260)?, 29, 28, 0)
        || !is_addi(word(264)?, 5, 5, 1)
        || !is_jal_zero(word(268)?)
        || !flow_targets(268, base + 236)
    {
        return Err(script_hash_machine_error("bounded Script args serialization changed"));
    }
    if !is_addi(word(272)?, 10, 2, 0)
        || !is_ld(word(276)?, 11, 2, 536)
        || !is_addi(word(280)?, 11, 11, 53)
        || !is_ld(word(284)?, 12, 2, 544)
        || !is_auipc(word(288)?, 1)
        || !is_jalr_call(word(292)?)
        || !flow_targets(292, blake_block.range.start)
        || !is_jal_zero(word(296)?)
        || !flow_targets(296, base + 304)
        || !is_addi(word(300)?, 10, 0, 72)
        || !is_ld(word(304)?, 1, 2, 552)
        || !is_addi(word(308)?, 2, 2, 560)
        || word(312)? != 0x0000_8067
    {
        return Err(script_hash_machine_error("Blake2b delegation, error 72, or bounded-frame return changed"));
    }
    Ok(())
}

fn script_hash_machine_error(message: impl Into<String>) -> CheckerError {
    CheckerError::new(
        CheckerRejectionCode::V2417SyscallContractInvalid,
        format!("canonical Script hash machine contract: {}", message.into()),
    )
}

const POLICY_WRAPPER_ENTRY_ID: &str = "wrapper:_cellscript_entry";
const POLICY_ENTRY_FRAME_BYTES: u32 = 4_192;
const POLICY_ADAPTER_FRAME_BYTES: u32 = 5_376;
const POLICY_ARGS_POINTER_OFFSET: i32 = 4_144;
const POLICY_ARGS_LENGTH_OFFSET: i32 = 4_152;
const POLICY_TAG_OFFSET: i32 = 4_160;
const POLICY_FOUND_OFFSET: i32 = 4_168;
const POLICY_RA_OFFSET: i32 = 4_184;
const POLICY_HASH_BUFFER_OFFSET: i32 = 4_112;
const POLICY_RECORD_FIXED_BYTES: i32 = 61;
const POLICY_TYPE_ROLE: i32 = 1;
const POLICY_WITNESS_MAGIC: &[u8; 8] = b"CSPOLv1\0";
const ENTRY_WITNESS_MAGIC: &[u8; 8] = b"CSARGv1\0";
const CKB_LOAD_SCRIPT_HASH: u64 = 2_062;
const CKB_LOAD_WITNESS: u64 = 2_074;
const CKB_LOAD_CELL_BY_FIELD: u64 = 2_081;
const CKB_LOAD_CELL_DATA: u64 = 2_092;
const CKB_GROUP_FLAG: u64 = 0x0100_0000_0000_0000;
const CKB_GROUP_INPUT: u64 = CKB_GROUP_FLAG | 1;
const CKB_GROUP_OUTPUT: u64 = CKB_GROUP_FLAG | 2;

#[derive(Debug)]
struct BoundedGroupInputMachineContract<'a> {
    owner: &'a str,
    maximum: u64,
    element_width: u64,
}

#[derive(Debug)]
struct BoundedOutputMachineContract {
    owner: String,
    maximum: u64,
    element_width: u64,
    output_width: u64,
    capacity_floor: u64,
    field_count: usize,
    lock_plan_offset: u64,
}

fn validate_bounded_output_plan_machine_contract(
    metadata: &Value,
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
) -> Result<(), CheckerError> {
    let schema = json_u64(metadata, &["metadata_schema_version"])
        .ok_or_else(|| bounded_output_machine_error("compile metadata has no numeric metadata schema"))?;
    let typed_load_count = record
        .typed_semantics
        .entries
        .iter()
        .flat_map(|entry| &entry.blocks)
        .flat_map(|block| &block.operations)
        .filter(|operation| operation.opcode == "bounded-plan-load")
        .count();
    let contracts = bounded_output_contracts_from_metadata(metadata, record)?;
    if contracts.is_empty() && typed_load_count == 0 {
        return Ok(());
    }
    if schema < BOUNDED_OUTPUT_PLAN_METADATA_SCHEMA {
        return Err(bounded_output_machine_error("bounded output evidence is present before metadata schema 72"));
    }
    if contracts.len() != typed_load_count {
        return Err(bounded_output_machine_error(
            "typed bounded Plan loads and metadata contracts do not have one-to-one correspondence",
        ));
    }

    for owner in contracts.iter().map(|contract| contract.owner.as_str()).collect::<BTreeSet<_>>() {
        let owner_contracts = contracts.iter().filter(|contract| contract.owner == owner).collect::<Vec<_>>();
        let typed_entry = record
            .typed_semantics
            .entries
            .iter()
            .find(|entry| entry.id == owner)
            .ok_or_else(|| bounded_output_machine_error(format!("metadata owner '{owner}' has no typed entry")))?;
        let typed_loads = typed_entry
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .filter(|operation| operation.opcode == "bounded-plan-load")
            .collect::<Vec<_>>();
        let typed_verifies = typed_entry
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .filter(|operation| operation.opcode == "bounded-output-verify")
            .collect::<Vec<_>>();
        let typed_ends = typed_entry
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .filter(|operation| operation.opcode == "bounded-output-end")
            .collect::<Vec<_>>();
        if typed_loads.len() != owner_contracts.len()
            || typed_verifies.len() != owner_contracts.len()
            || typed_ends.len() != owner_contracts.len()
        {
            return Err(bounded_output_machine_error(format!(
                "entry '{owner}' must have one typed load, verify, and exact-count end for each bounded output contract"
            )));
        }

        let headers = generated_blocks(record, owner, ".Lbounded_plan_header_ok_");
        let magic = generated_blocks(record, owner, ".Lbounded_plan_magic_ok_");
        let counts = generated_blocks(record, owner, ".Lbounded_plan_count_ok_");
        let lengths = generated_blocks(record, owner, ".Lbounded_plan_length_ok_");
        let found = generated_blocks(record, owner, ".Lbounded_plan_element_found_");
        let done = generated_blocks(record, owner, ".Lbounded_plan_load_done_");
        let exact = generated_blocks(record, owner, ".Lbounded_output_count_exact_");
        let type_only = generated_blocks(record, owner, ".Lbounded_output_type_only_");
        let capacity_ok = generated_blocks(record, owner, ".Lbounded_output_capacity_ok_");
        let expected = owner_contracts.len();
        if headers.len() != expected
            || magic.len() != expected * 8
            || counts.len() != expected
            || lengths.len() != expected
            || found.len() != expected
            || done.len() != expected
            || exact.len() != expected
            || type_only.len() != expected
            || capacity_ok.len() != expected
        {
            return Err(bounded_output_machine_error(format!(
                "entry '{owner}' does not have one complete decoder and output verifier per typed contract"
            )));
        }
        for (index, contract) in owner_contracts.into_iter().enumerate() {
            validate_one_bounded_output_machine_contract(
                record,
                elf,
                contract,
                headers[index],
                &magic[index * 8..index * 8 + 8],
                counts[index],
                lengths[index],
                found[index],
                done[index],
                exact[index],
                type_only[index],
                capacity_ok[index],
            )?;
        }
    }
    Ok(())
}

fn bounded_output_contracts_from_metadata(
    metadata: &Value,
    record: &VerifiedLoweringRecord,
) -> Result<Vec<BoundedOutputMachineContract>, CheckerError> {
    fn text<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
        value.get(field).and_then(Value::as_str)
    }
    fn number(value: &Value, field: &str) -> Option<u64> {
        value.get(field).and_then(Value::as_u64)
    }
    let Some(collections) =
        metadata.get("runtime").and_then(|runtime| runtime.get("collection_instantiations")).and_then(Value::as_array)
    else {
        return Ok(Vec::new());
    };
    let mut contracts = Vec::new();
    for collection in collections {
        let Some(contract) = collection.get("bounded_output_plan") else {
            continue;
        };
        if text(collection, "scope_kind") != Some("action")
            || text(collection, "status") != Some("checked-runtime")
            || text(collection, "source") != Some("witness")
            || text(collection, "ownership") != Some("bounded-output-plan")
            || text(collection, "evidence_tier") != Some("checked-runtime")
            || text(contract, "schema") != Some("cellscript-bounded-output-plan-contract")
            || number(contract, "version") != Some(1)
            || text(contract, "codec") != Some("molecule-fixvec-fixed-item-v1")
            || text(contract, "codec_magic_hex") != Some("0x435342504c763100")
            || text(contract, "placement") != Some("entry-witness-args-v1-param-payload")
            || contract.get("allow_zero").and_then(Value::as_bool) != Some(true)
            || text(contract, "output_source") != Some("ckb-group-output")
            || text(contract, "ordering") != Some("plan-index-equals-group-output-index")
            || text(contract, "correspondence") != Some("exactly-one-group-output-per-plan-element")
            || text(contract, "type_script_policy") != Some("exact-current-script-hash")
            || text(contract, "lock_policy") != Some("exact-plan-field-hash")
            || text(contract, "identity_policy") != Some("fresh-output-outpoint-plus-type-group-ordinal")
        {
            return Err(bounded_output_machine_error("metadata bounded output contract identity is invalid"));
        }
        let scope_name = text(collection, "scope_name")
            .ok_or_else(|| bounded_output_machine_error("bounded output metadata has no action name"))?;
        let element_type =
            text(contract, "element_ty").ok_or_else(|| bounded_output_machine_error("bounded output metadata has no Plan type"))?;
        let output_type =
            text(contract, "output_ty").ok_or_else(|| bounded_output_machine_error("bounded output metadata has no Resource type"))?;
        let maximum =
            number(contract, "max_elements").ok_or_else(|| bounded_output_machine_error("bounded output metadata has no maximum"))?;
        let element_width = number(contract, "element_width_bytes")
            .ok_or_else(|| bounded_output_machine_error("bounded output metadata has no Plan width"))?;
        let output_width = number(contract, "output_width_bytes")
            .ok_or_else(|| bounded_output_machine_error("bounded output metadata has no output width"))?;
        let capacity_floor = number(contract, "capacity_floor_shannons")
            .ok_or_else(|| bounded_output_machine_error("bounded output metadata has no capacity floor"))?;
        if !(1..=1024).contains(&maximum)
            || element_width == 0
            || maximum.checked_mul(element_width).and_then(|bytes| bytes.checked_add(12)).is_none_or(|bytes| bytes > 4084)
            || !(1..=512).contains(&output_width)
            || capacity_floor == 0
            || number(collection, "max_elements") != Some(maximum)
            || number(collection, "element_width_bytes") != Some(element_width)
            || number(collection, "output_cardinality_max") != Some(maximum)
        {
            return Err(bounded_output_machine_error("metadata bounded output resource bounds are invalid"));
        }
        let plan_layout = record
            .typed_semantics
            .types
            .iter()
            .find(|ty| ty.name == element_type && ty.kind == "struct" && ty.encoded_size == u32::try_from(element_width).ok())
            .ok_or_else(|| bounded_output_machine_error("metadata Plan layout does not match typed semantics"))?;
        let output_layout = record
            .typed_semantics
            .types
            .iter()
            .find(|ty| {
                ty.name == output_type
                    && ty.kind == "resource"
                    && ty.identity_policy == "none"
                    && ty.encoded_size == u32::try_from(output_width).ok()
            })
            .ok_or_else(|| bounded_output_machine_error("metadata Resource layout does not match typed semantics"))?;
        let field_bindings = contract
            .get("field_bindings")
            .and_then(Value::as_array)
            .filter(|bindings| bindings.len() == output_layout.fields.len() && !bindings.is_empty())
            .ok_or_else(|| bounded_output_machine_error("metadata field bindings are incomplete"))?;
        let mut seen = BTreeSet::new();
        let mut covered = vec![false; output_width as usize];
        for binding in field_bindings {
            let output_field_name = text(binding, "output_field")
                .ok_or_else(|| bounded_output_machine_error("metadata field binding has no output field"))?;
            let plan_field_name =
                text(binding, "plan_field").ok_or_else(|| bounded_output_machine_error("metadata field binding has no Plan field"))?;
            let output_offset = number(binding, "output_offset_bytes");
            let plan_offset = number(binding, "plan_offset_bytes");
            let width = number(binding, "width_bytes");
            let binding_type = text(binding, "ty");
            let output_field = output_layout.fields.iter().find(|field| field.name == output_field_name);
            let plan_field = plan_layout.fields.iter().find(|field| field.name == plan_field_name);
            if !seen.insert(output_field_name)
                || output_field.is_none_or(|field| {
                    Some(u64::from(field.offset)) != output_offset
                        || field.width_bytes.map(u64::from) != width
                        || binding_type.is_none_or(|ty| canonical_abi_type(ty) != canonical_abi_type(&field.ty))
                })
                || plan_field.is_none_or(|field| {
                    Some(u64::from(field.offset)) != plan_offset
                        || field.width_bytes.map(u64::from) != width
                        || binding_type.is_none_or(|ty| canonical_abi_type(ty) != canonical_abi_type(&field.ty))
                })
            {
                return Err(bounded_output_machine_error("metadata field binding does not match typed fixed layouts"));
            }
            let Some((start, end)) = output_offset.zip(width).and_then(|(offset, width)| {
                let start = usize::try_from(offset).ok()?;
                let end = usize::try_from(offset.checked_add(width)?).ok()?;
                (end <= covered.len()).then_some((start, end))
            }) else {
                return Err(bounded_output_machine_error("metadata field binding is outside output data"));
            };
            for byte in &mut covered[start..end] {
                if *byte {
                    return Err(bounded_output_machine_error("metadata output field bindings overlap"));
                }
                *byte = true;
            }
        }
        if covered.iter().any(|covered| !covered) {
            return Err(bounded_output_machine_error("metadata output field bindings do not cover exact output data"));
        }
        let lock = contract
            .get("lock_binding")
            .ok_or_else(|| bounded_output_machine_error("metadata bounded output contract has no lock binding"))?;
        let lock_name = text(lock, "plan_field");
        let lock_offset = number(lock, "plan_offset_bytes");
        let lock_width = number(lock, "width_bytes");
        let lock_type = text(lock, "ty");
        if lock_width != Some(32)
            || plan_layout.fields.iter().find(|field| Some(field.name.as_str()) == lock_name).is_none_or(|field| {
                Some(u64::from(field.offset)) != lock_offset
                    || field.width_bytes.map(u64::from) != lock_width
                    || !matches!(canonical_abi_type(lock_type.unwrap_or_default()).as_str(), "address" | "hash")
            })
        {
            return Err(bounded_output_machine_error("metadata lock binding does not match a 32-byte Plan field"));
        }
        contracts.push(BoundedOutputMachineContract {
            owner: format!("action:{scope_name}"),
            maximum,
            element_width,
            output_width,
            capacity_floor,
            field_count: field_bindings.len(),
            lock_plan_offset: lock_offset.expect("validated bounded output lock offset"),
        });
    }
    Ok(contracts)
}

#[allow(clippy::too_many_arguments)]
fn validate_one_bounded_output_machine_contract(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    contract: &BoundedOutputMachineContract,
    header: &LoweringBlock,
    magic: &[&LoweringBlock],
    count_ok: &LoweringBlock,
    length_ok: &LoweringBlock,
    found: &LoweringBlock,
    done: &LoweringBlock,
    exact: &LoweringBlock,
    type_only: &LoweringBlock,
    capacity_ok: &LoweringBlock,
) -> Result<(), CheckerError> {
    if magic.len() != 8
        || !(header.range.start < magic[0].range.start
            && magic.windows(2).all(|pair| pair[0].range.start < pair[1].range.start)
            && magic[7].range.start < count_ok.range.start
            && count_ok.range.start < length_ok.range.start
            && length_ok.range.start < found.range.start
            && found.range.start < done.range.start)
    {
        return Err(bounded_output_machine_error("bounded Plan decoder blocks are not in canonical order"));
    }

    let plan_pointer_offset = ld_stack_offset(bounded_word(elf, header.range.start - 24)?, 29)
        .ok_or_else(|| bounded_output_machine_error("bounded Plan decoder does not load its exact witness pointer"))?;
    let _plan_size_offset = ld_stack_offset(bounded_word(elf, header.range.start - 20)?, 30)
        .ok_or_else(|| bounded_output_machine_error("bounded Plan decoder does not load its exact witness length"))?;
    if !is_ld(bounded_word(elf, header.range.start - 20)?, 30, 2, _plan_size_offset)
        || !is_addi(bounded_word(elf, header.range.start - 16)?, 5, 0, 12)
        || !is_sltu(bounded_word(elf, header.range.start - 12)?, 7, 30, 5)
        || !is_beq(bounded_word(elf, header.range.start - 8)?, 7, 0)
        || !flow_targets(elf, header.range.start - 8, header.range.start)
        || !jump_targets_runtime_error(record, elf, header.range.start - 4, 25)
    {
        return Err(bounded_output_machine_error("bounded Plan header no longer requires the exact 12-byte minimum"));
    }
    for (byte_index, (block, expected)) in magic.iter().zip(b"CSBPLv1\0").enumerate() {
        let start = block.range.start;
        if !is_lbu(bounded_word(elf, start - 20)?, 5, 29, byte_index as i32)
            || !is_addi(bounded_word(elf, start - 16)?, 6, 0, i32::from(*expected))
            || !is_sub(bounded_word(elf, start - 12)?, 7, 5, 6)
            || !is_beq(bounded_word(elf, start - 8)?, 7, 0)
            || !flow_targets(elf, start - 8, start)
            || !jump_targets_runtime_error(record, elf, start - 4, 25)
        {
            return Err(bounded_output_machine_error("bounded Plan magic comparison is incomplete"));
        }
    }

    let maximum = i32::try_from(contract.maximum)
        .map_err(|_| bounded_output_machine_error("bounded Plan maximum does not fit a machine immediate"))?;
    if !is_addi(bounded_word(elf, count_ok.range.start - 16)?, 5, 0, maximum)
        || !is_sltu(bounded_word(elf, count_ok.range.start - 12)?, 7, 5, 28)
        || !is_beq(bounded_word(elf, count_ok.range.start - 8)?, 7, 0)
        || !flow_targets(elf, count_ok.range.start - 8, count_ok.range.start)
        || !jump_targets_runtime_error(record, elf, count_ok.range.start - 4, 21)
    {
        return Err(bounded_output_machine_error("bounded Plan count is not the typed count <= N contract"));
    }
    let width = i32::try_from(contract.element_width)
        .map_err(|_| bounded_output_machine_error("bounded Plan width does not fit a machine immediate"))?;
    if !is_addi(bounded_word(elf, length_ok.range.start - 24)?, 5, 0, width)
        || !is_mul(bounded_word(elf, length_ok.range.start - 20)?, 6, 28, 5)
        || !is_addi(bounded_word(elf, length_ok.range.start - 16)?, 6, 6, 12)
        || !is_sub(bounded_word(elf, length_ok.range.start - 12)?, 7, 30, 6)
        || !is_beq(bounded_word(elf, length_ok.range.start - 8)?, 7, 0)
        || !flow_targets(elf, length_ok.range.start - 8, length_ok.range.start)
        || !jump_targets_runtime_error(record, elf, length_ok.range.start - 4, 25)
    {
        return Err(bounded_output_machine_error("bounded Plan does not enforce exact 12 + count * width length"));
    }
    let index_offset = ld_stack_offset(bounded_word(elf, length_ok.range.start)?, 5)
        .ok_or_else(|| bounded_output_machine_error("bounded Plan loop ordinal is not loaded from its typed stack slot"))?;
    let found_words = instructions_from_bounded(elf, found.range.start, 10)?;
    let destination_offset = sd_stack_offset(found_words[5].word, 29)
        .ok_or_else(|| bounded_output_machine_error("bounded Plan element pointer is not stored"))?;
    let element_size_offset = sd_stack_offset(found_words[7].word, 6)
        .ok_or_else(|| bounded_output_machine_error("bounded Plan element width is not stored"))?;
    let presence_offset = sd_stack_offset(found_words[9].word, 6)
        .ok_or_else(|| bounded_output_machine_error("bounded Plan presence bit is not stored"))?;
    if !is_addi(found_words[0].word, 6, 0, width)
        || !is_mul(found_words[1].word, 7, 5, 6)
        || !is_addi(found_words[2].word, 7, 7, 12)
        || !is_ld(found_words[3].word, 29, 2, plan_pointer_offset)
        || !is_add(found_words[4].word, 29, 29, 7)
        || !is_addi(found_words[6].word, 6, 0, width)
        || !is_addi(found_words[8].word, 6, 0, 1)
        || destination_offset == element_size_offset
        || destination_offset == presence_offset
        || element_size_offset == presence_offset
        || found.range.end != done.range.start
    {
        return Err(bounded_output_machine_error("bounded Plan element pointer/width/presence result is not canonical"));
    }

    let owner_sites = record
        .syscall_sites
        .iter()
        .filter(|site| block_for_address(record, site.address).is_some_and(|block| block.owner_entry == contract.owner))
        .collect::<Vec<_>>();
    let end_site = owner_sites
        .iter()
        .copied()
        .filter(|site| done.range.start < site.address && site.address < exact.range.start)
        .max_by_key(|site| site.address)
        .ok_or_else(|| bounded_output_machine_error("bounded output exact-count check has no GroupOutput capacity probe"))?;
    let end_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        end_site.address,
        CKB_LOAD_CELL_BY_FIELD,
        Some(CKB_GROUP_OUTPUT),
        Some(0),
        Some(8),
    )?;
    if !is_addi(bounded_word(elf, exact.range.start - 16)?, 5, 0, 1)
        || !is_sub(bounded_word(elf, exact.range.start - 12)?, 6, 10, 5)
        || !is_beq(bounded_word(elf, exact.range.start - 8)?, 6, 0)
        || !flow_targets(elf, exact.range.start - 8, exact.range.start)
        || !jump_targets_runtime_error(record, elf, exact.range.start - 4, 21)
    {
        return Err(bounded_output_machine_error(
            "bounded output count no longer requires the first absent GroupOutput at the plan count",
        ));
    }

    let verify_sites = owner_sites
        .iter()
        .copied()
        .filter(|site| exact.range.end <= site.address && site.address < capacity_ok.range.start)
        .collect::<Vec<_>>();
    if verify_sites.len() != 4 {
        return Err(bounded_output_machine_error(
            "bounded output verification must contain data, current-Script, Lock-hash, and capacity syscalls",
        ));
    }
    let data_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        verify_sites[0].address,
        CKB_LOAD_CELL_DATA,
        Some(CKB_GROUP_OUTPUT),
        None,
        Some(512),
    )?;
    validate_bounded_output_syscall_result(record, elf, verify_sites[0].address, data_abi.size_offset, contract.output_width, 21)?;
    let current_abi =
        validate_bounded_group_input_syscall(record, elf, verify_sites[1].address, CKB_LOAD_SCRIPT_HASH, None, None, Some(32))?;
    validate_bounded_output_syscall_result(record, elf, verify_sites[1].address, current_abi.size_offset, 32, 1)?;
    let lock_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        verify_sites[2].address,
        CKB_LOAD_CELL_BY_FIELD,
        Some(CKB_GROUP_OUTPUT),
        Some(3),
        Some(32),
    )?;
    validate_bounded_output_syscall_result(record, elf, verify_sites[2].address, lock_abi.size_offset, 32, 12)?;
    let capacity_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        verify_sites[3].address,
        CKB_LOAD_CELL_BY_FIELD,
        Some(CKB_GROUP_OUTPUT),
        Some(0),
        Some(8),
    )?;
    validate_bounded_output_syscall_result(record, elf, verify_sites[3].address, capacity_abi.size_offset, 8, 26)?;
    if data_abi.index_offset != Some(index_offset)
        || lock_abi.index_offset != Some(index_offset)
        || capacity_abi.index_offset != Some(index_offset)
        || end_abi.index_offset != Some(index_offset)
    {
        return Err(bounded_output_machine_error(
            "plan decode, data, Lock, capacity, and exact-count probes do not share one group-relative ordinal",
        ));
    }

    let data_error_guards = elf
        .instructions
        .iter()
        .filter(|instruction| verify_sites[0].address + 32 <= instruction.address && instruction.address < verify_sites[1].address)
        .filter(|instruction| jump_targets_runtime_error(record, elf, instruction.address, 3))
        .collect::<Vec<_>>();
    if data_error_guards.len() != contract.field_count
        || data_error_guards.iter().any(|instruction| !guarded_runtime_error_jump(elf, instruction.address))
    {
        return Err(bounded_output_machine_error(
            "bounded output data does not have one guarded exact comparison for every typed field",
        ));
    }

    let role_words = instructions_from_bounded(elf, type_only.range.start - 68, 17)?;
    if !is_ld(role_words[0].word, 5, 2, lock_abi.buffer_offset)
        || !is_ld(role_words[1].word, 6, 2, current_abi.buffer_offset)
        || !is_sub(role_words[2].word, 7, 5, 6)
    {
        return Err(bounded_output_machine_error("bounded output Lock/Type role comparison does not start at word zero"));
    }
    for word_index in 1..4 {
        let start = 3 + (word_index - 1) * 4;
        let byte_offset =
            i32::try_from(word_index * 8).map_err(|_| bounded_output_machine_error("bounded output hash word offset overflowed"))?;
        if !is_ld(role_words[start].word, 5, 2, lock_abi.buffer_offset + byte_offset)
            || !is_ld(role_words[start + 1].word, 6, 2, current_abi.buffer_offset + byte_offset)
            || !is_sub(role_words[start + 2].word, 5, 5, 6)
            || !is_or(role_words[start + 3].word, 7, 7, 5)
        {
            return Err(bounded_output_machine_error("bounded output Lock/Type role comparison omits a hash word"));
        }
    }
    if !is_bne(role_words[15].word, 7, 0)
        || !flow_targets(elf, role_words[15].address, type_only.range.start)
        || !jump_targets_runtime_error(record, elf, role_words[16].address, 47)
    {
        return Err(bounded_output_machine_error(
            "bounded GroupOutput Lock hash is no longer required to differ from the current Type Script hash",
        ));
    }
    let lock_value_errors = elf
        .instructions
        .iter()
        .filter(|instruction| type_only.range.start <= instruction.address && instruction.address < verify_sites[3].address)
        .filter(|instruction| jump_targets_runtime_error(record, elf, instruction.address, 12))
        .collect::<Vec<_>>();
    if lock_value_errors.len() != 1 || !guarded_runtime_error_jump(elf, lock_value_errors[0].address) {
        return Err(bounded_output_machine_error("bounded output Lock hash is not compared with the exact Plan field"));
    }
    let lock_start = type_only.range.start;
    let lock_end = lock_value_errors[0].address;
    let pointer_load = elf
        .instructions
        .iter()
        .find(|instruction| {
            lock_start <= instruction.address && instruction.address < lock_end && is_ld(instruction.word, 11, 2, destination_offset)
        })
        .ok_or_else(|| {
            bounded_output_machine_error("bounded output Lock comparison does not load the decoded Plan element pointer")
        })?;
    let pointer_ready = if contract.lock_plan_offset == 0 {
        pointer_load.address
    } else if contract.lock_plan_offset <= 2047 {
        let address = pointer_load.address + 4;
        let offset = i32::try_from(contract.lock_plan_offset)
            .map_err(|_| bounded_output_machine_error("bounded output Lock Plan offset does not fit a machine immediate"))?;
        if !is_addi(bounded_word(elf, address)?, 11, 11, offset) {
            return Err(bounded_output_machine_error("bounded output Lock comparison uses the wrong Plan field offset"));
        }
        address
    } else {
        let block = block_for_address(record, pointer_load.address)
            .ok_or_else(|| bounded_output_machine_error("bounded output Lock pointer adjustment is outside machine coverage"))?;
        elf.instructions
            .iter()
            .filter(|instruction| pointer_load.address < instruction.address && instruction.address < lock_end)
            .find(|instruction| {
                let word = instruction.word;
                if word & 0x7f != 0x33 || (word >> 7) & 0x1f != 11 || (word >> 15) & 0x1f != 11 {
                    return false;
                }
                let scratch = (word >> 20) & 0x1f;
                register_constant_before(elf, block, instruction.address, scratch as usize) == Some(contract.lock_plan_offset)
            })
            .map(|instruction| instruction.address)
            .ok_or_else(|| bounded_output_machine_error("bounded output Lock comparison uses the wrong large Plan field offset"))?
    };
    let comparison = elf
        .instructions
        .iter()
        .find(|instruction| {
            pointer_ready < instruction.address
                && instruction.address + 20 < lock_end
                && is_addi(instruction.word, 10, 2, data_abi.buffer_offset)
                && bounded_word(elf, instruction.address + 4).is_ok_and(|word| is_addi(word, 12, 0, 32))
                && bounded_word(elf, instruction.address + 8).is_ok_and(|word| is_auipc(word, 1))
                && bounded_word(elf, instruction.address + 12).is_ok_and(is_jalr_call)
                && bounded_word(elf, instruction.address + 16).is_ok_and(|word| is_bne(word, 10, 0))
        })
        .ok_or_else(|| bounded_output_machine_error("bounded output Lock comparison is not an exact 32-byte Plan-field comparison"))?;
    if !flow_targets(elf, comparison.address + 16, lock_value_errors[0].address) {
        return Err(bounded_output_machine_error("bounded output Lock mismatch branch no longer reaches error 12"));
    }
    let capacity_branch = capacity_ok.range.start - 8;
    let branch_block = block_for_address(record, capacity_branch)
        .ok_or_else(|| bounded_output_machine_error("bounded output capacity comparison is outside machine coverage"))?;
    if !is_bgeu(bounded_word(elf, capacity_branch)?, 5, 6)
        || !flow_targets(elf, capacity_branch, capacity_ok.range.start)
        || register_constant_before(elf, branch_block, capacity_branch, 6) != Some(contract.capacity_floor)
        || !jump_targets_runtime_error(record, elf, capacity_ok.range.start - 4, 26)
    {
        return Err(bounded_output_machine_error(
            "bounded output capacity is not checked against the metadata-declared positive floor",
        ));
    }
    for code in [1, 3, 4, 12, 21, 25, 26, 47] {
        if !owner_has_abort_error(record, elf, &contract.owner, code) {
            return Err(bounded_output_machine_error(format!(
                "entry '{}' no longer has stable bounded output runtime error {code}",
                contract.owner
            )));
        }
    }
    Ok(())
}

fn validate_bounded_output_syscall_result(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    address: u64,
    size_offset: i32,
    expected_width: u64,
    status_error: i32,
) -> Result<(), CheckerError> {
    let width = i32::try_from(expected_width)
        .map_err(|_| bounded_output_machine_error("bounded output syscall width does not fit a machine immediate"))?;
    if !is_beq(bounded_word(elf, address + 4)?, 10, 0)
        || !flow_targets(elf, address + 4, address + 12)
        || !jump_targets_runtime_error(record, elf, address + 8, status_error)
        || !is_ld(bounded_word(elf, address + 12)?, 10, 2, size_offset)
        || !is_addi(bounded_word(elf, address + 16)?, 11, 0, width)
        || !is_sub(bounded_word(elf, address + 20)?, 10, 10, 11)
        || !is_beq(bounded_word(elf, address + 24)?, 10, 0)
        || !flow_targets(elf, address + 24, address + 32)
        || !jump_targets_runtime_error(record, elf, address + 28, 4)
    {
        return Err(bounded_output_machine_error("bounded output syscall no longer requires success and its exact typed width"));
    }
    Ok(())
}

fn guarded_runtime_error_jump(elf: &ParsedElf, address: u64) -> bool {
    let prior = elf.control_flow.iter().filter(|edge| edge.address + 8 >= address && edge.address < address).collect::<Vec<_>>();
    prior.iter().any(|edge| bounded_word(elf, edge.address).is_ok_and(|word| word & 0x7f == 0x63) && edge.target >= address)
}

fn bounded_output_machine_error(message: impl Into<String>) -> CheckerError {
    CheckerError::new(
        CheckerRejectionCode::V2420TypedMachineBindingInvalid,
        format!("bounded GroupOutput machine contract: {}", message.into()),
    )
}

fn validate_bounded_group_input_machine_contract(record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    let mut contracts = Vec::new();
    for entry in &record.typed_semantics.entries {
        for block in &entry.blocks {
            for operation in &block.operations {
                if operation.opcode != "bounded-cell-load" {
                    continue;
                }
                let TypedSemanticOperationDetail::Collection { declared_type } = &operation.detail else {
                    return Err(bounded_group_input_machine_error("bounded Cell load has no collection contract"));
                };
                let (element, maximum) = parse_bounded_cell_set_contract(declared_type)
                    .ok_or_else(|| bounded_group_input_machine_error("bounded Cell load has an invalid declared type"))?;
                let element_width = record
                    .typed_semantics
                    .types
                    .iter()
                    .find(|ty| ty.name == element)
                    .and_then(|ty| ty.encoded_size)
                    .map(u64::from)
                    .ok_or_else(|| bounded_group_input_machine_error("bounded Cell element has no fixed encoded width"))?;
                contracts.push(BoundedGroupInputMachineContract { owner: entry.id.as_str(), maximum, element_width });
            }
        }
    }
    if contracts.is_empty() {
        return Ok(());
    }

    let owners = contracts.iter().map(|contract| contract.owner).collect::<BTreeSet<_>>();
    for owner in owners {
        let owner_contracts = contracts.iter().filter(|contract| contract.owner == owner).collect::<Vec<_>>();
        let loaded = generated_blocks(record, owner, ".Lbounded_cell_loaded_");
        let count_ok = generated_blocks(record, owner, ".Lbounded_cell_count_ok_");
        let out_of_bound = generated_blocks(record, owner, ".Lbounded_cell_out_of_bound_");
        let done = generated_blocks(record, owner, ".Lbounded_cell_load_done_");
        if loaded.len() != owner_contracts.len()
            || count_ok.len() != owner_contracts.len()
            || out_of_bound.len() != owner_contracts.len()
            || done.len() != owner_contracts.len()
        {
            return Err(bounded_group_input_machine_error(format!(
                "entry '{owner}' does not have one complete machine scan for each typed bounded Cell load"
            )));
        }
        for (index, contract) in owner_contracts.into_iter().enumerate() {
            validate_one_bounded_group_input_machine_contract(
                record,
                elf,
                contract,
                loaded[index],
                count_ok[index],
                out_of_bound[index],
                done[index],
            )?;
        }
    }
    Ok(())
}

fn parse_bounded_cell_set_contract(declared_type: &str) -> Option<(&str, u64)> {
    let body = declared_type.strip_prefix("BoundedCellSet<")?.strip_suffix('>')?;
    let (element, maximum) = body.rsplit_once(',')?;
    Some((element.trim(), maximum.trim().parse().ok()?))
}

fn generated_blocks<'a>(record: &'a VerifiedLoweringRecord, owner: &str, prefix: &str) -> Vec<&'a LoweringBlock> {
    let mut blocks = record
        .blocks
        .iter()
        .filter(|block| {
            block.owner_entry == owner && block.machine_label.as_deref().is_some_and(|label| generated_label(label, prefix))
        })
        .collect::<Vec<_>>();
    blocks.sort_by_key(|block| block.range.start);
    blocks
}

fn validate_one_bounded_group_input_machine_contract(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    contract: &BoundedGroupInputMachineContract<'_>,
    loaded: &LoweringBlock,
    count_ok: &LoweringBlock,
    out_of_bound: &LoweringBlock,
    done: &LoweringBlock,
) -> Result<(), CheckerError> {
    if !(loaded.range.start < count_ok.range.start
        && count_ok.range.start < out_of_bound.range.start
        && out_of_bound.range.start < done.range.start)
    {
        return Err(bounded_group_input_machine_error("bounded Cell scan blocks are not in canonical order"));
    }
    let data_site = record
        .syscall_sites
        .iter()
        .filter(|site| site.address < loaded.range.start)
        .filter(|site| block_for_address(record, site.address).is_some_and(|block| block.owner_entry == contract.owner))
        .max_by_key(|site| site.address)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell scan has no LOAD_CELL_DATA syscall"))?;
    let identity_sites = record
        .syscall_sites
        .iter()
        .filter(|site| loaded.range.start < site.address && site.address < done.range.start)
        .collect::<Vec<_>>();
    if identity_sites.len() != 3 {
        return Err(bounded_group_input_machine_error(
            "bounded Cell scan must contain current-Script, Type-hash, and Lock-hash syscalls",
        ));
    }
    let data_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        data_site.address,
        CKB_LOAD_CELL_DATA,
        Some(CKB_GROUP_INPUT),
        None,
        Some(512),
    )?;
    let current_hash_abi =
        validate_bounded_group_input_syscall(record, elf, identity_sites[0].address, CKB_LOAD_SCRIPT_HASH, None, None, Some(32))?;
    let type_hash_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        identity_sites[1].address,
        CKB_LOAD_CELL_BY_FIELD,
        Some(CKB_GROUP_INPUT),
        Some(5),
        Some(32),
    )?;
    let lock_hash_abi = validate_bounded_group_input_syscall(
        record,
        elf,
        identity_sites[2].address,
        CKB_LOAD_CELL_BY_FIELD,
        Some(CKB_GROUP_INPUT),
        Some(3),
        Some(32),
    )?;
    let index_offset = data_abi
        .index_offset
        .ok_or_else(|| bounded_group_input_machine_error("LOAD_CELL_DATA does not use the typed loop ordinal"))?;
    if type_hash_abi.index_offset != Some(index_offset) || lock_hash_abi.index_offset != Some(index_offset) {
        return Err(bounded_group_input_machine_error(
            "bounded Cell data, Type hash, and Lock hash syscalls do not use the same typed loop ordinal",
        ));
    }

    let data = data_site.address;
    if !is_beq(bounded_word(elf, data + 4)?, 10, 0)
        || !flow_targets(elf, data + 4, loaded.range.start)
        || !is_addi(bounded_word(elf, data + 8)?, 5, 0, 1)
        || !is_sub(bounded_word(elf, data + 12)?, 6, 10, 5)
        || !is_beq(bounded_word(elf, data + 16)?, 6, 0)
        || !flow_targets(elf, data + 16, out_of_bound.range.start)
        || !jump_targets_runtime_error(record, elf, data + 20, 3)
    {
        return Err(bounded_group_input_machine_error(
            "LOAD_CELL_DATA status no longer distinguishes success, end-of-group, and failure",
        ));
    }

    let maximum = i32::try_from(contract.maximum)
        .map_err(|_| bounded_group_input_machine_error("bounded Cell maximum does not fit its machine immediate"))?;
    let loaded_words = instructions_from_bounded(elf, loaded.range.start, 4)?;
    if !is_ld(loaded_words[0].word, 28, 2, index_offset)
        || !is_addi(loaded_words[1].word, 5, 0, maximum)
        || !is_sltu(loaded_words[2].word, 6, 28, 5)
        || !is_bne(loaded_words[3].word, 6, 0)
        || !flow_targets(elf, loaded_words[3].address, count_ok.range.start)
        || !jump_targets_runtime_error(record, elf, loaded.range.end, 21)
    {
        return Err(bounded_group_input_machine_error("runtime cardinality is not the typed strict index < N contract"));
    }

    let width = i32::try_from(contract.element_width)
        .map_err(|_| bounded_group_input_machine_error("bounded Cell width does not fit its machine immediate"))?;
    let count_words = instructions_from_bounded(elf, count_ok.range.start, 4)?;
    if !is_ld(count_words[0].word, 10, 2, data_abi.size_offset)
        || !is_addi(count_words[1].word, 11, 0, width)
        || !is_sub(count_words[2].word, 10, 10, 11)
        || !is_beq(count_words[3].word, 10, 0)
        || !jump_targets_runtime_error(record, elf, count_ok.range.end, 4)
    {
        return Err(bounded_group_input_machine_error("bounded Cell data is no longer decoded with the typed exact width"));
    }

    let type_words = generated_blocks(record, contract.owner, ".Lbounded_cell_type_word_ok_")
        .into_iter()
        .filter(|block| loaded.range.start < block.range.start && block.range.start < done.range.start)
        .collect::<Vec<_>>();
    if type_words.len() != 4 {
        return Err(bounded_group_input_machine_error("bounded Cell Type-hash identity must compare all four 64-bit words"));
    }
    for (word_index, block) in type_words.into_iter().enumerate() {
        let start = block.range.start;
        let byte_offset = i32::try_from(word_index * 8)
            .map_err(|_| bounded_group_input_machine_error("bounded Cell Type-hash word offset overflowed"))?;
        if !is_ld(bounded_word(elf, start - 20)?, 5, 2, type_hash_abi.buffer_offset + byte_offset)
            || !is_ld(bounded_word(elf, start - 16)?, 6, 2, current_hash_abi.buffer_offset + byte_offset)
            || !is_sub(bounded_word(elf, start - 12)?, 7, 5, 6)
            || !is_beq(bounded_word(elf, start - 8)?, 7, 0)
            || !flow_targets(elf, start - 8, start)
            || !jump_targets_runtime_error(record, elf, start - 4, 17)
        {
            return Err(bounded_group_input_machine_error("bounded Cell Type-hash identity comparison is incomplete"));
        }
    }

    let lock_distinct = generated_blocks(record, contract.owner, ".Lbounded_cell_lock_is_distinct_")
        .into_iter()
        .find(|block| loaded.range.start < block.range.start && block.range.start < done.range.start)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell scan has no Lock/Type role separation"))?;
    validate_bounded_hash_syscall_result(record, elf, identity_sites[0].address, current_hash_abi.size_offset, 1)?;
    validate_bounded_hash_syscall_result(record, elf, identity_sites[1].address, type_hash_abi.size_offset, 47)?;
    validate_bounded_hash_syscall_result(record, elf, identity_sites[2].address, lock_hash_abi.size_offset, 47)?;

    let lock_fold_start = identity_sites[2].address + 32;
    let lock_fold = instructions_from_bounded(elf, lock_fold_start, 17)?;
    if !is_ld(lock_fold[0].word, 5, 2, lock_hash_abi.buffer_offset)
        || !is_ld(lock_fold[1].word, 6, 2, current_hash_abi.buffer_offset)
        || !is_sub(lock_fold[2].word, 7, 5, 6)
    {
        return Err(bounded_group_input_machine_error("bounded Cell Lock/Type comparison does not begin with word zero"));
    }
    for word_index in 1..4 {
        let start = 3 + (word_index - 1) * 4;
        let byte_offset = i32::try_from(word_index * 8)
            .map_err(|_| bounded_group_input_machine_error("bounded Cell Lock-hash word offset overflowed"))?;
        if !is_ld(lock_fold[start].word, 5, 2, lock_hash_abi.buffer_offset + byte_offset)
            || !is_ld(lock_fold[start + 1].word, 6, 2, current_hash_abi.buffer_offset + byte_offset)
            || !is_sub(lock_fold[start + 2].word, 5, 5, 6)
            || !is_or(lock_fold[start + 3].word, 7, 7, 5)
        {
            return Err(bounded_group_input_machine_error(
                "bounded Cell Lock/Type comparison does not fold all corresponding hash words",
            ));
        }
    }
    if lock_fold[15].address != lock_distinct.range.start - 8
        || !is_bne(lock_fold[15].word, 7, 0)
        || !flow_targets(elf, lock_distinct.range.start - 8, lock_distinct.range.start)
        || lock_fold[16].address != lock_distinct.range.start - 4
        || !jump_targets_runtime_error(record, elf, lock_fold[16].address, 47)
    {
        return Err(bounded_group_input_machine_error(
            "bounded Cell Lock hash is no longer required to differ from the current Type Script hash",
        ));
    }

    let success_words = instructions_from_bounded(elf, lock_distinct.range.start, 5)?;
    let destination_offset = sd_stack_offset(success_words[1].word, 5)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell success does not store its element pointer"))?;
    let found_offset = sd_stack_offset(success_words[3].word, 5)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell success does not store its presence bit"))?;
    if destination_offset == found_offset
        || !is_addi(success_words[0].word, 5, 2, data_abi.buffer_offset)
        || !is_addi(success_words[2].word, 5, 0, 1)
        || !is_jal_zero(success_words[4].word)
        || !flow_targets(elf, success_words[4].address, done.range.start)
        || lock_distinct.range.end != out_of_bound.range.start
    {
        return Err(bounded_group_input_machine_error(
            "bounded Cell success no longer returns the loaded element and canonical presence bit",
        ));
    }

    let out_words = instructions_from_bounded(elf, out_of_bound.range.start, 2)?;
    if !is_sd(out_words[0].word, 0, 2, destination_offset)
        || !is_sd(out_words[1].word, 0, 2, found_offset)
        || out_of_bound.range.end != done.range.start
    {
        return Err(bounded_group_input_machine_error("end-of-group no longer produces the canonical absent element"));
    }
    for code in [1, 3, 4, 17, 21, 47] {
        if !owner_has_abort_error(record, elf, contract.owner, code) {
            return Err(bounded_group_input_machine_error(format!(
                "entry '{}' no longer has stable runtime error {code}",
                contract.owner
            )));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct BoundedGroupInputSyscallAbi {
    buffer_offset: i32,
    size_offset: i32,
    index_offset: Option<i32>,
}

fn validate_bounded_group_input_syscall(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    address: u64,
    syscall: u64,
    source: Option<u64>,
    field: Option<u64>,
    initialized_size: Option<i32>,
) -> Result<BoundedGroupInputSyscallAbi, CheckerError> {
    let block = block_for_address(record, address)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell syscall is outside machine coverage"))?;
    if register_constant_before(elf, block, address, 17) != Some(syscall)
        || register_constant_before(elf, block, address, 12) != Some(0)
        || source.is_some_and(|source| register_constant_before(elf, block, address, 14) != Some(source))
        || field.is_some_and(|field| register_constant_before(elf, block, address, 15) != Some(field))
    {
        return Err(bounded_group_input_machine_error(format!("bounded Cell syscall ABI changed at {address:#x}")));
    }
    let (a0_address, a0_word) = last_register_definition_before(elf, block, address, 10)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell syscall has no a0 buffer definition"))?;
    let (_, a1_word) = last_register_definition_before(elf, block, address, 11)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell syscall has no a1 size definition"))?;
    let buffer_offset = stack_address_offset(a0_word, 10)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell syscall a0 is not a canonical stack buffer"))?;
    let size_offset = stack_address_offset(a1_word, 11)
        .ok_or_else(|| bounded_group_input_machine_error("bounded Cell syscall a1 is not a canonical stack size slot"))?;
    if buffer_offset != size_offset + 8 {
        return Err(bounded_group_input_machine_error("bounded Cell syscall buffer and size slots are not adjacent"));
    }
    if let Some(initialized_size) = initialized_size
        && (a0_address < block.range.start + 8
            || !is_addi(bounded_word(elf, a0_address - 8)?, 5, 0, initialized_size)
            || !is_sd(bounded_word(elf, a0_address - 4)?, 5, 2, size_offset))
    {
        return Err(bounded_group_input_machine_error("bounded Cell syscall size slot is not initialized for its canonical buffer"));
    }

    let index_offset =
        if source.is_some() {
            let (a3_address, a3_word) = last_register_definition_before(elf, block, address, 13)
                .ok_or_else(|| bounded_group_input_machine_error("bounded Cell syscall has no a3 index definition"))?;
            if !is_addi(a3_word, 13, 28, 0) {
                return Err(bounded_group_input_machine_error("bounded Cell syscall a3 is not the typed loop ordinal"));
            }
            let (_, index_word) = last_register_definition_before(elf, block, a3_address, 28)
                .ok_or_else(|| bounded_group_input_machine_error("bounded Cell typed loop ordinal has no stack definition"))?;
            Some(ld_stack_offset(index_word, 28).ok_or_else(|| {
                bounded_group_input_machine_error("bounded Cell typed loop ordinal is not loaded from its stack slot")
            })?)
        } else {
            None
        };
    Ok(BoundedGroupInputSyscallAbi { buffer_offset, size_offset, index_offset })
}

fn validate_bounded_hash_syscall_result(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    address: u64,
    size_offset: i32,
    status_error: i32,
) -> Result<(), CheckerError> {
    if !is_beq(bounded_word(elf, address + 4)?, 10, 0)
        || !flow_targets(elf, address + 4, address + 12)
        || !jump_targets_runtime_error(record, elf, address + 8, status_error)
        || !is_ld(bounded_word(elf, address + 12)?, 10, 2, size_offset)
        || !is_addi(bounded_word(elf, address + 16)?, 11, 0, 32)
        || !is_sub(bounded_word(elf, address + 20)?, 10, 10, 11)
        || !is_beq(bounded_word(elf, address + 24)?, 10, 0)
        || !flow_targets(elf, address + 24, address + 32)
        || !jump_targets_runtime_error(record, elf, address + 28, 4)
    {
        return Err(bounded_group_input_machine_error(
            "bounded Cell identity syscall no longer requires success and an exact 32-byte hash",
        ));
    }
    Ok(())
}

fn last_register_definition_before(elf: &ParsedElf, block: &LoweringBlock, address: u64, register: u32) -> Option<(u64, u32)> {
    elf.instructions
        .iter()
        .filter(|instruction| block.range.start <= instruction.address && instruction.address < address)
        .rev()
        .find(|instruction| instruction_writes_register(instruction.word, register))
        .map(|instruction| (instruction.address, instruction.word))
}

fn instruction_writes_register(word: u32, register: u32) -> bool {
    matches!(word & 0x7f, 0x03 | 0x13 | 0x17 | 0x33 | 0x37 | 0x67 | 0x6f) && (word >> 7) & 0x1f == register
}

fn stack_address_offset(word: u32, register: u32) -> Option<i32> {
    (word & 0x7f == 0x13 && (word >> 12) & 0x7 == 0 && (word >> 7) & 0x1f == register && (word >> 15) & 0x1f == 2)
        .then_some((word as i32) >> 20)
}

fn ld_stack_offset(word: u32, register: u32) -> Option<i32> {
    (word & 0x7f == 0x03 && (word >> 12) & 0x7 == 0x3 && (word >> 7) & 0x1f == register && (word >> 15) & 0x1f == 2)
        .then_some((word as i32) >> 20)
}

fn sd_stack_offset(word: u32, source: u32) -> Option<i32> {
    if word & 0x7f != 0x23 || (word >> 12) & 0x7 != 0x3 || (word >> 20) & 0x1f != source || (word >> 15) & 0x1f != 2 {
        return None;
    }
    let immediate = (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 0x1f);
    Some(((immediate as i32) << 20) >> 20)
}

fn bounded_word(elf: &ParsedElf, address: u64) -> Result<u32, CheckerError> {
    elf.instructions
        .iter()
        .find(|instruction| instruction.address == address)
        .map(|instruction| instruction.word)
        .ok_or_else(|| bounded_group_input_machine_error(format!("missing instruction at {address:#x}")))
}

fn instructions_from_bounded(elf: &ParsedElf, address: u64, count: usize) -> Result<&[crate::elf::DecodedInstruction], CheckerError> {
    let start = elf
        .instructions
        .binary_search_by_key(&address, |instruction| instruction.address)
        .map_err(|_| bounded_group_input_machine_error(format!("missing instruction range at {address:#x}")))?;
    elf.instructions
        .get(start..start.saturating_add(count))
        .ok_or_else(|| bounded_group_input_machine_error(format!("truncated instruction range at {address:#x}")))
}

fn jump_targets_runtime_error(record: &VerifiedLoweringRecord, elf: &ParsedElf, address: u64, code: i32) -> bool {
    let Some(target_address) = elf.control_flow.iter().find(|edge| edge.address == address).map(|edge| edge.target) else {
        return false;
    };
    record.runtime_error_exits.iter().any(|exit| exit.code == code && exit.address == target_address)
        && bounded_word(elf, address).is_ok_and(is_jal_zero)
        && machine_error_jumps_to_abort(record, elf, target_address, code)
}

fn bounded_group_input_machine_error(message: impl Into<String>) -> CheckerError {
    CheckerError::new(
        CheckerRejectionCode::V2420TypedMachineBindingInvalid,
        format!("bounded GroupInput machine contract: {}", message.into()),
    )
}

fn validate_policy_dispatch_machine_contract(record: &VerifiedLoweringRecord, elf: &ParsedElf) -> Result<(), CheckerError> {
    let EntryDispatchContract::PolicyWitnessV1(contract) = &record.typed_semantics.foundation.entry_contract.dispatch else {
        return Ok(());
    };
    let wrapper = record
        .entries
        .iter()
        .find(|entry| entry.id == POLICY_WRAPPER_ENTRY_ID)
        .ok_or_else(|| policy_machine_error("missing policy entry wrapper"))?;
    if wrapper.kind != EntryKind::Wrapper
        || wrapper.name != "_cellscript_entry"
        || wrapper.frame_size_bytes != POLICY_ENTRY_FRAME_BYTES
        || wrapper.outgoing_argument_bytes != 0
        || record
            .blocks
            .iter()
            .filter(|block| block.owner_entry == POLICY_WRAPPER_ENTRY_ID)
            .any(|block| block.frame_size_bytes != POLICY_ENTRY_FRAME_BYTES)
    {
        return Err(policy_machine_error("policy entry wrapper frame or entry contract changed"));
    }

    let fail = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_witness_fail_")?;
    let done = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_entry_done_")?;
    let record_loop = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_record_")?;
    let args_valid = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_record_args_valid_")?;
    let key_loop = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_key_order_loop_")?;
    let ordered = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_key_ordered_")?;
    let hash_loop = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_current_hash_loop_")?;
    let next_record = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_next_record_")?;

    validate_policy_entry_syscalls(record, elf, fail)?;
    validate_policy_envelope_machine_contract(record, elf, fail)?;
    validate_policy_dynvec_machine_contract(elf, record_loop, fail)?;
    validate_policy_record_layout_machine_contract(record, elf, args_valid, fail)?;
    validate_policy_key_order_machine_contract(elf, args_valid, key_loop, ordered, fail)?;
    validate_policy_selector_machine_contract(elf, record_loop, ordered, hash_loop, next_record, fail)?;
    validate_policy_tag_dispatch_machine_contract(record, elf, contract, next_record, fail, done)?;
    validate_policy_action_adapters(record, elf, contract)?;

    if !machine_error_jumps_to_abort(record, elf, fail.range.start, 25) {
        return Err(policy_machine_error("policy rejection no longer terminates with entry-witness error 25"));
    }
    let done_words = instructions_from(elf, done.range.start, 8)?;
    if !matches_large_stack_load(done_words, 0, 1, POLICY_RA_OFFSET)
        || !matches_large_sp_adjust(done_words, 4, POLICY_ENTRY_FRAME_BYTES as i32)
        || done_words.get(7).is_none_or(|instruction| instruction.word != 0x0000_8067)
    {
        return Err(policy_machine_error("policy completion no longer restores the exact wrapper frame"));
    }
    Ok(())
}

fn unique_policy_block<'a>(
    record: &'a VerifiedLoweringRecord,
    owner: &str,
    label_prefix: &str,
) -> Result<&'a LoweringBlock, CheckerError> {
    let mut matches = record.blocks.iter().filter(|block| {
        block.owner_entry == owner && block.machine_label.as_deref().is_some_and(|label| generated_label(label, label_prefix))
    });
    let block =
        matches.next().ok_or_else(|| policy_machine_error(format!("missing machine block '{label_prefix}*' for '{owner}'")))?;
    if matches.next().is_some() {
        return Err(policy_machine_error(format!("ambiguous machine block '{label_prefix}*' for '{owner}'")));
    }
    Ok(block)
}

fn generated_label(label: &str, prefix: &str) -> bool {
    label.strip_prefix(prefix).is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn policy_machine_error(message: impl Into<String>) -> CheckerError {
    CheckerError::new(
        CheckerRejectionCode::V2420TypedMachineBindingInvalid,
        format!("policy dispatch machine contract: {}", message.into()),
    )
}

fn instruction_at(elf: &ParsedElf, address: u64) -> Result<&crate::elf::DecodedInstruction, CheckerError> {
    elf.instructions
        .iter()
        .find(|instruction| instruction.address == address)
        .ok_or_else(|| policy_machine_error(format!("missing instruction at {address:#x}")))
}

fn instructions_from(elf: &ParsedElf, address: u64, count: usize) -> Result<&[crate::elf::DecodedInstruction], CheckerError> {
    let start = elf
        .instructions
        .binary_search_by_key(&address, |instruction| instruction.address)
        .map_err(|_| policy_machine_error(format!("missing instruction range at {address:#x}")))?;
    elf.instructions
        .get(start..start.saturating_add(count))
        .ok_or_else(|| policy_machine_error(format!("truncated instruction range at {address:#x}")))
}

fn flow_targets(elf: &ParsedElf, address: u64, target: u64) -> bool {
    elf.control_flow.iter().any(|edge| edge.address == address && edge.target == target)
}

fn block_for_address(record: &VerifiedLoweringRecord, address: u64) -> Option<&LoweringBlock> {
    record.blocks.iter().find(|block| block.range.contains(address))
}

fn validate_policy_entry_syscalls(record: &VerifiedLoweringRecord, elf: &ParsedElf, fail: &LoweringBlock) -> Result<(), CheckerError> {
    let wrapper_blocks = record.blocks.iter().filter(|block| block.owner_entry == POLICY_WRAPPER_ENTRY_ID).collect::<Vec<_>>();
    let mut sites = elf
        .syscall_addresses
        .iter()
        .copied()
        .filter(|address| wrapper_blocks.iter().any(|block| block.range.contains(*address)))
        .collect::<Vec<_>>();
    sites.sort_unstable();
    if sites.len() != 4 {
        return Err(policy_machine_error(
            "policy selector must use exactly two witness loads, one empty-group probe, and one current Script hash load",
        ));
    }
    let expected = [
        (CKB_LOAD_WITNESS, CKB_GROUP_INPUT, None),
        (CKB_LOAD_CELL_BY_FIELD, CKB_GROUP_INPUT, Some(0_u64)),
        (CKB_LOAD_WITNESS, CKB_GROUP_OUTPUT, None),
        (CKB_LOAD_SCRIPT_HASH, 0, None),
    ];
    for (address, (syscall, source, field)) in sites.iter().copied().zip(expected) {
        let block =
            block_for_address(record, address).ok_or_else(|| policy_machine_error("policy syscall is outside machine coverage"))?;
        if register_constant_before(elf, block, address, 17) != Some(syscall)
            || register_constant_before(elf, block, address, 12) != Some(0)
            || (syscall != CKB_LOAD_SCRIPT_HASH
                && (register_constant_before(elf, block, address, 13) != Some(0)
                    || register_constant_before(elf, block, address, 14) != Some(source)))
            || field.is_some_and(|field| register_constant_before(elf, block, address, 15) != Some(field))
        {
            return Err(policy_machine_error("policy witness/current-Script selector syscall ABI changed"));
        }
    }
    if !is_beq(instruction_at(elf, sites[0] + 4)?.word, 10, 0)
        || !is_addi(instruction_at(elf, sites[1] + 4)?.word, 5, 0, 1)
        || !is_beq(instruction_at(elf, sites[1] + 8)?.word, 10, 5)
        || !is_jal_zero(instruction_at(elf, sites[1] + 12)?.word)
        || !flow_targets(elf, sites[1] + 12, fail.range.start)
        || !is_bne(instruction_at(elf, sites[2] + 4)?.word, 10, 0)
        || !flow_targets(elf, sites[2] + 4, fail.range.start)
        || !is_bne(instruction_at(elf, sites[3] + 4)?.word, 10, 0)
        || !flow_targets(elf, sites[3] + 4, fail.range.start)
    {
        return Err(policy_machine_error("policy syscall status/fallback control flow changed"));
    }
    let output_only = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_output_only_")?;
    let loaded = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_witness_loaded_")?;
    if !flow_targets(elf, sites[0] + 4, loaded.range.start) || !flow_targets(elf, sites[1] + 8, output_only.range.start) {
        return Err(policy_machine_error("policy GroupOutput fallback is no longer gated by an empty GroupInput"));
    }
    Ok(())
}

fn validate_policy_envelope_machine_contract(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    fail: &LoweringBlock,
) -> Result<(), CheckerError> {
    let copied = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lentry_witness_v2_copy_done_")?;
    let current_hash_syscall = elf
        .syscall_addresses
        .iter()
        .copied()
        .find(|address| {
            block_for_address(record, *address).is_some_and(|block| block.owner_entry == POLICY_WRAPPER_ENTRY_ID)
                && block_for_address(record, *address).and_then(|block| register_constant_before(elf, block, *address, 17))
                    == Some(CKB_LOAD_SCRIPT_HASH)
        })
        .ok_or_else(|| policy_machine_error("missing current Script hash syscall"))?;
    let mut has_minimum = false;
    let mut has_maximum = false;
    for instruction in elf
        .instructions
        .iter()
        .filter(|instruction| copied.range.start <= instruction.address && instruction.address < current_hash_syscall)
    {
        let Some(block) = block_for_address(record, instruction.address) else { continue };
        if is_bltu(instruction.word, 5, 6)
            && register_constant_before(elf, block, instruction.address, 6) == Some(77)
            && flow_targets(elf, instruction.address, fail.range.start)
        {
            has_minimum = true;
        }
        if is_bltu(instruction.word, 6, 5)
            && register_constant_before(elf, block, instruction.address, 6) == Some(4_076)
            && flow_targets(elf, instruction.address, fail.range.start)
        {
            has_maximum = true;
        }
    }
    if !has_minimum || !has_maximum {
        return Err(policy_machine_error("policy witness bundle 77..4076-byte bounds changed"));
    }
    let magic_start = elf
        .instructions
        .iter()
        .find(|instruction| {
            copied.range.start <= instruction.address
                && instruction.address < current_hash_syscall
                && is_lbu(instruction.word, 5, 2, 8)
        })
        .map(|instruction| instruction.address)
        .ok_or_else(|| policy_machine_error("missing policy witness magic check"))?;
    for (index, byte) in POLICY_WITNESS_MAGIC.iter().copied().enumerate() {
        let address = magic_start + (index as u64) * 12;
        if !is_lbu(instruction_at(elf, address)?.word, 5, 2, 8 + index as i32)
            || !is_addi(instruction_at(elf, address + 4)?.word, 6, 0, i32::from(byte))
            || !is_bne(instruction_at(elf, address + 8)?.word, 5, 6)
            || !flow_targets(elf, address + 8, fail.range.start)
        {
            return Err(policy_machine_error("canonical CSPOLv1 witness magic changed"));
        }
    }
    let after_hash = instructions_from(elf, current_hash_syscall + 4, 7)?;
    if !is_bne(after_hash[0].word, 10, 0)
        || !flow_targets(elf, after_hash[0].address, fail.range.start)
        || !matches_large_stack_load(after_hash, 1, 5, 4_104)
        || !is_addi(after_hash[5].word, 6, 0, 32)
        || !is_bne(after_hash[6].word, 5, 6)
        || !flow_targets(elf, after_hash[6].address, fail.range.start)
    {
        return Err(policy_machine_error("current Script hash exact-width check changed"));
    }
    Ok(())
}

fn validate_policy_record_layout_machine_contract(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    args_valid: &LoweringBlock,
    fail: &LoweringBlock,
) -> Result<(), CheckerError> {
    let start = elf
        .instructions
        .iter()
        .find(|instruction| {
            instruction.address < args_valid.range.start
                && block_for_address(record, instruction.address).is_some_and(|block| block.owner_entry == POLICY_WRAPPER_ENTRY_ID)
                && is_add(instruction.word, 15, 14, 5)
        })
        .map(|instruction| instruction.address)
        .ok_or_else(|| policy_machine_error("missing policy record base calculation"))?;
    let words = instructions_from(elf, start, 102)?;
    if !matches_u32_le_load(words, 1, 28, 15, 0, 29)
        || !is_bne(words[11].word, 7, 28)
        || !flow_targets(elf, words[11].address, fail.range.start)
    {
        return Err(policy_machine_error("policy record total-size validation changed"));
    }
    let mut cursor = 12;
    for (offset, expected) in [(4, 20), (8, 21), (12, 53), (16, 57)] {
        if !matches_u32_le_load(words, cursor, 28, 15, offset, 29)
            || !is_addi(words[cursor + 10].word, 29, 0, expected)
            || !is_bne(words[cursor + 11].word, 28, 29)
            || !flow_targets(elf, words[cursor + 11].address, fail.range.start)
        {
            return Err(policy_machine_error("policy record Molecule table offsets changed"));
        }
        cursor += 12;
    }
    if !matches_u32_le_load(words, cursor, 28, 15, 57, 29)
        || !is_addi(words[cursor + 10].word, 7, 7, -POLICY_RECORD_FIXED_BYTES)
        || !is_bne(words[cursor + 11].word, 7, 28)
        || !flow_targets(elf, words[cursor + 11].address, fail.range.start)
    {
        return Err(policy_machine_error("policy record args length binding changed"));
    }
    cursor += 12;
    if !is_lbu(words[cursor].word, 5, 15, 20)
        || !is_addi(words[cursor + 1].word, 6, 0, 2)
        || !is_bgeu(words[cursor + 2].word, 5, 6)
        || !flow_targets(elf, words[cursor + 2].address, fail.range.start)
        || !is_beq(words[cursor + 3].word, 28, 0)
        || !flow_targets(elf, words[cursor + 3].address, args_valid.range.start)
        || !is_addi(words[cursor + 4].word, 29, 0, ENTRY_WITNESS_MAGIC.len() as i32)
        || !is_bltu(words[cursor + 5].word, 28, 29)
        || !flow_targets(elf, words[cursor + 5].address, fail.range.start)
    {
        return Err(policy_machine_error("policy record role or empty/CSARG args framing changed"));
    }
    cursor += 6;
    for (index, byte) in ENTRY_WITNESS_MAGIC.iter().copied().enumerate() {
        if !is_lbu(words[cursor].word, 5, 15, POLICY_RECORD_FIXED_BYTES + index as i32)
            || !is_addi(words[cursor + 1].word, 6, 0, i32::from(byte))
            || !is_bne(words[cursor + 2].word, 5, 6)
            || !flow_targets(elf, words[cursor + 2].address, fail.range.start)
        {
            return Err(policy_machine_error("selected policy record no longer requires canonical CSARGv1 framing"));
        }
        cursor += 3;
    }
    if words[cursor - 1].address + 4 != args_valid.range.start {
        return Err(policy_machine_error("policy record validation admits an unchecked path before key ordering"));
    }
    Ok(())
}

fn validate_policy_dynvec_machine_contract(
    elf: &ParsedElf,
    record_loop: &LoweringBlock,
    fail: &LoweringBlock,
) -> Result<(), CheckerError> {
    let start =
        record_loop.range.start.checked_sub(160).ok_or_else(|| policy_machine_error("policy DynVec scanner prefix underflows"))?;
    let words = instructions_from(elf, start, 40)?;
    if !matches_large_stack_store(words, 0, 0, POLICY_FOUND_OFFSET)
        || !is_addi(words[4].word, 14, 2, 16)
        || !is_ld(words[5].word, 6, 2, 0)
        || !is_addi(words[6].word, 6, 6, -8)
        || !matches_u32_le_load(words, 7, 5, 14, 0, 29)
        || !is_bne(words[17].word, 5, 6)
        || !flow_targets(elf, words[17].address, fail.range.start)
        || !is_add(words[18].word, 17, 14, 5)
        || !matches_u32_le_load(words, 19, 6, 14, 4, 29)
        || !is_addi(words[29].word, 7, 0, 8)
        || !is_bltu(words[30].word, 6, 7)
        || !flow_targets(elf, words[30].address, fail.range.start)
        || !is_addi(words[31].word, 7, 0, 36)
        || !is_bltu(words[32].word, 7, 6)
        || !flow_targets(elf, words[32].address, fail.range.start)
        || !is_addi(words[33].word, 7, 0, 3)
        || !is_and(words[34].word, 7, 6, 7)
        || !is_bne(words[35].word, 7, 0)
        || !flow_targets(elf, words[35].address, fail.range.start)
        || !is_bltu(words[36].word, 5, 6)
        || !flow_targets(elf, words[36].address, fail.range.start)
        || !is_add(words[37].word, 13, 14, 6)
        || !is_addi(words[38].word, 12, 14, 4)
        || !is_addi(words[39].word, 16, 0, 0)
        || words[39].address + 4 != record_loop.range.start
    {
        return Err(policy_machine_error("bounded one-to-eight-record canonical DynVec scanner changed"));
    }
    Ok(())
}

fn validate_policy_key_order_machine_contract(
    elf: &ParsedElf,
    args_valid: &LoweringBlock,
    key_loop: &LoweringBlock,
    ordered: &LoweringBlock,
    fail: &LoweringBlock,
) -> Result<(), CheckerError> {
    let prefix = instructions_from(elf, args_valid.range.start, 4)?;
    if !is_beq(prefix[0].word, 16, 0)
        || !flow_targets(elf, prefix[0].address, ordered.range.start)
        || !is_addi(prefix[1].word, 5, 16, 0)
        || !is_addi(prefix[2].word, 6, 15, 20)
        || !is_addi(prefix[3].word, 7, 0, 33)
        || prefix[3].address + 4 != key_loop.range.start
    {
        return Err(policy_machine_error("policy record key-order initialization changed"));
    }
    let loop_words = instructions_from(elf, key_loop.range.start, 9)?;
    if !is_lbu(loop_words[0].word, 28, 5, 0)
        || !is_lbu(loop_words[1].word, 29, 6, 0)
        || !is_bltu(loop_words[2].word, 28, 29)
        || !flow_targets(elf, loop_words[2].address, ordered.range.start)
        || !is_bltu(loop_words[3].word, 29, 28)
        || !flow_targets(elf, loop_words[3].address, fail.range.start)
        || !is_addi(loop_words[4].word, 5, 5, 1)
        || !is_addi(loop_words[5].word, 6, 6, 1)
        || !is_addi(loop_words[6].word, 7, 7, -1)
        || !is_bne(loop_words[7].word, 7, 0)
        || !flow_targets(elf, loop_words[7].address, key_loop.range.start)
        || !is_jal_zero(loop_words[8].word)
        || !flow_targets(elf, loop_words[8].address, fail.range.start)
    {
        return Err(policy_machine_error("policy record keys are no longer strictly ordered and duplicate-rejecting"));
    }
    Ok(())
}

fn validate_policy_selector_machine_contract(
    elf: &ParsedElf,
    record_loop: &LoweringBlock,
    ordered: &LoweringBlock,
    hash_loop: &LoweringBlock,
    next_record: &LoweringBlock,
    fail: &LoweringBlock,
) -> Result<(), CheckerError> {
    let ordered_words = instructions_from(elf, ordered.range.start, 9)?;
    if !is_addi(ordered_words[0].word, 16, 15, 20)
        || !is_lbu(ordered_words[1].word, 5, 15, 20)
        || !is_addi(ordered_words[2].word, 6, 0, POLICY_TYPE_ROLE)
        || !is_bne(ordered_words[3].word, 5, 6)
        || !flow_targets(elf, ordered_words[3].address, next_record.range.start)
        || !is_addi(ordered_words[4].word, 5, 15, 21)
        || !matches_large_stack_address(ordered_words, 5, 6, POLICY_HASH_BUFFER_OFFSET)
        || !is_addi(ordered_words[8].word, 7, 0, 32)
        || ordered_words[8].address + 4 != hash_loop.range.start
    {
        return Err(policy_machine_error("policy selector no longer binds Type role and the complete current Script hash"));
    }
    let words = instructions_from(elf, hash_loop.range.start, 56)?;
    if !is_lbu(words[0].word, 28, 5, 0)
        || !is_lbu(words[1].word, 29, 6, 0)
        || !is_bne(words[2].word, 28, 29)
        || !flow_targets(elf, words[2].address, next_record.range.start)
        || !is_addi(words[3].word, 5, 5, 1)
        || !is_addi(words[4].word, 6, 6, 1)
        || !is_addi(words[5].word, 7, 7, -1)
        || !is_bne(words[6].word, 7, 0)
        || !flow_targets(elf, words[6].address, hash_loop.range.start)
        || !matches_large_stack_load(words, 7, 5, POLICY_FOUND_OFFSET)
        || !is_bne(words[11].word, 5, 0)
        || !flow_targets(elf, words[11].address, fail.range.start)
        || !is_addi(words[12].word, 5, 0, 1)
        || !matches_large_stack_store(words, 13, 5, POLICY_FOUND_OFFSET)
        || !matches_u32_le_load(words, 17, 5, 15, 53, 29)
        || !matches_large_stack_store(words, 27, 5, POLICY_TAG_OFFSET)
        || !matches_u32_le_load(words, 31, 5, 15, 57, 29)
        || !matches_large_stack_store(words, 41, 5, POLICY_ARGS_LENGTH_OFFSET)
        || !is_addi(words[45].word, 5, 15, POLICY_RECORD_FIXED_BYTES)
        || !matches_large_stack_store(words, 46, 5, POLICY_ARGS_POINTER_OFFSET)
        || words[49].address + 4 != next_record.range.start
    {
        return Err(policy_machine_error("policy selector tag/args extraction or single-match guard changed"));
    }
    let next = instructions_from(elf, next_record.range.start, 6)?;
    if !is_bltu(next[0].word, 12, 13)
        || !flow_targets(elf, next[0].address, record_loop.range.start)
        || !matches_large_stack_load(next, 1, 5, POLICY_FOUND_OFFSET)
        || !is_beq(next[5].word, 5, 0)
        || !flow_targets(elf, next[5].address, fail.range.start)
    {
        return Err(policy_machine_error("policy scanner no longer validates every record and requires exactly one matching Script"));
    }
    Ok(())
}

fn validate_policy_tag_dispatch_machine_contract(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    contract: &crate::PolicyWitnessContract,
    next_record: &LoweringBlock,
    fail: &LoweringBlock,
    done: &LoweringBlock,
) -> Result<(), CheckerError> {
    if contract.variants.is_empty() {
        return Err(policy_machine_error("policy machine contract has no declared variants"));
    }
    let mut variants = record
        .blocks
        .iter()
        .filter(|block| {
            block.owner_entry == POLICY_WRAPPER_ENTRY_ID
                && block.machine_label.as_deref().is_some_and(|label| label.starts_with(".Lpolicy_variant_"))
        })
        .collect::<Vec<_>>();
    variants.sort_by_key(|block| block.range.start);
    if variants.len() != contract.variants.len() {
        return Err(policy_machine_error("machine variant count differs from the typed policy"));
    }
    let variant_addresses = variants.iter().map(|block| block.range.start).collect::<BTreeSet<_>>();
    let tag_set = contract.variants.iter().map(|variant| u64::from(variant.tag)).collect::<BTreeSet<_>>();
    let mut branches = Vec::new();
    for instruction in elf.instructions.iter().filter(|instruction| {
        next_record.range.start <= instruction.address && instruction.address < fail.range.start && is_beq(instruction.word, 5, 6)
    }) {
        let Some(block) = block_for_address(record, instruction.address) else { continue };
        let Some(tag) = register_constant_before(elf, block, instruction.address, 6) else { continue };
        let Some(flow) = elf.control_flow.iter().find(|flow| flow.address == instruction.address) else { continue };
        if tag_set.contains(&tag) {
            branches.push((instruction.address, tag, flow.target));
        }
    }
    branches.sort_by_key(|branch| branch.0);
    let has_common = !contract.common_checks.is_empty();
    let expected_count = contract.variants.len() * if has_common { 2 } else { 1 };
    if branches.len() != expected_count {
        return Err(policy_machine_error("declared tag comparisons are missing or duplicated in machine dispatch"));
    }
    let expected_tags = contract.variants.iter().map(|variant| u64::from(variant.tag)).collect::<Vec<_>>();
    let dispatch_offset = if has_common { contract.variants.len() } else { 0 };
    if branches[dispatch_offset..].iter().map(|branch| branch.1).collect::<Vec<_>>() != expected_tags {
        return Err(policy_machine_error("machine dispatch tag order differs from the canonical policy variants"));
    }
    for ((_, _, target), variant_block) in branches[dispatch_offset..].iter().zip(&variants) {
        if *target != variant_block.range.start {
            return Err(policy_machine_error("a policy tag branches to the wrong action adapter"));
        }
    }
    let dispatch_start = block_for_address(record, branches[dispatch_offset].0)
        .ok_or_else(|| policy_machine_error("dispatch branch is outside machine blocks"))?
        .range
        .start;
    let dispatch_prefix = instructions_from(elf, dispatch_start, 4)?;
    if !matches_large_stack_load(dispatch_prefix, 0, 5, POLICY_TAG_OFFSET) {
        return Err(policy_machine_error("action dispatch no longer reads the selected record tag"));
    }
    let last_dispatch =
        branches.last().map(|branch| branch.0).ok_or_else(|| policy_machine_error("policy machine dispatch has no tag branches"))?;
    if !is_jal_zero(instruction_at(elf, last_dispatch + 4)?.word) || !flow_targets(elf, last_dispatch + 4, fail.range.start) {
        return Err(policy_machine_error("unknown policy action tags no longer reject"));
    }

    if has_common {
        let declared = unique_policy_block(record, POLICY_WRAPPER_ENTRY_ID, ".Lpolicy_declared_tag_")?;
        if branches[..dispatch_offset].iter().map(|branch| branch.1).collect::<Vec<_>>() != expected_tags
            || branches[..dispatch_offset].iter().any(|branch| branch.2 != declared.range.start)
        {
            return Err(policy_machine_error("common checks are no longer guarded by the complete declared tag set"));
        }
        validate_only_branches_enter(
            record,
            declared,
            &branches[..dispatch_offset].iter().map(|branch| branch.0).collect::<Vec<_>>(),
        )?;
        let first_common_branch = branches[0].0;
        let common_guard_start = block_for_address(record, first_common_branch)
            .ok_or_else(|| policy_machine_error("common-check tag guard is outside machine blocks"))?
            .range
            .start;
        let guard_prefix = instructions_from(elf, common_guard_start, 4)?;
        if !matches_large_stack_load(guard_prefix, 0, 5, POLICY_TAG_OFFSET) {
            return Err(policy_machine_error("common checks no longer read the selected record tag"));
        }
        let last_guard = branches[dispatch_offset - 1].0;
        if !is_jal_zero(instruction_at(elf, last_guard + 4)?.word) || !flow_targets(elf, last_guard + 4, fail.range.start) {
            return Err(policy_machine_error("unknown tags can bypass common-check rejection"));
        }
        let expected_targets =
            contract.common_checks.iter().map(|entry_id| entry_start(record, entry_id)).collect::<Result<Vec<_>, _>>()?;
        let mut calls = elf
            .control_flow
            .iter()
            .filter(|flow| {
                declared.range.start <= flow.address && flow.address < dispatch_start && expected_targets.contains(&flow.target)
            })
            .collect::<Vec<_>>();
        calls.sort_by_key(|flow| flow.address);
        if calls.len() != expected_targets.len() || calls.iter().map(|flow| flow.target).collect::<Vec<_>>() != expected_targets {
            return Err(policy_machine_error("ordered common-check calls differ from the typed policy"));
        }
        for call in calls {
            if call.address < 4
                || !is_auipc(instruction_at(elf, call.address - 4)?.word, 1)
                || !is_jalr_call(instruction_at(elf, call.address)?.word)
                || !is_bne(instruction_at(elf, call.address + 4)?.word, 10, 0)
                || !flow_targets(elf, call.address + 4, done.range.start)
            {
                return Err(policy_machine_error("common-check failure no longer dominates action dispatch"));
            }
        }
        validate_only_fallthrough_enters(record, dispatch_start)?;
    } else if record.blocks.iter().any(|block| {
        block.owner_entry == POLICY_WRAPPER_ENTRY_ID
            && block.machine_label.as_deref().is_some_and(|label| label.starts_with(".Lpolicy_declared_tag_"))
    }) {
        return Err(policy_machine_error("payload declares no common checks but the machine has a common-check dispatch block"));
    } else {
        validate_only_fallthrough_enters(record, dispatch_start)?;
    }

    let mut adapters = record
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Runtime && entry.name.starts_with(".Lpolicy_action_adapter_"))
        .collect::<Vec<_>>();
    adapters.sort_by_key(|entry| entry_start(record, &entry.id).unwrap_or(u64::MAX));
    if adapters.len() != variants.len() {
        return Err(policy_machine_error("policy action adapter count differs from the declared variant count"));
    }
    for ((variant_block, adapter), variant) in variants.iter().zip(adapters).zip(&contract.variants) {
        let words = instructions_from(elf, variant_block.range.start, 11)?;
        let adapter_start = entry_start(record, &adapter.id)?;
        if !matches_large_stack_load(words, 0, 10, POLICY_ARGS_POINTER_OFFSET)
            || !matches_large_stack_load(words, 4, 11, POLICY_ARGS_LENGTH_OFFSET)
            || !is_auipc(words[8].word, 1)
            || !is_jalr_call(words[9].word)
            || !flow_targets(elf, words[9].address, adapter_start)
            || !is_jal_zero(words[10].word)
            || !flow_targets(elf, words[10].address, done.range.start)
            || !variant_addresses.contains(&variant_block.range.start)
            || entry_start(record, &variant.entry_id).is_err()
        {
            return Err(policy_machine_error(format!(
                "tag {} no longer forwards the selected args to its exact adapter",
                variant.tag
            )));
        }
        let branch_address = branches[dispatch_offset..]
            .iter()
            .find(|branch| branch.2 == variant_block.range.start)
            .map(|branch| branch.0)
            .ok_or_else(|| policy_machine_error("policy variant has no unique declared tag branch"))?;
        validate_only_branch_enters(record, variant_block, branch_address)?;
    }
    Ok(())
}

fn validate_policy_action_adapters(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    contract: &crate::PolicyWitnessContract,
) -> Result<(), CheckerError> {
    let mut adapters = record
        .entries
        .iter()
        .filter(|entry| entry.kind == EntryKind::Runtime && entry.name.starts_with(".Lpolicy_action_adapter_"))
        .collect::<Vec<_>>();
    adapters.sort_by_key(|entry| entry_start(record, &entry.id).unwrap_or(u64::MAX));
    if adapters.len() != contract.variants.len() {
        return Err(policy_machine_error("policy adapter cardinality changed"));
    }
    let all_action_starts =
        contract.variants.iter().map(|variant| entry_start(record, &variant.entry_id)).collect::<Result<BTreeSet<_>, _>>()?;
    for (adapter, variant) in adapters.into_iter().zip(&contract.variants) {
        let entry = record
            .typed_semantics
            .entries
            .iter()
            .find(|entry| entry.id == variant.entry_id)
            .ok_or_else(|| policy_machine_error("policy variant has no typed action entry"))?;
        let expected_outgoing = policy_outgoing_argument_bytes(entry, &record.typed_semantics)?;
        let expected_record_frame = POLICY_ADAPTER_FRAME_BYTES
            .checked_add(expected_outgoing)
            .ok_or_else(|| policy_machine_error("policy adapter recorded frame overflows u32"))?;
        if adapter.frame_size_bytes != expected_record_frame || adapter.outgoing_argument_bytes != 0 {
            return Err(policy_machine_error(format!(
                "policy positional adapter frame contract changed: frame {}, outgoing {}, expected frame {expected_record_frame}, outgoing 0",
                adapter.frame_size_bytes, adapter.outgoing_argument_bytes
            )));
        }
        let blocks = record.blocks.iter().filter(|block| block.owner_entry == adapter.id).collect::<Vec<_>>();
        if blocks.iter().any(|block| block.frame_size_bytes != expected_record_frame || block.outgoing_argument_bytes != 0) {
            return Err(policy_machine_error("policy positional adapter blocks disagree on frame size"));
        }
        let base = entry_start(record, &adapter.id)?;
        let prologue = instructions_from(elf, base, 9)?;
        if !matches_large_sp_adjust(prologue, 0, -(POLICY_ADAPTER_FRAME_BYTES as i32))
            || !matches_large_stack_store(prologue, 3, 1, POLICY_ADAPTER_FRAME_BYTES as i32 - 8)
        {
            return Err(policy_machine_error("policy adapter prologue no longer owns a bounded private copy frame"));
        }
        let fail = unique_policy_block(record, &adapter.id, ".Lentry_witness_fail_")?;
        let done = unique_policy_block(record, &adapter.id, ".Lentry_witness_done_")?;
        let has_payload = entry.params.iter().any(|param| matches!(param.source.as_str(), "default" | "witness"));
        if has_payload {
            let copy = unique_policy_block(record, &adapter.id, ".Lpolicy_args_copy_")?;
            let prefix_address =
                copy.range.start.checked_sub(24).ok_or_else(|| policy_machine_error("policy adapter copy prefix underflows"))?;
            let prefix = instructions_from(elf, prefix_address, 6)?;
            if !is_lui(prefix[0].word, 5, 0x0000_1000)
                || !is_bltu(prefix[1].word, 5, 11)
                || !flow_targets(elf, prefix[1].address, fail.range.start)
                || !is_sd(prefix[2].word, 11, 2, 0)
                || !is_addi(prefix[3].word, 5, 10, 0)
                || !is_addi(prefix[4].word, 6, 2, 8)
                || !is_addi(prefix[5].word, 7, 0, 0)
            {
                return Err(policy_machine_error("policy adapter no longer bounds and privately copies selected args"));
            }
            let copied = unique_policy_block(record, &adapter.id, ".Lpolicy_args_copied_")?;
            let loop_words = instructions_from(elf, copy.range.start, 7)?;
            if !is_bgeu(loop_words[0].word, 7, 11)
                || !flow_targets(elf, loop_words[0].address, copied.range.start)
                || !is_add(loop_words[1].word, 28, 5, 7)
                || !is_lbu(loop_words[2].word, 29, 28, 0)
                || !is_add(loop_words[3].word, 28, 6, 7)
                || !is_sb(loop_words[4].word, 29, 28, 0)
                || !is_addi(loop_words[5].word, 7, 7, 1)
                || !is_jal_zero(loop_words[6].word)
                || !flow_targets(elf, loop_words[6].address, copy.range.start)
            {
                return Err(policy_machine_error("policy adapter selected-args copy loop changed"));
            }
        } else if !is_bne(prologue[7].word, 11, 0)
            || !flow_targets(elf, prologue[7].address, fail.range.start)
            || !is_sd(prologue[8].word, 0, 2, 0)
        {
            return Err(policy_machine_error("payload-free policy adapter no longer requires empty args"));
        }

        let target = entry_start(record, &variant.entry_id)?;
        let mut action_calls = elf
            .control_flow
            .iter()
            .filter(|flow| blocks.iter().any(|block| block.range.contains(flow.address)) && all_action_starts.contains(&flow.target))
            .collect::<Vec<_>>();
        action_calls.sort_by_key(|flow| flow.address);
        if action_calls.len() != 1 || action_calls[0].target != target {
            return Err(policy_machine_error(format!(
                "tag {} adapter no longer calls exactly action '{}'",
                variant.tag, variant.entry_id
            )));
        }
        let call = action_calls[0];
        if call.address < 4
            || !is_auipc(instruction_at(elf, call.address - 4)?.word, 1)
            || !is_jalr_call(instruction_at(elf, call.address)?.word)
            || !machine_error_jumps_to_abort(record, elf, fail.range.start, 25)
        {
            return Err(policy_machine_error("policy adapter call/failure completion changed"));
        }
        let completion = if expected_outgoing == 0 {
            call.address + 4
        } else {
            let outgoing = i32::try_from(expected_outgoing)
                .map_err(|_| policy_machine_error("policy adapter outgoing argument frame exceeds i32"))?;
            let reserve_bytes = sp_adjust_instruction_bytes(-outgoing);
            let reserve = call
                .address
                .checked_sub(4 + reserve_bytes)
                .ok_or_else(|| policy_machine_error("policy adapter outgoing argument reservation underflows"))?;
            if !matches_sp_adjust_at(elf, reserve, -outgoing)? || reserve + reserve_bytes != call.address - 4 {
                return Err(policy_machine_error("policy adapter outgoing argument frame changed"));
            }
            let restore = call.address + 4;
            if !matches_sp_adjust_at(elf, restore, outgoing)? {
                return Err(policy_machine_error("policy adapter outgoing argument frame changed"));
            }
            restore + sp_adjust_instruction_bytes(outgoing)
        };
        if !is_jal_zero(instruction_at(elf, completion)?.word) || !flow_targets(elf, completion, done.range.start) {
            return Err(policy_machine_error("policy adapter call no longer completes through its exact done block"));
        }
        let done_words = instructions_from(elf, done.range.start, 8)?;
        if !matches_large_stack_load(done_words, 0, 1, POLICY_ADAPTER_FRAME_BYTES as i32 - 8)
            || !matches_large_sp_adjust(done_words, 4, POLICY_ADAPTER_FRAME_BYTES as i32)
            || done_words[7].word != 0x0000_8067
        {
            return Err(policy_machine_error("policy adapter completion no longer restores its private frame"));
        }
    }
    Ok(())
}

fn policy_outgoing_argument_bytes(entry: &TypedSemanticEntry, typed: &TypedSemanticRecord) -> Result<u32, CheckerError> {
    let mut argument_count = 0usize;
    for param in &entry.params {
        let projection = crate::policy::builder_parameter_projection(param, entry, typed)?;
        let schema_pointer = projection.get("schema_pointer_abi").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let fixed_pointer = projection.get("fixed_byte_pointer_abi").and_then(serde_json::Value::as_bool).unwrap_or(false);
        let type_hash = projection.get("type_hash_pointer_abi").and_then(serde_json::Value::as_bool).unwrap_or(false);
        argument_count = argument_count.saturating_add(if schema_pointer {
            2 + usize::from(type_hash) * 2
        } else if fixed_pointer {
            2
        } else {
            1
        });
    }
    let bytes = argument_count.saturating_sub(8).saturating_mul(8);
    u32::try_from(if bytes == 0 { 0 } else { bytes.next_multiple_of(16) })
        .map_err(|_| policy_machine_error("policy adapter outgoing argument frame exceeds u32"))
}

fn entry_start(record: &VerifiedLoweringRecord, entry_id: &str) -> Result<u64, CheckerError> {
    let entry = record
        .entries
        .iter()
        .find(|entry| entry.id == entry_id)
        .ok_or_else(|| policy_machine_error(format!("missing lowering entry '{entry_id}'")))?;
    record
        .blocks
        .iter()
        .find(|block| block.id == entry.entry_block)
        .map(|block| block.range.start)
        .ok_or_else(|| policy_machine_error(format!("missing entry block for '{entry_id}'")))
}

fn validate_only_fallthrough_enters(record: &VerifiedLoweringRecord, target: u64) -> Result<(), CheckerError> {
    let block = block_for_address(record, target).ok_or_else(|| policy_machine_error("dispatch target is outside machine blocks"))?;
    let preceding = target
        .checked_sub(4)
        .and_then(|address| block_for_address(record, address))
        .ok_or_else(|| policy_machine_error("dispatch target has no adjacent predecessor block"))?;
    let incoming = record.edges.iter().filter(|edge| edge.to == block.id).collect::<Vec<_>>();
    if incoming.len() != 1 || incoming[0].from != preceding.id || incoming[0].kind != EdgeKind::ConditionalFallthrough {
        return Err(policy_machine_error("action dispatch has a machine path that bypasses a common check"));
    }
    Ok(())
}

fn validate_only_branches_enter(
    record: &VerifiedLoweringRecord,
    target: &LoweringBlock,
    branch_addresses: &[u64],
) -> Result<(), CheckerError> {
    let sources = branch_addresses
        .iter()
        .map(|address| {
            block_for_address(record, *address)
                .map(|block| block.id.as_str())
                .ok_or_else(|| policy_machine_error("declared-tag branch is outside machine blocks"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let incoming = record.edges.iter().filter(|edge| edge.to == target.id).collect::<Vec<_>>();
    if sources.len() != branch_addresses.len()
        || incoming.len() != sources.len()
        || incoming.iter().any(|edge| edge.kind != EdgeKind::ConditionalTaken || !sources.contains(edge.from.as_str()))
    {
        return Err(policy_machine_error("common checks have an entry path outside the declared tag branches"));
    }
    Ok(())
}

fn validate_only_branch_enters(
    record: &VerifiedLoweringRecord,
    target: &LoweringBlock,
    branch_address: u64,
) -> Result<(), CheckerError> {
    let source =
        block_for_address(record, branch_address).ok_or_else(|| policy_machine_error("variant branch is outside machine blocks"))?;
    let incoming = record.edges.iter().filter(|edge| edge.to == target.id).collect::<Vec<_>>();
    if incoming.len() != 1 || incoming[0].from != source.id || incoming[0].kind != EdgeKind::ConditionalTaken {
        return Err(policy_machine_error("a policy variant has an undeclared machine entry path"));
    }
    Ok(())
}

fn matches_u32_le_load(
    words: &[crate::elf::DecodedInstruction],
    start: usize,
    dest: u32,
    base: u32,
    offset: i32,
    scratch: u32,
) -> bool {
    words.get(start..start + 10).is_some_and(|words| {
        is_lbu(words[0].word, dest, base, offset)
            && is_lbu(words[1].word, scratch, base, offset + 1)
            && is_slli(words[2].word, scratch, scratch, 8)
            && is_or(words[3].word, dest, dest, scratch)
            && is_lbu(words[4].word, scratch, base, offset + 2)
            && is_slli(words[5].word, scratch, scratch, 16)
            && is_or(words[6].word, dest, dest, scratch)
            && is_lbu(words[7].word, scratch, base, offset + 3)
            && is_slli(words[8].word, scratch, scratch, 24)
            && is_or(words[9].word, dest, dest, scratch)
    })
}

fn matches_large_stack_address(words: &[crate::elf::DecodedInstruction], start: usize, dest: u32, offset: i32) -> bool {
    let Some((upper, lower)) = split_large_immediate(offset) else { return false };
    words.get(start..start + 3).is_some_and(|words| {
        is_lui(words[0].word, dest, upper) && is_addi(words[1].word, dest, dest, lower) && is_add(words[2].word, dest, 2, dest)
    })
}

fn matches_large_stack_load(words: &[crate::elf::DecodedInstruction], start: usize, dest: u32, offset: i32) -> bool {
    matches_large_stack_address(words, start, 31, offset)
        && words.get(start + 3).is_some_and(|instruction| is_ld(instruction.word, dest, 31, 0))
}

fn matches_large_stack_store(words: &[crate::elf::DecodedInstruction], start: usize, source: u32, offset: i32) -> bool {
    matches_large_stack_address(words, start, 31, offset)
        && words.get(start + 3).is_some_and(|instruction| is_sd(instruction.word, source, 31, 0))
}

fn matches_large_sp_adjust(words: &[crate::elf::DecodedInstruction], start: usize, delta: i32) -> bool {
    let Some((upper, lower)) = split_large_immediate(delta) else { return false };
    words.get(start..start + 3).is_some_and(|words| {
        is_lui(words[0].word, 31, upper) && is_addi(words[1].word, 31, 31, lower) && is_add(words[2].word, 2, 2, 31)
    })
}

fn sp_adjust_instruction_bytes(delta: i32) -> u64 {
    if (-2_048..=2_047).contains(&delta) {
        4
    } else {
        12
    }
}

fn matches_sp_adjust_at(elf: &ParsedElf, address: u64, delta: i32) -> Result<bool, CheckerError> {
    if (-2_048..=2_047).contains(&delta) {
        Ok(is_addi(instruction_at(elf, address)?.word, 2, 2, delta))
    } else {
        Ok(matches_large_sp_adjust(instructions_from(elf, address, 3)?, 0, delta))
    }
}

fn split_large_immediate(value: i32) -> Option<(u32, i32)> {
    let upper = value.checked_add(2_048)?.div_euclid(4_096).checked_mul(4_096)?;
    let lower = value.checked_sub(upper)?;
    Some((upper as u32 & 0xffff_f000, lower))
}

fn register_constant_before(elf: &ParsedElf, block: &LoweringBlock, address: u64, register: usize) -> Option<u64> {
    let mut values = [None; 32];
    values[0] = Some(0);
    for instruction in
        elf.instructions.iter().filter(|instruction| block.range.start <= instruction.address && instruction.address < address)
    {
        update_constant_registers(&mut values, instruction.word);
    }
    values.get(register).copied().flatten()
}

fn update_constant_registers(values: &mut [Option<u64>; 32], word: u32) {
    let opcode = word & 0x7f;
    let rd = ((word >> 7) & 0x1f) as usize;
    if rd == 0 {
        return;
    }
    let rs1 = ((word >> 15) & 0x1f) as usize;
    let rs2 = ((word >> 20) & 0x1f) as usize;
    let function = (word >> 12) & 0x7;
    let value = match opcode {
        0x37 => Some(((word & 0xffff_f000) as i32 as i64) as u64),
        0x13 if function == 0 => values[rs1].map(|value| value.wrapping_add_signed((word as i32 >> 20) as i64)),
        0x13 if function == 1 && (word >> 26) & 0x3f == 0 => values[rs1].map(|value| value.wrapping_shl((word >> 20) & 0x3f)),
        0x13 if function == 5 && (word >> 26) & 0x3f == 0 => values[rs1].map(|value| value >> ((word >> 20) & 0x3f)),
        0x33 if (word >> 25) & 0x7f == 0 && function == 0 => {
            values[rs1].zip(values[rs2]).map(|(left, right)| left.wrapping_add(right))
        }
        0x33 if (word >> 25) & 0x7f == 0x20 && function == 0 => {
            values[rs1].zip(values[rs2]).map(|(left, right)| left.wrapping_sub(right))
        }
        0x33 if (word >> 25) & 0x7f == 0 && function == 6 => values[rs1].zip(values[rs2]).map(|(left, right)| left | right),
        0x33 if (word >> 25) & 0x7f == 0 && function == 7 => values[rs1].zip(values[rs2]).map(|(left, right)| left & right),
        _ => None,
    };
    if matches!(opcode, 0x03 | 0x13 | 0x17 | 0x33 | 0x37 | 0x67 | 0x6f) {
        values[rd] = value;
    }
}

#[derive(Clone, Copy)]
struct HeaderDepSyscallContract {
    name: &'static str,
    syscall_number: u64,
    field_id: Option<i32>,
    buffer_bytes: u32,
    result_stack_offset: Option<i32>,
}

fn header_dep_syscall_contract(owner_entry: &str) -> Option<HeaderDepSyscallContract> {
    match owner_entry {
        "runtime:__ckb_header_dep_epoch_number" => Some(HeaderDepSyscallContract {
            name: "ckb-header-dep-epoch-number-v1",
            syscall_number: 2082,
            field_id: Some(0),
            buffer_bytes: 8,
            result_stack_offset: None,
        }),
        "runtime:__ckb_header_dep_epoch_start_block_number" => Some(HeaderDepSyscallContract {
            name: "ckb-header-dep-epoch-start-block-number-v1",
            syscall_number: 2082,
            field_id: Some(1),
            buffer_bytes: 8,
            result_stack_offset: None,
        }),
        "runtime:__ckb_header_dep_epoch_length" => Some(HeaderDepSyscallContract {
            name: "ckb-header-dep-epoch-length-v1",
            syscall_number: 2082,
            field_id: Some(2),
            buffer_bytes: 8,
            result_stack_offset: None,
        }),
        "runtime:__ckb_header_dep_block_number" => Some(HeaderDepSyscallContract {
            name: "ckb-header-dep-block-number-v1",
            syscall_number: 2072,
            field_id: None,
            buffer_bytes: 208,
            result_stack_offset: Some(32),
        }),
        "runtime:__ckb_header_dep_timestamp_millis" => Some(HeaderDepSyscallContract {
            name: "ckb-header-dep-timestamp-millis-v1",
            syscall_number: 2072,
            field_id: None,
            buffer_bytes: 208,
            result_stack_offset: Some(24),
        }),
        _ => None,
    }
}

fn validate_header_dep_syscall_site(
    record: &VerifiedLoweringRecord,
    elf: &ParsedElf,
    site: &SyscallSite,
    block: &LoweringBlock,
) -> Result<(), CheckerError> {
    let Some(expected) = header_dep_syscall_contract(&block.owner_entry) else {
        if site.contract.starts_with("ckb-header-dep-") {
            return Err(header_dep_machine_error(site, "a HeaderDep syscall contract is attached to the wrong runtime helper"));
        }
        return Ok(());
    };
    if site.syscall_number != Some(expected.syscall_number)
        || site.contract != expected.name
        || site.source_domain != "HeaderDepView/source=HeaderDep"
        || site.index_domain != "u32-source-view"
        || !site.return_code_checked
        || site.buffer_limit_bytes != expected.buffer_bytes
    {
        return Err(header_dep_machine_error(site, "the declared HeaderDep syscall contract differs from its helper"));
    }

    let word = |delta: i64| -> Result<u32, CheckerError> {
        let address =
            site.address.checked_add_signed(delta).ok_or_else(|| header_dep_machine_error(site, "instruction address overflow"))?;
        elf.instructions
            .iter()
            .find(|instruction| instruction.address == address)
            .map(|instruction| instruction.word)
            .ok_or_else(|| header_dep_machine_error(site, format!("missing instruction at {address:#x}")))
    };
    let syscall_lower = i32::try_from(expected.syscall_number).expect("CKB syscall fits i32") - 4096;
    if word(0)? != 0x0000_0073 || !is_lui(word(-8)?, 17, 0x1000) || !is_addi(word(-4)?, 17, 17, syscall_lower) {
        return Err(header_dep_machine_error(site, "the machine code does not materialize the declared HeaderDep syscall number"));
    }
    if !is_beq(word(4)?, 10, 0) || !is_addi(word(8)?, 10, 0, 45) || !machine_error_jumps_to_abort(record, elf, site.address + 8, 45) {
        return Err(header_dep_machine_error(site, "the HeaderDep syscall status does not terminate with error 45"));
    }

    if let Some(field_id) = expected.field_id {
        if !is_addi(word(-48)?, 5, 0, 4)
            || !is_bne(word(-44)?, 7, 5)
            || !is_addi(word(-40)?, 5, 0, 8)
            || !is_sd(word(-36)?, 5, 2, 8)
            || !is_addi(word(-20)?, 13, 6, 0)
            || !is_addi(word(-16)?, 14, 7, 0)
            || !is_addi(word(-12)?, 15, 0, field_id)
        {
            return Err(header_dep_machine_error(
                site,
                "the HeaderDep field selector, source, index, or 8-byte buffer contract changed",
            ));
        }
        if !is_ld(word(16)?, 10, 2, 8)
            || !is_addi(word(20)?, 11, 0, 8)
            || !is_sub(word(24)?, 10, 10, 11)
            || !is_beq(word(28)?, 10, 0)
            || !machine_error_jumps_to_abort(record, elf, site.address + 32, 4)
        {
            return Err(header_dep_machine_error(site, "the HeaderDep scalar exact-width check does not terminate with error 4"));
        }
    } else {
        if !is_addi(word(-44)?, 5, 0, 4)
            || !is_bne(word(-40)?, 7, 5)
            || !is_addi(word(-36)?, 5, 0, 208)
            || !is_sd(word(-32)?, 5, 2, 0)
            || !is_addi(word(-16)?, 13, 6, 0)
            || !is_addi(word(-12)?, 14, 7, 0)
        {
            return Err(header_dep_machine_error(site, "the full HeaderDep source, index, or 208-byte buffer contract changed"));
        }
        let result_stack_offset = expected.result_stack_offset.expect("full HeaderDep field offset");
        if !is_ld(word(16)?, 5, 2, 0)
            || !is_addi(word(20)?, 6, 0, 208)
            || !is_bne(word(24)?, 5, 6)
            || !is_ld(word(28)?, 10, 2, result_stack_offset)
            || !machine_error_jumps_to_abort(record, elf, site.address + 40, 4)
        {
            return Err(header_dep_machine_error(site, "the full HeaderDep exact-width or RawHeader field-offset contract changed"));
        }
    }

    if !owner_has_abort_error(record, elf, &block.owner_entry, 44) {
        return Err(header_dep_machine_error(site, "an invalid HeaderDep source does not terminate with error 44"));
    }
    Ok(())
}

fn header_dep_machine_error(site: &SyscallSite, message: impl Into<String>) -> CheckerError {
    CheckerError::new(
        CheckerRejectionCode::V2417SyscallContractInvalid,
        format!("HeaderDep syscall site at {:#x}: {}", site.address, message.into()),
    )
}

fn machine_error_jumps_to_abort(record: &VerifiedLoweringRecord, elf: &ParsedElf, address: u64, code: i32) -> bool {
    let Some(first) = elf.instructions.iter().find(|instruction| instruction.address == address) else {
        return false;
    };
    let Some(second) = elf.instructions.iter().find(|instruction| instruction.address == address + 4) else {
        return false;
    };
    let Some(abort_entry) = record.entries.iter().find(|entry| entry.id == "runtime:__cellscript_abort") else {
        return false;
    };
    let Some(abort_block) = record.blocks.iter().find(|block| block.id == abort_entry.entry_block) else {
        return false;
    };
    is_addi(first.word, 10, 0, code)
        && is_jal_zero(second.word)
        && elf.control_flow.iter().any(|edge| edge.address == second.address && edge.target == abort_block.range.start)
}

fn owner_has_abort_error(record: &VerifiedLoweringRecord, elf: &ParsedElf, owner_entry: &str, code: i32) -> bool {
    record.blocks.iter().filter(|block| block.owner_entry == owner_entry).any(|block| {
        elf.instructions
            .iter()
            .filter(|instruction| block.range.contains(instruction.address))
            .any(|instruction| machine_error_jumps_to_abort(record, elf, instruction.address, code))
    })
}

fn is_addi(word: u32, rd: u32, rs1: u32, immediate: i32) -> bool {
    word & 0x7f == 0x13
        && (word >> 12) & 0x7 == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word as i32) >> 20 == immediate
}

fn is_lui(word: u32, rd: u32, immediate: u32) -> bool {
    word & 0x7f == 0x37 && (word >> 7) & 0x1f == rd && word & 0xffff_f000 == immediate
}

fn is_ld(word: u32, rd: u32, rs1: u32, immediate: i32) -> bool {
    word & 0x7f == 0x03
        && (word >> 12) & 0x7 == 0x3
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word as i32) >> 20 == immediate
}

fn is_sd(word: u32, rs2: u32, rs1: u32, immediate: i32) -> bool {
    let decoded = (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 0x1f);
    let decoded = ((decoded as i32) << 20) >> 20;
    word & 0x7f == 0x23
        && (word >> 12) & 0x7 == 0x3
        && (word >> 20) & 0x1f == rs2
        && (word >> 15) & 0x1f == rs1
        && decoded == immediate
}

fn is_sub(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0x20
        && (word >> 12) & 0x7 == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

fn is_add(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0
        && (word >> 12) & 0x7 == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

fn is_mul(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0x01
        && (word >> 12) & 0x7 == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

fn is_or(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0
        && (word >> 12) & 0x7 == 6
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

fn is_and(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0
        && (word >> 12) & 0x7 == 7
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

fn is_sltu(word: u32, rd: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x33
        && (word >> 25) & 0x7f == 0
        && (word >> 12) & 0x7 == 3
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x1f == rs2
}

fn is_lbu(word: u32, rd: u32, rs1: u32, immediate: i32) -> bool {
    word & 0x7f == 0x03
        && (word >> 12) & 0x7 == 4
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word as i32) >> 20 == immediate
}

fn is_store(word: u32, function: u32, rs2: u32, rs1: u32, immediate: i32) -> bool {
    let decoded = (((word >> 25) & 0x7f) << 5) | ((word >> 7) & 0x1f);
    let decoded = ((decoded as i32) << 20) >> 20;
    word & 0x7f == 0x23
        && (word >> 12) & 0x7 == function
        && (word >> 20) & 0x1f == rs2
        && (word >> 15) & 0x1f == rs1
        && decoded == immediate
}

fn is_sb(word: u32, rs2: u32, rs1: u32, immediate: i32) -> bool {
    is_store(word, 0, rs2, rs1, immediate)
}

fn is_sw(word: u32, rs2: u32, rs1: u32, immediate: i32) -> bool {
    is_store(word, 2, rs2, rs1, immediate)
}

fn is_srli(word: u32, rd: u32, rs1: u32, shift: u32) -> bool {
    word & 0x7f == 0x13
        && (word >> 12) & 0x7 == 5
        && (word >> 26) & 0x3f == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x3f == shift
}

fn is_slli(word: u32, rd: u32, rs1: u32, shift: u32) -> bool {
    word & 0x7f == 0x13
        && (word >> 12) & 0x7 == 1
        && (word >> 26) & 0x3f == 0
        && (word >> 7) & 0x1f == rd
        && (word >> 15) & 0x1f == rs1
        && (word >> 20) & 0x3f == shift
}

fn is_auipc(word: u32, rd: u32) -> bool {
    word & 0x7f == 0x17 && (word >> 7) & 0x1f == rd
}

fn is_jalr_call(word: u32) -> bool {
    word & 0x7f == 0x67 && (word >> 7) & 0x1f == 1 && (word >> 12) & 0x7 == 0 && (word >> 15) & 0x1f == 1
}

fn is_beq(word: u32, rs1: u32, rs2: u32) -> bool {
    is_branch(word, 0, rs1, rs2)
}

fn is_bne(word: u32, rs1: u32, rs2: u32) -> bool {
    is_branch(word, 1, rs1, rs2)
}

fn is_bltu(word: u32, rs1: u32, rs2: u32) -> bool {
    is_branch(word, 6, rs1, rs2)
}

fn is_bgeu(word: u32, rs1: u32, rs2: u32) -> bool {
    is_branch(word, 7, rs1, rs2)
}

fn is_branch(word: u32, function: u32, rs1: u32, rs2: u32) -> bool {
    word & 0x7f == 0x63 && (word >> 12) & 0x7 == function && (word >> 15) & 0x1f == rs1 && (word >> 20) & 0x1f == rs2
}

fn is_jal_zero(word: u32) -> bool {
    word & 0x7f == 0x6f && (word >> 7) & 0x1f == 0
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

    fn public_interface_hash(interface: &Value) -> String {
        let canonical = canonical_json_value(interface);
        hex_encode(&ckb_blake2b256(&serde_json::to_vec(&canonical).unwrap()))
    }

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
    fn independent_checker_enforces_canonical_public_value_generics() {
        let interface = serde_json::json!({
            "schema": "cellscript-package-interface-v3",
            "version": 3,
            "module": "api",
            "types": [{
                "identity": "api::Pair",
                "type_parameters": [{
                    "name": "T",
                    "phantom": false,
                    "constraints": ["copy", "drop", "store", "fixed", "serializable", "non_linear"]
                }],
                "value_abilities": ["copy", "drop", "store", "fixed", "serializable", "non_linear"]
            }],
            "constants": [],
            "callables": []
        });
        let hash = public_interface_hash(&interface);
        let metadata = serde_json::json!({ "public_interface": interface });
        validate_public_interface_metadata(&metadata, "api", &hash).unwrap();

        let mut compact_machine_form = metadata.clone();
        compact_machine_form["public_interface"]["types"][0]["type_parameters"][0]["constraints"] = serde_json::json!(["fixed_value"]);
        let compact_hash = public_interface_hash(&compact_machine_form["public_interface"]);
        let error = validate_public_interface_metadata(&compact_machine_form, "api", &compact_hash).unwrap_err();
        assert!(error.message.contains("canonical order"), "{}", error.message);

        let mut unsafe_layout = metadata;
        unsafe_layout["public_interface"]["types"][0]["type_parameters"][0]["constraints"] =
            serde_json::json!(["copy", "drop", "store", "fixed", "serializable"]);
        let unsafe_hash = public_interface_hash(&unsafe_layout["public_interface"]);
        let error = validate_public_interface_metadata(&unsafe_layout, "api", &unsafe_hash).unwrap_err();
        assert!(error.message.contains("public layout boundary"), "{}", error.message);
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
