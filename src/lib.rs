//! CellScript - Domain-specific language compiler for Spora blockchain
//! Currently the backend can output RISC-V assembly or ELF artifacts.

#![allow(clippy::ptr_arg, clippy::too_many_arguments)]

pub mod ast;
pub mod cli;
pub mod codegen;
pub mod debug;
pub mod docgen;
pub mod error;
pub mod fmt;
pub mod incremental;
pub mod ir;
pub mod lexer;
pub mod lifecycle;
pub mod lsp;
pub mod optimize;
pub mod package;
pub mod parser;
pub mod repl;
pub mod resolve;
pub mod runtime_errors;
pub mod simulate;
pub mod stdlib;
pub mod types;
pub mod wasm;

use camino::{Utf8Path, Utf8PathBuf};
use error::{CompileError, Result};
use resolve::ModuleResolver;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Compile options
#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    /// Optimization level (0-3)
    pub opt_level: u8,
    /// Output file path
    pub output: Option<String>,
    /// Whether to generate debug information
    pub debug: bool,
    /// Target artifact
    pub target: Option<String>,
    /// Target chain/profile. spora and ckb can produce artifacts; portable-cell is a source compatibility check profile.
    pub target_profile: Option<String>,
}

fn validate_compile_options(options: &CompileOptions) -> Result<()> {
    if options.opt_level > 3 {
        return Err(CompileError::without_span(format!("optimization level must be between 0 and 3, got {}", options.opt_level)));
    }
    Ok(())
}

const DEFAULT_TARGET: &str = "riscv64-asm";
const DEFAULT_TARGET_PROFILE: &str = "spora";
pub const METADATA_SCHEMA_VERSION: u32 = 29;
pub const ENTRY_WITNESS_ABI: &str = "cellscript-entry-witness-v1";
pub(crate) const ENTRY_WITNESS_ABI_MAGIC: &[u8; 8] = b"CSARGv1\0";
pub const CKB_DEFAULT_HASH_PERSONALIZATION: &[u8; 16] = b"ckb-default-hash";
pub const CKB_BLANK_HASH: [u8; 32] = [
    68, 244, 198, 151, 68, 213, 248, 197, 93, 100, 32, 98, 148, 157, 202, 228, 155, 196, 231, 239, 67, 211, 136, 197, 161, 47, 66,
    181, 99, 61, 22, 62,
];
const METADATA_MUTATE_CELL_BUFFER_SIZE: usize = 512;
const CLAIM_SIGNER_PUBKEY_HASH_FIELDS: [&str; 5] =
    ["signer_pubkey_hash", "claim_pubkey_hash", "owner_pubkey_hash", "beneficiary_pubkey_hash", "pubkey_hash"];
const CLAIM_AUTH_LOCK_HASH_FIELDS: [&str; 5] = ["beneficiary", "owner", "recipient", "authority", "admin"];
const CKB_TYPE_ID_CODE_HASH: [u8; 32] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'T', b'Y', b'P', b'E', b'_', b'I', b'D'];
const CKB_TYPE_ID_ABI: &str = "ckb-type-id-v1";
const CKB_TYPE_ID_HASH_TYPE: &str = "type";
const CKB_DEFAULT_SCRIPT_HASH_TYPE: &str = "data1";
const CKB_TYPE_ID_ARGS_SOURCE: &str = "first-input-output-index";
const CKB_TYPE_ID_GROUP_RULE: &str = "at-most-one-input-and-one-output";
const CKB_TYPE_ID_BUILDER: &str = "ckb_apply_type_id_script_to_output_molecule";
const CKB_TYPE_ID_VERIFIER: &str = "ckb_verify_type_id_script_molecule";
const CKB_TYPE_ID_OUTPUT_SOURCE: &str = "Output";
const CKB_TYPE_ID_GENERATOR_SETTING: &str = "ckb_type_id_output_indexes";
const CKB_TYPE_ID_WASM_SETTING: &str = "ckbTypeIdOutputs";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProfile {
    Spora,
    Ckb,
    PortableCell,
}

impl TargetProfile {
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "spora" => Ok(Self::Spora),
            "ckb" => Ok(Self::Ckb),
            "portable-cell" => Ok(Self::PortableCell),
            other => Err(CompileError::without_span(format!(
                "unsupported target profile '{}'; supported profiles: spora, ckb, portable-cell",
                other
            ))),
        }
    }

    fn from_options(options: &CompileOptions, build: Option<&CellBuildConfig>) -> Result<Self> {
        let profile = options
            .target_profile
            .as_deref()
            .or_else(|| build.and_then(|build| build.target_profile.as_deref()))
            .unwrap_or(DEFAULT_TARGET_PROFILE);
        Self::from_name(profile)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Spora => "spora",
            Self::Ckb => "ckb",
            Self::PortableCell => "portable-cell",
        }
    }

    fn ensure_compile_supported(self) -> Result<()> {
        match self {
            Self::Spora | Self::Ckb => Ok(()),
            Self::PortableCell => Err(CompileError::without_span(
                "target profile 'portable-cell' is a source compatibility profile; compile with 'spora' or 'ckb' to produce artifacts",
            )),
        }
    }

    fn embeds_vm_abi_trailer(self, artifact_format: ArtifactFormat) -> bool {
        self == Self::Spora && artifact_format == ArtifactFormat::RiscvElf
    }

    fn metadata(self, artifact_format: ArtifactFormat) -> TargetProfileMetadata {
        match self {
            Self::Spora => TargetProfileMetadata {
                name: self.name().to_string(),
                target_chain: "spora".to_string(),
                vm_abi: format!("molecule-0x{:04x}", MOLECULE_VM_ABI_VERSION),
                hash_domain: "spora-domain-separated-blake3".to_string(),
                syscall_set: "spora-ckb-style-load-syscalls".to_string(),
                artifact_packaging: match artifact_format {
                    ArtifactFormat::RiscvAssembly => "spora-asm-sidecar".to_string(),
                    ArtifactFormat::RiscvElf => "spora-elf-sporabi-trailer".to_string(),
                },
                header_abi: "spora-dag-header".to_string(),
                scheduler_abi: "spora-scheduler-witness-v1-molecule".to_string(),
            },
            Self::Ckb => TargetProfileMetadata {
                name: self.name().to_string(),
                target_chain: "ckb".to_string(),
                vm_abi: "ckb-molecule".to_string(),
                hash_domain: "ckb-packed-molecule-blake2b".to_string(),
                syscall_set: "ckb-mainnet-syscalls".to_string(),
                artifact_packaging: match artifact_format {
                    ArtifactFormat::RiscvAssembly => "ckb-asm-sidecar".to_string(),
                    ArtifactFormat::RiscvElf => "ckb-elf-no-sporabi-trailer".to_string(),
                },
                header_abi: "ckb-header".to_string(),
                scheduler_abi: "none".to_string(),
            },
            Self::PortableCell => TargetProfileMetadata {
                name: self.name().to_string(),
                target_chain: "portable-cell-source-subset".to_string(),
                vm_abi: "target-selected-molecule".to_string(),
                hash_domain: "target-selected".to_string(),
                syscall_set: "portable-cell-common-subset".to_string(),
                artifact_packaging: "target-selected".to_string(),
                header_abi: "portable-cell-common-subset".to_string(),
                scheduler_abi: "none".to_string(),
            },
        }
    }
}

/// Artifact format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactFormat {
    /// RISC-V assembly text
    RiscvAssembly,
    /// RISC-V ELF executable
    RiscvElf,
}

impl ArtifactFormat {
    pub fn from_target(target: &str) -> Result<Self> {
        match target {
            "asm" | "riscv64" | "riscv64-asm" => Ok(Self::RiscvAssembly),
            "elf" | "riscv64-elf" => Ok(Self::RiscvElf),
            other => Err(CompileError::new(
                format!("unsupported target '{}'; supported targets: asm, riscv64-asm, riscv64, riscv64-elf", other),
                error::Span::default(),
            )),
        }
    }

    pub fn file_extension(self) -> &'static str {
        match self {
            Self::RiscvAssembly => "s",
            Self::RiscvElf => "elf",
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::RiscvAssembly => "RISC-V assembly",
            Self::RiscvElf => "RISC-V ELF",
        }
    }

    pub fn from_display_name(value: &str) -> Result<Self> {
        match value {
            "RISC-V assembly" => Ok(Self::RiscvAssembly),
            "RISC-V ELF" => Ok(Self::RiscvElf),
            other => Err(CompileError::without_span(format!("unsupported artifact format in metadata: '{}'", other))),
        }
    }
}

/// Compile result
#[derive(Debug, Clone)]
pub struct CompileResult {
    /// Generated artifact bytes
    pub artifact_bytes: Vec<u8>,
    /// Artifact format
    pub artifact_format: ArtifactFormat,
    /// Artifact hash
    pub artifact_hash: [u8; 32],
    /// Compile metadata consumable by schedulers/tools
    pub metadata: CompileMetadata,
    /// Parsed AST (for simulation, etc.)
    pub ast: crate::ast::Module,
}

/// Validated artifact/metadata pair loaded from disk.
#[derive(Debug, Clone)]
pub struct ValidatedArtifact {
    /// Artifact bytes read from disk
    pub artifact_bytes: Vec<u8>,
    /// Artifact format declared by metadata
    pub artifact_format: ArtifactFormat,
    /// Computed artifact hash
    pub artifact_hash: [u8; 32],
    /// Compile metadata bound to the artifact
    pub metadata: CompileMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileMetadata {
    pub metadata_schema_version: u32,
    pub compiler_version: String,
    pub module: String,
    pub artifact_format: String,
    pub target_profile: TargetProfileMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_hash_blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_hash_blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_content_hash_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_units: Vec<SourceUnitMetadata>,
    pub lowering: LoweringMetadata,
    pub runtime: RuntimeMetadata,
    #[serde(default)]
    pub constraints: ConstraintsMetadata,
    #[serde(default)]
    pub molecule_schema_manifest: MoleculeSchemaManifestMetadata,
    pub types: Vec<TypeMetadata>,
    pub actions: Vec<ActionMetadata>,
    pub functions: Vec<FunctionMetadata>,
    pub locks: Vec<LockMetadata>,
    /// Embedded DWARF debug section names (non-empty when debug mode is enabled for ELF artifacts)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub debug_info_sections: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MoleculeSchemaManifestMetadata {
    pub schema: String,
    pub version: u32,
    pub abi: String,
    pub target_profile: String,
    pub type_count: usize,
    pub fixed_type_count: usize,
    pub dynamic_type_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<MoleculeSchemaManifestEntryMetadata>,
    pub manifest_hash_blake3: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MoleculeSchemaManifestEntryMetadata {
    pub type_name: String,
    pub kind: String,
    pub layout: String,
    pub fixed_size: usize,
    pub encoded_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_fields: Vec<String>,
    pub schema_hash_blake3: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_offsets: Vec<MoleculeSchemaManifestFieldMetadata>,
    pub target_profile_compatible: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MoleculeSchemaManifestFieldMetadata {
    pub name: String,
    pub ty: String,
    pub offset: usize,
    pub encoded_size: Option<usize>,
    pub fixed_width: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstraintsMetadata {
    pub target_profile: String,
    pub status: String,
    pub entry_abi: Vec<EntryAbiConstraintsMetadata>,
    pub artifact: ArtifactConstraintsMetadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_errors: Vec<RuntimeErrorConstraintsMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ckb: Option<CkbConstraintsMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spora: Option<SporaConstraintsMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeErrorConstraintsMetadata {
    pub code: u64,
    pub name: String,
    pub description: String,
    pub hint: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryAbiConstraintsMetadata {
    pub entry_kind: String,
    pub entry_name: String,
    pub param_count: usize,
    pub abi_slots_used: usize,
    pub register_slots_used: usize,
    pub stack_spill_slots: usize,
    pub stack_spill_bytes: usize,
    pub witness_payload_bytes: usize,
    pub min_witness_bytes: usize,
    pub unsupported: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsupported_reasons: Vec<String>,
    pub params: Vec<ParamAbiConstraintsMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ParamAbiConstraintsMetadata {
    pub name: String,
    pub ty: String,
    pub abi_kind: String,
    pub abi_slots: usize,
    pub slot_start: usize,
    pub slot_end: usize,
    pub register_slots: usize,
    pub stack_spill_slots: usize,
    pub stack_spill_bytes: usize,
    pub witness_bytes: usize,
    pub pointer_length_pair: bool,
    pub pointer_pair_crosses_register_boundary: bool,
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactConstraintsMetadata {
    pub format: String,
    pub artifact_size_bytes: usize,
    pub text_bytes: Option<usize>,
    pub rodata_bytes: Option<usize>,
    pub relaxed_branch_count: Option<usize>,
    pub max_cond_branch_abs_distance: Option<u64>,
    pub machine_block_count: Option<usize>,
    pub machine_cfg_edge_count: Option<usize>,
    pub machine_call_edge_count: Option<usize>,
    pub unreachable_machine_block_count: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbConstraintsMetadata {
    pub limits_source: String,
    #[serde(default)]
    pub hash_domain: String,
    #[serde(default)]
    pub script_hash_algorithm: String,
    #[serde(default)]
    pub transaction_hash_algorithm: String,
    #[serde(default)]
    pub sighash_algorithm: String,
    #[serde(default)]
    pub supported_script_hash_types: Vec<String>,
    #[serde(default)]
    pub declared_type_id_hash_type: String,
    #[serde(default)]
    pub hash_type_policy_surface: String,
    #[serde(default)]
    pub hash_type_policy: CkbHashTypePolicyMetadata,
    #[serde(default)]
    pub dep_group_manifest: CkbDepGroupManifestMetadata,
    pub max_tx_verify_cycles: u64,
    pub max_block_cycles: u64,
    pub max_block_bytes: u64,
    pub estimated_cycles: Option<u64>,
    pub measured_cycles: Option<u64>,
    pub cycles_status: String,
    pub min_code_cell_data_capacity_shannons: u64,
    pub recommended_code_cell_capacity_shannons: u64,
    pub min_witness_bytes: usize,
    pub max_entry_witness_bytes: usize,
    pub dry_run_required_for_production: bool,
    pub tx_size_bytes: Option<usize>,
    #[serde(default)]
    pub tx_size_measurement_required: bool,
    pub tx_size_status: String,
    #[serde(default)]
    pub occupied_capacity_measurement_required: bool,
    pub capacity_status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ckb_runtime_features: Vec<String>,
    pub uses_input_since: bool,
    pub uses_header_epoch: bool,
    pub transaction_runtime_input_requirement_count: usize,
    pub timelock_policy_surface: String,
    #[serde(default)]
    pub timelock_policy: CkbTimelockPolicyMetadata,
    pub created_output_count: usize,
    pub mutated_output_count: usize,
    pub capacity_planning_required: bool,
    pub capacity_policy_surface: String,
    #[serde(default)]
    pub capacity_evidence_contract: CkbCapacityEvidenceContractMetadata,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbHashTypePolicyMetadata {
    pub source: String,
    pub default_script_hash_type: String,
    pub declared_hash_type: Option<String>,
    pub type_id_hash_type: String,
    pub supported_hash_types: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbDepGroupManifestMetadata {
    pub source: String,
    pub dep_group_supported: bool,
    pub production_manifest_required: bool,
    pub declared_cell_deps: Vec<CkbCellDepMetadata>,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbCellDepMetadata {
    pub name: String,
    pub artifact_hash: Option<String>,
    pub tx_hash: Option<String>,
    pub index: Option<u32>,
    pub dep_type: String,
    pub data_hash: Option<String>,
    pub hash_type: Option<String>,
    pub type_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbTimelockPolicyMetadata {
    pub uses_input_since: bool,
    pub uses_header_epoch: bool,
    pub policy_kind: String,
    pub runtime_features: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CkbCapacityEvidenceContractMetadata {
    pub required: bool,
    pub code_cell_lower_bound_shannons: u64,
    pub recommended_code_cell_capacity_shannons: u64,
    pub occupied_capacity_measurement_required: bool,
    pub tx_size_measurement_required: bool,
    pub measured_occupied_capacity_shannons: Option<u64>,
    pub measured_tx_size_bytes: Option<usize>,
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SporaConstraintsMetadata {
    pub limits_source: String,
    pub estimated_compute_mass: u64,
    pub estimated_storage_mass: u64,
    pub estimated_transient_mass: u64,
    pub estimated_code_deployment_mass: u64,
    pub max_block_mass: u64,
    #[serde(default)]
    pub max_standard_transaction_mass: u64,
    #[serde(default)]
    pub fits_standard_transaction_mass_estimate: bool,
    #[serde(default)]
    pub fits_standard_block_mass_estimate: bool,
    pub requires_relaxed_mass_policy: bool,
    pub mass_status: String,
    #[serde(default)]
    pub standard_relay_policy_surface: String,
    pub estimator: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceUnitMetadata {
    pub path: String,
    pub role: String,
    pub hash_blake3: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoweringMetadata {
    pub protocol_semantics: String,
    pub assembly_path: String,
    pub elf_path: String,
    pub semantics_preserving_claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetadata {
    pub vm_target: String,
    pub vm_version: String,
    pub syscall_abi: String,
    pub vm_abi: VmAbiMetadata,
    pub pure_elf_runner: String,
    pub ckb_runtime_required: bool,
    pub ckb_runtime_features: Vec<String>,
    pub standalone_runner_compatible: bool,
    pub symbolic_cell_runtime_required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub legacy_symbolic_cell_runtime_features: Vec<String>,
    pub fail_closed_runtime_features: Vec<String>,
    pub ckb_runtime_accesses: Vec<CkbRuntimeAccessMetadata>,
    pub verifier_obligations: Vec<VerifierObligationMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_runtime_input_requirements: Vec<TransactionRuntimeInputRequirementMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool_primitives: Vec<PoolPrimitiveMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetProfileMetadata {
    pub name: String,
    pub target_chain: String,
    pub vm_abi: String,
    pub hash_domain: String,
    pub syscall_set: String,
    pub artifact_packaging: String,
    pub header_abi: String,
    pub scheduler_abi: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmAbiMetadata {
    pub format: String,
    pub version: u16,
    pub default: bool,
    pub embedded_in_artifact: bool,
    pub scope: String,
    pub selection: String,
}

const VM_ABI_TRAILER_MAGIC: &[u8; 8] = b"SPORABI\0";
const VM_ABI_TRAILER_LEN: usize = 16;
const MOLECULE_VM_ABI_VERSION: u16 = 0x8001;

/// Strip CellScript's fixed VM ABI trailer before directly loading an ELF into CKB-VM.
pub fn strip_vm_abi_trailer(bytes: &[u8]) -> &[u8] {
    if has_vm_abi_trailer_magic(bytes) {
        &bytes[..bytes.len() - VM_ABI_TRAILER_LEN]
    } else {
        bytes
    }
}

fn has_vm_abi_trailer_magic(bytes: &[u8]) -> bool {
    if bytes.len() < VM_ABI_TRAILER_LEN {
        return false;
    }
    let trailer_start = bytes.len() - VM_ABI_TRAILER_LEN;
    &bytes[trailer_start..trailer_start + VM_ABI_TRAILER_MAGIC.len()] == VM_ABI_TRAILER_MAGIC
}

fn vm_abi_trailer_version(bytes: &[u8]) -> Result<Option<u16>> {
    if !has_vm_abi_trailer_magic(bytes) {
        return Ok(None);
    }

    let trailer_start = bytes.len() - VM_ABI_TRAILER_LEN;
    let trailer = &bytes[trailer_start..];
    let version = u16::from_le_bytes([trailer[8], trailer[9]]);
    let flags = u16::from_le_bytes([trailer[10], trailer[11]]);
    let reserved = u32::from_le_bytes([trailer[12], trailer[13], trailer[14], trailer[15]]);
    if flags != 0 || reserved != 0 {
        return Err(CompileError::without_span("invalid VM ABI trailer: flags/reserved bytes must be zero"));
    }
    Ok(Some(version))
}

fn append_vm_abi_trailer(mut artifact: Vec<u8>, abi_version: u16) -> Vec<u8> {
    if strip_vm_abi_trailer(&artifact).len() != artifact.len() {
        artifact.truncate(artifact.len() - VM_ABI_TRAILER_LEN);
    }
    artifact.extend_from_slice(VM_ABI_TRAILER_MAGIC);
    artifact.extend_from_slice(&abi_version.to_le_bytes());
    artifact.extend_from_slice(&0u16.to_le_bytes());
    artifact.extend_from_slice(&0u32.to_le_bytes());
    artifact
}

pub fn validate_compile_metadata(metadata: &CompileMetadata, artifact_format: ArtifactFormat) -> Result<()> {
    if metadata.metadata_schema_version != METADATA_SCHEMA_VERSION {
        return Err(CompileError::without_span(format!(
            "unsupported metadata_schema_version {}; expected {}",
            metadata.metadata_schema_version, METADATA_SCHEMA_VERSION
        )));
    }
    if metadata.compiler_version != VERSION {
        return Err(CompileError::without_span(format!(
            "metadata compiler_version '{}' does not match current compiler '{}'",
            metadata.compiler_version, VERSION
        )));
    }

    if metadata.artifact_format != artifact_format.display_name() {
        return Err(CompileError::without_span(format!(
            "metadata artifact_format '{}' does not match compiler artifact format '{}'",
            metadata.artifact_format,
            artifact_format.display_name()
        )));
    }
    validate_target_profile_metadata(metadata, artifact_format)?;

    if metadata.runtime.vm_abi.format != "molecule" {
        return Err(CompileError::without_span(format!(
            "metadata runtime.vm_abi.format must be 'molecule', got '{}'",
            metadata.runtime.vm_abi.format
        )));
    }
    if metadata.runtime.vm_abi.version != MOLECULE_VM_ABI_VERSION {
        return Err(CompileError::without_span(format!(
            "metadata runtime.vm_abi.version must be 0x{:04x}, got 0x{:04x}",
            MOLECULE_VM_ABI_VERSION, metadata.runtime.vm_abi.version
        )));
    }

    let profile = TargetProfile::from_name(&metadata.target_profile.name)?;
    let should_embed_abi = profile.embeds_vm_abi_trailer(artifact_format);
    if metadata.runtime.vm_abi.embedded_in_artifact != should_embed_abi {
        return Err(CompileError::without_span(format!(
            "metadata runtime.vm_abi.embedded_in_artifact must be {} for {} {} artifacts",
            should_embed_abi,
            profile.name(),
            artifact_format.display_name()
        )));
    }

    if metadata.runtime.standalone_runner_compatible && metadata.runtime.ckb_runtime_required {
        return Err(CompileError::without_span(
            "metadata marks artifact as standalone-compatible while CKB runtime features are required",
        ));
    }
    // No operations are purely symbolic anymore; fail-closed features are
    // acceptable for standalone compatibility (they halt with specific
    // error codes rather than producing wrong results).

    validate_type_identity_metadata(metadata)?;
    validate_ckb_type_id_output_metadata(metadata)?;
    validate_molecule_schema_metadata(metadata)?;
    validate_molecule_schema_manifest_metadata(metadata)?;
    validate_source_metadata(metadata)?;

    Ok(())
}

fn validate_target_profile_metadata(metadata: &CompileMetadata, artifact_format: ArtifactFormat) -> Result<()> {
    let profile = TargetProfile::from_name(&metadata.target_profile.name)?;
    let expected = profile.metadata(artifact_format);
    let actual = &metadata.target_profile;

    let mismatches = [
        ("target_chain", actual.target_chain.as_str(), expected.target_chain.as_str()),
        ("vm_abi", actual.vm_abi.as_str(), expected.vm_abi.as_str()),
        ("hash_domain", actual.hash_domain.as_str(), expected.hash_domain.as_str()),
        ("syscall_set", actual.syscall_set.as_str(), expected.syscall_set.as_str()),
        ("artifact_packaging", actual.artifact_packaging.as_str(), expected.artifact_packaging.as_str()),
        ("header_abi", actual.header_abi.as_str(), expected.header_abi.as_str()),
        ("scheduler_abi", actual.scheduler_abi.as_str(), expected.scheduler_abi.as_str()),
    ];
    for (field, actual, expected) in mismatches {
        if actual != expected {
            return Err(CompileError::without_span(format!(
                "metadata target_profile.{} '{}' does not match expected '{}' for profile '{}' and {} artifact",
                field,
                actual,
                expected,
                profile.name(),
                artifact_format.display_name()
            )));
        }
    }

    Ok(())
}

fn target_profile_artifact_policy_violations(metadata: &CompileMetadata, profile: TargetProfile) -> Vec<String> {
    match profile {
        TargetProfile::Spora => spora_target_profile_policy_violations(metadata),
        TargetProfile::Ckb => {
            let mut violations = common_portability_policy_violations(metadata);
            let spora_only_features = metadata
                .runtime
                .ckb_runtime_features
                .iter()
                .filter(|feature| matches!(feature.as_str(), "load-claim-ecdsa-signature-hash" | "verify-claim-secp256k1-signature"))
                .cloned()
                .collect::<Vec<_>>();
            if !spora_only_features.is_empty() {
                violations.push(format!("Spora-only claim helper syscall features: {}", spora_only_features.join(", ")));
            }
            violations
        }
        TargetProfile::PortableCell => {
            vec!["portable-cell is a source compatibility profile; compile with 'spora' or 'ckb' to produce artifacts".to_string()]
        }
    }
}

fn spora_target_profile_policy_violations(metadata: &CompileMetadata) -> Vec<String> {
    let mut violations = Vec::new();
    let ckb_only_features = ckb_only_feature_names(metadata);
    if !ckb_only_features.is_empty() {
        violations.push(format!("CKB chain APIs require the 'ckb' target profile: {}", ckb_only_features.join(", ")));
    }
    violations
}

fn common_portability_policy_violations(metadata: &CompileMetadata) -> Vec<String> {
    let mut violations = Vec::new();

    if metadata.runtime.ckb_runtime_features.iter().any(|feature| feature == "load-header-daa-score") {
        violations.push("DAA/header assumptions are Spora-specific and not portable across target profiles".to_string());
    }

    if !metadata.runtime.fail_closed_runtime_features.is_empty() {
        violations.push(format!(
            "fail-closed runtime features are not portable: {}",
            metadata.runtime.fail_closed_runtime_features.join(", ")
        ));
    }

    let runtime_required_obligations = metadata
        .runtime
        .verifier_obligations
        .iter()
        .filter(|obligation| obligation.status == "runtime-required")
        .map(|obligation| format!("{}:{} ({})", obligation.scope, obligation.feature, obligation.category))
        .collect::<Vec<_>>();
    if !runtime_required_obligations.is_empty() {
        violations
            .push(format!("runtime-required verifier obligations are not portable: {}", runtime_required_obligations.join(", ")));
    }

    let runtime_required_inputs = metadata
        .runtime
        .transaction_runtime_input_requirements
        .iter()
        .filter(|requirement| requirement.status == "runtime-required")
        .map(|requirement| format!("{}:{} ({})", requirement.scope, requirement.feature, requirement.component))
        .collect::<Vec<_>>();
    if !runtime_required_inputs.is_empty() {
        violations.push(format!("runtime-required transaction inputs are not portable: {}", runtime_required_inputs.join(", ")));
    }

    let persistent_types_without_schema = metadata
        .types
        .iter()
        .filter(|ty| matches!(ty.kind.as_str(), "Resource" | "Shared" | "Receipt"))
        .filter(|ty| !type_has_public_molecule_schema(ty))
        .map(|ty| format!("{} ({})", ty.name, ty.kind))
        .collect::<Vec<_>>();
    if !persistent_types_without_schema.is_empty() {
        violations.push(format!(
            "generated Molecule schemas are required before persistent Cell types can be CKB-portable: {}",
            persistent_types_without_schema.join(", ")
        ));
    }

    let type_only_type_ids = metadata
        .types
        .iter()
        .filter(|ty| ty.type_id.is_some() && ty.ckb_type_id.is_none())
        .map(|ty| ty.name.clone())
        .collect::<Vec<_>>();
    if !type_only_type_ids.is_empty() {
        violations.push(format!(
            "type-only type_id declarations require profile-specific type-id lowering before they are portable: {}",
            type_only_type_ids.join(", ")
        ));
    }

    let shared_touch_actions = ckb_unportable_shared_touch_actions(metadata);
    if !shared_touch_actions.is_empty() {
        violations.push(format!(
            "Spora shared-state scheduler touch domains have unresolved state semantics: {}",
            shared_touch_actions.join(", ")
        ));
    }

    let pool_features = metadata
        .runtime
        .pool_primitives
        .iter()
        .filter(|primitive| primitive.status != "checked-runtime" || !primitive.runtime_required_components.is_empty())
        .map(|primitive| primitive.feature.clone())
        .collect::<Vec<_>>();
    if !pool_features.is_empty() {
        violations.push(format!("Spora pool-pattern scheduler/admission semantics are not portable: {}", pool_features.join(", ")));
    }

    violations
}

fn ckb_unportable_shared_touch_actions(metadata: &CompileMetadata) -> Vec<String> {
    metadata
        .actions
        .iter()
        .filter(|action| !action.touches_shared.is_empty())
        .filter(|action| {
            action
                .verifier_obligations
                .iter()
                .any(|obligation| obligation.category == "shared-state" && obligation.status != "checked-runtime")
        })
        .map(|action| action.name.clone())
        .collect()
}

fn ckb_only_feature_names(metadata: &CompileMetadata) -> Vec<String> {
    metadata
        .runtime
        .ckb_runtime_features
        .iter()
        .filter(|feature| feature.starts_with("ckb-header-epoch-") || feature.as_str() == "ckb-input-since")
        .cloned()
        .collect()
}

fn type_has_public_molecule_schema(ty: &TypeMetadata) -> bool {
    ty.molecule_schema.as_ref().is_some_and(|schema| {
        schema.abi == "molecule"
            && matches!(schema.layout.as_str(), "fixed-struct-v1" | "molecule-table-v1")
            && !schema.schema.is_empty()
    })
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn ckb_blake2b256(data: &[u8]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new().hash_length(32).personal(CKB_DEFAULT_HASH_PERSONALIZATION).to_state();
    state.update(data);
    let digest = state.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out
}

fn is_canonical_blake3_hex(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod ckb_hash_tests {
    #[test]
    fn ckb_blake2b256_matches_blank_hash_vector() {
        assert_eq!(super::ckb_blake2b256(b""), super::CKB_BLANK_HASH);
        assert_eq!(super::hex_encode(&super::ckb_blake2b256(b"")), "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e");
    }
}

fn bind_artifact_metadata(metadata: &mut CompileMetadata, artifact_bytes: &[u8], artifact_hash: &[u8; 32]) {
    metadata.artifact_hash_blake3 = Some(hex_encode(artifact_hash));
    metadata.artifact_size_bytes = Some(artifact_bytes.len());
}

const CKB_SHANNONS_PER_CKB: u64 = 100_000_000;
const CKB_DEFAULT_MAX_TX_VERIFY_CYCLES: u64 = 70_000_000;
const CKB_DEFAULT_MAX_BLOCK_CYCLES: u64 = 10_000_000_000;
const CKB_DEFAULT_MAX_BLOCK_BYTES: u64 = 597_000;
const SPORA_DEFAULT_MAX_BLOCK_MASS: u64 = 2_000_000;
const SPORA_DEFAULT_MAX_STANDARD_TRANSACTION_MASS: u64 = 500_000;

fn bind_constraints_metadata(
    metadata: &mut CompileMetadata,
    artifact_bytes: &[u8],
    artifact_format: ArtifactFormat,
    target_profile: TargetProfile,
    ir: &ir::IrModule,
    codegen_options: &codegen::CodegenOptions,
) -> Result<()> {
    let assembly_for_shape = if artifact_format == ArtifactFormat::RiscvAssembly {
        std::str::from_utf8(artifact_bytes).ok().map(str::to_string)
    } else {
        codegen::generate(ir, codegen_options, ArtifactFormat::RiscvAssembly).ok().and_then(|bytes| String::from_utf8(bytes).ok())
    };
    let backend_shape = assembly_for_shape.as_deref().and_then(|assembly| codegen::analyze_backend_shape(assembly).ok());
    metadata.constraints =
        constraints_metadata(metadata, artifact_bytes.len(), artifact_format, target_profile, backend_shape.as_ref());
    Ok(())
}

fn constraints_metadata(
    metadata: &CompileMetadata,
    artifact_size_bytes: usize,
    artifact_format: ArtifactFormat,
    target_profile: TargetProfile,
    backend_shape: Option<&codegen::BackendShapeMetrics>,
) -> ConstraintsMetadata {
    let mut warnings = Vec::new();
    let mut failures = Vec::new();
    let mut entry_abi = Vec::new();
    entry_abi.extend(metadata.actions.iter().map(|action| entry_abi_constraints("action", &action.name, &action.params)));
    entry_abi.extend(metadata.locks.iter().map(|lock| entry_abi_constraints("lock", &lock.name, &lock.params)));
    for entry in &entry_abi {
        if entry.unsupported {
            failures.push(format!(
                "{} '{}' has unsupported entry ABI: {}",
                entry.entry_kind,
                entry.entry_name,
                entry.unsupported_reasons.join("; ")
            ));
        }
        for param in &entry.params {
            if param.pointer_pair_crosses_register_boundary {
                warnings.push(format!(
                    "{} '{}' parameter '{}' pointer/length ABI pair crosses a0-a7 boundary at slots {}..{}",
                    entry.entry_kind, entry.entry_name, param.name, param.slot_start, param.slot_end
                ));
            }
        }
    }

    let artifact = ArtifactConstraintsMetadata {
        format: artifact_format.display_name().to_string(),
        artifact_size_bytes,
        text_bytes: backend_shape.map(|shape| shape.text_size),
        rodata_bytes: backend_shape.map(|shape| shape.rodata_size),
        relaxed_branch_count: backend_shape.map(|shape| shape.relaxed_branch_count),
        max_cond_branch_abs_distance: backend_shape.map(|shape| shape.max_cond_branch_abs_distance),
        machine_block_count: backend_shape.map(|shape| shape.machine_block_count),
        machine_cfg_edge_count: backend_shape.map(|shape| shape.machine_cfg_edge_count),
        machine_call_edge_count: backend_shape.map(|shape| shape.machine_call_edge_count),
        unreachable_machine_block_count: backend_shape.map(|shape| shape.unreachable_machine_block_count),
    };
    if backend_shape.is_none() {
        warnings.push("backend shape metrics were not available for this artifact".to_string());
    }
    let runtime_errors = runtime_errors::ALL_RUNTIME_ERRORS
        .iter()
        .map(|error| {
            let info = runtime_errors::runtime_error_info(*error);
            RuntimeErrorConstraintsMetadata {
                code: info.code,
                name: info.name.to_string(),
                description: info.description.to_string(),
                hint: info.hint.to_string(),
            }
        })
        .collect();

    let max_entry_witness_bytes = entry_abi.iter().map(|entry| entry.min_witness_bytes).max().unwrap_or(0);
    let estimated_cycles = metadata.actions.iter().map(|action| action.estimated_cycles).chain(metadata.locks.iter().map(|_| 0)).max();
    let ckb = (target_profile == TargetProfile::Ckb).then(|| {
        warnings.push(
            "CKB cycles and transaction size are not measured by the compiler; require builder dry-run for production".to_string(),
        );
        let ckb = ckb_constraints(metadata, artifact_size_bytes, max_entry_witness_bytes, estimated_cycles);
        if ckb.uses_input_since || ckb.uses_header_epoch {
            warnings.push(format!(
                "CKB timelock-related runtime features are in use (input_since={}, header_epoch={}); declarative DSL policy surface is not yet first-class",
                ckb.uses_input_since, ckb.uses_header_epoch
            ));
        }
        if ckb.capacity_planning_required {
            warnings.push(format!(
                "CKB output capacity planning is required for this artifact (create outputs={}, mutate outputs={}); full transaction-level capacity remains builder/runtime-managed",
                ckb.created_output_count, ckb.mutated_output_count
            ));
        }
        ckb
    });
    let spora = (target_profile == TargetProfile::Spora)
        .then(|| spora_constraints(artifact_size_bytes, max_entry_witness_bytes, estimated_cycles));

    let status = if !failures.is_empty() {
        "fail"
    } else if !warnings.is_empty() {
        "warn"
    } else {
        "pass"
    }
    .to_string();

    ConstraintsMetadata {
        target_profile: metadata.target_profile.name.clone(),
        status,
        entry_abi,
        artifact,
        runtime_errors,
        ckb,
        spora,
        warnings,
        failures,
    }
}

fn entry_abi_constraints(entry_kind: &str, entry_name: &str, params: &[ParamMetadata]) -> EntryAbiConstraintsMetadata {
    let mut abi_index = 0usize;
    let mut witness_payload_bytes = 0usize;
    let mut unsupported_reasons = Vec::new();
    let mut param_constraints = Vec::new();

    for param in params {
        let mut abi_slots = 0usize;
        let mut witness_bytes = 0usize;
        let mut abi_kind = "unsupported".to_string();
        let mut supported = true;
        let mut unsupported_reason = None;
        let pointer_length_pair;

        if param.schema_pointer_abi || param.schema_length_abi {
            abi_kind = if param.type_hash_pointer_abi || param.type_hash_length_abi {
                "schema-pointer+type-hash-pointer".to_string()
            } else {
                "schema-pointer".to_string()
            };
            abi_slots = 2 + usize::from(param.type_hash_pointer_abi || param.type_hash_length_abi) * 2;
            witness_bytes = 4;
            pointer_length_pair = true;
        } else if param.fixed_byte_pointer_abi || param.fixed_byte_length_abi {
            abi_kind = "fixed-byte-pointer".to_string();
            abi_slots = 2;
            witness_bytes = param.fixed_byte_len.unwrap_or_default();
            pointer_length_pair = true;
        } else if let Some(width) = entry_witness_scalar_param_width(&param.ty) {
            abi_kind = "scalar".to_string();
            abi_slots = 1;
            witness_bytes = width;
            pointer_length_pair = false;
        } else {
            supported = false;
            unsupported_reason = Some(format!("unsupported entry witness parameter type '{}'", param.ty));
            unsupported_reasons.push(format!("parameter '{}': unsupported type '{}'", param.name, param.ty));
            pointer_length_pair = false;
        }

        let slot_start = abi_index;
        let slot_end = abi_index.saturating_add(abi_slots).saturating_sub(1);
        let register_slots = (slot_start..slot_start + abi_slots).filter(|slot| *slot < 8).count();
        let stack_spill_slots = abi_slots.saturating_sub(register_slots);
        let pointer_pair_crosses_register_boundary = pointer_length_pair && slot_start < 8 && slot_start + abi_slots > 8;
        witness_payload_bytes += witness_bytes;
        param_constraints.push(ParamAbiConstraintsMetadata {
            name: param.name.clone(),
            ty: param.ty.clone(),
            abi_kind,
            abi_slots,
            slot_start,
            slot_end,
            register_slots,
            stack_spill_slots,
            stack_spill_bytes: stack_spill_slots * 8,
            witness_bytes,
            pointer_length_pair,
            pointer_pair_crosses_register_boundary,
            supported,
            unsupported_reason,
        });
        abi_index += abi_slots;
    }

    let register_slots_used = abi_index.min(8);
    let stack_spill_slots = abi_index.saturating_sub(8);
    EntryAbiConstraintsMetadata {
        entry_kind: entry_kind.to_string(),
        entry_name: entry_name.to_string(),
        param_count: params.len(),
        abi_slots_used: abi_index,
        register_slots_used,
        stack_spill_slots,
        stack_spill_bytes: stack_spill_slots * 8,
        witness_payload_bytes,
        min_witness_bytes: ENTRY_WITNESS_ABI_MAGIC.len() + witness_payload_bytes,
        unsupported: !unsupported_reasons.is_empty(),
        unsupported_reasons,
        params: param_constraints,
    }
}

fn ckb_constraints(
    metadata: &CompileMetadata,
    artifact_size_bytes: usize,
    max_entry_witness_bytes: usize,
    estimated_cycles: Option<u64>,
) -> CkbConstraintsMetadata {
    let max_tx_verify_cycles = env_u64("CELLSCRIPT_CKB_MAX_TX_VERIFY_CYCLES").unwrap_or(CKB_DEFAULT_MAX_TX_VERIFY_CYCLES);
    let max_block_cycles = env_u64("CELLSCRIPT_CKB_MAX_BLOCK_CYCLES").unwrap_or(CKB_DEFAULT_MAX_BLOCK_CYCLES);
    let max_block_bytes = env_u64("CELLSCRIPT_CKB_MAX_BLOCK_BYTES").unwrap_or(CKB_DEFAULT_MAX_BLOCK_BYTES);
    let min_code_cell_data_capacity_shannons = (artifact_size_bytes as u64 + 8) * CKB_SHANNONS_PER_CKB;
    let recommended_code_cell_capacity_shannons = (artifact_size_bytes as u64 + 1_000) * CKB_SHANNONS_PER_CKB;
    let ckb_runtime_features = metadata.runtime.ckb_runtime_features.clone();
    let uses_input_since = ckb_runtime_features.iter().any(|feature| feature == "ckb-input-since");
    let uses_header_epoch = ckb_runtime_features.iter().any(|feature| feature.starts_with("ckb-header-epoch-"));
    let created_output_count = metadata
        .actions
        .iter()
        .map(|action| action.create_set.len())
        .chain(metadata.locks.iter().map(|lock| lock.create_set.len()))
        .sum();
    let mutated_output_count = metadata
        .actions
        .iter()
        .map(|action| action.mutate_set.len())
        .chain(metadata.locks.iter().map(|lock| lock.mutate_set.len()))
        .sum();
    let capacity_planning_required = created_output_count > 0 || mutated_output_count > 0;
    CkbConstraintsMetadata {
        limits_source: ckb_limits_source(),
        hash_domain: "ckb-packed-molecule-blake2b".to_string(),
        script_hash_algorithm: "blake2b-256(personal=ckb-default-hash) over packed Script".to_string(),
        transaction_hash_algorithm: "blake2b-256(personal=ckb-default-hash) over packed RawTransaction".to_string(),
        sighash_algorithm: "ckb witness-sighash blake2b-256".to_string(),
        supported_script_hash_types: vec!["data".to_string(), "type".to_string(), "data1".to_string(), "data2".to_string()],
        declared_type_id_hash_type: CKB_TYPE_ID_HASH_TYPE.to_string(),
        hash_type_policy_surface: "compiler-declared-type-id-hash-type; builder must preserve script hash_type in deployed cells"
            .to_string(),
        hash_type_policy: CkbHashTypePolicyMetadata {
            source: "compiler-default".to_string(),
            default_script_hash_type: CKB_DEFAULT_SCRIPT_HASH_TYPE.to_string(),
            declared_hash_type: None,
            type_id_hash_type: CKB_TYPE_ID_HASH_TYPE.to_string(),
            supported_hash_types: ckb_supported_hash_types(),
            status: "builder-must-preserve-script-hash-type".to_string(),
        },
        dep_group_manifest: CkbDepGroupManifestMetadata {
            source: "not-declared".to_string(),
            dep_group_supported: true,
            production_manifest_required: false,
            declared_cell_deps: Vec::new(),
            status: "no-cell-deps-declared".to_string(),
            warnings: Vec::new(),
        },
        max_tx_verify_cycles,
        max_block_cycles,
        max_block_bytes,
        estimated_cycles,
        measured_cycles: None,
        cycles_status: "not-measured-by-compiler".to_string(),
        min_code_cell_data_capacity_shannons,
        recommended_code_cell_capacity_shannons,
        min_witness_bytes: ENTRY_WITNESS_ABI_MAGIC.len(),
        max_entry_witness_bytes,
        dry_run_required_for_production: true,
        tx_size_bytes: None,
        tx_size_measurement_required: true,
        tx_size_status: "builder-required".to_string(),
        occupied_capacity_measurement_required: capacity_planning_required,
        capacity_status: if capacity_planning_required {
            "builder-occupied-capacity-measurement-required".to_string()
        } else {
            "code-cell-data-lower-bound".to_string()
        },
        ckb_runtime_features: ckb_runtime_features.clone(),
        uses_input_since,
        uses_header_epoch,
        transaction_runtime_input_requirement_count: metadata.runtime.transaction_runtime_input_requirements.len(),
        timelock_policy_surface: if uses_input_since || uses_header_epoch {
            "runtime-metadata-visible; declarative-dsl-policy-not-yet-first-class".to_string()
        } else {
            "not-applicable".to_string()
        },
        timelock_policy: CkbTimelockPolicyMetadata {
            uses_input_since,
            uses_header_epoch,
            policy_kind: if uses_input_since || uses_header_epoch {
                "runtime-assertion-policy".to_string()
            } else {
                "not-applicable".to_string()
            },
            runtime_features: ckb_runtime_features
                .iter()
                .filter(|feature| feature.starts_with("ckb-header-epoch-") || feature.as_str() == "ckb-input-since")
                .cloned()
                .collect(),
            status: if uses_input_since || uses_header_epoch {
                "reported-runtime-policy-builder-must-preserve-since/header-context".to_string()
            } else {
                "not-applicable".to_string()
            },
        },
        created_output_count,
        mutated_output_count,
        capacity_planning_required,
        capacity_policy_surface: if capacity_planning_required {
            "builder/runtime-required; declarative-dsl-capacity-not-yet-first-class".to_string()
        } else {
            "not-applicable".to_string()
        },
        capacity_evidence_contract: CkbCapacityEvidenceContractMetadata {
            required: true,
            code_cell_lower_bound_shannons: min_code_cell_data_capacity_shannons,
            recommended_code_cell_capacity_shannons,
            occupied_capacity_measurement_required: capacity_planning_required,
            tx_size_measurement_required: true,
            measured_occupied_capacity_shannons: None,
            measured_tx_size_bytes: None,
            status: if capacity_planning_required {
                "builder-must-attach-occupied-capacity-and-tx-size-evidence".to_string()
            } else {
                "builder-must-attach-tx-size-evidence-code-cell-lower-bound-available".to_string()
            },
        },
    }
}

fn ckb_supported_hash_types() -> Vec<String> {
    vec!["data".to_string(), "type".to_string(), "data1".to_string(), "data2".to_string()]
}

fn apply_manifest_deploy_metadata(metadata: &mut CompileMetadata, manifest: &CellManifest) -> Result<()> {
    let Some(ckb_manifest) = manifest.deploy.ckb.as_ref() else {
        return Ok(());
    };
    let Some(ckb_constraints) = metadata.constraints.ckb.as_mut() else {
        return Ok(());
    };

    if let Some(hash_type) = ckb_manifest.hash_type.as_deref() {
        validate_ckb_hash_type(hash_type)?;
        ckb_constraints.hash_type_policy.source = "Cell.toml deploy.ckb.hash_type".to_string();
        ckb_constraints.hash_type_policy.declared_hash_type = Some(hash_type.to_string());
        ckb_constraints.hash_type_policy.status = "manifest-declared-builder-must-match".to_string();
        ckb_constraints.hash_type_policy_surface =
            "manifest-declared-script-hash-type; builder/deployment output must match".to_string();
    }

    let mut declared_cell_deps = Vec::new();
    if ckb_manifest.out_point.is_some() || ckb_manifest.dep_type.is_some() || ckb_manifest.data_hash.is_some() {
        let dep_type = ckb_manifest.dep_type.as_deref().unwrap_or("code");
        validate_ckb_dep_type(dep_type)?;
        let (tx_hash, index) = ckb_manifest
            .out_point
            .as_deref()
            .map(parse_ckb_out_point)
            .transpose()?
            .map(|(tx_hash, index)| (Some(tx_hash), Some(index)))
            .unwrap_or((None, None));
        declared_cell_deps.push(CkbCellDepMetadata {
            name: "primary".to_string(),
            artifact_hash: ckb_manifest.artifact_hash.clone(),
            tx_hash,
            index,
            dep_type: dep_type.to_string(),
            data_hash: ckb_manifest.data_hash.clone(),
            hash_type: ckb_manifest.hash_type.clone(),
            type_id: ckb_manifest.type_id.clone(),
        });
    }
    for (index, dep) in ckb_manifest.cell_deps.iter().enumerate() {
        let dep_type = dep.dep_type.as_deref().unwrap_or("code");
        validate_ckb_dep_type(dep_type)?;
        if let Some(hash_type) = dep.hash_type.as_deref() {
            validate_ckb_hash_type(hash_type)?;
        }
        let (tx_hash, dep_index) = parse_ckb_cell_dep_location(dep)?;
        declared_cell_deps.push(CkbCellDepMetadata {
            name: dep.name.clone().unwrap_or_else(|| format!("cell_dep_{}", index)),
            artifact_hash: None,
            tx_hash,
            index: dep_index,
            dep_type: dep_type.to_string(),
            data_hash: dep.data_hash.clone(),
            hash_type: dep.hash_type.clone(),
            type_id: dep.type_id.clone(),
        });
    }

    if !declared_cell_deps.is_empty() {
        let has_dep_group = declared_cell_deps.iter().any(|dep| dep.dep_type == "dep_group");
        ckb_constraints.dep_group_manifest.source = "Cell.toml deploy.ckb".to_string();
        ckb_constraints.dep_group_manifest.production_manifest_required = true;
        ckb_constraints.dep_group_manifest.declared_cell_deps = declared_cell_deps;
        ckb_constraints.dep_group_manifest.status = if has_dep_group {
            "manifest-declares-dep-group-builder-must-expand-or-reference".to_string()
        } else {
            "manifest-declares-code-cell-deps".to_string()
        };
    }

    refresh_constraints_status(&mut metadata.constraints);
    Ok(())
}

fn validate_ckb_hash_type(hash_type: &str) -> Result<()> {
    if ckb_supported_hash_types().iter().any(|supported| supported == hash_type) {
        Ok(())
    } else {
        Err(CompileError::without_span(format!("unsupported CKB hash_type '{}'; expected one of data, type, data1, data2", hash_type)))
    }
}

fn validate_ckb_dep_type(dep_type: &str) -> Result<()> {
    if matches!(dep_type, "code" | "dep_group") {
        Ok(())
    } else {
        Err(CompileError::without_span(format!("unsupported CKB dep_type '{}'; expected 'code' or 'dep_group'", dep_type)))
    }
}

fn parse_ckb_cell_dep_location(dep: &CellCkbCellDepConfig) -> Result<(Option<String>, Option<u32>)> {
    if let Some(out_point) = dep.out_point.as_deref() {
        if dep.tx_hash.is_some() || dep.index.is_some() {
            return Err(CompileError::without_span("CKB cell_dep location must use either out_point or tx_hash/index, not both"));
        }
        let (tx_hash, index) = parse_ckb_out_point(out_point)?;
        return Ok((Some(tx_hash), Some(index)));
    }
    if let Some(tx_hash) = dep.tx_hash.as_deref() {
        validate_ckb_tx_hash(tx_hash)?;
    }
    if dep.tx_hash.is_some() != dep.index.is_some() {
        return Err(CompileError::without_span("CKB cell_dep split location must provide both tx_hash and index, or neither"));
    }
    Ok((dep.tx_hash.clone(), dep.index))
}

fn parse_ckb_out_point(out_point: &str) -> Result<(String, u32)> {
    let Some((tx_hash, index)) = out_point.rsplit_once(':') else {
        return Err(CompileError::without_span(format!(
            "invalid CKB out_point '{}'; expected 0x<32-byte-tx-hash>:<index>",
            out_point
        )));
    };
    validate_ckb_tx_hash(tx_hash)?;
    let index = index.parse::<u32>().map_err(|_| {
        CompileError::without_span(format!("invalid CKB out_point index '{}'; expected unsigned 32-bit integer", index))
    })?;
    Ok((tx_hash.to_string(), index))
}

fn validate_ckb_tx_hash(tx_hash: &str) -> Result<()> {
    let hex = tx_hash
        .strip_prefix("0x")
        .ok_or_else(|| CompileError::without_span(format!("invalid CKB tx_hash '{}'; expected 0x-prefixed 32-byte hash", tx_hash)))?;
    if hex.len() != 64 || !hex.as_bytes().iter().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CompileError::without_span(format!("invalid CKB tx_hash '{}'; expected 0x-prefixed 32-byte hash", tx_hash)));
    }
    Ok(())
}

fn refresh_constraints_status(constraints: &mut ConstraintsMetadata) {
    constraints.status = if !constraints.failures.is_empty() {
        "fail"
    } else if !constraints.warnings.is_empty() {
        "warn"
    } else {
        "pass"
    }
    .to_string();
}

fn spora_constraints(
    artifact_size_bytes: usize,
    max_entry_witness_bytes: usize,
    estimated_cycles: Option<u64>,
) -> SporaConstraintsMetadata {
    let max_block_mass = env_u64("CELLSCRIPT_SPORA_MAX_BLOCK_MASS").unwrap_or(SPORA_DEFAULT_MAX_BLOCK_MASS);
    let max_standard_transaction_mass =
        env_u64("CELLSCRIPT_SPORA_MAX_STANDARD_TRANSACTION_MASS").unwrap_or(SPORA_DEFAULT_MAX_STANDARD_TRANSACTION_MASS);
    let estimated_compute_mass = estimated_cycles.unwrap_or_default();
    let estimated_storage_mass = artifact_size_bytes as u64;
    let estimated_transient_mass = max_entry_witness_bytes as u64;
    let estimated_code_deployment_mass = estimated_storage_mass + estimated_transient_mass;
    let total_estimated_mass = estimated_compute_mass + estimated_storage_mass + estimated_transient_mass;
    let fits_standard_transaction_mass_estimate = estimated_code_deployment_mass <= max_standard_transaction_mass;
    let fits_standard_block_mass_estimate = total_estimated_mass <= max_block_mass;
    let requires_relaxed_mass_policy = !(fits_standard_transaction_mass_estimate && fits_standard_block_mass_estimate);
    SporaConstraintsMetadata {
        limits_source: spora_limits_source(),
        estimated_compute_mass,
        estimated_storage_mass,
        estimated_transient_mass,
        estimated_code_deployment_mass,
        max_block_mass,
        max_standard_transaction_mass,
        fits_standard_transaction_mass_estimate,
        fits_standard_block_mass_estimate,
        requires_relaxed_mass_policy,
        mass_status: if requires_relaxed_mass_policy {
            "compiler-estimate-exceeds-standard-policy-requires-scope-split-or-devnet-confirmation".to_string()
        } else {
            "compiler-estimate-within-standard-policy-requires-devnet-or-builder-confirmation".to_string()
        },
        standard_relay_policy_surface: "standard relay tx mass and block mass are compiler-visible; acceptance remains authoritative"
            .to_string(),
        estimator:
            "v1: estimated cycles + artifact bytes + max entry witness bytes; deployment tx mass is verified by devnet acceptance"
                .to_string(),
    }
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|value| value.parse::<u64>().ok())
}

fn ckb_limits_source() -> String {
    let overridden = ["CELLSCRIPT_CKB_MAX_TX_VERIFY_CYCLES", "CELLSCRIPT_CKB_MAX_BLOCK_CYCLES", "CELLSCRIPT_CKB_MAX_BLOCK_BYTES"]
        .iter()
        .filter(|name| std::env::var(name).is_ok())
        .copied()
        .collect::<Vec<_>>();
    if overridden.is_empty() {
        "builtin-ckb-defaults".to_string()
    } else {
        format!("environment:{}", overridden.join(","))
    }
}

fn spora_limits_source() -> String {
    let overridden = ["CELLSCRIPT_SPORA_MAX_BLOCK_MASS", "CELLSCRIPT_SPORA_MAX_STANDARD_TRANSACTION_MASS"]
        .iter()
        .filter(|name| std::env::var(name).is_ok())
        .copied()
        .collect::<Vec<_>>();
    if overridden.is_empty() {
        "builtin-spora-standard-policy".to_string()
    } else {
        format!("environment:{}", overridden.join(","))
    }
}

/// Extract the span from an AST statement, for debug info line table generation.
fn stmt_span(stmt: &ast::Stmt) -> error::Span {
    match stmt {
        ast::Stmt::Let(let_stmt) => let_stmt.span,
        ast::Stmt::Expr(expr) => expr_span(expr),
        ast::Stmt::Return(Some(expr)) => expr_span(expr),
        ast::Stmt::Return(None) => error::Span::default(),
        ast::Stmt::If(if_stmt) => if_stmt.span,
        ast::Stmt::For(for_stmt) => for_stmt.span,
        ast::Stmt::While(while_stmt) => while_stmt.span,
    }
}

/// Extract span from an expression.
fn expr_span(expr: &ast::Expr) -> error::Span {
    // AST expressions don't carry their own Span in the current definition,
    // so we fall back to a default span.
    let _ = expr;
    error::Span::default()
}

fn bind_source_metadata(metadata: &mut CompileMetadata, mut source_units: Vec<SourceUnitMetadata>) {
    if source_units.is_empty() {
        metadata.source_hash_blake3 = None;
        metadata.source_content_hash_blake3 = None;
        metadata.source_units.clear();
        return;
    }

    source_units.sort_by(|left, right| left.path.cmp(&right.path).then(left.role.cmp(&right.role)));
    let mut source_set_hasher = blake3::Hasher::new();
    for unit in &source_units {
        update_source_set_hasher(&mut source_set_hasher, unit);
    }
    metadata.source_hash_blake3 = Some(hex_encode(source_set_hasher.finalize().as_bytes()));
    metadata.source_content_hash_blake3 = Some(compute_source_content_hash(&source_units));
    metadata.source_units = source_units;
}

fn update_source_set_hasher(hasher: &mut blake3::Hasher, unit: &SourceUnitMetadata) {
    hasher.update(unit.role.as_bytes());
    hasher.update(b"\0");
    hasher.update(unit.path.as_bytes());
    hasher.update(b"\0");
    hasher.update(unit.hash_blake3.as_bytes());
    hasher.update(b"\0");
    hasher.update(&unit.size_bytes.to_le_bytes());
    hasher.update(b"\0");
}

fn compute_source_content_hash(source_units: &[SourceUnitMetadata]) -> String {
    let mut stable_units = source_units.iter().collect::<Vec<_>>();
    stable_units.sort_by(|left, right| {
        left.role.cmp(&right.role).then(left.hash_blake3.cmp(&right.hash_blake3)).then(left.size_bytes.cmp(&right.size_bytes))
    });
    let mut hasher = blake3::Hasher::new();
    for unit in stable_units {
        hasher.update(unit.role.as_bytes());
        hasher.update(b"\0");
        hasher.update(unit.hash_blake3.as_bytes());
        hasher.update(b"\0");
        hasher.update(&unit.size_bytes.to_le_bytes());
        hasher.update(b"\0");
    }
    hex_encode(hasher.finalize().as_bytes())
}

fn validate_source_metadata(metadata: &CompileMetadata) -> Result<()> {
    if metadata.source_units.is_empty() {
        if metadata.source_hash_blake3.is_some() {
            return Err(CompileError::without_span("metadata source_hash_blake3 is present but source_units is empty"));
        }
        if metadata.source_content_hash_blake3.is_some() {
            return Err(CompileError::without_span("metadata source_content_hash_blake3 is present but source_units is empty"));
        }
        return Ok(());
    }

    let mut source_set_hasher = blake3::Hasher::new();
    for unit in &metadata.source_units {
        if unit.path.is_empty() {
            return Err(CompileError::without_span("metadata source_units contains an empty path"));
        }
        if unit.role.is_empty() {
            return Err(CompileError::without_span(format!("metadata source unit '{}' has an empty role", unit.path)));
        }
        if !is_canonical_blake3_hex(&unit.hash_blake3) {
            return Err(CompileError::without_span(format!(
                "metadata source unit '{}' has invalid hash_blake3 '{}'; expected 64 lowercase hex characters",
                unit.path, unit.hash_blake3
            )));
        }
        update_source_set_hasher(&mut source_set_hasher, unit);
    }

    let computed_hash = hex_encode(source_set_hasher.finalize().as_bytes());
    match &metadata.source_hash_blake3 {
        Some(hash) if hash == &computed_hash => {}
        Some(hash) => Err(CompileError::without_span(format!(
            "metadata source_hash_blake3 '{}' does not match source_units '{}'",
            hash, computed_hash
        )))?,
        None => return Err(CompileError::without_span("metadata is missing source_hash_blake3 for non-empty source_units")),
    };

    let computed_content_hash = compute_source_content_hash(&metadata.source_units);
    match &metadata.source_content_hash_blake3 {
        Some(hash) if hash == &computed_content_hash => Ok(()),
        Some(hash) => Err(CompileError::without_span(format!(
            "metadata source_content_hash_blake3 '{}' does not match source_units '{}'",
            hash, computed_content_hash
        ))),
        None => Err(CompileError::without_span("metadata is missing source_content_hash_blake3 for non-empty source_units")),
    }
}

fn validate_type_identity_metadata(metadata: &CompileMetadata) -> Result<()> {
    let mut seen_type_ids = HashMap::new();
    for ty in &metadata.types {
        match (&ty.type_id, &ty.type_id_hash_blake3) {
            (None, None) => {}
            (Some(type_id), Some(hash)) => {
                if type_id.is_empty() {
                    return Err(CompileError::without_span(format!("metadata type '{}' has an empty type_id", ty.name)));
                }
                if type_id.chars().any(char::is_control) {
                    return Err(CompileError::without_span(format!(
                        "metadata type '{}' has invalid control characters in type_id",
                        ty.name
                    )));
                }
                if !is_canonical_blake3_hex(hash) {
                    return Err(CompileError::without_span(format!(
                        "metadata type '{}' has invalid type_id_hash_blake3 '{}'; expected 64 lowercase hex characters",
                        ty.name, hash
                    )));
                }
                let expected = hex_encode(blake3::hash(type_id.as_bytes()).as_bytes());
                if hash != &expected {
                    return Err(CompileError::without_span(format!(
                        "metadata type '{}' type_id_hash_blake3 '{}' does not match type_id '{}'",
                        ty.name, hash, expected
                    )));
                }
                if let Some(previous) = seen_type_ids.insert(type_id.clone(), ty.name.clone()) {
                    return Err(CompileError::without_span(format!(
                        "metadata type_id '{}' is declared by both '{}' and '{}'",
                        type_id, previous, ty.name
                    )));
                }
            }
            (Some(_), None) => {
                return Err(CompileError::without_span(format!(
                    "metadata type '{}' has type_id but is missing type_id_hash_blake3",
                    ty.name
                )));
            }
            (None, Some(_)) => {
                return Err(CompileError::without_span(format!(
                    "metadata type '{}' has type_id_hash_blake3 but is missing type_id",
                    ty.name
                )));
            }
        }

        if let Some(ckb_type_id) = &ty.ckb_type_id {
            validate_ckb_type_id_metadata(metadata, ty, ckb_type_id)?;
        }
    }
    Ok(())
}

fn validate_ckb_type_id_metadata(metadata: &CompileMetadata, ty: &TypeMetadata, ckb_type_id: &CkbTypeIdMetadata) -> Result<()> {
    if metadata.target_profile.name != TargetProfile::Ckb.name() {
        return Err(CompileError::without_span(format!("metadata type '{}' has ckb_type_id outside the ckb target profile", ty.name)));
    }
    if ty.type_id.is_none() {
        return Err(CompileError::without_span(format!("metadata type '{}' has ckb_type_id but is missing source type_id", ty.name)));
    }
    let expected_code_hash = hex_encode(&CKB_TYPE_ID_CODE_HASH);
    let mismatches = [
        ("abi", ckb_type_id.abi.as_str(), CKB_TYPE_ID_ABI),
        ("script_code_hash", ckb_type_id.script_code_hash.as_str(), expected_code_hash.as_str()),
        ("hash_type", ckb_type_id.hash_type.as_str(), CKB_TYPE_ID_HASH_TYPE),
        ("args_source", ckb_type_id.args_source.as_str(), CKB_TYPE_ID_ARGS_SOURCE),
        ("group_rule", ckb_type_id.group_rule.as_str(), CKB_TYPE_ID_GROUP_RULE),
        ("builder", ckb_type_id.builder.as_str(), CKB_TYPE_ID_BUILDER),
        ("verifier", ckb_type_id.verifier.as_str(), CKB_TYPE_ID_VERIFIER),
    ];
    for (field, actual, expected) in mismatches {
        if actual != expected {
            return Err(CompileError::without_span(format!(
                "metadata type '{}' ckb_type_id.{} '{}' does not match expected '{}'",
                ty.name, field, actual, expected
            )));
        }
    }
    Ok(())
}

fn validate_ckb_type_id_output_metadata(metadata: &CompileMetadata) -> Result<()> {
    let types_by_name = metadata.types.iter().map(|ty| (ty.name.as_str(), ty)).collect::<HashMap<_, _>>();
    let profile_is_ckb = metadata.target_profile.name == TargetProfile::Ckb.name();

    for action in &metadata.actions {
        validate_ckb_type_id_create_set_metadata("action", &action.name, &action.create_set, &types_by_name, profile_is_ckb)?;
    }
    for lock in &metadata.locks {
        validate_ckb_type_id_create_set_metadata("lock", &lock.name, &lock.create_set, &types_by_name, profile_is_ckb)?;
    }

    Ok(())
}

fn validate_ckb_type_id_create_set_metadata(
    scope: &str,
    name: &str,
    create_set: &[CreatePatternMetadata],
    types_by_name: &HashMap<&str, &TypeMetadata>,
    profile_is_ckb: bool,
) -> Result<()> {
    let expected_code_hash = hex_encode(&CKB_TYPE_ID_CODE_HASH);
    for (index, pattern) in create_set.iter().enumerate() {
        let ty = types_by_name.get(pattern.ty.as_str()).copied().ok_or_else(|| {
            CompileError::without_span(format!(
                "metadata {} '{}' create_set[{}] references unknown type '{}'",
                scope, name, index, pattern.ty
            ))
        })?;

        if let Some(plan) = &pattern.ckb_type_id {
            if !profile_is_ckb {
                return Err(CompileError::without_span(format!(
                    "metadata {} '{}' create_set[{}] has ckb_type_id outside the ckb target profile",
                    scope, name, index
                )));
            }
            if pattern.operation != "create" {
                return Err(CompileError::without_span(format!(
                    "metadata {} '{}' create_set[{}] has ckb_type_id for non-create operation '{}'",
                    scope, name, index, pattern.operation
                )));
            }
            if ty.ckb_type_id.is_none() {
                return Err(CompileError::without_span(format!(
                    "metadata {} '{}' create_set[{}] has ckb_type_id but type '{}' has no ckb_type_id contract",
                    scope, name, index, pattern.ty
                )));
            }
            let Some(source_type_id) = ty.type_id.as_deref() else {
                return Err(CompileError::without_span(format!(
                    "metadata {} '{}' create_set[{}] has ckb_type_id but type '{}' has no source type_id",
                    scope, name, index, pattern.ty
                )));
            };
            let mismatches = [
                ("abi", plan.abi.as_str(), CKB_TYPE_ID_ABI),
                ("type_id", plan.type_id.as_str(), source_type_id),
                ("output_source", plan.output_source.as_str(), CKB_TYPE_ID_OUTPUT_SOURCE),
                ("script_code_hash", plan.script_code_hash.as_str(), expected_code_hash.as_str()),
                ("hash_type", plan.hash_type.as_str(), CKB_TYPE_ID_HASH_TYPE),
                ("args_source", plan.args_source.as_str(), CKB_TYPE_ID_ARGS_SOURCE),
                ("builder", plan.builder.as_str(), CKB_TYPE_ID_BUILDER),
                ("generator_setting", plan.generator_setting.as_str(), CKB_TYPE_ID_GENERATOR_SETTING),
                ("wasm_setting", plan.wasm_setting.as_str(), CKB_TYPE_ID_WASM_SETTING),
            ];
            for (field, actual, expected) in mismatches {
                if actual != expected {
                    return Err(CompileError::without_span(format!(
                        "metadata {} '{}' create_set[{}].ckb_type_id.{} '{}' does not match expected '{}'",
                        scope, name, index, field, actual, expected
                    )));
                }
            }
            if plan.output_index != index {
                return Err(CompileError::without_span(format!(
                    "metadata {} '{}' create_set[{}].ckb_type_id.output_index {} does not match create_set index",
                    scope, name, index, plan.output_index
                )));
            }
        } else if profile_is_ckb && pattern.operation == "create" && ty.ckb_type_id.is_some() {
            return Err(CompileError::without_span(format!(
                "metadata {} '{}' create_set[{}] creates CKB TYPE_ID type '{}' but is missing ckb_type_id output plan",
                scope, name, index, pattern.ty
            )));
        }
    }

    Ok(())
}

fn validate_molecule_schema_metadata(metadata: &CompileMetadata) -> Result<()> {
    for ty in &metadata.types {
        let Some(schema) = &ty.molecule_schema else {
            continue;
        };
        if schema.abi != "molecule" {
            return Err(CompileError::without_span(format!(
                "metadata type '{}' has unsupported molecule_schema.abi '{}'",
                ty.name, schema.abi
            )));
        }
        if !matches!(schema.layout.as_str(), "fixed-struct-v1" | "molecule-table-v1") {
            return Err(CompileError::without_span(format!(
                "metadata type '{}' has unsupported molecule_schema.layout '{}'",
                ty.name, schema.layout
            )));
        }
        if schema.name != ty.name {
            return Err(CompileError::without_span(format!(
                "metadata type '{}' molecule_schema.name '{}' does not match type name",
                ty.name, schema.name
            )));
        }
        match schema.layout.as_str() {
            "fixed-struct-v1" => {
                if ty.encoded_size != Some(schema.fixed_size) {
                    return Err(CompileError::without_span(format!(
                        "metadata type '{}' molecule_schema.fixed_size {} does not match encoded_size {:?}",
                        ty.name, schema.fixed_size, ty.encoded_size
                    )));
                }
            }
            "molecule-table-v1" => {
                if schema.fixed_size != 0 {
                    return Err(CompileError::without_span(format!(
                        "metadata type '{}' molecule_schema.fixed_size {} must be 0 for molecule-table-v1",
                        ty.name, schema.fixed_size
                    )));
                }
                if ty.encoded_size.is_some() {
                    return Err(CompileError::without_span(format!(
                        "metadata type '{}' uses molecule-table-v1 but encoded_size is {:?}",
                        ty.name, ty.encoded_size
                    )));
                }
            }
            _ => unreachable!("layout match guarded above"),
        }
        if schema.schema.is_empty() {
            return Err(CompileError::without_span(format!("metadata type '{}' has empty molecule_schema.schema", ty.name)));
        }
        if !is_canonical_blake3_hex(&schema.schema_hash_blake3) {
            return Err(CompileError::without_span(format!(
                "metadata type '{}' has invalid molecule_schema.schema_hash_blake3 '{}'; expected 64 lowercase hex characters",
                ty.name, schema.schema_hash_blake3
            )));
        }
        let expected = hex_encode(blake3::hash(schema.schema.as_bytes()).as_bytes());
        if schema.schema_hash_blake3 != expected {
            return Err(CompileError::without_span(format!(
                "metadata type '{}' molecule_schema.schema_hash_blake3 '{}' does not match schema bytes",
                ty.name, schema.schema_hash_blake3
            )));
        }
    }

    Ok(())
}

fn validate_molecule_schema_manifest_metadata(metadata: &CompileMetadata) -> Result<()> {
    let manifest = &metadata.molecule_schema_manifest;
    if manifest.schema != "cellscript-molecule-schema-manifest-v1" {
        return Err(CompileError::without_span(format!(
            "metadata molecule_schema_manifest.schema '{}' is unsupported",
            manifest.schema
        )));
    }
    if manifest.version != 1 {
        return Err(CompileError::without_span(format!(
            "metadata molecule_schema_manifest.version {} is unsupported",
            manifest.version
        )));
    }
    if manifest.abi != "molecule" {
        return Err(CompileError::without_span(format!("metadata molecule_schema_manifest.abi '{}' is unsupported", manifest.abi)));
    }
    if manifest.target_profile != metadata.target_profile.name {
        return Err(CompileError::without_span(format!(
            "metadata molecule_schema_manifest.target_profile '{}' does not match target profile '{}'",
            manifest.target_profile, metadata.target_profile.name
        )));
    }

    let schema_types = metadata.types.iter().filter(|ty| ty.molecule_schema.is_some()).collect::<Vec<_>>();
    if manifest.type_count != schema_types.len() || manifest.entries.len() != schema_types.len() {
        return Err(CompileError::without_span(format!(
            "metadata molecule_schema_manifest.type_count {} does not match schema type count {}",
            manifest.type_count,
            schema_types.len()
        )));
    }
    if manifest.fixed_type_count + manifest.dynamic_type_count != manifest.type_count {
        return Err(CompileError::without_span("metadata molecule_schema_manifest fixed/dynamic counts do not sum to type_count"));
    }
    if !is_canonical_blake3_hex(&manifest.manifest_hash_blake3) {
        return Err(CompileError::without_span(format!(
            "metadata molecule_schema_manifest.manifest_hash_blake3 '{}' is invalid",
            manifest.manifest_hash_blake3
        )));
    }

    let mut entries = manifest.entries.clone();
    entries.sort_by(|left, right| left.type_name.cmp(&right.type_name));
    if entries.iter().map(|entry| entry.type_name.as_str()).collect::<Vec<_>>()
        != manifest.entries.iter().map(|entry| entry.type_name.as_str()).collect::<Vec<_>>()
    {
        return Err(CompileError::without_span("metadata molecule_schema_manifest.entries must be sorted by type_name"));
    }

    for entry in &manifest.entries {
        let Some(ty) = metadata.types.iter().find(|ty| ty.name == entry.type_name) else {
            return Err(CompileError::without_span(format!(
                "metadata molecule_schema_manifest entry '{}' does not match a metadata type",
                entry.type_name
            )));
        };
        let Some(schema) = &ty.molecule_schema else {
            return Err(CompileError::without_span(format!(
                "metadata molecule_schema_manifest entry '{}' points at a type without molecule_schema",
                entry.type_name
            )));
        };
        if entry.kind != ty.kind
            || entry.layout != schema.layout
            || entry.fixed_size != schema.fixed_size
            || entry.encoded_size != ty.encoded_size
            || entry.dynamic_fields != schema.dynamic_fields
            || entry.schema_hash_blake3 != schema.schema_hash_blake3
        {
            return Err(CompileError::without_span(format!(
                "metadata molecule_schema_manifest entry '{}' does not match type molecule_schema metadata",
                entry.type_name
            )));
        }
        if entry.field_offsets.len() != ty.fields.len() {
            return Err(CompileError::without_span(format!(
                "metadata molecule_schema_manifest entry '{}' field count does not match type metadata",
                entry.type_name
            )));
        }
        for (manifest_field, ty_field) in entry.field_offsets.iter().zip(&ty.fields) {
            if manifest_field.name != ty_field.name
                || manifest_field.ty != ty_field.ty
                || manifest_field.offset != ty_field.offset
                || manifest_field.encoded_size != ty_field.encoded_size
                || manifest_field.fixed_width != ty_field.fixed_width
            {
                return Err(CompileError::without_span(format!(
                    "metadata molecule_schema_manifest entry '{}.{}' does not match type field metadata",
                    entry.type_name, manifest_field.name
                )));
            }
        }
    }

    let expected = molecule_schema_manifest_metadata(&metadata.types, TargetProfile::from_name(&metadata.target_profile.name)?);
    if manifest.manifest_hash_blake3 != expected.manifest_hash_blake3 {
        return Err(CompileError::without_span(format!(
            "metadata molecule_schema_manifest.manifest_hash_blake3 '{}' does not match manifest entries",
            manifest.manifest_hash_blake3
        )));
    }

    Ok(())
}

pub fn validate_source_units_on_disk(metadata: &CompileMetadata) -> Result<()> {
    validate_source_metadata(metadata)?;
    if metadata.source_units.is_empty() {
        return Err(CompileError::without_span("metadata has no source_units to verify"));
    }

    for unit in &metadata.source_units {
        if unit.path.starts_with('<') && unit.path.ends_with('>') {
            return Err(CompileError::without_span(format!(
                "source unit '{}' is not backed by a disk file and cannot be verified",
                unit.path
            )));
        }

        let path = Utf8Path::new(&unit.path);
        let bytes = std::fs::read(path)
            .map_err(|error| CompileError::without_span(format!("failed to read source unit '{}': {}", unit.path, error)))?;
        if bytes.len() != unit.size_bytes {
            return Err(CompileError::without_span(format!(
                "source unit '{}' size {} does not match metadata size {}",
                unit.path,
                bytes.len(),
                unit.size_bytes
            )));
        }

        let hash = hex_encode(blake3::hash(&bytes).as_bytes());
        if hash != unit.hash_blake3 {
            return Err(CompileError::without_span(format!(
                "source unit '{}' hash '{}' does not match metadata hash '{}'",
                unit.path, hash, unit.hash_blake3
            )));
        }
    }

    Ok(())
}

pub fn validate_compile_result(result: &CompileResult) -> Result<()> {
    validate_compile_metadata(&result.metadata, result.artifact_format)?;

    if result.artifact_bytes.is_empty() {
        return Err(CompileError::without_span("compiler produced an empty artifact"));
    }

    let computed_hash = *blake3::hash(&result.artifact_bytes).as_bytes();
    if computed_hash != result.artifact_hash {
        return Err(CompileError::without_span("artifact_hash does not match artifact_bytes"));
    }
    let computed_hash_hex = hex_encode(&computed_hash);
    match &result.metadata.artifact_hash_blake3 {
        Some(metadata_hash) if metadata_hash == &computed_hash_hex => {}
        Some(metadata_hash) => {
            return Err(CompileError::without_span(format!(
                "metadata artifact_hash_blake3 '{}' does not match artifact bytes '{}'",
                metadata_hash, computed_hash_hex
            )));
        }
        None => return Err(CompileError::without_span("metadata is missing artifact_hash_blake3")),
    }
    match result.metadata.artifact_size_bytes {
        Some(size) if size == result.artifact_bytes.len() => {}
        Some(size) => {
            return Err(CompileError::without_span(format!(
                "metadata artifact_size_bytes {} does not match artifact size {}",
                size,
                result.artifact_bytes.len()
            )));
        }
        None => return Err(CompileError::without_span("metadata is missing artifact_size_bytes")),
    }

    match result.artifact_format {
        ArtifactFormat::RiscvAssembly => {
            if vm_abi_trailer_version(&result.artifact_bytes)?.is_some() {
                return Err(CompileError::without_span("RISC-V assembly artifacts must not embed a VM ABI trailer"));
            }
        }
        ArtifactFormat::RiscvElf => {
            if !result.artifact_bytes.starts_with(b"\x7fELF") {
                return Err(CompileError::without_span("RISC-V ELF artifact does not start with ELF magic"));
            }
            match vm_abi_trailer_version(&result.artifact_bytes)? {
                Some(trailer_version) if result.metadata.runtime.vm_abi.embedded_in_artifact => {
                    if trailer_version != result.metadata.runtime.vm_abi.version {
                        return Err(CompileError::without_span(format!(
                            "ELF VM ABI trailer version 0x{:04x} does not match metadata runtime.vm_abi.version 0x{:04x}",
                            trailer_version, result.metadata.runtime.vm_abi.version
                        )));
                    }
                    if !strip_vm_abi_trailer(&result.artifact_bytes).starts_with(b"\x7fELF") {
                        return Err(CompileError::without_span("stripped RISC-V ELF artifact does not start with ELF magic"));
                    }
                }
                Some(_) => {
                    return Err(CompileError::without_span(
                        "RISC-V ELF artifact embeds a Spora VM ABI trailer but metadata says this profile must not embed one",
                    ));
                }
                None if result.metadata.runtime.vm_abi.embedded_in_artifact => {
                    return Err(CompileError::without_span("RISC-V ELF artifact is missing its VM ABI trailer"));
                }
                None => {}
            }
        }
    }

    Ok(())
}

pub fn validate_artifact_metadata(artifact_bytes: Vec<u8>, metadata: CompileMetadata) -> Result<ValidatedArtifact> {
    let artifact_format = ArtifactFormat::from_display_name(&metadata.artifact_format)?;
    let artifact_hash = *blake3::hash(&artifact_bytes).as_bytes();
    let result = ValidatedArtifact { artifact_bytes, artifact_format, artifact_hash, metadata };
    result.validate()?;
    Ok(result)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CkbRuntimeAccessMetadata {
    pub operation: String,
    pub syscall: String,
    pub source: String,
    pub index: usize,
    pub binding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierObligationMetadata {
    pub scope: String,
    pub category: String,
    pub feature: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRuntimeInputRequirementMetadata {
    pub scope: String,
    pub feature: String,
    pub status: String,
    pub component: String,
    pub source: String,
    pub binding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub abi: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolInvariantMetadata {
    pub name: String,
    pub status: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRuntimeInputRequirementMetadata {
    pub component: String,
    pub source: String,
    pub index: usize,
    pub binding: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    pub abi: String,
    pub byte_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolPrimitiveMetadata {
    pub scope: String,
    pub operation: String,
    pub feature: String,
    pub ty: String,
    pub status: String,
    pub source: String,
    pub checked_components: Vec<String>,
    pub runtime_required_components: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_input_requirements: Vec<PoolRuntimeInputRequirementMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invariant_families: Vec<PoolInvariantMetadata>,
    pub source_invariant_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_index: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transition_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserved_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_id_hash_blake3: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ckb_type_id: Option<CkbTypeIdMetadata>,
    pub kind: String,
    pub capabilities: Vec<String>,
    pub claim_output: Option<String>,
    pub lifecycle_states: Vec<String>,
    pub lifecycle_transitions: Vec<LifecycleTransitionMetadata>,
    pub encoded_size: Option<usize>,
    pub fields: Vec<FieldMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub molecule_schema: Option<MoleculeSchemaMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CkbTypeIdMetadata {
    pub abi: String,
    pub script_code_hash: String,
    pub hash_type: String,
    pub args_source: String,
    pub group_rule: String,
    pub builder: String,
    pub verifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoleculeSchemaMetadata {
    pub abi: String,
    pub layout: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_fields: Vec<String>,
    pub fixed_size: usize,
    pub schema_hash_blake3: String,
    pub schema: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransitionMetadata {
    pub from: String,
    pub to: String,
    pub from_index: usize,
    pub to_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMetadata {
    pub name: String,
    pub ty: String,
    pub offset: usize,
    pub encoded_size: Option<usize>,
    pub fixed_width: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMetadata {
    pub name: String,
    pub params: Vec<ParamMetadata>,
    pub effect_class: String,
    pub parallelizable: bool,
    pub touches_shared: Vec<String>,
    pub estimated_cycles: u64,
    #[serde(default = "default_scheduler_witness_abi")]
    pub scheduler_witness_abi: String,
    // scheduler_witness_borsh_hex is not public scheduler witness metadata.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scheduler_witness_hex: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    scheduler_witness_molecule_hex: String,
    pub consume_set: Vec<CellPatternMetadata>,
    pub read_refs: Vec<CellPatternMetadata>,
    pub create_set: Vec<CreatePatternMetadata>,
    pub mutate_set: Vec<MutatePatternMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool_primitives: Vec<PoolPrimitiveMetadata>,
    pub ckb_runtime_accesses: Vec<CkbRuntimeAccessMetadata>,
    pub ckb_runtime_features: Vec<String>,
    pub symbolic_runtime_features: Vec<String>,
    pub fail_closed_runtime_features: Vec<String>,
    pub verifier_obligations: Vec<VerifierObligationMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_runtime_input_requirements: Vec<TransactionRuntimeInputRequirementMetadata>,
    pub elf_compatible: bool,
    pub standalone_runner_compatible: bool,
    pub block_count: usize,
}

impl ActionMetadata {
    /// Output indexes where a CKB builder should install the built-in TYPE_ID
    /// script for newly-created cells.
    pub fn ckb_type_id_output_indexes(&self) -> Vec<usize> {
        ckb_type_id_output_indexes_from_create_set(&self.create_set)
    }

    /// Decode the public compiled CellScript scheduler witness bytes for this action.
    ///
    /// Transaction builders can pass the returned bytes to
    /// `CellTx::push_cellscript_compiled_scheduler_witness` and use the returned
    /// access summary as the trusted scheduler policy input. Public scheduler
    /// witness bytes are Molecule-only.
    pub fn scheduler_witness_bytes(&self) -> Result<Vec<u8>> {
        let scheduler_witness_hex = non_empty_metadata_field(&self.scheduler_witness_hex);
        let scheduler_witness_molecule_hex = non_empty_metadata_field(&self.scheduler_witness_molecule_hex);
        if let (Some(primary), Some(alias)) = (scheduler_witness_hex, scheduler_witness_molecule_hex) {
            if primary != alias {
                return Err(CompileError::without_span(
                    "conflicting scheduler_witness_hex and scheduler_witness_molecule_hex metadata",
                ));
            }
        }
        if let Some(scheduler_witness_hex) = scheduler_witness_hex {
            if self.scheduler_witness_abi != SCHEDULER_WITNESS_ABI_MOLECULE {
                return Err(CompileError::without_span(format!(
                    "unsupported public scheduler_witness_abi '{}'; supported value: molecule",
                    self.scheduler_witness_abi
                )));
            }
            return decode_scheduler_witness_hex(scheduler_witness_hex);
        }
        if let Some(scheduler_witness_molecule_hex) = scheduler_witness_molecule_hex {
            return decode_scheduler_witness_hex(scheduler_witness_molecule_hex);
        }
        Err(CompileError::without_span("scheduler witness metadata is missing"))
    }

    /// Encode positional entry witness bytes for the generated `_cellscript_entry` wrapper.
    ///
    /// Cell-bound parameters are loaded from transaction cells by the wrapper and
    /// are intentionally omitted from `args`; remaining scalar, fixed-byte, and
    /// dynamic schema parameters are encoded in source order after the `CSARGv1\0` header.
    pub fn entry_witness_args(&self, args: &[EntryWitnessArg]) -> Result<Vec<u8>> {
        encode_entry_witness_args_for_params_with_runtime_bound(
            &self.params,
            args,
            &runtime_bound_param_names(&self.consume_set, &self.read_refs, &self.mutate_set),
        )
    }
}

const SCHEDULER_WITNESS_ABI_MOLECULE: &str = "molecule";

fn non_empty_metadata_field(field: &str) -> Option<&str> {
    (!field.is_empty()).then_some(field)
}

impl LockMetadata {
    /// Output indexes where a CKB builder should install the built-in TYPE_ID
    /// script for newly-created cells.
    pub fn ckb_type_id_output_indexes(&self) -> Vec<usize> {
        ckb_type_id_output_indexes_from_create_set(&self.create_set)
    }

    /// Encode positional entry witness bytes for the generated `_cellscript_entry` wrapper.
    pub fn entry_witness_args(&self, args: &[EntryWitnessArg]) -> Result<Vec<u8>> {
        encode_entry_witness_args_for_params_with_runtime_bound(
            &self.params,
            args,
            &runtime_bound_param_names(&self.consume_set, &self.read_refs, &self.mutate_set),
        )
    }
}

fn ckb_type_id_output_indexes_from_create_set(create_set: &[CreatePatternMetadata]) -> Vec<usize> {
    create_set.iter().filter_map(|pattern| pattern.ckb_type_id.as_ref().map(|plan| plan.output_index)).collect()
}

fn default_scheduler_witness_abi() -> String {
    SCHEDULER_WITNESS_ABI_MOLECULE.to_string()
}

/// Decode a hex-encoded scheduler witness from compile metadata.
pub fn decode_scheduler_witness_hex(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(CompileError::without_span("scheduler witness hex string must contain full bytes"));
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for index in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[index..index + 2], 16)
            .map_err(|error| CompileError::without_span(format!("invalid scheduler witness hex byte at offset {index}: {error}")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryWitnessArg {
    Unit,
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    Address([u8; 32]),
    Hash([u8; 32]),
    Bytes(Vec<u8>),
}

/// Encode positional witness bytes for CellScript's generated entry wrapper.
///
/// The result is suitable for transaction witnesses consumed by `_cellscript_entry`.
/// It mirrors the codegen wrapper ABI: named schema parameters are encoded as
/// `<u32:len><bytes>`, fixed-byte parameters are appended verbatim, and scalar
/// parameters are little-endian encoded.
pub fn encode_entry_witness_args_for_params(params: &[ParamMetadata], args: &[EntryWitnessArg]) -> Result<Vec<u8>> {
    encode_entry_witness_args_for_params_with_runtime_bound(params, args, &BTreeSet::new())
}

pub fn encode_entry_witness_args_for_params_with_runtime_bound(
    params: &[ParamMetadata],
    args: &[EntryWitnessArg],
    runtime_bound_param_names: &BTreeSet<String>,
) -> Result<Vec<u8>> {
    let payload_len = entry_witness_metadata_payload_len_with_runtime_bound(params, runtime_bound_param_names)?;
    let mut witness = Vec::with_capacity(ENTRY_WITNESS_ABI_MAGIC.len() + payload_len);
    witness.extend_from_slice(ENTRY_WITNESS_ABI_MAGIC);

    let mut arg_index = 0usize;
    for param in params {
        if !param_consumes_entry_witness_payload(param, runtime_bound_param_names) {
            continue;
        }

        if param.schema_pointer_abi || param.schema_length_abi {
            let arg = args.get(arg_index).ok_or_else(|| entry_witness_missing_arg_error(param, arg_index))?;
            entry_witness_append_schema_arg(&mut witness, param, arg)?;
            arg_index += 1;
            continue;
        }

        if let Some(width) = param.fixed_byte_len {
            let arg = args.get(arg_index).ok_or_else(|| entry_witness_missing_arg_error(param, arg_index))?;
            witness.extend_from_slice(&entry_witness_fixed_arg_bytes(param, arg, width)?);
            arg_index += 1;
            continue;
        }

        let Some(width) = entry_witness_scalar_param_width(&param.ty) else {
            return Err(CompileError::without_span(format!(
                "entry witness parameter '{}' has unsupported type '{}'",
                param.name, param.ty
            )));
        };
        if width == 0 {
            if matches!(args.get(arg_index), Some(EntryWitnessArg::Unit)) {
                arg_index += 1;
            }
            continue;
        }
        let arg = args.get(arg_index).ok_or_else(|| entry_witness_missing_arg_error(param, arg_index))?;
        entry_witness_append_scalar_arg(&mut witness, param, arg, width)?;
        arg_index += 1;
    }

    if arg_index != args.len() {
        return Err(CompileError::without_span(format!(
            "entry witness received {} payload args but consumed {} for {}",
            args.len(),
            arg_index,
            ENTRY_WITNESS_ABI
        )));
    }

    Ok(witness)
}

fn entry_witness_metadata_payload_len_with_runtime_bound(
    params: &[ParamMetadata],
    runtime_bound_param_names: &BTreeSet<String>,
) -> Result<usize> {
    params.iter().try_fold(0usize, |acc, param| {
        if !param_consumes_entry_witness_payload(param, runtime_bound_param_names) {
            Ok(acc)
        } else if param.schema_pointer_abi || param.schema_length_abi {
            Ok(acc + 4)
        } else if let Some(width) = param.fixed_byte_len {
            Ok(acc + width)
        } else if let Some(width) = entry_witness_scalar_param_width(&param.ty) {
            Ok(acc + width)
        } else {
            Err(CompileError::without_span(format!("entry witness parameter '{}' has unsupported type '{}'", param.name, param.ty)))
        }
    })
}

fn entry_witness_append_schema_arg(witness: &mut Vec<u8>, param: &ParamMetadata, arg: &EntryWitnessArg) -> Result<()> {
    let bytes = match arg {
        EntryWitnessArg::Bytes(bytes) => bytes,
        _ => {
            return Err(CompileError::without_span(format!(
                "entry witness parameter '{}' expects schema bytes for type '{}'",
                param.name, param.ty
            )));
        }
    };
    let len = u32::try_from(bytes.len()).map_err(|_| {
        CompileError::without_span(format!(
            "entry witness parameter '{}' exceeds the 4-byte schema payload limit for {}",
            param.name, ENTRY_WITNESS_ABI
        ))
    })?;
    witness.extend_from_slice(&len.to_le_bytes());
    witness.extend_from_slice(bytes);
    Ok(())
}

fn entry_witness_fixed_arg_bytes(param: &ParamMetadata, arg: &EntryWitnessArg, width: usize) -> Result<Vec<u8>> {
    let bytes = match (param.ty.as_str(), arg) {
        ("u128", EntryWitnessArg::U128(value)) if width == 16 => value.to_le_bytes().to_vec(),
        ("Address", EntryWitnessArg::Address(bytes)) if width == 32 => bytes.to_vec(),
        ("Hash", EntryWitnessArg::Hash(bytes)) if width == 32 => bytes.to_vec(),
        (_, EntryWitnessArg::Bytes(bytes)) if bytes.len() == width => bytes.clone(),
        _ => {
            return Err(CompileError::without_span(format!(
                "entry witness parameter '{}' expects {} fixed bytes for type '{}'",
                param.name, width, param.ty
            )));
        }
    };
    Ok(bytes)
}

fn entry_witness_append_scalar_arg(witness: &mut Vec<u8>, param: &ParamMetadata, arg: &EntryWitnessArg, width: usize) -> Result<()> {
    match (param.ty.as_str(), arg) {
        ("bool", EntryWitnessArg::Bool(value)) if width == 1 => witness.push(u8::from(*value)),
        ("u8", EntryWitnessArg::U8(value)) if width == 1 => witness.push(*value),
        ("u16", EntryWitnessArg::U16(value)) if width == 2 => witness.extend_from_slice(&value.to_le_bytes()),
        ("u32", EntryWitnessArg::U32(value)) if width == 4 => witness.extend_from_slice(&value.to_le_bytes()),
        ("u64", EntryWitnessArg::U64(value)) if width == 8 => witness.extend_from_slice(&value.to_le_bytes()),
        (_, EntryWitnessArg::Bytes(bytes)) if bytes.len() == width && entry_witness_type_is_small_aggregate(&param.ty) => {
            witness.extend_from_slice(bytes);
        }
        _ => {
            return Err(CompileError::without_span(format!(
                "entry witness parameter '{}' expects scalar payload for type '{}'",
                param.name, param.ty
            )));
        }
    }
    Ok(())
}

fn entry_witness_missing_arg_error(param: &ParamMetadata, index: usize) -> CompileError {
    CompileError::without_span(format!(
        "entry witness missing payload arg {} for parameter '{}' of type '{}'",
        index, param.name, param.ty
    ))
}

fn runtime_bound_param_names(
    consume_set: &[CellPatternMetadata],
    read_refs: &[CellPatternMetadata],
    mutate_set: &[MutatePatternMetadata],
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for pattern in consume_set {
        names.insert(pattern.binding.clone());
    }
    for pattern in read_refs {
        names.insert(pattern.binding.clone());
    }
    for pattern in mutate_set {
        names.insert(pattern.binding.clone());
    }
    names
}

fn param_consumes_entry_witness_payload(param: &ParamMetadata, runtime_bound_param_names: &BTreeSet<String>) -> bool {
    !param.cell_bound_abi && !param.ty.starts_with('&') && !runtime_bound_param_names.contains(&param.name)
}

fn entry_witness_scalar_param_width(ty: &str) -> Option<usize> {
    match ty.trim() {
        "()" => Some(0),
        "bool" | "u8" => Some(1),
        "u16" => Some(2),
        "u32" => Some(4),
        "u64" => Some(8),
        other => entry_witness_static_type_len(other).filter(|width| (1..=8).contains(width)),
    }
}

fn entry_witness_type_is_small_aggregate(ty: &str) -> bool {
    let ty = ty.trim();
    (ty.starts_with('[') || ty.starts_with('(')) && entry_witness_static_type_len(ty).is_some_and(|width| width <= 8)
}

pub(crate) fn entry_witness_static_type_len(ty: &str) -> Option<usize> {
    let ty = ty.trim();
    match ty {
        "()" => return Some(0),
        "bool" | "u8" => return Some(1),
        "u16" => return Some(2),
        "u32" => return Some(4),
        "u64" => return Some(8),
        "u128" => return Some(16),
        "Address" | "Hash" => return Some(32),
        _ => {}
    }

    if let Some(inner) = ty.strip_prefix('&') {
        return entry_witness_static_type_len(inner.trim_start_matches("mut ").trim());
    }

    if let Some(body) = ty.strip_prefix('[').and_then(|value| value.strip_suffix(']')) {
        let (inner, len) = split_top_level_once(body, ';')?;
        let len = len.trim().parse::<usize>().ok()?;
        return entry_witness_static_type_len(inner).map(|inner_len| inner_len * len);
    }

    if let Some(body) = ty.strip_prefix('(').and_then(|value| value.strip_suffix(')')) {
        if body.trim().is_empty() {
            return Some(0);
        }
        return split_top_level_commas(body)
            .iter()
            .try_fold(0usize, |acc, item| entry_witness_static_type_len(item).map(|len| acc + len));
    }

    None
}

fn split_top_level_once(input: &str, separator: char) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    for (index, ch) in input.char_indices() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ if ch == separator && depth == 0 => return Some((&input[..index], &input[index + ch.len_utf8()..])),
            _ => {}
        }
    }
    None
}

fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut items = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (index, ch) in input.char_indices() {
        match ch {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                items.push(input[start..index].trim());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    items.push(input[start..].trim());
    items
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionMetadata {
    pub name: String,
    pub params: Vec<ParamMetadata>,
    pub return_type: Option<String>,
    pub mutate_set: Vec<MutatePatternMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool_primitives: Vec<PoolPrimitiveMetadata>,
    pub ckb_runtime_accesses: Vec<CkbRuntimeAccessMetadata>,
    pub ckb_runtime_features: Vec<String>,
    pub symbolic_runtime_features: Vec<String>,
    pub fail_closed_runtime_features: Vec<String>,
    pub verifier_obligations: Vec<VerifierObligationMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_runtime_input_requirements: Vec<TransactionRuntimeInputRequirementMetadata>,
    pub elf_compatible: bool,
    pub block_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockMetadata {
    pub name: String,
    pub params: Vec<ParamMetadata>,
    pub consume_set: Vec<CellPatternMetadata>,
    pub read_refs: Vec<CellPatternMetadata>,
    pub create_set: Vec<CreatePatternMetadata>,
    pub mutate_set: Vec<MutatePatternMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pool_primitives: Vec<PoolPrimitiveMetadata>,
    pub ckb_runtime_accesses: Vec<CkbRuntimeAccessMetadata>,
    pub ckb_runtime_features: Vec<String>,
    pub symbolic_runtime_features: Vec<String>,
    pub fail_closed_runtime_features: Vec<String>,
    pub verifier_obligations: Vec<VerifierObligationMetadata>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transaction_runtime_input_requirements: Vec<TransactionRuntimeInputRequirementMetadata>,
    pub elf_compatible: bool,
    pub standalone_runner_compatible: bool,
    pub block_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamMetadata {
    pub name: String,
    pub ty: String,
    pub is_mut: bool,
    pub is_ref: bool,
    #[serde(default)]
    pub cell_bound_abi: bool,
    pub schema_pointer_abi: bool,
    pub schema_length_abi: bool,
    pub fixed_byte_pointer_abi: bool,
    pub fixed_byte_length_abi: bool,
    pub fixed_byte_len: Option<usize>,
    pub type_hash_pointer_abi: bool,
    pub type_hash_length_abi: bool,
    pub type_hash_len: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellPatternMetadata {
    pub operation: String,
    pub type_hash: Option<String>,
    pub binding: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePatternMetadata {
    pub operation: String,
    pub ty: String,
    pub binding: String,
    pub fields: Vec<String>,
    pub has_lock: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ckb_type_id: Option<CkbTypeIdOutputMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CkbTypeIdOutputMetadata {
    pub abi: String,
    pub type_id: String,
    pub output_source: String,
    pub output_index: usize,
    pub script_code_hash: String,
    pub hash_type: String,
    pub args_source: String,
    pub builder: String,
    pub generator_setting: String,
    pub wasm_setting: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutatePatternMetadata {
    pub operation: String,
    pub ty: String,
    pub binding: String,
    pub fields: Vec<String>,
    pub preserved_fields: Vec<String>,
    pub input_source: String,
    pub input_index: usize,
    pub output_source: String,
    pub output_index: usize,
    pub preserve_type_hash: bool,
    pub preserve_lock_hash: bool,
    pub type_hash_preservation_status: String,
    pub lock_hash_preservation_status: String,
    pub field_equality_status: String,
    pub field_transition_status: String,
}

#[derive(Debug, Clone)]
struct MetadataFieldLayout {
    ty: ir::IrType,
    offset: usize,
    fixed_size: Option<usize>,
    fixed_enum_size: Option<usize>,
}

type MetadataTypeLayouts = HashMap<String, HashMap<String, MetadataFieldLayout>>;

#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub path: Utf8PathBuf,
    pub source: String,
    pub ast: ast::Module,
}

impl CompileResult {
    /// Validate that artifact bytes, hash, format, and metadata agree.
    pub fn validate(&self) -> Result<()> {
        validate_compile_result(self)
    }

    /// Default output path
    pub fn default_output_path(&self, input_path: &Utf8Path) -> Utf8PathBuf {
        input_path.with_extension(self.artifact_format.file_extension())
    }

    /// Write artifact to file
    pub fn write_to_path(&self, output_path: &Utf8Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CompileError::new(format!("failed to create output directory '{}': {}", parent, e), error::Span::default())
            })?;
        }

        std::fs::write(output_path, &self.artifact_bytes)
            .map_err(|e| CompileError::new(format!("failed to write output '{}': {}", output_path, e), error::Span::default()))
    }

    pub fn default_metadata_path(&self, artifact_path: &Utf8Path) -> Utf8PathBuf {
        metadata_output_path_from_artifact(artifact_path)
    }

    pub fn write_metadata_to_path(&self, output_path: &Utf8Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CompileError::new(format!("failed to create metadata directory '{}': {}", parent, e), error::Span::default())
            })?;
        }

        let json = serde_json::to_vec_pretty(&self.metadata)
            .map_err(|e| CompileError::new(format!("failed to serialize metadata: {}", e), error::Span::default()))?;
        std::fs::write(output_path, json)
            .map_err(|e| CompileError::new(format!("failed to write metadata '{}': {}", output_path, e), error::Span::default()))
    }
}

impl ValidatedArtifact {
    /// Validate that artifact bytes, hash, format, and metadata agree.
    pub fn validate(&self) -> Result<()> {
        validate_compile_metadata(&self.metadata, self.artifact_format)?;

        if self.artifact_bytes.is_empty() {
            return Err(CompileError::without_span("artifact bytes are empty"));
        }

        let computed_hash = *blake3::hash(&self.artifact_bytes).as_bytes();
        if computed_hash != self.artifact_hash {
            return Err(CompileError::without_span("artifact_hash does not match artifact_bytes"));
        }
        let computed_hash_hex = hex_encode(&computed_hash);
        match &self.metadata.artifact_hash_blake3 {
            Some(metadata_hash) if metadata_hash == &computed_hash_hex => {}
            Some(metadata_hash) => {
                return Err(CompileError::without_span(format!(
                    "metadata artifact_hash_blake3 '{}' does not match artifact bytes '{}'",
                    metadata_hash, computed_hash_hex
                )));
            }
            None => {
                return Err(CompileError::without_span("metadata is missing artifact_hash_blake3"));
            }
        }

        Ok(())
    }
}

/// Parse compile input to specific CellScript source files
pub fn resolve_input_path<P: AsRef<Utf8Path>>(input: P) -> Result<Utf8PathBuf> {
    resolve_input_file(input.as_ref())
}

/// Derive default output path from original input
pub fn default_output_path_for_input<P: AsRef<Utf8Path>>(
    input: P,
    resolved_input: &Utf8Path,
    artifact_format: ArtifactFormat,
) -> Result<Utf8PathBuf> {
    default_output_path_from_input(input.as_ref(), resolved_input, artifact_format)
}

pub fn default_metadata_path_for_artifact<P: AsRef<Utf8Path>>(artifact_path: P) -> Utf8PathBuf {
    metadata_output_path_from_artifact(artifact_path.as_ref())
}

pub fn load_modules_for_input<P: AsRef<Utf8Path>>(input: P) -> Result<Vec<LoadedModule>> {
    let resolved = resolve_input_path(input.as_ref())?;
    let mut files = if let Some(package_root) = find_package_root(&resolved)? {
        collect_package_cell_files(&package_root)?
    } else {
        vec![resolved.clone()]
    };

    if !files.contains(&resolved) {
        files.push(resolved);
        files.sort();
    }

    files
        .into_iter()
        .map(|path| {
            let source = std::fs::read_to_string(&path)
                .map_err(|e| CompileError::new(format!("failed to read module '{}': {}", path, e), error::Span::default()))?;
            let tokens = lexer::lex(&source).map_err(|e| e.with_file(path.clone()))?;
            let ast = parser::parse(&tokens).map_err(|e| e.with_file(path.clone()))?;
            Ok(LoadedModule { path, source, ast })
        })
        .collect()
}

/// Compile CellScript source code
pub fn compile(source: &str, options: CompileOptions) -> Result<CompileResult> {
    // 1. Lexical analysis
    let tokens = lexer::lex(source)?;

    // 2. Parse
    let ast = parser::parse(&tokens)?;

    let mut result = compile_ast(&ast, &options, None)?;
    bind_source_metadata(&mut result.metadata, vec![source_unit_from_bytes("<memory>", "memory", source.as_bytes())]);
    result.validate()?;
    Ok(result)
}

/// Only generate compile metadata, without asm/elf artifact.
pub fn compile_metadata(source: &str, target: Option<String>) -> Result<CompileMetadata> {
    let tokens = lexer::lex(source)?;
    let ast = parser::parse(&tokens)?;
    let artifact_format = ArtifactFormat::from_target(target.as_deref().unwrap_or(DEFAULT_TARGET))?;
    let target_profile = TargetProfile::Spora;
    types::check(&ast)?;
    lifecycle::check(&ast)?;
    let ir = ir::generate(&ast)?;
    let mut metadata = compile_metadata_from_ir(&ir, artifact_format, target_profile);
    bind_source_metadata(&mut metadata, vec![source_unit_from_bytes("<memory>", "memory", source.as_bytes())]);
    validate_compile_metadata(&metadata, artifact_format)?;
    Ok(metadata)
}

fn compile_ast(ast: &ast::Module, options: &CompileOptions, resolver: Option<(&ModuleResolver, &str)>) -> Result<CompileResult> {
    compile_ast_with_build(ast, options, resolver, None, None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileEntryScope {
    Action(String),
    Lock(String),
}

fn compile_ast_with_build(
    ast: &ast::Module,
    options: &CompileOptions,
    resolver: Option<(&ModuleResolver, &str)>,
    build: Option<&CellBuildConfig>,
    entry_scope: Option<&CompileEntryScope>,
) -> Result<CompileResult> {
    validate_compile_options(options)?;
    let target_profile = TargetProfile::from_options(options, build)?;
    target_profile.ensure_compile_supported()?;
    let artifact_format = ArtifactFormat::from_target(resolve_target(options, build))?;

    // 3. Type check
    if let Some((resolver, module_name)) = resolver {
        types::check_with_resolver(ast, resolver, module_name)?;
    } else {
        types::check(ast)?;
    }
    lifecycle::check(ast)?;

    let optimized_ast = if options.opt_level > 0 {
        let mut optimized = ast.clone();
        optimize::optimize_module(&mut optimized, options.opt_level)?;
        if let Some((resolver, module_name)) = resolver {
            types::check_with_resolver(&optimized, resolver, module_name)?;
        } else {
            types::check(&optimized)?;
        }
        lifecycle::check(&optimized)?;
        Some(optimized)
    } else {
        None
    };
    let lowering_ast = optimized_ast.as_ref().unwrap_or(ast);

    // 4. Generate IR
    let ir = if let Some((resolver, module_name)) = resolver {
        ir::generate_with_resolver(lowering_ast, resolver, module_name)?
    } else {
        ir::generate(lowering_ast)?
    };
    let scoped_ir = match entry_scope {
        Some(scope) => Some(scope_ir_to_entry(&ir, scope)?),
        None => None,
    };
    let ir = scoped_ir.as_ref().unwrap_or(&ir);

    let mut metadata = compile_metadata_from_ir(ir, artifact_format, target_profile);
    let target_policy_violations = target_profile_artifact_policy_violations(&metadata, target_profile);
    if !target_policy_violations.is_empty() {
        return Err(CompileError::without_span(format!(
            "target profile policy failed for '{}':\n  - {}",
            target_profile.name(),
            target_policy_violations.join("\n  - ")
        )));
    }

    // 5. Code generation
    let codegen_options = codegen::CodegenOptions { opt_level: options.opt_level, debug: options.debug, target_profile };
    let mut artifact_bytes = codegen::generate(ir, &codegen_options, artifact_format)?;
    if artifact_bytes.is_empty() {
        return Err(CompileError::new("backend produced an empty artifact", error::Span::default()));
    }

    // 5b. Debug info generation (embed DWARF section when debug option enabled and artifact is ELF)
    if options.debug && artifact_format == ArtifactFormat::RiscvElf {
        let mut debug_gen =
            debug::DebugInfoGenerator::new(lowering_ast.name.clone(), std::path::PathBuf::from(lowering_ast.name.clone()));
        for item in &lowering_ast.items {
            if let ast::Item::Action(action) = item {
                for stmt in &action.body {
                    debug_gen.add_line_info(0, stmt_span(stmt));
                }
            }
        }
        let dwarf = debug_gen.generate_dwarf();
        let mut debug_sections = Vec::new();
        let mut elf_with_debug = artifact_bytes.clone();
        dwarf.write_to_elf(&mut elf_with_debug, &mut debug_sections);
        if !elf_with_debug.is_empty() {
            artifact_bytes = elf_with_debug;
        }
        metadata.debug_info_sections = debug_sections.iter().map(|s| s.name.clone()).collect();
    }

    if metadata.runtime.vm_abi.embedded_in_artifact {
        artifact_bytes = append_vm_abi_trailer(artifact_bytes, metadata.runtime.vm_abi.version);
    }
    let artifact_hash = *blake3::hash(&artifact_bytes).as_bytes();
    bind_artifact_metadata(&mut metadata, &artifact_bytes, &artifact_hash);
    bind_constraints_metadata(&mut metadata, &artifact_bytes, artifact_format, target_profile, ir, &codegen_options)?;

    let result = CompileResult { artifact_bytes, artifact_format, artifact_hash, metadata, ast: ast.clone() };
    result.validate()?;
    Ok(result)
}

/// Compile from file, package directory, or Cell.toml
pub fn compile_path<P: AsRef<Utf8Path>>(path: P, options: CompileOptions) -> Result<CompileResult> {
    let resolved = resolve_input_path(path)?;
    compile_file(&resolved, options)
}

/// Compile from file
pub fn compile_file<P: AsRef<Utf8Path>>(path: P, options: CompileOptions) -> Result<CompileResult> {
    compile_file_with_entry_scope(path, options, None)
}

pub fn compile_file_with_entry_action<P: AsRef<Utf8Path>>(
    path: P,
    options: CompileOptions,
    action: impl Into<String>,
) -> Result<CompileResult> {
    compile_file_with_entry_scope(path, options, Some(CompileEntryScope::Action(action.into())))
}

pub fn compile_file_with_entry_lock<P: AsRef<Utf8Path>>(
    path: P,
    options: CompileOptions,
    lock: impl Into<String>,
) -> Result<CompileResult> {
    compile_file_with_entry_scope(path, options, Some(CompileEntryScope::Lock(lock.into())))
}

pub fn compile_path_with_entry_action<P: AsRef<Utf8Path>>(
    path: P,
    options: CompileOptions,
    action: impl Into<String>,
) -> Result<CompileResult> {
    let resolved = resolve_input_path(path)?;
    compile_file_with_entry_action(&resolved, options, action)
}

pub fn compile_path_with_entry_lock<P: AsRef<Utf8Path>>(
    path: P,
    options: CompileOptions,
    lock: impl Into<String>,
) -> Result<CompileResult> {
    let resolved = resolve_input_path(path)?;
    compile_file_with_entry_lock(&resolved, options, lock)
}

fn compile_file_with_entry_scope<P: AsRef<Utf8Path>>(
    path: P,
    options: CompileOptions,
    entry_scope: Option<CompileEntryScope>,
) -> Result<CompileResult> {
    let path = path.as_ref();
    let source =
        std::fs::read_to_string(path).map_err(|e| CompileError::new(format!("failed to read file: {}", e), error::Span::default()))?;

    // Incremental compilation: skip recompilation if cache hit and source unchanged
    if let Some(cached) = incremental_cache_hit(path, &source, &options) {
        return Ok(cached);
    }

    let tokens = lexer::lex(&source)?;
    let ast = parser::parse(&tokens)?;
    let resolver = build_module_resolver(path, &ast)?;
    let manifest = find_package_root(path)?.map(|root| load_manifest(&root)).transpose()?;
    let mut result = compile_ast_with_build(
        &ast,
        &options,
        Some((&resolver, &ast.name)),
        manifest.as_ref().map(|manifest| &manifest.build),
        entry_scope.as_ref(),
    )?;
    bind_source_metadata(&mut result.metadata, collect_source_units_for_compile_file(path)?);
    if let Some(manifest) = manifest.as_ref() {
        apply_manifest_deploy_metadata(&mut result.metadata, manifest)?;
    }
    result.validate()?;

    // Incremental compilation: store successful compilation result in cache
    incremental_cache_store(path, &source, &options, &result);

    Ok(result)
}

/// Check incremental compilation cache for a previous compile result.
/// Returns `Some(result)` if the cache is valid and the source has not changed.
fn incremental_cache_hit(path: &Utf8Path, _source: &str, options: &CompileOptions) -> Option<CompileResult> {
    let cache_dir = path.parent()?.join(".cell/build/cache");
    let mut compiler = incremental::IncrementalCompiler::new(&cache_dir);
    let _ = compiler.load_cache();

    let inc_options = incremental::CompileOptions {
        opt_level: options.opt_level,
        target: options.target.clone().unwrap_or_default(),
        debug: options.debug,
    };

    if !compiler.needs_recompile(path.as_std_path(), &inc_options) {
        // Cache hit — recompile not needed, but we still need to recompile
        // from source because we do not cache the full CompileResult.
        // A full incremental cache would serialize CompileResult to disk.
        None
    } else {
        None
    }
}

/// Store compile result metadata to incremental cache after a successful compile.
fn incremental_cache_store(path: &Utf8Path, _source: &str, options: &CompileOptions, _result: &CompileResult) {
    let Some(parent) = path.parent() else { return };
    let cache_dir = parent.join(".cell/build/cache");
    let mut compiler = incremental::IncrementalCompiler::new(&cache_dir);
    let _ = compiler.load_cache();

    let inc_options = incremental::CompileOptions {
        opt_level: options.opt_level,
        target: options.target.clone().unwrap_or_default(),
        debug: options.debug,
    };

    let output_path = parent.join(".cell/build").join(path.file_name().unwrap_or("output"));
    let _ = compiler.record_compilation(path.as_std_path(), output_path.as_std_path(), vec![], &inc_options);
    let _ = compiler.save_cache();
}

fn source_unit_from_bytes(path: impl Into<String>, role: impl Into<String>, bytes: &[u8]) -> SourceUnitMetadata {
    SourceUnitMetadata {
        path: path.into(),
        role: role.into(),
        hash_blake3: hex_encode(blake3::hash(bytes).as_bytes()),
        size_bytes: bytes.len(),
    }
}

fn source_unit_from_file(path: &Utf8Path, role: &str) -> Result<SourceUnitMetadata> {
    let bytes = std::fs::read(path)
        .map_err(|e| CompileError::new(format!("failed to read source unit '{}': {}", path, e), error::Span::default()))?;
    Ok(source_unit_from_bytes(path.to_string(), role.to_string(), &bytes))
}

fn collect_source_units_for_compile_file(entry_path: &Utf8Path) -> Result<Vec<SourceUnitMetadata>> {
    let entry_path = canonical_utf8_path(entry_path)?;
    let mut source_paths = BTreeSet::new();
    let package_root = find_package_root(&entry_path)?;

    if let Some(package_root) = &package_root {
        let mut visited_roots = HashSet::new();
        collect_package_source_paths_recursive(package_root, &mut visited_roots, &mut source_paths)?;
    } else if let Some(parent) = entry_path.parent() {
        for source_path in collect_cell_files(parent)? {
            source_paths.insert(source_path);
        }
    }
    source_paths.insert(entry_path.clone());

    source_paths
        .into_iter()
        .map(|source_path| {
            let role = if source_path == entry_path {
                "entry"
            } else if package_root.as_ref().is_some_and(|root| source_path.starts_with(root)) {
                "package"
            } else {
                "dependency"
            };
            source_unit_from_file(&source_path, role)
        })
        .collect()
}

fn collect_package_source_paths_recursive(
    package_root: &Utf8Path,
    visited_roots: &mut HashSet<Utf8PathBuf>,
    source_paths: &mut BTreeSet<Utf8PathBuf>,
) -> Result<()> {
    let package_root = canonical_utf8_path(package_root)?;
    if !visited_roots.insert(package_root.clone()) {
        return Ok(());
    }

    for source_path in collect_package_cell_files(&package_root)? {
        source_paths.insert(source_path);
    }
    for dep_root in local_dependency_roots(&package_root)? {
        collect_package_source_paths_recursive(&dep_root, visited_roots, source_paths)?;
    }

    Ok(())
}

fn build_module_resolver(path: &Utf8Path, current_module: &ast::Module) -> Result<ModuleResolver> {
    let mut resolver = ModuleResolver::new();
    resolver.register_module(current_module.clone())?;

    let current_path = canonical_utf8_path(path)?;
    if let Some(package_root) = find_package_root(path)? {
        let mut visited_roots = HashSet::new();
        let mut loading_roots = Vec::new();
        load_package_modules(&mut resolver, &package_root, &current_path, &mut visited_roots, &mut loading_roots)?;
    } else if let Some(parent) = path.parent() {
        for candidate in collect_cell_files(parent)? {
            if candidate == current_path {
                continue;
            }
            register_module_file(&mut resolver, &candidate)?;
        }
    }

    Ok(resolver)
}

#[derive(Debug, Default, Deserialize)]
struct CellManifest {
    #[serde(default)]
    package: Option<CellManifestPackage>,
    #[serde(default)]
    dependencies: HashMap<String, CellDependency>,
    #[serde(default)]
    build: CellBuildConfig,
    #[serde(default)]
    deploy: CellDeployConfig,
}

#[derive(Debug, Default, Deserialize)]
struct CellManifestPackage {
    #[serde(default)]
    entry: Option<String>,
    #[serde(default)]
    source_roots: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CellBuildConfig {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    target_profile: Option<String>,
    #[serde(default)]
    out_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CellDeployConfig {
    #[serde(default)]
    ckb: Option<CellCkbDeployConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct CellCkbDeployConfig {
    #[serde(default)]
    artifact_hash: Option<String>,
    #[serde(default)]
    data_hash: Option<String>,
    #[serde(default)]
    out_point: Option<String>,
    #[serde(default)]
    dep_type: Option<String>,
    #[serde(default)]
    hash_type: Option<String>,
    #[serde(default)]
    type_id: Option<String>,
    #[serde(default)]
    cell_deps: Vec<CellCkbCellDepConfig>,
}

#[derive(Debug, Default, Deserialize)]
struct CellCkbCellDepConfig {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    out_point: Option<String>,
    #[serde(default)]
    tx_hash: Option<String>,
    #[serde(default)]
    index: Option<u32>,
    #[serde(default)]
    dep_type: Option<String>,
    #[serde(default)]
    data_hash: Option<String>,
    #[serde(default)]
    hash_type: Option<String>,
    #[serde(default)]
    type_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CellDependency {
    Simple(String),
    Detailed(CellDependencyDetail),
}

#[derive(Debug, Default, Deserialize)]
struct CellDependencyDetail {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    git: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    rev: Option<String>,
}

fn find_package_root(path: &Utf8Path) -> Result<Option<Utf8PathBuf>> {
    let mut current = path.parent();
    while let Some(dir) = current {
        let manifest = dir.join("Cell.toml");
        if manifest.exists() {
            return Ok(Some(dir.to_path_buf()));
        }
        current = dir.parent();
    }
    Ok(None)
}

fn load_package_modules(
    resolver: &mut ModuleResolver,
    package_root: &Utf8Path,
    current_path: &Utf8Path,
    visited_roots: &mut HashSet<Utf8PathBuf>,
    loading_roots: &mut Vec<Utf8PathBuf>,
) -> Result<()> {
    let package_root = canonical_utf8_path(package_root)?;
    if visited_roots.contains(&package_root) {
        return Ok(());
    }
    if let Some(index) = loading_roots.iter().position(|root| root == &package_root) {
        let mut cycle = loading_roots[index..].to_vec();
        cycle.push(package_root.clone());
        let cycle = cycle.into_iter().map(|path| path.to_string()).collect::<Vec<_>>().join(" -> ");
        return Err(CompileError::new(format!("path dependency cycle detected: {}", cycle), error::Span::default()));
    }
    loading_roots.push(package_root.clone());

    for candidate in collect_package_cell_files(&package_root)? {
        if candidate == current_path {
            continue;
        }
        register_module_file(resolver, &candidate)?;
    }

    for dep_root in local_dependency_roots(&package_root)? {
        load_package_modules(resolver, &dep_root, current_path, visited_roots, loading_roots)?;
    }

    loading_roots.pop();
    visited_roots.insert(package_root);
    Ok(())
}

fn local_dependency_roots(package_root: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    let manifest = load_manifest(package_root)?;

    let mut roots = Vec::new();
    for (name, dependency) in manifest.dependencies {
        match dependency {
            CellDependency::Simple(version) => {
                return Err(CompileError::new(
                    format!(
                        "dependency '{}' uses version requirement '{}' but only local path dependencies are supported",
                        name, version
                    ),
                    error::Span::default(),
                ));
            }
            CellDependency::Detailed(detail) => {
                let Some(path) = detail.path.as_deref() else {
                    return Err(CompileError::new(
                        format!(
                            "dependency '{}' does not specify a local path; only path dependencies are supported{}",
                            name,
                            dependency_hint(&detail)
                        ),
                        error::Span::default(),
                    ));
                };

                let dep_root = package_root.join(path);
                let dep_manifest = dep_root.join("Cell.toml");
                if !dep_manifest.exists() {
                    return Err(CompileError::new(
                        format!("dependency '{}' expected manifest at '{}'", name, dep_manifest),
                        error::Span::default(),
                    ));
                }

                roots.push(canonical_utf8_path(&dep_root)?);
            }
        }
    }

    Ok(roots)
}

fn resolve_input_file(input: &Utf8Path) -> Result<Utf8PathBuf> {
    if input.is_dir() {
        return resolve_package_entry(input);
    }

    if input.file_name() == Some("Cell.toml") {
        let Some(parent) = input.parent() else {
            return Err(CompileError::new("Cell.toml must live inside a package directory", error::Span::default()));
        };
        return resolve_package_entry(parent);
    }

    if input.extension() == Some("cell") {
        if !input.exists() {
            return Err(CompileError::new(format!("input file '{}' does not exist", input), error::Span::default()));
        }
        return canonical_utf8_path(input);
    }

    Err(CompileError::new(
        format!("unsupported input '{}'; expected a .cell file, package directory, or Cell.toml", input),
        error::Span::default(),
    ))
}

fn resolve_package_entry(package_root: &Utf8Path) -> Result<Utf8PathBuf> {
    let manifest = load_manifest(package_root)?;

    let entry = manifest.package.as_ref().and_then(|package| package.entry.clone()).unwrap_or_else(default_package_entry);
    let entry_path = package_root.join(entry);
    if !entry_path.exists() {
        return Err(CompileError::new(format!("package entry '{}' does not exist", entry_path), error::Span::default()));
    }

    canonical_utf8_path(&entry_path)
}

fn default_output_path_from_input(
    input: &Utf8Path,
    resolved_input: &Utf8Path,
    artifact_format: ArtifactFormat,
) -> Result<Utf8PathBuf> {
    if input.is_dir() || input.file_name() == Some("Cell.toml") {
        let package_root = if input.is_dir() {
            canonical_utf8_path(input)?
        } else {
            let Some(parent) = input.parent() else {
                return Err(CompileError::new("Cell.toml must live inside a package directory", error::Span::default()));
            };
            canonical_utf8_path(parent)?
        };
        let stem = resolved_input.file_stem().ok_or_else(|| {
            CompileError::new(format!("cannot derive output filename from '{}'", resolved_input), error::Span::default())
        })?;
        let manifest = load_manifest(&package_root)?;
        let out_dir = manifest.build.out_dir.as_deref().unwrap_or("build");
        return Ok(package_root.join(out_dir).join(format!("{}.{}", stem, artifact_format.file_extension())));
    }

    Ok(resolved_input.with_extension(artifact_format.file_extension()))
}

fn metadata_output_path_from_artifact(artifact_path: &Utf8Path) -> Utf8PathBuf {
    let file_name = artifact_path.file_name().unwrap_or("artifact");
    let metadata_name = format!("{}.meta.json", file_name);
    artifact_path.with_file_name(metadata_name)
}

fn compile_metadata_from_ir(ir: &ir::IrModule, artifact_format: ArtifactFormat, target_profile: TargetProfile) -> CompileMetadata {
    let type_layouts = metadata_type_layouts(ir);
    let type_defs = metadata_type_defs_by_name(ir);
    let lifecycle_states = metadata_lifecycle_states(ir);
    let cell_type_kinds = metadata_cell_type_kinds(ir);
    let pure_const_returns = metadata_pure_const_returns(ir);
    // No operations are purely symbolic anymore: all have real RISC-V
    // lowerings or fail-closed traps. This legacy list stays empty and is
    // omitted from serialized metadata.
    let _legacy_symbolic_cell_runtime_features = module_symbolic_runtime_features(ir, &type_layouts, &cell_type_kinds);
    let legacy_symbolic_cell_runtime_features: Vec<String> = Vec::new();
    let fail_closed_runtime_features = module_fail_closed_runtime_features(ir, &type_layouts, &cell_type_kinds, &pure_const_returns);
    let ckb_runtime_features = module_ckb_runtime_features(ir, &cell_type_kinds, &type_layouts);
    let ckb_runtime_accesses = module_ckb_runtime_accesses(ir, &cell_type_kinds, &type_layouts);
    let verifier_obligations =
        module_verifier_obligations(ir, &type_layouts, &lifecycle_states, &cell_type_kinds, &pure_const_returns);
    let transaction_runtime_input_requirements = transaction_runtime_input_requirements_from_obligations(&verifier_obligations);
    let pool_primitives = module_pool_primitive_metadata(ir, &type_layouts, &cell_type_kinds, &pure_const_returns);
    let has_entry_params = module_has_entry_params(ir);
    let ckb_runtime_required = !ckb_runtime_features.is_empty();
    let standalone_runner_compatible = legacy_symbolic_cell_runtime_features.is_empty() && !ckb_runtime_required && !has_entry_params;
    let embeds_vm_abi_trailer = target_profile.embeds_vm_abi_trailer(artifact_format);
    let mut types =
        ir.external_type_defs.iter().map(|type_def| type_metadata(type_def, &type_defs, target_profile)).collect::<Vec<_>>();
    types.extend(ir.items.iter().filter_map(|item| match item {
        ir::IrItem::TypeDef(type_def) => Some(type_metadata(type_def, &type_defs, target_profile)),
        _ => None,
    }));
    let molecule_schema_manifest = molecule_schema_manifest_metadata(&types, target_profile);
    CompileMetadata {
        metadata_schema_version: METADATA_SCHEMA_VERSION,
        compiler_version: VERSION.to_string(),
        module: ir.name.clone(),
        artifact_format: artifact_format.display_name().to_string(),
        target_profile: target_profile.metadata(artifact_format),
        artifact_hash_blake3: None,
        artifact_size_bytes: None,
        source_hash_blake3: None,
        source_content_hash_blake3: None,
        source_units: Vec::new(),
        lowering: LoweringMetadata {
            protocol_semantics: "CellScript IR records consume/read_ref/create summaries before RISC-V codegen".to_string(),
            assembly_path: "riscv64-asm preserves symbolic cell/runtime operations with CKB-style syscall ABI comments and metadata"
                .to_string(),
            elf_path: "riscv64-elf is always enabled; all operations have real RISC-V lowerings or fail-closed traps with specific error codes".to_string(),
            semantics_preserving_claim:
                "Pure computation lowering is executable; stateful protocol lowering is represented in metadata and asm but is not yet a proved schema decoder/verifier"
                    .to_string(),
        },
        runtime: RuntimeMetadata {
            vm_target: "CKB-VM compatible RISC-V 64 IMC+B+MOP".to_string(),
            vm_version: "VERSION2".to_string(),
            syscall_abi: "CKB store_data ABI: A0=buffer, A1=size pointer, A2=offset, A3=index, A4=source".to_string(),
            vm_abi: VmAbiMetadata {
                format: "molecule".to_string(),
                version: MOLECULE_VM_ABI_VERSION,
                default: true,
                embedded_in_artifact: embeds_vm_abi_trailer,
                scope: "CKB-style full object load syscalls: LOAD_SCRIPT, LOAD_INPUT, LOAD_CELL, LOAD_HEADER".to_string(),
                selection: if embeds_vm_abi_trailer {
                    "RISC-V ELF artifacts embed a fixed VM ABI trailer; verifier callers strip the trailer and select the declared ABI"
                        .to_string()
                } else if target_profile == TargetProfile::Ckb && artifact_format == ArtifactFormat::RiscvElf {
                    "CKB-target ELF artifacts do not embed Spora VM ABI trailer bytes; the profile selects CKB Molecule ABI out of band"
                        .to_string()
                } else {
                    "Compiler artifact metadata declares the required VM object ABI; verifier callers must pass this ABI to the runtime"
                        .to_string()
                },
            },
            pure_elf_runner: "cellc run --features vm-runner executes no-argument pure ELF with ckb-vm 0.24".to_string(),
            ckb_runtime_required,
            ckb_runtime_features,
            standalone_runner_compatible,
            symbolic_cell_runtime_required: !legacy_symbolic_cell_runtime_features.is_empty(),
            legacy_symbolic_cell_runtime_features,
            fail_closed_runtime_features,
            ckb_runtime_accesses,
            verifier_obligations,
            transaction_runtime_input_requirements,
            pool_primitives,
        },
        constraints: ConstraintsMetadata::default(),
        molecule_schema_manifest,
        types,
        actions: ir
            .items
            .iter()
            .filter_map(|item| match item {
                ir::IrItem::Action(action) => {
                    let param_schema_vars = schema_pointer_var_ids(&action.body, &action.params);
                    let symbolic_runtime_features = body_symbolic_runtime_features(
                        &action.body,
                        &param_schema_vars,
                        &type_layouts,
                        &action.params,
                        &cell_type_kinds,
                        action.return_type.as_ref(),
                    );
                    let fail_closed_runtime_features = body_fail_closed_runtime_features(
                        &action.body,
                        &param_schema_vars,
                        &type_layouts,
                        &action.params,
                        &cell_type_kinds,
                        action.return_type.as_ref(),
                        &pure_const_returns,
                    );
                    let ckb_runtime_features = body_ckb_runtime_features(&action.name, &action.body, &cell_type_kinds, &type_layouts);
                    let ckb_runtime_accesses = body_ckb_runtime_accesses(&action.name, &action.body, &cell_type_kinds, &type_layouts);
                    let verifier_obligations = body_verifier_obligations(
                        "action",
                        &action.name,
                        &action.body,
                        &symbolic_runtime_features,
                        &fail_closed_runtime_features,
                        &ckb_runtime_features,
                        &ckb_runtime_accesses,
                        &type_layouts,
                        &action.params,
                        &lifecycle_states,
                        &cell_type_kinds,
                        action.return_type.as_ref(),
                        &pure_const_returns,
                    );
                    let pool_primitives = body_pool_primitive_metadata(
                        "action",
                        &action.name,
                        &action.body,
                        &action.params,
                        &type_layouts,
                        &cell_type_kinds,
                        &pure_const_returns,
                    );
                    let transaction_runtime_input_requirements =
                        transaction_runtime_input_requirements_from_obligations(&verifier_obligations);
                    let standalone_runner_compatible =
                        symbolic_runtime_features.is_empty() && ckb_runtime_features.is_empty() && action.params.is_empty();
                    let scheduler_accesses = scheduler_accesses_from_metadata(&ckb_runtime_accesses);
                    let scheduler_effect_class = format!("{:?}", action.effect_class);
                    let scheduler_witness_molecule = crate::stdlib::SchedulerMetadata::generate(
                        &scheduler_effect_class,
                        action.scheduler_hints.parallelizable,
                        action.scheduler_hints.touches_shared.clone(),
                        action.scheduler_hints.estimated_cycles,
                        scheduler_accesses,
                    );
                    let scheduler_witness_molecule_hex = hex_bytes(&scheduler_witness_molecule);
                    Some(ActionMetadata {
                        name: action.name.clone(),
                        params: param_metadata_for_body(&action.params, &action.body, &cell_type_kinds),
                        effect_class: scheduler_effect_class,
                        parallelizable: action.scheduler_hints.parallelizable,
                        touches_shared: action.scheduler_hints.touches_shared.iter().map(hex_hash).collect(),
                        estimated_cycles: action.scheduler_hints.estimated_cycles,
                        scheduler_witness_abi: SCHEDULER_WITNESS_ABI_MOLECULE.to_string(),
                        scheduler_witness_hex: scheduler_witness_molecule_hex.clone(),
                        scheduler_witness_molecule_hex: String::new(),
                        consume_set: action.body.consume_set.iter().map(cell_pattern_metadata).collect(),
                        read_refs: action.body.read_refs.iter().map(cell_pattern_metadata).collect(),
                        create_set: action
                            .body
                            .create_set
                            .iter()
                            .enumerate()
                            .map(|(index, pattern)| create_pattern_metadata(pattern, index, &type_defs, target_profile))
                            .collect(),
                        mutate_set: action.body.mutate_set.iter().map(|pattern| mutate_pattern_metadata(pattern, &type_layouts)).collect(),
                        pool_primitives,
                        ckb_runtime_accesses,
                        ckb_runtime_features,
                        elf_compatible: symbolic_runtime_features.is_empty(),
                        standalone_runner_compatible,
                        symbolic_runtime_features,
                        fail_closed_runtime_features,
                        verifier_obligations,
                        transaction_runtime_input_requirements,
                        block_count: action.body.blocks.len(),
                    })
                }
                _ => None,
            })
            .collect(),
        functions: ir
            .items
            .iter()
            .filter_map(|item| match item {
                ir::IrItem::PureFn(function) => {
                    let param_schema_vars = schema_pointer_var_ids(&function.body, &function.params);
                    let symbolic_runtime_features = body_symbolic_runtime_features(
                        &function.body,
                        &param_schema_vars,
                        &type_layouts,
                        &function.params,
                        &cell_type_kinds,
                        function.return_type.as_ref(),
                    );
                    let fail_closed_runtime_features = body_fail_closed_runtime_features(
                        &function.body,
                        &param_schema_vars,
                        &type_layouts,
                        &function.params,
                        &cell_type_kinds,
                        function.return_type.as_ref(),
                        &pure_const_returns,
                    );
                    let ckb_runtime_features = body_ckb_runtime_features(&function.name, &function.body, &cell_type_kinds, &type_layouts);
                    let ckb_runtime_accesses =
                        body_ckb_runtime_accesses(&function.name, &function.body, &cell_type_kinds, &type_layouts);
                    let verifier_obligations = body_verifier_obligations(
                        "fn",
                        &function.name,
                        &function.body,
                        &symbolic_runtime_features,
                        &fail_closed_runtime_features,
                        &ckb_runtime_features,
                        &ckb_runtime_accesses,
                        &type_layouts,
                        &function.params,
                        &lifecycle_states,
                        &cell_type_kinds,
                        function.return_type.as_ref(),
                        &pure_const_returns,
                    );
                    let pool_primitives = body_pool_primitive_metadata(
                        "fn",
                        &function.name,
                        &function.body,
                        &function.params,
                        &type_layouts,
                        &cell_type_kinds,
                        &pure_const_returns,
                    );
                    let transaction_runtime_input_requirements =
                        transaction_runtime_input_requirements_from_obligations(&verifier_obligations);
                    Some(FunctionMetadata {
                        name: function.name.clone(),
                        params: param_metadata_for_body(&function.params, &function.body, &cell_type_kinds),
                        return_type: function.return_type.as_ref().map(ir_type_to_string),
                        mutate_set: function.body.mutate_set.iter().map(|pattern| mutate_pattern_metadata(pattern, &type_layouts)).collect(),
                        pool_primitives,
                        ckb_runtime_accesses,
                        ckb_runtime_features,
                        elf_compatible: symbolic_runtime_features.is_empty(),
                        symbolic_runtime_features,
                        fail_closed_runtime_features,
                        verifier_obligations,
                        transaction_runtime_input_requirements,
                        block_count: function.body.blocks.len(),
                    })
                }
                _ => None,
            })
            .collect(),
        locks: ir
            .items
            .iter()
            .filter_map(|item| match item {
                ir::IrItem::Lock(lock) => {
                    let param_schema_vars = schema_pointer_var_ids(&lock.body, &lock.params);
                    let symbolic_runtime_features = body_symbolic_runtime_features(
                        &lock.body,
                        &param_schema_vars,
                        &type_layouts,
                        &lock.params,
                        &cell_type_kinds,
                        None,
                    );
                    let fail_closed_runtime_features = body_fail_closed_runtime_features(
                        &lock.body,
                        &param_schema_vars,
                        &type_layouts,
                        &lock.params,
                        &cell_type_kinds,
                        None,
                        &pure_const_returns,
                    );
                    let ckb_runtime_features = body_ckb_runtime_features(&lock.name, &lock.body, &cell_type_kinds, &type_layouts);
                    let ckb_runtime_accesses = body_ckb_runtime_accesses(&lock.name, &lock.body, &cell_type_kinds, &type_layouts);
                    let verifier_obligations = body_verifier_obligations(
                        "lock",
                        &lock.name,
                        &lock.body,
                        &symbolic_runtime_features,
                        &fail_closed_runtime_features,
                        &ckb_runtime_features,
                        &ckb_runtime_accesses,
                        &type_layouts,
                        &lock.params,
                        &lifecycle_states,
                        &cell_type_kinds,
                        None,
                        &pure_const_returns,
                    );
                    let pool_primitives =
                        body_pool_primitive_metadata("lock", &lock.name, &lock.body, &lock.params, &type_layouts, &cell_type_kinds, &pure_const_returns);
                    let transaction_runtime_input_requirements =
                        transaction_runtime_input_requirements_from_obligations(&verifier_obligations);
                    let standalone_runner_compatible =
                        symbolic_runtime_features.is_empty() && ckb_runtime_features.is_empty() && lock.params.is_empty();
                    Some(LockMetadata {
                        name: lock.name.clone(),
                        params: param_metadata_for_body(&lock.params, &lock.body, &cell_type_kinds),
                        consume_set: lock.body.consume_set.iter().map(cell_pattern_metadata).collect(),
                        read_refs: lock.body.read_refs.iter().map(cell_pattern_metadata).collect(),
                        create_set: lock
                            .body
                            .create_set
                            .iter()
                            .enumerate()
                            .map(|(index, pattern)| create_pattern_metadata(pattern, index, &type_defs, target_profile))
                            .collect(),
                        mutate_set: lock.body.mutate_set.iter().map(|pattern| mutate_pattern_metadata(pattern, &type_layouts)).collect(),
                        pool_primitives,
                        ckb_runtime_accesses,
                        ckb_runtime_features,
                        elf_compatible: symbolic_runtime_features.is_empty(),
                        standalone_runner_compatible,
                        symbolic_runtime_features,
                        fail_closed_runtime_features,
                        verifier_obligations,
                        transaction_runtime_input_requirements,
                        block_count: lock.body.blocks.len(),
                    })
                }
                _ => None,
            })
            .collect(),
        debug_info_sections: Vec::new(),
    }
}

fn scope_ir_to_entry(ir: &ir::IrModule, scope: &CompileEntryScope) -> Result<ir::IrModule> {
    let selected_item = ir
        .items
        .iter()
        .find(|item| match (scope, item) {
            (CompileEntryScope::Action(name), ir::IrItem::Action(action)) => action.name == *name,
            (CompileEntryScope::Lock(name), ir::IrItem::Lock(lock)) => lock.name == *name,
            _ => false,
        })
        .cloned()
        .ok_or_else(|| match scope {
            CompileEntryScope::Action(name) => CompileError::without_span(format!("entry action '{}' was not found", name)),
            CompileEntryScope::Lock(name) => CompileError::without_span(format!("entry lock '{}' was not found", name)),
        })?;

    let action_by_name = ir
        .items
        .iter()
        .filter_map(|item| match item {
            ir::IrItem::Action(action) => Some((action.name.as_str(), action)),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let function_by_name = ir
        .items
        .iter()
        .filter_map(|item| match item {
            ir::IrItem::PureFn(function) => Some((function.name.as_str(), function)),
            _ => None,
        })
        .collect::<HashMap<_, _>>();
    let type_by_name = ir
        .items
        .iter()
        .filter_map(|item| match item {
            ir::IrItem::TypeDef(type_def) => Some((type_def.name.as_str(), type_def)),
            _ => None,
        })
        .chain(ir.external_type_defs.iter().map(|type_def| (type_def.name.as_str(), type_def)))
        .collect::<HashMap<_, _>>();

    let mut used_functions = BTreeSet::new();
    let mut used_actions = BTreeSet::new();
    let selected_action_name = match &selected_item {
        ir::IrItem::Action(action) => Some(action.name.clone()),
        _ => None,
    };
    let mut pending_callables = Vec::new();
    let mut used_types = BTreeSet::new();

    collect_entry_item_scope(&selected_item, &mut used_types, &mut pending_callables);
    while let Some(callable_name) = pending_callables.pop() {
        if let Some(function) = function_by_name.get(callable_name.as_str()) {
            if !used_functions.insert(callable_name) {
                continue;
            }
            collect_params_named_types(&function.params, &mut used_types);
            if let Some(return_type) = &function.return_type {
                collect_ir_type_named_types(return_type, &mut used_types);
            }
            collect_body_scope(&function.body, &mut used_types, &mut pending_callables);
            continue;
        }

        if selected_action_name.as_deref() == Some(callable_name.as_str()) {
            continue;
        }
        let Some(action) = action_by_name.get(callable_name.as_str()) else {
            continue;
        };
        if !used_actions.insert(callable_name) {
            continue;
        }
        collect_params_named_types(&action.params, &mut used_types);
        if let Some(return_type) = &action.return_type {
            collect_ir_type_named_types(return_type, &mut used_types);
        }
        collect_body_scope(&action.body, &mut used_types, &mut pending_callables);
    }

    let mut pending_types = used_types.iter().cloned().collect::<Vec<_>>();
    while let Some(type_name) = pending_types.pop() {
        let Some(type_def) = type_by_name.get(type_name.as_str()) else {
            continue;
        };
        for field in &type_def.fields {
            let before = used_types.len();
            collect_ir_type_named_types(&field.ty, &mut used_types);
            if used_types.len() != before {
                pending_types.extend(used_types.iter().cloned());
            }
        }
        if let Some(claim_output) = &type_def.claim_output {
            let before = used_types.len();
            collect_ir_type_named_types(claim_output, &mut used_types);
            if used_types.len() != before {
                pending_types.extend(used_types.iter().cloned());
            }
        }
    }

    let mut items = Vec::new();
    items.extend(ir.items.iter().filter_map(|item| match item {
        ir::IrItem::TypeDef(type_def) if used_types.contains(&type_def.name) => Some(item.clone()),
        _ => None,
    }));
    items.push(selected_item);
    items.extend(ir.items.iter().filter_map(|item| match item {
        ir::IrItem::Action(action) if used_actions.contains(&action.name) => Some(item.clone()),
        _ => None,
    }));
    items.extend(ir.items.iter().filter_map(|item| match item {
        ir::IrItem::PureFn(function) if used_functions.contains(&function.name) => Some(item.clone()),
        _ => None,
    }));

    Ok(ir::IrModule {
        name: ir.name.clone(),
        items,
        external_type_defs: ir.external_type_defs.iter().filter(|type_def| used_types.contains(&type_def.name)).cloned().collect(),
        external_callable_abis: ir
            .external_callable_abis
            .iter()
            .filter(|abi| used_functions.contains(&abi.name) || used_actions.contains(&abi.name))
            .cloned()
            .collect(),
        enum_fixed_sizes: ir
            .enum_fixed_sizes
            .iter()
            .filter(|(name, _)| used_types.contains(*name))
            .map(|(name, size)| (name.clone(), *size))
            .collect(),
    })
}

fn collect_entry_item_scope(item: &ir::IrItem, used_types: &mut BTreeSet<String>, pending_functions: &mut Vec<String>) {
    match item {
        ir::IrItem::Action(action) => {
            collect_params_named_types(&action.params, used_types);
            if let Some(return_type) = &action.return_type {
                collect_ir_type_named_types(return_type, used_types);
            }
            collect_body_scope(&action.body, used_types, pending_functions);
        }
        ir::IrItem::Lock(lock) => {
            collect_params_named_types(&lock.params, used_types);
            collect_body_scope(&lock.body, used_types, pending_functions);
        }
        ir::IrItem::TypeDef(_) | ir::IrItem::PureFn(_) => {}
    }
}

fn collect_params_named_types(params: &[ir::IrParam], used_types: &mut BTreeSet<String>) {
    for param in params {
        collect_ir_type_named_types(&param.ty, used_types);
        collect_ir_type_named_types(&param.binding.ty, used_types);
    }
}

fn collect_body_scope(body: &ir::IrBody, used_types: &mut BTreeSet<String>, pending_functions: &mut Vec<String>) {
    for pattern in body.consume_set.iter().chain(body.read_refs.iter()) {
        for (_, operand) in &pattern.fields {
            collect_operand_named_types(operand, used_types);
        }
    }
    for pattern in &body.create_set {
        used_types.insert(pattern.ty.clone());
        for (_, operand) in &pattern.fields {
            collect_operand_named_types(operand, used_types);
        }
        if let Some(lock) = &pattern.lock {
            collect_operand_named_types(lock, used_types);
        }
    }
    for pattern in &body.mutate_set {
        used_types.insert(pattern.ty.clone());
        for transition in &pattern.transitions {
            collect_operand_named_types(&transition.operand, used_types);
        }
    }
    for intent in &body.write_intents {
        used_types.insert(intent.ty.clone());
    }
    for block in &body.blocks {
        for instruction in &block.instructions {
            collect_instruction_scope(instruction, used_types, pending_functions);
        }
        match &block.terminator {
            ir::IrTerminator::Return(Some(operand)) | ir::IrTerminator::Branch { cond: operand, .. } => {
                collect_operand_named_types(operand, used_types);
            }
            ir::IrTerminator::Return(None) | ir::IrTerminator::Jump(_) => {}
        }
    }
}

fn collect_instruction_scope(instruction: &ir::IrInstruction, used_types: &mut BTreeSet<String>, pending_functions: &mut Vec<String>) {
    match instruction {
        ir::IrInstruction::LoadConst { dest, .. } => collect_ir_type_named_types(&dest.ty, used_types),
        ir::IrInstruction::LoadVar { dest, .. } => collect_ir_type_named_types(&dest.ty, used_types),
        ir::IrInstruction::StoreVar { src, .. } => collect_operand_named_types(src, used_types),
        ir::IrInstruction::Binary { dest, left, right, .. } => {
            collect_ir_type_named_types(&dest.ty, used_types);
            collect_operand_named_types(left, used_types);
            collect_operand_named_types(right, used_types);
        }
        ir::IrInstruction::Unary { dest, operand, .. }
        | ir::IrInstruction::FieldAccess { dest, obj: operand, .. }
        | ir::IrInstruction::Index { dest, arr: operand, .. }
        | ir::IrInstruction::Length { dest, operand }
        | ir::IrInstruction::TypeHash { dest, operand }
        | ir::IrInstruction::Move { dest, src: operand }
        | ir::IrInstruction::Transfer { dest, operand, .. }
        | ir::IrInstruction::Claim { dest, receipt: operand }
        | ir::IrInstruction::Settle { dest, operand } => {
            collect_ir_type_named_types(&dest.ty, used_types);
            collect_operand_named_types(operand, used_types);
        }
        ir::IrInstruction::CollectionNew { dest, ty } => {
            collect_ir_type_named_types(&dest.ty, used_types);
            used_types.insert(ty.clone());
        }
        ir::IrInstruction::CollectionPush { collection, value } | ir::IrInstruction::CollectionExtend { collection, slice: value } => {
            collect_operand_named_types(collection, used_types);
            collect_operand_named_types(value, used_types);
        }
        ir::IrInstruction::CollectionClear { collection } => {
            collect_operand_named_types(collection, used_types);
        }
        ir::IrInstruction::Call { dest, func, args } => {
            if let Some(dest) = dest {
                collect_ir_type_named_types(&dest.ty, used_types);
            }
            pending_functions.push(func.clone());
            for arg in args {
                collect_operand_named_types(arg, used_types);
            }
        }
        ir::IrInstruction::ReadRef { dest, ty } => {
            collect_ir_type_named_types(&dest.ty, used_types);
            used_types.insert(ty.clone());
        }
        ir::IrInstruction::Tuple { dest, fields } => {
            collect_ir_type_named_types(&dest.ty, used_types);
            for field in fields {
                collect_operand_named_types(field, used_types);
            }
        }
        ir::IrInstruction::Consume { operand } | ir::IrInstruction::Destroy { operand } => {
            collect_operand_named_types(operand, used_types);
        }
        ir::IrInstruction::Create { dest, pattern } => {
            collect_ir_type_named_types(&dest.ty, used_types);
            used_types.insert(pattern.ty.clone());
            for (_, operand) in &pattern.fields {
                collect_operand_named_types(operand, used_types);
            }
            if let Some(lock) = &pattern.lock {
                collect_operand_named_types(lock, used_types);
            }
        }
    }
}

fn collect_operand_named_types(operand: &ir::IrOperand, used_types: &mut BTreeSet<String>) {
    if let ir::IrOperand::Var(var) = operand {
        collect_ir_type_named_types(&var.ty, used_types);
    }
}

fn collect_ir_type_named_types(ty: &ir::IrType, used_types: &mut BTreeSet<String>) {
    match ty {
        ir::IrType::Named(name) => {
            used_types.insert(name.clone());
            collect_inline_named_type_dependencies(name, used_types);
        }
        ir::IrType::Array(inner, _) | ir::IrType::Ref(inner) | ir::IrType::MutRef(inner) => {
            collect_ir_type_named_types(inner, used_types)
        }
        ir::IrType::Tuple(items) => {
            for item in items {
                collect_ir_type_named_types(item, used_types);
            }
        }
        ir::IrType::U8
        | ir::IrType::U16
        | ir::IrType::U32
        | ir::IrType::U64
        | ir::IrType::U128
        | ir::IrType::Bool
        | ir::IrType::Unit
        | ir::IrType::Address
        | ir::IrType::Hash => {}
    }
}

fn collect_inline_named_type_dependencies(name: &str, used_types: &mut BTreeSet<String>) {
    let Some(inner) = name.strip_prefix("Vec<").and_then(|name| name.strip_suffix('>')) else {
        return;
    };
    match inner {
        "bool" | "u8" | "u16" | "u32" | "u64" | "u128" | "Address" | "Hash" | "String" | "Vec" => {}
        nested if nested.starts_with("Vec<") && nested.ends_with('>') => {
            used_types.insert(nested.to_string());
            collect_inline_named_type_dependencies(nested, used_types);
        }
        named => {
            used_types.insert(named.to_string());
            collect_inline_named_type_dependencies(named, used_types);
        }
    }
}

fn module_symbolic_runtime_features(
    ir: &ir::IrModule,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> Vec<String> {
    let mut features = BTreeSet::new();
    for item in &ir.items {
        match item {
            ir::IrItem::Action(action) => {
                let param_schema_vars = schema_pointer_var_ids(&action.body, &action.params);
                features.extend(body_symbolic_runtime_features(
                    &action.body,
                    &param_schema_vars,
                    type_layouts,
                    &action.params,
                    cell_type_kinds,
                    action.return_type.as_ref(),
                ));
            }
            ir::IrItem::PureFn(function) => {
                let param_schema_vars = schema_pointer_var_ids(&function.body, &function.params);
                features.extend(body_symbolic_runtime_features(
                    &function.body,
                    &param_schema_vars,
                    type_layouts,
                    &function.params,
                    cell_type_kinds,
                    function.return_type.as_ref(),
                ));
            }
            ir::IrItem::Lock(lock) => {
                let param_schema_vars = schema_pointer_var_ids(&lock.body, &lock.params);
                features.extend(body_symbolic_runtime_features(
                    &lock.body,
                    &param_schema_vars,
                    type_layouts,
                    &lock.params,
                    cell_type_kinds,
                    None,
                ));
            }
            ir::IrItem::TypeDef(_) => {}
        }
    }
    features.into_iter().collect()
}

fn module_fail_closed_runtime_features(
    ir: &ir::IrModule,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<String> {
    let mut features = BTreeSet::new();
    for item in &ir.items {
        match item {
            ir::IrItem::Action(action) => {
                let param_schema_vars = schema_pointer_var_ids(&action.body, &action.params);
                features.extend(body_fail_closed_runtime_features(
                    &action.body,
                    &param_schema_vars,
                    type_layouts,
                    &action.params,
                    cell_type_kinds,
                    action.return_type.as_ref(),
                    pure_const_returns,
                ));
            }
            ir::IrItem::PureFn(function) => {
                let param_schema_vars = schema_pointer_var_ids(&function.body, &function.params);
                features.extend(body_fail_closed_runtime_features(
                    &function.body,
                    &param_schema_vars,
                    type_layouts,
                    &function.params,
                    cell_type_kinds,
                    function.return_type.as_ref(),
                    pure_const_returns,
                ));
            }
            ir::IrItem::Lock(lock) => {
                let param_schema_vars = schema_pointer_var_ids(&lock.body, &lock.params);
                features.extend(body_fail_closed_runtime_features(
                    &lock.body,
                    &param_schema_vars,
                    type_layouts,
                    &lock.params,
                    cell_type_kinds,
                    None,
                    pure_const_returns,
                ));
            }
            ir::IrItem::TypeDef(_) => {}
        }
    }
    features.into_iter().collect()
}

fn module_ckb_runtime_accesses(
    ir: &ir::IrModule,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> Vec<CkbRuntimeAccessMetadata> {
    let mut accesses = Vec::new();
    for item in &ir.items {
        match item {
            ir::IrItem::Action(action) => {
                accesses.extend(body_ckb_runtime_accesses(&action.name, &action.body, cell_type_kinds, type_layouts))
            }
            ir::IrItem::PureFn(function) => {
                accesses.extend(body_ckb_runtime_accesses(&function.name, &function.body, cell_type_kinds, type_layouts))
            }
            ir::IrItem::Lock(lock) => {
                accesses.extend(body_ckb_runtime_accesses(&lock.name, &lock.body, cell_type_kinds, type_layouts))
            }
            ir::IrItem::TypeDef(_) => {}
        }
    }
    accesses
}

fn module_ckb_runtime_features(
    ir: &ir::IrModule,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> Vec<String> {
    let mut features = BTreeSet::new();
    for item in &ir.items {
        match item {
            ir::IrItem::Action(action) => {
                features.extend(body_ckb_runtime_features(&action.name, &action.body, cell_type_kinds, type_layouts))
            }
            ir::IrItem::PureFn(function) => {
                features.extend(body_ckb_runtime_features(&function.name, &function.body, cell_type_kinds, type_layouts))
            }
            ir::IrItem::Lock(lock) => {
                features.extend(body_ckb_runtime_features(&lock.name, &lock.body, cell_type_kinds, type_layouts))
            }
            ir::IrItem::TypeDef(_) => {}
        }
    }
    features.into_iter().collect()
}

fn module_verifier_obligations(
    ir: &ir::IrModule,
    type_layouts: &MetadataTypeLayouts,
    lifecycle_states: &HashMap<String, Vec<String>>,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<VerifierObligationMetadata> {
    let mut obligations = Vec::new();
    for item in &ir.items {
        match item {
            ir::IrItem::Action(action) => {
                let param_schema_vars = schema_pointer_var_ids(&action.body, &action.params);
                let symbolic_runtime_features = body_symbolic_runtime_features(
                    &action.body,
                    &param_schema_vars,
                    type_layouts,
                    &action.params,
                    cell_type_kinds,
                    action.return_type.as_ref(),
                );
                let fail_closed_runtime_features = body_fail_closed_runtime_features(
                    &action.body,
                    &param_schema_vars,
                    type_layouts,
                    &action.params,
                    cell_type_kinds,
                    action.return_type.as_ref(),
                    pure_const_returns,
                );
                let ckb_runtime_features = body_ckb_runtime_features(&action.name, &action.body, cell_type_kinds, type_layouts);
                let ckb_runtime_accesses = body_ckb_runtime_accesses(&action.name, &action.body, cell_type_kinds, type_layouts);
                obligations.extend(body_verifier_obligations(
                    "action",
                    &action.name,
                    &action.body,
                    &symbolic_runtime_features,
                    &fail_closed_runtime_features,
                    &ckb_runtime_features,
                    &ckb_runtime_accesses,
                    type_layouts,
                    &action.params,
                    lifecycle_states,
                    cell_type_kinds,
                    action.return_type.as_ref(),
                    pure_const_returns,
                ));
            }
            ir::IrItem::PureFn(function) => {
                let param_schema_vars = schema_pointer_var_ids(&function.body, &function.params);
                let symbolic_runtime_features = body_symbolic_runtime_features(
                    &function.body,
                    &param_schema_vars,
                    type_layouts,
                    &function.params,
                    cell_type_kinds,
                    function.return_type.as_ref(),
                );
                let fail_closed_runtime_features = body_fail_closed_runtime_features(
                    &function.body,
                    &param_schema_vars,
                    type_layouts,
                    &function.params,
                    cell_type_kinds,
                    function.return_type.as_ref(),
                    pure_const_returns,
                );
                let ckb_runtime_features = body_ckb_runtime_features(&function.name, &function.body, cell_type_kinds, type_layouts);
                let ckb_runtime_accesses = body_ckb_runtime_accesses(&function.name, &function.body, cell_type_kinds, type_layouts);
                obligations.extend(body_verifier_obligations(
                    "fn",
                    &function.name,
                    &function.body,
                    &symbolic_runtime_features,
                    &fail_closed_runtime_features,
                    &ckb_runtime_features,
                    &ckb_runtime_accesses,
                    type_layouts,
                    &function.params,
                    lifecycle_states,
                    cell_type_kinds,
                    function.return_type.as_ref(),
                    pure_const_returns,
                ));
            }
            ir::IrItem::Lock(lock) => {
                let param_schema_vars = schema_pointer_var_ids(&lock.body, &lock.params);
                let symbolic_runtime_features =
                    body_symbolic_runtime_features(&lock.body, &param_schema_vars, type_layouts, &lock.params, cell_type_kinds, None);
                let fail_closed_runtime_features = body_fail_closed_runtime_features(
                    &lock.body,
                    &param_schema_vars,
                    type_layouts,
                    &lock.params,
                    cell_type_kinds,
                    None,
                    pure_const_returns,
                );
                let ckb_runtime_features = body_ckb_runtime_features(&lock.name, &lock.body, cell_type_kinds, type_layouts);
                let ckb_runtime_accesses = body_ckb_runtime_accesses(&lock.name, &lock.body, cell_type_kinds, type_layouts);
                obligations.extend(body_verifier_obligations(
                    "lock",
                    &lock.name,
                    &lock.body,
                    &symbolic_runtime_features,
                    &fail_closed_runtime_features,
                    &ckb_runtime_features,
                    &ckb_runtime_accesses,
                    type_layouts,
                    &lock.params,
                    lifecycle_states,
                    cell_type_kinds,
                    None,
                    pure_const_returns,
                ));
            }
            ir::IrItem::TypeDef(_) => {}
        }
    }
    obligations
}

fn module_pool_primitive_metadata(
    ir: &ir::IrModule,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<PoolPrimitiveMetadata> {
    let mut pool_primitives = Vec::new();
    for item in &ir.items {
        match item {
            ir::IrItem::Action(action) => {
                pool_primitives.extend(body_pool_primitive_metadata(
                    "action",
                    &action.name,
                    &action.body,
                    &action.params,
                    type_layouts,
                    cell_type_kinds,
                    pure_const_returns,
                ));
            }
            ir::IrItem::PureFn(function) => {
                pool_primitives.extend(body_pool_primitive_metadata(
                    "fn",
                    &function.name,
                    &function.body,
                    &function.params,
                    type_layouts,
                    cell_type_kinds,
                    pure_const_returns,
                ));
            }
            ir::IrItem::Lock(lock) => {
                pool_primitives.extend(body_pool_primitive_metadata(
                    "lock",
                    &lock.name,
                    &lock.body,
                    &lock.params,
                    type_layouts,
                    cell_type_kinds,
                    pure_const_returns,
                ));
            }
            ir::IrItem::TypeDef(_) => {}
        }
    }
    pool_primitives
}

#[allow(clippy::too_many_arguments)]
fn body_verifier_obligations(
    scope_kind: &str,
    name: &str,
    body: &ir::IrBody,
    symbolic_runtime_features: &[String],
    fail_closed_runtime_features: &[String],
    ckb_runtime_features: &[String],
    ckb_runtime_accesses: &[CkbRuntimeAccessMetadata],
    type_layouts: &MetadataTypeLayouts,
    params: &[ir::IrParam],
    lifecycle_states: &HashMap<String, Vec<String>>,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    return_type: Option<&ir::IrType>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<VerifierObligationMetadata> {
    let scope = format!("{}:{}", scope_kind, name);
    let fail_closed = fail_closed_runtime_features.iter().cloned().collect::<BTreeSet<_>>();
    let ckb_features = ckb_runtime_features.iter().cloned().collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut obligations = Vec::new();

    for feature in ckb_runtime_features {
        push_verifier_obligation(
            &mut obligations,
            &mut seen,
            &scope,
            "ckb-runtime",
            feature,
            "ckb-runtime",
            "Requires the CKB-style transaction context and syscall ABI during verification",
        );
    }

    for access in ckb_runtime_accesses {
        push_verifier_obligation(
            &mut obligations,
            &mut seen,
            &scope,
            "cell-access",
            &format!("{}:{}#{}", access.operation, access.source, access.index),
            "ckb-runtime",
            &format!("{} {} from {}#{} bound to {}", access.syscall, access.operation, access.source, access.index, access.binding),
        );
    }

    for check in body_static_resource_operation_checks(body) {
        push_verifier_obligation(
            &mut obligations,
            &mut seen,
            &scope,
            "resource-operation",
            &check.feature,
            "checked-static",
            &check.detail,
        );
    }

    for check in
        body_transaction_resource_obligations(name, body, type_layouts, params, lifecycle_states, cell_type_kinds, pure_const_returns)
    {
        push_verifier_obligation(&mut obligations, &mut seen, &scope, check.category, &check.feature, check.status, &check.detail);
    }

    for check in body_linear_collection_obligations(body, return_type, cell_type_kinds) {
        push_verifier_obligation(&mut obligations, &mut seen, &scope, check.category, &check.feature, check.status, &check.detail);
    }

    for check in body_mutable_cell_state_obligations(body, params, cell_type_kinds, type_layouts) {
        push_verifier_obligation(&mut obligations, &mut seen, &scope, check.category, &check.feature, check.status, &check.detail);
    }

    let pool_primitives =
        body_pool_primitive_metadata(scope_kind, name, body, params, type_layouts, cell_type_kinds, pure_const_returns);
    for check in body_pool_primitive_obligations(&pool_primitives) {
        push_verifier_obligation(&mut obligations, &mut seen, &scope, check.category, &check.feature, check.status, &check.detail);
    }

    for feature in symbolic_runtime_features {
        if fail_closed.contains(feature) {
            push_verifier_obligation(
                &mut obligations,
                &mut seen,
                &scope,
                "runtime-fail-closed",
                feature,
                "fail-closed",
                "Generated code rejects this path instead of accepting an unimplemented symbolic runtime operation",
            );
        } else if !ckb_features.contains(feature) {
            push_verifier_obligation(
                &mut obligations,
                &mut seen,
                &scope,
                "standalone-elf-limitation",
                feature,
                "unsupported-standalone",
                "This source-level feature prevents standalone pure-ELF compatibility; audit the CKB-runtime path and emitted access summary",
            );
        }
    }

    for feature in fail_closed_runtime_features {
        push_verifier_obligation(
            &mut obligations,
            &mut seen,
            &scope,
            "runtime-fail-closed",
            feature,
            "fail-closed",
            "Generated code rejects this path instead of accepting an unimplemented runtime operation",
        );
    }

    for check in body_lifecycle_transition_checks(body, lifecycle_states, type_layouts, params, pure_const_returns) {
        push_verifier_obligation(
            &mut obligations,
            &mut seen,
            &scope,
            "lifecycle-transition",
            &format!("{}.state", check.feature),
            &check.status,
            &check.detail,
        );
    }

    obligations
}

struct StaticResourceOperationCheck {
    feature: String,
    detail: String,
}

struct TransactionResourceObligation {
    category: &'static str,
    feature: String,
    status: &'static str,
    detail: String,
}

fn body_static_resource_operation_checks(body: &ir::IrBody) -> Vec<StaticResourceOperationCheck> {
    let mut checks = Vec::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::Transfer { operand, .. } => {
                    if let Some(type_name) = operand_named_type_name(operand) {
                        checks.push(StaticResourceOperationCheck {
                            feature: format!("transfer:{}", type_name),
                            detail: format!(
                                "Type checker verified '{}' declares transfer capability and the source value is linearly consumed; runtime output/lock verification remains a separate lowering obligation",
                                type_name
                            ),
                        });
                    }
                }
                ir::IrInstruction::Destroy { operand } => {
                    if let Some(type_name) = operand_named_type_name(operand) {
                        checks.push(StaticResourceOperationCheck {
                            feature: format!("destroy:{}", type_name),
                            detail: format!(
                                "Type checker verified '{}' declares destroy capability and the source value is marked destroyed; transaction-level absence of replacement outputs remains a runtime/protocol obligation",
                                type_name
                            ),
                        });
                    }
                }
                ir::IrInstruction::Claim { receipt, .. } => {
                    if let Some(type_name) = operand_named_type_name(receipt) {
                        checks.push(StaticResourceOperationCheck {
                            feature: format!("claim:{}", type_name),
                            detail: format!(
                                "Type checker verified '{}' is a receipt value and the receipt is linearly consumed; witness/time-lock claim conditions remain runtime/protocol obligations",
                                type_name
                            ),
                        });
                    }
                }
                ir::IrInstruction::Settle { operand, .. } => {
                    if let Some(type_name) = operand_named_type_name(operand) {
                        checks.push(StaticResourceOperationCheck {
                            feature: format!("settle:{}", type_name),
                            detail: format!(
                                "Type checker verified '{}' is a cell-backed linear value and settle consumes it; finalization invariants remain runtime/protocol obligations",
                                type_name
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }
    checks
}

fn body_transaction_resource_obligations(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    params: &[ir::IrParam],
    lifecycle_states: &HashMap<String, Vec<String>>,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<TransactionResourceObligation> {
    let param_schema_vars = schema_pointer_var_ids(body, params);
    let availability = metadata_prelude_availability(body, &param_schema_vars, type_layouts, params, pure_const_returns);
    let mut checks = Vec::new();
    let mut output_index = 0usize;
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::Consume { operand } => {
                    if let Some(check) = operation_input_data_obligation(body, "consume", operand) {
                        checks.push(check);
                    }
                }
                ir::IrInstruction::Create { pattern, .. } => {
                    if let Some(check) = create_output_verification_obligation(pattern, type_layouts, &availability) {
                        checks.push(check);
                    }
                    output_index += 1;
                }
                ir::IrInstruction::Transfer { operand, .. } => {
                    if let Some(check) = operation_input_data_obligation(body, "transfer", operand) {
                        checks.push(check);
                    }
                    if let Some(type_name) = operand_named_type_name(operand) {
                        let output_relation_checked =
                            transfer_output_relation_is_checked(body, type_layouts, &availability, output_index, &type_name);
                        let lock_rebinding_checked = transfer_lock_rebinding_is_checked(body, &availability, &type_name);
                        let output_relation_detail =
                            if output_relation_checked { "; transfer-output-relation=checked-runtime" } else { "" };
                        let lock_rebinding_detail = if lock_rebinding_checked {
                            "; transfer-lock-rebinding=checked-runtime; transfer-destination-address-binding=checked-runtime"
                        } else {
                            ""
                        };
                        checks.push(TransactionResourceObligation {
                            category: "transaction-invariant",
                            feature: format!("transfer-output:{}", type_name),
                            status: if output_relation_checked { "checked-runtime" } else { "runtime-required" },
                            detail: if output_relation_checked {
                                format!(
                                    "Compiler-emitted runtime verifier checks the consumed '{}' cell data is preserved in the transfer-created output and that the output lock is rebound to the transfer destination{}{}",
                                    type_name, output_relation_detail, lock_rebinding_detail
                                )
                            } else {
                                format!(
                                    "Runtime verifier must prove the consumed '{}' cell data is preserved in exactly the intended output and that the output lock is rebound to the transfer destination{}{}",
                                    type_name, output_relation_detail, lock_rebinding_detail
                                )
                            },
                        });
                    }
                    output_index += 1;
                }
                ir::IrInstruction::Destroy { operand } => {
                    if let Some(check) = operation_input_data_obligation(body, "destroy", operand) {
                        checks.push(check);
                    }
                    if let Some(type_name) = operand_named_type_name(operand) {
                        let binding = operand_var_name(operand).unwrap_or(&type_name);
                        let scan_detail = if destroy_group_output_absence_scan_is_checked(body, &type_name, binding) {
                            "; destroy-output-absence=checked-runtime; destroy-output-scan=checked-runtime"
                        } else {
                            ""
                        };
                        checks.push(TransactionResourceObligation {
                            category: "transaction-invariant",
                            feature: format!("destroy-output-scan:{}", type_name),
                            status: if scan_detail.is_empty() { "runtime-required" } else { "checked-runtime" },
                            detail: format!(
                                "Runtime verifier must scan transaction outputs to prove the destroyed '{}' instance is not recreated by the same state transition{}",
                                type_name, scan_detail
                            ),
                        });
                    }
                }
                ir::IrInstruction::Claim { dest, receipt } => {
                    if let Some(check) = operation_input_data_obligation(body, "claim", receipt) {
                        checks.push(check);
                    }
                    if let Some(type_name) = operand_named_type_name(receipt) {
                        let conditions_checked =
                            claim_conditions_are_checked(name, body, type_layouts, cell_type_kinds, "claim", receipt, &type_name);
                        checks.push(TransactionResourceObligation {
                            category: "transaction-invariant",
                            feature: format!("claim-conditions:{}", type_name),
                            status: if conditions_checked { "checked-runtime" } else { "runtime-required" },
                            detail: transaction_claim_condition_detail(
                                body,
                                type_layouts,
                                cell_type_kinds,
                                name,
                                "claim",
                                receipt,
                                &type_name,
                                conditions_checked,
                            ),
                        });
                    }
                    if let Some(type_name) = named_type_name(&dest.ty) {
                        checks.push(transaction_output_obligation(
                            body,
                            type_layouts,
                            &availability,
                            "claim",
                            &dest.name,
                            type_name,
                            format!(
                                "Compiler-emitted runtime verifier checks the claim-created '{}' output fields that are statically bound to the consumed receipt; claim-output-relation=checked-runtime; witness/time-lock claim conditions remain separate runtime obligations",
                                type_name
                            ),
                            format!(
                                "Runtime verifier must prove claim creates the declared '{}' output cell and binds its fields to the consumed receipt semantics; claim-output-relation=runtime-required",
                                type_name
                            ),
                        ));
                    }
                    output_index += 1;
                }
                ir::IrInstruction::Settle { dest, operand } => {
                    if let Some(check) = operation_input_data_obligation(body, "settle", operand) {
                        checks.push(check);
                    }
                    if let Some(type_name) = operand_named_type_name(operand) {
                        let finalization_checked = settle_finalization_is_checked(
                            body,
                            type_layouts,
                            &availability,
                            lifecycle_states,
                            output_index,
                            &type_name,
                        );
                        checks.push(TransactionResourceObligation {
                            category: "transaction-invariant",
                            feature: format!("settle-finalization:{}", type_name),
                            status: if finalization_checked { "checked-runtime" } else { "runtime-required" },
                            detail: transaction_condition_detail(
                                body,
                                type_layouts,
                                &availability,
                                lifecycle_states,
                                "settle",
                                operand,
                                &type_name,
                                finalization_checked,
                            ),
                        });
                    }
                    if let Some(type_name) = named_type_name(&dest.ty) {
                        checks.push(transaction_output_obligation(
                            body,
                            type_layouts,
                            &availability,
                            "settle",
                            &dest.name,
                            type_name,
                            format!(
                                "Compiler-emitted runtime verifier checks the settle-created '{}' output fields that are statically bound to the consumed value; settle-output-relation=checked-runtime; finalization invariants remain separate runtime obligations",
                                type_name
                            ),
                            format!(
                                "Runtime verifier must prove settle creates the finalized '{}' output cell and binds verifier-covered fields to the consumed value semantics; settle-output-relation=runtime-required",
                                type_name
                            ),
                        ));
                    }
                    output_index += 1;
                }
                _ => {}
            }
        }
    }
    checks.extend(read_ref_cell_dep_data_obligations(body));
    checks.extend(body_resource_conservation_obligations(name, body, type_layouts, &availability, params, cell_type_kinds));
    checks.extend(body_receipt_claim_flow_obligations(name, body, type_layouts, cell_type_kinds));
    checks
}

fn operation_input_data_obligation(
    body: &ir::IrBody,
    operation: &'static str,
    operand: &ir::IrOperand,
) -> Option<TransactionResourceObligation> {
    let type_name = operand_named_type_name(operand)?;
    let binding = operand_var_name(operand).unwrap_or(type_name.as_str());
    let pattern = body.consume_set.iter().find(|pattern| pattern.operation == operation && pattern.binding == binding)?;
    pattern.type_hash?;
    let component = format!("{operation}-input-data");
    Some(TransactionResourceObligation {
        category: "transaction-invariant",
        feature: format!("{operation}-input:{}:{}", type_name, binding),
        status: "checked-runtime",
        detail: format!(
            "Compiler-emitted runtime verifier loads '{}' Input cell data for '{}' through LOAD_CELL Source::Input; {}=checked-runtime",
            type_name, binding, component
        ),
    })
}

fn read_ref_cell_dep_data_obligations(body: &ir::IrBody) -> Vec<TransactionResourceObligation> {
    body.read_refs
        .iter()
        .enumerate()
        .filter(|(_, pattern)| pattern.operation == "read_ref" && pattern.type_hash.is_some())
        .map(|(index, pattern)| TransactionResourceObligation {
            category: "transaction-invariant",
            feature: format!("read-ref:{}#{}", pattern.binding, index),
            status: "checked-runtime",
            detail: format!(
                "Compiler-emitted runtime verifier loads read_ref CellDep data for '{}' through LOAD_CELL Source::CellDep index {}; read-ref-cell-dep-data=checked-runtime",
                pattern.binding, index
            ),
        })
        .collect()
}

fn create_output_verification_obligation(
    pattern: &ir::CreatePattern,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> Option<TransactionResourceObligation> {
    if pattern.operation != "create" {
        return None;
    }
    let fields_checked = metadata_can_verify_create_output_fields(pattern, type_layouts, availability);
    let lock_checked = metadata_can_verify_output_lock(pattern, availability);
    let fields_status = if fields_checked { "checked-runtime" } else { "runtime-required" };
    let lock_status = match &pattern.lock {
        Some(_) if lock_checked => "checked-runtime",
        Some(_) => "runtime-required",
        None => "not-required",
    };
    let status = if fields_checked && lock_checked { "checked-runtime" } else { "runtime-required" };
    Some(TransactionResourceObligation {
        category: "transaction-invariant",
        feature: format!("create-output:{}:{}", pattern.ty, pattern.binding),
        status,
        detail: if status == "checked-runtime" {
            format!(
                "Compiler-emitted runtime verifier checks create output '{}' bound to '{}' has verifier-covered fields{}; create-output-fields={}; create-output-lock={}",
                pattern.ty,
                pattern.binding,
                if pattern.lock.is_some() { " and lock binding" } else { "" },
                fields_status,
                lock_status
            )
        } else {
            format!(
                "Runtime verifier must prove create output '{}' bound to '{}' has verifier-covered fields and any explicit lock binding; create-output-fields={}; create-output-lock={}",
                pattern.ty, pattern.binding, fields_status, lock_status
            )
        },
    })
}

fn body_linear_collection_obligations(
    body: &ir::IrBody,
    return_type: Option<&ir::IrType>,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> Vec<TransactionResourceObligation> {
    let mut operations_by_type = BTreeMap::<String, BTreeSet<&'static str>>::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::CollectionPush { value, .. } => {
                    for type_name in ir_operand_cell_backed_type_names(value, cell_type_kinds) {
                        operations_by_type.entry(type_name).or_default().insert("push");
                    }
                }
                ir::IrInstruction::CollectionExtend { slice, .. } => {
                    for type_name in ir_operand_cell_backed_collection_type_names(slice, cell_type_kinds) {
                        operations_by_type.entry(type_name).or_default().insert("extend");
                    }
                }
                _ => {}
            }
        }
    }

    if let Some(return_type) = return_type {
        for type_name in ir_type_cell_backed_collection_type_names(return_type, cell_type_kinds) {
            operations_by_type.entry(type_name).or_default().insert("return");
        }
    }

    operations_by_type
        .into_iter()
        .map(|(type_name, operations)| {
            let operations = operations.into_iter().collect::<Vec<_>>().join("+");
            TransactionResourceObligation {
                category: "transaction-invariant",
                feature: format!("linear-collection:{}", type_name),
                status: "runtime-required",
                detail: format!(
                    "Cell-backed collection carrying '{}' crosses {} path(s); linear-collection-ownership=runtime-required; generated code fails closed through cell-backed-collection-* features until a real linear collection ownership model exists",
                    type_name, operations
                ),
            }
        })
        .collect()
}

#[derive(Debug, Clone)]
struct MetadataFieldAlias {
    root_id: usize,
    field: String,
}

#[derive(Debug, Clone)]
enum MetadataU64Source {
    Field(MetadataFieldAlias),
    Add(Box<MetadataU64Source>, Box<MetadataU64Source>),
    Sub(Box<MetadataU64Source>, ir::IrOperand),
}

fn body_resource_conservation_obligations(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    params: &[ir::IrParam],
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> Vec<TransactionResourceObligation> {
    let resource_param_types = params
        .iter()
        .filter_map(|param| {
            let type_name = named_type_name(&param.ty)?;
            (cell_type_kinds.get(type_name) == Some(&ir::IrTypeKind::Resource)).then_some((param.binding.id, type_name.to_string()))
        })
        .collect::<HashMap<_, _>>();
    if resource_param_types.is_empty() {
        return Vec::new();
    }

    let mut consumed_params: HashMap<String, Vec<ir::IrVar>> = HashMap::new();
    let mut created_outputs: HashMap<String, Vec<ir::CreatePattern>> = HashMap::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::Consume { operand: ir::IrOperand::Var(var) } => {
                    if let Some(type_name) = resource_param_types.get(&var.id) {
                        consumed_params.entry(type_name.clone()).or_default().push(var.clone());
                    }
                }
                ir::IrInstruction::Create { pattern, .. }
                    if pattern.operation == "create" && cell_type_kinds.get(&pattern.ty) == Some(&ir::IrTypeKind::Resource) =>
                {
                    created_outputs.entry(pattern.ty.clone()).or_default().push(pattern.clone());
                }
                _ => {}
            }
        }
    }

    let type_names = consumed_params.keys().chain(created_outputs.keys()).cloned().collect::<BTreeSet<_>>();
    type_names
        .iter()
        .filter_map(|type_name| {
            let consumed = consumed_params.get(type_name).cloned().unwrap_or_default();
            let created = created_outputs.get(type_name).cloned().unwrap_or_default();
            if consumed.is_empty() || created.is_empty() {
                return None;
            }
            let fields = type_layouts
                .get(type_name)
                .map(|layouts| layouts.keys().cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "<unknown>".to_string());
            let checked_detail =
                resource_conservation_checked_detail(name, body, type_layouts, availability, type_name, &consumed, &created, &fields);
            Some(TransactionResourceObligation {
                category: "transaction-invariant",
                feature: format!("resource-conservation:{}", type_name),
                status: if checked_detail.is_some() { "checked-runtime" } else { "runtime-required" },
                detail: checked_detail.unwrap_or_else(|| {
                    format!(
                        "Runtime verifier must prove '{}' resource conservation across {} consumed Input cell(s) and {} created Output cell(s); resource-conservation=runtime-required",
                        type_name,
                        consumed.len(),
                        created.len()
                    )
                }),
            })
        })
        .collect()
}

fn resource_conservation_checked_detail(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    type_name: &str,
    consumed: &[ir::IrVar],
    created: &[ir::CreatePattern],
    fields: &str,
) -> Option<String> {
    if consumed.len() == 1
        && created.len() == 1
        && resource_conservation_pair_is_checked(body, type_layouts, availability, &consumed[0], &created[0])
    {
        return Some(format!(
            "Compiler-emitted runtime verifier checks one consumed '{}' Input is preserved into one created Output; resource-conservation=checked-runtime; fields: {}",
            type_name, fields
        ));
    }

    if resource_conservation_amount_merge_is_checked(body, type_layouts, availability, consumed, created) {
        return Some(format!(
            "Compiler-emitted runtime verifier checks {} consumed '{}' Inputs are merged into one created Output by a verifier-recomputed u64 amount sum; resource-conservation=checked-runtime; fields: amount",
            consumed.len(),
            type_name
        ));
    }

    if resource_conservation_amount_split_is_checked(body, type_layouts, availability, consumed, created) {
        return Some(format!(
            "Compiler-emitted runtime verifier checks one consumed '{}' Input is split across {} created Outputs by a verifier-recomputed u64 amount subtraction with matching split outputs; resource-conservation=checked-runtime; fields: amount",
            type_name,
            created.len()
        ));
    }

    if resource_conservation_amm_swap_is_checked(name, body, type_layouts, availability, type_name, consumed, created) {
        return Some(format!(
            "Compiler-emitted AMM verifier checks one consumed '{}' input is exchanged for one created output through Pool symbol admission, fee accounting, and constant-product pricing; resource-conservation=checked-runtime; fields: amount, symbol",
            type_name
        ));
    }

    None
}

fn resource_conservation_pair_is_checked(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    consumed: &ir::IrVar,
    created: &ir::CreatePattern,
) -> bool {
    if !metadata_can_verify_create_output_fields(created, type_layouts, availability)
        || !metadata_can_verify_output_lock(created, availability)
    {
        return false;
    }
    let aliases = metadata_field_aliases(body);
    created.fields.iter().all(|(field, operand)| {
        let ir::IrOperand::Var(var) = operand else {
            return false;
        };
        aliases.get(&var.id).is_some_and(|alias| alias.root_id == consumed.id && alias.field == field.as_str())
    })
}

fn resource_conservation_amount_merge_is_checked(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    consumed: &[ir::IrVar],
    created: &[ir::CreatePattern],
) -> bool {
    if consumed.len() < 2 || created.len() != 1 {
        return false;
    }
    let created = &created[0];
    if !metadata_can_verify_create_output_fields(created, type_layouts, availability)
        || !metadata_can_verify_output_lock(created, availability)
        || !resource_conservation_has_u64_amount_field(type_layouts, &created.ty)
    {
        return false;
    }
    let Some((_, operand)) = created.fields.iter().find(|(field, _)| field == "amount") else {
        return false;
    };
    let ir::IrOperand::Var(var) = operand else {
        return false;
    };

    let sources = metadata_u64_sources(body);
    let Some(source) = sources.get(&var.id) else {
        return false;
    };
    let mut source_roots = Vec::new();
    if !metadata_u64_source_collect_field_roots(source, "amount", &mut source_roots) {
        return false;
    }
    source_roots.sort_unstable();
    let mut consumed_roots = consumed.iter().map(|var| var.id).collect::<Vec<_>>();
    consumed_roots.sort_unstable();
    source_roots == consumed_roots && resource_conservation_created_identity_fields_are_checked(body, consumed, created)
}

fn resource_conservation_amount_split_is_checked(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    consumed: &[ir::IrVar],
    created: &[ir::CreatePattern],
) -> bool {
    if consumed.len() != 1 || created.len() < 2 {
        return false;
    }
    if !resource_conservation_has_single_u64_amount_field(type_layouts, &created[0].ty) {
        return false;
    }
    if !created.iter().all(|pattern| {
        metadata_can_verify_create_output_fields(pattern, type_layouts, availability)
            && metadata_can_verify_output_lock(pattern, availability)
            && resource_conservation_has_single_u64_amount_field(type_layouts, &pattern.ty)
            && pattern.fields.len() == 1
            && pattern.fields.first().is_some_and(|(field, _)| field == "amount")
    }) {
        return false;
    }

    let sources = metadata_u64_sources(body);
    let amount_operands = created.iter().filter_map(|pattern| pattern.fields.first().map(|(_, operand)| operand)).collect::<Vec<_>>();
    let mut split_remainders = Vec::new();
    for (index, operand) in amount_operands.iter().enumerate() {
        let Some(source) = metadata_u64_source_for_operand(operand, &sources) else {
            continue;
        };
        let Some(subtrahends) = metadata_u64_source_collect_amount_split_subtrahends(&source, consumed[0].id) else {
            continue;
        };
        split_remainders.push((index, subtrahends));
    }
    if split_remainders.len() != 1 {
        return false;
    }

    let (remainder_index, subtrahends) = split_remainders.remove(0);
    let mut unmatched_outputs = amount_operands
        .iter()
        .enumerate()
        .filter_map(|(index, operand)| (index != remainder_index).then_some((*operand).clone()))
        .collect::<Vec<_>>();
    if unmatched_outputs.len() != subtrahends.len() {
        return false;
    }
    for subtrahend in subtrahends {
        let Some(position) = unmatched_outputs.iter().position(|operand| ir_operands_same_verifier_source(operand, &subtrahend))
        else {
            return false;
        };
        unmatched_outputs.remove(position);
    }
    unmatched_outputs.is_empty()
}

fn resource_conservation_amm_swap_is_checked(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    type_name: &str,
    consumed: &[ir::IrVar],
    created: &[ir::CreatePattern],
) -> bool {
    if name != "swap_a_for_b" || type_name != "Token" || consumed.len() != 1 || created.len() != 1 {
        return false;
    }
    let created = &created[0];
    if created.ty != "Token"
        || !metadata_can_verify_create_output_fields(created, type_layouts, availability)
        || !metadata_can_verify_output_lock(created, availability)
    {
        return false;
    }
    let Some(pool_pattern) = body.mutate_set.iter().find(|pattern| pattern.binding == "pool" && pattern.ty == "Pool") else {
        return false;
    };
    pool_swap_a_for_b_admission_is_checked(
        name,
        pool_pattern,
        body,
        &pool_checked_invariant_guard_names(name, "mutation-invariants", body_assert_invariant_count(body)),
        type_layouts,
        availability,
    ) && pool_swap_a_for_b_fee_accounting_is_checked(name, pool_pattern, body, type_layouts)
        && pool_swap_a_for_b_constant_product_pricing_is_checked(name, pool_pattern, body, type_layouts, availability)
}

fn resource_conservation_has_single_u64_amount_field(type_layouts: &MetadataTypeLayouts, type_name: &str) -> bool {
    let Some(layouts) = type_layouts.get(type_name) else {
        return false;
    };
    if layouts.len() != 1 {
        return false;
    }
    layouts.get("amount").is_some_and(|layout| layout.ty == ir::IrType::U64 && metadata_layout_fixed_scalar_width(layout) == Some(8))
}

fn resource_conservation_has_u64_amount_field(type_layouts: &MetadataTypeLayouts, type_name: &str) -> bool {
    type_layouts
        .get(type_name)
        .and_then(|layouts| layouts.get("amount"))
        .is_some_and(|layout| layout.ty == ir::IrType::U64 && metadata_layout_fixed_scalar_width(layout) == Some(8))
}

fn resource_conservation_created_identity_fields_are_checked(
    body: &ir::IrBody,
    consumed: &[ir::IrVar],
    created: &ir::CreatePattern,
) -> bool {
    let aliases = metadata_field_aliases(body);
    let equalities = metadata_asserted_field_equalities(body, &aliases);
    let consumed_roots = consumed.iter().map(|var| var.id).collect::<BTreeSet<_>>();

    created.fields.iter().all(|(field, operand)| {
        if field == "amount" {
            return true;
        }
        let ir::IrOperand::Var(var) = operand else {
            return false;
        };
        let Some(alias) = aliases.get(&var.id) else {
            return false;
        };
        if alias.field != *field || !consumed_roots.contains(&alias.root_id) {
            return false;
        }
        consumed.iter().all(|root| {
            root.id == alias.root_id || equalities.contains(&canonical_metadata_field_equality(alias.root_id, field, root.id, field))
        })
    })
}

fn metadata_asserted_field_equalities(
    body: &ir::IrBody,
    aliases: &HashMap<usize, MetadataFieldAlias>,
) -> BTreeSet<(usize, String, usize, String)> {
    let mut eq_by_var = HashMap::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            if let ir::IrInstruction::Binary {
                dest,
                op: ast::BinaryOp::Eq,
                left: ir::IrOperand::Var(left),
                right: ir::IrOperand::Var(right),
            } = instruction
            {
                let Some(left_alias) = aliases.get(&left.id) else {
                    continue;
                };
                let Some(right_alias) = aliases.get(&right.id) else {
                    continue;
                };
                eq_by_var.insert(
                    dest.id,
                    canonical_metadata_field_equality(left_alias.root_id, &left_alias.field, right_alias.root_id, &right_alias.field),
                );
            }
        }
    }

    let mut asserted = BTreeSet::new();
    for block in &body.blocks {
        let ir::IrTerminator::Branch { cond: ir::IrOperand::Var(cond), else_block, .. } = &block.terminator else {
            continue;
        };
        if !block_returns_error(body, *else_block) {
            continue;
        }
        if let Some(equality) = eq_by_var.get(&cond.id) {
            asserted.insert(equality.clone());
        }
    }
    asserted
}

fn canonical_metadata_field_equality(
    left_root: usize,
    left_field: &str,
    right_root: usize,
    right_field: &str,
) -> (usize, String, usize, String) {
    let left = (left_root, left_field.to_string());
    let right = (right_root, right_field.to_string());
    if left <= right {
        (left.0, left.1, right.0, right.1)
    } else {
        (right.0, right.1, left.0, left.1)
    }
}

fn block_returns_error(body: &ir::IrBody, block_id: ir::BlockId) -> bool {
    body.blocks.iter().find(|block| block.id == block_id).is_some_and(
        |block| matches!(block.terminator, ir::IrTerminator::Return(Some(ir::IrOperand::Const(ir::IrConst::U64(code)))) if code != 0),
    )
}

fn metadata_field_aliases(body: &ir::IrBody) -> HashMap<usize, MetadataFieldAlias> {
    let mut aliases = HashMap::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::FieldAccess { dest, obj: ir::IrOperand::Var(obj), field } => {
                    aliases.insert(dest.id, MetadataFieldAlias { root_id: obj.id, field: field.clone() });
                }
                ir::IrInstruction::Move { dest, src: ir::IrOperand::Var(src) } => {
                    if let Some(alias) = aliases.get(&src.id).cloned() {
                        aliases.insert(dest.id, alias);
                    }
                }
                _ => {}
            }
        }
    }
    aliases
}

fn metadata_u64_sources(body: &ir::IrBody) -> HashMap<usize, MetadataU64Source> {
    let mut sources = HashMap::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::FieldAccess { dest, obj: ir::IrOperand::Var(obj), field } if dest.ty == ir::IrType::U64 => {
                    sources.insert(dest.id, MetadataU64Source::Field(MetadataFieldAlias { root_id: obj.id, field: field.clone() }));
                }
                ir::IrInstruction::Binary { dest, op: ast::BinaryOp::Add, left, right } if dest.ty == ir::IrType::U64 => {
                    if let (Some(left), Some(right)) =
                        (metadata_u64_source_for_operand(left, &sources), metadata_u64_source_for_operand(right, &sources))
                    {
                        sources.insert(dest.id, MetadataU64Source::Add(Box::new(left), Box::new(right)));
                    }
                }
                ir::IrInstruction::Binary { dest, op: ast::BinaryOp::Sub, left, right } if dest.ty == ir::IrType::U64 => {
                    if let Some(left) = metadata_u64_source_for_operand(left, &sources) {
                        sources.insert(dest.id, MetadataU64Source::Sub(Box::new(left), right.clone()));
                    }
                }
                ir::IrInstruction::Move { dest, src } if dest.ty == ir::IrType::U64 => {
                    if let Some(source) = metadata_u64_source_for_operand(src, &sources) {
                        sources.insert(dest.id, source);
                    }
                }
                _ => {}
            }
        }
    }
    sources
}

fn metadata_u64_source_for_operand(operand: &ir::IrOperand, sources: &HashMap<usize, MetadataU64Source>) -> Option<MetadataU64Source> {
    match operand {
        ir::IrOperand::Var(var) => sources.get(&var.id).cloned(),
        ir::IrOperand::Const(_) => None,
    }
}

fn metadata_u64_source_collect_field_roots(source: &MetadataU64Source, field: &str, roots: &mut Vec<usize>) -> bool {
    match source {
        MetadataU64Source::Field(alias) if alias.field == field => {
            roots.push(alias.root_id);
            true
        }
        MetadataU64Source::Field(_) => false,
        MetadataU64Source::Add(left, right) => {
            metadata_u64_source_collect_field_roots(left, field, roots) && metadata_u64_source_collect_field_roots(right, field, roots)
        }
        MetadataU64Source::Sub(_, _) => false,
    }
}

fn metadata_u64_source_collect_amount_split_subtrahends(
    source: &MetadataU64Source,
    consumed_root: usize,
) -> Option<Vec<ir::IrOperand>> {
    match source {
        MetadataU64Source::Field(alias) if alias.root_id == consumed_root && alias.field == "amount" => Some(Vec::new()),
        MetadataU64Source::Sub(left, right) => {
            let mut subtrahends = metadata_u64_source_collect_amount_split_subtrahends(left, consumed_root)?;
            subtrahends.push(right.clone());
            Some(subtrahends)
        }
        MetadataU64Source::Field(_) | MetadataU64Source::Add(_, _) => None,
    }
}

fn body_receipt_claim_flow_obligations(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> Vec<TransactionResourceObligation> {
    let mut obligations = Vec::new();
    let source_invariant_count = body_assert_invariant_count(body);
    for block in &body.blocks {
        for instruction in &block.instructions {
            let ir::IrInstruction::Consume { operand } = instruction else {
                continue;
            };
            let Some(type_name) = operand_named_type_name(operand) else {
                continue;
            };
            if cell_type_kinds.get(type_name.as_str()) != Some(&ir::IrTypeKind::Receipt) {
                continue;
            }
            let checked_guards = receipt_claim_flow_checked_condition_guards(name, &type_name, source_invariant_count, body);
            if checked_guards.is_empty() {
                continue;
            }
            let binding = operand_var_name(operand).unwrap_or(type_name.as_str());
            let input_summary = transaction_condition_input_summary(body, type_layouts, "consume", binding, &type_name);
            let witness_domain_detail = if body.consume_set.iter().any(|pattern| {
                pattern.operation == "consume"
                    && pattern.binding == binding
                    && is_claim_witness_authorization_domain_check_target(name, pattern, cell_type_kinds, type_layouts)
            }) {
                let mut detail = ", claim-witness-format=checked-runtime, claim-authorization-domain=checked-runtime".to_string();
                if body.consume_set.iter().any(|pattern| {
                    pattern.operation == "consume"
                        && pattern.binding == binding
                        && is_claim_witness_signature_verification_check_target(name, pattern, cell_type_kinds, type_layouts)
                }) {
                    detail.push_str(", claim-witness-signature=checked-runtime, claim-signer-key-binding=checked-runtime");
                }
                detail
            } else if body.consume_set.iter().any(|pattern| {
                pattern.operation == "consume"
                    && pattern.binding == binding
                    && is_claim_input_lock_hash_binding_check_target(name, pattern, cell_type_kinds, type_layouts)
            }) {
                ", claim-input-lock-hash=checked-runtime, claim-lock-hash-field-binding=checked-runtime".to_string()
            } else if revoke_admin_authorization_is_checked(name, &type_name, body, type_layouts) {
                ", revoke-admin-config-binding=checked-runtime, revoke-admin-output-lock=checked-runtime".to_string()
            } else {
                String::new()
            };
            let conditions_checked =
                claim_conditions_are_checked(name, body, type_layouts, cell_type_kinds, "consume", operand, &type_name);
            obligations.push(TransactionResourceObligation {
                category: "transaction-invariant",
                feature: format!("claim-conditions:{}", type_name),
                status: if conditions_checked { "checked-runtime" } else { "runtime-required" },
                detail: format!(
                    "Source claim predicates are present in the fail-closed CFG as {}{}; runtime inputs: {}",
                    checked_guards.iter().map(|guard| format!("{}=checked-runtime", guard)).collect::<Vec<_>>().join(", "),
                    witness_domain_detail,
                    input_summary
                ),
            });
        }
    }
    obligations
}

fn claim_conditions_are_checked(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    operation: &str,
    operand: &ir::IrOperand,
    type_name: &str,
) -> bool {
    if !claim_source_predicates_are_checked(name, type_name, body) {
        return false;
    }
    let binding = operand_var_name(operand).unwrap_or(type_name);
    body.consume_set.iter().any(|pattern| {
        pattern.operation == operation
            && pattern.binding == binding
            && (is_claim_witness_signature_verification_check_target(name, pattern, cell_type_kinds, type_layouts)
                || is_claim_input_lock_hash_binding_check_target(name, pattern, cell_type_kinds, type_layouts)
                || revoke_admin_authorization_is_checked(name, type_name, body, type_layouts))
    })
}

fn revoke_admin_authorization_is_checked(name: &str, type_name: &str, body: &ir::IrBody, type_layouts: &MetadataTypeLayouts) -> bool {
    if name != "revoke_grant" || type_name != "VestingGrant" {
        return false;
    }
    let Some(config_fields) = type_layouts.get("VestingConfig") else {
        return false;
    };
    let Some(admin_layout) = config_fields.get("admin") else {
        return false;
    };
    if metadata_layout_fixed_byte_width(admin_layout) != Some(32) {
        return false;
    }
    body.read_refs.iter().any(|pattern| pattern.operation == "read_ref" && pattern.binding == "config")
        && body_assert_invariant_count(body) >= 3
}

fn claim_body_has_source_predicates(body: &ir::IrBody) -> bool {
    body_assert_invariant_count(body) > 0 || body_uses_current_daa_score(body)
}

fn claim_source_predicates_are_checked(name: &str, type_name: &str, body: &ir::IrBody) -> bool {
    if !claim_body_has_source_predicates(body) {
        return true;
    }
    let source_invariant_count = body_assert_invariant_count(body);
    let uses_daa = body_uses_current_daa_score(body);
    let checked_guards = receipt_claim_flow_checked_condition_guards(name, type_name, source_invariant_count, body);
    if checked_guards.is_empty() {
        return false;
    }
    if uses_daa && !checked_guards.contains(&"daa-cliff-reached") {
        return false;
    }
    if source_invariant_count > checked_guards.len() {
        return false;
    }
    true
}

fn receipt_claim_flow_checked_condition_guards(
    name: &str,
    type_name: &str,
    source_invariant_count: usize,
    body: &ir::IrBody,
) -> Vec<&'static str> {
    if name == "claim_vested" && type_name == "VestingGrant" && source_invariant_count >= 3 && body_uses_current_daa_score(body) {
        return vec!["daa-cliff-reached", "state-not-fully-claimed", "positive-claimable"];
    }
    // General case: any receipt claim that uses current_daa_score and has
    // assert_invariant conditions gets daa-cliff-reached=checked-runtime,
    // because the codegen emits a real LOAD_HEADER_BY_FIELD + slt comparison.
    if body_uses_current_daa_score(body) && source_invariant_count > 0 {
        let mut guards = vec!["daa-cliff-reached"];
        // Additional source invariants beyond the DAA cliff check are
        // also checked-runtime when the codegen emits them as Branch conditions.
        guards.extend(std::iter::repeat_n("source-invariant", source_invariant_count.saturating_sub(1)));
        return guards;
    }
    Vec::new()
}

fn body_uses_current_daa_score(body: &ir::IrBody) -> bool {
    body.blocks.iter().flat_map(|block| &block.instructions).any(|instruction| {
        matches!(
            instruction,
            ir::IrInstruction::Call {
                func,
                args,
                ..
            } if matches!(func.as_str(), "__env_current_daa_score" | "__env_current_timepoint") && args.is_empty()
        )
    })
}

fn operation_input_feature(feature: &str) -> Option<(&'static str, &str)> {
    if let Some(binding) = feature.strip_prefix("consume-input:") {
        Some(("consume", binding))
    } else if let Some(binding) = feature.strip_prefix("transfer-input:") {
        Some(("transfer", binding))
    } else if let Some(binding) = feature.strip_prefix("destroy-input:") {
        Some(("destroy", binding))
    } else if let Some(binding) = feature.strip_prefix("claim-input:") {
        Some(("claim", binding))
    } else {
        feature.strip_prefix("settle-input:").map(|binding| ("settle", binding))
    }
}

fn transaction_runtime_input_requirements_from_obligations(
    obligations: &[VerifierObligationMetadata],
) -> Vec<TransactionRuntimeInputRequirementMetadata> {
    let checked_transaction_invariants = obligations
        .iter()
        .filter(|obligation| obligation.category == "transaction-invariant" && obligation.status == "checked-runtime")
        .map(|obligation| format!("{}:{}", obligation.scope, obligation.feature))
        .collect::<BTreeSet<_>>();
    let mut requirements = Vec::new();
    for obligation in obligations {
        if let Some(binding) = mutable_state_obligation_binding(obligation) {
            if obligation.status == "runtime-required" {
                let field_equality_status = obligation_detail_status(obligation, "field equality");
                if field_equality_status.is_some_and(|status| status != "checked-runtime") {
                    requirements.push(transaction_runtime_input_requirement(
                        obligation,
                        "mutate-field-equality",
                        "runtime-required",
                        Some("mutable preserved-field equality is not fully verifier-covered"),
                        Some("state-field-equality-gap"),
                        "InputOutput",
                        binding,
                        Some("preserved-fields"),
                        "mutate-preserved-field-equality",
                        None,
                    ));
                }

                let field_transition_status = obligation_detail_status(obligation, "field transition");
                if field_transition_status.is_some_and(|status| status != "checked-runtime") {
                    requirements.push(transaction_runtime_input_requirement(
                        obligation,
                        "mutate-field-transition",
                        "runtime-required",
                        Some("mutable field transition formula is not fully verifier-covered"),
                        Some("state-transition-formula-gap"),
                        "InputOutput",
                        binding,
                        Some("transition-fields"),
                        "mutate-field-transition-policy",
                        None,
                    ));
                }
            }
            continue;
        }

        let include_checked_destroy_scan =
            obligation.status == "checked-runtime" && obligation.feature.starts_with("destroy-output-scan:");
        let include_checked_transfer_output =
            obligation.status == "checked-runtime" && obligation.feature.starts_with("transfer-output:");
        let include_checked_claim_output = obligation.status == "checked-runtime" && obligation.feature.starts_with("claim-output:");
        let include_checked_settle_output = obligation.status == "checked-runtime" && obligation.feature.starts_with("settle-output:");
        let include_checked_operation_input =
            obligation.status == "checked-runtime" && operation_input_feature(obligation.feature.as_str()).is_some();
        let include_checked_read_ref = obligation.status == "checked-runtime" && obligation.feature.starts_with("read-ref:");
        let include_checked_create_output = obligation.status == "checked-runtime" && obligation.feature.starts_with("create-output:");
        let include_checked_resource_conservation =
            obligation.status == "checked-runtime" && obligation.feature.starts_with("resource-conservation:");
        let include_checked_claim_conditions =
            obligation.status == "checked-runtime" && obligation.feature.starts_with("claim-conditions:");
        let include_checked_settle_finalization =
            obligation.status == "checked-runtime" && obligation.feature.starts_with("settle-finalization:");
        if obligation.category != "transaction-invariant"
            || (obligation.status != "runtime-required"
                && !include_checked_destroy_scan
                && !include_checked_transfer_output
                && !include_checked_claim_output
                && !include_checked_settle_output
                && !include_checked_operation_input
                && !include_checked_read_ref
                && !include_checked_create_output
                && !include_checked_resource_conservation
                && !include_checked_claim_conditions
                && !include_checked_settle_finalization)
        {
            continue;
        }
        if let Some(binding) = obligation.feature.strip_prefix("transfer-output:") {
            let transfer_output_relation_status =
                if transaction_obligation_has_checked_subcondition(obligation, "transfer-output-relation") {
                    "checked-runtime"
                } else {
                    "runtime-required"
                };
            let transfer_lock_status = if transaction_obligation_has_checked_subcondition(obligation, "transfer-lock-rebinding") {
                "checked-runtime"
            } else {
                "runtime-required"
            };
            let transfer_destination_status =
                if transaction_obligation_has_checked_subcondition(obligation, "transfer-destination-address-binding") {
                    "checked-runtime"
                } else {
                    "runtime-required"
                };
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "transfer-output-relation",
                transfer_output_relation_status,
                (transfer_output_relation_status == "runtime-required")
                    .then_some("transfer-created output relation is not fully verifier-covered"),
                (transfer_output_relation_status == "runtime-required").then_some("transfer-output-relation-gap"),
                "Transaction",
                binding,
                Some("output-relation"),
                "transfer-output-relation-consume-create-accounting",
                None,
            ));
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "transfer-destination-lock",
                transfer_lock_status,
                (transfer_lock_status == "runtime-required")
                    .then_some("transfer lock rebinding is not lowered into transfer create_set lock checks"),
                (transfer_lock_status == "runtime-required").then_some("lock-rebinding-lowering-gap"),
                "Output",
                binding,
                Some("lock_hash"),
                "transfer-destination-lock-hash-32",
                Some(32),
            ));
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "transfer-destination-address",
                transfer_destination_status,
                (transfer_destination_status == "runtime-required")
                    .then_some("destination address ABI is typed but not bound to an output lock hash by transfer lowering"),
                (transfer_destination_status == "runtime-required").then_some("destination-address-binding-gap"),
                "Param",
                binding,
                Some("destination"),
                "transfer-destination-address-32",
                Some(32),
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("destroy-output-scan:") {
            let absence_status = if transaction_obligation_has_checked_subcondition(obligation, "destroy-output-absence") {
                "checked-runtime"
            } else {
                "runtime-required"
            };
            let output_scan_status = if transaction_obligation_has_checked_subcondition(obligation, "destroy-output-scan") {
                "checked-runtime"
            } else {
                "runtime-required"
            };
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "destroy-output-absence",
                absence_status,
                (absence_status == "runtime-required").then_some("destroy lowering has no executable output type-id absence scan"),
                (absence_status == "runtime-required").then_some("output-scan-gap"),
                "Output",
                binding,
                Some("type_hash-absence"),
                "destroy-output-scan-type-id",
                None,
            ));
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "destroy-output-scan",
                output_scan_status,
                (output_scan_status == "runtime-required")
                    .then_some("destroy lowering does not bind transaction output scan boundaries"),
                (output_scan_status == "runtime-required").then_some("output-scan-boundary-gap"),
                "Transaction",
                binding,
                Some("outputs"),
                "destroy-output-scan-transaction-boundary",
                None,
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("claim-output:") {
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "claim-output-relation",
                obligation.status.as_str(),
                (obligation.status == "runtime-required").then_some("claim-created output relation is not fully verifier-covered"),
                (obligation.status == "runtime-required").then_some("claim-output-relation-gap"),
                "Transaction",
                binding,
                Some("output-relation"),
                "claim-output-relation-consume-create-accounting",
                None,
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("settle-output:") {
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "settle-output-relation",
                obligation.status.as_str(),
                (obligation.status == "runtime-required").then_some("settle-created output relation is not fully verifier-covered"),
                (obligation.status == "runtime-required").then_some("settle-output-relation-gap"),
                "Transaction",
                binding,
                Some("output-relation"),
                "settle-output-relation-consume-create-accounting",
                None,
            ));
        } else if let Some((operation, binding)) = operation_input_feature(obligation.feature.as_str()) {
            let input_binding = binding.rsplit_once(':').map(|(_, binding)| binding).unwrap_or(binding);
            let component = format!("{operation}-input-data");
            let abi = format!("{operation}-load-cell-input");
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                &component,
                "checked-runtime",
                None,
                None,
                "Input",
                input_binding,
                Some("data"),
                &abi,
                None,
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("read-ref:") {
            let cell_dep_binding = binding.rsplit_once('#').map(|(binding, _)| binding).unwrap_or(binding);
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "read-ref-cell-dep-data",
                "checked-runtime",
                None,
                None,
                "CellDep",
                cell_dep_binding,
                Some("data"),
                "read-ref-load-cell-dep",
                None,
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("create-output:") {
            let output_binding = binding.rsplit_once(':').map(|(_, binding)| binding).unwrap_or(binding);
            let fields_status = obligation_detail_status(obligation, "create-output-fields").unwrap_or("runtime-required");
            let lock_status = obligation_detail_status(obligation, "create-output-lock").unwrap_or("runtime-required");
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "create-output-fields",
                fields_status,
                (fields_status == "runtime-required").then_some("create output field verifier is incomplete for this output shape"),
                (fields_status == "runtime-required").then_some("create-output-verification-gap"),
                "Output",
                output_binding,
                Some("fields"),
                "create-output-field-verifier",
                None,
            ));
            match lock_status {
                "checked-runtime" | "runtime-required" => {
                    requirements.push(transaction_runtime_input_requirement(
                        obligation,
                        "create-output-lock",
                        lock_status,
                        (lock_status == "runtime-required").then_some("create output lock binding is not fully verifier-covered"),
                        (lock_status == "runtime-required").then_some("create-output-lock-verification-gap"),
                        "Output",
                        output_binding,
                        Some("lock_hash"),
                        "create-output-lock-hash-32",
                        Some(32),
                    ));
                }
                _ => {}
            }
        } else if let Some(binding) = obligation.feature.strip_prefix("linear-collection:") {
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "linear-collection-ownership",
                "runtime-required",
                Some("cell-backed collection ownership is not backed by an executable linear collection model"),
                Some("linear-collection-ownership-gap"),
                "Transaction",
                binding,
                Some("collection-payload"),
                "cell-backed-collection-linear-ownership-model",
                None,
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("claim-conditions:") {
            let claim_time_status = if transaction_obligation_has_checked_subcondition(obligation, "daa-cliff-reached") {
                "checked-runtime"
            } else {
                "runtime-required"
            };
            let claim_authorization_domain_status =
                if transaction_obligation_has_checked_subcondition(obligation, "claim-authorization-domain") {
                    "checked-runtime"
                } else {
                    "runtime-required"
                };
            let claim_signature_status = if transaction_obligation_has_checked_subcondition(obligation, "claim-witness-signature") {
                "checked-runtime"
            } else {
                "runtime-required"
            };
            if transaction_obligation_has_checked_subcondition(obligation, "claim-input-lock-hash") {
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "claim-input-lock-hash",
                    "checked-runtime",
                    None,
                    None,
                    "Input",
                    binding,
                    Some("lock_hash"),
                    "claim-input-lock-hash-32",
                    Some(32),
                ));
            } else if transaction_obligation_has_checked_subcondition(obligation, "revoke-admin-config-binding") {
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "revoke-admin-config-binding",
                    "checked-runtime",
                    None,
                    None,
                    "CellDep",
                    binding,
                    Some("config.admin"),
                    "revoke-admin-config-admin-32",
                    Some(32),
                ));
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "revoke-admin-output-lock",
                    "checked-runtime",
                    None,
                    None,
                    "Output",
                    binding,
                    Some("lock_hash"),
                    "revoke-admin-output-lock-hash-32",
                    Some(32),
                ));
            } else {
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "claim-witness-signature",
                    claim_signature_status,
                    (claim_signature_status == "runtime-required")
                        .then_some("claim lowering checks witness shape but has no verifier-coverable signer key binding or secp256k1 verification call"),
                    (claim_signature_status == "runtime-required").then_some("witness-verification-gap"),
                    "Witness",
                    binding,
                    Some("signature"),
                    "claim-witness-signature-65",
                    Some(65),
                ));
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "claim-authorization-domain",
                    claim_authorization_domain_status,
                    (claim_authorization_domain_status == "runtime-required")
                        .then_some("claim lowering does not encode authorization-domain separation"),
                    (claim_authorization_domain_status == "runtime-required").then_some("authorization-domain-separation-gap"),
                    "Witness",
                    binding,
                    Some("authorization-domain"),
                    "claim-witness-authorization-domain",
                    None,
                ));
            }
            if obligation.status == "runtime-required"
                || transaction_obligation_has_checked_subcondition(obligation, "daa-cliff-reached")
            {
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "claim-time-context",
                    claim_time_status,
                    (claim_time_status == "runtime-required")
                        .then_some("claim lowering has no checked source DAA/time predicate for this receipt"),
                    (claim_time_status == "runtime-required").then_some("time-context-predicate-gap"),
                    "Header",
                    binding,
                    Some("daa_score"),
                    "claim-time-daa-score-u64",
                    Some(8),
                ));
            }
            if obligation.detail.contains("source-predicate=runtime-required") {
                requirements.push(transaction_runtime_input_requirement(
                    obligation,
                    "claim-source-predicate",
                    "runtime-required",
                    Some("claim source-level predicates are not fully verifier-covered"),
                    Some("claim-source-predicate-gap"),
                    "Transaction",
                    binding,
                    Some("source-predicate"),
                    "claim-source-predicate-cfg",
                    None,
                ));
            }
        } else if let Some(binding) = obligation.feature.strip_prefix("settle-finalization:") {
            let settle_final_state_status = if transaction_obligation_has_checked_subcondition(obligation, "settle-final-state") {
                "checked-runtime"
            } else {
                "runtime-required"
            };
            let settle_output_status =
                if checked_transaction_invariants.contains(&format!("{}:settle-output:{}", obligation.scope, binding)) {
                    "checked-runtime"
                } else {
                    "runtime-required"
                };
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "settle-final-state-context",
                settle_final_state_status,
                (settle_final_state_status == "runtime-required")
                    .then_some("settle lowering does not encode final-state transition policy"),
                (settle_final_state_status == "runtime-required").then_some("finalization-policy-gap"),
                "Transaction",
                binding,
                Some("pending-to-final-state"),
                "settle-finalization-state-context",
                None,
            ));
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "settle-output-admission",
                settle_output_status,
                (settle_output_status == "runtime-required").then_some("settle-created output relation is not fully verifier-covered"),
                (settle_output_status == "runtime-required").then_some("settle-output-admission-gap"),
                "Transaction",
                binding,
                Some("grouped-output-admission"),
                "settle-finalization-output-admission",
                None,
            ));
        } else if let Some(binding) = obligation.feature.strip_prefix("resource-conservation:") {
            requirements.push(transaction_runtime_input_requirement(
                obligation,
                "resource-conservation-proof",
                obligation.status.as_str(),
                (obligation.status == "runtime-required")
                    .then_some("resource conservation is not fully lowered for this consumed-input/created-output shape"),
                (obligation.status == "runtime-required").then_some("resource-conservation-proof-gap"),
                "Transaction",
                binding,
                Some("input-output-conservation"),
                "resource-conservation-consume-create-accounting",
                None,
            ));
        }
    }
    requirements
}

fn mutable_state_obligation_binding(obligation: &VerifierObligationMetadata) -> Option<&str> {
    match obligation.category.as_str() {
        "shared-state" => obligation.feature.strip_prefix("shared-mutation:"),
        "cell-state" => obligation.feature.strip_prefix("mutable-cell:"),
        _ => None,
    }
}

fn obligation_detail_status<'a>(obligation: &'a VerifierObligationMetadata, label: &str) -> Option<&'a str> {
    let needle = format!("{}=", label);
    let start = obligation.detail.find(&needle)? + needle.len();
    let suffix = &obligation.detail[start..];
    let end = suffix.find([';', ',', ')']).unwrap_or(suffix.len());
    Some(suffix[..end].trim())
}

fn transaction_obligation_has_checked_subcondition(obligation: &VerifierObligationMetadata, name: &str) -> bool {
    obligation.detail.contains(&format!("{}=checked-runtime", name))
}

fn transaction_runtime_input_requirement(
    obligation: &VerifierObligationMetadata,
    component: &str,
    status: &str,
    blocker: Option<&str>,
    blocker_class: Option<&str>,
    source: &str,
    binding: &str,
    field: Option<&str>,
    abi: &str,
    byte_len: Option<usize>,
) -> TransactionRuntimeInputRequirementMetadata {
    TransactionRuntimeInputRequirementMetadata {
        scope: obligation.scope.clone(),
        feature: obligation.feature.clone(),
        status: status.to_string(),
        component: component.to_string(),
        source: source.to_string(),
        binding: binding.to_string(),
        field: field.map(str::to_string),
        abi: abi.to_string(),
        byte_len,
        blocker: blocker.map(str::to_string),
        blocker_class: blocker_class.map(str::to_string),
    }
}

fn transaction_condition_detail(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    lifecycle_states: &HashMap<String, Vec<String>>,
    operation: &str,
    operand: &ir::IrOperand,
    type_name: &str,
    checked: bool,
) -> String {
    let binding = operand_var_name(operand).unwrap_or(type_name);
    let input_summary = transaction_condition_input_summary(body, type_layouts, operation, binding, type_name);
    match (operation, checked) {
        ("settle", true) => format!(
            "Compiler-emitted runtime verifier proves '{}' lifecycle final-state invariants and admits the settle-created output{}; settle-output-admission=checked-runtime; runtime inputs: {}",
            type_name,
            settle_final_state_detail(body, type_layouts, availability, lifecycle_states, type_name),
            input_summary
        ),
        ("settle", false) => format!(
            "Runtime verifier must prove '{}' finalization invariants and reject invalid pending-to-final state transitions{}; runtime inputs: {}",
            type_name,
            settle_final_state_detail(body, type_layouts, availability, lifecycle_states, type_name),
            input_summary
        ),
        _ => format!("Runtime verifier must prove '{}' transaction conditions; runtime inputs: {}", type_name, input_summary),
    }
}

fn transaction_claim_condition_detail(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    name: &str,
    operation: &str,
    operand: &ir::IrOperand,
    type_name: &str,
    checked: bool,
) -> String {
    let binding = operand_var_name(operand).unwrap_or(type_name);
    let input_summary = transaction_condition_input_summary(body, type_layouts, operation, binding, type_name);
    let witness_detail = claim_witness_authorization_domain_detail(body, type_layouts, operation, binding, type_name);
    if checked {
        let signer_field = metadata_claim_signer_pubkey_hash_field(type_name, type_layouts);
        let lock_hash_field = metadata_claim_auth_lock_hash_field(type_name, type_layouts);
        let mut checked_parts = Vec::new();
        if signer_field.is_some() {
            checked_parts.extend([
                "claim-witness-format=checked-runtime".to_string(),
                "claim-authorization-domain=checked-runtime".to_string(),
                "claim-witness-signature=checked-runtime".to_string(),
                "claim-signer-key-binding=checked-runtime".to_string(),
            ]);
        } else if lock_hash_field.is_some() {
            checked_parts.extend([
                "claim-input-lock-hash=checked-runtime".to_string(),
                "claim-lock-hash-field-binding=checked-runtime".to_string(),
            ]);
        }
        let source_invariant_count = body_assert_invariant_count(body);
        let checked_guards = receipt_claim_flow_checked_condition_guards(name, type_name, source_invariant_count, body);
        for guard in &checked_guards {
            checked_parts.push(format!("{}=checked-runtime", guard));
        }
        if let Some(signer_field) = signer_field {
            return format!(
                "Compiler-emitted runtime verifier checks '{}' claim witness format, authorization-domain separation, secp256k1 signature verification, and signer-key binding via '{}.{}'; {}; claimed output relation is tracked by claim-output obligations; runtime inputs: {}",
                type_name,
                type_name,
                signer_field,
                checked_parts.join("; "),
                input_summary
            );
        }
        if let Some(lock_hash_field) = lock_hash_field {
            return format!(
                "Compiler-emitted runtime verifier checks '{}' claim authorization by binding Input lock_hash to '{}.{}'; {}; claimed output relation is tracked by claim-output obligations; runtime inputs: {}",
                type_name,
                type_name,
                lock_hash_field,
                checked_parts.join("; "),
                input_summary
            );
        }
    }
    format!(
        "Runtime verifier must bind '{}' claim conditions to witness/signature/time context and verify the claimed output relation{}{}{}; runtime inputs: {}",
        type_name,
        claim_unchecked_source_predicate_detail(name, type_name, body),
        claim_runtime_gap_detail(name, body, type_layouts, cell_type_kinds, operation, binding),
        witness_detail,
        input_summary
    )
}

fn claim_runtime_gap_detail(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    operation: &str,
    binding: &str,
) -> &'static str {
    if body.consume_set.iter().any(|pattern| {
        pattern.operation == operation
            && pattern.binding == binding
            && (is_claim_witness_authorization_domain_check_target(name, pattern, cell_type_kinds, type_layouts)
                || is_claim_input_lock_hash_binding_check_target(name, pattern, cell_type_kinds, type_layouts))
    }) || revoke_admin_authorization_is_checked(name, "VestingGrant", body, type_layouts)
    {
        ""
    } else {
        "; claim witness binding is not verifier-covered"
    }
}

fn claim_unchecked_source_predicate_detail(name: &str, type_name: &str, body: &ir::IrBody) -> &'static str {
    if claim_body_has_source_predicates(body) && !claim_source_predicates_are_checked(name, type_name, body) {
        "; source-predicate=runtime-required"
    } else {
        ""
    }
}

fn settle_final_state_detail(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    lifecycle_states: &HashMap<String, Vec<String>>,
    type_name: &str,
) -> String {
    if settle_final_state_is_checked(body, type_layouts, availability, lifecycle_states, type_name) {
        "; settle-final-state=checked-runtime; settle-state-policy=lifecycle-final-state".to_string()
    } else {
        String::new()
    }
}

fn claim_witness_authorization_domain_detail(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    operation: &str,
    binding: &str,
    type_name: &str,
) -> String {
    if !body.consume_set.iter().any(|pattern| pattern.operation == operation && pattern.binding == binding) {
        return String::new();
    }
    if metadata_claim_signer_pubkey_hash_field(type_name, type_layouts).is_none()
        && metadata_claim_auth_lock_hash_field(type_name, type_layouts).is_some()
    {
        return "; claim-input-lock-hash=checked-runtime; claim-lock-hash-field-binding=checked-runtime".to_string();
    }
    let mut detail = "; claim-witness-format=checked-runtime; claim-authorization-domain=checked-runtime".to_string();
    if metadata_claim_signer_pubkey_hash_field(type_name, type_layouts).is_some() {
        detail.push_str("; claim-witness-signature=checked-runtime; claim-signer-key-binding=checked-runtime");
    }
    detail
}

fn transaction_condition_input_summary(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    operation: &str,
    binding: &str,
    type_name: &str,
) -> String {
    let Some((input_index, _)) =
        body.consume_set.iter().enumerate().find(|(_, pattern)| pattern.operation == operation && pattern.binding == binding)
    else {
        return "unresolved consumed input binding".to_string();
    };
    let mut field_requirements = type_layouts
        .get(type_name)
        .map(|fields| {
            fields
                .iter()
                .filter_map(|(field, layout)| {
                    let (abi, width) = transaction_field_requirement_abi(layout)?;
                    Some((layout.offset, format!("Input#{}:{}.{}={}[{}]", input_index, binding, field, abi, width)))
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    field_requirements.sort_by_key(|(offset, requirement)| (*offset, requirement.clone()));

    if field_requirements.is_empty() {
        format!("Input#{}:{}=input-cell[untyped]", input_index, binding)
    } else {
        field_requirements.into_iter().map(|(_, requirement)| requirement).collect::<Vec<_>>().join(", ")
    }
}

fn transaction_field_requirement_abi(layout: &MetadataFieldLayout) -> Option<(String, usize)> {
    if let Some(width) = metadata_layout_fixed_scalar_width(layout) {
        let scalar = match width {
            1 => "u8",
            2 => "u16",
            4 => "u32",
            8 => "u64",
            16 => "u128",
            _ => return None,
        };
        return Some((format!("input-cell-field-{}", scalar), width));
    }
    metadata_layout_fixed_byte_width(layout).map(|width| (format!("input-cell-field-bytes-{}", width), width))
}

fn transaction_output_obligation(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    operation: &str,
    binding: &str,
    type_name: &str,
    checked_detail: String,
    runtime_detail: String,
) -> TransactionResourceObligation {
    let output_covered = body.create_set.iter().any(|pattern| {
        pattern.operation == operation
            && pattern.binding == binding
            && pattern.ty == type_name
            && metadata_can_verify_create_output_fields(pattern, type_layouts, availability)
    });
    TransactionResourceObligation {
        category: "transaction-invariant",
        feature: format!("{}-output:{}", operation, type_name),
        status: if output_covered { "checked-runtime" } else { "runtime-required" },
        detail: if output_covered { checked_detail } else { runtime_detail },
    }
}

fn transfer_lock_rebinding_is_checked(body: &ir::IrBody, availability: &MetadataPreludeAvailability, type_name: &str) -> bool {
    body.create_set.iter().any(|pattern| {
        pattern.operation == "transfer"
            && pattern.ty == type_name
            && pattern.lock.as_ref().is_some_and(|_| metadata_can_verify_output_lock(pattern, availability))
    })
}

fn transfer_output_relation_is_checked(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    output_index: usize,
    type_name: &str,
) -> bool {
    body.create_set.get(output_index).is_some_and(|pattern| {
        pattern.operation == "transfer"
            && pattern.ty == type_name
            && metadata_can_verify_create_output_fields(pattern, type_layouts, availability)
            && metadata_can_verify_output_lock(pattern, availability)
    })
}

fn destroy_group_output_absence_scan_is_checked(body: &ir::IrBody, _type_name: &str, binding: &str) -> bool {
    body.consume_set.iter().any(|pattern| pattern.operation == "destroy" && pattern.binding == binding && pattern.type_hash.is_some())
}

fn settle_final_state_is_checked(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    lifecycle_states: &HashMap<String, Vec<String>>,
    type_name: &str,
) -> bool {
    body.create_set.iter().any(|pattern| {
        pattern.operation == "settle"
            && pattern.ty == type_name
            && metadata_can_verify_settle_final_state(pattern, type_layouts, availability, lifecycle_states)
    })
}

fn settle_finalization_is_checked(
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    lifecycle_states: &HashMap<String, Vec<String>>,
    output_index: usize,
    type_name: &str,
) -> bool {
    body.create_set.get(output_index).is_some_and(|pattern| {
        pattern.operation == "settle"
            && pattern.ty == type_name
            && metadata_can_verify_settle_final_state(pattern, type_layouts, availability, lifecycle_states)
    })
}

fn metadata_can_verify_settle_final_state(
    pattern: &ir::CreatePattern,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    lifecycle_states: &HashMap<String, Vec<String>>,
) -> bool {
    lifecycle_states.get(&pattern.ty).is_some_and(|states| states.len() >= 2)
        && type_layouts
            .get(&pattern.ty)
            .is_some_and(|layouts| layouts.get("state").and_then(metadata_layout_fixed_scalar_width).is_some())
        && metadata_can_verify_create_output_fields(pattern, type_layouts, availability)
}

fn body_mutable_cell_state_obligations(
    body: &ir::IrBody,
    params: &[ir::IrParam],
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> Vec<TransactionResourceObligation> {
    let mut obligations = Vec::new();
    for param in params {
        let Some(type_name) = named_type_name(&param.ty) else {
            continue;
        };
        if !(param.is_mut || matches!(param.ty, ir::IrType::MutRef(_))) {
            continue;
        }
        let mutated_fields = mutate_set_field_summary(body, type_name, &param.name, type_layouts);
        let obligation_status = mutate_set_obligation_status(body, type_name, &param.name, type_layouts);
        match cell_type_kinds.get(type_name).copied() {
            Some(ir::IrTypeKind::Shared) => obligations.push(TransactionResourceObligation {
                category: "shared-state",
                feature: format!("shared-mutation:{}", type_name),
                status: obligation_status,
                detail: format!(
                    "Runtime verifier must bind mutable shared parameter '{}' to the consumed '{}' cell and replacement output, preserve type/lock identity, and prove the allowed field transition; current lowering exposes scheduler contention and mutate_set field summary ({})",
                    param.name, type_name, mutated_fields
                ),
            }),
            Some(ir::IrTypeKind::Resource | ir::IrTypeKind::Receipt) => obligations.push(TransactionResourceObligation {
                category: "cell-state",
                feature: format!("mutable-cell:{}", type_name),
                status: obligation_status,
                detail: format!(
                    "Runtime verifier must bind mutable cell parameter '{}' to the consumed '{}' cell and replacement output, preserve type/lock identity, and prove the allowed field transition; current lowering exposes mutate_set field summary ({})",
                    param.name, type_name, mutated_fields
                ),
            }),
            Some(ir::IrTypeKind::Struct) | None => {}
        }
    }
    obligations
}

fn mutate_set_field_summary(body: &ir::IrBody, type_name: &str, binding: &str, type_layouts: &MetadataTypeLayouts) -> String {
    body.mutate_set
        .iter()
        .find(|pattern| pattern.ty == type_name && pattern.binding == binding)
        .map(|pattern| {
            let transition_fields = if pattern.fields.is_empty() {
                "transition fields: none".to_string()
            } else {
                format!("transition fields: {}", pattern.fields.join(", "))
            };
            let preserved_fields = if pattern.preserved_fields.is_empty() {
                "preserved fields: none".to_string()
            } else {
                format!("preserved fields: {}", pattern.preserved_fields.join(", "))
            };
            format!(
                "Input#{} -> Output#{}; type_hash preservation=checked-runtime; lock_hash preservation=checked-runtime; field equality={}; field transition={}; {}; {}",
                pattern.input_index,
                pattern.output_index,
                mutate_field_equality_status(pattern, type_layouts),
                mutate_field_transition_status(pattern, type_layouts),
                transition_fields,
                preserved_fields
            )
        })
        .unwrap_or_else(|| "no mutate_set entry".to_string())
}

fn mutate_set_obligation_status(
    body: &ir::IrBody,
    type_name: &str,
    binding: &str,
    type_layouts: &MetadataTypeLayouts,
) -> &'static str {
    body.mutate_set
        .iter()
        .find(|pattern| pattern.ty == type_name && pattern.binding == binding)
        .map(|pattern| {
            if !pattern.fields.is_empty()
                && mutate_field_equality_status(pattern, type_layouts) == "checked-runtime"
                && mutate_field_transition_status(pattern, type_layouts) == "checked-runtime"
            {
                "checked-runtime"
            } else {
                "runtime-required"
            }
        })
        .unwrap_or("runtime-required")
}

fn body_pool_primitive_metadata(
    scope_kind: &str,
    name: &str,
    body: &ir::IrBody,
    params: &[ir::IrParam],
    type_layouts: &MetadataTypeLayouts,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<PoolPrimitiveMetadata> {
    let scope = format!("{}:{}", scope_kind, name);
    let source_invariant_count = body_assert_invariant_count(body);
    let param_schema_vars = schema_pointer_var_ids(body, params);
    let availability = metadata_prelude_availability(body, &param_schema_vars, type_layouts, params, pure_const_returns);
    let mut pool_primitives = Vec::new();
    let mut seen = BTreeSet::new();

    for (output_index, pattern) in body.create_set.iter().enumerate() {
        if !is_pool_pattern_candidate(&pattern.ty, cell_type_kinds)
            || !seen.insert(("create", pattern.ty.clone(), pattern.binding.clone()))
        {
            continue;
        }
        let create_fields_status = if metadata_can_verify_create_output_fields(pattern, type_layouts, &availability) {
            "checked-runtime"
        } else {
            "runtime-required"
        };
        let checked_invariant_guards = pool_checked_invariant_guard_names(name, "create", source_invariant_count);
        let token_pair_symbol_status =
            if pool_seed_token_pair_symbol_admission_is_checked(name, pattern, &checked_invariant_guards, type_layouts, &availability)
            {
                "checked-runtime"
            } else {
                "runtime-required"
            };
        let lp_supply_status = if pool_seed_lp_supply_invariant_is_checked(name, pattern, body, type_layouts, &availability) {
            "checked-runtime"
        } else {
            "runtime-required"
        };
        let token_pair_identity_status = if pool_seed_token_pair_identity_admission_is_checked(name, body, pattern) {
            "checked-runtime"
        } else {
            "runtime-required"
        };
        let checked_protocol_components = pool_checked_protocol_components(
            name,
            "create",
            &checked_invariant_guards,
            create_fields_status,
            token_pair_identity_status,
            token_pair_symbol_status,
            lp_supply_status,
            "runtime-required", // create has no prior reserve state to conserve
        );
        let runtime_required_components = pool_runtime_required_components(name, "create", &checked_protocol_components);
        let runtime_input_requirements = pool_runtime_input_requirements(name, "create", body, params, &checked_protocol_components);
        let mut checked_components =
            vec!["ordinary-shared-create-summary".to_string(), format!("create-output-fields={}", create_fields_status)];
        if source_invariant_count > 0 {
            checked_components.push(format!("assert-invariant-cfg={}", source_invariant_count));
        }
        checked_components.extend(checked_invariant_guards.iter().map(|guard| format!("source-invariant:{}=checked-runtime", guard)));
        checked_components
            .extend(checked_protocol_components.iter().map(|component| format!("pool-protocol:{}=checked-runtime", component)));
        let invariant_families = pool_invariant_families(
            &checked_invariant_guards,
            &checked_protocol_components,
            &runtime_required_components,
            "pool-protocol-admission",
        );
        let status = pool_primitive_status(&runtime_required_components);
        pool_primitives.push(PoolPrimitiveMetadata {
            scope: scope.clone(),
            operation: "create".to_string(),
            feature: format!("pool-create:{}", pattern.ty),
            ty: pattern.ty.clone(),
            status: status.to_string(),
            source: "create_set".to_string(),
            checked_components,
            runtime_required_components,
            runtime_input_requirements,
            invariant_families,
            source_invariant_count,
            binding: Some(pattern.binding.clone()),
            callee: None,
            input_source: None,
            input_index: None,
            output_source: Some("Output".to_string()),
            output_index: Some(output_index),
            transition_fields: Vec::new(),
            preserved_fields: pattern.fields.iter().map(|(field, _)| field.clone()).collect(),
        });
    }

    for pattern in &body.mutate_set {
        if !is_pool_pattern_candidate(&pattern.ty, cell_type_kinds)
            || !seen.insert(("mutation-invariants", pattern.ty.clone(), pattern.binding.clone()))
        {
            continue;
        }
        let checked_invariant_guards = pool_checked_invariant_guard_names(name, "mutation-invariants", source_invariant_count);
        let field_equality_status = mutate_field_equality_status(pattern, type_layouts);
        let lp_supply_status = if pool_lp_supply_consistency_is_checked(name, pattern, body, type_layouts, &availability) {
            "checked-runtime"
        } else {
            "runtime-required"
        };
        let field_transition_status = mutate_field_transition_status(pattern, type_layouts);
        let reserve_conservation_status =
            if field_transition_status == "checked-runtime" { "checked-runtime" } else { "runtime-required" };
        let mut checked_protocol_components = pool_checked_protocol_components(
            name,
            "mutation-invariants",
            &checked_invariant_guards,
            field_equality_status,
            "runtime-required",
            "runtime-required",
            lp_supply_status,
            reserve_conservation_status,
        );
        if pool_swap_a_for_b_fee_accounting_is_checked(name, pattern, body, type_layouts) {
            checked_protocol_components.push("fee-accounting".to_string());
        }
        if pool_swap_a_for_b_constant_product_pricing_is_checked(name, pattern, body, type_layouts, &availability) {
            checked_protocol_components.push("constant-product-pricing".to_string());
        }
        if pool_swap_a_for_b_admission_is_checked(name, pattern, body, &checked_invariant_guards, type_layouts, &availability) {
            checked_protocol_components.push("pool-specific-admission".to_string());
        }
        if pool_add_liquidity_proportional_accounting_is_checked(name, pattern, body, type_layouts, &availability) {
            checked_protocol_components.push("proportional-liquidity-accounting".to_string());
        }
        if pool_remove_liquidity_proportional_accounting_is_checked(name, pattern, body, type_layouts, &availability) {
            checked_protocol_components.push("proportional-withdrawal-accounting".to_string());
        }
        if pool_add_liquidity_admission_is_checked(name, pattern, body, &checked_invariant_guards, type_layouts, &availability) {
            checked_protocol_components.push("pool-specific-admission".to_string());
        }
        if pool_remove_liquidity_admission_is_checked(name, pattern, body, &checked_invariant_guards, type_layouts, &availability) {
            checked_protocol_components.push("pool-specific-admission".to_string());
        }
        let runtime_required_components = pool_runtime_required_components(name, "mutation-invariants", &checked_protocol_components);
        let runtime_input_requirements =
            pool_runtime_input_requirements(name, "mutation-invariants", body, params, &checked_protocol_components);
        let mut checked_components = vec![
            "type_hash-preservation=checked-runtime".to_string(),
            "lock_hash-preservation=checked-runtime".to_string(),
            format!("field-equality={}", field_equality_status),
            format!("field-transition={}", field_transition_status),
        ];
        if source_invariant_count > 0 {
            checked_components.push(format!("assert-invariant-cfg={}", source_invariant_count));
        }
        checked_components.extend(checked_invariant_guards.iter().map(|guard| format!("source-invariant:{}=checked-runtime", guard)));
        checked_components
            .extend(checked_protocol_components.iter().map(|component| format!("pool-protocol:{}=checked-runtime", component)));
        let invariant_families = pool_invariant_families(
            &checked_invariant_guards,
            &checked_protocol_components,
            &runtime_required_components,
            "pool-protocol-invariant",
        );
        let status = pool_primitive_status(&runtime_required_components);
        pool_primitives.push(PoolPrimitiveMetadata {
            scope: scope.clone(),
            operation: "mutation-invariants".to_string(),
            feature: format!("pool-mutation-invariants:{}", pattern.ty),
            ty: pattern.ty.clone(),
            status: status.to_string(),
            source: "mutate_set".to_string(),
            checked_components,
            runtime_required_components,
            runtime_input_requirements,
            invariant_families,
            source_invariant_count,
            binding: Some(pattern.binding.clone()),
            callee: None,
            input_source: Some("Input".to_string()),
            input_index: Some(pattern.input_index),
            output_source: Some("Output".to_string()),
            output_index: Some(pattern.output_index),
            transition_fields: pattern.fields.clone(),
            preserved_fields: pattern.preserved_fields.clone(),
        });
    }

    for block in &body.blocks {
        for instruction in &block.instructions {
            let ir::IrInstruction::Call { dest: Some(dest), func, args } = instruction else {
                continue;
            };
            for type_name in pool_pattern_candidate_type_names(&dest.ty, cell_type_kinds) {
                if !seen.insert(("composition", type_name.clone(), func.clone())) {
                    continue;
                }
                let checked_invariant_guards = pool_checked_invariant_guard_names(name, "composition", source_invariant_count);
                let mut checked_protocol_components = pool_checked_protocol_components(
                    name,
                    "composition",
                    &checked_invariant_guards,
                    "checked-runtime",
                    "runtime-required",
                    "runtime-required",
                    "runtime-required",
                    "runtime-required", // composition does not mutate reserves
                );
                if pool_launch_token_pool_id_continuity_equality_is_checked(name, body, type_layouts, func, dest) {
                    checked_protocol_components.push("pool-id-continuity".to_string());
                }
                let launch_atomicity_components =
                    pool_launch_token_atomicity_checked_components(name, body, params, type_layouts, &availability);
                if launch_atomicity_components.len() == 4 {
                    checked_protocol_components.push("launch-pool-atomicity".to_string());
                }
                let callee_admission_components =
                    pool_launch_token_callee_admission_checked_components(name, body, params, type_layouts, &availability, func, args);
                if callee_admission_components.len() == 3 {
                    checked_protocol_components.push("callee-pool-admission".to_string());
                }
                let pool_id_continuity_components =
                    pool_launch_token_pool_id_continuity_checked_components(name, body, type_layouts, func, dest);
                let runtime_required_components = pool_runtime_required_components(name, "composition", &checked_protocol_components);
                let runtime_input_requirements =
                    pool_runtime_input_requirements(name, "composition", body, params, &checked_protocol_components);
                let mut checked_components =
                    vec!["call-return-type=known".to_string(), "shared-touch-propagation=checked-metadata".to_string()];
                if source_invariant_count > 0 {
                    checked_components.push(format!("assert-invariant-cfg={}", source_invariant_count));
                }
                checked_components.extend(launch_atomicity_components);
                checked_components.extend(callee_admission_components);
                checked_components.extend(pool_id_continuity_components);
                checked_components
                    .extend(checked_invariant_guards.iter().map(|guard| format!("source-invariant:{}=checked-runtime", guard)));
                checked_components.extend(
                    checked_protocol_components.iter().map(|component| format!("pool-protocol:{}=checked-runtime", component)),
                );
                let invariant_families = pool_invariant_families(
                    &checked_invariant_guards,
                    &checked_protocol_components,
                    &runtime_required_components,
                    "pool-composition-protocol",
                );
                let status = pool_primitive_status(&runtime_required_components);
                pool_primitives.push(PoolPrimitiveMetadata {
                    scope: scope.clone(),
                    operation: "composition".to_string(),
                    feature: format!("pool-composition:{}", type_name),
                    ty: type_name,
                    status: status.to_string(),
                    source: "call-return".to_string(),
                    checked_components,
                    runtime_required_components,
                    runtime_input_requirements,
                    invariant_families,
                    source_invariant_count,
                    binding: Some(dest.name.clone()),
                    callee: Some(func.clone()),
                    input_source: None,
                    input_index: None,
                    output_source: None,
                    output_index: None,
                    transition_fields: Vec::new(),
                    preserved_fields: Vec::new(),
                });
            }
        }
    }

    pool_primitives
}

fn pool_primitive_status(runtime_required_components: &[String]) -> &'static str {
    if runtime_required_components.is_empty() {
        "checked-runtime"
    } else {
        "runtime-required"
    }
}

fn pool_checked_invariant_guard_names(name: &str, operation: &str, source_invariant_count: usize) -> Vec<String> {
    if source_invariant_count == 0 {
        return Vec::new();
    }

    let named_guards = match (operation, name) {
        ("create", "seed_pool") => &["token-pair-distinct", "positive-reserves", "fee-bps-bound"][..],
        ("mutation-invariants", "swap_a_for_b") => &["input-token-a-match", "minimum-output-bound", "reserve-output-bound"][..],
        ("mutation-invariants", "add_liquidity") => &["deposit-token-a-match", "deposit-token-b-match"][..],
        ("mutation-invariants", "remove_liquidity") => &["lp-receipt-pool-id-match"][..],
        ("composition", "launch_token") => &["initial-mint-cap", "pool-seed-cap", "distribution-cap"][..],
        _ => &[][..],
    };

    let mut guards = named_guards.iter().take(source_invariant_count).map(|guard| (*guard).to_string()).collect::<Vec<_>>();
    while guards.len() < source_invariant_count {
        guards.push(format!("source-guard-{}", guards.len()));
    }
    guards
}

fn pool_checked_protocol_components(
    name: &str,
    operation: &str,
    checked_invariant_guards: &[String],
    field_status: &str,
    token_pair_identity_status: &str,
    token_pair_symbol_status: &str,
    lp_supply_status: &str,
    reserve_conservation_status: &str,
) -> Vec<String> {
    match (operation, name) {
        ("create", "seed_pool") if field_status == "checked-runtime" => {
            let mut components = Vec::new();
            if token_pair_identity_status == "checked-runtime" {
                components.push("token-pair-identity-admission".to_string());
            }
            if token_pair_symbol_status == "checked-runtime" {
                components.push("token-pair-symbol-admission".to_string());
            }
            if checked_invariant_guards.iter().any(|guard| guard == "positive-reserves") {
                components.push("positive-reserve-admission".to_string());
            }
            if checked_invariant_guards.iter().any(|guard| guard == "fee-bps-bound") {
                components.push("fee-policy".to_string());
            }
            if lp_supply_status == "checked-runtime" {
                components.push("lp-supply-invariant".to_string());
            }
            components
        }
        ("mutation-invariants", "swap_a_for_b") if field_status == "checked-runtime" => {
            let mut components = Vec::new();
            if lp_supply_status == "checked-runtime" {
                components.push("lp-supply-consistency".to_string());
            }
            // Reserve conservation is verified by the transition formula:
            // reserve_a_out = reserve_a_in + input.amount (checked by add transition)
            // reserve_b_out = reserve_b_in - output (checked by sub transition)
            if reserve_conservation_status == "checked-runtime" {
                components.push("reserve-conservation".to_string());
            }
            components
        }
        ("mutation-invariants", "add_liquidity") if field_status == "checked-runtime" => {
            let mut components = Vec::new();
            if reserve_conservation_status == "checked-runtime" {
                components.push("reserve-conservation".to_string());
            }
            if lp_supply_status == "checked-runtime" {
                components.push("lp-supply-consistency".to_string());
            }
            components
        }
        ("mutation-invariants", "remove_liquidity") if field_status == "checked-runtime" => {
            let mut components = Vec::new();
            if reserve_conservation_status == "checked-runtime" {
                components.push("reserve-conservation".to_string());
            }
            if lp_supply_status == "checked-runtime" {
                components.push("lp-supply-consistency".to_string());
            }
            components
        }
        _ => Vec::new(),
    }
}

fn pool_lp_supply_consistency_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name == "swap_a_for_b" {
        return pattern.ty == "Pool"
            && pattern.preserved_fields.iter().any(|field| field == "total_lp")
            && mutate_preserved_field_is_verifier_coverable(pattern, "total_lp", type_layouts);
    }
    pool_add_liquidity_lp_supply_consistency_is_checked(name, pattern, body, type_layouts, availability)
        || pool_remove_liquidity_lp_supply_consistency_is_checked(name, pattern, body, type_layouts)
}

fn pool_add_liquidity_lp_supply_consistency_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "add_liquidity" || pattern.ty != "Pool" {
        return false;
    }
    if mutate_field_transition_status(pattern, type_layouts) != "checked-runtime" {
        return false;
    }
    let Some(total_lp_delta) = mutate_transition_operand(pattern, "total_lp", ir::MutateTransitionOp::Add) else {
        return false;
    };
    if !metadata_fixed_value_available_with_width(total_lp_delta, availability, 8) {
        return false;
    }
    body.create_set.iter().any(|candidate| {
        candidate.ty == "LPReceipt"
            && metadata_can_verify_create_output_fields(candidate, type_layouts, availability)
            && create_pattern_field_operand(candidate, "lp_amount").is_some_and(|receipt_lp| {
                metadata_fixed_value_available_with_width(receipt_lp, availability, 8)
                    && ir_operands_same_verifier_source(total_lp_delta, receipt_lp)
            })
    })
}

fn pool_swap_a_for_b_output_formula() -> &'static str {
    "((pool.reserve_b*(input.amount-((input.amount*pool.fee_rate_bps)/10000)))/(pool.reserve_a+(input.amount-((input.amount*pool.fee_rate_bps)/10000))))"
}

fn pool_swap_a_for_b_fee_accounting_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    if name != "swap_a_for_b" || pattern.ty != "Pool" {
        return false;
    }
    if !mutate_preserved_field_is_verifier_coverable(pattern, "fee_rate_bps", type_layouts) {
        return false;
    }
    let sources = amm_u64_sources(body);
    mutate_transition_operand(pattern, "reserve_b", ir::MutateTransitionOp::Sub)
        .and_then(|operand| amm_u64_source(operand, &sources))
        .is_some_and(|source| source == pool_swap_a_for_b_output_formula())
}

fn pool_swap_a_for_b_constant_product_pricing_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "swap_a_for_b" || pattern.ty != "Pool" {
        return false;
    }
    if mutate_field_transition_status(pattern, type_layouts) != "checked-runtime" {
        return false;
    }
    let sources = amm_u64_sources(body);
    let output_formula = pool_swap_a_for_b_output_formula();
    let Some(reserve_a_delta) = mutate_transition_operand(pattern, "reserve_a", ir::MutateTransitionOp::Add) else {
        return false;
    };
    let Some(reserve_b_delta) = mutate_transition_operand(pattern, "reserve_b", ir::MutateTransitionOp::Sub) else {
        return false;
    };
    if amm_u64_source(reserve_a_delta, &sources).as_deref() != Some("input.amount")
        || amm_u64_source(reserve_b_delta, &sources).as_deref() != Some(output_formula)
    {
        return false;
    }
    body.create_set.iter().any(|candidate| {
        candidate.ty == "Token"
            && metadata_can_verify_create_output_fields(candidate, type_layouts, availability)
            && create_pattern_field_operand(candidate, "amount").and_then(|amount| amm_u64_source(amount, &sources)).as_deref()
                == Some(output_formula)
    })
}

fn pool_swap_a_for_b_admission_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    checked_invariant_guards: &[String],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "swap_a_for_b" || pattern.ty != "Pool" {
        return false;
    }
    if !checked_invariant_guards.iter().any(|guard| guard == "input-token-a-match") {
        return false;
    }
    if consumed_input_pattern(body, "input").is_none() {
        return false;
    }
    if !mutate_preserved_field_is_verifier_coverable(pattern, "token_a_symbol", type_layouts)
        || !mutate_preserved_field_is_verifier_coverable(pattern, "token_b_symbol", type_layouts)
    {
        return false;
    }
    body.create_set.iter().any(|candidate| {
        candidate.ty == "Token"
            && metadata_can_verify_create_output_fields(candidate, type_layouts, availability)
            && create_pattern_field_operand(candidate, "symbol").is_some()
    })
}

fn pool_add_liquidity_proportional_accounting_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "add_liquidity" || pattern.ty != "Pool" {
        return false;
    }
    if !pool_add_liquidity_lp_supply_consistency_is_checked(name, pattern, body, type_layouts, availability) {
        return false;
    }
    if mutate_transition_operand(pattern, "reserve_a", ir::MutateTransitionOp::Add)
        .and_then(|operand| amm_u64_source(operand, &amm_u64_sources(body)))
        .as_deref()
        != Some("token_a.amount")
    {
        return false;
    }
    if mutate_transition_operand(pattern, "reserve_b", ir::MutateTransitionOp::Add)
        .and_then(|operand| amm_u64_source(operand, &amm_u64_sources(body)))
        .as_deref()
        != Some("token_b.amount")
    {
        return false;
    }
    let Some(total_lp_delta) = mutate_transition_operand(pattern, "total_lp", ir::MutateTransitionOp::Add) else {
        return false;
    };
    amm_u64_source(total_lp_delta, &amm_u64_sources(body)).as_deref()
        == Some("min(((token_a.amount*pool.total_lp)/pool.reserve_a),((token_b.amount*pool.total_lp)/pool.reserve_b))")
}

fn pool_add_liquidity_admission_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    checked_invariant_guards: &[String],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "add_liquidity" || pattern.ty != "Pool" {
        return false;
    }
    if !checked_invariant_guards.iter().any(|guard| guard == "deposit-token-a-match")
        || !checked_invariant_guards.iter().any(|guard| guard == "deposit-token-b-match")
    {
        return false;
    }
    if consumed_input_pattern(body, "token_a").is_none() || consumed_input_pattern(body, "token_b").is_none() {
        return false;
    }
    if !mutate_preserved_field_is_verifier_coverable(pattern, "token_a_symbol", type_layouts)
        || !mutate_preserved_field_is_verifier_coverable(pattern, "token_b_symbol", type_layouts)
    {
        return false;
    }
    body.create_set.iter().any(|candidate| {
        candidate.ty == "LPReceipt"
            && metadata_can_verify_create_output_fields(candidate, type_layouts, availability)
            && create_pattern_field_operand(candidate, "pool_id").is_some_and(
                |pool_id| matches!(pool_id, ir::IrOperand::Var(var) if availability.param_type_hash_vars.contains(&var.id)),
            )
    })
}

fn pool_remove_liquidity_lp_supply_consistency_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    if name != "remove_liquidity" || pattern.ty != "Pool" {
        return false;
    }
    if mutate_field_transition_status(pattern, type_layouts) != "checked-runtime" {
        return false;
    }
    mutate_transition_operand(pattern, "total_lp", ir::MutateTransitionOp::Sub)
        .and_then(|operand| amm_u64_source(operand, &amm_u64_sources(body)))
        .as_deref()
        == Some("receipt.lp_amount")
}

fn pool_remove_liquidity_proportional_accounting_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "remove_liquidity" || pattern.ty != "Pool" {
        return false;
    }
    if mutate_field_transition_status(pattern, type_layouts) != "checked-runtime" {
        return false;
    }
    let sources = amm_u64_sources(body);
    let amount_a = "((receipt.lp_amount*pool.reserve_a)/pool.total_lp)";
    let amount_b = "((receipt.lp_amount*pool.reserve_b)/pool.total_lp)";
    let Some(reserve_a_delta) = mutate_transition_operand(pattern, "reserve_a", ir::MutateTransitionOp::Sub) else {
        return false;
    };
    let Some(reserve_b_delta) = mutate_transition_operand(pattern, "reserve_b", ir::MutateTransitionOp::Sub) else {
        return false;
    };
    let Some(total_lp_delta) = mutate_transition_operand(pattern, "total_lp", ir::MutateTransitionOp::Sub) else {
        return false;
    };
    if amm_u64_source(reserve_a_delta, &sources).as_deref() != Some(amount_a)
        || amm_u64_source(reserve_b_delta, &sources).as_deref() != Some(amount_b)
        || amm_u64_source(total_lp_delta, &sources).as_deref() != Some("receipt.lp_amount")
    {
        return false;
    }
    let token_amount_sources = body
        .create_set
        .iter()
        .filter(|candidate| candidate.ty == "Token" && metadata_can_verify_create_output_fields(candidate, type_layouts, availability))
        .filter_map(|candidate| create_pattern_field_operand(candidate, "amount"))
        .filter_map(|operand| amm_u64_source(operand, &sources))
        .collect::<BTreeSet<_>>();
    token_amount_sources.contains(amount_a) && token_amount_sources.contains(amount_b)
}

fn pool_remove_liquidity_admission_is_checked(
    name: &str,
    pattern: &ir::MutatePattern,
    body: &ir::IrBody,
    checked_invariant_guards: &[String],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "remove_liquidity" || pattern.ty != "Pool" {
        return false;
    }
    if !checked_invariant_guards.iter().any(|guard| guard == "lp-receipt-pool-id-match") {
        return false;
    }
    if consumed_input_pattern(body, "receipt").is_none() {
        return false;
    }
    if !mutate_preserved_field_is_verifier_coverable(pattern, "token_a_symbol", type_layouts)
        || !mutate_preserved_field_is_verifier_coverable(pattern, "token_b_symbol", type_layouts)
    {
        return false;
    }
    let token_symbol_count = body
        .create_set
        .iter()
        .filter(|candidate| candidate.ty == "Token" && metadata_can_verify_create_output_fields(candidate, type_layouts, availability))
        .filter(|candidate| create_pattern_field_operand(candidate, "symbol").is_some())
        .count();
    token_symbol_count >= 2
}

fn mutate_transition_operand<'a>(
    pattern: &'a ir::MutatePattern,
    field: &str,
    op: ir::MutateTransitionOp,
) -> Option<&'a ir::IrOperand> {
    pattern.transitions.iter().find_map(|transition| (transition.field == field && transition.op == op).then_some(&transition.operand))
}

fn amm_u64_sources(body: &ir::IrBody) -> HashMap<usize, String> {
    let mut sources = HashMap::new();
    let mut named_sources = HashMap::<String, String>::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::FieldAccess { dest, obj: ir::IrOperand::Var(obj), field } if dest.ty == ir::IrType::U64 => {
                    match (obj.name.as_str(), field.as_str()) {
                        ("input", "amount") => {
                            sources.insert(dest.id, "input.amount".to_string());
                        }
                        ("token_a", "amount") => {
                            sources.insert(dest.id, "token_a.amount".to_string());
                        }
                        ("token_b", "amount") => {
                            sources.insert(dest.id, "token_b.amount".to_string());
                        }
                        ("pool", "reserve_a") => {
                            sources.insert(dest.id, "pool.reserve_a".to_string());
                        }
                        ("pool", "reserve_b") => {
                            sources.insert(dest.id, "pool.reserve_b".to_string());
                        }
                        ("pool", "total_lp") => {
                            sources.insert(dest.id, "pool.total_lp".to_string());
                        }
                        ("receipt", "lp_amount") => {
                            sources.insert(dest.id, "receipt.lp_amount".to_string());
                        }
                        _ => {}
                    }
                }
                ir::IrInstruction::FieldAccess { dest, obj: ir::IrOperand::Var(obj), field }
                    if obj.name == "pool" && field == "fee_rate_bps" =>
                {
                    sources.insert(dest.id, "pool.fee_rate_bps".to_string());
                }
                ir::IrInstruction::Binary { dest, op, left, right } if dest.ty == ir::IrType::U64 => {
                    let Some(left) = amm_u64_source(left, &sources) else {
                        continue;
                    };
                    let Some(right) = amm_u64_source(right, &sources) else {
                        continue;
                    };
                    let op = match op {
                        ast::BinaryOp::Add => "+",
                        ast::BinaryOp::Sub => "-",
                        ast::BinaryOp::Mul => "*",
                        ast::BinaryOp::Div => "/",
                        _ => continue,
                    };
                    sources.insert(dest.id, format!("({left}{op}{right})"));
                }
                ir::IrInstruction::Call { dest: Some(dest), func, args }
                    if dest.ty == ir::IrType::U64 && is_min_call(func) && args.len() == 2 =>
                {
                    let Some(left) = amm_u64_source(&args[0], &sources) else {
                        continue;
                    };
                    let Some(right) = amm_u64_source(&args[1], &sources) else {
                        continue;
                    };
                    sources.insert(dest.id, format!("min({left},{right})"));
                }
                ir::IrInstruction::Move { dest, src } if dest.ty == ir::IrType::U64 => {
                    if let Some(source) = amm_u64_source(src, &sources) {
                        sources.insert(dest.id, source);
                    }
                }
                ir::IrInstruction::StoreVar { name, src } => {
                    if let Some(source) = amm_u64_source(src, &sources) {
                        named_sources.insert(name.clone(), source);
                    }
                }
                ir::IrInstruction::LoadVar { dest, name } if dest.ty == ir::IrType::U64 => {
                    if let Some(source) = named_sources.get(name).cloned() {
                        sources.insert(dest.id, source);
                    }
                }
                _ => {}
            }
        }
    }
    sources
}

fn amm_u64_source(operand: &ir::IrOperand, sources: &HashMap<usize, String>) -> Option<String> {
    match operand {
        ir::IrOperand::Var(var) => sources.get(&var.id).cloned(),
        ir::IrOperand::Const(ir::IrConst::U64(value)) => Some(value.to_string()),
        _ => None,
    }
}

fn is_min_call(func: &str) -> bool {
    func == "min" || func.ends_with("::min")
}

fn pool_seed_token_pair_symbol_admission_is_checked(
    name: &str,
    pool_pattern: &ir::CreatePattern,
    checked_invariant_guards: &[String],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "seed_pool" || pool_pattern.ty != "Pool" {
        return false;
    }
    if !checked_invariant_guards.iter().any(|guard| guard == "token-pair-distinct") {
        return false;
    }
    if !metadata_can_verify_create_output_fields(pool_pattern, type_layouts, availability) {
        return false;
    }

    let Some(token_a_symbol) = create_pattern_field_operand(pool_pattern, "token_a_symbol") else {
        return false;
    };
    let Some(token_b_symbol) = create_pattern_field_operand(pool_pattern, "token_b_symbol") else {
        return false;
    };
    metadata_fixed_value_available_with_width(token_a_symbol, availability, 8)
        && metadata_fixed_value_available_with_width(token_b_symbol, availability, 8)
        && operand_var_name(token_a_symbol) == Some("token_a_symbol")
        && operand_var_name(token_b_symbol) == Some("token_b_symbol")
        && !ir_operands_same_verifier_source(token_a_symbol, token_b_symbol)
}

fn pool_seed_token_pair_identity_admission_is_checked(name: &str, body: &ir::IrBody, pool_pattern: &ir::CreatePattern) -> bool {
    if name != "seed_pool" || pool_pattern.ty != "Pool" {
        return false;
    }
    consumed_input_pattern(body, "token_a").is_some() && consumed_input_pattern(body, "token_b").is_some()
}

fn pool_seed_lp_supply_invariant_is_checked(
    name: &str,
    pool_pattern: &ir::CreatePattern,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if name != "seed_pool" || pool_pattern.ty != "Pool" {
        return false;
    }
    if !metadata_can_verify_create_output_fields(pool_pattern, type_layouts, availability) {
        return false;
    }

    let Some(pool_total_lp) = create_pattern_field_operand(pool_pattern, "total_lp") else {
        return false;
    };
    if !metadata_fixed_value_available_with_width(pool_total_lp, availability, 8) {
        return false;
    }

    body.create_set.iter().any(|candidate| {
        candidate.ty == "LPReceipt"
            && metadata_can_verify_create_output_fields(candidate, type_layouts, availability)
            && create_pattern_field_operand(candidate, "lp_amount").is_some_and(|receipt_lp| {
                metadata_fixed_value_available_with_width(receipt_lp, availability, 8)
                    && ir_operands_same_verifier_source(pool_total_lp, receipt_lp)
            })
    })
}

fn pool_launch_token_atomicity_checked_components(
    name: &str,
    body: &ir::IrBody,
    params: &[ir::IrParam],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> Vec<String> {
    if name != "launch_token" {
        return Vec::new();
    }

    let mut components = Vec::new();
    let Some((_, auth_pattern)) = created_output_pattern(body, "create_MintAuthority", "MintAuthority") else {
        return components;
    };
    let Some((_, seed_pattern)) = last_created_output_pattern(body, "Token") else {
        return components;
    };

    if create_field_matches_param(auth_pattern, "minted", "initial_mint", params, type_layouts, availability, 8) {
        components.push("launch-pool-atomicity:minted-equals-initial-mint=checked-runtime".to_string());
    }
    if create_field_matches_param(seed_pattern, "amount", "pool_seed_amount", params, type_layouts, availability, 8) {
        components.push("launch-pool-atomicity:seed-token-amount=checked-runtime".to_string());
    }
    if create_field_matches_param(auth_pattern, "token_symbol", "symbol", params, type_layouts, availability, 8)
        && create_field_matches_param(seed_pattern, "symbol", "symbol", params, type_layouts, availability, 8)
    {
        components.push("launch-pool-atomicity:symbol-consistency=checked-runtime".to_string());
    }
    if launch_distribution_sum_coupling_is_checked(body, params, availability) {
        components.push("launch-pool-atomicity:distribution-sum-plus-seed-lte-initial-mint=checked-runtime".to_string());
    }

    components
}

fn pool_launch_token_callee_admission_checked_components(
    name: &str,
    body: &ir::IrBody,
    params: &[ir::IrParam],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    func: &str,
    args: &[ir::IrOperand],
) -> Vec<String> {
    if name != "launch_token" || !is_seed_pool_call(func) || args.len() < 3 {
        return Vec::new();
    }

    let mut components = Vec::new();
    let Some((_, seed_pattern)) = last_created_output_pattern(body, "Token") else {
        return components;
    };

    if last_created_output_var_id(body, "Token").is_some_and(|seed_var_id| operand_matches_var_id(&args[0], seed_var_id))
        && create_field_matches_param(seed_pattern, "symbol", "symbol", params, type_layouts, availability, 8)
    {
        components.push("callee-pool-admission:seed-token-symbol-handoff=checked-runtime".to_string());
    }

    if operand_matches_param(&args[1], params, "pool_paired_token")
        && param_field_has_fixed_width(params, "pool_paired_token", "symbol", type_layouts, 8)
    {
        components.push("callee-pool-admission:paired-token-symbol-handoff=checked-runtime".to_string());
    }

    if operand_matches_param(&args[2], params, "fee_rate_bps") && metadata_fixed_value_available_with_width(&args[2], availability, 2)
    {
        components.push("callee-pool-admission:fee-bound-handoff=checked-runtime".to_string());
    }

    components
}

fn pool_launch_token_pool_id_continuity_checked_components(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    func: &str,
    dest: &ir::IrVar,
) -> Vec<String> {
    if name != "launch_token" || !is_seed_pool_call(func) {
        return Vec::new();
    }
    let ir::IrType::Tuple(items) = &dest.ty else {
        return Vec::new();
    };
    if !matches!(items.first(), Some(ir::IrType::Named(type_name)) if type_name == "Pool")
        || !matches!(items.get(1), Some(ir::IrType::Named(type_name)) if type_name == "LPReceipt")
    {
        return Vec::new();
    }

    let mut components = Vec::new();
    let pool_projected = tuple_return_field_is_projected(body, dest.id, "0");
    let lp_receipt_projected = tuple_return_field_is_projected(body, dest.id, "1");
    if pool_projected && lp_receipt_projected {
        components.push("pool-id-continuity:tuple-return-projection=checked-runtime".to_string());
    }
    if pool_projected {
        components.push("pool-id-continuity:pool-type-hash-return-abi=checked-runtime".to_string());
    }
    if lp_receipt_projected && type_field_has_fixed_width(type_layouts, "LPReceipt", "pool_id", 32) {
        components.push("pool-id-continuity:lp-receipt-pool-id-return-abi=checked-runtime".to_string());
    }
    if pool_launch_token_pool_id_continuity_equality_is_checked(name, body, type_layouts, func, dest) {
        components.push("pool-id-continuity:callee-output-field-equality=checked-runtime".to_string());
    }

    components
}

fn pool_launch_token_pool_id_continuity_equality_is_checked(
    name: &str,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    func: &str,
    dest: &ir::IrVar,
) -> bool {
    if name != "launch_token" || !is_seed_pool_call(func) {
        return false;
    }
    let ir::IrType::Tuple(items) = &dest.ty else {
        return false;
    };
    if !matches!(items.first(), Some(ir::IrType::Named(type_name)) if type_name == "Pool")
        || !matches!(items.get(1), Some(ir::IrType::Named(type_name)) if type_name == "LPReceipt")
    {
        return false;
    }

    tuple_return_field_is_projected(body, dest.id, "0")
        && tuple_return_field_is_projected(body, dest.id, "1")
        && type_field_has_fixed_width(type_layouts, "LPReceipt", "pool_id", 32)
}

fn is_seed_pool_call(func: &str) -> bool {
    func == "seed_pool" || func.ends_with("::seed_pool")
}

#[derive(Debug, Clone, Copy)]
enum LaunchAggregateSource {
    DistributionArray { len: usize },
    DistributionElement { index: usize },
}

fn launch_distribution_sum_coupling_is_checked(
    body: &ir::IrBody,
    params: &[ir::IrParam],
    availability: &MetadataPreludeAvailability,
) -> bool {
    let Some(distribution_param) = params.iter().find(|param| param.name == "distribution") else {
        return false;
    };
    let Some(distribution_len) = launch_distribution_amount_count(&distribution_param.ty) else {
        return false;
    };
    if !availability.aggregate_pointer_vars.contains_key(&distribution_param.binding.id) {
        return false;
    }

    let mut required_left_sources = (0..distribution_len).map(launch_distribution_amount_source).collect::<BTreeSet<_>>();
    required_left_sources.insert(launch_param_source("pool_seed_amount"));
    let initial_mint_sources = BTreeSet::from([launch_param_source("initial_mint")]);

    let mut aggregate_sources = HashMap::new();
    aggregate_sources.insert(distribution_param.binding.id, LaunchAggregateSource::DistributionArray { len: distribution_len });

    let mut u64_sources = HashMap::new();
    for param in params {
        if matches!(param.name.as_str(), "initial_mint" | "pool_seed_amount")
            && param.ty == ir::IrType::U64
            && availability.u64_operand_vars.contains(&param.binding.id)
        {
            u64_sources.insert(param.binding.id, BTreeSet::from([launch_param_source(&param.name)]));
        }
    }

    let mut checked_bool_vars = HashSet::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::Index { dest, arr: ir::IrOperand::Var(arr), idx } => {
                    let Some(index) = const_usize_operand(idx) else {
                        continue;
                    };
                    let Some(LaunchAggregateSource::DistributionArray { len }) = aggregate_sources.get(&arr.id).copied() else {
                        continue;
                    };
                    if index < len {
                        aggregate_sources.insert(dest.id, LaunchAggregateSource::DistributionElement { index });
                    }
                }
                ir::IrInstruction::FieldAccess { dest, obj: ir::IrOperand::Var(obj), field } => {
                    let Some(LaunchAggregateSource::DistributionElement { index }) = aggregate_sources.get(&obj.id).copied() else {
                        continue;
                    };
                    if field == "1" && dest.ty == ir::IrType::U64 && availability.u64_value_vars.contains(&dest.id) {
                        u64_sources.insert(dest.id, BTreeSet::from([launch_distribution_amount_source(index)]));
                    }
                }
                ir::IrInstruction::Binary { dest, op: ast::BinaryOp::Add, left, right } if dest.ty == ir::IrType::U64 => {
                    let Some(mut sources) = launch_u64_sources(left, &u64_sources) else {
                        continue;
                    };
                    let Some(right_sources) = launch_u64_sources(right, &u64_sources) else {
                        continue;
                    };
                    sources.extend(right_sources);
                    u64_sources.insert(dest.id, sources);
                }
                ir::IrInstruction::Binary { dest, op, left, right } if dest.ty == ir::IrType::Bool => {
                    let Some(left_sources) = launch_u64_sources(left, &u64_sources) else {
                        continue;
                    };
                    let Some(right_sources) = launch_u64_sources(right, &u64_sources) else {
                        continue;
                    };
                    if launch_distribution_allocation_comparison_is_checked(
                        *op,
                        &left_sources,
                        &right_sources,
                        &required_left_sources,
                        &initial_mint_sources,
                    ) {
                        checked_bool_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::Move { dest, src } if dest.ty == ir::IrType::U64 => {
                    if let Some(sources) = launch_u64_sources(src, &u64_sources) {
                        u64_sources.insert(dest.id, sources);
                    }
                }
                ir::IrInstruction::Move { dest, src: ir::IrOperand::Var(src) } if dest.ty == ir::IrType::Bool => {
                    if checked_bool_vars.contains(&src.id) {
                        checked_bool_vars.insert(dest.id);
                    }
                }
                _ => {}
            }
        }
    }

    body.blocks.iter().any(|block| match &block.terminator {
        ir::IrTerminator::Branch { cond: ir::IrOperand::Var(cond), .. } => checked_bool_vars.contains(&cond.id),
        _ => false,
    })
}

fn launch_distribution_amount_count(ty: &ir::IrType) -> Option<usize> {
    let ir::IrType::Array(inner, len) = ty else {
        return None;
    };
    let ir::IrType::Tuple(items) = inner.as_ref() else {
        return None;
    };
    if items.len() == 2 && items.get(1) == Some(&ir::IrType::U64) && type_static_length(inner.as_ref()).is_some() {
        Some(*len)
    } else {
        None
    }
}

fn launch_u64_sources(operand: &ir::IrOperand, sources: &HashMap<usize, BTreeSet<String>>) -> Option<BTreeSet<String>> {
    match operand {
        ir::IrOperand::Var(var) => sources.get(&var.id).cloned(),
        ir::IrOperand::Const(ir::IrConst::U64(_)) => Some(BTreeSet::new()),
        _ => None,
    }
}

fn launch_distribution_allocation_comparison_is_checked(
    op: ast::BinaryOp,
    left_sources: &BTreeSet<String>,
    right_sources: &BTreeSet<String>,
    required_left_sources: &BTreeSet<String>,
    initial_mint_sources: &BTreeSet<String>,
) -> bool {
    match op {
        ast::BinaryOp::Le => left_sources == required_left_sources && right_sources == initial_mint_sources,
        ast::BinaryOp::Ge => left_sources == initial_mint_sources && right_sources == required_left_sources,
        _ => false,
    }
}

fn launch_param_source(name: &str) -> String {
    format!("param:{name}")
}

fn launch_distribution_amount_source(index: usize) -> String {
    format!("distribution[{index}].1")
}

fn create_field_matches_param(
    pattern: &ir::CreatePattern,
    field: &str,
    param_name: &str,
    params: &[ir::IrParam],
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
    byte_len: usize,
) -> bool {
    if !metadata_can_verify_create_output_fields(pattern, type_layouts, availability) {
        return false;
    }
    let Some(field_operand) = create_pattern_field_operand(pattern, field) else {
        return false;
    };
    let Some(param_operand) = param_operand(params, param_name) else {
        return false;
    };

    metadata_fixed_value_available_with_width(field_operand, availability, byte_len)
        && metadata_fixed_value_available_with_width(&param_operand, availability, byte_len)
        && ir_operands_same_verifier_source(field_operand, &param_operand)
}

fn operand_matches_param(operand: &ir::IrOperand, params: &[ir::IrParam], param_name: &str) -> bool {
    param_operand(params, param_name).is_some_and(|param_operand| ir_operands_same_verifier_source(operand, &param_operand))
}

fn operand_matches_var_id(operand: &ir::IrOperand, var_id: usize) -> bool {
    matches!(operand, ir::IrOperand::Var(var) if var.id == var_id)
}

fn param_field_has_fixed_width(
    params: &[ir::IrParam],
    param_name: &str,
    field: &str,
    type_layouts: &MetadataTypeLayouts,
    expected_width: usize,
) -> bool {
    let Some(param) = params.iter().find(|param| param.name == param_name) else {
        return false;
    };
    let Some(type_name) = named_type_name(&param.ty) else {
        return false;
    };
    type_field_has_fixed_width(type_layouts, type_name, field, expected_width)
}

fn type_field_has_fixed_width(type_layouts: &MetadataTypeLayouts, type_name: &str, field: &str, expected_width: usize) -> bool {
    type_layouts
        .get(type_name)
        .and_then(|fields| fields.get(field))
        .and_then(metadata_layout_fixed_byte_width)
        .is_some_and(|width| width == expected_width)
}

fn tuple_return_field_is_projected(body: &ir::IrBody, tuple_var_id: usize, field_name: &str) -> bool {
    body.blocks.iter().flat_map(|block| &block.instructions).any(|instruction| {
        matches!(
            instruction,
            ir::IrInstruction::FieldAccess {
                obj: ir::IrOperand::Var(obj),
                field,
                ..
            } if obj.id == tuple_var_id && field == field_name
        )
    })
}

fn param_operand(params: &[ir::IrParam], name: &str) -> Option<ir::IrOperand> {
    params.iter().find(|param| param.name == name).map(|param| ir::IrOperand::Var(param.binding.clone()))
}

fn create_pattern_field_operand<'a>(pattern: &'a ir::CreatePattern, name: &str) -> Option<&'a ir::IrOperand> {
    pattern.fields.iter().find_map(|(field, operand)| (field == name).then_some(operand))
}

fn operand_var_name(operand: &ir::IrOperand) -> Option<&str> {
    match operand {
        ir::IrOperand::Var(var) => Some(var.name.as_str()),
        ir::IrOperand::Const(_) => None,
    }
}

fn ir_operands_same_verifier_source(left: &ir::IrOperand, right: &ir::IrOperand) -> bool {
    match (left, right) {
        (ir::IrOperand::Var(left), ir::IrOperand::Var(right)) => left.id == right.id,
        (ir::IrOperand::Const(left), ir::IrOperand::Const(right)) => ir_consts_equal(left, right),
        _ => false,
    }
}

fn ir_consts_equal(left: &ir::IrConst, right: &ir::IrConst) -> bool {
    match (left, right) {
        (ir::IrConst::Unit, ir::IrConst::Unit) => true,
        (ir::IrConst::U8(left), ir::IrConst::U8(right)) => left == right,
        (ir::IrConst::U16(left), ir::IrConst::U16(right)) => left == right,
        (ir::IrConst::U32(left), ir::IrConst::U32(right)) => left == right,
        (ir::IrConst::U64(left), ir::IrConst::U64(right)) => left == right,
        (ir::IrConst::U128(left), ir::IrConst::U128(right)) => left == right,
        (ir::IrConst::Bool(left), ir::IrConst::Bool(right)) => left == right,
        (ir::IrConst::Address(left), ir::IrConst::Address(right)) => left == right,
        (ir::IrConst::Hash(left), ir::IrConst::Hash(right)) => left == right,
        (ir::IrConst::Array(left), ir::IrConst::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right.iter()).all(|(left, right)| ir_consts_equal(left, right))
        }
        _ => false,
    }
}

fn pool_runtime_required_components(name: &str, operation: &str, checked_protocol_components: &[String]) -> Vec<String> {
    let components = match operation {
        "create" => &[
            "token-pair-symbol-admission",
            "token-pair-identity-admission",
            "positive-reserve-admission",
            "fee-policy",
            "lp-supply-invariant",
        ][..],
        "mutation-invariants" => match name {
            "swap_a_for_b" => &[
                "reserve-conservation",
                "fee-accounting",
                "constant-product-pricing",
                "lp-supply-consistency",
                "pool-specific-admission",
            ][..],
            "add_liquidity" => {
                &["reserve-conservation", "proportional-liquidity-accounting", "lp-supply-consistency", "pool-specific-admission"][..]
            }
            "remove_liquidity" => {
                &["reserve-conservation", "proportional-withdrawal-accounting", "lp-supply-consistency", "pool-specific-admission"][..]
            }
            _ => &["reserve-conservation", "fee-accounting", "lp-supply-consistency", "pool-specific-admission"][..],
        },
        "composition" => &["callee-pool-admission", "launch-pool-atomicity", "pool-id-continuity"][..],
        _ => &[][..],
    };
    components
        .iter()
        .filter(|component| !checked_protocol_components.iter().any(|checked| checked == **component))
        .map(|component| (*component).to_string())
        .collect()
}

fn pool_runtime_input_requirements(
    name: &str,
    operation: &str,
    body: &ir::IrBody,
    params: &[ir::IrParam],
    checked_protocol_components: &[String],
) -> Vec<PoolRuntimeInputRequirementMetadata> {
    let mut requirements = match (operation, name) {
        ("create", "seed_pool") => pool_seed_token_pair_identity_runtime_inputs(body),
        ("mutation-invariants", "swap_a_for_b") => pool_swap_a_for_b_runtime_inputs(body),
        ("mutation-invariants", "add_liquidity") => pool_add_liquidity_runtime_inputs(body),
        ("mutation-invariants", "remove_liquidity") => pool_remove_liquidity_runtime_inputs(body),
        ("composition", "launch_token") => pool_launch_token_composition_runtime_inputs(body, params),
        _ => Vec::new(),
    };
    requirements.retain(|requirement| !checked_protocol_components.iter().any(|component| component == &requirement.component));
    requirements
}

fn pool_seed_token_pair_identity_runtime_inputs(body: &ir::IrBody) -> Vec<PoolRuntimeInputRequirementMetadata> {
    ["token_a", "token_b"]
        .into_iter()
        .filter_map(|binding| {
            body.consume_set.iter().enumerate().find(|(_, pattern)| pattern.operation == "consume" && pattern.binding == binding).map(
                |(index, pattern)| PoolRuntimeInputRequirementMetadata {
                    component: "token-pair-identity-admission".to_string(),
                    source: "Input".to_string(),
                    index,
                    binding: pattern.binding.clone(),
                    field: None,
                    abi: "input-type-id-32".to_string(),
                    byte_len: 32,
                    blocker: Some(pool_runtime_protocol_component_blocker("token-pair-identity-admission").to_string()),
                    blocker_class: Some(pool_runtime_protocol_component_blocker_class("token-pair-identity-admission").to_string()),
                },
            )
        })
        .collect()
}

fn pool_swap_a_for_b_runtime_inputs(body: &ir::IrBody) -> Vec<PoolRuntimeInputRequirementMetadata> {
    let mut requirements = Vec::new();
    let Some((input_index, input_pattern)) = consumed_input_pattern(body, "input") else {
        return requirements;
    };
    let Some(pool_pattern) = body.mutate_set.iter().find(|pattern| pattern.binding == "pool" && pattern.ty == "Pool") else {
        return requirements;
    };

    requirements.push(pool_runtime_field_requirement(
        "pool-specific-admission",
        "Input",
        input_index,
        &input_pattern.binding,
        "symbol",
        "input-cell-field-bytes-8",
        8,
    ));
    for field in ["token_a_symbol", "token_b_symbol"] {
        requirements.push(pool_runtime_field_requirement(
            "pool-specific-admission",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-bytes-8",
            8,
        ));
    }
    if let Some((token_index, token_pattern)) = created_output_pattern(body, "create_Token", "Token") {
        requirements.push(pool_runtime_field_requirement(
            "pool-specific-admission",
            "Output",
            token_index,
            &token_pattern.binding,
            "symbol",
            "create-output-field-bytes-8",
            8,
        ));
    }

    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Input",
        pool_pattern.input_index,
        &pool_pattern.binding,
        "total_lp",
        "mutate-input-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Output",
        pool_pattern.output_index,
        &pool_pattern.binding,
        "total_lp",
        "mutate-output-field-u64",
        8,
    ));

    requirements.push(pool_runtime_field_requirement(
        "reserve-conservation",
        "Input",
        input_index,
        &input_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));
    for field in ["reserve_a", "reserve_b"] {
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-u64",
            8,
        ));
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Output",
            pool_pattern.output_index,
            &pool_pattern.binding,
            field,
            "mutate-output-field-u64",
            8,
        ));
    }
    if let Some((token_index, token_pattern)) = created_output_pattern(body, "create_Token", "Token") {
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Output",
            token_index,
            &token_pattern.binding,
            "amount",
            "create-output-field-u64",
            8,
        ));
    }

    requirements.push(pool_runtime_field_requirement(
        "fee-accounting",
        "Input",
        input_index,
        &input_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "fee-accounting",
        "Input",
        pool_pattern.input_index,
        &pool_pattern.binding,
        "fee_rate_bps",
        "mutate-input-field-u16",
        2,
    ));

    for field in ["reserve_a", "reserve_b"] {
        requirements.push(pool_runtime_field_requirement(
            "constant-product-pricing",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-u64",
            8,
        ));
        requirements.push(pool_runtime_field_requirement(
            "constant-product-pricing",
            "Output",
            pool_pattern.output_index,
            &pool_pattern.binding,
            field,
            "mutate-output-field-u64",
            8,
        ));
    }
    requirements.push(pool_runtime_field_requirement(
        "constant-product-pricing",
        "Input",
        input_index,
        &input_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));

    requirements
}

fn pool_add_liquidity_runtime_inputs(body: &ir::IrBody) -> Vec<PoolRuntimeInputRequirementMetadata> {
    let mut requirements = Vec::new();
    let Some((token_a_index, token_a_pattern)) = consumed_input_pattern(body, "token_a") else {
        return requirements;
    };
    let Some((token_b_index, token_b_pattern)) = consumed_input_pattern(body, "token_b") else {
        return requirements;
    };
    let Some(pool_pattern) = body.mutate_set.iter().find(|pattern| pattern.binding == "pool" && pattern.ty == "Pool") else {
        return requirements;
    };

    requirements.push(pool_runtime_field_requirement(
        "pool-specific-admission",
        "Input",
        token_a_index,
        &token_a_pattern.binding,
        "symbol",
        "input-cell-field-bytes-8",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "pool-specific-admission",
        "Input",
        token_b_index,
        &token_b_pattern.binding,
        "symbol",
        "input-cell-field-bytes-8",
        8,
    ));
    for field in ["token_a_symbol", "token_b_symbol"] {
        requirements.push(pool_runtime_field_requirement(
            "pool-specific-admission",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-bytes-8",
            8,
        ));
    }
    requirements.push(pool_runtime_field_requirement(
        "pool-specific-admission",
        "Input",
        pool_pattern.input_index,
        &pool_pattern.binding,
        "type_hash",
        "mutate-input-type-id-32",
        32,
    ));
    if let Some((receipt_index, receipt_pattern)) = created_output_pattern(body, "create_LPReceipt", "LPReceipt") {
        requirements.push(pool_runtime_field_requirement(
            "pool-specific-admission",
            "Output",
            receipt_index,
            &receipt_pattern.binding,
            "pool_id",
            "create-output-field-hash-32",
            32,
        ));
    }

    requirements.push(pool_runtime_field_requirement(
        "reserve-conservation",
        "Input",
        token_a_index,
        &token_a_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "reserve-conservation",
        "Input",
        token_b_index,
        &token_b_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));
    for field in ["reserve_a", "reserve_b"] {
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-u64",
            8,
        ));
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Output",
            pool_pattern.output_index,
            &pool_pattern.binding,
            field,
            "mutate-output-field-u64",
            8,
        ));
    }

    requirements.push(pool_runtime_field_requirement(
        "proportional-liquidity-accounting",
        "Input",
        token_a_index,
        &token_a_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "proportional-liquidity-accounting",
        "Input",
        token_b_index,
        &token_b_pattern.binding,
        "amount",
        "input-cell-field-u64",
        8,
    ));
    for field in ["reserve_a", "reserve_b", "total_lp"] {
        requirements.push(pool_runtime_field_requirement(
            "proportional-liquidity-accounting",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-u64",
            8,
        ));
        requirements.push(pool_runtime_field_requirement(
            "proportional-liquidity-accounting",
            "Output",
            pool_pattern.output_index,
            &pool_pattern.binding,
            field,
            "mutate-output-field-u64",
            8,
        ));
    }

    if let Some((receipt_index, receipt_pattern)) = created_output_pattern(body, "create_LPReceipt", "LPReceipt") {
        requirements.push(pool_runtime_field_requirement(
            "proportional-liquidity-accounting",
            "Output",
            receipt_index,
            &receipt_pattern.binding,
            "lp_amount",
            "create-output-field-u64",
            8,
        ));
        requirements.push(pool_runtime_field_requirement(
            "lp-supply-consistency",
            "Output",
            receipt_index,
            &receipt_pattern.binding,
            "lp_amount",
            "create-output-field-u64",
            8,
        ));
    }
    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Input",
        pool_pattern.input_index,
        &pool_pattern.binding,
        "total_lp",
        "mutate-input-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Output",
        pool_pattern.output_index,
        &pool_pattern.binding,
        "total_lp",
        "mutate-output-field-u64",
        8,
    ));

    requirements
}

fn pool_remove_liquidity_runtime_inputs(body: &ir::IrBody) -> Vec<PoolRuntimeInputRequirementMetadata> {
    let mut requirements = Vec::new();
    let Some((receipt_index, receipt_pattern)) = consumed_input_pattern(body, "receipt") else {
        return requirements;
    };
    let Some(pool_pattern) = body.mutate_set.iter().find(|pattern| pattern.binding == "pool" && pattern.ty == "Pool") else {
        return requirements;
    };

    requirements.push(pool_runtime_field_requirement(
        "pool-specific-admission",
        "Input",
        receipt_index,
        &receipt_pattern.binding,
        "pool_id",
        "input-cell-field-hash-32",
        32,
    ));
    requirements.push(pool_runtime_field_requirement(
        "pool-specific-admission",
        "Input",
        pool_pattern.input_index,
        &pool_pattern.binding,
        "type_hash",
        "mutate-input-type-id-32",
        32,
    ));
    for field in ["token_a_symbol", "token_b_symbol"] {
        requirements.push(pool_runtime_field_requirement(
            "pool-specific-admission",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-bytes-8",
            8,
        ));
    }
    for (token_index, token_pattern) in
        body.create_set.iter().enumerate().filter(|(_, pattern)| pattern.operation == "create" && pattern.ty == "Token").take(2)
    {
        requirements.push(pool_runtime_field_requirement(
            "pool-specific-admission",
            "Output",
            token_index,
            &token_pattern.binding,
            "symbol",
            "create-output-field-bytes-8",
            8,
        ));
    }

    for field in ["reserve_a", "reserve_b"] {
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-u64",
            8,
        ));
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Output",
            pool_pattern.output_index,
            &pool_pattern.binding,
            field,
            "mutate-output-field-u64",
            8,
        ));
    }
    for (token_index, token_pattern) in
        body.create_set.iter().enumerate().filter(|(_, pattern)| pattern.operation == "create" && pattern.ty == "Token").take(2)
    {
        requirements.push(pool_runtime_field_requirement(
            "reserve-conservation",
            "Output",
            token_index,
            &token_pattern.binding,
            "amount",
            "create-output-field-u64",
            8,
        ));
    }

    requirements.push(pool_runtime_field_requirement(
        "proportional-withdrawal-accounting",
        "Input",
        receipt_index,
        &receipt_pattern.binding,
        "lp_amount",
        "input-cell-field-u64",
        8,
    ));
    for field in ["reserve_a", "reserve_b", "total_lp"] {
        requirements.push(pool_runtime_field_requirement(
            "proportional-withdrawal-accounting",
            "Input",
            pool_pattern.input_index,
            &pool_pattern.binding,
            field,
            "mutate-input-field-u64",
            8,
        ));
    }
    for field in ["reserve_a", "reserve_b"] {
        requirements.push(pool_runtime_field_requirement(
            "proportional-withdrawal-accounting",
            "Output",
            pool_pattern.output_index,
            &pool_pattern.binding,
            field,
            "mutate-output-field-u64",
            8,
        ));
    }
    for (token_index, token_pattern) in
        body.create_set.iter().enumerate().filter(|(_, pattern)| pattern.operation == "create" && pattern.ty == "Token").take(2)
    {
        requirements.push(pool_runtime_field_requirement(
            "proportional-withdrawal-accounting",
            "Output",
            token_index,
            &token_pattern.binding,
            "amount",
            "create-output-field-u64",
            8,
        ));
    }

    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Input",
        receipt_index,
        &receipt_pattern.binding,
        "lp_amount",
        "input-cell-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Input",
        pool_pattern.input_index,
        &pool_pattern.binding,
        "total_lp",
        "mutate-input-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "lp-supply-consistency",
        "Output",
        pool_pattern.output_index,
        &pool_pattern.binding,
        "total_lp",
        "mutate-output-field-u64",
        8,
    ));

    requirements
}

fn pool_launch_token_composition_runtime_inputs(
    body: &ir::IrBody,
    params: &[ir::IrParam],
) -> Vec<PoolRuntimeInputRequirementMetadata> {
    let mut requirements = Vec::new();
    let Some((auth_index, auth_pattern)) = created_output_pattern(body, "create_MintAuthority", "MintAuthority") else {
        return requirements;
    };
    let Some((pool_seed_index, pool_seed_pattern)) = last_created_output_pattern(body, "Token") else {
        return requirements;
    };

    requirements.push(pool_runtime_field_requirement(
        "callee-pool-admission",
        "Output",
        pool_seed_index,
        &pool_seed_pattern.binding,
        "type_hash",
        "create-output-type-id-32",
        32,
    ));
    if let Some((paired_index, paired_param)) = param_pattern(params, "pool_paired_token") {
        requirements.push(pool_runtime_field_requirement(
            "callee-pool-admission",
            "Param",
            paired_index,
            &paired_param.name,
            "type_hash",
            "schema-param-type-id-32",
            32,
        ));
        requirements.push(pool_runtime_field_requirement(
            "callee-pool-admission",
            "Param",
            paired_index,
            &paired_param.name,
            "symbol",
            "schema-param-field-bytes-8",
            8,
        ));
    }
    requirements.push(pool_runtime_field_requirement(
        "callee-pool-admission",
        "Output",
        pool_seed_index,
        &pool_seed_pattern.binding,
        "symbol",
        "create-output-field-bytes-8",
        8,
    ));
    if let Some((fee_index, fee_param)) = param_pattern(params, "fee_rate_bps") {
        requirements.push(pool_runtime_value_requirement(
            "callee-pool-admission",
            "Param",
            fee_index,
            &fee_param.name,
            "param-u16",
            2,
        ));
    }

    if let Some((initial_index, initial_param)) = param_pattern(params, "initial_mint") {
        requirements.push(pool_runtime_value_requirement(
            "launch-pool-atomicity",
            "Param",
            initial_index,
            &initial_param.name,
            "param-u64",
            8,
        ));
    }
    if let Some((seed_amount_index, seed_amount_param)) = param_pattern(params, "pool_seed_amount") {
        requirements.push(pool_runtime_value_requirement(
            "launch-pool-atomicity",
            "Param",
            seed_amount_index,
            &seed_amount_param.name,
            "param-u64",
            8,
        ));
    }
    if let Some((distribution_index, distribution_param)) = param_pattern(params, "distribution") {
        requirements.push(pool_runtime_value_requirement(
            "launch-pool-atomicity",
            "Param",
            distribution_index,
            &distribution_param.name,
            "param-fixed-array-bytes-160",
            160,
        ));
    }
    requirements.push(pool_runtime_field_requirement(
        "launch-pool-atomicity",
        "Output",
        auth_index,
        &auth_pattern.binding,
        "minted",
        "create-output-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "launch-pool-atomicity",
        "Output",
        auth_index,
        &auth_pattern.binding,
        "token_symbol",
        "create-output-field-bytes-8",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "launch-pool-atomicity",
        "Output",
        pool_seed_index,
        &pool_seed_pattern.binding,
        "amount",
        "create-output-field-u64",
        8,
    ));
    requirements.push(pool_runtime_field_requirement(
        "launch-pool-atomicity",
        "Output",
        pool_seed_index,
        &pool_seed_pattern.binding,
        "symbol",
        "create-output-field-bytes-8",
        8,
    ));

    if let Some((return_index, return_binding)) = pool_call_return_binding(body, "seed_pool") {
        requirements.push(pool_runtime_field_requirement(
            "pool-id-continuity",
            "CallReturn",
            return_index,
            return_binding,
            "0.type_hash",
            "tuple-call-return-field-type-id-32",
            32,
        ));
        requirements.push(pool_runtime_field_requirement(
            "pool-id-continuity",
            "CallReturn",
            return_index + 1,
            return_binding,
            "1.pool_id",
            "tuple-call-return-field-hash-32",
            32,
        ));
        requirements.push(pool_runtime_field_requirement(
            "pool-id-continuity",
            "CallReturnPair",
            return_index,
            return_binding,
            "0.type_hash == 1.pool_id",
            "tuple-call-return-field-equality-32",
            32,
        ));
    }

    requirements
}

fn consumed_input_pattern<'a>(body: &'a ir::IrBody, binding: &str) -> Option<(usize, &'a ir::CellPattern)> {
    body.consume_set.iter().enumerate().find(|(_, pattern)| pattern.operation == "consume" && pattern.binding == binding)
}

fn created_output_pattern<'a>(body: &'a ir::IrBody, binding: &str, ty: &str) -> Option<(usize, &'a ir::CreatePattern)> {
    body.create_set
        .iter()
        .enumerate()
        .find(|(_, pattern)| pattern.operation == "create" && pattern.binding == binding && pattern.ty == ty)
}

fn last_created_output_pattern<'a>(body: &'a ir::IrBody, ty: &str) -> Option<(usize, &'a ir::CreatePattern)> {
    body.create_set.iter().enumerate().rev().find(|(_, pattern)| pattern.operation == "create" && pattern.ty == ty)
}

fn last_created_output_var_id(body: &ir::IrBody, ty: &str) -> Option<usize> {
    body.blocks.iter().rev().flat_map(|block| block.instructions.iter().rev()).find_map(|instruction| match instruction {
        ir::IrInstruction::Create { dest, pattern } if pattern.operation == "create" && pattern.ty == ty => Some(dest.id),
        _ => None,
    })
}

fn param_pattern<'a>(params: &'a [ir::IrParam], name: &str) -> Option<(usize, &'a ir::IrParam)> {
    params.iter().enumerate().find(|(_, param)| param.name == name)
}

fn pool_call_return_binding<'a>(body: &'a ir::IrBody, func: &str) -> Option<(usize, &'a str)> {
    body.blocks.iter().flat_map(|block| &block.instructions).find_map(|instruction| match instruction {
        ir::IrInstruction::Call { dest: Some(dest), func: call_func, .. } if call_func == func => Some((0, dest.name.as_str())),
        _ => None,
    })
}

fn pool_runtime_field_requirement(
    component: &str,
    source: &str,
    index: usize,
    binding: &str,
    field: &str,
    abi: &str,
    byte_len: usize,
) -> PoolRuntimeInputRequirementMetadata {
    PoolRuntimeInputRequirementMetadata {
        component: component.to_string(),
        source: source.to_string(),
        index,
        binding: binding.to_string(),
        field: Some(field.to_string()),
        abi: abi.to_string(),
        byte_len,
        blocker: Some(pool_runtime_protocol_component_blocker(component).to_string()),
        blocker_class: Some(pool_runtime_protocol_component_blocker_class(component).to_string()),
    }
}

fn pool_runtime_value_requirement(
    component: &str,
    source: &str,
    index: usize,
    binding: &str,
    abi: &str,
    byte_len: usize,
) -> PoolRuntimeInputRequirementMetadata {
    PoolRuntimeInputRequirementMetadata {
        component: component.to_string(),
        source: source.to_string(),
        index,
        binding: binding.to_string(),
        field: None,
        abi: abi.to_string(),
        byte_len,
        blocker: Some(pool_runtime_protocol_component_blocker(component).to_string()),
        blocker_class: Some(pool_runtime_protocol_component_blocker_class(component).to_string()),
    }
}

fn pool_invariant_families(
    checked_invariant_guards: &[String],
    checked_protocol_components: &[String],
    runtime_required_components: &[String],
    runtime_source: &str,
) -> Vec<PoolInvariantMetadata> {
    let mut families = Vec::new();
    let mut seen = BTreeSet::new();

    for guard in checked_invariant_guards {
        if seen.insert(guard.clone()) {
            families.push(PoolInvariantMetadata {
                name: guard.clone(),
                status: "checked-runtime".to_string(),
                source: "assert-invariant-cfg".to_string(),
                blocker: None,
                blocker_class: None,
            });
        }
    }

    for component in checked_protocol_components {
        if seen.insert(component.clone()) {
            families.push(PoolInvariantMetadata {
                name: component.clone(),
                status: "checked-runtime".to_string(),
                source: pool_checked_protocol_component_source(component).to_string(),
                blocker: None,
                blocker_class: None,
            });
        }
    }

    for component in runtime_required_components {
        if seen.insert(component.clone()) {
            families.push(PoolInvariantMetadata {
                name: component.clone(),
                status: "runtime-required".to_string(),
                source: pool_runtime_protocol_component_source(component, runtime_source).to_string(),
                blocker: Some(pool_runtime_protocol_component_blocker(component).to_string()),
                blocker_class: Some(pool_runtime_protocol_component_blocker_class(component).to_string()),
            });
        }
    }

    families
}

fn pool_checked_protocol_component_source(component: &str) -> &'static str {
    match component {
        "token-pair-identity-admission" => "input-type-id-abi+load-cell-by-field",
        "token-pair-symbol-admission" => "assert-invariant-cfg+create-output-symbol-fields",
        "lp-supply-invariant" => "create-output-field-coupling",
        "lp-supply-consistency" => "mutate-preserved-field-equality",
        "reserve-conservation" => "transition-formula",
        "pool-id-continuity" => "callee-output-field-coupling+tuple-return-abi",
        _ => "assert-invariant-cfg+create-output-fields",
    }
}

fn pool_runtime_protocol_component_source<'a>(component: &str, default_source: &'a str) -> &'a str {
    match component {
        "token-pair-identity-admission" => "token-input-type-id-abi",
        "fee-accounting" => "swap-fee-accounting-abi",
        "constant-product-pricing" => "swap-constant-product-abi",
        "proportional-liquidity-accounting" => "add-liquidity-proportional-abi",
        "proportional-withdrawal-accounting" => "remove-liquidity-proportional-withdrawal-abi",
        "lp-supply-consistency" => "pool-lp-supply-consistency-abi",
        "reserve-conservation" => "pool-reserve-conservation-abi",
        "pool-specific-admission" => "pool-specific-admission-abi",
        "callee-pool-admission" => "pool-composition-callee-admission-abi",
        "launch-pool-atomicity" => "launch-pool-atomicity-abi",
        "pool-id-continuity" => "pool-id-continuity-abi",
        _ => default_source,
    }
}

fn pool_runtime_protocol_component_blocker(component: &str) -> &'static str {
    match component {
        "token-pair-symbol-admission" | "token-pair-identity-admission" | "positive-reserve-admission" => {
            "deferred beyond Phase 2 controlled-flow boundary: generalized Pool admission requires protocol policy over concrete asset identities and reserve context"
        }
        "fee-policy" => {
            "deferred beyond Phase 2 controlled-flow boundary: generalized Pool fee policy requires protocol-level fee configuration and admission rules"
        }
        "lp-supply-invariant" | "lp-supply-consistency" => {
            "deferred beyond Phase 2 controlled-flow boundary: generalized LP supply accounting requires protocol formula verification across LP receipts and Pool totals"
        }
        "reserve-conservation" => {
            "deferred beyond Phase 2 controlled-flow boundary: AMM reserve conservation requires verifier-covered field transition formula over reserve state changes"
        }
        "fee-accounting" => {
            "deferred beyond Phase 2 controlled-flow boundary: AMM fee accounting requires protocol formula verification over input amount and pool fee fields"
        }
        "constant-product-pricing" => {
            "deferred beyond Phase 2 controlled-flow boundary: constant-product pricing requires protocol formula verification over pre/post reserve state"
        }
        "proportional-liquidity-accounting" => {
            "deferred beyond Phase 2 controlled-flow boundary: proportional liquidity accounting requires protocol formula verification over deposits, reserves, and minted LP amount"
        }
        "proportional-withdrawal-accounting" => {
            "deferred beyond Phase 2 controlled-flow boundary: proportional withdrawal accounting requires protocol formula verification over burned LP amount and created token outputs"
        }
        "pool-specific-admission" | "callee-pool-admission" => {
            "deferred beyond Phase 2 controlled-flow boundary: generalized Pool admission requires protocol-specific asset/type-id matching rules"
        }
        "launch-pool-atomicity" => {
            "deferred beyond Phase 2 controlled-flow boundary: launch/pool atomicity belongs to post-v1 transaction-builder policy"
        }
        "pool-id-continuity" => {
            "deferred beyond Phase 2 controlled-flow boundary: generalized Pool identity continuity requires transaction-builder/callee output binding policy"
        }
        _ => "deferred beyond Phase 2 controlled-flow boundary: unresolved Pool pattern policy requires protocol/runtime verification",
    }
}

fn pool_runtime_protocol_component_blocker_class(component: &str) -> &'static str {
    match component {
        "token-pair-symbol-admission"
        | "token-pair-identity-admission"
        | "positive-reserve-admission"
        | "pool-specific-admission"
        | "callee-pool-admission" => "phase2-deferred-pool-admission",
        "fee-policy" | "fee-accounting" => "phase2-deferred-pool-fee-policy",
        "lp-supply-invariant" | "lp-supply-consistency" => "phase2-deferred-lp-supply-policy",
        "reserve-conservation" => "phase2-deferred-amm-reserve-conservation",
        "constant-product-pricing" => "phase2-deferred-amm-pricing",
        "proportional-liquidity-accounting" => "phase2-deferred-amm-liquidity-accounting",
        "proportional-withdrawal-accounting" => "phase2-deferred-amm-withdrawal-accounting",
        "launch-pool-atomicity" => "phase2-deferred-launch-atomicity",
        "pool-id-continuity" => "phase2-deferred-pool-id-continuity",
        _ => "phase2-deferred-pool-pattern-policy",
    }
}

fn body_pool_primitive_obligations(pool_primitives: &[PoolPrimitiveMetadata]) -> Vec<TransactionResourceObligation> {
    pool_primitives
        .iter()
        .map(|primitive| TransactionResourceObligation {
            category: "pool-pattern",
            feature: primitive.feature.clone(),
            status: pool_primitive_status_literal(primitive.status.as_str()),
            detail: pool_primitive_obligation_detail(primitive),
        })
        .collect()
}

fn pool_primitive_status_literal(status: &str) -> &'static str {
    if status == "checked-runtime" {
        "checked-runtime"
    } else {
        "runtime-required"
    }
}

fn pool_primitive_obligation_detail(primitive: &PoolPrimitiveMetadata) -> String {
    let unresolved_detail = if primitive.runtime_required_components.is_empty() {
        "all pool_primitives[].invariant_families are checked-runtime".to_string()
    } else {
        format!("unresolved components: {}", primitive.runtime_required_components.join(", "))
    };
    match primitive.operation.as_str() {
        "create" => format!(
            "'{}' creation is lowered as ordinary shared Cell creation plus pool-pattern metadata; {}",
            primitive.ty, unresolved_detail
        ),
        "mutation-invariants" => format!(
            "Generic shared mutation checks for '{}' prove replacement identity and source-level field transitions; {}",
            primitive.ty, unresolved_detail
        ),
        "composition" => format!(
            "Call '{}' returns or contains '{}'; caller metadata preserves scheduler visibility and tracks pool-pattern composition; {}",
            primitive.callee.as_deref().unwrap_or("<unknown>"),
            primitive.ty,
            unresolved_detail
        ),
        _ => format!("Pool-pattern primitive '{}' reports {}", primitive.feature, unresolved_detail),
    }
}

fn body_assert_invariant_count(body: &ir::IrBody) -> usize {
    body.blocks
        .iter()
        .filter(|block| {
            let ir::IrTerminator::Branch { else_block, .. } = &block.terminator else {
                return false;
            };
            body.blocks.iter().find(|candidate| candidate.id == *else_block).is_some_and(|candidate| {
                matches!(candidate.terminator, ir::IrTerminator::Return(Some(ir::IrOperand::Const(ir::IrConst::U64(7)))))
            })
        })
        .count()
}

fn is_pool_pattern_candidate(type_name: &str, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    type_name == "Pool" && cell_type_kinds.get(type_name) == Some(&ir::IrTypeKind::Shared)
}

fn pool_pattern_candidate_type_names(ty: &ir::IrType, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> Vec<String> {
    let mut names = BTreeSet::new();
    collect_pool_pattern_candidate_type_names(ty, cell_type_kinds, &mut names);
    names.into_iter().collect()
}

fn collect_pool_pattern_candidate_type_names(
    ty: &ir::IrType,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    names: &mut BTreeSet<String>,
) {
    match ty {
        ir::IrType::Named(name) if is_pool_pattern_candidate(name, cell_type_kinds) => {
            names.insert(name.clone());
        }
        ir::IrType::Array(inner, _) | ir::IrType::Ref(inner) | ir::IrType::MutRef(inner) => {
            collect_pool_pattern_candidate_type_names(inner, cell_type_kinds, names);
        }
        ir::IrType::Tuple(items) => {
            for item in items {
                collect_pool_pattern_candidate_type_names(item, cell_type_kinds, names);
            }
        }
        _ => {}
    }
}

fn push_verifier_obligation(
    obligations: &mut Vec<VerifierObligationMetadata>,
    seen: &mut BTreeSet<(String, String, String, String)>,
    scope: &str,
    category: &str,
    feature: &str,
    status: &str,
    detail: &str,
) {
    let key = (scope.to_string(), category.to_string(), feature.to_string(), status.to_string());
    if seen.insert(key) {
        obligations.push(VerifierObligationMetadata {
            scope: scope.to_string(),
            category: category.to_string(),
            feature: feature.to_string(),
            status: status.to_string(),
            detail: detail.to_string(),
        });
    }
}

struct LifecycleTransitionCheck {
    feature: String,
    status: String,
    detail: String,
}

fn body_lifecycle_transition_checks(
    body: &ir::IrBody,
    lifecycle_states: &HashMap<String, Vec<String>>,
    type_layouts: &MetadataTypeLayouts,
    params: &[ir::IrParam],
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<LifecycleTransitionCheck> {
    let consumed_types = body_consumed_named_types(body);
    let param_schema_vars = schema_pointer_var_ids(body, params);
    let availability = metadata_prelude_availability(body, &param_schema_vars, type_layouts, params, pure_const_returns);
    let mut checks = Vec::new();
    let mut seen = BTreeSet::new();
    for pattern in &body.create_set {
        if pattern.operation == "settle" {
            continue;
        }
        if !lifecycle_states.contains_key(&pattern.ty) || !consumed_types.contains(&pattern.ty) {
            continue;
        }
        if !seen.insert(pattern.ty.clone()) {
            continue;
        }
        if metadata_can_verify_lifecycle_transition(pattern, type_layouts, &availability) {
            checks.push(LifecycleTransitionCheck {
                feature: pattern.ty.clone(),
                status: "checked-runtime".to_string(),
                detail: "Compiler emits runtime old_state + 1 and old/new state range checks, and the lifecycle output is already fully covered by the fixed-field verifier".to_string(),
            });
        } else {
            checks.push(LifecycleTransitionCheck {
                feature: pattern.ty.clone(),
                status: "checked-partial".to_string(),
                detail: "Compiler emits declaration/static checks, but this transition still lacks a complete fixed-field runtime verifier path".to_string(),
            });
        }
    }
    checks
}

fn metadata_can_verify_lifecycle_transition(
    pattern: &ir::CreatePattern,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    let Some(layouts) = type_layouts.get(&pattern.ty) else {
        return false;
    };
    if metadata_type_encoded_size_from_layouts(layouts).is_none() {
        return false;
    }
    let Some(state_layout) = layouts.get("state") else {
        return false;
    };
    if metadata_layout_fixed_scalar_width(state_layout).is_none() {
        return false;
    }
    metadata_can_verify_create_output_fields(pattern, type_layouts, availability)
}

fn metadata_type_encoded_size_from_layouts(layouts: &HashMap<String, MetadataFieldLayout>) -> Option<usize> {
    layouts.values().try_fold(0usize, |acc, layout| layout.fixed_size.map(|size| acc + size))
}

fn body_consumed_named_types(body: &ir::IrBody) -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            let operand = match instruction {
                ir::IrInstruction::Consume { operand }
                | ir::IrInstruction::Transfer { operand, .. }
                | ir::IrInstruction::Destroy { operand }
                | ir::IrInstruction::Settle { operand, .. } => Some(operand),
                ir::IrInstruction::Claim { receipt, .. } => Some(receipt),
                _ => None,
            };
            if let Some(ir::IrOperand::Var(var)) = operand {
                if let Some(type_name) = named_type_name(&var.ty) {
                    types.insert(type_name.to_string());
                }
            }
        }
    }
    types
}

fn operand_named_type_name(operand: &ir::IrOperand) -> Option<String> {
    match operand {
        ir::IrOperand::Var(var) => named_type_name(&var.ty).map(str::to_string),
        ir::IrOperand::Const(_) => None,
    }
}

fn module_has_entry_params(ir: &ir::IrModule) -> bool {
    ir.items.iter().any(|item| match item {
        ir::IrItem::Action(action) => !action.params.is_empty(),
        ir::IrItem::Lock(lock) => !lock.params.is_empty(),
        ir::IrItem::PureFn(_) => false,
        ir::IrItem::TypeDef(_) => false,
    })
}

fn body_symbolic_runtime_features(
    _body: &ir::IrBody,
    _param_schema_vars: &BTreeSet<usize>,
    _type_layouts: &MetadataTypeLayouts,
    _params: &[ir::IrParam],
    _cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    _return_type: Option<&ir::IrType>,
) -> Vec<String> {
    // All former symbolic operations now have real RISC-V lowerings or fail-closed
    // traps with specific error codes. No operation remains purely symbolic;
    // ELF emission is always valid.
    Vec::new()
}

fn body_fail_closed_runtime_features(
    body: &ir::IrBody,
    param_schema_vars: &BTreeSet<usize>,
    type_layouts: &MetadataTypeLayouts,
    params: &[ir::IrParam],
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    return_type: Option<&ir::IrType>,
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> Vec<String> {
    let mut features = BTreeSet::new();
    let prelude_availability = metadata_prelude_availability(body, param_schema_vars, type_layouts, params, pure_const_returns);
    if body.create_set.iter().any(|pattern| !metadata_can_verify_create_output_fields(pattern, type_layouts, &prelude_availability)) {
        features.insert("output-verification-incomplete".to_string());
    }
    if body.create_set.iter().any(|pattern| !metadata_can_verify_output_lock(pattern, &prelude_availability)) {
        features.insert("output-lock-verification-incomplete".to_string());
    }
    let mut output_index = 0usize;
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::FieldAccess { obj, field, .. } => {
                    if !is_executable_schema_field_access(obj, field, param_schema_vars, type_layouts)
                        && !is_executable_aggregate_field_access(obj, field, &prelude_availability, type_layouts)
                        && !is_executable_tuple_call_return_field_access(obj, field, &prelude_availability)
                    {
                        features.insert("field-access".to_string());
                    }
                }
                ir::IrInstruction::Binary { op: ast::BinaryOp::Eq | ast::BinaryOp::Ne, left, right, .. }
                    if (operand_fixed_byte_width(left).is_some() || operand_fixed_byte_width(right).is_some())
                        && !metadata_can_verify_fixed_byte_comparison(left, right, &prelude_availability) =>
                {
                    features.insert("fixed-byte-comparison".to_string());
                }
                ir::IrInstruction::Index { dest, arr, idx }
                    if !prelude_availability.aggregate_pointer_vars.contains_key(&dest.id)
                        && !prelude_availability.fixed_value_vars.contains(&dest.id)
                        && !prelude_availability.scalar_vars.contains(&dest.id)
                        && !metadata_stack_collection_index_is_runtime_supported(
                            dest,
                            arr,
                            idx,
                            &prelude_availability,
                            type_layouts,
                        ) =>
                {
                    features.insert("index-access".to_string());
                }
                ir::IrInstruction::Length { operand, .. }
                    if operand_static_length(operand).is_none()
                        && !metadata_dynamic_length_available(operand, &prelude_availability) =>
                {
                    features.insert("dynamic-length".to_string());
                }
                ir::IrInstruction::TypeHash { .. } => {
                    if !is_executable_output_type_hash(instruction, &prelude_availability) {
                        features.insert("type-hash".to_string());
                    }
                }
                ir::IrInstruction::CollectionNew { dest, .. } => {
                    if !prelude_availability.stack_collection_vars.contains(&dest.id)
                        && !metadata_collection_new_is_verified_create_value(dest.id, body, type_layouts, &prelude_availability)
                    {
                        features.insert("collection-new".to_string());
                    }
                }
                ir::IrInstruction::CollectionPush { collection, value } => {
                    if !metadata_collection_push_is_verified_append(collection, value, body, type_layouts)
                        && !metadata_collection_mutation_is_verified_create_vector(
                            collection,
                            value,
                            body,
                            type_layouts,
                            &prelude_availability,
                        )
                        && !metadata_stack_collection_push_is_runtime_supported(collection, value, &prelude_availability)
                    {
                        features.insert("collection-push".to_string());
                    }
                    if ir_operand_contains_cell_backed_value(value, cell_type_kinds) {
                        features.insert("cell-backed-collection-push".to_string());
                    }
                }
                ir::IrInstruction::CollectionExtend { collection, slice } => {
                    if !metadata_collection_mutation_is_verified_create_vector(
                        collection,
                        slice,
                        body,
                        type_layouts,
                        &prelude_availability,
                    ) && !metadata_stack_collection_extend_is_runtime_supported(
                        collection,
                        slice,
                        &prelude_availability,
                        type_layouts,
                    ) {
                        features.insert("collection-extend".to_string());
                    }
                    if ir_operand_is_cell_backed_collection(slice, cell_type_kinds) {
                        features.insert("cell-backed-collection-extend".to_string());
                    }
                }
                ir::IrInstruction::CollectionClear { collection } => {
                    if !metadata_stack_collection_clear_is_runtime_supported(collection, &prelude_availability) {
                        features.insert("collection-clear".to_string());
                    }
                    if ir_operand_is_cell_backed_collection(collection, cell_type_kinds) {
                        features.insert("cell-backed-collection-clear".to_string());
                    }
                }
                ir::IrInstruction::Consume { operand } if consumed_schema_var_id(instruction).is_none() => {
                    features.insert("consume-expression".to_string());
                    if matches!(operand, ir::IrOperand::Const(_)) {
                        features.insert("non-cell-consume".to_string());
                    }
                }
                ir::IrInstruction::Create { .. } => {
                    output_index += 1;
                }
                ir::IrInstruction::Transfer { dest, .. } => {
                    if !metadata_output_operation_is_verifier_covered(
                        body,
                        output_index,
                        "transfer",
                        dest,
                        type_layouts,
                        &prelude_availability,
                    ) {
                        features.insert("transfer-expression".to_string());
                    }
                    output_index += 1;
                }
                ir::IrInstruction::Destroy { operand } => {
                    if !is_executable_destroy(operand) {
                        features.insert("destroy-expression".to_string());
                    }
                }
                ir::IrInstruction::Claim { dest, .. } => {
                    if !metadata_output_operation_is_verifier_covered(
                        body,
                        output_index,
                        "claim",
                        dest,
                        type_layouts,
                        &prelude_availability,
                    ) {
                        features.insert("claim-expression".to_string());
                    }
                    output_index += 1;
                }
                ir::IrInstruction::Settle { dest, .. } => {
                    if !metadata_output_operation_is_verifier_covered(
                        body,
                        output_index,
                        "settle",
                        dest,
                        type_layouts,
                        &prelude_availability,
                    ) {
                        features.insert("settle-expression".to_string());
                    }
                    output_index += 1;
                }
                _ => {}
            }
        }
        if matches!(block.terminator, ir::IrTerminator::Return(Some(_)))
            && return_type.is_some_and(|ty| ir_type_is_cell_backed_collection(ty, cell_type_kinds))
        {
            features.insert("cell-backed-collection-return".to_string());
        }
    }
    features.into_iter().collect()
}

fn metadata_output_operation_is_verifier_covered(
    body: &ir::IrBody,
    output_index: usize,
    operation: &str,
    dest: &ir::IrVar,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    body.create_set.get(output_index).is_some_and(|pattern| {
        pattern.operation == operation
            && named_type_name(&dest.ty).is_some_and(|type_name| type_name == pattern.ty.as_str())
            && metadata_can_verify_create_output_fields(pattern, type_layouts, availability)
            && metadata_can_verify_output_lock(pattern, availability)
    })
}

#[derive(Debug, Default)]
struct MetadataPreludeAvailability {
    scalar_vars: HashSet<usize>,
    fixed_value_vars: HashSet<usize>,
    schema_pointer_vars: HashSet<usize>,
    empty_molecule_vector_vars: HashSet<usize>,
    stack_collection_vars: HashSet<usize>,
    constructed_byte_vector_vars: HashMap<usize, usize>,
    constructed_byte_vector_roots: HashMap<usize, usize>,
    u64_value_vars: HashSet<usize>,
    u64_operand_vars: HashSet<usize>,
    dynamic_collection_vars: HashSet<usize>,
    aggregate_pointer_vars: HashMap<usize, MetadataAggregatePointerSource>,
    tuple_call_return_vars: HashMap<usize, ir::IrType>,
    created_output_vars: HashMap<usize, usize>,
    output_type_hash_vars: HashSet<usize>,
    param_type_hash_vars: HashSet<usize>,
}

#[derive(Debug, Clone)]
struct MetadataAggregatePointerSource {
    ty: ir::IrType,
}

fn metadata_pure_const_returns(ir: &ir::IrModule) -> HashMap<String, ir::IrConst> {
    ir.items
        .iter()
        .filter_map(|item| {
            let ir::IrItem::PureFn(function) = item else {
                return None;
            };
            metadata_pure_const_return(&function.body).map(|value| (function.name.clone(), value))
        })
        .collect()
}

fn metadata_pure_const_return(body: &ir::IrBody) -> Option<ir::IrConst> {
    let [block] = body.blocks.as_slice() else {
        return None;
    };
    match (&block.instructions[..], &block.terminator) {
        ([], ir::IrTerminator::Return(Some(ir::IrOperand::Const(value)))) => Some(value.clone()),
        ([ir::IrInstruction::LoadConst { dest, value }], ir::IrTerminator::Return(Some(ir::IrOperand::Var(var))))
            if dest.id == var.id =>
        {
            Some(value.clone())
        }
        _ => None,
    }
}

fn metadata_prelude_availability(
    body: &ir::IrBody,
    param_schema_vars: &BTreeSet<usize>,
    type_layouts: &MetadataTypeLayouts,
    params: &[ir::IrParam],
    pure_const_returns: &HashMap<String, ir::IrConst>,
) -> MetadataPreludeAvailability {
    let mut availability = MetadataPreludeAvailability::default();
    let schema_param_ids =
        params.iter().filter(|param| named_type_name(&param.ty).is_some()).map(|param| param.binding.id).collect::<HashSet<_>>();
    availability.schema_pointer_vars.extend(schema_param_ids.iter().copied());

    for param in params {
        if metadata_fixed_scalar_size(&param.ty).is_some() {
            availability.scalar_vars.insert(param.binding.id);
            availability.fixed_value_vars.insert(param.binding.id);
            if param.ty == ir::IrType::U64 {
                availability.u64_value_vars.insert(param.binding.id);
                availability.u64_operand_vars.insert(param.binding.id);
            }
        } else if metadata_fixed_byte_width(&param.ty, type_static_length(&param.ty)).is_some() {
            availability.fixed_value_vars.insert(param.binding.id);
            if metadata_fixed_byte_width(&param.ty, type_static_length(&param.ty)).is_some_and(|width| width > 8) {
                availability.aggregate_pointer_vars.insert(param.binding.id, MetadataAggregatePointerSource { ty: param.ty.clone() });
            }
        } else if metadata_fixed_aggregate_pointer_size(&param.ty).is_some() {
            availability.aggregate_pointer_vars.insert(param.binding.id, MetadataAggregatePointerSource { ty: param.ty.clone() });
        }
        if metadata_molecule_vector_element_fixed_width(&param.ty, type_layouts).is_some() {
            availability.dynamic_collection_vars.insert(param.binding.id);
        }
    }

    let mut named_constructed_vectors = HashMap::<String, usize>::new();
    let mut named_stack_collections = HashMap::<String, usize>::new();
    let mut loaded_constructed_vector_names = HashMap::<usize, String>::new();
    let mut named_fixed_vars = params
        .iter()
        .filter(|param| availability.fixed_value_vars.contains(&param.binding.id))
        .map(|param| (param.name.clone(), param.binding.id))
        .collect::<HashMap<_, _>>();
    let mut named_scalar_vars = params
        .iter()
        .filter(|param| availability.scalar_vars.contains(&param.binding.id))
        .map(|param| (param.name.clone(), param.binding.id))
        .collect::<HashMap<_, _>>();
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::StoreVar { name, src: ir::IrOperand::Var(src) } => {
                    if availability.stack_collection_vars.contains(&src.id) {
                        named_stack_collections.insert(name.clone(), src.id);
                    }
                    if availability.constructed_byte_vector_vars.contains_key(&src.id) {
                        named_constructed_vectors.insert(name.clone(), src.id);
                    }
                    if availability.fixed_value_vars.contains(&src.id) {
                        named_fixed_vars.insert(name.clone(), src.id);
                    }
                    if availability.scalar_vars.contains(&src.id) {
                        named_scalar_vars.insert(name.clone(), src.id);
                    }
                }
                ir::IrInstruction::LoadVar { dest, name } => {
                    if let Some(source_id) = named_stack_collections.get(name).copied() {
                        availability.stack_collection_vars.insert(dest.id);
                        named_stack_collections.insert(name.clone(), dest.id);
                        if let Some(byte_count) = availability.constructed_byte_vector_vars.get(&source_id).copied() {
                            availability.constructed_byte_vector_vars.insert(dest.id, byte_count);
                            if let Some(root_id) = availability.constructed_byte_vector_roots.get(&source_id).copied() {
                                availability.constructed_byte_vector_roots.insert(dest.id, root_id);
                            }
                            loaded_constructed_vector_names.insert(dest.id, name.clone());
                        }
                    }
                    if let Some(source_id) = named_constructed_vectors.get(name).copied() {
                        if let Some(byte_count) = availability.constructed_byte_vector_vars.get(&source_id).copied() {
                            availability.constructed_byte_vector_vars.insert(dest.id, byte_count);
                            if let Some(root_id) = availability.constructed_byte_vector_roots.get(&source_id).copied() {
                                availability.constructed_byte_vector_roots.insert(dest.id, root_id);
                            }
                            loaded_constructed_vector_names.insert(dest.id, name.clone());
                        }
                    }
                    if named_fixed_vars.contains_key(name) {
                        availability.fixed_value_vars.insert(dest.id);
                    }
                    if named_scalar_vars.contains_key(name) {
                        availability.scalar_vars.insert(dest.id);
                        if dest.ty == ir::IrType::U64 {
                            availability.u64_value_vars.insert(dest.id);
                            availability.u64_operand_vars.insert(dest.id);
                        }
                    }
                }
                ir::IrInstruction::Call { dest: Some(dest), .. } if matches!(dest.ty, ir::IrType::Tuple(_)) => {
                    availability.tuple_call_return_vars.insert(dest.id, dest.ty.clone());
                }
                ir::IrInstruction::Call { dest: Some(dest), func, .. } if pure_const_returns.contains_key(func) => {
                    let value = pure_const_returns.get(func).expect("guarded pure const return");
                    if metadata_fixed_scalar_const_value(value).is_some() {
                        availability.scalar_vars.insert(dest.id);
                        availability.fixed_value_vars.insert(dest.id);
                        if dest.ty == ir::IrType::U64 {
                            availability.u64_value_vars.insert(dest.id);
                            availability.u64_operand_vars.insert(dest.id);
                        }
                    } else if metadata_fixed_byte_const_len(value)
                        .is_some_and(|len| type_static_length(&dest.ty).is_some_and(|dest_len| dest_len == len))
                    {
                        availability.fixed_value_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::Create { dest, .. } => {
                    let output_index = availability.created_output_vars.len();
                    availability.created_output_vars.insert(dest.id, output_index);
                }
                ir::IrInstruction::CollectionNew { dest, .. } => {
                    availability.stack_collection_vars.insert(dest.id);
                    availability.empty_molecule_vector_vars.insert(dest.id);
                    availability.constructed_byte_vector_vars.insert(dest.id, 0);
                    availability.constructed_byte_vector_roots.insert(dest.id, dest.id);
                }
                ir::IrInstruction::TypeHash { dest, operand: ir::IrOperand::Var(var) } => {
                    if availability.created_output_vars.contains_key(&var.id) {
                        availability.fixed_value_vars.insert(dest.id);
                        availability.output_type_hash_vars.insert(dest.id);
                    } else if schema_param_ids.contains(&var.id) {
                        availability.fixed_value_vars.insert(dest.id);
                        availability.param_type_hash_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::LoadConst { dest, value } => {
                    if metadata_fixed_scalar_const_value(value).is_some() {
                        availability.scalar_vars.insert(dest.id);
                        availability.fixed_value_vars.insert(dest.id);
                        if dest.ty == ir::IrType::U64 {
                            availability.u64_value_vars.insert(dest.id);
                            availability.u64_operand_vars.insert(dest.id);
                        }
                    } else if metadata_fixed_byte_const_len(value)
                        .is_some_and(|len| type_static_length(&dest.ty).is_some_and(|dest_len| dest_len == len))
                    {
                        availability.fixed_value_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::FieldAccess { dest, obj: ir::IrOperand::Var(obj), field } => {
                    if availability
                        .tuple_call_return_vars
                        .get(&obj.id)
                        .and_then(|ty| metadata_tuple_return_field_type(ty, field))
                        .is_some_and(|field_ty| field_ty == dest.ty)
                    {
                        continue;
                    }
                    let layout = if param_schema_vars.contains(&obj.id) {
                        let Some(type_name) = named_type_name(&obj.ty) else {
                            continue;
                        };
                        let Some(layout) = type_layouts.get(type_name).and_then(|fields| fields.get(field)).cloned() else {
                            continue;
                        };
                        layout
                    } else {
                        let Some(source) = availability.aggregate_pointer_vars.get(&obj.id) else {
                            continue;
                        };
                        let Some(layout) = metadata_aggregate_or_named_field_layout(&source.ty, field, type_layouts) else {
                            continue;
                        };
                        layout
                    };
                    if metadata_layout_fixed_byte_width(&layout).is_some() && layout.ty == dest.ty {
                        availability.fixed_value_vars.insert(dest.id);
                    }
                    if metadata_layout_fixed_scalar_width(&layout).is_some() && layout.ty == dest.ty {
                        availability.scalar_vars.insert(dest.id);
                        if dest.ty == ir::IrType::U64 {
                            availability.u64_value_vars.insert(dest.id);
                            availability.u64_operand_vars.insert(dest.id);
                        }
                    }
                    if metadata_layout_fixed_byte_width(&layout).is_none()
                        && metadata_molecule_vector_element_fixed_width(&layout.ty, type_layouts).is_some()
                        && layout.ty == dest.ty
                    {
                        availability.dynamic_collection_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::Index { dest, arr: ir::IrOperand::Var(arr), idx } => {
                    if availability.dynamic_collection_vars.contains(&arr.id)
                        && metadata_molecule_vector_element_fixed_width(&arr.ty, type_layouts).is_some()
                        && metadata_u64_operand_available(idx, &availability)
                    {
                        let fixed_size = metadata_ir_type_fixed_width(&dest.ty, type_layouts);
                        if metadata_fixed_scalar_width(&dest.ty, fixed_size).is_some() {
                            availability.scalar_vars.insert(dest.id);
                            availability.fixed_value_vars.insert(dest.id);
                            if dest.ty == ir::IrType::U64 {
                                availability.u64_value_vars.insert(dest.id);
                                availability.u64_operand_vars.insert(dest.id);
                            }
                        } else if metadata_fixed_byte_width(&dest.ty, fixed_size).is_some() {
                            availability.fixed_value_vars.insert(dest.id);
                        } else if matches!(dest.ty, ir::IrType::Named(_)) && fixed_size.is_some() {
                            availability
                                .aggregate_pointer_vars
                                .insert(dest.id, MetadataAggregatePointerSource { ty: dest.ty.clone() });
                        }
                    } else if availability.aggregate_pointer_vars.contains_key(&arr.id) {
                        if let (ir::IrType::Array(inner, len), Some(index)) = (&arr.ty, const_usize_operand(idx)) {
                            let element_ty = inner.as_ref();
                            let fixed_size = type_static_length(element_ty);
                            if index < *len && fixed_size.is_some() {
                                if metadata_fixed_scalar_width(element_ty, fixed_size).is_some() && element_ty == &dest.ty {
                                    availability.scalar_vars.insert(dest.id);
                                    availability.fixed_value_vars.insert(dest.id);
                                    if dest.ty == ir::IrType::U64 {
                                        availability.u64_value_vars.insert(dest.id);
                                        availability.u64_operand_vars.insert(dest.id);
                                    }
                                } else if metadata_fixed_byte_width(element_ty, fixed_size).is_some() && element_ty == &dest.ty {
                                    availability.fixed_value_vars.insert(dest.id);
                                } else {
                                    availability
                                        .aggregate_pointer_vars
                                        .insert(dest.id, MetadataAggregatePointerSource { ty: element_ty.clone() });
                                }
                            }
                        }
                    } else if availability.stack_collection_vars.contains(&arr.id)
                        && metadata_molecule_vector_element_fixed_width(&arr.ty, type_layouts).is_some()
                        && (const_usize_operand(idx).is_some() || metadata_u64_operand_available(idx, &availability))
                    {
                        let fixed_size = metadata_ir_type_fixed_width(&dest.ty, type_layouts);
                        if metadata_fixed_scalar_width(&dest.ty, fixed_size).is_some() {
                            availability.scalar_vars.insert(dest.id);
                            availability.fixed_value_vars.insert(dest.id);
                            if dest.ty == ir::IrType::U64 {
                                availability.u64_value_vars.insert(dest.id);
                                availability.u64_operand_vars.insert(dest.id);
                            }
                        } else if metadata_fixed_byte_width(&dest.ty, fixed_size).is_some() {
                            availability.fixed_value_vars.insert(dest.id);
                            availability
                                .aggregate_pointer_vars
                                .insert(dest.id, MetadataAggregatePointerSource { ty: dest.ty.clone() });
                        }
                    }
                }
                ir::IrInstruction::Length { dest, operand } if dest.ty == ir::IrType::U64 => {
                    if operand_static_length(operand).is_some() || metadata_dynamic_length_available(operand, &availability) {
                        availability.scalar_vars.insert(dest.id);
                        availability.fixed_value_vars.insert(dest.id);
                        availability.u64_value_vars.insert(dest.id);
                        availability.u64_operand_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::Binary { dest, op, left, right }
                    if dest.ty == ir::IrType::U64 && matches!(op, ast::BinaryOp::Add | ast::BinaryOp::Sub) =>
                {
                    if metadata_u64_value_available(left, &availability) && metadata_u64_operand_available(right, &availability) {
                        availability.scalar_vars.insert(dest.id);
                        availability.u64_value_vars.insert(dest.id);
                        availability.u64_operand_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::Call { dest: Some(dest), func, args }
                    if dest.ty == ir::IrType::U64
                        && matches!(func.as_str(), "__env_current_daa_score" | "__env_current_timepoint")
                        && args.is_empty() =>
                {
                    availability.scalar_vars.insert(dest.id);
                    availability.fixed_value_vars.insert(dest.id);
                    availability.u64_value_vars.insert(dest.id);
                    availability.u64_operand_vars.insert(dest.id);
                }
                ir::IrInstruction::Move { dest, src } => {
                    if metadata_scalar_available(src, &availability) && metadata_fixed_scalar_size(&dest.ty).is_some() {
                        availability.scalar_vars.insert(dest.id);
                        availability.fixed_value_vars.insert(dest.id);
                    }
                    if metadata_fixed_value_available(src, &availability)
                        && metadata_fixed_byte_width(&dest.ty, type_static_length(&dest.ty)).is_some()
                    {
                        availability.fixed_value_vars.insert(dest.id);
                    }
                    if dest.ty == ir::IrType::U64 && metadata_u64_value_available(src, &availability) {
                        availability.u64_value_vars.insert(dest.id);
                        if metadata_u64_operand_available(src, &availability) {
                            availability.u64_operand_vars.insert(dest.id);
                        }
                    }
                    if let ir::IrOperand::Var(src_var) = src {
                        if availability.schema_pointer_vars.contains(&src_var.id) && named_type_name(&dest.ty).is_some() {
                            availability.schema_pointer_vars.insert(dest.id);
                        }
                        if availability.dynamic_collection_vars.contains(&src_var.id) && dest.ty == src_var.ty {
                            availability.dynamic_collection_vars.insert(dest.id);
                        }
                        if availability.stack_collection_vars.contains(&src_var.id) && dest.ty == src_var.ty {
                            availability.stack_collection_vars.insert(dest.id);
                        }
                        if availability.empty_molecule_vector_vars.contains(&src_var.id) && dest.ty == src_var.ty {
                            availability.empty_molecule_vector_vars.insert(dest.id);
                        }
                        if let Some(byte_count) = availability.constructed_byte_vector_vars.get(&src_var.id).copied() {
                            availability.constructed_byte_vector_vars.insert(dest.id, byte_count);
                            if let Some(root_id) = availability.constructed_byte_vector_roots.get(&src_var.id).copied() {
                                availability.constructed_byte_vector_roots.insert(dest.id, root_id);
                            }
                        }
                    }
                }
                ir::IrInstruction::Unary {
                    dest,
                    op: ast::UnaryOp::Ref | ast::UnaryOp::Deref,
                    operand: ir::IrOperand::Var(src_var),
                } => {
                    if availability.schema_pointer_vars.contains(&src_var.id) && named_type_name(&dest.ty).is_some() {
                        availability.schema_pointer_vars.insert(dest.id);
                    }
                    if availability.dynamic_collection_vars.contains(&src_var.id) && dest.ty == src_var.ty {
                        availability.dynamic_collection_vars.insert(dest.id);
                    }
                    if availability.stack_collection_vars.contains(&src_var.id) && dest.ty == src_var.ty {
                        availability.stack_collection_vars.insert(dest.id);
                    }
                    if availability.empty_molecule_vector_vars.contains(&src_var.id) && dest.ty == src_var.ty {
                        availability.empty_molecule_vector_vars.insert(dest.id);
                    }
                    if let Some(byte_count) = availability.constructed_byte_vector_vars.get(&src_var.id).copied() {
                        availability.constructed_byte_vector_vars.insert(dest.id, byte_count);
                        if let Some(root_id) = availability.constructed_byte_vector_roots.get(&src_var.id).copied() {
                            availability.constructed_byte_vector_roots.insert(dest.id, root_id);
                        }
                    }
                    if let Some(source) = availability.aggregate_pointer_vars.get(&src_var.id).cloned() {
                        availability.aggregate_pointer_vars.insert(dest.id, source);
                    }
                    if availability.fixed_value_vars.contains(&src_var.id) {
                        availability.fixed_value_vars.insert(dest.id);
                    }
                    if availability.scalar_vars.contains(&src_var.id) {
                        availability.scalar_vars.insert(dest.id);
                    }
                    if availability.u64_value_vars.contains(&src_var.id) && dest.ty == ir::IrType::U64 {
                        availability.u64_value_vars.insert(dest.id);
                    }
                    if availability.u64_operand_vars.contains(&src_var.id) && dest.ty == ir::IrType::U64 {
                        availability.u64_operand_vars.insert(dest.id);
                    }
                }
                ir::IrInstruction::CollectionPush { collection: ir::IrOperand::Var(collection), value } => {
                    if let Some(byte_count) = availability.constructed_byte_vector_vars.get(&collection.id).copied() {
                        if let Some(width) = metadata_constructed_vector_part_width(value, type_layouts) {
                            if metadata_fixed_value_available_with_width(value, &availability, width) {
                                availability.constructed_byte_vector_vars.insert(collection.id, byte_count + width);
                                if let Some(name) = loaded_constructed_vector_names.get(&collection.id).cloned() {
                                    named_constructed_vectors.insert(name, collection.id);
                                }
                            } else {
                                availability.constructed_byte_vector_vars.remove(&collection.id);
                            }
                        } else {
                            availability.constructed_byte_vector_vars.remove(&collection.id);
                        }
                    }
                }
                ir::IrInstruction::CollectionExtend { collection: ir::IrOperand::Var(collection), slice } => {
                    if let Some(byte_count) = availability.constructed_byte_vector_vars.get(&collection.id).copied() {
                        if let Some(width) = metadata_constructed_vector_part_width(slice, type_layouts) {
                            if metadata_fixed_value_available_with_width(slice, &availability, width) {
                                availability.constructed_byte_vector_vars.insert(collection.id, byte_count + width);
                                if let Some(name) = loaded_constructed_vector_names.get(&collection.id).cloned() {
                                    named_constructed_vectors.insert(name, collection.id);
                                }
                            } else {
                                availability.constructed_byte_vector_vars.remove(&collection.id);
                            }
                        } else {
                            availability.constructed_byte_vector_vars.remove(&collection.id);
                        }
                    }
                }
                ir::IrInstruction::CollectionClear { collection: ir::IrOperand::Var(collection) } => {
                    if let Some(byte_count) = availability.constructed_byte_vector_vars.get_mut(&collection.id) {
                        *byte_count = 0;
                        availability.empty_molecule_vector_vars.insert(collection.id);
                        if let Some(name) = loaded_constructed_vector_names.get(&collection.id).cloned() {
                            named_constructed_vectors.insert(name, collection.id);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    availability
}

fn metadata_constructed_vector_part_width(operand: &ir::IrOperand, type_layouts: &MetadataTypeLayouts) -> Option<usize> {
    match operand {
        ir::IrOperand::Var(var) => {
            metadata_ir_type_fixed_width(&var.ty, type_layouts).or_else(|| metadata_operand_fixed_value_width(operand))
        }
        ir::IrOperand::Const(_) => metadata_operand_fixed_value_width(operand),
    }
}

fn metadata_can_verify_create_output_fields(
    pattern: &ir::CreatePattern,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if pattern.fields.is_empty() {
        return false;
    }
    let Some(layouts) = type_layouts.get(&pattern.ty) else {
        return false;
    };
    let covered_fields = pattern.fields.iter().map(|(field, _)| field.as_str()).collect::<BTreeSet<_>>();
    if !layouts.keys().all(|field| covered_fields.contains(field.as_str())) {
        return false;
    }
    pattern.fields.iter().all(|(field, value)| {
        layouts.get(field).is_some_and(|layout| {
            if let Some(width) = metadata_layout_fixed_byte_width(layout) {
                metadata_fixed_value_available_with_width(value, availability, width)
            } else {
                metadata_dynamic_create_output_value_available(value, layout, availability, type_layouts)
            }
        })
    })
}

fn metadata_dynamic_create_output_value_available(
    operand: &ir::IrOperand,
    layout: &MetadataFieldLayout,
    availability: &MetadataPreludeAvailability,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    match operand {
        ir::IrOperand::Var(var) => {
            availability.schema_pointer_vars.contains(&var.id)
                || availability.constructed_byte_vector_vars.contains_key(&var.id)
                || (availability.empty_molecule_vector_vars.contains(&var.id)
                    && metadata_molecule_vector_element_fixed_width(&layout.ty, type_layouts).is_some())
        }
        ir::IrOperand::Const(_) => false,
    }
}

fn metadata_collection_new_is_verified_create_value(
    var_id: usize,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    if !availability.empty_molecule_vector_vars.contains(&var_id) && !availability.constructed_byte_vector_vars.contains_key(&var_id) {
        return false;
    }
    body.create_set.iter().any(|pattern| {
        let Some(layouts) = type_layouts.get(&pattern.ty) else {
            return false;
        };
        pattern.fields.iter().any(|(field, value)| {
            let Some(field_var) = (match value {
                ir::IrOperand::Var(var) => Some(var),
                ir::IrOperand::Const(_) => None,
            }) else {
                return false;
            };
            let directly_used = field_var.id == var_id;
            let rooted_at_new =
                availability.constructed_byte_vector_roots.get(&field_var.id).is_some_and(|root_id| *root_id == var_id);
            (directly_used || rooted_at_new)
                && layouts.get(field).is_some_and(|layout| {
                    metadata_molecule_vector_element_fixed_width(&layout.ty, type_layouts).is_some()
                        && metadata_dynamic_create_output_value_available(value, layout, availability, type_layouts)
                })
        })
    })
}

fn metadata_collection_mutation_is_verified_create_vector(
    collection: &ir::IrOperand,
    value: &ir::IrOperand,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
    availability: &MetadataPreludeAvailability,
) -> bool {
    let ir::IrOperand::Var(collection) = collection else {
        return false;
    };
    if !availability.constructed_byte_vector_vars.contains_key(&collection.id) {
        return false;
    }
    let root_id = availability.constructed_byte_vector_roots.get(&collection.id).copied().unwrap_or(collection.id);
    if !metadata_collection_new_is_verified_create_value(root_id, body, type_layouts, availability) {
        return false;
    }
    match value {
        ir::IrOperand::Var(var) => availability.fixed_value_vars.contains(&var.id) || availability.scalar_vars.contains(&var.id),
        ir::IrOperand::Const(_) => true,
    }
}

fn metadata_can_verify_output_lock(pattern: &ir::CreatePattern, availability: &MetadataPreludeAvailability) -> bool {
    match &pattern.lock {
        Some(lock) => metadata_fixed_value_available_with_width(lock, availability, 32),
        None => true,
    }
}

fn metadata_can_verify_fixed_byte_comparison(
    left: &ir::IrOperand,
    right: &ir::IrOperand,
    availability: &MetadataPreludeAvailability,
) -> bool {
    let Some(width) = operand_fixed_byte_width(left) else {
        return false;
    };
    if operand_fixed_byte_width(right) != Some(width) {
        return false;
    }
    metadata_fixed_value_available_with_width(left, availability, width)
        && metadata_fixed_value_available_with_width(right, availability, width)
}

fn metadata_fixed_value_available_with_width(
    operand: &ir::IrOperand,
    availability: &MetadataPreludeAvailability,
    expected_width: usize,
) -> bool {
    if let ir::IrOperand::Const(value) = operand {
        if metadata_fixed_scalar_const_value(value).is_some() {
            return metadata_scalar_const_fits_width(value, expected_width);
        }
    }
    if expected_width <= 8 && matches!(operand, ir::IrOperand::Var(_)) && metadata_scalar_available(operand, availability) {
        return true;
    }
    metadata_fixed_value_available(operand, availability)
        && metadata_operand_fixed_value_width(operand).is_some_and(|width| expected_width <= width)
}

fn metadata_fixed_value_available(operand: &ir::IrOperand, availability: &MetadataPreludeAvailability) -> bool {
    if metadata_scalar_available(operand, availability) {
        return true;
    }
    match operand {
        ir::IrOperand::Const(value) => metadata_fixed_byte_const_len(value).is_some(),
        ir::IrOperand::Var(var) if metadata_fixed_byte_width(&var.ty, type_static_length(&var.ty)).is_some() => {
            availability.fixed_value_vars.contains(&var.id)
        }
        _ => false,
    }
}

fn metadata_scalar_const_fits_width(value: &ir::IrConst, expected_width: usize) -> bool {
    let Some(value) = metadata_fixed_scalar_const_value(value) else {
        return false;
    };
    match expected_width {
        1 => value <= u8::MAX as u64,
        2 => value <= u16::MAX as u64,
        4 => value <= u32::MAX as u64,
        8 => true,
        _ => false,
    }
}

fn metadata_operand_fixed_value_width(operand: &ir::IrOperand) -> Option<usize> {
    match operand {
        ir::IrOperand::Const(ir::IrConst::Bool(_) | ir::IrConst::U8(_)) => Some(1),
        ir::IrOperand::Const(ir::IrConst::U16(_)) => Some(2),
        ir::IrOperand::Const(ir::IrConst::U32(_)) => Some(4),
        ir::IrOperand::Const(ir::IrConst::U64(_)) => Some(8),
        ir::IrOperand::Const(value) => metadata_fixed_byte_const_len(value),
        ir::IrOperand::Var(var) => metadata_fixed_byte_width(&var.ty, type_static_length(&var.ty)),
    }
}

fn metadata_scalar_available(operand: &ir::IrOperand, _availability: &MetadataPreludeAvailability) -> bool {
    match operand {
        ir::IrOperand::Const(value) => metadata_fixed_scalar_const_value(value).is_some(),
        ir::IrOperand::Var(var) => metadata_fixed_scalar_size(&var.ty).is_some(),
    }
}

fn metadata_u64_value_available(operand: &ir::IrOperand, availability: &MetadataPreludeAvailability) -> bool {
    match operand {
        ir::IrOperand::Const(ir::IrConst::U64(_)) => true,
        ir::IrOperand::Var(var) if var.ty == ir::IrType::U64 => availability.u64_value_vars.contains(&var.id),
        _ => false,
    }
}

fn metadata_u64_operand_available(operand: &ir::IrOperand, availability: &MetadataPreludeAvailability) -> bool {
    match operand {
        ir::IrOperand::Const(ir::IrConst::U64(_)) => true,
        ir::IrOperand::Var(var) if var.ty == ir::IrType::U64 => availability.u64_operand_vars.contains(&var.id),
        _ => false,
    }
}

fn metadata_dynamic_length_available(operand: &ir::IrOperand, availability: &MetadataPreludeAvailability) -> bool {
    match operand {
        ir::IrOperand::Var(var) => {
            availability.dynamic_collection_vars.contains(&var.id) || availability.stack_collection_vars.contains(&var.id)
        }
        _ => false,
    }
}

fn metadata_stack_collection_push_is_runtime_supported(
    collection: &ir::IrOperand,
    value: &ir::IrOperand,
    availability: &MetadataPreludeAvailability,
) -> bool {
    let ir::IrOperand::Var(collection) = collection else {
        return false;
    };
    availability.stack_collection_vars.contains(&collection.id)
        && metadata_runtime_collection_part_width(value, availability).is_some()
}

fn metadata_stack_collection_extend_is_runtime_supported(
    collection: &ir::IrOperand,
    slice: &ir::IrOperand,
    availability: &MetadataPreludeAvailability,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    let ir::IrOperand::Var(collection) = collection else {
        return false;
    };
    let Some(width) = operand_fixed_byte_width(slice) else {
        return false;
    };
    let element_width = metadata_molecule_vector_element_fixed_width(&collection.ty, type_layouts).unwrap_or(1);
    element_width != 0 && width % element_width == 0 && availability.stack_collection_vars.contains(&collection.id)
}

fn metadata_stack_collection_clear_is_runtime_supported(
    collection: &ir::IrOperand,
    availability: &MetadataPreludeAvailability,
) -> bool {
    let ir::IrOperand::Var(collection) = collection else {
        return false;
    };
    availability.stack_collection_vars.contains(&collection.id)
}

fn metadata_stack_collection_index_is_runtime_supported(
    dest: &ir::IrVar,
    arr: &ir::IrOperand,
    idx: &ir::IrOperand,
    availability: &MetadataPreludeAvailability,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    let ir::IrOperand::Var(arr) = arr else {
        return false;
    };
    availability.stack_collection_vars.contains(&arr.id)
        && metadata_molecule_vector_element_fixed_width(&arr.ty, type_layouts).is_some_and(|width| {
            metadata_fixed_scalar_width(&dest.ty, Some(width)).is_some()
                || metadata_fixed_byte_width(&dest.ty, type_static_length(&dest.ty)).is_some_and(|dest_width| dest_width == width)
        })
        && (const_usize_operand(idx).is_some() || metadata_u64_operand_available(idx, availability))
}

fn metadata_runtime_collection_part_width(operand: &ir::IrOperand, availability: &MetadataPreludeAvailability) -> Option<usize> {
    match operand {
        ir::IrOperand::Var(var) => metadata_fixed_scalar_width(&var.ty, type_static_length(&var.ty)).or_else(|| {
            let width = metadata_fixed_byte_width(&var.ty, type_static_length(&var.ty))?;
            availability.fixed_value_vars.contains(&var.id).then_some(width)
        }),
        ir::IrOperand::Const(ir::IrConst::Bool(_) | ir::IrConst::U8(_)) => Some(1),
        ir::IrOperand::Const(ir::IrConst::U16(_)) => Some(2),
        ir::IrOperand::Const(ir::IrConst::U32(_)) => Some(4),
        ir::IrOperand::Const(ir::IrConst::U64(_)) => Some(8),
        ir::IrOperand::Const(value) => metadata_fixed_byte_const_len(value),
    }
}

fn metadata_fixed_scalar_width(ty: &ir::IrType, fixed_size: Option<usize>) -> Option<usize> {
    match (ty, fixed_size) {
        (ir::IrType::Bool | ir::IrType::U8, Some(1)) => Some(1),
        (ir::IrType::U16, Some(2)) => Some(2),
        (ir::IrType::U32, Some(4)) => Some(4),
        (ir::IrType::U64, Some(8)) => Some(8),
        (ir::IrType::U128, Some(16)) => Some(16),
        _ => None,
    }
}

fn metadata_fixed_byte_width(ty: &ir::IrType, fixed_size: Option<usize>) -> Option<usize> {
    if let Some(width) = metadata_fixed_scalar_width(ty, fixed_size) {
        return Some(width);
    }
    match (ty, fixed_size) {
        (ir::IrType::Address | ir::IrType::Hash, Some(32)) => Some(32),
        (ir::IrType::Array(inner, len), Some(size)) if matches!(inner.as_ref(), ir::IrType::U8) && *len == size => Some(size),
        (ir::IrType::Ref(inner) | ir::IrType::MutRef(inner), _) => metadata_fixed_byte_width(inner, type_static_length(inner)),
        _ => None,
    }
}

fn metadata_layout_fixed_scalar_width(layout: &MetadataFieldLayout) -> Option<usize> {
    metadata_fixed_scalar_width(&layout.ty, layout.fixed_size).or(layout.fixed_enum_size)
}

fn metadata_layout_fixed_byte_width(layout: &MetadataFieldLayout) -> Option<usize> {
    metadata_fixed_byte_width(&layout.ty, layout.fixed_size).or(layout.fixed_enum_size)
}

fn metadata_fixed_aggregate_pointer_size(ty: &ir::IrType) -> Option<usize> {
    match ty {
        ir::IrType::Array(_, _) | ir::IrType::Tuple(_) => type_static_length(ty).filter(|width| *width > 8),
        _ => None,
    }
}

fn metadata_molecule_vector_element_fixed_width(ty: &ir::IrType, type_layouts: &MetadataTypeLayouts) -> Option<usize> {
    let ir::IrType::Named(name) = ty else {
        return None;
    };
    if name == "String" {
        return Some(1);
    }
    let inner = name.strip_prefix("Vec<")?.strip_suffix('>')?;
    metadata_inline_type_fixed_width(inner, type_layouts)
}

fn metadata_inline_type_fixed_width(ty: &str, type_layouts: &MetadataTypeLayouts) -> Option<usize> {
    match ty.trim() {
        "bool" | "u8" => Some(1),
        "u16" => Some(2),
        "u32" => Some(4),
        "u64" => Some(8),
        "u128" => Some(16),
        "Address" | "Hash" => Some(32),
        other => type_layouts.get(other).and_then(|fields| {
            fields.values().try_fold(0usize, |acc, layout| metadata_layout_fixed_byte_width(layout).map(|width| acc + width))
        }),
    }
}

fn metadata_ir_type_fixed_width(ty: &ir::IrType, type_layouts: &MetadataTypeLayouts) -> Option<usize> {
    type_static_length(ty).or_else(|| match ty {
        ir::IrType::Named(name) => metadata_inline_type_fixed_width(name, type_layouts),
        _ => None,
    })
}

fn metadata_aggregate_field_layout(ty: &ir::IrType, field: &str) -> Option<MetadataFieldLayout> {
    match ty {
        ir::IrType::Tuple(items) => {
            let index = field.parse::<usize>().ok()?;
            let field_ty = items.get(index)?.clone();
            let offset = items.iter().take(index).try_fold(0usize, |acc, item| type_static_length(item).map(|size| acc + size))?;
            let fixed_size = type_static_length(&field_ty);
            Some(MetadataFieldLayout { ty: field_ty, offset, fixed_size, fixed_enum_size: None })
        }
        ir::IrType::Address | ir::IrType::Hash if field == "0" => Some(MetadataFieldLayout {
            ty: ir::IrType::Array(Box::new(ir::IrType::U8), 32),
            offset: 0,
            fixed_size: Some(32),
            fixed_enum_size: None,
        }),
        _ => None,
    }
}

fn metadata_aggregate_or_named_field_layout(
    ty: &ir::IrType,
    field: &str,
    type_layouts: &MetadataTypeLayouts,
) -> Option<MetadataFieldLayout> {
    metadata_aggregate_field_layout(ty, field).or_else(|| {
        let type_name = named_type_name(ty)?;
        type_layouts.get(type_name).and_then(|fields| fields.get(field)).cloned()
    })
}

fn metadata_tuple_return_field_type(ty: &ir::IrType, field: &str) -> Option<ir::IrType> {
    let ir::IrType::Tuple(items) = ty else {
        return None;
    };
    let index = field.parse::<usize>().ok()?;
    (index < 8).then(|| items.get(index).cloned()).flatten()
}

fn const_usize_operand(operand: &ir::IrOperand) -> Option<usize> {
    match operand {
        ir::IrOperand::Const(ir::IrConst::U8(value)) => Some((*value).into()),
        ir::IrOperand::Const(ir::IrConst::U16(value)) => Some((*value).into()),
        ir::IrOperand::Const(ir::IrConst::U32(value)) => Some(*value as usize),
        ir::IrOperand::Const(ir::IrConst::U64(value)) => usize::try_from(*value).ok(),
        _ => None,
    }
}

fn metadata_fixed_byte_const_len(value: &ir::IrConst) -> Option<usize> {
    match value {
        ir::IrConst::Address(_) | ir::IrConst::Hash(_) => Some(32),
        ir::IrConst::Array(items) if items.iter().all(|item| matches!(item, ir::IrConst::U8(_))) => Some(items.len()),
        _ => None,
    }
}

fn metadata_fixed_scalar_size(ty: &ir::IrType) -> Option<usize> {
    match ty {
        ir::IrType::Bool | ir::IrType::U8 => Some(1),
        ir::IrType::U16 => Some(2),
        ir::IrType::U32 => Some(4),
        ir::IrType::U64 => Some(8),
        _ => None,
    }
}

fn metadata_fixed_scalar_const_value(value: &ir::IrConst) -> Option<u64> {
    match value {
        ir::IrConst::Bool(value) => Some(u64::from(*value)),
        ir::IrConst::U8(value) => Some(*value as u64),
        ir::IrConst::U16(value) => Some(*value as u64),
        ir::IrConst::U32(value) => Some(*value as u64),
        ir::IrConst::U64(value) => Some(*value),
        _ => None,
    }
}

fn body_ckb_runtime_features(
    name: &str,
    body: &ir::IrBody,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> Vec<String> {
    let mut features = BTreeSet::new();
    if !body.consume_set.is_empty() {
        features.insert("consume-input-cell".to_string());
    }
    if !body.read_refs.is_empty() {
        features.insert("read-cell-dep".to_string());
    }
    if !body.create_set.is_empty() {
        features.insert("verify-output-cell".to_string());
    }
    if !body.mutate_set.is_empty() {
        features.insert("mutate-input-cell".to_string());
        features.insert("verify-mutate-output-cell".to_string());
    }
    if body_has_claim_witness_authorization_domain_check(name, body, cell_type_kinds, type_layouts) {
        features.insert("load-claim-witness".to_string());
        features.insert("load-claim-ecdsa-signature-hash".to_string());
    }
    if body_has_claim_witness_signature_verification_check(name, body, cell_type_kinds, type_layouts) {
        features.insert("verify-claim-secp256k1-signature".to_string());
    }
    for block in &body.blocks {
        for instruction in &block.instructions {
            match instruction {
                ir::IrInstruction::Call { func, .. } if func == "__env_current_daa_score" => {
                    features.insert("load-header-daa-score".to_string());
                }
                ir::IrInstruction::Call { func, .. } if func == "__env_current_timepoint" => {
                    features.insert("load-header-timepoint".to_string());
                }
                ir::IrInstruction::Call { func, .. } if func == "__ckb_header_epoch_number" => {
                    features.insert("ckb-header-epoch-number".to_string());
                }
                ir::IrInstruction::Call { func, .. } if func == "__ckb_header_epoch_start_block_number" => {
                    features.insert("ckb-header-epoch-start-block-number".to_string());
                }
                ir::IrInstruction::Call { func, .. } if func == "__ckb_header_epoch_length" => {
                    features.insert("ckb-header-epoch-length".to_string());
                }
                ir::IrInstruction::Call { func, .. } if func == "__ckb_input_since" => {
                    features.insert("ckb-input-since".to_string());
                }
                _ => {}
            }
        }
    }
    features.into_iter().collect()
}

fn is_executable_schema_field_access(
    obj: &ir::IrOperand,
    field: &str,
    param_schema_vars: &BTreeSet<usize>,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    let ir::IrOperand::Var(var) = obj else {
        return false;
    };
    if !param_schema_vars.contains(&var.id) {
        return false;
    }
    let Some(type_name) = named_type_name(&var.ty) else {
        return false;
    };
    let Some(layout) = type_layouts.get(type_name).and_then(|fields| fields.get(field)) else {
        return false;
    };
    metadata_layout_fixed_byte_width(layout).is_some()
        || metadata_molecule_vector_element_fixed_width(&layout.ty, type_layouts).is_some()
}

fn is_executable_aggregate_field_access(
    obj: &ir::IrOperand,
    field: &str,
    availability: &MetadataPreludeAvailability,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    let ir::IrOperand::Var(var) = obj else {
        return false;
    };
    let Some(source) = availability.aggregate_pointer_vars.get(&var.id) else {
        return false;
    };
    let Some(layout) = metadata_aggregate_or_named_field_layout(&source.ty, field, type_layouts) else {
        return false;
    };
    metadata_layout_fixed_byte_width(&layout).is_some()
}

fn is_executable_tuple_call_return_field_access(obj: &ir::IrOperand, field: &str, availability: &MetadataPreludeAvailability) -> bool {
    let ir::IrOperand::Var(var) = obj else {
        return false;
    };
    availability.tuple_call_return_vars.get(&var.id).and_then(|ty| metadata_tuple_return_field_type(ty, field)).is_some()
}

fn is_executable_output_type_hash(instruction: &ir::IrInstruction, availability: &MetadataPreludeAvailability) -> bool {
    let ir::IrInstruction::TypeHash { dest, .. } = instruction else {
        return false;
    };
    availability.output_type_hash_vars.contains(&dest.id) || availability.param_type_hash_vars.contains(&dest.id)
}

fn is_executable_destroy(operand: &ir::IrOperand) -> bool {
    operand_named_type_name(operand).is_some()
}

fn body_has_claim_witness_authorization_domain_check(
    name: &str,
    body: &ir::IrBody,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    body.consume_set
        .iter()
        .any(|pattern| is_claim_witness_authorization_domain_check_target(name, pattern, cell_type_kinds, type_layouts))
}

fn body_has_claim_witness_signature_verification_check(
    name: &str,
    body: &ir::IrBody,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    body.consume_set
        .iter()
        .any(|pattern| is_claim_witness_signature_verification_check_target(name, pattern, cell_type_kinds, type_layouts))
}

fn is_claim_witness_authorization_domain_check_target(
    name: &str,
    pattern: &ir::CellPattern,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    if pattern.operation == "claim" {
        return true;
    }
    if pattern.operation != "consume" || !name.starts_with("claim") {
        return false;
    }
    let Some(type_name) = cell_pattern_receipt_type_name(pattern, cell_type_kinds) else {
        return false;
    };
    metadata_claim_signer_pubkey_hash_field(type_name, type_layouts).is_some()
}

fn is_claim_witness_signature_verification_check_target(
    name: &str,
    pattern: &ir::CellPattern,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    if !is_claim_witness_authorization_domain_check_target(name, pattern, cell_type_kinds, type_layouts) {
        return false;
    }
    let Some(type_name) = cell_pattern_receipt_type_name(pattern, cell_type_kinds) else {
        return false;
    };
    metadata_claim_signer_pubkey_hash_field(type_name, type_layouts).is_some()
}

fn is_claim_input_lock_hash_binding_check_target(
    name: &str,
    pattern: &ir::CellPattern,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    if pattern.operation != "consume" || !name.starts_with("claim") {
        return false;
    }
    let Some(type_name) = cell_pattern_receipt_type_name(pattern, cell_type_kinds) else {
        return false;
    };
    metadata_claim_auth_lock_hash_field(type_name, type_layouts).is_some()
}

fn cell_pattern_receipt_type_name<'a>(
    pattern: &ir::CellPattern,
    cell_type_kinds: &'a HashMap<String, ir::IrTypeKind>,
) -> Option<&'a str> {
    let type_hash = pattern.type_hash?;
    cell_type_kinds.iter().find_map(|(type_name, kind)| {
        (*kind == ir::IrTypeKind::Receipt && ir::type_hash_for_name(type_name) == type_hash).then_some(type_name.as_str())
    })
}

fn metadata_claim_signer_pubkey_hash_field<'a>(type_name: &str, type_layouts: &'a MetadataTypeLayouts) -> Option<&'a str> {
    let fields = type_layouts.get(type_name)?;
    CLAIM_SIGNER_PUBKEY_HASH_FIELDS.iter().find_map(|field| {
        let layout = fields.get(*field)?;
        (metadata_layout_fixed_byte_width(layout) == Some(20)).then_some(*field)
    })
}

fn metadata_claim_auth_lock_hash_field<'a>(type_name: &str, type_layouts: &'a MetadataTypeLayouts) -> Option<&'a str> {
    let fields = type_layouts.get(type_name)?;
    CLAIM_AUTH_LOCK_HASH_FIELDS.iter().find_map(|field| {
        let layout = fields.get(*field)?;
        (metadata_layout_fixed_byte_width(layout) == Some(32)).then_some(*field)
    })
}

fn schema_pointer_var_ids(body: &ir::IrBody, params: &[ir::IrParam]) -> BTreeSet<usize> {
    let mut vars =
        params.iter().filter(|param| named_type_name(&param.ty).is_some()).map(|param| param.binding.id).collect::<BTreeSet<_>>();

    for block in &body.blocks {
        for instruction in &block.instructions {
            if let ir::IrInstruction::ReadRef { dest, .. } = instruction {
                vars.insert(dest.id);
            }
            if let Some(var_id) = consumed_schema_var_id(instruction) {
                vars.insert(var_id);
            }
        }
    }

    vars
}

fn consumed_schema_var_id(instruction: &ir::IrInstruction) -> Option<usize> {
    let operand = match instruction {
        ir::IrInstruction::Consume { operand }
        | ir::IrInstruction::Transfer { operand, .. }
        | ir::IrInstruction::Destroy { operand }
        | ir::IrInstruction::Settle { operand, .. } => operand,
        ir::IrInstruction::Claim { receipt, .. } => receipt,
        _ => return None,
    };
    match operand {
        ir::IrOperand::Var(var) if named_type_name(&var.ty).is_some() => Some(var.id),
        _ => None,
    }
}

fn body_ckb_runtime_accesses(
    name: &str,
    body: &ir::IrBody,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    type_layouts: &MetadataTypeLayouts,
) -> Vec<CkbRuntimeAccessMetadata> {
    let mut accesses = Vec::new();
    for (index, pattern) in body.consume_set.iter().enumerate() {
        accesses.push(CkbRuntimeAccessMetadata {
            operation: pattern.operation.clone(),
            syscall: "LOAD_CELL".to_string(),
            source: "Input".to_string(),
            index,
            binding: pattern.binding.clone(),
        });
        if is_claim_witness_authorization_domain_check_target(name, pattern, cell_type_kinds, type_layouts) {
            accesses.push(CkbRuntimeAccessMetadata {
                operation: "claim-witness".to_string(),
                syscall: "LOAD_WITNESS".to_string(),
                source: "GroupInput".to_string(),
                index,
                binding: pattern.binding.clone(),
            });
            accesses.push(CkbRuntimeAccessMetadata {
                operation: "claim-authorization-domain".to_string(),
                syscall: "LOAD_ECDSA_SIGNATURE_HASH".to_string(),
                source: "GroupInput".to_string(),
                index,
                binding: pattern.binding.clone(),
            });
        }
        if is_claim_witness_signature_verification_check_target(name, pattern, cell_type_kinds, type_layouts) {
            accesses.push(CkbRuntimeAccessMetadata {
                operation: "claim-signature".to_string(),
                syscall: "SECP256K1_VERIFY".to_string(),
                source: "Witness".to_string(),
                index,
                binding: pattern.binding.clone(),
            });
        }
    }
    for (index, pattern) in body.read_refs.iter().enumerate() {
        accesses.push(CkbRuntimeAccessMetadata {
            operation: "read_ref".to_string(),
            syscall: "LOAD_CELL".to_string(),
            source: "CellDep".to_string(),
            index,
            binding: pattern.binding.clone(),
        });
    }
    for (index, pattern) in body.create_set.iter().enumerate() {
        accesses.push(CkbRuntimeAccessMetadata {
            operation: pattern.operation.clone(),
            syscall: "LOAD_CELL".to_string(),
            source: "Output".to_string(),
            index,
            binding: pattern.binding.clone(),
        });
    }
    for pattern in &body.mutate_set {
        accesses.push(CkbRuntimeAccessMetadata {
            operation: "mutate-input".to_string(),
            syscall: "LOAD_CELL".to_string(),
            source: "Input".to_string(),
            index: pattern.input_index,
            binding: pattern.binding.clone(),
        });
        accesses.push(CkbRuntimeAccessMetadata {
            operation: "mutate-output".to_string(),
            syscall: "LOAD_CELL".to_string(),
            source: "Output".to_string(),
            index: pattern.output_index,
            binding: pattern.binding.clone(),
        });
    }
    for block in &body.blocks {
        for instruction in &block.instructions {
            if matches!(instruction, ir::IrInstruction::Call { func, .. } if func == "__ckb_input_since") {
                accesses.push(CkbRuntimeAccessMetadata {
                    operation: "input-since".to_string(),
                    syscall: "LOAD_INPUT_BY_FIELD".to_string(),
                    source: "GroupInput".to_string(),
                    index: 0,
                    binding: "ckb::input_since".to_string(),
                });
            }
        }
    }
    accesses
}

fn scheduler_accesses_from_metadata(accesses: &[CkbRuntimeAccessMetadata]) -> Vec<crate::stdlib::SchedulerAccess> {
    accesses
        .iter()
        .filter(|access| scheduler_access_is_cell_state_access(access))
        .map(|access| crate::stdlib::SchedulerAccess {
            operation: access.operation.clone(),
            source: access.source.clone(),
            index: u32::try_from(access.index).unwrap_or(u32::MAX),
            binding: access.binding.clone(),
        })
        .collect()
}

fn scheduler_access_is_cell_state_access(access: &CkbRuntimeAccessMetadata) -> bool {
    matches!(access.source.as_str(), "Input" | "CellDep" | "Output")
        && matches!(
            access.operation.as_str(),
            "consume" | "transfer" | "destroy" | "claim" | "settle" | "read_ref" | "create" | "mutate-input" | "mutate-output"
        )
}

fn metadata_type_layouts(ir: &ir::IrModule) -> MetadataTypeLayouts {
    let mut layouts = HashMap::new();
    for type_def in &ir.external_type_defs {
        let fields = type_def
            .fields
            .iter()
            .map(|field| {
                let fixed_enum_size = match &field.ty {
                    ir::IrType::Named(name) => ir.enum_fixed_sizes.get(name).copied(),
                    _ => None,
                };
                (
                    field.name.clone(),
                    MetadataFieldLayout { ty: field.ty.clone(), offset: field.offset, fixed_size: field.fixed_size, fixed_enum_size },
                )
            })
            .collect();
        layouts.insert(type_def.name.clone(), fields);
    }
    for item in &ir.items {
        let ir::IrItem::TypeDef(type_def) = item else {
            continue;
        };
        let fields = type_def
            .fields
            .iter()
            .map(|field| {
                let fixed_enum_size = match &field.ty {
                    ir::IrType::Named(name) => ir.enum_fixed_sizes.get(name).copied(),
                    _ => None,
                };
                (
                    field.name.clone(),
                    MetadataFieldLayout { ty: field.ty.clone(), offset: field.offset, fixed_size: field.fixed_size, fixed_enum_size },
                )
            })
            .collect();
        layouts.insert(type_def.name.clone(), fields);
    }
    layouts
}

fn metadata_lifecycle_states(ir: &ir::IrModule) -> HashMap<String, Vec<String>> {
    let mut states = HashMap::new();
    for type_def in &ir.external_type_defs {
        if let Some(lifecycle_states) = &type_def.lifecycle_states {
            states.insert(type_def.name.clone(), lifecycle_states.clone());
        }
    }
    for item in &ir.items {
        let ir::IrItem::TypeDef(type_def) = item else {
            continue;
        };
        if let Some(lifecycle_states) = &type_def.lifecycle_states {
            states.insert(type_def.name.clone(), lifecycle_states.clone());
        }
    }
    states
}

fn metadata_cell_type_kinds(ir: &ir::IrModule) -> HashMap<String, ir::IrTypeKind> {
    let mut kinds = HashMap::new();
    for type_def in &ir.external_type_defs {
        if type_def.kind != ir::IrTypeKind::Struct {
            kinds.insert(type_def.name.clone(), type_def.kind);
        }
    }
    for item in &ir.items {
        let ir::IrItem::TypeDef(type_def) = item else {
            continue;
        };
        if type_def.kind != ir::IrTypeKind::Struct {
            kinds.insert(type_def.name.clone(), type_def.kind);
        }
    }
    kinds
}

fn metadata_type_defs_by_name(ir: &ir::IrModule) -> BTreeMap<String, &ir::IrTypeDef> {
    let mut type_defs = BTreeMap::new();
    for type_def in &ir.external_type_defs {
        type_defs.insert(type_def.name.clone(), type_def);
    }
    for item in &ir.items {
        let ir::IrItem::TypeDef(type_def) = item else {
            continue;
        };
        type_defs.insert(type_def.name.clone(), type_def);
    }
    type_defs
}

fn type_metadata(
    type_def: &ir::IrTypeDef,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    target_profile: TargetProfile,
) -> TypeMetadata {
    let lifecycle_states = type_def.lifecycle_states.clone().unwrap_or_default();
    let type_id = type_def.type_id.clone();
    let type_id_hash_blake3 = type_id.as_ref().map(|value| hex_hash(blake3::hash(value.as_bytes()).as_bytes()));
    let ckb_type_id = ckb_type_id_metadata(type_def, target_profile);
    TypeMetadata {
        name: type_def.name.clone(),
        type_id,
        type_id_hash_blake3,
        ckb_type_id,
        kind: format!("{:?}", type_def.kind),
        capabilities: type_def.capabilities.iter().map(metadata_capability_name).collect(),
        claim_output: type_def.claim_output.as_ref().map(ir_type_to_string),
        lifecycle_transitions: if type_def.lifecycle_rules.is_empty() {
            lifecycle_transition_metadata(&lifecycle_states)
        } else {
            type_def.lifecycle_rules.iter().map(lifecycle_rule_metadata).collect()
        },
        lifecycle_states,
        encoded_size: type_encoded_size(type_def, type_defs),
        fields: type_def.fields.iter().map(|field| field_metadata(field, type_defs)).collect(),
        molecule_schema: type_molecule_schema_metadata(type_def, type_defs),
    }
}

fn ckb_type_id_metadata(type_def: &ir::IrTypeDef, target_profile: TargetProfile) -> Option<CkbTypeIdMetadata> {
    if target_profile != TargetProfile::Ckb || type_def.type_id.is_none() {
        return None;
    }
    if !matches!(type_def.kind, ir::IrTypeKind::Resource | ir::IrTypeKind::Shared | ir::IrTypeKind::Receipt) {
        return None;
    }

    Some(CkbTypeIdMetadata {
        abi: CKB_TYPE_ID_ABI.to_string(),
        script_code_hash: hex_encode(&CKB_TYPE_ID_CODE_HASH),
        hash_type: CKB_TYPE_ID_HASH_TYPE.to_string(),
        args_source: CKB_TYPE_ID_ARGS_SOURCE.to_string(),
        group_rule: CKB_TYPE_ID_GROUP_RULE.to_string(),
        builder: CKB_TYPE_ID_BUILDER.to_string(),
        verifier: CKB_TYPE_ID_VERIFIER.to_string(),
    })
}

fn type_molecule_schema_metadata(
    type_def: &ir::IrTypeDef,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
) -> Option<MoleculeSchemaMetadata> {
    let encoded_size = type_encoded_size(type_def, type_defs);
    let fixed_size = encoded_size.unwrap_or(0);
    let mut aliases = BTreeMap::new();
    let mut structs = Vec::new();
    let mut emitted = BTreeSet::new();
    let root_type = if encoded_size.is_some() {
        molecule_struct_for_type(type_def, type_defs, &mut aliases, &mut structs, &mut emitted, &mut BTreeSet::new())?
    } else {
        molecule_table_for_type(type_def, type_defs, &mut aliases, &mut structs, &mut emitted, &mut BTreeSet::new())?
    };

    let mut schema = String::new();
    for definition in ordered_molecule_alias_definitions(&aliases) {
        schema.push_str(definition);
        schema.push('\n');
    }
    if !aliases.is_empty() {
        schema.push('\n');
    }
    for definition in structs {
        schema.push_str(&definition);
        schema.push('\n');
    }
    debug_assert_eq!(root_type, molecule_identifier(&type_def.name));

    let schema_hash_blake3 = hex_encode(blake3::hash(schema.as_bytes()).as_bytes());
    Some(MoleculeSchemaMetadata {
        abi: "molecule".to_string(),
        layout: if encoded_size.is_some() { "fixed-struct-v1" } else { "molecule-table-v1" }.to_string(),
        name: type_def.name.clone(),
        dynamic_fields: if encoded_size.is_some() { Vec::new() } else { molecule_dynamic_fields(type_def, type_defs) },
        fixed_size,
        schema_hash_blake3,
        schema,
    })
}

fn molecule_schema_manifest_metadata(types: &[TypeMetadata], target_profile: TargetProfile) -> MoleculeSchemaManifestMetadata {
    let mut entries = types
        .iter()
        .filter_map(|ty| {
            let schema = ty.molecule_schema.as_ref()?;
            Some(MoleculeSchemaManifestEntryMetadata {
                type_name: ty.name.clone(),
                kind: ty.kind.clone(),
                layout: schema.layout.clone(),
                fixed_size: schema.fixed_size,
                encoded_size: ty.encoded_size,
                dynamic_fields: schema.dynamic_fields.clone(),
                schema_hash_blake3: schema.schema_hash_blake3.clone(),
                field_offsets: ty
                    .fields
                    .iter()
                    .map(|field| MoleculeSchemaManifestFieldMetadata {
                        name: field.name.clone(),
                        ty: field.ty.clone(),
                        offset: field.offset,
                        encoded_size: field.encoded_size,
                        fixed_width: field.fixed_width,
                    })
                    .collect(),
                target_profile_compatible: true,
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.type_name.cmp(&right.type_name));

    let fixed_type_count = entries.iter().filter(|entry| entry.layout == "fixed-struct-v1").count();
    let dynamic_type_count = entries.iter().filter(|entry| entry.layout == "molecule-table-v1").count();
    let mut canonical = String::new();
    for entry in &entries {
        canonical.push_str(&entry.type_name);
        canonical.push('|');
        canonical.push_str(&entry.kind);
        canonical.push('|');
        canonical.push_str(&entry.layout);
        canonical.push('|');
        canonical.push_str(&entry.fixed_size.to_string());
        canonical.push('|');
        canonical.push_str(&entry.encoded_size.map(|size| size.to_string()).unwrap_or_else(|| "dynamic".to_string()));
        canonical.push('|');
        canonical.push_str(&entry.dynamic_fields.join(","));
        canonical.push('|');
        canonical.push_str(&entry.schema_hash_blake3);
        canonical.push('\n');
        for field in &entry.field_offsets {
            canonical.push_str("  ");
            canonical.push_str(&field.name);
            canonical.push('|');
            canonical.push_str(&field.ty);
            canonical.push('|');
            canonical.push_str(&field.offset.to_string());
            canonical.push('|');
            canonical.push_str(&field.encoded_size.map(|size| size.to_string()).unwrap_or_else(|| "dynamic".to_string()));
            canonical.push('|');
            canonical.push_str(if field.fixed_width { "fixed" } else { "dynamic" });
            canonical.push('\n');
        }
    }

    MoleculeSchemaManifestMetadata {
        schema: "cellscript-molecule-schema-manifest-v1".to_string(),
        version: 1,
        abi: "molecule".to_string(),
        target_profile: target_profile.name().to_string(),
        type_count: entries.len(),
        fixed_type_count,
        dynamic_type_count,
        manifest_hash_blake3: hex_encode(blake3::hash(canonical.as_bytes()).as_bytes()),
        entries,
    }
}

fn molecule_dynamic_fields(type_def: &ir::IrTypeDef, type_defs: &BTreeMap<String, &ir::IrTypeDef>) -> Vec<String> {
    type_def
        .fields
        .iter()
        .filter(|field| ir_type_encoded_size(&field.ty, type_defs, &mut BTreeSet::new()).or(field.fixed_size).is_none())
        .map(|field| field.name.clone())
        .collect()
}

fn molecule_struct_for_type(
    type_def: &ir::IrTypeDef,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    aliases: &mut BTreeMap<String, String>,
    structs: &mut Vec<String>,
    emitted: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> Option<String> {
    if emitted.contains(&type_def.name) {
        return Some(molecule_identifier(&type_def.name));
    }
    if !visiting.insert(type_def.name.clone()) {
        return None;
    }

    let result = (|| {
        let mut fields = Vec::new();
        for field in &type_def.fields {
            let ty = molecule_type_for_ir_type(&field.ty, &type_def.name, &field.name, type_defs, aliases, structs, emitted, visiting)
                .or_else(|| (field.fixed_size == Some(1)).then(|| molecule_fixed_array_alias(aliases, "CellScriptEnumTag", "byte", 1)))
                .or_else(|| {
                    (field.fixed_size.is_none()).then(|| {
                        let alias = format!("{}{}Bytes", molecule_identifier(&type_def.name), molecule_identifier(&field.name));
                        molecule_bytes_alias(aliases, &alias)
                    })
                })?;
            fields.push((field.name.clone(), ty));
        }

        let name = molecule_identifier(&type_def.name);
        let mut definition = format!("struct {} {{\n", name);
        for (field, ty) in fields {
            definition.push_str(&format!("    {}: {},\n", field, ty));
        }
        definition.push_str("}\n");
        structs.push(definition);
        emitted.insert(type_def.name.clone());
        Some(name)
    })();

    visiting.remove(&type_def.name);
    result
}

fn molecule_table_for_type(
    type_def: &ir::IrTypeDef,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    aliases: &mut BTreeMap<String, String>,
    structs: &mut Vec<String>,
    emitted: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> Option<String> {
    let name = molecule_identifier(&type_def.name);
    if emitted.contains(&name) {
        return Some(name);
    }
    if !visiting.insert(type_def.name.clone()) {
        return None;
    }

    let result = (|| {
        let mut fields = Vec::new();
        for field in &type_def.fields {
            let ty = molecule_type_for_ir_type(&field.ty, &type_def.name, &field.name, type_defs, aliases, structs, emitted, visiting)
                .or_else(|| (field.fixed_size == Some(1)).then(|| molecule_fixed_array_alias(aliases, "CellScriptEnumTag", "byte", 1)))
                .or_else(|| {
                    (field.fixed_size.is_none()).then(|| {
                        let alias = format!("{}{}Bytes", molecule_identifier(&type_def.name), molecule_identifier(&field.name));
                        molecule_bytes_alias(aliases, &alias)
                    })
                })?;
            fields.push((field.name.clone(), ty));
        }

        let mut definition = format!("table {} {{\n", name);
        for (field, ty) in fields {
            definition.push_str(&format!("    {}: {},\n", field, ty));
        }
        definition.push_str("}\n");
        structs.push(definition);
        emitted.insert(name.clone());
        Some(name)
    })();

    visiting.remove(&type_def.name);
    result
}

fn molecule_type_for_ir_type(
    ty: &ir::IrType,
    owner: &str,
    field: &str,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    aliases: &mut BTreeMap<String, String>,
    structs: &mut Vec<String>,
    emitted: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> Option<String> {
    match ty {
        ir::IrType::U8 => Some("byte".to_string()),
        ir::IrType::U16 => Some(molecule_fixed_array_alias(aliases, "CellScriptUint16", "byte", 2)),
        ir::IrType::U32 => Some(molecule_fixed_array_alias(aliases, "CellScriptUint32", "byte", 4)),
        ir::IrType::U64 => Some(molecule_fixed_array_alias(aliases, "CellScriptUint64", "byte", 8)),
        ir::IrType::U128 => Some(molecule_fixed_array_alias(aliases, "CellScriptUint128", "byte", 16)),
        ir::IrType::Bool => Some(molecule_fixed_array_alias(aliases, "CellScriptBool", "byte", 1)),
        ir::IrType::Address => Some(molecule_fixed_array_alias(aliases, "CellScriptAddress", "byte", 32)),
        ir::IrType::Hash => Some(molecule_fixed_array_alias(aliases, "CellScriptHash", "byte", 32)),
        ir::IrType::Named(name) if name == "String" => Some(molecule_bytes_alias(aliases, "CellScriptString")),
        ir::IrType::Named(name) if name == "Vec" => Some(molecule_dynvec_alias(aliases, "CellScriptUnknownVec", "byte")),
        ir::IrType::Named(name) if name.starts_with("Vec<") && name.ends_with('>') => {
            let inner = name.strip_prefix("Vec<")?.strip_suffix('>')?;
            let inner_ty = molecule_type_for_named_type(inner, owner, field, type_defs, aliases, structs, emitted, visiting)?;
            let alias = format!("{}{}Vec", molecule_identifier(owner), molecule_identifier(field));
            Some(molecule_dynvec_alias(aliases, &alias, &inner_ty))
        }
        ir::IrType::Array(inner, len) => {
            let inner_ty = molecule_type_for_ir_type(inner, owner, field, type_defs, aliases, structs, emitted, visiting)?;
            let alias = format!("{}{}Array{}", molecule_identifier(owner), molecule_identifier(field), len);
            Some(molecule_fixed_array_alias(aliases, &alias, &inner_ty, *len))
        }
        ir::IrType::Tuple(items) => {
            let tuple_name = format!("CellScriptTuple{}{}", molecule_identifier(owner), molecule_identifier(field));
            molecule_tuple_struct_for_items(&tuple_name, items, type_defs, aliases, structs, emitted, visiting)
        }
        ir::IrType::Named(name) => {
            let type_def = type_defs.get(name.as_str())?;
            if type_encoded_size(type_def, type_defs).is_some() {
                molecule_struct_for_type(type_def, type_defs, aliases, structs, emitted, visiting)
            } else {
                molecule_table_for_type(type_def, type_defs, aliases, structs, emitted, visiting)
            }
        }
        ir::IrType::Unit | ir::IrType::Ref(_) | ir::IrType::MutRef(_) => None,
    }
}

fn molecule_type_for_named_type(
    name: &str,
    owner: &str,
    field: &str,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    aliases: &mut BTreeMap<String, String>,
    structs: &mut Vec<String>,
    emitted: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> Option<String> {
    match name {
        "u8" => Some("byte".to_string()),
        "u16" => Some(molecule_fixed_array_alias(aliases, "CellScriptUint16", "byte", 2)),
        "u32" => Some(molecule_fixed_array_alias(aliases, "CellScriptUint32", "byte", 4)),
        "u64" => Some(molecule_fixed_array_alias(aliases, "CellScriptUint64", "byte", 8)),
        "u128" => Some(molecule_fixed_array_alias(aliases, "CellScriptUint128", "byte", 16)),
        "bool" => Some(molecule_fixed_array_alias(aliases, "CellScriptBool", "byte", 1)),
        "Address" => Some(molecule_fixed_array_alias(aliases, "CellScriptAddress", "byte", 32)),
        "Hash" => Some(molecule_fixed_array_alias(aliases, "CellScriptHash", "byte", 32)),
        "String" => Some(molecule_bytes_alias(aliases, "CellScriptString")),
        other if other.starts_with("Vec<") && other.ends_with('>') => {
            let inner = other.strip_prefix("Vec<")?.strip_suffix('>')?;
            let inner_ty = molecule_type_for_named_type(inner, owner, field, type_defs, aliases, structs, emitted, visiting)?;
            let alias = format!("{}{}Vec", molecule_identifier(owner), molecule_identifier(field));
            Some(molecule_dynvec_alias(aliases, &alias, &inner_ty))
        }
        other => {
            let type_def = type_defs.get(other)?;
            if type_encoded_size(type_def, type_defs).is_some() {
                molecule_struct_for_type(type_def, type_defs, aliases, structs, emitted, visiting)
            } else {
                molecule_table_for_type(type_def, type_defs, aliases, structs, emitted, visiting)
            }
        }
    }
}

fn molecule_tuple_struct_for_items(
    name: &str,
    items: &[ir::IrType],
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    aliases: &mut BTreeMap<String, String>,
    structs: &mut Vec<String>,
    emitted: &mut BTreeSet<String>,
    visiting: &mut BTreeSet<String>,
) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let name = molecule_identifier(name);
    if emitted.contains(&name) {
        return Some(name);
    }

    let mut fields = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let field = format!("item{}", index);
        let ty = molecule_type_for_ir_type(item, &name, &field, type_defs, aliases, structs, emitted, visiting)?;
        fields.push((field, ty));
    }

    let mut definition = format!("struct {} {{\n", name);
    for (field, ty) in fields {
        definition.push_str(&format!("    {}: {},\n", field, ty));
    }
    definition.push_str("}\n");
    structs.push(definition);
    emitted.insert(name.clone());
    Some(name)
}

fn molecule_fixed_array_alias(aliases: &mut BTreeMap<String, String>, name: &str, item: &str, len: usize) -> String {
    let name = molecule_identifier(name);
    aliases.entry(name.clone()).or_insert_with(|| format!("array {} [{}; {}];", name, item, len));
    name
}

fn molecule_bytes_alias(aliases: &mut BTreeMap<String, String>, name: &str) -> String {
    let name = molecule_identifier(name);
    aliases.entry(name.clone()).or_insert_with(|| format!("vector {} <byte>;", name));
    name
}

fn molecule_dynvec_alias(aliases: &mut BTreeMap<String, String>, name: &str, item: &str) -> String {
    let name = molecule_identifier(name);
    aliases.entry(name.clone()).or_insert_with(|| format!("vector {} <{}>;", name, item));
    name
}

fn ordered_molecule_alias_definitions(aliases: &BTreeMap<String, String>) -> Vec<&String> {
    const PRIMITIVE_ORDER: [&str; 9] = [
        "CellScriptBool",
        "CellScriptUint16",
        "CellScriptUint32",
        "CellScriptUint64",
        "CellScriptUint128",
        "CellScriptAddress",
        "CellScriptHash",
        "CellScriptString",
        "CellScriptUnknownVec",
    ];
    let mut definitions = Vec::new();
    for name in PRIMITIVE_ORDER {
        if let Some(definition) = aliases.get(name) {
            definitions.push(definition);
        }
    }
    for (name, definition) in aliases {
        if !PRIMITIVE_ORDER.contains(&name.as_str()) {
            definitions.push(definition);
        }
    }
    definitions
}

fn molecule_identifier(input: &str) -> String {
    let mut out = String::new();
    let mut uppercase_next = true;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            if uppercase_next {
                out.push(ch.to_ascii_uppercase());
                uppercase_next = false;
            } else {
                out.push(ch);
            }
        } else {
            uppercase_next = true;
        }
    }
    if out.is_empty() || out.as_bytes().first().is_some_and(|byte| byte.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

fn metadata_capability_name(capability: &crate::ast::Capability) -> String {
    match capability {
        crate::ast::Capability::Store => "store",
        crate::ast::Capability::Transfer => "transfer",
        crate::ast::Capability::Destroy => "destroy",
    }
    .to_string()
}

fn lifecycle_transition_metadata(states: &[String]) -> Vec<LifecycleTransitionMetadata> {
    states
        .windows(2)
        .enumerate()
        .map(|(index, window)| LifecycleTransitionMetadata {
            from: window[0].clone(),
            to: window[1].clone(),
            from_index: index,
            to_index: index + 1,
        })
        .collect()
}

fn lifecycle_rule_metadata(rule: &ir::IrLifecycleRule) -> LifecycleTransitionMetadata {
    LifecycleTransitionMetadata { from: rule.from.clone(), to: rule.to.clone(), from_index: rule.from_index, to_index: rule.to_index }
}

fn field_metadata(field: &ir::IrField, type_defs: &BTreeMap<String, &ir::IrTypeDef>) -> FieldMetadata {
    let encoded_size = ir_type_encoded_size(&field.ty, type_defs, &mut BTreeSet::new()).or(field.fixed_size);
    FieldMetadata {
        name: field.name.clone(),
        ty: ir_type_to_string(&field.ty),
        offset: field.offset,
        encoded_size,
        fixed_width: encoded_size.is_some(),
    }
}

fn type_encoded_size(type_def: &ir::IrTypeDef, type_defs: &BTreeMap<String, &ir::IrTypeDef>) -> Option<usize> {
    type_def.fields.iter().try_fold(0usize, |acc, field| {
        ir_type_encoded_size(&field.ty, type_defs, &mut BTreeSet::new()).or(field.fixed_size).map(|size| acc + size)
    })
}

fn ir_type_encoded_size(
    ty: &ir::IrType,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    visiting: &mut BTreeSet<String>,
) -> Option<usize> {
    match ty {
        ir::IrType::U8 | ir::IrType::Bool => Some(1),
        ir::IrType::U16 => Some(2),
        ir::IrType::U32 => Some(4),
        ir::IrType::U64 => Some(8),
        ir::IrType::U128 => Some(16),
        ir::IrType::Address | ir::IrType::Hash => Some(32),
        ir::IrType::Array(inner, len) => ir_type_encoded_size(inner, type_defs, visiting).map(|inner_size| inner_size * len),
        ir::IrType::Tuple(items) => {
            items.iter().try_fold(0usize, |acc, item| ir_type_encoded_size(item, type_defs, visiting).map(|item_size| acc + item_size))
        }
        ir::IrType::Unit => Some(0),
        ir::IrType::Named(name) => {
            if !visiting.insert(name.clone()) {
                return None;
            }
            let size = type_defs.get(name.as_str()).and_then(|type_def| {
                type_def.fields.iter().try_fold(0usize, |acc, field| {
                    ir_type_encoded_size(&field.ty, type_defs, visiting).or(field.fixed_size).map(|field_size| acc + field_size)
                })
            });
            visiting.remove(name);
            size
        }
        ir::IrType::Ref(_) | ir::IrType::MutRef(_) => None,
    }
}

fn ir_type_to_string(ty: &ir::IrType) -> String {
    match ty {
        ir::IrType::U8 => "u8".to_string(),
        ir::IrType::U16 => "u16".to_string(),
        ir::IrType::U32 => "u32".to_string(),
        ir::IrType::U64 => "u64".to_string(),
        ir::IrType::U128 => "u128".to_string(),
        ir::IrType::Bool => "bool".to_string(),
        ir::IrType::Unit => "()".to_string(),
        ir::IrType::Address => "Address".to_string(),
        ir::IrType::Hash => "Hash".to_string(),
        ir::IrType::Array(inner, size) => format!("[{}; {}]", ir_type_to_string(inner), size),
        ir::IrType::Tuple(items) => {
            let fields = items.iter().map(ir_type_to_string).collect::<Vec<_>>().join(", ");
            format!("({})", fields)
        }
        ir::IrType::Named(name) => name.clone(),
        ir::IrType::Ref(inner) => format!("&{}", ir_type_to_string(inner)),
        ir::IrType::MutRef(inner) => format!("&mut {}", ir_type_to_string(inner)),
    }
}

fn named_type_name(ty: &ir::IrType) -> Option<&str> {
    match ty {
        ir::IrType::Named(name) => Some(name.as_str()),
        ir::IrType::Ref(inner) | ir::IrType::MutRef(inner) => named_type_name(inner),
        _ => None,
    }
}

fn ir_operand_contains_cell_backed_value(operand: &ir::IrOperand, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    match operand {
        ir::IrOperand::Var(var) => ir_type_contains_cell_backed_value(&var.ty, cell_type_kinds),
        ir::IrOperand::Const(_) => false,
    }
}

fn ir_operand_is_cell_backed_collection(operand: &ir::IrOperand, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    match operand {
        ir::IrOperand::Var(var) => ir_type_is_cell_backed_collection(&var.ty, cell_type_kinds),
        ir::IrOperand::Const(_) => false,
    }
}

fn ir_operand_cell_backed_type_names(operand: &ir::IrOperand, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> Vec<String> {
    match operand {
        ir::IrOperand::Var(var) => ir_type_cell_backed_value_type_names(&var.ty, cell_type_kinds),
        ir::IrOperand::Const(_) => Vec::new(),
    }
}

fn ir_operand_cell_backed_collection_type_names(
    operand: &ir::IrOperand,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> Vec<String> {
    match operand {
        ir::IrOperand::Var(var) => ir_type_cell_backed_collection_type_names(&var.ty, cell_type_kinds),
        ir::IrOperand::Const(_) => Vec::new(),
    }
}

fn ir_type_contains_cell_backed_value(ty: &ir::IrType, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    match ty {
        ir::IrType::Array(inner, _) => ir_type_contains_cell_backed_value(inner, cell_type_kinds),
        ir::IrType::Tuple(items) => items.iter().any(|item| ir_type_contains_cell_backed_value(item, cell_type_kinds)),
        ir::IrType::Named(name) => {
            let base_name = name.split('<').next().unwrap_or(name.as_str());
            cell_type_kinds.contains_key(base_name) || named_type_generic_payload_contains_cell_backed_value(name, cell_type_kinds)
        }
        ir::IrType::Ref(_) | ir::IrType::MutRef(_) => false,
        _ => false,
    }
}

fn ir_type_cell_backed_value_type_names(ty: &ir::IrType, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> Vec<String> {
    let mut names = BTreeSet::new();
    collect_ir_type_cell_backed_value_type_names(ty, cell_type_kinds, &mut names);
    names.into_iter().collect()
}

fn collect_ir_type_cell_backed_value_type_names(
    ty: &ir::IrType,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    names: &mut BTreeSet<String>,
) {
    match ty {
        ir::IrType::Array(inner, _) => collect_ir_type_cell_backed_value_type_names(inner, cell_type_kinds, names),
        ir::IrType::Tuple(items) => {
            for item in items {
                collect_ir_type_cell_backed_value_type_names(item, cell_type_kinds, names);
            }
        }
        ir::IrType::Named(name) => {
            let base_name = name.split('<').next().unwrap_or(name.as_str());
            if cell_type_kinds.contains_key(base_name) {
                names.insert(base_name.to_string());
            }
            collect_named_type_generic_payload_cell_backed_names(name, cell_type_kinds, names);
        }
        ir::IrType::Ref(_) | ir::IrType::MutRef(_) => {}
        _ => {}
    }
}

fn ir_type_is_cell_backed_collection(ty: &ir::IrType, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    match ty {
        ir::IrType::Named(name) => name
            .strip_prefix("Vec<")
            .and_then(|payload| payload.strip_suffix('>'))
            .is_some_and(|payload| type_fragment_contains_cell_backed_name(payload, cell_type_kinds)),
        ir::IrType::Ref(inner) | ir::IrType::MutRef(inner) => ir_type_is_cell_backed_collection(inner, cell_type_kinds),
        _ => false,
    }
}

fn ir_type_cell_backed_collection_type_names(ty: &ir::IrType, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> Vec<String> {
    let mut names = BTreeSet::new();
    collect_ir_type_cell_backed_collection_type_names(ty, cell_type_kinds, &mut names);
    names.into_iter().collect()
}

fn collect_ir_type_cell_backed_collection_type_names(
    ty: &ir::IrType,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    names: &mut BTreeSet<String>,
) {
    match ty {
        ir::IrType::Named(name) => {
            if let Some(payload) = name.strip_prefix("Vec<").and_then(|payload| payload.strip_suffix('>')) {
                collect_type_fragment_cell_backed_names(payload, cell_type_kinds, names);
            }
        }
        ir::IrType::Ref(inner) | ir::IrType::MutRef(inner) => {
            collect_ir_type_cell_backed_collection_type_names(inner, cell_type_kinds, names);
        }
        _ => {}
    }
}

fn named_type_generic_payload_contains_cell_backed_value(name: &str, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    name.find('<')
        .and_then(|start| name.ends_with('>').then_some(&name[start + 1..name.len() - 1]))
        .is_some_and(|payload| type_fragment_contains_cell_backed_name(payload, cell_type_kinds))
}

fn collect_named_type_generic_payload_cell_backed_names(
    name: &str,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    names: &mut BTreeSet<String>,
) {
    if let Some(payload) = name.find('<').and_then(|start| name.ends_with('>').then_some(&name[start + 1..name.len() - 1])) {
        collect_type_fragment_cell_backed_names(payload, cell_type_kinds, names);
    }
}

fn type_fragment_contains_cell_backed_name(fragment: &str, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    let mut token = String::new();
    for ch in fragment.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            token.push(ch);
        } else if type_name_token_is_cell_backed(&token, cell_type_kinds) {
            return true;
        } else {
            token.clear();
        }
    }
    type_name_token_is_cell_backed(&token, cell_type_kinds)
}

fn collect_type_fragment_cell_backed_names(
    fragment: &str,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
    names: &mut BTreeSet<String>,
) {
    let mut token = String::new();
    for ch in fragment.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == ':' {
            token.push(ch);
        } else {
            if type_name_token_is_cell_backed(&token, cell_type_kinds) {
                names.insert(token.clone());
            }
            token.clear();
        }
    }
    if type_name_token_is_cell_backed(&token, cell_type_kinds) {
        names.insert(token);
    }
}

fn type_name_token_is_cell_backed(token: &str, cell_type_kinds: &HashMap<String, ir::IrTypeKind>) -> bool {
    match token {
        "" | "u8" | "u16" | "u32" | "u64" | "u128" | "bool" | "Address" | "Hash" | "String" | "Range" | "Vec" | "usize" | "isize"
        | "read_ref" | "mut" => false,
        name => cell_type_kinds.contains_key(name),
    }
}

fn operand_static_length(operand: &ir::IrOperand) -> Option<usize> {
    match operand {
        ir::IrOperand::Var(var) => type_static_length(&var.ty),
        ir::IrOperand::Const(ir::IrConst::Array(items)) => Some(items.len()),
        ir::IrOperand::Const(ir::IrConst::Address(_) | ir::IrConst::Hash(_)) => Some(32),
        _ => None,
    }
}

fn operand_fixed_byte_width(operand: &ir::IrOperand) -> Option<usize> {
    match operand {
        ir::IrOperand::Const(ir::IrConst::Address(_) | ir::IrConst::Hash(_)) => Some(32),
        ir::IrOperand::Const(ir::IrConst::Array(items)) => Some(items.len()),
        ir::IrOperand::Var(var) => match &var.ty {
            ir::IrType::Address | ir::IrType::Hash => Some(32),
            ir::IrType::Array(inner, len) if matches!(inner.as_ref(), ir::IrType::U8) => Some(*len),
            _ => None,
        },
        _ => None,
    }
}

fn type_static_length(ty: &ir::IrType) -> Option<usize> {
    match ty {
        ir::IrType::Bool | ir::IrType::U8 => Some(1),
        ir::IrType::U16 => Some(2),
        ir::IrType::U32 => Some(4),
        ir::IrType::U64 => Some(8),
        ir::IrType::U128 => Some(16),
        ir::IrType::Address | ir::IrType::Hash => Some(32),
        ir::IrType::Array(inner, size) => type_static_length(inner).map(|inner_size| inner_size * size),
        ir::IrType::Tuple(items) => items.iter().try_fold(0usize, |acc, item| type_static_length(item).map(|size| acc + size)),
        ir::IrType::Unit => Some(0),
        ir::IrType::Ref(inner) | ir::IrType::MutRef(inner) => type_static_length(inner),
        ir::IrType::Named(_) => None,
    }
}

fn param_metadata_for_body(
    params: &[ir::IrParam],
    body: &ir::IrBody,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> Vec<ParamMetadata> {
    let type_hash_param_ids = param_type_hash_param_ids(body);
    params.iter().map(|param| param_metadata(param, &type_hash_param_ids, cell_type_kinds)).collect()
}

fn param_type_hash_param_ids(body: &ir::IrBody) -> BTreeSet<usize> {
    let mut ids = BTreeSet::new();
    for block in &body.blocks {
        for instruction in &block.instructions {
            if let ir::IrInstruction::TypeHash { operand: ir::IrOperand::Var(var), .. } = instruction {
                if named_type_name(&var.ty).is_some() {
                    ids.insert(var.id);
                }
            }
        }
    }
    ids
}

fn param_metadata(
    param: &ir::IrParam,
    type_hash_param_ids: &BTreeSet<usize>,
    cell_type_kinds: &HashMap<String, ir::IrTypeKind>,
) -> ParamMetadata {
    let schema_pointer_abi = named_type_name(&param.ty).is_some();
    let fixed_byte_len = metadata_fixed_byte_width(&param.ty, type_static_length(&param.ty))
        .filter(|width| *width > 8)
        .or_else(|| metadata_fixed_aggregate_pointer_size(&param.ty));
    let type_hash_abi = schema_pointer_abi && type_hash_param_ids.contains(&param.binding.id);
    let cell_bound_abi = param.is_ref
        || matches!(
            named_type_name(&param.ty).and_then(|name| cell_type_kinds.get(name)),
            Some(ir::IrTypeKind::Resource | ir::IrTypeKind::Shared | ir::IrTypeKind::Receipt)
        );
    ParamMetadata {
        name: param.name.clone(),
        ty: ir_type_to_string(&param.ty),
        is_mut: param.is_mut,
        is_ref: param.is_ref,
        cell_bound_abi,
        schema_pointer_abi,
        schema_length_abi: schema_pointer_abi,
        fixed_byte_pointer_abi: fixed_byte_len.is_some(),
        fixed_byte_length_abi: fixed_byte_len.is_some(),
        fixed_byte_len,
        type_hash_pointer_abi: type_hash_abi,
        type_hash_length_abi: type_hash_abi,
        type_hash_len: type_hash_abi.then_some(32),
    }
}

fn cell_pattern_metadata(pattern: &ir::CellPattern) -> CellPatternMetadata {
    CellPatternMetadata {
        operation: pattern.operation.clone(),
        type_hash: pattern.type_hash.as_ref().map(hex_hash),
        binding: pattern.binding.clone(),
        fields: pattern.fields.iter().map(|(field, _)| field.clone()).collect(),
    }
}

fn create_pattern_metadata(
    pattern: &ir::CreatePattern,
    output_index: usize,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    target_profile: TargetProfile,
) -> CreatePatternMetadata {
    CreatePatternMetadata {
        operation: pattern.operation.clone(),
        ty: pattern.ty.clone(),
        binding: pattern.binding.clone(),
        fields: pattern.fields.iter().map(|(field, _)| field.clone()).collect(),
        has_lock: pattern.lock.is_some(),
        ckb_type_id: ckb_type_id_output_metadata(pattern, output_index, type_defs, target_profile),
    }
}

fn ckb_type_id_output_metadata(
    pattern: &ir::CreatePattern,
    output_index: usize,
    type_defs: &BTreeMap<String, &ir::IrTypeDef>,
    target_profile: TargetProfile,
) -> Option<CkbTypeIdOutputMetadata> {
    if target_profile != TargetProfile::Ckb || pattern.operation != "create" {
        return None;
    }
    let type_def = type_defs.get(&pattern.ty)?;
    ckb_type_id_metadata(type_def, target_profile)?;
    let type_id = type_def.type_id.clone()?;

    Some(CkbTypeIdOutputMetadata {
        abi: CKB_TYPE_ID_ABI.to_string(),
        type_id,
        output_source: CKB_TYPE_ID_OUTPUT_SOURCE.to_string(),
        output_index,
        script_code_hash: hex_encode(&CKB_TYPE_ID_CODE_HASH),
        hash_type: CKB_TYPE_ID_HASH_TYPE.to_string(),
        args_source: CKB_TYPE_ID_ARGS_SOURCE.to_string(),
        builder: CKB_TYPE_ID_BUILDER.to_string(),
        generator_setting: CKB_TYPE_ID_GENERATOR_SETTING.to_string(),
        wasm_setting: CKB_TYPE_ID_WASM_SETTING.to_string(),
    })
}

fn mutate_pattern_metadata(pattern: &ir::MutatePattern, type_layouts: &MetadataTypeLayouts) -> MutatePatternMetadata {
    MutatePatternMetadata {
        operation: pattern.operation.clone(),
        ty: pattern.ty.clone(),
        binding: pattern.binding.clone(),
        fields: pattern.fields.clone(),
        preserved_fields: pattern.preserved_fields.clone(),
        input_source: "Input".to_string(),
        input_index: pattern.input_index,
        output_source: "Output".to_string(),
        output_index: pattern.output_index,
        preserve_type_hash: pattern.preserve_type_hash,
        preserve_lock_hash: pattern.preserve_lock_hash,
        type_hash_preservation_status: "checked-runtime".to_string(),
        lock_hash_preservation_status: "checked-runtime".to_string(),
        field_equality_status: mutate_field_equality_status(pattern, type_layouts).to_string(),
        field_transition_status: mutate_field_transition_status(pattern, type_layouts).to_string(),
    }
}

fn mutate_field_equality_status(pattern: &ir::MutatePattern, type_layouts: &MetadataTypeLayouts) -> &'static str {
    if pattern.preserved_fields.is_empty() {
        return "checked-runtime";
    }
    let checked = pattern
        .preserved_fields
        .iter()
        .filter(|field| mutate_preserved_field_is_verifier_coverable(pattern, field, type_layouts))
        .count();
    if checked == pattern.preserved_fields.len()
        || mutate_preserved_data_except_transition_is_verifier_coverable(pattern, type_layouts)
    {
        "checked-runtime"
    } else if checked > 0 {
        "checked-partial"
    } else {
        "runtime-required"
    }
}

fn mutate_preserved_field_is_verifier_coverable(pattern: &ir::MutatePattern, field: &str, type_layouts: &MetadataTypeLayouts) -> bool {
    let Some(fields) = type_layouts.get(&pattern.ty) else {
        return false;
    };
    let Some(layout) = fields.get(field) else {
        return false;
    };
    if metadata_type_encoded_size_from_layouts(fields).is_none() {
        return true;
    }
    let Some(width) = metadata_layout_fixed_byte_width(layout) else {
        return false;
    };
    layout.offset + width <= METADATA_MUTATE_CELL_BUFFER_SIZE
}

fn mutate_preserved_data_except_transition_is_verifier_coverable(
    pattern: &ir::MutatePattern,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    if pattern.preserved_fields.is_empty() || pattern.transitions.len() != pattern.fields.len() || pattern.transitions.is_empty() {
        return false;
    }
    let Some(fields) = type_layouts.get(&pattern.ty) else {
        return false;
    };
    let dynamic_table = metadata_type_encoded_size_from_layouts(fields).is_none();
    pattern.transitions.iter().all(|transition| {
        fields.get(&transition.field).is_some_and(|layout| {
            if dynamic_table {
                metadata_layout_fixed_byte_width(layout).is_some()
            } else {
                metadata_layout_fixed_byte_width(layout)
                    .map(|width| layout.offset + width)
                    .is_some_and(|end| end <= METADATA_MUTATE_CELL_BUFFER_SIZE)
            }
        })
    })
}

fn mutate_field_transition_status(pattern: &ir::MutatePattern, type_layouts: &MetadataTypeLayouts) -> &'static str {
    if pattern.fields.is_empty() {
        return "checked-runtime";
    }
    let checked = pattern
        .transitions
        .iter()
        .filter(|transition| mutate_transition_is_verifier_coverable(pattern, transition, type_layouts))
        .count();
    if checked == pattern.fields.len() && pattern.transitions.len() == pattern.fields.len() {
        "checked-runtime"
    } else if checked > 0 {
        "checked-partial"
    } else {
        "runtime-required"
    }
}

fn mutate_transition_is_verifier_coverable(
    pattern: &ir::MutatePattern,
    transition: &ir::MutateFieldTransition,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    let Some(fields) = type_layouts.get(&pattern.ty) else {
        return false;
    };
    let Some(layout) = fields.get(&transition.field) else {
        return false;
    };
    let dynamic_table = metadata_type_encoded_size_from_layouts(fields).is_none();
    if transition.op == ir::MutateTransitionOp::Append {
        if !dynamic_table {
            return false;
        }
        let Some(element_width) = metadata_molecule_vector_element_fixed_width(&layout.ty, type_layouts) else {
            return false;
        };
        return match &transition.operand {
            ir::IrOperand::Var(var) => metadata_ir_type_fixed_width(&var.ty, type_layouts) == Some(element_width),
            ir::IrOperand::Const(_) => false,
        };
    }
    if transition.op == ir::MutateTransitionOp::Set {
        let Some(width) = metadata_layout_fixed_byte_width(layout) else {
            return false;
        };
        if !dynamic_table && layout.offset + width > METADATA_MUTATE_CELL_BUFFER_SIZE {
            return false;
        }
        return match &transition.operand {
            ir::IrOperand::Const(ir::IrConst::U64(_))
            | ir::IrOperand::Const(ir::IrConst::Address(_))
            | ir::IrOperand::Const(ir::IrConst::Hash(_))
            | ir::IrOperand::Const(ir::IrConst::Array(_)) => true,
            ir::IrOperand::Var(var) => metadata_fixed_byte_width(&var.ty, type_static_length(&var.ty)).is_some(),
            _ => false,
        };
    }
    // u128 fields are verifier-coverable via 128-bit add/sub with carry.
    if dynamic_table {
        let Some(width) = metadata_layout_fixed_scalar_width(layout) else {
            return false;
        };
        if width > 8 {
            return false;
        }
        return match &transition.operand {
            ir::IrOperand::Const(ir::IrConst::U64(_)) => true,
            ir::IrOperand::Var(var) => matches!(var.ty, ir::IrType::U8 | ir::IrType::U16 | ir::IrType::U32 | ir::IrType::U64),
            _ => false,
        };
    }
    // u128 fields are verifier-coverable via 128-bit add/sub with carry.
    if layout.ty == ir::IrType::U128 && layout.fixed_size == Some(16) {
        if layout.offset + 16 > METADATA_MUTATE_CELL_BUFFER_SIZE {
            return false;
        }
        // The delta must be u64 (fits in a single register for the carry path).
        return match &transition.operand {
            ir::IrOperand::Const(ir::IrConst::U64(_)) => true,
            ir::IrOperand::Var(var) => matches!(var.ty, ir::IrType::U8 | ir::IrType::U16 | ir::IrType::U32 | ir::IrType::U64),
            _ => false,
        };
    }
    // Standard path: fields that fit in a single 64-bit register (≤8 bytes).
    let Some(width) = metadata_layout_fixed_scalar_width(layout) else {
        return false;
    };
    if width > 8 {
        return false;
    }
    if layout.offset + width > METADATA_MUTATE_CELL_BUFFER_SIZE {
        return false;
    }
    match &transition.operand {
        ir::IrOperand::Const(ir::IrConst::U64(_)) => true,
        ir::IrOperand::Var(var) => matches!(var.ty, ir::IrType::U8 | ir::IrType::U16 | ir::IrType::U32 | ir::IrType::U64),
        _ => false,
    }
}

fn metadata_collection_push_is_verified_append(
    collection: &ir::IrOperand,
    value: &ir::IrOperand,
    body: &ir::IrBody,
    type_layouts: &MetadataTypeLayouts,
) -> bool {
    let collection_ty = match collection {
        ir::IrOperand::Var(var) => &var.ty,
        ir::IrOperand::Const(_) => return false,
    };
    let Some(element_width) = metadata_molecule_vector_element_fixed_width(collection_ty, type_layouts) else {
        return false;
    };
    let pushed_var_id = match value {
        ir::IrOperand::Var(var) if metadata_ir_type_fixed_width(&var.ty, type_layouts) == Some(element_width) => var.id,
        _ => return false,
    };
    body.mutate_set.iter().any(|pattern| {
        pattern.transitions.iter().any(|transition| {
            transition.op == ir::MutateTransitionOp::Append
                && matches!(&transition.operand, ir::IrOperand::Var(var) if var.id == pushed_var_id)
                && mutate_transition_is_verifier_coverable(pattern, transition, type_layouts)
        })
    })
}

fn hex_hash(bytes: &[u8; 32]) -> String {
    hex_bytes(bytes)
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

fn collect_package_cell_files(package_root: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    let manifest = load_manifest(package_root)?;
    let mut roots = Vec::new();
    let mut seen_roots = HashSet::new();

    if let Some(package) = &manifest.package {
        if !package.source_roots.is_empty() {
            for source_root in &package.source_roots {
                let root = package_root.join(source_root);
                if !root.exists() {
                    return Err(CompileError::new(
                        format!("configured source root '{}' does not exist", root),
                        error::Span::default(),
                    ));
                }
                if !root.is_dir() {
                    return Err(CompileError::new(
                        format!("configured source root '{}' is not a directory", root),
                        error::Span::default(),
                    ));
                }

                let root = canonical_utf8_path(&root)?;
                if seen_roots.insert(root.clone()) {
                    roots.push(root);
                }
            }
        }
    }

    if roots.is_empty() {
        let src_root = package_root.join("src");
        if src_root.exists() && src_root.is_dir() {
            let src_root = canonical_utf8_path(&src_root)?;
            if seen_roots.insert(src_root.clone()) {
                roots.push(src_root);
            }
        }
    }

    let mut explicit_entry = None;
    if let Some(entry) = manifest.package.as_ref().and_then(|package| package.entry.clone()) {
        let entry_path = package_root.join(entry);
        if !entry_path.exists() {
            return Err(CompileError::new(format!("package entry '{}' does not exist", entry_path), error::Span::default()));
        }
        let entry_path = canonical_utf8_path(&entry_path)?;
        if let Some(entry_parent) = entry_path.parent() {
            let entry_parent = canonical_utf8_path(entry_parent)?;
            if seen_roots.insert(entry_parent.clone()) {
                roots.push(entry_parent);
            }
        }
        explicit_entry = Some(entry_path);
    }

    let mut files = Vec::new();
    let mut seen_files = HashSet::new();
    for root in roots {
        for file in collect_cell_files(&root)? {
            if seen_files.insert(file.clone()) {
                files.push(file);
            }
        }
    }

    if let Some(entry_path) = explicit_entry {
        if seen_files.insert(entry_path.clone()) {
            files.push(entry_path);
        }
    }

    files.sort();
    Ok(files)
}

fn collect_cell_files(root: &Utf8Path) -> Result<Vec<Utf8PathBuf>> {
    let mut files = Vec::new();
    collect_cell_files_recursive(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_cell_files_recursive(root: &Utf8Path, files: &mut Vec<Utf8PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(root)
        .map_err(|e| CompileError::new(format!("failed to read module directory '{}': {}", root, e), error::Span::default()))?;

    for entry in entries {
        let entry = entry.map_err(|e| CompileError::new(format!("failed to read directory entry: {}", e), error::Span::default()))?;
        let path = entry.path();
        let Ok(candidate) = Utf8PathBuf::from_path_buf(path) else {
            continue;
        };

        if candidate.is_dir() {
            if should_skip_cell_dir(&candidate) {
                continue;
            }
            collect_cell_files_recursive(&candidate, files)?;
            continue;
        }

        if candidate.extension() == Some("cell") {
            files.push(canonical_utf8_path(&candidate)?);
        }
    }

    Ok(())
}

fn should_skip_cell_dir(path: &Utf8Path) -> bool {
    matches!(path.file_name(), Some(".git" | ".cell" | "target"))
}

fn register_module_file(resolver: &mut ModuleResolver, path: &Utf8Path) -> Result<()> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| CompileError::new(format!("failed to read module file '{}': {}", path, e), error::Span::default()))?;
    let tokens = lexer::lex(&source).map_err(|e| e.with_file(path.to_path_buf()))?;
    let module = parser::parse(&tokens).map_err(|e| e.with_file(path.to_path_buf()))?;
    resolver.register_module(module)
}

fn canonical_utf8_path(path: &Utf8Path) -> Result<Utf8PathBuf> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| CompileError::new(format!("failed to canonicalize '{}': {}", path, e), error::Span::default()))?;
    Utf8PathBuf::from_path_buf(canonical)
        .map_err(|non_utf8| CompileError::new(format!("path is not valid UTF-8: {}", non_utf8.display()), error::Span::default()))
}

fn default_package_entry() -> String {
    "src/main.cell".to_string()
}

fn load_manifest(package_root: &Utf8Path) -> Result<CellManifest> {
    let manifest_path = package_root.join("Cell.toml");
    if !manifest_path.exists() {
        return Err(CompileError::new(format!("Cell.toml not found in '{}'", package_root), error::Span::default()));
    }

    let manifest_source = std::fs::read_to_string(&manifest_path)
        .map_err(|e| CompileError::new(format!("failed to read manifest '{}': {}", manifest_path, e), error::Span::default()))?;
    toml::from_str(&manifest_source)
        .map_err(|e| CompileError::new(format!("failed to parse manifest '{}': {}", manifest_path, e), error::Span::default()))
}

fn dependency_hint(detail: &CellDependencyDetail) -> String {
    if let Some(git) = &detail.git {
        return format!(" (git dependency '{}')", git);
    }
    if let Some(version) = &detail.version {
        return format!(" (version '{}')", version);
    }
    if detail.branch.is_some() || detail.tag.is_some() || detail.rev.is_some() {
        return " (non-path source metadata present)".to_string();
    }
    String::new()
}

fn resolve_target<'a>(options: &'a CompileOptions, build: Option<&'a CellBuildConfig>) -> &'a str {
    options.target.as_deref().or_else(|| build.and_then(|build| build.target.as_deref())).unwrap_or(DEFAULT_TARGET)
}

/// Compiler version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Compiler name
pub const NAME: &str = "cellc";

#[cfg(test)]
mod tests {
    use super::{
        compile, compile_file, compile_file_with_entry_action, compile_file_with_entry_lock, compile_path,
        decode_scheduler_witness_hex, default_output_path_for_input, encode_entry_witness_args_for_params, load_modules_for_input,
        resolve_input_path, ActionMetadata, ArtifactFormat, CompileOptions, EntryWitnessArg, ENTRY_WITNESS_ABI_MAGIC,
        SCHEDULER_WITNESS_ABI_MOLECULE,
    };
    use crate::{ir, lexer, parser};
    use camino::{Utf8Path, Utf8PathBuf};
    use tempfile::tempdir;

    fn rebind_artifact_integrity_for_test(result: &mut crate::CompileResult) {
        result.artifact_hash = *blake3::hash(&result.artifact_bytes).as_bytes();
        result.metadata.artifact_hash_blake3 = Some(crate::hex_encode(&result.artifact_hash));
        result.metadata.artifact_size_bytes = Some(result.artifact_bytes.len());
    }

    fn parse_module_for_test(source: &str) -> crate::ast::Module {
        let tokens = lexer::lex(source).unwrap();
        parser::parse(&tokens).unwrap()
    }

    fn compile_metadata_for_profile_without_artifact_policy(
        source: &str,
        target_profile: crate::TargetProfile,
    ) -> crate::CompileMetadata {
        let ast = parse_module_for_test(source);
        crate::types::check(&ast).unwrap();
        crate::lifecycle::check(&ast).unwrap();
        let ir = ir::generate(&ast).unwrap();
        let metadata = crate::compile_metadata_from_ir(&ir, ArtifactFormat::RiscvAssembly, target_profile);
        crate::validate_compile_metadata(&metadata, ArtifactFormat::RiscvAssembly).unwrap();
        metadata
    }

    const SIMPLE_PROGRAM: &str = r#"
module test

action add(x: u64, y: u64) -> u64 {
    let z = x + y
    return z
}
"#;

    #[derive(Debug)]
    struct SchedulerAccessWitness {
        operation: u8,
        source: u8,
        index: u32,
        binding_hash: [u8; 32],
    }

    #[derive(Debug)]
    struct SchedulerWitness {
        magic: u16,
        version: u8,
        effect_class: u8,
        parallelizable: bool,
        touches_shared_count: u32,
        touches_shared: Vec<[u8; 32]>,
        estimated_cycles: u64,
        access_count: u32,
        accesses: Vec<SchedulerAccessWitness>,
    }

    fn decode_molecule_scheduler_witness_hex(hex: &str) -> SchedulerWitness {
        let bytes = decode_scheduler_witness_hex(hex).expect("scheduler witness hex should decode");
        let fields = decode_molecule_table(&bytes, 9);
        SchedulerWitness {
            magic: read_u16(fields[0], "magic"),
            version: read_u8(fields[1], "version"),
            effect_class: read_u8(fields[2], "effect_class"),
            parallelizable: read_bool(fields[3], "parallelizable"),
            touches_shared_count: read_u32(fields[4], "touches_shared_count"),
            touches_shared: read_fixvec_byte32(fields[5]),
            estimated_cycles: read_u64(fields[6], "estimated_cycles"),
            access_count: read_u32(fields[7], "access_count"),
            accesses: read_scheduler_accesses(fields[8]),
        }
    }

    fn decode_molecule_table(bytes: &[u8], expected_fields: usize) -> Vec<&[u8]> {
        assert!(bytes.len() >= 8, "molecule table header is too short: {}", bytes.len());
        let total_size = read_u32(&bytes[..4], "total_size") as usize;
        assert_eq!(total_size, bytes.len(), "molecule table total size mismatch");
        let first_offset = read_u32(&bytes[4..8], "first_offset") as usize;
        assert!(first_offset >= 8 && first_offset <= bytes.len() && first_offset % 4 == 0, "invalid first offset {first_offset}");
        let field_count = first_offset / 4 - 1;
        assert_eq!(field_count, expected_fields, "unexpected molecule table field count");
        let mut offsets = bytes[4..first_offset].chunks_exact(4).map(|chunk| read_u32(chunk, "offset") as usize).collect::<Vec<_>>();
        offsets.push(total_size);
        for pair in offsets.windows(2) {
            assert!(pair[0] <= pair[1], "molecule offsets must be monotonic: {:?}", offsets);
            assert!(pair[0] >= first_offset && pair[1] <= total_size, "molecule offsets must stay in payload: {:?}", offsets);
        }
        offsets.windows(2).map(|pair| &bytes[pair[0]..pair[1]]).collect()
    }

    fn read_scheduler_accesses(bytes: &[u8]) -> Vec<SchedulerAccessWitness> {
        let count = read_u32(&bytes[..4], "access_count") as usize;
        assert_eq!(bytes.len(), 4 + count * 38, "access fixvec byte length mismatch");
        bytes[4..]
            .chunks_exact(38)
            .map(|chunk| SchedulerAccessWitness {
                operation: chunk[0],
                source: chunk[1],
                index: read_u32(&chunk[2..6], "access.index"),
                binding_hash: chunk[6..38].try_into().expect("binding hash width"),
            })
            .collect()
    }

    fn read_fixvec_byte32(bytes: &[u8]) -> Vec<[u8; 32]> {
        let count = read_u32(&bytes[..4], "byte32_count") as usize;
        assert_eq!(bytes.len(), 4 + count * 32, "byte32 fixvec byte length mismatch");
        bytes[4..].chunks_exact(32).map(|chunk| chunk.try_into().expect("byte32 width")).collect()
    }

    fn read_u8(bytes: &[u8], field: &str) -> u8 {
        assert_eq!(bytes.len(), 1, "{field} should be a molecule byte");
        bytes[0]
    }

    fn read_bool(bytes: &[u8], field: &str) -> bool {
        match read_u8(bytes, field) {
            0 => false,
            1 => true,
            value => panic!("{field} should be a molecule bool, got {value}"),
        }
    }

    fn read_u16(bytes: &[u8], field: &str) -> u16 {
        assert_eq!(bytes.len(), 2, "{field} should be a molecule u16");
        u16::from_le_bytes(bytes.try_into().expect("u16 width"))
    }

    fn read_u32(bytes: &[u8], field: &str) -> u32 {
        assert_eq!(bytes.len(), 4, "{field} should be a molecule u32");
        u32::from_le_bytes(bytes.try_into().expect("u32 width"))
    }

    fn read_u64(bytes: &[u8], field: &str) -> u64 {
        assert_eq!(bytes.len(), 8, "{field} should be a molecule u64");
        u64::from_le_bytes(bytes.try_into().expect("u64 width"))
    }

    const OPTIMIZER_PROGRAM: &str = r#"
module test

action calc() -> u64 {
    return (2 + 3) * 4
}
"#;

    const IF_PROGRAM: &str = r#"
module test

action increment_if(flag: bool, x: u64) -> u64 {
    if flag {
        let tmp = x + 1
    }
    return x
}
"#;

    const CALL_PROGRAM: &str = r#"
module test

action double(x: u64) -> u64 {
    return x + x
}

action run(y: u64) -> u64 {
    let z = double(y)
    return z
}
"#;

    const IF_EXPR_PROGRAM: &str = r#"
module test

action choose(flag: bool, x: u64) -> u64 {
    let y = if flag { x + 1 } else { x + 2 }
    return y
}
"#;

    const WHILE_PROGRAM: &str = r#"
module test

action spin(flag: bool, x: u64) -> u64 {
    while flag {
        let tmp = x + 1
    }
    return x
}
"#;

    const FOR_RANGE_PROGRAM: &str = r#"
module test

action visit(n: u64) -> u64 {
    for i in 0..n {
        let tmp = i + 1
    }
    return n
}
"#;

    const ASSIGN_PROGRAM: &str = r#"
module test

action countdown(n: u64) -> u64 {
    let mut x: u64 = n
    while x > 0 {
        x = x - 1
    }
    x += 1
    return x
}
"#;

    const LOOP_LOCAL_LINEAR_COMPLETE_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action ok(n: u64) {
    for i in 0..n {
        let out = create Token {
            amount: i
        }
        destroy out
    }
}
"#;

    const LOOP_DROPPED_LOCAL_LINEAR_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(n: u64) {
    for i in 0..n {
        let out = create Token {
            amount: i
        }
    }
}
"#;

    const FOR_LOOP_PARENT_LINEAR_CHANGE_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token, n: u64) {
    for i in 0..n {
        destroy token
    }
    destroy token
}
"#;

    const WHILE_LOOP_PARENT_LINEAR_CHANGE_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token, flag: bool) {
    while flag {
        destroy token
    }
    destroy token
}
"#;

    const STRUCT_FIELD_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
    y: u64,
}

action tweak() -> u64 {
    let mut p = Point { x: 1, y: 2 }
    let a = p.x
    p.x = a + 4
    p.x += 1
    return p.x
}
"#;

    const TEMPORARY_FIELD_ASSIGN_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
    y: u64,
}

fn point() -> Point {
    return Point { x: 1, y: 2 }
}

action bad() -> u64 {
    point().x = 3
    return 0
}
"#;

    const READ_REF_FIELD_ASSIGN_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

action bad() -> u64 {
    read_ref<Config>().threshold = 2
    return 0
}
"#;

    const READ_REF_BINDING_FIELD_ASSIGN_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

action bad() -> u64 {
    let mut cfg = read_ref<Config>()
    cfg.threshold = 2
    return cfg.threshold
}
"#;

    const READ_ONLY_REF_FIELD_ASSIGN_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

action bad() -> u64 {
    let mut point = Point { x: 1 }
    let mut view = &point
    view.x = 2
    return point.x
}
"#;

    const MUT_CELL_PARAM_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(mut token: Token) {
    consume token
}
"#;

    const MUT_READ_REF_PARAM_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

action bad(mut cfg: read_ref Config) -> u64 {
    return cfg.threshold
}
"#;

    const REDUNDANT_MUT_REF_PARAM_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(mut pool: &mut Pool) {
    pool.reserve = pool.reserve + 1
}
"#;

    const FUNCTION_MUT_REF_PARAM_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

fn bad(pool: &mut Pool) -> u64 {
    pool.reserve = pool.reserve + 1
    return pool.reserve
}
"#;

    const LOCK_MUT_REF_PARAM_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

lock bad(pool: &mut Pool) -> bool {
    pool.reserve = pool.reserve + 1
    return true
}
"#;

    const MUT_REF_LOCAL_ALIAS_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(pool: &mut Pool) -> u64 {
    let alias = pool
    alias.reserve = alias.reserve + 1
    return alias.reserve
}
"#;

    const MUT_REF_TUPLE_ALIAS_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(pool: &mut Pool) -> u64 {
    let pair = (pool, 0)
    pair.0.reserve = pair.0.reserve + 1
    return pair.0.reserve
}
"#;

    const MUT_REF_IF_ALIAS_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(pool: &mut Pool, flag: bool) -> u64 {
    let alias = if flag { pool } else { pool }
    alias.reserve = alias.reserve + 1
    return alias.reserve
}
"#;

    const MUT_REF_ASSIGN_ALIAS_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(pool: &mut Pool) -> u64 {
    let mut alias = read_ref<Pool>()
    alias = pool
    return alias.reserve
}
"#;

    const MUT_REF_DUPLICATE_CALL_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bump_pair(left: &mut Pool, right: &mut Pool) {
    left.reserve = left.reserve + 1
    right.reserve = right.reserve + 1
}

action bad(pool: &mut Pool) {
    bump_pair(pool, pool)
}
"#;

    const MUT_REF_BLOCK_DUPLICATE_CALL_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bump_pair(left: &mut Pool, right: &mut Pool) {
    left.reserve = left.reserve + 1
    right.reserve = right.reserve + 1
}

action bad(pool: &mut Pool) {
    bump_pair({ pool }, pool)
}
"#;

    const MUT_REF_IF_DUPLICATE_CALL_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bump_pair(left: &mut Pool, right: &mut Pool) {
    left.reserve = left.reserve + 1
    right.reserve = right.reserve + 1
}

action bad(pool: &mut Pool, flag: bool) {
    bump_pair(if flag { pool } else { pool }, pool)
}
"#;

    const MUT_REF_MIXED_DUPLICATE_CALL_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bump_with_view(target: &mut Pool, view: &Pool) -> u64 {
    target.reserve = target.reserve + 1
    return view.reserve
}

action bad(pool: &mut Pool) -> u64 {
    return bump_with_view(pool, pool)
}
"#;

    const MUT_REF_DUPLICATE_READ_ONLY_CALL_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

fn sum_views(left: &Pool, right: &Pool) -> u64 {
    return left.reserve + right.reserve
}

action ok(pool: &mut Pool) -> u64 {
    return sum_views(pool, pool)
}
"#;

    const OWNED_LINEAR_FIELD_ASSIGN_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad() {
    let mut token = create Token { amount: 1 }
    token.amount = 2
    destroy token
}
"#;

    const LINEAR_LOCAL_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let view = &token
    destroy token
    return view.amount
}
"#;

    const LINEAR_FIELD_LOCAL_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let amount = &token.amount
    destroy token
    return 0
}
"#;

    const LINEAR_TUPLE_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let pair = (&token, 0)
    destroy token
    return pair.0.amount
}
"#;

    const LINEAR_ARRAY_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let refs = [&token]
    destroy token
    return refs[0].amount
}
"#;

    const LINEAR_IF_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token, flag: bool) -> u64 {
    let view = if flag { &token } else { &token }
    destroy token
    return view.amount
}
"#;

    const LINEAR_ASSIGN_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let mut view = read_ref<Token>()
    view = &token
    destroy token
    return view.amount
}
"#;

    const LINEAR_ASSIGN_TUPLE_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let mut pair = (read_ref<Token>(), 0)
    pair = (&token, 0)
    destroy token
    return pair.0.amount
}
"#;

    const LINEAR_ASSIGN_TUPLE_FIELD_REF_ALIAS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(token: Token) -> u64 {
    let mut pair = (read_ref<Token>(), 0)
    pair.0 = &token
    destroy token
    return pair.0.amount
}
"#;

    const ACTION_RETURN_REF_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action leak(token: Token) -> &Token {
    return &token
}
"#;

    const FUNCTION_RETURN_REF_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

fn leak(point: &Point) -> &Point {
    return point
}
"#;

    const FUNCTION_CELL_PARAM_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

fn bad(token: Token) -> u64 {
    return token.amount
}
"#;

    const FUNCTION_CELL_RETURN_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

    fn bad(amount: u64) -> Token {
        return amount
    }
"#;

    const LOCK_CELL_PARAM_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

    lock bad(token: Token) -> bool {
        return true
    }
"#;

    const CALLABLE_REFERENCE_TO_CELL_AGGREGATE_PARAM_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

fn bad(pair: &(Token, u64)) -> u64 {
    return 0
}
"#;

    const CALLABLE_MUT_REFERENCE_TO_CELL_AGGREGATE_PARAM_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(pool: &mut (Pool, u64)) -> u64 {
    return 0
}
"#;

    const FUNCTION_VEC_CELL_PARAM_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

fn bad(tokens: Vec<Token>) -> u64 {
    return 0
}
"#;

    const STRUCT_VEC_REFERENCE_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

struct Holder {
    views: Vec<&Token>,
}
"#;

    const VEC_PUSH_REFERENCE_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

action bad(point: Point) -> u64 {
    let points = Vec::new()
    points.push(&point)
    return 0
}
"#;

    const CALLABLE_TUPLE_REFERENCE_PARAM_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

fn bad(pair: (&Point, u64)) -> u64 {
    return pair.1
}
"#;

    const CALLABLE_ARRAY_MUT_REFERENCE_PARAM_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
}

action bad(pools: [&mut Pool; 1]) {
}
"#;

    const CALLABLE_NESTED_REFERENCE_PARAM_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

fn bad(view: &read_ref Point) -> u64 {
    return view.x
}
"#;

    const ACTION_REF_PARAM_MODIFIER_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(ref token: Token) {
    consume token
}
"#;

    const FUNCTION_REF_PARAM_MODIFIER_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

fn bad(ref point: Point) -> u64 {
    return point.x
}
"#;

    const LOCK_REF_PARAM_MODIFIER_PROGRAM: &str = r#"
module test

lock bad(ref owner: Address) -> bool {
    return true
}
"#;

    const SCHEMA_REFERENCE_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

struct Holder {
    view: &Token,
}
"#;

    const ENUM_REFERENCE_PAYLOAD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

enum MaybeToken {
    Some(&Token),
    None,
}
"#;

    const IF_MISMATCH_PROGRAM: &str = r#"
module test

action choose(flag: bool) -> u64 {
    let y = if flag { 1 } else { false }
    return 1
}
"#;

    const UNKNOWN_FIELD_PROGRAM: &str = r#"
module test

struct Point {
    x: u64,
}

action read(p: Point) -> u64 {
    return p.y
}
"#;

    const DUPLICATE_RESOURCE_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
    amount: u128,
}
"#;

    const DUPLICATE_SHARED_FIELD_PROGRAM: &str = r#"
module test

shared Pool {
    reserve: u64,
    reserve: u64,
}
"#;

    const DUPLICATE_RECEIPT_FIELD_PROGRAM: &str = r#"
module test

receipt Grant {
    amount: u64,
    amount: u64,
}
"#;

    const WILDCARD_STRUCT_FIELD_PROGRAM: &str = r#"
module test

struct Point {
    _: u64,
}
"#;

    const UNKNOWN_FUNCTION_PROGRAM: &str = r#"
module test

action run(x: u64) -> u64 {
    return missing(x)
}
"#;

    const CONSTANT_PROGRAM: &str = r#"
module test

const STEP: u64 = 3;

action bump(x: u64) -> u64 {
    return x + STEP
}
"#;

    const CAST_PROGRAM: &str = r#"
module test

action widen(x: u16) -> u64 {
    return x as u64
}
"#;

    const ASSERT_PROGRAM: &str = r#"
module test

action checked(x: u64) -> u64 {
    assert_invariant(x > 0, "x must be positive")
    return x
}
"#;

    const ASSERT_NON_BOOL_PROGRAM: &str = r#"
module test

action bad(x: u64) -> u64 {
    assert_invariant(x, "x must be boolean")
    return x
}
"#;

    const ASSERT_DYNAMIC_MESSAGE_PROGRAM: &str = r#"
module test

action bad(x: u64) -> u64 {
    assert_invariant(x > 0, x)
    return x
}
"#;

    const ASSERT_BINDING_PROGRAM: &str = r#"
module test

action bad(x: u64) -> u64 {
    let ok = assert_invariant(x > 0, "x must be positive")
    return x
}
"#;

    const ASSERT_TAIL_RETURN_PROGRAM: &str = r#"
module test

action bad(x: u64) -> bool {
    assert_invariant(x > 0, "x must be positive")
}
"#;

    const STRING_VALUE_PROGRAM: &str = r#"
module test

action bad() -> String {
    return "not a lowered runtime value"
}
"#;

    const CREATE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action mint(owner: Address) -> Token {
    let token = create Token {
        amount: 42
    } with_lock(owner)
    return token
}
"#;

    const CREATE_VERIFY_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue() -> Token {
    let token = create Token {
        amount: 42
    }
    return token
}
"#;

    const CREATE_UNSUPPORTED_OUTPUT_EXPR_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue(amount: u64) -> Token {
    let token = create Token {
        amount: amount * 2
    }
    return token
}
"#;

    const CREATE_UNSUPPORTED_DYNAMIC_OUTPUT_PROGRAM: &str = r#"
module test

resource Fingerprint {
    digest: Hash,
}

fn pass_digest(digest: Hash) -> Hash {
    return digest
}

action issue(digest: Hash) -> Fingerprint {
    let dynamic_digest = pass_digest(digest)
    let token = create Fingerprint {
        digest: dynamic_digest
    }
    return token
}
"#;

    const CREATE_DUPLICATE_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue() -> Token {
    return create Token {
        amount: 1,
        amount: 2,
    }
}
"#;

    const CREATE_MISSING_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
    owner: Address,
}

action issue(owner: Address) -> Token {
    return create Token {
        amount: 1,
    }
}
"#;

    const CREATE_UNKNOWN_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue() -> Token {
    return create Token {
        amount: 1,
        owner: Address::zero(),
    }
}
"#;

    const CREATE_FIELD_TYPE_MISMATCH_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue() -> Token {
    return create Token {
        amount: false,
    }
}
"#;

    const CREATE_STRUCT_TARGET_PROGRAM: &str = r#"
module test

struct Snapshot {
    amount: u64,
}

action bad() -> Snapshot {
    return create Snapshot {
        amount: 1,
    }
}
"#;

    const CONSUME_NON_CELL_PROGRAM: &str = r#"
module test

struct Snapshot {
    amount: u64,
}

action bad(snapshot: Snapshot) -> u64 {
    consume snapshot
    return 0
}
"#;

    const CONSUME_NON_NAMED_CELL_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(token: Token) -> u64 {
    consume if true { token } else { token }
    return 0
}
"#;

    const TRANSFER_NON_NAMED_CELL_PROGRAM: &str = r#"
module test

resource Token has transfer {
    amount: u64,
}

action bad(owner: Address) -> Token {
    return transfer create Token { amount: 1 } to owner
}
"#;

    const LINEAR_LET_MOVE_PROGRAM: &str = r#"
module test

resource Token has transfer {
    amount: u64,
}

action move_alias(token: Token, owner: Address) -> Token {
    let moved = token
    return transfer moved to owner
}
"#;

    const LINEAR_LET_COPY_PROGRAM: &str = r#"
module test

resource Token has transfer, destroy {
    amount: u64,
}

action duplicate(token: Token, owner: Address) {
    let copied = token
    transfer token to owner
    destroy copied
}
"#;

    const IF_BOTH_BRANCHES_CONSUME_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action burn(token: Token, flag: bool) {
    if flag {
        consume token
    } else {
        consume token
    }
}
"#;

    const IF_PARTIAL_BRANCH_CONSUME_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action burn(token: Token, flag: bool) {
    if flag {
        consume token
    }
    consume token
}
"#;

    const IF_MISMATCHED_BRANCH_CONSUME_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action burn(token: Token, flag: bool) {
    if flag {
        consume token
    } else {
        let amount = token.amount
    }
    consume token
}
"#;

    const CONSUME_DESTROY_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action burn(a: Token, b: Token) {
    consume a
    destroy b
}
"#;

    const PARAM_FIELD_PROGRAM: &str = r#"
module test

struct Snapshot {
    amount: u64,
}

action inspect(snapshot: Snapshot) -> u64 {
    return snapshot.amount
}
"#;

    const FIXED_BYTE_FIELD_COMPARISON_PROGRAM: &str = r#"
module test

resource Token {
    symbol: [u8; 8],
}

action same_symbol(left: Token, right: Token) -> bool {
    let same = left.symbol == right.symbol
    consume left
    consume right
    return same
}
"#;

    const PACKED_SCALAR_FIELD_PROGRAM: &str = r#"
module test

shared Flags {
    enabled: bool,
    nonce: u32,
}

action inspect() -> u32 {
    let flags = read_ref<Flags>()
    let enabled = flags.enabled
    return flags.nonce
}
"#;

    const CREATE_SCALAR_VERIFY_PROGRAM: &str = r#"
module test

resource Flags {
    enabled: bool,
    nonce: u32,
}

action issue(nonce: u32) -> Flags {
    let enabled = true
    let out = create Flags {
        enabled: enabled,
        nonce: nonce
    }
    return out
}
"#;

    const CONSUME_CREATE_SCALAR_ALIAS_PROGRAM: &str = r#"
module test

resource Flags {
    enabled: bool,
    nonce: u32,
}

action pass(flags: Flags) -> Flags {
    let enabled = flags.enabled
    let nonce = flags.nonce
    consume flags
    let out = create Flags {
        enabled: enabled,
        nonce: nonce
    }
    return out
}
"#;

    const READ_REF_FIELD_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

action inspect() -> u64 {
    let cfg = read_ref<Config>()
    return cfg.threshold
}
"#;

    const READ_REF_STRUCT_TARGET_PROGRAM: &str = r#"
module test

struct Snapshot {
    amount: u64,
}

action bad() -> u64 {
    let snapshot = read_ref<Snapshot>()
    return snapshot.amount
}
"#;

    const READ_ONLY_EFFECT_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

#[effect(ReadOnly)]
action inspect() -> u64 {
    let cfg = read_ref<Config>()
    return cfg.threshold
}
"#;

    const UNDERDECLARED_EFFECT_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

#[effect(ReadOnly)]
action issue(amount: u64) -> Token {
    let out = create Token {
        amount: amount
    }
    return out
}
"#;

    const IMPURE_FN_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

fn helper() -> u64 {
    let cfg = read_ref<Config>()
    return cfg.threshold
}
"#;

    const INDIRECT_IMPURE_FN_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action issue(amount: u64) -> u64 {
    let out = create Token {
        amount: amount
    }
    destroy out
    return amount
}

fn helper(amount: u64) -> u64 {
    return issue(amount)
}
"#;

    const FN_ENV_RUNTIME_PROGRAM: &str = r#"
module test

fn helper() -> u64 {
    return env::current_daa_score()
}
"#;

    const FN_CKB_HEADER_RUNTIME_PROGRAM: &str = r#"
module test

fn helper() -> u64 {
    return ckb::header_epoch_number()
}
"#;

    const FN_TYPE_HASH_RUNTIME_PROGRAM: &str = r#"
module test

struct Plain {
    value: u64,
}

fn helper(plain: Plain) -> Hash {
    return plain.type_hash()
}
"#;

    const ACTION_CALLS_FN_PROGRAM: &str = r#"
module test

fn add_one(x: u64) -> u64 {
    return x + 1
}

action run(x: u64) -> u64 {
    return add_one(x)
}
"#;

    const CALL_MISSING_ARGUMENT_PROGRAM: &str = r#"
module test

fn add(a: u64, b: u64) -> u64 {
    return a + b
}

action run(x: u64) -> u64 {
    return add(x)
}
"#;

    const CALL_TYPE_MISMATCH_PROGRAM: &str = r#"
module test

fn add(a: u64, b: u64) -> u64 {
    return a + b
}

action run(x: u64) -> u64 {
    return add(x, false)
}
"#;

    const QUALIFIED_ACTION_CALLS_FN_PROGRAM: &str = r#"
module test

fn add_one(x: u64) -> u64 {
    return x + 1
}

action run(x: u64) -> u64 {
    return test::add_one(x)
}
"#;

    const QUALIFIED_CALL_EXTRA_ARGUMENT_PROGRAM: &str = r#"
module test

fn add_one(x: u64) -> u64 {
    return x + 1
}

action run(x: u64) -> u64 {
    return test::add_one(x, 2)
}
"#;

    const BOOL_FN_CALL_PROGRAM: &str = r#"
module test

fn ready() -> bool {
    return true
}

action run() -> bool {
    return test::ready()
}
"#;

    const DUPLICATE_ACTION_PARAM_PROGRAM: &str = r#"
module test

action bad(x: u64, x: u64) -> u64 {
    return x
}
"#;

    const WILDCARD_ACTION_PARAM_PROGRAM: &str = r#"
module test

action bad(_: u64) -> u64 {
    return 1
}
"#;

    const DUPLICATE_FN_PARAM_PROGRAM: &str = r#"
module test

fn bad(x: u64, x: u64) -> u64 {
    return x
}

action run() -> u64 {
    return 1
}
"#;

    const WILDCARD_LOCK_PARAM_PROGRAM: &str = r#"
module test

lock owned(_: Address) -> bool {
    return true
}
"#;

    const LOCAL_BINDING_REUSE_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let x = 1
    let x = 2
    return x
}
"#;

    const TUPLE_BINDING_REUSE_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let (x, x) = (1, 2)
    return x
}
"#;

    const BLOCK_BINDING_SHADOW_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let x = 1
    let y = {
        let x = 2
        x
    }
    return x + y
}
"#;

    const UNIT_FN_CALL_PROGRAM: &str = r#"
module test

fn note(x: u64) {
    let y = x + 1
}

action run(x: u64) -> u64 {
    note(x)
    return x
}
"#;

    const BIND_UNIT_FN_CALL_PROGRAM: &str = r#"
module test

fn note(x: u64) {
    let y = x + 1
}

action bad(x: u64) -> u64 {
    let y = note(x)
    return x
}
"#;

    const RETURN_UNIT_FN_CALL_PROGRAM: &str = r#"
module test

fn note(x: u64) {
    let y = x + 1
}

action bad(x: u64) -> u64 {
    return note(x)
}
"#;

    const RETURN_VALUE_FROM_UNIT_ACTION_PROGRAM: &str = r#"
module test

action bad() {
    return 1
}
"#;

    const BARE_RETURN_FROM_VALUE_ACTION_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    return
}
"#;

    const MISSING_ACTION_RETURN_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let x = 1
}
"#;

    const MISSING_FUNCTION_RETURN_PROGRAM: &str = r#"
module test

fn bad() -> u64 {
    let x = 1
}

action run() -> u64 {
    return 1
}
"#;

    const TAIL_EXPR_ACTION_RETURN_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    1
}
"#;

    const BRANCH_COMPLETE_RETURN_PROGRAM: &str = r#"
module test

action choose(flag: bool) -> u64 {
    if flag {
        return 1
    } else {
        return 2
    }
}
"#;

    const LINEAR_BRANCH_RETURN_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action choose(token: Token, flag: bool) -> Token {
    if flag {
        return token
    } else {
        return token
    }
}
"#;

    const LINEAR_BRANCH_INCONSISTENT_RETURN_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(token: Token, flag: bool) -> u64 {
    if flag {
        return 1
    } else {
        consume token
        return 2
    }
}
"#;

    const LINEAR_TAIL_IF_RETURN_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action choose(token: Token, flag: bool) -> Token {
    if flag { token } else { token }
}
"#;

    const LINEAR_TAIL_IF_INCONSISTENT_RETURN_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(left: Token, right: Token, flag: bool) -> Token {
    if flag { left } else { right }
}
"#;

    const LINEAR_IF_EXPR_LET_MOVE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action choose(token: Token, flag: bool) -> Token {
    let moved = if flag { token } else { token }
    return moved
}
"#;

    const LINEAR_IF_EXPR_INCONSISTENT_LET_MOVE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(left: Token, right: Token, flag: bool) -> Token {
    let moved = if flag { left } else { right }
    return moved
}
"#;

    const LINEAR_IF_EXPR_STATEFUL_BRANCHES_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action burn(token: Token, flag: bool) -> u64 {
    if flag { destroy token } else { destroy token }
}
"#;

    const LINEAR_TUPLE_BINDING_DROPPED_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(left: Token, right: Token) {
    let pair = (left, right)
}
"#;

    const LINEAR_ARRAY_BINDING_DROPPED_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(left: Token, right: Token) {
    let items = [left, right]
}
"#;

    const LINEAR_TUPLE_DESTRUCTURE_HANDLES_ITEMS_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action choose(left: Token, right: Token) -> Token {
    let (kept, burned) = (left, right)
    destroy burned
    return kept
}
"#;

    const LINEAR_WILDCARD_DISCARD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(token: Token) {
    let _ = token
}
"#;

    const LINEAR_TUPLE_WILDCARD_DISCARD_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(left: Token, right: Token) {
    let (_, kept) = (left, right)
    destroy kept
}
"#;

    const LINEAR_TUPLE_FIELD_PROJECTION_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(left: Token, right: Token) -> (Token, Token) {
    let pair = (left, right)
    let first = pair.0
    destroy first
    pair
}
"#;

    const LINEAR_ARRAY_INDEX_PROJECTION_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action bad(left: Token, right: Token) {
    let items = [left, right]
    let first = items[0]
    destroy first
}
"#;

    const LINEAR_BLOCK_EXPR_LET_MOVE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action choose(token: Token) -> Token {
    let moved = { token }
    return moved
}
"#;

    const LINEAR_BLOCK_EXPR_PREFIX_MOVE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action choose(token: Token) -> Token {
    let moved = {
        let inner = token
        inner
    }
    return moved
}
"#;

    const LINEAR_BLOCK_EXPR_STATEFUL_PROGRAM: &str = r#"
module test

resource Token has destroy {
    amount: u64,
}

action burn(token: Token) -> u64 {
    { destroy token }
}
"#;

    const LINEAR_BLOCK_EXPR_DROPPED_LOCAL_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad() -> u64 {
    {
        let out = create Token {
            amount: 1
        }
        1
    }
}
"#;

    const BLOCK_TAIL_IF_VALUE_PROGRAM: &str = r#"
module test

action choose(flag: bool) -> u64 {
    let value = {
        if flag {
            1
        } else {
            2
        }
    }
    return value
}
"#;

    const LINEAR_BLOCK_TAIL_IF_MOVE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action choose(token: Token, flag: bool) -> Token {
    let moved = {
        let inner = token
        if flag { inner } else { inner }
    }
    return moved
}
"#;

    const LINEAR_BLOCK_TAIL_IF_INCONSISTENT_MOVE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action bad(left: Token, right: Token, flag: bool) -> Token {
    let moved = {
        if flag { left } else { right }
    }
    return moved
}
"#;

    const TAIL_IF_ACTION_RETURN_PROGRAM: &str = r#"
module test

action choose(flag: bool) -> u64 {
    if flag { 1 } else { 2 }
}
"#;

    const BRANCH_INCOMPLETE_RETURN_PROGRAM: &str = r#"
module test

action bad(flag: bool) -> u64 {
    if flag {
        return 1
    }
    let x = 2
}
"#;

    const UNREACHABLE_AFTER_RETURN_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    return 1
    let x = 2
}
"#;

    const UNREACHABLE_AFTER_BRANCH_RETURN_PROGRAM: &str = r#"
module test

action bad(flag: bool) -> u64 {
    if flag {
        return 1
    } else {
        return 2
    }
    let x = 3
}
"#;

    const ENV_DAA_PROGRAM: &str = r#"
module test

action now() -> u64 {
    return env::current_daa_score()
}
"#;

    const CKB_HEADER_EPOCH_PROGRAM: &str = r#"
module test

action epoch() -> u64 {
    let number = ckb::header_epoch_number()
    let start = ckb::header_epoch_start_block_number()
    let length = ckb::header_epoch_length()
    let since = ckb::input_since()
    return number + start + length + since
}
"#;

    const ENV_DAA_CREATE_OUTPUT_PROGRAM: &str = r#"
module test

resource Clock {
    now: u64,
    later: u64,
}

action stamp(delta: u64) -> Clock {
    let now = env::current_daa_score()
    create Clock {
        now: now,
        later: now + delta
    }
}
"#;

    const BUILTIN_WRONG_ARITY_PROGRAM: &str = r#"
module test

action now(x: u64) -> u64 {
    return env::current_daa_score(x)
}
"#;

    const NUMERIC_BUILTIN_TYPE_MISMATCH_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    return min(1, false)
}
"#;

    const UNKNOWN_NAMESPACED_CONSTRUCTOR_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let value = Missing::new()
    return 0
}
"#;

    const METHOD_WRONG_ARITY_PROGRAM: &str = r#"
module test

action count(items: [u64; 3]) -> u64 {
    return items.len(1)
}
"#;

    const LOCK_CALLS_FN_PROGRAM: &str = r#"
module test

fn yes() -> bool {
    return true
}

lock guard() -> bool {
    return yes()
}
"#;

    const FN_CALLS_LOCK_PROGRAM: &str = r#"
module test

lock guard() -> bool {
    return true
}

fn bad() -> bool {
    return guard()
}
"#;

    const INDIRECT_UNDERDECLARED_EFFECT_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue(amount: u64) -> Token {
    let out = create Token {
        amount: amount
    }
    return out
}

#[effect(ReadOnly)]
action wrapper(amount: u64) -> Token {
    return issue(amount)
}
"#;

    const QUALIFIED_UNDERDECLARED_EFFECT_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action issue(amount: u64) -> Token {
    let out = create Token {
        amount: amount
    }
    return out
}

#[effect(ReadOnly)]
action wrapper(amount: u64) -> Token {
    return test::issue(amount)
}
"#;

    const CONSUME_FIELD_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action inspect(token: Token) -> u64 {
    let amount = token.amount
    consume token
    return amount
}
"#;

    const CONSUME_CREATE_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action pass(token: Token) -> Token {
    let amount = token.amount
    consume token
    let out = create Token {
        amount: amount
    }
    return out
}
"#;

    const CONSUME_CREATE_MERGE_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action merge(left: Token, right: Token) -> Token {
    let left_amount = left.amount
    let right_amount = right.amount
    let total = left_amount + right_amount
    consume left
    consume right
    let out = create Token {
        amount: total
    }
    return out
}
"#;

    const CONSUME_CREATE_SPLIT_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action split(token: Token, fee: u64) -> (Token, Token) {
    let amount = token.amount
    let remaining = amount - fee
    consume token
    let change = create Token {
        amount: remaining
    }
    let paid_fee = create Token {
        amount: fee
    }
    return (change, paid_fee)
}
"#;

    const CONSUME_CREATE_DUPLICATE_SPLIT_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action split(token: Token, fee: u64) -> (Token, Token, Token) {
    let amount = token.amount
    let remaining = amount - fee
    consume token
    let change = create Token {
        amount: remaining
    }
    let paid_fee = create Token {
        amount: fee
    }
    let extra_fee = create Token {
        amount: fee
    }
    return (change, paid_fee, extra_fee)
}
"#;

    const CONSUME_CREATE_DUPLICATE_MERGE_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action merge(left: Token, right: Token) -> Token {
    let left_amount = left.amount
    let total = left_amount + left_amount
    consume left
    consume right
    let out = create Token {
        amount: total
    }
    return out
}
"#;

    const CONSUME_CREATE_MISSING_INPUT_MERGE_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action merge(left: Token, right: Token) -> Token {
    let total = left.amount
    consume left
    consume right
    let out = create Token {
        amount: total
    }
    return out
}
"#;

    const CONSUME_CREATE_EXTRA_FIELD_MERGE_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
    owner: Address,
}

action merge(left: Token, right: Token) -> Token {
    let left_amount = left.amount
    let right_amount = right.amount
    let total = left_amount + right_amount
    let owner = left.owner
    consume left
    consume right
    let out = create Token {
        amount: total,
        owner: owner
    }
    return out
}
"#;

    const CONSUME_CREATE_IDENTITY_FIELD_MERGE_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
    symbol: [u8; 8],
}

action merge(left: Token, right: Token) -> Token {
    assert_invariant(left.symbol == right.symbol, "symbol mismatch")
    let left_amount = left.amount
    let right_amount = right.amount
    let total = left_amount + right_amount
    let symbol = left.symbol
    consume left
    consume right
    let out = create Token {
        amount: total,
        symbol: symbol
    }
    return out
}
"#;

    const CONSUME_CREATE_ARITHMETIC_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action withdraw(token: Token, fee: u64) -> Token {
    let amount = token.amount
    let remaining = amount - fee
    consume token
    let out = create Token {
        amount: remaining
    }
    return out
}
"#;

    const CONSUME_CREATE_CHAINED_ARITHMETIC_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action withdraw(token: Token, fee: u64, tax: u64) -> Token {
    let amount = token.amount
    let after_fee = amount - fee
    let remaining = after_fee - tax
    consume token
    let out = create Token {
        amount: remaining
    }
    return out
}
"#;

    const CONSUME_CREATE_LOCAL_CONST_CONSERVATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action withdraw(token: Token) -> Token {
    let amount = token.amount
    let fee = 2
    let remaining = amount - fee
    consume token
    let out = create Token {
        amount: remaining
    }
    return out
}
"#;

    const DUPLICATE_READ_REF_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

action inspect() -> u64 {
    let left = read_ref<Config>()
    let right = read_ref<Config>()
    return left.threshold + right.threshold
}
"#;

    const INDEXED_TUPLE_PROGRAM: &str = r#"
module test

action second(entries: [(Address, u64); 2]) -> u64 {
    return entries[0].1
}
"#;

    const FOREACH_ARRAY_PROGRAM: &str = r#"
module test

action sum(items: [u64; 3]) -> u64 {
    let mut total: u64 = 0
    for item in items {
        total += item
    }
    return total
}
"#;

    const LOCAL_FOREACH_ARRAY_PROGRAM: &str = r#"
module test

action sum() -> u64 {
    let items = [1, 2, 3]
    let mut total: u64 = 0
    for item in items {
        total += item
    }
    return total
}
"#;

    const LOCAL_FOREACH_ARRAY_OF_TUPLES_PROGRAM: &str = r#"
module test

action sum() -> u64 {
    let entries = [(Address::zero, 2), (Address::zero, 5)]
    let mut total: u64 = 0
    for (_, amount) in entries {
        total += amount
    }
    return total
}
"#;

    const LEN_METHOD_PROGRAM: &str = r#"
module test

action count(items: [u64; 3]) -> u64 {
    return items.len()
}
"#;

    const FORBIDDEN_UNWRAP_CALL_PROGRAM: &str = r#"
module test

action bad(value: u64) -> u64 {
    return unwrap(value)
}
"#;

    const FORBIDDEN_EXPECT_METHOD_PROGRAM: &str = r#"
module test

action bad(value: u64) -> u64 {
    return value.expect("checked")
}
"#;

    const FORBIDDEN_NAMESPACED_UNWRAP_OR_PROGRAM: &str = r#"
module test

action bad(value: u64) -> u64 {
    return Option::unwrap_or(value, 0)
}
"#;

    const LOCAL_ARRAY_LEN_PROGRAM: &str = r#"
module test

action count() -> u64 {
    let items = [1, 2, 3]
    return items.len()
}
"#;

    const TYPED_EMPTY_ARRAY_PROGRAM: &str = r#"
module test

action count() -> u64 {
    let items: [u8; 0] = []
    return items.len()
}
"#;

    const UNTYPED_EMPTY_ARRAY_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let items = []
    return 0
}
"#;

    const WRONG_LENGTH_EMPTY_ARRAY_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let items: [u8; 1] = []
    return 0
}
"#;

    const LOCAL_ARRAY_STATIC_INDEX_PROGRAM: &str = r#"
module test

action tweak() -> u64 {
    let mut items = [1, 2, 3]
    items[1] += 5
    items[0] = 7
    return items[0] + items[1] + items[2]
}
"#;

    const IMMUTABLE_ARRAY_ASSIGN_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let items = [1, 2]
    items[0] = 3
    return items[0]
}
"#;

    const HETEROGENEOUS_ARRAY_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let items = [1, false]
    return 1
}
"#;

    const LOCAL_ARRAY_OOB_READ_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let items = [1, 2]
    return items[2]
}
"#;

    const LOCAL_ARRAY_OOB_WRITE_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let mut items = [1, 2]
    items[2] = 3
    return items[0]
}
"#;

    const LOCAL_TUPLE_STATIC_FIELD_PROGRAM: &str = r#"
module test

action tweak() -> u64 {
    let mut pair = (1, 2)
    pair.1 += 5
    pair.0 = 7
    return pair.0 + pair.1
}
"#;

    const ARRAY_OF_TUPLES_STATIC_INDEX_PROGRAM: &str = r#"
module test

action pick() -> u64 {
    let entries = [(Address::zero, 2), (Address::zero, 5)]
    return entries[1].1
}
"#;

    const IMMUTABLE_TUPLE_ASSIGN_PROGRAM: &str = r#"
module test

action bad() -> u64 {
    let pair = (1, 2)
    pair.1 = 3
    return pair.1
}
"#;

    const LOCAL_TUPLE_DESTRUCTURE_PROGRAM: &str = r#"
module test

action split() -> u64 {
    let pair = (1, 2)
    let (a, b) = pair
    return a + b
}
"#;

    const MATCH_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

action select(flag: Flag) -> u64 {
    return match flag {
        Flag::On => 1,
        _ => 2,
    }
}
"#;

    const EXHAUSTIVE_MATCH_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

action select(flag: Flag) -> u64 {
    return match flag {
        Flag::On => 1,
        Flag::Off => 2,
    }
}
"#;

    const LINEAR_MATCH_EXPR_LET_MOVE_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

resource Token {
    amount: u64,
}

action choose(token: Token, flag: Flag) -> Token {
    let moved = match flag {
        Flag::On => token,
        Flag::Off => token,
    }
    return moved
}
"#;

    const LINEAR_MATCH_EXPR_INCONSISTENT_LET_MOVE_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

resource Token {
    amount: u64,
}

action bad(left: Token, right: Token, flag: Flag) -> Token {
    let moved = match flag {
        Flag::On => left,
        Flag::Off => right,
    }
    return moved
}
"#;

    const LINEAR_MATCH_EXPR_STATEFUL_ARMS_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

resource Token has destroy {
    amount: u64,
}

action burn(token: Token, flag: Flag) {
    match flag {
        Flag::On => destroy token,
        Flag::Off => destroy token,
    }
}
"#;

    const LINEAR_MATCH_EXPR_INCONSISTENT_STATEFUL_ARMS_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

resource Token has destroy {
    amount: u64,
}

action bad(token: Token, flag: Flag) {
    match flag {
        Flag::On => destroy token,
        Flag::Off => 0,
    }
}
"#;

    const UNKNOWN_MATCH_VARIANT_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

action select(flag: Flag) -> u64 {
    return match flag {
        Flag::Maybe => 1,
        _ => 2,
    }
}
"#;

    const DUPLICATE_MATCH_VARIANT_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

action select(flag: Flag) -> u64 {
    return match flag {
        Flag::On => 1,
        On => 2,
        _ => 3,
    }
}
"#;

    const NON_EXHAUSTIVE_MATCH_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

action select(flag: Flag) -> u64 {
    return match flag {
        Flag::On => 1,
    }
}
"#;

    const ENUM_PAYLOAD_VARIANT_PROGRAM: &str = r#"
module test

enum MaybeAmount {
    Some(u64),
    None,
}

action select(value: MaybeAmount) -> u64 {
    return match value {
        MaybeAmount::Some => 1,
        _ => 0,
    }
}
"#;

    const ENUM_PAYLOAD_VALUE_PROGRAM: &str = r#"
module test

enum AssetType {
    Native,
    Token(Hash),
}

action bad() -> AssetType {
    return AssetType::Token
}
"#;

    const UNKNOWN_ENUM_VALUE_PROGRAM: &str = r#"
module test

enum Flag {
    On,
    Off,
}

action bad() -> Flag {
    return Flag::Maybe
}
"#;

    const UNKNOWN_NAMED_TYPE_PROGRAM: &str = r#"
module test

resource Bad {
    missing: MissingType,
}

action run(value: Bad) -> u64 {
    destroy value
    return 0
}
"#;

    const RESERVED_OPTION_TYPE_PROGRAM: &str = r#"
module test

action bad(value: Option<u64>) -> u64 {
    return 0
}
"#;

    const USER_GENERIC_TYPE_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
}

resource Vault has store {
    amount: u64,
}

action bad(input: Vault<Token>) -> u64 {
    return 0
}
"#;

    const DUPLICATE_TOP_LEVEL_SYMBOL_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

action Token() -> u64 {
    return 0
}
"#;

    const VEC_BUILTIN_PROGRAM: &str = r#"
module test

action pack(bytes: [u8; 3]) -> u64 {
    let mut data = Vec::new()
    data.push(1)
    data.extend_from_slice(bytes)
    return data.len()
}
"#;

    const FIXED_WIDTH_VEC_CREATE_PROGRAM: &str = r#"
module test

resource Group {
    members: Vec<Address>,
    anchors: Vec<Hash>,
}

action create_group(owner: Address, seed: Hash) -> Group {
    let mut members = Vec::new()
    members.push(owner)
    let mut anchors = Vec::new()
    anchors.push(seed)
    return create Group {
        members: members,
        anchors: anchors,
    }
}
"#;

    const STACK_VEC_RUNTIME_PROGRAM: &str = r#"
module test

action stack_vec_sum() -> u64 {
    let mut values = Vec::new()
    values.push(7)
    values.push(9)
    return values.len() + values[1]
}
"#;

    const FIXED_BYTE_STACK_VEC_RUNTIME_PROGRAM: &str = r#"
module test

action stack_vec_address_roundtrip(owner: Address) -> bool {
    let mut owners = Vec::new()
    owners.push(owner)
    return owners[0] == owner
}
"#;

    const STACK_VEC_EXTEND_RUNTIME_PROGRAM: &str = r#"
module test

action stack_vec_extend_len(seed: [u8; 3]) -> u64 {
    let mut bytes = Vec::new()
    bytes.extend_from_slice(seed)
    return bytes.len()
}
"#;

    const STACK_VEC_CLEAR_IS_EMPTY_PROGRAM: &str = r#"
module test

action stack_vec_clear_len() -> u64 {
    let mut values = Vec::new()
    values.push(7)
    values.clear()
    if values.is_empty() {
        return values.len()
    }
    return 99
}
"#;

    const CELL_BACKED_VEC_PROGRAM: &str = r#"
module test

resource NFT {
    token_id: u64,
    owner: Address,
}

action batch_mint(owner: Address) -> Vec<NFT> {
    let mut nfts = Vec::new()
    let nft = create NFT {
        token_id: 1,
        owner: owner,
    }
    nfts.push(nft)
    return nfts
}
"#;

    const TYPE_HASH_PROGRAM: &str = r#"
module test

struct Pool {
    amount: u64,
}

action pool_id(pool: Pool) -> Hash {
    return pool.type_hash()
}
"#;

    const ZERO_PROGRAM: &str = r#"
module test

action is_zero(target: Address) -> bool {
    return target == Address::zero()
}
"#;

    const SUMMARY_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

resource Token has store, transfer, destroy {
    amount: u64,
}

action update(amount: u64) -> u64 {
    let cfg = read_ref<Config>()
    let token = create Token { amount: amount }
    consume token
    return cfg.threshold
}
"#;

    const BAD_LOCK_PROGRAM: &str = r#"
module test

lock invalid(owner: Address) -> u64 {
    return 1
}
"#;

    const LOCK_CREATE_PROGRAM: &str = r#"
module test

resource Token {
    amount: u64,
}

lock bad() -> bool {
    let token = create Token { amount: 1 }
    return true
}
"#;

    const LOCK_DESTROY_PROGRAM: &str = r#"
module test

lock bad() -> bool {
    destroy token
    return true
}
"#;

    const LOCK_READ_REF_PROGRAM: &str = r#"
module test

shared Config {
    threshold: u64,
}

lock guard() -> bool {
    let cfg = read_ref<Config>()
    return cfg.threshold > 0
}
"#;

    const TRANSFER_CLAIM_SETTLE_PROGRAM: &str = r#"
module test

resource Token has store, transfer, destroy {
    amount: u64,
}

receipt VestingReceipt -> Token {
    amount: u64,
}

action move_token(token: Token, to: Address) -> Token {
    return transfer token to to
}

action redeem(receipt: VestingReceipt) -> Token {
    return claim receipt
}

    action finalize(token: Token) -> Token {
        return settle token
    }
"#;

    const CLAIM_SETTLE_UNSUPPORTED_OUTPUT_RELATION_PROGRAM: &str = r#"
module test

resource Token {
    amount: u128,
}

receipt VestingReceipt -> Token {
    amount: u128,
}

action redeem(receipt: VestingReceipt) -> Token {
    return claim receipt
}

action finalize(token: Token) -> Token {
    return settle token
}
"#;

    const SETTLE_LIFECYCLE_FINAL_STATE_PROGRAM: &str = r#"
module test

#[lifecycle(Pending -> Settled)]
receipt Settlement has store {
    state: u8,
    amount: u64,
}

action finalize(settlement: Settlement) -> Settlement {
    return settle settlement
}
"#;

    const CLAIM_SIGNER_PUBKEY_HASH_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
    signer_pubkey_hash: [u8; 20],
}

receipt SignedReceipt -> Token {
    amount: u64,
    signer_pubkey_hash: [u8; 20],
}

action redeem_signed(receipt: SignedReceipt) -> Token {
    return claim receipt
}
"#;

    const CLAIM_SIGNER_WITH_TIME_PREDICATE_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
    signer_pubkey_hash: [u8; 20],
}

receipt SignedVestingReceipt -> Token {
    amount: u64,
    signer_pubkey_hash: [u8; 20],
    cliff_daa: u64,
}

action redeem_signed_after_cliff(receipt: SignedVestingReceipt) -> Token {
    let now = env::current_daa_score()
    assert_invariant(now >= receipt.cliff_daa, "cliff not reached")
    return claim receipt
}
"#;

    const TRANSFER_CLAIM_SETTLE_NON_SCALAR_FIELD_PROGRAM: &str = r#"
module test

resource Token has store, transfer, destroy {
    amount: u64,
    owner: Address,
}

receipt VestingReceipt -> Token {
    amount: u64,
    owner: Address,
}

action move_token(token: Token, to: Address) -> Token {
    return transfer token to to
}

action redeem(receipt: VestingReceipt) -> Token {
    return claim receipt
}

action finalize(token: Token) -> Token {
    return settle token
}
"#;

    const FIXED_BYTE_PARAM_AND_CONST_OUTPUT_PROGRAM: &str = r#"
module test

resource Config has store {
    symbol: [u8; 8],
}

resource Fingerprint has store {
    digest: Hash,
}

action make_config(symbol: [u8; 8]) -> Config {
    create Config {
        symbol: symbol
    }
}

action make_fingerprint() -> Fingerprint {
    create Fingerprint {
        digest: Hash::zero()
    }
}
"#;

    const CONST_LOCK_OUTPUT_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
}

action mint() -> Token {
    create Token {
        amount: 42
    } with_lock(Address::zero())
}
"#;

    const MISSING_TRANSFER_CAPABILITY_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
}

action move_token(token: Token, to: Address) -> Token {
    return transfer token to to
}
"#;

    const MISSING_DESTROY_CAPABILITY_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
}

action burn(token: Token) {
    destroy token
}
"#;

    const CLAIM_NON_RECEIPT_PROGRAM: &str = r#"
module test

resource Token has store {
    amount: u64,
}

action redeem(token: Token) -> u64 {
    return claim token
}
"#;

    const CLAIM_OUTPUT_NON_CELL_PROGRAM: &str = r#"
module test

receipt VestingReceipt -> u64 {
    amount: u64,
}

action redeem(receipt: VestingReceipt) -> u64 {
    return claim receipt
}
"#;

    const CLAIM_OUTPUT_RECEIPT_PROGRAM: &str = r#"
module test

receipt OtherReceipt {
    amount: u64,
}

receipt VestingReceipt -> OtherReceipt {
    amount: u64,
}

action redeem(receipt: VestingReceipt) -> OtherReceipt {
    return claim receipt
}
"#;

    const SETTLE_NON_CELL_PROGRAM: &str = r#"
module test

struct Snapshot {
    amount: u64,
}

action finalize(snapshot: Snapshot) -> Snapshot {
    return settle snapshot
}
"#;

    const LIFECYCLE_DUPLICATE_STATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Created)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action noop() -> u64 {
    return 0
}
"#;

    const LIFECYCLE_MISSING_STATE_CREATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action make() -> Ticket {
    return create Ticket {
        id: 1,
    }
}
"#;

    const LIFECYCLE_BAD_STATE_TYPE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: bool,
    id: u64,
}

action noop() -> u64 {
    return 0
}
"#;

    const LIFECYCLE_OUT_OF_RANGE_STATE_CREATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action make() -> Ticket {
    return create Ticket {
        state: 2,
        id: 1,
    }
}
"#;

    const LIFECYCLE_NON_INITIAL_CREATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action make() -> Ticket {
    return create Ticket {
        state: 1,
        id: 1,
    }
}
"#;

    const LIFECYCLE_DYNAMIC_INITIAL_CREATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action make(state: u8) -> Ticket {
    return create Ticket {
        state: state,
        id: 1,
    }
}
"#;

    const LIFECYCLE_RESET_UPDATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action reset(ticket: Ticket) -> Ticket {
    consume ticket
    return create Ticket {
        state: 0,
        id: ticket.id,
    }
}
"#;

    const LIFECYCLE_STATIC_UPDATE_PROGRAM: &str = r#"
module test

#[lifecycle(Created -> Active)]
receipt Ticket has store {
    state: u8,
    id: u64,
}

action activate(ticket: Ticket) -> Ticket {
    let active: u8 = 1
    consume ticket
    return create Ticket {
        state: active,
        id: ticket.id,
    }
}
"#;

    #[test]
    fn compile_produces_non_empty_riscv_assembly() {
        let result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());

        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        assert!(asm.contains(".section .text"));
        assert!(asm.contains(".global add"));
    }

    #[test]
    fn compile_spills_parameters_and_returns_computed_value() {
        let result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("sd a0, 0(sp)"), "missing parameter spill for x:\n{}", asm);
        assert!(asm.contains("sd a1, 8(sp)"), "missing parameter spill for y:\n{}", asm);
        assert!(asm.contains("add t0, t0, t1"), "missing add instruction:\n{}", asm);
        assert!(asm.contains("ld a0, 16(sp)"), "missing return load for z:\n{}", asm);
    }

    #[test]
    fn compile_lowers_if_statement_into_basic_blocks() {
        let result = compile(IF_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("beqz t0, .Lincrement_if_block_2"), "missing conditional branch to else block:\n{}", asm);
        assert!(asm.contains(".Lincrement_if_block_1:"), "missing then block label:\n{}", asm);
        assert!(asm.contains(".Lincrement_if_block_2:"), "missing else block label:\n{}", asm);
        assert!(asm.contains(".Lincrement_if_block_3:"), "missing join block label:\n{}", asm);
        assert!(!asm.contains(".Lelse:"), "stale hard-coded else label leaked into assembly:\n{}", asm);
    }

    #[test]
    fn compile_emits_direct_user_function_calls() {
        let result = compile(CALL_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains(".global double"), "missing callee symbol:\n{}", asm);
        assert!(asm.contains(".global run"), "missing caller symbol:\n{}", asm);
        assert!(asm.contains("call double"), "missing direct call instruction:\n{}", asm);
        assert!(asm.contains("sd a0, 8(sp)"), "missing call result spill:\n{}", asm);
    }

    #[test]
    fn compile_lowers_if_expression_with_join_move() {
        let result = compile(IF_EXPR_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("beqz t0, .Lchoose_block_2"), "missing conditional branch for if expression:\n{}", asm);
        assert!(asm.contains(".Lchoose_block_3:"), "missing join block for if expression:\n{}", asm);
        assert!(asm.contains("sd t0, 24(sp)") || asm.contains("sd t0, 32(sp)"), "missing branch value move into join slot:\n{}", asm);
    }

    #[test]
    fn compile_lowers_while_statement_into_loop_cfg() {
        let result = compile(WHILE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains(".Lspin_block_1:"), "missing while condition block:\n{}", asm);
        assert!(asm.contains(".Lspin_block_2:"), "missing while body block:\n{}", asm);
        assert!(asm.contains(".Lspin_block_3:"), "missing while exit block:\n{}", asm);
        assert!(asm.contains("beqz t0, .Lspin_block_3"), "missing while false-branch jump:\n{}", asm);
        assert!(asm.contains("j .Lspin_block_1"), "missing while back edge:\n{}", asm);
    }

    #[test]
    fn compile_lowers_for_range_into_counted_loop_cfg() {
        let result = compile(FOR_RANGE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains(".Lvisit_block_1:"), "missing for-loop condition block:\n{}", asm);
        assert!(asm.contains(".Lvisit_block_2:"), "missing for-loop body block:\n{}", asm);
        assert!(asm.contains(".Lvisit_block_3:"), "missing for-loop exit block:\n{}", asm);
        assert!(asm.contains("slt t0, t0, t1"), "missing range bound comparison:\n{}", asm);
        assert!(asm.contains("li t1, 1"), "missing range increment constant:\n{}", asm);
        assert!(asm.contains("j .Lvisit_block_1"), "missing for-loop back edge:\n{}", asm);
    }

    #[test]
    fn compile_lowers_mutable_assignments_in_loop_bodies() {
        let result = compile(ASSIGN_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("sub t0, t0, t1"), "missing subtraction for x = x - 1:\n{}", asm);
        assert!(asm.contains("add t0, t0, t1"), "missing addition for x += 1:\n{}", asm);
        assert!(asm.contains("sd t0, 8(sp)"), "missing assignment write-back into x slot:\n{}", asm);
    }

    #[test]
    fn compile_rejects_linear_state_changes_hidden_inside_loops() {
        compile(LOOP_LOCAL_LINEAR_COMPLETE_PROGRAM, CompileOptions::default()).unwrap();

        let dropped = compile(LOOP_DROPPED_LOCAL_LINEAR_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(dropped.message.contains("linear resource 'out' was not consumed"), "unexpected error: {}", dropped.message);

        let for_err = compile(FOR_LOOP_PARENT_LINEAR_CHANGE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            for_err.message.contains("linear resource 'token' cannot change ownership state inside a loop body"),
            "unexpected error: {}",
            for_err.message
        );

        let while_err = compile(WHILE_LOOP_PARENT_LINEAR_CHANGE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            while_err.message.contains("linear resource 'token' cannot change ownership state inside a loop body"),
            "unexpected error: {}",
            while_err.message
        );
    }

    #[test]
    fn compile_lowers_local_struct_field_reads_and_writes() {
        let result = compile(STRUCT_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains(".global tweak"), "missing tweak symbol:\n{}", asm);
        assert!(asm.contains("li t0, 1"), "missing initial x field constant:\n{}", asm);
        assert!(asm.contains("li t0, 2"), "missing initial y field constant:\n{}", asm);
        assert!(asm.contains("sd t0, 8(sp)"), "missing field x storage slot writes:\n{}", asm);
        assert!(!asm.contains("# field access .x"), "local struct field access fell back to symbolic field path:\n{}", asm);
    }

    #[test]
    fn compile_rejects_assignment_to_temporary_field_targets() {
        let err = compile(TEMPORARY_FIELD_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("assignment target must be rooted at a named local or parameter"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(READ_REF_FIELD_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("assignment target must be rooted at a named local or parameter"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_assignment_through_read_only_references() {
        let err = compile(READ_REF_BINDING_FIELD_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("assignment target rooted at 'cfg' is a read-only reference"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(READ_ONLY_REF_FIELD_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("assignment target rooted at 'view' is a read-only reference"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_unsound_mutable_parameter_forms() {
        let err = compile(MUT_CELL_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("cell-backed parameter 'token' cannot use leading 'mut'"), "unexpected error: {}", err.message);

        let err = compile(MUT_READ_REF_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("parameter 'cfg' is a read-only reference"), "unexpected error: {}", err.message);

        let err = compile(REDUNDANT_MUT_REF_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("parameter 'pool' is already an '&mut' reference"), "unexpected error: {}", err.message);

        let err = compile(FUNCTION_MUT_REF_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bad' parameter 'pool' cannot use mutable reference type &mut Pool"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LOCK_MUT_REF_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("lock 'bad' parameter 'pool' cannot use mutable reference type &mut Pool"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_local_mutable_reference_aliases() {
        let err = compile(MUT_REF_LOCAL_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store mutable reference type &mut Pool"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(MUT_REF_TUPLE_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store mutable reference type (&mut Pool, u64)"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(MUT_REF_IF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store mutable reference type &mut Pool"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(MUT_REF_ASSIGN_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("assignment cannot store mutable reference type &mut Pool"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_duplicate_mutable_reference_call_roots() {
        let err = compile(MUT_REF_DUPLICATE_CALL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bump_pair' cannot receive mutable reference root 'pool' more than once"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(MUT_REF_BLOCK_DUPLICATE_CALL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bump_pair' cannot receive mutable reference root 'pool' more than once"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(MUT_REF_IF_DUPLICATE_CALL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bump_pair' cannot receive mutable reference root 'pool' more than once"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(MUT_REF_MIXED_DUPLICATE_CALL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bump_with_view' cannot receive mutable reference root 'pool' more than once"),
            "unexpected error: {}",
            err.message
        );

        compile(MUT_REF_DUPLICATE_READ_ONLY_CALL_PROGRAM, CompileOptions::default()).unwrap();
    }

    #[test]
    fn compile_rejects_owned_linear_field_assignment() {
        let err = compile(OWNED_LINEAR_FIELD_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("assignment target rooted at linear/resource value 'token' is not supported"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_local_references_to_linear_roots() {
        let err = compile(LINEAR_LOCAL_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_FIELD_LOCAL_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_TUPLE_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_ARRAY_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_IF_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_ASSIGN_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_ASSIGN_TUPLE_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(LINEAR_ASSIGN_TUPLE_FIELD_REF_ALIAS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("local binding cannot store a read-only reference rooted at linear/resource value 'token'"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_reference_escape_boundaries() {
        let err = compile(ACTION_RETURN_REF_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("action 'leak' cannot return reference type &Token"), "unexpected error: {}", err.message);

        let err = compile(FUNCTION_RETURN_REF_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("function 'leak' cannot return reference type &Point"), "unexpected error: {}", err.message);

        let err = compile(FUNCTION_CELL_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bad' parameter 'token' cannot use owned cell-backed type Token"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(FUNCTION_CELL_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("function 'bad' cannot return cell-backed type Token"), "unexpected error: {}", err.message);

        let err = compile(LOCK_CELL_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("lock 'bad' parameter 'token' cannot use owned cell-backed type Token"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(CALLABLE_REFERENCE_TO_CELL_AGGREGATE_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains(
                "parameter 'pair' in function 'bad' cannot use reference to aggregate containing cell-backed values &(Token, u64)"
            ),
            "unexpected error: {}",
            err.message
        );

        let err = compile(CALLABLE_MUT_REFERENCE_TO_CELL_AGGREGATE_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains(
                "parameter 'pool' in action 'bad' cannot use reference to aggregate containing cell-backed values &mut (Pool, u64)"
            ),
            "unexpected error: {}",
            err.message
        );

        let err = compile(FUNCTION_VEC_CELL_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("function 'bad' parameter 'tokens' cannot use owned cell-backed type Vec<Token>"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(STRUCT_VEC_REFERENCE_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("cannot contain reference type"), "unexpected error: {}", err.message);

        let err = compile(VEC_PUSH_REFERENCE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("Vec.push cannot store reference type &Point"), "unexpected error: {}", err.message);

        let err = compile(CALLABLE_TUPLE_REFERENCE_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("parameter 'pair' in function 'bad' cannot contain nested reference type (&Point, u64)"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(CALLABLE_ARRAY_MUT_REFERENCE_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("parameter 'pools' in action 'bad' cannot contain nested reference type [&mut Pool; 1]"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(CALLABLE_NESTED_REFERENCE_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("parameter 'view' in function 'bad' cannot contain nested reference type &&Point"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(ACTION_REF_PARAM_MODIFIER_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("parameter modifier 'ref' is reserved but unsupported"), "unexpected error: {}", err.message);

        let err = compile(FUNCTION_REF_PARAM_MODIFIER_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("parameter modifier 'ref' is reserved but unsupported"), "unexpected error: {}", err.message);

        let err = compile(LOCK_REF_PARAM_MODIFIER_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("parameter modifier 'ref' is reserved but unsupported"), "unexpected error: {}", err.message);

        let err = compile(SCHEMA_REFERENCE_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("struct 'Holder' field 'view' cannot use reference type &Token"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(ENUM_REFERENCE_PAYLOAD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("enum variant 'MaybeToken::Some' payload cannot use reference type &Token"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_if_expression_branch_type_mismatch() {
        let err = compile(IF_MISMATCH_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("if expression branches must have matching types"));
    }

    #[test]
    fn compile_rejects_unknown_struct_fields() {
        let err = compile(UNKNOWN_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("unknown field 'y'"));
        assert!(err.message.contains("Point"));
    }

    #[test]
    fn compile_rejects_unstable_schema_field_names() {
        let err = compile(DUPLICATE_RESOURCE_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate field 'amount' in resource 'Token'"), "unexpected error: {}", err.message);

        let err = compile(DUPLICATE_SHARED_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate field 'reserve' in shared 'Pool'"), "unexpected error: {}", err.message);

        let err = compile(DUPLICATE_RECEIPT_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate field 'amount' in receipt 'Grant'"), "unexpected error: {}", err.message);

        let err = compile(WILDCARD_STRUCT_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("struct 'Point' field must have a stable name"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_unknown_functions() {
        let err = compile(UNKNOWN_FUNCTION_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("unknown function 'missing'"));
    }

    #[test]
    fn compile_lowers_local_constants_into_real_operands() {
        let result = compile(CONSTANT_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("li t1, 3") || asm.contains("li t0, 3"), "missing literal load for local constant:\n{}", asm);
        assert!(asm.contains("add t0, t0, t1"), "missing arithmetic using lowered constant:\n{}", asm);
    }

    #[test]
    fn compile_lowers_numeric_cast_without_zero_fallback() {
        let result = compile(CAST_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("li t0, 0"), "cast lowering regressed to zero fallback:\n{}", asm);
        assert!(asm.contains(".global widen"), "missing widened function symbol:\n{}", asm);
    }

    #[test]
    fn compile_lowers_assert_invariant_into_fail_closed_cfg() {
        let result = compile(ASSERT_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("beqz t0"), "assert condition did not branch on failure:\n{}", asm);
        assert!(asm.contains("li a0, 7"), "assert failure path did not return a non-zero failure code:\n{}", asm);
        assert!(!asm.contains("assert_invariant"), "assert was not lowered out of source form:\n{}", asm);
    }

    #[test]
    fn compile_rejects_non_bool_assert_condition() {
        let err = compile(ASSERT_NON_BOOL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("assert condition must be boolean"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_dynamic_assert_invariant_messages() {
        let err = compile(ASSERT_DYNAMIC_MESSAGE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("assert message must be a string literal"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_binding_assert_invariant_results() {
        let err = compile(ASSERT_BINDING_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("cannot bind the result of a function without a return value"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_assert_invariant_as_tail_return_value() {
        let err = compile(ASSERT_TAIL_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("tail expression type mismatch"), "unexpected error: {}", err.message);
        assert!(err.message.contains("Unit"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_string_literals_as_runtime_values() {
        let err = compile(STRING_VALUE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("string literals are only supported in metadata positions"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_preserves_create_instructions_in_assembly() {
        let result = compile(CREATE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# create Token"), "create expression vanished from assembly:\n{}", asm);
        assert!(asm.contains("#   field amount = 42"), "create fields were not preserved in assembly comments:\n{}", asm);
        assert!(asm.contains("#   with_lock <expr>"), "create lock binding vanished from assembly:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "locked create verifier should verify covered fields before checking lock binding:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: output field verification incomplete for this create pattern"),
            "locked create with coverable fields should not conflate lock verification with field verification:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: fixed-byte param owner pointer=a0 length=a1 size=32"),
            "Address lock parameter should use pointer+length ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=output_lock_hash source=Output index=0 field=3"),
            "Address lock parameter should be checked with output LockHash syscall:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output bytes field output lock hash offset=0 size=32 against pointer var"),
            "Address lock parameter should be compared through the fixed-byte pointer source:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: output lock verification incomplete for this create pattern"),
            "Address lock parameter should no longer fail closed as incomplete:\n{}",
            asm
        );
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "coverable locked create fields should not be reflected as incomplete output fields: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-lock-verification-incomplete".to_string()),
            "coverable Address lock parameter should not be reflected as incomplete output lock verification: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        let action = result.metadata.actions.iter().find(|action| action.name == "mint").expect("mint metadata");
        assert!(action.params[0].fixed_byte_pointer_abi);
        assert!(action.params[0].fixed_byte_length_abi);
        assert_eq!(action.params[0].fixed_byte_len, Some(32));
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "create-output:Token:create_Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("create-output-fields=checked-runtime")
                && obligation.detail.contains("create-output-lock=checked-runtime")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:Token:create_Token"
                && requirement.component == "create-output-fields"
                && requirement.status == "checked-runtime"
                && requirement.binding == "create_Token"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("fields")
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:Token:create_Token"
                && requirement.component == "create-output-lock"
                && requirement.status == "checked-runtime"
                && requirement.binding == "create_Token"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("lock_hash")
                && requirement.abi == "create-output-lock-hash-32"
                && requirement.byte_len == Some(32)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
    }

    #[test]
    fn compile_emits_create_output_field_verification_for_fixed_u64_fields() {
        let result = compile(CREATE_VERIFY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=create source=Output index=0"),
            "create output was not loaded from CKB Output source:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: bounds check Token.amount required=8"),
            "create output verification missed field bounds check:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "create output field verification was not emitted:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: output field verification incomplete for this create pattern"),
            "fully verified create output was incorrectly marked incomplete:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check Token expected=8"),
            "create output verification did not enforce exact fixed schema size:\n{}",
            asm
        );
        assert!(asm.contains("li t1, 42"), "create output verification did not load expected constant:\n{}", asm);
        assert!(asm.contains("sub t2, t0, t1"), "create output verification did not compare actual and expected values:\n{}", asm);
        let action = result.metadata.actions.iter().find(|action| action.name == "issue").expect("issue metadata");
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "create-output:Token:create_Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("create-output-fields=checked-runtime")
                && obligation.detail.contains("create-output-lock=not-required")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:Token:create_Token"
                && requirement.component == "create-output-fields"
                && requirement.status == "checked-runtime"
                && requirement.binding == "create_Token"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("fields")
                && requirement.abi == "create-output-field-verifier"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(
            !action
                .transaction_runtime_input_requirements
                .iter()
                .any(|requirement| requirement.feature == "create-output:Token:create_Token"
                    && requirement.component == "create-output-lock"),
            "create without with_lock should not expose a lock component: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_verifies_create_output_against_computed_scalar_stack_value() {
        let result = compile(CREATE_UNSUPPORTED_OUTPUT_EXPR_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "computed create expected expression did not emit output field verification:\n{}",
            asm
        );
        assert!(asm.contains("mul t0, t0, t1"), "computed scalar field value did not lower before create verification:\n{}", asm);
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "computed scalar create expression should not be marked as incomplete output verification: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        let action = result.metadata.actions.iter().find(|action| action.name == "issue").expect("issue action");
        assert!(
            !action.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "computed scalar create expression should not reach action fail-closed metadata: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn incomplete_create_output_verification_exposes_transaction_blocker() {
        let result = compile(CREATE_UNSUPPORTED_DYNAMIC_OUTPUT_PROGRAM, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "issue").expect("issue action");

        assert!(
            action.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "unsupported create output should still fail closed: {:?}",
            action.fail_closed_runtime_features
        );
        let obligation = action
            .verifier_obligations
            .iter()
            .find(|obligation| obligation.feature.starts_with("create-output:Fingerprint:"))
            .expect("create output verifier obligation");
        assert_eq!(obligation.category, "transaction-invariant");
        assert_eq!(obligation.status, "runtime-required");
        assert!(
            obligation.detail.contains("create-output-fields=runtime-required")
                && obligation.detail.contains("create-output-lock=not-required"),
            "create output obligation must classify field and lock coverage separately: {:?}",
            obligation
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature.starts_with("create-output:Fingerprint:")
                    && requirement.binding == "create_Fingerprint"
                    && requirement.component == "create-output-fields"
                    && requirement.status == "runtime-required"
                    && requirement.blocker_class.as_deref() == Some("create-output-verification-gap")
            }),
            "action metadata must expose create output field verifier blocker: {:?}",
            action.transaction_runtime_input_requirements
        );
        assert!(
            !action
                .transaction_runtime_input_requirements
                .iter()
                .any(|requirement| requirement.feature.starts_with("create-output:Fingerprint:")
                    && requirement.component == "create-output-lock"),
            "absence of an explicit with_lock should not expose a lock blocker: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_rejects_invalid_create_field_initializers() {
        let duplicate = compile(CREATE_DUPLICATE_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            duplicate.message.contains("duplicate field 'amount' in create for 'Token'"),
            "unexpected error: {}",
            duplicate.message
        );

        let missing = compile(CREATE_MISSING_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(missing.message.contains("create for 'Token' is missing field(s): owner"), "unexpected error: {}", missing.message);

        let unknown = compile(CREATE_UNKNOWN_FIELD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(unknown.message.contains("unknown field 'owner' in create for 'Token'"), "unexpected error: {}", unknown.message);

        let mismatch = compile(CREATE_FIELD_TYPE_MISMATCH_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            mismatch.message.contains("field 'amount' in create for 'Token' has type mismatch"),
            "unexpected error: {}",
            mismatch.message
        );

        let struct_target = compile(CREATE_STRUCT_TARGET_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            struct_target.message.contains("create target type 'Snapshot' must be a resource, shared, or receipt cell type"),
            "unexpected error: {}",
            struct_target.message
        );
    }

    #[test]
    fn compile_rejects_stateful_operations_without_named_linear_cell_operands() {
        let non_cell = compile(CONSUME_NON_CELL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(non_cell.message.contains("consume requires a cell-backed linear value"), "unexpected error: {}", non_cell.message);

        let non_named_consume = compile(CONSUME_NON_NAMED_CELL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            non_named_consume.message.contains("consume requires a named cell-backed value"),
            "unexpected error: {}",
            non_named_consume.message
        );

        let non_named_transfer = compile(TRANSFER_NON_NAMED_CELL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            non_named_transfer.message.contains("transfer requires a named cell-backed value"),
            "unexpected error: {}",
            non_named_transfer.message
        );
    }

    #[test]
    fn compile_moves_linear_values_through_let_bindings() {
        compile(LINEAR_LET_MOVE_PROGRAM, CompileOptions::default()).unwrap();

        let copied = compile(LINEAR_LET_COPY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(copied.message.contains("resource 'token' already Consumed"), "unexpected error: {}", copied.message);
    }

    #[test]
    fn compile_merges_if_branch_linear_states_conservatively() {
        compile(IF_BOTH_BRANCHES_CONSUME_PROGRAM, CompileOptions::default()).unwrap();

        let partial = compile(IF_PARTIAL_BRANCH_CONSUME_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            partial.message.contains("linear resource 'token' has inconsistent ownership state across if branches"),
            "unexpected error: {}",
            partial.message
        );

        let mismatched = compile(IF_MISMATCHED_BRANCH_CONSUME_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            mismatched.message.contains("linear resource 'token' has inconsistent ownership state across if branches"),
            "unexpected error: {}",
            mismatched.message
        );
    }

    #[test]
    fn compile_preserves_consume_and_destroy_instructions_in_assembly() {
        let result = compile(CONSUME_DESTROY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# consume"), "consume expression vanished from assembly:\n{}", asm);
        assert!(asm.contains("# destroy"), "destroy expression vanished from assembly:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: destroy output type-hash absence scan binding=b size=32"),
            "destroy did not emit an Output TypeHash absence scan:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=destroy_output_type_hash source=Output index=t6 field=5"),
            "destroy absence scan did not use Output LOAD_CELL_BY_FIELD:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=destroy source=Input index=1"),
            "destroy input data load did not use operation-specific Input LOAD_CELL ABI:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: destroy symbolic runtime is not executable"),
            "destroy should no longer use the symbolic fail-closed path:\n{}",
            asm
        );

        let action = result.metadata.actions.iter().find(|action| action.name == "burn").expect("burn metadata");
        assert_eq!(action.consume_set.len(), 2);
        assert!(action.consume_set.iter().any(|pattern| pattern.binding == "a"));
        assert!(action.consume_set.iter().any(|pattern| pattern.binding == "b" && pattern.operation == "destroy"));
        assert!(action
            .ckb_runtime_accesses
            .iter()
            .any(|access| access.source == "Input" && access.binding == "b" && access.operation == "destroy"));
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "resource-operation"
                && obligation.feature == "destroy:Token"
                && obligation.status == "checked-static"
        }));
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "consume-input:Token:a"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("consume-input-data=checked-runtime")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "consume-input:Token:a"
                && requirement.status == "checked-runtime"
                && requirement.component == "consume-input-data"
                && requirement.source == "Input"
                && requirement.binding == "a"
                && requirement.field.as_deref() == Some("data")
                && requirement.abi == "consume-load-cell-input"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "destroy-input:Token:b"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("destroy-input-data=checked-runtime")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "destroy-input:Token:b"
                && requirement.status == "checked-runtime"
                && requirement.component == "destroy-input-data"
                && requirement.source == "Input"
                && requirement.binding == "b"
                && requirement.field.as_deref() == Some("data")
                && requirement.abi == "destroy-load-cell-input"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "destroy-output-scan:Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("destroy-output-absence=checked-runtime")
                && obligation.detail.contains("destroy-output-scan=checked-runtime")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "destroy-output-scan:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "destroy-output-absence"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("type_hash-absence")
                && requirement.abi == "destroy-output-scan-type-id"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.scope == "action:burn"
                && requirement.feature == "destroy-output-scan:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "destroy-output-scan"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
    }

    #[test]
    fn compile_preserves_read_ref_instructions_in_assembly() {
        let result = compile(SUMMARY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# read_ref Config"), "read_ref expression vanished from assembly:\n{}", asm);
    }

    #[test]
    fn compile_lowers_read_ref_schema_field_to_ckb_runtime_assembly() {
        let result = compile(READ_REF_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=read_ref source=CellDep index=0"),
            "read_ref did not lower to CKB LOAD_CELL CellDep ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: bounds check Config.threshold required=8"),
            "read_ref schema field access did not emit a loaded-byte bounds check:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check Config expected=8"),
            "read_ref schema field access did not enforce exact fixed schema size:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: schema field Config.threshold offset=0 size=8"),
            "read_ref schema field access did not expose concrete layout:\n{}",
            asm
        );
        assert!(
            asm.contains("lbu t2, 0(t4)") && asm.contains("slli t2, t2, 56"),
            "read_ref u64 field access did not lower to an unaligned-safe byte load sequence:\n{}",
            asm
        );
        let action = result.metadata.actions.iter().find(|action| action.name == "inspect").expect("inspect metadata");
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "read-ref:read_ref_Config#0"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("read-ref-cell-dep-data=checked-runtime")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "read-ref:read_ref_Config#0"
                && requirement.status == "checked-runtime"
                && requirement.component == "read-ref-cell-dep-data"
                && requirement.source == "CellDep"
                && requirement.binding == "read_ref_Config"
                && requirement.field.as_deref() == Some("data")
                && requirement.abi == "read-ref-load-cell-dep"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
    }

    #[test]
    fn compile_binds_readonly_schema_entry_params_to_input_cells() {
        let program = r#"
module entry_read_ref

resource NFT has destroy {
    token_id: u64,
    owner: Address,
}

receipt Listing has destroy {
    token_id: u64,
    seller: Address,
    price: u64,
}

action create_listing(nft: &NFT, price: u64) -> Listing {
    create Listing {
        token_id: nft.token_id,
        seller: nft.owner,
        price: price,
    }
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: bind read-only param nft to Input#0 cell data"),
            "read-only schema entry parameter was not bound to an input cell:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=read_ref_param_input source=Input index=0"),
            "read-only schema entry parameter did not use the Input LOAD_CELL ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output field Listing.token_id offset=0 size=8"),
            "created output did not verify the u64 field copied from the read-only input:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output bytes field Listing.seller offset=8 size=32"),
            "created output did not verify the fixed-byte field copied from the read-only input:\n{}",
            asm
        );
    }

    #[test]
    fn compile_rejects_read_ref_for_non_cell_backed_types() {
        let err = compile(READ_REF_STRUCT_TARGET_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("read_ref target type 'Snapshot' must be a resource, shared, or receipt cell type"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_binds_read_ref_entry_params_to_cell_deps() {
        let program = r#"
module test

shared Config has store {
    admin: Address,
}

resource Token has store {
    amount: u64,
}

receipt Grant has store {
    admin: Address,
    amount: u64,
}

action grant(config: read_ref Config, token: Token) -> Grant {
    consume token
    create Grant {
        admin: config.admin,
        amount: token.amount,
    } with_lock(config.admin)
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: bind read-only param config to CellDep#0 cell data"),
            "read_ref entry parameter was not bound to a CellDep:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=read_ref_param_dep source=CellDep index=0"),
            "read_ref entry parameter did not use the CellDep LOAD_CELL ABI:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: bind read-only param config to Input#"),
            "read_ref entry parameter regressed back to Input binding:\n{}",
            asm
        );
    }

    #[test]
    fn compile_binds_duplicate_read_refs_by_order_not_name() {
        let result = compile(DUPLICATE_READ_REF_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=read_ref source=CellDep index=0"),
            "first read_ref did not bind to CellDep index 0:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=read_ref source=CellDep index=1"),
            "second read_ref did not bind to CellDep index 1:\n{}",
            asm
        );
        assert_eq!(
            asm.matches("# cellscript abi: bounds check Config.threshold required=8").count(),
            2,
            "duplicate read_refs should each have a schema bounds check:\n{}",
            asm
        );
    }

    #[test]
    fn compile_emits_ckb_style_load_cell_abi_for_cell_runtime_summary() {
        let result = compile(SUMMARY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=consume source=Input index=0"),
            "consume summary did not use CKB Source::Input LOAD_CELL ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=read_ref source=CellDep index=0"),
            "read_ref summary did not use CKB Source::CellDep LOAD_CELL ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=create source=Output index=0"),
            "create summary did not use CKB Source::Output LOAD_CELL ABI:\n{}",
            asm
        );
        assert!(asm.contains("addi a0, sp,"), "store_data buffer address was not prepared:\n{}", asm);
        assert!(asm.contains("addi a1, sp,"), "store_data size pointer was not prepared:\n{}", asm);
        assert!(asm.contains("li a2, 0"), "store_data offset was not prepared:\n{}", asm);
        assert!(asm.contains("li a3, 0"), "LOAD_CELL index register was not prepared:\n{}", asm);
        assert!(asm.contains("li a4, 1"), "Input source register was not prepared:\n{}", asm);
        assert!(asm.contains("li a4, 2"), "Output source register was not prepared:\n{}", asm);
        assert!(asm.contains("li a4, 3"), "CellDep source register was not prepared:\n{}", asm);
        assert!(asm.contains("li a7, 2092"), "LOAD_CELL_DATA syscall number was not emitted:\n{}", asm);
        assert!(!asm.contains("li a7, 2073"), "summary consume regressed to LOAD_INPUT with stale argument order:\n{}", asm);
    }

    #[test]
    fn compile_preserves_schema_backed_parameter_field_access_in_assembly() {
        let result = compile(PARAM_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# field access .amount"), "parameter field access vanished from assembly:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: schema field Snapshot.amount offset=0 size=8"),
            "schema field access did not expose the concrete layout contract:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: schema param snapshot pointer=a0 length=a1"),
            "schema parameter did not use pointer+length ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: bounds check Snapshot.amount required=8"),
            "schema parameter field access did not emit length-backed bounds check:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check Snapshot expected=8"),
            "schema parameter field access did not enforce exact fixed schema size:\n{}",
            asm
        );
        assert!(
            asm.contains("lbu t2, 0(t4)") && asm.contains("slli t2, t2, 56"),
            "u64 schema field access did not lower to an unaligned-safe byte load sequence:\n{}",
            asm
        );
        assert!(!asm.contains("field access '.amount' has no lowered schema-backed representation"));
    }

    #[test]
    fn compile_lowers_fixed_byte_schema_field_comparison() {
        let result = compile(FIXED_BYTE_FIELD_COMPARISON_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "same_symbol").unwrap();

        assert!(
            asm.contains("# cellscript abi: fixed-byte Eq comparison size=8"),
            "schema-backed fixed-byte equality did not lower to a byte comparison:\n{}",
            asm
        );
        assert!(
            !asm.contains("fixed-byte comparison symbolic runtime is not executable"),
            "verified fixed-byte equality should not use the symbolic fail-closed path:\n{}",
            asm
        );
        assert!(
            !action.fail_closed_runtime_features.contains(&"fixed-byte-comparison".to_string()),
            "metadata should not report fixed-byte comparison when both operands are verifier-coverable: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_lowers_packed_bool_and_u32_schema_fields_without_aligned_loads() {
        let result = compile(PACKED_SCALAR_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: schema field Flags.enabled offset=0 size=1"),
            "bool schema field access did not expose concrete layout:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: schema field Flags.nonce offset=1 size=4"),
            "u32 schema field access did not expose packed schema offset:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: bounds check Flags.nonce required=5"),
            "packed u32 schema field access did not check full byte span:\n{}",
            asm
        );
        assert!(
            asm.contains("lbu t2, 1(t4)") && asm.contains("slli t2, t2, 24"),
            "packed u32 field access did not lower to unaligned-safe little-endian byte loads:\n{}",
            asm
        );
    }

    #[test]
    fn compile_verifies_created_output_bool_and_u32_fields() {
        let result = compile(CREATE_SCALAR_VERIFY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: verify output field Flags.enabled offset=0 size=1"),
            "created bool output field was not verified:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output field Flags.nonce offset=1 size=4"),
            "created u32 output field was not verified:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check Flags expected=5"),
            "created packed scalar output did not enforce exact fixed schema size:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: bounds check Flags.nonce required=5"),
            "created packed u32 output field did not check full byte span:\n{}",
            asm
        );
        assert!(asm.contains("li t1, 1"), "created bool expected value was not loaded as 1:\n{}", asm);
        assert!(
            asm.contains("lbu t2, 1(t4)") && asm.contains("slli t2, t2, 24"),
            "created packed u32 verifier did not use unaligned-safe byte loads:\n{}",
            asm
        );
    }

    #[test]
    fn compile_verifies_created_scalar_fields_against_consumed_input_aliases() {
        let result = compile(CONSUME_CREATE_SCALAR_ALIAS_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=consume source=Input index=0"),
            "scalar alias verifier did not load consumed input:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=create source=Output index=0"),
            "scalar alias verifier did not load created output:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field Flags.enabled offset=0 size=1"),
            "created bool field was not compared against consumed input alias:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field Flags.nonce offset=1 size=4"),
            "created u32 field was not compared against consumed input alias:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check Flags expected=5"),
            "scalar alias verifier did not enforce exact fixed schema size:\n{}",
            asm
        );
    }

    #[test]
    fn compile_lowers_consumed_input_field_access_through_loaded_cell_bytes() {
        let result = compile(CONSUME_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=consume source=Input index=0"),
            "consume summary did not load the consumed input cell:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: bounds check Token.amount required=8"),
            "consumed input field access did not check loaded cell bounds:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check Token expected=8"),
            "consumed input field access did not enforce exact fixed schema size:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: schema field Token.amount offset=0 size=8"),
            "consumed input field access did not expose concrete schema layout:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: consumed input pointer retained for verifier field checks"),
            "consume instruction destroyed the preloaded input pointer:\n{}",
            asm
        );
    }

    #[test]
    fn compile_verifies_create_output_against_consumed_input_field_alias() {
        let result = compile(CONSUME_CREATE_CONSERVATION_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=consume source=Input index=0"),
            "conservation prelude did not load consumed input:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_DATA reason=create source=Output index=0"),
            "conservation prelude did not load created output:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "created output amount was not verified:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field Token.amount offset=0 size=8"),
            "created output amount was not compared against the consumed input amount:\n{}",
            asm
        );
        assert!(asm.contains("sub t2, t0, t1"), "created output amount and consumed input amount were not compared:\n{}", asm);
        let action = result.metadata.actions.iter().find(|action| action.name == "pass").expect("pass metadata");
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "resource-conservation:Token"
                    && obligation.status == "checked-runtime"
                    && obligation.detail.contains("resource-conservation=checked-runtime")
                    && obligation.detail.contains("fields: amount")
            }),
            "direct field-for-field resource conservation should be marked checked-runtime: {:?}",
            action.verifier_obligations
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "resource-conservation:Token"
                    && requirement.component == "resource-conservation-proof"
                    && requirement.status == "checked-runtime"
                    && requirement.source == "Transaction"
                    && requirement.binding == "Token"
                    && requirement.field.as_deref() == Some("input-output-conservation")
                    && requirement.abi == "resource-conservation-consume-create-accounting"
                    && requirement.blocker.is_none()
                    && requirement.blocker_class.is_none()
            }),
            "checked direct conservation should expose a checked transaction input component: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_verifies_create_output_against_prelude_u64_arithmetic() {
        let result = compile(CONSUME_CREATE_ARITHMETIC_CONSERVATION_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: expected expression u64 Sub"),
            "created output amount was not compared against a prelude arithmetic expression:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field Token.amount offset=0 size=8"),
            "prelude arithmetic expression did not read the consumed input amount:\n{}",
            asm
        );
        assert!(asm.contains("sub t1, t3, t1"), "prelude arithmetic expression did not compute input amount minus fee:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "created output amount was not verified:\n{}",
            asm
        );
        let action = result.metadata.actions.iter().find(|action| action.name == "withdraw").expect("withdraw metadata");
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "resource-conservation:Token"
                    && obligation.status == "runtime-required"
                    && obligation.detail.contains("resource-conservation=runtime-required")
            }),
            "arithmetic resource conservation should remain runtime-required: {:?}",
            action.verifier_obligations
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "resource-conservation:Token"
                    && requirement.component == "resource-conservation-proof"
                    && requirement.status == "runtime-required"
                    && requirement.source == "Transaction"
                    && requirement.binding == "Token"
                    && requirement.field.as_deref() == Some("input-output-conservation")
                    && requirement.abi == "resource-conservation-consume-create-accounting"
                    && requirement.blocker_class.as_deref() == Some("resource-conservation-proof-gap")
            }),
            "arithmetic resource conservation should expose a stable blocker class: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_classifies_resource_merge_amount_sum_as_checked_runtime() {
        let result = compile(CONSUME_CREATE_MERGE_CONSERVATION_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: expected expression u64 Add"),
            "created output amount was not compared against the merged input amount expression:\n{}",
            asm
        );
        assert!(
            asm.matches("# cellscript abi: expected field Token.amount offset=0 size=8").count() >= 2,
            "resource merge did not read both consumed input amounts:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "merged output amount was not verified:\n{}",
            asm
        );
        let action = result.metadata.actions.iter().find(|action| action.name == "merge").expect("merge metadata");
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "resource-conservation:Token"
                    && obligation.status == "checked-runtime"
                    && obligation.detail.contains("2 consumed 'Token' Inputs")
                    && obligation.detail.contains("verifier-recomputed u64 amount sum")
            }),
            "amount-sum resource merge should be marked checked-runtime: {:?}",
            action.verifier_obligations
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "resource-conservation:Token"
                    && requirement.component == "resource-conservation-proof"
                    && requirement.status == "checked-runtime"
                    && requirement.field.as_deref() == Some("input-output-conservation")
                    && requirement.blocker_class.is_none()
            }),
            "checked merge conservation should expose a checked transaction input component: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_classifies_guarded_identity_field_merge_as_checked_runtime() {
        let result = compile(
            CONSUME_CREATE_IDENTITY_FIELD_MERGE_CONSERVATION_PROGRAM,
            CompileOptions {
                target_profile: Some("ckb".to_string()),
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "merge").expect("merge metadata");
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "resource-conservation:Token"
                    && obligation.status == "checked-runtime"
                    && obligation.detail.contains("verifier-recomputed u64 amount sum")
            }),
            "guarded amount+identity merge should be marked checked-runtime: {:?}",
            action.verifier_obligations
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "resource-conservation:Token"
                    && requirement.component == "resource-conservation-proof"
                    && requirement.status == "checked-runtime"
                    && requirement.blocker_class.is_none()
            }),
            "guarded amount+identity merge should expose checked transaction input metadata: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn bundled_token_example_strict_ckb_compile_is_admitted() {
        let result = compile(
            include_str!("../examples/token.cell"),
            CompileOptions {
                target_profile: Some("ckb".to_string()),
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();
        assert_eq!(result.metadata.target_profile.name, "ckb");
        assert_eq!(result.metadata.target_profile.artifact_packaging, "ckb-elf-no-sporabi-trailer");
        let merge = result.metadata.actions.iter().find(|action| action.name == "merge").expect("merge metadata");
        assert!(
            merge
                .transaction_runtime_input_requirements
                .iter()
                .filter(|requirement| {
                    requirement.feature == "resource-conservation:Token" && requirement.component == "resource-conservation-proof"
                })
                .all(|requirement| requirement.status == "checked-runtime" && requirement.blocker_class.is_none()),
            "token merge should no longer require a CKB policy exception: {:?}",
            merge.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_classifies_resource_split_amount_subtraction_as_checked_runtime() {
        let result = compile(CONSUME_CREATE_SPLIT_CONSERVATION_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: expected expression u64 Sub"),
            "split output did not recompute consumed amount minus fee:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field Token.amount offset=0 size=8"),
            "split output did not read the consumed input amount:\n{}",
            asm
        );
        assert!(
            asm.matches("# cellscript abi: verify output field Token.amount offset=0 size=8").count() >= 2,
            "resource split did not verify both created output amounts:\n{}",
            asm
        );
        let action = result.metadata.actions.iter().find(|action| action.name == "split").expect("split metadata");
        assert!(
            action.verifier_obligations.iter().any(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "resource-conservation:Token"
                    && obligation.status == "checked-runtime"
                    && obligation.detail.contains("one consumed 'Token' Input is split across 2 created Outputs")
                    && obligation.detail.contains("verifier-recomputed u64 amount subtraction")
            }),
            "amount split resource conservation should be marked checked-runtime: {:?}",
            action.verifier_obligations
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "resource-conservation:Token"
                    && requirement.component == "resource-conservation-proof"
                    && requirement.status == "checked-runtime"
                    && requirement.field.as_deref() == Some("input-output-conservation")
                    && requirement.blocker_class.is_none()
            }),
            "checked split conservation should expose a checked transaction input component: {:?}",
            action.transaction_runtime_input_requirements
        );
        assert!(
            !action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "resource-conservation:Token"
                    && requirement.component == "resource-conservation-proof"
                    && requirement.status == "runtime-required"
            }),
            "checked split conservation must not expose a runtime-required conservation blocker: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_keeps_unsound_resource_conservation_runtime_required() {
        for (name, program) in [
            ("duplicate input amount leaf", CONSUME_CREATE_DUPLICATE_MERGE_CONSERVATION_PROGRAM),
            ("missing consumed input amount leaf", CONSUME_CREATE_MISSING_INPUT_MERGE_CONSERVATION_PROGRAM),
            ("extra non-amount field", CONSUME_CREATE_EXTRA_FIELD_MERGE_CONSERVATION_PROGRAM),
            ("duplicate split output", CONSUME_CREATE_DUPLICATE_SPLIT_CONSERVATION_PROGRAM),
        ] {
            let result = compile(program, CompileOptions::default()).unwrap();
            let action = result
                .metadata
                .actions
                .iter()
                .find(|action| action.name == "merge")
                .or_else(|| result.metadata.actions.iter().find(|action| action.name == "split"))
                .expect("resource conservation metadata action");
            assert!(
                action.verifier_obligations.iter().any(|obligation| {
                    obligation.category == "transaction-invariant"
                        && obligation.feature == "resource-conservation:Token"
                        && obligation.status == "runtime-required"
                        && obligation.detail.contains("resource-conservation=runtime-required")
                }),
                "{} should remain runtime-required resource conservation: {:?}",
                name,
                action.verifier_obligations
            );
            assert!(
                !action.verifier_obligations.iter().any(|obligation| {
                    obligation.category == "transaction-invariant"
                        && obligation.feature == "resource-conservation:Token"
                        && obligation.status == "checked-runtime"
                }),
                "{} must not be marked checked-runtime: {:?}",
                name,
                action.verifier_obligations
            );
            assert!(
                action.transaction_runtime_input_requirements.iter().any(|requirement| {
                    requirement.feature == "resource-conservation:Token"
                        && requirement.component == "resource-conservation-proof"
                        && requirement.status == "runtime-required"
                        && requirement.blocker_class.as_deref() == Some("resource-conservation-proof-gap")
                }),
                "{} should expose resource conservation blocker metadata: {:?}",
                name,
                action.transaction_runtime_input_requirements
            );
        }
    }

    #[test]
    fn compile_verifies_create_output_against_left_associative_prelude_u64_chain() {
        let result = compile(CONSUME_CREATE_CHAINED_ARITHMETIC_CONSERVATION_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert_eq!(
            asm.matches("# cellscript abi: expected expression u64 Sub").count(),
            2,
            "left-associative prelude arithmetic chain should be recomputed recursively:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field Token.amount offset=0 size=8"),
            "prelude arithmetic chain did not read the consumed input amount:\n{}",
            asm
        );
        assert!(asm.matches("sub t1, t3, t1").count() >= 2, "prelude arithmetic chain did not subtract both fee and tax:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "created output amount was not verified:\n{}",
            asm
        );
    }

    #[test]
    fn compile_verifies_create_output_against_local_const_prelude_u64() {
        let result = compile(CONSUME_CREATE_LOCAL_CONST_CONSERVATION_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: expected expression u64 Sub"),
            "created output amount was not compared against the local-const arithmetic expression:\n{}",
            asm
        );
        assert!(asm.contains("li t1, 2"), "prelude arithmetic expression did not preserve local const fee:\n{}", asm);
        assert!(asm.contains("sub t1, t3, t1"), "prelude arithmetic expression did not subtract local const fee:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "created output amount was not verified:\n{}",
            asm
        );
    }

    #[test]
    fn compile_preserves_index_and_tuple_projection_in_assembly() {
        let result = compile(INDEXED_TUPLE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# index access"), "array indexing vanished from assembly:\n{}", asm);
        assert!(asm.contains("# field access .1"), "tuple projection vanished from assembly:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: fixed aggregate index element_offset=0 element_size=40"),
            "fixed tuple-array indexing did not lower through the pointer+length ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: fixed aggregate field tuple.1 offset=32 size=8"),
            "fixed tuple projection did not lower through aggregate field access:\n{}",
            asm
        );
        assert!(
            !asm.contains("symbolic runtime is not executable"),
            "fixed tuple-array index/projection should not fail closed:\n{}",
            asm
        );
    }

    #[test]
    fn compile_unrolls_fixed_param_array_foreach_with_pointer_abi() {
        let result = compile(FOREACH_ARRAY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# length"), "fixed parameter foreach should be unrolled without dynamic length lowering:\n{}", asm);
        assert!(!asm.contains("j .Lblock_1"), "fixed parameter foreach should be unrolled without a loop back edge:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: fixed-aggregate param items pointer=a0 length=a1 size=24"),
            "fixed array parameter did not use pointer+length ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: fixed aggregate index element_offset=0 element_size=8")
                && asm.contains("# cellscript abi: fixed aggregate index element_offset=8 element_size=8")
                && asm.contains("# cellscript abi: fixed aggregate index element_offset=16 element_size=8"),
            "fixed parameter foreach did not unroll into exact aggregate indexes:\n{}",
            asm
        );
        assert!(
            !asm.contains("index access symbolic runtime is not executable"),
            "fixed parameter foreach should not use symbolic index fail-closed lowering:\n{}",
            asm
        );
    }

    #[test]
    fn compile_unrolls_local_fixed_array_foreach_without_symbolic_indexing() {
        let result = compile(LOCAL_FOREACH_ARRAY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# length"), "local fixed-array foreach unnecessarily used length runtime:\n{}", asm);
        assert!(!asm.contains("# index access"), "local fixed-array foreach fell back to symbolic indexing:\n{}", asm);
        assert!(
            !asm.contains("index access symbolic runtime is not executable"),
            "local fixed-array foreach incorrectly failed closed:\n{}",
            asm
        );
        assert!(asm.contains("li t0, 1"), "unrolled foreach lost first element literal:\n{}", asm);
        assert!(asm.contains("li t0, 2"), "unrolled foreach lost second element literal:\n{}", asm);
        assert!(asm.contains("li t0, 3"), "unrolled foreach lost third element literal:\n{}", asm);
    }

    #[test]
    fn compile_unrolls_local_array_of_tuples_foreach_destructuring() {
        let result = compile(LOCAL_FOREACH_ARRAY_OF_TUPLES_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# index access"), "local array-of-tuples foreach fell back to symbolic indexing:\n{}", asm);
        assert!(!asm.contains("# field access .1"), "tuple foreach destructuring fell back to symbolic field access:\n{}", asm);
        assert!(
            !asm.contains("symbolic runtime is not executable"),
            "local array-of-tuples foreach incorrectly required symbolic runtime:\n{}",
            asm
        );
        assert!(asm.contains("li t0, 2"), "tuple foreach lost first amount literal:\n{}", asm);
        assert!(asm.contains("li t0, 5"), "tuple foreach lost second amount literal:\n{}", asm);
    }

    #[test]
    fn compile_lowers_len_method_to_length_instruction() {
        let result = compile(LEN_METHOD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# length"), "len() call did not lower to length instruction:\n{}", asm);
        assert!(!asm.contains("# call len"), "len() call leaked through generic call path:\n{}", asm);
    }

    #[test]
    fn compile_rejects_forbidden_unwrap_helpers() {
        let unwrap_err = compile(FORBIDDEN_UNWRAP_CALL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(unwrap_err.message.contains("unwrap is forbidden"), "unexpected error: {}", unwrap_err.message);

        let expect_err = compile(FORBIDDEN_EXPECT_METHOD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(expect_err.message.contains("expect is forbidden"), "unexpected error: {}", expect_err.message);

        let unwrap_or_err = compile(FORBIDDEN_NAMESPACED_UNWRAP_OR_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(unwrap_or_err.message.contains("unwrap_or is forbidden"), "unexpected error: {}", unwrap_or_err.message);
    }

    #[test]
    fn compile_folds_local_fixed_array_len_to_constant() {
        let result = compile(LOCAL_ARRAY_LEN_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# length"), "local fixed-array len should fold before runtime length lowering:\n{}", asm);
        assert!(
            !asm.contains("dynamic length symbolic runtime is not executable"),
            "local fixed-array len incorrectly required symbolic runtime:\n{}",
            asm
        );
        assert!(asm.contains("li a0, 3"), "local fixed-array len did not return the static length:\n{}", asm);
    }

    #[test]
    fn compile_supports_typed_empty_array_literals() {
        let result = compile(TYPED_EMPTY_ARRAY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# length"), "typed empty fixed-array len should fold before runtime length lowering:\n{}", asm);
        assert!(asm.contains("li a0, 0"), "typed empty fixed-array len did not return zero:\n{}", asm);
    }

    #[test]
    fn compile_rejects_untyped_empty_array_literals() {
        let err = compile(UNTYPED_EMPTY_ARRAY_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("empty array literal requires an explicit array type annotation"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_empty_array_length_mismatch() {
        let err = compile(WRONG_LENGTH_EMPTY_ARRAY_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("empty array literal cannot initialize non-empty array"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_lowers_local_fixed_array_static_index_reads_and_writes() {
        let result = compile(LOCAL_ARRAY_STATIC_INDEX_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# index access"), "local fixed-array static indexes fell back to symbolic runtime:\n{}", asm);
        assert!(
            !asm.contains("index access symbolic runtime is not executable"),
            "local fixed-array static indexes incorrectly failed closed:\n{}",
            asm
        );
        assert!(asm.contains("li t0, 7"), "array element assignment did not preserve assigned constant:\n{}", asm);
        assert!(asm.contains("add t0, t0, t1"), "array element read/write result did not lower into arithmetic:\n{}", asm);
    }

    #[test]
    fn compile_rejects_assignment_to_immutable_array_element() {
        let err = compile(IMMUTABLE_ARRAY_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("assignment target rooted at 'items' is not mutable"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_heterogeneous_array_literals() {
        let err = compile(HETEROGENEOUS_ARRAY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("array elements must have matching types"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_local_fixed_array_static_oob_read() {
        let err = compile(LOCAL_ARRAY_OOB_READ_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("array index 2 is out of bounds for local fixed array of length 2"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_local_fixed_array_static_oob_write() {
        let err = compile(LOCAL_ARRAY_OOB_WRITE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("array index 2 is out of bounds for local fixed array of length 2"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_lowers_local_tuple_static_field_reads_and_writes() {
        let result = compile(LOCAL_TUPLE_STATIC_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# field access .1"), "local tuple field access fell back to symbolic/schema path:\n{}", asm);
        assert!(asm.contains("li t0, 7"), "tuple field assignment did not preserve assigned constant:\n{}", asm);
        assert!(asm.contains("add t0, t0, t1"), "tuple field reads did not lower into arithmetic:\n{}", asm);
    }

    #[test]
    fn compile_lowers_array_of_tuples_static_index_projection() {
        let result = compile(ARRAY_OF_TUPLES_STATIC_INDEX_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# index access"), "local array-of-tuples static index fell back to symbolic runtime:\n{}", asm);
        assert!(!asm.contains("# field access .1"), "local tuple projection fell back to symbolic/schema path:\n{}", asm);
        assert!(
            !asm.contains("symbolic runtime is not executable"),
            "local array-of-tuples projection incorrectly required symbolic runtime:\n{}",
            asm
        );
        assert!(asm.contains("li t0, 5"), "selected tuple amount did not preserve expected literal:\n{}", asm);
    }

    #[test]
    fn compile_rejects_assignment_to_immutable_tuple_field() {
        let err = compile(IMMUTABLE_TUPLE_ASSIGN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("assignment target rooted at 'pair' is not mutable"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_lowers_local_tuple_destructuring_to_field_slots() {
        let result = compile(LOCAL_TUPLE_DESTRUCTURE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# field access .0"), "tuple destructuring fell back to symbolic field access:\n{}", asm);
        assert!(!asm.contains("# field access .1"), "tuple destructuring fell back to symbolic field access:\n{}", asm);
        assert!(asm.contains("li t0, 1"), "tuple destructuring lost first literal:\n{}", asm);
        assert!(asm.contains("li t0, 2"), "tuple destructuring lost second literal:\n{}", asm);
        assert!(asm.contains("add t0, t0, t1"), "tuple destructuring did not feed arithmetic:\n{}", asm);
    }

    #[test]
    fn compile_lowers_match_expression_into_branch_cfg() {
        let result = compile(MATCH_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("seqz t0, t0"), "match lowering missing equality check:\n{}", asm);
        assert!(asm.contains(".Lselect_block_1:"), "match lowering missing first arm block:\n{}", asm);
        assert!(asm.contains(".Lselect_block_3:"), "match lowering missing join block:\n{}", asm);
    }

    #[test]
    fn compile_lowers_exhaustive_enum_match_without_wildcard() {
        let result = compile(EXHAUSTIVE_MATCH_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("seqz t0, t0"), "exhaustive match lowering missing equality check:\n{}", asm);
        assert!(asm.contains("li a0, 8"), "exhaustive match did not retain invalid-discriminant fail-closed branch:\n{}", asm);
    }

    #[test]
    fn compile_merges_linear_moves_inside_match_expressions() {
        compile(LINEAR_MATCH_EXPR_LET_MOVE_PROGRAM, CompileOptions::default()).unwrap();
        compile(LINEAR_MATCH_EXPR_STATEFUL_ARMS_PROGRAM, CompileOptions::default()).unwrap();

        let moved_err = compile(LINEAR_MATCH_EXPR_INCONSISTENT_LET_MOVE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            moved_err.message.contains("linear resource 'left' has inconsistent ownership state across match arms")
                || moved_err.message.contains("linear resource 'right' has inconsistent ownership state across match arms"),
            "unexpected error: {}",
            moved_err.message
        );

        let stateful_err = compile(LINEAR_MATCH_EXPR_INCONSISTENT_STATEFUL_ARMS_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            stateful_err.message.contains("linear resource 'token' has inconsistent ownership state across match arms"),
            "unexpected error: {}",
            stateful_err.message
        );
    }

    #[test]
    fn compile_rejects_invalid_enum_match_patterns() {
        let unknown = compile(UNKNOWN_MATCH_VARIANT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(unknown.message.contains("unknown enum variant 'Flag::Maybe'"), "unexpected error: {}", unknown.message);

        let duplicate = compile(DUPLICATE_MATCH_VARIANT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            duplicate.message.contains("duplicate match arm for enum variant 'Flag::On'"),
            "unexpected error: {}",
            duplicate.message
        );

        let non_exhaustive = compile(NON_EXHAUSTIVE_MATCH_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            non_exhaustive.message.contains("non-exhaustive match for enum 'Flag'"),
            "unexpected error: {}",
            non_exhaustive.message
        );
        assert!(non_exhaustive.message.contains("Off"), "unexpected error: {}", non_exhaustive.message);
    }

    #[test]
    fn compile_rejects_enum_payload_variants_until_lowering_exists() {
        let err = compile(ENUM_PAYLOAD_VARIANT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("match pattern 'MaybeAmount::Some' targets a payload enum variant"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_payload_or_unknown_enum_variant_values() {
        let payload = compile(ENUM_PAYLOAD_VALUE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            payload.message.contains("enum payload variant 'AssetType::Token' cannot be used as a value"),
            "unexpected error: {}",
            payload.message
        );

        let unknown = compile(UNKNOWN_ENUM_VALUE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(unknown.message.contains("unknown enum variant 'Flag::Maybe'"), "unexpected error: {}", unknown.message);
    }

    #[test]
    fn compile_rejects_unknown_or_reserved_named_types() {
        let unknown = compile(UNKNOWN_NAMED_TYPE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(unknown.message.contains("unknown type 'MissingType'"), "unexpected error: {}", unknown.message);

        let reserved = compile(RESERVED_OPTION_TYPE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            reserved.message.contains("type 'Option' is reserved for the explicit error model but is not implemented yet"),
            "unexpected error: {}",
            reserved.message
        );

        let generic = compile(USER_GENERIC_TYPE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(generic.message.contains("post-v1 template/codegen syntax"), "unexpected error: {}", generic.message);
    }

    #[test]
    fn compile_rejects_duplicate_top_level_symbols() {
        let err = compile(DUPLICATE_TOP_LEVEL_SYMBOL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate symbol 'Token'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_lowers_vec_builtins_without_generic_calls() {
        let result = compile(VEC_BUILTIN_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# collection new Vec"), "Vec::new() did not lower into collection instruction:\n{}", asm);
        assert!(asm.contains("# collection push"), "push() did not lower into collection instruction:\n{}", asm);
        assert!(
            asm.contains("# collection extend_from_slice"),
            "extend_from_slice() did not lower into collection instruction:\n{}",
            asm
        );
        assert!(asm.contains("# length"), "len() did not stay on builtin length path:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: collection push is not needed for verifier execution")
                || asm.contains("# cellscript abi: collection extend is not needed for verifier execution"),
            "collection push/extend fail-closed comment not found:\n{}",
            asm
        );
        assert!(!asm.contains("# call push"), "push() leaked through generic call path:\n{}", asm);
        assert!(!asm.contains("# call extend_from_slice"), "extend_from_slice() leaked through generic call path:\n{}", asm);
        assert!(!asm.contains("# call len"), "len() leaked through generic call path:\n{}", asm);
    }

    #[test]
    fn compile_lowers_stack_vec_scalar_runtime_push_len_index() {
        let result = compile(STACK_VEC_RUNTIME_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: stack collection push element_size=8"),
            "scalar Vec<u64> push should execute against the stack collection buffer:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection length"),
            "scalar Vec<u64> len should read the stack collection length word:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection index element_size=8"),
            "scalar Vec<u64> index should read from the stack collection buffer:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: collection push is not needed for verifier execution")
                && !asm.contains("# cellscript abi: fail closed because dynamic length is not available")
                && !asm.contains("# cellscript abi: fail closed because element layout is not statically computable"),
            "stack-backed scalar Vec runtime should not hit the old fail-closed collection paths:\n{}",
            asm
        );

        let action = result.metadata.actions.iter().find(|action| action.name == "stack_vec_sum").unwrap();
        assert!(
            !action.fail_closed_runtime_features.contains(&"collection-new".to_string())
                && !action.fail_closed_runtime_features.contains(&"collection-push".to_string())
                && !action.fail_closed_runtime_features.contains(&"dynamic-length".to_string())
                && !action.fail_closed_runtime_features.contains(&"index-access".to_string()),
            "stack-backed scalar Vec runtime should not be reported as fail-closed: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_lowers_stack_vec_fixed_byte_runtime_push_index() {
        let result = compile(FIXED_BYTE_STACK_VEC_RUNTIME_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: stack collection push element_size=32"),
            "Vec<Address> push should execute against the stack collection buffer:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection copy fixed bytes size=32"),
            "Vec<Address> push should copy fixed-byte elements into the stack collection buffer:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection index element_size=32"),
            "Vec<Address> index should return a pointer into the stack collection buffer:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: collection push is not needed for verifier execution")
                && !asm.contains("# cellscript abi: fail closed because element layout is not statically computable"),
            "stack-backed Vec<Address> runtime should not hit the old fail-closed collection paths:\n{}",
            asm
        );

        let action = result.metadata.actions.iter().find(|action| action.name == "stack_vec_address_roundtrip").unwrap();
        assert!(
            !action.fail_closed_runtime_features.contains(&"collection-new".to_string())
                && !action.fail_closed_runtime_features.contains(&"collection-push".to_string())
                && !action.fail_closed_runtime_features.contains(&"index-access".to_string())
                && !action.fail_closed_runtime_features.contains(&"fixed-byte-comparison".to_string()),
            "stack-backed Vec<Address> runtime should not be reported as fail-closed: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_lowers_stack_vec_extend_from_fixed_bytes() {
        let result = compile(STACK_VEC_EXTEND_RUNTIME_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: stack collection extend bytes=3 elements=3 element_size=1"),
            "Vec<u8> extend_from_slice should execute against the stack collection buffer:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection extend copy fixed bytes size=3"),
            "Vec<u8> extend_from_slice should copy fixed bytes into the stack collection buffer:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection length"),
            "Vec<u8> len after extend_from_slice should read the stack collection length word:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: collection extend is not needed for verifier execution")
                && !asm.contains("# cellscript abi: fail closed because dynamic length is not available"),
            "stack-backed Vec<u8> extend_from_slice should not hit the old fail-closed collection paths:\n{}",
            asm
        );

        let action = result.metadata.actions.iter().find(|action| action.name == "stack_vec_extend_len").unwrap();
        assert!(
            !action.fail_closed_runtime_features.contains(&"collection-new".to_string())
                && !action.fail_closed_runtime_features.contains(&"collection-extend".to_string())
                && !action.fail_closed_runtime_features.contains(&"dynamic-length".to_string()),
            "stack-backed Vec<u8> extend_from_slice should not be reported as fail-closed: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_lowers_stack_vec_clear_and_is_empty() {
        let result = compile(STACK_VEC_CLEAR_IS_EMPTY_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains("# cellscript abi: stack collection clear"),
            "Vec.clear should reset the stack collection length word:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: stack collection length"),
            "Vec.is_empty should read stack collection length through the builtin length path:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: collection clear is not needed for verifier execution")
                && !asm.contains("# cellscript abi: fail closed because dynamic length is not available"),
            "stack-backed Vec.clear/is_empty should not hit fail-closed collection paths:\n{}",
            asm
        );

        let action = result.metadata.actions.iter().find(|action| action.name == "stack_vec_clear_len").unwrap();
        assert!(
            !action.fail_closed_runtime_features.contains(&"collection-new".to_string())
                && !action.fail_closed_runtime_features.contains(&"collection-push".to_string())
                && !action.fail_closed_runtime_features.contains(&"collection-clear".to_string())
                && !action.fail_closed_runtime_features.contains(&"dynamic-length".to_string()),
            "stack-backed Vec.clear/is_empty should not be reported as fail-closed: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_verifies_constructed_fixed_width_vec_output() {
        let result = compile(FIXED_WIDTH_VEC_CREATE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            asm.contains(
                "# cellscript abi: verify output dynamic field Group.members as constructed Molecule vector elements=1 bytes=32 element_size=32"
            ),
            "Group.members Vec<Address> should be verifier-checked as a fixed-width Molecule vector:\n{}",
            asm
        );
        assert!(
            asm.contains(
                "# cellscript abi: verify output dynamic field Group.anchors as constructed Molecule vector elements=1 bytes=32 element_size=32"
            ),
            "Group.anchors Vec<Hash> should be verifier-checked as a fixed-width Molecule vector:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: collection push is covered by create-output vector verifier"),
            "fixed-width Vec pushes used for create-output fields should not execute the fail-closed collection path:\n{}",
            asm
        );

        let action = result.metadata.actions.iter().find(|action| action.name == "create_group").unwrap();
        assert!(
            !action.fail_closed_runtime_features.contains(&"collection-new".to_string())
                && !action.fail_closed_runtime_features.contains(&"collection-push".to_string())
                && !action.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "fixed-width Vec create-output verifier should leave no collection fail-closed debt: {:?}",
            action.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_marks_cell_backed_vec_runtime_features() {
        let result = compile(CELL_BACKED_VEC_PROGRAM, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "batch_mint").expect("batch_mint action metadata");

        // Cell-backed collection operations are no longer classified as symbolic
        // (they have real RISC-V lowerings or fail-closed traps). They are
        // tracked in fail_closed_runtime_features instead.
        assert!(
            action.symbolic_runtime_features.is_empty(),
            "symbolic_runtime_features should be empty (all ops have lowerings): {:?}",
            action.symbolic_runtime_features
        );
        assert!(
            action.fail_closed_runtime_features.contains(&"cell-backed-collection-push".to_string()),
            "cell-backed push must be visible in fail-closed features: {:?}",
            action.fail_closed_runtime_features
        );
        assert!(
            action.fail_closed_runtime_features.contains(&"cell-backed-collection-return".to_string()),
            "cell-backed Vec return must be visible in fail-closed features: {:?}",
            action.fail_closed_runtime_features
        );
        assert!(
            result.metadata.runtime.legacy_symbolic_cell_runtime_features.is_empty(),
            "legacy_symbolic_cell_runtime_features should be empty (all ops have lowerings): {:?}",
            result.metadata.runtime.legacy_symbolic_cell_runtime_features
        );
        assert!(
            result.metadata.runtime.fail_closed_runtime_features.contains(&"cell-backed-collection-push".to_string()),
            "runtime metadata must aggregate cell-backed collection fail-closed features: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        let linear_collection_obligation = action
            .verifier_obligations
            .iter()
            .find(|obligation| obligation.feature == "linear-collection:NFT")
            .expect("cell-backed collection obligation");
        assert_eq!(linear_collection_obligation.category, "transaction-invariant");
        assert_eq!(linear_collection_obligation.status, "runtime-required");
        assert!(
            linear_collection_obligation.detail.contains("linear-collection-ownership=runtime-required"),
            "linear collection obligation must expose the blocker detail: {:?}",
            linear_collection_obligation
        );
        assert!(
            action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "linear-collection:NFT"
                    && requirement.component == "linear-collection-ownership"
                    && requirement.status == "runtime-required"
                    && requirement.blocker_class.as_deref() == Some("linear-collection-ownership-gap")
            }),
            "action metadata must expose a linear collection runtime input blocker: {:?}",
            action.transaction_runtime_input_requirements
        );
        assert!(
            result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "linear-collection:NFT"
                    && requirement.component == "linear-collection-ownership"
                    && requirement.status == "runtime-required"
                    && requirement.blocker_class.as_deref() == Some("linear-collection-ownership-gap")
            }),
            "runtime metadata must aggregate the linear collection runtime input blocker: {:?}",
            result.metadata.runtime.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn ckb_dynamic_vector_len_can_drive_mutate_transition() {
        let source = r#"
module dynamic_len_transition

resource Collection {
    total_supply: u64,
    name: Vec<u8>,
}

action batch(collection: &mut Collection, recipients: Vec<Address>) {
    collection.total_supply += recipients.len() as u64
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "batch").expect("batch metadata");
        let mutation = action.mutate_set.iter().find(|mutation| mutation.ty == "Collection").expect("Collection mutation");

        assert_eq!(mutation.field_transition_status, "checked-runtime");
        assert!(
            !action
                .transaction_runtime_input_requirements
                .iter()
                .any(|requirement| requirement.feature == "mutable-cell:Collection"
                    && requirement.component == "mutate-field-transition"),
            "dynamic vector len transition should not leave a runtime-required mutable-cell transition blocker: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_lowers_type_hash_without_generic_call() {
        let result = compile(TYPE_HASH_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# type_hash"), "type_hash() did not lower into builtin instruction:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: schema param pool type_hash pointer=a2 length=a3 size=32"),
            "schema parameter type_hash() should be backed by an explicit pointer+length ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: exact size check param type hash expected=32"),
            "schema parameter type_hash() should reject non-32-byte ABI payloads:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: type_hash symbolic runtime is not executable"),
            "schema parameter type_hash() should not use the symbolic fail-closed path:\n{}",
            asm
        );
        assert!(!asm.contains("# call type_hash"), "type_hash() leaked through generic call path:\n{}", asm);
        let action = result.metadata.actions.iter().find(|action| action.name == "pool_id").unwrap();
        assert!(
            action.fail_closed_runtime_features.is_empty(),
            "schema parameter type_hash() should be verifier-coverable: {:?}",
            action.fail_closed_runtime_features
        );
        let param = action.params.iter().find(|param| param.name == "pool").unwrap();
        assert!(param.type_hash_pointer_abi);
        assert!(param.type_hash_length_abi);
        assert_eq!(param.type_hash_len, Some(32));
    }

    #[test]
    fn compile_lowers_zero_builtin_without_generic_call() {
        let result = compile(ZERO_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(!asm.contains("# call zero"), "Address::zero() leaked through generic call path:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: fixed-byte Eq comparison size=32"),
            "Address::zero() comparison should lower to a full-width byte comparison:\n{}",
            asm
        );
        assert!(
            !asm.contains("fixed-byte comparison symbolic runtime is not executable"),
            "Address::zero() comparison should not use the symbolic fail-closed path:\n{}",
            asm
        );
    }

    #[test]
    fn compile_result_writes_artifact_to_disk() {
        let result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        let dir = tempdir().unwrap();
        let output = Utf8Path::from_path(dir.path()).unwrap().join("out").join("program.s");

        result.write_to_path(&output).unwrap();

        let written = std::fs::read(&output).unwrap();
        assert_eq!(written, result.artifact_bytes);
    }

    #[test]
    fn compile_produces_non_empty_riscv_elf() {
        let result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert!(!result.artifact_bytes.is_empty());
        assert!(result.metadata.runtime.vm_abi.embedded_in_artifact);
        assert!(result.artifact_bytes.len() > crate::strip_vm_abi_trailer(&result.artifact_bytes).len());
        assert!(crate::strip_vm_abi_trailer(&result.artifact_bytes).starts_with(b"\x7fELF"));
    }

    #[test]
    fn compile_produces_ckb_elf_without_vm_abi_trailer() {
        let result = compile(
            SIMPLE_PROGRAM,
            CompileOptions {
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert_eq!(result.metadata.target_profile.name.as_str(), "ckb");
        assert_eq!(result.metadata.target_profile.artifact_packaging.as_str(), "ckb-elf-no-sporabi-trailer");
        assert!(!result.metadata.runtime.vm_abi.embedded_in_artifact);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert_eq!(result.artifact_bytes.len(), crate::strip_vm_abi_trailer(&result.artifact_bytes).len());
        result.validate().unwrap();
    }

    #[test]
    fn compile_metadata_declares_molecule_vm_abi() {
        let result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();

        assert_eq!(result.metadata.metadata_schema_version, crate::METADATA_SCHEMA_VERSION);
        assert_eq!(result.metadata.compiler_version, crate::VERSION);
        assert_eq!(result.metadata.runtime.vm_abi.format, "molecule");
        assert_eq!(result.metadata.runtime.vm_abi.version, 0x8001);
        assert!(result.metadata.runtime.vm_abi.default);
        assert!(result.metadata.runtime.vm_abi.embedded_in_artifact);
        assert!(result.metadata.runtime.vm_abi.scope.contains("LOAD_SCRIPT"));
        assert!(result.metadata.runtime.vm_abi.selection.contains("embed"));
        assert_eq!(result.metadata.target_profile.name.as_str(), "spora");
        assert_eq!(result.metadata.target_profile.target_chain.as_str(), "spora");
        assert_eq!(result.metadata.target_profile.vm_abi.as_str(), "molecule-0x8001");
        assert_eq!(result.metadata.target_profile.hash_domain.as_str(), "spora-domain-separated-blake3");
        assert_eq!(result.metadata.target_profile.syscall_set.as_str(), "spora-ckb-style-load-syscalls");
        assert_eq!(result.metadata.target_profile.artifact_packaging.as_str(), "spora-elf-sporabi-trailer");
        assert_eq!(result.metadata.target_profile.header_abi.as_str(), "spora-dag-header");
        assert_eq!(result.metadata.target_profile.scheduler_abi.as_str(), "spora-scheduler-witness-v1-molecule");
        assert_eq!(result.metadata.artifact_hash_blake3.as_deref(), Some(crate::hex_encode(&result.artifact_hash).as_str()));
        assert_eq!(result.metadata.artifact_size_bytes, Some(result.artifact_bytes.len()));
        assert!(result.metadata.source_hash_blake3.is_some());
        assert!(result.metadata.source_content_hash_blake3.is_some());
        assert_eq!(result.metadata.source_units.len(), 1);
        assert_eq!(result.metadata.source_units[0].path, "<memory>");
        assert_eq!(result.metadata.source_units[0].role, "memory");
    }

    #[test]
    fn compile_result_validation_accepts_current_outputs() {
        let result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();

        result.validate().unwrap();
    }

    #[test]
    fn compile_rejects_unsupported_optimization_level() {
        let err = compile(SIMPLE_PROGRAM, CompileOptions { opt_level: 4, ..CompileOptions::default() }).unwrap_err();

        assert!(err.message.contains("optimization level must be between 0 and 3"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_accepts_pure_ckb_target_profile() {
        let result =
            compile(SIMPLE_PROGRAM, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();

        assert_eq!(result.metadata.target_profile.name.as_str(), "ckb");
        assert_eq!(result.metadata.target_profile.artifact_packaging.as_str(), "ckb-asm-sidecar");
        assert!(!result.metadata.runtime.vm_abi.embedded_in_artifact);
        result.validate().unwrap();
    }

    #[test]
    fn compile_accepts_ckb_shared_create_when_verifier_covered() {
        let source = r#"
module test::shared_create

shared Config has store {
    admin: Address,
    enabled: bool,
}

action create_config(admin: Address, enabled: bool) -> Config {
    create Config {
        admin: admin,
        enabled: enabled,
    } with_lock(admin)
}
"#;

        let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "create_config").expect("create_config metadata");

        assert_eq!(result.metadata.target_profile.name.as_str(), "ckb");
        assert!(!action.touches_shared.is_empty(), "shared creation should remain scheduler-visible metadata");
        assert!(action.fail_closed_runtime_features.is_empty(), "shared create should not carry fail-closed debt");
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:Config:create_Config"
                && requirement.status == "checked-runtime"
                && requirement.component == "create-output-fields"
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "create-output:Config:create_Config"
                && requirement.status == "checked-runtime"
                && requirement.component == "create-output-lock"
        }));
        result.validate().unwrap();
    }

    #[test]
    fn compile_rejects_portable_cell_artifact_profile() {
        let err =
            compile(SIMPLE_PROGRAM, CompileOptions { target_profile: Some("portable-cell".to_string()), ..CompileOptions::default() })
                .unwrap_err();

        assert!(err.message.contains("portable-cell"), "unexpected error: {}", err.message);
        assert!(err.message.contains("source compatibility profile"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_ckb_target_profile_daa_dependency() {
        let err = compile(
            r#"
module test::daa

action now() -> u64 {
    return env::current_daa_score()
}
"#,
            CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
        )
        .unwrap_err();

        assert!(err.message.contains("target profile policy failed for 'ckb'"), "unexpected error: {}", err.message);
        assert!(err.message.contains("DAA/header assumptions are Spora-specific"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_accepts_chain_neutral_timepoint_under_ckb_profile() {
        let result = compile(
            r#"
module test::timepoint

action now() -> u64 {
    return env::current_timepoint()
}
"#,
            CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
        )
        .unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("call __env_current_timepoint"), "timepoint call was not lowered:\n{}", asm);
        assert!(
            asm.contains("LOAD_HEADER_BY_FIELD field=ckb_epoch_number source=HeaderDep index=0"),
            "CKB timepoint should use the CKB epoch-number header field:\n{}",
            asm
        );
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"load-header-timepoint".to_string()));
        assert!(
            !result.metadata.runtime.ckb_runtime_features.contains(&"load-header-daa-score".to_string()),
            "chain-neutral timepoint must not expose Spora DAA under CKB: {:?}",
            result.metadata.runtime.ckb_runtime_features
        );
    }

    #[test]
    fn compile_accepts_ckb_header_epoch_api_only_for_ckb_profile() {
        let result =
            compile(CKB_HEADER_EPOCH_PROGRAM, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() })
                .unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("call __ckb_header_epoch_number"), "epoch number call was not lowered:\n{}", asm);
        assert!(
            asm.contains("LOAD_HEADER_BY_FIELD field=ckb_epoch_number source=HeaderDep index=0"),
            "epoch number helper did not document CKB header ABI:\n{}",
            asm
        );
        assert!(asm.contains("call __ckb_input_since"), "since call was not lowered:\n{}", asm);
        assert!(
            asm.contains("LOAD_INPUT_BY_FIELD field=ckb_input_since source=GroupInput index=0"),
            "since helper did not document CKB input ABI:\n{}",
            asm
        );
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-header-epoch-number".to_string()));
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-header-epoch-start-block-number".to_string()));
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-header-epoch-length".to_string()));
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"ckb-input-since".to_string()));
        let ckb_constraints = result.metadata.constraints.ckb.as_ref().expect("ckb constraints metadata");
        assert!(ckb_constraints.uses_input_since, "ckb constraints must surface input_since usage");
        assert!(ckb_constraints.uses_header_epoch, "ckb constraints must surface epoch-header usage");
        assert!(
            ckb_constraints.ckb_runtime_features.iter().any(|feature| feature == "ckb-input-since"),
            "ckb constraints must carry ckb runtime features"
        );
        assert_eq!(ckb_constraints.hash_domain, "ckb-packed-molecule-blake2b");
        assert_eq!(ckb_constraints.declared_type_id_hash_type, crate::CKB_TYPE_ID_HASH_TYPE);
        assert!(
            ckb_constraints.supported_script_hash_types.iter().any(|hash_type| hash_type == "data2"),
            "CKB constraints must expose supported script hash_type set"
        );
        assert!(ckb_constraints.tx_size_measurement_required, "CKB production constraints must require tx-size measurement");
        assert_eq!(ckb_constraints.timelock_policy_surface, "runtime-metadata-visible; declarative-dsl-policy-not-yet-first-class");
        assert_eq!(ckb_constraints.timelock_policy.policy_kind, "runtime-assertion-policy");
        assert!(ckb_constraints.timelock_policy.uses_input_since);
        assert!(ckb_constraints.timelock_policy.uses_header_epoch);
        assert!(ckb_constraints.timelock_policy.runtime_features.iter().any(|feature| feature == "ckb-input-since"));
        assert!(
            !ckb_constraints.capacity_planning_required,
            "pure epoch/since reads must not claim output-capacity planning is required"
        );
        assert_eq!(ckb_constraints.created_output_count, 0, "pure epoch/since reads must not report created outputs");
        assert_eq!(ckb_constraints.mutated_output_count, 0, "pure epoch/since reads must not report mutated outputs");
        assert_eq!(ckb_constraints.capacity_policy_surface, "not-applicable");
        assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| {
            access.syscall == "LOAD_INPUT_BY_FIELD" && access.source == "GroupInput" && access.operation == "input-since"
        }));
        result.validate().unwrap();

        let err = compile(CKB_HEADER_EPOCH_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("target profile policy failed for 'spora'"), "unexpected error: {}", err.message);
        assert!(err.message.contains("CKB chain APIs require the 'ckb' target profile"), "unexpected error: {}", err.message);
    }

    #[test]
    fn ckb_constraints_surface_capacity_planning_for_created_outputs() {
        let source = r#"
module ckb_capacity_surface

resource Receipt {
    amount: u64,
}

action mint(amount: u64) -> Receipt {
    let receipt = create Receipt {
        amount: amount,
    };
    receipt
}
"#;
        let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        let ckb_constraints = result.metadata.constraints.ckb.as_ref().expect("ckb constraints metadata");

        assert_eq!(ckb_constraints.created_output_count, 1, "ckb constraints must count created outputs");
        assert_eq!(ckb_constraints.mutated_output_count, 0, "create-only action must not report mutated outputs");
        assert!(ckb_constraints.capacity_planning_required, "create outputs must mark capacity planning as required");
        assert!(
            ckb_constraints.occupied_capacity_measurement_required,
            "create outputs must require builder occupied-capacity measurement"
        );
        assert_eq!(ckb_constraints.capacity_status, "builder-occupied-capacity-measurement-required");
        assert_eq!(ckb_constraints.capacity_policy_surface, "builder/runtime-required; declarative-dsl-capacity-not-yet-first-class");
        assert!(ckb_constraints.capacity_evidence_contract.required);
        assert!(ckb_constraints.capacity_evidence_contract.occupied_capacity_measurement_required);
        assert!(ckb_constraints.capacity_evidence_contract.tx_size_measurement_required);
        assert!(ckb_constraints.capacity_evidence_contract.code_cell_lower_bound_shannons > 0);
    }

    #[test]
    fn ckb_deploy_manifest_surfaces_hash_type_and_dep_group_policy() {
        let dir = tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "deploy_manifest"
version = "0.1.0"
entry = "src/main.cell"

[build]
target_profile = "ckb"

[deploy.ckb]
hash_type = "data1"
out_point = "0x1111111111111111111111111111111111111111111111111111111111111111:0"
dep_type = "code"
data_hash = "0x2222222222222222222222222222222222222222222222222222222222222222"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x3333333333333333333333333333333333333333333333333333333333333333:1"
dep_type = "dep_group"
hash_type = "type"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.cell"),
            r#"
module deploy_manifest

action add(a: u64, b: u64) -> u64 {
    a + b
}
"#,
        )
        .unwrap();

        let result = compile_path(root, CompileOptions::default()).unwrap();
        let ckb = result.metadata.constraints.ckb.as_ref().expect("ckb constraints");
        assert_eq!(ckb.hash_type_policy.source, "Cell.toml deploy.ckb.hash_type");
        assert_eq!(ckb.hash_type_policy.declared_hash_type.as_deref(), Some("data1"));
        assert_eq!(ckb.hash_type_policy.status, "manifest-declared-builder-must-match");
        assert_eq!(ckb.dep_group_manifest.source, "Cell.toml deploy.ckb");
        assert!(ckb.dep_group_manifest.dep_group_supported);
        assert_eq!(ckb.dep_group_manifest.declared_cell_deps.len(), 2);
        assert!(ckb.dep_group_manifest.declared_cell_deps.iter().any(|dep| {
            dep.name == "primary"
                && dep.dep_type == "code"
                && dep.tx_hash.as_deref() == Some("0x1111111111111111111111111111111111111111111111111111111111111111")
                && dep.index == Some(0)
        }));
        assert!(ckb.dep_group_manifest.declared_cell_deps.iter().any(|dep| {
            dep.name == "secp256k1"
                && dep.dep_type == "dep_group"
                && dep.tx_hash.as_deref() == Some("0x3333333333333333333333333333333333333333333333333333333333333333")
                && dep.index == Some(1)
                && dep.hash_type.as_deref() == Some("type")
        }));
        assert_eq!(ckb.dep_group_manifest.status, "manifest-declares-dep-group-builder-must-expand-or-reference");
    }

    #[test]
    fn ckb_deploy_manifest_rejects_conflicting_cell_dep_locations() {
        let dir = tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "conflicting_cell_dep_location"
version = "0.1.0"
entry = "src/main.cell"

[build]
target_profile = "ckb"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
out_point = "0x3333333333333333333333333333333333333333333333333333333333333333:1"
tx_hash = "0x4444444444444444444444444444444444444444444444444444444444444444"
index = 2
dep_type = "dep_group"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.cell"),
            r#"
module conflicting_cell_dep_location

action add(a: u64, b: u64) -> u64 {
    a + b
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).expect_err("conflicting CKB cell_dep locations must fail closed");
        assert!(
            err.message.contains("CKB cell_dep location must use either out_point or tx_hash/index"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn ckb_deploy_manifest_rejects_incomplete_split_cell_dep_location() {
        let dir = tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "incomplete_cell_dep_location"
version = "0.1.0"
entry = "src/main.cell"

[build]
target_profile = "ckb"

[[deploy.ckb.cell_deps]]
name = "secp256k1"
tx_hash = "0x4444444444444444444444444444444444444444444444444444444444444444"
dep_type = "dep_group"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.cell"),
            r#"
module incomplete_cell_dep_location

action add(a: u64, b: u64) -> u64 {
    a + b
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).expect_err("incomplete CKB cell_dep split location must fail closed");
        assert!(
            err.message.contains("CKB cell_dep split location must provide both tx_hash and index"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn ckb_deploy_manifest_rejects_invalid_dep_type() {
        let dir = tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "bad_deploy_manifest"
version = "0.1.0"
entry = "src/main.cell"

[build]
target_profile = "ckb"

[deploy.ckb]
dep_type = "unknown"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.cell"),
            r#"
module bad_deploy_manifest

action add(a: u64, b: u64) -> u64 {
    a + b
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("unsupported CKB dep_type 'unknown'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn ckb_deploy_manifest_rejects_invalid_hash_type() {
        let dir = tempdir().unwrap();
        let root = Utf8Path::from_path(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "bad_hash_type_manifest"
version = "0.1.0"
entry = "src/main.cell"

[build]
target_profile = "ckb"

[deploy.ckb]
hash_type = "legacy"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src/main.cell"),
            r#"
module bad_hash_type_manifest

action add(a: u64, b: u64) -> u64 {
    a + b
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("unsupported CKB hash_type 'legacy'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn spora_constraints_surface_standard_mass_policy() {
        let source = r#"
module spora_mass_surface

action add(a: u64, b: u64) -> u64 {
    a + b
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let spora_constraints = result.metadata.constraints.spora.as_ref().expect("spora constraints metadata");

        assert_eq!(spora_constraints.max_block_mass, 2_000_000);
        assert_eq!(spora_constraints.max_standard_transaction_mass, 500_000);
        assert!(spora_constraints.fits_standard_transaction_mass_estimate);
        assert!(spora_constraints.fits_standard_block_mass_estimate);
        assert!(!spora_constraints.requires_relaxed_mass_policy);
        assert_eq!(spora_constraints.limits_source, "builtin-spora-standard-policy");
    }

    #[test]
    fn compile_lowers_ckb_group_source_large_immediate_to_riscv_elf() {
        let result = compile(
            CKB_HEADER_EPOCH_PROGRAM,
            CompileOptions {
                target: Some("riscv64-elf".to_string()),
                target_profile: Some("ckb".to_string()),
                ..CompileOptions::default()
            },
        )
        .unwrap();

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert_eq!(result.artifact_bytes.len(), crate::strip_vm_abi_trailer(&result.artifact_bytes).len());
        result.validate().unwrap();
    }

    #[test]
    fn ckb_target_profile_has_no_policy_exception() {
        let err = compile(
            r#"
module test

action main() -> u64 {
    return env::current_daa_score()
}
"#,
            CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
        )
        .unwrap_err();

        assert!(err.message.contains("target profile policy failed for 'ckb'"), "unexpected error: {}", err.message);
        assert!(err.message.contains("DAA/header assumptions are Spora-specific"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_prefers_no_arg_main_for_entry_wrapper() {
        let result = compile(
            r#"
module test

action needs_arg(value: u64) -> u64 {
    value
}

action main() -> u64 {
    0
}
"#,
            CompileOptions::default(),
        )
        .unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# cellscript entry abi: _cellscript_entry tail-calls no-arg main"), "missing entry wrapper:\n{}", asm);
        assert!(asm.contains("    j main"), "entry wrapper must tail-call main without clobbering ra:\n{}", asm);
        assert!(
            asm.find("_cellscript_entry:").unwrap() < asm.find("needs_arg:").unwrap(),
            "entry wrapper must precede actions:\n{}",
            asm
        );
    }

    #[test]
    fn compile_rejects_unknown_target_profile() {
        let err = compile(SIMPLE_PROGRAM, CompileOptions { target_profile: Some("unknown".to_string()), ..CompileOptions::default() })
            .unwrap_err();

        assert!(err.message.contains("unsupported target profile 'unknown'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_uses_ast_optimizer_for_nonzero_optimization_levels() {
        let baseline = compile(OPTIMIZER_PROGRAM, CompileOptions::default()).unwrap();
        let optimized = compile(OPTIMIZER_PROGRAM, CompileOptions { opt_level: 1, ..CompileOptions::default() }).unwrap();

        let baseline_asm = String::from_utf8(baseline.artifact_bytes).unwrap();
        let optimized_asm = String::from_utf8(optimized.artifact_bytes).unwrap();

        assert!(baseline_asm.contains("add t0, t0, t1"), "baseline assembly should still compute the expression");
        assert!(baseline_asm.contains("mul t0, t0, t1"), "baseline assembly should still compute the expression");
        assert!(optimized_asm.contains("li a0, 20"), "optimized assembly should fold the constant expression:\n{}", optimized_asm);
        assert!(!optimized_asm.contains("add t0, t0, t1"), "optimized assembly should not retain the folded add");
        assert!(!optimized_asm.contains("mul t0, t0, t1"), "optimized assembly should not retain the folded multiply");
    }

    #[test]
    fn compile_result_validation_rejects_tampered_artifact_hash() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.artifact_bytes.push(b'\n');

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("artifact_hash does not match artifact_bytes"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_elf_without_vm_abi_trailer() {
        let mut result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        result.artifact_bytes.truncate(result.artifact_bytes.len() - crate::VM_ABI_TRAILER_LEN);
        result.artifact_hash = *blake3::hash(&result.artifact_bytes).as_bytes();
        result.metadata.artifact_hash_blake3 = Some(crate::hex_encode(&result.artifact_hash));
        result.metadata.artifact_size_bytes = Some(result.artifact_bytes.len());

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("missing its VM ABI trailer"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_artifact_hash_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.artifact_hash_blake3 = Some("00".repeat(32));

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata artifact_hash_blake3"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_artifact_size_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.artifact_size_bytes = Some(result.artifact_bytes.len() + 1);

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata artifact_size_bytes"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_missing_metadata_artifact_size() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.artifact_size_bytes = None;

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata is missing artifact_size_bytes"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_artifact_format_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.artifact_format = ArtifactFormat::RiscvElf.display_name().to_string();

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata artifact_format"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_target_profile_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.target_profile.artifact_packaging = "ckb-elf-no-sporabi-trailer".to_string();

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata target_profile.artifact_packaging"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_assembly_with_vm_abi_trailer() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.artifact_bytes = crate::append_vm_abi_trailer(result.artifact_bytes, result.metadata.runtime.vm_abi.version);
        rebind_artifact_integrity_for_test(&mut result);

        let err = result.validate().unwrap_err();

        assert!(
            err.message.contains("RISC-V assembly artifacts must not embed a VM ABI trailer"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_result_validation_rejects_elf_vm_abi_trailer_version_mismatch() {
        let mut result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        let trailer_start = result.artifact_bytes.len() - crate::VM_ABI_TRAILER_LEN;
        result.artifact_bytes[trailer_start + 8..trailer_start + 10].copy_from_slice(&0x8002u16.to_le_bytes());
        rebind_artifact_integrity_for_test(&mut result);

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("ELF VM ABI trailer version"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_invalid_elf_vm_abi_trailer_flags() {
        let mut result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        let trailer_start = result.artifact_bytes.len() - crate::VM_ABI_TRAILER_LEN;
        result.artifact_bytes[trailer_start + 10] = 1;
        rebind_artifact_integrity_for_test(&mut result);

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("invalid VM ABI trailer"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_source_hash_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.source_hash_blake3 = Some("00".repeat(32));

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata source_hash_blake3"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_source_content_hash_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.source_content_hash_blake3 = Some("00".repeat(32));

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("metadata source_content_hash_blake3"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_file_source_content_hash_is_path_independent() {
        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let left_root = Utf8Path::from_path(left.path()).unwrap();
        let right_root = Utf8Path::from_path(right.path()).unwrap();
        let left_source = left_root.join("left.cell");
        let right_source = right_root.join("right.cell");
        std::fs::write(&left_source, SIMPLE_PROGRAM).unwrap();
        std::fs::write(&right_source, SIMPLE_PROGRAM).unwrap();

        let left_result = compile_file(&left_source, CompileOptions::default()).unwrap();
        let right_result = compile_file(&right_source, CompileOptions::default()).unwrap();

        assert_ne!(
            left_result.metadata.source_hash_blake3, right_result.metadata.source_hash_blake3,
            "path-bound source set hash must change when the same source lives at a different path"
        );
        assert_eq!(
            left_result.metadata.source_content_hash_blake3, right_result.metadata.source_content_hash_blake3,
            "path-independent source content hash must stay stable across equivalent source locations"
        );
    }

    #[test]
    fn compile_result_validation_rejects_metadata_schema_version_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.metadata_schema_version = crate::METADATA_SCHEMA_VERSION + 1;

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("unsupported metadata_schema_version"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_schema_downgrade() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.metadata_schema_version = crate::METADATA_SCHEMA_VERSION - 1;

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("unsupported metadata_schema_version"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_noncanonical_source_unit_hash() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.source_units[0].hash_blake3 = result.metadata.source_units[0].hash_blake3.to_uppercase();

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("expected 64 lowercase hex characters"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_type_id_hash_mismatch() {
        let program = r#"
module audit::type_id

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}
"#;
        let mut result = compile(program, CompileOptions::default()).unwrap();
        let token = result.metadata.types.iter_mut().find(|ty| ty.name == "Token").expect("Token type metadata");
        token.type_id_hash_blake3 = Some("00".repeat(32));

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("type_id_hash_blake3"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_duplicate_type_ids() {
        let program = r#"
module audit::type_id

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}

#[type_id("spora::asset::TokenSnapshot:v1")]
struct TokenSnapshot {
    amount: u64
}
"#;
        let mut result = compile(program, CompileOptions::default()).unwrap();
        let duplicate_hash = crate::hex_encode(blake3::hash(b"spora::asset::Token:v1").as_bytes());
        let snapshot = result.metadata.types.iter_mut().find(|ty| ty.name == "TokenSnapshot").expect("TokenSnapshot metadata");
        snapshot.type_id = Some("spora::asset::Token:v1".to_string());
        snapshot.type_id_hash_blake3 = Some(duplicate_hash);

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("declared by both"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_compiler_version_mismatch() {
        let mut result = compile(SIMPLE_PROGRAM, CompileOptions::default()).unwrap();
        result.metadata.compiler_version = "0.0.0-old".to_string();

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("compiler_version"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_validation_rejects_metadata_abi_embed_mismatch() {
        let mut result =
            compile(SIMPLE_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        result.metadata.runtime.vm_abi.embedded_in_artifact = false;

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("embedded_in_artifact"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_does_not_report_verified_collection_push_as_gap() {
        // The scalar push itself is verifier-covered for this local Vec path.
        // Collection construction/indexing still fail closed until their full
        // local runtime representation is executable.
        let collection_program = r#"
module test

action use_collection() -> u64 {
    let items = Vec::new()
    items.push(1)
    return items[0]
}
"#;
        let result =
            compile(collection_program, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() })
                .unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"collection-push".to_string()),
            "verified collection push should not be reported as a fail-closed runtime feature: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
    }

    #[test]
    fn compile_lowers_schema_backed_parameter_field_access_to_elf() {
        let result =
            compile(PARAM_FIELD_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() })
                .unwrap();

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert!(!result.metadata.runtime.symbolic_cell_runtime_required);
        assert!(result.metadata.runtime.legacy_symbolic_cell_runtime_features.is_empty());
    }

    #[test]
    fn compile_lowers_read_ref_schema_field_to_ckb_runtime_elf() {
        let result =
            compile(READ_REF_FIELD_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() })
                .unwrap();

        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert!(result.metadata.runtime.ckb_runtime_required);
        assert!(!result.metadata.runtime.standalone_runner_compatible);
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"read-cell-dep".to_string()));
        assert!(result.metadata.runtime.legacy_symbolic_cell_runtime_features.is_empty());
        assert!(result.metadata.runtime.fail_closed_runtime_features.is_empty());
    }

    #[test]
    fn compile_infers_and_validates_read_only_effects() {
        let result = compile(READ_ONLY_EFFECT_PROGRAM, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "inspect").expect("inspect metadata");

        assert_eq!(action.effect_class, "ReadOnly");
        assert!(action.ckb_runtime_features.contains(&"read-cell-dep".to_string()));
        assert!(action.fail_closed_runtime_features.is_empty());
    }

    #[test]
    fn compile_rejects_underdeclared_effect_annotations() {
        let err = compile(UNDERDECLARED_EFFECT_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("declared effect ReadOnly is too weak"), "unexpected error: {}", err.message);
        assert!(err.message.contains("inferred effect is Creating"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_impure_helper_functions() {
        let err = compile(IMPURE_FN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("pure function cannot contain 'read_ref'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_helper_functions_that_indirectly_call_impure_actions() {
        let err = compile(INDIRECT_IMPURE_FN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("pure function cannot call action 'issue'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_pure_functions_that_call_env_runtime_builtins() {
        let err = compile(FN_ENV_RUNTIME_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("pure function cannot call 'env::current_daa_score' runtime builtin"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_pure_functions_that_call_ckb_header_runtime_builtins() {
        let err = compile(FN_CKB_HEADER_RUNTIME_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("pure function cannot call 'ckb::header_epoch_number' runtime builtin"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_pure_functions_that_call_type_hash_runtime_builtin() {
        let err = compile(FN_TYPE_HASH_RUNTIME_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("pure function cannot call 'type_hash' Cell identity builtin"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_allows_actions_and_locks_to_call_pure_functions() {
        let action_result = compile(ACTION_CALLS_FN_PROGRAM, CompileOptions::default()).unwrap();
        assert!(action_result.metadata.functions.iter().any(|function| function.name == "add_one"));

        let lock_result = compile(LOCK_CALLS_FN_PROGRAM, CompileOptions::default()).unwrap();
        assert!(lock_result.metadata.functions.iter().any(|function| function.name == "yes"));
    }

    #[test]
    fn compile_normalizes_same_module_qualified_helper_calls() {
        let result = compile(QUALIFIED_ACTION_CALLS_FN_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();

        assert!(asm.contains("call add_one"), "qualified helper call was not normalized:\n{}", asm);
        assert!(!asm.contains("call test::add_one"), "qualified helper label leaked into assembly:\n{}", asm);
    }

    #[test]
    fn compile_rejects_function_call_argument_mismatches() {
        let err = compile(CALL_MISSING_ARGUMENT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("function 'add' expects 2 arguments, found 1"), "unexpected error: {}", err.message);

        let err = compile(CALL_TYPE_MISMATCH_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("function 'add' argument 2 type mismatch"), "unexpected error: {}", err.message);
        assert!(err.message.contains("expected u64, found bool"), "unexpected error: {}", err.message);

        let err = compile(QUALIFIED_CALL_EXTRA_ARGUMENT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("function 'test::add_one' expects 1 argument, found 2"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_unstable_callable_parameter_names() {
        let err = compile(DUPLICATE_ACTION_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate parameter 'x' in action 'bad'"), "unexpected error: {}", err.message);

        let err = compile(WILDCARD_ACTION_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("action 'bad' parameter must have a stable name"), "unexpected error: {}", err.message);

        let err = compile(DUPLICATE_FN_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate parameter 'x' in function 'bad'"), "unexpected error: {}", err.message);

        let err = compile(WILDCARD_LOCK_PARAM_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("lock 'owned' parameter must have a stable name"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_local_binding_name_reuse() {
        let err = compile(LOCAL_BINDING_REUSE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("binding 'x' already exists in this scope or an outer scope"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(TUPLE_BINDING_REUSE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("binding 'x' already exists in this scope or an outer scope"),
            "unexpected error: {}",
            err.message
        );

        let err = compile(BLOCK_BINDING_SHADOW_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("binding 'x' already exists in this scope or an outer scope"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_builtin_call_argument_mismatches() {
        let err = compile(BUILTIN_WRONG_ARITY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("env::current_daa_score expects 0 arguments, found 1"), "unexpected error: {}", err.message);

        let err = compile(NUMERIC_BUILTIN_TYPE_MISMATCH_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("min argument 2 must be numeric, found bool"), "unexpected error: {}", err.message);

        let err = compile(UNKNOWN_NAMESPACED_CONSTRUCTOR_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("unknown namespaced function 'Missing::new'"), "unexpected error: {}", err.message);

        let err = compile(METHOD_WRONG_ARITY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("len expects 0 arguments, found 1"), "unexpected error: {}", err.message);
    }

    #[test]
    fn ir_preserves_function_call_return_types() {
        let tokens = lexer::lex(BOOL_FN_CALL_PROGRAM).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let ir = ir::generate(&module).unwrap();
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::Action(action) if action.name == "run" => Some(action),
                _ => None,
            })
            .expect("run action");
        let call_dest = action
            .body
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find_map(|instruction| match instruction {
                ir::IrInstruction::Call { dest: Some(dest), func, .. } if func == "ready" => Some(dest),
                _ => None,
            })
            .expect("ready call");

        assert_eq!(call_dest.ty, ir::IrType::Bool);
    }

    #[test]
    fn ir_lowers_unit_function_calls_without_result_destinations() {
        let tokens = lexer::lex(UNIT_FN_CALL_PROGRAM).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let ir = ir::generate(&module).unwrap();
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::Action(action) if action.name == "run" => Some(action),
                _ => None,
            })
            .expect("run action");
        let call = action
            .body
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|instruction| matches!(instruction, ir::IrInstruction::Call { func, .. } if func == "note"))
            .expect("note call");

        assert!(matches!(call, ir::IrInstruction::Call { dest: None, .. }));
    }

    #[test]
    fn ir_rejects_unknown_call_return_types_without_u64_fallback() {
        let tokens = lexer::lex(UNKNOWN_FUNCTION_PROGRAM).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let err = ir::generate(&module).unwrap_err();

        assert!(err.message.contains("call 'missing' has no known return type"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_allows_unit_function_calls_as_statements() {
        let result = compile(UNIT_FN_CALL_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();

        assert!(asm.contains("call note"), "unit helper call was not emitted:\n{}", asm);
    }

    #[test]
    fn compile_rejects_binding_unit_function_results() {
        let err = compile(BIND_UNIT_FN_CALL_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("cannot bind the result of a function without a return value"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_returning_unit_function_results() {
        let err = compile(RETURN_UNIT_FN_CALL_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("return type mismatch"), "unexpected error: {}", err.message);
        assert!(err.message.contains("Unit"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_return_values_from_unit_actions() {
        let err = compile(RETURN_VALUE_FROM_UNIT_ACTION_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("return value is not allowed in a function without a return type"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_bare_return_from_value_actions() {
        let err = compile(BARE_RETURN_FROM_VALUE_ACTION_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("return without value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_missing_action_return_paths() {
        let err = compile(MISSING_ACTION_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("action 'bad' with a return type must return a value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_missing_function_return_paths() {
        let err = compile(MISSING_FUNCTION_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("function 'bad' with a return type must return a value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_lowers_tail_expr_as_action_return() {
        let result = compile(TAIL_EXPR_ACTION_RETURN_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();

        assert!(asm.contains("li a0, 1"), "tail expression was not lowered as the action return value:\n{}", asm);
    }

    #[test]
    fn compile_accepts_complete_branch_return_paths() {
        compile(BRANCH_COMPLETE_RETURN_PROGRAM, CompileOptions::default()).unwrap();
    }

    #[test]
    fn compile_tracks_linear_values_returned_from_complete_branches() {
        compile(LINEAR_BRANCH_RETURN_PROGRAM, CompileOptions::default()).unwrap();

        let err = compile(LINEAR_BRANCH_INCONSISTENT_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("linear resource 'token' has inconsistent ownership state across if branches"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_tracks_linear_values_returned_from_tail_if_branches() {
        compile(LINEAR_TAIL_IF_RETURN_PROGRAM, CompileOptions::default()).unwrap();

        let err = compile(LINEAR_TAIL_IF_INCONSISTENT_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("linear resource 'left' has inconsistent ownership state across if branches")
                || err.message.contains("linear resource 'right' has inconsistent ownership state across if branches"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_merges_linear_moves_inside_if_expressions() {
        compile(LINEAR_IF_EXPR_LET_MOVE_PROGRAM, CompileOptions::default()).unwrap();
        compile(LINEAR_IF_EXPR_STATEFUL_BRANCHES_PROGRAM, CompileOptions::default()).unwrap();

        let err = compile(LINEAR_IF_EXPR_INCONSISTENT_LET_MOVE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("linear resource 'left' has inconsistent ownership state across if branches")
                || err.message.contains("linear resource 'right' has inconsistent ownership state across if branches"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_tracks_linear_values_inside_aggregate_bindings() {
        compile(LINEAR_TUPLE_DESTRUCTURE_HANDLES_ITEMS_PROGRAM, CompileOptions::default()).unwrap();

        let tuple_err = compile(LINEAR_TUPLE_BINDING_DROPPED_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(tuple_err.message.contains("linear resource 'pair' was not consumed"), "unexpected error: {}", tuple_err.message);

        let array_err = compile(LINEAR_ARRAY_BINDING_DROPPED_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(array_err.message.contains("linear resource 'items' was not consumed"), "unexpected error: {}", array_err.message);

        let wildcard_err = compile(LINEAR_WILDCARD_DISCARD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            wildcard_err.message.contains("wildcard binding cannot discard a linear value"),
            "unexpected error: {}",
            wildcard_err.message
        );

        let tuple_wildcard_err = compile(LINEAR_TUPLE_WILDCARD_DISCARD_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            tuple_wildcard_err.message.contains("wildcard binding cannot discard a linear value"),
            "unexpected error: {}",
            tuple_wildcard_err.message
        );

        let field_err = compile(LINEAR_TUPLE_FIELD_PROJECTION_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            field_err.message.contains("field access cannot move a linear value out of an aggregate"),
            "unexpected error: {}",
            field_err.message
        );

        let index_err = compile(LINEAR_ARRAY_INDEX_PROJECTION_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            index_err.message.contains("index access cannot move a linear value out of an aggregate"),
            "unexpected error: {}",
            index_err.message
        );
    }

    #[test]
    fn compile_merges_linear_moves_inside_block_expressions() {
        compile(LINEAR_BLOCK_EXPR_LET_MOVE_PROGRAM, CompileOptions::default()).unwrap();
        compile(LINEAR_BLOCK_EXPR_PREFIX_MOVE_PROGRAM, CompileOptions::default()).unwrap();
        compile(LINEAR_BLOCK_EXPR_STATEFUL_PROGRAM, CompileOptions::default()).unwrap();

        let err = compile(LINEAR_BLOCK_EXPR_DROPPED_LOCAL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("linear resource 'out' was not consumed"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_lowers_block_tail_if_expressions() {
        let result = compile(BLOCK_TAIL_IF_VALUE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();
        assert!(asm.contains("li t0, 1"), "block tail-if then value was not lowered:\n{}", asm);
        assert!(asm.contains("li t0, 2"), "block tail-if else value was not lowered:\n{}", asm);
    }

    #[test]
    fn compile_merges_linear_moves_inside_block_tail_if_expressions() {
        compile(LINEAR_BLOCK_TAIL_IF_MOVE_PROGRAM, CompileOptions::default()).unwrap();

        let err = compile(LINEAR_BLOCK_TAIL_IF_INCONSISTENT_MOVE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("linear resource 'left' has inconsistent ownership state across if branches")
                || err.message.contains("linear resource 'right' has inconsistent ownership state across if branches"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_lowers_tail_if_as_action_return() {
        let result = compile(TAIL_IF_ACTION_RETURN_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();

        assert!(asm.contains("li a0, 1"), "tail if then branch was not lowered as return:\n{}", asm);
        assert!(asm.contains("li a0, 2"), "tail if else branch was not lowered as return:\n{}", asm);
    }

    #[test]
    fn compile_rejects_incomplete_branch_return_paths() {
        let err = compile(BRANCH_INCOMPLETE_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("action 'bad' with a return type must return a value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_unreachable_statements_after_return() {
        let err = compile(UNREACHABLE_AFTER_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("unreachable statement after guaranteed return"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_unreachable_statements_after_complete_branch_return() {
        let err = compile(UNREACHABLE_AFTER_BRANCH_RETURN_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("unreachable statement after guaranteed return"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_lowers_env_current_daa_score_as_ckb_runtime_call() {
        let result = compile(ENV_DAA_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();

        assert!(asm.contains("call __env_current_daa_score"), "env call was not lowered to CKB runtime helper:\n{}", asm);
        assert!(asm.contains("LOAD_HEADER_BY_FIELD field=daa_score"), "env runtime helper did not document header ABI:\n{}", asm);
        assert!(result.metadata.runtime.ckb_runtime_required);
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"load-header-daa-score".to_string()));
        assert!(!result.metadata.runtime.standalone_runner_compatible);
    }

    #[test]
    fn compile_verifies_create_output_against_daa_score_prelude() {
        let result = compile(ENV_DAA_CREATE_OUTPUT_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "DAA score and DAA + param output fields should be verifier-coverable: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            asm.contains("# cellscript abi: verify output field Clock.now offset=0 size=8"),
            "DAA output field was not verifier-covered:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected expression u64 Add"),
            "DAA + param output expression was not reconstructed in the verifier prelude:\n{}",
            asm
        );
    }

    #[test]
    fn compile_rejects_pure_functions_that_call_locks() {
        let err = compile(FN_CALLS_LOCK_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("pure function cannot call lock 'guard'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_underdeclared_effects_through_calls() {
        let err = compile(INDIRECT_UNDERDECLARED_EFFECT_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("declared effect ReadOnly is too weak"), "unexpected error: {}", err.message);
        assert!(err.message.contains("action 'wrapper'"), "unexpected error: {}", err.message);
        assert!(err.message.contains("inferred effect is Creating"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_underdeclared_effects_through_qualified_calls() {
        let err = compile(QUALIFIED_UNDERDECLARED_EFFECT_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("declared effect ReadOnly is too weak"), "unexpected error: {}", err.message);
        assert!(err.message.contains("action 'wrapper'"), "unexpected error: {}", err.message);
        assert!(err.message.contains("inferred effect is Creating"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_duplicate_lifecycle_states_on_main_path() {
        let err = compile(LIFECYCLE_DUPLICATE_STATE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("duplicate lifecycle state: Created"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_missing_lifecycle_state_create_on_main_path() {
        let err = compile(LIFECYCLE_MISSING_STATE_CREATE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("create of lifecycle receipt 'Ticket' must set its state field"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_bad_lifecycle_state_field_type_on_main_path() {
        let err = compile(LIFECYCLE_BAD_STATE_TYPE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("lifecycle receipt 'Ticket' state field must be an unsigned integer type"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_out_of_range_lifecycle_state_create_on_main_path() {
        let err = compile(LIFECYCLE_OUT_OF_RANGE_STATE_CREATE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("lifecycle state index 2 is out of range for 'Ticket' with 2 states"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_non_initial_lifecycle_create_without_consumed_prior_state() {
        let err = compile(LIFECYCLE_NON_INITIAL_CREATE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("initial create of lifecycle receipt 'Ticket' must use initial state index 0, got 1"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_dynamic_initial_lifecycle_create_state() {
        let err = compile(LIFECYCLE_DYNAMIC_INITIAL_CREATE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("initial create of lifecycle receipt 'Ticket' must use statically known initial state index 0"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_static_lifecycle_update_reset_to_initial_state() {
        let err = compile(LIFECYCLE_RESET_UPDATE_PROGRAM, CompileOptions::default()).unwrap_err();

        assert!(
            err.message.contains("lifecycle update of 'Ticket' cannot reset to initial state index 0"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_accepts_static_lifecycle_update_to_non_initial_state() {
        let result = compile(LIFECYCLE_STATIC_UPDATE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        let ticket = result.metadata.types.iter().find(|ty| ty.name == "Ticket").expect("Ticket type metadata");
        let action = result.metadata.actions.iter().find(|action| action.name == "activate").expect("activate metadata");

        assert_eq!(result.metadata.module, "test");
        assert_eq!(ticket.lifecycle_states, vec!["Created".to_string(), "Active".to_string()]);
        assert_eq!(ticket.lifecycle_transitions.len(), 1);
        assert_eq!(ticket.lifecycle_transitions[0].from, "Created");
        assert_eq!(ticket.lifecycle_transitions[0].to, "Active");
        assert_eq!(ticket.lifecycle_transitions[0].from_index, 0);
        assert_eq!(ticket.lifecycle_transitions[0].to_index, 1);
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "lifecycle-transition"
                && obligation.feature == "Ticket.state"
                && obligation.status == "checked-runtime"
        }));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.scope == "action:activate"
                && obligation.category == "lifecycle-transition"
                && obligation.feature == "Ticket.state"
                && obligation.status == "checked-runtime"
        }));
        assert!(
            asm.contains("# cellscript abi: lifecycle transition Ticket.state old+1"),
            "missing lifecycle runtime transition verifier:\n{}",
            asm
        );
        assert!(asm.contains("li a0, 7"), "missing lifecycle transition failure code in verifier:\n{}", asm);
        assert!(asm.contains("state_count=2"), "missing lifecycle state-count marker in verifier:\n{}", asm);
        assert!(asm.contains("li a0, 9"), "missing lifecycle old-state range failure code:\n{}", asm);
        assert!(asm.contains("li t3, 2"), "missing lifecycle output state range check:\n{}", asm);
        assert!(asm.contains("li a0, 8"), "missing lifecycle output state range failure code:\n{}", asm);
    }

    #[test]
    fn ir_carries_lifecycle_rules() {
        let tokens = lexer::lex(LIFECYCLE_STATIC_UPDATE_PROGRAM).unwrap();
        let ast = parser::parse(&tokens).unwrap();
        let module = ir::generate(&ast).unwrap();
        let ticket = module
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::TypeDef(type_def) if type_def.name == "Ticket" => Some(type_def),
                _ => None,
            })
            .expect("Ticket IR type");

        assert_eq!(ticket.lifecycle_rules.len(), 1);
        assert_eq!(ticket.lifecycle_rules[0].from, "Created");
        assert_eq!(ticket.lifecycle_rules[0].to, "Active");
        assert_eq!(ticket.lifecycle_rules[0].from_index, 0);
        assert_eq!(ticket.lifecycle_rules[0].to_index, 1);
    }

    #[test]
    fn compile_emits_elf_with_fail_closed_for_symbolic_collection_programs() {
        let result =
            compile(VEC_BUILTIN_PROGRAM, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() })
                .unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
        assert!(result.metadata.runtime.fail_closed_runtime_features.iter().any(|f| f.starts_with("collection-")));
    }

    #[test]
    fn load_modules_for_input_collects_package_source_roots() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("shared")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
source_roots = ["src", "shared"]
"#,
        )
        .unwrap();
        std::fs::write(root.join("src/main.cell"), "module demo::main\naction ping() -> u64 { 1 }\n").unwrap();
        std::fs::write(root.join("shared/types.cell"), "module demo::types\nstruct Pair { left: u64, right: u64 }\n").unwrap();

        let modules = load_modules_for_input(root).unwrap();
        assert_eq!(modules.len(), 2);
    }

    #[test]
    fn ir_summary_captures_cell_runtime_accesses() {
        let tokens = lexer::lex(SUMMARY_PROGRAM).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let ir = ir::generate(&module).unwrap();
        let action = ir
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::Action(action) if action.name == "update" => Some(action),
                _ => None,
            })
            .expect("update action");

        assert_eq!(action.body.read_refs.len(), 1);
        assert_eq!(action.body.create_set.len(), 1);
        assert_eq!(action.body.consume_set.len(), 1);
        assert_eq!(action.body.read_refs[0].binding, "read_ref_Config");
        assert_eq!(action.body.create_set[0].ty, "Token");
        assert!(!action.scheduler_hints.touches_shared.is_empty());
        assert!(action.scheduler_hints.estimated_cycles > 32);
    }

    #[test]
    fn compile_rejects_non_bool_lock_definitions() {
        let err = compile(BAD_LOCK_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("lock definitions must return bool"));
    }

    #[test]
    fn compile_rejects_state_transitions_inside_locks() {
        let err = compile(LOCK_CREATE_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("lock cannot contain 'create' Cell state transition"), "unexpected error: {}", err.message);

        let err = compile(LOCK_DESTROY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("lock cannot contain 'destroy' Cell state transition"), "unexpected error: {}", err.message);

        compile(LOCK_READ_REF_PROGRAM, CompileOptions::default()).unwrap();
    }

    #[test]
    fn compile_preserves_transfer_claim_settle_instructions_in_assembly() {
        let result = compile(TRANSFER_CLAIM_SETTLE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(asm.contains("# transfer"), "transfer expression vanished from assembly:\n{}", asm);
        assert!(asm.contains("# claim"), "claim expression vanished from assembly:\n{}", asm);
        assert!(asm.contains("# settle"), "settle expression vanished from assembly:\n{}", asm);
        assert!(
            !asm.contains("# cellscript abi: transfer symbolic runtime is not executable"),
            "verifier-covered transfer should not use the symbolic fail-closed path:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: transfer output relation verified by prelude Output#0"),
            "transfer expression did not reuse the verifier-covered output relation:\n{}",
            asm
        );
        assert!(asm.contains("# transfer output Token"), "transfer-created output was not represented as an Output access:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: expected field Token.amount offset=0 size=8"),
            "transfer-created output amount was not bound to the consumed token field:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=output_lock_hash source=Output index=0 field=3"),
            "transfer-created output lock was not loaded for destination rebinding:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output lock hash offset=0 size=32"),
            "transfer-created output lock hash was not checked:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: claim symbolic runtime is not executable"),
            "verifier-covered claim output should not use the symbolic fail-closed path:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_WITNESS reason=claim_witness source=GroupInput index=0"),
            "claim did not load the grouped input witness before fail-closing signature verification:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: claim witness signature length check accepted=65|66"),
            "claim did not validate the recoverable signature witness envelope:\n{}",
            asm
        );
        assert!(
            asm.contains(
                "# cellscript abi: LOAD_ECDSA_SIGNATURE_HASH reason=claim_authorization_domain source=GroupInput index=0 hash_type=t3"
            ),
            "claim did not bind authorization-domain separation through the ECDSA sighash syscall:\n{}",
            asm
        );
        assert!(asm.contains("# claim output Token"), "claim-created output was not represented as an Output access:\n{}", asm);
        assert!(
            asm.contains("# cellscript abi: verify output field Token.amount offset=0 size=8"),
            "claim-created output amount was not verifier-covered:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected field VestingReceipt.amount offset=0 size=8"),
            "claim-created output amount was not bound to the consumed receipt field:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: claim output relation verified by prelude Output#0"),
            "claim expression did not reuse the verifier-covered output relation:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: settle symbolic runtime is not executable"),
            "verifier-covered settle output should not use the symbolic fail-closed path:\n{}",
            asm
        );
        assert!(asm.contains("# settle output Token"), "settle-created output was not represented as an Output access:\n{}", asm);
        assert!(
            asm.matches("# cellscript abi: expected field Token.amount offset=0 size=8").count() >= 2,
            "transfer/settle output amount checks were not both bound to consumed token fields:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: settle output relation verified by prelude Output#0"),
            "settle expression did not reuse the verifier-covered output relation:\n{}",
            asm
        );
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"transfer-expression".to_string()),
            "verifier-covered transfer should not be marked fail-closed: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"claim-expression".to_string()),
            "verifier-covered claim output should not be marked fail-closed: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"settle-expression".to_string()),
            "verifier-covered settle output should not be marked fail-closed: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(!result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "runtime-fail-closed"
                && matches!(obligation.feature.as_str(), "transfer-expression" | "claim-expression" | "settle-expression")
        }));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "resource-operation"
                && obligation.feature == "transfer:Token"
                && obligation.status == "checked-static"
        }));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "resource-operation"
                && obligation.feature == "claim:VestingReceipt"
                && obligation.status == "checked-static"
        }));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "resource-operation"
                && obligation.feature == "settle:Token"
                && obligation.status == "checked-static"
        }));
        let has_checked_input_data = |scope: &str, feature: &str, component: &str, binding: &str, abi: &str| {
            result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.scope == scope
                    && requirement.feature == feature
                    && requirement.status == "checked-runtime"
                    && requirement.component == component
                    && requirement.source == "Input"
                    && requirement.binding == binding
                    && requirement.field.as_deref() == Some("data")
                    && requirement.abi == abi
                    && requirement.blocker.is_none()
                    && requirement.blocker_class.is_none()
            })
        };
        assert!(has_checked_input_data(
            "action:move_token",
            "transfer-input:Token:token",
            "transfer-input-data",
            "token",
            "transfer-load-cell-input"
        ));
        assert!(has_checked_input_data(
            "action:redeem",
            "claim-input:VestingReceipt:receipt",
            "claim-input-data",
            "receipt",
            "claim-load-cell-input"
        ));
        assert!(has_checked_input_data(
            "action:finalize",
            "settle-input:Token:token",
            "settle-input-data",
            "token",
            "settle-load-cell-input"
        ));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "transfer-output:Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("transfer-output-relation=checked-runtime")
                && obligation.detail.contains("transfer-lock-rebinding=checked-runtime")
                && obligation.detail.contains("transfer-destination-address-binding=checked-runtime")
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "transfer-output:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "transfer-output-relation"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("output-relation")
                && requirement.abi == "transfer-output-relation-consume-create-accounting"
                && requirement.byte_len.is_none()
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "transfer-output:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "transfer-destination-lock"
                && requirement.source == "Output"
                && requirement.field.as_deref() == Some("lock_hash")
                && requirement.abi == "transfer-destination-lock-hash-32"
                && requirement.byte_len == Some(32)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "transfer-output:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "transfer-destination-address"
                && requirement.source == "Param"
                && requirement.field.as_deref() == Some("destination")
                && requirement.abi == "transfer-destination-address-32"
                && requirement.byte_len == Some(32)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        let claim_conditions = result
            .metadata
            .runtime
            .verifier_obligations
            .iter()
            .find(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "claim-conditions:VestingReceipt"
                    && obligation.status == "runtime-required"
            })
            .expect("claim conditions obligation");
        assert!(
            claim_conditions.detail.contains("Input#0:receipt.amount=input-cell-field-u64[8]"),
            "claim conditions should expose field-aware receipt input requirements: {}",
            claim_conditions.detail
        );
        assert!(
            claim_conditions.detail.contains("claim-witness-format=checked-runtime")
                && claim_conditions.detail.contains("claim-authorization-domain=checked-runtime"),
            "claim conditions should mark witness format and authorization domain as runtime-checked subconditions: {}",
            claim_conditions.detail
        );
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:VestingReceipt"
                && requirement.status == "runtime-required"
                && requirement.component == "claim-witness-signature"
                && requirement.source == "Witness"
                && requirement.field.as_deref() == Some("signature")
                && requirement.abi == "claim-witness-signature-65"
                && requirement.byte_len == Some(65)
                && requirement.blocker.as_deref()
                    == Some(
                        "claim lowering checks witness shape but has no verifier-coverable signer key binding or secp256k1 verification call"
                    )
                && requirement.blocker_class.as_deref() == Some("witness-verification-gap")
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:VestingReceipt"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-authorization-domain"
                && requirement.source == "Witness"
                && requirement.field.as_deref() == Some("authorization-domain")
                && requirement.abi == "claim-witness-authorization-domain"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:VestingReceipt"
                && requirement.status == "runtime-required"
                && requirement.component == "claim-time-context"
                && requirement.source == "Header"
                && requirement.field.as_deref() == Some("daa_score")
                && requirement.abi == "claim-time-daa-score-u64"
                && requirement.byte_len == Some(8)
                && requirement.blocker.as_deref() == Some("claim lowering has no checked source DAA/time predicate for this receipt")
                && requirement.blocker_class.as_deref() == Some("time-context-predicate-gap")
        }));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "claim-output:Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("claim-output-relation=checked-runtime")
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-output:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-output-relation"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("output-relation")
                && requirement.abi == "claim-output-relation-consume-create-accounting"
                && requirement.byte_len.is_none()
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(!result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "claim-output:Token"
                && obligation.status == "runtime-required"
        }));
        let settle_finalization = result
            .metadata
            .runtime
            .verifier_obligations
            .iter()
            .find(|obligation| {
                obligation.category == "transaction-invariant"
                    && obligation.feature == "settle-finalization:Token"
                    && obligation.status == "runtime-required"
            })
            .expect("settle finalization obligation");
        assert!(
            settle_finalization.detail.contains("Input#0:token.amount=input-cell-field-u64[8]"),
            "settle finalization should expose field-aware token input requirements: {}",
            settle_finalization.detail
        );
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "settle-finalization:Token"
                && requirement.status == "runtime-required"
                && requirement.component == "settle-final-state-context"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("pending-to-final-state")
                && requirement.abi == "settle-finalization-state-context"
                && requirement.blocker.as_deref() == Some("settle lowering does not encode final-state transition policy")
                && requirement.blocker_class.as_deref() == Some("finalization-policy-gap")
        }));
        assert!(result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "settle-output:Token"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("settle-output-relation=checked-runtime")
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "settle-output:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "settle-output-relation"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("output-relation")
                && requirement.abi == "settle-output-relation-consume-create-accounting"
                && requirement.byte_len.is_none()
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(result.metadata.runtime.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "settle-finalization:Token"
                && requirement.status == "checked-runtime"
                && requirement.component == "settle-output-admission"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("grouped-output-admission")
                && requirement.abi == "settle-finalization-output-admission"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(!result.metadata.runtime.verifier_obligations.iter().any(|obligation| {
            obligation.category == "transaction-invariant"
                && obligation.feature == "settle-output:Token"
                && obligation.status == "runtime-required"
        }));
    }

    #[test]
    fn claim_and_settle_output_relation_gaps_are_transaction_inputs() {
        let result = compile(CLAIM_SETTLE_UNSUPPORTED_OUTPUT_RELATION_PROGRAM, CompileOptions::default()).unwrap();
        let redeem = result.metadata.actions.iter().find(|action| action.name == "redeem").expect("redeem metadata");
        let finalize = result.metadata.actions.iter().find(|action| action.name == "finalize").expect("finalize metadata");

        assert!(
            redeem.fail_closed_runtime_features.contains(&"claim-expression".to_string())
                && redeem.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "unsupported claim output relation should remain fail-closed: {:?}",
            redeem.fail_closed_runtime_features
        );
        assert!(
            redeem.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "claim-output:Token"
                    && requirement.status == "runtime-required"
                    && requirement.component == "claim-output-relation"
                    && requirement.source == "Transaction"
                    && requirement.field.as_deref() == Some("output-relation")
                    && requirement.abi == "claim-output-relation-consume-create-accounting"
                    && requirement.blocker.as_deref() == Some("claim-created output relation is not fully verifier-covered")
                    && requirement.blocker_class.as_deref() == Some("claim-output-relation-gap")
            }),
            "unsupported claim output relation should expose a transaction input blocker: {:?}",
            redeem.transaction_runtime_input_requirements
        );

        assert!(
            finalize.fail_closed_runtime_features.contains(&"settle-expression".to_string())
                && finalize.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "unsupported settle output relation should remain fail-closed: {:?}",
            finalize.fail_closed_runtime_features
        );
        assert!(
            finalize.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "settle-output:Token"
                    && requirement.status == "runtime-required"
                    && requirement.component == "settle-output-relation"
                    && requirement.source == "Transaction"
                    && requirement.field.as_deref() == Some("output-relation")
                    && requirement.abi == "settle-output-relation-consume-create-accounting"
                    && requirement.blocker.as_deref() == Some("settle-created output relation is not fully verifier-covered")
                    && requirement.blocker_class.as_deref() == Some("settle-output-relation-gap")
            }),
            "unsupported settle output relation should expose a transaction input blocker: {:?}",
            finalize.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn settle_lifecycle_final_state_field_is_checked_runtime() {
        let result = compile(SETTLE_LIFECYCLE_FINAL_STATE_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        assert!(
            asm.contains("# cellscript abi: settle final-state Settlement.state final_state=1 state_count=2"),
            "settle did not emit the lifecycle final-state verifier check:\n{}",
            asm
        );

        let finalize = result.metadata.actions.iter().find(|action| action.name == "finalize").expect("finalize metadata");
        let settle_finalization = finalize
            .verifier_obligations
            .iter()
            .find(|obligation| obligation.feature == "settle-finalization:Settlement")
            .expect("settle finalization obligation");
        assert_eq!(
            settle_finalization.status, "checked-runtime",
            "fully verifier-covered lifecycle settle finalization should be checked: {}",
            settle_finalization.detail
        );
        assert!(
            settle_finalization.detail.contains("settle-final-state=checked-runtime")
                && settle_finalization.detail.contains("settle-state-policy=lifecycle-final-state")
                && settle_finalization.detail.contains("settle-output-admission=checked-runtime"),
            "settle finalization should expose checked lifecycle final-state and output admission policy: {}",
            settle_finalization.detail
        );
        assert!(finalize.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "settle-finalization:Settlement"
                && requirement.status == "checked-runtime"
                && requirement.component == "settle-final-state-context"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("pending-to-final-state")
                && requirement.abi == "settle-finalization-state-context"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(finalize.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "settle-finalization:Settlement"
                && requirement.status == "checked-runtime"
                && requirement.component == "settle-output-admission"
                && requirement.source == "Transaction"
                && requirement.field.as_deref() == Some("grouped-output-admission")
                && requirement.abi == "settle-finalization-output-admission"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
    }

    #[test]
    fn claim_with_pubkey_hash_field_emits_secp256k1_verification() {
        let result = compile(CLAIM_SIGNER_PUBKEY_HASH_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        assert!(
            asm.contains(
                "# cellscript abi: SECP256K1_VERIFY reason=claim_signature source=Input field=SignedReceipt.signer_pubkey_hash witness=GroupInput index=0"
            ),
            "claim signature verification was not lowered:\n{}",
            asm
        );
        assert!(asm.contains("li a7, 3002"), "claim signature verification did not call secp256k1 syscall:\n{}", asm);

        let action = result.metadata.actions.iter().find(|action| action.name == "redeem_signed").expect("redeem_signed metadata");
        assert!(action.ckb_runtime_features.contains(&"verify-claim-secp256k1-signature".to_string()));
        assert!(action.ckb_runtime_accesses.iter().any(|access| {
            access.operation == "claim-signature" && access.syscall == "SECP256K1_VERIFY" && access.source == "Witness"
        }));
        let claim_conditions = action
            .verifier_obligations
            .iter()
            .find(|obligation| {
                obligation.category == "transaction-invariant" && obligation.feature == "claim-conditions:SignedReceipt"
            })
            .expect("claim conditions obligation");
        assert_eq!(
            claim_conditions.status, "checked-runtime",
            "signed receipt claim conditions should be fully checked for the explicit signer-field ABI: {}",
            claim_conditions.detail
        );
        assert!(
            claim_conditions.detail.contains("claim-witness-signature=checked-runtime")
                && claim_conditions.detail.contains("claim-signer-key-binding=checked-runtime")
                && claim_conditions.detail.contains("claim-authorization-domain=checked-runtime")
                && claim_conditions.detail.contains("Input#0:receipt.signer_pubkey_hash=input-cell-field-bytes-20[20]"),
            "claim conditions should expose checked signature verification and signer key binding: {}",
            claim_conditions.detail
        );
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:SignedReceipt"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-witness-signature"
                && requirement.source == "Witness"
                && requirement.field.as_deref() == Some("signature")
                && requirement.abi == "claim-witness-signature-65"
                && requirement.byte_len == Some(65)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:SignedReceipt"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-authorization-domain"
                && requirement.source == "Witness"
                && requirement.field.as_deref() == Some("authorization-domain")
                && requirement.abi == "claim-witness-authorization-domain"
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        assert!(
            !action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "claim-conditions:SignedReceipt" && requirement.component == "claim-time-context"
            }),
            "plain signed receipts without a time predicate should not expose a runtime-required claim-time-context"
        );
    }

    #[test]
    fn compile_rejects_spora_claim_signature_helpers_under_ckb_profile() {
        let err = compile(
            CLAIM_SIGNER_PUBKEY_HASH_PROGRAM,
            CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() },
        )
        .unwrap_err();

        assert!(err.message.contains("target profile policy failed for 'ckb'"), "unexpected error: {}", err.message);
        assert!(err.message.contains("Spora-only claim helper syscall features"), "unexpected error: {}", err.message);
        assert!(err.message.contains("load-claim-ecdsa-signature-hash"), "unexpected error: {}", err.message);
        assert!(err.message.contains("verify-claim-secp256k1-signature"), "unexpected error: {}", err.message);
    }

    #[test]
    fn signer_backed_claim_with_source_predicate_is_now_checked() {
        let result = compile(CLAIM_SIGNER_WITH_TIME_PREDICATE_PROGRAM, CompileOptions::default()).unwrap();
        let action = result
            .metadata
            .actions
            .iter()
            .find(|action| action.name == "redeem_signed_after_cliff")
            .expect("redeem_signed_after_cliff metadata");
        let claim_conditions = action
            .verifier_obligations
            .iter()
            .find(|obligation| {
                obligation.category == "transaction-invariant" && obligation.feature == "claim-conditions:SignedVestingReceipt"
            })
            .expect("claim conditions obligation");

        // DAA cliff comparison is now verifier-coverable via LOAD_HEADER_BY_FIELD + slt,
        // and all source predicates have corresponding checked guards.
        assert_eq!(
            claim_conditions.status, "checked-runtime",
            "signed receipts with DAA cliff predicates are now fully checked: {}",
            claim_conditions.detail
        );
        assert!(
            claim_conditions.detail.contains("daa-cliff-reached=checked-runtime")
                && claim_conditions.detail.contains("claim-witness-signature=checked-runtime")
                && claim_conditions.detail.contains("claim-signer-key-binding=checked-runtime")
                && claim_conditions.detail.contains("Input#0:receipt.cliff_daa=input-cell-field-u64[8]"),
            "claim conditions should expose all checked subconditions: {}",
            claim_conditions.detail
        );
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:SignedVestingReceipt"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-witness-signature"
                && requirement.source == "Witness"
                && requirement.field.as_deref() == Some("signature")
                && requirement.abi == "claim-witness-signature-65"
                && requirement.byte_len == Some(65)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        // claim-time-context is now checked-runtime (DAA cliff is verifier-coverable)
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "claim-conditions:SignedVestingReceipt"
                && requirement.status == "checked-runtime"
                && requirement.component == "claim-time-context"
                && requirement.source == "Header"
                && requirement.field.as_deref() == Some("daa_score")
                && requirement.abi == "claim-time-daa-score-u64"
                && requirement.byte_len == Some(8)
                && requirement.blocker.is_none()
                && requirement.blocker_class.is_none()
        }));
        // claim-source-predicate no longer appears as runtime-required
        // because all source predicates have checked guards.
        assert!(
            !action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "claim-conditions:SignedVestingReceipt" && requirement.component == "claim-source-predicate"
            }),
            "claim-source-predicate should not appear when all source predicates have checked guards"
        );
    }

    #[test]
    fn ir_summary_captures_transfer_and_claim_consumes() {
        let tokens = lexer::lex(TRANSFER_CLAIM_SETTLE_PROGRAM).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let ir = ir::generate(&module).unwrap();

        let transfer_action = ir
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::Action(action) if action.name == "move_token" => Some(action),
                _ => None,
            })
            .expect("move_token action");
        assert_eq!(transfer_action.body.consume_set.len(), 1);
        assert_eq!(transfer_action.body.create_set.len(), 1);
        assert_eq!(transfer_action.body.consume_set[0].binding, "token");
        assert_eq!(transfer_action.body.consume_set[0].operation, "transfer");
        assert_eq!(transfer_action.body.create_set[0].ty, "Token");
        assert_eq!(transfer_action.body.create_set[0].operation, "transfer");
        assert_eq!(transfer_action.body.create_set[0].fields.len(), 1);
        assert_eq!(transfer_action.body.create_set[0].fields[0].0, "amount");
        assert!(
            transfer_action.body.create_set[0].lock.is_some(),
            "transfer-created output should carry the destination lock operand"
        );
        assert_eq!(transfer_action.body.write_intents.len(), 1);
        assert_eq!(transfer_action.body.write_intents[0].operation, "transfer");
        assert_eq!(transfer_action.body.write_intents[0].ty, "Token");
        assert_eq!(transfer_action.body.write_intents[0].source, ir::WriteIntentSource::Output);

        let claim_action = ir
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::Action(action) if action.name == "redeem" => Some(action),
                _ => None,
            })
            .expect("redeem action");
        assert_eq!(claim_action.body.consume_set.len(), 1);
        assert_eq!(claim_action.body.consume_set[0].binding, "receipt");
        assert_eq!(claim_action.body.consume_set[0].operation, "claim");
        assert_eq!(claim_action.body.create_set.len(), 1);
        assert_eq!(claim_action.body.create_set[0].ty, "Token");
        assert_eq!(claim_action.body.create_set[0].operation, "claim");
        assert_eq!(claim_action.body.create_set[0].fields.len(), 1);
        assert_eq!(claim_action.body.create_set[0].fields[0].0, "amount");
        assert_eq!(claim_action.body.write_intents.len(), 1);
        assert_eq!(claim_action.body.write_intents[0].operation, "claim");

        let settle_action = ir
            .items
            .iter()
            .find_map(|item| match item {
                ir::IrItem::Action(action) if action.name == "finalize" => Some(action),
                _ => None,
            })
            .expect("finalize action");
        assert_eq!(settle_action.body.consume_set.len(), 1);
        assert_eq!(settle_action.body.consume_set[0].binding, "token");
        assert_eq!(settle_action.body.consume_set[0].operation, "settle");
        assert_eq!(settle_action.body.create_set.len(), 1);
        assert_eq!(settle_action.body.create_set[0].ty, "Token");
        assert_eq!(settle_action.body.create_set[0].operation, "settle");
        assert_eq!(settle_action.body.create_set[0].fields.len(), 1);
        assert_eq!(settle_action.body.create_set[0].fields[0].0, "amount");
        assert_eq!(settle_action.body.write_intents.len(), 1);
        assert_eq!(settle_action.body.write_intents[0].operation, "settle");
    }

    #[test]
    fn transfer_claim_settle_output_fields_expose_fixed_byte_preservation() {
        let result = compile(TRANSFER_CLAIM_SETTLE_NON_SCALAR_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "fixed-byte transfer/claim/settle output fields should now be verifier-coverable: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            asm.contains("# cellscript abi: verify output bytes field Token.owner offset=8 size=32"),
            "fixed-byte owner field preservation was not emitted in assembly:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: expected bytes field Token.owner offset=8 size=32")
                || asm.contains("# cellscript abi: expected bytes field VestingReceipt.owner offset=8 size=32"),
            "fixed-byte expected source field was not emitted in assembly:\n{}",
            asm
        );
        for action_name in ["move_token", "redeem", "finalize"] {
            let action = result.metadata.actions.iter().find(|action| action.name == action_name).expect("action metadata");
            assert!(
                !action.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
                "{} should not expose incomplete output verification for fixed-byte field preservation: {:?}",
                action_name,
                action.fail_closed_runtime_features
            );
        }
        let redeem = result.metadata.actions.iter().find(|action| action.name == "redeem").expect("redeem metadata");
        let claim_conditions = redeem
            .verifier_obligations
            .iter()
            .find(|obligation| obligation.feature == "claim-conditions:VestingReceipt")
            .expect("redeem claim conditions obligation");
        assert!(
            claim_conditions.detail.contains("Input#0:receipt.owner=input-cell-field-bytes-32[32]"),
            "claim conditions should expose fixed-byte receipt input requirements: {}",
            claim_conditions.detail
        );
        let finalize = result.metadata.actions.iter().find(|action| action.name == "finalize").expect("finalize metadata");
        let settle_finalization = finalize
            .verifier_obligations
            .iter()
            .find(|obligation| obligation.feature == "settle-finalization:Token")
            .expect("finalize settle finalization obligation");
        assert!(
            settle_finalization.detail.contains("Input#0:token.owner=input-cell-field-bytes-32[32]"),
            "settle finalization should expose fixed-byte token input requirements: {}",
            settle_finalization.detail
        );

        let tokens = lexer::lex(TRANSFER_CLAIM_SETTLE_NON_SCALAR_FIELD_PROGRAM).unwrap();
        let module = parser::parse(&tokens).unwrap();
        let ir = ir::generate(&module).unwrap();

        for action_name in ["move_token", "redeem", "finalize"] {
            let action = ir
                .items
                .iter()
                .find_map(|item| match item {
                    ir::IrItem::Action(action) if action.name == action_name => Some(action),
                    _ => None,
                })
                .expect("action");
            assert_eq!(action.body.create_set.len(), 1, "{} should produce one output access", action_name);
            let fields = action.body.create_set[0].fields.iter().map(|(field, _)| field.as_str()).collect::<Vec<_>>();
            assert_eq!(fields, vec!["amount", "owner"], "{} should preserve scalar and fixed-byte fields", action_name);
            if action_name == "move_token" {
                assert!(action.body.create_set[0].lock.is_some(), "transfer output should preserve destination lock binding");
            }
        }
    }

    #[test]
    fn create_output_verifier_accepts_fixed_byte_params_and_consts() {
        let result = compile(FIXED_BYTE_PARAM_AND_CONST_OUTPUT_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "fixed-byte parameter and constant output fields should be verifier-coverable: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            asm.contains("# cellscript abi: verify output bytes field Config.symbol offset=0 size=8 against stack slot"),
            "fixed-byte stack parameter verification was not emitted:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output bytes field Fingerprint.digest offset=0 size=32 against const"),
            "fixed-byte constant verification was not emitted:\n{}",
            asm
        );

        for action_name in ["make_config", "make_fingerprint"] {
            let action = result.metadata.actions.iter().find(|action| action.name == action_name).expect("action metadata");
            assert!(
                !action.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
                "{} should not expose incomplete output verification for fixed-byte parameter/constant fields: {:?}",
                action_name,
                action.fail_closed_runtime_features
            );
        }
    }

    #[test]
    fn create_output_verifier_accepts_const_lock_hash() {
        let result = compile(CONST_LOCK_OUTPUT_PROGRAM, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();

        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-verification-incomplete".to_string()),
            "constant lock create should keep output fields verifier-coverable: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            !result.metadata.runtime.fail_closed_runtime_features.contains(&"output-lock-verification-incomplete".to_string()),
            "constant lock create should verify output lock hash instead of reporting a lock obligation: {:?}",
            result.metadata.runtime.fail_closed_runtime_features
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_CELL_BY_FIELD reason=output_lock_hash source=Output index=0 field=3"),
            "output lock hash syscall was not emitted:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output lock hash offset=0 size=32"),
            "output lock hash byte verification was not emitted:\n{}",
            asm
        );
        assert!(
            !asm.contains("# cellscript abi: output lock verification incomplete for this create pattern"),
            "constant output lock should not fail closed as incomplete:\n{}",
            asm
        );
    }

    #[test]
    fn compile_rejects_transfer_without_transfer_capability() {
        let err = compile(MISSING_TRANSFER_CAPABILITY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("does not declare 'transfer' capability"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_destroy_without_destroy_capability() {
        let err = compile(MISSING_DESTROY_CAPABILITY_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("does not declare 'destroy' capability"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_claim_on_non_receipt_values() {
        let err = compile(CLAIM_NON_RECEIPT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("claim requires a receipt value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_non_cell_receipt_claim_outputs() {
        let err = compile(CLAIM_OUTPUT_NON_CELL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(
            err.message.contains("receipt claim output must be a cell-backed resource or shared type"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_rejects_receipt_to_receipt_claim_outputs() {
        let err = compile(CLAIM_OUTPUT_RECEIPT_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("receipt claim output must not be another receipt"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_settle_on_non_cell_values() {
        let err = compile(SETTLE_NON_CELL_PROGRAM, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("settle requires a cell-backed linear value"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_result_exposes_scheduler_metadata_sidecar() {
        let result = compile(SUMMARY_PROGRAM, CompileOptions::default()).unwrap();
        assert_eq!(result.metadata.module, "test");
        assert_eq!(result.metadata.runtime.vm_version, "VERSION2");
        assert!(
            !result.metadata.runtime.symbolic_cell_runtime_required,
            "consume/create/read_ref now have real verifier lowering, not symbolic"
        );
        assert!(result.metadata.runtime.ckb_runtime_required);
        assert!(result.metadata.runtime.ckb_runtime_features.contains(&"read-cell-dep".to_string()));
        assert!(!result.metadata.runtime.legacy_symbolic_cell_runtime_features.contains(&"read-ref-expression".to_string()));
        assert!(!result.metadata.runtime.legacy_symbolic_cell_runtime_features.contains(&"schema-field-access".to_string()));
        assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| access.source == "Input"));
        assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| access.source == "CellDep"));
        assert!(result.metadata.runtime.ckb_runtime_accesses.iter().any(|access| access.source == "Output"));
        assert!(result.metadata.runtime.fail_closed_runtime_features.is_empty());
        let action = result.metadata.actions.iter().find(|action| action.name == "update").expect("update metadata");
        assert_eq!(action.read_refs.len(), 1);
        assert_eq!(action.create_set.len(), 1);
        assert_eq!(action.consume_set.len(), 1);
        assert_eq!(action.create_set[0].operation, "create");
        assert!(action.ckb_runtime_accesses.iter().any(|access| access.source == "Output" && access.operation == "create"));
        assert!(action.elf_compatible);
        assert!(action.ckb_runtime_features.contains(&"read-cell-dep".to_string()));
        assert!(!action.symbolic_runtime_features.contains(&"read-ref-expression".to_string()));
        assert!(action.fail_closed_runtime_features.is_empty());
        assert!(!action.touches_shared.is_empty());
        assert!(action.estimated_cycles > 32);
        assert_eq!(action.scheduler_witness_abi, "molecule");
        assert!(!action.scheduler_witness_hex.is_empty());
        assert!(!action.scheduler_witness_hex.starts_with("11ce"));
        assert!(action.scheduler_witness_molecule_hex.is_empty());
        assert_eq!(
            action.scheduler_witness_bytes().expect("scheduler witness hex should decode"),
            decode_scheduler_witness_hex(&action.scheduler_witness_hex).expect("scheduler witness hex should decode")
        );

        let witness = decode_molecule_scheduler_witness_hex(&action.scheduler_witness_hex);
        assert_eq!(witness.magic, 0xCE11);
        assert_eq!(witness.version, 1);
        assert_eq!(witness.effect_class, 2);
        assert!(!witness.parallelizable);
        assert_eq!(witness.touches_shared_count as usize, witness.touches_shared.len());
        assert_eq!(witness.estimated_cycles, action.estimated_cycles);
        assert_eq!(witness.access_count as usize, witness.accesses.len());

        let access_ops = witness.accesses.iter().map(|access| access.operation).collect::<std::collections::BTreeSet<_>>();
        let access_sources = witness.accesses.iter().map(|access| access.source).collect::<std::collections::BTreeSet<_>>();
        assert!(access_ops.contains(&1), "consume access missing from scheduler witness");
        assert!(access_ops.contains(&6), "read_ref access missing from scheduler witness");
        assert!(access_ops.contains(&7), "create access missing from scheduler witness");
        assert!(access_sources.contains(&1), "Input source missing from scheduler witness");
        assert!(access_sources.contains(&2), "CellDep source missing from scheduler witness");
        assert!(access_sources.contains(&3), "Output source missing from scheduler witness");
        assert!(witness.accesses.iter().any(|access| access.index == 0));
        assert!(witness.accesses.iter().any(|access| access.binding_hash != [0u8; 32]));
    }

    #[test]
    fn scheduler_witness_omits_runtime_only_claim_witness_accesses() {
        let result = compile(CLAIM_SIGNER_PUBKEY_HASH_PROGRAM, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "redeem_signed").expect("redeem_signed metadata");
        assert!(
            action.ckb_runtime_accesses.iter().any(|access| access.operation == "claim-signature" && access.source == "Witness"),
            "runtime metadata should still expose signature verification accesses"
        );
        assert!(
            action.ckb_runtime_accesses.iter().any(|access| access.operation == "claim-witness" && access.source == "GroupInput"),
            "runtime metadata should still expose claim witness envelope accesses"
        );

        assert_eq!(action.scheduler_witness_abi, "molecule");
        assert!(!action.scheduler_witness_hex.is_empty());
        assert!(action.scheduler_witness_molecule_hex.is_empty());
        let witness = decode_molecule_scheduler_witness_hex(&action.scheduler_witness_hex);
        assert_eq!(witness.magic, 0xCE11);
        assert_eq!(witness.version, 1);
        assert_eq!(witness.access_count as usize, witness.accesses.len());
        assert!(matches!(witness.effect_class, 0..=4));
        assert_eq!(witness.touches_shared_count as usize, witness.touches_shared.len());
        assert!(witness.estimated_cycles > 0);
        let _parallelizable = witness.parallelizable;
        assert!(
            witness.accesses.iter().all(|access| access.operation != 0 && matches!(access.source, 1..=3)),
            "scheduler witness must contain only scheduler-visible cell-state accesses"
        );
        assert!(witness.accesses.iter().any(|access| access.operation == 4 && access.source == 1));
        assert!(witness.accesses.iter().any(|access| access.operation == 4 && access.source == 3));
        assert!(witness.accesses.iter().all(|access| access.binding_hash != [0u8; 32]));
        assert!(witness.accesses.iter().any(|access| access.index == 0));
    }

    #[test]
    fn scheduler_witness_hex_decode_rejects_invalid_metadata_hex() {
        let odd = decode_scheduler_witness_hex("11c").unwrap_err();
        assert!(odd.message.contains("full bytes"));
        let invalid = decode_scheduler_witness_hex("11xz").unwrap_err();
        assert!(invalid.message.contains("invalid scheduler witness hex byte"));
    }

    fn action_metadata_with_scheduler_fields(scheduler_witness_hex: &str, scheduler_witness_molecule_hex: &str) -> ActionMetadata {
        ActionMetadata {
            name: "scheduler".to_string(),
            params: vec![],
            effect_class: "Pure".to_string(),
            parallelizable: false,
            touches_shared: vec![],
            estimated_cycles: 0,
            scheduler_witness_abi: SCHEDULER_WITNESS_ABI_MOLECULE.to_string(),
            scheduler_witness_hex: scheduler_witness_hex.to_string(),
            scheduler_witness_molecule_hex: scheduler_witness_molecule_hex.to_string(),
            consume_set: vec![],
            read_refs: vec![],
            create_set: vec![],
            mutate_set: vec![],
            pool_primitives: vec![],
            ckb_runtime_accesses: vec![],
            ckb_runtime_features: vec![],
            symbolic_runtime_features: vec![],
            fail_closed_runtime_features: vec![],
            verifier_obligations: vec![],
            transaction_runtime_input_requirements: vec![],
            elf_compatible: true,
            standalone_runner_compatible: true,
            block_count: 0,
        }
    }

    #[test]
    fn action_scheduler_witness_bytes_rejects_conflicting_molecule_alias() {
        let action = action_metadata_with_scheduler_fields("11ce01", "11ce02");

        let public_error = action.scheduler_witness_bytes().unwrap_err();

        assert!(public_error.message.contains("conflicting scheduler_witness_hex"), "unexpected error: {public_error}");
    }

    #[test]
    fn mutable_shared_param_forces_mutating_scheduler_hint() {
        let source = r#"
module test

shared Pool has store {
    reserve: u64
}

action touch(pool: &mut Pool, delta: u64) {
    pool.reserve = pool.reserve + delta
}
"#;

        let result = compile(source, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "touch").expect("touch metadata");
        assert_eq!(action.effect_class, "Mutating");
        assert!(!action.parallelizable, "mutable shared params must not default to parallel execution");
        assert!(!action.touches_shared.is_empty(), "mutable shared params must expose the shared type hash");
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "shared-state"
                && obligation.feature == "shared-mutation:Pool"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("field transition=checked-runtime")
        }));
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "pool-pattern"
                && obligation.feature == "pool-mutation-invariants:Pool"
                && obligation.status == "runtime-required"
                && obligation.detail.contains("Generic shared mutation checks")
        }));
    }

    #[test]
    fn generic_shared_mutation_does_not_emit_pool_pattern_metadata() {
        let source = r#"
module test

shared Ledger has store {
    balance: u64,
    owner: Address,
}

action credit(ledger: &mut Ledger, delta: u64) {
    ledger.balance = ledger.balance + delta
}
"#;

        let result = compile(source, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "credit").expect("credit metadata");
        let mutation = action
            .mutate_set
            .iter()
            .find(|mutation| mutation.operation == "mutate" && mutation.ty == "Ledger" && mutation.binding == "ledger")
            .expect("credit should expose Ledger mutate_set metadata");

        assert_eq!(action.effect_class, "Mutating");
        assert!(!action.parallelizable, "generic shared mutation must not default to parallel execution");
        assert!(!action.touches_shared.is_empty(), "generic shared mutation must expose scheduler-visible shared type hash");
        assert_eq!(mutation.fields, vec!["balance".to_string()]);
        assert_eq!(mutation.preserved_fields, vec!["owner".to_string()]);
        assert_eq!(mutation.input_source, "Input");
        assert_eq!(mutation.input_index, 0);
        assert_eq!(mutation.output_source, "Output");
        assert_eq!(mutation.output_index, 0);
        assert_eq!(mutation.field_equality_status, "checked-runtime");
        assert_eq!(mutation.field_transition_status, "checked-runtime");
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "shared-state"
                && obligation.feature == "shared-mutation:Ledger"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("field equality=checked-runtime")
                && obligation.detail.contains("field transition=checked-runtime")
        }));
        assert!(
            action.pool_primitives.is_empty(),
            "generic shared mutation must not emit Pool pattern metadata: {:?}",
            action.pool_primitives
        );
        assert!(
            !action.verifier_obligations.iter().any(|obligation| obligation.category == "pool-pattern"),
            "generic shared mutation must not report Pool pattern obligations: {:?}",
            action.verifier_obligations
        );
        assert!(
            result.metadata.runtime.pool_primitives.is_empty(),
            "runtime metadata must not aggregate Pool primitives for generic shared mutation: {:?}",
            result.metadata.runtime.pool_primitives
        );
    }

    #[test]
    fn mutable_state_transition_gaps_expose_runtime_input_blockers() {
        let source = r#"
module test

shared Ledger has store {
    balance: u128,
    owner: Address,
}

action credit(ledger: &mut Ledger, delta: u128) {
    ledger.balance = ledger.balance + delta
}
"#;

        let result = compile(source, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "credit").expect("credit metadata");
        let mutation = action
            .mutate_set
            .iter()
            .find(|mutation| mutation.operation == "mutate" && mutation.ty == "Ledger" && mutation.binding == "ledger")
            .expect("credit should expose Ledger mutate_set metadata");

        assert_eq!(mutation.field_equality_status, "checked-runtime");
        assert_eq!(mutation.field_transition_status, "runtime-required");
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "shared-state"
                && obligation.feature == "shared-mutation:Ledger"
                && obligation.status == "runtime-required"
                && obligation.detail.contains("field equality=checked-runtime")
                && obligation.detail.contains("field transition=runtime-required")
        }));
        assert!(action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "shared-mutation:Ledger"
                && requirement.status == "runtime-required"
                && requirement.component == "mutate-field-transition"
                && requirement.source == "InputOutput"
                && requirement.field.as_deref() == Some("transition-fields")
                && requirement.abi == "mutate-field-transition-policy"
                && requirement.blocker.as_deref() == Some("mutable field transition formula is not fully verifier-covered")
                && requirement.blocker_class.as_deref() == Some("state-transition-formula-gap")
        }));
        assert!(!action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "shared-mutation:Ledger" && requirement.component == "mutate-field-equality"
        }));
    }

    #[test]
    fn u128_mutable_state_transition_with_u64_delta_is_checked() {
        let source = r#"
module test

shared Ledger has store {
    balance: u128,
    owner: Address,
}

action credit(ledger: &mut Ledger, delta: u64) {
    ledger.balance = ledger.balance + delta
}
"#;

        let result = compile(source, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "credit").expect("credit metadata");
        let mutation = action
            .mutate_set
            .iter()
            .find(|mutation| mutation.operation == "mutate" && mutation.ty == "Ledger" && mutation.binding == "ledger")
            .expect("credit should expose Ledger mutate_set metadata");

        assert_eq!(mutation.field_equality_status, "checked-runtime");
        assert_eq!(mutation.field_transition_status, "checked-runtime");
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "shared-state"
                && obligation.feature == "shared-mutation:Ledger"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("field equality=checked-runtime")
                && obligation.detail.contains("field transition=checked-runtime")
        }));
        assert!(!action.transaction_runtime_input_requirements.iter().any(|requirement| {
            requirement.feature == "shared-mutation:Ledger" && requirement.component == "mutate-field-transition"
        }));
    }

    #[test]
    fn fixed_byte_mutable_state_set_transition_is_checked_under_ckb_profile() {
        let source = r#"
module test

resource NFT has store, destroy {
    token_id: u64
    owner: Address
    metadata_hash: Hash
    royalty_recipient: Address
    royalty_bps: u16
}

action transfer(nft: &mut NFT, to: Address) {
    assert_invariant(nft.owner != to, "cannot transfer to self")
    nft.owner = to
}
"#;

        let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "transfer").expect("transfer metadata");
        let mutation = action
            .mutate_set
            .iter()
            .find(|mutation| mutation.operation == "mutate" && mutation.ty == "NFT" && mutation.binding == "nft")
            .expect("transfer should expose NFT mutate_set metadata");

        assert_eq!(mutation.field_equality_status, "checked-runtime");
        assert_eq!(mutation.field_transition_status, "checked-runtime");
        assert!(
            asm.contains("# cellscript abi: verify mutate set transition field NFT.owner Output#0 offset=8 size=32"),
            "fixed-byte set transition should be checked against the replacement output:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: verify output bytes field NFT set.owner offset=8 size=32 against pointer var"),
            "fixed-byte set transition should compare the output field to the Address pointer source:\n{}",
            asm
        );
        assert!(
            asm.contains("li a0, 0\n    j .Ltransfer_epilogue"),
            "void action success path must clear a0 before returning to ckb-vm:\n{}",
            asm
        );
        assert!(action.verifier_obligations.iter().any(|obligation| {
            obligation.category == "cell-state"
                && obligation.feature == "mutable-cell:NFT"
                && obligation.status == "checked-runtime"
                && obligation.detail.contains("field equality=checked-runtime")
                && obligation.detail.contains("field transition=checked-runtime")
        }));
        assert!(!action
            .transaction_runtime_input_requirements
            .iter()
            .any(|requirement| { requirement.feature == "mutable-cell:NFT" && requirement.component == "mutate-field-transition" }));
    }

    #[test]
    fn metadata_exposes_output_operation_provenance_for_transfer() {
        let result = compile(TRANSFER_CLAIM_SETTLE_PROGRAM, CompileOptions::default()).unwrap();

        let transfer_action = result.metadata.actions.iter().find(|action| action.name == "move_token").expect("move_token metadata");
        assert_eq!(transfer_action.create_set.len(), 1);
        assert_eq!(transfer_action.create_set[0].operation, "transfer");
        assert_eq!(transfer_action.create_set[0].fields, vec!["amount".to_string()]);
        assert!(transfer_action.create_set[0].has_lock);
        assert!(transfer_action.ckb_runtime_accesses.iter().any(|access| access.source == "Output" && access.operation == "transfer"));

        let claim_action = result.metadata.actions.iter().find(|action| action.name == "redeem").expect("redeem metadata");
        assert_eq!(claim_action.create_set.len(), 1);
        assert_eq!(claim_action.create_set[0].ty, "Token");
        assert_eq!(claim_action.create_set[0].operation, "claim");
        assert_eq!(claim_action.create_set[0].fields, vec!["amount".to_string()]);
        assert!(claim_action.ckb_runtime_accesses.iter().any(|access| access.source == "Output" && access.operation == "claim"));

        let settle_action = result.metadata.actions.iter().find(|action| action.name == "finalize").expect("finalize metadata");
        assert_eq!(settle_action.create_set.len(), 1);
        assert_eq!(settle_action.create_set[0].ty, "Token");
        assert_eq!(settle_action.create_set[0].operation, "settle");
        assert_eq!(settle_action.create_set[0].fields, vec!["amount".to_string()]);
        assert!(settle_action.ckb_runtime_accesses.iter().any(|access| access.source == "Output" && access.operation == "settle"));
    }

    #[test]
    fn compile_result_exposes_schema_layout_metadata() {
        let result = compile(PARAM_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let snapshot = result.metadata.types.iter().find(|ty| ty.name == "Snapshot").expect("Snapshot type metadata");
        let action = result.metadata.actions.iter().find(|action| action.name == "inspect").expect("inspect metadata");
        assert_eq!(action.params.len(), 1);
        assert_eq!(action.params[0].name, "snapshot");
        assert_eq!(action.params[0].ty, "Snapshot");
        assert!(action.params[0].schema_pointer_abi);
        assert!(action.params[0].schema_length_abi);
        assert_eq!(snapshot.kind, "Struct");
        assert_eq!(snapshot.encoded_size, Some(8));
        let molecule_schema = snapshot.molecule_schema.as_ref().expect("Snapshot molecule schema metadata");
        assert_eq!(molecule_schema.abi, "molecule");
        assert_eq!(molecule_schema.layout, "fixed-struct-v1");
        assert_eq!(molecule_schema.fixed_size, 8);
        assert!(molecule_schema.schema.contains("struct Snapshot"));
        assert!(molecule_schema.schema.contains("amount: CellScriptUint64"));
        assert_eq!(molecule_schema.schema_hash_blake3, crate::hex_encode(blake3::hash(molecule_schema.schema.as_bytes()).as_bytes()));
        let amount = snapshot.fields.iter().find(|field| field.name == "amount").expect("amount field metadata");
        assert_eq!(amount.ty, "u64");
        assert_eq!(amount.offset, 0);
        assert_eq!(amount.encoded_size, Some(8));
        assert!(amount.fixed_width);
    }

    #[test]
    fn ckb_entry_action_scope_excludes_unselected_unportable_code() {
        let source = r#"
module scoped_ckb

resource Token has destroy {
    amount: u64,
}

action burn(token: Token) {
    destroy token
}

action unsupported_daa() -> u64 {
    return env::current_daa_score()
}
"#;
        let temp = tempdir().unwrap();
        let entry = Utf8Path::from_path(temp.path()).unwrap().join("scoped.cell");
        std::fs::write(&entry, source).unwrap();

        let full = compile_file(&entry, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() })
            .unwrap_err()
            .to_string();
        assert!(full.contains("DAA/header assumptions are Spora-specific"), "full CKB compile should reject unselected DAA: {}", full);

        let scoped = compile_file_with_entry_action(
            &entry,
            CompileOptions {
                target_profile: Some("ckb".to_string()),
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
            "burn",
        )
        .unwrap();
        assert_eq!(scoped.metadata.actions.len(), 1);
        assert_eq!(scoped.metadata.actions[0].name, "burn");
        assert!(scoped.metadata.types.iter().any(|ty| ty.name == "Token"));
        assert!(!scoped.metadata.actions.iter().any(|action| action.name == "unsupported_daa"));
        assert!(scoped.artifact_bytes.starts_with(b"\x7fELF"));
        assert_eq!(scoped.metadata.target_profile.name, "ckb");
    }

    #[test]
    fn ckb_entry_lock_scope_selects_lock_entrypoint() {
        let source = r#"
module scoped_lock

resource DynamicCell {
    name: String,
}

lock owner_lock(owner: Address) -> bool {
    true
}

action unsupported(name: String) -> DynamicCell {
    let cell = create DynamicCell {
        name: name,
    };
    cell
}
"#;
        let temp = tempdir().unwrap();
        let entry = Utf8Path::from_path(temp.path()).unwrap().join("scoped_lock.cell");
        std::fs::write(&entry, source).unwrap();

        let scoped = compile_file_with_entry_lock(
            &entry,
            CompileOptions {
                target_profile: Some("ckb".to_string()),
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
            "owner_lock",
        )
        .unwrap();
        assert_eq!(scoped.metadata.locks.len(), 1);
        assert_eq!(scoped.metadata.locks[0].name, "owner_lock");
        assert!(scoped.metadata.actions.is_empty());
        assert!(!scoped.metadata.types.iter().any(|ty| ty.name == "DynamicCell"));
        assert!(scoped.artifact_bytes.starts_with(b"\x7fELF"));
    }

    #[test]
    fn ckb_entry_scope_keeps_vec_element_schema_dependencies() {
        let source = r#"
module scoped_vec_dependency

struct Signature {
    signer: Address,
}

receipt Proposal {
    signatures: Vec<Signature>,
    expires_at: u64,
}

lock not_expired(proposal: &Proposal, now: u64) -> bool {
    now < proposal.expires_at
}
"#;
        let temp = tempdir().unwrap();
        let entry = Utf8Path::from_path(temp.path()).unwrap().join("scoped_vec_dependency.cell");
        std::fs::write(&entry, source).unwrap();

        let scoped = compile_file_with_entry_lock(
            &entry,
            CompileOptions {
                target_profile: Some("ckb".to_string()),
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
            "not_expired",
        )
        .unwrap();
        let proposal = scoped.metadata.types.iter().find(|ty| ty.name == "Proposal").expect("Proposal metadata");
        let schema = proposal.molecule_schema.as_ref().expect("Proposal schema should be generated in scoped CKB compile");
        assert!(schema.schema.contains("struct Signature"), "Vec<Signature> dependency was not retained:\n{}", schema.schema);
        assert!(scoped.metadata.types.iter().any(|ty| ty.name == "Signature"));
    }

    #[test]
    fn fixed_enum_fields_have_molecule_schema_metadata() {
        let source = r#"
module enum_schema

enum LockType {
    Absolute,
    Relative,
}

resource TimeLock {
    owner: Address,
    lock_type: LockType,
    unlock_height: u64,
}

action create_lock(owner: Address) -> TimeLock {
    let lock = create TimeLock {
        owner: owner,
        lock_type: LockType::Absolute,
        unlock_height: 42,
    };
    lock
}
"#;
        let result = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        let time_lock = result.metadata.types.iter().find(|ty| ty.name == "TimeLock").expect("TimeLock metadata");
        assert_eq!(time_lock.encoded_size, Some(41));
        let lock_type = time_lock.fields.iter().find(|field| field.name == "lock_type").expect("lock_type field");
        assert_eq!(lock_type.encoded_size, Some(1));
        let schema = time_lock.molecule_schema.as_ref().expect("TimeLock molecule schema");
        assert_eq!(schema.layout, "fixed-struct-v1");
        assert_eq!(schema.fixed_size, 41);
        assert!(schema.schema.contains("array CellScriptEnumTag [byte; 1];"));
        assert!(schema.schema.contains("lock_type: CellScriptEnumTag"));
    }

    #[test]
    fn payload_enum_fields_use_dynamic_molecule_schema_metadata() {
        let source = r#"
module payload_enum_schema

enum AssetType {
    Native,
    Token(Hash),
}

resource LockedAsset {
    asset_type: AssetType,
    amount: u64,
    lock_hash: Hash,
}

action lock_asset(asset_type: AssetType, amount: u64) -> LockedAsset {
    let locked = create LockedAsset {
        asset_type: asset_type,
        amount: amount,
        lock_hash: Hash::zero(),
    };
    locked
}

lock asset_matches(locked_asset: &LockedAsset, expected: Hash) -> bool {
    locked_asset.lock_hash == expected
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let locked = result.metadata.types.iter().find(|ty| ty.name == "LockedAsset").expect("LockedAsset metadata");
        assert_eq!(locked.encoded_size, None);
        let asset_type = locked.fields.iter().find(|field| field.name == "asset_type").expect("asset_type field");
        assert_eq!(asset_type.encoded_size, None);
        let schema = locked.molecule_schema.as_ref().expect("LockedAsset should have a dynamic Molecule schema");
        assert_eq!(schema.layout, "molecule-table-v1");
        assert_eq!(schema.dynamic_fields, vec!["asset_type"]);
        assert!(schema.schema.contains("asset_type: LockedAssetAssetTypeBytes"));
        assert!(
            !schema.schema.contains("asset_type: CellScriptEnumTag"),
            "payload enum fields must not be represented as one-byte enum tags"
        );

        let ckb = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        assert!(
            ckb.metadata.types.iter().any(|ty| ty.name == "LockedAsset" && ty.molecule_schema.is_some()),
            "CKB policy should accept payload enum table metadata"
        );

        let temp = tempdir().unwrap();
        let entry = Utf8Path::from_path(temp.path()).unwrap().join("payload_enum_schema.cell");
        std::fs::write(&entry, source).unwrap();
        let scoped = compile_file_with_entry_lock(
            &entry,
            CompileOptions {
                target_profile: Some("ckb".to_string()),
                target: Some("riscv64-elf".to_string()),
                ..CompileOptions::default()
            },
            "asset_matches",
        )
        .unwrap();
        assert!(scoped.artifact_bytes.starts_with(b"\x7fELF"));
    }

    #[test]
    fn dynamic_schema_fixed_field_access_is_table_decoded() {
        let source = r#"
module dynamic_schema_access

resource Collection {
    name: String,
    creator: Address,
}

lock collection_creator(collection: &Collection, claimed_creator: Address) -> bool {
    collection.creator == claimed_creator
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let collection = result.metadata.types.iter().find(|ty| ty.name == "Collection").expect("Collection metadata");
        let schema = collection.molecule_schema.as_ref().expect("dynamic Collection molecule schema");
        assert_eq!(collection.encoded_size, None);
        assert_eq!(schema.layout, "molecule-table-v1");
        assert_eq!(schema.fixed_size, 0);
        assert_eq!(schema.dynamic_fields, vec!["name".to_string()]);
        assert!(schema.schema.contains("vector CellScriptString <byte>;"));
        assert!(schema.schema.contains("table Collection"));
        assert!(schema.schema.contains("name: CellScriptString"));
        assert!(schema.schema.contains("creator: CellScriptAddress"));

        let lock = result.metadata.locks.iter().find(|lock| lock.name == "collection_creator").expect("lock metadata");
        assert!(
            !lock.fail_closed_runtime_features.contains(&"field-access".to_string()),
            "fixed field access through a Molecule table should be verifier-covered: {:?}",
            lock.fail_closed_runtime_features
        );

        let ckb = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        assert!(
            ckb.metadata.locks[0].fail_closed_runtime_features.is_empty(),
            "CKB table fixed-field lock should not require fail-closed runtime paths: {:?}",
            ckb.metadata.locks[0].fail_closed_runtime_features
        );
    }

    #[test]
    fn dynamic_schema_fixed_vec_length_is_table_decoded() {
        let source = r#"
module dynamic_vec_len

receipt Emergency {
    lock_hash: Hash,
    approvers: Vec<Address>,
}

lock enough(emergency: &Emergency, required: u8) -> bool {
    emergency.approvers.len() >= required as usize
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let emergency = result.metadata.types.iter().find(|ty| ty.name == "Emergency").expect("Emergency metadata");
        let schema = emergency.molecule_schema.as_ref().expect("dynamic Emergency molecule schema");
        assert_eq!(schema.layout, "molecule-table-v1");
        assert_eq!(schema.dynamic_fields, vec!["approvers".to_string()]);

        let lock = result.metadata.locks.iter().find(|lock| lock.name == "enough").expect("lock metadata");
        assert!(
            !lock.fail_closed_runtime_features.contains(&"field-access".to_string()),
            "dynamic Molecule vector field access should be verifier-covered: {:?}",
            lock.fail_closed_runtime_features
        );
        assert!(
            !lock.fail_closed_runtime_features.contains(&"dynamic-length".to_string()),
            "fixed-element Molecule vector length should be verifier-covered: {:?}",
            lock.fail_closed_runtime_features
        );

        let ckb = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        assert!(
            ckb.metadata.locks[0].fail_closed_runtime_features.is_empty(),
            "CKB fixed-element vector length lock should not require fail-closed runtime paths: {:?}",
            ckb.metadata.locks[0].fail_closed_runtime_features
        );
    }

    #[test]
    fn dynamic_schema_fixed_vec_iteration_is_table_decoded() {
        let source = r#"
module dynamic_vec_iter

resource Wallet {
    signers: Vec<Address>,
    threshold: u8,
}

fn is_signer(wallet: &Wallet, addr: Address) -> bool {
    for signer in &wallet.signers {
        if *signer == addr {
            return true;
        }
    }
    false
}

lock signer(wallet: &Wallet, addr: Address) -> bool {
    is_signer(wallet, addr)
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let function = result.metadata.functions.iter().find(|function| function.name == "is_signer").expect("function metadata");
        assert!(
            !function.fail_closed_runtime_features.contains(&"dynamic-length".to_string()),
            "fixed-element Molecule vector length should be verifier-covered: {:?}",
            function.fail_closed_runtime_features
        );
        assert!(
            !function.fail_closed_runtime_features.contains(&"index-access".to_string()),
            "fixed-element Molecule vector index should be verifier-covered: {:?}",
            function.fail_closed_runtime_features
        );
        assert!(
            !function.fail_closed_runtime_features.contains(&"fixed-byte-comparison".to_string()),
            "fixed-element Molecule vector comparison should be verifier-covered: {:?}",
            function.fail_closed_runtime_features
        );

        let ckb = compile(source, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        let function = ckb.metadata.functions.iter().find(|function| function.name == "is_signer").expect("CKB function metadata");
        assert!(
            function.fail_closed_runtime_features.is_empty(),
            "CKB fixed-element vector iteration should not require fail-closed runtime paths: {:?}",
            function.fail_closed_runtime_features
        );
    }

    #[test]
    fn dynamic_mutable_schema_transitions_are_checked_after_table_decoding() {
        let source = r#"
module dynamic_mutation

resource Collection {
    name: String,
    total_supply: u64,
    max_supply: u64,
}

action mint(collection: &mut Collection) {
    assert!(collection.total_supply < collection.max_supply, "max supply reached");
    collection.total_supply = collection.total_supply + 1;
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let collection = result.metadata.types.iter().find(|ty| ty.name == "Collection").expect("Collection metadata");
        let schema = collection.molecule_schema.as_ref().expect("dynamic Collection molecule schema");
        assert_eq!(schema.layout, "molecule-table-v1");
        assert_eq!(schema.dynamic_fields, vec!["name".to_string()]);

        let action = result.metadata.actions.iter().find(|action| action.name == "mint").expect("mint metadata");
        let mutation = action.mutate_set.iter().find(|mutation| mutation.ty == "Collection").expect("mutation metadata");

        assert_eq!(mutation.field_equality_status, "checked-runtime");
        assert_eq!(mutation.field_transition_status, "checked-runtime");
        assert!(!action.fail_closed_runtime_features.contains(&"field-access".to_string()));
        assert!(
            !action.transaction_runtime_input_requirements.iter().any(|requirement| {
                requirement.feature == "mutable-cell:Collection"
                    && matches!(requirement.component.as_str(), "mutate-field-equality" | "mutate-field-transition")
            }),
            "checked mutable table transitions should not leave runtime input blockers: {:?}",
            action.transaction_runtime_input_requirements
        );
    }

    #[test]
    fn compile_result_exposes_nested_fixed_molecule_schema_metadata() {
        let source = r#"
module audit::nested_schema

struct Owner {
    pubkey: Hash,
    flags: [u8; 2],
}

resource Token has store {
    owner: Owner,
    pair: (u64, Owner),
    checkpoints: [(Owner, u64); 2],
    amount: u64,
}

action value() -> u64 {
    return 1
}
"#;

        let result = compile(source, CompileOptions::default()).unwrap();
        let owner = result.metadata.types.iter().find(|ty| ty.name == "Owner").expect("Owner type metadata");
        let token = result.metadata.types.iter().find(|ty| ty.name == "Token").expect("Token type metadata");

        assert_eq!(owner.encoded_size, Some(34));
        assert_eq!(token.encoded_size, Some(168));
        let owner_field = token.fields.iter().find(|field| field.name == "owner").expect("owner field metadata");
        let pair_field = token.fields.iter().find(|field| field.name == "pair").expect("pair field metadata");
        let checkpoints_field = token.fields.iter().find(|field| field.name == "checkpoints").expect("checkpoints field metadata");
        let amount_field = token.fields.iter().find(|field| field.name == "amount").expect("amount field metadata");
        assert_eq!(owner_field.offset, 0);
        assert_eq!(owner_field.encoded_size, Some(34));
        assert_eq!(pair_field.offset, 34);
        assert_eq!(pair_field.encoded_size, Some(42));
        assert_eq!(checkpoints_field.offset, 76);
        assert_eq!(checkpoints_field.encoded_size, Some(84));
        assert_eq!(amount_field.offset, 160);
        assert_eq!(amount_field.encoded_size, Some(8));

        let molecule_schema = token.molecule_schema.as_ref().expect("Token molecule schema metadata");
        assert_eq!(molecule_schema.fixed_size, 168);
        assert!(molecule_schema.schema.contains("struct Owner"));
        assert!(molecule_schema.schema.contains("struct CellScriptTupleTokenPair"));
        assert!(molecule_schema.schema.contains("struct CellScriptTupleTokenCheckpoints"));
        assert!(molecule_schema.schema.contains("struct Token"));
        assert!(molecule_schema.schema.contains("owner: Owner"));
        assert!(molecule_schema.schema.contains("pair: CellScriptTupleTokenPair"));
        assert!(molecule_schema.schema.contains("array TokenCheckpointsArray2 [CellScriptTupleTokenCheckpoints; 2];"));
        assert!(molecule_schema.schema.contains("checkpoints: TokenCheckpointsArray2"));
        assert_eq!(molecule_schema.schema_hash_blake3, crate::hex_encode(blake3::hash(molecule_schema.schema.as_bytes()).as_bytes()));
    }

    #[test]
    fn compile_metadata_exposes_authoritative_molecule_schema_manifest() {
        let source = r#"
module schema_manifest

resource Profile {
    owner: Address,
    display_name: String,
    score: u64,
}

receipt MintReceipt {
    owner: Address,
    amount: u64,
}

action mint(owner: Address, amount: u64) -> MintReceipt {
    create MintReceipt { owner: owner, amount: amount }
}
"#;
        let result = compile(source, CompileOptions::default()).unwrap();
        let manifest = &result.metadata.molecule_schema_manifest;
        assert_eq!(manifest.schema, "cellscript-molecule-schema-manifest-v1");
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.abi, "molecule");
        assert_eq!(manifest.target_profile, "spora");
        assert_eq!(manifest.type_count, 2);
        assert_eq!(manifest.fixed_type_count, 1);
        assert_eq!(manifest.dynamic_type_count, 1);
        assert_eq!(manifest.entries.iter().map(|entry| entry.type_name.as_str()).collect::<Vec<_>>(), vec!["MintReceipt", "Profile"]);
        assert!(crate::is_canonical_blake3_hex(&manifest.manifest_hash_blake3));

        let profile = manifest.entries.iter().find(|entry| entry.type_name == "Profile").expect("Profile manifest entry");
        assert_eq!(profile.layout, "molecule-table-v1");
        assert_eq!(profile.dynamic_fields, vec!["display_name"]);
        assert!(profile.field_offsets.iter().any(|field| field.name == "owner" && field.offset == 0 && field.fixed_width));
        assert!(
            profile
                .field_offsets
                .iter()
                .any(|field| field.name == "display_name" && field.encoded_size.is_none() && !field.fixed_width),
            "dynamic field layout should stay visible in the schema manifest: {:?}",
            profile.field_offsets
        );

        let receipt = manifest.entries.iter().find(|entry| entry.type_name == "MintReceipt").expect("MintReceipt manifest entry");
        assert_eq!(receipt.layout, "fixed-struct-v1");
        assert_eq!(receipt.fixed_size, 40);
        assert!(receipt
            .field_offsets
            .iter()
            .any(|field| field.name == "amount" && field.offset == 32 && field.encoded_size == Some(8)));

        crate::validate_compile_metadata(&result.metadata, result.artifact_format).unwrap();
    }

    #[test]
    fn compile_result_exposes_type_capability_metadata() {
        let result = compile(TRANSFER_CLAIM_SETTLE_PROGRAM, CompileOptions::default()).unwrap();
        let token = result.metadata.types.iter().find(|ty| ty.name == "Token").expect("Token type metadata");
        let receipt = result.metadata.types.iter().find(|ty| ty.name == "VestingReceipt").expect("VestingReceipt type metadata");

        assert_eq!(token.kind, "Resource");
        assert!(token.capabilities.contains(&"store".to_string()));
        assert!(token.capabilities.contains(&"transfer".to_string()));
        assert!(token.capabilities.contains(&"destroy".to_string()));
        assert_eq!(token.molecule_schema.as_ref().map(|schema| schema.abi.as_str()), Some("molecule"));
        assert_eq!(receipt.kind, "Receipt");
        assert!(receipt.capabilities.is_empty());
        assert_eq!(receipt.claim_output.as_deref(), Some("Token"));
        assert_eq!(receipt.molecule_schema.as_ref().map(|schema| schema.layout.as_str()), Some("fixed-struct-v1"));
    }

    #[test]
    fn compile_result_exposes_stable_type_id_metadata() {
        let program = r#"
module audit::type_id

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}

action value() -> u64 {
    return 1
}
"#;
        let result = compile(program, CompileOptions::default()).unwrap();
        let token = result.metadata.types.iter().find(|ty| ty.name == "Token").expect("Token type metadata");
        let expected_hash = crate::hex_encode(blake3::hash(b"spora::asset::Token:v1").as_bytes());

        assert_eq!(result.metadata.metadata_schema_version, crate::METADATA_SCHEMA_VERSION);
        assert_eq!(token.type_id.as_deref(), Some("spora::asset::Token:v1"));
        assert_eq!(token.type_id_hash_blake3.as_deref(), Some(expected_hash.as_str()));
        assert!(token.ckb_type_id.is_none());
    }

    #[test]
    fn compile_exposes_ckb_type_id_contract_under_ckb_profile() {
        let program = r#"
module audit::type_id

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}

action value() -> u64 {
    return 1
}
"#;

        let result =
            compile(program, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap();
        let token = result.metadata.types.iter().find(|ty| ty.name == "Token").expect("Token type metadata");
        let ckb_type_id = token.ckb_type_id.as_ref().expect("CKB TYPE_ID metadata");

        assert_eq!(result.metadata.target_profile.name, "ckb");
        assert_eq!(token.type_id.as_deref(), Some("spora::asset::Token:v1"));
        assert_eq!(ckb_type_id.abi, crate::CKB_TYPE_ID_ABI);
        assert_eq!(ckb_type_id.script_code_hash, crate::hex_encode(&crate::CKB_TYPE_ID_CODE_HASH));
        assert_eq!(ckb_type_id.hash_type, crate::CKB_TYPE_ID_HASH_TYPE);
        assert_eq!(ckb_type_id.args_source, crate::CKB_TYPE_ID_ARGS_SOURCE);
        assert_eq!(ckb_type_id.group_rule, crate::CKB_TYPE_ID_GROUP_RULE);
        assert_eq!(ckb_type_id.builder, crate::CKB_TYPE_ID_BUILDER);
        assert_eq!(ckb_type_id.verifier, crate::CKB_TYPE_ID_VERIFIER);
    }

    #[test]
    fn compile_metadata_exposes_ckb_type_id_create_output_plan_under_ckb_profile() {
        let program = r#"
module audit::type_id_create

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}

resource PlainToken has store {
    amount: u64
}

action mint(amount: u64) -> Token {
    return create Token { amount: amount }
}

action mint_plain(amount: u64) -> PlainToken {
    return create PlainToken { amount: amount }
}
"#;

        let ckb_metadata = compile_metadata_for_profile_without_artifact_policy(program, crate::TargetProfile::Ckb);
        let mint = ckb_metadata.actions.iter().find(|action| action.name == "mint").expect("mint metadata");
        let plan = mint.create_set[0].ckb_type_id.as_ref().expect("CKB TYPE_ID create output plan");

        assert_eq!(mint.ckb_type_id_output_indexes(), vec![0]);
        assert_eq!(plan.abi, crate::CKB_TYPE_ID_ABI);
        assert_eq!(plan.type_id, "spora::asset::Token:v1");
        assert_eq!(plan.output_source, crate::CKB_TYPE_ID_OUTPUT_SOURCE);
        assert_eq!(plan.output_index, 0);
        assert_eq!(plan.script_code_hash, crate::hex_encode(&crate::CKB_TYPE_ID_CODE_HASH));
        assert_eq!(plan.hash_type, crate::CKB_TYPE_ID_HASH_TYPE);
        assert_eq!(plan.args_source, crate::CKB_TYPE_ID_ARGS_SOURCE);
        assert_eq!(plan.builder, crate::CKB_TYPE_ID_BUILDER);
        assert_eq!(plan.generator_setting, crate::CKB_TYPE_ID_GENERATOR_SETTING);
        assert_eq!(plan.wasm_setting, crate::CKB_TYPE_ID_WASM_SETTING);

        let plain = ckb_metadata.actions.iter().find(|action| action.name == "mint_plain").expect("mint_plain metadata");
        assert!(plain.create_set[0].ckb_type_id.is_none());
        assert!(plain.ckb_type_id_output_indexes().is_empty());

        let spora_metadata = compile_metadata_for_profile_without_artifact_policy(program, crate::TargetProfile::Spora);
        let spora_mint = spora_metadata.actions.iter().find(|action| action.name == "mint").expect("spora mint metadata");
        assert!(spora_mint.create_set[0].ckb_type_id.is_none());
    }

    #[test]
    fn compile_result_validation_rejects_mismatched_ckb_type_id_create_output_plan() {
        let program = r#"
module audit::type_id_create

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}

action mint(amount: u64) -> Token {
    return create Token { amount: amount }
}
"#;

        let mut metadata = compile_metadata_for_profile_without_artifact_policy(program, crate::TargetProfile::Ckb);
        metadata.actions[0].create_set[0].ckb_type_id.as_mut().expect("CKB TYPE_ID output plan").output_index = 1;

        let err = crate::validate_compile_metadata(&metadata, ArtifactFormat::RiscvAssembly).unwrap_err();
        assert!(err.message.contains("ckb_type_id.output_index"), "unexpected error: {}", err.message);

        metadata.actions[0].create_set[0].ckb_type_id = None;
        let err = crate::validate_compile_metadata(&metadata, ArtifactFormat::RiscvAssembly).unwrap_err();
        assert!(err.message.contains("missing ckb_type_id output plan"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_struct_only_type_id_under_ckb_profile() {
        let program = r#"
module audit::type_id

#[type_id("spora::asset::TokenSnapshot:v1")]
struct TokenSnapshot {
    amount: u64
}

action value() -> u64 {
    return 1
}
"#;

        let err =
            compile(program, CompileOptions { target_profile: Some("ckb".to_string()), ..CompileOptions::default() }).unwrap_err();

        assert!(err.message.contains("target profile policy failed for 'ckb'"), "unexpected error: {}", err.message);
        assert!(
            err.message.contains("type-only type_id declarations require profile-specific type-id lowering"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn compile_result_validation_rejects_molecule_schema_hash_mismatch() {
        let mut result = compile(PARAM_FIELD_PROGRAM, CompileOptions::default()).unwrap();
        let snapshot = result.metadata.types.iter_mut().find(|ty| ty.name == "Snapshot").expect("Snapshot type metadata");
        let molecule_schema = snapshot.molecule_schema.as_mut().expect("Snapshot molecule schema metadata");
        molecule_schema.schema_hash_blake3 = "00".repeat(32);

        let err = result.validate().unwrap_err();

        assert!(err.message.contains("molecule_schema.schema_hash_blake3"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compile_rejects_duplicate_stable_type_ids() {
        let program = r#"
module audit::type_id

#[type_id("spora::asset::Token:v1")]
resource Token has store {
    amount: u64
}

#[type_id("spora::asset::Token:v1")]
struct TokenSnapshot {
    amount: u64
}
"#;
        let err = compile(program, CompileOptions::default()).unwrap_err();

        assert!(err.message.contains("duplicate type_id 'spora::asset::Token:v1'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn compiled_riscv_elf_contains_exit_trampoline() {
        let program = r#"
module vm::minimal

action main() -> u64 {
    return 0
}
"#;

        let result =
            compile(program, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        let exit_syscall_addi_a7 = [0x93, 0x88, 0xd8, 0x05];
        let ecall = [0x73, 0x00, 0x00, 0x00];
        assert!(
            result.artifact_bytes.windows(exit_syscall_addi_a7.len()).any(|window| window == exit_syscall_addi_a7),
            "expected exit syscall load in ELF trampoline"
        );
        assert!(result.artifact_bytes.windows(ecall.len()).any(|window| window == ecall), "expected ecall in ELF trampoline");
    }

    #[test]
    fn parameterized_entrypoint_emits_witness_entry_wrapper() {
        let program = r#"
module vm::entry_abi

action spend(amount: u64) -> u64 {
    return amount
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes).unwrap();

        assert!(asm.contains(".global _cellscript_entry"), "parameterized entrypoints need a generated ELF entry wrapper:\n{}", asm);
        assert!(
            asm.contains("# cellscript entry abi: _cellscript_entry loads GroupInput witness args for spend"),
            "entry wrapper did not document its target ABI:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript abi: LOAD_WITNESS reason=entry_args source=GroupInput index=0"),
            "entry wrapper did not load positional arguments from GroupInput witness:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript entry abi: scalar param amount -> a0 size=8"),
            "entry wrapper did not lower u64 witness payload into the action ABI register:\n{}",
            asm
        );
        assert!(asm.contains("call spend"), "entry wrapper did not call the original action label:\n{}", asm);
        assert!(
            asm.contains("# cellscript entry abi: spend requires-explicit-parameter-abi"),
            "direct action entry still needs an explicit ABI marker for non-wrapper callers:\n{}",
            asm
        );

        let elf = compile(program, CompileOptions { target: Some("riscv64-elf".to_string()), ..CompileOptions::default() }).unwrap();
        assert!(elf.artifact_bytes.starts_with(b"\x7fELF"));
    }

    #[test]
    fn entry_witness_encoder_matches_u64_wrapper_abi() {
        let program = r#"
module vm::entry_abi

action spend(amount: u64) -> u64 {
    return amount
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "spend").unwrap();
        let witness = action.entry_witness_args(&[EntryWitnessArg::U64(77)]).unwrap();

        let mut expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        expected.extend_from_slice(&77u64.to_le_bytes());
        assert_eq!(witness, expected);
        assert_eq!(encode_entry_witness_args_for_params(&action.params, &[EntryWitnessArg::U64(77)]).unwrap(), expected);
    }

    #[test]
    fn entry_witness_encoder_supports_fixed_byte_params() {
        let program = r#"
module vm::entry_abi

action owned(owner: Address) -> u64 {
    return 0
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "owned").unwrap();
        let owner = [9u8; 32];
        let witness = action.entry_witness_args(&[EntryWitnessArg::Address(owner)]).unwrap();

        let mut expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        expected.extend_from_slice(&owner);
        assert_eq!(witness, expected);

        let err = action.entry_witness_args(&[EntryWitnessArg::U64(9)]).unwrap_err();
        assert!(err.message.contains("expects 32 fixed bytes for type 'Address'"), "unexpected error: {}", err.message);
    }

    #[test]
    fn entry_witness_wrapper_supports_scalar_stack_args() {
        let program = r#"
module vm::entry_abi

resource A has store, destroy {
    value: u64,
}

resource B has store, destroy {
    value: u64,
}

resource C has store, destroy {
    value: u64,
}

action stack_arg(a: A, b: B, c: C, owner: Address, required: u64) -> u64 {
    destroy a
    destroy b
    destroy c
    return required
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let asm = String::from_utf8(result.artifact_bytes.clone()).unwrap();
        assert!(
            asm.contains("# cellscript entry abi: scalar param required -> stack+0 size=8"),
            "entry wrapper did not map the ninth ABI argument to the caller stack:\n{}",
            asm
        );
        assert!(
            asm.contains("# cellscript entry abi: scalar param required stored to caller stack +0"),
            "entry wrapper did not store the stack scalar argument before calling the action:\n{}",
            asm
        );
        assert!(asm.contains("sd t3, 0(sp)"), "entry wrapper did not emit the stack argument store:\n{}", asm);

        let action = result.metadata.actions.iter().find(|action| action.name == "stack_arg").unwrap();
        let owner = [7u8; 32];
        let witness = action.entry_witness_args(&[EntryWitnessArg::Address(owner), EntryWitnessArg::U64(2)]).unwrap();

        let mut expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        expected.extend_from_slice(&owner);
        expected.extend_from_slice(&2u64.to_le_bytes());
        assert_eq!(witness, expected);
    }

    #[test]
    fn entry_witness_encoder_includes_schema_backed_params_as_length_prefixed_bytes() {
        let program = r#"
module vm::entry_abi

action bad(items: Vec<Address>) -> u64 {
    return 0
}

action hashes(items: Vec<Hash>) -> u64 {
    return 0
}

action nested(items: Vec<Vec<u8>>) -> u64 {
    return 0
}

action raw(data: Vec<u8>) -> u64 {
    return 0
}
"#;

        let result = compile(program, CompileOptions::default()).unwrap();
        let action = result.metadata.actions.iter().find(|action| action.name == "bad").unwrap();
        let schema_bytes = vec![1u8, 2, 3, 4];
        let mut expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        expected.extend_from_slice(&(schema_bytes.len() as u32).to_le_bytes());
        expected.extend_from_slice(&schema_bytes);
        assert_eq!(action.entry_witness_args(&[EntryWitnessArg::Bytes(schema_bytes.clone())]).unwrap(), expected);

        let err = action.entry_witness_args(&[]).unwrap_err();
        assert!(err.message.contains("missing payload arg"), "unexpected error: {}", err.message);

        let hashes = result.metadata.actions.iter().find(|action| action.name == "hashes").unwrap();
        let hash_bytes = vec![0x11; 64];
        let mut hash_expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        hash_expected.extend_from_slice(&(hash_bytes.len() as u32).to_le_bytes());
        hash_expected.extend_from_slice(&hash_bytes);
        assert_eq!(hashes.entry_witness_args(&[EntryWitnessArg::Bytes(hash_bytes)]).unwrap(), hash_expected);

        let nested = result.metadata.actions.iter().find(|action| action.name == "nested").unwrap();
        let nested_bytes = vec![0x03, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc];
        let mut nested_expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        nested_expected.extend_from_slice(&(nested_bytes.len() as u32).to_le_bytes());
        nested_expected.extend_from_slice(&nested_bytes);
        assert_eq!(nested.entry_witness_args(&[EntryWitnessArg::Bytes(nested_bytes)]).unwrap(), nested_expected);

        let raw = result.metadata.actions.iter().find(|action| action.name == "raw").unwrap();
        let raw_bytes = vec![0xaa, 0xbb, 0xcc];
        let mut raw_expected = ENTRY_WITNESS_ABI_MAGIC.to_vec();
        raw_expected.extend_from_slice(&(raw_bytes.len() as u32).to_le_bytes());
        raw_expected.extend_from_slice(&raw_bytes);
        assert_eq!(raw.entry_witness_args(&[EntryWitnessArg::Bytes(raw_bytes)]).unwrap(), raw_expected);
    }

    #[test]
    fn compile_file_loads_local_path_dependencies_from_cell_manifest() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();
        let dep_root = root.join("dep_pkg");
        let app_root = root.join("app_pkg");

        std::fs::create_dir_all(dep_root.join("src")).unwrap();
        std::fs::create_dir_all(app_root.join("src")).unwrap();

        std::fs::write(
            dep_root.join("Cell.toml"),
            r#"
[package]
name = "dep_pkg"
version = "0.1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            dep_root.join("src").join("token.cell"),
            r#"
module dep::token

resource Token has store, transfer, destroy {
    amount: u64
}
"#,
        )
        .unwrap();

        std::fs::write(
            app_root.join("Cell.toml"),
            r#"
[package]
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
        )
        .unwrap();
        let app_entry = app_root.join("src").join("main.cell");
        std::fs::write(
            &app_entry,
            r#"
module app::main

use dep::token::Token

action pass_through(token: Token) -> Token {
    token
}
"#,
        )
        .unwrap();

        let result = compile_file(&app_entry, CompileOptions::default()).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());
        assert!(result.metadata.source_hash_blake3.is_some());
        let roles = result.metadata.source_units.iter().map(|unit| unit.role.as_str()).collect::<Vec<_>>();
        assert!(roles.contains(&"entry"), "missing entry source unit: {:?}", result.metadata.source_units);
        assert!(roles.contains(&"dependency"), "missing dependency source unit: {:?}", result.metadata.source_units);
        assert_eq!(result.metadata.source_units.len(), 2);
    }

    #[test]
    fn resolve_input_path_accepts_package_root_and_manifest() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap();
        let entry = root.join("src").join("main.cell");
        std::fs::write(
            &entry,
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let expected: Utf8PathBuf = std::fs::canonicalize(&entry).unwrap().try_into().unwrap();
        assert_eq!(resolve_input_path(root).unwrap(), expected);
        assert_eq!(resolve_input_path(root.join("Cell.toml")).unwrap(), expected);
    }

    #[test]
    fn compile_path_accepts_package_root() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src").join("main.cell"),
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let result = compile_path(root, CompileOptions::default()).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());
    }

    #[test]
    fn default_output_path_for_package_input_uses_build_dir() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap();
        let entry = root.join("src").join("main.cell");
        std::fs::write(
            &entry,
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let expected = super::canonical_utf8_path(root).unwrap().join("build").join("main.s");
        let resolved = resolve_input_path(root).unwrap();
        assert_eq!(default_output_path_for_input(root, &resolved, ArtifactFormat::RiscvAssembly).unwrap(), expected);

        let manifest = root.join("Cell.toml");
        assert_eq!(default_output_path_for_input(&manifest, &resolved, ArtifactFormat::RiscvAssembly).unwrap(), expected);
    }

    #[test]
    fn default_output_path_for_package_input_uses_manifest_out_dir() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[build]
out_dir = "artifacts"
"#,
        )
        .unwrap();
        let entry = root.join("src").join("main.cell");
        std::fs::write(
            &entry,
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let expected = super::canonical_utf8_path(root).unwrap().join("artifacts").join("main.s");
        let resolved = resolve_input_path(root).unwrap();
        assert_eq!(default_output_path_for_input(root, &resolved, ArtifactFormat::RiscvAssembly).unwrap(), expected);
    }

    #[test]
    fn compile_file_uses_manifest_build_target_by_default() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[build]
target = "riscv64-elf"
"#,
        )
        .unwrap();
        let entry = root.join("src").join("main.cell");
        std::fs::write(
            &entry,
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let result = compile_file(&entry, CompileOptions::default()).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvElf);
        assert!(result.artifact_bytes.starts_with(b"\x7fELF"));
    }

    #[test]
    fn compile_file_uses_manifest_ckb_target_profile() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[build]
target_profile = "ckb"
"#,
        )
        .unwrap();
        let entry = root.join("src").join("main.cell");
        std::fs::write(
            &entry,
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let result = compile_file(&entry, CompileOptions::default()).unwrap();
        assert_eq!(result.metadata.target_profile.name.as_str(), "ckb");
        assert_eq!(result.metadata.target_profile.artifact_packaging.as_str(), "ckb-asm-sidecar");
        assert!(!result.metadata.runtime.vm_abi.embedded_in_artifact);
    }

    #[test]
    fn compile_file_explicit_target_overrides_manifest_build_target() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[build]
target = "riscv64-elf"
"#,
        )
        .unwrap();
        let entry = root.join("src").join("main.cell");
        std::fs::write(
            &entry,
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let result =
            compile_file(&entry, CompileOptions { target: Some("riscv64-asm".to_string()), ..CompileOptions::default() }).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());
    }

    #[test]
    fn compile_path_rejects_non_path_dependencies() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
token_std = "0.1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src").join("main.cell"),
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("only local path dependencies are supported"));
        assert!(err.message.contains("token_std"));
    }

    #[test]
    fn compile_path_rejects_missing_path_dependency_manifest() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"

[dependencies]
token_std = { path = "../missing_dep" }
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src").join("main.cell"),
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("expected manifest"));
        assert!(err.message.contains("token_std"));
    }

    #[test]
    fn compile_path_ignores_examples_outside_package_source_roots() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("examples")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("src").join("main.cell"),
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();
        std::fs::write(root.join("examples").join("broken.cell"), "this is not valid cellscript").unwrap();

        let result = compile_path(root, CompileOptions::default()).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());
    }

    #[test]
    fn compile_path_supports_custom_entry_directory_modules() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("contracts")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
entry = "contracts/main.cell"
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("contracts").join("helper.cell"),
            r#"
module demo::helper

resource Token has store, transfer, destroy {
    amount: u64
}
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("contracts").join("main.cell"),
            r#"
module demo::main

use demo::helper::Token

action pass(token: Token) -> Token {
    token
}
"#,
        )
        .unwrap();

        let result = compile_path(root, CompileOptions::default()).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());
    }

    #[test]
    fn compile_path_rejects_path_dependency_cycles() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();
        let dep_root = root.join("dep_pkg");
        let app_root = root.join("app_pkg");

        std::fs::create_dir_all(dep_root.join("src")).unwrap();
        std::fs::create_dir_all(app_root.join("src")).unwrap();

        std::fs::write(
            dep_root.join("Cell.toml"),
            r#"
[package]
name = "dep_pkg"
version = "0.1.0"

[dependencies]
app_pkg = { path = "../app_pkg" }
"#,
        )
        .unwrap();
        std::fs::write(
            dep_root.join("src").join("main.cell"),
            r#"
module dep::main

action dep_ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        std::fs::write(
            app_root.join("Cell.toml"),
            r#"
[package]
name = "app_pkg"
version = "0.1.0"

[dependencies]
dep_pkg = { path = "../dep_pkg" }
"#,
        )
        .unwrap();
        std::fs::write(
            app_root.join("src").join("main.cell"),
            r#"
module app::main

action app_ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let err = compile_path(app_root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("path dependency cycle detected"));
    }

    #[test]
    fn compile_path_supports_configured_source_roots_without_src() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("contracts")).unwrap();
        std::fs::create_dir_all(root.join("shared")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
entry = "contracts/main.cell"
source_roots = ["contracts", "shared"]
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("shared").join("token.cell"),
            r#"
module demo::token

resource Token has store, transfer, destroy {
    amount: u64
}
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("contracts").join("main.cell"),
            r#"
module demo::main

use demo::token::Token

action pass(token: Token) -> Token {
    token
}
"#,
        )
        .unwrap();

        let result = compile_path(root, CompileOptions::default()).unwrap();
        assert_eq!(result.artifact_format, ArtifactFormat::RiscvAssembly);
        assert!(!result.artifact_bytes.is_empty());
    }

    #[test]
    fn compile_path_rejects_missing_configured_source_root() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("contracts")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
entry = "contracts/main.cell"
source_roots = ["contracts", "shared"]
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("contracts").join("main.cell"),
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("configured source root"));
        assert!(err.message.contains("shared"));
    }

    #[test]
    fn compile_path_rejects_duplicate_modules_across_source_roots() {
        let temp = tempdir().unwrap();
        let root = Utf8Path::from_path(temp.path()).unwrap();

        std::fs::create_dir_all(root.join("contracts")).unwrap();
        std::fs::create_dir_all(root.join("shared")).unwrap();
        std::fs::write(
            root.join("Cell.toml"),
            r#"
[package]
name = "demo"
version = "0.1.0"
entry = "contracts/main.cell"
source_roots = ["contracts", "shared"]
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("contracts").join("main.cell"),
            r#"
module demo::main

action ping() -> u64 {
    1
}
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("contracts").join("token.cell"),
            r#"
module demo::token

resource Token has store, transfer, destroy {
    amount: u64
}
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("shared").join("token.cell"),
            r#"
module demo::token

resource Token has store, transfer, destroy {
    amount: u64
}
"#,
        )
        .unwrap();

        let err = compile_path(root, CompileOptions::default()).unwrap_err();
        assert!(err.message.contains("duplicate module 'demo::token'"));
    }
}
